# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Plugin bridge -- communicates with the Ghidra Java plugin over TCP.

Instead of starting a local JVM (like bridge.py does), this module
connects to a TCP server running inside the Ghidra GUI via the
GhidraMSCPlugin Java extension.  Commands are serialized as
length-prefixed JSON and forwarded over the wire.

The Python side is a pure passthrough -- no query logic runs here.
All Ghidra API calls happen on the Java side.

Protocol
--------
Transport: TCP, localhost only (127.0.0.1).
Framing:   4-byte big-endian uint32 length prefix + UTF-8 JSON body.

Request::

    {"id": 1, "command": "decompile_function", "binary": "sample.bin",
     "args": {"addr_hex": "0x1c908"}}

Response (success)::

    {"id": 1, "result": "// decompiled C code..."}

Response (error)::

    {"id": 1, "error": "No function at or containing 0xdeadbeef"}
"""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

from .tool_registry import get_tool


# Default plugin TCP port (distinct from HTTP server's 13100).
DEFAULT_PLUGIN_PORT = 18100
DEFAULT_PLUGIN_HOST = "127.0.0.1"
MAX_JAVA_INT = 2_147_483_647


class PluginProtocolError(ConnectionError):
    """The plugin returned a response that cannot match the request."""


class PluginCapacityError(ConnectionError):
    """The listener rejected a connection because its client cap was full."""

    def __init__(self, message: str, max_clients: int) -> None:
        super().__init__(message)
        self.max_clients = max_clients


class AmbiguousMutationResultError(ConnectionError):
    """A mutation was sent, but its result could not be determined safely.

    The bridge deliberately does not reconnect and replay the mutation.  The
    caller must inspect current program state before deciding what to do next.
    """


class PluginProjectHandle:
    """Proxy that forwards commands to the Ghidra Java plugin via TCP.

    Implements the same logical interface as ``ProjectHandle`` (from
    bridge.py) but instead of holding Java object references it
    serializes commands over a TCP socket using 4-byte big-endian
    length-prefixed JSON framing.

    Usage::

        with PluginProjectHandle("127.0.0.1", 18100) as project:
            result = project.invoke("decompile_function", "sample.bin",
                                    {"addr_hex": "0x1c908"})
    """

    def __init__(
        self,
        host: str = DEFAULT_PLUGIN_HOST,
        port: int = DEFAULT_PLUGIN_PORT,
        timeout: float = 60.0,
        max_clients: Optional[int] = None,
    ) -> None:
        if max_clients is not None and (
            type(max_clients) is not int
            or max_clients < 1
            or max_clients > MAX_JAVA_INT
        ):
            raise ValueError(
                "max_clients must be an integer from 1 to {}".format(
                    MAX_JAVA_INT
                )
            )
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._request_id: int = 0
        self._closed = False
        self._max_clients = max_clients
        self._effective_max_clients: Optional[int] = None
        self._connect()
        if max_clients is not None:
            try:
                self._configure_listener(max_clients)
            except Exception:
                self.close()
                raise

    # -- connection management -------------------------------------

    def _connect(self) -> None:
        """Establish TCP connection to the plugin."""
        if self._closed:
            raise ConnectionError("Plugin handle is closed")
        sock = socket.create_connection(
            (self._host, self._port), timeout=self._timeout
        )
        try:
            sock.settimeout(self._timeout)
        except Exception:
            sock.close()
            raise
        self._sock = sock

    def _drop_connection(self) -> None:
        """Discard the current socket after a terminal transport failure."""
        sock = self._sock
        self._sock = None
        self._effective_max_clients = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    # -- wire protocol (4-byte length-prefix framing) --------------

    def _send(self, data: bytes) -> None:
        """Send a length-prefixed frame."""
        header = struct.pack(">I", len(data))
        if self._sock is None:
            raise ConnectionError(
                "Plugin connection is unavailable; create a new handle"
            )
        self._sock.sendall(header + data)

    def _recv(self) -> bytes:
        """Receive a length-prefixed frame."""
        header = self._recv_exact(4)
        length = struct.unpack(">I", header)[0]
        return self._recv_exact(length)

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly *n* bytes from the socket."""
        buf = bytearray()
        if self._sock is None:
            raise ConnectionError(
                "Plugin connection is unavailable; create a new handle"
            )
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError(
                    "Plugin connection closed unexpectedly"
                )
            buf.extend(chunk)
        return bytes(buf)

    # -- command transport -----------------------------------------

    def _send_command(
        self,
        command: str,
        binary: Optional[str],
        args: Dict[str, Any],
    ) -> Any:
        """Send one command once; a later call may reconnect first."""
        if self._closed:
            raise ConnectionError("Plugin handle is closed")
        if self._sock is None:
            try:
                self._connect()
                if self._max_clients is not None:
                    self._configure_listener(self._max_clients)
            except Exception:
                self._drop_connection()
                raise

        try:
            is_mutation = get_tool(command)["category"] == "mutation"
        except KeyError:
            is_mutation = False

        try:
            return self._request_once(command, binary, args)
        except PluginCapacityError:
            self._drop_connection()
            raise
        except (OSError, ConnectionError, UnicodeError) as exc:
            self._drop_connection()
            if is_mutation:
                raise AmbiguousMutationResultError(
                    "Plugin connection failed after mutation {!r} was sent; "
                    "the operation was not replayed. Inspect program state "
                    "before retrying: {}".format(command, exc)
                ) from exc
            raise

    def _configure_listener(self, max_clients: int) -> None:
        """Apply and validate one internal listener configuration request."""
        try:
            result = self._request_once(
                "configure_listener", None, {"max_clients": max_clients}
            )
        except RuntimeError as exc:
            raise PluginProtocolError(
                "Plugin did not accept --max-clients; the running plugin may "
                "not support listener configuration: {}".format(exc)
            ) from exc

        if not isinstance(result, dict):
            raise PluginProtocolError(
                "Plugin listener configuration result must be an object"
            )
        effective = result.get("max_clients")
        if type(effective) is not int or effective < 1:
            raise PluginProtocolError(
                "Plugin listener configuration returned invalid max_clients: "
                "{!r}".format(effective)
            )
        if effective != max_clients:
            raise PluginProtocolError(
                "Plugin listener configuration mismatch: requested {}, got {}"
                .format(max_clients, effective)
            )
        self._effective_max_clients = effective

    def _request_once(
        self,
        command: str,
        binary: Optional[str],
        args: Dict[str, Any],
    ) -> Any:
        """Perform exactly one framed request/response round trip."""
        req_id = self._next_id()
        request: Dict[str, Any] = {
            "id": req_id,
            "command": command,
            "args": args,
        }
        if binary is not None:
            request["binary"] = binary

        payload = json.dumps(request).encode("utf-8")
        self._send(payload)

        raw = self._recv()
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PluginProtocolError(
                "Plugin returned malformed UTF-8 JSON: {}".format(exc)
            ) from exc

        if not isinstance(response, dict):
            raise PluginProtocolError("Plugin response must be a JSON object")
        if (
            type(response.get("id")) is int
            and response.get("id") == 0
            and response.get("error_code") == "client_capacity"
            and "error" in response
            and "result" not in response
        ):
            max_clients = response.get("max_clients")
            if type(max_clients) is not int or max_clients < 1:
                raise PluginProtocolError(
                    "Plugin capacity response has invalid max_clients: {!r}"
                    .format(max_clients)
                )
            error = response.get("error")
            if not isinstance(error, str) or not error:
                raise PluginProtocolError(
                    "Plugin capacity response must contain an error message"
                )
            raise PluginCapacityError(error, max_clients)
        response_id = response.get("id")
        if type(response_id) is not int or response_id != req_id:
            raise PluginProtocolError(
                "Plugin response ID mismatch: expected {}, got {!r}".format(
                    req_id, response_id
                )
            )
        if ("result" in response) == ("error" in response):
            raise PluginProtocolError(
                "Plugin response must contain exactly one of result or error"
            )

        if "error" in response:
            raise RuntimeError(str(response["error"]))

        return response["result"]

    # -- public interface (mirrors ProjectHandle) ------------------

    def invoke(
        self,
        command: str,
        binary: Optional[str],
        args: Dict[str, Any],
    ) -> Any:
        """Send command to plugin, return result.

        Handles ``json_path`` pre-reading: if any arg is named
        ``json_path``, the file is read locally and sent as
        ``json_data`` instead (Option A from the design doc).
        """
        args = dict(args)  # don't mutate caller's dict
        _preread_json_paths(command, args)
        return self._send_command(command, binary, args)

    def list_programs(self) -> List[str]:
        """Return program names from the plugin."""
        result = self.invoke("list_programs", None, {})
        if isinstance(result, dict) and "programs" in result:
            return result["programs"]
        if isinstance(result, list):
            return result
        return []

    def get_program(self, name: str) -> "_PluginProgramProxy":
        """Return a lightweight proxy -- the real program lives in the GUI."""
        return _PluginProgramProxy(name)

    def save(self, name: Optional[str] = None) -> Any:
        """Explicitly save *name*, or the active GUI program when omitted."""
        return self.invoke("save_program", name, {})

    def close(self) -> None:
        """Close the TCP connection."""
        self._closed = True
        self._drop_connection()

    @property
    def effective_max_clients(self) -> Optional[int]:
        """Return the listener limit acknowledged for an explicit override."""
        return self._effective_max_clients

    def ping(self) -> bool:
        """Health check -- returns True if the plugin responds to ping."""
        try:
            result = self._send_command("ping", None, {})
            return result == "pong"
        except PluginCapacityError:
            raise
        except Exception:
            return False

    # -- context manager -------------------------------------------

    def __enter__(self) -> "PluginProjectHandle":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return "PluginProjectHandle({}:{})".format(self._host, self._port)


class _PluginProgramProxy:
    """Lightweight stand-in for a remote program.

    In plugin mode the real ``Program`` Java object lives on the GUI
    side.  This proxy exists only so that callers that check program
    identity have something to reference.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return "_PluginProgramProxy({!r})".format(self.name)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _preread_json_paths(command: str, args: Dict[str, Any]) -> None:
    """Replace JSON file args with their declared plugin-wire values.

    This keeps file I/O on the Python side (consistent with the
    passthrough model) and avoids cross-platform path issues between
    the Python process and the Ghidra plugin.
    """
    try:
        tool = get_tool(command)
    except KeyError:
        # Let the plugin report unknown commands over the normal protocol.
        return
    for param in tool["params"]:
        wire = param.get("plugin_wire")
        key = param["name"]
        if wire is None or key not in args or args[key] is None:
            continue

        path = Path(args[key])
        with open(path, "r", encoding="utf-8") as fh:
            value = json.load(fh)

        expected = wire["type"]
        valid = (
            (expected == "array" and isinstance(value, list))
            or (expected == "object" and isinstance(value, dict))
        )
        if not valid:
            raise ValueError(
                "{} JSON input must contain a top-level {}, got {}".format(
                    command, expected, type(value).__name__
                )
            )

        args.pop(key)
        args[wire["name"]] = value
