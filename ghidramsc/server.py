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

"""HTTP server that holds a Ghidra JVM + project open for fast queries.

Start with::

    python -m ghidramsc serve [-b <binary>] [--port 13100]

The server keeps the JVM warm and the project open so that subsequent
CLI invocations can forward queries over HTTP instead of cold-starting
a JVM each time.  Programs (binaries) are opened on demand and cached.

If ``-b`` is given, it becomes the default binary.  Each ``/query``
request may override the binary by including a ``"binary"`` field.

Protocol
--------
- ``GET  /health``    -- returns ``{"status":"ok","default_binary":"<name>","cached":[...]}``
- ``GET  /programs``  -- returns ``{"programs":["sample.bin","libsample.so",...]}``
- ``POST /query``     -- JSON body ``{"command":"decompile_function","args":{...}[,"binary":"..."]}``.
                         Returns the query result as JSON.
- ``POST /shutdown``  -- gracefully stops the server.
"""

from __future__ import annotations

import json
import signal
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Optional

from .bridge import GhidraBridge, ProjectHandle
from .config import GhidraMSCConfig
from ._headless_dispatch import (
    build_dispatch_table as _build_dispatch_table,
    invoke_query,
)
from .result_contract import application_result_is_error, validation_failure
from .tool_registry import (
    get_tool,
    tool_accepts_mcp_binary,
    tool_mcp_modes,
    validate_tool_arguments,
)

# Default port; overridable via config or --port.
DEFAULT_PORT = 13100

# Sentinel written next to the config so the client can discover the port.
_PORT_FILE_NAME = ".ghidramsc_port"
_BAD_REQUEST_BODY = object()


def _port_file_path() -> Path:
    """Return the path to the port-file in the CWD."""
    return Path.cwd() / _PORT_FILE_NAME


def _write_port_file(port: int) -> Path:
    p = _port_file_path()
    p.write_text(str(port), encoding="ascii")
    return p


def _remove_port_file() -> None:
    p = _port_file_path()
    if p.exists():
        try:
            p.unlink()
        except OSError:
            pass


# -------------------------------------------------------------------
# Query dispatcher -- maps command names to functions in queries.py
# -------------------------------------------------------------------

_DISPATCH = _build_dispatch_table()


def _invoke(
    project: ProjectHandle,
    command: str,
    args: Dict[str, Any],
    default_binary: Optional[str],
) -> Any:
    """Call the query function and return its result."""
    try:
        get_tool(command)
    except KeyError as exc:
        raise ValueError("Unknown command: {}".format(command)) from exc

    if command == "list_programs":
        return {"programs": project.list_programs()}

    # Resolve binary per-request.
    binary = args.pop("binary", None) or default_binary
    if not binary:
        raise ValueError(
            "No binary specified.  Include 'binary' in the request or "
            "start the server with -b / GHIDRAMSC_BINARY."
        )

    return invoke_query(
        project, command, args, binary, _DISPATCH, "Unknown command: {}"
    )


# -------------------------------------------------------------------
# Request handler
# -------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    """Handle /health, /programs, /query, /shutdown."""

    # Populated by the server after construction.
    project: ProjectHandle
    default_binary: Optional[str]
    shutdown_event: threading.Event

    def log_message(self, fmt, *args):  # noqa: D401
        """Write to stderr with a prefix."""
        sys.stderr.write("[ghidramsc-server] {}\n".format(fmt % args))

    # -- GET /health, /programs ------------------------------------

    def do_GET(self):  # noqa: N802
        if not self._has_safe_host():
            self._json_response(403, {"error": "invalid Host header"})
            return
        if self.path == "/health":
            self._json_response(200, {
                "status": "ok",
                "default_binary": self.default_binary,
                "cached": list(self.project._programs.keys()),
            })
        elif self.path == "/programs":
            try:
                programs = self.project.list_programs()
            except Exception as exc:
                self._json_response(500, {"error": str(exc)})
                return
            self._json_response(200, {"programs": programs})
        else:
            self._json_response(404, {"error": "not found"})

    # -- POST /query, /shutdown ------------------------------------

    def do_POST(self):  # noqa: N802
        boundary_error = self._post_boundary_error()
        if boundary_error is not None:
            code, message = boundary_error
            self._json_response(code, {"error": message})
            return
        if self.path == "/query":
            self._handle_query()
        elif self.path == "/shutdown":
            payload = self._read_json_body()
            if payload is _BAD_REQUEST_BODY:
                return
            if payload != {}:
                self._json_response(400, {
                    "error": "shutdown body must be an empty JSON object"
                })
                return
            self._json_response(200, {"status": "shutting_down"})
            self.shutdown_event.set()
        else:
            self._json_response(404, {"error": "not found"})

    def _handle_query(self) -> None:
        payload = self._read_json_body()
        if payload is _BAD_REQUEST_BODY:
            return

        if not isinstance(payload, dict):
            self._json_response(400, {"error": "request body must be a JSON object"})
            return
        unknown_fields = sorted(set(payload) - {"command", "args", "binary"})
        if unknown_fields:
            self._json_response(400, {
                "error": "unknown request field(s): {}".format(
                    ", ".join(unknown_fields)
                )
            })
            return

        command = payload.get("command", "")
        args = payload.get("args", {})
        if not isinstance(command, str) or not command:
            self._json_response(400, {"error": "command must be a non-empty string"})
            return
        try:
            tool = get_tool(command)
        except KeyError:
            self._json_response(400, {"error": "Unknown command: {}".format(command)})
            return
        if "headless" not in tool_mcp_modes(tool):
            self._json_response(400, {
                "error": "Tool {!r} is unavailable through HTTP /query.".format(
                    command
                )
            })
            return
        schema_error = validate_tool_arguments(command, args)
        if schema_error is not None:
            self._json_response(
                422, validation_failure(command, args, schema_error)
            )
            return
        args = dict(args)

        # Allow per-request binary override at the top level of the payload.
        binary_override = payload.get("binary")
        if binary_override is not None and not isinstance(binary_override, str):
            self._json_response(400, {"error": "binary must be a string"})
            return
        if binary_override is not None and not tool_accepts_mcp_binary(tool):
            self._json_response(400, {
                "error": "Tool {!r} does not accept a binary selector.".format(
                    command
                )
            })
            return
        if binary_override:
            args["binary"] = binary_override

        try:
            result = _invoke(self.project, command, args, self.default_binary)
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        # Keep application payloads unchanged; only the mechanical HTTP status
        # reflects their shared outcome classification.
        if isinstance(result, dict):
            code = 422 if application_result_is_error(result) else 200
            self._json_response(code, result)
        else:
            body = {"result": str(result)}
            code = 422 if application_result_is_error(result) else 200
            self._json_response(code, body)

    # -- helpers ---------------------------------------------------

    def _has_safe_host(self) -> bool:
        host = self.headers.get("Host", "")
        hostname = host.rsplit(":", 1)[0].lower()
        return hostname in {"127.0.0.1", "localhost"}

    def _post_boundary_error(self):
        if not self._has_safe_host():
            return 403, "invalid Host header"
        if self.headers.get("Origin") is not None:
            return 403, "browser-originated requests are not accepted"
        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return 415, "Content-Type must be application/json"
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            return 400, "invalid Content-Length"
        if length < 0:
            return 411, "Content-Length is required"
        return None

    def _read_json_body(self):
        try:
            length = int(self.headers["Content-Length"])
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("incomplete request body")
            return json.loads(body.decode("utf-8"))
        except Exception as exc:
            self._json_response(400, {"error": "bad request: {}".format(exc)})
            return _BAD_REQUEST_BODY

    def _json_response(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, indent=2, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# -------------------------------------------------------------------
# Server lifecycle
# -------------------------------------------------------------------

def run_server(
    config: GhidraMSCConfig,
    binary: Optional[str] = None,
    port: int = DEFAULT_PORT,
    owner: Optional[str] = None,
) -> None:
    """Start the HTTP server and serve until shutdown or SIGINT.

    This call blocks until a ``/shutdown`` request or ``SIGINT`` is received.

    Parameters
    ----------
    config : GhidraMSCConfig
        Loaded configuration.
    binary : str or None
        Default binary name.  Each ``/query`` request may override this
        with a ``"binary"`` field.  If *binary* is None and no per-request
        binary is given, queries will fail with a clear error.
    port : int
        TCP port to listen on.
    owner : str or None
        Optional Ghidra project owner applied before the headless JVM starts.
    """
    bridge = (
        GhidraBridge(config, owner=owner)
        if owner is not None
        else GhidraBridge(config)
    )

    # Open the project (not a single program).  Programs are
    # opened on demand and cached for the lifetime of the server.
    with bridge.open_project() as project:
        # Pre-warm the default binary if one was specified.
        if binary:
            project.get_program(binary)

        shutdown_event = threading.Event()

        # Attach shared state to the handler class so every request can
        # reach it (BaseHTTPRequestHandler instantiates per request).
        _Handler.project = project
        _Handler.default_binary = binary
        _Handler.shutdown_event = shutdown_event

        httpd = HTTPServer(("127.0.0.1", port), _Handler)
        httpd.timeout = 1  # so we can check the event

        pf = _write_port_file(port)

        # Handle SIGINT (Ctrl-C) gracefully.
        def _sigint_handler(signum, frame):
            shutdown_event.set()

        prev = signal.signal(signal.SIGINT, _sigint_handler)

        sys.stderr.write(
            "[ghidramsc-server] listening on 127.0.0.1:{} "
            "(default_binary={})\n".format(port, binary or "(none)")
        )
        sys.stderr.write(
            "[ghidramsc-server] port file: {}\n".format(pf)
        )

        try:
            while not shutdown_event.is_set():
                httpd.handle_request()
        finally:
            signal.signal(signal.SIGINT, prev)
            _remove_port_file()
            httpd.server_close()
            sys.stderr.write("[ghidramsc-server] stopped.\n")
