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

"""MCP (Model Context Protocol) transport for GhidraMSC.

Speaks JSON-RPC 2.0 over stdio, implementing the MCP tool-serving
protocol.  Start with::

    python -m ghidramsc mcp [-b <binary>]

The host (e.g. VS Code) spawns this process and communicates via
stdin/stdout.  The JVM + Ghidra *project* stay loaded for the lifetime
of the process.  Individual programs (binaries) are opened on demand
and cached.

If ``-b`` is given, it becomes the default binary for program-scoped calls.
Those calls may override it with a ``binary`` parameter. Project-level and
CodeBrowser-context tools do not accept that selector.

Implemented MCP methods:
  - initialize
  - notifications/initialized
  - tools/list
  - tools/call
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from . import __version__
from .bridge import GhidraBridge, ProjectHandle
from .bridge_plugin import PluginProjectHandle
from .config import GhidraMSCConfig
from ._headless_dispatch import (
    build_dispatch_table as _build_dispatch,
    invoke_query,
)
from .result_contract import application_result_is_error, validation_failure
from .tool_registry import (
    TOOLS as _REGISTRY,
    tool_accepts_mcp_binary,
    validate_tool_arguments,
)
from .toolset_loader import ResolvedToolset, resolve_toolset

# -------------------------------------------------------------------
# Tool schema generation (driven by tool_registry.py)
# -------------------------------------------------------------------

_BINARY_PROP = {
    "type": "string",
    "description": (
        "Program name in the Ghidra project.  Optional if a "
        "default was set at startup via -b or GHIDRAMSC_BINARY."
    ),
}

_REGISTRY_BY_NAME = {entry["name"]: entry for entry in _REGISTRY}

_SUPPORTED_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
)
_LATEST_PROTOCOL_VERSION = _SUPPORTED_PROTOCOL_VERSIONS[-1]
_ANNOTATIONS_PROTOCOL_VERSION = "2025-03-26"
_STRUCTURED_CONTENT_PROTOCOL_VERSION = "2025-06-18"


def _protocol_at_least(protocol_version: str, minimum: str) -> bool:
    """Return whether a supported handshake revision includes *minimum*."""
    try:
        return _SUPPORTED_PROTOCOL_VERSIONS.index(protocol_version) >= (
            _SUPPORTED_PROTOCOL_VERSIONS.index(minimum)
        )
    except ValueError:
        return False


def _tool_annotations(entry: Dict[str, Any]) -> Dict[str, bool]:
    """Build conservative MCP behavior hints from the registry category."""
    read_only = entry["category"] == "query"
    return {
        "readOnlyHint": read_only,
        "destructiveHint": not read_only,
        "idempotentHint": read_only,
        "openWorldHint": False,
    }


def _build_tool_schemas(
    enabled_names: Optional[Iterable[str]] = None,
    protocol_version: str = _LATEST_PROTOCOL_VERSION,
) -> List[Dict[str, Any]]:
    """Generate MCP tool definitions from the central tool registry."""
    tools: List[Dict[str, Any]] = []
    entries = (
        _REGISTRY
        if enabled_names is None
        else [_REGISTRY_BY_NAME[name] for name in enabled_names]
    )

    for entry in entries:
        properties: Dict[str, Any] = {}
        required: List[str] = []

        if tool_accepts_mcp_binary(entry):
            properties["binary"] = _BINARY_PROP

        for p in entry["params"]:
            prop: Dict[str, Any] = {"type": p["type"]}
            if "desc" in p:
                prop["description"] = p["desc"]
            if "items" in p:
                prop["items"] = p["items"]
            if "default" in p:
                prop["default"] = p["default"]
            properties[p["name"]] = prop
            if p["required"]:
                required.append(p["name"])

        schema: Dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = required

        tool = {
            "name": entry["name"],
            "description": entry["description"],
            "inputSchema": schema,
        }
        if _protocol_at_least(
            protocol_version, _ANNOTATIONS_PROTOCOL_VERSION
        ):
            tool["annotations"] = _tool_annotations(entry)
        tools.append(tool)

    return tools


def _get_tool_schemas(
    enabled_names: Optional[Iterable[str]] = None,
    protocol_version: str = _LATEST_PROTOCOL_VERSION,
) -> List[Dict[str, Any]]:
    return _build_tool_schemas(enabled_names, protocol_version)


# -------------------------------------------------------------------
# Tool invocation (shared headless binding; mode-specific routing)
# -------------------------------------------------------------------

_DISPATCH = _build_dispatch()


def _invoke_tool(
    project,
    name: str,
    args: Dict[str, Any],
    default_binary: Optional[str],
    timing: Optional["_MCPRequestTiming"] = None,
) -> Any:
    tool = _REGISTRY_BY_NAME.get(name)
    if tool is None:
        raise ValueError("Unknown tool: {}".format(name))

    # Plugin mode -- forward everything over TCP to the Java plugin.
    if isinstance(project, PluginProjectHandle):
        binary = args.pop("binary", None) or default_binary
        # Commands that don't need a binary argument.
        if not tool_accepts_mcp_binary(tool):
            if timing is None:
                return project.invoke(name, None, args)
            started = time.perf_counter_ns()
            try:
                return project.invoke(name, None, args)
            finally:
                timing.record("query", time.perf_counter_ns() - started)
        if not binary:
            raise ValueError(
                "No binary specified.  Pass 'binary' in the tool arguments "
                "or start the server with -b / GHIDRAMSC_BINARY."
            )
        if timing is None:
            return project.invoke(name, binary, args)
        started = time.perf_counter_ns()
        try:
            return project.invoke(name, binary, args)
        finally:
            timing.record("query", time.perf_counter_ns() - started)

    # Headless mode -- local dispatch via queries.py.
    if name == "list_programs":
        if timing is None:
            return {"programs": project.list_programs()}
        started = time.perf_counter_ns()
        try:
            return {"programs": project.list_programs()}
        finally:
            timing.record("query", time.perf_counter_ns() - started)

    binary = args.pop("binary", None) or default_binary
    if not binary:
        raise ValueError(
            "No binary specified.  Pass 'binary' in the tool arguments "
            "or start the server with -b / GHIDRAMSC_BINARY."
        )

    if timing is None:
        return invoke_query(
            project, name, args, binary, _DISPATCH, "Unknown tool: {}"
        )
    return invoke_query(
        project, name, args, binary, _DISPATCH, "Unknown tool: {}",
        phase_timer=timing.record,
    )


# -------------------------------------------------------------------
# JSON-RPC 2.0 message handling
# -------------------------------------------------------------------

_SERVER_INFO = {
    "name": "ghidramsc",
    "version": __version__,
}

_CAPABILITIES = {
    "tools": {},
}


@dataclass
class _MCPConnectionState:
    """Handshake-era protocol state for one stdio connection."""

    protocol_version: str = _LATEST_PROTOCOL_VERSION
    initialized: bool = False


@dataclass
class _MCPRequestTiming:
    """Timing counters for one response; no request contents are retained."""

    request_id: str
    started_ns: int
    mode: str
    program_acquisition_ns: int = 0
    query_ns: int = 0
    dispatch_ns: int = 0
    serialization_ns: int = 0
    write_flush_ns: int = 0
    total_ns: int = 0

    def record(self, phase: str, elapsed_ns: int) -> None:
        if phase == "program_acquisition":
            self.program_acquisition_ns += elapsed_ns
        elif phase == "query":
            self.query_ns += elapsed_ns

    def event(self) -> Dict[str, Any]:
        def ms(value: int) -> float:
            return round(value / 1_000_000, 3)

        return {
            "schema": "ghidramsc.mcp.timing.v1",
            "request_id": self.request_id,
            "mode": self.mode,
            "phase_ms": {
                "dispatch": ms(self.dispatch_ns),
                "program_acquisition": ms(self.program_acquisition_ns),
                "query": ms(self.query_ns),
                "serialization": ms(self.serialization_ns),
                "write_flush": ms(self.write_flush_ns),
            },
            "program_acquisition_observable": self.mode == "headless",
            "total_ms": ms(self.total_ns),
        }


def _negotiate_protocol_version(requested: str) -> str:
    """Select a supported handshake revision for an initialize request."""
    if requested in _SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return _LATEST_PROTOCOL_VERSION


def _make_response(id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _make_error(id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": err}


# JSON-RPC error codes.
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


def _make_tool_result(
    result: Any,
    protocol_version: str,
    *,
    is_error: bool,
    error_category: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a backward-compatible tool result for the negotiated revision."""
    if isinstance(result, dict):
        text = json.dumps(result, indent=2, default=str)
    else:
        text = str(result)

    payload: Dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }
    if is_error and error_category is not None:
        payload["_meta"] = {"ghidramsc/errorCategory": error_category}
    if (
        isinstance(result, dict)
        and _protocol_at_least(
            protocol_version, _STRUCTURED_CONTENT_PROTOCOL_VERSION
        )
    ):
        # Match the text representation's ``default=str`` behavior so the
        # structured value is always JSON-compatible on the wire.
        payload["structuredContent"] = json.loads(
            json.dumps(result, default=str)
        )
    return payload


def _application_error_category(tool_name: str, result: Any) -> str:
    """Classify the few native failures with known semantics; keep others broad."""
    if isinstance(result, dict):
        if result.get("status") == "validation_failed":
            return "validation"
        error = result.get("error")
    else:
        error = result
    if isinstance(error, str):
        message = error.removeprefix("ERROR: ")
        if (
            tool_name in {"get_function_info", "decompile_function"}
            and message.startswith("No function at or containing ")
        ) or (
            tool_name == "get_data_at_address"
            and message.startswith("No defined data at ")
        ):
            return "not_found"
    return "application_failure"


def _tool_failure(text: str, category: str) -> Dict[str, Any]:
    """Keep the established text shape for pre-dispatch and caught failures."""
    return {
        "content": [{"type": "text", "text": text}],
        "isError": True,
        "_meta": {"ghidramsc/errorCategory": category},
    }


def _handle_message(
    msg: Any,
    project: ProjectHandle,
    default_binary: Optional[str],
    toolset: Optional[ResolvedToolset] = None,
    state: Optional[_MCPConnectionState] = None,
    timing: Optional[_MCPRequestTiming] = None,
) -> Optional[Dict[str, Any]]:
    """Process one JSON-RPC message.  Returns a response dict, or None for
    notifications (no 'id' field)."""
    if not isinstance(msg, dict):
        return _make_error(None, _INVALID_REQUEST, "Request must be a JSON object")

    msg_id = msg.get("id")
    if "id" in msg and (
        isinstance(msg_id, bool)
        or not isinstance(msg_id, (str, int, float, type(None)))
    ):
        return _make_error(None, _INVALID_REQUEST, "Invalid request id")
    connection = state if state is not None else _MCPConnectionState()
    is_notification = "id" not in msg
    if msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str) or not msg["method"]:
        if is_notification:
            return None
        return _make_error(msg_id, _INVALID_REQUEST,
                           "Request requires jsonrpc 2.0 and a string method")

    # Notifications cannot produce responses and must not dispatch tools.
    if is_notification:
        return None

    method = msg["method"]
    params = msg.get("params", {})
    if method in {"initialize", "tools/list", "tools/call", "ping",
                  "notifications/initialized"} and not isinstance(params, dict):
        return _make_error(msg_id, _INVALID_PARAMS,
                           "{} requires object params{}".format(
                               method,
                               " with protocolVersion" if method == "initialize" else "",
                           ))

    if method == "initialize":
        requested = (
            params.get("protocolVersion") if isinstance(params, dict) else None
        )
        if not isinstance(requested, str) or not requested:
            return _make_error(
                msg_id,
                _INVALID_PARAMS,
                "initialize requires a non-empty string protocolVersion",
            )
        negotiated = _negotiate_protocol_version(requested)
        connection.protocol_version = negotiated
        connection.initialized = True
        result = {
            "protocolVersion": negotiated,
            "serverInfo": _SERVER_INFO,
            "capabilities": _CAPABILITIES,
        }
        return _make_response(msg_id, result)

    elif method == "notifications/initialized":
        return _make_error(msg_id, _INVALID_REQUEST,
                           "notifications/initialized must not have an id")

    elif method == "tools/list":
        enabled_names = toolset.effective_names if toolset is not None else None
        return _make_response(
            msg_id,
            {"tools": _get_tool_schemas(
                enabled_names, connection.protocol_version
            )},
        )

    elif method == "tools/call":
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return _make_error(msg_id, _INVALID_PARAMS,
                               "tools/call requires a non-empty string name")
        tool_args = params.get("arguments", {})
        if not isinstance(tool_args, dict):
            return _make_error(msg_id, _INVALID_PARAMS,
                               "tools/call requires object arguments")
        if toolset is not None:
            if tool_name not in _REGISTRY_BY_NAME:
                return _make_response(msg_id, _tool_failure(
                    "Error: Unknown MCP tool {!r}.".format(tool_name),
                    "unavailable_tool",
                ))
            if tool_name in toolset.omitted_set:
                return _make_response(msg_id, _tool_failure(
                    ("Error: Tool {!r} is unavailable in {} MCP mode.")
                    .format(tool_name, toolset.mode),
                    "unavailable_tool",
                ))
            if tool_name not in toolset.effective_set:
                return _make_response(msg_id, _tool_failure(
                    ("Error: Tool {!r} is not enabled by MCP toolset {!r}.")
                    .format(tool_name, toolset.name),
                    "unavailable_tool",
                ))
        try:
            schema_error = validate_tool_arguments(
                tool_name, tool_args, include_mcp_binary=True
            )
            if schema_error is not None:
                failure = validation_failure(
                    tool_name,
                    tool_args if isinstance(tool_args, dict) else {},
                    schema_error,
                )
                return _make_response(
                    msg_id,
                    _make_tool_result(
                        failure,
                        connection.protocol_version,
                        is_error=True,
                        error_category="validation",
                    ),
                )
            tool_args = dict(tool_args)
            if timing is None:
                result = _invoke_tool(project, tool_name, tool_args, default_binary)
            else:
                result = _invoke_tool(
                    project, tool_name, tool_args, default_binary, timing=timing
                )
            is_error = application_result_is_error(result)
            return _make_response(
                msg_id,
                _make_tool_result(
                    result,
                    connection.protocol_version,
                    is_error=is_error,
                    error_category=(
                        _application_error_category(tool_name, result)
                        if is_error else None
                    ),
                ),
            )
        except Exception as exc:
            return _make_response(msg_id, _tool_failure(
                "Error: {}".format(exc), "exception"
            ))

    elif method == "ping":
        return _make_response(msg_id, {})

    else:
        if is_notification:
            return None
        return _make_error(msg_id, _METHOD_NOT_FOUND,
                           "Method not found: {}".format(method))


# -------------------------------------------------------------------
# stdio transport
# -------------------------------------------------------------------

_JSON_NULL = object()


def _read_message(stream=None) -> Any:
    """Read one JSON-RPC message from stdin (line-delimited JSON)."""
    if stream is None:
        stream = sys.stdin
    line = stream.readline()
    if line == "":
        return None
    message = json.loads(line)
    return _JSON_NULL if message is None else message


def _write_message(
    msg: Dict[str, Any], stream=None,
    timing: Optional[_MCPRequestTiming] = None,
) -> None:
    """Write one JSON-RPC message to stdout (line-delimited JSON)."""
    if stream is None:
        stream = sys.stdout
    if timing is None:
        stream.write(json.dumps(msg, default=str))
        stream.write("\n")
        stream.flush()
        return
    started = time.perf_counter_ns()
    wire = json.dumps(msg, default=str)
    serialized = time.perf_counter_ns()
    stream.write(wire)
    stream.write("\n")
    stream.flush()
    flushed = time.perf_counter_ns()
    timing.serialization_ns = serialized - started
    timing.write_flush_ns = flushed - serialized
    timing.total_ns = flushed - timing.started_ns


def _mcp_loop(
    project,
    default_binary: Optional[str],
    toolset: Optional[ResolvedToolset] = None,
    timing_enabled: bool = False,
) -> None:
    """Read JSON-RPC messages from stdin and dispatch until EOF."""
    sys.stderr.write("[ghidramsc-mcp] ready, waiting for messages on stdin\n")
    state = _MCPConnectionState()

    while True:
        try:
            msg = _read_message()
        except json.JSONDecodeError as exc:
            err = _make_error(None, _PARSE_ERROR, "Parse error: {}".format(exc))
            _write_message(err)
            continue

        if msg is None:
            # EOF -- host closed stdin.
            break

        if not timing_enabled:
            response = _handle_message(
                msg, project, default_binary, toolset, state
            )
            if response is not None:
                _write_message(response)
            continue

        started = time.perf_counter_ns()
        timing = _MCPRequestTiming(
            request_id=secrets.token_hex(8), started_ns=started,
            mode=toolset.mode if toolset is not None else "headless",
        )
        response = _handle_message(
            msg, project, default_binary, toolset, state, timing=timing
        )
        handled = time.perf_counter_ns()
        if response is not None:
            timing.dispatch_ns = max(
                0, handled - started - timing.program_acquisition_ns
                - timing.query_ns
            )
            _write_message(response, timing=timing)
            sys.stderr.write(
                "GHIDRAMSC_MCP_TIMING " + json.dumps(timing.event()) + "\n"
            )
            sys.stderr.flush()


def run_mcp(
    config: Optional[GhidraMSCConfig] = None,
    binary: Optional[str] = None,
    plugin: bool = False,
    plugin_host: str = "127.0.0.1",
    plugin_port: int = 18100,
    max_clients: Optional[int] = None,
    toolset: str = "all",
    owner: Optional[str] = None,
) -> None:
    """Run the MCP stdio server.  Blocks until stdin is closed.

    Parameters
    ----------
    config : GhidraMSCConfig or None
        Loaded configuration (Ghidra install dir, project path, etc.).
        Required for headless mode (Tiers 1-3).  Ignored in plugin mode.
    binary : str or None
        Default program name.  Each tool call may override this with a
        ``binary`` argument.  If *binary* is None and no per-call binary
        is provided, tool calls will fail with a clear error.
    plugin : bool
        If True, connect to the Ghidra GUI plugin via TCP instead of
        starting a local JVM.
    plugin_host : str
        Host for the plugin TCP server (default ``127.0.0.1``).
    plugin_port : int
        Port for the plugin TCP server (default ``18100``).
    max_clients : int or None
        Optional positive global listener cap to apply in plugin mode.
    toolset : str
        Name of the packaged MCP toolset to expose (default ``all``).
    owner : str or None
        Optional Ghidra project owner applied before the headless JVM starts.
        Not used by GUI/plugin mode.
    """
    mode = "plugin" if plugin else "headless"
    timing_enabled = os.getenv("GHIDRAMSC_MCP_TIMING") == "1"
    selection = resolve_toolset(toolset, mode)
    sys.stderr.write(
        "[ghidramsc-mcp] toolset={} source={} mode={} requested={} "
        "exposed={}\n".format(
            selection.name,
            selection.source,
            selection.mode,
            len(selection.requested_names),
            len(selection.effective_names),
        )
    )
    if selection.omitted_unavailable:
        sys.stderr.write(
            "[ghidramsc-mcp] unavailable in {} mode: {}\n".format(
                selection.mode, ", ".join(selection.omitted_unavailable)
            )
        )

    if max_clients is not None and not plugin:
        raise ValueError("max_clients requires plugin mode")
    if owner is not None and plugin:
        raise ValueError("owner requires headless mode")
    if plugin:
        sys.stderr.write(
            "[ghidramsc-mcp] connecting to plugin at {}:{}...\n".format(
                plugin_host, plugin_port
            )
        )
        project = PluginProjectHandle(
            host=plugin_host, port=plugin_port, max_clients=max_clients
        )
        try:
            if max_clients is not None:
                sys.stderr.write(
                    "[ghidramsc-mcp] plugin listener max clients={}.\n".format(
                        project.effective_max_clients
                    )
                )
            if project.ping():
                sys.stderr.write("[ghidramsc-mcp] plugin connected\n")
            else:
                raise ConnectionError(
                    "Plugin startup health check did not return pong"
                )
            _mcp_loop(
                project, binary, selection, timing_enabled=timing_enabled
            )
        finally:
            project.close()
    else:
        if config is None:
            raise ValueError(
                "config is required for headless MCP mode.  "
                "Use --mode gui for GUI mode."
            )
        bridge = (
            GhidraBridge(config, owner=owner)
            if owner is not None
            else GhidraBridge(config)
        )

        if binary:
            sys.stderr.write(
                "[ghidramsc-mcp] starting JVM (default binary={})...\n".format(
                    binary
                )
            )
        else:
            sys.stderr.write(
                "[ghidramsc-mcp] starting JVM (no default binary)...\n"
            )

        with bridge.open_project() as project:
            # Pre-warm the default binary if one was specified.
            if binary:
                project.get_program(binary)
            _mcp_loop(
                project, binary, selection, timing_enabled=timing_enabled
            )

    sys.stderr.write("[ghidramsc-mcp] stopped.\n")
