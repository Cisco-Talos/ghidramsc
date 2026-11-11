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

"""Tests for ghidramsc.mcp_transport -- MCP protocol handler tests.

Tests the JSON-RPC message handling, tool schema generation, tool
invocation, and stdio transport without a real JVM.
"""

from __future__ import annotations

import io
import json
from unittest import mock

import pytest

from ghidramsc.bridge_plugin import AmbiguousMutationResultError


# -------------------------------------------------------------------
# Tool schema generation
# -------------------------------------------------------------------

class TestToolSchemas:
    def test_all_schemas_follow_mode_availability(self):
        from ghidramsc.mcp_transport import _build_tool_schemas
        from ghidramsc.toolset_loader import resolve_toolset

        headless = resolve_toolset("all", "headless")
        gui = resolve_toolset("all", "plugin")
        headless_names = [tool["name"] for tool in
                          _build_tool_schemas(headless.effective_names)]
        gui_names = [tool["name"] for tool in
                     _build_tool_schemas(gui.effective_names)]
        assert headless_names == list(headless.effective_names)
        assert gui_names == list(gui.effective_names)
        assert "get_cursor_address" not in headless_names
        assert "get_cursor_address" in gui_names

    def test_create_structure_category_path_schema(self):
        from ghidramsc.mcp_transport import _get_tool_schemas

        schemas = _get_tool_schemas()
        create = next(t for t in schemas if t["name"] == "create_structure")
        schema = create["inputSchema"]
        assert schema["properties"]["category_path"] == {
            "type": "string",
            "description": "Exact Ghidra data-type category path",
            "default": "/",
        }
        assert "category_path" not in schema.get("required", [])

    def test_new_tools_have_descriptions(self):
        from ghidramsc.mcp_transport import _get_tool_schemas
        schemas = _get_tool_schemas()
        for tool in schemas:
            assert tool["description"], "Empty description for {}".format(tool["name"])

    def test_filtered_schemas_preserve_requested_order(self):
        from ghidramsc.mcp_transport import _build_tool_schemas

        names = ("list_strings", "list_programs", "decompile_function")
        schemas = _build_tool_schemas(names)
        assert [schema["name"] for schema in schemas] == list(names)

    def test_2024_schema_omits_tool_annotations(self):
        from ghidramsc.mcp_transport import _build_tool_schemas

        schemas = _build_tool_schemas(("decompile_function",), "2024-11-05")
        assert "annotations" not in schemas[0]

    def test_2025_annotations_are_conservative_and_category_aware(self):
        from ghidramsc.mcp_transport import _build_tool_schemas

        schemas = {
            schema["name"]: schema
            for schema in _build_tool_schemas(
                ("decompile_function", "set_function_name"), "2025-03-26"
            )
        }
        assert schemas["decompile_function"]["annotations"] == {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
        assert schemas["set_function_name"]["annotations"] == {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        }


# -------------------------------------------------------------------
# Message handling
# -------------------------------------------------------------------

class TestHandleMessage:
    @pytest.fixture()
    def project(self):
        """Mock ProjectHandle that returns a mock ProgramContext."""
        ctx = mock.MagicMock()
        proj = mock.MagicMock()
        proj.get_program.return_value = ctx
        proj.list_programs.return_value = ["sample.bin", "libsample.so"]
        return proj

    @pytest.fixture()
    def default_binary(self):
        return "sample.bin"

    def test_initialize(self, project, default_binary):
        from ghidramsc.mcp_transport import _MCPConnectionState, _handle_message

        state = _MCPConnectionState()
        msg = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        }
        resp = _handle_message(msg, project, default_binary, state=state)
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == "2025-11-25"
        assert result["serverInfo"]["name"] == "ghidramsc"
        assert "tools" in result["capabilities"]
        assert state.protocol_version == "2025-11-25"
        assert state.initialized is True

    @pytest.mark.parametrize(
        "requested",
        ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"],
    )
    def test_initialize_preserves_supported_version(
        self, project, default_binary, requested
    ):
        from ghidramsc.mcp_transport import _handle_message

        response = _handle_message({
            "jsonrpc": "2.0", "id": 101, "method": "initialize",
            "params": {"protocolVersion": requested},
        }, project, default_binary)
        assert response["result"]["protocolVersion"] == requested

    def test_initialize_offers_latest_handshake_fallback(
        self, project, default_binary
    ):
        from ghidramsc.mcp_transport import _handle_message

        response = _handle_message({
            "jsonrpc": "2.0", "id": 102, "method": "initialize",
            "params": {"protocolVersion": "2026-07-28"},
        }, project, default_binary)
        assert response["result"]["protocolVersion"] == "2025-11-25"

    @pytest.mark.parametrize("params", [{}, None, {"protocolVersion": 20251125}])
    def test_initialize_rejects_missing_or_invalid_version(
        self, project, default_binary, params
    ):
        from ghidramsc.mcp_transport import _handle_message

        response = _handle_message({
            "jsonrpc": "2.0", "id": 103, "method": "initialize",
            "params": params,
        }, project, default_binary)
        assert response["error"]["code"] == -32602
        assert "protocolVersion" in response["error"]["message"]

    def test_initialized_notification(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message
        msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        resp = _handle_message(msg, project, default_binary)
        assert resp is None

    def test_tools_list(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        resp = _handle_message(msg, project, default_binary)
        assert resp["id"] == 2
        tools = resp["result"]["tools"]
        assert isinstance(tools, list)
        names = [t["name"] for t in tools]
        assert "decompile_function" in names
        assert "list_functions" in names
        assert "list_programs" in names

    def test_tools_call_success(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message, _DISPATCH
        spy = mock.MagicMock(return_value="decompiled code here")
        with mock.patch.dict(_DISPATCH, {"decompile_function": spy}):
            msg = {
                "jsonrpc": "2.0", "id": 3,
                "method": "tools/call",
                "params": {"name": "decompile_function", "arguments": {"addr_hex": "0x1000"}},
            }
            resp = _handle_message(msg, project, default_binary)
        assert resp["id"] == 3
        assert resp["result"]["isError"] is False
        content = resp["result"]["content"]
        assert len(content) == 1
        assert content[0]["type"] == "text"
        assert "decompiled code here" in content[0]["text"]

    def test_tools_call_dict_result(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message, _DISPATCH
        spy = mock.MagicMock(return_value={"name": "main", "addr": "0x1000"})
        with mock.patch.dict(_DISPATCH, {"get_function_info": spy}):
            msg = {
                "jsonrpc": "2.0", "id": 4,
                "method": "tools/call",
                "params": {"name": "get_function_info", "arguments": {"addr_hex": "0x1000"}},
            }
            resp = _handle_message(msg, project, default_binary)
        text = resp["result"]["content"][0]["text"]
        parsed = json.loads(text)
        assert parsed["name"] == "main"
        assert resp["result"]["structuredContent"] == {
            "name": "main", "addr": "0x1000"
        }

    def test_pre_structured_content_version_keeps_text_only(
        self, project, default_binary
    ):
        from ghidramsc.mcp_transport import (
            _DISPATCH,
            _MCPConnectionState,
            _handle_message,
        )

        state = _MCPConnectionState(
            protocol_version="2025-03-26", initialized=True
        )
        with mock.patch.dict(
            _DISPATCH,
            {"get_function_info": mock.MagicMock(return_value={"name": "main"})},
        ):
            response = _handle_message({
                "jsonrpc": "2.0", "id": 104, "method": "tools/call",
                "params": {
                    "name": "get_function_info", "arguments": {"addr_hex": "0x1000"},
                },
            }, project, default_binary, state=state)

        assert "structuredContent" not in response["result"]
        assert json.loads(response["result"]["content"][0]["text"]) == {
            "name": "main"
        }

    def test_structured_content_is_limited_to_object_results(
        self, project, default_binary
    ):
        from ghidramsc.mcp_transport import _DISPATCH, _handle_message

        with mock.patch.dict(
            _DISPATCH,
            {"decompile_function": mock.MagicMock(return_value="decompiled text")},
        ):
            response = _handle_message({
                "jsonrpc": "2.0", "id": 105, "method": "tools/call",
                "params": {
                    "name": "decompile_function", "arguments": {"addr_hex": "0x1000"},
                },
            }, project, default_binary)

        assert "structuredContent" not in response["result"]

    @pytest.mark.parametrize(
        ("result_status", "old", "stored", "error", "is_error"),
        [
            (
                "success",
                {"address": "00000100", "name": "old_name"},
                {"address": "00000100", "name": "new_name"},
                None, False,
            ),
            (
                "no_change",
                {"address": "00000100", "name": "new_name"},
                {"address": "00000100", "name": "new_name"},
                None, False,
            ),
            (
                "validation_failed", None, None,
                "No function at or containing 0x100", True,
            ),
        ],
    )
    def test_headless_rename_returns_shared_contract_unchanged(
        self, project, default_binary, result_status, old, stored, error,
        is_error
    ):
        from ghidramsc.mcp_transport import _handle_message, _DISPATCH

        contract = {
            "operation": "set_function_name",
            "status": result_status,
            "requested": {"address": "0x100", "name": "new_name"},
            "old": old,
            "stored": stored,
            "error": error,
        }
        with mock.patch.dict(
            _DISPATCH, {"set_function_name": mock.MagicMock(return_value=contract)}
        ):
            resp = _handle_message({
                "jsonrpc": "2.0", "id": 43, "method": "tools/call",
                "params": {
                    "name": "set_function_name",
                    "arguments": {"addr_hex": "0x100", "new_name": "new_name"},
                },
            }, project, default_binary)

        assert resp["result"]["isError"] is is_error
        assert json.loads(resp["result"]["content"][0]["text"]) == contract

    def test_headless_save_incomplete_is_structured_tool_error(
        self, project, default_binary
    ):
        from ghidramsc.mcp_transport import _handle_message, _DISPATCH
        failure = {
            "operation": "save_program", "status": "failed",
            "save": {"completed": False}, "error": "disk full",
        }
        with mock.patch.dict(_DISPATCH, {"save_program": mock.MagicMock(return_value=failure)}):
            resp = _handle_message({
                "jsonrpc": "2.0", "id": 44, "method": "tools/call",
                "params": {"name": "save_program", "arguments": {}},
            }, project, default_binary)
        assert resp["result"]["isError"] is True
        assert json.loads(resp["result"]["content"][0]["text"]) == failure

    def test_tools_call_error(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message, _DISPATCH
        spy = mock.MagicMock(side_effect=RuntimeError("JVM exploded"))
        with mock.patch.dict(_DISPATCH, {"decompile_function": spy}):
            msg = {
                "jsonrpc": "2.0", "id": 5,
                "method": "tools/call",
                "params": {"name": "decompile_function", "arguments": {"addr_hex": "0x1"}},
            }
            resp = _handle_message(msg, project, default_binary)
        assert resp["result"]["isError"] is True
        assert "JVM exploded" in resp["result"]["content"][0]["text"]

    def test_tools_call_unknown(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message
        msg = {
            "jsonrpc": "2.0", "id": 6,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        }
        resp = _handle_message(msg, project, default_binary)
        assert resp["result"]["isError"] is True

    @pytest.mark.parametrize(
        "tool_name",
        [
            "detect_security_mitigations",
            "find_format_string_vulns",
            "identify_user_input_sources",
            "identify_crypto_patterns",
            "find_obfuscated_strings",
            "fix_region",
        ],
    )
    def test_disabled_tool_call_is_rejected_before_dispatch(
        self, project, default_binary, tool_name
    ):
        from ghidramsc import mcp_transport

        with mock.patch.object(mcp_transport, "_invoke_tool") as invoke:
            response = mcp_transport._handle_message({
                "jsonrpc": "2.0", "id": 60, "method": "tools/call",
                "params": {"name": tool_name, "arguments": {}},
            }, project, default_binary)

        invoke.assert_not_called()
        project.get_program.assert_not_called()
        assert response["result"]["isError"] is True
        failure = json.loads(response["result"]["content"][0]["text"])
        assert failure["status"] == "validation_failed"
        assert "Unknown command" in failure["error"]

    @pytest.mark.parametrize(
        ("command", "arguments"),
        [
            ("decompile_function", {}),
            ("decompile_function", {"addr_hex": 4096}),
            ("decompile_function", {"addr_hex": "0x1000", "bogus": True}),
            ("read_memory_bytes", {"addr_hex": "0x1000", "length": "four"}),
            ("set_memory_block_permissions", {"block_name": "ram", "read": "yes"}),
            ("decompile_functions", {"addresses": {"not": "an array"}}),
            ("decompile_functions", {"addresses": ["0x1000", 4097]}),
            ("decompile_function", {"addr_hex": "0x1000", "binary": 7}),
            ("list_programs", {"binary": "sample.bin"}),
        ],
    )
    def test_invalid_tool_arguments_stop_before_dispatch(
        self, project, default_binary, command, arguments
    ):
        from ghidramsc import mcp_transport

        with mock.patch.object(mcp_transport, "_invoke_tool") as invoke:
            resp = mcp_transport._handle_message({
                "jsonrpc": "2.0", "id": 61, "method": "tools/call",
                "params": {"name": command, "arguments": arguments},
            }, project, default_binary)

        invoke.assert_not_called()
        project.get_program.assert_not_called()
        assert resp["result"]["isError"] is True
        failure = json.loads(resp["result"]["content"][0]["text"])
        assert failure["operation"] == command
        assert failure["status"] == "validation_failed"
        assert "binary" not in failure["requested"]
        assert resp["result"]["structuredContent"] == failure

    @pytest.mark.parametrize(
        "result",
        [
            {"error": "missing"},
            "ERROR: missing",
            {"operation": "set_function_names", "status": "partial_success"},
        ],
    )
    def test_returned_application_failures_set_mcp_error(
        self, project, default_binary, result
    ):
        from ghidramsc import mcp_transport

        with mock.patch.object(
            mcp_transport, "_invoke_tool", return_value=result
        ):
            response = mcp_transport._handle_message({
                "jsonrpc": "2.0", "id": 63, "method": "tools/call",
                "params": {
                    "name": "list_functions", "arguments": {},
                },
            }, project, default_binary)

        assert response["result"]["isError"] is True

    @pytest.mark.parametrize(
        ("command", "arguments"),
        [
            ("set_function_names", {"json_path": "renames.json"}),
            ("set_variable_type", {
                "addr_hex": "0x1000", "var_name": "local_8",
                "type_name": "int",
            }),
            ("apply_data_type", {
                "addr_hex": "0x1000", "type_name": "int",
                "clear_mode": "fail",
            }),
            ("create_structure", {
                "name": "Packet", "size": 8, "category_path": "/net",
            }),
        ],
    )
    def test_drift_prone_arguments_reach_dispatch_unchanged(
        self, project, default_binary, command, arguments
    ):
        from ghidramsc import mcp_transport

        with mock.patch.object(
            mcp_transport, "_invoke_tool", return_value="ok"
        ) as invoke:
            resp = mcp_transport._handle_message({
                "jsonrpc": "2.0", "id": 62, "method": "tools/call",
                "params": {"name": command, "arguments": arguments},
            }, project, default_binary)

        invoke.assert_called_once_with(
            project, command, arguments, default_binary
        )
        assert resp["result"]["isError"] is False

    def test_tools_call_with_per_call_binary(self, project, default_binary):
        """Tool call specifying binary overrides the default."""
        from ghidramsc.mcp_transport import _handle_message, _DISPATCH
        spy = mock.MagicMock(return_value="ok")
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            msg = {
                "jsonrpc": "2.0", "id": 10,
                "method": "tools/call",
                "params": {"name": "list_functions", "arguments": {"binary": "libsample.so"}},
            }
            resp = _handle_message(msg, project, default_binary)
        project.get_program.assert_called_with("libsample.so")
        assert resp["result"]["isError"] is False

    def test_tools_call_list_programs(self, project, default_binary):
        """list_programs is a project-level tool, no binary needed."""
        from ghidramsc.mcp_transport import _handle_message
        msg = {
            "jsonrpc": "2.0", "id": 11,
            "method": "tools/call",
            "params": {"name": "list_programs", "arguments": {}},
        }
        resp = _handle_message(msg, project, default_binary)
        assert resp["result"]["isError"] is False
        text = resp["result"]["content"][0]["text"]
        parsed = json.loads(text)
        assert "sample.bin" in parsed["programs"]

    def test_ping(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message
        msg = {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}}
        resp = _handle_message(msg, project, default_binary)
        assert resp["id"] == 7
        assert resp["result"] == {}

    def test_unknown_method(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message
        msg = {"jsonrpc": "2.0", "id": 8, "method": "bogus/method", "params": {}}
        resp = _handle_message(msg, project, default_binary)
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    def test_unknown_notification_ignored(self, project, default_binary):
        from ghidramsc.mcp_transport import _handle_message
        msg = {"jsonrpc": "2.0", "method": "notifications/whatever"}
        resp = _handle_message(msg, project, default_binary)
        assert resp is None


class TestToolsetEnforcement:
    @pytest.fixture()
    def project(self):
        return mock.MagicMock()

    def test_tools_list_uses_exact_effective_order(self, project):
        from ghidramsc.mcp_transport import _handle_message
        from ghidramsc.toolset_loader import resolve_toolset

        selection = resolve_toolset("minimal", "headless")
        response = _handle_message({
            "jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {},
        }, project, "sample.bin", selection)

        assert [
            tool["name"] for tool in response["result"]["tools"]
        ] == list(selection.effective_names)

    def test_excluded_call_is_rejected_before_dispatch(self, project):
        from ghidramsc import mcp_transport
        from ghidramsc.toolset_loader import resolve_toolset

        selection = resolve_toolset("minimal", "plugin")
        with mock.patch.object(mcp_transport, "_invoke_tool") as invoke:
            response = mcp_transport._handle_message({
                "jsonrpc": "2.0", "id": 21, "method": "tools/call",
                "params": {
                    "name": "set_function_name",
                    "arguments": {"addr_hex": "0x100", "new_name": "renamed"},
                },
            }, project, "sample.bin", selection)

        invoke.assert_not_called()
        project.get_program.assert_not_called()
        assert response["result"]["isError"] is True
        assert "not enabled" in response["result"]["content"][0]["text"]

    def test_mode_unavailable_call_is_rejected_before_dispatch(self, project):
        from ghidramsc import mcp_transport
        from ghidramsc.toolset_loader import resolve_toolset

        selection = resolve_toolset("all", "headless")
        with mock.patch.object(mcp_transport, "_invoke_tool") as invoke:
            response = mcp_transport._handle_message({
                "jsonrpc": "2.0", "id": 22, "method": "tools/call",
                "params": {"name": "get_cursor_address", "arguments": {}},
            }, project, "sample.bin", selection)

        invoke.assert_not_called()
        project.get_program.assert_not_called()
        assert response["result"]["isError"] is True
        assert "unavailable in headless" in response["result"]["content"][0]["text"]

    def test_unknown_call_is_rejected_before_dispatch(self, project):
        from ghidramsc import mcp_transport
        from ghidramsc.toolset_loader import resolve_toolset

        selection = resolve_toolset("default", "plugin")
        with mock.patch.object(mcp_transport, "_invoke_tool") as invoke:
            response = mcp_transport._handle_message({
                "jsonrpc": "2.0", "id": 23, "method": "tools/call",
                "params": {"name": "not_a_tool", "arguments": {}},
            }, project, "sample.bin", selection)

        invoke.assert_not_called()
        assert response["result"]["isError"] is True
        assert "Unknown MCP tool" in response["result"]["content"][0]["text"]


# -------------------------------------------------------------------
# stdio read/write
# -------------------------------------------------------------------

class TestStdioTransport:
    @pytest.mark.parametrize("timing_enabled", [False, True])
    def test_malformed_envelopes_keep_loop_alive_before_valid_calls(
        self, timing_enabled
    ):
        from ghidramsc import mcp_transport

        messages = [
            "{bad json",                       # parse error, id null
            "",                                # blank line is a parse error, not EOF
            "null",                            # invalid top-level JSON value
            "[]",
            json.dumps({"jsonrpc": "1.0", "id": 1, "method": "ping"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": []}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": None}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": []}),
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                        "params": {"name": ["list_programs"]}}),
            json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                        "params": {"name": "list_programs", "arguments": None}}),
            json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                        "params": {"name": "list_programs", "arguments": {}}}),
            json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                        "params": []}),
            json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                        "params": {"name": "list_programs", "arguments": {}}}),
        ]
        stdin = io.StringIO("\n".join(messages) + "\n")
        stdout = io.StringIO()
        stderr = io.StringIO()
        project = mock.MagicMock()
        with (
            mock.patch.object(mcp_transport.sys, "stdin", stdin),
            mock.patch.object(mcp_transport.sys, "stdout", stdout),
            mock.patch.object(mcp_transport.sys, "stderr", stderr),
            mock.patch.object(mcp_transport, "_invoke_tool",
                              return_value={"programs": ["sample.bin"]}) as invoke,
        ):
            mcp_transport._mcp_loop(project, None, timing_enabled=timing_enabled)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert len(responses) == 12
        assert [item["id"] for item in responses] == [
            None, None, None, None, 1, 2, 3, 4, 5, 6, 7, 8,
        ]
        assert [item["error"]["code"] for item in responses[:10]] == [
            -32700, -32700, -32600, -32600, -32600, -32600,
            -32602, -32602, -32602, -32602,
        ]
        assert any(tool["name"] == "list_programs"
                   for tool in responses[10]["result"]["tools"])
        assert responses[11]["result"]["isError"] is False
        assert json.loads(responses[11]["result"]["content"][0]["text"]) == (
            {"programs": ["sample.bin"]}
        )
        assert invoke.call_count == 1
        assert invoke.call_args.args == (project, "list_programs", {}, None)
        assert ("timing" in invoke.call_args.kwargs) is timing_enabled
        project.get_program.assert_not_called()
        assert len([line for line in stderr.getvalue().splitlines()
                    if line.startswith("GHIDRAMSC_MCP_TIMING ")]) == (
            len(responses) - 2 if timing_enabled else 0
        )

    def test_read_message(self):
        from ghidramsc.mcp_transport import _read_message
        stream = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        msg = _read_message(stream)
        assert msg["method"] == "ping"

    def test_read_eof(self):
        from ghidramsc.mcp_transport import _read_message
        stream = io.StringIO("")
        assert _read_message(stream) is None

    @pytest.mark.parametrize("line", ["\n", " \t\r\n"])
    def test_read_blank_line(self, line):
        from ghidramsc.mcp_transport import _read_message
        stream = io.StringIO(line)
        with pytest.raises(json.JSONDecodeError):
            _read_message(stream)

    def test_write_message(self):
        from ghidramsc.mcp_transport import _write_message
        stream = io.StringIO()
        _write_message({"jsonrpc": "2.0", "id": 1, "result": {}}, stream)
        output = stream.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["id"] == 1

    def test_loop_persists_negotiated_version(self):
        from ghidramsc import mcp_transport

        input_stream = io.StringIO(
            json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            }) + "\n" + json.dumps({
                "jsonrpc": "2.0", "id": 2, "method": "tools/list",
                "params": {},
            }) + "\n"
        )
        output_stream = io.StringIO()
        with (
            mock.patch.object(mcp_transport.sys, "stdin", input_stream),
            mock.patch.object(mcp_transport.sys, "stdout", output_stream),
        ):
            mcp_transport._mcp_loop(mock.MagicMock(), None)

        responses = [
            json.loads(line) for line in output_stream.getvalue().splitlines()
        ]
        assert responses[0]["result"]["protocolVersion"] == "2024-11-05"
        assert all(
            "annotations" not in tool
            for tool in responses[1]["result"]["tools"]
        )


# -------------------------------------------------------------------
# CLI mcp subcommand argparse
# -------------------------------------------------------------------

class TestMCPParser:
    @pytest.fixture()
    def parser(self):
        from ghidramsc.cli import build_parser
        return build_parser()

    def test_mcp_basic(self, parser):
        ns = parser.parse_args(["mcp", "-b", "firmware.bin"])
        assert ns.command == "mcp"
        assert ns.binary == "firmware.bin"
        assert ns.mode == "headless"
        assert callable(ns.func)

    @pytest.mark.parametrize("mode", ["headless", "gui"])
    def test_mcp_explicit_mode(self, parser, mode):
        ns = parser.parse_args(["mcp", "--mode", mode])
        assert ns.mode == mode

    def test_mcp_mode_and_legacy_plugin_are_mutually_exclusive(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["mcp", "--mode", "gui", "--plugin"])

    def test_mcp_with_config(self, parser):
        ns = parser.parse_args(["mcp", "-b", "fw.bin", "-c", "my.toml"])
        assert ns.config == "my.toml"

    def test_mcp_with_owner(self, parser):
        ns = parser.parse_args(["mcp", "--owner", "patrick"])
        assert ns.owner == "patrick"

    def test_mcp_missing_binary_defaults_none(self, parser):
        """Omitting -b is allowed at parse time (env var fallback)."""
        ns = parser.parse_args(["mcp"])
        assert ns.binary is None

    @pytest.mark.parametrize(
        ("args", "expected"),
        [
            (["mcp"], "all"),
            (["mcp", "-t", "minimal"], "minimal"),
            (["mcp", "--toolset", "default"], "default"),
        ],
    )
    def test_mcp_toolset_argument(self, parser, args, expected):
        assert parser.parse_args(args).toolset == expected


class TestPluginStartup:
    def test_owner_is_rejected_before_plugin_construction(self):
        from ghidramsc import mcp_transport

        with mock.patch.object(
            mcp_transport, "PluginProjectHandle"
        ) as plugin_handle:
            with pytest.raises(ValueError, match="owner requires headless"):
                mcp_transport.run_mcp(plugin=True, owner="patrick")

        plugin_handle.assert_not_called()

    def test_explicit_limit_is_applied_and_logged(self, capsys):
        from ghidramsc import mcp_transport

        project = mock.MagicMock()
        project.effective_max_clients = 9
        project.ping.return_value = True
        with mock.patch.object(
            mcp_transport, "PluginProjectHandle", return_value=project
        ) as handle_type, mock.patch.object(
            mcp_transport, "_mcp_loop"
        ) as loop:
            mcp_transport.run_mcp(
                binary="firmware.bin",
                plugin=True,
                plugin_host="127.0.0.2",
                plugin_port=19100,
                max_clients=9,
            )

        handle_type.assert_called_once_with(
            host="127.0.0.2", port=19100, max_clients=9
        )
        loop.assert_called_once()
        loop_project, loop_binary, selection = loop.call_args.args
        assert loop_project is project
        assert loop_binary == "firmware.bin"
        assert selection.name == "all"
        assert selection.mode == "plugin"
        project.close.assert_called_once_with()
        stderr = capsys.readouterr().err
        assert "toolset=all" in stderr
        assert "plugin listener max clients=9" in stderr


class TestHeadlessStartup:
    def test_owner_is_forwarded_to_bridge(self):
        from ghidramsc import mcp_transport

        config = object()
        project = mock.MagicMock()
        bridge = mock.MagicMock()
        bridge.open_project.return_value.__enter__.return_value = project
        with mock.patch.object(
            mcp_transport, "GhidraBridge", return_value=bridge
        ) as bridge_type, mock.patch.object(
            mcp_transport, "_mcp_loop"
        ) as loop:
            mcp_transport.run_mcp(config=config, owner="patrick")

        bridge_type.assert_called_once_with(config, owner="patrick")
        loop.assert_called_once()

    def test_invalid_toolset_fails_before_runtime_construction(self):
        from ghidramsc import mcp_transport

        with mock.patch.object(
            mcp_transport, "PluginProjectHandle"
        ) as plugin_handle, mock.patch.object(
            mcp_transport, "GhidraBridge"
        ) as bridge:
            with pytest.raises(ValueError, match="without a path"):
                mcp_transport.run_mcp(plugin=True, toolset="../minimal")

        plugin_handle.assert_not_called()
        bridge.assert_not_called()

    def test_capacity_rejection_aborts_before_mcp_loop(self):
        from ghidramsc import mcp_transport
        from ghidramsc.bridge_plugin import PluginCapacityError

        project = mock.MagicMock()
        project.ping.side_effect = PluginCapacityError(
            "client capacity reached", 12
        )
        with mock.patch.object(
            mcp_transport, "PluginProjectHandle", return_value=project
        ), mock.patch.object(mcp_transport, "_mcp_loop") as loop:
            with pytest.raises(PluginCapacityError, match="capacity"):
                mcp_transport.run_mcp(plugin=True)

        loop.assert_not_called()
        project.close.assert_called_once_with()

    def test_failed_health_check_closes_slot_and_aborts(self):
        from ghidramsc import mcp_transport

        project = mock.MagicMock()
        project.ping.return_value = False
        with mock.patch.object(
            mcp_transport, "PluginProjectHandle", return_value=project
        ), mock.patch.object(mcp_transport, "_mcp_loop") as loop:
            with pytest.raises(ConnectionError, match="health check"):
                mcp_transport.run_mcp(plugin=True)

        loop.assert_not_called()
        project.close.assert_called_once_with()


# -------------------------------------------------------------------
# Dispatch
# -------------------------------------------------------------------

class TestMCPDispatch:
    def test_dispatch_table_has_entries(self):
        from ghidramsc.mcp_transport import _DISPATCH
        assert "decompile_function" in _DISPATCH
        assert "list_functions" in _DISPATCH

    def test_invoke_tool_unknown(self):
        from ghidramsc.mcp_transport import _invoke_tool
        project = mock.MagicMock()
        project.get_program.return_value = mock.MagicMock()
        with pytest.raises(ValueError, match="Unknown tool"):
            _invoke_tool(project, "nonexistent", {}, "bin.so")

    def test_invoke_tool_passes_args(self):
        from ghidramsc.mcp_transport import _invoke_tool, _DISPATCH
        ctx = mock.MagicMock()
        project = mock.MagicMock()
        project.get_program.return_value = ctx
        def _fake(ctx, addr_hex=""):
            return "result_{}".format(addr_hex)
        spy = mock.MagicMock(side_effect=_fake)
        spy.__signature__ = __import__("inspect").signature(_fake)
        with mock.patch.dict(_DISPATCH, {"decompile_function": spy}):
            result = _invoke_tool(project, "decompile_function", {"addr_hex": "0xABC"}, "test.so")
        spy.assert_called_once_with(ctx, addr_hex="0xABC")

    def test_create_structure_forwards_category_path_headlessly(self):
        from ghidramsc.mcp_transport import _invoke_tool, _DISPATCH

        ctx = mock.MagicMock()
        project = mock.MagicMock()
        project.get_program.return_value = ctx

        def _fake(ctx, name, size=0, category_path="/"):
            return category_path

        spy = mock.MagicMock(side_effect=_fake)
        spy.__signature__ = __import__("inspect").signature(_fake)
        with mock.patch.dict(_DISPATCH, {"create_structure": spy}):
            result = _invoke_tool(project, "create_structure", {
                "name": "Packet", "size": 8,
                "category_path": "/analysis/types",
            }, "sample.bin")
        assert result == "/analysis/types"
        spy.assert_called_once_with(
            ctx, name="Packet", size=8,
            category_path="/analysis/types",
        )


# -------------------------------------------------------------------
# Plugin-mode dispatch
# -------------------------------------------------------------------

class TestPluginModeDispatch:
    """Verify _invoke_tool routes through PluginProjectHandle."""

    def test_invoke_plugin_forwards_command(self):
        from ghidramsc.mcp_transport import _invoke_tool
        from ghidramsc.bridge_plugin import PluginProjectHandle

        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = "decompiled code"
        # isinstance check relies on spec=
        result = _invoke_tool(
            project, "decompile_function",
            {"addr_hex": "0x1000", "binary": "sample.bin"}, "default.so"
        )
        project.invoke.assert_called_once_with(
            "decompile_function", "sample.bin", {"addr_hex": "0x1000"}
        )
        assert result == "decompiled code"

    def test_invoke_plugin_uses_default_binary(self):
        from ghidramsc.mcp_transport import _invoke_tool
        from ghidramsc.bridge_plugin import PluginProjectHandle

        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = "ok"
        _invoke_tool(project, "list_functions", {}, "sample.bin")
        project.invoke.assert_called_once_with(
            "list_functions", "sample.bin", {}
        )

    def test_create_structure_forwards_category_path_to_plugin(self):
        from ghidramsc.mcp_transport import _invoke_tool
        from ghidramsc.bridge_plugin import PluginProjectHandle

        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = {"status": "success"}
        args = {
            "name": "Packet", "size": 8,
            "category_path": "/analysis/types",
        }
        _invoke_tool(project, "create_structure", dict(args), "sample.bin")
        project.invoke.assert_called_once_with(
            "create_structure", "sample.bin", args
        )

    def test_invoke_plugin_list_programs_no_binary_needed(self):
        from ghidramsc.mcp_transport import _invoke_tool
        from ghidramsc.bridge_plugin import PluginProjectHandle

        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = {"programs": ["sample.bin"]}
        result = _invoke_tool(project, "list_programs", {}, None)
        project.invoke.assert_called_once_with("list_programs", None, {})
        assert "programs" in result

    def test_invoke_plugin_no_binary_raises(self):
        from ghidramsc.mcp_transport import _invoke_tool
        from ghidramsc.bridge_plugin import PluginProjectHandle

        project = mock.MagicMock(spec=PluginProjectHandle)
        with pytest.raises(ValueError, match="No binary specified"):
            _invoke_tool(project, "decompile_function", {"addr_hex": "0x1"}, None)

    def test_invoke_plugin_per_call_binary_overrides(self):
        from ghidramsc.mcp_transport import _invoke_tool
        from ghidramsc.bridge_plugin import PluginProjectHandle

        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = "ok"
        _invoke_tool(
            project, "decompile_function",
            {"addr_hex": "0x1", "binary": "libsample.so"}, "sample.bin"
        )
        project.invoke.assert_called_once_with(
            "decompile_function", "libsample.so", {"addr_hex": "0x1"}
        )

    def test_handle_message_tools_call_plugin(self):
        """End-to-end: tools/call through _handle_message in plugin mode."""
        from ghidramsc.mcp_transport import _handle_message
        from ghidramsc.bridge_plugin import PluginProjectHandle

        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = "result text"
        msg = {
            "jsonrpc": "2.0", "id": 42,
            "method": "tools/call",
            "params": {
                "name": "list_functions",
                "arguments": {"binary": "sample.bin"},
            },
        }
        resp = _handle_message(msg, project, None)
        assert resp["id"] == 42
        assert resp["result"]["isError"] is False
        assert "result text" in resp["result"]["content"][0]["text"]

    @pytest.mark.parametrize(
        ("failed_tool", "arguments", "failure"),
        [
            ("list_programs", {}, ConnectionError("socket lost")),
            (
                "set_function_name",
                {"binary": "fw.bin", "addr_hex": "0x1000",
                 "new_name": "renamed"},
                AmbiguousMutationResultError(
                    "mutation outcome unknown; inspect program state"
                ),
            ),
        ],
    )
    def test_loop_keeps_catalog_and_later_read_after_bridge_failure(
        self, failed_tool, arguments, failure
    ):
        from ghidramsc.bridge_plugin import PluginProjectHandle
        from ghidramsc import mcp_transport

        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.side_effect = [failure, {"programs": ["fw.bin"]}]
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": failed_tool, "arguments": arguments}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
             "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "list_programs", "arguments": {}}},
        ]
        stdin = io.StringIO("".join(json.dumps(item) + "\n" for item in messages))
        stdout = io.StringIO()
        with mock.patch.object(mcp_transport.sys, "stdin", stdin), \
                mock.patch.object(mcp_transport.sys, "stdout", stdout):
            mcp_transport._mcp_loop(project, None)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert [response["id"] for response in responses] == [1, 2, 3]
        assert responses[0]["result"]["isError"] is True
        assert str(failure) in responses[0]["result"]["content"][0]["text"]
        assert any(tool["name"] == "list_programs"
                   for tool in responses[1]["result"]["tools"])
        assert responses[2]["result"]["isError"] is False
        assert project.invoke.call_count == 2

    @pytest.mark.parametrize(
        ("result_status", "old", "stored", "error", "is_error"),
        [
            (
                "success",
                {"address": "00000100", "name": "old_name"},
                {"address": "00000100", "name": "new_name"},
                None, False,
            ),
            (
                "no_change",
                {"address": "00000100", "name": "new_name"},
                {"address": "00000100", "name": "new_name"},
                None, False,
            ),
            (
                "validation_failed", None, None,
                "No function at or containing 0x100", True,
            ),
        ],
    )
    def test_plugin_rename_returns_shared_contract_unchanged(
        self, result_status, old, stored, error, is_error
    ):
        from ghidramsc.mcp_transport import _handle_message
        from ghidramsc.bridge_plugin import PluginProjectHandle

        contract = {
            "operation": "set_function_name",
            "status": result_status,
            "requested": {"address": "0x100", "name": "new_name"},
            "old": old,
            "stored": stored,
            "error": error,
        }
        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = contract

        resp = _handle_message({
            "jsonrpc": "2.0", "id": 44, "method": "tools/call",
            "params": {
                "name": "set_function_name",
                "arguments": {
                    "binary": "sample.bin",
                    "addr_hex": "0x100",
                    "new_name": "new_name",
                },
            },
        }, project, None)

        project.invoke.assert_called_once_with(
            "set_function_name", "sample.bin",
            {"addr_hex": "0x100", "new_name": "new_name"},
        )
        assert resp["result"]["isError"] is is_error
        assert json.loads(resp["result"]["content"][0]["text"]) == contract

    def test_plugin_save_incomplete_is_structured_tool_error(self):
        from ghidramsc.mcp_transport import _handle_message
        from ghidramsc.bridge_plugin import PluginProjectHandle

        failure = {
            "operation": "save_program", "status": "validation_failed",
            "save": {"completed": False}, "error": "read only",
        }
        project = mock.MagicMock(spec=PluginProjectHandle)
        project.invoke.return_value = failure
        resp = _handle_message({
            "jsonrpc": "2.0", "id": 45, "method": "tools/call",
            "params": {"name": "save_program",
                       "arguments": {"binary": "sample.bin"}},
        }, project, None)
        assert resp["result"]["isError"] is True
        assert json.loads(resp["result"]["content"][0]["text"]) == failure
