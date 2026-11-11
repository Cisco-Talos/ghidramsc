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

"""U22a MCP failure categories preserve existing result bodies."""

import json
from unittest import mock

import pytest

from ghidramsc import mcp_transport
from ghidramsc.toolset_loader import resolve_toolset


@pytest.mark.parametrize("protocol", ["2025-03-26", "2025-06-18"])
@pytest.mark.parametrize(
    ("name", "arguments", "returned", "category"),
    [
        ("get_function_info", {"addr_hex": "0x100"},
         {"error": "No function at or containing 0x100"}, "not_found"),
        ("get_data_at_address", {"addr_hex": "0x100"},
         "ERROR: No defined data at 0x100", "not_found"),
        ("get_function_info", {"addr_hex": "0x100"},
         {"error": "Backend unavailable"}, "application_failure"),
    ],
)
def test_returned_failure_category_preserves_body(
    protocol, name, arguments, returned, category
):
    state = mcp_transport._MCPConnectionState(
        protocol_version=protocol, initialized=True
    )
    with mock.patch.object(mcp_transport, "_invoke_tool", return_value=returned):
        response = mcp_transport._handle_message({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }, object(), "sample.bin", resolve_toolset("all", "headless"), state)
    result = json.loads(json.dumps(response))["result"]
    assert result["isError"] is True
    assert result["_meta"] == {"ghidramsc/errorCategory": category}
    expected_text = (json.dumps(returned, indent=2) if isinstance(returned, dict)
                     else returned)
    assert result["content"] == [{"type": "text", "text": expected_text}]
    if isinstance(returned, dict) and protocol == "2025-06-18":
        assert result["structuredContent"] == returned
    else:
        assert "structuredContent" not in result


@pytest.mark.parametrize("protocol", ["2025-03-26", "2025-06-18"])
def test_validation_unavailable_and_exception_categories(protocol):
    state = mcp_transport._MCPConnectionState(
        protocol_version=protocol, initialized=True
    )
    selection = resolve_toolset("all", "headless")

    def call(name, arguments):
        return mcp_transport._handle_message({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }, object(), "sample.bin", selection, state)["result"]

    with mock.patch.object(mcp_transport, "_invoke_tool") as invoke:
        validation = call("get_function_info", {})
        unavailable = call("get_cursor_address", {})
        unknown = call("not_a_tool", {})
        invoke.assert_not_called()
    assert validation["_meta"]["ghidramsc/errorCategory"] == "validation"
    assert validation["isError"] is True
    assert json.loads(validation["content"][0]["text"])["status"] == "validation_failed"
    assert ("structuredContent" in validation) is (protocol == "2025-06-18")
    for result in (unavailable, unknown):
        assert result["isError"] is True
        assert result["_meta"]["ghidramsc/errorCategory"] == "unavailable_tool"
        assert "structuredContent" not in result

    with mock.patch.object(mcp_transport, "_invoke_tool", side_effect=RuntimeError("boom")):
        caught = call("get_function_info", {"addr_hex": "0x100"})
    assert caught["content"] == [{"type": "text", "text": "Error: boom"}]
    assert caught["isError"] is True
    assert caught["_meta"]["ghidramsc/errorCategory"] == "exception"
    assert "structuredContent" not in caught
