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

"""U22c opt-in MCP stderr phase timing and disabled-path behavior."""

import io
import json
import re
from unittest import mock

from ghidramsc import mcp_transport
from ghidramsc.toolset_loader import resolve_toolset


def _run_loop(enabled):
    messages = [
        {"jsonrpc": "2.0", "id": "C:/private/client-id", "method": "tools/call",
         "params": {"name": "get_function_info", "arguments": {
             "addr_hex": "0x100", "binary": "private/program.exe"}}},
        None,
    ]
    project = mock.Mock()
    project.get_program.return_value = object()
    stdout = io.StringIO()
    stderr = io.StringIO()

    def query(ctx, addr_hex):
        return {"name": "example"}

    with (
        mock.patch.object(mcp_transport, "_read_message", side_effect=messages),
        mock.patch.dict(mcp_transport._DISPATCH, {"get_function_info": query}),
        mock.patch.object(mcp_transport.sys, "stdout", stdout),
        mock.patch.object(mcp_transport.sys, "stderr", stderr),
    ):
        mcp_transport._mcp_loop(
            project, None, resolve_toolset("all", "headless"), enabled
        )
    return stdout.getvalue(), stderr.getvalue()


def test_opt_in_timing_preserves_response_and_excludes_request_contents():
    normal_stdout, normal_stderr = _run_loop(False)
    timed_stdout, timed_stderr = _run_loop(True)
    assert json.loads(normal_stdout) == json.loads(timed_stdout)
    assert "GHIDRAMSC_MCP_TIMING" not in normal_stderr
    events = [json.loads(line.split(" ", 1)[1]) for line in timed_stderr.splitlines()
              if line.startswith("GHIDRAMSC_MCP_TIMING ")]
    assert len(events) == 1
    event = events[0]
    assert event["schema"] == "ghidramsc.mcp.timing.v1"
    assert re.fullmatch(r"[0-9a-f]{16}", event["request_id"])
    assert event["request_id"] != "C:/private/client-id"
    assert event["mode"] == "headless"
    assert event["program_acquisition_observable"] is True
    assert set(event["phase_ms"]) == {
        "dispatch", "program_acquisition", "query", "serialization",
        "write_flush",
    }
    assert all(value >= 0 for value in event["phase_ms"].values())
    assert event["total_ms"] >= 0
    assert "private" not in timed_stderr
    assert "0x100" not in timed_stderr


def test_disabled_path_avoids_clock_and_opaque_id_generation():
    with (
        mock.patch.object(mcp_transport.time, "perf_counter_ns",
                          side_effect=AssertionError("clock used")),
        mock.patch.object(mcp_transport.secrets, "token_hex",
                          side_effect=AssertionError("ID generated")),
    ):
        stdout, stderr = _run_loop(False)
    assert json.loads(stdout)["result"]["isError"] is False
    assert "GHIDRAMSC_MCP_TIMING" not in stderr


def test_plugin_timing_marks_acquisition_unobservable():
    timing = mcp_transport._MCPRequestTiming("aabbccddeeff0011", 0, "plugin")
    timing.record("query", 5_000_000)
    event = timing.event()
    assert event["phase_ms"]["query"] == 5.0
    assert event["program_acquisition_observable"] is False
