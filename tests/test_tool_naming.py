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

"""Canonical public-tool naming and clean-break checks."""

from __future__ import annotations

import json
import re
from unittest import mock

import pytest


LEGACY_RENAMED_TOOL_NAMES = (
    "get_current_address",
    "get_current_function",
    "get_current_selection",
    "navigate_to",
    "undo",
    "read_bytes",
    "get_data_at",
    "get_stack_frame",
    "decompile",
    "xrefs_to",
    "xrefs_from",
    "listing",
    "func_info",
    "strings",
    "search_mem",
    "search_hex",
    "find_func",
    "batch_decompile",
    "func_vars",
    "func_var_identities",
    "is_program_dirty",
    "get_memory_map",
    "list_imports",
    "list_exports",
    "list_namespaces",
    "list_classes",
    "get_segments",
    "get_comment",
    "get_bookmarks",
    "generate_call_graph",
    "get_basic_blocks",
    "get_function_xrefs",
    "rename_func",
    "batch_rename",
    "remove_func",
    "set_func_body",
    "create_func",
    "create_stack_var",
    "delete_stack_var",
    "apply_stack_structure",
    "bulk_create_funcs",
    "disassemble_at",
    "rename_var",
    "retype_var",
    "rename_var_by_id",
    "retype_var_by_id",
    "create_var_by_id",
    "delete_var_by_id",
    "set_return_type",
    "annotate_func",
    "set_comment",
    "set_bookmark",
    "remove_bookmark",
    "rename_structure",
    "patch_bytes",
    "set_calling_convention",
    "rename_data",
    "set_image_base",
    "set_memory_permissions",
)


def test_canonical_names_follow_accepted_grammar_and_vocabulary():
    allowed_verbs = {
        "get", "list", "read", "search", "is", "has", "export",
        "create", "set", "delete", "apply", "write", "import",
        "save", "decompile", "disassemble", "clear", "undo",
    }
    prohibited_verbs = {"update", "rename", "retype", "remove", "find", "generate", "batch", "bulk"}
    prohibited_abbreviations = {"func", "var", "mem", "xref", "xrefs"}

    from ghidramsc.tool_registry import all_tool_names

    for name in all_tool_names():
        assert re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", name)
        words = name.split("_")
        assert words[0] in allowed_verbs
        assert words[0] not in prohibited_verbs
        assert prohibited_abbreviations.isdisjoint(words)


@pytest.mark.parametrize("legacy_name", LEGACY_RENAMED_TOOL_NAMES)
def test_legacy_names_are_not_registry_aliases(legacy_name):
    from ghidramsc.tool_registry import get_tool

    with pytest.raises(KeyError):
        get_tool(legacy_name)


def test_representative_legacy_name_is_rejected_by_cli_http_and_mcp():
    from ghidramsc.cli import build_parser
    from ghidramsc.mcp_transport import _handle_message
    from ghidramsc.server import _invoke

    with pytest.raises(SystemExit):
        build_parser().parse_args(["decompile", "-b", "sample.bin", "0x1000"])

    project = mock.MagicMock()
    with pytest.raises(ValueError, match="Unknown command"):
        _invoke(project, "decompile", {"addr_hex": "0x1000"}, "sample.bin")
    project.get_program.assert_not_called()

    response = _handle_message({
        "jsonrpc": "2.0",
        "id": 16,
        "method": "tools/call",
        "params": {"name": "decompile", "arguments": {"addr_hex": "0x1000"}},
    }, project, "sample.bin")
    project.get_program.assert_not_called()
    assert response["result"]["isError"] is True
    failure = json.loads(response["result"]["content"][0]["text"])
    assert failure["status"] == "validation_failed"
    assert "Unknown command" in failure["error"]
