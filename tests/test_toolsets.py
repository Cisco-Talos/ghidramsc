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

"""Executable tests for packaged MCP toolset selection."""

from __future__ import annotations

from pathlib import Path

import pytest


PLUGIN_ONLY = {
    "get_cursor_address",
    "get_function_at_cursor",
    "get_gui_selection",
    "set_cursor_address",
    "undo_gui_transaction",
}

CURATED_PROFILE_SHAPES = {
    "minimal": (5, 5, 0),
    "inspect": (20, 20, 0),
    "default": (44, 25, 19),
    "vuln-research": (59, 32, 27),
    "most": (75, 34, 41),
}

MOST_EXCLUDED = PLUGIN_ONLY | {
    "list_enums",
    "get_enum",
    "list_bookmarks",
    "create_bookmark",
    "delete_bookmark",
    "create_union",
    "set_union_field",
    "set_composite_bitfield",
    "delete_composite_field",
    "set_composite_layout",
}


def _resource_root(tmp_path: Path, content: str, name: str = "testset") -> Path:
    package = tmp_path / "ghidramsc"
    toolsets = package / "toolsets"
    toolsets.mkdir(parents=True)
    (toolsets / "{}.txt".format(name)).write_bytes(content.encode("utf-8"))
    return package


class TestPackagedProfiles:
    def test_minimal_is_exact_five_tool_orientation_surface(self):
        from ghidramsc.toolset_loader import resolve_toolset

        selection = resolve_toolset("minimal", "headless")

        assert selection.requested_names == (
            "list_programs",
            "get_program_info",
            "list_strings",
            "list_functions",
            "decompile_function",
        )
        assert selection.requested_names == selection.effective_names
        assert selection.omitted_unavailable == ()

    def test_curated_profiles_are_nested_mode_stable_and_well_shaped(self):
        from ghidramsc.tool_registry import get_tool
        from ghidramsc.toolset_loader import resolve_toolset

        previous = frozenset()
        for name, (total, queries, mutations) in CURATED_PROFILE_SHAPES.items():
            plugin = resolve_toolset(name, "plugin")
            headless = resolve_toolset(name, "headless")
            categories = [
                get_tool(tool_name)["category"]
                for tool_name in plugin.requested_names
            ]

            assert len(plugin.requested_names) == total
            assert categories.count("query") == queries
            assert categories.count("mutation") == mutations
            assert previous < plugin.requested_set
            assert plugin.requested_names == plugin.effective_names
            assert headless.requested_names == headless.effective_names
            assert headless.requested_set == plugin.requested_set
            assert plugin.omitted_unavailable == ()
            assert headless.omitted_unavailable == ()
            previous = plugin.requested_set

    def test_default_contains_report_and_code_recovery_operations(self):
        from ghidramsc.toolset_loader import resolve_toolset

        selection = resolve_toolset("default", "headless")

        assert {
            "set_function_name",
            "set_variable_name_by_id",
            "set_function_prototype",
            "set_function_noreturn",
            "set_instruction_flow_override",
            "set_data_label",
            "apply_data_type",
            "set_comment_at_address",
            "create_function",
            "set_function_body",
            "disassemble_memory",
            "clear_code_units",
            "write_memory_bytes",
            "save_program",
        }.issubset(selection.requested_set)

    def test_most_is_registry_except_documented_specialized_families(self):
        from ghidramsc.tool_registry import all_tool_names
        from ghidramsc.toolset_loader import resolve_toolset

        selection = resolve_toolset("most", "plugin")

        assert set(all_tool_names()) - selection.requested_set == MOST_EXCLUDED

    def test_virtual_all_uses_registry_order_and_mode_metadata(self):
        from ghidramsc.tool_registry import all_tool_names
        from ghidramsc.toolset_loader import resolve_toolset

        registry_names = tuple(all_tool_names())
        plugin = resolve_toolset("all", "plugin")
        headless = resolve_toolset("all", "headless")

        assert plugin.source == "virtual:all"
        assert plugin.effective_names == registry_names
        assert set(headless.omitted_unavailable) == PLUGIN_ONLY
        assert headless.effective_names == tuple(
            name for name in registry_names if name not in PLUGIN_ONLY
        )


class TestToolsetParsing:
    @pytest.mark.parametrize(
        "name",
        ["Default", "default.txt", "./default", "toolsets/default", "C:-bad"],
    )
    def test_selector_rejects_non_names(self, name):
        from ghidramsc.toolset_loader import ToolsetError, resolve_toolset

        with pytest.raises(ToolsetError, match="without a path"):
            resolve_toolset(name, "plugin")

    def test_utf8_bom_comments_crlf_and_final_line(self, tmp_path, monkeypatch):
        from ghidramsc import toolset_loader

        package = _resource_root(
            tmp_path,
            "\ufeff# comment\r\nlist_programs  # orientation\r\n\r\n"
            "decompile_function\t# semantic view",
        )
        monkeypatch.setattr(toolset_loader.resources, "files", lambda _: package)

        selection = toolset_loader.resolve_toolset("testset", "headless")
        assert selection.requested_names == ("list_programs", "decompile_function")

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            ("", "enables no tools"),
            ("# only a comment\n", "enables no tools"),
            ("  # only a comment\n", "enables no tools"),
            ("list_programs\nlist_programs\n", "repeats tool"),
            ("not_a_real_tool\n", "unknown tool"),
            ("list_programs#old\n", "unknown tool"),
        ],
    )
    def test_invalid_content_fails(self, tmp_path, monkeypatch, content, message):
        from ghidramsc import toolset_loader

        package = _resource_root(tmp_path, content)
        monkeypatch.setattr(toolset_loader.resources, "files", lambda _: package)

        with pytest.raises(toolset_loader.ToolsetError, match=message):
            toolset_loader.resolve_toolset("testset", "plugin")

    def test_inline_comment_keeps_duplicate_physical_lines(self, tmp_path, monkeypatch):
        from ghidramsc import toolset_loader

        package = _resource_root(
            tmp_path, "list_programs # first\n# section\nlist_programs # again\n"
        )
        monkeypatch.setattr(toolset_loader.resources, "files", lambda _: package)

        with pytest.raises(toolset_loader.ToolsetError) as exc_info:
            toolset_loader.resolve_toolset("testset", "plugin")
        message = str(exc_info.value)
        assert "ghidramsc/toolsets/testset.txt" in message
        assert "repeats tool 'list_programs' at line 3; first seen at line 1" in message

    def test_unknown_name_does_not_fall_back(self):
        from ghidramsc.toolset_loader import ToolsetError, resolve_toolset

        with pytest.raises(ToolsetError, match="was not found"):
            resolve_toolset("missing", "plugin")

    def test_unknown_mode_fails(self):
        from ghidramsc.toolset_loader import ToolsetError, resolve_toolset

        with pytest.raises(ToolsetError, match="execution mode"):
            resolve_toolset("all", "other")
