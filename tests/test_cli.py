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

"""Tests for ghidramsc.cli -- argparse construction and handler wiring."""

from __future__ import annotations

import argparse
import importlib
import json
from contextlib import contextmanager
from unittest import mock
import pytest

from ghidramsc.cli import build_parser, _resolve_binary
from ghidramsc import _cli_commands as cli_commands, _cli_execution as cli_execution


def test_cli_function_ranges_preserve_qualified_overlay_endpoints():
    assert cli_commands._cli_function_ranges([
        "recovered::00101faf:recovered::00102683",
        "0x1000:recovered::00102000",
        "0x2000:0x20ff",
    ]) == [
        {"start": "recovered::00101faf", "end": "recovered::00102683"},
        {"start": "0x1000", "end": "recovered::00102000"},
        {"start": "0x2000", "end": "0x20ff"},
    ]


@pytest.mark.parametrize("value", [
    "recovered::00101faf", "0x1000:0x2000:0x3000", ":0x2000",
    "0x1000:", "recovered:::00102683",
])
def test_cli_function_ranges_reject_missing_or_ambiguous_separator(value):
    with pytest.raises(ValueError, match="START:END"):
        cli_commands._cli_function_ranges([value])


class TestResolveBinary:
    """Verify _resolve_binary env-var fallback."""

    def test_flag_wins(self, monkeypatch):
        monkeypatch.delenv("GHIDRAMSC_BINARY", raising=False)
        ns = argparse.Namespace(binary="from_flag")
        assert _resolve_binary(ns) == "from_flag"

    def test_env_fallback(self, monkeypatch):
        monkeypatch.setenv("GHIDRAMSC_BINARY", "from_env")
        ns = argparse.Namespace(binary=None)
        assert _resolve_binary(ns) == "from_env"

    def test_flag_over_env(self, monkeypatch):
        monkeypatch.setenv("GHIDRAMSC_BINARY", "from_env")
        ns = argparse.Namespace(binary="from_flag")
        assert _resolve_binary(ns) == "from_flag"

    def test_neither_exits(self, monkeypatch):
        monkeypatch.delenv("GHIDRAMSC_BINARY", raising=False)
        ns = argparse.Namespace(binary=None)
        with pytest.raises(SystemExit):
            _resolve_binary(ns)

    def test_not_required_returns_none(self, monkeypatch):
        """When required=False, missing binary returns None (for serve/mcp)."""
        monkeypatch.delenv("GHIDRAMSC_BINARY", raising=False)
        ns = argparse.Namespace(binary=None)
        assert _resolve_binary(ns, required=False) is None

    def test_not_required_still_resolves_env(self, monkeypatch):
        monkeypatch.setenv("GHIDRAMSC_BINARY", "from_env")
        ns = argparse.Namespace(binary=None)
        assert _resolve_binary(ns, required=False) == "from_env"


def test_open_bridge_forwards_owner(monkeypatch):
    from ghidramsc import cli

    config = object()
    bridge = object()
    bridge_type = mock.MagicMock(return_value=bridge)
    monkeypatch.setattr(cli_execution, "load_config", lambda _: config)
    monkeypatch.setattr(cli_execution, "GhidraBridge", bridge_type)

    actual, actual_config = cli._open_bridge(
        argparse.Namespace(config=None, owner="patrick")
    )

    assert actual is bridge
    assert actual_config is config
    bridge_type.assert_called_once_with(config, owner="patrick")


class TestBuildParser:
    """Verify that argparse is wired correctly for all subcommands."""

    @pytest.fixture()
    def parser(self):
        return build_parser()

    @pytest.mark.parametrize(
        "command, operands, expected",
        [
            # Shared query and mutation command smoke cases.
            pytest.param(
                'list_functions', [], {'command': 'list_functions'},
                id='list_functions',
            ),
            pytest.param(
                'list_references_to_address', ['0xdead'], {'address': '0xdead'},
                id='xrefs_to',
            ),
            pytest.param(
                'list_references_from_address', ['0xbeef'], {'address': '0xbeef'},
                id='xrefs_from',
            ),
            pytest.param(
                'search_memory_text', ['AAAA'], {'pattern': 'AAAA'},
                id='search_mem',
            ),
            pytest.param(
                'search_memory_bytes', ['e92d4830'], {'hex_bytes': 'e92d4830'},
                id='search_hex',
            ),
            pytest.param(
                'search_functions_by_name', ['main.*'], {'pattern': 'main.*'},
                id='find_func',
            ),
            pytest.param(
                'set_function_name', ['0x100', 'my_func'], {'address': '0x100', 'name': 'my_func'},
                id='rename_func',
            ),
            pytest.param(
                'set_function_names', ['renames.json'], {'json_path': 'renames.json'},
                id='batch_rename',
            ),
            pytest.param(
                'delete_function', ['0x200'], {'address': '0x200'},
                id='remove_func',
            ),
            pytest.param(
                'create_functions', ['funcs.json'], {'json_path': 'funcs.json'},
                id='bulk_create_funcs',
            ),
            pytest.param(
                'export_annotations', [], {'command': 'export_annotations'},
                id='export_annotations',
            ),
            pytest.param(
                'import_annotations', ['ann.json'], {'json_path': 'ann.json'},
                id='import_annotations',
            ),
            pytest.param(
                'list_function_variables', ['0x5000'], {'address': '0x5000'},
                id='func_vars',
            ),
            pytest.param(
                'set_variable_name', ['0x5000', 'old', 'new'], {'old_name': 'old', 'new_name': 'new'},
                id='rename_var',
            ),
            pytest.param(
                'set_variable_type', ['0x5000', 'x', 'int'], {'var_name': 'x', 'type_name': 'int'},
                id='retype_var',
            ),
            pytest.param(
                'delete_variable_by_id', ['0x5000', 'high:20'], {'var_id': 'high:20'},
                id='delete_var_by_id',
            ),
            pytest.param(
                'set_function_return_type', ['0x5000', 'void'], {'type_name': 'void'},
                id='set_return_type',
            ),
            pytest.param(
                'apply_function_annotations', ['0x5000', 'ann.json'], {'json_path': 'ann.json'},
                id='annotate_func',
            ),
            pytest.param(
                'decompile_functions', ['0x1,0x2,0x3'], {'addresses': '0x1,0x2,0x3'},
                id='batch_decompile',
            ),
            pytest.param(
                'get_program_save_state', [], {'command': 'get_program_save_state'},
                id='is_program_dirty',
            ),
            # Program, data type, and memory command smoke cases.
            pytest.param(
                'get_program_memory_map', [], {'command': 'get_program_memory_map'},
                id='get_memory_map',
            ),
            pytest.param(
                'list_program_imports', [], {'command': 'list_program_imports'},
                id='list_imports',
            ),
            pytest.param(
                'list_program_exports', [], {'command': 'list_program_exports'},
                id='list_exports',
            ),
            pytest.param(
                'list_program_namespaces', [], {'command': 'list_program_namespaces'},
                id='list_namespaces',
            ),
            pytest.param(
                'list_program_classes', [], {'command': 'list_program_classes'},
                id='list_classes',
            ),
            pytest.param(
                'list_memory_blocks', [], {'command': 'list_memory_blocks'},
                id='get_segments',
            ),
            pytest.param(
                'get_comment_at_address', ['0x1000'], {'address': '0x1000'},
                id='get_comment',
            ),
            pytest.param(
                'create_bookmark', ['0x1000', 'vuln'], {'address': '0x1000', 'category': 'vuln'},
                id='set_bookmark',
            ),
            pytest.param(
                'delete_bookmark', ['0x1000', 'vuln'], {'category': 'vuln'},
                id='remove_bookmark',
            ),
            pytest.param(
                'list_structures', [], {'command': 'list_structures'},
                id='list_structures',
            ),
            pytest.param(
                'get_structure', ['my_struct'], {'name': 'my_struct'},
                id='get_structure',
            ),
            pytest.param(
                'set_structure_name', ['old', 'new'], {'old_name': 'old', 'new_name': 'new'},
                id='rename_structure',
            ),
            pytest.param(
                'delete_structure', ['my_struct'], {'name': 'my_struct'},
                id='delete_structure',
            ),
            pytest.param(
                'delete_structure_field', ['Entry', '/', '8'], {'offset': 8},
                id='delete_structure_field',
            ),
            pytest.param(
                'delete_composite_field', ['Flags', '/', '2'], {'ordinal': 2},
                id='delete_composite_field',
            ),
            pytest.param(
                'list_function_basic_blocks', ['0x1000'], {'address': '0x1000'},
                id='get_basic_blocks',
            ),
            pytest.param(
                'get_function_call_relationships', ['0x1000'], {'address': '0x1000'},
                id='get_function_xrefs',
            ),
            pytest.param(
                'write_memory_bytes', ['0x1000', '90909090'], {'address': '0x1000', 'hex_bytes': '90909090'},
                id='patch_bytes',
            ),
            pytest.param(
                'set_function_prototype', ['0x1000', 'int foo(int x)'], {'address': '0x1000', 'prototype': 'int foo(int x)'},
                id='set_function_prototype',
            ),
            pytest.param(
                'set_function_calling_convention', ['0x1000', '__stdcall'], {'convention': '__stdcall'},
                id='set_calling_convention',
            ),
            pytest.param(
                'set_data_label', ['0x3000', 'my_global'], {'address': '0x3000', 'name': 'my_global'},
                id='rename_data',
            ),
            pytest.param(
                'set_program_image_base', ['0x400000'], {'address': '0x400000'},
                id='set_image_base',
            ),
        ],
    )
    def test_routine_parser_smoke(self, parser, command, operands, expected):
        ns = parser.parse_args([command, "-b", "test.so", *operands])
        for field, value in expected.items():
            assert getattr(ns, field) == value

    def test_decompile(self, parser):
        ns = parser.parse_args(["decompile_function", "-b", "test.so", "0x1234"])
        assert ns.command == "decompile_function"
        assert ns.binary == "test.so"
        assert ns.address == "0x1234"
        assert callable(ns.func)

    def test_list_programs_is_project_level(self, parser):
        ns = parser.parse_args(["list_programs"])
        assert ns.command == "list_programs"
        assert not hasattr(ns, "binary")

    def test_exact_non_gui_registry_capabilities_have_cli_commands(self, parser):
        from ghidramsc.tool_registry import TOOLS, tool_mcp_modes

        subparsers = next(
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        commands = set(subparsers.choices)
        non_gui = {
            tool["name"] for tool in TOOLS
            if "headless" in tool_mcp_modes(tool)
        }
        gui_only = {tool["name"] for tool in TOOLS} - non_gui

        assert non_gui.issubset(commands)
        assert gui_only.isdisjoint(commands)

    def test_listing_default_count(self, parser):
        ns = parser.parse_args(["get_listing_at_address", "-b", "test.so", "0x100"])
        assert ns.count is None

    def test_listing_with_count(self, parser):
        ns = parser.parse_args(["get_listing_at_address", "-b", "test.so", "0x100", "-n", "80"])
        assert ns.count == 80

    def test_func_info(self, parser):
        ns = parser.parse_args(["get_function_info", "-b", "test.so", "0xabcd"])
        assert ns.address == "0xabcd"
        assert (ns.incoming_offset, ns.incoming_limit) == (0, 100)
        page = parser.parse_args([
            "get_function_info", "-b", "test.so", "0xabcd",
            "--incoming-offset", "4", "--incoming-limit", "2",
        ])
        assert (page.incoming_offset, page.incoming_limit) == (4, 2)

    def test_strings_no_filter(self, parser):
        ns = parser.parse_args(["list_strings", "-b", "test.so"])
        assert ns.filter is None

    def test_strings_with_filter(self, parser):
        ns = parser.parse_args(["list_strings", "-b", "test.so", "hello"])
        assert ns.filter == "hello"

    def test_save_flags_are_mutation_only(self, parser):
        ns = parser.parse_args([
            "set_function_name", "-b", "test.so", "0x100", "my_func",
            "--save", "--save-comment", "checkpoint",
        ])
        assert ns.save is True
        assert ns.save_comment == "checkpoint"
        with pytest.raises(SystemExit):
            parser.parse_args(["decompile_function", "-b", "test.so", "0x100", "--save"])

    def test_create_func_no_name(self, parser):
        ns = parser.parse_args(["create_function", "-b", "test.so", "0x200"])
        assert ns.name is None

    def test_create_func_with_name(self, parser):
        ns = parser.parse_args(["create_function", "-b", "test.so", "0x200", "--name", "foo"])
        assert ns.name == "foo"

    def test_create_func_with_explicit_ranges(self, parser):
        ns = parser.parse_args([
            "create_function", "-b", "test.so", "0x200",
            "--range", "0x200:0x20f", "--range", "0x240:0x24f",
        ])
        assert ns.ranges == ["0x200:0x20f", "0x240:0x24f"]

    def test_create_stack_var(self, parser):
        ns = parser.parse_args([
            "create_stack_variable", "-b", "test.so", "0x200",
            "-16", "saved_count", "uint", "--size", "0x4",
        ])
        assert ns.address == "0x200"
        assert ns.stack_offset == -16
        assert ns.name == "saved_count"
        assert ns.type_name == "uint"
        assert ns.size == 4

    def test_delete_stack_var(self, parser):
        ns = parser.parse_args([
            "delete_stack_variable", "-b", "test.so", "0x200", "-16",
        ])
        assert ns.address == "0x200"
        assert ns.stack_offset == -16

    def test_apply_stack_structure(self, parser):
        ns = parser.parse_args([
            "create_stack_variable_from_structure", "-b", "test.so", "0x200",
            "-32", "Header", "--category-path", "/protocol",
            "--name", "header",
        ])
        assert ns.stack_offset == -32
        assert ns.structure_name == "Header"
        assert ns.category_path == "/protocol"
        assert ns.name == "header"

    def test_set_func_body(self, parser):
        ns = parser.parse_args([
            "set_function_body", "-b", "test.so", "0x200",
            "--range", "0x200:0x20f",
        ])
        assert ns.address == "0x200"
        assert ns.ranges == ["0x200:0x20f"]

    def test_disassemble_at_no_end(self, parser):
        ns = parser.parse_args(["disassemble_memory", "-b", "test.so", "0x300"])
        assert ns.end is None

    def test_disassemble_at_with_end(self, parser):
        ns = parser.parse_args(["disassemble_memory", "-b", "test.so", "0x300", "--end", "0x400"])
        assert ns.end == "0x400"

    def test_clear_code_units_defaults_to_preview_and_requires_apply_flag(self, parser):
        preview = parser.parse_args([
            "clear_code_units", "-b", "test.so", "0x300", "0x33f",
        ])
        assert (preview.start, preview.end, preview.apply) == (
            "0x300", "0x33f", False,
        )
        apply = parser.parse_args([
            "clear_code_units", "-b", "test.so", "0x300", "0x33f", "--apply",
        ])
        assert apply.apply is True

    def test_func_var_identities_pagination_and_filter(self, parser):
        ns = parser.parse_args([
            "list_function_variable_identities", "-b", "test.so", "0x5000",
            "--offset", "100", "--limit", "25", "--filter", "stack",
        ])
        assert ns.address == "0x5000"
        assert ns.offset == 100
        assert ns.limit == 25
        assert ns.filter_str == "stack"

    def test_rename_var_by_merge_group(self, parser):
        ns = parser.parse_args([
            "set_variable_name_by_id", "-b", "test.so", "0x5000", "high:10",
            "part", "--split-use", "--merge-group-id", "merge:2",
        ])
        assert ns.split_use is True
        assert ns.merge_group_id == "merge:2"

    def test_create_var_by_id(self, parser):
        ns = parser.parse_args([
            "create_variable_by_id", "-b", "test.so", "0x5000", "high:20",
            "--name", "value", "--type-name", "uint",
        ])
        assert ns.name == "value"
        assert ns.type_name == "uint"

    def test_decompile_chunk_arguments(self, parser):
        ns = parser.parse_args([
            "decompile_function", "-b", "test.so", "0x1000",
            "--offset", "16384", "--limit", "8192",
        ])
        assert ns.offset == 16384
        assert ns.limit == 8192

    # -- New tool parser tests --

    def test_get_program_info(self, parser):
        ns = parser.parse_args(["get_program_info", "-b", "test.so"])
        assert ns.command == "get_program_info"
        assert callable(ns.func)

    def test_save_program(self, parser):
        ns = parser.parse_args([
            "save_program", "-b", "test.so", "--comment", "checkpoint"
        ])
        assert ns.comment == "checkpoint"


class TestExplicitMutationSave:
    @pytest.fixture()
    def parser(self):
        return build_parser()

    def _bridge(self, events):
        ctx = object()

        class Project:
            def get_program(self, name):
                events.append(("get", name))
                return ctx

        class Bridge:
            @contextmanager
            def open_project(self):
                events.append("open")
                try:
                    yield Project()
                finally:
                    events.append("close")

        return Bridge(), ctx

    @pytest.mark.parametrize("forwarded", [False, True])
    @pytest.mark.parametrize("save", [False, True])
    @pytest.mark.parametrize("status,expected_rc", [
        ("success", 0), ("no_change", 0),
        ("failed", 1), ("partial_success", 1),
    ])
    def test_mutation_outcome_controls_exit_and_explicit_save(
        self, monkeypatch, capsys, forwarded, save, status, expected_rc
    ):
        from ghidramsc import cli, client

        mutation = {
            "operation": "set_function_name", "status": status,
            "transaction": {"started": True, "committed": status == "failed"},
            "error": "readback mismatch" if status == "failed" else None,
        }
        persistence = {"operation": "save_program", "status": "success",
                       "save": {"completed": True}}
        events = []

        if forwarded:
            def send(command, args, binary=None):
                events.append((command, binary))
                return {"result": mutation if command == "set_function_name"
                        else persistence}

            monkeypatch.setattr(client, "send_query", send)
        else:
            ctx = object()

            class Bridge:
                @contextmanager
                def open_program(self, name):
                    yield ctx

                @contextmanager
                def open_project(self):
                    class Project:
                        def get_program(self, name):
                            return ctx
                    yield Project()

            monkeypatch.setattr(cli_execution, "load_config", mock.MagicMock())
            monkeypatch.setattr(cli_execution, "GhidraBridge", lambda config: Bridge())
            monkeypatch.setattr(cli.queries, "set_function_name",
                                lambda *args: mutation)

            def save_program(*args):
                events.append("save_program")
                return persistence

            monkeypatch.setattr(cli.queries, "save_program", save_program)

        args = ["set_function_name", "-b", "test.so", "0x100", "new_name"]
        if not forwarded:
            args.append("--no-server")
        if save:
            args.append("--save")
        assert cli.main(args) == expected_rc
        output = json.loads(capsys.readouterr().out)
        should_save = save and expected_rc == 0
        assert output == ({**mutation, "persistence": persistence}
                          if should_save else mutation)
        if forwarded:
            assert events == ([("set_function_name", "test.so"),
                               ("save_program", "test.so")]
                              if should_save else [("set_function_name", "test.so")])
        else:
            assert events == (["save_program"] if should_save else [])

    def test_direct_rename_emits_shared_contract_unchanged(
        self, monkeypatch, capsys
    ):
        from ghidramsc import cli

        contract = {
            "operation": "set_function_name",
            "status": "success",
            "requested": {"address": "0x100", "name": "new_name"},
            "old": {"address": "00000100", "name": "old_name"},
            "stored": {"address": "00000100", "name": "new_name"},
            "error": None,
        }

        class DirectBridge:
            @contextmanager
            def open_program(self, name):
                yield object()

        monkeypatch.setattr(cli_execution, "load_config", mock.MagicMock())
        monkeypatch.setattr(cli_execution, "GhidraBridge", lambda config: DirectBridge())
        monkeypatch.setattr(cli_commands, "_try_server", lambda *args: None)
        monkeypatch.setattr(cli.queries, "set_function_name", lambda *args: contract)

        rc = cli.main([
            "set_function_name", "-b", "test.so", "0x100", "new_name",
            "--no-server",
        ])

        assert rc == 0
        assert json.loads(capsys.readouterr().out) == contract

    def test_direct_save_uses_same_context_before_close(self, monkeypatch, capsys):
        from ghidramsc import cli

        events = []
        bridge, ctx = self._bridge(events)
        monkeypatch.setattr(cli_execution, "load_config", mock.MagicMock())
        monkeypatch.setattr(cli_execution, "GhidraBridge", lambda config: bridge)
        monkeypatch.setattr(
            cli.queries, "set_function_name",
            lambda actual, address, name: (
                events.append(("mutation", actual)),
                {"operation": "set_function_name", "status": "success"},
            )[1],
        )

        def save(actual, comment):
            assert actual is ctx
            assert "close" not in events
            events.append(("save", actual, comment))
            return {"operation": "save_program", "status": "success",
                    "save": {"completed": True}}

        monkeypatch.setattr(cli.queries, "save_program", save)
        rc = cli.main([
            "set_function_name", "-b", "test.so", "0x100", "new_name",
            "--no-server", "--save", "--save-comment", "checkpoint",
        ])
        output = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert output["persistence"]["status"] == "success"
        assert events[-1] == "close"

    def test_direct_save_failure_is_nonzero(self, monkeypatch, capsys):
        from ghidramsc import cli

        events = []
        bridge, _ = self._bridge(events)
        monkeypatch.setattr(cli_execution, "load_config", mock.MagicMock())
        monkeypatch.setattr(cli_execution, "GhidraBridge", lambda config: bridge)
        monkeypatch.setattr(cli.queries, "set_function_name",
                            lambda *args: {"status": "success"})
        monkeypatch.setattr(
            cli.queries, "save_program",
            lambda *args: {"operation": "save_program", "status": "failed",
                           "save": {"completed": False}, "error": "disk full"},
        )
        rc = cli.main([
            "set_function_name", "-b", "test.so", "0x100", "new_name",
            "--no-server", "--save",
        ])
        output = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert output["persistence"]["error"] == "disk full"

    def test_http_mutation_and_save_use_same_service_and_program(
        self, monkeypatch, capsys
    ):
        from ghidramsc import cli, client

        calls = []

        def send(command, args, binary=None):
            calls.append((command, args, binary))
            if command == "set_function_name":
                return {"result": {"operation": command, "status": "success"}}
            return {"result": {"operation": "save_program", "status": "success",
                               "save": {"completed": True}}}

        monkeypatch.setattr(client, "send_query", send)
        rc = cli.main([
            "set_function_name", "-b", "folder/test.so", "0x100", "new_name",
            "--save",
        ])
        output = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert [call[0] for call in calls] == ["set_function_name", "save_program"]
        assert [call[2] for call in calls] == ["folder/test.so", "folder/test.so"]
        assert output["persistence"]["save"]["completed"] is True

    def test_http_save_failure_attaches_exact_server_payload(
        self, monkeypatch, capsys
    ):
        from ghidramsc import cli, client

        failure = {
            "operation": "save_program", "status": "failed",
            "program": "test.so", "old": {}, "requested": {}, "stored": {},
            "save": {"completed": False}, "error": "disk full",
        }
        calls = []

        def send(command, args, binary=None):
            calls.append(command)
            if command == "set_function_name":
                return {"result": {"operation": command, "status": "success"}}
            raise client.ServerQueryError("Server error: disk full", failure)

        monkeypatch.setattr(client, "send_query", send)
        rc = cli.main([
            "set_function_name", "-b", "test.so", "0x100", "new_name", "--save",
        ])
        output = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert calls == ["set_function_name", "save_program"]
        assert output["persistence"] == failure

    def test_unavailable_http_save_does_not_claim_comment_support(
        self, monkeypatch, capsys
    ):
        from ghidramsc import cli, client

        calls = []

        def send(command, args, binary=None):
            calls.append(command)
            if command == "set_function_name":
                return {"result": {"operation": command, "status": "success"}}
            return None

        monkeypatch.setattr(client, "send_query", send)
        rc = cli.main([
            "set_function_name", "-b", "test.so", "0x100", "new_name",
            "--save", "--save-comment", "checkpoint",
        ])
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert calls == ["set_function_name", "save_program"]
        assert output["persistence"]["save"]["backend"] == (
            "http_service_unavailable"
        )
        assert output["persistence"]["save"]["comment_supported"] is False
        assert output["persistence"]["save"]["comment_applied"] is False

    def test_lost_http_save_response_reports_unknown(self, monkeypatch, capsys):
        from ghidramsc import cli, client

        calls = []

        def send(command, args, binary=None):
            calls.append(command)
            if command == "set_function_name":
                return {"result": {"operation": command, "status": "success"}}
            raise client.ServerResponseUnavailable(
                "No usable HTTP response for 'save_program'; outcome unknown."
            )

        monkeypatch.setattr(client, "send_query", send)
        rc = cli.main([
            "set_function_name", "-b", "test.so", "0x100", "new_name",
            "--save",
        ])
        captured = capsys.readouterr()
        assert rc == 1
        assert calls == ["set_function_name", "save_program"]
        assert captured.out == ""
        assert "save_program" in captured.err
        assert "outcome unknown" in captured.err

    def test_standalone_save_failure_is_nonzero(self, monkeypatch, capsys):
        from ghidramsc import cli, client

        failure = {
            "operation": "save_program", "status": "failed",
            "save": {"completed": False}, "error": "read only",
        }

        def fail(*args):
            raise client.ServerQueryError("Server error: read only", failure)

        monkeypatch.setattr(cli_commands, "_try_server", fail)
        ns = argparse.Namespace(
            comment="checkpoint", binary="test.so", quiet=False, output=None)
        assert cli.cmd_save_program(ns) == 1
        assert json.loads(capsys.readouterr().out) == failure

    def test_list_data_items_defaults(self, parser):
        ns = parser.parse_args(["list_data_items", "-b", "test.so"])
        assert ns.command == "list_data_items"
        assert ns.offset is None
        assert ns.limit is None

    def test_list_data_items_with_pagination(self, parser):
        ns = parser.parse_args(["list_data_items", "-b", "test.so", "--offset", "100", "--limit", "50"])
        assert ns.offset == 100
        assert ns.limit == 50

    def test_set_comment(self, parser):
        ns = parser.parse_args(["set_comment_at_address", "-b", "test.so", "0x1000", "my comment"])
        assert ns.address == "0x1000"
        assert ns.comment == "my comment"
        assert ns.comment_type is None

    def test_set_comment_with_type(self, parser):
        ns = parser.parse_args(["set_comment_at_address", "-b", "test.so", "0x1000", "test", "--type", "pre"])
        assert ns.comment_type == "pre"

    def test_set_comment_interior_opt_in(self, parser):
        ns = parser.parse_args([
            "set_comment_at_address", "-b", "test.so", "0x1002", "test",
            "--allow-containing-item",
        ])
        assert ns.allow_containing_item is True

    def test_set_bookmark_with_comment(self, parser):
        ns = parser.parse_args(["create_bookmark", "-b", "test.so", "0x1000", "vuln", "--comment", "overflow"])
        assert ns.comment == "overflow"

    def test_get_bookmarks_no_addr(self, parser):
        ns = parser.parse_args(["list_bookmarks", "-b", "test.so"])
        assert ns.address is None

    def test_get_bookmarks_with_addr(self, parser):
        ns = parser.parse_args(["list_bookmarks", "-b", "test.so", "0x1000"])
        assert ns.address == "0x1000"

    def test_get_structure_category_path(self, parser):
        ns = parser.parse_args([
            "get_structure", "-b", "test.so", "my_struct",
            "--category-path", "/protocol",
        ])
        assert ns.category_path == "/protocol"

    def test_get_composite_category_path(self, parser):
        ns = parser.parse_args([
            "get_composite", "-b", "test.so", "Flags",
            "--category-path", "/protocol",
        ])
        assert ns.name == "Flags"
        assert ns.category_path == "/protocol"

    def test_create_structure(self, parser):
        ns = parser.parse_args(["create_structure", "-b", "test.so", "new_struct"])
        assert ns.name == "new_struct"
        assert ns.size is None
        assert ns.category_path == "/"

    def test_create_structure_with_size(self, parser):
        ns = parser.parse_args([
            "create_structure", "-b", "test.so", "s", "--size", "16",
            "--category-path", "/analysis/types",
        ])
        assert ns.size == 16
        assert ns.category_path == "/analysis/types"

    def test_create_structure_forwards_category_path_to_service(
        self, monkeypatch
    ):
        from ghidramsc import cli

        seen = {}

        def try_server(command, args, ns):
            seen.update({"command": command, "args": args})
            return {"result": {"status": "success"}}

        monkeypatch.setattr(cli_commands, "_try_server", try_server)
        monkeypatch.setattr(cli_commands, "_emit_server_result", mock.MagicMock())
        ns = argparse.Namespace(
            name="Packet", size=8, category_path="/analysis/types",
            binary="sample.bin",
        )

        assert cli.cmd_create_structure(ns) == 0
        assert seen == {
            "command": "create_structure",
            "args": {
                "name": "Packet", "size": 8,
                "category_path": "/analysis/types",
            },
        }

    def test_create_structure_forwards_category_path_directly(
        self, monkeypatch
    ):
        from ghidramsc import cli

        ctx = object()

        class Bridge:
            @contextmanager
            def open_program(self, binary):
                assert binary == "sample.bin"
                yield ctx

        call = mock.MagicMock(return_value={"status": "success"})
        monkeypatch.setattr(cli_commands, "_try_server", lambda *args: None)
        monkeypatch.setattr(cli_commands, "_open_bridge", lambda ns: (Bridge(), None))
        monkeypatch.setattr(cli.queries, "create_structure", call)
        monkeypatch.setattr(cli_commands, "_emit", mock.MagicMock())
        ns = argparse.Namespace(
            name="Packet", size=None, category_path="/analysis/types",
            binary="sample.bin",
        )

        assert cli.cmd_create_structure(ns) == 0
        call.assert_called_once_with(
            ctx, name="Packet", size=0,
            category_path="/analysis/types",
        )

    def test_list_programs_uses_http_query_when_available(self, monkeypatch):
        from ghidramsc import cli

        emitted = mock.MagicMock()
        monkeypatch.setattr(
            cli_commands, "_try_server",
            lambda command, args, ns: {"programs": ["sample.bin"]},
        )
        monkeypatch.setattr(cli_commands, "_emit_server_result", emitted)
        ns = argparse.Namespace()

        assert cli.cmd_list_programs(ns) == 0
        emitted.assert_called_once_with({"programs": ["sample.bin"]}, ns)

    def test_list_programs_uses_project_directly_without_server(
        self, monkeypatch
    ):
        from ghidramsc import cli

        class Project:
            def list_programs(self):
                return ["sample.bin", "deep/tool.bin"]

        class Bridge:
            @contextmanager
            def open_project(self):
                yield Project()

        emitted = mock.MagicMock()
        monkeypatch.setattr(cli_commands, "_try_server", lambda *args: None)
        monkeypatch.setattr(cli_commands, "_open_bridge", lambda ns: (Bridge(), None))
        monkeypatch.setattr(cli_commands, "_emit", emitted)
        ns = argparse.Namespace()

        assert cli.cmd_list_programs(ns) == 0
        emitted.assert_called_once_with(
            {"programs": ["sample.bin", "deep/tool.bin"]}, ns
        )

    def test_set_structure_field(self, parser):
        ns = parser.parse_args([
            "set_structure_field", "-b", "test.so", "Entry", "/", "8",
            "handler", "pointer", "--mode", "replace",
        ])
        assert ns.offset == 8
        assert ns.field_name == "handler"

    def test_set_structure_layout(self, parser):
        ns = parser.parse_args([
            "set_structure_layout", "-b", "test.so", "Entry", "/",
            "explicit", "explicit", "--packing-value", "4",
            "--alignment-value", "4",
        ])
        assert ns.packing_value == 4
        assert ns.alignment_value == 4

    def test_create_union(self, parser):
        ns = parser.parse_args([
            "create_union", "-b", "test.so", "Value",
            "--category-path", "/protocol",
        ])
        assert ns.name == "Value"
        assert ns.category_path == "/protocol"

    def test_set_union_field(self, parser):
        ns = parser.parse_args([
            "set_union_field", "-b", "test.so", "Value", "/", "0",
            "word", "uint", "--mode", "insert",
        ])
        assert ns.ordinal == 0
        assert ns.mode == "insert"

    def test_set_composite_bitfield(self, parser):
        ns = parser.parse_args([
            "set_composite_bitfield", "-b", "test.so", "Flags", "/",
            "0", "enabled", "uint", "1", "--byte-offset", "4",
            "--storage-size", "4", "--bit-offset", "2",
        ])
        assert ns.bit_size == 1
        assert ns.byte_offset == 4
        assert ns.storage_size == 4
        assert ns.bit_offset == 2

    def test_set_composite_layout(self, parser):
        ns = parser.parse_args([
            "set_composite_layout", "-b", "test.so", "Value", "/",
            "explicit", "machine", "--packing-value", "2",
        ])
        assert ns.packing_value == 2
        assert ns.alignment == "machine"

    def test_generate_call_graph(self, parser):
        ns = parser.parse_args(["get_function_call_graph", "-b", "test.so", "0x1000"])
        assert ns.address == "0x1000"
        assert ns.depth is None

    def test_generate_call_graph_with_depth(self, parser):
        ns = parser.parse_args(["get_function_call_graph", "-b", "test.so", "0x1000", "--depth", "5"])
        assert ns.depth == 5

    def test_apply_data_type(self, parser):
        ns = parser.parse_args(["apply_data_type", "-b", "test.so", "0x3000", "int"])
        assert ns.type_name == "int"
        assert ns.clear_mode == "fail"

        ns = parser.parse_args([
            "apply_data_type", "-b", "test.so", "0x3000", "char *[5]",
            "--clear-mode", "data_only",
        ])
        assert ns.type_name == "char *[5]"
        assert ns.clear_mode == "data_only"

    def test_set_memory_permissions(self, parser):
        ns = parser.parse_args(["set_memory_block_permissions", "-b", "test.so", ".text", "--execute"])
        assert ns.block_name == ".text"
        assert ns.execute is True

    @pytest.mark.parametrize(
        "command",
        [
            "detect_security_mitigations",
            "find_format_string_vulns",
            "identify_user_input_sources",
            "identify_crypto_patterns",
            "find_obfuscated_strings",
            "fix_region",
        ],
    )
    def test_disabled_tools_are_not_cli_commands(self, parser, command):
        with pytest.raises(SystemExit):
            parser.parse_args([command])

    def test_output_flag(self, parser):
        ns = parser.parse_args(["decompile_function", "-b", "test.so", "-o", "out.txt", "0x1"])
        assert ns.output == "out.txt"

    def test_quiet_flag(self, parser):
        ns = parser.parse_args(["decompile_function", "-b", "test.so", "-q", "0x1"])
        assert ns.quiet is True

    def test_owner_flag(self, parser):
        ns = parser.parse_args([
            "decompile_function", "-b", "test.so", "--owner", "patrick", "0x1234"
        ])
        assert ns.owner == "patrick"

    def test_owner_rejects_empty_value(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args([
                "decompile_function", "-b", "test.so", "--owner", "", "0x1234"
            ])

    def test_missing_binary_defaults_none(self, parser):
        """Omitting -b is allowed at parse time (env var fallback)."""
        ns = parser.parse_args(["decompile_function", "0x1"])
        assert ns.binary is None

    def test_no_command_fails(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestMCPModeArgs:
    """Verify runtime-mode and GUI transport arguments for MCP."""

    @pytest.fixture()
    def parser(self):
        from ghidramsc.cli import build_parser
        return build_parser()

    def test_plugin_flag(self, parser):
        ns = parser.parse_args(["mcp", "--plugin"])
        assert ns.mode == "gui"

    def test_mode_defaults_headless(self, parser):
        ns = parser.parse_args(["mcp"])
        assert ns.mode == "headless"

    def test_explicit_gui_mode(self, parser):
        ns = parser.parse_args(["mcp", "--mode", "gui"])
        assert ns.mode == "gui"

    def test_mode_and_plugin_alias_are_mutually_exclusive(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["mcp", "--mode", "gui", "--plugin"])

    def test_plugin_port(self, parser):
        ns = parser.parse_args([
            "mcp", "--mode", "gui", "--plugin-port", "9999"
        ])
        assert ns.plugin_port == 9999

    def test_plugin_host(self, parser):
        ns = parser.parse_args([
            "mcp", "--mode", "gui", "--plugin-host", "192.0.2.1"
        ])
        assert ns.plugin_host == "192.0.2.1"

    def test_plugin_port_default_none(self, parser):
        ns = parser.parse_args(["mcp", "--plugin"])
        assert ns.plugin_port is None

    def test_plugin_host_default_none(self, parser):
        ns = parser.parse_args(["mcp", "--plugin"])
        assert ns.plugin_host is None

    def test_plugin_with_binary(self, parser):
        ns = parser.parse_args([
            "mcp", "--mode", "gui", "-b", "firmware.elf"
        ])
        assert ns.mode == "gui"
        assert ns.binary == "firmware.elf"

    def test_max_clients(self, parser):
        ns = parser.parse_args([
            "mcp", "--mode", "gui", "--max-clients", "24"
        ])
        assert ns.max_clients == 24

    @pytest.mark.parametrize("value", ["0", "-1", "2147483648", "many"])
    def test_max_clients_rejects_non_positive_or_non_java_int(
        self, parser, value
    ):
        with pytest.raises(SystemExit):
            parser.parse_args([
                "mcp", "--mode", "gui", "--max-clients", value
            ])

    def test_max_clients_requires_gui_mode(self, parser):
        from ghidramsc.cli import cmd_mcp

        ns = parser.parse_args(["mcp", "--max-clients", "3"])
        with pytest.raises(ValueError, match="requires --mode gui"):
            cmd_mcp(ns)

    def test_max_clients_is_forwarded(self, parser, monkeypatch):
        from ghidramsc.cli import cmd_mcp

        calls = []
        mcp_transport = importlib.import_module("ghidramsc.mcp_transport")
        monkeypatch.setattr(
            mcp_transport, "run_mcp", lambda **kwargs: calls.append(kwargs)
        )
        ns = parser.parse_args([
            "mcp", "--mode", "gui", "--plugin-host", "127.0.0.2",
            "--plugin-port", "19100", "--max-clients", "19",
            "--toolset", "default",
        ])

        assert cmd_mcp(ns) == 0
        assert calls == [{
            "config": None,
            "binary": None,
            "plugin": True,
            "plugin_host": "127.0.0.2",
            "plugin_port": 19100,
            "max_clients": 19,
            "toolset": "default",
        }]

    @pytest.mark.parametrize(
        ("args", "message"),
        [
            (["--plugin-host", "127.0.0.2"], "--plugin-host"),
            (["--plugin-port", "19100"], "--plugin-port"),
        ],
    )
    def test_gui_transport_options_require_gui_mode(
        self, parser, args, message
    ):
        from ghidramsc.cli import cmd_mcp

        ns = parser.parse_args(["mcp"] + args)
        with pytest.raises(ValueError, match=message):
            cmd_mcp(ns)

    def test_config_is_rejected_in_gui_mode_before_runtime(
        self, parser, monkeypatch
    ):
        from ghidramsc import cli

        load_config = mock.MagicMock()
        monkeypatch.setattr(cli_commands, "load_config", load_config)
        mcp_transport = importlib.import_module("ghidramsc.mcp_transport")
        run_mcp = mock.MagicMock()
        monkeypatch.setattr(mcp_transport, "run_mcp", run_mcp)

        ns = parser.parse_args([
            "mcp", "--mode", "gui", "--config", "headless.toml"
        ])
        with pytest.raises(ValueError, match="--config requires --mode headless"):
            cli.cmd_mcp(ns)

        load_config.assert_not_called()
        run_mcp.assert_not_called()

    @pytest.mark.parametrize(
        "mode_args",
        [["--mode", "gui"], ["--plugin"]],
    )
    def test_owner_is_rejected_in_gui_mode_before_runtime(
        self, parser, monkeypatch, mode_args
    ):
        from ghidramsc import cli

        load_config = mock.MagicMock()
        monkeypatch.setattr(cli_commands, "load_config", load_config)
        mcp_transport = importlib.import_module("ghidramsc.mcp_transport")
        run_mcp = mock.MagicMock()
        monkeypatch.setattr(mcp_transport, "run_mcp", run_mcp)

        ns = parser.parse_args(["mcp"] + mode_args + ["--owner", "patrick"])
        with pytest.raises(ValueError, match="--owner requires --mode headless"):
            cli.cmd_mcp(ns)

        load_config.assert_not_called()
        run_mcp.assert_not_called()

    def test_legacy_plugin_alias_selects_gui(self, parser, monkeypatch):
        from ghidramsc import cli

        calls = []
        mcp_transport = importlib.import_module("ghidramsc.mcp_transport")
        monkeypatch.setattr(
            mcp_transport, "run_mcp", lambda **kwargs: calls.append(kwargs)
        )

        ns = parser.parse_args(["mcp", "--plugin"])
        assert cli.cmd_mcp(ns) == 0
        assert calls[0]["plugin"] is True

    def test_headless_toolset_is_forwarded(self, parser, monkeypatch):
        from ghidramsc import cli

        calls = []
        config = object()
        monkeypatch.setattr(cli_commands, "load_config", lambda _: config)
        mcp_transport = importlib.import_module("ghidramsc.mcp_transport")
        monkeypatch.setattr(
            mcp_transport, "run_mcp", lambda **kwargs: calls.append(kwargs)
        )
        ns = parser.parse_args(["mcp", "-t", "minimal"])

        assert cli.cmd_mcp(ns) == 0
        assert calls == [{
            "config": config,
            "binary": None,
            "owner": None,
            "toolset": "minimal",
        }]

    def test_headless_owner_is_forwarded(self, parser, monkeypatch):
        from ghidramsc import cli

        calls = []
        config = object()
        monkeypatch.setattr(cli_commands, "load_config", lambda _: config)
        mcp_transport = importlib.import_module("ghidramsc.mcp_transport")
        monkeypatch.setattr(
            mcp_transport, "run_mcp", lambda **kwargs: calls.append(kwargs)
        )
        ns = parser.parse_args(["mcp", "--owner", "patrick"])

        assert cli.cmd_mcp(ns) == 0
        assert calls == [{
            "config": config,
            "binary": None,
            "owner": "patrick",
            "toolset": "all",
        }]
