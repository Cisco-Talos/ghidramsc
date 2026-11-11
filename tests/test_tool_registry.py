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

"""Executable consistency tests for the central Python tool registry.

These tests verify the public registry against Python query signatures and
generated MCP schemas. Java handler behavior is exercised by JVM or live
Ghidra tests at the appropriate boundary.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest


class TestRegistryVsPython:
    """Verify every registry entry (except list_programs) has a matching
    public function in queries.py, and vice-versa."""

    def test_registry_tools_have_python_functions(self):
        from ghidramsc.tool_registry import TOOL_DEFINITIONS
        from ghidramsc import queries

        py_funcs = {
            name
            for name, _ in inspect.getmembers(queries, inspect.isfunction)
            if not name.startswith("_")
        }
        for entry in TOOL_DEFINITIONS:
            name = entry["name"]
            if name == "list_programs":
                continue  # project-level, not in queries.py
            assert name in py_funcs, (
                "Registry tool '{}' has no matching function in queries.py".format(name)
            )

    def test_python_functions_are_in_registry(self):
        from ghidramsc.tool_registry import TOOL_DEFINITIONS
        from ghidramsc import queries

        registry_names = {entry["name"] for entry in TOOL_DEFINITIONS}
        for name, _ in inspect.getmembers(queries, inspect.isfunction):
            if name.startswith("_"):
                continue
            assert name in registry_names, (
                "queries.py function '{}' is not in tool_registry.py".format(name)
            )

    def test_python_parameter_contracts_match_registry(self):
        """Names, order, types, required flags, and defaults must agree."""
        from ghidramsc.tool_registry import TOOL_DEFINITIONS
        from ghidramsc import queries

        annotation_types = {
            "str": "string",
            "int": "integer",
            "float": "number",
            "bool": "boolean",
            "List[str]": "array",
            "List[Dict[str, str]]": "array",
            "Optional[List[Dict[str, str]]]": "array",
        }

        for entry in TOOL_DEFINITIONS:
            if entry["name"] == "list_programs":
                continue
            function = getattr(queries, entry["name"])
            parameters = list(inspect.signature(function).parameters.values())
            assert parameters and parameters[0].name == "ctx"
            parameters = parameters[1:]
            registry_params = entry["params"]

            assert [p.name for p in parameters] == [
                p["name"] for p in registry_params
            ], "Python parameter drift for '{}'".format(entry["name"])

            for actual, declared in zip(parameters, registry_params):
                required = actual.default is inspect.Parameter.empty
                assert required == declared["required"], (
                    "Required/optional drift for '{}.{}'".format(
                        entry["name"], actual.name
                    )
                )
                annotation = actual.annotation
                assert annotation in annotation_types, (
                    "Unrecorded Python type for '{}.{}': {!r}".format(
                        entry["name"], actual.name, annotation
                    )
                )
                assert annotation_types[annotation] == declared["type"], (
                    "Type drift for '{}.{}'".format(entry["name"], actual.name)
                )
                if not required:
                    assert "default" in declared, (
                        "Optional registry parameter '{}.{}' has no default".format(
                            entry["name"], actual.name
                        )
                    )
                    effective_default = actual.default
                    if (entry["name"] == "create_function"
                            and actual.name == "ranges"
                            and actual.default is None):
                        # Keep the public empty-array default without a mutable
                        # Python function default.
                        effective_default = []
                    assert declared["default"] == effective_default, (
                        "Default drift for '{}.{}'".format(
                            entry["name"], actual.name
                        )
                    )


class TestRegistryConsistency:
    """Internal consistency checks on the registry itself."""

    def test_no_duplicate_names(self):
        from ghidramsc.tool_registry import TOOL_DEFINITIONS

        seen = set()
        for entry in TOOL_DEFINITIONS:
            assert entry["name"] not in seen, (
                "Duplicate tool name in registry: '{}'".format(entry["name"])
            )
            seen.add(entry["name"])

    def test_all_entries_have_required_fields(self):
        from ghidramsc.tool_registry import TOOL_DEFINITIONS

        for entry in TOOL_DEFINITIONS:
            assert "name" in entry
            assert "description" in entry
            assert "category" in entry
            assert "params" in entry
            assert entry["category"] in ("query", "mutation")

    def test_mcp_execution_modes_are_valid_and_exact(self):
        from ghidramsc.tool_registry import (
            MCP_EXECUTION_MODES,
            TOOLS,
            tool_mcp_modes,
        )

        plugin_only = set()
        for entry in TOOLS:
            modes = tool_mcp_modes(entry)
            assert modes
            assert len(modes) == len(set(modes))
            assert set(modes).issubset(MCP_EXECUTION_MODES)
            if modes == ("plugin",):
                plugin_only.add(entry["name"])
            else:
                assert modes == MCP_EXECUTION_MODES

        assert plugin_only == {
            "get_cursor_address",
            "get_function_at_cursor",
            "get_gui_selection",
            "set_cursor_address",
            "undo_gui_transaction",
        }

    def test_mcp_binary_policy_is_registry_owned_and_exact(self):
        from ghidramsc.tool_registry import TOOLS, tool_accepts_mcp_binary

        no_binary = {
            entry["name"] for entry in TOOLS
            if not tool_accepts_mcp_binary(entry)
        }
        assert no_binary == {
            "list_programs",
            "get_cursor_address",
            "get_function_at_cursor",
            "get_gui_selection",
            "set_cursor_address",
            "undo_gui_transaction",
        }

    def test_params_have_required_fields(self):
        from ghidramsc.tool_registry import TOOL_DEFINITIONS

        for entry in TOOL_DEFINITIONS:
            for p in entry["params"]:
                assert "name" in p, (
                    "Param in '{}' missing 'name'".format(entry["name"])
                )
                assert "type" in p, (
                    "Param '{}' in '{}' missing 'type'".format(
                        p.get("name", "?"), entry["name"]
                    )
                )
                assert "required" in p, (
                    "Param '{}' in '{}' missing 'required'".format(
                        p["name"], entry["name"]
                    )
                )
                assert p["type"] in (
                    "string", "integer", "number", "boolean", "array",
                    "object",
                ), "Param '{}' in '{}' has invalid type '{}'".format(
                    p["name"], entry["name"], p["type"]
                )

    def test_disabled_implementations_are_not_public_tools(self):
        from ghidramsc.tool_registry import (
            DISABLED_TOOL_NAMES,
            TOOL_DEFINITIONS,
            TOOLS,
            get_tool,
        )

        expected = {
            "detect_security_mitigations",
            "find_format_string_vulns",
            "identify_user_input_sources",
            "identify_crypto_patterns",
            "find_obfuscated_strings",
            "fix_region",
        }
        definition_names = {entry["name"] for entry in TOOL_DEFINITIONS}
        public_names = {entry["name"] for entry in TOOLS}

        assert set(DISABLED_TOOL_NAMES) == expected
        assert expected.issubset(definition_names)
        assert expected.isdisjoint(public_names)
        assert len(TOOL_DEFINITIONS) == len(TOOLS) + len(expected)
        for name in expected:
            with pytest.raises(KeyError):
                get_tool(name)

    def test_registry_to_mcp_schema_contract(self):
        from ghidramsc.tool_registry import TOOLS, tool_accepts_mcp_binary
        from ghidramsc.mcp_transport import _build_tool_schemas

        schemas = _build_tool_schemas()
        assert [schema["name"] for schema in schemas] == [
            entry["name"] for entry in TOOLS
        ]
        for entry, tool in zip(TOOLS, schemas):
            schema = tool["inputSchema"]
            properties = schema["properties"]
            expected_names = (["binary"] if tool_accepts_mcp_binary(entry)
                              else []) + [param["name"] for param in entry["params"]]
            assert list(properties) == expected_names
            assert schema["type"] == "object"
            assert schema["additionalProperties"] is False
            assert schema.get("required", []) == [
                param["name"] for param in entry["params"] if param["required"]
            ]
            for param in entry["params"]:
                prop = properties[param["name"]]
                assert prop["type"] == param["type"]
                if "default" in param:
                    assert prop["default"] == param["default"]
                else:
                    assert "default" not in prop
                if "items" in param:
                    assert prop["items"] == param["items"]

        # The reader-facing catalog is maintained by hand, but its exact
        # public names, parameter types, and omission/default states must stay
        # aligned with the same registry that generates MCP schemas.
        catalog = (Path(__file__).resolve().parents[1] / "TOOL_CATALOG.md").read_text(
            encoding="utf-8"
        )
        headings = list(re.finditer(r"^### `([a-z][a-z0-9_]*)`$", catalog, re.M))
        catalog_names = [match.group(1) for match in headings]
        assert len(catalog_names) == len(set(catalog_names)) == len(TOOLS)
        assert set(catalog_names) == {entry["name"] for entry in TOOLS}

        def displayed_type(param):
            if param["type"] != "array":
                return param["type"]
            item = param.get("items", {})
            if item.get("type") != "object":
                return f"array of {item.get('type', 'values')}"
            fields = ", ".join(
                f"{name}: {field['type']}"
                for name, field in item.get("properties", {}).items()
            )
            return f"array of objects {{{fields}}}"

        def displayed_default(param):
            if "default" not in param:
                return "—" if param["required"] else "Not declared"
            value = param["default"]
            if value == "":
                return '`""`'
            if value is True:
                return "`true`"
            if value is False:
                return "`false`"
            return f"`{value}`"

        by_name = {entry["name"]: entry for entry in TOOLS}
        for index, heading in enumerate(headings):
            section = catalog[
                heading.end():headings[index + 1].start()
                if index + 1 < len(headings) else len(catalog)
            ]
            entry = by_name[heading.group(1)]
            expected = [
                (param["name"], displayed_type(param),
                 "Required" if param["required"] else "Optional",
                 displayed_default(param))
                for param in entry["params"]
            ]
            if tool_accepts_mcp_binary(entry):
                expected.append(
                    ("binary", "string", "Optional", "`configured default program`")
                )
            actual = re.findall(
                r"^\| `([a-z][a-z0-9_]*)` \| ([^|]+) \| ([^|]+) \| ([^|]+) \|",
                section, re.M,
            )
            assert actual == expected, entry["name"]
            assert f"**Role:** {entry['category'].capitalize()}." in section
            availability = (
                "GUI MCP only" if entry.get("mcp_modes") == ["plugin"]
                else "CLI, HTTP, headless MCP, GUI MCP"
            )
            assert f"**Availability:** {availability}." in section

    def test_mcp_schema_unknown_arguments_match_validator(self):
        from ghidramsc.mcp_transport import _build_tool_schemas
        from ghidramsc.tool_registry import validate_tool_arguments

        schemas = {tool["name"]: tool["inputSchema"]
                   for tool in _build_tool_schemas()}
        pairs = [
            ("list_programs", {}, True),
            ("list_programs", {"extra": 1}, False),
            ("list_programs", {"binary": "sample.bin"}, False),
            ("decompile_function", {"addr_hex": "0x100", "binary": "sample.bin"}, True),
            ("decompile_function", {"addr_hex": "0x100", "extra": 1}, False),
        ]
        for name, args, accepted in pairs:
            schema = schemas[name]
            declared = set(schema["properties"])
            schema_accepts = (set(args) <= declared and
                              set(schema.get("required", [])) <= set(args))
            assert schema_accepts is accepted
            assert (validate_tool_arguments(
                name, args, include_mcp_binary=True) is None
            ) is accepted

    def test_create_structure_category_path_contract(self):
        from ghidramsc.tool_registry import get_tool

        tool = get_tool("create_structure")
        category = next(
            param for param in tool["params"]
            if param["name"] == "category_path"
        )
        assert category["type"] == "string"
        assert category["required"] is False
        assert category["default"] == "/"


class TestRegistryArgumentValidation:
    @pytest.mark.parametrize(
        ("command", "args", "message"),
        [
            ("not_a_tool", {}, "Unknown command"),
            ("decompile_function", [], "JSON object"),
            ("decompile_function", {}, "Missing required argument"),
            ("decompile_function", {"addr_hex": 4096}, "expected string"),
            ("decompile_function", {"addr_hex": "0x1000", "extra": 1}, "Unknown argument"),
            ("decompile_functions", {"addresses": ["0x1000", 4097]}, "expected string"),
            ("set_function_body", {
                "addr_hex": "0x1000",
                "ranges": [{"start": "0x1000"}],
            }, "Missing required argument"),
            ("create_function", {
                "addr_hex": "0x1000",
                "ranges": [{
                    "start": "0x1000", "end": "0x1003", "extra": True,
                }],
            }, "Unknown argument"),
        ],
    )
    def test_rejects_invalid_registry_arguments(self, command, args, message):
        from ghidramsc.tool_registry import validate_tool_arguments

        assert message in validate_tool_arguments(command, args)

    @pytest.mark.parametrize(
        ("command", "args"),
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
    def test_accepts_drift_prone_public_contracts(self, command, args):
        from ghidramsc.tool_registry import validate_tool_arguments

        assert validate_tool_arguments(command, args) is None
