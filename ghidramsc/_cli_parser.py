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

"""CLI parser and public option/help contract."""

from __future__ import annotations

import argparse

from .tool_registry import TOOLS
from ._cli_commands import *

_MAX_JAVA_INT = 2_147_483_647


def _positive_java_int(value: str) -> int:
    """Parse a positive integer representable by Java's ``int`` type."""
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a positive integer"
        ) from exc
    if parsed < 1 or parsed > _MAX_JAVA_INT:
        raise argparse.ArgumentTypeError(
            "must be between 1 and {}".format(_MAX_JAVA_INT)
        )
    return parsed


def _project_owner(value: str) -> str:
    """Parse a non-empty Ghidra project-owner override."""
    owner = value.strip()
    if not owner:
        raise argparse.ArgumentTypeError("must not be empty")
    if any(char in owner for char in ("\x00", "\r", "\n")):
        raise argparse.ArgumentTypeError("must not contain control characters")
    return owner


def _add_common(
    parser: argparse.ArgumentParser, *, include_binary: bool = True
) -> None:
    """Add flags shared by all query subcommands."""
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to ghidramsc.toml config file.",
    )
    parser.add_argument(
        "--owner",
        type=_project_owner,
        default=None,
        help=("Override the Ghidra project owner before starting the local "
              "headless JVM; bypasses HTTP server forwarding."),
    )
    if include_binary:
        parser.add_argument(
            "--binary", "-b",
            default=None,
            help="Binary/program name as it appears in the Ghidra project. "
                 "Falls back to GHIDRAMSC_BINARY env var if not given.",
        )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write result to this file instead of (or in addition to) stdout.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress stdout output (use with --output).",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Skip server check; always use a direct JVM.",
    )


def _add_mutation_save_options(parser: argparse.ArgumentParser) -> None:
    """Add explicit same-process persistence flags to a mutation command."""
    parser.add_argument(
        "--save",
        action="store_true",
        help="Explicitly save this mutation before the command process exits.",
    )
    parser.add_argument(
        "--save-comment",
        default=None,
        help=(
            "Requested save comment (applied only when the active save backend "
            "supports comments); requires --save."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        prog="ghidramsc",
        description="GhidraMSC -- Ghidra query tool for LLM agents (pyghidra).",
    )
    sub = top.add_subparsers(dest="command", required=True)

    # -- serve (server mode) --
    p = sub.add_parser("serve", help="Start the GhidraMSC query server (keeps JVM warm).")
    p.add_argument("--config", "-c", default=None, help="Path to ghidramsc.toml config file.")
    p.add_argument(
        "--owner", type=_project_owner, default=None,
        help="Override the Ghidra project owner before starting the headless JVM.",
    )
    p.add_argument("--binary", "-b", default=None,
                    help="Binary/program name to load. Falls back to GHIDRAMSC_BINARY env var.")
    p.add_argument("--port", type=int, default=None, help="Port (default: config or 13100).")
    p.set_defaults(func=cmd_serve)

    # -- shutdown --
    p = sub.add_parser("shutdown", help="Ask a running server to shut down.")
    p.add_argument("--port", type=int, default=None, help="Server port.")
    p.set_defaults(func=cmd_shutdown)

    # -- mcp (Model Context Protocol stdio server) --
    p = sub.add_parser("mcp", help="Start MCP stdio server for LLM host integration.")
    p.add_argument("--config", "-c", default=None, help="Path to ghidramsc.toml config file.")
    p.add_argument(
        "--owner", type=_project_owner, default=None,
        help="Override the Ghidra project owner (headless mode only).",
    )
    p.add_argument("--binary", "-b", default=None,
                    help="Binary/program name to load. Falls back to GHIDRAMSC_BINARY env var.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--mode", choices=("headless", "gui"), default="headless",
        help="Ghidra runtime mode (default: headless).",
    )
    mode.add_argument(
        "--plugin", dest="mode", action="store_const", const="gui",
        default=argparse.SUPPRESS,
        help="Deprecated alias for --mode gui.",
    )
    p.add_argument("--plugin-host", default=None,
                    help="GUI plugin TCP host (default: 127.0.0.1; requires --mode gui).")
    p.add_argument("--plugin-port", type=int, default=None,
                    help="GUI plugin TCP port (default: 18100; requires --mode gui).")
    p.add_argument(
        "--max-clients", type=_positive_java_int, default=None,
        help=("Set the running plugin listener's positive global client "
              "limit (requires --mode gui)."),
    )
    p.add_argument(
        "--toolset", "-t", default="all",
        help=("Packaged MCP toolset name from ghidramsc/toolsets "
              "(default: all). Paths are not accepted."),
    )
    p.set_defaults(func=cmd_mcp)

    # -- list_programs (project-level; no binary selector) --
    p = sub.add_parser("list_programs", help="List programs in the Ghidra project.")
    _add_common(p, include_binary=False)
    p.set_defaults(func=cmd_list_programs)

    # -- list_functions --
    p = sub.add_parser("list_functions", help="List all functions by address.")
    _add_common(p)
    p.set_defaults(func=cmd_list_functions)

    # -- decompile_function --
    p = sub.add_parser("decompile_function", help="Decompile function at/containing address.")
    _add_common(p)
    p.add_argument("address", help="Hex address (e.g. 0x1c908).")
    p.add_argument("--offset", type=int, default=0,
                   help="Character offset for a decompilation chunk.")
    p.add_argument("--limit", type=int, default=16384,
                   help="Chunk size in characters (1..32768).")
    p.set_defaults(func=cmd_decompile_function)

    # -- list_references_to_address --
    p = sub.add_parser("list_references_to_address", help="Cross-references TO address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--offset", type=int, default=0, help="Reference page offset.")
    p.add_argument("--limit", type=int, default=100, help="Reference page size (max 500).")
    p.set_defaults(func=cmd_list_references_to_address)

    # -- list_references_from_address --
    p = sub.add_parser("list_references_from_address", help="Cross-references FROM address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--offset", type=int, default=0, help="Reference page offset.")
    p.add_argument("--limit", type=int, default=100, help="Reference page size (max 500).")
    p.set_defaults(func=cmd_list_references_from_address)

    # -- get_listing_at_address --
    p = sub.add_parser("get_listing_at_address", help="Disassembly listing at address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--count", "-n", type=int, default=None, help="Instruction count (default 40).")
    p.add_argument("--offset", type=int, default=0, help="Listing page offset.")
    p.add_argument("--limit", type=int, default=100, help="Listing page size (max 500).")
    p.set_defaults(func=cmd_get_listing_at_address)

    # -- get_function_info --
    p = sub.add_parser("get_function_info", help="Function metadata as JSON.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--incoming-offset", type=int, default=0,
                   help="Incoming-reference page offset (default 0).")
    p.add_argument("--incoming-limit", type=int, default=100,
                   help="Incoming-reference page size (default 100, max 500).")
    p.add_argument("--evidence-offset", type=int, default=0,
                   help="Function-evidence array page offset (default 0).")
    p.add_argument("--evidence-limit", type=int, default=100,
                   help="Function-evidence array page size (default 100, max 500).")
    p.set_defaults(func=cmd_get_function_info)

    # -- list_strings --
    p = sub.add_parser("list_strings", help="Defined strings, optionally filtered.")
    _add_common(p)
    p.add_argument("filter", nargs="?", default=None, help="Substring filter (case-insensitive).")
    p.set_defaults(func=cmd_list_strings)

    # -- search_memory_text --
    p = sub.add_parser("search_memory_text", help="Search memory for ASCII pattern.")
    _add_common(p)
    p.add_argument("pattern", help="ASCII search pattern.")
    p.set_defaults(func=cmd_search_memory_text)

    # -- search_memory_bytes --
    p = sub.add_parser("search_memory_bytes", help="Search memory for hex byte pattern.")
    _add_common(p)
    p.add_argument("hex_bytes", help="Hex bytes (e.g. e92d4830).")
    p.set_defaults(func=cmd_search_memory_bytes)

    # -- search_functions_by_name --
    p = sub.add_parser("search_functions_by_name", help="Find functions by name pattern (regex).")
    _add_common(p)
    p.add_argument("pattern", help="Regex pattern (case-insensitive).")
    p.set_defaults(func=cmd_search_functions_by_name)

    # -- set_function_name --
    p = sub.add_parser("set_function_name", help="Rename a function.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("name", help="New function name.")
    p.set_defaults(func=cmd_set_function_name)

    # -- set_function_names --
    p = sub.add_parser("set_function_names", help="Rename functions from JSON file.")
    _add_common(p)
    p.add_argument("json_path", help="Path to JSON file.")
    p.set_defaults(func=cmd_set_function_names)

    # -- create_function --
    p = sub.add_parser(
        "create_function", help="Create a function, optionally with exact ranges.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--name", default=None, help="Optional function name.")
    p.add_argument(
        "--range", dest="ranges", action="append", default=[],
        metavar="START:END", help="Inclusive function-body range; repeatable.")
    p.set_defaults(func=cmd_create_function)

    # -- delete_function --
    p = sub.add_parser("delete_function", help="Remove only a function definition.")
    _add_common(p)
    p.add_argument("address", help="Address at or inside the function.")
    p.set_defaults(func=cmd_delete_function)

    # -- create_stack_variable --
    p = sub.add_parser(
        "create_stack_variable", help="Create a local stack variable at an exact offset.")
    _add_common(p)
    p.add_argument("address", help="Address at or inside the function.")
    p.add_argument("stack_offset", type=lambda value: int(value, 0),
                   help="Exact signed stack offset (decimal; use -- before negative hex).")
    p.add_argument("name", help="New local variable name.")
    p.add_argument("type_name", help="Data type name.")
    p.add_argument("--size", type=lambda value: int(value, 0), default=0,
                   help="Optional expected size; must match the resolved type.")
    p.set_defaults(func=cmd_create_stack_variable)

    # -- delete_stack_variable --
    p = sub.add_parser(
        "delete_stack_variable", help="Delete a local stack variable at its exact offset.")
    _add_common(p)
    p.add_argument("address", help="Address at or inside the function.")
    p.add_argument("stack_offset", type=lambda value: int(value, 0),
                   help="Exact signed stack offset (decimal; use -- before negative hex).")
    p.set_defaults(func=cmd_delete_stack_variable)

    # -- create_stack_variable_from_structure --
    p = sub.add_parser(
        "create_stack_variable_from_structure",
        help="Create a structure-typed local stack variable at an exact offset.")
    _add_common(p)
    p.add_argument("address", help="Address at or inside the function.")
    p.add_argument("stack_offset", type=lambda value: int(value, 0),
                   help="Exact signed stack offset (decimal; use -- before negative hex).")
    p.add_argument("structure_name", help="Structure data type name.")
    p.add_argument("--category-path", default="",
                   help="Exact category path used to disambiguate the structure.")
    p.add_argument("--name", default="",
                   help="Optional local variable name.")
    p.set_defaults(func=cmd_create_stack_variable_from_structure)

    # -- set_function_body --
    p = sub.add_parser(
        "set_function_body", help="Replace a function body with exact ranges.")
    _add_common(p)
    p.add_argument("address", help="Address at or inside the function.")
    p.add_argument(
        "--range", dest="ranges", action="append", required=True,
        metavar="START:END", help="Inclusive function-body range; repeatable.")
    p.set_defaults(func=cmd_set_function_body)

    # -- create_functions --
    p = sub.add_parser("create_functions", help="Create functions from JSON file.")
    _add_common(p)
    p.add_argument("json_path", help="Path to JSON file.")
    p.set_defaults(func=cmd_create_functions)

    # -- disassemble_memory --
    p = sub.add_parser("disassemble_memory", help="Follow disassembly flow from one start within a bounded range; result reports coverage.")
    _add_common(p)
    p.add_argument("address", help="Start hex address.")
    p.add_argument("--end", default=None, help="Inclusive flow limit (at most 4096 bytes); does not seed every address.")
    p.set_defaults(func=cmd_disassemble_memory)

    # -- clear_code_units --
    p = sub.add_parser(
        "clear_code_units",
        help=("Preview or clear an exact listing range; may remove references "
              "and affect function analysis while preserving bytes and context."),
    )
    _add_common(p)
    p.add_argument("start", help="Inclusive start hex address.")
    p.add_argument("end", help="Inclusive end hex address.")
    p.add_argument("--apply", action="store_true",
                   help="Commit the clear after preflight; default is preview only.")
    p.set_defaults(func=cmd_clear_code_units)

    # -- export_annotations --
    p = sub.add_parser("export_annotations", help="Export symbols, comments, sigs as JSON.")
    _add_common(p)
    p.set_defaults(func=cmd_export_annotations)

    # -- import_annotations --
    p = sub.add_parser("import_annotations", help="Import annotations from JSON file.")
    _add_common(p)
    p.add_argument("json_path", help="Path to JSON file.")
    p.set_defaults(func=cmd_import_annotations)

    # -- list_function_variables --
    p = sub.add_parser("list_function_variables", help="List function variables with types.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.set_defaults(func=cmd_list_function_variables)

    # -- list_function_variable_identities --
    p = sub.add_parser(
        "list_function_variable_identities",
        help="List decompiler variables with stable identities.",
    )
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--offset", type=int, default=0,
                   help="Pagination offset (default: 0).")
    p.add_argument("--limit", type=int, default=100,
                   help="Pagination limit (default: 100, max: 500).")
    p.add_argument("--filter", dest="filter_str", default="",
                   help="Case-insensitive identity substring filter.")
    p.set_defaults(func=cmd_list_function_variable_identities)

    # -- get_function_stack_frame --
    p = sub.add_parser("get_function_stack_frame", help="Stack frame layout for a function.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.set_defaults(func=cmd_get_function_stack_frame)

    # -- set_variable_name --
    p = sub.add_parser("set_variable_name", help="Rename a variable in a function.")
    _add_common(p)
    p.add_argument("address", help="Function hex address.")
    p.add_argument("old_name", help="Current variable name.")
    p.add_argument("new_name", help="New variable name.")
    p.set_defaults(func=cmd_set_variable_name)

    # -- set_variable_type --
    p = sub.add_parser("set_variable_type", help="Change variable data type.")
    _add_common(p)
    p.add_argument("address", help="Function hex address.")
    p.add_argument("var_name", help="Variable name.")
    p.add_argument("type_name", help="New type (e.g. 'int', 'char *').")
    p.set_defaults(func=cmd_set_variable_type)

    # -- set_variable_name_by_id --
    p = sub.add_parser(
        "set_variable_name_by_id",
        help="Rename a decompiler variable by list_function_variable_identities var_id.",
    )
    _add_common(p)
    p.add_argument("address", help="Function hex address.")
    p.add_argument("var_id", help="Stable variable identity.")
    p.add_argument("new_name", help="New variable name.")
    p.add_argument("--split-use", action="store_true",
                   help="Unsupported for rename-only splitting; materialize with create_variable_by_id first.")
    p.add_argument("--merge-group-id", default="",
                   help="Merge-group identity from list_function_variable_identities.")
    p.set_defaults(func=cmd_set_variable_name_by_id)

    # -- set_variable_type_by_id --
    p = sub.add_parser(
        "set_variable_type_by_id",
        help="Retype a decompiler variable by list_function_variable_identities var_id.",
    )
    _add_common(p)
    p.add_argument("address", help="Function hex address.")
    p.add_argument("var_id", help="Stable variable identity.")
    p.add_argument("type_name", help="New type.")
    p.add_argument("--split-use", action="store_true",
                   help="Unsupported for retype-only splitting; materialize with create_variable_by_id first.")
    p.add_argument("--merge-group-id", default="",
                   help="Merge-group identity from list_function_variable_identities.")
    p.set_defaults(func=cmd_set_variable_type_by_id)

    # -- create_variable_by_id --
    p = sub.add_parser(
        "create_variable_by_id",
        help="Materialize a decompiler variable in the function database.",
    )
    _add_common(p)
    p.add_argument("address", help="Function hex address.")
    p.add_argument("var_id", help="Stable variable identity.")
    p.add_argument("--name", default="", help="Stored name; empty keeps current.")
    p.add_argument("--type-name", default="",
                   help="Stored type; empty keeps current.")
    p.add_argument("--split-use", action="store_true",
                   help="Materialize only one merge group.")
    p.add_argument("--merge-group-id", default="",
                   help="Merge-group identity from list_function_variable_identities.")
    p.set_defaults(func=cmd_create_variable_by_id)

    # -- delete_variable_by_id --
    p = sub.add_parser(
        "delete_variable_by_id",
        help="Delete an exact database-backed parameter or local.",
    )
    _add_common(p)
    p.add_argument("address", help="Function hex address.")
    p.add_argument("var_id", help="Stable variable identity.")
    p.set_defaults(func=cmd_delete_variable_by_id)

    # -- set_function_return_type --
    p = sub.add_parser("set_function_return_type", help="Set function return type.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("type_name", help="Return type (e.g. 'void', 'int').")
    p.set_defaults(func=cmd_set_function_return_type)

    # -- apply_function_annotations --
    p = sub.add_parser("apply_function_annotations", help="Batch rename/retype vars from JSON.")
    _add_common(p)
    p.add_argument("address", help="Function hex address.")
    p.add_argument("json_path", help="Path to JSON annotation file.")
    p.set_defaults(func=cmd_apply_function_annotations)

    # -- decompile_functions --
    p = sub.add_parser("decompile_functions", help="Decompile multiple addresses in one run.")
    _add_common(p)
    p.add_argument("addresses", help="Comma-separated hex addresses.")
    p.set_defaults(func=cmd_decompile_functions)

    # -- get_program_info --
    p = sub.add_parser("get_program_info", help="Program metadata (arch, base, format, etc.).")
    _add_common(p)
    p.set_defaults(func=cmd_get_program_info)

    # -- get_program_save_state --
    p = sub.add_parser("get_program_save_state", help="Report unsaved program changes.")
    _add_common(p)
    p.set_defaults(func=cmd_get_program_save_state)

    # -- save_program --
    p = sub.add_parser("save_program", help="Explicitly save pending program changes.")
    _add_common(p)
    p.add_argument("--comment", default="Saved by GhidraMSC",
                   help=("Save comment in headless mode; the GUI plugin "
                         "uses Ghidra's in-place save lifecycle without "
                         "a custom comment."))
    p.set_defaults(func=cmd_save_program)

    # -- get_program_memory_map --
    p = sub.add_parser("get_program_memory_map", help="Memory layout with block addresses and permissions.")
    _add_common(p)
    p.set_defaults(func=cmd_get_program_memory_map)

    # -- list_program_imports --
    p = sub.add_parser("list_program_imports", help="List imported symbols.")
    _add_common(p)
    p.set_defaults(func=cmd_list_program_imports)

    # -- list_program_exports --
    p = sub.add_parser("list_program_exports", help="List exported symbols.")
    _add_common(p)
    p.set_defaults(func=cmd_list_program_exports)

    # -- list_program_namespaces --
    p = sub.add_parser("list_program_namespaces", help="List all namespaces.")
    _add_common(p)
    p.set_defaults(func=cmd_list_program_namespaces)

    # -- list_program_classes --
    p = sub.add_parser("list_program_classes", help="List all class namespaces.")
    _add_common(p)
    p.set_defaults(func=cmd_list_program_classes)

    # -- list_data_items --
    p = sub.add_parser("list_data_items", help="List defined data items (globals, constants).")
    _add_common(p)
    p.add_argument("--offset", type=int, default=None, help="Pagination offset (default 0).")
    p.add_argument("--limit", type=int, default=None, help="Max items (default 500).")
    p.set_defaults(func=cmd_list_data_items)

    # -- read_memory_bytes --
    p = sub.add_parser("read_memory_bytes", help="Read raw bytes at address as hex dump.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--length", type=int, default=None, help="Bytes to read (default 256, max 4096).")
    p.set_defaults(func=cmd_read_memory_bytes)

    # -- get_data_at_address --
    p = sub.add_parser("get_data_at_address", help="Defined data item at address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--value-offset", type=int, default=0,
                   help="Rendered-value code-point offset.")
    p.add_argument("--value-limit", type=int, default=2048,
                   help="Rendered-value page size (max 8192 code points).")
    p.set_defaults(func=cmd_get_data_at_address)

    # -- list_memory_blocks --
    p = sub.add_parser("list_memory_blocks", help="Segment/section details (addresses, permissions).")
    _add_common(p)
    p.set_defaults(func=cmd_list_memory_blocks)

    # -- set_comment_at_address --
    p = sub.add_parser("set_comment_at_address", help="Set a comment at an address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("comment", help="Comment text.")
    p.add_argument("--type", dest="comment_type", default=None,
                   help="Comment type: plate, pre, post, eol (default), repeatable.")
    p.add_argument("--allow-containing-item", action="store_true",
                   help="Allow an interior address to change the containing item's shared comment.")
    p.set_defaults(func=cmd_set_comment_at_address)

    # -- get_comment_at_address --
    p = sub.add_parser("get_comment_at_address", help="Get the comment at an address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--type", dest="comment_type", default=None,
                   help="Comment type: plate, pre, post, eol (default), repeatable.")
    p.set_defaults(func=cmd_get_comment_at_address)

    # -- create_bookmark --
    p = sub.add_parser("create_bookmark", help="Add a bookmark at an address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("category", help="Bookmark category label.")
    p.add_argument("--comment", default=None, help="Optional bookmark comment.")
    p.set_defaults(func=cmd_create_bookmark)

    # -- delete_bookmark --
    p = sub.add_parser("delete_bookmark", help="Remove a bookmark.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("category", help="Bookmark category.")
    p.set_defaults(func=cmd_delete_bookmark)

    # -- list_bookmarks --
    p = sub.add_parser("list_bookmarks", help="List bookmarks, optionally by address.")
    _add_common(p)
    p.add_argument("address", nargs="?", default=None, help="Optional hex address filter.")
    p.set_defaults(func=cmd_list_bookmarks)

    # -- list_structures --
    p = sub.add_parser("list_structures", help="List all defined structures.")
    _add_common(p)
    p.set_defaults(func=cmd_list_structures)

    # -- get_structure --
    p = sub.add_parser("get_structure", help="Get structure details (fields, offsets, types).")
    _add_common(p)
    p.add_argument("name", help="Structure name.")
    p.add_argument("--category-path", default="",
                   help="Exact category path; omitted names must be unique.")
    p.set_defaults(func=cmd_get_structure)

    # -- get_composite --
    p = sub.add_parser(
        "get_composite",
        help="Get exact structure/union fields and bitfield metadata.",
    )
    _add_common(p)
    p.add_argument("name", help="Composite name.")
    p.add_argument("--category-path", default="",
                   help="Exact category path; omitted names must be unique.")
    p.set_defaults(func=cmd_get_composite)

    # -- list_enums --
    p = sub.add_parser("list_enums", help="List all defined enum types.")
    _add_common(p)
    p.set_defaults(func=cmd_list_enums)

    # -- get_enum --
    p = sub.add_parser("get_enum", help="Get enum definition with members.")
    _add_common(p)
    p.add_argument("name", help="Enum name.")
    p.set_defaults(func=cmd_get_enum)

    # -- create_structure --
    p = sub.add_parser("create_structure", help="Create a new structure data type.")
    _add_common(p)
    p.add_argument("name", help="Structure name.")
    p.add_argument("--size", type=int, default=None, help="Size in bytes (0 = growable).")
    p.add_argument("--category-path", default="/", help="Exact category path.")
    p.set_defaults(func=cmd_create_structure)

    # -- set_structure_name --
    p = sub.add_parser("set_structure_name", help="Rename a structure.")
    _add_common(p)
    p.add_argument("old_name", help="Current structure name.")
    p.add_argument("new_name", help="New structure name.")
    p.set_defaults(func=cmd_set_structure_name)

    # -- delete_structure --
    p = sub.add_parser("delete_structure", help="Delete a structure.")
    _add_common(p)
    p.add_argument("name", help="Structure name.")
    p.set_defaults(func=cmd_delete_structure)

    # -- set_structure_field --
    p = sub.add_parser("set_structure_field",
                       help="Insert or replace a structure field by offset.")
    _add_common(p)
    p.add_argument("name", help="Structure name.")
    p.add_argument("category_path", help="Exact category path.")
    p.add_argument("offset", type=int, help="Byte offset.")
    p.add_argument("field_name", help="Field name.")
    p.add_argument("type_name", help="Data type name.")
    p.add_argument("--mode", choices=("replace", "insert"), default="replace")
    p.add_argument("--length", type=int, default=0)
    p.add_argument("--comment", default="")
    p.set_defaults(func=cmd_set_structure_field)

    # -- delete_structure_field --
    p = sub.add_parser("delete_structure_field",
                       help="Delete a structure field by exact offset.")
    _add_common(p)
    p.add_argument("name", help="Structure name.")
    p.add_argument("category_path", help="Exact category path.")
    p.add_argument("offset", type=int, help="Byte offset.")
    p.set_defaults(func=cmd_delete_structure_field)

    # -- set_structure_layout --
    p = sub.add_parser("set_structure_layout",
                       help="Set structure packing and alignment.")
    _add_common(p)
    p.add_argument("name", help="Structure name.")
    p.add_argument("category_path", help="Exact category path.")
    p.add_argument("packing", choices=("disabled", "default", "explicit"))
    p.add_argument("alignment", choices=("default", "machine", "explicit"))
    p.add_argument("--packing-value", type=int, default=0)
    p.add_argument("--alignment-value", type=int, default=0)
    p.set_defaults(func=cmd_set_structure_layout)

    # -- create_union --
    p = sub.add_parser("create_union", help="Create an empty union.")
    _add_common(p)
    p.add_argument("name", help="Union name.")
    p.add_argument("--category-path", default="/", help="Exact category path.")
    p.set_defaults(func=cmd_create_union)

    # -- set_union_field --
    p = sub.add_parser("set_union_field",
                       help="Insert or replace a union field by ordinal.")
    _add_common(p)
    p.add_argument("name", help="Union name.")
    p.add_argument("category_path", help="Exact category path.")
    p.add_argument("ordinal", type=int, help="Component ordinal.")
    p.add_argument("field_name", help="Field name.")
    p.add_argument("type_name", help="Data type name.")
    p.add_argument("--mode", choices=("replace", "insert"), default="replace")
    p.add_argument("--length", type=int, default=0)
    p.add_argument("--comment", default="")
    p.set_defaults(func=cmd_set_union_field)

    # -- set_composite_bitfield --
    p = sub.add_parser("set_composite_bitfield",
                       help="Insert or replace a structure/union bitfield.")
    _add_common(p)
    p.add_argument("name", help="Composite name.")
    p.add_argument("category_path", help="Exact category path.")
    p.add_argument("ordinal", type=int, help="Insertion/replacement ordinal.")
    p.add_argument("field_name", help="Bitfield name.")
    p.add_argument("type_name", help="Integer or enum base type.")
    p.add_argument("bit_size", type=int, help="Declared bit width.")
    p.add_argument("--mode", choices=("insert", "replace"), default="insert")
    p.add_argument("--byte-offset", type=int, default=0)
    p.add_argument("--storage-size", type=int, default=0)
    p.add_argument("--bit-offset", type=int, default=0)
    p.set_defaults(func=cmd_set_composite_bitfield)

    # -- delete_composite_field --
    p = sub.add_parser("delete_composite_field",
                       help="Delete a composite field by exact ordinal.")
    _add_common(p)
    p.add_argument("name", help="Composite name.")
    p.add_argument("category_path", help="Exact category path.")
    p.add_argument("ordinal", type=int, help="Component ordinal.")
    p.set_defaults(func=cmd_delete_composite_field)

    # -- set_composite_layout --
    p = sub.add_parser("set_composite_layout",
                       help="Set structure/union packing and alignment.")
    _add_common(p)
    p.add_argument("name", help="Composite name.")
    p.add_argument("category_path", help="Exact category path.")
    p.add_argument("packing", choices=("disabled", "default", "explicit"))
    p.add_argument("alignment", choices=("default", "machine", "explicit"))
    p.add_argument("--packing-value", type=int, default=0)
    p.add_argument("--alignment-value", type=int, default=0)
    p.set_defaults(func=cmd_set_composite_layout)

    # -- get_function_call_graph --
    p = sub.add_parser("get_function_call_graph", help="Hierarchical call graph from a function.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("--depth", type=int, default=None, help="Recursion depth (default 3).")
    p.set_defaults(func=cmd_get_function_call_graph)

    # -- list_function_basic_blocks --
    p = sub.add_parser("list_function_basic_blocks", help="Basic blocks for a function.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.set_defaults(func=cmd_list_function_basic_blocks)

    # -- get_function_call_relationships --
    p = sub.add_parser("get_function_call_relationships", help="All callers + callees for a function.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.set_defaults(func=cmd_get_function_call_relationships)

    # -- write_memory_bytes --
    p = sub.add_parser("write_memory_bytes", help="Write raw bytes at an address.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("hex_bytes", help="Hex bytes to write (e.g. 90909090).")
    p.set_defaults(func=cmd_write_memory_bytes)

    # -- set_function_prototype --
    p = sub.add_parser("set_function_prototype", help="Set full C-style function prototype.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("prototype", help="C-style signature (e.g. 'int foo(char *buf, int len)').")
    p.set_defaults(func=cmd_set_function_prototype)

    # -- set_function_calling_convention --
    p = sub.add_parser("set_function_calling_convention", help="Set calling convention.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("convention", help="Convention (__stdcall, __cdecl, default, etc.).")
    p.set_defaults(func=cmd_set_function_calling_convention)

    # -- set_function_noreturn --
    p = sub.add_parser("set_function_noreturn", help="Set the native function no-return flag.")
    _add_common(p)
    p.add_argument("address", help="Function address in hex.")
    p.add_argument("no_return", choices=("true", "false"),
                   help="Use true for a function that never returns; false to clear it.")
    p.set_defaults(func=cmd_set_function_noreturn)

    # -- set_instruction_flow_override --
    p = sub.add_parser("set_instruction_flow_override",
                       help="Set a native override on one instruction's flow.")
    _add_common(p)
    p.add_argument("address", help="Exact instruction start address in hex.")
    p.add_argument("flow_override", help="Native FlowOverride enum name.")
    p.set_defaults(func=cmd_set_instruction_flow_override)

    # -- set_data_label --
    p = sub.add_parser("set_data_label", help="Rename a data label.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("name", help="New data label name.")
    p.set_defaults(func=cmd_set_data_label)

    # -- set_address_label --
    p = sub.add_parser("set_address_label", help="Set a mapped address's primary label.")
    _add_common(p)
    p.add_argument("address")
    p.add_argument("name")
    p.set_defaults(func=cmd_set_address_label)

    # -- apply_data_type --
    p = sub.add_parser("apply_data_type", help="Apply a fixed-size type in mapped initialized or uninitialized data; BSS remains uninitialized.")
    _add_common(p)
    p.add_argument("address", help="Hex address.")
    p.add_argument("type_name", help="Data type (e.g. 'int', 'char *', 'my_struct').")
    p.add_argument(
        "--clear-mode", choices=("fail", "data_only"), default="fail",
        help="Conflict policy. Default fail; data_only may replace data but never instructions.",
    )
    p.set_defaults(func=cmd_apply_data_type)

    # -- set_program_image_base --
    p = sub.add_parser("set_program_image_base", help="Set the image base address.")
    _add_common(p)
    p.add_argument("address", help="New image base hex address.")
    p.set_defaults(func=cmd_set_program_image_base)

    # -- set_memory_block_permissions --
    p = sub.add_parser("set_memory_block_permissions", help="Set R/W/X on a memory block.")
    _add_common(p)
    p.add_argument("block_name", help="Memory block name.")
    p.add_argument("--read", action="store_true", default=True, help="Set read (default True).")
    p.add_argument("--no-read", dest="read", action="store_false")
    p.add_argument("--write", action="store_true", default=False, help="Set write.")
    p.add_argument("--execute", action="store_true", default=False, help="Set execute.")
    p.set_defaults(func=cmd_set_memory_block_permissions)

    # -- create_memory_block --
    p = sub.add_parser("create_memory_block", help="Create a bounded analysis memory block.")
    _add_common(p)
    p.add_argument("block_name")
    p.add_argument("address")
    p.add_argument("length", type=int)
    p.add_argument("mode", choices=("uninitialized", "fill", "bytes", "byte_mapped"))
    p.add_argument("--overlay", action="store_true")
    p.add_argument("--no-read", dest="read", action="store_false", default=True)
    p.add_argument("--no-write", dest="write", action="store_false", default=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--fill-byte", type=int, default=0)
    p.add_argument("--hex-bytes", default="")
    p.add_argument("--source-addr-hex", default="")
    p.add_argument("--preview-only", action="store_true")
    p.set_defaults(func=cmd_create_memory_block)

    # -- delete_memory_block --
    p = sub.add_parser("delete_memory_block", help="Remove an exact GhidraMSC analysis block.")
    _add_common(p)
    p.add_argument("block_name")
    p.add_argument("start")
    p.add_argument("length", type=int)
    p.add_argument("--preview-only", action="store_true")
    p.add_argument("--confirm-content-removal", action="store_true")
    p.set_defaults(func=cmd_delete_memory_block)

    # -- create_recovered_code_overlay --
    p = sub.add_parser("create_recovered_code_overlay",
                       help="Copy exact recovered bytes into an executable overlay.")
    _add_common(p)
    p.add_argument("block_name")
    p.add_argument("analysis_addr_hex")
    p.add_argument("hex_bytes")
    p.add_argument("transform")
    p.add_argument("--source-addr-hex", default="")
    p.add_argument("--source-length", type=int, default=0)
    p.add_argument("--runtime-addr-hex", default="")
    p.add_argument("--allow-physical-overlap", action="store_true")
    p.add_argument("--preview-only", action="store_true")
    p.set_defaults(func=cmd_create_recovered_code_overlay)

    # Persistence flags belong only to executable CLI mutation commands.
    # ``save_program`` already has its standalone ``--comment`` contract.
    for tool in TOOLS:
        if tool["category"] != "mutation" or tool["name"] == "save_program":
            continue
        mutation_parser = sub.choices.get(tool["name"])
        if mutation_parser is not None:
            _add_mutation_save_options(mutation_parser)

    return top
