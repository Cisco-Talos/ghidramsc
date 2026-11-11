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

"""Central tool registry -- single source of truth for GhidraMSC tools.

``TOOL_DEFINITIONS`` retains every implemented tool contract, including
disabled implementations kept for possible future repair. ``TOOLS`` is the
publicly available registry used by CLI, HTTP, and MCP surfaces.

Each entry defines:
  - name          tool name (snake_case, matches Python function + Java handler)
  - description   one-line description shown to MCP clients
  - category      "query" or "mutation"
  - mcp_modes     optional MCP execution modes; defaults to plugin + headless
  - mcp_binary    whether MCP accepts its transport-level binary selector;
                  defaults to True
  - params        ordered list of parameter dicts:
        name      parameter name
        type      JSON-Schema type: "string", "integer", "number",
                  "boolean", "array", or "object"
        required  True if mandatory
        desc      one-line description (optional)
        items     element type for arrays, e.g. {"type": "string"} (optional)
        default   default value when omitted (optional, informational)
        plugin_wire
                  replacement name/type after bridge-local preprocessing
                  (optional; currently used for JSON file contents)

To add a new tool under a separately selected capability item:
  1. Define its public contract and mode availability here.
  2. Implement it in the appropriate Python _query_* module and export the
     stable name and signature through queries.py.
  3. Implement and register the Java handler through QueryHandlers.java or
     MutationHandlers.java, using a cohesive internal family where suitable.
  4. Check cross-runtime semantics, transport behavior, and live mode claims.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Optional, Tuple


MCP_EXECUTION_MODES: Tuple[str, ...] = ("plugin", "headless")

# -- Parameter shortcuts (reusable descriptions) -----------------------

_D_ADDR      = "Hex address (e.g. '0x1c908')"
_D_HEX_PAT   = "Hex byte string to search for (e.g. 'e92d4830')"
_D_HEX_BYTES  = "Hex byte string to write (e.g. '90909090')"
_D_START      = "Start hex address of range"
_D_END        = "End hex address of range"
_D_PATTERN    = "Search pattern (regex for search_functions_by_name, ASCII for search_memory_text)"
_D_FILTER     = "Substring filter (case-insensitive)"
_D_NEW_NAME   = "New name to assign"
_D_OLD_NAME   = "Current name to match"
_D_OLD_STRUCT = "Current structure name"
_D_JSON_PATH  = "Path to a JSON file on disk"
_D_COUNT      = "Number of items (default varies by command)"
_D_NAME       = "Name string"
_D_TYPE_NAME  = "C data type (e.g. 'int', 'char *', 'void')"
_D_VAR_NAME   = "Variable name within the function"
_D_ADDRS      = "List of hex address strings"
_D_ANALYZE    = "Whether to run auto-analysis (default false)"
_D_PROGRAM    = (
    "Slash-qualified project-relative binary name returned by list_programs"
)
_D_COMMENT    = "Comment text to set"
_D_CMT_TYPE   = "Comment type: plate, pre, post, eol (default), repeatable"
_D_CATEGORY   = "Bookmark category label"
_D_DEPTH      = "Recursion depth for call graph (default 3)"
_D_OFFSET     = "Pagination offset (default 0)"
_D_LIMIT      = "Pagination limit (default varies by command)"
_D_SIZE       = "Size in bytes (for structure creation; 0 = growable)"
_D_STACK_OFFSET = "Signed stack offset relative to the function stack frame"
_D_STACK_SIZE = "Expected stored size; 0 uses the resolved type length"
_D_STRUCTURE_NAME = "Exact structure name"
_D_PROTO      = "C-style function signature (e.g. 'int foo(char *buf, int len)')"
_D_CONV       = "Calling convention (e.g. '__stdcall', '__cdecl', 'default')"
_D_BLOCK      = "Name of a memory block"
_D_READ       = "Set read permission (boolean)"
_D_WRITE      = "Set write permission (boolean)"
_D_EXECUTE    = "Set execute permission (boolean)"
_D_FUNC_RANGES = (
    "Inclusive function-body ranges as [{start: '0x...', end: '0x...'}]"
)
_FUNC_RANGE_ITEMS = {
    "type": "object",
    "properties": {
        "start": {"type": "string", "description": _D_START},
        "end": {"type": "string", "description": _D_END},
    },
    "required": ["start", "end"],
    "additionalProperties": False,
}

# -- Helpers for compact param declarations ----------------------------

def _p(name: str, type: str = "string", required: bool = True,
       desc: str = "", **kw: Any) -> Dict[str, Any]:
    """Build a parameter dict."""
    d: Dict[str, Any] = {"name": name, "type": type, "required": required}
    if desc:
        d["desc"] = desc
    d.update(kw)
    return d


def _json_path(wire_type: str) -> Dict[str, Any]:
    """Declare a JSON file parameter and its plugin-wire representation."""
    return _p(
        "json_path",
        desc=_D_JSON_PATH,
        plugin_wire={"name": "json_data", "type": wire_type},
    )


# -- The registry itself -----------------------------------------------

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    # ================================================================
    # Project-level (no binary required)
    # ================================================================
    {
        "name": "list_programs",
        "description": "List all programs in the Ghidra project using slash-qualified project-relative names that can be passed back as binary.",
        "category": "query",
        "mcp_binary": False,
        "params": [],
    },
    {
        "name": "get_cursor_address",
        "description": "Get the address at the current cursor position in the Ghidra GUI (GUI mode only).",
        "category": "query",
        "mcp_modes": ["plugin"],
        "mcp_binary": False,
        "params": [],
    },
    {
        "name": "get_function_at_cursor",
        "description": "Get the function containing the current cursor position in the Ghidra GUI (GUI mode only).",
        "category": "query",
        "mcp_modes": ["plugin"],
        "mcp_binary": False,
        "params": [],
    },
    {
        "name": "get_gui_selection",
        "description": "Get the selected address count and min/max addresses in the Ghidra GUI (GUI mode only); disjoint selections are not returned as separate ranges. Returns null start/end with num_addresses=0 when nothing is selected.",
        "category": "query",
        "mcp_modes": ["plugin"],
        "mcp_binary": False,
        "params": [],
    },
    {
        "name": "set_cursor_address",
        "description": "Move the Ghidra GUI cursor to an address (GUI mode only).",
        "category": "mutation",
        "mcp_modes": ["plugin"],
        "mcp_binary": False,
        "params": [_p("addr_hex", desc=_D_ADDR)],
    },
    {
        "name": "undo_gui_transaction",
        "description": "Undo the last transaction on the Code Browser's active program (GUI mode only). Only affects the binary currently open in Code Browser; changes to other binaries cannot be undone via this tool.",
        "category": "mutation",
        "mcp_modes": ["plugin"],
        "mcp_binary": False,
        "params": [],
    },

    # ================================================================
    # Queries
    # ================================================================
    {
        "name": "list_functions",
        "description": "List all functions in the binary, sorted by address.",
        "category": "query",
        "params": [],
    },
    {
        "name": "read_memory_bytes",
        "description": "Read up to 4096 initialized memory bytes at an address as a hex dump with ASCII sidebar.",
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("length", type="integer", required=False, default=256,
               desc="Number of bytes to read (default 256, max 4096)"),
        ],
    },
    {
        "name": "get_data_at_address",
        "description": ("Get defined data and exact symbols at a requested "
                        "address, including its containing item and a finite "
                        "rendered-value page. Use value_next_offset to continue. Undefined bytes "
                        "have no data item; use read_memory_bytes and "
                        "list_references_to_address."),
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("value_offset", type="integer", required=False, default=0,
               desc="Rendered-value code-point offset"),
            _p("value_limit", type="integer", required=False, default=2048,
               desc="Rendered-value page size, 1..8192 code points"),
        ],
    },
    {
        "name": "get_function_stack_frame",
        "description": "Get the stack frame layout of a function (offsets, sizes, types).",
        "category": "query",
        "params": [_p("addr_hex", desc=_D_ADDR)],
    },
    {
        "name": "list_enums",
        "description": "List all enum data types defined in the program.",
        "category": "query",
        "params": [],
    },
    {
        "name": "get_enum",
        "description": "Get the members of a named enum data type.",
        "category": "query",
        "params": [_p("name", desc=_D_NAME)],
    },
    {
        "name": "decompile_function",
        "description": "Decompile a function in bounded text chunks; use offset to continue when next_offset is reported.",
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("offset", type="integer", required=False, default=0,
               desc="Character offset of decompiled output (default 0)"),
            _p("limit", type="integer", required=False, default=16384,
               desc="Maximum characters in this chunk (default 16384, max 32768)"),
        ],
    },
    {
        "name": "list_references_to_address",
        "description": "List cross-references TO an exact address; large results have finite, lossless pages and complete totals.",
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("offset", type="integer", required=False, default=0,
               desc="Reference page offset"),
            _p("limit", type="integer", required=False, default=100,
               desc="Reference page size, 1..500"),
        ],
    },
    {
        "name": "list_references_from_address",
        "description": "List cross-references FROM an exact address; large results have finite, lossless pages and complete totals.",
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("offset", type="integer", required=False, default=0,
               desc="Reference page offset"),
            _p("limit", type="integer", required=False, default=100,
               desc="Reference page size, 1..500"),
        ],
    },
    {
        "name": "get_listing_at_address",
        "description": ("Show listing code units from an address (default 40), "
                        "including the containing item and exact interior "
                        "symbols when the request is inside a code unit. "
                        "Large windows return finite pages with complete totals."),
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("count", type="integer", required=False, default=40,
               desc=_D_COUNT),
            _p("offset", type="integer", required=False, default=0,
               desc="Code-unit page offset within the requested count"),
            _p("limit", type="integer", required=False, default=100,
               desc="Code-unit page size, 1..500"),
        ],
    },
    {
        "name": "get_function_info",
        "description": ("Get function metadata and bounded call-site evidence. "
                        "Calls include confirmed direct and resolved indirect targets; "
                        "possible targets and unresolved computed calls are separate. "
                        "Incoming entry references have conservative categories, "
                        "complete counts, and paged sites. Other evidence "
                        "arrays have their own complete page totals; "
                        "called_by remains Ghidra-known only."),
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("incoming_offset", type="integer", required=False, default=0,
               desc="Zero-based incoming-reference offset"),
            _p("incoming_limit", type="integer", required=False, default=100,
               desc="Incoming-reference page size, 1..500"),
            _p("evidence_offset", type="integer", required=False, default=0,
               desc="Other function-evidence array page offset"),
            _p("evidence_limit", type="integer", required=False, default=100,
               desc="Other function-evidence array page size, 1..500"),
        ],
    },
    {
        "name": "list_strings",
        "description": "List defined strings in the binary, optionally filtered.",
        "category": "query",
        "params": [_p("filter_str", required=False, default="",
                      desc=_D_FILTER)],
    },
    {
        "name": "search_memory_text",
        "description": "Search memory for an ASCII pattern.",
        "category": "query",
        "params": [_p("pattern", desc=_D_PATTERN)],
    },
    {
        "name": "search_memory_bytes",
        "description": "Search memory for a hex byte pattern.",
        "category": "query",
        "params": [_p("hex_pattern", desc=_D_HEX_PAT)],
    },
    {
        "name": "search_functions_by_name",
        "description": "Find functions whose name matches a regex pattern.",
        "category": "query",
        "params": [_p("pattern", desc=_D_PATTERN)],
    },
    {
        "name": "decompile_functions",
        "description": "Decompile up to 16 addresses with bounded batch text; truncated entries direct you to paged decompile_function.",
        "category": "query",
        "params": [_p("addresses", type="array",
                      desc="Up to 16 hex address strings",
                      items={"type": "string"})],
    },
    {
        "name": "list_function_variables",
        "description": "List decompiler-visible parameters and locals in a function with types and storage.",
        "category": "query",
        "params": [_p("addr_hex", desc=_D_ADDR)],
    },
    {
        "name": "list_function_variable_identities",
        "description": "Page and filter decompiler variable identities with storage and reported mutation eligibility; IDs are snapshot-scoped.",
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("offset", type="integer", required=False, default=0,
               desc=_D_OFFSET),
            _p("limit", type="integer", required=False, default=100,
               desc="Pagination limit (default 100, max 500)"),
            _p("filter_str", required=False, default="", desc=_D_FILTER),
        ],
    },
    {
        "name": "export_annotations",
        "description": "Return JSON of user-defined symbols, comments, and signatures for user-named functions; does not write a file.",
        "category": "query",
        "params": [],
    },
    {
        "name": "get_program_info",
        "description": "Get program metadata: architecture, compiler, format, image base, pointer size.",
        "category": "query",
        "params": [],
    },
    {
        "name": "get_program_save_state",
        "description": "Report whether a program has unsaved changes and can be saved.",
        "category": "query",
        "params": [],
    },
    {
        "name": "get_program_memory_map",
        "description": "Get Ghidra memory blocks with addresses, sizes, R/W/X permissions, initialization, volatility, and source.",
        "category": "query",
        "params": [],
    },
    {
        "name": "list_program_imports",
        "description": "List imported symbols (external dependencies) with addresses.",
        "category": "query",
        "params": [],
    },
    {
        "name": "list_program_exports",
        "description": "List exported symbols with addresses.",
        "category": "query",
        "params": [],
    },
    {
        "name": "list_program_namespaces",
        "description": "List all namespaces in the binary.",
        "category": "query",
        "params": [],
    },
    {
        "name": "list_program_classes",
        "description": "List all class namespaces.",
        "category": "query",
        "params": [],
    },
    {
        "name": "list_data_items",
        "description": "List defined data items (globals, constants, arrays). Supports offset/limit pagination.",
        "category": "query",
        "params": [
            _p("offset", type="integer", required=False, default=0,
               desc=_D_OFFSET),
            _p("limit", type="integer", required=False, default=500,
               desc=_D_LIMIT),
        ],
    },
    {
        "name": "list_memory_blocks",
        "description": "List Ghidra memory blocks with addresses, sizes, permissions, initialization, and block type.",
        "category": "query",
        "params": [],
    },
    {
        "name": "get_comment_at_address",
        "description": ("Get the containing code-unit comment. An interior "
                        "request also reports its exact and effective addresses."),
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("comment_type", required=False, default="eol",
               desc=_D_CMT_TYPE),
        ],
    },
    {
        "name": "list_bookmarks",
        "description": "List bookmarks, optionally filtered by address.",
        "category": "query",
        "params": [_p("addr_hex", required=False, default="",
                      desc=_D_ADDR)],
    },
    {
        "name": "list_structures",
        "description": "List all defined structure data types with sizes and field counts.",
        "category": "query",
        "params": [],
    },
    {
        "name": "get_structure",
        "description": "Get full structure details: fields, offsets, types, sizes.",
        "category": "query",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", required=False, default="",
               desc="Exact category path; omitted names must be unique"),
        ],
    },
    {
        "name": "get_composite",
        "description": "Get an exact structure or union with layout and bitfield metadata.",
        "category": "query",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", required=False, default="",
               desc="Exact Ghidra data-type category path"),
        ],
    },
    {
        "name": "get_function_call_graph",
        "description": ("Follow evidenced direct and resolved indirect call edges "
                        "to a configurable depth. Report unresolved computed calls, "
                        "possible targets, scan limits, and depth/revisit limits explicitly."),
        "category": "query",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("depth", type="integer", required=False, default=3,
               desc=_D_DEPTH),
        ],
    },
    {
        "name": "list_function_basic_blocks",
        "description": "Get basic blocks for a function with successor addresses.",
        "category": "query",
        "params": [_p("addr_hex", desc=_D_ADDR)],
    },
    {
        "name": "get_function_call_relationships",
        "description": ("Get bounded call-site evidence, including imported pointer "
                        "calls. Distinguish confirmed direct and resolved indirect "
                        "callees from possible targets and unresolved computed calls; "
                        "caller coverage remains Ghidra-known only."),
        "category": "query",
        "params": [_p("addr_hex", desc=_D_ADDR)],
    },
    {
        "name": "detect_security_mitigations",
        "description": "Detect binary security mitigations (NX, canaries, PIE, RELRO, fortify).",
        "category": "query",
        "params": [],
    },
    {
        "name": "find_format_string_vulns",
        "description": "Find potential format string vulnerabilities (printf-family call analysis).",
        "category": "query",
        "params": [],
    },
    {
        "name": "identify_user_input_sources",
        "description": "Find user-input entry points (recv, fgets, getenv, ReadFile, etc.) and their call sites.",
        "category": "query",
        "params": [],
    },
    {
        "name": "identify_crypto_patterns",
        "description": "Detect cryptographic implementations via magic constants and crypto-related function names.",
        "category": "query",
        "params": [],
    },
    {
        "name": "find_obfuscated_strings",
        "description": "Locate obfuscated/encoded strings: XOR loops, high-entropy data, base64 candidates.",
        "category": "query",
        "params": [],
    },

    # ================================================================
    # Mutations
    # ================================================================
    {
        "name": "set_function_name",
        "description": "Rename the function at the given address.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("new_name", desc=_D_NEW_NAME),
        ],
    },
    {
        "name": "set_function_names",
        "description": "Rename functions from a JSON file of addr/name entries, with independent per-item results.",
        "category": "mutation",
        "params": [_json_path("array")],
    },
    {
        "name": "delete_function",
        "description": "Remove only the function definition containing an address.",
        "category": "mutation",
        "params": [_p("addr_hex", desc=_D_ADDR)],
    },
    {
        "name": "set_function_body",
        "description": "Replace a function body with explicit inclusive address ranges.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("ranges", type="array", desc=_D_FUNC_RANGES,
               items=_FUNC_RANGE_ITEMS),
        ],
    },
    {
        "name": "create_function",
        "description": "Create a function, optionally with explicit body ranges.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("name", required=False, default="", desc=_D_NAME),
            _p("ranges", type="array", required=False, default=[],
               desc=_D_FUNC_RANGES, items=_FUNC_RANGE_ITEMS),
        ],
    },
    {
        "name": "create_stack_variable",
        "description": "Create an exact local stack variable without replacing overlaps.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("stack_offset", type="integer", desc=_D_STACK_OFFSET),
            _p("name", desc=_D_NAME),
            _p("type_name", desc=_D_TYPE_NAME),
            _p("size", type="integer", required=False, default=0,
               desc=_D_STACK_SIZE),
        ],
    },
    {
        "name": "delete_stack_variable",
        "description": "Delete the local stack variable starting at an exact offset.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("stack_offset", type="integer", desc=_D_STACK_OFFSET),
        ],
    },
    {
        "name": "create_stack_variable_from_structure",
        "description": "Create a local stack variable using an exact structure type.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("stack_offset", type="integer", desc=_D_STACK_OFFSET),
            _p("structure_name", desc=_D_STRUCTURE_NAME),
            _p("category_path", required=False, default="",
               desc="Exact Ghidra data-type category path"),
            _p("name", required=False, default="", desc=_D_NAME),
        ],
    },
    {
        "name": "create_functions",
        "description": "Create multiple functions from a JSON file.",
        "category": "mutation",
        "params": [_json_path("array")],
    },
    {
        "name": "disassemble_memory",
        "description": ("Follow native disassembly flow from one start address within an "
                        "inclusive range of at most 4096 bytes. The end limits flow; "
                        "it does not seed every address. Result coverage identifies "
                        "decoded, undefined, and conflicting bytes. Existing code is "
                        "never cleared."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("end_hex", required=False, default="", desc=_D_END),
        ],
    },
    {
        "name": "clear_code_units",
        "description": ("Preview or explicitly clear all defined instructions and data in an "
                        "exact initialized range. May remove references and affect "
                        "function analysis; bytes and context are preserved."),
        "category": "mutation",
        "params": [
            _p("start_hex", desc=_D_START),
            _p("end_hex", desc=_D_END),
            _p("preview_only", type="boolean", required=False, default=True,
               desc="Preview only by default; set false to clear code units."),
        ],
    },
    {
        "name": "import_annotations",
        "description": "Import function names, labels, and comments from a JSON file with independent per-item results; signature types are not applied.",
        "category": "mutation",
        "params": [_json_path("object")],
    },
    {
        "name": "fix_region",
        "description": "Fix undefined ARM code in an address range (clear + disassemble + create functions).",
        "category": "mutation",
        "params": [
            _p("start_hex", desc=_D_START),
            _p("end_hex", desc=_D_END),
        ],
    },
    {
        "name": "set_variable_name",
        "description": "Rename a uniquely named database-backed parameter or local in a function.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("old_name", desc=_D_OLD_NAME),
            _p("new_name", desc=_D_NEW_NAME),
        ],
    },
    {
        "name": "set_variable_type",
        "description": "Retype a uniquely named database-backed parameter or local in a function.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("var_name", desc=_D_VAR_NAME),
            _p("type_name", desc=_D_TYPE_NAME),
        ],
    },
    {
        "name": "set_variable_name_by_id",
        "description": ("Rename one persistable decompiler HighSymbol by fresh var_id. "
                        "Name-only inferred-parameter materialization may lock its "
                        "type; see name_only_materialization. If ID editing is "
                        "unsupported, a uniquely named database variable may be "
                        "editable with set_variable_name."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("var_id", desc="var_id returned by list_function_variable_identities"),
            _p("new_name", desc=_D_NEW_NAME),
            _p("split_use", type="boolean", required=False, default=False,
               desc="Unsupported for rename-only splitting; materialize a group with create_variable_by_id first"),
            _p("merge_group_id", required=False, default="",
               desc="Merge-group identity returned by list_function_variable_identities; required with split_use"),
        ],
    },
    {
        "name": "set_variable_type_by_id",
        "description": ("Retype one persistable decompiler HighSymbol by fresh var_id. "
                        "If ID editing is unsupported, a uniquely named database "
                        "variable may be editable with set_variable_type."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("var_id", desc="var_id returned by list_function_variable_identities"),
            _p("type_name", desc=_D_TYPE_NAME),
            _p("split_use", type="boolean", required=False, default=False,
               desc="Unsupported for retype-only splitting; materialize a group with create_variable_by_id first"),
            _p("merge_group_id", required=False, default="",
               desc="Merge-group identity returned by list_function_variable_identities; required with split_use"),
        ],
    },
    {
        "name": "create_variable_by_id",
        "description": ("Materialize database backing for one decompiler variable "
                        "or selected merge group. Name-only inferred-parameter "
                        "materialization may lock its type; see "
                        "name_only_materialization."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("var_id", desc="var_id returned by list_function_variable_identities"),
            _p("name", required=False, default="",
               desc="Stored variable name; empty keeps the decompiler name"),
            _p("type_name", required=False, default="",
               desc="Stored data type; empty keeps the decompiler type"),
            _p("split_use", type="boolean", required=False, default=False,
               desc="Materialize only one reported merge group"),
            _p("merge_group_id", required=False, default="",
               desc="Merge-group identity returned by list_function_variable_identities; required with split_use"),
        ],
    },
    {
        "name": "delete_variable_by_id",
        "description": "Delete the exact database-backed parameter or local selected by decompiler identity.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("var_id", desc="var_id returned by list_function_variable_identities"),
        ],
    },
    {
        "name": "set_function_return_type",
        "description": (
            "Set and verify a function return type while preserving effective "
            "parameters; inferred parameters require set_function_prototype."
        ),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("type_name", desc=_D_TYPE_NAME),
        ],
    },
    {
        "name": "apply_function_annotations",
        "description": (
            "Atomically annotate a function from a JSON file; return-type changes "
            "preserve effective parameters or require set_function_prototype."
        ),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _json_path("object"),
        ],
    },
    {
        "name": "set_comment_at_address",
        "description": ("Set a code-unit comment (plate, pre, post, eol, "
                        "repeatable). Interior addresses require explicit "
                        "allow_containing_item opt-in."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("comment", desc=_D_COMMENT),
            _p("comment_type", required=False, default="eol",
               desc=_D_CMT_TYPE),
            _p("allow_containing_item", type="boolean", required=False,
               default=False,
               desc="Explicitly allow an interior address to change the containing item's shared comment"),
        ],
    },
    {
        "name": "create_bookmark",
        "description": "Create or update a Note bookmark at an address and category.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("category", desc=_D_CATEGORY),
            _p("comment", required=False, default="", desc=_D_COMMENT),
        ],
    },
    {
        "name": "delete_bookmark",
        "description": "Delete a Note bookmark at an address and category.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("category", desc=_D_CATEGORY),
        ],
    },
    {
        "name": "create_structure",
        "description": "Create a new structure data type.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("size", type="integer", required=False, default=0,
               desc=_D_SIZE),
            _p("category_path", required=False, default="/",
               desc="Exact Ghidra data-type category path"),
        ],
    },
    {
        "name": "set_structure_name",
        "description": "Rename an existing structure.",
        "category": "mutation",
        "params": [
            _p("old_name", desc=_D_OLD_STRUCT),
            _p("new_name", desc=_D_NEW_NAME),
        ],
    },
    {
        "name": "delete_structure",
        "description": "Delete a structure data type.",
        "category": "mutation",
        "params": [_p("name", desc=_D_NAME)],
    },
    {
        "name": "set_structure_field",
        "description": "Insert or replace a structure field at an exact offset; replace also supports rename and retype.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", desc="Exact Ghidra data-type category path"),
            _p("offset", type="integer", desc="Exact byte offset"),
            _p("field_name", desc="Field name to store"),
            _p("type_name", desc=_D_TYPE_NAME),
            _p("mode", required=False, default="replace",
               desc="replace or insert"),
            _p("length", type="integer", required=False, default=0,
               desc="Stored length; 0 uses the resolved type length"),
            _p("comment", required=False, default="", desc=_D_COMMENT),
        ],
    },
    {
        "name": "delete_structure_field",
        "description": "Delete the defined structure field starting at an exact offset.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", desc="Exact Ghidra data-type category path"),
            _p("offset", type="integer", desc="Exact byte offset"),
        ],
    },
    {
        "name": "set_structure_layout",
        "description": "Set structure packing and minimum-alignment policy with exact read-back.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", desc="Exact Ghidra data-type category path"),
            _p("packing", desc="disabled, default, or explicit"),
            _p("alignment", desc="default, machine, or explicit"),
            _p("packing_value", type="integer", required=False, default=0,
               desc="Positive value required for explicit packing"),
            _p("alignment_value", type="integer", required=False, default=0,
               desc="Positive value required for explicit alignment"),
        ],
    },
    {
        "name": "create_union",
        "description": "Create an empty union at an exact data-type category path.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", required=False, default="/",
               desc="Exact Ghidra data-type category path"),
        ],
    },
    {
        "name": "set_union_field",
        "description": "Insert or replace a union field selected by ordinal.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", desc="Exact Ghidra data-type category path"),
            _p("ordinal", type="integer", desc="Exact union component ordinal"),
            _p("field_name", desc="Field name to store"),
            _p("type_name", desc=_D_TYPE_NAME),
            _p("mode", required=False, default="replace",
               desc="replace or insert"),
            _p("length", type="integer", required=False, default=0,
               desc="Stored length; 0 uses the resolved type length"),
            _p("comment", required=False, default="", desc=_D_COMMENT),
        ],
    },
    {
        "name": "set_composite_bitfield",
        "description": "Insert or replace an exact structure or union bitfield.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", desc="Exact Ghidra data-type category path"),
            _p("ordinal", type="integer",
               desc="Insertion/replacement ordinal; structures use it only for replacement"),
            _p("field_name", desc="Bitfield name to store"),
            _p("type_name", desc="Integer or enum bitfield base type"),
            _p("bit_size", type="integer", desc="Declared bit width; zero creates a zero-width bitfield"),
            _p("mode", required=False, default="insert",
               desc="insert or replace"),
            _p("byte_offset", type="integer", required=False, default=0,
               desc="Structure byte offset"),
            _p("storage_size", type="integer", required=False, default=0,
               desc="Structure storage-unit size in bytes"),
            _p("bit_offset", type="integer", required=False, default=0,
               desc="Structure bit offset within the storage unit"),
        ],
    },
    {
        "name": "delete_composite_field",
        "description": "Delete a structure or union field selected by exact ordinal.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", desc="Exact Ghidra data-type category path"),
            _p("ordinal", type="integer", desc="Exact component ordinal"),
        ],
    },
    {
        "name": "set_composite_layout",
        "description": "Set structure or union packing and minimum-alignment policy.",
        "category": "mutation",
        "params": [
            _p("name", desc=_D_NAME),
            _p("category_path", desc="Exact Ghidra data-type category path"),
            _p("packing", desc="disabled, default, or explicit"),
            _p("alignment", desc="default, machine, or explicit"),
            _p("packing_value", type="integer", required=False, default=0,
               desc="Positive value required for explicit packing"),
            _p("alignment_value", type="integer", required=False, default=0,
               desc="Positive value required for explicit alignment"),
        ],
    },
    {
        "name": "write_memory_bytes",
        "description": "Write raw bytes at an address (hex string, e.g. '90909090').",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("hex_bytes", desc=_D_HEX_BYTES),
        ],
    },
    {
        "name": "save_program",
        "description": "Explicitly save a program's pending changes.",
        "category": "mutation",
        "params": [
            _p("comment", required=False, default="Saved by GhidraMSC",
               desc=("Requested save comment; applied only when the selected "
                     "persistence backend supports custom comments")),
        ],
    },
    {
        "name": "set_function_prototype",
        "description": "Set full C-style function signature/prototype.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("prototype", desc=_D_PROTO),
        ],
    },
    {
        "name": "set_function_calling_convention",
        "description": ("Set a convention supported by the current program; "
                        "validation errors list available names. 'default' is supported."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("convention", desc=_D_CONV),
        ],
    },
    {
        "name": "set_function_noreturn",
        "description": ("Set or clear Ghidra's native function no-return flag. "
                        "A thunk changes its effective target; the result identifies "
                        "both entries and verifies the stored flag. Existing "
                        "CALL_RETURN flow overrides at caller instructions remain "
                        "in place and can still truncate decompilation."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("no_return", type="boolean",
               desc="True if the function never returns; false to clear the flag."),
        ],
    },
    {
        "name": "set_instruction_flow_override",
        "description": ("Set Ghidra's native flow override on one exact instruction. "
                        "Use NONE to clear a saved CALL_RETURN override after "
                        "checking the call and its target. Returns old and stored "
                        "flow type and fallthrough; preserves instruction bytes "
                        "and listing. Does not change a function's no-return flag."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc="Exact instruction start address in hex."),
            _p("flow_override", desc="Native FlowOverride enum name, such as NONE or CALL_RETURN."),
        ],
    },
    {
        "name": "set_data_label",
        "description": "Set the primary label of an existing defined data item; cannot label code or undefined bytes.",
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("new_name", desc=_D_NEW_NAME),
        ],
    },
    {
        "name": "set_address_label",
        "description": ("Set the primary label at an exact mapped address, including an "
                        "instruction, undefined byte, BSS, or overlay. Preserve its namespace "
                        "and verify the stored primary symbol. Function entries use "
                        "set_function_name; unmapped addresses are rejected."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("new_name", desc=_D_NEW_NAME),
        ],
    },
    {
        "name": "apply_data_type",
        "description": ("Apply a fixed-size scalar, pointer, array, or composite type in "
                        "mapped memory, including up to 4096 bytes in an "
                        "uninitialized BSS block. BSS stays uninitialized; "
                        "no file bytes are created. Conflicts are preserved by default; "
                        "label defined data with set_data_label."),
        "category": "mutation",
        "params": [
            _p("addr_hex", desc=_D_ADDR),
            _p("type_name", desc=_D_TYPE_NAME),
            _p("clear_mode", required=False, default="fail",
               desc="Conflict policy: fail or data_only; instructions are never cleared."),
        ],
    },
    {
        "name": "set_program_image_base",
        "description": "Set the image base address of the program.",
        "category": "mutation",
        "params": [_p("addr_hex", desc=_D_ADDR)],
    },
    {
        "name": "set_memory_block_permissions",
        "description": "Set all R/W/X permissions on a named memory block; omitted bits default to read=true, write=false, execute=false.",
        "category": "mutation",
        "params": [
            _p("block_name", desc=_D_BLOCK),
            _p("read", type="boolean", required=False, default=True,
               desc=_D_READ),
            _p("write", type="boolean", required=False, default=False,
               desc=_D_WRITE),
            _p("execute", type="boolean", required=False, default=False,
               desc=_D_EXECUTE),
        ],
    },
    {
        "name": "create_memory_block",
        "description": ("Create one bounded analysis memory block (at most 4096 bytes). "
                        "Modes: uninitialized, fill, exact bytes, or byte_mapped. "
                        "byte_mapped aliases its initialized source; writes can change source bytes. "
                        "Overlay creation uses a separate address space. Preview first to inspect overlaps."),
        "category": "mutation",
        "params": [
            _p("block_name", desc=_D_BLOCK),
            _p("addr_hex", desc=_D_ADDR),
            _p("length", type="integer", desc="Exact block length, 1..4096 bytes"),
            _p("mode", desc="uninitialized, fill, bytes, or byte_mapped"),
            _p("overlay", type="boolean", required=False, default=False,
               desc="Create a separate overlay address space"),
            _p("read", type="boolean", required=False, default=True, desc=_D_READ),
            _p("write", type="boolean", required=False, default=True, desc=_D_WRITE),
            _p("execute", type="boolean", required=False, default=False, desc=_D_EXECUTE),
            _p("fill_byte", type="integer", required=False, default=0,
               desc="0..255 fill byte for fill mode"),
            _p("hex_bytes", required=False, default="",
               desc="Exactly length bytes of hex for bytes mode"),
            _p("source_addr_hex", required=False, default="",
               desc="Initialized source start for byte_mapped alias mode"),
            _p("preview_only", type="boolean", required=False, default=False,
               desc="Inspect proposed map without starting a transaction"),
        ],
    },
    {
        "name": "delete_memory_block",
        "description": ("Remove an exact GhidraMSC-created analysis block. Native removal "
                        "deletes analysis content in the range; preview it first and explicitly "
                        "confirm when code, data, or symbols are present."),
        "category": "mutation",
        "params": [
            _p("block_name", desc=_D_BLOCK),
            _p("start", desc="Exact qualified start returned by the memory map"),
            _p("length", type="integer", desc="Exact block length"),
            _p("preview_only", type="boolean", required=False, default=False,
               desc="Inspect content without starting a transaction"),
            _p("confirm_content_removal", type="boolean", required=False,
               default=False, desc="Allow deletion of code, data, and symbols in this block"),
        ],
    },
    {
        "name": "create_recovered_code_overlay",
        "description": ("Copy 1..65536 exact recovered code bytes into a new executable overlay "
                        "without changing physical/source bytes. Record source and optional runtime "
                        "address provenance. A physical overlap requires explicit opt-in. The returned "
                        "qualified overlay address works with read, disassembly, and function tools. "
                        "Delete later with exact delete_memory_block identity."),
        "category": "mutation",
        "params": [
            _p("block_name", desc="Unique name for the recovered overlay"),
            _p("analysis_addr_hex", desc="Physical offset where the overlay is placed"),
            _p("hex_bytes", desc="Exact recovered bytes as hex, 1..65536 bytes"),
            _p("transform", desc="Short provenance label, such as XOR key or unpacking step"),
            _p("source_addr_hex", required=False, default="",
               desc="Optional physical source range start; requires source_length"),
            _p("source_length", type="integer", required=False, default=0,
               desc="Source range length, 0..65536; not the recovered length"),
            _p("runtime_addr_hex", required=False, default="",
               desc="Optional known runtime address, bare hex; empty means unknown"),
            _p("allow_physical_overlap", type="boolean", required=False, default=False,
               desc="Explicitly allow the overlay to share an offset with physical memory"),
            _p("preview_only", type="boolean", required=False, default=False,
               desc="Inspect overlaps and hashes without creating a block"),
        ],
    },
]

# -- Availability policy and convenience accessors --------------------

# These implementations are intentionally retained for possible future
# repair, but they are not public tools in this release.  The five queries
# make GhidraMSC-owned semantic judgments rather than delegating to a native
# Ghidra capability.  fix_region similarly adds GhidraMSC-owned function-entry
# inference on top of native disassembly and function-creation commands.
DISABLED_TOOL_NAMES: FrozenSet[str] = frozenset({
    "detect_security_mitigations",
    "find_format_string_vulns",
    "identify_user_input_sources",
    "identify_crypto_patterns",
    "find_obfuscated_strings",
    "fix_region",
})

TOOLS: List[Dict[str, Any]] = [
    tool for tool in TOOL_DEFINITIONS
    if tool["name"] not in DISABLED_TOOL_NAMES
]

_BY_NAME: Dict[str, Dict[str, Any]] = {t["name"]: t for t in TOOLS}


def get_tool(name: str) -> Dict[str, Any]:
    """Return the registry entry for *name*, or raise KeyError."""
    return _BY_NAME[name]


def all_tool_names() -> List[str]:
    """Return all available tool names in declaration order."""
    return [t["name"] for t in TOOLS]


def query_tool_names() -> List[str]:
    """Return tool names where category == 'query'."""
    return [t["name"] for t in TOOLS if t["category"] == "query"]


def mutation_tool_names() -> List[str]:
    """Return tool names where category == 'mutation'."""
    return [t["name"] for t in TOOLS if t["category"] == "mutation"]


def tool_mcp_modes(tool: Dict[str, Any]) -> Tuple[str, ...]:
    """Return the MCP execution modes supported by one registry entry."""
    return tuple(tool.get("mcp_modes", MCP_EXECUTION_MODES))


def tool_accepts_mcp_binary(tool: Dict[str, Any]) -> bool:
    """Return whether MCP accepts its transport-level binary selector."""
    return bool(tool.get("mcp_binary", True))


def _matches_json_type(value: Any, expected: str) -> bool:
    checks = {
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: type(item) is int,
        "number": lambda item: (
            isinstance(item, (int, float)) and not isinstance(item, bool)
        ),
        "boolean": lambda item: isinstance(item, bool),
        "array": lambda item: isinstance(item, list),
        "object": lambda item: isinstance(item, dict),
    }
    check = checks.get(expected)
    return check is not None and check(value)


def _validate_schema_fragment(value: Any, schema: Dict[str, Any], path: str) -> Optional[str]:
    """Validate the small JSON-Schema subset used by registry parameters."""
    expected = schema.get("type")
    if expected and not _matches_json_type(value, expected):
        return "Invalid argument type for {}: expected {}".format(
            path, expected
        )

    if expected == "array" and "items" in schema:
        for index, item in enumerate(value):
            error = _validate_schema_fragment(
                item, schema["items"], "{}[{}]".format(path, index)
            )
            if error is not None:
                return error

    if expected == "object":
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                return "Missing required argument for {}: {}".format(
                    path, name
                )
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                return "Unknown argument(s) for {}: {}".format(
                    path, ", ".join(unknown)
                )
        for name, child in value.items():
            child_schema = properties.get(name)
            if child_schema is None:
                continue
            error = _validate_schema_fragment(
                child, child_schema, "{}.{}".format(path, name)
            )
            if error is not None:
                return error
    return None


def validate_tool_arguments(
    command: str,
    args: Any,
    *,
    include_mcp_binary: bool = False,
) -> Optional[str]:
    """Return a registry-derived argument error, or ``None`` when valid."""
    try:
        tool = get_tool(command)
    except KeyError:
        return "Unknown command: {}".format(command)
    if not isinstance(args, dict):
        return "args must be a JSON object"

    declared = {param["name"]: param for param in tool["params"]}
    if include_mcp_binary and tool_accepts_mcp_binary(tool):
        declared["binary"] = {
            "name": "binary", "type": "string", "required": False,
        }
    unknown = sorted(set(args) - set(declared))
    if unknown:
        return "Unknown argument(s) for {}: {}".format(
            command, ", ".join(unknown)
        )

    for name, param in declared.items():
        if param["required"] and name not in args:
            return "Missing required argument for {}: {}".format(
                command, name
            )
        if name not in args:
            continue
        error = _validate_schema_fragment(
            args[name], param, "{}.{}".format(command, name)
        )
        if error is not None:
            return error
    return None
