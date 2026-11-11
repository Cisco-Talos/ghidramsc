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

"""CLI command adapters: preserve command-specific argument handling."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any, Dict, List, Optional

from . import queries
from .config import load_config
from ._cli_execution import (
    _try_server, _emit_server_result, _open_bridge, _emit,
    _save_completed, _unwrap_server_result,
)


def cmd_list_programs(ns: argparse.Namespace) -> int:
    srv = _try_server("list_programs", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_project() as project:
        result = {"programs": project.list_programs()}
    _emit(result, ns)
    return 0

def cmd_list_functions(ns: argparse.Namespace) -> int:
    srv = _try_server("list_functions", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_functions(ctx)
    _emit(result, ns)
    return 0


def cmd_decompile_function(ns: argparse.Namespace) -> int:
    args = {"addr_hex": ns.address, "offset": ns.offset, "limit": ns.limit}
    srv = _try_server("decompile_function", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.decompile_function(ctx, ns.address, ns.offset, ns.limit)
    _emit(result, ns)
    return 0


def cmd_list_references_to_address(ns: argparse.Namespace) -> int:
    srv = _try_server("list_references_to_address", {
        "addr_hex": ns.address, "offset": ns.offset, "limit": ns.limit,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_references_to_address(
            ctx, ns.address, ns.offset, ns.limit)
    _emit(result, ns)
    return 0


def cmd_list_references_from_address(ns: argparse.Namespace) -> int:
    srv = _try_server("list_references_from_address", {
        "addr_hex": ns.address, "offset": ns.offset, "limit": ns.limit,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_references_from_address(
            ctx, ns.address, ns.offset, ns.limit)
    _emit(result, ns)
    return 0


def cmd_get_listing_at_address(ns: argparse.Namespace) -> int:
    count = ns.count if ns.count is not None else 40
    srv = _try_server("get_listing_at_address", {
        "addr_hex": ns.address, "count": count,
        "offset": ns.offset, "limit": ns.limit,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_listing_at_address(
            ctx, ns.address, count, ns.offset, ns.limit)
    _emit(result, ns)
    return 0


def cmd_get_function_info(ns: argparse.Namespace) -> int:
    srv = _try_server("get_function_info", {
        "addr_hex": ns.address, "incoming_offset": ns.incoming_offset,
        "incoming_limit": ns.incoming_limit,
        "evidence_offset": ns.evidence_offset,
        "evidence_limit": ns.evidence_limit,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_function_info(
            ctx, ns.address, ns.incoming_offset, ns.incoming_limit,
            ns.evidence_offset, ns.evidence_limit)
    _emit(result, ns)
    return 0


def cmd_list_strings(ns: argparse.Namespace) -> int:
    srv = _try_server("list_strings", {"filter_str": ns.filter or ""}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_strings(ctx, ns.filter or "")
    _emit(result, ns)
    return 0


def cmd_search_memory_text(ns: argparse.Namespace) -> int:
    srv = _try_server("search_memory_text", {"pattern": ns.pattern}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.search_memory_text(ctx, ns.pattern)
    _emit(result, ns)
    return 0


def cmd_search_memory_bytes(ns: argparse.Namespace) -> int:
    srv = _try_server("search_memory_bytes", {"hex_pattern": ns.hex_bytes}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.search_memory_bytes(ctx, ns.hex_bytes)
    _emit(result, ns)
    return 0


def cmd_search_functions_by_name(ns: argparse.Namespace) -> int:
    srv = _try_server("search_functions_by_name", {"pattern": ns.pattern}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.search_functions_by_name(ctx, ns.pattern)
    _emit(result, ns)
    return 0


def cmd_set_function_name(ns: argparse.Namespace) -> int:
    srv = _try_server("set_function_name", {"addr_hex": ns.address, "new_name": ns.name}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_function_name(ctx, ns.address, ns.name)
    _emit(result, ns)
    return 0


def cmd_set_function_names(ns: argparse.Namespace) -> int:
    srv = _try_server("set_function_names", {"json_path": ns.json_path}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_function_names(ctx, ns.json_path)
    _emit(result, ns)
    return 0


def _cli_function_ranges(values: list[str]) -> list[dict[str, str]]:
    ranges = []
    for value in values:
        # A qualified address contains "::"; only a standalone colon
        # separates the two inclusive endpoints.
        separators = list(re.finditer(r"(?<!:):(?!:)", value))
        if len(separators) != 1:
            raise ValueError(
                "Function range must use START:END, got '{}'".format(value))
        separator = separators[0].start()
        start, end = value[:separator], value[separator + 1:]
        if not start or not end:
            raise ValueError(
                "Function range must use START:END, got '{}'".format(value))
        ranges.append({"start": start, "end": end})
    return ranges


def cmd_delete_function(ns: argparse.Namespace) -> int:
    srv = _try_server("delete_function", {"addr_hex": ns.address}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_function(ctx, ns.address)
    _emit(result, ns)
    return 0


def cmd_set_function_body(ns: argparse.Namespace) -> int:
    ranges = _cli_function_ranges(ns.ranges)
    srv = _try_server(
        "set_function_body", {"addr_hex": ns.address, "ranges": ranges}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_function_body(ctx, ns.address, ranges)
    _emit(result, ns)
    return 0


def cmd_create_function(ns: argparse.Namespace) -> int:
    ranges = _cli_function_ranges(ns.ranges) if ns.ranges else None
    request = {"addr_hex": ns.address, "name": ns.name or ""}
    if ranges is not None:
        request["ranges"] = ranges
    srv = _try_server("create_function", request, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_function(
            ctx, ns.address, ns.name or "", ranges)
    _emit(result, ns)
    return 0


def cmd_create_stack_variable(ns: argparse.Namespace) -> int:
    request = {
        "addr_hex": ns.address,
        "stack_offset": ns.stack_offset,
        "name": ns.name,
        "type_name": ns.type_name,
        "size": ns.size,
    }
    srv = _try_server("create_stack_variable", request, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_stack_variable(
            ctx, ns.address, ns.stack_offset, ns.name, ns.type_name, ns.size)
    _emit(result, ns)
    return 0


def cmd_delete_stack_variable(ns: argparse.Namespace) -> int:
    request = {"addr_hex": ns.address, "stack_offset": ns.stack_offset}
    srv = _try_server("delete_stack_variable", request, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_stack_variable(ctx, ns.address, ns.stack_offset)
    _emit(result, ns)
    return 0


def cmd_create_stack_variable_from_structure(ns: argparse.Namespace) -> int:
    request = {
        "addr_hex": ns.address,
        "stack_offset": ns.stack_offset,
        "structure_name": ns.structure_name,
        "category_path": ns.category_path,
        "name": ns.name,
    }
    srv = _try_server("create_stack_variable_from_structure", request, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_stack_variable_from_structure(
            ctx,
            ns.address,
            ns.stack_offset,
            ns.structure_name,
            ns.category_path,
            ns.name,
        )
    _emit(result, ns)
    return 0


def cmd_create_functions(ns: argparse.Namespace) -> int:
    srv = _try_server("create_functions", {"json_path": ns.json_path}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_functions(ctx, ns.json_path)
    _emit(result, ns)
    return 0


def cmd_disassemble_memory(ns: argparse.Namespace) -> int:
    srv = _try_server("disassemble_memory", {"addr_hex": ns.address, "end_hex": ns.end or ""}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.disassemble_memory(ctx, ns.address, ns.end or "")
    _emit(result, ns)
    return 0


def cmd_clear_code_units(ns: argparse.Namespace) -> int:
    args = {
        "start_hex": ns.start,
        "end_hex": ns.end,
        "preview_only": not ns.apply,
    }
    srv = _try_server("clear_code_units", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.clear_code_units(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_export_annotations(ns: argparse.Namespace) -> int:
    srv = _try_server("export_annotations", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.export_annotations(ctx)
    _emit(result, ns)
    return 0


def cmd_import_annotations(ns: argparse.Namespace) -> int:
    srv = _try_server("import_annotations", {"json_path": ns.json_path}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.import_annotations(ctx, ns.json_path)
    _emit(result, ns)
    return 0


def cmd_fix_region(ns: argparse.Namespace) -> int:
    srv = _try_server("fix_region", {"start_hex": ns.start, "end_hex": ns.end}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.fix_region(ctx, ns.start, ns.end)
    _emit(result, ns)
    return 0


def cmd_list_function_variables(ns: argparse.Namespace) -> int:
    srv = _try_server("list_function_variables", {"addr_hex": ns.address}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_function_variables(ctx, ns.address)
    _emit(result, ns)
    return 0


def cmd_list_function_variable_identities(ns: argparse.Namespace) -> int:
    args = {
        "addr_hex": ns.address,
        "offset": ns.offset,
        "limit": ns.limit,
        "filter_str": ns.filter_str,
    }
    srv = _try_server("list_function_variable_identities", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_function_variable_identities(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_variable_name(ns: argparse.Namespace) -> int:
    srv = _try_server("set_variable_name", {
        "addr_hex": ns.address,
        "old_name": ns.old_name,
        "new_name": ns.new_name,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_variable_name(ctx, ns.address, ns.old_name, ns.new_name)
    _emit(result, ns)
    return 0


def cmd_set_variable_type(ns: argparse.Namespace) -> int:
    srv = _try_server("set_variable_type", {
        "addr_hex": ns.address,
        "var_name": ns.var_name,
        "type_name": ns.type_name,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_variable_type(ctx, ns.address, ns.var_name, ns.type_name)
    _emit(result, ns)
    return 0


def cmd_set_variable_name_by_id(ns: argparse.Namespace) -> int:
    args = {
        "addr_hex": ns.address,
        "var_id": ns.var_id,
        "new_name": ns.new_name,
        "split_use": ns.split_use,
        "merge_group_id": ns.merge_group_id,
    }
    srv = _try_server("set_variable_name_by_id", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_variable_name_by_id(
            ctx, ns.address, ns.var_id, ns.new_name, ns.split_use,
            ns.merge_group_id,
        )
    _emit(result, ns)
    return 0


def cmd_set_variable_type_by_id(ns: argparse.Namespace) -> int:
    args = {
        "addr_hex": ns.address,
        "var_id": ns.var_id,
        "type_name": ns.type_name,
        "split_use": ns.split_use,
        "merge_group_id": ns.merge_group_id,
    }
    srv = _try_server("set_variable_type_by_id", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_variable_type_by_id(
            ctx, ns.address, ns.var_id, ns.type_name, ns.split_use,
            ns.merge_group_id,
        )
    _emit(result, ns)
    return 0


def cmd_create_variable_by_id(ns: argparse.Namespace) -> int:
    args = {
        "addr_hex": ns.address,
        "var_id": ns.var_id,
        "name": ns.name,
        "type_name": ns.type_name,
        "split_use": ns.split_use,
        "merge_group_id": ns.merge_group_id,
    }
    srv = _try_server("create_variable_by_id", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_variable_by_id(ctx, ns.address, ns.var_id,
            ns.name, ns.type_name, ns.split_use, ns.merge_group_id)
    _emit(result, ns)
    return 0


def cmd_delete_variable_by_id(ns: argparse.Namespace) -> int:
    args = {"addr_hex": ns.address, "var_id": ns.var_id}
    srv = _try_server("delete_variable_by_id", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_variable_by_id(ctx, ns.address, ns.var_id)
    _emit(result, ns)
    return 0


def cmd_set_function_return_type(ns: argparse.Namespace) -> int:
    srv = _try_server("set_function_return_type", {"addr_hex": ns.address, "type_name": ns.type_name}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_function_return_type(ctx, ns.address, ns.type_name)
    _emit(result, ns)
    return 0


def cmd_apply_function_annotations(ns: argparse.Namespace) -> int:
    srv = _try_server("apply_function_annotations", {"addr_hex": ns.address, "json_path": ns.json_path}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.apply_function_annotations(ctx, ns.address, ns.json_path)
    _emit(result, ns)
    return 0


def cmd_decompile_functions(ns: argparse.Namespace) -> int:
    addresses = [a.strip() for a in ns.addresses.split(",") if a.strip()]
    srv = _try_server("decompile_functions", {"addresses": addresses}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.decompile_functions(ctx, addresses)
    _emit(result, ns)
    return 0


# -------------------------------------------------------------------
# New tool handlers
# -------------------------------------------------------------------

def cmd_get_program_info(ns: argparse.Namespace) -> int:
    srv = _try_server("get_program_info", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_program_info(ctx)
    _emit(result, ns)
    return 0


def cmd_get_program_save_state(ns: argparse.Namespace) -> int:
    srv = _try_server("get_program_save_state", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_program_save_state(ctx)
    _emit(result, ns)
    return 0


def cmd_save_program(ns: argparse.Namespace) -> int:
    args = {"comment": ns.comment}
    from . import client
    try:
        srv = _try_server("save_program", args, ns)
    except client.ServerQueryError as exc:
        _emit(exc.payload, ns)
        return 1
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0 if _save_completed(_unwrap_server_result(srv)) else 1
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.save_program(ctx, ns.comment)
    _emit(result, ns)
    return 0 if _save_completed(result) else 1


def cmd_get_program_memory_map(ns: argparse.Namespace) -> int:
    srv = _try_server("get_program_memory_map", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_program_memory_map(ctx)
    _emit(result, ns)
    return 0


def cmd_list_program_imports(ns: argparse.Namespace) -> int:
    srv = _try_server("list_program_imports", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_program_imports(ctx)
    _emit(result, ns)
    return 0


def cmd_list_program_exports(ns: argparse.Namespace) -> int:
    srv = _try_server("list_program_exports", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_program_exports(ctx)
    _emit(result, ns)
    return 0


def cmd_list_program_namespaces(ns: argparse.Namespace) -> int:
    srv = _try_server("list_program_namespaces", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_program_namespaces(ctx)
    _emit(result, ns)
    return 0


def cmd_list_program_classes(ns: argparse.Namespace) -> int:
    srv = _try_server("list_program_classes", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_program_classes(ctx)
    _emit(result, ns)
    return 0


def cmd_list_data_items(ns: argparse.Namespace) -> int:
    offset = ns.offset if ns.offset else 0
    limit = ns.limit if ns.limit else 500
    srv = _try_server("list_data_items", {"offset": offset, "limit": limit}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_data_items(ctx, offset, limit)
    _emit(result, ns)
    return 0


def cmd_list_memory_blocks(ns: argparse.Namespace) -> int:
    srv = _try_server("list_memory_blocks", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_memory_blocks(ctx)
    _emit(result, ns)
    return 0


def cmd_set_comment_at_address(ns: argparse.Namespace) -> int:
    ct = ns.comment_type if ns.comment_type else "eol"
    srv = _try_server("set_comment_at_address", {
        "addr_hex": ns.address, "comment": ns.comment, "comment_type": ct,
        "allow_containing_item": ns.allow_containing_item,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_comment_at_address(
            ctx, ns.address, ns.comment, ct, ns.allow_containing_item
        )
    _emit(result, ns)
    return 0


def cmd_get_comment_at_address(ns: argparse.Namespace) -> int:
    ct = ns.comment_type if ns.comment_type else "eol"
    srv = _try_server("get_comment_at_address", {
        "addr_hex": ns.address, "comment_type": ct,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_comment_at_address(ctx, ns.address, ct)
    _emit(result, ns)
    return 0


def cmd_create_bookmark(ns: argparse.Namespace) -> int:
    srv = _try_server("create_bookmark", {
        "addr_hex": ns.address, "category": ns.category,
        "comment": ns.comment or "",
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_bookmark(ctx, ns.address, ns.category, ns.comment or "")
    _emit(result, ns)
    return 0


def cmd_delete_bookmark(ns: argparse.Namespace) -> int:
    srv = _try_server("delete_bookmark", {
        "addr_hex": ns.address, "category": ns.category,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_bookmark(ctx, ns.address, ns.category)
    _emit(result, ns)
    return 0


def cmd_list_bookmarks(ns: argparse.Namespace) -> int:
    addr = ns.address if ns.address else ""
    srv = _try_server("list_bookmarks", {"addr_hex": addr}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_bookmarks(ctx, addr)
    _emit(result, ns)
    return 0


def cmd_list_structures(ns: argparse.Namespace) -> int:
    srv = _try_server("list_structures", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_structures(ctx)
    _emit(result, ns)
    return 0


def cmd_get_structure(ns: argparse.Namespace) -> int:
    args = {"name": ns.name, "category_path": ns.category_path}
    srv = _try_server("get_structure", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_structure(ctx, ns.name, ns.category_path)
    _emit(result, ns)
    return 0


def cmd_get_composite(ns: argparse.Namespace) -> int:
    args = {"name": ns.name, "category_path": ns.category_path}
    srv = _try_server("get_composite", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_composite(ctx, ns.name, ns.category_path)
    _emit(result, ns)
    return 0


def cmd_create_structure(ns: argparse.Namespace) -> int:
    sz = ns.size if ns.size else 0
    args = {
        "name": ns.name,
        "size": sz,
        "category_path": ns.category_path,
    }
    srv = _try_server("create_structure", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_structure(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_structure_name(ns: argparse.Namespace) -> int:
    srv = _try_server("set_structure_name", {
        "old_name": ns.old_name, "new_name": ns.new_name,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_structure_name(ctx, ns.old_name, ns.new_name)
    _emit(result, ns)
    return 0


def cmd_delete_structure(ns: argparse.Namespace) -> int:
    srv = _try_server("delete_structure", {"name": ns.name}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_structure(ctx, ns.name)
    _emit(result, ns)
    return 0


def cmd_set_structure_field(ns: argparse.Namespace) -> int:
    args = {
        "name": ns.name, "category_path": ns.category_path,
        "offset": ns.offset, "field_name": ns.field_name,
        "type_name": ns.type_name, "mode": ns.mode,
        "length": ns.length, "comment": ns.comment,
    }
    srv = _try_server("set_structure_field", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_structure_field(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_delete_structure_field(ns: argparse.Namespace) -> int:
    args = {
        "name": ns.name, "category_path": ns.category_path,
        "offset": ns.offset,
    }
    srv = _try_server("delete_structure_field", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_structure_field(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_structure_layout(ns: argparse.Namespace) -> int:
    args = {
        "name": ns.name, "category_path": ns.category_path,
        "packing": ns.packing, "packing_value": ns.packing_value,
        "alignment": ns.alignment, "alignment_value": ns.alignment_value,
    }
    srv = _try_server("set_structure_layout", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_structure_layout(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_create_union(ns: argparse.Namespace) -> int:
    args = {"name": ns.name, "category_path": ns.category_path}
    srv = _try_server("create_union", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_union(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_union_field(ns: argparse.Namespace) -> int:
    args = {
        "name": ns.name, "category_path": ns.category_path,
        "ordinal": ns.ordinal, "field_name": ns.field_name,
        "type_name": ns.type_name, "mode": ns.mode,
        "length": ns.length, "comment": ns.comment,
    }
    srv = _try_server("set_union_field", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_union_field(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_composite_bitfield(ns: argparse.Namespace) -> int:
    args = {
        "name": ns.name, "category_path": ns.category_path,
        "ordinal": ns.ordinal, "field_name": ns.field_name,
        "type_name": ns.type_name, "bit_size": ns.bit_size,
        "mode": ns.mode, "byte_offset": ns.byte_offset,
        "storage_size": ns.storage_size, "bit_offset": ns.bit_offset,
    }
    srv = _try_server("set_composite_bitfield", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_composite_bitfield(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_delete_composite_field(ns: argparse.Namespace) -> int:
    args = {
        "name": ns.name, "category_path": ns.category_path,
        "ordinal": ns.ordinal,
    }
    srv = _try_server("delete_composite_field", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_composite_field(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_composite_layout(ns: argparse.Namespace) -> int:
    args = {
        "name": ns.name, "category_path": ns.category_path,
        "packing": ns.packing, "packing_value": ns.packing_value,
        "alignment": ns.alignment, "alignment_value": ns.alignment_value,
    }
    srv = _try_server("set_composite_layout", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_composite_layout(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_get_function_call_graph(ns: argparse.Namespace) -> int:
    depth = ns.depth if ns.depth else 3
    srv = _try_server("get_function_call_graph", {
        "addr_hex": ns.address, "depth": depth,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_function_call_graph(ctx, ns.address, depth)
    _emit(result, ns)
    return 0


def cmd_list_function_basic_blocks(ns: argparse.Namespace) -> int:
    srv = _try_server("list_function_basic_blocks", {"addr_hex": ns.address}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_function_basic_blocks(ctx, ns.address)
    _emit(result, ns)
    return 0


def cmd_get_function_call_relationships(ns: argparse.Namespace) -> int:
    srv = _try_server("get_function_call_relationships", {"addr_hex": ns.address}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_function_call_relationships(ctx, ns.address)
    _emit(result, ns)
    return 0


def cmd_write_memory_bytes(ns: argparse.Namespace) -> int:
    srv = _try_server("write_memory_bytes", {
        "addr_hex": ns.address, "hex_bytes": ns.hex_bytes,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.write_memory_bytes(ctx, ns.address, ns.hex_bytes)
    _emit(result, ns)
    return 0


def cmd_set_function_prototype(ns: argparse.Namespace) -> int:
    srv = _try_server("set_function_prototype", {
        "addr_hex": ns.address, "prototype": ns.prototype,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_function_prototype(ctx, ns.address, ns.prototype)
    _emit(result, ns)
    return 0


def cmd_set_function_calling_convention(ns: argparse.Namespace) -> int:
    srv = _try_server("set_function_calling_convention", {
        "addr_hex": ns.address, "convention": ns.convention,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_function_calling_convention(ctx, ns.address, ns.convention)
    _emit(result, ns)
    return 0


def cmd_set_function_noreturn(ns: argparse.Namespace) -> int:
    args = {"addr_hex": ns.address, "no_return": ns.no_return == "true"}
    srv = _try_server("set_function_noreturn", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_function_noreturn(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_instruction_flow_override(ns: argparse.Namespace) -> int:
    args = {"addr_hex": ns.address, "flow_override": ns.flow_override}
    srv = _try_server("set_instruction_flow_override", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_instruction_flow_override(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_set_data_label(ns: argparse.Namespace) -> int:
    srv = _try_server("set_data_label", {
        "addr_hex": ns.address, "new_name": ns.name,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_data_label(ctx, ns.address, ns.name)
    _emit(result, ns)
    return 0


def cmd_set_address_label(ns: argparse.Namespace) -> int:
    args = {"addr_hex": ns.address, "new_name": ns.name}
    srv = _try_server("set_address_label", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_address_label(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_apply_data_type(ns: argparse.Namespace) -> int:
    srv = _try_server("apply_data_type", {
        "addr_hex": ns.address, "type_name": ns.type_name,
        "clear_mode": ns.clear_mode,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.apply_data_type(
            ctx, ns.address, ns.type_name, ns.clear_mode)
    _emit(result, ns)
    return 0


def cmd_detect_security_mitigations(ns: argparse.Namespace) -> int:
    srv = _try_server("detect_security_mitigations", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.detect_security_mitigations(ctx)
    _emit(result, ns)
    return 0


def cmd_find_format_string_vulns(ns: argparse.Namespace) -> int:
    srv = _try_server("find_format_string_vulns", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.find_format_string_vulns(ctx)
    _emit(result, ns)
    return 0


def cmd_set_program_image_base(ns: argparse.Namespace) -> int:
    srv = _try_server("set_program_image_base", {"addr_hex": ns.address}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_program_image_base(ctx, ns.address)
    _emit(result, ns)
    return 0


def cmd_set_memory_block_permissions(ns: argparse.Namespace) -> int:
    srv = _try_server("set_memory_block_permissions", {
        "block_name": ns.block_name,
        "read": ns.read, "write": ns.write, "execute": ns.execute,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.set_memory_block_permissions(
            ctx, ns.block_name, ns.read, ns.write, ns.execute)
    _emit(result, ns)
    return 0


def cmd_create_memory_block(ns: argparse.Namespace) -> int:
    args = dict(block_name=ns.block_name, addr_hex=ns.address,
                length=ns.length, mode=ns.mode, overlay=ns.overlay,
                read=ns.read, write=ns.write, execute=ns.execute,
                fill_byte=ns.fill_byte, hex_bytes=ns.hex_bytes,
                source_addr_hex=ns.source_addr_hex,
                preview_only=ns.preview_only)
    srv = _try_server("create_memory_block", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_memory_block(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_delete_memory_block(ns: argparse.Namespace) -> int:
    args = dict(block_name=ns.block_name, start=ns.start,
                length=ns.length, preview_only=ns.preview_only,
                confirm_content_removal=ns.confirm_content_removal)
    srv = _try_server("delete_memory_block", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.delete_memory_block(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_create_recovered_code_overlay(ns: argparse.Namespace) -> int:
    args = dict(block_name=ns.block_name,
                analysis_addr_hex=ns.analysis_addr_hex,
                hex_bytes=ns.hex_bytes,
                source_addr_hex=ns.source_addr_hex,
                source_length=ns.source_length,
                runtime_addr_hex=ns.runtime_addr_hex,
                transform=ns.transform,
                allow_physical_overlap=ns.allow_physical_overlap,
                preview_only=ns.preview_only)
    srv = _try_server("create_recovered_code_overlay", args, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.create_recovered_code_overlay(ctx, **args)
    _emit(result, ns)
    return 0


def cmd_identify_user_input_sources(ns: argparse.Namespace) -> int:
    srv = _try_server("identify_user_input_sources", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.identify_user_input_sources(ctx)
    _emit(result, ns)
    return 0


def cmd_identify_crypto_patterns(ns: argparse.Namespace) -> int:
    srv = _try_server("identify_crypto_patterns", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.identify_crypto_patterns(ctx)
    _emit(result, ns)
    return 0


def cmd_find_obfuscated_strings(ns: argparse.Namespace) -> int:
    srv = _try_server("find_obfuscated_strings", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.find_obfuscated_strings(ctx)
    _emit(result, ns)
    return 0


def cmd_read_memory_bytes(ns: argparse.Namespace) -> int:
    length = ns.length if ns.length else 256
    srv = _try_server("read_memory_bytes", {"addr_hex": ns.address, "length": length}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.read_memory_bytes(ctx, ns.address, length)
    _emit(result, ns)
    return 0


def cmd_get_data_at_address(ns: argparse.Namespace) -> int:
    srv = _try_server("get_data_at_address", {
        "addr_hex": ns.address,
        "value_offset": ns.value_offset,
        "value_limit": ns.value_limit,
    }, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_data_at_address(
            ctx, ns.address, ns.value_offset, ns.value_limit)
    _emit(result, ns)
    return 0


def cmd_get_function_stack_frame(ns: argparse.Namespace) -> int:
    srv = _try_server("get_function_stack_frame", {"addr_hex": ns.address}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_function_stack_frame(ctx, ns.address)
    _emit(result, ns)
    return 0


def cmd_list_enums(ns: argparse.Namespace) -> int:
    srv = _try_server("list_enums", {}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.list_enums(ctx)
    _emit(result, ns)
    return 0


def cmd_get_enum(ns: argparse.Namespace) -> int:
    srv = _try_server("get_enum", {"name": ns.name}, ns)
    if srv is not None:
        _emit_server_result(srv, ns)
        return 0
    bridge, _ = _open_bridge(ns)
    with bridge.open_program(ns.binary) as ctx:
        result = queries.get_enum(ctx, ns.name)
    _emit(result, ns)
    return 0


# -------------------------------------------------------------------
# serve / shutdown handlers
# -------------------------------------------------------------------

def cmd_serve(ns: argparse.Namespace) -> int:
    """Start the GhidraMSC query server."""
    cfg = load_config(getattr(ns, "config", None))
    port = ns.port if ns.port else cfg.server_port
    from .server import run_server
    run_server(cfg, ns.binary, port=port, owner=ns.owner)
    return 0


def cmd_shutdown(ns: argparse.Namespace) -> int:
    """Ask a running server to shut down."""
    from . import client
    port = ns.port if ns.port else None
    if client.shutdown_server(port):
        print("Server shutdown requested.")
        return 0
    print("No server found.", file=sys.stderr)
    return 1


def cmd_mcp(ns: argparse.Namespace) -> int:
    """Start the MCP (Model Context Protocol) stdio server."""
    mode = getattr(ns, "mode", "headless")
    config_path = getattr(ns, "config", None)
    plugin_host = getattr(ns, "plugin_host", None)
    plugin_port = getattr(ns, "plugin_port", None)
    max_clients = getattr(ns, "max_clients", None)
    toolset = getattr(ns, "toolset", "all")
    owner = getattr(ns, "owner", None)
    if mode == "gui":
        if config_path is not None:
            raise ValueError("--config requires --mode headless")
        if owner is not None:
            raise ValueError("--owner requires --mode headless")
        from .bridge_plugin import DEFAULT_PLUGIN_HOST, DEFAULT_PLUGIN_PORT
        from .mcp_transport import run_mcp
        host = plugin_host or DEFAULT_PLUGIN_HOST
        port = plugin_port or DEFAULT_PLUGIN_PORT
        run_mcp(
            config=None,
            binary=ns.binary,
            plugin=True,
            plugin_host=host,
            plugin_port=port,
            max_clients=max_clients,
            toolset=toolset,
        )
    else:
        for option, value in (
            ("--plugin-host", plugin_host),
            ("--plugin-port", plugin_port),
            ("--max-clients", max_clients),
        ):
            if value is not None:
                raise ValueError("{} requires --mode gui".format(option))
        cfg = load_config(config_path)
        from .mcp_transport import run_mcp
        run_mcp(
            config=cfg,
            binary=ns.binary,
            owner=owner,
            toolset=toolset,
        )
    return 0


__all__ = [name for name in globals() if name.startswith("cmd_")]
