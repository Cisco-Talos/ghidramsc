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

"""Private variables implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .bridge import ProgramContext

from ._query_composites import (
    _find_structure,
)

from ._query_core import (
    _MISSING,
    _addr_int,
    _end_mutation_transaction,
    _get_decompiler,
    _get_monitor,
    _mutation_contract_result,
    _mutation_no_change,
    _mutation_validation_failure,
    _resolve_type,
    _run_mutation_transaction,
    _start_mutation_transaction,
)

from ._query_inspection import (
    _stack_frame_state,
    _stack_variable_state,
    get_function_info,
)


def _stack_mutation_result(operation: str, status: str,
                           requested: Dict[str, Any],
                           old: Optional[Dict[str, Any]] = None,
                           stored: Optional[Dict[str, Any]] = None,
                           conflicts: Optional[List[Dict[str, Any]]] = None,
                           error: str = "") -> Dict[str, Any]:
    result = {
        "operation": operation,
        "status": status,
        "requested": requested,
        "conflicting_variables": conflicts or [],
        "transaction": {
            "started": status in ("success", "rolled_back"),
            "committed": status == "success",
        },
    }
    if old is not None:
        result["old"] = old
    if stored is not None:
        result["stored"] = stored
    if error:
        result["error"] = error
    return result


def _stack_storage_conflicts(frame, start: int,
                             end: int) -> List[Dict[str, Any]]:
    conflicts = []
    for variable in frame.getStackVariables():
        existing_start = variable.getStackOffset()
        existing_end = existing_start + variable.getLength() - 1
        if start <= existing_end and existing_start <= end:
            conflicts.append(_stack_variable_state(frame, variable))
    return conflicts


def _create_stack_variable(ctx: ProgramContext, operation: str,
                           addr_hex: str, stack_offset: int, name: str,
                           data_type, size: int,
                           requested: Dict[str, Any], source) -> Dict[str, Any]:
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _stack_mutation_result(
            operation, "validation_failed", requested,
            error="No function at or containing " + addr_hex)
    frame = func.getStackFrame()
    old = _stack_frame_state(func)
    type_length = data_type.getLength()
    if type_length <= 0:
        return _stack_mutation_result(
            operation, "validation_failed", requested, old,
            error="Stack variable type must have a positive fixed length")
    if size < 0 or (size != 0 and size != type_length):
        error = ("size must be zero or positive" if size < 0 else
                 "Requested size {} does not match type length {}".format(
                     size, type_length))
        return _stack_mutation_result(
            operation, "validation_failed", requested, old, error=error)
    end_offset = stack_offset + type_length - 1
    if end_offset > 0x7fffffff:
        return _stack_mutation_result(
            operation, "validation_failed", requested, old,
            error="Stack variable range exceeds the supported offset range")
    if (frame.isParameterOffset(stack_offset)
            or frame.isParameterOffset(end_offset)):
        return _stack_mutation_result(
            operation, "validation_failed", requested, old,
            error="Parameter stack offsets are not supported; use function "
                  "prototype tools")
    if name:
        for variable in func.getAllVariables():
            if variable.getName() == name:
                return _stack_mutation_result(
                    operation, "validation_failed", requested, old,
                    error="Variable name '{}' already exists in the function".format(
                        name))
    conflicts = _stack_storage_conflicts(frame, stack_offset, end_offset)
    if conflicts:
        return _stack_mutation_result(
            operation, "validation_failed", requested, old,
            conflicts=conflicts,
            error="Requested stack storage overlaps existing variables")
    requested.update({
        "resolved_type": str(data_type.getName()),
        "resolved_type_path": str(data_type.getPathName()),
        "resolved_size": type_length,
    })

    tx_id = _start_mutation_transaction(
        ctx,
        "Apply stack structure" if operation == "create_stack_variable_from_structure"
        else "Create stack variable")
    commit = False
    try:
        created = frame.createVariable(
            name or None, stack_offset, data_type, source)
        stored_variable = frame.getVariableContaining(stack_offset)
        if (created is None or stored_variable is None
                or stored_variable.getStackOffset() != stack_offset
                or stored_variable.getLength() != type_length
                or not stored_variable.getDataType().isEquivalent(data_type)
                or (name and stored_variable.getName() != name)):
            raise ValueError(
                "Stack variable read-back did not match the request")
        stored = _stack_frame_state(func)
        commit = True
        return _stack_mutation_result(
            operation, "success", requested, old, stored, conflicts)
    except Exception as exc:
        return _stack_mutation_result(
            operation, "rolled_back", requested, old,
            conflicts=conflicts, error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def create_stack_variable(ctx: ProgramContext, addr_hex: str, stack_offset: int,
                     name: str, type_name: str,
                     size: int = 0) -> Dict[str, Any]:
    """Create one exact local stack variable without replacing conflicts."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {
        "address": addr_hex,
        "stack_offset": stack_offset,
        "name": name,
        "type_name": type_name,
        "size": size,
    }
    if not name.strip():
        return _stack_mutation_result(
            "create_stack_variable", "validation_failed", requested,
            error="Stack variable name must not be blank")
    data_type = _resolve_type(ctx.program, type_name)
    if data_type is None:
        return _stack_mutation_result(
            "create_stack_variable", "validation_failed", requested,
            error="Unknown type '{}'".format(type_name))
    return _create_stack_variable(
        ctx, "create_stack_variable", addr_hex, stack_offset, name,
        data_type, size, requested, SourceType.USER_DEFINED)


def delete_stack_variable(ctx: ProgramContext, addr_hex: str,
                     stack_offset: int) -> Dict[str, Any]:
    """Delete the local stack variable starting at an exact offset."""
    requested = {"address": addr_hex, "stack_offset": stack_offset}
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _stack_mutation_result(
            "delete_stack_variable", "validation_failed", requested,
            error="No function at or containing " + addr_hex)
    frame = func.getStackFrame()
    old = _stack_frame_state(func)
    target = frame.getVariableContaining(stack_offset)
    if target is None:
        return _stack_mutation_result(
            "delete_stack_variable", "validation_failed", requested, old,
            error="No stack variable starts at offset {}".format(stack_offset))
    conflicts = [_stack_variable_state(frame, target)]
    if target.getStackOffset() != stack_offset:
        return _stack_mutation_result(
            "delete_stack_variable", "validation_failed", requested, old,
            conflicts=conflicts,
            error=("Offset {} is inside stack variable '{}'; specify its "
                   "exact start offset {}").format(
                       stack_offset, target.getName(),
                       target.getStackOffset()))
    if frame.isParameterOffset(stack_offset):
        return _stack_mutation_result(
            "delete_stack_variable", "validation_failed", requested, old,
            conflicts=conflicts,
            error="Parameter stack variables are not supported; use function "
                  "prototype tools")
    requested["target"] = _stack_variable_state(frame, target)

    tx_id = _start_mutation_transaction(ctx, "Delete stack variable")
    commit = False
    try:
        func.removeVariable(target)
        if frame.getVariableContaining(stack_offset) is not None:
            raise ValueError(
                "Stack variable still exists at offset {}".format(
                    stack_offset))
        stored = _stack_frame_state(func)
        commit = True
        return _stack_mutation_result(
            "delete_stack_variable", "success", requested, old, stored)
    except Exception as exc:
        return _stack_mutation_result(
            "delete_stack_variable", "rolled_back", requested, old,
            conflicts=conflicts, error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def create_stack_variable_from_structure(ctx: ProgramContext, addr_hex: str,
                          stack_offset: int, structure_name: str,
                          category_path: str = "",
                          name: str = "") -> Dict[str, Any]:
    """Create one local stack variable using an exact structure type."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {
        "address": addr_hex,
        "stack_offset": stack_offset,
        "structure_name": structure_name,
        "category_path": category_path,
        "name": name,
    }
    if name and not name.strip():
        return _stack_mutation_result(
            "create_stack_variable_from_structure", "validation_failed", requested,
            error="Stack variable name must not be blank")
    try:
        structure = _find_structure(ctx, structure_name, category_path)
    except ValueError as exc:
        return _stack_mutation_result(
            "create_stack_variable_from_structure", "validation_failed", requested,
            error=str(exc))
    if structure is None:
        where = " in {}".format(category_path) if category_path else ""
        return _stack_mutation_result(
            "create_stack_variable_from_structure", "validation_failed", requested,
            error="Structure '{}' not found{}".format(
                structure_name, where))
    if structure.getLength() <= 0:
        return _stack_mutation_result(
            "create_stack_variable_from_structure", "validation_failed", requested,
            error="Structure must have a positive stored length")
    resolved_path = str(structure.getCategoryPath())
    requested.update({
        "resolved_category_path": resolved_path,
        "size": structure.getLength(),
    })
    return _create_stack_variable(
        ctx, "create_stack_variable_from_structure", addr_hex, stack_offset, name,
        structure, structure.getLength(), requested,
        SourceType.USER_DEFINED if name else SourceType.DEFAULT)


def _func_var_state(symbol) -> Dict[str, Any]:
    state = {
        "name": symbol.getName(),
        "type": str(symbol.getDataType()),
        "size": symbol.getSize(),
        "storage": str(symbol.getStorage()),
        "is_param": symbol.isParameter(),
    }
    pc_address = symbol.getPCAddress()
    if pc_address is not None:
        state["pc_addr"] = str(pc_address)
    return state


def list_function_variables(ctx: ProgramContext, addr_hex: str) -> Dict[str, Any]:
    """List all variables (params + locals) in a function."""
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return {"error": "No function at or containing " + addr_hex}

    decomp = _get_decompiler(ctx.program)
    try:
        result = decomp.decompileFunction(func, 120, _get_monitor())
        if result is None or not result.decompileCompleted():
            return {"error": "Decompile failed for " + func.getName()}

        hfunc = result.getHighFunction()
        lsm = hfunc.getLocalSymbolMap()

        params = []
        locals_list = []

        for sym in list(lsm.getSymbols()):
            entry = _func_var_state(sym)
            if sym.isParameter():
                params.append(entry)
            else:
                locals_list.append(entry)

        params.sort(key=lambda e: e["storage"])

        return {
            "func": func.getName(),
            "entry": str(func.getEntryPoint()),
            "return_type": str(func.getReturnType()),
            "signature": str(func.getSignature()),
            "params": params,
            "locals": locals_list,
        }
    finally:
        decomp.dispose()


def _high_var_id(symbol) -> str:
    return "high:{:x}".format(int(symbol.getId()) & ((1 << 64) - 1))


def _merge_group_id(varnode) -> str:
    return "merge:{:x}".format(int(varnode.getMergeGroup()) & 0xffff)


def _high_var_capability_reason(
    symbol, database_backed: bool = False
) -> Optional[str]:
    if symbol.isGlobal():
        return "Global high symbols are outside function-variable editing"
    high_variable = symbol.getHighVariable()
    if high_variable is None:
        return (
            "Decompiler symbol has no associated high variable and cannot be "
            "persisted"
        )
    if database_backed:
        return None
    if str(symbol.getStorage()).startswith("unique:"):
        return (
            "Decompiler unique-space storage cannot be materialized as a "
            "database function variable"
        )
    representative = high_variable.getRepresentative()
    if representative is not None and representative.isConstant():
        return (
            "Decompiler high variable is constant-backed and cannot be "
            "persisted as a function variable"
        )
    high_function = symbol.getHighFunction()
    if high_function is None:
        return "Decompiler high variable has no function identity"
    locator = _high_var_locator(symbol)
    symbols = list(high_function.getLocalSymbolMap().getSymbols())
    if sum(_high_var_id(candidate) == locator["var_id"] for candidate in symbols) != 1:
        return "Decompiler high-symbol ID is not unique in this function"
    if sum(_high_var_matches_locator(candidate, locator) for candidate in symbols) != 1:
        return "Decompiler high-variable locator is ambiguous in this function"
    return None


def _high_var_state(symbol) -> Dict[str, Any]:
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore

    storage = symbol.getStorage()
    database_symbol = symbol.getSymbol()
    database_variable = HighFunctionDBUtil.getFunctionVariable(symbol)
    if storage.isStackStorage():
        storage_kind = "stack"
    elif storage.isRegisterStorage():
        storage_kind = "register"
    elif storage.isHashStorage():
        storage_kind = "hash"
    elif storage.isMemoryStorage():
        storage_kind = "memory"
    else:
        storage_kind = "other"
    database_backed = database_symbol is not None or database_variable is not None
    capability_reason = _high_var_capability_reason(symbol, database_backed)
    state = {
        "var_id": _high_var_id(symbol),
        "high_symbol_id": "{:x}".format(
            int(symbol.getId()) & ((1 << 64) - 1)
        ),
        "name": symbol.getName(),
        "type": str(symbol.getDataType()),
        "size": symbol.getSize(),
        "storage": str(storage),
        "storage_kind": storage_kind,
        "is_param": bool(symbol.isParameter()),
        "category_index": symbol.getCategoryIndex(),
        "name_locked": bool(symbol.isNameLocked()),
        "type_locked": bool(symbol.isTypeLocked()),
        "database_backed": database_backed,
        "identity_stability": (
            "database_symbol" if database_backed else "decompile_snapshot"
        ),
        "refresh_required_after_mutation": not database_backed,
        "backing": (
            "parameter" if symbol.isParameter()
            else "database_local" if database_backed
            else "decompiler_high"
        ),
        "selection_scope": "high_symbol",
        "persistable": capability_reason is None,
    }
    groups: Dict[int, Dict[str, Any]] = {}
    high_variable = symbol.getHighVariable()
    if high_variable is not None:
        for instance in list(high_variable.getInstances()):
            group_number = int(instance.getMergeGroup()) & 0xffff
            group = groups.get(group_number)
            if group is None:
                group = {
                    "merge_group_id": _merge_group_id(instance),
                    "merge_group": group_number,
                    "instance_count": 0,
                    "representative_storage": str(instance.getAddress()),
                    "representative_size": instance.getSize(),
                }
                if instance.getPCAddress() is not None:
                    group["representative_pc_addr"] = str(
                        instance.getPCAddress()
                    )
                groups[group_number] = group
            group["instance_count"] += 1
    state["merge_group_count"] = len(groups)
    state["merged"] = len(groups) > 1
    state["merge_group_split_supported"] = (
        len(groups) > 1 and not symbol.isNameLocked()
    )
    state["merge_groups"] = [groups[key] for key in sorted(groups)]
    if symbol.getPCAddress() is not None:
        state["pc_addr"] = str(symbol.getPCAddress())
    if database_symbol is not None:
        state["database_symbol_id"] = str(database_symbol.getID())
    if capability_reason is not None:
        state["capability_reason"] = capability_reason
    return state


_FUNC_VAR_IDENTITY_DEFAULT_LIMIT = 100


_FUNC_VAR_IDENTITY_MAX_LIMIT = 500


_FUNC_VAR_IDENTITY_FILTER_FIELDS = (
    "name", "var_id", "type", "storage", "storage_kind", "backing",
    "capability_reason", "pc_addr", "database_symbol_id",
)


def _page_func_var_identities(
    params: List[Dict[str, Any]],
    locals_list: List[Dict[str, Any]],
    offset: int = 0,
    limit: int = _FUNC_VAR_IDENTITY_DEFAULT_LIMIT,
    filter_str: str = "",
) -> Dict[str, Any]:
    """Annotate, filter, and page a complete HighSymbol identity set."""
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    if (isinstance(limit, bool) or not isinstance(limit, int)
            or limit < 1 or limit > _FUNC_VAR_IDENTITY_MAX_LIMIT):
        raise ValueError(
            "limit must be an integer between 1 and {}".format(
                _FUNC_VAR_IDENTITY_MAX_LIMIT))
    if not isinstance(filter_str, str):
        raise ValueError("filter_str must be a string")

    all_entries = params + locals_list
    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for entry in all_entries:
        by_name.setdefault(entry["name"], []).append(entry)

    ambiguity_by_name: Dict[str, Dict[str, Any]] = {}
    for name in sorted(by_name):
        matches = by_name[name]
        candidate_ids = [match["var_id"] for match in matches]
        ambiguous = len(matches) > 1
        for match in matches:
            match["display_name_ambiguous"] = ambiguous
            match["same_name_var_ids"] = list(candidate_ids)
        if ambiguous:
            ambiguity_by_name[name] = {
                "name": name,
                "candidate_var_ids": candidate_ids,
            }

    normalized_filter = filter_str.strip()
    needle = normalized_filter.lower()
    if needle:
        filtered = [
            entry for entry in all_entries
            if any(
                needle in str(entry.get(field, "")).lower()
                for field in _FUNC_VAR_IDENTITY_FILTER_FIELDS
            )
        ]
    else:
        filtered = all_entries

    page = filtered[offset:offset + limit]
    page_ids = {id(entry) for entry in page}
    page_names = {entry["name"] for entry in page}
    returned = len(page)
    total = len(filtered)
    has_more = offset + returned < total
    return {
        "filter": normalized_filter,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "returned": returned,
            "total": total,
            "total_unfiltered": len(all_entries),
            "has_more": has_more,
            "next_offset": offset + returned if has_more else None,
        },
        "ambiguous_names": [
            ambiguity_by_name[name]
            for name in sorted(page_names)
            if name in ambiguity_by_name
        ],
        "params": [entry for entry in params if id(entry) in page_ids],
        "locals": [entry for entry in locals_list if id(entry) in page_ids],
    }


def list_function_variable_identities(
    ctx: ProgramContext,
    addr_hex: str,
    offset: int = 0,
    limit: int = _FUNC_VAR_IDENTITY_DEFAULT_LIMIT,
    filter_str: str = "",
) -> Dict[str, Any]:
    """Return explicit HighSymbol identities and their stability scope."""
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return {"error": "No function at or containing " + addr_hex}
    decomp = _get_decompiler(ctx.program)
    try:
        result = decomp.decompileFunction(func, 120, _get_monitor())
        if result is None or not result.decompileCompleted():
            return {"error": "Decompile failed for " + func.getName()}
        params = []
        locals_list = []
        for symbol in list(result.getHighFunction().getLocalSymbolMap().getSymbols()):
            entry = _high_var_state(symbol)
            (params if symbol.isParameter() else locals_list).append(entry)
        page = _page_func_var_identities(
            params, locals_list, offset, limit, filter_str)
        response = {
            "func": func.getName(),
            "entry": str(func.getEntryPoint()),
            "identity_model": "decompiler_high_symbol_v2",
            "selection_scope": "complete_high_symbol",
            "merge_group_split_supported": True,
        }
        response.update(page)
        return response
    finally:
        decomp.dispose()


_RETURN_TYPE_INFERRED_PARAMETER_ERROR = (
    "Return-type-only mutation cannot safely preserve inferred, "
    "non-database parameters; use set_function_prototype with the complete "
    "signature."
)


def _effective_parameter_contract(
    ctx: ProgramContext, addr_hex: str
) -> List[Dict[str, Any]]:
    """Return stable semantics for the complete decompiler parameter list."""
    identities = list_function_variable_identities(
        ctx, addr_hex, offset=0, limit=_FUNC_VAR_IDENTITY_MAX_LIMIT
    )
    if "error" in identities:
        raise ValueError(
            "Cannot verify effective parameters: " + str(identities["error"])
        )
    pagination = identities.get("pagination", {})
    if pagination.get("has_more"):
        raise ValueError(
            "Cannot verify more than {} effective variables; use "
            "set_function_prototype with the complete signature.".format(
                _FUNC_VAR_IDENTITY_MAX_LIMIT
            )
        )
    fields = (
        "name", "type", "size", "storage", "is_param", "category_index",
        "database_backed", "backing", "database_symbol_id",
    )
    return [
        {key: parameter.get(key) for key in fields if key in parameter}
        for parameter in identities.get("params", [])
    ]


def _return_type_parameter_preflight(
    ctx: ProgramContext, addr_hex: str
) -> tuple[List[Dict[str, Any]], str]:
    try:
        parameters = _effective_parameter_contract(ctx, addr_hex)
    except Exception as exc:
        return [], str(exc) or type(exc).__name__
    if any(
        not parameter.get("database_backed", False)
        for parameter in parameters
    ):
        return parameters, _RETURN_TYPE_INFERRED_PARAMETER_ERROR
    return parameters, ""


def _function_contract_state(
    ctx: ProgramContext, addr_hex: str
) -> Dict[str, Any]:
    info = _func_info_contract_state(ctx, addr_hex)
    variables = list_function_variables(ctx, addr_hex)
    if "error" in variables:
        raise ValueError("list_function_variables read-back failed: " + str(variables["error"]))
    return {"info": info, "variables": variables}


def _func_info_contract_state(
    ctx: ProgramContext, addr_hex: str
) -> Dict[str, Any]:
    info = get_function_info(ctx, addr_hex)
    if "error" in info:
        raise ValueError("get_function_info read-back failed: " + str(info["error"]))
    return info


def _resolve_unique_variable(func, name: str):
    matches = []
    for variable in func.getParameters():
        if str(variable.getName()) == name:
            matches.append((variable, True))
    for variable in func.getLocalVariables():
        if str(variable.getName()) == name:
            matches.append((variable, False))
    if len(matches) > 1:
        raise ValueError(
            "Variable '{}' is ambiguous in {}".format(name, func.getName())
        )
    return matches[0] if matches else (None, False)


def _find_variable_by_storage(func, storage: str, parameter: bool):
    variables = (
        func.getParameters() if parameter else func.getLocalVariables()
    )
    for variable in variables:
        if str(variable.getVariableStorage()) == storage:
            return variable
    return None


def set_variable_name(ctx: ProgramContext, addr_hex: str, old_name: str,
               new_name: str) -> Dict[str, Any]:
    """Rename one uniquely selected database variable and verify storage."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {"old_name": old_name, "new_name": new_name}
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _mutation_validation_failure(
            "set_variable_name", requested, "No function at " + addr_hex
        )
    try:
        variable, parameter = _resolve_unique_variable(func, old_name)
        if variable is None:
            raise ValueError(
                "Variable '{}' not found in {}".format(
                    old_name, func.getName()
                )
            )
        conflict, _ = _resolve_unique_variable(func, new_name)
        if (
            conflict is not None
            and str(conflict.getVariableStorage())
            != str(variable.getVariableStorage())
        ):
            raise ValueError(
                "Requested name '{}' conflicts with an existing variable at {}"
                .format(new_name, conflict.getVariableStorage())
            )
    except Exception as exc:
        return _mutation_validation_failure(
            "set_variable_name", requested, str(exc) or type(exc).__name__
        )

    old = _function_contract_state(ctx, addr_hex)
    if old_name == new_name:
        return _mutation_no_change("set_variable_name", requested, old)
    storage = str(variable.getVariableStorage())

    def validate(stored: Any) -> Optional[str]:
        stored_variable = _find_variable_by_storage(func, storage, parameter)
        if stored_variable is None or str(stored_variable.getName()) != new_name:
            return "Variable name read-back mismatch at " + storage
        return None

    return _run_mutation_transaction(
        ctx,
        "set_variable_name",
        "Rename variable",
        requested,
        old,
        lambda: variable.setName(new_name, SourceType.USER_DEFINED),
        lambda: _function_contract_state(ctx, addr_hex),
        validate,
    )


def set_variable_type(ctx: ProgramContext, addr_hex: str, var_name: str,
               type_name: str) -> Dict[str, Any]:
    """Retype one uniquely selected database variable and verify storage."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {"name": var_name, "type": type_name}
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _mutation_validation_failure(
            "set_variable_type", requested, "No function at " + addr_hex
        )
    dt = _resolve_type(ctx.program, type_name)
    if dt is None:
        return _mutation_validation_failure(
            "set_variable_type", requested, "Unknown data type: " + type_name
        )
    requested["type"] = str(dt)
    try:
        variable, parameter = _resolve_unique_variable(func, var_name)
        if variable is None:
            raise ValueError(
                "Variable '{}' not found in {}".format(
                    var_name, func.getName()
                )
            )
    except Exception as exc:
        return _mutation_validation_failure(
            "set_variable_type", requested, str(exc) or type(exc).__name__
        )

    old = _function_contract_state(ctx, addr_hex)
    if variable.getDataType().isEquivalent(dt):
        return _mutation_no_change("set_variable_type", requested, old)
    storage = str(variable.getVariableStorage())

    def validate(stored: Any) -> Optional[str]:
        stored_variable = _find_variable_by_storage(func, storage, parameter)
        if (
            stored_variable is None
            or not stored_variable.getDataType().isEquivalent(dt)
        ):
            return "Variable type read-back mismatch at " + storage
        return None

    return _run_mutation_transaction(
        ctx,
        "set_variable_type",
        "Retype variable",
        requested,
        old,
        lambda: variable.setDataType(dt, SourceType.USER_DEFINED),
        lambda: _function_contract_state(ctx, addr_hex),
        validate,
    )


def _select_high_var(ctx: ProgramContext, addr_hex: str, var_id: str):
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        raise ValueError("No function at or containing " + addr_hex)
    decomp = _get_decompiler(ctx.program)
    try:
        result = decomp.decompileFunction(func, 120, _get_monitor())
        if result is None or not result.decompileCompleted():
            raise ValueError("Decompile failed for " + func.getName())
        high_function = result.getHighFunction()
        for symbol in list(high_function.getLocalSymbolMap().getSymbols()):
            if _high_var_id(symbol) == var_id:
                return decomp, high_function, symbol
        raise ValueError(
            "Variable identity '{}' was not found; refresh "
            "list_function_variable_identities".format(var_id)
        )
    except Exception:
        decomp.dispose()
        raise


def _high_var_locator(symbol) -> Dict[str, Any]:
    return {
        "var_id": _high_var_id(symbol),
        "name": symbol.getName(),
        "storage": str(symbol.getStorage()),
        "pc_addr": (
            str(symbol.getPCAddress())
            if symbol.getPCAddress() is not None else None
        ),
        "is_param": bool(symbol.isParameter()),
        "category_index": symbol.getCategoryIndex(),
    }


def _high_var_matches_locator(symbol, locator: Dict[str, Any]) -> bool:
    if bool(symbol.isParameter()) != locator["is_param"]:
        return False
    if locator["is_param"]:
        return symbol.getCategoryIndex() == locator["category_index"]
    pc_addr = (
        str(symbol.getPCAddress())
        if symbol.getPCAddress() is not None else None
    )
    if pc_addr != locator["pc_addr"]:
        return False
    return (
        str(symbol.getStorage()) == locator["storage"]
        or symbol.getName() == locator["name"]
    )


def _find_high_var_after(ctx: ProgramContext, addr_hex: str,
                         locator: Dict[str, Any]):
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        raise ValueError("No function at or containing " + addr_hex)
    decomp = _get_decompiler(ctx.program)
    try:
        result = decomp.decompileFunction(func, 120, _get_monitor())
        if result is None or not result.decompileCompleted():
            raise ValueError("Decompile failed for " + func.getName())
        symbols = list(result.getHighFunction().getLocalSymbolMap().getSymbols())
        expected_name = locator.get("expected_name")
        if expected_name is not None:
            named = [symbol for symbol in symbols
                     if symbol.getName() == expected_name
                     and bool(symbol.isParameter()) == locator["is_param"]]
            if len(named) == 1:
                return decomp, named[0]
            if len(named) > 1:
                raise ValueError("Variable name became ambiguous after mutation")
        exact = [symbol for symbol in symbols
                 if _high_var_id(symbol) == locator["var_id"]
                 and _high_var_matches_locator(symbol, locator)]
        if len(exact) == 1:
            return decomp, exact[0]
        if len(exact) > 1:
            raise ValueError("Variable high-symbol ID became ambiguous after mutation")
        fallback = [symbol for symbol in symbols
                    if _high_var_matches_locator(symbol, locator)]
        if len(fallback) == 1:
            return decomp, fallback[0]
        if len(fallback) > 1:
            raise ValueError(
                "Variable identity became ambiguous after mutation; refresh "
                "list_function_variable_identities"
            )
        raise ValueError("Variable disappeared after mutation")
    except Exception:
        decomp.dispose()
        raise


def _unsupported_high_var_result(operation: str, requested: Dict[str, Any],
                                 message: str) -> Dict[str, Any]:
    return {
        "operation": operation,
        "status": "unsupported",
        "requested": requested,
        "error": message,
        "transaction": {"started": False, "committed": False},
    }


def _high_var_validation_result(operation: str, requested: Dict[str, Any],
                                message: str) -> Dict[str, Any]:
    return {
        "operation": operation,
        "status": "validation_failed",
        "requested": requested,
        "error": message,
        "transaction": {"started": False, "committed": False},
    }


def _validate_merge_group_selection(symbol, split_use: bool,
                                    merge_group_id: str) -> str:
    if not split_use:
        return "" if not merge_group_id else (
            "merge_group_id requires split_use=true"
        )
    if not merge_group_id:
        return (
            "split_use=true requires a merge_group_id returned by "
            "list_function_variable_identities"
        )
    high_variable = symbol.getHighVariable()
    if high_variable is None:
        return "Decompiler symbol has no high variable to split"
    group_ids = {
        _merge_group_id(instance)
        for instance in list(high_variable.getInstances())
    }
    if merge_group_id not in group_ids:
        return (
            "Merge-group identity '{}' was not found for {}; refresh "
            "list_function_variable_identities".format(merge_group_id, _high_var_id(symbol))
        )
    if len(group_ids) < 2:
        return "Selected variable has only one merge group and cannot be split"
    if symbol.isNameLocked():
        return (
            "Selected variable has a locked name and its merge group cannot "
            "be split by this operation"
        )
    return ""


def _split_high_variable(high_function, symbol, merge_group_id: str):
    high_variable = symbol.getHighVariable()
    selected = next((
        instance for instance in list(high_variable.getInstances())
        if _merge_group_id(instance) == merge_group_id
    ), None)
    if selected is None:
        raise ValueError(
            "Merge-group identity disappeared; refresh list_function_variable_identities"
        )
    split = high_function.splitOutMergeGroup(high_variable, selected)
    if split is None or split.getSymbol() is None:
        raise ValueError(
            "Decompiler did not produce a symbol for the split group"
        )
    return split.getSymbol()


def _use_anchor(instance) -> Tuple[str, str, int]:
    """Identify one decompiler use across fresh decompositions."""
    pc = instance.getPCAddress()
    return (str(pc) if pc is not None else "",
            str(instance.getAddress()), int(instance.getSize()))


def _split_use_anchors(symbol, merge_group_id: str):
    selected: Set[Tuple[str, str, int]] = set()
    remaining: Set[Tuple[str, str, int]] = set()
    instances = list(symbol.getHighVariable().getInstances())
    for instance in instances:
        anchor = _use_anchor(instance)
        (selected if _merge_group_id(instance) == merge_group_id
         else remaining).add(anchor)
    if (not selected or not remaining
            or len(selected | remaining) != len(instances)):
        raise ValueError("Merge-group uses cannot be identified uniquely")
    return selected, remaining


def _verify_split_use_isolation(
    ctx: ProgramContext, addr_hex: str, selected: Set[Tuple[str, str, int]],
    remaining: Set[Tuple[str, str, int]], name: str,
) -> None:
    """Require every original use to have one truthful fresh symbol owner."""
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        raise ValueError("Split verification function disappeared")
    decomp = _get_decompiler(ctx.program)
    try:
        result = decomp.decompileFunction(func, 120, _get_monitor())
        if result is None or not result.decompileCompleted():
            raise ValueError("Fresh decompilation failed during split verification")
        owners = {}
        owner_uses = {}
        for symbol in list(result.getHighFunction().getLocalSymbolMap().getSymbols()):
            variable = symbol.getHighVariable()
            if variable is None:
                continue
            uses = {_use_anchor(instance) for instance in
                    list(variable.getInstances())}
            owner_uses[id(symbol)] = uses
            for anchor in uses & (selected | remaining):
                if anchor in owners:
                    raise ValueError("Split use has ambiguous fresh ownership")
                owners[anchor] = symbol
        if set(owners) != selected | remaining:
            raise ValueError("Split uses changed or disappeared after decompilation")
        selected_owners = {id(owners[anchor]) for anchor in selected}
        if len(selected_owners) != 1:
            raise ValueError("Selected merge-group uses did not stay together")
        owner = owners[next(iter(selected))]
        if owner.getName() != name or owner_uses[id(owner)] != selected:
            raise ValueError("Selected merge group was not isolated under its name")
        if any(owners[anchor] is owner or owners[anchor].getName() == name
               for anchor in remaining):
            raise ValueError("Remaining merge-group uses received the selected name")
    finally:
        decomp.dispose()


def _stable_identity_function_state(
    ctx: ProgramContext, addr_hex: str
) -> Dict[str, Any]:
    """Return database state that stable-identity edits must restore exactly."""
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        raise ValueError("No function at or containing " + addr_hex)

    def variable_state(variable, parameter: bool) -> Dict[str, Any]:
        symbol = variable.getSymbol()
        state = {
            "name": str(variable.getName()),
            "type": str(variable.getDataType()),
            "storage": str(variable.getVariableStorage()),
            "source": str(variable.getSource()),
            "symbol_id": (
                str(symbol.getID()) if symbol is not None else None
            ),
        }
        if parameter:
            state.update({
                "ordinal": variable.getOrdinal(),
                "auto": bool(variable.isAutoParameter()),
            })
        else:
            state["first_use_offset"] = variable.getFirstUseOffset()
        return state

    parameters = [
        variable_state(variable, True)
        for variable in list(func.getParameters())
    ]
    parameters.sort(key=lambda state: state["ordinal"])
    locals_list = [
        variable_state(variable, False)
        for variable in list(func.getLocalVariables())
    ]
    locals_list.sort(key=lambda state: (
        state["first_use_offset"], state["storage"], state["name"]
    ))
    frame = func.getStackFrame()
    return {
        "signature": str(func.getSignature()),
        "signature_source": str(func.getSignatureSource()),
        "calling_convention": str(func.getCallingConventionName()),
        "return_type": str(func.getReturnType()),
        "custom_variable_storage": bool(func.hasCustomVariableStorage()),
        "var_args": bool(func.hasVarArgs()),
        "stack_local_size": frame.getLocalSize() if frame else 0,
        "stack_param_size": frame.getParameterSize() if frame else 0,
        "parameters": parameters,
        "locals": locals_list,
    }


def _high_var_restoration_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Select stable semantic fields from a decompiler-variable snapshot."""
    keys = (
        "name",
        "type",
        "size",
        "storage",
        "storage_kind",
        "is_param",
        "category_index",
        "name_locked",
        "type_locked",
        "database_backed",
        "backing",
    )
    return {key: state.get(key) for key in keys}


def _read_high_var_after(
    ctx: ProgramContext, addr_hex: str, locator: Dict[str, Any]
) -> Dict[str, Any]:
    decomp, symbol = _find_high_var_after(ctx, addr_hex, locator)
    try:
        return _high_var_state(symbol)
    finally:
        decomp.dispose()


def _find_database_variable_by_symbol_id(function, symbol_id: int):
    for variable in list(function.getAllVariables()):
        symbol = variable.getSymbol()
        if symbol is not None and int(symbol.getID()) == symbol_id:
            return variable
    return None


def _run_stable_identity_transaction(
    ctx: ProgramContext,
    operation: str,
    description: str,
    requested: Dict[str, Any],
    old: Dict[str, Any],
    apply_and_validate: Callable[[], None],
    success_read_back: Callable[[], Any],
    validate_success: Callable[[Any], Optional[str]],
    rollback_read_back: Callable[[], Any],
    validate_rollback: Callable[[Any], Optional[str]],
) -> Dict[str, Any]:
    """Close the transaction before classifying a stable-identity result."""
    tx_id = _start_mutation_transaction(ctx, description)
    commit = False
    error = ""
    try:
        apply_and_validate()
        commit = True
    except Exception as exc:
        error = str(exc) or type(exc).__name__

    try:
        _end_mutation_transaction(ctx, tx_id, commit)
    except Exception as exc:
        close_error = str(exc) or type(exc).__name__
        try:
            stored = rollback_read_back()
            read_back_error = ""
        except Exception as read_exc:
            stored = _MISSING
            read_back_error = str(read_exc) or type(read_exc).__name__
        return _mutation_contract_result(
            operation,
            "failed",
            requested,
            old=old,
            stored=stored,
            error="Transaction close outcome is ambiguous: " + close_error,
            transaction_description=description,
            transaction_started=True,
            transaction_committed=False,
            read_back_error=read_back_error,
        )

    read_back = success_read_back if commit else rollback_read_back
    validator = validate_success if commit else validate_rollback
    try:
        stored = read_back()
    except Exception as exc:
        read_back_error = str(exc) or type(exc).__name__
        prefix = (
            "Committed mutation could not be verified"
            if commit else "Rollback could not be verified"
        )
        combined_error = prefix
        if error:
            combined_error = error + "; " + combined_error
        return _mutation_contract_result(
            operation,
            "failed",
            requested,
            old=old,
            error=combined_error,
            transaction_description=description,
            transaction_started=True,
            transaction_committed=commit,
            read_back_error=read_back_error,
        )

    mismatch = validator(stored)
    if mismatch:
        prefix = (
            "Committed mutation final read-back failed: "
            if commit else "Rollback verification failed: "
        )
        combined_error = prefix + mismatch
        if error:
            combined_error = error + "; " + combined_error
        return _mutation_contract_result(
            operation,
            "failed",
            requested,
            old=old,
            stored=stored,
            error=combined_error,
            transaction_description=description,
            transaction_started=True,
            transaction_committed=commit,
        )

    return _mutation_contract_result(
        operation,
        "success" if commit else "rolled_back",
        requested,
        old=old,
        stored=stored,
        error=error,
        transaction_description=description,
        transaction_started=True,
        transaction_committed=commit,
    )


def _disclose_name_only_materialization(result: Dict[str, Any]) -> Dict[str, Any]:
    """Expose native type-lock effects of an inferred name-only edit."""
    if result.get("status") != "success":
        return result
    old = result.get("old", {})
    stored = result.get("stored", {})
    if old.get("database_backed") or not stored.get("database_backed"):
        return result
    fields = ("name", "type", "database_backed", "name_locked", "type_locked")
    before = {field: old.get(field) for field in fields}
    after = {field: stored.get(field) for field in fields}
    locked = (bool(old.get("is_param")) and not old.get("type_locked")
              and bool(stored.get("type_locked")))
    effect = {
        "caller_requested_type": False,
        "before": before,
        "after": after,
        "inferred_parameter_type_locked": locked,
    }
    if locked:
        effect["guidance"] = (
            "Native Ghidra materialization locked the inferred parameter type "
            "although no type was requested; refresh variable identities "
            "before further edits"
        )
    result["name_only_materialization"] = effect
    return result


def set_variable_name_by_id(ctx: ProgramContext, addr_hex: str, var_id: str,
                     new_name: str, split_use: bool = False,
                     merge_group_id: str = "") -> Dict[str, Any]:
    """Rename one complete decompiler HighSymbol by stable identity."""
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {
        "address": addr_hex,
        "var_id": var_id,
        "new_name": new_name,
        "split_use": split_use,
        "merge_group_id": merge_group_id,
    }
    try:
        decomp, high_function, symbol = _select_high_var(ctx, addr_hex, var_id)
    except Exception as exc:
        return _unsupported_high_var_result(
            "set_variable_name_by_id", requested, str(exc)
        )
    try:
        old = _high_var_state(symbol)
        if not old["persistable"]:
            return _unsupported_high_var_result(
                "set_variable_name_by_id", requested,
                old.get("capability_reason", "Variable cannot be persisted")
                + ". This limits high-symbol ID editing; if a uniquely named "
                + "database-backed variable exists, use set_variable_name "
                + "with its exact current name, then refresh identities.",
            )
        split_failure = _validate_merge_group_selection(
            symbol, split_use, merge_group_id
        )
        if split_failure:
            return _high_var_validation_result(
                "set_variable_name_by_id", requested, split_failure
            )
        if split_use:
            return _unsupported_high_var_result(
                "set_variable_name_by_id", requested,
                "Rename-only merge-group splitting cannot be verified or "
                "safely rolled back; materialize the selected group with "
                "create_variable_by_id, refresh identities, then rename its "
                "separate database variable",
            )
        if symbol.getName() == new_name:
            return {
                "operation": "set_variable_name_by_id",
                "status": "no_change",
                "requested": requested,
                "old": old,
                "stored": old,
                "transaction": {"started": False, "committed": False},
            }
        for candidate in list(high_function.getLocalSymbolMap().getSymbols()):
            if candidate is not symbol and candidate.getName() == new_name:
                return _high_var_validation_result(
                    "set_variable_name_by_id", requested,
                    "Requested name '{}' conflicts with {} at storage {}".format(
                        new_name, _high_var_id(candidate), candidate.getStorage()
                    ),
                )
        rollback_locator = _high_var_locator(symbol)
        old_function_state = _stable_identity_function_state(ctx, addr_hex)
        mutation_locator: Dict[str, Any] = {}

        def apply_and_validate() -> None:
            target = (
                _split_high_variable(high_function, symbol, merge_group_id)
                if split_use else symbol
            )
            mutation_locator.update(_high_var_locator(target))
            mutation_locator["expected_name"] = new_name
            HighFunctionDBUtil.updateDBVariable(
                target, new_name, None, SourceType.USER_DEFINED
            )
            database_variable = HighFunctionDBUtil.getFunctionVariable(target)
            if (
                database_variable is None
                or str(database_variable.getName()) != new_name
            ):
                raise ValueError("Database variable name read-back mismatch")

        def validate_success(stored: Any) -> Optional[str]:
            if not stored.get("database_backed"):
                return "Renamed variable is not database-backed"
            if stored.get("name") != new_name:
                return "Decompiler variable name read-back mismatch"
            return None

        def validate_rollback(stored: Any) -> Optional[str]:
            if (
                _high_var_restoration_state(stored)
                != _high_var_restoration_state(old)
            ):
                return "Decompiler variable state differs from pre-state"
            if (
                _stable_identity_function_state(ctx, addr_hex)
                != old_function_state
            ):
                return "Function signature or database-variable state differs from pre-state"
            return None

        return _disclose_name_only_materialization(_run_stable_identity_transaction(
            ctx,
            "set_variable_name_by_id",
            "Rename decompiler variable",
            requested,
            old,
            apply_and_validate,
            lambda: _read_high_var_after(ctx, addr_hex, mutation_locator),
            validate_success,
            lambda: _read_high_var_after(ctx, addr_hex, rollback_locator),
            validate_rollback,
        ))
    finally:
        decomp.dispose()


def set_variable_type_by_id(ctx: ProgramContext, addr_hex: str, var_id: str,
                     type_name: str, split_use: bool = False,
                     merge_group_id: str = "") -> Dict[str, Any]:
    """Retype one complete decompiler HighSymbol by stable identity."""
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {
        "address": addr_hex,
        "var_id": var_id,
        "type_name": type_name,
        "split_use": split_use,
        "merge_group_id": merge_group_id,
    }
    data_type = _resolve_type(ctx.program, type_name)
    if data_type is None:
        return _high_var_validation_result(
            "set_variable_type_by_id", requested, "Unknown type: " + type_name
        )
    requested["resolved_type"] = str(data_type)
    try:
        decomp, high_function, symbol = _select_high_var(
            ctx, addr_hex, var_id
        )
    except Exception as exc:
        return _unsupported_high_var_result(
            "set_variable_type_by_id", requested, str(exc)
        )
    try:
        old = _high_var_state(symbol)
        if not old["persistable"]:
            return _unsupported_high_var_result(
                "set_variable_type_by_id", requested,
                old.get("capability_reason", "Variable cannot be persisted")
                + ". This limits high-symbol ID editing; if a uniquely named "
                + "database-backed variable exists, use set_variable_type "
                + "with its exact current name, then refresh identities.",
            )
        split_failure = _validate_merge_group_selection(
            symbol, split_use, merge_group_id
        )
        if split_failure:
            return _high_var_validation_result(
                "set_variable_type_by_id", requested, split_failure
            )
        if split_use:
            return _unsupported_high_var_result(
                "set_variable_type_by_id", requested,
                "Retype-only merge-group splitting cannot be verified or "
                "safely rolled back; materialize the selected group with "
                "create_variable_by_id, refresh identities, then retype its "
                "separate database variable",
            )
        if not split_use and symbol.getDataType().isEquivalent(data_type):
            return {
                "operation": "set_variable_type_by_id",
                "status": "no_change",
                "requested": requested,
                "old": old,
                "stored": old,
                "transaction": {"started": False, "committed": False},
            }
        rollback_locator = _high_var_locator(symbol)
        old_function_state = _stable_identity_function_state(ctx, addr_hex)
        mutation_locator: Dict[str, Any] = {}

        def apply_and_validate() -> None:
            target = (
                _split_high_variable(high_function, symbol, merge_group_id)
                if split_use else symbol
            )
            mutation_locator.update(_high_var_locator(target))
            HighFunctionDBUtil.updateDBVariable(
                target, None, data_type, SourceType.USER_DEFINED
            )
            database_variable = HighFunctionDBUtil.getFunctionVariable(target)
            if (
                database_variable is None
                or not database_variable.getDataType().isEquivalent(data_type)
            ):
                raise ValueError("Database variable type read-back mismatch")

        def validate_success(stored: Any) -> Optional[str]:
            if not stored.get("database_backed"):
                return "Retyped variable is not database-backed"
            stored_type = _resolve_type(ctx.program, stored.get("type", ""))
            if stored_type is None or not stored_type.isEquivalent(data_type):
                return "Decompiler variable type read-back mismatch"
            return None

        def validate_rollback(stored: Any) -> Optional[str]:
            if (
                _high_var_restoration_state(stored)
                != _high_var_restoration_state(old)
            ):
                return "Decompiler variable state differs from pre-state"
            if (
                _stable_identity_function_state(ctx, addr_hex)
                != old_function_state
            ):
                return "Function signature or database-variable state differs from pre-state"
            return None

        return _run_stable_identity_transaction(
            ctx,
            "set_variable_type_by_id",
            "Retype decompiler variable",
            requested,
            old,
            apply_and_validate,
            lambda: _read_high_var_after(ctx, addr_hex, mutation_locator),
            validate_success,
            lambda: _read_high_var_after(ctx, addr_hex, rollback_locator),
            validate_rollback,
        )
    finally:
        decomp.dispose()


def create_variable_by_id(ctx: ProgramContext, addr_hex: str, var_id: str,
                     name: str = "", type_name: str = "",
                     split_use: bool = False,
                     merge_group_id: str = "") -> Dict[str, Any]:
    """Materialize database backing for a selected decompiler variable."""
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {
        "address": addr_hex,
        "var_id": var_id,
        "name": name,
        "type_name": type_name,
        "split_use": split_use,
        "merge_group_id": merge_group_id,
    }
    requested_type = _resolve_type(ctx.program, type_name) if type_name else None
    if type_name and requested_type is None:
        return _high_var_validation_result(
            "create_variable_by_id", requested, "Unknown type: " + type_name
        )
    if requested_type is not None:
        requested["resolved_type"] = str(requested_type)
    try:
        decomp, high_function, symbol = _select_high_var(
            ctx, addr_hex, var_id
        )
    except Exception as exc:
        return _unsupported_high_var_result(
            "create_variable_by_id", requested, str(exc)
        )
    try:
        old = _high_var_state(symbol)
        if not old["persistable"]:
            return _unsupported_high_var_result(
                "create_variable_by_id", requested,
                old.get("capability_reason", "Variable cannot be persisted"),
            )
        split_failure = _validate_merge_group_selection(
            symbol, split_use, merge_group_id
        )
        if split_failure:
            return _high_var_validation_result(
                "create_variable_by_id", requested, split_failure
            )
        stored_name = name or symbol.getName()
        stored_type = requested_type or symbol.getDataType()
        requested["stored_name"] = stored_name
        requested["stored_type"] = str(stored_type)
        database_variable = HighFunctionDBUtil.getFunctionVariable(symbol)
        if database_variable is not None and not split_use:
            if (stored_name == symbol.getName()
                    and symbol.getDataType().isEquivalent(stored_type)):
                return {
                    "operation": "create_variable_by_id",
                    "status": "no_change",
                    "requested": requested,
                    "old": old,
                    "stored": old,
                    "transaction": {"started": False, "committed": False},
                }
            return _high_var_validation_result(
                "create_variable_by_id", requested,
                "Variable already has database backing; use the identity-"
                "backed rename or retype operation",
            )
        if split_use and stored_name == symbol.getName():
            return _high_var_validation_result(
                "create_variable_by_id", requested,
                "A split merge group requires a name distinct from the "
                "remaining complete symbol",
            )
        for candidate in list(high_function.getLocalSymbolMap().getSymbols()):
            if candidate is not symbol and candidate.getName() == stored_name:
                return _high_var_validation_result(
                    "create_variable_by_id", requested,
                    "Requested name '{}' conflicts with {} at storage {}".format(
                        stored_name, _high_var_id(candidate),
                        candidate.getStorage(),
                    ),
                )
        if split_use:
            try:
                selected_uses, remaining_uses = _split_use_anchors(
                    symbol, merge_group_id
                )
            except ValueError as exc:
                return _high_var_validation_result(
                    "create_variable_by_id", requested, str(exc)
                )
        rollback_locator = _high_var_locator(symbol)
        old_function_state = _stable_identity_function_state(ctx, addr_hex)
        mutation_locator: Dict[str, Any] = {}

        def apply_and_validate() -> None:
            target = (
                _split_high_variable(high_function, symbol, merge_group_id)
                if split_use else symbol
            )
            mutation_locator.update(_high_var_locator(target))
            mutation_locator["expected_name"] = stored_name
            HighFunctionDBUtil.updateDBVariable(
                target, stored_name, stored_type, SourceType.USER_DEFINED
            )
            database_variable = HighFunctionDBUtil.getFunctionVariable(target)
            if (
                database_variable is None
                or str(database_variable.getName()) != stored_name
                or not database_variable.getDataType().isEquivalent(stored_type)
            ):
                raise ValueError("Created variable database read-back mismatch")
            if split_use:
                _verify_split_use_isolation(
                    ctx, addr_hex, selected_uses, remaining_uses, stored_name
                )

        def validate_success(stored: Any) -> Optional[str]:
            if not stored.get("database_backed"):
                return "Created variable is not database-backed"
            if stored.get("name") != stored_name:
                return "Created variable name read-back mismatch"
            final_type = _resolve_type(ctx.program, stored.get("type", ""))
            if final_type is None or not final_type.isEquivalent(stored_type):
                return "Created variable type read-back mismatch"
            if split_use:
                try:
                    _verify_split_use_isolation(
                        ctx, addr_hex, selected_uses, remaining_uses, stored_name
                    )
                except ValueError as exc:
                    return str(exc)
            return None

        def validate_rollback(stored: Any) -> Optional[str]:
            if (
                _high_var_restoration_state(stored)
                != _high_var_restoration_state(old)
            ):
                return "Decompiler variable state differs from pre-state"
            if (
                _stable_identity_function_state(ctx, addr_hex)
                != old_function_state
            ):
                return "Function signature or database-variable state differs from pre-state"
            return None

        result = _run_stable_identity_transaction(
            ctx,
            "create_variable_by_id",
            "Create database variable from decompiler identity",
            requested,
            old,
            apply_and_validate,
            lambda: _read_high_var_after(ctx, addr_hex, mutation_locator),
            validate_success,
            lambda: _read_high_var_after(ctx, addr_hex, rollback_locator),
            validate_rollback,
        )
        if (split_use and result.get("status") == "failed"
                and "Rollback could not be verified" in result.get("error", "")):
            result["error"] += (
                "; inspect current variable identities before further mutation"
            )
        if not type_name:
            _disclose_name_only_materialization(result)
        return result
    finally:
        decomp.dispose()


def delete_variable_by_id(ctx: ProgramContext, addr_hex: str,
                     var_id: str) -> Dict[str, Any]:
    """Delete an exact database-backed parameter or local variable."""
    from ghidra.program.model.listing import Parameter  # type: ignore
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore

    requested = {"address": addr_hex, "var_id": var_id}
    try:
        decomp, high_function, symbol = _select_high_var(
            ctx, addr_hex, var_id
        )
    except Exception as exc:
        return _high_var_validation_result(
            "delete_variable_by_id", requested, str(exc)
        )
    try:
        old = _high_var_state(symbol)
        variable = HighFunctionDBUtil.getFunctionVariable(symbol)
        if variable is None or variable.getSymbol() is None:
            return {
                "operation": "delete_variable_by_id",
                "status": "no_change",
                "requested": requested,
                "old": old,
                "stored": old,
                "transaction": {"started": False, "committed": False},
            }
        if isinstance(variable, Parameter) and variable.isAutoParameter():
            return _unsupported_high_var_result(
                "delete_variable_by_id", requested,
                "Auto parameters are controlled by the function signature "
                "and cannot be deleted independently",
            )
        function = high_function.getFunction()
        database_symbol_id = int(variable.getSymbol().getID())
        requested["database_symbol_id"] = str(
            database_symbol_id & ((1 << 64) - 1)
        )
        rollback_locator = _high_var_locator(symbol)
        old_function_state = _stable_identity_function_state(ctx, addr_hex)

        def apply_and_validate() -> None:
            if isinstance(variable, Parameter):
                function.removeParameter(variable.getOrdinal())
            else:
                function.removeVariable(variable)
            if _find_database_variable_by_symbol_id(
                function, database_symbol_id
            ) is not None:
                raise ValueError(
                    "Deleted variable remains in the function database"
                )

        def success_read_back() -> Dict[str, Any]:
            remaining = _find_database_variable_by_symbol_id(
                function, database_symbol_id
            )
            return {
                "deleted": True,
                "database_symbol_id": requested["database_symbol_id"],
                "function": list_function_variables(ctx, addr_hex),
                "database_variable_present": remaining is not None,
            }

        def validate_success(stored: Any) -> Optional[str]:
            if stored.get("database_variable_present"):
                return "Deleted variable remains after transaction close"
            variables = stored.get("function", {})
            if "error" in variables:
                return "Function-variable read-back failed: " + str(
                    variables["error"]
                )
            return None

        def validate_rollback(stored: Any) -> Optional[str]:
            if (
                _high_var_restoration_state(stored)
                != _high_var_restoration_state(old)
            ):
                return "Decompiler variable state differs from pre-state"
            if (
                _stable_identity_function_state(ctx, addr_hex)
                != old_function_state
            ):
                return "Function signature or database-variable state differs from pre-state"
            return None

        result = _run_stable_identity_transaction(
            ctx,
            "delete_variable_by_id",
            "Delete database variable",
            requested,
            old,
            apply_and_validate,
            success_read_back,
            validate_success,
            lambda: _read_high_var_after(ctx, addr_hex, rollback_locator),
            validate_rollback,
        )
        if result.get("status") == "success":
            result["stored"].pop("database_variable_present", None)
        return result
    finally:
        decomp.dispose()


def set_function_return_type(ctx: ProgramContext, addr_hex: str,
                    type_name: str) -> Dict[str, Any]:
    """Set the return type of a function."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {"return_type": type_name}
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _mutation_validation_failure(
            "set_function_return_type", requested, "No function at " + addr_hex
        )

    dt = _resolve_type(ctx.program, type_name)
    if dt is None:
        return _mutation_validation_failure(
            "set_function_return_type", requested,
            "Unknown data type: " + type_name,
        )
    requested["return_type"] = str(dt)
    old = _func_info_contract_state(ctx, addr_hex)
    if func.getReturnType().isEquivalent(dt):
        return _mutation_no_change("set_function_return_type", requested, old)
    old_parameters, parameter_error = _return_type_parameter_preflight(
        ctx, addr_hex
    )
    if parameter_error:
        return _mutation_validation_failure(
            "set_function_return_type", requested, parameter_error
        )

    def validate(stored: Any) -> Optional[str]:
        if not func.getReturnType().isEquivalent(dt):
            return "Return type read-back mismatch: requested {}, stored {}".format(
                dt, func.getReturnType()
            )
        if _effective_parameter_contract(ctx, addr_hex) != old_parameters:
            return "Effective parameter list changed during return-type mutation"
        return None

    def validate_rollback(stored: Any) -> Optional[str]:
        if stored != old:
            return "Function metadata differs from pre-state"
        if _effective_parameter_contract(ctx, addr_hex) != old_parameters:
            return "Effective parameter list differs from pre-state"
        return None

    return _run_mutation_transaction(
        ctx,
        "set_function_return_type",
        "Set return type",
        requested,
        old,
        lambda: func.setReturnType(dt, SourceType.USER_DEFINED),
        lambda: _func_info_contract_state(ctx, addr_hex),
        validate,
        validate_rollback=validate_rollback,
    )


__all__ = [
    "_stack_mutation_result",
    "_stack_storage_conflicts",
    "_create_stack_variable",
    "create_stack_variable",
    "delete_stack_variable",
    "create_stack_variable_from_structure",
    "_func_var_state",
    "list_function_variables",
    "_high_var_id",
    "_merge_group_id",
    "_high_var_capability_reason",
    "_high_var_state",
    "_FUNC_VAR_IDENTITY_DEFAULT_LIMIT",
    "_FUNC_VAR_IDENTITY_MAX_LIMIT",
    "_FUNC_VAR_IDENTITY_FILTER_FIELDS",
    "_page_func_var_identities",
    "list_function_variable_identities",
    "_RETURN_TYPE_INFERRED_PARAMETER_ERROR",
    "_effective_parameter_contract",
    "_return_type_parameter_preflight",
    "_function_contract_state",
    "_func_info_contract_state",
    "_resolve_unique_variable",
    "_find_variable_by_storage",
    "set_variable_name",
    "set_variable_type",
    "_select_high_var",
    "_high_var_locator",
    "_high_var_matches_locator",
    "_find_high_var_after",
    "_unsupported_high_var_result",
    "_high_var_validation_result",
    "_validate_merge_group_selection",
    "_split_high_variable",
    "_stable_identity_function_state",
    "_high_var_restoration_state",
    "_read_high_var_after",
    "_find_database_variable_by_symbol_id",
    "_run_stable_identity_transaction",
    "set_variable_name_by_id",
    "set_variable_type_by_id",
    "create_variable_by_id",
    "delete_variable_by_id",
    "set_function_return_type",
]
