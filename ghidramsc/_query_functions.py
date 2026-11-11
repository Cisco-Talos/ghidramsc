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

"""Private functions implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .bridge import ProgramContext

from ._query_core import (
    _addr_int,
    _batch_mutation_result,
    _end_mutation_transaction,
    _get_monitor,
    _mutation_no_change,
    _mutation_validation_failure,
    _run_mutation_transaction,
    _start_mutation_transaction,
)

from ._query_inspection import (
    _function_body_ranges,
    get_function_info,
)

from ._query_variables import (
    _effective_parameter_contract,
    _func_info_contract_state,
)


def _rename_func_state(func) -> Optional[Dict[str, str]]:
    """Return only the function identity needed by the rename contract."""
    if func is None:
        return None
    return {
        "address": str(func.getEntryPoint()),
        "name": str(func.getName()),
    }


def _rename_func_result(status: str, addr_hex: str, new_name: str,
                        old: Optional[Dict[str, str]] = None,
                        stored: Optional[Dict[str, str]] = None,
                        error: Optional[str] = None) -> Dict[str, Any]:
    """Build the transport-independent public result for ``set_function_name``."""
    return {
        "operation": "set_function_name",
        "status": status,
        "requested": {"address": addr_hex, "name": new_name},
        "old": old,
        "stored": stored,
        "error": error,
    }


def set_function_name(ctx: ProgramContext, addr_hex: str,
                new_name: str) -> Dict[str, Any]:
    """Rename one function and verify its stored name before success."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    addr_int = _addr_int(addr_hex)
    func = ctx.resolve_function(addr_int)
    if func is None:
        return _rename_func_result(
            "validation_failed", addr_hex, new_name,
            error="No function at or containing " + addr_hex,
        )

    old = _rename_func_state(func)
    if old["name"] == new_name:
        return _rename_func_result(
            "no_change", addr_hex, new_name, old, dict(old),
        )

    tx_id = _start_mutation_transaction(ctx, "Rename function")
    commit = False
    error = None
    stored = None
    try:
        func.setName(new_name, SourceType.USER_DEFINED)
        stored = _rename_func_state(ctx.resolve_function(addr_int))
        if stored is None or stored["name"] != new_name:
            stored_name = None if stored is None else stored["name"]
            raise ValueError(
                "Function name read-back mismatch: requested {}, stored {}"
                .format(new_name, stored_name)
            )
        commit = True
    except Exception as exc:
        error = str(exc)
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)

    if commit:
        return _rename_func_result(
            "success", addr_hex, new_name, old, stored,
        )

    try:
        stored = _rename_func_state(ctx.resolve_function(addr_int))
    except Exception:
        stored = None
    return _rename_func_result(
        "rolled_back", addr_hex, new_name, old, stored, error=error,
    )


def _compact_rename_item(result: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten one U03 rename result for a compact batch response."""
    requested = result["requested"]
    old = result.get("old")
    stored = result.get("stored")
    return {
        "address": requested["address"],
        "status": result["status"],
        "requested_name": requested["name"],
        "old_name": None if old is None else old["name"],
        "stored_name": None if stored is None else stored["name"],
        "error": result.get("error"),
    }


def _batch_rename_result(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the compact per-item aggregation required by U05."""
    succeeded = sum(item["status"] == "success" for item in items)
    unchanged = sum(item["status"] == "no_change" for item in items)
    failed = len(items) - succeeded - unchanged
    if failed == 0:
        status = "no_change" if succeeded == 0 else "success"
    elif succeeded or unchanged:
        status = "partial_success"
    else:
        status = "validation_failed"
    return {
        "operation": "set_function_names",
        "status": status,
        "atomicity": "per_item",
        "succeeded": succeeded,
        "unchanged": unchanged,
        "failed": failed,
        "total": len(items),
        "items": items,
    }


def _batch_rename_item(ctx: ProgramContext, address: str,
                       requested_name: str) -> Dict[str, Any]:
    """Run and compact one per-item rename without aborting later entries."""
    try:
        return _compact_rename_item(
            set_function_name(ctx, address, requested_name)
        )
    except Exception as exc:
        return {
            "address": address,
            "status": "validation_failed",
            "requested_name": requested_name,
            "old_name": None,
            "stored_name": None,
            "error": str(exc) or type(exc).__name__,
        }


def set_function_names(ctx: ProgramContext, json_path: str) -> Dict[str, Any]:
    """Rename functions from a JSON file with compact per-item results.

    JSON: [{"addr": "0x...", "name": "NewName"}, ...]
    """
    with open(json_path, "r", encoding="utf-8") as stream:
        entries = json.load(stream)
    if not isinstance(entries, list):
        raise ValueError("set_function_names input must be a JSON array")
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("addr"), str)
            or not isinstance(entry.get("name"), str)
        ):
            raise ValueError(
                "set_function_names entries must contain string addr and name fields"
            )

    items = [
        _batch_rename_item(ctx, entry["addr"], entry["name"])
        for entry in entries
    ]
    return _batch_rename_result(items)


def _function_state(ctx: ProgramContext, addr) -> Dict[str, Any]:
    func = ctx.get_function_at(addr)
    if func is None:
        func = ctx.get_function_containing(addr)
    if func is None:
        return {"exists": False, "address": str(addr)}
    state = get_function_info(ctx, str(func.getEntryPoint()))
    state["exists"] = True
    return state


def _function_conflict_state(func) -> Dict[str, Any]:
    return {
        "name": str(func.getName()),
        "entry": str(func.getEntryPoint()),
        "body_bytes": func.getBody().getNumAddresses(),
        "body_ranges": _function_body_ranges(func.getBody()),
    }


def _function_conflicts(ctx: ProgramContext, body,
                        ignored_entry=None) -> List[Dict[str, Any]]:
    conflicts = []
    iterator = ctx.program.getFunctionManager().getFunctionsOverlapping(body)
    while iterator.hasNext():
        func = iterator.next()
        if (ignored_entry is not None
                and func.getEntryPoint().equals(ignored_entry)):
            continue
        conflicts.append(_function_conflict_state(func))
    return conflicts


def _normalize_function_body_ranges(ctx: ProgramContext,
                                    ranges: List[Dict[str, str]], entry):
    from ghidra.program.model.address import AddressSet  # type: ignore

    if not isinstance(ranges, list) or not ranges:
        raise ValueError(
            "ranges must contain at least one inclusive address range")
    body = AddressSet()
    for spec in ranges:
        if not isinstance(spec, dict):
            raise ValueError("Each function-body range must be an object")
        if not isinstance(spec.get("start"), str):
            raise ValueError("Function-body range start must be a string")
        if not isinstance(spec.get("end"), str):
            raise ValueError("Function-body range end must be a string")
        start = ctx.to_addr(_addr_int(spec["start"]))
        end = ctx.to_addr(_addr_int(spec["end"]))
        if not start.getAddressSpace().equals(end.getAddressSpace()):
            raise ValueError(
                "Function-body range endpoints must share an address space")
        if end.compareTo(start) < 0:
            raise ValueError(
                "Function-body range end precedes start: {}-{}".format(
                    spec["start"], spec["end"]))
        item = AddressSet(start, end)
        if not ctx.program.getMemory().contains(item):
            raise ValueError(
                "Function-body range is not entirely in memory: {}-{}".format(
                    spec["start"], spec["end"]))
        if body.intersects(item):
            raise ValueError(
                "Function-body ranges overlap: {}-{}".format(
                    spec["start"], spec["end"]))
        body.addRange(start, end)
    if not body.contains(entry):
        raise ValueError("Function body must contain entry point " + str(entry))
    return body, _function_body_ranges(body)


def _function_mutation_result(operation: str, status: str,
                              requested: Dict[str, Any],
                              old: Optional[Dict[str, Any]] = None,
                              stored: Optional[Dict[str, Any]] = None,
                              conflicts: Optional[List[Dict[str, Any]]] = None,
                              error: str = "") -> Dict[str, Any]:
    result = {
        "operation": operation,
        "status": status,
        "requested": requested,
        "conflicting_functions": conflicts or [],
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


def delete_function(ctx: ProgramContext, addr_hex: str) -> Dict[str, Any]:
    """Remove only a function definition, preserving code units and bytes."""
    addr = ctx.to_addr(_addr_int(addr_hex))
    func = ctx.resolve_function(_addr_int(addr_hex))
    requested = {"address": str(addr)}
    if func is None:
        return _function_mutation_result(
            "delete_function", "validation_failed", requested,
            error="No function at or containing " + addr_hex)
    entry = func.getEntryPoint()
    requested["entry"] = str(entry)
    old = _function_state(ctx, entry)
    tx_id = _start_mutation_transaction(ctx, "Remove function")
    commit = False
    try:
        removed = ctx.program.getFunctionManager().removeFunction(entry)
        if (not removed or ctx.program.getFunctionManager()
                .getFunctionAt(entry) is not None):
            raise ValueError("Function was not removed at " + str(entry))
        stored = _function_state(ctx, entry)
        commit = True
        return _function_mutation_result(
            "delete_function", "success", requested, old, stored)
    except Exception as exc:
        return _function_mutation_result(
            "delete_function", "rolled_back", requested, old,
            error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def set_function_body(ctx: ProgramContext, addr_hex: str,
                  ranges: List[Dict[str, str]]) -> Dict[str, Any]:
    """Replace a function body with explicit inclusive address ranges."""
    addr = ctx.to_addr(_addr_int(addr_hex))
    func = ctx.resolve_function(_addr_int(addr_hex))
    requested: Dict[str, Any] = {
        "address": str(addr), "ranges": ranges,
    }
    if func is None:
        return _function_mutation_result(
            "set_function_body", "validation_failed", requested,
            error="No function at or containing " + addr_hex)
    entry = func.getEntryPoint()
    requested["entry"] = str(entry)
    old = _function_state(ctx, entry)
    try:
        body, normalized = _normalize_function_body_ranges(
            ctx, ranges, entry)
        requested["ranges"] = normalized
    except Exception as exc:
        return _function_mutation_result(
            "set_function_body", "validation_failed", requested, old,
            error=str(exc))
    conflicts = _function_conflicts(ctx, body, entry)
    if conflicts:
        return _function_mutation_result(
            "set_function_body", "validation_failed", requested, old,
            conflicts=conflicts,
            error="Requested body overlaps existing functions")
    if func.getBody().hasSameAddresses(body):
        return _function_mutation_result(
            "set_function_body", "no_change", requested, old, old,
            conflicts)

    tx_id = _start_mutation_transaction(ctx, "Set function body")
    commit = False
    try:
        func.setBody(body)
        stored_func = ctx.program.getFunctionManager().getFunctionAt(entry)
        if (stored_func is None
                or not stored_func.getBody().hasSameAddresses(body)):
            raise ValueError(
                "Function body read-back did not match the request")
        stored = _function_state(ctx, entry)
        commit = True
        return _function_mutation_result(
            "set_function_body", "success", requested, old, stored, conflicts)
    except Exception as exc:
        return _function_mutation_result(
            "set_function_body", "rolled_back", requested, old,
            conflicts=conflicts, error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def create_function(ctx: ProgramContext, addr_hex: str, name: str = "",
                ranges: Optional[List[Dict[str, str]]] = None
                ) -> Dict[str, Any]:
    """Create a function, optionally with exact inclusive body ranges."""
    from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore

    addr = ctx.to_addr(_addr_int(addr_hex))
    requested: Dict[str, Any] = {"address": str(addr), "name": name}
    old = _function_state(ctx, addr)
    existing = ctx.resolve_function(_addr_int(addr_hex))
    if existing is not None:
        return _function_mutation_result(
            "create_function", "validation_failed", requested, old,
            conflicts=[_function_conflict_state(existing)],
            error="A function already exists at or contains " + addr_hex)

    body = None
    if ranges:
        try:
            body, normalized = _normalize_function_body_ranges(
                ctx, ranges, addr)
            requested["ranges"] = normalized
        except Exception as exc:
            return _function_mutation_result(
                "create_function", "validation_failed", requested, old,
                error=str(exc))
    conflicts = _function_conflicts(ctx, body) if body is not None else []
    if conflicts:
        return _function_mutation_result(
            "create_function", "validation_failed", requested, old,
            conflicts=conflicts,
            error="Requested body overlaps existing functions")

    tx_id = _start_mutation_transaction(ctx, "Create function")
    commit = False
    try:
        if body is None:
            cmd = CreateFunctionCmd(addr)
        else:
            source = SourceType.USER_DEFINED if name else SourceType.DEFAULT
            cmd = CreateFunctionCmd(name or None, addr, body, source)
        if not cmd.applyTo(ctx.program, _get_monitor()):
            raise ValueError(
                "Failed to create function at {}: {}".format(
                    addr_hex, cmd.getStatusMsg()))
        func = ctx.program.getFunctionManager().getFunctionAt(addr)
        if func is None:
            raise ValueError("Function was not stored at " + addr_hex)
        if name and func.getName() != name:
            func.setName(name, SourceType.USER_DEFINED)
        if body is not None and not func.getBody().hasSameAddresses(body):
            raise ValueError(
                "Function body read-back did not match the request")
        stored = _function_state(ctx, addr)
        if name and stored.get("name") != name:
            raise ValueError(
                "Function name read-back did not match the request")
        commit = True
        return _function_mutation_result(
            "create_function", "success", requested, old, stored, conflicts)
    except Exception as exc:
        return _function_mutation_result(
            "create_function", "rolled_back", requested, old,
            conflicts=conflicts, error=str(exc))
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def create_functions(ctx: ProgramContext, json_path: str) -> Dict[str, Any]:
    """Create functions with an independent verified transaction per item."""
    with open(json_path, "r", encoding="utf-8") as stream:
        entries = json.load(stream)
    if not isinstance(entries, list):
        raise ValueError("create_functions JSON input must contain an array")
    for entry in entries:
        valid = isinstance(entry, str)
        if isinstance(entry, dict):
            valid = isinstance(entry.get("addr"), str)
            if "name" in entry:
                valid = valid and isinstance(entry["name"], str)
        if not valid:
            return _mutation_validation_failure(
                "create_functions",
                {"json_data": entries},
                "create_functions entries must be address strings or objects",
            )

    items = []
    for entry in entries:
        address = entry["addr"] if isinstance(entry, dict) else entry
        name = entry.get("name", "") if isinstance(entry, dict) else ""
        try:
            item = create_function(ctx, address, name)
        except Exception as exc:
            item = _mutation_validation_failure(
                "create_function",
                {"address": address, "name": name},
                str(exc) or type(exc).__name__,
            )
        items.append(item)
    return _batch_mutation_result("create_functions", entries, items)


def _require_resolved_prototype_type(location: str, data_type) -> None:
    from jpype import JClass  # type: ignore

    TypeDef = JClass("ghidra.program.model.data.TypeDef")
    Pointer = JClass("ghidra.program.model.data.Pointer")
    BadDataType = JClass("ghidra.program.model.data.BadDataType")
    Undefined = JClass("ghidra.program.model.data.Undefined")
    current = data_type
    while current is not None and isinstance(current, TypeDef):
        current = current.getBaseDataType()
    while current is not None and isinstance(current, Pointer):
        current = current.getDataType()
        while current is not None and isinstance(current, TypeDef):
            current = current.getBaseDataType()
    if (
        current is None
        or isinstance(current, BadDataType)
        or bool(Undefined.isUndefined(current))
    ):
        display = "null" if data_type is None else data_type.getDisplayName()
        raise ValueError(
            "Unresolved {} type: {}".format(location, display)
        )


def _parse_function_signature(program, func, prototype: str):
    from jpype import JClass  # type: ignore

    declaration = prototype.strip()
    if not declaration:
        raise ValueError("Prototype must not be empty")
    if not declaration.endswith(";"):
        declaration += ";"
    CParser = JClass("ghidra.app.util.cparser.C.CParser")
    FunctionDefinitionDataType = JClass(
        "ghidra.program.model.data.FunctionDefinitionDataType"
    )
    try:
        parser = CParser(program.getDataTypeManager())
        parsed = parser.parse(declaration)
        if (
            not parser.didParseSucceed()
            or not isinstance(parsed, FunctionDefinitionDataType)
        ):
            details = str(parser.getParseMessages())
            suffix = "" if not details else ": " + details
            raise ValueError("Could not parse function prototype" + suffix)
        _require_resolved_prototype_type("return", parsed.getReturnType())
        for parameter in parsed.getArguments():
            name = parameter.getName()
            _require_resolved_prototype_type(
                "parameter '{}'".format("" if name is None else name),
                parameter.getDataType(),
            )
        if parsed.getName() is None or not str(parsed.getName()).strip():
            raise ValueError("Prototype must declare a function name")

        requested_convention = str(parsed.getCallingConventionName())
        compiler_spec = program.getCompilerSpec()
        if compiler_spec.getCallingConvention(requested_convention) is None:
            current = func.getCallingConventionName()
            if (
                current is not None
                and compiler_spec.getCallingConvention(str(current)) is not None
            ):
                parsed.setCallingConvention(str(current))
        return parsed
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            "Could not parse function prototype: {}".format(
                str(exc) or type(exc).__name__
            )
        ) from exc


def _prototype_parameter_conflict(func, parsed) -> Optional[str]:
    requested_ordinals: Dict[str, int] = {}
    for parameter in parsed.getArguments():
        name = parameter.getName()
        if name is None or not str(name).strip():
            continue
        text = str(name)
        ordinal = int(parameter.getOrdinal())
        if text in requested_ordinals:
            return "Requested parameter name '{}' is duplicated at ordinals {} and {}".format(
                text, requested_ordinals[text], ordinal
            )
        requested_ordinals[text] = ordinal

    for variable in func.getLocalVariables():
        if str(variable.getName()) in requested_ordinals:
            return _prototype_variable_conflict(variable, False)
    for parameter in func.getParameters():
        name = str(parameter.getName())
        if (
            name in requested_ordinals
            and requested_ordinals[name] != int(parameter.getOrdinal())
        ):
            return _prototype_variable_conflict(parameter, True)
    return None


def _prototype_variable_conflict(variable, parameter: bool) -> str:
    symbol = variable.getSymbol()
    if symbol is None:
        symbol_type = "PARAMETER" if parameter else "LOCAL_VAR"
    else:
        symbol_type = str(symbol.getSymbolType())
    return "Requested parameter name '{}' conflicts with existing {} at storage {}".format(
        variable.getName(), symbol_type, variable.getVariableStorage()
    )


def _function_signature_matches(func, parsed) -> bool:
    if str(func.getName()) != str(parsed.getName()):
        return False
    stored = func.getSignature()
    if bool(stored.isEquivalentSignature(parsed)):
        return True
    # Ghidra can reject equivalence for signatures with identical public
    # semantics because the parsed definition carries different metadata.
    stored_args = list(stored.getArguments())
    parsed_args = list(parsed.getArguments())
    return (
        str(stored) == str(parsed)
        and str(stored.getCallingConventionName())
        == str(parsed.getCallingConventionName())
        and bool(stored.hasVarArgs()) == bool(parsed.hasVarArgs())
        and bool(stored.hasNoReturn()) == bool(parsed.hasNoReturn())
        and stored.getReturnType().isEquivalent(parsed.getReturnType())
        and len(stored_args) == len(parsed_args)
        and all(
            left.getDataType().isEquivalent(right.getDataType())
            for left, right in zip(stored_args, parsed_args)
        )
    )


def _apply_function_signature(program, func, parsed) -> None:
    from jpype import JClass  # type: ignore

    ApplyFunctionSignatureCmd = JClass(
        "ghidra.app.cmd.function.ApplyFunctionSignatureCmd"
    )
    SourceType = JClass("ghidra.program.model.symbol.SourceType")
    DataTypeConflictHandler = JClass(
        "ghidra.program.model.data.DataTypeConflictHandler"
    )
    FunctionRenameOption = JClass(
        "ghidra.app.cmd.function.FunctionRenameOption"
    )
    command = ApplyFunctionSignatureCmd(
        func.getEntryPoint(),
        parsed,
        SourceType.USER_DEFINED,
        False,
        False,
        DataTypeConflictHandler.DEFAULT_HANDLER,
        FunctionRenameOption.RENAME,
    )
    if not command.applyTo(program, _get_monitor()):
        status = str(command.getStatusMsg())
        suffix = "" if not status else ": " + status
        raise ValueError("Failed to apply prototype" + suffix)


def set_function_prototype(ctx: ProgramContext, addr_hex: str,
                           prototype: str) -> Dict[str, Any]:
    """Apply one parsed function signature atomically with exact read-back."""
    requested = {"address": addr_hex, "prototype": prototype}
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _mutation_validation_failure(
            "set_function_prototype", requested,
            "No function at " + addr_hex,
        )
    old = _func_info_contract_state(ctx, addr_hex)
    try:
        parsed = _parse_function_signature(ctx.program, func, prototype)
    except Exception as exc:
        return _mutation_validation_failure(
            "set_function_prototype", requested,
            str(exc) or type(exc).__name__,
        )
    conflict = _prototype_parameter_conflict(func, parsed)
    if conflict is not None:
        return _mutation_validation_failure(
            "set_function_prototype", requested, conflict
        )
    if _function_signature_matches(func, parsed):
        return _mutation_no_change(
            "set_function_prototype", requested, old
        )
    try:
        old_parameters = _effective_parameter_contract(ctx, addr_hex)
    except Exception as exc:
        return _mutation_validation_failure(
            "set_function_prototype", requested,
            str(exc) or type(exc).__name__,
        )

    def validate_rollback(stored: Any) -> Optional[str]:
        if stored != old:
            return "Function metadata differs from pre-state"
        if _effective_parameter_contract(ctx, addr_hex) != old_parameters:
            return "Effective parameter list differs from pre-state"
        return None

    return _run_mutation_transaction(
        ctx,
        "set_function_prototype",
        "Set function prototype",
        requested,
        old,
        lambda: _apply_function_signature(ctx.program, func, parsed),
        lambda: _func_info_contract_state(ctx, addr_hex),
        lambda stored: (
            None if _function_signature_matches(func, parsed)
            else "Prototype read-back does not match the parsed request"
        ),
        validate_rollback=validate_rollback,
    )


def set_function_calling_convention(ctx: ProgramContext, addr_hex: str,
                           convention: str) -> Dict[str, Any]:
    """Set the calling convention for a function (e.g. '__stdcall',
    '__cdecl', '__thiscall', '__fastcall', 'default')."""
    requested = {"calling_convention": convention}
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _mutation_validation_failure(
            "set_function_calling_convention", requested,
            "No function at " + addr_hex,
        )
    current = str(func.getCallingConventionName())
    if (
        convention != current
        and convention != "default"
        and ctx.program.getFunctionManager().getCallingConvention(
            convention
        ) is None
    ):
        available = sorted({str(name) for name in
                            ctx.program.getFunctionManager()
                            .getCallingConventionNames()} | {"default"})
        return _mutation_validation_failure(
            "set_function_calling_convention", requested,
            "Unknown calling convention: {}. Available for this program: {}"
            .format(convention, ", ".join(available)),
        )
    old = _func_info_contract_state(ctx, addr_hex)
    if convention == current:
        return _mutation_no_change(
            "set_function_calling_convention", requested, old
        )
    return _run_mutation_transaction(
        ctx,
        "set_function_calling_convention",
        "Set calling convention",
        requested,
        old,
        lambda: func.setCallingConvention(convention),
        lambda: _func_info_contract_state(ctx, addr_hex),
        lambda stored: (
            None if stored.get("calling_convention") == convention
            else "Calling convention read-back mismatch: requested {}, stored {}"
            .format(convention, stored.get("calling_convention"))
        ),
    )


def _function_noreturn_state(func) -> Dict[str, Any]:
    """Read the native flag and its effective target through a thunk."""
    effective = func.getThunkedFunction(True) if func.isThunk() else None
    if effective is None:
        effective = func
    return {
        "entry": str(func.getEntryPoint()),
        "name": str(func.getName()),
        "no_return": bool(func.hasNoReturn()),
        "is_thunk": bool(func.isThunk()),
        "is_external": bool(func.isExternal()),
        "effective_entry": str(effective.getEntryPoint()),
        "effective_no_return": bool(effective.hasNoReturn()),
        "signature": str(func.getSignature()),
    }


def set_function_noreturn(ctx: ProgramContext, addr_hex: str,
                          no_return: bool) -> Dict[str, Any]:
    """Set Ghidra's native no-return flag, including the effective thunk target."""
    operation = "set_function_noreturn"
    requested = {"address": addr_hex, "no_return": no_return}
    if not isinstance(addr_hex, str) or type(no_return) is not bool:
        return _mutation_validation_failure(
            operation, requested, "Address must be a string and no_return a boolean")
    try:
        func = ctx.resolve_function(_addr_int(addr_hex))
    except Exception as exc:
        return _mutation_validation_failure(operation, requested,
                                            "Invalid address: " + str(exc))
    if func is None:
        return _mutation_validation_failure(operation, requested,
                                            "No function at " + addr_hex)
    old = _function_noreturn_state(func)
    if old["no_return"] == no_return:
        return _mutation_no_change(operation, requested, old)

    def validate(stored: Dict[str, Any]) -> Optional[str]:
        if (stored["entry"] != old["entry"] or
                stored["effective_entry"] != old["effective_entry"] or
                stored["no_return"] != no_return or
                stored["effective_no_return"] != no_return):
            return "Function no-return read-back mismatch"
        return None

    return _run_mutation_transaction(
        ctx, operation, "Set function no-return", requested, old,
        lambda: func.setNoReturn(no_return),
        lambda: _function_noreturn_state(func), validate,
        validate_rollback=lambda state: (
            None if state == old else "Function no-return rollback mismatch"))


def _instruction_flow_state(ctx: ProgramContext, instruction) -> Dict[str, Any]:
    """Snapshot exact listing identity, bytes, and effective native flow."""
    address = instruction.getAddress()
    length = int(instruction.getLength())
    memory = ctx.program.getMemory()
    raw = bytes(int(memory.getByte(address.add(i))) & 0xff for i in range(length))
    fallthrough = instruction.getFallThrough()
    return {
        "address": str(address),
        "length": length,
        "bytes_hex": raw.hex(),
        "instruction": str(instruction),
        "flow_override": str(instruction.getFlowOverride()),
        "flow_type": str(instruction.getFlowType()),
        "fallthrough": str(fallthrough) if fallthrough is not None else None,
    }


def set_instruction_flow_override(ctx: ProgramContext, addr_hex: str,
                                  flow_override: str) -> Dict[str, Any]:
    """Set a native flow override on one instruction without changing bytes."""
    from ghidra.program.model.listing import FlowOverride  # type: ignore

    operation = "set_instruction_flow_override"
    requested = {"address": addr_hex, "flow_override": flow_override}
    if not isinstance(addr_hex, str) or not isinstance(flow_override, str):
        return _mutation_validation_failure(
            operation, requested, "Address and flow_override must be strings")
    allowed = {str(value): value for value in FlowOverride.values()}
    if flow_override not in allowed:
        return _mutation_validation_failure(
            operation, requested,
            "flow_override must be one of " + ", ".join(sorted(allowed)))
    try:
        address = ctx.to_addr(_addr_int(addr_hex))
    except Exception as exc:
        return _mutation_validation_failure(operation, requested,
                                            "Invalid address: " + str(exc))
    instruction = ctx.program.getListing().getInstructionAt(address)
    if instruction is None:
        return _mutation_validation_failure(
            operation, requested, "No instruction starts at " + addr_hex)
    old = _instruction_flow_state(ctx, instruction)
    if old["flow_override"] == flow_override:
        return _mutation_no_change(operation, requested, old)

    def validate(stored: Dict[str, Any]) -> Optional[str]:
        for key in ("address", "length", "bytes_hex", "instruction"):
            if stored[key] != old[key]:
                return "Instruction listing or bytes changed: " + key
        if stored["flow_override"] != flow_override:
            return "Instruction flow override read-back mismatch"
        return None

    return _run_mutation_transaction(
        ctx, operation, "Set instruction flow override", requested, old,
        lambda: instruction.setFlowOverride(allowed[flow_override]),
        lambda: _instruction_flow_state(ctx, instruction), validate,
        validate_rollback=lambda state: (
            None if state == old else "Instruction flow rollback mismatch"))


__all__ = [
    "_rename_func_state",
    "_rename_func_result",
    "set_function_name",
    "_compact_rename_item",
    "_batch_rename_result",
    "_batch_rename_item",
    "set_function_names",
    "_function_state",
    "_function_conflict_state",
    "_function_conflicts",
    "_normalize_function_body_ranges",
    "_function_mutation_result",
    "delete_function",
    "set_function_body",
    "create_function",
    "create_functions",
    "_require_resolved_prototype_type",
    "_parse_function_signature",
    "_prototype_parameter_conflict",
    "_prototype_variable_conflict",
    "_function_signature_matches",
    "_apply_function_signature",
    "set_function_prototype",
    "set_function_calling_convention",
    "set_function_noreturn",
    "set_instruction_flow_override",
]
