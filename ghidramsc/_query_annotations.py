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

"""Private annotations implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from .bridge import ProgramContext

from ._query_core import (
    _addr_int,
    _batch_mutation_result,
    _get_monitor,
    _mutation_no_change,
    _mutation_contract_result,
    _mutation_validation_failure,
    _qualified_program_name,
    _read_memory_buffer,
    _resolve_type,
    _run_mutation_transaction,
)

from ._query_functions import (
    set_function_name,
)

from ._query_variables import (
    _effective_parameter_contract,
    _find_variable_by_storage,
    _function_contract_state,
    _return_type_parameter_preflight,
)


_MAX_DISASSEMBLY_BYTES = 4096
_MAX_DISASSEMBLY_DETAILS = 64


def _code_state(ctx: ProgramContext, start, end) -> Dict[str, Any]:
    """Return bounded listing state and exact coverage for a flow disassembly."""
    from ghidra.program.model.address import AddressSet  # type: ignore

    address_set = AddressSet(start, end)
    listing = ctx.program.getListing()
    code_units = []
    code_unit_count = 0
    iterator = listing.getCodeUnits(address_set, True)
    while iterator.hasNext():
        code_unit = iterator.next()
        code_unit_count += 1
        if len(code_units) >= _MAX_DISASSEMBLY_DETAILS:
            continue
        code_units.append({
            "address": str(code_unit.getAddress()),
            "length": code_unit.getLength(),
            "kind": (
                "instruction"
                if listing.getInstructionAt(code_unit.getAddress()) is not None
                else "data"
            ),
            "text": str(code_unit)[:120],
        })

    functions = []
    function_count = 0
    iterator = ctx.program.getFunctionManager().getFunctions(
        address_set, True
    )
    while iterator.hasNext():
        function = iterator.next()
        function_count += 1
        if len(functions) >= _MAX_DISASSEMBLY_DETAILS:
            continue
        functions.append({
            "entry": str(function.getEntryPoint()),
            "name": str(function.getName()),
            "body_min": str(function.getBody().getMinAddress()),
            "body_max": str(function.getBody().getMaxAddress()),
        })
    coverage = []
    counts = {"instruction": 0, "undefined": 0,
              "defined_data": 0, "unmapped": 0}
    length = int(end.subtract(start)) + 1
    for offset in range(length):
        address = start.add(offset)
        unit = listing.getCodeUnitContaining(address)
        if unit is None:
            kind = "unmapped"
        elif listing.getInstructionContaining(address) is not None:
            kind = "instruction"
        elif unit.isDefined():
            kind = "defined_data"
        else:
            kind = "undefined"
        counts[kind] += 1
        if coverage and coverage[-1]["kind"] == kind:
            coverage[-1]["end"] = str(address)
            coverage[-1]["length"] += 1
        else:
            coverage.append({"start": str(address), "end": str(address),
                             "length": 1, "kind": kind})
    return {
        "start": str(start),
        "end": str(end),
        "start_is_instruction": listing.getInstructionAt(start) is not None,
        "code_units": code_units,
        "code_unit_count": code_unit_count,
        "code_units_truncated": code_unit_count > len(code_units),
        "functions": functions,
        "function_count": function_count,
        "functions_truncated": function_count > len(functions),
        "coverage": {
            "total_bytes": length,
            "instruction_bytes": counts["instruction"],
            "undefined_bytes": counts["undefined"],
            "defined_data_bytes": counts["defined_data"],
            "unmapped_bytes": counts["unmapped"],
            "complete": counts["instruction"] == length,
            "status": "complete" if counts["instruction"] == length else "partial",
            "ranges": coverage[:_MAX_DISASSEMBLY_DETAILS],
            "range_count": len(coverage),
            "ranges_truncated": len(coverage) > _MAX_DISASSEMBLY_DETAILS,
        },
    }


def disassemble_memory(ctx: ProgramContext, addr_hex: str,
                   end_hex: str = "") -> Dict[str, Any]:
    """Follow flow from one seed within an inclusive range; report coverage."""
    from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore
    from ghidra.program.model.address import AddressSet  # type: ignore

    start = ctx.to_addr(_addr_int(addr_hex))
    end = ctx.to_addr(_addr_int(end_hex)) if end_hex else start
    requested = {"start": str(start), "end": str(end)}
    if end.compareTo(start) < 0:
        return _mutation_validation_failure(
            "disassemble_memory", requested, "End address precedes start address"
        )
    if (not start.getAddressSpace().equals(end.getAddressSpace())
            or int(end.subtract(start)) + 1 > _MAX_DISASSEMBLY_BYTES):
        return _mutation_validation_failure(
            "disassemble_memory", requested,
            "Range must be within one address space and at most {} bytes".format(
                _MAX_DISASSEMBLY_BYTES))
    old = _code_state(ctx, start, end)
    listing = ctx.program.getListing()
    start_unit = listing.getCodeUnitContaining(start)
    if start_unit is not None and start_unit.getMinAddress().compareTo(start) != 0:
        return _mutation_validation_failure(
            "disassemble_memory", requested,
            "Start is inside an existing code unit; use its start address or clear code units explicitly")
    if old["start_is_instruction"]:
        return _mutation_no_change("disassemble_memory", requested, old)
    if start_unit is not None and start_unit.isDefined():
        return _mutation_validation_failure(
            "disassemble_memory", requested,
            "Start contains defined data; clear code units explicitly before disassembly")

    newly_disassembled = {}

    def apply() -> None:
        command = DisassembleCommand(start, AddressSet(start, end), True)
        if not command.applyTo(ctx.program, _get_monitor()):
            suffix = command.getStatusMsg()
            raise ValueError(
                "Disassemble failed at {}{}".format(
                    addr_hex, "" if not suffix else ": " + str(suffix)
                )
            )
        address_set = command.getDisassembledAddressSet()
        ranges = []
        iterator = address_set.getAddressRanges(True)
        range_count = 0
        while iterator.hasNext():
            span = iterator.next()
            range_count += 1
            if len(ranges) < _MAX_DISASSEMBLY_DETAILS:
                ranges.append({"start": str(span.getMinAddress()),
                               "end": str(span.getMaxAddress())})
        newly_disassembled.update({
            "address_count": int(address_set.getNumAddresses()),
            "ranges": ranges,
            "range_count": range_count,
            "ranges_truncated": range_count > len(ranges),
        })

    def read_stored():
        state = _code_state(ctx, start, end)
        state["newly_disassembled"] = newly_disassembled.copy()
        return state

    return _run_mutation_transaction(
        ctx,
        "disassemble_memory",
        "Disassemble",
        requested,
        old,
        apply,
        read_stored,
        lambda stored: (
            None if (stored["start_is_instruction"]
                     and stored["newly_disassembled"]["address_count"] > 0)
            else "Disassembly read-back found no newly decoded instruction at " + addr_hex
        ),
        rollback_read_back=lambda: _code_state(ctx, start, end),
    )


_MAX_CLEAR_CODE_UNIT_BYTES = 4096
_MAX_CLEAR_DEFINED_UNITS = 128
_MAX_CLEAR_DISPLAY_CHARS = 120


def _clear_code_units_state(ctx: ProgramContext, start, end, length: int) -> Dict[str, Any]:
    """Describe every defined unit a native clear would affect."""
    from ghidra.program.model.address import AddressSet  # type: ignore

    listing = ctx.program.getListing()
    affected_units = []
    seen = set()

    def append(unit) -> None:
        if unit is None:
            return
        address = unit.getMinAddress()
        key = str(address)
        if key in seen:
            return
        seen.add(key)
        instruction = listing.getInstructionAt(address) is not None
        if not instruction and not unit.isDefined():
            return
        if len(affected_units) >= _MAX_CLEAR_DEFINED_UNITS:
            raise ValueError(
                "Range affects more than {} defined code units".format(
                    _MAX_CLEAR_DEFINED_UNITS
                )
            )
        affected_units.append({
            "address": key,
            "end": str(unit.getMaxAddress()),
            "length": int(unit.getLength()),
            "kind": "instruction" if instruction else "data",
            "display": str(unit)[:_MAX_CLEAR_DISPLAY_CHARS],
        })

    # Ghidra's range iterator may omit a unit that begins before start.
    append(listing.getCodeUnitContaining(start))
    iterator = listing.getCodeUnits(AddressSet(start, end), True)
    while iterator.hasNext():
        append(iterator.next())
    return {
        "start": str(start),
        "end": str(end),
        "length": length,
        "affected_units": affected_units,
        "affected_count": len(affected_units),
        "all_undefined": bool(listing.isUndefined(start, end)),
    }


def clear_code_units(ctx: ProgramContext, start_hex: str, end_hex: str,
                     preview_only: bool = True) -> Dict[str, Any]:
    """Preview or clear an exact initialized listing range, preserving bytes."""
    requested = {
        "start": start_hex,
        "end": end_hex,
        "preview_only": preview_only,
    }
    try:
        start = ctx.to_addr(_addr_int(start_hex))
        end = ctx.to_addr(_addr_int(end_hex))
        requested["start"] = str(start)
        requested["end"] = str(end)
        if start.getAddressSpace() != end.getAddressSpace():
            raise ValueError("Start and end must be in the same address space")
        if end.compareTo(start) < 0:
            raise ValueError("End address precedes start address")
        length = int(end.subtract(start)) + 1
        if length > _MAX_CLEAR_CODE_UNIT_BYTES:
            raise ValueError(
                "Range exceeds {} bytes".format(_MAX_CLEAR_CODE_UNIT_BYTES)
            )
        block = ctx.program.getMemory().getBlock(start)
        if block is None or not block.contains(end) or not block.isInitialized():
            raise ValueError("Range must stay within one initialized memory block")
        listing = ctx.program.getListing()
        first = listing.getCodeUnitContaining(start)
        last = listing.getCodeUnitContaining(end)
        if first is None or last is None:
            raise ValueError("Range has no listing units at both endpoints")
        first_is_instruction = listing.getInstructionAt(first.getMinAddress()) is not None
        last_is_instruction = listing.getInstructionAt(last.getMinAddress()) is not None
        if first_is_instruction or first.isDefined():
            if first.getMinAddress() != start:
                raise ValueError("Start lies inside a defined code unit")
        if last_is_instruction or last.isDefined():
            if last.getMaxAddress() != end:
                raise ValueError("End lies inside a defined code unit")
        old = _clear_code_units_state(ctx, start, end, length)
        original_bytes, actual = _read_memory_buffer(ctx.program, start, length)
        if actual != length:
            raise ValueError("Cannot read the complete target byte range")
    except Exception as exc:
        return _mutation_validation_failure(
            "clear_code_units", requested, str(exc) or type(exc).__name__
        )

    if preview_only:
        result = _mutation_contract_result(
            "clear_code_units", "preview", requested, old=old
        )
        result["preview"] = old
        return result
    if old["all_undefined"]:
        return _mutation_no_change("clear_code_units", requested, old)

    def read_back() -> Dict[str, Any]:
        stored = _clear_code_units_state(ctx, start, end, length)
        current_bytes, actual = _read_memory_buffer(ctx.program, start, length)
        stored["bytes_preserved"] = actual == length and current_bytes == original_bytes
        stored["byte_count"] = length
        return stored

    def validate_stored(stored: Dict[str, Any]) -> Optional[str]:
        if not stored["all_undefined"] or stored["affected_count"] != 0:
            return "Clear read-back found defined code units in the target range"
        if not stored["bytes_preserved"]:
            return "Clear read-back found changed target bytes"
        return None

    def validate_rollback(stored: Dict[str, Any]) -> Optional[str]:
        if not stored["bytes_preserved"]:
            return "Target bytes changed after rollback"
        for key in ("affected_units", "affected_count", "all_undefined"):
            if stored[key] != old[key]:
                return "Listing state changed after rollback"
        return None

    return _run_mutation_transaction(
        ctx,
        "clear_code_units",
        "Clear code units",
        requested,
        old,
        lambda: ctx.program.getListing().clearCodeUnits(
            start, end, False, _get_monitor()
        ),
        read_back,
        validate_stored,
        validate_rollback=validate_rollback,
    )


def export_annotations(ctx: ProgramContext) -> Dict[str, Any]:
    """Export all user-defined symbols, comments, and function signatures."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    data: Dict[str, Any] = {
        "binary": _qualified_program_name(ctx.program),
        "image_base": str(ctx.program.getImageBase()),
        "symbols": [],
        "comments": [],
        "function_signatures": [],
    }

    st = ctx.program.getSymbolTable()
    for sym in st.getAllSymbols(True):
        if sym.getSource() != SourceType.USER_DEFINED:
            continue
        data["symbols"].append({
            "addr": str(sym.getAddress()),
            "name": sym.getName(),
            "namespace": str(sym.getParentNamespace()),
            "type": str(sym.getSymbolType()),
            "primary": bool(sym.isPrimary()),
        })

    prog_listing = ctx.program.getListing()
    comment_types = {0: "plate", 1: "pre", 2: "post", 3: "eol", 4: "repeatable"}
    cu_iter = prog_listing.getCodeUnits(True)
    while cu_iter.hasNext():
        cu = cu_iter.next()
        for ct_id, ct_name in comment_types.items():
            cmt = cu.getComment(ct_id)
            if cmt is not None and len(cmt.strip()) > 0:
                data["comments"].append({
                    "addr": str(cu.getAddress()),
                    "type": ct_name,
                    "text": cmt,
                })

    fm = ctx.program.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getSymbol().getSource() != SourceType.USER_DEFINED:
            continue
        params = []
        for p in func.getParameters():
            params.append({
                "name": p.getName(),
                "type": str(p.getDataType()),
                "ordinal": p.getOrdinal(),
            })
        data["function_signatures"].append({
            "addr": str(func.getEntryPoint()),
            "name": func.getName(),
            "signature": str(func.getSignature()),
            "return_type": str(func.getReturnType()),
            "calling_convention": str(func.getCallingConventionName()),
            "params": params,
        })

    return data


def _validate_annotation_import(data: Any) -> None:
    if not isinstance(data, dict):
        raise ValueError("import_annotations JSON input must contain an object")
    required = {
        "function_signatures": ("addr", "name"),
        "symbols": ("addr", "name"),
        "comments": ("addr", "type", "text"),
    }
    for key, fields in required.items():
        if key not in data:
            continue
        if not isinstance(data[key], list):
            raise ValueError("Invalid JSON array field: " + key)
        for entry in data[key]:
            if not isinstance(entry, dict):
                raise ValueError(key + " entries must be objects")
            for field in fields:
                if not isinstance(entry.get(field), str):
                    raise ValueError(
                        "Missing or invalid JSON string argument: " + field
                    )


def _symbol_state(ctx: ProgramContext, address) -> Dict[str, Any]:
    table = ctx.program.getSymbolTable()
    primary = table.getPrimarySymbol(address)
    labels = []
    for symbol in table.getSymbols(address):
        labels.append({
            "name": str(symbol.getName()),
            "type": str(symbol.getSymbolType()),
            "primary": (
                primary is not None
                and int(primary.getID()) == int(symbol.getID())
            ),
        })
    return {"address": str(address), "labels": labels}


def _address_label_state(ctx: ProgramContext, address) -> Dict[str, Any]:
    """Read the exact primary symbol and all symbols at one memory address."""
    table = ctx.program.getSymbolTable()
    primary = table.getPrimarySymbol(address)

    def describe(symbol):
        if symbol is None:
            return None
        return {"id": int(symbol.getID()), "name": str(symbol.getName()),
                "type": str(symbol.getSymbolType()),
                "namespace": str(symbol.getParentNamespace()),
                "source": str(symbol.getSource()),
                "address": str(symbol.getAddress())}

    return {"address": str(address), "primary": describe(primary),
            "symbols": [describe(symbol) for symbol in table.getSymbols(address)]}


def set_address_label(ctx: ProgramContext, addr_hex: str,
                      new_name: str) -> Dict[str, Any]:
    """Set the primary label at one mapped address without changing code/data."""
    from ghidra.program.model.symbol import (  # type: ignore
        SourceType, SymbolType, SymbolUtilities,
    )

    operation = "set_address_label"
    requested = {"address": addr_hex, "primary_label": new_name}

    def fail(message):
        return _mutation_validation_failure(operation, requested, message)

    if not isinstance(addr_hex, str) or not isinstance(new_name, str):
        return fail("Address and label name must be strings")
    try:
        address = ctx.to_addr(_addr_int(addr_hex))
        SymbolUtilities.validateName(new_name)
    except Exception as exc:
        return fail("Invalid address or label name: " + str(exc))
    if (not address.isMemoryAddress() or
            not ctx.program.getMemory().contains(address)):
        return fail("Address must be mapped program memory")

    table = ctx.program.getSymbolTable()
    primary = table.getPrimarySymbol(address)
    if primary is not None and primary.getSymbolType() == SymbolType.FUNCTION:
        return fail("Address is a function entry; use set_function_name")
    namespace = (primary.getParentNamespace() if primary is not None
                 else ctx.program.getGlobalNamespace())
    old = _address_label_state(ctx, address)
    if old["primary"] is not None and old["primary"]["name"] == new_name:
        return _mutation_no_change(operation, requested, old)

    collision = table.getNamespaceSymbol(new_name, namespace)
    if collision is None:
        collision = table.getClassSymbol(new_name, namespace)
    global_namespace = ctx.program.getGlobalNamespace()
    if (collision is None and namespace.equals(global_namespace)):
        collision = table.getLibrarySymbol(new_name)
    if collision is not None:
        return fail("Requested label conflicts with an existing namespace, class, or library")

    def apply() -> None:
        requested_symbol = table.getSymbol(new_name, address, namespace)
        if requested_symbol is not None:
            if not requested_symbol.isPrimary() and not requested_symbol.setPrimary():
                raise ValueError("Could not promote requested label")
            if requested_symbol.getSource() != SourceType.USER_DEFINED:
                requested_symbol.setName(new_name, SourceType.USER_DEFINED)
        elif primary is not None:
            primary.setName(new_name, SourceType.USER_DEFINED)
        else:
            created = table.createLabel(
                address, new_name, namespace, SourceType.USER_DEFINED)
            if not created.isPrimary() and not created.setPrimary():
                raise ValueError("Could not make new label primary")

    def validate(stored: Dict[str, Any]) -> Optional[str]:
        current = stored["primary"]
        if (current is None or current["address"] != str(address) or
                current["name"] != new_name or
                current["namespace"] != str(namespace) or
                current["source"] != str(SourceType.USER_DEFINED) or
                current["type"] != str(SymbolType.LABEL)):
            return "Primary address-label read-back mismatch"
        return None

    return _run_mutation_transaction(
        ctx, operation, "Set address label", requested, old, apply,
        lambda: _address_label_state(ctx, address), validate,
        validate_rollback=lambda state: (
            None if state == old else "Address-label rollback mismatch"))


def _import_symbol(ctx: ProgramContext, addr_hex: str,
                   name: str) -> Dict[str, Any]:
    from ghidra.program.model.symbol import SourceType  # type: ignore

    requested = {"address": addr_hex, "name": name}
    try:
        address = ctx.to_addr(_addr_int(addr_hex))
    except Exception as exc:
        return _mutation_validation_failure(
            "import_symbol", requested, str(exc) or type(exc).__name__
        )
    old = _symbol_state(ctx, address)
    if any(label["name"] == name for label in old["labels"]):
        return _mutation_no_change("import_symbol", requested, old)

    def validate(stored: Any) -> Optional[str]:
        if any(label["name"] == name for label in stored["labels"]):
            return None
        return "Symbol read-back mismatch at " + addr_hex

    return _run_mutation_transaction(
        ctx,
        "import_symbol",
        "Import symbol",
        requested,
        old,
        lambda: ctx.program.getSymbolTable().createLabel(
            address, name, SourceType.USER_DEFINED
        ),
        lambda: _symbol_state(ctx, address),
        validate,
    )


def _annotation_import_item(kind: str, source: Dict[str, Any],
                            action: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    try:
        item = action()
    except Exception as exc:
        item = _mutation_validation_failure(
            "import_" + kind,
            source,
            str(exc) or type(exc).__name__,
        )
    item["import_kind"] = kind
    item["source"] = dict(source)
    return item


def import_annotations(ctx: ProgramContext,
                       json_path: str) -> Dict[str, Any]:
    """Import annotations with an independent transaction per item."""
    with open(json_path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("import_annotations JSON input must contain an object")
    try:
        _validate_annotation_import(data)
    except Exception as exc:
        return _mutation_validation_failure(
            "import_annotations",
            {"json_data": data},
            str(exc) or type(exc).__name__,
        )

    items = []
    for signature in data.get("function_signatures", []):
        items.append(_annotation_import_item(
            "function_signature",
            signature,
            lambda signature=signature: set_function_name(
                ctx, signature["addr"], signature["name"]
            ),
        ))
    for symbol in data.get("symbols", []):
        items.append(_annotation_import_item(
            "symbol",
            symbol,
            lambda symbol=symbol: _import_symbol(
                ctx, symbol["addr"], symbol["name"]
            ),
        ))
    for comment in data.get("comments", []):
        items.append(_annotation_import_item(
            "comment",
            comment,
            lambda comment=comment: set_comment_at_address(
                ctx,
                comment["addr"],
                comment["text"],
                comment["type"],
            ),
        ))
    return _batch_mutation_result("import_annotations", data, items)


def fix_region(ctx: ProgramContext, start_hex: str,
               end_hex: str) -> Dict[str, Any]:
    """Disassemble a range and create referenced function entries atomically."""
    from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore
    from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore
    from ghidra.program.model.address import AddressSet  # type: ignore

    start = ctx.to_addr(_addr_int(start_hex))
    end = ctx.to_addr(_addr_int(end_hex))
    requested = {"start": str(start), "end": str(end)}
    if end.compareTo(start) < 0:
        return _mutation_validation_failure(
            "fix_region", requested, "End address precedes start address"
        )
    old = _code_state(ctx, start, end)
    address_set = AddressSet(start, end)

    def apply() -> None:
        disassemble = DisassembleCommand(start, address_set, True)
        if not disassemble.applyTo(ctx.program, _get_monitor()):
            suffix = disassemble.getStatusMsg()
            raise ValueError(
                "Disassembly failed{}".format(
                    "" if not suffix else ": " + str(suffix)
                )
            )
        iterator = ctx.program.getListing().getInstructions(
            address_set, True
        )
        while iterator.hasNext():
            instruction_address = iterator.next().getAddress()
            if (ctx.program.getFunctionManager()
                    .getFunctionAt(instruction_address) is not None):
                continue
            references = ctx.program.getReferenceManager().getReferencesTo(
                instruction_address
            )
            if not references.hasNext():
                continue
            create = CreateFunctionCmd(instruction_address)
            if not create.applyTo(ctx.program, _get_monitor()):
                suffix = create.getStatusMsg()
                raise ValueError(
                    "Failed to create inferred function at {}{}".format(
                        instruction_address,
                        "" if not suffix else ": " + str(suffix),
                    )
                )

    return _run_mutation_transaction(
        ctx,
        "fix_region",
        "Fix region",
        requested,
        old,
        apply,
        lambda: _code_state(ctx, start, end),
        lambda stored: (
            None
            if stored["start_is_instruction"]
            else "Fixed-region read-back found no instruction at " + start_hex
        ),
    )


def _preflight_annotation(ctx: ProgramContext, func, data: Dict[str, Any]):
    requested: Dict[str, Any] = {}
    return_type = None

    if "calling_convention" in data:
        convention = data["calling_convention"]
        if not isinstance(convention, str):
            raise ValueError(
                "Missing or invalid JSON string argument: calling_convention"
            )
        if (
            convention != str(func.getCallingConventionName())
            and convention != "default"
            and ctx.program.getFunctionManager().getCallingConvention(
                convention
            ) is None
        ):
            raise ValueError("Unknown calling convention: " + convention)
        requested["calling_convention"] = convention

    if "return_type" in data:
        type_name = data["return_type"]
        if not isinstance(type_name, str):
            raise ValueError(
                "Missing or invalid JSON string argument: return_type"
            )
        return_type = _resolve_type(ctx.program, type_name)
        if return_type is None:
            raise ValueError("Unknown return type: " + type_name)
        requested["return_type"] = str(return_type)

    variables_by_name: Dict[str, List[Any]] = {}
    parameter_kinds = {}
    for parameter in func.getParameters():
        variables_by_name.setdefault(str(parameter.getName()), []).append(
            parameter
        )
        parameter_kinds[id(parameter)] = True
    for local in func.getLocalVariables():
        variables_by_name.setdefault(str(local.getName()), []).append(local)
        parameter_kinds[id(local)] = False

    specs = data.get("vars", [])
    if not isinstance(specs, list):
        raise ValueError("Invalid JSON array field: vars")
    changes = []
    normalized_vars = []
    seen_old_names = set()
    requested_names = set()
    for spec in specs:
        if not isinstance(spec, dict):
            raise ValueError("apply_function_annotations vars entries must be objects")
        old_name = spec.get("old_name")
        if not isinstance(old_name, str):
            raise ValueError(
                "Missing or invalid JSON string argument: old_name"
            )
        if old_name in seen_old_names:
            raise ValueError("Duplicate variable request: " + old_name)
        seen_old_names.add(old_name)
        matches = variables_by_name.get(old_name, [])
        if not matches:
            raise ValueError(
                "Variable '{}' not found in {}".format(
                    old_name, func.getName()
                )
            )
        if len(matches) != 1:
            raise ValueError(
                "Variable '{}' is ambiguous in {}".format(
                    old_name, func.getName()
                )
            )
        variable = matches[0]
        new_name = old_name
        if "new_name" in spec:
            value = spec["new_name"]
            if not isinstance(value, str):
                raise ValueError(
                    "Missing or invalid JSON string argument: new_name"
                )
            if value:
                new_name = value
        if new_name in requested_names:
            raise ValueError(
                "Multiple variables request the name '{}'".format(new_name)
            )
        requested_names.add(new_name)
        if new_name != old_name and new_name in variables_by_name:
            raise ValueError(
                "Requested name '{}' conflicts with an existing variable"
                .format(new_name)
            )

        data_type = None
        if "type" in spec:
            type_name = spec["type"]
            if not isinstance(type_name, str):
                raise ValueError(
                    "Missing or invalid JSON string argument: type"
                )
            if type_name:
                data_type = _resolve_type(ctx.program, type_name)
                if data_type is None:
                    raise ValueError(
                        "Unknown variable type '{}' for {}".format(
                            type_name, old_name
                        )
                    )
        parameter = parameter_kinds[id(variable)]
        storage = str(variable.getVariableStorage())
        changes.append({
            "variable": variable,
            "old_name": old_name,
            "new_name": new_name,
            "storage": storage,
            "parameter": parameter,
            "data_type": data_type,
        })
        normalized = {
            "old_name": old_name,
            "new_name": new_name,
            "storage": storage,
            "kind": "parameter" if parameter else "local",
        }
        if data_type is not None:
            normalized["type"] = str(data_type)
        normalized_vars.append(normalized)
    requested["vars"] = normalized_vars
    return requested, changes, return_type


def _annotation_would_change(func, requested: Dict[str, Any], changes,
                             return_type) -> bool:
    if (
        "calling_convention" in requested
        and requested["calling_convention"]
        != str(func.getCallingConventionName())
    ):
        return True
    if (
        "return_type" in requested
        and not func.getReturnType().isEquivalent(return_type)
    ):
        return True
    for change in changes:
        if change["old_name"] != change["new_name"]:
            return True
        if (
            change["data_type"] is not None
            and not change["variable"].getDataType().isEquivalent(
                change["data_type"]
            )
        ):
            return True
    return False


def _verify_annotation(func, requested: Dict[str, Any], changes,
                       return_type) -> Optional[str]:
    if "calling_convention" in requested:
        stored = str(func.getCallingConventionName())
        if requested["calling_convention"] != stored:
            return (
                "Calling convention read-back mismatch: requested {}, "
                "stored {}".format(requested["calling_convention"], stored)
            )
    if (
        "return_type" in requested
        and not func.getReturnType().isEquivalent(return_type)
    ):
        return "Return type read-back mismatch: requested {}, stored {}".format(
            requested["return_type"], func.getReturnType()
        )
    for change in changes:
        variable = _find_variable_by_storage(
            func, change["storage"], change["parameter"]
        )
        if variable is None:
            return "Variable read-back failed for storage " + change["storage"]
        if change["new_name"] != str(variable.getName()):
            return (
                "Variable name read-back mismatch at {}: requested {}, "
                "stored {}".format(
                    change["storage"],
                    change["new_name"],
                    variable.getName(),
                )
            )
        if (
            change["data_type"] is not None
            and not variable.getDataType().isEquivalent(change["data_type"])
        ):
            return (
                "Variable type read-back mismatch at {}: requested {}, "
                "stored {}".format(
                    change["storage"],
                    change["data_type"],
                    variable.getDataType(),
                )
            )
    return None


def apply_function_annotations(ctx: ProgramContext, addr_hex: str,
                  json_path: str) -> Dict[str, Any]:
    """Apply a function annotation as one preflighted atomic change."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    with open(json_path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("apply_function_annotations JSON input must contain an object")

    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return _mutation_validation_failure(
            "apply_function_annotations", data, "No function at " + addr_hex
        )
    try:
        old = _function_contract_state(ctx, addr_hex)
        requested, changes, return_type = _preflight_annotation(
            ctx, func, data
        )
    except Exception as exc:
        return _mutation_validation_failure(
            "apply_function_annotations", data, str(exc) or type(exc).__name__
        )
    if not _annotation_would_change(
        func, requested, changes, return_type
    ):
        return _mutation_no_change("apply_function_annotations", requested, old)
    return_type_changes = (
        "return_type" in requested
        and not func.getReturnType().isEquivalent(return_type)
    )
    old_parameters: List[Dict[str, Any]] = []
    if return_type_changes:
        old_parameters, parameter_error = _return_type_parameter_preflight(
            ctx, addr_hex
        )
        if parameter_error:
            return _mutation_validation_failure(
                "apply_function_annotations", requested, parameter_error
            )

    def apply() -> None:
        if "calling_convention" in requested:
            func.setCallingConvention(requested["calling_convention"])
        if return_type_changes:
            func.setReturnType(return_type, SourceType.USER_DEFINED)
        for change in changes:
            variable = change["variable"]
            if change["old_name"] != change["new_name"]:
                variable.setName(
                    change["new_name"], SourceType.USER_DEFINED
                )
            if (
                change["data_type"] is not None
                and not variable.getDataType().isEquivalent(
                    change["data_type"]
                )
            ):
                variable.setDataType(
                    change["data_type"], SourceType.USER_DEFINED
                )

    def validate(stored: Any) -> Optional[str]:
        mismatch = _verify_annotation(
            func, requested, changes, return_type
        )
        if mismatch:
            return mismatch
        if (
            return_type_changes
            and _effective_parameter_contract(ctx, addr_hex) != old_parameters
        ):
            return "Effective parameter list changed during return-type mutation"
        return None

    def validate_rollback(stored: Any) -> Optional[str]:
        if stored != old:
            return "Function state differs from pre-state"
        if (
            return_type_changes
            and _effective_parameter_contract(ctx, addr_hex) != old_parameters
        ):
            return "Effective parameter list differs from pre-state"
        return None

    return _run_mutation_transaction(
        ctx,
        "apply_function_annotations",
        "Annotate function",
        requested,
        old,
        apply,
        lambda: _function_contract_state(ctx, addr_hex),
        validate,
        validate_rollback=validate_rollback,
    )


_COMMENT_TYPES = {
    "plate": 3,
    "pre": 1,
    "post": 2,
    "eol": 0,
    "repeatable": 4,
}


def _comment_state(ctx: ProgramContext, addr_hex: str,
                   comment_type: str) -> str:
    value = get_comment_at_address(ctx, addr_hex, comment_type)
    if isinstance(value, dict):
        return value["comment"]
    if value.startswith("ERROR:"):
        raise ValueError("get_comment_at_address read-back failed: " + value)
    return value


def set_comment_at_address(ctx: ProgramContext, addr_hex: str, comment: str,
                comment_type: str = "eol",
                allow_containing_item: bool = False) -> Dict[str, Any]:
    """Set a comment at the given address.  comment_type is one of:
    plate, pre, post, eol (default), repeatable."""
    requested = {
        "address": addr_hex,
        "comment_type": comment_type,
        "comment": comment,
        "allow_containing_item": allow_containing_item,
    }
    if not isinstance(allow_containing_item, bool):
        return _mutation_validation_failure(
            "set_comment_at_address", requested,
            "allow_containing_item must be a boolean",
        )
    ct_id = _COMMENT_TYPES.get(comment_type.lower())
    if ct_id is None:
        return _mutation_validation_failure(
            "set_comment_at_address", requested,
            "Unknown comment type '{}'".format(comment_type),
        )

    addr = ctx.to_addr(_addr_int(addr_hex))
    prog_listing = ctx.program.getListing()
    cu = prog_listing.getCodeUnitAt(addr)
    exact = cu is not None
    if not exact:
        cu = prog_listing.getCodeUnitContaining(addr)
    if cu is None:
        return _mutation_validation_failure(
            "set_comment_at_address", requested,
            "No code unit at {}".format(addr_hex),
        )

    effective = addr if exact else cu.getAddress()
    target = {
        "requested_address": str(addr),
        "containing_address": str(effective),
        "containing_end": str(cu.getMaxAddress()),
        "effective_address": str(effective),
        "byte_offset": 0 if exact else int(addr.subtract(effective)),
    }
    if not exact and not allow_containing_item:
        result = _mutation_validation_failure(
            "set_comment_at_address", requested,
            "Interior address shares the containing code-unit comment; "
            "set allow_containing_item=true to change that comment",
        )
        result.update(target)
        return result

    old = _comment_state(ctx, addr_hex, comment_type)
    if old == comment:
        result = _mutation_no_change("set_comment_at_address", requested, old)
        result.update(target)
        return result
    result = _run_mutation_transaction(
        ctx,
        "set_comment_at_address",
        "Set comment",
        requested,
        old,
        lambda: cu.setComment(ct_id, comment),
        lambda: _comment_state(ctx, addr_hex, comment_type),
        lambda stored: (
            None if stored == comment else "Comment read-back mismatch"
        ),
    )
    result.update(target)
    return result


def get_comment_at_address(ctx: ProgramContext, addr_hex: str,
                comment_type: str = "eol") -> Any:
    """Get the comment at the given address.  comment_type is one of:
    plate, pre, post, eol (default), repeatable."""
    ct_id = _COMMENT_TYPES.get(comment_type.lower())
    if ct_id is None:
        return "ERROR: Unknown comment type '{}'. Use one of: {}".format(
            comment_type, ", ".join(sorted(_COMMENT_TYPES.keys())))

    addr = ctx.to_addr(_addr_int(addr_hex))
    prog_listing = ctx.program.getListing()
    cu = prog_listing.getCodeUnitAt(addr)
    exact = cu is not None
    if not exact:
        cu = prog_listing.getCodeUnitContaining(addr)
    if cu is None:
        return "ERROR: No code unit at {}".format(addr_hex)

    cmt = cu.getComment(ct_id) or ""
    if exact:
        return cmt
    effective = cu.getAddress()
    return {
        "requested_address": str(addr),
        "containing_address": str(effective),
        "containing_end": str(cu.getMaxAddress()),
        "effective_address": str(effective),
        "byte_offset": int(addr.subtract(effective)),
        "comment_type": comment_type,
        "comment": cmt,
        "distinct_interior_comment_storage": False,
    }


def _bookmark_state(ctx: ProgramContext, addr, category: str) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "address": str(addr),
        "category": category,
        "type": "Note",
        "present": False,
    }
    for bookmark in ctx.program.getBookmarkManager().getBookmarks(addr):
        if (
            str(bookmark.getCategory()) == category
            and str(bookmark.getTypeString()) == "Note"
        ):
            state["present"] = True
            comment = bookmark.getComment()
            state["comment"] = "" if comment is None else str(comment)
            break
    return state


def create_bookmark(ctx: ProgramContext, addr_hex: str, category: str,
                 comment: str = "") -> Dict[str, Any]:
    """Add a bookmark at the given address."""
    addr = ctx.to_addr(_addr_int(addr_hex))
    bm = ctx.program.getBookmarkManager()
    requested = {
        "address": addr_hex,
        "category": category,
        "comment": comment,
    }
    old = _bookmark_state(ctx, addr, category)
    if old["present"] and old["comment"] == comment:
        return _mutation_no_change("create_bookmark", requested, old)
    return _run_mutation_transaction(
        ctx,
        "create_bookmark",
        "Set bookmark",
        requested,
        old,
        lambda: bm.setBookmark(addr, "Note", category, comment),
        lambda: _bookmark_state(ctx, addr, category),
        lambda stored: (
            None if stored["present"] and stored["comment"] == comment
            else "Bookmark read-back mismatch"
        ),
    )


def delete_bookmark(ctx: ProgramContext, addr_hex: str,
                    category: str) -> Dict[str, Any]:
    """Remove a bookmark at the given address and category."""
    addr = ctx.to_addr(_addr_int(addr_hex))
    bm = ctx.program.getBookmarkManager()
    requested = {
        "address": addr_hex,
        "category": category,
        "present": False,
    }
    old = _bookmark_state(ctx, addr, category)
    if not old["present"]:
        return _mutation_validation_failure(
            "delete_bookmark",
            requested,
            "No bookmark at {} with category '{}'".format(
                addr_hex, category
            ),
        )

    def remove_matching() -> None:
        for bookmark in list(bm.getBookmarks(addr)):
            if (
                str(bookmark.getCategory()) == category
                and str(bookmark.getTypeString()) == "Note"
            ):
                bm.removeBookmark(bookmark)

    return _run_mutation_transaction(
        ctx,
        "delete_bookmark",
        "Remove bookmark",
        requested,
        old,
        remove_matching,
        lambda: _bookmark_state(ctx, addr, category),
        lambda stored: (
            None if not stored["present"] else "Bookmark remains after removal"
        ),
    )


def list_bookmarks(ctx: ProgramContext, addr_hex: str = "") -> str:
    """List bookmarks.  If addr_hex is given, list only bookmarks at that
    address; otherwise list all bookmarks."""
    bm = ctx.program.getBookmarkManager()
    lines = []
    if addr_hex:
        addr = ctx.to_addr(_addr_int(addr_hex))
        bookmarks = list(bm.getBookmarks(addr))
    else:
        bookmarks = []
        for b_type in ["Note", "Warning", "Error", "Info", "Analysis"]:
            iterator = bm.getBookmarksIterator(b_type)
            while iterator.hasNext():
                bookmarks.append(iterator.next())

    for b in bookmarks:
        lines.append("{}  [{}] {} -- {}".format(
            str(b.getAddress()), b.getCategory(), b.getTypeString(), b.getComment()))

    header = "BOOKMARKS in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), len(lines))
    return header + "\n".join(lines)


__all__ = [
    "_code_state",
    "disassemble_memory",
    "export_annotations",
    "_validate_annotation_import",
    "_symbol_state",
    "set_address_label",
    "_import_symbol",
    "_annotation_import_item",
    "import_annotations",
    "fix_region",
    "_preflight_annotation",
    "_annotation_would_change",
    "_verify_annotation",
    "apply_function_annotations",
    "_COMMENT_TYPES",
    "_comment_state",
    "set_comment_at_address",
    "get_comment_at_address",
    "_bookmark_state",
    "create_bookmark",
    "delete_bookmark",
    "list_bookmarks",
]
