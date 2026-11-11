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

"""Private inspection implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .bridge import ProgramContext

from ._query_core import (
    _addr_int,
    _get_decompiler,
    _get_monitor,
    _qualified_program_name,
    _read_memory_buffer,
)
from ._query_paging import page_items, validate_page


def list_functions(ctx: ProgramContext) -> str:
    """List all functions sorted by address."""
    fm = ctx.program.getFunctionManager()
    funcs = sorted(list(fm.getFunctions(True)), key=lambda f: f.getEntryPoint())
    lines = ["FUNCTIONS in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), len(funcs))]
    for f in funcs:
        thunk = " [thunk]" if f.isThunk() else ""
        lines.append("{}  {}{}".format(str(f.getEntryPoint()), f.getName(), thunk))
    return "\n".join(lines)


def read_memory_bytes(ctx: ProgramContext, addr_hex: str, length: int = 256) -> str:
    """Read raw bytes at an address.  Returns hex dump with ASCII sidebar."""
    length = max(1, min(length, 4096))
    addr = ctx.to_addr(_addr_int(addr_hex))
    buf = b""
    actual = 0
    try:
        buf, actual = _read_memory_buffer(ctx.program, addr, length)
    except Exception:
        pass
    if actual <= 0:
        return "ERROR: Cannot read memory at " + addr_hex

    lines = ["READ_BYTES at {} ({} bytes)\n".format(addr_hex, actual)]
    for off in range(0, actual, 16):
        chunk = buf[off:off + 16]
        hex_part = " ".join("{:02x}".format(b) for b in chunk)
        ascii_part = "".join(
            chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        line_addr = addr.add(off)
        lines.append("{}  {:48s}  {}".format(
            str(line_addr), hex_part, ascii_part))
    return "\n".join(lines)


def get_data_at_address(ctx: ProgramContext, addr_hex: str,
                        value_offset: int = 0,
                        value_limit: int = 2048) -> Any:
    """Get the defined data item at a specific address."""
    try:
        validate_page(value_offset, value_limit, label="value", maximum=8192)
    except ValueError as exc:
        return "ERROR: " + str(exc)
    addr = ctx.to_addr(_addr_int(addr_hex))
    listing = ctx.program.getListing()
    data = listing.getDefinedDataAt(addr)
    if data is None:
        data = listing.getDefinedDataContaining(addr)
    if data is None:
        return ("ERROR: No defined data at " + addr_hex
                + ". For initialized undefined bytes, use read_memory_bytes; "
                + "use list_references_to_address for incoming references. "
                + "A qualified space address uses space::hex_offset.")

    result = _defined_data_state(ctx, data, addr)
    value = result["value"]
    total = len(value)
    page = value[value_offset:value_offset + value_limit]
    next_offset = value_offset + len(page)
    has_more = next_offset < total
    result.update({
        "value": page,
        "value_offset": value_offset,
        "value_limit": value_limit,
        "value_returned_chars": len(page),
        "value_total_chars": total,
        "value_has_more": has_more,
        "value_truncated": value_offset > 0 or has_more,
        "value_next_offset": next_offset if has_more else None,
    })
    return result


def _data_symbol_state(symbol, primary: bool) -> Dict[str, Any]:
    return {
        "id": str(int(symbol.getID()) & ((1 << 64) - 1)),
        "name": str(symbol.getName()),
        "namespace": str(symbol.getParentNamespace()),
        "type": str(symbol.getSymbolType()),
        "source": str(symbol.getSource()),
        "primary": primary,
        "dynamic": bool(symbol.isDynamic()),
    }


def _defined_data_state(ctx: ProgramContext, data, requested_addr=None) -> Dict[str, Any]:
    """Return the shared Python/Java defined-data state."""
    primary = data.getPrimarySymbol()
    labels = []
    if primary is not None:
        labels.append(_data_symbol_state(primary, True))
    for symbol in ctx.program.getSymbolTable().getSymbols(data.getAddress()):
        if primary is None or int(symbol.getID()) != int(primary.getID()):
            labels.append(_data_symbol_state(symbol, False))

    result = {
        "address": str(data.getAddress()),
        "type": str(data.getDataType().getName()),
        "size": data.getLength(),
        "value": str(data.getDefaultValueRepresentation()),
        "labels": labels,
    }
    if primary is not None:
        result["label"] = str(primary.getName())
    if requested_addr is not None:
        table = ctx.program.getSymbolTable()
        exact_primary = table.getPrimarySymbol(requested_addr)
        result.update({
            "requested_address": str(requested_addr),
            "containing_address": str(data.getAddress()),
            "containing_end": str(data.getMaxAddress()),
            "byte_offset": int(requested_addr.subtract(data.getAddress())),
            "exact_symbols": [
                _data_symbol_state(
                    symbol,
                    exact_primary is not None
                    and int(symbol.getID()) == int(exact_primary.getID()),
                )
                for symbol in table.getSymbols(requested_addr)
            ],
        })
    return result


def get_function_stack_frame(ctx: ProgramContext, addr_hex: str) -> Dict[str, Any]:
    """Get the stack frame layout of a function."""
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return {"error": "No function at or containing " + addr_hex}

    return _stack_frame_state(func)


def _stack_frame_state(func) -> Dict[str, Any]:
    """Return deterministic, complete stack-frame state for read-back."""

    frame = func.getStackFrame()
    variables = [
        _stack_variable_state(frame, var)
        for var in frame.getStackVariables()
    ]
    variables.sort(key=lambda v: v["offset"])

    return {
        "func": func.getName(),
        "entry": str(func.getEntryPoint()),
        "frame_size": frame.getFrameSize(),
        "local_size": frame.getLocalSize(),
        "parameter_size": frame.getParameterSize(),
        "param_offset": frame.getParameterOffset(),
        "return_addr_offset": frame.getReturnAddressOffset(),
        "grows_negative": bool(frame.growsNegative()),
        "custom_variable_storage": bool(func.hasCustomVariableStorage()),
        "variables": variables,
    }


def _stack_variable_state(frame, var) -> Dict[str, Any]:
    data_type = var.getDataType()
    offset = var.getStackOffset()
    size = var.getLength()
    return {
        "offset": offset,
        "end_offset": offset + size - 1,
        "name": var.getName(),
        "type": str(data_type.getName()),
        "display_type": str(data_type.getDisplayName()),
        "type_path": str(data_type.getPathName()),
        "size": size,
        "storage": str(var.getVariableStorage()),
        "source": str(var.getSource()),
        "comment": var.getComment() or "",
        "first_use_offset": var.getFirstUseOffset(),
        "is_parameter": bool(frame.isParameterOffset(offset)),
    }


def list_enums(ctx: ProgramContext) -> str:
    """List all enum data types defined in the program."""
    dtm = ctx.program.getDataTypeManager()
    enums = []
    for dt in dtm.getAllDataTypes():
        if hasattr(dt, 'getCount') and hasattr(dt, 'getNames'):
            enums.append({
                "name": dt.getName(),
                "path": str(dt.getCategoryPath()),
                "size": dt.getLength(),
                "count": dt.getCount(),
            })
    enums.sort(key=lambda e: e["name"])
    lines = ["ENUMS in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), len(enums))]
    for e in enums:
        lines.append("  {} ({} bytes, {} members)  {}".format(
            e["name"], e["size"], e["count"], e["path"]))
    return "\n".join(lines)


def get_enum(ctx: ProgramContext, name: str) -> Dict[str, Any]:
    """Get the members of a named enum data type."""
    dtm = ctx.program.getDataTypeManager()
    found = None
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name and hasattr(dt, 'getCount') and hasattr(dt, 'getNames'):
            found = dt
            break
    if found is None:
        return {"error": "Enum '{}' not found".format(name)}

    members = []
    for n in found.getNames():
        members.append({"name": n, "value": found.getValue(n)})
    members.sort(key=lambda m: m["value"])

    return {
        "name": found.getName(),
        "path": str(found.getCategoryPath()),
        "size": found.getLength(),
        "count": found.getCount(),
        "members": members,
    }


_DECOMPILE_PAGE_DEFAULT = 16384
_DECOMPILE_PAGE_MAX = 32768
_BATCH_DECOMPILE_ADDRESSES_MAX = 16
_BATCH_DECOMPILE_FUNCTION_CHARS = 8192
_BATCH_DECOMPILE_TOTAL_CHARS = 32768


def _decompile_page(output: str, offset: int, limit: int) -> str:
    total = len(output)
    if offset > total:
        return "ERROR: offset {} exceeds decompiled output length {}".format(
            offset, total
        )
    end = min(total, offset + limit)
    if offset == 0 and end == total:
        return output
    next_offset = str(end) if end < total else "none"
    return (
        "// GHIDRAMSC OUTPUT CHUNK offset={} next_offset={} total_chars={}\n"
        .format(offset, next_offset, total) + output[offset:end]
    )


def _batch_decompile_entry(output: str, remaining: int) -> str:
    available = max(0, min(_BATCH_DECOMPILE_FUNCTION_CHARS, remaining))
    if len(output) <= available:
        return output
    note = (
        "// GHIDRAMSC BATCH TRUNCATED: total_chars={}; use "
        "decompile_function with offset to read all text.\n"
        .format(len(output))
    )
    return note + output[:max(0, available - len(note))]


def decompile_function(ctx: ProgramContext, addr_hex: str,
                       offset: int = 0,
                       limit: int = _DECOMPILE_PAGE_DEFAULT) -> str:
    """Decompile the function at/containing addr with bounded output."""
    if offset < 0 or not 1 <= limit <= _DECOMPILE_PAGE_MAX:
        return "ERROR: offset must be non-negative and limit must be 1..32768"
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return "ERROR: No function at or containing " + addr_hex

    d = _get_decompiler(ctx.program)
    try:
        result = d.decompileFunction(func, 120, _get_monitor())
        if result is None or not result.decompileCompleted():
            msg = result.getErrorMessage() if result else "unknown error"
            return "ERROR: Decompile failed for {} -- {}".format(func.getName(), str(msg))
        c_code = result.getDecompiledFunction().getC()
        out = "// Binary:    {}\n".format(_qualified_program_name(ctx.program))
        out += "// Function:  {}\n".format(func.getName())
        out += "// Entry:     {}\n".format(str(func.getEntryPoint()))
        out += "// Signature: {}\n\n".format(str(func.getSignature()))
        out += c_code
        return _decompile_page(out, offset, limit)
    finally:
        d.dispose()


def list_references_to_address(ctx: ProgramContext, addr_hex: str,
                               offset: int = 0, limit: int = 100) -> Any:
    """All cross-references TO addr."""
    try:
        validate_page(offset, limit, label="reference")
    except ValueError as exc:
        return "ERROR: " + str(exc)
    addr = ctx.to_addr(_addr_int(addr_hex))
    rm = ctx.program.getReferenceManager()
    refs = list(rm.getReferencesTo(addr))
    paged = offset > 0 or len(refs) > limit
    if paged:
        refs.sort(key=lambda ref: (
            str(ref.getFromAddress()), str(ref.getReferenceType()),
            int(ref.getOperandIndex()),
        ))
    selected, pagination = page_items(refs, offset, limit)
    lines = ["XREFs TO {} in {} ({} refs)\n".format(
        addr_hex, _qualified_program_name(ctx.program), len(refs))]
    records = []
    for ref in selected:
        from_addr = ref.getFromAddress()
        ref_type = str(ref.getReferenceType())
        fn = ctx.get_function_containing(from_addr)
        fn_name = fn.getName() if fn else "<no function>"
        lines.append("  {}  {}  in {}".format(str(from_addr), ref_type, fn_name))
        records.append({
            "from_address": str(from_addr),
            "to_address": str(ref.getToAddress()),
            "reference_kind": ref_type,
            "operand_index": int(ref.getOperandIndex()),
            "source_function": ({"name": str(fn.getName()),
                                 "entry": str(fn.getEntryPoint())}
                                if fn is not None else None),
        })
    rendered = "\n".join(lines)
    if not paged:
        return rendered
    containing = ctx.program.getListing().getCodeUnitContaining(addr)
    return {
        "text": rendered,
        "references": records,
        "pagination": pagination,
        "requested_address": str(addr),
        "containing_address": str(containing.getAddress()) if containing else None,
        "containing_end": str(containing.getMaxAddress()) if containing else None,
    }


def list_references_from_address(ctx: ProgramContext, addr_hex: str,
                                 offset: int = 0, limit: int = 100) -> Any:
    """All cross-references FROM addr."""
    try:
        validate_page(offset, limit, label="reference")
    except ValueError as exc:
        return "ERROR: " + str(exc)
    addr = ctx.to_addr(_addr_int(addr_hex))
    rm = ctx.program.getReferenceManager()
    refs = list(rm.getReferencesFrom(addr))
    paged = offset > 0 or len(refs) > limit
    if paged:
        refs.sort(key=lambda ref: (
            str(ref.getToAddress()), str(ref.getReferenceType()),
            int(ref.getOperandIndex()),
        ))
    selected, pagination = page_items(refs, offset, limit)
    lines = ["XREFs FROM {} in {} ({} refs)\n".format(
        addr_hex, _qualified_program_name(ctx.program), len(refs))]
    records = []
    for ref in selected:
        to_addr = ref.getToAddress()
        ref_type = str(ref.getReferenceType())
        fn = ctx.get_function_at(to_addr)
        fn_name = fn.getName() if fn else "<no function>"
        lines.append("  {}  {}  -> {}".format(str(to_addr), ref_type, fn_name))
        records.append({
            "from_address": str(ref.getFromAddress()),
            "to_address": str(to_addr),
            "reference_kind": ref_type,
            "operand_index": int(ref.getOperandIndex()),
            "target_function": ({"name": str(fn.getName()),
                                 "entry": str(fn.getEntryPoint())}
                                if fn is not None else None),
        })
    rendered = "\n".join(lines)
    if not paged:
        return rendered
    containing = ctx.program.getListing().getCodeUnitContaining(addr)
    return {
        "text": rendered,
        "references": records,
        "pagination": pagination,
        "requested_address": str(addr),
        "containing_address": str(containing.getAddress()) if containing else None,
        "containing_end": str(containing.getMaxAddress()) if containing else None,
    }


def get_listing_at_address(ctx: ProgramContext, addr_hex: str, count: int = 40,
                           offset: int = 0, limit: int = 100) -> Any:
    """Disassembly listing at addr for count instructions."""
    from ghidra.program.model.listing import CodeUnit  # type: ignore
    try:
        validate_page(offset, limit, label="listing")
    except ValueError as exc:
        return "ERROR: " + str(exc)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0 or count > 100000:
        return "ERROR: count must be 0..100000"
    addr = ctx.to_addr(_addr_int(addr_hex))
    prog_listing = ctx.program.getListing()
    header = "LISTING {} +{} instructions in {}\n".format(
        addr_hex, count, _qualified_program_name(ctx.program))
    containing = prog_listing.getCodeUnitContaining(addr)
    interior = (containing is not None
                and str(containing.getAddress()) != str(addr))
    start = containing.getAddress() if interior else addr
    cu_iter = prog_listing.getCodeUnits(start, True)
    units = []
    while cu_iter.hasNext() and len(units) < count:
        units.append(cu_iter.next())
    selected, pagination = page_items(units, offset, limit)
    items = []
    for cu in selected:
        lines = []
        primary = cu.getPrimarySymbol()
        if primary is not None:
            lines.append("{}:".format(primary.getName()))
        plate = cu.getComment(CodeUnit.PLATE_COMMENT)
        pre = cu.getComment(CodeUnit.PRE_COMMENT)
        eol = cu.getComment(CodeUnit.EOL_COMMENT)
        if plate:
            lines.append("; [PLATE] " + plate)
        if pre:
            lines.append("; " + pre)
        line = "{}  {}".format(str(cu.getAddress()), str(cu))
        if eol:
            line += "   ; " + eol
        lines.append(line)
        items.append("\n".join(lines))
    rendered = "\n".join([header] + items)
    if not interior and offset == 0 and len(units) <= limit:
        return rendered
    table = ctx.program.getSymbolTable()
    primary = table.getPrimarySymbol(addr)
    return {
        "text": rendered,
        "items": items,
        "pagination": pagination,
        "count": count,
        "requested_address": str(addr),
        "containing_address": str(containing.getAddress()) if containing else None,
        "containing_end": str(containing.getMaxAddress()) if containing else None,
        "byte_offset": int(addr.subtract(start)) if containing else None,
        "exact_symbols": [
            _data_symbol_state(
                symbol,
                primary is not None
                and int(symbol.getID()) == int(primary.getID()),
            )
            for symbol in table.getSymbols(addr)
        ],
    }


def _function_body_ranges(body) -> List[Dict[str, str]]:
    ranges = []
    iterator = body.getAddressRanges(True)
    while iterator.hasNext():
        item = iterator.next()
        ranges.append({
            "start": str(item.getMinAddress()),
            "end": str(item.getMaxAddress()),
        })
    return ranges


_INCOMING_CATEGORIES = (
    "direct_call", "verified_thunk_or_tail_flow", "other", "ambiguous",
)


def _incoming_reference_evidence(ctx: ProgramContext, func, offset: int,
                                 limit: int) -> Dict[str, Any]:
    """Conservative, entry-only incoming-reference inventory."""
    entry = func.getEntryPoint()
    fm = ctx.program.getFunctionManager()
    refs = list(ctx.program.getReferenceManager().getReferencesTo(entry))
    refs.sort(key=lambda ref: (
        str(ref.getFromAddress()), str(ref.getReferenceType()),
        int(ref.getOperandIndex()),
    ))
    sites = []
    for ref in refs:
        source = ref.getFromAddress()
        source_func = fm.getFunctionContaining(source)
        kind = ref.getReferenceType()
        category = "other"
        basis = "non_flow_reference"
        if kind.isCall():
            if kind.isComputed() or source_func is None:
                category, basis = "ambiguous", "computed_or_unowned_call"
            else:
                category, basis = "direct_call", "native_direct_call_reference"
        elif kind.isJump():
            thunk_target = (source_func.getThunkedFunction(True)
                            if source_func is not None and source_func.isThunk()
                            else None)
            if (not kind.isComputed() and thunk_target is not None
                    and str(thunk_target.getEntryPoint()) == str(entry)):
                category, basis = (
                    "verified_thunk_or_tail_flow", "native_thunk_target",
                )
            else:
                category, basis = "ambiguous", "jump_without_tail_proof"
        elif kind.isFlow():
            basis = "other_flow_reference"
        sites.append({
            "from_address": str(source),
            "to_address": str(ref.getToAddress()),
            "reference_kind": str(kind),
            "operand_index": int(ref.getOperandIndex()),
            "source_function": ({
                "name": str(source_func.getName()),
                "entry": str(source_func.getEntryPoint()),
            } if source_func is not None else None),
            "category": category,
            "classification_basis": basis,
        })

    def counts(rows):
        return {
            "reference_count": len(rows),
            "site_count": len({row["from_address"] for row in rows}),
            "distinct_source_function_count": len({
                row["source_function"]["entry"] for row in rows
                if row["source_function"] is not None
            }),
        }

    total = len(sites)
    selected = sites[offset:offset + limit]
    next_offset = offset + len(selected)
    has_more = next_offset < total
    return {
        "target_entry": str(entry),
        "coverage": "ghidra_references_to_entry_only",
        "classification_coverage": "conservative_native_evidence",
        **counts(sites),
        "category_counts": {
            category: counts([row for row in sites if row["category"] == category])
            for category in _INCOMING_CATEGORIES
        },
        "sites": selected,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "returned": len(selected),
            "total": total,
            "has_more": has_more,
            "next_offset": next_offset if has_more else None,
        },
    }


def get_function_info(ctx: ProgramContext, addr_hex: str,
                      incoming_offset: int = 0,
                      incoming_limit: int = 100,
                      evidence_offset: int = 0,
                      evidence_limit: int = 100) -> Dict[str, Any]:
    """Full function metadata as a dict."""
    if (incoming_offset < 0 or incoming_limit < 1 or incoming_limit > 500):
        return {"error": "incoming_offset must be non-negative and "
                "incoming_limit must be 1..500"}
    try:
        validate_page(evidence_offset, evidence_limit, label="evidence")
    except ValueError as exc:
        return {"error": str(exc)}
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return {"error": "No function at or containing " + addr_hex}

    monitor = _get_monitor()
    params = []
    for p in func.getParameters():
        params.append({
            "name": p.getName(),
            "type": str(p.getDataType()),
            "ordinal": p.getOrdinal(),
        })

    from ._query_analysis import _call_evidence
    evidence = _call_evidence(ctx, func, max_sites=0)
    callees = [{"name": item["name"], "entry": item["address"],
                "classification": item["classification"]}
               for item in evidence["callees"]]

    callers = []
    for c in func.getCallingFunctions(monitor):
        callers.append({"name": c.getName(), "entry": str(c.getEntryPoint())})
    callers.sort(key=lambda item: item["entry"])

    frame = func.getStackFrame()
    result = {
        "binary": _qualified_program_name(ctx.program),
        "name": func.getName(),
        "entry": str(func.getEntryPoint()),
        "signature": str(func.getSignature()),
        "calling_convention": str(func.getCallingConventionName()),
        "return_type": str(func.getReturnType()),
        "body_min": str(func.getBody().getMinAddress()),
        "body_max": str(func.getBody().getMaxAddress()),
        "body_bytes": func.getBody().getNumAddresses(),
        "body_ranges": _function_body_ranges(func.getBody()),
        "is_thunk": bool(func.isThunk()),
        "no_return": bool(func.hasNoReturn()),
        "effective_entry": str((func.getThunkedFunction(True) or func).getEntryPoint()),
        "stack_local_size": frame.getLocalSize() if frame else 0,
        "stack_param_size": frame.getParameterSize() if frame else 0,
        "parameters": params,
        "calls": callees,
        "called_by": callers,
        "call_sites": evidence["call_sites"],
        "possible_callees": evidence["possible_callees"],
        "unresolved_calls": evidence["unresolved_calls"],
        "call_scan_complete": evidence["scan_complete"],
        "caller_coverage": "ghidra_known_only",
        "incoming_references": _incoming_reference_evidence(
            ctx, func, incoming_offset, incoming_limit),
    }
    pagination = {}
    for key in ("parameters", "body_ranges", "calls", "called_by",
                "call_sites", "possible_callees", "unresolved_calls"):
        result[key], pagination[key] = page_items(
            result[key], evidence_offset, evidence_limit)
    result["evidence_pagination"] = pagination
    return result


def list_strings(ctx: ProgramContext, filter_str: str = "") -> str:
    """Dump all Ghidra-defined strings, optionally filtered."""
    prog_listing = ctx.program.getListing()
    data_iter = prog_listing.getDefinedData(True)
    results = []
    flt = filter_str.lower()
    while data_iter.hasNext():
        d = data_iter.next()
        dt_name = d.getDataType().getName().lower()
        if "string" not in dt_name and "char" not in dt_name:
            continue
        try:
            val = d.getValue()
            if val is None:
                continue
            sval = str(val)
            if flt == "" or flt in sval.lower():
                results.append("{}  {}".format(str(d.getAddress()), repr(sval)))
        except Exception:
            pass
    header = "STRINGS in {}  filter={!r}  ({} matches)\n".format(
        _qualified_program_name(ctx.program), filter_str, len(results))
    return header + "\n".join(results)


def search_memory_text(ctx: ProgramContext, pattern: str) -> str:
    """Search raw memory for an ASCII byte pattern."""
    import array as _array
    pat_bytes = _array.array('b', [ord(c) if c else 0 for c in pattern])
    mem = ctx.program.getMemory()
    monitor = _get_monitor()
    results = []
    addr = mem.getMinAddress()
    while addr is not None:
        try:
            found = mem.findBytes(addr, pat_bytes, None, True, monitor)
        except Exception:
            break
        if found is None:
            break
        fn = ctx.get_function_containing(found)
        fn_info = fn.getName() if fn else "<no function>"
        blk = mem.getBlock(found)
        blk_name = blk.getName() if blk else "?"
        results.append("{}  [{}]  in {}".format(str(found), blk_name, fn_info))
        try:
            addr = found.add(1)
        except Exception:
            break
    header = "SEARCH_MEM {!r} in {}  ({} hits)\n".format(
        pattern, _qualified_program_name(ctx.program), len(results))
    return header + "\n".join(results)


def search_memory_bytes(ctx: ProgramContext, hex_pattern: str) -> str:
    """Search memory for a hex-encoded byte pattern (e.g. 'e92d4830')."""
    import array as _array
    cleaned = hex_pattern.replace(" ", "").replace("\t", "")
    if len(cleaned) % 2 != 0:
        return "ERROR: search_memory_bytes pattern must have even number of hex chars, got: " + hex_pattern
    try:
        byte_vals = []
        for i in range(0, len(cleaned), 2):
            b = int(cleaned[i:i+2], 16)
            if b > 127:
                b = b - 256
            byte_vals.append(b)
        pat_bytes = _array.array('b', byte_vals)
    except ValueError as e:
        return "ERROR: search_memory_bytes invalid hex: " + str(e)

    mem = ctx.program.getMemory()
    monitor = _get_monitor()
    results = []
    addr = mem.getMinAddress()
    while addr is not None:
        try:
            found = mem.findBytes(addr, pat_bytes, None, True, monitor)
        except Exception:
            break
        if found is None:
            break
        fn = ctx.get_function_containing(found)
        fn_info = fn.getName() if fn else "<no function>"
        blk = mem.getBlock(found)
        blk_name = blk.getName() if blk else "?"
        results.append("{}  [{}]  in {}".format(str(found), blk_name, fn_info))
        try:
            addr = found.add(1)
        except Exception:
            break
    header = "SEARCH_HEX '{}' in {}  ({} hits)\n".format(
        cleaned, _qualified_program_name(ctx.program), len(results))
    return header + "\n".join(results)


def search_functions_by_name(ctx: ProgramContext, pattern: str) -> str:
    """Find functions whose name matches a regex pattern (case-insensitive)."""
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return "ERROR: Invalid regex {!r}: {}".format(pattern, e)

    fm = ctx.program.getFunctionManager()
    funcs = sorted(
        [f for f in fm.getFunctions(True) if rx.search(f.getName())],
        key=lambda f: f.getEntryPoint(),
    )
    lines = ["FIND_FUNC {!r} in {}  ({} matches)\n".format(
        pattern, _qualified_program_name(ctx.program), len(funcs))]
    for f in funcs:
        thunk = " [thunk]" if f.isThunk() else ""
        lines.append("{}  {}{}".format(str(f.getEntryPoint()), f.getName(), thunk))
    return "\n".join(lines)


def decompile_functions(ctx: ProgramContext, addresses: List[str]) -> Dict[str, str]:
    """Decompile multiple functions in one session.

    Returns a dict mapping each address to its decompiled output."""
    if not addresses or len(addresses) > _BATCH_DECOMPILE_ADDRESSES_MAX:
        return {"error": "decompile_functions requires 1..16 addresses; split larger requests"}
    d = _get_decompiler(ctx.program)
    monitor = _get_monitor()
    results = {}
    used = 0
    try:
        for addr_hex in addresses:
            if used >= _BATCH_DECOMPILE_TOTAL_CHARS:
                results[addr_hex] = (
                    "// GHIDRAMSC BATCH OUTPUT OMITTED: call "
                    "decompile_function for paged output."
                )
                continue
            func = ctx.resolve_function(_addr_int(addr_hex))
            if func is None:
                results[addr_hex] = "ERROR: No function at " + addr_hex
                continue
            res = d.decompileFunction(func, 120, monitor)
            if not res.decompileCompleted():
                results[addr_hex] = "ERROR: Decompile failed for " + func.getName()
                continue
            sig = str(func.getSignature()) if func.getSignature() else ""
            header = "// Function:  {}\n// Entry:     {}\n// Signature: {}\n\n".format(
                func.getName(), func.getEntryPoint(), sig)
            results[addr_hex] = _batch_decompile_entry(
                header + res.getDecompiledFunction().getC(),
                _BATCH_DECOMPILE_TOTAL_CHARS - used,
            )
            used += len(results[addr_hex])
    finally:
        d.dispose()
    return results


__all__ = [
    "list_functions",
    "read_memory_bytes",
    "get_data_at_address",
    "_data_symbol_state",
    "_defined_data_state",
    "get_function_stack_frame",
    "_stack_frame_state",
    "_stack_variable_state",
    "list_enums",
    "get_enum",
    "decompile_function",
    "list_references_to_address",
    "list_references_from_address",
    "get_listing_at_address",
    "_function_body_ranges",
    "get_function_info",
    "list_strings",
    "search_memory_text",
    "search_memory_bytes",
    "search_functions_by_name",
    "decompile_functions",
]
