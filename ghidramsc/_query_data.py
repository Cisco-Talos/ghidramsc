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

"""Private data implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any, Dict, Optional

from .bridge import ProgramContext

from ._query_core import (
    _addr_int,
    _end_mutation_transaction,
    _mutation_no_change,
    _mutation_contract_result,
    _mutation_validation_failure,
    _resolve_type,
    _read_memory_buffer,
    _run_mutation_transaction,
    _start_mutation_transaction,
)

from ._query_inspection import (
    _defined_data_state,
    get_data_at_address,
)

from ._query_program import (
    get_program_memory_map,
    get_program_info,
)


_DATA_APPLICATION_DETAIL_LIMIT = 64
_DATA_APPLICATION_VALUE_LIMIT = 1024
_UNINITIALIZED_DATA_MAX_BYTES = 4096
_ANALYSIS_BLOCK_MAX_BYTES = 4096
_ANALYSIS_BLOCK_SOURCE = "GhidraMSC analysis block"
_RECOVERED_CODE_MAX_BYTES = 65536
_RECOVERED_CODE_COMMENT_PREFIX = "GhidraMSC recovered code v1: "


def _byte_state(ctx: ProgramContext, addr, length: int) -> Dict[str, Any]:
    data, read = _read_memory_buffer(ctx.program, addr, length)
    if read != length:
        raise ValueError(
            "Requested {} bytes but read {}".format(length, read)
        )
    return {
        "address": str(addr),
        "length": length,
        "hex_bytes": data.hex(),
    }


def write_memory_bytes(ctx: ProgramContext, addr_hex: str,
                hex_bytes: str) -> Dict[str, Any]:
    """Write raw bytes at the given address.  hex_bytes is a hex string
    (e.g. '90909090' for 4 NOP bytes on x86)."""
    cleaned = hex_bytes.replace(" ", "").replace("\t", "")
    requested = {
        "address": addr_hex,
        "hex_bytes": cleaned.lower(),
    }
    if len(cleaned) % 2 != 0:
        return _mutation_validation_failure(
            "write_memory_bytes", requested,
            "hex_bytes must have even number of chars",
        )
    try:
        if re.fullmatch(r"[0-9a-fA-F]*", cleaned) is None:
            raise ValueError("non-hexadecimal character")
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        return _mutation_validation_failure(
            "write_memory_bytes", requested, "Invalid hex: {}".format(str(exc))
        )

    addr = ctx.to_addr(_addr_int(addr_hex))
    mem = ctx.program.getMemory()
    try:
        old = _byte_state(ctx, addr, len(data))
    except Exception as exc:
        return _mutation_validation_failure(
            "write_memory_bytes", requested,
            "Cannot read target bytes: {}".format(str(exc)),
        )
    if old["hex_bytes"] == data.hex():
        return _mutation_no_change("write_memory_bytes", requested, old)
    return _run_mutation_transaction(
        ctx,
        "write_memory_bytes",
        "Patch bytes",
        requested,
        old,
        lambda: mem.setBytes(addr, data),
        lambda: _byte_state(ctx, addr, len(data)),
        lambda stored: (
            None if stored["hex_bytes"] == data.hex()
            else "Byte read-back mismatch at {}".format(addr_hex)
        ),
    )


def set_data_label(ctx: ProgramContext, addr_hex: str,
                new_name: str) -> Dict[str, Any]:
    """Rename or promote the exact primary label for defined data."""
    from ghidra.program.model.symbol import SourceType  # type: ignore

    addr = ctx.to_addr(_addr_int(addr_hex))
    requested = {"address": addr_hex, "primary_label": new_name}
    listing = ctx.program.getListing()
    data = listing.getDefinedDataAt(addr)
    if data is None:
        data = listing.getDefinedDataContaining(addr)
    if data is None:
        return _mutation_validation_failure(
            "set_data_label", requested, "No defined data at " + addr_hex
        )
    data_address = data.getAddress()
    old = _defined_data_state(ctx, data)
    if old.get("label") == new_name:
        return _mutation_no_change("set_data_label", requested, old)

    st = ctx.program.getSymbolTable()
    primary = data.getPrimarySymbol()
    namespace = (
        primary.getParentNamespace()
        if primary is not None else ctx.program.getGlobalNamespace()
    )
    collision = st.getNamespaceSymbol(new_name, namespace)
    if collision is None:
        collision = st.getClassSymbol(new_name, namespace)
    global_namespace = ctx.program.getGlobalNamespace()
    try:
        is_global = bool(namespace.equals(global_namespace))
    except Exception:
        is_global = namespace == global_namespace
    if collision is None and is_global:
        collision = st.getLibrarySymbol(new_name)
    if collision is not None:
        return _mutation_validation_failure(
            "set_data_label",
            requested,
            "Requested primary label '{}' conflicts with existing {} in namespace {}"
            .format(new_name, collision.getSymbolType(), namespace),
        )

    def apply_primary_label() -> None:
        requested_symbol = st.getSymbol(
            new_name, data_address, namespace
        )
        if (
            requested_symbol is not None
            and (
                primary is None
                or int(requested_symbol.getID()) != int(primary.getID())
            )
        ):
            if not requested_symbol.setPrimary():
                raise ValueError(
                    "Could not make existing label '{}' primary at {}".format(
                        new_name, data_address
                    )
                )
        elif primary is not None:
            primary.setName(new_name, SourceType.USER_DEFINED)
        else:
            requested_symbol = st.createLabel(
                data_address, new_name, namespace, SourceType.USER_DEFINED
            )
            if (
                not requested_symbol.isPrimary()
                and not requested_symbol.setPrimary()
            ):
                raise ValueError(
                    "Could not make new label '{}' primary at {}".format(
                        new_name, data_address
                    )
                )

    return _run_mutation_transaction(
        ctx,
        "set_data_label",
        "Rename data",
        requested,
        old,
        apply_primary_label,
        lambda: _defined_data_state(ctx, data),
        lambda stored: (
            None if stored.get("label") == new_name
            else "Primary-symbol read-back mismatch: requested {}, stored {}"
            .format(new_name, stored.get("label", "<none>"))
        ),
    )


def _data_application_result(operation: str, status: str,
                             requested: Dict[str, Any],
                             old: Dict[str, Any],
                             stored: Optional[Dict[str, Any]] = None,
                             error: str = "") -> Dict[str, Any]:
    result = {
        "operation": operation,
        "status": status,
        "requested": requested,
        "old": old,
        "transaction": {
            "started": status in ("success", "rolled_back"),
            "committed": status == "success",
        },
    }
    if stored is not None:
        result["stored"] = stored
    if error:
        result["error"] = error
    return result


def _data_application_state(ctx: ProgramContext, addr, length: int) -> Dict[str, Any]:
    from ghidra.program.model.address import AddressSet  # type: ignore

    end = addr.add(length - 1)
    address_set = AddressSet(addr, end)
    listing = ctx.program.getListing()
    code_units = []
    conflicts = []
    seen = set()
    has_instructions = False
    code_unit_count = 0
    conflict_count = 0

    def add_unit(unit) -> None:
        nonlocal has_instructions, code_unit_count, conflict_count
        key = str(unit.getAddress())
        if key in seen:
            return
        seen.add(key)
        code_unit_count += 1
        instruction = listing.getInstructionAt(unit.getAddress()) is not None
        if instruction:
            has_instructions = True
        defined = not instruction and bool(unit.isDefined())
        if defined:
            conflict_count += 1
        if (len(code_units) >= _DATA_APPLICATION_DETAIL_LIMIT
                and (not defined or len(conflicts) >= _DATA_APPLICATION_DETAIL_LIMIT)):
            return
        item = {
            "address": key,
            "end": str(unit.getMaxAddress()),
            "length": unit.getLength(),
            "kind": "instruction" if instruction else "data",
        }
        if not instruction:
            item["type"] = str(unit.getDataType())
            item["defined"] = defined
            if defined and len(conflicts) < _DATA_APPLICATION_DETAIL_LIMIT:
                conflicts.append(dict(item))
        if len(code_units) < _DATA_APPLICATION_DETAIL_LIMIT:
            code_units.append(item)

    containing = listing.getCodeUnitContaining(addr)
    if containing is not None:
        add_unit(containing)

    iterator = listing.getCodeUnits(address_set, True)
    while iterator.hasNext():
        add_unit(iterator.next())

    target = get_data_at_address(ctx, str(addr))
    if isinstance(target, dict):
        target = dict(target)
        value = target.get("value")
        if isinstance(value, str) and len(value) > _DATA_APPLICATION_VALUE_LIMIT:
            target["value"] = value[:_DATA_APPLICATION_VALUE_LIMIT]
            target["value_length"] = len(value)
            target["value_truncated"] = True
        labels = target.get("labels")
        if isinstance(labels, list) and len(labels) > _DATA_APPLICATION_DETAIL_LIMIT:
            target["labels"] = labels[:_DATA_APPLICATION_DETAIL_LIMIT]
            target["label_count"] = len(labels)
            target["labels_truncated"] = True

    return {
        "address": str(addr),
        "end": str(end),
        "length": length,
        "has_instructions": has_instructions,
        "code_units": code_units,
        "code_unit_count": code_unit_count,
        "code_units_truncated": code_unit_count > len(code_units),
        "conflicts": conflicts,
        "conflict_count": conflict_count,
        "conflicts_truncated": conflict_count > len(conflicts),
        "target": target,
    }


def _read_application_bytes(ctx: ProgramContext, addr, length: int) -> bytes:
    data, actual = _read_memory_buffer(ctx.program, addr, length)
    if actual != length:
        raise ValueError(
            "Requested {} bytes but read {}".format(length, actual)
        )
    return data


def apply_data_type(ctx: ProgramContext, addr_hex: str, type_name: str,
                    clear_mode: str = "fail") -> Dict[str, Any]:
    """Apply fixed-size data without implicitly clearing instructions.

    The default ``fail`` policy rejects existing defined data.  The explicit
    ``data_only`` policy may replace conflicting data while preserving bytes.
    """
    requested = {
        "address": addr_hex,
        "type_name": type_name,
        "clear_mode": clear_mode,
    }
    if clear_mode not in ("fail", "data_only"):
        return _data_application_result(
            "apply_data_type", "validation_failed", requested, {},
            error="clear_mode must be fail or data_only",
        )
    addr = ctx.to_addr(_addr_int(addr_hex))
    dt = _resolve_type(ctx.program, type_name)
    if dt is None:
        return _data_application_result(
            "apply_data_type", "validation_failed", requested, {},
            error="Unknown data type '{}'".format(type_name),
        )
    length = dt.getLength()
    if length <= 0:
        return _data_application_result(
            "apply_data_type", "validation_failed", requested, {},
            error="Resolved type has no fixed positive size: {}".format(dt),
        )
    requested["resolved_type"] = str(dt)
    requested["size"] = length

    try:
        end = addr.add(length - 1)
        memory = ctx.program.getMemory()
        block = memory.getBlock(addr)
        if block is None or not block.contains(end):
            raise ValueError("Target range must stay within one mapped memory block")
        initialized_set = memory.getAllInitializedAddressSet()
        initialized = bool(initialized_set.contains(addr, end))
        has_initialized_bytes = bool(initialized_set.intersects(addr, end))
        if not initialized and has_initialized_bytes:
            raise ValueError("Target range mixes initialized and uninitialized memory")
        if not initialized and length > _UNINITIALIZED_DATA_MAX_BYTES:
            raise ValueError(
                "Uninitialized data object exceeds {} bytes".format(
                    _UNINITIALIZED_DATA_MAX_BYTES))
        block_state = {
            "name": str(block.getName()),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "initialized": bool(block.isInitialized()),
            "range_initialized": initialized,
            "range_has_initialized_bytes": has_initialized_bytes,
        }
        old = _data_application_state(ctx, addr, length)
        old["memory_block"] = block_state
        original_bytes = (
            _read_application_bytes(ctx, addr, length) if initialized else None
        )
    except Exception as exc:
        return _data_application_result(
            "apply_data_type", "validation_failed", requested, {},
            error="Cannot inspect target range: {}".format(exc),
        )
    existing = ctx.program.getListing().getDefinedDataAt(addr)
    if existing is not None and existing.getDataType().isEquivalent(dt):
        return _data_application_result(
            "apply_data_type", "no_change", requested, old, old,
        )
    if old["has_instructions"]:
        return _data_application_result(
            "apply_data_type", "validation_failed", requested, old,
            error=("Target range contains instructions; apply_data_type "
                   "never clears instructions"),
        )
    if clear_mode == "fail" and old["conflicts"]:
        return _data_application_result(
            "apply_data_type", "validation_failed", requested, old,
            error=("Target range contains defined data; retry with "
                   "clear_mode=data_only to replace data explicitly"),
        )

    from ghidra.program.model.data import DataUtilities  # type: ignore

    tx_id = _start_mutation_transaction(ctx, "Apply data type")
    commit = False
    try:
        try:
            mode = (
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
                if clear_mode == "data_only"
                else DataUtilities.ClearDataMode.CHECK_FOR_SPACE
            )
            DataUtilities.createData(
                ctx.program, addr, dt, length, False, mode
            )
            stored_data = ctx.program.getListing().getDefinedDataAt(addr)
            if (stored_data is None
                    or not stored_data.getDataType().isEquivalent(dt)):
                raise ValueError("Data-type read-back mismatch at " + addr_hex)
            stored = _data_application_state(ctx, addr, length)
            stored_block = memory.getBlock(addr)
            stored_initialized_set = memory.getAllInitializedAddressSet()
            stored["memory_block"] = {
                "name": str(stored_block.getName()),
                "start": str(stored_block.getStart()),
                "end": str(stored_block.getEnd()),
                "initialized": bool(stored_block.isInitialized()),
                "range_initialized": bool(stored_initialized_set.contains(addr, end)),
                "range_has_initialized_bytes": bool(
                    stored_initialized_set.intersects(addr, end)),
            }
            if stored["memory_block"] != block_state:
                raise ValueError("Memory block changed while applying data type")
            if initialized:
                stored_bytes = _read_application_bytes(ctx, addr, length)
                stored["bytes_preserved"] = stored_bytes == original_bytes
                stored["byte_count"] = length
                if not stored["bytes_preserved"]:
                    raise ValueError("Target bytes changed while applying data type")
            else:
                stored["byte_state"] = "uninitialized_no_file_bytes"
                stored["byte_count"] = 0
                stored["bytes_preserved"] = None
            commit = True
            return _data_application_result(
                "apply_data_type", "success", requested, old, stored,
            )
        except Exception as exc:
            return _data_application_result(
                "apply_data_type", "rolled_back", requested, old,
                error=str(exc),
            )
    finally:
        _end_mutation_transaction(ctx, tx_id, commit)


def set_program_image_base(ctx: ProgramContext, addr_hex: str) -> Dict[str, Any]:
    """Set the image base address of the program."""
    addr = ctx.to_addr(_addr_int(addr_hex))
    requested = {"image_base": str(addr)}
    old = get_program_info(ctx)
    if str(ctx.program.getImageBase()) == str(addr):
        return _mutation_no_change("set_program_image_base", requested, old)
    return _run_mutation_transaction(
        ctx,
        "set_program_image_base",
        "Set image base",
        requested,
        old,
        lambda: ctx.program.setImageBase(addr, True),
        lambda: get_program_info(ctx),
        lambda stored: (
            None if str(ctx.program.getImageBase()) == str(addr)
            else "Image-base read-back mismatch: requested {}, stored {}".format(
                addr, ctx.program.getImageBase()
            )
        ),
    )


def set_memory_block_permissions(ctx: ProgramContext, block_name: str,
                           read: bool = True, write: bool = False,
                           execute: bool = False) -> Dict[str, Any]:
    """Set read/write/execute permissions on a named memory block."""
    mem = ctx.program.getMemory()
    blk = mem.getBlock(block_name)
    requested = {
        "block_name": block_name,
        "read": read,
        "write": write,
        "execute": execute,
    }
    if blk is None:
        return _mutation_validation_failure(
            "set_memory_block_permissions", requested,
            "Memory block not found: " + block_name,
        )
    old = get_program_memory_map(ctx)
    if (
        bool(blk.isRead()) == read
        and bool(blk.isWrite()) == write
        and bool(blk.isExecute()) == execute
    ):
        return _mutation_no_change(
            "set_memory_block_permissions", requested, old
        )

    def apply_permissions() -> None:
        blk.setRead(read)
        blk.setWrite(write)
        blk.setExecute(execute)

    def validate_permissions(stored: Any) -> Optional[str]:
        if (
            bool(blk.isRead()) == read
            and bool(blk.isWrite()) == write
            and bool(blk.isExecute()) == execute
        ):
            return None
        return "Memory-permission read-back mismatch for " + block_name

    return _run_mutation_transaction(
        ctx,
        "set_memory_block_permissions",
        "Set memory permissions",
        requested,
        old,
        apply_permissions,
        lambda: get_program_memory_map(ctx),
        validate_permissions,
    )


def create_memory_block(ctx: ProgramContext, block_name: str, addr_hex: str,
                        length: int, mode: str, overlay: bool = False,
                        read: bool = True, write: bool = True,
                        execute: bool = False, fill_byte: int = 0,
                        hex_bytes: str = "", source_addr_hex: str = "",
                        preview_only: bool = False) -> Dict[str, Any]:
    """Create one small analysis block without changing a mapped file block.

    ``byte_mapped`` is a live alias of source bytes, not a copy.  Overlay
    creation gets a new address space; the actual qualified start is returned.
    """
    from ghidra.util.task import TaskMonitor  # type: ignore

    operation = "create_memory_block"
    requested = dict(block_name=block_name, address=addr_hex, length=length,
                     mode=mode, overlay=overlay, read=read, write=write,
                     execute=execute, fill_byte=fill_byte,
                     hex_bytes=hex_bytes, source_addr_hex=source_addr_hex,
                     preview_only=preview_only)
    def fail(message: str) -> Dict[str, Any]:
        return _mutation_validation_failure(operation, requested, message)
    if (not isinstance(block_name, str) or not block_name.strip() or
            block_name != block_name.strip()):
        return fail("block_name must be nonempty and have no surrounding whitespace")
    if (not isinstance(addr_hex, str) or not isinstance(mode, str) or
            not isinstance(hex_bytes, str) or not isinstance(source_addr_hex, str)):
        return fail("Address, mode, and byte/source arguments must be strings")
    if any(type(value) is not bool for value in
           (overlay, read, write, execute, preview_only)):
        return fail("Overlay, permissions, and preview_only must be booleans")
    if mode not in ("uninitialized", "fill", "bytes", "byte_mapped"):
        return fail("mode must be uninitialized, fill, bytes, or byte_mapped")
    if type(length) is not int or not 1 <= length <= _ANALYSIS_BLOCK_MAX_BYTES:
        return fail("length must be 1..4096 bytes")
    if type(fill_byte) is not int or not 0 <= fill_byte <= 255:
        return fail("fill_byte must be 0..255")
    if (mode != "fill" and fill_byte != 0 or
            mode != "bytes" and hex_bytes or
            mode != "byte_mapped" and source_addr_hex):
        return fail("fill_byte, hex_bytes, and source_addr_hex require their matching mode")
    data = b""
    if mode == "bytes":
        try:
            if re.fullmatch(r"[0-9a-fA-F]+", hex_bytes) is None:
                raise ValueError("non-hexadecimal input")
            data = bytes.fromhex(hex_bytes)
        except ValueError as exc:
            return fail("Invalid hex_bytes: " + str(exc))
        if len(data) != length:
            return fail("hex_bytes must contain exactly length bytes")
    mem = ctx.program.getMemory()
    if mem.getBlock(block_name) is not None:
        return fail("Memory block name already exists: " + block_name)
    try:
        start = ctx.to_addr(_addr_int(addr_hex))
        end = start.addNoWrap(length - 1)
        if start.getAddressSpace().isOverlaySpace():
            return fail("Create start must be in the physical address space")
    except Exception as exc:
        return fail("Invalid target range: " + str(exc))
    overlaps = [b.getName() for b in mem.getBlocks()
                if b.getStart().getAddressSpace() == start.getAddressSpace()
                and b.getStart().compareTo(end) <= 0
                and b.getEnd().compareTo(start) >= 0]
    if overlaps and not overlay:
        return fail("Target range overlaps existing blocks: " + ", ".join(overlaps))
    source = None
    if mode == "byte_mapped":
        try:
            source = ctx.to_addr(_addr_int(source_addr_hex))
            source_end = source.addNoWrap(length - 1)
            source_block = mem.getBlock(source)
            if (source_block is None or not source_block.isInitialized() or
                    source_block.getEnd().compareTo(source_end) < 0):
                return fail("Source range must lie in one initialized memory block")
        except Exception as exc:
            return fail("Invalid source range: " + str(exc))
    old = get_program_memory_map(ctx)
    preview = {"start": str(start), "end": str(end), "length": length,
               "overlaps": overlaps, "overlay": overlay,
               "source_aliases_original": mode == "byte_mapped"}
    existing_symbols = []
    symbol_table = ctx.program.getSymbolTable()
    for offset in range(length):
        for symbol in symbol_table.getSymbols(start.add(offset)):
            existing_symbols.append({"address": str(symbol.getAddress()),
                                     "name": str(symbol.getName()),
                                     "source": str(symbol.getSource())})
            if len(existing_symbols) >= 16:
                break
        if len(existing_symbols) >= 16:
            break
    preview["existing_symbols_sample"] = existing_symbols
    if preview_only:
        result = _mutation_contract_result(operation, "preview", requested,
                                           old=old, stored=old)
        result["preview"] = preview
        return result

    def apply() -> None:
        if mode == "uninitialized":
            block = mem.createUninitializedBlock(block_name, start, length, overlay)
        elif mode == "byte_mapped":
            block = mem.createByteMappedBlock(block_name, start, source, length, overlay)
        else:
            import jpype
            signed_fill = fill_byte if fill_byte < 128 else fill_byte - 256
            block = mem.createInitializedBlock(block_name, start, length,
                                               jpype.JByte(signed_fill),
                                               TaskMonitor.DUMMY, overlay)
            if mode == "bytes":
                byte_array = jpype.JArray(jpype.JByte)(
                    [value if value < 128 else value - 256 for value in data])
                mem.setBytes(block.getStart(), byte_array)
        block.setSourceName(_ANALYSIS_BLOCK_SOURCE)
        block.setRead(read)
        block.setWrite(write)
        block.setExecute(execute)

    def validate(stored: Any) -> Optional[str]:
        block = mem.getBlock(block_name)
        if (block is None or int(block.getSize()) != length or
                bool(block.isOverlay()) != overlay or
                (mode == "uninitialized" and bool(block.isInitialized())) or
                (mode in ("fill", "bytes") and not bool(block.isInitialized())) or
                (mode == "byte_mapped" and str(block.getType()) != "Byte Mapped") or
                bool(block.isRead()) != read or bool(block.isWrite()) != write or
                bool(block.isExecute()) != execute or
                str(block.getSourceName()) != _ANALYSIS_BLOCK_SOURCE):
            return "Created block read-back mismatch"
        if mode == "bytes":
            actual, count = _read_memory_buffer(ctx.program, block.getStart(), length)
            if count != length or actual != data:
                return "Created block bytes read-back mismatch"
        return None

    result = _run_mutation_transaction(ctx, operation, "Create analysis memory block",
                                       requested, old, apply,
                                       lambda: get_program_memory_map(ctx), validate,
                                       validate_rollback=lambda state: (
                                           None if mem.getBlock(block_name) is None else
                                           "Rollback left target block present"))
    result["preview"] = preview
    return result


def delete_memory_block(ctx: ProgramContext, block_name: str, start: str,
                        length: int, preview_only: bool = False,
                        confirm_content_removal: bool = False) -> Dict[str, Any]:
    """Remove only an exactly identified GhidraMSC analysis block."""
    from ghidra.util.task import TaskMonitor  # type: ignore

    operation = "delete_memory_block"
    requested = dict(block_name=block_name, start=start, length=length,
                     preview_only=preview_only,
                     confirm_content_removal=confirm_content_removal)
    def fail(message: str) -> Dict[str, Any]:
        return _mutation_validation_failure(operation, requested, message)
    if (not isinstance(block_name, str) or not isinstance(start, str) or
            type(preview_only) is not bool or
            type(confirm_content_removal) is not bool):
        return fail("Block identity and confirmation arguments have invalid types")
    mem = ctx.program.getMemory()
    block = mem.getBlock(block_name)
    if (block is None or str(block.getStart()) != start or
            type(length) is not int or int(block.getSize()) != length or
            str(block.getSourceName()) != _ANALYSIS_BLOCK_SOURCE):
        return fail("Block identity or GhidraMSC analysis provenance does not match")
    listing = ctx.program.getListing()
    symbols = ctx.program.getSymbolTable()
    occupied = []
    content_details = []
    for offset in range(length):
        address = block.getStart().add(offset)
        instruction = listing.getInstructionContaining(address)
        data = listing.getDefinedDataContaining(address)
        at_symbols = symbols.getSymbols(address)
        if instruction is not None or data is not None or len(at_symbols) > 0:
            occupied.append(str(address))
            content_details.append({
                "address": str(address),
                "instruction": instruction is not None,
                "defined_data": data is not None,
                "symbols": [{"name": str(symbol.getName()),
                             "source": str(symbol.getSource())}
                            for symbol in at_symbols[:8]],
            })
            if len(occupied) >= 16:
                break
    preview = {"start": start, "end": str(block.getEnd()),
               "length": length, "content_addresses_sample": occupied,
               "content_details_sample": content_details,
               "content_removal_required": bool(occupied)}
    old = get_program_memory_map(ctx)
    if preview_only:
        result = _mutation_contract_result(operation, "preview", requested,
                                           old=old, stored=old)
        result["preview"] = preview
        return result
    if occupied and not confirm_content_removal:
        return fail("Block contains code, data, or symbols; preview and explicitly confirm removal")

    def apply() -> None:
        mem.removeBlock(block, TaskMonitor.DUMMY)

    result = _run_mutation_transaction(ctx, operation, "Remove analysis memory block",
                                       requested, old, apply,
                                       lambda: get_program_memory_map(ctx),
                                       lambda state: (None if mem.getBlock(block_name) is None
                                                      else "Removed block is still present"),
                                       validate_rollback=lambda state: (
                                           None if mem.getBlock(block_name) is not None else
                                           "Rollback did not restore target block"))
    result["preview"] = preview
    return result


def create_recovered_code_overlay(
        ctx: ProgramContext, block_name: str, analysis_addr_hex: str,
        hex_bytes: str, transform: str, source_addr_hex: str = "",
        source_length: int = 0, runtime_addr_hex: str = "",
        allow_physical_overlap: bool = False,
        preview_only: bool = False) -> Dict[str, Any]:
    """Copy exact recovered bytes into a separate, executable address space.

    Source and runtime addresses describe provenance; neither is written.
    Use exact-identity ``delete_memory_block`` to remove the overlay.
    """
    from ghidra.util.task import TaskMonitor  # type: ignore
    from java.io import ByteArrayInputStream  # type: ignore
    import jpype

    operation = "create_recovered_code_overlay"
    requested = {"block_name": block_name, "analysis_addr_hex": analysis_addr_hex,
                 "source_addr_hex": source_addr_hex, "source_length": source_length,
                 "runtime_addr_hex": runtime_addr_hex, "transform": transform,
                 "allow_physical_overlap": allow_physical_overlap,
                 "preview_only": preview_only}
    def fail(message: str) -> Dict[str, Any]:
        return _mutation_validation_failure(operation, requested, message)
    if (not isinstance(block_name, str) or not block_name.strip() or
            block_name != block_name.strip() or len(block_name) > 80 or
            not isinstance(analysis_addr_hex, str) or
            not isinstance(source_addr_hex, str) or
            not isinstance(runtime_addr_hex, str) or
            not isinstance(transform, str) or not 1 <= len(transform) <= 256 or
            type(allow_physical_overlap) is not bool or
            type(preview_only) is not bool):
        return fail("Invalid block name, address, transform, or boolean argument")
    if type(source_length) is not int or not 0 <= source_length <= _RECOVERED_CODE_MAX_BYTES:
        return fail("source_length must be 0..65536")
    if bool(source_addr_hex) != bool(source_length):
        return fail("source_addr_hex and positive source_length must be supplied together")
    if (not isinstance(hex_bytes, str) or not hex_bytes or
            len(hex_bytes) % 2 or len(hex_bytes) > 2 * _RECOVERED_CODE_MAX_BYTES or
            re.fullmatch(r"[0-9a-fA-F]+", hex_bytes) is None):
        return fail("hex_bytes must contain 1..65536 exact bytes")
    recovered = bytes.fromhex(hex_bytes)
    length = len(recovered)
    digest = hashlib.sha256(recovered).hexdigest()
    requested.update(length=length, sha256=digest)
    mem = ctx.program.getMemory()
    if mem.getBlock(block_name) is not None:
        return fail("Memory block name already exists: " + block_name)
    try:
        start = ctx.to_addr(_addr_int(analysis_addr_hex))
        end = start.addNoWrap(length - 1)
        if start.getAddressSpace().isOverlaySpace():
            return fail("analysis_addr_hex must name the physical address space")
        source = ctx.to_addr(_addr_int(source_addr_hex)) if source_addr_hex else None
        source_end = source.addNoWrap(source_length - 1) if source else None
        if source and source.getAddressSpace().isOverlaySpace():
            return fail("source_addr_hex must name the physical address space")
        if source:
            source_block = mem.getBlock(source)
            if source_block is None or source_block.getEnd().compareTo(source_end) < 0:
                return fail("Source range must lie in one existing physical block")
        if runtime_addr_hex:
            runtime_offset = _addr_int(runtime_addr_hex)
            if not isinstance(runtime_offset, int):
                return fail("runtime_addr_hex must be a bare hex address")
    except Exception as exc:
        return fail("Invalid analysis/source/runtime range: " + str(exc))
    overlaps = [str(block.getName()) for block in mem.getBlocks()
                if block.getStart().getAddressSpace() == start.getAddressSpace()
                and block.getStart().compareTo(end) <= 0
                and block.getEnd().compareTo(start) >= 0]
    if overlaps and not allow_physical_overlap:
        return fail("Physical range overlaps existing blocks; set allow_physical_overlap explicitly")
    source_before = None
    if source and source_block.isInitialized():
        source_before, count = _read_memory_buffer(ctx.program, source, source_length)
        if count != source_length:
            return fail("Could not read exact source range")
    physical_before = None
    physical_block = mem.getBlock(start)
    if (physical_block is not None and physical_block.isInitialized() and
            physical_block.getEnd().compareTo(end) >= 0):
        physical_before, count = _read_memory_buffer(ctx.program, start, length)
        if count != length:
            return fail("Could not read exact physical target range")
    metadata = {"analysis_requested_start": str(start),
                "source_start": str(source) if source else None,
                "source_length": source_length, "runtime_start": runtime_addr_hex or None,
                "transform": transform, "length": length, "sha256": digest}
    comment = _RECOVERED_CODE_COMMENT_PREFIX + json.dumps(metadata, sort_keys=True)
    preview = {"analysis_requested_start": str(start), "length": length,
               "sha256": digest, "physical_overlaps": overlaps,
               "source_sha256": (hashlib.sha256(source_before).hexdigest()
                                  if source_before is not None else None),
               "physical_sha256": (hashlib.sha256(physical_before).hexdigest()
                                    if physical_before is not None else None)}
    old = {"block_present": False, "physical_overlaps": overlaps}
    if preview_only:
        result = _mutation_contract_result(operation, "preview", requested,
                                           old=old, stored=old)
        result["preview"] = preview
        return result

    def apply() -> None:
        byte_array = jpype.JArray(jpype.JByte)(
            [value if value < 128 else value - 256 for value in recovered])
        stream = ByteArrayInputStream(byte_array)
        block = mem.createInitializedBlock(block_name, start, stream, length,
                                           TaskMonitor.DUMMY, True)
        block.setSourceName(_ANALYSIS_BLOCK_SOURCE)
        block.setComment(comment)
        block.setRead(True)
        block.setWrite(False)
        block.setExecute(True)

    def read_back() -> Dict[str, Any]:
        block = mem.getBlock(block_name)
        if block is None:
            return {"block_present": False}
        actual, count = _read_memory_buffer(ctx.program, block.getStart(), length)
        source_after = None
        if source_before is not None:
            source_after, source_count = _read_memory_buffer(
                ctx.program, source, source_length)
            if source_count != source_length:
                raise ValueError("Source read-back is incomplete")
        physical_after = None
        if physical_before is not None:
            physical_after, physical_count = _read_memory_buffer(
                ctx.program, start, length)
            if physical_count != length:
                raise ValueError("Physical read-back is incomplete")
        return {"block_present": True, "name": str(block.getName()),
                "start": str(block.getStart()), "length": int(block.getSize()),
                "overlay": bool(block.isOverlay()),
                "initialized": bool(block.isInitialized()),
                "sha256": hashlib.sha256(actual).hexdigest() if count == length else None,
                "comment": str(block.getComment()),
                "source_bytes_preserved": source_after == source_before,
                "physical_bytes_preserved": physical_after == physical_before}

    def validate(stored: Dict[str, Any]) -> Optional[str]:
        if (not stored.get("block_present") or not stored.get("overlay") or
                not stored.get("initialized") or stored.get("length") != length or
                stored.get("sha256") != digest or stored.get("comment") != comment or
                not stored.get("source_bytes_preserved") or
                not stored.get("physical_bytes_preserved")):
            return "Recovered overlay, provenance, or original-byte read-back mismatch"
        block = mem.getBlock(block_name)
        if (block is None or str(block.getSourceName()) != _ANALYSIS_BLOCK_SOURCE or
                not block.isRead() or block.isWrite() or not block.isExecute()):
            return "Recovered overlay permissions or deletion provenance mismatch"
        return None

    result = _run_mutation_transaction(
        ctx, operation, "Create recovered code overlay", requested, old,
        apply, read_back, validate,
        validate_rollback=lambda state: (
            None if mem.getBlock(block_name) is None else
            "Rollback left recovered overlay present"))
    result["preview"] = preview
    return result


__all__ = [
    "_byte_state",
    "write_memory_bytes",
    "set_data_label",
    "_data_application_result",
    "_data_application_state",
    "_read_application_bytes",
    "apply_data_type",
    "set_program_image_base",
    "set_memory_block_permissions",
    "create_memory_block",
    "delete_memory_block",
    "create_recovered_code_overlay",
]
