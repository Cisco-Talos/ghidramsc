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

"""Private core implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from .bridge import ProgramContext


def _addr_int(hex_str: str) -> int | str:
    """Parse bare hex, or retain an exact Ghidra-qualified space address."""
    if "::" in hex_str:
        if re.fullmatch(r"[^:\s]+::(?:0[xX])?[0-9a-fA-F]+", hex_str) is None:
            raise ValueError("Invalid qualified address: " + hex_str)
        return hex_str
    return int(hex_str, 16)


def _read_memory_buffer(program: Any, addr: Any, length: int) -> tuple[bytes, int]:
    """Read Ghidra bytes through a writable Java array in a live JVM.

    JPype converts a Python ``bytearray`` argument to a Java array by copy, so
    Ghidra's ``getBytes`` writes never reach the original Python buffer.
    Lightweight tests without a JVM retain a mutable Python buffer.
    """
    import jpype

    # DataType.getLength() can return a JPype JInt. JArray's constructor
    # accepts the same value only after conversion to a native Python int.
    length = int(length)
    buffer = (jpype.JArray(jpype.JByte)(length)
              if jpype.isJVMStarted() else bytearray(length))
    actual = program.getMemory().getBytes(addr, buffer)
    if actual <= 0:
        return b"", actual
    return bytes(int(value) & 0xff for value in buffer[:actual]), actual


def _qualified_program_name(program: Any) -> str:
    """Return the project-relative identity accepted by ``binary``.

    Ghidra domain paths use a leading slash.  Public program identities do
    not, and always use forward slashes so values can round-trip unchanged
    across operating systems and execution modes.
    """
    try:
        domain_file = program.getDomainFile()
        if domain_file is not None:
            pathname = str(domain_file.getPathname()).replace("\\", "/")
            if pathname.startswith("/"):
                qualified = pathname.lstrip("/")
                parts = qualified.split("/")
                if qualified and all(part not in ("", ".", "..") for part in parts):
                    return qualified
    except Exception:
        pass
    return str(program.getName())


def _java_isinstance(value: Any, java_type: Any,
                     fallback_method: str) -> bool:
    """Support real PyGhidra types and lightweight mocked Java interfaces."""
    try:
        return isinstance(value, java_type)
    except TypeError:
        return hasattr(value, fallback_method)


def _resolve_type(program, type_name: str):
    """Resolve a data type by name.  Supports pointer syntax (e.g. 'char *')
    and common C type names."""
    from ghidra.program.model.data import (  # type: ignore
        PointerDataType, IntegerDataType, UnsignedIntegerDataType,
        CharDataType, ShortDataType,
        UnsignedShortDataType, LongDataType, UnsignedLongDataType,
        BooleanDataType, VoidDataType, Undefined4DataType,
        Undefined1DataType, Undefined2DataType,
    )

    try:
        from ghidra.util.data import DataTypeParser  # type: ignore
        dtm = program.getDataTypeManager()
        parser = DataTypeParser(
            dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL
        )
        parsed = parser.parse(type_name.strip())
        if parsed is not None:
            return parsed
    except Exception:
        pass

    name = type_name.strip()
    ptr_depth = 0
    while name.endswith("*"):
        ptr_depth += 1
        name = name[:-1].strip()

    quick = {
        "int":             IntegerDataType.dataType,
        "uint":            UnsignedIntegerDataType.dataType,
        "uint32_t":        UnsignedIntegerDataType.dataType,
        "int32_t":         IntegerDataType.dataType,
        "unsigned int":    UnsignedIntegerDataType.dataType,
        "char":            CharDataType.dataType,
        "uchar":           CharDataType.dataType,
        "uint8_t":         CharDataType.dataType,
        "int8_t":          CharDataType.dataType,
        "unsigned char":   CharDataType.dataType,
        "byte":            CharDataType.dataType,
        "short":           ShortDataType.dataType,
        "ushort":          UnsignedShortDataType.dataType,
        "uint16_t":        UnsignedShortDataType.dataType,
        "int16_t":         ShortDataType.dataType,
        "unsigned short":  UnsignedShortDataType.dataType,
        "long":            LongDataType.dataType,
        "ulong":           UnsignedLongDataType.dataType,
        "unsigned long":   UnsignedLongDataType.dataType,
        "bool":            BooleanDataType.dataType,
        "void":            VoidDataType.dataType,
        "undefined4":      Undefined4DataType.dataType,
        "undefined1":      Undefined1DataType.dataType,
        "undefined2":      Undefined2DataType.dataType,
        "size_t":          UnsignedIntegerDataType.dataType,
    }

    dt = quick.get(name.lower())

    if dt is None:
        dtm = program.getDataTypeManager()
        for candidate in dtm.getAllDataTypes():
            cname = candidate.getName()
            if cname == name or cname.lower() == name.lower():
                dt = candidate
                break

    if dt is None:
        from ghidra.program.model.data import BuiltInDataTypeManager  # type: ignore
        builtin = BuiltInDataTypeManager.getDataTypeManager()
        for candidate in builtin.getAllDataTypes():
            cname = candidate.getName()
            if cname == name or cname.lower() == name.lower():
                dt = candidate
                break

    if dt is None:
        return None

    for _ in range(ptr_depth):
        dt = PointerDataType(dt)

    return dt


def _get_decompiler(program):
    """Return a configured DecompInterface.  Caller must call dispose()."""
    from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
    d = DecompInterface()
    d.setOptions(DecompileOptions())
    d.openProgram(program)
    return d


def _get_monitor():
    """Return a TaskMonitor suitable for headless use."""
    from ghidra.util.task import TaskMonitor  # type: ignore
    return TaskMonitor.DUMMY


_MISSING = object()


def _mutation_contract_result(
    operation: str,
    status: str,
    requested: Dict[str, Any],
    *,
    old: Any = _MISSING,
    stored: Any = _MISSING,
    error: str = "",
    transaction_description: str = "",
    transaction_started: bool = False,
    transaction_committed: bool = False,
    read_back_error: str = "",
) -> Dict[str, Any]:
    """Build the shared Python/Java mutation result envelope."""
    result: Dict[str, Any] = {
        "operation": operation,
        "status": status,
        "requested": requested,
    }
    if old is not _MISSING:
        result["old"] = old
    if stored is not _MISSING:
        result["stored"] = stored
    if error:
        result["error"] = error
    transaction = {
        "started": transaction_started,
        "committed": transaction_committed,
    }
    if transaction_description:
        transaction["description"] = transaction_description
    result["transaction"] = transaction
    if read_back_error:
        result["read_back_error"] = read_back_error
    return result


def _mutation_validation_failure(
    operation: str, requested: Dict[str, Any], error: str
) -> Dict[str, Any]:
    return _mutation_contract_result(
        operation, "validation_failed", requested, error=error
    )


def _mutation_no_change(
    operation: str, requested: Dict[str, Any], old: Any
) -> Dict[str, Any]:
    return _mutation_contract_result(
        operation, "no_change", requested, old=old, stored=old
    )


def _batch_mutation_result(
    operation: str, requested: Any, items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Build the shared per-item batch result used by both runtimes."""
    succeeded = sum(item.get("status") == "success" for item in items)
    unchanged = sum(item.get("status") == "no_change" for item in items)
    failed = len(items) - succeeded - unchanged
    if failed == 0:
        status = "no_change" if succeeded == 0 else "success"
    elif succeeded or unchanged:
        status = "partial_success"
    else:
        status = "validation_failed"
    result = _mutation_contract_result(operation, status, requested)
    result.update({
        "atomicity": "per_item",
        "succeeded": succeeded,
        "unchanged": unchanged,
        "failed": failed,
        "total": len(items),
        "items": items,
    })
    return result


def _start_mutation_transaction(ctx: ProgramContext, description: str) -> int:
    """Use isolated project transactions for real contexts and mocks alike."""
    if isinstance(ctx, ProgramContext):
        return ctx.start_mutation_transaction(description)
    return ctx.program.startTransaction(description)


def _end_mutation_transaction(ctx: ProgramContext, transaction_id: int,
                              commit: bool) -> None:
    if isinstance(ctx, ProgramContext):
        ctx.end_mutation_transaction(transaction_id, commit)
        return
    ctx.program.endTransaction(transaction_id, commit)


def _run_mutation_transaction(
    ctx: ProgramContext,
    operation: str,
    description: str,
    requested: Dict[str, Any],
    old: Any,
    apply: Callable[[], None],
    read_back: Callable[[], Any],
    validate_stored: Callable[[Any], Optional[str]],
    rollback_read_back: Optional[Callable[[], Any]] = None,
    validate_rollback: Optional[Callable[[Any], Optional[str]]] = None,
) -> Dict[str, Any]:
    """Run one atomic edit and return its verified public result."""
    tx_id = _start_mutation_transaction(ctx, description)
    committed = False
    stored: Any = _MISSING
    error = ""
    try:
        apply()
        stored = read_back()
        mismatch = validate_stored(stored)
        if mismatch:
            raise ValueError(mismatch)
        committed = True
    except Exception as exc:
        error = str(exc) or type(exc).__name__
    finally:
        _end_mutation_transaction(ctx, tx_id, committed)

    if committed:
        return _mutation_contract_result(
            operation,
            "success",
            requested,
            old=old,
            stored=stored,
            transaction_description=description,
            transaction_started=True,
            transaction_committed=True,
        )

    read_back_error = ""
    try:
        stored = (
            rollback_read_back() if rollback_read_back is not None
            else read_back()
        )
    except Exception as exc:
        stored = _MISSING
        read_back_error = str(exc) or type(exc).__name__
    rollback_error = ""
    if validate_rollback is not None:
        if read_back_error:
            rollback_error = "Rollback state could not be read back"
        else:
            try:
                rollback_error = validate_rollback(stored) or ""
            except Exception as exc:
                rollback_error = str(exc) or type(exc).__name__
    if rollback_error:
        error = "{}; rollback verification failed: {}".format(
            error, rollback_error
        )
    return _mutation_contract_result(
        operation,
        "failed" if rollback_error else "rolled_back",
        requested,
        old=old,
        stored=stored,
        error=error,
        transaction_description=description,
        transaction_started=True,
        transaction_committed=False,
        read_back_error=read_back_error,
    )


def get_cursor_address(ctx: ProgramContext) -> Dict[str, Any]:
    """Get the current cursor address in the Ghidra GUI (GUI mode only)."""
    raise RuntimeError(
        "get_cursor_address is only available in GUI mode "
        "(--mode gui).  In headless mode there is no GUI cursor."
    )


def get_function_at_cursor(ctx: ProgramContext) -> Dict[str, Any]:
    """Get the function at the current cursor position (GUI mode only)."""
    raise RuntimeError(
        "get_function_at_cursor is only available in GUI mode "
        "(--mode gui).  In headless mode there is no GUI cursor."
    )


def get_gui_selection(ctx: ProgramContext) -> Dict[str, Any]:
    """Get the current selection range in the Ghidra GUI (GUI mode only)."""
    raise RuntimeError(
        "get_gui_selection is only available in GUI mode "
        "(--mode gui).  In headless mode there is no GUI selection."
    )


def set_cursor_address(ctx: ProgramContext, addr_hex: str) -> str:
    """Move the Ghidra GUI cursor to an address (GUI mode only)."""
    raise RuntimeError(
        "set_cursor_address is only available in GUI mode "
        "(--mode gui).  In headless mode there is no GUI to navigate."
    )


def undo_gui_transaction(ctx: ProgramContext) -> str:
    """Undo the last transaction on the program (GUI mode only)."""
    raise RuntimeError(
        "undo_gui_transaction is only available in GUI mode "
        "(--mode gui).  In headless mode there is no undo support."
    )


__all__ = [
    "_addr_int",
    "_read_memory_buffer",
    "_qualified_program_name",
    "_java_isinstance",
    "_resolve_type",
    "_get_decompiler",
    "_get_monitor",
    "_MISSING",
    "_mutation_contract_result",
    "_mutation_validation_failure",
    "_mutation_no_change",
    "_batch_mutation_result",
    "_start_mutation_transaction",
    "_end_mutation_transaction",
    "_run_mutation_transaction",
    "get_cursor_address",
    "get_function_at_cursor",
    "get_gui_selection",
    "set_cursor_address",
    "undo_gui_transaction",
]
