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

"""Private program implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

import json
from typing import Any, Dict

from .bridge import ProgramContext

from ._query_core import (
    _qualified_program_name,
)


def _program_persistence_state(program) -> Dict[str, Any]:
    """Return the stable identity and persistence state for *program*."""
    state: Dict[str, Any] = {
        "program": _qualified_program_name(program),
        "dirty": bool(program.isChanged()),
        "can_save": bool(program.canSave()),
    }
    domain_file = program.getDomainFile()
    if domain_file is not None:
        state["path"] = str(domain_file.getPathname())
    return state


def get_program_save_state(ctx: ProgramContext) -> Dict[str, Any]:
    """Return whether the program has unsaved changes and can be saved."""
    return _program_persistence_state(ctx.program)


def save_program(ctx: ProgramContext,
                 comment: str = "Saved by GhidraMSC") -> Dict[str, Any]:
    """Explicitly persist pending program changes and verify clean state."""
    program = ctx.program
    old = _program_persistence_state(program)
    requested = {"comment": comment}
    save = {
        "attempted": False,
        "completed": False,
        "succeeded": False,
        "backend": ctx.save_backend,
        "completion_observed": True,
        "comment_supported": ctx.save_comment_supported,
        "comment_applied": False,
    }
    if not old["can_save"]:
        return {
            "operation": "save_program",
            "status": "validation_failed",
            "program": old["program"],
            "old": old,
            "requested": requested,
            "stored": _program_persistence_state(program),
            "save": save,
            "error": "Program cannot be saved",
        }
    if not old["dirty"]:
        save["completed"] = True
        return {
            "operation": "save_program",
            "status": "no_change",
            "program": old["program"],
            "old": old,
            "requested": requested,
            "stored": dict(old),
            "save": save,
        }

    save["attempted"] = True
    try:
        ctx.save(comment)
    except Exception as exc:
        return {
            "operation": "save_program",
            "status": "failed",
            "program": old["program"],
            "old": old,
            "requested": requested,
            "stored": _program_persistence_state(program),
            "save": save,
            "error": "Save failed: {}".format(str(exc) or type(exc).__name__),
        }

    stored = _program_persistence_state(program)
    if stored["dirty"]:
        return {
            "operation": "save_program",
            "status": "failed",
            "program": old["program"],
            "old": old,
            "requested": requested,
            "stored": stored,
            "save": save,
            "error": "Program remains dirty after save",
        }
    save["succeeded"] = True
    save["completed"] = True
    save["comment_applied"] = ctx.save_comment_supported
    return {
        "operation": "save_program",
        "status": "success",
        "program": old["program"],
        "old": old,
        "requested": requested,
        "stored": stored,
        "save": save,
    }


def get_program_info(ctx: ProgramContext) -> Dict[str, Any]:
    """Return program metadata: architecture, compiler, format, image base,
    address ranges, endianness, pointer size, and more."""
    prog = ctx.program
    lang = prog.getLanguage()
    comp_spec = prog.getCompilerSpec()
    mem = prog.getMemory()

    info: Dict[str, Any] = {
        "binary": _qualified_program_name(prog),
        "image_base": str(prog.getImageBase()),
        "language_id": str(lang.getLanguageID()),
        "processor": str(lang.getProcessor()),
        "endianness": str(lang.isBigEndian() and "big" or "little"),
        "pointer_size": lang.getDefaultSpace().getPointerSize(),
        "address_size": lang.getDefaultSpace().getSize(),
        "compiler_spec": str(comp_spec.getCompilerSpecID()),
        "executable_format": str(prog.getExecutableFormat()),
        "executable_path": str(prog.getExecutablePath()),
        "min_address": str(mem.getMinAddress()),
        "max_address": str(mem.getMaxAddress()),
        "num_memory_blocks": len(mem.getBlocks()),
        "num_functions": prog.getFunctionManager().getFunctionCount(),
    }

    # Add creation/analysis dates if available.
    try:
        info["creation_date"] = str(prog.getCreationDate())
    except Exception:
        pass

    return info


def get_program_memory_map(ctx: ProgramContext) -> Dict[str, Any]:
    """Return the full memory layout: blocks with base addresses, sizes,
    and permissions (R/W/X).  Useful for identifying loadable segments,
    the image base, and executable regions."""
    prog = ctx.program
    mem = prog.getMemory()
    blocks_out = []
    for blk in mem.getBlocks():
        mapped_start = None
        mapped_end = None
        recovered_code = None
        comment = str(blk.getComment()) if blk.getComment() is not None else ""
        prefix = "GhidraMSC recovered code v1: "
        if comment.startswith(prefix):
            try:
                recovered_code = json.loads(comment[len(prefix):])
            except ValueError:
                recovered_code = None
        if blk.isMapped():
            for source_info in blk.getSourceInfos():
                mapped_range = source_info.getMappedRange()
                if mapped_range.isPresent():
                    mapped_start = str(mapped_range.get().getMinAddress())
                    mapped_end = str(mapped_range.get().getMaxAddress())
                    break
        source_name = blk.getSourceName()
        blocks_out.append({
            "name": blk.getName(),
            "start": str(blk.getStart()),
            "end": str(blk.getEnd()),
            "size": blk.getSize(),
            "read": bool(blk.isRead()),
            "write": bool(blk.isWrite()),
            "execute": bool(blk.isExecute()),
            "volatile": bool(blk.isVolatile()),
            "initialized": bool(blk.isInitialized()),
            "overlay": bool(blk.isOverlay()),
            "type": str(blk.getType()),
            "mapped_source_start": mapped_start,
            "mapped_source_end": mapped_end,
            "source": None if source_name is None else str(source_name),
            "recovered_code": recovered_code,
        })

    return {
        "binary": _qualified_program_name(prog),
        "image_base": str(prog.getImageBase()),
        "total_blocks": len(blocks_out),
        "blocks": blocks_out,
    }


def list_program_imports(ctx: ProgramContext) -> str:
    """List imported symbols and their addresses."""
    from ghidra.program.model.symbol import SymbolType  # type: ignore
    st = ctx.program.getSymbolTable()
    ext_syms = list(st.getExternalSymbols())
    lines = ["IMPORTS in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), len(ext_syms))]
    for sym in ext_syms:
        addr = sym.getAddress()
        lib = sym.getParentNamespace()
        lines.append("{}  {}  ({})".format(str(addr), sym.getName(), str(lib)))
    return "\n".join(lines)


def list_program_exports(ctx: ProgramContext) -> str:
    """List exported symbols and their addresses."""
    st = ctx.program.getSymbolTable()
    lines = []
    count = 0
    sym_iter = st.getAllSymbols(True)
    for sym in sym_iter:
        if sym.isExternalEntryPoint():
            lines.append("{}  {}".format(str(sym.getAddress()), sym.getName()))
            count += 1
    header = "EXPORTS in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), count)
    return header + "\n".join(lines)


def list_program_namespaces(ctx: ProgramContext) -> str:
    """List all namespaces (classes, libraries, categories)."""
    st = ctx.program.getSymbolTable()

    # Iterate all symbols and collect unique namespaces.
    seen = set()
    namespaces = []
    for sym in st.getAllSymbols(True):
        ns = sym.getParentNamespace()
        ns_name = str(ns)
        if ns_name not in seen:
            seen.add(ns_name)
            namespaces.append(ns_name)

    namespaces.sort()
    lines = ["NAMESPACES in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), len(namespaces))]
    lines.extend(namespaces)
    return "\n".join(lines)


def list_program_classes(ctx: ProgramContext) -> str:
    """List all class namespaces in the program."""
    from ghidra.program.model.symbol import SymbolType  # type: ignore
    st = ctx.program.getSymbolTable()
    classes = list(st.getClassNamespaces())
    lines = ["CLASSES in {} ({} total)\n".format(
        _qualified_program_name(ctx.program), len(classes))]
    for cls in classes:
        lines.append("  {}".format(str(cls.getName(True))))
    return "\n".join(lines)


def list_data_items(ctx: ProgramContext, offset: int = 0, limit: int = 500) -> str:
    """List defined data items (globals, constants, arrays, structs).
    Supports pagination via offset/limit."""
    prog_listing = ctx.program.getListing()
    data_iter = prog_listing.getDefinedData(True)
    lines = []
    idx = 0
    shown = 0
    while data_iter.hasNext():
        d = data_iter.next()
        if idx < offset:
            idx += 1
            continue
        if shown >= limit:
            break
        dt = d.getDataType()
        val = d.getDefaultValueRepresentation()
        label = ""
        sym = d.getPrimarySymbol()
        if sym is not None:
            label = sym.getName()
        lines.append("{}  {}  {}  {}".format(
            str(d.getAddress()), label, dt.getName(), val))
        idx += 1
        shown += 1

    header = "DATA in {} (showing {}, offset {})\n".format(
        _qualified_program_name(ctx.program), shown, offset)
    return header + "\n".join(lines)


def list_memory_blocks(ctx: ProgramContext) -> Dict[str, Any]:
    """Return segment/section details -- name, address, size, permissions.
    Similar to get_program_memory_map but focused on section-level info that
    maps to ELF sections / PE sections."""
    prog = ctx.program
    mem = prog.getMemory()
    segments = []
    for blk in mem.getBlocks():
        perms = ""
        if blk.isRead():
            perms += "R"
        if blk.isWrite():
            perms += "W"
        if blk.isExecute():
            perms += "X"
        segments.append({
            "name": blk.getName(),
            "start": str(blk.getStart()),
            "end": str(blk.getEnd()),
            "size": blk.getSize(),
            "permissions": perms,
            "initialized": bool(blk.isInitialized()),
            "type": str(blk.getType()),
        })
    return {
        "binary": _qualified_program_name(prog),
        "image_base": str(prog.getImageBase()),
        "segments": segments,
    }


__all__ = [
    "_program_persistence_state",
    "get_program_save_state",
    "save_program",
    "get_program_info",
    "get_program_memory_map",
    "list_program_imports",
    "list_program_exports",
    "list_program_namespaces",
    "list_program_classes",
    "list_data_items",
    "list_memory_blocks",
]
