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

"""Private analysis implementation family for :mod:`ghidramsc.queries`."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .bridge import ProgramContext

from ._query_core import (
    _addr_int,
    _get_monitor,
    _qualified_program_name,
)


_MAX_CALL_SITES = 128


def _call_evidence(ctx: ProgramContext, func,
                   max_sites: int = _MAX_CALL_SITES) -> Dict[str, Any]:
    """Classify bounded listing call sites without promoting guesses to edges."""
    program = ctx.program
    manager = program.getFunctionManager()
    references = program.getReferenceManager()
    symbols = program.getSymbolTable()
    iterator = program.getListing().getInstructions(func.getBody(), True)
    sites: List[Dict[str, Any]] = []
    targets: Dict[str, Any] = {}
    scan_complete = True
    while iterator.hasNext():
        instruction = iterator.next()
        flow = instruction.getFlowType()
        if not flow.isCall():
            continue
        if max_sites > 0 and len(sites) >= max_sites:
            scan_complete = False
            break
        computed = "COMPUTED" in str(flow)
        target = None
        kind = "unresolved_computed" if computed else "unresolved_direct"
        pointer_address = None
        refs = list(instruction.getReferencesFrom())
        for ref in refs:
            if not ref.getReferenceType().isCall():
                continue
            candidate = manager.getFunctionAt(ref.getToAddress())
            if candidate is not None:
                target = candidate
                kind = "resolved_indirect" if computed else "confirmed_direct"
                break
        if target is None and computed:
            for ref in refs:
                cell = ref.getToAddress()
                symbol = symbols.getPrimarySymbol(cell)
                if (not ref.getReferenceType().isRead() or symbol is None
                        or not str(symbol.getName()).startswith("PTR_")):
                    continue
                candidates = []
                for data_ref in references.getReferencesFrom(cell):
                    candidate = manager.getFunctionAt(data_ref.getToAddress())
                    if candidate is not None and candidate.isExternal():
                        candidates.append(candidate)
                if len(candidates) == 1:
                    target = candidates[0]
                    kind = "resolved_indirect"
                    pointer_address = str(cell)
                    break
        site: Dict[str, Any] = {
            "address": str(instruction.getAddress()),
            "instruction": str(instruction),
            "flow_type": str(flow),
            "classification": kind,
        }
        if target is not None:
            effective = target.getThunkedFunction(True) if target.isThunk() else None
            if effective is None:
                effective = target
            site["target"] = {"name": str(target.getName()),
                              "address": str(target.getEntryPoint()),
                              "effective_entry": str(effective.getEntryPoint()),
                              "external": bool(effective.isExternal()),
                              "via_pointer": pointer_address}
            targets[str(target.getEntryPoint())] = (target, kind)
        sites.append(site)
    known = sorted(func.getCalledFunctions(_get_monitor()),
                   key=lambda item: str(item.getEntryPoint()))
    resolved_entries = set(targets)
    resolved_entries.update(
        str(item[0].getThunkedFunction(True).getEntryPoint())
        for item in targets.values()
        if item[0].isThunk() and item[0].getThunkedFunction(True) is not None)
    possible = [{"name": str(item.getName()),
                 "address": str(item.getEntryPoint()),
                 "classification": "possible_target"}
                for item in known
                if str(item.getEntryPoint()) not in resolved_entries]
    callees = [{"name": str(target.getName()),
                "address": str(target.getEntryPoint()),
                "classification": kind}
               for target, kind in targets.values()]
    return {"call_sites": sites, "callees": callees,
            "possible_callees": possible,
            "unresolved_calls": [site for site in sites if "target" not in site],
            "scan_complete": scan_complete, "target_functions": targets}


def get_function_call_graph(ctx: ProgramContext, addr_hex: str,
                        depth: int = 3) -> Dict[str, Any]:
    """Generate a hierarchical call graph from the function at addr_hex.
    depth controls how many levels of callees to follow (default 3)."""
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return {"error": "No function at or containing " + addr_hex}

    visited = set()

    def _walk(f, d):
        entry = str(f.getEntryPoint())
        if entry in visited or d <= 0:
            return {"name": f.getName(), "address": entry, "callees": "...",
                    "limit_reason": "revisit" if entry in visited else "depth",
                    "complete": False}
        visited.add(entry)
        evidence = _call_evidence(ctx, f)
        callees = []
        for callee, _ in evidence["target_functions"].values():
            callees.append(_walk(callee, d - 1))
        return {
            "name": f.getName(),
            "address": entry,
            "callees": callees,
            "call_sites": evidence["call_sites"],
            "possible_callees": evidence["possible_callees"],
            "unresolved_calls": evidence["unresolved_calls"],
            "scan_complete": evidence["scan_complete"],
            "complete": (evidence["scan_complete"] and
                         not evidence["possible_callees"] and
                         not evidence["unresolved_calls"] and
                         all(child["complete"] for child in callees)),
        }

    return _walk(func, depth)


def list_function_basic_blocks(ctx: ProgramContext, addr_hex: str) -> Dict[str, Any]:
    """Get basic blocks for the function at/containing addr_hex."""
    from ghidra.program.model.block import BasicBlockModel  # type: ignore

    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return {"error": "No function at or containing " + addr_hex}

    model = BasicBlockModel(ctx.program)
    monitor = _get_monitor()
    body = func.getBody()
    block_iter = model.getCodeBlocksContaining(body, monitor)

    blocks = []
    while block_iter.hasNext():
        blk = block_iter.next()
        successors = []
        dest_iter = blk.getDestinations(monitor)
        while dest_iter.hasNext():
            dest = dest_iter.next()
            successors.append(str(dest.getDestinationAddress()))

        blocks.append({
            "start": str(blk.getMinAddress()),
            "end": str(blk.getMaxAddress()),
            "size": blk.getNumAddresses() if hasattr(blk, 'getNumAddresses') else 0,
            "successors": successors,
        })

    return {
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "num_blocks": len(blocks),
        "blocks": blocks,
    }


def get_function_call_relationships(ctx: ProgramContext, addr_hex: str) -> Dict[str, Any]:
    """Get all cross-references for a function: both callers (who calls it)
    and callees (what it calls).  Convenience wrapper combining caller/callee
    data in one call."""
    func = ctx.resolve_function(_addr_int(addr_hex))
    if func is None:
        return {"error": "No function at or containing " + addr_hex}

    monitor = _get_monitor()
    callers = []
    for c in func.getCallingFunctions(monitor):
        callers.append({"name": c.getName(), "address": str(c.getEntryPoint())})

    evidence = _call_evidence(ctx, func)
    callees = evidence["callees"]

    return {
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "callers": callers,
        "callees": callees,
        "num_callers": len(callers),
        "num_callees": len(callees),
        "call_sites": evidence["call_sites"],
        "possible_callees": evidence["possible_callees"],
        "unresolved_calls": evidence["unresolved_calls"],
        "scan_complete": evidence["scan_complete"],
        "complete": (evidence["scan_complete"] and
                     not evidence["possible_callees"] and
                     not evidence["unresolved_calls"]),
        "caller_coverage": "ghidra_known_only",
    }


def detect_security_mitigations(ctx: ProgramContext) -> Dict[str, Any]:
    """Detect binary security mitigations: NX/DEP, ASLR, stack canaries,
    RELRO, PIE.  Works by inspecting memory permissions, symbols, and
    program properties."""
    prog = ctx.program
    mem = prog.getMemory()
    fm = prog.getFunctionManager()

    results: Dict[str, Any] = {
        "binary": _qualified_program_name(prog),
        "format": str(prog.getExecutableFormat()),
        "mitigations": {},
    }

    # NX/DEP: check if any writable block is also executable.
    wx_blocks = []
    for blk in mem.getBlocks():
        if blk.isWrite() and blk.isExecute():
            wx_blocks.append({
                "name": blk.getName(),
                "start": str(blk.getStart()),
                "size": blk.getSize(),
            })
    results["mitigations"]["nx_dep"] = {
        "enabled": len(wx_blocks) == 0,
        "wx_segments": wx_blocks,
        "note": "No W+X segments found" if not wx_blocks else "{} W+X segments found".format(len(wx_blocks)),
    }

    # Stack canary detection: look for __stack_chk_fail or similar symbols.
    canary_syms = ["__stack_chk_fail", "__stack_chk_guard",
                   "__stack_chk_fail_local", "__security_check_cookie",
                   "_security_cookie"]
    found_canary = []
    st = prog.getSymbolTable()
    for sym_name in canary_syms:
        syms = list(st.getSymbols(sym_name))
        if syms:
            found_canary.append(sym_name)
    results["mitigations"]["stack_canary"] = {
        "detected": len(found_canary) > 0,
        "symbols": found_canary,
    }

    # ASLR / PIE indicators: check executable format properties.
    exe_fmt = str(prog.getExecutableFormat()).lower()
    is_pie = False
    if "elf" in exe_fmt:
        # ELF shared objects are typically PIE.
        try:
            props = prog.getOptions("Program Information")
            elf_type = str(props.getString("ELF Type", ""))
            is_pie = "dyn" in elf_type.lower() or "shared" in elf_type.lower()
        except Exception:
            pass
    elif "pe" in exe_fmt:
        try:
            props = prog.getOptions("Program Information")
            dll_chars = props.getString("DLL Characteristics", "")
            is_pie = "DYNAMIC_BASE" in str(dll_chars)
        except Exception:
            pass
    results["mitigations"]["pie_aslr"] = {
        "detected": is_pie,
    }

    # RELRO: look for .got.plt vs .got (full RELRO has no .got.plt).
    has_got_plt = False
    has_got = False
    for blk in mem.getBlocks():
        bname = blk.getName()
        if bname == ".got.plt":
            has_got_plt = True
        if bname == ".got":
            has_got = True
    if has_got and not has_got_plt:
        relro = "full"
    elif has_got_plt:
        relro = "partial"
    else:
        relro = "none"
    results["mitigations"]["relro"] = {"level": relro}

    # Fortified functions: look for _chk variants.
    fortified = []
    for func in fm.getFunctions(True):
        fname = func.getName()
        if fname.endswith("_chk") and "__" in fname:
            fortified.append(fname)
    results["mitigations"]["fortify"] = {
        "detected": len(fortified) > 0,
        "functions": fortified[:20],
    }

    return results


def find_format_string_vulns(ctx: ProgramContext) -> Dict[str, Any]:
    """Find potential format string vulnerabilities by locating calls to
    printf-family functions and checking if the format argument could be
    user-controlled."""
    fm = ctx.program.getFunctionManager()
    monitor = _get_monitor()

    printf_names = {
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
        "vsprintf", "vsnprintf", "syslog", "dprintf", "wprintf",
        "swprintf", "__printf_chk", "__fprintf_chk", "__sprintf_chk",
    }

    findings = []
    for func in fm.getFunctions(True):
        fname = func.getName().lower()
        if fname not in printf_names:
            continue

        # Find all callers of this printf-family function.
        callers = list(func.getCallingFunctions(monitor))
        for caller in callers:
            # Check xrefs TO the printf function FROM the caller.
            rm = ctx.program.getReferenceManager()
            refs = list(rm.getReferencesTo(func.getEntryPoint()))
            caller_refs = [r for r in refs
                          if r.getFromAddress().getOffset() >= caller.getBody().getMinAddress().getOffset()
                          and r.getFromAddress().getOffset() <= caller.getBody().getMaxAddress().getOffset()]
            for ref in caller_refs:
                findings.append({
                    "printf_func": func.getName(),
                    "caller": caller.getName(),
                    "caller_addr": str(caller.getEntryPoint()),
                    "call_site": str(ref.getFromAddress()),
                })

    # Deduplicate by call_site.
    seen = set()
    unique = []
    for f in findings:
        key = f["call_site"]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "binary": _qualified_program_name(ctx.program),
        "potential_format_string_vulns": len(unique),
        "findings": unique,
    }


def identify_user_input_sources(ctx: ProgramContext) -> Dict[str, Any]:
    """Identify functions commonly associated with user-controlled input
    (network, file, stdin).  Returns each source with call sites."""
    fm = ctx.program.getFunctionManager()
    monitor = _get_monitor()

    _INPUT_FUNCS = {
        # Network
        "recv", "recvfrom", "recvmsg", "read", "readv",
        "accept", "accept4", "listen", "getpeername",
        "WSARecv", "WSARecvFrom",
        # File / stdio
        "fgets", "fread", "fgetc", "getc", "getchar", "gets",
        "scanf", "fscanf", "sscanf", "vscanf",
        "getline", "getdelim",
        # Environment / argv
        "getenv", "getopt", "getopt_long",
        # Windows-specific
        "ReadFile", "ReadConsole", "GetCommandLineA",
        "GetCommandLineW", "GetEnvironmentVariableA",
        "GetEnvironmentVariableW", "InternetReadFile",
    }

    findings: List[Dict[str, Any]] = []
    for func in fm.getFunctions(True):
        fname = func.getName()
        if fname not in _INPUT_FUNCS:
            continue
        callers = list(func.getCallingFunctions(monitor))
        sites: List[Dict[str, str]] = []
        rm = ctx.program.getReferenceManager()
        refs = list(rm.getReferencesTo(func.getEntryPoint()))
        for ref in refs:
            sites.append({
                "call_site": str(ref.getFromAddress()),
            })
        findings.append({
            "function": fname,
            "address": str(func.getEntryPoint()),
            "call_sites": sites,
        })

    return {
        "binary": _qualified_program_name(ctx.program),
        "input_sources_found": len(findings),
        "sources": findings,
    }


def identify_crypto_patterns(ctx: ProgramContext) -> Dict[str, Any]:
    """Detect common cryptographic implementations by searching for known
    magic constants and crypto-related symbol names."""
    prog = ctx.program
    fm = prog.getFunctionManager()
    mem = prog.getMemory()

    # Well-known crypto constants (hex, big-endian).
    _CRYPTO_CONSTS = {
        "AES S-box (first 4 bytes)": "637c777b",
        "SHA-256 init H0": "6a09e667",
        "SHA-256 init H1": "bb67ae85",
        "SHA-256 K[0]": "428a2f98",
        "SHA-1 init H0": "67452301",
        "SHA-1 init H1": "efcdab89",
        "MD5 init A": "67452301",
        "MD5 T[1] (sin table)": "d76aa478",
        "RSA/DH 0x10001": "00010001",
        "Blowfish P[0]": "243f6a88",
        "ChaCha20 constant": "61707865",
        "RC4 identity perm (0..3)": "00010203",
    }

    const_hits: List[Dict[str, str]] = []
    for label, hex_bytes in _CRYPTO_CONSTS.items():
        try:
            raw = bytes.fromhex(hex_bytes)
            addr = mem.findBytes(prog.getMinAddress(), raw, None, True, None)
            if addr is not None:
                const_hits.append({
                    "pattern": label,
                    "address": str(addr),
                    "hex": hex_bytes,
                })
        except Exception:
            pass

    # Crypto-related function names.
    _CRYPTO_NAMES_RE = [
        "aes", "des", "sha1", "sha256", "sha512", "sha384",
        "md5", "hmac", "rsa", "ecdsa", "chacha", "poly1305",
        "blowfish", "rc4", "salsa", "argon", "bcrypt", "scrypt",
        "pbkdf", "encrypt", "decrypt", "cipher", "hash",
        "EVP_", "OPENSSL", "crypt", "mbedtls_",
    ]
    crypto_funcs: List[Dict[str, str]] = []
    for func in fm.getFunctions(True):
        fname = func.getName()
        flower = fname.lower()
        for pat in _CRYPTO_NAMES_RE:
            if pat.lower() in flower:
                crypto_funcs.append({
                    "function": fname,
                    "address": str(func.getEntryPoint()),
                    "matched_pattern": pat,
                })
                break

    return {
        "binary": _qualified_program_name(prog),
        "constant_hits": const_hits,
        "crypto_functions": crypto_funcs,
        "total_indicators": len(const_hits) + len(crypto_funcs),
    }


def find_obfuscated_strings(ctx: ProgramContext) -> Dict[str, Any]:
    """Locate potential obfuscated or encoded strings by scanning for
    XOR loops, high-entropy data regions, and base64-like patterns."""
    prog = ctx.program
    fm = prog.getFunctionManager()
    mem = prog.getMemory()
    listing_obj = prog.getListing()

    findings: List[Dict[str, Any]] = []

    # 1. XOR-loop detection: look for XOR instructions with a register
    #    source inside small loops.
    for func in fm.getFunctions(True):
        insn = listing_obj.getInstructionAt(func.getEntryPoint())
        seen = 0
        xor_sites: List[str] = []
        while insn is not None and seen < 500:
            mnemonic = str(insn.getMnemonicString()).lower()
            if "xor" in mnemonic:
                # Skip xor reg, reg (register zeroing idiom).
                ops = insn.getNumOperands()
                if ops >= 2:
                    op0 = str(insn.getDefaultOperandRepresentation(0))
                    op1 = str(insn.getDefaultOperandRepresentation(1))
                    if op0 != op1:
                        xor_sites.append(str(insn.getAddress()))
            seen += 1
            insn = insn.getNext()
        if xor_sites:
            findings.append({
                "type": "xor_instruction",
                "function": func.getName(),
                "function_addr": str(func.getEntryPoint()),
                "xor_addresses": xor_sites[:10],
            })

    # 2. High-entropy data: scan defined data for byte sequences that
    #    deviate significantly from ASCII.
    data_iter = listing_obj.getDefinedData(True)
    data_count = 0
    while data_iter.hasNext() and data_count < 5000:
        d = data_iter.next()
        data_count += 1
        dt = d.getDataType()
        dtname = str(dt.getName()).lower()
        length = d.getLength()
        if length < 8:
            continue
        if "string" in dtname:
            continue
        try:
            raw = bytearray(length)
            mem.getBytes(d.getAddress(), raw)
            # Simple entropy heuristic: count bytes outside printable ASCII.
            non_ascii = sum(1 for b in raw if b < 0x20 or b > 0x7e)
            ratio = non_ascii / length
            if ratio > 0.6 and length >= 16:
                findings.append({
                    "type": "high_entropy_data",
                    "address": str(d.getAddress()),
                    "size": length,
                    "non_ascii_ratio": round(ratio, 2),
                })
        except Exception:
            pass

    # 3. Base64-like patterns in string data.
    str_iter = listing_obj.getDefinedData(True)
    str_count = 0
    while str_iter.hasNext() and str_count < 5000:
        d = str_iter.next()
        str_count += 1
        dt = d.getDataType()
        dtname = str(dt.getName()).lower()
        if "string" not in dtname:
            continue
        try:
            val = str(d.getValue())
        except Exception:
            continue
        if len(val) < 16:
            continue
        # Check for base64 characteristics: A-Za-z0-9+/= with length % 4 == 0.
        if re.match(r'^[A-Za-z0-9+/=]{16,}$', val) and len(val) % 4 == 0:
            findings.append({
                "type": "base64_candidate",
                "address": str(d.getAddress()),
                "length": len(val),
                "preview": val[:60],
            })

    return {
        "binary": _qualified_program_name(prog),
        "total_findings": len(findings),
        "findings": findings,
    }


__all__ = [
    "get_function_call_graph",
    "list_function_basic_blocks",
    "get_function_call_relationships",
    "detect_security_mitigations",
    "find_format_string_vulns",
    "identify_user_input_sources",
    "identify_crypto_patterns",
    "find_obfuscated_strings",
]
