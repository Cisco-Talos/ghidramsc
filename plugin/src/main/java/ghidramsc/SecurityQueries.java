// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ghidramsc;

import static ghidramsc.ProgramQueries.programName;
import static ghidramsc.QuerySupport.hexToBytes;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/** Read-only security indicators and heuristic findings. */
final class SecurityQueries {
    private SecurityQueries() { }

    // -----------------------------------------------------------------
    // detect_security_mitigations
    // -----------------------------------------------------------------

    static JsonElement detectSecurityMitigations(
            Program program, JsonObject args) {
        Memory mem = program.getMemory();
        FunctionManager fm = program.getFunctionManager();
        SymbolTable st = program.getSymbolTable();

        JsonObject out = new JsonObject();
        out.addProperty("binary", programName(program));
        out.addProperty("format", program.getExecutableFormat());
        JsonObject mitigations = new JsonObject();

        // NX / DEP
        JsonArray wxBlocks = new JsonArray();
        for (MemoryBlock blk : mem.getBlocks()) {
            if (blk.isWrite() && blk.isExecute()) {
                JsonObject bobj = new JsonObject();
                bobj.addProperty("name", blk.getName());
                bobj.addProperty("start",
                    blk.getStart().toString());
                bobj.addProperty("size", blk.getSize());
                wxBlocks.add(bobj);
            }
        }
        JsonObject nxDep = new JsonObject();
        nxDep.addProperty("enabled", wxBlocks.size() == 0);
        nxDep.add("wx_segments", wxBlocks);
        nxDep.addProperty("note", wxBlocks.size() == 0
            ? "No W+X segments found"
            : wxBlocks.size() + " W+X segments found");
        mitigations.add("nx_dep", nxDep);

        // Stack canary
        String[] canarySyms = {
            "__stack_chk_fail", "__stack_chk_guard",
            "__stack_chk_fail_local", "__security_check_cookie",
            "_security_cookie"
        };
        JsonArray foundCanary = new JsonArray();
        for (String symName : canarySyms) {
            SymbolIterator si = st.getSymbols(symName);
            if (si.hasNext()) {
                foundCanary.add(symName);
            }
        }
        JsonObject stackCanary = new JsonObject();
        stackCanary.addProperty("detected",
            foundCanary.size() > 0);
        stackCanary.add("symbols", foundCanary);
        mitigations.add("stack_canary", stackCanary);

        // PIE / ASLR
        boolean isPie = false;
        String exeFmt = program.getExecutableFormat().toLowerCase();
        if (exeFmt.contains("elf")) {
            try {
                var props = program.getOptions(
                    "Program Information");
                String elfType =
                    props.getString("ELF Type", "");
                isPie = elfType.toLowerCase().contains("dyn")
                    || elfType.toLowerCase().contains("shared");
            } catch (Exception e) { /* skip */ }
        } else if (exeFmt.contains("pe")) {
            try {
                var props = program.getOptions(
                    "Program Information");
                String dllChars = props.getString(
                    "DLL Characteristics", "");
                isPie = dllChars.contains("DYNAMIC_BASE");
            } catch (Exception e) { /* skip */ }
        }
        JsonObject pieAslr = new JsonObject();
        pieAslr.addProperty("detected", isPie);
        mitigations.add("pie_aslr", pieAslr);

        // RELRO
        boolean hasGotPlt = false;
        boolean hasGot = false;
        for (MemoryBlock blk : mem.getBlocks()) {
            if (".got.plt".equals(blk.getName())) hasGotPlt = true;
            if (".got".equals(blk.getName())) hasGot = true;
        }
        String relro = hasGot && !hasGotPlt ? "full"
            : hasGotPlt ? "partial" : "none";
        JsonObject relroObj = new JsonObject();
        relroObj.addProperty("level", relro);
        mitigations.add("relro", relroObj);

        // Fortified functions
        JsonArray fortified = new JsonArray();
        FunctionIterator funcIter = fm.getFunctions(true);
        int fortCount = 0;
        while (funcIter.hasNext() && fortCount < 50) {
            Function f = funcIter.next();
            String fname = f.getName();
            if (fname.endsWith("_chk")
                    && fname.contains("__")) {
                fortified.add(fname);
                fortCount++;
            }
        }
        JsonObject fortifyObj = new JsonObject();
        fortifyObj.addProperty("detected",
            fortified.size() > 0);
        fortifyObj.add("functions", fortified);
        mitigations.add("fortify", fortifyObj);

        out.add("mitigations", mitigations);
        return out;
    }

    // -----------------------------------------------------------------
    // find_format_string_vulns
    // -----------------------------------------------------------------

    static JsonElement findFormatStringVulns(
            Program program, JsonObject args) {
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();

        Set<String> printfNames = new HashSet<>();
        Collections.addAll(printfNames,
            "printf", "fprintf", "sprintf", "snprintf",
            "vprintf", "vfprintf", "vsprintf", "vsnprintf",
            "syslog", "dprintf", "wprintf", "swprintf",
            "__printf_chk", "__fprintf_chk", "__sprintf_chk");

        JsonArray findings = new JsonArray();
        Set<String> seenSites = new HashSet<>();

        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (!printfNames.contains(
                    func.getName().toLowerCase())) continue;

            var refIter =
                rm.getReferencesTo(func.getEntryPoint());
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                String callSite =
                    ref.getFromAddress().toString();
                if (seenSites.contains(callSite)) continue;
                seenSites.add(callSite);

                Function caller = fm.getFunctionContaining(
                    ref.getFromAddress());
                String callerName = caller != null
                    ? caller.getName() : "<unknown>";
                String callerAddr = caller != null
                    ? caller.getEntryPoint().toString() : "";

                JsonObject finding = new JsonObject();
                finding.addProperty("printf_func",
                    func.getName());
                finding.addProperty("caller", callerName);
                finding.addProperty("caller_addr", callerAddr);
                finding.addProperty("call_site", callSite);
                findings.add(finding);
            }
        }

        JsonObject out = new JsonObject();
        out.addProperty("binary", programName(program));
        out.addProperty("potential_format_string_vulns",
            findings.size());
        out.add("findings", findings);
        return out;
    }

    // -----------------------------------------------------------------
    // identify_user_input_sources
    // -----------------------------------------------------------------

    static JsonElement identifyUserInputSources(
            Program program, JsonObject args) {
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();

        Set<String> inputFuncs = new HashSet<>();
        Collections.addAll(inputFuncs,
            "recv", "recvfrom", "recvmsg", "read", "readv",
            "accept", "accept4", "listen", "getpeername",
            "WSARecv", "WSARecvFrom",
            "fgets", "fread", "fgetc", "getc", "getchar", "gets",
            "scanf", "fscanf", "sscanf", "vscanf",
            "getline", "getdelim",
            "getenv", "getopt", "getopt_long",
            "ReadFile", "ReadConsole",
            "GetCommandLineA", "GetCommandLineW",
            "GetEnvironmentVariableA",
            "GetEnvironmentVariableW",
            "InternetReadFile");

        JsonArray sources = new JsonArray();
        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (!inputFuncs.contains(func.getName())) continue;

            JsonArray sites = new JsonArray();
            var refIter =
                rm.getReferencesTo(func.getEntryPoint());
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                JsonObject site = new JsonObject();
                site.addProperty("call_site",
                    ref.getFromAddress().toString());
                Function caller = fm.getFunctionContaining(
                    ref.getFromAddress());
                if (caller != null) {
                    site.addProperty("caller",
                        caller.getName());
                }
                sites.add(site);
            }

            JsonObject src = new JsonObject();
            src.addProperty("function", func.getName());
            src.addProperty("address",
                func.getEntryPoint().toString());
            src.add("call_sites", sites);
            sources.add(src);
        }

        JsonObject out = new JsonObject();
        out.addProperty("binary", programName(program));
        out.addProperty("input_sources_found", sources.size());
        out.add("sources", sources);
        return out;
    }

    // -----------------------------------------------------------------
    // identify_crypto_patterns
    // -----------------------------------------------------------------

    static JsonElement identifyCryptoPatterns(
            Program program, JsonObject args) {
        Memory mem = program.getMemory();
        FunctionManager fm = program.getFunctionManager();

        // Known crypto constants
        String[][] cryptoConsts = {
            {"AES S-box (first 4 bytes)", "637c777b"},
            {"SHA-256 init H0", "6a09e667"},
            {"SHA-256 init H1", "bb67ae85"},
            {"SHA-256 K[0]", "428a2f98"},
            {"SHA-1 init H0", "67452301"},
            {"SHA-1 init H1", "efcdab89"},
            {"MD5 init A", "67452301"},
            {"MD5 T[1] (sin table)", "d76aa478"},
            {"RSA/DH 0x10001", "00010001"},
            {"Blowfish P[0]", "243f6a88"},
            {"ChaCha20 constant", "61707865"},
            {"RC4 identity perm (0..3)", "00010203"},
        };

        JsonArray constHits = new JsonArray();
        for (String[] entry : cryptoConsts) {
            try {
                byte[] raw = hexToBytes(entry[1]);
                Address found = mem.findBytes(
                    program.getMinAddress(), raw, null,
                    true, TaskMonitor.DUMMY);
                if (found != null) {
                    JsonObject hit = new JsonObject();
                    hit.addProperty("pattern", entry[0]);
                    hit.addProperty("address",
                        found.toString());
                    hit.addProperty("hex", entry[1]);
                    constHits.add(hit);
                }
            } catch (Exception e) { /* skip */ }
        }

        // Crypto function names
        String[] cryptoPatterns = {
            "aes", "des", "sha1", "sha256", "sha512",
            "sha384", "md5", "hmac", "rsa", "ecdsa",
            "chacha", "poly1305", "blowfish", "rc4",
            "salsa", "argon", "bcrypt", "scrypt", "pbkdf",
            "encrypt", "decrypt", "cipher", "hash",
            "EVP_", "OPENSSL", "crypt", "mbedtls_"
        };
        JsonArray cryptoFuncs = new JsonArray();
        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String fname = func.getName();
            String flower = fname.toLowerCase();
            for (String pat : cryptoPatterns) {
                if (flower.contains(pat.toLowerCase())) {
                    JsonObject fobj = new JsonObject();
                    fobj.addProperty("function", fname);
                    fobj.addProperty("address",
                        func.getEntryPoint().toString());
                    fobj.addProperty("matched_pattern", pat);
                    cryptoFuncs.add(fobj);
                    break;
                }
            }
        }

        JsonObject out = new JsonObject();
        out.addProperty("binary", programName(program));
        out.add("constant_hits", constHits);
        out.add("crypto_functions", cryptoFuncs);
        out.addProperty("total_indicators",
            constHits.size() + cryptoFuncs.size());
        return out;
    }

    // -----------------------------------------------------------------
    // find_obfuscated_strings
    // -----------------------------------------------------------------

    static JsonElement findObfuscatedStrings(
            Program program, JsonObject args) {
        Listing pListing = program.getListing();
        Memory mem = program.getMemory();
        FunctionManager fm = program.getFunctionManager();

        JsonArray findings = new JsonArray();

        // 1. XOR instruction detection
        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Instruction insn = pListing.getInstructionAt(
                func.getEntryPoint());
            int seen = 0;
            List<String> xorSites = new ArrayList<>();
            while (insn != null && seen < 500) {
                String mnemonic =
                    insn.getMnemonicString().toLowerCase();
                if (mnemonic.contains("xor")
                        || mnemonic.contains("eor")) {
                    int numOps = insn.getNumOperands();
                    if (numOps >= 2) {
                        String op0 = insn
                            .getDefaultOperandRepresentation(0);
                        String op1 = insn
                            .getDefaultOperandRepresentation(1);
                        if (!op0.equals(op1)) {
                            xorSites.add(
                                insn.getAddress().toString());
                        }
                    }
                }
                seen++;
                insn = insn.getNext();
            }
            if (!xorSites.isEmpty()) {
                JsonObject finding = new JsonObject();
                finding.addProperty("type",
                    "xor_instruction");
                finding.addProperty("function",
                    func.getName());
                finding.addProperty("function_addr",
                    func.getEntryPoint().toString());
                JsonArray xorArr = new JsonArray();
                for (int i = 0;
                        i < Math.min(xorSites.size(), 10); i++) {
                    xorArr.add(xorSites.get(i));
                }
                finding.add("xor_addresses", xorArr);
                findings.add(finding);
            }
        }

        // 2. High-entropy data
        Iterator<Data> dataIter = pListing.getDefinedData(true);
        int dataCount = 0;
        while (dataIter.hasNext() && dataCount < 5000) {
            Data d = dataIter.next();
            dataCount++;
            int length = d.getLength();
            if (length < 16) continue;
            String dtName =
                d.getDataType().getName().toLowerCase();
            if (dtName.contains("string")) continue;
            try {
                byte[] raw = new byte[length];
                mem.getBytes(d.getAddress(), raw);
                int nonAscii = 0;
                for (byte b : raw) {
                    int v = b & 0xFF;
                    if (v < 0x20 || v > 0x7e) nonAscii++;
                }
                double ratio = (double) nonAscii / length;
                if (ratio > 0.6) {
                    JsonObject finding = new JsonObject();
                    finding.addProperty("type",
                        "high_entropy_data");
                    finding.addProperty("address",
                        d.getAddress().toString());
                    finding.addProperty("size", length);
                    finding.addProperty("non_ascii_ratio",
                        Math.round(ratio * 100.0) / 100.0);
                    findings.add(finding);
                }
            } catch (Exception e) { /* skip */ }
        }

        // 3. Base64 candidates
        Iterator<Data> strIter = pListing.getDefinedData(true);
        int strCount = 0;
        while (strIter.hasNext() && strCount < 5000) {
            Data d = strIter.next();
            strCount++;
            String dtName =
                d.getDataType().getName().toLowerCase();
            if (!dtName.contains("string")) continue;
            try {
                Object val = d.getValue();
                if (val == null) continue;
                String sval = val.toString();
                if (sval.length() < 16) continue;
                if (sval.length() % 4 == 0
                        && sval.matches(
                            "[A-Za-z0-9+/=]{16,}")) {
                    JsonObject finding = new JsonObject();
                    finding.addProperty("type",
                        "base64_candidate");
                    finding.addProperty("address",
                        d.getAddress().toString());
                    finding.addProperty("length",
                        sval.length());
                    finding.addProperty("preview",
                        sval.length() > 60
                            ? sval.substring(0, 60)
                            : sval);
                    findings.add(finding);
                }
            } catch (Exception e) { /* skip */ }
        }

        JsonObject out = new JsonObject();
        out.addProperty("binary", programName(program));
        out.addProperty("total_findings", findings.size());
        out.add("findings", findings);
        return out;
    }

}
