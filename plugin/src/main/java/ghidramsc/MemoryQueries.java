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
import static ghidramsc.QuerySupport.optInt;
import static ghidramsc.QuerySupport.optString;
import static ghidramsc.QuerySupport.requireString;
import static ghidramsc.QuerySupport.toAddress;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** References, listing, defined data, and bounded memory reads/searches. */
final class MemoryQueries {
    private MemoryQueries() { }

    // -----------------------------------------------------------------
    // list_references_to_address
    // -----------------------------------------------------------------

    static JsonElement listReferencesToAddress(Program program, JsonObject args) {
        return referencePage(program, args, true);
    }

    // -----------------------------------------------------------------
    // list_references_from_address
    // -----------------------------------------------------------------

    static JsonElement listReferencesFromAddress(Program program, JsonObject args) {
        return referencePage(program, args, false);
    }

    private static JsonElement referencePage(
            Program program, JsonObject args, boolean toTarget) {
        String addrHex = requireString(args, "addr_hex");
        int offset = optInt(args, "offset", 0);
        int limit = optInt(args, "limit", 100);
        try {
            QueryPaging.validate(offset, limit, "reference", 500);
        } catch (IllegalArgumentException error) {
            return new JsonPrimitive("ERROR: " + error.getMessage());
        }
        Address addr = toAddress(program, addrHex);
        ReferenceManager rm = program.getReferenceManager();
        List<Reference> refs = new ArrayList<>();
        if (toTarget) {
            var iterator = rm.getReferencesTo(addr);
            while (iterator.hasNext()) refs.add(iterator.next());
        } else {
            for (Reference ref : rm.getReferencesFrom(addr)) refs.add(ref);
        }
        boolean paged = offset > 0 || refs.size() > limit;
        if (paged) {
            refs.sort(java.util.Comparator
                .comparing((Reference ref) -> (toTarget
                    ? ref.getFromAddress() : ref.getToAddress()).toString())
                .thenComparing(ref -> ref.getReferenceType().toString())
                .thenComparingInt(Reference::getOperandIndex));
        }

        StringBuilder sb = new StringBuilder();
        sb.append(toTarget ? "XREFs TO " : "XREFs FROM ").append(addrHex)
          .append(" in ").append(programName(program))
          .append(" (").append(refs.size()).append(" refs)\n\n");

        JsonArray records = new JsonArray();
        int end = (int) Math.min((long) refs.size(), (long) offset + limit);
        for (int index = offset; index < end; index++) {
            Reference ref = refs.get(index);
            Address side = toTarget ? ref.getFromAddress() : ref.getToAddress();
            String refType = ref.getReferenceType().toString();
            Function fn = toTarget
                ? program.getFunctionManager().getFunctionContaining(side)
                : program.getFunctionManager().getFunctionAt(side);
            String fnName = fn != null ? fn.getName() : "<no function>";
            sb.append("  ").append(side).append("  ").append(refType)
              .append(toTarget ? "  in " : "  -> ")
              .append(fnName).append('\n');
            JsonObject row = new JsonObject();
            row.addProperty("from_address", ref.getFromAddress().toString());
            row.addProperty("to_address", ref.getToAddress().toString());
            row.addProperty("reference_kind", refType);
            row.addProperty("operand_index", ref.getOperandIndex());
            String key = toTarget ? "source_function" : "target_function";
            if (fn == null) {
                row.add(key, com.google.gson.JsonNull.INSTANCE);
            } else {
                JsonObject function = new JsonObject();
                function.addProperty("name", fn.getName());
                function.addProperty("entry", fn.getEntryPoint().toString());
                row.add(key, function);
            }
            records.add(row);
        }
        if (!paged) {
            return new JsonPrimitive(sb.toString());
        }
        JsonObject out = new JsonObject();
        out.addProperty("text", sb.toString());
        out.add("references", records);
        out.add("pagination", QueryPaging.metadata(
            offset, limit, records.size(), refs.size()));
        out.addProperty("requested_address", addr.toString());
        CodeUnit containing = program.getListing().getCodeUnitContaining(addr);
        if (containing == null) {
            out.add("containing_address", com.google.gson.JsonNull.INSTANCE);
            out.add("containing_end", com.google.gson.JsonNull.INSTANCE);
        } else {
            out.addProperty("containing_address",
                containing.getAddress().toString());
            out.addProperty("containing_end",
                containing.getMaxAddress().toString());
        }
        return out;
    }

    // -----------------------------------------------------------------
    // get_listing_at_address
    // -----------------------------------------------------------------

    static JsonElement getListingAtAddress(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        int count = optInt(args, "count", 40);
        int offset = optInt(args, "offset", 0);
        int limit = optInt(args, "limit", 100);
        try {
            QueryPaging.validate(offset, limit, "listing", 500);
        } catch (IllegalArgumentException error) {
            return new JsonPrimitive("ERROR: " + error.getMessage());
        }
        if (count < 0 || count > 100000) {
            return new JsonPrimitive("ERROR: count must be 0..100000");
        }
        Address addr = toAddress(program, addrHex);
        Listing progListing = program.getListing();
        CodeUnit containing = progListing.getCodeUnitContaining(addr);
        boolean interior = containing != null
            && !containing.getAddress().equals(addr);
        Address start = interior ? containing.getAddress() : addr;

        CodeUnitIterator cuIter = progListing.getCodeUnits(start, true);
        List<CodeUnit> units = new ArrayList<>();
        while (cuIter.hasNext() && units.size() < count) {
            units.add(cuIter.next());
        }
        int end = (int) Math.min((long) units.size(), (long) offset + limit);
        JsonArray items = new JsonArray();
        StringBuilder sb = new StringBuilder();
        sb.append("LISTING ").append(addrHex)
          .append(" +").append(count).append(" instructions in ")
          .append(programName(program)).append("\n\n");
        for (int index = offset; index < end; index++) {
            CodeUnit cu = units.get(index);
            StringBuilder line = new StringBuilder();
            Symbol primary = cu.getPrimarySymbol();
            if (primary != null) {
                line.append(primary.getName()).append(":\n");
            }
            String plate = cu.getComment(CodeUnit.PLATE_COMMENT);
            String pre = cu.getComment(CodeUnit.PRE_COMMENT);
            String eol = cu.getComment(CodeUnit.EOL_COMMENT);
            if (plate != null) {
                line.append("; [PLATE] ").append(plate).append('\n');
            }
            if (pre != null) {
                line.append("; ").append(pre).append('\n');
            }
            line.append(cu.getAddress()).append("  ").append(cu.toString());
            if (eol != null) {
                line.append("   ; ").append(eol);
            }
            items.add(line.toString());
            sb.append(line).append('\n');
        }
        if (!interior && offset == 0 && units.size() <= limit) {
            return new JsonPrimitive(sb.toString());
        }
        JsonObject out = new JsonObject();
        out.addProperty("text", sb.toString());
        out.add("items", items);
        out.add("pagination", QueryPaging.metadata(
            offset, limit, items.size(), units.size()));
        out.addProperty("count", count);
        out.addProperty("requested_address", addr.toString());
        if (containing == null) {
            out.add("containing_address", com.google.gson.JsonNull.INSTANCE);
            out.add("containing_end", com.google.gson.JsonNull.INSTANCE);
            out.add("byte_offset", com.google.gson.JsonNull.INSTANCE);
        } else {
            out.addProperty("containing_address",
                containing.getAddress().toString());
            out.addProperty("containing_end",
                containing.getMaxAddress().toString());
            out.addProperty("byte_offset", addr.subtract(start));
        }
        out.add("exact_symbols", exactSymbols(program, addr));
        return out;
    }

    // -----------------------------------------------------------------
    // list_strings
    // -----------------------------------------------------------------

    static JsonElement listStrings(Program program, JsonObject args) {
        String filterStr = optString(args, "filter_str", "");
        String flt = filterStr.toLowerCase();
        Listing progListing = program.getListing();

        List<String> results = new ArrayList<>();
        Iterator<Data> dataIter = progListing.getDefinedData(true);
        while (dataIter.hasNext()) {
            Data d = dataIter.next();
            String dtName = d.getDataType().getName().toLowerCase();
            if (!dtName.contains("string") && !dtName.contains("char")) {
                continue;
            }
            try {
                Object val = d.getValue();
                if (val == null) continue;
                String sval = val.toString();
                if (flt.isEmpty() || sval.toLowerCase().contains(flt)) {
                    results.add(d.getAddress() + "  \"" + sval + "\"");
                }
            } catch (Exception e) {
                // skip
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("STRINGS in ").append(programName(program))
          .append("  filter='").append(filterStr).append("'  (")
          .append(results.size()).append(" matches)\n\n");
        for (String line : results) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // search_memory_text
    // -----------------------------------------------------------------

    static JsonElement searchMemoryText(Program program, JsonObject args) {
        String pattern = requireString(args, "pattern");
        Memory mem = program.getMemory();
        byte[] patBytes = pattern.getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        List<String> results = new ArrayList<>();
        Address addr = mem.getMinAddress();
        while (addr != null) {
            try {
                Address found = mem.findBytes(
                    addr, patBytes, null, true, TaskMonitor.DUMMY);
                if (found == null) break;
                Function fn = program.getFunctionManager()
                    .getFunctionContaining(found);
                String fnInfo = fn != null ? fn.getName() : "<no function>";
                MemoryBlock blk = mem.getBlock(found);
                String blkName = blk != null ? blk.getName() : "?";
                results.add(found + "  [" + blkName + "]  in " + fnInfo);
                addr = found.add(1);
            } catch (Exception e) {
                break;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("SEARCH_MEM '").append(pattern).append("' in ")
          .append(programName(program)).append("  (")
          .append(results.size()).append(" hits)\n\n");
        for (String line : results) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // search_memory_bytes
    // -----------------------------------------------------------------

    static JsonElement searchMemoryBytes(Program program, JsonObject args) {
        String hexPattern = requireString(args, "hex_pattern");
        String cleaned = hexPattern.replace(" ", "").replace("\t", "");
        if (cleaned.length() % 2 != 0) {
            return new JsonPrimitive(
                "ERROR: hex pattern must have even number of hex chars");
        }

        byte[] patBytes;
        try {
            patBytes = hexToBytes(cleaned);
        } catch (NumberFormatException e) {
            return new JsonPrimitive(
                "ERROR: search_memory_bytes invalid hex: " + e.getMessage());
        }

        Memory mem = program.getMemory();
        List<String> results = new ArrayList<>();
        Address addr = mem.getMinAddress();
        while (addr != null) {
            try {
                Address found = mem.findBytes(
                    addr, patBytes, null, true, TaskMonitor.DUMMY);
                if (found == null) break;
                Function fn = program.getFunctionManager()
                    .getFunctionContaining(found);
                String fnInfo = fn != null ? fn.getName() : "<no function>";
                MemoryBlock blk = mem.getBlock(found);
                String blkName = blk != null ? blk.getName() : "?";
                results.add(found + "  [" + blkName + "]  in " + fnInfo);
                addr = found.add(1);
            } catch (Exception e) {
                break;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("SEARCH_HEX '").append(cleaned).append("' in ")
          .append(programName(program)).append("  (")
          .append(results.size()).append(" hits)\n\n");
        for (String line : results) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // list_data_items
    // -----------------------------------------------------------------

    static JsonElement listDataItems(Program program, JsonObject args) {
        int offset = optInt(args, "offset", 0);
        int limit = optInt(args, "limit", 500);
        Listing progListing = program.getListing();
        Iterator<Data> dataIter = progListing.getDefinedData(true);

        List<String> lines = new ArrayList<>();
        int idx = 0;
        int shown = 0;
        while (dataIter.hasNext()) {
            Data d = dataIter.next();
            if (idx < offset) { idx++; continue; }
            if (shown >= limit) break;
            DataType dt = d.getDataType();
            String val = d.getDefaultValueRepresentation();
            Symbol sym = d.getPrimarySymbol();
            String label = sym != null ? sym.getName() : "";
            lines.add(d.getAddress() + "  " + label + "  "
                + dt.getName() + "  " + val);
            idx++;
            shown++;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("DATA in ").append(programName(program))
          .append(" (showing ").append(shown).append(", offset ")
          .append(offset).append(")\n\n");
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // read_memory_bytes
    // -----------------------------------------------------------------

    static JsonElement readMemoryBytes(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        int length = optInt(args, "length", 256);
        length = Math.max(1, Math.min(length, 4096));
        Address addr = toAddress(program, addrHex);

        Memory mem = program.getMemory();
        byte[] buf = new byte[length];
        int actual;
        try {
            actual = mem.getBytes(addr, buf);
        } catch (Exception e) {
            return new JsonPrimitive("ERROR: Cannot read memory at " + addrHex);
        }
        if (actual <= 0) {
            return new JsonPrimitive("ERROR: Cannot read memory at " + addrHex);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("READ_BYTES at ").append(addrHex)
          .append(" (").append(actual).append(" bytes)\n\n");
        for (int off = 0; off < actual; off += 16) {
            int end = Math.min(off + 16, actual);
            Address lineAddr = addr.add(off);
            sb.append(lineAddr.toString()).append("  ");
            StringBuilder ascii = new StringBuilder();
            for (int i = off; i < end; i++) {
                sb.append(String.format("%02x ", buf[i] & 0xff));
                int b = buf[i] & 0xff;
                ascii.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
            }
            // Pad hex if line is short
            for (int i = end; i < off + 16; i++) {
                sb.append("   ");
            }
            sb.append(" ").append(ascii).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // get_data_at_address
    // -----------------------------------------------------------------

    static JsonElement getDataAtAddress(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        int valueOffset = optInt(args, "value_offset", 0);
        int valueLimit = optInt(args, "value_limit", 2048);
        try {
            QueryPaging.validate(valueOffset, valueLimit, "value", 8192);
        } catch (IllegalArgumentException error) {
            return new JsonPrimitive("ERROR: " + error.getMessage());
        }
        Address addr = toAddress(program, addrHex);
        Data data = resolveDefinedData(program, addr);
        if (data == null) {
            return new JsonPrimitive("ERROR: No defined data at " + addrHex
                + ". For initialized undefined bytes, use read_memory_bytes; "
                + "use list_references_to_address for incoming references. "
                + "A qualified space address uses space::hex_offset.");
        }

        JsonObject out = dataState(program, data, addr);
        String value = out.get("value").getAsString();
        int total = value.codePointCount(0, value.length());
        int end = (int) Math.min((long) total, (long) valueOffset + valueLimit);
        int startIndex = value.offsetByCodePoints(0, Math.min(valueOffset, total));
        int endIndex = value.offsetByCodePoints(0, end);
        String page = value.substring(startIndex, endIndex);
        int returned = end - Math.min(valueOffset, total);
        boolean hasMore = (long) valueOffset + returned < total;
        out.addProperty("value", page);
        out.addProperty("value_offset", valueOffset);
        out.addProperty("value_limit", valueLimit);
        out.addProperty("value_returned_chars", returned);
        out.addProperty("value_total_chars", total);
        out.addProperty("value_has_more", hasMore);
        out.addProperty("value_truncated", valueOffset > 0 || hasMore);
        if (hasMore) {
            out.addProperty("value_next_offset", valueOffset + returned);
        } else {
            out.add("value_next_offset", com.google.gson.JsonNull.INSTANCE);
        }
        return out;
    }

    static Data resolveDefinedData(Program program, Address address) {
        Listing listing = program.getListing();
        Data data = listing.getDefinedDataAt(address);
        return data != null ? data : listing.getDefinedDataContaining(address);
    }

    static JsonObject dataState(Program program, Data data) {
        JsonObject out = new JsonObject();
        out.addProperty("address", data.getAddress().toString());
        out.addProperty("type", data.getDataType().getName());
        out.addProperty("size", data.getLength());
        out.addProperty("value", data.getDefaultValueRepresentation());
        Symbol primary = data.getPrimarySymbol();
        if (primary != null) {
            out.addProperty("label", primary.getName());
        }
        JsonArray labels = new JsonArray();
        if (primary != null) {
            labels.add(dataSymbolState(primary, true));
        }
        for (Symbol symbol : program.getSymbolTable()
                .getSymbols(data.getAddress())) {
            if (primary == null || symbol.getID() != primary.getID()) {
                labels.add(dataSymbolState(symbol, false));
            }
        }
        out.add("labels", labels);
        return out;
    }

    private static JsonObject dataState(
            Program program, Data data, Address requested) {
        JsonObject out = dataState(program, data);
        out.addProperty("requested_address", requested.toString());
        out.addProperty("containing_address", data.getAddress().toString());
        out.addProperty("containing_end", data.getMaxAddress().toString());
        out.addProperty("byte_offset", requested.subtract(data.getAddress()));
        out.add("exact_symbols", exactSymbols(program, requested));
        return out;
    }

    private static JsonArray exactSymbols(Program program, Address address) {
        JsonArray symbols = new JsonArray();
        Symbol primary = program.getSymbolTable().getPrimarySymbol(address);
        for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
            symbols.add(dataSymbolState(symbol,
                primary != null && symbol.getID() == primary.getID()));
        }
        return symbols;
    }

    private static JsonObject dataSymbolState(
            Symbol symbol, boolean primary) {
        JsonObject out = new JsonObject();
        out.addProperty("id", Long.toUnsignedString(symbol.getID()));
        out.addProperty("name", symbol.getName());
        out.addProperty("namespace", symbol.getParentNamespace().toString());
        out.addProperty("type", symbol.getSymbolType().toString());
        out.addProperty("source", symbol.getSource().toString());
        out.addProperty("primary", primary);
        out.addProperty("dynamic", symbol.isDynamic());
        return out;
    }

}
