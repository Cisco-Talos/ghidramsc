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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Program identity, persistence state, memory map, and symbol inventory. */
final class ProgramQueries {
    private ProgramQueries() { }

    static String programName(Program program) {
        return GhidraMSCPlugin.qualifiedProgramName(program);
    }

    static JsonElement getProgramInfo(Program program, JsonObject args) {
        var lang = program.getLanguage();
        var compSpec = program.getCompilerSpec();
        Memory mem = program.getMemory();

        JsonObject info = new JsonObject();
        info.addProperty("binary", programName(program));
        info.addProperty("image_base", program.getImageBase().toString());
        info.addProperty("language_id", lang.getLanguageID().toString());
        info.addProperty("processor", lang.getProcessor().toString());
        info.addProperty("endianness",
            lang.isBigEndian() ? "big" : "little");
        info.addProperty("pointer_size",
            lang.getDefaultSpace().getPointerSize());
        info.addProperty("address_size",
            lang.getDefaultSpace().getSize());
        info.addProperty("compiler_spec",
            compSpec.getCompilerSpecID().toString());
        info.addProperty("executable_format",
            program.getExecutableFormat());
        info.addProperty("executable_path",
            program.getExecutablePath());
        info.addProperty("min_address", mem.getMinAddress().toString());
        info.addProperty("max_address", mem.getMaxAddress().toString());
        info.addProperty("num_memory_blocks", mem.getBlocks().length);
        info.addProperty("num_functions",
            program.getFunctionManager().getFunctionCount());

        try {
            info.addProperty("creation_date",
                program.getCreationDate().toString());
        } catch (Exception e) {
            // optional
        }

        return info;
    }

    // -----------------------------------------------------------------
    // get_program_save_state
    // -----------------------------------------------------------------

    static JsonElement getProgramSaveState(
            Program program, JsonObject args) {
        return programPersistenceState(program);
    }

    static JsonObject programPersistenceState(Program program) {
        JsonObject state = new JsonObject();
        state.addProperty("program", programName(program));
        state.addProperty("dirty", program.isChanged());
        state.addProperty("can_save", program.canSave());
        if (program.getDomainFile() != null) {
            state.addProperty("path",
                program.getDomainFile().getPathname());
        }
        return state;
    }

    static JsonElement getProgramMemoryMap(Program program, JsonObject args) {
        Memory mem = program.getMemory();
        JsonArray blocksArr = new JsonArray();
        for (MemoryBlock blk : mem.getBlocks()) {
            JsonObject bobj = new JsonObject();
            String mappedStart = null;
            String mappedEnd = null;
            if (blk.isMapped()) {
                for (ghidra.program.model.mem.MemoryBlockSourceInfo sourceInfo : blk.getSourceInfos()) {
                    java.util.Optional<ghidra.program.model.address.AddressRange> range =
                        sourceInfo.getMappedRange();
                    if (range.isPresent()) {
                        mappedStart = range.get().getMinAddress().toString();
                        mappedEnd = range.get().getMaxAddress().toString();
                        break;
                    }
                }
            }
            bobj.addProperty("name", blk.getName());
            bobj.addProperty("start", blk.getStart().toString());
            bobj.addProperty("end", blk.getEnd().toString());
            bobj.addProperty("size", blk.getSize());
            bobj.addProperty("read", blk.isRead());
            bobj.addProperty("write", blk.isWrite());
            bobj.addProperty("execute", blk.isExecute());
            bobj.addProperty("volatile", blk.isVolatile());
            bobj.addProperty("initialized", blk.isInitialized());
            bobj.addProperty("overlay", blk.isOverlay());
            bobj.addProperty("type", blk.getType().toString());
            bobj.addProperty("mapped_source_start", mappedStart);
            bobj.addProperty("mapped_source_end", mappedEnd);
            bobj.addProperty("source", blk.getSourceName());
            JsonElement recoveredCode = com.google.gson.JsonNull.INSTANCE;
            String blockComment = blk.getComment();
            String recoveredPrefix = "GhidraMSC recovered code v1: ";
            if (blockComment != null && blockComment.startsWith(recoveredPrefix)) {
                try {
                    recoveredCode = com.google.gson.JsonParser.parseString(
                        blockComment.substring(recoveredPrefix.length()));
                } catch (RuntimeException ignored) {
                    // An unrelated or damaged comment is not valid provenance.
                }
            }
            bobj.add("recovered_code", recoveredCode);
            blocksArr.add(bobj);
        }

        JsonObject out = new JsonObject();
        out.addProperty("binary", programName(program));
        out.addProperty("image_base",
            program.getImageBase().toString());
        out.addProperty("total_blocks", blocksArr.size());
        out.add("blocks", blocksArr);
        return out;
    }

    // -----------------------------------------------------------------
    // list_program_imports
    // -----------------------------------------------------------------

    static JsonElement listProgramImports(Program program, JsonObject args) {
        SymbolTable st = program.getSymbolTable();
        SymbolIterator extSyms = st.getExternalSymbols();
        List<String> lines = new ArrayList<>();
        int count = 0;
        while (extSyms.hasNext()) {
            Symbol sym = extSyms.next();
            lines.add(sym.getAddress() + "  " + sym.getName()
                + "  (" + sym.getParentNamespace() + ")");
            count++;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("IMPORTS in ").append(programName(program))
          .append(" (").append(count).append(" total)\n\n");
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // list_program_exports
    // -----------------------------------------------------------------

    static JsonElement listProgramExports(Program program, JsonObject args) {
        SymbolTable st = program.getSymbolTable();
        List<String> lines = new ArrayList<>();
        SymbolIterator symIter = st.getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            if (sym.isExternalEntryPoint()) {
                lines.add(sym.getAddress() + "  " + sym.getName());
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("EXPORTS in ").append(programName(program))
          .append(" (").append(lines.size()).append(" total)\n\n");
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // list_program_namespaces
    // -----------------------------------------------------------------

    static JsonElement listProgramNamespaces(Program program, JsonObject args) {
        SymbolTable st = program.getSymbolTable();
        Set<String> seen = new HashSet<>();
        List<String> namespaces = new ArrayList<>();
        SymbolIterator symIter = st.getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            String nsName = sym.getParentNamespace().toString();
            if (!seen.contains(nsName)) {
                seen.add(nsName);
                namespaces.add(nsName);
            }
        }
        Collections.sort(namespaces);

        StringBuilder sb = new StringBuilder();
        sb.append("NAMESPACES in ").append(programName(program))
          .append(" (").append(namespaces.size())
          .append(" total)\n\n");
        for (String ns : namespaces) {
            sb.append(ns).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // list_program_classes
    // -----------------------------------------------------------------

    static JsonElement listProgramClasses(Program program, JsonObject args) {
        SymbolTable st = program.getSymbolTable();
        List<String> classes = new ArrayList<>();
        var classIter = st.getClassNamespaces();
        while (classIter.hasNext()) {
            classes.add(classIter.next().getName(true));
        }
        StringBuilder sb = new StringBuilder();
        sb.append("CLASSES in ").append(programName(program))
          .append(" (").append(classes.size())
          .append(" total)\n\n");
        for (String cls : classes) {
            sb.append("  ").append(cls).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    static JsonElement listMemoryBlocks(Program program, JsonObject args) {
        Memory mem = program.getMemory();
        JsonArray segments = new JsonArray();
        for (MemoryBlock blk : mem.getBlocks()) {
            String perms = "";
            if (blk.isRead()) perms += "R";
            if (blk.isWrite()) perms += "W";
            if (blk.isExecute()) perms += "X";

            JsonObject sobj = new JsonObject();
            sobj.addProperty("name", blk.getName());
            sobj.addProperty("start", blk.getStart().toString());
            sobj.addProperty("end", blk.getEnd().toString());
            sobj.addProperty("size", blk.getSize());
            sobj.addProperty("permissions", perms);
            sobj.addProperty("initialized", blk.isInitialized());
            sobj.addProperty("type", blk.getType().toString());
            segments.add(sobj);
        }
        JsonObject out = new JsonObject();
        out.addProperty("binary", programName(program));
        out.addProperty("image_base",
            program.getImageBase().toString());
        out.add("segments", segments);
        return out;
    }

}
