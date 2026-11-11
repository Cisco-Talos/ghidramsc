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
import static ghidramsc.QuerySupport.optInt;
import static ghidramsc.QuerySupport.requireString;
import static ghidramsc.QuerySupport.resolveFunction;
import static ghidramsc.QuerySupport.toAddress;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Function inventory, decompilation, control flow, and stack state. */
final class FunctionQueries {
    private FunctionQueries() { }

    private static final int DECOMPILE_PAGE_DEFAULT = 16384;
    private static final int DECOMPILE_PAGE_MAX = 32768;
    private static final int BATCH_DECOMPILE_ADDRESSES_MAX = 16;
    private static final int BATCH_DECOMPILE_FUNCTION_CHARS = 8192;
    private static final int BATCH_DECOMPILE_TOTAL_CHARS = 32768;

    // -----------------------------------------------------------------
    // list_functions
    // -----------------------------------------------------------------

    static JsonElement listFunctions(Program program, JsonObject args) {
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);

        List<Function> funcs = new ArrayList<>();
        while (iter.hasNext()) {
            funcs.add(iter.next());
        }
        Collections.sort(funcs,
            Comparator.comparing(Function::getEntryPoint));

        StringBuilder sb = new StringBuilder();
        sb.append("FUNCTIONS in ")
          .append(programName(program))
          .append(" (")
          .append(funcs.size())
          .append(" total)\n\n");

        for (Function f : funcs) {
            sb.append(f.getEntryPoint().toString())
              .append("  ")
              .append(f.getName());
            if (f.isThunk()) {
                sb.append(" [thunk]");
            }
            sb.append('\n');
        }

        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // decompile_function
    // -----------------------------------------------------------------

    static JsonElement decompileFunction(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        int offset = optInt(args, "offset", 0);
        int limit = optInt(args, "limit", DECOMPILE_PAGE_DEFAULT);
        if (offset < 0 || limit < 1 || limit > DECOMPILE_PAGE_MAX) {
            return new JsonPrimitive(
                "ERROR: offset must be non-negative and limit must be 1..32768");
        }
        Address addr = toAddress(program, addrHex);

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        if (func == null) {
            return new JsonPrimitive(
                "ERROR: No function at or containing " + addrHex);
        }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.setOptions(new DecompileOptions());
            decomp.openProgram(program);

            DecompileResults result =
                decomp.decompileFunction(func, 120, TaskMonitor.DUMMY);

            if (result == null || !result.decompileCompleted()) {
                String msg = (result != null)
                    ? result.getErrorMessage() : "unknown error";
                return new JsonPrimitive(
                    "ERROR: Decompile failed for " + func.getName()
                    + " -- " + msg);
            }

            String cCode = result.getDecompiledFunction().getC();
            StringBuilder sb = new StringBuilder();
            sb.append("// Binary:    ").append(programName(program)).append('\n');
            sb.append("// Function:  ").append(func.getName()).append('\n');
            sb.append("// Entry:     ").append(func.getEntryPoint()).append('\n');
            sb.append("// Signature: ").append(func.getSignature()).append('\n');
            sb.append('\n');
            sb.append(cCode);
            return new JsonPrimitive(decompilePage(sb.toString(), offset, limit));
        } finally {
            decomp.dispose();
        }
    }

    static String decompilePage(String output, int offset, int limit) {
        int total = output.codePointCount(0, output.length());
        if (offset > total) {
            return "ERROR: offset " + offset
                + " exceeds decompiled output length " + total;
        }
        int end = (int) Math.min((long) total, (long) offset + limit);
        if (offset == 0 && end == total) {
            return output;
        }
        int startIndex = output.offsetByCodePoints(0, offset);
        int endIndex = output.offsetByCodePoints(0, end);
        String nextOffset = end < total ? Integer.toString(end) : "none";
        return "// GHIDRAMSC OUTPUT CHUNK offset=" + offset
            + " next_offset=" + nextOffset + " total_chars=" + total
            + "\n" + output.substring(startIndex, endIndex);
    }

    static String batchDecompileEntry(String output, int remaining) {
        int available = Math.max(0,
            Math.min(BATCH_DECOMPILE_FUNCTION_CHARS, remaining));
        int total = output.codePointCount(0, output.length());
        if (total <= available) {
            return output;
        }
        String note = "// GHIDRAMSC BATCH TRUNCATED: total_chars=" + total
            + "; use decompile_function with offset to read all text.\n";
        int shown = Math.max(0, available - note.length());
        return note + output.substring(0,
            output.offsetByCodePoints(0, Math.min(total, shown)));
    }

    // -----------------------------------------------------------------
    // get_function_info
    // -----------------------------------------------------------------

    static JsonElement getFunctionInfo(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        int incomingOffset = optInt(args, "incoming_offset", 0);
        int incomingLimit = optInt(args, "incoming_limit", 100);
        int evidenceOffset = optInt(args, "evidence_offset", 0);
        int evidenceLimit = optInt(args, "evidence_limit", 100);
        if (incomingOffset < 0 || incomingLimit < 1 || incomingLimit > 500) {
            JsonObject err = new JsonObject();
            err.addProperty("error", "incoming_offset must be non-negative "
                + "and incoming_limit must be 1..500");
            return err;
        }
        try {
            QueryPaging.validate(evidenceOffset, evidenceLimit,
                "evidence", 500);
        } catch (IllegalArgumentException error) {
            JsonObject err = new JsonObject();
            err.addProperty("error", error.getMessage());
            return err;
        }
        Address addr = toAddress(program, addrHex);

        Function func = resolveFunction(program, addr);
        if (func == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "No function at or containing " + addrHex);
            return err;
        }

        JsonObject info = new JsonObject();
        info.addProperty("binary", programName(program));
        info.addProperty("name", func.getName());
        info.addProperty("entry", func.getEntryPoint().toString());
        info.addProperty("signature", func.getSignature().toString());
        info.addProperty("calling_convention",
            func.getCallingConventionName());
        info.addProperty("return_type", func.getReturnType().toString());
        info.addProperty("body_min",
            func.getBody().getMinAddress().toString());
        info.addProperty("body_max",
            func.getBody().getMaxAddress().toString());
        info.addProperty("body_bytes", func.getBody().getNumAddresses());
        info.add("body_ranges", addressRanges(func.getBody()));
        info.addProperty("is_thunk", func.isThunk());
        info.addProperty("no_return", func.hasNoReturn());
        Function effective = func.isThunk() ? func.getThunkedFunction(true) : null;
        info.addProperty("effective_entry",
            (effective == null ? func : effective).getEntryPoint().toString());

        var frame = func.getStackFrame();
        info.addProperty("stack_local_size",
            frame != null ? frame.getLocalSize() : 0);
        info.addProperty("stack_param_size",
            frame != null ? frame.getParameterSize() : 0);

        JsonArray params = new JsonArray();
        for (Parameter p : func.getParameters()) {
            JsonObject pobj = new JsonObject();
            pobj.addProperty("name", p.getName());
            pobj.addProperty("type", p.getDataType().toString());
            pobj.addProperty("ordinal", p.getOrdinal());
            params.add(pobj);
        }
        info.add("parameters", params);

        CallRelationshipQueries.CallEvidence callEvidence =
            CallRelationshipQueries.callEvidence(program, func, 0);
        JsonArray callees = new JsonArray();
        for (JsonElement item : callEvidence.callees) {
            JsonObject source = item.getAsJsonObject();
            JsonObject cobj = new JsonObject();
            cobj.addProperty("name", source.get("name").getAsString());
            cobj.addProperty("entry", source.get("address").getAsString());
            cobj.addProperty("classification",
                source.get("classification").getAsString());
            callees.add(cobj);
        }
        info.add("calls", callees);

        JsonArray callers = new JsonArray();
        List<Function> knownCallers = new ArrayList<>(
            func.getCallingFunctions(TaskMonitor.DUMMY));
        knownCallers.sort(Comparator.comparing(
            item -> item.getEntryPoint().toString()));
        for (Function c : knownCallers) {
            JsonObject cobj = new JsonObject();
            cobj.addProperty("name", c.getName());
            cobj.addProperty("entry", c.getEntryPoint().toString());
            callers.add(cobj);
        }
        info.add("called_by", callers);
        info.add("call_sites", callEvidence.sites);
        info.add("possible_callees", callEvidence.possible);
        info.add("unresolved_calls", callEvidence.unresolved);
        info.addProperty("call_scan_complete", callEvidence.scanComplete);
        info.addProperty("caller_coverage", "ghidra_known_only");
        info.add("incoming_references",
            IncomingReferenceQueries.incomingReferences(
                program, func, incomingOffset, incomingLimit));

        JsonObject pagination = new JsonObject();
        for (String key : new String[] {
                "parameters", "body_ranges", "calls", "called_by",
                "call_sites", "possible_callees", "unresolved_calls"}) {
            JsonArray complete = info.getAsJsonArray(key);
            JsonArray page = QueryPaging.slice(
                complete, evidenceOffset, evidenceLimit);
            pagination.add(key, QueryPaging.metadata(
                evidenceOffset, evidenceLimit, page.size(), complete.size()));
            info.add(key, page);
        }
        info.add("evidence_pagination", pagination);

        return info;
    }

    static JsonArray addressRanges(
            ghidra.program.model.address.AddressSetView addresses) {
        JsonArray ranges = new JsonArray();
        var iterator = addresses.getAddressRanges(true);
        while (iterator.hasNext()) {
            var range = iterator.next();
            JsonObject item = new JsonObject();
            item.addProperty("start", range.getMinAddress().toString());
            item.addProperty("end", range.getMaxAddress().toString());
            ranges.add(item);
        }
        return ranges;
    }

    // -----------------------------------------------------------------
    // search_functions_by_name
    // -----------------------------------------------------------------

    static JsonElement searchFunctionsByName(Program program, JsonObject args) {
        String pattern = requireString(args, "pattern");
        Pattern rx;
        try {
            rx = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            return new JsonPrimitive(
                "ERROR: Invalid regex '" + pattern + "': " + e.getMessage());
        }

        FunctionManager fm = program.getFunctionManager();
        List<Function> matched = new ArrayList<>();
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (rx.matcher(f.getName()).find()) {
                matched.add(f);
            }
        }
        Collections.sort(matched, Comparator.comparing(Function::getEntryPoint));

        StringBuilder sb = new StringBuilder();
        sb.append("FIND_FUNC '").append(pattern).append("' in ")
          .append(programName(program)).append("  (")
          .append(matched.size()).append(" matches)\n\n");
        for (Function f : matched) {
            sb.append(f.getEntryPoint()).append("  ").append(f.getName());
            if (f.isThunk()) sb.append(" [thunk]");
            sb.append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // decompile_functions
    // -----------------------------------------------------------------

    static JsonElement decompileFunctions(Program program, JsonObject args) {
        JsonArray addresses = args.getAsJsonArray("addresses");
        if (addresses == null || addresses.size() == 0
                || addresses.size() > BATCH_DECOMPILE_ADDRESSES_MAX) {
            JsonObject error = new JsonObject();
            error.addProperty("error",
                "decompile_functions requires 1..16 addresses; split larger requests");
            return error;
        }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.setOptions(new DecompileOptions());
            decomp.openProgram(program);

            JsonObject results = new JsonObject();
            int used = 0;
            for (JsonElement addrElem : addresses) {
                String addrHex = addrElem.getAsString();
                if (used >= BATCH_DECOMPILE_TOTAL_CHARS) {
                    results.addProperty(addrHex,
                        "// GHIDRAMSC BATCH OUTPUT OMITTED: call "
                        + "decompile_function for paged output.");
                    continue;
                }
                Address addr = toAddress(program, addrHex);
                Function func = resolveFunction(program, addr);
                if (func == null) {
                    results.addProperty(addrHex,
                        "ERROR: No function at " + addrHex);
                    continue;
                }
                DecompileResults res = decomp.decompileFunction(
                    func, 120, TaskMonitor.DUMMY);
                if (res == null || !res.decompileCompleted()) {
                    results.addProperty(addrHex,
                        "ERROR: Decompile failed for " + func.getName());
                    continue;
                }
                String sig = func.getSignature() != null
                    ? func.getSignature().toString() : "";
                String header = "// Function:  " + func.getName() + "\n"
                    + "// Entry:     " + func.getEntryPoint() + "\n"
                    + "// Signature: " + sig + "\n\n";
                String bounded = batchDecompileEntry(
                    header + res.getDecompiledFunction().getC(),
                    BATCH_DECOMPILE_TOTAL_CHARS - used);
                results.addProperty(addrHex, bounded);
                used += bounded.codePointCount(0, bounded.length());
            }
            return results;
        } finally {
            decomp.dispose();
        }
    }

    // -----------------------------------------------------------------
    // get_function_call_graph
    // -----------------------------------------------------------------

    static JsonElement getFunctionCallGraph(
            Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        int depth = optInt(args, "depth", 3);
        Address addr = toAddress(program, addrHex);
        Function func = resolveFunction(program, addr);
        if (func == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "No function at or containing " + addrHex);
            return err;
        }

        return CallRelationshipQueries.callGraph(program, func, depth);
    }

    // -----------------------------------------------------------------
    // list_function_basic_blocks
    // -----------------------------------------------------------------

    static JsonElement listFunctionBasicBlocks(
            Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        Address addr = toAddress(program, addrHex);
        Function func = resolveFunction(program, addr);
        if (func == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "No function at or containing " + addrHex);
            return err;
        }

        BasicBlockModel model = new BasicBlockModel(program);
        try {
            CodeBlockIterator blockIter =
                model.getCodeBlocksContaining(
                    func.getBody(), TaskMonitor.DUMMY);

            JsonArray blocks = new JsonArray();
            while (blockIter.hasNext()) {
                CodeBlock blk = blockIter.next();
                JsonArray successors = new JsonArray();
                CodeBlockReferenceIterator destIter =
                    blk.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    CodeBlockReference dest = destIter.next();
                    successors.add(
                        dest.getDestinationAddress().toString());
                }
                JsonObject bobj = new JsonObject();
                bobj.addProperty("start",
                    blk.getMinAddress().toString());
                bobj.addProperty("end",
                    blk.getMaxAddress().toString());
                bobj.addProperty("size", blk.getNumAddresses());
                bobj.add("successors", successors);
                blocks.add(bobj);
            }

            JsonObject out = new JsonObject();
            out.addProperty("function", func.getName());
            out.addProperty("address",
                func.getEntryPoint().toString());
            out.addProperty("num_blocks", blocks.size());
            out.add("blocks", blocks);
            return out;
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "Failed to get basic blocks: " + e.getMessage());
            return err;
        }
    }

    // -----------------------------------------------------------------
    // get_function_call_relationships
    // -----------------------------------------------------------------

    static JsonElement getFunctionCallRelationships(
            Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        Address addr = toAddress(program, addrHex);
        Function func = resolveFunction(program, addr);
        if (func == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "No function at or containing " + addrHex);
            return err;
        }

        return CallRelationshipQueries.relationships(program, func);
    }

    // -----------------------------------------------------------------
    // get_function_stack_frame
    // -----------------------------------------------------------------

    static JsonElement getFunctionStackFrame(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        Address addr = toAddress(program, addrHex);
        Function func = resolveFunction(program, addr);
        if (func == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "No function at or containing " + addrHex);
            return err;
        }

        return stackFrameState(func);
    }

    static JsonObject stackFrameState(Function func) {
        ghidra.program.model.listing.StackFrame frame =
            func.getStackFrame();
        ghidra.program.model.listing.Variable[] stackVars =
            frame.getStackVariables();
        Arrays.sort(stackVars,
            Comparator.comparingInt(Variable::getStackOffset));

        JsonArray vars = new JsonArray();
        for (ghidra.program.model.listing.Variable v : stackVars) {
            vars.add(stackVariableState(frame, v));
        }

        JsonObject out = new JsonObject();
        out.addProperty("func", func.getName());
        out.addProperty("entry", func.getEntryPoint().toString());
        out.addProperty("frame_size", frame.getFrameSize());
        out.addProperty("local_size", frame.getLocalSize());
        out.addProperty("parameter_size", frame.getParameterSize());
        out.addProperty("param_offset", frame.getParameterOffset());
        out.addProperty("return_addr_offset",
            frame.getReturnAddressOffset());
        out.addProperty("grows_negative", frame.growsNegative());
        out.addProperty("custom_variable_storage",
            func.hasCustomVariableStorage());
        out.add("variables", vars);
        return out;
    }

    static JsonObject stackVariableState(
            ghidra.program.model.listing.StackFrame frame, Variable variable) {
        JsonObject state = new JsonObject();
        int offset = variable.getStackOffset();
        int size = variable.getLength();
        state.addProperty("offset", offset);
        state.addProperty("end_offset", offset + size - 1);
        state.addProperty("name", variable.getName());
        state.addProperty("type", variable.getDataType().getName());
        state.addProperty("display_type",
            variable.getDataType().getDisplayName());
        state.addProperty("type_path",
            variable.getDataType().getPathName());
        state.addProperty("size", size);
        state.addProperty("storage",
            variable.getVariableStorage().toString());
        state.addProperty("source", variable.getSource().toString());
        state.addProperty("comment",
            variable.getComment() == null ? "" : variable.getComment());
        state.addProperty("first_use_offset", variable.getFirstUseOffset());
        state.addProperty("is_parameter", frame.isParameterOffset(offset));
        return state;
    }

}
