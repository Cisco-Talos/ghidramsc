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

import static ghidramsc.MutationTransaction.withTransaction;

import static ghidramsc.MemoryMutationSupport.readBytes;

import static ghidramsc.MutationResult.addTransaction;
import static ghidramsc.MutationResult.baseResult;
import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.noChangeResult;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.statusSuffix;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Bounded disassembly, code-unit, byte, and datatype mutations. */
final class CodeDataMutations {
    private CodeDataMutations() { }

    private static final int DATA_APPLICATION_DETAIL_LIMIT = 64;
    private static final int DATA_APPLICATION_VALUE_LIMIT = 1024;
    private static final int UNINITIALIZED_DATA_MAX_BYTES = 4096;

    // -----------------------------------------------------------------
    // disassemble_memory
    // -----------------------------------------------------------------

    private static final int DISASSEMBLY_MAX_BYTES = 4096;
    private static final int DISASSEMBLY_DETAIL_LIMIT = 64;

    static JsonElement disassembleMemory(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String endHex = QuerySupport.optString(args, "end_hex", "");
        Address start = QuerySupport.toAddress(program, addrHex);
        Address end = endHex.isEmpty()
            ? start : QuerySupport.toAddress(program, endHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("start", start.toString());
        requested.addProperty("end", end.toString());
        if (end.compareTo(start) < 0) {
            return validationFailure("disassemble_memory", requested,
                "End address precedes start address");
        }
        if (!start.getAddressSpace().equals(end.getAddressSpace())
                || end.subtract(start) + 1 > DISASSEMBLY_MAX_BYTES) {
            return validationFailure("disassemble_memory", requested,
                "Range must be within one address space and at most "
                + DISASSEMBLY_MAX_BYTES + " bytes");
        }
        JsonObject oldState = codeState(program, start, end);
        CodeUnit startUnit = program.getListing().getCodeUnitContaining(start);
        if (startUnit != null && !startUnit.getMinAddress().equals(start)) {
            return validationFailure("disassemble_memory", requested,
                "Start is inside an existing code unit; use its start address or clear code units explicitly");
        }
        if (oldState.get("start_is_instruction").getAsBoolean()) {
            return noChangeResult("disassemble_memory", oldState,
                requested, oldState);
        }
        if (startUnit instanceof Data && ((Data) startUnit).isDefined()) {
            return validationFailure("disassemble_memory", requested,
                "Start contains defined data; clear code units explicitly before disassembly");
        }

        return withTransaction(program, "Disassemble", tx -> {
            try {
                AddressSet set = new AddressSet(start, end);
                DisassembleCommand cmd = new DisassembleCommand(
                    start, set, true);
                boolean ok = cmd.applyTo(program, TaskMonitor.DUMMY);
                if (!ok) {
                    return rolledBackResult("disassemble_memory", oldState,
                        requested, "Disassemble failed at " + addrHex
                        + statusSuffix(cmd.getStatusMsg()));
                }
                AddressSetView newly = cmd.getDisassembledAddressSet();
                JsonObject stored = codeState(program, start, end);
                JsonObject newlyState = new JsonObject();
                newlyState.addProperty("address_count",
                    newly.getNumAddresses());
                JsonArray newlyRanges = new JsonArray();
                int newlyRangeCount = 0;
                var newlyIterator = newly.getAddressRanges(true);
                while (newlyIterator.hasNext()) {
                    var span = newlyIterator.next();
                    newlyRangeCount++;
                    if (newlyRanges.size() < DISASSEMBLY_DETAIL_LIMIT) {
                        JsonObject item = new JsonObject();
                        item.addProperty("start", span.getMinAddress().toString());
                        item.addProperty("end", span.getMaxAddress().toString());
                        newlyRanges.add(item);
                    }
                }
                newlyState.add("ranges", newlyRanges);
                newlyState.addProperty("range_count", newlyRangeCount);
                newlyState.addProperty("ranges_truncated",
                    newlyRangeCount > newlyRanges.size());
                stored.add("newly_disassembled", newlyState);
                if (!stored.get("start_is_instruction").getAsBoolean()
                        || newly.getNumAddresses() == 0) {
                    throw new IllegalStateException(
                        "Disassembly read-back found no newly decoded instruction at "
                        + addrHex);
                }
                tx.commit();
                return successResult("disassemble_memory", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("disassemble_memory", oldState,
                    requested, errorMessage(e));
            }
        }, () -> codeState(program, start, end));
    }

    // -----------------------------------------------------------------
    // clear_code_units
    // -----------------------------------------------------------------

    private static final int CLEAR_CODE_UNITS_MAX_BYTES = 4096;
    private static final int CLEAR_CODE_UNITS_MAX_AFFECTED = 128;

    static JsonElement clearCodeUnits(
            Program program, JsonObject args) {
        String startHex = QuerySupport.requireString(args, "start_hex");
        String endHex = QuerySupport.requireString(args, "end_hex");
        boolean previewOnly = QuerySupport.optBool(
            args, "preview_only", true);
        Address start = QuerySupport.toAddress(program, startHex);
        Address end = QuerySupport.toAddress(program, endHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("start", start.toString());
        requested.addProperty("end", end.toString());
        requested.addProperty("preview_only", previewOnly);

        if (!start.getAddressSpace().equals(end.getAddressSpace())
                || end.compareTo(start) < 0) {
            return validationFailure("clear_code_units", requested,
                "Range must be ordered within one address space");
        }
        long length = end.subtract(start) + 1;
        if (length <= 0 || length > CLEAR_CODE_UNITS_MAX_BYTES) {
            return validationFailure("clear_code_units", requested,
                "Range must contain 1 to " + CLEAR_CODE_UNITS_MAX_BYTES
                + " bytes");
        }
        MemoryBlock block = program.getMemory().getBlock(start);
        if (block == null || block != program.getMemory().getBlock(end)
                || !block.isInitialized()) {
            return validationFailure("clear_code_units", requested,
                "Range must lie in one initialized memory block");
        }
        Listing listing = program.getListing();
        CodeUnit first = listing.getCodeUnitContaining(start);
        CodeUnit last = listing.getCodeUnitContaining(end);
        if (first == null || last == null) {
            return validationFailure("clear_code_units", requested,
                "Range has no listing units at both endpoints");
        }
        if (first.getMinAddress().compareTo(start) < 0
                || last.getMaxAddress().compareTo(end) > 0) {
            return validationFailure("clear_code_units", requested,
                "Range cuts through a code unit; use its full boundaries");
        }

        JsonObject oldState = clearCodeUnitsState(program, start, end,
            (int) length);
        int affected = oldState.get("affected_count").getAsInt();
        if (affected > CLEAR_CODE_UNITS_MAX_AFFECTED) {
            return validationFailure("clear_code_units", requested,
                "Range contains more than " + CLEAR_CODE_UNITS_MAX_AFFECTED
                + " defined code units; split the request");
        }
        byte[] originalBytes;
        try {
            originalBytes = readBytes(program, start, (int) length);
        } catch (Exception e) {
            return validationFailure("clear_code_units", requested,
                "Cannot read target bytes: " + errorMessage(e));
        }
        if (previewOnly) {
            JsonObject result = baseResult("clear_code_units", "preview",
                requested);
            result.add("old", oldState.deepCopy());
            result.add("preview", oldState.deepCopy());
            addTransaction(result, null, false, false);
            return result;
        }
        if (affected == 0) {
            return noChangeResult("clear_code_units", oldState,
                requested, oldState.deepCopy());
        }

        JsonElement result = withTransaction(program, "Clear code units", tx -> {
            try {
                listing.clearCodeUnits(start, end, false,
                    TaskMonitor.DUMMY);
                JsonObject stored = clearCodeUnitsState(program, start, end,
                    (int) length);
                if (stored.get("affected_count").getAsInt() != 0) {
                    throw new IllegalStateException(
                        "Clear read-back found remaining defined code units");
                }
                if (!Arrays.equals(originalBytes,
                        readBytes(program, start, (int) length))) {
                    throw new IllegalStateException(
                        "Clear read-back found changed bytes");
                }
                stored.addProperty("bytes_preserved", true);
                stored.addProperty("byte_count", length);
                tx.commit();
                return successResult("clear_code_units", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("clear_code_units", oldState,
                    requested, errorMessage(e));
            }
        }, () -> clearCodeUnitsState(program, start, end, (int) length));
        JsonObject outcome = result.getAsJsonObject();
        if ("rolled_back".equals(outcome.get("status").getAsString())) {
            try {
                JsonObject afterRollback = clearCodeUnitsState(
                    program, start, end, (int) length);
                if (!oldState.equals(afterRollback)
                        || !Arrays.equals(originalBytes,
                            readBytes(program, start, (int) length))) {
                    throw new IllegalStateException(
                        "Listing or bytes differ from the pre-mutation state");
                }
                outcome.add("stored", afterRollback);
            } catch (Exception e) {
                outcome.addProperty("status", "failed");
                outcome.addProperty("error", outcome.get("error").getAsString()
                    + "; rollback verification failed: "
                    + errorMessage(e));
            }
        }
        return outcome;
    }

    // -----------------------------------------------------------------
    // fix_region
    // -----------------------------------------------------------------

    static JsonElement fixRegion(
            Program program, JsonObject args) {
        String startHex = QuerySupport.requireString(args, "start_hex");
        String endHex = QuerySupport.requireString(args, "end_hex");
        Address start = QuerySupport.toAddress(program, startHex);
        Address end = QuerySupport.toAddress(program, endHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("start", start.toString());
        requested.addProperty("end", end.toString());
        if (end.compareTo(start) < 0) {
            return validationFailure("fix_region", requested,
                "End address precedes start address");
        }
        JsonObject oldState = codeState(program, start, end);

        return withTransaction(program, "Fix region", tx -> {
            try {
                AddressSet range = new AddressSet(start, end);
                DisassembleCommand dis = new DisassembleCommand(
                    start, range, true);
                if (!dis.applyTo(program, TaskMonitor.DUMMY)) {
                    return rolledBackResult("fix_region", oldState,
                        requested, "Disassembly failed"
                        + statusSuffix(dis.getStatusMsg()));
                }

                ghidra.program.model.listing.InstructionIterator
                    instructions = program.getListing()
                        .getInstructions(range, true);
                while (instructions.hasNext()) {
                    Address instructionAddress = instructions.next()
                        .getAddress();
                    if (program.getFunctionManager()
                            .getFunctionAt(instructionAddress) != null) {
                        continue;
                    }
                    if (program.getReferenceManager()
                            .getReferencesTo(instructionAddress).hasNext()) {
                        CreateFunctionCmd cmd =
                            new CreateFunctionCmd(instructionAddress);
                        if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                            throw new IllegalStateException(
                                "Failed to create inferred function at "
                                + instructionAddress
                                + statusSuffix(cmd.getStatusMsg()));
                        }
                    }
                }
                JsonObject stored = codeState(program, start, end);
                if (!stored.get("start_is_instruction").getAsBoolean()) {
                    throw new IllegalStateException(
                        "Fixed-region read-back found no instruction at "
                        + startHex);
                }
                tx.commit();
                return successResult("fix_region", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("fix_region", oldState,
                    requested, errorMessage(e));
            }
        }, () -> codeState(program, start, end));
    }

    // -----------------------------------------------------------------
    // write_memory_bytes
    // -----------------------------------------------------------------

    static JsonElement writeMemoryBytes(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String hexBytes = QuerySupport.requireString(
            args, "hex_bytes");
        String cleaned = hexBytes.replace(" ", "")
            .replace("\t", "");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("hex_bytes", cleaned.toLowerCase());
        if (cleaned.length() % 2 != 0) {
            return validationFailure("write_memory_bytes", requested,
                "hex_bytes must have even number of chars");
        }

        byte[] data;
        try {
            data = QuerySupport.hexToBytes(cleaned);
        } catch (Exception e) {
            return validationFailure("write_memory_bytes", requested,
                "Invalid hex: " + errorMessage(e));
        }

        Address addr = QuerySupport.toAddress(program, addrHex);
        JsonObject oldState;
        try {
            oldState = byteState(program, addr, data.length);
        } catch (Exception e) {
            return validationFailure("write_memory_bytes", requested,
                "Cannot read target bytes: " + errorMessage(e));
        }
        if (Arrays.equals(readBytes(program, addr, data.length), data)) {
            return noChangeResult("write_memory_bytes", oldState,
                requested, oldState.deepCopy());
        }

        return withTransaction(program, "Patch bytes", tx -> {
            try {
                program.getMemory().setBytes(addr, data);
                byte[] storedBytes = readBytes(
                    program, addr, data.length);
                if (!Arrays.equals(data, storedBytes)) {
                    throw new IllegalStateException(
                        "Byte read-back mismatch at " + addrHex);
                }
                JsonObject stored = byteState(
                    program, addr, data.length);
                tx.commit();
                return successResult("write_memory_bytes", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("write_memory_bytes", oldState,
                    requested, errorMessage(e));
            }
        }, () -> byteState(program, addr, data.length));
    }

    // -----------------------------------------------------------------
    // apply_data_type
    // -----------------------------------------------------------------

    static JsonElement applyDataType(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String typeName = QuerySupport.requireString(
            args, "type_name");
        String clearMode = QuerySupport.optString(
            args, "clear_mode", "fail");
        Address addr = QuerySupport.toAddress(program, addrHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("type_name", typeName);
        requested.addProperty("clear_mode", clearMode);

        if (!Set.of("fail", "data_only").contains(clearMode)) {
            return validationFailure("apply_data_type", requested,
                "clear_mode must be fail or data_only");
        }

        DataType dt = DataTypeResolver.resolveDataType(program, typeName);
        if (dt == null) {
            return validationFailure("apply_data_type", requested,
                "Unknown data type: " + typeName);
        }
        int length = dt.getLength();
        if (length <= 0) {
            return validationFailure("apply_data_type", requested,
                "Resolved type has no fixed positive size: " + dt);
        }
        requested.addProperty("resolved_type", dt.toString());
        requested.addProperty("size", length);
        JsonObject oldState;
        byte[] originalBytes;
        JsonObject blockState;
        boolean initialized;
        try {
            Address end = addr.add(length - 1);
            MemoryBlock block = program.getMemory().getBlock(addr);
            if (block == null || !block.contains(end)) {
                throw new IllegalArgumentException(
                    "Target range must stay within one mapped memory block");
            }
            AddressSetView initializedSet = program.getMemory()
                .getAllInitializedAddressSet();
            initialized = initializedSet.contains(addr, end);
            if (!initialized && initializedSet.intersects(addr, end)) {
                throw new IllegalArgumentException(
                    "Target range mixes initialized and uninitialized memory");
            }
            if (!initialized && length > UNINITIALIZED_DATA_MAX_BYTES) {
                throw new IllegalArgumentException(
                    "Uninitialized data object exceeds "
                    + UNINITIALIZED_DATA_MAX_BYTES + " bytes");
            }
            blockState = memoryBlockIdentity(
                block, initializedSet, addr, end);
            oldState = dataApplicationState(program, addr, length);
            oldState.add("memory_block", blockState.deepCopy());
            originalBytes = initialized
                ? readBytes(program, addr, length) : null;
        } catch (Exception e) {
            return validationFailure("apply_data_type", requested,
                "Cannot inspect target range: " + errorMessage(e));
        }
        Data existing = program.getListing().getDefinedDataAt(addr);
        if (existing != null
                && existing.getDataType().isEquivalent(dt)) {
            return noChangeResult("apply_data_type", oldState,
                requested, oldState.deepCopy());
        }
        if (oldState.get("has_instructions").getAsBoolean()) {
            JsonObject failure = validationFailure(
                "apply_data_type", requested,
                "Target range contains instructions; apply_data_type never "
                + "clears instructions");
            failure.add("old", oldState.deepCopy());
            return failure;
        }
        if ("fail".equals(clearMode)
                && oldState.getAsJsonArray("conflicts").size() > 0) {
            JsonObject failure = validationFailure(
                "apply_data_type", requested,
                "Target range contains defined data; retry with "
                + "clear_mode=data_only to replace data explicitly");
            failure.add("old", oldState.deepCopy());
            return failure;
        }

        return withTransaction(program, "Apply data type", tx -> {
            try {
                DataUtilities.createData(program, addr, dt,
                    length, false, "data_only".equals(clearMode)
                        ? DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
                        : DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
                Data storedData = program.getListing()
                    .getDefinedDataAt(addr);
                JsonObject stored = dataApplicationState(
                    program, addr, length);
                MemoryBlock storedBlock = program.getMemory().getBlock(addr);
                if (storedBlock == null) {
                    throw new IllegalStateException(
                        "Memory block disappeared while applying data type");
                }
                JsonObject storedBlockState = memoryBlockIdentity(
                    storedBlock, program.getMemory().getAllInitializedAddressSet(),
                    addr, addr.add(length - 1));
                stored.add("memory_block", storedBlockState);
                if (!storedBlockState.equals(blockState)) {
                    throw new IllegalStateException(
                        "Memory block changed while applying data type");
                }
                if (storedData == null
                        || !storedData.getDataType().isEquivalent(dt)
                        || storedData.getLength() != length) {
                    throw new IllegalStateException(
                        "Data-type read-back mismatch at " + addrHex);
                }
                if (initialized) {
                    byte[] storedBytes = readBytes(program, addr, length);
                    boolean bytesPreserved = Arrays.equals(
                        originalBytes, storedBytes);
                    stored.addProperty("bytes_preserved", bytesPreserved);
                    stored.addProperty("byte_count", length);
                    if (!bytesPreserved) {
                        throw new IllegalStateException(
                            "Target bytes changed while applying data type");
                    }
                } else {
                    stored.addProperty("byte_state",
                        "uninitialized_no_file_bytes");
                    stored.addProperty("byte_count", 0);
                    stored.add("bytes_preserved", JsonNull.INSTANCE);
                }
                tx.commit();
                return successResult("apply_data_type", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("apply_data_type", oldState,
                    requested, errorMessage(e));
            }
        }, () -> dataApplicationState(program, addr, length));
    }

    private static JsonObject queryDataState(
            Program program, Address address) {
        Data data = MemoryQueries.resolveDefinedData(program, address);
        if (data == null) {
            JsonObject missing = new JsonObject();
            missing.addProperty("exists", false);
            missing.addProperty("address", address.toString());
            return missing;
        }
        JsonObject state = MemoryQueries.dataState(program, data);
        state.addProperty("exists", true);
        return state;
    }

    private static JsonObject memoryBlockIdentity(
            MemoryBlock block, AddressSetView initializedSet,
            Address start, Address end) {
        JsonObject state = new JsonObject();
        state.addProperty("name", block.getName());
        state.addProperty("start", block.getStart().toString());
        state.addProperty("end", block.getEnd().toString());
        state.addProperty("initialized", block.isInitialized());
        state.addProperty("range_initialized",
            initializedSet.contains(start, end));
        state.addProperty("range_has_initialized_bytes",
            initializedSet.intersects(start, end));
        return state;
    }

    private static JsonObject dataApplicationState(
            Program program, Address address, int length) {
        Address end = address.add(length - 1L);
        AddressSet range = new AddressSet(address, end);
        JsonArray codeUnits = new JsonArray();
        JsonArray conflicts = new JsonArray();
        Set<String> seen = new HashSet<>();
        boolean[] hasInstructions = { false };
        int[] counts = { 0, 0 };
        Listing listing = program.getListing();

        CodeUnit containing = listing.getCodeUnitContaining(address);
        if (containing != null) {
            appendDataApplicationUnit(
                containing, codeUnits, conflicts, seen, hasInstructions,
                counts);
        }
        var iterator = listing.getCodeUnits(range, true);
        while (iterator.hasNext()) {
            appendDataApplicationUnit(
                iterator.next(), codeUnits, conflicts, seen, hasInstructions,
                counts);
        }

        JsonObject state = new JsonObject();
        state.addProperty("address", address.toString());
        state.addProperty("end", end.toString());
        state.addProperty("length", length);
        state.addProperty("has_instructions", hasInstructions[0]);
        state.add("code_units", codeUnits);
        state.addProperty("code_unit_count", counts[0]);
        state.addProperty("code_units_truncated", counts[0] > codeUnits.size());
        state.add("conflicts", conflicts);
        state.addProperty("conflict_count", counts[1]);
        state.addProperty("conflicts_truncated", counts[1] > conflicts.size());
        JsonObject target = queryDataState(program, address);
        if (target.has("value") && target.get("value").isJsonPrimitive()) {
            String value = target.get("value").getAsString();
            if (value.length() > DATA_APPLICATION_VALUE_LIMIT) {
                target.addProperty("value", value.substring(
                    0, DATA_APPLICATION_VALUE_LIMIT));
                target.addProperty("value_length", value.length());
                target.addProperty("value_truncated", true);
            }
        }
        if (target.has("labels") && target.get("labels").isJsonArray()) {
            JsonArray labels = target.getAsJsonArray("labels");
            if (labels.size() > DATA_APPLICATION_DETAIL_LIMIT) {
                JsonArray preview = new JsonArray();
                for (int i = 0; i < DATA_APPLICATION_DETAIL_LIMIT; i++) {
                    preview.add(labels.get(i));
                }
                target.add("labels", preview);
                target.addProperty("label_count", labels.size());
                target.addProperty("labels_truncated", true);
            }
        }
        state.add("target", target);
        return state;
    }

    private static void appendDataApplicationUnit(
            CodeUnit codeUnit, JsonArray codeUnits, JsonArray conflicts,
            Set<String> seen, boolean[] hasInstructions, int[] counts) {
        String key = codeUnit.getAddress().toString();
        if (!seen.add(key)) {
            return;
        }
        counts[0]++;
        boolean instruction = codeUnit instanceof Instruction;
        if (instruction) {
            hasInstructions[0] = true;
        }
        boolean defined = !instruction && ((Data) codeUnit).isDefined();
        if (defined) {
            counts[1]++;
        }
        if (codeUnits.size() >= DATA_APPLICATION_DETAIL_LIMIT
                && (!defined
                    || conflicts.size() >= DATA_APPLICATION_DETAIL_LIMIT)) {
            return;
        }
        JsonObject item = new JsonObject();
        item.addProperty("address", key);
        item.addProperty("end", codeUnit.getMaxAddress().toString());
        item.addProperty("length", codeUnit.getLength());
        if (instruction) {
            item.addProperty("kind", "instruction");
        } else {
            item.addProperty("kind", "data");
            Data data = (Data) codeUnit;
            item.addProperty("type", data.getDataType().toString());
            item.addProperty("defined", defined);
            if (defined && conflicts.size() < DATA_APPLICATION_DETAIL_LIMIT) {
                conflicts.add(item.deepCopy());
            }
        }
        if (codeUnits.size() < DATA_APPLICATION_DETAIL_LIMIT) {
            codeUnits.add(item);
        }
    }

    private static JsonObject codeState(
            Program program, Address start, Address end) {
        AddressSet range = new AddressSet(start, end);
        JsonArray codeUnits = new JsonArray();
        int codeUnitCount = 0;
        var iterator = program.getListing().getCodeUnits(range, true);
        while (iterator.hasNext()) {
            CodeUnit codeUnit = iterator.next();
            codeUnitCount++;
            if (codeUnits.size() >= DISASSEMBLY_DETAIL_LIMIT) {
                continue;
            }
            JsonObject item = new JsonObject();
            item.addProperty("address", codeUnit.getAddress().toString());
            item.addProperty("length", codeUnit.getLength());
            item.addProperty("kind",
                codeUnit instanceof
                    ghidra.program.model.listing.Instruction
                    ? "instruction" : "data");
            String display = codeUnit.toString();
            item.addProperty("text", display.substring(0,
                Math.min(display.length(), 120)));
            codeUnits.add(item);
        }

        JsonArray functions = new JsonArray();
        int functionCount = 0;
        var functionIterator = program.getFunctionManager()
            .getFunctions(range, true);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            functionCount++;
            if (functions.size() >= DISASSEMBLY_DETAIL_LIMIT) {
                continue;
            }
            JsonObject item = new JsonObject();
            item.addProperty("entry",
                function.getEntryPoint().toString());
            item.addProperty("name", function.getName());
            item.addProperty("body_min",
                function.getBody().getMinAddress().toString());
            item.addProperty("body_max",
                function.getBody().getMaxAddress().toString());
            functions.add(item);
        }

        JsonObject state = new JsonObject();
        state.addProperty("start", start.toString());
        state.addProperty("end", end.toString());
        state.addProperty("start_is_instruction",
            program.getListing().getInstructionAt(start) != null);
        state.add("code_units", codeUnits);
        state.addProperty("code_unit_count", codeUnitCount);
        state.addProperty("code_units_truncated",
            codeUnitCount > codeUnits.size());
        state.add("functions", functions);
        state.addProperty("function_count", functionCount);
        state.addProperty("functions_truncated",
            functionCount > functions.size());

        int instructionBytes = 0;
        int undefinedBytes = 0;
        int definedDataBytes = 0;
        int unmappedBytes = 0;
        JsonArray coverageRanges = new JsonArray();
        int coverageRangeCount = 0;
        String previousKind = null;
        Address segmentStart = null;
        Address segmentEnd = null;
        int totalBytes = (int) end.subtract(start) + 1;
        Listing listing = program.getListing();
        for (int offset = 0; offset < totalBytes; offset++) {
            Address address = start.add(offset);
            CodeUnit unit = listing.getCodeUnitContaining(address);
            String kind;
            if (unit == null) {
                kind = "unmapped";
                unmappedBytes++;
            } else if (listing.getInstructionContaining(address) != null) {
                kind = "instruction";
                instructionBytes++;
            } else if (unit instanceof Data && ((Data) unit).isDefined()) {
                kind = "defined_data";
                definedDataBytes++;
            } else {
                kind = "undefined";
                undefinedBytes++;
            }
            if (previousKind != null && !previousKind.equals(kind)) {
                coverageRangeCount++;
                if (coverageRanges.size() < DISASSEMBLY_DETAIL_LIMIT) {
                    coverageRanges.add(coverageRange(segmentStart,
                        segmentEnd, previousKind));
                }
                segmentStart = address;
            } else if (previousKind == null) {
                segmentStart = address;
            }
            previousKind = kind;
            segmentEnd = address;
        }
        if (previousKind != null) {
            coverageRangeCount++;
            if (coverageRanges.size() < DISASSEMBLY_DETAIL_LIMIT) {
                coverageRanges.add(coverageRange(segmentStart,
                    segmentEnd, previousKind));
            }
        }
        JsonObject coverage = new JsonObject();
        coverage.addProperty("total_bytes", totalBytes);
        coverage.addProperty("instruction_bytes", instructionBytes);
        coverage.addProperty("undefined_bytes", undefinedBytes);
        coverage.addProperty("defined_data_bytes", definedDataBytes);
        coverage.addProperty("unmapped_bytes", unmappedBytes);
        coverage.addProperty("complete", instructionBytes == totalBytes);
        coverage.addProperty("status",
            instructionBytes == totalBytes ? "complete" : "partial");
        coverage.add("ranges", coverageRanges);
        coverage.addProperty("range_count", coverageRangeCount);
        coverage.addProperty("ranges_truncated",
            coverageRangeCount > coverageRanges.size());
        state.add("coverage", coverage);
        return state;
    }

    private static JsonObject coverageRange(
            Address start, Address end, String kind) {
        JsonObject range = new JsonObject();
        range.addProperty("start", start.toString());
        range.addProperty("end", end.toString());
        range.addProperty("length", (int) end.subtract(start) + 1);
        range.addProperty("kind", kind);
        return range;
    }

    private static JsonObject clearCodeUnitsState(
            Program program, Address start, Address end, int length) {
        JsonArray units = new JsonArray();
        int affected = 0;
        var iterator = program.getListing().getCodeUnits(
            new AddressSet(start, end), true);
        while (iterator.hasNext()) {
            CodeUnit unit = iterator.next();
            boolean instruction = unit instanceof Instruction;
            if (!instruction && !((Data) unit).isDefined()) {
                continue;
            }
            affected++;
            if (units.size() >= CLEAR_CODE_UNITS_MAX_AFFECTED) {
                continue;
            }
            JsonObject item = new JsonObject();
            item.addProperty("address", unit.getMinAddress().toString());
            item.addProperty("end", unit.getMaxAddress().toString());
            item.addProperty("length", unit.getLength());
            item.addProperty("kind", instruction ? "instruction" : "data");
            String display = unit.toString();
            item.addProperty("display", display.substring(0,
                Math.min(display.length(), 120)));
            units.add(item);
        }
        JsonObject state = new JsonObject();
        state.addProperty("start", start.toString());
        state.addProperty("end", end.toString());
        state.addProperty("length", length);
        state.add("affected_units", units);
        state.addProperty("affected_count", affected);
        state.addProperty("all_undefined", affected == 0);
        return state;
    }

    private static JsonObject byteState(
            Program program, Address address, int length) {
        byte[] bytes = readBytes(program, address, length);
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            hex.append(String.format("%02x", value & 0xff));
        }
        JsonObject state = new JsonObject();
        state.addProperty("address", address.toString());
        state.addProperty("length", length);
        state.addProperty("hex_bytes", hex.toString());
        return state;
    }

}
