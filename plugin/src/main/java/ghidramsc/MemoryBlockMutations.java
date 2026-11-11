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

import static ghidramsc.MemoryMutationSupport.readBytes;
import static ghidramsc.MutationResult.addTransaction;
import static ghidramsc.MutationResult.baseResult;
import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.noChangeResult;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;
import static ghidramsc.MutationTransaction.withTransaction;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/** Program image base, memory block, and recovered-code overlay mutations. */
final class MemoryBlockMutations {
    private MemoryBlockMutations() { }

    private static final int ANALYSIS_BLOCK_MAX_BYTES = 4096;
    private static final String ANALYSIS_BLOCK_SOURCE = "GhidraMSC analysis block";
    private static final int RECOVERED_CODE_MAX_BYTES = 65536;
    private static final String RECOVERED_CODE_COMMENT_PREFIX =
        "GhidraMSC recovered code v1: ";

    // -----------------------------------------------------------------
    // set_program_image_base
    // -----------------------------------------------------------------

    static JsonElement setProgramImageBase(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        Address newBase = QuerySupport.toAddress(program, addrHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("image_base", newBase.toString());
        JsonElement oldState = ProgramQueries.getProgramInfo(
            program, new JsonObject());
        if (program.getImageBase().equals(newBase)) {
            return noChangeResult("set_program_image_base", oldState,
                requested, oldState.deepCopy());
        }

        return withTransaction(program, "Set image base", tx -> {
            try {
                program.setImageBase(newBase, true);
                JsonElement stored = ProgramQueries.getProgramInfo(
                    program, new JsonObject());
                if (!program.getImageBase().equals(newBase)) {
                    throw new IllegalStateException(
                        "Image-base read-back mismatch: requested "
                        + newBase + ", stored " + program.getImageBase());
                }
                tx.commit();
                return successResult("set_program_image_base", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_program_image_base", oldState,
                    requested, errorMessage(e));
            }
        }, () -> ProgramQueries.getProgramInfo(program, new JsonObject()));
    }

    // -----------------------------------------------------------------
    // set_memory_block_permissions
    // -----------------------------------------------------------------

    static JsonElement setMemoryBlockPermissions(
            Program program, JsonObject args) {
        String blockName = QuerySupport.requireString(args, "block_name");
        boolean read = QuerySupport.optBool(args, "read", true);
        boolean write = QuerySupport.optBool(args, "write", false);
        boolean execute = QuerySupport.optBool(
            args, "execute", false);
        JsonObject requested = new JsonObject();
        requested.addProperty("block_name", blockName);
        requested.addProperty("read", read);
        requested.addProperty("write", write);
        requested.addProperty("execute", execute);
        Memory mem = program.getMemory();
        MemoryBlock blk = mem.getBlock(blockName);
        if (blk == null) {
            return validationFailure("set_memory_block_permissions", requested,
                "Memory block not found: " + blockName);
        }
        JsonElement oldState = ProgramQueries.getProgramMemoryMap(
            program, new JsonObject());
        if (blk.isRead() == read && blk.isWrite() == write
                && blk.isExecute() == execute) {
            return noChangeResult("set_memory_block_permissions", oldState,
                requested, oldState.deepCopy());
        }

        return withTransaction(program,
                "Set memory permissions", tx -> {
            try {
                blk.setRead(read);
                blk.setWrite(write);
                blk.setExecute(execute);
                JsonElement stored = ProgramQueries.getProgramMemoryMap(
                    program, new JsonObject());
                if (blk.isRead() != read || blk.isWrite() != write
                        || blk.isExecute() != execute) {
                    throw new IllegalStateException(
                        "Memory-permission read-back mismatch for "
                        + blockName);
                }
                tx.commit();
                return successResult("set_memory_block_permissions", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_memory_block_permissions", oldState,
                    requested, errorMessage(e));
            }
        }, () -> ProgramQueries.getProgramMemoryMap(program, new JsonObject()));
    }

    // Bounded analysis storage. A byte-mapped block aliases its source.
    static JsonElement createMemoryBlock(Program program, JsonObject args) {
        final String op = "create_memory_block";
        String name = QuerySupport.requireString(args, "block_name");
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        int length = QuerySupport.requireInt(args, "length");
        String mode = QuerySupport.requireString(args, "mode");
        boolean overlay = QuerySupport.optBool(args, "overlay", false);
        boolean read = QuerySupport.optBool(args, "read", true);
        boolean write = QuerySupport.optBool(args, "write", true);
        boolean execute = QuerySupport.optBool(args, "execute", false);
        int fill = QuerySupport.optInt(args, "fill_byte", 0);
        String hex = QuerySupport.optString(args, "hex_bytes", "");
        String sourceHex = QuerySupport.optString(args, "source_addr_hex", "");
        boolean previewOnly = QuerySupport.optBool(args, "preview_only", false);
        JsonObject requested = args.deepCopy();
        if (name.isBlank() || !name.equals(name.trim())) {
            return validationFailure(op, requested, "block_name must be nonempty and have no surrounding whitespace");
        }
        if (!mode.equals("uninitialized") && !mode.equals("fill")
                && !mode.equals("bytes") && !mode.equals("byte_mapped")) {
            return validationFailure(op, requested, "mode must be uninitialized, fill, bytes, or byte_mapped");
        }
        if (length < 1 || length > ANALYSIS_BLOCK_MAX_BYTES) {
            return validationFailure(op, requested, "length must be 1..4096 bytes");
        }
        if (fill < 0 || fill > 255) {
            return validationFailure(op, requested, "fill_byte must be 0..255");
        }
        if ((!mode.equals("fill") && fill != 0)
                || (!mode.equals("bytes") && !hex.isEmpty())
                || (!mode.equals("byte_mapped") && !sourceHex.isEmpty())) {
            return validationFailure(op, requested, "fill_byte, hex_bytes, and source_addr_hex require their matching mode");
        }
        byte[] data = new byte[0];
        if (mode.equals("bytes")) {
            if (!hex.matches("[0-9a-fA-F]+") || hex.length() != length * 2) {
                return validationFailure(op, requested, "hex_bytes must contain exactly length bytes");
            }
            data = new byte[length];
            for (int i = 0; i < length; i++) {
                data[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
            }
        }
        final byte[] targetBytes = data;
        Memory mem = program.getMemory();
        if (mem.getBlock(name) != null) {
            return validationFailure(op, requested, "Memory block name already exists: " + name);
        }
        Address start;
        Address end;
        try {
            start = QuerySupport.toAddress(program, addrHex);
            end = start.addNoWrap(length - 1);
            if (start.getAddressSpace().isOverlaySpace()) {
                return validationFailure(op, requested, "Create start must be in the physical address space");
            }
        } catch (Exception error) {
            return validationFailure(op, requested, "Invalid target range: " + errorMessage(error));
        }
        JsonArray overlaps = new JsonArray();
        for (MemoryBlock block : mem.getBlocks()) {
            if (block.getStart().getAddressSpace().equals(start.getAddressSpace())
                    && block.getStart().compareTo(end) <= 0
                    && block.getEnd().compareTo(start) >= 0) {
                overlaps.add(block.getName());
            }
        }
        if (overlaps.size() > 0 && !overlay) {
            return validationFailure(op, requested, "Target range overlaps existing blocks: " + overlaps);
        }
        Address source = null;
        if (mode.equals("byte_mapped")) {
            try {
                source = QuerySupport.toAddress(program, sourceHex);
                Address sourceEnd = source.addNoWrap(length - 1);
                MemoryBlock sourceBlock = mem.getBlock(source);
                if (sourceBlock == null || !sourceBlock.isInitialized()
                        || sourceBlock.getEnd().compareTo(sourceEnd) < 0) {
                    return validationFailure(op, requested, "Source range must lie in one initialized memory block");
                }
            } catch (Exception error) {
                return validationFailure(op, requested, "Invalid source range: " + errorMessage(error));
            }
        }
        final Address target = start;
        final Address mappedSource = source;
        JsonElement old = ProgramQueries.getProgramMemoryMap(program, new JsonObject());
        JsonObject preview = new JsonObject();
        preview.addProperty("start", start.toString());
        preview.addProperty("end", end.toString());
        preview.addProperty("length", length);
        preview.add("overlaps", overlaps);
        preview.addProperty("overlay", overlay);
        preview.addProperty("source_aliases_original", mode.equals("byte_mapped"));
        JsonArray existingSymbols = new JsonArray();
        for (int offset = 0; offset < length && existingSymbols.size() < 16; offset++) {
            for (Symbol symbol : program.getSymbolTable().getSymbols(start.add(offset))) {
                JsonObject item = new JsonObject();
                item.addProperty("address", symbol.getAddress().toString());
                item.addProperty("name", symbol.getName());
                item.addProperty("source", symbol.getSource().toString());
                existingSymbols.add(item);
                if (existingSymbols.size() >= 16) {
                    break;
                }
            }
        }
        preview.add("existing_symbols_sample", existingSymbols);
        if (previewOnly) {
            JsonObject result = baseResult(op, "preview", requested);
            result.add("old", old.deepCopy());
            result.add("stored", old.deepCopy());
            result.add("preview", preview);
            addTransaction(result, null, false, false);
            return result;
        }
        return withTransaction(program, "Create analysis memory block", tx -> {
            try {
                MemoryBlock block;
                if (mode.equals("uninitialized")) {
                    block = mem.createUninitializedBlock(name, target, length, overlay);
                } else if (mode.equals("byte_mapped")) {
                    block = mem.createByteMappedBlock(name, target, mappedSource, length, overlay);
                } else {
                    block = mem.createInitializedBlock(name, target, length,
                        (byte) fill, TaskMonitor.DUMMY, overlay);
                    if (mode.equals("bytes")) {
                        mem.setBytes(block.getStart(), targetBytes);
                    }
                }
                block.setSourceName(ANALYSIS_BLOCK_SOURCE);
                block.setRead(read);
                block.setWrite(write);
                block.setExecute(execute);
                MemoryBlock storedBlock = mem.getBlock(name);
                if (storedBlock == null || storedBlock.getSize() != length
                        || storedBlock.isOverlay() != overlay
                        || storedBlock.isRead() != read || storedBlock.isWrite() != write
                        || storedBlock.isExecute() != execute
                        || !ANALYSIS_BLOCK_SOURCE.equals(storedBlock.getSourceName())
                        || (mode.equals("uninitialized") && storedBlock.isInitialized())
                        || ((mode.equals("fill") || mode.equals("bytes")) && !storedBlock.isInitialized())
                        || (mode.equals("byte_mapped") && !storedBlock.getType().toString().equals("Byte Mapped"))) {
                    throw new IllegalStateException("Created block read-back mismatch");
                }
                if (mode.equals("bytes") && !Arrays.equals(
                        readBytes(program, storedBlock.getStart(), length), targetBytes)) {
                    throw new IllegalStateException("Created block bytes read-back mismatch");
                }
                JsonElement stored = ProgramQueries.getProgramMemoryMap(program, new JsonObject());
                tx.commit();
                JsonObject result = successResult(op, old, requested, stored);
                result.add("preview", preview);
                return result;
            } catch (Exception error) {
                JsonObject result = rolledBackResult(op, old, requested, errorMessage(error));
                result.add("preview", preview);
                return result;
            }
        }, () -> ProgramQueries.getProgramMemoryMap(program, new JsonObject()));
    }

    static JsonElement deleteMemoryBlock(Program program, JsonObject args) {
        final String op = "delete_memory_block";
        String name = QuerySupport.requireString(args, "block_name");
        String start = QuerySupport.requireString(args, "start");
        int length = QuerySupport.requireInt(args, "length");
        boolean previewOnly = QuerySupport.optBool(args, "preview_only", false);
        boolean confirm = QuerySupport.optBool(args, "confirm_content_removal", false);
        JsonObject requested = args.deepCopy();
        Memory mem = program.getMemory();
        MemoryBlock block = mem.getBlock(name);
        if (block == null || !block.getStart().toString().equals(start)
                || block.getSize() != length
                || !ANALYSIS_BLOCK_SOURCE.equals(block.getSourceName())) {
            return validationFailure(op, requested, "Block identity or GhidraMSC analysis provenance does not match");
        }
        JsonArray occupied = new JsonArray();
        JsonArray contentDetails = new JsonArray();
        for (int offset = 0; offset < length; offset++) {
            Address address = block.getStart().add(offset);
            boolean instruction = program.getListing().getInstructionContaining(address) != null;
            boolean data = program.getListing().getDefinedDataContaining(address) != null;
            Symbol[] atSymbols = program.getSymbolTable().getSymbols(address);
            if (instruction || data || atSymbols.length > 0) {
                occupied.add(address.toString());
                JsonObject detail = new JsonObject();
                detail.addProperty("address", address.toString());
                detail.addProperty("instruction", instruction);
                detail.addProperty("defined_data", data);
                JsonArray names = new JsonArray();
                for (int index = 0; index < atSymbols.length && index < 8; index++) {
                    JsonObject symbol = new JsonObject();
                    symbol.addProperty("name", atSymbols[index].getName());
                    symbol.addProperty("source", atSymbols[index].getSource().toString());
                    names.add(symbol);
                }
                detail.add("symbols", names);
                contentDetails.add(detail);
                if (occupied.size() >= 16) {
                    break;
                }
            }
        }
        JsonObject preview = new JsonObject();
        preview.addProperty("start", start);
        preview.addProperty("end", block.getEnd().toString());
        preview.addProperty("length", length);
        preview.add("content_addresses_sample", occupied);
        preview.add("content_details_sample", contentDetails);
        preview.addProperty("content_removal_required", occupied.size() > 0);
        JsonElement old = ProgramQueries.getProgramMemoryMap(program, new JsonObject());
        if (previewOnly) {
            JsonObject result = baseResult(op, "preview", requested);
            result.add("old", old.deepCopy());
            result.add("stored", old.deepCopy());
            result.add("preview", preview);
            addTransaction(result, null, false, false);
            return result;
        }
        if (occupied.size() > 0 && !confirm) {
            return validationFailure(op, requested,
                "Block contains code, data, or symbols; preview and explicitly confirm removal");
        }
        return withTransaction(program, "Remove analysis memory block", tx -> {
            try {
                mem.removeBlock(block, TaskMonitor.DUMMY);
                if (mem.getBlock(name) != null) {
                    throw new IllegalStateException("Removed block is still present");
                }
                JsonElement stored = ProgramQueries.getProgramMemoryMap(program, new JsonObject());
                tx.commit();
                JsonObject result = successResult(op, old, requested, stored);
                result.add("preview", preview);
                return result;
            } catch (Exception error) {
                JsonObject result = rolledBackResult(op, old, requested, errorMessage(error));
                result.add("preview", preview);
                return result;
            }
        }, () -> ProgramQueries.getProgramMemoryMap(program, new JsonObject()));
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    static JsonElement createRecoveredCodeOverlay(
            Program program, JsonObject args) {
        final String op = "create_recovered_code_overlay";
        String name = QuerySupport.requireString(args, "block_name");
        String analysisHex = QuerySupport.requireString(args, "analysis_addr_hex");
        String hex = QuerySupport.requireString(args, "hex_bytes");
        String sourceHex = QuerySupport.optString(args, "source_addr_hex", "");
        int sourceLength = QuerySupport.optInt(args, "source_length", 0);
        String runtimeHex = QuerySupport.optString(args, "runtime_addr_hex", "");
        String transform = QuerySupport.requireString(args, "transform");
        boolean allowOverlap = QuerySupport.optBool(args, "allow_physical_overlap", false);
        boolean previewOnly = QuerySupport.optBool(args, "preview_only", false);
        JsonObject requested = new JsonObject();
        requested.addProperty("block_name", name);
        requested.addProperty("analysis_addr_hex", analysisHex);
        requested.addProperty("source_addr_hex", sourceHex);
        requested.addProperty("source_length", sourceLength);
        requested.addProperty("runtime_addr_hex", runtimeHex);
        requested.addProperty("transform", transform);
        requested.addProperty("allow_physical_overlap", allowOverlap);
        requested.addProperty("preview_only", previewOnly);
        if (name.isBlank() || !name.equals(name.trim()) || name.length() > 80
                || transform.isEmpty() || transform.length() > 256) {
            return validationFailure(op, requested,
                "Invalid block name or transform");
        }
        if (sourceLength < 0 || sourceLength > RECOVERED_CODE_MAX_BYTES
                || sourceHex.isEmpty() != (sourceLength == 0)) {
            return validationFailure(op, requested,
                "source_addr_hex and positive source_length must be supplied together (max 65536)");
        }
        if (hex.isEmpty() || hex.length() % 2 != 0
                || hex.length() > 2 * RECOVERED_CODE_MAX_BYTES
                || !hex.matches("[0-9a-fA-F]+")) {
            return validationFailure(op, requested,
                "hex_bytes must contain 1..65536 exact bytes");
        }
        int length = hex.length() / 2;
        byte[] recovered = new byte[length];
        for (int i = 0; i < length; i++) {
            recovered[i] = (byte) Integer.parseInt(
                hex.substring(2 * i, 2 * i + 2), 16);
        }
        String digest = sha256(recovered);
        requested.addProperty("length", length);
        requested.addProperty("sha256", digest);
        Memory mem = program.getMemory();
        if (mem.getBlock(name) != null) {
            return validationFailure(op, requested,
                "Memory block name already exists: " + name);
        }
        Address start;
        Address end;
        Address source = null;
        MemoryBlock sourceBlock = null;
        try {
            start = QuerySupport.toAddress(program, analysisHex);
            end = start.addNoWrap(length - 1);
            if (start.getAddressSpace().isOverlaySpace()) {
                return validationFailure(op, requested,
                    "analysis_addr_hex must name the physical address space");
            }
            if (!sourceHex.isEmpty()) {
                source = QuerySupport.toAddress(program, sourceHex);
                Address sourceEnd = source.addNoWrap(sourceLength - 1);
                sourceBlock = mem.getBlock(source);
                if (source.getAddressSpace().isOverlaySpace() || sourceBlock == null
                        || sourceBlock.getEnd().compareTo(sourceEnd) < 0) {
                    return validationFailure(op, requested,
                        "Source range must lie in one existing physical block");
                }
            }
            if (!runtimeHex.isEmpty()) {
                if (runtimeHex.contains("::")) {
                    return validationFailure(op, requested,
                        "runtime_addr_hex must be a bare hex address");
                }
                QuerySupport.toAddress(program, runtimeHex);
            }
        } catch (Exception error) {
            return validationFailure(op, requested,
                "Invalid analysis/source/runtime range: " + errorMessage(error));
        }
        JsonArray overlaps = new JsonArray();
        for (MemoryBlock block : mem.getBlocks()) {
            if (block.getStart().getAddressSpace().equals(start.getAddressSpace())
                    && block.getStart().compareTo(end) <= 0
                    && block.getEnd().compareTo(start) >= 0) {
                overlaps.add(block.getName());
            }
        }
        if (overlaps.size() > 0 && !allowOverlap) {
            return validationFailure(op, requested,
                "Physical range overlaps existing blocks; set allow_physical_overlap explicitly");
        }
        byte[] sourceBefore = null;
        if (source != null && sourceBlock.isInitialized()) {
            sourceBefore = readBytes(program, source, sourceLength);
        }
        byte[] physicalBefore = null;
        MemoryBlock physicalBlock = mem.getBlock(start);
        if (physicalBlock != null && physicalBlock.isInitialized()
                && physicalBlock.getEnd().compareTo(end) >= 0) {
            physicalBefore = readBytes(program, start, length);
        }
        JsonObject metadata = new JsonObject();
        metadata.addProperty("analysis_requested_start", start.toString());
        metadata.addProperty("source_start", source == null ? null : source.toString());
        metadata.addProperty("source_length", sourceLength);
        metadata.addProperty("runtime_start", runtimeHex.isEmpty() ? null : runtimeHex);
        metadata.addProperty("transform", transform);
        metadata.addProperty("length", length);
        metadata.addProperty("sha256", digest);
        String comment = RECOVERED_CODE_COMMENT_PREFIX + metadata;
        JsonObject preview = new JsonObject();
        preview.addProperty("analysis_requested_start", start.toString());
        preview.addProperty("length", length);
        preview.addProperty("sha256", digest);
        preview.add("physical_overlaps", overlaps);
        preview.addProperty("source_sha256", sourceBefore == null ? null : sha256(sourceBefore));
        preview.addProperty("physical_sha256", physicalBefore == null ? null : sha256(physicalBefore));
        JsonObject old = new JsonObject();
        old.addProperty("block_present", false);
        old.add("physical_overlaps", overlaps.deepCopy());
        if (previewOnly) {
            JsonObject result = baseResult(op, "preview", requested);
            result.add("old", old.deepCopy());
            result.add("stored", old.deepCopy());
            result.add("preview", preview);
            addTransaction(result, null, false, false);
            return result;
        }
        final Address target = start;
        final Address sourceAddress = source;
        final byte[] sourceSnapshot = sourceBefore;
        final byte[] physicalSnapshot = physicalBefore;
        return withTransaction(program, "Create recovered code overlay", tx -> {
            try {
                MemoryBlock block = mem.createInitializedBlock(name, target,
                    new ByteArrayInputStream(recovered), length,
                    TaskMonitor.DUMMY, true);
                block.setSourceName(ANALYSIS_BLOCK_SOURCE);
                block.setComment(comment);
                block.setRead(true);
                block.setWrite(false);
                block.setExecute(true);
                MemoryBlock storedBlock = mem.getBlock(name);
                if (storedBlock == null || storedBlock.getSize() != length
                        || !storedBlock.isOverlay() || !storedBlock.isInitialized()
                        || !storedBlock.isRead() || storedBlock.isWrite()
                        || !storedBlock.isExecute()
                        || !ANALYSIS_BLOCK_SOURCE.equals(storedBlock.getSourceName())
                        || !comment.equals(storedBlock.getComment())
                        || !Arrays.equals(readBytes(program, storedBlock.getStart(), length),
                            recovered)
                        || (sourceSnapshot != null && !Arrays.equals(
                            readBytes(program, sourceAddress, sourceLength), sourceSnapshot))
                        || (physicalSnapshot != null && !Arrays.equals(
                            readBytes(program, target, length), physicalSnapshot))) {
                    throw new IllegalStateException(
                        "Recovered overlay, provenance, or original-byte read-back mismatch");
                }
                JsonObject stored = new JsonObject();
                stored.addProperty("block_present", true);
                stored.addProperty("name", storedBlock.getName());
                stored.addProperty("start", storedBlock.getStart().toString());
                stored.addProperty("length", storedBlock.getSize());
                stored.addProperty("overlay", storedBlock.isOverlay());
                stored.addProperty("initialized", storedBlock.isInitialized());
                stored.addProperty("sha256", digest);
                stored.addProperty("comment", comment);
                stored.addProperty("source_bytes_preserved", true);
                stored.addProperty("physical_bytes_preserved", true);
                tx.commit();
                JsonObject result = successResult(op, old, requested, stored);
                result.add("preview", preview);
                return result;
            } catch (Exception error) {
                JsonObject result = rolledBackResult(op, old, requested,
                    errorMessage(error));
                result.add("preview", preview);
                return result;
            }
        }, () -> ProgramQueries.getProgramMemoryMap(program, new JsonObject()));
    }

}
