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

import static ghidramsc.MutationArguments.requireJsonArray;
import static ghidramsc.MutationArguments.requireJsonString;

import static ghidramsc.MutationResult.batchResult;
import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.mutationStatus;
import static ghidramsc.MutationResult.noChangeResult;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.statusSuffix;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;
import java.util.Set;

/** Function creation, body, deletion, and rename mutations. */
final class FunctionLifecycleMutations {
    private FunctionLifecycleMutations() { }

    // -----------------------------------------------------------------
    // set_function_name
    // -----------------------------------------------------------------

    static JsonElement setFunctionName(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String newName = QuerySupport.requireString(args, "new_name");
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("name", newName);
        if (func == null) {
            return renameResult("validation_failed", requested, null, null,
                "No function at or containing " + addrHex);
        }
        JsonObject oldState = renameFunctionState(func);
        if (newName.equals(func.getName())) {
            return renameResult("no_change", requested, oldState,
                oldState.deepCopy(), null);
        }

        int txId = program.startTransaction("Rename function");
        boolean commit = false;
        JsonObject storedState = null;
        String error = null;
        try {
            func.setName(newName, SourceType.USER_DEFINED);
            Function storedFunction = QuerySupport.resolveFunction(
                program, addr);
            storedState = renameFunctionState(storedFunction);
            String storedName = storedState == null
                ? null : storedState.get("name").getAsString();
            if (!newName.equals(storedName)) {
                throw new IllegalStateException(
                    "Function name read-back mismatch: requested "
                    + newName + ", stored " + storedName);
            }
            commit = true;
        } catch (Exception e) {
            error = errorMessage(e);
        } finally {
            program.endTransaction(txId, commit);
        }

        if (commit) {
            return renameResult("success", requested, oldState,
                storedState, null);
        }
        try {
            storedState = renameFunctionState(
                QuerySupport.resolveFunction(program, addr));
        } catch (Exception ignored) {
            storedState = null;
        }
        return renameResult("rolled_back", requested, oldState,
            storedState, error);
    }

    // -----------------------------------------------------------------
    // set_function_names
    // -----------------------------------------------------------------

    static JsonElement setFunctionNames(
            Program program, JsonObject args) {
        // json_data is the inline content (bridge pre-reads files)
        JsonArray pairs;
        try {
            pairs = requireJsonArray(args, "json_data");
            for (JsonElement elem : pairs) {
                if (!elem.isJsonObject()) {
                    throw new IllegalArgumentException(
                        "set_function_names entries must be objects");
                }
                JsonObject entry = elem.getAsJsonObject();
                requireJsonString(entry, "addr");
                requireJsonString(entry, "name");
            }
        } catch (Exception e) {
            return validationFailure("set_function_names", args,
                errorMessage(e));
        }

        JsonArray items = new JsonArray();
        int succeeded = 0;
        int unchanged = 0;
        int failed = 0;
        for (JsonElement elem : pairs) {
            JsonObject entry = elem.getAsJsonObject();
            JsonObject itemArgs = new JsonObject();
            itemArgs.addProperty("addr_hex",
                entry.get("addr").getAsString());
            itemArgs.addProperty("new_name",
                entry.get("name").getAsString());
            String status;
            try {
                JsonElement rename = setFunctionName(program, itemArgs);
                items.add(compactRenameItem(rename));
                status = mutationStatus(rename);
            } catch (Exception e) {
                items.add(compactRenameFailure(
                    entry.get("addr").getAsString(),
                    entry.get("name").getAsString(),
                    errorMessage(e)));
                status = "validation_failed";
            }
            if ("success".equals(status)) {
                succeeded++;
            } else if ("no_change".equals(status)) {
                unchanged++;
            } else {
                failed++;
            }
        }
        return batchRenameResult(items,
            succeeded, unchanged, failed);
    }

    // -----------------------------------------------------------------
    // delete_function
    // -----------------------------------------------------------------

    static JsonElement deleteFunction(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addr.toString());
        JsonArray conflicts = new JsonArray();
        if (func == null) {
            return withFunctionConflicts(
                validationFailure("delete_function", requested,
                    "No function at or containing " + addrHex), conflicts);
        }

        Address entry = func.getEntryPoint();
        requested.addProperty("entry", entry.toString());
        JsonObject oldState = FunctionMutationReadback.queryFunctionAtState(
            program, entry.toString());
        return withTransaction(program, "Remove function", tx -> {
            try {
                boolean removed = program.getFunctionManager()
                    .removeFunction(entry);
                if (!removed || program.getFunctionManager()
                        .getFunctionAt(entry) != null) {
                    throw new IllegalStateException(
                        "Function was not removed at " + entry);
                }
                JsonObject stored = FunctionMutationReadback.queryFunctionAtState(
                    program, entry.toString());
                tx.commit();
                return withFunctionConflicts(
                    successResult("delete_function", oldState,
                        requested, stored), conflicts);
            } catch (Exception e) {
                return withFunctionConflicts(
                    rolledBackResult("delete_function", oldState,
                        requested, errorMessage(e)), conflicts);
            }
        }, () -> FunctionMutationReadback.queryFunctionAtState(program, entry.toString()));
    }

    // -----------------------------------------------------------------
    // set_function_body
    // -----------------------------------------------------------------

    static JsonElement setFunctionBody(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addr.toString());
        if (args.has("ranges")) {
            requested.add("ranges", args.get("ranges").deepCopy());
        }
        JsonArray noConflicts = new JsonArray();
        if (func == null) {
            return withFunctionConflicts(
                validationFailure("set_function_body", requested,
                    "No function at or containing " + addrHex),
                noConflicts);
        }

        Address entry = func.getEntryPoint();
        requested.addProperty("entry", entry.toString());
        AddressSet body;
        try {
            JsonArray rangeSpecs = requireJsonArray(args, "ranges");
            body = requireFunctionBodyRanges(program, rangeSpecs, entry);
            requested.add("ranges", FunctionQueries.addressRanges(body));
        } catch (Exception e) {
            JsonObject failure = validationFailure(
                "set_function_body", requested, errorMessage(e));
            failure.add("old", FunctionMutationReadback.queryFunctionAtState(
                program, entry.toString()));
            return withFunctionConflicts(failure, noConflicts);
        }

        JsonObject oldState = FunctionMutationReadback.queryFunctionAtState(
            program, entry.toString());
        JsonArray conflicts = conflictingFunctions(
            program, body, entry);
        if (!conflicts.isEmpty()) {
            JsonObject failure = validationFailure(
                "set_function_body", requested,
                "Requested body overlaps existing functions");
            failure.add("old", oldState.deepCopy());
            return withFunctionConflicts(failure, conflicts);
        }
        if (func.getBody().hasSameAddresses(body)) {
            return withFunctionConflicts(
                noChangeResult("set_function_body", oldState,
                    requested, oldState.deepCopy()), conflicts);
        }

        return withTransaction(program, "Set function body", tx -> {
            try {
                func.setBody(body);
                Function storedFunction = program.getFunctionManager()
                    .getFunctionAt(entry);
                if (storedFunction == null
                        || !storedFunction.getBody()
                            .hasSameAddresses(body)) {
                    throw new IllegalStateException(
                        "Function body read-back did not match the request");
                }
                JsonObject stored = FunctionMutationReadback.queryFunctionAtState(
                    program, entry.toString());
                tx.commit();
                return withFunctionConflicts(
                    successResult("set_function_body", oldState,
                        requested, stored), conflicts);
            } catch (Exception e) {
                return withFunctionConflicts(
                    rolledBackResult("set_function_body", oldState,
                        requested, errorMessage(e)), conflicts);
            }
        }, () -> FunctionMutationReadback.queryFunctionAtState(program, entry.toString()));
    }

    // -----------------------------------------------------------------
    // create_function
    // -----------------------------------------------------------------

    static JsonElement createFunction(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String name = QuerySupport.optString(args, "name", "");
        Address addr = QuerySupport.toAddress(program, addrHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addr.toString());
        requested.addProperty("name", name);
        AddressSet body = null;
        JsonArray rangeSpecs = optionalJsonArray(args, "ranges");
        if (rangeSpecs != null && !rangeSpecs.isEmpty()) {
            try {
                body = requireFunctionBodyRanges(program, rangeSpecs, addr);
                requested.add("ranges", FunctionQueries.addressRanges(body));
            } catch (Exception e) {
                return withFunctionConflicts(
                    validationFailure("create_function", requested,
                        errorMessage(e)), new JsonArray());
            }
        }
        JsonElement oldState = FunctionMutationReadback.queryFunctionAtState(program, addrHex);
        Function existing = QuerySupport.resolveFunction(program, addr);
        if (existing != null) {
            JsonArray conflicts = new JsonArray();
            conflicts.add(functionConflictState(existing));
            JsonObject failure = validationFailure(
                "create_function", requested,
                "A function already exists at or contains " + addrHex);
            failure.add("old", oldState.deepCopy());
            return withFunctionConflicts(failure, conflicts);
        }
        JsonArray conflicts = body == null
            ? new JsonArray()
            : conflictingFunctions(program, body, null);
        if (!conflicts.isEmpty()) {
            JsonObject failure = validationFailure(
                "create_function", requested,
                "Requested body overlaps existing functions");
            failure.add("old", oldState.deepCopy());
            return withFunctionConflicts(failure, conflicts);
        }

        AddressSet explicitBody = body;
        return withTransaction(program, "Create function", tx -> {
            try {
                CreateFunctionCmd cmd = explicitBody == null
                    ? new CreateFunctionCmd(addr)
                    : new CreateFunctionCmd(
                        name.isEmpty() ? null : name,
                        addr, explicitBody,
                        name.isEmpty()
                            ? SourceType.DEFAULT
                            : SourceType.USER_DEFINED);
                boolean ok = cmd.applyTo(program, TaskMonitor.DUMMY);
                if (!ok) {
                    throw new IllegalStateException(
                        "Failed to create function at " + addrHex
                        + statusSuffix(cmd.getStatusMsg()));
                }
                Function func = program.getFunctionManager()
                    .getFunctionAt(addr);
                if (func == null) {
                    throw new IllegalStateException(
                        "Function was not stored at " + addrHex);
                }
                if (!name.isEmpty()) {
                    func.setName(name, SourceType.USER_DEFINED);
                }
                if (explicitBody != null
                        && !func.getBody()
                            .hasSameAddresses(explicitBody)) {
                    throw new IllegalStateException(
                        "Function body read-back did not match the request");
                }
                JsonElement stored = FunctionMutationReadback.queryFunctionAtState(
                    program, addrHex);
                JsonObject storedObject = stored.getAsJsonObject();
                if (!storedObject.get("exists").getAsBoolean()
                        || !name.isEmpty()
                        && !name.equals(storedObject.get("name")
                            .getAsString())) {
                    throw new IllegalStateException(
                        "Function read-back did not match the request");
                }
                tx.commit();
                return withFunctionConflicts(
                    successResult("create_function", oldState,
                        requested, stored), conflicts);
            } catch (Exception e) {
                return withFunctionConflicts(
                    rolledBackResult("create_function", oldState,
                        requested, errorMessage(e)), conflicts);
            }
        }, () -> FunctionMutationReadback.queryFunctionAtState(program, addrHex));
    }

    // -----------------------------------------------------------------
    // create_stack_variable / delete_stack_variable / create_stack_variable_from_structure
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // create_functions
    // -----------------------------------------------------------------

    static JsonElement createFunctions(
            Program program, JsonObject args) {
        JsonArray entries;
        try {
            entries = requireJsonArray(args, "json_data");
            for (JsonElement elem : entries) {
                if (elem.isJsonObject()) {
                    JsonObject entry = elem.getAsJsonObject();
                    requireJsonString(entry, "addr");
                    if (entry.has("name")) {
                        requireJsonString(entry, "name");
                    }
                } else if (!elem.isJsonPrimitive()
                        || !elem.getAsJsonPrimitive().isString()) {
                    throw new IllegalArgumentException(
                        "create_functions entries must be address strings or objects");
                }
            }
        } catch (Exception e) {
            return validationFailure("create_functions", args,
                errorMessage(e));
        }

        JsonArray items = new JsonArray();
        int succeeded = 0;
        int unchanged = 0;
        int failed = 0;
        for (JsonElement elem : entries) {
            String address;
            String name = "";
            if (elem.isJsonObject()) {
                JsonObject entry = elem.getAsJsonObject();
                address = entry.get("addr").getAsString();
                name = entry.has("name")
                    ? entry.get("name").getAsString() : "";
            } else {
                address = elem.getAsString();
            }
            JsonObject itemArgs = new JsonObject();
            itemArgs.addProperty("addr_hex", address);
            itemArgs.addProperty("name", name);
            JsonElement item;
            try {
                item = createFunction(program, itemArgs);
            } catch (Exception e) {
                JsonObject itemRequested = new JsonObject();
                itemRequested.addProperty("address", address);
                itemRequested.addProperty("name", name);
                item = validationFailure("create_function", itemRequested,
                    errorMessage(e));
            }
            items.add(item);
            String status = mutationStatus(item);
            if ("success".equals(status)) {
                succeeded++;
            } else if ("no_change".equals(status)) {
                unchanged++;
            } else {
                failed++;
            }
        }
        return batchResult("create_functions", entries, items,
            succeeded, unchanged, failed);
    }

    private static AddressSet requireFunctionBodyRanges(
            Program program, JsonArray ranges, Address entry) {
        if (ranges.isEmpty()) {
            throw new IllegalArgumentException(
                "ranges must contain at least one inclusive address range");
        }

        AddressSet body = new AddressSet();
        for (JsonElement element : ranges) {
            if (!element.isJsonObject()) {
                throw new IllegalArgumentException(
                    "Each function-body range must be an object");
            }
            JsonObject spec = element.getAsJsonObject();
            String startHex = requireJsonString(spec, "start");
            String endHex = requireJsonString(spec, "end");
            Address start = QuerySupport.toAddress(program, startHex);
            Address end = QuerySupport.toAddress(program, endHex);
            if (!start.getAddressSpace().equals(end.getAddressSpace())) {
                throw new IllegalArgumentException(
                    "Function-body range endpoints must share an address space");
            }
            if (end.compareTo(start) < 0) {
                throw new IllegalArgumentException(
                    "Function-body range end precedes start: "
                    + startHex + "-" + endHex);
            }
            AddressSet range = new AddressSet(start, end);
            if (!program.getMemory().contains(range)) {
                throw new IllegalArgumentException(
                    "Function-body range is not entirely in memory: "
                    + startHex + "-" + endHex);
            }
            if (body.intersects(range)) {
                throw new IllegalArgumentException(
                    "Function-body ranges overlap: "
                    + startHex + "-" + endHex);
            }
            body.addRange(start, end);
        }
        if (!body.contains(entry)) {
            throw new IllegalArgumentException(
                "Function body must contain entry point " + entry);
        }
        return body;
    }

    private static JsonArray optionalJsonArray(
            JsonObject args, String name) {
        if (!args.has(name)) {
            return null;
        }
        return requireJsonArray(args, name);
    }

    private static JsonArray conflictingFunctions(
            Program program, AddressSetView body, Address ignoredEntry) {
        JsonArray conflicts = new JsonArray();
        Iterator<Function> iterator = program.getFunctionManager()
            .getFunctionsOverlapping(body);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (ignoredEntry != null
                    && ignoredEntry.equals(function.getEntryPoint())) {
                continue;
            }
            conflicts.add(functionConflictState(function));
        }
        return conflicts;
    }

    private static JsonObject functionConflictState(Function function) {
        JsonObject state = new JsonObject();
        state.addProperty("name", function.getName());
        state.addProperty("entry", function.getEntryPoint().toString());
        state.addProperty("body_bytes",
            function.getBody().getNumAddresses());
        state.add("body_ranges",
            FunctionQueries.addressRanges(function.getBody()));
        return state;
    }

    private static JsonObject withFunctionConflicts(
            JsonObject result, JsonArray conflicts) {
        result.add("conflicting_functions", conflicts.deepCopy());
        return result;
    }

    private static JsonObject renameFunctionState(Function function) {
        if (function == null) {
            return null;
        }
        JsonObject state = new JsonObject();
        state.addProperty("address", function.getEntryPoint().toString());
        state.addProperty("name", function.getName());
        return state;
    }

    private static JsonObject renameResult(String status,
            JsonObject requested, JsonObject oldState,
            JsonObject storedState, String error) {
        JsonObject result = new JsonObject();
        result.addProperty("operation", "set_function_name");
        result.addProperty("status", status);
        result.add("requested", requested.deepCopy());
        result.add("old", oldState == null
            ? JsonNull.INSTANCE : oldState.deepCopy());
        result.add("stored", storedState == null
            ? JsonNull.INSTANCE : storedState.deepCopy());
        if (error == null) {
            result.add("error", JsonNull.INSTANCE);
        } else {
            result.addProperty("error", error);
        }
        return result;
    }

    private static JsonObject compactRenameItem(JsonElement rename) {
        JsonObject full = rename.getAsJsonObject();
        JsonObject requested = full.getAsJsonObject("requested");
        JsonObject compact = new JsonObject();
        compact.addProperty("address", requested.get("address").getAsString());
        compact.addProperty("status", full.get("status").getAsString());
        compact.addProperty("requested_name",
            requested.get("name").getAsString());
        addNullableRenameName(compact, "old_name", full.get("old"));
        addNullableRenameName(compact, "stored_name", full.get("stored"));
        compact.add("error", full.get("error").deepCopy());
        return compact;
    }

    private static void addNullableRenameName(JsonObject target,
            String key, JsonElement state) {
        if (state == null || state.isJsonNull()) {
            target.add(key, JsonNull.INSTANCE);
        } else {
            target.addProperty(key,
                state.getAsJsonObject().get("name").getAsString());
        }
    }

    private static JsonObject compactRenameFailure(String address,
            String requestedName, String error) {
        JsonObject compact = new JsonObject();
        compact.addProperty("address", address);
        compact.addProperty("status", "validation_failed");
        compact.addProperty("requested_name", requestedName);
        compact.add("old_name", JsonNull.INSTANCE);
        compact.add("stored_name", JsonNull.INSTANCE);
        compact.addProperty("error", error);
        return compact;
    }

    private static JsonObject batchRenameResult(JsonArray items,
            int succeeded, int unchanged, int failed) {
        String status;
        if (failed == 0) {
            status = succeeded == 0 ? "no_change" : "success";
        } else if (succeeded > 0 || unchanged > 0) {
            status = "partial_success";
        } else {
            status = "validation_failed";
        }
        JsonObject result = new JsonObject();
        result.addProperty("operation", "set_function_names");
        result.addProperty("status", status);
        result.addProperty("atomicity", "per_item");
        result.addProperty("succeeded", succeeded);
        result.addProperty("unchanged", unchanged);
        result.addProperty("failed", failed);
        result.addProperty("total", items.size());
        result.add("items", items);
        return result;
    }

}
