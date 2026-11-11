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

import static ghidramsc.QuerySupport.optInt;
import static ghidramsc.QuerySupport.optString;
import static ghidramsc.QuerySupport.requireString;
import static ghidramsc.QuerySupport.resolveFunction;
import static ghidramsc.QuerySupport.toAddress;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Decompiled variable identity, capabilities, and pagination. */
final class VariableQueries {
    private VariableQueries() { }

    private static final int FUNC_VAR_IDENTITY_DEFAULT_LIMIT = 100;
    private static final int FUNC_VAR_IDENTITY_MAX_LIMIT = 500;
    private static final String[] FUNC_VAR_IDENTITY_FILTER_FIELDS = {
        "name", "var_id", "type", "storage", "storage_kind", "backing",
        "capability_reason", "pc_addr", "database_symbol_id"
    };

    // -----------------------------------------------------------------
    // list_function_variables
    // -----------------------------------------------------------------

    static JsonElement listFunctionVariables(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        return functionVariables(program, addrHex, false, 0,
            FUNC_VAR_IDENTITY_DEFAULT_LIMIT, "");
    }

    static JsonElement listFunctionVariableIdentities(
            Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        int offset = optInt(args, "offset", 0);
        int limit = optInt(args, "limit",
            FUNC_VAR_IDENTITY_DEFAULT_LIMIT);
        String filter = optString(args, "filter_str", "");
        validateIdentityPageArguments(offset, limit);
        return functionVariables(
            program, addrHex, true, offset, limit, filter);
    }

    private static JsonElement functionVariables(
            Program program, String addrHex, boolean includeIdentity,
            int offset, int limit, String filter) {
        Address addr = toAddress(program, addrHex);
        Function func = resolveFunction(program, addr);
        if (func == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "No function at or containing " + addrHex);
            return err;
        }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.setOptions(new DecompileOptions());
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(
                func, 120, TaskMonitor.DUMMY);
            if (result == null || !result.decompileCompleted()) {
                JsonObject err = new JsonObject();
                err.addProperty("error",
                    "Decompile failed for " + func.getName());
                return err;
            }

            HighFunction hfunc = result.getHighFunction();
            LocalSymbolMap lsm = hfunc.getLocalSymbolMap();

            JsonArray paramArr = new JsonArray();
            JsonArray localArr = new JsonArray();
            List<JsonObject> identityEntries = new ArrayList<>();

            Iterator<HighSymbol> symIter = lsm.getSymbols();
            while (symIter.hasNext()) {
                HighSymbol sym = symIter.next();
                JsonObject entry = new JsonObject();
                entry.addProperty("name", sym.getName());
                entry.addProperty("type", sym.getDataType().toString());
                entry.addProperty("size", sym.getSize());
                entry.addProperty("storage",
                    sym.getStorage().toString());
                entry.addProperty("is_param", sym.isParameter());
                if (includeIdentity) {
                    addVariableIdentity(entry, sym);
                    identityEntries.add(entry);
                }
                if (sym.getPCAddress() != null) {
                    entry.addProperty("pc_addr",
                        sym.getPCAddress().toString());
                }
                if (sym.isParameter()) {
                    paramArr.add(entry);
                } else {
                    localArr.add(entry);
                }
            }

            JsonObject out = new JsonObject();
            out.addProperty("func", func.getName());
            out.addProperty("entry", func.getEntryPoint().toString());
            out.addProperty("return_type",
                func.getReturnType().toString());
            out.addProperty("signature",
                func.getSignature().toString());
            if (includeIdentity) {
                identityEntries.clear();
                for (JsonElement element : paramArr) {
                    identityEntries.add(element.getAsJsonObject());
                }
                for (JsonElement element : localArr) {
                    identityEntries.add(element.getAsJsonObject());
                }
                JsonArray ambiguousNames = addNameAmbiguityMetadata(
                    identityEntries);
                JsonObject page = pageVariableIdentities(
                    identityEntries, ambiguousNames, offset, limit, filter);
                out.addProperty("identity_model",
                    "decompiler_high_symbol_v2");
                out.addProperty("selection_scope",
                    "complete_high_symbol");
                out.addProperty("merge_group_split_supported", true);
                out.addProperty("filter",
                    page.get("filter").getAsString());
                out.add("pagination", page.get("pagination"));
                out.add("ambiguous_names", page.get("ambiguous_names"));
                paramArr = page.getAsJsonArray("params");
                localArr = page.getAsJsonArray("locals");
            }
            out.add("params", paramArr);
            out.add("locals", localArr);
            return out;
        } finally {
            decomp.dispose();
        }
    }

    static String highVariableId(HighSymbol symbol) {
        return "high:" + Long.toUnsignedString(symbol.getId(), 16);
    }

    static JsonObject highVariableState(HighSymbol symbol) {
        JsonObject entry = new JsonObject();
        entry.addProperty("var_id", highVariableId(symbol));
        entry.addProperty("name", symbol.getName());
        entry.addProperty("type", symbol.getDataType().toString());
        entry.addProperty("size", symbol.getSize());
        entry.addProperty("storage", symbol.getStorage().toString());
        entry.addProperty("is_param", symbol.isParameter());
        if (symbol.getPCAddress() != null) {
            entry.addProperty("pc_addr", symbol.getPCAddress().toString());
        }
        addVariableIdentity(entry, symbol);
        return entry;
    }

    private static void addVariableIdentity(
            JsonObject entry, HighSymbol symbol) {
        entry.addProperty("var_id", highVariableId(symbol));
        entry.addProperty("high_symbol_id",
            Long.toUnsignedString(symbol.getId(), 16));
        entry.addProperty("category_index", symbol.getCategoryIndex());
        entry.addProperty("name_locked", symbol.isNameLocked());
        entry.addProperty("type_locked", symbol.isTypeLocked());
        Variable databaseVariable =
            HighFunctionDBUtil.getFunctionVariable(symbol);
        Symbol databaseSymbol = symbol.getSymbol();
        boolean databaseBacked =
            databaseVariable != null || databaseSymbol != null;
        entry.addProperty("database_backed", databaseBacked);
        entry.addProperty("identity_stability", databaseBacked
            ? "database_symbol" : "decompile_snapshot");
        entry.addProperty("refresh_required_after_mutation",
            !databaseBacked);
        if (databaseSymbol != null) {
            entry.addProperty("database_symbol_id",
                Long.toUnsignedString(databaseSymbol.getID()));
        }
        entry.addProperty("backing",
            symbol.isParameter() ? "parameter"
                : databaseBacked ? "database_local" : "decompiler_high");
        entry.addProperty("storage_kind", variableStorageKind(symbol));
        entry.addProperty("selection_scope", "high_symbol");
        String capabilityReason = highVariableCapabilityReason(symbol);
        entry.addProperty("persistable", capabilityReason == null);
        addMergeGroupIdentity(entry, symbol);
        if (capabilityReason != null) {
            entry.addProperty("capability_reason", capabilityReason);
        }
    }

    static String highVariableCapabilityReason(HighSymbol symbol) {
        if (symbol.isGlobal()) {
            return "Global high symbols are outside function-variable editing";
        }
        HighVariable highVariable = symbol.getHighVariable();
        if (highVariable == null) {
            return "Decompiler symbol has no associated high variable and "
                + "cannot be persisted";
        }
        if (HighFunctionDBUtil.getFunctionVariable(symbol) != null
                || symbol.getSymbol() != null) {
            return null;
        }
        if (symbol.getStorage().toString().startsWith("unique:")) {
            return "Decompiler unique-space storage cannot be materialized "
                + "as a database function variable";
        }
        Varnode representative = highVariable.getRepresentative();
        if (representative != null && representative.isConstant()) {
            return "Decompiler high variable is constant-backed and cannot "
                + "be persisted as a function variable";
        }
        HighFunction highFunction = symbol.getHighFunction();
        if (highFunction == null) {
            return "Decompiler high variable has no function identity";
        }
        String varId = highVariableId(symbol);
        int idMatches = 0;
        int locatorMatches = 0;
        Iterator<HighSymbol> symbols =
            highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol candidate = symbols.next();
            if (varId.equals(highVariableId(candidate))) {
                idMatches++;
            }
            if (highVariablePreflightLocatorMatches(symbol, candidate)) {
                locatorMatches++;
            }
        }
        if (idMatches != 1) {
            return "Decompiler high-symbol ID is not unique in this function";
        }
        if (locatorMatches != 1) {
            return "Decompiler high-variable locator is ambiguous in this function";
        }
        return null;
    }

    private static boolean highVariablePreflightLocatorMatches(
            HighSymbol selected, HighSymbol candidate) {
        if (selected.isParameter() != candidate.isParameter()) {
            return false;
        }
        if (selected.isParameter()) {
            return selected.getCategoryIndex() == candidate.getCategoryIndex();
        }
        if (!java.util.Objects.equals(
                selected.getPCAddress(), candidate.getPCAddress())) {
            return false;
        }
        return selected.getStorage().equals(candidate.getStorage())
            || selected.getName().equals(candidate.getName());
    }

    private static void addMergeGroupIdentity(
            JsonObject entry, HighSymbol symbol) {
        HighVariable highVariable = symbol.getHighVariable();
        JsonArray groups = new JsonArray();
        if (highVariable == null) {
            entry.addProperty("merge_group_count", 0);
            entry.addProperty("merged", false);
            entry.addProperty("merge_group_split_supported", false);
            entry.add("merge_groups", groups);
            return;
        }

        Map<Integer, JsonObject> byGroup = new java.util.TreeMap<>();
        for (Varnode instance : highVariable.getInstances()) {
            int group = Short.toUnsignedInt(instance.getMergeGroup());
            JsonObject groupState = byGroup.get(group);
            if (groupState == null) {
                groupState = new JsonObject();
                groupState.addProperty("merge_group_id",
                    mergeGroupId(instance));
                groupState.addProperty("merge_group", group);
                groupState.addProperty("instance_count", 0);
                groupState.addProperty("representative_storage",
                    instance.getAddress().toString());
                groupState.addProperty("representative_size",
                    instance.getSize());
                if (instance.getPCAddress() != null) {
                    groupState.addProperty("representative_pc_addr",
                        instance.getPCAddress().toString());
                }
                byGroup.put(group, groupState);
            }
            groupState.addProperty("instance_count",
                groupState.get("instance_count").getAsInt() + 1);
        }
        for (JsonObject group : byGroup.values()) {
            groups.add(group);
        }
        entry.addProperty("merge_group_count", byGroup.size());
        entry.addProperty("merged", byGroup.size() > 1);
        entry.addProperty("merge_group_split_supported",
            byGroup.size() > 1 && !symbol.isNameLocked());
        entry.add("merge_groups", groups);
    }

    static String mergeGroupId(Varnode varnode) {
        return "merge:" + Integer.toHexString(
            Short.toUnsignedInt(varnode.getMergeGroup()));
    }

    private static JsonArray addNameAmbiguityMetadata(
            List<JsonObject> entries) {
        Map<String, List<JsonObject>> byName = new HashMap<>();
        for (JsonObject entry : entries) {
            byName.computeIfAbsent(entry.get("name").getAsString(),
                ignored -> new ArrayList<>()).add(entry);
        }
        JsonArray ambiguousNames = new JsonArray();
        List<String> names = new ArrayList<>(byName.keySet());
        Collections.sort(names);
        for (String name : names) {
            List<JsonObject> matches = byName.get(name);
            JsonArray candidateIds = new JsonArray();
            for (JsonObject match : matches) {
                candidateIds.add(match.get("var_id").getAsString());
            }
            boolean ambiguous = matches.size() > 1;
            for (JsonObject match : matches) {
                match.addProperty("display_name_ambiguous", ambiguous);
                match.add("same_name_var_ids", candidateIds.deepCopy());
            }
            if (ambiguous) {
                JsonObject ambiguity = new JsonObject();
                ambiguity.addProperty("name", name);
                ambiguity.add("candidate_var_ids", candidateIds);
                ambiguousNames.add(ambiguity);
            }
        }
        return ambiguousNames;
    }

    static void validateIdentityPageArguments(int offset, int limit) {
        if (offset < 0) {
            throw new IllegalArgumentException(
                "offset must be a non-negative integer");
        }
        if (limit < 1 || limit > FUNC_VAR_IDENTITY_MAX_LIMIT) {
            throw new IllegalArgumentException(
                "limit must be an integer between 1 and "
                    + FUNC_VAR_IDENTITY_MAX_LIMIT);
        }
    }

    static JsonObject pageVariableIdentities(
            List<JsonObject> entries, JsonArray ambiguousNames,
            int offset, int limit, String filter) {
        validateIdentityPageArguments(offset, limit);
        String normalizedFilter = filter.trim();
        String needle = normalizedFilter.toLowerCase(Locale.ROOT);
        List<JsonObject> filtered = new ArrayList<>();
        for (JsonObject entry : entries) {
            if (needle.isEmpty() || identityMatchesFilter(entry, needle)) {
                filtered.add(entry);
            }
        }

        int from = Math.min(offset, filtered.size());
        int to = (int) Math.min((long) filtered.size(),
            (long) from + limit);
        JsonArray params = new JsonArray();
        JsonArray locals = new JsonArray();
        Set<String> pageNames = new HashSet<>();
        for (int i = from; i < to; i++) {
            JsonObject entry = filtered.get(i);
            pageNames.add(entry.get("name").getAsString());
            if (entry.get("is_param").getAsBoolean()) {
                params.add(entry);
            } else {
                locals.add(entry);
            }
        }

        JsonArray pageAmbiguities = new JsonArray();
        for (JsonElement element : ambiguousNames) {
            JsonObject ambiguity = element.getAsJsonObject();
            if (pageNames.contains(ambiguity.get("name").getAsString())) {
                pageAmbiguities.add(ambiguity);
            }
        }

        int returned = to - from;
        boolean hasMore = to < filtered.size();
        JsonObject pagination = new JsonObject();
        pagination.addProperty("offset", offset);
        pagination.addProperty("limit", limit);
        pagination.addProperty("returned", returned);
        pagination.addProperty("total", filtered.size());
        pagination.addProperty("total_unfiltered", entries.size());
        pagination.addProperty("has_more", hasMore);
        if (hasMore) {
            pagination.addProperty("next_offset", to);
        } else {
            pagination.add("next_offset", null);
        }

        JsonObject page = new JsonObject();
        page.addProperty("filter", normalizedFilter);
        page.add("pagination", pagination);
        page.add("ambiguous_names", pageAmbiguities);
        page.add("params", params);
        page.add("locals", locals);
        return page;
    }

    private static boolean identityMatchesFilter(
            JsonObject entry, String needle) {
        for (String field : FUNC_VAR_IDENTITY_FILTER_FIELDS) {
            if (entry.has(field) && !entry.get(field).isJsonNull()
                    && entry.get(field).getAsString()
                        .toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static String variableStorageKind(HighSymbol symbol) {
        var storage = symbol.getStorage();
        if (storage.isStackStorage()) return "stack";
        if (storage.isRegisterStorage()) return "register";
        if (storage.isHashStorage()) return "hash";
        if (storage.isMemoryStorage()) return "memory";
        return "other";
    }

}
