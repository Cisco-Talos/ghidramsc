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

import static ghidramsc.MutationResult.capabilityFailure;
import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.noChangeResult;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;
import static ghidramsc.MutationTransaction.withTransaction;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/** Database and decompiler variable mutation with stable identity selection. */
final class VariableMutations {
    private VariableMutations() { }

    // -----------------------------------------------------------------
    // set_variable_name
    // -----------------------------------------------------------------

    static JsonElement setVariableName(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String oldName = QuerySupport.requireString(
            args, "old_name");
        String newName = QuerySupport.requireString(
            args, "new_name");
        JsonObject requested = new JsonObject();
        requested.addProperty("old_name", oldName);
        requested.addProperty("new_name", newName);
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        if (func == null) {
            return validationFailure("set_variable_name", requested,
                "No function at " + addrHex);
        }

        Variable variable;
        try {
            variable = resolveUniqueVariable(func, oldName);
            if (variable == null) {
                throw new IllegalArgumentException(
                    "Variable '" + oldName + "' not found in "
                    + func.getName());
            }
            Variable conflict = resolveUniqueVariable(func, newName);
            if (conflict != null
                    && !conflict.getVariableStorage().equals(
                        variable.getVariableStorage())) {
                throw new IllegalArgumentException(
                    "Requested name '" + newName
                    + "' conflicts with an existing variable at "
                    + conflict.getVariableStorage());
            }
        } catch (Exception e) {
            return validationFailure("set_variable_name", requested,
                errorMessage(e));
        }
        JsonObject oldState = FunctionMutationReadback.queryFunctionState(program, addrHex);
        if (oldName.equals(newName)) {
            return noChangeResult("set_variable_name", oldState,
                requested, oldState.deepCopy());
        }
        String storage = variable.getVariableStorage().toString();
        boolean parameter = variable instanceof Parameter;

        return withTransaction(program, "Rename variable", tx -> {
            try {
                variable.setName(newName, SourceType.USER_DEFINED);
                Variable storedVariable = findVariableByStorage(
                    func, storage, parameter);
                if (storedVariable == null
                        || !newName.equals(storedVariable.getName())) {
                    throw new IllegalStateException(
                        "Variable name read-back mismatch at " + storage);
                }
                JsonObject stored = FunctionMutationReadback.queryFunctionState(program, addrHex);
                tx.commit();
                return successResult("set_variable_name", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_variable_name", oldState,
                    requested, errorMessage(e));
            }
        }, () -> FunctionMutationReadback.queryFunctionState(program, addrHex));
    }

    // -----------------------------------------------------------------
    // set_variable_type
    // -----------------------------------------------------------------

    static JsonElement setVariableType(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String varName = QuerySupport.requireString(
            args, "var_name");
        String newType = QuerySupport.requireString(
            args, "type_name");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", varName);
        requested.addProperty("type", newType);
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        if (func == null) {
            return validationFailure("set_variable_type", requested,
                "No function at " + addrHex);
        }

        DataType dt = DataTypeResolver.resolveDataType(program, newType);
        if (dt == null) {
            return validationFailure("set_variable_type", requested,
                "Unknown data type: " + newType);
        }
        requested.addProperty("type", dt.toString());
        Variable variable;
        try {
            variable = resolveUniqueVariable(func, varName);
            if (variable == null) {
                throw new IllegalArgumentException(
                    "Variable '" + varName + "' not found in "
                    + func.getName());
            }
        } catch (Exception e) {
            return validationFailure("set_variable_type", requested,
                errorMessage(e));
        }
        JsonObject oldState = FunctionMutationReadback.queryFunctionState(program, addrHex);
        if (variable.getDataType().isEquivalent(dt)) {
            return noChangeResult("set_variable_type", oldState,
                requested, oldState.deepCopy());
        }
        String storage = variable.getVariableStorage().toString();
        boolean parameter = variable instanceof Parameter;

        return withTransaction(program, "Retype variable", tx -> {
            try {
                variable.setDataType(dt, SourceType.USER_DEFINED);
                Variable storedVariable = findVariableByStorage(
                    func, storage, parameter);
                if (storedVariable == null
                        || !storedVariable.getDataType().isEquivalent(dt)) {
                    throw new IllegalStateException(
                        "Variable type read-back mismatch at " + storage);
                }
                JsonObject stored = FunctionMutationReadback.queryFunctionState(program, addrHex);
                tx.commit();
                return successResult("set_variable_type", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_variable_type", oldState,
                    requested, errorMessage(e));
            }
        }, () -> FunctionMutationReadback.queryFunctionState(program, addrHex));
    }

    // -----------------------------------------------------------------
    // identity-backed decompiler variable editing
    // -----------------------------------------------------------------

    static JsonElement setVariableNameById(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String varId = QuerySupport.requireString(args, "var_id");
        String newName = QuerySupport.requireString(args, "new_name");
        boolean splitUse = QuerySupport.optBool(args, "split_use", false);
        String mergeGroupId = QuerySupport.optString(
            args, "merge_group_id", "");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("var_id", varId);
        requested.addProperty("new_name", newName);
        requested.addProperty("split_use", splitUse);
        requested.addProperty("merge_group_id", mergeGroupId);

        try (HighVariableSelection selection =
                selectHighVariable(program, addrHex, varId)) {
            HighSymbol symbol = selection.symbol;
            JsonObject oldState = VariableQueries.highVariableState(symbol);
            String unsupported = highVariableCapabilityFailure(symbol);
            if (unsupported != null) {
                return capabilityFailure(
                    "set_variable_name_by_id", requested, unsupported
                    + ". This limits high-symbol ID editing; if a uniquely "
                    + "named database-backed variable exists, use "
                    + "set_variable_name with its exact current name, then "
                    + "refresh identities.");
            }
            String splitFailure = validateMergeGroupSelection(
                symbol, splitUse, mergeGroupId);
            if (splitFailure != null) {
                return validationFailure(
                    "set_variable_name_by_id", requested, splitFailure);
            }
            if (splitUse) {
                return capabilityFailure("set_variable_name_by_id", requested,
                    "Rename-only merge-group splitting cannot be verified or "
                    + "safely rolled back; materialize the selected group "
                    + "with create_variable_by_id, refresh identities, then "
                    + "rename its separate database variable");
            }
            if (newName.equals(symbol.getName())) {
                return noChangeResult("set_variable_name_by_id", oldState,
                    requested, oldState.deepCopy());
            }
            String conflict = highVariableNameConflict(
                selection.highFunction, symbol, newName);
            if (conflict != null) {
                return validationFailure(
                    "set_variable_name_by_id", requested, conflict);
            }
            HighVariableLocator rollbackLocator =
                new HighVariableLocator(symbol);
            return withTransaction(program, "Rename decompiler variable", tx -> {
                try {
                    HighSymbol target = splitUse
                        ? splitHighVariable(selection, symbol, mergeGroupId)
                        : symbol;
                    HighVariableLocator locator =
                        new HighVariableLocator(target, newName);
                    HighFunctionDBUtil.updateDBVariable(
                        target, newName, null, SourceType.USER_DEFINED);
                    JsonObject stored = queryHighVariableState(
                        program, addrHex, locator);
                    if (!stored.get("database_backed").getAsBoolean()
                            || !newName.equals(
                                stored.get("name").getAsString())) {
                        throw new IllegalStateException(
                            "Decompiler variable database name read-back mismatch");
                    }
                    tx.commit();
                    JsonObject success = successResult(
                        "set_variable_name_by_id", oldState, requested,
                        stored);
                    discloseNameOnlyMaterialization(success, oldState, stored);
                    return success;
                } catch (Exception e) {
                    return rolledBackResult("set_variable_name_by_id", oldState,
                        requested, errorMessage(e));
                }
            }, () -> queryHighVariableState(
                program, addrHex, rollbackLocator));
        } catch (Exception e) {
            return validationFailure(
                "set_variable_name_by_id", requested, errorMessage(e));
        }
    }

    static JsonElement setVariableTypeById(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String varId = QuerySupport.requireString(args, "var_id");
        String typeName = QuerySupport.requireString(args, "type_name");
        boolean splitUse = QuerySupport.optBool(args, "split_use", false);
        String mergeGroupId = QuerySupport.optString(
            args, "merge_group_id", "");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("var_id", varId);
        requested.addProperty("type_name", typeName);
        requested.addProperty("split_use", splitUse);
        requested.addProperty("merge_group_id", mergeGroupId);
        DataType dataType = DataTypeResolver.resolveDataType(program, typeName);
        if (dataType == null) {
            return validationFailure("set_variable_type_by_id", requested,
                "Unknown type: " + typeName);
        }
        requested.addProperty("resolved_type", dataType.toString());

        try (HighVariableSelection selection =
                selectHighVariable(program, addrHex, varId)) {
            HighSymbol symbol = selection.symbol;
            JsonObject oldState = VariableQueries.highVariableState(symbol);
            String unsupported = highVariableCapabilityFailure(symbol);
            if (unsupported != null) {
                return capabilityFailure(
                    "set_variable_type_by_id", requested, unsupported
                    + ". This limits high-symbol ID editing; if a uniquely "
                    + "named database-backed variable exists, use "
                    + "set_variable_type with its exact current name, then "
                    + "refresh identities.");
            }
            String splitFailure = validateMergeGroupSelection(
                symbol, splitUse, mergeGroupId);
            if (splitFailure != null) {
                return validationFailure(
                    "set_variable_type_by_id", requested, splitFailure);
            }
            if (splitUse) {
                return capabilityFailure("set_variable_type_by_id", requested,
                    "Retype-only merge-group splitting cannot be verified or "
                    + "safely rolled back; materialize the selected group "
                    + "with create_variable_by_id, refresh identities, then "
                    + "retype its separate database variable");
            }
            if (!splitUse && symbol.getDataType().isEquivalent(dataType)) {
                return noChangeResult("set_variable_type_by_id", oldState,
                    requested, oldState.deepCopy());
            }
            HighVariableLocator rollbackLocator =
                new HighVariableLocator(symbol);
            return withTransaction(program, "Retype decompiler variable", tx -> {
                try {
                    HighSymbol target = splitUse
                        ? splitHighVariable(selection, symbol, mergeGroupId)
                        : symbol;
                    HighVariableLocator locator =
                        new HighVariableLocator(target);
                    HighFunctionDBUtil.updateDBVariable(
                        target, null, dataType, SourceType.USER_DEFINED);
                    JsonObject stored = queryHighVariableState(
                        program, addrHex, locator);
                    if (!stored.get("database_backed").getAsBoolean()) {
                        throw new IllegalStateException(
                            "Retyped variable is not database-backed");
                    }
                    DataType storedType = DataTypeResolver.resolveDataType(
                        program, stored.get("type").getAsString());
                    if (storedType == null
                            || !storedType.isEquivalent(dataType)) {
                        throw new IllegalStateException(
                            "Decompiler variable type read-back mismatch");
                    }
                    tx.commit();
                    return successResult("set_variable_type_by_id", oldState,
                        requested, stored);
                } catch (Exception e) {
                    return rolledBackResult("set_variable_type_by_id", oldState,
                        requested, errorMessage(e));
                }
            }, () -> queryHighVariableState(
                program, addrHex, rollbackLocator));
        } catch (Exception e) {
            return validationFailure(
                "set_variable_type_by_id", requested, errorMessage(e));
        }
    }

    static JsonElement createVariableById(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String varId = QuerySupport.requireString(args, "var_id");
        String name = QuerySupport.optString(args, "name", "");
        String typeName = QuerySupport.optString(args, "type_name", "");
        boolean splitUse = QuerySupport.optBool(args, "split_use", false);
        String mergeGroupId = QuerySupport.optString(
            args, "merge_group_id", "");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("var_id", varId);
        requested.addProperty("name", name);
        requested.addProperty("type_name", typeName);
        requested.addProperty("split_use", splitUse);
        requested.addProperty("merge_group_id", mergeGroupId);

        DataType requestedType = typeName.isEmpty()
            ? null : DataTypeResolver.resolveDataType(program, typeName);
        if (!typeName.isEmpty() && requestedType == null) {
            return validationFailure("create_variable_by_id", requested,
                "Unknown type: " + typeName);
        }
        if (requestedType != null) {
            requested.addProperty("resolved_type", requestedType.toString());
        }

        try (HighVariableSelection selection =
                selectHighVariable(program, addrHex, varId)) {
            HighSymbol symbol = selection.symbol;
            JsonObject oldState = VariableQueries.highVariableState(symbol);
            String unsupported = highVariableCapabilityFailure(symbol);
            if (unsupported != null) {
                return capabilityFailure(
                    "create_variable_by_id", requested, unsupported);
            }
            String splitFailure = validateMergeGroupSelection(
                symbol, splitUse, mergeGroupId);
            if (splitFailure != null) {
                return validationFailure(
                    "create_variable_by_id", requested, splitFailure);
            }
            boolean databaseBacked =
                HighFunctionDBUtil.getFunctionVariable(symbol) != null;
            String storedName = name.isEmpty() ? symbol.getName() : name;
            DataType storedType = requestedType == null
                ? symbol.getDataType() : requestedType;
            requested.addProperty("stored_name", storedName);
            requested.addProperty("stored_type", storedType.toString());
            if (databaseBacked && !splitUse) {
                if (storedName.equals(symbol.getName())
                        && symbol.getDataType().isEquivalent(storedType)) {
                    return noChangeResult("create_variable_by_id", oldState,
                        requested, oldState.deepCopy());
                }
                return validationFailure("create_variable_by_id", requested,
                    "Variable already has database backing; use the identity-"
                    + "backed rename or retype operation");
            }
            if (splitUse && storedName.equals(symbol.getName())) {
                return validationFailure("create_variable_by_id", requested,
                    "A split merge group requires a name distinct from the "
                    + "remaining complete symbol");
            }
            String conflict = highVariableNameConflict(
                selection.highFunction, symbol, storedName);
            if (conflict != null) {
                return validationFailure(
                    "create_variable_by_id", requested, conflict);
            }
            SplitUseAnchors splitAnchors = splitUse
                ? captureSplitUseAnchors(symbol, mergeGroupId) : null;
            HighVariableLocator rollbackLocator =
                new HighVariableLocator(symbol);
            JsonObject outcome = withTransaction(program,
                    "Create database variable from decompiler identity", tx -> {
                try {
                    HighSymbol target = splitUse
                        ? splitHighVariable(selection, symbol, mergeGroupId)
                        : symbol;
                    HighVariableLocator locator =
                        new HighVariableLocator(target, storedName);
                    HighFunctionDBUtil.updateDBVariable(target, storedName,
                        storedType, SourceType.USER_DEFINED);
                    JsonObject stored = queryHighVariableState(
                        program, addrHex, locator);
                    if (!stored.get("database_backed").getAsBoolean()
                            || !storedName.equals(
                                stored.get("name").getAsString())) {
                        throw new IllegalStateException(
                            "Created variable database read-back mismatch");
                    }
                    DataType readBackType = DataTypeResolver.resolveDataType(
                        program, stored.get("type").getAsString());
                    if (readBackType == null
                            || !readBackType.isEquivalent(storedType)) {
                        throw new IllegalStateException(
                            "Created variable type read-back mismatch");
                    }
                    if (splitUse) {
                        verifySplitUseIsolation(program, addrHex,
                            splitAnchors, storedName);
                    }
                    tx.commit();
                    JsonObject success = successResult(
                        "create_variable_by_id", oldState, requested,
                        stored);
                    if (typeName.isEmpty()) {
                        discloseNameOnlyMaterialization(
                            success, oldState, stored);
                    }
                    return success;
                } catch (Exception e) {
                    return rolledBackResult("create_variable_by_id", oldState,
                        requested, errorMessage(e));
                }
            }, () -> queryHighVariableState(
                program, addrHex, rollbackLocator)).getAsJsonObject();
            if (splitUse && "rolled_back".equals(
                    outcome.get("status").getAsString())
                    && (!outcome.has("stored")
                        || !oldState.equals(outcome.get("stored")))) {
                outcome.addProperty("status", "failed");
                outcome.addProperty("error", outcome.get("error").getAsString()
                    + "; Rollback could not be verified; inspect current "
                    + "variable identities before further mutation");
            }
            return outcome;
        } catch (Exception e) {
            return validationFailure(
                "create_variable_by_id", requested, errorMessage(e));
        }
    }

    static JsonElement deleteVariableById(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String varId = QuerySupport.requireString(args, "var_id");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("var_id", varId);

        try (HighVariableSelection selection =
                selectHighVariable(program, addrHex, varId)) {
            HighSymbol symbol = selection.symbol;
            JsonObject oldState = VariableQueries.highVariableState(symbol);
            Variable variable = HighFunctionDBUtil.getFunctionVariable(symbol);
            if (variable == null || variable.getSymbol() == null) {
                return noChangeResult("delete_variable_by_id", oldState,
                    requested, oldState.deepCopy());
            }
            if (variable instanceof Parameter
                    && ((Parameter) variable).isAutoParameter()) {
                return capabilityFailure("delete_variable_by_id", requested,
                    "Auto parameters are controlled by the function signature "
                    + "and cannot be deleted independently");
            }
            Function function = selection.highFunction.getFunction();
            long databaseSymbolId = variable.getSymbol().getID();
            requested.addProperty("database_symbol_id",
                Long.toUnsignedString(databaseSymbolId));
            return withTransaction(program, "Delete database variable", tx -> {
                try {
                    if (variable instanceof Parameter) {
                        function.removeParameter(
                            ((Parameter) variable).getOrdinal());
                    } else {
                        function.removeVariable(variable);
                    }
                    if (findDatabaseVariableBySymbolId(
                            function, databaseSymbolId) != null) {
                        throw new IllegalStateException(
                            "Deleted variable remains in the function database");
                    }
                    JsonObject stored = new JsonObject();
                    stored.addProperty("deleted", true);
                    stored.addProperty("database_symbol_id",
                        Long.toUnsignedString(databaseSymbolId));
                    stored.add("function", FunctionMutationReadback.queryFunctionState(
                        program, addrHex));
                    tx.commit();
                    return successResult("delete_variable_by_id", oldState,
                        requested, stored);
                } catch (Exception e) {
                    return rolledBackResult("delete_variable_by_id", oldState,
                        requested, errorMessage(e));
                }
            }, () -> FunctionMutationReadback.queryFunctionState(program, addrHex));
        } catch (Exception e) {
            return validationFailure(
                "delete_variable_by_id", requested, errorMessage(e));
        }
    }

    private static final class HighVariableSelection
            implements AutoCloseable {
        private final DecompInterface decompiler;
        private final HighFunction highFunction;
        private final HighSymbol symbol;

        HighVariableSelection(DecompInterface decompiler,
                HighFunction highFunction, HighSymbol symbol) {
            this.decompiler = decompiler;
            this.highFunction = highFunction;
            this.symbol = symbol;
        }

        @Override
        public void close() {
            decompiler.dispose();
        }
    }

    private static final class HighVariableLocator {
        private final String varId;
        private final String name;
        private final String storage;
        private final String pcAddress;
        private final boolean parameter;
        private final int categoryIndex;
        private final String expectedName;

        HighVariableLocator(HighSymbol symbol) {
            this(symbol, null);
        }

        HighVariableLocator(HighSymbol symbol, String expectedName) {
            varId = VariableQueries.highVariableId(symbol);
            name = symbol.getName();
            storage = symbol.getStorage().toString();
            pcAddress = symbol.getPCAddress() == null
                ? null : symbol.getPCAddress().toString();
            parameter = symbol.isParameter();
            categoryIndex = symbol.getCategoryIndex();
            this.expectedName = expectedName;
        }
    }

    private static HighVariableSelection selectHighVariable(
            Program program, String addrHex, String varId) {
        HighVariableLocator requested = null;
        return selectHighVariable(program, addrHex, varId, requested);
    }

    private static HighVariableSelection selectHighVariable(
            Program program, String addrHex, HighVariableLocator locator) {
        return selectHighVariable(
            program, addrHex, locator.varId, locator);
    }

    private static HighVariableSelection selectHighVariable(
            Program program, String addrHex, String varId,
            HighVariableLocator locator) {
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        if (func == null) {
            throw new IllegalArgumentException(
                "No function at or containing " + addrHex);
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.openProgram(program);
            DecompileResults result = decompiler.decompileFunction(
                func, 120, TaskMonitor.DUMMY);
            if (result == null || !result.decompileCompleted()) {
                throw new IllegalArgumentException(
                    "Decompile failed for " + func.getName());
            }
            HighFunction highFunction = result.getHighFunction();
            HighSymbol exact = null;
            HighSymbol named = null;
            HighSymbol fallback = null;
            int namedCount = 0;
            int fallbackCount = 0;
            Iterator<HighSymbol> symbols =
                highFunction.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol candidate = symbols.next();
                if (locator == null
                        && VariableQueries.highVariableId(candidate).equals(varId)) {
                    return new HighVariableSelection(
                        decompiler, highFunction, candidate);
                }
                if (locator != null) {
                    boolean matches = highVariableLocatorMatches(
                        candidate, locator);
                    if (matches) {
                        fallback = candidate;
                        fallbackCount++;
                    }
                    if (matches && VariableQueries.highVariableId(candidate)
                            .equals(varId)) {
                        if (exact != null) {
                            throw new IllegalArgumentException(
                                "Variable high-symbol ID became ambiguous "
                                + "after mutation");
                        }
                        exact = candidate;
                    }
                    if (locator.expectedName != null
                            && candidate.isParameter() == locator.parameter
                            && locator.expectedName.equals(
                                candidate.getName())) {
                        named = candidate;
                        namedCount++;
                    }
                }
            }
            if (namedCount == 1) {
                return new HighVariableSelection(
                    decompiler, highFunction, named);
            }
            if (namedCount > 1) {
                throw new IllegalArgumentException(
                    "Variable name became ambiguous after mutation");
            }
            if (exact != null) {
                return new HighVariableSelection(
                    decompiler, highFunction, exact);
            }
            if (fallbackCount == 1) {
                return new HighVariableSelection(
                    decompiler, highFunction, fallback);
            }
            if (fallbackCount > 1) {
                throw new IllegalArgumentException(
                    "Variable identity became ambiguous after mutation; "
                    + "refresh list_function_variable_identities");
            }
            throw new IllegalArgumentException(
                "Variable identity '" + varId + "' was not found; "
                + "refresh list_function_variable_identities");
        } catch (RuntimeException e) {
            decompiler.dispose();
            throw e;
        }
    }

    private static boolean highVariableLocatorMatches(
            HighSymbol candidate, HighVariableLocator locator) {
        if (candidate.isParameter() != locator.parameter) {
            return false;
        }
        if (locator.parameter) {
            return candidate.getCategoryIndex() == locator.categoryIndex;
        }
        String pcAddress = candidate.getPCAddress() == null
            ? null : candidate.getPCAddress().toString();
        if (locator.storage.equals(candidate.getStorage().toString())
                && java.util.Objects.equals(locator.pcAddress, pcAddress)) {
            return true;
        }
        return locator.name.equals(candidate.getName())
            && java.util.Objects.equals(locator.pcAddress, pcAddress);
    }

    private static JsonObject queryHighVariableState(
            Program program, String addrHex, HighVariableLocator locator) {
        try (HighVariableSelection selected =
                selectHighVariable(program, addrHex, locator)) {
            return VariableQueries.highVariableState(selected.symbol);
        }
    }

    private static String highVariableCapabilityFailure(HighSymbol symbol) {
        return VariableQueries.highVariableCapabilityReason(symbol);
    }

    private static String highVariableNameConflict(
            HighFunction highFunction, HighSymbol selected,
            String requestedName) {
        Iterator<HighSymbol> symbols =
            highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol candidate = symbols.next();
            if (candidate != selected
                    && requestedName.equals(candidate.getName())) {
                return "Requested name '" + requestedName
                    + "' conflicts with "
                    + VariableQueries.highVariableId(candidate)
                    + " at storage " + candidate.getStorage();
            }
        }
        return null;
    }

    private static JsonObject materializationFields(JsonObject state) {
        JsonObject fields = new JsonObject();
        for (String key : new String[] {
                "name", "type", "database_backed", "name_locked",
                "type_locked"}) {
            fields.add(key, state.get(key).deepCopy());
        }
        return fields;
    }

    private static void discloseNameOnlyMaterialization(
            JsonObject result, JsonObject oldState, JsonObject stored) {
        if (oldState.get("database_backed").getAsBoolean()
                || !stored.get("database_backed").getAsBoolean()) {
            return;
        }
        boolean locked = oldState.get("is_param").getAsBoolean()
            && !oldState.get("type_locked").getAsBoolean()
            && stored.get("type_locked").getAsBoolean();
        JsonObject effect = new JsonObject();
        effect.addProperty("caller_requested_type", false);
        effect.add("before", materializationFields(oldState));
        effect.add("after", materializationFields(stored));
        effect.addProperty("inferred_parameter_type_locked", locked);
        if (locked) {
            effect.addProperty("guidance",
                "Native Ghidra materialization locked the inferred parameter "
                + "type although no type was requested; refresh variable "
                + "identities before further edits");
        }
        result.add("name_only_materialization", effect);
    }

    private static String validateMergeGroupSelection(
            HighSymbol symbol, boolean splitUse, String mergeGroupId) {
        if (!splitUse) {
            return mergeGroupId.isEmpty() ? null
                : "merge_group_id requires split_use=true";
        }
        if (mergeGroupId.isEmpty()) {
            return "split_use=true requires a merge_group_id returned by "
                + "list_function_variable_identities";
        }
        HighVariable highVariable = symbol.getHighVariable();
        if (highVariable == null) {
            return "Decompiler symbol has no high variable to split";
        }
        Set<String> groupIds = new HashSet<>();
        for (Varnode instance : highVariable.getInstances()) {
            groupIds.add(VariableQueries.mergeGroupId(instance));
        }
        if (!groupIds.contains(mergeGroupId)) {
            return "Merge-group identity '" + mergeGroupId
                + "' was not found for " + VariableQueries.highVariableId(symbol)
                + "; refresh list_function_variable_identities";
        }
        if (groupIds.size() < 2) {
            return "Selected variable has only one merge group and cannot be "
                + "split";
        }
        if (symbol.isNameLocked()) {
            return "Selected variable has a locked name and its merge group "
                + "cannot be split by this operation";
        }
        return null;
    }

    private static HighSymbol splitHighVariable(
            HighVariableSelection selection, HighSymbol symbol,
            String mergeGroupId)
            throws ghidra.program.model.pcode.PcodeException {
        HighVariable highVariable = symbol.getHighVariable();
        Varnode selected = null;
        for (Varnode instance : highVariable.getInstances()) {
            if (mergeGroupId.equals(VariableQueries.mergeGroupId(instance))) {
                selected = instance;
                break;
            }
        }
        if (selected == null) {
            throw new IllegalArgumentException(
                "Merge-group identity disappeared; refresh "
                + "list_function_variable_identities");
        }
        HighVariable split = selection.highFunction.splitOutMergeGroup(
            highVariable, selected);
        if (split == null || split.getSymbol() == null) {
            throw new IllegalStateException(
                "Decompiler did not produce a symbol for the split group");
        }
        return split.getSymbol();
    }

    private static String useAnchor(Varnode instance) {
        String pc = instance.getPCAddress() == null ? ""
            : instance.getPCAddress().toString();
        return pc + "|" + instance.getAddress() + "|" + instance.getSize();
    }

    private static final class SplitUseAnchors {
        private final Set<String> selected = new HashSet<>();
        private final Set<String> remaining = new HashSet<>();
    }

    private static SplitUseAnchors captureSplitUseAnchors(
            HighSymbol symbol, String mergeGroupId) {
        SplitUseAnchors anchors = new SplitUseAnchors();
        Varnode[] instances = symbol.getHighVariable().getInstances();
        for (Varnode instance : instances) {
            Set<String> owner = mergeGroupId.equals(
                VariableQueries.mergeGroupId(instance))
                ? anchors.selected : anchors.remaining;
            owner.add(useAnchor(instance));
        }
        Set<String> all = new HashSet<>(anchors.selected);
        all.addAll(anchors.remaining);
        if (anchors.selected.isEmpty() || anchors.remaining.isEmpty()
                || all.size() != instances.length) {
            throw new IllegalArgumentException(
                "Merge-group uses cannot be identified uniquely");
        }
        return anchors;
    }

    private static void verifySplitUseIsolation(Program program,
            String addrHex, SplitUseAnchors anchors, String name) {
        Address address = QuerySupport.toAddress(program, addrHex);
        Function function = QuerySupport.resolveFunction(program, address);
        if (function == null) {
            throw new IllegalStateException(
                "Split verification function disappeared");
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.openProgram(program);
            DecompileResults result = decompiler.decompileFunction(
                function, 120, TaskMonitor.DUMMY);
            if (result == null || !result.decompileCompleted()) {
                throw new IllegalStateException(
                    "Fresh decompilation failed during split verification");
            }
            Set<String> all = new HashSet<>(anchors.selected);
            all.addAll(anchors.remaining);
            Map<String, HighSymbol> owners = new HashMap<>();
            Map<HighSymbol, Set<String>> ownerUses = new HashMap<>();
            Iterator<HighSymbol> symbols = result.getHighFunction()
                .getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                HighVariable variable = symbol.getHighVariable();
                if (variable == null) {
                    continue;
                }
                Set<String> uses = new HashSet<>();
                for (Varnode instance : variable.getInstances()) {
                    String anchor = useAnchor(instance);
                    if (!uses.add(anchor)) {
                        throw new IllegalStateException(
                            "Split use has ambiguous fresh ownership");
                    }
                    if (all.contains(anchor)
                            && owners.putIfAbsent(anchor, symbol) != null) {
                        throw new IllegalStateException(
                            "Split use has ambiguous fresh ownership");
                    }
                }
                ownerUses.put(symbol, uses);
            }
            if (!owners.keySet().equals(all)) {
                throw new IllegalStateException(
                    "Split uses changed or disappeared after decompilation");
            }
            HighSymbol selectedOwner = null;
            for (String anchor : anchors.selected) {
                HighSymbol owner = owners.get(anchor);
                if (selectedOwner != null && selectedOwner != owner) {
                    throw new IllegalStateException(
                        "Selected merge-group uses did not stay together");
                }
                selectedOwner = owner;
            }
            if (selectedOwner == null || !name.equals(
                    selectedOwner.getName())
                    || !anchors.selected.equals(ownerUses.get(selectedOwner))) {
                throw new IllegalStateException(
                    "Selected merge group was not isolated under its name");
            }
            for (String anchor : anchors.remaining) {
                HighSymbol owner = owners.get(anchor);
                if (owner == selectedOwner || name.equals(owner.getName())) {
                    throw new IllegalStateException(
                        "Remaining merge-group uses received the selected name");
                }
            }
        } finally {
            decompiler.dispose();
        }
    }

    private static Variable findDatabaseVariableBySymbolId(
            Function function, long symbolId) {
        for (Variable variable : function.getAllVariables()) {
            Symbol symbol = variable.getSymbol();
            if (symbol != null && symbol.getID() == symbolId) {
                return variable;
            }
        }
        return null;
    }

    // -----------------------------------------------------------------
    // Transaction helper
    // -----------------------------------------------------------------

    static Variable findVariableByStorage(
            Function func, String storage, boolean parameter) {
        Variable[] variables = parameter
            ? func.getParameters() : func.getLocalVariables();
        for (Variable variable : variables) {
            if (storage.equals(variable.getVariableStorage().toString())) {
                return variable;
            }
        }
        return null;
    }

    private static Variable resolveUniqueVariable(
            Function func, String name) {
        Variable found = null;
        for (Parameter parameter : func.getParameters()) {
            if (name.equals(parameter.getName())) {
                if (found != null) {
                    throw new IllegalArgumentException(
                        "Variable '" + name + "' is ambiguous in "
                        + func.getName());
                }
                found = parameter;
            }
        }
        for (Variable local : func.getLocalVariables()) {
            if (name.equals(local.getName())) {
                if (found != null) {
                    throw new IllegalArgumentException(
                        "Variable '" + name + "' is ambiguous in "
                        + func.getName());
                }
                found = local;
            }
        }
        return found;
    }

}
