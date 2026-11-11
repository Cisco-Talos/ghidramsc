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

import static ghidramsc.MutationArguments.requireJsonObject;
import static ghidramsc.MutationArguments.requireJsonString;

import static ghidramsc.FunctionMutationReadback.queryFunctionState;
import static ghidramsc.FunctionMutationReadback.queryFuncInfo;

import static ghidramsc.QuerySupport.isQueryError;
import static ghidramsc.QuerySupport.queryError;

import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.noChangeResult;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.statusSuffix;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Function prototype, return, convention, no-return, and annotation edits. */
final class FunctionSignatureMutations {
    private FunctionSignatureMutations() { }

    static final String RETURN_TYPE_INFERRED_PARAMETER_ERROR =
        "Return-type-only mutation cannot safely preserve inferred, "
        + "non-database parameters; use set_function_prototype with the "
        + "complete signature.";

    // -----------------------------------------------------------------
    // set_function_return_type
    // -----------------------------------------------------------------

    static JsonElement setFunctionReturnType(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String typeName = QuerySupport.requireString(
            args, "type_name");
        JsonObject requested = new JsonObject();
        requested.addProperty("return_type", typeName);
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        if (func == null) {
            return validationFailure("set_function_return_type", requested,
                "No function at " + addrHex);
        }

        DataType dt = DataTypeResolver.resolveDataType(program, typeName);
        if (dt == null) {
            return validationFailure("set_function_return_type", requested,
                "Unknown data type: " + typeName);
        }
        requested.addProperty("return_type", dt.toString());
        JsonElement oldState = FunctionMutationReadback.queryFuncInfo(program, addrHex);
        if (func.getReturnType().isEquivalent(dt)) {
            return noChangeResult("set_function_return_type", oldState,
                requested, oldState.deepCopy());
        }
        JsonArray oldParameters;
        try {
            JsonElement identities = queryEffectiveParameterIdentities(
                program, addrHex);
            String parameterError = returnTypeParameterBlocker(identities);
            if (parameterError != null) {
                return validationFailure("set_function_return_type", requested,
                    parameterError);
            }
            oldParameters = effectiveParameterContract(identities);
        } catch (Exception e) {
            return validationFailure("set_function_return_type", requested,
                errorMessage(e));
        }

        return withTransaction(program, "Set return type", tx -> {
            try {
                func.setReturnType(dt, SourceType.USER_DEFINED);
                JsonElement stored = FunctionMutationReadback.queryFuncInfo(program, addrHex);
                if (!func.getReturnType().isEquivalent(dt)) {
                    throw new IllegalStateException(
                        "Return type read-back mismatch: requested "
                        + dt + ", stored " + func.getReturnType());
                }
                assertEffectiveParametersPreserved(
                    program, addrHex, oldParameters);
                tx.commit();
                return successResult("set_function_return_type", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_function_return_type", oldState,
                    requested, errorMessage(e));
            }
        }, () -> FunctionMutationReadback.queryFuncInfo(program, addrHex));
    }

    // -----------------------------------------------------------------
    // apply_function_annotations
    // -----------------------------------------------------------------

    static JsonElement applyFunctionAnnotations(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        JsonObject data = requireJsonObject(args, "json_data");

        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        if (func == null) {
            return validationFailure("apply_function_annotations", data,
                "No function at " + addrHex);
        }

        JsonObject oldState;
        List<VariableChange> changes = new ArrayList<>();
        JsonObject requested;
        try {
            oldState = FunctionMutationReadback.queryFunctionState(program, addrHex);
            requested = preflightAnnotation(
                program, func, data, changes);
        } catch (Exception e) {
            return validationFailure("apply_function_annotations", data,
                errorMessage(e));
        }
        DataType annotationReturnType = data.has("return_type")
            ? DataTypeResolver.resolveDataType(program,
                data.get("return_type").getAsString()) : null;

        if (!annotationWouldChange(
                func, requested, changes, annotationReturnType)) {
            return noChangeResult(
                "apply_function_annotations", oldState, requested, oldState.deepCopy());
        }
        boolean returnTypeChanges = requested.has("return_type")
            && !func.getReturnType().isEquivalent(annotationReturnType);
        JsonArray oldParameters = null;
        if (returnTypeChanges) {
            try {
                JsonElement identities = queryEffectiveParameterIdentities(
                    program, addrHex);
                String parameterError = returnTypeParameterBlocker(identities);
                if (parameterError != null) {
                    return validationFailure("apply_function_annotations", requested,
                        parameterError);
                }
                oldParameters = effectiveParameterContract(identities);
            } catch (Exception e) {
                return validationFailure("apply_function_annotations", requested,
                    errorMessage(e));
            }
        }
        JsonArray preservedParameters = oldParameters;

        return withTransaction(
            program, "Annotate function", tx -> {
                try {
                    if (requested.has("calling_convention")) {
                        func.setCallingConvention(requested.get(
                            "calling_convention").getAsString());
                    }
                    if (returnTypeChanges) {
                        func.setReturnType(annotationReturnType,
                            SourceType.USER_DEFINED);
                    }

                    for (VariableChange change : changes) {
                        if (!change.oldName.equals(change.newName)) {
                            change.variable.setName(change.newName,
                                SourceType.USER_DEFINED);
                        }
                        if (change.dataType != null
                                && !change.variable.getDataType()
                                    .isEquivalent(change.dataType)) {
                            change.variable.setDataType(change.dataType,
                                SourceType.USER_DEFINED);
                        }
                    }

                    verifyAnnotation(func, requested, changes,
                        annotationReturnType);
                    if (returnTypeChanges) {
                        assertEffectiveParametersPreserved(
                            program, addrHex, preservedParameters);
                    }
                    JsonObject stored = FunctionMutationReadback.queryFunctionState(
                        program, addrHex);
                    tx.commit();
                    return successResult("apply_function_annotations", oldState,
                        requested, stored);
                } catch (Exception e) {
                    return rolledBackResult("apply_function_annotations", oldState,
                        requested, errorMessage(e));
                }
            }, () -> FunctionMutationReadback.queryFunctionState(program, addrHex));
    }

    // -----------------------------------------------------------------
    // set_function_prototype
    // -----------------------------------------------------------------

    static JsonElement setFunctionPrototype(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String prototype = QuerySupport.requireString(
            args, "prototype");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("prototype", prototype);
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        if (func == null) {
            return validationFailure("set_function_prototype", requested,
                "No function at " + addrHex);
        }
        JsonElement oldState = FunctionMutationReadback.queryFuncInfo(program, addrHex);
        ghidra.program.model.listing.FunctionSignature parsed;
        try {
            parsed = parseFunctionSignature(program, prototype);
            normalizeParsedCallingConvention(program, func, parsed);
        } catch (IllegalArgumentException e) {
            return validationFailure("set_function_prototype", requested,
                errorMessage(e));
        }
        String parameterConflict = findPrototypeParameterConflict(
            func, parsed);
        if (parameterConflict != null) {
            return validationFailure("set_function_prototype", requested,
                parameterConflict);
        }
        if (functionSignatureMatches(func, parsed)) {
            return noChangeResult("set_function_prototype", oldState,
                requested, oldState.deepCopy());
        }

        return withTransaction(program, "Set function prototype", tx -> {
            try {
                var cmd = new ghidra.app.cmd.function
                    .ApplyFunctionSignatureCmd(
                        func.getEntryPoint(),
                        parsed,
                        SourceType.USER_DEFINED,
                        false,
                        false,
                        DataTypeConflictHandler.DEFAULT_HANDLER,
                        FunctionRenameOption.RENAME);
                boolean ok = cmd.applyTo(program,
                    TaskMonitor.DUMMY);
                if (!ok) {
                    return rolledBackResult("set_function_prototype",
                        oldState, requested,
                        "Failed to apply prototype"
                        + statusSuffix(cmd.getStatusMsg()));
                }
                JsonElement stored = FunctionMutationReadback.queryFuncInfo(program, addrHex);
                if (!functionSignatureMatches(func, parsed)) {
                    throw new IllegalStateException(
                        "Prototype read-back does not match the parsed request");
                }
                tx.commit();
                return successResult("set_function_prototype", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_function_prototype", oldState,
                    requested, errorMessage(e));
            }
        }, () -> FunctionMutationReadback.queryFuncInfo(program, addrHex));
    }

    // -----------------------------------------------------------------
    // set_function_calling_convention
    // -----------------------------------------------------------------

    static JsonElement setFunctionCallingConvention(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String convention = QuerySupport.requireString(
            args, "convention");
        JsonObject requested = new JsonObject();
        requested.addProperty("calling_convention", convention);
        Address addr = QuerySupport.toAddress(program, addrHex);
        Function func = QuerySupport.resolveFunction(program, addr);
        if (func == null) {
            return validationFailure("set_function_calling_convention", requested,
                "No function at " + addrHex);
        }
        if (!convention.equals(func.getCallingConventionName())
                && !Function.DEFAULT_CALLING_CONVENTION_STRING
                    .equals(convention)
                && program.getFunctionManager()
                    .getCallingConvention(convention) == null) {
            java.util.List<String> available = new java.util.ArrayList<>(
                program.getFunctionManager().getCallingConventionNames());
            if (!available.contains(Function.DEFAULT_CALLING_CONVENTION_STRING)) {
                available.add(Function.DEFAULT_CALLING_CONVENTION_STRING);
            }
            java.util.Collections.sort(available);
            return validationFailure("set_function_calling_convention", requested,
                "Unknown calling convention: " + convention
                    + ". Available for this program: "
                    + String.join(", ", available));
        }
        JsonElement oldState = FunctionMutationReadback.queryFuncInfo(program, addrHex);
        if (convention.equals(func.getCallingConventionName())) {
            return noChangeResult("set_function_calling_convention", oldState,
                requested, oldState.deepCopy());
        }

        return withTransaction(program, "Set calling convention", tx -> {
            try {
                func.setCallingConvention(convention);
                JsonElement stored = FunctionMutationReadback.queryFuncInfo(program, addrHex);
                String storedConvention = stored.getAsJsonObject()
                    .get("calling_convention").getAsString();
                if (!convention.equals(storedConvention)) {
                    throw new IllegalStateException(
                        "Calling convention read-back mismatch: requested "
                        + convention + ", stored " + storedConvention);
                }
                tx.commit();
                return successResult("set_function_calling_convention", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_function_calling_convention", oldState,
                    requested, errorMessage(e));
            }
        }, () -> FunctionMutationReadback.queryFuncInfo(program, addrHex));
    }

    // -----------------------------------------------------------------
    // set_function_noreturn
    // -----------------------------------------------------------------

    private static JsonObject functionNoReturnState(Function function) {
        Function effective = function.isThunk()
            ? function.getThunkedFunction(true) : null;
        if (effective == null) {
            effective = function;
        }
        JsonObject state = new JsonObject();
        state.addProperty("entry", function.getEntryPoint().toString());
        state.addProperty("name", function.getName());
        state.addProperty("no_return", function.hasNoReturn());
        state.addProperty("is_thunk", function.isThunk());
        state.addProperty("is_external", function.isExternal());
        state.addProperty("effective_entry", effective.getEntryPoint().toString());
        state.addProperty("effective_no_return", effective.hasNoReturn());
        state.addProperty("signature", function.getSignature().toString());
        return state;
    }

    static JsonElement setFunctionNoReturn(Program program, JsonObject args) {
        final String op = "set_function_noreturn";
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        if (!args.has("no_return") || !args.get("no_return").isJsonPrimitive()
                || !args.get("no_return").getAsJsonPrimitive().isBoolean()) {
            return validationFailure(op, requested,
                "no_return must be a boolean");
        }
        boolean noReturn = args.get("no_return").getAsBoolean();
        requested.addProperty("no_return", noReturn);
        Function function;
        try {
            Address address = QuerySupport.toAddress(program, addrHex);
            function = QuerySupport.resolveFunction(program, address);
        } catch (Exception error) {
            return validationFailure(op, requested,
                "Invalid address: " + errorMessage(error));
        }
        if (function == null) {
            return validationFailure(op, requested,
                "No function at " + addrHex);
        }
        JsonObject old = functionNoReturnState(function);
        if (old.get("no_return").getAsBoolean() == noReturn) {
            return noChangeResult(op, old, requested, old.deepCopy());
        }
        return withTransaction(program, "Set function no-return", tx -> {
            try {
                function.setNoReturn(noReturn);
                JsonObject stored = functionNoReturnState(function);
                if (!stored.get("entry").equals(old.get("entry"))
                        || !stored.get("effective_entry").equals(
                            old.get("effective_entry"))
                        || stored.get("no_return").getAsBoolean() != noReturn
                        || stored.get("effective_no_return").getAsBoolean()
                            != noReturn) {
                    throw new IllegalStateException(
                        "Function no-return read-back mismatch");
                }
                tx.commit();
                return successResult(op, old, requested, stored);
            } catch (Exception error) {
                return rolledBackResult(op, old, requested,
                    errorMessage(error));
            }
        }, () -> functionNoReturnState(function));
    }

    private static final class VariableChange {
        private final Variable variable;
        private final String oldName;
        private final String newName;
        private final String storage;
        private final boolean parameter;
        private final DataType dataType;

        VariableChange(Variable variable, String newName,
                DataType dataType, boolean parameter) {
            this.variable = variable;
            this.oldName = variable.getName();
            this.newName = newName;
            this.storage = variable.getVariableStorage().toString();
            this.parameter = parameter;
            this.dataType = dataType;
        }
    }

    private static JsonObject preflightAnnotation(
            Program program, Function func, JsonObject data,
            List<VariableChange> changes) {
        JsonObject requested = new JsonObject();

        if (data.has("calling_convention")) {
            String convention = requireJsonString(
                data, "calling_convention");
            if (!convention.equals(func.getCallingConventionName())
                    && !Function.DEFAULT_CALLING_CONVENTION_STRING
                        .equals(convention)
                    && program.getFunctionManager()
                        .getCallingConvention(convention) == null) {
                throw new IllegalArgumentException(
                    "Unknown calling convention: " + convention);
            }
            requested.addProperty("calling_convention", convention);
        }

        if (data.has("return_type")) {
            String typeName = requireJsonString(data, "return_type");
            DataType returnType = DataTypeResolver.resolveDataType(program, typeName);
            if (returnType == null) {
                throw new IllegalArgumentException(
                    "Unknown return type: " + typeName);
            }
            requested.addProperty("return_type", returnType.toString());
        }

        Map<String, List<Variable>> variablesByName = new HashMap<>();
        Map<Variable, Boolean> parameterKinds = new HashMap<>();
        for (Parameter parameter : func.getParameters()) {
            variablesByName.computeIfAbsent(parameter.getName(),
                ignored -> new ArrayList<>()).add(parameter);
            parameterKinds.put(parameter, true);
        }
        for (Variable local : func.getLocalVariables()) {
            variablesByName.computeIfAbsent(local.getName(),
                ignored -> new ArrayList<>()).add(local);
            parameterKinds.put(local, false);
        }

        JsonArray normalizedVars = new JsonArray();
        Set<String> seenOldNames = new HashSet<>();
        Set<String> requestedNames = new HashSet<>();
        if (data.has("vars")) {
            if (!data.get("vars").isJsonArray()) {
                throw new IllegalArgumentException(
                    "Invalid JSON array field: vars");
            }
            for (JsonElement element : data.getAsJsonArray("vars")) {
                if (!element.isJsonObject()) {
                    throw new IllegalArgumentException(
                        "apply_function_annotations vars entries must be objects");
                }
                JsonObject spec = element.getAsJsonObject();
                String oldName = requireJsonString(spec, "old_name");
                if (!seenOldNames.add(oldName)) {
                    throw new IllegalArgumentException(
                        "Duplicate variable request: " + oldName);
                }

                List<Variable> matches = variablesByName.get(oldName);
                if (matches == null || matches.isEmpty()) {
                    throw new IllegalArgumentException(
                        "Variable '" + oldName + "' not found in "
                        + func.getName());
                }
                if (matches.size() != 1) {
                    throw new IllegalArgumentException(
                        "Variable '" + oldName
                        + "' is ambiguous in " + func.getName());
                }

                Variable variable = matches.get(0);
                String newName = oldName;
                if (spec.has("new_name")) {
                    String value = requireJsonString(spec, "new_name");
                    if (!value.isEmpty()) {
                        newName = value;
                    }
                }
                if (!requestedNames.add(newName)) {
                    throw new IllegalArgumentException(
                        "Multiple variables request the name '"
                        + newName + "'");
                }
                if (!newName.equals(oldName)
                        && variablesByName.containsKey(newName)) {
                    throw new IllegalArgumentException(
                        "Requested name '" + newName
                        + "' conflicts with an existing variable");
                }

                DataType dataType = null;
                if (spec.has("type")) {
                    String typeName = requireJsonString(spec, "type");
                    if (!typeName.isEmpty()) {
                        dataType = DataTypeResolver.resolveDataType(program, typeName);
                        if (dataType == null) {
                            throw new IllegalArgumentException(
                                "Unknown variable type '" + typeName
                                + "' for " + oldName);
                        }
                    }
                }

                boolean parameter = parameterKinds.get(variable);
                VariableChange change = new VariableChange(
                    variable, newName, dataType, parameter);
                changes.add(change);

                JsonObject normalized = new JsonObject();
                normalized.addProperty("old_name", oldName);
                normalized.addProperty("new_name", newName);
                normalized.addProperty("storage", change.storage);
                normalized.addProperty("kind",
                    parameter ? "parameter" : "local");
                if (dataType != null) {
                    normalized.addProperty("type", dataType.toString());
                }
                normalizedVars.add(normalized);
            }
        }
        requested.add("vars", normalizedVars);
        return requested;
    }

    private static boolean annotationWouldChange(
            Function func, JsonObject requested,
            List<VariableChange> changes, DataType returnType) {
        if (requested.has("calling_convention")
                && !requested.get("calling_convention").getAsString()
                    .equals(func.getCallingConventionName())) {
            return true;
        }
        if (requested.has("return_type")) {
            if (!func.getReturnType().isEquivalent(returnType)) {
                return true;
            }
        }
        for (VariableChange change : changes) {
            if (!change.oldName.equals(change.newName)
                    || change.dataType != null
                    && !change.variable.getDataType()
                        .isEquivalent(change.dataType)) {
                return true;
            }
        }
        return false;
    }

    private static void verifyAnnotation(
            Function func, JsonObject requested,
            List<VariableChange> changes, DataType returnType) {
        if (requested.has("calling_convention")) {
            String expected = requested.get(
                "calling_convention").getAsString();
            if (!expected.equals(func.getCallingConventionName())) {
                throw new IllegalStateException(
                    "Calling convention read-back mismatch: requested "
                    + expected + ", stored "
                    + func.getCallingConventionName());
            }
        }
        if (requested.has("return_type")) {
            if (!func.getReturnType().isEquivalent(returnType)) {
                throw new IllegalStateException(
                    "Return type read-back mismatch: requested "
                    + requested.get("return_type").getAsString()
                    + ", stored " + func.getReturnType());
            }
        }
        for (VariableChange change : changes) {
            Variable stored = VariableMutations.findVariableByStorage(
                func, change.storage, change.parameter);
            if (stored == null) {
                throw new IllegalStateException(
                    "Variable read-back failed for storage "
                    + change.storage);
            }
            if (!change.newName.equals(stored.getName())) {
                throw new IllegalStateException(
                    "Variable name read-back mismatch at "
                    + change.storage + ": requested "
                    + change.newName + ", stored " + stored.getName());
            }
            if (change.dataType != null
                    && !stored.getDataType()
                        .isEquivalent(change.dataType)) {
                throw new IllegalStateException(
                    "Variable type read-back mismatch at "
                    + change.storage + ": requested "
                    + change.dataType + ", stored "
                    + stored.getDataType());
            }
        }
    }

    private static JsonElement queryEffectiveParameterIdentities(
            Program program, String addrHex) {
        JsonObject queryArgs = new JsonObject();
        queryArgs.addProperty("addr_hex", addrHex);
        queryArgs.addProperty("offset", 0);
        queryArgs.addProperty("limit", 500);
        JsonElement identities = VariableQueries.listFunctionVariableIdentities(
            program, queryArgs);
        if (isQueryError(identities)) {
            throw new IllegalStateException(
                "Cannot verify effective parameters: "
                + queryError(identities));
        }
        return identities;
    }

    static String returnTypeParameterBlocker(JsonElement identities) {
        if (identities == null || !identities.isJsonObject()) {
            return "Cannot verify effective parameters; use "
                + "set_function_prototype with the complete signature.";
        }
        JsonObject state = identities.getAsJsonObject();
        if (!state.has("pagination")
                || !state.get("pagination").isJsonObject()
                || !state.has("params") || !state.get("params").isJsonArray()) {
            return "Cannot verify effective parameters; use "
                + "set_function_prototype with the complete signature.";
        }
        JsonObject pagination = state.getAsJsonObject("pagination");
        if (pagination.has("has_more")
                && pagination.get("has_more").getAsBoolean()) {
            return "Cannot verify more than 500 effective variables; use "
                + "set_function_prototype with the complete signature.";
        }
        for (JsonElement element : state.getAsJsonArray("params")) {
            JsonObject parameter = element.getAsJsonObject();
            if (!parameter.has("database_backed")
                    || !parameter.get("database_backed").getAsBoolean()) {
                return RETURN_TYPE_INFERRED_PARAMETER_ERROR;
            }
        }
        return null;
    }

    static JsonArray effectiveParameterContract(JsonElement identities) {
        JsonArray contract = new JsonArray();
        String[] fields = {
            "name", "type", "size", "storage", "is_param",
            "category_index", "database_backed", "backing",
            "database_symbol_id"
        };
        for (JsonElement element : identities.getAsJsonObject()
                .getAsJsonArray("params")) {
            JsonObject parameter = element.getAsJsonObject();
            JsonObject normalized = new JsonObject();
            for (String field : fields) {
                if (parameter.has(field)) {
                    normalized.add(field, parameter.get(field).deepCopy());
                }
            }
            contract.add(normalized);
        }
        return contract;
    }

    private static void assertEffectiveParametersPreserved(
            Program program, String addrHex, JsonArray expected) {
        JsonElement identities = queryEffectiveParameterIdentities(
            program, addrHex);
        String parameterError = returnTypeParameterBlocker(identities);
        if (parameterError != null) {
            throw new IllegalStateException(parameterError);
        }
        JsonArray stored = effectiveParameterContract(identities);
        if (!expected.equals(stored)) {
            throw new IllegalStateException(
                "Effective parameter list changed during return-type mutation");
        }
    }

    static ghidra.program.model.listing.FunctionSignature
            parseFunctionSignature(Program program, String prototype) {
        String declaration = prototype == null ? "" : prototype.trim();
        if (declaration.isEmpty()) {
            throw new IllegalArgumentException(
                "Prototype must not be empty");
        }
        if (!declaration.endsWith(";")) {
            declaration += ";";
        }
        try {
            var parser = new ghidra.app.util.cparser.C.CParser(
                program.getDataTypeManager());
            DataType parsed = parser.parse(declaration);
            if (!parser.didParseSucceed()
                    || !(parsed instanceof FunctionDefinitionDataType)) {
                String details = parser.getParseMessages();
                throw new IllegalArgumentException(
                    "Could not parse function prototype"
                    + statusSuffix(details));
            }
            FunctionDefinitionDataType signature =
                (FunctionDefinitionDataType) parsed;
            validateResolvedSignatureTypes(signature);
            if (signature.getName() == null
                    || signature.getName().isBlank()) {
                throw new IllegalArgumentException(
                    "Prototype must declare a function name");
            }
            return signature;
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) {
                throw (IllegalArgumentException) e;
            }
            throw new IllegalArgumentException(
                "Could not parse function prototype: " + errorMessage(e), e);
        }
    }

    private static void validateResolvedSignatureTypes(
            ghidra.program.model.listing.FunctionSignature signature) {
        requireResolvedPrototypeType("return", signature.getReturnType());
        for (ParameterDefinition parameter : signature.getArguments()) {
            String name = parameter.getName();
            requireResolvedPrototypeType(
                "parameter '" + (name == null ? "" : name) + "'",
                parameter.getDataType());
        }
    }

    private static void normalizeParsedCallingConvention(
            Program program, Function func,
            ghidra.program.model.listing.FunctionSignature signature) {
        String requested = signature.getCallingConventionName();
        if (program.getCompilerSpec().getCallingConvention(requested) != null) {
            return;
        }
        String current = func.getCallingConventionName();
        if (current == null
                || program.getCompilerSpec().getCallingConvention(current)
                    == null) {
            return;
        }
        try {
            ((FunctionDefinitionDataType) signature)
                .setCallingConvention(current);
        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Could not preserve calling convention '" + current
                + "': " + errorMessage(e), e);
        }
    }

    private static void requireResolvedPrototypeType(
            String location, DataType dataType) {
        DataType current = dataType;
        while (current instanceof ghidra.program.model.data.TypeDef) {
            current = ((ghidra.program.model.data.TypeDef) current)
                .getBaseDataType();
        }
        while (current instanceof ghidra.program.model.data.Pointer) {
            current = ((ghidra.program.model.data.Pointer) current)
                .getDataType();
            if (current == null) {
                return;
            }
            while (current instanceof ghidra.program.model.data.TypeDef) {
                current = ((ghidra.program.model.data.TypeDef) current)
                    .getBaseDataType();
            }
        }
        if (current == null
                || current instanceof ghidra.program.model.data.BadDataType
                || ghidra.program.model.data.Undefined.isUndefined(current)) {
            throw new IllegalArgumentException(
                "Unresolved " + location + " type: "
                + (dataType == null ? "null" : dataType.getDisplayName()));
        }
    }

    private static String findPrototypeParameterConflict(
            Function func,
            ghidra.program.model.listing.FunctionSignature signature) {
        Map<String, Integer> requestedOrdinals = new HashMap<>();
        for (ParameterDefinition requested : signature.getArguments()) {
            String name = requested.getName();
            if (name == null || name.isBlank()) {
                continue;
            }
            Integer prior = requestedOrdinals.putIfAbsent(
                name, requested.getOrdinal());
            if (prior != null) {
                return "Requested parameter name '" + name
                    + "' is duplicated at ordinals " + prior + " and "
                    + requested.getOrdinal();
            }
        }
        for (Variable local : func.getLocalVariables()) {
            if (requestedOrdinals.containsKey(local.getName())) {
                return prototypeVariableConflict(local);
            }
        }
        for (Parameter existing : func.getParameters()) {
            Integer requestedOrdinal = requestedOrdinals.get(
                existing.getName());
            if (requestedOrdinal != null
                    && requestedOrdinal != existing.getOrdinal()) {
                return prototypeVariableConflict(existing);
            }
        }
        return null;
    }

    private static String prototypeVariableConflict(Variable variable) {
        Symbol symbol = variable.getSymbol();
        String symbolType = symbol == null
            ? (variable instanceof Parameter ? "PARAMETER" : "LOCAL_VAR")
            : symbol.getSymbolType().toString();
        return "Requested parameter name '" + variable.getName()
            + "' conflicts with existing " + symbolType
            + " at storage " + variable.getVariableStorage();
    }

    private static boolean functionSignatureMatches(
            Function func,
            ghidra.program.model.listing.FunctionSignature requested) {
        if (!func.getName().equals(requested.getName())) {
            return false;
        }
        var stored = func.getSignature();
        if (stored.isEquivalentSignature(requested)) {
            return true;
        }
        // Parsed definitions can differ in hidden metadata even when Ghidra
        // stores the same visible prototype and equivalent data types.
        if (!stored.toString().equals(requested.toString())
                || !Objects.equals(stored.getCallingConventionName(),
                    requested.getCallingConventionName())
                || stored.hasVarArgs() != requested.hasVarArgs()
                || stored.hasNoReturn() != requested.hasNoReturn()
                || !stored.getReturnType().isEquivalent(
                    requested.getReturnType())) {
            return false;
        }
        var storedArgs = stored.getArguments();
        var requestedArgs = requested.getArguments();
        if (storedArgs.length != requestedArgs.length) {
            return false;
        }
        for (int i = 0; i < storedArgs.length; i++) {
            if (!storedArgs[i].getDataType().isEquivalent(
                    requestedArgs[i].getDataType())) {
                return false;
            }
        }
        return true;
    }

}
