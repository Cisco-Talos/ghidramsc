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

import static ghidramsc.QuerySupport.isQueryError;
import static ghidramsc.QuerySupport.queryError;

import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

/** Stack variable creation and removal with conflict read-back. */
final class StackVariableMutations {
    private StackVariableMutations() { }

    static JsonElement createStackVariable(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        int stackOffset = QuerySupport.requireInt(args, "stack_offset");
        String name = QuerySupport.requireString(args, "name");
        String typeName = QuerySupport.requireString(args, "type_name");
        int size = QuerySupport.optInt(args, "size", 0);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("stack_offset", stackOffset);
        requested.addProperty("name", name);
        requested.addProperty("type_name", typeName);
        requested.addProperty("size", size);
        if (name.isBlank()) {
            return withStackVariableConflicts(
                validationFailure("create_stack_variable", requested,
                    "Stack variable name must not be blank"),
                new JsonArray());
        }
        DataType dataType = DataTypeResolver.resolveDataType(program, typeName);
        if (dataType == null) {
            return withStackVariableConflicts(
                validationFailure("create_stack_variable", requested,
                    "Unknown type '" + typeName + "'"), new JsonArray());
        }
        return createStackVariable(program, "create_stack_variable", addrHex,
            stackOffset, name, dataType, size, requested,
            SourceType.USER_DEFINED);
    }

    static JsonElement createStackVariableFromStructure(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        int stackOffset = QuerySupport.requireInt(args, "stack_offset");
        String structureName = QuerySupport.requireString(
            args, "structure_name");
        String categoryPath = QuerySupport.optString(
            args, "category_path", "");
        String name = QuerySupport.optString(args, "name", "");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("stack_offset", stackOffset);
        requested.addProperty("structure_name", structureName);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("name", name);
        if (!name.isEmpty() && name.isBlank()) {
            return withStackVariableConflicts(
                validationFailure("create_stack_variable_from_structure", requested,
                    "Stack variable name must not be blank"),
                new JsonArray());
        }

        JsonObject queryArgs = new JsonObject();
        queryArgs.addProperty("name", structureName);
        if (!categoryPath.isEmpty()) {
            queryArgs.addProperty("category_path", categoryPath);
        }
        JsonElement structureState = CompositeQueries.getStructure(
            program, queryArgs);
        if (isQueryError(structureState)) {
            return withStackVariableConflicts(
                validationFailure("create_stack_variable_from_structure", requested,
                    queryError(structureState)), new JsonArray());
        }
        String resolvedPath = structureState.getAsJsonObject()
            .get("path").getAsString();
        Structure structure = CompositeMutations.findStructure(
            program, structureName, resolvedPath);
        if (structure == null || structure.getLength() <= 0) {
            return withStackVariableConflicts(
                validationFailure("create_stack_variable_from_structure", requested,
                    "Structure must have a positive stored length"),
                new JsonArray());
        }
        requested.addProperty("resolved_category_path", resolvedPath);
        requested.addProperty("size", structure.getLength());
        return createStackVariable(program, "create_stack_variable_from_structure",
            addrHex, stackOffset, name, structure, structure.getLength(),
            requested, name.isEmpty()
                ? SourceType.DEFAULT : SourceType.USER_DEFINED);
    }

    static JsonElement deleteStackVariable(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        int stackOffset = QuerySupport.requireInt(args, "stack_offset");
        Address address = QuerySupport.toAddress(program, addrHex);
        Function function = QuerySupport.resolveFunction(program, address);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", address.toString());
        requested.addProperty("stack_offset", stackOffset);
        JsonArray conflicts = new JsonArray();
        if (function == null) {
            return withStackVariableConflicts(
                validationFailure("delete_stack_variable", requested,
                    "No function at or containing " + addrHex), conflicts);
        }
        ghidra.program.model.listing.StackFrame frame =
            function.getStackFrame();
        JsonObject oldState = FunctionQueries.stackFrameState(function);
        Variable target = frame.getVariableContaining(stackOffset);
        if (target == null) {
            JsonObject failure = validationFailure(
                "delete_stack_variable", requested,
                "No stack variable starts at offset " + stackOffset);
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        conflicts.add(FunctionQueries.stackVariableState(frame, target));
        if (target.getStackOffset() != stackOffset) {
            JsonObject failure = validationFailure(
                "delete_stack_variable", requested,
                "Offset " + stackOffset + " is inside stack variable '"
                + target.getName() + "'; specify its exact start offset "
                + target.getStackOffset());
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        if (frame.isParameterOffset(stackOffset)) {
            JsonObject failure = validationFailure(
                "delete_stack_variable", requested,
                "Parameter stack variables are not supported; use function "
                + "prototype tools");
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        requested.add("target",
            FunctionQueries.stackVariableState(frame, target));

        return withTransaction(program, "Delete stack variable", tx -> {
            try {
                function.removeVariable(target);
                if (frame.getVariableContaining(stackOffset) != null) {
                    throw new IllegalStateException(
                        "Stack variable still exists at offset "
                        + stackOffset);
                }
                JsonObject stored = FunctionQueries.stackFrameState(function);
                tx.commit();
                return withStackVariableConflicts(
                    successResult("delete_stack_variable", oldState,
                        requested, stored), new JsonArray());
            } catch (Exception e) {
                return withStackVariableConflicts(
                    rolledBackResult("delete_stack_variable", oldState,
                        requested, errorMessage(e)), conflicts);
            }
        }, () -> FunctionQueries.stackFrameState(function));
    }

    private static JsonElement createStackVariable(
            Program program, String operation, String addrHex,
            int stackOffset, String name, DataType dataType, int size,
            JsonObject requested, SourceType source) {
        Address address = QuerySupport.toAddress(program, addrHex);
        Function function = QuerySupport.resolveFunction(program, address);
        JsonArray conflicts = new JsonArray();
        if (function == null) {
            return withStackVariableConflicts(
                validationFailure(operation, requested,
                    "No function at or containing " + addrHex), conflicts);
        }
        JsonObject oldState = FunctionQueries.stackFrameState(function);
        ghidra.program.model.listing.StackFrame frame =
            function.getStackFrame();
        int typeLength = dataType.getLength();
        if (typeLength <= 0) {
            JsonObject failure = validationFailure(operation, requested,
                "Stack variable type must have a positive fixed length");
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        if (size < 0 || size != 0 && size != typeLength) {
            JsonObject failure = validationFailure(operation, requested,
                size < 0
                    ? "size must be zero or positive"
                    : "Requested size " + size + " does not match type length "
                        + typeLength);
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        long endOffset = (long) stackOffset + typeLength - 1L;
        if (endOffset > Integer.MAX_VALUE) {
            JsonObject failure = validationFailure(operation, requested,
                "Stack variable range exceeds the supported offset range");
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        if (frame.isParameterOffset(stackOffset)
                || frame.isParameterOffset((int) endOffset)) {
            JsonObject failure = validationFailure(operation, requested,
                "Parameter stack offsets are not supported; use function "
                + "prototype tools");
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        if (!name.isEmpty()) {
            for (Variable existing : function.getAllVariables()) {
                if (name.equals(existing.getName())) {
                    JsonObject failure = validationFailure(
                        operation, requested,
                        "Variable name '" + name
                        + "' already exists in the function");
                    failure.add("old", oldState.deepCopy());
                    return withStackVariableConflicts(failure, conflicts);
                }
            }
        }
        conflicts = stackVariableConflicts(
            frame, stackOffset, (int) endOffset);
        if (!conflicts.isEmpty()) {
            JsonObject failure = validationFailure(operation, requested,
                "Requested stack storage overlaps existing variables");
            failure.add("old", oldState.deepCopy());
            return withStackVariableConflicts(failure, conflicts);
        }
        requested.addProperty("resolved_type", dataType.getName());
        requested.addProperty("resolved_type_path", dataType.getPathName());
        requested.addProperty("resolved_size", typeLength);

        JsonArray reportedConflicts = conflicts;
        return withTransaction(program,
                "create_stack_variable_from_structure".equals(operation)
                    ? "Apply stack structure" : "Create stack variable",
                tx -> {
            try {
                Variable created = frame.createVariable(
                    name.isEmpty() ? null : name, stackOffset,
                    dataType, source);
                Variable storedVariable =
                    frame.getVariableContaining(stackOffset);
                if (created == null || storedVariable == null
                        || storedVariable.getStackOffset() != stackOffset
                        || storedVariable.getLength() != typeLength
                        || !storedVariable.getDataType()
                            .isEquivalent(dataType)
                        || !name.isEmpty()
                            && !name.equals(storedVariable.getName())) {
                    throw new IllegalStateException(
                        "Stack variable read-back did not match the request");
                }
                JsonObject stored = FunctionQueries.stackFrameState(function);
                tx.commit();
                return withStackVariableConflicts(
                    successResult(operation, oldState,
                        requested, stored), reportedConflicts);
            } catch (Exception e) {
                return withStackVariableConflicts(
                    rolledBackResult(operation, oldState,
                        requested, errorMessage(e)), reportedConflicts);
            }
        }, () -> FunctionQueries.stackFrameState(function));
    }

    private static JsonArray stackVariableConflicts(
            ghidra.program.model.listing.StackFrame frame,
            int requestedStart, int requestedEnd) {
        JsonArray conflicts = new JsonArray();
        for (Variable variable : frame.getStackVariables()) {
            long existingStart = variable.getStackOffset();
            long existingEnd = existingStart + variable.getLength() - 1L;
            if (requestedStart <= existingEnd
                    && existingStart <= requestedEnd) {
                conflicts.add(FunctionQueries.stackVariableState(
                    frame, variable));
            }
        }
        return conflicts;
    }

    private static JsonObject withStackVariableConflicts(
            JsonObject result, JsonArray conflicts) {
        result.add("conflicting_variables", conflicts.deepCopy());
        return result;
    }

}
