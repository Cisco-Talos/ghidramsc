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

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

/**
 * Stable dispatcher facade for GhidraMSC mutation commands.
 * Domain classes own native operations; MutationTransaction owns commit
 * and read-back, and ProgramPersistence owns GUI save.
 */
public final class MutationHandlers {

    static final String RETURN_TYPE_INFERRED_PARAMETER_ERROR =
        FunctionSignatureMutations.RETURN_TYPE_INFERRED_PARAMETER_ERROR;

    static String returnTypeParameterBlocker(JsonElement identities) {
        return FunctionSignatureMutations.returnTypeParameterBlocker(identities);
    }

    static JsonArray effectiveParameterContract(JsonElement identities) {
        return FunctionSignatureMutations.effectiveParameterContract(identities);
    }

    private MutationHandlers() { /* utility class */ }

    public static JsonElement setFunctionName(Program program, JsonObject args) {
        return FunctionLifecycleMutations.setFunctionName(program, args);
    }

    public static JsonElement setFunctionNames(Program program, JsonObject args) {
        return FunctionLifecycleMutations.setFunctionNames(program, args);
    }

    public static JsonElement deleteFunction(Program program, JsonObject args) {
        return FunctionLifecycleMutations.deleteFunction(program, args);
    }

    public static JsonElement setFunctionBody(Program program, JsonObject args) {
        return FunctionLifecycleMutations.setFunctionBody(program, args);
    }

    public static JsonElement createFunction(Program program, JsonObject args) {
        return FunctionLifecycleMutations.createFunction(program, args);
    }

    public static JsonElement createStackVariable(Program program, JsonObject args) {
        return StackVariableMutations.createStackVariable(program, args);
    }

    public static JsonElement createStackVariableFromStructure(Program program, JsonObject args) {
        return StackVariableMutations.createStackVariableFromStructure(program, args);
    }

    public static JsonElement deleteStackVariable(Program program, JsonObject args) {
        return StackVariableMutations.deleteStackVariable(program, args);
    }

    public static JsonElement createFunctions(Program program, JsonObject args) {
        return FunctionLifecycleMutations.createFunctions(program, args);
    }

    public static JsonElement disassembleMemory(Program program, JsonObject args) {
        return CodeDataMutations.disassembleMemory(program, args);
    }

    public static JsonElement clearCodeUnits(Program program, JsonObject args) {
        return CodeDataMutations.clearCodeUnits(program, args);
    }

    public static JsonElement importAnnotations(Program program, JsonObject args) {
        return AnnotationImportMutations.importAnnotations(program, args);
    }

    public static JsonElement fixRegion(Program program, JsonObject args) {
        return CodeDataMutations.fixRegion(program, args);
    }

    public static JsonElement setVariableName(Program program, JsonObject args) {
        return VariableMutations.setVariableName(program, args);
    }

    public static JsonElement setVariableType(Program program, JsonObject args) {
        return VariableMutations.setVariableType(program, args);
    }

    public static JsonElement setVariableNameById(Program program, JsonObject args) {
        return VariableMutations.setVariableNameById(program, args);
    }

    public static JsonElement setVariableTypeById(Program program, JsonObject args) {
        return VariableMutations.setVariableTypeById(program, args);
    }

    public static JsonElement createVariableById(Program program, JsonObject args) {
        return VariableMutations.createVariableById(program, args);
    }

    public static JsonElement deleteVariableById(Program program, JsonObject args) {
        return VariableMutations.deleteVariableById(program, args);
    }

    public static JsonElement setFunctionReturnType(Program program, JsonObject args) {
        return FunctionSignatureMutations.setFunctionReturnType(program, args);
    }

    public static JsonElement applyFunctionAnnotations(Program program, JsonObject args) {
        return FunctionSignatureMutations.applyFunctionAnnotations(program, args);
    }

    public static JsonElement setCommentAtAddress(Program program, JsonObject args) {
        return AnnotationMutations.setCommentAtAddress(program, args);
    }

    public static JsonElement createBookmark(Program program, JsonObject args) {
        return AnnotationMutations.createBookmark(program, args);
    }

    public static JsonElement deleteBookmark(Program program, JsonObject args) {
        return AnnotationMutations.deleteBookmark(program, args);
    }

    public static JsonElement createStructure(Program program, JsonObject args) {
        return CompositeMutations.createStructure(program, args);
    }

    public static JsonElement setStructureName(Program program, JsonObject args) {
        return CompositeMutations.setStructureName(program, args);
    }

    public static JsonElement deleteStructure(Program program, JsonObject args) {
        return CompositeMutations.deleteStructure(program, args);
    }

    public static JsonElement setStructureField(Program program, JsonObject args) {
        return CompositeMutations.setStructureField(program, args);
    }

    public static JsonElement deleteStructureField(Program program, JsonObject args) {
        return CompositeMutations.deleteStructureField(program, args);
    }

    public static JsonElement setStructureLayout(Program program, JsonObject args) {
        return CompositeMutations.setStructureLayout(program, args);
    }

    public static JsonElement createUnion(Program program, JsonObject args) {
        return CompositeMutations.createUnion(program, args);
    }

    public static JsonElement setUnionField(Program program, JsonObject args) {
        return CompositeMutations.setUnionField(program, args);
    }

    public static JsonElement setCompositeBitfield(Program program, JsonObject args) {
        return CompositeMutations.setCompositeBitfield(program, args);
    }

    public static JsonElement deleteCompositeField(Program program, JsonObject args) {
        return CompositeMutations.deleteCompositeField(program, args);
    }

    public static JsonElement setCompositeLayout(Program program, JsonObject args) {
        return CompositeMutations.setCompositeLayout(program, args);
    }

    public static JsonElement writeMemoryBytes(Program program, JsonObject args) {
        return CodeDataMutations.writeMemoryBytes(program, args);
    }

    // -----------------------------------------------------------------
    // save_program
    // -----------------------------------------------------------------

    public static JsonElement saveProgram(
            Program program, JsonObject args, PluginTool tool) {
        return ProgramPersistence.saveProgram(program, args, tool);
    }

    public static JsonElement setFunctionPrototype(Program program, JsonObject args) {
        return FunctionSignatureMutations.setFunctionPrototype(program, args);
    }

    public static JsonElement setFunctionCallingConvention(Program program, JsonObject args) {
        return FunctionSignatureMutations.setFunctionCallingConvention(program, args);
    }

    public static JsonElement setFunctionNoReturn(Program program, JsonObject args) {
        return FunctionSignatureMutations.setFunctionNoReturn(program, args);
    }

    public static JsonElement setInstructionFlowOverride(Program program, JsonObject args) {
        return ControlFlowMutations.setInstructionFlowOverride(program, args);
    }

    public static JsonElement setAddressLabel(Program program, JsonObject args) {
        return SymbolMutations.setAddressLabel(program, args);
    }

    public static JsonElement setDataLabel(Program program, JsonObject args) {
        return SymbolMutations.setDataLabel(program, args);
    }

    public static JsonElement applyDataType(Program program, JsonObject args) {
        return CodeDataMutations.applyDataType(program, args);
    }

    public static JsonElement setProgramImageBase(Program program, JsonObject args) {
        return MemoryBlockMutations.setProgramImageBase(program, args);
    }

    public static JsonElement setMemoryBlockPermissions(Program program, JsonObject args) {
        return MemoryBlockMutations.setMemoryBlockPermissions(program, args);
    }

    public static JsonElement createMemoryBlock(Program program, JsonObject args) {
        return MemoryBlockMutations.createMemoryBlock(program, args);
    }

    public static JsonElement deleteMemoryBlock(Program program, JsonObject args) {
        return MemoryBlockMutations.deleteMemoryBlock(program, args);
    }

    public static JsonElement createRecoveredCodeOverlay(Program program, JsonObject args) {
        return MemoryBlockMutations.createRecoveredCodeOverlay(program, args);
    }

    static JsonElement withTransaction(Program program, String description,
            MutationTransaction.TransactionAction action) {
        return MutationTransaction.withTransaction(program, description,
            action);
    }

    static JsonElement withTransaction(Program program, String description,
            MutationTransaction.TransactionAction action,
            java.util.function.Supplier<JsonElement> finalReadback) {
        return MutationTransaction.withTransaction(program, description,
            action, finalReadback);
    }

    // -----------------------------------------------------------------
    // Data type resolver
    // -----------------------------------------------------------------

    static DataType resolveDataType(Program program, String name) {
        return DataTypeResolver.resolveDataType(program, name);
    }

    // -----------------------------------------------------------------
    // Function signature parser
    // -----------------------------------------------------------------

    static ghidra.program.model.listing.FunctionSignature
            parseFunctionSignature(Program program, String prototype) {
        return FunctionSignatureMutations.parseFunctionSignature(program, prototype);
    }

    // -----------------------------------------------------------------
    // Register all mutation handlers
    // -----------------------------------------------------------------

    public static void registerAll(CommandDispatcher dispatcher) {
        dispatcher.register("set_function_name",
            MutationHandlers::setFunctionName);
        dispatcher.register("set_function_names",
            MutationHandlers::setFunctionNames);
        dispatcher.register("delete_function",
            MutationHandlers::deleteFunction);
        dispatcher.register("set_function_body",
            MutationHandlers::setFunctionBody);
        dispatcher.register("create_function",
            MutationHandlers::createFunction);
        dispatcher.register("create_stack_variable",
            MutationHandlers::createStackVariable);
        dispatcher.register("delete_stack_variable",
            MutationHandlers::deleteStackVariable);
        dispatcher.register("create_stack_variable_from_structure",
            MutationHandlers::createStackVariableFromStructure);
        dispatcher.register("create_functions",
            MutationHandlers::createFunctions);
        dispatcher.register("disassemble_memory",
            MutationHandlers::disassembleMemory);
        dispatcher.register("clear_code_units",
            MutationHandlers::clearCodeUnits);
        dispatcher.register("import_annotations",
            MutationHandlers::importAnnotations);
        dispatcher.register("set_variable_name",
            MutationHandlers::setVariableName);
        dispatcher.register("set_variable_type",
            MutationHandlers::setVariableType);
        dispatcher.register("set_variable_name_by_id",
            MutationHandlers::setVariableNameById);
        dispatcher.register("set_variable_type_by_id",
            MutationHandlers::setVariableTypeById);
        dispatcher.register("create_variable_by_id",
            MutationHandlers::createVariableById);
        dispatcher.register("delete_variable_by_id",
            MutationHandlers::deleteVariableById);
        dispatcher.register("set_function_return_type",
            MutationHandlers::setFunctionReturnType);
        dispatcher.register("apply_function_annotations",
            MutationHandlers::applyFunctionAnnotations);
        dispatcher.register("set_comment_at_address",
            MutationHandlers::setCommentAtAddress);
        dispatcher.register("create_bookmark",
            MutationHandlers::createBookmark);
        dispatcher.register("delete_bookmark",
            MutationHandlers::deleteBookmark);
        dispatcher.register("create_structure",
            MutationHandlers::createStructure);
        dispatcher.register("set_structure_name",
            MutationHandlers::setStructureName);
        dispatcher.register("delete_structure",
            MutationHandlers::deleteStructure);
        dispatcher.register("set_structure_field",
            MutationHandlers::setStructureField);
        dispatcher.register("delete_structure_field",
            MutationHandlers::deleteStructureField);
        dispatcher.register("set_structure_layout",
            MutationHandlers::setStructureLayout);
        dispatcher.register("create_union",
            MutationHandlers::createUnion);
        dispatcher.register("set_union_field",
            MutationHandlers::setUnionField);
        dispatcher.register("set_composite_bitfield",
            MutationHandlers::setCompositeBitfield);
        dispatcher.register("delete_composite_field",
            MutationHandlers::deleteCompositeField);
        dispatcher.register("set_composite_layout",
            MutationHandlers::setCompositeLayout);
        dispatcher.register("write_memory_bytes",
            MutationHandlers::writeMemoryBytes);
        dispatcher.register("set_function_prototype",
            MutationHandlers::setFunctionPrototype);
        dispatcher.register("set_function_calling_convention",
            MutationHandlers::setFunctionCallingConvention);
        dispatcher.register("set_function_noreturn",
            MutationHandlers::setFunctionNoReturn);
        dispatcher.register("set_instruction_flow_override",
            MutationHandlers::setInstructionFlowOverride);
        dispatcher.register("set_data_label",
            MutationHandlers::setDataLabel);
        dispatcher.register("set_address_label",
            MutationHandlers::setAddressLabel);
        dispatcher.register("apply_data_type",
            MutationHandlers::applyDataType);
        dispatcher.register("set_program_image_base",
            MutationHandlers::setProgramImageBase);
        dispatcher.register("set_memory_block_permissions",
            MutationHandlers::setMemoryBlockPermissions);
        dispatcher.register("create_memory_block",
            MutationHandlers::createMemoryBlock);
        dispatcher.register("delete_memory_block",
            MutationHandlers::deleteMemoryBlock);
        dispatcher.register("create_recovered_code_overlay",
            MutationHandlers::createRecoveredCodeOverlay);
    }
}
