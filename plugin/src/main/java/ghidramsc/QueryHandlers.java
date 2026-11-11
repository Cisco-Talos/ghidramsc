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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;
import java.util.List;

/**
 * Stable dispatcher facade for read-only GhidraMSC queries.
 *
 * Each static method matches the signature expected by
 * {@link CommandDispatcher.CommandHandler}: (Program, JsonObject) -&gt; JsonElement.
 *
 * Output formats match the Python queries.py implementations as closely
 * as possible so the LLM sees identical results regardless of backend.
 */
public final class QueryHandlers {

    private QueryHandlers() { /* utility class */ }

    public static JsonElement listFunctions(Program program, JsonObject args) {
        return FunctionQueries.listFunctions(program, args);
    }

    public static JsonElement decompileFunction(Program program, JsonObject args) {
        return FunctionQueries.decompileFunction(program, args);
    }

    static String decompilePage(String output, int offset, int limit) {
        return FunctionQueries.decompilePage(output, offset, limit);
    }

    static String batchDecompileEntry(String output, int remaining) {
        return FunctionQueries.batchDecompileEntry(output, remaining);
    }

    public static JsonElement getFunctionInfo(Program program, JsonObject args) {
        return FunctionQueries.getFunctionInfo(program, args);
    }

    static JsonArray addressRanges(ghidra.program.model.address.AddressSetView addresses) {
        return FunctionQueries.addressRanges(addresses);
    }

    // -----------------------------------------------------------------
    // get_program_info
    // -----------------------------------------------------------------

    public static JsonElement getProgramInfo(Program program, JsonObject args) {
        return ProgramQueries.getProgramInfo(program, args);
    }

    public static JsonElement getProgramSaveState(
            Program program, JsonObject args) {
        return ProgramQueries.getProgramSaveState(program, args);
    }

    static JsonObject programPersistenceState(Program program) {
        return ProgramQueries.programPersistenceState(program);
    }

    public static JsonElement listReferencesToAddress(Program program, JsonObject args) {
        return MemoryQueries.listReferencesToAddress(program, args);
    }

    public static JsonElement listReferencesFromAddress(Program program, JsonObject args) {
        return MemoryQueries.listReferencesFromAddress(program, args);
    }

    public static JsonElement getListingAtAddress(Program program, JsonObject args) {
        return MemoryQueries.getListingAtAddress(program, args);
    }

    public static JsonElement listStrings(Program program, JsonObject args) {
        return MemoryQueries.listStrings(program, args);
    }

    public static JsonElement searchMemoryText(Program program, JsonObject args) {
        return MemoryQueries.searchMemoryText(program, args);
    }

    public static JsonElement searchMemoryBytes(Program program, JsonObject args) {
        return MemoryQueries.searchMemoryBytes(program, args);
    }

    public static JsonElement searchFunctionsByName(Program program, JsonObject args) {
        return FunctionQueries.searchFunctionsByName(program, args);
    }

    public static JsonElement decompileFunctions(Program program, JsonObject args) {
        return FunctionQueries.decompileFunctions(program, args);
    }

    public static JsonElement listFunctionVariables(Program program, JsonObject args) {
        return VariableQueries.listFunctionVariables(program, args);
    }

    public static JsonElement listFunctionVariableIdentities(Program program, JsonObject args) {
        return VariableQueries.listFunctionVariableIdentities(program, args);
    }

    static String highVariableId(HighSymbol symbol) {
        return VariableQueries.highVariableId(symbol);
    }

    static JsonObject highVariableState(HighSymbol symbol) {
        return VariableQueries.highVariableState(symbol);
    }

    static String highVariableCapabilityReason(HighSymbol symbol) {
        return VariableQueries.highVariableCapabilityReason(symbol);
    }

    static String mergeGroupId(Varnode varnode) {
        return VariableQueries.mergeGroupId(varnode);
    }

    static void validateIdentityPageArguments(int offset, int limit) {
        VariableQueries.validateIdentityPageArguments(offset, limit);
    }

    static JsonObject pageVariableIdentities(List<JsonObject> entries,
            JsonArray ambiguousNames, int offset, int limit, String filter) {
        return VariableQueries.pageVariableIdentities(entries,
            ambiguousNames, offset, limit, filter);
    }

    public static JsonElement exportAnnotations(Program program, JsonObject args) {
        return AnnotationQueries.exportAnnotations(program, args);
    }

    // -----------------------------------------------------------------
    // get_program_memory_map
    // -----------------------------------------------------------------

    public static JsonElement getProgramMemoryMap(Program program, JsonObject args) {
        return ProgramQueries.getProgramMemoryMap(program, args);
    }

    public static JsonElement listProgramImports(Program program, JsonObject args) {
        return ProgramQueries.listProgramImports(program, args);
    }

    public static JsonElement listProgramExports(Program program, JsonObject args) {
        return ProgramQueries.listProgramExports(program, args);
    }

    public static JsonElement listProgramNamespaces(Program program, JsonObject args) {
        return ProgramQueries.listProgramNamespaces(program, args);
    }

    public static JsonElement listProgramClasses(Program program, JsonObject args) {
        return ProgramQueries.listProgramClasses(program, args);
    }

    public static JsonElement listDataItems(Program program, JsonObject args) {
        return MemoryQueries.listDataItems(program, args);
    }

    // -----------------------------------------------------------------
    // list_memory_blocks
    // -----------------------------------------------------------------

    public static JsonElement listMemoryBlocks(Program program, JsonObject args) {
        return ProgramQueries.listMemoryBlocks(program, args);
    }

    public static JsonElement getCommentAtAddress(Program program, JsonObject args) {
        return AnnotationQueries.getCommentAtAddress(program, args);
    }

    public static JsonElement listBookmarks(Program program, JsonObject args) {
        return AnnotationQueries.listBookmarks(program, args);
    }

    public static JsonElement listStructures(Program program, JsonObject args) {
        return CompositeQueries.listStructures(program, args);
    }

    public static JsonElement getStructure(Program program, JsonObject args) {
        return CompositeQueries.getStructure(program, args);
    }

    public static JsonElement getComposite(Program program, JsonObject args) {
        return CompositeQueries.getComposite(program, args);
    }

    static JsonObject compositeState(Composite composite) {
        return CompositeQueries.compositeState(composite);
    }

    public static JsonElement getFunctionCallGraph(Program program, JsonObject args) {
        return FunctionQueries.getFunctionCallGraph(program, args);
    }

    public static JsonElement listFunctionBasicBlocks(Program program, JsonObject args) {
        return FunctionQueries.listFunctionBasicBlocks(program, args);
    }

    public static JsonElement getFunctionCallRelationships(Program program, JsonObject args) {
        return FunctionQueries.getFunctionCallRelationships(program, args);
    }

    public static JsonElement detectSecurityMitigations(Program program, JsonObject args) {
        return SecurityQueries.detectSecurityMitigations(program, args);
    }

    public static JsonElement findFormatStringVulns(Program program, JsonObject args) {
        return SecurityQueries.findFormatStringVulns(program, args);
    }

    public static JsonElement identifyUserInputSources(Program program, JsonObject args) {
        return SecurityQueries.identifyUserInputSources(program, args);
    }

    public static JsonElement identifyCryptoPatterns(Program program, JsonObject args) {
        return SecurityQueries.identifyCryptoPatterns(program, args);
    }

    public static JsonElement findObfuscatedStrings(Program program, JsonObject args) {
        return SecurityQueries.findObfuscatedStrings(program, args);
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    // Stable package-level entrypoints for existing handler callers.
    static Address toAddress(Program program, String hex) {
        return QuerySupport.toAddress(program, hex);
    }

    static Function resolveFunction(Program program, Address addr) {
        return QuerySupport.resolveFunction(program, addr);
    }

    static String requireString(JsonObject args, String key) {
        return QuerySupport.requireString(args, key);
    }

    static String optString(JsonObject args, String key, String def) {
        return QuerySupport.optString(args, key, def);
    }

    static int optInt(JsonObject args, String key, int def) {
        return QuerySupport.optInt(args, key, def);
    }

    static int requireInt(JsonObject args, String key) {
        return QuerySupport.requireInt(args, key);
    }

    static boolean optBool(JsonObject args, String key, boolean def) {
        return QuerySupport.optBool(args, key, def);
    }

    static int commentTypeId(String commentType) {
        return QuerySupport.commentTypeId(commentType);
    }

    static byte[] hexToBytes(String hex) {
        return QuerySupport.hexToBytes(hex);
    }

    public static JsonElement readMemoryBytes(Program program, JsonObject args) {
        return MemoryQueries.readMemoryBytes(program, args);
    }

    public static JsonElement getDataAtAddress(Program program, JsonObject args) {
        return MemoryQueries.getDataAtAddress(program, args);
    }

    static Data resolveDefinedData(Program program, Address address) {
        return MemoryQueries.resolveDefinedData(program, address);
    }

    static JsonObject dataState(Program program, Data data) {
        return MemoryQueries.dataState(program, data);
    }

    public static JsonElement getFunctionStackFrame(Program program, JsonObject args) {
        return FunctionQueries.getFunctionStackFrame(program, args);
    }

    static JsonObject stackFrameState(Function func) {
        return FunctionQueries.stackFrameState(func);
    }

    static JsonObject stackVariableState(ghidra.program.model.listing.StackFrame frame,
            Variable variable) {
        return FunctionQueries.stackVariableState(frame, variable);
    }

    public static JsonElement listEnums(Program program, JsonObject args) {
        return CompositeQueries.listEnums(program, args);
    }

    public static JsonElement getEnum(Program program, JsonObject args) {
        return CompositeQueries.getEnum(program, args);
    }

    /**
     * Register all query handlers with the dispatcher.
     */
    public static void registerAll(CommandDispatcher dispatcher) {
        dispatcher.register("list_functions",
            QueryHandlers::listFunctions);
        dispatcher.register("decompile_function",
            QueryHandlers::decompileFunction);
        dispatcher.register("get_function_info",
            QueryHandlers::getFunctionInfo);
        dispatcher.register("get_program_info",
            QueryHandlers::getProgramInfo);
        dispatcher.register("get_program_save_state",
            QueryHandlers::getProgramSaveState);
        dispatcher.register("list_references_to_address",
            QueryHandlers::listReferencesToAddress);
        dispatcher.register("list_references_from_address",
            QueryHandlers::listReferencesFromAddress);
        dispatcher.register("get_listing_at_address",
            QueryHandlers::getListingAtAddress);
        dispatcher.register("list_strings",
            QueryHandlers::listStrings);
        dispatcher.register("search_memory_text",
            QueryHandlers::searchMemoryText);
        dispatcher.register("search_memory_bytes",
            QueryHandlers::searchMemoryBytes);
        dispatcher.register("search_functions_by_name",
            QueryHandlers::searchFunctionsByName);
        dispatcher.register("decompile_functions",
            QueryHandlers::decompileFunctions);
        dispatcher.register("list_function_variables",
            QueryHandlers::listFunctionVariables);
        dispatcher.register("list_function_variable_identities",
            QueryHandlers::listFunctionVariableIdentities);
        dispatcher.register("export_annotations",
            QueryHandlers::exportAnnotations);
        dispatcher.register("get_program_memory_map",
            QueryHandlers::getProgramMemoryMap);
        dispatcher.register("list_program_imports",
            QueryHandlers::listProgramImports);
        dispatcher.register("list_program_exports",
            QueryHandlers::listProgramExports);
        dispatcher.register("list_program_namespaces",
            QueryHandlers::listProgramNamespaces);
        dispatcher.register("list_program_classes",
            QueryHandlers::listProgramClasses);
        dispatcher.register("list_data_items",
            QueryHandlers::listDataItems);
        dispatcher.register("list_memory_blocks",
            QueryHandlers::listMemoryBlocks);
        dispatcher.register("get_comment_at_address",
            QueryHandlers::getCommentAtAddress);
        dispatcher.register("list_bookmarks",
            QueryHandlers::listBookmarks);
        dispatcher.register("list_structures",
            QueryHandlers::listStructures);
        dispatcher.register("get_structure",
            QueryHandlers::getStructure);
        dispatcher.register("get_composite",
            QueryHandlers::getComposite);
        dispatcher.register("get_function_call_graph",
            QueryHandlers::getFunctionCallGraph);
        dispatcher.register("list_function_basic_blocks",
            QueryHandlers::listFunctionBasicBlocks);
        dispatcher.register("get_function_call_relationships",
            QueryHandlers::getFunctionCallRelationships);
        dispatcher.register("read_memory_bytes",
            QueryHandlers::readMemoryBytes);
        dispatcher.register("get_data_at_address",
            QueryHandlers::getDataAtAddress);
        dispatcher.register("get_function_stack_frame",
            QueryHandlers::getFunctionStackFrame);
        dispatcher.register("list_enums",
            QueryHandlers::listEnums);
        dispatcher.register("get_enum",
            QueryHandlers::getEnum);
    }
}
