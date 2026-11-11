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

import static ghidramsc.QuerySupport.isQueryError;
import static ghidramsc.QuerySupport.queryError;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/** Function-state read-back shared across mutation families. */
final class FunctionMutationReadback {
    private FunctionMutationReadback() { }

    static JsonObject queryFunctionState(
            Program program, String addrHex) {
        JsonObject queryArgs = new JsonObject();
        queryArgs.addProperty("addr_hex", addrHex);
        JsonElement info = queryFuncInfo(program, addrHex);
        JsonElement variables = QueryHandlers.listFunctionVariables(program, queryArgs);
        if (isQueryError(variables)) {
            throw new IllegalStateException(
                "list_function_variables read-back failed: " + queryError(variables));
        }
        JsonObject state = new JsonObject();
        state.add("info", info);
        state.add("variables", variables);
        return state;
    }

    static JsonElement queryFuncInfo(
            Program program, String addrHex) {
        JsonObject queryArgs = new JsonObject();
        queryArgs.addProperty("addr_hex", addrHex);
        JsonElement info = QueryHandlers.getFunctionInfo(program, queryArgs);
        if (isQueryError(info)) {
            throw new IllegalStateException(
                "get_function_info read-back failed: " + queryError(info));
        }
        return info;
    }

    static JsonObject queryFunctionAtState(
            Program program, String addrHex) {
        Address address = QuerySupport.toAddress(program, addrHex);
        Function function = QuerySupport.resolveFunction(program, address);
        if (function == null) {
            JsonObject state = new JsonObject();
            state.addProperty("exists", false);
            state.addProperty("address", address.toString());
            return state;
        }
        JsonObject state = queryFuncInfo(
            program, addrHex).getAsJsonObject();
        state.addProperty("exists", true);
        return state;
    }

}
