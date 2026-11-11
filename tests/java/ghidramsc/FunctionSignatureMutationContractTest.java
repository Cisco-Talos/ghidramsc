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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.junit.jupiter.api.Test;

class FunctionSignatureMutationContractTest {

    @Test
    void inferredParametersBlockReturnTypeOnlyMutation() {
        JsonObject identities = identities(false);

        assertEquals(
            MutationHandlers.RETURN_TYPE_INFERRED_PARAMETER_ERROR,
            MutationHandlers.returnTypeParameterBlocker(identities));
    }

    @Test
    void databaseParametersProduceStableComparisonContract() {
        JsonObject identities = identities(true);

        assertNull(MutationHandlers.returnTypeParameterBlocker(identities));
        JsonArray contract =
            MutationHandlers.effectiveParameterContract(identities);
        assertEquals(1, contract.size());
        JsonObject parameter = contract.get(0).getAsJsonObject();
        assertEquals("thread", parameter.get("name").getAsString());
        assertEquals("r0:4", parameter.get("storage").getAsString());
        assertTrue(parameter.get("database_backed").getAsBoolean());
    }

    @Test
    void incompleteIdentityPageFailsClosedWithPrototypeInstruction() {
        JsonObject identities = identities(true);
        identities.getAsJsonObject("pagination")
            .addProperty("has_more", true);

        String error =
            MutationHandlers.returnTypeParameterBlocker(identities);

        assertTrue(error.contains("set_function_prototype"));
        assertTrue(error.contains("complete signature"));
    }

    private static JsonObject identities(boolean databaseBacked) {
        JsonObject parameter = new JsonObject();
        parameter.addProperty("name", "thread");
        parameter.addProperty("type", "CExecThread *");
        parameter.addProperty("size", 4);
        parameter.addProperty("storage", "r0:4");
        parameter.addProperty("is_param", true);
        parameter.addProperty("category_index", 0);
        parameter.addProperty("database_backed", databaseBacked);
        parameter.addProperty("backing", "parameter");
        if (databaseBacked) {
            parameter.addProperty("database_symbol_id", "42");
        }
        JsonArray params = new JsonArray();
        params.add(parameter);
        JsonObject pagination = new JsonObject();
        pagination.addProperty("has_more", false);
        JsonObject identities = new JsonObject();
        identities.add("pagination", pagination);
        identities.add("params", params);
        return identities;
    }
}
