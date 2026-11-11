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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

/** Executable checks at the local helper and actual handler boundaries. */
class HandlerArgumentConsumptionTest {

    private static JsonObject identity(
            String varId, String name, boolean parameter, String type) {
        JsonObject entry = new JsonObject();
        entry.addProperty("var_id", varId);
        entry.addProperty("name", name);
        entry.addProperty("is_param", parameter);
        entry.addProperty("type", type);
        return entry;
    }

    @Test
    void queryHelperConsumesOnlyJsonStrings() {
        JsonObject args = new JsonObject();
        IllegalArgumentException missing = assertThrows(
            IllegalArgumentException.class,
            () -> QueryHandlers.requireString(args, "value"));
        assertEquals("Missing or invalid string argument: value",
            missing.getMessage());

        args.addProperty("value", "0x1000");
        assertEquals("0x1000", QueryHandlers.requireString(args, "value"));

        args.addProperty("value", 4096);
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> QueryHandlers.requireString(args, "value"));
        assertEquals("Missing or invalid string argument: value",
            error.getMessage());
    }

    @Test
    void queryHelperConsumesOnlyExactIntegers() {
        JsonObject args = new JsonObject();
        IllegalArgumentException missing = assertThrows(
            IllegalArgumentException.class,
            () -> QueryHandlers.requireInt(args, "value"));
        assertEquals("Missing integer argument: value", missing.getMessage());

        args.addProperty("value", 7);
        assertEquals(7, QueryHandlers.requireInt(args, "value"));

        args.addProperty("value", 7.5);
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> QueryHandlers.requireInt(args, "value"));
        assertEquals("Invalid integer argument: value", error.getMessage());
    }

    @Test
    void queryHelperConsumesOnlyJsonBooleans() {
        JsonObject args = new JsonObject();
        assertTrue(QueryHandlers.optBool(args, "value", true));

        args.addProperty("value", true);
        assertTrue(QueryHandlers.optBool(args, "value", false));

        args.addProperty("value", "true");
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> QueryHandlers.optBool(args, "value", false));
        assertEquals("Invalid boolean argument: value", error.getMessage());
    }

    @Test
    void functionVariableIdentityPagingIsBoundedAndFiltersBeforePaging() {
        List<JsonObject> entries = new ArrayList<>();
        entries.add(identity("high:1", "first", true, "int"));
        entries.add(identity("high:2", "second", false, "constant"));
        entries.add(identity("high:3", "third", false, "constant_ptr"));
        JsonArray ambiguities = new JsonArray();

        JsonObject page = QueryHandlers.pageVariableIdentities(
            entries, ambiguities, 1, 1, " CONSTANT ");

        assertEquals("CONSTANT", page.get("filter").getAsString());
        assertEquals(0, page.getAsJsonArray("params").size());
        assertEquals("high:3", page.getAsJsonArray("locals")
            .get(0).getAsJsonObject().get("var_id").getAsString());
        JsonObject pagination = page.getAsJsonObject("pagination");
        assertEquals(1, pagination.get("returned").getAsInt());
        assertEquals(2, pagination.get("total").getAsInt());
        assertEquals(3, pagination.get("total_unfiltered").getAsInt());
        assertEquals(false, pagination.get("has_more").getAsBoolean());
        assertTrue(pagination.get("next_offset").isJsonNull());
    }

    @Test
    void functionVariableIdentityHandlerRejectsInvalidBoundsBeforeGhidraUse() {
        JsonObject args = new JsonObject();
        args.addProperty("addr_hex", "0x1000");
        args.addProperty("offset", -1);
        IllegalArgumentException offsetError = assertThrows(
            IllegalArgumentException.class,
            () -> QueryHandlers.listFunctionVariableIdentities(null, args));
        assertEquals("offset must be a non-negative integer",
            offsetError.getMessage());

        args.addProperty("offset", 0);
        args.addProperty("limit", 501);
        IllegalArgumentException limitError = assertThrows(
            IllegalArgumentException.class,
            () -> QueryHandlers.listFunctionVariableIdentities(null, args));
        assertEquals("limit must be an integer between 1 and 500",
            limitError.getMessage());
    }

    @Test
    void decompileChunksPreserveCompleteTextAndBoundBatchEntries() {
        String output = "header\n" + "x".repeat(40000) + "\uD83D\uDE00";
        String first = QueryHandlers.decompilePage(output, 0, 16384);
        String second = QueryHandlers.decompilePage(output, 16384, 16384);
        String third = QueryHandlers.decompilePage(output, 32768, 16384);
        assertTrue(first.startsWith("// GHIDRAMSC OUTPUT CHUNK offset=0"));
        assertTrue(third.contains("next_offset=none"));
        String recovered = first.substring(first.indexOf('\n') + 1)
            + second.substring(second.indexOf('\n') + 1)
            + third.substring(third.indexOf('\n') + 1);
        assertEquals(output, recovered);

        String batch = QueryHandlers.batchDecompileEntry(output, 32768);
        assertTrue(batch.contains("BATCH TRUNCATED"));
        assertTrue(batch.length() < 8300);
        assertEquals("small", QueryHandlers.batchDecompileEntry("small", 32768));
    }

    @Test
    void batchDecompileRejectsExcessAddressesBeforeGhidraUse() {
        JsonArray addresses = new JsonArray();
        for (int i = 0; i < 17; i++) {
            addresses.add("0x1000");
        }
        JsonObject args = new JsonObject();
        args.add("addresses", addresses);
        JsonObject result = QueryHandlers.decompileFunctions(null, args)
            .getAsJsonObject();
        assertTrue(result.get("error").getAsString()
            .contains("1..16 addresses"));
    }

    @Test
    void batchRenameConsumesAnArrayAtTheActualHandlerBoundary() {
        JsonObject valid = new JsonObject();
        valid.add("json_data", new JsonArray());
        JsonObject accepted = MutationHandlers.setFunctionNames(null, valid)
            .getAsJsonObject();
        assertEquals("no_change", accepted.get("status").getAsString());
        assertTrue(accepted.get("items").isJsonArray());
        assertEquals(0, accepted.get("total").getAsInt());

        JsonObject invalid = new JsonObject();
        invalid.add("json_data", new JsonObject());
        JsonObject rejected = MutationHandlers.setFunctionNames(null, invalid)
            .getAsJsonObject();
        assertEquals("validation_failed",
            rejected.get("status").getAsString());
        assertEquals("Missing or invalid JSON array argument: json_data",
            rejected.get("error").getAsString());

        JsonObject missing = MutationHandlers.setFunctionNames(
            null, new JsonObject()).getAsJsonObject();
        assertEquals("Missing or invalid JSON array argument: json_data",
            missing.get("error").getAsString());
    }

    @Test
    void importAnnotationsConsumesAnObjectAtTheActualHandlerBoundary() {
        JsonObject valid = new JsonObject();
        valid.add("json_data", new JsonObject());
        JsonObject accepted = MutationHandlers.importAnnotations(null, valid)
            .getAsJsonObject();
        assertEquals("no_change", accepted.get("status").getAsString());
        assertTrue(accepted.get("requested").isJsonObject());

        JsonObject invalid = new JsonObject();
        invalid.add("json_data", new JsonArray());
        JsonObject rejected = MutationHandlers.importAnnotations(null, invalid)
            .getAsJsonObject();
        assertEquals("validation_failed",
            rejected.get("status").getAsString());
        assertEquals("Missing or invalid JSON object argument: json_data",
            rejected.get("error").getAsString());

        JsonObject missing = MutationHandlers.importAnnotations(
            null, new JsonObject()).getAsJsonObject();
        assertEquals("Missing or invalid JSON object argument: json_data",
            missing.get("error").getAsString());
    }

    @Test
    void driftProneMutationHandlersConsumeTheirPublicFieldNamesLocally() {
        JsonObject retype = new JsonObject();
        retype.addProperty("addr_hex", "0x1000");
        retype.addProperty("var_name", "local_8");
        retype.addProperty("new_type", "int");
        IllegalArgumentException retypeError = assertThrows(
            IllegalArgumentException.class,
            () -> MutationHandlers.setVariableType(null, retype));
        assertEquals("Missing or invalid string argument: type_name",
            retypeError.getMessage());

        JsonObject apply = new JsonObject();
        apply.addProperty("addr_hex", "0x1000");
        apply.addProperty("type_name", "int");
        apply.addProperty("clear_mode", 7);
        IllegalArgumentException applyError = assertThrows(
            IllegalArgumentException.class,
            () -> MutationHandlers.applyDataType(null, apply));
        assertEquals("Invalid string argument: clear_mode",
            applyError.getMessage());

        JsonObject create = new JsonObject();
        create.addProperty("name", "Packet");
        create.addProperty("size", 8);
        create.addProperty("category_path", 7);
        IllegalArgumentException createError = assertThrows(
            IllegalArgumentException.class,
            () -> MutationHandlers.createStructure(null, create));
        assertEquals("Invalid string argument: category_path",
            createError.getMessage());
    }
}
