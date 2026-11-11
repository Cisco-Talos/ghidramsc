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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import org.junit.jupiter.api.Test;

class SetFunctionNameContractTest {

    private static final Set<String> CONTRACT_FIELDS = Set.of(
        "operation", "status", "requested", "old", "stored", "error");
    private static final Set<String> STATE_FIELDS = Set.of("address", "name");
    private static final Set<String> BATCH_FIELDS = Set.of(
        "operation", "status", "atomicity", "succeeded", "unchanged",
        "failed", "total", "items");
    private static final Set<String> BATCH_ITEM_FIELDS = Set.of(
        "address", "status", "requested_name", "old_name", "stored_name",
        "error");

    @Test
    void successfulRenameReturnsOnlyTheSharedMinimalContract() {
        Fixture fixture = new Fixture(true, "old_name");

        JsonObject result = MutationHandlers.setFunctionName(
            fixture.program, args("0x100", "new_name")).getAsJsonObject();

        assertContract(result, "success", "0x100", "new_name");
        assertState(result.getAsJsonObject("old"), fixture.entry, "old_name");
        assertState(result.getAsJsonObject("stored"), fixture.entry, "new_name");
        assertTrue(result.get("error").isJsonNull());
        assertEquals(1, fixture.transactions);
        assertTrue(fixture.lastCommit);
        assertEquals("new_name", fixture.name);
    }

    @Test
    void missingFunctionUsesTheSameShapeWithoutStartingATransaction() {
        Fixture fixture = new Fixture(false, null);

        JsonObject result = MutationHandlers.setFunctionName(
            fixture.program, args("0x100", "new_name")).getAsJsonObject();

        assertContract(result, "validation_failed", "0x100", "new_name");
        assertTrue(result.get("old").isJsonNull());
        assertTrue(result.get("stored").isJsonNull());
        assertEquals("No function at or containing 0x100",
            result.get("error").getAsString());
        assertEquals(0, fixture.transactions);
    }

    @Test
    void noChangeUsesTheSameShapeWithoutStartingATransaction() {
        Fixture fixture = new Fixture(true, "same_name");

        JsonObject result = MutationHandlers.setFunctionName(
            fixture.program, args("0x100", "same_name")).getAsJsonObject();

        assertContract(result, "no_change", "0x100", "same_name");
        assertState(result.getAsJsonObject("old"), fixture.entry, "same_name");
        assertState(result.getAsJsonObject("stored"), fixture.entry, "same_name");
        assertTrue(result.get("error").isJsonNull());
        assertEquals(0, fixture.transactions);
    }

    @Test
    void storedNameMismatchRollsBackAndReportsTheSameContract() {
        Fixture fixture = new Fixture(true, "old_name");
        fixture.ignoreRename = true;

        JsonObject result = MutationHandlers.setFunctionName(
            fixture.program, args("0x100", "new_name")).getAsJsonObject();

        assertContract(result, "rolled_back", "0x100", "new_name");
        assertState(result.getAsJsonObject("old"), fixture.entry, "old_name");
        assertState(result.getAsJsonObject("stored"), fixture.entry, "old_name");
        assertTrue(result.get("error").getAsString()
            .contains("read-back mismatch"));
        assertFalse(fixture.lastCommit);
        assertEquals("old_name", fixture.name);
    }

    @Test
    void pluginWirePreservesTheExplicitNullErrorField() {
        Fixture fixture = new Fixture(true, "old_name");
        JsonElement result = MutationHandlers.setFunctionName(
            fixture.program, args("0x100", "new_name"));
        JsonObject response = new JsonObject();
        response.addProperty("id", 7);
        response.add("result", result);

        JsonObject decoded = JsonParser.parseString(
            GhidraMSCPlugin.wireJson(response)).getAsJsonObject();
        JsonObject decodedResult = decoded.getAsJsonObject("result");

        assertEquals(CONTRACT_FIELDS, decodedResult.keySet());
        assertTrue(decodedResult.has("error"));
        assertTrue(decodedResult.get("error").isJsonNull());
    }

    @Test
    void setFunctionNamesReturnsCompactOrderedMixedResults() {
        Fixture fixture = new Fixture(true, "old_name");
        JsonArray pairs = JsonParser.parseString("["
            + "{\"addr\":\"0x100\",\"name\":\"new_name\"},"
            + "{\"addr\":\"not-an-address\",\"name\":\"invalid_name\"},"
            + "{\"addr\":\"0x100\",\"name\":\"new_name\"},"
            + "{\"addr\":\"0x200\",\"name\":\"missing_name\"}"
            + "]").getAsJsonArray();
        JsonObject batchArgs = new JsonObject();
        batchArgs.add("json_data", pairs);

        JsonObject result = MutationHandlers.setFunctionNames(
            fixture.program, batchArgs).getAsJsonObject();

        assertEquals(BATCH_FIELDS, result.keySet());
        assertEquals("set_function_names", result.get("operation").getAsString());
        assertEquals("partial_success", result.get("status").getAsString());
        assertEquals("per_item", result.get("atomicity").getAsString());
        assertEquals(1, result.get("succeeded").getAsInt());
        assertEquals(1, result.get("unchanged").getAsInt());
        assertEquals(2, result.get("failed").getAsInt());
        assertEquals(4, result.get("total").getAsInt());
        JsonArray items = result.getAsJsonArray("items");
        assertEquals(4, items.size());
        assertBatchItem(items.get(0).getAsJsonObject(), "0x100", "success",
            "new_name", "old_name", "new_name", null);
        JsonObject invalid = items.get(1).getAsJsonObject();
        assertBatchItem(invalid, "not-an-address", "validation_failed",
            "invalid_name", null, null, invalid.get("error").getAsString());
        assertFalse(invalid.get("error").getAsString().isEmpty());
        assertBatchItem(items.get(2).getAsJsonObject(), "0x100", "no_change",
            "new_name", "new_name", "new_name", null);
        assertBatchItem(items.get(3).getAsJsonObject(), "0x200",
            "validation_failed", "missing_name", null, null,
            "No function at or containing 0x200");
        assertEquals(1, fixture.transactions);
        assertTrue(fixture.lastCommit);
    }

    private static void assertContract(JsonObject result, String status,
            String address, String name) {
        assertEquals(CONTRACT_FIELDS, result.keySet());
        assertEquals("set_function_name", result.get("operation").getAsString());
        assertEquals(status, result.get("status").getAsString());
        JsonObject requested = result.getAsJsonObject("requested");
        assertEquals(STATE_FIELDS, requested.keySet());
        assertEquals(address, requested.get("address").getAsString());
        assertEquals(name, requested.get("name").getAsString());
        assertFalse(result.has("transaction"));
        assertFalse(result.has("signature"));
        assertFalse(result.has("callers"));
        assertFalse(result.has("callees"));
    }

    private static void assertState(JsonObject state, Address address,
            String name) {
        assertEquals(STATE_FIELDS, state.keySet());
        assertEquals(address.toString(), state.get("address").getAsString());
        assertEquals(name, state.get("name").getAsString());
    }

    private static void assertBatchItem(JsonObject item, String address,
            String status, String requestedName, String oldName,
            String storedName, String error) {
        assertEquals(BATCH_ITEM_FIELDS, item.keySet());
        assertEquals(address, item.get("address").getAsString());
        assertEquals(status, item.get("status").getAsString());
        assertEquals(requestedName, item.get("requested_name").getAsString());
        if (oldName == null) {
            assertTrue(item.get("old_name").isJsonNull());
        } else {
            assertEquals(oldName, item.get("old_name").getAsString());
        }
        if (storedName == null) {
            assertTrue(item.get("stored_name").isJsonNull());
        } else {
            assertEquals(storedName, item.get("stored_name").getAsString());
        }
        if (error == null) {
            assertTrue(item.get("error").isJsonNull());
        } else {
            assertEquals(error, item.get("error").getAsString());
        }
    }

    private static JsonObject args(String address, String name) {
        JsonObject args = new JsonObject();
        args.addProperty("addr_hex", address);
        args.addProperty("new_name", name);
        return args;
    }

    private static final class Fixture {
        private final Address entry;
        private final Function function;
        private final Program program;
        private boolean present;
        private String name;
        private String snapshot;
        private int transactions;
        private boolean lastCommit;
        private boolean ignoreRename;

        private Fixture(boolean present, String name) {
            this.present = present;
            this.name = name;
            AddressSpace space = new GenericAddressSpace(
                "ram", 32, 1, AddressSpace.TYPE_RAM);
            entry = space.getAddress(0x100);
            AddressFactory addressFactory = new DefaultAddressFactory(
                new AddressSpace[] { space }, space);
            function = (Function) Proxy.newProxyInstance(
                Function.class.getClassLoader(),
                new Class<?>[] { Function.class },
                (proxy, method, methodArgs) -> {
                    if ("getName".equals(method.getName())) {
                        return this.name;
                    }
                    if ("getEntryPoint".equals(method.getName())) {
                        return entry;
                    }
                    if ("setName".equals(method.getName())) {
                        if (!ignoreRename) {
                            this.name = (String) methodArgs[0];
                        }
                        return null;
                    }
                    if ("toString".equals(method.getName())) {
                        return "FixtureFunction";
                    }
                    return defaultValue(method.getReturnType());
                });
            FunctionManager manager = (FunctionManager) Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] { FunctionManager.class },
                (proxy, method, methodArgs) -> {
                    if (("getFunctionAt".equals(method.getName())
                            || "getFunctionContaining".equals(method.getName()))
                            && present && entry.equals(methodArgs[0])) {
                        return function;
                    }
                    if ("toString".equals(method.getName())) {
                        return "FixtureFunctionManager";
                    }
                    return defaultValue(method.getReturnType());
                });
            program = (Program) Proxy.newProxyInstance(
                Program.class.getClassLoader(), new Class<?>[] { Program.class },
                (proxy, method, methodArgs) -> {
                    if ("getAddressFactory".equals(method.getName())) {
                        return addressFactory;
                    }
                    if ("getFunctionManager".equals(method.getName())) {
                        return manager;
                    }
                    if ("startTransaction".equals(method.getName())) {
                        transactions++;
                        snapshot = this.name;
                        return 37;
                    }
                    if ("endTransaction".equals(method.getName())) {
                        lastCommit = (Boolean) methodArgs[1];
                        if (!lastCommit) {
                            this.name = snapshot;
                        }
                        return defaultValue(method.getReturnType());
                    }
                    if ("toString".equals(method.getName())) {
                        return "FixtureProgram";
                    }
                    return defaultValue(method.getReturnType());
                });
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return '\0';
        }
        return 0;
    }
}
