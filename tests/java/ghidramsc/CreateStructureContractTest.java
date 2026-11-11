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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import org.junit.jupiter.api.Test;

class CreateStructureContractTest {

    @Test
    void createsAndReadsBackAnExactNonRootStructure() {
        Fixture fixture = new Fixture();

        JsonObject result = MutationHandlers.createStructure(
            fixture.program, args("Packet", 8, "/analysis/types"))
                .getAsJsonObject();

        assertEquals("success", result.get("status").getAsString());
        assertEquals("/analysis/types", result.getAsJsonObject("requested")
            .get("category_path").getAsString());
        assertEquals("/analysis/types", result.getAsJsonObject("stored")
            .get("path").getAsString());
        assertEquals(1, fixture.count("Packet", "/analysis/types"));
        assertTrue(fixture.lastCommit);
    }

    @Test
    void omittedCategoryPreservesRootDefault() {
        Fixture fixture = new Fixture();
        JsonObject args = new JsonObject();
        args.addProperty("name", "RootPacket");
        args.addProperty("size", 8);

        JsonObject result = MutationHandlers.createStructure(
            fixture.program, args).getAsJsonObject();

        assertEquals("success", result.get("status").getAsString());
        assertEquals("/", result.getAsJsonObject("requested")
            .get("category_path").getAsString());
        assertEquals("/", result.getAsJsonObject("stored")
            .get("path").getAsString());
        assertEquals(1, fixture.count("RootPacket", "/"));
    }

    @Test
    void sameNameInAnotherCategoryDoesNotBlockCreation() {
        Fixture fixture = new Fixture();
        fixture.add(new StructureDataType(
            new CategoryPath("/other"), "Packet", 8));

        JsonObject result = MutationHandlers.createStructure(
            fixture.program, args("Packet", 8, "/analysis/types"))
                .getAsJsonObject();

        assertEquals("success", result.get("status").getAsString());
        assertEquals(1, fixture.count("Packet", "/other"));
        assertEquals(1, fixture.count("Packet", "/analysis/types"));
    }

    @Test
    void exactPathCollisionIsRejectedBeforeTransaction() {
        Fixture fixture = new Fixture();
        fixture.add(new StructureDataType(
            new CategoryPath("/analysis/types"), "Packet", 8));

        JsonObject result = MutationHandlers.createStructure(
            fixture.program, args("Packet", 8, "/analysis/types"))
                .getAsJsonObject();

        assertEquals("validation_failed",
            result.get("status").getAsString());
        assertEquals(0, fixture.transactions);
        assertEquals(1, fixture.count("Packet", "/analysis/types"));
    }

    @Test
    void invalidPathIsRejectedWithoutMutation() {
        Fixture fixture = new Fixture();

        JsonObject result = MutationHandlers.createStructure(
            fixture.program, args("Packet", 8, "relative/path"))
                .getAsJsonObject();

        assertEquals("validation_failed",
            result.get("status").getAsString());
        assertTrue(result.get("error").getAsString()
            .contains("Invalid category path"));
        assertEquals(0, fixture.transactions);
        assertTrue(fixture.types.isEmpty());
    }

    @Test
    void storedIdentityMismatchRollsBackWithoutResidue() {
        Fixture fixture = new Fixture();
        fixture.mismatchOnAdd = true;

        JsonObject result = MutationHandlers.createStructure(
            fixture.program, args("Packet", 8, "/analysis/types"))
                .getAsJsonObject();

        assertEquals("rolled_back", result.get("status").getAsString());
        assertFalse(result.getAsJsonObject("transaction")
            .get("committed").getAsBoolean());
        assertEquals(0, fixture.count("Packet", "/analysis/types"));
        assertEquals(0, fixture.count("Packet", "/wrong"));
        assertFalse(fixture.lastCommit);
    }

    private static JsonObject args(
            String name, int size, String categoryPath) {
        JsonObject args = new JsonObject();
        args.addProperty("name", name);
        args.addProperty("size", size);
        args.addProperty("category_path", categoryPath);
        return args;
    }

    private static final class Fixture {
        private final List<DataType> types = new ArrayList<>();
        private final ProgramBasedDataTypeManager manager;
        private final Program program;
        private List<DataType> snapshot = List.of();
        private int transactions;
        private boolean lastCommit;
        private boolean mismatchOnAdd;

        private Fixture() {
            manager = (ProgramBasedDataTypeManager) Proxy.newProxyInstance(
                ProgramBasedDataTypeManager.class.getClassLoader(),
                new Class<?>[] { ProgramBasedDataTypeManager.class },
                (proxy, method, args) -> {
                    String methodName = method.getName();
                    if ("getDataType".equals(methodName)
                            && args != null && args.length == 2
                            && args[0] instanceof CategoryPath
                            && args[1] instanceof String) {
                        return find((String) args[1], args[0].toString());
                    }
                    if ("getAllDataTypes".equals(methodName)) {
                        return iterator();
                    }
                    if ("addDataType".equals(methodName)) {
                        DataType value = (DataType) args[0];
                        if (mismatchOnAdd) {
                            value = new StructureDataType(
                                new CategoryPath("/wrong"),
                                value.getName(), value.getLength());
                        }
                        types.add(value);
                        return value;
                    }
                    if ("toString".equals(methodName)) {
                        return "FixtureDataTypeManager";
                    }
                    return defaultValue(method.getReturnType());
                });
            program = (Program) Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] { Program.class },
                (proxy, method, args) -> {
                    String methodName = method.getName();
                    if ("getDataTypeManager".equals(methodName)) {
                        return manager;
                    }
                    if ("startTransaction".equals(methodName)) {
                        transactions++;
                        snapshot = new ArrayList<>(types);
                        return 37;
                    }
                    if ("endTransaction".equals(methodName)) {
                        lastCommit = (Boolean) args[1];
                        if (!lastCommit) {
                            types.clear();
                            types.addAll(snapshot);
                        }
                        return defaultValue(method.getReturnType());
                    }
                    if ("getName".equals(methodName)) {
                        return "fixture";
                    }
                    if ("toString".equals(methodName)) {
                        return "FixtureProgram";
                    }
                    return defaultValue(method.getReturnType());
                });
        }

        private void add(DataType value) {
            types.add(value);
        }

        private Iterator<DataType> iterator() {
            return new ArrayList<>(types).iterator();
        }

        private DataType find(String name, String path) {
            return types.stream()
                .filter(type -> name.equals(type.getName()))
                .filter(type -> path.equals(type.getCategoryPath().toString()))
                .findFirst().orElse(null);
        }

        private long count(String name, String path) {
            return types.stream()
                .filter(type -> name.equals(type.getName()))
                .filter(type -> path.equals(type.getCategoryPath().toString()))
                .count();
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
