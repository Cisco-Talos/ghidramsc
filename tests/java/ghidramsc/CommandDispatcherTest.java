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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.google.gson.JsonObject;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

import org.junit.jupiter.api.Test;

class CommandDispatcherTest {

    @Test
    void dispatchesPingAndPreservesNumericId() {
        CommandDispatcher dispatcher = new CommandDispatcher(new FakeContext());

        JsonObject response = dispatcher.dispatch(request(41, "ping"));

        assertEquals(41, response.get("id").getAsLong());
        assertEquals("pong", response.get("result").getAsString());
        assertFalse(response.has("error"));
    }

    @Test
    void rejectsMalformedRequestEnvelope() {
        FakeContext context = new FakeContext();
        CommandDispatcher dispatcher = new CommandDispatcher(context);

        JsonObject badId = request(1, "ping");
        badId.addProperty("id", "one");
        assertEquals("Request id must be a number",
            dispatcher.dispatch(badId).get("error").getAsString());

        JsonObject unknownField = request(3, "ping");
        unknownField.addProperty("extra", true);
        JsonObject unknownResponse = dispatcher.dispatch(unknownField);
        assertEquals(3, unknownResponse.get("id").getAsLong());
        assertEquals("Unknown request field: extra",
            unknownResponse.get("error").getAsString());

        JsonObject badArgs = request(4, "ping");
        badArgs.addProperty("args", "not-an-object");
        assertEquals("args must be a JSON object",
            dispatcher.dispatch(badArgs).get("error").getAsString());

        JsonObject badBinary = request(5, "ping");
        badBinary.addProperty("binary", 12);
        assertEquals("binary must be a string",
            dispatcher.dispatch(badBinary).get("error").getAsString());

        JsonObject missingCommand = new JsonObject();
        assertEquals("Command must be a non-empty string",
            dispatcher.dispatch(missingCommand).get("error").getAsString());

        JsonObject numericCommand = new JsonObject();
        numericCommand.addProperty("command", 7);
        assertEquals("Command must be a non-empty string",
            dispatcher.dispatch(numericCommand).get("error").getAsString());

        JsonObject emptyCommand = new JsonObject();
        emptyCommand.addProperty("command", "");
        assertEquals("Command must be a non-empty string",
            dispatcher.dispatch(emptyCommand).get("error").getAsString());
    }

    @Test
    void rejectsUnknownCommandBeforeProgramResolution() {
        FakeContext context = new FakeContext();
        CommandDispatcher dispatcher = new CommandDispatcher(context);
        JsonObject request = request(9, "not_registered");
        request.addProperty("binary", "named-program");

        JsonObject response = dispatcher.dispatch(request);

        assertEquals("Unknown command: not_registered",
            response.get("error").getAsString());
        assertNull(context.resolvedName);
    }

    @Test
    void rejectsLegacyToolNameBeforeProgramResolution() {
        FakeContext context = new FakeContext();
        CommandDispatcher dispatcher = new CommandDispatcher(context);
        JsonObject legacyRequest = request(10, "decompile");
        legacyRequest.addProperty("binary", "named-program");

        JsonObject response = dispatcher.dispatch(legacyRequest);

        assertEquals("Unknown command: decompile",
            response.get("error").getAsString());
        assertNull(context.resolvedName);
    }

    @Test
    void resolvesAnExplicitBinaryAndPassesItToTheRealDispatchPath() {
        FakeContext context = new FakeContext();
        Program named = program("named");
        context.programs.put("folder/named", named);
        CommandDispatcher dispatcher = new CommandDispatcher(context);
        AtomicReference<Program> seen = new AtomicReference<>();
        dispatcher.register("list_functions", (program, args) -> {
            seen.set(program);
            return CommandDispatcher.jsonPrimitive("handled");
        });
        JsonObject request = request(12, "list_functions");
        request.addProperty("binary", "folder/named");

        JsonObject response = dispatcher.dispatch(request);

        assertEquals("folder/named", context.resolvedName);
        assertSame(named, seen.get());
        assertEquals("handled", response.get("result").getAsString());
    }

    @Test
    void usesTheActiveProgramWhenBinaryIsOmitted() {
        FakeContext context = new FakeContext();
        context.active = program("active");
        CommandDispatcher dispatcher = new CommandDispatcher(context);
        AtomicReference<Program> seen = new AtomicReference<>();
        dispatcher.register("list_functions", (program, args) -> {
            seen.set(program);
            return CommandDispatcher.jsonPrimitive("active-result");
        });

        JsonObject response = dispatcher.dispatch(request(13, "list_functions"));

        assertSame(context.active, seen.get());
        assertEquals("active-result", response.get("result").getAsString());
    }

    @Test
    void reportsMissingNamedAndActiveProgramsWithoutCallingHandler() {
        FakeContext context = new FakeContext();
        CommandDispatcher dispatcher = new CommandDispatcher(context);
        AtomicBoolean called = new AtomicBoolean();
        dispatcher.register("list_functions", (program, args) -> {
            called.set(true);
            return CommandDispatcher.jsonPrimitive("unexpected");
        });

        JsonObject namedRequest = request(14, "list_functions");
        namedRequest.addProperty("binary", "missing");
        assertEquals("Program not found: missing",
            dispatcher.dispatch(namedRequest).get("error").getAsString());
        assertEquals("No program specified and no active program in the GUI.",
            dispatcher.dispatch(request(15, "list_functions"))
                .get("error").getAsString());
        assertFalse(called.get());
    }

    @Test
    void reportsProgramUpgradeBlockingWithOriginalRequestId() {
        FakeContext context = new FakeContext();
        context.resolutionFailure =
            new GhidraMSCPlugin.ProgramOpenBlockedException(
                "Program open blocked for 'legacy.bin': resolve the "
                    + "'Upgrade Program Data?' dialog");
        CommandDispatcher dispatcher = new CommandDispatcher(context);
        JsonObject request = request(17, "list_functions");
        request.addProperty("binary", "legacy.bin");

        JsonObject response = dispatcher.dispatch(request);

        assertEquals(17, response.get("id").getAsLong());
        assertTrue(response.get("error").getAsString()
            .contains("legacy.bin"));
        assertTrue(response.get("error").getAsString()
            .contains("Upgrade Program Data?"));
    }

    @Test
    void convertsHandlerExceptionsToErrorResponses() {
        FakeContext context = new FakeContext();
        context.active = program("active");
        CommandDispatcher dispatcher = new CommandDispatcher(context);
        dispatcher.register("list_functions", (program, args) -> {
            throw new IllegalStateException("handler failed");
        });

        JsonObject response = dispatcher.dispatch(request(16, "list_functions"));

        assertEquals(16, response.get("id").getAsLong());
        assertEquals("handler failed", response.get("error").getAsString());
        assertFalse(response.has("result"));
    }

    @Test
    void listsProgramsFromTheContextWithoutResolvingOne() {
        FakeContext context = new FakeContext();
        context.names = new String[] { "root.bin", "nested/tool.bin" };
        CommandDispatcher dispatcher = new CommandDispatcher(context);

        JsonObject response = dispatcher.dispatch(request(18, "list_programs"));

        assertEquals("root.bin", response.getAsJsonObject("result")
            .getAsJsonArray("programs").get(0).getAsString());
        assertEquals("nested/tool.bin", response.getAsJsonObject("result")
            .getAsJsonArray("programs").get(1).getAsString());
        assertNull(context.resolvedName);
    }

    @Test
    void saveValidationFailureUsesCanonicalPersistenceShape() {
        JsonObject result = MutationHandlers.saveProgram(
            program("named"), new JsonObject(), null).getAsJsonObject();

        assertEquals("save_program", result.get("operation").getAsString());
        assertEquals("validation_failed", result.get("status").getAsString());
        assertEquals("named", result.get("program").getAsString());
        assertTrue(result.has("old"));
        assertTrue(result.has("requested"));
        assertTrue(result.has("stored"));
        assertTrue(result.has("error"));
        assertFalse(result.has("transaction"));
        JsonObject save = result.getAsJsonObject("save");
        assertFalse(save.get("attempted").getAsBoolean());
        assertFalse(save.get("completed").getAsBoolean());
        assertFalse(save.get("succeeded").getAsBoolean());
    }

    private static JsonObject request(long id, String command) {
        JsonObject request = new JsonObject();
        request.addProperty("id", id);
        request.addProperty("command", command);
        return request;
    }

    private static Program program(String name) {
        return (Program) Proxy.newProxyInstance(
            Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, args) -> {
                if ("getName".equals(method.getName())) {
                    return name;
                }
                if ("toString".equals(method.getName())) {
                    return "Program[" + name + "]";
                }
                return defaultValue(method.getReturnType());
            });
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

    private static final class FakeContext implements CommandDispatcher.Context {
        private Program active;
        private String resolvedName;
        private String[] names = new String[0];
        private final Map<String, Program> programs = new HashMap<>();
        private int activeLookups;
        private int resolveCalls;
        private RuntimeException resolutionFailure;

        @Override
        public Program getActiveProgram() {
            activeLookups++;
            return active;
        }

        @Override
        public Program resolveProgram(String name) {
            resolveCalls++;
            resolvedName = name;
            if (resolutionFailure != null) {
                throw resolutionFailure;
            }
            return programs.get(name);
        }

        @Override
        public String[] listProgramNames() {
            return names;
        }

        @Override
        public ProgramLocation getCurrentLoc() {
            return null;
        }

        @Override
        public ProgramSelection getCurrentSel() {
            return null;
        }

        @Override
        public PluginTool getTool() {
            return null;
        }
    }
}
