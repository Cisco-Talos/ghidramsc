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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import ghidra.program.model.listing.Program;

import org.junit.jupiter.api.Test;

class MutationHandlersTransactionTest {

    @Test
    void explicitCommitEndsTransactionBeforeFinalReadback() {
        List<String> events = new ArrayList<>();
        Program program = recordingProgram(events);

        JsonObject result = MutationHandlers.withTransaction(
            program, "rename", transaction -> {
                events.add("action");
                transaction.commit();
                return structured("succeeded");
            }, () -> {
                events.add("readback");
                return new JsonPrimitive("stored-value");
            }).getAsJsonObject();

        assertEquals(List.of("start:rename", "action", "end:37:true",
            "readback"), events);
        assertEquals("stored-value", result.get("stored").getAsString());
        assertTrue(result.getAsJsonObject("transaction")
            .get("committed").getAsBoolean());
    }

    @Test
    void structuredFailureRollsBackBeforeFinalReadbackEvenIfCommitWasRequested() {
        List<String> events = new ArrayList<>();
        Program program = recordingProgram(events);

        JsonObject result = MutationHandlers.withTransaction(
            program, "failure", transaction -> {
                events.add("action");
                transaction.commit();
                return structured("validation_failed");
            }, () -> {
                events.add("readback");
                return new JsonPrimitive("unchanged");
            }).getAsJsonObject();

        assertEquals(List.of("start:failure", "action", "end:37:false",
            "readback"), events);
        assertFalse(result.getAsJsonObject("transaction")
            .get("committed").getAsBoolean());
        assertEquals("unchanged", result.get("stored").getAsString());
    }

    @Test
    void exceptionRollsBackAndSkipsFinalReadback() {
        List<String> events = new ArrayList<>();
        Program program = recordingProgram(events);

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> MutationHandlers.withTransaction(program, "explode",
                transaction -> {
                    events.add("action");
                    throw new IllegalStateException("boom");
                }, () -> {
                    events.add("readback");
                    return new JsonPrimitive("unexpected");
                }));

        assertEquals("boom", error.getMessage());
        assertEquals(List.of("start:explode", "action", "end:37:false"),
            events);
    }

    @Test
    void successfulResultWithoutCommitDecisionRollsBackAndFails() {
        List<String> events = new ArrayList<>();
        Program program = recordingProgram(events);

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> MutationHandlers.withTransaction(program, "undecided",
                transaction -> {
                    events.add("action");
                    return structured("succeeded");
                }));

        assertTrue(error.getMessage().contains("explicit commit decision"));
        assertEquals(List.of("start:undecided", "action", "end:37:false"),
            events);
    }

    private static JsonObject structured(String status) {
        JsonObject result = new JsonObject();
        result.addProperty("status", status);
        return result;
    }

    private static Program recordingProgram(List<String> events) {
        return (Program) Proxy.newProxyInstance(
            Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, args) -> {
                if ("startTransaction".equals(method.getName())) {
                    events.add("start:" + args[0]);
                    return 37;
                }
                if ("endTransaction".equals(method.getName())) {
                    events.add("end:" + args[0] + ":" + args[1]);
                    return defaultValue(method.getReturnType());
                }
                if ("toString".equals(method.getName())) {
                    return "RecordingProgram";
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
}
