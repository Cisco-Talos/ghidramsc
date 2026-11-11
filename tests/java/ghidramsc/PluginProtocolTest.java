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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicReference;

import com.google.gson.JsonObject;

import org.junit.jupiter.api.Test;

class PluginProtocolTest {

    @Test
    void parsesARequestObjectWithoutRewritingIt() {
        JsonObject request = PluginProtocol.parseRequest(
            "{\"id\":7,\"command\":\"ping\",\"args\":{}}");

        assertEquals(7, request.get("id").getAsInt());
        assertEquals("ping", request.get("command").getAsString());
        assertTrue(request.get("args").isJsonObject());
    }

    @Test
    void rejectsNonObjectJson() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> PluginProtocol.parseRequest("[1,2,3]"));

        assertEquals("Request must be a JSON object", error.getMessage());
    }

    @Test
    void malformedJsonBecomesAProtocolError() {
        JsonObject response = PluginProtocol.handleRequest("{",
            request -> {
                throw new AssertionError("dispatch must not run");
            });

        assertEquals(0, response.get("id").getAsLong());
        assertTrue(response.get("error").getAsString()
            .startsWith("Malformed request:"));
    }

    @Test
    void validJsonObjectIsPassedToDispatch() {
        AtomicReference<JsonObject> seen = new AtomicReference<>();
        JsonObject dispatched = new JsonObject();
        dispatched.addProperty("id", 19);

        JsonObject response = PluginProtocol.handleRequest(
            "{\"id\":19,\"command\":\"ping\"}", request -> {
                seen.set(request);
                return dispatched;
            });

        assertSame(dispatched, response);
        assertEquals("ping", seen.get().get("command").getAsString());
    }

    @Test
    void dispatchFailureBecomesAProtocolError() {
        JsonObject response = PluginProtocol.handleRequest(
            "{\"command\":\"ping\"}", request -> {
                throw new IllegalStateException("broken dispatcher");
        });

        assertEquals(0, response.get("id").getAsLong());
        assertTrue(response.has("error"));
        assertTrue(response.get("error").getAsString()
            .contains("broken dispatcher"));
    }
}
