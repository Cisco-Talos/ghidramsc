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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;

import com.google.gson.JsonPrimitive;
import com.google.gson.JsonObject;

import org.junit.jupiter.api.Test;

class ClientAdmissionTest {

    @Test
    void defaultLimitAdmitsTwelveAndReleaseFreesOneSlot() {
        ClientAdmission admission = new ClientAdmission();

        for (int i = 0; i < ClientAdmission.DEFAULT_MAX_CLIENTS; i++) {
            assertTrue(admission.tryAcquire().isAdmitted());
        }
        assertEquals(12, admission.getActiveClients());
        ClientAdmission.Decision rejected = admission.tryAcquire();
        assertFalse(rejected.isAdmitted());
        assertEquals(12, rejected.getMaxClients());

        admission.release();
        assertTrue(admission.tryAcquire().isAdmitted());
        assertEquals(12, admission.getActiveClients());
    }

    @Test
    void lastOverrideWinsAndLoweringDrainsWithoutEviction() {
        ClientAdmission admission = new ClientAdmission(4);
        assertTrue(admission.tryAcquire().isAdmitted());
        assertTrue(admission.tryAcquire().isAdmitted());
        assertTrue(admission.tryAcquire().isAdmitted());

        assertEquals(2, admission.configure(2));
        assertEquals(3, admission.getActiveClients());
        assertFalse(admission.tryAcquire().isAdmitted());

        admission.release();
        assertFalse(admission.tryAcquire().isAdmitted());
        admission.release();
        assertTrue(admission.tryAcquire().isAdmitted());

        assertEquals(5, admission.configure(5));
        assertTrue(admission.tryAcquire().isAdmitted());
    }

    @Test
    void deniedDecisionRetainsTheAtomicLimitSnapshot() {
        ClientAdmission admission = new ClientAdmission(1);
        assertTrue(admission.tryAcquire().isAdmitted());

        ClientAdmission.Decision denied = admission.tryAcquire();
        assertFalse(denied.isAdmitted());
        admission.configure(3);

        assertEquals(1, denied.getMaxClients());
        assertEquals(3, admission.getMaxClients());
    }

    @Test
    void rejectsInvalidLimitsAndUnbalancedRelease() {
        assertThrows(IllegalArgumentException.class,
            () -> new ClientAdmission(0));
        ClientAdmission admission = new ClientAdmission();
        assertThrows(IllegalArgumentException.class,
            () -> admission.configure(0));
        assertThrows(IllegalStateException.class, admission::release);
    }

    @Test
    void configurationEnvelopeAcknowledgesEffectiveGlobalLimit() {
        ClientAdmission admission = new ClientAdmission();
        JsonObject request = configurationRequest(41, 7);

        JsonObject response = ListenerProtocol.handleConfiguration(
            request, admission);

        assertEquals(41, response.get("id").getAsLong());
        assertEquals(7, response.getAsJsonObject("result")
            .get("max_clients").getAsInt());
        assertEquals(7, admission.getMaxClients());
    }

    @Test
    void configurationIsInternalAndRejectsInvalidLimit() {
        ClientAdmission admission = new ClientAdmission();
        JsonObject ordinary = new JsonObject();
        ordinary.addProperty("id", 1);
        ordinary.addProperty("command", "ping");
        assertNull(ListenerProtocol.handleConfiguration(ordinary, admission));

        JsonObject response = ListenerProtocol.handleConfiguration(
            configurationRequest(42, 0), admission);
        assertEquals(42, response.get("id").getAsLong());
        assertEquals("max_clients must be a positive integer",
            response.get("error").getAsString());
        assertEquals(12, admission.getMaxClients());
    }

    @Test
    void configurationRejectsWrongTypeFractionOverflowAndExtraField() {
        ClientAdmission admission = new ClientAdmission();

        JsonObject wrongType = configurationRequest(43, 2);
        wrongType.getAsJsonObject("args").addProperty("max_clients", "2");
        assertConfigurationError(wrongType, admission);

        JsonObject fractional = configurationRequest(44, 2);
        fractional.getAsJsonObject("args").addProperty("max_clients", 2.5);
        assertConfigurationError(fractional, admission);

        JsonObject overflow = configurationRequest(45, 2);
        overflow.getAsJsonObject("args").add("max_clients",
            new JsonPrimitive(new BigDecimal("2147483648")));
        assertConfigurationError(overflow, admission);

        JsonObject extraField = configurationRequest(46, 2);
        extraField.addProperty("binary", "sample.bin");
        assertConfigurationError(extraField, admission);

        assertEquals(12, admission.getMaxClients());
    }

    @Test
    void capacityEnvelopeIsStructuredAndListenerLevel() {
        JsonObject response = ListenerProtocol.capacityError(12);

        assertEquals(0, response.get("id").getAsLong());
        assertEquals("client_capacity",
            response.get("error_code").getAsString());
        assertEquals(12, response.get("max_clients").getAsInt());
        assertTrue(response.get("error").getAsString()
            .contains("capacity reached"));
        assertFalse(response.has("result"));
    }

    private static JsonObject configurationRequest(long id, int maxClients) {
        JsonObject args = new JsonObject();
        args.addProperty("max_clients", maxClients);
        JsonObject request = new JsonObject();
        request.addProperty("id", id);
        request.addProperty("command", "configure_listener");
        request.add("args", args);
        return request;
    }

    private static void assertConfigurationError(JsonObject request,
            ClientAdmission admission) {
        JsonObject response = ListenerProtocol.handleConfiguration(
            request, admission);
        assertTrue(response.has("error"));
        assertFalse(response.has("result"));
    }
}
