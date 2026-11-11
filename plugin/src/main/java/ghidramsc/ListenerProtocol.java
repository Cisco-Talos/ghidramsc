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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/** Pure listener-level protocol separate from the public command registry. */
final class ListenerProtocol {

    static final String CONFIGURE_LISTENER = "configure_listener";
    static final String CAPACITY_ERROR_CODE = "client_capacity";

    private ListenerProtocol() {
    }

    /**
     * Handle the internal listener configuration command.
     *
     * @return a response for the internal command, or null for ordinary
     *         dispatcher requests
     */
    static JsonObject handleConfiguration(JsonObject request,
            ClientAdmission admission) {
        if (!isConfigurationRequest(request)) {
            return null;
        }

        Long id = requestId(request);
        if (id == null) {
            return error(0, "Request id must be an integer");
        }
        if (request.size() != 3 || !request.has("args")) {
            return error(id,
                "configure_listener requires only id, command, and args");
        }
        JsonElement argsElement = request.get("args");
        if (!argsElement.isJsonObject()) {
            return error(id, "args must be a JSON object");
        }
        JsonObject args = argsElement.getAsJsonObject();
        if (args.size() != 1 || !args.has("max_clients")) {
            return error(id,
                "configure_listener requires only max_clients");
        }

        JsonElement maxElement = args.get("max_clients");
        if (!maxElement.isJsonPrimitive()
                || !maxElement.getAsJsonPrimitive().isNumber()) {
            return error(id, "max_clients must be a positive integer");
        }

        final int requested;
        try {
            requested = maxElement.getAsBigDecimal().intValueExact();
        } catch (ArithmeticException | NumberFormatException e) {
            return error(id, "max_clients must be a positive integer");
        }
        if (requested < 1) {
            return error(id, "max_clients must be a positive integer");
        }

        JsonObject result = new JsonObject();
        result.addProperty("max_clients", admission.configure(requested));
        JsonObject response = new JsonObject();
        response.addProperty("id", id);
        response.add("result", result);
        return response;
    }

    static JsonObject capacityError(int maxClients) {
        JsonObject response = new JsonObject();
        response.addProperty("id", 0);
        response.addProperty("error",
            "GhidraMSC plugin client capacity reached (max_clients="
                + maxClients + ")");
        response.addProperty("error_code", CAPACITY_ERROR_CODE);
        response.addProperty("max_clients", maxClients);
        return response;
    }

    private static boolean isConfigurationRequest(JsonObject request) {
        return request.has("command")
            && request.get("command").isJsonPrimitive()
            && request.get("command").getAsJsonPrimitive().isString()
            && CONFIGURE_LISTENER.equals(
                request.get("command").getAsString());
    }

    private static Long requestId(JsonObject request) {
        if (!request.has("id") || !request.get("id").isJsonPrimitive()
                || !request.get("id").getAsJsonPrimitive().isNumber()) {
            return null;
        }
        try {
            return request.get("id").getAsBigDecimal().longValueExact();
        } catch (ArithmeticException | NumberFormatException e) {
            return null;
        }
    }

    private static JsonObject error(long id, String message) {
        JsonObject response = new JsonObject();
        response.addProperty("id", id);
        response.addProperty("error", message);
        return response;
    }
}
