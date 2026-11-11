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

import java.util.function.Function;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Pure request parsing and protocol-error handling for the plugin wire. */
final class PluginProtocol {

    private PluginProtocol() {
    }

    static JsonObject parseRequest(String raw) {
        JsonElement parsed = JsonParser.parseString(raw);
        if (!parsed.isJsonObject()) {
            throw new IllegalArgumentException("Request must be a JSON object");
        }
        return parsed.getAsJsonObject();
    }

    static JsonObject handleRequest(String raw,
            Function<JsonObject, JsonObject> dispatch) {
        try {
            return dispatch.apply(parseRequest(raw));
        } catch (Exception error) {
            return protocolError("Malformed request: " + error.getMessage());
        }
    }

    static JsonObject protocolError(String message) {
        JsonObject response = new JsonObject();
        response.addProperty("id", 0);
        response.addProperty("error", message);
        return response;
    }
}
