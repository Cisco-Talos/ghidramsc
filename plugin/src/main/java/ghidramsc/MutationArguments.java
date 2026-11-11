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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/** JSON structure validation shared by batch and function mutations. */
final class MutationArguments {
    private MutationArguments() { }

    static JsonArray requireJsonArray(
            JsonObject args, String key) {
        if (!args.has(key) || !args.get(key).isJsonArray()) {
            throw new IllegalArgumentException(
                "Missing or invalid JSON array argument: " + key);
        }
        return args.getAsJsonArray(key);
    }

    static JsonObject requireJsonObject(
            JsonObject args, String key) {
        if (!args.has(key) || !args.get(key).isJsonObject()) {
            throw new IllegalArgumentException(
                "Missing or invalid JSON object argument: " + key);
        }
        return args.getAsJsonObject(key);
    }

    static String requireJsonString(
            JsonObject object, String key) {
        if (!object.has(key) || !object.get(key).isJsonPrimitive()
                || !object.get(key).getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(
                "Missing or invalid JSON string field: " + key);
        }
        return object.get(key).getAsString();
    }

}
