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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/** Structured mutation results and transaction status shared by handlers. */
final class MutationResult {
    private MutationResult() { }

    static JsonObject successResult(String operation,
            JsonElement oldState, JsonElement requested,
            JsonElement stored) {
        JsonObject result = baseResult(operation, "success", requested);
        result.add("old", oldState.deepCopy());
        result.add("stored", stored.deepCopy());
        return result;
    }

    static JsonObject rolledBackResult(String operation,
            JsonElement oldState, JsonElement requested, String error) {
        JsonObject result = baseResult(
            operation, "rolled_back", requested);
        result.add("old", oldState.deepCopy());
        result.addProperty("error", error);
        return result;
    }

    static JsonObject validationFailure(String operation,
            JsonElement requested, String error) {
        JsonObject result = baseResult(
            operation, "validation_failed", requested);
        result.addProperty("error", error);
        addTransaction(result, null, false, false);
        return result;
    }

    static JsonObject capabilityFailure(String operation,
            JsonElement requested, String error) {
        JsonObject result = baseResult(operation, "unsupported", requested);
        result.addProperty("error", error);
        addTransaction(result, null, false, false);
        return result;
    }

    static JsonObject noChangeResult(String operation,
            JsonElement oldState, JsonElement requested,
            JsonElement stored) {
        JsonObject result = baseResult(
            operation, "no_change", requested);
        result.add("old", oldState.deepCopy());
        result.add("stored", stored.deepCopy());
        addTransaction(result, null, false, false);
        return result;
    }

    static JsonObject baseResult(String operation,
            String status, JsonElement requested) {
        JsonObject result = new JsonObject();
        result.addProperty("operation", operation);
        result.addProperty("status", status);
        result.add("requested", requested.deepCopy());
        return result;
    }

    static String mutationStatus(JsonElement result) {
        if (result != null && result.isJsonObject()
                && result.getAsJsonObject().has("status")) {
            return result.getAsJsonObject().get("status").getAsString();
        }
        if (isFailureResult(result)) {
            return "rolled_back";
        }
        return "success";
    }

    static JsonObject batchResult(String operation,
            JsonElement requested, JsonArray items, int succeeded,
            int unchanged, int failed) {
        String status;
        if (failed == 0) {
            status = succeeded == 0 ? "no_change" : "success";
        } else if (succeeded > 0 || unchanged > 0) {
            status = "partial_success";
        } else {
            status = "validation_failed";
        }
        JsonObject result = baseResult(operation, status, requested);
        result.addProperty("atomicity", "per_item");
        result.addProperty("succeeded", succeeded);
        result.addProperty("unchanged", unchanged);
        result.addProperty("failed", failed);
        result.addProperty("total", items.size());
        result.add("items", items);
        addTransaction(result, null, false, false);
        return result;
    }

    static void addTransaction(JsonObject result,
            String description, boolean started, boolean committed) {
        JsonObject transaction = new JsonObject();
        transaction.addProperty("started", started);
        transaction.addProperty("committed", committed);
        if (description != null) {
            transaction.addProperty("description", description);
        }
        result.add("transaction", transaction);
    }

    static String errorMessage(Exception error) {
        String message = error.getMessage();
        return message == null || message.isEmpty()
            ? error.getClass().getSimpleName() : message;
    }

    static String statusSuffix(String status) {
        return status == null || status.isEmpty()
            ? "" : ": " + status;
    }

    static boolean isFailureResult(JsonElement result) {
        if (result == null) {
            return false;
        }
        if (result.isJsonPrimitive()
                && result.getAsJsonPrimitive().isString()) {
            return result.getAsString().startsWith("ERROR:");
        }
        if (result.isJsonObject()
                && result.getAsJsonObject().has("status")) {
            String status = result.getAsJsonObject()
                .get("status").getAsString();
            return "validation_failed".equals(status)
                || "rolled_back".equals(status);
        }
        return false;
    }
}
