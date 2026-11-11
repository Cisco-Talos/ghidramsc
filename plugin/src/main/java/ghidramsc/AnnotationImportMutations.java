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

import static ghidramsc.MutationArguments.requireJsonObject;
import static ghidramsc.MutationArguments.requireJsonString;
import static ghidramsc.MutationResult.batchResult;
import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.mutationStatus;
import static ghidramsc.MutationResult.validationFailure;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;

/** Import annotations through the domain mutation contracts. */
final class AnnotationImportMutations {
    private AnnotationImportMutations() { }

    // -----------------------------------------------------------------

    static JsonElement importAnnotations(
            Program program, JsonObject args) {
        JsonObject data;
        try {
            data = requireJsonObject(args, "json_data");
            validateAnnotationImport(data);
        } catch (Exception e) {
            return validationFailure("import_annotations", args,
                errorMessage(e));
        }

        JsonArray items = new JsonArray();
        int succeeded = 0;
        int unchanged = 0;
        int failed = 0;

        if (data.has("function_signatures")) {
            for (JsonElement element
                    : data.getAsJsonArray("function_signatures")) {
                JsonObject signature = element.getAsJsonObject();
                JsonObject itemArgs = new JsonObject();
                itemArgs.addProperty("addr_hex",
                    signature.get("addr").getAsString());
                itemArgs.addProperty("new_name",
                    signature.get("name").getAsString());
                JsonElement item = invokeImportItem(() ->
                    FunctionLifecycleMutations.setFunctionName(program, itemArgs), "function_signature",
                    signature);
                int[] counts = countMutationStatus(item);
                succeeded += counts[0];
                unchanged += counts[1];
                failed += counts[2];
                items.add(item);
            }
        }

        if (data.has("symbols")) {
            for (JsonElement element : data.getAsJsonArray("symbols")) {
                JsonObject symbol = element.getAsJsonObject();
                JsonElement item = invokeImportItem(() ->
                    SymbolMutations.importLabel(program,
                        symbol.get("addr").getAsString(),
                        symbol.get("name").getAsString()),
                    "symbol", symbol);
                int[] counts = countMutationStatus(item);
                succeeded += counts[0];
                unchanged += counts[1];
                failed += counts[2];
                items.add(item);
            }
        }

        if (data.has("comments")) {
            for (JsonElement element : data.getAsJsonArray("comments")) {
                JsonObject comment = element.getAsJsonObject();
                JsonObject itemArgs = new JsonObject();
                itemArgs.addProperty("addr_hex",
                    comment.get("addr").getAsString());
                itemArgs.addProperty("comment_type",
                    comment.get("type").getAsString());
                itemArgs.addProperty("comment",
                    comment.get("text").getAsString());
                JsonElement item = invokeImportItem(() ->
                    AnnotationMutations.setCommentAtAddress(program, itemArgs), "comment", comment);
                int[] counts = countMutationStatus(item);
                succeeded += counts[0];
                unchanged += counts[1];
                failed += counts[2];
                items.add(item);
            }
        }

        return batchResult("import_annotations", data, items,
            succeeded, unchanged, failed);
    }

    private static void validateAnnotationImport(JsonObject data) {
        validateImportEntries(data, "function_signatures",
            "addr", "name");
        validateImportEntries(data, "symbols", "addr", "name");
        validateImportEntries(data, "comments",
            "addr", "type", "text");
    }

    private static void validateImportEntries(JsonObject data,
            String key, String... fields) {
        if (!data.has(key)) {
            return;
        }
        if (!data.get(key).isJsonArray()) {
            throw new IllegalArgumentException(
                "Invalid JSON array field: " + key);
        }
        for (JsonElement element : data.getAsJsonArray(key)) {
            if (!element.isJsonObject()) {
                throw new IllegalArgumentException(
                    key + " entries must be objects");
            }
            JsonObject entry = element.getAsJsonObject();
            for (String field : fields) {
                requireJsonString(entry, field);
            }
        }
    }

    private static JsonElement invokeImportItem(
            java.util.function.Supplier<JsonElement> action,
            String kind, JsonObject source) {
        JsonElement item;
        try {
            item = action.get();
        } catch (Exception e) {
            item = validationFailure("import_" + kind, source,
                errorMessage(e));
        }
        if (item.isJsonObject()) {
            item.getAsJsonObject().addProperty("import_kind", kind);
            item.getAsJsonObject().add("source", source.deepCopy());
        }
        return item;
    }

    private static int[] countMutationStatus(JsonElement item) {
        String status = mutationStatus(item);
        if ("success".equals(status)) {
            return new int[] {1, 0, 0};
        }
        if ("no_change".equals(status)) {
            return new int[] {0, 1, 0};
        }
        return new int[] {0, 0, 1};
    }

}
