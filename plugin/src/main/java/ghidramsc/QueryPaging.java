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
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

/** Shared finite-page validation and exact end metadata. */
final class QueryPaging {
    private QueryPaging() { }

    static void validate(int offset, int limit, String label, int maximum) {
        if (offset < 0) {
            throw new IllegalArgumentException(
                label + " offset must be non-negative");
        }
        if (limit < 1 || limit > maximum) {
            throw new IllegalArgumentException(
                label + " limit must be 1.." + maximum);
        }
    }

    static JsonObject metadata(int offset, int limit, int returned,
            int total) {
        JsonObject out = new JsonObject();
        out.addProperty("offset", offset);
        out.addProperty("limit", limit);
        out.addProperty("returned", returned);
        out.addProperty("total", total);
        long next = (long) offset + returned;
        boolean hasMore = next < total;
        out.addProperty("has_more", hasMore);
        if (hasMore) {
            out.addProperty("next_offset", next);
        } else {
            out.add("next_offset", JsonNull.INSTANCE);
        }
        return out;
    }

    static JsonArray slice(JsonArray items, int offset, int limit) {
        JsonArray out = new JsonArray();
        int end = (int) Math.min((long) items.size(), (long) offset + limit);
        for (int index = offset; index < end; index++) {
            out.add(items.get(index));
        }
        return out;
    }
}
