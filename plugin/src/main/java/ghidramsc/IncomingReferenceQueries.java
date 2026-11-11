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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Conservative entry-only incoming-reference evidence for function info. */
final class IncomingReferenceQueries {
    private IncomingReferenceQueries() { }

    private static final String[] CATEGORIES = {
        "direct_call", "verified_thunk_or_tail_flow", "other", "ambiguous"
    };

    private static final class Site {
        final Reference ref;
        final Function sourceFunction;
        final String category;
        final String basis;

        Site(Reference ref, Function sourceFunction, String category,
                String basis) {
            this.ref = ref;
            this.sourceFunction = sourceFunction;
            this.category = category;
            this.basis = basis;
        }

        JsonObject toJson() {
            JsonObject out = new JsonObject();
            out.addProperty("from_address", ref.getFromAddress().toString());
            out.addProperty("to_address", ref.getToAddress().toString());
            out.addProperty("reference_kind", ref.getReferenceType().toString());
            out.addProperty("operand_index", ref.getOperandIndex());
            if (sourceFunction == null) {
                out.add("source_function", JsonNull.INSTANCE);
            } else {
                JsonObject source = new JsonObject();
                source.addProperty("name", sourceFunction.getName());
                source.addProperty("entry",
                    sourceFunction.getEntryPoint().toString());
                out.add("source_function", source);
            }
            out.addProperty("category", category);
            out.addProperty("classification_basis", basis);
            return out;
        }
    }

    static JsonObject incomingReferences(Program program, Function target,
            int offset, int limit) {
        Address entry = target.getEntryPoint();
        var iterator = program.getReferenceManager().getReferencesTo(entry);
        List<Reference> refs = new ArrayList<>();
        while (iterator.hasNext()) {
            refs.add(iterator.next());
        }
        refs.sort(Comparator
            .comparing((Reference ref) -> ref.getFromAddress().toString())
            .thenComparing(ref -> ref.getReferenceType().toString())
            .thenComparingInt(Reference::getOperandIndex));

        List<Site> sites = new ArrayList<>();
        for (Reference ref : refs) {
            Function source = program.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            RefType kind = ref.getReferenceType();
            String category = "other";
            String basis = "non_flow_reference";
            if (kind.isCall()) {
                if (kind.isComputed() || source == null) {
                    category = "ambiguous";
                    basis = "computed_or_unowned_call";
                } else {
                    category = "direct_call";
                    basis = "native_direct_call_reference";
                }
            } else if (kind.isJump()) {
                Function thunkTarget = source != null && source.isThunk()
                    ? source.getThunkedFunction(true) : null;
                if (!kind.isComputed() && thunkTarget != null
                        && thunkTarget.getEntryPoint().equals(entry)) {
                    category = "verified_thunk_or_tail_flow";
                    basis = "native_thunk_target";
                } else {
                    category = "ambiguous";
                    basis = "jump_without_tail_proof";
                }
            } else if (kind.isFlow()) {
                basis = "other_flow_reference";
            }
            sites.add(new Site(ref, source, category, basis));
        }

        JsonObject out = new JsonObject();
        out.addProperty("target_entry", entry.toString());
        out.addProperty("coverage", "ghidra_references_to_entry_only");
        out.addProperty("classification_coverage",
            "conservative_native_evidence");
        addCounts(out, sites);
        JsonObject categories = new JsonObject();
        for (String category : CATEGORIES) {
            List<Site> matches = new ArrayList<>();
            for (Site site : sites) {
                if (category.equals(site.category)) {
                    matches.add(site);
                }
            }
            JsonObject count = new JsonObject();
            addCounts(count, matches);
            categories.add(category, count);
        }
        out.add("category_counts", categories);

        JsonArray page = new JsonArray();
        int end = (int) Math.min((long) sites.size(), (long) offset + limit);
        for (int index = offset; index < end; index++) {
            page.add(sites.get(index).toJson());
        }
        out.add("sites", page);
        JsonObject pagination = new JsonObject();
        pagination.addProperty("offset", offset);
        pagination.addProperty("limit", limit);
        pagination.addProperty("returned", page.size());
        pagination.addProperty("total", sites.size());
        boolean hasMore = (long) offset + page.size() < sites.size();
        pagination.addProperty("has_more", hasMore);
        if (hasMore) {
            pagination.addProperty("next_offset", offset + page.size());
        } else {
            pagination.add("next_offset", JsonNull.INSTANCE);
        }
        out.add("pagination", pagination);
        return out;
    }

    private static void addCounts(JsonObject out, List<Site> sites) {
        Set<String> addresses = new HashSet<>();
        Set<String> functions = new HashSet<>();
        for (Site site : sites) {
            addresses.add(site.ref.getFromAddress().toString());
            if (site.sourceFunction != null) {
                functions.add(site.sourceFunction.getEntryPoint().toString());
            }
        }
        out.addProperty("reference_count", sites.size());
        out.addProperty("site_count", addresses.size());
        out.addProperty("distinct_source_function_count", functions.size());
    }
}
