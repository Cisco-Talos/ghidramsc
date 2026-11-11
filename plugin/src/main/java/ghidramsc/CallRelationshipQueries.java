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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Native call-site evidence shared by function info, call graphs, and
 * call relationships. Public entrypoints remain in QueryHandlers.
 */
final class CallRelationshipQueries {
    private static final int MAX_CALL_SITES = 128;

    private CallRelationshipQueries() { }

    static final class CallEvidence {
        final JsonArray sites = new JsonArray();
        final JsonArray callees = new JsonArray();
        final JsonArray possible = new JsonArray();
        final JsonArray unresolved = new JsonArray();
        final Map<String, Function> targets = new LinkedHashMap<>();
        boolean scanComplete = true;

        boolean complete() {
            return scanComplete && possible.isEmpty() && unresolved.isEmpty();
        }
    }

    static CallEvidence callEvidence(Program program, Function function) {
        return callEvidence(program, function, MAX_CALL_SITES);
    }

    static CallEvidence callEvidence(Program program, Function function,
            int maxSites) {
        CallEvidence evidence = new CallEvidence();
        var manager = program.getFunctionManager();
        var symbols = program.getSymbolTable();
        var referenceManager = program.getReferenceManager();
        var instructions = program.getListing().getInstructions(function.getBody(), true);
        Map<String, String> classifications = new LinkedHashMap<>();
        Set<String> resolvedEntries = new HashSet<>();
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            var flow = instruction.getFlowType();
            if (!flow.isCall()) {
                continue;
            }
            if (maxSites > 0 && evidence.sites.size() >= maxSites) {
                evidence.scanComplete = false;
                break;
            }
            boolean computed = flow.toString().contains("COMPUTED");
            String classification = computed
                ? "unresolved_computed" : "unresolved_direct";
            Function target = null;
            String pointerAddress = null;
            Reference[] refs = instruction.getReferencesFrom();
            for (Reference ref : refs) {
                if (!ref.getReferenceType().isCall()) {
                    continue;
                }
                Function candidate = manager.getFunctionAt(ref.getToAddress());
                if (candidate != null) {
                    target = candidate;
                    classification = computed
                        ? "resolved_indirect" : "confirmed_direct";
                    break;
                }
            }
            if (target == null && computed) {
                for (Reference ref : refs) {
                    Address cell = ref.getToAddress();
                    Symbol symbol = symbols.getPrimarySymbol(cell);
                    if (!ref.getReferenceType().isRead() || symbol == null
                            || !symbol.getName().startsWith("PTR_")) {
                        continue;
                    }
                    Map<String, Function> candidates = new LinkedHashMap<>();
                    for (Reference dataRef : referenceManager.getReferencesFrom(cell)) {
                        Function candidate = manager.getFunctionAt(
                            dataRef.getToAddress());
                        if (candidate != null && candidate.isExternal()) {
                            candidates.put(candidate.getEntryPoint().toString(), candidate);
                        }
                    }
                    if (candidates.size() == 1) {
                        target = candidates.values().iterator().next();
                        classification = "resolved_indirect";
                        pointerAddress = cell.toString();
                        break;
                    }
                }
            }
            JsonObject site = new JsonObject();
            site.addProperty("address", instruction.getAddress().toString());
            site.addProperty("instruction", instruction.toString());
            site.addProperty("flow_type", flow.toString());
            site.addProperty("classification", classification);
            if (target != null) {
                Function effective = target.isThunk()
                    ? target.getThunkedFunction(true) : null;
                if (effective == null) {
                    effective = target;
                }
                JsonObject targetInfo = new JsonObject();
                targetInfo.addProperty("name", target.getName());
                targetInfo.addProperty("address", target.getEntryPoint().toString());
                targetInfo.addProperty("effective_entry",
                    effective.getEntryPoint().toString());
                targetInfo.addProperty("external", effective.isExternal());
                if (pointerAddress == null) {
                    targetInfo.add("via_pointer", com.google.gson.JsonNull.INSTANCE);
                } else {
                    targetInfo.addProperty("via_pointer", pointerAddress);
                }
                site.add("target", targetInfo);
                String entry = target.getEntryPoint().toString();
                evidence.targets.putIfAbsent(entry, target);
                classifications.putIfAbsent(entry, classification);
                resolvedEntries.add(entry);
                resolvedEntries.add(effective.getEntryPoint().toString());
            } else {
                evidence.unresolved.add(site);
            }
            evidence.sites.add(site);
        }
        for (Map.Entry<String, Function> item : evidence.targets.entrySet()) {
            Function target = item.getValue();
            JsonObject callee = new JsonObject();
            callee.addProperty("name", target.getName());
            callee.addProperty("address", item.getKey());
            callee.addProperty("classification", classifications.get(item.getKey()));
            evidence.callees.add(callee);
        }
        java.util.List<Function> known = new java.util.ArrayList<>(
            function.getCalledFunctions(TaskMonitor.DUMMY));
        known.sort(java.util.Comparator.comparing(
            item -> item.getEntryPoint().toString()));
        for (Function candidate : known) {
            if (!resolvedEntries.contains(candidate.getEntryPoint().toString())) {
                JsonObject possible = new JsonObject();
                possible.addProperty("name", candidate.getName());
                possible.addProperty("address", candidate.getEntryPoint().toString());
                possible.addProperty("classification", "possible_target");
                evidence.possible.add(possible);
            }
        }
        return evidence;
    }

    static JsonObject callGraph(Program program, Function function, int depth) {
        return walkCallGraph(program, function, depth, new HashSet<>());
    }

    private static JsonObject walkCallGraph(
            Program program, Function func, int depth, Set<String> visited) {
        String entry = func.getEntryPoint().toString();
        JsonObject node = new JsonObject();
        node.addProperty("name", func.getName());
        node.addProperty("address", entry);

        if (visited.contains(entry) || depth <= 0) {
            node.addProperty("callees", "...");
            node.addProperty("limit_reason",
                visited.contains(entry) ? "revisit" : "depth");
            node.addProperty("complete", false);
            return node;
        }
        visited.add(entry);

        CallEvidence evidence = callEvidence(program, func);
        JsonArray callees = new JsonArray();
        boolean childrenComplete = true;
        for (Function callee : evidence.targets.values()) {
            JsonObject child = walkCallGraph(program, callee, depth - 1, visited);
            childrenComplete &= child.get("complete").getAsBoolean();
            callees.add(child);
        }
        node.add("callees", callees);
        node.add("call_sites", evidence.sites);
        node.add("possible_callees", evidence.possible);
        node.add("unresolved_calls", evidence.unresolved);
        node.addProperty("scan_complete", evidence.scanComplete);
        node.addProperty("complete", evidence.complete() && childrenComplete);
        return node;
    }

    static JsonObject relationships(Program program, Function func) {
        JsonArray callerArr = new JsonArray();
        for (Function c
                : func.getCallingFunctions(TaskMonitor.DUMMY)) {
            JsonObject cobj = new JsonObject();
            cobj.addProperty("name", c.getName());
            cobj.addProperty("address",
                c.getEntryPoint().toString());
            callerArr.add(cobj);
        }

        CallEvidence evidence = callEvidence(program, func);
        JsonArray calleeArr = evidence.callees;

        JsonObject out = new JsonObject();
        out.addProperty("function", func.getName());
        out.addProperty("address",
            func.getEntryPoint().toString());
        out.add("callers", callerArr);
        out.add("callees", calleeArr);
        out.addProperty("num_callers", callerArr.size());
        out.addProperty("num_callees", calleeArr.size());
        out.add("call_sites", evidence.sites);
        out.add("possible_callees", evidence.possible);
        out.add("unresolved_calls", evidence.unresolved);
        out.addProperty("scan_complete", evidence.scanComplete);
        out.addProperty("complete", evidence.complete());
        out.addProperty("caller_coverage", "ghidra_known_only");
        return out;
    }
}
