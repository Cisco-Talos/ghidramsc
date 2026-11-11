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

import static ghidramsc.MutationTransaction.withTransaction;

import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.noChangeResult;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

import java.util.HexFormat;
import java.util.Set;

/** Native instruction flow override with byte and listing read-back. */
final class ControlFlowMutations {
    private ControlFlowMutations() { }

    private static JsonObject instructionFlowState(Program program,
            Instruction instruction) {
        Address address = instruction.getAddress();
        int length = instruction.getLength();
        byte[] bytes = new byte[length];
        try {
            for (int index = 0; index < length; index++) {
                bytes[index] = program.getMemory().getByte(address.add(index));
            }
        } catch (Exception error) {
            throw new IllegalStateException("Cannot read instruction bytes", error);
        }
        Address fallthrough = instruction.getFallThrough();
        JsonObject state = new JsonObject();
        state.addProperty("address", address.toString());
        state.addProperty("length", length);
        state.addProperty("bytes_hex", HexFormat.of().formatHex(bytes));
        state.addProperty("instruction", instruction.toString());
        state.addProperty("flow_override", instruction.getFlowOverride().toString());
        state.addProperty("flow_type", instruction.getFlowType().toString());
        if (fallthrough == null) {
            state.add("fallthrough", JsonNull.INSTANCE);
        } else {
            state.addProperty("fallthrough", fallthrough.toString());
        }
        return state;
    }

    static JsonElement setInstructionFlowOverride(Program program,
            JsonObject args) {
        final String op = "set_instruction_flow_override";
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String overrideName = QuerySupport.requireString(args, "flow_override");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("flow_override", overrideName);
        FlowOverride requestedOverride;
        try {
            requestedOverride = FlowOverride.valueOf(overrideName);
        } catch (IllegalArgumentException error) {
            return validationFailure(op, requested,
                "Invalid native flow_override: " + overrideName);
        }
        Address address;
        try {
            address = QuerySupport.toAddress(program, addrHex);
        } catch (Exception error) {
            return validationFailure(op, requested,
                "Invalid address: " + errorMessage(error));
        }
        Instruction instruction = program.getListing().getInstructionAt(address);
        if (instruction == null) {
            return validationFailure(op, requested,
                "No instruction starts at " + addrHex);
        }
        JsonObject old = instructionFlowState(program, instruction);
        if (old.get("flow_override").getAsString().equals(overrideName)) {
            return noChangeResult(op, old, requested, old.deepCopy());
        }
        return withTransaction(program, "Set instruction flow override", tx -> {
            try {
                instruction.setFlowOverride(requestedOverride);
                JsonObject stored = instructionFlowState(program, instruction);
                for (String key : new String[] {
                        "address", "length", "bytes_hex", "instruction" }) {
                    if (!stored.get(key).equals(old.get(key))) {
                        throw new IllegalStateException(
                            "Instruction listing or bytes changed: " + key);
                    }
                }
                if (!stored.get("flow_override").getAsString()
                        .equals(overrideName)) {
                    throw new IllegalStateException(
                        "Instruction flow override read-back mismatch");
                }
                tx.commit();
                return successResult(op, old, requested, stored);
            } catch (Exception error) {
                return rolledBackResult(op, old, requested,
                    errorMessage(error));
            }
        }, () -> instructionFlowState(program, instruction));
    }

}
