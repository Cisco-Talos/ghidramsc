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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/** Shared validation and address resolution for query and mutation families. */
final class QuerySupport {
    private QuerySupport() { }

    static Address toAddress(Program program, String hex) {
        String cleaned = hex.trim();
        AddressFactory af = program.getAddressFactory();
        int separator = cleaned.indexOf("::");
        if (separator >= 0) {
            String name = cleaned.substring(0, separator);
            String offset = cleaned.substring(separator + 2);
            if (name.isEmpty() || offset.isEmpty() || offset.contains(":")) {
                throw new IllegalArgumentException("Invalid qualified address: " + hex);
            }
            if (offset.startsWith("0x") || offset.startsWith("0X")) {
                offset = offset.substring(2);
            }
            if (!offset.matches("[0-9a-fA-F]+")) {
                throw new IllegalArgumentException("Invalid qualified address: " + hex);
            }
            ghidra.program.model.address.AddressSpace space = af.getAddressSpace(name);
            if (space == null) {
                throw new IllegalArgumentException("Unknown address space: " + name);
            }
            Address address = space.getAddress(Long.parseUnsignedLong(offset, 16));
            if (address == null || !address.getAddressSpace().equals(space)) {
                throw new IllegalArgumentException("Address is outside space: " + hex);
            }
            return address;
        }
        if (cleaned.startsWith("0x") || cleaned.startsWith("0X")) {
            cleaned = cleaned.substring(2);
        }
        long val = Long.parseUnsignedLong(cleaned, 16);
        return af.getDefaultAddressSpace().getAddress(val);
    }

    static Function resolveFunction(Program program, Address addr) {
        Function func =
            program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager()
                .getFunctionContaining(addr);
        }
        return func;
    }

    static String requireString(JsonObject args, String key) {
        if (!args.has(key) || !args.get(key).isJsonPrimitive()
                || !args.get(key).getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(
                "Missing or invalid string argument: " + key);
        }
        return args.get(key).getAsString();
    }

    static String optString(JsonObject args, String key, String def) {
        if (!args.has(key)) {
            return def;
        }
        if (!args.get(key).isJsonPrimitive()
                || !args.get(key).getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(
                "Invalid string argument: " + key);
        }
        return args.get(key).getAsString();
    }

    static int optInt(JsonObject args, String key, int def) {
        if (!args.has(key)) {
            return def;
        }
        if (!args.get(key).isJsonPrimitive()
                || !args.get(key).getAsJsonPrimitive().isNumber()) {
            throw new IllegalArgumentException(
                "Invalid integer argument: " + key);
        }
        try {
            return args.get(key).getAsBigDecimal().intValueExact();
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(
                "Invalid integer argument: " + key, e);
        }
    }

    static int requireInt(JsonObject args, String key) {
        if (!args.has(key)) {
            throw new IllegalArgumentException(
                "Missing integer argument: " + key);
        }
        return optInt(args, key, 0);
    }

    static boolean optBool(JsonObject args, String key, boolean def) {
        if (!args.has(key)) {
            return def;
        }
        if (!args.get(key).isJsonPrimitive()
                || !args.get(key).getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(
                "Invalid boolean argument: " + key);
        }
        return args.get(key).getAsBoolean();
    }

    static int commentTypeId(String commentType) {
        switch (commentType.toLowerCase()) {
            case "plate":      return CodeUnit.PLATE_COMMENT;
            case "pre":        return CodeUnit.PRE_COMMENT;
            case "post":       return CodeUnit.POST_COMMENT;
            case "eol":        return CodeUnit.EOL_COMMENT;
            case "repeatable": return CodeUnit.REPEATABLE_COMMENT;
            default:           return -1;
        }
    }

    static byte[] hexToBytes(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) Integer.parseInt(
                hex.substring(i * 2, i * 2 + 2), 16);
        }
        return data;
    }

    static boolean isQueryError(JsonElement value) {
        return value != null
            && (value.isJsonObject()
                && value.getAsJsonObject().has("error")
                || value.isJsonPrimitive()
                && value.getAsJsonPrimitive().isString()
                && value.getAsString().startsWith("ERROR:"));
    }

    static String queryError(JsonElement value) {
        if (value.isJsonObject()) {
            return value.getAsJsonObject().get("error").getAsString();
        }
        return value.getAsString();
    }

}
