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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.util.Set;

/** Address and defined-data labels, including annotation imports. */
final class SymbolMutations {
    private SymbolMutations() { }

    // -----------------------------------------------------------------

    private static JsonObject describeAddressSymbol(Symbol symbol) {
        if (symbol == null) {
            return null;
        }
        JsonObject state = new JsonObject();
        state.addProperty("id", symbol.getID());
        state.addProperty("name", symbol.getName());
        state.addProperty("type", symbol.getSymbolType().toString());
        state.addProperty("namespace", symbol.getParentNamespace().toString());
        state.addProperty("source", symbol.getSource().toString());
        state.addProperty("address", symbol.getAddress().toString());
        return state;
    }

    private static JsonObject addressLabelState(Program program, Address address) {
        SymbolTable table = program.getSymbolTable();
        JsonObject state = new JsonObject();
        state.addProperty("address", address.toString());
        Symbol primary = table.getPrimarySymbol(address);
        state.add("primary", primary == null ? JsonNull.INSTANCE
            : describeAddressSymbol(primary));
        JsonArray symbols = new JsonArray();
        for (Symbol symbol : table.getSymbols(address)) {
            symbols.add(describeAddressSymbol(symbol));
        }
        state.add("symbols", symbols);
        return state;
    }

    static JsonElement setAddressLabel(Program program, JsonObject args) {
        final String op = "set_address_label";
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String newName = QuerySupport.requireString(args, "new_name");
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("primary_label", newName);
        Address address;
        try {
            address = QuerySupport.toAddress(program, addrHex);
            SymbolUtilities.validateName(newName);
        } catch (Exception error) {
            return validationFailure(op, requested,
                "Invalid address or label name: " + errorMessage(error));
        }
        if (!address.isMemoryAddress() || !program.getMemory().contains(address)) {
            return validationFailure(op, requested,
                "Address must be mapped program memory");
        }
        SymbolTable table = program.getSymbolTable();
        Symbol primary = table.getPrimarySymbol(address);
        if (primary != null && primary.getSymbolType() == SymbolType.FUNCTION) {
            return validationFailure(op, requested,
                "Address is a function entry; use set_function_name");
        }
        ghidra.program.model.symbol.Namespace namespace = primary != null
            ? primary.getParentNamespace() : program.getGlobalNamespace();
        JsonObject old = addressLabelState(program, address);
        if (primary != null && primary.getName().equals(newName)) {
            return noChangeResult(op, old, requested, old.deepCopy());
        }
        Symbol collision = table.getNamespaceSymbol(newName, namespace);
        if (collision == null) {
            collision = table.getClassSymbol(newName, namespace);
        }
        if (collision == null && namespace.equals(program.getGlobalNamespace())) {
            collision = table.getLibrarySymbol(newName);
        }
        if (collision != null) {
            return validationFailure(op, requested,
                "Requested label conflicts with an existing namespace, class, or library");
        }
        return withTransaction(program, "Set address label", tx -> {
            try {
                Symbol requestedSymbol = table.getSymbol(newName, address, namespace);
                if (requestedSymbol != null) {
                    if (!requestedSymbol.isPrimary() && !requestedSymbol.setPrimary()) {
                        throw new IllegalStateException(
                            "Could not promote requested label");
                    }
                    if (requestedSymbol.getSource() != SourceType.USER_DEFINED) {
                        requestedSymbol.setName(newName, SourceType.USER_DEFINED);
                    }
                } else if (primary != null) {
                    primary.setName(newName, SourceType.USER_DEFINED);
                } else {
                    Symbol created = table.createLabel(address, newName,
                        namespace, SourceType.USER_DEFINED);
                    if (!created.isPrimary() && !created.setPrimary()) {
                        throw new IllegalStateException(
                            "Could not make new label primary");
                    }
                }
                Symbol storedPrimary = table.getPrimarySymbol(address);
                if (storedPrimary == null || !storedPrimary.getAddress().equals(address)
                        || !storedPrimary.getName().equals(newName)
                        || !storedPrimary.getParentNamespace().equals(namespace)
                        || storedPrimary.getSource() != SourceType.USER_DEFINED
                        || storedPrimary.getSymbolType() != SymbolType.LABEL) {
                    throw new IllegalStateException(
                        "Primary address-label read-back mismatch");
                }
                JsonObject stored = addressLabelState(program, address);
                tx.commit();
                return successResult(op, old, requested, stored);
            } catch (Exception error) {
                return rolledBackResult(op, old, requested,
                    errorMessage(error));
            }
        }, () -> addressLabelState(program, address));
    }

    // -----------------------------------------------------------------
    // set_data_label
    // -----------------------------------------------------------------

    static JsonElement setDataLabel(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String newName = QuerySupport.requireString(args, "new_name");
        Address addr = QuerySupport.toAddress(program, addrHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("primary_label", newName);
        Data data = MemoryQueries.resolveDefinedData(program, addr);
        if (data == null) {
            return validationFailure("set_data_label", requested,
                "No defined data at " + addrHex);
        }
        Address dataAddress = data.getAddress();
        JsonObject oldState = MemoryQueries.dataState(program, data);
        if (oldState.has("label")
                && newName.equals(oldState.get("label").getAsString())) {
            return noChangeResult("set_data_label", oldState,
                requested, oldState.deepCopy());
        }

        Symbol primary = data.getPrimarySymbol();
        ghidra.program.model.symbol.Namespace namespace = primary != null
            ? primary.getParentNamespace() : program.getGlobalNamespace();
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol namespaceCollision = symbolTable.getNamespaceSymbol(
            newName, namespace);
        if (namespaceCollision == null) {
            namespaceCollision = symbolTable.getClassSymbol(
                newName, namespace);
        }
        if (namespaceCollision == null
                && namespace.equals(program.getGlobalNamespace())) {
            namespaceCollision = symbolTable.getLibrarySymbol(newName);
        }
        if (namespaceCollision != null) {
            return validationFailure("set_data_label", requested,
                "Requested primary label '" + newName
                + "' conflicts with existing "
                + namespaceCollision.getSymbolType() + " in namespace "
                + namespace);
        }

        return withTransaction(program, "Rename data", tx -> {
            try {
                Symbol requestedSymbol = symbolTable.getSymbol(
                    newName, dataAddress, namespace);
                if (requestedSymbol != null
                        && (primary == null
                            || requestedSymbol.getID() != primary.getID())) {
                    if (!requestedSymbol.setPrimary()) {
                        throw new IllegalStateException(
                            "Could not make existing label '" + newName
                            + "' primary at " + dataAddress);
                    }
                } else if (primary != null) {
                    primary.setName(newName, SourceType.USER_DEFINED);
                } else {
                    requestedSymbol = symbolTable.createLabel(
                        dataAddress, newName, namespace,
                        SourceType.USER_DEFINED);
                    if (!requestedSymbol.isPrimary()
                            && !requestedSymbol.setPrimary()) {
                        throw new IllegalStateException(
                            "Could not make new label '" + newName
                            + "' primary at " + dataAddress);
                    }
                }
                JsonObject stored = MemoryQueries.dataState(program, data);
                if (!stored.has("label")
                        || !newName.equals(
                            stored.get("label").getAsString())) {
                    throw new IllegalStateException(
                        "Primary-symbol read-back mismatch: requested "
                        + newName + ", stored "
                        + (stored.has("label")
                            ? stored.get("label").getAsString() : "<none>"));
                }
                tx.commit();
                return successResult("set_data_label", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_data_label", oldState,
                    requested, errorMessage(e));
            }
        }, () -> MemoryQueries.dataState(program, data));
    }

    static JsonElement importLabel(
            Program program, String addrHex, String name) {
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("name", name);
        Address address;
        try {
            address = QuerySupport.toAddress(program, addrHex);
        } catch (Exception e) {
            return validationFailure("import_symbol", requested,
                errorMessage(e));
        }
        JsonObject oldState = symbolState(program, address);
        if (hasLabel(oldState, name)) {
            return noChangeResult("import_symbol", oldState,
                requested, oldState.deepCopy());
        }
        return withTransaction(program, "Import symbol", tx -> {
            try {
                program.getSymbolTable().createLabel(
                    address, name, SourceType.USER_DEFINED);
                JsonObject stored = symbolState(program, address);
                if (!hasLabel(stored, name)) {
                    throw new IllegalStateException(
                        "Symbol read-back mismatch at " + addrHex);
                }
                tx.commit();
                return successResult("import_symbol", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("import_symbol", oldState,
                    requested, errorMessage(e));
            }
        }, () -> symbolState(program, address));
    }

    private static JsonObject symbolState(
            Program program, Address address) {
        JsonObject state = new JsonObject();
        state.addProperty("address", address.toString());
        JsonArray labels = new JsonArray();
        Symbol primary = program.getSymbolTable().getPrimarySymbol(address);
        for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
            JsonObject label = new JsonObject();
            label.addProperty("name", symbol.getName());
            label.addProperty("type", symbol.getSymbolType().toString());
            label.addProperty("primary", primary != null
                && primary.getID() == symbol.getID());
            labels.add(label);
        }
        state.add("labels", labels);
        return state;
    }

    private static boolean hasLabel(JsonObject state, String name) {
        for (JsonElement element : state.getAsJsonArray("labels")) {
            if (name.equals(element.getAsJsonObject()
                    .get("name").getAsString())) {
                return true;
            }
        }
        return false;
    }

}
