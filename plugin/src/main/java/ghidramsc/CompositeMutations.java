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

import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.noChangeResult;
import static ghidramsc.MutationResult.rolledBackResult;
import static ghidramsc.MutationResult.successResult;
import static ghidramsc.MutationResult.validationFailure;
import static ghidramsc.MutationTransaction.withTransaction;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Iterator;
import java.util.Set;

/** Structure, union, field, bitfield, and layout mutations. */
final class CompositeMutations {
    private CompositeMutations() { }

    // -----------------------------------------------------------------
    // create_structure
    // -----------------------------------------------------------------

    static JsonElement createStructure(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        int size = QuerySupport.optInt(args, "size", 0);
        String categoryPath = QuerySupport.optString(
            args, "category_path", "/");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("size", size);
        requested.addProperty("category_path", categoryPath);
        if (size < 0) {
            return validationFailure("create_structure", requested,
                "Structure size cannot be negative");
        }
        CategoryPath path;
        try {
            path = new CategoryPath(categoryPath);
        } catch (Exception e) {
            return validationFailure("create_structure", requested,
                "Invalid category path: " + errorMessage(e));
        }
        var dtm = program.getDataTypeManager();
        if (dtm.getDataType(path, name) != null) {
            return validationFailure("create_structure", requested,
                "Data type already exists at " + categoryPath + "/" + name);
        }
        JsonObject oldState = queryStructureState(
            program, name, categoryPath);

        return withTransaction(program, "Create structure", tx -> {
            try {
                StructureDataType sdt = new StructureDataType(
                    path, name, size);
                DataType added = dtm.addDataType(sdt,
                    DataTypeConflictHandler.DEFAULT_HANDLER);
                if (!(added instanceof Structure)
                        || !name.equals(added.getName())
                        || !categoryPath.equals(
                            added.getCategoryPath().toString())
                        || added.getLength() != size) {
                    throw new IllegalStateException(
                        "Stored structure identity mismatch");
                }
                JsonObject stored = queryStructureState(
                    program, name, categoryPath);
                if (!stored.get("exists").getAsBoolean()
                        || !name.equals(stored.get("name").getAsString())
                        || !categoryPath.equals(
                            stored.get("path").getAsString())
                        || stored.get("size").getAsInt() != size) {
                    throw new IllegalStateException(
                        "Structure read-back mismatch for " + name);
                }
                tx.commit();
                return successResult("create_structure", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("create_structure", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryStructureState(program, name, categoryPath));
    }

    // -----------------------------------------------------------------
    // set_structure_name
    // -----------------------------------------------------------------

    static JsonElement setStructureName(
            Program program, JsonObject args) {
        String oldName = QuerySupport.requireString(args, "old_name");
        String newName = QuerySupport.requireString(
            args, "new_name");
        JsonObject requested = new JsonObject();
        requested.addProperty("old_name", oldName);
        requested.addProperty("new_name", newName);
        JsonObject oldState = queryStructureState(program, oldName);
        if (!oldState.get("exists").getAsBoolean()) {
            return validationFailure("set_structure_name", requested,
                "Structure '" + oldName + "' not found");
        }
        if (oldName.equals(newName)) {
            return noChangeResult("set_structure_name", oldState,
                requested, oldState.deepCopy());
        }
        if (queryStructureState(program, newName)
                .get("exists").getAsBoolean()) {
            return validationFailure("set_structure_name", requested,
                "Structure '" + newName + "' already exists");
        }
        DataType structure = findStructure(program, oldName);

        return withTransaction(program, "Rename structure", tx -> {
            try {
                structure.setName(newName);
                JsonObject stored = queryStructureState(program, newName);
                if (!stored.get("exists").getAsBoolean()
                        || queryStructureState(program, oldName)
                            .get("exists").getAsBoolean()) {
                    throw new IllegalStateException(
                        "Structure rename read-back mismatch");
                }
                tx.commit();
                return successResult("set_structure_name", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_structure_name", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryStructureState(program, oldName));
    }

    // -----------------------------------------------------------------
    // delete_structure
    // -----------------------------------------------------------------

    static JsonElement deleteStructure(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("exists", false);
        JsonObject oldState = queryStructureState(program, name);
        if (!oldState.get("exists").getAsBoolean()) {
            return validationFailure("delete_structure", requested,
                "Structure '" + name + "' not found");
        }
        DataType structure = findStructure(program, name);

        return withTransaction(program, "Delete structure", tx -> {
            try {
                program.getDataTypeManager().remove(
                    structure, TaskMonitor.DUMMY);
                JsonObject stored = queryStructureState(program, name);
                if (stored.get("exists").getAsBoolean()) {
                    throw new IllegalStateException(
                        "Structure remains after deletion: " + name);
                }
                tx.commit();
                return successResult("delete_structure", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("delete_structure", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryStructureState(program, name));
    }

    // -----------------------------------------------------------------
    // structure field and layout editing
    // -----------------------------------------------------------------

    static JsonElement setStructureField(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.requireString(args, "category_path");
        int offset = QuerySupport.requireInt(args, "offset");
        String fieldName = QuerySupport.requireString(args, "field_name");
        String typeName = QuerySupport.requireString(args, "type_name");
        String mode = QuerySupport.optString(args, "mode", "replace");
        int requestedLength = QuerySupport.optInt(args, "length", 0);
        String comment = QuerySupport.optString(args, "comment", "");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("offset", offset);
        requested.addProperty("field_name", fieldName);
        requested.addProperty("type_name", typeName);
        requested.addProperty("mode", mode);
        requested.addProperty("length", requestedLength);
        requested.addProperty("comment", comment);
        if (offset < 0) {
            return validationFailure("set_structure_field", requested,
                "Field offset cannot be negative");
        }
        if (!"replace".equals(mode) && !"insert".equals(mode)) {
            return validationFailure("set_structure_field", requested,
                "mode must be 'replace' or 'insert'");
        }
        Structure structure = findStructure(program, name, categoryPath);
        if (structure == null) {
            return validationFailure("set_structure_field", requested,
                "Structure '" + name + "' not found in " + categoryPath);
        }
        DataTypeComponent containing = structure.getComponentContaining(offset);
        if ("insert".equals(mode) && containing != null
                && !ghidra.program.model.data.Undefined.isUndefined(
                    containing.getDataType())
                && containing.getOffset() < offset) {
            return validationFailure("set_structure_field", requested,
                "Insertion offset " + offset + " overlaps field '"
                    + containing.getFieldName() + "' at ["
                    + containing.getOffset() + ", "
                    + (containing.getEndOffset() + 1) + ")");
        }
        DataType dataType = DataTypeResolver.resolveDataType(program, typeName);
        if (dataType == null) {
            return validationFailure("set_structure_field", requested,
                "Unknown type: " + typeName);
        }
        int length = requestedLength > 0 ? requestedLength : dataType.getLength();
        if (length <= 0) {
            return validationFailure("set_structure_field", requested,
                "A positive length is required for dynamic type " + typeName);
        }
        requested.addProperty("effective_length", length);
        JsonObject oldState = queryStructureState(program, name, categoryPath);
        return withTransaction(program, "Edit structure field", tx -> {
            try {
                DataTypeComponent component = "insert".equals(mode)
                    ? structure.insertAtOffset(offset, dataType, length,
                        fieldName, comment)
                    : structure.replaceAtOffset(offset, dataType, length,
                        fieldName, comment);
                JsonObject stored = queryStructureState(program, name, categoryPath);
                if (!stored.get("exists").getAsBoolean()
                        || component.getOffset() != offset
                        || !fieldName.equals(component.getFieldName())
                        || component.getLength() != length
                        || !dataType.isEquivalent(component.getDataType())) {
                    throw new IllegalStateException(
                        "Structure field read-back mismatch at offset " + offset);
                }
                tx.commit();
                return successResult("set_structure_field", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_structure_field", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryStructureState(program, name, categoryPath));
    }

    static JsonElement deleteStructureField(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.requireString(args, "category_path");
        int offset = QuerySupport.requireInt(args, "offset");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("offset", offset);
        Structure structure = findStructure(program, name, categoryPath);
        if (structure == null) {
            return validationFailure("delete_structure_field", requested,
                "Structure '" + name + "' not found in " + categoryPath);
        }
        DataTypeComponent component = structure.getComponentAt(offset);
        if (component == null || component.getOffset() != offset
                || ghidra.program.model.data.Undefined.isUndefined(
                    component.getDataType())) {
            return validationFailure("delete_structure_field", requested,
                "No defined field starts at offset " + offset);
        }
        JsonObject oldState = queryStructureState(program, name, categoryPath);
        int definedBefore = structure.getNumDefinedComponents();
        return withTransaction(program, "Delete structure field", tx -> {
            try {
                structure.deleteAtOffset(offset);
                // Later components can shift into this offset after deletion.
                if (structure.getNumDefinedComponents() != definedBefore - 1) {
                    throw new IllegalStateException(
                        "Structure defined-field count did not decrease");
                }
                JsonObject stored = queryStructureState(program, name, categoryPath);
                tx.commit();
                return successResult("delete_structure_field", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("delete_structure_field", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryStructureState(program, name, categoryPath));
    }

    static JsonElement setStructureLayout(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.requireString(args, "category_path");
        String packing = QuerySupport.requireString(args, "packing");
        int packingValue = QuerySupport.optInt(args, "packing_value", 0);
        String alignment = QuerySupport.requireString(args, "alignment");
        int alignmentValue = QuerySupport.optInt(args, "alignment_value", 0);
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("packing", packing);
        requested.addProperty("packing_value", packingValue);
        requested.addProperty("alignment", alignment);
        requested.addProperty("alignment_value", alignmentValue);
        if (!Set.of("disabled", "default", "explicit").contains(packing)) {
            return validationFailure("set_structure_layout", requested,
                "packing must be disabled, default, or explicit");
        }
        if (!Set.of("default", "machine", "explicit").contains(alignment)) {
            return validationFailure("set_structure_layout", requested,
                "alignment must be default, machine, or explicit");
        }
        if ("explicit".equals(packing) && packingValue <= 0) {
            return validationFailure("set_structure_layout", requested,
                "packing_value must be positive for explicit packing");
        }
        if ("explicit".equals(alignment) && alignmentValue <= 0) {
            return validationFailure("set_structure_layout", requested,
                "alignment_value must be positive for explicit alignment");
        }
        Structure structure = findStructure(program, name, categoryPath);
        if (structure == null) {
            return validationFailure("set_structure_layout", requested,
                "Structure '" + name + "' not found in " + categoryPath);
        }
        JsonObject oldState = queryStructureState(program, name, categoryPath);
        return withTransaction(program, "Set structure layout", tx -> {
            try {
                if ("disabled".equals(packing)) {
                    structure.setPackingEnabled(false);
                } else if ("default".equals(packing)) {
                    structure.setToDefaultPacking();
                } else {
                    structure.setExplicitPackingValue(packingValue);
                }
                if ("default".equals(alignment)) {
                    structure.setToDefaultAligned();
                } else if ("machine".equals(alignment)) {
                    structure.setToMachineAligned();
                } else {
                    structure.setExplicitMinimumAlignment(alignmentValue);
                }
                JsonObject stored = queryStructureState(program, name, categoryPath);
                boolean mismatch = !packing.equals(stored.get("packing").getAsString())
                    || !alignment.equals(stored.get("alignment_mode").getAsString())
                    || ("explicit".equals(packing)
                        && stored.get("packing_value").getAsInt() != packingValue)
                    || ("explicit".equals(alignment)
                        && stored.get("minimum_alignment").getAsInt()
                            != alignmentValue);
                if (mismatch) {
                    throw new IllegalStateException(
                        "Structure layout read-back mismatch");
                }
                tx.commit();
                return successResult("set_structure_layout", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_structure_layout", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryStructureState(program, name, categoryPath));
    }

    static JsonElement createUnion(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.optString(
            args, "category_path", "/");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        CategoryPath path;
        try {
            path = new CategoryPath(categoryPath);
        } catch (Exception e) {
            return validationFailure("create_union", requested,
                "Invalid category path: " + errorMessage(e));
        }
        DataType existing = program.getDataTypeManager()
            .getDataType(path, name);
        if (existing != null) {
            return validationFailure("create_union", requested,
                "Data type already exists at " + categoryPath + "/" + name);
        }
        JsonObject oldState = new JsonObject();
        oldState.addProperty("exists", false);
        return withTransaction(program, "Create union", tx -> {
            try {
                UnionDataType created = new UnionDataType(
                    path, name, program.getDataTypeManager());
                DataType storedType = program.getDataTypeManager().addDataType(
                    created, DataTypeConflictHandler.DEFAULT_HANDLER);
                if (!(storedType instanceof Union)) {
                    throw new IllegalStateException(
                        "Created data type is not a union");
                }
                JsonObject stored = queryCompositeState(
                    program, name, categoryPath);
                if (!stored.get("exists").getAsBoolean()
                        || !"union".equals(
                            stored.get("kind").getAsString())) {
                    throw new IllegalStateException(
                        "Union read-back mismatch");
                }
                tx.commit();
                return successResult("create_union", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("create_union", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryCompositeState(program, name, categoryPath));
    }

    static JsonElement setUnionField(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.requireString(args, "category_path");
        int ordinal = QuerySupport.requireInt(args, "ordinal");
        String fieldName = QuerySupport.requireString(args, "field_name");
        String typeName = QuerySupport.requireString(args, "type_name");
        String mode = QuerySupport.optString(args, "mode", "replace");
        int requestedLength = QuerySupport.optInt(args, "length", 0);
        String comment = QuerySupport.optString(args, "comment", "");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("ordinal", ordinal);
        requested.addProperty("field_name", fieldName);
        requested.addProperty("type_name", typeName);
        requested.addProperty("mode", mode);
        requested.addProperty("length", requestedLength);
        requested.addProperty("comment", comment);
        if (!Set.of("insert", "replace").contains(mode)) {
            return validationFailure("set_union_field", requested,
                "mode must be insert or replace");
        }
        Composite composite = findComposite(
            program, name, categoryPath);
        if (!(composite instanceof Union)) {
            return validationFailure("set_union_field", requested,
                "Union '" + name + "' not found in " + categoryPath);
        }
        Union union = (Union) composite;
        int count = union.getNumComponents();
        if (ordinal < 0 || ordinal > count
                || ("replace".equals(mode) && ordinal == count)) {
            return validationFailure("set_union_field", requested,
                "ordinal is outside the union component range");
        }
        DataType dataType = DataTypeResolver.resolveDataType(program, typeName);
        if (dataType == null) {
            return validationFailure("set_union_field", requested,
                "Unknown type: " + typeName);
        }
        int length = requestedLength > 0
            ? requestedLength : dataType.getLength();
        if (length <= 0) {
            return validationFailure("set_union_field", requested,
                "A positive length is required for dynamic type " + typeName);
        }
        requested.addProperty("effective_length", length);
        JsonObject oldState = queryCompositeState(
            program, name, categoryPath);
        return withTransaction(program, "Edit union field", tx -> {
            try {
                if ("replace".equals(mode)) {
                    union.delete(ordinal);
                }
                DataTypeComponent component = union.insert(
                    ordinal, dataType, length, fieldName, comment);
                if (component.getOrdinal() != ordinal
                        || !fieldName.equals(component.getFieldName())
                        || component.getLength() != length
                        || !dataType.isEquivalent(component.getDataType())) {
                    throw new IllegalStateException(
                        "Union field read-back mismatch at ordinal " + ordinal);
                }
                JsonObject stored = queryCompositeState(
                    program, name, categoryPath);
                tx.commit();
                return successResult("set_union_field", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_union_field", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryCompositeState(program, name, categoryPath));
    }

    static JsonElement setCompositeBitfield(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.requireString(args, "category_path");
        int ordinal = QuerySupport.requireInt(args, "ordinal");
        String fieldName = QuerySupport.requireString(args, "field_name");
        String typeName = QuerySupport.requireString(args, "type_name");
        int bitSize = QuerySupport.requireInt(args, "bit_size");
        String mode = QuerySupport.optString(args, "mode", "insert");
        int byteOffset = QuerySupport.optInt(args, "byte_offset", 0);
        int storageSize = QuerySupport.optInt(args, "storage_size", 0);
        int bitOffset = QuerySupport.optInt(args, "bit_offset", 0);
        String comment = "";
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("ordinal", ordinal);
        requested.addProperty("field_name", fieldName);
        requested.addProperty("type_name", typeName);
        requested.addProperty("bit_size", bitSize);
        requested.addProperty("mode", mode);
        requested.addProperty("byte_offset", byteOffset);
        requested.addProperty("storage_size", storageSize);
        requested.addProperty("bit_offset", bitOffset);
        if (!Set.of("insert", "replace").contains(mode)) {
            return validationFailure("set_composite_bitfield", requested,
                "mode must be insert or replace");
        }
        if (bitSize < 0) {
            return validationFailure("set_composite_bitfield", requested,
                "bit_size cannot be negative");
        }
        Composite composite = findComposite(program, name, categoryPath);
        if (composite == null) {
            return validationFailure("set_composite_bitfield", requested,
                "Composite '" + name + "' not found in " + categoryPath);
        }
        DataType baseType = DataTypeResolver.resolveDataType(program, typeName);
        if (baseType == null || !BitFieldDataType.isValidBaseDataType(baseType)) {
            return validationFailure("set_composite_bitfield", requested,
                "Invalid bitfield base type: " + typeName);
        }
        int count = composite.getNumComponents();
        if (ordinal < 0 || ordinal > count
                || ("replace".equals(mode) && ordinal == count)) {
            return validationFailure("set_composite_bitfield", requested,
                "ordinal is outside the composite component range");
        }
        if (composite instanceof Structure
                && (byteOffset < 0 || storageSize <= 0 || bitOffset < 0)) {
            return validationFailure("set_composite_bitfield", requested,
                "Structure bitfields require non-negative byte/bit offsets "
                + "and a positive storage_size");
        }
        if ("replace".equals(mode)) {
            DataTypeComponent existing = composite.getComponent(ordinal);
            if (!existing.isBitFieldComponent()) {
                return validationFailure("set_composite_bitfield", requested,
                    "replace requires an existing bitfield at ordinal "
                    + ordinal);
            }
        }
        JsonObject oldState = queryCompositeState(
            program, name, categoryPath);
        return withTransaction(program, "Edit composite bitfield", tx -> {
            try {
                if ("replace".equals(mode)) {
                    if (composite instanceof Structure) {
                        ((Structure) composite).clearComponent(ordinal);
                    } else {
                        composite.delete(ordinal);
                    }
                }
                DataTypeComponent component;
                if (composite instanceof Union) {
                    component = ((Union) composite).insertBitField(
                        ordinal, baseType, bitSize, fieldName, comment);
                } else if (composite instanceof Structure) {
                    component = ((Structure) composite).insertBitFieldAt(
                        byteOffset, storageSize, bitOffset, baseType,
                        bitSize, fieldName, comment);
                } else {
                    throw new IllegalStateException(
                        "Unsupported composite implementation");
                }
                if (!component.isBitFieldComponent()
                        || !fieldName.equals(component.getFieldName())
                        || !(component.getDataType()
                            instanceof BitFieldDataType)) {
                    throw new IllegalStateException(
                        "Composite bitfield read-back mismatch");
                }
                BitFieldDataType storedBitField =
                    (BitFieldDataType) component.getDataType();
                if (!baseType.isEquivalent(storedBitField.getBaseDataType())
                        || storedBitField.getDeclaredBitSize() != bitSize
                        || (composite instanceof Structure
                            && (component.getOffset() != byteOffset
                                || storedBitField.getBitOffset()
                                    != bitOffset))) {
                    throw new IllegalStateException(
                        "Composite bitfield metadata read-back mismatch");
                }
                JsonObject stored = queryCompositeState(
                    program, name, categoryPath);
                tx.commit();
                return successResult("set_composite_bitfield", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_composite_bitfield", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryCompositeState(program, name, categoryPath));
    }

    static JsonElement deleteCompositeField(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.requireString(args, "category_path");
        int ordinal = QuerySupport.requireInt(args, "ordinal");
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("ordinal", ordinal);
        Composite composite = findComposite(program, name, categoryPath);
        if (composite == null || ordinal < 0
                || ordinal >= composite.getNumComponents()) {
            return validationFailure("delete_composite_field", requested,
                "Composite or ordinal not found");
        }
        DataTypeComponent component = composite.getComponent(ordinal);
        if (component.isUndefined()) {
            return validationFailure("delete_composite_field", requested,
                "No defined field exists at ordinal " + ordinal);
        }
        JsonObject oldState = queryCompositeState(
            program, name, categoryPath);
        int oldDefinedCount = composite.getNumDefinedComponents();
        return withTransaction(program, "Delete composite field", tx -> {
            try {
                if (composite instanceof Structure) {
                    ((Structure) composite).clearComponent(ordinal);
                } else {
                    composite.delete(ordinal);
                }
                if (composite.getNumDefinedComponents()
                        != oldDefinedCount - 1) {
                    throw new IllegalStateException(
                        "Composite field deletion read-back mismatch");
                }
                JsonObject stored = queryCompositeState(
                    program, name, categoryPath);
                tx.commit();
                return successResult("delete_composite_field", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("delete_composite_field", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryCompositeState(program, name, categoryPath));
    }

    static JsonElement setCompositeLayout(
            Program program, JsonObject args) {
        String name = QuerySupport.requireString(args, "name");
        String categoryPath = QuerySupport.requireString(args, "category_path");
        String packing = QuerySupport.requireString(args, "packing");
        int packingValue = QuerySupport.optInt(args, "packing_value", 0);
        String alignment = QuerySupport.requireString(args, "alignment");
        int alignmentValue = QuerySupport.optInt(args, "alignment_value", 0);
        JsonObject requested = new JsonObject();
        requested.addProperty("name", name);
        requested.addProperty("category_path", categoryPath);
        requested.addProperty("packing", packing);
        requested.addProperty("packing_value", packingValue);
        requested.addProperty("alignment", alignment);
        requested.addProperty("alignment_value", alignmentValue);
        if (!Set.of("disabled", "default", "explicit").contains(packing)
                || !Set.of("default", "machine", "explicit")
                    .contains(alignment)) {
            return validationFailure("set_composite_layout", requested,
                "Invalid packing or alignment mode");
        }
        if (("explicit".equals(packing) && packingValue <= 0)
                || ("explicit".equals(alignment)
                    && alignmentValue <= 0)) {
            return validationFailure("set_composite_layout", requested,
                "Explicit packing/alignment values must be positive");
        }
        Composite composite = findComposite(program, name, categoryPath);
        if (composite == null) {
            return validationFailure("set_composite_layout", requested,
                "Composite '" + name + "' not found in " + categoryPath);
        }
        JsonObject oldState = queryCompositeState(
            program, name, categoryPath);
        return withTransaction(program, "Set composite layout", tx -> {
            try {
                if ("disabled".equals(packing)) {
                    composite.setPackingEnabled(false);
                } else if ("default".equals(packing)) {
                    composite.setToDefaultPacking();
                } else {
                    composite.setExplicitPackingValue(packingValue);
                }
                if ("default".equals(alignment)) {
                    composite.setToDefaultAligned();
                } else if ("machine".equals(alignment)) {
                    composite.setToMachineAligned();
                } else {
                    composite.setExplicitMinimumAlignment(alignmentValue);
                }
                JsonObject stored = queryCompositeState(
                    program, name, categoryPath);
                if (!packing.equals(stored.get("packing").getAsString())
                        || !alignment.equals(
                            stored.get("alignment_mode").getAsString())
                        || ("explicit".equals(packing)
                            && stored.get("packing_value").getAsInt()
                                != packingValue)
                        || ("explicit".equals(alignment)
                            && stored.get("minimum_alignment").getAsInt()
                                != alignmentValue)) {
                    throw new IllegalStateException(
                        "Composite layout read-back mismatch");
                }
                tx.commit();
                return successResult("set_composite_layout", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_composite_layout", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryCompositeState(program, name, categoryPath));
    }

    private static DataType findStructure(Program program, String name) {
        Iterator<DataType> iterator = program.getDataTypeManager()
            .getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dataType = iterator.next();
            if (name.equals(dataType.getName())
                    && dataType instanceof
                        ghidra.program.model.data.Structure) {
                return dataType;
            }
        }
        return null;
    }

    static Structure findStructure(
            Program program, String name, String categoryPath) {
        Iterator<DataType> iterator = program.getDataTypeManager()
            .getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dataType = iterator.next();
            if (name.equals(dataType.getName())
                    && categoryPath.equals(dataType.getCategoryPath().toString())
                    && dataType instanceof Structure) {
                return (Structure) dataType;
            }
        }
        return null;
    }

    private static Composite findComposite(
            Program program, String name, String categoryPath) {
        Iterator<DataType> iterator = program.getDataTypeManager()
            .getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dataType = iterator.next();
            if (name.equals(dataType.getName())
                    && categoryPath.equals(
                        dataType.getCategoryPath().toString())
                    && dataType instanceof Composite) {
                return (Composite) dataType;
            }
        }
        return null;
    }

    private static JsonObject queryStructureState(
            Program program, String name) {
        return queryStructureState(program, name, "");
    }

    private static JsonObject queryStructureState(
            Program program, String name, String categoryPath) {
        JsonObject args = new JsonObject();
        args.addProperty("name", name);
        if (!categoryPath.isEmpty()) {
            args.addProperty("category_path", categoryPath);
        }
        JsonElement result = CompositeQueries.getStructure(program, args);
        if (QuerySupport.isQueryError(result)) {
            JsonObject missing = new JsonObject();
            missing.addProperty("exists", false);
            missing.addProperty("name", name);
            return missing;
        }
        JsonObject state = result.getAsJsonObject();
        state.addProperty("exists", true);
        return state;
    }

    private static JsonObject queryCompositeState(
            Program program, String name, String categoryPath) {
        JsonObject args = new JsonObject();
        args.addProperty("name", name);
        args.addProperty("category_path", categoryPath);
        JsonElement result = CompositeQueries.getComposite(program, args);
        if (QuerySupport.isQueryError(result)) {
            JsonObject missing = new JsonObject();
            missing.addProperty("exists", false);
            missing.addProperty("name", name);
            missing.addProperty("category_path", categoryPath);
            return missing;
        }
        JsonObject state = result.getAsJsonObject();
        state.addProperty("exists", true);
        return state;
    }

}
