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

import static ghidramsc.ProgramQueries.programName;
import static ghidramsc.QuerySupport.optString;
import static ghidramsc.QuerySupport.requireString;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/** Native datatype inventory and composite/enum state queries. */
final class CompositeQueries {
    private CompositeQueries() { }

    // -----------------------------------------------------------------

    static JsonElement listStructures(Program program, JsonObject args) {
        var dtm = program.getDataTypeManager();
        List<String> lines = new ArrayList<>();
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (dt instanceof ghidra.program.model.data.Structure) {
                ghidra.program.model.data.Structure s =
                    (ghidra.program.model.data.Structure) dt;
                lines.add("  " + s.getName() + " ("
                    + s.getLength() + " bytes, "
                    + s.getNumComponents() + " fields)  "
                    + s.getCategoryPath());
            }
        }
        Collections.sort(lines);

        StringBuilder sb = new StringBuilder();
        sb.append("STRUCTURES in ").append(programName(program))
          .append(" (").append(lines.size())
          .append(" total)\n\n");
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // get_structure
    // -----------------------------------------------------------------

    static JsonElement getStructure(Program program, JsonObject args) {
        String name = requireString(args, "name");
        String categoryPath = optString(args, "category_path", "");
        var dtm = program.getDataTypeManager();
        ghidra.program.model.data.Structure foundStruct = null;
        List<String> matches = new ArrayList<>();
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (dt.getName().equals(name)
                    && dt instanceof ghidra.program.model.data.Structure) {
                String candidatePath = dt.getCategoryPath().toString();
                if (!categoryPath.isEmpty()
                        && !categoryPath.equals(candidatePath)) {
                    continue;
                }
                matches.add(candidatePath);
                foundStruct = (ghidra.program.model.data.Structure) dt;
            }
        }
        if (matches.size() > 1) {
            JsonObject err = new JsonObject();
            err.addProperty("error", "Structure '" + name
                + "' is ambiguous; specify category_path");
            JsonArray paths = new JsonArray();
            Collections.sort(matches);
            for (String path : matches) {
                paths.add(path);
            }
            err.add("matching_paths", paths);
            return err;
        }
        if (foundStruct == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "Structure '" + name + "' not found"
                    + (categoryPath.isEmpty() ? ""
                        : " in " + categoryPath));
            return err;
        }

        JsonArray fields = new JsonArray();
        for (int i = 0; i < foundStruct.getNumComponents(); i++) {
            var comp = foundStruct.getComponent(i);
            JsonObject fobj = new JsonObject();
            fobj.addProperty("ordinal", i);
            fobj.addProperty("offset", comp.getOffset());
            String fieldName = comp.getFieldName();
            fobj.addProperty("name",
                fieldName != null ? fieldName : "");
            fobj.addProperty("type",
                comp.getDataType().getName());
            fobj.addProperty("size", comp.getLength());
            String comment = comp.getComment();
            fobj.addProperty("comment",
                comment != null ? comment : "");
            fields.add(fobj);
        }

        JsonObject out = new JsonObject();
        out.addProperty("name", foundStruct.getName());
        out.addProperty("path",
            foundStruct.getCategoryPath().toString());
        out.addProperty("size", foundStruct.getLength());
        out.addProperty("num_fields",
            foundStruct.getNumComponents());
        out.addProperty("num_defined_fields",
            foundStruct.getNumDefinedComponents());
        out.addProperty("packing_enabled",
            foundStruct.isPackingEnabled());
        out.addProperty("packing", foundStruct.hasExplicitPackingValue()
            ? "explicit" : foundStruct.hasDefaultPacking()
                ? "default" : "disabled");
        out.addProperty("packing_value",
            foundStruct.hasExplicitPackingValue()
                ? foundStruct.getExplicitPackingValue() : 0);
        out.addProperty("alignment", foundStruct.getAlignment());
        out.addProperty("alignment_mode", foundStruct.isMachineAligned()
            ? "machine" : foundStruct.hasExplicitMinimumAlignment()
                ? "explicit" : "default");
        out.addProperty("minimum_alignment",
            foundStruct.hasExplicitMinimumAlignment()
                ? foundStruct.getExplicitMinimumAlignment() : 0);
        out.add("fields", fields);
        return out;
    }

    static JsonElement getComposite(Program program, JsonObject args) {
        String name = requireString(args, "name");
        String categoryPath = optString(args, "category_path", "");
        List<Composite> matches = new ArrayList<>();
        Iterator<DataType> dataTypes =
            program.getDataTypeManager().getAllDataTypes();
        while (dataTypes.hasNext()) {
            DataType dataType = dataTypes.next();
            if (!(dataType instanceof Composite)
                    || !name.equals(dataType.getName())) {
                continue;
            }
            if (!categoryPath.isEmpty()
                    && !categoryPath.equals(
                        dataType.getCategoryPath().toString())) {
                continue;
            }
            matches.add((Composite) dataType);
        }
        if (matches.size() > 1) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Composite '" + name
                + "' is ambiguous; specify category_path");
            JsonArray paths = new JsonArray();
            matches.stream()
                .map(item -> item.getCategoryPath().toString())
                .sorted()
                .forEach(paths::add);
            error.add("matching_paths", paths);
            return error;
        }
        if (matches.isEmpty()) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Composite '" + name + "' not found"
                + (categoryPath.isEmpty() ? "" : " in " + categoryPath));
            return error;
        }
        return compositeState(matches.get(0));
    }

    static JsonObject compositeState(Composite composite) {
        JsonArray fields = new JsonArray();
        for (DataTypeComponent component : composite.getComponents()) {
            JsonObject field = new JsonObject();
            field.addProperty("ordinal", component.getOrdinal());
            field.addProperty("offset", component.getOffset());
            field.addProperty("end_offset", component.getEndOffset());
            field.addProperty("name",
                component.getFieldName() == null
                    ? "" : component.getFieldName());
            field.addProperty("type", component.getDataType().getName());
            field.addProperty("display_type",
                component.getDataType().getDisplayName());
            field.addProperty("size", component.getLength());
            field.addProperty("comment",
                component.getComment() == null ? "" : component.getComment());
            field.addProperty("is_bitfield", component.isBitFieldComponent());
            field.addProperty("is_zero_bitfield",
                component.isZeroBitFieldComponent());
            if (component.getDataType() instanceof BitFieldDataType) {
                BitFieldDataType bitField =
                    (BitFieldDataType) component.getDataType();
                field.addProperty("base_type",
                    bitField.getBaseDataType().getName());
                field.addProperty("bit_size", bitField.getBitSize());
                field.addProperty("declared_bit_size",
                    bitField.getDeclaredBitSize());
                field.addProperty("bit_offset", bitField.getBitOffset());
                field.addProperty("storage_size", bitField.getStorageSize());
            }
            fields.add(field);
        }
        JsonObject out = new JsonObject();
        out.addProperty("name", composite.getName());
        out.addProperty("path", composite.getCategoryPath().toString());
        out.addProperty("kind", composite instanceof Union
            ? "union" : composite instanceof Structure
                ? "structure" : "composite");
        out.addProperty("size", composite.getLength());
        out.addProperty("num_fields", composite.getNumComponents());
        out.addProperty("num_defined_fields",
            composite.getNumDefinedComponents());
        out.addProperty("packing_enabled", composite.isPackingEnabled());
        out.addProperty("packing", composite.hasExplicitPackingValue()
            ? "explicit" : composite.hasDefaultPacking()
                ? "default" : "disabled");
        out.addProperty("packing_value", composite.hasExplicitPackingValue()
            ? composite.getExplicitPackingValue() : 0);
        out.addProperty("alignment", composite.getAlignment());
        out.addProperty("alignment_mode", composite.isMachineAligned()
            ? "machine" : composite.hasExplicitMinimumAlignment()
                ? "explicit" : "default");
        out.addProperty("minimum_alignment",
            composite.hasExplicitMinimumAlignment()
                ? composite.getExplicitMinimumAlignment() : 0);
        out.add("fields", fields);
        return out;
    }

    // -----------------------------------------------------------------

    static JsonElement listEnums(Program program, JsonObject args) {
        var dtm = program.getDataTypeManager();
        List<String> lines = new ArrayList<>();
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum e =
                    (ghidra.program.model.data.Enum) dt;
                lines.add("  " + e.getName() + " ("
                    + e.getLength() + " bytes, "
                    + e.getCount() + " members)  "
                    + e.getCategoryPath());
            }
        }
        Collections.sort(lines);

        StringBuilder sb = new StringBuilder();
        sb.append("ENUMS in ").append(programName(program))
          .append(" (").append(lines.size())
          .append(" total)\n\n");
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

    // -----------------------------------------------------------------
    // get_enum
    // -----------------------------------------------------------------

    static JsonElement getEnum(Program program, JsonObject args) {
        String name = requireString(args, "name");
        var dtm = program.getDataTypeManager();
        ghidra.program.model.data.Enum foundEnum = null;
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (dt.getName().equals(name)
                    && dt instanceof ghidra.program.model.data.Enum) {
                foundEnum = (ghidra.program.model.data.Enum) dt;
                break;
            }
        }
        if (foundEnum == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                "Enum '" + name + "' not found");
            return err;
        }

        JsonArray members = new JsonArray();
        for (String n : foundEnum.getNames()) {
            JsonObject mobj = new JsonObject();
            mobj.addProperty("name", n);
            mobj.addProperty("value", foundEnum.getValue(n));
            members.add(mobj);
        }

        JsonObject out = new JsonObject();
        out.addProperty("name", foundEnum.getName());
        out.addProperty("path", foundEnum.getCategoryPath().toString());
        out.addProperty("size", foundEnum.getLength());
        out.addProperty("count", foundEnum.getCount());
        out.add("members", members);
        return out;
    }

}
