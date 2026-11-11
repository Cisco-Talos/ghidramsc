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

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import java.util.Iterator;

/** Shared native datatype lookup for function, data, and composite mutations. */
final class DataTypeResolver {
    private DataTypeResolver() { }

    static DataType resolveDataType(Program program, String name) {
        var dtm = program.getDataTypeManager();
        // Try exact search first
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
        }
        // Try case-insensitive
        iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        try {
            var parser = new ghidra.util.data.DataTypeParser(
                dtm, dtm, null,
                ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);
            DataType parsed = parser.parse(name);
            if (parsed != null) {
                return parsed;
            }
        } catch (Exception e) {
            // Fall through to the built-in exact-path lookup.
        }
        // Try built-in types
        var builtInDtm = program.getDataTypeManager()
            .getDataType("/" + name);
        return builtInDtm;
    }

}
