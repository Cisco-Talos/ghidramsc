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
import static ghidramsc.QuerySupport.commentTypeId;
import static ghidramsc.QuerySupport.optString;
import static ghidramsc.QuerySupport.requireString;
import static ghidramsc.QuerySupport.toAddress;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.List;

/** User annotations, comments, and bookmark queries. */
final class AnnotationQueries {
    private AnnotationQueries() { }

    // -----------------------------------------------------------------
    // export_annotations
    // -----------------------------------------------------------------

    static JsonElement exportAnnotations(Program program, JsonObject args) {
        JsonObject data = new JsonObject();
        data.addProperty("binary", programName(program));
        data.addProperty("image_base",
            program.getImageBase().toString());

        // User-defined symbols
        JsonArray symbols = new JsonArray();
        SymbolTable st = program.getSymbolTable();
        SymbolIterator symIter = st.getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            if (sym.getSource() != SourceType.USER_DEFINED) continue;
            JsonObject sobj = new JsonObject();
            sobj.addProperty("addr", sym.getAddress().toString());
            sobj.addProperty("name", sym.getName());
            sobj.addProperty("namespace",
                sym.getParentNamespace().toString());
            sobj.addProperty("type",
                sym.getSymbolType().toString());
            sobj.addProperty("primary", sym.isPrimary());
            symbols.add(sobj);
        }
        data.add("symbols", symbols);

        // Comments
        int[] commentTypes = {
            CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT,
            CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT,
            CodeUnit.REPEATABLE_COMMENT
        };
        String[] commentNames = {
            "plate", "pre", "post", "eol", "repeatable"
        };

        JsonArray comments = new JsonArray();
        Listing progListing = program.getListing();
        CodeUnitIterator cuIter = progListing.getCodeUnits(true);
        while (cuIter.hasNext()) {
            CodeUnit cu = cuIter.next();
            for (int ci = 0; ci < commentTypes.length; ci++) {
                String cmt = cu.getComment(commentTypes[ci]);
                if (cmt != null && !cmt.trim().isEmpty()) {
                    JsonObject cobj = new JsonObject();
                    cobj.addProperty("addr",
                        cu.getAddress().toString());
                    cobj.addProperty("type", commentNames[ci]);
                    cobj.addProperty("text", cmt);
                    comments.add(cobj);
                }
            }
        }
        data.add("comments", comments);

        // Function signatures (user-defined only)
        JsonArray sigs = new JsonArray();
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (func.getSymbol().getSource() != SourceType.USER_DEFINED)
                continue;
            JsonObject fobj = new JsonObject();
            fobj.addProperty("addr",
                func.getEntryPoint().toString());
            fobj.addProperty("name", func.getName());
            fobj.addProperty("signature",
                func.getSignature().toString());
            fobj.addProperty("return_type",
                func.getReturnType().toString());
            fobj.addProperty("calling_convention",
                func.getCallingConventionName());
            JsonArray fparams = new JsonArray();
            for (Parameter p : func.getParameters()) {
                JsonObject pp = new JsonObject();
                pp.addProperty("name", p.getName());
                pp.addProperty("type", p.getDataType().toString());
                pp.addProperty("ordinal", p.getOrdinal());
                fparams.add(pp);
            }
            fobj.add("params", fparams);
            sigs.add(fobj);
        }
        data.add("function_signatures", sigs);

        return data;
    }

    // -----------------------------------------------------------------
    // get_comment_at_address
    // -----------------------------------------------------------------

    static JsonElement getCommentAtAddress(Program program, JsonObject args) {
        String addrHex = requireString(args, "addr_hex");
        String commentType = optString(args, "comment_type", "eol");
        int ctId = commentTypeId(commentType);
        if (ctId < 0) {
            return new JsonPrimitive(
                "ERROR: Unknown comment type '" + commentType
                + "'. Use: plate, pre, post, eol, repeatable");
        }

        Address addr = toAddress(program, addrHex);
        CodeUnit cu = program.getListing().getCodeUnitAt(addr);
        boolean exact = cu != null;
        if (!exact) {
            cu = program.getListing().getCodeUnitContaining(addr);
        }
        if (cu == null) {
            return new JsonPrimitive(
                "ERROR: No code unit at " + addrHex);
        }
        String cmt = cu.getComment(ctId);
        if (exact) {
            return new JsonPrimitive(cmt != null ? cmt : "");
        }
        Address effective = cu.getAddress();
        JsonObject out = new JsonObject();
        out.addProperty("requested_address", addr.toString());
        out.addProperty("containing_address", effective.toString());
        out.addProperty("containing_end", cu.getMaxAddress().toString());
        out.addProperty("effective_address", effective.toString());
        out.addProperty("byte_offset", addr.subtract(effective));
        out.addProperty("comment_type", commentType);
        out.addProperty("comment", cmt != null ? cmt : "");
        out.addProperty("distinct_interior_comment_storage", false);
        return out;
    }

    // -----------------------------------------------------------------
    // list_bookmarks
    // -----------------------------------------------------------------

    static JsonElement listBookmarks(Program program, JsonObject args) {
        String addrHex = optString(args, "addr_hex", "");
        var bm = program.getBookmarkManager();

        List<String> lines = new ArrayList<>();
        if (!addrHex.isEmpty()) {
            Address addr = toAddress(program, addrHex);
            for (var b : bm.getBookmarks(addr)) {
                lines.add(b.getAddress() + "  [" + b.getCategory()
                    + "] " + b.getTypeString()
                    + " -- " + b.getComment());
            }
        } else {
            String[] types = {
                "Note", "Warning", "Error", "Info", "Analysis"
            };
            for (String bType : types) {
                try {
                    var iter = bm.getBookmarksIterator(bType);
                    while (iter.hasNext()) {
                        var b = iter.next();
                        lines.add(b.getAddress() + "  ["
                            + b.getCategory() + "] "
                            + b.getTypeString()
                            + " -- " + b.getComment());
                    }
                } catch (Exception e) {
                    // skip unknown bookmark types
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("BOOKMARKS in ").append(programName(program))
          .append(" (").append(lines.size())
          .append(" total)\n\n");
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        return new JsonPrimitive(sb.toString());
    }

}
