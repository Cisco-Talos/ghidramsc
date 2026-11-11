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
import static ghidramsc.QuerySupport.isQueryError;
import static ghidramsc.QuerySupport.queryError;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

/** Comment and bookmark mutations with native read-back. */
final class AnnotationMutations {
    private AnnotationMutations() { }

    // -----------------------------------------------------------------
    // set_comment_at_address
    // -----------------------------------------------------------------

    static JsonElement setCommentAtAddress(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String text = QuerySupport.requireString(args, "comment");
        String commentType = QuerySupport.optString(
            args, "comment_type", "eol");
        boolean allowContainingItem = QuerySupport.optBool(
            args, "allow_containing_item", false);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("comment_type", commentType);
        requested.addProperty("comment", text);
        requested.addProperty("allow_containing_item", allowContainingItem);
        int ctId = QuerySupport.commentTypeId(commentType);
        if (ctId < 0) {
            return validationFailure("set_comment_at_address", requested,
                "Unknown comment type '" + commentType + "'");
        }

        Address addr = QuerySupport.toAddress(program, addrHex);
        CodeUnit codeUnit = program.getListing().getCodeUnitAt(addr);
        boolean exact = codeUnit != null;
        if (!exact) {
            codeUnit = program.getListing().getCodeUnitContaining(addr);
        }
        if (codeUnit == null) {
            return validationFailure("set_comment_at_address", requested,
                "No code unit at " + addrHex);
        }
        final CodeUnit target = codeUnit;
        Address effective = exact ? addr : target.getAddress();
        if (!exact && !allowContainingItem) {
            JsonObject rejected = validationFailure(
                "set_comment_at_address", requested,
                "Interior address shares the containing code-unit comment; "
                + "set allow_containing_item=true to change that comment");
            addCommentTarget(rejected, addr, target, effective);
            return rejected;
        }
        JsonElement oldState = queryComment(
            program, effective.toString(), commentType);
        if (text.equals(oldState.getAsString())) {
            JsonObject unchanged = noChangeResult(
                "set_comment_at_address", oldState,
                requested, oldState.deepCopy());
            addCommentTarget(unchanged, addr, target, effective);
            return unchanged;
        }

        JsonObject result = withTransaction(program, "Set comment", tx -> {
            try {
                target.setComment(ctId, text);
                JsonElement stored = queryComment(
                    program, effective.toString(), commentType);
                if (!text.equals(stored.getAsString())) {
                    throw new IllegalStateException(
                        "Comment read-back mismatch");
                }
                tx.commit();
                return successResult("set_comment_at_address", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("set_comment_at_address", oldState,
                    requested, errorMessage(e));
            }
        }, () -> queryComment(program, effective.toString(), commentType))
            .getAsJsonObject();
        addCommentTarget(result, addr, target, effective);
        return result;
    }

    // -----------------------------------------------------------------
    // create_bookmark
    // -----------------------------------------------------------------

    static JsonElement createBookmark(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String category = QuerySupport.requireString(args, "category");
        String comment = QuerySupport.optString(
            args, "comment", "");

        Address addr = QuerySupport.toAddress(program, addrHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("category", category);
        requested.addProperty("comment", comment);
        JsonObject oldState = bookmarkState(
            program, addr, category);
        if (oldState.get("present").getAsBoolean()
                && comment.equals(oldState.get("comment").getAsString())) {
            return noChangeResult("create_bookmark", oldState,
                requested, oldState.deepCopy());
        }

        return withTransaction(program, "Set bookmark", tx -> {
            try {
                program.getBookmarkManager().setBookmark(
                    addr, BookmarkType.NOTE, category, comment);
                JsonObject stored = bookmarkState(
                    program, addr, category);
                if (!stored.get("present").getAsBoolean()
                        || !comment.equals(
                            stored.get("comment").getAsString())) {
                    throw new IllegalStateException(
                        "Bookmark read-back mismatch");
                }
                tx.commit();
                return successResult("create_bookmark", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("create_bookmark", oldState,
                    requested, errorMessage(e));
            }
        }, () -> bookmarkState(program, addr, category));
    }

    // -----------------------------------------------------------------
    // delete_bookmark
    // -----------------------------------------------------------------

    static JsonElement deleteBookmark(
            Program program, JsonObject args) {
        String addrHex = QuerySupport.requireString(args, "addr_hex");
        String category = QuerySupport.requireString(args, "category");

        Address addr = QuerySupport.toAddress(program, addrHex);
        JsonObject requested = new JsonObject();
        requested.addProperty("address", addrHex);
        requested.addProperty("category", category);
        requested.addProperty("present", false);
        JsonObject oldState = bookmarkState(program, addr, category);
        if (!oldState.get("present").getAsBoolean()) {
            return validationFailure("delete_bookmark", requested,
                "No bookmark at " + addrHex
                + " with category '" + category + "'");
        }

        return withTransaction(program, "Remove bookmark", tx -> {
            try {
                var bm = program.getBookmarkManager();
                for (var bookmark : bm.getBookmarks(addr)) {
                    if (bookmark.getCategory().equals(category)
                            && BookmarkType.NOTE.equals(
                                bookmark.getTypeString())) {
                        bm.removeBookmark(bookmark);
                    }
                }
                JsonObject stored = bookmarkState(
                    program, addr, category);
                if (stored.get("present").getAsBoolean()) {
                    throw new IllegalStateException(
                        "Bookmark remains after removal");
                }
                tx.commit();
                return successResult("delete_bookmark", oldState,
                    requested, stored);
            } catch (Exception e) {
                return rolledBackResult("delete_bookmark", oldState,
                    requested, errorMessage(e));
            }
        }, () -> bookmarkState(program, addr, category));
    }

    private static JsonElement queryComment(Program program,
            String addrHex, String commentType) {
        JsonObject queryArgs = new JsonObject();
        queryArgs.addProperty("addr_hex", addrHex);
        queryArgs.addProperty("comment_type", commentType);
        JsonElement comment = AnnotationQueries.getCommentAtAddress(program, queryArgs);
        if (isQueryError(comment)) {
            throw new IllegalStateException(
                "get_comment_at_address read-back failed: " + queryError(comment));
        }
        return comment;
    }

    private static void addCommentTarget(JsonObject result, Address requested,
            CodeUnit containing, Address effective) {
        result.addProperty("requested_address", requested.toString());
        result.addProperty("containing_address",
            containing.getAddress().toString());
        result.addProperty("containing_end",
            containing.getMaxAddress().toString());
        result.addProperty("effective_address", effective.toString());
        result.addProperty("byte_offset", requested.subtract(effective));
    }

    private static JsonObject bookmarkState(
            Program program, Address address, String category) {
        JsonObject state = new JsonObject();
        state.addProperty("address", address.toString());
        state.addProperty("category", category);
        state.addProperty("type", BookmarkType.NOTE);
        state.addProperty("present", false);
        for (var bookmark
                : program.getBookmarkManager().getBookmarks(address)) {
            if (category.equals(bookmark.getCategory())
                    && BookmarkType.NOTE.equals(
                        bookmark.getTypeString())) {
                state.addProperty("present", true);
                String comment = bookmark.getComment();
                state.addProperty("comment",
                    comment != null ? comment : "");
                break;
            }
        }
        return state;
    }

}
