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

import static ghidramsc.MutationResult.addTransaction;
import static ghidramsc.MutationResult.errorMessage;
import static ghidramsc.MutationResult.isFailureResult;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;

/** Explicit commit decision and read-back for every program mutation. */
final class MutationTransaction {
    private MutationTransaction() { }

    @FunctionalInterface
    interface TransactionAction {
        JsonElement run(TransactionControl transaction);
    }

    static final class TransactionControl {
        private boolean commitRequested;

        void commit() {
            commitRequested = true;
        }

        boolean isCommitRequested() {
            return commitRequested;
        }
    }

    static JsonElement withTransaction(Program program,
            String description, TransactionAction action) {
        return withTransaction(program, description, action, null);
    }

    static JsonElement withTransaction(Program program,
            String description, TransactionAction action,
            java.util.function.Supplier<JsonElement> finalReadback) {
        int txId = program.startTransaction(description);
        TransactionControl transaction = new TransactionControl();
        boolean commit = false;
        JsonElement result;
        try {
            result = action.run(transaction);
            if (!isFailureResult(result)
                    && !transaction.isCommitRequested()) {
                throw new IllegalStateException(
                    "Mutation returned without an explicit commit decision");
            }
            commit = !isFailureResult(result)
                && transaction.isCommitRequested();
        } catch (RuntimeException | Error error) {
            program.endTransaction(txId, false);
            throw error;
        }
        program.endTransaction(txId, commit);
        if (result.isJsonObject()
                && result.getAsJsonObject().has("status")) {
            JsonObject structured = result.getAsJsonObject();
            addTransaction(structured,
                description, true, commit);
            if (!structured.has("stored") && finalReadback != null) {
                try {
                    structured.add("stored", finalReadback.get());
                } catch (RuntimeException readBackError) {
                    structured.addProperty("read_back_error",
                        errorMessage(readBackError));
                }
            }
        }
        return result;
    }

}
