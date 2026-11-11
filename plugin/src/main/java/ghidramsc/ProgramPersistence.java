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

import static ghidramsc.MutationResult.baseResult;
import static ghidramsc.MutationResult.errorMessage;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/** GUI-backed program persistence and exact completion reporting. */
final class ProgramPersistence {
    private ProgramPersistence() { }

    static JsonElement saveProgram(
            Program program, JsonObject args, PluginTool tool) {
        String comment = QueryHandlers.optString(
            args, "comment", "Saved by GhidraMSC");
        JsonObject requested = new JsonObject();
        requested.addProperty("comment", comment);
        JsonObject oldState = QueryHandlers.programPersistenceState(program);
        DomainFile domainFile = program.getDomainFile();
        if (tool == null || domainFile == null) {
            return persistenceResult("validation_failed", oldState,
                requested, QueryHandlers.programPersistenceState(program),
                false, false, true,
                "Ghidra GUI save services are unavailable");
        }
        if (!program.canSave() || !domainFile.canSave()) {
            return persistenceResult("validation_failed", oldState,
                requested, QueryHandlers.programPersistenceState(program),
                false, false, true,
                "Program cannot be saved in place");
        }
        if (!program.isChanged()) {
            return persistenceResult("no_change", oldState,
                requested, oldState.deepCopy(), false, false, true, null);
        }
        if (!program.canLock() || program.isLocked()) {
            return persistenceResult("failed", oldState, requested,
                QueryHandlers.programPersistenceState(program),
                false, false, true,
                "Program is busy and cannot be saved safely");
        }

        GuiSaveTask saveTask = new GuiSaveTask(domainFile);
        AtomicBoolean lockAcquired = new AtomicBoolean(false);
        try {
            Swing.runNow(() -> {
                tool.prepareToSave(program);
                if (!program.lock("GhidraMSC save")) {
                    return;
                }
                lockAcquired.set(true);
                try {
                    new TaskLauncher(saveTask, tool.getToolFrame());
                } finally {
                    program.unlock();
                }
            });
        } catch (Exception e) {
            return persistenceResult("failed", oldState, requested,
                oldState.deepCopy(), lockAcquired.get(), false, false,
                "GUI save did not complete: " + errorMessage(e));
        }
        if (!lockAcquired.get()) {
            return persistenceResult("failed", oldState, requested,
                QueryHandlers.programPersistenceState(program),
                false, false, true,
                "Program became busy before the save started");
        }
        if (saveTask.wasCancelled()) {
            return persistenceResult("failed", oldState, requested,
                QueryHandlers.programPersistenceState(program),
                true, false, true, "Save was cancelled");
        }
        if (saveTask.getFailure() != null) {
            return persistenceResult("failed", oldState, requested,
                QueryHandlers.programPersistenceState(program),
                true, false, true,
                "Save failed: " + errorMessage(saveTask.getFailure()));
        }
        JsonObject stored = QueryHandlers.programPersistenceState(program);
        if (program.isChanged()) {
            return persistenceResult("failed", oldState, requested,
                stored, true, false, true,
                "Program remains dirty after save");
        }
        return persistenceResult("success", oldState, requested,
            stored, true, true, true, null);
    }

    private static JsonObject persistenceResult(String status,
            JsonObject oldState, JsonObject requested, JsonObject stored,
            boolean attempted, boolean succeeded,
            boolean completionObserved, String error) {
        JsonObject result = baseResult("save_program", status, requested);
        result.add("program", oldState.get("program").deepCopy());
        result.add("old", oldState.deepCopy());
        result.add("stored", stored.deepCopy());
        JsonObject save = new JsonObject();
        save.addProperty("attempted", attempted);
        save.addProperty("completed",
            "success".equals(status) || "no_change".equals(status));
        save.addProperty("succeeded", succeeded);
        save.addProperty("backend", "plugin_gui_domain_file");
        save.addProperty("completion_observed", completionObserved);
        save.addProperty("comment_supported", false);
        save.addProperty("comment_applied", false);
        result.add("save", save);
        if (error != null) {
            result.addProperty("error", error);
        }
        return result;
    }

    private static final class GuiSaveTask extends Task {
        private final DomainFile domainFile;
        private volatile IOException failure;
        private volatile boolean cancelled;

        GuiSaveTask(DomainFile domainFile) {
            super("Save Program", true, true, true);
            this.domainFile = domainFile;
        }

        @Override
        public void run(TaskMonitor monitor) {
            monitor.setMessage("Saving Program...");
            try {
                domainFile.save(monitor);
            } catch (CancelledException e) {
                cancelled = true;
            } catch (IOException e) {
                failure = e;
            }
        }

        boolean wasCancelled() {
            return cancelled;
        }

        IOException getFailure() {
            return failure;
        }
    }

}
