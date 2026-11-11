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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

/**
 * Routes incoming JSON commands to the appropriate handler method.
 *
 * Each command is registered as a name -> handler mapping.  The handler
 * receives the {@link Program} and the {@code args} JsonObject, and
 * returns a {@link JsonElement} result (string, object, array, etc.).
 *
 * Request format:
 * <pre>
 * {"id": 1, "command": "decompile_function", "binary": "firmware.elf",
 *  "args": {"addr_hex": "0x1000"}}
 * </pre>
 *
 * Response format (success):
 * <pre>
 * {"id": 1, "result": "// decompiled C code..."}
 * </pre>
 *
 * Response format (error):
 * <pre>
 * {"id": 1, "error": "No function at or containing 0xdeadbeef"}
 * </pre>
 */
public class CommandDispatcher {

    /**
     * Functional interface for command handlers.
     * Takes (Program, argsJsonObject) and returns a JsonElement result.
     */
    @FunctionalInterface
    public interface CommandHandler extends BiFunction<Program, JsonObject, JsonElement> {
    }

    interface Context {
        Program getActiveProgram();

        Program resolveProgram(String name);

        String[] listProgramNames();

        ProgramLocation getCurrentLoc();

        ProgramSelection getCurrentSel();

        PluginTool getTool();
    }

    private final Context context;
    private final Map<String, CommandHandler> handlers = new HashMap<>();

    public CommandDispatcher(GhidraMSCPlugin plugin) {
        this(new Context() {
            @Override
            public Program getActiveProgram() {
                return plugin.getActiveProgram();
            }

            @Override
            public Program resolveProgram(String name) {
                return plugin.resolveProgram(name);
            }

            @Override
            public String[] listProgramNames() {
                return plugin.listProgramNames();
            }

            @Override
            public ProgramLocation getCurrentLoc() {
                return plugin.getCurrentLoc();
            }

            @Override
            public ProgramSelection getCurrentSel() {
                return plugin.getCurrentSel();
            }

            @Override
            public PluginTool getTool() {
                return plugin.getTool();
            }
        });
    }

    CommandDispatcher(Context context) {
        this.context = Objects.requireNonNull(context);
        registerBuiltins();
    }

    /**
     * Register all built-in command handlers.
     */
    private void registerBuiltins() {
        // -- Special / meta commands --
        register("ping", (prog, args) -> jsonPrimitive("pong"));
        register("list_programs", (prog, args) -> {
            String[] names = context.listProgramNames();
            JsonObject result = new JsonObject();
            JsonArray arr = new JsonArray();
            for (String n : names) {
                arr.add(n);
            }
            result.add("programs", arr);
            return result;
        });

        // -- GUI-context commands (plugin-only) --
        register("get_cursor_address", (prog, args) -> {
            var loc = context.getCurrentLoc();
            if (loc == null) {
                return jsonPrimitive("ERROR: No current location in the GUI");
            }
            JsonObject r = new JsonObject();
            r.addProperty("address", "0x" + loc.getAddress().toString(false));
            if (prog != null) {
                r.addProperty("program",
                    GhidraMSCPlugin.qualifiedProgramName(prog));
            }
            return r;
        });
        register("get_function_at_cursor", (prog, args) -> {
            var loc = context.getCurrentLoc();
            if (loc == null) {
                return jsonPrimitive("ERROR: No current location in the GUI");
            }
            if (prog == null) {
                return jsonPrimitive("ERROR: No active program");
            }
            ghidra.program.model.listing.Function fn =
                prog.getFunctionManager().getFunctionContaining(loc.getAddress());
            if (fn == null) {
                return jsonPrimitive(
                    "ERROR: No function at cursor address 0x"
                    + loc.getAddress().toString(false));
            }
            JsonObject r = new JsonObject();
            r.addProperty("name", fn.getName());
            r.addProperty("address", "0x" + fn.getEntryPoint().toString(false));
            r.addProperty("signature", fn.getPrototypeString(true, false));
            r.addProperty("size", fn.getBody().getNumAddresses());
            r.addProperty("program",
                GhidraMSCPlugin.qualifiedProgramName(prog));
            return r;
        });
        register("get_gui_selection", (prog, args) -> {
            var sel = context.getCurrentSel();
            if (sel == null || sel.isEmpty()) {
                JsonObject r = new JsonObject();
                r.add("start", com.google.gson.JsonNull.INSTANCE);
                r.add("end", com.google.gson.JsonNull.INSTANCE);
                r.addProperty("num_addresses", 0);
                if (prog != null) {
                    r.addProperty("program",
                        GhidraMSCPlugin.qualifiedProgramName(prog));
                }
                return r;
            }
            JsonObject r = new JsonObject();
            r.addProperty("start", "0x" + sel.getMinAddress().toString(false));
            r.addProperty("end", "0x" + sel.getMaxAddress().toString(false));
            r.addProperty("num_addresses", sel.getNumAddresses());
            if (prog != null) {
                r.addProperty("program",
                    GhidraMSCPlugin.qualifiedProgramName(prog));
            }
            return r;
        });
        register("set_cursor_address", (prog, args) -> {
            JsonObject requested = new JsonObject();
            if (prog == null) {
                return nonTransactionalFailure("set_cursor_address", requested,
                    "validation_failed", "No active program", "gui");
            }
            String addrHex = QueryHandlers.requireString(args, "addr_hex");
            requested.addProperty("address", addrHex);
            ghidra.program.model.address.Address addr;
            try {
                addr = prog.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(addrHex);
            } catch (ghidra.program.model.address.AddressFormatException e) {
                return nonTransactionalFailure("set_cursor_address", requested,
                    "validation_failed", "Invalid address: " + addrHex,
                    "gui");
            }
            ghidra.app.services.GoToService goTo =
                context.getTool().getService(
                    ghidra.app.services.GoToService.class);
            if (goTo == null) {
                return nonTransactionalFailure("set_cursor_address", requested,
                    "validation_failed", "GoToService not available",
                    "gui");
            }
            JsonObject oldState = currentLocationState();
            boolean ok = goTo.goTo(addr);
            JsonObject stored = currentLocationState();
            boolean matches = stored.has("address")
                && (addr.toString().equals(
                    stored.get("address").getAsString())
                    || ("0x" + addr.toString(false)).equals(
                        stored.get("address").getAsString()));
            if (!ok || !matches) {
                JsonObject failure = nonTransactionalFailure(
                    "set_cursor_address", requested, "failed",
                    !ok ? "GoToService rejected the navigation"
                        : "GUI address read-back mismatch", "gui");
                failure.add("old", oldState);
                failure.add("stored", stored);
                return failure;
            }
            return nonTransactionalSuccess("set_cursor_address", requested,
                oldState, stored, "gui");
        });
        register("undo_gui_transaction", (prog, args) -> {
            JsonObject requested = new JsonObject();
            requested.addProperty("action", "undo");
            if (prog == null) {
                return nonTransactionalFailure("undo_gui_transaction", requested,
                    "validation_failed", "No active program", "undo");
            }
            if (!prog.canUndo()) {
                return nonTransactionalFailure("undo_gui_transaction", requested,
                    "validation_failed", "Nothing to undo", "undo");
            }
            JsonObject oldState = undoState(prog);
            String undoName = prog.getUndoName();
            requested.addProperty("transaction", undoName);
            try {
                prog.undo();
            } catch (java.io.IOException e) {
                JsonObject failure = nonTransactionalFailure(
                    "undo_gui_transaction", requested, "failed",
                    "Undo failed: " + e.getMessage(), "undo");
                failure.add("old", oldState);
                failure.add("stored", undoState(prog));
                return failure;
            }
            return nonTransactionalSuccess("undo_gui_transaction", requested,
                oldState, undoState(prog), "undo");
        });

        // -- All query (read-only) handlers --
        QueryHandlers.registerAll(this);

        // -- All mutation (write) handlers --
        MutationHandlers.registerAll(this);
        register("save_program", (prog, args) -> {
            return MutationHandlers.saveProgram(prog, args, context.getTool());
        });
    }

    /**
     * Register a command handler.
     */
    public void register(String command, CommandHandler handler) {
        handlers.put(command, handler);
    }

    /**
     * Dispatch a JSON request and return a JSON response.
     *
     * @param request the parsed request object
     * @return the response object (always has "id")
     */
    public JsonObject dispatch(JsonObject request) {
        long id = 0;
        if (request.has("id")) {
            if (!request.get("id").isJsonPrimitive()
                    || !request.get("id").getAsJsonPrimitive().isNumber()) {
                return errorResponse(0, "Request id must be a number");
            }
            id = request.get("id").getAsLong();
        }

        for (Map.Entry<String, JsonElement> entry : request.entrySet()) {
            String key = entry.getKey();
            if (!"id".equals(key) && !"command".equals(key)
                    && !"binary".equals(key) && !"args".equals(key)) {
                return errorResponse(id,
                    "Unknown request field: " + key);
            }
        }

        if (!request.has("command")
                || !request.get("command").isJsonPrimitive()
                || !request.get("command").getAsJsonPrimitive().isString()
                || request.get("command").getAsString().isEmpty()) {
            return errorResponse(id,
                "Command must be a non-empty string");
        }
        String command = request.get("command").getAsString();

        JsonObject args = new JsonObject();
        if (request.has("args")) {
            if (!request.get("args").isJsonObject()) {
                return errorResponse(id, "args must be a JSON object");
            }
            args = request.getAsJsonObject("args");
        }

        String binaryName = null;
        if (request.has("binary")) {
            if (!request.get("binary").isJsonPrimitive()
                    || !request.get("binary").getAsJsonPrimitive().isString()) {
                return errorResponse(id, "binary must be a string");
            }
            binaryName = request.get("binary").getAsString();
        }

        if (!handlers.containsKey(command)) {
            return errorResponse(id, "Unknown command: " + command);
        }

        // These commands don't need a resolved program (or use
        // the active program themselves).
        if ("ping".equals(command) || "list_programs".equals(command)
                || "get_cursor_address".equals(command)
                || "get_function_at_cursor".equals(command)
                || "get_gui_selection".equals(command)
                || "set_cursor_address".equals(command)
                || "undo_gui_transaction".equals(command)) {
            // For GUI-context commands, pass the active program if available.
            Program active = context.getActiveProgram();
            return dispatchCommand(id, command, active, args);
        }

        // Resolve the program for all other commands.
        Program program = null;
        if (binaryName != null && !binaryName.isEmpty()) {
            try {
                program = context.resolveProgram(binaryName);
            } catch (GhidraMSCPlugin.ProgramOpenBlockedException e) {
                return errorResponse(id, e.getMessage());
            }
            if (program == null) {
                return errorResponse(id,
                    "Program not found: " + binaryName);
            }
        } else {
            program = context.getActiveProgram();
            if (program == null) {
                return errorResponse(id,
                    "No program specified and no active program in the GUI.");
            }
        }

        return dispatchCommand(id, command, program, args);
    }

    private JsonObject dispatchCommand(long id, String command,
            Program program, JsonObject args) {
        CommandHandler handler = handlers.get(command);
        if (handler == null) {
            return errorResponse(id, "Unknown command: " + command);
        }

        try {
            JsonElement result = handler.apply(program, args);
            return successResponse(id, result);
        } catch (Exception e) {
            Msg.error(this, "Error in command '" + command + "'", e);
            String msg = e.getMessage();
            if (msg == null || msg.isEmpty()) {
                msg = e.getClass().getSimpleName();
            }
            return errorResponse(id, msg);
        }
    }

    // -- Response builders ----------------------------------------

    private static JsonObject successResponse(long id, JsonElement result) {
        JsonObject resp = new JsonObject();
        resp.addProperty("id", id);
        resp.add("result", result);
        return resp;
    }

    private static JsonObject errorResponse(long id, String message) {
        JsonObject resp = new JsonObject();
        resp.addProperty("id", id);
        resp.addProperty("error", message);
        return resp;
    }

    /**
     * Helper to wrap a plain string as a JsonPrimitive.
     */
    static com.google.gson.JsonPrimitive jsonPrimitive(String value) {
        return new com.google.gson.JsonPrimitive(value);
    }

    private JsonObject currentLocationState() {
        JsonObject state = new JsonObject();
        var location = context.getCurrentLoc();
        if (location == null) {
            state.addProperty("present", false);
            return state;
        }
        state.addProperty("present", true);
        state.addProperty("address",
            "0x" + location.getAddress().toString(false));
        return state;
    }

    private static JsonObject undoState(Program program) {
        JsonObject state = new JsonObject();
        state.addProperty("program",
            GhidraMSCPlugin.qualifiedProgramName(program));
        state.addProperty("can_undo", program.canUndo());
        if (program.canUndo()) {
            state.addProperty("undo_name", program.getUndoName());
        }
        state.addProperty("can_redo", program.canRedo());
        if (program.canRedo()) {
            state.addProperty("redo_name", program.getRedoName());
        }
        return state;
    }

    private static JsonObject nonTransactionalSuccess(String operation,
            JsonObject requested, JsonObject oldState,
            JsonObject stored, String kind) {
        JsonObject result = new JsonObject();
        result.addProperty("operation", operation);
        result.addProperty("status", "success");
        result.add("requested", requested.deepCopy());
        result.add("old", oldState.deepCopy());
        result.add("stored", stored.deepCopy());
        addNonTransaction(result, kind);
        return result;
    }

    private static JsonObject nonTransactionalFailure(String operation,
            JsonObject requested, String status, String error,
            String kind) {
        JsonObject result = new JsonObject();
        result.addProperty("operation", operation);
        result.addProperty("status", status);
        result.add("requested", requested.deepCopy());
        result.addProperty("error", error);
        addNonTransaction(result, kind);
        return result;
    }

    private static void addNonTransaction(
            JsonObject result, String kind) {
        JsonObject transaction = new JsonObject();
        transaction.addProperty("kind", kind);
        transaction.addProperty("started", false);
        transaction.addProperty("committed", false);
        result.add("transaction", transaction);
    }
}
