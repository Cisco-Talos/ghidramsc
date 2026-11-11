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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra plugin that exposes a TCP server for GhidraMSC LLM tools.
 *
 * When loaded, the plugin opens a ServerSocket on localhost (default
 * port 18100) and dispatches incoming commands to
 * {@link CommandDispatcher}.  This lets LLM agents query the open
 * Ghidra project through the Python MCP layer without needing their
 * own JVM.
 *
 * Lifecycle:
 * <ol>
 *   <li>Ghidra loads the extension and calls {@link #init()}.</li>
 *   <li>The TCP server starts in a daemon thread.</li>
 *   <li>Each admitted client runs in its own daemon thread.</li>
 *   <li>On plugin dispose, the listener and active clients are closed.</li>
 * </ol>
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.DIAGNOSTIC,
    shortDescription = "TCP bridge for GhidraMSC LLM tools",
    description = "Exposes Ghidra analysis capabilities over a TCP socket "
        + "so that GhidraMSC's Python MCP server can relay LLM tool calls "
        + "to the running Ghidra GUI."
)
//@formatter:on
public class GhidraMSCPlugin extends ProgramPlugin {

    static final class ProgramOpenBlockedException extends RuntimeException {
        ProgramOpenBlockedException(String message) {
            super(message);
        }
    }

    private static final String PROP_PORT = "ghidramsc.port";
    private static final int DEFAULT_PORT = 18100;
    private static final Gson WIRE_GSON =
        new GsonBuilder().serializeNulls().create();
    private ServerSocket serverSocket;
    private Thread serverThread;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ClientAdmission clientAdmission = new ClientAdmission();
    private final Set<Socket> activeClients = ConcurrentHashMap.newKeySet();
    private final Set<Thread> clientThreads = ConcurrentHashMap.newKeySet();
    private final AtomicInteger clientThreadNumber = new AtomicInteger();
    private final ListenerLifecycle listenerLifecycle = new ListenerLifecycle();
    private CommandDispatcher dispatcher;
    private int port;

    public GhidraMSCPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();

        port = DEFAULT_PORT;
        String portProp = System.getProperty(PROP_PORT);
        if (portProp != null) {
            try {
                port = Integer.parseInt(portProp.trim());
            } catch (NumberFormatException e) {
                Msg.warn(this, "Invalid " + PROP_PORT + " value: " + portProp
                    + "; using default " + DEFAULT_PORT);
            }
        }

        dispatcher = new CommandDispatcher(this);
        startServer();
    }

    @Override
    protected void dispose() {
        stopServer();
        super.dispose();
    }

    // -- Program / GUI access (used by CommandDispatcher) ----------

    /**
     * Return the currently active program in the GUI.
     */
    public Program getActiveProgram() {
        return currentProgram;
    }

    /**
     * Return the current cursor location in the listing, or null.
     */
    public ghidra.program.util.ProgramLocation getCurrentLoc() {
        return currentLocation;
    }

    /**
     * Return the current selection in the listing, or null.
     */
    public ghidra.program.util.ProgramSelection getCurrentSel() {
        return currentSelection;
    }

    /**
     * Resolve a program by its project-relative, slash-qualified name.
     * Bare names address only files in the project root, so duplicate
     * leaf names in nested folders remain unambiguous.
     *
     * @param name program name (e.g. "firmware.elf" or "arm/firmware.elf")
     * @return the Program, or null if not found
     */
    public Program resolveProgram(String name) {
        String normalized = normalizeProgramName(name);
        if (normalized == null) {
            return null;
        }

        // Fast path: check current program.
        if (currentProgram != null
                && qualifiedProgramName(currentProgram).equals(normalized)) {
            return currentProgram;
        }

        // Check if ProgramManager already has it open.
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) {
            for (Program p : pm.getAllOpenPrograms()) {
                if (qualifiedProgramName(p).equals(normalized)) {
                    return p;
                }
            }
        }

        // Look through the project's programs.
        Project project = tool.getProject();
        if (project == null) {
            return null;
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        String[] parts = normalized.split("/");
        DomainFolder folder = root;
        for (int i = 0; i < parts.length - 1; i++) {
            folder = folder.getFolder(parts[i]);
            if (folder == null) {
                return null;
            }
        }
        DomainFile df = folder.getFile(parts[parts.length - 1]);
        if (df == null) {
            return null;
        }

        // Open via ProgramManager so the program appears as a
        // CodeBrowser tab with full write access.  The user can
        // then save it normally (Ctrl+S / File > Save).
        if (pm != null) {
            preflightProgramVersion(df, this, normalized);
            return pm.openProgram(df);
        }

        // Fallback: open read-only (should not happen in CodeBrowser).
        try {
            Object obj = df.getReadOnlyDomainObject(this,
                DomainFile.DEFAULT_VERSION,
                ghidra.util.task.TaskMonitor.DUMMY);
            if (obj instanceof Program) {
                return (Program) obj;
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to open program: " + normalized, e);
        }
        return null;
    }

    static void preflightProgramVersion(
            DomainFile file, Object consumer, String qualifiedName) {
        DomainObject probe = null;
        try {
            // Match ProgramManager's normal writable-open compatibility gate,
            // but never authorize an upgrade or recovery.  A read-only open
            // can load some legacy databases and therefore cannot predict the
            // upgrade prompt raised by the later normal open.
            probe = file.getDomainObject(
                consumer, false, false, TaskMonitor.DUMMY);
        } catch (VersionException e) {
            if (e.isUpgradable()) {
                throw new ProgramOpenBlockedException(
                    "Program open blocked for '" + qualifiedName
                        + "': Ghidra requires a data upgrade. Open this "
                        + "program in the Ghidra GUI and resolve the "
                        + "'Upgrade Program Data?' dialog, then retry the "
                        + "request on this same plugin connection.");
            }
            throw new ProgramOpenBlockedException(
                "Program open blocked for '" + qualifiedName
                    + "': its stored program version is not compatible with "
                    + "this Ghidra release. Resolve the Ghidra version "
                    + "mismatch, then retry the request on this same plugin "
                    + "connection.");
        } catch (IOException | CancelledException e) {
            // Preserve ProgramManager's established handling for non-version
            // open failures. This preflight exists only to avoid a hidden,
            // blocking upgrade prompt.
            Msg.debug(GhidraMSCPlugin.class,
                "Program version preflight deferred to ProgramManager for "
                    + qualifiedName + ": " + e.getMessage());
        } finally {
            if (probe != null) {
                probe.release(consumer);
            }
        }
    }

    /**
     * List every project file recursively using project-relative,
     * slash-qualified names.  Root files keep their bare names.
     */
    public String[] listProgramNames() {
        Project project = tool.getProject();
        if (project == null) {
            return new String[0];
        }
        DomainFolder root = project.getProjectData().getRootFolder();
        List<String> names = new ArrayList<>();
        collectProgramNames(root, "", names);
        Collections.sort(names);
        return names.toArray(new String[0]);
    }

    private static void collectProgramNames(DomainFolder folder,
            String prefix, List<String> names) {
        for (DomainFile file : folder.getFiles()) {
            names.add(prefix + file.getName());
        }
        for (DomainFolder child : folder.getFolders()) {
            collectProgramNames(child,
                prefix + child.getName() + "/", names);
        }
    }

    /**
     * Return the canonical name that callers can pass back as {@code binary}.
     */
    static String qualifiedProgramName(Program program) {
        if (program == null) {
            return "";
        }
        DomainFile file = program.getDomainFile();
        if (file != null) {
            String normalized = normalizeProgramName(file.getPathname());
            if (normalized != null) {
                return normalized;
            }
        }
        return program.getName();
    }

    private static String normalizeProgramName(String name) {
        if (name == null || name.isEmpty()) {
            return null;
        }
        String normalized = name.replace('\\', '/');
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.isEmpty()) {
            return null;
        }
        for (String part : normalized.split("/", -1)) {
            if (part.isEmpty() || ".".equals(part) || "..".equals(part)) {
                return null;
            }
        }
        return normalized;
    }

    // -- TCP server ------------------------------------------------

    private void startServer() {
        try {
            serverSocket = new ServerSocket(port, 5,
                java.net.InetAddress.getLoopbackAddress());
            serverSocket.setSoTimeout(1000); // 1s accept timeout for clean shutdown
            running.set(true);

            serverThread = new Thread(this::acceptLoop, "GhidraMSC-TCP-Server");
            serverThread.setDaemon(true);
            serverThread.start();

            Msg.info(this, listenerLifecycle.listening(port,
                clientAdmission.getMaxClients()));
        } catch (IOException e) {
            if (serverSocket != null) {
                try {
                    serverSocket.close();
                } catch (IOException closeError) {
                    e.addSuppressed(closeError);
                }
                serverSocket = null;
            }
            Msg.error(this, listenerLifecycle.bindFailed(port), e);
        }
    }

    private void stopServer() {
        running.set(false);
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // ignore
            }
        }
        if (serverThread != null) {
            try {
                serverThread.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        for (Socket client : new ArrayList<>(activeClients)) {
            try {
                client.close();
            } catch (IOException e) {
                // ignore
            }
        }
        long joinDeadline = System.nanoTime()
            + java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
        for (Thread clientThread : new ArrayList<>(clientThreads)) {
            try {
                long remaining = joinDeadline - System.nanoTime();
                if (remaining <= 0) {
                    break;
                }
                clientThread.join(
                    Math.max(1L,
                        java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
                            remaining)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        long liveHandlers = clientThreads.stream()
            .filter(Thread::isAlive)
            .count();
        if (liveHandlers > 0) {
            Msg.warn(this, "GhidraMSC server stopped with " + liveHandlers
                + " client handler(s) still finishing");
        }
        Msg.info(this, listenerLifecycle.stopped(port));
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = serverSocket.accept();
                if (!running.get()) {
                    client.close();
                    break;
                }
                ClientAdmission.Decision admission =
                    clientAdmission.tryAcquire();
                if (!admission.isAdmitted()) {
                    int maxClients = admission.getMaxClients();
                    Msg.warn(this, "Rejecting GhidraMSC client: client capacity "
                        + "reached (max_clients=" + maxClients + ")");
                    try {
                        JsonRpcFraming.writeFrame(
                            wireJson(
                                ListenerProtocol.capacityError(maxClients)),
                            client.getOutputStream());
                    } catch (IOException e) {
                        Msg.debug(this,
                            "Unable to send client capacity response: "
                                + e.getMessage());
                    }
                    client.close();
                    continue;
                }
                activeClients.add(client);
                Thread clientThread = null;
                try {
                    clientThread = new Thread(() -> {
                        try {
                            handleClient(client);
                        } finally {
                            activeClients.remove(client);
                            clientAdmission.release();
                            clientThreads.remove(Thread.currentThread());
                        }
                    }, "GhidraMSC-Client-"
                        + clientThreadNumber.incrementAndGet());
                    clientThread.setDaemon(true);
                    clientThreads.add(clientThread);
                    clientThread.start();
                } catch (RuntimeException | Error e) {
                    if (clientThread != null) {
                        clientThreads.remove(clientThread);
                    }
                    activeClients.remove(client);
                    clientAdmission.release();
                    try {
                        client.close();
                    } catch (IOException closeError) {
                        // The original construction/start failure is primary.
                    }
                    if (running.get()) {
                        Msg.error(this,
                            "Unable to start GhidraMSC client handler", e);
                    }
                }
            } catch (SocketTimeoutException e) {
                // Normal -- lets us check the running flag.
            } catch (IOException e) {
                if (running.get()) {
                    Msg.error(this, "Accept error", e);
                }
            }
        }
    }

    private void handleClient(Socket client) {
        try (InputStream in = client.getInputStream();
             OutputStream out = client.getOutputStream()) {

            while (running.get() && !client.isClosed()) {
                String raw;
                try {
                    raw = JsonRpcFraming.readFrame(in);
                } catch (IOException e) {
                    JsonRpcFraming.writeFrame(
                        wireJson(PluginProtocol.protocolError(
                            "Invalid request frame: " + e.getMessage())), out);
                    break;
                }
                if (raw == null) {
                    break; // client disconnected
                }

                JsonObject response = PluginProtocol.handleRequest(raw,
                    request -> {
                        JsonObject listenerResponse =
                            ListenerProtocol.handleConfiguration(request,
                                clientAdmission);
                        if (listenerResponse != null) {
                            if (listenerResponse.has("result")) {
                                Msg.info(this,
                                    "GhidraMSC listener max clients set to "
                                        + clientAdmission.getMaxClients());
                            } else {
                                Msg.warn(this,
                                    "Rejected GhidraMSC listener configuration: "
                                        + listenerResponse.get("error")
                                            .getAsString());
                            }
                            return listenerResponse;
                        }
                        String command = request.has("command")
                            && request.get("command").isJsonPrimitive()
                            ? request.get("command").getAsString()
                            : "<invalid>";
                        Msg.debug(this,
                            "GhidraMSC request command=" + command);
                        return dispatcher.dispatch(request);
                    });

                if (response.has("error") && response.has("id")
                        && response.get("id").isJsonPrimitive()
                        && response.get("id").getAsJsonPrimitive().isNumber()
                        && response.get("id").getAsLong() == 0) {
                    Msg.warn(this,
                        "Rejected malformed GhidraMSC protocol request");
                }

                JsonRpcFraming.writeFrame(wireJson(response), out);
            }
        } catch (IOException e) {
            if (running.get()) {
                Msg.warn(this, "Client connection error: " + e.getMessage());
            }
        } catch (Exception e) {
            Msg.error(this, "Unexpected error handling client", e);
        } finally {
            try {
                client.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    static String wireJson(JsonObject response) {
        return WIRE_GSON.toJson(response);
    }

}
