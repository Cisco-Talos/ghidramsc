# GhidraMSC

Expose a Ghidra reverse-engineering project through four interfaces:

1. **Command-line** -- one-shot tool calls from a terminal or shell script.
2. **HTTP server** -- a local REST-style API that keeps the JVM warm
   between requests.
3. **MCP (headless)** -- a [Model Context Protocol](https://modelcontextprotocol.io/)
   stdio server that publishes every non-GUI operation as a typed tool for LLM
   hosts.
   Starts its own JVM; the Ghidra GUI cannot be open at the same time.
4. **MCP (plugin/GUI)** -- same MCP interface, but connects to a running
   Ghidra GUI over TCP instead of starting its own JVM.  No project-lock
   conflict; the LLM sees the same programs you have open in Code Browser.

The public registry contains 90 tools (40 queries, 50 mutations). CLI, HTTP,
and headless MCP expose the same 85 non-GUI tools. Plugin MCP exposes those 85
plus five CodeBrowser-only tools. Mutation persistence also differs by
execution mode as described below. Pick the interface whose lifetime and GUI
requirements match the workflow.

The headless interfaces use [pyghidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
to load the Ghidra analysis framework inside the same Python process, giving
direct access to the Java API without subprocesses or Jython. Plugin MCP instead
connects to the Java extension in an already-running Ghidra GUI.

Start with [USAGE.md](USAGE.md) for a short end-to-end guide. Agents using MCP
should also read [LLM_README.md](LLM_README.md) for tool selection and result
handling.

For a complete task-oriented walkthrough with Ghidra 12.1.4 screenshots,
use the [standalone user manual PDF](docs/user-manual/GhidraMSC_User_Manual.pdf).
Its [editable source and offline build instructions](docs/user-manual/README.md)
are retained alongside the image assets.

---

## Requirements

- Python 3.10 or newer, with a matching JPype wheel for the chosen interpreter
- Ghidra 12.1.4 (the current package's primary tested release;
  bundled pyghidra wheels are under `Ghidra/Features/PyGhidra/pypkg/dist/`)
- PyGhidra + JPype importable by the Python interpreter used for CLI, HTTP,
  or headless MCP (Ghidra bundles their wheels)

## Cross-version project data

Ghidra program data is not guaranteed to remain readable by older Ghidra
versions after a newer version saves it. Programs within one project may have
different stored versions, so upgrading or saving one program does not prove
that every program in the project was upgraded.

When a headless interface opens program data last saved by an older Ghidra
version, Ghidra may upgrade that program **in memory without displaying the
GUI's Upgrade Program Data prompt**. The program can report `dirty: true`
immediately after opening, before any GhidraMSC mutation. GhidraMSC does not
automatically save this conversion: stopping the headless process without
calling `save_program` or using a CLI command's `--save` option discards the
in-memory upgrade, and a later open may repeat it.

Calling `save_program`, using `--save`, or approving and saving an upgrade in
the Ghidra GUI persists the newer program-data format. The older Ghidra version
may then be unable to open that program. If continued access from multiple
Ghidra versions matters, make a separate project copy or backup for each
version before opening it with the newer version. Record the dirty state at
initial open; `get_program_save_state` alone cannot distinguish a version upgrade
from later analysis or user mutations.

## Installation

Ghidra includes the PyGhidra and JPype wheels. If your selected Python can
already `import pyghidra`, use it directly. If it cannot, install from the
bundled wheel directory into that interpreter, replacing the path below:

```text
python -m pip install --no-index --find-links "/path/to/ghidra/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
```

No `pip install` of GhidraMSC itself is needed -- run it as
`python -m ghidramsc` from the repo root.

## Concepts: project vs. program

A Ghidra **project** (`.gpr` file + `.rep/` folder) can contain one or
more imported **programs** (binaries).  GhidraMSC configuration works at
two levels:

1. **`ghidramsc.toml`** tells GhidraMSC where the Ghidra installation
   and project live.
2. **`-b <name>`** tells it which program *inside* that project to
   query. It is required for program-scoped one-shot CLI commands;
   project-level `list_programs` takes no binary selector. For the HTTP and
   MCP servers, `-b` sets a *default* binary but is optional -- the binary
   can be specified per-request instead. Alternatively, set the
   `GHIDRAMSC_BINARY` environment variable and omit `-b`.

`-b` is **not a filesystem path**.  It is the project-relative name of a
program that has already been imported into the Ghidra project.  Use the
exact slash-qualified value returned by `list_programs`, such as
`sample.bin` for a root program or `firmware/arm/sample.bin` for a nested
program.  Bare names address only the project root; duplicate leaf names in
different folders must be selected by their qualified names.  The binary
must already be imported and analyzed -- GhidraMSC does not import files.

### Example

Suppose your Ghidra project is at:

```
C:/ghidra_projects/
    MyProject.gpr          <-- project file
    MyProject.rep/          <-- project data
```

And inside the Ghidra GUI you imported a file called `firmware.elf`.
Your config and commands would be:

```toml
# ghidramsc.toml
[ghidramsc]
ghidra_install_dir = "C:/tools/ghidra_12.1.4_PUBLIC"
project_path       = "C:/ghidra_projects"
project_name       = "MyProject"
```

```bash
python -m ghidramsc decompile_function -b firmware.elf 0x1c908
#                              ^^^^^^^^^^^^^^
#                 program name inside the project, NOT a file path
```

## Configuration

Copy `ghidramsc.toml.example` to `ghidramsc.toml` and edit the paths.
CLI, HTTP, and headless MCP use this config. GUI MCP connects to the open
CodeBrowser project and does not read it.

```toml
[ghidramsc]
ghidra_install_dir = "C:/tools/ghidra_12.1.4_PUBLIC"
project_path = "C:/ghidra_projects"
project_name = "MyProject"
# server_port = 13100
```

| Key                  | Meaning                                                    |
|----------------------|------------------------------------------------------------|
| `ghidra_install_dir` | Absolute path to the Ghidra installation root              |
| `project_path`       | Directory that **contains** the `.gpr` file (not the `.gpr` itself) |
| `project_name`       | The `.gpr` filename without the `.gpr` extension           |
| `server_port`        | HTTP server port, default 13100 (optional)                 |

Config is loaded from (in order):
1. `GHIDRAMSC_CONFIG` environment variable (path to toml)
2. `./ghidramsc.toml` in the working directory
3. `ghidramsc.toml` next to the package

Any key can be overridden with an env var prefixed `GHIDRAMSC_`:

```
GHIDRAMSC_GHIDRA_INSTALL_DIR=C:/other/ghidra
GHIDRAMSC_PROJECT_NAME=OtherProject
```

The binary/program name can also be set via environment variable:

```
GHIDRAMSC_BINARY=firmware.elf
```

When `GHIDRAMSC_BINARY` is set, the `-b` flag becomes optional on all
program-scoped commands and when starting `serve` or `mcp`.

---

## Project locking

Ghidra allows only **one process** to hold a project open at a time.
The HTTP server, headless MCP server, and `--no-server` CLI all open the
project directly and hold a filesystem lock.  Consequences:

- You cannot run the HTTP server and headless MCP server simultaneously
  on the same project.
- `--no-server` CLI will fail with a `LockException` while a server
  (HTTP or headless MCP) is already running.
- The **Ghidra GUI** also locks the project.  Headless commands will
  fail while the GUI has the project open, and vice versa.
- To switch between interfaces, shut down the current one first
  (`POST /shutdown` for HTTP, close stdin / stop the host for MCP).

**GUI mode** (`--mode gui`) is the exception: it connects to the
already-running Ghidra GUI over TCP and shares the GUI's project lock.
This means there is no lock conflict between the GUI and GUI-mode MCP.
Use GUI mode when you want LLM access alongside the GUI. The former
`--plugin` flag remains a deprecated alias for `--mode gui`.

### Headless project-owner override

Most users do not need to set a project owner: Ghidra normally uses the
operating-system account that starts the JVM. If a local project was created
under a different recorded owner, the headless interfaces accept an optional
`--owner <project-owner>` startup override:

```bash
python -m ghidramsc list_programs --owner project_owner
python -m ghidramsc serve --owner project_owner
python -m ghidramsc mcp --mode headless --owner project_owner
```

The override sets Java's `user.name` before the local JVM starts. It is
available to one-shot CLI tools, `serve`, and headless MCP only; GUI mode and
its deprecated `--plugin` alias reject it. Because a running process cannot
change its Java identity, an owner-bearing one-shot command bypasses HTTP
server auto-forwarding and starts its own headless JVM. The command also fails
if a JVM has already started in that Python process. This option configures the
headless Ghidra process, not MCP protocol state.

---

## Available tools

GhidraMSC currently exposes 90 canonical public tools: 40 queries and 50 mutations. CLI, HTTP, and headless MCP expose 85 shared tools; GUI MCP also exposes five CodeBrowser-context tools. The [public tool catalog](TOOL_CATALOG.md) lists every tool, exact JSON parameter, type, required/default state, mode, bound, and conditional use. It also explains the MCP/HTTP `binary` selector and CLI syntax differences.

Start with `list_programs` to get an exact project-relative program identity, then use `get_program_info`, `get_program_save_state`, `list_functions`, or `decompile_function` for read-only inspection. Mutations such as `set_function_name` change the open program; save explicitly with `save_program` or an eligible one-shot CLI `--save` after checking the result. See the catalog for the complete operation list and [LLM guide](LLM_README.md) for analysis workflows.

---

## 1. Command-line interface

Run any query as a one-shot shell command.  Each invocation starts a
JVM, opens the Ghidra project, runs the query, prints the result, and
exits.

```
python -m ghidramsc <tool> -b <program_name> [args...]
```

Every program-scoped tool command needs a binary/program name. Supply it with
`-b` / `--binary`, or set the `GHIDRAMSC_BINARY` environment variable.
`list_programs`, `serve`, `shutdown`, and `mcp` do not require one.

**Flags common to one-shot tool commands:**

| Flag             | Purpose                                           |
|------------------|---------------------------------------------------|
| `-b`, `--binary` | Slash-qualified project-relative name from `list_programs` (or set `GHIDRAMSC_BINARY`) |
| `-c`, `--config` | Path to `ghidramsc.toml`                          |
| `--owner`         | Set the Ghidra project owner before starting the local headless JVM |
| `-o`, `--output` | Write result to a file (in addition to stdout)    |
| `-q`, `--quiet`  | Suppress stdout (use with `-o`)                   |
| `--no-server`    | Skip server auto-detection; always start a fresh JVM |

Mutation subcommands additionally accept `--save` and `--save-comment TEXT`.
CLI commands return a nonzero exit code for a failed or partial result in both
direct and HTTP-forwarded mode while emitting the returned payload unchanged.
Success and no-change results return zero. A failed or partial mutation does
not trigger `--save`, even if its result reports a committed transaction; inspect
the reported state and make any later persistence decision explicitly.
For a successful or no-change mutation, `--save` performs `save_program` before the
selected program closes, then includes the exact save result in the mutation
output's `persistence` field. `--save-comment` requires `--save`. If an HTTP
service is active, the mutation and save are sent to that same persistent
service and selected program. A requested save that does not complete exits
nonzero; no mutation command is saved merely because its CLI process exits.

### CLI examples

```bash
# List all functions
python -m ghidramsc list_functions -b my_binary

# Decompile a function
python -m ghidramsc decompile_function -b my_binary 0x1c908

# Decompile and save to file
python -m ghidramsc decompile_function -b my_binary 0x1c908 -o decomp.c

# Find functions matching a regex
python -m ghidramsc search_functions_by_name -b my_binary "init_.*"

# Get function metadata as JSON
python -m ghidramsc get_function_info -b my_binary 0x1c908

# Decompile multiple addresses
python -m ghidramsc decompile_functions -b my_binary "0x1c908,0x1d000,0x1e400"

# Cross-references to an address
python -m ghidramsc list_references_to_address -b my_binary 0x1c908

# Rename a function and explicitly persist it in the same invocation
python -m ghidramsc set_function_name -b my_binary 0x1c908 init_network --save

# Filter strings (filter_str is positional, not a flag)
python -m ghidramsc list_strings -b my_binary socket

# Export all user annotations to JSON
python -m ghidramsc export_annotations -b my_binary -o annotations.json
```

### Server-aware CLI

When an HTTP server is running (see next section), the CLI automatically
forwards queries to it instead of starting a new JVM.  This is
transparent -- the same commands work either way.  The `-b` flag is
forwarded as a per-request binary override so the server queries the
correct program.  Pass `--no-server` to force a cold JVM start.
Passing `--owner` also forces a cold JVM start because the owner must be set
before that process starts Java.

If an HTTP query receives no usable response, the CLI exits with an
"outcome unknown" error. Inspect the current program state before retrying
a mutation; the CLI does not start a direct JVM after that query attempt.

---

## 2. HTTP server API

The HTTP server starts the JVM once and holds the Ghidra project open so
that queries complete in milliseconds instead of waiting for a cold
start each time.  Programs (binaries) are opened on demand -- you can
query any binary in the project without restarting the server.

### Starting and stopping

```bash
# Start with a default binary:
python -m ghidramsc serve -b my_binary

# Or start without a default (binary is then required only for
# program-scoped requests):
python -m ghidramsc serve

# In another terminal, queries now hit the warm server:
python -m ghidramsc decompile_function -b my_binary 0x1c908    # fast

# Shut down:
python -m ghidramsc shutdown
```

The port defaults to 13100.  Override it with `--port` or the
`server_port` key in `ghidramsc.toml`.  On startup the server writes a
`.ghidramsc_port` file to the working directory; the CLI and HTTP client
use this file for auto-discovery.

If the project has a different recorded owner, add
`--owner <project-owner>` when starting the server. The owner applies to the
server's headless JVM for its entire lifetime.

Project inventory does not need a default binary. Use `GET /programs` or call
`list_programs` through `POST /query`, then pass one returned slash-qualified
identity as the top-level `binary` value on later program-scoped requests.

**Stale port file:** If the server crashes or is killed, the
`.ghidramsc_port` file may not be cleaned up. The CLI checks server health
before forwarding a query and uses its direct JVM path if the server is
unavailable. Delete the stale file to skip that unnecessary check:

```bash
rm .ghidramsc_port          # Linux/macOS
del .ghidramsc_port          # Windows
```

### Endpoints

All responses are `application/json`.

**`GET /health`**

Returns server status, the default binary (if any), and the list of
currently cached (opened) programs.

```json
{"status": "ok", "default_binary": "my_binary", "cached": ["my_binary"]}
```

**`GET /programs`**

Returns all programs (binaries) imported into the Ghidra project.

```json
{"programs": ["firmware.elf", "libfoo.so", "libbar.so"]}
```

**`POST /query`**

Execute a query.  Send a JSON body with `command` and `args`.  To
query a binary other than the default, add a top-level `binary` key:

```bash
# Uses the default binary:
curl -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "decompile_function", "args": {"addr_hex": "0x1c908"}}'

# Override to a specific binary:
curl -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "decompile_function", "args": {"addr_hex": "0x1c908"}, "binary": "libfoo.so"}'
```

The response body is the query result.  Dict-returning queries produce
the dict directly; string-returning queries wrap the result:

```json
{"result": "// Function: init_network\n..."}
```

Malformed, browser-originated, unknown, and schema-invalid requests
are rejected with an HTTP 4xx response before tool dispatch. There is no
general HTTP request-body size cap; the server reads the declared nonnegative
`Content-Length` before parsing and dispatch. Application-level
tool failures and error payloads return HTTP 422 without changing the tool's
payload shape; unexpected dispatch exceptions return HTTP 500. Successful
results return HTTP 200. Always inspect the response body as well as the status.

**`POST /shutdown`**

Gracefully stop the server.

```json
{"status": "shutting_down"}
```

### HTTP examples with curl

```bash
# Health check
curl http://127.0.0.1:13100/health

# Decompile
curl -s -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "decompile_function", "args": {"addr_hex": "0x1c908"}}'

# List functions
curl -s -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "list_functions", "args": {}}'

# Function info (returns JSON directly)
curl -s -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "get_function_info", "args": {"addr_hex": "0x1c908"}}'

# Rename a function
curl -s -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "set_function_name", "args": {"addr_hex": "0x1c908", "new_name": "init_network"}}'

# Shut down
curl -X POST http://127.0.0.1:13100/shutdown \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Local service trust boundary

The HTTP server and GUI plugin bind to loopback only. They do not authenticate
individual local clients: the supported threat model trusts processes running
as the same operating-system user. Do not expose either port through port
forwarding, a reverse proxy, a shared container/network namespace, or a
multi-user host where other users can reach your loopback services.

The transports no longer impose the older 1 MiB request-frame cap; individual
tools still have their documented bounds. The HTTP server uses a blocking read
for the full declared body, with no global frame-size or read-time limit. A
trusted local client can consume substantial memory with a large body or hold
the single HTTP request handler waiting by sending fewer bytes than declared.
The HTTP service requires
`application/json`, rejects requests carrying an `Origin` header, validates the
loopback `Host`, and validates tool arguments before dispatch. The plugin TCP
service caps concurrent clients and returns structured errors for malformed
JSON/envelopes. These controls block browser-originated requests and resource
some malformed requests; they are not authentication or a general resource
limit against a hostile local process.

The GUI plugin permits 12 simultaneous TCP client connections by default. This
limit counts MCP processes or other clients holding plugin
sockets, not LLM agents, tasks, or tool calls that an MCP host multiplexes over
one connection. Codex, VS Code, Claude, and other applications can connect at
the same time while the combined number of live plugin client sockets remains
within that limit. Additional connections receive a structured
`client_capacity` error and are closed. An MCP process can explicitly change
the running listener's global limit with `--max-clients N`; the last processed
positive override wins, lowering the limit does not evict existing clients,
and new clients remain rejected until the active count falls below the limit.
The configuring process must first hold a slot under the current limit.

Accepted plugin sockets do not have an idle/read timeout. Each Python plugin
handle performs each command exactly once and never reconnects or replays after
a transport or response-protocol failure. It validates every response ID and
the result/error envelope, then permanently discards the failed socket. A lost
or invalid mutation response is reported as an explicit ambiguous outcome, and
the caller must inspect current Ghidra state before deciding whether to retry.
Callers needing concurrency should use independent handles. Plugin shutdown
closes the listener and all active sockets, gives their daemon handlers one
bounded interval to finish, and warns if an in-flight handler is still winding
down.

### Python client

GhidraMSC includes a thin Python HTTP client (`ghidramsc.client`):

```python
from ghidramsc.client import server_health, send_query, shutdown_server

# Check if server is running
health = server_health()         # None if unreachable
print(health)                    # {"status": "ok", "default_binary": "my_binary", "cached": [...]}

# Run a query
result = send_query("decompile_function", {"addr_hex": "0x1c908"})
print(result["result"])

# Structured query
info = send_query("get_function_info", {"addr_hex": "0x1c908"})
print(info["name"], info["signature"])

# Shut down
shutdown_server()
```

---

## 3. MCP (Model Context Protocol)

The MCP interface lets any MCP-capable LLM host (VS Code Copilot, Claude
Desktop, Cursor, etc.) discover and call the selected operations as typed tools.

GhidraMSC implements [MCP](https://modelcontextprotocol.io/) over stdio
using JSON-RPC 2.0. The host spawns the process and GhidraMSC publishes
registry-generated parameter schemas for the selected toolset: virtual `all`
contains 85 tools in headless mode and 90 in GUI mode.

There are two modes:

| Mode | Flag | How it works |
|------|------|--------------|
| **Headless** | `--mode headless` (default) | GhidraMSC reads `ghidramsc.toml`, boots a JVM with pyghidra, and opens the Ghidra project itself. Locks the project -- the Ghidra GUI cannot be open at the same time. |
| **GUI** | `--mode gui` | Connects over TCP to a running Ghidra GUI with the GhidraMSC plugin loaded. No project lock conflict. Mutations appear in the GUI and can be saved explicitly; undo depends on Ghidra's active-program undo history. Also provides 5 GUI-context tools. |

Every program-scoped MCP tool accepts an optional `binary` parameter. If
omitted, the default binary (from `-b` or `GHIDRAMSC_BINARY`) is used. This lets
you query multiple binaries in the same project without restarting.
`list_programs` and the five CodeBrowser-only tools do not accept `binary`.
When no default is configured, call `list_programs()` first without arguments,
select its exact slash-qualified result, and pass that value as `binary` on
every later program-scoped call.

### Running the MCP server

```bash
# Headless mode with a default binary:
python -m ghidramsc mcp --mode headless -b my_binary

# Optional: start the headless JVM as the project's recorded owner:
python -m ghidramsc mcp --mode headless --owner project_owner -b my_binary

# GUI mode (connect to the running Ghidra GUI):
python -m ghidramsc mcp --mode gui -b my_binary

# GUI mode with an explicit global listener limit:
python -m ghidramsc mcp --mode gui --max-clients 20 -b my_binary

# Without a default (call list_programs first, then specify binary on each
# program-scoped call):
python -m ghidramsc mcp --mode headless
```

This blocks on stdin.  You do not run this manually -- the LLM host
spawns it.

### Client configuration examples

See [USAGE.md](USAGE.md) for VS Code,
Codex/ChatGPT, and Claude host configurations. Each example uses headless mode;
change the mode value to connect to the running Ghidra GUI.

With the default virtual `all` toolset, headless publishes 85 non-GUI tools and
GUI mode publishes all 90. A named toolset publishes its ordered entries
that are available in the selected mode. Enable only one project-owning
headless configuration at a time; GUI mode shares the running GUI project.

### How it works

1. The host connects over stdio and sends `initialize` with its preferred
   handshake-era protocol revision.
2. GhidraMSC responds with the requested supported revision, or offers its
   latest supported handshake revision, plus its capabilities (tools).
3. The host calls `tools/list` to discover the selected effective tool surface
   and its typed parameter schemas (85 for headless `all`, 90 for plugin `all`).
4. The host (or the LLM) calls `tools/call` with the tool name and
   arguments.
5. GhidraMSC executes the query against the loaded Ghidra project and
   returns the result.
6. The process stays alive until the host closes stdin.

### MCP protocol details

- Protocol versions: `2024-11-05`, `2025-03-26`, `2025-06-18`, and
  `2025-11-25` (latest supported handshake revision)
- Transport: stdio (line-delimited JSON, one JSON-RPC message per line)
- Server info: `{"name": "ghidramsc", "version": "0.9.0rc1"}`
- Capabilities: `{"tools": {}}`
- Supported methods: `initialize`, `notifications/initialized`,
  `tools/list`, `tools/call`, `ping`
- Tool annotations are included for revisions `2025-03-26` and later.
- For revisions `2025-06-18` and later, JSON-object tool results include
  `structuredContent` while retaining the existing text content for compatible
  rendering and older clients.
- Unsuccessful `tools/call` results retain their text and `isError` and add
  `_meta["ghidramsc/errorCategory"]` at every supported revision. Stable
  values are `not_found`, `validation`, `unavailable_tool`, `exception`, and
  `application_failure`. The broad last value covers native failures without
  a more specific known meaning. JSON-RPC protocol errors are separate.
- The stateless `2026-07-28` protocol era is not supported.
- Set `GHIDRAMSC_MCP_TIMING=1` when starting an MCP process to emit one
  `GHIDRAMSC_MCP_TIMING` JSON record on stderr after each response flush.
  Records contain an opaque request ID and milliseconds for dispatch, program
  acquisition, query, serialization, write/flush, and total server time; they
  contain no tool arguments or project/program identity. In GUI mode, plugin
  program acquisition is included in query time and marked unobservable.
  Unset the variable for ordinary operation; stdout responses are unchanged.

Tool schemas are generated from the central tool registry
(`tool_registry.py`).  Parameter types map to JSON Schema
(`str` -> `string`, `int` -> `integer`, `List[str]` -> `array`).

### LLM reference

See [LLM_README.md](LLM_README.md) for agent workflows, result handling,
JSON file formats, and common mistakes to avoid.

### Tool context cost and optimization

Every MCP tool you have enabled is included in the system prompt on
**every message** you send.  Each tool adds its name, description, and
full parameter schema to the context window -- roughly 100-300 tokens
per tool. With all 90 plugin-mode `all` tools enabled, this can consume
10,000-15,000 tokens of context before you type a single word.

This matters because:

- It reduces the space available for conversation history, code
  snippets, and reasoning.
- It increases cost (tokens are billed on both input and output).
- LLM tool selection accuracy degrades as the tool count rises past
  about 40-60 tools.  The model is more likely to pick the wrong tool
  or hallucinate parameters when the menu is long.

Choose the advertised MCP surface at launch with `--toolset` (or `-t`):

| Name | Requested/file count | Headless effective | GUI effective | Intended surface |
|------|---------------------:|-------------------:|-----------------:|------------------|
| `minimal` | 5 | 5 | 5 | Fast read-only orientation: program identity, metadata, strings, functions, and decompilation |
| `inspect` | 20 | 20 | 20 | Read-only binary understanding without persistent analysis changes |
| `default` | 44 | 44 | 44 | Full reversing and report production, including semantic annotation and exact code recovery |
| `vuln-research` | 59 | 59 | 59 | Vulnerability research tools with richer typing, prototypes, structures, batch annotation, and export |
| `most` | 75 | 75 | 75 | Broad expert surface excluding GUI-current-context, enum, bookmark, and union/bitfield families |
| `all` | 90 | 85 | 90 | Every registry tool available in the selected mode; this is the launch default |

```text
python -m ghidramsc mcp --mode headless --toolset minimal
python -m ghidramsc mcp --mode headless --toolset inspect
python -m ghidramsc mcp --mode gui --toolset default
python -m ghidramsc mcp --mode headless --toolset vuln-research
```

Named profiles are adjustable text files in the single packaged
`ghidramsc/toolsets` directory. Pass the lowercase profile name without a path
or filename extension. Blank lines and full lines whose first non-whitespace
character is `#` are ignored, so files can document sections and membership
rationale. A tool name may also have a trailing inline `#` comment when at
least one whitespace character separates the name and `#`, for example
`decompile_function  # primary semantic view`. A `#` joined directly to the
name remains an invalid tool name. Restart the MCP process after changing a
profile so it loads the new list; a Ghidra restart is not required for this
data-only change. An MCP host may still hide additional tools in its own UI.

---

## 4. GUI mode

GUI mode connects the MCP server to a running Ghidra GUI instead of
launching its own headless JVM.  This avoids the project-locking issue
and gives the LLM access to the same programs you have open in the
CodeBrowser.

### Installing the plugin

A pre-built Ghidra 12.1.4 plugin zip is included at
`plugin/dist/GhidraMSCPlugin.zip`. The plugin is compiled Java bytecode, so
that zip works on any supported OS running the target Ghidra release.

1. In Ghidra: **File > Install Extensions**, browse to
   `plugin/dist/GhidraMSCPlugin.zip`, install, and restart Ghidra.

2. Open a project and open at least one binary in a **CodeBrowser** window.

3. In that CodeBrowser window, select **File > Configure... > Configure All
   Plugins**, find `GhidraMSCPlugin`, and check it.  This is separate from the
   checkbox in the Project Manager's **Install Extensions** dialog.  Because
   GhidraMSC is a `ProgramPlugin`, it appears in the CodeBrowser plugin list,
   not the Project Manager's plugin list.

4. Once enabled, the plugin starts a TCP server on `127.0.0.1:18100`
   automatically.  The Ghidra application log should contain:

   ```text
   GhidraMSC TCP server listening on 127.0.0.1:18100
   ```

If an MCP client reports `Connection refused` or Windows error 10061, first
verify that `GhidraMSCPlugin` is checked in the **CodeBrowser's** plugin
configuration and that the listener message appears in the Ghidra log.  Merely
checking the extension in **Install Extensions** does not activate the plugin
inside a CodeBrowser tool.

When a tool targets a closed program whose stored data requires a Ghidra
upgrade, the plugin checks compatibility without opening an upgrade dialog.
It returns an error naming the program and **Upgrade Program Data?** instead of
letting the MCP request time out behind that modal. To use the legacy program,
open it manually in Ghidra and approve the upgrade only when that change is
intended; after it opens successfully, retry on the same MCP connection. If you
cancel instead, the connection still remains usable for other programs. The
plugin never approves an upgrade or save automatically.

#### Building from source (optional)

If you modify the plugin Java code, use JDK 25 and Gradle 9.7.1, the version
selected by Ghidra 12.1.4's `support/gradle/gradle-wrapper.properties`.
Ghidra's wrapper does not include the Gradle distribution. From the repository
root, use an existing Gradle 9.7.1 executable and cached dependencies for a
network-free build:

```powershell
$env:JAVA_HOME = "C:\path\to\jdk-25"
$env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra_12.1.4_PUBLIC"
$env:GRADLE_USER_HOME = "C:\path\to\populated-gradle-cache"
$gradleExe = "C:\path\to\gradle-9.7.1\bin\gradle.bat"
& $gradleExe --offline --no-daemon -p plugin clean buildExtension
```

On Linux or macOS, set the same three environment variables and run
`/path/to/gradle-9.7.1/bin/gradle --offline --no-daemon -p plugin clean buildExtension`.

The new zip appears in `plugin/dist/`. For an upgrade, stop Ghidra and replace
the one installed `GhidraMSCPlugin` directory from the new ZIP while Ghidra is
closed; do not leave both a user-level and installation-level copy. Start
Ghidra once, confirm the plugin remains enabled in CodeBrowser, and restart the
MCP host only if its cached tool schemas changed.

To run the plugin's Java unit tests, use the same environment and executable:

```powershell
& $gradleExe --offline --no-daemon -p plugin test --console=plain
```

### How mutations work in GUI mode

When the LLM modifies a binary that is not currently active in the
CodeBrowser, the plugin opens it via ProgramManager. It appears as a
new tab in the CodeBrowser with write access. Mutation responses report their
transaction and final read-back. In particular:

- **Undo** applies only to an entry in the active program's Ghidra undo history.
  Some committed edits, including observed memory changes, can leave the
  program dirty without a corresponding undo entry. `undo_gui_transaction`
  cannot restore those edits. Confirm the active program with
  `get_cursor_address` before using it; use a project copy for changes that
  must be disposable.
- **Save** is explicit -- use `save_program`, Ctrl+S, or File > Save to
  persist changes when you are satisfied. Closing a headless project does not
  implicitly save cached programs.
- On project close, reconcile unsaved changes and verify the saved state after
  reopening. Do not rely on a save prompt or on undo availability as proof that
  every edit was restored.
- Mutation results are classified after the transaction closes and final state
  is read back. `rolled_back` means restoration was verified; `failed` means
  the outcome or final state needs attention. Check `transaction.committed`
  before retrying a failed call so a committed edit is not applied twice.

### GUI-mode CLI flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--mode` | `headless` | Select `headless` or `gui` explicitly. |
| `--plugin` | off | Deprecated compatibility alias for `--mode gui`; cannot be combined with `--mode`. |
| `--plugin-host` | `127.0.0.1` | TCP host for the plugin server; requires `--mode gui`. |
| `--plugin-port` | `18100` | TCP port for the plugin server; requires `--mode gui`. |
| `--max-clients` | omitted | Set a positive global limit on the already-running plugin listener. Requires `--mode gui`; omission leaves the current listener limit unchanged. |

### GUI-context tools (GUI mode only)

These tools read the current GUI state and are only available in GUI mode.
They have no parameters.

| Tool | Returns | Purpose |
|------|---------|---------|
| `get_cursor_address` | dict | The address at the cursor position plus the active program name. |
| `get_function_at_cursor` | dict | Name, address, signature, and size of the function at the cursor. |
| `get_gui_selection` | dict | Start address, end address, and byte count of the current selection. Returns `null` start/end with `num_addresses: 0` when nothing is selected. |

**Important:** `set_cursor_address` and `undo_gui_transaction` operate on the program currently
open in the Ghidra Code Browser, regardless of the `-b` default binary.
Mutations (e.g. `set_comment_at_address`) accept a `binary` parameter and target
the correct program even if a different tab is active.  However, `undo_gui_transaction`
has no `binary` parameter -- it always targets the Code Browser's active
program.  Changes made to a binary that is *not* open in Code Browser
cannot be undone via the `undo_gui_transaction` tool; they require manual reversal.

---

## Python API

Use GhidraMSC as a library for custom scripts:

```python
from ghidramsc.config import load_config
from ghidramsc.bridge import GhidraBridge
from ghidramsc import queries

cfg = load_config("ghidramsc.toml")
bridge = GhidraBridge(cfg)

# Project-level access (query multiple binaries):
with bridge.open_project() as project:
    ctx = project.get_program("my_binary")
    print(queries.decompile_function(ctx, "0x1c908"))

    # Switch to another binary without restarting:
    ctx2 = project.get_program("other_binary")
    print(queries.list_functions(ctx2))

    # List all programs in the project:
    print(project.list_programs())

# Single-program access (backward compatible):
with bridge.open_program("my_binary") as ctx:
    print(queries.list_functions(ctx))
    info = queries.get_function_info(ctx, "0x1c908")
    print(info["name"], info["signature"])
```

## Testing

```text
python -m pytest tests/ -v
```

The Python suite mocks the Ghidra Java API, so it needs no JVM or project.
Java handler/dispatcher tests are a build-time check described in the optional
plugin build section above.

Neither suite is live-project acceptance. Runtime claims require a separate
test against a disposable Ghidra project.

## Performance notes

- `list_functions` and `list_strings` can return very large output on big
  binaries (145KB+ for 6000+ functions).  Use `search_functions_by_name` or `list_strings`
  with `filter_str` to narrow results when possible.
- `search_memory_bytes` with broad patterns (e.g. `00000000`) can match
  thousands of locations and produce enormous output.  Use specific
  multi-byte sequences.
- `get_function_call_graph` output grows exponentially with `depth`.
  Depth 2 is typically 5-10KB; depth 3 (default) can be much larger.
  Use `depth=1` or `depth=2` unless you need the full tree.
- `decompile_functions` is significantly faster than calling `decompile_function` in
  a loop because the decompiler session is reused. Long batch entries are
  truncated explicitly; retrieve the full text with `decompile_function`
  and its `offset`/`limit` pagination.
- **HTTP server and MCP** keep the JVM warm -- every query is fast.
  **CLI without a server** cold-starts the JVM each time (~5-10s).

## JVM stderr noise

Every cold JVM start prints warnings to stderr about `sun.misc.Unsafe`
illegal reflective access.  These are cosmetic JPype/pyghidra warnings
and do not affect results.

To suppress them when scripting:

```bash
# Bash / Linux / macOS
python -m ghidramsc list_functions -b my_binary 2>/dev/null

# PowerShell
python -m ghidramsc list_functions -b my_binary 2>$null
```

The HTTP server and MCP server only produce this noise once at startup.
Steady-state queries are clean.

## Contributing and security

GhidraMSC is maintained by one researcher as time permits. See
[CONTRIBUTING.md](CONTRIBUTING.md) for bug reports and proposed changes.
Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).
Community participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
See [MAINTAINERS.md](MAINTAINERS.md) for project ownership.

## License

Distributed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
more information.

## Attribution

Copyright 2026 Cisco Systems, Inc. and its affiliates

Author: padesant@cisco.com (Patrick DeSantis)
