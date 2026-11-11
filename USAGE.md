# Install and use GhidraMSC

GhidraMSC exposes programs in a Ghidra project through four interfaces: CLI,
HTTP, headless MCP, and GUI MCP. An LLM can use any of them when its host has
the corresponding terminal, HTTP, or MCP access. This guide assumes Ghidra and
the project are already available.

For an illustrated fresh-project walkthrough, see the
[standalone user manual PDF](docs/user-manual/GhidraMSC_User_Manual.pdf) and its
[editable source and offline build instructions](docs/user-manual/README.md).

## 1. Download and choose a method

Download and extract the GhidraMSC archive to a permanent directory. It
contains the `ghidramsc` Python module, `ghidramsc.toml.example`, and the
prebuilt `plugin/dist/GhidraMSCPlugin.zip`. Run the commands below from the
extracted directory, or point your MCP host's working directory or Python path
there. The package declares Python 3.10 as its minimum; use a Python version
supported by your Ghidra installation.

| Method | Why choose it | Tradeoff |
|---|---|---|
| **CLI** | A terminal-based LLM agent or person can make an occasional call, including over SSH, with no service to manage. | Each standalone call opens the project and starts a JVM, so repeated calls are slow. |
| **HTTP** | A terminal or HTTP-capable agent can make many calls to one local server; the JVM stays warm. CLI calls can also forward to it. | The server holds the project lock until stopped, so the GUI or another headless owner cannot open that project. |
| **Headless MCP** | An MCP host gives the LLM typed tools directly and keeps one JVM warm for the session. | The MCP process holds the project lock; the GUI cannot open that project at the same time. |
| **GUI MCP** | An MCP host works with the project already open in CodeBrowser and can expose five extra GUI-context tools. | Ghidra and the installed plugin must stay running. |

CLI, HTTP, and headless MCP use Ghidra's PyGhidra integration. GUI MCP uses the
prebuilt plugin and a Python client; it does not start PyGhidra. For a headless
method, use a Python interpreter that can import `pyghidra`. Ghidra includes
the required wheels. If `python -c "import pyghidra"` fails in your chosen
interpreter, follow the bundled-wheel setup in [README.md](README.md#installation)
for that interpreter.

## 2. Configure the project for CLI, HTTP, or headless MCP

Copy `ghidramsc.toml.example` to `ghidramsc.toml` in the extracted directory
and set the Ghidra installation and project location:

```toml
[ghidramsc]
ghidra_install_dir = "C:/tools/ghidra_12.1.4_PUBLIC"
project_path = "C:/ghidra_projects"
project_name = "MyProject"
```

Use your actual paths. `project_path` contains `MyProject.gpr`, and
`project_name` is that filename without `.gpr`. You can point
`GHIDRAMSC_CONFIG` at a config file elsewhere. GUI MCP uses the project open in
CodeBrowser and does not read this file.

Only one Ghidra process can own a local project. Use CLI, HTTP, or headless MCP
while the GUI is closed on that project. GUI MCP shares the running GUI's
project. Multiple LLM clients can use one MCP process if their host shares it;
starting another headless process on the same project encounters its lock.

## 3. Use one of the four methods

### CLI: occasional terminal calls

Give the LLM terminal access to the extracted directory, or run the same
commands yourself. First obtain exact program names from the project, then
select one with `-b`:

```text
python -m ghidramsc list_programs --no-server
python -m ghidramsc get_program_info -b firmware/arm/example.bin --no-server
```

`-b` is a program name returned by `list_programs`, not a filesystem path.
`--no-server` makes each command a standalone call. For other commands, run
`python -m ghidramsc <tool> --help`. Add `--save` to a one-shot mutation when
you intend to persist it. Direct and HTTP-forwarded CLI calls return nonzero
for failed or partial results while printing the original payload. Such a result
skips automatic `--save`; inspect any committed or uncertain state and decide
explicitly whether to persist it.

### HTTP: repeated terminal or HTTP calls

Start one server in the extracted directory:

```text
python -m ghidramsc serve
```

The server listens on `127.0.0.1:13100` by default. The LLM can send local
HTTP requests through an HTTP-capable host or a terminal. For example, in
PowerShell, list programs and query one of the returned names:

```powershell
Invoke-RestMethod http://127.0.0.1:13100/programs
$body = @{ command = "get_program_info"; args = @{}; binary = "firmware/arm/example.bin" } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:13100/query -Method Post -ContentType "application/json" -Body $body
```

The local HTTP transport has no general request-body size cap; it reads the
declared `Content-Length` before parsing. Send complete bodies from trusted
local clients: a large body can consume memory, and an incomplete body can
hold the single request handler waiting. Individual tools retain their own
payload bounds.

While the server runs, ordinary CLI commands also forward to it and avoid a
new JVM start. Stop it with `python -m ghidramsc shutdown`. Call
`save_program` before stopping if you intend to keep persistent mutations.
See the [HTTP reference](README.md#2-http-server-api) for the request format
and endpoints.

### Headless MCP: LLM tools without the GUI

Configure your MCP host to launch this command from the extracted directory:

```text
python -m ghidramsc mcp --mode headless --toolset default
```

The host starts and keeps this process running; it opens the project in
`ghidramsc.toml`. Use one headless MCP process per project. Host configuration
examples are below.

### GUI MCP: LLM tools beside CodeBrowser

Install the included `plugin/dist/GhidraMSCPlugin.zip` once:

1. In Ghidra, select **File > Install Extensions**, choose the ZIP, install it,
   and restart Ghidra.
2. In a **CodeBrowser** window, select **File > Configure... > Configure All
   Plugins** and enable `GhidraMSCPlugin`.
3. Confirm the Ghidra log says `GhidraMSC TCP server listening on
   127.0.0.1:18100`.

Configure your MCP host to launch this command from the extracted directory:

```text
python -m ghidramsc mcp --mode gui --toolset all
```

The host connects to the running plugin on the same computer. The GUI owns
the project; the Python MCP process does not need `ghidramsc.toml` or
PyGhidra. The `all` toolset includes the five CodeBrowser-context tools.

## 4. Pick the MCP tools the LLM sees

`--toolset` applies to headless and GUI MCP. It selects the tools advertised
to the LLM when the MCP process starts. A smaller set reduces tool-description
context and makes the relevant choices easier to find. Change the toolset and
restart the MCP process when the task needs a broader surface.

| Toolset | Good starting use |
|---|---|
| `minimal` | Five read-only orientation tools. |
| `inspect` | Read-only inspection. |
| `default` | General reversing and annotation. |
| `vuln-research` | Richer typing, structures, batch annotation, and export. |
| `most` | A broad expert set. |
| `all` | Every tool available in the chosen mode, including the five GUI-context tools in GUI mode. |

`all` is the launch default when `--toolset` is omitted. Named toolsets are
defined in `ghidramsc/toolsets/*.txt`; they can be edited and take effect when
the MCP process restarts. Toolsets do not limit CLI or HTTP commands. See the
[toolset guide](ghidramsc/toolsets/README.md) for profile format and the
[tool catalog](TOOL_CATALOG.md) for the full list and exact parameters.

To diagnose MCP server latency, set `GHIDRAMSC_MCP_TIMING=1` in the MCP
process environment. GhidraMSC then writes one `GHIDRAMSC_MCP_TIMING` JSON
line to stderr after each response flush. It reports an opaque request ID
and dispatch, program acquisition, query, serialization, write/flush, and
total milliseconds without logging tool arguments, project paths, or binary
names. The GUI plugin's program acquisition is included in query time and
marked unobservable. Leave the variable unset for ordinary use; stdout and
tool results keep their usual shape.

## 5. Configure an MCP host and make the first call

These examples start **headless MCP** with the `default` toolset. Replace
`C:/path/to/GhidraMSC` with the extracted directory and use the Python
executable that can import PyGhidra. For **GUI MCP**, enable the plugin as
above, change `headless` to `gui`, and use `all` if you want GUI-context tools.
The host starts GhidraMSC for you; do not run the MCP command in a separate
terminal.

### VS Code

Add this to `.vscode/mcp.json`:

```json
{
  "servers": {
    "ghidramsc": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "ghidramsc", "mcp", "--mode", "headless", "--toolset", "default"],
      "cwd": "C:/path/to/GhidraMSC"
    }
  }
}
```

### Codex and ChatGPT desktop

Add this to user-level `~/.codex/config.toml` or `.codex/config.toml` in a
trusted project:

```toml
[mcp_servers.ghidramsc]
command = "python"
args = ["-m", "ghidramsc", "mcp", "--mode", "headless", "--toolset", "default"]
cwd = "C:/path/to/GhidraMSC"
startup_timeout_sec = 120
```

### Claude Desktop or Claude Code

For Claude Desktop, add this to `claude_desktop_config.json`. Claude Code can
use the same `mcpServers` block in a project-level `.mcp.json`:

```json
{
  "mcpServers": {
    "ghidramsc": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "ghidramsc", "mcp", "--mode", "headless", "--toolset", "default"],
      "env": {
        "GHIDRAMSC_CONFIG": "C:/path/to/GhidraMSC/ghidramsc.toml",
        "PYTHONPATH": "C:/path/to/GhidraMSC"
      }
    }
  }
}
```

`PYTHONPATH` lets this host import the module when it starts elsewhere. For
GUI MCP, the `GHIDRAMSC_CONFIG` entry is unnecessary.

Once the host shows GhidraMSC tools, ask the LLM to call `list_programs`
without a `binary` argument. Pass one exact returned program name as `binary`
to `get_program_info`, then to other program-scoped tools. Give the LLM
[LLM_README.md](LLM_README.md) for tool selection and result handling.
