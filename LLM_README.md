# GhidraMSC -- LLM Guide

You have access to GhidraMSC, a set of tools for querying and modifying a
Ghidra reverse-engineering project. Persistent HTTP and MCP modes keep their
project open for the session; one-shot CLI opens it for one command. Most tools
operate on a **program** (binary) inside that project. Select the program by
passing the optional `binary` parameter to a program-scoped MCP call. If
omitted, the default binary configured at startup is used.

Use the names exposed by the current tool list; no alternate tool names are
registered.

Use `list_programs` to see all programs available in the project.  Its values
are canonical project-relative identities: root programs are bare names and
nested programs use `/` separators (for example,
`firmware/arm/sample.bin`).  Pass those values back unchanged as `binary`.
`list_programs` is project-scoped: call it without `binary`, including when no
default program was configured. Then pass one exact returned identity on every
program-scoped call. The five CodeBrowser-only tools also omit `binary` because
they intentionally use active GUI state.

GhidraMSC is available through four interfaces. The public registry contains 90 tools:
CLI, HTTP, and headless MCP expose the same 85 non-GUI tools, while plugin MCP
adds five CodeBrowser-only tools. GUI-plugin mutations remain dirty in Ghidra;
persistent-headless mutations remain dirty in the warm process; one-shot CLI
mutations are transient unless the command includes `--save`.

**Cross-version safety:** a headless Ghidra version may silently upgrade older
program data in memory while opening it. This can make the `dirty` field in
the object returned by `get_program_save_state` become `true` before any tool
mutation. Do not infer user changes from that field alone. Closing the
headless process without `save_program` discards the
in-memory upgrade, but an explicit save can persist the newer format and make
the program unreadable by the older Ghidra version. Unless the user has
authorized that conversion, work from a version-specific project copy and do
not call `save_program` or use a CLI command's `--save` option.

MCP negotiates handshake-era protocol revisions through `2025-11-25` while
remaining compatible with `2024-11-05`. Clients using `2025-06-18` or later
receive JSON-object results in `structuredContent` as well as the unchanged
text content. The stateless `2026-07-28` protocol era is not supported.

## Agent starting sequence

1. Use the tools exposed by the current MCP session. If the requested tool is
   absent, check the selected toolset and mode; do not invent an alias.
2. Call `list_programs` without `binary`, then carry one exact returned program
   identity through every program-scoped call. Addresses alone do not identify
   a program in a multi-binary project.
3. Read the relevant listing, decompilation, references, and current stored
   state before editing. Treat empty results, decompiler output, and existing
   analyst labels as evidence with different limits; corroborate a conclusion
   with the underlying program data.
4. Make only edits authorized by the task. For each mutation inspect `status`,
   `transaction.started`, `transaction.committed`, and `stored`. After an edit,
   read the affected program state again before another dependent call.
   `no_change` and `preview` are valid outcomes. If a response is missing or
   an outcome is uncertain, inspect current state before considering a retry.
5. Use `get_program_save_state` to check dirty state. Save explicitly only when
   persistence is intended. In GUI mode, verify the active CodeBrowser program
   before `undo_gui_transaction`; Ghidra does not make every committed edit
   undoable.

## Choosing an interface

| Interface | Best when | How it works |
|-----------|-----------|--------------|
| **MCP (headless)** | You are running inside an MCP-capable host (VS Code Copilot, Claude Desktop, Cursor). | The host spawns `python -m ghidramsc mcp --mode headless` (optionally with `-b <default>`). Program-scoped tools have an optional `binary` parameter. The JVM stays warm for the lifetime of the session. **This is the preferred interface for LLM agents.** |
| **MCP (GUI)** | Same as MCP, but you want to use the Ghidra GUI at the same time. | The host spawns `python -m ghidramsc mcp --mode gui`. Connects to a running Ghidra GUI with the GhidraMSC plugin installed. No project lock conflict. Mutations appear in the GUI; undo depends on the active program's Ghidra undo history. Also provides 5 GUI-context tools. |
| **HTTP server** | You have terminal access and will make many queries in sequence. | Start the server once (`python -m ghidramsc serve`), then send `POST /query` requests with an optional `binary` override. |
| **CLI** | You need a single one-shot query, or are writing a shell script. | Run `python -m ghidramsc <tool> -b <program> [args]` for program-scoped tools; `list_programs` takes no `-b`. Each invocation cold-starts a JVM (~5-10s) unless the HTTP server is already running. |

For GUI mode, installing the extension is not sufficient by itself.  An
operator must open a binary in a CodeBrowser window and enable
`GhidraMSCPlugin` from that window's **File > Configure... > Configure All
Plugins** dialog.  The similarly named **Install Extensions** dialog belongs
to the Project Manager and only controls whether the extension is installed.
The plugin listener is ready when Ghidra logs `GhidraMSC TCP server listening
on 127.0.0.1:18100`.

For program-scoped operations in all four interfaces, `-b` can be omitted if
the `GHIDRAMSC_BINARY` environment variable is set.

For MCP, `--toolset minimal`, `inspect`, `default`, `vuln-research`, `most`, or
`all` selects the launch-time tool surface. Named profiles come only from the
adjustable files in `ghidramsc/toolsets`; pass a lowercase name without a path
or filename extension. Blank lines and full-line `#` comments are ignored.
Trailing inline comments are allowed when whitespace separates the tool name
and `#`, for example `decompile_function  # primary semantic view`; a `#`
joined directly to a name remains invalid.
Restart the MCP process, not Ghidra, after changing a profile file.

- `minimal`: 5 read-only orientation tools.
- `inspect`: 20 read-only binary-understanding tools.
- `default`: 44 full reversing/report tools, including ordinary mutations and
  exact code recovery.
- `vuln-research`: 59 tools for vulnerability research and annotation.
- `most`: 75 broad expert tools.
- virtual `all`: 85 tools headlessly or all 90 through the GUI plugin.

**If you are an MCP-connected agent:** use the tools directly as they appear in
your tool list. Start with `list_programs()` when the exact program identity is
not already established; it takes no `binary`. Pass one returned identity as
`binary` on every later program-scoped call, even when a default exists, to
avoid silently querying the wrong program. Use the live tool list for names
and parameters.

**If you have terminal access but no MCP:** start the HTTP server first
for speed, then use either the CLI or direct HTTP calls.

## Project preparation boundary

GhidraMSC uses programs already present in the selected Ghidra project. It
does not provide import or initial-analysis tools. Prepare the project in
Ghidra before starting a headless MCP process that will own it, then call
`list_programs` to obtain each program's exact project identity.

---

## Address format

All addresses are hexadecimal strings. The `0x` prefix and leading zeros are
optional. Examples: `0x1000`, `0001d000`, `0x00000000`.

## Return values

- Tools that return **str** produce human-readable text (one item per line).
- Tools that return **dict** produce structured JSON.
- Errors are inline: either an `"error"` key in a dict, or a string
  starting with `ERROR:`.

---

## Multi-binary projects

When a Ghidra project contains multiple binaries (e.g. sample.bin,
libsample.so, libhelper.so), their address spaces overlap.  The same
hex address can exist in every binary, mapping to completely different
functions.  If you omit the `binary` parameter, the server uses the
default binary -- which may silently resolve your address to the wrong
function in the wrong binary with no error.

**Always pass `binary` explicitly to program-scoped tools in multi-binary
projects.** This includes `decompile_function`, `get_function_info`, `list_references_to_address`,
`decompile_functions`, `set_function_name`, and `get_listing_at_address`. `list_programs` is
project-level, while the five plugin-only GUI tools intentionally use active
CodeBrowser state; none of those six accepts `binary`.

Common failure mode: you collect xrefs from binary A, then call
`decompile_function` on the caller addresses without specifying `binary`. The addresses resolve
in binary B (the default), returning unrelated functions.  The output
looks plausible but is wrong.  Always carry the binary name through
the entire analysis chain.

For programs in project folders, always retain the entire value returned by
`list_programs`.  A bare name selects only a root-level program; it never
selects a same-named program in a nested folder.  This makes duplicate leaf
names such as `arm/libfoo.so` and `x86/libfoo.so` unambiguous.  Structured
`binary` and `program` response fields use the same qualified identity and can
be passed directly into later calls.

---

## Finding tools

For MCP, use the tools shown by the current host. That live list reflects the
selected mode and toolset, and its schemas define the accepted parameters. A
tool absent from the live list is unavailable in this session; change the mode
or toolset and restart the MCP process if the task needs it.

For CLI, HTTP, or cross-mode discovery, see the
[full tool catalog](TOOL_CATALOG.md). Read only the relevant section
when you need to discover a capability. This guide focuses on selecting
programs, interpreting results, and making edits.

---

## Using the tools via MCP

If the tools appear in your tool list, call them directly by name using the
parameters in their live schemas. There is nothing else to configure.

Example tool calls:

```
# Discover canonical project-relative program identities (no binary argument):
list_programs()

# Query the default binary:
decompile_function(addr_hex="0x1000")
get_function_info(addr_hex="0x1000")

# Query a specific binary by name:
decompile_function(addr_hex="0x1000", binary="libfoo.so")
list_references_to_address(addr_hex="0x1000", binary="firmware.elf")

# Other examples:
search_functions_by_name(pattern=".*socket.*")
set_function_name(addr_hex="0x1000", new_name="init_network")
decompile_functions(addresses=["0x1000", "0x1d000", "0x1e400"])
```

The MCP server keeps the JVM and Ghidra project loaded for the entire
session.  Every tool call is fast.

---

## Using the tools via HTTP server

Start the server first, then send queries as `POST /query`:

```bash
# Start (once, in a terminal or background)
python -m ghidramsc serve -b my_binary

# Query (uses default binary)
curl -s -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "decompile_function", "args": {"addr_hex": "0x1000"}}'

# Query a different binary (per-request override)
curl -s -X POST http://127.0.0.1:13100/query \
  -H "Content-Type: application/json" \
  -d '{"command": "decompile_function", "args": {"addr_hex": "0x1000"}, "binary": "libfoo.so"}'

# List all programs in the project
curl http://127.0.0.1:13100/programs

# Health check
curl http://127.0.0.1:13100/health
# {"status": "ok", "default_binary": "my_binary", "cached": ["my_binary"]}

# Shut down
curl -X POST http://127.0.0.1:13100/shutdown
```

The server listens on `127.0.0.1:13100` by default.

---

## Using the tools via CLI

Each command maps to a tool.  The program name is always required with
`-b` (this is the name from the Ghidra project tree, not a file path).

```bash
python -m ghidramsc decompile_function -b my_binary 0x1000
python -m ghidramsc get_function_info -b my_binary 0x1000
python -m ghidramsc search_functions_by_name -b my_binary ".*socket.*"
python -m ghidramsc set_function_name -b my_binary 0x1000 init_network
python -m ghidramsc list_references_to_address -b my_binary 0x1000
python -m ghidramsc decompile_functions -b my_binary "0x1000,0x1d000,0x1e400"
python -m ghidramsc export_annotations -b my_binary -o annotations.json
```

If the HTTP server is running, the CLI automatically forwards to it
(no cold start).  Pass `--no-server` to force a direct JVM launch.

---

## Recommended workflows

### Understand a function

1. Call `decompile_function` on the target address to read the C pseudocode.
2. `get_function_info` to inspect bounded call sites and evidenced callees;
   review `possible_callees`, `unresolved_calls`, and scan completeness before
   treating the graph as complete.
3. `list_function_variables` to see variable names and types.
4. Follow interesting callees with `decompile_function` on their entry addresses.
5. Use `list_references_to_address` on global addresses or function entries to find all callers.

### Identify a function's purpose

1. Call `decompile_function` on the function.
2. `list_strings` with a filter if you see string references in the code.
3. `list_references_to_address` / `list_references_from_address` to trace data flow.
4. `get_listing_at_address` if you need to see raw instructions the decompiler may have simplified.

### Rename and annotate

There are two paths for annotating variables: individual tool calls
and the batch JSON approach.  Choose based on volume:

- **1-5 unambiguous renames/retypes:** Use `set_variable_name` or
  `set_variable_type` when a database-backed parameter or local has a unique
  name. For decompiler identities, call `list_function_variable_identities`,
  using `filter_str` when the likely name, type, storage, ID, or backing is
  known; follow `pagination.next_offset` only when `has_more` is true. Then use
  `set_variable_name_by_id` or `set_variable_type_by_id` with a fresh ID.
- **6+ changes to one function:** Write a JSON file and use
  `apply_function_annotations`.  One tool call applies all changes atomically.
  Also useful when setting return type and calling convention
  simultaneously with variable changes. If the effective parameters are
  inferred rather than database-backed, a return-type change is rejected
  before mutation; supply the complete signature with
  `set_function_prototype` first.

For stable-identity mutations, count a result with
`transaction.committed=true` as a committed edit before validating its label or
read-back. `rolled_back` means restoration was verified. `failed` can mean a
committed edit could not be fully verified or that restoration is ambiguous;
inspect the transaction fields and stored state before retrying.

Individual calls:
```
set_variable_name(addr_hex="0x11088", old_name="param_1", new_name="sock_fd", binary="X.so")
set_variable_type(addr_hex="0x11088", var_name="sock_fd", type_name="int", binary="X.so")
set_function_prototype(addr_hex="0x11088", prototype="int dispatch_cmd(int sock_fd, char *buf, int len)", binary="X.so")
```

Batch approach (write JSON file first):
```json
{
    "return_type": "int",
    "calling_convention": "__stdcall",
    "vars": [
        {"old_name": "param_1", "new_name": "sock_fd", "type": "int"},
        {"old_name": "local_10", "new_name": "buf", "type": "char *"}
    ]
}
```
```
apply_function_annotations(addr_hex="0x11088", json_path="/path/to/annot.json", binary="X.so")
```

All fields in the JSON are optional -- omit what you don't want to change.

After significant analysis, checkpoint:
```
export_annotations(binary="X.so")
```

### Explore the binary

1. `list_functions` to get the full function list.
2. `search_functions_by_name` with a regex to narrow down (e.g. `search_functions_by_name(".*socket.*")`).
3. `list_strings` with a filter to find interesting data references.
4. `search_memory_bytes` for specific byte patterns (opcode sequences, magic bytes).
5. Use `search_memory_text` for ASCII strings in raw memory.
6. `get_program_info` for binary metadata (architecture, compiler, image base).
7. `get_program_memory_map` to see all memory regions and their permissions.
8. `list_program_imports` / `list_program_exports` for the symbol table.
9. `list_memory_blocks` for section layout (.text, .data, .bss, etc.).

### Locate code across different builds

When working with two builds of the same binary (e.g. a Ghidra project
loaded from a firmware image vs. a binary pulled from a live device),
addresses will NOT match -- the delta varies by region due to compiler
differences.  Do not apply a fixed offset formula.

Use `search_memory_bytes` with 12+ bytes of instruction opcodes to find the
matching code.  Example workflow:

1. Disassemble the function on the device (or extract opcodes from a
   core dump / objdump output).
2. Take 12-16 bytes of contiguous opcodes from a distinctive code
   sequence (avoid prologues -- they are often identical across
   unrelated functions).
3. `search_memory_bytes(hex_pattern="<12+ hex chars>", binary="X.so")`
4. The result gives you the address in the Ghidra binary.

This is more reliable than name-based matching when symbols are
stripped or when names have been applied inconsistently between builds.

### Assess binary security

Use GhidraMSC to retrieve Ghidra evidence such as `get_program_info`,
`get_program_memory_map`, imports, references, instruction listings, bytes, and decompilation. Do not
infer a mitigation, vulnerability, cryptographic implementation, obfuscation,
or input-flow conclusion merely from a tool name or candidate pattern. When a
binary property matters, corroborate the Ghidra evidence with an appropriate
format-aware external tool.

### Work with structures and data types

1. `list_structures` to see existing struct definitions.
2. `get_structure` for a structure, or `get_composite` when unions or bitfield
   metadata matter.
3. `create_structure` or `create_union` to define the composite shell.
4. Use `set_structure_field` for offset-based structure fields and
   `set_union_field` for ordinal-based union fields.
5. Use `set_composite_bitfield`, `delete_composite_field`, and
   `set_composite_layout` for exact bitfield/component/layout work.
6. `set_structure_name` / `delete_structure` manage structure lifecycle.
7. `apply_data_type` stamps a scalar, pointer, array, or composite at a data
   address. It fails on conflicts by default; `clear_mode=data_only` explicitly
   replaces data but never instructions.
8. `set_data_label` sets a primary label only on already defined data. Use
   `set_address_label` for a label at an instruction or undefined mapped byte.

### Recover undefined code

1. `disassemble_memory` to disassemble bytes at an address or range.
   If an existing decode must be removed, preview and explicitly apply
   `clear_code_units` at the exact affected range first.
2. `create_function` to create a function once disassembly looks correct.
3. Repeat those explicit operations for additional verified entry points;
   GhidraMSC does not infer function entries for an entire region.

### Repair split or misbounded functions

1. Record `get_function_info`, including `body_ranges`, for every affected function.
2. Use `delete_function` for the obsolete function definition. This does not clear
   bytes, instructions, references, or unrelated annotations.
3. Use `set_function_body` on the retained entry point with inclusive range objects
   such as `[{"start":"0x1000","end":"0x103f"}]`.
4. Use `create_function` with the same optional `ranges` shape when defining a new
   function over already-disassembled instructions.
5. Check `conflicting_functions` on validation failures; overlaps are never
   removed implicitly.

For CLI `create_function` and `set_function_body`, repeat `--range START:END`
for each inclusive range. Qualified overlay endpoints retain their address
space, for example
`--range recovered::00101faf:recovered::00102683`. Both endpoints of a range
must be in the same address space.

Ghidra's native decompiler can fail on recovered overlay code with
`Start and end addresses must be in same address space!` when analyzed flow
crosses from the overlay to default memory. This error does not invalidate the
stored overlay or function body. Use `get_function_info`, listings, references,
and bytes for that code, and treat pseudocode for that function as unavailable.

### Edit local stack layout

1. Call `get_function_stack_frame` and select a free local offset from the complete
   returned layout.
2. Use `create_stack_variable` for a scalar or other fixed-size type, or
   `create_stack_variable_from_structure` for one exact structure type.
3. Treat `size` as a type-length assertion. The tools do not resize a type or
   replace overlapping storage.
4. Use `delete_stack_variable` with the variable's exact starting offset. Interior
   offsets and parameter offsets are rejected before a transaction starts.
5. Verify the full `stored` stack-frame layout returned after each mutation.

---

## Working effectively with shared projects

### Existing labels are evidence to check

When working with a Ghidra project that has been analyzed before (by a
human or another LLM agent), function and variable names fall into two
categories:

- **Compiler-originated** (exports, debug symbols, RTTI, import stubs):
  stronger evidence for identity, though a stale or mismatched symbol file can
  still mislead.
- **Analyst-applied** (everything else): a prior analyst's best guess.
  May be wrong, incomplete, or reflect a narrow context.

Do not assume an analyst-applied name is correct without reading the
code.  A function named `validate_input` may only check length, or may
not validate at all.  When the name conflicts with what the code does,
the code is the authority.  This matters most on security-relevant
paths -- "the function is called check_auth so it must check auth" is
not evidence.

### Annotate as you go

When the task authorizes project edits, record well-supported findings before
moving on. Renames and comments accumulate across sessions, so check existing
annotations and use names that describe observed behavior. A read-only task
does not call mutation tools merely to satisfy this workflow.

Useful annotations after deep analysis of a function include:
1. `set_function_name` if the function is still `FUN_*` or has a misleading name.
2. `set_variable_name` on key parameters and locals you identified.
3. `set_comment_at_address` (plate or pre) summarizing purpose and key findings.
4. `set_function_prototype` if you identified the signature.

### Variable identity limitations

`set_variable_name` and `set_variable_type` select a uniquely named
database-backed parameter or local. For a decompiler symbol, use
`list_function_variable_identities` and the corresponding `*_by_id` tool.
The identity query reports whether a symbol appears persistable, but a freshly
reported eligible identity may still fail to resolve during mutation. Treat
the mutation result and its read-back as authoritative.
`persistable=false` means the high-symbol ID operation is unavailable. If
`get_function_stack_frame` shows a uniquely named database local or parameter,
an exact `set_variable_name` or `set_variable_type` may still work. Verify the
name and storage; a high symbol's matching name alone is insufficient. Refresh
identities after every decompiler-affecting mutation.
Unique-space decompiler temporaries report `persistable=false` because they
cannot be materialized as database function variables; choose a supported
register, stack, memory, or hash-backed identity when the task requires one.
The identity query returns at most 100 entries by default. Filter first when
possible; otherwise continue with `pagination.next_offset`. Duplicate-name
metadata on every returned entry still names all matching IDs from the complete
`decompile_function` result, including IDs outside the current page.

The current `var_id` selects a complete decompiler `HighSymbol`. Each identity
also reports its actual decompiler merge groups. By default, rename, retype,
and materialization affect the complete symbol. To materialize one group, use
`create_variable_by_id` with `split_use=true` and one reported
`merge_group_id`; then refresh identities before renaming or retyping its
database variable. Rename-only and retype-only split requests return
`unsupported` because safe read-back and rollback cannot be established. IDs
scoped to a decompiler snapshot must be refreshed after mutation. A temporary with
`persistable=false` cannot be materialized and should be documented with an
address comment instead.

### Use comments to anchor findings

Comments persist in the Ghidra project and appear in both the Listing
and Decompiler views.  Use them to record:
- What a code path does and why it matters
- Security-relevant observations (unchecked lengths, missing auth, etc.)
- Constraints discovered during testing (e.g., "timer is 80s not 30min")
- Cross-references to external documentation

Comment types:
- `plate`: appears above the function header.  Use for function-level summaries.
- `pre`: appears before the instruction.  Use for block-level notes.
- `eol`: appears at end of line.  Use for single-instruction notes.
- `repeatable`: propagates to xref sites.  Use sparingly.

---

## JSON file formats

### apply_function_annotations input

```json
{
    "return_type": "int",
    "calling_convention": "__stdcall",
    "vars": [
        {"old_name": "param_1", "new_name": "sock_fd", "type": "int"},
        {"old_name": "local_10", "new_name": "buf", "type": "char *"}
    ]
}
```

All fields are optional.  Omit `return_type` or `calling_convention` to
leave them unchanged.  Each entry in `vars` can have `old_name` +
`new_name` (rename), `old_name` + `type` (retype), or both.
When `return_type` would change a function whose effective parameters are
inferred, the complete annotation is rejected before mutation. Use
`set_function_prototype` with the full signature, then apply any remaining
annotation fields.

### set_function_names input

```json
[
    {"addr": "0x1000", "name": "init_network"},
    {"addr": "0x1d000", "name": "process_packet"}
]
```

### export_annotations output

```json
{
    "binary": "firmware.bin",
    "image_base": "0x00000000",
    "symbols": [
        {"addr": "0x1000", "name": "init_network", "namespace": "Global", "type": "Function", "primary": true}
    ],
    "comments": [
        {"addr": "0x1000", "type": "eol", "text": "setup socket"}
    ],
    "function_signatures": [
        {"addr": "0x1000", "name": "init_network", "signature": "int init_network(int port)", "return_type": "int", "calling_convention": "__stdcall", "params": [{"name": "port", "type": "int", "ordinal": 0}]}
    ]
}
```

This same format is accepted by `import_annotations`, but import applies only
function names, labels, and comments. It does not restore signature types or
parameters from `function_signatures`.

### create_functions input

```json
[
    {"addr": "0x1000"},
    {"addr": "0x1d000", "name": "my_func"}
]
```

---

## Common mistakes to avoid

- **Omitting `binary` in a multi-binary project.**  Addresses overlap
  between binaries.  Without `binary`, the default resolves your address
  in the wrong binary -- silently returning unrelated data.  Always pass
  `binary` explicitly.  See "Multi-binary projects" above.
- Addresses are hex strings. The `0x` prefix is accepted everywhere
  but is **optional** -- bare hex like `0001d43c` works in all four
  interfaces.  Do NOT pass decimal addresses.
- `search_memory_bytes` takes raw hex bytes (`e92d4830`), NOT `0x`-prefixed.
  The hex string must have an even number of characters.
- `decompile_functions` takes an **array** of address strings, not a
  comma-separated string. It accepts at most 16 addresses; a long function or
  full batch yields an explicit truncation marker. Use `decompile_function`
  with successive `offset` values to read all of a long function.
- `json_path` parameters require the file to exist on disk.  Write it
  first, then pass the absolute path.
- `decompile_function` and `get_function_info` accept any address inside a function
  body, not just the entry point.  The tool resolves the containing
  function automatically.
- `set_variable_name` needs the current variable name (`old_name`), not the
  new one, to identify the target.  Get names from `list_function_variables` first.
- `set_variable_type` uses C type syntax: `char *` not `char*`, `int **` not
  `int * *`.  Use the exact type names listed above.

## Interface-specific gotchas

### Project locking

Ghidra allows only **one process** to hold a project open at a time.
The HTTP server, MCP server, and `--no-server` CLI all open the same
project.  Consequences:

- You cannot run the HTTP server and MCP server simultaneously.
- CLI `--no-server` will fail with a `LockException` while a server
  (HTTP or MCP) is already running.
- To switch between interfaces, shut down the current one first
  (`/shutdown` for HTTP, or close stdin for MCP).

### CLI

- When the HTTP server is running, CLI commands **auto-forward** to it.
  This is fast (~500ms vs ~6s cold JVM).  The CLI's `-b` flag is
  forwarded as a per-request binary override so the server queries the
  correct program.  Pass `--no-server` to force a direct JVM launch.
- `list_strings` filter is a **positional argument**, not a flag:
  `python -m ghidramsc list_strings -b firmware.elf socket`
  (NOT `--filter socket`).
- CLI output goes to stdout.  Errors go to stderr with a non-zero exit
  code.  Redirect stderr to `/dev/null` or `$null` if you only want
  clean output.
- If a forwarded HTTP query loses its response, the CLI reports an unknown
  outcome and does not run the command again in a direct JVM. Inspect the
  current program state before retrying a mutation.

### HTTP server

- Default address: `127.0.0.1:13100`.
- Health check: `GET /health` returns
  `{"status":"ok","default_binary":"...","cached":[...]}`.
- Program list: `GET /programs` returns
  `{"programs":[...]}` with all project binaries.
- Per-request binary: add `"binary": "name"` at the top level of the
  POST body to override the default.
- The server writes its port to `.ghidramsc_port` on startup and
  removes it on clean shutdown.  If the server crashes, the stale port
  file may remain.
- String-returning tools wrap the result:
  `{"result": "<text>"}`.
  Dict-returning tools place keys **at the top level** (no `result`
  wrapper).  Check whether the response has a `"result"` key or direct
  keys like `"binary"`, `"blocks"`, etc.
- Application-level failures and error payloads return HTTP 422 while
  preserving the tool's payload shape. Unexpected dispatch exceptions return
  HTTP 500; successful results return HTTP 200. Inspect the body as well as the
  status.
- Shutdown is a `POST /shutdown` (not GET).  Health check is
  `GET /health`.

### MCP

- The host (VS Code, Claude Desktop) manages the process lifecycle.
  You do not need to start or stop anything.
- **Headless cross-version warning:** opening older program data may perform an
  in-memory upgrade without a modal and may make the program immediately dirty.
  Restarting without saving discards that transient conversion. Calling
  `save_program` persists it and may prevent the older Ghidra version from
  reopening the program. Use a version-specific project copy when compatibility
  with the older version must be preserved.
- **GUI mode** (`--mode gui`): the MCP server connects to a running
  Ghidra GUI over TCP instead of starting its own JVM. Programs
  modified by the LLM open as CodeBrowser tabs. Changes are not auto-saved;
  use `save_program` or save in the GUI when persistence is intended.
  `undo_gui_transaction` acts on the active CodeBrowser program only, and some
  committed edits may leave no undo entry. Check `get_cursor_address` before
  undo and verify the saved state after a disposable session. The listener
  admits 12 simultaneous clients by default. `--max-clients N` applies a
  positive global override to
  the already-running listener and reports the effective limit.
- Tool results that are very large (>100KB) may be truncated or written
  to a temp file by the host.  Prefer filtered queries (`search_functions_by_name`,
  `list_strings` with `filter_str`) over full dumps when possible.
- Errors come back in the tool result with `isError: true` and an
  error message in the content text. The result `_meta` contains
  `ghidramsc/errorCategory` for `not_found`, `validation`,
  `unavailable_tool`, `exception`, or other `application_failure`. This
  metadata is available at old and new MCP protocol revisions; the existing
  text and newer `structuredContent` retain their meanings. The MCP
  connection stays alive -- errors do not kill the server.
- For timing diagnostics, start the MCP process with
  `GHIDRAMSC_MCP_TIMING=1`. Each response gets a structured stderr event
  with an opaque request ID and dispatch, program acquisition, query,
  serialization, write/flush, and total milliseconds. The event does not
  identify a binary or include arguments. GUI/plugin acquisition is included
  in query time and explicitly marked unobservable. Normal tool responses
  stay unchanged.
- In GUI mode, every command gets one transport attempt. The handle
  never reconnects or replays after a TCP or response-protocol failure. A lost,
  timed-out, malformed, or mismatched mutation response is reported as an
  ambiguous outcome, and you must inspect current Ghidra state before retrying.
  Idle connections remain usable; use independent handles for concurrent work.
- If a closed target requires a Ghidra data upgrade, the GUI plugin returns a
  bounded error naming the program and **Upgrade Program Data?** without
  opening the modal itself. To use the target, open it manually in Ghidra and
  approve the upgrade only when intended, then retry on the same MCP
  connection. Saving after approval persists the newer format and may prevent
  older Ghidra versions from reopening that program. If the dialog is cancelled,
  keep using that connection for other programs. The plugin never approves the
  upgrade automatically.
- Since the host prevents calling undefined tools, you cannot trigger
  an "unknown tool" error through normal MCP usage.

## Empty results are valid

Some tools return empty or zero-count results that are not errors:

- `get_comment_at_address` on an address with no comment returns an empty string.
- `list_bookmarks` with no bookmarks returns a text header showing zero total.
- `list_references_to_address` / `list_references_from_address` may return 0 references.
- `search_memory_bytes` or `search_memory_text` may return 0 hits.

Do not treat these as failures.  They mean the data does not exist.

## Performance notes

- `list_functions` and `list_strings` can return very large output on big
  binaries (145KB+ for 6000 functions).  Use `search_functions_by_name` or `list_strings`
  with `filter_str` to narrow results when possible.
- `search_memory_bytes` with broad patterns (e.g. `00000000`) can match
  thousands of locations and produce enormous output.  Use specific
  multi-byte sequences.
- `get_function_call_graph` output grows exponentially with `depth`.
  Depth 2 produced 9KB for a modest function; depth 3 (default) can be
  much larger.  Use `depth=1` or `depth=2` unless you need the full
  tree.
- `decompile_functions` is significantly faster than calling `decompile_function`
  individually for each address because the decompiler session is reused.
  Its response is bounded; use a paged single-function call for omitted text.
- `export_annotations` scans every code unit for comments and can be
  slow on large binaries.  Call it only when you need to checkpoint.
- **MCP and HTTP server** keep the JVM warm -- every call is fast.
  **CLI without a server** cold-starts the JVM each time (~5-10s).

## Stderr noise

The JVM prints warnings to stderr on startup, especially about
`sun.misc.Unsafe` access.  These are **cosmetic** and do not affect
tool output or correctness.  Ignore them.
