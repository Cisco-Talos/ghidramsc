# Public tool catalog

This is the exact public registry for GhidraMSC. It contains 90 canonical tools: 40 queries and 50 mutations. Every shared tool is available through CLI, the local HTTP `/query` API, headless MCP, and GUI MCP. The five tools in [GUI context](#gui-context-gui-mode-only) require CodeBrowser and are available only in GUI MCP. Internal disabled implementations are excluded.

The tables describe the registry's JSON arguments used by MCP `tools/call` and HTTP `/query` `args`. `Required` means the argument must be present. `Optional` means it may be omitted; `Not declared` in the default column means the registry declares no default. A described runtime fallback can still apply. Bounds and conditional relationships are in the Details column. Addresses are hexadecimal strings; use exact slash-qualified project-relative program identities returned by `list_programs`.

For every program-scoped MCP tool, `binary` is an optional transport-level string selector. Its fallback is the configured default program. Pass the exact result of `list_programs` explicitly in multi-program projects. The HTTP equivalent is the top-level `binary` field beside `command` and `args`, rather than inside `args`. CLI selects it with `-b` / `--binary` or `GHIDRAMSC_BINARY` and uses positional arguments or flags that can differ from these JSON names. Run `python -m ghidramsc <command> --help` for exact CLI syntax; see [CLI usage](USAGE.md#cli-occasional-terminal-calls) and [MCP setup](USAGE.md#headless-mcp-llm-tools-without-the-gui). `list_programs` and all five GUI-context tools do not accept `binary`.

A mutation changes the open program's in-memory state unless its description says it is a preview. Persist with `save_program` or an eligible one-shot CLI `--save` after checking the result. A returned failure or partial result never triggers automatic CLI save. See [persistence and cleanup](README.md#1-command-line-interface).

## How to use this reference

For a JSON call, use the exact parameter names in its table. For example, MCP `create_memory_block` uses `block_name`, `addr_hex`, `length`, and `mode` for the mandatory arguments; `hex_bytes` is required by the `bytes` mode, while `source_addr_hex` is required by `byte_mapped`. HTTP places the same command arguments in `args` and its program selector at the top level. For CLI, check command help: `list_strings` takes its filter as a positional argument, and other commands translate JSON names into positional arguments or flags.

Examples of checked CLI help shapes: `list_strings [filter]`; `create_memory_block block_name address length {uninitialized,fill,bytes,byte_mapped}` with mode-specific flags such as `--hex-bytes`; `set_composite_bitfield name category_path ordinal field_name type_name bit_size` with placement flags; and `save_program --comment TEXT`. The CLI's `address` positional value for `create_memory_block` maps to the JSON `addr_hex` parameter. Run each command's `--help` for all options and defaults.

`get_program_save_state` returns an **object**, including boolean `dirty`; it is not itself a boolean. Opening a project with a different Ghidra version can make the initial in-memory program state dirty. `save_program` reports the persistence backend and whether a requested comment was supported. Headless project and GUI saves do not accept a custom comment; standalone domain-object saving may apply one. Persistent mutations remain pending until explicitly saved or discarded. HTTP and headless MCP shutdown, and one-shot CLI close, discard unsaved changes; GUI programs follow CodeBrowser's save/discard lifecycle.

`get_function_info.incoming_references` counts all Ghidra entry references while paging `sites`; a direct call is `direct_call`, a jump is verified as thunk/tail flow only when Ghidra identifies its source as a thunk, and other jumps remain `ambiguous`. `called_by` is Ghidra-known caller coverage. Other evidence arrays have independent continuation. `list_function_variable_identities` filters before pagination and returns snapshot-scoped IDs; refresh after mutation. A high-symbol identity can be ineligible even when an exact database variable can be edited by current name.

For `create_variable_by_id` with `split_use=true`, verify fresh use ownership: a failed verification can leave changed open-program state despite a rollback result. Name-only materialization of an inferred parameter can lock its type; inspect the returned before/after fields and fresh identity before continuing. A reported failure never establishes that the open program is clean.

## Sections

- [Program & project](#program--project)
- [Function analysis](#function-analysis)
- [Cross-references](#cross-references)
- [Memory & disassembly](#memory--disassembly)
- [Data & strings](#data--strings)
- [Structures & types](#structures--types)
- [Comments & bookmarks](#comments--bookmarks)
- [Renaming & refactoring](#renaming--refactoring)
- [GUI context (GUI mode only)](#gui-context-gui-mode-only)

## Program & project

### `get_program_memory_map`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get Ghidra memory blocks with addresses, sizes, R/W/X permissions, initialization, volatility, and source.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_program_info`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get program metadata: architecture, compiler, format, image base, pointer size.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_program_save_state`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Report whether a program has unsaved changes and can be saved.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_memory_blocks`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List Ghidra memory blocks with addresses, sizes, permissions, initialization, and block type.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_program_classes`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List all class namespaces.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_program_exports`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List exported symbols with addresses.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_program_imports`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List imported symbols (external dependencies) with addresses.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_program_namespaces`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List all namespaces in the binary.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_programs`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List all programs in the Ghidra project using slash-qualified project-relative names that can be passed back as binary.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| *(none)* | — | — | — | No arguments. |

### `save_program`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Explicitly save a program's pending changes.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `comment` | string | Optional | `Saved by GhidraMSC` | Requested save comment; applied only when the selected persistence backend supports custom comments |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## Function analysis

### `decompile_functions`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Decompile up to 16 addresses with bounded batch text; truncated entries direct you to paged decompile_function.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addresses` | array of string | Required | — | Up to 16 hex address strings |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `decompile_function`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Decompile a function in bounded text chunks; use offset to continue when next_offset is reported.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `offset` | integer | Optional | `0` | Character offset of decompiled output (default 0) |
| `limit` | integer | Optional | `16384` | Maximum characters in this chunk (default 16384, max 32768) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `search_functions_by_name`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Find functions whose name matches a regex pattern.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `pattern` | string | Required | — | Search pattern (regex for search_functions_by_name, ASCII for search_memory_text) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_function_info`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get function metadata and bounded call-site evidence. Calls include confirmed direct and resolved indirect targets; possible targets and unresolved computed calls are separate. Incoming entry references have conservative categories, complete counts, and paged sites. Other evidence arrays have their own complete page totals; called_by remains Ghidra-known only.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `incoming_offset` | integer | Optional | `0` | Zero-based incoming-reference offset |
| `incoming_limit` | integer | Optional | `100` | Incoming-reference page size, 1..500 |
| `evidence_offset` | integer | Optional | `0` | Other function-evidence array page offset |
| `evidence_limit` | integer | Optional | `100` | Other function-evidence array page size, 1..500 |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_function_variables`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List decompiler-visible parameters and locals in a function with types and storage.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_function_variable_identities`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Page and filter decompiler variable identities with storage and reported mutation eligibility; IDs are snapshot-scoped.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `offset` | integer | Optional | `0` | Pagination offset (default 0) |
| `limit` | integer | Optional | `100` | Pagination limit (default 100, max 500) |
| `filter_str` | string | Optional | `""` | Substring filter (case-insensitive) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_function_call_graph`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Follow evidenced direct and resolved indirect call edges to a configurable depth. Report unresolved computed calls, possible targets, scan limits, and depth/revisit limits explicitly.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `depth` | integer | Optional | `3` | Recursion depth for call graph (default 3) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_function_basic_blocks`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get basic blocks for a function with successor addresses.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_function_stack_frame`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get the stack frame layout of a function (offsets, sizes, types).

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_functions`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List all functions in the binary, sorted by address.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## Cross-references

### `get_function_call_relationships`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get bounded call-site evidence, including imported pointer calls. Distinguish confirmed direct and resolved indirect callees from possible targets and unresolved computed calls; caller coverage remains Ghidra-known only.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_references_from_address`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List cross-references FROM an exact address; large results have finite, lossless pages and complete totals.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `offset` | integer | Optional | `0` | Reference page offset |
| `limit` | integer | Optional | `100` | Reference page size, 1..500 |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_references_to_address`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List cross-references TO an exact address; large results have finite, lossless pages and complete totals.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `offset` | integer | Optional | `0` | Reference page offset |
| `limit` | integer | Optional | `100` | Reference page size, 1..500 |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## Memory & disassembly

### `disassemble_memory`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Follow native disassembly flow from one start address within an inclusive range of at most 4096 bytes. The end limits flow; it does not seed every address. Result coverage identifies decoded, undefined, and conflicting bytes. Existing code is never cleared.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `end_hex` | string | Optional | `""` | End hex address of range |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `clear_code_units`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Preview or explicitly clear all defined instructions and data in an exact initialized range of at most 4096 bytes. May remove references and affect function analysis; bytes and context are preserved.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `start_hex` | string | Required | — | Start hex address of range |
| `end_hex` | string | Required | — | End hex address of range |
| `preview_only` | boolean | Optional | `true` | Preview only by default; set false to clear code units. |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_listing_at_address`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Show listing code units from an address (default 40), including the containing item and exact interior symbols when the request is inside a code unit. Large windows return finite pages with complete totals.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `count` | integer | Optional | `40` | Number of items (default varies by command) |
| `offset` | integer | Optional | `0` | Code-unit page offset within the requested count |
| `limit` | integer | Optional | `100` | Code-unit page size, 1..500 |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `write_memory_bytes`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Write raw bytes at an address (hex string, e.g. '90909090').

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `hex_bytes` | string | Required | — | Hex byte string to write (e.g. '90909090') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `read_memory_bytes`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Read up to 4096 initialized memory bytes at an address as a hex dump with ASCII sidebar.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `length` | integer | Optional | `256` | Number of bytes to read (default 256, max 4096) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `search_memory_bytes`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Search memory for a hex byte pattern.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `hex_pattern` | string | Required | — | Hex byte string to search for (e.g. 'e92d4830') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `search_memory_text`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Search memory for an ASCII pattern.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `pattern` | string | Required | — | Search pattern (regex for search_functions_by_name, ASCII for search_memory_text) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_program_image_base`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set the image base address of the program.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_memory_block_permissions`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set all R/W/X permissions on a named memory block; omitted bits default to read=true, write=false, execute=false.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `block_name` | string | Required | — | Name of a memory block |
| `read` | boolean | Optional | `true` | Set read permission (boolean) |
| `write` | boolean | Optional | `false` | Set write permission (boolean) |
| `execute` | boolean | Optional | `false` | Set execute permission (boolean) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_memory_block`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create one bounded analysis memory block (at most 4096 bytes). Modes: uninitialized, fill, exact bytes, or byte_mapped. byte_mapped aliases its initialized source; writes can change source bytes. Overlay creation uses a separate address space. Preview first to inspect overlaps.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `block_name` | string | Required | — | Name of a memory block |
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `length` | integer | Required | — | Exact block length, 1..4096 bytes |
| `mode` | string | Required | — | uninitialized, fill, bytes, or byte_mapped |
| `overlay` | boolean | Optional | `false` | Create a separate overlay address space |
| `read` | boolean | Optional | `true` | Set read permission (boolean) |
| `write` | boolean | Optional | `true` | Set write permission (boolean) |
| `execute` | boolean | Optional | `false` | Set execute permission (boolean) |
| `fill_byte` | integer | Optional | `0` | 0..255 fill byte for fill mode |
| `hex_bytes` | string | Optional | `""` | Exactly length bytes of hex for bytes mode |
| `source_addr_hex` | string | Optional | `""` | Initialized source start for byte_mapped alias mode |
| `preview_only` | boolean | Optional | `false` | Inspect proposed map without starting a transaction |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_memory_block`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Remove an exact GhidraMSC-created analysis block. Native removal deletes analysis content in the range; preview it first and explicitly confirm when code, data, or symbols are present.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `block_name` | string | Required | — | Name of a memory block |
| `start` | string | Required | — | Exact qualified start returned by the memory map |
| `length` | integer | Required | — | Exact block length |
| `preview_only` | boolean | Optional | `false` | Inspect content without starting a transaction |
| `confirm_content_removal` | boolean | Optional | `false` | Allow deletion of code, data, and symbols in this block |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_recovered_code_overlay`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Copy 1..65536 exact recovered code bytes into a new executable overlay without changing physical/source bytes. Record source and optional runtime address provenance. A physical overlap requires explicit opt-in. The returned qualified overlay address works with read, disassembly, and function tools. Delete later with exact delete_memory_block identity.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `block_name` | string | Required | — | Unique name for the recovered overlay |
| `analysis_addr_hex` | string | Required | — | Physical offset where the overlay is placed |
| `hex_bytes` | string | Required | — | Exact recovered bytes as hex, 1..65536 bytes |
| `transform` | string | Required | — | Short provenance label, such as XOR key or unpacking step |
| `source_addr_hex` | string | Optional | `""` | Optional physical source range start; requires source_length |
| `source_length` | integer | Optional | `0` | Source range length, 0..65536; not the recovered length |
| `runtime_addr_hex` | string | Optional | `""` | Optional known runtime address, bare hex; empty means unknown |
| `allow_physical_overlap` | boolean | Optional | `false` | Explicitly allow the overlay to share an offset with physical memory |
| `preview_only` | boolean | Optional | `false` | Inspect overlaps and hashes without creating a block |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## Data & strings

### `get_data_at_address`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get defined data and exact symbols at a requested address, including its containing item and a finite rendered-value page. Use value_next_offset to continue. Undefined bytes have no data item; use read_memory_bytes and list_references_to_address.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `value_offset` | integer | Optional | `0` | Rendered-value code-point offset |
| `value_limit` | integer | Optional | `2048` | Rendered-value page size, 1..8192 code points |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_data_items`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List defined data items (globals, constants, arrays). Supports offset/limit pagination.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `offset` | integer | Optional | `0` | Pagination offset (default 0) |
| `limit` | integer | Optional | `500` | Pagination limit (default 500) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_strings`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List defined strings in the binary, optionally filtered.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `filter_str` | string | Optional | `""` | Substring filter (case-insensitive) |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## Structures & types

### `create_structure`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create a new structure data type.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `size` | integer | Optional | `0` | Size in bytes (for structure creation; 0 = growable) |
| `category_path` | string | Optional | `/` | Exact Ghidra data-type category path |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_structure`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Delete a structure data type.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_enum`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get the members of a named enum data type.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_composite`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get an exact structure or union with layout and bitfield metadata.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Optional | `""` | Exact Ghidra data-type category path |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_structure`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get full structure details: fields, offsets, types, sizes.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Optional | `""` | Exact category path; omitted names must be unique |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_enums`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List all enum data types defined in the program.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `list_structures`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List all defined structure data types with sizes and field counts.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_structure_name`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Rename an existing structure.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `old_name` | string | Required | — | Current structure name |
| `new_name` | string | Required | — | New name to assign |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_structure_field`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Insert or replace a structure field at an exact offset; replace also supports rename and retype.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Required | — | Exact Ghidra data-type category path |
| `offset` | integer | Required | — | Exact byte offset |
| `field_name` | string | Required | — | Field name to store |
| `type_name` | string | Required | — | C data type (e.g. 'int', 'char *', 'void') |
| `mode` | string | Optional | `replace` | replace or insert |
| `length` | integer | Optional | `0` | Stored length; 0 uses the resolved type length |
| `comment` | string | Optional | `""` | Comment text to set |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_structure_field`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Delete the defined structure field starting at an exact offset.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Required | — | Exact Ghidra data-type category path |
| `offset` | integer | Required | — | Exact byte offset |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_structure_layout`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set structure packing and minimum-alignment policy with exact read-back.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Required | — | Exact Ghidra data-type category path |
| `packing` | string | Required | — | disabled, default, or explicit |
| `alignment` | string | Required | — | default, machine, or explicit |
| `packing_value` | integer | Optional | `0` | Positive value required for explicit packing |
| `alignment_value` | integer | Optional | `0` | Positive value required for explicit alignment |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_union`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create an empty union at an exact data-type category path.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Optional | `/` | Exact Ghidra data-type category path |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_union_field`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Insert or replace a union field selected by ordinal.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Required | — | Exact Ghidra data-type category path |
| `ordinal` | integer | Required | — | Exact union component ordinal |
| `field_name` | string | Required | — | Field name to store |
| `type_name` | string | Required | — | C data type (e.g. 'int', 'char *', 'void') |
| `mode` | string | Optional | `replace` | replace or insert |
| `length` | integer | Optional | `0` | Stored length; 0 uses the resolved type length |
| `comment` | string | Optional | `""` | Comment text to set |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_composite_bitfield`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Insert or replace an exact structure or union bitfield.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Required | — | Exact Ghidra data-type category path |
| `ordinal` | integer | Required | — | Insertion/replacement ordinal; structures use it only for replacement |
| `field_name` | string | Required | — | Bitfield name to store |
| `type_name` | string | Required | — | Integer or enum bitfield base type |
| `bit_size` | integer | Required | — | Declared bit width; zero creates a zero-width bitfield |
| `mode` | string | Optional | `insert` | insert or replace |
| `byte_offset` | integer | Optional | `0` | Structure byte offset |
| `storage_size` | integer | Optional | `0` | Structure storage-unit size in bytes |
| `bit_offset` | integer | Optional | `0` | Structure bit offset within the storage unit |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_composite_field`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Delete a structure or union field selected by exact ordinal.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Required | — | Exact Ghidra data-type category path |
| `ordinal` | integer | Required | — | Exact component ordinal |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_composite_layout`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set structure or union packing and minimum-alignment policy.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `name` | string | Required | — | Name string |
| `category_path` | string | Required | — | Exact Ghidra data-type category path |
| `packing` | string | Required | — | disabled, default, or explicit |
| `alignment` | string | Required | — | default, machine, or explicit |
| `packing_value` | integer | Optional | `0` | Positive value required for explicit packing |
| `alignment_value` | integer | Optional | `0` | Positive value required for explicit alignment |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## Comments & bookmarks

### `list_bookmarks`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

List bookmarks, optionally filtered by address.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Optional | `""` | Hex address (e.g. '0x1c908') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `get_comment_at_address`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Get the containing code-unit comment. An interior request also reports its exact and effective addresses.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `comment_type` | string | Optional | `eol` | Comment type: plate, pre, post, eol (default), repeatable |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_bookmark`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Delete a Note bookmark at an address and category.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `category` | string | Required | — | Bookmark category label |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_bookmark`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create or update a Note bookmark at an address and category.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `category` | string | Required | — | Bookmark category label |
| `comment` | string | Optional | `""` | Comment text to set |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_comment_at_address`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set a code-unit comment (plate, pre, post, eol, repeatable). Interior addresses require explicit allow_containing_item opt-in.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `comment` | string | Required | — | Comment text to set |
| `comment_type` | string | Optional | `eol` | Comment type: plate, pre, post, eol (default), repeatable |
| `allow_containing_item` | boolean | Optional | `false` | Explicitly allow an interior address to change the containing item's shared comment |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## Renaming & refactoring

### `apply_function_annotations`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Atomically annotate a function from a JSON file; return-type changes preserve effective parameters or require set_function_prototype.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `json_path` | string | Required | — | Path to a JSON file on disk |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `apply_data_type`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Apply a fixed-size scalar, pointer, array, or composite type in mapped memory, including up to 4096 bytes in an uninitialized BSS block. BSS stays uninitialized; no file bytes are created. Conflicts are preserved by default; label defined data with set_data_label.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `type_name` | string | Required | — | C data type (e.g. 'int', 'char *', 'void') |
| `clear_mode` | string | Optional | `fail` | Conflict policy: fail or data_only; instructions are never cleared. |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_stack_variable_from_structure`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create a local stack variable using an exact structure type.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `stack_offset` | integer | Required | — | Signed stack offset relative to the function stack frame |
| `structure_name` | string | Required | — | Exact structure name |
| `category_path` | string | Optional | `""` | Exact Ghidra data-type category path |
| `name` | string | Optional | `""` | Name string |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_function_names`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Rename functions from a JSON file of addr/name entries, with independent per-item results.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `json_path` | string | Required | — | Path to a JSON file on disk |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_functions`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create multiple functions from a JSON file.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `json_path` | string | Required | — | Path to a JSON file on disk |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_function`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create a function, optionally with explicit body ranges.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `name` | string | Optional | `""` | Name string |
| `ranges` | array of objects {start: string, end: string} | Optional | `[]` | Inclusive function-body ranges as [{start: '0x...', end: '0x...'}] |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_stack_variable`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Create an exact local stack variable without replacing overlaps.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `stack_offset` | integer | Required | — | Signed stack offset relative to the function stack frame |
| `name` | string | Required | — | Name string |
| `type_name` | string | Required | — | C data type (e.g. 'int', 'char *', 'void') |
| `size` | integer | Optional | `0` | Expected stored size; 0 uses the resolved type length |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_stack_variable`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Delete the local stack variable starting at an exact offset.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `stack_offset` | integer | Required | — | Signed stack offset relative to the function stack frame |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `export_annotations`

**Role:** Query. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Return JSON of user-defined symbols, comments, and signatures for user-named functions; does not write a file.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `import_annotations`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Import function names, labels, and comments from a JSON file with independent per-item results; signature types are not applied.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `json_path` | string | Required | — | Path to a JSON file on disk |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_data_label`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set the primary label of an existing defined data item; cannot label code or undefined bytes.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `new_name` | string | Required | — | New name to assign |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_address_label`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set the primary label at an exact mapped address, including an instruction, undefined byte, BSS, or overlay. Preserve its namespace and verify the stored primary symbol. Function entries use set_function_name; unmapped addresses are rejected.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `new_name` | string | Required | — | New name to assign |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_function_name`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Rename the function at the given address.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `new_name` | string | Required | — | New name to assign |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_function`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Remove only the function definition containing an address.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_variable_name`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Rename a uniquely named database-backed parameter or local in a function.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `old_name` | string | Required | — | Current name to match |
| `new_name` | string | Required | — | New name to assign |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_variable_type`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Retype a uniquely named database-backed parameter or local in a function.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `var_name` | string | Required | — | Variable name within the function |
| `type_name` | string | Required | — | C data type (e.g. 'int', 'char *', 'void') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_function_body`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Replace a function body with explicit inclusive address ranges.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `ranges` | array of objects {start: string, end: string} | Required | — | Inclusive function-body ranges as [{start: '0x...', end: '0x...'}] |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_variable_name_by_id`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Rename one persistable decompiler HighSymbol by fresh var_id. Name-only inferred-parameter materialization may lock its type; see name_only_materialization. If ID editing is unsupported, a uniquely named database variable may be editable with set_variable_name.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `var_id` | string | Required | — | var_id returned by list_function_variable_identities |
| `new_name` | string | Required | — | New name to assign |
| `split_use` | boolean | Optional | `false` | Unsupported for rename-only splitting; materialize a group with create_variable_by_id first |
| `merge_group_id` | string | Optional | `""` | Merge-group identity returned by list_function_variable_identities; required with split_use |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_variable_type_by_id`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Retype one persistable decompiler HighSymbol by fresh var_id. If ID editing is unsupported, a uniquely named database variable may be editable with set_variable_type.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `var_id` | string | Required | — | var_id returned by list_function_variable_identities |
| `type_name` | string | Required | — | C data type (e.g. 'int', 'char *', 'void') |
| `split_use` | boolean | Optional | `false` | Unsupported for retype-only splitting; materialize a group with create_variable_by_id first |
| `merge_group_id` | string | Optional | `""` | Merge-group identity returned by list_function_variable_identities; required with split_use |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `create_variable_by_id`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Materialize database backing for one decompiler variable or selected merge group. Name-only inferred-parameter materialization may lock its type; see name_only_materialization.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `var_id` | string | Required | — | var_id returned by list_function_variable_identities |
| `name` | string | Optional | `""` | Stored variable name; empty keeps the decompiler name |
| `type_name` | string | Optional | `""` | Stored data type; empty keeps the decompiler type |
| `split_use` | boolean | Optional | `false` | Materialize only one reported merge group |
| `merge_group_id` | string | Optional | `""` | Merge-group identity returned by list_function_variable_identities; required with split_use |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `delete_variable_by_id`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Delete the exact database-backed parameter or local selected by decompiler identity.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `var_id` | string | Required | — | var_id returned by list_function_variable_identities |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_function_calling_convention`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set a convention supported by the current program; validation errors list available names. 'default' is supported.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `convention` | string | Required | — | Calling convention (e.g. '__stdcall', '__cdecl', 'default') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_function_noreturn`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set or clear Ghidra's native function no-return flag. A thunk changes its effective target; the result identifies both entries and verifies the stored flag. Existing CALL_RETURN flow overrides at caller instructions remain in place and can still truncate decompilation.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `no_return` | boolean | Required | — | True if the function never returns; false to clear the flag. |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_instruction_flow_override`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set Ghidra's native flow override on one exact instruction. Use NONE to clear a saved CALL_RETURN override after checking the call and its target. Returns old and stored flow type and fallthrough; preserves instruction bytes and listing. Does not change a function's no-return flag.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Exact instruction start address in hex. |
| `flow_override` | string | Required | — | Native FlowOverride enum name, such as NONE or CALL_RETURN. |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_function_prototype`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set full C-style function signature/prototype.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `prototype` | string | Required | — | C-style function signature (e.g. 'int foo(char *buf, int len)') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

### `set_function_return_type`

**Role:** Mutation. **Availability:** CLI, HTTP, headless MCP, GUI MCP.

Set and verify a function return type while preserving effective parameters; inferred parameters require set_function_prototype.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |
| `type_name` | string | Required | — | C data type (e.g. 'int', 'char *', 'void') |
| `binary` | string | Optional | `configured default program` | MCP transport selector only. HTTP uses top-level binary; CLI uses -b/--binary. Use an exact list_programs identity. |

## GUI context (GUI mode only)

### `get_cursor_address`

**Role:** Query. **Availability:** GUI MCP only.

Get the address at the current cursor position in the Ghidra GUI (GUI mode only).

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| *(none)* | — | — | — | No arguments. |

### `get_function_at_cursor`

**Role:** Query. **Availability:** GUI MCP only.

Get the function containing the current cursor position in the Ghidra GUI (GUI mode only).

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| *(none)* | — | — | — | No arguments. |

### `get_gui_selection`

**Role:** Query. **Availability:** GUI MCP only.

Get the selected address count and min/max addresses in the Ghidra GUI (GUI mode only); disjoint selections are not returned as separate ranges. Returns null start/end with num_addresses=0 when nothing is selected.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| *(none)* | — | — | — | No arguments. |

### `set_cursor_address`

**Role:** Mutation. **Availability:** GUI MCP only.

Move the Ghidra GUI cursor to an address (GUI mode only).

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| `addr_hex` | string | Required | — | Hex address (e.g. '0x1c908') |

### `undo_gui_transaction`

**Role:** Mutation. **Availability:** GUI MCP only.

Undo the last transaction on the Code Browser's active program (GUI mode only). Only affects the binary currently open in Code Browser; changes to other binaries cannot be undone via this tool.

| Parameter | JSON type | State | Default | Details |
|---|---|---|---|---|
| *(none)* | — | — | — | No arguments. |
