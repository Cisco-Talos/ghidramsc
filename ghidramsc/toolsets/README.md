# MCP toolsets

A toolset controls which GhidraMSC tools an MCP host advertises to an LLM when
the MCP process starts. A smaller set uses less tool-description context and
makes relevant tools easier to find. It does not change what GhidraMSC can do,
and it does not affect CLI or HTTP commands.

## Choose a toolset

| Name | Starting use |
|---|---|
| `minimal` | Quick, read-only orientation. |
| `inspect` | Broader read-only analysis. |
| `default` | Reversing and report work, including common changes. |
| `vuln-research` | More typing, structure, annotation, and export tools. |
| `most` | Broad expert use without every specialized tool. |
| `all` | Every tool available in the selected MCP mode. |

`all` is the default when `--toolset` is omitted. It is generated from the tool
registry and has no `all.txt` file. The other names correspond to editable
`.txt` files in this directory. The current named profiles contain tools
available in both headless and GUI MCP; `all` also exposes the five GUI-context
tools when used in GUI mode.

Select a profile in the command that your MCP host starts, for example:

```text
python -m ghidramsc mcp --mode headless --toolset default
```

Restart the MCP process after changing a profile. In GUI mode, CodeBrowser can
stay open; in headless mode, the restarted process opens its project again. The
MCP host may apply its own tool filtering as well.

## Edit or add a named toolset

Each `.txt` file lists one canonical tool name per line, in the order to
advertise it. Use names from the [tool catalog](../../README.md#available-tools).
Blank lines and lines whose first non-whitespace character is `#` are ignored.
An inline comment is allowed when whitespace separates it from the name:

```text
# Project orientation
list_programs
decompile_function  # inspect function behavior
```

Save a new profile as a lowercase `<name>.txt` in this directory, then pass
`--toolset <name>` without a path or extension. Unknown or repeated tool names
and empty profiles are rejected. Tools unavailable in the selected MCP mode
are omitted from that session.

For setup and MCP host examples, see
[USAGE.md](../../USAGE.md#4-pick-the-mcp-tools-the-llm-sees).
