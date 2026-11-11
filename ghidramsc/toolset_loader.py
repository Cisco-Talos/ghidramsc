# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Load one named MCP toolset from the packaged toolsets directory."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import re
from typing import FrozenSet, Tuple

from .tool_registry import (
    MCP_EXECUTION_MODES,
    TOOLS,
    tool_mcp_modes,
)


_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
_RESOURCE_DIR = "toolsets"
_REGISTRY_BY_NAME = {entry["name"]: entry for entry in TOOLS}


class ToolsetError(ValueError):
    """Raised when an MCP toolset cannot be resolved or validated."""


@dataclass(frozen=True)
class ResolvedToolset:
    """Immutable requested and mode-effective MCP tool selection."""

    name: str
    mode: str
    source: str
    requested_names: Tuple[str, ...]
    effective_names: Tuple[str, ...]
    omitted_unavailable: Tuple[str, ...]

    @property
    def requested_set(self) -> FrozenSet[str]:
        return frozenset(self.requested_names)

    @property
    def effective_set(self) -> FrozenSet[str]:
        return frozenset(self.effective_names)

    @property
    def omitted_set(self) -> FrozenSet[str]:
        return frozenset(self.omitted_unavailable)


def _validate_name(name: str) -> None:
    if not isinstance(name, str) or _NAME_RE.fullmatch(name) is None:
        raise ToolsetError(
            "Invalid toolset name {!r}; use a lowercase name without a path "
            "or filename extension.".format(name)
        )


def _read_named_toolset(name: str) -> Tuple[Tuple[str, ...], str]:
    filename = "{}.txt".format(name)
    root = resources.files("ghidramsc").joinpath(_RESOURCE_DIR)
    try:
        entries = {entry.name: entry for entry in root.iterdir()}
    except OSError as exc:
        raise ToolsetError(
            "The packaged ghidramsc/toolsets directory could not be read: "
            "{}.".format(exc)
        ) from exc
    source = "ghidramsc/toolsets/{}".format(filename)
    entry = entries.get(filename)
    try:
        is_file = entry is not None and entry.is_file()
    except OSError as exc:
        raise ToolsetError(
            "Toolset {!r} ({}) could not be inspected: {}.".format(
                name, source, exc
            )
        ) from exc
    if not is_file:
        raise ToolsetError(
            "Toolset {!r} was not found at ghidramsc/toolsets/{}.".format(
                name, filename
            )
        )

    try:
        text = entry.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ToolsetError(
            "Toolset {!r} ({}) is not valid UTF-8: {}.".format(
                name, source, exc
            )
        ) from exc
    except OSError as exc:
        raise ToolsetError(
            "Toolset {!r} ({}) could not be read: {}.".format(
                name, source, exc
            )
        ) from exc

    selected = []
    first_lines = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        tool_name = raw_line.strip()
        if not tool_name or tool_name.startswith("#"):
            continue
        # A separator is required so a typo such as "tool#old" stays invalid.
        tool_name = re.split(r"\s+#", tool_name, maxsplit=1)[0].rstrip()
        if tool_name in first_lines:
            raise ToolsetError(
                "Toolset {!r} ({}) repeats tool {!r} at line {}; first seen "
                "at line {}.".format(
                    name, source, tool_name, line_number, first_lines[tool_name]
                )
            )
        if tool_name not in _REGISTRY_BY_NAME:
            raise ToolsetError(
                "Toolset {!r} ({}) line {} names unknown tool {!r}.".format(
                    name, source, line_number, tool_name
                )
            )
        first_lines[tool_name] = line_number
        selected.append(tool_name)

    if not selected:
        raise ToolsetError(
            "Toolset {!r} ({}) enables no tools.".format(name, source)
        )
    return tuple(selected), source


def resolve_toolset(name: str = "all", mode: str = "plugin") -> ResolvedToolset:
    """Resolve a named toolset and filter it for one MCP execution mode."""
    _validate_name(name)
    if mode not in MCP_EXECUTION_MODES:
        raise ToolsetError("Unknown MCP execution mode: {!r}.".format(mode))

    if name == "all":
        requested = tuple(entry["name"] for entry in TOOLS)
        source = "virtual:all"
    else:
        requested, source = _read_named_toolset(name)

    effective = []
    omitted = []
    for tool_name in requested:
        if mode in tool_mcp_modes(_REGISTRY_BY_NAME[tool_name]):
            effective.append(tool_name)
        else:
            omitted.append(tool_name)

    return ResolvedToolset(
        name=name,
        mode=mode,
        source=source,
        requested_names=requested,
        effective_names=tuple(effective),
        omitted_unavailable=tuple(omitted),
    )
