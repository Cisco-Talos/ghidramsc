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

"""PyGhidra bridge -- manages JVM lifecycle and program access.

This module wraps pyghidra's API to provide a clean interface for
opening programs in an existing Ghidra project.  The JVM is started
once per process and reused across queries.

Usage (single program -- CLI)::

    from ghidramsc.bridge import GhidraBridge

    bridge = GhidraBridge(config)
    with bridge.open_program("mybin.so") as ctx:
        program = ctx.program
        flat_api = ctx.flat_api
        fm = program.getFunctionManager()
        ...

Usage (multi-program -- servers)::

    bridge = GhidraBridge(config)
    with bridge.open_project() as project:
        ctx = project.get_program("sample.bin")
        # ... use ctx ...
        ctx2 = project.get_program("libsample.so")
        # both stay open and cached until project closes
"""

from __future__ import annotations

import contextlib
import os
from typing import Callable, Optional, TYPE_CHECKING

from .config import GhidraMSCConfig

if TYPE_CHECKING:
    from ghidra.program.model.listing import Program  # type: ignore
    from ghidra.program.flatapi import FlatProgramAPI  # type: ignore


def _normalize_program_name(name: str) -> str:
    """Canonicalize and validate a project-relative program identity."""
    if not isinstance(name, str):
        raise TypeError("Program name must be a string")
    normalized = name.replace("\\", "/").lstrip("/")
    parts = normalized.split("/")
    if not normalized or any(part in ("", ".", "..") for part in parts):
        raise ValueError("Invalid project-relative program name: {!r}".format(name))
    return normalized


def _analyze_program(ctx: "ProgramContext") -> None:
    """Run PyGhidra-equivalent conditional analysis without saving."""
    from ghidra.program.util import GhidraProgramUtilities  # type: ignore

    program = ctx.program
    if GhidraProgramUtilities.shouldAskToAnalyze(program):
        ctx.flat_api.analyzeAll(program)
        GhidraProgramUtilities.markProgramAnalyzed(program)


class ProgramContext:
    """Holds references to an open Ghidra program and its FlatProgramAPI."""

    def __init__(
        self,
        flat_api: "FlatProgramAPI",
        program: "Program",
        project_save: Optional[Callable[["Program"], None]] = None,
        project_checkpoint: Optional[Callable[["Program"], None]] = None,
        project_rollback: Optional[Callable[["Program"], None]] = None,
    ) -> None:
        self.flat_api = flat_api
        self.program = program
        self._project_save = project_save
        self._project_checkpoint = project_checkpoint
        self._project_rollback = project_rollback

    def start_mutation_transaction(self, description: str) -> int:
        """Start an edit transaction isolated from GhidraProject's outer one.

        ``GhidraProject.openProgram`` keeps a Batch Processing transaction open.
        A nested transaction cannot provide immediate rollback read-back until
        that outer transaction ends.  Checkpoint prior successful edits before
        each mutation so a later failure can roll back only the current outer
        scope and re-arm the project lifecycle.
        """
        if self._project_checkpoint is not None:
            self._project_checkpoint(self.program)
        return self.program.startTransaction(description)

    def end_mutation_transaction(self, transaction_id: int,
                                 commit: bool) -> None:
        """End an edit and make failed headless rollback immediately visible."""
        self.program.endTransaction(transaction_id, commit)
        if not commit and self._project_rollback is not None:
            self._project_rollback(self.program)

    @property
    def save_backend(self) -> str:
        """Return the persistence backend used by :meth:`save`."""
        if self._project_save is not None:
            return "headless_ghidra_project"
        return "headless_domain_object"

    @property
    def save_comment_supported(self) -> bool:
        """Whether :meth:`save` can pass a custom comment to Ghidra."""
        return self._project_save is None

    def save(self, comment: str = "Saved by GhidraMSC") -> None:
        """Persist this program through the context's supported lifecycle."""
        if self._project_save is not None:
            self._project_save(self.program)
            return

        from ghidra.util.task import TaskMonitor  # type: ignore

        self.program.save(comment, TaskMonitor.DUMMY)

    def to_addr(self, addr_int: int | str):
        """Resolve bare hex in the default space or an exact named space."""
        if isinstance(addr_int, str):
            space_name, separator, offset = addr_int.partition("::")
            if not separator or not space_name or not offset:
                raise ValueError("Invalid qualified address: " + addr_int)
            factory = self.program.getAddressFactory()
            space = factory.getAddressSpace(space_name)
            if space is None:
                raise ValueError("Unknown address space: " + space_name)
            address = space.getAddress(int(offset, 16))
            if address is None or address.getAddressSpace() != space:
                raise ValueError("Address is outside space: " + addr_int)
            return address
        # FlatProgramAPI.toAddr overload selection can narrow a Python int to
        # Java int before a 64-bit PE image address reaches Ghidra.
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(
            addr_int)

    def get_function_at(self, addr):
        """Get the function starting at addr, or None."""
        return self.flat_api.getFunctionAt(addr)

    def get_function_containing(self, addr):
        """Get the function containing addr, or None."""
        return self.flat_api.getFunctionContaining(addr)

    def resolve_function(self, addr_int: int | str):
        """Find function at or containing the given address.  Returns None if
        no function covers the address."""
        addr = self.to_addr(addr_int)
        func = self.get_function_at(addr)
        if func is None:
            func = self.get_function_containing(addr)
        return func


class GhidraBridge:
    """Manages pyghidra JVM startup and program access."""

    def __init__(
        self, config: GhidraMSCConfig, owner: Optional[str] = None
    ) -> None:
        self.config = config
        self.owner = owner
        self._started = False

    def ensure_started(self) -> None:
        """Start pyghidra / the JVM if not already running."""
        import pyghidra

        if self._started:
            return

        if pyghidra.started():
            if self.owner is not None:
                raise RuntimeError(
                    "--owner must be set before the local JVM starts"
                )
            self._started = True
            return

        # Set GHIDRA_INSTALL_DIR so pyghidra can find the installation
        os.environ["GHIDRA_INSTALL_DIR"] = str(self.config.ghidra_install_dir)
        if self.owner is None:
            pyghidra.start(install_dir=self.config.ghidra_install_dir)
        else:
            launcher = pyghidra.HeadlessPyGhidraLauncher(
                install_dir=self.config.ghidra_install_dir
            )
            launcher.add_vmargs("-Duser.name={}".format(self.owner))
            launcher.start()
        self._started = True

    @contextlib.contextmanager
    def open_program(self, program_name: str, analyze: bool = False):
        """Open a program from the configured Ghidra project.

        Yields a `ProgramContext` with ``flat_api`` and ``program``.

        Parameters
        ----------
        program_name : str
            Name of the program inside the Ghidra project (e.g. ``mybin.so``).
        analyze : bool
            Whether to run auto-analysis.  Almost always False for existing
            projects that are already analyzed.
        """
        # PyGhidra's deprecated ``open_program`` context manager saves the
        # program unconditionally on exit.  Route one-shot access through the
        # same explicit-persistence project lifecycle used by servers instead.
        with self.open_project() as project:
            ctx = project.get_program(program_name)
            if analyze:
                _analyze_program(ctx)
            yield ctx

    @contextlib.contextmanager
    def open_project(self):
        """Open the Ghidra project for multi-program access.

        Yields a :class:`ProjectHandle` from which individual programs
        can be opened on demand (and cached for the lifetime of the
        project).  Use this instead of :meth:`open_program` when you
        need to query multiple binaries without restarting.
        """
        self.ensure_started()

        from ghidra.base.project import GhidraProject       # type: ignore
        from ghidra.app.script import GhidraScriptUtil       # type: ignore

        project = GhidraProject.openProject(
            str(self.config.project_path),
            self.config.project_name,
            True,   # restore flag
        )
        GhidraScriptUtil.acquireBundleHostReference()
        handle = ProjectHandle(project, self.config)
        try:
            yield handle
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
            handle.close()


class ProjectHandle:
    """Wraps an open GhidraProject.  Programs are opened on demand and
    cached for the lifetime of the handle.

    The project is locked while the handle is open -- exactly like
    having the project open in the Ghidra GUI.
    """

    def __init__(self, ghidra_project, config: "GhidraMSCConfig") -> None:
        self._project = ghidra_project
        self._config = config
        self._programs: dict[str, ProgramContext] = {}   # name -> ctx

    # -- program access --------------------------------------------

    def get_program(self, name: str) -> ProgramContext:
        """Return a ProgramContext for *name*, opening it if necessary.

        *name* can be a bare filename (``"example.dll"``) resolved from
        the project root, or a folder-qualified path
        (``"win32/example.dll"``) to open a program inside a subfolder.
        """
        normalized = _normalize_program_name(name)
        if normalized in self._programs:
            return self._programs[normalized]

        from ghidra.program.flatapi import FlatProgramAPI  # type: ignore

        folder_path, leaf = self._program_location(normalized)

        program = self._project.openProgram(folder_path, leaf, False)
        if program is None:
            raise RuntimeError(
                "Program '{}' not found in project '{}' at '{}'".format(
                    normalized, self._config.project_name, self._config.project_path,
                )
            )
        flat_api = FlatProgramAPI(program)
        ctx = ProgramContext(
            flat_api,
            program,
            project_save=lambda opened_program: self._save_project_program(
                normalized, opened_program
            ),
            project_checkpoint=self._project.checkPoint,
            project_rollback=self._project.rollback,
        )
        self._programs[normalized] = ctx
        return ctx

    @staticmethod
    def _program_location(normalized: str) -> tuple[str, str]:
        """Split a normalized program identity for ``GhidraProject`` APIs."""
        if "/" in normalized:
            folder, leaf = normalized.rsplit("/", 1)
            return "/" + folder, leaf
        return "/", normalized

    def _save_project_program(self, normalized: str, program: "Program") -> None:
        """Save and restore GhidraProject's outer transaction on failure."""
        try:
            self._project.save(program)
        except Exception:
            # GhidraProject.save() ends its Batch Processing transaction before
            # DomainFile.save().  Its failure path does not start a replacement,
            # so reopen the exact same program through the public project API to
            # re-arm that transaction before the original exception is reported.
            folder_path, leaf = self._program_location(normalized)
            self._project.openProgram(folder_path, leaf, False)
            raise

    def list_programs(self) -> list[str]:
        """Return the names of every program in the project, recursing
        into subfolders.  Programs in subfolders are returned as
        ``folder/name`` (e.g. ``win32/example.dll``)."""
        results: list[str] = []
        self._collect_programs(self._project.getRootFolder(), "", results)
        return sorted(results)

    def _collect_programs(self, folder, prefix: str, out: list[str]) -> None:
        """Recursively collect program names from *folder*."""
        for f in folder.getFiles():
            name = str(f.getName())
            out.append(prefix + name if prefix else name)
        for sub in folder.getFolders():
            sub_name = str(sub.getName())
            sub_prefix = (prefix + sub_name + "/") if prefix else (sub_name + "/")
            self._collect_programs(sub, sub_prefix, out)

    # -- persistence -----------------------------------------------

    def save(self, name: Optional[str] = None) -> None:
        """Save one program (by name) or all cached programs."""
        if name is not None:
            ctx = self._programs.get(_normalize_program_name(name))
            if ctx is not None:
                ctx.save()
        else:
            for ctx in self._programs.values():
                ctx.save()

    def close(self) -> None:
        """Close the project without implicitly saving cached programs.

        Persistence is deliberately explicit through ``save_program`` or
        :meth:`save`; callers can inspect dirty state before closing.
        """
        self._project.close()
