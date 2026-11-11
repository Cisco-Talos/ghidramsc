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

"""Focused lifecycle tests for the direct bridge."""

from contextlib import contextmanager
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import mock

import pytest

from ghidramsc.bridge import GhidraBridge, ProgramContext, ProjectHandle
from ghidramsc.queries import delete_function, save_program


def test_owner_uses_headless_launcher_before_jvm_start(monkeypatch):
    launcher = mock.MagicMock()
    pyghidra = SimpleNamespace(
        started=mock.MagicMock(return_value=False),
        start=mock.MagicMock(),
        HeadlessPyGhidraLauncher=mock.MagicMock(return_value=launcher),
    )
    monkeypatch.setitem(sys.modules, "pyghidra", pyghidra)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    install_dir = Path("C:/fake/ghidra")
    config = mock.MagicMock(ghidra_install_dir=install_dir)
    bridge = GhidraBridge(config, owner="patrick")

    bridge.ensure_started()
    bridge.ensure_started()

    pyghidra.HeadlessPyGhidraLauncher.assert_called_once_with(
        install_dir=install_dir
    )
    assert launcher.mock_calls == [
        mock.call.add_vmargs("-Duser.name=patrick"),
        mock.call.start(),
    ]
    pyghidra.start.assert_not_called()


def test_default_startup_still_uses_pyghidra_start(monkeypatch):
    pyghidra = SimpleNamespace(
        started=mock.MagicMock(return_value=False),
        start=mock.MagicMock(),
        HeadlessPyGhidraLauncher=mock.MagicMock(),
    )
    monkeypatch.setitem(sys.modules, "pyghidra", pyghidra)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    install_dir = Path("C:/fake/ghidra")
    bridge = GhidraBridge(mock.MagicMock(ghidra_install_dir=install_dir))

    bridge.ensure_started()

    pyghidra.start.assert_called_once_with(install_dir=install_dir)
    pyghidra.HeadlessPyGhidraLauncher.assert_not_called()


def test_owner_rejected_after_jvm_already_started(monkeypatch):
    pyghidra = SimpleNamespace(
        started=mock.MagicMock(return_value=True),
        start=mock.MagicMock(),
        HeadlessPyGhidraLauncher=mock.MagicMock(),
    )
    monkeypatch.setitem(sys.modules, "pyghidra", pyghidra)
    bridge = GhidraBridge(
        mock.MagicMock(ghidra_install_dir=Path("C:/fake/ghidra")),
        owner="patrick",
    )

    with pytest.raises(RuntimeError, match="before the local JVM starts"):
        bridge.ensure_started()

    pyghidra.start.assert_not_called()
    pyghidra.HeadlessPyGhidraLauncher.assert_not_called()


def test_open_program_uses_explicit_project_lifecycle(monkeypatch):
    bridge = GhidraBridge(mock.MagicMock())
    ctx = mock.MagicMock()
    project = mock.MagicMock()
    project.get_program.return_value = ctx
    events = []

    @contextmanager
    def open_project():
        events.append("open")
        try:
            yield project
        finally:
            events.append("close")

    monkeypatch.setattr(bridge, "open_project", open_project)
    with bridge.open_program("folder/test") as opened:
        assert opened is ctx
        assert events == ["open"]
    project.get_program.assert_called_once_with("folder/test")
    assert events == ["open", "close"]


def test_open_program_preserves_requested_analysis(monkeypatch):
    bridge = GhidraBridge(mock.MagicMock())
    ctx = mock.MagicMock()
    project = mock.MagicMock()
    project.get_program.return_value = ctx

    @contextmanager
    def open_project():
        yield project

    analyze = mock.MagicMock()
    monkeypatch.setattr(bridge, "open_project", open_project)
    monkeypatch.setattr("ghidramsc.bridge._analyze_program", analyze)
    with bridge.open_program("test", analyze=True):
        pass
    analyze.assert_called_once_with(ctx)


def test_project_context_delegates_save_without_comment():
    project = mock.MagicMock()
    config = mock.MagicMock()
    program = mock.MagicMock()
    project.openProgram.return_value = program
    handle = ProjectHandle(project, config)

    ctx = handle.get_program("test")
    ctx.save("checkpoint")

    assert ctx.save_backend == "headless_ghidra_project"
    assert ctx.save_comment_supported is False
    project.save.assert_called_once_with(program)
    program.save.assert_not_called()


def test_project_context_checkpoints_before_mutation_transaction():
    events = []
    project = mock.MagicMock()
    config = mock.MagicMock()
    program = mock.MagicMock()
    project.checkPoint.side_effect = lambda opened: events.append(
        ("checkpoint", opened)
    )
    program.startTransaction.side_effect = lambda description: (
        events.append(("start", description)) or 17
    )
    project.openProgram.return_value = program
    ctx = ProjectHandle(project, config).get_program("test")

    transaction_id = ctx.start_mutation_transaction("Rename function")

    assert transaction_id == 17
    project.checkPoint.assert_called_once_with(program)
    program.startTransaction.assert_called_once_with("Rename function")
    assert events == [
        ("checkpoint", program),
        ("start", "Rename function"),
    ]


def test_project_context_rolls_back_failed_outer_mutation_scope():
    project = mock.MagicMock()
    config = mock.MagicMock()
    program = mock.MagicMock()
    project.openProgram.return_value = program
    ctx = ProjectHandle(project, config).get_program("test")

    ctx.end_mutation_transaction(17, False)

    program.endTransaction.assert_called_once_with(17, False)
    project.rollback.assert_called_once_with(program)


def test_project_context_does_not_roll_back_successful_mutation():
    project = mock.MagicMock()
    config = mock.MagicMock()
    program = mock.MagicMock()
    project.openProgram.return_value = program
    ctx = ProjectHandle(project, config).get_program("test")

    ctx.end_mutation_transaction(17, True)

    program.endTransaction.assert_called_once_with(17, True)
    project.rollback.assert_not_called()


def test_function_failure_routes_through_project_aware_rollback(monkeypatch):
    events = []
    state = {"exists": True}
    address = mock.MagicMock(__str__=mock.MagicMock(return_value="00000100"))
    function = mock.MagicMock()
    function.getEntryPoint.return_value = address
    flat_api = mock.MagicMock()
    flat_api.toAddr.return_value = address
    flat_api.getFunctionAt.return_value = function
    flat_api.getFunctionContaining.return_value = None
    manager = mock.MagicMock()

    def remove(_entry):
        events.append("mutate")
        state["exists"] = False
        return False

    manager.removeFunction.side_effect = remove
    program = mock.MagicMock()
    program.getFunctionManager.return_value = manager
    program.startTransaction.side_effect = lambda _description: (
        events.append("start") or 17
    )
    program.endTransaction.side_effect = lambda _tx_id, commit: events.append(
        ("end", commit)
    )

    def checkpoint(_program):
        events.append("checkpoint")

    def rollback(_program):
        events.append("rollback")
        state["exists"] = True

    ctx = ProgramContext(
        flat_api,
        program,
        project_checkpoint=checkpoint,
        project_rollback=rollback,
    )
    monkeypatch.setattr(
        "ghidramsc._query_functions._function_state",
        lambda _ctx, _address: {"exists": state["exists"]},
    )

    result = delete_function(ctx, "0x100")

    assert result["status"] == "rolled_back"
    assert result["transaction"] == {"started": True, "committed": False}
    assert state["exists"] is True
    assert events == [
        "checkpoint",
        "start",
        "mutate",
        ("end", False),
        "rollback",
    ]


def test_standalone_context_saves_domain_object_with_comment(monkeypatch):
    monitor = mock.MagicMock()
    monkeypatch.setitem(
        __import__("sys").modules,
        "ghidra.util.task",
        mock.MagicMock(TaskMonitor=mock.MagicMock(DUMMY=monitor)),
    )
    program = mock.MagicMock()
    ctx = ProgramContext(mock.MagicMock(), program)

    ctx.save("checkpoint")

    assert ctx.save_backend == "headless_domain_object"
    assert ctx.save_comment_supported is True
    program.save.assert_called_once_with("checkpoint", monitor)


def test_project_save_failure_reopens_path_before_clean_close():
    events = []
    project = mock.MagicMock()
    config = mock.MagicMock()
    program = mock.MagicMock()
    program.isChanged.side_effect = [True, True]
    program.canSave.return_value = True
    program.getDomainFile.return_value.getPathname.return_value = "/folder/test"

    def open_program(folder, leaf, read_only):
        events.append(("open", folder, leaf, read_only))
        return program

    def fail_save(opened_program):
        events.append(("save", opened_program))
        raise OSError("disk full")

    def close_project():
        assert events[-1] == ("open", "/folder", "test", False)
        events.append(("close",))

    project.openProgram.side_effect = open_program
    project.save.side_effect = fail_save
    project.close.side_effect = close_project
    handle = ProjectHandle(project, config)
    ctx = handle.get_program("folder/test")

    result = save_program(ctx, "checkpoint")
    handle.close()

    assert result["status"] == "failed"
    assert result["save"]["completed"] is False
    assert result["save"]["comment_supported"] is False
    assert result["error"] == "Save failed: disk full"
    assert events == [
        ("open", "/folder", "test", False),
        ("save", program),
        ("open", "/folder", "test", False),
        ("close",),
    ]
