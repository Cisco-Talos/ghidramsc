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

"""Focused transaction regressions for stable-identity mutations."""

from __future__ import annotations

import sys
from types import ModuleType
from unittest import mock
import pytest

from ghidramsc.bridge import ProgramContext
from ghidramsc.queries import (
    _find_high_var_after,
    _run_stable_identity_transaction,
)
from ghidramsc._query_variables import (
    _disclose_name_only_materialization,
    _split_use_anchors,
    _verify_split_use_isolation,
    set_variable_name_by_id,
    set_variable_type_by_id,
)


@pytest.mark.parametrize("parameter,locked", [(True, True), (False, False)])
def test_name_only_materialization_discloses_native_lock_transition(
        parameter, locked):
    old = {
        "name": "param_1" if parameter else "uVar5",
        "type": "undefined4", "database_backed": False,
        "name_locked": False, "type_locked": False, "is_param": parameter,
    }
    stored = {
        "name": "renamed", "type": "undefined4",
        "database_backed": True, "name_locked": True,
        "type_locked": locked, "is_param": parameter,
    }
    result = {"status": "success", "old": old, "stored": stored}
    assert _disclose_name_only_materialization(result) is result
    effect = result["name_only_materialization"]
    assert effect["caller_requested_type"] is False
    assert effect["before"]["type"] == effect["after"]["type"] == "undefined4"
    assert effect["before"]["database_backed"] is False
    assert effect["after"]["database_backed"] is True
    assert effect["before"]["type_locked"] is False
    assert effect["after"]["type_locked"] is locked
    assert effect["inferred_parameter_type_locked"] is locked
    assert ("guidance" in effect) is locked


def _split_instance(group, pc):
    instance = mock.Mock()
    instance.getMergeGroup.return_value = group
    instance.getPCAddress.return_value = pc
    instance.getAddress.return_value = "register:00000000"
    instance.getSize.return_value = 4
    return instance


def _split_symbol(name, instances):
    symbol = mock.Mock()
    symbol.getName.return_value = name
    symbol.getHighVariable.return_value.getInstances.return_value = instances
    return symbol


@pytest.mark.parametrize("fresh,expected_error", [
    (("selected", "remaining"), None),
    (("merged",), "not isolated"),
    (("selected", "selected"), "Remaining merge-group uses"),
    (("selected",), "changed or disappeared"),
])
def test_split_requires_fresh_exact_use_ownership(fresh, expected_error):
    first = _split_instance(0, "14000128c")
    second = _split_instance(1, "1400012b9")
    original = _split_symbol("uVar5", [first, second])
    selected, remaining = _split_use_anchors(original, "merge:1")
    symbols = []
    if fresh == ("merged",):
        symbols.append(_split_symbol("U15Selected", [first, second]))
    else:
        symbols.append(_split_symbol("U15Selected", [second]))
        if len(fresh) == 2:
            symbols.append(_split_symbol(
                "U15Selected" if fresh[1] == "selected" else "uVar5",
                [first],
            ))
    decompiler = mock.Mock()
    result = decompiler.decompileFunction.return_value
    result.decompileCompleted.return_value = True
    result.getHighFunction.return_value.getLocalSymbolMap.return_value.getSymbols.return_value = symbols
    ctx = mock.Mock()
    with (
        mock.patch("ghidramsc._query_variables._get_decompiler",
                   return_value=decompiler),
        mock.patch("ghidramsc._query_variables._get_monitor", return_value=object()),
    ):
        if expected_error:
            with pytest.raises(ValueError, match=expected_error):
                _verify_split_use_isolation(
                    ctx, "140001270", selected, remaining, "U15Selected"
                )
        else:
            _verify_split_use_isolation(
                ctx, "140001270", selected, remaining, "U15Selected"
            )
    decompiler.dispose.assert_called_once()


def _project_context(state, events, *, restore_on_rollback):
    program = mock.MagicMock()
    program.startTransaction.side_effect = lambda description: (
        events.append(("start", description)) or 17
    )
    program.endTransaction.side_effect = lambda tx_id, commit: events.append(
        ("end", tx_id, commit)
    )

    def checkpoint(_program):
        events.append(("checkpoint", state["value"]))

    def rollback(_program):
        events.append(("rollback", state["value"]))
        if restore_on_rollback:
            state["value"] = "old"

    return ProgramContext(
        mock.MagicMock(),
        program,
        project_checkpoint=checkpoint,
        project_rollback=rollback,
    )


def _run(ctx, state, events, apply, validate_rollback):
    def success_read_back():
        events.append(("success_read_back", state["value"]))
        return {"value": state["value"]}

    def rollback_read_back():
        events.append(("rollback_read_back", state["value"]))
        return {"value": state["value"]}

    return _run_stable_identity_transaction(
        ctx,
        "set_variable_name_by_id",
        "Rename decompiler variable",
        {"new_name": "new"},
        {"value": "old"},
        apply,
        success_read_back,
        lambda stored: (
            None if stored["value"] == "new" else "success mismatch"
        ),
        rollback_read_back,
        validate_rollback,
    )


def test_success_is_reported_only_after_transaction_close_and_final_readback():
    state = {"value": "old"}
    events = []
    ctx = _project_context(state, events, restore_on_rollback=True)

    def apply():
        events.append(("apply", state["value"]))
        state["value"] = "new"

    result = _run(
        ctx,
        state,
        events,
        apply,
        lambda stored: None if stored["value"] == "old" else "not restored",
    )

    assert result["status"] == "success"
    assert result["stored"] == {"value": "new"}
    assert result["transaction"] == {
        "started": True,
        "committed": True,
        "description": "Rename decompiler variable",
    }
    assert events == [
        ("checkpoint", "old"),
        ("start", "Rename decompiler variable"),
        ("apply", "old"),
        ("end", 17, True),
        ("success_read_back", "new"),
    ]


def test_failed_apply_rolls_back_outer_project_before_reporting_rolled_back():
    state = {"value": "old"}
    events = []
    ctx = _project_context(state, events, restore_on_rollback=True)

    def apply():
        events.append(("apply", state["value"]))
        state["value"] = "new"
        raise ValueError("forced read-back mismatch")

    result = _run(
        ctx,
        state,
        events,
        apply,
        lambda stored: None if stored["value"] == "old" else "not restored",
    )

    assert result["status"] == "rolled_back"
    assert result["stored"] == result["old"] == {"value": "old"}
    assert result["transaction"]["committed"] is False
    assert events == [
        ("checkpoint", "old"),
        ("start", "Rename decompiler variable"),
        ("apply", "old"),
        ("end", 17, False),
        ("rollback", "new"),
        ("rollback_read_back", "old"),
    ]


def test_retained_state_is_failed_never_reported_as_rolled_back():
    state = {"value": "old"}
    events = []
    ctx = _project_context(state, events, restore_on_rollback=False)

    def apply():
        state["value"] = "new"
        raise ValueError("forced read-back mismatch")

    result = _run(
        ctx,
        state,
        events,
        apply,
        lambda stored: None if stored["value"] == "old" else "not restored",
    )

    assert result["status"] == "failed"
    assert result["stored"] == {"value": "new"}
    assert result["transaction"]["committed"] is False
    assert "Rollback verification failed: not restored" in result["error"]


def test_snapshot_id_reuse_does_not_capture_the_wrong_variable():
    recycled = mock.MagicMock()
    recycled.getId.return_value = int("4000a400000000ca", 16)
    recycled.isParameter.return_value = False
    recycled.getPCAddress.return_value = "00032d5c"
    recycled.getStorage.return_value = "r0:4"
    recycled.getName.return_value = "iVar3"

    materialized_parameter = mock.MagicMock()
    materialized_parameter.getId.return_value = int("2ded", 16)
    materialized_parameter.isParameter.return_value = True
    materialized_parameter.getCategoryIndex.return_value = 2

    result = mock.MagicMock()
    result.decompileCompleted.return_value = True
    symbols = [recycled, materialized_parameter]
    symbol_map = result.getHighFunction.return_value.getLocalSymbolMap.return_value
    symbol_map.getSymbols.return_value = symbols
    decompiler = mock.MagicMock()
    decompiler.decompileFunction.return_value = result
    ctx = mock.MagicMock()
    ctx.resolve_function.return_value = mock.MagicMock()
    locator = {
        "var_id": "high:4000a400000000ca",
        "name": "param_3",
        "storage": "r2:4",
        "pc_addr": "00032c6f",
        "is_param": True,
        "category_index": 2,
    }

    with (
        mock.patch(
            "ghidramsc._query_variables._get_decompiler",
            return_value=decompiler,
        ),
        mock.patch("ghidramsc._query_variables._get_monitor", return_value=object()),
    ):
        returned_decompiler, selected = _find_high_var_after(
            ctx, "0x32c70", locator
        )

    assert returned_decompiler is decompiler
    assert selected is materialized_parameter


def test_requested_name_recovers_a_renamed_symbol_with_changed_snapshot_location():
    renamed = mock.MagicMock()
    renamed.getId.return_value = 99
    renamed.getName.return_value = "semantic_cursor"
    renamed.getStorage.return_value = "Stack[-0x20]:4"
    renamed.getPCAddress.return_value = "00001100"
    renamed.isParameter.return_value = False

    stale_storage = mock.MagicMock()
    stale_storage.getId.return_value = 100
    stale_storage.getName.return_value = "other"
    stale_storage.getStorage.return_value = "r1:4"
    stale_storage.getPCAddress.return_value = "00001000"
    stale_storage.isParameter.return_value = False

    second_stale_storage = mock.MagicMock()
    second_stale_storage.getId.return_value = 101
    second_stale_storage.getName.return_value = "another"
    second_stale_storage.getStorage.return_value = "r1:4"
    second_stale_storage.getPCAddress.return_value = "00001000"
    second_stale_storage.isParameter.return_value = False

    result = mock.MagicMock()
    result.decompileCompleted.return_value = True
    result.getHighFunction.return_value.getLocalSymbolMap.return_value.getSymbols.return_value = [
        stale_storage, second_stale_storage, renamed
    ]
    decompiler = mock.MagicMock()
    decompiler.decompileFunction.return_value = result
    ctx = mock.MagicMock()
    ctx.resolve_function.return_value = mock.MagicMock()
    locator = {
        "var_id": "high:13",
        "name": "uVar1",
        "expected_name": "semantic_cursor",
        "storage": "r1:4",
        "pc_addr": "00001000",
        "is_param": False,
        "category_index": -1,
    }
    with (
        mock.patch("ghidramsc._query_variables._get_decompiler", return_value=decompiler),
        mock.patch("ghidramsc._query_variables._get_monitor", return_value=object()),
    ):
        returned_decompiler, selected = _find_high_var_after(ctx, "0x1000", locator)

    assert returned_decompiler is decompiler
    assert selected is renamed


def test_rename_and_retype_split_reject_before_starting_a_transaction():
    modules = {}
    for name in ("ghidra", "ghidra.program", "ghidra.program.model",
                 "ghidra.program.model.pcode", "ghidra.program.model.symbol"):
        module = ModuleType(name)
        module.__path__ = []
        modules[name] = module
    modules["ghidra.program.model.pcode"].HighFunctionDBUtil = mock.Mock()
    modules["ghidra.program.model.symbol"].SourceType = mock.Mock()
    decompiler = mock.Mock()
    symbol = mock.Mock()
    old = {"persistable": True, "name": "iVar1"}
    with (
        mock.patch.dict(sys.modules, modules),
        mock.patch("ghidramsc._query_variables._select_high_var",
                   return_value=(decompiler, mock.Mock(), symbol)),
        mock.patch("ghidramsc._query_variables._high_var_state",
                   return_value=old),
        mock.patch("ghidramsc._query_variables._validate_merge_group_selection",
                   return_value=""),
        mock.patch("ghidramsc._query_variables._resolve_type",
                   return_value=mock.Mock()),
        mock.patch("ghidramsc._query_variables._start_mutation_transaction",
                   side_effect=AssertionError("transaction must not start")),
    ):
        renamed = set_variable_name_by_id(
            mock.Mock(), "0x1000", "high:1", "selected",
            split_use=True, merge_group_id="merge:1")
        retyped = set_variable_type_by_id(
            mock.Mock(), "0x1000", "high:1", "int",
            split_use=True, merge_group_id="merge:1")
    for result in (renamed, retyped):
        assert result["status"] == "unsupported"
        assert result["transaction"] == {"started": False, "committed": False}
        assert "create_variable_by_id" in result["error"]
    assert decompiler.dispose.call_count == 2
