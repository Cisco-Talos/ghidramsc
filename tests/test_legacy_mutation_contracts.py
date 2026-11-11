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

"""Focused parity tests for the last U08 legacy mutation tranche."""

from __future__ import annotations

import json
import sys
from types import ModuleType
from unittest import mock

from ghidramsc import _query_annotations, _query_functions, queries


def _result(operation, status):
    return {
        "operation": operation,
        "status": status,
        "requested": {},
        "transaction": {"started": False, "committed": False},
    }


def test_bulk_create_funcs_aggregates_independent_item_results(tmp_path):
    path = tmp_path / "functions.json"
    path.write_text(json.dumps([
        "0x100",
        {"addr": "0x200", "name": "named"},
        "bad",
    ]), encoding="utf-8")
    items = [
        _result("create_function", "success"),
        _result("create_function", "no_change"),
        _result("create_function", "rolled_back"),
    ]
    with mock.patch.object(
        _query_functions, "create_function", side_effect=items
    ) as create:
        result = queries.create_functions(mock.MagicMock(), str(path))

    assert result["status"] == "partial_success"
    assert result["atomicity"] == "per_item"
    assert (result["succeeded"], result["unchanged"], result["failed"]) == (
        1, 1, 1
    )
    assert create.call_args_list == [
        mock.call(mock.ANY, "0x100", ""),
        mock.call(mock.ANY, "0x200", "named"),
        mock.call(mock.ANY, "bad", ""),
    ]


def test_import_annotations_preserves_java_item_order_and_source(tmp_path):
    data = {
        "function_signatures": [{"addr": "0x100", "name": "renamed"}],
        "symbols": [{"addr": "0x200", "name": "label"}],
        "comments": [{"addr": "0x300", "type": "eol", "text": "note"}],
    }
    path = tmp_path / "annotations.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with (
        mock.patch.object(
            _query_annotations,
            "set_function_name",
            return_value=_result("set_function_name", "success"),
        ),
        mock.patch.object(
            _query_annotations,
            "_import_symbol",
            return_value=_result("import_symbol", "no_change"),
        ),
        mock.patch.object(
            _query_annotations,
            "set_comment_at_address",
            return_value=_result("set_comment_at_address", "rolled_back"),
        ),
    ):
        result = queries.import_annotations(mock.MagicMock(), str(path))

    assert result["status"] == "partial_success"
    assert [item["import_kind"] for item in result["items"]] == [
        "function_signature", "symbol", "comment"
    ]
    assert [item["source"] for item in result["items"]] == [
        data["function_signatures"][0],
        data["symbols"][0],
        data["comments"][0],
    ]


def _command_modules(command_type, create_type=None):
    disassemble = ModuleType("ghidra.app.cmd.disassemble")
    disassemble.DisassembleCommand = command_type
    function = ModuleType("ghidra.app.cmd.function")
    if create_type is not None:
        function.CreateFunctionCmd = create_type
    address = ModuleType("ghidra.program.model.address")
    address.AddressSet = lambda start, end: (start, end)
    return {
        "ghidra.app.cmd.disassemble": disassemble,
        "ghidra.app.cmd.function": function,
        "ghidra.program.model.address": address,
    }


def test_disassemble_at_commits_only_after_instruction_readback():
    state = {"instruction": False}

    class Command:
        def __init__(self, *_args):
            pass

        def applyTo(self, _program, _monitor):
            state["instruction"] = True
            return True

        def getStatusMsg(self):
            return ""

        def getDisassembledAddressSet(self):
            result = mock.MagicMock()
            result.getNumAddresses.return_value = 1
            result.getAddressRanges.return_value.hasNext.return_value = False
            return result

    start = mock.MagicMock(__str__=mock.MagicMock(return_value="100"))
    start.compareTo.return_value = 0
    start.subtract.return_value = 0
    start.getAddressSpace.return_value.equals.return_value = True
    ctx = mock.MagicMock()
    ctx.to_addr.return_value = start
    ctx.program.startTransaction.return_value = 7
    ctx.program.getListing.return_value.getCodeUnitContaining.return_value = None

    def range_state(*_args):
        return {
            "start_is_instruction": state["instruction"],
            "coverage": {"status": "partial", "undefined_bytes": 2},
        }

    with (
        mock.patch.dict(sys.modules, _command_modules(Command)),
        mock.patch.object(_query_annotations, "_code_state", side_effect=range_state),
    ):
        result = queries.disassemble_memory(ctx, "0x100")

    assert result["status"] == "success"
    assert result["old"]["start_is_instruction"] is False
    assert result["stored"]["start_is_instruction"] is True
    assert result["stored"]["newly_disassembled"]["address_count"] == 1
    assert result["stored"]["coverage"]["status"] == "partial"
    ctx.program.endTransaction.assert_called_once_with(7, True)


def test_disassemble_existing_instruction_is_no_change_without_transaction():
    start = mock.MagicMock(__str__=mock.MagicMock(return_value="100"))
    start.compareTo.return_value = 0
    start.subtract.return_value = 0
    start.getAddressSpace.return_value.equals.return_value = True
    unit = mock.MagicMock()
    unit.getMinAddress.return_value = start
    ctx = mock.MagicMock()
    ctx.to_addr.return_value = start
    ctx.program.getListing.return_value.getCodeUnitContaining.return_value = unit
    with (
        mock.patch.dict(sys.modules, _command_modules(mock.MagicMock)),
        mock.patch.object(_query_annotations, "_code_state",
                          return_value={"start_is_instruction": True}),
    ):
        result = queries.disassemble_memory(ctx, "0x100")
    assert result["status"] == "no_change"
    ctx.program.startTransaction.assert_not_called()


def test_disassemble_offcut_start_is_rejected_without_transaction():
    start = mock.MagicMock(__str__=mock.MagicMock(return_value="101"))
    start.compareTo.return_value = 0
    start.subtract.return_value = 0
    start.getAddressSpace.return_value.equals.return_value = True
    unit = mock.MagicMock()
    unit.getMinAddress.return_value.compareTo.return_value = -1
    ctx = mock.MagicMock()
    ctx.to_addr.return_value = start
    ctx.program.getListing.return_value.getCodeUnitContaining.return_value = unit
    with (
        mock.patch.dict(sys.modules, _command_modules(mock.MagicMock)),
        mock.patch.object(_query_annotations, "_code_state",
                          return_value={"start_is_instruction": False}),
    ):
        result = queries.disassemble_memory(ctx, "0x101")
    assert result["status"] == "validation_failed"
    assert "inside an existing code unit" in result["error"]
    ctx.program.startTransaction.assert_not_called()


def test_fix_region_rolls_back_when_inferred_function_creation_fails():
    state = {"instruction": False}

    class Disassemble:
        def __init__(self, *_args):
            pass

        def applyTo(self, _program, _monitor):
            state["instruction"] = True
            return True

        def getStatusMsg(self):
            return ""

    class Create:
        def __init__(self, *_args):
            pass

        def applyTo(self, _program, _monitor):
            return False

        def getStatusMsg(self):
            return "blocked"

    start = mock.MagicMock(__str__=mock.MagicMock(return_value="100"))
    end = mock.MagicMock(__str__=mock.MagicMock(return_value="104"))
    end.compareTo.return_value = 1
    instruction = mock.MagicMock()
    instruction.getAddress.return_value = start
    instructions = mock.MagicMock()
    instructions.hasNext.side_effect = [True, False]
    instructions.next.return_value = instruction
    references = mock.MagicMock()
    references.hasNext.return_value = True
    ctx = mock.MagicMock()
    ctx.to_addr.side_effect = [start, end]
    ctx.program.startTransaction.return_value = 8
    ctx.program.getListing.return_value.getInstructions.return_value = instructions
    ctx.program.getFunctionManager.return_value.getFunctionAt.return_value = None
    ctx.program.getReferenceManager.return_value.getReferencesTo.return_value = references

    def finish(_tx_id, commit):
        if not commit:
            state["instruction"] = False

    ctx.program.endTransaction.side_effect = finish

    def range_state(*_args):
        return {"start_is_instruction": state["instruction"]}

    with (
        mock.patch.dict(sys.modules, _command_modules(Disassemble, Create)),
        mock.patch.object(_query_annotations, "_code_state", side_effect=range_state),
    ):
        result = queries.fix_region(ctx, "0x100", "0x104")

    assert result["status"] == "rolled_back"
    assert result["stored"] == {"start_is_instruction": False}
    assert "blocked" in result["error"]
    ctx.program.endTransaction.assert_called_once_with(8, False)


def test_annotate_func_applies_compound_change_in_one_transaction(tmp_path):
    path = tmp_path / "annotation.json"
    path.write_text(json.dumps({
        "return_type": "int",
        "calling_convention": "__cdecl",
        "vars": [{"old_name": "arg", "new_name": "count", "type": "int"}],
    }), encoding="utf-8")

    old_type = mock.MagicMock(__str__=mock.MagicMock(return_value="void"))
    new_type = mock.MagicMock(__str__=mock.MagicMock(return_value="int"))
    old_type.isEquivalent.return_value = False
    new_type.isEquivalent.side_effect = lambda value: value is new_type
    variable_state = {"name": "arg", "type": old_type}
    variable = mock.MagicMock()
    variable.getName.side_effect = lambda: variable_state["name"]
    variable.setName.side_effect = (
        lambda value, _source: variable_state.__setitem__("name", value)
    )
    variable.getDataType.side_effect = lambda: variable_state["type"]
    variable.setDataType.side_effect = (
        lambda value, _source: variable_state.__setitem__("type", value)
    )
    variable.getVariableStorage.return_value = mock.MagicMock(
        __str__=mock.MagicMock(return_value="Register(r0,4)")
    )

    function_state = {"calling_convention": "default", "return_type": old_type}
    function = mock.MagicMock()
    function.getName.return_value = "target"
    function.getParameters.return_value = [variable]
    function.getLocalVariables.return_value = []
    function.getCallingConventionName.side_effect = (
        lambda: function_state["calling_convention"]
    )
    function.setCallingConvention.side_effect = (
        lambda value: function_state.__setitem__("calling_convention", value)
    )
    function.getReturnType.side_effect = lambda: function_state["return_type"]
    function.setReturnType.side_effect = (
        lambda value, _source: function_state.__setitem__("return_type", value)
    )

    ctx = mock.MagicMock()
    ctx.resolve_function.return_value = function
    ctx.program.startTransaction.return_value = 9
    ctx.program.getFunctionManager.return_value.getCallingConvention.return_value = object()

    def contract_state(*_args):
        return {
            "calling_convention": function_state["calling_convention"],
            "return_type": str(function_state["return_type"]),
            "variable": variable_state["name"],
        }

    with (
        mock.patch.object(
            _query_annotations, "_resolve_type", return_value=new_type
        ),
        mock.patch.object(
            _query_annotations,
            "_function_contract_state",
            side_effect=contract_state,
        ),
        mock.patch.object(
            _query_annotations,
            "_return_type_parameter_preflight",
            return_value=([], ""),
        ),
    ):
        result = queries.apply_function_annotations(ctx, "0x100", str(path))

    assert result["status"] == "success"
    assert result["stored"]["variable"] == "count"
    assert result["requested"]["vars"][0]["kind"] == "parameter"
    ctx.program.endTransaction.assert_called_once_with(9, True)


def test_annotate_func_rejects_unsafe_return_type_before_other_changes(tmp_path):
    path = tmp_path / "annotation.json"
    path.write_text(json.dumps({
        "return_type": "int",
        "vars": [],
    }), encoding="utf-8")
    old_type = mock.MagicMock(__str__=mock.MagicMock(return_value="undefined"))
    new_type = mock.MagicMock(__str__=mock.MagicMock(return_value="int"))
    old_type.isEquivalent.return_value = False
    function = mock.MagicMock()
    function.getName.return_value = "target"
    function.getParameters.return_value = []
    function.getLocalVariables.return_value = []
    function.getReturnType.return_value = old_type
    ctx = mock.MagicMock()
    ctx.resolve_function.return_value = function

    with (
        mock.patch.object(
            _query_annotations, "_resolve_type", return_value=new_type
        ),
        mock.patch.object(
            _query_annotations, "_function_contract_state", return_value={}
        ),
        mock.patch.object(
            _query_annotations,
            "_return_type_parameter_preflight",
            return_value=(
                [{"name": "param_1", "database_backed": False}],
                "use set_function_prototype with the complete signature",
            ),
        ),
    ):
        result = queries.apply_function_annotations(ctx, "0x100", str(path))

    assert result["status"] == "validation_failed"
    assert result["transaction"] == {"started": False, "committed": False}
    assert "set_function_prototype" in result["error"]
    function.setReturnType.assert_not_called()
    ctx.program.startTransaction.assert_not_called()
