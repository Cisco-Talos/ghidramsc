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

"""Tests for new query functions added to ghidramsc.queries.

Covers: get_program_info, get_program_memory_map, list_program_imports, list_program_exports,
list_program_namespaces, list_program_classes, list_data_items, list_memory_blocks,
set_comment_at_address, get_comment_at_address, create_bookmark, delete_bookmark, list_bookmarks,
list_structures, get_structure, create_structure, set_structure_name,
delete_structure, get_function_call_graph, list_function_basic_blocks,
get_function_call_relationships, write_memory_bytes, set_function_prototype,
set_function_calling_convention, set_data_label, apply_data_type,
detect_security_mitigations, find_format_string_vulns,
set_program_image_base, set_memory_block_permissions.
"""

from __future__ import annotations

import sys
from types import ModuleType
from types import SimpleNamespace
from unittest import mock

import pytest

from ghidramsc.bridge import ProgramContext, ProjectHandle
from ghidramsc._query_data import _data_application_state
from ghidramsc._query_inspection import get_data_at_address
from ghidramsc._query_core import _read_memory_buffer
from ghidramsc.queries import (
    _func_var_state,
    _page_func_var_identities,
    _qualified_program_name,
    _high_var_capability_reason,
    _apply_function_signature,
    get_program_info,
    get_program_save_state,
    save_program,
    get_program_memory_map,
    list_program_imports,
    list_program_exports,
    list_program_namespaces,
    list_program_classes,
    list_data_items,
    list_memory_blocks,
    set_comment_at_address,
    get_comment_at_address,
    create_bookmark,
    delete_bookmark,
    list_bookmarks,
    list_structures,
    get_structure,
    create_structure,
    set_structure_name,
    delete_structure,
    get_function_call_graph,
    list_function_basic_blocks,
    get_function_call_relationships,
    write_memory_bytes,
    set_variable_name,
    set_variable_type,
    set_function_return_type,
    set_function_prototype,
    set_function_calling_convention,
    set_data_label,
    apply_data_type,
    create_stack_variable_from_structure,
    create_stack_variable,
    delete_stack_variable,
    get_function_stack_frame,
    detect_security_mitigations,
    find_format_string_vulns,
    set_program_image_base,
    set_memory_block_permissions,
    identify_user_input_sources,
    identify_crypto_patterns,
    find_obfuscated_strings,
)


def _identity(var_id, name, is_param=False, **fields):
    entry = {
        "var_id": var_id,
        "name": name,
        "is_param": is_param,
        "type": fields.pop("type", "int"),
        "storage": fields.pop("storage", "Stack[-0x4]:4"),
        "storage_kind": fields.pop("storage_kind", "stack"),
        "backing": fields.pop("backing", "decompiler_high"),
    }
    entry.update(fields)
    return entry


def test_func_var_identity_page_is_bounded_and_preserves_global_ambiguity():
    params = [
        _identity("high:1", "dup", True),
        _identity("high:2", "count", True),
    ]
    locals_list = [_identity("high:3", "dup")]

    result = _page_func_var_identities(params, locals_list, limit=2)

    assert result["pagination"] == {
        "offset": 0,
        "limit": 2,
        "returned": 2,
        "total": 3,
        "total_unfiltered": 3,
        "has_more": True,
        "next_offset": 2,
    }
    assert [item["var_id"] for item in result["params"]] == [
        "high:1", "high:2",
    ]
    assert result["locals"] == []
    assert result["params"][0]["same_name_var_ids"] == ["high:1", "high:3"]
    assert result["ambiguous_names"] == [{
        "name": "dup", "candidate_var_ids": ["high:1", "high:3"],
    }]


def test_func_var_identity_filter_precedes_pagination_and_reports_totals():
    params = [_identity("high:1", "first", True)]
    locals_list = [
        _identity("high:2", "second", capability_reason="Constant-backed"),
        _identity("high:3", "third", type="constant_ptr"),
    ]

    result = _page_func_var_identities(
        params, locals_list, offset=1, limit=1, filter_str=" CONSTANT ")

    assert result["filter"] == "CONSTANT"
    assert [item["var_id"] for item in result["locals"]] == ["high:3"]
    assert result["pagination"] == {
        "offset": 1,
        "limit": 1,
        "returned": 1,
        "total": 2,
        "total_unfiltered": 3,
        "has_more": False,
        "next_offset": None,
    }


def test_func_var_identity_default_page_is_bounded_to_100():
    locals_list = [
        _identity("high:{:x}".format(index), "local_{}".format(index))
        for index in range(101)
    ]

    result = _page_func_var_identities([], locals_list)

    assert result["pagination"]["returned"] == 100
    assert result["pagination"]["has_more"] is True
    assert result["pagination"]["next_offset"] == 100


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"offset": -1}, "offset must be a non-negative integer"),
        ({"limit": 0}, "limit must be an integer between 1 and 500"),
        ({"limit": 501}, "limit must be an integer between 1 and 500"),
    ],
)
def test_func_var_identity_page_rejects_invalid_bounds(kwargs, message):
    with pytest.raises(ValueError, match=message):
        _page_func_var_identities([], [], **kwargs)


def test_func_var_state_uses_java_optional_pc_address_contract():
    symbol = mock.MagicMock()
    symbol.getName.return_value = "local"
    symbol.getDataType.return_value = "uint"
    symbol.getSize.return_value = 4
    symbol.getStorage.return_value = "Stack[-0x4]:4"
    symbol.isParameter.return_value = False
    symbol.getPCAddress.return_value = None

    state = _func_var_state(symbol)

    assert state == {
        "name": "local",
        "type": "uint",
        "size": 4,
        "storage": "Stack[-0x4]:4",
        "is_param": False,
    }

    symbol.getPCAddress.return_value = "000205a4"
    assert _func_var_state(symbol)["pc_addr"] == "000205a4"


class TestProjectFolderIdentity:
    class _DomainFile:
        def __init__(self, name):
            self._name = name

        def getName(self):
            return self._name

    class _Folder:
        def __init__(self, name, files=(), folders=()):
            self._name = name
            self._files = [TestProjectFolderIdentity._DomainFile(f) for f in files]
            self._folders = list(folders)

        def getName(self):
            return self._name

        def getFiles(self):
            return self._files

        def getFolders(self):
            return self._folders

    def test_recursive_discovery_is_qualified_and_sorted(self):
        deep = self._Folder("deep", files=("same.bin",))
        arm = self._Folder("arm", files=("same.bin",), folders=(deep,))
        zed = self._Folder("zed", files=("other.bin",))
        root = self._Folder("", files=("same.bin",), folders=(zed, arm))
        project = mock.MagicMock()
        project.getRootFolder.return_value = root

        handle = ProjectHandle(project, mock.MagicMock())

        assert handle.list_programs() == [
            "arm/deep/same.bin",
            "arm/same.bin",
            "same.bin",
            "zed/other.bin",
        ]

    def test_qualified_lookup_round_trips_and_bare_name_stays_at_root(self):
        project = mock.MagicMock()
        project.openProgram.return_value = mock.MagicMock()
        handle = ProjectHandle(project, mock.MagicMock())

        nested = handle.get_program("arm/deep/same.bin")
        root = handle.get_program("same.bin")

        assert nested is handle.get_program("/arm\\deep\\same.bin")
        assert root is handle.get_program("same.bin")
        assert project.openProgram.call_args_list == [
            mock.call("/arm/deep", "same.bin", False),
            mock.call("/", "same.bin", False),
        ]

    @pytest.mark.parametrize(
        "name", ["", "/", "arm//same.bin", "./same.bin", "arm/../same.bin"]
    )
    def test_invalid_program_paths_are_rejected_before_open(self, name):
        project = mock.MagicMock()
        handle = ProjectHandle(project, mock.MagicMock())

        with pytest.raises(ValueError, match="Invalid project-relative"):
            handle.get_program(name)
        project.openProgram.assert_not_called()

    def test_response_identity_uses_domain_path_and_root_fallback(self):
        nested = mock.MagicMock()
        nested.getDomainFile.return_value.getPathname.return_value = (
            "/arm/deep/same.bin"
        )
        nested.getName.return_value = "same.bin"
        assert _qualified_program_name(nested) == "arm/deep/same.bin"

        root = mock.MagicMock()
        root.getDomainFile.return_value = None
        root.getName.return_value = "same.bin"
        assert _qualified_program_name(root) == "same.bin"


class TestHighVariableCapabilities:
    def test_constant_backed_high_variable_is_not_persistable(self):
        symbol = mock.MagicMock()
        symbol.isGlobal.return_value = False
        representative = mock.MagicMock()
        representative.isConstant.return_value = True
        symbol.getHighVariable.return_value.getRepresentative.return_value = (
            representative
        )

        assert _high_var_capability_reason(symbol) == (
            "Decompiler high variable is constant-backed and cannot be "
            "persisted as a function variable"
        )

    def test_nonconstant_high_variable_remains_persistable(self):
        symbol = mock.MagicMock()
        symbol.isGlobal.return_value = False
        symbol.getId.return_value = 19
        symbol.getName.return_value = "local"
        symbol.getStorage.return_value = "r1:4"
        symbol.getPCAddress.return_value = "00001000"
        symbol.isParameter.return_value = False
        symbol.getHighFunction.return_value.getLocalSymbolMap.return_value.getSymbols.return_value = [symbol]
        representative = mock.MagicMock()
        representative.isConstant.return_value = False
        symbol.getHighVariable.return_value.getRepresentative.return_value = (
            representative
        )

        assert _high_var_capability_reason(symbol) is None

    def test_duplicate_snapshot_id_is_not_persistable(self):
        selected = mock.MagicMock()
        selected.isGlobal.return_value = False
        selected.getId.return_value = 19
        selected.getName.return_value = "local"
        selected.getStorage.return_value = "r1:4"
        selected.getPCAddress.return_value = "00001000"
        selected.isParameter.return_value = False
        selected.getHighVariable.return_value.getRepresentative.return_value.isConstant.return_value = False
        duplicate = mock.MagicMock()
        duplicate.getId.return_value = 19
        duplicate.isParameter.return_value = False
        selected.getHighFunction.return_value.getLocalSymbolMap.return_value.getSymbols.return_value = [selected, duplicate]

        assert _high_var_capability_reason(selected) == (
            "Decompiler high-symbol ID is not unique in this function"
        )

    def test_ambiguous_locator_is_not_persistable(self):
        selected = mock.MagicMock()
        selected.isGlobal.return_value = False
        selected.getId.return_value = 19
        selected.getName.return_value = "cursor_a"
        selected.getStorage.return_value = "r1:4"
        selected.getPCAddress.return_value = "00001000"
        selected.isParameter.return_value = False
        selected.getHighVariable.return_value.getRepresentative.return_value.isConstant.return_value = False
        other = mock.MagicMock()
        other.getId.return_value = 20
        other.getName.return_value = "cursor_b"
        other.getStorage.return_value = "r1:4"
        other.getPCAddress.return_value = "00001000"
        other.isParameter.return_value = False
        selected.getHighFunction.return_value.getLocalSymbolMap.return_value.getSymbols.return_value = [selected, other]

        assert _high_var_capability_reason(selected) == (
            "Decompiler high-variable locator is ambiguous in this function"
        )

    def test_database_backed_constant_remains_editable(self):
        symbol = mock.MagicMock()
        symbol.isGlobal.return_value = False
        representative = mock.MagicMock()
        representative.isConstant.return_value = True
        symbol.getHighVariable.return_value.getRepresentative.return_value = (
            representative
        )

        assert _high_var_capability_reason(symbol, database_backed=True) is None


class TestProgramPersistence:
    def _ctx(self, dirty=True, can_save=True, project_save=None):
        program = mock.MagicMock()
        program.getName.return_value = "test_binary"
        program.isChanged.return_value = dirty
        program.canSave.return_value = can_save
        program.getDomainFile.return_value.getPathname.return_value = "/test_binary"
        ctx = ProgramContext(mock.MagicMock(), program, project_save=project_save)
        return ctx

    def test_dirty_state_reports_identity(self):
        result = get_program_save_state(self._ctx())
        assert result == {
            "program": "test_binary",
            "dirty": True,
            "can_save": True,
            "path": "/test_binary",
        }

    def test_save_success_requires_clean_readback(self):
        ctx = self._ctx()
        ctx.program.isChanged.side_effect = [True, False]
        result = save_program(ctx, "checkpoint")
        assert result["status"] == "success"
        assert result["program"] == "test_binary"
        assert result["old"]["dirty"] is True
        assert result["stored"]["dirty"] is False
        assert result["save"]["backend"] == "headless_domain_object"
        assert result["save"]["completion_observed"] is True
        assert result["save"]["comment_supported"] is True
        assert result["save"]["comment_applied"] is True
        assert result["save"]["attempted"] is True
        assert result["save"]["completed"] is True
        assert result["save"]["succeeded"] is True
        ctx.program.save.assert_called_once()

    def test_project_save_reports_unsupported_comment_truthfully(self):
        project_save = mock.MagicMock()
        ctx = self._ctx(project_save=project_save)
        ctx.program.isChanged.side_effect = [True, False]

        result = save_program(ctx, "checkpoint")

        assert result["status"] == "success"
        assert result["requested"]["comment"] == "checkpoint"
        assert result["save"]["backend"] == "headless_ghidra_project"
        assert result["save"]["comment_supported"] is False
        assert result["save"]["comment_applied"] is False
        project_save.assert_called_once_with(ctx.program)
        ctx.program.save.assert_not_called()

    def test_save_failure_is_not_success(self):
        ctx = self._ctx()
        ctx.program.save.side_effect = OSError("disk full")
        result = save_program(ctx)
        assert result["status"] == "failed"
        assert result["save"]["attempted"] is True
        assert result["save"]["completed"] is False
        assert result["save"]["succeeded"] is False
        assert result["save"]["comment_applied"] is False
        assert "disk full" in result["error"]

    def test_clean_program_is_no_change(self):
        ctx = self._ctx(dirty=False)
        result = save_program(ctx)
        assert result["status"] == "no_change"
        assert result["save"]["completed"] is True
        ctx.program.save.assert_not_called()

    def test_unsaveable_program_is_validation_failure(self):
        ctx = self._ctx(can_save=False)
        result = save_program(ctx)
        assert result["status"] == "validation_failed"
        assert result["save"]["completed"] is False
        ctx.program.save.assert_not_called()

    def test_project_close_does_not_implicitly_save(self):
        project = mock.MagicMock()
        handle = ProjectHandle(project, mock.MagicMock())
        handle._programs["test_binary"] = self._ctx()
        handle.close()
        project.save.assert_not_called()
        project.close.assert_called_once_with()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _addr_obj(val):
    a = mock.MagicMock()
    a.__str__ = mock.MagicMock(return_value=hex(val))
    a.getOffset.return_value = val
    a.subtract.side_effect = lambda other: val - other.getOffset()
    a.__lt__ = mock.MagicMock(side_effect=lambda o: val < o.getOffset())
    a.__le__ = mock.MagicMock(side_effect=lambda o: val <= o.getOffset())
    a.__gt__ = mock.MagicMock(side_effect=lambda o: val > o.getOffset())
    a.__ge__ = mock.MagicMock(side_effect=lambda o: val >= o.getOffset())
    a.__eq__ = mock.MagicMock(side_effect=lambda o: val == getattr(o, 'getOffset', lambda: None)())
    return a


def _mock_block(name, start, end, size=None, r=True, w=False, x=False,
                volatile=False, initialized=True, source="test"):
    blk = mock.MagicMock()
    blk.getName.return_value = name
    blk.getStart.return_value = _addr_obj(start)
    blk.getEnd.return_value = _addr_obj(end)
    blk.getSize.return_value = size if size else (end - start + 1)
    blk.isRead.return_value = r
    blk.isWrite.return_value = w
    blk.isExecute.return_value = x
    blk.isVolatile.return_value = volatile
    blk.isInitialized.return_value = initialized
    blk.getSourceName.return_value = source
    blk.getType.return_value = "DEFAULT"
    return blk


def _mock_function(name, addr_int, is_thunk=False, body_min=None, body_max=None):
    f = mock.MagicMock()
    f.getName.return_value = name
    entry = _addr_obj(addr_int)
    f.getEntryPoint.return_value = entry
    f.isThunk.return_value = is_thunk
    f.getSignature.return_value = mock.MagicMock(
        __str__=mock.MagicMock(return_value="void {}(void)".format(name))
    )
    f.getCallingConventionName.return_value = "default"
    f.getReturnType.return_value = mock.MagicMock(
        __str__=mock.MagicMock(return_value="void")
    )
    body = mock.MagicMock()
    body.getMinAddress.return_value = _addr_obj(body_min or addr_int)
    body.getMaxAddress.return_value = _addr_obj(body_max or addr_int + 0x20)
    body.getNumAddresses.return_value = (body_max or addr_int + 0x20) - (body_min or addr_int)
    f.getBody.return_value = body
    f.getParameters.return_value = []
    f.getCalledFunctions.return_value = []
    f.getCallingFunctions.return_value = []
    f.getStackFrame.return_value = mock.MagicMock(
        getLocalSize=mock.MagicMock(return_value=16),
        getParameterSize=mock.MagicMock(return_value=8),
    )
    return f


def _make_ctx(functions=None, blocks=None):
    """Build a mock ProgramContext with optional functions and memory blocks."""
    ctx = mock.MagicMock()
    ctx.program.getListing.return_value.getInstructions.return_value.hasNext.return_value = False
    ctx.program.getName.return_value = "test_binary"
    functions = functions or []
    blocks = blocks or []

    func_mgr = mock.MagicMock()
    func_mgr.getFunctions.return_value = functions
    func_mgr.getFunctionCount.return_value = len(functions)
    ctx.program.getFunctionManager.return_value = func_mgr

    mem = mock.MagicMock()
    mem.getBlocks.return_value = blocks
    mem.getMinAddress.return_value = _addr_obj(0x1000) if blocks else _addr_obj(0)
    mem.getMaxAddress.return_value = _addr_obj(0xFFFF) if blocks else _addr_obj(0)
    ctx.program.getMemory.return_value = mem

    # ImageBase
    ctx.program.getImageBase.return_value = _addr_obj(0x10000)

    # Language
    lang = mock.MagicMock()
    lang.getLanguageID.return_value = "ARM:LE:32:v7"
    lang.getProcessor.return_value = "ARM"
    lang.isBigEndian.return_value = False
    space = mock.MagicMock()
    space.getPointerSize.return_value = 4
    space.getSize.return_value = 32
    lang.getDefaultSpace.return_value = space
    ctx.program.getLanguage.return_value = lang

    # CompilerSpec
    comp = mock.MagicMock()
    comp.getCompilerSpecID.return_value = "default"
    ctx.program.getCompilerSpec.return_value = comp

    ctx.program.getExecutableFormat.return_value = "ELF"
    ctx.program.getExecutablePath.return_value = "/path/to/binary"

    def to_addr(val):
        return _addr_obj(val)
    ctx.to_addr.side_effect = to_addr

    def get_function_at(addr):
        target = addr.getOffset()
        for f in functions:
            if f.getEntryPoint().getOffset() == target:
                return f
        return None

    def get_function_containing(addr):
        target = addr.getOffset()
        for f in functions:
            body = f.getBody()
            lo = body.getMinAddress().getOffset()
            hi = body.getMaxAddress().getOffset()
            if lo <= target <= hi:
                return f
        return None

    ctx.get_function_at.side_effect = get_function_at
    ctx.get_function_containing.side_effect = get_function_containing

    def resolve_function(addr_int):
        addr = to_addr(addr_int)
        result = get_function_at(addr)
        if result is None:
            result = get_function_containing(addr)
        return result
    ctx.resolve_function.side_effect = resolve_function

    return ctx


def _mock_stack_variable(offset, name, data_type, size=None,
                         source="USER_DEFINED", comment="",
                         first_use=0):
    variable = mock.MagicMock()
    variable.getStackOffset.return_value = offset
    variable.getName.return_value = name
    variable.getDataType.return_value = data_type
    variable.getLength.return_value = (
        data_type.getLength() if size is None else size)
    variable.getVariableStorage.return_value = "Stack[{}]".format(offset)
    variable.getSource.return_value = source
    variable.getComment.return_value = comment
    variable.getFirstUseOffset.return_value = first_use
    return variable


def _mock_stack_type(name="uint", length=4, path=None):
    data_type = mock.MagicMock()
    data_type.getName.return_value = name
    data_type.getDisplayName.return_value = name
    data_type.getPathName.return_value = path or "/" + name
    data_type.getCategoryPath.return_value = (
        (path or "/" + name).rsplit("/", 1)[0] or "/")
    data_type.getLength.return_value = length
    data_type.isEquivalent.side_effect = lambda other: other is data_type
    return data_type


def _prepare_stack_function(variables=None):
    function = _mock_function("stack_target", 0x200)
    function.hasCustomVariableStorage.return_value = False
    frame = mock.MagicMock()
    current = list(variables or [])
    frame.getFrameSize.return_value = 48
    frame.getLocalSize.return_value = 32
    frame.getParameterSize.return_value = 12
    frame.getParameterOffset.return_value = 4
    frame.getReturnAddressOffset.return_value = 0
    frame.growsNegative.return_value = True
    frame.isParameterOffset.side_effect = lambda offset: offset >= 4
    frame.getStackVariables.side_effect = lambda: list(current)
    frame.getVariableContaining.side_effect = lambda offset: next(
        (variable for variable in current
         if variable.getStackOffset() <= offset
         <= variable.getStackOffset() + variable.getLength() - 1), None)

    def create_variable(name, offset, data_type, source):
        variable = _mock_stack_variable(
            offset, name or "local_{}".format(abs(offset)), data_type,
            source=str(source))
        current.append(variable)
        return variable

    def remove_variable(variable):
        current.remove(variable)

    frame.createVariable.side_effect = create_variable
    function.removeVariable.side_effect = remove_variable
    function.getStackFrame.return_value = frame
    function.getAllVariables.side_effect = lambda: list(current)
    return function, frame, current


def _ghidra_symbol_modules():
    symbol_module = ModuleType("ghidra.program.model.symbol")
    symbol_module.SourceType = SimpleNamespace(
        USER_DEFINED="USER_DEFINED", DEFAULT="DEFAULT")
    return {
        "ghidra": ModuleType("ghidra"),
        "ghidra.program": ModuleType("ghidra.program"),
        "ghidra.program.model": ModuleType("ghidra.program.model"),
        "ghidra.program.model.symbol": symbol_module,
    }


class TestStackFrameEditing:
    def test_get_stack_frame_returns_complete_sorted_layout(self):
        uint_type = _mock_stack_type()
        later = _mock_stack_variable(-4, "later", uint_type)
        earlier = _mock_stack_variable(-16, "earlier", uint_type)
        function, _frame, _current = _prepare_stack_function([later, earlier])
        ctx = _make_ctx([function])

        result = get_function_stack_frame(ctx, "0x200")

        assert result["func"] == "stack_target"
        assert result["frame_size"] == 48
        assert result["parameter_size"] == 12
        assert result["grows_negative"] is True
        assert [item["offset"] for item in result["variables"]] == [-16, -4]
        assert result["variables"][0]["end_offset"] == -13
        assert result["variables"][0]["type_path"] == "/uint"
        assert result["variables"][0]["is_parameter"] is False

    @mock.patch("ghidramsc._query_variables._resolve_type")
    def test_create_stack_var_commits_after_exact_readback(self, resolve_type):
        uint_type = _mock_stack_type()
        resolve_type.return_value = uint_type
        function, frame, _current = _prepare_stack_function()
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 17

        with mock.patch.dict(sys.modules, _ghidra_symbol_modules()):
            result = create_stack_variable(
                ctx, "0x200", -16, "saved_count", "uint", 4)

        assert result["status"] == "success"
        assert result["transaction"] == {"started": True, "committed": True}
        assert result["conflicting_variables"] == []
        assert result["stored"]["variables"][0]["offset"] == -16
        assert result["stored"]["variables"][0]["name"] == "saved_count"
        frame.createVariable.assert_called_once_with(
            "saved_count", -16, uint_type, "USER_DEFINED")
        ctx.program.endTransaction.assert_called_once_with(17, True)

    @mock.patch("ghidramsc._query_variables._resolve_type")
    def test_create_stack_var_overlap_fails_before_transaction(self, resolve_type):
        uint_type = _mock_stack_type()
        resolve_type.return_value = uint_type
        existing = _mock_stack_variable(-16, "existing", uint_type)
        function, frame, _current = _prepare_stack_function([existing])
        ctx = _make_ctx([function])

        with mock.patch.dict(sys.modules, _ghidra_symbol_modules()):
            result = create_stack_variable(
                ctx, "0x200", -14, "overlap", "uint")

        assert result["status"] == "validation_failed"
        assert result["conflicting_variables"][0]["name"] == "existing"
        ctx.program.startTransaction.assert_not_called()
        frame.createVariable.assert_not_called()

    @pytest.mark.parametrize(
        ("offset", "size", "message"),
        [(-16, 8, "does not match"), (4, 0, "Parameter stack offsets")],
    )
    @mock.patch("ghidramsc._query_variables._resolve_type")
    def test_create_stack_var_rejects_invalid_request_before_transaction(
            self, resolve_type, offset, size, message):
        resolve_type.return_value = _mock_stack_type()
        function, frame, _current = _prepare_stack_function()
        ctx = _make_ctx([function])

        with mock.patch.dict(sys.modules, _ghidra_symbol_modules()):
            result = create_stack_variable(
                ctx, "0x200", offset, "bad_local", "uint", size)

        assert result["status"] == "validation_failed"
        assert message in result["error"]
        ctx.program.startTransaction.assert_not_called()
        frame.createVariable.assert_not_called()

    def test_delete_stack_var_requires_exact_start_offset(self):
        uint_type = _mock_stack_type()
        existing = _mock_stack_variable(-16, "existing", uint_type)
        function, frame, _current = _prepare_stack_function([existing])
        ctx = _make_ctx([function])

        result = delete_stack_variable(ctx, "0x200", -15)

        assert result["status"] == "validation_failed"
        assert "exact start offset -16" in result["error"]
        assert result["conflicting_variables"][0]["offset"] == -16
        ctx.program.startTransaction.assert_not_called()
        function.removeVariable.assert_not_called()

    def test_delete_stack_var_commits_and_returns_remaining_layout(self):
        uint_type = _mock_stack_type()
        target = _mock_stack_variable(-16, "target", uint_type)
        remaining = _mock_stack_variable(-8, "remaining", uint_type)
        function, frame, _current = _prepare_stack_function([target, remaining])
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 23

        result = delete_stack_variable(ctx, "0x200", -16)

        assert result["status"] == "success"
        assert result["requested"]["target"]["name"] == "target"
        assert [item["name"] for item in result["stored"]["variables"]] == [
            "remaining"]
        function.removeVariable.assert_called_once_with(target)
        ctx.program.endTransaction.assert_called_once_with(23, True)

    @mock.patch("ghidramsc._query_variables._find_structure")
    def test_apply_stack_structure_commits_exact_composite(self, find_structure):
        structure = _mock_stack_type(
            "Header", 12, "/protocol/Header")
        find_structure.return_value = structure
        function, frame, _current = _prepare_stack_function()
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 29

        with mock.patch.dict(sys.modules, _ghidra_symbol_modules()):
            result = create_stack_variable_from_structure(
                ctx, "0x200", -24, "Header", "/protocol", "header")

        assert result["status"] == "success"
        assert result["requested"]["resolved_category_path"] == "/protocol"
        assert result["stored"]["variables"][0]["type"] == "Header"
        frame.createVariable.assert_called_once_with(
            "header", -24, structure, "USER_DEFINED")
        ctx.program.endTransaction.assert_called_once_with(29, True)

    @mock.patch("ghidramsc._query_variables._resolve_type")
    def test_create_stack_var_rolls_back_on_readback_failure(self, resolve_type):
        uint_type = _mock_stack_type()
        resolve_type.return_value = uint_type
        function, frame, _current = _prepare_stack_function()
        frame.createVariable.side_effect = RuntimeError("storage rejected")
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 31

        with mock.patch.dict(sys.modules, _ghidra_symbol_modules()):
            result = create_stack_variable(
                ctx, "0x200", -16, "saved_count", "uint")

        assert result["status"] == "rolled_back"
        assert "storage rejected" in result["error"]
        ctx.program.endTransaction.assert_called_once_with(31, False)


# ---------------------------------------------------------------------------
# Program metadata
# ---------------------------------------------------------------------------

class TestGetProgramInfo:
    def test_basic(self):
        ctx = _make_ctx()
        result = get_program_info(ctx)
        assert result["binary"] == "test_binary"
        assert result["pointer_size"] == 4
        assert result["endianness"] == "little"
        assert result["image_base"] == hex(0x10000)
        assert result["num_functions"] == 0

    def test_with_functions(self):
        f = _mock_function("main", 0x100)
        ctx = _make_ctx([f])
        result = get_program_info(ctx)
        assert result["num_functions"] == 1

    def test_memory_block_count_uses_blocks_not_address_ranges(self):
        ctx = _make_ctx(blocks=[
            _mock_block("first", 0x1000, 0x1fff),
            _mock_block("second", 0x2000, 0x2fff),
        ])
        ctx.program.getMemory.return_value.getNumAddressRanges.return_value = 1

        assert get_program_info(ctx)["num_memory_blocks"] == 2


class TestGetMemoryMap:
    def test_empty(self):
        ctx = _make_ctx(blocks=[])
        result = get_program_memory_map(ctx)
        assert result["total_blocks"] == 0
        assert result["blocks"] == []

    def test_with_blocks(self):
        blk1 = _mock_block(".text", 0x1000, 0x2000, r=True, x=True)
        blk2 = _mock_block(".data", 0x3000, 0x4000, r=True, w=True)
        ctx = _make_ctx(blocks=[blk1, blk2])
        result = get_program_memory_map(ctx)
        assert result["total_blocks"] == 2
        assert result["blocks"][0]["name"] == ".text"
        assert result["blocks"][0]["execute"] is True
        assert result["blocks"][1]["name"] == ".data"
        assert result["blocks"][1]["write"] is True

    def test_missing_source_remains_null(self):
        ctx = _make_ctx(blocks=[
            _mock_block("tdb", 0x1000, 0x1fff, source=None),
        ])

        assert get_program_memory_map(ctx)["blocks"][0]["source"] is None


class TestGetSegments:
    def test_permissions_string(self):
        blk = _mock_block(".text", 0x1000, 0x2000, r=True, x=True)
        ctx = _make_ctx(blocks=[blk])
        result = list_memory_blocks(ctx)
        assert result["segments"][0]["permissions"] == "RX"


# ---------------------------------------------------------------------------
# Imports / Exports / Namespaces / Classes
# ---------------------------------------------------------------------------

class TestListImports:
    def test_empty_imports(self):
        ctx = _make_ctx()
        st = mock.MagicMock()
        st.getExternalSymbols.return_value = []
        ctx.program.getSymbolTable.return_value = st
        result = list_program_imports(ctx)
        assert "0 total" in result

    def test_with_imports(self):
        ctx = _make_ctx()
        sym1 = mock.MagicMock()
        sym1.getAddress.return_value = _addr_obj(0xEEEE)
        sym1.getName.return_value = "printf"
        sym1.getParentNamespace.return_value = mock.MagicMock(
            __str__=mock.MagicMock(return_value="libc"))
        st = mock.MagicMock()
        st.getExternalSymbols.return_value = [sym1]
        ctx.program.getSymbolTable.return_value = st
        result = list_program_imports(ctx)
        assert "1 total" in result
        assert "printf" in result
        assert "libc" in result


class TestListExports:
    def test_empty(self):
        ctx = _make_ctx()
        sym = mock.MagicMock()
        sym.isExternalEntryPoint.return_value = False
        sym.getName.return_value = "internal"
        st = mock.MagicMock()
        st.getAllSymbols.return_value = [sym]
        ctx.program.getSymbolTable.return_value = st
        result = list_program_exports(ctx)
        assert "0 total" in result


class TestListNamespaces:
    def test_collects_unique(self):
        ctx = _make_ctx()
        sym1 = mock.MagicMock()
        sym1.getParentNamespace.return_value = mock.MagicMock(
            __str__=mock.MagicMock(return_value="Global"))
        sym2 = mock.MagicMock()
        sym2.getParentNamespace.return_value = mock.MagicMock(
            __str__=mock.MagicMock(return_value="MyClass"))
        st = mock.MagicMock()
        st.getAllSymbols.return_value = [sym1, sym2]
        ctx.program.getSymbolTable.return_value = st
        result = list_program_namespaces(ctx)
        assert "2 total" in result
        assert "MyClass" in result


class TestListClasses:
    def test_empty(self):
        ctx = _make_ctx()
        st = mock.MagicMock()
        st.getClassNamespaces.return_value = []
        ctx.program.getSymbolTable.return_value = st
        result = list_program_classes(ctx)
        assert "0 total" in result


class TestListDataItems:
    def test_empty(self):
        ctx = _make_ctx()
        listing_mock = mock.MagicMock()
        data_iter = mock.MagicMock()
        data_iter.hasNext.return_value = False
        listing_mock.getDefinedData.return_value = data_iter
        ctx.program.getListing.return_value = listing_mock
        result = list_data_items(ctx)
        assert "showing 0" in result


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

class TestSetComment:
    def test_interior_requires_explicit_containing_item_opt_in(self):
        ctx = _make_ctx()
        comment = {"value": "existing"}
        cu = mock.MagicMock()
        cu.getAddress.return_value = _addr_obj(0x1000)
        cu.getMaxAddress.return_value = _addr_obj(0x100f)
        cu.getComment.side_effect = lambda _kind: comment["value"]
        cu.setComment.side_effect = (
            lambda _kind, value: comment.__setitem__("value", value)
        )
        listing = ctx.program.getListing.return_value
        listing.getCodeUnitAt.return_value = None
        listing.getCodeUnitContaining.return_value = cu

        rejected = set_comment_at_address(ctx, "0x1002", "new", "pre")
        assert rejected["status"] == "validation_failed"
        assert rejected["transaction"] == {"started": False, "committed": False}
        assert rejected["requested_address"] == "0x1002"
        assert rejected["effective_address"] == "0x1000"
        assert rejected["byte_offset"] == 2
        assert comment["value"] == "existing"
        cu.setComment.assert_not_called()
        ctx.program.startTransaction.assert_not_called()

        read = get_comment_at_address(ctx, "0x1002", "pre")
        assert read["comment"] == "existing"
        assert read["effective_address"] == "0x1000"
        assert read["distinct_interior_comment_storage"] is False

        ctx.program.startTransaction.return_value = 17
        changed = set_comment_at_address(
            ctx, "0x1002", "new", "pre", allow_containing_item=True
        )
        assert changed["status"] == "success"
        assert changed["old"] == "existing"
        assert changed["stored"] == "new"
        assert changed["byte_offset"] == 2
        cu.setComment.assert_called_once_with(1, "new")

    def test_success(self):
        ctx = _make_ctx()
        state = {"comment": "old"}
        cu = mock.MagicMock()
        cu.getComment.side_effect = lambda _kind: state["comment"]
        cu.setComment.side_effect = (
            lambda _kind, value: state.__setitem__("comment", value)
        )
        listing_mock = mock.MagicMock()
        listing_mock.getCodeUnitAt.return_value = cu
        ctx.program.getListing.return_value = listing_mock
        ctx.program.startTransaction.return_value = 17
        result = set_comment_at_address(ctx, "0x1000", "this is a test", "eol")
        assert result["status"] == "success"
        assert result["old"] == "old"
        assert result["stored"] == "this is a test"
        assert result["transaction"]["committed"] is True
        cu.setComment.assert_called_once_with(0, "this is a test")
        ctx.program.endTransaction.assert_called_once_with(17, True)

    def test_bad_type(self):
        ctx = _make_ctx()
        result = set_comment_at_address(ctx, "0x1000", "test", "invalid")
        assert result["status"] == "validation_failed"
        assert result["transaction"] == {
            "started": False, "committed": False,
        }

    def test_no_code_unit(self):
        ctx = _make_ctx()
        listing_mock = mock.MagicMock()
        listing_mock.getCodeUnitAt.return_value = None
        listing_mock.getCodeUnitContaining.return_value = None
        ctx.program.getListing.return_value = listing_mock
        result = set_comment_at_address(ctx, "0x1000", "test", "eol")
        assert result["status"] == "validation_failed"

    def test_no_change_does_not_start_transaction(self):
        ctx = _make_ctx()
        cu = mock.MagicMock()
        cu.getComment.return_value = "same"
        ctx.program.getListing.return_value.getCodeUnitAt.return_value = cu

        result = set_comment_at_address(ctx, "0x1000", "same", "eol")

        assert result["status"] == "no_change"
        assert result["old"] == result["stored"] == "same"
        ctx.program.startTransaction.assert_not_called()


class TestGetComment:
    def test_found(self):
        ctx = _make_ctx()
        cu = mock.MagicMock()
        cu.getComment.return_value = "hello"
        listing_mock = mock.MagicMock()
        listing_mock.getCodeUnitAt.return_value = cu
        ctx.program.getListing.return_value = listing_mock
        result = get_comment_at_address(ctx, "0x1000", "eol")
        assert result == "hello"

    def test_none(self):
        ctx = _make_ctx()
        cu = mock.MagicMock()
        cu.getComment.return_value = None
        listing_mock = mock.MagicMock()
        listing_mock.getCodeUnitAt.return_value = cu
        ctx.program.getListing.return_value = listing_mock
        result = get_comment_at_address(ctx, "0x1000", "eol")
        assert result == ""


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

class TestSetBookmark:
    def test_success(self):
        ctx = _make_ctx()
        bm = mock.MagicMock()
        bookmarks = []
        bm.getBookmarks.side_effect = lambda _addr: list(bookmarks)

        def add_bookmark(_addr, _kind, category, comment):
            bookmark = mock.MagicMock()
            bookmark.getCategory.return_value = category
            bookmark.getTypeString.return_value = "Note"
            bookmark.getComment.return_value = comment
            bookmarks.append(bookmark)

        bm.setBookmark.side_effect = add_bookmark
        ctx.program.getBookmarkManager.return_value = bm
        ctx.program.startTransaction.return_value = 21
        result = create_bookmark(ctx, "0x1000", "vuln", "possible overflow")
        assert result["status"] == "success"
        assert result["old"]["present"] is False
        assert result["stored"]["present"] is True
        assert result["stored"]["comment"] == "possible overflow"
        assert result["transaction"]["committed"] is True
        bm.setBookmark.assert_called_once()
        ctx.program.endTransaction.assert_called_once_with(21, True)


class TestRemoveBookmark:
    def test_not_found(self):
        ctx = _make_ctx()
        bm = mock.MagicMock()
        bm.getBookmarks.return_value = []
        ctx.program.getBookmarkManager.return_value = bm
        result = delete_bookmark(ctx, "0x1000", "vuln")
        assert result["status"] == "validation_failed"
        ctx.program.startTransaction.assert_not_called()

    def test_success(self):
        ctx = _make_ctx()
        bm = mock.MagicMock()
        bookmark_obj = mock.MagicMock()
        bookmark_obj.getCategory.return_value = "vuln"
        bookmark_obj.getTypeString.return_value = "Note"
        bookmark_obj.getComment.return_value = "possible overflow"
        bookmarks = [bookmark_obj]
        bm.getBookmarks.side_effect = lambda _addr: list(bookmarks)
        bm.removeBookmark.side_effect = lambda bookmark: bookmarks.remove(bookmark)
        ctx.program.getBookmarkManager.return_value = bm
        ctx.program.startTransaction.return_value = 22
        result = delete_bookmark(ctx, "0x1000", "vuln")
        assert result["status"] == "success"
        assert result["old"]["present"] is True
        assert result["stored"]["present"] is False
        assert result["transaction"]["committed"] is True
        bm.removeBookmark.assert_called_once_with(bookmark_obj)
        ctx.program.endTransaction.assert_called_once_with(22, True)


class TestGetBookmarks:
    def test_all_bookmarks_uses_type_iterators(self):
        ctx = _make_ctx()
        bm = mock.MagicMock()
        bookmark = mock.MagicMock()
        bookmark.getAddress.return_value = _addr_obj(0x1000)
        bookmark.getCategory.return_value = "analysis"
        bookmark.getTypeString.return_value = "Note"
        bookmark.getComment.return_value = "test"

        def iterator_for(bookmark_type):
            iterator = mock.MagicMock()
            entries = [bookmark] if bookmark_type == "Note" else []
            iterator.hasNext.side_effect = [True, False] if entries else [False]
            iterator.next.side_effect = entries
            return iterator

        bm.getBookmarksIterator.side_effect = iterator_for
        ctx.program.getBookmarkManager.return_value = bm

        result = list_bookmarks(ctx)

        assert "1 total" in result
        assert "analysis" in result
        assert bm.getBookmarksIterator.call_args_list == [
            mock.call(bookmark_type) for bookmark_type in
            ["Note", "Warning", "Error", "Info", "Analysis"]
        ]
        bm.getBookmarks.assert_not_called()

    def test_all_bookmark_retrieval_error_is_not_suppressed(self):
        ctx = _make_ctx()
        ctx.program.getBookmarkManager.return_value.getBookmarksIterator.side_effect = RuntimeError("failed")

        with pytest.raises(RuntimeError, match="failed"):
            list_bookmarks(ctx)

    def test_at_address(self):
        ctx = _make_ctx()
        bm = mock.MagicMock()
        b = mock.MagicMock()
        b.getAddress.return_value = _addr_obj(0x1000)
        b.getCategory.return_value = "vuln"
        b.getTypeString.return_value = "Note"
        b.getComment.return_value = "test"
        bm.getBookmarks.return_value = [b]
        ctx.program.getBookmarkManager.return_value = bm
        result = list_bookmarks(ctx, "0x1000")
        assert "1 total" in result
        assert "vuln" in result


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------

class TestListStructures:
    def test_empty(self):
        ctx = _make_ctx()
        dtm = mock.MagicMock()
        dtm.getAllDataTypes.return_value = []
        ctx.program.getDataTypeManager.return_value = dtm
        result = list_structures(ctx)
        assert "0 total" in result


class TestGetStructure:
    def test_not_found(self):
        ctx = _make_ctx()
        dtm = mock.MagicMock()
        dtm.getAllDataTypes.return_value = []
        ctx.program.getDataTypeManager.return_value = dtm
        result = get_structure(ctx, "my_struct")
        assert "error" in result

    def test_found(self):
        ctx = _make_ctx()
        dt = mock.MagicMock()
        dt.getName.return_value = "my_struct"
        dt.getNumComponents.return_value = 2
        dt.getLength.return_value = 8
        dt.getCategoryPath.return_value = "/"

        comp0 = mock.MagicMock()
        comp0.getOffset.return_value = 0
        comp0.getFieldName.return_value = "x"
        comp0.getDataType.return_value.getName.return_value = "int"
        comp0.getLength.return_value = 4
        comp0.getComment.return_value = ""

        comp1 = mock.MagicMock()
        comp1.getOffset.return_value = 4
        comp1.getFieldName.return_value = "y"
        comp1.getDataType.return_value.getName.return_value = "int"
        comp1.getLength.return_value = 4
        comp1.getComment.return_value = ""

        dt.getComponent.side_effect = [comp0, comp1]

        dtm = mock.MagicMock()
        dtm.getAllDataTypes.return_value = [dt]
        ctx.program.getDataTypeManager.return_value = dtm

        result = get_structure(ctx, "my_struct")
        assert result["name"] == "my_struct"
        assert result["num_fields"] == 2
        assert result["fields"][0]["name"] == "x"
        assert result["fields"][1]["offset"] == 4


class TestCreateStructure:
    class _Path:
        def __init__(self, value):
            self.value = value

        def __str__(self):
            return self.value

    class _Structure:
        def __init__(self, path, name, size):
            self.path = path
            self.name = name
            self.size = size

        def getName(self):
            return self.name

        def getCategoryPath(self):
            return self.path

        def getLength(self):
            return self.size

        def getComponentContaining(self, offset):
            return None

    def _setup(self, monkeypatch, category_path="/analysis/types",
               read_path=None, stored_size=8):
        import ghidramsc._query_composites as queries_module

        data_module = sys.modules["ghidra.program.model.data"]
        path = self._Path(category_path)
        category_ctor = mock.MagicMock(return_value=path)
        created = self._Structure(path, "Packet", stored_size)
        structure_ctor = mock.MagicMock(return_value=created)
        conflict_handler = SimpleNamespace(DEFAULT_HANDLER=object())
        monkeypatch.setattr(
            data_module, "CategoryPath", category_ctor, raising=False)
        monkeypatch.setattr(
            data_module, "DataTypeConflictHandler", conflict_handler,
            raising=False)
        monkeypatch.setattr(
            data_module, "Structure", self._Structure, raising=False)
        monkeypatch.setattr(
            data_module, "StructureDataType", structure_ctor, raising=False)

        ctx = _make_ctx()
        ctx.program.startTransaction.return_value = 17
        dtm = mock.MagicMock()
        dtm.getDataType.return_value = None
        dtm.addDataType.return_value = created
        dtm.getAllDataTypes.return_value = [created]
        ctx.program.getDataTypeManager.return_value = dtm
        stored_path = read_path if read_path is not None else category_path
        readback = mock.MagicMock(return_value={
            "name": "Packet", "path": stored_path, "size": stored_size,
            "fields": [],
        })
        monkeypatch.setattr(queries_module, "get_structure", readback)
        return ctx, dtm, category_ctor, structure_ctor, readback

    def test_non_root_creation_reports_exact_requested_and_stored_path(
        self, monkeypatch
    ):
        ctx, dtm, category_ctor, structure_ctor, readback = self._setup(
            monkeypatch
        )

        result = create_structure(
            ctx, "Packet", 8, "/analysis/types"
        )

        assert result["status"] == "success"
        assert result["requested"]["category_path"] == "/analysis/types"
        assert result["stored"]["path"] == "/analysis/types"
        assert result["stored"]["exists"] is True
        category_ctor.assert_called_once_with("/analysis/types")
        dtm.getDataType.assert_called_once()
        structure_ctor.assert_called_once()
        readback.assert_called_once_with(ctx, "Packet", "/analysis/types")
        ctx.program.endTransaction.assert_called_once_with(17, True)

    def test_omitted_category_preserves_root_behavior(self, monkeypatch):
        ctx, _, category_ctor, _, _ = self._setup(
            monkeypatch, category_path="/", stored_size=1
        )

        result = create_structure(ctx, "Packet")

        assert result["status"] == "success"
        assert result["requested"]["size"] == 0
        assert result["requested"]["category_path"] == "/"
        assert result["stored"]["path"] == "/"
        assert result["stored"]["size"] == 1
        category_ctor.assert_called_once_with("/")

    def test_invalid_path_is_rejected_before_transaction(self, monkeypatch):
        ctx, dtm, category_ctor, _, _ = self._setup(monkeypatch)
        category_ctor.side_effect = ValueError("not absolute")

        result = create_structure(ctx, "Packet", 8, "relative/path")

        assert result["status"] == "validation_failed"
        assert "Invalid category path" in result["error"]
        ctx.program.startTransaction.assert_not_called()
        dtm.addDataType.assert_not_called()

    def test_exact_path_collision_is_rejected_without_mutation(
        self, monkeypatch
    ):
        ctx, dtm, _, _, _ = self._setup(monkeypatch)
        dtm.getDataType.return_value = object()

        result = create_structure(
            ctx, "Packet", 8, "/analysis/types"
        )

        assert result["status"] == "validation_failed"
        ctx.program.startTransaction.assert_not_called()
        dtm.addDataType.assert_not_called()

    def test_same_name_in_another_category_does_not_block_creation(
        self, monkeypatch
    ):
        ctx, dtm, _, _, _ = self._setup(monkeypatch)
        other = self._Structure(self._Path("/other"), "Packet", 8)
        dtm.getAllDataTypes.return_value = [other]

        result = create_structure(
            ctx, "Packet", 8, "/analysis/types"
        )

        assert result["status"] == "success"
        dtm.getAllDataTypes.assert_not_called()
        ctx.program.endTransaction.assert_called_once_with(17, True)

    def test_stored_path_mismatch_rolls_back(self, monkeypatch):
        ctx, _, _, _, _ = self._setup(
            monkeypatch, read_path="/other"
        )

        result = create_structure(
            ctx, "Packet", 8, "/analysis/types"
        )

        assert result["status"] == "rolled_back"
        assert "stored" not in result
        assert "read-back mismatch" in result["error"]
        ctx.program.endTransaction.assert_called_once_with(17, False)


class TestRenameStructure:
    def test_not_found(self):
        ctx = _make_ctx()
        dtm = mock.MagicMock()
        dtm.getAllDataTypes.return_value = []
        ctx.program.getDataTypeManager.return_value = dtm
        result = set_structure_name(ctx, "missing", "new_name")
        assert result["status"] == "validation_failed"

    @mock.patch("ghidramsc._query_composites._find_first_structure")
    @mock.patch("ghidramsc._query_composites._structure_state_by_name")
    def test_success_preserves_name_only_selection(
        self, state_query, find_first
    ):
        ctx = _make_ctx()
        structure = mock.MagicMock()
        state = {"old": True, "new": False}
        state_query.side_effect = lambda _ctx, name: {
            "exists": state[name], "name": name,
        }
        find_first.return_value = structure
        structure.setName.side_effect = lambda _name: state.update(
            {"old": False, "new": True}
        )
        ctx.program.startTransaction.return_value = 41

        result = set_structure_name(ctx, "old", "new")

        assert result["status"] == "success"
        assert result["stored"] == {"exists": True, "name": "new"}
        ctx.program.endTransaction.assert_called_once_with(41, True)

    @mock.patch("ghidramsc._query_composites._find_first_structure")
    @mock.patch("ghidramsc._query_composites._structure_state_by_name")
    def test_failure_reads_old_identity_after_rollback(
        self, state_query, find_first
    ):
        ctx = _make_ctx()
        structure = mock.MagicMock()
        state_query.side_effect = lambda _ctx, name: {
            "exists": name == "old", "name": name,
        }
        find_first.return_value = structure
        structure.setName.side_effect = ValueError("rename rejected")
        ctx.program.startTransaction.return_value = 42

        result = set_structure_name(ctx, "old", "new")

        assert result["status"] == "rolled_back"
        assert result["stored"] == {"exists": True, "name": "old"}
        ctx.program.endTransaction.assert_called_once_with(42, False)


class TestDeleteStructure:
    def test_not_found(self):
        ctx = _make_ctx()
        dtm = mock.MagicMock()
        dtm.getAllDataTypes.return_value = []
        ctx.program.getDataTypeManager.return_value = dtm
        result = delete_structure(ctx, "missing")
        assert result["status"] == "validation_failed"

    @mock.patch("ghidramsc._query_composites._get_monitor")
    @mock.patch("ghidramsc._query_composites._find_first_structure")
    @mock.patch("ghidramsc._query_composites._structure_state_by_name")
    def test_success(self, state_query, find_first, monitor):
        ctx = _make_ctx()
        structure = mock.MagicMock()
        present = {"value": True}
        state_query.side_effect = lambda *_args: {
            "exists": present["value"], "name": "target",
        }
        find_first.return_value = structure
        dtm = ctx.program.getDataTypeManager()
        dtm.remove.side_effect = lambda *_args: present.__setitem__(
            "value", False
        )
        ctx.program.startTransaction.return_value = 43

        result = delete_structure(ctx, "target")

        assert result["status"] == "success"
        assert result["stored"] == {"exists": False, "name": "target"}
        dtm.remove.assert_called_once_with(structure, monitor.return_value)
        ctx.program.endTransaction.assert_called_once_with(43, True)


# ---------------------------------------------------------------------------
# Call graph / basic blocks / function xrefs
# ---------------------------------------------------------------------------

class TestGenerateCallGraph:
    def test_not_found(self):
        ctx = _make_ctx()
        result = get_function_call_graph(ctx, "0xdead")
        assert "error" in result

    @mock.patch("ghidramsc._query_analysis._get_monitor")
    def test_simple_graph(self, mock_monitor):
        f1 = _mock_function("main", 0x100)
        f2 = _mock_function("helper", 0x200)
        f1.getCalledFunctions.return_value = [f2]
        f2.getCalledFunctions.return_value = []
        ctx = _make_ctx([f1, f2])
        result = get_function_call_graph(ctx, "0x100", depth=2)
        assert result["name"] == "main"
        assert result["callees"] == []
        assert result["possible_callees"][0]["name"] == "helper"
        assert result["complete"] is False


class TestGetFunctionXrefs:
    def test_not_found(self):
        ctx = _make_ctx()
        result = get_function_call_relationships(ctx, "0xdead")
        assert "error" in result

    @mock.patch("ghidramsc._query_analysis._get_monitor")
    def test_found(self, mock_monitor):
        f1 = _mock_function("caller", 0x100)
        f2 = _mock_function("target", 0x200)
        f2.getCallingFunctions.return_value = [f1]
        f2.getCalledFunctions.return_value = []
        ctx = _make_ctx([f1, f2])
        result = get_function_call_relationships(ctx, "0x200")
        assert result["function"] == "target"
        assert result["num_callers"] == 1
        assert result["callers"][0]["name"] == "caller"


# ---------------------------------------------------------------------------
# write_memory_bytes
# ---------------------------------------------------------------------------

class TestPatchBytes:
    def test_odd_length(self):
        ctx = _make_ctx()
        result = write_memory_bytes(ctx, "0x1000", "abc")
        assert result["status"] == "validation_failed"

    def test_invalid_hex(self):
        ctx = _make_ctx()
        result = write_memory_bytes(ctx, "0x1000", "zzzz")
        assert result["status"] == "validation_failed"

    def test_success(self):
        ctx = _make_ctx()
        mem = mock.MagicMock()
        state = bytearray.fromhex("01020304")

        def read(_addr, output):
            output[:] = state
            return len(state)

        def write(_addr, value):
            state[:] = value

        mem.getBytes.side_effect = read
        mem.setBytes.side_effect = write
        ctx.program.getMemory.return_value = mem
        ctx.program.startTransaction.return_value = 23
        result = write_memory_bytes(ctx, "0x1000", "90909090")
        assert result["status"] == "success"
        assert result["old"]["hex_bytes"] == "01020304"
        assert result["stored"]["hex_bytes"] == "90909090"
        mem.setBytes.assert_called_once()
        ctx.program.endTransaction.assert_called_once_with(23, True)

    def test_write_failure_rolls_back_and_reads_final_state(self):
        ctx = _make_ctx()
        mem = mock.MagicMock()
        state = bytearray.fromhex("01020304")

        def read(_addr, output):
            output[:] = state
            return len(state)

        mem.getBytes.side_effect = read
        mem.setBytes.side_effect = OSError("write blocked")
        ctx.program.getMemory.return_value = mem
        ctx.program.startTransaction.return_value = 24

        result = write_memory_bytes(ctx, "0x1000", "90909090")

        assert result["status"] == "rolled_back"
        assert result["stored"]["hex_bytes"] == "01020304"
        assert "write blocked" in result["error"]
        ctx.program.endTransaction.assert_called_once_with(24, False)


# ---------------------------------------------------------------------------
# Calling convention / set_data_label / apply_data_type
# ---------------------------------------------------------------------------

class TestGetDataGuidance:
    def test_undefined_address_suggests_raw_bytes_and_references(self):
        ctx = mock.MagicMock()
        ctx.program.getListing.return_value.getDefinedDataAt.return_value = None
        ctx.program.getListing.return_value.getDefinedDataContaining.return_value = None
        result = get_data_at_address(ctx, "0x100")
        assert result.startswith("ERROR: No defined data at 0x100")
        assert "read_memory_bytes" in result
        assert "list_references_to_address" in result


class TestSetCallingConvention:
    def test_not_found(self):
        ctx = _make_ctx()
        result = set_function_calling_convention(ctx, "0xdead", "__stdcall")
        assert result["status"] == "validation_failed"

    def test_invalid_name_lists_program_conventions_without_transaction(self):
        ctx = _make_ctx([_mock_function("target", 0x100)])
        manager = ctx.program.getFunctionManager()
        manager.getCallingConvention.return_value = None
        manager.getCallingConventionNames.return_value = ["__stdcall", "__cdecl"]
        result = set_function_calling_convention(ctx, "0x100", "__bogus")
        assert result["status"] == "validation_failed"
        assert "__cdecl, __stdcall, default" in result["error"]
        ctx.program.startTransaction.assert_not_called()

    @mock.patch("ghidramsc._query_functions._func_info_contract_state")
    def test_success(self, state_query):
        f = _mock_function("target", 0x100)
        state = {"calling_convention": "default"}
        f.getCallingConventionName.side_effect = (
            lambda: state["calling_convention"]
        )
        f.setCallingConvention.side_effect = (
            lambda value: state.__setitem__("calling_convention", value)
        )
        state_query.side_effect = lambda *_args: dict(state)
        ctx = _make_ctx([f])
        ctx.program.startTransaction.return_value = 31
        result = set_function_calling_convention(ctx, "0x100", "__cdecl")
        assert result["status"] == "success"
        assert result["old"]["calling_convention"] == "default"
        assert result["stored"]["calling_convention"] == "__cdecl"
        f.setCallingConvention.assert_called_once_with("__cdecl")
        ctx.program.endTransaction.assert_called_once_with(31, True)


class TestLegacyVariableContracts:
    @staticmethod
    def _variable(name="old", data_type=None):
        variable = mock.MagicMock()
        state = {"name": name, "type": data_type or mock.MagicMock()}
        storage = mock.MagicMock(
            __str__=mock.MagicMock(return_value="Stack[-0x4]:4")
        )
        variable.getName.side_effect = lambda: state["name"]
        variable.setName.side_effect = (
            lambda value, _source: state.__setitem__("name", value)
        )
        variable.getDataType.side_effect = lambda: state["type"]
        variable.setDataType.side_effect = (
            lambda value, _source: state.__setitem__("type", value)
        )
        variable.getVariableStorage.return_value = storage
        return variable, state

    @mock.patch("ghidramsc._query_variables._function_contract_state")
    def test_rename_var_success(self, state_query):
        variable, state = self._variable()
        function = _mock_function("target", 0x100)
        function.getParameters.return_value = []
        function.getLocalVariables.return_value = [variable]
        state_query.side_effect = lambda *_args: {"name": state["name"]}
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 32

        result = set_variable_name(ctx, "0x100", "old", "new")

        assert result["status"] == "success"
        assert result["old"] == {"name": "old"}
        assert result["stored"] == {"name": "new"}
        ctx.program.endTransaction.assert_called_once_with(32, True)

    def test_rename_var_rejects_ambiguous_display_name(self):
        first, _ = self._variable()
        second, _ = self._variable()
        function = _mock_function("target", 0x100)
        function.getParameters.return_value = [first]
        function.getLocalVariables.return_value = [second]
        ctx = _make_ctx([function])

        result = set_variable_name(ctx, "0x100", "old", "new")

        assert result["status"] == "validation_failed"
        assert "ambiguous" in result["error"]
        ctx.program.startTransaction.assert_not_called()

    @mock.patch("ghidramsc._query_variables._function_contract_state")
    @mock.patch("ghidramsc._query_variables._resolve_type")
    def test_retype_var_success(self, resolve_type, state_query):
        old_type = mock.MagicMock()
        old_type.isEquivalent.return_value = False
        new_type = mock.MagicMock(
            __str__=mock.MagicMock(return_value="int")
        )
        new_type.isEquivalent.side_effect = lambda other: other is new_type
        resolve_type.return_value = new_type
        variable, state = self._variable(data_type=old_type)
        function = _mock_function("target", 0x100)
        function.getParameters.return_value = [variable]
        function.getLocalVariables.return_value = []
        state_query.side_effect = lambda *_args: {
            "type": str(state["type"])
        }
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 33

        result = set_variable_type(ctx, "0x100", "old", "int")

        assert result["status"] == "success"
        assert result["requested"]["type"] == "int"
        ctx.program.endTransaction.assert_called_once_with(33, True)


class TestSetReturnType:
    @mock.patch("ghidramsc._query_variables._return_type_parameter_preflight")
    @mock.patch("ghidramsc._query_variables._func_info_contract_state")
    @mock.patch("ghidramsc._query_variables._resolve_type")
    def test_success(self, resolve_type, state_query, parameter_preflight):
        old_type = mock.MagicMock()
        new_type = mock.MagicMock(
            __str__=mock.MagicMock(return_value="int")
        )
        old_type.isEquivalent.return_value = False
        new_type.isEquivalent.side_effect = lambda other: other is new_type
        resolve_type.return_value = new_type
        function = _mock_function("target", 0x100)
        state = {"type": old_type}
        function.getReturnType.side_effect = lambda: state["type"]
        function.setReturnType.side_effect = (
            lambda value, _source: state.__setitem__("type", value)
        )
        state_query.side_effect = lambda *_args: {"return_type": str(state["type"])}
        parameter_preflight.return_value = ([], "")
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 34

        result = set_function_return_type(ctx, "0x100", "int")

        assert result["status"] == "success"
        assert result["stored"]["return_type"] == "int"
        ctx.program.endTransaction.assert_called_once_with(34, True)

    @mock.patch("ghidramsc._query_variables._return_type_parameter_preflight")
    @mock.patch("ghidramsc._query_variables._func_info_contract_state")
    @mock.patch("ghidramsc._query_variables._resolve_type")
    def test_inferred_parameters_are_rejected_before_transaction(
        self, resolve_type, state_query, parameter_preflight
    ):
        old_type = mock.MagicMock()
        new_type = mock.MagicMock(
            __str__=mock.MagicMock(return_value="int")
        )
        old_type.isEquivalent.return_value = False
        resolve_type.return_value = new_type
        function = _mock_function("target", 0x100)
        function.getReturnType.return_value = old_type
        state_query.return_value = {"return_type": "undefined"}
        parameter_preflight.return_value = (
            [{"name": "param_1", "database_backed": False}],
            "use set_function_prototype with the complete signature",
        )
        ctx = _make_ctx([function])

        result = set_function_return_type(ctx, "0x100", "int")

        assert result["status"] == "validation_failed"
        assert result["transaction"] == {"started": False, "committed": False}
        assert "set_function_prototype" in result["error"]
        function.setReturnType.assert_not_called()
        ctx.program.startTransaction.assert_not_called()


class TestSetFunctionPrototype:
    @mock.patch("ghidramsc._query_functions._effective_parameter_contract", return_value=[])
    @mock.patch("ghidramsc._query_functions._apply_function_signature")
    @mock.patch("ghidramsc._query_functions._function_signature_matches")
    @mock.patch("ghidramsc._query_functions._parse_function_signature")
    @mock.patch("ghidramsc._query_functions._func_info_contract_state")
    def test_success_uses_one_transaction_and_verified_readback(
        self, state_query, parse_signature, signature_matches,
        apply_signature, _parameter_contract
    ):
        function = _mock_function("target", 0x100)
        function.getLocalVariables.return_value = []
        function.getParameters.return_value = []
        parsed = mock.MagicMock()
        parsed.getArguments.return_value = []
        parse_signature.return_value = parsed
        state = {"signature": "void target(void)"}
        state_query.side_effect = lambda *_args: dict(state)
        signature_matches.side_effect = [False, True]
        apply_signature.side_effect = lambda *_args: state.__setitem__(
            "signature", "int target(int x)"
        )
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 35

        result = set_function_prototype(
            ctx, "0x100", "int target(int x)"
        )

        assert result["status"] == "success"
        assert result["stored"] == {"signature": "int target(int x)"}
        ctx.program.endTransaction.assert_called_once_with(35, True)

    @mock.patch("ghidramsc._query_functions._effective_parameter_contract", return_value=[])
    @mock.patch("ghidramsc._query_functions._apply_function_signature")
    @mock.patch("ghidramsc._query_functions._function_signature_matches")
    @mock.patch("ghidramsc._query_functions._parse_function_signature")
    @mock.patch("ghidramsc._query_functions._func_info_contract_state")
    def test_late_failure_rolls_back_before_final_readback(
        self, state_query, parse_signature, signature_matches,
        apply_signature, _parameter_contract
    ):
        function = _mock_function("target", 0x100)
        function.getLocalVariables.return_value = []
        function.getParameters.return_value = []
        parsed = mock.MagicMock()
        parsed.getArguments.return_value = []
        parse_signature.return_value = parsed
        state = {"signature": "void target(void)"}
        state_query.side_effect = lambda *_args: dict(state)
        signature_matches.side_effect = [False]

        def partially_apply(*_args):
            state["signature"] = "int target(int x)"
            raise ValueError("late apply failure")

        apply_signature.side_effect = partially_apply
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 36

        def finish_transaction(_tx_id, commit):
            if not commit:
                state["signature"] = "void target(void)"

        ctx.program.endTransaction.side_effect = finish_transaction

        result = set_function_prototype(
            ctx, "0x100", "int target(int x)"
        )

        assert result["status"] == "rolled_back"
        assert result["stored"] == {"signature": "void target(void)"}
        assert "late apply failure" in result["error"]
        ctx.program.endTransaction.assert_called_once_with(36, False)

    def test_runtime_lookup_uses_ghidra_12_function_rename_option(self):
        lookups = []
        command = mock.MagicMock()
        command.applyTo.return_value = True
        command_type = mock.MagicMock(return_value=command)
        source_type = SimpleNamespace(USER_DEFINED=object())
        conflict_handler = SimpleNamespace(DEFAULT_HANDLER=object())
        rename_option = SimpleNamespace(RENAME=object())
        classes = {
            "ghidra.app.cmd.function.ApplyFunctionSignatureCmd": command_type,
            "ghidra.program.model.symbol.SourceType": source_type,
            "ghidra.program.model.data.DataTypeConflictHandler": conflict_handler,
            "ghidra.app.cmd.function.FunctionRenameOption": rename_option,
        }
        jpype = ModuleType("jpype")

        def jclass(name):
            lookups.append(name)
            return classes[name]

        jpype.JClass = jclass
        program = mock.MagicMock()
        function = mock.MagicMock()
        parsed = mock.MagicMock()
        monitor = object()

        with (
            mock.patch.dict(sys.modules, {"jpype": jpype}),
            mock.patch(
                "ghidramsc._query_functions._get_monitor",
                return_value=monitor,
            ),
        ):
            _apply_function_signature(program, function, parsed)

        assert "ghidra.app.cmd.function.FunctionRenameOption" in lookups
        assert "ghidra.program.model.listing.FunctionRenameOption" not in lookups
        command.applyTo.assert_called_once_with(program, monitor)


class TestRenameData:
    def test_no_defined_data(self):
        ctx = _make_ctx()
        ctx.program.getListing.return_value.getDefinedDataAt.return_value = None
        ctx.program.getListing.return_value.getDefinedDataContaining.return_value = None
        result = set_data_label(ctx, "0x3000", "new_label")
        assert result["status"] == "validation_failed"

    def test_success(self):
        ctx = _make_ctx()
        address = _addr_obj(0x3000)
        state = {"name": "old_label"}
        sym = mock.MagicMock()
        sym.getID.return_value = 7
        sym.getName.side_effect = lambda: state["name"]
        sym.setName.side_effect = (
            lambda value, _source: state.__setitem__("name", value)
        )
        sym.getParentNamespace.return_value = mock.MagicMock()
        sym.getSymbolType.return_value = "LABEL"
        sym.getSource.return_value = "USER_DEFINED"
        sym.isDynamic.return_value = False
        data = mock.MagicMock()
        data.getAddress.return_value = address
        data.getDataType.return_value.getName.return_value = "int"
        data.getLength.return_value = 4
        data.getDefaultValueRepresentation.return_value = "1"
        data.getPrimarySymbol.return_value = sym
        listing = mock.MagicMock()
        listing.getDefinedDataAt.return_value = data
        ctx.program.getListing.return_value = listing
        st = mock.MagicMock()
        st.getSymbols.return_value = [sym]
        st.getNamespaceSymbol.return_value = None
        st.getClassSymbol.return_value = None
        st.getLibrarySymbol.return_value = None
        st.getSymbol.return_value = None
        ctx.program.getSymbolTable.return_value = st
        ctx.program.startTransaction.return_value = 37
        result = set_data_label(ctx, "0x3000", "new_label")
        assert result["status"] == "success"
        assert result["old"]["label"] == "old_label"
        assert result["stored"]["label"] == "new_label"
        assert result["stored"]["labels"][0]["primary"] is True
        ctx.program.endTransaction.assert_called_once_with(37, True)


class TestApplyDataType:
    def test_large_state_keeps_late_conflict_and_instruction_facts(self):
        ctx = _make_ctx()
        addr = mock.MagicMock()
        units = []
        for index in range(130):
            unit = mock.MagicMock()
            unit.getAddress.return_value = "{:08x}".format(index)
            unit.getMaxAddress.return_value = "{:08x}".format(index)
            unit.getLength.return_value = 1
            unit.getDataType.return_value = "undefined1"
            unit.isDefined.return_value = index == 120
            units.append(unit)
        listing = mock.MagicMock()
        listing.getCodeUnitContaining.return_value = None
        listing.getInstructionAt.side_effect = (
            lambda address: object() if address == "00000081" else None
        )
        iterator = mock.MagicMock()
        iterator.hasNext.side_effect = [True] * len(units) + [False]
        iterator.next.side_effect = units
        listing.getCodeUnits.return_value = iterator
        ctx.program.getListing.return_value = listing
        address_module = ModuleType("ghidra.program.model.address")
        address_module.AddressSet = mock.MagicMock()
        modules = {
            "ghidra": ModuleType("ghidra"),
            "ghidra.program": ModuleType("ghidra.program"),
            "ghidra.program.model": ModuleType("ghidra.program.model"),
            "ghidra.program.model.address": address_module,
        }
        target = {"type": "int[130]", "size": 130,
                  "value": "x" * 2000,
                  "labels": [{"name": str(i)} for i in range(70)]}
        with mock.patch.dict(sys.modules, modules), mock.patch(
                "ghidramsc._query_data.get_data_at_address",
                return_value=target):
            state = _data_application_state(ctx, addr, 130)

        assert state["code_unit_count"] == 130
        assert len(state["code_units"]) == 64
        assert state["code_units_truncated"] is True
        assert state["conflict_count"] == 1
        assert state["conflicts"][0]["address"] == "00000078"
        assert state["has_instructions"] is True
        assert state["target"]["type"] == "int[130]"
        assert state["target"]["size"] == 130
        assert state["target"]["value_length"] == 2000
        assert len(state["target"]["value"]) == 1024
        assert state["target"]["label_count"] == 70
        assert len(state["target"]["labels"]) == 64

    @mock.patch("ghidramsc._query_data._resolve_type")
    def test_unknown_type(self, mock_resolve):
        mock_resolve.return_value = None
        ctx = _make_ctx()
        result = apply_data_type(ctx, "0x3000", "weird_type")
        assert result["status"] == "validation_failed"
        assert "Unknown data type" in result["error"]
        assert result["transaction"] == {
            "started": False, "committed": False,
        }

    def test_invalid_clear_mode(self):
        ctx = _make_ctx()
        result = apply_data_type(ctx, "0x3000", "int", "instructions")
        assert result["status"] == "validation_failed"
        assert "fail or data_only" in result["error"]

    @mock.patch("ghidramsc._query_data._read_application_bytes", return_value=b"ABCD")
    @mock.patch("ghidramsc._query_data._data_application_state")
    @mock.patch("ghidramsc._query_data._resolve_type")
    def test_default_rejects_defined_data_without_transaction(
            self, mock_resolve, mock_state, _mock_bytes):
        dt = mock.MagicMock()
        dt.getLength.return_value = 4
        mock_resolve.return_value = dt
        mock_state.return_value = {
            "has_instructions": False,
            "conflicts": [{"address": "00003000", "kind": "data"}],
        }
        ctx = _make_ctx()
        ctx.to_addr.return_value = mock.MagicMock()
        ctx.program.getListing.return_value.getDefinedDataAt.return_value = None

        result = apply_data_type(ctx, "0x3000", "int")

        assert result["status"] == "validation_failed"
        assert "clear_mode=data_only" in result["error"]
        ctx.program.startTransaction.assert_not_called()

    @mock.patch("ghidramsc._query_data._read_application_bytes", return_value=b"ABCD")
    @mock.patch("ghidramsc._query_data._data_application_state")
    @mock.patch("ghidramsc._query_data._resolve_type")
    def test_data_only_never_clears_instructions(
            self, mock_resolve, mock_state, _mock_bytes):
        dt = mock.MagicMock()
        dt.getLength.return_value = 4
        mock_resolve.return_value = dt
        mock_state.return_value = {
            "has_instructions": True,
            "conflicts": [],
        }
        ctx = _make_ctx()
        ctx.to_addr.return_value = mock.MagicMock()
        ctx.program.getListing.return_value.getDefinedDataAt.return_value = None

        result = apply_data_type(ctx, "0x3000", "int", "data_only")

        assert result["status"] == "validation_failed"
        assert "never clears instructions" in result["error"]
        ctx.program.startTransaction.assert_not_called()

    @mock.patch("ghidramsc._query_data._read_application_bytes", return_value=b"ABCD")
    @mock.patch("ghidramsc._query_data._data_application_state")
    @mock.patch("ghidramsc._query_data._resolve_type")
    def test_data_only_success_reports_byte_preservation(
            self, mock_resolve, mock_state, _mock_bytes):
        dt = mock.MagicMock()
        dt.getLength.return_value = 4
        dt.isEquivalent.return_value = True
        mock_resolve.return_value = dt
        mock_state.side_effect = [
            {"has_instructions": False, "conflicts": [{"kind": "data"}]},
            {"has_instructions": False, "conflicts": [{"kind": "data"}]},
        ]
        ctx = _make_ctx()
        ctx.to_addr.return_value = mock.MagicMock()
        stored_data = mock.MagicMock()
        stored_data.getDataType.return_value = dt
        ctx.program.getListing.return_value.getDefinedDataAt.side_effect = [
            None, stored_data,
        ]
        ctx.program.startTransaction.return_value = 17

        data_module = ModuleType("ghidra.program.model.data")
        data_utilities = mock.MagicMock()
        data_utilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA = "data_only"
        data_utilities.ClearDataMode.CHECK_FOR_SPACE = "fail"
        data_module.DataUtilities = data_utilities
        modules = {
            "ghidra": ModuleType("ghidra"),
            "ghidra.program": ModuleType("ghidra.program"),
            "ghidra.program.model": ModuleType("ghidra.program.model"),
            "ghidra.program.model.data": data_module,
        }
        with mock.patch.dict(sys.modules, modules):
            result = apply_data_type(ctx, "0x3000", "int", "data_only")

        assert result["status"] == "success"
        assert result["stored"]["bytes_preserved"] is True
        assert result["stored"]["byte_count"] == 4
        data_utilities.createData.assert_called_once()
        ctx.program.endTransaction.assert_called_once_with(17, True)

    @mock.patch("ghidramsc._query_data._read_application_bytes")
    @mock.patch("ghidramsc._query_data._data_application_state")
    @mock.patch("ghidramsc._query_data._resolve_type")
    def test_mapped_uninitialized_data_is_typed_without_inventing_bytes(
            self, mock_resolve, mock_state, mock_bytes):
        dt = mock.MagicMock()
        dt.getLength.return_value = 64
        dt.isEquivalent.return_value = True
        mock_resolve.return_value = dt
        mock_state.side_effect = [
            {"has_instructions": False, "conflicts": []},
            {"has_instructions": False, "conflicts": [],
             "target": {"type": "char[64]", "label": "DAT_0040f080"}},
        ]
        ctx = _make_ctx()
        addr = mock.MagicMock()
        ctx.to_addr.return_value = addr
        block = ctx.program.getMemory.return_value.getBlock.return_value
        block.contains.return_value = True
        block.isInitialized.return_value = False
        block.getName.return_value = ".bss"
        block.getStart.return_value = addr
        block.getEnd.return_value = addr
        initialized_set = ctx.program.getMemory.return_value.getAllInitializedAddressSet.return_value
        initialized_set.contains.return_value = False
        initialized_set.intersects.return_value = False
        ctx.program.getListing.return_value.getDefinedDataAt.side_effect = [
            None, mock.MagicMock(getDataType=mock.MagicMock(return_value=dt)),
        ]
        ctx.program.startTransaction.return_value = 17

        data_module = ModuleType("ghidra.program.model.data")
        data_utilities = mock.MagicMock()
        data_utilities.ClearDataMode.CHECK_FOR_SPACE = "fail"
        data_module.DataUtilities = data_utilities
        modules = {
            "ghidra": ModuleType("ghidra"),
            "ghidra.program": ModuleType("ghidra.program"),
            "ghidra.program.model": ModuleType("ghidra.program.model"),
            "ghidra.program.model.data": data_module,
        }
        with mock.patch.dict(sys.modules, modules):
            result = apply_data_type(ctx, "0x40f080", "char[64]")

        assert result["status"] == "success"
        assert result["stored"]["memory_block"]["initialized"] is False
        assert result["stored"]["byte_state"] == "uninitialized_no_file_bytes"
        assert result["stored"]["byte_count"] == 0
        assert result["stored"]["bytes_preserved"] is None
        assert result["stored"]["target"]["label"] == "DAT_0040f080"
        mock_bytes.assert_not_called()
        data_utilities.createData.assert_called_once()
        ctx.program.endTransaction.assert_called_once_with(17, True)

    @mock.patch("ghidramsc._query_data._read_application_bytes")
    @mock.patch("ghidramsc._query_data._resolve_type")
    def test_uninitialized_object_over_limit_is_rejected_before_transaction(
            self, mock_resolve, mock_bytes):
        dt = mock.MagicMock()
        dt.getLength.return_value = 4097
        mock_resolve.return_value = dt
        ctx = _make_ctx()
        block = ctx.program.getMemory.return_value.getBlock.return_value
        block.contains.return_value = True
        block.isInitialized.return_value = False
        initialized_set = ctx.program.getMemory.return_value.getAllInitializedAddressSet.return_value
        initialized_set.contains.return_value = False
        initialized_set.intersects.return_value = False

        result = apply_data_type(ctx, "0x40f080", "char[4097]")

        assert result["status"] == "validation_failed"
        assert "exceeds 4096 bytes" in result["error"]
        ctx.program.startTransaction.assert_not_called()
        mock_bytes.assert_not_called()

    @mock.patch("ghidramsc._query_data._resolve_type")
    def test_partly_initialized_object_is_rejected_before_transaction(
            self, mock_resolve):
        dt = mock.MagicMock()
        dt.getLength.return_value = 64
        mock_resolve.return_value = dt
        ctx = _make_ctx()
        block = ctx.program.getMemory.return_value.getBlock.return_value
        block.contains.return_value = True
        initialized_set = ctx.program.getMemory.return_value.getAllInitializedAddressSet.return_value
        initialized_set.contains.return_value = False
        initialized_set.intersects.return_value = True

        result = apply_data_type(ctx, "0x40f080", "char[64]")

        assert result["status"] == "validation_failed"
        assert "mixes initialized and uninitialized" in result["error"]
        ctx.program.startTransaction.assert_not_called()


# ---------------------------------------------------------------------------
# Security heuristics
# ---------------------------------------------------------------------------

class TestDetectSecurityMitigations:
    def test_no_wx(self):
        blk1 = _mock_block(".text", 0x1000, 0x2000, r=True, x=True, w=False)
        blk2 = _mock_block(".data", 0x3000, 0x4000, r=True, w=True, x=False)
        ctx = _make_ctx(blocks=[blk1, blk2])
        # Symbol table for canary check.
        st = mock.MagicMock()
        st.getSymbols.return_value = []
        ctx.program.getSymbolTable.return_value = st
        ctx.program.getOptions.return_value = mock.MagicMock(
            getString=mock.MagicMock(return_value=""))
        result = detect_security_mitigations(ctx)
        assert result["mitigations"]["nx_dep"]["enabled"] is True
        assert len(result["mitigations"]["nx_dep"]["wx_segments"]) == 0

    def test_wx_detected(self):
        blk = _mock_block(".rwx", 0x1000, 0x2000, r=True, w=True, x=True)
        ctx = _make_ctx(blocks=[blk])
        st = mock.MagicMock()
        st.getSymbols.return_value = []
        ctx.program.getSymbolTable.return_value = st
        ctx.program.getOptions.return_value = mock.MagicMock(
            getString=mock.MagicMock(return_value=""))
        result = detect_security_mitigations(ctx)
        assert result["mitigations"]["nx_dep"]["enabled"] is False
        assert len(result["mitigations"]["nx_dep"]["wx_segments"]) == 1

    def test_canary_detected(self):
        blk = _mock_block(".text", 0x1000, 0x2000, r=True, x=True)
        ctx = _make_ctx(blocks=[blk])
        st = mock.MagicMock()
        chk_sym = mock.MagicMock()
        chk_sym.getName.return_value = "__stack_chk_fail"
        def get_symbols(name):
            if name == "__stack_chk_fail":
                return [chk_sym]
            return []
        st.getSymbols.side_effect = get_symbols
        ctx.program.getSymbolTable.return_value = st
        ctx.program.getOptions.return_value = mock.MagicMock(
            getString=mock.MagicMock(return_value=""))
        result = detect_security_mitigations(ctx)
        assert result["mitigations"]["stack_canary"]["detected"] is True
        assert "__stack_chk_fail" in result["mitigations"]["stack_canary"]["symbols"]


class TestFindFormatStringVulns:
    @mock.patch("ghidramsc._query_analysis._get_monitor")
    def test_no_printf(self, mock_monitor):
        ctx = _make_ctx()
        result = find_format_string_vulns(ctx)
        assert result["potential_format_string_vulns"] == 0


# ---------------------------------------------------------------------------
# Image base / memory permissions
# ---------------------------------------------------------------------------

class TestSetImageBase:
    def test_success(self):
        ctx = _make_ctx()
        base = [_addr_obj(0x10000)]
        ctx.program.getImageBase.side_effect = lambda: base[0]
        ctx.program.setImageBase.side_effect = (
            lambda value, _relocate: base.__setitem__(0, value)
        )
        ctx.program.startTransaction.return_value = 25
        result = set_program_image_base(ctx, "0x400000")
        assert result["status"] == "success"
        assert result["old"]["image_base"] == "0x10000"
        assert result["stored"]["image_base"] == "0x400000"
        ctx.program.setImageBase.assert_called_once()
        ctx.program.endTransaction.assert_called_once_with(25, True)

    def test_failure(self):
        ctx = _make_ctx()
        ctx.program.setImageBase.side_effect = Exception("cannot rebase")
        ctx.program.startTransaction.return_value = 26
        result = set_program_image_base(ctx, "0x400000")
        assert result["status"] == "rolled_back"
        assert result["stored"]["image_base"] == "0x10000"
        assert "cannot rebase" in result["error"]
        ctx.program.endTransaction.assert_called_once_with(26, False)


class TestSetMemoryPermissions:
    def test_block_not_found(self):
        ctx = _make_ctx()
        mem = mock.MagicMock()
        mem.getBlock.return_value = None
        ctx.program.getMemory.return_value = mem
        result = set_memory_block_permissions(ctx, ".missing")
        assert result["status"] == "validation_failed"
        ctx.program.startTransaction.assert_not_called()

    def test_success(self):
        blk = _mock_block(
            ".text", 0x1000, 0x1fff, r=True, w=False, x=False
        )
        state = {"read": True, "write": False, "execute": False}
        blk.isRead.side_effect = lambda: state["read"]
        blk.isWrite.side_effect = lambda: state["write"]
        blk.isExecute.side_effect = lambda: state["execute"]
        blk.setRead.side_effect = lambda value: state.__setitem__("read", value)
        blk.setWrite.side_effect = lambda value: state.__setitem__("write", value)
        blk.setExecute.side_effect = (
            lambda value: state.__setitem__("execute", value)
        )
        ctx = _make_ctx(blocks=[blk])
        mem = ctx.program.getMemory()
        mem.getBlock.return_value = blk
        ctx.program.startTransaction.return_value = 27
        result = set_memory_block_permissions(ctx, ".text", read=True, write=False, execute=True)
        assert result["status"] == "success"
        assert result["old"]["blocks"][0]["execute"] is False
        assert result["stored"]["blocks"][0]["execute"] is True
        blk.setRead.assert_called_once_with(True)
        blk.setWrite.assert_called_once_with(False)
        blk.setExecute.assert_called_once_with(True)
        ctx.program.endTransaction.assert_called_once_with(27, True)


class TestIdentifyUserInputSources:
    def test_no_input_functions(self):
        ctx = _make_ctx()
        fm = mock.MagicMock()
        fm.getFunctions.return_value = iter([])
        ctx.program.getFunctionManager.return_value = fm
        result = identify_user_input_sources(ctx)
        assert result["input_sources_found"] == 0
        assert result["sources"] == []

    def test_finds_recv(self):
        ctx = _make_ctx()
        func = mock.MagicMock()
        func.getName.return_value = "recv"
        entry = mock.MagicMock()
        entry.__str__ = lambda s: "0x1000"
        func.getEntryPoint.return_value = entry
        func.getCallingFunctions.return_value = []

        ref = mock.MagicMock()
        ref_addr = mock.MagicMock()
        ref_addr.__str__ = lambda s: "0x2000"
        ref.getFromAddress.return_value = ref_addr
        rm = mock.MagicMock()
        rm.getReferencesTo.return_value = [ref]
        ctx.program.getReferenceManager.return_value = rm

        fm = mock.MagicMock()
        fm.getFunctions.return_value = iter([func])
        ctx.program.getFunctionManager.return_value = fm

        result = identify_user_input_sources(ctx)
        assert result["input_sources_found"] == 1
        assert result["sources"][0]["function"] == "recv"


class TestIdentifyCryptoPatterns:
    def test_no_crypto(self):
        ctx = _make_ctx()
        fm = mock.MagicMock()
        fm.getFunctions.return_value = iter([])
        ctx.program.getFunctionManager.return_value = fm
        mem = mock.MagicMock()
        mem.findBytes.return_value = None
        ctx.program.getMemory.return_value = mem
        result = identify_crypto_patterns(ctx)
        assert result["total_indicators"] == 0

    def test_finds_crypto_function(self):
        ctx = _make_ctx()
        func = mock.MagicMock()
        func.getName.return_value = "AES_encrypt"
        entry = mock.MagicMock()
        entry.__str__ = lambda s: "0x5000"
        func.getEntryPoint.return_value = entry
        fm = mock.MagicMock()
        fm.getFunctions.return_value = iter([func])
        ctx.program.getFunctionManager.return_value = fm
        mem = mock.MagicMock()
        mem.findBytes.return_value = None
        ctx.program.getMemory.return_value = mem
        result = identify_crypto_patterns(ctx)
        assert len(result["crypto_functions"]) == 1
        assert result["crypto_functions"][0]["function"] == "AES_encrypt"

    def test_finds_constant(self):
        ctx = _make_ctx()
        fm = mock.MagicMock()
        fm.getFunctions.return_value = iter([])
        ctx.program.getFunctionManager.return_value = fm
        addr = mock.MagicMock()
        addr.__str__ = lambda s: "0x8000"
        mem = mock.MagicMock()
        # Return addr for first findBytes call, None for the rest
        mem.findBytes.side_effect = [addr] + [None] * 20
        ctx.program.getMemory.return_value = mem
        result = identify_crypto_patterns(ctx)
        assert len(result["constant_hits"]) >= 1


class TestFindObfuscatedStrings:
    def test_empty_binary(self):
        ctx = _make_ctx()
        fm = mock.MagicMock()
        fm.getFunctions.return_value = iter([])
        ctx.program.getFunctionManager.return_value = fm

        empty_iter = mock.MagicMock()
        empty_iter.hasNext.return_value = False
        listing = mock.MagicMock()
        listing.getDefinedData.return_value = empty_iter

        ctx.program.getListing.return_value = listing
        result = find_obfuscated_strings(ctx)
        assert result["total_findings"] == 0

    def test_xor_detection(self):
        ctx = _make_ctx()
        insn = mock.MagicMock()
        insn.getMnemonicString.return_value = "XOR"
        insn.getNumOperands.return_value = 2
        insn.getDefaultOperandRepresentation.side_effect = lambda i: "EAX" if i == 0 else "EBX"
        addr = mock.MagicMock()
        addr.__str__ = lambda s: "0x100"
        insn.getAddress.return_value = addr
        insn.getNext.return_value = None

        func = mock.MagicMock()
        func.getName.return_value = "decode_string"
        entry = mock.MagicMock()
        entry.__str__ = lambda s: "0x100"
        func.getEntryPoint.return_value = entry

        fm = mock.MagicMock()
        fm.getFunctions.return_value = iter([func])
        ctx.program.getFunctionManager.return_value = fm

        listing = mock.MagicMock()
        listing.getInstructionAt.return_value = insn
        empty_iter = mock.MagicMock()
        empty_iter.hasNext.return_value = False
        listing.getDefinedData.return_value = empty_iter
        ctx.program.getListing.return_value = listing

        result = find_obfuscated_strings(ctx)
        xor_findings = [f for f in result["findings"] if f["type"] == "xor_instruction"]
        assert len(xor_findings) >= 1


def test_memory_buffer_uses_java_array_and_native_length_for_jpype():
    """A Python bytearray is copied by JPype; Java JInt cannot size JArray."""
    class JavaInt(int):
        pass

    class JavaByteArray(list):
        pass

    fake_jpype = ModuleType("jpype")
    fake_jpype.JByte = object()
    fake_jpype.isJVMStarted = lambda: True

    def array_type(_):
        def construct(length):
            assert type(length) is int
            return JavaByteArray([0] * length)
        return construct

    fake_jpype.JArray = array_type
    program = mock.MagicMock()

    def get_bytes(_addr, buffer):
        assert isinstance(buffer, JavaByteArray)
        buffer[:] = [12, -1, 0]
        return 3

    program.getMemory.return_value.getBytes.side_effect = get_bytes
    with mock.patch.dict(sys.modules, {"jpype": fake_jpype}):
        value, count = _read_memory_buffer(program, object(), JavaInt(3))
    assert count == 3
    assert value == bytes((12, 255, 0))
