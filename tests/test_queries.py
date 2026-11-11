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

"""Tests for ghidramsc.queries -- mock-based tests for query functions.

These tests do NOT require a running JVM or a real Ghidra project.  They
verify the logic of each query handler by mocking ProgramContext and the
Ghidra Java objects it wraps.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest

from ghidramsc.queries import (
    _addr_int,
    list_functions,
    decompile_function,
    list_references_to_address,
    list_references_from_address,
    get_listing_at_address,
    get_function_info,
    list_strings,
    search_functions_by_name,
    set_function_name,
    set_function_names,
    search_memory_bytes,
    decompile_functions,
)
from ghidramsc._query_inspection import _incoming_reference_evidence


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _addr_obj(val):
    """Create a mock Ghidra Address with an int offset."""
    a = mock.MagicMock()
    a.__str__ = mock.MagicMock(return_value=hex(val))
    a.getOffset.return_value = val
    a.compareTo = mock.MagicMock(side_effect=lambda o: val - o.getOffset())
    # Support Python-level sorting via < > == operators
    a.__lt__ = mock.MagicMock(side_effect=lambda o: val < o.getOffset())
    a.__le__ = mock.MagicMock(side_effect=lambda o: val <= o.getOffset())
    a.__gt__ = mock.MagicMock(side_effect=lambda o: val > o.getOffset())
    a.__ge__ = mock.MagicMock(side_effect=lambda o: val >= o.getOffset())
    a.__eq__ = mock.MagicMock(side_effect=lambda o: val == getattr(o, 'getOffset', lambda: None)())
    return a


def _mock_function(name, addr_int, is_thunk=False, body_min=None, body_max=None):
    """Create a mock Ghidra Function object."""
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
    body_range = mock.MagicMock()
    body_range.getMinAddress.return_value = body.getMinAddress.return_value
    body_range.getMaxAddress.return_value = body.getMaxAddress.return_value
    range_iterator = mock.MagicMock()
    range_iterator.hasNext.side_effect = [True, False]
    range_iterator.next.return_value = body_range
    body.getAddressRanges.return_value = range_iterator
    f.getBody.return_value = body
    f.getParameters.return_value = []
    f.getCalledFunctions.return_value = []
    f.getCallingFunctions.return_value = []
    f.getStackFrame.return_value = mock.MagicMock(
        getLocalSize=mock.MagicMock(return_value=16),
        getParameterSize=mock.MagicMock(return_value=8),
    )
    return f


def _make_ctx(functions=None):
    """Build a mock ProgramContext with optional functions."""
    ctx = mock.MagicMock()
    ctx.program.getListing.return_value.getInstructions.return_value.hasNext.return_value = False
    ctx.program.getName.return_value = "test_binary"
    functions = functions or []

    func_mgr = mock.MagicMock()
    func_mgr.getFunctions.return_value = functions

    ctx.program.getFunctionManager.return_value = func_mgr

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


# ---------------------------------------------------------------------------
# _addr_int
# ---------------------------------------------------------------------------

class TestAddrInt:
    def test_basic(self):
        assert _addr_int("0x1234") == 0x1234

    def test_no_prefix(self):
        assert _addr_int("abcd") == 0xabcd

    def test_uppercase(self):
        assert _addr_int("0xDEAD") == 0xdead

    def test_qualified_overlay_address(self):
        assert _addr_int("recovered::00404040") == "recovered::00404040"

    def test_reject_malformed_qualified_address(self):
        import pytest
        with pytest.raises(ValueError, match="Invalid qualified address"):
            _addr_int("recovered::not_hex")


# ---------------------------------------------------------------------------
# list_functions
# ---------------------------------------------------------------------------

class TestListFunctions:
    def test_empty(self):
        ctx = _make_ctx([])
        result = list_functions(ctx)
        assert "0 total" in result

    def test_two_funcs(self):
        f1 = _mock_function("alpha", 0x100)
        f2 = _mock_function("beta", 0x200, is_thunk=True)
        ctx = _make_ctx([f1, f2])
        result = list_functions(ctx)
        assert "2 total" in result
        assert "alpha" in result
        assert "[thunk]" in result


# ---------------------------------------------------------------------------
# decompile_function  (needs decompiler mock)
# ---------------------------------------------------------------------------

class TestDecompile:
    def test_no_function(self):
        ctx = _make_ctx([])
        result = decompile_function(ctx, "0x9999")
        assert "ERROR" in result

    @mock.patch("ghidramsc._query_inspection._get_monitor")
    @mock.patch("ghidramsc._query_inspection._get_decompiler")
    def test_success(self, mock_decomp_factory, mock_monitor):
        f = _mock_function("my_func", 0x100)
        ctx = _make_ctx([f])

        decomp = mock.MagicMock()
        dec_result = mock.MagicMock()
        dec_result.decompileCompleted.return_value = True
        dec_result.getDecompiledFunction.return_value.getC.return_value = "int my_func() { return 0; }"
        decomp.decompileFunction.return_value = dec_result
        mock_decomp_factory.return_value = decomp

        result = decompile_function(ctx, "0x100")
        assert "my_func" in result
        assert "return 0" in result
        decomp.dispose.assert_called_once()

    @mock.patch("ghidramsc._query_inspection._get_monitor")
    @mock.patch("ghidramsc._query_inspection._get_decompiler")
    def test_large_function_is_recoverable_in_bounded_chunks(
            self, mock_decomp_factory, _mock_monitor):
        ctx = _make_ctx([_mock_function("large", 0x100)])
        code = "x" * 40000
        decomp = mock.MagicMock()
        result = mock.MagicMock()
        result.decompileCompleted.return_value = True
        result.getDecompiledFunction.return_value.getC.return_value = code
        decomp.decompileFunction.return_value = result
        mock_decomp_factory.return_value = decomp

        first = decompile_function(ctx, "0x100")
        second = decompile_function(ctx, "0x100", 16384)
        third = decompile_function(ctx, "0x100", 32768)

        assert "next_offset=16384" in first.splitlines()[0]
        assert "next_offset=32768" in second.splitlines()[0]
        assert "next_offset=none" in third.splitlines()[0]
        reconstructed = "".join(
            part.split("\n", 1)[1] for part in (first, second, third)
        )
        assert reconstructed.endswith(code)
        assert len(first) < 17000
        assert "limit must be" in decompile_function(ctx, "0x100", limit=40000)
        assert decomp.decompileFunction.call_count == 3


# ---------------------------------------------------------------------------
# list_references_to_address
# ---------------------------------------------------------------------------

class TestXrefsTo:
    def test_no_refs(self):
        ctx = _make_ctx([])
        ref_mgr = mock.MagicMock()
        ref_mgr.getReferencesTo.return_value = []
        ctx.program.getReferenceManager.return_value = ref_mgr

        result = list_references_to_address(ctx, "0x100")
        assert "0 refs" in result


# ---------------------------------------------------------------------------
# list_references_from_address
# ---------------------------------------------------------------------------

class TestXrefsFrom:
    def test_no_refs(self):
        ctx = _make_ctx([])
        ref_mgr = mock.MagicMock()
        ref_mgr.getReferencesFrom.return_value = []
        ctx.program.getReferenceManager.return_value = ref_mgr

        result = list_references_from_address(ctx, "0x100")
        assert "0 refs" in result


# ---------------------------------------------------------------------------
# get_listing_at_address
# ---------------------------------------------------------------------------

class TestListing:
    def test_primary_symbol_is_rendered(self):
        ctx = _make_ctx()
        code_unit = mock.MagicMock()
        code_unit.getAddress.return_value = _addr_obj(0x1000)
        code_unit.__str__ = mock.MagicMock(return_value="undefined4 0h")
        code_unit.getComment.return_value = None
        primary = mock.MagicMock()
        primary.getName.return_value = "requested_primary"
        code_unit.getPrimarySymbol.return_value = primary
        iterator = mock.MagicMock()
        iterator.hasNext.side_effect = [True, False]
        iterator.next.return_value = code_unit
        ctx.program.getListing.return_value.getCodeUnits.return_value = iterator
        ctx.program.getListing.return_value.getCodeUnitContaining.return_value = code_unit

        result = get_listing_at_address(ctx, "0x1000", 1)

        assert "requested_primary:" in result
        assert "0x1000  undefined4 0h" in result


# ---------------------------------------------------------------------------
# get_function_info
# ---------------------------------------------------------------------------

class TestFuncInfo:
    def test_not_found(self):
        ctx = _make_ctx([])
        result = get_function_info(ctx, "0xdead")
        assert "error" in result

    @mock.patch("ghidramsc._query_inspection._get_monitor")
    def test_found(self, mock_monitor):
        f = _mock_function("target_func", 0x400, body_min=0x400, body_max=0x450)
        ctx = _make_ctx([f])

        result = get_function_info(ctx, "0x400")
        assert result["name"] == "target_func"
        assert result["body_bytes"] == 0x50
        assert result["body_ranges"] == [
            {"start": "0x400", "end": "0x450"}
        ]

    @mock.patch("ghidramsc._query_inspection._get_monitor")
    def test_incoming_sites_count_and_page_conservatively(self, mock_monitor):
        target = _mock_function("target", 0x400)
        target.getThunkedFunction.return_value = None
        caller = _mock_function("caller", 0x100, body_max=0x130)
        thunk = _mock_function("thunk", 0x200, is_thunk=True)
        thunk.getThunkedFunction.return_value = target
        ctx = _make_ctx([caller, thunk, target])
        fm = ctx.program.getFunctionManager.return_value
        fm.getFunctionContaining.side_effect = ctx.get_function_containing.side_effect

        def reference(source, kind, *, call=False, jump=False):
            ref = mock.MagicMock()
            ref.getFromAddress.return_value = _addr_obj(source)
            ref.getToAddress.return_value = target.getEntryPoint()
            ref.getOperandIndex.return_value = 0
            ref.getReferenceType.return_value.__str__.return_value = kind
            ref.getReferenceType.return_value.isCall.return_value = call
            ref.getReferenceType.return_value.isJump.return_value = jump
            ref.getReferenceType.return_value.isComputed.return_value = False
            ref.getReferenceType.return_value.isFlow.return_value = call or jump
            return ref

        ctx.program.getReferenceManager.return_value.getReferencesTo.return_value = [
            reference(0x300, "DATA"),
            reference(0x120, "UNCONDITIONAL_JUMP", jump=True),
            reference(0x200, "UNCONDITIONAL_JUMP", jump=True),
            reference(0x115, "UNCONDITIONAL_CALL", call=True),
            reference(0x110, "UNCONDITIONAL_CALL", call=True),
        ]
        incoming = get_function_info(ctx, "0x400", 1, 2)["incoming_references"]
        assert incoming["reference_count"] == 5
        assert incoming["site_count"] == 5
        assert incoming["distinct_source_function_count"] == 2
        assert incoming["category_counts"] == {
            "direct_call": {"reference_count": 2, "site_count": 2,
                            "distinct_source_function_count": 1},
            "verified_thunk_or_tail_flow": {"reference_count": 1,
                                             "site_count": 1,
                                             "distinct_source_function_count": 1},
            "other": {"reference_count": 1, "site_count": 1,
                      "distinct_source_function_count": 0},
            "ambiguous": {"reference_count": 1, "site_count": 1,
                          "distinct_source_function_count": 1},
        }
        assert [item["category"] for item in incoming["sites"]] == [
            "direct_call", "ambiguous",
        ]
        assert incoming["pagination"] == {
            "offset": 1, "limit": 2, "returned": 2, "total": 5,
            "has_more": True, "next_offset": 3,
        }
        end = _incoming_reference_evidence(ctx, target, 5, 2)
        assert end["sites"] == []
        assert end["pagination"] == {
            "offset": 5, "limit": 2, "returned": 0, "total": 5,
            "has_more": False, "next_offset": None,
        }

    def test_incoming_page_rejects_invalid_window(self):
        ctx = _make_ctx([])
        assert "incoming_limit must be 1..500" in get_function_info(
            ctx, "0x400", 0, 501)["error"]


# ---------------------------------------------------------------------------
# search_functions_by_name
# ---------------------------------------------------------------------------

class TestFindFunc:
    def test_match(self):
        f1 = _mock_function("init_hardware", 0x100)
        f2 = _mock_function("main", 0x200)
        f3 = _mock_function("init_software", 0x300)
        ctx = _make_ctx([f1, f2, f3])

        result = search_functions_by_name(ctx, "init_.*")
        assert "2 matches" in result
        assert "init_hardware" in result
        assert "init_software" in result
        assert "main" not in result

    def test_no_match(self):
        f1 = _mock_function("main", 0x100)
        ctx = _make_ctx([f1])
        result = search_functions_by_name(ctx, "zzzzz")
        assert "0 matches" in result

    def test_bad_regex(self):
        ctx = _make_ctx([])
        result = search_functions_by_name(ctx, "[invalid")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# set_function_name
# ---------------------------------------------------------------------------

class TestRenameFunc:
    def test_not_found(self):
        ctx = _make_ctx([])
        result = set_function_name(ctx, "0xdead", "new_name")
        assert result == {
            "operation": "set_function_name",
            "status": "validation_failed",
            "requested": {"address": "0xdead", "name": "new_name"},
            "old": None,
            "stored": None,
            "error": "No function at or containing 0xdead",
        }
        ctx.program.startTransaction.assert_not_called()

    def test_success(self):
        f = _mock_function("old_name", 0x100)
        current = {"name": "old_name"}
        f.getName.side_effect = lambda: current["name"]
        f.setName.side_effect = lambda name, source: current.update(name=name)
        ctx = _make_ctx([f])
        ctx.program.startTransaction.return_value = 37

        result = set_function_name(ctx, "0x100", "new_name")
        assert result == {
            "operation": "set_function_name",
            "status": "success",
            "requested": {"address": "0x100", "name": "new_name"},
            "old": {"address": "0x100", "name": "old_name"},
            "stored": {"address": "0x100", "name": "new_name"},
            "error": None,
        }
        assert ctx.resolve_function.call_count == 2
        ctx.program.startTransaction.assert_called_once_with("Rename function")
        ctx.program.endTransaction.assert_called_once_with(37, True)

    def test_no_change_uses_same_contract_without_transaction(self):
        f = _mock_function("same_name", 0x100)
        ctx = _make_ctx([f])

        result = set_function_name(ctx, "0x100", "same_name")

        assert result == {
            "operation": "set_function_name",
            "status": "no_change",
            "requested": {"address": "0x100", "name": "same_name"},
            "old": {"address": "0x100", "name": "same_name"},
            "stored": {"address": "0x100", "name": "same_name"},
            "error": None,
        }
        f.setName.assert_not_called()
        ctx.program.startTransaction.assert_not_called()

    def test_readback_mismatch_rolls_back_in_same_contract(self):
        f = _mock_function("old_name", 0x100)
        ctx = _make_ctx([f])
        ctx.program.startTransaction.return_value = 37

        result = set_function_name(ctx, "0x100", "new_name")

        assert result["status"] == "rolled_back"
        assert result["requested"] == {
            "address": "0x100", "name": "new_name",
        }
        assert result["old"] == {
            "address": "0x100", "name": "old_name",
        }
        assert result["stored"] == result["old"]
        assert "read-back mismatch" in result["error"]
        assert set(result) == {
            "operation", "status", "requested", "old", "stored", "error",
        }
        ctx.program.endTransaction.assert_called_once_with(37, False)


class TestBatchRename:
    def test_compact_ordered_success_unchanged_and_failure(self, tmp_path):
        function = _mock_function("old_name", 0x100)
        current = {"name": "old_name"}
        function.getName.side_effect = lambda: current["name"]
        function.setName.side_effect = (
            lambda name, source: current.update(name=name)
        )
        ctx = _make_ctx([function])
        ctx.program.startTransaction.return_value = 37
        source = tmp_path / "renames.json"
        source.write_text(json.dumps([
            {"addr": "0x100", "name": "new_name"},
            {"addr": "not-an-address", "name": "invalid_name"},
            {"addr": "0x100", "name": "new_name"},
            {"addr": "0xdead", "name": "missing_name"},
        ]), encoding="utf-8")

        result = set_function_names(ctx, str(source))

        assert result == {
            "operation": "set_function_names",
            "status": "partial_success",
            "atomicity": "per_item",
            "succeeded": 1,
            "unchanged": 1,
            "failed": 2,
            "total": 4,
            "items": [
                {
                    "address": "0x100",
                    "status": "success",
                    "requested_name": "new_name",
                    "old_name": "old_name",
                    "stored_name": "new_name",
                    "error": None,
                },
                {
                    "address": "not-an-address",
                    "status": "validation_failed",
                    "requested_name": "invalid_name",
                    "old_name": None,
                    "stored_name": None,
                    "error": (
                        "invalid literal for int() with base 16: "
                        "'not-an-address'"
                    ),
                },
                {
                    "address": "0x100",
                    "status": "no_change",
                    "requested_name": "new_name",
                    "old_name": "new_name",
                    "stored_name": "new_name",
                    "error": None,
                },
                {
                    "address": "0xdead",
                    "status": "validation_failed",
                    "requested_name": "missing_name",
                    "old_name": None,
                    "stored_name": None,
                    "error": "No function at or containing 0xdead",
                },
            ],
        }
        ctx.program.startTransaction.assert_called_once_with("Rename function")
        ctx.program.endTransaction.assert_called_once_with(37, True)


# ---------------------------------------------------------------------------
# search_memory_bytes
# ---------------------------------------------------------------------------

class TestSearchHex:
    def test_odd_length(self):
        ctx = _make_ctx([])
        result = search_memory_bytes(ctx, "abc")
        assert "ERROR" in result

    def test_invalid_hex(self):
        ctx = _make_ctx([])
        result = search_memory_bytes(ctx, "zzzz")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# decompile_functions (mock decompiler)
# ---------------------------------------------------------------------------

class TestBatchDecompile:
    @mock.patch("ghidramsc._query_inspection._get_monitor")
    @mock.patch("ghidramsc._query_inspection._get_decompiler")
    def test_mixed(self, mock_decomp_factory, mock_monitor):
        f1 = _mock_function("func_a", 0x100)
        ctx = _make_ctx([f1])

        decomp = mock.MagicMock()
        dec_result = mock.MagicMock()
        dec_result.decompileCompleted.return_value = True
        dec_result.getDecompiledFunction.return_value.getC.return_value = "void func_a() {}"
        decomp.decompileFunction.return_value = dec_result
        mock_decomp_factory.return_value = decomp
        mock_monitor.return_value = mock.MagicMock()

        result = decompile_functions(ctx, ["0x100", "0x999"])
        assert "func_a" in result["0x100"]
        assert "ERROR" in result["0x999"]
        decomp.dispose.assert_called_once()

    @mock.patch("ghidramsc._query_inspection._get_monitor")
    @mock.patch("ghidramsc._query_inspection._get_decompiler")
    def test_batch_bounds_large_individual_and_aggregate_output(
            self, mock_decomp_factory, _mock_monitor):
        functions = [_mock_function("f{}".format(i), 0x100 + i)
                     for i in range(6)]
        ctx = _make_ctx(functions)
        decomp = mock.MagicMock()
        result = mock.MagicMock()
        result.decompileCompleted.return_value = True
        result.getDecompiledFunction.return_value.getC.return_value = "x" * 40000
        decomp.decompileFunction.return_value = result
        mock_decomp_factory.return_value = decomp
        addresses = [hex(0x100 + i) for i in range(6)]

        output = decompile_functions(ctx, addresses)

        assert list(output) == addresses
        assert all("BATCH TRUNCATED" in output[addr]
                   or "BATCH OUTPUT OMITTED" in output[addr]
                   for addr in addresses)
        assert sum(len(value) for value in output.values()) < 34000
        assert decomp.decompileFunction.call_count <= 5
        assert "1..16 addresses" in decompile_functions(
            ctx, ["0x100"] * 17)["error"]
