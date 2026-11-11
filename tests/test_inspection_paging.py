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

"""Finite inspection pages, including value reconstruction and end state."""

from unittest import mock

import pytest

from ghidramsc._query_inspection import get_data_at_address, get_function_info
from ghidramsc._query_paging import page_items, validate_page
from ghidramsc._query_annotations import _COMMENT_TYPES


def test_comment_type_ids_match_ghidra_listing_order():
    assert _COMMENT_TYPES == {
        "eol": 0, "pre": 1, "post": 2, "plate": 3, "repeatable": 4,
    }


def test_page_metadata_keeps_complete_total_at_and_past_end():
    items = list(range(7))
    first, page = page_items(items, 0, 3)
    assert first == [0, 1, 2]
    assert page == {"offset": 0, "limit": 3, "returned": 3,
                    "total": 7, "has_more": True, "next_offset": 3}
    end, page = page_items(items, 7, 3)
    assert end == []
    assert page == {"offset": 7, "limit": 3, "returned": 0,
                    "total": 7, "has_more": False, "next_offset": None}
    for offset, limit in ((-1, 2), (0, 0), (0, 501)):
        with pytest.raises(ValueError):
            validate_page(offset, limit)


def test_data_value_pages_reconstruct_unicode_representation():
    ctx = mock.MagicMock()
    addr = mock.MagicMock()
    addr.__str__.return_value = "0x1000"
    addr.subtract.return_value = 0
    ctx.to_addr.return_value = addr
    data = mock.MagicMock()
    data.getAddress.return_value = addr
    data.getMaxAddress.return_value = addr
    data.getPrimarySymbol.return_value = None
    data.getDataType.return_value.getName.return_value = "string"
    data.getLength.return_value = 6000
    value = "A😀B" * 2000
    data.getDefaultValueRepresentation.return_value = value
    ctx.program.getListing.return_value.getDefinedDataAt.return_value = data
    ctx.program.getSymbolTable.return_value.getSymbols.return_value = []
    ctx.program.getSymbolTable.return_value.getPrimarySymbol.return_value = None

    pages = []
    offset = 0
    while True:
        result = get_data_at_address(ctx, "0x1000", offset, 2048)
        assert result["value_total_chars"] == len(value)
        assert result["value_returned_chars"] <= 2048
        pages.append(result["value"])
        if not result["value_has_more"]:
            break
        offset = result["value_next_offset"]
    assert "".join(pages) == value
    end = get_data_at_address(ctx, "0x1000", len(value), 2048)
    assert end["value"] == ""
    assert end["value_next_offset"] is None
    assert get_data_at_address(ctx, "0x1000", 0, 8193).startswith("ERROR:")


def test_function_evidence_arrays_have_independent_complete_totals():
    from tests.test_queries import _make_ctx, _mock_function

    func = _mock_function("target", 0x400)
    func.getThunkedFunction.return_value = None
    func.getCallingFunctions.return_value = [
        _mock_function("caller{}".format(index), 0x1000 + index)
        for index in range(125)
    ]
    ctx = _make_ctx([func])
    evidence = {
        "call_sites": [{"address": str(index)} for index in range(150)],
        "callees": [], "possible_callees": [], "unresolved_calls": [],
        "scan_complete": True,
    }
    with mock.patch("ghidramsc._query_analysis._call_evidence",
                    return_value=evidence) as classify:
        result = get_function_info(ctx, "0x400", evidence_offset=100,
                                   evidence_limit=50)
    classify.assert_called_once_with(ctx, func, max_sites=0)
    assert len(result["call_sites"]) == 50
    assert result["evidence_pagination"]["call_sites"] == {
        "offset": 100, "limit": 50, "returned": 50, "total": 150,
        "has_more": False, "next_offset": None,
    }
    assert len(result["called_by"]) == 25
    assert result["evidence_pagination"]["called_by"]["total"] == 125
    assert result["evidence_pagination"]["calls"]["total"] == 0
    assert result["call_scan_complete"] is True
