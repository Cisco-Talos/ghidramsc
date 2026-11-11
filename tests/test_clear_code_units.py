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

"""Focused contract tests for the explicit listing-clear operation."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from types import ModuleType
from unittest import mock

from ghidramsc import queries
from ghidramsc import _query_annotations


@dataclass(frozen=True)
class Address:
    value: int

    def __str__(self):
        return format(self.value, "x")

    def getAddressSpace(self):
        return "ram"

    def compareTo(self, other):
        return (self.value > other.value) - (self.value < other.value)

    def subtract(self, other):
        return self.value - other.value


@dataclass
class Unit:
    start: int
    length: int
    kind: str
    display: str

    def getMinAddress(self):
        return Address(self.start)

    def getMaxAddress(self):
        return Address(self.start + self.length - 1)

    def getLength(self):
        return self.length

    def isDefined(self):
        return self.kind == "data"

    def __str__(self):
        return self.display


class Iterator:
    def __init__(self, items):
        self.items = iter(items)
        self.next_item = next(self.items, None)

    def hasNext(self):
        return self.next_item is not None

    def next(self):
        item = self.next_item
        self.next_item = next(self.items, None)
        return item


class Listing:
    def __init__(self, units):
        self.units = list(units)
        self.clear_calls = []
        self.fail_after_clear = False
        self.skip_clear = False

    def getCodeUnitContaining(self, address):
        for unit in self.units:
            if unit.start <= address.value < unit.start + unit.length:
                return unit
        return Unit(address.value, 1, "undefined", "??")

    def getCodeUnits(self, address_set, _forward):
        start, end = address_set
        return Iterator([
            unit for unit in self.units
            if unit.start <= end.value
            and unit.start + unit.length - 1 >= start.value
        ])

    def getInstructionAt(self, address):
        return next((
            unit for unit in self.units
            if unit.start == address.value and unit.kind == "instruction"
        ), None)

    def isUndefined(self, start, end):
        return not any(
            unit.start <= end.value
            and unit.start + unit.length - 1 >= start.value
            for unit in self.units
        )

    def clearCodeUnits(self, start, end, clear_context, monitor):
        self.clear_calls.append((start.value, end.value, clear_context, monitor))
        if not self.skip_clear:
            self.units = [
                unit for unit in self.units
                if unit.start > end.value
                or unit.start + unit.length - 1 < start.value
            ]
        if self.fail_after_clear:
            raise ValueError("simulated native failure")


class Block:
    def contains(self, address):
        return 0x1000 <= address.value <= 0x1fff

    def isInitialized(self):
        return True


class Program:
    def __init__(self, listing):
        self.listing = listing
        self.original_units = list(listing.units)
        self.transactions = []

    def getListing(self):
        return self.listing

    def getMemory(self):
        return self

    def getBlock(self, address):
        return Block() if 0x1000 <= address.value <= 0x1fff else None

    def startTransaction(self, description):
        self.transactions.append(("start", description))
        return 7

    def endTransaction(self, transaction_id, commit):
        self.transactions.append(("end", transaction_id, commit))
        if not commit:
            self.listing.units = list(self.original_units)


class Context:
    def __init__(self, units):
        self.program = Program(Listing(units))

    def to_addr(self, value):
        return Address(value)


def _run(ctx, start="0x1000", end="0x1005", preview_only=True):
    address_module = ModuleType("ghidra.program.model.address")
    address_module.AddressSet = lambda first, last: (first, last)
    with (
        mock.patch.dict(sys.modules, {
            "ghidra.program.model.address": address_module,
        }),
        mock.patch.object(
            _query_annotations, "_read_memory_buffer",
            side_effect=lambda _program, _start, length: (b"\x90" * length, length),
        ),
        mock.patch.object(_query_annotations, "_get_monitor", return_value="monitor"),
    ):
        return queries.clear_code_units(ctx, start, end, preview_only)


def test_preview_is_complete_and_does_not_start_transaction():
    ctx = Context([
        Unit(0x1000, 3, "instruction", "mov eax, ebx"),
        Unit(0x1003, 3, "data", "byte[3]"),
    ])

    result = _run(ctx)

    assert result["status"] == "preview"
    assert result["transaction"] == {"started": False, "committed": False}
    assert result["preview"] == result["old"]
    assert result["preview"]["affected_count"] == 2
    assert [item["kind"] for item in result["preview"]["affected_units"]] == [
        "instruction", "data",
    ]
    assert ctx.program.transactions == []
    assert ctx.program.listing.clear_calls == []


def test_apply_clears_exact_units_preserves_bytes_and_commits():
    ctx = Context([Unit(0x1000, 6, "instruction", "mov eax, ebx")])

    result = _run(ctx, preview_only=False)

    assert result["status"] == "success"
    assert result["transaction"]["committed"] is True
    assert result["stored"]["all_undefined"] is True
    assert result["stored"]["affected_count"] == 0
    assert result["stored"]["bytes_preserved"] is True
    assert result["stored"]["byte_count"] == 6
    assert ctx.program.listing.clear_calls == [(0x1000, 0x1005, False, "monitor")]
    assert ctx.program.transactions == [
        ("start", "Clear code units"), ("end", 7, True),
    ]


def test_partial_endpoint_is_rejected_before_mutation():
    ctx = Context([Unit(0x1000, 6, "instruction", "mov eax, ebx")])

    result = _run(ctx, start="0x1001", preview_only=False)

    assert result["status"] == "validation_failed"
    assert "Start lies inside" in result["error"]
    assert ctx.program.transactions == []
    assert ctx.program.listing.clear_calls == []


def test_native_failure_rolls_back_and_reads_original_listing():
    ctx = Context([Unit(0x1000, 6, "instruction", "mov eax, ebx")])
    ctx.program.listing.fail_after_clear = True

    result = _run(ctx, preview_only=False)

    assert result["status"] == "rolled_back"
    assert result["transaction"]["committed"] is False
    assert result["stored"]["affected_units"] == result["old"]["affected_units"]
    assert ctx.program.transactions[-1] == ("end", 7, False)


def test_readback_rejects_native_noop_and_rolls_back():
    ctx = Context([Unit(0x1000, 6, "instruction", "mov eax, ebx")])
    ctx.program.listing.skip_clear = True

    result = _run(ctx, preview_only=False)

    assert result["status"] == "rolled_back"
    assert "found defined" in result["error"]
    assert ctx.program.transactions[-1] == ("end", 7, False)


def test_preview_rejects_more_than_128_defined_units_without_truncation():
    ctx = Context([
        Unit(0x1000 + index, 1, "data", "db")
        for index in range(129)
    ])

    result = _run(ctx, end="0x1080")

    assert result["status"] == "validation_failed"
    assert "more than 128" in result["error"]
    assert ctx.program.transactions == []


def test_range_must_stay_in_one_initialized_block():
    ctx = Context([Unit(0x1fff, 1, "data", "db")])

    result = _run(ctx, start="0x1fff", end="0x2000", preview_only=False)

    assert result["status"] == "validation_failed"
    assert "one initialized memory block" in result["error"]
    assert ctx.program.transactions == []
