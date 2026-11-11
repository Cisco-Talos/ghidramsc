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

"""Architectural checks for the stable :mod:`ghidramsc.queries` facade."""

from __future__ import annotations

import importlib
import inspect


PRIVATE_MODULES = (
    "_query_core",
    "_query_inspection",
    "_query_program",
    "_query_composites",
    "_query_variables",
    "_query_functions",
    "_query_annotations",
    "_query_data",
    "_query_analysis",
)


def test_private_implementation_symbols_are_partitioned_through_facade():
    from ghidramsc import queries

    owners = {}
    for module_name in PRIVATE_MODULES:
        module = importlib.import_module("ghidramsc.{}".format(module_name))
        for name in module.__all__:
            assert name not in owners, (
                "Implementation symbol {!r} is owned by both {} and {}".format(
                    name, owners.get(name), module_name
                )
            )
            owners[name] = module_name
            assert getattr(queries, name) is getattr(module, name)


def test_facade_public_functions_keep_historical_module_identity():
    from ghidramsc import queries
    from ghidramsc.tool_registry import TOOL_DEFINITIONS

    expected = {
        entry["name"]
        for entry in TOOL_DEFINITIONS
        if entry["name"] != "list_programs"
    }
    actual = {
        name
        for name, value in inspect.getmembers(queries, inspect.isfunction)
        if not name.startswith("_")
    }

    assert actual == expected
    assert all(getattr(queries, name).__module__ == queries.__name__ for name in expected)
