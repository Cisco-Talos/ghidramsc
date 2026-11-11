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

"""Shared fixtures for GhidraMSC tests.

Stubs out ``ghidra.*`` Java package imports so that queries.py functions
can do ``from ghidra.xxx import Yyy`` without a running JVM.  The actual
behaviour of those Java classes is tested via mocks in each test.
"""

from __future__ import annotations

import sys
from unittest import mock

import pytest

# List of ghidra.* module paths that queries.py imports at function scope.
_GHIDRA_MODULES = [
    "ghidra",
    "ghidra.app",
    "ghidra.app.decompiler",
    "ghidra.app.util",
    "ghidra.app.util.cparser",
    "ghidra.program",
    "ghidra.program.flatapi",
    "ghidra.program.model",
    "ghidra.program.model.address",
    "ghidra.program.model.block",
    "ghidra.program.model.data",
    "ghidra.program.model.listing",
    "ghidra.program.model.pcode",
    "ghidra.program.model.symbol",
    "ghidra.util",
    "ghidra.util.task",
]


@pytest.fixture(autouse=True)
def _mock_ghidra_imports():
    """Inject mock modules for every ghidra.* path so that ``from
    ghidra.x.y import Z`` never triggers a real import.

    Uses ``unittest.mock.patch.dict`` on ``sys.modules`` so that the
    original state is restored after each test.
    """
    mocks = {}
    for mod_path in _GHIDRA_MODULES:
        if mod_path not in sys.modules:
            mocks[mod_path] = mock.MagicMock()

    with mock.patch.dict(sys.modules, mocks):
        yield
