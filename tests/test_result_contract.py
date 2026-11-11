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

"""Focused tests for shared HTTP/MCP application-outcome classification."""

from __future__ import annotations

import pytest


@pytest.mark.parametrize(
    ("result", "outcome", "is_error"),
    [
        ({"operation": "x", "status": "success"}, "success", False),
        ({"operation": "x", "status": "no_change"}, "no_change", False),
        (
            {"operation": "x", "status": "partial_success"},
            "partial_success", True,
        ),
        ({"operation": "x", "status": "validation_failed"}, "failure", True),
        ({"operation": "x", "status": "rolled_back"}, "failure", True),
        ({"operation": "x", "status": "unsupported"}, "failure", True),
        ({"error": "not found"}, "failure", True),
        ("ERROR: not found", "failure", True),
        ({"items": []}, "success", False),
        ("ordinary text", "success", False),
    ],
)
def test_application_outcome(result, outcome, is_error):
    from ghidramsc.result_contract import (
        application_outcome,
        application_result_is_error,
    )

    assert application_outcome(result) == outcome
    assert application_result_is_error(result) is is_error


def test_validation_failure_uses_public_arguments_only():
    from ghidramsc.result_contract import validation_failure

    assert validation_failure(
        "decompile_function", {"binary": "sample.bin", "addr_hex": 4096}, "wrong type"
    ) == {
        "operation": "decompile_function",
        "status": "validation_failed",
        "requested": {"addr_hex": 4096},
        "error": "wrong type",
    }


def test_validation_failure_handles_non_object_arguments():
    from ghidramsc.result_contract import validation_failure

    assert validation_failure("decompile_function", [], "args must be a JSON object") == {
        "operation": "decompile_function",
        "status": "validation_failed",
        "requested": {},
        "error": "args must be a JSON object",
    }
