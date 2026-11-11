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

"""Shared application-outcome interpretation for HTTP and MCP transports."""

from __future__ import annotations

from typing import Any, Dict, Mapping


_FAILURE_STATUSES = {
    "failed",
    "rolled_back",
    "unsupported",
    "validation_failed",
}


def validation_failure(
    operation: str, arguments: Any, error: str
) -> Dict[str, Any]:
    """Build the canonical pre-dispatch validation failure payload."""
    requested = {}
    if isinstance(arguments, Mapping):
        requested = {
            name: value for name, value in arguments.items()
            if name != "binary"
        }
    return {
        "operation": operation,
        "status": "validation_failed",
        "requested": requested,
        "error": error,
    }


def application_outcome(result: Any) -> str:
    """Classify a returned tool value without changing its payload.

    Returns ``success``, ``no_change``, ``partial_success``, or ``failure``.
    Transport/protocol exceptions are handled by their transports and are not
    application result values.
    """
    if isinstance(result, dict):
        status = result.get("status")
        if status == "no_change":
            return "no_change"
        if status == "partial_success":
            return "partial_success"
        if status in _FAILURE_STATUSES:
            return "failure"
        if status == "success":
            return "success"
        if result.get("error") not in (None, ""):
            return "failure"
        save = result.get("save")
        if isinstance(save, dict) and save.get("completed") is False:
            return "failure"
    elif isinstance(result, str) and result.startswith("ERROR:"):
        return "failure"
    return "success"


def application_result_is_error(result: Any) -> bool:
    """Return whether a completed tool result represents an application error."""
    return application_outcome(result) in {"failure", "partial_success"}
