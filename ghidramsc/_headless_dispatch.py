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

"""Shared Python query invocation for HTTP and headless MCP transports."""

from __future__ import annotations

import inspect
import time
from typing import Any, Callable, Dict, Optional

from . import queries


def build_dispatch_table() -> Dict[str, Any]:
    """Expose public query-facade functions to a transport-local table."""
    return {
        name: obj
        for name, obj in inspect.getmembers(queries, inspect.isfunction)
        if not name.startswith("_")
    }


def invoke_query(
    project: Any,
    name: str,
    args: Dict[str, Any],
    binary: str,
    dispatch: Dict[str, Any],
    unknown_message: str,
    phase_timer: Optional[Callable[[str, int], None]] = None,
) -> Any:
    """Open the selected program, then bind declared facade parameters."""
    if phase_timer is None:
        ctx = project.get_program(binary)
    else:
        started = time.perf_counter_ns()
        try:
            ctx = project.get_program(binary)
        finally:
            phase_timer("program_acquisition", time.perf_counter_ns() - started)
    func = dispatch.get(name)
    if func is None:
        raise ValueError(unknown_message.format(name))
    if phase_timer is None:
        params = list(inspect.signature(func).parameters)[1:]
        kwargs = {param: args[param] for param in params if param in args}
        return func(ctx, **kwargs)
    started = time.perf_counter_ns()
    try:
        params = list(inspect.signature(func).parameters)[1:]
        kwargs = {param: args[param] for param in params if param in args}
        return func(ctx, **kwargs)
    finally:
        phase_timer("query", time.perf_counter_ns() - started)
