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

"""Stable command-line interface and compatibility entrypoint."""

from __future__ import annotations

import sys
from typing import List, Optional

from . import queries
from . import _cli_execution
from .result_contract import application_result_is_error
from ._cli_commands import *
from ._cli_commands import _cli_function_ranges
from ._cli_parser import (
    build_parser, _positive_java_int, _project_owner,
    _add_common, _add_mutation_save_options,
)
from ._cli_execution import (
    _ExplicitSaveBridge, _ExplicitSaveSession, _resolve_binary,
    _unwrap_server_result, _save_completed, _unavailable_save_result,
    _emit, _open_bridge, _try_server, _emit_server_result,
)

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    if getattr(ns, "save_comment", None) is not None and not getattr(ns, "save", False):
        parser.error("--save-comment requires --save")
    # Resolve binary from -b flag or GHIDRAMSC_BINARY env var.
    # For serve / mcp / shutdown the binary is optional (per-request).
    if hasattr(ns, "binary"):
        is_server_cmd = getattr(ns, "command", "") in ("serve", "mcp", "shutdown")
        ns.binary = _resolve_binary(ns, required=not is_server_cmd)
    try:
        if getattr(ns, "save", False):
            with _cli_execution.active_save_session(ns) as session:
                command_status = ns.func(ns)
                if command_status or application_result_is_error(session.emitted_result):
                    result = session.emitted_result
                    completed = False
                else:
                    result, completed = session.complete()
            _emit(result, ns)
            return command_status if completed else 1
        with _cli_execution.active_result_session() as result_session:
            command_status = ns.func(ns)
        if result_session.has_result and application_result_is_error(result_session.result):
            return 1
        return command_status
    except (ValueError, FileNotFoundError) as exc:
        print("Config error: {}".format(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print("Runtime error: {}".format(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return 1
