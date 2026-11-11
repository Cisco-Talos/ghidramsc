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

"""CLI transport, direct-project, output, and explicit-save lifecycle."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .bridge import GhidraBridge
from .config import load_config
from . import queries

_DEFAULT_SAVE_COMMENT = "Saved by GhidraMSC"
_ACTIVE_SAVE_SESSION = None
_ACTIVE_RESULT_SESSION = None


class _ResultSession:
    def __init__(self) -> None:
        self.result: Any = None
        self.has_result = False

    def capture(self, result: Any) -> None:
        self.result = result
        self.has_result = True


@contextlib.contextmanager
def active_result_session():
    """Observe the command payload without changing its output."""
    global _ACTIVE_RESULT_SESSION
    previous = _ACTIVE_RESULT_SESSION
    session = _ResultSession()
    _ACTIVE_RESULT_SESSION = session
    try:
        yield session
    finally:
        _ACTIVE_RESULT_SESSION = previous


def _resolve_binary(ns: argparse.Namespace, required: bool = True) -> str:
    """Return the binary name from -b flag or GHIDRAMSC_BINARY env var.

    When *required* is True (default, used by query subcommands),
    exit with an error if no binary can be determined.  When False
    (serve / mcp), return None -- the binary can be specified per
    request instead.
    """
    import os
    name = getattr(ns, "binary", None) or os.environ.get("GHIDRAMSC_BINARY")
    if not name and required:
        print("ERROR: No binary specified.  Use -b <name> or set "
              "GHIDRAMSC_BINARY env var.", file=sys.stderr)
        sys.exit(1)
    return name


def _unwrap_server_result(raw: Any) -> Any:
    if isinstance(raw, dict) and list(raw.keys()) == ["result"]:
        return raw["result"]
    return raw


def _save_completed(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and isinstance(result.get("save"), dict)
        and result["save"].get("completed") is True
    )


def _unavailable_save_result(binary: str, comment: str, error: str) -> Dict[str, Any]:
    state = {
        "program": binary,
        "dirty": None,
        "can_save": None,
    }
    return {
        "operation": "save_program",
        "status": "failed",
        "program": binary,
        "old": dict(state),
        "requested": {"comment": comment},
        "stored": dict(state),
        "save": {
            "attempted": False,
            "completed": False,
            "succeeded": False,
            "backend": "http_service_unavailable",
            "completion_observed": False,
            "comment_supported": False,
            "comment_applied": False,
        },
        "error": error,
    }


class _ExplicitSaveBridge:
    """Keep a direct command's project/context alive through its save."""

    def __init__(self, bridge: GhidraBridge, session: "_ExplicitSaveSession") -> None:
        self._bridge = bridge
        self._session = session

    @contextlib.contextmanager
    def open_program(self, program_name: str, analyze: bool = False):
        ctx = self._session.open_direct_program(
            self._bridge, program_name, analyze=analyze)
        yield ctx


class _ExplicitSaveSession:
    """Coordinate one CLI mutation and its requested persistence result."""

    def __init__(self, ns: argparse.Namespace) -> None:
        self.ns = ns
        self.server_selected = False
        self.emitted_result: Any = None
        self._has_result = False
        self._project_cm = None
        self._project = None
        self._ctx = None

    def capture(self, result: Any) -> None:
        self.emitted_result = result
        self._has_result = True

    def open_bridge(self, bridge: GhidraBridge) -> _ExplicitSaveBridge:
        return _ExplicitSaveBridge(bridge, self)

    def open_direct_program(
        self, bridge: GhidraBridge, program_name: str, analyze: bool = False
    ):
        if self._project is None:
            self._project_cm = bridge.open_project()
            self._project = self._project_cm.__enter__()
        ctx = self._project.get_program(program_name)
        if analyze:
            from .bridge import _analyze_program
            _analyze_program(ctx)
        if self._ctx is not None and self._ctx is not ctx:
            raise RuntimeError("Explicit CLI save must use one selected program")
        self._ctx = ctx
        return ctx

    def complete(self) -> tuple[Any, bool]:
        if not self._has_result:
            raise RuntimeError("Mutation command produced no result to persist")
        comment = self.ns.save_comment or _DEFAULT_SAVE_COMMENT
        if self.server_selected:
            from . import client
            try:
                raw = client.send_query(
                    "save_program", {"comment": comment}, binary=self.ns.binary)
                if raw is None:
                    persistence = _unavailable_save_result(
                        self.ns.binary, comment,
                        "Requested save was not completed: HTTP service unavailable",
                    )
                else:
                    persistence = _unwrap_server_result(raw)
            except client.ServerQueryError as exc:
                persistence = exc.payload
        else:
            if self._ctx is None:
                raise RuntimeError("Mutation did not open the selected program")
            persistence = queries.save_program(self._ctx, comment)

        if isinstance(self.emitted_result, dict):
            result = dict(self.emitted_result)
        else:
            result = {"result": self.emitted_result}
        result["persistence"] = persistence
        return result, _save_completed(persistence)

    def close(self) -> None:
        if self._project_cm is not None:
            self._project_cm.__exit__(None, None, None)
            self._project_cm = None
            self._project = None
            self._ctx = None


@contextlib.contextmanager
def active_save_session(ns: argparse.Namespace):
    """Keep one direct project open until the mutation and save both finish."""
    global _ACTIVE_SAVE_SESSION
    session = _ExplicitSaveSession(ns)
    _ACTIVE_SAVE_SESSION = session
    try:
        yield session
    finally:
        try:
            session.close()
        finally:
            _ACTIVE_SAVE_SESSION = None


def _emit(result: Any, ns: argparse.Namespace) -> None:
    """Print and/or write the query result."""
    if _ACTIVE_RESULT_SESSION is not None:
        _ACTIVE_RESULT_SESSION.capture(result)
    if _ACTIVE_SAVE_SESSION is not None:
        _ACTIVE_SAVE_SESSION.capture(result)
        return
    if isinstance(result, dict):
        text = json.dumps(result, indent=2, default=str)
    else:
        text = str(result)

    if not ns.quiet:
        print(text)

    if ns.output:
        out_path = Path(ns.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")


def _open_bridge(ns: argparse.Namespace):
    """Load config and return (bridge, config)."""
    cfg = load_config(getattr(ns, "config", None))
    owner = getattr(ns, "owner", None)
    bridge = (
        GhidraBridge(cfg, owner=owner)
        if owner is not None
        else GhidraBridge(cfg)
    )
    if _ACTIVE_SAVE_SESSION is not None:
        bridge = _ACTIVE_SAVE_SESSION.open_bridge(bridge)
    return bridge, cfg


def _try_server(command: str, args: Dict[str, Any], ns: argparse.Namespace) -> Optional[Any]:
    """Attempt to forward *command* to a running server.

    Returns the deserialised result, or ``None`` if no server is
    reachable (caller should fall back to direct JVM).

    The ``-b`` / ``--binary`` flag is forwarded as a per-request binary
    override so the server queries the correct program.
    """
    if (
        getattr(ns, "no_server", False)
        or getattr(ns, "owner", None) is not None
    ):
        return None
    from . import client
    binary = getattr(ns, "binary", None)
    result = client.send_query(command, args, binary=binary)
    if result is not None and _ACTIVE_SAVE_SESSION is not None:
        _ACTIVE_SAVE_SESSION.server_selected = True
    return result


def _emit_server_result(raw: Any, ns: argparse.Namespace) -> None:
    """Unwrap the HTTP scalar envelope before emitting a command result."""
    _emit(_unwrap_server_result(raw), ns)
