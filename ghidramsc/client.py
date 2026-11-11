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

"""Thin HTTP client for the GhidraMSC server.

If a server is running on localhost, queries are forwarded to it instead
of cold-starting a JVM.  An unavailable server before a query returns
``None`` so the caller can use the direct (in-process) path.  A lost query
response raises instead: the server may already have run the command.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from .server import _PORT_FILE_NAME


class ServerQueryError(RuntimeError):
    """HTTP query failure retaining the server's decoded JSON body."""

    def __init__(self, message: str, payload: Dict[str, Any]) -> None:
        super().__init__(message)
        self.payload = payload


class ServerResponseUnavailable(RuntimeError):
    """A query may have run, but no usable HTTP response was received."""


def _discover_port() -> Optional[int]:
    """Try to read the port from the CWD port-file.  Returns ``None``
    if the file does not exist or is unreadable."""
    pf = Path.cwd() / _PORT_FILE_NAME
    if not pf.is_file():
        return None
    try:
        return int(pf.read_text(encoding="ascii").strip())
    except (ValueError, OSError):
        return None


def _base_url(port: int) -> str:
    return "http://127.0.0.1:{}".format(port)


def server_health(port: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Return the server's ``/health`` payload, or ``None`` if unreachable."""
    if port is None:
        port = _discover_port()
    if port is None:
        return None
    url = _base_url(port) + "/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def send_query(
    command: str,
    args: Dict[str, Any],
    port: Optional[int] = None,
    binary: Optional[str] = None,
) -> Optional[Any]:
    """Send a query to the running server.

    Returns the deserialised JSON response body on success, or ``None``
    if the server is unavailable before the query (so the caller can fall
    back).  Once the query is attempted, a missing or unusable response
    raises ServerResponseUnavailable because its outcome is unknown.

    Parameters
    ----------
    binary : str or None
        If given, sent as top-level ``"binary"`` field so the server
        queries the correct program (per-request override).

    Raises ``RuntimeError`` if the server returns an error payload.
    """
    if port is None:
        port = _discover_port()
    if port is None:
        return None

    # Quick health-check first so we don't confuse a stale port-file
    # with a live server.
    health = server_health(port)
    if health is None:
        return None

    url = _base_url(port) + "/query"
    body_dict: Dict[str, Any] = {"command": command, "args": args}
    if binary:
        body_dict["binary"] = binary
    payload = json.dumps(body_dict).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    unknown_response = (
        "No usable HTTP response for '{}'; outcome unknown. "
        "Inspect current state before retrying.".format(command)
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # The server returned an HTTP error status.
        try:
            err_body = json.loads(exc.read().decode("utf-8"))
            if not isinstance(err_body, dict):
                err_body = {"error": str(err_body)}
            msg = err_body.get("error", str(exc))
        except Exception:
            err_body = {"error": str(exc)}
            msg = str(exc)
        raise ServerQueryError(
            "Server error: {}".format(msg), err_body) from exc
    except (urllib.error.URLError, OSError, http.client.IncompleteRead,
            UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServerResponseUnavailable(unknown_response) from exc

    if not isinstance(body, dict):
        raise ServerResponseUnavailable(unknown_response)
    if "error" in body:
        raise ServerQueryError(
            "Server error: {}".format(body["error"]), body)
    return body


def shutdown_server(port: Optional[int] = None) -> bool:
    """Ask the server to shut down.  Returns True on success."""
    if port is None:
        port = _discover_port()
    if port is None:
        return False
    url = _base_url(port) + "/shutdown"
    req = urllib.request.Request(
        url,
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False
