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

"""Tests for ghidramsc.server and ghidramsc.client.

These test the server HTTP protocol, dispatch table, client discovery,
and the CLI serve/shutdown arg wiring -- all without a real JVM.
"""

from __future__ import annotations

import json
import http.client
import socket
import sys
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest


# -------------------------------------------------------------------
# server unit tests (dispatch table, handler, port file)
# -------------------------------------------------------------------

class TestDispatchTable:
    """Verify _build_dispatch_table picks up public functions from queries."""

    def test_includes_decompile(self):
        from ghidramsc.server import _DISPATCH
        assert "decompile_function" in _DISPATCH

    def test_includes_list_functions(self):
        from ghidramsc.server import _DISPATCH
        assert "list_functions" in _DISPATCH

    def test_excludes_private(self):
        from ghidramsc.server import _DISPATCH
        for name in _DISPATCH:
            assert not name.startswith("_")

    def test_has_all_25(self):
        from ghidramsc.server import _DISPATCH
        expected = {
            "list_functions", "decompile_function", "list_references_to_address", "list_references_from_address",
            "get_listing_at_address", "get_function_info", "list_strings", "search_memory_text", "search_memory_bytes",
            "search_functions_by_name", "set_function_name", "set_function_names", "create_function",
            "delete_function", "set_function_body", "create_functions",
            "disassemble_memory", "export_annotations",
            "import_annotations", "fix_region", "list_function_variables", "set_variable_name",
            "set_variable_type", "set_function_return_type", "apply_function_annotations",
            "decompile_functions",
            # New tools
            "get_program_info", "get_program_memory_map", "list_program_imports",
            "list_program_exports", "list_program_namespaces", "list_program_classes",
            "list_data_items", "list_memory_blocks", "set_comment_at_address", "get_comment_at_address",
            "create_bookmark", "delete_bookmark", "list_bookmarks",
            "list_structures", "get_structure", "create_structure",
            "set_structure_name", "delete_structure", "get_function_call_graph",
            "list_function_basic_blocks", "get_function_call_relationships", "write_memory_bytes",
            "set_function_prototype", "set_function_calling_convention",
            "set_data_label", "apply_data_type", "detect_security_mitigations",
            "find_format_string_vulns", "set_program_image_base",
            "set_memory_block_permissions",
            "identify_user_input_sources", "identify_crypto_patterns",
            "find_obfuscated_strings",
        }
        assert expected.issubset(set(_DISPATCH.keys()))


class TestInvoke:
    """Test _invoke dispatches to the right function with correct args."""

    def _make_project(self):
        """Return a mock ProjectHandle."""
        ctx = mock.MagicMock()
        proj = mock.MagicMock()
        proj.get_program.return_value = ctx
        return proj, ctx

    def test_unknown_command(self):
        from ghidramsc.server import _invoke
        proj, _ = self._make_project()
        with pytest.raises(ValueError, match="Unknown command"):
            _invoke(proj, "no_such_command", {}, "test.so")

    @pytest.mark.parametrize(
        "command",
        [
            "detect_security_mitigations",
            "find_format_string_vulns",
            "identify_user_input_sources",
            "identify_crypto_patterns",
            "find_obfuscated_strings",
            "fix_region",
        ],
    )
    def test_disabled_command(self, command):
        from ghidramsc.server import _invoke
        proj, _ = self._make_project()
        with pytest.raises(ValueError, match="Unknown command"):
            _invoke(proj, command, {}, "test.so")

    def test_known_command_called(self):
        from ghidramsc.server import _invoke, _DISPATCH
        proj, ctx = self._make_project()
        with mock.patch.dict(_DISPATCH, {"list_functions": mock.MagicMock(return_value="ok")}):
            result = _invoke(proj, "list_functions", {}, "test.so")
        assert result == "ok"

    def test_args_passed(self):
        from ghidramsc.server import _invoke, _DISPATCH
        proj, ctx = self._make_project()
        # Give the spy a real signature so _invoke sees addr_hex as a param.
        def _fake_decompile(ctx, addr_hex=""):
            pass
        spy = mock.MagicMock(side_effect=_fake_decompile, return_value="decompiled")
        spy.__signature__ = __import__("inspect").signature(_fake_decompile)
        with mock.patch.dict(_DISPATCH, {"decompile_function": spy}):
            _invoke(proj, "decompile_function", {"addr_hex": "0x1234"}, "test.so")
        spy.assert_called_once_with(ctx, addr_hex="0x1234")

    def test_create_structure_category_path_is_forwarded(self):
        from ghidramsc.server import _invoke, _DISPATCH

        proj, ctx = self._make_project()

        def _fake_create(ctx, name, size=0, category_path="/"):
            return category_path

        spy = mock.MagicMock(
            side_effect=_fake_create, return_value="/analysis/types"
        )
        spy.__signature__ = __import__("inspect").signature(_fake_create)
        with mock.patch.dict(_DISPATCH, {"create_structure": spy}):
            result = _invoke(proj, "create_structure", {
                "name": "Packet", "size": 8,
                "category_path": "/analysis/types",
            }, "sample.bin")
        assert result == "/analysis/types"
        spy.assert_called_once_with(
            ctx, name="Packet", size=8,
            category_path="/analysis/types",
        )

    def test_extra_args_ignored(self):
        """Extra keys not in the function signature are dropped."""
        from ghidramsc.server import _invoke, _DISPATCH
        proj, ctx = self._make_project()
        spy = mock.MagicMock(return_value="ok")
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            _invoke(proj, "list_functions", {"bogus_param": 42}, "test.so")
        spy.assert_called_once_with(ctx)

    def test_per_request_binary_override(self):
        """Binary in args overrides the default."""
        from ghidramsc.server import _invoke, _DISPATCH
        proj, ctx = self._make_project()
        spy = mock.MagicMock(return_value="ok")
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            _invoke(proj, "list_functions", {"binary": "other.so"}, "test.so")
        proj.get_program.assert_called_with("other.so")

    def test_no_binary_errors(self):
        """No binary anywhere raises ValueError."""
        from ghidramsc.server import _invoke, _DISPATCH
        proj, _ = self._make_project()
        spy = mock.MagicMock(return_value="ok")
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            with pytest.raises(ValueError, match="No binary"):
                _invoke(proj, "list_functions", {}, None)


class TestPortFile:
    """Test port-file creation and removal."""

    def test_write_and_remove(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from ghidramsc.server import _write_port_file, _remove_port_file, _port_file_path
        pf = _write_port_file(9999)
        assert pf.exists()
        assert pf.read_text(encoding="ascii") == "9999"
        _remove_port_file()
        assert not _port_file_path().exists()

    def test_remove_missing_is_noop(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from ghidramsc.server import _remove_port_file
        _remove_port_file()  # should not raise


# -------------------------------------------------------------------
# Handler integration test (real HTTP on loopback)
# -------------------------------------------------------------------

class TestHandlerIntegration:
    """Spin up a real _Handler on localhost to test the HTTP protocol."""

    @pytest.fixture()
    def live_server(self):
        """Start a real HTTP server with a mock ProjectHandle."""
        from ghidramsc.server import _Handler, _DISPATCH

        ctx = mock.MagicMock()
        project = mock.MagicMock()
        project.get_program.return_value = ctx
        project._programs = {"test.so": ctx}
        project.list_programs.return_value = ["test.so", "other.so"]

        shutdown_event = threading.Event()
        _Handler.project = project
        _Handler.default_binary = "test.so"
        _Handler.shutdown_event = shutdown_event

        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        yield port, project, ctx, shutdown_event
        httpd.shutdown()
        httpd.server_close()

    def _get(self, port, path):
        import urllib.request
        url = "http://127.0.0.1:{}/{}".format(port, path.lstrip("/"))
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def _post(self, port, path, body):
        import urllib.request
        url = "http://127.0.0.1:{}/{}".format(port, path.lstrip("/"))
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_health(self, live_server):
        port, project, ctx, shutdown_event = live_server
        status, body = self._get(port, "/health")
        assert status == 200
        assert body["status"] == "ok"
        assert body["default_binary"] == "test.so"
        assert "test.so" in body["cached"]

    def test_programs(self, live_server):
        port, project, ctx, shutdown_event = live_server
        status, body = self._get(port, "/programs")
        assert status == 200
        assert "test.so" in body["programs"]
        assert "other.so" in body["programs"]

    def test_query_success(self, live_server):
        port, project, ctx, shutdown_event = live_server
        from ghidramsc.server import _DISPATCH
        spy = mock.MagicMock(return_value={"functions": ["main"]})
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            status, body = self._post(port, "/query", {
                "command": "list_functions",
                "args": {},
            })
        assert status == 200
        assert body == {"functions": ["main"]}

    @pytest.mark.parametrize(
        ("result_status", "old", "stored", "error", "http_status"),
        [
            (
                "success",
                {"address": "00000100", "name": "old_name"},
                {"address": "00000100", "name": "new_name"},
                None, 200,
            ),
            (
                "no_change",
                {"address": "00000100", "name": "new_name"},
                {"address": "00000100", "name": "new_name"},
                None, 200,
            ),
            (
                "validation_failed", None, None,
                "No function at or containing 0x100", 422,
            ),
        ],
    )
    def test_rename_returns_shared_contract_unchanged(
        self, live_server, result_status, old, stored, error, http_status
    ):
        import urllib.error

        port, project, ctx, shutdown_event = live_server
        from ghidramsc.server import _DISPATCH

        contract = {
            "operation": "set_function_name",
            "status": result_status,
            "requested": {"address": "0x100", "name": "new_name"},
            "old": old,
            "stored": stored,
            "error": error,
        }
        with mock.patch.dict(
            _DISPATCH, {"set_function_name": mock.MagicMock(return_value=contract)}
        ):
            try:
                status, body = self._post(port, "/query", {
                    "command": "set_function_name",
                    "args": {"addr_hex": "0x100", "new_name": "new_name"},
                })
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = json.loads(exc.read().decode("utf-8"))

        assert status == http_status
        assert body == contract

    def test_list_programs_executes_through_query_without_binary(
        self, live_server
    ):
        port, project, ctx, shutdown_event = live_server

        status, body = self._post(port, "/query", {
            "command": "list_programs", "args": {},
        })

        assert status == 200
        assert body == {"programs": ["test.so", "other.so"]}
        project.get_program.assert_not_called()

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("get_cursor_address", {}),
            ("get_function_at_cursor", {}),
            ("get_gui_selection", {}),
            ("set_cursor_address", {"addr_hex": "0x1000"}),
            ("undo_gui_transaction", {}),
        ],
    )
    def test_gui_only_tools_are_rejected_before_project_access(
        self, live_server, command, args
    ):
        port, project, ctx, shutdown_event = live_server
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            self._post(port, "/query", {"command": command, "args": args})

        assert exc_info.value.code == 400
        assert "unavailable through HTTP" in exc_info.value.read().decode()
        project.get_program.assert_not_called()

    def test_list_programs_rejects_binary_selector(self, live_server):
        port, project, ctx, shutdown_event = live_server
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            self._post(port, "/query", {
                "command": "list_programs", "args": {}, "binary": "test.so",
            })

        assert exc_info.value.code == 400
        project.get_program.assert_not_called()

    def test_query_string_result(self, live_server):
        """String results are wrapped in {\"result\": ...}."""
        port, project, ctx, shutdown_event = live_server
        from ghidramsc.server import _DISPATCH
        spy = mock.MagicMock(return_value="sometext")
        with mock.patch.dict(_DISPATCH, {"decompile_function": spy}):
            status, body = self._post(port, "/query", {
                "command": "decompile_function",
                "args": {"addr_hex": "0x1"},
            })
        assert status == 200
        assert body == {"result": "sometext"}

    def test_query_per_request_binary(self, live_server):
        """Binary override in /query request."""
        port, project, ctx, shutdown_event = live_server
        from ghidramsc.server import _DISPATCH
        spy = mock.MagicMock(return_value="ok")
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            status, body = self._post(port, "/query", {
                "command": "list_functions",
                "args": {},
                "binary": "other.so",
            })
        assert status == 200
        project.get_program.assert_called_with("other.so")

    def test_query_unknown_command(self, live_server):
        """Unknown commands are rejected before dispatch."""
        port, project, ctx, shutdown_event = live_server
        import urllib.error
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            self._post(port, "/query", {"command": "nope", "args": {}})
        assert exc_info.value.code == 400

    @pytest.mark.parametrize(
        "command",
        [
            "detect_security_mitigations",
            "find_format_string_vulns",
            "identify_user_input_sources",
            "identify_crypto_patterns",
            "find_obfuscated_strings",
            "fix_region",
        ],
    )
    def test_query_disabled_command(self, live_server, command):
        """Disabled implementations are unavailable through HTTP."""
        port, project, ctx, shutdown_event = live_server
        import urllib.error
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            self._post(port, "/query", {"command": command, "args": {}})
        assert exc_info.value.code == 400

    def test_cross_origin_query_is_rejected_before_dispatch(self, live_server):
        port, project, ctx, shutdown_event = live_server
        import urllib.error
        import urllib.request
        from ghidramsc.server import _DISPATCH
        spy = mock.MagicMock(return_value="should not run")
        data = json.dumps({"command": "list_functions", "args": {}}).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:{}/query".format(port),
            data=data,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://attacker.example",
            },
            method="POST",
        )
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 403
        spy.assert_not_called()

    def test_simple_browser_content_type_is_rejected(self, live_server):
        port, project, ctx, shutdown_event = live_server
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:{}/query".format(port),
            data=b"command=list_functions",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 415

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("decompile_function", []),
            ("decompile_function", {}),
            ("decompile_function", {"addr_hex": 4096}),
            ("decompile_function", {"addr_hex": "0x1000", "bogus": True}),
            ("read_memory_bytes", {"addr_hex": "0x1000", "length": "four"}),
            ("set_memory_block_permissions", {"block_name": "ram", "read": "yes"}),
            ("decompile_functions", {"addresses": ["0x1000", 4097]}),
        ],
    )
    def test_schema_invalid_request_is_rejected_before_dispatch(
        self, live_server, command, args
    ):
        port, project, ctx, shutdown_event = live_server
        import urllib.error
        from ghidramsc.server import _DISPATCH
        spy = mock.MagicMock(return_value="should not run")
        with mock.patch.dict(_DISPATCH, {command: spy}):
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                self._post(port, "/query", {
                    "command": command,
                    "args": args,
                })
        assert exc_info.value.code == 422
        spy.assert_not_called()
        project.get_program.assert_not_called()

    def test_request_larger_than_one_mib_is_accepted(self, live_server):
        port, project, ctx, shutdown_event = live_server
        from ghidramsc.server import _DISPATCH

        large_comment = "x" * (1024 * 1024)

        def set_comment_at_address(ctx, addr_hex, comment, comment_type="eol"):
            assert len(comment) == len(large_comment)
            return "ok"

        with mock.patch.dict(_DISPATCH, {"set_comment_at_address": set_comment_at_address}):
            status, body = self._post(port, "/query", {
                "command": "set_comment_at_address",
                "args": {"addr_hex": "0x1", "comment": large_comment},
            })
        assert status == 200
        assert body == {"result": "ok"}

    @pytest.mark.parametrize("declared,expected", [
        (None, 411), ("bad", 400), ("-1", 411),
        (str(2 ** 31), None),
    ])
    def test_declared_length_boundary_has_no_size_cap(
        self, declared, expected
    ):
        from ghidramsc.server import _Handler

        handler = object.__new__(_Handler)
        handler.headers = {
            "Host": "127.0.0.1",
            "Content-Type": "application/json",
        }
        if declared is not None:
            handler.headers["Content-Length"] = declared
        boundary = handler._post_boundary_error()
        assert (boundary[0] if boundary else None) == expected

    def test_incomplete_declared_body_rejected_before_dispatch(self, live_server):
        port, project, ctx, shutdown_event = live_server
        from ghidramsc.server import _DISPATCH

        body = json.dumps({"command": "list_functions", "args": {}}).encode()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.putrequest("POST", "/query")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(body) + 10))
        connection.endheaders()
        connection.send(body)
        connection.sock.shutdown(socket.SHUT_WR)
        spy = mock.MagicMock()
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            response = connection.getresponse()
            result = json.loads(response.read().decode())
        connection.close()

        assert response.status == 400
        assert "incomplete request body" in result["error"]
        spy.assert_not_called()
        project.get_program.assert_not_called()

    @pytest.mark.parametrize("path", ["/query", "/shutdown"])
    def test_json_null_body_receives_400(self, live_server, path):
        import urllib.error

        port, project, ctx, shutdown_event = live_server
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            self._post(port, path, None)
        assert exc_info.value.code == 400
        project.get_program.assert_not_called()
        assert not shutdown_event.is_set()

    def test_cross_origin_shutdown_is_rejected(self, live_server):
        port, project, ctx, shutdown_event = live_server
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:{}/shutdown".format(port),
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": "https://attacker.example",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 403
        assert not shutdown_event.is_set()

    def test_shutdown_sets_event(self, live_server):
        port, project, ctx, shutdown_event = live_server
        status, body = self._post(port, "/shutdown", {})
        assert status == 200
        assert body["status"] == "shutting_down"
        assert shutdown_event.wait(timeout=1)


# -------------------------------------------------------------------
# client tests
# -------------------------------------------------------------------

class TestClientDiscover:
    """Test port-file discovery."""

    def test_no_port_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from ghidramsc.client import _discover_port
        assert _discover_port() is None

    def test_valid_port_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".ghidramsc_port").write_text("9876", encoding="ascii")
        from ghidramsc.client import _discover_port
        assert _discover_port() == 9876

    def test_corrupt_port_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".ghidramsc_port").write_text("not_a_number", encoding="ascii")
        from ghidramsc.client import _discover_port
        assert _discover_port() is None


class TestClientServerHealth:
    """Test server_health against a live server."""

    def test_no_server(self):
        from ghidramsc.client import server_health
        # Port 1 is virtually never bound
        assert server_health(port=1) is None

    def test_live_server(self):
        from ghidramsc.server import _Handler
        import threading
        project = mock.MagicMock()
        project._programs = {"client_test.so": mock.MagicMock()}
        _Handler.project = project
        _Handler.default_binary = "client_test.so"
        _Handler.shutdown_event = threading.Event()
        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            from ghidramsc.client import server_health
            h = server_health(port=port)
            assert h is not None
            assert h["default_binary"] == "client_test.so"
            assert "cached" in h
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestClientSendQuery:
    """Test send_query with a live server."""

    @pytest.fixture()
    def live(self):
        from ghidramsc.server import _Handler
        project = mock.MagicMock()
        project._programs = {}
        _Handler.project = project
        _Handler.default_binary = "q.so"
        _Handler.shutdown_event = threading.Event()
        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        yield port
        httpd.shutdown()
        httpd.server_close()

    def test_send_returns_dict(self, live):
        from ghidramsc.client import send_query
        from ghidramsc.server import _DISPATCH
        spy = mock.MagicMock(return_value={"data": 1})
        with mock.patch.dict(_DISPATCH, {"list_functions": spy}):
            result = send_query("list_functions", {}, port=live)
        assert result == {"data": 1}

    def test_send_returns_none_no_server(self):
        from ghidramsc.client import send_query
        assert send_query("decompile_function", {}, port=1) is None

    def test_lost_query_response_is_not_server_absence(self, monkeypatch):
        from urllib.error import URLError
        from ghidramsc import client

        monkeypatch.setattr(client, "server_health", lambda port: {"ok": True})

        def lose_response(request, timeout):
            assert request.full_url.endswith("/query")
            raise URLError("connection reset")

        monkeypatch.setattr(client.urllib.request, "urlopen", lose_response)
        with pytest.raises(client.ServerResponseUnavailable,
                           match="outcome unknown"):
            client.send_query("set_function_name", {
                "addr_hex": "0x100", "new_name": "renamed",
            }, port=18100)

    @pytest.mark.parametrize("response_body", [b"{", b"null"])
    def test_unusable_query_response_is_unknown(
        self, monkeypatch, response_body
    ):
        from ghidramsc import client

        monkeypatch.setattr(client, "server_health", lambda port: {"ok": True})
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = response_body
        monkeypatch.setattr(client.urllib.request, "urlopen", lambda *a, **k: response)

        with pytest.raises(client.ServerResponseUnavailable,
                           match="outcome unknown"):
            client.send_query("set_function_name", {}, port=18100)

    def test_lost_mutation_response_never_opens_direct_project(
        self, monkeypatch, capsys
    ):
        from urllib.error import URLError
        from ghidramsc import client, cli, _cli_commands

        monkeypatch.setattr(client, "_discover_port", lambda: 18100)
        monkeypatch.setattr(client, "server_health", lambda port: {"ok": True})
        monkeypatch.setattr(
            client.urllib.request, "urlopen",
            mock.Mock(side_effect=URLError("connection reset")),
        )
        open_direct = mock.Mock(side_effect=AssertionError("unexpected direct open"))
        monkeypatch.setattr(_cli_commands, "_open_bridge", open_direct)

        rc = cli.main([
            "set_function_name", "-b", "test.so", "0x100", "renamed",
        ])
        captured = capsys.readouterr()
        assert rc == 1
        assert "outcome unknown" in captured.err
        assert captured.out == ""
        open_direct.assert_not_called()

    def test_send_error_raises(self, live):
        """Server error becomes RuntimeError on the client side."""
        from ghidramsc.client import send_query
        with pytest.raises(RuntimeError, match="Unknown command"):
            send_query("nope", {}, port=live)

    def test_save_failure_preserves_structured_body(self, live):
        from ghidramsc.client import send_query, ServerQueryError
        from ghidramsc.server import _DISPATCH

        failure = {
            "operation": "save_program", "status": "failed",
            "program": "q.so", "old": {}, "requested": {}, "stored": {},
            "save": {"completed": False}, "error": "disk full",
        }
        with mock.patch.dict(
            _DISPATCH, {"save_program": mock.MagicMock(return_value=failure)}
        ):
            with pytest.raises(ServerQueryError) as exc_info:
                send_query("save_program", {}, port=live)
        assert exc_info.value.payload == failure


class TestClientShutdown:
    def test_shutdown_no_server(self):
        from ghidramsc.client import shutdown_server
        assert shutdown_server(port=1) is False


# -------------------------------------------------------------------
# CLI serve / shutdown argparse wiring
# -------------------------------------------------------------------

class TestServeShutdownParser:
    @pytest.fixture()
    def parser(self):
        from ghidramsc.cli import build_parser
        return build_parser()

    def test_serve_basic(self, parser):
        ns = parser.parse_args(["serve", "-b", "fw.bin"])
        assert ns.command == "serve"
        assert ns.binary == "fw.bin"
        assert ns.port is None
        assert callable(ns.func)

    def test_serve_with_port(self, parser):
        ns = parser.parse_args(["serve", "-b", "fw.bin", "--port", "9999"])
        assert ns.port == 9999

    def test_serve_with_owner(self, parser):
        ns = parser.parse_args(["serve", "--owner", "patrick"])
        assert ns.owner == "patrick"

    def test_serve_forwards_owner(self, parser, monkeypatch):
        from ghidramsc import cli

        config = mock.MagicMock(server_port=13100)
        run_server = mock.MagicMock()
        from ghidramsc import _cli_commands
        monkeypatch.setattr(_cli_commands, "load_config", lambda _: config)
        monkeypatch.setitem(
            sys.modules,
            "ghidramsc.server",
            SimpleNamespace(run_server=run_server),
        )

        ns = parser.parse_args(["serve", "--owner", "patrick"])
        assert cli.cmd_serve(ns) == 0
        run_server.assert_called_once_with(
            config, None, port=13100, owner="patrick"
        )

    def test_shutdown_basic(self, parser):
        ns = parser.parse_args(["shutdown"])
        assert ns.command == "shutdown"
        assert ns.port is None

    def test_shutdown_with_port(self, parser):
        ns = parser.parse_args(["shutdown", "--port", "8888"])
        assert ns.port == 8888

    def test_no_server_flag(self, parser):
        ns = parser.parse_args(["decompile_function", "-b", "test.so", "--no-server", "0x1234"])
        assert ns.no_server is True


def test_run_server_constructs_owner_aware_bridge():
    from ghidramsc import server

    class StopBeforeRuntime(RuntimeError):
        pass

    config = object()
    bridge = mock.MagicMock()
    bridge.open_project.return_value.__enter__.side_effect = StopBeforeRuntime
    with mock.patch.object(
        server, "GhidraBridge", return_value=bridge
    ) as bridge_type:
        with pytest.raises(StopBeforeRuntime):
            server.run_server(config, owner="patrick")

    bridge_type.assert_called_once_with(config, owner="patrick")


# -------------------------------------------------------------------
# CLI _try_server / _emit_server_result
# -------------------------------------------------------------------

class TestTryServer:
    def test_no_server_flag_skips(self):
        from ghidramsc.cli import _try_server
        import argparse
        ns = argparse.Namespace(no_server=True)
        assert _try_server("decompile_function", {"addr_hex": "0x1"}, ns) is None

    def test_no_server_running_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from ghidramsc.cli import _try_server
        import argparse
        ns = argparse.Namespace(no_server=False)
        assert _try_server("decompile_function", {"addr_hex": "0x1"}, ns) is None

    def test_owner_bypasses_http_forwarding(self, monkeypatch):
        from ghidramsc import client
        from ghidramsc.cli import _try_server
        import argparse

        send_query = mock.MagicMock()
        monkeypatch.setattr(client, "send_query", send_query)
        ns = argparse.Namespace(
            no_server=False, owner="patrick", binary="test.so"
        )

        assert _try_server("decompile_function", {"addr_hex": "0x1"}, ns) is None
        send_query.assert_not_called()


class TestEmitServerResult:
    def test_unwraps_scalar(self, capsys):
        from ghidramsc.cli import _emit_server_result
        import argparse
        ns = argparse.Namespace(quiet=False, output=None)
        _emit_server_result({"result": "hello"}, ns)
        assert capsys.readouterr().out.strip() == "hello"

    def test_passes_dict_through(self, capsys):
        from ghidramsc.cli import _emit_server_result
        import argparse
        ns = argparse.Namespace(quiet=False, output=None)
        _emit_server_result({"a": 1, "b": 2}, ns)
        out = json.loads(capsys.readouterr().out)
        assert out == {"a": 1, "b": 2}


# -------------------------------------------------------------------
# Config server_port
# -------------------------------------------------------------------

class TestConfigServerPort:
    def test_default_port(self):
        from ghidramsc.config import GhidraMSCConfig
        cfg = GhidraMSCConfig(
            ghidra_install_dir="/fake",
            project_path="/fake",
            project_name="Test",
        )
        assert cfg.server_port == 13100

    def test_custom_port(self):
        from ghidramsc.config import GhidraMSCConfig
        cfg = GhidraMSCConfig(
            ghidra_install_dir="/fake",
            project_path="/fake",
            project_name="Test",
            server_port="9999",
        )
        assert cfg.server_port == 9999
