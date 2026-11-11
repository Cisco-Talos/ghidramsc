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

"""Tests for ghidramsc.bridge_plugin -- plugin TCP bridge.

Uses a mock TCP server running in a background thread to validate the
PluginProjectHandle framing, command dispatch, error handling, and
json_path pre-reading.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

import pytest

from ghidramsc.bridge_plugin import (
    AmbiguousMutationResultError,
    DEFAULT_PLUGIN_HOST,
    DEFAULT_PLUGIN_PORT,
    PluginCapacityError,
    PluginProtocolError,
    PluginProjectHandle,
    _preread_json_paths,
)


# -------------------------------------------------------------------
# Mock TCP server
# -------------------------------------------------------------------

class MockPluginServer:
    """A minimal TCP server that speaks the 4-byte length-prefix protocol.

    Pass a *handler* callback that receives the parsed request dict and
    returns a response dict.  The server handles one connection at a
    time in a background thread.
    """

    def __init__(
        self,
        handler: Callable[[Dict[str, Any]], Any],
        host: str = "127.0.0.1",
    ) -> None:
        self._handler = handler
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((host, 0))  # OS-assigned port
        self._server.listen(1)
        self.host, self.port = self._server.getsockname()
        self._thread: Optional[threading.Thread] = None
        self._client_threads: List[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._server.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=self._run_conn, args=(conn,), daemon=True
            )
            self._client_threads.append(thread)
            thread.start()

    def _run_conn(self, conn: socket.socket) -> None:
        try:
            self._handle_conn(conn)
        except Exception:
            pass
        finally:
            conn.close()

    def _handle_conn(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        while not self._stop.is_set():
            try:
                header = self._recv_exact(conn, 4)
            except (ConnectionError, socket.timeout, OSError):
                break
            length = struct.unpack(">I", header)[0]
            body = self._recv_exact(conn, length)
            request = json.loads(body.decode("utf-8"))
            response = self._handler(request)
            if response is None:
                return
            payload = (
                response if isinstance(response, bytes)
                else json.dumps(response).encode("utf-8")
            )
            frame = struct.pack(">I", len(payload)) + payload
            conn.sendall(frame)

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf.extend(chunk)
        return bytes(buf)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._server.close()
        for thread in self._client_threads:
            thread.join(timeout=3)


# -------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------

def _default_handler(request: Dict[str, Any]) -> Dict[str, Any]:
    """Route commands to canned responses."""
    cmd = request.get("command", "")
    req_id = request.get("id", 0)
    args = request.get("args", {})
    binary = request.get("binary")

    if cmd == "ping":
        return {"id": req_id, "result": "pong"}

    if cmd == "list_programs":
        return {
            "id": req_id,
            "result": {"programs": ["firmware.elf", "libfoo.so"]},
        }

    if cmd == "list_functions":
        return {
            "id": req_id,
            "result": "0x1000  main\n0x2000  helper\n",
        }

    if cmd == "decompile_function":
        addr = args.get("addr_hex", "???")
        return {
            "id": req_id,
            "result": "// decompiled {}:{}\nvoid func() {{}}\n".format(
                binary or "?", addr
            ),
        }

    if cmd == "get_function_info":
        return {
            "id": req_id,
            "result": {
                "name": "main",
                "address": args.get("addr_hex", "0x0"),
                "binary": binary or "?",
            },
        }

    if cmd == "set_function_names":
        # Echo back json_data if it was sent (tests pre-read).
        if "json_data" in args:
            return {
                "id": req_id,
                "result": "Renamed {} entries".format(len(args["json_data"])),
            }
        return {"id": req_id, "result": "set_function_names ok"}

    if cmd == "save_program":
        return {
            "id": req_id,
            "result": {
                "operation": "save_program",
                "status": "success",
                "program": binary,
            },
        }

    if cmd == "error_test":
        return {"id": req_id, "error": "Something went wrong"}

    return {"id": req_id, "error": "Unknown command: {}".format(cmd)}


@pytest.fixture()
def mock_server():
    """Start a mock plugin TCP server and yield it.  Stops on cleanup."""
    srv = MockPluginServer(_default_handler)
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture()
def plugin(mock_server):
    """Return a connected PluginProjectHandle."""
    handle = PluginProjectHandle(
        host=mock_server.host, port=mock_server.port, timeout=5.0
    )
    yield handle
    handle.close()


# -------------------------------------------------------------------
# Tests: connection and framing
# -------------------------------------------------------------------

class TestConnection:
    def test_connect_and_ping(self, plugin):
        assert plugin.ping() is True

    def test_repr(self, plugin):
        r = repr(plugin)
        assert "PluginProjectHandle" in r

    def test_context_manager(self, mock_server):
        with PluginProjectHandle(
            host=mock_server.host, port=mock_server.port, timeout=5.0
        ) as p:
            assert p.ping() is True
        # Socket should be closed after __exit__.
        assert p._sock is None

    def test_close_idempotent(self, plugin):
        plugin.close()
        plugin.close()  # should not raise

    def test_closed_handle_does_not_reconnect(self, plugin):
        plugin.close()
        with pytest.raises(ConnectionError, match="closed"):
            plugin.invoke("list_programs", None, {})

    def test_connect_refused(self):
        """Connecting to a port with no server should raise."""
        with pytest.raises((ConnectionRefusedError, OSError)):
            PluginProjectHandle(host="127.0.0.1", port=1, timeout=1.0)

    def test_request_and_response_larger_than_one_mib(self, plugin):
        large_address = "0x" + ("1" * (1024 * 1024))
        result = plugin.invoke(
            "decompile_function", "firmware.elf", {"addr_hex": large_address}
        )
        assert large_address in result


# -------------------------------------------------------------------
# Tests: command invocation
# -------------------------------------------------------------------

class TestInvoke:
    def test_list_programs(self, plugin):
        programs = plugin.list_programs()
        assert "firmware.elf" in programs
        assert "libfoo.so" in programs

    def test_invoke_string_result(self, plugin):
        result = plugin.invoke("list_functions", "firmware.elf", {})
        assert "main" in result
        assert "helper" in result

    def test_invoke_dict_result(self, plugin):
        result = plugin.invoke("get_function_info", "firmware.elf", {"addr_hex": "0x1000"})
        assert result["name"] == "main"
        assert result["binary"] == "firmware.elf"

    def test_invoke_with_args(self, plugin):
        result = plugin.invoke(
            "decompile_function", "firmware.elf", {"addr_hex": "0x1000"}
        )
        assert "firmware.elf" in result
        assert "0x1000" in result

    def test_invoke_error_raises(self, plugin):
        with pytest.raises(RuntimeError, match="Something went wrong"):
            plugin.invoke("error_test", "firmware.elf", {})

    def test_invoke_unknown_command_raises(self, plugin):
        with pytest.raises(RuntimeError, match="Unknown command"):
            plugin.invoke("totally_bogus", "firmware.elf", {})

    def test_get_program_proxy(self, plugin):
        proxy = plugin.get_program("firmware.elf")
        assert proxy.name == "firmware.elf"
        assert "firmware.elf" in repr(proxy)

    def test_save_forwards_explicit_operation(self, plugin):
        active = plugin.save()
        named = plugin.save("firmware.elf")
        assert active["status"] == "success"
        assert active["program"] is None
        assert named["status"] == "success"
        assert named["program"] == "firmware.elf"

    def test_multiple_sequential_commands(self, plugin):
        """Verify the persistent connection handles multiple round-trips."""
        for _ in range(5):
            assert plugin.ping() is True
        programs = plugin.list_programs()
        assert len(programs) == 2

    def test_request_ids_increment(self, plugin):
        assert plugin._request_id == 0
        plugin.ping()
        assert plugin._request_id == 1
        plugin.ping()
        assert plugin._request_id == 2


# -------------------------------------------------------------------
# Tests: response validation, recovery, and concurrency
# -------------------------------------------------------------------

class TestRecovery:
    def test_upgrade_block_error_keeps_same_handle_usable(self):
        commands = []
        blocked = True

        def handler(request):
            nonlocal blocked
            commands.append((request["command"], request.get("binary")))
            if request.get("binary") == "legacy.bin" and blocked:
                blocked = False
                return {
                    "id": request["id"],
                    "error": (
                        "Program open blocked for 'legacy.bin': resolve the "
                        "'Upgrade Program Data?' dialog, then retry the "
                        "request on this same plugin connection."
                    ),
                }
            return {"id": request["id"], "result": "ok"}

        srv = MockPluginServer(handler)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            with pytest.raises(RuntimeError) as raised:
                p.invoke("list_functions", "legacy.bin", {})
            assert "legacy.bin" in str(raised.value)
            assert "Upgrade Program Data?" in str(raised.value)
            assert p.invoke("list_functions", "current.bin", {}) == "ok"
            assert p.invoke("list_functions", "legacy.bin", {}) == "ok"
            assert commands == [
                ("list_functions", "legacy.bin"),
                ("list_functions", "current.bin"),
                ("list_functions", "legacy.bin"),
            ]
            p.close()
        finally:
            srv.stop()

    def test_query_disconnect_returns_error_then_later_read_reconnects(self):
        commands = []

        def disconnect_once(request):
            commands.append(request["command"])
            if len(commands) == 1:
                return None
            return {"id": request["id"], "result": {"programs": ["fw.bin"]}}

        srv = MockPluginServer(disconnect_once)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            with pytest.raises(ConnectionError, match="closed unexpectedly"):
                p.invoke("list_functions", "firmware.elf", {})
            assert commands == ["list_functions"]
            assert p.list_programs() == ["fw.bin"]
            assert commands == ["list_functions", "list_programs"]
            p.close()
        finally:
            srv.stop()

    def test_later_call_can_retry_after_listener_remains_unavailable(self):
        srv = MockPluginServer(lambda request: None)
        srv.start()
        p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
        try:
            with pytest.raises(ConnectionError, match="closed unexpectedly"):
                p.invoke("list_functions", "firmware.elf", {})
            srv.stop()
            with pytest.raises(OSError):
                p.list_programs()
            with pytest.raises(OSError):
                p.list_programs()
        finally:
            p.close()
            srv.stop()

    @pytest.mark.parametrize(
        "bad_response",
        [
            lambda request: {"id": request["id"] + 1, "result": "wrong"},
            lambda request: {"result": "missing id"},
            lambda request: [request["id"], "not an object"],
            lambda request: b"not-json",
            lambda request: {
                "id": request["id"], "result": "value", "error": "error"
            },
            lambda request: {"id": request["id"]},
        ],
        ids=[
            "mismatched-id", "missing-id", "non-object", "malformed-json",
            "result-and-error", "neither-result-nor-error",
        ],
    )
    def test_invalid_response_is_rejected_on_each_independent_call(
        self, bad_response
    ):
        calls = 0

        def handler(request):
            nonlocal calls
            calls += 1
            return bad_response(request)

        srv = MockPluginServer(handler)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            with pytest.raises(PluginProtocolError):
                p.invoke("list_functions", "firmware.elf", {})
            assert calls == 1
            with pytest.raises(PluginProtocolError):
                p.invoke("list_functions", "firmware.elf", {})
            assert calls == 2
            p.close()
        finally:
            srv.stop()

    def test_query_timeout_gets_one_attempt(self):
        calls = 0
        calls_lock = threading.Lock()

        def slow_handler(request):
            nonlocal calls
            with calls_lock:
                calls += 1
            time.sleep(0.2)
            return {"id": request["id"], "result": "too late"}

        srv = MockPluginServer(slow_handler)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=0.05)
            with pytest.raises(socket.timeout):
                p.invoke("list_functions", "firmware.elf", {})
            assert calls == 1
            p.close()
        finally:
            srv.stop()

    def test_mutation_has_no_ping_preflight(self):
        commands = []

        def record_mutation(request):
            commands.append(request["command"])
            return {"id": request["id"], "result": "mutated"}

        srv = MockPluginServer(record_mutation)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            result = p.invoke(
                "set_function_name", "firmware.elf",
                {"addr_hex": "0x1000", "new_name": "renamed"},
            )
            assert result == "mutated"
            assert commands == ["set_function_name"]
            p.close()
        finally:
            srv.stop()

    def test_explicit_mutation_handler_error_keeps_connection_usable(self):
        commands = []

        def handler(request):
            commands.append(request["command"])
            if request["command"] == "set_function_name":
                return {"id": request["id"], "error": "rename rejected"}
            return {"id": request["id"], "result": "pong"}

        srv = MockPluginServer(handler)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            with pytest.raises(RuntimeError, match="rename rejected"):
                p.invoke(
                    "set_function_name", "firmware.elf",
                    {"addr_hex": "0x1000", "new_name": "renamed"},
                )
            assert p.ping() is True
            assert commands == ["set_function_name", "ping"]
            p.close()
        finally:
            srv.stop()

    def test_lost_mutation_response_is_never_replayed(self):
        mutation_calls = 0
        read_calls = 0

        def lose_mutation_response(request):
            nonlocal mutation_calls, read_calls
            if request["command"] == "set_function_name":
                mutation_calls += 1
                return None
            read_calls += 1
            return {"id": request["id"], "result": "query ok"}

        srv = MockPluginServer(lose_mutation_response)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            with pytest.raises(
                AmbiguousMutationResultError, match="was not replayed"
            ):
                p.invoke(
                    "set_function_name", "firmware.elf",
                    {"addr_hex": "0x1000", "new_name": "renamed"},
                )
            assert mutation_calls == 1
            assert p.invoke("list_functions", "firmware.elf", {}) == "query ok"
            assert mutation_calls == 1
            assert read_calls == 1
            p.close()
        finally:
            srv.stop()

    def test_mismatched_mutation_response_id_is_not_replayed(self):
        mutation_calls = 0

        def wrong_mutation_id(request):
            nonlocal mutation_calls
            mutation_calls += 1
            return {"id": request["id"] + 1, "result": "mutated"}

        srv = MockPluginServer(wrong_mutation_id)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            with pytest.raises(
                AmbiguousMutationResultError, match="ID mismatch"
            ) as raised:
                p.invoke(
                    "set_function_name", "firmware.elf",
                    {"addr_hex": "0x1000", "new_name": "renamed"},
                )
            assert mutation_calls == 1
            assert isinstance(raised.value.__cause__, PluginProtocolError)
            p.close()
        finally:
            srv.stop()

    def test_mutation_timeout_is_ambiguous_and_not_replayed(self):
        mutation_calls = 0

        def slow_mutation(request):
            nonlocal mutation_calls
            mutation_calls += 1
            time.sleep(0.2)
            return {"id": request["id"], "result": "too late"}

        srv = MockPluginServer(slow_mutation)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=0.05)
            with pytest.raises(AmbiguousMutationResultError):
                p.invoke(
                    "set_function_name", "firmware.elf",
                    {"addr_hex": "0x1000", "new_name": "renamed"},
                )
            assert mutation_calls == 1
            p.close()
        finally:
            srv.stop()

    def test_independent_handles_can_overlap(self):
        both_arrived = threading.Event()
        arrival_lock = threading.Lock()
        arrivals = 0

        def echo(request):
            nonlocal arrivals
            with arrival_lock:
                arrivals += 1
                if arrivals == 2:
                    both_arrived.set()
            assert both_arrived.wait(timeout=1.0)
            return {
                "id": request["id"],
                "result": request["args"]["addr_hex"],
            }

        srv = MockPluginServer(echo)
        srv.start()
        try:
            first = PluginProjectHandle(srv.host, srv.port, timeout=2.0)
            second = PluginProjectHandle(srv.host, srv.port, timeout=2.0)
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        handle.invoke, "decompile_function", "firmware.elf",
                        {"addr_hex": address},
                    )
                    for handle, address in (
                        (first, "0x1000"), (second, "0x2000")
                    )
                ]
                assert [future.result() for future in futures] == [
                    "0x1000", "0x2000"
                ]
            first.close()
            second.close()
        finally:
            srv.stop()


class TestListenerControl:
    def test_omitted_limit_sends_no_configuration_request(self):
        commands = []

        def handler(request):
            commands.append(request["command"])
            return {"id": request["id"], "result": "pong"}

        srv = MockPluginServer(handler)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            assert p.effective_max_clients is None
            assert p.ping() is True
            assert commands == ["ping"]
            p.close()
        finally:
            srv.stop()

    def test_explicit_limit_sends_one_internal_configuration_request(self):
        requests = []

        def handler(request):
            requests.append(request)
            assert request["command"] == "configure_listener"
            return {
                "id": request["id"],
                "result": {"max_clients": request["args"]["max_clients"]},
            }

        srv = MockPluginServer(handler)
        srv.start()
        try:
            p = PluginProjectHandle(
                srv.host, srv.port, timeout=1.0, max_clients=17
            )
            assert p.effective_max_clients == 17
            assert len(requests) == 1
            assert requests[0] == {
                "id": 1,
                "command": "configure_listener",
                "args": {"max_clients": 17},
            }
            p.close()
        finally:
            srv.stop()

    def test_explicit_limit_is_reapplied_before_request_after_reconnect(self):
        commands = []

        def handler(request):
            command = request["command"]
            commands.append(command)
            if command == "configure_listener":
                return {
                    "id": request["id"],
                    "result": {"max_clients": request["args"]["max_clients"]},
                }
            if commands.count("list_programs") == 1:
                return None
            return {"id": request["id"], "result": {"programs": []}}

        srv = MockPluginServer(handler)
        srv.start()
        try:
            p = PluginProjectHandle(
                srv.host, srv.port, timeout=1.0, max_clients=7
            )
            with pytest.raises(ConnectionError, match="closed unexpectedly"):
                p.list_programs()
            assert p.effective_max_clients is None
            assert p.list_programs() == []
            assert p.effective_max_clients == 7
            assert commands == [
                "configure_listener", "list_programs",
                "configure_listener", "list_programs",
            ]
            p.close()
        finally:
            srv.stop()

    def test_explicit_limit_fails_clearly_against_old_plugin(self):
        def old_plugin(request):
            return {
                "id": request["id"],
                "error": "Unknown command: configure_listener",
            }

        srv = MockPluginServer(old_plugin)
        srv.start()
        try:
            with pytest.raises(
                PluginProtocolError, match="may not support"
            ):
                PluginProjectHandle(
                    srv.host, srv.port, timeout=1.0, max_clients=4
                )
        finally:
            srv.stop()

    @pytest.mark.parametrize(
        "acknowledgement",
        [
            {"max_clients": "17"},
            {"max_clients": 18},
            {},
        ],
        ids=["wrong-type", "wrong-value", "missing"],
    )
    def test_explicit_limit_validates_acknowledged_effective_value(
        self, acknowledgement
    ):
        def handler(request):
            return {"id": request["id"], "result": acknowledgement}

        srv = MockPluginServer(handler)
        srv.start()
        try:
            with pytest.raises(PluginProtocolError):
                PluginProjectHandle(
                    srv.host, srv.port, timeout=1.0, max_clients=17
                )
        finally:
            srv.stop()

    def test_capacity_envelope_is_recognized_before_response_id(self):
        def at_capacity(request):
            return {
                "id": 0,
                "error": "client capacity reached",
                "error_code": "client_capacity",
                "max_clients": 12,
            }

        srv = MockPluginServer(at_capacity)
        srv.start()
        try:
            p = PluginProjectHandle(srv.host, srv.port, timeout=1.0)
            with pytest.raises(PluginCapacityError) as raised:
                p.invoke("list_programs", None, {})
            assert raised.value.max_clients == 12
            with pytest.raises(PluginCapacityError):
                p.invoke("list_programs", None, {})
            p.close()
        finally:
            srv.stop()

    @pytest.mark.parametrize("value", [0, -1, True, 2_147_483_648])
    def test_limit_validation(self, value):
        with pytest.raises(ValueError, match="max_clients"):
            PluginProjectHandle("127.0.0.1", 1, max_clients=value)


# -------------------------------------------------------------------
# Tests: json_path pre-reading
# -------------------------------------------------------------------

class TestJsonPathPreread:
    def test_preread_replaces_path(self, tmp_path):
        data = [
            {"addr": "0x1000", "name": "main"},
            {"addr": "0x2000", "name": "helper"},
        ]
        jfile = tmp_path / "renames.json"
        jfile.write_text(json.dumps(data), encoding="utf-8")

        args = {"json_path": str(jfile)}
        _preread_json_paths("set_function_names", args)
        assert "json_path" not in args
        assert args["json_data"] == data

    def test_preread_no_json_path_is_noop(self):
        args = {"addr_hex": "0x1000", "new_name": "foo"}
        _preread_json_paths("set_function_name", args)
        assert args == {"addr_hex": "0x1000", "new_name": "foo"}

    def test_preread_none_value_is_noop(self):
        args = {"json_path": None, "other": "val"}
        _preread_json_paths("set_function_names", args)
        # json_path with None should be left alone (not opened).
        assert "json_path" in args

    def test_invoke_prereads_json_path(self, plugin, tmp_path):
        """End-to-end: invoke with json_path should send json_data."""
        data = [{"addr": "0x1000", "name": "renamed_func"}]
        jfile = tmp_path / "batch.json"
        jfile.write_text(json.dumps(data), encoding="utf-8")

        result = plugin.invoke("set_function_names", "firmware.elf", {
            "json_path": str(jfile),
        })
        assert "Renamed 1 entries" in result

    def test_preread_missing_file_raises(self):
        args = {"json_path": "/nonexistent/path/file.json"}
        with pytest.raises(FileNotFoundError):
            _preread_json_paths("set_function_names", args)

    @pytest.mark.parametrize(
        ("command", "value"),
        [
            ("set_function_names", [{"addr": "0x1000", "name": "main"}]),
            ("create_functions", [{"addr": "0x1000"}]),
            ("import_annotations", {"symbols": []}),
            ("apply_function_annotations", {"vars": []}),
        ],
    )
    def test_each_json_tool_sends_declared_wire_type(
        self, command, value, tmp_path
    ):
        jfile = tmp_path / "input.json"
        jfile.write_text(json.dumps(value), encoding="utf-8")
        args = {"json_path": str(jfile)}

        _preread_json_paths(command, args)

        assert args == {"json_data": value}

    @pytest.mark.parametrize(
        ("command", "wrong_value", "expected"),
        [
            ("set_function_names", {"0x1000": "main"}, "array"),
            ("create_functions", {"addr": "0x1000"}, "array"),
            ("import_annotations", [], "object"),
            ("apply_function_annotations", [], "object"),
        ],
    )
    def test_wrong_top_level_type_is_rejected_before_send(
        self, plugin, command, wrong_value, expected, tmp_path
    ):
        jfile = tmp_path / "wrong.json"
        jfile.write_text(json.dumps(wrong_value), encoding="utf-8")

        with pytest.raises(ValueError, match="top-level {}".format(expected)):
            plugin.invoke(command, "firmware.elf", {
                "json_path": str(jfile),
            })

        # Rejection happens before transport, so the connection stays usable.
        assert plugin.ping() is True


# -------------------------------------------------------------------
# Tests: ping failure
# -------------------------------------------------------------------

class TestPingFailure:
    def test_ping_returns_false_on_bad_response(self):
        """A server that returns garbage for ping -> ping() returns False."""
        def bad_handler(req):
            return {"id": req.get("id", 0), "result": "not_pong"}
        srv = MockPluginServer(bad_handler)
        srv.start()
        try:
            p = PluginProjectHandle(host=srv.host, port=srv.port, timeout=3.0)
            assert p.ping() is False
            p.close()
        finally:
            srv.stop()
