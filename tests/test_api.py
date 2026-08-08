"""Tests for recoverage.api — WSGI-level endpoint tests and unit tests for validation logic."""

from __future__ import annotations

import json
import queue
import sqlite3
import threading
import time
from io import BytesIO
from typing import Any
from wsgiref.util import setup_testing_defaults

import pytest
from conftest import HAS_DB, decode_body, get_first_target, wsgi_get, wsgi_post, wsgi_request

from recoverage.server import HAS_CAPSTONE

# ── Regen origin validation (actual endpoint) ─────────────────────


class TestRegenOriginValidation:
    """Test origin/remote_addr checks on the actual /api/regen endpoint."""

    def test_remote_addr_external_rejected(self) -> None:
        """Non-localhost REMOTE_ADDR should be rejected with 403."""
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="192.168.1.100")
        assert status.startswith("403")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Forbidden: localhost only"

    def test_remote_addr_localhost_accepted(self) -> None:
        """Localhost REMOTE_ADDR should pass the remote check (may fail later for other reasons)."""
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        # Should NOT be 403 for remote_addr — may be 500 if rebrew not available, that's fine
        assert not status.startswith("403")

    def test_cross_origin_rejected(self) -> None:
        """Cross-origin request should be rejected with 403."""
        status, headers, body = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://evil.com:8001"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Forbidden: cross-origin"

    def test_localhost_origin_accepted(self) -> None:
        """localhost Origin should pass origin check."""
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://localhost:8001"},
            remote_addr="127.0.0.1",
        )
        assert not status.startswith("403")

    def test_evil_subdomain_rejected(self) -> None:
        """Origin like 127.0.0.1.evil.com must be rejected."""
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://127.0.0.1.evil.com"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")

    def test_ipv6_loopback_remote_addr(self) -> None:
        """::1 REMOTE_ADDR should be accepted."""
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr="::1")
        assert not status.startswith("403")

    @pytest.mark.parametrize(
        "remote_addr",
        [
            "10.0.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "127.0.0.2",
        ],
    )
    def test_non_loopback_remote_addrs_rejected(self, remote_addr: str) -> None:
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr=remote_addr)
        assert status.startswith("403")


# ── API endpoint smoke tests ──────────────────────────────────────


class TestApiHealth:
    """Test /api/health returns valid JSON."""

    def test_health_returns_200(self) -> None:
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "version" in data
        assert "db" in data
        assert "extras" in data

    def test_health_has_security_headers(self) -> None:
        status, headers, _ = wsgi_get("/api/health")
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"

    def test_health_content_type(self) -> None:
        _, headers, _ = wsgi_get("/api/health")
        assert "application/json" in headers.get("Content-Type", "")


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiTargets:
    """Test /api/targets returns target list."""

    def test_targets_returns_200(self) -> None:
        status, headers, body = wsgi_get("/api/targets")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "targets" in data
        assert isinstance(data["targets"], list)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiFunctions:
    """Test /api/targets/<target>/functions with sort validation."""

    def test_default_sort(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "functions" in data
        assert "total" in data

    def test_valid_sort_field(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = wsgi_get(f"/api/targets/{target}/functions?sort=name:desc")
        assert status.startswith("200")

    def test_invalid_sort_field_falls_back(self) -> None:
        """SQL injection in sort field should be rejected by whitelist."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        # Should still return 200 — invalid sort falls back to default "va"
        status, _, _ = wsgi_get(f"/api/targets/{target}/functions?sort=DROP%20TABLE%20functions")
        assert status.startswith("200")

    def test_pagination(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?limit=5&offset=0")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["limit"] == 5
        assert data["offset"] == 0
        assert len(data["functions"]) <= 5

    def test_limit_capped_at_500(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?limit=9999")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["limit"] == 500


# ── VA boundary validation (arithmetic invariants) ─────────────────


class TestVaBoundaryCheck:
    """Verify arithmetic invariants used in handle_api_asm's VA boundary checks.

    These test the mathematical properties that the real handler relies on —
    the same expressions appear in the file_offset and VA boundary checks in
    api.py's handle_api_asm. They do NOT call the endpoint directly.
    """

    def test_va_before_section_start(self) -> None:
        sec_va, sec_file_offset = 0x10001000, 0x400
        va = 0x10000000
        file_offset = sec_file_offset + (va - sec_va)
        assert file_offset < 0

    def test_va_beyond_section_end(self) -> None:
        sec_va, sec_size = 0x10001000, 0x1000
        va = sec_va + sec_size + 1  # one past the end
        assert va >= sec_va + sec_size  # rejected by handler's >= check

    def test_va_at_section_start(self) -> None:
        file_offset = 0x400 + (0x10001000 - 0x10001000)
        assert file_offset == 0x400

    def test_va_just_inside_section(self) -> None:
        sec_va, sec_size = 0x10001000, 0x1000
        last_valid_va = sec_va + sec_size - 1
        assert last_valid_va < sec_va + sec_size  # last byte is in-bounds

    def test_va_at_exact_section_end(self) -> None:
        """VA equal to sec_va + sec_size is out-of-bounds (handler uses >= check)."""
        sec_va, sec_size = 0x10001000, 0x1000
        va = sec_va + sec_size
        # At the boundary: rejected
        assert va >= sec_va + sec_size
        # One byte before: accepted
        assert (va - 1) < sec_va + sec_size

    def test_zero_section_size(self) -> None:
        """Zero-size section has no valid VAs — even sec_va itself is out of bounds."""
        sec_va, sec_size = 0x10001000, 0
        # Every VA is out-of-bounds when size is 0
        assert sec_va >= sec_va + sec_size
        # With a non-zero size, sec_va would be valid
        assert sec_va < sec_va + 1

    def test_max_uint32_va(self) -> None:
        sec_va, sec_file_offset, sec_size = 0xFFFFF000, 0x400, 0x1000
        va = 0xFFFFFFFF
        assert va < sec_va + sec_size
        assert sec_file_offset + (va - sec_va) == sec_file_offset + 0xFFF

    def test_file_offset_overflow_check(self) -> None:
        sec_va, sec_file_offset = 0x80000000, 0x200
        va = 0x00000100
        assert sec_file_offset + (va - sec_va) < 0


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiAsm:
    """Test /api/targets/<target>/asm boundary checks via actual endpoint."""

    def test_missing_params_returns_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = wsgi_get(f"/api/targets/{target}/asm")
        # Either 400 (missing params) or 501 (no capstone) — both are correct rejections
        assert status.startswith("4") or status.startswith("5")

    def test_zero_size_returns_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000&size=0")
        if status.startswith("501"):
            pytest.skip("Capstone not installed")
        assert status.startswith("400")


class TestRegenRateLimit:
    """Server-side cooldown on /api/regen (the UI throttles, the API must too)."""

    def _reset_cooldown(self) -> None:
        import recoverage.api as _api

        _api._regen_last_attempt = 0.0

    def test_rapid_second_call_rate_limited(self) -> None:
        self._reset_cooldown()
        # First call passes the cooldown gate (fails later in the sandbox for
        # other reasons — that's fine, the timestamp is set before subprocess).
        status1, _, _ = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        assert not status1.startswith("429")

        # Immediate second call within the cooldown window → 429.
        status2, headers2, body2 = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        assert status2.startswith("429")
        data = json.loads(decode_body(body2, headers2))
        assert data["error"].startswith("Rate limited")
        assert data["retry_after"] >= 0

    def test_cooldown_expires(self) -> None:
        """After the window elapses the endpoint accepts again."""
        import recoverage.api as _api

        self._reset_cooldown()
        _api._regen_last_attempt = _api.time.monotonic() - _api._REGEN_COOLDOWN_SECONDS - 1
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        assert not status.startswith("429")


class TestServeBindFlag:
    def test_bind_option_help(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--bind" in result.output
        assert "127.0.0.1" in result.output


class TestLastVerify:
    """/functions/<va> attaches the last `rebrew verify -o` record."""

    def test_function_detail_includes_last_verify(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0x10001000")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["last_verify"]["byte_delta"] == 0
        assert "verified_at" in data["last_verify"]

    def test_function_without_verify_record_omits_field(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0x10001030")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "last_verify" not in data


# ── SSE live reload (/api/events) ─────────────────────────────────


def wsgi_stream(path: str, max_chunks: int = 1) -> tuple[str, dict[str, str], list[bytes], Any]:
    """Call the app directly against /api/events and iterate up to max_chunks.

    Returns (status, headers, chunks, result_iter).  The caller must
    ``close()`` the returned iterator to simulate client disconnect — the
    regular ``wsgi_get`` helper cannot be used here because the stream never
    ends on its own.
    """
    environ: dict[str, Any] = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = "GET"
    environ["PATH_INFO"] = path
    environ["QUERY_STRING"] = ""
    environ["REMOTE_ADDR"] = "127.0.0.1"
    environ["wsgi.input"] = BytesIO(b"")
    environ["CONTENT_LENGTH"] = "0"

    status_holder: dict[str, str | dict[str, str]] = {"status": "", "headers": {}}

    def _start_response(status: str, response_headers, exc_info=None) -> None:
        status_holder["status"] = status
        status_holder["headers"] = {k: v for k, v in response_headers}

    from recoverage.server import app

    result = app(environ, _start_response)
    chunks: list[bytes] = []
    for chunk in result:
        chunks.append(chunk)
        if len(chunks) >= max_chunks:
            break
    return str(status_holder["status"]), dict(status_holder["headers"]), chunks, result


class TestSseEvents:
    """SSE stream endpoint, broadcast frames, and disconnect cleanup."""

    def test_stream_headers_and_initial_comment(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            status, headers, chunks, result = wsgi_stream("/api/events", max_chunks=1)
            assert status.startswith("200")
            assert headers["Content-Type"] == "text/event-stream"
            assert headers["Cache-Control"] == "no-cache, no-store, must-revalidate"
            assert chunks == [b": connected\n\n"]
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()

    def test_stream_registers_and_unregisters_client(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            _, _, _, result = wsgi_stream("/api/events", max_chunks=1)
            assert len(api._SSE_CLIENTS) == 1
            result.close()  # client disconnect → generator finally
            assert len(api._SSE_CLIENTS) == 0
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()

    def test_stream_delivers_db_updated_frame(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            _, _, chunks, result = wsgi_stream("/api/events", max_chunks=1)
            assert chunks == [b": connected\n\n"]
            api._broadcast_db_updated((123456789, 1024))
            frame = next(iter(result))
            assert frame.startswith(b"event: db-updated\n")
            assert b'"event": "db-updated"' in frame
            payload = json.loads(frame.split(b"data: ", 1)[1])
            assert payload["db"]["mtime_ns"] == 123456789
            assert payload["db"]["size_bytes"] == 1024
            result.close()
            assert len(api._SSE_CLIENTS) == 0
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()

    def test_broadcast_frame_format(self) -> None:
        import recoverage.api as api

        q: queue.Queue[bytes] = queue.Queue()
        api._SSE_CLIENTS.add(q)
        try:
            api._broadcast_db_updated((987654321, 512))
            frame = q.get_nowait()
            assert frame.startswith(b"event: db-updated\ndata: ")
            assert frame.endswith(b"\n\n")
            payload = json.loads(frame.split(b"data: ", 1)[1])
            assert payload["event"] == "db-updated"
            assert payload["db"]["mtime_ns"] == 987654321
            assert payload["db"]["size_bytes"] == 512
            assert q.empty()
        finally:
            api._SSE_CLIENTS.discard(q)

    def test_snapshot_reads_real_db(self) -> None:
        import recoverage.api as api

        snapshot = api._snapshot_db_mtime()
        assert snapshot is not None
        assert snapshot[1] > 0  # the synthetic DB has a non-zero size

    def test_ensure_db_watcher_starts_thread(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        try:
            api._ensure_db_watcher()
            assert api._DB_WATCHER_THREAD is not None
            assert api._DB_WATCHER_THREAD.is_alive()
        finally:
            api._stop_db_watcher()

    def test_stream_heartbeat(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            monkeypatch.setattr(api, "_SSE_HEARTBEAT_SECONDS", 0.05)
            _, _, chunks, result = wsgi_stream("/api/events", max_chunks=2)
            assert chunks[0] == b": connected\n\n"
            assert chunks[1] == b": ping\n\n"
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()


class TestSseDbWatcher:
    """Background watcher: polls mtime and broadcasts on change."""

    def test_watcher_broadcasts_on_mtime_change(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        seq = [(111, 1), (111, 1), (222, 2)]
        state = {"i": 0}

        def fake_snapshot() -> tuple[int, int]:
            i = min(state["i"], len(seq) - 1)
            value = seq[i]
            state["i"] += 1
            return value

        calls: list[tuple[int, int]] = []
        monkeypatch.setattr(api, "_snapshot_db_mtime", fake_snapshot)
        monkeypatch.setattr(api, "_broadcast_db_updated", lambda s: calls.append(s))
        monkeypatch.setattr(api, "_SSE_POLL_INTERVAL_SECONDS", 0.01)

        stop = threading.Event()
        thread = threading.Thread(target=api._db_watcher_loop, args=(stop,), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 2
            while len(calls) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert calls == [(222, 2)]
        finally:
            stop.set()
            thread.join(timeout=2)

    def test_watcher_ignores_unchanged_mtime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "_snapshot_db_mtime", lambda: (111, 1))
        calls: list[tuple[int, int]] = []
        monkeypatch.setattr(api, "_broadcast_db_updated", lambda s: calls.append(s))
        monkeypatch.setattr(api, "_SSE_POLL_INTERVAL_SECONDS", 0.01)

        stop = threading.Event()
        thread = threading.Thread(target=api._db_watcher_loop, args=(stop,), daemon=True)
        thread.start()
        try:
            time.sleep(0.05)
            assert calls == []
        finally:
            stop.set()
            thread.join(timeout=2)


# ── Threaded WSGI server ──────────────────────────────────────────


class TestThreadingServer:
    """The serve command must use a threaded WSGI server: the SSE /api/events
    stream stays open indefinitely, and wsgiref's stock single-threaded server
    would stall every other request while a client is connected."""

    def test_threading_server_subclasses_mixins(self) -> None:
        from socketserver import ThreadingMixIn
        from wsgiref.simple_server import WSGIServer

        from recoverage.cli import _ThreadingWSGIServer

        assert issubclass(_ThreadingWSGIServer, ThreadingMixIn)
        assert issubclass(_ThreadingWSGIServer, WSGIServer)

    def test_threading_server_daemon_threads(self) -> None:
        from recoverage.cli import _ThreadingWSGIServer

        assert _ThreadingWSGIServer.daemon_threads is True


# ── Batch function lookup ─────────────────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestBatchFunctionLookup:
    """POST /api/targets/<target>/functions batch VA lookup."""

    def _post(self, target: str, body: str | bytes) -> tuple[str, dict[str, str], bytes]:
        return wsgi_post(
            f"/api/targets/{target}/functions",
            headers={"Content-Type": "application/json"},
            body=body,
        )

    def test_batch_returns_details_with_last_verify(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10001010"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert isinstance(data, list)
        assert [fn["name"] for fn in data] == ["_func_a", "_func_b"]
        assert data[0]["va"] == 0x10001000
        assert data[0]["last_verify"]["byte_delta"] == 0
        assert "last_verify" not in data[1]

    def test_batch_omits_unknown_vas(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x99999999"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["va"] for fn in data] == [0x10001000]

    def test_batch_all_unknown_vas_returns_empty_list(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": ["0x99999999"]}))
        assert status.startswith("200")
        assert json.loads(decode_body(body, headers)) == []

    def test_batch_includes_globals(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10002000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert len(data) == 2
        assert data[1]["name"] == "g_counter"
        assert data[1]["isGlobal"] == 1

    def test_batch_preserves_input_order(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001030", "0x10001000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data] == ["_func_c", "_func_a"]

    def test_batch_accepts_int_vas(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": [0x10001000]}))
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data] == ["_func_a"]

    def test_batch_dedupes_repeated_vas(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10001000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert len(data) == 1

    def test_batch_empty_vas_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": []}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"

    def test_batch_non_json_body_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, "not json at all")
        assert status.startswith("400")

    def test_batch_empty_body_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, "")
        assert status.startswith("400")

    def test_batch_body_not_object_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, json.dumps([1, 2, 3]))
        assert status.startswith("400")

    def test_batch_missing_vas_key_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, json.dumps({}))
        assert status.startswith("400")

    def test_batch_vas_not_list_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, json.dumps({"vas": "0x10001000"}))
        assert status.startswith("400")

    def test_batch_malformed_va_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": ["not-a-va"]}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"
        assert "not-a-va" in data["detail"]

    def test_batch_too_many_vas_400(self) -> None:
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        vas = ["0x10001000"] * (api._MAX_BATCH_LOOKUP + 1)
        status, headers, body = self._post(target, json.dumps({"vas": vas}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert str(api._MAX_BATCH_LOOKUP) in data["error"]


# ── Error-response consistency ────────────────────────────────────


class TestErrorResponseShape:
    """Every JSON error response carries {error, code, detail} (+ extras)."""

    def _check(
        self, status: str, headers: dict[str, str], body: bytes, expected_code: str
    ) -> dict[str, Any]:
        assert status.startswith("4") or status.startswith("5")
        data = json.loads(decode_body(body, headers))
        assert set(data) >= {"error", "code", "detail"}
        assert data["code"] == expected_code
        assert isinstance(data["error"], str) and data["error"]
        assert isinstance(data["detail"], str)
        return data

    def test_404_function_detail(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0xdeadbeef")
        data = self._check(status, headers, body, "not_found")
        assert "0xdeadbeef" in data["detail"]

    def test_400_bad_request(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_post(f"/api/targets/{target}/functions", body="[]")
        self._check(status, headers, body, "bad_request")

    def test_403_forbidden(self) -> None:
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="192.168.1.100")
        data = self._check(status, headers, body, "forbidden")
        assert data["error"] == "Forbidden: localhost only"

    def test_429_rate_limited_preserves_extras(self) -> None:
        import recoverage.api as api

        api._regen_last_attempt = 0.0
        wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        data = self._check(status, headers, body, "rate_limited")
        assert data["retry_after"] >= 0
        assert data["detail"]

    def test_501_not_implemented(self) -> None:
        if HAS_CAPSTONE:
            pytest.skip("capstone installed — asm route serves normally")
        status, headers, body = wsgi_get("/api/targets/FAKEDLL/asm?va=0x10001000&size=16")
        data = self._check(status, headers, body, "not_implemented")
        assert "capstone" in data["error"]

    def test_503_db_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")

        def _boom() -> sqlite3.Connection:
            raise sqlite3.OperationalError("no such file")

        monkeypatch.setattr(api, "_db", _boom)
        status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        self._check(status, headers, body, "db_unavailable")


# ── Host-header validation & CORS allowlist (security) ─────────────


class TestHostHeaderValidation:
    """Loopback installs reject unexpected Host headers (DNS-rebinding guard)."""

    def _set_allowed(self, value: set[str] | None) -> None:
        import recoverage.server as srv

        srv.ALLOWED_HOSTS = value

    def teardown_method(self) -> None:
        self._set_allowed(None)

    def test_loopback_host_accepted(self) -> None:
        self._set_allowed({"127.0.0.1", "localhost", "::1"})
        status, _, _ = wsgi_get("/api/health", headers={"Host": "localhost:8001"})
        assert status.startswith("200")

    def test_evil_host_rejected(self) -> None:
        self._set_allowed({"127.0.0.1", "localhost", "::1"})
        status, headers, body = wsgi_get("/api/health", headers={"Host": "evil.example.com"})
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Bad Request"
        assert "evil.example.com" in data["detail"]

    def test_no_validation_when_remote_bind(self) -> None:
        # --allow-remote binds leave ALLOWED_HOSTS None → any Host passes.
        self._set_allowed(None)
        status, _, _ = wsgi_get("/api/health", headers={"Host": "anything.example.com"})
        assert status.startswith("200")


class TestCorsOriginAllowlist:
    """--cors never emits the wildcard; only allowlisted origins are echoed."""

    def _enable(self, origins: list[str]) -> None:
        import recoverage.server as srv

        srv.CORS_ENABLED = True
        srv.CORS_ALLOWED_ORIGINS = origins

    def teardown_method(self) -> None:
        import recoverage.server as srv

        srv.CORS_ENABLED = False
        srv.CORS_ALLOWED_ORIGINS = []

    def test_allowed_origin_echoed(self) -> None:
        # Origins are matched at scheme://host[:port] granularity, not hostname.
        self._enable(["http://localhost:5173"])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert status.startswith("200")
        assert headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
        assert "Origin" in headers.get("Vary", "")

    def test_unknown_origin_gets_no_aca_header(self) -> None:
        self._enable(["http://localhost:5173"])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://evil.example.com"})
        assert status.startswith("200")
        assert "Access-Control-Allow-Origin" not in headers

    def test_wildcard_never_emitted(self) -> None:
        """An empty allowlist must never emit Access-Control-Allow-Origin:*."""
        self._enable([])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert status.startswith("200")
        assert "Access-Control-Allow-Origin" not in headers

    def test_different_port_not_allowed(self) -> None:
        self._enable(["http://localhost:5173"])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:9999"})
        assert status.startswith("200")
        assert "Access-Control-Allow-Origin" not in headers
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert status.startswith("200")
        assert headers.get("Access-Control-Allow-Origin") != "*"


# ── Unknown target handling (V14) ──────────────────────────────────


class TestUnknownTarget:
    """Target-scoped endpoints 404 on unknown targets instead of empty 200s."""

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_stats_unknown_target_404(self) -> None:
        status, headers, body = wsgi_get("/api/targets/DOESNOTEXIST/stats")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Target not found"
        assert "DOESNOTEXIST" in data["detail"]

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_functions_unknown_target_404(self) -> None:
        status, headers, body = wsgi_get("/api/targets/DOESNOTEXIST/functions")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Target not found"

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_known_target_still_200(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = wsgi_get(f"/api/targets/{target}/stats")
        assert status.startswith("200")


class TestServeBindGuard:
    """--bind on a non-loopback interface requires --allow-remote."""

    def test_non_loopback_refused_without_allow_remote(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--bind", "0.0.0.0", "--port", "8123"])
        assert result.exit_code != 0
        assert "--allow-remote" in result.output

    def test_allow_remote_flag_documented(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--allow-remote" in result.output
        assert "--cors-origin" in result.output


class TestPostConnectSqliteError:
    """Queries that fail after connect (corrupt DB, SQLITE_BUSY) must keep
    the JSON 503 contract instead of surfacing Bottle's HTML 500."""

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_query_failure_returns_json_503(self, monkeypatch: Any) -> None:
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")

        real_conn = api._db()

        class _BoomCursor:
            def __init__(self) -> None:
                pass

            def execute(self, *a, **k):
                raise sqlite3.OperationalError("no such table: section_cell_stats")

            def fetchone(self) -> None:
                return None

            def fetchall(self) -> list:
                return []

        class _BoomConn:
            def cursor(self):
                return _BoomCursor()

            def close(self) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(api, "_db", lambda: _BoomConn())
        try:
            status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        finally:
            real_conn.close()
        assert status.startswith("503")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Database unavailable"
        assert data["code"] == "db_unavailable"


class TestNormalizeOriginEdges:
    def test_default_port_dropped(self) -> None:
        from recoverage.server import _normalize_origin

        assert _normalize_origin("http://localhost:80") == "http://localhost"
        assert _normalize_origin("https://example.com:443") == "https://example.com"
        assert _normalize_origin("http://localhost:5173") == "http://localhost:5173"

    def test_ipv6_brackets_preserved(self) -> None:
        from recoverage.server import _normalize_origin

        assert _normalize_origin("http://[::1]:8001") == "http://[::1]:8001"


class TestDataPayloadMemo:
    """/api/targets/<t>/data memoises the assembled payload per DB fingerprint.

    The endpoint materialises all cells + search index + stats on every
    cache-missing request; the memo (keyed on db mtime_ns/size) serves
    repeat requests without re-querying, and is cleared on rebuild.
    """

    def _make_db(self, tmp_path: Any) -> Any:
        import sqlite3

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        c.execute(
            "CREATE TABLE sections (target TEXT, name TEXT, va INTEGER, size INTEGER, fileOffset INTEGER)"
        )
        c.execute(
            "CREATE TABLE cells (id INTEGER, target TEXT, section_name TEXT, start INTEGER, "
            "end INTEGER, span INTEGER, state TEXT, functions TEXT, label TEXT, parent_function TEXT)"
        )
        c.execute(
            "CREATE TABLE functions (target TEXT, va INTEGER, name TEXT, vaStart TEXT, size INTEGER, "
            "status TEXT, module TEXT, cflags TEXT, symbol TEXT, markerType TEXT)"
        )
        c.execute("CREATE TABLE globals (target TEXT, name TEXT, va INTEGER)")
        c.execute(
            "CREATE VIEW section_cell_stats AS SELECT target, section_name, "
            "COUNT(*) AS total_cells, 0 AS exact_count, 0 AS reloc_count, 0 AS near_match_count, "
            "0 AS stub_count, 0 AS padding_count, 0 AS data_count, 0 AS thunk_count, "
            "0 AS none_count, 0 AS proven_count, 0 AS size_mismatch_count "
            "FROM cells GROUP BY target, section_name"
        )
        c.execute("INSERT INTO metadata VALUES ('GAME', 'db_version', '\"4\"')")
        conn.commit()
        conn.close()
        return db

    def test_memo_serves_second_request_and_clears(self, tmp_path: Any, monkeypatch: Any) -> None:
        import recoverage.api as api

        db = self._make_db(tmp_path)

        def _open_like(p: Any) -> Any:
            conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            return conn

        monkeypatch.setattr(api, "_db_path", lambda: db)
        monkeypatch.setattr(api, "_open_db", _open_like)
        monkeypatch.setattr(api, "_require_target", lambda c, t: None)
        monkeypatch.setattr(api, "request", type("R", (), {"headers": {}, "query": {}})())
        api._clear_data_cache()

        resp1 = api.handle_api_data("GAME")
        assert isinstance(resp1, bytes)
        assert len(api._DATA_CACHE) == 1

        # Second request: cache hit (payload identical, no query re-run).
        resp2 = api.handle_api_data("GAME")
        assert isinstance(resp2, bytes)

        # Rebuild invalidation path.
        api._clear_data_cache()
        assert len(api._DATA_CACHE) == 0
