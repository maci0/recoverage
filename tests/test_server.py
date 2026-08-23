"""Tests for recoverage.server — compression, encoding, path helpers, response helpers."""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import brotli
import pytest
import zstandard as zstd

from recoverage.server import (
    _best_encoding,
    _db_path,
    _escape_like,
    _find_dll_path,
    _project_dir,
    clear_target_cache,
    compress_payload,
)

# ── _best_encoding ─────────────────────────────────────────────────


class TestBestEncoding:
    def test_prefers_zstd(self) -> None:
        assert _best_encoding("gzip, br, zstd") == "zstd"

    def test_prefers_br_over_gzip(self) -> None:
        assert _best_encoding("gzip, br") == "br"

    def test_falls_back_to_gzip(self) -> None:
        assert _best_encoding("gzip") == "gzip"

    def test_empty_returns_empty(self) -> None:
        assert _best_encoding("") == ""

    def test_identity_returns_empty(self) -> None:
        assert _best_encoding("identity") == ""

    def test_strips_quality_values(self) -> None:
        assert _best_encoding("gzip;q=0.5, br;q=1.0") == "br"

    def test_case_insensitive(self) -> None:
        assert _best_encoding("GZIP, BR") == "br"

    def test_no_false_substring_match(self) -> None:
        """Encoding token 'not-zstd' should not match 'zstd'."""
        assert _best_encoding("not-zstd") == ""

    def test_whitespace_handling(self) -> None:
        assert _best_encoding("  gzip  ,  br  ") == "br"

    # ── Adversarial Accept-Encoding inputs ─────────────────────────

    def test_null_byte_in_encoding(self) -> None:
        """Null bytes in header must not crash or produce false match."""
        result = _best_encoding("gzip\x00, br")
        # "gzip\x00" is not "gzip" — null byte prevents match; "br" is clean
        assert result == "br"

    def test_very_long_header(self) -> None:
        """Header with many tokens should still work."""
        tokens = ", ".join(f"enc{i}" for i in range(1000)) + ", gzip"
        assert _best_encoding(tokens) == "gzip"

    def test_semicolons_only(self) -> None:
        assert _best_encoding(";;;") == ""

    def test_commas_only(self) -> None:
        assert _best_encoding(",,,") == ""

    def test_duplicate_encodings(self) -> None:
        assert _best_encoding("gzip, gzip, gzip") == "gzip"

    @pytest.mark.parametrize(
        "header,expected",
        [
            ("*", ""),
            ("zstd, br, gzip, deflate, sdch", "zstd"),
            ("br;q=1.0, gzip;q=0.5, zstd;q=0.9", "zstd"),
        ],
    )
    def test_various_real_world_headers(self, header: str, expected: str) -> None:
        assert _best_encoding(header) == expected


# ── compress_payload ───────────────────────────────────────────────


class TestCompressPayload:
    def test_gzip_roundtrip(self) -> None:
        data = b"hello world" * 100
        compressed, encoding = compress_payload(data, "gzip")
        assert encoding == "gzip"
        assert gzip.decompress(compressed) == data

    def test_no_compression(self) -> None:
        data = b"hello"
        result, encoding = compress_payload(data, "identity")
        assert encoding == ""
        assert result == data

    def test_brotli_returns_br(self) -> None:
        data = b"x" * 100
        _, encoding = compress_payload(data, "br")
        assert encoding == "br"

    def test_zstd_returns_zstd(self) -> None:
        data = b"x" * 100
        _, encoding = compress_payload(data, "zstd")
        assert encoding == "zstd"

    # ── Compression roundtrip fuzz ────────────────────────────────

    def test_brotli_roundtrip(self) -> None:
        data = b"decompression test data " * 50
        compressed, encoding = compress_payload(data, "br")
        assert encoding == "br"
        assert brotli.decompress(compressed) == data

    def test_zstd_roundtrip(self) -> None:
        data = b"zstandard roundtrip " * 50
        compressed, encoding = compress_payload(data, "zstd")
        assert encoding == "zstd"
        dctx = zstd.ZstdDecompressor()
        assert dctx.decompress(compressed) == data

    def test_empty_payload(self) -> None:
        compressed, encoding = compress_payload(b"", "gzip")
        assert encoding == "gzip"
        assert gzip.decompress(compressed) == b""

    def test_single_byte_payload(self) -> None:
        compressed, encoding = compress_payload(b"\xff", "br")
        assert encoding == "br"
        assert brotli.decompress(compressed) == b"\xff"

    def test_binary_payload(self) -> None:
        """Full byte range should compress and decompress correctly."""
        data = bytes(range(256)) * 10
        compressed, encoding = compress_payload(data, "gzip")
        assert gzip.decompress(compressed) == data

    def test_unknown_encoding_passes_through(self) -> None:
        data = b"passthrough"
        result, encoding = compress_payload(data, "deflate")
        assert encoding == ""
        assert result == data

    def test_concurrent_zstd_roundtrip(self) -> None:
        """compress_payload must be safe under concurrent request threads.

        A shared module-level ZstdCompressor is not supported by
        python-zstandard (the C extension releases the GIL during compress,
        so threads shared one ZSTD_CCtx and the process segfaulted).  Each
        thread compresses its own payload; every output must round-trip.
        """
        payloads = [bytes([i % 256]) * 4096 + b"payload-%d" % i for i in range(16)]
        results: list[tuple[bytes, str] | None] = [None] * len(payloads)
        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                results[idx] = compress_payload(payloads[idx], "zstd")
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(payloads))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        dctx = zstd.ZstdDecompressor()
        for idx, (data, res) in enumerate(zip(payloads, results, strict=True)):
            assert res is not None
            compressed, encoding = res
            assert encoding == "zstd"
            assert dctx.decompress(compressed) == data, f"thread {idx} payload corrupted"


# ── Path helpers ───────────────────────────────────────────────────


class TestPathHelpers:
    def test_project_dir_is_absolute(self) -> None:
        assert _project_dir().is_absolute()

    def test_db_path_ends_with_coverage_db(self) -> None:
        assert _db_path().name == "coverage.db"
        assert _db_path().parent.name == "db"

    def test_find_dll_path_none_for_unconfigured_target(self) -> None:
        """A target with no [targets.<tid>].binary must return None, not a
        silently-served fallback (SERVER's DLL) — the caller then reports a
        target-specific error instead of plausible-but-wrong disassembly."""
        clear_target_cache()
        assert _find_dll_path("NONEXISTENT") is None

    def test_find_dll_path_resolves_configured_binary(self, monkeypatch: Any) -> None:
        from unittest.mock import patch

        from recoverage import server as srv

        with (
            patch.object(srv, "_project_dir", return_value=Path("/proj")),
            patch.object(
                srv, "_get_targets_config", return_value={"GAME": {"filename": "bin/game.dll"}}
            ),
        ):
            assert _find_dll_path("GAME") == Path("/proj/bin/game.dll")


# ── DB-freshness ETags ─────────────────────────────────────────────


class TestDbEtag:
    """DB-freshness ETags must key on the WAL-aware snapshot, not raw mtime.

    A rebuild can commit only to coverage.db-wal (main file untouched);
    raw-st_mtime ETags then keep answering 304 and browsers serve stale
    /data, /asm, /bytes, and /potato responses forever.
    """

    def test_snapshot_tracks_wal_file(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        db.write_bytes(b"x" * 64)
        wal = tmp_path / "coverage.db-wal"
        wal.write_bytes(b"")
        monkeypatch.setattr(srv, "_db_path", lambda: db)
        before = srv._snapshot_db_mtime()
        assert before is not None
        wal.write_bytes(b"y" * 64)
        after = srv._snapshot_db_mtime()
        assert after is not None
        assert after != before

    def test_etag_changes_on_wal_only_commit(self, tmp_path: Path, monkeypatch: Any) -> None:
        """The /asm//bytes/potato ETag input must change when only -wal does."""
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        db.write_bytes(b"x" * 64)
        wal = tmp_path / "coverage.db-wal"
        wal.write_bytes(b"")
        monkeypatch.setattr(srv, "_db_path", lambda: db)
        before = srv._etag_or_304(srv._snapshot_db_mtime(), "FAKEDLL", ".text", 16)
        assert before is not None
        wal.write_bytes(b"y" * 64)
        after = srv._etag_or_304(srv._snapshot_db_mtime(), "FAKEDLL", ".text", 16)
        assert after is not None
        assert after != before

    def test_etag_none_when_db_unreadable(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_db_path", lambda: tmp_path / "missing.db")
        assert srv._etag_or_304(srv._snapshot_db_mtime(), "T") is None

    def test_matching_if_none_match_raises_304(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        db.write_bytes(b"x" * 64)
        monkeypatch.setattr(srv, "_db_path", lambda: db)
        etag = srv._etag_or_304(srv._snapshot_db_mtime(), "T")

        class _Req:
            headers = {"If-None-Match": etag}

        monkeypatch.setattr(srv, "request", _Req())
        with pytest.raises(srv.HTTPResponse) as excinfo:
            srv._etag_or_304(srv._snapshot_db_mtime(), "T")
        assert excinfo.value.status_code == 304


# ── clear_target_cache ─────────────────────────────────────────────


class TestClearTargetCache:
    def test_clear_is_safe_when_empty(self) -> None:
        clear_target_cache()
        clear_target_cache()  # should not raise

    def test_thread_safety(self) -> None:
        errors: list[Exception] = []

        def _clear() -> None:
            try:
                for _ in range(100):
                    clear_target_cache()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_clear) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ── LIKE escape consistency ────────────────────────────────────────


class TestLikeEscape:
    """Verify that LIKE wildcard escaping is consistent."""

    def test_percent_escaped(self) -> None:
        assert _escape_like("100%") == "%100\\%%"

    def test_underscore_escaped(self) -> None:
        assert _escape_like("foo_bar") == "%foo\\_bar%"

    def test_no_special_chars(self) -> None:
        assert _escape_like("alloc") == "%alloc%"

    def test_both_wildcards(self) -> None:
        assert _escape_like("100%_test") == "%100\\%\\_test%"

    # ── LIKE escape fuzz ──────────────────────────────────────────

    def test_backslash_in_search(self) -> None:
        """Backslash is the ESCAPE char in LIKE — must be escaped to match literally."""
        result = _escape_like("c:\\path")
        assert result == "%c:\\\\path%"

    def test_consecutive_underscores(self) -> None:
        result = _escape_like("__init__")
        assert result == "%\\_\\_init\\_\\_%"

    def test_all_percents(self) -> None:
        result = _escape_like("%%%")
        assert result == "%\\%\\%\\%%"

    def test_empty_search(self) -> None:
        result = _escape_like("")
        assert result == "%%"

    def test_unicode_search(self) -> None:
        """Unicode chars are not LIKE specials, should pass through."""
        result = _escape_like("日本語")
        assert "日本語" in result

    def test_sql_injection_in_search(self) -> None:
        """SQL injection attempt must have its wildcards escaped."""
        result = _escape_like("' OR 1=1; DROP TABLE--")
        assert "' OR 1=1; DROP TABLE--" in result
        # No unescaped % or _ injected
        assert result == "%' OR 1=1; DROP TABLE--%"

    def test_backslash_before_percent(self) -> None:
        """Input '\\%' must produce escaped backslash + escaped percent, not a wildcard."""
        result = _escape_like("\\%")
        assert result == "%\\\\\\%%"

    def test_backslash_before_underscore(self) -> None:
        """Input '\\_' must produce escaped backslash + escaped underscore."""
        result = _escape_like("\\_")
        assert result == "%\\\\\\_%"


def _create_v4_db(db: Path, functions_columns: str) -> None:
    """Create a minimal v4-shaped DB stamped db_version="4".

    *functions_columns* is the tail of the functions table's column list, so
    tests can omit query-critical columns to exercise the column gate.
    """
    conn = sqlite3.connect(db)
    try:
        c = conn.cursor()
        c.executescript(
            f"""
            CREATE TABLE metadata (target TEXT, key TEXT, value TEXT);
            CREATE TABLE sections (
                target TEXT, name TEXT, va INTEGER, size INTEGER,
                fileOffset INTEGER, unitBytes INTEGER, columns INTEGER
            );
            CREATE TABLE cells (
                target TEXT, section_name TEXT, start INTEGER, end INTEGER,
                span INTEGER, state TEXT, functions TEXT, label TEXT,
                parent_function TEXT
            );
            CREATE TABLE functions (
                target TEXT, va INTEGER, name TEXT, vaStart TEXT, size INTEGER,
                fileOffset INTEGER, status TEXT, module TEXT, cflags TEXT,
                symbol TEXT, markerType TEXT, ghidra_name TEXT, list_name TEXT,
                is_thunk INTEGER, is_export INTEGER, sha256 TEXT, files TEXT,
                detected_by TEXT, size_by_tool TEXT, {functions_columns}
            );
            CREATE TABLE globals (
                target TEXT, va INTEGER, name TEXT, decl TEXT, files TEXT,
                module TEXT, size INTEGER
            );
            CREATE TABLE verify_results (
                target TEXT, va INTEGER, verified_at TEXT, byte_delta INTEGER,
                diff_lines INTEGER, similarity REAL
            );
            CREATE TABLE history (
                id INTEGER, target TEXT, va INTEGER, old_status TEXT,
                new_status TEXT, changed_at TEXT
            );
            CREATE VIEW section_cell_stats AS
                SELECT target, section_name, COUNT(*) AS total_cells,
                0 AS exact_count, 0 AS reloc_count, 0 AS near_match_count,
                0 AS stub_count, 0 AS padding_count, 0 AS data_count,
                0 AS thunk_count, 0 AS none_count, 0 AS proven_count,
                0 AS size_mismatch_count
                FROM cells GROUP BY target, section_name;
            """
        )
        c.execute("INSERT INTO metadata VALUES ('__schema__', 'db_version', '\"4\"')")
        conn.commit()
    finally:
        conn.close()


_FN_COLUMNS_FULL = (
    "textOffset INTEGER, blocker TEXT, blockerDelta INTEGER, size_reason TEXT, similarity REAL"
)
_FN_COLUMNS_NO_TEXT_OFFSET = "blocker TEXT, blockerDelta INTEGER, size_reason TEXT, similarity REAL"


class TestSchemaShapeGuard:
    """A DB stamped with a known version but missing required schema objects
    must report <incomplete> (endpoints then return the 503 contract)."""

    def test_missing_object_reports_incomplete(self, tmp_path: Any) -> None:
        import sqlite3

        from recoverage import server as srv

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        c.execute("INSERT INTO metadata VALUES ('__schema__', 'db_version', '\"4\"')")
        c.execute("CREATE TABLE sections (id INTEGER)")
        # Deliberately omit history + section_cell_stats view.
        conn.commit()
        conn.close()

        with contextlib.closing(sqlite3.connect(db)) as conn2:
            assert srv._check_schema_version_uncached(conn2) == "<incomplete>"

    def test_complete_db_reports_version(self, tmp_path: Any) -> None:
        import sqlite3

        from recoverage import server as srv

        db = tmp_path / "coverage.db"
        # A complete v4 DB: the shape guard now verifies the query-critical
        # columns, not just table names.
        _create_v4_db(db, _FN_COLUMNS_FULL)

        with contextlib.closing(sqlite3.connect(db)) as conn2:
            assert srv._check_schema_version_uncached(conn2) == "4"


class TestSchemaColumnGate:
    def test_missing_column_reports_incomplete(self, tmp_path: Any) -> None:
        """A complete v4 object set with ONE required column missing must
        report <incomplete> — the name-only gate would pass it and the
        dashboard would 500 at query time."""
        import sqlite3

        from recoverage import server as srv

        db = tmp_path / "coverage.db"
        _create_v4_db(db, _FN_COLUMNS_NO_TEXT_OFFSET)
        # functions intentionally lacks the query-critical textOffset column
        # (see _FN_COLUMNS_NO_TEXT_OFFSET) — the column gate must reject it
        # even though every object name is present.

        with contextlib.closing(sqlite3.connect(db)) as conn2:
            assert srv._check_schema_version_uncached(conn2) == "<incomplete>"


class TestDeepLinking:
    """J9: the SPA carries URL deep-link wiring (target/fn/section/q)."""

    def test_spa_has_deep_link_code(self) -> None:
        import importlib.resources

        from recoverage import assets

        app_js = importlib.resources.files(assets).joinpath("app.js").read_text(encoding="utf-8")
        for marker in (
            "URL_PARAMS = new URLSearchParams",
            "const syncUrl = () =>",
            'params.set("target"',
            'params.set("fn"',
            'params.set("section"',
            'params.set("q"',
            "history.replaceState",
        ):
            assert marker in app_js, f"deep-link marker missing: {marker}"


# ── Token auth & security headers ──────────────────────────────────


class TestAuthTokenMatches:
    """_auth_token_matches must accept the right token only, in constant time."""

    def test_correct_token_accepted(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "hunter2")
        assert srv._auth_token_matches("hunter2") is True

    def test_wrong_token_rejected(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "hunter2")
        assert srv._auth_token_matches("hunter3") is False

    def test_empty_config_token_never_matches(self, monkeypatch: Any) -> None:
        """No --token configured means the helper must not authenticate."""
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "")
        assert srv._auth_token_matches("") is False


class TestTokenAuthEndpoint:
    """WSGI-level behavior of the --token gate, incl. guess throttling."""

    @pytest.fixture(autouse=True)
    def _token(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "unit-test-token")
        yield
        srv._clear_auth_failures()

    def test_missing_token_is_401(self) -> None:
        from conftest import wsgi_get

        status, _, _ = wsgi_get("/api/health")
        assert status.startswith("401")

    def test_failed_auth_is_audit_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """A rejected token attempt must leave an audit trail (brute-force
        visibility) without ever logging the attempted token value."""
        from conftest import wsgi_get

        with caplog.at_level(logging.WARNING, logger="recoverage"):
            wsgi_get("/api/health", headers={"Authorization": "Bearer wrong-guess-123"})
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("invalid auth token" in r.getMessage() for r in warnings)
        assert all("wrong-guess-123" not in r.getMessage() for r in caplog.records)

    def test_bearer_token_accepted(self) -> None:
        from conftest import wsgi_get

        status, _, _ = wsgi_get("/api/health", headers={"Authorization": "Bearer unit-test-token"})
        assert status.startswith("200")

    def test_rate_limit_after_max_failures(self) -> None:
        from conftest import wsgi_get

        from recoverage.server import _AUTH_FAIL_MAX

        codes = []
        for _ in range(_AUTH_FAIL_MAX + 2):
            status, _, _ = wsgi_get("/api/health")
            codes.append(status.split()[0])
        assert codes[:_AUTH_FAIL_MAX] == ["401"] * _AUTH_FAIL_MAX
        assert all(c == "429" for c in codes[_AUTH_FAIL_MAX:])

    def test_query_param_token_accepted(self) -> None:
        """The documented share-link flow: /?token=<token> authenticates."""
        from conftest import wsgi_get

        status, _, _ = wsgi_get("/api/health?token=unit-test-token")
        assert status.startswith("200")

    def test_cookie_token_accepted(self) -> None:
        """After the SPA cookie is set, plain navigation authenticates."""
        from conftest import wsgi_get

        status, _, _ = wsgi_get(
            "/api/health", headers={"Cookie": "recoverage_token=unit-test-token"}
        )
        assert status.startswith("200")

    def test_ui_route_gets_html_401_page(self) -> None:
        """A browser asking for a page gets the human-readable 401 page,
        not a raw JSON blob with no instructions."""
        from conftest import wsgi_get

        status, headers, body = wsgi_get("/", headers={"Accept": "text/html"})
        assert status.startswith("401")
        assert "text/html" in headers.get("Content-Type", "")
        assert b"Access token required" in body

    def test_api_route_stays_json_401_despite_html_accept(self) -> None:
        """API consumers keep the JSON error contract even when they send
        Accept: text/html — only UI routes get the page."""
        from conftest import wsgi_get

        status, headers, body = wsgi_get(
            "/api/health",
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        assert status.startswith("401")
        assert headers.get("Content-Type", "").startswith("application/json")
        data = json.loads(body)
        assert data["code"] == "unauthorized"

    def test_valid_token_on_index_sets_httponly_cookie(self) -> None:
        """Opening / as /?token=<token> must set the SPA's HttpOnly cookie."""
        from conftest import wsgi_get

        status, headers, _ = wsgi_get("/?token=unit-test-token")
        assert status.startswith("200")
        cookie = headers.get("Set-Cookie", "")
        assert "recoverage_token=" in cookie
        assert "HttpOnly" in cookie


class TestAuthFailureLimiter:
    """Unit behavior of the failure window."""

    def test_success_clears_failures(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "tok")
        try:
            for _ in range(srv._AUTH_FAIL_MAX - 1):
                srv._record_auth_failure(time.monotonic())
            assert not srv._auth_rate_limited(time.monotonic())
            # A successful match wipes the slate.
            assert srv._auth_token_matches("tok")
            srv._clear_auth_failures()
            assert not srv._auth_rate_limited(time.monotonic())
        finally:
            srv._clear_auth_failures()

    def test_old_entries_expire_from_window(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        try:
            old = time.monotonic() - srv._AUTH_FAIL_WINDOW_SECONDS * 2
            for _ in range(srv._AUTH_FAIL_MAX):
                srv._record_auth_failure(old)
            assert not srv._auth_rate_limited(time.monotonic())
        finally:
            srv._clear_auth_failures()

    def test_concurrent_reserves_never_exceed_cap(self, monkeypatch: Any) -> None:
        """A burst of simultaneous bad-token requests must not slip past the
        cap: the cap check and the slot append share one critical section
        (_auth_throttle), so exactly _AUTH_FAIL_MAX reservations succeed no
        matter how many threads race the window."""
        import recoverage.server as srv

        workers = srv._AUTH_FAIL_MAX * 6
        barrier = threading.Barrier(workers)
        reserved: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            got = srv._auth_throttle(time.monotonic(), reserve_slot=True)
            with lock:
                reserved.append(got)

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        finally:
            srv._clear_auth_failures()

        assert all(t.ident is not None for t in threads)
        assert len(reserved) == workers
        assert reserved.count(False) == srv._AUTH_FAIL_MAX
        assert reserved.count(True) == workers - srv._AUTH_FAIL_MAX


class TestEvictOldest:
    """Bounded-cache arithmetic shared by the /data memo and Potato cells
    memo: callers invoke it BEFORE inserting, so at-capacity caches shed
    exactly one entry."""

    def test_under_cap_is_noop(self) -> None:
        from recoverage.server import _evict_oldest

        cache = dict.fromkeys(range(5))
        _evict_oldest(cache, 8)
        assert len(cache) == 5

    def test_empty_cache_is_noop(self) -> None:
        from recoverage.server import _evict_oldest

        cache: dict[int, int] = {}
        _evict_oldest(cache, 8)
        assert cache == {}

    def test_at_cap_evicts_single_oldest(self) -> None:
        from recoverage.server import _evict_oldest

        cache = dict.fromkeys(range(8))
        _evict_oldest(cache, 8)
        assert len(cache) == 7
        assert 0 not in cache  # insertion-order oldest dropped first

    def test_far_over_cap_drops_down_below_cap(self) -> None:
        from recoverage.server import _evict_oldest

        cache = dict.fromkeys(range(20))
        _evict_oldest(cache, 8)
        assert len(cache) < 8
        assert set(cache) == set(range(13, 20))  # newest kept, oldest gone


class TestHostnameOf:
    """_hostname_of is the parser behind BOTH the DNS-rebinding Host
    allowlist and the regen Origin check — values that browsers never emit
    (userinfo, escapes, control bytes) must parse as "" so they can never
    match an allowlist entry."""

    def test_bare_host_with_port(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("localhost:8001") == "localhost"

    def test_origin_url(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("http://localhost:5173") == "localhost"

    def test_uppercase_lowered(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("HTTP://LOCALHOST:8001") == "localhost"

    @pytest.mark.parametrize(
        "origin",
        [
            "http://evil@localhost",  # userinfo spoofing
            "http://local\\\\host",  # backslash confusion
            "http://loc%61lhost",  # percent-encoding
            "http://loc\x01alhost",  # control byte
            "http://[::1",  # unparsable IPv6
            "",
        ],
    )
    def test_non_plain_values_parse_empty(self, origin: str) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of(origin) == ""

    def test_junk_host_never_matches_allowlist(self) -> None:
        """Garbage without scheme separators parses as a literal hostname;
        the contract that matters is that it can never equal an allowlisted
        loopback name."""
        from recoverage.server import LOOPBACK_HOSTS, _hostname_of

        junk = _hostname_of("not a url at all")
        assert junk not in LOOPBACK_HOSTS

    def test_ipv6_literal_kept(self) -> None:
        from recoverage.server import _hostname_of

        assert _hostname_of("http://[::1]:8001") == "::1"


class TestSecurityHeaders:
    """Every response carries the hardening header set."""

    EXPECTED = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }

    @pytest.mark.parametrize(("header", "value"), sorted(EXPECTED.items()))
    def test_headers_on_api_response(self, header: str, value: str) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/api/health")
        assert headers.get(header) == value

    def test_csp_on_api_response(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/api/health")
        csp = headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "base-uri 'none'" in csp
        # The SPA injects VanJS + app.js inline; the policy must allow that.
        assert "script-src 'self' 'unsafe-inline'" in csp

    def test_csp_allows_spa_inline_script_and_self_connect(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/")
        csp = headers.get("Content-Security-Policy", "")
        assert "'unsafe-inline'" in csp
        assert "connect-src 'self'" in csp


class TestLogInjection:
    """Request-derived log fields cannot forge multi-line entries: the path
    is percent-decoded by the time it reaches the app, so %0A arrives as a
    raw newline unless escaped before logging."""

    def test_log_safe_escapes_control_characters(self) -> None:
        from recoverage.server import _log_safe

        assert _log_safe("normal/path?q=1") == "normal/path?q=1"
        assert _log_safe("a\nb\rc\x00d\x7f") == "a\\x0ab\\x0dc\\x00d\\x7f"

    def test_newline_in_path_stays_one_log_line(self, caplog: pytest.LogCaptureFixture) -> None:
        from conftest import wsgi_get

        with caplog.at_level(logging.DEBUG, logger="recoverage"):
            wsgi_get("/api/health\nX-Forged: yes")
        msgs = [r.getMessage() for r in caplog.records if r.name == "recoverage"]
        assert any("X-Forged" in m for m in msgs), "request was not logged at all"
        assert all("\n" not in m and "\r" not in m for m in msgs)


class TestLoadDllTransientFailure:
    """A transient DLL read failure must NOT be negative-cached: caching
    ``DLL_DATA[target] = None`` would keep the target's /asm and /bytes
    endpoints failing until the next rebuild broadcast clears the cache,
    even after the file comes back."""

    def test_os_failure_not_cached_and_self_heals(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        key = "__transient_test_target__"
        holder: dict[str, Path] = {"p": tmp_path / "missing.dll"}
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: holder["p"])
        try:
            # stat() on the absent path raises FileNotFoundError inside
            # _load_dll's OSError handler: logged, returned as None, NOT stored.
            assert srv._load_dll(key) is None
            assert key not in srv.DLL_DATA

            # The file comes back (build finished, lock released): retrying on
            # the next request self-heals with no cache invalidation in between.
            real = tmp_path / "real.dll"
            real.write_bytes(b"MZ-fake-binary")
            holder["p"] = real
            assert srv._load_dll(key) == b"MZ-fake-binary"
            assert srv.DLL_DATA[key] == b"MZ-fake-binary"

            # A later transient failure cannot poison the cached success.
            holder["p"] = tmp_path / "gone-again.dll"
            assert srv._load_dll(key) == b"MZ-fake-binary"
        finally:
            with srv.DLL_LOCK:
                srv.DLL_DATA.pop(key, None)


class TestGetDisassemblyNoNegativeCache:
    """get_disassembly must not memoize the "" result of a DLL-load failure.

    The memo sits BELOW the load guard: caching "" under (va, size,
    file_offset, target) would pin a transient read failure past recovery
    (the exact scenario _load_dll's no-negative-cache contract exists for),
    replaying empty disassembly until the next rebuild broadcast.
    """

    def test_load_failure_bypasses_memo_and_self_heals(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        import recoverage.server as srv

        key = "__disasm_transient_target__"
        holder: dict[str, Path] = {"p": tmp_path / "missing.dll"}
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: holder["p"])

        calls: list[tuple[int, int, int, str]] = []

        def fake_impl(va: int, size: int, file_offset: int, target: str) -> str:
            calls.append((va, size, file_offset, target))
            return f"disasm:{va:#x}"

        monkeypatch.setattr(srv, "_disassemble_loaded", fake_impl)
        try:
            # Load fails: the caller sees "" and the memo was never consulted.
            assert srv.get_disassembly(0x1000, 4, 0, key) == ""
            assert calls == []

            # The binary comes back: the same slice disassembles for real
            # instead of replaying the pinned "".
            real = tmp_path / "real.dll"
            real.write_bytes(b"MZ-fake-binary")
            holder["p"] = real
            assert srv.get_disassembly(0x1000, 4, 0, key) == "disasm:0x1000"
            assert calls == [(0x1000, 4, 0, key)]
        finally:
            with srv.DLL_LOCK:
                srv.DLL_DATA.pop(key, None)

    def test_clear_derived_caches_clears_disassembly_memo(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Rebuilds must evict memoized disassembly through the shared
        invalidation entry point (wiring guard for the split cache)."""
        import recoverage.api
        import recoverage.server as srv

        key = "__disasm_invalidation_target__"
        holder: dict[str, Path] = {"p": tmp_path / "missing.dll"}
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: holder["p"])
        real = tmp_path / "real.dll"

        @srv.functools.lru_cache(maxsize=16)
        def _prime(va: int, size: int, file_offset: int, target: str) -> str:
            return "cached"

        monkeypatch.setattr(srv, "_disassemble_loaded", _prime)
        try:
            holder["p"] = real
            real.write_bytes(b"MZ-fake-binary")
            assert srv.get_disassembly(0x2000, 1, 0, key) == "cached"
            assert _prime.cache_info().currsize == 1
            recoverage.api._clear_derived_caches()
            assert _prime.cache_info().currsize == 0
        finally:
            with srv.DLL_LOCK:
                srv.DLL_DATA.pop(key, None)
        _prime.cache_clear()
