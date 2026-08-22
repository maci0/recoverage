"""Tests for recoverage.server — compression, encoding, path helpers, response helpers."""

from __future__ import annotations

import contextlib
import gzip
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
    minify_css,
    minify_js,
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
            except BaseException as exc:  # noqa: BLE001 — surface worker crashes
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


# ── Minification ───────────────────────────────────────────────────


class TestMinification:
    def test_minify_css_removes_whitespace(self) -> None:
        css = "body {\n  color: red;\n  margin: 0;\n}"
        result = minify_css(css)
        assert len(result) < len(css)
        assert "color:red" in result or "color: red" in result

    def test_minify_js_removes_whitespace(self) -> None:
        js = "function foo() {\n  return 42;\n}"
        result = minify_js(js)
        assert len(result) <= len(js)
        assert "return 42" in result

    def test_minify_css_empty(self) -> None:
        assert minify_css("") == ""

    def test_minify_js_empty(self) -> None:
        assert minify_js("") == ""

    def test_minify_css_already_minified(self) -> None:
        css = "body{color:red;margin:0}"
        result = minify_css(css)
        assert "color:red" in result

    def test_minify_js_preserves_strings(self) -> None:
        """String literals with whitespace must be preserved."""
        js = 'var x = "hello   world";'
        result = minify_js(js)
        assert "hello   world" in result


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


# ── clear_target_cache ─────────────────────────────────────────────


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
        before = srv._etag_or_304("FAKEDLL", ".text", 16)
        assert before is not None
        wal.write_bytes(b"y" * 64)
        after = srv._etag_or_304("FAKEDLL", ".text", 16)
        assert after is not None
        assert after != before

    def test_etag_none_when_db_unreadable(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_db_path", lambda: tmp_path / "missing.db")
        assert srv._etag_or_304("T") is None

    def test_matching_if_none_match_raises_304(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        db.write_bytes(b"x" * 64)
        monkeypatch.setattr(srv, "_db_path", lambda: db)
        etag = srv._etag_or_304("T")

        class _Req:
            headers = {"If-None-Match": etag}

        monkeypatch.setattr(srv, "request", _Req())
        with pytest.raises(srv.HTTPResponse) as excinfo:
            srv._etag_or_304("T")
        assert excinfo.value.status_code == 304


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
            'p.set("target"',
            'p.set("fn"',
            'p.set("section"',
            'p.set("q"',
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


class TestSecurityHeaders:
    """Every response carries the hardening header set."""

    EXPECTED = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }

    @pytest.mark.parametrize(
        ("header", "value"),
        [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
        ],
    )
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
