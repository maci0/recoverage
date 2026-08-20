"""Tests for recoverage.server — compression, encoding, path helpers, response helpers."""

from __future__ import annotations

import contextlib
import gzip
import threading
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
        conn = sqlite3.connect(db)
        c = conn.cursor()
        # A complete v4 DB: the shape guard now verifies the query-critical
        # columns, not just table names.
        c.executescript(
            """
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
                detected_by TEXT, size_by_tool TEXT, textOffset INTEGER,
                blocker TEXT, blockerDelta INTEGER, size_reason TEXT,
                similarity REAL
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
        conn.close()

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
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.executescript(
            """
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
                detected_by TEXT, size_by_tool TEXT, blocker TEXT,
                blockerDelta INTEGER, size_reason TEXT, similarity REAL
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
        # functions intentionally lacks the query-critical textOffset column
        # (the schema above omits it) — the column gate must reject it even
        # though every object name is present.
        c.execute("INSERT INTO metadata VALUES ('__schema__', 'db_version', '\"4\"')")
        conn.commit()
        conn.close()

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
