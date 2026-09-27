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
from typing import IO, Any, ClassVar

import brotli
import pytest
import zstandard as zstd

from recoverage.server import (
    DLL_DATA,
    DLL_LOCK,
    SCHEMA_TARGET,
    _best_encoding,
    _db_path,
    _escape_like,
    _find_dll_path,
    _load_dll,
    _project_dir,
    clear_target_cache,
    compress_payload,
)

# ── Advisory-lock probe ────────────────────────────────────────────


def _probe_free_lock(fh: IO[bytes]) -> None:
    """Raise BlockingIOError unless *fh*'s advisory lock is free.

    Mirrors the split the production lock makes (rebrew's
    ``file_handle_lock``: ``fcntl`` on POSIX, ``msvcrt`` elsewhere), so the
    caller probes the same mechanism the server takes on this platform —
    importing fcntl unconditionally would fail the run on the Windows
    CI runner.
    """
    try:
        import fcntl
    except ImportError:  # Windows
        import msvcrt

        fh.seek(0)
        try:
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError(str(exc)) from exc
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        return
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(fh, fcntl.LOCK_UN)


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
        compressed, _encoding = compress_payload(data, "gzip")
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
            headers: ClassVar[dict[str, str]] = {"If-None-Match": etag}

        monkeypatch.setattr(srv, "request", _Req())
        with pytest.raises(srv.HTTPResponse) as excinfo:
            srv._etag_or_304(srv._snapshot_db_mtime(), "T")
        assert excinfo.value.status_code == 304


# ── clear_target_cache ─────────────────────────────────────────────


class TestClearTargetCache:
    def test_clear_is_safe_when_empty(self) -> None:
        """Clearing an already-empty cache is a no-op, not a KeyError.

        Asserting the resulting state rather than "did not raise" also pins
        the part that is easy to get wrong: a second clear must leave every
        global None, not a half-reset pair.
        """
        import recoverage.server as srv

        clear_target_cache()
        srv._TOML_CONFIG_CACHE = {"a": 1}
        srv._TOML_CACHE_MTIME = (1, 2)
        srv._RESOLVED_TARGETS_CACHE = ["T"]
        srv._SCHEMA_VERSION_CACHE = 3

        clear_target_cache()
        assert srv._TOML_CONFIG_CACHE is None
        assert srv._TOML_CACHE_MTIME is None
        assert srv._RESOLVED_TARGETS_CACHE is None
        assert srv._SCHEMA_VERSION_CACHE is None

        # Idempotent: a second clear over the emptied state changes nothing.
        clear_target_cache()
        assert srv._TOML_CONFIG_CACHE is None
        assert srv._RESOLVED_TARGETS_CACHE is None

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


def _create_v4_db(db: Path, functions_columns: str, *, version: str = "4") -> None:
    """Create a minimal v4-shaped DB stamped with *version*.

    *functions_columns* is the tail of the functions table's column list, so
    tests can omit query-critical columns to exercise the column gate.
    The column set is what v4 through v10 share; *version* only changes the
    stamp.
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
        c.execute(
            "INSERT INTO metadata VALUES (?, 'db_version', ?)",
            (SCHEMA_TARGET, f'"{version}"'),
        )
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
        c.execute(
            "INSERT INTO metadata VALUES (?, 'db_version', '\"4\"')",
            (SCHEMA_TARGET,),
        )
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


class TestCurrentRebrewSchema:
    """The installed rebrew's stamp must be a version this server accepts."""

    def test_stamp_is_known_and_column_gated(self, tmp_path: Any) -> None:
        import sqlite3

        from rebrew.build_db import _CURRENT_DB_VERSION

        from recoverage import server as srv

        assert _CURRENT_DB_VERSION in srv.KNOWN_SCHEMA_VERSIONS
        db = tmp_path / "coverage.db"
        _create_v4_db(db, _FN_COLUMNS_FULL, version=_CURRENT_DB_VERSION)
        with contextlib.closing(sqlite3.connect(db)) as conn:
            assert srv._check_schema_version_uncached(conn) == _CURRENT_DB_VERSION

        incomplete = tmp_path / "incomplete.db"
        _create_v4_db(incomplete, _FN_COLUMNS_NO_TEXT_OFFSET, version=_CURRENT_DB_VERSION)
        with contextlib.closing(sqlite3.connect(incomplete)) as conn:
            assert srv._check_schema_version_uncached(conn) == "<incomplete>"


class TestReadOnlyOpen:
    def test_open_db_rejects_writes(self, tmp_path: Path) -> None:
        import sqlite3

        from recoverage import server as srv

        db = tmp_path / "coverage.db"
        sqlite3.connect(db).close()
        conn = srv._open_db(db)
        try:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("CREATE TABLE blocked (id INTEGER)")
        finally:
            conn.close()

    def test_shared_lock_drops_when_the_connection_is_collected(self, tmp_path: Path) -> None:
        import gc
        import sqlite3

        from recoverage import server as srv

        db = tmp_path / "coverage.db"
        sqlite3.connect(db).close()
        conn = srv._open_db(db)
        lock_path = db.with_name(db.name + ".lock")
        # Binary handles: msvcrt.locking needs a fileno it can lock a byte
        # range on, and fcntl behaves the same on one.
        held = lock_path.open("ab")
        try:
            with pytest.raises(BlockingIOError):
                _probe_free_lock(held)
        finally:
            held.close()

        conn.close()
        del conn
        gc.collect()

        held = lock_path.open("ab")
        try:
            _probe_free_lock(held)
        finally:
            held.close()


class TestReadSnapshot:
    """A multi-statement read must see ONE database version.

    Python's sqlite3 begins a deferred transaction per statement, so a
    rebuild committing between two reads of the same table would answer the
    second from the new build. `read_snapshot` pins the snapshot for the
    block instead.
    """

    @staticmethod
    def _wal_db(tmp_path: Path) -> Path:
        import sqlite3

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE sections (target TEXT, name TEXT, size INTEGER)")
        conn.execute("INSERT INTO sections VALUES ('GAME', '.text', 16)")
        conn.commit()
        conn.close()
        return db

    def test_rebuild_mid_block_is_invisible(self, tmp_path: Path) -> None:
        import sqlite3

        from recoverage import server as srv

        db = self._wal_db(tmp_path)
        conn = srv._open_db(db)
        try:
            c = conn.cursor()
            with srv.read_snapshot(c):
                c.execute("SELECT size FROM sections WHERE target = 'GAME'")
                before = c.fetchone()[0]

                writer = sqlite3.connect(db)
                try:
                    writer.execute("UPDATE sections SET size = 99")
                    writer.commit()
                finally:
                    writer.close()

                c.execute("SELECT size FROM sections WHERE target = 'GAME'")
                during = c.fetchone()[0]
            # Outside the block the next statement sees the committed rebuild.
            c.execute("SELECT size FROM sections WHERE target = 'GAME'")
            after = c.fetchone()[0]
        finally:
            conn.close()

        assert before == during == 16
        assert after == 99

    def test_block_closes_the_transaction(self, tmp_path: Path) -> None:
        from recoverage import server as srv

        conn = srv._open_db(self._wal_db(tmp_path))
        try:
            c = conn.cursor()
            with srv.read_snapshot(c):
                c.execute("SELECT 1 FROM sections")
            assert not conn.in_transaction
        finally:
            conn.close()

    def test_nested_inside_an_open_transaction_is_a_noop(self, tmp_path: Path) -> None:
        """The CLI reuses one connection across commands; SQLite has no
        nested BEGIN, and the outer transaction already pins the snapshot."""
        from recoverage import server as srv

        conn = srv._open_db(self._wal_db(tmp_path))
        try:
            c = conn.cursor()
            conn.execute("BEGIN")
            with srv.read_snapshot(c):
                c.execute("SELECT 1 FROM sections")
            assert conn.in_transaction, "read_snapshot closed the caller's transaction"
            conn.rollback()
        finally:
            conn.close()


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
        assert headers.get("Cache-Control") == "no-store"
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

    # Far above what the in-process burst below needs, low enough that a wedged
    # worker fails the test instead of stalling the run.
    _WORKER_TIMEOUT_SECONDS = 30.0

    def test_success_clears_failures(self, monkeypatch: Any) -> None:
        """A request carrying the right token empties a FULL window.  Only
        _require_auth calls _clear_auth_failures, so the assertion is made
        after a real WSGI request: calling the helper here instead would stay
        green with the production call deleted."""
        from conftest import wsgi_get

        import recoverage.server as srv

        monkeypatch.setattr(srv, "_AUTH_TOKEN", "tok")
        try:
            for _ in range(srv._AUTH_FAIL_MAX):
                srv._auth_throttle(time.monotonic(), reserve_slot=True)
            # The window is full, so the next failure is a 429 ...
            assert srv._auth_throttle(time.monotonic(), reserve_slot=False)
            status, _, _ = wsgi_get("/api/health?token=tok")
            assert status.startswith("200")
            # ... and the verified request wiped the slate.
            assert not srv._auth_throttle(time.monotonic(), reserve_slot=False)
        finally:
            srv._clear_auth_failures()

    def test_old_entries_expire_from_window(self, monkeypatch: Any) -> None:
        import recoverage.server as srv

        try:
            old = time.monotonic() - srv._AUTH_FAIL_WINDOW_SECONDS * 2
            for _ in range(srv._AUTH_FAIL_MAX):
                srv._auth_throttle(old, reserve_slot=True)
            assert not srv._auth_throttle(time.monotonic(), reserve_slot=False)
        finally:
            srv._clear_auth_failures()

    def test_concurrent_reserves_never_exceed_cap(self, monkeypatch: Any) -> None:
        """A burst of simultaneous bad-token requests must not slip past the
        cap: the cap check and the slot append share one critical section
        (_auth_throttle), so exactly _AUTH_FAIL_MAX reservations succeed no
        matter how many threads race the window.

        A wedged worker must FAIL the test, never hang the run: the barrier
        bounds how long the workers wait for one another and the join bounds
        how long this test waits for them.  Each worker flags its own Event
        after recording, so a worker that died without recording is caught
        too (Thread.ident cannot detect that: start() sets it permanently).
        """
        import recoverage.server as srv

        workers = srv._AUTH_FAIL_MAX * 6
        barrier = threading.Barrier(workers)
        reserved: list[bool] = []
        lock = threading.Lock()
        done = [threading.Event() for _ in range(workers)]

        def worker(finished: threading.Event) -> None:
            barrier.wait(timeout=self._WORKER_TIMEOUT_SECONDS)
            got = srv._auth_throttle(time.monotonic(), reserve_slot=True)
            with lock:
                reserved.append(got)
            finished.set()

        threads = [threading.Thread(target=worker, args=(ev,)) for ev in done]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=self._WORKER_TIMEOUT_SECONDS)
        finally:
            srv._clear_auth_failures()

        assert [t for t in threads if t.is_alive()] == [], "worker thread wedged"
        assert all(ev.is_set() for ev in done)
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


class TestStaticAssetRevalidation:
    """Static assets answer If-None-Match with a 304 and no body.

    Cache-Control is no-cache, so the browser revalidates on every load; with
    no validator the only answer was the full body again (45 KB of hljs.min.js
    per asm pane, 9.5 KB of detail.js per visit). The ETag must be stable
    across requests, distinct per encoding, and must reject a stale tag.

    wsgiref title-cases header names on the way out, so the tag arrives as
    "Etag"; HTTP field names are case-insensitive either way.
    """

    def test_asset_carries_an_etag(self) -> None:
        from conftest import wsgi_get

        status, headers, body = wsgi_get("/detail.js", headers={"Accept-Encoding": "gzip"})
        assert status == "200 OK"
        assert headers["Etag"]
        assert body

    def test_matching_if_none_match_returns_empty_304(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/detail.js", headers={"Accept-Encoding": "gzip"})
        etag = headers["Etag"]
        status, headers_304, body = wsgi_get(
            "/detail.js",
            headers={"Accept-Encoding": "gzip", "If-None-Match": etag},
        )
        assert status == "304 Not Modified"
        assert body == b""
        assert headers_304["Etag"] == etag
        assert headers_304["Vary"] == "Accept-Encoding"

    def test_weak_validator_still_matches(self) -> None:
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/detail.js", headers={"Accept-Encoding": "gzip"})
        weak = f"W/{headers['Etag']}"
        status, _, _ = wsgi_get(
            "/detail.js", headers={"Accept-Encoding": "gzip", "If-None-Match": weak}
        )
        assert status == "304 Not Modified"

    def test_stale_etag_gets_the_full_body(self) -> None:
        from conftest import wsgi_get

        status, _, body = wsgi_get(
            "/detail.js",
            headers={"Accept-Encoding": "gzip", "If-None-Match": '"not-the-tag"'},
        )
        assert status == "200 OK"
        assert body

    def test_etag_differs_per_encoding(self) -> None:
        """br and zstd are different representations of the same file: a
        strong validator must not match across them."""
        from conftest import wsgi_get

        _, br_headers, _ = wsgi_get("/detail.js", headers={"Accept-Encoding": "br"})
        _, zstd_headers, _ = wsgi_get("/detail.js", headers={"Accept-Encoding": "zstd"})
        assert br_headers["Etag"] != zstd_headers["Etag"]

    def test_index_revalidates_instead_of_resending(self) -> None:
        """The shell is static, so a repeat visit must answer 304.

        It used to be the one response served no-store with no validator, so
        every reload re-downloaded the whole document while every subordinate
        asset answered 304.
        """
        from conftest import wsgi_get

        status, headers, _ = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        assert status == "200 OK"
        assert headers["Cache-Control"] == "no-cache, must-revalidate"
        etag = headers["Etag"]

        status_304, headers_304, body_304 = wsgi_get(
            "/", headers={"Accept-Encoding": "gzip", "If-None-Match": etag}
        )
        assert status_304 == "304 Not Modified"
        assert body_304 == b""
        assert headers_304["Etag"] == etag
        assert headers_304["Vary"] == "Accept-Encoding"

    def test_index_etag_differs_per_encoding(self) -> None:
        """Same rule as the static assets: a strong validator must not match
        across representations."""
        from conftest import wsgi_get

        _, br_headers, _ = wsgi_get("/", headers={"Accept-Encoding": "br"})
        _, zstd_headers, _ = wsgi_get("/", headers={"Accept-Encoding": "zstd"})
        assert br_headers["Etag"] != zstd_headers["Etag"]

    def test_index_preloads_detail_js(self) -> None:
        """detail.js is requested by the inlined app.js, so the shell
        advertises it during the preload scan instead of a round trip later."""
        from conftest import decode_body, wsgi_get

        _, headers, body = wsgi_get("/", headers={"Accept-Encoding": "gzip"})
        html = decode_body(body, headers).decode("utf-8")
        assert 'rel="preload"' in html
        assert 'href="/detail.js"' in html
        assert 'as="script"' in html


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

    EXPECTED: ClassVar[dict[str, str]] = {
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

    def test_potato_page_forces_revalidation(self) -> None:
        """Potato Mode is the one DB-derived response that used to carry no
        cache directive at all, leaving heuristic freshness to the browser and
        storage-plus-replay to any shared cache in front of the dashboard."""
        from conftest import wsgi_get

        _, headers, _ = wsgi_get("/potato")
        assert headers.get("Cache-Control") == "no-cache, must-revalidate"
        # bottle normalizes header names to Title-Case ("Etag").
        assert headers.get("Etag")


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

    def test_target_id_cannot_forge_a_dll_log_line(self, caplog: pytest.LogCaptureFixture) -> None:
        """Target ids are routable request data and originate in analyzed
        binary names, so the DLL loader's warnings carry them through
        _log_safe like every other request-derived log field does."""
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            with DLL_LOCK:
                DLL_DATA.clear()
            assert _load_dll("evil\nX-Forged: yes") is None
        msgs = [r.getMessage() for r in caplog.records if r.name == "recoverage"]
        assert any("X-Forged" in m for m in msgs), "failure was not logged at all"
        assert all("\n" not in m and "\r" not in m for m in msgs)
        with DLL_LOCK:
            DLL_DATA.clear()


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


class TestBucketReconciliation:
    """total_cells must equal the sum of the counted buckets on BOTH paths.

    rebrew's build_db writes an `other_count` catch-all into
    section_cell_stats for exactly this reason: without it the residual states
    (compile_error, extract_error, invalid_va, missing_file, missing_size,
    skip, unknown, drift, unchecked) vanish and the buckets silently
    undercount.  The live-query fallback carried no such catch-all, so the
    same database answered two different totals depending on whether the
    materialized table was present.
    """

    # Every short key _cell_bucket_row emits except total_cells, which is the
    # sum they must reconcile with.
    BUCKET_KEYS = (
        "exact",
        "reloc",
        "near_match",
        "stub",
        "padding",
        "data",
        "thunk",
        "none",
        "proven",
        "size_mismatch",
        "other",
    )

    @staticmethod
    def _reconciles(sec: dict[str, Any]) -> None:
        assert sum(sec[k] for k in TestBucketReconciliation.BUCKET_KEYS) == sec["total_cells"]

    @staticmethod
    def _cells_db() -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "CREATE TABLE cells (target TEXT, section_name TEXT, start INT,"
            " end INT, span INT, state TEXT)"
        )
        c.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        c.execute("CREATE TABLE sections (target TEXT, name TEXT, va INT, size INT)")
        c.execute("CREATE TABLE functions (target TEXT, va INT, status TEXT, markerType TEXT)")
        states = [
            "exact",
            "reloc",
            "near_match",
            "stub",
            "padding",
            "data",
            "thunk",
            "none",
            "proven",
            "size_mismatch",
            "compile_error",
            "skip",
            "unknown",
        ]
        c.executemany(
            "INSERT INTO cells (target, section_name, start, end, span, state)"
            " VALUES ('T', '.text', ?, ?, 1, ?)",
            [(i, i + 1, s) for i, s in enumerate(states)],
        )
        return conn

    def test_fallback_path_reconciles(self) -> None:
        import recoverage.server as srv

        conn = self._cells_db()
        try:
            c = conn.cursor()
            # No section_cell_stats: the live-query fallback answers.
            stats = srv._section_stats(c, "T")
        finally:
            conn.close()
        sec = stats["sections"][".text"]
        assert sec["other"] == 3
        self._reconciles(sec)

    def test_materialized_path_reconciles(self) -> None:
        import recoverage.server as srv

        conn = self._cells_db()
        try:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE section_cell_stats (target TEXT, section_name TEXT,"
                " total_cells INT, exact_count INT, reloc_count INT,"
                " near_match_count INT, stub_count INT, padding_count INT,"
                " data_count INT, thunk_count INT, none_count INT,"
                " proven_count INT, size_mismatch_count INT, other_count INT)"
            )
            # rebrew's definition: 'verified' folds into exact_count.
            c.execute(
                "INSERT INTO section_cell_stats SELECT target, section_name,"
                " COUNT(*),"
                " SUM(state IN ('exact','verified')), SUM(state='reloc'),"
                " SUM(state IN ('near_match','near_matching')), SUM(state='stub'),"
                " SUM(state='padding'), SUM(state='data'), SUM(state='thunk'),"
                " SUM(state='none'), SUM(state='proven'),"
                " SUM(state='size_mismatch'),"
                " SUM(state NOT IN ('exact','verified','reloc','near_match',"
                " 'near_matching','stub','padding','data','thunk','none','proven',"
                " 'size_mismatch'))"
                " FROM cells GROUP BY target, section_name"
            )
            stats = srv._section_stats(c, "T")
        finally:
            conn.close()
        sec = stats["sections"][".text"]
        assert sec["other"] == 3
        self._reconciles(sec)

    def test_absent_other_count_column_reports_zero(self) -> None:
        """A pre-catch-all section_cell_stats keeps the key, at 0."""
        import recoverage.server as srv

        conn = self._cells_db()
        try:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE section_cell_stats (target TEXT, section_name TEXT,"
                " total_cells INT, exact_count INT, reloc_count INT,"
                " near_match_count INT, stub_count INT, padding_count INT,"
                " data_count INT, thunk_count INT, none_count INT,"
                " proven_count INT, size_mismatch_count INT)"
            )
            c.execute(
                "INSERT INTO section_cell_stats SELECT target, section_name,"
                " COUNT(*), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 FROM cells"
                " GROUP BY target, section_name"
            )
            stats = srv._section_stats(c, "T")
        finally:
            conn.close()
        assert stats["sections"][".text"]["other"] == 0


class TestSpaStateVocabulary:
    """The SPA's STATE_ID must cover every state rebrew can write.

    An unmapped state packed to slot 0 and painted as an undocumented gap,
    contradicting /stats (which counts 'verified' as exact and covered_bytes
    over every state != 'none'). PALETTE_VARS and FILTER_KEY are indexed by the
    same ids, so they must stay the same length.
    """

    @staticmethod
    def _assets() -> tuple[str, str]:
        import importlib.resources

        from recoverage import assets

        base = importlib.resources.files(assets)
        return (
            base.joinpath("app.js").read_text(encoding="utf-8"),
            base.joinpath("detail.js").read_text(encoding="utf-8"),
        )

    def _window_rc_keys(self, app_js: str) -> set[str]:
        """Top-level key names of the ``window.RC = { ... }`` literal in *app_js*.

        detail.js reads its shared state off ``window.RC``, so the contract is
        which names are published, not the order or spelling of the literal.
        Splitting on commas is wrong: the object holds arrow bodies with their
        own commas, so the scan tracks brace depth and only yields keys that
        sit at depth 1.
        """
        import re

        literal = re.search(r"window\.RC\s*=\s*\{", app_js)
        assert literal is not None, "app.js never publishes window.RC"
        body = app_js[literal.end() :]
        keys: set[str] = set()
        depth = 1
        start = 0
        for i, ch in enumerate(body):
            if ch in "{([":
                depth += 1
            elif ch in "})]":
                depth -= 1
                if depth == 0:
                    segment = body[start:i]
                    key = segment.split(":", 1)[0].strip()
                    if key:
                        keys.add(key)
                    return keys
            elif ch == "," and depth == 1:
                segment = body[start:i]
                key = segment.split(":", 1)[0].strip()
                if key:
                    keys.add(key)
                start = i + 1
        raise AssertionError("window.RC literal is never closed")

    def test_state_id_covers_every_known_cell_state(self) -> None:
        from rebrew.build_db import _KNOWN_CELL_STATES

        app_js, _ = self._assets()
        block = app_js.split("const STATE_ID = {", 1)[1].split("};", 1)[0]
        mapped = {
            line.split(":")[0].strip()
            for line in block.replace("\n", " ").split(",")
            if ":" in line
        }
        missing = sorted(_KNOWN_CELL_STATES - mapped)
        assert missing == [], f"cell states the SPA paints as undocumented: {missing}"

    def test_verified_is_not_packed_as_none(self) -> None:
        app_js, _ = self._assets()
        block = app_js.split("const STATE_ID = {", 1)[1].split("};", 1)[0]
        assert "verified: 1" in block
        assert "verified: 0" not in block

    def test_palette_and_filter_arrays_match_the_state_count(self) -> None:
        """STATE_ID tops out at 7; both lookup tables must be that long.

        A short array makes pal[st] undefined (silently --none) and
        FILTER_KEY[st] undefined (a filter mismatch on every such cell).
        The tooltip's word list is a third such table: a short one shows
        "undefined" in the hover title, which is worse than showing nothing.
        """
        import re

        app_js, detail_js = self._assets()
        palette = re.search(r"const PALETTE_VARS = \[(.*?)\];", detail_js).group(1)
        filters = re.search(r"const FILTER_KEY = \[(.*?)\];", detail_js).group(1)
        assert palette.count('"--') == 8
        assert len([v for v in filters.split(",") if v.strip()]) == 8
        labels = re.search(r"const STATE_LABEL = \[(.*?)\];", app_js, re.DOTALL).group(1)
        assert len([v for v in labels.split(",") if v.strip()]) == 8
        assert "STATE_LABEL" in detail_js
        published = self._window_rc_keys(app_js)
        missing = sorted({"STATE_LABEL"} - published)
        assert missing == [], f"read by detail.js but not published on window.RC: {missing}"

    def test_cell_tooltip_names_the_state_and_function(self) -> None:
        """The hover title must say what the cell is, not print a 0/1 flag.

        It used to end in `${fn ? 1 : 0} fn`, which told a user nothing about
        the cell they were pointing at.
        """
        _, detail_js = self._assets()
        assert "0} fn" not in detail_js
        assert "wrap.title = [`Block ${idx}`" in detail_js

    def test_other_bg_token_is_defined(self) -> None:
        import importlib.resources

        from recoverage import assets

        css = importlib.resources.files(assets).joinpath("style.css").read_text(encoding="utf-8")
        assert "--other-bg:" in css
        assert ".swatch-compile_error" in css


class TestSpaGridLayoutMemo:
    """The grid layout memo must key on the packed cells, not on a count.

    ``layout`` caches the walk, the hit-map, and the per-cell rect geometry
    for a section.  A rebuild re-spans cells without necessarily changing how
    many there are, so a (columns, cell-count) key matches while the spans
    differ: the map then hands a click the wrong cell and the rects have the
    wrong widths.  packSection returns a fresh object per section version and
    after a lazy cells fetch, so the pack identity is the exact change token.
    """

    @staticmethod
    def _detail_js() -> str:
        import importlib.resources

        from recoverage import assets

        return importlib.resources.files(assets).joinpath("detail.js").read_text(encoding="utf-8")

    def test_layout_keys_on_the_pack_object(self) -> None:
        detail_js = self._detail_js()
        assert "g.layPack === pack" in detail_js
        assert "g.layPack = pack" in detail_js
        assert "pack.n}" not in detail_js, (
            "layout keyed on a cell count: a re-span that keeps the count serves stale geometry"
        )

    def test_rebuild_resyncs_the_declared_column_count(self) -> None:
        """A changed section width lives in the DOM, so paint must refresh it.

        layout reads the column count back off ``wrap.dataset.cols``, which was
        written when the grid was first created.  Without the resync a rebuild
        that changes a section's column count keeps wrapping at the old one.
        """
        detail_js = self._detail_js()
        assert "g.wrap.dataset.cols !== declared" in detail_js
        assert "g.wrap.dataset.cols = declared" in detail_js
        assert "const declared = String(sec.columns || 64);" in detail_js

    def test_pack_is_invalidated_when_lazy_cells_land(self) -> None:
        """The lazy cells fetch must drop the memoized pack, or the layout
        memo keys on a pack built from an empty section forever."""
        import importlib.resources

        from recoverage import assets

        app_js = importlib.resources.files(assets).joinpath("app.js").read_text(encoding="utf-8")
        assert "delete sec._pack;" in app_js
        assert "sec._pack = " in app_js


class TestSpaResourceTeardown:
    """The SPA must release what it registers, on every path that drops it.

    A live dashboard re-renders on every coverage.db rebuild, so a
    registration made per render and never released accumulates for the life
    of the tab rather than for one request. The browser half of that contract
    is not observable from Python, so it is pinned against the source, the
    same way the SPA state vocabulary above is.
    """

    @staticmethod
    def _assets() -> tuple[str, str]:
        import importlib.resources

        from recoverage import assets

        base = importlib.resources.files(assets)
        return (
            base.joinpath("app.js").read_text(encoding="utf-8"),
            base.joinpath("detail.js").read_text(encoding="utf-8"),
        )

    def test_grid_teardown_disconnects_the_resize_observer(self) -> None:
        """Every observed grid wrapper is dropped by dropGrids, so the
        observer that holds them must be disconnected there too. A ResizeObserver
        keeps its targets alive until unobserved, and a dropped wrapper carries
        its canvas context and the per-section hit-map typed arrays with it."""
        _, detail_js = self._assets()
        drop = detail_js.split("const dropGrids = () => {", 1)[1].split("};", 1)[0]
        assert "ro.disconnect()" in drop
        assert "container.innerHTML" in drop

    def test_live_reload_subscribes_once(self) -> None:
        """The SSE stream pins a bounded server-side /api/events slot until it
        is closed, so the derive that opens it must not open a second one when
        it re-runs."""
        app_js, _ = self._assets()
        after = app_js.split("let closeEvents = null;", 1)[1]
        derive = after.split("van.derive(() => {", 1)[1].split("});", 1)[0]
        assert "connectEvents" in derive
        assert "!detailReady.val || closeEvents" in derive


class TestSpaSectionCellsFeedback:
    """A sibling tab fetches its cells on switch, so it can be slow or fail.

    Without a frame of its own the map area went blank for the fetch and stayed
    blank after a failure, with nothing to click and nothing said: the tab was
    a dead end.  The grid renders a loading overlay while the cells are in
    flight and a retryable notice when the fetch fails.
    """

    @staticmethod
    def _assets() -> tuple[str, str]:
        import importlib.resources

        from recoverage import assets

        base = importlib.resources.files(assets)
        return (
            base.joinpath("app.js").read_text(encoding="utf-8"),
            base.joinpath("detail.js").read_text(encoding="utf-8"),
        )

    def test_grid_frames_a_section_whose_cells_have_not_arrived(self) -> None:
        _, detail_js = self._assets()
        branch = detail_js.split("if (sec.cells == null) {", 1)[1].split("return;", 1)[0]
        assert "loading-overlay" in branch
        assert "grid-error" in branch
        assert "Retry" in branch
        assert "retrySectionCells(secName)" in branch

    def test_a_failed_cells_fetch_is_reported_and_retryable(self) -> None:
        app_js, _ = self._assets()
        fetch = app_js.split("const ensureSectionCells = async (name) => {", 1)[1]
        catch = fetch.split("} catch (error)", 1)[1].split("} finally", 1)[0]
        assert "cellLoadError.val = { section: name, detail: error.message }" in catch
        # The grid reads the state, so it has to be handed to mountGrid.
        mount = app_js.split("window.RC.mountGrid({", 1)[1].split("});", 1)[0]
        assert "cellLoadError" in mount
        assert "retrySectionCells" in mount

    def test_error_frame_is_styled(self) -> None:
        import importlib.resources

        from recoverage import assets

        css = importlib.resources.files(assets).joinpath("style.css").read_text(encoding="utf-8")
        assert ".grid-error {" in css
