"""Shared test fixtures and helpers for recoverage tests."""

from __future__ import annotations

import json
import sqlite3
from io import BytesIO
from pathlib import Path
from wsgiref.util import setup_testing_defaults

from recoverage.webapp import app

# -- Synthetic coverage.db -------------------------------------------------
# The DB-gated tests below skip when no coverage.db is in cwd, and CI has no
# real rebrew project — so they silently never ran.  Generate a minimal DB
# matching rebrew build-db's schema (schema v4) so those tests execute
# everywhere.  The file is gitignored (see .gitignore).

_DB_FILE = Path.cwd() / "db" / "coverage.db"


def _build_synthetic_db() -> None:
    """Create a minimal coverage.db (rebrew build-db schema v4)."""
    _DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_FILE)
    try:
        c = conn.cursor()
        c.execute(
            "CREATE TABLE metadata ("
            " target TEXT NOT NULL, key TEXT NOT NULL, value TEXT,"
            " PRIMARY KEY (target, key))"
        )
        c.execute(
            "CREATE TABLE sections ("
            " target TEXT NOT NULL, name TEXT NOT NULL,"
            " va INTEGER CHECK (va IS NULL OR va >= 0),"
            " size INTEGER CHECK (size IS NULL OR size >= 0),"
            " fileOffset INTEGER CHECK (fileOffset IS NULL OR fileOffset >= 0),"
            " unitBytes INTEGER CHECK (unitBytes IS NULL OR unitBytes > 0),"
            " columns INTEGER CHECK (columns IS NULL OR columns > 0),"
            " PRIMARY KEY (target, name))"
        )
        c.execute(
            "CREATE TABLE cells ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " target TEXT NOT NULL, section_name TEXT NOT NULL,"
            " start INTEGER NOT NULL CHECK (start >= 0),"
            " end INTEGER NOT NULL CHECK (end >= start),"
            " span INTEGER NOT NULL DEFAULT 1 CHECK (span > 0),"
            " state TEXT NOT NULL,"
            " functions TEXT NOT NULL DEFAULT '[]',"
            " label TEXT, parent_function TEXT)"
        )
        c.execute(
            "CREATE TABLE functions ("
            " target TEXT NOT NULL, va INTEGER NOT NULL CHECK (va >= 0),"
            " name TEXT NOT NULL DEFAULT '', vaStart TEXT NOT NULL DEFAULT '',"
            " size INTEGER CHECK (size IS NULL OR size >= 0),"
            " fileOffset INTEGER CHECK (fileOffset IS NULL OR fileOffset >= 0),"
            " status TEXT NOT NULL DEFAULT 'UNKNOWN',"
            " module TEXT NOT NULL DEFAULT '', cflags TEXT, symbol TEXT,"
            " markerType TEXT NOT NULL DEFAULT 'FUNCTION'"
            "  CHECK (markerType IN ('FUNCTION','LIBRARY','STUB','GLOBAL','DATA')),"
            " ghidra_name TEXT, list_name TEXT,"
            " is_thunk INTEGER NOT NULL DEFAULT 0 CHECK (is_thunk IN (0, 1)),"
            " is_export INTEGER NOT NULL DEFAULT 0 CHECK (is_export IN (0, 1)),"
            " sha256 TEXT,"
            " files TEXT NOT NULL DEFAULT '[]',"
            " detected_by TEXT NOT NULL DEFAULT '[]',"
            " size_by_tool TEXT NOT NULL DEFAULT '{}',"
            " textOffset INTEGER CHECK (textOffset IS NULL OR textOffset >= 0),"
            " blocker TEXT,"
            " blockerDelta INTEGER CHECK (blockerDelta IS NULL OR blockerDelta >= 0),"
            " size_reason TEXT,"
            " similarity REAL CHECK (similarity IS NULL OR "
            "(similarity >= 0.0 AND similarity <= 1.0)),"
            " PRIMARY KEY (target, va))"
        )
        c.execute(
            "CREATE TABLE globals ("
            " target TEXT NOT NULL, va INTEGER NOT NULL CHECK (va >= 0),"
            " name TEXT NOT NULL DEFAULT '', decl TEXT NOT NULL DEFAULT '',"
            " files TEXT NOT NULL DEFAULT '[]',"
            " module TEXT NOT NULL DEFAULT '',"
            " size INTEGER NOT NULL DEFAULT 4 CHECK (size >= 0),"
            " PRIMARY KEY (target, va))"
        )
        c.execute(
            "CREATE VIEW section_cell_stats AS"
            " SELECT target, section_name,"
            " COUNT(*) as total_cells,"
            " SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,"
            " SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) as reloc_count,"
            " SUM(CASE WHEN state IN ('near_match','near_matching') THEN 1 ELSE 0 END)"
            "   as near_match_count,"
            " SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) as stub_count,"
            " SUM(CASE WHEN state = 'padding' THEN 1 ELSE 0 END) as padding_count,"
            " SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) as data_count,"
            " SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) as thunk_count,"
            " SUM(CASE WHEN state = 'none' THEN 1 ELSE 0 END) as none_count,"
            " SUM(CASE WHEN state = 'proven' THEN 1 ELSE 0 END) as proven_count,"
            " SUM(CASE WHEN state = 'size_mismatch' THEN 1 ELSE 0 END) as size_mismatch_count"
            " FROM cells GROUP BY target, section_name"
        )

        target = "FAKEDLL"
        c.executemany(
            "INSERT INTO metadata (target, key, value) VALUES (?, ?, ?)",
            [
                (target, "db_version", '"4"'),
                (target, "summary", json.dumps({"totalFunctions": 3})),
                (target, "function_stats", json.dumps({"total": 3})),
            ],
        )
        c.executemany(
            "INSERT INTO sections (target, name, va, size, fileOffset, unitBytes, columns)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (target, ".text", 0x10001000, 0x1000, 0x200, 16, 8),
                (target, ".data", 0x10002000, 0x400, 0x1200, 16, 8),
            ],
        )
        c.executemany(
            "INSERT INTO cells (target, section_name, start, end, span, state,"
            " functions, label, parent_function) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (target, ".text", 0, 16, 1, "exact", '["_func_a"]', None, None),
                (target, ".text", 16, 32, 1, "reloc", '["_func_b"]', None, None),
                (target, ".text", 32, 48, 1, "stub", '["_func_c"]', None, None),
                (target, ".text", 48, 64, 1, "padding", "[]", None, None),
                (target, ".text", 64, 80, 1, "data", "[]", "jt_10001060", None),
                (target, ".text", 80, 96, 1, "thunk", "[]", None, "_func_a"),
                (target, ".text", 96, 112, 1, "none", "[]", None, None),
                (target, ".text", 112, 128, 1, "exact", "[]", None, None),
                (target, ".data", 0, 16, 1, "data", '["g_counter"]', "g_counter", None),
            ],
        )
        c.executemany(
            "INSERT INTO functions (target, va, name, vaStart, size, fileOffset, status,"
            " module, cflags, symbol, markerType) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    target,
                    0x10001000,
                    "_func_a",
                    "0x10001000",
                    48,
                    0x200,
                    "EXACT",
                    "T",
                    "/O2",
                    "_func_a",
                    "FUNCTION",
                ),
                (
                    target,
                    0x10001010,
                    "_func_b",
                    "0x10001010",
                    16,
                    0x210,
                    "RELOC",
                    "T",
                    "/O2",
                    "_func_b",
                    "FUNCTION",
                ),
                (
                    target,
                    0x10001030,
                    "_func_c",
                    "0x10001030",
                    32,
                    0x230,
                    "STUB",
                    "T",
                    "",
                    "_func_c",
                    "FUNCTION",
                ),
            ],
        )
        c.execute(
            "INSERT INTO globals (target, va, name, decl, files, module, size)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target, 0x10002000, "g_counter", "int g_counter", "[]", "T", 4),
        )
        c.execute(
            "CREATE TABLE verify_results ("
            " target TEXT NOT NULL, va INTEGER NOT NULL,"
            " verified_at TEXT NOT NULL,"
            " byte_delta INTEGER, diff_lines INTEGER,"
            " similarity REAL,"
            " PRIMARY KEY (target, va))"
        )
        c.execute(
            "INSERT INTO verify_results "
            "(target, va, verified_at, byte_delta, diff_lines, similarity)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (target, 0x10001000, "2026-01-01T00:00:00+00:00", 0, 0, 87.3),
        )
        # history + all required objects must exist: the schema-shape check
        # (round-4) verifies the full object set, not just the version stamp.
        c.execute(
            "CREATE TABLE history ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " target TEXT NOT NULL, va INTEGER NOT NULL,"
            " old_status TEXT, new_status TEXT, changed_at TEXT NOT NULL)"
        )
        conn.commit()
    finally:
        conn.close()


# Build the synthetic DB only when we are NOT inside a real rebrew workspace:
# a real project has a rebrew-project.toml and its own coverage.db, which the
# DB-gated tests must never read (assertions would depend on unrelated project
# data, and building a synthetic DB here could clobber the real one).
_IN_REAL_PROJECT = (Path.cwd() / "rebrew-project.toml").exists()

if not _DB_FILE.exists() and not _IN_REAL_PROJECT:
    _build_synthetic_db()

HAS_DB = _DB_FILE.exists() and not _IN_REAL_PROJECT


def wsgi_request(
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    remote_addr: str = "127.0.0.1",
    body: bytes | str = b"",
) -> tuple[str, dict[str, str], bytes]:
    """Issue a WSGI request against the Bottle app and return (status, headers, body)."""
    environ: dict[str, str | BytesIO] = {}
    setup_testing_defaults(environ)
    url_path, _, query = path.partition("?")
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = url_path
    environ["QUERY_STRING"] = query
    environ["REMOTE_ADDR"] = remote_addr
    if isinstance(body, str):
        body = body.encode("utf-8")
    environ["wsgi.input"] = BytesIO(body)
    environ["CONTENT_LENGTH"] = str(len(body))
    if headers:
        for k, v in headers.items():
            environ[f"HTTP_{k.upper().replace('-', '_')}"] = v

    status_holder: dict[str, str | dict[str, str]] = {"status": "", "headers": {}}

    def _start_response(status: str, response_headers, exc_info=None):
        status_holder["status"] = status
        status_holder["headers"] = dict(response_headers)

    result = app(environ, _start_response)
    # PEP 3333: the server MUST call close() on the returned iterable when
    # provided — that is what closes handles behind responses like
    # static_file's open file object. Skipping it leaks fds until GC.
    try:
        body = b"".join(result)
    finally:
        close = getattr(result, "close", None)
        if close is not None:
            close()
    return str(status_holder["status"]), dict(status_holder["headers"]), body


def wsgi_get(path: str, headers: dict[str, str] | None = None) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", path, headers)


def wsgi_post(
    path: str,
    headers: dict[str, str] | None = None,
    remote_addr: str = "127.0.0.1",
    body: bytes | str = b"",
) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("POST", path, headers, remote_addr=remote_addr, body=body)


def decode_body(body: bytes, headers: dict[str, str]) -> bytes:
    """Decompress response body based on Content-Encoding header."""
    encoding = headers.get("Content-Encoding", "")
    if encoding == "gzip":
        import gzip

        return gzip.decompress(body)
    if encoding == "br":
        import brotli

        return brotli.decompress(body)
    if encoding == "zstd":
        import zstandard as zstd

        return zstd.ZstdDecompressor().decompress(body)
    return body


def get_first_target() -> str:
    """Get the first target from the coverage database."""
    from recoverage._paths import sqlite_ro_uri
    from recoverage.server import _db_path

    conn = sqlite3.connect(sqlite_ro_uri(_db_path()), uri=True)
    try:
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM metadata ORDER BY target LIMIT 1")
        row = c.fetchone()
        return row[0] if row else ""
    finally:
        conn.close()
