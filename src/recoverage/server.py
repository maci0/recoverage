#!/usr/bin/env python3
"""Recoverage server — coverage dashboard for binary-matching projects.

Bottle WSGI app serving a VanJS + SQLite dashboard.
Reads the coverage database from the path resolved by
``recoverage._paths._resolve_db_path()``, which honours
``rebrew-project.toml [project] db_dir`` when present and falls back to
``./db/coverage.db`` otherwise.
"""

from __future__ import annotations

import functools
import gzip
import importlib.util
import json
import logging
import platform
import sqlite3
import subprocess
import threading
import webbrowser
from pathlib import Path
from typing import Any, cast

import bottle  # type: ignore
import brotli  # type: ignore[import-untyped]
import rcssmin  # type: ignore[import-untyped]
import rjsmin  # type: ignore[import-untyped]
import zstandard as zstd  # type: ignore[import-untyped]

from recoverage._paths import _db_path

# Module-level compressor — ZstdCompressor is thread-safe for compress() calls
_ZSTD_COMPRESSOR = zstd.ZstdCompressor(level=3)

# Shared timeout for rebrew regen subprocesses (imported by cli.py and api.py)
REGEN_TIMEOUT = 120  # seconds — must accommodate large projects

Bottle = cast(Any, bottle.Bottle)
request = cast(Any, bottle.request)
response = cast(Any, bottle.response)
static_file = cast(Any, bottle.static_file)
HTTPResponse = cast(Any, bottle.HTTPResponse)

HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None

# CORS — configured once at startup by the CLI before the server starts
# accepting requests.  Thread-safe: set before any worker threads exist.
CORS_ENABLED = False

# Origins allowed to read the API cross-origin (normalized scheme://host[:port]
# from --cors-origin).  Empty = no cross-origin reads; the wildcard "*" is
# never emitted.
CORS_ALLOWED_ORIGINS: list[str] = []

# Expected Host-header hostnames.  Loopback binds validate the Host header
# to defeat DNS rebinding (an attacker's domain resolving to 127.0.0.1);
# None = remote bind (user opted in via --allow-remote) — skip validation.
ALLOWED_HOSTS: set[str] | None = None


def _hostname_of(origin: str) -> str:
    """Lowercased hostname of an Origin/Host header value ("" if unparsable).

    Origins carry a scheme (``http://localhost:5173``); bare Host headers
    (``localhost:8001``) get a synthetic scheme so urlsplit parses both.
    Values containing userinfo/escape characters (``evil@host``, backslash,
    percent-encoding, control bytes) are rejected — browsers never emit them
    in Host/Origin, so their presence means the value is not a plain header.
    """
    try:
        from urllib.parse import urlsplit

        if any(ch in origin for ch in ("@", "\\", "%")) or any(ord(c) < 32 for c in origin):
            return ""
        candidate = origin if "://" in origin else f"//{origin}"
        return (urlsplit(candidate).hostname or "").lower()
    except ValueError:
        return ""


def _normalize_origin(origin: str) -> str:
    """Normalize an Origin URL to ``scheme://host[:port]`` for allowlist matching.

    ``http://localhost:5173`` → ``http://localhost:5173``; a scheme-default
    port is dropped (``http://localhost:80`` → ``http://localhost``) so both
    spellings match; IPv6 hosts keep their brackets
    (``http://[::1]:8001`` → ``http://[::1]:8001``).  Returns "" for
    unparsable or userinfo-bearing values.
    """
    if _hostname_of(origin) == "":
        return ""
    try:
        from urllib.parse import urlsplit

        u = urlsplit(origin if "://" in origin else f"//{origin}")
        host = (u.hostname or "").lower()
        port = u.port
        scheme = u.scheme or "http"
        default_port = {"http": 80, "https": 443}.get(scheme)
        if port == default_port:
            port = None
        host_part = f"[{host}]" if ":" in host else host
        return f"{scheme}://{host_part}" + (f":{port}" if port else "")
    except ValueError:
        return ""


# Byte-based per-section stats query shared by /api/targets/<target>/stats and
# the `recoverage stats` CLI.  ONE definition: these two queries already
# drifted apart once (cell-count vs byte-based coverage) and were fixed in
# lockstep twice — a single constant makes the next divergence impossible.
SECTION_STATS_SQL = """
    SELECT section_name,
      SUM(CASE WHEN state != 'none' THEN end - start ELSE 0 END) AS covered_bytes,
      SUM(end - start) AS total_bytes,
      COUNT(*) AS total_cells,
      SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) AS exact_count,
      SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) AS reloc_count,
      SUM(CASE WHEN state IN ('near_match','near_matching') THEN 1 ELSE 0 END) AS near_match_count,
      SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) AS stub_count,
      SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) AS data_count,
      SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) AS thunk_count
    FROM cells WHERE target = ? GROUP BY section_name
"""


def _section_stats(c: sqlite3.Cursor, target: str) -> dict[str, Any]:
    """Byte-based per-section stats + summary + by_status for *target*.

    ONE implementation shared by the ``/api/targets/<target>/stats`` endpoint
    and the ``recoverage stats`` CLI.  The summary parse, the SECTION_STATS_SQL
    loop, the section-size lookup, and the by-status count were copy-pasted in
    both (and drifted twice — cell-count vs byte-based, covered_bytes presence,
    key names); this is the single source of truth.
    """
    # Pre-computed summary from metadata
    summary: dict[str, Any] = {}
    c.execute("SELECT value FROM metadata WHERE target = ? AND key = 'summary'", (target,))
    row = c.fetchone()
    if row:
        try:
            summary = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            _log.warning("Corrupt summary metadata for target %s", target)

    # Per-section stats.  Coverage is BYTE-based: covered = every cell span
    # whose state is not "none", over the section's total cell bytes.
    sections: dict[str, Any] = {}
    c.execute(SECTION_STATS_SQL, (target,))
    for row in c.fetchall():
        total = row["total_bytes"] or 0
        covered = row["covered_bytes"] or 0
        matched = row["exact_count"] + row["reloc_count"]
        sections[row["section_name"]] = {
            "total_cells": row["total_cells"],
            "exact": row["exact_count"],
            "reloc": row["reloc_count"],
            "near_match": row["near_match_count"],
            "stub": row["stub_count"],
            "data": row["data_count"],
            "thunk": row["thunk_count"],
            "matched": matched,
            "covered_bytes": covered,
            "total_bytes": total,
            "coverage_pct": round(covered / total * 100, 2) if total else 0.0,
        }

    # Section byte sizes
    c.execute("SELECT name, size FROM sections WHERE target = ?", (target,))
    for row in c.fetchall():
        name = row["name"]
        if name in sections:
            sections[name]["size_bytes"] = row["size"]

    # Function counts by status.  GLOBAL/DATA marker rows live in the
    # functions table but are data markers, not functions — exclude them.
    by_status: dict[str, int] = {}
    c.execute(
        "SELECT status, COUNT(*) as cnt FROM functions"
        " WHERE target = ? AND markerType NOT IN ('GLOBAL','DATA') GROUP BY status",
        (target,),
    )
    for row in c.fetchall():
        by_status[row["status"] or "unknown"] = row["cnt"]

    return {"summary": summary, "sections": sections, "by_status": by_status}


# ── Path helpers ───────────────────────────────────────────────────


def _assets_dir() -> Path:
    """Return the directory containing recoverage UI files (HTML/CSS/JS).
    These ship as package data inside the recoverage package."""
    return Path(__file__).resolve().parent / "assets"


def _project_dir() -> Path:
    """Return the project directory (cwd)."""
    return Path.cwd().resolve()


# ── DLL loading & disassembly ──────────────────────────────────────

DLL_DATA: dict[str, bytes | None] = {}
DLL_LOCK = threading.Lock()
_MAX_DLL_SIZE = 512 * 1024 * 1024  # 512 MiB — reject unreasonably large binaries


_TOML_CONFIG_CACHE: dict[str, Any] | None = None
_RESOLVED_TARGETS_CACHE: dict[str, Any] | None = None
_RESOLVED_TARGETS_CACHE_LOCK = threading.RLock()


_log = logging.getLogger("recoverage")


def _get_targets_config() -> dict[str, Any]:
    """Load target configuration from rebrew-project.toml (thread-safe, cached)."""
    global _TOML_CONFIG_CACHE
    with _RESOLVED_TARGETS_CACHE_LOCK:
        if _TOML_CONFIG_CACHE is not None:
            return _TOML_CONFIG_CACHE

        root = _project_dir()
        targets_info: dict[str, Any] = {}
        try:
            import tomllib

            toml_path = root / "rebrew-project.toml"
            if toml_path.exists():
                text = toml_path.read_text(encoding="utf-8")
                doc = tomllib.loads(text)
                targets_dict = doc.get("targets", {})
                for tid, tdata in targets_dict.items():
                    # The DLL path comes from [targets.<tid>].binary — without
                    # it, /asm, /bytes and Potato disasm resolve the wrong file
                    # (previously `filename` was always the target id).
                    filename = tid
                    if isinstance(tdata, dict):
                        binary = tdata.get("binary", "")
                        if isinstance(binary, str) and binary:
                            filename = binary
                    targets_info[tid] = {"filename": filename}
        except (ImportError, OSError, ValueError) as exc:
            _log.warning("Failed to load rebrew-project.toml: %s", exc)

        _TOML_CONFIG_CACHE = targets_info
        return targets_info


def clear_target_cache() -> None:
    global _TOML_CONFIG_CACHE, _RESOLVED_TARGETS_CACHE, _SCHEMA_VERSION_CACHE
    with _RESOLVED_TARGETS_CACHE_LOCK:
        _TOML_CONFIG_CACHE = None
        _RESOLVED_TARGETS_CACHE = None
        _SCHEMA_VERSION_CACHE = None


def resolve_targets(c: sqlite3.Cursor) -> tuple[list[str], list[dict[str, str]]]:
    """Resolve available targets from DB + config (thread-safe, cached via RLock)."""
    global _RESOLVED_TARGETS_CACHE
    with _RESOLVED_TARGETS_CACHE_LOCK:
        if _RESOLVED_TARGETS_CACHE is not None:
            return _RESOLVED_TARGETS_CACHE["target_ids"], _RESOLVED_TARGETS_CACHE["targets_list"]

        c.execute("SELECT DISTINCT target FROM metadata")
        target_ids = [row[0] for row in c.fetchall()]
        targets_info = _get_targets_config()

        targets_list: list[dict[str, str]] = []
        added_tids: set[str] = set()

        for tid, t_info in targets_info.items():
            # Config-declared targets are always addressable, even before
            # their first build — _require_target treats "declared in the
            # project config" as valid, so a never-built target must not 404.
            filename = t_info.get("filename", tid) if isinstance(t_info, dict) else tid
            targets_list.append({"id": tid, "name": Path(filename).name})
            added_tids.add(tid)

        for tid in target_ids:
            if tid not in added_tids:
                targets_list.append({"id": tid, "name": tid})

        _RESOLVED_TARGETS_CACHE = {
            "target_ids": target_ids,
            "targets_list": targets_list,
        }
        return target_ids, targets_list


def _find_dll_path(target: str) -> Path | None:
    """Find the DLL path for a target from project config.

    Returns ``None`` when *target* has no ``[targets.<tid>].binary`` entry —
    the caller then reports a target-specific error instead of silently
    serving a different target's DLL (previously fell back to SERVER's
    binary, which produced plausible-but-wrong disassembly for config-less
    targets).
    """
    targets = _get_targets_config()
    if target not in targets:
        return None
    target_info = targets.get(target)
    filename = target_info.get("filename", "") if isinstance(target_info, dict) else ""
    if not filename:
        return None
    return _project_dir() / filename


def _load_dll(target: str) -> bytes | None:
    """Load DLL bytes for a target into DLL_DATA (thread-safe).

    Why no outer check: reading DLL_DATA[target] outside the lock races with
    dict resize triggered by __setitem__ in another thread.  The GIL protects
    individual bytecodes but not multi-step dict operations during resize.
    """
    with DLL_LOCK:
        if target in DLL_DATA:
            return DLL_DATA[target]
        dll_path = _find_dll_path(target)
        if dll_path is None:
            _log.warning(
                "No [targets.%s].binary configured — cannot load DLL for target %s",
                target,
                target,
            )
            DLL_DATA[target] = None
            return None
        try:
            file_size = dll_path.stat().st_size
            if file_size > _MAX_DLL_SIZE:
                _log.warning(
                    "DLL %s (%d MiB) exceeds %d MiB limit, skipping",
                    dll_path,
                    file_size >> 20,
                    _MAX_DLL_SIZE >> 20,
                )
                DLL_DATA[target] = None
                return None
            with open(dll_path, "rb") as f:
                DLL_DATA[target] = f.read()
        except OSError:
            _log.warning("Failed to load DLL for target %s at %s", target, dll_path)
            DLL_DATA[target] = None
        return DLL_DATA[target]


_CAPSTONE_MD_TLS = threading.local()


def _get_capstone_md() -> Any:
    """Return a thread-local Capstone disassembler.

    A single shared ``Cs`` instance is NOT safe to disassemble concurrently
    (libcapstone is not thread-safe) — with the threaded WSGI server, request
    threads were racing on it and producing garbage/crashes.
    """
    md = getattr(_CAPSTONE_MD_TLS, "md", None)
    if md is None:
        import capstone as _capstone  # type: ignore # noqa: PLC0415

        md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
        md.detail = False
        _CAPSTONE_MD_TLS.md = md
    return md


@functools.lru_cache(maxsize=2048)
def get_disassembly(va: int, size: int, file_offset: int, target: str) -> str:
    target_data = _load_dll(target)
    if target_data is None:
        return ""

    code_bytes = target_data[file_offset : file_offset + size]
    if len(code_bytes) < size:
        return ""

    md = _get_capstone_md()
    asm_lines = [
        f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}"
        for insn in md.disasm(code_bytes, va)
    ]

    return "\n".join(asm_lines) if asm_lines else "  (no instructions)"


# ── Minification ───────────────────────────────────────────────────


def minify_css(css: str) -> str:
    return rcssmin.cssmin(css)


def minify_js(js: str) -> str:
    return rjsmin.jsmin(js)


# ── Compression ────────────────────────────────────────────────────


def _best_encoding(accept_encoding: str) -> str:
    """Return the best available compression encoding name, or empty string.

    Parses comma-separated tokens from Accept-Encoding to avoid false substring
    matches (e.g. 'not-zstd' should not match 'zstd').
    """
    tokens = {t.strip().split(";")[0].strip().lower() for t in accept_encoding.split(",")}
    if "zstd" in tokens:
        return "zstd"
    if "br" in tokens:
        return "br"
    if "gzip" in tokens:
        return "gzip"
    return ""


def compress_payload(body: bytes, accept_encoding: str) -> tuple[bytes, str]:
    """Compress body with the best algorithm the client accepts.

    Returns (compressed_body, encoding_name). encoding_name is "" if no
    compression was applied, guaranteeing the caller can always set
    Content-Encoding only when encoding is truthy.
    """
    encoding = _best_encoding(accept_encoding)
    if encoding == "zstd":
        return _ZSTD_COMPRESSOR.compress(body), "zstd"
    if encoding == "br":
        return brotli.compress(body), "br"  # type: ignore
    if encoding == "gzip":
        return gzip.compress(body), "gzip"
    return body, ""


# ── SQL helpers ────────────────────────────────────────────────────


def _escape_like(search: str) -> str:
    """Escape SQL LIKE wildcards (% and _) for safe parameterized queries.

    Returns the escaped pattern wrapped in % for substring matching.
    Uses backslash as the ESCAPE character — all callers must include
    ``ESCAPE '\\\\'`` in their LIKE clauses.

    Backslash itself must be escaped first, since it is the ESCAPE character
    and would otherwise consume the next character as a literal.
    """
    return "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ── SQL fragments ──────────────────────────────────────────────────

_FN_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'vaStart', vaStart, 'size', size, "
    "'fileOffset', fileOffset, 'status', status, 'module', module, "
    "'cflags', cflags, 'symbol', symbol, 'markerType', markerType, "
    "'ghidra_name', ghidra_name, 'list_name', list_name, "
    "'is_thunk', is_thunk, 'is_export', is_export, 'sha256', sha256, "
    "'files', json(files), "
    "'detected_by', json(detected_by), 'size_by_tool', json(size_by_tool), "
    "'textOffset', textOffset, 'blocker', blocker, 'blockerDelta', blockerDelta, "
    "'size_reason', size_reason, 'similarity', similarity"
    ")"
)

_GLOBAL_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'decl', decl, "
    "'files', json(files), 'module', module, 'size', size, 'isGlobal', 1"
    ")"
)


_KNOWN_SCHEMA_VERSIONS: frozenset[str] = frozenset({"3", "4"})

# Schema check memoized per DB (mtime_ns, size): the check is two queries
# (metadata + full sqlite_master scan) that would otherwise run on every
# request; the DB only changes when build-db rewrites it, which the SSE
# watcher already detects and funnels through clear_target_cache().
_SCHEMA_VERSION_CACHE: tuple[tuple[int, int], str] | None = None


def _check_schema_version(conn: sqlite3.Connection) -> str:
    """Read the stored db_version metadata; warn if it is not a known-compatible version.

    Known-compatible versions: 3 and 4.  Version 3 is still readable because
    none of the v4 constraints affect reads of existing data.  Any other version
    is logged as a warning — recoverage does not abort.

    The version stamp alone is not proof of shape: a DB stamped "4" can be
    missing required objects (e.g. the ``history`` table) and pass this gate,
    then 500 at query time.  A known version with missing objects is reported
    as ``"<incomplete>"`` so endpoints can respond with a clear 503 instead.

    Returns the version string (or ``"<unknown>"`` / ``"<incomplete>"``).
    """
    global _SCHEMA_VERSION_CACHE
    try:
        st = _db_path().stat()
        fingerprint = (st.st_mtime_ns, st.st_size)
    except OSError:
        fingerprint = None
    if fingerprint is not None:
        with _RESOLVED_TARGETS_CACHE_LOCK:
            if _SCHEMA_VERSION_CACHE is not None and _SCHEMA_VERSION_CACHE[0] == fingerprint:
                return _SCHEMA_VERSION_CACHE[1]
    version = _check_schema_version_uncached(conn)
    if fingerprint is not None:
        with _RESOLVED_TARGETS_CACHE_LOCK:
            _SCHEMA_VERSION_CACHE = (fingerprint, version)
    return version


def _check_schema_version_uncached(conn: sqlite3.Connection) -> str:
    """Uncached schema version read; see :func:`_check_schema_version`."""
    try:
        # Prefer the schema-level __schema__ stamp (deterministic across
        # targets); fall back to any per-target stamp for legacy DBs.
        row = conn.execute(
            "SELECT value FROM metadata WHERE target = '__schema__' AND key = 'db_version' LIMIT 1"
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = 'db_version' LIMIT 1"
            ).fetchone()
        if row is None:
            return "<unknown>"
        v = row[0]
        if isinstance(v, str):
            v = v.strip('"')
        version = str(v)
        if version in _KNOWN_SCHEMA_VERSIONS:
            present = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master"
                    " WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            required = {
                "metadata",
                "sections",
                "cells",
                "functions",
                "globals",
                "verify_results",
                "history",
                "section_cell_stats",
            }
            missing = required - present
            if missing:
                _log.warning(
                    "recoverage: db_version %r but missing schema objects: %s",
                    version,
                    ", ".join(sorted(missing)),
                )
                return "<incomplete>"
        else:
            _log.warning(
                "recoverage: unexpected db_version %r (known: %s) — "
                "some features may not work correctly",
                version,
                ", ".join(sorted(_KNOWN_SCHEMA_VERSIONS)),
            )
        return version
    except sqlite3.Error as exc:
        _log.warning("recoverage: could not read db_version: %s", exc)
        return "<unknown>"


def _open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _db() -> sqlite3.Connection:
    conn = _open_db(_db_path())
    version = _check_schema_version(conn)
    _log.info("recoverage: opened coverage.db (schema v%s)", version)
    if version == "<incomplete>":
        # Stamped with a known version but missing required objects — every
        # query would 500.  Fail fast with the standard 503 JSON contract.
        conn.close()
        raise sqlite3.OperationalError(
            "coverage.db schema is incomplete (missing tables/views) — "
            "run rebrew build-db --force to rebuild"
        )
    return conn


# ── Response helpers ───────────────────────────────────────────────


def _compressed(body: bytes, content_type: str, **headers: str) -> bytes:
    """Compress body, set response headers, return final body."""
    accept_enc = request.headers.get("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    response.content_type = content_type
    if encoding:
        response.set_header("Content-Encoding", encoding)
    response.set_header("Vary", "Accept-Encoding")
    response.set_header("Content-Length", str(len(body)))
    for k, v in headers.items():
        response.set_header(k.replace("_", "-"), v)
    return body


def _json_ok(data: dict[str, Any] | list[Any] | bytes, **headers: str) -> bytes:
    """Return compressed JSON 200."""
    body = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
    return _compressed(body, "application/json", **headers)


# Every JSON error response carries this trio: `error` (human message),
# `code` (stable machine-readable string), `detail` (extra context, often "").
_STATUS_ERROR_CODES: dict[int, str] = {
    400: "bad_request",
    403: "forbidden",
    404: "not_found",
    422: "unprocessable_entity",
    429: "rate_limited",
    500: "internal",
    501: "not_implemented",
    503: "db_unavailable",
    504: "gateway_timeout",
}


def _json_err(status: int, data: dict[str, Any]) -> Any:
    """Return a JSON error response.

    Body is always ``{"error": <human message>, "code": <machine code>,
    "detail": <context>}``.  ``code`` defaults to a status-based mapping
    (call sites may override it) and any extra keys in ``data`` (e.g.
    ``retry_after``) are preserved alongside the standard trio.
    """
    body_data: dict[str, Any] = {
        "error": data.get("error", "error"),
        "code": data.get("code", _STATUS_ERROR_CODES.get(status, "internal")),
        "detail": data.get("detail", ""),
    }
    for key, value in data.items():
        if key not in body_data:
            body_data[key] = value
    body = json.dumps(body_data).encode("utf-8")
    accept_enc = request.headers.get("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    resp = HTTPResponse(status=status, body=body)
    resp.content_type = "application/json"
    if encoding:
        resp.set_header("Content-Encoding", encoding)
    resp.set_header("Vary", "Accept-Encoding")
    resp.set_header("Content-Length", str(len(body)))
    return resp


# ── Bottle app ─────────────────────────────────────────────────────

app = Bottle()


@app.error(500)
def _handle_sqlite_error(error: Any) -> Any:
    """Keep the JSON error contract when a query fails after connect.

    ``_db()`` open failures already return 503 JSON, but every query after
    connect was unguarded — a corrupt/incompatible DB or SQLITE_BUSY during a
    concurrent build-db raised inside ``c.execute`` and surfaced as Bottle's
    HTML 500.  All sqlite3 errors become a 503 JSON response instead.
    """
    exc = getattr(error, "exception", None)
    if isinstance(exc, sqlite3.Error):
        _log.warning("Database error serving %s: %s", request.path, exc)
        return _json_err(503, {"error": "Database unavailable"})
    # Non-DB 500: delegate to bottle's default error page.  Returning the
    # HTTPError itself would make _cast re-enter the error handler (recursion
    # until the wsgi catch-all); returning None would emit an empty 500 body.
    return app.default_error_handler(error)


@app.hook("before_request")
def _log_request() -> None:
    """Log incoming requests at DEBUG level for operational visibility."""
    _log.debug("%s %s", request.method, request.path)
    # DNS-rebinding guard for loopback installs: the Host header must name a
    # loopback host.  Requests without a Host header (non-HTTP/1.1 clients,
    # WSGI test harnesses) are left to the server's own address handling.
    if ALLOWED_HOSTS is not None:
        host = request.headers.get("Host", "")
        if host and _hostname_of(host) not in ALLOWED_HOSTS:
            raise _json_err(
                400,
                {
                    "error": "Bad Request",
                    "detail": f"unexpected Host header {host!r}",
                },
            )


@app.hook("after_request")
def _security_headers() -> None:
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("X-Frame-Options", "DENY")
    if CORS_ENABLED:
        # Echo the request origin only when it is explicitly allowed.  Never
        # emit the wildcard: the API serves unauthenticated binary bytes.
        origin = request.headers.get("Origin", "")
        if origin and _normalize_origin(origin) in CORS_ALLOWED_ORIGINS:
            response.set_header("Access-Control-Allow-Origin", origin)
            # Append to any existing Vary (compressed responses already carry
            # "Accept-Encoding") instead of replacing it — a shared cache must
            # key on both.
            existing_vary = response.headers.get("Vary", "")
            combined = ", ".join(v for v in (existing_vary, "Origin") if v)
            response.set_header("Vary", combined)
        response.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.set_header("Access-Control-Allow-Headers", "Content-Type")


@app.route("<path:path>", method="OPTIONS")
def _cors_preflight(path: str) -> str:
    """Handle CORS preflight requests. Headers are set by the after_request hook."""
    return ""


# ── Browser opener ─────────────────────────────────────────────────


def open_browser(url: str) -> None:
    system = platform.system()
    # start_new_session=True detaches the child so it won't become a zombie
    try:
        if system == "Linux":
            subprocess.Popen(
                ["xdg-open", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        elif system == "Darwin":
            subprocess.Popen(
                ["open", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        elif system == "Windows":
            subprocess.Popen(
                ["start", url],
                shell=True,  # noqa: S603 — required for Windows 'start'; url is internally generated
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            webbrowser.open(url)
    except (OSError, subprocess.SubprocessError):
        webbrowser.open(url)


# ── Register routes from submodules ────────────────────────────────

import recoverage.api  # noqa: F401, E402
import recoverage.ui  # noqa: F401, E402
