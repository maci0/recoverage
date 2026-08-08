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

    ``http://localhost:5173`` → ``http://localhost:5173``; a default port is
    dropped (``http://localhost:80`` → ``http://localhost``) so both spellings
    match.  Returns "" for unparsable or userinfo-bearing values.
    """
    if _hostname_of(origin) == "":
        return ""
    try:
        from urllib.parse import urlsplit

        u = urlsplit(origin if "://" in origin else f"//{origin}")
        host = (u.hostname or "").lower()
        port = u.port
        scheme = u.scheme or "http"
        return f"{scheme}://{host}" + (f":{port}" if port else "")
    except ValueError:
        return ""


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
    global _TOML_CONFIG_CACHE, _RESOLVED_TARGETS_CACHE
    with _RESOLVED_TARGETS_CACHE_LOCK:
        _TOML_CONFIG_CACHE = None
        _RESOLVED_TARGETS_CACHE = None


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
            if tid in target_ids or not target_ids:
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


def _find_dll_path(target: str) -> Path:
    """Find the DLL path for a target from project config."""
    targets = _get_targets_config()
    target_info = targets.get(target, targets.get("SERVER", {}))
    filename = (
        target_info.get("filename", "original/Server/server.dll")
        if isinstance(target_info, dict)
        else "original/Server/server.dll"
    )
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


def _check_schema_version(conn: sqlite3.Connection) -> str:
    """Read the stored db_version metadata; warn if it is not a known-compatible version.

    Known-compatible versions: 3 and 4.  Version 3 is still readable because
    none of the v4 constraints affect reads of existing data.  Any other version
    is logged as a warning — recoverage does not abort.

    Returns the version string (or ``"<unknown>"`` when not present / on error).
    """
    try:
        row = conn.execute("SELECT value FROM metadata WHERE key = 'db_version' LIMIT 1").fetchone()
        if row is None:
            return "<unknown>"
        v = row[0]
        if isinstance(v, str):
            v = v.strip('"')
        version = str(v)
        if version not in _KNOWN_SCHEMA_VERSIONS:
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
