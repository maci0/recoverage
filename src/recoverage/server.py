#!/usr/bin/env python3
"""Recoverage server — coverage dashboard for binary-matching projects.

Bottle WSGI app serving a VanJS + SQLite dashboard.
Expects db/coverage.db in the working directory.
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

# CORS — mutated once at startup by CLI --cors flag before the server starts
# accepting requests.  Thread-safe: set before any worker threads exist.
CORS_ENABLED = False


# ── Path helpers ───────────────────────────────────────────────────


def _assets_dir() -> Path:
    """Return the directory containing recoverage UI files (HTML/CSS/JS).
    These ship as package data inside the recoverage package."""
    return Path(__file__).resolve().parent / "assets"


def _project_dir() -> Path:
    """Return the project directory (cwd)."""
    return Path.cwd().resolve()


def _db_path() -> Path:
    """Return the path to the coverage database."""
    return _project_dir() / "db" / "coverage.db"


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
                for tid in targets_dict:
                    targets_info[tid] = {"filename": tid}
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


_CAPSTONE_MD: Any = None
_CAPSTONE_MD_LOCK = threading.Lock()


def _get_capstone_md() -> Any:
    """Return a shared Capstone disassembler instance (created on first use)."""
    global _CAPSTONE_MD
    if _CAPSTONE_MD is not None:
        return _CAPSTONE_MD
    with _CAPSTONE_MD_LOCK:
        if _CAPSTONE_MD is not None:
            return _CAPSTONE_MD
        import capstone as _capstone  # type: ignore # noqa: PLC0415

        md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
        md.detail = False
        _CAPSTONE_MD = md
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


def _open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _db() -> sqlite3.Connection:
    return _open_db(_db_path())


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


def _json_err(status: int, data: dict[str, Any]) -> Any:
    """Return a JSON error response."""
    body = json.dumps(data).encode("utf-8")
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


@app.hook("after_request")
def _security_headers() -> None:
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("X-Frame-Options", "DENY")
    if CORS_ENABLED:
        response.set_header("Access-Control-Allow-Origin", "*")
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
