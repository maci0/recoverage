#!/usr/bin/env python3
"""Recoverage dev server — coverage dashboard for binary-matching projects.

Serves a VanJS + SQLite dashboard at http://localhost:8001.
Run from a project directory containing db/coverage.db.
"""

from __future__ import annotations

import functools
import gzip
import importlib.util
import json
import platform
import re
import sqlite3
import subprocess
import threading
import webbrowser
from pathlib import Path
from typing import Any, cast

import bottle  # type: ignore

Bottle = cast(Any, bottle.Bottle)
request = cast(Any, bottle.request)
response = cast(Any, bottle.response)
static_file = cast(Any, bottle.static_file)
HTTPResponse = cast(Any, bottle.HTTPResponse)

HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None

# CORS — set to True by CLI --cors flag
CORS_ENABLED = False


try:
    import rcssmin  # type: ignore
    import rjsmin  # type: ignore

    HAS_MINIFIERS = True
except ImportError:
    HAS_MINIFIERS = False

try:
    import brotli  # type: ignore

    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

try:
    import zstandard as zstd  # type: ignore

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


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


def _find_dll_path(target: str) -> Path:
    """Find the DLL path for a target from project config."""
    root = _project_dir()
    try:
        import yaml  # type: ignore

        yml_path = root / "reccmp-project.yml"
        with open(yml_path, encoding="utf-8") as f:
            project_config = yaml.safe_load(f)
        targets = project_config.get("targets", {}) if isinstance(project_config, dict) else {}
        target_info = targets.get(target, targets.get("SERVER", {}))
        filename = (
            target_info.get("filename", "original/Server/server.dll")
            if isinstance(target_info, dict)
            else "original/Server/server.dll"
        )
        return root / filename
    except Exception:
        return root / "original" / "Server" / "server.dll"


def _load_dll(target: str) -> bytes | None:
    """Load DLL bytes for a target into DLL_DATA (thread-safe, double-checked)."""
    if target in DLL_DATA:
        return DLL_DATA[target]
    with DLL_LOCK:
        if target in DLL_DATA:
            return DLL_DATA[target]
        dll_path = _find_dll_path(target)
        try:
            with open(dll_path, "rb") as f:
                DLL_DATA[target] = f.read()
        except OSError:
            DLL_DATA[target] = None
    return DLL_DATA[target]


@functools.lru_cache(maxsize=2048)
def get_disassembly(va: int, size: int, file_offset: int, target: str) -> str:
    target_data = _load_dll(target)
    if target_data is None:
        return ""

    code_bytes = target_data[file_offset : file_offset + size]
    if len(code_bytes) < size:
        return ""

    import capstone as _capstone  # type: ignore # noqa: PLC0415

    md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
    md.detail = False

    asm_lines = [
        f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}"
        for insn in md.disasm(code_bytes, va)
    ]

    return "\n".join(asm_lines) if asm_lines else "  (no instructions)"


# ── Minification ───────────────────────────────────────────────────


def minify_css(css: str) -> str:
    if HAS_MINIFIERS:
        return rcssmin.cssmin(css)  # type: ignore
    css = re.sub(r"/\*[\s\S]*?\*/", "", css)
    css = re.sub(r"\s+", " ", css)
    css = re.sub(r"\s*([{}:;,])\s*", r"\1", css)
    return css.strip()


def minify_js(js: str) -> str:
    if HAS_MINIFIERS:
        return rjsmin.jsmin(js)  # type: ignore
    js = re.sub(r"^\s*//.*$", "", js, flags=re.MULTILINE)
    js = re.sub(r"/\*[\s\S]*?\*/", "", js)
    lines = [line.strip() for line in js.split("\n")]
    return "\n".join(line for line in lines if line)


# ── Compression ────────────────────────────────────────────────────


def _best_encoding(accept_encoding: str) -> str:
    """Return the best available compression encoding name, or empty string."""
    if HAS_ZSTD and "zstd" in accept_encoding:
        return "zstd"
    if HAS_BROTLI and "br" in accept_encoding:
        return "br"
    if "gzip" in accept_encoding:
        return "gzip"
    return ""


def compress_payload(body: bytes, accept_encoding: str) -> tuple[bytes, str]:
    """Compress payload using the best available algorithm."""
    encoding = _best_encoding(accept_encoding)
    if encoding == "zstd":
        cctx = zstd.ZstdCompressor(level=3)  # type: ignore
        return cctx.compress(body), "zstd"
    if encoding == "br":
        return brotli.compress(body), "br"  # type: ignore
    if encoding == "gzip":
        return gzip.compress(body), "gzip"
    return body, ""


# ── SQL fragments ──────────────────────────────────────────────────

_FN_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'vaStart', vaStart, 'size', size, "
    "'fileOffset', fileOffset, 'status', status, 'origin', origin, "
    "'cflags', cflags, 'symbol', symbol, 'markerType', markerType, "
    "'ghidra_name', ghidra_name, 'r2_name', r2_name, "
    "'is_thunk', is_thunk, 'is_export', is_export, 'sha256', sha256, "
    "'files', json(files), "
    "'detected_by', json(detected_by), 'size_by_tool', json(size_by_tool), "
    "'textOffset', textOffset"
    ")"
)

_GLOBAL_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'decl', decl, "
    "'files', json(files), 'origin', origin, 'size', size, 'isGlobal', 1"
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
    resp.set_header("Content-Length", str(len(body)))
    return resp


# ── Bottle app ─────────────────────────────────────────────────────

app = Bottle()


@app.hook("after_request")
def _cors_headers() -> None:
    if CORS_ENABLED:
        response.set_header("Access-Control-Allow-Origin", "*")
        response.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.set_header("Access-Control-Allow-Headers", "Content-Type")


# ── Browser opener ─────────────────────────────────────────────────


def open_browser(url: str) -> None:
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.Popen(
                ["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        elif system == "Darwin":
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "Windows":
            subprocess.Popen(
                ["start", url],
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            webbrowser.open(url)
    except Exception:
        webbrowser.open(url)


# ── Register routes from submodules ────────────────────────────────

import recoverage.api  # noqa: F401, E402
import recoverage.ui  # noqa: F401, E402
