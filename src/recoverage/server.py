#!/usr/bin/env python3
"""Recoverage dev server — coverage dashboard for binary-matching projects.

Serves a VanJS + SQLite dashboard at http://localhost:8001.
Run from a project directory containing db/coverage.db.
"""


import functools
import gzip
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from urllib.parse import urlparse
import importlib.util

from typing import Any, cast
import bottle  # type: ignore

from recoverage import __version__

Bottle = cast(Any, bottle.Bottle)
request = cast(Any, bottle.request)
response = cast(Any, bottle.response)
static_file = cast(Any, bottle.static_file)
HTTPResponse = cast(Any, bottle.HTTPResponse)

HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None

# CORS — set to True by CLI --cors flag
CORS_ENABLED = False


try:
    import rjsmin  # type: ignore
    import rcssmin  # type: ignore

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
        with open(yml_path, "r") as f:
            project_config = yaml.safe_load(f)
        targets = project_config.get("targets", {})
        target_info = targets.get(target, targets.get("SERVER", {}))
        return root / target_info.get("filename", "original/Server/server.dll")
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
        except FileNotFoundError:
            DLL_DATA[target] = None
    return DLL_DATA[target]


@functools.lru_cache(maxsize=2048)
def get_disassembly(
    va: int, size: int, file_offset: int, target: str
) -> str:
    target_data = _load_dll(target)
    if target_data is None:
        return ""

    code_bytes = target_data[file_offset : file_offset + size]  # type: ignore
    if len(code_bytes) < size:
        return ""

    import capstone as _capstone  # type: ignore # noqa: PLC0415

    md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
    md.detail = False

    asm_lines = []
    for insn in md.disasm(code_bytes, va):
        asm_lines.append(f"0x{insn.address:08x}  {insn.mnemonic:8s} {insn.op_str}")

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


def compress_payload(body: bytes, accept_encoding: str) -> tuple[bytes, str]:
    """Compress payload using the best available algorithm."""
    if HAS_ZSTD and "zstd" in accept_encoding:
        cctx = zstd.ZstdCompressor(level=3)  # type: ignore
        return cctx.compress(body), "zstd"
    if HAS_BROTLI and "br" in accept_encoding:
        return brotli.compress(body), "br"  # type: ignore
    if "gzip" in accept_encoding:
        return gzip.compress(body), "gzip"
    return body, ""


# ── Index caching ──────────────────────────────────────────────────

CACHED_INDEX_PAYLOAD: bytes | None = None
CACHED_INDEX_COMPRESSED: dict[str, bytes] = {}
INDEX_LOCK = threading.Lock()

# ── SQL fragments ──────────────────────────────────────────────────

_FN_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'vaStart', vaStart, 'size', size, "
    "'fileOffset', fileOffset, 'status', status, 'origin', origin, "
    "'cflags', cflags, 'symbol', symbol, 'markerType', markerType, "
    "'ghidra_name', ghidra_name, 'r2_name', r2_name, "
    "'is_thunk', is_thunk, 'is_export', is_export, 'sha256', sha256, "
    "'files', json(files)"
    ")"
)

_GLOBAL_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'decl', decl, "
    "'files', json(files), 'isGlobal', 1"
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


def _json_ok(data, **headers: str) -> bytes:
    """Return compressed JSON 200."""
    body = json.dumps(data).encode("utf-8") if isinstance(data, dict) else data
    return _compressed(body, "application/json", **headers)


def _json_err(status: int, data: dict) -> Any:
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
def _cors_headers():
    if CORS_ENABLED:
        response.set_header("Access-Control-Allow-Origin", "*")
        response.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.set_header("Access-Control-Allow-Headers", "Content-Type")


@app.get("/potato")
def handle_potato():
    try:
        from recoverage.potato import render_potato  # type: ignore

        parsed = urlparse(request.url)
        body = render_potato(parsed).encode("utf-8")
        return _compressed(body, "text/html; charset=utf-8")
    except Exception as e:
        return HTTPResponse(status=500, body=f"Error: {e}")


@app.get("/")
@app.get("/index.html")
def handle_index():
    global CACHED_INDEX_PAYLOAD, CACHED_INDEX_COMPRESSED
    accept_encoding = request.headers.get("Accept-Encoding", "")

    with INDEX_LOCK:
        if CACHED_INDEX_PAYLOAD is None:
            assets = _assets_dir()
            html = (assets / "index.html").read_text(encoding="utf-8")
            css = (assets / "style.css").read_text(encoding="utf-8")
            js = (assets / "app.js").read_text(encoding="utf-8")
            try:
                vanjs = (assets / "van.min.js").read_text(encoding="utf-8")
            except FileNotFoundError:
                vanjs = ""

            html = html.replace(
                "<!-- INJECT_CSS -->", f"<style>{minify_css(css)}</style>"
            )
            html = html.replace(
                "<!-- INJECT_JS -->",
                f"<script>{vanjs}\n{minify_js(js)}</script>",
            )
            CACHED_INDEX_PAYLOAD = html.encode("utf-8")
            CACHED_INDEX_COMPRESSED.clear()

    _, encoding = compress_payload(b"", accept_encoding)
    with INDEX_LOCK:
        if encoding not in CACHED_INDEX_COMPRESSED:
            compressed, _ = compress_payload(CACHED_INDEX_PAYLOAD, accept_encoding)
            CACHED_INDEX_COMPRESSED[encoding] = compressed
        body = CACHED_INDEX_COMPRESSED[encoding]

    response.content_type = "text/html; charset=utf-8"
    response.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
    if encoding:
        response.set_header("Content-Encoding", encoding)
    response.set_header("Content-Length", str(len(body)))
    return body


@app.get("/api/health")
def handle_api_health():
    db = _db_path()
    db_info: dict[str, Any] = {"path": str(db), "exists": db.exists()}
    if db.exists():
        stat = db.stat()
        db_info["size_bytes"] = stat.st_size
        db_info["mtime"] = stat.st_mtime
    target_count = 0
    try:
        conn = _open_db(db)
        c = conn.cursor()
        c.execute("SELECT COUNT(DISTINCT target) FROM metadata")
        target_count = c.fetchone()[0]
        conn.close()
    except Exception:
        pass
    return _json_ok({
        "version": __version__,
        "db": db_info,
        "extras": {
            "capstone": HAS_CAPSTONE,
            "brotli": HAS_BROTLI,
            "zstd": HAS_ZSTD,
            "minify": HAS_MINIFIERS,
        },
        "targets_count": target_count,
        "cors": CORS_ENABLED,
    })


@app.get("/api/targets")
def handle_api_targets():
    try:
        conn = _db()
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM metadata")
        target_ids = [row[0] for row in c.fetchall()]
        conn.close()
    except sqlite3.OperationalError:
        target_ids = []

    if not target_ids:
        # DB not available or empty, try to get target from config files later
        pass

    targets_info: dict[str, Any] = {}
    root = _project_dir()
    try:
        import yaml  # type: ignore

        yml_path = root / "reccmp-project.yml"
        if yml_path.exists():
            with open(yml_path, "r") as f:
                doc = yaml.safe_load(f)
                if isinstance(doc, dict):
                    t = doc.get("targets")
                    if isinstance(t, dict):
                        targets_info.update(t)
    except Exception:
        pass

    # Fallback to rebrew.toml if reccmp-project.yml missing or empty
    if not targets_info:
        try:
            toml_path = root / "rebrew.toml"
            if toml_path.exists():
                text = toml_path.read_text(encoding="utf-8")
                import tomllib
                doc = tomllib.loads(text)
                targets_dict = doc.get("targets", {})
                for tid in targets_dict.keys():
                    targets_info[tid] = {"filename": tid}
        except Exception:
            pass

    targets_list = []
    for tid in target_ids:
        filename = tid
        t_info = targets_info.get(tid)
        if isinstance(t_info, dict) and "filename" in t_info:
            filename = Path(t_info["filename"]).name
        targets_list.append({"id": tid, "name": filename})

    if not targets_list and targets_info:
        for tid, t_info in targets_info.items():
            filename = t_info.get("filename", tid) if isinstance(t_info, dict) else tid
            targets_list.append({"id": tid, "name": Path(filename).name})

    return _json_ok(
        {"targets": targets_list},
        Cache_Control="no-cache, no-store, must-revalidate",
    )


@app.get("/api/targets/<target>/stats")
def handle_api_stats(target):
    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()

    # Pre-computed summary from metadata
    summary = {}
    c.execute("SELECT value FROM metadata WHERE target = ? AND key = 'summary'", (target,))
    row = c.fetchone()
    if row:
        try:
            summary = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            pass

    # Per-section stats from the view
    sections: dict[str, Any] = {}
    c.execute(
        "SELECT section_name, total_cells, exact_count, reloc_count, "
        "matching_count, stub_count FROM section_cell_stats WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        total = row["total_cells"]
        matched = row["exact_count"] + row["reloc_count"]
        sections[row["section_name"]] = {
            "total_cells": total,
            "exact": row["exact_count"],
            "reloc": row["reloc_count"],
            "matching": row["matching_count"],
            "stub": row["stub_count"],
            "matched": matched,
            "coverage_pct": round(matched / total * 100, 2) if total else 0.0,
        }

    # Section byte sizes
    c.execute("SELECT name, size FROM sections WHERE target = ?", (target,))
    for row in c.fetchall():
        name = row["name"]
        if name in sections:
            sections[name]["size_bytes"] = row["size"]

    # Function counts by status
    by_status: dict[str, int] = {}
    c.execute(
        "SELECT status, COUNT(*) as cnt FROM functions WHERE target = ? GROUP BY status",
        (target,),
    )
    for row in c.fetchall():
        by_status[row["status"] or "unknown"] = row["cnt"]

    conn.close()
    return _json_ok({
        "target": target,
        "summary": summary,
        "sections": sections,
        "functions_by_status": by_status,
    })


@app.get("/api/targets/<target>/data")
def handle_api_data(target):
    db = _db_path()
    section_filter = request.query.get("section", "").strip() or None

    # ETag caching based on DB modification time + target + section
    etag = None
    try:
        mtime = db.stat().st_mtime
        etag_key = f"{mtime}-{target}"
        if section_filter:
            etag_key += f"-{section_filter}"
        etag = f'"{etag_key}"'
        if request.headers.get("If-None-Match") == etag:
            return HTTPResponse(status=304)
    except FileNotFoundError:
        pass

    try:
        conn = _open_db(db)
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    data: dict = {}

    c.execute("SELECT key, value FROM metadata WHERE target = ?", (target,))
    for row in c.fetchall():
        try:
            data[row["key"]] = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            data[row["key"]] = row["value"]

    if section_filter:
        c.execute(
            "SELECT * FROM sections WHERE target = ? AND name = ?",
            (target, section_filter),
        )
    else:
        c.execute("SELECT * FROM sections WHERE target = ?", (target,))
    data["sections"] = {}
    for row in c.fetchall():
        sec = dict(row)
        sec["cells"] = []
        data["sections"][sec["name"]] = sec

    if section_filter:
        c.execute(
            "SELECT section_name, json_group_array(json_object("
            "'id', id, 'start', start, 'end', end, 'span', span, "
            "'state', state, 'functions', json(functions)"
            ")) FROM cells WHERE target = ? AND section_name = ? GROUP BY section_name",
            (target, section_filter),
        )
    else:
        c.execute(
            "SELECT section_name, json_group_array(json_object("
            "'id', id, 'start', start, 'end', end, 'span', span, "
            "'state', state, 'functions', json(functions)"
            ")) FROM cells WHERE target = ? GROUP BY section_name",
            (target,),
        )
    for row in c.fetchall():
        sec_name = row[0]
        if sec_name in data["sections"]:
            data["sections"][sec_name]["cells"] = json.loads(row[1])

    # Lightweight search index
    data["search_index"] = {}
    c.execute(
        "SELECT name, vaStart, symbol FROM functions WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        data["search_index"][row["name"]] = {
            "va": row["vaStart"],
            "symbol": row["symbol"],
        }
    c.execute("SELECT name, va FROM globals WHERE target = ?", (target,))
    for row in c.fetchall():
        data["search_index"][row["name"]] = {
            "va": hex(row["va"]) if row["va"] else "",
            "symbol": "",
        }

    # Per-section cell stats from SQL view
    data["section_cell_stats"] = {}
    if section_filter:
        c.execute(
            "SELECT section_name, total_cells, exact_count, reloc_count, "
            "matching_count, stub_count FROM section_cell_stats "
            "WHERE target = ? AND section_name = ?",
            (target, section_filter),
        )
    else:
        c.execute(
            "SELECT section_name, total_cells, exact_count, reloc_count, "
            "matching_count, stub_count FROM section_cell_stats WHERE target = ?",
            (target,),
        )
    for row in c.fetchall():
        data["section_cell_stats"][row["section_name"]] = {
            "total": row["total_cells"],
            "exact": row["exact_count"],
            "reloc": row["reloc_count"],
            "matching": row["matching_count"],
            "stub": row["stub_count"],
        }

    conn.close()
    if etag is not None:
        return _json_ok(data, Cache_Control="no-cache, must-revalidate", ETag=str(etag))
    return _json_ok(data, Cache_Control="no-cache, must-revalidate")


@app.get("/api/targets/<target>/functions")
def handle_api_functions_list(target):
    """Paginated function listing with optional filters."""
    status_filter = request.query.get("status", "").strip() or None
    search = request.query.get("search", "").strip() or None
    sort_param = request.query.get("sort", "va").strip()  # field:dir
    try:
        limit = min(int(request.query.get("limit", 50)), 500)
    except ValueError:
        limit = 50
    try:
        offset = max(int(request.query.get("offset", 0)), 0)
    except ValueError:
        offset = 0

    # Parse sort
    allowed_sort = {"va", "name", "size", "status", "symbol"}
    sort_field = "va"
    sort_dir = "ASC"
    if ":" in sort_param:
        sf, sd = sort_param.split(":", 1)
        if sf in allowed_sort:
            sort_field = sf
        if sd.lower() == "desc":
            sort_dir = "DESC"
    elif sort_param in allowed_sort:
        sort_field = sort_param

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    where = ["target = ?"]
    params: list[Any] = [target]

    if status_filter:
        where.append("status = ?")
        params.append(status_filter)
    if search:
        where.append("(name LIKE ? OR symbol LIKE ? OR CAST(va AS TEXT) LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])

    where_sql = " AND ".join(where)

    # Total count
    c.execute(f"SELECT COUNT(*) FROM functions WHERE {where_sql}", params)
    total = c.fetchone()[0]

    # Fetch page
    c.execute(
        f"SELECT va, name, vaStart, size, status, origin, symbol, markerType "
        f"FROM functions WHERE {where_sql} "
        f"ORDER BY {sort_field} {sort_dir} LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    items = []
    for row in c.fetchall():
        items.append({
            "va": row["va"],
            "name": row["name"],
            "vaStart": row["vaStart"],
            "size": row["size"],
            "status": row["status"],
            "origin": row["origin"],
            "symbol": row["symbol"],
            "markerType": row["markerType"],
        })

    conn.close()
    return _json_ok({
        "target": target,
        "total": total,
        "limit": limit,
        "offset": offset,
        "functions": items,
    })


@app.get("/api/targets/<target>/functions/<va>")
def handle_api_function(target, va):

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    no_cache = "no-cache, no-store, must-revalidate"

    # Try functions first (by va int or name string)
    try:
        va_int = int(va, 0)
        c.execute(
            f"SELECT {_FN_JSON_SQL} FROM functions WHERE target = ? AND va = ?",
            (target, va_int),
        )
    except ValueError:
        c.execute(
            f"SELECT {_FN_JSON_SQL} FROM functions WHERE target = ? AND name = ?",
            (target, va),
        )

    row = c.fetchone()
    if row:
        conn.close()
        return _json_ok(row[0].encode("utf-8"), Cache_Control=no_cache)

    # Try globals
    try:
        va_int = int(va, 0)
        c.execute(
            f"SELECT {_GLOBAL_JSON_SQL} FROM globals WHERE target = ? AND va = ?",
            (target, va_int),
        )
    except ValueError:
        c.execute(
            f"SELECT {_GLOBAL_JSON_SQL} FROM globals WHERE target = ? AND name = ?",
            (target, va),
        )

    row = c.fetchone()
    conn.close()
    if row:
        return _json_ok(row[0].encode("utf-8"), Cache_Control=no_cache)

    return _json_err(404, {"error": "not found"})


@app.get("/api/targets/<target>/asm")
def handle_api_asm(target):
    if not HAS_CAPSTONE:
        return _json_err(500, {"error": "capstone not installed"})

    va_str = request.query.get("va")
    size_str = request.query.get("size")
    section = request.query.get("section", ".text")
    fmt = request.query.get("format", "text").strip()

    if not va_str or not size_str:
        return _json_err(400, {"error": "missing va or size"})

    try:
        va = int(va_str, 0)
        size = min(int(size_str, 0), 4096)
    except ValueError:
        return _json_err(400, {"error": "invalid va or size"})

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    c.execute(
        "SELECT * FROM sections WHERE target = ? AND name = ?",
        (target, section),
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return _json_err(404, {"error": f"section {section} not found"})

    sec = dict(row)
    file_offset = sec["fileOffset"] + (va - sec["va"])

    if fmt == "json":
        # Structured JSON output
        target_data = _load_dll(target)
        if target_data is None:
            return _json_err(404, {"error": "DLL not found"})
        code_bytes = target_data[file_offset : file_offset + size]
        if len(code_bytes) < size:
            return _json_err(404, {"error": "not enough bytes in DLL"})

        import capstone as _capstone  # type: ignore # noqa: PLC0415

        md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
        md.detail = False
        instructions = []
        for insn in md.disasm(code_bytes, va):
            instructions.append({
                "addr": f"0x{insn.address:08x}",
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
            })
        return _json_ok(
            {"instructions": instructions},
            Cache_Control="public, max-age=31536000",
        )

    # Default: plain text
    asm_text = get_disassembly(va, size, file_offset, target)
    if not asm_text:
        return _json_err(404, {"error": "not enough bytes in DLL"})

    return _json_ok({"asm": asm_text}, Cache_Control="public, max-age=31536000")


@app.get("/api/targets/<target>/sections/<section>/bytes")
def handle_api_bytes(target, section):
    """Return raw bytes from the original binary for a given section range."""
    try:
        req_offset = int(request.query.get("offset", 0), 0)
    except ValueError:
        return _json_err(400, {"error": "invalid offset"})
    try:
        req_size = min(int(request.query.get("size", 256), 0), 4096)
    except ValueError:
        return _json_err(400, {"error": "invalid size"})

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    c = conn.cursor()
    c.execute(
        "SELECT * FROM sections WHERE target = ? AND name = ?",
        (target, section),
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return _json_err(404, {"error": f"section {section} not found"})

    sec = dict(row)
    target_data = _load_dll(target)
    if target_data is None:
        return _json_err(404, {"error": "DLL not found for target"})

    file_start = sec["fileOffset"] + req_offset
    chunk = target_data[file_start : file_start + req_size]

    # Format as hex lines (16 bytes per line)
    hex_lines = []
    for i in range(0, len(chunk), 16):
        line_bytes = chunk[i : i + 16]
        offset_str = f"{req_offset + i:08x}"
        hex_part = " ".join(f"{b:02x}" for b in line_bytes)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in line_bytes)
        hex_lines.append(f"{offset_str}  {hex_part:<48s}  |{ascii_part}|")

    return _json_ok({
        "target": target,
        "section": section,
        "offset": req_offset,
        "size": len(chunk),
        "hex": "\n".join(hex_lines),
        "raw": list(chunk),
    }, Cache_Control="public, max-age=31536000")


@app.post("/regen")
def handle_regen():
    remote = request.environ.get("REMOTE_ADDR", "")
    if remote not in ("127.0.0.1", "::1", "localhost"):
        return _json_err(403, {"ok": False, "error": "Forbidden: localhost only"})

    global CACHED_INDEX_PAYLOAD, CACHED_INDEX_COMPRESSED
    with INDEX_LOCK:
        CACHED_INDEX_PAYLOAD = None
        CACHED_INDEX_COMPRESSED.clear()

    root = _project_dir()
    try:
        subprocess.check_call(
            ["uv", "run", "rebrew", "catalog"],
            cwd=str(root),
            timeout=60,
        )
        subprocess.check_call(
            ["uv", "run", "rebrew", "build-db"],
            cwd=str(root),
            timeout=60,
        )
        return _json_ok({"ok": True})
    except subprocess.TimeoutExpired:
        return _json_err(504, {"ok": False, "error": "Regen timed out"})
    except subprocess.CalledProcessError as e:
        return _json_err(500, {"ok": False, "code": e.returncode})


# ── Static file serving ────────────────────────────────────────────
# Serve /src/* and /original/* from project dir (for source viewing)
# Serve static assets (app.js, style.css) from package assets


@app.get("/src/<filepath:path>")
@app.get("/original/<filepath:path>")
def serve_repo_file(filepath):
    """Serve source and original files from project dir (path-traversal safe)."""
    prefix = "src" if request.path.startswith("/src/") else "original"
    return static_file(filepath, root=str(_project_dir() / prefix))


@app.get("/<filename:re:(?:app\\.js|style\\.css|van\\.min\\.js)>")
def serve_static_asset(filename):
    return static_file(filename, root=str(_assets_dir()))


# ── Browser opener ─────────────────────────────────────────────────


def open_browser(url: str) -> None:
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.Popen(
                ["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        elif system == "Darwin":
            subprocess.Popen(
                ["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
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



