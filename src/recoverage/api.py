"""API routes for the recoverage dashboard."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from recoverage import __version__
from recoverage import server as _server
from recoverage.server import (
    _FN_JSON_SQL,
    _GLOBAL_JSON_SQL,
    DLL_DATA,
    DLL_LOCK,
    HAS_BROTLI,
    HAS_CAPSTONE,
    HAS_MINIFIERS,
    HAS_ZSTD,
    HTTPResponse,
    _db,
    _db_path,
    _json_err,
    _json_ok,
    _load_dll,
    _open_db,
    _project_dir,
    app,
    get_disassembly,
    request,
)


@app.get("/api/health")
def handle_api_health() -> bytes:
    db = _db_path()
    db_info: dict[str, Any] = {"path": str(db), "exists": db.exists()}
    if db.exists():
        stat = db.stat()
        db_info["size_bytes"] = stat.st_size
        db_info["mtime"] = stat.st_mtime
    target_count = 0
    try:
        conn = _open_db(db)
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(DISTINCT target) FROM metadata")
            target_count = c.fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return _json_ok(
        {
            "version": __version__,
            "db": db_info,
            "extras": {
                "capstone": HAS_CAPSTONE,
                "brotli": HAS_BROTLI,
                "zstd": HAS_ZSTD,
                "minify": HAS_MINIFIERS,
            },
            "targets_count": target_count,
            "cors": _server.CORS_ENABLED,
        }
    )


@app.get("/api/targets")
def handle_api_targets() -> bytes:
    try:
        conn = _db()
        try:
            c = conn.cursor()
            c.execute("SELECT DISTINCT target FROM metadata")
            target_ids = [row[0] for row in c.fetchall()]
        finally:
            conn.close()
    except sqlite3.OperationalError:
        target_ids = []

    targets_info = _server._get_targets_config()

    targets_list: list[dict[str, str]] = []
    added_tids: set[str] = set()

    # 1. Add targets in the order they appear in config
    for tid, t_info in targets_info.items():
        if tid in target_ids or not target_ids:
            filename = t_info.get("filename", tid) if isinstance(t_info, dict) else tid
            targets_list.append({"id": tid, "name": Path(filename).name})
            added_tids.add(tid)

    # 2. Add any remaining targets from the DB that weren't in config
    for tid in target_ids:
        if tid not in added_tids:
            targets_list.append({"id": tid, "name": tid})

    return _json_ok(
        {"targets": targets_list},
        Cache_Control="no-cache, no-store, must-revalidate",
    )


@app.get("/api/targets/<target>/stats")
def handle_api_stats(target: str) -> bytes | Any:
    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    try:
        c = conn.cursor()

        # Pre-computed summary from metadata
        summary: dict[str, Any] = {}
        c.execute("SELECT value FROM metadata WHERE target = ? AND key = 'summary'", (target,))
        row = c.fetchone()
        if row:
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                summary = json.loads(row[0])

        # Per-section stats from the view
        sections: dict[str, Any] = {}
        c.execute(
            "SELECT section_name, total_cells, exact_count, reloc_count, "
            "matching_count, stub_count, data_count, thunk_count FROM section_cell_stats WHERE target = ?",
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
                "data": row["data_count"],
                "thunk": row["thunk_count"],
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

        return _json_ok(
            {
                "target": target,
                "summary": summary,
                "sections": sections,
                "functions_by_status": by_status,
            }
        )
    finally:
        conn.close()


@app.get("/api/targets/<target>/data")
def handle_api_data(target: str) -> bytes | Any:
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
    except OSError:
        pass

    try:
        conn = _open_db(db)
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    try:
        c = conn.cursor()
        data: dict[str, Any] = {}

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
                "'state', state, 'functions', json(functions), 'label', label, 'parent_function', parent_function"
                ")) FROM cells WHERE target = ? AND section_name = ? GROUP BY section_name",
                (target, section_filter),
            )
        else:
            c.execute(
                "SELECT section_name, json_group_array(json_object("
                "'id', id, 'start', start, 'end', end, 'span', span, "
                "'state', state, 'functions', json(functions), 'label', label, 'parent_function', parent_function"
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
                "matching_count, stub_count, data_count, thunk_count FROM section_cell_stats "
                "WHERE target = ? AND section_name = ?",
                (target, section_filter),
            )
        else:
            c.execute(
                "SELECT section_name, total_cells, exact_count, reloc_count, "
                "matching_count, stub_count, data_count, thunk_count FROM section_cell_stats WHERE target = ?",
                (target,),
            )
        for row in c.fetchall():
            data["section_cell_stats"][row["section_name"]] = {
                "total": row["total_cells"],
                "exact": row["exact_count"],
                "reloc": row["reloc_count"],
                "matching": row["matching_count"],
                "stub": row["stub_count"],
                "data": row["data_count"],
                "thunk": row["thunk_count"],
            }

        if etag is not None:
            return _json_ok(data, Cache_Control="no-cache, must-revalidate", ETag=str(etag))
        return _json_ok(data, Cache_Control="no-cache, must-revalidate")
    finally:
        conn.close()


@app.get("/api/targets/<target>/functions")
def handle_api_functions_list(target: str) -> bytes | Any:
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
    allowed_sort = {"va", "name", "size", "status", "symbol", "origin"}
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

    try:
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
        items: list[dict[str, Any]] = []
        for row in c.fetchall():
            items.append(
                {
                    "va": row["va"],
                    "name": row["name"],
                    "vaStart": row["vaStart"],
                    "size": row["size"],
                    "status": row["status"],
                    "origin": row["origin"],
                    "symbol": row["symbol"],
                    "markerType": row["markerType"],
                }
            )

        return _json_ok(
            {
                "target": target,
                "total": total,
                "limit": limit,
                "offset": offset,
                "functions": items,
            }
        )
    finally:
        conn.close()


@app.get("/api/targets/<target>/functions/<va>")
def handle_api_function(target: str, va: str) -> bytes | Any:
    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    try:
        c = conn.cursor()
        no_cache = "no-cache, no-store, must-revalidate"

        # Parse va once: numeric -> lookup by va column, string -> lookup by name
        try:
            va_int = int(va, 0)
            is_numeric = True
        except ValueError:
            va_int = 0
            is_numeric = False

        # Try functions first
        if is_numeric:
            c.execute(
                f"SELECT {_FN_JSON_SQL} FROM functions WHERE target = ? AND va = ?",
                (target, va_int),
            )
        else:
            c.execute(
                f"SELECT {_FN_JSON_SQL} FROM functions WHERE target = ? AND name = ?",
                (target, va),
            )

        row = c.fetchone()
        if row:
            return _json_ok(row[0].encode("utf-8"), Cache_Control=no_cache)

        # Try globals
        if is_numeric:
            c.execute(
                f"SELECT {_GLOBAL_JSON_SQL} FROM globals WHERE target = ? AND va = ?",
                (target, va_int),
            )
        else:
            c.execute(
                f"SELECT {_GLOBAL_JSON_SQL} FROM globals WHERE target = ? AND name = ?",
                (target, va),
            )

        row = c.fetchone()
        if row:
            return _json_ok(row[0].encode("utf-8"), Cache_Control=no_cache)

        return _json_err(404, {"error": "not found"})
    finally:
        conn.close()


@app.get("/api/targets/<target>/asm")
def handle_api_asm(target: str) -> bytes | Any:
    if not HAS_CAPSTONE:
        return _json_err(501, {"error": "capstone not installed"})

    va_str = request.query.get("va")
    size_str = request.query.get("size")
    section = request.query.get("section", ".text")
    fmt = request.query.get("format", "text").strip()

    if not va_str or not size_str:
        return _json_err(400, {"error": "missing va or size"})

    try:
        va = int(va_str, 0)
        size = min(max(int(size_str, 0), 0), 4096)
    except ValueError:
        return _json_err(400, {"error": "invalid va or size"})

    if size == 0:
        return _json_err(400, {"error": "size must be positive"})

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    try:
        c = conn.cursor()
        c.execute(
            "SELECT * FROM sections WHERE target = ? AND name = ?",
            (target, section),
        )
        row = c.fetchone()

        if not row:
            return _json_err(404, {"error": f"section {section} not found"})

        sec = dict(row)
        file_offset = sec["fileOffset"] + (va - sec["va"])
        if file_offset < 0:
            return _json_err(400, {"error": "va is before section start"})

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
            instructions: list[dict[str, Any]] = []
            for insn in md.disasm(code_bytes, va):
                instructions.append(
                    {
                        "addr": f"0x{insn.address:08x}",
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "size": insn.size,
                    }
                )
            return _json_ok(
                {"instructions": instructions},
                Cache_Control="public, max-age=31536000",
            )

        # Default: plain text
        asm_text = get_disassembly(va, size, file_offset, target)
        if not asm_text:
            return _json_err(404, {"error": "not enough bytes in DLL"})

        return _json_ok({"asm": asm_text}, Cache_Control="public, max-age=31536000")
    finally:
        conn.close()


@app.get("/api/targets/<target>/sections/<section>/bytes")
def handle_api_bytes(target: str, section: str) -> bytes | Any:
    """Return raw bytes from the original binary for a given section range."""
    try:
        req_offset = int(request.query.get("offset", "0"), 0)
        if req_offset < 0:
            return _json_err(400, {"error": "invalid offset"})
    except (ValueError, TypeError):
        return _json_err(400, {"error": "invalid offset"})
    try:
        req_size = min(max(int(request.query.get("size", "256"), 0), 0), 4096)
    except (ValueError, TypeError):
        return _json_err(400, {"error": "invalid size"})

    try:
        conn = _db()
    except sqlite3.OperationalError as e:
        return _json_err(503, {"error": str(e)})

    try:
        c = conn.cursor()
        c.execute(
            "SELECT * FROM sections WHERE target = ? AND name = ?",
            (target, section),
        )
        row = c.fetchone()

        if not row:
            return _json_err(404, {"error": f"section {section} not found"})

        sec = dict(row)
        target_data = _load_dll(target)
        if target_data is None:
            return _json_err(404, {"error": "DLL not found for target"})

        file_start = sec["fileOffset"] + req_offset
        chunk = target_data[file_start : file_start + req_size]

        # Format as hex lines (16 bytes per line)
        hex_lines: list[str] = []
        for i in range(0, len(chunk), 16):
            line_bytes = chunk[i : i + 16]
            offset_str = f"{req_offset + i:08x}"
            hex_part = " ".join(f"{b:02x}" for b in line_bytes)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in line_bytes)
            hex_lines.append(f"{offset_str}  {hex_part:<48s}  |{ascii_part}|")

        return _json_ok(
            {
                "target": target,
                "section": section,
                "offset": req_offset,
                "size": len(chunk),
                "hex": "\n".join(hex_lines),
                "raw": list(chunk),
            },
            Cache_Control="public, max-age=31536000",
        )
    finally:
        conn.close()


@app.post("/regen")
def handle_regen() -> bytes | Any:
    from recoverage.ui import clear_index_cache  # noqa: PLC0415

    remote = request.environ.get("REMOTE_ADDR", "")
    if remote not in ("127.0.0.1", "::1", "localhost"):
        return _json_err(403, {"ok": False, "error": "Forbidden: localhost only"})

    clear_index_cache()

    # Clear DLL and disassembly caches so regen picks up new binaries
    with DLL_LOCK:
        DLL_DATA.clear()
    get_disassembly.cache_clear()
    _server._TARGETS_CACHE = None

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
