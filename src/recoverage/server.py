#!/usr/bin/env python3
"""Recoverage server — coverage dashboard for binary-matching projects.

Bottle WSGI app serving a VanJS + SQLite dashboard.
Reads the coverage database from the path resolved by
``recoverage._paths._db_path()``, which honours
``rebrew-project.toml [project] db_dir`` when present and falls back to
``./db/coverage.db`` otherwise.
"""

from __future__ import annotations

import contextlib
import functools
import gzip
import hashlib
import hmac
import importlib.util
import json
import logging
import os
import signal
import sqlite3
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import bottle  # type: ignore[import-untyped]
import brotli  # type: ignore[import-untyped]
import zstandard as zstd

from recoverage._paths import _db_path, sqlite_ro_uri

# Thread-local compressor — python-zstandard gives ZstdCompressor instances NO
# thread-safety guarantees ("do not operate on the same instance from different
# threads") and releases the GIL inside compress(), so a shared instance raced
# on one ZSTD_CCtx and reproducibly segfaulted the server under concurrent
# requests.  One context per request thread (same pattern as _get_capstone_md).
_ZSTD_COMPRESSOR_TLS = threading.local()


def _get_zstd_compressor() -> Any:
    compressor = getattr(_ZSTD_COMPRESSOR_TLS, "compressor", None)
    if compressor is None:
        compressor = _ZSTD_COMPRESSOR_TLS.compressor = zstd.ZstdCompressor(level=3)
    return compressor


# Shared timeout for rebrew regen subprocesses (imported by cli.py and api.py)
REGEN_TIMEOUT = 120  # seconds — must accommodate large projects


def _kill_and_reap(proc: subprocess.Popen[bytes]) -> None:
    """Kill *proc* — on POSIX its whole session — and always reap it.

    Every child we spawn gets its own session (start_new_session), so
    terminal signals such as Ctrl+C never reach it: any abandonment path
    must signal the process GROUP, not just the direct child, or the rebrew
    grandchild survives and keeps writing coverage.db behind a restarted
    dashboard.  The trailing wait() reaps the child either way (setsid does
    not prevent zombies; only a wait does).
    """
    if os.name == "posix":
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    else:
        proc.kill()
    proc.wait()


def run_regen_step(step: str, root: Path) -> None:
    """Run ``uv run rebrew <step>`` in *root*, killing the whole process group on timeout.

    ``check_call(timeout=...)`` kills only the direct child (uv); the actual
    rebrew worker is uv's grandchild and would survive, still writing
    coverage.db while the dashboard resumes serving.  The child gets its own
    session so the group can be signalled, and it is always reaped — on
    timeouts AND on KeyboardInterrupt/SystemExit mid-wait, which would
    otherwise orphan the still-running regen tree.
    """
    cmd = ["uv", "run", "rebrew", step]
    proc = subprocess.Popen(cmd, cwd=str(root), start_new_session=(os.name == "posix"))
    try:
        proc.wait(timeout=REGEN_TIMEOUT)
    except subprocess.TimeoutExpired:
        _kill_and_reap(proc)
        raise subprocess.TimeoutExpired(cmd, REGEN_TIMEOUT) from None
    except BaseException:
        # KeyboardInterrupt (Ctrl+C during serve --regen / POST /api/regen) or
        # interpreter shutdown: the child sits in its own session, so the
        # terminal's SIGINT did not reach it — kill the group before dying or
        # uv+rebrew keep rebuilding coverage.db as orphans.
        _kill_and_reap(proc)
        raise
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)


Bottle = cast(Any, bottle.Bottle)
request = cast(Any, bottle.request)
response = cast(Any, bottle.response)
static_file = cast(Any, bottle.static_file)
HTTPResponse = cast(Any, bottle.HTTPResponse)

HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None
HAS_PYGMENTS = importlib.util.find_spec("pygments") is not None

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

# Loopback hostnames, ONE definition shared by the CLI's --bind guard, the
# regen endpoint's remote-addr/Origin checks, and the DNS-rebinding Host
# allowlist above.  Membership tests only — order carries no meaning.
LOOPBACK_HOSTS: tuple[str, ...] = ("127.0.0.1", "::1", "localhost")


def _hostname_of(origin: str) -> str:
    """Lowercased hostname of an Origin/Host header value ("" if unparsable).

    Origins carry a scheme (``http://localhost:5173``); bare Host headers
    (``localhost:8001``) get a synthetic scheme so urlsplit parses both.
    Values containing userinfo/escape characters (``evil@host``, backslash,
    percent-encoding, control bytes) are rejected — browsers never emit them
    in Host/Origin, so their presence means the value is not a plain header.
    """
    if any(ch in origin for ch in ("@", "\\", "%")) or any(ord(c) < 32 for c in origin):
        return ""
    try:
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


def _safe_etag(*parts: object) -> str:
    """Deterministic ETag from arbitrary parts.

    Parts include request-controlled strings (VA, section, format) — they
    are hashed so no raw request data can ever reach a response header
    (bottle rejects control characters, but that is a library property,
    not the app's contract).
    """
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:32]
    return f'"{digest}"'


def _snapshot_db_mtime() -> tuple[int, int] | None:
    """Return (fingerprint, main-file size) of coverage.db, or None when unreadable.

    The fingerprint folds the DB's identity into one int (main-file
    mtime_ns + size, plus -wal's when present); element 1 is the main file's
    size alone.  Callers must treat the fingerprint as an opaque change
    token, never as an mtime.

    WAL-aware: the DB runs in ``journal_mode=wal``, so a writer can commit
    to ``coverage.db-wal`` without checkpointing the main file — main-file
    mtime/size alone would miss the change (stale memo/ETag/watcher).  Fold
    the -wal stat in.  (NOT -shm: sqlite touches the shared-memory index on
    every connection, so including it would make the snapshot — and thus
    every ETag — change between requests.)

    EVERY DB-derived cache key and ETag must be built on this snapshot, not
    raw ``st_mtime`` — raw mtimes served stale 304s after rebuilds that only
    touched the WAL.
    """
    try:
        st = _db_path().stat()
        acc = st.st_mtime_ns + st.st_size
        try:
            w = Path(f"{_db_path()}-wal").stat()
            acc += w.st_mtime_ns + w.st_size
        except OSError:
            pass
        return acc, st.st_size
    except OSError:
        return None


def _etag_or_304(snap: tuple[int, int] | None, *parts: object) -> str | None:
    """DB-freshness ETag over the WAL-aware snapshot *snap* + *parts*; 304 on match.

    Shared tail of every cacheable DB-derived endpoint (/data, /asm, /bytes,
    /potato): compute ``_safe_etag(snap[0], parts...)``, answer
    ``If-None-Match`` with a 304, else hand the ETag back for the caller to
    attach to its response.  Callers pass their own
    :func:`_snapshot_db_mtime` result — endpoints that also key a memo on
    that snapshot (/data) stat the DB exactly once.  Returns None when *snap*
    is None (DB unreadable) — the caller then sends no ETag (the endpoint
    itself fails with 503 shortly after).
    """
    if snap is None:
        return None
    etag = _safe_etag(snap[0], *parts)
    if request.headers.get("If-None-Match") == etag:
        raise HTTPResponse(
            status=304,
            headers={"ETag": etag, "Cache-Control": CACHE_REVALIDATE},
        )
    return etag


# Byte-based per-section stats query shared by /api/targets/<target>/stats and
# the `recoverage stats` CLI.  ONE definition: these two queries already
# drifted apart once (cell-count vs byte-based coverage) and were fixed in
# lockstep twice — a single constant makes the next divergence impossible.
# Bucket set matches the section_cell_stats view served by /api/.../data so
# consumers can sum the buckets and reconcile with total_cells everywhere.
SECTION_STATS_SQL = """
    SELECT section_name,
      SUM(CASE WHEN state != 'none' THEN end - start ELSE 0 END) AS covered_bytes,
      SUM(end - start) AS total_bytes,
      COUNT(*) AS total_cells,
      SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) AS exact_count,
      SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) AS reloc_count,
      SUM(CASE WHEN state IN ('near_match','near_matching') THEN 1 ELSE 0 END) AS near_match_count,
      SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) AS stub_count,
      SUM(CASE WHEN state = 'padding' THEN 1 ELSE 0 END) AS padding_count,
      SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) AS data_count,
      SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) AS thunk_count,
      SUM(CASE WHEN state = 'none' THEN 1 ELSE 0 END) AS none_count,
      SUM(CASE WHEN state = 'proven' THEN 1 ELSE 0 END) AS proven_count,
      SUM(CASE WHEN state = 'size_mismatch' THEN 1 ELSE 0 END) AS size_mismatch_count
    FROM cells WHERE target = ? GROUP BY section_name
"""


def _cell_bucket_row(row: sqlite3.Row) -> dict[str, Any]:
    """Map a per-section stats row (SECTION_STATS_SQL or the
    section_cell_stats view) to the short-key bucket dict served by /stats
    and /data.  ONE definition so the two response shapes cannot drift."""
    return {
        "total_cells": row["total_cells"],
        "exact": row["exact_count"],
        "reloc": row["reloc_count"],
        "near_match": row["near_match_count"],
        "stub": row["stub_count"],
        "padding": row["padding_count"],
        "data": row["data_count"],
        "thunk": row["thunk_count"],
        "none": row["none_count"],
        "proven": row["proven_count"],
        "size_mismatch": row["size_mismatch_count"],
    }


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
        # PROVEN is a semantic-equivalence promotion and counts as matched
        # (consistent with the catalog grid's matchedFunctions).
        matched = row["exact_count"] + row["reloc_count"] + row["proven_count"]
        sections[row["section_name"]] = {
            **_cell_bucket_row(row),
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

# Control characters (C0 + DEL), which would otherwise let a crafted URL
# forge multi-line entries in the request log (%0A in the path percent-
# decodes to a raw newline).  Each is replaced by its \xNN escape so the
# offending request stays identifiable while remaining one log line.
_LOG_CONTROL_CHARS = {c: f"\\x{c:02x}" for c in range(32)} | {127: "\\x7f"}


def _log_safe(value: str) -> str:
    """Escape control characters in untrusted text destined for the log."""
    return value.translate(_LOG_CONTROL_CHARS)


# Reserved metadata target holding the schema-level db_version stamp (written
# by rebrew build-db).  It is NOT a real project target and must never appear
# in target enumeration, stats, or the dashboard dropdown.
SCHEMA_TARGET = "__schema__"


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
                    # The DLL path comes from [targets.<tid>].binary; an
                    # entry without one stores "" so DLL lookups report the
                    # target-specific error instead of resolving a wrong
                    # file (display names fall back to the target id).
                    binary = ""
                    if isinstance(tdata, dict):
                        b = tdata.get("binary", "")
                        if isinstance(b, str):
                            binary = b
                    targets_info[tid] = {"filename": binary}
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


def _target_filename(tid: str, t_info: Any) -> str:
    """Binary filename configured for target *tid* (*tid* when unset).

    ONE definition of the defensive shape check used for display names —
    the config loader stores the raw ``binary`` value ("" when absent), and
    both target-list builders fall back to the id here.
    """
    filename = t_info.get("filename", tid) if isinstance(t_info, dict) else tid
    return filename if filename else tid


def resolve_targets(c: sqlite3.Cursor) -> tuple[list[str], list[dict[str, str]]]:
    """Resolve available targets from DB + config (thread-safe, cached via RLock)."""
    global _RESOLVED_TARGETS_CACHE
    with _RESOLVED_TARGETS_CACHE_LOCK:
        if _RESOLVED_TARGETS_CACHE is not None:
            return _RESOLVED_TARGETS_CACHE["target_ids"], _RESOLVED_TARGETS_CACHE["targets_list"]

        c.execute("SELECT DISTINCT target FROM metadata WHERE target != ?", (SCHEMA_TARGET,))
        target_ids = [row[0] for row in c.fetchall()]
        targets_info = _get_targets_config()

        # Config-declared targets come first and are always addressable, even
        # before their first build — _require_target treats "declared in the
        # project config" as valid, so a never-built target must not 404.
        targets_list = [
            {"id": tid, "name": Path(_target_filename(tid, t_info)).name}
            for tid, t_info in targets_info.items()
        ]
        targets_list += [{"id": tid, "name": tid} for tid in target_ids if tid not in targets_info]

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
    t_info = targets.get(target)
    filename = t_info.get("filename", "") if isinstance(t_info, dict) else ""
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
        except OSError as exc:
            _log.warning(
                "Failed to load DLL for target %s at %s: %s: %s",
                target,
                dll_path,
                type(exc).__name__,
                exc,
            )
            # Transient OS failure (file being rewritten by a build, AV lock):
            # NOT cached — DLL_DATA[target] = None here would keep the target's
            # disassembly/bytes endpoints failing until the next rebuild
            # broadcast clears the cache.  Retrying on the next request
            # self-heals for free.
            return None
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
        import capstone as _capstone  # type: ignore[import-not-found]

        md = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_32)
        md.detail = False
        _CAPSTONE_MD_TLS.md = md
    return md


def get_disassembly(va: int, size: int, file_offset: int, target: str) -> str:
    """Disassemble *size* bytes of *target* at *va*, memoized per slice.

    The DLL-load guard deliberately stays OUTSIDE the memo cache: ``_load_dll``
    leaves transient OS failures uncached so the next request self-heals, and
    memoizing their "" result here would pin that outage until the next
    rebuild broadcast happened to clear the cache.
    """
    if _load_dll(target) is None:
        return ""
    return _disassemble_loaded(va, size, file_offset, target)


@functools.lru_cache(maxsize=2048)
def _disassemble_loaded(va: int, size: int, file_offset: int, target: str) -> str:
    """Cached disassembly; :func:`get_disassembly` verified the DLL loads."""
    target_data = _load_dll(target)
    if target_data is None:
        # Raced a rebuild's DLL_DATA.clear() between the two loads; the same
        # broadcast clears this cache, so the "" can never be served twice.
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


def clear_disassembly_cache() -> None:
    """Drop memoized disassembly (called when the original binary changes)."""
    _disassemble_loaded.cache_clear()


# ── Compression ────────────────────────────────────────────────────


def _best_encoding(accept_encoding: str) -> str:
    """Return the best available compression encoding name, or empty string.

    Parses comma-separated tokens from Accept-Encoding to avoid false substring
    matches (e.g. 'not-zstd' should not match 'zstd').  Honours q-values as an
    exclusion gate only — ``gzip;q=0`` means "not acceptable" (RFC 9110) and
    must not be chosen — then applies a fixed preference order among the
    remaining supported encodings (zstd, then br, then gzip), regardless of
    the tokens' relative q-values.
    """
    candidates: dict[str, float] = {}
    for t in accept_encoding.split(","):
        parts = [p.strip().lower() for p in t.split(";")]
        name = parts[0]
        if not name or name == "*":
            continue
        q = 1.0
        for param in parts[1:]:
            if param.startswith("q="):
                try:
                    q = float(param[2:])
                except ValueError:
                    q = 0.0
        if q > 0:
            candidates[name] = max(candidates.get(name, 0.0), q)
    for name in ("zstd", "br", "gzip"):
        if name in candidates:
            return name
    return ""


# Brotli quality is the difference between a fast response and a stalled one.
# On a 5.6 MB coverage payload, measured: q=11 gives 334 KB in 5.9 s, q=5 gives
# 444 KB in 68 ms.  Dynamic responses pay that cost on every request (there is
# no compressed-response cache), and clients without zstd — Safari, older
# browsers — land on brotli, so q=11 there means a six-second stall on every
# load and every live reload.  110 KB is cheaper than 5.8 s on any real link.
BROTLI_DYNAMIC_QUALITY = 5
# The inlined index is compressed once and cached per encoding, and it has a
# hard byte budget (the initial congestion window), so it keeps maximum effort.
BROTLI_STATIC_QUALITY = 11


def compress_payload(
    body: bytes, accept_encoding: str, brotli_quality: int = BROTLI_DYNAMIC_QUALITY
) -> tuple[bytes, str]:
    """Compress body with the best algorithm the client accepts.

    Returns (compressed_body, encoding_name). encoding_name is "" if no
    compression was applied, guaranteeing the caller can always set
    Content-Encoding only when encoding is truthy.
    """
    encoding = _best_encoding(accept_encoding)
    if encoding == "zstd":
        return _get_zstd_compressor().compress(body), "zstd"
    if encoding == "br":
        return brotli.compress(body, quality=brotli_quality), "br"
    if encoding == "gzip":
        # Level 6, not gzip.compress's default 9: measured on a ~9 MB /data
        # payload, -9 costs 2x the CPU of -6 for ~9% fewer bytes (96 ms ->
        # 707 KB vs 45 ms -> 774 KB).  Dynamic responses pay this on every
        # request, and scripted clients (python-requests advertises only
        # gzip) always land here.  Same reasoning as BROTLI_DYNAMIC_QUALITY.
        return gzip.compress(body, compresslevel=6), "gzip"
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


# Upper bound for client-supplied VA integers.  SQLite INTEGER is a SIGNED
# 64-bit value: anything larger raises OverflowError at execute time, which
# would surface as an uncaught 500 instead of a clean 4xx/404.  No stored
# va can exceed this (rebrew writes through the same binding), so rejecting
# above it can never hide a real match.
VA_MAX = (1 << 63) - 1


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

# Cell shape contract for BOTH consumers (SPA /data and Potato grid): the
# json_object keys here are what app.js and potato.py render.  ONE fragment
# so a column added for one surface cannot silently miss the other.
_CELLS_JSON_SQL = (
    "SELECT section_name, json_group_array(json_object("
    "'id', id, 'start', start, 'end', end, 'span', span, "
    "'state', state, 'functions', json(functions), 'label', label, "
    "'parent_function', parent_function"
    ")) FROM cells WHERE target = ?"
)


def _cells_json_rows(
    c: sqlite3.Cursor, target: str, section: str | None = None
) -> list[sqlite3.Row]:
    """Per-section cell JSON payloads as (section_name, cells_json) rows."""
    clause = " AND section_name = ?" if section else ""
    params: list[Any] = [target] + ([section] if section else [])
    c.execute(_CELLS_JSON_SQL + f"{clause} GROUP BY section_name", params)
    return c.fetchall()


def _evict_oldest(cache: dict[Any, Any], max_size: int) -> None:
    """Drop oldest entries (dict insertion order) until *cache* holds < max_size.

    ONE definition of the bounded-cache arithmetic shared by the /data
    payload memo and Potato's cells memo — both cap multi-MB payloads so a
    long-running server across many rebuilds cannot accumulate forever.
    Caller holds the cache's own lock.
    """
    if len(cache) >= max_size:
        for old_key in list(cache)[: len(cache) - max_size + 1]:
            cache.pop(old_key, None)


def _load_metadata(c: sqlite3.Cursor, target: str) -> dict[str, Any]:
    """Load *target*'s metadata rows as a dict, JSON-decoding values when valid.

    ONE loader for every consumer of the metadata table (SPA /data, Potato
    summary/paths): malformed JSON falls back to the raw string instead of
    failing the whole response.
    """
    data: dict[str, Any] = {}
    c.execute("SELECT key, value FROM metadata WHERE target = ?", (target,))
    for key, value in c.fetchall():
        try:
            data[key] = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            data[key] = value
    return data


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
    # WAL-aware snapshot, not raw st_mtime: a rebuild that commits only to
    # -wal must invalidate the memo or a stale verdict (e.g. "<incomplete>")
    # survives the fix — same contract as every other DB-derived cache key.
    fingerprint = _snapshot_db_mtime()
    if fingerprint is not None:
        with _RESOLVED_TARGETS_CACHE_LOCK:
            if _SCHEMA_VERSION_CACHE is not None and _SCHEMA_VERSION_CACHE[0] == fingerprint:
                return _SCHEMA_VERSION_CACHE[1]
    version = _check_schema_version_uncached(conn)
    if fingerprint is not None:
        with _RESOLVED_TARGETS_CACHE_LOCK:
            _SCHEMA_VERSION_CACHE = (fingerprint, version)
    return version


def _missing_required_columns(conn: sqlite3.Connection) -> set[str]:
    """Query-critical columns a v4 DB must have; ``table.column`` for gaps.

    The name-only shape gate passes a DB stamped "4" whose ``functions``
    table lacks ``textOffset``/``similarity`` (queried by the function
    detail endpoint) or whose ``section_cell_stats`` view is stale — those
    fail at query time instead of at open.  Column sets mirror the schema
    build_db creates so drift is caught here.
    """
    required_columns: dict[str, set[str]] = {
        "metadata": {"target", "key", "value"},
        "sections": {"target", "name", "va", "size", "fileOffset", "unitBytes", "columns"},
        "cells": {
            "target",
            "section_name",
            "start",
            "end",
            "span",
            "state",
            "functions",
            "label",
            "parent_function",
        },
        "functions": {
            "target",
            "va",
            "name",
            "vaStart",
            "size",
            "fileOffset",
            "status",
            "module",
            "cflags",
            "symbol",
            "markerType",
            "ghidra_name",
            "list_name",
            "is_thunk",
            "is_export",
            "sha256",
            "files",
            "detected_by",
            "size_by_tool",
            "textOffset",
            "blocker",
            "blockerDelta",
            "size_reason",
            "similarity",
        },
        "globals": {"target", "va", "name", "decl", "files", "module", "size"},
        "verify_results": {"target", "va", "verified_at", "byte_delta", "diff_lines", "similarity"},
        "section_cell_stats": {
            "target",
            "section_name",
            "total_cells",
            "exact_count",
            "reloc_count",
            "near_match_count",
            "stub_count",
            "padding_count",
            "data_count",
            "thunk_count",
            "none_count",
            "proven_count",
            "size_mismatch_count",
        },
    }
    missing: set[str] = set()
    for obj, cols in required_columns.items():
        try:
            rows = conn.execute(f"PRAGMA table_info({obj})").fetchall()
        except sqlite3.Error:
            missing.add(obj)
            continue
        actual = {r[1] for r in rows}
        for col in cols - actual:
            missing.add(f"{obj}.{col}")
    return missing


def _check_schema_version_uncached(conn: sqlite3.Connection) -> str:
    """Uncached schema version read; see :func:`_check_schema_version`."""
    try:
        # Prefer the schema-level __schema__ stamp (deterministic across
        # targets); fall back to any per-target stamp for legacy DBs.
        row = conn.execute(
            "SELECT value FROM metadata WHERE target = ? AND key = 'db_version' LIMIT 1",
            (SCHEMA_TARGET,),
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
            if not missing and version == "4":
                # Object names present — verify the query-critical columns.
                # A DB stamped "4" whose functions table lacks textOffset /
                # similarity (or whose view is stale) 500s at query time.
                missing |= _missing_required_columns(conn)
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
    conn = sqlite3.connect(sqlite_ro_uri(db_path), uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _db() -> sqlite3.Connection:
    conn = _open_db(_db_path())
    version = _check_schema_version(conn)
    # DEBUG: this runs on every DB-touching request; an INFO line here makes
    # the operational log one "opened coverage.db" entry per request.
    _log.debug("recoverage: opened coverage.db (schema v%s)", version)
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

# The two cache policies for DB-derived responses.  NO_STORE: mutable
# payloads (target lists, grids) that must never survive a rebuild.
# REVALIDATE: ETag-bearing payloads (/data, /asm, /bytes, /potato) that a
# browser may keep but must re-verify with If-None-Match every time.
CACHE_NO_STORE = "no-cache, no-store, must-revalidate"
CACHE_REVALIDATE = "no-cache, must-revalidate"


def _finalized(body: bytes, content_type: str, encoding: str, **headers: str) -> bytes:
    """Set payload headers for an already-final *body* and return it."""
    response.content_type = content_type
    if encoding:
        response.set_header("Content-Encoding", encoding)
    response.set_header("Vary", "Accept-Encoding")
    response.set_header("Content-Length", str(len(body)))
    for k, v in headers.items():
        response.set_header(k.replace("_", "-"), v)
    return body


def _compressed(body: bytes, content_type: str, **headers: str) -> bytes:
    """Compress body, set response headers, return final body."""
    accept_enc = request.headers.get("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    return _finalized(body, content_type, encoding, **headers)


def _json_ok(data: dict[str, Any] | list[Any] | bytes, **headers: str) -> bytes:
    """Return compressed JSON 200."""
    body = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
    return _compressed(body, "application/json", **headers)


def _json_ok_precompressed(body: bytes, encoding: str, **headers: str) -> bytes:
    """Return a JSON 200 from an already-compressed body (no recompression)."""
    return _finalized(body, "application/json", encoding, **headers)


# Every JSON error response carries this trio: `error` (human message),
# `code` (stable machine-readable string), `detail` (extra context, often "").
_STATUS_ERROR_CODES: dict[int, str] = {
    400: "bad_request",
    403: "forbidden",
    404: "not_found",
    413: "payload_too_large",
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
    # Errors must never be cached by intermediaries: a proxy could serve a
    # stale 503 after the DB recovers.
    resp.set_header("Cache-Control", "no-store")
    return resp


# ── Bottle app ─────────────────────────────────────────────────────

app = Bottle()

# Optional token auth for the dashboard (--token): when set, every request
# must present it via Authorization: Bearer <token>, ?token=, or the
# HttpOnly cookie the index route sets for the SPA.  Loopback stays
# unauthenticated when no token is configured.
_AUTH_TOKEN: str = ""


# Deliberately does not echo the expected token, and carries no CSS of its own
# beyond the handful of attributes needed to be readable on a dark background.
_UNAUTHORIZED_HTML = (
    b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
    b'<meta name="viewport" content="width=device-width, initial-scale=1">'
    b"<title>ReCoverage - access token required</title></head>"
    b'<body bgcolor="#0f1216" text="#e7edf4">'
    b'<table width="100%" height="90%" border="0"><tr><td align="center" valign="middle">'
    b'<font face="system-ui, sans-serif">'
    b"<h1>Access token required</h1>"
    b"<p>This dashboard was started with <tt>--token</tt>. Open it with the token"
    b" appended to the URL:</p>"
    b'<p><tt bgcolor="#151a21">?token=YOUR_TOKEN</tt></p>'
    b'<p><font color="#8b949e" size="2">The person who started the server has the token.'
    b" It is stored in a cookie afterwards, so you only need the URL once.</font></p>"
    b"</font></td></tr></table></body></html>"
)


def _auth_token_matches(provided: str) -> bool:
    # Constant-time comparison: a plain == leaks the token one byte at a
    # time to a client measuring response latency on a network-reachable
    # server (--allow-remote).  Both sides are encoded because
    # hmac.compare_digest raises TypeError on non-ASCII str — and *provided*
    # comes straight from request headers.
    return bool(_AUTH_TOKEN) and hmac.compare_digest(
        provided.encode("utf-8"), _AUTH_TOKEN.encode("utf-8")
    )


# Failed-token-attempt throttle: without it, a network-reachable server
# (--allow-remote + --token) accepts unlimited online guesses at the bearer
# token.  Global (per-process), not per-source-IP — behind NAT every client
# shares one address anyway, and the dashboard's threat model is "someone on
# the LAN is guessing", not "multi-tenant fairness".  A success clears the
# counter so the operator never trips their own limit.
_AUTH_FAIL_WINDOW_SECONDS = 60.0
_AUTH_FAIL_MAX = 10
_auth_failures: deque[float] = deque()
_AUTH_FAILURES_LOCK = threading.Lock()


def _auth_throttle(now: float, reserve_slot: bool) -> bool:
    """Prune expired failures, enforce the window cap, optionally take a slot.

    The prune, the cap check, and *reserve_slot*'s append must share ONE
    critical section: as separate steps, a burst of concurrent bad-token
    requests all observe ``len < max`` before any of them records, and every
    one of them slips past the cap (check-then-act TOCTOU).  The slot is
    therefore taken BEFORE the token is verified; a verified request releases
    everything again via :func:`_clear_auth_failures`.

    Returns True when the window is full — the caller answers 429.
    """
    with _AUTH_FAILURES_LOCK:
        while _auth_failures and now - _auth_failures[0] > _AUTH_FAIL_WINDOW_SECONDS:
            _auth_failures.popleft()
        if len(_auth_failures) >= _AUTH_FAIL_MAX:
            return True
        if reserve_slot:
            _auth_failures.append(now)
        return False


def _auth_rate_limited(now: float) -> bool:
    """True once *_AUTH_FAIL_MAX* failures were recorded inside the window."""
    return _auth_throttle(now, reserve_slot=False)


def _record_auth_failure(now: float) -> None:
    _auth_throttle(now, reserve_slot=True)


def _clear_auth_failures() -> None:
    with _AUTH_FAILURES_LOCK:
        _auth_failures.clear()


def _require_auth() -> None:
    if not _AUTH_TOKEN:
        return

    now = time.monotonic()
    # Reserve a failure slot atomically with the cap check (see
    # _auth_throttle) — reserving before verification is what keeps N
    # concurrent guesses from all passing the cap before any of them
    # records.  A verified token refunds everyone via the clear below.
    if _auth_throttle(now, reserve_slot=True):
        raise HTTPResponse(
            status=429,
            body=b'{"error": "rate limited", "code": "rate_limited", '
            b'"detail": "too many failed token attempts; retry later"}',
            content_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "Retry-After": str(int(_AUTH_FAIL_WINDOW_SECONDS)),
            },
        )
    provided = request.headers.get("Authorization", "")
    if provided.startswith("Bearer "):
        provided = provided[len("Bearer ") :]
    else:
        provided = request.query.get("token", "")
        if not provided:
            provided = request.get_cookie("recoverage_token", default="")
    if _auth_token_matches(provided):
        _clear_auth_failures()
        return

    # Audit trail for brute-force visibility: on a network-reachable server
    # (--allow-remote --token) the throttle bounds guessing, but a silent 401
    # gives the operator no way to see the attempt happened.  The provided
    # value is never logged (it may be someone's near-miss guess at a
    # secret); REMOTE_ADDR comes from the socket peer.
    _log.warning(
        "Rejected %s auth token from %s",
        "missing" if not provided else "invalid",
        request.environ.get("REMOTE_ADDR", "") or "unknown peer",
    )
    # A browser asking for a page gets a page; API clients keep the JSON
    # error contract.  Someone handed a share URL who dropped the query
    # string used to land on a raw JSON blob with no way to tell what to do.
    wants_html = "text/html" in request.headers.get("Accept", "") and not request.path.startswith(
        "/api/"
    )
    if wants_html:
        raise HTTPResponse(
            status=401,
            body=_UNAUTHORIZED_HTML,
            content_type="text/html; charset=utf-8",
        )
    raise HTTPResponse(
        status=401,
        body=(
            b'{"error": "unauthorized", "code": "unauthorized", '
            b'"detail": "missing or invalid token"}'
        ),
        content_type="application/json",
    )


app.add_hook("before_request", _require_auth)


def _db_unavailable_err(exc: sqlite3.Error) -> Any:
    """JSON 503 for an unreadable coverage.db, logged so the failure is visible.

    ONE tail for every DB-open failure path (the shared target cursor and the
    unexpected-error handler): without the log line a missing or corrupt
    database is invisible in the server log — the 503 only reaches the one
    client that happened to make the request.  The response detail carries the
    OS/SQLite cause and the rebuild hint so an operator can act on the API
    response alone, matching Potato Mode's 503 page.
    """
    _log.warning(
        "Database unavailable serving %s %s: %s: %s",
        _log_safe(request.method),
        _log_safe(request.path),
        type(exc).__name__,
        exc,
    )
    return _json_err(
        503,
        {
            "error": "Database unavailable",
            "detail": f"{type(exc).__name__}: {exc} — "
            "run 'rebrew catalog --json && rebrew build-db' to create or rebuild it",
        },
    )


@app.error(500)
def _handle_unexpected_error(error: Any) -> Any:
    """Keep every surface's error contract when a handler raises unexpectedly.

    ``_db()`` open failures already return 503 JSON, but every query after
    connect was unguarded — a corrupt/incompatible DB or SQLITE_BUSY during a
    concurrent build-db raised inside ``c.execute`` and surfaced as Bottle's
    HTML 500.  All sqlite3 errors become a 503 JSON response instead.

    Non-DB exceptions are logged here with their request context: bottle only
    dumps the raw traceback to wsgi.errors (and ``serve`` runs wsgiref with
    quiet=True), so without this the failing endpoint is hard to identify from
    the log alone.  /api/* requests get the standard JSON 500 contract — the
    SPA's fetch() handlers and API consumers parse JSON, not Bottle's HTML
    error page — while UI routes keep Bottle's HTML error page.
    """
    exc = getattr(error, "exception", None)
    if isinstance(exc, sqlite3.Error):
        return _db_unavailable_err(exc)
    # Returning the HTTPError itself would make _cast re-enter the error
    # handler (recursion until the wsgi catch-all); returning None would emit
    # an empty 500 body.
    _log.error(
        "Unhandled error serving %s %s",
        request.method,
        request.path,
        exc_info=exc or error,
    )
    if request.path.startswith("/api/"):
        return _json_err(500, {"error": "Internal server error"})
    return app.default_error_handler(error)


@app.hook("before_request")
def _log_request() -> None:
    """Log incoming requests at DEBUG level for operational visibility."""
    # Method/path are attacker-controlled (the path is percent-decoded), so
    # control characters are escaped to keep the log line-per-request.
    _log.debug("%s %s", _log_safe(request.method), _log_safe(request.path))
    # DNS-rebinding guard for loopback installs: the Host header must name a
    # loopback host.  Requests without a Host header (non-HTTP/1.1 clients,
    # WSGI test harnesses) are left to the server's own address handling.
    if ALLOWED_HOSTS is not None:
        host = request.headers.get("Host", "")
        if host and _hostname_of(host) not in ALLOWED_HOSTS:
            # Audit trail: a rejected Host on a loopback bind is a
            # DNS-rebinding attempt signal; without it the 400 leaves no
            # trace for incident investigation.  %r escapes control
            # characters, so the hostile value cannot forge log lines.
            _log.warning(
                "Rejected request with unexpected Host header %r from %s",
                host,
                request.environ.get("REMOTE_ADDR", "") or "unknown peer",
            )
            raise _json_err(
                400,
                {
                    "error": "Bad Request",
                    "detail": f"unexpected Host header {host!r}",
                },
            )


# Content-Security-Policy for the dashboard.  The SPA inlines VanJS + app.js
# into the HTML shell and uses inline styles, so 'unsafe-inline' is required
# for scripts/styles; everything else is same-origin (detail.js, hljs assets,
# fetch/EventSource to /api/*) or data: images (grid sprites, SVG badges).
# The policy still pins the useful gates: no plugins, no base-element hijack,
# no framing, no off-host exfil from any future injection sink.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.hook("after_request")
def _security_headers() -> None:
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("X-Frame-Options", "DENY")
    response.set_header("Content-Security-Policy", _CSP)
    # Tokens travel in URLs (?token= share links); never let them leak to a
    # third party via Referer if the dashboard ever navigates off-host.
    response.set_header("Referrer-Policy", "no-referrer")
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
