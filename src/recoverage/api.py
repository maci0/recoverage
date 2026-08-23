"""API routes for the recoverage dashboard."""

from __future__ import annotations

import contextlib
import json
import logging
import queue
import sqlite3
import subprocess
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

from recoverage import __version__
from recoverage import server as _server
from recoverage.server import (
    _FN_JSON_SQL,
    _GLOBAL_JSON_SQL,
    CACHE_NO_STORE,
    CACHE_REVALIDATE,
    DLL_DATA,
    DLL_LOCK,
    HAS_CAPSTONE,
    HAS_PYGMENTS,
    LOOPBACK_HOSTS,
    VA_MAX,
    _best_encoding,
    _cell_bucket_row,
    _cells_json_rows,
    _db,
    _db_path,
    _escape_like,
    _etag_or_304,
    _get_capstone_md,
    _get_targets_config,
    _hostname_of,
    _json_err,
    _json_ok,
    _json_ok_precompressed,
    _load_dll,
    _load_metadata,
    _open_db,
    _project_dir,
    _snapshot_db_mtime,
    _target_filename,
    app,
    clear_target_cache,
    compress_payload,
    get_disassembly,
    request,
    resolve_targets,
    response,
)

_log = logging.getLogger("recoverage")

# ── Cache invalidation ─────────────────────────────────────────────


def _clear_derived_caches() -> None:
    """Drop every cache derived from coverage.db or the original binaries.

    ONE invalidation entry point, shared by the SSE ``db-updated`` broadcast
    and both regen paths (in-app POST /api/regen): resolved targets + TOML
    config, memoized /data payloads (including the SPA search index they
    carry), Potato cells, DLL bytes, and cached disassembly must all go
    together, or one endpoint serves post-rebuild data while another is
    still stale.

    The SPA shell cache (ui.CACHED_INDEX_PAYLOAD) is deliberately NOT
    invalidated here: it is built solely from static package assets and has
    no dependence on coverage.db.  Clearing it on every rebuild would make
    the next / request re-read the assets, re-minify, and redo the three
    full-strength budget compressions under INDEX_LOCK for zero staleness
    benefit.
    """
    clear_target_cache()
    _clear_data_cache()
    from recoverage.potato import clear_cells_cache

    clear_cells_cache()
    # Disassembly/DLL bytes reflect the original binary and section layout,
    # both of which change with a rebuild.
    with DLL_LOCK:
        DLL_DATA.clear()
    get_disassembly.cache_clear()


# Server-side regen cooldown (seconds): the UI throttles Reload clicks, but
# direct API calls must not be able to trigger repeated rebrew catalog runs.
_REGEN_COOLDOWN_SECONDS = 5.0
_regen_last_attempt = 0.0  # time.monotonic() of the last accepted regen POST
_REGEN_LOCK = threading.Lock()  # serializes regen (check + subprocess, TOCTOU)

# Memoized /api/targets/<t>/data payloads: the endpoint materializes ALL
# cells for the target (json_group_array over the whole cells table) plus
# every function/global for the search index on each cache-missing request.
# The ETag gives 304s to repeat clients, but N fresh clients each rebuilt
# the multi-MB payload.  Keyed by the WAL-aware db snapshot + target +
# section so a rebuild (which the SSE watcher detects and funnels through
# clear_target_cache) invalidates it.
# Each value maps encoding name ("zstd"/"br"/"gzip"/"" for identity) to the
# FINAL response body for that encoding, plus "raw" (the uncompressed JSON)
# so a first request with an unseen Accept-Encoding can mint its variant
# without re-running the queries or json.dumps.  Compressing the multi-MB
# payload on every memo hit dominated repeat-request cost (~30-70 ms CPU).
_DATA_CACHE: dict[tuple[tuple[int, int] | None, str, str | None], dict[str, bytes]] = {}
_DATA_CACHE_LOCK = threading.Lock()
# Upper bound on retained payloads: a long-running server across many rebuilds
# must not accumulate one multi-MB payload per fingerprint forever.
_DATA_CACHE_MAX = 8


def _clear_data_cache() -> None:
    with _DATA_CACHE_LOCK:
        _DATA_CACHE.clear()


def _cache_data_insert(
    key: tuple[tuple[int, int] | None, str, str | None],
    raw: bytes,
    encoding: str,
    body: bytes,
) -> None:
    """Insert a memoized payload (raw + this request's encoded form), evicting
    the oldest entries past the cap."""
    with _DATA_CACHE_LOCK:
        _server._evict_oldest(_DATA_CACHE, _DATA_CACHE_MAX)
        entry = _DATA_CACHE.setdefault(key, {})
        entry["raw"] = raw
        entry[encoding] = body


def _target_not_found(target: str) -> Any:
    """JSON 404 for a target-scoped endpoint referencing an unknown target."""
    return _json_err(
        404,
        {
            "error": "Target not found",
            "detail": f"no such target {target!r}",
        },
    )


def _dll_not_found(target: str, error: str) -> Any:
    """JSON 404 for a target whose original binary is missing or unconfigured."""
    hint = (
        f" add [targets.{target}].binary to rebrew-project.toml"
        if target not in _get_targets_config()
        else ""
    )
    return _json_err(
        404,
        {"error": error, "detail": f"original binary for target {target!r} not found;{hint}"},
    )


def _section_not_found(target: str, section: str) -> Any:
    """JSON 404 for a target-scoped endpoint referencing an unknown section."""
    return _json_err(
        404,
        {
            "error": f"section {section} not found",
            "detail": f"target {target!r} has no section {section!r}",
        },
    )


def _require_target(c: sqlite3.Cursor, target: str) -> Any | None:
    """Return a 404 response if *target* is unknown, else None.

    *target* is valid when it has DB rows or is declared in the project
    config (a configured-but-not-yet-built target is still addressable).
    """
    try:
        _, targets_list = resolve_targets(c)
    except sqlite3.Error:
        return None  # DB unavailable — let the endpoint's own 503 path run
    if any(t.get("id") == target for t in targets_list):
        return None
    return _target_not_found(target)


@contextlib.contextmanager
def _target_cursor(target: str) -> Generator[sqlite3.Cursor]:
    """Open coverage.db read-only and yield a cursor with *target* validated.

    ONE shared tail for every /api/targets/<target>/* endpoint: fails the
    request with the standard JSON contract (503 ``db_unavailable`` when the
    DB cannot open, 404 ``not_found`` for an unknown target) by raising the
    HTTPResponse, so handlers are straight-line code instead of repeating
    the connect/close/validate boilerplate.  The connection always closes.
    """
    try:
        conn = _db()
    except sqlite3.Error:
        raise _json_err(503, {"error": "Database unavailable"}) from None
    try:
        c = conn.cursor()
        not_found = _require_target(c, target)
        if not_found is not None:
            raise not_found
        yield c
    finally:
        conn.close()


def _parse_va_candidates(raw_va: str) -> list[int]:
    """Parse *raw_va* into deduped candidate lookup ints, order preserved.

    ONE parser for every endpoint that resolves a ?va= spelling.  Hex
    spellings: 0x-prefixed or containing a-f (rebrew's parse_va convention,
    bare hex valid).  All-digit strings: DECIMAL first (the /functions list
    emits va as a decimal int — a consumer taking that value straight into
    this route must not miss), with a bare-hex fallback for legacy callers.
    Candidates beyond SQLite's signed-64-bit INTEGER range are dropped:
    passing one raises OverflowError at execute time instead of a clean
    miss.  Negatives stay candidates so section-bounds classification can
    report "before section start" (matching the historical va=-0x10
    contract).
    """
    lowered = raw_va.lower()
    bases = (16,) if lowered.startswith("0x") or any(c in "abcdef" for c in lowered) else (10, 16)
    candidates: list[int] = []
    for base in bases:
        with contextlib.suppress(ValueError):
            parsed = int(raw_va, base)
            if parsed <= VA_MAX and parsed not in candidates:
                candidates.append(parsed)
    return candidates


def _file_backed_section(
    c: sqlite3.Cursor, target: str, section: str, *fields: str
) -> dict[str, Any]:
    """Fetch *target*'s *section* row and require int-typed *fields*, else raise.

    ONE shared guard for the endpoints that do pointer arithmetic on a
    section (asm, bytes): an unknown section raises the shared JSON 404,
    and NULL/non-int fields — sections with no file backing (.bss) carry
    NULL offsets — raise this endpoint family's JSON 422 contract instead of
    letting the arithmetic raise TypeError and surface as an HTML 500.
    """
    c.execute("SELECT * FROM sections WHERE target = ? AND name = ?", (target, section))
    row = c.fetchone()
    if row is None:
        raise _section_not_found(target, section)
    sec = dict(row)
    if any(not isinstance(sec[f], int) for f in fields):
        raise _json_err(
            422,
            {
                "error": "section has no file backing",
                "detail": f"section {section!r} has NULL {'/'.join(fields)} — "
                "raw bytes are only served for file-backed sections",
            },
        )
    return sec


# ── Server-Sent Events (live DB change notifications) ─────────────
#
# A single background watcher thread polls coverage.db mtime every couple of
# seconds and broadcasts a `db-updated` SSE frame to every connected client.
# Each /api/events connection gets its own bounded queue; the route drains it
# and streams frames.  When no client is connected the watcher keeps polling
# (cheap), and client disconnects are handled by removing the queue when the
# stream generator is closed (wsgiref closes the iterator on abrupt socket
# teardown, which propagates GeneratorExit into the generator's finally).

_SSE_POLL_INTERVAL_SECONDS = 2.0
_SSE_HEARTBEAT_SECONDS = 15.0
_SSE_QUEUE_MAX = 32  # per-client buffer; slow clients drop events, not memory
_SSE_MAX_CLIENTS = 32  # cap on concurrent /api/events streams (thread DoS guard)

_SSE_CLIENTS: set[queue.Queue[bytes]] = set()
_SSE_CLIENTS_LOCK = threading.Lock()
_DB_WATCHER_THREAD: threading.Thread | None = None
_DB_WATCHER_STOP = threading.Event()
_DB_WATCHER_LOCK = threading.Lock()


def _broadcast_db_updated(snapshot: tuple[int, int] | None) -> None:
    """Push a db-updated SSE frame to every connected client queue.

    Also invalidates every derived cache (see :func:`_clear_derived_caches`)
    — an external ``rebrew build-db`` (the documented workflow) must refresh
    the target dropdown, any cached data, and the disassembly derived from
    the original binary, not just the in-app /api/regen path.
    """
    try:
        _clear_derived_caches()
    except Exception:
        # A failed invalidation leaves stale caches behind while clients are
        # told the DB changed — that divergence must be visible in the log.
        _log.warning("Cache invalidation during db-updated broadcast failed", exc_info=True)
    payload: dict[str, Any] = {
        "event": "db-updated",
        # Basename only — the absolute path leaks the user's home-directory
        # layout to any LAN/browser client (see security review).
        "db": {"path": _db_path().name},
        "timestamp": time.time(),
    }
    if snapshot is not None:
        # Opaque WAL-aware change token (see _snapshot_db_mtime) — NOT an
        # mtime; named so clients cannot misread it as wall-clock data.
        payload["db"]["fingerprint"] = snapshot[0]
        payload["db"]["size_bytes"] = snapshot[1]
    frame = f"event: db-updated\ndata: {json.dumps(payload)}\n\n".encode()
    with _SSE_CLIENTS_LOCK:
        clients = list(_SSE_CLIENTS)
    for client in clients:
        try:
            client.put_nowait(frame)
        except queue.Full:
            _log.debug("SSE client queue full — dropping db-updated event")


def _db_watcher_loop(stop: threading.Event) -> None:
    """Poll coverage.db mtime every few seconds and broadcast changes.

    The first snapshot is the baseline; any later change (including the file
    appearing or disappearing) broadcasts an event.  Runs until ``stop`` is
    set, which also serves as the poll sleep so tests can drive it quickly.

    Each iteration is guarded: this is a daemon thread nobody joins, so an
    unguarded exception would kill live-reload silently for the remaining
    lifetime of the process.
    """
    last = _snapshot_db_mtime()
    while not stop.is_set():
        stop.wait(_SSE_POLL_INTERVAL_SECONDS)
        if stop.is_set():
            break
        try:
            snapshot = _snapshot_db_mtime()
            if snapshot != last:
                # Advance the baseline only after a successful broadcast: a
                # failed iteration retries the same change on the next poll
                # (at-least-once) instead of silently dropping the event.
                _broadcast_db_updated(snapshot)
                last = snapshot
        except Exception:
            _log.exception("DB watcher iteration failed — continuing to poll")


def _ensure_db_watcher() -> None:
    """Start the watcher thread on first use (idempotent, thread-safe)."""
    global _DB_WATCHER_THREAD
    with _DB_WATCHER_LOCK:
        if _DB_WATCHER_THREAD is not None and _DB_WATCHER_THREAD.is_alive():
            return
        _DB_WATCHER_STOP.clear()
        _DB_WATCHER_THREAD = threading.Thread(
            target=_db_watcher_loop,
            args=(_DB_WATCHER_STOP,),
            name="recoverage-db-watcher",
            daemon=True,
        )
        _DB_WATCHER_THREAD.start()


def _stop_db_watcher() -> None:
    """Stop the watcher thread (used by tests)."""
    global _DB_WATCHER_THREAD
    _DB_WATCHER_STOP.set()
    with _DB_WATCHER_LOCK:
        if _DB_WATCHER_THREAD is not None:
            _DB_WATCHER_THREAD.join(timeout=5)
            _DB_WATCHER_THREAD = None


@app.get("/api/events")
def handle_api_events() -> Any:
    """SSE stream: emits a db-updated event when coverage.db is rewritten.

    Bottle streams the returned generator.  The watcher thread broadcasts to a
    per-client queue; this route drains it.  Disconnects are detected when the
    generator is closed — the client queue is removed in a ``finally``.
    """
    _ensure_db_watcher()
    # Cap concurrent SSE clients: each connection pins a server thread for
    # the life of the stream (minutes/hours), and wsgiref has no connection
    # limit.  A LAN client (or a cross-origin EventSource from any webpage
    # a victim visits — no-cors, loopback) could otherwise exhaust threads.
    with _SSE_CLIENTS_LOCK:
        if len(_SSE_CLIENTS) >= _SSE_MAX_CLIENTS:
            return _json_err(
                503,
                {
                    "error": "too many event-stream clients",
                    "code": "rate_limited",
                    "detail": f"max {_SSE_MAX_CLIENTS} concurrent /api/events connections",
                },
            )
        client_queue: queue.Queue[bytes] = queue.Queue(maxsize=_SSE_QUEUE_MAX)
        _SSE_CLIENTS.add(client_queue)

    def _events() -> Generator[bytes, None, None]:
        try:
            yield b": connected\n\n"
            last_heartbeat = time.monotonic()
            while True:
                try:
                    frame = client_queue.get(timeout=1.0)
                except queue.Empty:
                    frame = None
                if frame is not None:
                    yield frame
                now = time.monotonic()
                if now - last_heartbeat >= _SSE_HEARTBEAT_SECONDS:
                    yield b": ping\n\n"
                    last_heartbeat = now
        finally:
            with _SSE_CLIENTS_LOCK:
                _SSE_CLIENTS.discard(client_queue)

    response.content_type = "text/event-stream"
    response.set_header("Cache-Control", CACHE_NO_STORE)
    response.set_header("X-Accel-Buffering", "no")
    return _events()


@app.get("/api/health")
def handle_api_health() -> bytes:
    db = _db_path()
    db_info: dict[str, Any] = {"path": db.name, "exists": False}
    status = "healthy"
    try:
        stat = db.stat()
        db_info["exists"] = True
        db_info["size_bytes"] = stat.st_size
        db_info["mtime"] = stat.st_mtime
    except OSError:
        _log.warning("Database file not accessible at %s", db)
        status = "degraded"
    target_count = 0
    try:
        with contextlib.closing(_open_db(db)) as conn:
            c = conn.cursor()
            # Exclude the reserved schema-version row from the target count.
            c.execute(
                "SELECT COUNT(DISTINCT target) FROM metadata WHERE target != ?",
                (_server.SCHEMA_TARGET,),
            )
            target_count = c.fetchone()[0]
    except sqlite3.Error as exc:
        _log.warning("Failed to query target count from database: %s", exc)
        status = "degraded"
    return _json_ok(
        {
            "status": status,
            "version": __version__,
            "db": db_info,
            "extras": {
                "capstone": HAS_CAPSTONE,
                "pygments": HAS_PYGMENTS,
            },
            "targets_count": target_count,
            "cors": _server.CORS_ENABLED,
        },
        Cache_Control=CACHE_NO_STORE,
    )


@app.get("/api/targets")
def handle_api_targets() -> bytes:
    try:
        with contextlib.closing(_db()) as conn:
            c = conn.cursor()
            _, targets_list = resolve_targets(c)
    except sqlite3.Error:
        _log.warning("Database unavailable, falling back to config-only target list")
        targets_list = [
            {"id": tid, "name": Path(_target_filename(tid, t_info)).name}
            for tid, t_info in _server._get_targets_config().items()
        ]

    return _json_ok(
        {"targets": targets_list},
        Cache_Control=CACHE_NO_STORE,
    )


@app.get("/api/targets/<target>/stats")
def handle_api_stats(target: str) -> bytes | Any:
    with _target_cursor(target) as c:
        stats = _server._section_stats(c, target)
        return _json_ok(
            {
                "target": target,
                "summary": stats["summary"],
                "sections": stats["sections"],
                "functions_by_status": stats["by_status"],
            },
            Cache_Control=CACHE_NO_STORE,
        )


def _build_search_index(c: sqlite3.Cursor, target: str) -> dict[str, Any]:
    """Lightweight name -> {va, symbol} index for the SPA search box.

    Names are not unique across functions and globals — keep the FIRST
    (functions win over globals) so navigation never silently jumps to a
    colliding global's VA.
    """
    index: dict[str, Any] = {}
    # Iterate the cursor, not fetchall(): the functions table holds tens of
    # thousands of rows on real projects, and the intermediate row list would
    # double the transient footprint of an already multi-MB payload build.
    c.execute(
        "SELECT name, vaStart, symbol FROM functions WHERE target = ?",
        (target,),
    )
    for row in c:
        index.setdefault(row["name"], {"va": row["vaStart"], "symbol": row["symbol"]})
    c.execute("SELECT name, va FROM globals WHERE target = ?", (target,))
    for row in c:
        index.setdefault(row["name"], {"va": hex(row["va"]) if row["va"] else "", "symbol": ""})
    return index


@app.get("/api/targets/<target>/data")
def handle_api_data(target: str) -> bytes | Any:
    section_filter = request.query.get("section", "").strip() or None

    # ETag caching based on DB modification time + target + section.
    # Uses the WAL-aware snapshot (mtime_ns-precision) so two rebuilds
    # within the same second get distinct ETags (a float mtime would let a
    # browser keep a stale 304), and a WAL-committed change that did not
    # checkpoint the main file still invalidates.  The snapshot is computed
    # once here: it is both the memo key and the ETag input (see
    # _etag_or_304).  etag is None only when the DB is unreadable — no ETag
    # is sent, and the queries below answer the standard 503 shortly after.
    snap = _snapshot_db_mtime()
    fingerprint: tuple[tuple[int, int] | None, str, str | None] = (snap, target, section_filter)
    etag = _etag_or_304(snap, target, section_filter)
    headers: dict[str, str] = {"Cache_Control": CACHE_REVALIDATE}
    if etag:
        headers["ETag"] = etag

    # Serve a memoized payload for an unchanged DB instead of re-running the
    # full-table queries, re-serialization, and recompression on every
    # cache-missing request.
    entry: dict[str, bytes] | None
    with _DATA_CACHE_LOCK:
        entry = _DATA_CACHE.get(fingerprint)
    if entry is not None:
        accept_enc = request.headers.get("Accept-Encoding", "")
        encoding = _best_encoding(accept_enc)
        body = entry.get(encoding)
        if body is None:
            # First request for this encoding: mint the variant from the
            # stored raw JSON (queries + json.dumps already paid for).
            raw = entry["raw"]
            body, _ = compress_payload(raw, accept_enc)
            with _DATA_CACHE_LOCK:
                entry[encoding] = body
        return _json_ok_precompressed(body, encoding, **headers)

    with _target_cursor(target) as c:
        data: dict[str, Any] = _load_metadata(c, target)

        # Optional ?section= narrowing: the same queries with one extra WHERE
        # term, so no branch duplicates a query that only adds "AND name = ?".
        sec_params: list[Any] = [target] + ([section_filter] if section_filter else [])
        sections_clause = " AND name = ?" if section_filter else ""

        c.execute(
            f"SELECT * FROM sections WHERE target = ?{sections_clause}",
            sec_params,
        )
        data["sections"] = {}
        for row in c.fetchall():
            sec = dict(row)
            sec["cells"] = []
            data["sections"][sec["name"]] = sec

        if section_filter and not data["sections"]:
            # Mirror /asm: an unknown section must 404, not return a silent
            # empty grid (which would also get memoized under that key).
            return _section_not_found(target, section_filter)

        for row in _cells_json_rows(c, target, section_filter):
            sec_name = row[0]
            if sec_name in data["sections"]:
                data["sections"][sec_name]["cells"] = json.loads(row[1])

        data["search_index"] = _build_search_index(c, target)

        # Per-section cell stats from SQL view.  All buckets are selected so
        # consumers can sum them and reconcile with total_cells (padding,
        # none, proven, and size_mismatch were previously omitted).
        data["section_cell_stats"] = {}
        stats_clause = " AND section_name = ?" if section_filter else ""
        c.execute(
            "SELECT section_name, total_cells, exact_count, reloc_count, "
            "near_match_count, stub_count, padding_count, data_count, thunk_count, "
            f"none_count, proven_count, size_mismatch_count "
            f"FROM section_cell_stats WHERE target = ?{stats_clause}",
            sec_params,
        )
        for row in c.fetchall():
            data["section_cell_stats"][row["section_name"]] = _cell_bucket_row(row)

        raw_json = json.dumps(data).encode("utf-8")
        accept_enc = request.headers.get("Accept-Encoding", "")
        body, encoding = compress_payload(raw_json, accept_enc)
        _cache_data_insert(fingerprint, raw_json, encoding, body)
        return _json_ok_precompressed(body, encoding, **headers)


# Mirrors the list endpoint's limit cap.
_MAX_BATCH_LOOKUP = 500

# Bound on the batch-lookup request body: the payload is fully parsed before
# the _MAX_BATCH_LOOKUP cap applies, so an unbounded read would let one
# request pin memory and CPU.  The read takes cap + 1 so an oversized body
# is detectable without a second read.
_MAX_BATCH_BODY_BYTES = 64 * 1024

# Pagination offset ceiling: real function tables are orders of magnitude
# smaller, so clamping here changes no legitimate page while keeping OFFSET
# inside sqlite3's INTEGER range.
_MAX_PAGE_OFFSET = 10_000_000


@app.get("/api/targets/<target>/functions")
def handle_api_functions_list(target: str) -> bytes | Any:
    """Paginated function listing with optional filters."""
    status_filter = request.query.get("status", "").strip() or None
    search = request.query.get("search", "").strip() or None
    sort_param = request.query.get("sort", "va").strip()  # field:dir
    try:
        limit = min(max(int(request.query.get("limit", 50)), 1), _MAX_BATCH_LOOKUP)
    except ValueError:
        limit = 50
    try:
        # Upper bound keeps a giant ?offset= from overflowing sqlite3's
        # signed-64-bit INTEGER conversion (OverflowError -> raw 500).
        offset = min(max(int(request.query.get("offset", 0)), 0), _MAX_PAGE_OFFSET)
    except ValueError:
        offset = 0

    # SAFETY: sort_field is whitelisted to allowed_sort (no user strings reach SQL).
    # sort_dir is validated to "ASC"/"DESC" only. ORDER BY cannot use parameterized queries.
    allowed_sort = {"va", "name", "size", "status", "symbol", "module"}
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

    with _target_cursor(target) as c:
        # Base filter: GLOBAL/DATA marker rows are data, not functions.
        where = ["target = ? AND markerType NOT IN ('GLOBAL','DATA')"]
        params: list[Any] = [target]

        if status_filter:
            where.append("status = ?")
            params.append(status_filter)
        if search:
            # vaStart (hex text) search keeps parity with Potato Mode, which
            # matches hex addresses; CAST(va AS TEXT) alone only matches
            # decimal spellings.
            where.append(
                "(name LIKE ? ESCAPE '\\' OR symbol LIKE ? ESCAPE '\\'"
                " OR CAST(va AS TEXT) LIKE ? ESCAPE '\\'"
                " OR vaStart LIKE ? ESCAPE '\\')"
            )
            like = _escape_like(search)
            params.extend([like, like, like, like])

        where_sql = " AND ".join(where)

        # SAFETY: where_sql is constructed from whitelisted column names + parameterized values.
        # sort_field is constrained to allowed_sort set, sort_dir to "ASC"/"DESC" literals.
        # No user-supplied strings reach the SQL statement unparameterized.
        c.execute(f"SELECT COUNT(*) FROM functions WHERE {where_sql}", params)
        total = c.fetchone()[0]

        c.execute(
            f"SELECT va, name, vaStart, size, status, module, symbol, markerType "
            f"FROM functions WHERE {where_sql} "
            f"ORDER BY {sort_field} {sort_dir} LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        # SELECT enumerates exactly the response fields; dict(row) carries the
        # same keys, in the same order, as an explicit per-field dict would.
        items: list[dict[str, Any]] = [dict(row) for row in c.fetchall()]

        return _json_ok(
            {
                "target": target,
                "total": total,
                "limit": limit,
                "offset": offset,
                "functions": items,
            },
            Cache_Control=CACHE_NO_STORE,
        )


def _last_verify_payload(vr: sqlite3.Row) -> dict[str, Any]:
    """Shape a verify_results row as the ``last_verify`` object attached to
    function details — ONE definition shared by the single-VA and batch
    endpoints so the two response shapes cannot drift apart."""
    return {
        "verified_at": vr["verified_at"],
        "byte_delta": vr["byte_delta"],
        "diff_lines": vr["diff_lines"],
        "similarity": vr["similarity"],
    }


@app.post("/api/targets/<target>/functions")
def handle_api_functions_batch(target: str) -> bytes | Any:
    """Batch function/global lookup by VA list.

    Body: ``{"vas": ["0x10001000", ...]}`` (hex strings or integers).  Returns
    a JSON array of function/global detail objects in input order — the same
    shape as ``GET /functions/<va>``, including the ``last_verify`` attachment.
    VAs with no match are omitted from the response (not an error).
    """
    # Bound the request body: this endpoint is unauthenticated and (with
    # --allow-remote) reachable off-loopback, and the payload is fully
    # parsed before the 500-VA cap applies.  A bounded read rejects
    # oversized bodies whether or not Content-Length is present.
    try:
        raw = request.body.read(_MAX_BATCH_BODY_BYTES + 1)
    except (OSError, ValueError):
        raw = b""
    if len(raw) > _MAX_BATCH_BODY_BYTES:
        return _json_err(
            413,
            {
                "error": "Request body too large",
                "detail": "expected a JSON body under 64 KiB",
            },
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, dict):
        return _json_err(
            400,
            {
                "error": "Body must be a JSON object",
                "detail": 'expected {"vas": ["0x10001000", ...]}',
            },
        )
    vas = payload.get("vas")
    if not isinstance(vas, list):
        return _json_err(
            400,
            {
                "error": "vas must be an array",
                "detail": 'expected {"vas": ["0x10001000", ...]}',
            },
        )
    if not vas:
        return _json_err(400, {"error": "vas must not be empty"})
    if len(vas) > _MAX_BATCH_LOOKUP:
        return _json_err(
            400,
            {
                "error": f"vas list too large (max {_MAX_BATCH_LOOKUP})",
                "detail": f"received {len(vas)} entries",
            },
        )

    def invalid_va(entry: Any, detail: str) -> Any:
        return _json_err(400, {"error": f"invalid VA: {entry!r}", "detail": detail})

    va_ints: list[int] = []
    for entry in vas:
        if isinstance(entry, bool):
            return invalid_va(entry, "VAs must be hex strings or integers")
        if isinstance(entry, int):
            if entry < 0:
                return invalid_va(entry, "VAs must be non-negative")
            if entry > VA_MAX:
                return invalid_va(entry, f"VA out of range (max 0x{VA_MAX:x})")
            va_ints.append(entry)
        elif isinstance(entry, str):
            try:
                # Base-16 (with or without 0x prefix), matching rebrew's
                # parse_va — bare hex like "10001000" is valid here.
                parsed_va = int(entry.strip(), 16)
                if parsed_va < 0:
                    raise ValueError("negative VA")
                if parsed_va > VA_MAX:
                    raise ValueError("VA exceeds 64 bits")
                va_ints.append(parsed_va)
            except ValueError:
                return invalid_va(entry, f"unparseable VA {entry!r}; expected hex like 0x10001000")
        else:
            return invalid_va(entry, "VAs must be hex strings or integers")

    # Preserve input order; duplicate VAs collapse to a single result.
    seen: set[int] = set()
    unique_vas: list[int] = []
    for va in va_ints:
        if va not in seen:
            seen.add(va)
            unique_vas.append(va)

    with _target_cursor(target) as c:
        results: list[dict[str, Any]] = []

        placeholders = ",".join("?" * len(unique_vas))

        # Functions first (parity with GET /functions/<va>), then globals.
        fn_by_va: dict[int, dict[str, Any]] = {}
        c.execute(
            f"SELECT {_FN_JSON_SQL} FROM functions WHERE target = ? AND va IN ({placeholders})",
            [target, *unique_vas],
        )
        for row in c.fetchall():
            fn = json.loads(row[0])
            fn_by_va[fn["va"]] = fn

        if fn_by_va:
            c.execute(
                "SELECT va, verified_at, byte_delta, diff_lines, similarity FROM verify_results"
                f" WHERE target = ? AND va IN ({placeholders})",
                [target, *unique_vas],
            )
            for vr in c.fetchall():
                fn = fn_by_va.get(vr["va"])
                if fn is not None:
                    fn["last_verify"] = _last_verify_payload(vr)

        c.execute(
            f"SELECT {_GLOBAL_JSON_SQL} FROM globals WHERE target = ? AND va IN ({placeholders})",
            [target, *unique_vas],
        )
        globals_by_va: dict[int, dict[str, Any]] = {}
        for row in c.fetchall():
            gl = json.loads(row[0])
            globals_by_va[gl["va"]] = gl

        for va in unique_vas:
            if va in fn_by_va:
                results.append(fn_by_va[va])
            elif va in globals_by_va:
                results.append(globals_by_va[va])

        return _json_ok(results, Cache_Control=CACHE_NO_STORE)


@app.get("/api/targets/<target>/functions/<va>")
def handle_api_function(target: str, va: str) -> bytes | Any:
    with _target_cursor(target) as c:
        no_cache = CACHE_NO_STORE

        # Parse va into candidate lookup ints (shared spelling parser — see
        # _parse_va_candidates); anything unparseable falls through to the
        # exact-name lookup below.
        va_candidates = _parse_va_candidates(va.strip())
        is_numeric = bool(va_candidates)

        def _lookup(table: str, json_sql: str) -> Any | None:
            """First matching row in *table* by VA candidates (numeric) or exact name."""
            if is_numeric:
                for va_int in va_candidates:
                    c.execute(
                        f"SELECT {json_sql} FROM {table} WHERE target = ? AND va = ?",
                        (target, va_int),
                    )
                    row = c.fetchone()
                    if row:
                        return row
                return None
            c.execute(
                f"SELECT {json_sql} FROM {table} WHERE target = ? AND name = ?",
                (target, va),
            )
            return c.fetchone()

        # Functions win over globals (parity with the batch endpoint).
        row = _lookup("functions", _FN_JSON_SQL)
        if row:
            fn_json = json.loads(row[0])
            # Attach the last `rebrew verify -o` record for this function.
            c.execute(
                "SELECT verified_at, byte_delta, diff_lines, similarity FROM verify_results"
                " WHERE target = ? AND va = ?",
                (target, fn_json["va"]),
            )
            vr = c.fetchone()
            if vr:
                fn_json["last_verify"] = _last_verify_payload(vr)
            return _json_ok(json.dumps(fn_json).encode("utf-8"), Cache_Control=no_cache)

        row = _lookup("globals", _GLOBAL_JSON_SQL)
        if row:
            return _json_ok(row[0].encode("utf-8"), Cache_Control=no_cache)

        return _json_err(
            404,
            {
                "error": "not found",
                "detail": f"no function or global matching {va!r} for target {target!r}",
            },
        )


@app.get("/api/targets/<target>/asm")
def handle_api_asm(target: str) -> bytes | Any:
    if not HAS_CAPSTONE:
        return _json_err(
            501,
            {
                "error": "capstone not installed",
                "detail": "install the optional extra to enable disassembly: "
                "pip install 'recoverage[capstone]'",
            },
        )

    va_str = request.query.get("va")
    size_str = request.query.get("size")
    section = request.query.get("section", ".text")
    fmt = request.query.get("format", "text").strip()

    if not va_str or not size_str:
        return _json_err(400, {"error": "missing va or size"})

    raw_va = va_str.strip()
    try:
        # Decimal size (base-0 with no prefix), matching /bytes — the two
        # endpoints must not interpret the same ?size= differently.
        size = min(max(int(size_str.strip(), 0), 0), 4096)
    except ValueError:
        return _json_err(400, {"error": "invalid va or size"})

    if size == 0:
        return _json_err(400, {"error": "size must be positive"})

    # Parse va into candidate ints via the shared spelling parser (same
    # convention as GET /functions/<va>).  The SPA builds asm URLs by
    # interpolating JS numbers (the INTEGER section VAs it got from /data),
    # which spell decimal — parsing those digits as base-16 read an address
    # orders of magnitude past every section and rejected each
    # undocumented-block disassembly with "beyond section end".
    va_candidates = _parse_va_candidates(raw_va)
    if not va_candidates:
        return _json_err(400, {"error": "invalid va or size"})

    # ETag bound to the WAL-aware DB snapshot + request identity (see
    # _etag_or_304): disassembly reflects the binary + section layout, which
    # change when the DB is rebuilt.  Without this, a one-year immutable
    # Cache-Control served stale disassembly to browsers after re-gen /
    # --fix-sizes; raw st_mtime alone also missed WAL-committed rebuilds.
    # The raw spelling (not the resolved int) keys the ETag: it is hashed, so
    # request data never reaches a header, and each spelling is just its own
    # revalidation identity.
    asm_etag = _etag_or_304(_snapshot_db_mtime(), target, section, raw_va, size, fmt)

    with _target_cursor(target) as c:
        sec = _file_backed_section(c, target, section, "fileOffset", "va", "size")

        # Resolve among the decimal/hex candidate spellings: whichever lands
        # inside the section wins (decimal-first when both fit, matching
        # /functions/<va>).  No in-bounds candidate → 400, driven by the first
        # candidate so "before start" vs "beyond end" stays meaningful.
        sec_va = sec["va"]
        va = next(
            (cand for cand in va_candidates if sec_va <= cand < sec_va + sec["size"]),
            None,
        )
        if va is None:
            if va_candidates[0] < sec_va:
                return _json_err(400, {"error": "va is before section start"})
            return _json_err(400, {"error": "va is beyond section end"})
        file_offset = sec["fileOffset"] + va - sec_va
        if file_offset < 0:
            # Unreachable for a schema-valid sections row (fileOffset carries a
            # CHECK >= 0 and va >= sec_va here) — kept so a foreign DB without
            # that constraint cannot read bytes from before the file.
            return _json_err(400, {"error": "va is before section start"})

        if fmt == "json":
            # Structured JSON output
            target_data = _load_dll(target)
            if target_data is None:
                return _dll_not_found(target, "DLL not found")
            code_bytes = target_data[file_offset : file_offset + size]
            if len(code_bytes) < size:
                return _json_err(
                    422,
                    {
                        "error": "not enough bytes in DLL",
                        "detail": f"requested {size} bytes, {len(code_bytes)} available",
                    },
                )

            md = _get_capstone_md()
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
                Cache_Control=CACHE_REVALIDATE,
                ETag=asm_etag,
            )

        # Default: plain text
        asm_text = get_disassembly(va, size, file_offset, target)
        if not asm_text:
            return _json_err(
                422,
                {
                    "error": "not enough bytes in DLL",
                    "detail": f"requested {size} bytes starting at va {va_str!r}",
                },
            )

        return _json_ok({"asm": asm_text}, Cache_Control=CACHE_REVALIDATE, ETag=asm_etag)


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

    # ETag bound to the WAL-aware DB snapshot + request identity so /bytes
    # revalidates after a rebuild instead of serving year-immutable stale
    # bytes (raw st_mtime alone missed WAL-committed rebuilds).
    bytes_etag = _etag_or_304(_snapshot_db_mtime(), target, section, req_offset, req_size)

    with _target_cursor(target) as c:
        sec = _file_backed_section(c, target, section, "fileOffset", "size")
        if req_offset >= sec["size"]:
            return _json_err(400, {"error": "offset beyond section bounds"})
        target_data = _load_dll(target)
        if target_data is None:
            return _dll_not_found(target, "DLL not found for target")

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
            Cache_Control=CACHE_REVALIDATE,
            ETag=bytes_etag,
        )


@app.post("/api/regen")
def handle_regen() -> bytes | Any:
    global _regen_last_attempt

    remote = request.environ.get("REMOTE_ADDR", "")
    if remote not in LOOPBACK_HOSTS:
        return _json_err(
            403,
            {
                "error": "Forbidden: localhost only",
                "detail": f"request came from remote address {remote!r}",
            },
        )

    origin = request.headers.get("Origin", "")
    if origin:
        # Same hardened parser as the Host allowlist: userinfo-bearing or
        # otherwise non-plain values parse as "" and are rejected.
        origin_host = _hostname_of(origin)
        if origin_host not in LOOPBACK_HOSTS:
            return _json_err(
                403,
                {
                    "error": "Forbidden: cross-origin",
                    "detail": f"origin host {origin_host!r} is not loopback",
                },
            )
    else:
        # Origin is absent on every non-browser client (curl, scripts), so its
        # absence alone must stay allowed — but that also lets a cross-site
        # form POST through whenever a proxy or privacy extension strips
        # Origin.  Browsers attach Sec-Fetch-Site to every request they make,
        # and only they ever send "cross-site": treat that as a definitive
        # cross-origin POST and reject it.
        fetch_site = request.headers.get("Sec-Fetch-Site", "").strip().lower()
        if fetch_site == "cross-site":
            return _json_err(
                403,
                {
                    "error": "Forbidden: cross-site request",
                    "detail": f"Sec-Fetch-Site: {fetch_site} is not a same-origin regen",
                },
            )

    # Server-side cooldown + serialization: the cooldown check and the
    # subprocess must be atomic — two concurrent POSTs could otherwise both
    # pass the check and run catalog/build-db in parallel, tearing the
    # data_*.json / coverage.db (TOCTOU).  Non-blocking acquire: a second
    # POST while a regen runs gets an immediate 429 instead of blocking on
    # the lock for the whole (up to 240s) subprocess run.
    if not _REGEN_LOCK.acquire(blocking=False):
        return _json_err(
            429,
            {
                "error": "Rate limited: regeneration already running",
                "detail": "a catalog/build-db run is in progress",
            },
        )
    try:
        now = time.monotonic()
        if now - _regen_last_attempt < _REGEN_COOLDOWN_SECONDS:
            remaining = max(0, _REGEN_COOLDOWN_SECONDS - (now - _regen_last_attempt))
            return _json_err(
                429,
                {
                    "error": "Rate limited: wait before regenerating again",
                    "detail": f"retry after {remaining:.1f}s",
                    "retry_after": round(remaining, 1),
                },
            )
        _regen_last_attempt = now
        return _do_regen(remote)
    finally:
        _REGEN_LOCK.release()


def _do_regen(remote: str) -> bytes | Any:
    """Run catalog + build-db. Caller holds _REGEN_LOCK."""
    # Clear derived caches before AND after: the pre-run clears matter while
    # the subprocesses run; the resolved-target / index caches get
    # repopulated from the OLD db the moment anything queries them, and with
    # no SSE client connected the watcher would never re-invalidate them
    # (curl-only regen -> stale target dropdown).
    _clear_derived_caches()

    root = _project_dir()
    _log.info("Regen started from %s", remote)
    try:
        _server.run_regen_step("catalog", root)
        _server.run_regen_step("build-db", root)
        _clear_derived_caches()
        _log.info("Regen completed successfully")
        return _json_ok({"ok": True})
    except subprocess.TimeoutExpired:
        _log.error("Regen timed out after %ds", _server.REGEN_TIMEOUT)
        return _json_err(
            504,
            {
                "error": "Regen timed out",
                "detail": f"exceeded {_server.REGEN_TIMEOUT}s timeout",
            },
        )
    except subprocess.CalledProcessError as e:
        _log.error("Regen failed with exit code %d", e.returncode)
        return _json_err(
            500,
            {
                "error": f"Regen failed (exit code {e.returncode})",
                "detail": f"rebrew build-db exited with code {e.returncode}",
            },
        )
    except (OSError, subprocess.SubprocessError) as e:
        # Missing uv, launch failure, etc. — keep the JSON error contract
        # instead of letting an uncaught exception surface as an HTML 500.
        _log.error("Regen could not start: %s", e)
        return _json_err(
            500,
            {
                "error": "Regen could not start",
                "detail": f"{type(e).__name__}: {e}",
            },
        )
