"""API routes for the recoverage dashboard."""

from __future__ import annotations

import contextlib
import json
import logging
import math
import queue
import re
import sqlite3
import threading
from collections.abc import Generator
from pathlib import Path
from typing import Any

import typer
from rebrew.workspace import KNOWN_STATUSES, VA_MAX, parse_va_candidates

from recoverage import __version__, clock
from recoverage import metrics as _metrics
from recoverage import server as _server
from recoverage._paths import _db_path
from recoverage.disasm import (
    HAS_CAPSTONE,
    clear_disassembly_cache,
    get_capstone_md,
    get_disassembly,
)
from recoverage.regen import run_regen
from recoverage.server import (
    _SECTION_BUCKETS_SQL,
    CACHE_NO_STORE,
    CACHE_REVALIDATE,
    DLL_DATA,
    DLL_LOCK,
    HAS_PYGMENTS,
    NOT_DATA_MARKER_SQL,
    _best_encoding,
    _cell_bucket_row,
    _cells_json_rows,
    _db,
    _escape_like,
    _etag_or_304,
    _fn_json_sql,
    _format_hex_dump,
    _get_targets_config,
    _global_json_sql,
    _header,
    _json_err,
    _json_ok,
    _json_ok_precompressed,
    _load_dll,
    _load_metadata,
    _open_db,
    _peer_is_loopback,
    _project_dir,
    _snapshot_db_mtime,
    _target_filename,
    _verify_one_select,
    _verify_select,
    app,
    clear_target_cache,
    compress_payload,
    folded_like_clause,
    like_match,
    origin_is_this_dashboard,
    path_param,
    query_param,
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
    _clear_stats_cache()
    _clear_list_total_cache()
    from recoverage.potato import clear_cells_cache

    clear_cells_cache()
    # Disassembly/DLL bytes reflect the original binary and section layout,
    # both of which change with a rebuild.
    with DLL_LOCK:
        DLL_DATA.clear()
    clear_disassembly_cache()


# Server-side regen cooldown (seconds): the UI throttles Reload clicks, but
# direct API calls must not be able to trigger repeated rebrew catalog runs.
_REGEN_COOLDOWN_SECONDS = 5.0
# clock.monotonic() of the last accepted regen POST, or None before the first
# one.  None, never 0.0: on Linux the monotonic clock counts from boot, so a
# process started seconds after a reboot would read now < 5.0 and reject the
# very first POST as "cooling down" for the length of the cooldown window.
_regen_last_attempt: float | None = None
_REGEN_LOCK = threading.Lock()  # serializes regen (check + run, TOCTOU)

# Idempotency-Key ledger for POST /api/regen.  A regen is a whole-pipeline
# rebuild, so a duplicate that arrives after the first one finished answers
# from the ledger instead of running catalog+build-db a second time: a client
# retry (proxy replay, a lost response, a double-clicked Reload) re-sends the
# request it never saw answered, and re-running it is minutes of duplicated
# work plus a second write of coverage.db for an identical result.
#
# Key -> monotonic completion time.  Only completed runs are recorded, so a
# run that failed retries for real, and only the outcome is stored: the
# success body is a constant, and rebuilding it per request keeps the
# response's Content-Encoding matched to that request's Accept-Encoding.
# Bounded on both axes so the ledger cannot grow without limit: a key only has
# to outlive the client's retry horizon, and the count cap keeps a client
# that mints a fresh key per attempt from pinning memory.
_REGEN_KEY_TTL_SECONDS = 600.0
# The count cap is a memory backstop, never the binding retention rule: the
# cooldown admits at most _REGEN_KEY_TTL_SECONDS / _REGEN_COOLDOWN_SECONDS + 1
# = 121 completions inside any single retention window, so 128 slots always fit
# them all.  A tighter cap silently shortened the documented window below: a
# client regenerating more often than the cap held slots lost an unexpired key
# and paid a second pipeline run for a retry the ledger was meant to absorb.
_REGEN_KEY_MAX = 128
# A key is an opaque client nonce; anything outside this set is a client bug
# or an attempt to fill the ledger with junk, and is rejected rather than
# stored.
_REGEN_KEY_RE = re.compile(rf"[A-Za-z0-9._:-]{{1,{_REGEN_KEY_MAX}}}")
_REGEN_COMPLETED_KEYS: dict[str, float] = {}
_REGEN_COMPLETED_KEYS_LOCK = threading.Lock()


def _prune_completed_keys(now: float) -> None:
    """Drop completed keys past the retention window. Caller holds the lock."""
    for key, done_at in list(_REGEN_COMPLETED_KEYS.items()):
        if now - done_at >= _REGEN_KEY_TTL_SECONDS:
            del _REGEN_COMPLETED_KEYS[key]


def _regen_replayed(key: str) -> bool:
    """True when *key* already completed a regen inside the retention window."""
    now = clock.monotonic()
    with _REGEN_COMPLETED_KEYS_LOCK:
        _prune_completed_keys(now)
        return key in _REGEN_COMPLETED_KEYS


def _record_completed_key(key: str) -> None:
    """Remember that *key*'s regen completed, so its retry is answered, not re-run."""
    now = clock.monotonic()
    with _REGEN_COMPLETED_KEYS_LOCK:
        _prune_completed_keys(now)
        # Re-insert (rather than refresh in place) so the eviction order stays
        # completion order.
        _REGEN_COMPLETED_KEYS.pop(key, None)
        _server._evict_oldest(_REGEN_COMPLETED_KEYS, _REGEN_KEY_MAX)
        _REGEN_COMPLETED_KEYS[key] = now


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
# Single-flight build coordination: fingerprint -> Event set while one thread
# runs the queries/serialization for that key.  A rebuild broadcast clears the
# memo and wakes every connected SSE client, which all refetch /data at once;
# without this, each of those cold misses materializes its own multi-MB
# payload (full-table json_group_array + search index + json.dumps).
_DATA_CACHE_BUILDING: dict[tuple[tuple[int, int] | None, str, str | None], threading.Event] = {}
#: How long a follower waits on the leader's build Event.  The leader's finally
#: always sets it, so this only bounds the case where it does not (a thread
#: killed mid-build).  Comfortably longer than a cold /data build on a large
#: target, so a follower that gives up here has genuinely lost its leader.
_DATA_CACHE_BUILD_WAIT_SECONDS = 30.0


def _clear_data_cache() -> None:
    # Deliberately leaves _DATA_CACHE_BUILDING alone: each Event is owned by
    # the thread that registered it and is set in that thread's finally, so
    # waiters always wake.  Clearing here could strand a waiter on an Event
    # nobody will ever set.  A waiter that wakes to a cleared memo simply
    # builds the (post-clear) payload itself.
    with _DATA_CACHE_LOCK:
        _DATA_CACHE.clear()


def _data_cache_checkout(
    key: tuple[tuple[int, int] | None, str, str | None],
) -> tuple[dict[str, bytes] | None, threading.Event | None]:
    """Return ``(memo_entry, owned_event)`` for *key*.

    - Memo hit: ``(<entry>, None)`` — serve it.
    - No entry, no in-flight build: ``(None, <event>)`` — caller builds and
      MUST pass *owned_event* to :func:`_data_cache_build_done` in a finally.
    - Build already running: waits for it, then returns whatever the memo
      holds now (None when the leader failed or short-circuited with a 404 —
      the caller then builds its own payload).
    """
    with _DATA_CACHE_LOCK:
        entry = _DATA_CACHE.get(key)
        if entry is not None:
            return entry, None
        event = _DATA_CACHE_BUILDING.get(key)
        if event is None:
            event = _DATA_CACHE_BUILDING[key] = threading.Event()
            return None, event
    # Follower path (outside the lock): the leader's finally always sets the
    # event — success, error, or 404 short-circuit alike.  The bound is the
    # backstop for the case it does not (a thread killed between checkout and
    # the finally); a follower that gives up rebuilds its own payload, which
    # is what the None below tells it to do.
    event.wait(timeout=_DATA_CACHE_BUILD_WAIT_SECONDS)
    with _DATA_CACHE_LOCK:
        return _DATA_CACHE.get(key), None


def _data_cache_build_done(
    key: tuple[tuple[int, int] | None, str, str | None], event: threading.Event
) -> None:
    """Release followers of *key* (owner only — see :func:`_data_cache_checkout`)."""
    with _DATA_CACHE_LOCK:
        if _DATA_CACHE_BUILDING.get(key) is event:
            del _DATA_CACHE_BUILDING[key]
    event.set()


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


# Memoized /stats results, keyed by the WAL-aware DB snapshot + target.
# handle_api_stats re-runs the full-cells-table SECTION_STATS_SQL aggregation
# plus four more queries on every miss; a polling consumer must not re-pay
# that scan while the DB is unchanged.  Same self-invalidation contract as the
# /data payload memo: a rebuild changes the snapshot, so stale entries miss.
# Lives HERE, not in server._section_stats, because only this module knows
# which database its connections come from (the CLI passes its own cursor).
_STATS_CACHE: dict[tuple[tuple[int, int] | None, str], dict[str, Any]] = {}
_STATS_CACHE_LOCK = threading.Lock()
_STATS_CACHE_MAX = 16


def _clear_stats_cache() -> None:
    """Drop memoized /stats results (called on DB rebuild)."""
    with _STATS_CACHE_LOCK:
        _STATS_CACHE.clear()


# Memoized `total` for the paginated function list.  COUNT(*) over `functions`
# is a full row scan of a wide table (measured 7.2 ms on a 20k-function
# target with no filter, 8.2 ms once a search LIKE joins it) and the SPA
# re-requests the list on every filter, status and page change, paying it
# again for a number the DB has not changed.  Keyed by the same WAL-aware
# snapshot as the other memos plus the exact filter triple the count depends
# on, so a rebuild or a different filter misses; capped like the rest.
_LIST_TOTAL_CACHE: dict[tuple[tuple[int, int] | None, str, str | None, str | None], int] = {}
_LIST_TOTAL_CACHE_LOCK = threading.Lock()
_LIST_TOTAL_CACHE_MAX = 64


def _clear_list_total_cache() -> None:
    """Drop memoized function-list totals (called on DB rebuild)."""
    with _LIST_TOTAL_CACHE_LOCK:
        _LIST_TOTAL_CACHE.clear()


def _function_total(
    c: sqlite3.Cursor,
    target: str,
    where_sql: str,
    params: list[Any],
    snap: tuple[int, int] | None,
    status_filter: str | None,
    search: str | None,
) -> int:
    """Rows matching the list endpoint's filter, memoized per DB snapshot.

    The count is served from the memo only when the filter and the database
    both match; otherwise the COUNT(*) runs and repopulates it.  A None
    snapshot (DB unreadable) never memoizes — the endpoint is about to 503
    and a value derived from that state must not outlive it.
    """
    key: tuple[tuple[int, int] | None, str, str | None, str | None] | None = (
        (snap, target, status_filter, search) if snap is not None else None
    )
    if key is not None:
        with _LIST_TOTAL_CACHE_LOCK:
            cached = _LIST_TOTAL_CACHE.get(key)
        if cached is not None:
            return cached
    c.execute(f"SELECT COUNT(*) FROM functions WHERE {where_sql}", params)
    total = c.fetchone()[0]
    if key is not None:
        with _LIST_TOTAL_CACHE_LOCK:
            _server._evict_oldest(_LIST_TOTAL_CACHE, _LIST_TOTAL_CACHE_MAX)
            _LIST_TOTAL_CACHE[key] = total
    return total


def _target_not_found(target: str) -> Any:
    """JSON 404 for a target-scoped endpoint referencing an unknown target."""
    return _json_err(
        404,
        {
            "error": "Target not found",
            "detail": f"no such target {target!r}",
        },
    )


def _dll_not_found(target: str) -> Any:
    """JSON 404 for a target whose original binary is missing or unconfigured."""
    hint = (
        f" add [targets.{target}].binary to rebrew-project.toml"
        if target not in _get_targets_config()
        else ""
    )
    return _json_err(
        404,
        {
            "error": "DLL not found",
            "detail": f"original binary for target {target!r} not found;{hint}",
        },
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
        targets_list = resolve_targets(c)
    except sqlite3.Error as exc:
        # Transient SQLITE_BUSY / locked must surface as 503, not be swallowed
        # as "unknown target" or silent success.  Every other sqlite error
        # means the DB is unreadable — let the endpoint's own 503 path run.
        if isinstance(exc, sqlite3.OperationalError) and (
            "busy" in str(exc).lower() or "locked" in str(exc).lower()
        ):
            raise
        return None
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
    except sqlite3.Error as exc:
        # Logged + detailed by the shared helper — a swallowed sqlite3.Error
        # here would make a missing/corrupt DB invisible in the server log.
        raise _server._db_unavailable_err(exc) from None
    try:
        c = conn.cursor()
        not_found = _require_target(c, target)
        if not_found is not None:
            raise not_found
        yield c
    finally:
        conn.close()


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
# teardown, which propagates GeneratorExit into the generator's ``finally``).

_SSE_POLL_INTERVAL_SECONDS = 2.0
_SSE_HEARTBEAT_SECONDS = 15.0
# How long a stream blocks on an empty client queue before it re-reads the
# clock.  Below the heartbeat interval so a ping is never more than one
# poll late, and a named constant so a test can shorten the wait.
_SSE_QUEUE_POLL_SECONDS = 1.0
_SSE_QUEUE_MAX = 32  # per-client buffer; slow clients drop events, not memory
_SSE_MAX_CLIENTS = 32  # cap on concurrent /api/events streams (thread DoS guard)

_SSE_CLIENTS: set[queue.Queue[bytes]] = set()
_SSE_CLIENTS_LOCK = threading.Lock()
_DB_WATCHER_THREAD: threading.Thread | None = None
_DB_WATCHER_STOP = threading.Event()
_DB_WATCHER_LOCK = threading.Lock()
# Grace period _stop_db_watcher gives a wedged watcher before giving up on
# the join (must comfortably exceed _SSE_POLL_INTERVAL_SECONDS).
_DB_WATCHER_JOIN_TIMEOUT = 5.0


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
        # layout to any LAN/browser client (docs/THREAT_MODEL.md).
        "db": {"path": _db_path().name},
        "timestamp": clock.wall_time(),
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
    lifetime of the process.  The guard is the WHOLE loop, baseline snapshot
    included: the baseline read sat outside it, so a failure there (a
    ``coverage.db`` path that cannot be stat'ed raises rather than returning
    None) killed the thread with its traceback going to a stream nobody
    reads.  ``/api/health`` only reports ``watcher_alive: false`` as
    ``degraded`` while a client is connected, so with no SSE client the
    dashboard answered "healthy" with live reload dead for the rest of the
    process.  The ``finally`` names the exit so a dead poller is one grep
    away, and says whether the stop event asked for it.
    """
    try:
        last = _snapshot_db_mtime()
        while not stop.is_set():
            stop.wait(_SSE_POLL_INTERVAL_SECONDS)
            if stop.is_set():
                break
            try:
                snapshot = _snapshot_db_mtime()
                if snapshot != last:
                    # Advance the baseline only after a successful broadcast:
                    # a failed iteration retries the same change on the next
                    # poll (at-least-once) instead of silently dropping the
                    # event.
                    _broadcast_db_updated(snapshot)
                    last = snapshot
            except Exception:
                _log.exception("DB watcher iteration failed — continuing to poll")
    except BaseException:
        _log.exception(
            "DB watcher stopped after an unhandled error — live reload is off "
            "until the server restarts"
        )
        raise
    _log.debug("DB watcher stopped on request")


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
    """Stop the watcher thread (used by tests).

    The stop event is set under _DB_WATCHER_LOCK so stop and
    :func:`_ensure_db_watcher` are mutually exclusive: set-then-lock let a
    concurrent ensure observe the still-alive thread and return, after which
    the join here retired it — a stopped watcher with SSE clients registered
    and nothing left to restart it.

    A join that times out KEEPS the reference. Nulling it would let the next
    ensure clear the (still set) stop event and start a SECOND poller beside
    the wedged one, which then un-wedges, sees stop cleared, and keeps
    broadcasting duplicates as an untracked thread forever. With the
    reference retained, ensure returns early while the thread is alive and
    stop stays set — the wedged loop retires itself at its next loop check,
    and a later stop retries the join.
    """
    global _DB_WATCHER_THREAD
    with _DB_WATCHER_LOCK:
        _DB_WATCHER_STOP.set()
        if _DB_WATCHER_THREAD is not None:
            _DB_WATCHER_THREAD.join(timeout=_DB_WATCHER_JOIN_TIMEOUT)
            if _DB_WATCHER_THREAD.is_alive():
                _log.warning(
                    "DB watcher did not stop within %.1fs — leaving it referenced "
                    "so no second poller starts alongside it",
                    _DB_WATCHER_JOIN_TIMEOUT,
                )
            else:
                _DB_WATCHER_THREAD = None


class _SSEStream:
    """The /api/events body: the frame generator plus an idempotent close().

    A generator's ``finally`` runs only if the generator was STARTED, and PEP
    3333 lets a server close the iterable it was handed without ever
    iterating it — a peer that hangs up between the handler returning and the
    first write is exactly that case, and ``gen.close()`` on a not-yet-started
    generator raises GeneratorExit at the definition, skipping the body.  The
    client queue is registered before the stream exists, so unregistering it
    from the generator's ``finally`` alone loses a slot, a file descriptor and
    a handler thread for the process's remaining lifetime, permanently eroding
    the ``_SSE_MAX_CLIENTS`` cap.  Both exit paths go through
    :meth:`_release` instead, and :meth:`close` is safe to call twice.
    """

    def __init__(self, client_queue: queue.Queue[bytes]) -> None:
        self._queue = client_queue
        self._gen: Generator[bytes] | None = None
        self._released = False

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        with _SSE_CLIENTS_LOCK:
            _SSE_CLIENTS.discard(self._queue)

    def __iter__(self) -> Generator[bytes]:
        # One generator for the object's life, so a second iter()/next() sees
        # the same stream position rather than restarting the stream.
        if self._gen is None:
            self._gen = self._frames()
        return self._gen

    def _frames(self) -> Generator[bytes]:
        try:
            yield b": connected\n\n"
            last_heartbeat = clock.monotonic()
            while True:
                try:
                    frame = self._queue.get(timeout=_SSE_QUEUE_POLL_SECONDS)
                except queue.Empty:
                    frame = None
                if frame is not None:
                    yield frame
                now = clock.monotonic()
                if now - last_heartbeat >= _SSE_HEARTBEAT_SECONDS:
                    yield b": ping\n\n"
                    last_heartbeat = now
        finally:
            self._release()

    def close(self) -> None:
        self._release()


@app.get("/api/events")
def handle_api_events() -> Any:
    """SSE stream: emits a db-updated event when coverage.db is rewritten.

    Bottle streams the returned :class:`_SSEStream`.  The watcher thread
    broadcasts to a per-client queue; this route drains it.  Disconnects are
    detected when the stream is closed — the client queue is removed by
    :meth:`_SSEStream.close`, which the server calls on every exit path.
    """
    # Cap concurrent SSE clients: each connection pins a server thread for
    # the life of the stream (minutes/hours), and wsgiref has no connection
    # limit.  A LAN client (or a cross-origin EventSource from any webpage
    # a victim visits — no-cors, loopback) could otherwise exhaust threads.
    with _SSE_CLIENTS_LOCK:
        if len(_SSE_CLIENTS) >= _SSE_MAX_CLIENTS:
            # Refusals reach /api/health's error count, but a health snapshot
            # says "the cap is full", not "the cap has been full since 10:04
            # and every SPA tab since then is stale".  One line per refusal is
            # bounded by the refusal rate, which is the interesting signal.
            _log.warning(
                "Refusing /api/events: %d/%d streams already connected",
                len(_SSE_CLIENTS),
                _SSE_MAX_CLIENTS,
            )
            return _json_err(
                503,
                {
                    "error": "too many event-stream clients",
                    "code": "rate_limited",
                    "detail": f"max {_SSE_MAX_CLIENTS} concurrent /api/events connections",
                    "retry_after": _SSE_POLL_INTERVAL_SECONDS,
                },
                # One value in both places: a client that reads the header
                # instead of the body (the auth throttle and /api/regen send
                # the same header) must not be told a different wait than one
                # the JSON states.
                Retry_After=str(int(_SSE_POLL_INTERVAL_SECONDS)),
            )
        client_queue: queue.Queue[bytes] = queue.Queue(maxsize=_SSE_QUEUE_MAX)
        _SSE_CLIENTS.add(client_queue)
    # Start the poller only once a client is actually registered; rejected
    # connections must not leave background work behind.  A failed start
    # (e.g. RuntimeError under thread exhaustion) must not leave the queue
    # registered: every leaked slot permanently shrinks the _SSE_MAX_CLIENTS
    # cap toward a standing 503 for /api/events.
    try:
        _ensure_db_watcher()
    except BaseException:
        with _SSE_CLIENTS_LOCK:
            _SSE_CLIENTS.discard(client_queue)
        raise

    response.content_type = "text/event-stream"
    response.set_header("Cache-Control", CACHE_NO_STORE)
    response.set_header("X-Accel-Buffering", "no")
    return _SSEStream(client_queue)


#: Last (status, reason) ``/api/health`` reported, so the probe logs a
#: transition rather than one line per poll.  Without it a monitor pointed at
#: the endpoint (an external health check, a shell while-loop) turned a missing
#: coverage.db into a WARNING per probe for as long as it stayed missing, which
#: is what teaches an operator to skip the line; the transition is the news,
#: and the recovery line is what closes it.  The snapshot still carries
#: ``status`` on every probe, so dropping the repeats loses nothing an
#: operator reads.
_HEALTH_LOG_LOCK = threading.Lock()
_health_reported: tuple[str, str] | None = None


def _log_health_status(status: str, reason: str) -> None:
    """Log the first probe in a state, the first probe after it, and nothing else.

    A repeat of the current state returns without logging.  A change of reason
    inside one state does too: the status did not move, and the per-check
    detail already says which dependency is unhappy.
    """
    global _health_reported
    with _HEALTH_LOG_LOCK:
        if _health_reported is not None and _health_reported[0] == status:
            return
        previous = _health_reported
        _health_reported = (status, reason)
    if previous is None or previous[0] == "healthy":
        # The first probe of the process, or the move out of healthy: the same
        # alert either way.  A healthy first probe is not news.
        if status != "healthy":
            _log.warning("Dashboard health degraded: %s", reason)
    else:
        _log.info("Dashboard health recovered: was %s (%s)", previous[0], previous[1])


@app.get("/api/health")
def handle_api_health() -> bytes:
    """Liveness and environment report: status, version, DB stat, extras, targets.

    status is "degraded" (not an error) when coverage.db cannot be stat'ed or
    queried; db.path is the basename only, never the absolute path.  db.mtime
    is epoch seconds and db.mtime_utc the same instant as an ISO-8601 instant
    (``+00:00``), both read off one conversion of the file's mtime
    (``server.mtime_ns_to_utc``) so they cannot disagree; both are absent when
    the DB cannot be stat'ed.

    Every reason the probe found is named in one log line per transition
    (:func:`_log_health_status`), not one line per probe.
    """
    db = _db_path()
    db_info: dict[str, Any] = {"path": db.name, "exists": False}
    reasons: list[str] = []
    try:
        stat = db.stat()
        db_info["exists"] = True
        db_info["size_bytes"] = stat.st_size
    except OSError as exc:
        reasons.append(f"coverage.db not accessible: {type(exc).__name__}: {exc}")
    # Freshness is the newest mtime across the DB and its -wal sibling: a
    # rebuild that commits only to the WAL leaves the main file's mtime where
    # it was, and every other DB-freshness surface (ETags, memos, the SSE
    # watcher, Potato Mode's footer) already reads the WAL-aware stamp.
    mtime_ns = _server._newest_mtime_ns(db)
    if mtime_ns is not None:
        # Seconds since the epoch (UTC) plus the same instant spelled out with
        # an explicit zone, so a client never has to assume the host's TZ.
        # Both come from ONE conversion: a float second cannot hold the
        # nanosecond mtime, so deriving the two independently let the ISO
        # stamp sit up to half a second off the epoch field beside it.
        stamp = _server.mtime_ns_to_utc(mtime_ns)
        db_info["mtime"] = stamp.timestamp()
        db_info["mtime_utc"] = stamp.isoformat()
    target_count = 0
    try:
        with contextlib.closing(_open_db(db)) as conn:
            c = conn.cursor()
            # Counted from the same read the target list uses, so the health
            # number and the dropdown can never disagree on the schema row.
            target_count = len(_server.db_target_ids(c))
    except sqlite3.Error as exc:
        reasons.append(f"coverage.db target count query failed: {type(exc).__name__}: {exc}")
    streams = _stream_stats()
    if streams["watcher_alive"] is False and streams["clients"] > 0:
        # Connected clients with no poller means live reload is dead while
        # every page still renders: healthy-looking, silently stale.
        reasons.append("the DB watcher is not running while event-stream clients are connected")
    status = "degraded" if reasons else "healthy"
    _log_health_status(status, "; ".join(reasons) or "ok")
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
            # RED counters for this process: request rate, error rate, and
            # latency extremes, so the operator can tell "one slow request"
            # from "the dashboard got slow" without a metrics backend.
            "requests": _metrics.REQUESTS.snapshot(),
            # The regen pipeline runs for minutes, so its outcome and duration
            # need counters of their own; the request snapshot cannot show a
            # run that has not finished.
            "regen": _metrics.REGEN.snapshot(),
            # Live-reload saturation: every connected stream pins a server
            # thread for its whole life, and the cap answers 503 to the next
            # one.  clients vs max is the distance to that refusal.
            "streams": streams,
        },
        Cache_Control=CACHE_NO_STORE,
    )


def _stream_stats() -> dict[str, Any]:
    """SSE saturation and poller liveness for /api/health.

    ``watcher_alive`` is None before the first client connects: the poller
    starts lazily, so "not started yet" is not a fault and must not read as
    one.
    """
    with _SSE_CLIENTS_LOCK:
        clients = len(_SSE_CLIENTS)
    watcher = _DB_WATCHER_THREAD
    if watcher is None:
        alive: bool | None = None
    else:
        alive = watcher.is_alive()
    return {
        "clients": clients,
        "max_clients": _SSE_MAX_CLIENTS,
        "queue_max": _SSE_QUEUE_MAX,
        "watcher_alive": alive,
    }


@app.get("/api/targets")
def handle_api_targets() -> bytes:
    try:
        with contextlib.closing(_db()) as conn:
            c = conn.cursor()
            targets_list = resolve_targets(c)
    except sqlite3.Error as exc:
        # The cause goes in the line: a locked database and a corrupt one both
        # land here, and the operator needs to tell them apart without reading
        # the source.
        _log.warning(
            "Database unavailable reading the target list, falling back to the "
            "config-only list: %s: %s",
            type(exc).__name__,
            exc,
        )
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
    target = path_param(target)
    snap = _snapshot_db_mtime()
    # Same validator contract as /data, /asm and /bytes: the payload is a pure
    # function of the WAL-aware snapshot and the target, so a poll that
    # revalidates gets a 304 instead of re-running the SECTION_STATS_SQL
    # aggregation.  "stats" is a part of its own so the tag can never collide
    # with /data's (snap, target, section) over the same DB.
    etag = _etag_or_304(snap, target, "stats")
    key = (snap, target)
    stats: dict[str, Any] | None = None
    if snap is not None:
        with _STATS_CACHE_LOCK:
            stats = _STATS_CACHE.get(key)
    if stats is None:
        with _target_cursor(target) as c:
            stats = _server._section_stats(c, target)
        if snap is not None:
            with _STATS_CACHE_LOCK:
                _server._evict_oldest(_STATS_CACHE, _STATS_CACHE_MAX)
                _STATS_CACHE[key] = stats
    # ONE response shape for memo hits and fresh builds.
    return _json_ok(
        {
            "target": target,
            "summary": stats["summary"],
            "sections": stats["sections"],
            "functions_by_status": stats["by_status"],
        },
        **_revalidate_headers(etag),
    )


def _build_search_index(c: sqlite3.Cursor, target: str) -> dict[str, Any]:
    """Lightweight name -> {va, symbol} index for the SPA search box.

    Names are not unique across functions and globals — keep the FIRST
    (functions win over globals) so navigation never silently jumps to a
    colliding global's VA.
    """
    index: dict[str, Any] = {}
    c.execute(
        "SELECT name, vaStart, symbol FROM functions WHERE target = ?",
        (target,),
    )
    # Iterate the cursor rather than fetchall(): this walks every function of
    # the target (tens of thousands of rows), and fetchall would hold the whole
    # rowset as a list on top of the index being built from it.
    for row in c:
        index.setdefault(row["name"], {"va": row["vaStart"], "symbol": row["symbol"]})
    # Globals get their own cursor: one cursor per query keeps the functions
    # rowset above from being clobbered by the second execute.
    c2 = c.connection.cursor()
    try:
        c2.execute("SELECT name, va FROM globals WHERE target = ?", (target,))
        for row in c2:
            va = row["va"]
            index.setdefault(row["name"], {"va": hex(va) if va is not None else "", "symbol": ""})
    finally:
        c2.close()
    return index


def _build_data_raw(c: sqlite3.Cursor, target: str, section_filter: str | None) -> bytes:
    """Query and serialize the full /data payload (sections + cells + search index).

    Raises the shared JSON 404 for an unknown *section_filter*.  Pure DB
    work — caching/compression stays in the endpoint.
    """
    # Sections, cells, the search index, and the per-section buckets are four
    # statements over four tables; a rebuild committing between them would
    # pair one build's section rows with the next build's cells.
    with _server.read_snapshot(c):
        return _read_data_raw(c, target, section_filter)


def _read_data_raw(c: sqlite3.Cursor, target: str, section_filter: str | None) -> bytes:
    """_build_data_raw body, run against the snapshot read_snapshot pinned."""
    data: dict[str, Any] = _load_metadata(c, target)

    # Always load every section row so the SPA can render tabs from a
    # ?section= payload.  Cells are the multi-MB part: omit siblings when
    # the client asked for one section (null, not []).
    c.execute("SELECT * FROM sections WHERE target = ?", (target,))
    data["sections"] = {}
    for row in c.fetchall():
        data["sections"][row["name"]] = dict(row)

    if section_filter and section_filter not in data["sections"]:
        # Mirror /asm: an unknown section must 404, not return a silent
        # empty grid (which would also get memoized under that key).
        raise _section_not_found(target, section_filter)

    # SQLite already emitted each section's cells as a JSON array.  Parsing
    # that into Python and json.dumps-ing it back was ~70 ms of the ~115 ms
    # cold /data build on an 80k-cell DB, for identical bytes.  Keep the
    # strings and splice them into the envelope below.
    cells_json: dict[str, str | None] = {}
    # data["sections"] is every section row for the target, so a materialized
    # section_cells_json that covers only some of them cannot silently blank
    # the rest: _cells_json_rows re-aggregates the gaps from `cells`.
    for row in _cells_json_rows(c, target, section_filter, set(data["sections"])):
        sec_name = row[0]
        if sec_name in data["sections"]:
            cells_json[sec_name] = row[1]
    if section_filter:
        for name in data["sections"]:
            cells_json.setdefault(name, None)

    data["search_index"] = _build_search_index(c, target)

    # The accepted schema set travels with the payload: the SPA's empty-state
    # message needs it to tell "no section rows yet" from "this build does not
    # understand the DB", and a second copy hardcoded in app.js would drift as
    # rebrew advances the schema.
    data["known_schema"] = sorted(_server.KNOWN_SCHEMA_VERSIONS)

    # Per-section cell stats from the materialized table.  _cell_bucket_row reads the whole
    # row, so the projection is the shared one server._per_section_buckets
    # uses: a hand-listed column set here can silently drop a bucket rebrew
    # adds, and the served key set would then differ from /stats.
    data["section_cell_stats"] = {}
    stats_clause = " AND section_name = ?" if section_filter else ""
    stats_params: list[Any] = [target] + ([section_filter] if section_filter else [])
    c.execute(_SECTION_BUCKETS_SQL + stats_clause, stats_params)
    for row in c.fetchall():
        data["section_cell_stats"][row["section_name"]] = _cell_bucket_row(row)

    return _dumps_with_cells(data, cells_json)


def _dumps_with_cells(data: dict[str, Any], cells_json: dict[str, str | None]) -> bytes:
    """Serialize *data* while splicing pre-encoded ``cells`` JSON arrays.

    ``data["sections"][name]`` is the section row *without* a cells key.
    *cells_json* maps names to ``json_group_array`` output, or ``None`` to
    omit the key (SPA lazy-load).  Missing names become ``[]``.
    """
    sections = data.pop("sections")
    rest = json.dumps(data, separators=(",", ":"))
    parts: list[str] = ["{"]
    if rest != "{}":
        parts.append(rest[1:-1])
        parts.append(",")
    parts.append('"sections":{')
    for i, (name, sec) in enumerate(sections.items()):
        if i:
            parts.append(",")
        sec_json = json.dumps(sec, separators=(",", ":"))
        cells = cells_json.get(name, "[]")
        # String splice, not a JSON encoder: cells is already a JSON array
        # (json_group_array) and re-parsing it through Python dominated the
        # cold /data build.  A non-JSON cells encoding would need a real
        # encoder here.
        if cells is None:
            spliced = "{}" if sec_json == "{}" else sec_json
        elif sec_json == "{}":
            spliced = '{"cells":' + cells + "}"
        else:
            spliced = sec_json[:-1] + ',"cells":' + cells + "}"
        parts.append(json.dumps(name))
        parts.append(":")
        parts.append(spliced)
    parts.append("}}")
    return "".join(parts).encode("utf-8")


@app.get("/api/targets/<target>/data")
def handle_api_data(target: str) -> bytes | Any:
    target = path_param(target)
    section_filter = query_param("section").strip() or None

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
    # cache-missing request.  A cold miss single-flights: concurrent misses
    # (the post-rebuild SSE refetch herd) share one build.
    entry, building = _data_cache_checkout(fingerprint)
    if entry is not None:
        accept_enc = _header("Accept-Encoding", "")
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

    try:
        with _target_cursor(target) as c:
            raw_json = _build_data_raw(c, target, section_filter)
            accept_enc = _header("Accept-Encoding", "")
            body, encoding = compress_payload(raw_json, accept_enc)
            _cache_data_insert(fingerprint, raw_json, encoding, body)
            return _json_ok_precompressed(body, encoding, **headers)
    finally:
        if building is not None:
            _data_cache_build_done(fingerprint, building)


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

# Upper bound for a binary-slice request (?size= on /asm and /bytes): both
# endpoints clamp identically so the same query string cannot mean two
# different window sizes.
_MAX_SLICE_SIZE = 4096

# Longest ?search= the list endpoint accepts.  A longer pattern is a bounded
# LIKE over a wide table, not a useful query; rejecting it keeps the work per
# request finite.
_MAX_SEARCH_CHARS = 500

#: Statuses ``functions.status`` can carry: rebrew's own vocabulary
#: (``rebrew.build_db._FUNCTION_DB_STATUSES``, which is KNOWN_STATUSES plus the
#: UNKNOWN default a catalog row falls back to) read from rebrew rather than
#: restated, so a status rebrew adds is filterable the day it lands.
#: ``tests/test_api.py`` (``TestFunctionStatusVocabulary``) pins the set against
#: rebrew's, so a rebrew change that misses this import fails a test instead of
#: silently 400-ing a status the DB does hold.
_FUNCTION_STATUSES: frozenset[str] = frozenset({*KNOWN_STATUSES, "UNKNOWN"})

# Media types POST /api/targets/<t>/functions accepts for its body.  The
# endpoint has exactly one body format, so a request declaring anything else
# is refused with 415 rather than being read and answered with a parse error
# that reads as "your JSON is broken" when the bytes were fine.
_JSON_MEDIA_TYPE = "application/json"
_JSON_SUFFIX = "+json"

# Representations GET /api/targets/<t>/asm can produce.  Anything else is
# rejected rather than silently answered with the text form.
_ASM_FORMATS = frozenset({"text", "json"})


def _parse_byte_count(raw: str) -> int:
    """Parse a byte count from the query string: decimal, or 0x-prefixed hex.

    ONE parse for ``?size=`` on /asm and /bytes and ``?offset=`` on /bytes, so
    the three cannot read the same spelling three ways.

    NOT ``int(raw, 0)``.  Base 0 was wrong in both directions: it rejects a
    leading-zero decimal ("064" is a byte count, answered 400), and it accepts
    spellings these endpoints never documented — ``0b1010`` and ``0o17`` both
    parsed, so a client sending a binary count got a slice it never asked for.
    A sign is still honoured, because the callers clamp or reject a negative
    value with their own message.
    """
    text = raw.strip()
    sign = -1 if text.startswith("-") else 1
    if text[:1] in ("+", "-"):
        text = text[1:]
    return sign * int(text, 16 if text[:2].lower() == "0x" else 10)


def _slice_size(raw_size: str, parse_error: str) -> tuple[int, Any | None]:
    """Clamp a binary-slice ``?size=`` to 1.._MAX_SLICE_SIZE.

    ONE parse for /asm and /bytes, so the same query string cannot mean two
    different windows on the two endpoints: surrounding whitespace is stripped
    here (only /asm used to), the value is a decimal count or a 0x-prefixed hex
    one (see :func:`_parse_byte_count`), and an empty slice is a rejected query
    rather than a valid empty dump.

    *parse_error* is the caller's ``error`` label for an unparseable value
    ("invalid va or size" on /asm, "invalid size" on /bytes); the rejected
    value itself goes in the detail either way.

    Returns ``(size, None)`` on success, ``(0, error_response)`` when the value
    is unparseable or clamps to zero.
    """
    try:
        size = min(max(_parse_byte_count(raw_size), 0), _MAX_SLICE_SIZE)
    except ValueError:
        return 0, _json_err(
            400,
            {
                "error": parse_error,
                "detail": f"size {raw_size!r} is not a byte count "
                f"(decimal, or 0x-prefixed hex; 1..{_MAX_SLICE_SIZE})",
            },
        )
    if size == 0:
        return 0, _json_err(
            400,
            {
                "error": "size must be positive",
                "detail": f"size {raw_size!r} requests an empty slice; "
                f"expected 1..{_MAX_SLICE_SIZE}",
            },
        )
    return size, None


def _revalidate_headers(etag: str | None) -> dict[str, str]:
    """Cache headers for a revalidating binary-slice response."""
    headers = {"Cache_Control": CACHE_REVALIDATE}
    if etag is not None:
        headers["ETag"] = etag
    return headers


@app.get("/api/targets/<target>/functions")
def handle_api_functions_list(target: str) -> bytes | Any:
    """Paginated function listing with optional filters."""
    target = path_param(target)
    status_filter = query_param("status").strip() or None
    if status_filter is not None and status_filter not in _FUNCTION_STATUSES:
        # Same contract as /asm's ?format=: an enum the server does not have is
        # a rejected query, not a silent empty page.  Without it a typo
        # (?status=EXACT vs ?status=exact) answers 200 with total 0, which
        # reads as "this target has no EXACT functions" and costs the caller
        # the whole filter to find out otherwise.
        return _json_err(
            400,
            {
                "error": "invalid status",
                "detail": f"status {status_filter!r} is not a function status; "
                f"expected one of {', '.join(sorted(_FUNCTION_STATUSES))}",
            },
        )
    search = query_param("search").strip() or None
    if search is not None and len(search) > _MAX_SEARCH_CHARS:
        return _json_err(
            400,
            {
                "error": "search query too long",
                "detail": f"max {_MAX_SEARCH_CHARS} characters",
            },
        )
    sort_param = query_param("sort", "va").strip()  # field:dir
    try:
        limit = min(max(int(query_param("limit", "50")), 1), _MAX_BATCH_LOOKUP)
    except ValueError:
        limit = 50
    try:
        # Upper bound keeps a giant ?offset= from overflowing sqlite3's
        # signed-64-bit INTEGER conversion (OverflowError -> raw 500).
        offset = min(max(int(query_param("offset", "0")), 0), _MAX_PAGE_OFFSET)
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
            # Every direction but "desc" — "asc", empty, and anything else —
            # sorts ascending, which is the default.  An unknown sort_field
            # ignores the whole sort_param rather than applying its (possibly
            # tainted) sort_dir.
            sort_dir = "DESC" if sd.lower() == "desc" else "ASC"
    elif sort_param in allowed_sort:
        sort_field = sort_param

    with _target_cursor(target) as c:
        # Base filter: GLOBAL/DATA/VTABLE/STRING marker rows are data, not
        # functions (rebrew ADR 023 widened the legal marker set).
        where = ["target = ?", NOT_DATA_MARKER_SQL]
        params: list[Any] = [target]

        if status_filter:
            where.append("status = ?")
            params.append(status_filter)
        if search:
            # vaStart (hex text) search keeps parity with Potato Mode, which
            # matches hex addresses; CAST(va AS TEXT) alone only matches
            # decimal spellings.
            chain, arity = like_match(["name", "symbol", "CAST(va AS TEXT)", "vaStart"])
            like = _escape_like(search)
            # The folded disjunct covers the two name columns only (the VA
            # columns hold ASCII hex, which LIKE folds correctly) and joins
            # the same OR group, because it is an alternative the ASCII LIKE
            # cannot judge, not a further requirement: ANDed, it would only
            # narrow the result.  Without it a term like "CAFÉ" silently
            # misses "Café_Render" (SQLite folds case for ASCII only) and an
            # NFD spelling misses its NFC twin.
            folded_sql, folded_params = folded_like_clause(["name", "symbol"], search)
            where.append(f"{chain} OR {folded_sql}" if folded_sql else chain)
            params.extend([like] * arity)
            params.extend(folded_params)

        where_sql = " AND ".join(where)

        # SAFETY: where_sql joins whitelisted column fragments with
        # parameterized values; sort_field/sort_dir were whitelisted above.
        #
        # One pinned read snapshot for the COUNT and the page: they are two
        # separate statements, and Python's sqlite3 opens a deferred
        # transaction per statement, so a `rebrew build-db` committing between
        # them served `total` from one build beside a page from the next (the
        # SPA then paginates against a count the rows do not match).  The
        # snapshot is stat'ed BEFORE the BEGIN, so the pinned read is never
        # older than the memo key it is filed under.
        snap = _snapshot_db_mtime()
        with _server.read_snapshot(c):
            total = _function_total(c, target, where_sql, params, snap, status_filter, search)

            c.execute(
                f"SELECT va, name, vaStart, size, status, module, symbol, markerType "
                f"FROM functions WHERE {where_sql} "
                f"ORDER BY {sort_field} {sort_dir} LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
            # SELECT enumerates exactly the response fields; dict(row) carries
            # the same keys, in the same order, as an explicit per-field dict
            # would.
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
    endpoints so the two response shapes cannot drift apart.

    ``similarity`` is passed through as the 0-1 fraction the column stores
    (its CHECK constrains the unit interval), like ``functions.similarity``;
    the percent scaling belongs to the renderers."""
    keys = vr.keys()
    return {
        "verified_at": vr["verified_at"],
        "byte_delta": vr["byte_delta"],
        "diff_lines": vr["diff_lines"],
        "similarity": vr["similarity"],
        "reg_delta": vr["reg_delta"] if "reg_delta" in keys else None,
        "effective_match": bool(vr["effective_match"])
        if "effective_match" in keys and vr["effective_match"] is not None
        else None,
    }


def _batch_request_vas() -> tuple[list[int], Any | None]:
    """Read + validate the POST /functions body into deduped VA ints.

    Returns ``(unique_vas, None)`` on success, ``([], error_response)`` when
    the body violates the contract: a bounded read (the whole body is parsed
    before the 500-VA cap applies, and with --allow-remote the endpoint is
    reachable off-loopback), a JSON object
    with a non-empty "vas" array capped at _MAX_BATCH_LOOKUP, and entries
    that are integers or hex strings (base-16 with or without 0x prefix,
    matching rebrew's parse_va — bare hex like "10001000" is valid here).

    This is the only base-16-only spelling: GET /functions/<va> and /asm run
    rebrew's parse_va_candidates, which reads an all-digit string as decimal
    first, so the same digits name different VAs in the two endpoints.
    """
    media_type = _header("Content-Type", "").split(";", 1)[0].strip().lower()
    # A missing Content-Type is not a refusal: non-browser clients and the
    # WSGI test harness may omit it, and the body is still parsed below.  A
    # declared type that is not JSON is a 415 — the bytes were never going to
    # be read as this endpoint's format, and "Body must be a JSON object"
    # would blame the payload for a header the client set wrongly.
    if media_type and media_type != _JSON_MEDIA_TYPE and not media_type.endswith(_JSON_SUFFIX):
        return [], _json_err(
            415,
            {
                "error": "Unsupported Media Type",
                "detail": f"Content-Type {media_type!r} is not supported; "
                f"expected {_JSON_MEDIA_TYPE}",
            },
        )
    try:
        raw = request.body.read(_MAX_BATCH_BODY_BYTES + 1)
    except (OSError, ValueError) as exc:
        # A read that fails is not an empty body: it is a client that hung up
        # or a stream that broke mid-transfer, and reporting it as "Body must
        # be a JSON object" blames the payload for a transport failure the
        # caller has to be able to see.
        _log.warning(
            "Reading the batch request body failed: %s: %s",
            type(exc).__name__,
            exc,
        )
        return [], _json_err(
            400,
            {
                "error": "Could not read request body",
                "detail": f"the body stream failed before it was received "
                f"({type(exc).__name__}); resend it with a Content-Length",
            },
        )
    if len(raw) > _MAX_BATCH_BODY_BYTES:
        return [], _json_err(
            413,
            {
                "error": "Request body too large",
                "detail": f"expected a JSON body under {_MAX_BATCH_BODY_BYTES // 1024} KiB",
            },
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, dict):
        return [], _json_err(
            400,
            {
                "error": "Body must be a JSON object",
                "detail": 'expected {"vas": ["0x10001000", ...]}',
            },
        )
    vas = payload.get("vas")
    if not isinstance(vas, list):
        return [], _json_err(
            400,
            {
                "error": "vas must be an array",
                "detail": 'expected {"vas": ["0x10001000", ...]}',
            },
        )
    if not vas:
        return [], _json_err(400, {"error": "vas must not be empty"})
    if len(vas) > _MAX_BATCH_LOOKUP:
        return [], _json_err(
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
            return [], invalid_va(entry, "VAs must be hex strings or integers")
        if isinstance(entry, int):
            if entry < 0:
                return [], invalid_va(entry, "VAs must be non-negative")
            if entry > VA_MAX:
                return [], invalid_va(entry, f"VA out of range (max 0x{VA_MAX:x})")
            va_ints.append(entry)
        elif isinstance(entry, str):
            try:
                s = entry.strip()
                # Strip an optional 0x/0X prefix before the base-16 parse, so
                # "0x1000" and bare "10001000" both land on the same int.
                if s.lower().startswith("0x"):
                    s = s[2:]
                if not s:
                    raise ValueError("empty VA")
                parsed_va = int(s, 16)
                if parsed_va < 0:
                    raise ValueError("negative VA")
                if parsed_va > VA_MAX:
                    raise ValueError("VA exceeds 64 bits")
                va_ints.append(parsed_va)
            except ValueError:
                return [], invalid_va(
                    entry, f"unparseable VA {entry!r}; expected hex like 0x10001000"
                )
        else:
            return [], invalid_va(entry, "VAs must be hex strings or integers")

    # Preserve input order; duplicate VAs collapse to a single result.
    return list(dict.fromkeys(va_ints)), None


@app.post("/api/targets/<target>/functions")
def handle_api_functions_batch(target: str) -> bytes | Any:
    """Batch function/global lookup by VA list.

    Body: ``{"vas": ["0x10001000", ...]}`` (hex strings or integers).  Returns
    a JSON array of function/global detail objects in input order — the same
    shape as ``GET /functions/<va>``, including the ``last_verify`` attachment.
    VAs with no match are omitted from the response (not an error).
    """
    target = path_param(target)
    unique_vas, err = _batch_request_vas()
    if err is not None:
        return err

    with _target_cursor(target) as c:
        results: list[dict[str, Any]] = []

        placeholders = ",".join("?" * len(unique_vas))

        # Three statements over three tables make one answer, so they share one
        # pinned read snapshot (see server.read_snapshot): Python's sqlite3
        # opens a deferred transaction per statement, and a `rebrew build-db`
        # committing between them attached a build's verify_results rows to the
        # next build's function rows — a `last_verify` describing a size and a
        # diff the function payload beside it does not carry.  Same contract as
        # /data, /stats and the function list.
        with _server.read_snapshot(c):
            # SAFETY: placeholders is only "?,?,..." built from the length of the
            # validated VA list; every value reaches the statement parameterized.
            # Functions first (parity with GET /functions/<va>), then globals.
            fn_by_va: dict[int, dict[str, Any]] = {}
            c.execute(
                f"SELECT {_fn_json_sql(c.connection)} FROM functions "
                f"WHERE target = ? AND va IN ({placeholders})",
                [target, *unique_vas],
            )
            for row in c.fetchall():
                fn = json.loads(row[0])
                fn_by_va[fn["va"]] = fn

            if fn_by_va:
                c.execute(
                    f"{_verify_select(c.connection)} FROM verify_results"
                    f" WHERE target = ? AND va IN ({placeholders})",
                    [target, *unique_vas],
                )
                for vr in c.fetchall():
                    fn = fn_by_va.get(vr["va"])
                    if fn is not None:
                        fn["last_verify"] = _last_verify_payload(vr)

            c.execute(
                f"SELECT {_global_json_sql(c.connection)} FROM globals "
                f"WHERE target = ? AND va IN ({placeholders})",
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
    target = path_param(target)
    va = path_param(va)
    with _target_cursor(target) as c:
        # The resolution below is up to seven statements (VA candidates, exact
        # name, folded name — for functions, then for globals) plus the
        # verify_results read, so the whole answer is pinned to ONE read
        # snapshot (see server.read_snapshot).  Unpinned, a `rebrew build-db`
        # committing midway pairs one build's function row with the next
        # build's `last_verify`, which reports a size and a diff for a payload
        # that no longer carries them.
        with _server.read_snapshot(c):
            # One shared resolution order (server._lookup_by_va_or_name): VA
            # candidates first, then the exact name for a name-form lookup.  The
            # stripped spelling is used for both, so "?va=%20Foo" resolves the same
            # way the value is spelled in the database.
            value = va.strip()

            # Functions win over globals (parity with the batch endpoint).
            row = _server._lookup_by_va_or_name(
                c, "functions", _fn_json_sql(c.connection), target, value
            )
            if row:
                fn_json = json.loads(row[0])
                # Attach the last `rebrew verify -o` record for this function.
                c.execute(
                    f"{_verify_one_select(c.connection)} FROM verify_results "
                    f"WHERE target = ? AND va = ?",
                    (target, fn_json["va"]),
                )
                vr = c.fetchone()
                if vr:
                    fn_json["last_verify"] = _last_verify_payload(vr)
                return _json_ok(json.dumps(fn_json).encode("utf-8"), Cache_Control=CACHE_NO_STORE)

            row = _server._lookup_by_va_or_name(
                c, "globals", _global_json_sql(c.connection), target, value
            )
            if row:
                return _json_ok(row[0].encode("utf-8"), Cache_Control=CACHE_NO_STORE)

        return _json_err(
            404,
            {
                "error": "not found",
                "detail": f"no function or global matching {va!r} for target {target!r}",
            },
        )


@app.get("/api/targets/<target>/asm")
def handle_api_asm(target: str) -> bytes | Any:
    target = path_param(target)
    if not HAS_CAPSTONE:
        return _json_err(
            501,
            {
                "error": "capstone not installed",
                "detail": "install the optional extra to enable disassembly: "
                "pip install 'recoverage[capstone]'",
            },
        )

    va_str = query_param("va")
    size_str = query_param("size")
    section = query_param("section", ".text")
    fmt = query_param("format", "text").strip().lower() or "text"
    # An unrecognised ?format= used to fall through to the text
    # representation silently, so a client's typo (?format=JSOM, ?format=json5)
    # answered 200 with a body shape it cannot parse.  Reject the unknown
    # value and name the accepted ones: the caller asked for a representation
    # the server does not have.
    if fmt not in _ASM_FORMATS:
        return _json_err(
            400,
            {
                "error": "invalid format",
                "detail": f"format {query_param('format')!r} is not supported; "
                f"expected one of {', '.join(sorted(_ASM_FORMATS))}",
            },
        )

    if not va_str or not size_str:
        missing = [name for name, value in (("va", va_str), ("size", size_str)) if not value]
        return _json_err(
            400,
            {
                "error": "missing va or size",
                "detail": f"required query parameter(s) absent: {', '.join(missing)} "
                "(e.g. ?va=0x10001000&size=64)",
            },
        )

    raw_va = va_str.strip()
    size, size_err = _slice_size(size_str, "invalid va or size")
    if size_err is not None:
        return size_err

    # Parse va into candidate ints via the shared spelling parser (same
    # convention as GET /functions/<va>).  The SPA builds asm URLs by
    # interpolating JS numbers (the INTEGER section VAs it got from /data),
    # which spell decimal — parsing those digits as base-16 read an address
    # orders of magnitude past every section and rejected each
    # undocumented-block disassembly with "beyond section end".
    va_candidates = parse_va_candidates(raw_va)
    if not va_candidates:
        return _json_err(
            400,
            {
                "error": "invalid va or size",
                "detail": f"va {raw_va!r} is not a hexadecimal address "
                "(with or without 0x, or a decimal address)",
            },
        )

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
                return _json_err(
                    400,
                    {
                        "error": "va is before section start",
                        "detail": f"section {section!r} starts at va 0x{sec_va:x}",
                    },
                )
            return _json_err(
                400,
                {
                    "error": "va is beyond section end",
                    "detail": f"section {section!r} spans va 0x{sec_va:x}"
                    f"..0x{sec_va + sec['size'] - 1:x}",
                },
            )
        file_offset = sec["fileOffset"] + va - sec_va
        if file_offset < 0:
            # Unreachable for a schema-valid sections row (fileOffset carries a
            # CHECK >= 0 and va >= sec_va here) — kept so a foreign DB without
            # that constraint cannot read bytes from before the file.
            return _json_err(
                400,
                {
                    "error": "va is before section start",
                    "detail": f"section {section!r} maps va 0x{va:x} to file offset "
                    f"{file_offset}, before the start of the file",
                },
            )

        # Both response shapes carry the same validator headers; build them once.
        headers_asm = _revalidate_headers(asm_etag)

        # ONE missing-binary verdict for both representations: an absent or
        # unconfigured original binary is the same 404 (/bytes answers the
        # same way), so the format= path must not turn it into a 422 the
        # client reads as "your address is past the end of the section".
        target_data = _load_dll(target)
        if target_data is None:
            return _dll_not_found(target)

        if fmt == "json":
            code_bytes = target_data[file_offset : file_offset + size]
            if len(code_bytes) < size:
                return _json_err(
                    422,
                    {
                        "error": "not enough bytes in DLL",
                        "detail": f"requested {size} bytes, {len(code_bytes)} available",
                    },
                )

            md = get_capstone_md()
            instructions: list[dict[str, Any]] = [
                {
                    "addr": f"0x{insn.address:08x}",
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "size": insn.size,
                }
                for insn in md.disasm(code_bytes, va)
            ]
            return _json_ok(
                {"instructions": instructions},
                **headers_asm,
            )

        asm_text = get_disassembly(va, size, file_offset, target)
        if not asm_text:
            return _json_err(
                422,
                {
                    "error": "not enough bytes in DLL",
                    "detail": f"requested {size} bytes starting at va {va_str!r}",
                },
            )

        return _json_ok({"asm": asm_text}, **headers_asm)


@app.get("/api/targets/<target>/sections/<section>/bytes")
def handle_api_bytes(target: str, section: str) -> bytes | Any:
    """Return raw bytes from the original binary for a given section range."""
    target = path_param(target)
    section = path_param(section)
    raw_offset = query_param("offset", "0")
    try:
        req_offset = _parse_byte_count(raw_offset)
        if req_offset < 0:
            return _json_err(
                400,
                {"error": "invalid offset", "detail": f"offset {raw_offset!r} is negative"},
            )
    except (ValueError, TypeError):
        return _json_err(
            400,
            {
                "error": "invalid offset",
                "detail": f"offset {raw_offset!r} is not a byte offset "
                "(decimal, or 0x-prefixed hexadecimal)",
            },
        )
    raw_size = query_param("size", "256")
    req_size, size_err = _slice_size(raw_size, "invalid size")
    if size_err is not None:
        return size_err

    # ETag bound to the WAL-aware DB snapshot + request identity so /bytes
    # revalidates after a rebuild instead of serving year-immutable stale
    # bytes (raw st_mtime alone missed WAL-committed rebuilds).
    bytes_etag = _etag_or_304(_snapshot_db_mtime(), target, section, req_offset, req_size)

    with _target_cursor(target) as c:
        sec = _file_backed_section(c, target, section, "fileOffset", "size")
        if req_offset >= sec["size"]:
            return _json_err(
                400,
                {
                    "error": "offset beyond section bounds",
                    "detail": f"offset {req_offset} is past the end of section "
                    f"{section!r} (size {sec['size']})",
                },
            )
        # Overflow guard: req_offset + req_size exceeding section size would
        # slice past the section's file range.
        if req_offset + req_size > sec["size"]:
            return _json_err(
                400,
                {
                    "error": "offset+size beyond section bounds",
                    "detail": f"offset {req_offset} + size {req_size} exceeds section "
                    f"{section!r} (size {sec['size']}); largest size here is "
                    f"{sec['size'] - req_offset}",
                },
            )
        target_data = _load_dll(target)
        if target_data is None:
            return _dll_not_found(target)

        file_start = sec["fileOffset"] + req_offset
        if file_start < 0:
            # Same guard as /asm: unreachable for a schema-valid sections row
            # (fileOffset carries CHECK >= 0), kept so a foreign DB with a
            # negative offset cannot slice from before the file — Python's
            # negative indexing would silently serve tail-of-binary bytes.
            return _json_err(400, {"error": "offset beyond section bounds"})
        chunk = target_data[file_start : file_start + req_size]

        return _json_ok(
            {
                "target": target,
                "section": section,
                "offset": req_offset,
                "size": len(chunk),
                # Shared canonical hex dump (see server._format_hex_dump);
                # the chunk is already clamped, so dump it whole.
                "hex": _format_hex_dump(chunk, base_offset=req_offset, max_bytes=None),
                "raw": list(chunk),
            },
            **_revalidate_headers(bytes_etag),
        )


@app.post("/api/regen")
def handle_regen() -> bytes | Any:
    """Re-run rebrew catalog + build-db for the project workspace.

    Duplicate execution: a rebuild is convergent, so a second run ends in the
    same state as the first, but it is minutes of work and a second write of
    coverage.db.  Send an ``Idempotency-Key`` header to make a retry cheap:
    the key is remembered once the run completes (see ``_REGEN_KEY_TTL_SECONDS``
    and ``_REGEN_KEY_MAX`` for the retention window) and a later request
    carrying it is answered from the ledger with ``Idempotent-Replay: true``
    instead of re-running.  A run that failed is not recorded, so retrying a
    failure retries for real.  Without the header, every POST re-runs.
    """
    global _regen_last_attempt

    # `or ""` also folds an explicit None environ value into the rejected-by-
    # default path (same clean 403 as a missing REMOTE_ADDR, no TypeError).
    remote = request.environ.get("REMOTE_ADDR") or ""
    if not _peer_is_loopback(remote):
        return _json_err(
            403,
            {
                "error": "Forbidden: localhost only",
                "detail": f"request came from remote address {remote!r}",
            },
        )

    origin = _header("Origin", "")
    if origin:
        # Same-origin against the request's own Host, not "the origin's
        # hostname is loopback": a page served from any OTHER loopback port is
        # a different origin whose operator this gate is meant to exclude, it
        # passes a hostname check, and a browser cannot read the reply, so the
        # rebuild it starts is invisible to the operator who started it.
        if not origin_is_this_dashboard(origin, _header("Host", "")):
            return _json_err(
                403,
                {
                    "error": "Forbidden: cross-origin",
                    "detail": f"origin {origin!r} is not this dashboard",
                },
            )
    else:
        # Origin is absent on every non-browser client (curl, scripts), so its
        # absence alone must stay allowed — but that also lets a cross-site
        # form POST through whenever a proxy or privacy extension strips
        # Origin.  Browsers attach Sec-Fetch-Site to every request they make,
        # and only they ever send "cross-site": treat that as a definitive
        # cross-origin POST and reject it.
        fetch_site = _header("Sec-Fetch-Site", "").strip().lower()
        if fetch_site == "cross-site":
            return _json_err(
                403,
                {
                    "error": "Forbidden: cross-site request",
                    "detail": f"Sec-Fetch-Site: {fetch_site} is not a same-origin regen",
                },
            )

    # Idempotency-Key: a client that retries a regen whose response it never
    # saw re-sends the same request.  A key that already completed is answered
    # from the ledger here, BEFORE the cooldown below, because the retry lands
    # seconds after the first run — inside the cooldown window, where the
    # throttle would 429 the very request it is meant to dedup.
    key = request.headers.get("Idempotency-Key", "").strip()
    if key and not _REGEN_KEY_RE.fullmatch(key):
        return _json_err(
            400,
            {
                "error": "Bad request: malformed Idempotency-Key",
                "detail": f"expected 1-{_REGEN_KEY_MAX} characters of [A-Za-z0-9._:-]",
            },
        )
    if key and _regen_replayed(key):
        _log.info("Regen %s already completed — answering the retry without re-running", key)
        return _json_ok({"ok": True}, Idempotent_Replay="true")

    # Server-side cooldown + serialization: the cooldown check and the regen
    # run must be atomic — two concurrent POSTs could otherwise both pass the
    # check and run catalog/build-db in parallel, tearing the data_*.json /
    # coverage.db (TOCTOU).  Non-blocking acquire: a second POST while a regen
    # runs gets an immediate 429 instead of blocking on the lock for the whole
    # run.
    if not _REGEN_LOCK.acquire(blocking=False):
        _metrics.REGEN.reject()
        return _json_err(
            429,
            {
                "error": "Rate limited: regeneration already running",
                "detail": "a catalog/build-db run is in progress",
                "retry_after": _REGEN_COOLDOWN_SECONDS,
            },
            Retry_After=str(int(_REGEN_COOLDOWN_SECONDS)),
        )
    try:
        now = clock.monotonic()
        since = math.inf if _regen_last_attempt is None else now - _regen_last_attempt
        if since < _REGEN_COOLDOWN_SECONDS:
            remaining = _REGEN_COOLDOWN_SECONDS - since
            _metrics.REGEN.reject()
            return _json_err(
                429,
                {
                    "error": "Rate limited: wait before regenerating again",
                    "detail": f"retry after {remaining:.1f}s",
                    "retry_after": round(remaining, 1),
                },
                # The auth throttle sends the same header, so a client can read
                # one Retry-After for every 429 the server emits.
                Retry_After=str(math.ceil(remaining)),
            )
        _regen_last_attempt = now
        result = _do_regen(remote)
        # _do_regen answers the success body as bytes and a mapped failure as
        # an HTTPResponse.  Only a completed run is recorded, so a client that
        # retries a failure gets a real second attempt.
        if key and isinstance(result, bytes):
            _record_completed_key(key)
        return result
    finally:
        _REGEN_LOCK.release()


def _do_regen(remote: str) -> bytes | Any:
    """Run catalog + build-db in-process. Caller holds _REGEN_LOCK."""
    # Clear derived caches before AND after: the pre-run clears matter while
    # the regen runs; the resolved-target / index caches get repopulated from
    # the OLD db the moment anything queries them, and with no SSE client
    # connected the watcher would never re-invalidate them (curl-only regen ->
    # stale target dropdown).
    _clear_derived_caches()

    root = _project_dir()
    _log.info("Regen started from %s", remote)
    started_at = clock.monotonic()
    _metrics.REGEN.start()
    try:
        run_regen(root)
    except typer.Exit as e:
        # rebrew's error_exit reports the failure itself and raises
        # typer.Exit — click's Exit, a RuntimeError, not SystemExit.  Map it
        # to the JSON 500 contract instead of letting it escape as a traceback.
        _regen_failed(started_at, "rebrew exited with status %s", e.exit_code)
        return _json_err(
            500,
            {
                "error": "Regen failed",
                "detail": f"rebrew exited with status {e.exit_code}",
            },
        )
    except Exception as e:
        # A rebrew exception, an import error, a filesystem error: keep the
        # JSON error contract instead of an HTML 500.  The class name reaches
        # the body and the message does not — a rebrew or OSError message
        # quotes absolute paths from the project tree.
        _regen_failed(started_at, "%s: %s", type(e).__name__, e)
        return _json_err(
            500,
            {
                "error": "Regen failed",
                "detail": f"{type(e).__name__} — the server log has the full cause",
            },
        )
    _clear_derived_caches()
    elapsed = _elapsed_s(started_at)
    _metrics.REGEN.finish(True, elapsed * 1000.0)
    _log.info("Regen completed successfully in %.1fs", elapsed)
    return _json_ok({"ok": True})


def _elapsed_s(started_at: float) -> float:
    """Seconds since *started_at* on the injectable clock."""
    return clock.monotonic() - started_at


def _regen_failed(started_at: float, reason: str, *args: object) -> None:
    """Log a failed run with its duration and close out its counters.

    Every failure path runs this, so the elapsed time is read once and lands
    in the same place on each: a rebuild that dies after two seconds and one
    that dies after two hundred are told apart by the line, not by the clock.
    """
    elapsed = _elapsed_s(started_at)
    _log.error("Regen failed after %.1fs: " + reason, elapsed, *args)
    _metrics.REGEN.finish(False, elapsed * 1000.0)
