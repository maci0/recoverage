"""API routes for the recoverage dashboard.

``/api/*``: the coverage reads the SPA and Potato Mode are built from, the
health probe, the SSE rebuild broadcast and the regen endpoint.  Routes mount on
``recoverage.server.app`` at import time and share the kernel there (snapshot
access, ETags, auth and the JSON error envelope); nothing in this module is a
cross-route edge, and the one sibling wiring it needs — dropping Potato Mode's
grid memo on a rebuild — is registered through :func:`register_cache_invalidator`
by the composition root.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import queue
import re
import threading
from collections.abc import Callable, Generator, Mapping, Sequence
from heapq import nlargest, nsmallest
from pathlib import Path
from typing import Any

from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError, Function, Global
from rebrew.workspace import VA_MAX, parse_va_candidates
from rebrew.workspace.status import COVERAGE_DB_STATUSES

from recoverage import __version__, clock
from recoverage import metrics as _metrics
from recoverage import server as _server
from recoverage._paths import _db_path
from recoverage.disasm import (
    capstone_unavailable_reason,
    clear_disassembly_cache,
    disassembly_available,
    get_capstone_md,
    get_disassembly,
)
from recoverage.regen import RegenBusyError, RegenDbMismatchError, RegenError, run_regen
from recoverage.server import (
    CACHE_NO_STORE,
    CACHE_REVALIDATE,
    DLL_DATA,
    DLL_LOCK,
    HAS_PYGMENTS,
    HTTPResponse,
    _best_encoding,
    _etag_or_304,
    _format_hex_dump,
    _get_targets_config,
    _header,
    _json_err,
    _json_ok,
    _json_ok_precompressed,
    _load_dll,
    _peer_is_loopback,
    _project_dir,
    _snapshot_db_mtime,
    _target_filename,
    app,
    clear_target_cache,
    compress_payload,
    config_fingerprint,
    fold_match_folded,
    header_present,
    origin_is_this_dashboard,
    path_param,
    query_param,
    request,
    resolve_targets,
    response,
)

_log = logging.getLogger("recoverage")


# ── Cache invalidation ─────────────────────────────────────────────

#: Invalidators for caches this module does not own.  ``_clear_derived_caches``
#: is the one entry point every rebuild path calls, but a sibling route module's
#: state is that module's to drop, and importing it here would be a
#: route-to-route edge: the two sit at the SAME level, so the level table in
#: ``tests/test_import_graph.py`` cannot see it and the graph ``webapp``
#: documents would be prose rather than structure.  The composition root
#: registers each one instead (see :func:`register_cache_invalidator`).
_EXTRA_INVALIDATORS: list[Callable[[], None]] = []


def register_cache_invalidator(invalidate: Callable[[], None]) -> None:
    """Run *invalidate* inside :func:`_clear_derived_caches`.

    Called by ``recoverage.webapp`` at import time, which is the one place
    that already imports every route module to mount its routes: the wiring
    lands beside the mounting, not in a consumer of it.
    """
    _EXTRA_INVALIDATORS.append(invalidate)


def _clear_derived_caches() -> None:
    """Drop every cache derived from the coverage documents or the binaries.

    ONE invalidation entry point, shared by the SSE ``db-updated`` broadcast
    and both regen paths (in-app POST /api/regen): resolved targets + TOML
    config, memoized /data payloads (including the SPA search index they
    carry), Potato cells, DLL bytes, and cached disassembly must all go
    together, or one endpoint serves post-rebuild data while another is
    still stale.

    The SPA shell cache (ui.CACHED_INDEX_PAYLOAD) is deliberately NOT
    invalidated here: it is built solely from static package assets and has
    no dependence on the coverage documents.  Clearing it would make
    the next / request re-read the assets, re-minify, and redo the three
    full-strength budget compressions under INDEX_LOCK for zero staleness
    benefit.
    """
    clear_target_cache()
    _clear_data_cache()
    _clear_stats_cache()
    _clear_list_total_cache()
    for invalidate in _EXTRA_INVALIDATORS:
        invalidate()
    # Disassembly/DLL bytes reflect the original binary and section layout,
    # both of which change with a rebuild.
    with DLL_LOCK:
        DLL_DATA.clear()
    clear_disassembly_cache()


def _clear_derived_caches_logged(where: str) -> None:
    """:func:`_clear_derived_caches`, reporting rather than propagating.

    Callers are the ``db-updated`` broadcast and the two ends of a regen, the
    last of which may run inside a ``finally``.  A failed invalidation is the
    worst outcome here: clients are told the database changed and the server
    keeps serving payloads derived from the old one, and an exception raised
    out of a ``finally`` would replace the regen failure the operator needed
    to see with a cache error they cannot act on.
    """
    try:
        _clear_derived_caches()
    except Exception:
        _log.warning(
            "Cache invalidation %s failed — derived data may be stale", where, exc_info=True
        )


# Server-side regen cooldown (seconds): the UI throttles Regenerate clicks, but
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
# work plus a second write of the coverage documents for an identical result.
#
# Key -> monotonic completion time.  Only completed runs are recorded, so a
# run that failed retries for real, and only the outcome is stored: the
# success body is a constant, and rebuilding it per request keeps the
# response's Content-Encoding matched to that request's Accept-Encoding.
# Bounded on both axes so the ledger cannot grow without limit: a key only has
# to outlive the client's retry horizon, and the count cap keeps a client
# that mints a fresh key per attempt from pinning memory.
_REGEN_KEY_TTL_SECONDS = 600.0
#: The entry cap is a memory backstop, never the binding retention rule: the
#: cooldown admits at most _REGEN_KEY_TTL_SECONDS / _REGEN_COOLDOWN_SECONDS + 1
#: = 121 completions inside any single retention window, so 128 slots always fit
#: them all.  A tighter cap silently shortened the documented window below: a
#: client regenerating more often than the cap held slots lost an unexpired key
#: and paid a second pipeline run for a retry the ledger was meant to absorb.
_REGEN_LEDGER_MAX_ENTRIES = 128
#: Longest Idempotency-Key this server accepts, in characters.  Separate from
#: the entry cap above: both happen to be 128, and one name for both had the
#: count cap quoted in the client's "expected 1-128 characters" error.
_REGEN_KEY_MAX_CHARS = 128
# A key is an opaque client nonce; anything outside this set is a client bug
# or an attempt to fill the ledger with junk, and is rejected rather than
# stored.
_REGEN_KEY_RE = re.compile(rf"[A-Za-z0-9._:-]{{1,{_REGEN_KEY_MAX_CHARS}}}")
_REGEN_COMPLETED_KEYS: dict[str, float] = {}
_REGEN_COMPLETED_KEYS_LOCK = threading.Lock()

# The IN-FLIGHT half of the same key space.  A key whose run is still going is
# a retry that arrived before its answer existed, which is the common case: a
# regen runs for minutes while the proxy or the browser gives up long before
# that, so the client's re-send lands while the first run still holds the lock.
# The 429 the lock gives is true (this server is busy) and useless (it reads as
# "your regenerate failed", and the reader's next click mints a NEW key and
# pays for a second full pipeline), so a key that matches the run in flight is
# answered with that run's own state instead of a refusal.
#
# Key -> monotonic start.  Bounded by the same count cap as the completed
# ledger and past the same retention window, so it cannot grow without limit: a
# marker abandoned by a run that died with the process expires on its own and
# the key is free again.  That expiry can never let two pipelines run, because
# _REGEN_LOCK (not this dict) is what serializes the runs.
_REGEN_ACTIVE_KEYS: dict[str, float] = {}


def _prune_expired(ledger: dict[str, float], now: float) -> None:
    """Drop *ledger* entries past the retention window. Caller holds the lock."""
    for key, stamp in list(ledger.items()):
        if now - stamp >= _REGEN_KEY_TTL_SECONDS:
            del ledger[key]


def _regen_in_progress(key: str) -> bool:
    """True when *key* is the run happening right now."""
    now = clock.monotonic()
    with _REGEN_COMPLETED_KEYS_LOCK:
        _prune_expired(_REGEN_ACTIVE_KEYS, now)
        return key in _REGEN_ACTIVE_KEYS


def _record_active_key(key: str) -> None:
    """Remember that *key*'s regen is running; cleared when the run ends."""
    now = clock.monotonic()
    with _REGEN_COMPLETED_KEYS_LOCK:
        _prune_expired(_REGEN_ACTIVE_KEYS, now)
        _REGEN_ACTIVE_KEYS.pop(key, None)
        _server._evict_oldest(_REGEN_ACTIVE_KEYS, _REGEN_LEDGER_MAX_ENTRIES)
        _REGEN_ACTIVE_KEYS[key] = now


def _clear_active_key(key: str) -> None:
    """Forget a run that has ended, completed or failed."""
    with _REGEN_COMPLETED_KEYS_LOCK:
        _REGEN_ACTIVE_KEYS.pop(key, None)


def _regen_replayed(key: str) -> bool:
    """True when *key* already completed a regen inside the retention window."""
    now = clock.monotonic()
    with _REGEN_COMPLETED_KEYS_LOCK:
        _prune_expired(_REGEN_COMPLETED_KEYS, now)
        return key in _REGEN_COMPLETED_KEYS


def _regen_replay_response(key: str) -> bytes:
    """The answer a retry of an already-completed *key* gets.

    One function because the check runs twice, before and after the lock is
    taken, and a duplicate that reached the second read (below) must get the
    same body and the same log line as one that reached the first.
    """
    _log.info("Regen %s already completed — answering the retry without re-running", key)
    return _json_ok({"ok": True}, Idempotent_Replay="true")


def _regen_in_progress_response(key: str) -> HTTPResponse:
    """The answer a retry of the run already in flight for *key* gets.

    One function because the check runs twice: once before the lock is taken,
    and once on the far side of a failed acquire, where the duplicate that
    raced its own predecessor arrives.  A key in the in-flight map means a run
    for that key holds the lock, so the 202 cannot be a lie about work that is
    not under way.
    """
    _log.info("Regen %s is still running — answering the retry as in progress", key)
    return _server._json_accepted(
        {"ok": True, "in_progress": True},
        Idempotent_Replay="in-progress",
        Retry_After=str(int(_REGEN_COOLDOWN_SECONDS)),
    )


def _record_completed_key(key: str) -> None:
    """Remember that *key*'s regen completed, so its retry is answered, not re-run."""
    now = clock.monotonic()
    with _REGEN_COMPLETED_KEYS_LOCK:
        _prune_expired(_REGEN_COMPLETED_KEYS, now)
        # Re-insert (rather than refresh in place) so the eviction order stays
        # completion order.
        _REGEN_COMPLETED_KEYS.pop(key, None)
        _server._evict_oldest(_REGEN_COMPLETED_KEYS, _REGEN_LEDGER_MAX_ENTRIES)
        _REGEN_COMPLETED_KEYS[key] = now


# Memoized /api/targets/<t>/data payloads: the endpoint materializes every
# cell for the target plus every function/global for the search index on each
# cache-missing request.
# The ETag gives 304s to repeat clients, but N fresh clients each rebuilt
# the multi-MB payload.  Keyed by the document snapshot + target + section so
# a rebuild (which the SSE watcher detects and funnels through
# clear_target_cache) invalidates it.
# Each value maps encoding name ("zstd"/"br"/"gzip"/"" for identity) to the
# FINAL response body for that encoding, plus "raw" (the uncompressed JSON)
# so a first request with an unseen Accept-Encoding can mint its variant
# without re-serializing.  Compressing the multi-MB payload on every memo hit
# dominated repeat-request cost (~30-70 ms CPU).
#
# The section filter and the search-index opt-out are both part of the key, so
# the two payload shapes never share a memo entry (and, further down, a
# validator) even though they are built from the same snapshot.
_DataKey = tuple[tuple[int, int] | None, str, str | None, bool]
_DATA_CACHE: dict[_DataKey, dict[str, bytes]] = {}
_DATA_CACHE_LOCK = threading.Lock()
# Upper bound on retained payloads: a long-running server across many rebuilds
# must not accumulate one multi-MB payload per fingerprint forever.
_DATA_CACHE_MAX = 8
# Single-flight build coordination: fingerprint -> claim held while one thread
# serializes that key.  A rebuild broadcast clears the memo and wakes every
# connected SSE client, which all refetch /data at once; without this, each of
# those cold misses materializes its own multi-MB payload.
#
# A claim is the Event a follower waits on plus the monotonic instant it stops
# being answerable, because a leader that is KILLED between checkout and its
# finally never sets the Event and never releases the claim.  Duplicate
# execution safety for that leader is the whole reason the deadline is in the
# value: an unbounded claim is one that outlives its owner, so a later request
# for the same key parks on an Event nobody will ever set, pays the full wait
# again, and the entry itself is never released.  The deadline bounds that
# (a claim past it is dropped on the next checkout, whether or not a follower
# ever arrives for that key), and the follower that times out on it reclaims
# the claim instead of leaving the dead owner registered.
_DataClaim = tuple[threading.Event, float]
_DATA_CACHE_BUILDING: dict[_DataKey, _DataClaim] = {}
#: How long a follower waits on the leader's build Event, and how long a claim
#: stays answerable after it was taken.  The leader's finally always sets the
#: Event and releases the claim, so this only bounds the case where it does not
#: (a thread killed mid-build).  Comfortably longer than a cold /data build on
#: a large target, so a follower that gives up here has genuinely lost its
#: leader, and a live leader is never mistaken for a dead one.
_DATA_CACHE_BUILD_WAIT_SECONDS = 30.0
#: How long the follower parks between two reads of the clock that ends its
#: wait (see :func:`_await_build_event`).  It bounds nothing about the leader:
#: the wait still ends the instant the leader's finally sets the Event, so this
#: only decides how late a reclaim of a DEAD leader's claim lands past its
#: deadline, and a live build wakes its followers on the set, not on the slice.
_DATA_BUILD_WAIT_SLICE_SECONDS = 0.05


def _await_build_event(event: threading.Event, deadline: float) -> bool:
    """Wait for the leader's *event*, bounded by *deadline* read from the clock.

    The bound comes from :func:`recoverage.clock.monotonic`, the seam every
    other elapsed-time read in the package uses, so the wait is answerable
    without the wall-clock seconds it used to park for: a test (or a
    simulation driving one clock) reaches the expired-Event branch by advancing
    the clock past *deadline* rather than by shrinking the production constant,
    and a run replayed from its seed waits exactly as long as the first did.

    A patched clock must advance, or a leader that never comes back never ends
    the wait: real time advances on its own and this does not.
    """
    while True:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            return event.is_set()
        if event.wait(timeout=min(remaining, _DATA_BUILD_WAIT_SLICE_SECONDS)):
            return True


def _prune_stale_claims(now: float) -> None:
    """Drop claims whose owner never released them. Caller holds the lock."""
    for key, (_event, expires_at) in list(_DATA_CACHE_BUILDING.items()):
        if now >= expires_at:
            del _DATA_CACHE_BUILDING[key]


def _clear_data_cache() -> None:
    # Deliberately leaves _DATA_CACHE_BUILDING alone: each claim is owned by
    # the thread that took it and is released in that thread's finally, so
    # waiters always wake.  Clearing here could strand a waiter on an Event
    # nobody will ever set.  A waiter that wakes to a cleared memo simply
    # builds the (post-clear) payload itself.  A claim whose owner was killed
    # is the one entry here that no finally will ever release, and that is
    # what _prune_stale_claims reclaims, on its own deadline rather than here.
    with _DATA_CACHE_LOCK:
        _DATA_CACHE.clear()


def _data_cache_checkout(
    key: _DataKey,
) -> tuple[dict[str, bytes] | None, threading.Event | None]:
    """Return ``(memo_entry, owned_event)`` for *key*.

    - Memo hit: ``(<entry>, None)`` — serve it.
    - No entry, no live claim: ``(None, <event>)`` — caller builds and MUST pass
      *owned_event* to :func:`_data_cache_build_done` in a finally.
    - Build already running: waits for it, then returns whatever the memo
      holds now (None when the leader failed or short-circuited with a 404 —
      the caller then builds its own payload).
    - Leader that never came back: the wait expires, the caller takes the claim
      over and builds (the same answer as the failed-leader case above, from a
      claim that is actually released afterwards).
    - ``(None, None)``: a live leader registered between the wait expiring and
      the reclaim. The caller builds beside it, unclaimed.
    """
    now = clock.monotonic()
    with _DATA_CACHE_LOCK:
        # A claim past its deadline belongs to a leader that was killed
        # between checkout and its finally: it never published a payload and
        # never released the claim, so leaving it registered would park every
        # later request for this key on an Event nobody will ever set.  Drop
        # it here, before the lookup below, so the caller below becomes the
        # new leader rather than a second follower of a dead one.
        _prune_stale_claims(now)
        entry = _DATA_CACHE.get(key)
        # Counted inside the same critical section as the read, so the
        # `caches` block in /api/health cannot report more hits than the memo
        # ever served.
        if entry is not None:
            _metrics.CACHES.hit(_metrics.DATA_PAYLOAD_CACHE)
            return entry, None
        _metrics.CACHES.miss(_metrics.DATA_PAYLOAD_CACHE)
        claim = _DATA_CACHE_BUILDING.get(key)
        if claim is None:
            event = threading.Event()
            _DATA_CACHE_BUILDING[key] = (event, now + _DATA_CACHE_BUILD_WAIT_SECONDS)
            return None, event
        event = claim[0]
    # Follower path (outside the lock): the leader's finally always sets the
    # event — success, error, or 404 short-circuit alike — and only then
    # releases the claim, so a set event is the leader's own answer and
    # whatever it published (or did not) is what this request reads.
    released = _await_build_event(event, now + _DATA_CACHE_BUILD_WAIT_SECONDS)
    with _DATA_CACHE_LOCK:
        if released:
            # A follower the leader's build answered: the memo miss above was
            # the checkout, not the answer, so the published entry counts as
            # the hit it is.
            entry = _DATA_CACHE.get(key)
            if entry is not None:
                _metrics.CACHES.hit(_metrics.DATA_PAYLOAD_CACHE)
            return entry, None
        # The wait expired on an Event nobody set.  Reclaim the claim rather
        # than build beside it: a duplicate build is the accepted cost here,
        # but leaving the dead leader registered is not — every later request
        # for this key would pay the same full wait again, and the entry would
        # outlive the process.  The `is event` guard means a leader that
        # released (or was superseded by an earlier reclaim) is left alone —
        # and the same guard
        # has to decide the install.  A claim registered in between (an
        # earlier follower already reclaimed and a later request became the
        # leader) belongs to a LIVE builder, and overwriting it would
        # disarm its single-flight: its _data_cache_build_done identity check
        # would no longer match, so the claim would never be released and a
        # third request would start a second build beside it.  Building
        # without a claim is the accepted duplicate cost; displacing a live
        # leader is not.
        current = _DATA_CACHE_BUILDING.get(key)
        if current is not None and current[0] is not event:
            return None, None
        _DATA_CACHE_BUILDING.pop(key, None)
        # The claim outlived the thread that took it, so a leader was killed
        # between checkout and its finally.  Reclaiming recovers THIS request
        # and leaves nothing behind, which is exactly why the fault is silent:
        # no error is raised, no line is written, and the only trace is a
        # follower that waited the full window and built anyway — which reads
        # as a slow dashboard rather than as a dead thread.  One line per
        # reclaim, with the key that identifies what the killed build was
        # serving.  The values are caller-chosen, so they ride as JSON-encoded
        # fields rather than in the prose.
        _log.warning(
            "Reclaimed a /data build claim for %r after %.0fs: the leader never "
            "released it, so this request is rebuilding the payload",
            _server._log_safe(key[1]),
            _DATA_CACHE_BUILD_WAIT_SECONDS,
            extra={
                _server.LOG_FIELDS_ATTR: {
                    "event": "data_claim_reclaimed",
                    "target": key[1],
                    "section": key[2],
                    "wait_s": _DATA_CACHE_BUILD_WAIT_SECONDS,
                }
            },
        )
        _metrics.REQUESTS.note_stale_claim()
        reclaimed = threading.Event()
        _DATA_CACHE_BUILDING[key] = (
            reclaimed,
            clock.monotonic() + _DATA_CACHE_BUILD_WAIT_SECONDS,
        )
        return None, reclaimed


def _data_cache_build_done(key: _DataKey, event: threading.Event) -> None:
    """Release followers of *key* (owner only — see :func:`_data_cache_checkout`)."""
    with _DATA_CACHE_LOCK:
        current = _DATA_CACHE_BUILDING.get(key)
        if current is not None and current[0] is event:
            del _DATA_CACHE_BUILDING[key]
    # Set after the claim is released, not before: a follower that wakes on a
    # set event takes the memo as this build's answer, so the claim must
    # already be gone by then or a second checkout would hand the same key to
    # two builders.  Identity-checked above, so a leader whose claim a
    # reclaiming follower already took over cannot delete the new owner's.
    event.set()


def _cache_data_insert(
    key: _DataKey,
    raw: bytes,
    encoding: str,
    body: bytes,
) -> None:
    """Insert a memoized payload (raw + this request's encoded form), evicting
    the oldest entries past the cap.

    *key*'s snapshot was taken before the payload was built, so a rebuild
    that committed in between leaves the PRE-rebuild rows under a key naming
    the POST-rebuild fingerprint.  Publishing that payload poisons the memo:
    the db-updated broadcast has already cleared the cache and nothing clears
    it again until the next rebuild, so the refetch herd behind the broadcast
    would be served the data it was woken to replace.  Re-stat the documents
    and drop the write when the watermark moved (same contract as
    ``potato._load_grid_cells``).
    """
    if key[0] is not None and _snapshot_db_mtime() != key[0]:
        return
    with _DATA_CACHE_LOCK:
        _server._evict_oldest(_DATA_CACHE, _DATA_CACHE_MAX)
        entry = _DATA_CACHE.setdefault(key, {})
        entry["raw"] = raw
        entry[encoding] = body


# Memoized /stats results, keyed by the document snapshot + target.
# handle_api_stats re-walks every cell of the target on every miss; a polling
# consumer must not re-pay that walk while the documents are unchanged.  Same
# self-invalidation contract as the /data payload memo: a rebuild changes the
# snapshot, so stale entries miss.  Lives HERE, not in server._section_stats,
# because only this module knows which documents the answer was built from.
_STATS_CACHE: dict[tuple[tuple[int, int] | None, str], dict[str, Any]] = {}
_STATS_CACHE_LOCK = threading.Lock()
_STATS_CACHE_MAX = 16


def _clear_stats_cache() -> None:
    """Drop memoized /stats results (called on DB rebuild)."""
    with _STATS_CACHE_LOCK:
        _STATS_CACHE.clear()


# Memoized `total` for the paginated function list.  The count is a pass over
# every row of the target's functions, and the SPA re-requests the list on
# every filter, status and page change, paying it again for a number the
# documents have not changed.  Keyed by the same snapshot as the other memos
# plus the exact filter triple the count depends on, so a rebuild or a
# different filter misses; capped like the rest.
_LIST_TOTAL_CACHE: dict[tuple[tuple[int, int] | None, str, str | None, str | None], int] = {}
_LIST_TOTAL_CACHE_LOCK = threading.Lock()
_LIST_TOTAL_CACHE_MAX = 64


def _clear_list_total_cache() -> None:
    """Drop memoized function-list totals (called on DB rebuild)."""
    with _LIST_TOTAL_CACHE_LOCK:
        _LIST_TOTAL_CACHE.clear()


def _function_total(
    snap_fingerprint: tuple[int, int] | None,
    target: str,
    status_filter: str | None,
    search: str | None,
    rows: Sequence[Function],
) -> int:
    """*rows* count, memoized per snapshot.

    The count is served from the memo only when the filter and the coverage
    directory both match; otherwise it is taken and the memo repopulated.  A
    None fingerprint (no coverage document) never memoizes — the endpoint is
    about to 503 and a value derived from that state must not outlive it.

    *rows* is the caller's own ``_filtered_functions`` result for the same
    filter.  The list endpoint needs the count and the page from the same pass
    (that is what pins the count to the rows it paginates), so it filters once
    and hands the result here rather than having the count re-derive a second
    full list it would throw away.
    """
    key: tuple[tuple[int, int] | None, str, str | None, str | None] | None = (
        (snap_fingerprint, target, status_filter, search) if snap_fingerprint is not None else None
    )
    if key is not None:
        with _LIST_TOTAL_CACHE_LOCK:
            cached = _LIST_TOTAL_CACHE.get(key)
        if cached is not None:
            return cached
    total = len(rows)
    # The watermark re-check every other coverage-derived memo publishes
    # through: a rebuild that committed after the caller took its token moved
    # the fingerprint, so these rows were not read from the build the key
    # names and nothing files them.
    if key is not None and _snapshot_db_mtime() == snap_fingerprint:
        with _LIST_TOTAL_CACHE_LOCK:
            _server._evict_oldest(_LIST_TOTAL_CACHE, _LIST_TOTAL_CACHE_MAX)
            _LIST_TOTAL_CACHE[key] = total
    return total


#: The columns the list endpoint can sort by: the package's one vocabulary
#: (`server.FUNCTION_SORT_COLUMNS`), which this endpoint takes whole, since it
#: carries every one of them.  A field outside it is a rejected query, like the
#: `?status=`, `?format=` and `?index=` values the sibling endpoints refuse.
_ALLOWED_SORT = _server.FUNCTION_SORT_COLUMNS

#: The directions `?sort=field:dir` accepts, empty included: a bare field
#: carries none, and that is the ascending default rather than a bad value.
_SORT_DIRECTIONS = frozenset({"", "asc", "desc"})

#: What the refusal names, so the answer tells a caller which spellings work
#: instead of only that the one they sent does not.
_SORT_SYNTAX_HINT = (
    f"{', '.join(sorted(_ALLOWED_SORT))}, each optionally suffixed with ':asc' or ':desc'"
)


def _filtered_functions(
    functions: Sequence[Function],
    status_filter: str | None,
    search: str | None,
    folded: Mapping[int, tuple[str, str, str]] | None = None,
) -> list[Function]:
    """The functions the list endpoint would serve, before paging.

    The data-marker rows (server.DATA_MARKER_TYPES) are data, not functions
    (rebrew ADR 023 widened the legal marker set), so they are dropped here for
    the count, the page and the by-status filter alike.

    Search folds BOTH sides through :func:`server.fold_match`, over the same
    four columns the SQL matched: the name, the symbol, the decimal VA text and
    the ``vaStart`` hex spelling Potato Mode matches.  The old statement needed
    two disjuncts — SQLite's ASCII-only ``LIKE`` plus an ``rc_fold`` arm — only
    because the comparison happened in SQL; one folding in Python matches what
    the SPA highlights, which is the guarantee the fuzz campaigns assert.

    *folded* is :func:`server.folded_row_columns` for *functions*, the three
    name columns already folded for this snapshot.  A search re-folding them
    per row is what the fold is not free for, and the rows do not change while
    the term does, so the caller holding the snapshot passes the table in and
    the loop pays a substring test per column.  It is optional because the
    filter is also callable on a list the snapshot was never shown, and there
    the per-row fold is the only way to the same answer.  The decimal VA
    column is built and folded per row either way, and only when the term can
    hold one (``server.fold_can_match_decimal``).
    """
    rows = [fn for fn in functions if not _server._is_data_marker(fn)]
    if status_filter is not None:
        rows = [fn for fn in rows if fn.status == status_filter]
    if search:
        needle = _server.fold_needle(search)
        # `str(va)` is built and folded per row, so a term holding a character
        # no decimal number can hold skips the arm outright
        # (server.fold_can_match_decimal).
        match_decimal = _server.fold_can_match_decimal(needle)
        if folded is None:
            rows = [
                fn
                for fn in rows
                if fold_match_folded(fn.name, needle)
                or fold_match_folded(fn.symbol, needle)
                or (match_decimal and fold_match_folded(str(fn.va), needle))
                or fold_match_folded(fn.vaStart, needle)
            ]
        else:
            rows = [
                fn
                for fn in rows
                if _any_column_matches(folded[id(fn)], needle)
                or (match_decimal and fold_match_folded(str(fn.va), needle))
            ]
    return rows


def _any_column_matches(columns: tuple[str, str, str], needle: str) -> bool:
    """Whether *needle* occurs in any of the three FOLDED *columns*.

    The same three substring tests :func:`fold_match_folded` runs, against text
    that has been folded once instead of once per row per keystroke.  A NULL
    column folded as the empty string, which no non-empty term matches, so the
    answer is the one the fold-then-test path gives.
    """
    return needle in columns[0] or needle in columns[1] or needle in columns[2]


def _function_page(
    rows: list[Function], sort_field: str, sort_dir: str, offset: int, limit: int
) -> list[Function]:
    """The *offset*..*offset*+*limit* window of *rows* in their sorted order.

    A page is a window on the ORDERED match set, and the window is the only
    part that is served, so the set is selected rather than sorted: ordering
    6000 rows to answer a page of 50 costs the O(n log n) comparisons of the
    whole set on every keystroke, and `heapq` is the documented equivalent of
    ``sorted(rows)[:k]`` (stable, ties in document order) at O(n log k).  The
    key is built for every row either way; only the comparison count falls.

    The `nlargest` arm is the descending half: `nsmallest` has no reverse
    spelling, and reversing the key to select the largest would break the
    ordering on the very column the reader asked to reverse.  A window that
    reaches past the end of the set has nothing to select, and sorts.
    """
    key = _server.function_sort_key(sort_field)
    wanted = offset + limit
    if wanted >= len(rows):
        rows.sort(key=key, reverse=sort_dir == "DESC")
        return rows[offset : offset + limit]
    select = nlargest if sort_dir == "DESC" else nsmallest
    return select(wanted, rows, key=key)[offset:]


def _target_not_found(target: str) -> HTTPResponse:
    """JSON 404 for a target-scoped endpoint referencing an unknown target."""
    return _json_err(
        404,
        {
            "error": "Target not found",
            "detail": f"no such target {target!r}",
        },
    )


def _dll_not_found(target: str) -> HTTPResponse:
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


def _section_not_found(target: str, section: str) -> HTTPResponse:
    """JSON 404 for a target-scoped endpoint referencing an unknown section."""
    return _json_err(
        404,
        {
            "error": f"section {section} not found",
            "detail": f"target {target!r} has no section {section!r}",
        },
    )


def _require_target(target: str, targets: Sequence[Mapping[str, str]]) -> HTTPResponse | None:
    """Return a 404 response if *target* is absent from *targets*, else None.

    *target* is valid when the last build wrote a document for it or when the
    project config declares it (a configured-but-not-yet-built target is still
    addressable).  A coverage directory with nothing readable in it is not
    "unknown target" — :func:`server.resolve_targets` raises for that, and the
    endpoint's own 503 path runs.

    *targets* is the caller's already-resolved list: re-resolving here would
    re-walk the coverage directory, which is a directory scan per document plus
    a hash, on the path of every target-scoped request.
    """
    if any(t.get("id") == target for t in targets):
        return None
    return _target_not_found(target)


@contextlib.contextmanager
def _target_snapshot(target: str) -> Generator[CoverageSnapshot]:
    """Yield *target*'s frozen snapshot with *target* validated.

    ONE shared tail for every /api/targets/<target>/* endpoint: fails the
    request with the standard JSON contract (503 ``db_unavailable`` when the
    coverage directory holds nothing readable, 404 ``not_found`` for an unknown
    target) by raising the HTTPResponse, so handlers are straight-line code
    instead of repeating the read/validate boilerplate.

    The snapshot IS the read pin `server.read_snapshot` used to provide: it is
    frozen, so every field a handler reads comes from one build.
    """
    try:
        resolved = resolve_targets()
    except CoverageTomlError as exc:
        # Logged + detailed by the shared helper — a swallowed reader error
        # here would make a missing or malformed document invisible in the log.
        raise _server._db_unavailable_err(exc) from None
    not_found = _require_target(target, resolved)
    if not_found is not None:
        raise not_found
    yield _server.coverage_for(target)


def _file_backed_section(snap: CoverageSnapshot, section: str) -> dict[str, Any]:
    """Fetch *snapshot*'s *section* row and require the three file-backed ints, else raise.

    ONE shared guard for the endpoints that do pointer arithmetic on a
    section (asm, bytes): an unknown section raises the shared JSON 404,
    and a section with no file backing raises this endpoint family's JSON 422
    contract instead of letting the arithmetic raise TypeError and surface as
    an HTML 500.

    The absence test is any of the three ints the arithmetic below needs: a
    section the catalog could not place in the image has no VA, and a `.bss`
    has no file offset at all, so a section missing any of them has nothing on
    disk to slice and both endpoints answer their JSON 422 contract instead of
    letting the addition raise TypeError into an HTML 500.  The document
    spells an absent value as ``""`` and the reader keeps it as ``None`` — a
    stored 0 is a real offset and is NOT the same answer.
    """
    found = snap.sections.get(section)
    if found is None:
        raise _section_not_found(snap.target, section)
    sec = {
        "va": found.va,
        "size": found.size,
        "fileOffset": found.file_offset,
    }
    if any(not isinstance(value, int) for value in sec.values()):
        raise _json_err(
            422,
            {
                "error": "section has no file backing",
                "detail": f"section {section!r} has no va/size/fileOffset — "
                "raw bytes are only served for file-backed sections",
            },
        )
    return sec


# ── Server-Sent Events (live DB change notifications) ─────────────
#
# A single background watcher thread polls the coverage documents' mtime every
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

#: Connected streams, queue -> peer that opened it.  A MAP, not a set: a
#: dropped frame is only diagnosable if the line names the dashboard it was
#: dropped for, and the peer is known once, where the stream is registered.
#: Membership, ``len`` and the cap all read the same way off a dict.
_SSE_CLIENTS: dict[queue.Queue[bytes], str] = {}
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
    _clear_derived_caches_logged("during db-updated broadcast")
    payload: dict[str, Any] = {
        "event": "db-updated",
        # Basename only — the absolute path leaks the user's home-directory
        # layout to any LAN/browser client (docs/THREAT_MODEL.md).
        "db": {"path": _db_path().name},
        "timestamp": clock.wall_time(),
    }
    if snapshot is not None:
        # Opaque change token over the coverage documents (see
        # _snapshot_db_mtime), NOT an mtime; named so clients cannot misread
        # it as wall-clock data.
        payload["db"]["fingerprint"] = snapshot[0]
        payload["db"]["size_bytes"] = snapshot[1]
    frame = f"event: db-updated\ndata: {json.dumps(payload)}\n\n".encode()
    with _SSE_CLIENTS_LOCK:
        clients = list(_SSE_CLIENTS.items())
    for client, peer in clients:
        try:
            client.put_nowait(frame)
        except queue.Full:
            # A dropped frame is not recoverable for that client: it is the
            # only notice that the documents moved, so the tab goes on
            # rendering the previous build with nothing to say why.  The queue
            # is full because the client stopped reading, which is a wedged
            # stream an operator can act on (the socket deadline reaps it), so
            # the line is a warning rather than a debug breadcrumb.  One per
            # wedged client per rebuild, bounded by _SSE_MAX_CLIENTS.  The peer
            # is on it because without it N wedged streams produce N identical
            # lines and no way to tell which dashboard to go reload.
            _log.warning(
                "SSE client %s queue full (%d frames) — dropping db-updated event; "
                "that dashboard will not refresh until it is reloaded",
                peer,
                _SSE_QUEUE_MAX,
            )


def _db_watcher_loop(stop: threading.Event) -> None:
    """Poll the coverage documents' mtime every few seconds and broadcast changes.

    The first snapshot is the baseline; any later change (including the file
    appearing or disappearing) broadcasts an event.  Runs until ``stop`` is
    set, which also serves as the poll sleep so tests can drive it quickly.

    Each iteration is guarded: this is a daemon thread nobody joins, so an
    unguarded exception would kill live-reload silently for the remaining
    lifetime of the process.  The guard is the WHOLE loop, baseline snapshot
    included: the baseline read sat outside it, so a failure there (a
    coverage directory that cannot be walked raises rather than returning
    None) killed the thread with its traceback going to a stream nobody
    reads.  ``/api/health`` only reports ``watcher_alive: false`` as
    ``degraded`` while a client is connected, so with no SSE client the
    dashboard answered "healthy" with live reload dead for the rest of the
    process.  Both exits name themselves, so a dead poller is one grep away:
    the ``except`` arm logs at exception level and re-raises, and a stop the
    event asked for falls through to the debug line under it.
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


def _db_watcher() -> threading.Thread | None:
    """The watcher thread, or None when none is registered.

    Read under the lock :func:`_ensure_db_watcher` and :func:`_stop_db_watcher`
    both take, so a caller reporting the thread's state reads the reference its
    writers published rather than a bare module global.  The pair
    ``/api/health`` reports (stream count, watcher liveness) is meant to be one
    reading; taking one lock for the count and racing the global for the thread
    is what let the two describe different moments.
    """
    with _DB_WATCHER_LOCK:
        return _DB_WATCHER_THREAD


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

    def __init__(self, client_queue: queue.Queue[bytes], peer: str = "unknown") -> None:
        self._queue = client_queue
        self._peer = peer
        self._gen: Generator[bytes] | None = None
        self._released = False

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        with _SSE_CLIENTS_LOCK:
            _SSE_CLIENTS.pop(self._queue, None)

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
    """SSE stream: emits a db-updated event when the coverage documents change.

    Bottle streams the returned :class:`_SSEStream`.  The watcher thread
    broadcasts to a per-client queue; this route drains it.  Disconnects are
    detected when the stream is closed — the client queue is removed by
    :meth:`_SSEStream.close`, which the server calls on every exit path.
    """
    # Cap concurrent SSE clients: each connection pins a server thread for
    # the life of the stream (minutes/hours), and the connection cap admits
    # them, so this is the tighter of the two bounds.  A LAN client (or a
    # cross-origin EventSource from any webpage a victim visits — no-cors,
    # loopback) could otherwise take a slot each until the wider cap bit too.
    # Read the environ before registering, so the peer that goes in the map is
    # the one every later log line about this stream names.
    peer = _server.peer_label()
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
                    "retry_after": int(_SSE_POLL_INTERVAL_SECONDS),
                },
                # One value in both places: a client that reads the header
                # instead of the body (the auth throttle and /api/regen send
                # the same header) must not be told a different wait than one
                # the JSON states.  An int in both, which is the type every
                # 429's `retry_after` now carries too, so one client reads one
                # JSON type out of the key whichever refusal it hit.
                Retry_After=str(int(_SSE_POLL_INTERVAL_SECONDS)),
            )
        client_queue: queue.Queue[bytes] = queue.Queue(maxsize=_SSE_QUEUE_MAX)
        _SSE_CLIENTS[client_queue] = peer
    # Start the poller on the first registered client; ``serve`` already
    # started it at startup, so this is the idempotent call.  A failed start
    # (e.g. RuntimeError under thread exhaustion) must not leave the queue
    # registered: every leaked slot permanently shrinks the _SSE_MAX_CLIENTS
    # cap toward a standing 503 for /api/events.
    try:
        _ensure_db_watcher()
    except BaseException:
        with _SSE_CLIENTS_LOCK:
            _SSE_CLIENTS.pop(client_queue, None)
        raise

    response.content_type = "text/event-stream"
    response.set_header("Cache-Control", CACHE_NO_STORE)
    response.set_header("X-Accel-Buffering", "no")
    return _SSEStream(client_queue, peer)


#: Last (status, reason) ``/api/health`` reported, so the probe logs a
#: transition rather than one line per poll.  Without it a monitor pointed at
#: the endpoint (an external health check, a shell while-loop) turned a missing
#: coverage into a WARNING per probe for as long as it stayed missing, which
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
    if status != "healthy":
        # Any move INTO a fault, including the first probe of the process,
        # where there is no previous state to have recovered from: the same
        # alert either way.  A healthy first probe is not news.
        _log.warning("Dashboard health degraded: %s", reason)
    elif previous is not None:
        _log.info("Dashboard health recovered: was %s (%s)", previous[0], previous[1])


@app.get("/api/health")
def handle_api_health() -> bytes:
    """Liveness and environment report: status, version, coverage stat, extras, targets.

    status is "degraded" (not an error) when the coverage directory cannot be
    read; db.path is the basename only, never the absolute path.  db.mtime
    is epoch seconds and db.mtime_utc the same instant as an ISO-8601 instant
    (``+00:00``), both read off one conversion of the newest document's mtime
    (``server.mtime_ns_to_utc``) so they cannot disagree; both are absent when
    no document can be stat'ed.

    Every reason the probe found is named in one log line per transition
    (:func:`_log_health_status`), not one line per probe.
    """
    db = _db_path()
    db_info: dict[str, Any] = {"path": db.name, "exists": db.is_dir()}
    reasons: list[str] = []
    # Freshness is the newest mtime across the directory's documents: a rebuild
    # rewrites one document per target, so reading any single one would report a
    # target that did not move.  Every other coverage-freshness surface (ETags,
    # memos, the SSE watcher, Potato Mode's footer) folds the same `mtime_ns`
    # values into its own token.
    # ONE scan answers both the stamp and the sizes: the same list
    # `_newest_mtime_ns` folds, so asking for each walked the coverage
    # directory twice per probe, and a rebuild landing between the two walks
    # let the reported stamp and the reported size come from different builds.
    documents = _server._coverage_file_stats()
    mtime_ns = max((mtime for _name, mtime, _size in documents), default=None)
    if mtime_ns is not None:
        # Seconds since the epoch (UTC) plus the same instant spelled out with
        # an explicit zone, so a client never has to assume the host's TZ.
        # Both come from ONE conversion: a float second cannot hold the
        # nanosecond mtime, so deriving the two independently let the ISO
        # stamp sit up to half a second off the epoch field beside it.
        stamp = _server.mtime_ns_to_utc(mtime_ns)
        db_info["mtime"] = stamp.timestamp()
        db_info["mtime_utc"] = stamp.isoformat()
    # Counted from the built ids rather than the target list, so the health
    # number answers "how many targets did the last build write" and stays
    # narrower than the dropdown: `db_target_ids` omits a target the config
    # declares and no build has written, which `/api/targets` still serves.
    target_count = len(_server.db_target_ids())
    if documents:
        db_info["size_bytes"] = sum(size for _name, _mtime, size in documents)
        if not target_count:
            # A document present but unreadable is the corrupt-coverage case:
            # the reader skipped it (with a warning of its own) and there is
            # nothing to serve.  Reporting only the missing-directory case
            # would call that deployment healthy.
            reasons.append(f"no readable coverage-*.toml in {db}")
    else:
        reasons.append(f"no coverage-*.toml document in {db}")
    streams = _stream_stats()
    if streams["watcher_alive"] is False and streams["clients"] > 0:
        # Connected clients with no poller means live reload is dead while
        # every page still renders: healthy-looking, silently stale.
        reasons.append("the DB watcher is not running while event-stream clients are connected")
    connections = _metrics.CONNECTIONS.snapshot()
    if connections["refused"]:
        # Refusals are the same condition /api/events reports, at the wider
        # cap: every new request is answered 503 while the connections already
        # open keep rendering, so a probe reading only the documents and the
        # streams called that healthy.
        reasons.append(
            f"{connections['refused']} connections refused at the "
            f"{connections['max']}-connection cap"
        )
    # A peer the token gate has locked out is guessing, and it is the only
    # condition below that says the server is under attack rather than
    # saturated: the gate answers 429, so nothing else in this snapshot moves.
    # The counter behind it is a lifetime one and deliberately not a reason
    # (one typo an hour ago would degrade every probe until restart); the
    # gauge is the live reading, and it drops with the window.
    auth = _metrics.AUTH.snapshot()
    auth["locked_peers"] = _server.auth_locked_peers()
    if auth["locked_peers"]:
        reasons.append(f"{auth['locked_peers']} peers locked out of the token gate")
    status = "degraded" if reasons else "healthy"
    _log_health_status(status, "; ".join(reasons) or "ok")
    return _json_ok(
        {
            "status": status,
            "version": __version__,
            "db": db_info,
            "extras": {
                # Whether disassembly actually runs here, not merely whether a
                # capstone distribution is on the path: an extra that imports
                # to a broken 500 is not an extra this process has.
                "capstone": disassembly_available(),
                "pygments": HAS_PYGMENTS,
            },
            "targets_count": target_count,
            "cors": _server.CORS_ENABLED,
            # The settings THIS process started with, so the answer to "what
            # is it running with" comes from the server rather than from a
            # shell that re-resolves the environment.  None in a process that
            # never ran `serve` (a mounted WSGI app), which is not a value to
            # guess at.
            "config": _active_config(),
            # RED counters for this process: request rate, error rate, and
            # latency extremes, so the operator can tell "one slow request"
            # from "the dashboard got slow" without a metrics backend.
            "requests": _metrics.REQUESTS.snapshot(),
            # Hit/miss for the payload memos and the conditional GET, because
            # a rising mean duration is otherwise the same reading for "the
            # build got slower" and "the cache stopped being consulted".
            "caches": _metrics.CACHES.snapshot(),
            # The regen pipeline runs for minutes, so its outcome and duration
            # need counters of their own; the request snapshot cannot show a
            # run that has not finished.
            "regen": _metrics.REGEN.snapshot(),
            # Live-reload saturation: every connected stream pins a server
            # thread for its whole life, and the cap answers 503 to the next
            # one.  clients vs max is the distance to that refusal.
            "streams": streams,
            # Connection admission saturation: the cap above the streams one,
            # which refuses every new request including a fresh tab.  A server
            # at it keeps serving the connections it already has, so without
            # this block health read "healthy" while refusing every new client.
            "connections": connections,
            # Token-gate attempts: rejected credentials and peers the throttle
            # has stopped reading, with the live lockout gauge.  A brute-force
            # run is invisible in every other block here, because the gate
            # answers 401/429 and neither is a 5xx.
            "auth": auth,
        },
        Cache_Control=CACHE_NO_STORE,
    )


def _active_config() -> dict[str, str] | None:
    """The startup settings of the running process, for ``/api/health``.

    ``recoverage config`` re-resolves the environment of the shell that runs
    it, which under a unit file or a container spec is not the server's
    environment: the same flags, a different answer, and an operator who
    checks the wrong one.  This reads what the process actually resolved.

    ``db`` is dropped: this endpoint names the coverage directory by its
    basename only, and the ``db`` block beside it already answers the
    question the absolute path was for.
    """
    active = _server.ACTIVE_CONFIG
    if active is None:
        return None
    return {key: value for key, value in active.items() if key != "db"}


def _stream_stats() -> dict[str, Any]:
    """SSE saturation and poller liveness for /api/health.

    ``watcher_alive`` is None before the watcher thread exists: ``serve``
    starts it at startup, but it can be absent in a process that never
    reached that call, so "not started yet" is not a fault and must not read
    as one.
    """
    with _SSE_CLIENTS_LOCK:
        clients = len(_SSE_CLIENTS)
    watcher = _db_watcher()
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


#: Last cause the target-list fallback reported, so it logs a transition and
#: not one line per request.  ``/api/targets`` is the request the SPA cannot
#: avoid and the shell preloads, so a broken coverage directory wrote one
#: WARNING per page load for as long as it stayed broken, which is what
#: teaches an operator to skip the line.  The same rule
#: :func:`_log_health_status` follows for the health probe.
_TARGETS_LOG_LOCK = threading.Lock()
_targets_fallback_reported: str | None = None


def _log_targets_fallback(exc: Exception) -> None:
    """Log the target-list fallback on the first failure and on the recovery.

    The cause goes in the line: a missing directory and a malformed document
    both land here, and the operator needs to tell them apart without reading
    the source.  It is escaped because a coverage document's own parse error
    is untrusted text and a line break in it would split the entry.
    """
    global _targets_fallback_reported
    reason = f"{type(exc).__name__}: {_server._log_safe(str(exc))}"
    with _TARGETS_LOG_LOCK:
        previous = _targets_fallback_reported
        if previous == reason:
            return
        _targets_fallback_reported = reason
    if previous is None:
        _log.warning(
            "Coverage unavailable reading the target list, falling back to the "
            "config-only list: %s",
            reason,
        )
    else:
        _log.info("Target list recovered from the config-only list (was: %s)", previous)


def _clear_targets_fallback() -> None:
    """Note that the coverage documents read, closing an open fallback report.

    Called on the success path of the same handler, so the recovery is logged
    once and the NEXT outage is news again rather than a repeat of a state
    that has already been reported.
    """
    global _targets_fallback_reported
    with _TARGETS_LOG_LOCK:
        previous = _targets_fallback_reported
        if previous is None:
            return
        _targets_fallback_reported = None
    _log.info("Coverage documents read again; target list is no longer config-only")


@app.get("/api/targets")
def handle_api_targets() -> bytes | HTTPResponse:
    """The target list, and the validator that lets a repeat visit skip it.

    This is the one request the SPA cannot avoid and the one the shell
    preloads (see `assets/index.html`), so it is asked on every page load.  It
    used to be answered ``no-store`` with no ETag, which is the same defect
    the SPA shell had: a reloading reader re-downloaded the whole list every
    time, and ``no-cache`` on the fetch (see ``web/app/api.ts``) had no
    validator to revalidate against.  A 304 is now the answer for a list that
    has not moved.

    The tag names BOTH inputs ``resolve_targets`` merges — the coverage
    snapshot and the project config's stat — because the fallback above reads
    only the config, and a key over the snapshot alone would answer 304 for the
    config-only list after a target was added to ``rebrew-project.toml``.
    ``max-age`` stays at zero for the same reason the shell's does: this list
    changes under a running server, and only revalidation is honest about when.
    """
    try:
        targets_list = resolve_targets()
    except CoverageTomlError as exc:
        # The cause goes in the line, once per outage rather than once per
        # request: see _log_targets_fallback.
        _log_targets_fallback(exc)
        targets_list = [
            {"id": tid, "name": Path(_target_filename(tid, t_info)).name}
            for tid, t_info in _server._get_targets_config().items()
        ]
    else:
        _clear_targets_fallback()

    etag = _etag_or_304(
        _snapshot_db_mtime(),
        "targets",
        config_fingerprint(_project_dir()),
    )
    if etag is None:
        # An unreadable DB is the case the snapshot cannot fingerprint, so
        # there is nothing to revalidate against and the list stays
        # uncacheable rather than being pinned to a tag that proves nothing.
        return _json_ok(
            {"targets": targets_list},
            Cache_Control=CACHE_NO_STORE,
        )
    return _json_ok(
        {"targets": targets_list},
        **_revalidate_headers(etag),
    )


@app.get("/api/targets/<target>/stats")
def handle_api_stats(target: str) -> bytes | HTTPResponse:
    """Per-section coverage stats, derived from one frozen snapshot.

    No query parameters: the payload is a pure function of the coverage
    documents and *target*, so the ``ETag`` covers the snapshot alone and two
    requests carrying the same tag describe the same numbers.  ``summary`` is
    the ``.text`` block, ``sections`` one row per section and
    ``functions_by_status`` the counts behind the list endpoint's ``?status=``
    vocabulary.
    """
    target = path_param(target)
    snap = _snapshot_db_mtime()
    # Same validator contract as /data, /asm and /bytes: the payload is a pure
    # function of the coverage snapshot and the target, so a poll that
    # revalidates gets a 304 instead of re-walking every cell.  "stats" is a
    # part of its own so the tag can never collide with /data's
    # (snap, target, section) over the same directory.
    etag = _etag_or_304(snap, target, "stats")
    key = (snap, target)
    stats: dict[str, Any] | None = None
    if snap is not None:
        with _STATS_CACHE_LOCK:
            stats = _STATS_CACHE.get(key)
    # Counted here, at the one place the memo is read, so the numbers in
    # /api/health's `caches` are the ones this endpoint actually served from.
    if stats is not None:
        _metrics.CACHES.hit(_metrics.STATS_CACHE)
    else:
        _metrics.CACHES.miss(_metrics.STATS_CACHE)
    if stats is None:
        with _target_snapshot(target) as coverage:
            stats = _server._section_stats(coverage)
        # Same watermark re-check as _cache_data_insert: a rebuild committed
        # between the snapshot and the aggregation would file pre-rebuild
        # numbers under the post-rebuild fingerprint, and the broadcast's
        # clear has already run by then.
        if snap is not None and _snapshot_db_mtime() == snap:
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


def _build_search_index(snap: CoverageSnapshot) -> dict[str, Any]:
    """Lightweight name -> {va, symbol} index for the SPA search box.

    Names are not unique across functions and globals — keep the FIRST
    (functions win over globals) so navigation never silently jumps to a
    colliding global's VA.
    """
    index: dict[str, Any] = {}
    for fn in snap.functions:
        index.setdefault(fn.name, {"va": fn.vaStart, "symbol": fn.symbol})
    for gl in snap.globals:
        index.setdefault(gl.name, {"va": hex(gl.va), "symbol": ""})
    return index


def _build_data_raw(
    snap: CoverageSnapshot,
    target: str,
    section_filter: str | None,
    include_search_index: bool = True,
) -> bytes:
    """Serialize the full /data payload (sections + cells + search index).

    Raises the shared JSON 404 for an unknown *section_filter*.  Pure snapshot
    work — caching/compression stays in the endpoint, and the snapshot is
    already the pin `server.read_snapshot` used to take: every field below comes
    from one build.

    *include_search_index* false omits the index (an absent key, the same
    signal `cells` uses), for the section-switch request that only wants one
    more section's cells and already holds the index from the load before it.
    """
    data: dict[str, Any] = _server.load_metadata(snap)

    # Always load every section row so the SPA can render tabs from a
    # ?section= payload.  Cells are the multi-MB part: omit siblings when
    # the client asked for one section (null, not []).
    data["sections"] = {
        name: {
            "target": snap.target,
            "name": name,
            "va": sec.va,
            "size": sec.size,
            "fileOffset": sec.file_offset,
            "unitBytes": sec.unit_bytes,
            "columns": sec.columns,
        }
        for name, sec in snap.sections.items()
    }

    if section_filter and section_filter not in data["sections"]:
        # Mirror /asm: an unknown section must 404, not return a silent
        # empty grid (which would also get memoized under that key).
        raise _section_not_found(target, section_filter)

    # Each section's cells are serialized to JSON text once and spliced into
    # the envelope, rather than parsed back into Python: re-encoding them
    # dominated the cold /data build on an 80k-cell target, for identical bytes.
    cells_json: dict[str, str | None] = {}
    for name, sec in snap.sections.items():
        if section_filter and name != section_filter:
            # Siblings are omitted (absent key), which is the SPA's lazy-load
            # signal, not an empty grid.
            cells_json[name] = None
        else:
            cells_json[name] = _server.cells_json(sec.cells)

    if include_search_index:
        data["search_index"] = _build_search_index(snap)

    # The format version travels with the payload so the client learns it from
    # the server; a second copy hardcoded in app.js would drift as rebrew
    # advances the format. It is the version of the documents THIS build read
    # (server.known_schema_versions documents why that is not the same thing
    # as the set the reader accepts), so it is a constant while rebrew reads
    # exactly one version.
    data["known_schema"] = _server.known_schema_versions()

    # Per-section cell stats, through the same reader /stats and the Potato map
    # header use: the buckets are derived from the snapshot's cells, so /data
    # and /stats cannot disagree about the same section.
    # ?section= narrows the cells, not the section set, so the unfiltered
    # payload is keyed by every section that has cells to count; the filtered
    # one carries the single section it was asked for.
    data["section_cell_stats"] = {
        name: _server._bucket_row(sec)
        for name, sec in snap.sections.items()
        if sec.cells and (not section_filter or name == section_filter)
    }

    return _dumps_with_cells(data, cells_json)


def _dumps_with_cells(data: dict[str, Any], cells_json: dict[str, str | None]) -> bytes:
    """Serialize *data* while splicing pre-encoded ``cells`` JSON arrays.

    ``data["sections"][name]`` is the section row *without* a cells key.
    *cells_json* maps names to ``server.cells_json`` output, or ``None`` to
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
        # String splice, not a JSON encoder: cells already holds a serialized
        # JSON array, and re-parsing it through Python dominated the cold
        # /data build.  A non-JSON cells encoding would need a real encoder
        # here.  An omitted key (``cells is None``) leaves the section row as
        # it stands, including the empty object that carries nothing else.
        if cells is None:
            spliced = sec_json
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
def handle_api_data(target: str) -> bytes | HTTPResponse:
    """The section rows, their cells, and the target-wide search index.

    ``?section=`` narrows the CELLS (every section row is still sent, so the
    tabs render, and the siblings carry no ``cells`` key), and ``?index=0``
    omits ``search_index`` for the section-switch request that already holds
    it.  Both are part of the ``ETag``, so a request that would produce a
    different payload never answers 304 for one that did not.
    """
    target = path_param(target)
    # ASCII whitespace only, like every other query value this package reads:
    # a section name comes out of a PE image, so one ending in U+00A0 or
    # U+FEFF is a real value, and str.strip() removed exactly those along
    # with the ASCII runs, leaving a filter that matched no section and a
    # payload with every `cells` key omitted.  `?index=` below is a flag
    # spelling, not a document value, so it keeps the plain strip.
    section_filter = _server.strip_ascii_whitespace(query_param("section")) or None
    # `?index=0` is the section-switch request: it arrives for one more
    # section's cells and already holds the target-wide search index, which is
    # the part of this payload that grows with the function count rather than
    # with the section. Omitted rather than emptied, the same signal `cells`
    # already uses, so one absence convention covers both.
    # Same contract as `?format=` and `?status=`: a value outside the flag's
    # two spellings is a 400, not a silent full payload.  `?index=false` and
    # `?index=no` used to read as "on" and cost the caller the very payload
    # size the flag exists to save, with nothing in the answer to say so.
    index_flag = query_param("index").strip()
    if index_flag not in ("", "0", "1"):
        return _json_err(
            400,
            {
                "error": "invalid index",
                "detail": f"index {index_flag!r} is not supported; "
                "expected 0 (omit search_index) or 1 (include it, the default)",
            },
        )
    include_search_index = index_flag != "0"

    # ETag caching based on the coverage-document fingerprint + target +
    # section.  The token folds every document's content digest, so two
    # rebuilds within the same second get distinct ETags when they wrote
    # different bytes, a rebuild that rewrote the same bytes keeps the ETag,
    # and a rebuild that changed any other target's document invalidates too.
    # The snapshot is computed once here: it is both the memo key and the
    # ETag input (see _etag_or_304).  etag is None only when the DB is unreadable — no ETag
    # is sent, and the queries below answer the standard 503 shortly after.
    snap = _snapshot_db_mtime()
    fingerprint: _DataKey = (
        snap,
        target,
        section_filter,
        include_search_index,
    )
    etag = _etag_or_304(snap, target, section_filter, include_search_index)
    headers = _revalidate_headers(etag)

    # Serve a memoized payload for an unchanged DB instead of re-running the
    # full-table queries, re-serialization, and recompression on every
    # cache-missing request.  A cold miss single-flights: concurrent misses
    # (the post-rebuild SSE refetch herd) share one build.
    entry, building = _data_cache_checkout(fingerprint)
    if entry is not None:
        accept_enc = _header("Accept-Encoding", "")
        encoding = _best_encoding(accept_enc)
        # The entry is SHARED state, not this request's: a checkout hands the
        # same dict to more than one thread (a follower the leader answered,
        # and the unclaimed duplicate build the single-flight deliberately
        # allows beside a live leader), and every one of them inserts variants
        # into it under _DATA_CACHE_LOCK.  Reading it outside that lock leaves
        # the answer to whichever interleaving of another thread's writes this
        # one lands between.  One hold covers both keys, and "raw" is
        # guaranteed present under it: _cache_data_insert publishes the entry,
        # "raw" and the variant together inside one acquisition, so no reader
        # can observe it half-built.
        with _DATA_CACHE_LOCK:
            body = entry.get(encoding)
            raw = entry["raw"]
        if body is None:
            # First request for this encoding: mint the variant from the
            # stored raw JSON (queries + json.dumps already paid for).  The
            # compression stays OUTSIDE the lock: brotli at q5 over a
            # multi-megabyte payload must not hold the lock every other /data
            # request queues on.
            body, _ = compress_payload(raw, accept_enc)
            with _DATA_CACHE_LOCK:
                entry[encoding] = body
        return _json_ok_precompressed(body, encoding, **headers)

    try:
        with _target_snapshot(target) as coverage:
            raw_json = _build_data_raw(coverage, target, section_filter, include_search_index)
            accept_enc = _header("Accept-Encoding", "")
            body, encoding = compress_payload(raw_json, accept_enc)
            _cache_data_insert(fingerprint, raw_json, encoding, body)
            return _json_ok_precompressed(body, encoding, **headers)
    finally:
        if building is not None:
            _data_cache_build_done(fingerprint, building)


# How many VAs one batch lookup accepts.  A COUNT OF REQUESTS, bounding a
# request body's list, so it is named for that rather than for the page it is
# not.
_MAX_BATCH_LOOKUP = 500

# The per-page cap the function list clamps ?limit= to.  A COUNT OF ROWS IN A
# RESPONSE, a different quantity from the batch cap above that happens to be
# the same number today; one constant serving both would make a change to
# either silently move the other.
_MAX_PAGE_LIMIT = 500

# Page size the function list serves when ?limit= is absent or unparseable:
# one constant, so the two answers cannot drift apart.
_DEFAULT_PAGE_LIMIT = 50

# Bound on the batch-lookup request body: the payload is fully parsed before
# the _MAX_BATCH_LOOKUP cap applies, so an unbounded read would let one
# request pin memory and CPU.  server.read_request_body refuses an oversized
# body from the declared Content-Length alone, so nothing past the cap is
# ever allocated.
_MAX_BATCH_BODY_BYTES = 64 * 1024

# Pagination offset ceiling: a real target holds orders of magnitude fewer
# functions, so clamping here changes no legitimate page while keeping the
# offset arithmetic far from a value that would overflow the loops that step
# through rows.
_MAX_PAGE_OFFSET = 10_000_000

# Upper bound for a binary-slice request (?size= on /asm and /bytes): both
# endpoints clamp identically so the same query string cannot mean two
# different window sizes.
_MAX_SLICE_SIZE = 4096

#: Section a disassembly request names when it names none.  The default the
#: endpoint serves, beside _MAX_SLICE_SIZE, so both read off the one place.
_DEFAULT_ASM_SECTION = ".text"

#: Bytes a raw-slice request reads when it asks for no size.
_DEFAULT_SLICE_SIZE = 256

# Longest ?search= the list endpoint accepts: server.MAX_SEARCH_CHARS, the one
# cap both search surfaces read, so the term a client can get past on one is
# the term it can get past on the other.
_MAX_SEARCH_CHARS = _server.MAX_SEARCH_CHARS

#: Statuses ``functions.status`` can carry: rebrew's own vocabulary
#: (``rebrew.workspace.status.COVERAGE_DB_STATUSES``, which build_db installs as
#: ``FUNCTION_DB_STATUSES``) read from rebrew rather than restated, so a status
#: rebrew adds is filterable the day it lands, and one it withdraws stops being
#: accepted the day it goes.  The same rule ``server.DATA_MARKER_TYPES`` follows
#: for the marker vocabulary.
#: ``tests/test_api.py`` (``TestFunctionStatusVocabulary``) pins the set against
#: rebrew's, so a rebrew change that misses this import fails a test instead of
#: silently 400-ing a status the DB does hold.
_FUNCTION_STATUSES: frozenset[str] = COVERAGE_DB_STATUSES

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
    sign, text = _server.strip_sign(raw.strip())
    if text[:2].lower() == "0x":
        return sign * _server.parse_ascii_int(text[2:], 16)
    return sign * _server.parse_ascii_int(text, 10)


def _page_int(raw: str) -> int:
    """A decimal pagination parameter, or :class:`ValueError` for anything else.

    ``?limit=`` and ``?offset=`` are the two integers a page is built from, and
    they carry no sign and no prefix: an unpadded run of ASCII digits.  Callers
    turn the :class:`ValueError` into their own default, so the shape of the
    failure never reaches the client.
    """
    return _server.parse_ascii_int(raw.strip(), 10)


def _slice_size(raw_size: str, parse_error: str) -> tuple[int, HTTPResponse | None]:
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
    is unparseable, negative or clamps to zero.
    """
    try:
        parsed = _parse_byte_count(raw_size)
    except ValueError:
        return 0, _json_err(
            400,
            {
                "error": parse_error,
                "detail": f"size {raw_size!r} is not a byte count "
                f"(decimal, or 0x-prefixed hex; 1..{_MAX_SLICE_SIZE})",
            },
        )
    # The sign is checked before the clamp, as /bytes' ?offset= does it: a
    # negative count clamped to zero answered "requests an empty slice", which
    # describes a value the client never sent.
    if parsed < 0:
        return 0, _json_err(
            400,
            {
                "error": "size must be positive",
                "detail": f"size {raw_size!r} is negative; expected 1..{_MAX_SLICE_SIZE}",
            },
        )
    size = min(parsed, _MAX_SLICE_SIZE)
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
    """Cache headers for a revalidating response that carries a strong ETag.

    The shared helper behind every GET that answers a validator:
    ``/api/targets``, ``/stats``, ``/data``, the function list, the function
    detail route, ``/asm`` and ``/bytes``.  *etag* is ``None`` only where the
    response has no validator to publish yet, and the caller then falls back to
    ``no-store`` rather than serving an unvalidatable body as revalidating.
    """
    headers = {"Cache_Control": CACHE_REVALIDATE}
    if etag is not None:
        headers["ETag"] = etag
    return headers


@app.get("/api/targets/<target>/functions")
def handle_api_functions_list(target: str) -> bytes | HTTPResponse:
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
    search = _server.strip_ascii_whitespace(query_param("search")) or None
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
        limit = min(
            max(_page_int(query_param("limit", str(_DEFAULT_PAGE_LIMIT))), 1),
            _MAX_PAGE_LIMIT,
        )
    except ValueError:
        limit = _DEFAULT_PAGE_LIMIT
    try:
        # Upper bound keeps a giant ?offset= from naming a page the row loop
        # would have to walk to before it discovered there is nothing there.
        offset = min(max(_page_int(query_param("offset", "0")), 0), _MAX_PAGE_OFFSET)
    except ValueError:
        offset = 0

    # Same contract as ?status= above, ?format= on /asm and ?index= on /data:
    # the parameter is an enum the server owns, so a value outside it is a
    # rejected query rather than a silent va-order page.  A typo (?sort=namee,
    # ?sort=name:sideways) answered 200 with a full page in an order the caller
    # never asked for and nothing in the answer to say so, which is the exact
    # answer ?status=?EXACT used to give.  An ABSENT ?sort= and an empty one
    # are still the default: those spell "no preference", not a bad value.
    sort_field = "va"
    sort_dir = "ASC"
    if sort_param:
        # A `field` or `field:direction` spelling; a bare field has no
        # direction, which is the default.
        sf, _, sd = sort_param.partition(":")
        direction = sd.lower()
        if sf not in _ALLOWED_SORT or direction not in _SORT_DIRECTIONS:
            return _json_err(
                400,
                {
                    "error": "invalid sort",
                    "detail": f"sort {sort_param!r} is not a column and direction "
                    f"this list orders by; expected {_SORT_SYNTAX_HINT}",
                },
            )
        sort_field = sf
        sort_dir = "DESC" if direction == "desc" else "ASC"

    # The change token the total is memoized on is stat'ed BEFORE the read
    # snapshot is loaded, the same order api.handle_api_stats,
    # api.handle_api_data and potato.render_potato use. Stat'ed after, a
    # rebuild committing between the load and the stat files the PRE-rebuild
    # count under the post-rebuild fingerprint — and the db-updated broadcast
    # has already run its clear by then, so nothing drops that entry until the
    # next rebuild, and every later list request reads a count that describes
    # rows the DB no longer holds.
    snap = _snapshot_db_mtime()
    # The page is a pure function of the snapshot and every query parameter
    # that shaped it, so it revalidates like its sibling DB-derived reads
    # (/stats, /data, /asm, /bytes) instead of answering no-store.  Every input
    # is in the key — the raw spellings for the ones the server reads as typed
    # (?status, ?search, ?sort, including the ones that fall back to a
    # default) and the resolved values for the two that clamp (?limit,
    # ?offset), so two requests that produced the same page share the tag and
    # two that did not cannot.
    etag = _etag_or_304(
        snap,
        target,
        "functions",
        status_filter,
        search,
        sort_param,
        limit,
        offset,
    )
    with _target_snapshot(target) as coverage:
        # `total` and the page come from ONE filter pass over one frozen
        # snapshot, so the count and the rows it paginates cannot describe two
        # different builds — the guarantee `read_snapshot` used to buy with a
        # deferred read transaction.
        rows = _filtered_functions(
            coverage.functions,
            status_filter,
            search,
            _server.folded_row_columns(coverage, coverage.functions),
        )
        total = _function_total(snap, target, status_filter, search, rows)
        # Enumerate exactly the response fields, in order: the SPA reads
        # these keys by name, so the shape is the contract.
        items = [
            {
                "va": fn.va,
                "name": fn.name,
                "vaStart": fn.vaStart,
                "size": fn.size,
                "status": fn.status,
                "module": fn.module,
                "symbol": fn.symbol,
                "markerType": fn.markerType,
            }
            for fn in _function_page(rows, sort_field, sort_dir, offset, limit)
        ]

        return _json_ok(
            {
                "target": target,
                "total": total,
                "limit": limit,
                "offset": offset,
                "functions": items,
            },
            **_revalidate_headers(etag),
        )


def _body_rejected(status: int, error: str, detail: str) -> HTTPResponse:
    """A refused POST body, answered on a connection that is then closed.

    ``server.read_request_body`` stops reading at its cap, so whatever the
    client sent after that point is still in the socket and a keep-alive
    handler would parse those bytes as the next request.  Every refusal it
    raises therefore answers with ``Connection: close``; one helper owns that
    so no refusal can answer without it.
    """
    return _json_err(status, {"error": error, "detail": detail}, Connection="close")


def _batch_request_vas() -> tuple[list[int], HTTPResponse | None]:
    """Read + validate the POST /functions body into deduped VA ints.

    Returns ``(unique_vas, None)`` on success, ``([], error_response)`` when
    the body violates the contract: a body read under
    :func:`recoverage.server.read_request_body`'s cap (with --allow-remote the
    endpoint is reachable off-loopback, and bottle's own body reader drains
    the whole declared body before any endpoint cap can see it), a JSON object
    with a non-empty "vas" array capped at _MAX_BATCH_LOOKUP, and entries
    that are integers or hex strings (base-16 with or without 0x prefix, so
    bare hex like "10001000" is valid here).

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
        raw = _server.read_request_body(_MAX_BATCH_BODY_BYTES)
    except _server.RequestBodyTooLargeError:
        return [], _body_rejected(
            413,
            "Request body too large",
            f"expected a JSON body under {_MAX_BATCH_BODY_BYTES // 1024} KiB",
        )
    except _server.RequestBodyMalformedError:
        return [], _body_rejected(
            400,
            "Malformed request body",
            "the body is framed in a way this endpoint cannot read",
        )
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
        return [], _body_rejected(
            400,
            "Could not read request body",
            f"the body stream failed before it was received ({type(exc).__name__})",
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        # RecursionError is a decode failure like the other two, not a crash:
        # the C scanner nests one frame per bracket, so `{"vas": [[[...` runs
        # out of stack in a body a kilobyte long. The byte cap bounds the body,
        # not the depth inside it.
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
        return [], _json_err(
            400,
            {
                "error": "vas must not be empty",
                "detail": 'expected at least one VA: {"vas": ["0x10001000", ...]}',
            },
        )
    if len(vas) > _MAX_BATCH_LOOKUP:
        return [], _json_err(
            400,
            {
                "error": f"vas list too large (max {_MAX_BATCH_LOOKUP})",
                "detail": f"received {len(vas)} entries",
            },
        )

    def invalid_va(entry: Any, detail: str) -> HTTPResponse:
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
                parsed_va = _server.parse_ascii_int(s, 16)
            except ValueError:
                return [], invalid_va(
                    entry, f"unparseable VA {entry!r}; expected hex like 0x10001000"
                )
            # Range-checked outside the parse arm, so a well-formed VA past the
            # address space gets the same "VA out of range" answer the integer
            # arm gives it.  Raising it inside the try answered "unparseable VA
            # '0x1'0000000000000000'; expected hex like 0x10001000" for a string
            # that parsed perfectly, naming the format as the fault.
            if parsed_va > VA_MAX:
                return [], invalid_va(entry, f"VA out of range (max 0x{VA_MAX:x})")
            va_ints.append(parsed_va)
        else:
            return [], invalid_va(entry, "VAs must be hex strings or integers")

    # Preserve input order; duplicate VAs collapse to a single result.
    return list(dict.fromkeys(va_ints)), None


@app.post("/api/targets/<target>/functions")
def handle_api_functions_batch(target: str) -> bytes | HTTPResponse:
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

    with _target_snapshot(target) as coverage:
        # Functions first (parity with GET /functions/<va>), then globals, and
        # every row comes from the same frozen snapshot — the build's function
        # rows and the `last_verify` attached to them cannot describe two builds.
        verify_rows = _server.verify_by_va(coverage)
        global_rows: Mapping[int, Global] | None = None
        results: list[dict[str, Any]] = []
        for wanted in unique_vas:
            fn = coverage.functions_by_va.get(wanted)
            if fn is not None:
                payload = _server.function_json(fn)
                record = verify_rows.get(fn.va)
                if record is not None:
                    payload["last_verify"] = _server.verify_payload(record)
                results.append(payload)
                continue
            # The globals arm is indexed on its first miss: a batch of function
            # VAs, which is what the SPA sends, never pays for it.
            if global_rows is None:
                global_rows = _server.globals_by_va(coverage)
            found = global_rows.get(wanted)
            if found is not None:
                results.append(_server.global_json(found))

        return _json_ok(json.dumps(results).encode("utf-8"), Cache_Control=CACHE_NO_STORE)


@app.get("/api/targets/<target>/functions/<va>")
def handle_api_function(target: str, va: str) -> bytes | HTTPResponse:
    target = path_param(target)
    va = path_param(va)
    value = va.strip()
    # Same validator contract as /stats, /data, the function list, /asm and
    # /bytes: the row is a pure function of the coverage snapshot, the target
    # and the requested spelling (the `last_verify` attachment comes from the
    # same frozen snapshot), so a client polling a cell revalidates instead of
    # re-downloading.  It used to be sent `no-store` with no ETag, the one
    # DB-derived GET in the family that could not answer 304.  The raw
    # spelling keys the tag, exactly as /asm's does: a name and a VA that
    # resolve to the same row stay separate revalidation identities, and the
    # value never reaches a header (it is hashed).
    snap = _snapshot_db_mtime()
    etag = _etag_or_304(snap, target, "function", value)
    headers = _revalidate_headers(etag)
    with _target_snapshot(target) as coverage:
        # One shared resolution order (server.lookup_function): VA candidates
        # first, then the exact name and then the folded one.  Both arms read
        # the stripped spelling, so a URL carrying a padded name resolves the
        # same way the name is spelled in the document.

        # Functions win over globals (parity with the batch endpoint).
        found_fn = _server.lookup_function(coverage, value)
        if isinstance(found_fn, Function):
            fn_json = _server.function_json(found_fn)
            # Attach the last `rebrew verify -o` record for this function.
            record = _server.verify_by_va(coverage).get(found_fn.va)
            if record is not None:
                fn_json["last_verify"] = _server.verify_payload(record)
            return _json_ok(json.dumps(fn_json).encode("utf-8"), **headers)

        found_gl = _server.lookup_global(coverage, value)
        if found_gl is not None:
            return _json_ok(
                json.dumps(_server.global_json(found_gl)).encode("utf-8"),
                **headers,
            )

        return _json_err(
            404,
            {
                "error": "not found",
                "detail": f"no function or global matching {value!r} for target {target!r}",
            },
        )


@app.get("/api/targets/<target>/asm")
def handle_api_asm(target: str) -> bytes | HTTPResponse:
    target = path_param(target)
    reason = capstone_unavailable_reason()
    if reason is not None:
        return _json_err(
            501,
            {
                "error": "capstone not available",
                "detail": f"{reason}; disassembly needs the optional extra: "
                "uv sync --extra capstone",
            },
        )

    va_str = query_param("va")
    size_str = query_param("size")
    section = query_param("section", _DEFAULT_ASM_SECTION)
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

    # ETag bound to the coverage-document fingerprint + request identity (see
    # _etag_or_304): disassembly reflects the binary + section layout, which
    # change when the documents are rebuilt.  Without this, a one-year
    # immutable Cache-Control served stale disassembly to browsers after
    # re-gen / --fix-sizes; a single file's mtime missed a rebuild that
    # rewrote any other target's document.
    # The raw spelling (not the resolved int) keys the ETag: it is hashed, so
    # request data never reaches a header, and each spelling is just its own
    # revalidation identity.
    asm_etag = _etag_or_304(
        _snapshot_db_mtime(), target, section, raw_va, size, fmt, _server.binary_stamp(target)
    )

    with _target_snapshot(target) as coverage:
        sec = _file_backed_section(coverage, section)

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
        # The section bounds the SLICE, not just the start address: `va` inside
        # the section says nothing about `va + size` being inside it, so a va at
        # the section's tail read the NEXT section's file bytes and
        # disassembled them at this section's VAs — an answer that depended on
        # where .text sat in the file.  Clamped rather than refused, because the
        # SPA asks for a FUNCTION's `vaStart`/`size` and a function whose body
        # runs to the section's last byte would otherwise lose its disassembly
        # entirely; the refusal of the whole request belongs to /bytes, whose
        # caller asked for an exact offset+size range.  The 422 below still
        # answers a section that cannot supply what the request named.
        size = min(size, sec["size"] - (va - sec_va))
        file_offset = sec["fileOffset"] + va - sec_va
        if file_offset < 0:
            # Unreachable for a document rebrew wrote (every fileOffset it
            # emits is the section's own position in the file), and kept
            # because nothing validates the field on read: a hand-edited or
            # foreign document carrying a negative offset would otherwise
            # slice from before the start of the file.
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
def handle_api_bytes(target: str, section: str) -> bytes | HTTPResponse:
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
    except ValueError:
        return _json_err(
            400,
            {
                "error": "invalid offset",
                "detail": f"offset {raw_offset!r} is not a byte offset "
                "(decimal, or 0x-prefixed hexadecimal)",
            },
        )
    raw_size = query_param("size", str(_DEFAULT_SLICE_SIZE))
    req_size, size_err = _slice_size(raw_size, "invalid size")
    if size_err is not None:
        return size_err

    # ETag bound to the coverage-document fingerprint + request identity so
    # /bytes revalidates after a rebuild instead of serving year-immutable
    # stale bytes (one file's mtime missed a rebuild that rewrote any other
    # target's document).
    bytes_etag = _etag_or_304(
        _snapshot_db_mtime(),
        target,
        section,
        req_offset,
        req_size,
        _server.binary_stamp(target),
    )

    with _target_snapshot(target) as coverage:
        sec = _file_backed_section(coverage, section)
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
            # Same guard as /asm: unreachable for a document rebrew wrote, and
            # kept for the same reason — a negative offset would slice from
            # before the file, where Python's negative indexing would silently
            # serve tail-of-binary bytes.  It names the offset the document
            # carries, like the two bounds refusals above: an `error` with an
            # empty `detail` is the one answer in this endpoint a caller cannot
            # act on, and here the actionable part IS the number.
            return _json_err(
                400,
                {
                    "error": "offset beyond section bounds",
                    "detail": f"section {section!r} maps offset {req_offset} to "
                    f"file offset {file_start}, before the start of the file",
                },
            )
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
def handle_regen() -> bytes | HTTPResponse:
    """Re-run rebrew catalog + build-db for the project workspace.

    Duplicate execution: a rebuild is convergent, so a second run ends in the
    same state as the first, but it is minutes of work and a second write of
    the coverage documents.  Two runs at the SAME time are worse than that: they
    interleave, and a reader can land between one writer's truncate and its
    write.  ``_REGEN_LOCK`` and the ledger below are this process's, so neither
    sees a ``recoverage regen`` at another terminal or a cron job over the same
    tree; ``regen.run_regen`` takes an advisory lock in the coverage directory
    for that, and the refusal arrives here as the same 429 the in-process lock
    gives.

    Send an ``Idempotency-Key`` header to make a retry cheap:
    the key is remembered once the run completes (see ``_REGEN_KEY_TTL_SECONDS``
    for the retention window and ``_REGEN_LEDGER_MAX_ENTRIES`` for the ledger's
    cap) and a later request
    carrying it is answered from the ledger with ``Idempotent-Replay: true``
    instead of re-running.  A key whose run is still going is answered 202 with
    ``in_progress``, which is the retry that lands before the first answer
    exists: it is told the operation is under way, not that it failed.  A run
    that failed is not recorded, so retrying a failure retries for real.
    Without the header, every POST re-runs.
    """
    global _regen_last_attempt

    # `or ""` also folds an explicit None environ value into the rejected-by-
    # default path (same clean 403 as a missing REMOTE_ADDR, no TypeError).
    remote = request.environ.get("REMOTE_ADDR") or ""
    if not _peer_is_loopback(remote):
        return _regen_forbidden(
            "not localhost",
            "Forbidden: localhost only",
            f"request came from remote address {remote!r}",
        )

    origin = _header("Origin", "")
    if not origin and header_present("Origin"):
        # An Origin that arrived and arrived empty is not the absence the arm
        # below is written for. No browser sends one, so it is a value
        # something between the page and here emptied, and folding it into the
        # absent case admits a privileged POST on the strength of the one
        # header that should have named it.
        return _regen_forbidden(
            "empty Origin", "Forbidden: cross-origin", "Origin is present but empty"
        )
    if origin:
        # Same-origin against the request's own Host, not "the origin's
        # hostname is loopback": a page served from any OTHER loopback port is
        # a different origin whose operator this gate is meant to exclude, it
        # passes a hostname check, and a browser cannot read the reply, so the
        # rebuild it starts is invisible to the operator who started it.
        if not origin_is_this_dashboard(origin, _header("Host", "")):
            return _regen_forbidden(
                "cross-origin",
                "Forbidden: cross-origin",
                f"origin {origin!r} is not this dashboard",
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
            return _regen_forbidden(
                "cross-site request",
                "Forbidden: cross-site request",
                f"Sec-Fetch-Site: {fetch_site} is not a same-origin regen",
            )

    # Idempotency-Key: a client that retries a regen whose response it never
    # saw re-sends the same request.  A key that already completed is answered
    # from the ledger here, BEFORE the cooldown below, because the retry lands
    # seconds after the first run — inside the cooldown window, where the
    # throttle would 429 the very request it is meant to dedup.
    key = _header("Idempotency-Key", "").strip()
    if key and not _REGEN_KEY_RE.fullmatch(key):
        return _json_err(
            400,
            {
                "error": "Bad request: malformed Idempotency-Key",
                "detail": f"expected 1-{_REGEN_KEY_MAX_CHARS} characters of [A-Za-z0-9._:-]",
            },
        )
    if key and _regen_replayed(key):
        return _regen_replay_response(key)
    if key and _regen_in_progress(key):
        # The retry of a run still going, not a second regenerate: answer with
        # the operation's own state.  202 says the request was accepted and the
        # work is not done, which is what a client needs to tell apart from a
        # regeneration that failed and from a 429 that means "somebody else's
        # run" — the latter is the only one that leaves a key free to re-run.
        return _regen_in_progress_response(key)

    # Server-side cooldown + serialization: the cooldown check and the regen
    # run must be atomic — two concurrent POSTs could otherwise both pass the
    # check and run catalog/build-db in parallel, tearing the data_*.json /
    # documents (TOCTOU).  Non-blocking acquire: a second POST while a regen
    # runs gets an immediate 429 instead of blocking on the lock for the whole
    # run.
    if not _REGEN_LOCK.acquire(blocking=False):
        # The read above ran without the lock, so a duplicate that arrived in
        # the same instant as the request it retries saw no in-flight key and
        # came here: the run holding _REGEN_LOCK IS the one this key names.
        # Answering 429 to it is what the 202 above exists to prevent, because
        # the SPA reads a 429 as a failed regenerate, mints a NEW key and pays
        # for a second full pipeline.  Re-read under the loss, so a duplicate
        # racing its own predecessor is absorbed rather than refused.
        if key and _regen_in_progress(key):
            return _regen_in_progress_response(key)
        _metrics.REGEN.reject()
        return _json_err(
            429,
            {
                "error": "Rate limited: regeneration already running",
                "detail": "a catalog/build-db run is in progress",
                # An int, the type the cooldown arm below and every other 429
                # in the package send, so a client reads one JSON type out of
                # `retry_after` whichever limit it hit.
                "retry_after": int(_REGEN_COOLDOWN_SECONDS),
            },
            Retry_After=str(int(_REGEN_COOLDOWN_SECONDS)),
        )
    try:
        # Re-read the ledger UNDER the lock, so claiming a key is atomic with
        # running it.  The checks above ran without it, which leaves one window
        # open: a duplicate whose predecessor was still running saw neither a
        # completed nor an in-flight key and reaches this point after the
        # predecessor released.  The cooldown cannot close it, because it counts
        # from the previous run's START and a regen runs for minutes, so it has
        # long expired by the time that run ends.  Without this read, a retry of
        # a key that already completed starts a second full pipeline.
        if key and _regen_replayed(key):
            return _regen_replay_response(key)
        now = clock.monotonic()
        since = math.inf if _regen_last_attempt is None else now - _regen_last_attempt
        if since < _REGEN_COOLDOWN_SECONDS:
            remaining = _REGEN_COOLDOWN_SECONDS - since
            _metrics.REGEN.reject()
            # The wait ONE number, read in two places.  Every other 429 and the
            # 503 the SSE cap sends put the header's own value in the body
            # (``server._auth_throttle``, ``handle_api_events``), and this arm
            # sent a rounded float beside a ceiled integer: a client that read
            # the body waited 4.2s and was refused again, while one that read
            # the header waited the 5s the header named.  The header is the
            # whole seconds RFC 9110 allows, so the body carries that same
            # value and the human-precision wait stays in ``detail``.
            wait = math.ceil(remaining)
            return _json_err(
                429,
                {
                    "error": "Rate limited: wait before regenerating again",
                    "detail": f"retry after {remaining:.1f}s",
                    "retry_after": wait,
                },
                # The auth throttle sends the same header, so a client can read
                # one Retry-After for every 429 the server emits.
                Retry_After=str(wait),
            )
        _regen_last_attempt = now
        # From here to the release the key names THIS run, so a retry arriving
        # mid-flight is answered as in progress rather than refused.  Recorded
        # only once the run is certain to start: a request turned away above
        # (cooldown, or a key already in flight) must leave the key free.
        if key:
            _record_active_key(key)
        result = _do_regen(remote)
        # _do_regen answers the success body as bytes and a mapped failure as
        # an HTTPResponse.  Only a completed run is recorded, so a client that
        # retries a failure gets a real second attempt.
        if key and isinstance(result, bytes):
            _record_completed_key(key)
        return result
    finally:
        # Both outcomes, and the exceptions: the marker describes a run, and
        # the run is over in every case, so a key left marked in flight would
        # answer every later request with 202 and no pipeline behind it.
        if key:
            _clear_active_key(key)
        _REGEN_LOCK.release()


def _do_regen(remote: str) -> bytes | HTTPResponse:
    """Run catalog + build-db in-process. Caller holds _REGEN_LOCK."""
    # Clear derived caches before AND after: the pre-run clears matter while
    # the regen runs; the resolved-target / index caches get repopulated from
    # the OLD db the moment anything queries them, and with no SSE client
    # connected the watcher would never re-invalidate them (curl-only regen ->
    # stale target dropdown).
    _clear_derived_caches_logged("before regen")

    # The counters open before the guard because every arm below closes them,
    # and the BaseException arm reads started_at.  Resolving the project root
    # is inside it: it touches the filesystem (a deleted cwd raises), and an
    # exception escaping there would skip _regen_failed, leave REGEN in flight,
    # and answer an HTML 500 instead of the JSON contract every other outcome
    # uses.
    started_at = clock.monotonic()
    _metrics.REGEN.start()
    try:
        root = _project_dir()
        _log.info("Regen started from %s", remote, extra=_regen_log_fields("started"))
        run_regen(root)
    except RegenDbMismatchError as e:
        # A setting this package reads and rebrew cannot honour: the regen was
        # refused before it ran, so the operator has to change configuration
        # before a rebuild can mean anything. 500 would read as a broken
        # pipeline; the message is a path pair the operator has to see.
        _regen_failed(started_at, "%s: %s", type(e).__name__, e)
        return _json_err(
            500,
            {
                "error": "Regen refused",
                "detail": str(e),
            },
        )
    except RegenBusyError as e:
        # Another PROCESS holds this project's regen lock: a `recoverage regen`
        # at a terminal beside this server, or a cron job over the same tree.
        # `_REGEN_LOCK` cannot see either, so this is the one duplicate the
        # handler's own serialization does not already answer. It gets the same
        # answer the in-process lock gives, so a client has one shape for "a
        # regen is already running", and it is counted as the refusal it is
        # rather than a pipeline that broke.
        _regen_rejected(started_at, "%s: %s", type(e).__name__, e)
        return _json_err(
            429,
            {
                "error": "Rate limited: regeneration already running",
                "detail": str(e),
                "retry_after": int(_REGEN_COOLDOWN_SECONDS),
            },
            Retry_After=str(int(_REGEN_COOLDOWN_SECONDS)),
        )
    except RegenError as e:
        # rebrew's error_exit reported the failure and its status is carried
        # here.  Map it to the JSON 500 contract instead of letting it escape
        # as a traceback.
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
    except BaseException as e:
        # A BaseException — Ctrl+C at the terminal running `serve`, a
        # SystemExit from somewhere inside rebrew — unwinds past both arms
        # above, and the in_flight gauge is a gauge: nothing ever closes it,
        # so /api/health would answer `regen.in_flight: 1` for the rest of the
        # process and every later reading would be one regen ahead of the
        # truth.  Close the counters with the same elapsed the other arms
        # record, then let the exception through: it is the server's exit, not
        # this handler's to swallow.
        elapsed = _elapsed_s(started_at)
        _metrics.REGEN.finish(False, _elapsed_ms(started_at))
        _log.error(
            "Regen interrupted after %.1fs: %s",
            elapsed,
            type(e).__name__,
            extra=_regen_log_fields("interrupted", elapsed),
        )
        raise
    finally:
        # A FAILED run invalidates too, and that is the case the post-run
        # clear used to miss: the writer replaces the documents before it can fail
        # (a bad row, a full disk, a missing input), so a run that dies leaves
        # the server serving payloads derived from the file it just replaced,
        # and the watcher's mtime poll only clears them on its next tick — up
        # to _SSE_POLL_INTERVAL_SECONDS of a dashboard that reports the old
        # numbers as current.  Both outcomes go through the same tail.
        _clear_derived_caches_logged("after regen")
    elapsed = _elapsed_s(started_at)
    _metrics.REGEN.finish(True, _elapsed_ms(started_at))
    _log.info(
        "Regen completed successfully in %.1fs", elapsed, extra=_regen_log_fields("ok", elapsed)
    )
    return _json_ok({"ok": True})


def _elapsed_s(started_at: float) -> float:
    """Seconds since *started_at* on the injectable clock."""
    return clock.monotonic() - started_at


def _elapsed_ms(started_at: float) -> float:
    """Milliseconds since *started_at*, the unit ``REGEN.finish`` records.

    The inverse of :func:`_elapsed_s`, which every log line in the regen
    lifecycle reads.  Written as a named conversion so the metric's unit and
    the log's cannot drift apart at a call site.
    """
    return _elapsed_s(started_at) * 1000.0


def _regen_log_fields(outcome: str, elapsed_s: float | None = None) -> dict[str, dict[str, object]]:
    """The ``extra=`` for a regen lifecycle line.

    A regen is the one operation that runs for minutes and the one an
    operator needs to correlate with ``/api/health``'s ``regen`` block, so its
    lines carry the outcome and the elapsed time as fields: the counter says
    three runs failed, the fields say which three and how long each took,
    without reading the prose.
    """
    fields: dict[str, object] = {"event": "regen", "outcome": outcome}
    if elapsed_s is not None:
        fields["duration_s"] = round(elapsed_s, 1)
    return {_server.LOG_FIELDS_ATTR: fields}


def _regen_forbidden(reason: str, error: str, detail: str) -> HTTPResponse:
    """Answer one security refusal of ``POST /api/regen``, loudly and counted.

    A refused regen is the one event on this endpoint an operator has no
    other way to see: the request never enters the pipeline, so no regen
    lifecycle line is written and ``regen.in_flight`` never moved, and the
    per-request line is DEBUG unless the request was slow.  A cross-origin
    POST aimed at the one privileged operation therefore left the log saying
    nothing at all, and the two sibling security refusals in the package (a
    bad ``Host`` header, a bad bearer token) each write a line for exactly
    that reason.

    *error* is the wire message the arm already sent and *reason* the short
    form the log carries; the body a client reads is unchanged.

    The peer is escaped like every other request log argument: it is peer
    input through a proxy, and a control byte in it would forge entries.
    """
    _log.warning(
        "Refused POST /api/regen (%s) from %s: %s",
        reason,
        _server.peer_label(),
        _server._log_safe(detail),
        extra=_server.request_log_fields(403, target="regen"),
    )
    # Counted as a rejection, not a failure: nothing ran, so a peer probing
    # the privileged endpoint shows up in `/api/health` without the pipeline
    # reporting a breakage that did not happen.
    _metrics.REGEN.reject()
    return _json_err(403, {"error": error, "detail": detail})


def _regen_failed(started_at: float, reason: str, *args: object) -> None:
    """Log a failed run with its duration and close out its counters.

    Every failure path runs this, so the elapsed time is read once and lands
    in the same place on each: a rebuild that dies after two seconds and one
    that dies after two hundred are told apart by the line, not by the clock.
    ``exc_info`` is left on so the frames of the exception that brought the
    run down ride along: the JSON body carries the class name only (a rebrew
    or OSError message quotes paths from the project tree), so without them
    the operator has a class name and no way to find the line that raised it.
    """
    elapsed = _elapsed_s(started_at)
    _log.error(
        "Regen failed after %.1fs: " + reason,
        elapsed,
        *args,
        exc_info=True,
        extra=_regen_log_fields("failed", elapsed),
    )
    _metrics.REGEN.finish(False, _elapsed_ms(started_at))


def _regen_rejected(started_at: float, reason: str, *args: object) -> None:
    """Close out a run that was refused rather than failed.

    The ``RegenBusyError`` arm answers 429, the same shape the in-process
    lock gives, and running it through :func:`_regen_failed` filed it as a
    pipeline error: a second process's ``recoverage regen`` (or a cron job
    over the same tree) wrote a red ``Regen failed after 0.0s`` line every
    time, which is noise on the one line that does mean the pipeline broke.
    """
    elapsed = _elapsed_s(started_at)
    _log.info(
        "Regen refused after %.1fs: " + reason,
        elapsed,
        *args,
        extra=_regen_log_fields("rejected", elapsed),
    )
    # None, not False: the gauge closes and the elapsed time is recorded, but
    # nothing was written and nothing broke, so `failures` stays the count of
    # runs that ran and failed.
    _metrics.REGEN.finish(None, _elapsed_ms(started_at))
    _metrics.REGEN.reject()
