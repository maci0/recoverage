"""In-process RED counters for the dashboard server.

The server is a single process serving one operator (or one team behind a
shared coverage read).  There is no metrics backend to push to, so the
numbers live in memory and are read back through ``/api/health``: request
count, error count, slow-request count, and the latency figures needed to
tell "one slow request" from "every request got slower" (a max, and the
p50/p95 of a bounded window of the most recent timed requests).

Cardinality is bounded on purpose.  Routes are bucketed by their Bottle rule
(``/api/targets/<target>/data``), never by the raw path, so a caller cannot
grow the map by inventing target names; anything that reaches a handler
without a rule falls back to its first path segment, and
:data:`ROUTE_LABEL_MAX` caps that map for the rest.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Final

#: A request slower than this is counted separately and logged at WARNING.
#: Above the slowest cold-start read the dashboard makes, far below anything
#: an operator would call a hang.
SLOW_REQUEST_MS: Final = 1_000.0

#: Requests that never leave the handler while it runs (the SSE event stream
#: holds its response open by design), so their "duration" is connection
#: lifetime, not service time.  Counting them would poison every latency
#: number in the snapshot.
UNBOUNDED_ROUTES: Final = frozenset({"/api/events"})

#: Most route labels :class:`RequestStats` keeps.  A label from the matched
#: Bottle rule is one of the server's own few dozen, but :func:`route_label`
#: falls back to the first path segment for a request that matched nothing, and
#: that segment is caller-chosen, so the map needs a cap.
#:
#: The cap alone does not protect the routes the server really serves: under
#: plain oldest-first eviction, 64 distinct unknown first segments is enough to
#: push out a real route row inserted on its first request, and a caller
#: choosing that many names silently blanks the breakdown an operator reads.
#: So the two kinds of label are not treated alike.  A rule label evicts the
#: oldest entry when the map is full (there are only a few dozen of them, and
#: each is one the server really serves); a fallback label is never inserted
#: into a full map, so the 404s that fill it cost no real route its row.  The
#: request still counts in the process-wide totals and in ``by_status``.
ROUTE_LABEL_MAX: Final = 64

#: Timed durations kept for the percentile figures in the snapshot.  A fixed
#: window of the most recent requests, not the whole run: ``p50_ms`` and
#: ``p95_ms`` answer "is every request slow RIGHT NOW", which is the question an
#: operator has while a dashboard is slow, and a window bounds both the memory
#: (a deque of 512 floats, dropped oldest-first) and the work (one append per
#: timed request, and the sort happens only when ``/api/health`` is polled).
#: A lifetime histogram would answer the other question, "was the process ever
#: slow", which ``max_ms`` already answers, and would grow without limit.
LATENCY_WINDOW: Final = 512


def percentile(samples: list[float], fraction: float) -> float:
    """The *fraction* quantile of the SORTED *samples*, by order statistic.

    Zero samples answer 0.0 rather than raising: the snapshot is read while a
    process may have served nothing yet, and a health probe that raises is a
    probe that reports a fault the operator has to diagnose in the metrics
    code.  No interpolation, and no nearest-rank ``ceil(f*n)-1`` either: the
    figure is always a sample the slow-request log can then name.
    """
    if not samples:
        return 0.0
    rank = min(len(samples) - 1, round(fraction * (len(samples) - 1)))
    return samples[rank]


@dataclass
class _RouteRow:
    """One row of the per-route breakdown.

    A dataclass rather than a dict of mixed values: the row holds a counter, a
    counter, a float and a deque, and a dict spelling them is a union every
    read has to narrow.
    """

    requests: int = 0
    errors: int = 0
    max_ms: float = 0.0
    #: This route's own bounded window, behind its p50/p95.  The same
    #: LATENCY_WINDOW the process-wide figures use, so the per-route memory is
    #: bounded by ROUTE_LABEL_MAX * LATENCY_WINDOW samples and a route that
    #: goes quiet forgets its own history on the same terms.
    recent_ms: deque[float] = field(default_factory=lambda: deque(maxlen=LATENCY_WINDOW))


class RequestStats:
    """Per-route request counters, guarded by one lock.

    Every mutation takes ``_lock`` and every read copies under it, so a
    ``/api/health`` snapshot can never observe a half-updated route.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total = 0
        self._errors = 0
        self._slow = 0
        self._max_ms = 0.0
        self._sum_ms = 0.0
        self._timed = 0
        self._in_flight = 0
        self._stale_claims = 0
        self._transport_rejected = 0
        # The bounded window behind p50_ms / p95_ms; see LATENCY_WINDOW.
        self._recent_ms: deque[float] = deque(maxlen=LATENCY_WINDOW)
        self._by_route: dict[str, _RouteRow] = {}
        self._by_status: dict[str, int] = {}

    def start(self) -> None:
        with self._lock:
            self._in_flight += 1

    def finish(
        self,
        route: str,
        status: int,
        duration_ms: float,
        timed: bool = True,
        rule_matched: bool = True,
    ) -> None:
        """Record one completed request.

        *timed* is False for the routes whose response is held open: their
        duration is connection lifetime, so it updates the counters but not
        the latency extremes.

        *rule_matched* is False for the caller-chosen fallback label
        :func:`route_label` builds when no Bottle rule matched.  Such a label
        is dropped rather than admitted to a full map, so a caller naming
        enough unknown paths cannot evict the routes the server really serves
        (see :data:`ROUTE_LABEL_MAX`); the request is still counted in the
        totals and in ``by_status``.
        """
        slow = timed and duration_ms >= SLOW_REQUEST_MS
        with self._lock:
            self._in_flight -= 1
            self._total += 1
            if status >= 500:
                self._errors += 1
            if slow:
                self._slow += 1
            if timed:
                self._timed += 1
                self._sum_ms += duration_ms
                self._max_ms = max(self._max_ms, duration_ms)
                self._recent_ms.append(duration_ms)
            bucket = f"{status // 100}xx"
            self._by_status[bucket] = self._by_status.get(bucket, 0) + 1
            if route in self._by_route:
                route_row = self._by_route[route]
            elif not rule_matched and len(self._by_route) >= ROUTE_LABEL_MAX:
                return
            else:
                while len(self._by_route) >= ROUTE_LABEL_MAX:
                    del self._by_route[next(iter(self._by_route))]
                route_row = self._by_route[route] = _RouteRow()
            route_row.requests += 1
            if status >= 500:
                route_row.errors += 1
            if timed:
                route_row.max_ms = max(route_row.max_ms, duration_ms)
                route_row.recent_ms.append(duration_ms)

    def reclassify(self, route: str, from_status: int, to_status: int) -> None:
        """Re-bucket a finished request under its real status.

        Bottle runs ``after_request`` before the error handler turns an
        escaped exception into a 500 (or a 503, for a database failure), so
        the hook sees 200 for a request that never succeeded.  The error
        handler calls this with what it is about to answer.

        The request is re-bucketed, not retracted: ``_by_status`` moves it
        between status buckets, so ``_by_route`` keeps counting it too, and
        the per-route request counts keep summing to ``total``.  Retracting it
        from the route row instead made a route whose every request failed
        report ``requests: 0, errors: 3``.  The route's error count follows
        the same 500 threshold as the process-wide one, so a reclassification
        into a non-5xx bucket does not leave the two disagreeing.
        """
        if from_status == to_status:
            return
        old, new = f"{from_status // 100}xx", f"{to_status // 100}xx"
        delta = 1 if to_status >= 500 else -1
        with self._lock:
            self._by_status[old] = self._by_status.get(old, 0) - 1
            if self._by_status[old] <= 0:
                del self._by_status[old]
            self._by_status[new] = self._by_status.get(new, 0) + 1
            self._errors += delta
            row = self._by_route.get(route)
            if row is not None:
                row.errors += delta

    def note_transport_rejection(self) -> None:
        """Record one request the HTTP transport refused before any route ran.

        An over-long or malformed request line, an unsupported version, an
        oversized header block, a client that stalled past the socket deadline:
        every one of those is answered by ``devserver``'s handler class, ahead
        of ``before_request``, so it reaches no counter here and no ``by_status``
        bucket.  The log line it does write is the only trace, and a scanner
        looping on a malformed request produces one line per attempt and no
        number an operator can alert on.  Counted apart from the request
        counters, which cannot hold it: there is no route, no status and no
        duration to file it under.
        """
        with self._lock:
            self._transport_rejected += 1

    def note_stale_claim(self) -> None:
        """Record one single-flight claim that outlived the thread that took it.

        ``/data`` serializes one payload build per key, so a leader whose
        thread is killed before its ``finally`` leaves a claim no waiter can
        wake on: every later request for that key pays the full wait before it
        reclaims it and builds its own.  The reclaim recovers the request and
        says nothing about the fault that caused it, so the count here is the
        only reading that distinguishes one killed leader from a dashboard that
        merely refetches a lot.
        """
        with self._lock:
            self._stale_claims += 1

    def snapshot(self) -> dict[str, Any]:
        """A JSON-ready copy of the counters.

        ``mean_ms`` is a lifetime average over every timed request, so it
        moves when the workload changes.  The mean divides by the timed
        count, not by ``total``, so a connection held open by an
        :data:`UNBOUNDED_ROUTES` route is counted in ``total`` and absent
        from the sum, and drags neither figure down.  ``max_ms`` is the
        worst single timed request since start, and ``p50_ms``/``p95_ms``
        are quantiles of the last :data:`LATENCY_WINDOW` timed requests:
        the mean of a mostly-fast window hides a tail, and the max alone
        cannot tell "one slow request" from "every request got slower",
        which is the distinction a p95 carries.  ``latency_window`` says how
        many samples the two quantiles were taken from, so a figure read off
        a quiet server is not read as a verdict on a busy one.
        ``in_flight`` counts requests currently inside a
        handler, so a snapshot taken from ``/api/health`` includes the
        request asking.
        """
        with self._lock:
            mean = self._sum_ms / self._timed if self._timed else 0.0
            window = sorted(self._recent_ms)
            by_route: dict[str, Any] = {}
            for route, row in sorted(self._by_route.items()):
                # One sort of this route's window, read twice: every
                # request's `finish` waits on this lock.
                route_window = sorted(row.recent_ms)
                by_route[route] = {
                    "requests": row.requests,
                    "errors": row.errors,
                    "max_ms": round(row.max_ms, 3),
                    # Quantiles of this route's own window, so a
                    # process-wide p95 that moved can be attributed
                    # without a second request: the row whose p95 sits
                    # at SLOW_REQUEST_MS is the endpoint that moved.
                    "latency_window": len(route_window),
                    "p50_ms": round(percentile(route_window, 0.50), 3),
                    "p95_ms": round(percentile(route_window, 0.95), 3),
                }
            return {
                "total": self._total,
                "errors": self._errors,
                "slow": self._slow,
                "in_flight": self._in_flight,
                "stale_claims": self._stale_claims,
                "transport_rejected": self._transport_rejected,
                "slow_threshold_ms": SLOW_REQUEST_MS,
                "mean_ms": round(mean, 3),
                "max_ms": round(self._max_ms, 3),
                "latency_window": len(window),
                "p50_ms": round(percentile(window, 0.50), 3),
                "p95_ms": round(percentile(window, 0.95), 3),
                "by_status": dict(self._by_status),
                "by_route": by_route,
            }

    def reset(self) -> None:
        """Zero the lifetime counters.

        ``_in_flight`` is a gauge, not a lifetime counter, and is left alone:
        a request already inside a handler holds its slot, and zeroing it here
        would let that request's ``finish`` drive the gauge negative.
        """
        with self._lock:
            self._total = 0
            self._errors = 0
            self._slow = 0
            self._sum_ms = 0.0
            self._timed = 0
            self._max_ms = 0.0
            self._stale_claims = 0
            self._transport_rejected = 0
            self._recent_ms.clear()
            self._by_route.clear()
            self._by_status.clear()


#: The process-wide registry the hooks update and /api/health reads.
REQUESTS = RequestStats()


class RegenStats:
    """Outcome and duration counters for the catalog/build-db pipeline.

    A regen is the one request that runs for minutes, so the per-request
    latency numbers say little about it: one sample, and none at all while it
    is still running.  A hung regen is the failure an operator most needs to
    see and the one the request counters cannot show, so the run's state is
    tracked on its own: ``in_flight`` says a run is going, ``last_duration_ms``
    says how long the previous one took, and ``failures`` separates a pipeline
    that will not run from one nobody asked to run.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs = 0
        self._failures = 0
        self._rejected = 0
        self._in_flight = 0
        self._last_ms = 0.0
        self._last_ok: bool | None = None

    def start(self) -> None:
        with self._lock:
            self._in_flight += 1
            self._runs += 1

    def finish(self, ok: bool, duration_ms: float) -> None:
        """Record one finished run. *duration_ms* comes from ``clock.monotonic``."""
        with self._lock:
            self._in_flight -= 1
            if not ok:
                self._failures += 1
            self._last_ms = duration_ms
            self._last_ok = ok

    def reject(self) -> None:
        """Record a POST refused by the lock or the cooldown, not by a failure.

        A dashboard whose Reload button is being double-clicked reports runs
        and no failures; the refused attempts are the whole story, and without
        this counter they are indistinguishable from a pipeline that nobody
        triggered.
        """
        with self._lock:
            self._rejected += 1

    def snapshot(self) -> dict[str, Any]:
        """A JSON-ready copy. ``last_ok`` is None until the first run finishes."""
        with self._lock:
            return {
                "runs": self._runs,
                "failures": self._failures,
                "rejected": self._rejected,
                "in_flight": self._in_flight,
                "last_duration_ms": round(self._last_ms, 3),
                "last_ok": self._last_ok,
            }

    def reset(self) -> None:
        """Zero the lifetime counters.

        ``_in_flight`` is a gauge, not a lifetime counter, and is left alone
        for the reason :meth:`RequestStats.reset` gives: a regen already
        running holds its slot, and zeroing it here would let that run's
        ``finish`` drive the gauge negative, so ``/api/health`` would answer
        ``regen.in_flight: -1`` and every reading after it one off.
        """
        with self._lock:
            self._runs = 0
            self._failures = 0
            self._rejected = 0
            self._last_ms = 0.0
            self._last_ok = None


#: The regen registry ``/api/regen`` updates and /api/health reads.
REGEN = RegenStats()

#: The names the cache counters are keyed by.  Bounded by the call sites, never
#: by request data, so this map cannot grow the way a route label can.
DATA_PAYLOAD_CACHE: Final = "data_payload"
STATS_CACHE: Final = "stats"
REVALIDATION_CACHE: Final = "revalidate"


class CacheStats:
    """Hit and miss counts for the memos and the conditional-GET path.

    The dashboard is fast or slow mostly because of these, and the two causes
    are indistinguishable from latency alone: a payload memo that stopped
    hitting makes every poll rebuild a multi-megabyte body, and an ETag that
    stopped revalidating does the same one step earlier.  Neither showed up in
    any counter, so ``/api/health`` could report a rising ``mean_ms`` with no
    way to say whether the server got slower or the cache stopped working.

    ``REVALIDATION_CACHE`` counts ``If-None-Match`` answers: a hit is the 304
    the client asked for, a miss is a request the server had to answer in full
    (a first load, a changed build, or a client that stopped sending the
    validator).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_cache: dict[str, list[int]] = {}

    def hit(self, name: str) -> None:
        self._count(name, 0)

    def miss(self, name: str) -> None:
        self._count(name, 1)

    def _count(self, name: str, column: int) -> None:
        with self._lock:
            row = self._by_cache.get(name)
            if row is None:
                row = self._by_cache[name] = [0, 0]
            row[column] += 1

    def snapshot(self) -> dict[str, dict[str, int]]:
        """A JSON-ready copy, one row per cache that has been read from."""
        with self._lock:
            return {
                name: {"hits": row[0], "misses": row[1]} for name, row in self._by_cache.items()
            }

    def reset(self) -> None:
        with self._lock:
            self._by_cache.clear()


#: The registry the request path updates and ``/api/health`` reads.
CACHES = CacheStats()


class AuthStats:
    """Counters for the bearer-token gate, and the gate's own window.

    The gate logs every rejected token and every throttled peer, but a log line
    is an event, not a rate: once it has rotated, or when the reader is a poll
    of ``/api/health``, there was nothing left to say that a peer spent its
    whole window guessing.  The refused attempts are the only reading that
    separates a scanner working through a network-reachable ``--token`` server
    from a quiet one, and ``throttled`` separates a peer that filled its window
    from one that gave up after a couple of typos.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures = 0
        self._throttled = 0

    def note_failure(self) -> None:
        """One rejected token (missing or wrong), answered 401."""
        with self._lock:
            self._failures += 1

    def note_throttled(self) -> None:
        """One request refused because the peer's window was already full."""
        with self._lock:
            self._throttled += 1

    def snapshot(self) -> dict[str, int]:
        """A JSON-ready copy of the lifetime counters."""
        with self._lock:
            return {"failures": self._failures, "throttled": self._throttled}

    def reset(self) -> None:
        with self._lock:
            self._failures = 0
            self._throttled = 0


#: The registry the auth gate updates and /api/health reads.
AUTH = AuthStats()


class ConnectionStats:
    """Admission gauge for the connection cap, plus the refusals it has made.

    The third saturation bound in the package (``devserver._MAX_CONNECTIONS``),
    and the one that was invisible.  A server at this cap answers 503 to
    everything and keeps every page rendering for the clients already on it,
    so ``/api/health`` read ``healthy`` while refusing every new tab; the only
    trace was one log line per refused accept.  ``open`` against ``max`` is the
    distance to that refusal, the same reading ``streams`` gives for the SSE
    cap, and ``refused`` separates a cap that has been full once from a server
    that has refused everything since the operator last looked.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._open = 0
        self._max = 0
        self._refused = 0

    def set_limit(self, limit: int) -> None:
        """Record the cap this process enforces, before the first accept.

        Called from ``devserver.configure_transport`` so ``max`` answers "what
        is the cap" from the moment the listener is configured, rather than
        only once a connection has been admitted.  A process that never
        reached ``serve`` leaves it 0, which is what that is: no cap is being
        enforced there.
        """
        with self._lock:
            self._max = limit

    def admit(self, limit: int) -> bool:
        """Take a slot if the map of connections has room; answer whether it did.

        *limit* is passed rather than read from a module constant so the cap
        and the gauge cannot be configured apart.
        """
        with self._lock:
            if self._open >= limit:
                self._refused += 1
                return False
            self._open += 1
            self._max = limit
            return True

    def release(self) -> None:
        with self._lock:
            self._open = max(0, self._open - 1)

    @property
    def open(self) -> int:
        """Live connections, for the admission path and the tests that wait on it."""
        with self._lock:
            return self._open

    def snapshot(self) -> dict[str, Any]:
        """A JSON-ready copy.  ``max`` is 0 until the transport is configured, so
        a mounted WSGI app that never reached ``serve`` reports no cap rather
        than one it is not enforcing."""
        with self._lock:
            return {
                "open": self._open,
                "max": self._max,
                "refused": self._refused,
            }

    def reset(self) -> None:
        """Zero the lifetime refusal count and the cap.

        ``open`` is a gauge, not a lifetime counter, and is left alone for the
        reason :meth:`RequestStats.reset` gives: a connection already accepted
        holds its slot, and zeroing it here would let that connection's
        release drive the gauge negative.  A caller that must return the gauge
        to zero releases the connections it is holding first.
        """
        with self._lock:
            self._max = 0
            self._refused = 0


#: The admission registry ``devserver`` updates and /api/health reads.
CONNECTIONS = ConnectionStats()


def route_label(path: str, rule: str | None) -> str:
    """A bounded label for *path*: its route *rule*, else its first segment."""
    if rule:
        return rule
    head = path.lstrip("/").split("/", 1)[0]
    return f"/{head}" if head else "/"
