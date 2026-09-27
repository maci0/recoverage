"""In-process RED counters for the dashboard server.

The server is a single process serving one operator (or one team behind a
shared ``coverage.db``).  There is no metrics backend to push to, so the
numbers live in memory and are read back through ``/api/health``: request
count, error count, slow-request count, and the latency extremes needed to
tell "one slow request" from "every request got slower".

Cardinality is bounded on purpose.  Routes are bucketed by their Bottle rule
(``/api/targets/<target>/data``), never by the raw path, so a caller cannot
grow the map by inventing target names; anything that reaches a handler
without a rule falls back to its first path segment.
"""

from __future__ import annotations

import threading
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
        self._timed = 0
        self._by_route: dict[str, dict[str, int]] = {}
        self._by_status: dict[str, int] = {}

    def start(self) -> None:
        self._lock.acquire()
        try:
            self._in_flight += 1
        finally:
            self._lock.release()

    def finish(self, route: str, status: int, duration_ms: float, timed: bool = True) -> None:
        """Record one completed request.

        *timed* is False for the routes whose response is held open: their
        duration is connection lifetime, so it updates the counters but not
        the latency extremes.
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
            bucket = f"{status // 100}xx"
            self._by_status[bucket] = self._by_status.get(bucket, 0) + 1
            route_row = self._by_route.setdefault(
                route, {"requests": 0, "errors": 0, "max_ms": 0.0}
            )
            route_row["requests"] += 1
            if status >= 500:
                route_row["errors"] += 1
            if timed:
                route_row["max_ms"] = max(float(route_row["max_ms"]), duration_ms)

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
                row["errors"] += delta

    def snapshot(self) -> dict[str, Any]:
        """A JSON-ready copy of the counters.

        ``mean_ms`` is a lifetime average over every timed request, so it
        moves when the workload changes.  The mean divides by the timed
        count, not by ``total``, so a connection held open by an
        :data:`UNBOUNDED_ROUTES` route is counted in ``total`` and absent
        from the sum, and drags neither figure down.  ``max_ms`` is the
        worst single timed request since start.  Neither is a percentile:
        keeping every sample to compute one would cost more than the number
        is worth here.  ``in_flight`` counts requests currently inside a
        handler, so a snapshot taken from ``/api/health`` includes the
        request asking.
        """
        with self._lock:
            mean = self._sum_ms / self._timed if self._timed else 0.0
            return {
                "total": self._total,
                "errors": self._errors,
                "slow": self._slow,
                "in_flight": self._in_flight,
                "slow_threshold_ms": SLOW_REQUEST_MS,
                "mean_ms": round(mean, 3),
                "max_ms": round(self._max_ms, 3),
                "by_status": dict(self._by_status),
                "by_route": {
                    route: {
                        "requests": row["requests"],
                        "errors": row["errors"],
                        "max_ms": round(float(row["max_ms"]), 3),
                    }
                    for route, row in sorted(self._by_route.items())
                },
            }

    def reset(self) -> None:
        with self._lock:
            self._total = 0
            self._errors = 0
            self._slow = 0
            self._sum_ms = 0.0
            self._timed = 0
            self._max_ms = 0.0
            self._timed = 0
            self._by_route.clear()
            self._by_status.clear()


#: The process-wide registry the hooks update and /api/health reads.
REQUESTS = RequestStats()


def route_label(path: str, rule: str | None) -> str:
    """A bounded label for *path*: its route *rule*, else its first segment."""
    if rule:
        return rule
    head = path.lstrip("/").split("/", 1)[0]
    return f"/{head}" if head else "/"
