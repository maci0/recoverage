"""Request instrumentation: correlation id, RED counters, slow-request line."""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager as ContextManager

import pytest
from conftest import wsgi_get

from recoverage import api as _api
from recoverage import clock, metrics, server


@pytest.fixture(autouse=True)
def _reset_counters() -> None:
    metrics.REQUESTS.reset()
    yield
    metrics.REQUESTS.reset()


def _header(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup: bottle title-cases what it stores."""
    return next((v for k, v in headers.items() if k.lower() == name.lower()), "")


def _health() -> dict:
    status, _headers, body = wsgi_get("/api/health")
    assert status.startswith("200"), status
    return json.loads(body)


@contextlib.contextmanager
def _swap_route(rule: str, wrapper: Callable[[Callable], object]) -> Iterator[None]:
    for route in server.app.routes:
        if route.rule == rule and "GET" in route.method:
            break
    else:
        raise AssertionError(f"no GET route for {rule}")
    original = route.callback
    route.callback = wrapper(original)  # type: ignore[method-assign]
    # bottle caches the plugin-wrapped callback on the route, so swapping
    # self.callback alone would keep serving the old one.
    route.reset()
    try:
        yield
    finally:
        route.callback = original
        route.reset()


@pytest.fixture
def replace_route() -> Swap:
    """Temporarily swap a route's callback, as a context manager."""
    return _swap_route


def _boom(original: Callable) -> object:
    def _handler() -> object:
        raise ValueError("instrumented failure")

    return _handler


#: What the ``replace_route`` fixture hands a test: install ``wrapper`` over
#: the route serving ``rule`` for the duration of a ``with`` block.
Swap = Callable[[str, Callable[[Callable], object]], ContextManager[None]]


class TestRequestId:
    def test_generated_id_is_echoed(self) -> None:
        status, headers, _ = wsgi_get("/api/health")
        assert status.startswith("200"), status
        assert _header(headers, "X-Request-ID")

    def test_caller_supplied_id_is_reused(self) -> None:
        _status, headers, _ = wsgi_get("/api/health", headers={"X-Request-ID": "abc123"})
        assert _header(headers, "X-Request-ID") == "abc123"

    def test_hostile_id_cannot_forge_a_log_line(self) -> None:
        _status, headers, _ = wsgi_get("/api/health", headers={"X-Request-ID": "a\nb c"})
        echoed = _header(headers, "X-Request-ID")
        assert "\n" not in echoed
        assert echoed.startswith("a\\x0ab")

    def test_long_id_is_capped(self) -> None:
        _status, headers, _ = wsgi_get("/api/health", headers={"X-Request-ID": "x" * 500})
        assert len(_header(headers, "X-Request-ID")) == server._REQUEST_ID_MAX_LEN

    def test_error_log_carries_the_id(
        self, replace_route: Swap, caplog: pytest.LogCaptureFixture
    ) -> None:
        with (
            replace_route("/api/health", _boom),
            caplog.at_level(logging.ERROR, logger="recoverage"),
        ):
            wsgi_get("/api/health", headers={"X-Request-ID": "trace-me"})
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert errors, "the unhandled error produced no log record"
        assert errors[0].request_id == "trace-me"
        assert errors[0].exc_info is not None, "the traceback did not reach the log"


class TestRedCounters:
    def test_health_reports_the_counters(self) -> None:
        body = _health()
        # The snapshot is built inside the handler, before after_request
        # files this request, so it describes everything before it.
        assert body["requests"]["total"] == 0
        assert _health()["requests"]["total"] == 1
        # Read from inside a request, so it counts the one asking.
        assert _health()["requests"]["in_flight"] >= 1
        assert body["requests"]["slow_threshold_ms"] == metrics.SLOW_REQUEST_MS

    def test_client_error_is_counted_as_4xx(self) -> None:
        wsgi_get("/api/no-such-endpoint")
        body = _health()
        assert body["requests"]["by_status"]["4xx"] >= 1
        assert body["requests"]["errors"] == 0

    def test_unhandled_exception_is_counted_as_5xx(self, replace_route: Swap) -> None:
        with replace_route("/api/health", _boom):
            status, _headers, _ = wsgi_get("/api/health")
        assert status.startswith("500"), status
        body = _health()
        assert body["requests"]["by_status"]["5xx"] >= 1
        assert body["requests"]["errors"] >= 1

    def test_db_failure_is_counted_as_503(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.coverage_toml import CoverageTomlError

        def _raise() -> None:
            raise CoverageTomlError("no readable coverage document")

        # The coverage read is what a target-scoped handler runs first, so
        # patching it is the "the storage layer cannot answer" fault this test
        # is about; it used to be a sqlite3.OperationalError out of `_db`.
        monkeypatch.setattr(_api, "resolve_targets", _raise)
        status, _headers, _ = wsgi_get("/api/targets/FAKEDLL/stats")
        assert status.startswith("503"), status
        body = _health()
        assert body["requests"]["by_status"]["5xx"] >= 1
        assert body["requests"]["errors"] >= 1

    def test_routes_are_bucketed_by_rule_not_by_path(self) -> None:
        wsgi_get("/api/does-not-exist-one")
        wsgi_get("/api/does-not-exist-two")
        body = _health()
        # Both misses land on the one catch-all rule, so the map cannot grow
        # with whatever path a caller invents.
        assert "/api/does-not-exist-one" not in body["requests"]["by_route"]
        assert body["requests"]["by_route"]

    def test_duration_comes_from_the_patched_clock(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A request crosses the threshold on the clock, not on real time.

        The handler runs in microseconds; the request is slow because the
        clock read at the two ends of it are two seconds apart.  The recorded
        duration is therefore a whole multiple of the fake step, which a real
        wall-clock read could not produce, and nothing here sleeps, so the same
        numbers come out on a loaded machine as on an idle one.
        """
        step = 2.0
        reads = [0]

        def _fake_monotonic() -> float:
            reads[0] += 1
            return 1.0 + step * reads[0]

        monkeypatch.setattr(clock, "monotonic", _fake_monotonic)
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            wsgi_get("/api/health")
        assert any("Slow request" in r.getMessage() for r in caplog.records)
        requests = _health()["requests"]
        assert requests["slow"] >= 1
        max_ms = max(float(row["max_ms"]) for row in requests["by_route"].values())
        assert max_ms % (step * 1000.0) == 0.0

    def test_slow_request_carries_the_counters_as_fields(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The slow line is pivotable, not just readable.

        The counters name a route and a duration; the line naming WHICH requests
        were slow has to carry the same values as fields, or an operator pivots
        from the counter to a wall of prose.
        """
        step = 2.0
        reads = [0]

        def _fake_monotonic() -> float:
            reads[0] += 1
            return 1.0 + step * reads[0]

        monkeypatch.setattr(clock, "monotonic", _fake_monotonic)
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            wsgi_get("/api/health")
        slow = [r for r in caplog.records if "Slow request" in r.getMessage()]
        assert slow, "the slow request was not logged"
        fields = getattr(slow[0], server.LOG_FIELDS_ATTR)
        assert fields["method"] == "GET"
        assert fields["path"] == "/api/health"
        assert fields["status"] == 200
        assert fields["route"] == "/api/health"
        assert fields["duration_ms"] >= metrics.SLOW_REQUEST_MS

    def test_fields_are_escaped_like_the_message(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A hostile path cannot forge a line through the fields either.

        The fields are rendered as JSON after the message, so an unescaped
        newline would break the same parsers the message escaping protects.
        """
        with caplog.at_level(logging.DEBUG, logger="recoverage"):
            wsgi_get("/api/health\nX-Forged: yes")
        records = [r for r in caplog.records if r.name == "recoverage"]
        assert records, "request was not logged at all"
        for record in records:
            fields = getattr(record, server.LOG_FIELDS_ATTR, None)
            if fields is None:
                continue
            assert "\n" not in fields["path"] and "\r" not in fields["path"]


class TestCacheCounters:
    """The ``caches`` block: what the memos and the validators actually did."""

    def test_a_second_payload_serving_is_a_hit(self) -> None:
        """One cold /data, then a repeat served from the memo.

        The two shapes of slowness an operator cannot otherwise tell apart are
        a build that got slower and a memo that stopped being consulted, so the
        counter has to follow the read the handler actually served from.
        """
        metrics.CACHES.reset()
        wsgi_get("/api/targets/FAKEDLL/data?section=.text")
        first = _health()["caches"][metrics.DATA_PAYLOAD_CACHE]
        assert first == {"hits": 0, "misses": 1}, first
        wsgi_get("/api/targets/FAKEDLL/data?section=.text")
        second = _health()["caches"][metrics.DATA_PAYLOAD_CACHE]
        assert second == {"hits": 1, "misses": 1}, second

    def test_a_revalidated_request_is_a_hit(self) -> None:
        """The conditional GET is counted where it is answered.

        A 304 is the SPA's poll costing nothing; a full answer is the one that
        rebuilds.  Counting them is what makes a payload that grew expensive
        visible as a fall in revalidation rather than as a mystery.
        """
        metrics.CACHES.reset()
        status, headers, _ = wsgi_get("/api/targets/FAKEDLL/stats")
        assert status.startswith("200"), status
        etag = _header(headers, "ETag")
        assert etag
        before = _health()["caches"][metrics.REVALIDATION_CACHE]
        assert before["misses"] == 1 and before["hits"] == 0, before
        status, _headers, _ = wsgi_get(
            "/api/targets/FAKEDLL/stats", headers={"If-None-Match": etag}
        )
        assert status.startswith("304"), status
        after = _health()["caches"][metrics.REVALIDATION_CACHE]
        assert after["hits"] == 1 and after["misses"] == 1, after

    def test_the_stats_memo_is_counted_both_ways(self) -> None:
        metrics.CACHES.reset()
        wsgi_get("/api/targets/FAKEDLL/stats")
        wsgi_get("/api/targets/FAKEDLL/stats")
        row = _health()["caches"][metrics.STATS_CACHE]
        assert row == {"hits": 1, "misses": 1}, row


class TestStats:
    def test_in_flight_returns_to_zero(self) -> None:
        metrics.REQUESTS.start()
        assert metrics.REQUESTS.snapshot()["in_flight"] == 1
        metrics.REQUESTS.finish("/x", 200, 1.0)
        assert metrics.REQUESTS.snapshot()["in_flight"] == 0

    def test_reclassify_moves_the_error_to_the_right_bucket(self) -> None:
        metrics.REQUESTS.finish("/api/x", 200, 5.0)
        metrics.REQUESTS.reclassify("/api/x", 200, 503)
        snap = metrics.REQUESTS.snapshot()
        assert snap["by_status"] == {"5xx": 1}
        assert snap["errors"] == 1
        assert snap["total"] == 1
        assert snap["by_route"]["/api/x"]["errors"] == 1

    def test_reclassify_rebuckets_without_retracting_the_request(self) -> None:
        """The failed request stays counted on its route.

        `by_status` moves it between buckets, so `by_route` has to keep
        counting it: retracting it there made the per-route request counts
        stop summing to `total`, and a route whose every request failed
        reported `requests: 0, errors: 3` — an error rate no reader can
        compute and a route that looks like it was never called.
        """
        metrics.REQUESTS.finish("/api/x", 200, 5.0)
        metrics.REQUESTS.finish("/api/y", 200, 1.0)
        metrics.REQUESTS.reclassify("/api/x", 200, 503)
        snap = metrics.REQUESTS.snapshot()
        assert snap["by_route"]["/api/x"] == {"requests": 1, "errors": 1, "max_ms": 5.0}
        assert sum(r["requests"] for r in snap["by_route"].values()) == snap["total"]
        assert sum(r["errors"] for r in snap["by_route"].values()) == snap["errors"]

    def test_unbounded_route_updates_counts_but_not_latency(self) -> None:
        metrics.REQUESTS.finish("/api/events", 200, 900_000.0, timed=False)
        snap = metrics.REQUESTS.snapshot()
        assert snap["total"] == 1
        assert snap["max_ms"] == 0.0
        assert snap["slow"] == 0

    def test_held_open_route_does_not_dilute_the_mean(self) -> None:
        """mean_ms averages the timed requests only.

        A connection the server holds open by design (SSE) is excluded from
        the latency extremes, so averaging over `total` instead of the timed
        count would report a mean the same connection is not in, and an idle
        dashboard with one browser tab open reads a third of its real latency.
        """
        metrics.REQUESTS.finish("/api/events", 200, 900_000.0, timed=False)
        metrics.REQUESTS.finish("/api/targets", 200, 10.0)
        metrics.REQUESTS.finish("/api/targets", 200, 30.0)
        snap = metrics.REQUESTS.snapshot()
        assert snap["total"] == 3
        assert snap["mean_ms"] == 20.0

    def test_route_label_falls_back_to_the_first_segment(self) -> None:
        assert metrics.route_label("/api/targets/FAKEDLL/data", None) == "/api"
        assert metrics.route_label("/", None) == "/"
        assert metrics.route_label("/api/x", "/api/targets/<target>/data") == (
            "/api/targets/<target>/data"
        )

    def test_by_route_is_capped(self) -> None:
        # The unrouted fallback labels a request by its first path segment,
        # which the caller chose, so the map needs a cap of its own.
        for i in range(metrics.ROUTE_LABEL_MAX + 20):
            metrics.REQUESTS.finish(f"/seg{i}", 404, 1.0)
        snap = metrics.REQUESTS.snapshot()
        assert len(snap["by_route"]) == metrics.ROUTE_LABEL_MAX
        assert "/seg0" not in snap["by_route"]
        assert f"/seg{metrics.ROUTE_LABEL_MAX + 19}" in snap["by_route"]
        assert snap["total"] == metrics.ROUTE_LABEL_MAX + 20
        assert snap["by_status"]["4xx"] == metrics.ROUTE_LABEL_MAX + 20

    def test_unrouted_fallbacks_never_evict_a_served_route(self) -> None:
        # The cap alone does not protect the real routes: 64 caller-chosen
        # first segments is enough to push one out under oldest-first
        # eviction, blanking the breakdown an operator reads.  A fallback is
        # admitted while the map has room and dropped once it is full, so the
        # real route keeps its row and the 404s past the cap live in the
        # totals and in by_status only.
        metrics.REQUESTS.finish("/api/targets/<target>/data", 200, 1.0)
        for i in range(metrics.ROUTE_LABEL_MAX + 20):
            metrics.REQUESTS.finish(f"/seg{i}", 404, 1.0, rule_matched=False)
        snap = metrics.REQUESTS.snapshot()
        assert "/api/targets/<target>/data" in snap["by_route"]
        assert len(snap["by_route"]) == metrics.ROUTE_LABEL_MAX
        assert snap["total"] == metrics.ROUTE_LABEL_MAX + 21
        assert snap["by_status"]["4xx"] == metrics.ROUTE_LABEL_MAX + 20

    def test_a_late_rule_label_still_gets_a_row(self) -> None:
        # A real route arriving after the map is full of fallbacks keeps the
        # oldest-first eviction; the map stays bounded and serving.
        for i in range(metrics.ROUTE_LABEL_MAX):
            metrics.REQUESTS.finish(f"/seg{i}", 404, 1.0, rule_matched=False)
        metrics.REQUESTS.finish("/api/targets", 200, 1.0)
        snap = metrics.REQUESTS.snapshot()
        assert len(snap["by_route"]) == metrics.ROUTE_LABEL_MAX
        assert "/api/targets" in snap["by_route"]
        assert "/seg0" not in snap["by_route"]
