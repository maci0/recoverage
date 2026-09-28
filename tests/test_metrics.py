"""Request instrumentation: correlation id, RED counters, slow-request line."""

from __future__ import annotations

import contextlib
import itertools
import json
import logging
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager as ContextManager
from unittest.mock import patch

import pytest
from conftest import wsgi_get, wsgi_request

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

    def test_minted_ids_come_from_a_counter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A replay of the same requests mints the same ids.

        The correlation id is the one per-request value that lands in the log
        line, the response header and the RED counters, so an id drawn from OS
        entropy makes two runs of the same sequence differ before any other
        field is compared.  Minting from a counter keeps a replay diffable;
        uniqueness within the process is what the id has to give.
        """

        def mint_twice() -> list[str]:
            monkeypatch.setattr(server, "_REQUEST_ID_SEQ", itertools.count(1))
            return [server._mint_request_id(), server._mint_request_id()]

        first = mint_twice()
        assert first == mint_twice(), "the same sequence minted different ids"
        assert first[0] != first[1]
        assert all(len(value) == 12 for value in first)

    def test_minted_ids_are_unique_across_requests(self) -> None:
        minted = {server._mint_request_id() for _ in range(500)}
        assert len(minted) == 500

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
        # Read from inside a request, so it counts the one asking and no
        # other: the autouse fixture zeroes the counters, so the exact figure
        # is known.  A bound here would pass on a counter that fires twice.
        assert _health()["requests"]["in_flight"] == 1
        assert body["requests"]["slow_threshold_ms"] == metrics.SLOW_REQUEST_MS

    def test_client_error_is_counted_as_4xx(self) -> None:
        wsgi_get("/api/no-such-endpoint")
        body = _health()
        assert body["requests"]["by_status"] == {"4xx": 1}
        assert body["requests"]["errors"] == 0

    def test_unhandled_exception_is_counted_as_5xx(self, replace_route: Swap) -> None:
        with replace_route("/api/health", _boom):
            status, _headers, _ = wsgi_get("/api/health")
        assert status.startswith("500"), status
        body = _health()
        assert body["requests"]["by_status"] == {"5xx": 1}
        assert body["requests"]["errors"] == 1

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
        assert body["requests"]["by_status"] == {"5xx": 1}
        assert body["requests"]["errors"] == 1

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
        # Counting the ones that carry fields: a filter that skipped every
        # record would leave this loop with nothing to assert on and the test
        # green, which is the same as the fields never being attached.
        with_fields = [r for r in records if getattr(r, server.LOG_FIELDS_ATTR, None) is not None]
        assert with_fields, f"no log record among {len(records)} carried the fields"
        for record in with_fields:
            fields = getattr(record, server.LOG_FIELDS_ATTR)
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


class TestAuthCounters:
    """The ``auth`` block: the token gate's attempts and its live lockouts."""

    @pytest.fixture(autouse=True)
    def _token(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        monkeypatch.setattr(server, "_AUTH_TOKEN", "unit-test-token")
        metrics.AUTH.reset()
        # The connection cap is a lifetime refusal counter that feeds the
        # status, and an earlier test's refusals would hold this one at
        # degraded for a reason that has nothing to do with the gate.
        metrics.CONNECTIONS.reset()
        server._auth_failures.clear()
        yield
        metrics.AUTH.reset()
        server._auth_failures.clear()

    @staticmethod
    def _probe() -> dict:
        """The health snapshot, read by a peer the lockout does not touch.

        A verified request clears the WINDOW OF ITS OWN PEER (the mistyped-
        then-retyped operator is forgiven), so a probe over the guessing peer's
        own connection would empty the window and read healthy.  The monitor
        that has to see the lockout is a different host, and that is the case
        this reads.
        """
        status, _headers, body = wsgi_request(
            "GET",
            "/api/health",
            headers={"Authorization": "Bearer unit-test-token"},
            remote_addr="127.0.0.2",
        )
        assert status.startswith("200"), status
        return json.loads(body)

    def test_a_rejected_token_is_counted_and_the_throttle_is_not(self) -> None:
        status, _headers, _ = wsgi_get("/api/health", headers={"Authorization": "Bearer wrong"})
        assert status.startswith("401"), status
        block = self._probe()["auth"]
        assert block["failures"] == 1, block
        assert block["throttled"] == 0, block

    def test_a_full_window_is_a_throttle_and_turns_the_probe_degraded(self) -> None:
        """The attempts past a full window are the ones nothing else records.

        A peer that spent its window is answered 429, which is not a 5xx, lands
        in no ``by_status`` an operator alerts on, and would otherwise be one
        DEBUG line per attempt: the counter and the gauge are the only reading
        that a network-reachable server is being guessed at.
        """
        bad = {"Authorization": "Bearer wrong", "Accept": "application/json"}
        for _ in range(server._AUTH_FAIL_MAX):
            assert wsgi_get("/api/health", headers=bad)[0].startswith("401")
        assert wsgi_get("/api/health", headers=bad)[0].startswith("429")
        health = self._probe()
        block = health["auth"]
        assert block["throttled"] == 1, block
        assert block["locked_peers"] == 1, block
        assert health["status"] == "degraded", health["status"]

    def test_a_window_that_has_expired_stops_the_degraded_reading(self) -> None:
        """The gauge drops with the window, so health recovers on its own.

        A lifetime count cannot be the degradation trigger: one typo an hour
        ago would hold every probe at ``degraded`` until the process restarted.
        """
        bad = {"Authorization": "Bearer wrong", "Accept": "application/json"}
        for _ in range(server._AUTH_FAIL_MAX + 1):
            wsgi_get("/api/health", headers=bad)
        assert self._probe()["status"] == "degraded"
        with patch.object(clock, "monotonic", return_value=clock.monotonic() + 120.0):
            health = self._probe()
        assert health["auth"]["locked_peers"] == 0, health["auth"]
        assert health["status"] == "healthy", health
        # The lifetime counters do NOT follow the window: they are the record
        # of what happened, which is what a rotated log line no longer says.
        assert health["auth"]["failures"] >= server._AUTH_FAIL_MAX, health["auth"]


class TestTransportRejectionCount:
    """A request refused before any route ran still reaches a counter."""

    def test_a_transport_rejection_is_counted_and_leaves_the_request_totals(self) -> None:
        from recoverage import devserver

        handler = object.__new__(devserver._QuietTimeoutRequestHandler)
        handler.client_address = ("127.0.0.1", 51234)  # type: ignore[attr-defined]
        before = metrics.REQUESTS.snapshot()
        devserver._QuietTimeoutRequestHandler.log_error(handler, "Bad request syntax (%r)", "!")
        after = metrics.REQUESTS.snapshot()
        assert after["transport_rejected"] == before["transport_rejected"] + 1
        # There is no route, no status and no duration to file it under, so
        # it must not perturb the counters a request rate is computed from.
        assert after["total"] == before["total"]
        assert after["by_status"] == before["by_status"]
        after = _health()["requests"]
        assert after["transport_rejected"] == before["transport_rejected"] + 1
        # There is no route, no status and no duration to file it under, so
        # it must not perturb the counters a request rate is computed from.
        assert after["total"] == before["total"]
        assert after["by_status"] == before["by_status"]


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
        assert snap["by_route"]["/api/x"] == {
            "requests": 1,
            "errors": 1,
            "max_ms": 5.0,
            "latency_window": 1,
            "p50_ms": 5.0,
            "p95_ms": 5.0,
        }
        assert sum(r["requests"] for r in snap["by_route"].values()) == snap["total"]
        assert sum(r["errors"] for r in snap["by_route"].values()) == snap["errors"]

    def test_reclassify_out_of_the_5xx_bucket_takes_the_error_back(self) -> None:
        """The negative delta arm, and the equality guard beside it.

        `reclassify` is documented to move the error with the request, so a
        5xx reclassified as a 4xx has to give the error back: an
        implementation that always added one would report an error rate above
        the share of requests that errored, and one that dropped the
        `from_status == to_status` guard would delete the live `2xx` bucket
        on the way there.
        """
        metrics.REQUESTS.finish("/api/x", 500, 5.0)
        metrics.REQUESTS.reclassify("/api/x", 500, 404)
        snap = metrics.REQUESTS.snapshot()
        assert snap["by_status"] == {"4xx": 1}
        assert snap["errors"] == 0
        assert snap["total"] == 1
        assert snap["by_route"]["/api/x"]["errors"] == 0
        metrics.REQUESTS.reclassify("/api/x", 404, 404)
        snap = metrics.REQUESTS.snapshot()
        assert snap["by_status"] == {"4xx": 1}
        assert snap["total"] == 1

    def test_reset_leaves_the_in_flight_gauge_alone(self) -> None:
        """`reset` zeroes lifetime counters, not the gauge.

        The autouse fixture calls it around every test in this file while
        requests are alive, and a `reset` that zeroed the gauge would let the
        in-flight request's own `finish` drive it negative.  The reading is
        taken relative to the gauge's own value, which this file does not
        reset: the claim is that `reset` leaves it untouched, not that it is
        a particular number.
        """
        metrics.REQUESTS.start()
        metrics.REQUESTS.finish("/api/x", 500, 5.0)
        metrics.REQUESTS.start()
        held = metrics.REQUESTS.snapshot()["in_flight"]
        metrics.REQUESTS.reset()
        snap = metrics.REQUESTS.snapshot()
        assert snap["in_flight"] == held, "reset moved the in-flight gauge"
        assert snap["total"] == 0
        assert snap["by_status"] == {}
        metrics.REQUESTS.finish("/api/x", 200, 1.0)
        assert metrics.REQUESTS.snapshot()["in_flight"] == held - 1

    def test_unbounded_route_updates_counts_but_not_latency(self) -> None:
        metrics.REQUESTS.finish("/api/events", 200, 900_000.0, timed=False)
        snap = metrics.REQUESTS.snapshot()
        assert snap["total"] == 1
        assert snap["max_ms"] == 0.0
        assert snap["slow"] == 0
        assert snap["latency_window"] == 0
        assert snap["p95_ms"] == 0.0

    def test_percentiles_separate_a_slow_tail_from_a_fast_window(self) -> None:
        """p50/p95 answer "is every request slow now", the mean cannot.

        One slow request in a window of fast ones moves the mean a little and
        the max all the way, so neither separates a single slow read from a
        server where every read got slower. The p95 sits on the slow side of
        that line and the p50 does not, which is the pair an operator reads
        while the dashboard is slow.
        """
        for _ in range(90):
            metrics.REQUESTS.finish("/api/targets", 200, 10.0)
        for _ in range(10):
            metrics.REQUESTS.finish("/api/targets", 200, 5_000.0)
        snap = metrics.REQUESTS.snapshot()
        assert snap["max_ms"] == 5_000.0
        assert snap["mean_ms"] < 1_000.0
        assert snap["p50_ms"] == 10.0
        assert snap["p95_ms"] == 5_000.0
        assert snap["latency_window"] == 100

    def test_every_recent_request_slow_raises_the_median(self) -> None:
        for _ in range(10):
            metrics.REQUESTS.finish("/api/targets", 200, 4_000.0)
        snap = metrics.REQUESTS.snapshot()
        assert snap["p50_ms"] == 4_000.0
        assert snap["p95_ms"] == 4_000.0

    def test_the_window_is_bounded_and_drops_the_oldest(self) -> None:
        """The quantiles describe the most recent requests, not the whole run.

        A slow burst an hour ago must not read as the current latency, and an
        unbounded list of every sample would grow for the life of the process.
        """
        for _ in range(metrics.LATENCY_WINDOW):
            metrics.REQUESTS.finish("/api/targets", 200, 9_000.0)
        for _ in range(metrics.LATENCY_WINDOW):
            metrics.REQUESTS.finish("/api/targets", 200, 1.0)
        snap = metrics.REQUESTS.snapshot()
        assert snap["latency_window"] == metrics.LATENCY_WINDOW
        assert snap["p95_ms"] == 1.0
        assert snap["max_ms"] == 9_000.0
        assert snap["mean_ms"] > 1_000.0

    def test_percentile_of_an_empty_sample_is_zero(self) -> None:
        assert metrics.percentile([], 0.95) == 0.0

    def test_the_slow_route_is_named_by_its_own_p95(self) -> None:
        """A process-wide p95 is only half a diagnosis.

        The operator's next question is which endpoint moved, and reading it
        off a lifetime max per route cannot answer it: one slow /data read
        makes /data look like the slow route for the rest of the process. Each
        row carries the quantiles of its own window, so the route whose p95
        sits at the slow threshold is the one to look at.
        """
        for _ in range(20):
            metrics.REQUESTS.finish("/api/targets", 200, 8.0)
        for _ in range(20):
            metrics.REQUESTS.finish("/api/targets/<target>/data", 200, 900.0)
        snap = metrics.REQUESTS.snapshot()
        assert snap["by_route"]["/api/targets"]["p95_ms"] == 8.0
        assert snap["by_route"]["/api/targets/<target>/data"]["p95_ms"] == 900.0
        assert snap["by_route"]["/api/targets"]["latency_window"] == 20

    def test_a_dropped_fallback_label_keeps_no_window(self) -> None:
        """A row refused for want of room is not admitted with stale figures."""
        for i in range(metrics.ROUTE_LABEL_MAX):
            metrics.REQUESTS.finish(f"/unknown{i}", 404, 1.0, rule_matched=False)
        metrics.REQUESTS.finish("/unknown-again", 404, 1.0, rule_matched=False)
        snap = metrics.REQUESTS.snapshot()
        assert len(snap["by_route"]) == metrics.ROUTE_LABEL_MAX
        assert "/unknown-again" not in snap["by_route"]
        assert snap["total"] == metrics.ROUTE_LABEL_MAX + 1

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
