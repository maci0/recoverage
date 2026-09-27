"""Request instrumentation: correlation id, RED counters, slow-request line."""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
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
        def _raise() -> None:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(_api, "_db", _raise)
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

    def test_route_label_falls_back_to_the_first_segment(self) -> None:
        assert metrics.route_label("/api/targets/FAKEDLL/data", None) == "/api"
        assert metrics.route_label("/", None) == "/"
        assert metrics.route_label("/api/x", "/api/targets/<target>/data") == (
            "/api/targets/<target>/data"
        )
