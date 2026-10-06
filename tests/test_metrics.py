"""Request instrumentation: correlation id, RED counters, slow-request line."""

from __future__ import annotations

import contextlib
import importlib
import inspect
import itertools
import json
import logging
import pkgutil
import re
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager as ContextManager
from types import ModuleType
from typing import ClassVar
from unittest.mock import patch

import pytest
from conftest import wsgi_get, wsgi_request

from recoverage import api as _api
from recoverage import clock, metrics, server


@pytest.fixture(autouse=True)
def _reset_counters() -> None:
    """Zero the RED registry around every test in this module.

    ``RequestStats.reset`` deliberately leaves the ``in_flight`` GAUGE alone
    (a real request's release drives it down, and zeroing under it would let a
    second release go negative).  That reasoning is about the request path,
    where ``before_request``/``after_request`` always pair; most cases here
    drive ``finish()`` directly to place counts in a bucket, with no
    ``start()`` to open the matching half.  Each of those decremented the
    gauge, so a run's final gauge was minus the number of calls the whole
    module had made: a shuffled order took ``test_in_flight_returns_to_zero``
    to -237 and it asserted 1.  Reaching into the private counter is the only
    way to undo it, and it is what the next two assertions below need
    restored to be meaningful.
    """
    metrics.REQUESTS.reset()
    _zero_in_flight()
    yield
    metrics.REQUESTS.reset()
    _zero_in_flight()


def _zero_in_flight() -> None:
    # The private counter is the only handle there is: `reset()` deliberately
    # leaves the gauge alone, which is right on the request path and wrong in a
    # test module that drives `finish()` on its own.
    metrics.REQUESTS._in_flight = 0


def _header(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup: bottle title-cases what it stores."""
    return next((v for k, v in headers.items() if k.lower() == name.lower()), "")


def _health() -> dict:
    status, _headers, body = wsgi_get("/api/health")
    assert status.startswith("200"), status
    return json.loads(body)


_STEP = 2.0


def _one_slow_request(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> list[logging.LogRecord]:
    """Drive one request over the slow threshold on the clock, not in real time.

    Each read of the patched clock advances by ``_STEP`` seconds, so the
    duration the request is recorded with is a whole multiple of it — a figure a
    real wall-clock read could not have produced — and nothing here sleeps, so
    the same numbers come out on a loaded machine as on an idle one.
    """
    reads = [0]

    def _fake_monotonic() -> float:
        reads[0] += 1
        return 1.0 + _STEP * reads[0]

    monkeypatch.setattr(clock, "monotonic", _fake_monotonic)
    with caplog.at_level(logging.WARNING, logger="recoverage"):
        wsgi_get("/api/health")
    return [r for r in caplog.records if "Slow request" in r.getMessage()]


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

    def test_every_module_logs_on_the_package_logger(self) -> None:
        """No module names itself, or it silently loses the correlation.

        ``Logger.handle`` runs the filters of the logger a record was logged
        ON and never an ancestor's, so ``getLogger(__name__)`` gives a module
        a stream but no ``rid``: every line it writes renders ``[rid=-]`` and
        the operator cannot join it to the request that produced it.
        ``documents.py`` did exactly that, which is why the coverage-document
        warnings, the ones naming the broken file, were uncorrelatable from
        the 503 they explain.
        """
        from recoverage import api, cli, devserver, disasm, documents, potato, server, ui

        offenders = sorted(
            module.__name__
            for module in (api, cli, devserver, disasm, documents, potato, server, ui)
            if getattr(module, "_log", None) is not None and module._log.name != "recoverage"
        )
        assert offenders == [], (
            f"these modules log on a logger the request-id filter never sees: {offenders}"
        )

    def test_a_module_line_is_stamped_mid_request(self, caplog: pytest.LogCaptureFixture) -> None:
        """A line written from another module mid-request carries the id.

        The filter reads thread-local state rather than the request scope, so
        any module logging inside a handler gets the same id the response
        header echoed, which is the pivot from a client's report to the log.
        """
        from recoverage import documents

        with caplog.at_level(logging.WARNING, logger="recoverage"):
            server._REQUEST_TLS.request_id = "mid-request"
            try:
                documents._log.warning("a module line inside a request")
            finally:
                server._REQUEST_TLS.request_id = None
        stamped = [r for r in caplog.records if r.getMessage() == "a module line inside a request"]
        assert stamped, "the line reached no handler"
        assert stamped[0].request_id == "mid-request"


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
        clock read at the two ends of it are ``_STEP`` seconds apart.
        """
        assert _one_slow_request(monkeypatch, caplog)
        requests = _health()["requests"]
        assert requests["slow"] >= 1
        max_ms = max(float(row["max_ms"]) for row in requests["by_route"].values())
        assert max_ms % (_STEP * 1000.0) == 0.0

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
        slow = _one_slow_request(monkeypatch, caplog)
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


class TestRegenOutcomeCounters:
    """A refused run is neither a success nor a failure.

    `RegenStats.finish(None)` closes the in-flight gauge and records the
    elapsed time while counting the run under neither bucket. It is the
    outcome of a regen another process already holds the lock on: nothing was
    written and nothing broke, and filing it under `failures` put a red
    "Regen failed" line (and a broken-pipeline reading in /api/health) on
    every overlap between a cron job and a dashboard's own regenerate.
    """

    def test_a_refused_run_closes_the_gauge_without_failing(self) -> None:
        metrics.REGEN.reset()
        metrics.REGEN.start()
        metrics.REGEN.finish(None, 12.0)
        metrics.REGEN.reject()
        snap = metrics.REGEN.snapshot()
        assert snap["in_flight"] == 0
        assert snap["failures"] == 0
        assert snap["rejected"] == 1
        assert snap["runs"] == 1
        assert snap["last_ok"] is None
        assert snap["last_duration_ms"] == 12.0


class TestTargetsFallbackLogging:
    """/api/targets logs the config-only fallback on a transition, not a poll.

    It is the one request the SPA cannot avoid and the shell preloads, so a
    broken coverage directory wrote one WARNING per page load for as long as
    it stayed broken. The same rule `api._log_health_status` follows for the
    health probe: the outage is the news, the recovery closes it, and the
    repeats say nothing.
    """

    def _reason(self, text: str) -> str:
        from rebrew.coverage_toml import CoverageTomlError

        _api._log_targets_fallback(CoverageTomlError(text))
        return text

    def test_the_repeat_is_silent_and_the_recovery_is_logged(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "_targets_fallback_reported", None)
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            self._reason("first outage")
            self._reason("first outage")
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1, warnings
        assert "first outage" in warnings[0]

        caplog.clear()
        with caplog.at_level(logging.INFO, logger="recoverage"):
            api._clear_targets_fallback()
            api._clear_targets_fallback()
        infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
        assert len(infos) == 1, infos
        assert "no longer config-only" in infos[0]

        # A second outage after the recovery is news again, not a repeat.
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            self._reason("second outage")
        assert [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING] == [
            (
                "Coverage unavailable reading the target list, falling back to the "
                "config-only list: CoverageTomlError: second outage"
            )
        ]

    def test_the_message_is_escaped(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A coverage document's own parse error is untrusted text.

        `server._db_unavailable_err` escapes the same value for the API; an
        escaped line is one entry, and a raw one is two, with the operator
        reading whichever half the attacker chose.
        """
        import recoverage.api as api

        # Through monkeypatch, not a bare assignment: the latch is a process
        # global whose value outlives this test, so writing `None` here leaves
        # the next test inheriting a "no outage open" state it never set.  The
        # sibling test above and every `_health_reported` case in test_api.py
        # restore through the same mechanism.
        monkeypatch.setattr(api, "_targets_fallback_reported", None)
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            self._reason("line one\nINJECTED: pwned")
        messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert messages and not any("\n" in m for m in messages), messages


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

    def test_percentile_of_an_even_window_takes_the_upper_middle(self) -> None:
        """The p50 of six samples is the fourth, not the third.

        `round` is banker's rounding, so the scaled position of a p50 over an
        even-length window lands on exactly .5 and it answered 2 where the
        median is 3. Banker's rounding also put the p95 a full sample low on
        a window whose length makes its position odd, which reads as "the tail
        is fine" on a window that is one request short of it.
        """
        samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
        assert metrics.percentile(samples, 0.50) == 4.0
        # 0.95 * 5 = 4.75: a half-up floor lands on the last sample, where
        # banker's rounding read 4.0 and reported the second-slowest request
        # as the 95th percentile.
        assert metrics.percentile(samples, 0.95) == 6.0
        assert metrics.percentile(samples, 0.0) == 1.0
        assert metrics.percentile(samples, 1.0) == 6.0

    def test_percentile_clamps_a_fraction_outside_the_unit_range(self) -> None:
        """An out-of-range share indexes an end rather than raising."""
        samples = [1.0, 2.0, 3.0, 4.0]
        assert metrics.percentile(samples, -1.0) == 1.0
        assert metrics.percentile(samples, 2.0) == 4.0

    def test_a_median_over_an_even_window_is_the_upper_middle_sample(self) -> None:
        """The snapshot's own p50 over an even window agrees with percentile()."""
        for duration in (1.0, 2.0, 3.0, 4.0, 5.0, 6.0):
            metrics.REQUESTS.finish("/api/targets", 200, duration)
        snap = metrics.REQUESTS.snapshot()
        assert snap["latency_window"] == 6
        assert snap["p50_ms"] == 4.0

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


#: Sentinel for "this container declares no bound", so a bound that IS None
#: (which bounds nothing) stays distinguishable from one never written.
_NOT_FOUND = object()

#: The type names of the containers this check reads. `frozenset` is absent on
#: purpose: one built at import time holds a constant number of rows and
#: nothing inserts into it, so it is the case the scan must not flag.
_CONTAINER_KINDS = frozenset(
    {"dict", "list", "set", "Queue", "deque", "defaultdict", "OrderedDict", "Counter"}
)


class TestProcessGrowthIsBounded:
    """No container a request fills may grow without a bound.

    `serve` runs for days. A map, set or queue the request path inserts into
    and no path empties is an OOM with a slow fuse, and it is the kind of
    defect that never reproduces in a test suite: tests exit long before the
    accumulation matters. So the property is held against the CODE, not
    against a run.

    It is not that every container has a cap. Most of them are static: a
    colour table, the log-escape map, the sort-column map. A container nothing
    in the package inserts into cannot grow, and writing a bound beside a
    21-row table would be a constant that lies. The property is the pair: a
    container with no insertion anywhere is static, and one WITH an insertion
    must name the bound that stops it.

    Insertion sites are found, not inferred from the name — `DLL_DATA` and
    `_auth_failures` do not read like caches and both grow. Classifying by
    name would let a leak in under a plain name, and would demand a constant
    beside every constant.
    """

    #: Insertions that add an element to a container. A subscript is not among
    #: them: `NAME[` is a READ for most dicts in the tree and an insertion for
    #: only some, so subscript sites are read through the source instead
    #: (`_growing_containers`).
    _INSERTIONS: ClassVar[tuple[str, ...]] = (
        ".append(",
        ".add(",
        ".extend(",
        ".setdefault(",
        ".update(",
        ".insert(",
        ".put(",
        ".appendleft(",
    )

    #: Every container the package inserts into, and the bound that stops each.
    #: `count` is a cap an eviction path compares the container's size against;
    #: `seconds` is a per-ROW deadline a prune reclaims on the next touch;
    #: `peers` is a cap the transport enforces by REFUSING a connection, so
    #: the container never reaches it; `keys` is a closed key space, spelled
    #: either as a fixed enumeration or as the project config; `imports` is a
    #: list the composition root fills once per route module at import,
    #: closed by the import graph.
    #: Read the binding site before adding a row: a bound with no enforcement
    #: behind it is a note about an intention.
    _BOUNDED: ClassVar[dict[str, tuple[str, str]]] = {
        # /api/data payloads, keyed on target+section; the leader publishes
        # and a rebuild empties it.
        "recoverage.api._DATA_CACHE": ("_DATA_CACHE_MAX", "count"),
        # /api/stats payloads, keyed on target.
        "recoverage.api._STATS_CACHE": ("_STATS_CACHE_MAX", "count"),
        # The total-count memo behind a paginated function list.
        "recoverage.api._LIST_TOTAL_CACHE": ("_LIST_TOTAL_CACHE_MAX", "count"),
        # Function and global detail bodies, keyed on snapshot, target and the
        # requested spelling.
        "recoverage.api._FUNCTION_CACHE": ("_FUNCTION_CACHE_MAX", "count"),
        # The idempotency ledger for POST /api/regen, and the in-flight marker
        # beside it, both keyed on the client's own key.
        "recoverage.api._REGEN_COMPLETED_KEYS": ("_REGEN_LEDGER_MAX_ENTRIES", "count"),
        "recoverage.api._REGEN_ACTIVE_KEYS": ("_REGEN_LEDGER_MAX_ENTRIES", "count"),
        # The /data single-flight claim. A build in flight is not a row to
        # count — dropping a LIVE leader's claim on a size would run a second
        # build beside it — so a claim is bounded by the instant past which a
        # prune reclaims it, and a killed owner's claim costs one slot until
        # then.
        "recoverage.api._DATA_CACHE_BUILDING": ("_DATA_CACHE_BUILD_WAIT_SECONDS", "seconds"),
        # One row per CONNECTED client, capped by the refusal at the transport
        # rather than by an eviction.
        "recoverage.api._SSE_CLIENTS": ("_SSE_MAX_CLIENTS", "peers"),
        # One window per peer that has failed a token guess, capped by the
        # same map's own peer bound.
        "recoverage.server._auth_failures": ("_AUTH_FAIL_MAX_PEERS", "peers"),
        # Per-target image width, memoized on the binary's stamp and dropped
        # beside the disassembly memo on a rebuild.
        "recoverage.disasm._WIDTH_MEMO": ("_WIDTH_MEMO_MAX", "count"),
        "recoverage.potato._GRID_CACHE": ("_GRID_CACHE_MAX", "count"),
        "recoverage.potato._PARENT_INDEX": ("_PARENT_INDEX_MAX", "count"),
        "recoverage.potato._POTATO_STATS_CACHE": ("_POTATO_STATS_CACHE_MAX", "count"),
        "recoverage.potato._SECTION_DATA_CACHE": ("_SECTION_DATA_CACHE_MAX", "count"),
        # The snapshot-keyed derived tables (by-VA indices, the folded search
        # columns, the marker-free function rows) the /asm, /bytes, search and
        # list endpoints read. `function_rows` is one of these kinds: it moved
        # here from `potato._FUNCTION_ROWS` when the API list endpoint started
        # reading the same derived set instead of re-deriving it per request.
        "recoverage.server._SNAPSHOT_INDEX": ("_SNAPSHOT_INDEX_MAX", "count"),
        # The route module's cache invalidators, registered once per route
        # module by the composition root at import. No bound constant: the
        # list is closed by the import graph, which `tests/test_import_graph.py`
        # already holds acyclic and level-ordered.
        "recoverage.api._EXTRA_INVALIDATORS": ("", "imports"),
        # The original binary's bytes, and the stamp each was read under.
        # Keyed on target alone, so the map is at most one entry per entry in
        # `[targets]`: every reader validates its target against the resolved
        # config first (`api._target_snapshot`, Potato's render), and a config
        # edit that changes the vocabulary clears both maps on the
        # `config_fingerprint` they are keyed beside. `recoverage.api.DLL_DATA`
        # is the same dict under an import alias, and the eviction is the same.
        "recoverage.server.DLL_DATA": ("", "keys"),
        "recoverage.server._DLL_STAMPS": ("", "keys"),
        # One precompressed SPA shell per accepted-encoding set. The key is
        # `static_variant_key`, which draws from `SUPPORTED_ENCODINGS` in that
        # fixed order, so it is at most 2**3 spellings however long the header
        # the client sends is. The shell cannot change under a running server,
        # so the map never needs emptying; the closed key space is the bound.
        "recoverage.ui.CACHED_INDEX_COMPRESSED": ("SUPPORTED_ENCODINGS", "keys"),
        "recoverage.ui._STATIC_CACHE": ("SUPPORTED_ENCODINGS", "keys"),
    }

    #: For each `keys` row, the function that turns a request-supplied value
    #: into a key. The key space is only closed if every key passes through
    #: it, so this is the claim the arm below checks rather than restates.
    _KEY_PRODUCERS: ClassVar[dict[str, str]] = {
        "recoverage.server.DLL_DATA": "server._find_dll_path",
        "recoverage.server._DLL_STAMPS": "server._find_dll_path",
        "recoverage.ui.CACHED_INDEX_COMPRESSED": "server.static_variant_key",
        "recoverage.ui._STATIC_CACHE": "server.static_variant_key",
    }

    def _modules(self) -> list[ModuleType]:
        """Every module in the package, walked from the composition root.

        An unreferenced module is still a module `serve` imported, and its
        containers grow on the same clock as the rest; walking is what stops a
        new module from being outside the check by being new.
        """
        pending = [importlib.import_module("recoverage")]
        seen: set[str] = set()
        out: list[ModuleType] = []
        while pending:
            module = pending.pop()
            if module.__name__ in seen:
                continue
            seen.add(module.__name__)
            out.append(module)
            # `pkgutil.walk_packages` needs a package path, and a module
            # without one (`__main__`, a leaf like `webapp` when the root is
            # imported as a module) is still a module whose globals can hold a
            # growing container.
            paths = getattr(module, "__path__", None)
            for info in pkgutil.walk_packages(paths, module.__name__ + ".") if paths else ():
                try:
                    pending.append(importlib.import_module(info.name))
                except Exception:
                    continue
        return out

    def _source(self, module: ModuleType) -> str:
        try:
            return inspect.getsource(module)
        except (OSError, TypeError):
            return ""

    def _growing_containers(self) -> dict[str, str]:
        """Every container the package inserts into, by qualified name.

        The union of two scans: a method call ON the container, and an
        assignment into it by subscript. A container neither scan names holds
        a fixed set of rows and cannot grow. The value is the source that
        inserted into it, for the message to name.
        """
        growing: dict[str, str] = {}
        for module in self._modules():
            source = self._source(module)
            if not source:
                continue
            for name, value in vars(module).items():
                if name.startswith("__") or type(value).__name__ not in _CONTAINER_KINDS:
                    continue
                qualified = f"{module.__name__}.{name}"
                if any(f"{name}{call}" in source for call in self._INSERTIONS):
                    growing[qualified] = source
                    continue
                # `NAME[key] = value` inserts into NAME; `NAME[a][b] = c`
                # inserts into NAME's VALUES, so only a plain subscript whose
                # contents close on the first bracket counts.
                if re.search(
                    rf"^[ \t]*{re.escape(name)}\[[^\]\n]*\]\s*=(?!=)", source, re.MULTILINE
                ):
                    growing[qualified] = source
        return growing

    def test_every_container_the_package_fills_is_bounded(self) -> None:
        growing = self._growing_containers()
        assert growing, "no insertion found anywhere, so the scan is not reading the package"
        for qualified in sorted(growing):
            if qualified in self._BOUNDED:
                continue
            raise AssertionError(
                f"{qualified} is inserted into and declares no bound. Add it to "
                f"TestProcessGrowthIsBounded._BOUNDED with the constant that stops "
                f"it and the kind of bound it is, or — if the scan misread a "
                f"static table as growing — fix the scan, because a check that "
                f"cannot read its own tree is not one."
            )

    def test_a_declared_bound_exists(self) -> None:
        """A bound that is missing, None, zero or negative bounds nothing."""
        for qualified, (constant, kind) in self._BOUNDED.items():
            if not constant:
                continue  # an `imports` row: closed by the import graph
            if kind == "keys":
                continue  # a vocabulary, checked by the arm that reads it
            module_name, _, _attr = qualified.rpartition(".")
            module = importlib.import_module(module_name)
            bound = getattr(module, constant, _NOT_FOUND)
            assert bound is not _NOT_FOUND, (
                f"{qualified} is registered as bounded by {constant}, which "
                f"{module_name} does not define"
            )
            assert isinstance(bound, int | float) and not isinstance(bound, bool), (
                f"{qualified} is capped by {constant}={bound!r}, which is not a "
                f"number: the container fills past a cap that cannot be compared"
            )
            assert bound > 0, (
                f"{qualified} is capped by {constant}={bound!r}, which is not "
                f"positive: a cap of zero bounds nothing while the name reads "
                f"like a bound"
            )

    def test_a_count_bound_is_a_whole_number_of_rows(self) -> None:
        """A `count` bounds how many rows fit, so a fraction is not one."""
        for qualified, (constant, kind) in self._BOUNDED.items():
            if kind != "count":
                continue
            module_name, _, _attr = qualified.rpartition(".")
            bound = getattr(importlib.import_module(module_name), constant)
            assert isinstance(bound, int) and not isinstance(bound, bool), (
                f"{qualified} is bounded by {constant}={bound!r}, which is not "
                f"a whole number of rows"
            )

    def test_a_keys_bound_is_closed_over_a_vocabulary_the_code_resolves(self) -> None:
        """A `keys` row claims the key space cannot grow, in one of two ways.

        Either the keys are drawn from a fixed spelling set — a precompressed
        variant keyed on the accepted-encoding set, which is at most one key
        per subset of a seven-constant vocabulary — or they are drawn from the
        project config's `[targets]`, which the config itself closes, and the
        map is emptied when that config changes. The first is a finite
        enumeration, the second a vocabulary with an eviction.

        What neither allows is a key taken from the request. A map keyed on a
        client-supplied value is unbounded however it is named, so the arm
        checks the thing that decides: the writing site maps the request value
        through a named producer, and the producer reads the vocabulary the
        bound names.
        """
        for qualified, (constant, kind) in self._BOUNDED.items():
            if kind != "keys":
                continue
            module_name, _, attr = qualified.rpartition(".")
            module = importlib.import_module(module_name)
            source = self._source(module)
            producer_name = self._KEY_PRODUCERS[qualified]
            producer_module_name, _, producer_attr = producer_name.rpartition(".")
            producer_module = importlib.import_module(
                producer_module_name
                if producer_module_name.startswith("recoverage")
                else f"recoverage.{producer_module_name}"
            )
            producer = getattr(producer_module, producer_attr, None)
            assert callable(producer), (
                f"{qualified} names {producer_name} as the function mapping a "
                f"request value into its closed key space, and no such function "
                f"exists"
            )
            assert re.search(rf"\b{re.escape(producer_attr)}\(", source), (
                f"{qualified} never calls {producer_name}, so its keys are not "
                f"the closed set the bound claims"
            )
            if not constant:
                # Closed over the project config: the map must be emptied when
                # that config changes, or an entry outlives the configuration
                # that authorised it. `server._clear_derived_caches` is the
                # `config_fingerprint` arm that does it.
                assert re.search(rf"{re.escape(attr)}\.clear\(", source), (
                    f"{qualified} is bounded by a key space the project config "
                    f"closes, but {module_name} never empties it: a removed "
                    f"target's bytes outlive the config that named them"
                )
                continue
            vocabulary = constant.rpartition(".")[2]
            assert vocabulary in (self._source(producer_module) or ""), (
                f"{qualified} is bounded by {constant}, but {producer_name} never "
                f"reads it: the producer is what makes the key space finite, and "
                f"it draws its values from somewhere else"
            )

    def test_a_seconds_bound_names_a_deadline_not_a_count(self) -> None:
        """A `seconds` bound is a duration, so a whole number of seconds reads
        like the wrong unit: 30 rows is a different claim from 30 seconds."""
        for qualified, (constant, kind) in self._BOUNDED.items():
            if kind != "seconds":
                continue
            module_name, _, _attr = qualified.rpartition(".")
            bound = getattr(importlib.import_module(module_name), constant)
            assert isinstance(bound, float), (
                f"{qualified} is bounded by {constant}={bound!r}, which is not "
                f"a duration: a `seconds` bound is read as a float interval "
                f"throughout the package, and an int here would read as a row "
                f"count to the next reader"
            )
