"""Concurrency invariants for the shared state the threaded server touches.

The package keeps its cross-request state in process globals behind one lock
each: the /data payload memo and the single-flight claim ledger beside it, the
per-snapshot and per-target memos, the RED counters, the connection admission
gauge and the auth throttle.  A defect in any of them is invisible to a
single-threaded test, because the single-threaded path is the one that works.

Each test here drives one of those paths from several threads released by a
``Barrier`` at the same instant, so the interleaving is a fact of the test
rather than a matter of timing, and asserts the property that has to hold
whatever order the threads run in: one build per herd, no error answered to a
reader that raced a rebuild, counters that balance, a cap that admits exactly
its limit, and a throttle that hands out exactly as many slots as it promises.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable, Mapping
from typing import Any

import pytest
from conftest import HAS_DB, decode_body, wsgi_get, wsgi_post

from recoverage import api, metrics
from recoverage import server as _server

pytestmark = pytest.mark.skipif(not HAS_DB, reason="needs the synthetic coverage documents")

#: Threads per concurrent test.  Enough for the check-then-act windows to be
#: reachable on a machine with any parallelism at all, few enough that the
#: suite does not spend its time on thread startup.
WORKERS = 8

#: One cold request per worker, on the connection a keep-alive client holds.
_IDENTITY = {"Accept-Encoding": "identity"}


def _in_parallel(worker: Callable[[int], None], workers: int = WORKERS) -> None:
    """Run *worker(index)* on *workers* threads, released at the same instant.

    The barrier is the point: threads that start staggered would let the
    first finish before the last begins, and the window these tests guard
    would never be open.  Every thread is joined, so a failure inside one
    surfaces here rather than as a stray exception in a later test.
    """
    barrier = threading.Barrier(workers)
    errors: list[BaseException] = []

    def run(index: int) -> None:
        try:
            barrier.wait(timeout=30)
            worker(index)
        # Re-raised on the test thread: a worker's failure is the test's.
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive(), "a concurrency worker never finished"
    if errors:
        raise errors[0]


class TestDataSingleFlight:
    """The /data memo and the claim ledger that keeps a herd to one build."""

    def test_a_concurrent_herd_builds_the_payload_exactly_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Eight simultaneous misses for one key, one build.

        Every request is a cold miss at the same instant.  Without the claim
        each materializes its own multi-MB payload, the last insert wins, and
        the memo holds whichever body happened to be published last rather
        than the one every client was answered from.  With it, the first
        thread takes the claim, the rest wait on its event, and the build runs
        once however the threads interleave.
        """
        builds = 0
        build_lock = threading.Lock()
        real_build = api._build_data_raw

        def counting_build(*args: Any, **kwargs: Any) -> bytes:
            nonlocal builds
            with build_lock:
                builds += 1
            return real_build(*args, **kwargs)

        monkeypatch.setattr(api, "_build_data_raw", counting_build)
        bodies: list[bytes] = []
        body_lock = threading.Lock()

        def worker(index: int) -> None:
            status, headers, body = wsgi_get("/api/targets/FAKEDLL/data?section=.text", _IDENTITY)
            assert status == "200 OK", f"{status}: {decode_body(body, headers)[:200]!r}"
            with body_lock:
                bodies.append(body)

        _in_parallel(worker)

        assert builds == 1, f"the herd built the payload {builds} times"
        # One build means one body, so every client of the herd is answered
        # from the same bytes.
        assert len(set(bodies)) == 1

    def test_a_herd_minting_variants_never_serves_a_mismatched_body(self) -> None:
        """Concurrent misses on ONE key, each asking for a different encoding.

        The variant each request reads out of the memo is SHARED state: a
        checkout hands the same entry to every thread in the herd, and each
        mints its own encoding into it.  A read that consults the entry outside
        the lock the writers take is answered from whatever interleaving of
        another thread's writes it lands between, and the shape of that answer
        is a body announced under another encoding's name — a brotli payload
        labelled zstd, which no client can decode.

        The oracle is the response itself rather than the lock: decode each
        body by the Content-Encoding the server DECLARED for it and require the
        same JSON every identity client sees.  A mismatch cannot survive that,
        and a lock that is merely present but wrongly scoped would not fail it
        either, which is the point.
        """
        path = "/api/targets/FAKEDLL/data?section=.text"
        # A cold memo, so the herd is the FIRST set of requests for this key
        # and every non-identity worker takes the mint-the-variant branch.  The
        # memo outlives a test (it is keyed on the coverage fingerprint, which
        # no test moves), so a leftover entry from an earlier one would make
        # this a pure read and the branch untested.
        api._clear_data_cache()
        # One accepted encoding per worker, cycled, so several threads share
        # each one and each also races the other two.
        offered = ["identity", "gzip", "br", "zstd"]
        _status, headers, body = wsgi_get(path, _IDENTITY)
        wanted = json.loads(decode_body(body, headers))
        # The identity request above minted only the unencoded variant, so
        # every other encoding is still absent and must be minted under the
        # herd.  Asserted rather than assumed: without it the test would pass
        # while never reaching the code it is here to guard.
        key = (api._snapshot_db_mtime(), "FAKEDLL", ".text", True)
        assert key in api._DATA_CACHE, "the identity request did not populate the memo"
        assert "gzip" not in api._DATA_CACHE[key]

        answered: list[tuple[str, str]] = []
        answered_lock = threading.Lock()

        def worker(index: int) -> None:
            encoding = offered[index % len(offered)]
            status, headers, body = wsgi_get(
                path, {"Accept-Encoding": encoding} if encoding != "identity" else _IDENTITY
            )
            assert status == "200 OK", f"{status}: {decode_body(body, headers)[:200]!r}"
            # decode_body dispatches on the DECLARED encoding, so a body
            # announced under the wrong one raises here rather than parsing.
            assert json.loads(decode_body(body, headers)) == wanted
            with answered_lock:
                answered.append((encoding, headers.get("Content-Encoding", "")))

        _in_parallel(worker)

        assert len(answered) == WORKERS
        for requested, declared in answered:
            # The identity client is the only one that may be served
            # unencoded; every other one asked for a coding and must be told
            # one, or the shared entry served it the wrong representation.
            if requested != "identity":
                assert declared in ("gzip", "br", "zstd"), (
                    f"asked for {requested}, served as {declared or 'identity'!r}"
                )
        # The claim is released on the way out, so a later request is a memo
        # hit and not a second build behind a claim nobody will ever release.
        assert not api._DATA_CACHE_BUILDING

    def test_a_reclaim_releases_the_claim_it_took_over(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A follower that gives up on a dead leader owns the key afterwards.

        The leader's own ``finally`` never runs when it is killed between
        checkout and the build, so the claim outlives its owner unless the
        follower that times out on it takes it over.  The entry has to be
        gone when the reclaiming follower's own build finishes, or the next
        request for the key waits on an event nobody will set.

        The reclaim is also the only trace of the fault that caused it, so it
        is counted where ``/api/health`` reads it and logged with the key the
        killed build was serving: a killed leader and a slow dashboard are
        otherwise the same symptom with no line between them.
        """
        # The claim is registered with its full deadline ahead of it, so the
        # prune does not take it: the reclaim is the branch under test, not
        # the pruning it shadows.  The follower's wait ends on the clock seam,
        # so the test reaches the expired-Event path by advancing that clock
        # past the wait rather than by shortening the production 30 s: a test
        # that had to shrink the constant to reach this branch would pass just
        # as well against a follower that parked on wall-clock time.
        now = [1_000.0]

        def window_per_read() -> float:
            """One read of the clock spends the whole follower window.

            The wait ends the moment a read comes back at or past its deadline,
            so a clock that jumps a window at a time ends it in one slice
            instead of the 600 a real one would take.  A clock frozen instead
            would never end it, which is why this one advances.
            """
            value = now[0]
            now[0] += api._DATA_CACHE_BUILD_WAIT_SECONDS
            return value

        monkeypatch.setattr(api.clock, "monotonic", window_per_read)
        key: tuple[Any, ...] = (("fingerprint", 1), "dead-target", None, True)
        event = threading.Event()  # never set: this is the killed leader
        with api._DATA_CACHE_LOCK:
            api._DATA_CACHE_BUILDING[key] = (event, api.clock.monotonic() + 60.0)

        before = metrics.REQUESTS.snapshot()["stale_claims"]
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            entry, owned = api._data_cache_checkout(key)
        assert entry is None
        assert owned is not None and owned is not event
        api._data_cache_build_done(key, owned)
        assert key not in api._DATA_CACHE_BUILDING
        assert metrics.REQUESTS.snapshot()["stale_claims"] == before + 1
        reclaimed = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(reclaimed) == 1, [r.getMessage() for r in caplog.records]
        fields = getattr(reclaimed[0], _server.LOG_FIELDS_ATTR)
        assert fields["event"] == "data_claim_reclaimed"
        assert fields["target"] == "dead-target"
        # The dead leader's own release must not delete the new owner's claim.
        api._data_cache_build_done(key, event)
        with api._DATA_CACHE_LOCK:
            api._DATA_CACHE_BUILDING.pop(key, None)

    def test_an_expired_claim_is_pruned_rather_than_waited_on(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A claim past its deadline is dropped by the prune, not the wait.

        The reclaim above is the follower's path: it pays the full wait and
        then takes the key over.  A claim that is already past its deadline
        when the next request arrives is cheaper to drop, and the checkout
        that does it is a plain leader claiming a free key, so it must not
        log the reclaim an operator would read as a dead thread.
        """
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            key: tuple[Any, ...] = (("fingerprint", 2), "expired-target", None, True)
            with api._DATA_CACHE_LOCK:
                event = threading.Event()
                api._DATA_CACHE_BUILDING[key] = (event, api.clock.monotonic() - 1.0)
            entry, owned = api._data_cache_checkout(key)
        try:
            assert entry is None
            assert owned is not None and owned is not event
            assert not [r for r in caplog.records if r.levelno >= logging.WARNING], [
                r.getMessage() for r in caplog.records
            ]
        finally:
            api._data_cache_build_done(key, owned)


class TestConcurrentInvalidation:
    """The broadcast's cache clear running against readers, as a rebuild does."""

    def test_readers_survive_a_concurrent_invalidation(self) -> None:
        """Clear every derived memo while threads read through those memos.

        The clear runs on the SSE watcher's thread and the reads on request
        threads, so a payload read through a snapshot a rebuild has replaced
        has to be dropped rather than filed under the key naming the newer
        build.  The assertion is the one an operator sees: every request is
        answered, and none of them is an error.
        """
        stop = threading.Event()
        churn_errors: list[BaseException] = []
        invalidations = 0

        def churn() -> None:
            nonlocal invalidations
            while not stop.is_set():
                try:
                    api._clear_derived_caches()
                    invalidations += 1
                except BaseException as exc:  # the failure is reported, not swallowed
                    churn_errors.append(exc)
                    return

        clearer = threading.Thread(target=churn, daemon=True)
        clearer.start()
        failures: list[tuple[str, str, str]] = []
        fail_lock = threading.Lock()
        try:

            def worker(index: int) -> None:
                for _ in range(6):
                    for path in (
                        "/api/targets/FAKEDLL/stats",
                        "/api/targets/FAKEDLL/data?section=.text",
                        "/api/targets/FAKEDLL/functions?limit=10",
                        "/potato?view=map",
                    ):
                        status, headers, body = wsgi_get(path, _IDENTITY)
                        if not status.startswith("200"):
                            with fail_lock:
                                failures.append((status, path, decode_body(body, headers)[:200]))

            _in_parallel(worker)
        finally:
            stop.set()
            clearer.join(timeout=30)
        # A churn thread that raised, or was made a no-op, would leave every
        # reader green over a run that never invalidated anything, so the
        # invalidations the readers raced are counted rather than assumed.
        assert not churn_errors, churn_errors[:3]
        assert invalidations > 0, "the memos were never invalidated during the read"
        assert not failures, failures[:3]


class TestRequestCounters:
    """``metrics.REQUESTS`` under concurrent requests."""

    def test_the_counters_balance_under_concurrent_requests(self) -> None:
        """The status buckets sum to the request total, and the gauge returns.

        ``before_request`` and ``after_request`` run on every request thread
        and each updates the shared counters in one critical section.  A lost
        update in any of them shows up here as a total that disagrees with the
        sum of its own buckets, or an ``in_flight`` that never came back down.
        """
        before = metrics.REQUESTS.snapshot()
        per_thread = 6
        issued = WORKERS * per_thread
        results: list[str] = []
        result_lock = threading.Lock()

        def worker(index: int) -> None:
            local: list[str] = []
            for _ in range(per_thread):
                status, _headers, _body = wsgi_get(
                    "/api/targets/FAKEDLL/functions?limit=5", _IDENTITY
                )
                local.append(status)
            with result_lock:
                results.extend(local)

        _in_parallel(worker)

        after = metrics.REQUESTS.snapshot()
        assert len(results) == issued
        assert set(results) == {"200 OK"}
        assert after["total"] - before["total"] == issued
        assert sum(after["by_status"].values()) - sum(before["by_status"].values()) == issued
        # The gauge is a gauge: every request that entered has left, so it
        # reads what it read before the herd.
        assert after["in_flight"] == before["in_flight"]
        route = "/api/targets/<target>/functions"
        assert (
            after["by_route"][route]["requests"] - before["by_route"][route]["requests"] == issued
        )


class TestAdmissionCap:
    """``metrics.CONNECTIONS``, the cap the server refuses accepts at."""

    def test_exactly_the_cap_is_admitted_from_many_threads(self) -> None:
        """Many threads, many attempts, exactly ``limit`` admissions.

        The check and the increment have to be one step.  As two steps every
        thread can read a gauge below the cap before any of them writes, and
        the server admits more connections than it is configured to hold: the
        bound the whole saturation story rests on is the one number an
        attacker gets to choose.
        """
        stats = metrics.ConnectionStats()
        limit = 4
        attempts = 5
        admitted = 0
        admit_lock = threading.Lock()

        def worker(index: int) -> None:
            nonlocal admitted
            local = sum(1 for _ in range(attempts) if stats.admit(limit))
            with admit_lock:
                admitted += local

        _in_parallel(worker)

        assert admitted == limit
        assert stats.open == limit
        assert stats.snapshot()["refused"] == WORKERS * attempts - limit
        for _ in range(limit):
            stats.release()
        assert stats.open == 0
        # The gauge floors at zero: a release past the open count (a
        # connection whose thread died between the admit and the release)
        # must not report a negative number of live connections.
        stats.release()
        assert stats.open == 0


class TestAuthThrottle:
    """``server._auth_throttle``, the offline-guessing window."""

    PEER = "127.0.0.1"

    def test_exactly_the_window_is_handed_out(self) -> None:
        """A burst of concurrent guesses gets exactly ``_AUTH_FAIL_MAX`` slots.

        The prune, the cap check and the reservation are one critical section
        on purpose.  Split, every thread in the burst sees a short deque
        before any of them appends, so the throttle admits the whole burst
        and the bound it exists to enforce is the one thing a caller decides.
        """
        now = 1_000.0
        granted = 0
        grant_lock = threading.Lock()

        def worker(index: int) -> None:
            nonlocal granted
            local = 0
            for _ in range(5):
                if not _server._auth_throttle(self.PEER, now, reserve_slot=True):
                    local += 1
            with grant_lock:
                granted += local

        try:
            _server._clear_auth_failures(self.PEER)
            _in_parallel(worker)
            assert granted == _server._AUTH_FAIL_MAX
            # The window is full, so even a check that reserves nothing is
            # refused until it ages out.
            assert _server._auth_throttle(self.PEER, now, reserve_slot=False)
            # A verified request clears it, so an operator never trips their
            # own limit.
            _server._clear_auth_failures(self.PEER)
            assert not _server._auth_throttle(self.PEER, now, reserve_slot=True)
        finally:
            _server._clear_auth_failures(self.PEER)

    def test_one_peer_exhausting_its_window_does_not_refuse_another(self) -> None:
        """The window is per peer, and a success forgives only its own.

        One shared window was a lever in both directions: ten failures from
        anyone answered 429 to the operator for the rest of the window (so an
        unauthenticated peer could deny the dashboard by never stopping), and
        any one successful request emptied it (so the operator's own page loads
        refilled a guesser's allowance on another host without bound).  The
        window is keyed on the socket peer, so neither reaches across.
        """
        now = 1_000.0
        attacker = "192.0.2.10"
        operator = "192.0.2.20"
        try:
            for _ in range(_server._AUTH_FAIL_MAX):
                assert not _server._auth_throttle(attacker, now, reserve_slot=True)
            assert _server._auth_throttle(attacker, now, reserve_slot=False)

            # The operator is unaffected by the attacker's full window, and by
            # the attacker's own verified request, which must not clear it.
            assert not _server._auth_throttle(operator, now, reserve_slot=True)
            _server._clear_auth_failures(operator)
            assert _server._auth_throttle(attacker, now, reserve_slot=False)
        finally:
            _server._clear_auth_failures(attacker)
            _server._clear_auth_failures(operator)

    def test_a_live_window_survives_pressure_from_other_peers(self) -> None:
        """The cap is a memory bound, not a way to refund a guesser.

        The map is bounded per peer count, so it has to evict something when it
        is full.  Evicting the oldest entry regardless of its window throws away
        the throttle of a peer still inside it, and the next distinct address
        arrives to find a fresh window: a guesser with addresses to spare buys
        unlimited attempts out of a cap that reads as a limit on them.  A window
        whose newest failure has aged out holds no state, so those go first.
        """
        now = 1_000.0
        attacker = "203.0.113.7"
        spent = "203.0.113.8"
        try:
            for _ in range(_server._AUTH_FAIL_MAX):
                assert not _server._auth_throttle(attacker, now, reserve_slot=True)
            assert _server._auth_throttle(attacker, now, reserve_slot=False)

            # Fill the map to its cap from addresses that are all mid-window,
            # so every one of them is a window worth keeping, and put one
            # entry in past its window: that entry is what a new peer takes.
            for index in range(_server._AUTH_FAIL_MAX_PEERS - 2):
                _server._auth_throttle(f"198.51.100.{index % 256}-{index}", now, reserve_slot=True)
            _server._auth_throttle(spent, now - _server._AUTH_FAIL_WINDOW_SECONDS - 1.0, True)
            for index in range(1):
                _server._auth_throttle(f"203.0.113.{index % 256}-{index}", now, reserve_slot=True)

            assert spent not in _server._auth_failures, "the spent window was not the one dropped"
            assert _server._auth_throttle(attacker, now, reserve_slot=False), (
                "the attacker's exhausted window was evicted and refunded by "
                "traffic from other peers"
            )
        finally:
            _server._auth_failures.clear()

    def test_the_peer_map_is_bounded_when_every_window_is_live(self) -> None:
        """Memory is a hard limit: the oldest window still goes past the cap.

        With more live peers than the cap allows there is no spent entry to
        drop, and holding the map open is the worse failure, so the eviction
        falls back to oldest-first.  What must not happen is the map growing
        instead, which is what an unbounded peer key would have done.
        """
        now = 1_000.0
        try:
            for index in range(_server._AUTH_FAIL_MAX_PEERS + 50):
                _server._auth_throttle(f"198.51.100.{index % 256}-{index}", now, reserve_slot=True)

            assert len(_server._auth_failures) <= _server._AUTH_FAIL_MAX_PEERS
            newest = _server._AUTH_FAIL_MAX_PEERS + 49
            assert f"198.51.100.{newest % 256}-{newest}" in _server._auth_failures
            assert "198.51.100.0-0" not in _server._auth_failures
        finally:
            _server._auth_failures.clear()

    def test_a_peer_is_refunded_once_its_failures_age_out(self) -> None:
        """The window SLIDES: an exhausted peer is let back in on the clock.

        Every other case here either reserves at one frozen `now` or arrives as
        a new peer with an old timestamp, so the prune inside `_auth_throttle`
        itself never runs.  A throttle that never dropped an aged-out failure
        would keep answering one peer 429 for the life of the process after a
        burst that ended a minute earlier.
        """
        peer = "203.0.113.7"
        now = 1_000.0
        try:
            for _ in range(_server._AUTH_FAIL_MAX):
                assert not _server._auth_throttle(peer, now, reserve_slot=True), (
                    "the peer was refused before its window was full"
                )
            assert _server._auth_throttle(peer, now, reserve_slot=True), (
                "an exhausted peer was not refused at the cap"
            )
            aged = now + _server._AUTH_FAIL_WINDOW_SECONDS + 1.0
            assert not _server._auth_throttle(peer, aged, reserve_slot=True), (
                "the peer stayed locked out after every failure aged out of the window"
            )
            assert len(_server._auth_failures[peer]) == 1, (
                "the aged-out failures were not pruned, so the window refills "
                "from a deque that never empties"
            )
        finally:
            _server._auth_failures.clear()


class TestSnapshotIndex:
    """``server._snapshot_index``, the by-VA memos keyed on snapshot identity."""

    def test_a_concurrent_build_publishes_one_index_for_the_snapshot(self) -> None:
        """Threads building the same index agree on what was published.

        The build runs outside the lock (it walks every global), so several
        threads can build it at once.  What must not differ is the answer: a
        half-built index, or one keyed to a snapshot the reader is no longer
        holding, is what a caller walking the returned mapping would serve.
        """
        snapshot = _server.coverage_for("FAKEDLL")
        expected: dict[int, Any] = {}
        for gl in snapshot.globals:
            expected.setdefault(gl.va, gl)
        # The memo is process-wide and keyed on snapshot identity, so it can
        # already hold an entry for a snapshot another test read. What this
        # test owns is the delta its own herd causes.
        before = sum(1 for key in _server._SNAPSHOT_INDEX if key[1] == "globals_by_va")

        results: list[Mapping[int, Any]] = []
        result_lock = threading.Lock()

        def worker(index: int) -> None:
            built = _server.globals_by_va(snapshot)
            with result_lock:
                results.append(built)

        _in_parallel(worker)

        assert results and all(result == expected for result in results)
        # Every caller is answered from the ONE published index, and the herd
        # adds at most the entry this snapshot did not already have: eight
        # threads building the same index publish one, not eight.
        assert all(result is results[0] for result in results)
        after = sum(1 for key in _server._SNAPSHOT_INDEX if key[1] == "globals_by_va")
        assert after - before <= 1


class TestBatchLookup:
    """The batch POST, the one endpoint whose answer is a per-caller ordering."""

    def test_every_caller_is_answered_in_its_own_input_order(self) -> None:
        """Concurrent batch lookups do not interleave rows between requests.

        Each request builds its result list from the shared snapshot and the
        shared by-VA memos, so a payload holding another caller's rows is a
        cross-request leak rather than a wrong answer for one of them.  Every
        caller asks for a DIFFERENT rotation of the same VAs: with one body
        shared by all of them, a handler holding a single result list across
        callers would answer correctly.
        """
        vas = ["0x10001000", "0x10001010", "0x10001020"]
        snapshot = _server.coverage_for("FAKEDLL")
        known = {int(va, 16) for va in vas if int(va, 16) in snapshot.functions_by_va}
        assert known, "the synthetic target has no function at the queried VAs"
        orders = {tuple(vas[i:] + vas[:i]) for i in range(len(vas))}
        assert len(orders) == len(vas), "the rotations are not distinct"

        payloads: dict[tuple[str, ...], list[Any]] = {}
        answered = 0
        payload_lock = threading.Lock()

        def worker(index: int) -> None:
            nonlocal answered
            order = tuple(vas[index % len(vas) :] + vas[: index % len(vas)])
            status, headers, body = wsgi_post(
                "/api/targets/FAKEDLL/functions",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"vas": list(order)}),
            )
            assert status == "200 OK", f"{status}: {decode_body(body, headers)[:200]!r}"
            with payload_lock:
                payloads[order] = json.loads(decode_body(body, headers))
                answered += 1

        _in_parallel(worker)

        assert answered == WORKERS
        assert set(payloads) == orders, (
            "a caller was answered with another caller's rows: "
            f"{sorted(payloads)} against {sorted(orders)}"
        )
        for order, rows in payloads.items():
            expected = [int(va, 16) for va in order if int(va, 16) in known]
            assert [row["va"] for row in rows] == expected, (
                f"the rows are not in the caller's own input order: {order}"
            )
