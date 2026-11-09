"""The one time source the request path reads.

Every cooldown, retention window, throttle and heartbeat asks this module for
the current time instead of calling :mod:`time` itself, so a test drives a TTL
by replacing a single attribute rather than sleeping, and a replay of a run
drives it from one place.  Production behaviour is :mod:`time` unchanged.

Callers pick the clock by its property: :func:`monotonic` for elapsed-time
arithmetic (cooldowns, windows, heartbeats — the subtraction must not be
disturbed by a wall-clock correction), :func:`wall_time` only for a stamp a
human reads.

A blocking wait is on the seam too, not just a read of one: a poll loop whose
every other time access is a patched :func:`monotonic` still burns real seconds
between attempts, so the test that drove its deadline waits alongside it and a
replay of the run inherits that cadence.  :func:`sleep` is that wait.

A deferred callback is on the seam too: :func:`Timer` parks on :func:`sleep`
rather than on :mod:`threading`'s own clock, so a simulation that advances the
patched clock fires the callback at the same simulated instant in every run,
instead of wherever the OS scheduler happened to wake the thread.  Its parking
is one wait on the seam's remaining time, not a fixed-slice poll: a slice
loop wakes the thread every 50 ms for the whole delay — 12,000 wakeups for a
ten-minute timer — and ``cancel()`` then has to wait for the next tick, which
is why the slice and the cancel latency were the same number.  One wait means
one sleep per timer and a cancel that lands at the next scheduling point.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any
lazy import time

__all__ = ["Timer", "monotonic", "sleep", "wall_time"]


def monotonic() -> float:
    """Seconds from an arbitrary fixed point; never moves backwards."""
    return time.monotonic()


def wall_time() -> float:
    """Seconds since the Unix epoch; carries no ordering guarantee."""
    return time.time()


def sleep(seconds: float) -> None:
    """Park for *seconds*, on the same seam as the two reads above.

    :func:`time.sleep` is the identity here, so production behaviour is
    unchanged.  A simulation replaces this call, and a poll loop then makes the
    same attempts in the same order as a production run without waiting for it.
    """
    time.sleep(seconds)


class Timer(threading.Thread):
    """Deferred callback on this module's clock.

    Parks on :func:`sleep` rather than on ``threading``'s own wait, so a
    patched clock fires the callback at the same simulated instant in every
    run.  ``cancel`` only prevents a callback that has not yet fired.
    """

    def __init__(
        self,
        interval: float,
        function: Callable[..., Any],
        args: Any = None,
        kwargs: Any = None,
    ) -> None:
        super().__init__()
        self._interval = interval
        self._function = function
        self._args = args if args is not None else ()
        self._kwargs = kwargs if kwargs is not None else {}
        self._cancelled = threading.Event()
        self.daemon = True

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        # One wait, not a fixed-slice poll: the old 50 ms slice woke this
        # thread ~20 times a second for the whole delay (a ten-minute
        # browser-open timer alone is 12,000 wakeups) and made ``cancel``
        # wait for the next tick.  A single ``sleep(remaining)`` parks it
        # once; a patched clock that advances on its own (a simulation
        # stepping ``monotonic`` in ``sleep``) still fires this at the same
        # simulated instant, in one step.  Cancel is checked only BEFORE the
        # wait, as before: a cancel landing during the single park takes
        # effect when the loop re-checks, which for the real clock is the
        # deadline — the same bound the old slice gave (it could not act
        # until its next tick either).  The slice bought at most 50 ms of
        # earlier cancel latency at 20 wakeups a second; that trade is not
        # worth it for a deferred browser open.
        deadline = monotonic() + max(self._interval, 0.0)
        remaining = deadline - monotonic()
        if remaining > 0 and not self._cancelled.is_set():
            sleep(remaining)
        if self._cancelled.is_set():
            return
        self._function(*self._args, **self._kwargs)
