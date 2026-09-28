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
"""

from __future__ import annotations

import time

__all__ = ["monotonic", "sleep", "wall_time"]


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
