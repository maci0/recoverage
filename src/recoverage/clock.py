"""The one time source the request path reads.

Every cooldown, retention window, throttle and heartbeat asks this module for
the current time instead of calling :mod:`time` itself, so a test drives a TTL
by replacing a single attribute rather than sleeping, and a replay of a run
drives it from one place.  Production behaviour is :mod:`time` unchanged.

Callers pick the clock by its property: :func:`monotonic` for elapsed-time
arithmetic (cooldowns, windows, heartbeats — the subtraction must not be
disturbed by a wall-clock correction), :func:`wall_time` only for a stamp a
human reads.
"""

from __future__ import annotations

import time

__all__ = ["monotonic", "wall_time"]


def monotonic() -> float:
    """Seconds from an arbitrary fixed point; never moves backwards."""
    return time.monotonic()


def wall_time() -> float:
    """Seconds since the Unix epoch; carries no ordering guarantee."""
    return time.time()
