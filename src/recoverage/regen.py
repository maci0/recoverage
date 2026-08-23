"""rebrew regen subprocess lifecycle.

Running ``uv run rebrew <step>`` safely is a process-management concern, not
an HTTP one: each child gets its own session so the whole process group can
be signalled on timeout or interpreter exit, and every abandonment path reaps
the child.  Shared by the CLI (``serve --regen``, ``recoverage regen``, the
bounded browser-opener wait) and the API's POST /api/regen; this module has
no in-package dependencies so either side can import it without pulling the
Bottle stack.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
from pathlib import Path

# Shared timeout for rebrew regen subprocesses (imported by cli.py and api.py)
REGEN_TIMEOUT = 120  # seconds — must accommodate large projects


def _kill_and_reap(proc: subprocess.Popen[bytes]) -> None:
    """Kill *proc* — on POSIX its whole session — and always reap it.

    Every child we spawn gets its own session (start_new_session), so
    terminal signals such as Ctrl+C never reach it: any abandonment path
    must signal the process GROUP, not just the direct child, or the rebrew
    grandchild survives and keeps writing coverage.db behind a restarted
    dashboard.  The trailing wait() reaps the child either way (setsid does
    not prevent zombies; only a wait does).
    """
    if os.name == "posix":
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    else:
        proc.kill()
    proc.wait()


def run_regen_step(step: str, root: Path) -> None:
    """Run ``uv run rebrew <step>`` in *root*, killing the whole process group on timeout.

    ``check_call(timeout=...)`` kills only the direct child (uv); the actual
    rebrew worker is uv's grandchild and would survive, still writing
    coverage.db while the dashboard resumes serving.  The child gets its own
    session so the group can be signalled, and it is always reaped — on
    timeouts AND on KeyboardInterrupt/SystemExit mid-wait, which would
    otherwise orphan the still-running regen tree.
    """
    cmd = ["uv", "run", "rebrew", step]
    proc = subprocess.Popen(cmd, cwd=str(root), start_new_session=(os.name == "posix"))
    try:
        proc.wait(timeout=REGEN_TIMEOUT)
    except subprocess.TimeoutExpired:
        _kill_and_reap(proc)
        raise subprocess.TimeoutExpired(cmd, REGEN_TIMEOUT) from None
    except BaseException:
        # KeyboardInterrupt (Ctrl+C during serve --regen / POST /api/regen) or
        # interpreter shutdown: the child sits in its own session, so the
        # terminal's SIGINT did not reach it — kill the group before dying or
        # uv+rebrew keep rebuilding coverage.db as orphans.
        _kill_and_reap(proc)
        raise
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)
