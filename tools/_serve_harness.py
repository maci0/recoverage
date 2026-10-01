"""Shared harness for booting the dashboard against synthetic coverage documents.

Used by tools/smoke.py and tools/lint_html.py: both build the synthetic
coverage through ``build_sample_db`` (which calls ``tests/coverage_fixture``'s
builder directly), start ``recoverage serve`` on a free local port, probe
documents over HTTP, and always stop the server process.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

from recoverage import clock

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
SCRATCH_DIR = REPO_ROOT / ".scratch"

#: Seconds between two probes while :func:`wait_for` waits for the listener.
WAIT_FOR_INTERVAL_SECONDS = 0.3


@contextlib.contextmanager
def scratch_project_dir() -> Iterator[Path]:
    """Yield an empty throwaway project dir, removed on exit.

    Under the repo's gitignored ``.scratch/``, not the system temp dir: the
    system temp is RAM-backed, so the coverage documents and the served HTML
    tree would eat memory and vanish on reboot, and the build is easier to
    inspect when it lands next to the tree it came from.
    """
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH_DIR) as td:
        project_dir = Path(td) / "proj"
        project_dir.mkdir()
        yield project_dir


def build_sample_db(project_dir: Path) -> Path:
    """Build the sample coverage documents in *project_dir*/db; return their path.

    Re-runnable: any number of calls, in any order, against the same or a
    different *project_dir*, in one process or across processes, all end with
    the same documents.  The builder is called directly with the target
    directory, and the ``tests`` entry added to ``sys.path`` for that import is
    removed again, so no call leaves a copy behind.

    The builder is ``coverage_fixture``'s, not ``conftest``'s: importing
    conftest to reach it ran the suite's import-time fixture write, which lands
    under the cwd the tool was launched from, so the call had to chdir and
    plant a sentinel document to suppress it.
    """
    tests_dir = str(REPO_ROOT / "tests")
    sys.path.insert(0, tests_dir)
    try:
        from coverage_fixture import build_synthetic_coverage
    finally:
        with contextlib.suppress(ValueError):
            sys.path.remove(tests_dir)
    return build_synthetic_coverage(project_dir / "db")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        # getsockname() is typed as a union of address shapes, so the [1] is Any
        # on a tuple the bind above just fixed to ("127.0.0.1", port).
        return cast(int, s.getsockname()[1])


def get(port: int, path: str) -> tuple[int, bytes]:
    """GET *path* uncompressed (Accept-Encoding: identity); (0, b"") when down."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path, headers={"Accept-Encoding": "identity"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    except (ConnectionRefusedError, OSError):
        return 0, b""
    finally:
        conn.close()


def wait_for(predicate: Callable[[], bool], timeout: float = 30.0) -> bool:
    """Poll *predicate* on :mod:`recoverage.clock`, the seam the server reads.

    The harness drives a real subprocess, so the wait is on the same module the
    server's own cooldowns and heartbeats read: one patched clock then reaches
    both sides of the probe, and a replayed run makes the same attempts in the
    same order instead of inheriting whatever cadence the wall clock decided.
    """
    deadline = clock.monotonic() + timeout
    while clock.monotonic() < deadline:
        if predicate():
            return True
        clock.sleep(WAIT_FOR_INTERVAL_SECONDS)
    return False


#: Bytes of the server's own stderr kept for the failure report.  Enough for a
#: traceback and the banner, bounded so a chatty run cannot fill the temp dir.
SERVER_STDERR_CAPTURE_BYTES = 64 * 1024


def server_stderr(proc: subprocess.Popen[bytes]) -> str:
    """What the server under *proc* wrote to stderr, decoded for the failure report.

    The report is built from the live file, not from a buffer the harness
    accumulated, so nothing is lost when the child outran whatever was kept in
    memory.  :data:`SERVER_STDERR_CAPTURE_BYTES` is the ceiling, not a
    promise: a full disk or a write error under this directory leaves the file
    short rather than raising out of a teardown that has a verdict to deliver,
    which is the opposite of what the report exists for.
    """
    tail: Path | None = getattr(proc, "stderr_tail", None)
    if tail is None:
        return ""
    try:
        with tail.open("rb") as fh:
            try:
                fh.seek(-SERVER_STDERR_CAPTURE_BYTES, os.SEEK_END)
            except OSError:
                fh.seek(0)
            return fh.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def report_server_exit(proc: subprocess.Popen[bytes], stream: Any = None) -> None:
    """Print why the server under *proc* is not answering, then that it is gone.

    ``server exited early with code 1`` on its own is the finding this exists
    to fix: every boot failure the harness can hit — a port already bound, a
    ``rebrew-project.toml`` that does not parse, a coverage override pointing
    at a file, an import error in the tree under test — prints its cause on
    stderr and exits 1 or 2, and a harness that sends that stream to
    ``DEVNULL`` reports the code and nothing else, so the CI log names a
    failure with no way to act on it.  The report is emitted from the exit path
    the caller already detected, so a healthy run stays silent.
    """
    out = sys.stderr if stream is None else stream
    if proc.poll() is None:
        return
    print(f"server exited early with code {proc.returncode}", file=out)
    tail = server_stderr(proc)
    if tail:
        print("--- server stderr ---", file=out)
        print(tail, file=out)
        print("--- end server stderr ---", file=out)
    else:
        print("server stderr was empty", file=out)


@contextlib.contextmanager
def running_server(project_dir: Path) -> Iterator[tuple[int, subprocess.Popen[bytes]]]:
    """Run ``recoverage serve`` in *project_dir*; yield ``(port, process)``, stop it.

    stderr goes to a file under the system temp dir rather than to
    ``DEVNULL``: a server that refuses to boot writes the reason there, and
    :func:`report_server_exit` reads it back on the failure paths.  The file is
    unlinked on the way out, so a run leaves nothing behind, and the tail is
    bounded by :data:`SERVER_STDERR_CAPTURE_BYTES`.  ``serve`` logs at INFO by
    default, so a healthy run fills a little of it and the file is where that
    goes instead of the parent terminal.
    """
    port = free_port()
    # A NamedTemporaryFile kept open is unlinkable-as-a-directory-entry on
    # Windows, and the child inherits the handle; delete=False plus an
    # explicit unlink in the finally is the shape that works on both.
    # SIM115 is off for this line because the lifetime is the child's, not this
    # scope's: a `with` here would close the handle the moment the block ends,
    # and the server has not even been spawned yet.  Every exit below — the
    # spawn failure, the yield's finally — closes and unlinks it exactly once.
    log = tempfile.NamedTemporaryFile(prefix="recoverage-serve-", suffix=".log", delete=False)  # noqa: SIM115
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "recoverage", "serve", "--no-open", "--port", str(port)],
            cwd=str(project_dir),
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
        # Carried on the handle rather than yielded as a third element, so
        # every existing caller keeps its two and a call site that forgets to
        # report still gets a file it can read.
        proc.stderr_tail = Path(log.name)  # type: ignore[attr-defined]
    except BaseException:
        log.close()
        Path(log.name).unlink(missing_ok=True)
        raise
    try:
        yield port, proc
    finally:
        log.close()
        try:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                # kill() signals; only a wait() reaps.  Without this the harness
                # leaves a zombie behind on every timed-out teardown.
                proc.wait()
        finally:
            Path(log.name).unlink(missing_ok=True)
