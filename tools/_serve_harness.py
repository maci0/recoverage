"""Shared harness for booting the dashboard against a synthetic coverage.db.

Used by tools/smoke.py and tools/lint-html.py: both build the synthetic
DB through ``build_sample_db`` (which calls ``tests/conftest``'s builder
directly), start ``recoverage
serve`` on a free local port, probe documents over HTTP, and always stop the
server process.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
SCRATCH_DIR = REPO_ROOT / ".scratch"


@contextlib.contextmanager
def scratch_project_dir() -> Iterator[Path]:
    """Yield an empty throwaway project dir, removed on exit.

    Under the repo's gitignored ``.scratch/``, not the system temp dir: the
    system temp is RAM-backed, so a SQLite database and the served HTML tree
    would eat memory and vanish on reboot, and the build is easier to inspect
    when it lands next to the tree it came from.
    """
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH_DIR) as td:
        project_dir = Path(td) / "proj"
        project_dir.mkdir()
        yield project_dir


def build_sample_db(project_dir: Path) -> Path:
    """Build db/coverage.db using the shared synthetic schema builder.

    Re-runnable: any number of calls, in any order, against the same or a
    different *project_dir*, in one process or across processes, all end
    with the same database.  Two things used to break that, and both are
    fixed here:

    - ``import conftest`` is a no-op once the module is in ``sys.modules``,
      and conftest's import-time side effect binds its own output path to
      the cwd at ITS first import, so a second call built nothing.  The
      builder is now called directly with the target path.
    - The ``tests`` entry added to ``sys.path`` for that import was never
      removed, so each call left another copy behind.

    The chdir still happens, because conftest's own import-time side effect
    creates ``db/coverage.db`` under the cwd: confining it to *project_dir*
    keeps it out of whatever directory the tool was launched from.  Touching
    the target first makes that side effect skip, so the database is written
    exactly once, by the call below.
    """
    db_dir = project_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_file = db_dir / "coverage.db"
    db_file.touch()
    tests_dir = str(REPO_ROOT / "tests")
    old_cwd = Path.cwd()
    sys.path.insert(0, tests_dir)
    try:
        os.chdir(project_dir)
        import conftest  # type: ignore[import-not-found]
    finally:
        os.chdir(old_cwd)
        with contextlib.suppress(ValueError):
            sys.path.remove(tests_dir)
    conftest._build_synthetic_db(db_file)  # type: ignore[attr-defined]
    return db_file


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.3)
    return False


@contextlib.contextmanager
def running_server(project_dir: Path) -> Iterator[tuple[int, subprocess.Popen[bytes]]]:
    """Run ``recoverage serve`` in *project_dir*; yield ``(port, process)``, stop it."""
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "recoverage", "serve", "--no-open", "--port", str(port)],
        cwd=str(project_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield port, proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            # kill() signals; only a wait() reaps.  Without this the harness
            # leaves a zombie behind on every timed-out teardown.
            proc.wait()
