"""Shared harness for booting the dashboard against synthetic coverage documents.

Used by tools/smoke.py and tools/lint_html.py: both build the synthetic
coverage through ``build_sample_db`` (which calls ``tests/coverage_fixture``'s
builder directly), start ``recoverage serve`` on a free local port, probe
documents over HTTP, and always stop the server process.
"""

from __future__ import annotations

import contextlib
import http.client
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
SCRATCH_DIR = REPO_ROOT / ".scratch"


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
    # tests/ is outside the type gate, so the imported builder is untyped here.
    return cast(Path, build_synthetic_coverage(project_dir / "db"))


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
