"""Shared harness for booting the dashboard against a synthetic coverage.db.

Used by tools/smoke.py and tools/lint-served-html.py: both build the synthetic
DB via tests/conftest (imported for its side effect), start ``recoverage
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
import time
from collections.abc import Callable, Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def build_sample_db(project_dir: Path) -> Path:
    """Build db/coverage.db using the shared synthetic schema builder.

    conftest binds its DB path at import time (``cwd/db/coverage.db``), so
    the chdir must happen before the import.
    """
    db_dir = project_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    old_cwd = Path.cwd()
    try:
        os.chdir(project_dir)
        sys.path.insert(0, str(REPO_ROOT / "tests"))
        # Importing conftest builds the synthetic DB as a module side effect
        # (guarded by cwd/db/coverage.db + no rebrew-project.toml).
        import conftest  # noqa: F401  # type: ignore[import-not-found]
    finally:
        os.chdir(old_cwd)
    return db_dir / "coverage.db"


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
