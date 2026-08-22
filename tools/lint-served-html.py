#!/usr/bin/env python3
"""Validate the HTML documents recoverage actually serves, using vnu.

The static asset lint (tools/lint-html.mjs) checks the source HTML/CSS files.
This script validates the assembled documents a browser receives:

  - GET /       — the SPA shell with style.css and app.js injected server-side
  - GET /potato — the fully server-rendered Potato Mode page

It boots the real server against a synthetic coverage.db (the same builder the
test suite uses via tests/conftest.py), fetches both documents, and runs the
Nu Html Checker (vnu.jar) over them with ``--also-check-css``, which also
validates the embedded CSS.

Potato Mode deliberately renders HTML4-era markup (``<font>``, ``bgcolor``,
``cellpadding``, ... — see the "no CSS" docstrings in potato.py). The obsolete
family is filtered for that document as the documented retro contract, while
every other message stays fatal — the SPA shell is checked strictly.

Requires: uv (project venv), java on PATH, and ``npm install`` already run
(for vnu-jar).
"""

from __future__ import annotations

import http.client
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
VNU_JAR = REPO_ROOT / "node_modules" / "vnu-jar" / "build" / "dist" / "vnu.jar"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_sample_db(project_dir: Path) -> Path:
    """Build db/coverage.db using the shared synthetic schema builder.

    Same approach as tools/smoke.py: conftest builds the DB at cwd/db/coverage.db
    as an import side effect, so the chdir must happen before the import.
    """
    import os

    db_dir = project_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    old_cwd = Path.cwd()
    try:
        os.chdir(project_dir)
        sys.path.insert(0, str(TESTS_DIR))
        import conftest  # noqa: F401 — builds the synthetic DB on import
    finally:
        os.chdir(old_cwd)
    return db_dir / "coverage.db"


def _wait_for(predicate, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.3)
    return False


def _get(port: int, path: str) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path, headers={"Accept-Encoding": "identity"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    except (ConnectionRefusedError, OSError):
        return 0, b""
    finally:
        conn.close()


def main() -> int:
    if not VNU_JAR.is_file():
        print("vnu.jar not found; run `npm install` first.")
        return 2

    with tempfile.TemporaryDirectory() as td:
        project_dir = Path(td) / "proj"
        project_dir.mkdir()
        db = _build_sample_db(project_dir)
        if not db.is_file():
            print("sample coverage.db not built")
            return 1

        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "recoverage", "serve", "--no-open", "--port", str(port)],
            cwd=str(project_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if not _wait_for(lambda: _get(port, "/api/health")[0] == 200):
                print("server never became healthy")
                return 1

            docs: dict[str, Path] = {}
            for path, name in (("/", "spa.html"), ("/potato", "potato.html")):
                status, body = _get(port, path)
                if status != 200:
                    print(f"GET {path} -> {status}; cannot lint served document")
                    return 1
                (project_dir / name).write_bytes(body)
                docs[name] = project_dir / name

            # SPA shell: strict — any vnu message of any severity fails the gate.
            spa_cmd = [
                "java",
                "-jar",
                str(VNU_JAR),
                "--also-check-css",
                str(docs["spa.html"]),
            ]
            # Potato Mode: the obsolete-element/attribute family (<font>,
            # bgcolor, valign, ...) is the documented retro design, so hide
            # those messages; every other message still fails the gate.
            # (vnu's --filterpattern matches the full message, hence the .*)
            potato_cmd = [
                "java",
                "-jar",
                str(VNU_JAR),
                "--also-check-css",
                "--filterpattern",
                ".*obsolete.*",
                str(docs["potato.html"]),
            ]
            for cmd in (spa_cmd, potato_cmd):
                print(f"vnu: {' '.join(cmd)}")
                result = subprocess.run(cmd)
                if result.returncode != 0:
                    print("served-document lint failed")
                    return result.returncode
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    print("served-document lint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
