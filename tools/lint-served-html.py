#!/usr/bin/env python3
"""Validate the HTML documents recoverage actually serves, using vnu.

The static asset lint (tools/lint-html.mjs) checks the source HTML/CSS files.
This script validates the assembled documents a browser receives:

  - GET /       — the SPA shell with style.css and app.js injected server-side
  - GET /potato — the fully server-rendered Potato Mode page

It boots the real server against a synthetic coverage.db (the shared builder
in tools/_serve_harness.py, same one tools/smoke.py uses), fetches both
documents, and runs the Nu Html Checker (vnu.jar) over them with
``--also-check-css``, which also validates the embedded CSS.

Potato Mode deliberately renders HTML4-era markup (``<font>``, ``bgcolor``,
``cellpadding``, ... — see the "no CSS" docstrings in potato.py). The obsolete
family is filtered for that document as the documented retro contract, while
every other message stays fatal — the SPA shell is checked strictly.

Requires: uv (project venv), java on PATH, and ``npm install`` already run
(for vnu-jar).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from _serve_harness import build_sample_db, get, running_server, wait_for

REPO_ROOT = Path(__file__).resolve().parent.parent
VNU_JAR = REPO_ROOT / "node_modules" / "vnu-jar" / "build" / "dist" / "vnu.jar"


def main() -> int:
    if not VNU_JAR.is_file():
        print("vnu.jar not found; run `npm install` first.")
        return 2

    with tempfile.TemporaryDirectory() as td:
        project_dir = Path(td) / "proj"
        project_dir.mkdir()
        if not build_sample_db(project_dir).is_file():
            print("sample coverage.db not built")
            return 1

        with running_server(project_dir) as (port, _):
            if not wait_for(lambda: get(port, "/api/health")[0] == 200):
                print("server never became healthy")
                return 1

            docs: dict[str, Path] = {}
            for path, name in (("/", "spa.html"), ("/potato", "potato.html")):
                status, body = get(port, path)
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

    print("served-document lint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
