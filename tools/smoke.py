"""smoke.py — boot the dashboard against a real coverage.db and probe it.

End-to-end server smoke for CI: builds a synthetic ``db/coverage.db`` (the
exact rebrew build-db schema v4, shared with the test suite via
``tests/conftest._build_synthetic_db``), starts ``recoverage serve`` on a
random port, and probes the surfaces a browser hits: the SPA shell, the
health endpoint, a target's data API, and Potato Mode.  Exits non-zero on
any failed probe.

Usage::

    python tools/smoke.py                 # full smoke (expects success)
    python tools/smoke.py --expect-failure  # negative: corrupt DB must fail

No rebrew needed — the DB is built from the shared synthetic schema, so this
runs entirely inside recoverage's own CI.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from _serve_harness import build_sample_db, get, running_server, wait_for


def smoke(project_dir: Path, *, expect_failure: bool = False) -> int:
    db = build_sample_db(project_dir)
    assert db.is_file(), "sample coverage.db not built"

    if expect_failure:
        db.write_text("corrupt!", encoding="utf-8")  # break the schema

    with running_server(project_dir) as (port, proc):
        if not wait_for(lambda: get(port, "/api/health")[0] == 200):
            print("server never became healthy")
            if proc.poll() is not None:
                print(f"server exited early with code {proc.returncode}")
            return 1

        if expect_failure:
            # Corrupt DB: the dashboard must report a degraded health status
            # (the SPA shell still serves 200 with its empty state — that is
            # the designed degradation, not a healthy server).
            status, body = get(port, "/api/health")
            if status != 200 or b'"degraded"' not in body:
                print(f"expected degraded health but got status {status}: {body[:120]!r}")
                return 1
            print("negative smoke passed (corrupt DB reported as degraded)")
            return 0

        probes = {
            "/": 200,  # SPA shell
            "/api/health": 200,
            "/api/targets": 200,
            "/api/targets/FAKEDLL/data": 200,
            "/api/targets/FAKEDLL/stats": 200,
            "/api/targets/FAKEDLL/functions": 200,
            "/potato": 200,  # Potato Mode
        }
        failed = 0
        for path, want in probes.items():
            status, body = get(port, path)
            ok = status == want
            if not ok:
                failed += 1
            print(f"[{'PASS' if ok else 'FAIL'}] {path} -> {status}")
            if path == "/" and ok:
                shell = b"ReCoverage" in body
                if not shell:
                    failed += 1
                    print("       SPA shell marker 'ReCoverage' missing")
        return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Boot and probe the dashboard.")
    parser.add_argument(
        "--expect-failure",
        action="store_true",
        help="Negative smoke: a corrupt DB must not serve 200s.",
    )
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as td:
        project_dir = Path(td) / "proj"
        project_dir.mkdir()
        return smoke(project_dir, expect_failure=args.expect_failure)


if __name__ == "__main__":
    sys.exit(main())
