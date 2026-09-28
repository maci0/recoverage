"""Re-run safety of the tools/ serve harness.

``tools/smoke.py`` and ``tools/lint-html.py`` both build their sample coverage
through :func:`build_sample_db`, and CI runs both (the smoke job runs
``smoke.py`` and then ``smoke.py --expect-failure``).  The harness must
therefore produce the same documents however many times it is called, into the
same directory or a fresh one, without leaking process-wide state.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())

sys.path.insert(0, str(REPO_ROOT / "tools"))
from _serve_harness import build_sample_db  # noqa: E402 — tools/ is on sys.path on the line above


def _digest(db: Path) -> str:
    return hashlib.sha256(db.read_bytes()).hexdigest()


def _snapshot(db_dir: Path) -> Any:
    """The synthetic document, read through the real reader.

    *db_dir* is the directory the documents live in; the reader resolves the
    directory from the project ROOT, which is one level up.
    """
    from rebrew.coverage_toml import load_coverage

    return load_coverage(db_dir.parent, "FAKEDLL")


def _count(directory: Path) -> int:
    """Cells the synthetic document carries."""
    return sum(len(section.cells) for section in _snapshot(directory).sections.values())


def load_functions(directory: Path) -> tuple[Any, ...]:
    """Functions the synthetic document carries."""
    return _snapshot(directory).functions


class TestBuildSampleDbRerun:
    def test_two_directories_one_process_build_identical_databases(self, tmp_path: Path) -> None:
        """A second call must build, not no-op on the already-imported conftest."""
        first = build_sample_db(tmp_path / "one")
        second = build_sample_db(tmp_path / "two")

        assert first.is_file(), "first call built nothing"
        assert second.is_file(), "second call into a fresh directory built nothing"
        assert _digest(first) == _digest(second)

    def test_rerun_over_an_existing_db_rebuilds_it(self, tmp_path: Path) -> None:
        """Re-running over a populated directory converges instead of failing."""
        build_sample_db(tmp_path / "proj").write_text("corrupt!", encoding="utf-8")

        rebuilt = build_sample_db(tmp_path / "proj")

        assert _digest(rebuilt) == _digest(build_sample_db(tmp_path / "other"))
        assert _count(rebuilt.parent) == 9
        assert len(load_functions(rebuilt.parent)) == 3

    def test_repeated_calls_leave_no_process_state_behind(self, tmp_path: Path) -> None:
        """sys.path and the cwd are restored, so N calls cost N entries, not 2N."""
        path_before = list(sys.path)
        cwd_before = Path.cwd()

        for i in range(3):
            build_sample_db(tmp_path / f"proj{i}").unlink()

        assert sys.path == path_before
        assert Path.cwd() == cwd_before
