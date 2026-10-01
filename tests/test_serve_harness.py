"""Re-run safety of the tools/ serve harness.

``tools/smoke.py`` and ``tools/lint_html.py`` both build their sample coverage
through :func:`build_sample_db`, and CI runs both (the smoke job runs
``smoke.py`` and then ``smoke.py --expect-failure``).  The harness must
therefore produce the same documents however many times it is called, into the
same directory or a fresh one, without leaking process-wide state.

It must also fail LOUDLY: a server that refuses to boot writes why on its
stderr, and the harness used to send that stream to ``DEVNULL`` and report
only the exit code, so a CI log named a failure with no cause and no way to
act on it.
"""

from __future__ import annotations

import hashlib
import io
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())

sys.path.insert(0, str(REPO_ROOT / "tools"))
from _serve_harness import (  # noqa: E402 — tools/ is on sys.path on the line above
    SERVER_STDERR_CAPTURE_BYTES,
    build_sample_db,
    report_server_exit,
    server_stderr,
)


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


def _finished_proc(tmp_path: Path, stderr_bytes: bytes) -> Any:
    """A reaped child with *stderr_bytes* standing in for what it wrote."""
    log = tmp_path / "serve.log"
    log.write_bytes(stderr_bytes)
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    proc.stderr_tail = log  # type: ignore[attr-defined]
    return proc


class TestServerBootFailureIsReported:
    """The exit report has to carry the server's cause, not only its code.

    A harness that answers ``server exited early with code 1`` and nothing
    else turns every boot failure — a bound port, an unparseable
    ``rebrew-project.toml``, a coverage override pointing at a file, an
    import error in the tree under test — into a CI log line with no way to
    act on it.  The stream is a temp file the harness deletes on the way out,
    so the read has to work before the teardown, which is where the failure
    paths sit.
    """

    def test_the_stderr_reaches_the_report(self, tmp_path: Path) -> None:
        proc = _finished_proc(
            tmp_path, b"Failed to start server: Address already in use\nsecond line\n"
        )

        out = io.StringIO()
        report_server_exit(proc, out)
        report = out.getvalue()

        assert "code 0" in report
        assert "Address already in use" in report, "the cause did not reach the report"
        assert "second line" in report, "the whole tail is the report, not its first line"

    def test_a_silent_child_says_so_rather_than_pretending(self, tmp_path: Path) -> None:
        """An empty stderr is its own answer, and is labelled as one."""
        proc = _finished_proc(tmp_path, b"   \n\n")

        out = io.StringIO()
        report_server_exit(proc, out)

        assert "code 0" in out.getvalue()
        assert "server stderr was empty" in out.getvalue()

    def test_a_live_server_reports_nothing(self, tmp_path: Path) -> None:
        """The report is for the exit path; a healthy run stays silent."""
        log = tmp_path / "serve.log"
        log.write_bytes(b"Starting recoverage server\n")
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        proc.stderr_tail = log  # type: ignore[attr-defined]
        try:
            out = io.StringIO()
            report_server_exit(proc, out)
            assert out.getvalue() == ""
        finally:
            proc.terminate()
            proc.wait()

    def test_the_tail_is_bounded(self, tmp_path: Path) -> None:
        """A chatty server cannot grow the report without limit."""
        proc = _finished_proc(tmp_path, b"x" * (SERVER_STDERR_CAPTURE_BYTES * 2))

        tail = server_stderr(proc)

        assert len(tail) <= SERVER_STDERR_CAPTURE_BYTES
        assert tail, "a short read of an oversized log is a read, not an empty answer"

    def test_a_missing_capture_is_not_an_exception(self, tmp_path: Path) -> None:
        """A process started without the harness still has a reportable exit."""
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()

        out = io.StringIO()
        report_server_exit(proc, out)

        assert "code 0" in out.getvalue()
        assert "server stderr was empty" in out.getvalue()
