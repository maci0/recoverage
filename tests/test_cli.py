"""Tests for recoverage.cli — CLI commands via CliRunner and export formatting."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from conftest import HAS_DB
from typer.testing import CliRunner

from recoverage.cli import app

runner = CliRunner()


# ── Version command ───────────────────────────────────────────────


class TestVersionFlag:
    def test_version_prints_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "recoverage" in result.output


# ── Export command (actual CLI) ───────────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestExportCommand:
    """Test the actual `export` CLI command output."""

    def test_export_json_format(self) -> None:
        result = runner.invoke(app, ["export", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0
        assert "target" in data[0]
        assert "sections" in data[0]

    def test_export_csv_format(self) -> None:
        result = runner.invoke(app, ["export", "--format", "csv"])
        assert result.exit_code == 0
        reader = csv.reader(io.StringIO(result.output))
        rows = list(reader)
        assert len(rows) >= 2  # header + at least one data row
        header = rows[0]
        assert "target" in header
        assert "section" in header
        assert "coverage_pct" in header

    def test_export_md_format(self) -> None:
        result = runner.invoke(app, ["export", "--format", "md"])
        assert result.exit_code == 0
        assert "| Section |" in result.output
        assert "|------" in result.output

    def test_export_csv_roundtrip(self) -> None:
        """CSV output should parse back correctly with Python's csv module."""
        result = runner.invoke(app, ["export", "--format", "csv"])
        assert result.exit_code == 0
        reader = csv.reader(io.StringIO(result.output))
        rows = list(reader)
        # Every row should have the same number of columns as the header
        header_len = len(rows[0])
        for i, row in enumerate(rows[1:], 1):
            assert len(row) == header_len, f"Row {i} has {len(row)} cols, expected {header_len}"

    def test_export_csv_lf_terminators(self) -> None:
        """The csv writer must emit bare \\n, never its default \\r\\n.

        The default lineterminator ("\\r\\n") gets translated a second time by
        Windows' text-mode stdout, corrupting every row to \\r\\r\\n.  Bare \\n
        means each platform performs exactly one newline translation (CRLF on
        Windows, LF unchanged on POSIX).
        """
        result = runner.invoke(app, ["export", "--format", "csv"])
        assert result.exit_code == 0
        assert "\r" not in result.output
        assert "\n" in result.output


# ── Stats command ─────────────────────────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestStatsCommand:
    def test_stats_runs(self) -> None:
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 0

    def test_stats_with_nonexistent_target(self) -> None:
        result = runner.invoke(app, ["stats", "--target", "NONEXISTENT_TARGET_XYZ"])
        # A typo'd target must fail loudly — silently printing an empty table
        # lets automation gate on fabricated zero-coverage data.
        assert result.exit_code == 1
        assert "not found" in result.output or "not found" in result.stderr_bytes.decode()


# ── Check command ─────────────────────────────────────────────────


def _make_section_db(
    path: Path,
    sections: list[str],
    cells: list[tuple[str, int, int, str]],
) -> None:
    """Build a minimal DB: each *section* is 100 bytes with one cell per entry."""
    import sqlite3 as _sqlite3

    conn = _sqlite3.connect(path)
    try:
        c = conn.cursor()
        c.execute(
            "CREATE TABLE metadata (target TEXT, key TEXT, value TEXT,"
            " PRIMARY KEY (target, key))"
        )
        c.execute(
            "CREATE TABLE sections (target TEXT, name TEXT, va INTEGER,"
            " size INTEGER, fileOffset INTEGER, unitBytes INTEGER,"
            " columns INTEGER, PRIMARY KEY (target, name))"
        )
        c.execute(
            "CREATE TABLE cells (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " target TEXT, section_name TEXT, start INTEGER, end INTEGER,"
            " span INTEGER DEFAULT 1, state TEXT, functions TEXT DEFAULT '[]',"
            " label TEXT, parent_function TEXT)"
        )
        c.execute("CREATE TABLE functions (target TEXT, status TEXT, markerType TEXT)")
        c.execute(
            "INSERT INTO metadata VALUES ('T','summary',?)",
            (json.dumps({"totalFunctions": 1}),),
        )
        for name in sections:
            c.execute("INSERT INTO sections VALUES ('T',?,0,100,0,16,8)", (name,))
        for sec_name, start, end, state in cells:
            c.execute(
                "INSERT INTO cells (target, section_name, start, end, state)"
                " VALUES ('T',?,?,?,?)",
                (sec_name, start, end, state),
            )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestCheckCommand:
    def test_check_with_zero_threshold(self) -> None:
        """0% threshold should always pass."""
        result = runner.invoke(app, ["check", "--min-coverage", "0"])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_check_json_output(self) -> None:
        """--json emits a pure JSON verdict (no text mixed into stdout)."""
        result = runner.invoke(app, ["check", "--min-coverage", "0", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["passed"] is True
        assert payload["min_coverage"] == 0.0
        assert all("status" in r for r in payload["results"])

    def test_check_with_100_threshold(self) -> None:
        """100% threshold must produce a definitive exit code: either every
        section is at 100% (0) or at least one section fails (1)."""
        result = runner.invoke(app, ["check", "--min-coverage", "100"])
        assert result.exit_code in (0, 1)
        if result.exit_code == 0:
            assert "FAIL" not in result.output

    def test_check_min_coverage_out_of_range(self) -> None:
        """--min-coverage outside [0, 100] must be rejected, not silently
        always-pass (negative) or always-fail (over 100)."""
        for bad in ("-5", "150"):
            result = runner.invoke(app, ["check", "--min-coverage", bad])
            # Our explicit range validation → exit 1 with a clear message.
            assert result.exit_code == 1
            assert (
                "min-coverage" in result.output.lower()
                or "min-coverage" in (result.stderr_bytes or b"").decode().lower()
            )
        # Non-numeric input is a Typer parse error (exit 2) — also rejected.
        result = runner.invoke(app, ["check", "--min-coverage", "abc"])
        assert result.exit_code == 2

    def test_check_nonexistent_section(self) -> None:
        result = runner.invoke(app, ["check", "--min-coverage", "50", "--section", "NONEXISTENT"])
        assert result.exit_code == 1

    def test_check_skips_untracked_sections(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sections whose cells are all 'none' carry no coverage signal and
        must not fail the gate; explicitly gating one must fail loudly."""
        db = tmp_path / "cov.db"
        _make_section_db(
            db,
            [".text", ".data"],
            [(".text", 0, 50, "exact"), (".text", 50, 100, "none"), (".data", 0, 100, "none")],
        )

        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)
        # Untracked .data must be skipped; .text (50%) is still evaluated.
        result = runner.invoke(app, ["check", "--min-coverage", "50"])
        assert result.exit_code == 0
        assert "SKIP" in result.output
        assert "no tracked cells" in result.output
        assert "PASS" in result.output
        # Explicitly gating the untracked section must fail loudly.
        result = runner.invoke(app, ["check", "--min-coverage", "50", "--section", ".data"])
        assert result.exit_code == 1
        assert "no tracked cells" in result.output
        # A project with nothing tracked must not pass vacuously.
        db2 = tmp_path / "cov2.db"
        _make_section_db(db2, [".text"], [(".text", 0, 100, "none")])

        monkeypatch.setattr("recoverage.cli._db_path", lambda: db2)
        result = runner.invoke(app, ["check", "--min-coverage", "0"])
        assert result.exit_code == 1
        assert "nothing was checked" in result.output


# ── Export without DB ─────────────────────────────────────────────


class TestExportNoDb:
    def test_export_missing_db_exits(self, tmp_path, monkeypatch) -> None:
        """Running export from a directory without coverage.db should fail gracefully."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["export", "--format", "json"])
        assert result.exit_code == 1


# ── Export CSV (exercises recoverage's CSV writer) ─────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestExportCsv:
    def test_csv_export_has_header_and_rows(self) -> None:
        """export --format csv must emit the header + one row per section."""
        result = runner.invoke(app, ["export", "--format", "csv"])
        assert result.exit_code == 0
        lines = [ln for ln in result.output.splitlines() if ln.strip()]
        assert lines, "CSV export produced no rows"
        header = lines[0].split(",")
        assert header[0] == "target"
        assert "section" in header
        assert "coverage_pct" in header

    def test_csv_export_target_not_found(self) -> None:
        result = runner.invoke(app, ["export", "--format", "csv", "--target", "BOGUS"])
        assert result.exit_code == 1
        assert "not found" in result.output or "not found" in (result.stderr_bytes or b"").decode()


class TestCheckFailureExit:
    def test_below_threshold_exits_1(self) -> None:
        """A tracked section under the threshold must exit 1 (the CI gate's
        real failure mode — previously only the tautological (0,1) assertion
        existed)."""
        # The synthetic DB's .text is ~87.5% covered (112/128 bytes) — a
        # threshold above that fails the gate with the real coverage path.
        result = runner.invoke(app, ["check", "--min-coverage", "90", "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["passed"] is False
        assert any(r["status"] == "FAIL" for r in payload["results"])


class TestStatsJson:
    def test_stats_json_output(self) -> None:
        """stats --json must emit a parseable list of per-target stat dicts."""
        result = runner.invoke(app, ["stats", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data
        assert "target" in data[0]
        assert "sections" in data[0]
        assert ".text" in data[0]["sections"]


class TestPartialSchemaCleanExit:
    """A DB that lists targets but cannot answer stats queries must exit 2
    with a rebuild hint, not a traceback (same contract as _select_targets)."""

    def test_stats_clean_error_on_partial_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sqlite3

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        conn.execute("INSERT INTO metadata VALUES ('t1', 'db_version', '\"4\"')")
        conn.commit()
        conn.close()

        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 2
        assert "rebuild" in result.output
        assert not isinstance(result.exception, SystemExit) or result.exit_code == 2


# ── check: exit-code and verdict contracts ────────────────────────


class TestCheckMissingDbExitCode:
    def test_missing_db_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing database is an infrastructure error: README documents
        exit 2 for `check` (database missing/unreadable), distinct from the
        gate-failure exit 1 a CI consumer acts on."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--min-coverage", "60"])
        assert result.exit_code == 2
        assert "database not found" in result.output


class TestCheckExplicitUntrackedSectionVerdict:
    def test_fail_verdict_reaches_json_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Gating an explicitly requested untracked section records FAIL; that
        verdict — not the generic 'nothing was checked' error object — must be
        what --json emits."""
        db = tmp_path / "cov.db"
        _make_section_db(
            db,
            [".text", ".rdata"],
            [(".text", 0, 100, "exact"), (".rdata", 0, 100, "none")],
        )
        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)

        result = runner.invoke(
            app, ["check", "--min-coverage", "60", "--section", ".rdata", "--json"]
        )
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["passed"] is False
        assert payload["results"] == [
            {
                "target": "T",
                "section": ".rdata",
                "status": "FAIL",
                "reason": "no tracked cells — coverage is not recorded for this section",
            }
        ]
        assert "nothing was checked" not in result.output

    def test_all_untracked_still_errors_without_verdicts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no explicit section and nothing tracked anywhere, the guard
        still fires: no recorded coverage must not pass vacuously."""
        db = tmp_path / "cov.db"
        _make_section_db(
            db,
            [".text", ".rdata"],
            [(".text", 0, 100, "exact"), (".rdata", 0, 100, "none")],
        )
        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)

        # Drop the tracked .text cell so every section is untracked.
        import sqlite3 as _sqlite3

        conn = _sqlite3.connect(db)
        conn.execute("DELETE FROM cells WHERE section_name = '.text'")
        conn.commit()
        conn.close()

        result = runner.invoke(app, ["check", "--min-coverage", "0", "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["error"] == "no tracked sections — nothing was checked"


class TestServePortRange:
    def test_out_of_range_port_rejected_cleanly(self) -> None:
        """--port 99999 must be a clean CLI validation error, not an
        OverflowError traceback from socket.bind after startup."""
        result = runner.invoke(app, ["serve", "--port", "99999", "--no-open"])
        assert result.exit_code != 0
        assert "OverflowError" not in result.output
        assert "not in the range" in result.output

    def test_open_port_range_validated(self) -> None:
        result = runner.invoke(app, ["open", "--port", "70000"])
        assert result.exit_code != 0


class TestServeBindFailure:
    def test_bind_failure_does_not_open_browser(self, monkeypatch: Any) -> None:
        """A bind failure (port already in use) must cancel the deferred
        browser opener: no tab at a dead port, and the CLI exits promptly
        instead of waiting on the opener thread at interpreter shutdown."""
        import socket
        import time

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        opened: list[str] = []
        monkeypatch.setattr("recoverage.server.open_browser", lambda url: opened.append(url))

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            port = sock.getsockname()[1]
            start = time.monotonic()
            result = runner.invoke(app, ["serve", "--port", str(port), "--bind", "127.0.0.1"])

        assert result.exit_code == 1
        assert "already running" in result.output or "Failed to start server" in result.output
        # The timer fires 0.5s after scheduling; serve() cancels it on the
        # failure path before exiting, so a bounded wait proves the event
        # never happens.
        time.sleep(0.7)
        assert opened == []
        assert time.monotonic() - start < 5, "serve took too long to exit after bind failure"


class TestServeKeyboardInterrupt:
    def test_ctrl_c_exits_cleanly(self, monkeypatch: Any) -> None:
        """Ctrl+C is the documented stop mechanism ("Stop: Ctrl+C"): serve
        must exit 0 quietly instead of unwinding a KeyboardInterrupt
        traceback out of wsgiref's accept loop."""
        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)

        def raise_interrupt(self: Any, **kwargs: Any) -> None:
            raise KeyboardInterrupt

        # Instance-level monkeypatch breaks bottle: Bottle.__setattr__ rejects
        # re-setting a name once it exists in the instance dict (plugin
        # conflict guard), so patch the class method instead.
        monkeypatch.setattr(type(server_app), "run", raise_interrupt)
        result = runner.invoke(app, ["serve", "--no-open", "--port", "8123"])
        assert result.exit_code == 0


class TestBrokenPipe:
    def test_main_converts_broken_pipe_to_clean_exit(self, monkeypatch: Any) -> None:
        """`recoverage export | head` closing stdout early must exit
        non-zero without a spurious traceback at interpreter shutdown."""
        import recoverage.cli as cli

        class _NoFd(io.StringIO):
            """Captured stdout has no real fd; the devnull redirect is skipped."""

            def fileno(self) -> int:
                raise io.UnsupportedOperation("no fd")

        def boom() -> None:
            raise BrokenPipeError(32, "Broken pipe")

        monkeypatch.setattr(cli, "app", boom)
        monkeypatch.setattr(sys, "stdout", _NoFd())
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        assert excinfo.value.code == 1

    def test_main_reruns_app_normally_after_other_errors(self, monkeypatch: Any) -> None:
        """Only BrokenPipeError is converted; other exceptions propagate."""
        import recoverage.cli as cli

        def boom() -> None:
            raise RuntimeError("unrelated crash")

        monkeypatch.setattr(cli, "app", boom)
        with pytest.raises(RuntimeError):
            cli.main()
