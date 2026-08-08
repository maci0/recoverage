"""Tests for recoverage.cli — CLI commands via CliRunner and export formatting."""

from __future__ import annotations

import csv
import io
import json

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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestCheckCommand:
    def test_check_with_zero_threshold(self) -> None:
        """0% threshold should always pass."""
        result = runner.invoke(app, ["check", "--min-coverage", "0"])
        assert result.exit_code == 0
        assert "PASS" in result.output

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
