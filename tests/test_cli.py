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
        # Should succeed but show empty/no data (not crash)
        assert result.exit_code == 0


# ── Check command ─────────────────────────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestCheckCommand:
    def test_check_with_zero_threshold(self) -> None:
        """0% threshold should always pass."""
        result = runner.invoke(app, ["check", "--min-coverage", "0"])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_check_with_100_threshold(self) -> None:
        """100% threshold will likely fail for most projects."""
        result = runner.invoke(app, ["check", "--min-coverage", "100"])
        # Exit code 1 means a section failed, which is expected
        # Exit code 0 means everything is at 100%, also valid
        assert result.exit_code in (0, 1)

    def test_check_nonexistent_section(self) -> None:
        result = runner.invoke(
            app, ["check", "--min-coverage", "50", "--section", "NONEXISTENT"]
        )
        assert result.exit_code == 1


# ── Export without DB ─────────────────────────────────────────────


class TestExportNoDb:
    def test_export_missing_db_exits(self, tmp_path, monkeypatch) -> None:
        """Running export from a directory without coverage.db should fail gracefully."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["export", "--format", "json"])
        assert result.exit_code == 1


# ── CSV edge cases (stdlib csv module) ────────────────────────────


class TestCsvEdgeCases:
    """Verify CSV module handles edge cases correctly (these values could appear in exports)."""

    def test_csv_with_commas_in_values(self) -> None:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["name,with,commas", ".data", 5000])
        buf.seek(0)
        rows = list(csv.reader(buf))
        assert rows[0][0] == "name,with,commas"

    def test_csv_with_quotes_in_values(self) -> None:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['value "with" quotes', "normal"])
        buf.seek(0)
        rows = list(csv.reader(buf))
        assert rows[0][0] == 'value "with" quotes'
