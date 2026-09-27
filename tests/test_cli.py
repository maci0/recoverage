"""Tests for recoverage.cli — CLI commands via CliRunner and export formatting."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from conftest import HAS_DB
from typer.testing import CliRunner

from recoverage import cli
from recoverage.cli import app

runner = CliRunner()

#: The SGR sequence Rich paints the bold cyan target heading of `stats` with.
#: Named because the color opt-out test asserts on the color part of that
#: sequence, and Rich keeps the bold attribute when color is dropped.
CYAN_HEADING = "\x1b[1;36m"


# ── Version command ───────────────────────────────────────────────


class TestColorOptOut:
    """`--no-color`, NO_COLOR, and TERM=dumb must all silence the escapes.

    Click only strips ANSI when the stream is not a TTY, so on a terminal
    these three conditions were previously ignored and every error, warning,
    and check verdict carried escape codes into a color_forced log.  Every
    invocation passes color=True, which is what makes the escapes visible at
    all, and clears NO_COLOR/TERM unless the test is about one of them.
    """

    @pytest.fixture(autouse=True)
    def _colored_terminal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")

    def test_color_enabled_by_default(self) -> None:
        result = runner.invoke(app, ["check", "--min-coverage", "0"], color=True)
        assert result.exit_code == 0
        assert "\x1b[" in result.output

    def test_no_color_flag(self) -> None:
        result = runner.invoke(app, ["--no-color", "check", "--min-coverage", "0"], color=True)
        assert result.exit_code == 0
        assert "\x1b[" not in result.output

    def test_no_color_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        result = runner.invoke(app, ["check", "--min-coverage", "0"], color=True)
        assert result.exit_code == 0
        assert "\x1b[" not in result.output

    def test_dumb_terminal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TERM", "dumb")
        result = runner.invoke(app, ["check", "--min-coverage", "0"], color=True)
        assert result.exit_code == 0
        assert "\x1b[" not in result.output

    def test_opt_out_does_not_leak_into_the_next_run(self) -> None:
        """The global flag is per invocation, not sticky process state."""
        first = runner.invoke(app, ["--no-color", "check", "--min-coverage", "0"], color=True)
        assert first.exit_code == 0
        assert "\x1b[" not in first.output, "the opt-out run must already be uncolored"
        result = runner.invoke(app, ["check", "--min-coverage", "0"], color=True)
        assert result.exit_code == 0
        assert "\x1b[" in result.output

    def test_errors_honor_the_opt_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The stderr error path takes the same route as the verdicts."""
        monkeypatch.setenv("NO_COLOR", "1")
        result = runner.invoke(app, ["check", "--min-coverage", "200"], color=True)
        assert result.exit_code == 2
        assert "\x1b[" not in result.stderr

    @pytest.mark.parametrize(
        ("argv", "env"),
        [
            (["open", "--port", "99999"], {}),
            (["serve", "--port", "99999"], {}),
            # `stats` validates the environment through _check_env_or_exit;
            # an empty RECOVERAGE_DB is the one setting every command reads.
            (["stats"], {"RECOVERAGE_DB": ""}),
        ],
        ids=["open-port", "serve-config", "bad-environment"],
    )
    def test_config_error_paths_honor_the_opt_out(
        self, argv: list[str], env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every exit-2 configuration error colors through _secho, not
        typer.secho: a bare secho ignored all three opt-outs and still wrote
        red escapes into a color_forced log.  `serve` and `open` exit before
        they do any work, so neither starts a listener."""
        monkeypatch.setenv("NO_COLOR", "1")
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        result = runner.invoke(app, argv, color=True)
        assert result.exit_code == 2, result.output
        assert "\x1b[" not in result.stderr

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_stats_table_honors_the_opt_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`stats` renders through Rich, which detects NO_COLOR and TERM=dumb
        itself but cannot see the --no-color flag; the table is the widest
        colored surface the CLI has, so the flag has to reach the Console.

        FORCE_COLOR is what makes Rich emit color into a pipe, the state a
        redirected run is in, and the bold cyan target heading is the color
        surface it paints.  Rich's no_color drops color and keeps text
        attributes, so the bold that remains is not the assertion.
        """
        monkeypatch.setenv("FORCE_COLOR", "1")
        colored = runner.invoke(app, ["stats"], color=True)
        assert colored.exit_code == 0, colored.output
        assert CYAN_HEADING in colored.stdout

        plain = runner.invoke(app, ["--no-color", "stats"], color=True)
        assert plain.exit_code == 0, plain.output
        assert CYAN_HEADING not in plain.stdout


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

    def test_export_md_column_counts_match_header(self) -> None:
        """Every Markdown data row must have as many cells as the header."""
        result = runner.invoke(app, ["export", "--format", "md"])
        assert result.exit_code == 0
        header = next(line for line in result.output.splitlines() if line.startswith("| Section |"))
        expected = header.count("|")
        data_rows = [
            line for line in result.output.splitlines() if line.startswith("|") and " B |" in line
        ]
        assert data_rows, "Markdown export produced no section rows"
        for row in data_rows:
            assert row.count("|") == expected, f"ragged Markdown row: {row}"

    def test_export_md_table_columns_line_up(self) -> None:
        """Header, separator, and body rows must carry the same cell count.

        The md export once emitted 8 header cells, a 9-cell separator, and 11
        body values (Exact/Reloc/Near duplicated), so no renderer could line the
        table up.
        """
        result = runner.invoke(app, ["export", "--format", "md"])
        assert result.exit_code == 0
        table_rows = [ln.strip() for ln in result.output.splitlines() if ln.strip().startswith("|")]
        assert table_rows, "no markdown table rows in md export"
        widths = {len(ln.strip("|").split("|")) for ln in table_rows}
        assert len(widths) == 1, f"ragged markdown table: column counts {sorted(widths)}"

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
        assert "\n" in result.output
        if os.linesep == "\n":
            assert "\r" not in result.output
        else:
            # The captured stream is text mode with universal newlines, so the
            # bare \n is translated once on the way out.  Two translations
            # (the default "\r\n" terminator plus that one) show as "\r\r\n".
            assert "\r\r\n" not in result.output


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
            "CREATE TABLE metadata (target TEXT, key TEXT, value TEXT, PRIMARY KEY (target, key))"
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
                "INSERT INTO cells (target, section_name, start, end, state) VALUES ('T',?,?,?,?)",
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
        """100% threshold must fail the synthetic DB deterministically:
        .text sits at 87.5% covered (112/128 bytes) and .data at 100%, so
        the gate exits 1 with exactly one FAIL verdict — the CI consumer's
        real contract (the old assertion accepted any exit in (0, 1))."""
        result = runner.invoke(app, ["check", "--min-coverage", "100", "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["passed"] is False
        by_section = {r["section"]: r for r in payload["results"]}
        assert by_section[".text"]["status"] == "FAIL"
        assert by_section[".text"]["coverage_pct"] == 87.5
        assert by_section[".data"]["status"] == "PASS"

    def test_check_gate_compares_unrounded_ratio(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The gate decides on the RAW byte ratio, not the 2dp-rounded
        coverage_pct: 999997/1000000 bytes is truly 99.9997% covered even
        though _section_stats stores it as 100.0, so --min-coverage 100 must
        FAIL — and a ratio exactly at the threshold still PASSes."""
        db = tmp_path / "cov.db"
        _make_section_db(
            db,
            [".text"],
            [(".text", 0, 999_997, "exact"), (".text", 999_997, 1_000_000, "none")],
        )
        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)
        result = runner.invoke(app, ["check", "--min-coverage", "100", "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["passed"] is False

        exact_db = tmp_path / "exact.db"
        _make_section_db(
            exact_db,
            [".text"],
            [(".text", 0, 875, "exact"), (".text", 875, 1_000, "none")],
        )
        monkeypatch.setattr("recoverage.cli._db_path", lambda: exact_db)
        result = runner.invoke(app, ["check", "--min-coverage", "87.5", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["passed"] is True

    def test_check_out_of_range_json_emits_error_object(self) -> None:
        """--json with an out-of-range threshold must still emit a parseable
        JSON error (not the human-readable stderr path) before exiting 2."""
        result = runner.invoke(app, ["check", "--min-coverage", "150", "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.output)
        assert payload["error"]
        assert payload["exit_code"] == 2

    def test_check_min_coverage_out_of_range(self) -> None:
        """--min-coverage outside [0, 100] must be rejected, not silently
        always-pass (negative) or always-fail (over 100)."""
        for bad in ("-5", "150"):
            result = runner.invoke(app, ["check", "--min-coverage", bad])
            # Our explicit range validation → exit 2 with a clear message,
            # the same usage-error code a non-numeric value gets.
            assert result.exit_code == 2
            assert (
                "min-coverage" in result.output.lower()
                or "min-coverage" in (result.stderr_bytes or b"").decode().lower()
            )
        # Non-numeric input is a Typer parse error (exit 2) — also rejected.
        result = runner.invoke(app, ["check", "--min-coverage", "abc"])
        assert result.exit_code == 2

    def test_check_nonexistent_section(self) -> None:
        """A --section matching nothing is an error, not a gate failure: exit 1
        alone would also accept a genuine coverage failure, so the message and
        the empty verdict list are what this test pins."""
        result = runner.invoke(
            app, ["check", "--min-coverage", "50", "--section", "NONEXISTENT", "--json"]
        )
        assert result.exit_code == 1
        lines = result.output.splitlines()
        assert any("has no section NONEXISTENT" in line for line in lines)
        # The per-target SKIP note shares the stream with the JSON error object,
        # so the payload is the last line, not the whole output.
        payload = json.loads(lines[-1])
        assert payload["error"] == "no sections matched — nothing was checked"
        assert "results" not in payload

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


class TestExportCsvFormulaInjection:
    """Section names originate in analyzed PE binaries — untrusted input.
    A crafted name must not survive export as a spreadsheet-executable
    formula (CWE-1236): cells starting with = + - @ are apostrophe-prefixed."""

    def _export_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, section: str
    ) -> list[list[str]]:
        """Export a one-section DB as CSV; return the parsed rows."""
        db = tmp_path / "cov.db"
        _make_section_db(db, [section], [(section, 0, 100, "exact")])
        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)

        result = runner.invoke(app, ["export", "--format", "csv"])
        assert result.exit_code == 0
        return list(csv.reader(io.StringIO(result.output)))

    def test_formula_section_name_is_neutralized(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        evil = '=HYPERLINK("http://evil.example","pwned")'
        rows = self._export_rows(tmp_path, monkeypatch, evil)
        sec_col = rows[0].index("section")
        assert rows[1][sec_col] == "'" + evil

    @pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t"])
    def test_all_formula_leads_are_escaped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str
    ) -> None:
        rows = self._export_rows(tmp_path, monkeypatch, f"{prefix}evil")
        sec_col = rows[0].index("section")
        assert rows[1][sec_col] == f"'{prefix}evil"

    def test_normal_names_pass_through_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = self._export_rows(tmp_path, monkeypatch, ".text")
        sec_col = rows[0].index("section")
        assert rows[1][sec_col] == ".text"


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


class TestStatsNullSectionSize:
    def test_stats_survives_null_section_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A schema-legal NULL sections.size on a section that has cells must
        render as "0 B", not crash `recoverage stats`/`export` with a raw
        TypeError from f"{size_bytes:,}" (None is not formattable)."""
        import sqlite3

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        try:
            c = conn.cursor()
            c.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
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
                "CREATE VIEW section_cell_stats AS"
                " SELECT target, section_name, COUNT(*) as total_cells,"
                " SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,"
                " SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) as reloc_count,"
                " SUM(CASE WHEN state IN ('near_match','near_matching') THEN 1 ELSE 0 END)"
                "   as near_match_count,"
                " SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) as stub_count,"
                " SUM(CASE WHEN state = 'padding' THEN 1 ELSE 0 END) as padding_count,"
                " SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) as data_count,"
                " SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) as thunk_count,"
                " SUM(CASE WHEN state = 'none' THEN 1 ELSE 0 END) as none_count,"
                " SUM(CASE WHEN state = 'proven' THEN 1 ELSE 0 END) as proven_count,"
                " SUM(CASE WHEN state = 'size_mismatch' THEN 1 ELSE 0 END)"
                "   as size_mismatch_count"
                " FROM cells GROUP BY target, section_name"
            )
            c.execute("INSERT INTO metadata VALUES ('T','summary','{}')")
            # .bss shape: every column NULL except identity.
            c.execute("INSERT INTO sections VALUES ('T','.bss',NULL,NULL,NULL,NULL,NULL)")
            c.execute(
                "INSERT INTO cells (target, section_name, start, end, state)"
                " VALUES ('T','.bss',0,16,'none')"
            )
            conn.commit()
        finally:
            conn.close()

        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 0
        assert ".bss" in result.output
        assert "0 B" in result.output


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
        # The partial schema must surface as the clean exit 2 above, not as a
        # leaked sqlite3 error riding out through the runner.
        assert not isinstance(result.exception, sqlite3.OperationalError)


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


class TestJsonErrorEnvelope:
    """A machine-readable mode answers every failure in one shape.

    `check --json` emitted a JSON envelope for a failed gate, a bad
    --min-coverage and an empty result set, but a missing database and an
    unknown --target still printed a plain stderr line, and `stats --json` /
    `export --format json` had no envelope at all.  A script piping the JSON
    channel into a parser therefore had to special-case which failure it was.
    Every failure in a --json mode now answers
    {"error": ..., "exit_code": N} on stdout, with the exit status unchanged.
    """

    MISSING = "database not found"

    def test_check_json_missing_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--min-coverage", "60", "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.stdout)
        assert self.MISSING in payload["error"]
        assert payload["exit_code"] == 2

    def test_stats_json_missing_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["stats", "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert self.MISSING in payload["error"]
        assert payload["exit_code"] == 1

    def test_export_json_missing_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["export", "--format", "json"])
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert self.MISSING in payload["error"]
        assert payload["exit_code"] == 1

    def test_csv_export_keeps_the_human_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-JSON format has no machine channel to fill, so its failure
        stays a stderr line and stdout carries nothing a parser could
        misread as data."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["export", "--format", "csv"])
        assert result.exit_code == 1
        assert result.stdout == ""
        assert self.MISSING in result.stderr

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_unknown_target_is_an_envelope(self) -> None:
        for argv in (
            ["stats", "--json", "--target", "no-such-target"],
            ["check", "--min-coverage", "0", "--json", "--target", "no-such-target"],
        ):
            result = runner.invoke(app, argv)
            assert result.exit_code == 1, argv
            payload = json.loads(result.stdout)
            assert payload == {"error": "target not found: 'no-such-target'", "exit_code": 1}


class TestHelpMarkup:
    """`--help` is rendered through Rich, so a reStructuredText spelling in a
    command docstring reaches the user verbatim: double backticks around a
    flag name print as ``` ``--no-open`` ``` rather than as emphasis."""

    @pytest.mark.parametrize("command", ["serve", "open"])
    def test_no_raw_rest_markup_in_help(self, command: str) -> None:
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0
        assert "``" not in result.output


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestStatsOutputStart:
    def test_first_target_heading_starts_the_output(self) -> None:
        """The first heading carried a leading newline no later heading did,
        so redirected output opened with an empty line.  `export --format md`
        already refuses that leading blank; the table must agree."""
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 0
        assert result.stdout.startswith("FAKEDLL")


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


class TestOpenPort:
    """`open` targets the port `serve` would use, so the env reaches it too."""

    def test_env_port_is_the_default(self, monkeypatch: Any) -> None:
        opened: list[str] = []
        monkeypatch.setenv("RECOVERAGE_PORT", "9100")
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url))
        result = runner.invoke(app, ["open"])
        assert result.exit_code == 0
        assert opened == ["http://127.0.0.1:9100"]

    def test_flag_beats_env(self, monkeypatch: Any) -> None:
        opened: list[str] = []
        monkeypatch.setenv("RECOVERAGE_PORT", "9100")
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url))
        result = runner.invoke(app, ["open", "--port", "9200"])
        assert result.exit_code == 0
        assert opened == ["http://127.0.0.1:9200"]

    def test_invalid_env_port_exits_2(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("RECOVERAGE_PORT", "not-a-port")
        result = runner.invoke(app, ["open"])
        assert result.exit_code == 2
        assert "RECOVERAGE_PORT" in result.output


class TestServeServerWiring:
    def test_run_gets_threaded_server_and_bounded_handler(self, monkeypatch: Any) -> None:
        """serve must wire the threaded server class AND the request handler
        carrying the per-connection socket deadline.  ThreadingMixIn caps
        neither threads nor connections; without the handler's timeout, a
        silent peer (crashed laptop, dropped NAT mapping) or an SSE client
        that stops reading pins its handler thread forever."""
        import recoverage.cli as cli
        from recoverage.server import app as server_app

        captured: dict[str, Any] = {}

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)

        def capture_run(self: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        # Instance-level monkeypatch breaks bottle: Bottle.__setattr__ rejects
        # re-setting a name once it exists in the instance dict (plugin
        # conflict guard), so patch the class method instead.
        monkeypatch.setattr(type(server_app), "run", capture_run)
        result = runner.invoke(app, ["serve", "--no-open", "--port", "8123"])
        assert result.exit_code == 0
        assert captured["server_class"] is cli._ThreadingWSGIServer
        assert captured["server_class"].daemon_threads is True
        assert captured["handler_class"] is cli._KeepAliveRequestHandler
        handler = captured["handler_class"]
        assert issubclass(handler, cli._QuietTimeoutRequestHandler)
        assert handler.timeout == cli._CLIENT_SOCKET_TIMEOUT_SECONDS > 0

    def test_served_over_http_1_1_so_the_browser_reuses_the_connection(self) -> None:
        """The handler must speak HTTP/1.1.

        wsgiref is HTTP/1.0 and answers one request per connection, so
        loading the dashboard paid a TCP handshake for the shell, detail.js,
        the targets list and the data payload.  Keep-alive only exists under
        1.1, and the preamble comes from the ServerHandler subclass, not the
        request handler, so both are pinned here.
        """
        import recoverage.cli as cli

        assert cli._KeepAliveRequestHandler.protocol_version == "HTTP/1.1"
        assert cli._KeepAliveServerHandler.http_version == "1.1"


class TestResponseFraming:
    """Which responses may leave the connection open after them.

    A response with neither Content-Length nor Transfer-Encoding ends only
    when the socket does.  Under HTTP/1.1 the client would read straight into
    the next response, so the streamed /api/events has to close the
    connection it finishes on.
    """

    @staticmethod
    def _framed(headers: dict[str, str], status: str = "200 OK", method: str = "GET") -> bool:
        from wsgiref.headers import Headers

        import recoverage.cli as cli

        handler = cli._KeepAliveServerHandler.__new__(cli._KeepAliveServerHandler)
        handler.headers = Headers()
        for name, value in headers.items():
            handler.headers[name] = value
        handler.status = status
        handler.environ = {"REQUEST_METHOD": method}
        return handler._response_is_framed()

    def test_content_length_keeps_the_connection(self) -> None:
        assert self._framed({"Content-Length": "12"})

    def test_chunked_keeps_the_connection(self) -> None:
        assert self._framed({"Transfer-Encoding": "chunked"})

    def test_header_name_case_does_not_decide(self) -> None:
        assert self._framed({"content-length": "12"})

    def test_unframed_body_closes_the_connection(self) -> None:
        assert not self._framed({"Content-Type": "text/event-stream"})

    def test_bodyless_status_needs_no_length(self) -> None:
        assert self._framed({}, status="304 Not Modified")
        assert self._framed({}, status="204 No Content")

    def test_head_response_needs_no_length(self) -> None:
        assert self._framed({}, method="HEAD")


class TestServeBindFailure:
    def test_bind_failure_does_not_open_browser(self, monkeypatch: Any) -> None:
        """A bind failure (port already in use) must cancel the deferred
        browser opener: no tab at a dead port, and the CLI exits promptly
        instead of waiting on the opener thread at interpreter shutdown."""
        import socket
        import time

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        opened: list[str] = []
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url))

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

    def test_ctrl_c_cancels_deferred_browser_opener(self, monkeypatch: Any) -> None:
        """A Ctrl+C inside the opener's 0.5s scheduling window is a failed
        start: like the bind-failure path, it must cancel the timer so no
        browser tab opens pointing at a port that was never served."""
        import time

        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        opened: list[str] = []
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url))

        def raise_interrupt(self: Any, **kwargs: Any) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(type(server_app), "run", raise_interrupt)
        result = runner.invoke(app, ["serve", "--port", "8123"])
        assert result.exit_code == 0
        time.sleep(0.7)  # past the timer's 0.5s deadline
        assert opened == [], "cancelled opener still fired after Ctrl+C"


class TestRegenFailures:
    def test_failing_in_process_regen_exits_cleanly(self, monkeypatch: Any) -> None:
        """A rebrew failure inside run_regen must get the clean exit-1 contract
        (not a raw traceback), matching the API regen endpoint's JSON 500."""
        import recoverage.regen as regen

        def boom(root: Path) -> None:
            raise RuntimeError("catastrophic catalog failure")

        monkeypatch.setattr(regen, "run_regen", boom)

        result = runner.invoke(app, ["regen"])
        assert result.exit_code == 1
        assert "catastrophic catalog failure" in result.output
        assert "Traceback" not in result.output

    def test_missing_rebrew_import_error_exits_cleanly(self, monkeypatch: Any) -> None:
        """rebrew is a required dependency, so an ImportError means a broken
        install: it gets the generic exit-1 contract, with no install hint."""
        import recoverage.regen as regen

        def boom(root: Path) -> None:
            raise ImportError("No module named 'rebrew'")

        monkeypatch.setattr(regen, "run_regen", boom)

        result = runner.invoke(app, ["regen"])
        assert result.exit_code == 1
        assert "No module named 'rebrew'" in result.output
        assert "recoverage[regen]" not in result.output
        assert "Traceback" not in result.output

    def test_rebrew_error_exit_is_not_a_traceback(self, monkeypatch: Any) -> None:
        """rebrew's error_exit raises typer.Exit, which is click's Exit (a
        RuntimeError), not SystemExit: it must not escape as a traceback."""
        import typer

        import recoverage.regen as regen

        def boom(root: Path) -> None:
            raise typer.Exit(2)

        monkeypatch.setattr(regen, "run_regen", boom)

        result = runner.invoke(app, ["regen"])
        assert result.exit_code == 1
        assert "Traceback" not in result.output


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


def test_export_md_rows_match_the_header() -> None:
    """Every markdown row must have as many cells as the header.

    The row builder emitted near_match twice against an 8-column header, so
    Stub rendered under the Coverage heading and the real coverage landed in an
    unlabeled 9th column — every markdown export read as a malformed table.
    """
    result = runner.invoke(app, ["export", "--format", "md"])
    assert result.exit_code == 0
    lines = [ln for ln in result.output.splitlines() if ln.strip()]
    header = next(ln for ln in lines if ln.startswith("| Section |"))
    ncols = header.count("|") - 1
    for line in lines:
        if not line.startswith("| ") or set(line) <= set("|- "):
            continue
        assert line.count("|") - 1 == ncols, f"row does not match header: {line}"


# ── stdout encoding ───────────────────────────────────────────────


def _unicode_db(path: Path) -> Path:
    """A DB whose target id and section name are both non-ASCII."""
    import sqlite3 as _sqlite3

    conn = _sqlite3.connect(path)
    try:
        c = conn.cursor()
        c.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        c.execute(
            "CREATE TABLE sections (target TEXT, name TEXT, va INTEGER, size INTEGER,"
            " fileOffset INTEGER, unitBytes INTEGER, columns INTEGER)"
        )
        c.execute(
            "CREATE TABLE cells (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT,"
            " section_name TEXT, start INTEGER, end INTEGER, span INTEGER DEFAULT 1,"
            " state TEXT, functions TEXT DEFAULT '[]', label TEXT, parent_function TEXT)"
        )
        c.execute(
            "CREATE TABLE functions (target TEXT, va INTEGER, name TEXT, status TEXT,"
            " markerType TEXT)"
        )
        c.execute(
            "INSERT INTO metadata VALUES ('café & bar','summary',?)",
            (json.dumps({"totalFunctions": 1}),),
        )
        c.execute("INSERT INTO sections VALUES ('café & bar','.données',0,100,0,16,8)")
        c.execute(
            "INSERT INTO cells (target, section_name, start, end, state)"
            " VALUES ('café & bar','.données',0,50,'exact')"
        )
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestExportStdoutEncoding:
    """The export must not inherit the locale's codec.

    Target ids and section names come from the PE image, so a non-ASCII one
    is ordinary input.  With stdout on an ASCII codec the CSV writer raised
    UnicodeEncodeError part-way through, leaving a truncated file behind the
    `> coverage.csv` redirect the help text documents.
    """

    def _ascii_stdout(self, monkeypatch: pytest.MonkeyPatch) -> io.BytesIO:
        buffer = io.BytesIO()
        monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer, encoding="ascii"))
        return buffer

    def test_csv_export_survives_an_ascii_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _unicode_db(tmp_path / "unicode.db")
        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)
        buffer = self._ascii_stdout(monkeypatch)
        # Called directly, not through CliRunner: the runner swaps in its own
        # UTF-8 stdout, which is exactly the codec under test.
        cli.export(output_format=cli.ExportFormat.csv, target=None)
        sys.stdout.flush()
        assert ".données" in buffer.getvalue().decode("utf-8")

    def test_md_export_survives_an_ascii_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _unicode_db(tmp_path / "unicode.db")
        monkeypatch.setattr("recoverage.cli._db_path", lambda: db)
        buffer = self._ascii_stdout(monkeypatch)
        cli.export(output_format=cli.ExportFormat.md, target=None)
        sys.stdout.flush()
        text = buffer.getvalue().decode("utf-8")
        assert "## café & bar" in text
        assert ".données" in text
