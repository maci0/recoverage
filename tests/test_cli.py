"""Tests for recoverage.cli — CLI commands via CliRunner and export formatting."""

from __future__ import annotations

import csv
import io
import json
import os
import socket
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import typer
from conftest import HAS_DB
from coverage_fixture import cell, coverage_dir, write_coverage
from rebrew.coverage_toml import CoverageTomlError
from typer.testing import CliRunner

from recoverage import cli, devserver, server
from recoverage.cli import ExportFormat, _server_class_for, app

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

    @pytest.mark.parametrize(
        "argv",
        [
            ["check", "--min-coverage", "200"],
            ["stats"],
            ["export", "--format", "csv"],
            ["config"],
            ["open", "--port", "99999"],
        ],
    )
    def test_no_color_after_the_subcommand(self, argv: list[str]) -> None:
        """The flag is declared on every command, not only on the group.

        A flag that can only be spelled before the subcommand is a usage
        error in the position a user reaches for first, and that position is
        where every other flag goes.  `check` with an out-of-range threshold
        is the command that prints without a coverage database, so it also
        carries the color assertion; the rest only have to parse.
        """
        result = runner.invoke(app, [*argv, "--no-color"], color=True)
        assert "No such option" not in result.output
        if argv[0] == "check":
            assert result.exit_code == 2
            assert "\x1b[" not in result.stderr

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


class TestHelpOptionNames:
    """`-h` is the alias the man page documents, on the group and every command.

    The man page lists `-h, --help`, and `-h` is the spelling a POSIX reader
    reaches for first, so a tree that only accepted `--help` made the page
    wrong. The context setting covers the group and every subcommand, and no
    command claims `-h` for anything else.
    """

    COMMANDS = (
        (),
        ("serve",),
        ("stats",),
        ("export",),
        ("check",),
        ("regen",),
        ("open",),
        ("config",),
    )

    def test_short_help_works_everywhere_long_help_does(self) -> None:
        for command in self.COMMANDS:
            short = runner.invoke(app, [*command, "-h"])
            long = runner.invoke(app, [*command, "--help"])
            assert short.exit_code == 0, (command, short.output)
            assert short.output == long.output, command


class TestRebuildAdvice:
    """Every place the CLI tells a user how to build the documents.

    `rebrew build-db` runs the catalog analysis in process, so an advice
    string naming a separate `rebrew catalog` step sends a user looking for
    a command they do not have to run. Both spellings are pinned here, since
    they are separate strings in the source and one can drift alone.
    """

    def test_help_names_only_the_command_that_writes_the_documents(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        prerequisites = result.output.split("Prerequisites:")[1]
        assert "rebrew build-db" in prerequisites
        assert "rebrew catalog" not in prerequisites

    def test_the_database_error_hint_names_only_build_db(self) -> None:
        assert "rebrew catalog" not in cli._REBUILD_HINT
        assert "rebrew build-db" in cli._REBUILD_HINT


class TestBareInvocationServes:
    """`recoverage` with no arguments serves the dashboard.

    Click's "Missing command" is what a user standing in a rebrew project
    directory used to get, which is the one answer that helps nobody: the
    dashboard is the only thing most invocations want, and `serve` is the
    only spelling of it that requires remembering the subcommand.  Any
    argument at all keeps click's own answer, so `recoverage --help` still
    prints help and `recoverage --version` still prints the version.
    """

    def test_bare_argv_runs_serve(self) -> None:
        assert cli._argv_with_default_command(["recoverage"]) == ["recoverage", "serve"]

    @pytest.mark.parametrize(
        "argv",
        [
            ["recoverage", "serve"],
            ["recoverage", "stats"],
            ["recoverage", "serve", "--port", "9000"],
            ["recoverage", "--no-color", "stats"],
            ["recoverage", "--help"],
        ],
    )
    def test_any_argument_is_left_alone(self, argv: list[str]) -> None:
        assert cli._argv_with_default_command(argv) == argv

    @pytest.mark.parametrize(
        "argv",
        [
            ["recoverage", "--no-color"],
            ["recoverage", "--version", "--no-color"],
        ],
    )
    def test_a_group_flag_alone_still_serves(self, argv: list[str]) -> None:
        # The group flags are documented as accepted before the subcommand,
        # so the bare form reaches `serve` too.  `--version` is eager and
        # ends the invocation, appended token or not.
        expected = argv if "--version" in argv else [*argv, "serve"]
        assert cli._argv_with_default_command(argv) == expected

    def test_bare_run_reaches_the_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # End to end through the entry point, with the listener stubbed: the
        # proof is that `serve`'s banner is printed, not click's error.
        class _StubApp:
            @staticmethod
            def run(**_kwargs: Any) -> None:
                raise KeyboardInterrupt

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("recoverage.webapp.app", _StubApp)
        monkeypatch.setattr(cli, "open_browser", lambda _url: None)
        monkeypatch.setattr(sys, "argv", ["recoverage"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "Serving coverage dashboard at" in out
        assert "Missing command" not in out

    def test_a_group_flag_before_the_subcommand_reaches_the_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class _StubApp:
            @staticmethod
            def run(**_kwargs: Any) -> None:
                raise KeyboardInterrupt

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("recoverage.webapp.app", _StubApp)
        monkeypatch.setattr(cli, "open_browser", lambda _url: None)
        monkeypatch.setattr(sys, "argv", ["recoverage", "--no-color"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "Serving coverage dashboard at" in out
        assert "Missing command" not in out


class TestLogStamp:
    """The log line's time stamp must place a record on a timeline.

    A bare "%H:%M:%S" cannot: 23:59 and 00:01 read as the same moment, and a
    log spanning a fall-back transition prints its repeated hour twice with
    nothing to tell the two apart.  The offset matters for the same reason —
    a reader must not have to assume the host's zone to place a line.

    The stamp is local time with the offset attached, so the expected strings
    below only hold under a known zone: the fixture pins TZ=UTC and the third
    test reads the offset off the line instead of assuming one.
    """

    @pytest.fixture(autouse=True)
    def _utc(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        import time

        if not hasattr(time, "tzset"):
            pytest.skip("no time.tzset() on this platform")
        previous = os.environ.get("TZ")
        monkeypatch.setenv("TZ", "UTC")
        time.tzset()
        yield
        # Restore before tzset(), or the process keeps the C library reading
        # the fixture's zone for every later test in the session.
        if previous is None:
            monkeypatch.delenv("TZ", raising=False)
        else:
            monkeypatch.setenv("TZ", previous)
        time.tzset()

    def _formatted(self, when: float) -> str:
        import logging

        formatter = logging.Formatter(
            cli.LOG_FORMAT, datefmt=cli.LOG_DATEFMT, defaults={"request_id": "-"}
        )
        record = logging.LogRecord("recoverage", logging.INFO, __file__, 1, "hello", (), None)
        record.created = when
        return formatter.format(record)

    def test_stamp_carries_date_and_offset(self) -> None:
        # 2023-11-14T22:13:20Z, an ordinary instant, read in UTC.
        assert self._formatted(1_700_000_000.0).startswith("2023-11-14 22:13:20+0000 ")

    def test_stamp_distinguishes_two_instants_a_day_apart(self) -> None:
        day_one = self._formatted(1_700_000_000.0)
        day_two = self._formatted(1_700_000_000.0 + 86_400)
        assert day_one != day_two
        assert day_two.startswith("2023-11-15 22:13:20+0000 ")

    def test_offset_moves_with_the_host_zone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The stamp is local, and says which local: the same instant reads
        differently under two zones, and the offset tells the reader which."""
        import time

        if not hasattr(time, "tzset"):
            pytest.skip("no time.tzset() on this platform")
        stamp = self._formatted(1_700_000_000.0)
        monkeypatch.setenv("TZ", "Asia/Tokyo")
        time.tzset()
        try:
            tokyo = self._formatted(1_700_000_000.0)
        finally:
            time.tzset()
        assert stamp != tokyo
        assert tokyo.startswith("2023-11-15 07:13:20+0900 ")


class TestClockStampedFilter:
    """The stamp on a served log line comes from `clock`, not from `time`.

    `logging` fills `record.created` from `time.time()` when the record is
    built, and `%(asctime)s` renders that field, so the stamp was the one
    wall-clock reading under `src/recovery/` that bypassed the `clock` seam
    while every other one read `clock.wall_time()`. A run driven from a single
    patched clock therefore wrote two different instants for the same event,
    and a replay could not be diffed against the run it replays.

    The tests drive the filter rather than the formatter: the formatter only
    ever renders `record.created`, which is what `TestLogStamp` above pins, so
    the seam under test is the one that fills the field.
    """

    @staticmethod
    def _filtered(monkeypatch: pytest.MonkeyPatch, when: float) -> float:
        import logging

        from recoverage import clock

        monkeypatch.setattr(clock, "wall_time", lambda: when)
        record = logging.LogRecord("recoverage", logging.INFO, __file__, 1, "hello", (), None)
        # logging's own stamp, which the filter must not be reading.
        record.created = 0.0
        assert cli.ClockStampedFilter().filter(record) is True
        return record.created

    def test_the_stamp_is_the_clock_reading(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self._filtered(monkeypatch, 1_700_000_000.0) == 1_700_000_000.0

    def test_the_stamp_ignores_the_instant_logging_chose(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The point of the filter: logging's own `time.time()` is not the source."""
        assert self._filtered(monkeypatch, 1_700_000_000.0) != 0.0

    def test_two_runs_of_one_seed_write_the_same_line(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The replay property: one patched clock, one line, byte for byte.

        Two records built a moment apart under a frozen clock carry the same
        stamp, so the diff of two replays is empty. This is the whole claim the
        filter exists to make, asserted on the formatted line rather than on
        the field, because the line is what a replay is diffed against.
        """
        import logging

        from recoverage import clock

        monkeypatch.setattr(clock, "wall_time", lambda: 1_700_000_000.0)
        formatter = cli.StructuredFormatter(
            cli.LOG_FORMAT, datefmt=cli.LOG_DATEFMT, defaults={"request_id": "-"}
        )
        stamp_filter = cli.ClockStampedFilter()

        def one_line(message: str) -> str:
            record = logging.LogRecord("recoverage", logging.INFO, __file__, 1, message, (), None)
            stamp_filter.filter(record)
            return formatter.format(record)

        assert one_line("GET /api/health 200") == one_line("GET /api/health 200")

    def test_configured_handler_carries_the_filter(self) -> None:
        """`_configure_logging` is the one place a record enters stderr.

        A filter nothing attaches is a class no run reaches: the field would
        keep logging's stamp in production while the tests above passed against
        a seam nothing uses. Driven through the real entry point, asserting
        the handler the root logger ends up with.
        """
        import logging

        root = logging.getLogger()
        previous_handlers = root.handlers[:]
        previous_level = root.level
        try:
            root.handlers.clear()
            cli._configure_logging(logging.WARNING)
            assert any(isinstance(f, cli.ClockStampedFilter) for f in root.handlers[0].filters), [
                type(f).__name__ for f in root.handlers[0].filters
            ]
        finally:
            for handler in root.handlers[:]:
                root.removeHandler(handler)
            root.handlers[:] = previous_handlers
            root.setLevel(previous_level)


class TestStructuredFormatter:
    """A record's named fields must render as fields, not only as prose.

    The request line reads the same either way; what the fields buy is that an
    aggregator can filter on a status or a route without parsing the message.
    A record carrying none renders exactly as the plain format did, because
    loggers this package does not own (bottle, rebrew) and the CLI's own lines
    have no fields and must not grow invented ones.
    """

    @staticmethod
    def _formatted(fields: dict[str, object] | None) -> str:
        import logging

        formatter = cli.StructuredFormatter(
            cli.LOG_FORMAT, datefmt=cli.LOG_DATEFMT, defaults={"request_id": "-"}
        )
        record = logging.LogRecord("recoverage", logging.WARNING, __file__, 1, "boom", (), None)
        if fields is not None:
            record.__dict__.update(fields)
        return formatter.format(record)

    def test_fields_render_as_key_value_pairs(self) -> None:
        line = self._formatted(
            {"log_fields": {"method": "GET", "path": "/api/health", "status": 200}}
        )
        assert 'method="GET"' in line
        assert 'path="/api/health"' in line
        assert "status=200" in line
        assert "boom method=" in line

    def test_a_value_with_a_quote_stays_one_field(self) -> None:
        """JSON encoding, so a quoted value cannot forge a second field.

        Without the quotes a path carrying `x=` would be read as its own field
        by any aggregator that splits the line on spaces.
        """
        line = self._formatted({"log_fields": {"reason": 'broken "x" and y'}})
        tail = line.split("boom ", 1)[1]
        assert tail.count("=") == 1
        assert json.loads(tail.split("=", 1)[1]) == 'broken "x" and y'

    def test_a_record_without_fields_is_unchanged(self) -> None:
        line = self._formatted(None)
        assert line.endswith("boom")

    def test_a_foreign_loggers_record_is_unchanged(self) -> None:
        import logging

        formatter = cli.StructuredFormatter(
            cli.LOG_FORMAT, datefmt=cli.LOG_DATEFMT, defaults={"request_id": "-"}
        )
        record = logging.LogRecord("bottle", logging.INFO, __file__, 1, "hello", (), None)
        assert formatter.format(record).endswith("hello")


# ── Export command (actual CLI) ───────────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestExportCommand:
    """Test the actual `export` CLI command output."""

    def test_export_json_format(self) -> None:
        result = runner.invoke(app, ["export", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        # `len(data) > 0` is satisfied by an export that dropped every target
        # but one. The synthetic DB has exactly one, with two sections.
        assert len(data) == 1
        assert "target" in data[0]
        assert "sections" in data[0]
        assert set(data[0]["sections"]) == {".text", ".data"}
        assert data[0]["sections"][".text"]["total_cells"] == 8

    def test_export_json_flag_matches_the_format_it_shorthands(self) -> None:
        """`--json` is the spelling stats/check/config take; it must be the
        same export, not a second path that can drift from --format json."""
        flagged = runner.invoke(app, ["export", "--json"])
        spelled = runner.invoke(app, ["export", "--format", "json"])
        assert flagged.exit_code == 0
        assert json.loads(flagged.output) == json.loads(spelled.output)

    def test_export_json_flag_with_another_format_is_a_usage_error(self) -> None:
        """Two flags asking for two formats has no winner worth guessing."""
        result = runner.invoke(app, ["export", "--json", "--format", "csv"])
        assert result.exit_code == 2
        assert "--format csv" in result.output

    def test_export_csv_format(self) -> None:
        result = runner.invoke(app, ["export", "--format", "csv"])
        assert result.exit_code == 0
        reader = csv.reader(io.StringIO(result.output))
        rows = list(reader)
        # header + one row per section: the fixture has two, so `>= 2` is
        # satisfied by an export that emitted a single section.
        assert len(rows) == 3
        header = rows[0]
        assert "target" in header
        assert "section" in header
        assert "coverage_pct" in header
        assert {r[header.index("section")] for r in rows[1:]} == {".text", ".data"}

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
        """The table is the deliverable, so read it: exit code 0 says only
        that nothing raised. The synthetic coverage seeds FAKEDLL with 3
        functions and two sections, and `.text` is 87.5% covered by bytes
        (112 of its 128 cell bytes are not 'none').

        The function line is derived now, not read from a stored summary blob:
        rebrew counts a function matched when it is byte-identical, so _func_a
        (EXACT) and _func_b (RELOC) are 2 of the 3, and only _func_c (STUB) is
        not.  The SQLite fixture hand-wrote a summary without the
        matchedFunctions key, so the CLI's default of 0 stood in for it.
        """
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 0
        out = result.output
        assert "FAKEDLL" in out
        assert "Functions: 2/3 matched" in out
        assert ".text" in out and ".data" in out
        assert "87.5%" in out

    def test_stats_with_nonexistent_target(self) -> None:
        result = runner.invoke(app, ["stats", "--target", "NONEXISTENT_TARGET_XYZ"])
        # A typo'd target must fail loudly — silently printing an empty table
        # lets automation gate on fabricated zero-coverage data.
        assert result.exit_code == 1
        assert "not found" in result.output or "not found" in result.stderr_bytes.decode()


# ── Check command ─────────────────────────────────────────────────


#: Target id every throwaway document below writes, which is the id the
#: assertions that read them name.
FIXTURE_TARGET = "T"


def _coverage_dir(tmp_path: Path, *parts: str) -> Path:
    """A created directory a throwaway coverage document can be written into."""
    directory = coverage_dir(tmp_path, *parts)
    directory.mkdir(parents=True)
    return directory


def _write_sections(
    directory: Path,
    sections: list[str],
    cells: list[tuple[str, int, int, str]],
) -> Path:
    """Write one coverage document: each *section* is 100 bytes, one cell per entry.

    The document-era replacement for the throwaway SQLite database: the CLI
    reads rebrew's ``coverage-*.toml`` now, so a test-local fixture is a
    directory of documents rather than a scratch ``coverage.db``.  *directory*
    comes from :func:`_coverage_dir`, and the caller points the CLI at it with
    ``monkeypatch.setenv("RECOVERAGE_DB", str(directory))``.
    """
    definitions: dict[str, dict[str, Any]] = {
        name: {"size": 100, "unitBytes": 16, "columns": 8, "cells": []} for name in sections
    }
    for section, start, end, state in cells:
        definitions[section]["cells"].append(cell(start, end, state))
    return write_coverage(directory, FIXTURE_TARGET, definitions)


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
        near = _coverage_dir(tmp_path, "near")
        _write_sections(
            near,
            [".text"],
            [(".text", 0, 999_997, "exact"), (".text", 999_997, 1_000_000, "none")],
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(near))
        result = runner.invoke(app, ["check", "--min-coverage", "100", "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["passed"] is False
        # The quoted figure is floored, so a verdict cannot report 100.0% for a
        # section with three bytes still uncovered.  It is the same number
        # /stats serves for that section (server.coverage_pct).
        assert payload["results"][0]["coverage_pct"] == 99.99

        exact = _coverage_dir(tmp_path, "exact")
        _write_sections(
            exact,
            [".text"],
            [(".text", 0, 875, "exact"), (".text", 875, 1_000, "none")],
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(exact))
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
        directory = _coverage_dir(tmp_path)
        _write_sections(
            directory,
            [".text", ".data"],
            [(".text", 0, 50, "exact"), (".text", 50, 100, "none"), (".data", 0, 100, "none")],
        )

        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
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
        untracked = _coverage_dir(tmp_path, "untracked")
        _write_sections(untracked, [".text"], [(".text", 0, 100, "none")])

        monkeypatch.setenv("RECOVERAGE_DB", str(untracked))
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
        """Export a one-section document as CSV; return the parsed rows."""
        directory = _coverage_dir(tmp_path)
        _write_sections(directory, [section], [(section, 0, 100, "exact")])
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

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


class TestExportCsvStdoutEncoding:
    """The export must write UTF-8 whatever stdout's locale encoding is.

    Section and target names come from analyzed PE binaries, so a non-ASCII
    one is ordinary input.  Under a locale that names a legacy 8-bit charset
    (LANG=en_US.ISO-8859-1) sys.stdout encodes with that codec, and the raw
    csv write raises UnicodeEncodeError part-way through the file, leaving
    the user's spreadsheet truncated mid-row.  Python coerces a bare
    ``LC_ALL=C`` to UTF-8, so the test forces the encoding instead.
    """

    class _FailingBuffer(io.RawIOBase):
        """A stdout buffer whose every write fails, as a full disk's does."""

        def writable(self) -> bool:
            return True

        def write(self, data: Any) -> int:
            raise OSError(28, "No space left on device")

    class _ClosedPipe(io.RawIOBase):
        """A stdout buffer whose reader hung up, as ``export | head`` does."""

        def writable(self) -> bool:
            return True

        def write(self, data: Any) -> int:
            raise BrokenPipeError(32, "Broken pipe")

    def _export_to_ascii_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, section: str
    ) -> bytes:
        """Export a one-section document with an ASCII stdout; return the raw bytes."""
        from recoverage.cli import ExportFormat, export

        directory = _coverage_dir(tmp_path)
        _write_sections(directory, [section], [(section, 0, 100, "exact")])
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

        sink = io.BytesIO()
        real_stdout = sys.stdout
        wrapper = io.TextIOWrapper(sink, encoding="ascii", errors="strict")
        monkeypatch.setattr(sys, "stdout", wrapper)
        try:
            export(output_format=ExportFormat.csv, json_flag=False, target=None)
        finally:
            wrapper.flush()
            monkeypatch.setattr(sys, "stdout", real_stdout)
        return sink.getvalue()

    def test_non_ascii_section_survives_ascii_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        section = ".données_café"
        raw = self._export_to_ascii_stdout(tmp_path, monkeypatch, section)
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
        assert rows[0].index("section") >= 0
        assert rows[1][rows[0].index("section")] == section

    def test_utf8_stream_is_a_passthrough_for_utf8_stdout(self) -> None:
        from recoverage.cli import _utf8_stream

        stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        assert _utf8_stream(stdout) is stdout

    def test_utf8_stream_reencodes_an_ascii_stdout(self) -> None:
        from recoverage.cli import _utf8_stream

        sink = io.BytesIO()
        stdout = io.TextIOWrapper(sink, encoding="ascii", errors="strict")
        pinned = _utf8_stream(stdout)
        assert pinned is not stdout
        pinned.write("café")
        pinned.flush()
        assert sink.getvalue() == "café".encode()

    def test_a_failed_write_reports_and_does_not_close_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A write that fails mid-export must say so, and must not close stdout.

        The redirect the operator is reading IS the file being written, so an
        ENOSPC halfway through leaves it truncated; the command reporting that
        with the row it stopped on is the whole difference between a usable
        and an unusable export. The wrapper ``_utf8_stream`` built owns
        stdout's buffer and its destructor closes what it wraps, so leaving it
        attached on the failure path turned one clear error into a closed
        stdout and a ValueError from the interpreter's final flush.
        """
        from recoverage.cli import ExportFormat, export

        directory = _coverage_dir(tmp_path)
        _write_sections(directory, [".text"], [(".text", 0, 100, "exact")])
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

        buffer = self._FailingBuffer()
        real_stdout = sys.stdout
        wrapper = io.TextIOWrapper(buffer, encoding="ascii", errors="strict")
        monkeypatch.setattr(sys, "stdout", wrapper)
        try:
            with pytest.raises(typer.Exit) as raised:
                export(output_format=ExportFormat.csv, json_flag=False, target=None)
        finally:
            monkeypatch.setattr(sys, "stdout", real_stdout)
        assert raised.value.exit_code == 1
        # The wrapper must not have taken stdout's buffer down with it: the
        # error above was reported, and the interpreter still has to flush.
        assert not real_stdout.closed
        assert not real_stdout.buffer.closed

    @pytest.mark.parametrize("output_format", [ExportFormat.json, ExportFormat.md])
    def test_a_failed_write_reports_in_every_format(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        output_format: ExportFormat,
    ) -> None:
        """The other two formats must report a failed write the same way.

        Only the CSV arm had the guard, so `export --format md > out.md` on a
        full disk escaped the OSError as a traceback: the operator got a
        truncated file and a stack trace, with nothing naming the operation
        that failed. All three arms go through ``_export_write_failed`` now.
        """
        from recoverage.cli import export

        directory = _coverage_dir(tmp_path)
        _write_sections(directory, [".text"], [(".text", 0, 100, "exact")])
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

        buffer = self._FailingBuffer()
        real_stdout = sys.stdout
        wrapper = io.TextIOWrapper(buffer, encoding="ascii", errors="strict")
        monkeypatch.setattr(sys, "stdout", wrapper)
        try:
            with pytest.raises(typer.Exit) as raised:
                export(output_format=output_format, json_flag=False, target=None)
        finally:
            monkeypatch.setattr(sys, "stdout", real_stdout)
        assert raised.value.exit_code == 1

    @pytest.mark.parametrize("output_format", [ExportFormat.json, ExportFormat.md])
    def test_a_broken_pipe_still_reaches_main(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        output_format: ExportFormat,
    ) -> None:
        """A pipe that closes early must propagate, not become a write error.

        ``export | head`` is a documented use and ``main()`` owns it (devnull,
        then exit 1). Swallowing the BrokenPipeError as a failed write would
        report a full disk that does not exist.
        """
        from recoverage.cli import export

        directory = _coverage_dir(tmp_path)
        _write_sections(directory, [".text"], [(".text", 0, 100, "exact")])
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

        real_stdout = sys.stdout
        wrapper = io.TextIOWrapper(self._ClosedPipe(), encoding="utf-8", errors="strict")
        monkeypatch.setattr(sys, "stdout", wrapper)
        try:
            with pytest.raises(BrokenPipeError):
                export(output_format=output_format, json_flag=False, target=None)
        finally:
            monkeypatch.setattr(sys, "stdout", real_stdout)


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
        """A coverage document with no recorded size for a section that has
        cells must render as "0 B", not crash `recoverage stats`/`export` with
        a raw TypeError from f"{size_bytes:,}" (None is not formattable).

        TOML has no null: the schema's NULL ``sections.size`` — the .bss shape,
        which has no file extent — is the absent key, and the reader defaults
        it to 0.
        """
        directory = _coverage_dir(tmp_path)
        # .bss shape: a cell to report and no va/size/fileOffset at all.
        write_coverage(directory, FIXTURE_TARGET, {".bss": {"cells": [cell(0, 16, "none")]}})

        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 0
        assert ".bss" in result.output
        assert "0 B" in result.output


class TestUnreadableCoverageCleanExit:
    """A document that cannot be read as coverage must exit 2 with a rebuild
    hint, not a traceback (same contract as _select_targets).

    The SQLite era probed a partially-created database — one that listed
    targets but had none of the tables the stats queries needed.  The document
    era's equivalent is a file that carries the ``coverage-*.toml`` name and
    none of the schema, which the reader skips; with no readable document left
    the command has nothing to report coverage from.
    """

    def test_stats_clean_error_on_unreadable_document(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        directory = _coverage_dir(tmp_path)
        # Valid TOML, wrong shape: `sections` is a table of tables in the
        # schema, so a string here is what makes the reader refuse the file.
        (directory / f"coverage-{FIXTURE_TARGET}.toml").write_text(
            'version = 1\ntarget = "T"\nsections = "not a table"\n', encoding="utf-8"
        )

        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 2
        assert "rebuild" in result.output
        # The unreadable document must surface as the clean exit 2 above, not
        # as a leaked reader error riding out through the runner.
        assert "Traceback" not in result.output
        assert not isinstance(result.exception, CoverageTomlError)


class TestBrokenProjectFile:
    """A present but invalid rebrew-project.toml must not select another database."""

    def test_stats_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text("this is not valid toml }{", encoding="utf-8")
        result = runner.invoke(app, ["stats"])
        text = result.output + (result.stderr or "")
        assert result.exit_code == 2, text
        assert "not valid TOML" in text
        assert "Traceback" not in text

    def test_stats_json_reports_the_parse_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text("this is not valid toml }{", encoding="utf-8")
        result = runner.invoke(app, ["stats", "--json"])
        assert result.exit_code == 2, result.output
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 2
        assert "not valid TOML" in payload["error"]


# ── check: exit-code and verdict contracts ────────────────────────


class TestCheckMissingDbExitCode:
    def test_missing_db_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing coverage set is an infrastructure error: README documents
        exit 2 for `check` (coverage missing/unreadable), distinct from the
        gate-failure exit 1 a CI consumer acts on."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--min-coverage", "60"])
        assert result.exit_code == 2
        assert "coverage not found" in result.output


class TestJsonErrorEnvelope:
    """A machine-readable mode answers every failure in one shape.

    `check --json` emitted a JSON envelope for a failed gate, a bad
    --min-coverage and an empty result set, but a missing coverage set and an
    unknown --target still printed a plain stderr line, and `stats --json` /
    `export --format json` had no envelope at all.  A script piping the JSON
    channel into a parser therefore had to special-case which failure it was.
    Every failure in a --json mode now answers
    {"error": ..., "exit_code": N} on stdout, with the exit status unchanged.
    """

    MISSING = "coverage not found"

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
        directory = _coverage_dir(tmp_path)
        _write_sections(
            directory,
            [".text", ".rdata"],
            [(".text", 0, 100, "exact"), (".rdata", 0, 100, "none")],
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

        result = runner.invoke(
            app, ["check", "--min-coverage", "60", "--section", ".rdata", "--json"]
        )
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["passed"] is False
        assert payload["results"] == [
            {
                "target": FIXTURE_TARGET,
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
        directory = _coverage_dir(tmp_path)
        # .text carries no cell at all (the SQLite version dropped the one it
        # had), so only .rdata's untracked 'none' cell is left to evaluate.
        _write_sections(directory, [".text", ".rdata"], [(".rdata", 0, 100, "none")])
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

        result = runner.invoke(app, ["check", "--min-coverage", "0", "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["error"] == "no tracked sections — nothing was checked"


class TestEphemeralPort:
    """``--port 0`` asks the OS for a free port, so nothing may print the 0.

    The banner, the config block, ``/api/health`` and the URL the browser is
    handed are read by a person or a script rather than fed back into
    ``bind()``: naming port 0 there produces a tab that cannot connect and a
    health report whose port is not one the listener answers on.
    """

    def test_a_named_port_is_left_alone(self) -> None:
        assert devserver.resolve_listen_port(8123, "127.0.0.1") == 8123

    def test_zero_resolves_to_a_port_this_host_can_bind(self) -> None:
        port = devserver.resolve_listen_port(0, "127.0.0.1")
        assert port > 0
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))

    def test_the_probe_binds_the_family_the_listener_will_hold(self) -> None:
        """The probe and the listener must not resolve the family separately.

        The probe used to take ``infos[0][0]`` (whichever answer the resolver
        listed first) while ``_server_class_for`` took IPv6 only when EVERY
        answer was IPv6.  On a dual-stack host that reserved the port on the
        IPv6 socket and printed a number the AF_INET listener then failed to
        bind, so ``--port 0`` published a port the server never held.  One
        definition, read by both, is the fix; this pins that they read it.
        """
        for host in ("127.0.0.1", "::1", "localhost"):
            family = devserver.listen_family(host)
            assert _server_class_for(host).address_family is family, host

    def test_a_bind_the_probe_cannot_make_keeps_the_zero(self) -> None:
        """A host that resolves but is not bindable reports 0, not a number.

        The listener fails on that address with the resolver's and the OS's
        own error and a better message; a port taken off a socket this process
        could not open would be a number nothing ever answers on.
        """
        assert devserver.resolve_listen_port(0, "192.0.2.1") == 0

    def test_banner_and_config_name_the_bound_port(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class _StubApp:
            @staticmethod
            def run(**_kwargs: Any) -> None:
                raise KeyboardInterrupt

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("recoverage.webapp.app", _StubApp)
        monkeypatch.setattr(cli, "open_browser", lambda _url: None)
        monkeypatch.setattr(sys, "argv", ["recoverage", "serve", "--port", "0", "--no-open"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert ":0" not in out
        bound = int(out.split("Listening on: http://127.0.0.1:")[1].split()[0])
        assert bound > 0
        # The config block is the other reader of the value (/api/health
        # serves it), and it has to be the same number.
        assert f"port={bound}" in out


class TestServeInstallsTheResolvedOriginList:
    """`serve` installs and reports the RESOLVED allowlist, never `--cors-origin`.

    The flag is `list[str] | None` and is None for every invocation that
    does not spell it out, so passing it on reaches `list(None)` inside
    `configure_security` and `",".join(None)` inside `active_config`: a bare
    `recoverage serve` died on a TypeError before the listener bound.  The
    values both callers want are `resolved.cors_origins`, which
    `_resolve_serve_config` normalized and dropped to empty when CORS is off.
    """

    @staticmethod
    def _serve(argv: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
        class _StubApp:
            @staticmethod
            def run(**_kwargs: Any) -> None:
                raise KeyboardInterrupt

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("recoverage.webapp.app", _StubApp)
        monkeypatch.setattr(cli, "open_browser", lambda _url: None)
        monkeypatch.setattr(sys, "argv", ["recoverage", *argv])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
        return str(server.ACTIVE_CONFIG["cors_origin"])

    def test_no_flag_installs_and_reports_no_origin(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        assert self._serve(["serve", "--no-open"], monkeypatch, tmp_path) == "none"

    def test_the_installed_allowlist_is_the_normalized_one(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        reported = self._serve(
            ["serve", "--cors", "--cors-origin", "http://localhost:5173", "--no-open"],
            monkeypatch,
            tmp_path,
        )
        assert reported == "http://localhost:5173"
        assert server.CORS_ALLOWED_ORIGINS == ["http://localhost:5173"]


class TestServePortRange:
    def test_out_of_range_port_rejected_cleanly(self) -> None:
        """--port 99999 must be a clean CLI validation error, not an
        OverflowError traceback from socket.bind after startup."""
        result = runner.invoke(app, ["serve", "--port", "99999", "--no-open"])
        assert result.exit_code != 0
        assert "OverflowError" not in result.output
        assert "not in the range" in result.output

    def test_open_port_range_validated(self) -> None:
        """`open` resolves the port through the same range check `serve`
        does, so an out-of-range value is a clean validation error naming the
        range. Exit code alone is satisfied by a typo'd flag or a missing DB."""
        result = runner.invoke(app, ["open", "--port", "70000"])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "not in the range" in result.output


class TestOpenPort:
    """`open` targets the port `serve` would use, so the env reaches it too."""

    def test_env_port_is_the_default(self, monkeypatch: Any) -> None:
        opened: list[str] = []
        monkeypatch.setenv("RECOVERAGE_PORT", "9100")
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)
        result = runner.invoke(app, ["open"])
        assert result.exit_code == 0
        assert opened == ["http://127.0.0.1:9100"]

    def test_flag_beats_env(self, monkeypatch: Any) -> None:
        opened: list[str] = []
        monkeypatch.setenv("RECOVERAGE_PORT", "9100")
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)
        result = runner.invoke(app, ["open", "--port", "9200"])
        assert result.exit_code == 0
        assert opened == ["http://127.0.0.1:9200"]

    def test_invalid_env_port_exits_2(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("RECOVERAGE_PORT", "not-a-port")
        result = runner.invoke(app, ["open"])
        assert result.exit_code == 2
        assert "RECOVERAGE_PORT" in result.output

    def test_port_zero_is_refused(self, monkeypatch: Any) -> None:
        """`--port 0` is a request for an ephemeral port, not an address.

        `open` has no way to learn which one the server bound, so opening
        http://127.0.0.1:0 would pop a tab that cannot connect and report
        success. The refusal is a usage error and says where the real port is.
        """
        opened: list[str] = []
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)
        result = runner.invoke(app, ["open", "--port", "0"])
        assert result.exit_code == 2
        assert opened == []
        assert "banner" in result.stderr

    def test_env_port_zero_is_refused(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("RECOVERAGE_PORT", "0")
        result = runner.invoke(app, ["open"])
        assert result.exit_code == 2

    def test_no_browser_exits_1(self, monkeypatch: Any) -> None:
        """Nothing was launched, so exit 0 would be a false success.

        The headless case is the one a script hits: a container entrypoint
        runs `recoverage open`, no opener exists, and the exit code is the only
        thing it gets.
        """
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: False)
        result = runner.invoke(app, ["open"])
        assert result.exit_code == 1
        assert "no browser available" in result.stderr


class TestServeServerWiring:
    def test_the_installed_allowlist_is_what_the_server_is_configured_with(
        self, monkeypatch: Any
    ) -> None:
        """The CORS allowlist reaches the server as the RESOLVED list.

        The flag is ``None`` whenever ``--cors-origin`` is absent, which is the
        default and every ``RECOVERAGE_CORS_ORIGIN``-only deployment, and both
        ``configure_security`` (``list(...)``) and ``active_config``
        (``",".join(...)``) iterate what they are handed: passing the raw
        option terminated ``serve`` with a TypeError before the listener ever
        bound.  The resolved list is the normalized one the request-path
        matcher compares against, so anything else installs a different
        allowlist than the banner reports.
        """
        from recoverage.server import app as server_app

        captured: list[dict[str, Any]] = []
        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        monkeypatch.setattr(
            "recoverage.server.configure_security",
            lambda **kwargs: captured.append(kwargs),
        )
        monkeypatch.setattr(type(server_app), "run", lambda self, **kwargs: None)

        result = runner.invoke(
            app,
            [
                "serve",
                "--no-open",
                "--port",
                "8123",
                "--cors",
                "--cors-origin",
                "http://EXAMPLE.com:5173",
            ],
        )
        assert result.exit_code == 0
        assert captured[-1]["cors_allowed_origins"] == ["http://example.com:5173"]
        assert "cors_origin=http://example.com:5173" in result.output

    def test_no_cors_origin_leaves_an_empty_allowlist_not_none(self, monkeypatch: Any) -> None:
        """CORS off is the default and must install an empty LIST: the matcher
        is handed None for the flag's absence today, which nothing downstream
        can iterate."""
        from recoverage.server import app as server_app

        captured: list[dict[str, Any]] = []
        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        monkeypatch.setattr(
            "recoverage.server.configure_security",
            lambda **kwargs: captured.append(kwargs),
        )
        monkeypatch.setattr(type(server_app), "run", lambda self, **kwargs: None)

        result = runner.invoke(app, ["serve", "--no-open", "--port", "8123"])
        assert result.exit_code == 0
        assert captured[-1]["cors_allowed_origins"] == []
        assert "cors_origin=none" in result.output

    def test_run_gets_threaded_server_and_bounded_handler(self, monkeypatch: Any) -> None:
        """serve must wire the threaded server class AND the request handler
        carrying the per-connection socket deadline.  ThreadingMixIn caps
        neither threads nor connections; without the handler's timeout, a
        silent peer (crashed laptop, dropped NAT mapping) or an SSE client
        that stops reading pins its handler thread forever."""
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
        assert captured["server_class"] is devserver._ThreadingWSGIServer
        assert captured["server_class"].daemon_threads is True
        assert captured["handler_class"] is devserver._KeepAliveRequestHandler
        handler = captured["handler_class"]
        assert issubclass(handler, devserver._QuietTimeoutRequestHandler)
        assert handler.timeout == devserver._CLIENT_SOCKET_TIMEOUT_SECONDS > 0

    def test_the_installed_cors_allowlist_is_the_normalized_one(self, monkeypatch: Any) -> None:
        """The request path normalizes the Origin it is given and compares it
        to the installed list, so the list has to be the normalized one. A raw
        ``--cors-origin`` entry stores a spelling no browser sends: the host
        keeps its case, and a scheme-default port is kept where the reducer
        drops it, so a request from the page the entry was written for is
        refused by the very entry that allows it.
        """
        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        installed: dict[str, Any] = {}
        monkeypatch.setattr(
            server_app.__class__,
            "run",
            lambda self, **kwargs: None,
        )
        monkeypatch.setattr(
            "recoverage.server.configure_security",
            lambda **kwargs: installed.update(kwargs),
        )
        result = runner.invoke(
            app,
            [
                "serve",
                "--no-open",
                "--port",
                "8123",
                "--cors",
                "--cors-origin",
                "http://App.test:80",
            ],
        )
        assert result.exit_code == 0
        assert installed["cors_enabled"] is True
        assert installed["cors_allowed_origins"] == ["http://app.test"]
        # The banner reports the same list, so it cannot name an allowlist the
        # request path does not match against.
        assert "cors_origin=http://app.test" in result.output

    def test_served_over_http_1_1_so_the_browser_reuses_the_connection(self) -> None:
        """The handler must speak HTTP/1.1.

        wsgiref is HTTP/1.0 and answers one request per connection, so
        loading the dashboard paid a TCP handshake for the shell and its assets,
        the targets list and the data payload.  Keep-alive only exists under
        1.1, and the preamble comes from the ServerHandler subclass, not the
        request handler, so both are pinned here.
        """

        assert devserver._KeepAliveRequestHandler.protocol_version == "HTTP/1.1"

    def test_serve_installs_the_normalized_allowlist_and_a_keep_alive_handler(
        self, monkeypatch: Any
    ) -> None:
        """The request-path allowlist is what `_allowed_origins` installed.

        `serve` resolved the operator's spelling into `resolved.cors_origins`
        and then installed the `--cors-origin` flag beside it, so the entry the
        matcher compared against was the one the operator typed rather than the
        one that was validated, and it was None outright whenever the origins
        came from RECOVERAGE_CORS_ORIGIN: a server that answers every
        cross-origin read with a 403 while the banner and `recoverage config`
        print a populated allowlist.  The flag is the input, the resolved list
        is the installation, and the two are not the same value.

        Named for the case its sibling below cannot reach: an operator's
        spelling that NEEDS normalizing. Every input in that one is already
        lowercase with an explicit port, so only this proves the install
        normalizes rather than passing the flag through.
        """
        from recoverage import server as server_mod
        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        monkeypatch.setattr(type(server_app), "run", lambda self, **kwargs: None)
        result = runner.invoke(
            app,
            ["serve", "--no-open", "--port", "8123", "--cors", "--cors-origin", "http://A.test:80"],
        )
        assert result.exit_code == 0, result.output
        assert server_mod.CORS_ENABLED is True
        # The stored entry is compared as a request's Origin is normalized, so
        # it must be the normalized spelling of what the operator wrote: the
        # raw flag spelled `http://A.test:80` matches no request at all, and a
        # browser's Origin for that page is `http://a.test`.
        assert server_mod.CORS_ALLOWED_ORIGINS == ["http://a.test"]

    @pytest.mark.parametrize(
        ("flag", "environment", "expected"),
        [
            (["--cors", "--cors-origin", "http://a.test:5173"], None, ["http://a.test:5173"]),
            (["--cors"], "http://b.test:5173", ["http://b.test:5173"]),
            (["--cors"], None, []),
        ],
    )
    def test_the_installed_cors_allowlist_comes_from_the_flag_or_the_env(
        self,
        flag: list[str],
        environment: str | None,
        expected: list[str],
        monkeypatch: Any,
    ) -> None:
        """`serve` must install the RESOLVED allowlist, not the raw flag.

        The flag is `None` whenever it was not given, so passing it straight
        to `configure_security` raised `TypeError` on every `serve` at all,
        and where it did not, an allowlist named only by
        `RECOVERAGE_CORS_ORIGIN` was never installed: the server came up with
        an empty list and refused precisely the reads the entry was written
        for, which is the outcome the setting exists to prevent.
        """
        from recoverage import server as srv

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        monkeypatch.setattr(type(srv.app), "run", lambda self, **kwargs: None)
        if environment is None:
            monkeypatch.delenv("RECOVERAGE_CORS_ORIGIN", raising=False)
        else:
            monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", environment)
        result = runner.invoke(app, ["serve", "--no-open", "--port", "8123", *flag])
        assert result.exit_code == 0, result.output
        assert expected == srv.CORS_ALLOWED_ORIGINS

    @pytest.mark.parametrize(
        "error", [TimeoutError("timed out"), ConnectionResetError("peer gone")]
    )
    def test_a_dead_connection_closes_without_a_traceback(self, error: BaseException) -> None:
        """An idle keep-alive peer must not print a socketserver traceback.

        The readline that reads the NEXT request runs under the 15s idle
        deadline, so every browser tab that sat still tripped it, and
        socketserver prints a full traceback for anything escaping ``handle()``.
        The dashboard was working; the log was a dozen lines of noise per tab.
        """
        handler = devserver._KeepAliveRequestHandler.__new__(devserver._KeepAliveRequestHandler)

        class _DeadRFile:
            def readline(self, limit: int) -> bytes:
                raise error

        handler.rfile = _DeadRFile()  # type: ignore[assignment]
        handler.handle()  # must return, not raise

    def test_a_served_request_still_walks_the_loop(self) -> None:
        """The quiet close must not swallow the loop: a real request line is
        read, dispatched, and the next one read until the peer stops sending."""
        served: list[str] = []
        handler = devserver._KeepAliveRequestHandler.__new__(devserver._KeepAliveRequestHandler)
        lines = [b"GET /a HTTP/1.1\r\n\r\n", b"GET /b HTTP/1.1\r\n\r\n", b""]

        class _RFile:
            def readline(self, limit: int) -> bytes:
                return lines.pop(0) if lines else b""

        def parse_request() -> bool:
            served.append(handler.raw_requestline.split()[1].decode())
            handler.close_connection = False  # the response was framed
            return True

        handler.rfile = _RFile()  # type: ignore[assignment]
        handler.connection = _FakeConnection()  # type: ignore[assignment]
        handler.parse_request = parse_request  # type: ignore[method-assign]
        handler._run_wsgi = lambda: None  # type: ignore[method-assign]
        handler.handle()
        assert served == ["/a", "/b"]


class _FakeConnection:
    """Just enough socket for the keep-alive loop's settimeout calls."""

    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)


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

        handler = devserver._KeepAliveServerHandler.__new__(devserver._KeepAliveServerHandler)
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
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)

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
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)

        def raise_interrupt(self: Any, **kwargs: Any) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(type(server_app), "run", raise_interrupt)
        result = runner.invoke(app, ["serve", "--port", "8123"])
        assert result.exit_code == 0
        time.sleep(0.7)  # past the timer's 0.5s deadline
        assert opened == [], "cancelled opener still fired after Ctrl+C"

    def test_an_unexpected_exit_cancels_the_deferred_browser_opener(self, monkeypatch: Any) -> None:
        """The one exit path the two handlers above missed.

        Anything else out of the listener (an OverflowError from socket.bind()
        on an address outside the port range, the RuntimeError a server with no
        WSGI app installed raises) unwinds with the deferred opener still
        armed, so half a second after the traceback a tab opens on a port
        nothing is listening on.
        """
        import time

        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        opened: list[str] = []
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)

        def blow_up(self: Any, **kwargs: Any) -> None:
            raise OverflowError("port too large")

        monkeypatch.setattr(type(server_app), "run", blow_up)
        result = runner.invoke(app, ["serve", "--port", "8123"])
        assert result.exit_code != 0
        time.sleep(0.7)  # past the timer's 0.5s deadline
        assert opened == [], "cancelled opener still fired after the listener failed"

    def test_a_failed_watcher_start_cancels_the_deferred_browser_opener(
        self, monkeypatch: Any
    ) -> None:
        """A startup step BETWEEN the armed opener and the listener is a failed
        start too.

        The DB watcher thread and the cache warm-up thread start after the
        timer is armed, and each raises RuntimeError under thread exhaustion.
        While they sat outside the try, such a raise unwound past the finally,
        so half a second after the traceback a tab opened on a port nothing
        was listening on — the outcome the surrounding comment claimed the
        finally covered.
        """
        import time

        from recoverage.server import app as server_app

        def no_watcher() -> None:
            raise RuntimeError("can't start new thread")

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", no_watcher)
        opened: list[str] = []
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)

        # The listener must never be reached: the watcher start raises first.
        def blow_up(self: Any, **kwargs: Any) -> None:
            raise AssertionError("the listener should not have started")

        monkeypatch.setattr(type(server_app), "run", blow_up)
        result = runner.invoke(app, ["serve", "--port", "8123"])
        assert result.exit_code != 0
        time.sleep(0.7)  # past the timer's 0.5s deadline
        assert opened == [], "cancelled opener still fired after the watcher failed to start"


class TestServeStopSignal:
    """SIGTERM is how a deployment stops the server; Ctrl+C is not.

    ``systemctl stop``, ``docker stop`` and a pod eviction all send SIGTERM,
    whose default disposition kills the process where it stands: the accept
    loop never unwinds, ``serve``'s ``finally`` never runs, and every
    request in flight is cut mid-body.  The stop handler turns it into the
    same path the keystroke already takes.
    """

    def test_sigterm_handler_is_installed_while_serving(self, monkeypatch: Any) -> None:
        import signal

        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        installed: list[Any] = []

        def record_and_interrupt(self: Any, **kwargs: Any) -> None:
            installed.append(signal.getsignal(signal.SIGTERM))
            raise KeyboardInterrupt

        monkeypatch.setattr(type(server_app), "run", record_and_interrupt)
        result = runner.invoke(app, ["serve", "--no-open", "--port", "8123"])

        assert result.exit_code == 0
        assert installed and installed[0] is not signal.getsignal(signal.SIGTERM), (
            "serve ran with the inherited SIGTERM disposition"
        )

    def test_the_handler_raises_the_path_serve_already_handles(self) -> None:
        """The handler's whole contract: the stop unwinds like Ctrl+C.

        Judged against KeyboardInterrupt, the exception ``serve`` already
        catches, rather than against the exit code: the point is that it
        reaches the existing cleanup and not that it invents a new exit.
        """
        import signal

        from recoverage import cli

        previous = signal.getsignal(signal.SIGTERM)
        restore = cli._stop_on_sigterm()
        try:
            handler = signal.getsignal(signal.SIGTERM)
            assert callable(handler)
            with pytest.raises(KeyboardInterrupt):
                handler(signal.SIGTERM, None)  # type: ignore[operator]
        finally:
            restore()

        assert signal.getsignal(signal.SIGTERM) is previous, "handler not restored"

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Windows cannot deliver SIGTERM: os.kill with anything but "
        "CTRL_C_EVENT/CTRL_BREAK_EVENT calls TerminateProcess, so this kills "
        "the pytest run instead of raising in the handler. The handler's own "
        "contract is still covered above; Windows stops with Ctrl+C.",
    )
    def test_sigterm_cancels_deferred_browser_opener(self, monkeypatch: Any) -> None:
        """Same as the Ctrl+C case: a stop must not leave the armed opener to
        fire half a second later at a port that is no longer served.

        The signal is really delivered (``os.kill`` to this process while the
        stubbed listener stands in for the accept loop), so the test covers
        the whole path: disposition, handler, ``except KeyboardInterrupt``,
        ``finally``.  The handler is process-wide for the duration, and
        ``serve``'s finally restores it.
        """
        import signal
        import time

        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        opened: list[str] = []
        monkeypatch.setattr("recoverage.cli.open_browser", lambda url: opened.append(url) or True)

        def stop(self: Any, **kwargs: Any) -> None:
            os.kill(os.getpid(), signal.SIGTERM)

        monkeypatch.setattr(type(server_app), "run", stop)
        result = runner.invoke(app, ["serve", "--port", "8123"])
        assert result.exit_code == 0
        time.sleep(0.7)  # past the timer's 0.5s deadline
        assert opened == [], "cancelled opener still fired after the stop signal"

    def test_sigterm_restores_the_previous_handler(self, monkeypatch: Any) -> None:
        """The restore runs on the way out of every exit, so a handler is never
        left installed on a process that has stopped serving."""
        import signal

        from recoverage.server import app as server_app

        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)
        before = signal.getsignal(signal.SIGTERM)
        monkeypatch.setattr(type(server_app), "run", lambda self, **kwargs: None)
        result = runner.invoke(app, ["serve", "--no-open", "--port", "8123"])

        assert result.exit_code == 0
        assert signal.getsignal(signal.SIGTERM) is before

    def test_every_stop_signal_the_platform_delivers_is_handled(self) -> None:
        """The stop arm covers every signal the platform can actually deliver.

        SIGTERM on POSIX, SIGBREAK on Windows: a signal with no handler stops
        the dashboard the abrupt way this class exists to prevent, and one is
        only the default disposition on a platform that has it. So the set is
        read off the module rather than off this platform's own constants,
        which is the only way the Windows arm is covered from a Linux run.
        """
        import signal

        from recoverage import cli

        expected = [
            getattr(signal, name) for name in ("SIGTERM", "SIGBREAK") if hasattr(signal, name)
        ]
        assert expected, "no stop signal this platform delivers"
        before = {signum: signal.getsignal(signum) for signum in expected}
        restore = cli._stop_on_sigterm()
        try:
            for signum in expected:
                assert signal.getsignal(signum) is not before[signum], f"{signum} left undisposed"
                with pytest.raises(KeyboardInterrupt):
                    signal.getsignal(signum)(signum, None)  # type: ignore[operator]
        finally:
            restore()
        assert {signum: signal.getsignal(signum) for signum in expected} == before


class TestAllowRemoteWithoutRemoteBind:
    """The acknowledgment that does nothing.

    A loopback bind is refused without it and accepts it silently, so an
    operator who exported ``RECOVERAGE_ALLOW_REMOTE=1`` expecting a reachable
    dashboard gets one only this machine can reach.  The only clue otherwise
    is a connection refused from the machine they were serving.
    """

    def test_a_loopback_bind_with_the_acknowledgment_warns(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("RECOVERAGE_ALLOW_REMOTE", "1")
        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        assert "allow-remote is set but --bind 127.0.0.1" in result.output

    def test_a_remote_bind_with_the_acknowledgment_does_not_warn(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("RECOVERAGE_ALLOW_REMOTE", "1")
        monkeypatch.setenv("RECOVERAGE_BIND", "0.0.0.0")
        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        assert "is set but --bind" not in result.output

    def test_a_loopback_bind_without_the_acknowledgment_does_not_warn(
        self, monkeypatch: Any
    ) -> None:
        monkeypatch.delenv("RECOVERAGE_ALLOW_REMOTE", raising=False)
        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        assert "is set but --bind" not in result.output


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
        """rebrew's error_exit becomes RegenError, whose exit status the CLI
        reports as exit 1 rather than a traceback."""
        import recoverage.regen as regen

        def boom(root: Path) -> None:
            raise regen.RegenError(2)

        monkeypatch.setattr(regen, "run_regen", boom)

        result = runner.invoke(app, ["regen"])
        assert result.exit_code == 1
        assert "Traceback" not in result.output

    def test_a_regen_running_elsewhere_exits_cleanly(self, monkeypatch: Any) -> None:
        """A second regen of the same tree is refused, not run alongside the first.

        Nothing in this process is holding a lock in that case: the duplicate is
        a `recoverage regen` at another terminal, or a cron job over the same
        documents, and two writers of one `coverage-<target>.toml` interleave
        rather than converge.  Exit 1 (the regen did not happen) with a message
        saying why, and never a traceback.
        """
        import recoverage.regen as regen

        def busy(root: Path) -> None:
            raise regen.RegenBusyError("another regen is already writing /proj/db")

        monkeypatch.setattr(regen, "run_regen", busy)

        result = runner.invoke(app, ["regen"])
        assert result.exit_code == 1
        assert "another regen is already writing" in result.output
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

    def test_main_exits_cleanly_when_devnull_cannot_be_opened(self, monkeypatch: Any) -> None:
        """The devnull redirect is best-effort; failing it must not raise.

        The redirect only exists to keep the interpreter's final flush quiet,
        so a host that cannot open /dev/null (a sandbox, a stripped
        container) is no reason to lose the exit status: the OSError escaped
        the handler and replaced "pipe closed" with a traceback, which is the
        one report the operator did not ask for.
        """
        import recoverage.cli as cli

        def boom() -> None:
            raise BrokenPipeError(32, "Broken pipe")

        def no_devnull(path: Any, flags: int, *args: Any) -> int:
            raise OSError(2, "No such file or directory")

        monkeypatch.setattr(cli, "app", boom)
        monkeypatch.setattr(cli.os, "open", no_devnull)
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        assert excinfo.value.code == 1


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


def _unicode_dir(tmp_path: Path) -> Path:
    """A coverage directory whose target id and section name are both non-ASCII."""
    directory = _coverage_dir(tmp_path)
    write_coverage(
        directory,
        "café & bar",
        {".données": {"size": 100, "unitBytes": 16, "columns": 8, "cells": [cell(0, 50, "exact")]}},
    )
    return directory


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
        directory = _unicode_dir(tmp_path)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        buffer = self._ascii_stdout(monkeypatch)
        # Called directly, not through CliRunner: the runner swaps in its own
        # UTF-8 stdout, which is exactly the codec under test.
        cli.export(output_format=cli.ExportFormat.csv, json_flag=False, target=None)
        sys.stdout.flush()
        assert ".données" in buffer.getvalue().decode("utf-8")

    def test_md_export_survives_an_ascii_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        directory = _unicode_dir(tmp_path)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        buffer = self._ascii_stdout(monkeypatch)
        cli.export(output_format=cli.ExportFormat.md, json_flag=False, target=None)
        sys.stdout.flush()
        text = buffer.getvalue().decode("utf-8")
        assert "## café & bar" in text
        assert ".données" in text
