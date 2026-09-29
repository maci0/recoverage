"""Typer CLI for recoverage — coverage dashboard for binary-matching projects."""

from __future__ import annotations

import contextlib
import enum
import io
import json
import logging
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import webbrowser
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import IO, Any, NamedTuple, NoReturn
from urllib.parse import urlsplit

import typer
from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError
from rebrew.utils import floor_pct

from recoverage import clock, config
from recoverage._paths import _db_path
from recoverage.devserver import (
    _KeepAliveRequestHandler,
    _ThreadingWSGIServer,
    configure_transport,
    listen_family,
    resolve_listen_port,
)

app = typer.Typer(
    help="Coverage dashboard for binary-matching decompilation projects.",
    add_completion=True,
    rich_markup_mode="rich",
    # -h alongside --help, on the group and on every subcommand: the man page
    # documents it and POSIX readers reach for it first.  No command claims -h,
    # so the alias cannot shadow a flag, and one context setting covers the
    # whole tree rather than repeating the option per command.
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        f"  recoverage [dim]# start the dashboard (port {config.DEFAULT_PORT})[/dim]\n\n"
        f"  recoverage serve [dim]# same thing, spelled out[/dim]\n\n"
        "  recoverage serve --port 3000 [dim]# custom port[/dim]\n\n"
        "  recoverage stats --json [dim]# machine-readable statistics[/dim]\n\n"
        "  recoverage export --format csv > coverage.csv [dim]# export as CSV[/dim]\n\n"
        "  recoverage check --min-coverage 50 [dim]# CI gate[/dim]\n\n"
        "  recoverage regen [dim]# re-run catalog + build-db[/dim]\n\n"
        "  recoverage open [dim]# open a running dashboard in a browser[/dim]\n\n"
        "  recoverage config [dim]# show the settings serve would start with[/dim]\n\n"
        "[bold]Prerequisites:[/bold]\n\n"
        "  Run [dim]rebrew build-db[/dim] first to create "
        "db/coverage-*.toml.\n\n"
        f"[dim]Reads db/coverage-*.toml (RECOVERAGE_DB overrides the directory, "
        f"for every command). Serves SPA at "
        f"http://localhost:{config.DEFAULT_PORT}.[/dim]"
    ),
)

_log = logging.getLogger("recoverage")


# Color is emitted through _secho, never bare typer.secho, so the opt-outs are
# honored on a terminal too.  Click only strips ANSI when the stream is not a
# TTY, so a piped run already loses color, but NO_COLOR (https://no-color.org)
# and a dumb terminal are terminal conditions, and a user who sets either
# expects no escape codes.  The opt-outs only ever force color OFF: passing
# color=True would make click keep the codes even when stdout is a pipe.  Rich
# has its own detection for the two environment conditions and none for the
# flag, so the `stats` table is handed the resolved opt-out separately.
_color_disabled = False


def _color_off() -> bool:
    if _color_disabled:
        return True
    if os.environ.get("NO_COLOR"):
        return True
    return os.environ.get("TERM") == "dumb"


def _secho(message: str, **styles: Any) -> None:
    typer.secho(message, color=False if _color_off() else None, **styles)


def _no_color_callback(value: bool) -> bool:
    """Turn the opt-out on at parse time, wherever the flag was spelled.

    Every command declares the option, so ``recoverage --no-color stats`` and
    ``recoverage stats --no-color`` are the same run.  A parse-time callback is
    what makes that true: the command body has not run yet, and the first
    colored line of ``stats`` is printed from inside it.
    """
    global _color_disabled
    if value:
        _color_disabled = True
    return value


def _no_color_option() -> Any:
    """The ``--no-color`` option, one spelling for the group and each command."""
    return typer.Option(
        False,
        "--no-color",
        help="Disable colored output (overrides NO_COLOR and TERM=dumb).",
        callback=_no_color_callback,
    )


class _ThreadingWSGIServer6(_ThreadingWSGIServer):
    """The same server on an IPv6 socket.

    ``wsgiref``'s ``WSGIServer`` inherits ``http.server.HTTPServer``'s
    ``AF_INET`` and never changes it, so an IPv6 bind address that
    ``config.validate_bind`` deliberately accepts (``::1``, ``::``) dies in
    ``socket.bind()`` (EAFNOSUPPORT here), and the OSError
    handler below then reports "is another instance already running?" for what
    is an address-family mismatch.  On Linux an ``AF_INET6`` socket bound to
    ``::`` also accepts IPv4-mapped peers, which is the case
    ``server._peer_is_loopback`` documents.
    """

    address_family = socket.AF_INET6


def _server_class_for(bind: str) -> type[_ThreadingWSGIServer]:
    """The threaded server class whose address family *bind* needs.

    The answer is :func:`devserver.listen_family`, shared with the
    ``--port 0`` probe: the port the banner publishes has to come off a socket
    of the family the listener will hold, so the two cannot each resolve it.
    """
    if listen_family(bind) is socket.AF_INET6:
        return _ThreadingWSGIServer6
    return _ThreadingWSGIServer


#: Log line layout, and the stamp it carries.  The date and numeric offset are
#: load-bearing, not decoration: a bare "%H:%M:%S" cannot place a line on a
#: timeline, so 23:59 and 00:01 read as the same moment and a log spanning a
#: fall-back transition prints its repeated hour twice with nothing to tell the
#: two apart.  %z also means a reader never has to assume the host's zone.  The
#: stamp is local time on purpose — an operator comparing it against their own
#: wall clock needs to see their own clock, and the offset is what makes that
#: comparison unambiguous across a DST change.  Elapsed times never come from
#: it; those read `recoverage.clock.monotonic()`.
LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] [rid=%(request_id)s] %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S%z"


class ClockStampedFilter(logging.Filter):
    """Re-stamp each record from :mod:`recoverage.clock` as it is handled.

    :mod:`logging` fills ``record.created`` from :func:`time.time` when the
    record is built, and ``%(asctime)s`` renders that field, so the stamp a
    human reads came from outside the :mod:`recoverage.clock` seam — the one
    read under ``src/recoverage/`` that :mod:`time` made on its own.  Every
    other wall-clock stamp the package publishes reads ``clock.wall_time()``,
    so a run driven from one patched clock produced two different instants for
    the same event and a replay of it could not be diffed against the run it
    replays, line for line.

    The filter is where the re-stamp belongs, not ``formatTime``: it leaves
    ``%(asctime)s`` rendering ``record.created`` as the format string says it
    does, so a test that sets ``created`` by hand and formats a bare
    ``logging.Formatter`` still reads back the instant it set (the
    ``TestLogStamp`` fixture in ``tests/test_cli.py`` is one).  Only the records
    this handler actually writes are touched, which is every record the
    operator sees: the ones from loggers this package does not own (bottle,
    rebrew) arrive on the same handler and are stamped the same way.

    The stamp is the instant the handler reached the record, not the instant
    the caller built it, which is the same reading to within the emit for the
    unqueued :class:`logging.StreamHandler` this is attached to.  Nothing in
    the package orders, expires or rate-limits on ``created``; it is read for
    display and nothing else.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.created = clock.wall_time()
        return True


class StructuredFormatter(logging.Formatter):
    """:data:`LOG_FORMAT` plus whatever named fields a record carries.

    A record that passes ``extra={"log_fields": {...}}`` (``server.
    request_log_fields`` writes it) renders those fields after the message as
    ``key=JSON`` pairs.  The message stays prose for a human reading the
    terminal; the fields are what an aggregator indexes, so pivoting from a
    metric anomaly to the requests behind it is a filter over a field rather
    than a regular expression over prose.  JSON-encoding the value keeps a
    space, a quote or a backslash from splitting the field, and escapes
    non-ASCII by default, matching the ``backslashreplace`` the stderr handler
    applies to the stream.

    A record without the attribute renders exactly as the plain format did:
    loggers this package does not own (bottle, rebrew) and the CLI's own lines
    carry no fields, and the formatter must not invent any.
    """

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802 - logging's own name
        # Imported here, not at module scope: the CLI deliberately reaches for
        # the server lazily so `recoverage stats` does not import bottle.  By
        # the time a record is formatted, ``serve`` has already imported it, so
        # this is a sys.modules lookup on a path that is writing to stderr.
        from recoverage.server import LOG_FIELDS_ATTR

        message = super().formatMessage(record)
        fields = getattr(record, LOG_FIELDS_ATTR, None)
        if not fields:
            return message
        rendered = " ".join(f"{key}={json.dumps(value)}" for key, value in sorted(fields.items()))
        return f"{message} {rendered}"


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version

        typer.echo(f"recoverage {version('recoverage')}")
        raise typer.Exit


@app.callback()
def _app_callback(
    no_color: bool = _no_color_option(),
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    # The group runs before its subcommand, so this is the per-invocation
    # reset: the flag's own callback (and the subcommand's copy of it, parsed
    # later) turns the opt-out back on, and the next run starts clean.
    global _color_disabled
    _color_disabled = no_color


# ── Helpers ────────────────────────────────────────────────────────


class ExportFormat(enum.StrEnum):
    json = "json"
    csv = "csv"
    md = "md"


# Verdict colors for `check` output — one emit site colors every verdict.
_VERDICT_COLORS: dict[str, str] = {
    "PASS": typer.colors.GREEN,
    "SKIP": typer.colors.YELLOW,
    "FAIL": typer.colors.RED,
}

# Leading characters spreadsheets (Excel, LibreOffice) interpret as formulas
# or control sequences when a CSV cell starts with them.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Line terminators a Markdown reader breaks on and `str.splitlines` splits on,
# beyond the CR and LF the table's own rows are made of.  A section name or
# target id carrying U+2028 or U+2029 came from a PE image, so it is a value a
# hostile sample plants, and it turns one table row into two: the export
# renders ragged and the row after it reads as a section that does not exist.
# Folding them to a space is what the CR/LF arms already do, and it keeps the
# value recognisable, which an escape sequence would not.
_MD_LINE_BREAKS = str.maketrans(
    {
        "\r": " ",
        "\n": " ",
        "\u2028": " ",
        "\u2029": " ",
    }
)

# The one character a pipe inside a table cell ends, and the escape the export
# writes in its place (GFM's own spelling, so the file stays readable).
_MD_PIPE = "\\|"

# ONE spelling of the operator-facing rebuild advice so it cannot drift
# between the commands that embed it in their database-error messages.
_REBUILD_HINT = "(run 'rebrew build-db' to rebuild it)"


def _pin_utf8(stream: IO[str], errors: str) -> None:
    """Reconfigure *stream* to encode UTF-8, whatever the locale's codec is.

    One implementation for the two operator-facing streams, because they fail
    the same way and only differ in what they do with a character the target
    encoding cannot hold: stdout has to be readable (a piped value is parsed by
    whatever reads it next), stderr only has to stay one line per warning.
    """
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    if encoding == "utf8" and errors == "strict":
        return
    # A stream that cannot be reconfigured (an in-memory test double, a pipe
    # wrapper) keeps its own codec; nothing here is worth failing.
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    with contextlib.suppress(ValueError, OSError):
        reconfigure(encoding="utf-8", errors=errors)


def _use_utf8_stdout() -> None:
    """Make stdout encode UTF-8, whatever the environment's locale says.

    `export`, `check`, `stats`, `serve`, `config` and `regen` write target ids,
    section names and filesystem paths straight from the database and the
    project, and those come out of PE images and off a disk: any byte is
    possible.  stdout carries the locale's codec, so under LC_ALL=C (with
    locale coercion off) or a Windows code page the write raises
    UnicodeEncodeError part-way through the output, and for `serve` that is
    before the listener binds, so a checkout under a non-ASCII path is a
    traceback and an exit rather than a dashboard.

    ``replace``, not ``strict``: with the codec pinned to UTF-8 the only text
    this stream still cannot encode is a lone surrogate, which reaches Python
    from ``os.fsdecode`` reading a name the filesystem spelled in bytes outside
    UTF-8 (a coverage directory on a mounted volume, or one extracted from an
    archive with a mangled entry).  Strict made `recoverage config` raise on the
    banner line naming that directory, printing nothing at all; replace writes
    the one name as U+FFFD and the command runs.  No other character is
    affected, because UTF-8 encodes every code point there is.
    """
    _pin_utf8(sys.stdout, "replace")


def _use_utf8_stderr() -> None:
    """Make stderr carry a path the platform's code page cannot spell.

    The startup warnings embed the bind address, the CORS origins and the
    coverage directory, and they are printed before `_configure_logging`
    installs the `backslashreplace` filter the log stream runs with, so a
    non-ASCII project path reached stderr unprotected there.  backslashreplace
    is the same choice `_configure_logging` makes: the warning stays readable
    and stays one line.
    """
    _pin_utf8(sys.stderr, "backslashreplace")


def _utf8_stream(stream: IO[str]) -> IO[str]:
    """Return *stream* pinned to UTF-8, or *stream* itself when it already is.

    Exported target and section names come from analyzed PE binaries, so a
    non-ASCII one reaches the writer.  ``sys.stdout`` encodes with the
    locale's preferred codec, a legacy 8-bit one under a LANG such as
    ``en_US.ISO-8859-1`` (Python's C-locale coercion covers plain
    ``LC_ALL=C``, not a locale that names a real charset): the raw write
    then raises UnicodeEncodeError part-way through the export and the file
    the user is redirecting into a spreadsheet ends up truncated.
    Re-decoding the existing buffer keeps one destination and the ``\\n``
    line terminator's "written once, natively" contract; ``errors="replace"``
    keeps a lone surrogate from the database out of the crash path.  The
    caller must detach the result, since a wrapper's destructor closes the
    buffer it wraps.
    """
    # A stream that is ALREADY UTF-8 is the common case on a modern locale, and
    # it returned here unchanged with whatever error handler it was opened
    # with, so the replace the docstring promises did not apply to it.  Re-pin
    # the handler on the one branch that reuses the stream, and leave a stream
    # that needs re-encoding to the wrapper below, which replaces anyway.
    if "utf" in (getattr(stream, "encoding", None) or "").lower():
        _pin_utf8(stream, "replace")
        return stream
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        return stream
    return io.TextIOWrapper(buffer, encoding="utf-8", errors="replace", newline="")


def _csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula injection (CWE-1236) in exported cells.

    Target ids and section names originate in analyzed PE binaries, so a
    malicious sample can plant a section named ``=HYPERLINK(...)`` or
    ``@SUM(...)`` that Excel executes when the exported file is opened.
    Prefixing with an apostrophe forces text interpretation (the standard
    OWASP mitigation); a non-string cell (the numbers the rows carry) passes
    through untouched.  A string that merely looks numeric is prefixed like any
    other, because ``-`` and ``+`` are formula prefixes too.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _checked_port(value: int | str) -> int:
    """Return *value* as a port, or raise config.ConfigError naming ``--port``.

    Two rules, and ``RECOVERAGE_PORT`` gets both, so the flag gets both too:
    one setting, two sources.  The value must be ASCII digits (typer hands the
    flag over as text for this reason — click's ``INT`` runs it through
    ``int()``, which takes digits from every Unicode Nd set and reads ``_`` as a
    separator, so ``--port 1_0`` would otherwise become port 10), and it must
    be in the port range.
    """
    from recoverage.server import parse_ascii_int

    if isinstance(value, str):
        try:
            port = parse_ascii_int(value)
        except ValueError as exc:
            raise config.ConfigError(f"--port: {exc}") from None
    else:
        port = value
    if not config.MIN_PORT <= port <= config.MAX_PORT:
        raise config.ConfigError(
            f"--port: {port} is not in the range {config.MIN_PORT}-{config.MAX_PORT}"
        )
    return port


class _ServeConfig(NamedTuple):
    """The settings `serve` starts with, after flags and environment merge."""

    port: int
    bind: str
    allow_remote: bool
    cors: bool
    cors_origins: list[str]
    #: What the operator actually wrote, before ``_allowed_origins`` dropped the
    #: whole list for CORS being off.  ``_cors_warnings`` needs this, not
    #: ``cors_origins``: the entry that has no effect is precisely the one that
    #: is not installed.
    cors_origins_requested: list[str]
    token: str | None
    db: Path | None
    log_level: int
    max_connections: int
    client_timeout: int


def _resolve_serve_config(
    *,
    port: int | str | None = None,
    bind: str | None = None,
    allow_remote: bool | None = None,
    cors: bool | None = None,
    cors_origin: list[str] | None = None,
    token: str | None = None,
    log_level: str | None = None,
) -> _ServeConfig:
    """Merge `serve`'s flags over the RECOVERAGE_* environment.

    A flag that was passed wins over the environment; a flag left at None
    takes the environment value, and the environment itself falls back to the
    documented default.  Every environment value is validated HERE, at
    startup, so a deployment typo exits 2 with the variable name instead of
    reaching socket.bind() or the auth layer.  The CORS allowlist is returned
    already normalized, so the banner, ``recoverage config`` and the value the
    request path matches against are one list.
    """
    try:
        config.check_unknown_vars()
        # Read first: whether CORS is on decides whether the allowlist is
        # installed at all, and a refused origin is a startup error (see
        # _allowed_origins), so it has to be resolved with the same cors value
        # the server will run with rather than in a second pass beside it.
        resolved_cors = config.cors() if cors is None else cors
        requested_origins = config.cors_origins() if cors_origin is None else list(cors_origin)
        # A RECOVERAGE_DB that is not a directory is a startup error, not a
        # resolved path: the coverage glob matches nothing, and the dashboard
        # then serves an empty target list that reads as a healthy zero.
        config.check_db_override()
        resolved = _ServeConfig(
            port=config.port() if port is None else _checked_port(port),
            # validate_bind, not the raw flag: one setting, two sources, and
            # the floor the environment gets is the flag's too.
            bind=config.bind() if bind is None else config.validate_bind(bind, "--bind"),
            allow_remote=config.allow_remote() if allow_remote is None else allow_remote,
            cors=resolved_cors,
            cors_origins=_allowed_origins(resolved_cors, requested_origins),
            cors_origins_requested=requested_origins,
            token=(
                (config.token() or None)
                if token is None
                else config.validate_token(token, "--token")
            ),
            # Read for validation only; _db_path() resolves the value again.
            # check_db_override, not db_override alone: a RECOVERAGE_DB naming
            # a file resolves to a path no glob can match, which serves an
            # empty target list rather than an error.
            db=config.db_override(),
            log_level=(
                config.log_level() if log_level is None else config.parse_log_level(log_level)
            ),
            # The transport bounds have no flag: they size a process rather
            # than select a behavior, and the flag table is the one place a
            # reader looks for what can be set, so the environment names them.
            # Read HERE so a bad value is the same exit 2 as any other.
            max_connections=config.max_connections(),
            client_timeout=config.client_timeout(),
        )
    except config.ConfigError as exc:
        _secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    return resolved


def _fail(
    human: str,
    error: str,
    exit_code: int,
    json_output: bool,
    fg: str = typer.colors.RED,
) -> NoReturn:
    """Report a failure in the caller's output mode, then exit.

    ONE tail for every CLI failure, so the machine channel cannot drift from
    the human one: with --json the report goes to stdout as
    ``{"error": ..., "exit_code": ...}``, so a script parses the same shape
    whether the gate failed, the database is missing or a flag is out of
    range; without it the human line goes to stderr.  *exit_code* separates
    a gate failure (1) from a usage or infrastructure error (2), so a script
    can tell "the build is below threshold" from "I passed a bad flag".
    """
    if json_output:
        typer.echo(json.dumps({"error": error, "exit_code": exit_code}))
    else:
        _secho(human, fg=fg, err=True)
    raise typer.Exit(exit_code)


def _check_env_or_exit() -> None:
    """Validate the RECOVERAGE_* environment, exiting 2 on the first bad value.

    `serve` runs the full merge through :func:`_resolve_serve_config`; the
    other commands read the environment directly (through `_db_path`), where
    a misspelled name is a silent no-op and an empty ``RECOVERAGE_DB`` escapes
    as a raw ConfigError traceback.  Both are the same fail-fast contract,
    so every command applies it before it consumes a setting.
    """
    try:
        config.check_unknown_vars()
        config.check_db_override()
    except config.ConfigError as exc:
        _secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None


def _db_path_or_exit(*, json_output: bool = False) -> Path:
    """Resolve the coverage directory, exiting 2 when the project file is broken.

    A missing ``rebrew-project.toml`` still resolves to ``db/``.  A file that is
    present but not valid TOML raises from the shared reader; exiting here keeps
    that from becoming a traceback, and from silently reading a different
    project's coverage.
    """
    from rebrew.workspace import WorkspaceConfigError

    try:
        return _db_path()
    except WorkspaceConfigError as exc:
        _fail(f"Error: {exc}", str(exc), 2, json_output)


def _load_coverage_or_exit(
    *, missing_exit_code: int, json_output: bool
) -> Mapping[str, CoverageSnapshot]:
    """Load every coverage document, exiting the process on failure.

    A directory with no ``coverage-*.toml`` exits with *missing_exit_code*
    (``check`` passes 2: its documented contract classifies a missing or
    unreadable coverage set as an infrastructure error, distinct from
    "coverage below threshold" = 1); sibling commands keep their historical 1.
    """
    from recoverage.server import coverage_snapshots

    _check_env_or_exit()
    p = _db_path_or_exit(json_output=json_output)
    if not any(p.glob("coverage-*.toml")):
        _fail(
            f"Error: coverage not found at {p}",
            f"coverage not found at {p}",
            missing_exit_code,
            json_output,
        )
    try:
        return coverage_snapshots()
    except CoverageTomlError as exc:
        # rebrew's own message can already end with the advice; the hint is
        # ours to add only where the reader would not get it twice.
        hint = "" if _REBUILD_HINT in str(exc) else f" {_REBUILD_HINT}"
        _fail(
            f"Error: cannot read coverage at {p}: {exc}{hint}",
            f"cannot read coverage: {exc}",
            2,
            json_output,
        )


def _select_targets(target: str | None, *, json_output: bool) -> list[str]:
    """Return the targets to operate on, validating a requested --target.

    Named apart from ``server.resolve_targets`` (the webapp's coverage+config
    merge): this one reads only the documents and validates a CLI --target
    choice.  A requested target that was never built exits 1 with a clear
    error — sibling commands must not silently succeed on a typo'd target.
    """
    from recoverage.server import db_target_ids

    known = db_target_ids()
    if target is None:
        return known
    if target not in known:
        _fail(
            f"Error: target {target!r} not found in coverage (have: {', '.join(known) or 'none'}).",
            f"target not found: {target!r}",
            1,
            json_output,
        )
    return [target]


@contextlib.contextmanager
def _open_targets(
    target: str | None, *, missing_exit_code: int = 1, json_output: bool = False
) -> Iterator[tuple[Mapping[str, CoverageSnapshot], list[str]]]:
    """Yield the loaded documents and the targets the command operates on.

    Load, ``--target`` validation and the empty-coverage exit are one contract
    for every command that reads targets, so they are written once here.
    *missing_exit_code* is ``check``'s 2 for unreadable coverage; the siblings
    keep their historical 1.
    """
    snapshots = _load_coverage_or_exit(missing_exit_code=missing_exit_code, json_output=json_output)
    targets = _select_targets(target, json_output=json_output)
    if not targets:
        # Same class as "no document": the coverage set is there and yields no
        # target, so it is the infrastructure error *missing_exit_code* names,
        # not the gate verdict the siblings report as 1.
        _fail(
            "No targets found in coverage.",
            "no targets in coverage",
            missing_exit_code,
            json_output,
            fg=typer.colors.YELLOW,
        )
    yield snapshots, targets


def _get_stats(
    snapshots: Mapping[str, CoverageSnapshot], target: str, *, json_output: bool = False
) -> dict[str, Any]:
    from recoverage.server import _section_stats

    try:
        return {"target": target, **_section_stats(snapshots[target])}
    except CoverageTomlError as exc:
        # A document that lists a target but cannot be walked (replaced between
        # the stat and the read) must not surface as a traceback — same
        # clean-exit contract as _select_targets.
        _fail(
            f"Error: cannot read coverage statistics for target {target!r}: {exc} {_REBUILD_HINT}",
            f"cannot read coverage statistics for target {target!r}: {exc}",
            2,
            json_output,
        )


def _run_regen(root: Path) -> list[Path]:
    """Regenerate the coverage documents by calling rebrew's pipeline in-process."""
    from recoverage.regen import (
        RegenBusyError,
        RegenDbMismatchError,
        RegenError,
        run_regen,
    )

    # Progress, not data: stderr, like every failure this function reports, so
    # `recoverage regen` in a pipeline and `serve --regen`'s banner keep stdout
    # for the data they do carry.
    _secho("Running rebrew catalog + build-db...", err=True)
    try:
        return run_regen(root)
    except RegenDbMismatchError as e:
        # A setting this package reads and rebrew cannot honour. Exit 2, the
        # misconfiguration code `config` uses, not the regen-failed 1: rebrew
        # never ran and the operator has to change something first.
        _secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    except RegenBusyError as e:
        # Another PROCESS is rebuilding the same documents (a dashboard
        # running beside this terminal, a cron job over the same tree). Not
        # misconfiguration and not a rebrew failure, so it is the regen-failed
        # 1, but with a message saying the work is already under way: a second
        # writer of one document interleaves with the first rather than
        # producing the same bytes, so this one is refused rather than run.
        _secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None
    except RegenError:
        # rebrew's error_exit reported the failure itself; run_regen carried
        # that across as RegenError.  Keep the exit-1 contract.
        raise typer.Exit(1) from None
    except Exception as e:
        # Same clean exit-1 contract for any other in-process failure.
        _secho(
            f"Error: rebrew regen failed: {type(e).__name__}: {e}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1) from None


# ── Browser opener ─────────────────────────────────────────────────

# Openers exit in well under a second; the bound only guards a wedged one.
_BROWSER_OPEN_TIMEOUT_SECONDS = 10

#: How long the deferred opener waits for the listener to answer before it
#: gives up, and how often it looks.  Long enough to cover a bind that lands
#: after the warmup thread has been started, short enough that a start that
#: failed does not hold the thread.
_OPEN_LISTEN_WAIT_SECONDS = 5.0
_OPEN_LISTEN_POLL_SECONDS = 0.05

#: How long after the listener is asked to start the opener is scheduled.  It
#: probes rather than assuming, so this only has to clear the startup banner.
_BROWSER_OPEN_DELAY_SECONDS = 0.5

#: The port a URL with no explicit one names, for the opener's probe.  It
#: builds `http://host/` URLs, so http and nothing else.
_DEFAULT_HTTP_PORT = 80


def _open_when_listening(url: str) -> None:
    """Open *url* only once something is accepting on the address it names.

    ``Timer.cancel`` sets the timer's event and returns; it does not wait, so a
    start that fails while the timer is already past its own check (EADDRINUSE
    from a second instance, a Ctrl+C inside the scheduling window) still ran
    this callback, and cancelling it then did nothing at all.  The tab popped
    at a port nothing would ever listen on, which is the outcome the cancel
    exists to prevent.  Asking the listener removes the guess: no answer, no
    opener, whatever order the two threads got to.

    A connect that fails is the answer to poll on, not an error to report: the
    bind has not landed yet.  The opener is one attempt at a local socket, so
    the probe closes as soon as the listener accepts it, and it probes the
    address *url* names rather than the bind address, which for a wildcard is
    not connectable.
    """
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or _DEFAULT_HTTP_PORT
    deadline = clock.monotonic() + _OPEN_LISTEN_WAIT_SECONDS
    while True:
        try:
            with socket.create_connection((host, port), timeout=_OPEN_LISTEN_POLL_SECONDS):
                break
        except OSError:
            if clock.monotonic() >= deadline:
                _log.debug("no listener on %s:%d — not opening a browser", host, port)
                return
            clock.sleep(_OPEN_LISTEN_POLL_SECONDS)
    open_browser(url)


def _windows_detach_flags() -> int:
    """Creation flags that detach an opener from this console on Windows.

    Windows has no start_new_session, so the POSIX guarantees the opener path
    relies on need their own flags: CREATE_NEW_PROCESS_GROUP keeps a console
    Ctrl+C meant for `serve` from reaching the opener (which can die before
    the browser has been handed off), and DETACHED_PROCESS keeps it off the
    parent's console.  Zero everywhere else, where start_new_session applies.
    """
    if os.name != "nt":
        return 0
    return int(subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS)  # type: ignore[attr-defined]


def _kill_and_reap(proc: subprocess.Popen[bytes]) -> None:
    """Kill *proc* — on POSIX its whole session — and always reap it.

    Every opener gets its own session (start_new_session), so a terminal
    signal never reaches it: the abandonment paths must signal the process
    GROUP, not just the direct child, or an xdg-open wrapper's grandchild
    survives.  The trailing wait() reaps the child either way (setsid does
    not prevent zombies; only a wait does).  Windows has no process-group
    signal, so there only the direct child is terminated.

    Best-effort, and it never raises: both callers are error paths, one of
    them inside a daemon Timer, so a kill or wait that fails (a process that
    exited between the two calls, an EPERM from a sandbox, a wait that
    outlives its bound because the SIGKILL never landed) would otherwise
    propagate out of the handler, print an unobserved "Exception in thread"
    and leave the child unreaped — the one job this function exists to do.
    The wait is bounded for the same reason the opener's is: a kill that did
    not land must not trade a hung opener for a hung thread.
    """
    if os.name == "posix":
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
    else:
        try:
            proc.kill()
        except OSError as exc:
            _log.warning("Browser opener pid %s could not be killed: %s", proc.pid, exc)
    try:
        proc.wait(timeout=_BROWSER_OPEN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _log.warning(
            "Browser opener pid %s did not exit within %.1fs of SIGKILL — leaving it unreaped",
            proc.pid,
            float(_BROWSER_OPEN_TIMEOUT_SECONDS),
        )
    except OSError as exc:
        _log.warning("Browser opener pid %s could not be reaped: %s", proc.pid, exc)


def _open_and_reap(url: str, args: list[str]) -> bool:
    """Launch the opener for *url* fire-and-forget and still reap it.

    Returns whether a browser was actually launched: True once Popen has
    returned (the child exists), and otherwise whatever the webbrowser
    fallback reported, so the caller with an exit code to set (`open`) does
    not report success on a headless box where nothing was launched.

    Detaching (setsid, or the Windows creation flags) does NOT keep a child
    from becoming a zombie —
    only a wait() does, and nothing else ever waits on these openers.  The
    wait is bounded so a hung opener cannot stall serve startup; past the
    deadline it is killed and reaped.

    Once Popen has returned, the child exists and every later failure must go
    through :func:`_kill_and_reap`: a wait() that raises anything other than
    TimeoutExpired (a signal, an OSError) would otherwise take the same branch
    as a failed Popen and leave the opener unreaped and possibly still
    running.
    """
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # No shell: every argv here is the platform's own opener, and the
            # Windows one carries `cmd /c start` itself.
            shell=False,
            start_new_session=(os.name == "posix"),
            creationflags=_windows_detach_flags(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        # Expected on minimal installs (no xdg-open/open); say why before
        # falling back — "no browser ever appeared" must be diagnosable from
        # the log alone instead of failing silently.
        _log.warning(
            "Browser opener %s failed to start (%s: %s) — falling back to webbrowser",
            args[0],
            type(exc).__name__,
            exc,
        )
        if not webbrowser.open(url):
            _log.warning("webbrowser.open(%s): no usable browser found", url)
            return False
        return True
    try:
        proc.wait(timeout=_BROWSER_OPEN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _kill_and_reap(proc)
    except (OSError, subprocess.SubprocessError) as exc:
        _log.warning(
            "Browser opener %s wait failed (%s: %s) — killing and reaping it",
            args[0],
            type(exc).__name__,
            exc,
        )
        _kill_and_reap(proc)
    return True


def open_browser(url: str) -> bool:
    """Hand *url* to the platform opener; return whether one was launched."""
    system = platform.system()
    if system == "Linux":
        return _open_and_reap(url, ["xdg-open", url])
    if system == "Darwin":
        return _open_and_reap(url, ["open", url])
    if system == "Windows":
        return _open_and_reap(url, ["cmd", "/c", "start", "", url])
    return webbrowser.open(url)


# ── Commands ───────────────────────────────────────────────────────


def _allowed_origins(cors: bool, requested: list[str]) -> list[str]:
    """The allowlist `serve` installs, from the origins the operator asked for.

    ONE resolution for the banner and for ``recoverage config``, so the value
    an operator checks is the value the server matches against: a default port
    is dropped, the host is lowercased, and an entry that cannot normalize is
    refused rather than stored.  A stored "" would match every unparsable
    request Origin and echo it back as Access-Control-Allow-Origin.

    A refused entry is a startup error, not a warning, and the same way for
    the flag and the variable: the operator wrote an origin that no browser
    can send, so the server would come up with an allowlist one entry short of
    what was asked for and refuse exactly the reads that entry was meant to
    allow.  The refusal happens while CORS is on, because that is the only
    case where the entry would have been installed; with CORS off the
    allowlist is unused and ``serve`` already says the origins do nothing.
    """
    from recoverage.server import _normalize_origin

    if not cors:
        return []

    allowed: list[str] = []
    for origin_url in requested:
        normalized = _normalize_origin(origin_url) if _is_browser_origin(origin_url) else ""
        if not normalized:
            raise config.ConfigError(
                f"origin {origin_url!r} is not a URL the browser could send: "
                "expected scheme://host[:port], with no userinfo, path or whitespace"
            )
        allowed.append(normalized)
    return allowed


#: Schemes an Origin header can carry.  A browser serializes the origin's scheme
#: verbatim, so anything else is a value no browser sends.
_ORIGIN_SCHEMES = frozenset({"http", "https"})


def _is_browser_origin(value: str) -> bool:
    """Whether *value* is shaped like an Origin header a browser would send.

    Stricter than :func:`recoverage.server._normalize_origin`, which is built to
    READ whatever arrives on a request: it drops a path, drops a query, and
    synthesizes a scheme for a bare host, so it accepts values no browser can
    emit.  Validating an operator's allowlist through it would store a different
    entry than the one written, and the operator would not learn that until a
    request they expected to be allowed was refused.
    """
    if not value or any(ch.isspace() for ch in value):
        return False
    parts = urlsplit(value)
    if parts.scheme not in _ORIGIN_SCHEMES:
        return False
    if parts.path or parts.query or parts.fragment:
        return False
    if not parts.netloc or parts.username is not None or parts.password is not None:
        return False
    try:
        parts.port  # noqa: B018  -- raises ValueError on a non-numeric port
    except ValueError:
        return False
    return bool(parts.hostname)


def _remote_bind_gate(bind: str, allow_remote: bool) -> str | None:
    """The refusal a network bind earns without the acknowledgment, else None.

    Shared by `serve` and `recoverage config`, because a preflight that
    answered "this configuration is fine" for a bind `serve` exits 1 on is
    worse than no preflight: the operator deploys on the strength of the
    green run and the server never comes up.

    NOTE: "::" is the IPv6 wildcard (binds every interface) and must NOT be
    treated as loopback, or `--bind ::` would silently expose the
    unauthenticated API without the acknowledgment.
    """
    from recoverage.server import LOOPBACK_HOSTS

    if bind in LOOPBACK_HOSTS or allow_remote:
        return None
    return (
        f"--bind {bind} exposes the unauthenticated recoverage API (including raw "
        "binary bytes and disassembly) to every reachable host on the network. "
        "Pass --allow-remote (or RECOVERAGE_ALLOW_REMOTE=1) to confirm you want this."
    )


def _cors_warnings(cors: bool, requested: list[str]) -> list[str]:
    """The CORS settings that will not do what was written, as warnings.

    Neither is fatal: both combinations start a server, and each is a
    configuration the operator can only discover from a browser that refuses
    the read.  Returned rather than printed so `serve` and
    `recoverage config` warn from one rule.

    *requested* is what the operator wrote, not the installed allowlist: the
    entry that has no effect without ``--cors`` is by definition the one
    ``_allowed_origins`` did not install, so passing the installed list would
    make this warning unreachable.

    Each line names BOTH spellings of the setting, because the rule does not
    know which one supplied it: a unit file or a container spec spells the pair
    as ``RECOVERAGE_CORS`` and ``RECOVERAGE_CORS_ORIGIN``, and a warning that
    read as a flag would send that operator to argv for a value that belongs in
    the environment they configured.
    """
    warnings: list[str] = []
    if cors and not requested:
        warnings.append(
            "warning: --cors without --cors-origin allows no cross-origin reads "
            "(Access-Control-Allow-Origin: * is no longer emitted). "
            "Add --cors-origin URL for each origin you want to allow, or list them "
            "comma-separated in RECOVERAGE_CORS_ORIGIN."
        )
    if requested and not cors:
        warnings.append(
            "warning: --cors-origin has no effect without --cors — "
            f"CORS processing is disabled, so {len(requested)} origin(s) were "
            "dropped. Pass --cors, or set RECOVERAGE_CORS=1, to enable it."
        )
    return warnings


def _db_warnings(db: Path | None) -> list[str]:
    """The coverage directory this process will read nothing from, as warnings.

    Not fatal, and deliberately not the same rule as
    :func:`config.check_db_override`: a directory that does not exist yet is a
    normal state for a checkout that has not been built, while one that is a
    file can never hold documents and is refused before the listener binds.
    What both share is the consequence, and it is silent: ``db_target_ids``
    answers an empty list for an absent or empty directory, so the dashboard
    renders zero targets and every served figure reads as a healthy zero. The
    likeliest cause is a service started from a directory that is not the
    project root (``RECOVERAGE_DB`` names the right one), and the only clue
    today is a map with nothing on it.

    Returned rather than printed so ``serve`` and ``recoverage config`` warn
    from one rule, and so a preflight reports what ``serve`` will do.

    A path the project config cannot resolve to is not warned about here: the
    request path already answers it as a 503 naming the file, and this runs
    before any of that.
    """
    from rebrew.workspace import WorkspaceConfigError

    from recoverage._paths import _db_path

    try:
        path = db if db is not None else _db_path()
    except (OSError, WorkspaceConfigError):
        return []
    if not path.exists():
        state = f"the coverage directory {path} does not exist"
    elif not path.is_dir():
        # config.check_db_override refuses this one at startup; a warning here
        # would only repeat a refusal `serve` has already exited on.
        return []
    elif any(path.glob("coverage-*.toml")):
        return []
    else:
        state = f"no coverage-*.toml in {path}"
    return [
        (
            f"warning: {state}; the dashboard will list no targets until 'rebrew build-db' "
            "writes one. If this is a service, check RECOVERAGE_DB and the directory serve "
            "was started from."
        )
    ]


def _ack_warnings(bind: str, allow_remote: bool) -> list[str]:
    """The network acknowledgment that will not do what was written.

    The counterpart of :func:`_remote_bind_gate`, which refuses a remote bind
    nobody acknowledged. This is the other direction, and it cannot be fatal:
    a loopback bind is the safe one, so the server still starts and still
    serves. But the operator who exported the acknowledgment expected a
    reachable dashboard and has a loopback-only one, and the only clue is a
    connection refused from the machine they were serving.

    Returned rather than printed so ``serve`` and ``recoverage config`` warn
    from one rule, and so the preflight says what ``serve`` will say.
    """
    from recoverage.server import LOOPBACK_HOSTS

    if allow_remote and bind in LOOPBACK_HOSTS:
        return [
            (
                f"warning: --allow-remote is set but --bind {bind} is a loopback address, "
                "so the dashboard is reachable only from this machine. Bind an interface "
                "address (0.0.0.0 for every interface) to serve the network, in the flag "
                "or as RECOVERAGE_BIND=0.0.0.0."
            )
        ]
    return []


def _stop_on_sigterm() -> Callable[[], None]:
    """Stop on SIGTERM the way Ctrl+C stops; return the restore callable.

    Ctrl+C is the documented way to stop the dashboard, but a deployment does
    not press it: ``systemctl stop``, ``docker stop`` and a pod eviction all
    send SIGTERM, whose default disposition terminates the process where it
    stands. The accept loop never unwinds, the ``finally`` in ``serve`` never
    runs, and every request in flight is cut mid-body with no log line and no
    stop record.

    Raising :class:`KeyboardInterrupt` from the handler is the whole fix. A
    signal is delivered on the main thread, which is the thread inside
    ``bottle_app.run``, so ``serve``'s existing ``except KeyboardInterrupt``
    and ``finally`` cover the stop exactly as they cover the keystroke: the
    same quiet exit, the same cancelled deferred opener.

    Windows has no SIGTERM a handler can ever see: ``os.kill`` with anything
    but CTRL_C_EVENT/CTRL_BREAK_EVENT calls TerminateProcess, and a service
    stop there arrives as CTRL_BREAK_EVENT (SIGBREAK), whose default
    disposition is the same abrupt kill. So SIGBREAK is the Windows arm of
    the same rule, installed only where the constant exists; Ctrl+C is left to
    the interpreter on both.

    SIGINT is left to the interpreter, which already raises here. The
    returned callable puts back whatever handlers were installed before, so a
    test or an embedding caller is not left running under this one.
    """
    names = [name for name in ("SIGTERM", "SIGBREAK") if hasattr(signal, name)]
    if not names:
        return lambda: None
    installed = {getattr(signal, name): signal.getsignal(getattr(signal, name)) for name in names}

    def raise_interrupt(signum: int, frame: object) -> NoReturn:
        raise KeyboardInterrupt

    def restore() -> None:
        # signal.signal returns the handler it displaced; the callable handed
        # back says nothing, and serve's finally only calls it.
        for signum, handler in installed.items():
            signal.signal(signum, handler)

    for signum in installed:
        signal.signal(signum, raise_interrupt)
    return restore


def _configure_logging(level: int) -> None:
    """Route the root logger to stderr at *level*, with the request-id format.

    The level is the resolved one, so a service can turn the per-request
    chatter down (WARNING) or the detail up (DEBUG) without a code change;
    the level it runs at is reported in the startup banner.

    The request id is the pivot between a log line and the client that
    reported it: it is echoed on the X-Request-ID response header, and carried
    into the traceback line of a failed request.  ``defaults`` fills it in for
    records from loggers the app does not own (bottle, rebrew).
    """
    handler = logging.StreamHandler()
    # The log carries the same untrusted text as stdout (target ids, request
    # paths, the X-Request-ID value), and stderr carries the locale's codec:
    # under LC_ALL=C, or on a Windows code page, encoding a non-ASCII record
    # raises inside logging and the record is replaced by a
    # "--- Logging error ---" traceback that says nothing about the request.
    # backslashreplace keeps the record readable in whatever the stream is.
    # A stream that cannot be reconfigured (an in-memory test double) keeps
    # its own codec, as in _use_utf8_stdout.
    reconfigure = getattr(handler.stream, "reconfigure", None)
    if reconfigure is not None:
        with contextlib.suppress(ValueError, OSError):
            reconfigure(errors="backslashreplace")
    handler.setFormatter(
        StructuredFormatter(LOG_FORMAT, datefmt=LOG_DATEFMT, defaults={"request_id": "-"})
    )
    # The stamp comes from `clock`, not from logging's own `time.time()`, so
    # every wall-clock reading this process writes is one a test can drive and
    # a replay reproduces. See ClockStampedFilter.
    handler.addFilter(ClockStampedFilter())
    logging.basicConfig(handlers=[handler], level=level)


def _echo_banner(
    url: str,
    listen_url: str,
    assets: Path,
    active: Mapping[str, str],
    cors: bool,
) -> None:
    """Print the startup banner on stdout.

    The caller publishes *active* through ``server.configure_startup`` before
    calling, so the banner and ``/api/health`` carry the same rendered
    values.  Kept apart from ``serve`` so the banner is one callable rather
    than nine echoes interleaved with the listener setup.

    ``_db_path_or_exit`` runs inside the print, so an unresolvable coverage
    directory still fails before the listener binds.
    """
    typer.echo(f"Serving coverage dashboard at {url}")
    typer.echo(f"  Listening on: {listen_url}")
    typer.echo(f"  Assets: {assets}")
    typer.echo(f"  DB: {_db_path_or_exit()}")
    typer.echo("  Config: " + " ".join(f"{key}={value}" for key, value in active.items()))
    if cors:
        typer.echo("  CORS: enabled")
    typer.echo("  Regen: POST /api/regen or click Reload in UI")
    typer.echo("  Stop: Ctrl+C, or SIGTERM (systemctl stop, docker stop)")


@app.command()
def serve(
    # Every option backed by a RECOVERAGE_* variable defaults to None so "not
    # passed on the command line" stays distinguishable from a passed value,
    # and the environment supplies the default for it.  A flag always wins over
    # the environment.  (The three that default to False are the flags with no
    # variable: --no-open, --regen and --no-color, whose "off" is the absence
    # of a pass.)
    # (min/max moved into the config module: the range check has to run for
    # an env-provided port too, or an out-of-range value reaches socket.bind()
    # and surfaces as a raw OverflowError after the banner has printed.)
    port: str | None = typer.Option(
        None,
        "--port",
        "-p",
        metavar="PORT",
        help=f"Port to serve on, 0-65535 (0 binds a free port the OS picks and "
        f"reports in the banner; default: {config.DEFAULT_PORT}; env: RECOVERAGE_PORT)",
    ),
    bind: str | None = typer.Option(
        None,
        "--bind",
        metavar="ADDRESS",
        help=f"Interface to bind to (default: {config.DEFAULT_BIND}; use 0.0.0.0 for LAN; "
        "env: RECOVERAGE_BIND)",
    ),
    allow_remote: bool | None = typer.Option(
        None,
        "--allow-remote/--no-allow-remote",
        help="Required with --bind 0.0.0.0: acknowledge that the unauthenticated "
        "API (including raw binary bytes) is exposed on the network "
        "(env: RECOVERAGE_ALLOW_REMOTE)",
    ),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open browser automatically"),
    regen: bool = typer.Option(False, "--regen", help="Regenerate DB before starting"),
    cors: bool | None = typer.Option(
        None,
        "--cors/--no-cors",
        help="Enable CORS processing (allowlisted origins only; env: RECOVERAGE_CORS)",
    ),
    cors_origin: list[str] | None = typer.Option(
        None,
        "--cors-origin",
        metavar="ORIGIN",
        help="Origin URL allowed to read the API cross-origin (repeatable, "
        "e.g. http://localhost:5173; env: RECOVERAGE_CORS_ORIGIN, comma-separated)",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        metavar="TOKEN",
        help="Require this bearer token for every request (Authorization: Bearer <token>, "
        "?token=, or open the dashboard as /?token=<token> (or /potato?token=<token>) "
        "to set the browser cookie; env: RECOVERAGE_TOKEN, which keeps the token out "
        "of the process listing). An empty value turns auth off; one carrying "
        "whitespace is refused, because a trimmed request header cannot present it",
    ),
    log_level: str | None = typer.Option(
        None,
        "--log-level",
        metavar="LEVEL",
        help=f"Log threshold (default: {logging.getLevelName(config.DEFAULT_LOG_LEVEL)}; any name "
        "or number logging knows, e.g. DEBUG, INFO, WARN, WARNING, ERROR, CRITICAL; "
        "env: RECOVERAGE_LOG_LEVEL)",
    ),
    no_color: bool = _no_color_option(),
) -> None:
    """Start the recoverage dashboard server.

    Every setting flag also reads a RECOVERAGE_* environment variable, used as
    its default: RECOVERAGE_PORT, RECOVERAGE_BIND, RECOVERAGE_ALLOW_REMOTE,
    RECOVERAGE_CORS, RECOVERAGE_CORS_ORIGIN, RECOVERAGE_TOKEN,
    RECOVERAGE_LOG_LEVEL and RECOVERAGE_DB (an explicit coverage directory,
    instead of resolving rebrew-project.toml from the working directory, and
    read by every command rather than by serve alone), plus
    RECOVERAGE_MAX_CONNECTIONS and RECOVERAGE_CLIENT_TIMEOUT, which size the
    transport rather than select a behavior and so have no flag.
    [bold]--no-open[/bold], [bold]--regen[/bold] and [bold]--no-color[/bold] are
    the three flags with no variable, because a service that wants the browser
    or a rebuild asks for it in argv, not in the environment, and the colour
    opt-out is the unprefixed NO_COLOR convention rather than a RECOVERAGE_*
    name.

    A flag always wins over the environment; an unrecognised RECOVERAGE_*
    name is a startup error, and so is a value that is not a valid port,
    boolean, log level, CORS origin a browser could send, or (for every
    setting but the token) a non-empty string.

    Exits 2 for any of those, before the listener binds. Exits 1 when --bind
    names a non-loopback address without --allow-remote (the refusal and the
    firewall warning go to stderr) or when the port is already taken, and 0 on
    Ctrl+C. [bold]recoverage config[/bold] runs the same checks and ends the
    same way, so a deployment can preflight this configuration. It reads the
    environment only and takes none of these flags, so it preflights a
    deployment that sets RECOVERAGE_*; one that passes these flags in argv is
    checked when it starts.
    """
    import recoverage.server as _server
    from recoverage.server import (
        LOOPBACK_HOSTS,
        _assets_dir,
        _project_dir,
    )
    from recoverage.webapp import app as bottle_app

    # The banner echoes the assets and coverage directories, and the warnings
    # below quote the bind address, the origins and the coverage directory, all
    # before _configure_logging installs the log stream's own codec. A project
    # under a non-ASCII path is a name a Windows code page cannot spell, so pin
    # both streams before anything prints rather than after.
    _use_utf8_stdout()
    _use_utf8_stderr()

    resolved = _resolve_serve_config(
        port=port,
        bind=bind,
        allow_remote=allow_remote,
        cors=cors,
        cors_origin=cors_origin,
        token=token,
        log_level=log_level,
    )
    bind = resolved.bind
    # --port 0 asks the OS for a free port. Resolve it here, before anything
    # prints or binds, so the banner, the config block, /api/health and the
    # browser URL all name the port that is actually bound rather than the 0
    # that was asked for.
    listen_port = resolve_listen_port(resolved.port, bind)
    allow_remote = resolved.allow_remote
    cors = resolved.cors
    token = resolved.token

    # Every warning in this block goes to stderr, so a deployment that
    # captures stdout for the banner (tools/smoke.py, the harness) still
    # sees the half of the configuration that will not work.
    refusal = _remote_bind_gate(bind, allow_remote)
    if refusal is not None:
        _secho(refusal, fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    is_remote = bind not in LOOPBACK_HOSTS
    if is_remote:
        _secho(
            "warning: serving unauthenticated binary data on the network — "
            "restrict access at the firewall.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    for warning in _cors_warnings(cors, resolved.cors_origins_requested):
        _secho(warning, fg=typer.colors.YELLOW, err=True)
    for warning in _ack_warnings(bind, allow_remote):
        _secho(warning, fg=typer.colors.YELLOW, err=True)
    for warning in _db_warnings(resolved.db):
        _secho(warning, fg=typer.colors.YELLOW, err=True)
    # IPv6 hosts need brackets in any URL spelling (a bare "::1" leaves
    # urlsplit with no hostname and a ".port" that raises).
    display_host = f"[{bind}]" if ":" in bind else bind

    _configure_logging(resolved.log_level)

    if token:
        _secho(
            f"token auth enabled — requests need Authorization: Bearer <token> "
            f"(SPA: open as http://{display_host}:{listen_port}/?token=<token>)",
            fg=typer.colors.GREEN,
        )
    # Loopback binds validate the Host header (DNS-rebinding guard); remote
    # binds (user opted in via --allow-remote) skip validation.
    #
    # The INSTALLED allowlist, never the `--cors-origin` flag it was resolved
    # from: the flag is the operator's spelling, `resolved.cors_origins` is what
    # `_allowed_origins` validated and normalized, and a request's Origin is
    # normalized again before it is matched. Installing the raw list is the
    # dropped-entry failure `_is_browser_origin` exists to prevent, and a
    # spelling the operator never wrote is the one the matcher then refuses. The
    # flag is also None whenever the origins came from RECOVERAGE_CORS_ORIGIN,
    # which installed an empty allowlist over the list the banner and
    # `recoverage config` render. `recoverage config` reads the resolved list,
    # so the preflight and the process answer the same question.
    _server.configure_security(
        cors_enabled=cors,
        cors_allowed_origins=resolved.cors_origins,
        auth_token=token or "",
        allowed_hosts=None if is_remote else set(LOOPBACK_HOSTS),
    )

    root = _project_dir()
    assets = _assets_dir()
    listen_url = f"http://{display_host}:{listen_port}"
    # The browser opens against the bound loopback interface: --bind ::1
    # listens on IPv6 loopback only, so the hard-coded http://127.0.0.1 (IPv4)
    # would open a tab that refuses to connect.  Remote binds keep 127.0.0.1 —
    # a wildcard/external address also answers on IPv4 loopback.
    url = listen_url if not is_remote else f"http://127.0.0.1:{listen_port}"

    if regen:
        _run_regen(root)

    _log.info("Starting recoverage server on %s (port=%d, cors=%s)", listen_url, listen_port, cors)

    # The full active configuration, resolved from flags and the environment,
    # so an operator can confirm what the process is actually running with.
    # Rendered ONCE and published to /api/health: the banner and the running
    # process's answer are the same values, so they cannot drift.  The token is
    # reported as set/unset, never by value.
    active = config.active_config(
        port=listen_port,
        bind=bind,
        allow_remote=allow_remote,
        cors=cors,
        cors_origin=resolved.cors_origins,
        token=token,
        db=resolved.db,
        log_level=resolved.log_level,
        max_connections=resolved.max_connections,
        client_timeout=resolved.client_timeout,
    )
    _server.configure_startup(active)
    # Install the transport bounds the same values report, before the listener
    # binds: a cap validated and then not installed is a config the banner
    # lies about.
    configure_transport(
        max_connections=resolved.max_connections,
        client_timeout_seconds=resolved.client_timeout,
    )
    _echo_banner(
        url=url,
        listen_url=listen_url,
        assets=assets,
        active=active,
        cors=cors,
    )

    browser_timer: threading.Timer | None = None
    if not no_open:
        # Daemon + kept reference: a hung opener must never delay interpreter
        # exit.  The finally below cancels the timer, and the opener asks the
        # listener before it launches, so a start that never got as far as
        # accepting does not pop a browser tab pointing at a dead port by
        # either route.
        browser_timer = threading.Timer(
            _BROWSER_OPEN_DELAY_SECONDS, _open_when_listening, args=(url,)
        )
        browser_timer.daemon = True
        browser_timer.start()

    # Start the DB watcher at startup (not on first /api/events connection):
    # without it, external rebuilds leave the target/dropdown caches stale
    # for servers that never receive an SSE client (curl-only automation).
    from recoverage.api import _ensure_db_watcher

    # Warm the SPA shell cache off the request path: the first page load
    # would otherwise pay the asset read + minify + three full-strength
    # compressions synchronously.  Daemon thread, started before the listener
    # accepts; failures are logged and stay lazy.
    from recoverage.ui import warm_index_cache

    # Both starts are INSIDE the try, and the try opens at the first of them
    # rather than at bottle_app.run: each is a Thread.start, which raises
    # RuntimeError under thread exhaustion, and a raise there escaped before
    # the finally existed — so the armed opener popped a tab at a port nothing
    # was listening on half a second later, which is the exact outcome the
    # finally's own comment claims to cover.  A startup step that fails this
    # way is a failed start, whichever step it was.
    # Armed before the try, so the finally below always finds the callable
    # bound: signal.signal only raises off the main thread, and a serve() run
    # from a test thread must fail the way it did before rather than through
    # a NameError in the cleanup.
    restore_stop_handler = _stop_on_sigterm()
    try:
        _ensure_db_watcher()

        warmup = threading.Thread(
            target=warm_index_cache, name="recoverage-index-warmup", daemon=True
        )
        warmup.start()

        bottle_app.run(
            host=bind,
            port=listen_port,
            quiet=True,
            server="wsgiref",
            server_class=_server_class_for(bind),
            handler_class=_KeepAliveRequestHandler,
        )
    except KeyboardInterrupt:
        # Ctrl+C is the documented way to stop the dashboard; wsgiref's
        # accept loop unwinds with KeyboardInterrupt — exit quietly instead
        # of dumping a traceback.  The deferred opener is cancelled by the
        # finally below, like every other way out of this block: a Ctrl+C
        # inside the 0.5s scheduling window is a failed start and must not pop
        # a tab at a dead port.
        _log.debug("serve stopped on Ctrl+C")
    except OSError as e:
        # EADDRINUSE is the most common failure for a dashboard tool — a
        # second instance or another dev server on the same port.
        _secho(
            f"Failed to start server on {listen_url}: {e.strerror or e} "
            "(is another instance already running?)",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1) from None
    finally:
        # Once bottle_app.run has returned there is no listener left, so the
        # deferred opener has nothing to open: a start that failed (EADDRINUSE,
        # Ctrl+C, a thread that would not start) and one that ran and stopped
        # both pop a browser tab at a dead port if the timer is still armed.
        # One place covers every exit, including the unexpected one — an
        # OverflowError out of socket.bind() or a RuntimeError from a server
        # with no app installed used to leave the timer to fire half a second
        # after the traceback, which is the one exit path nobody had covered.
        # Cancel alone cannot be the whole answer: it returns before the timer
        # thread has stopped, so a callback already past its own check runs
        # anyway — hence the listener probe inside the opener.
        restore_stop_handler()
        if browser_timer is not None:
            browser_timer.cancel()


#: Per-section values the table, CSV and Markdown renders all print, in the
#: order they print them.  ONE list: `stats`, `export --format csv` and
#: `export --format md` are the same table in three spellings, and a key added
#: to one and forgotten in another renders a header and a body that disagree.
#: The human labels stay at each call site (the table calls near_match
#: "Match", the exports its JSON key).
_SECTION_COLUMNS: tuple[str, ...] = (
    "size_bytes",
    "total_cells",
    "exact",
    "reloc",
    "near_match",
    "stub",
    "coverage_pct",
)


def _section_row(sec: dict[str, Any]) -> list[Any]:
    """One section's :data:`_SECTION_COLUMNS` values, in that order.

    ``.get(..., 0)`` for every key, not a mix: a NULL section size is
    schema-legal (.bss carries one) and reaches the CLI as 0 from
    ``_section_stats``, so a missing key and a zero-sized section read the
    same in every format.
    """
    return [sec.get(field, 0) for field in _SECTION_COLUMNS]


def _export_write_failed(
    exc: OSError | UnicodeError, output_format: str, progress: str
) -> NoReturn:
    """Report a failed write on the export's stdout and exit 1.

    ONE tail for every ``--format`` arm, so a half-written redirect reads the
    same whichever format produced it: ENOSPC, a quota, a closed pipe on a
    network mount. Without it the failure escapes as an OSError traceback from
    whichever arm happened to lack the guard, and the operator is left with a
    truncated file and a stack trace instead of the operation that failed.

    *progress* names how far the arm got ("after 12 of 40 section rows", or
    "while writing the document" for the single-write JSON arm), because the
    file the operator is looking at is the one this ran out of room on.

    ``UnicodeError`` joins ``OSError`` for the same reason: a stream that could
    not be pinned (a pipe wrapper, a closed stream, a test double without
    ``reconfigure``) still holds its own error handler, and a target id the
    filesystem spelled with a byte outside UTF-8 reaches the writer as a lone
    surrogate that strict encoding refuses.  That is a truncation like any
    other, so it reads as one instead of escaping as a traceback.
    """
    _secho(
        f"Error: {output_format} export failed {progress} "
        f"({type(exc).__name__}: {exc}). The output is truncated; free space "
        "or redirect to another path and retry.",
        fg=typer.colors.RED,
        err=True,
    )
    raise typer.Exit(1) from None


@app.command()
def stats(
    target: str | None = typer.Option(
        None, "--target", "-t", metavar="TARGET", help="Target ID (default: all)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    no_color: bool = _no_color_option(),
) -> None:
    """Print coverage stats as a table (or JSON with --json).

    Exits 1 when the coverage directory holds no document, or when --target
    names a target no build has written; the errors go to stderr, or to
    stdout as a JSON object under --json.
    """
    _use_utf8_stdout()

    from rich import box
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    from recoverage.server import pct_1dp

    with _open_targets(target, json_output=json_output) as (snapshots, targets):
        if json_output:
            typer.echo(
                json.dumps(
                    [_get_stats(snapshots, tid, json_output=True) for tid in targets], indent=2
                )
            )
            return

        # Rich detects NO_COLOR and TERM=dumb on its own, but not the
        # --no-color flag (a process-wide setting it cannot see), so the
        # resolved opt-out is passed through: a table is the widest colored
        # surface the CLI has, and it must honor the same three opt-outs
        # every _secho caller does.
        console = Console(no_color=True if _color_off() else None)
        for index, tid in enumerate(targets):
            data = _get_stats(snapshots, tid)
            # Blank line between targets, never before the first one: the
            # same rule `export --format md` follows, so redirected output
            # does not start with an empty line.
            if index:
                console.print()
            # escape(): the target id is a value out of a coverage document,
            # and Rich reads square brackets in a printed string or a table
            # cell as markup. The CSV and Markdown arms route the same value
            # through _csv_safe / _md_safe for the same reason.
            console.print(f"[bold cyan]{escape(tid)}[/bold cyan]")

            if data["summary"]:
                s = data["summary"]
                total_fn = s.get("totalFunctions", 0)
                matched_fn = s.get("matchedFunctions", 0)
                # Floored, like every other match figure rebrew reports: 2809
                # of 2810 functions is 99.96%, and round() printed that line as
                # "(100.0%)" with a function still unmatched beside it.
                pct = floor_pct(matched_fn, total_fn, 1)
                console.print(f"  Functions: {matched_fn}/{total_fn} matched ({pct}%)")

            # box.SIMPLE_HEAD, not Rich's stock HEAVY_HEAD: the rest of this
            # product draws a hairline and square corners (--radius-hair, the
            # Potato tables' bordercolor), and a heavy double rule around eight
            # right-aligned numbers is the library's demo look, not a readout.
            # One rule under the header is all a table of figures needs to be
            # read down a column.
            table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAD)
            table.add_column("Section", style="cyan")
            table.add_column("Size", justify="right")
            table.add_column("Cells", justify="right")
            table.add_column("Exact", justify="right", style="green")
            table.add_column("Reloc", justify="right", style="blue")
            table.add_column("Match", justify="right", style="yellow")
            table.add_column("Stub", justify="right", style="red")
            table.add_column("Coverage", justify="right", style="bold")

            for sec_name, sec in sorted(data["sections"].items()):
                size, cells, exact, reloc, near_match, stub, coverage_pct = _section_row(sec)
                table.add_row(
                    escape(sec_name),
                    f"{size:,} B",
                    str(cells),
                    str(exact),
                    str(reloc),
                    str(near_match),
                    str(stub),
                    f"{pct_1dp(coverage_pct):.1f}%",
                )

            console.print(table)


@app.command()
def export(
    output_format: ExportFormat = typer.Option(
        ExportFormat.json,
        "--format",
        "-f",
        help="Output format (choose json, csv, or md)",
    ),
    json_flag: bool = typer.Option(
        False, "--json", help="Output JSON (shorthand for --format json)"
    ),
    target: str | None = typer.Option(
        None, "--target", "-t", metavar="TARGET", help="Target ID (default: all)"
    ),
    no_color: bool = _no_color_option(),
) -> None:
    """Export coverage data to stdout.

    JSON verbatim. CSV cells that start with a spreadsheet formula or control
    character are prefixed with an apostrophe, rows end with the platform's
    line ending, and a line break inside a cell is written as the document
    spells it. Markdown cells escape pipes and newlines.

    The rows are the only thing on stdout, so a redirect or a pipe gets clean
    data. Exits 1 when the coverage directory holds no document or --target
    names a target no build has written, and the report goes to stderr (to
    stdout as a JSON object under --format json).

    --json is the spelling every other reporting command takes
    ([bold]stats[/bold], [bold]check[/bold], [bold]config[/bold]), and it means
    --format json.  Naming both, with a --format that is not json, is a usage
    error rather than a silent winner.
    """
    _use_utf8_stdout()
    if json_flag and output_format is not ExportFormat.json:
        _fail(
            f"Error: --json and --format {output_format.value} cannot be "
            "combined: --json is shorthand for --format json.",
            f"--json and --format {output_format.value} cannot be combined",
            2,
            json_flag,
        )
    if json_flag:
        output_format = ExportFormat.json
    json_output = output_format is ExportFormat.json

    from recoverage.server import pct_1dp

    with _open_targets(target, json_output=json_output) as (snapshots, targets):
        all_data = [_get_stats(snapshots, tid, json_output=json_output) for tid in targets]

    if output_format == ExportFormat.json:
        try:
            typer.echo(json.dumps(all_data, indent=2))
        except BrokenPipeError:
            # `recoverage export | head` is a documented use, and main() owns
            # that contract (devnull, then exit 1).
            raise
        except (OSError, UnicodeError) as exc:
            _export_write_failed(exc, "JSON", "while writing the document")

    elif output_format == ExportFormat.csv:
        import csv

        # The csv module owns every line break it writes: stdout's newline
        # translation is switched off and the rows end in os.linesep, so a row
        # ends in the platform's native ending exactly once.  Left on,
        # Windows' text-mode stdout also rewrote a "\n" INSIDE a quoted cell
        # (a section or target name can hold one) to "\r\n", and the cell read
        # back was not the name the document holds.
        stream = _utf8_stream(sys.stdout)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(newline="")
        written = 0
        total = sum(len(data["sections"]) for data in all_data)
        try:
            writer = csv.writer(stream, lineterminator=os.linesep)
            writer.writerow(["target", "section", *_SECTION_COLUMNS])
            for data in all_data:
                for sec_name, sec in sorted(data["sections"].items()):
                    writer.writerow(
                        [_csv_safe(data["target"]), _csv_safe(sec_name), *_section_row(sec)]
                    )
                    written += 1
            stream.flush()
        except BrokenPipeError:
            # `recoverage export | head` is a documented use, and main() owns
            # that contract: it repoints stdout at devnull and reports the
            # truncation with exit 1. Swallowing it here would export a
            # complete file and exit 0.
            raise
        except (OSError, UnicodeError) as exc:
            _export_write_failed(exc, "CSV", f"after {written} of {total} section rows")
        finally:
            # Detach on EVERY path, not only the successful one: the wrapper
            # _utf8_stream built owns sys.stdout's buffer, and its destructor
            # closes what it wraps. Leaving it attached to unwind out of a
            # failed write closed the real stdout, so the error the operator
            # needed was replaced by a ValueError from the interpreter's
            # final flush. detach() flushes, so a pending write can make it
            # raise the same OSError; the exit is already reported and a
            # second one here would mask it.
            if isinstance(stream, io.TextIOWrapper) and stream is not sys.stdout:
                with contextlib.suppress(OSError, ValueError):
                    stream.detach()

    elif output_format == ExportFormat.md:

        def _md_safe(s: str) -> str:
            return s.replace("|", _MD_PIPE).translate(_MD_LINE_BREAKS)

        written = 0
        total = sum(len(data["sections"]) for data in all_data)
        try:
            for index, data in enumerate(all_data):
                # Blank line between targets, never before the first one: a
                # redirected file must not start with an empty line.
                if index:
                    typer.echo()
                typer.echo(f"## {_md_safe(data['target'])}\n")
                # Same columns as the CSV export, minus the per-target key the
                # "## <target>" heading above already carries.  Header,
                # separator, and body must agree on the count or the table
                # renders ragged.
                typer.echo("| Section | Size | Cells | Exact | Reloc | Near | Stub | Coverage |")
                typer.echo("|---------|------|-------|-------|-------|------|------|----------|")
                for sec_name, sec in sorted(data["sections"].items()):
                    size, cells, exact, reloc, near_match, stub, coverage_pct = _section_row(sec)
                    typer.echo(
                        f"| {_md_safe(sec_name)}"
                        f" | {size:,} B | {cells}"
                        f" | {exact} | {reloc} | {near_match}"
                        f" | {stub} | {pct_1dp(coverage_pct):.1f}% |"
                    )
                    written += 1
        except BrokenPipeError:
            # main() owns `export | head`; see the CSV arm above.
            raise
        except (OSError, UnicodeError) as exc:
            _export_write_failed(exc, "Markdown", f"after {written} of {total} section rows")


def _section_verdict(
    pct: float,
    untracked: bool,
    section_requested: bool,
    min_coverage: float,
) -> tuple[str, dict[str, Any], str]:
    """Classify one section against the gate: (status, JSON extras, human text).

    *pct* is the UNROUNDED coverage percentage — callers recompute it from
    the raw covered/total byte counts, because the gate must decide on the
    true ratio: comparing the 2dp display value _section_stats stores lets
    99.9997% pass a --min-coverage 100 gate.  The quoted value is the same
    floored-to-2dp percentage /stats serves (server.coverage_pct), so a
    verdict never quotes a number the dashboard does not, and a FAIL line
    cannot read "coverage 100.00% < 100.00%".

    Sections whose cells are all "none" carry no coverage signal — the grid
    only records match states in .text — so they must not fail the gate.
    An explicitly requested untracked section still fails: the user asked to
    gate something that is not being recorded.
    """
    if untracked and section_requested:
        return (
            "FAIL",
            {"reason": "no tracked cells — coverage is not recorded for this section"},
            "has no tracked cells — coverage is not recorded for this section",
        )
    if untracked:
        return (
            "SKIP",
            {"reason": "no tracked cells — coverage not recorded"},
            "has no tracked cells — coverage not recorded",
        )
    # Compare the unrounded ratio, print it floored to 2dp (see docstring).
    # The /100 denominator cancels the helper's own ×100: what matters is that
    # the value is floored, so 99.9997% cannot be quoted as 100.00% beside a
    # FAIL verdict that just compared it against 100.00%.
    shown = floor_pct(pct, 100, 2)
    if pct < min_coverage:
        return (
            "FAIL",
            {"coverage_pct": shown},
            f"coverage {shown:.2f}% < {min_coverage:.2f}%",
        )
    return (
        "PASS",
        {"coverage_pct": shown},
        f"coverage {shown:.2f}% >= {min_coverage:.2f}%",
    )


def _checked_min_coverage(value: str, json_output: bool) -> float:
    """*value* as a coverage percentage, or exit 2 through ``_fail``.

    The flag is text for the same reason ``--port`` is: click's ``FLOAT`` runs
    the value through ``float()``, which accepts ``inf``, ``nan``, Unicode
    digits and the ``_`` separator, so a CI gate could be handed a threshold
    that is not the number that was typed.  A leading sign is allowed (a
    negative gate is a usage error the range check reports, not a parse error);
    everything after it must be ASCII digits and one ASCII dot.
    """
    from recoverage.server import parse_ascii_int

    text = value.strip()
    sign = ""
    if text[:1] in ("+", "-"):
        sign, text = text[0], text[1:]
    whole, dot, frac = text.partition(".")
    parsed: float | None = None
    if whole and not (dot and not frac) and "." not in frac:
        try:
            parsed = float(f"{sign}{parse_ascii_int(whole)}.{parse_ascii_int(frac) if frac else 0}")
        except ValueError:
            parsed = None
    if parsed is None:
        _fail(
            f"Error: --min-coverage is not a number: {value!r}.",
            "--min-coverage is not a number",
            2,
            json_output,
        )
    return parsed


@app.command()
def check(
    min_coverage: str = typer.Option(
        ...,
        "--min-coverage",
        "-m",
        metavar="MIN_COVERAGE",
        help="Minimum coverage percentage (0-100)",
    ),
    target: str | None = typer.Option(
        None, "--target", "-t", metavar="TARGET", help="Target ID (default: all)"
    ),
    section: str | None = typer.Option(
        None, "--section", "-s", metavar="SECTION", help="Section name (default: all)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    no_color: bool = _no_color_option(),
) -> None:
    """Check coverage against a threshold (CI gate).

    Exits 0 when every compared section meets the threshold, 1 when one does
    not, and 2 for a bad --min-coverage or an unreadable database.  A section
    the grid never records matches for is reported SKIP, unless --section
    named it, which FAILs.
    """
    _use_utf8_stdout()
    threshold = _checked_min_coverage(min_coverage, json_output)
    if not 0.0 <= threshold <= 100.0:
        # A flag value outside its own documented range is a usage error, the
        # same exit 2 a non-numeric value gets from the parser.
        _fail(
            f"Error: --min-coverage must be between 0 and 100, got {threshold!r}.",
            "--min-coverage must be between 0 and 100",
            2,
            json_output,
        )

    with _open_targets(target, missing_exit_code=2, json_output=json_output) as (
        snapshots,
        targets,
    ):
        failed = False
        checked = 0
        compared = 0
        verdicts: list[dict[str, Any]] = []
        for tid in targets:
            data = _get_stats(snapshots, tid, json_output=json_output)
            sections_to_check = data["sections"]
            if section:
                if section not in sections_to_check:
                    # A per-section verdict, so it belongs on stdout with the
                    # PASS/FAIL lines: `check 2>/dev/null` must not drop the
                    # sections it declined to gate.  Under --json, stdout is
                    # the machine channel, so the note moves to stderr.
                    _secho(
                        f"SKIP: {tid} has no section {section}",
                        fg=typer.colors.YELLOW,
                        err=json_output,
                    )
                    continue
                sections_to_check = {section: sections_to_check[section]}

            for sec_name, sec in sorted(sections_to_check.items()):
                checked += 1
                covered = sec.get("covered_bytes") or 0
                untracked = covered <= 0
                if not untracked:
                    compared += 1
                # Gate on the unrounded byte ratio; sec["coverage_pct"] is
                # display-rounded to 2dp (see _section_verdict).  total_bytes
                # == 0 implies covered == 0 (cell spans are non-negative, so
                # covered <= total), i.e. an untracked section whose verdict
                # never reads pct, so no fallback value can reach a comparison.
                total_bytes = sec.get("total_bytes") or 0
                pct = covered / total_bytes * 100 if total_bytes else 0.0
                status, extra, human = _section_verdict(pct, untracked, bool(section), threshold)
                if status == "FAIL":
                    failed = True
                verdicts.append({"target": tid, "section": sec_name, "status": status, **extra})
                if not json_output:
                    _secho(f"{status}: {tid} {sec_name} {human}", fg=_VERDICT_COLORS[status])

    if checked == 0:
        _fail(
            "Error: no sections matched — nothing was checked.",
            "no sections matched — nothing was checked",
            1,
            json_output,
        )
    if compared == 0 and not failed:
        # Every section was skipped as untracked and nothing failed — a
        # project with no recorded coverage must not pass vacuously.  An
        # explicit --section on an untracked section already produced a FAIL
        # verdict above; that verdict (and the JSON results array) must reach
        # the caller instead of being replaced by this generic error.
        _fail(
            "Error: no tracked sections — nothing was checked.",
            "no tracked sections — nothing was checked",
            1,
            json_output,
        )
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "passed": not failed,
                    "min_coverage": threshold,
                    "results": verdicts,
                },
                indent=2,
            )
        )
    if failed:
        raise typer.Exit(1)


@app.command()
def regen(no_color: bool = _no_color_option()) -> None:
    """Re-run rebrew catalog + build-db to regenerate the coverage documents.

    Writes nothing to stdout: the progress line, the completion line and every
    error are status, and status goes to stderr, so a caller reads the report
    from the exit code alone. Exits 2 when RECOVERAGE_DB names a directory
    rebrew would not write to (the mismatch is refused rather than reported
    as a done regen that left the dashboard stale), 1 when rebrew fails or
    another process already holds this project's regen lock, and 0 when it
    succeeds, whether or not it had a built target to write.
    """
    from recoverage.server import _project_dir

    _use_utf8_stdout()
    # `_run_regen` prints its failures to stderr and they carry the coverage
    # directory, so this command needs the stderr arm `serve` and
    # `recoverage config` both take before the logging filter is installed.
    _use_utf8_stderr()
    _check_env_or_exit()
    written = _run_regen(_project_dir())
    if written:
        _secho(
            f"Done — {len(written)} coverage document(s) written to {written[0].parent}.",
            fg=typer.colors.GREEN,
            err=True,
        )
    else:
        _secho(
            "Done — rebrew wrote no coverage documents (no built targets).",
            fg=typer.colors.GREEN,
            err=True,
        )


@app.command("open")
def open_cmd(
    port: str | None = typer.Option(
        None,
        "--port",
        "-p",
        metavar="PORT",
        help=f"Port of the running server (default: {config.DEFAULT_PORT}; env: RECOVERAGE_PORT)",
    ),
    no_color: bool = _no_color_option(),
) -> None:
    """Open the dashboard in a browser.

    The port falls back to RECOVERAGE_PORT, the same default [bold]serve[/bold]
    uses, so a deployment that moved the server off 8001 does not need every
    operator to remember the new port as well.  A port of 0 is refused: it
    names the free port the server picked, which is in the banner
    [bold]serve[/bold] printed and is not something this command can know.

    Exits 1 when no browser could be launched, so a script or a container
    entrypoint that runs this and finds nothing open learns why.
    """
    _check_env_or_exit()
    try:
        resolved_port = config.port() if port is None else _checked_port(port)
    except config.ConfigError as exc:
        _secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    if resolved_port == config.MIN_PORT:
        source = "RECOVERAGE_PORT" if port is None else "--port"
        _secho(
            f"Error: {source} 0 is not an address: it asks the server for a free "
            "port of the OS's choosing. Open the URL from the serve banner, or "
            "pass the port it printed.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2) from None
    url = f"http://127.0.0.1:{resolved_port}"
    typer.echo(f"Opening {url}")
    if not open_browser(url):
        _secho(
            f"Error: no browser available to open {url}. Open the URL by hand, "
            "or check that a desktop opener (xdg-open, open) is installed.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)


@app.command("config")
def config_cmd(
    as_json: bool = typer.Option(
        False, "--json", help="Emit the resolved settings as a JSON object"
    ),
    no_color: bool = _no_color_option(),
) -> None:
    """Print the configuration [bold]serve[/bold] would start with, without binding a port.

    The values come from the same merge and validation [bold]serve[/bold] runs,
    over the [bold]environment[/bold]: this command declares no setting flags,
    so a flag given to [bold]serve[/bold] on the command line is not a value it
    can see or check.  It preflights the deployment that configures
    [bold]serve[/bold] through RECOVERAGE_*; to preflight one that passes flags
    in argv, read the answers back from a [bold]serve[/bold] that starts and
    stops on them.  The token is reported as [bold]set[/bold] or
    [bold]unset[/bold]; its value is never printed.

    It is a preflight, so it also ends the way [bold]serve[/bold] ends: the same
    network-bind refusal (exit 1) and the same CORS warnings, after the
    values.  A check that exited 0 for a configuration [bold]serve[/bold] refuses
    is a deployment that finds out at boot instead of at the check.

    A port of 0 prints as 0: it is the configured value, and the free port
    [bold]serve[/bold] binds in its place is a different one on every run.  The
    banner that run prints is where the real number is.
    """
    _use_utf8_stdout()
    _use_utf8_stderr()
    resolved = _resolve_serve_config()
    settings = config.active_config(
        port=resolved.port,
        bind=resolved.bind,
        allow_remote=resolved.allow_remote,
        cors=resolved.cors,
        cors_origin=resolved.cors_origins,
        token=resolved.token,
        db=resolved.db,
        log_level=resolved.log_level,
        max_connections=resolved.max_connections,
        client_timeout=resolved.client_timeout,
    )
    if as_json:
        typer.echo(json.dumps(settings, indent=2))
    else:
        for key, value in settings.items():
            typer.echo(f"{key}={value}")
    for warning in _cors_warnings(resolved.cors, resolved.cors_origins_requested):
        _secho(warning, fg=typer.colors.YELLOW, err=True)
    for warning in _ack_warnings(resolved.bind, resolved.allow_remote):
        _secho(warning, fg=typer.colors.YELLOW, err=True)
    for warning in _db_warnings(resolved.db):
        _secho(warning, fg=typer.colors.YELLOW, err=True)
    refusal = _remote_bind_gate(resolved.bind, resolved.allow_remote)
    if refusal is not None:
        _secho(refusal, fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


# Group flags that answer the invocation themselves, so ``recoverage --help``
# must not grow a subcommand behind them.
_GROUP_TERMINAL_FLAGS = frozenset(
    {"-h", "--help", "--version", "-V", "--show-completion", "--install-completion"}
)


def _argv_with_default_command(argv: list[str]) -> list[str]:
    """Bare ``recoverage`` runs ``serve``.

    The dashboard is the only thing most invocations want, and it is the one
    a user types in a rebrew project directory without thinking — the way
    ``rebrew`` itself runs its action when no subcommand is named.  The
    subcommand stays the only spelling with flags (``recoverage serve
    --port 9000``), because the flags belong to ``serve`` and a group that
    declared them too would carry two option tables that can disagree.  Every
    group flag is a boolean, so a command line carrying only those has a
    subcommand appended after them (click parses the two in either order) and
    ``recoverage --no-color`` serves the dashboard.  A flag that ends the
    invocation on its own, and any non-flag token at all, is left exactly as
    it came, so ``recoverage --help`` still prints the help and not a server.
    """
    args = argv[1:]
    if any(arg in _GROUP_TERMINAL_FLAGS for arg in args):
        return argv
    if any(not arg.startswith("-") for arg in args):
        return argv
    return [*argv, "serve"]


def main() -> None:
    sys.argv = _argv_with_default_command(sys.argv)
    try:
        app()
    except BrokenPipeError:
        # Downstream closed the pipe early (e.g. `recoverage export | head`):
        # the interpreter flushes stdout at exit and would print a spurious
        # "Exception ignored" traceback.  Point stdout's fd at devnull so the
        # final flush succeeds (no-op when stdout has no real fd), then report
        # the truncation with a non-zero status.
        # The open is inside the suppress because it is as fallible as the dup2
        # beside it (a sandbox or a stripped container with no /dev/null, a
        # full descriptor table), and an OSError from it would escape this
        # handler and replace the exit status with a traceback: the one path
        # whose whole job is to report a clean truncation.
        with contextlib.suppress(OSError, ValueError):
            fd = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(fd, sys.stdout.fileno())
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd)
        raise SystemExit(1) from None
