"""Typer CLI for recoverage — coverage dashboard for binary-matching projects."""

from __future__ import annotations

import contextlib
import email.message
import enum
import json
import logging
import os
import platform
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import webbrowser
from collections.abc import Iterator
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import IO, Any, NamedTuple, NoReturn, cast
from wsgiref.simple_server import ServerHandler, WSGIRequestHandler, WSGIServer
from wsgiref.types import InputStream, WSGIApplication

import typer

from recoverage import config
from recoverage._paths import _db_path

app = typer.Typer(
    help="Coverage dashboard for binary-matching decompilation projects.",
    add_completion=True,
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        f"  recoverage serve [dim]# start the dashboard (port {config.DEFAULT_PORT})[/dim]\n\n"
        "  recoverage serve --port 3000 [dim]# custom port[/dim]\n\n"
        "  recoverage stats --json [dim]# machine-readable statistics[/dim]\n\n"
        "  recoverage export --format csv > coverage.csv [dim]# export as CSV[/dim]\n\n"
        "  recoverage check --min-coverage 50 [dim]# CI gate[/dim]\n\n"
        "  recoverage regen [dim]# re-run catalog + build-db[/dim]\n\n"
        "  recoverage open [dim]# open a running dashboard in a browser[/dim]\n\n"
        "  recoverage config [dim]# show the settings serve would start with[/dim]\n\n"
        "[bold]Prerequisites:[/bold]\n\n"
        "  Run [dim]rebrew catalog && rebrew build-db[/dim] first to create "
        "db/coverage.db.\n\n"
        f"[dim]Reads db/coverage.db (SQLite). Serves SPA at "
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


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Threaded WSGI server for the dashboard.

    wsgiref's stock WSGIServer handles one connection at a time; the SSE
    /api/events stream stays open indefinitely, which would stall every other
    request.  ThreadingMixIn gives each connection its own daemon thread.
    """

    daemon_threads = True


class _ThreadingWSGIServer6(_ThreadingWSGIServer):
    """The same server on an IPv6 socket.

    ``wsgiref``'s ``WSGIServer`` inherits ``http.server.HTTPServer``'s
    ``AF_INET`` and never changes it, so an IPv6 bind address that
    ``config.validate_bind`` deliberately accepts (``::1``, ``::``) dies in
    ``socket.bind()`` with EADDRNOTAVAIL on every platform, and the OSError
    handler below then reports "is another instance already running?" for what
    is an address-family mismatch.  On Linux an ``AF_INET6`` socket bound to
    ``::`` also accepts IPv4-mapped peers, which is the case
    ``server._peer_is_loopback`` documents.
    """

    address_family = socket.AF_INET6


def _server_class_for(bind: str) -> type[_ThreadingWSGIServer]:
    """The threaded server class whose address family *bind* needs.

    Probed through ``getaddrinfo`` rather than sniffed off the spelling, so a
    hostname that resolves to IPv6 only is covered as well as a literal, and a
    name that offers both keeps ``AF_INET`` (the historical default, and the
    one a dual-stack host's own loopback answer points at).  A name that
    resolves to neither keeps ``AF_INET`` and fails in ``bind()`` with the
    resolver's own error, as it always has.
    """
    try:
        infos = socket.getaddrinfo(bind, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return _ThreadingWSGIServer
    families = {info[0] for info in infos}
    if families == {socket.AF_INET6}:
        return _ThreadingWSGIServer6
    return _ThreadingWSGIServer


# Hard deadline for every socket operation on a client connection (the request
# read and each response write).  Without it a half-open TCP peer (crashed
# laptop, dropped NAT mapping) or an SSE client that stops reading pins its
# handler thread forever: ThreadingMixIn caps neither threads nor connections,
# so wedged peers silently accumulate until process exit.  With the deadline,
# socket.timeout unwinds the stalled op and the thread exits, releasing the
# connection and (for /api/events) its bounded SSE slot.  Generous multiples
# of the 15s SSE heartbeat (_SSE_HEARTBEAT_SECONDS) so only a genuinely
# stalled peer can trip it — healthy streams write far more often.
_CLIENT_SOCKET_TIMEOUT_SECONDS = 120

#: How long an idle keep-alive connection waits for its next request before the
#: handler thread gives up and the socket closes.  The per-connection deadline
#: above covers a request in flight; a browser holding a connection open
#: between loads must not pin a thread for that whole deadline, and
#: ThreadingMixIn starts a thread per connection.  15 s is longer than any
#: real page load's asset burst, so a connection survives a slow load and dies
#: soon after the tab goes quiet.
_KEEPALIVE_IDLE_SECONDS = 15

#: Status codes whose response carries no body by definition (RFC 9110 15), so a
#: missing Content-Length on one is correct and the connection stays usable.
#: Strings, because the wire status line is the only place they are read.
_BODYLESS_STATUS_CODES = frozenset(("204", "304"))

#: Headers that frame a body without ending the connection (RFC 9112 6).
_SELF_DELIMITING_HEADERS = frozenset(("content-length", "transfer-encoding"))

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


class _QuietTimeoutRequestHandler(WSGIRequestHandler):
    """wsgiref request handler with the per-connection deadline above.

    Also carries bottle's FixedHandler behavior (peer address without reverse
    DNS; no per-request logging): passing ``handler_class`` to Bottle replaces
    FixedHandler wholesale, so both overrides must be reproduced here.
    ``serve`` always runs with quiet=True.
    """

    timeout = _CLIENT_SOCKET_TIMEOUT_SECONDS

    def address_string(self) -> str:
        return self.client_address[0]

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        pass


class _KeepAliveRequestHandler(_QuietTimeoutRequestHandler):
    """Handler that serves every request on a connection, not just the first.

    wsgiref's stock handler is HTTP/1.0 and its ``handle`` reads one request
    line and returns, so the connection closed after every response: loading
    the dashboard opened a fresh TCP connection for the shell, ``detail.js``,
    ``/api/targets`` and the data payload, and paid a handshake for each.  The
    loop below is stock ``BaseHTTPRequestHandler.handle`` behaviour that
    wsgiref narrowed to a single request; restoring it is what makes
    ``protocol_version = "HTTP/1.1"`` mean anything.

    Two framing rules keep HTTP/1.1 honest:

    * A response that names no length and no transfer encoding (the streamed
      ``/api/events``, whose body ends when the stream does) is sent with
      ``Connection: close``.  Under HTTP/1.1 a client would otherwise read
      until the connection dropped, and every response after it on that
      socket would be misframed.
    * A connection left idle between requests falls back to the short idle
      deadline rather than the full per-request one, so an open browser tab
      does not hold a handler thread for two minutes.
    """

    protocol_version = "HTTP/1.1"

    # wsgiref assigns this in HTTPServer.__init__; the stub types it as the
    # BaseServer base, which has no get_app().
    server: WSGIServer

    def handle(self) -> None:
        self.raw_requestline = self.rfile.readline(65537)
        while self.raw_requestline:
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.parse_request():
                return
            # The request is in flight now, so the full per-connection
            # deadline applies to its reads and writes again.
            self.connection.settimeout(_CLIENT_SOCKET_TIMEOUT_SECONDS)
            self._run_wsgi()
            if self.close_connection:
                return
            self.connection.settimeout(_KEEPALIVE_IDLE_SECONDS)
            self.raw_requestline = self.rfile.readline(65537)

    def _run_wsgi(self) -> None:
        # rfile/wfile/get_stderr are binary streams at runtime, which is what
        # ServerHandler wants; the stubs name their concrete socket classes,
        # which do not spell the wsgiref ErrorStream protocols structurally.
        handler = _KeepAliveServerHandler(
            cast("InputStream", self.rfile),
            cast("IO[bytes]", self.wfile),
            self.get_stderr(),
            self.get_environ(),
            multithread=True,
        )
        handler.request_handler = self  # backpointer for logging
        # WSGIServer.application is optional in the stubs; the instance is
        # built with the app below, so it is never None here.
        handler.run(cast("WSGIApplication", self.server.application))


class _KeepAliveServerHandler(ServerHandler):
    """The HTTP/1.1 half of keep-alive: the status line and the framing rule.

    wsgiref writes the preamble itself (``HTTP/`` + :attr:`http_version`), not
    through the request handler, so announcing 1.1 belongs here.

    A response that carries neither Content-Length nor Transfer-Encoding ends
    only when the connection does (RFC 9112 6.3), which under HTTP/1.1 would
    leave the client reading into whatever the next response put on the
    socket.  The streamed ``/api/events`` is exactly that response, and
    nothing else here is: bottle sets Content-Length for every body it
    returns.  So an unframed response gets ``Connection: close``, which is
    what a client has to do with it either way.
    """

    http_version = "1.1"

    # wsgiref's BaseHandler.run()/parse_request() populate all four; the stubs
    # declare none of them, so the framing checks below would read them as
    # attributes the class does not have.
    request_handler: _KeepAliveRequestHandler
    headers: email.message.Message
    environ: dict[str, str]
    status: str

    def send_headers(self) -> None:
        if not self._response_is_framed():
            self.request_handler.close_connection = True
            self.headers["Connection"] = "close"
        super().send_headers()

    def _response_is_framed(self) -> bool:
        # wsgiref's Headers.__contains__ is case-insensitive; iterating it is not.
        if any(name in self.headers for name in _SELF_DELIMITING_HEADERS):
            return True
        if self.environ.get("REQUEST_METHOD") == "HEAD":
            return True
        return self.status[:3] in _BODYLESS_STATUS_CODES


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version

        typer.echo(f"recoverage {version('recoverage')}")
        raise typer.Exit


@app.callback()
def _app_callback(
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output (overrides NO_COLOR and TERM=dumb).",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
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

# ONE spelling of the operator-facing rebuild advice so it cannot drift
# between the commands that embed it in their database-error messages.
_REBUILD_HINT = "(run 'rebrew catalog && rebrew build-db' to rebuild it)"


def _use_utf8_stdout() -> None:
    """Make stdout encode UTF-8, whatever the environment's locale says.

    `export`, `check` and `stats` write target ids and section names straight
    from the database, and those come out of PE images: any byte is possible.
    stdout carries the locale's codec, so under LC_ALL=C (with locale coercion
    off) or a Windows code page the write raises UnicodeEncodeError part-way
    through the output and leaves a truncated file behind a `>` redirect.
    """
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    if encoding == "utf8":
        return
    # A stream that cannot be reconfigured (an in-memory test double, a pipe
    # wrapper) keeps its own codec; nothing here is worth failing.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is None:
        return
    with contextlib.suppress(ValueError, OSError):
        reconfigure(encoding="utf-8")


def _csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula injection (CWE-1236) in exported cells.

    Target ids and section names originate in analyzed PE binaries, so a
    malicious sample can plant a section named ``=HYPERLINK(...)`` or
    ``@SUM(...)`` that Excel executes when the exported file is opened.
    Prefixing with an apostrophe forces text interpretation (the standard
    OWASP mitigation); numeric and ordinary fields pass through untouched.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _checked_port(value: int) -> int:
    """Return *value* if it is in the port range, else raise config.ConfigError."""
    if not config.MIN_PORT <= value <= config.MAX_PORT:
        raise config.ConfigError(
            f"--port: {value} is not in the range {config.MIN_PORT}-{config.MAX_PORT}"
        )
    return value


class _ServeConfig(NamedTuple):
    """The settings `serve` starts with, after flags and environment merge."""

    port: int
    bind: str
    allow_remote: bool
    cors: bool
    cors_origins: list[str]
    token: str | None
    db: Path | None
    log_level: int


def _resolve_serve_config(
    *,
    port: int | None = None,
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
        resolved = _ServeConfig(
            port=config.port() if port is None else _checked_port(port),
            # validate_bind, not the raw flag: one setting, two sources, and
            # the floor the environment gets is the flag's too.
            bind=config.bind() if bind is None else config.validate_bind(bind, "--bind"),
            allow_remote=config.allow_remote() if allow_remote is None else allow_remote,
            cors=resolved_cors,
            cors_origins=_allowed_origins(
                resolved_cors, config.cors_origins() if cors_origin is None else cors_origin
            ),
            token=(config.token() or None) if token is None else token,
            # Read for validation only; _db_path() resolves the value again.
            db=config.db_override(),
            log_level=(
                config.log_level() if log_level is None else config.parse_log_level(log_level)
            ),
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
        config.db_override()
    except config.ConfigError as exc:
        _secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None


def _open_db_or_exit(
    *, missing_exit_code: int = 1, json_output: bool = False
) -> sqlite3.Connection:
    """Open coverage.db read-only, exiting the process on failure.

    Named apart from ``server._open_db`` (which raises instead of exiting):
    a missing database exits with *missing_exit_code* (``check`` passes 2:
    its documented contract classifies a missing/unreadable database as an
    infrastructure error, distinct from "coverage below threshold" = 1);
    sibling commands keep their historical exit 1.
    """
    from recoverage.server import _open_db

    _check_env_or_exit()
    p = _db_path()
    if not p.exists():
        _fail(
            f"Error: database not found at {p}",
            f"database not found at {p}",
            missing_exit_code,
            json_output,
        )
    try:
        conn = _open_db(p)
    except sqlite3.Error as exc:
        _fail(
            f"Error: cannot open database {p}: {exc} {_REBUILD_HINT}",
            f"cannot open database: {exc}",
            2,
            json_output,
        )
    return conn


def _list_targets(conn: sqlite3.Connection) -> list[str]:
    from recoverage.server import db_target_ids

    return db_target_ids(conn.cursor())


def _select_targets(
    conn: sqlite3.Connection, target: str | None, *, json_output: bool = False
) -> list[str]:
    """Return the targets to operate on, validating a requested --target.

    Named apart from ``server.resolve_targets`` (the webapp's DB+config
    merge): this one only reads the DB and validates a CLI --target choice.
    A requested target that is not in the DB exits 1 with a clear error —
    sibling commands must not silently succeed on a typo'd target.  A DB
    that cannot be queried (schema-less/corrupt) exits 2 with a rebuild hint
    instead of a raw traceback.
    """
    try:
        if target is not None:
            known = _list_targets(conn)
            if target not in known:
                _fail(
                    f"Error: target {target!r} not found in database "
                    f"(have: {', '.join(known) or 'none'}).",
                    f"target not found: {target!r}",
                    1,
                    json_output,
                )
            return [target]
        return _list_targets(conn)
    except sqlite3.Error as exc:
        _fail(
            f"Error: cannot query coverage database: {exc} {_REBUILD_HINT}",
            f"cannot query coverage database: {exc}",
            2,
            json_output,
        )


@contextlib.contextmanager
def _open_targets(
    target: str | None, *, missing_exit_code: int = 1, json_output: bool = False
) -> Iterator[tuple[sqlite3.Connection, list[str]]]:
    """Yield the open database and the targets the command operates on.

    Open, ``--target`` validation and the empty-database exit are one
    contract for every command that reads targets, so they are written once
    here.  *missing_exit_code* is ``check``'s 2 for an unreadable database;
    the siblings keep their historical 1.
    """
    with contextlib.closing(
        _open_db_or_exit(missing_exit_code=missing_exit_code, json_output=json_output)
    ) as conn:
        targets = _select_targets(conn, target, json_output=json_output)
        if not targets:
            _fail(
                "No targets found in database.",
                "no targets in database",
                1,
                json_output,
                fg=typer.colors.YELLOW,
            )
        yield conn, targets


def _get_stats(
    conn: sqlite3.Connection, target: str, *, json_output: bool = False
) -> dict[str, Any]:
    c = conn.cursor()
    from recoverage.server import _section_stats

    try:
        return {"target": target, **_section_stats(c, target)}
    except sqlite3.Error as exc:
        # A DB that lists targets but cannot answer the stats queries
        # (schema-less / partially rebuilt) must not surface as a traceback —
        # same clean-exit contract as _select_targets.
        _fail(
            f"Error: cannot read coverage statistics for target {target!r}: {exc} {_REBUILD_HINT}",
            f"cannot read coverage statistics for target {target!r}: {exc}",
            2,
            json_output,
        )


def _run_regen(root: Path) -> None:
    """Regenerate coverage.db by calling rebrew's catalog + build-db in-process."""
    from recoverage.regen import run_regen

    typer.echo("Running rebrew catalog + build-db...")
    try:
        run_regen(root)
    except typer.Exit:
        # rebrew's error_exit reports the failure itself and raises
        # typer.Exit — click's Exit, a RuntimeError, not SystemExit — which
        # would otherwise escape as a raw traceback.  Keep the exit-1 contract.
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
_BROWSER_OPEN_TIMEOUT = 10


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
    return subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]


def _kill_and_reap(proc: subprocess.Popen[bytes]) -> None:
    """Kill *proc* — on POSIX its whole session — and always reap it.

    Every opener gets its own session (start_new_session), so a terminal
    signal never reaches it: the abandonment paths must signal the process
    GROUP, not just the direct child, or an xdg-open wrapper's grandchild
    survives.  The trailing wait() reaps the child either way (setsid does
    not prevent zombies; only a wait does).  Windows has no process-group
    signal, so there only the direct child is terminated.
    """
    if os.name == "posix":
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
    else:
        proc.kill()
    proc.wait()


def _open_and_reap(url: str, args: list[str], shell: bool = False) -> None:
    """Launch the opener for *url* fire-and-forget and still reap it.

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
            # Windows 'start' needs cmd.exe; args are internally generated
            shell=shell,
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
        return
    try:
        proc.wait(timeout=_BROWSER_OPEN_TIMEOUT)
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


def open_browser(url: str) -> None:
    system = platform.system()
    if system == "Linux":
        _open_and_reap(url, ["xdg-open", url])
    elif system == "Darwin":
        _open_and_reap(url, ["open", url])
    elif system == "Windows":
        _open_and_reap(url, ["cmd", "/c", "start", "", url])
    else:
        webbrowser.open(url)


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
        normalized = _normalize_origin(origin_url)
        if not normalized:
            raise config.ConfigError(
                f"origin {origin_url!r} is not a URL the browser could send: "
                "expected scheme://host[:port], with no userinfo, path or whitespace"
            )
        allowed.append(normalized)
    return allowed


@app.command()
def serve(
    # Every option defaults to None so "not passed on the command line" stays
    # distinguishable from a passed value, and the RECOVERAGE_* environment
    # supplies the default for it.  A flag always wins over the environment.
    # (min/max moved into the config module: the range check has to run for
    # an env-provided port too, or an out-of-range value reaches socket.bind()
    # and surfaces as a raw OverflowError after the banner has printed.)
    port: int | None = typer.Option(
        None,
        "--port",
        "-p",
        help=f"Port to serve on, 0-65535 (default: {config.DEFAULT_PORT}; env: RECOVERAGE_PORT)",
    ),
    bind: str | None = typer.Option(
        None,
        "--bind",
        help=f"Interface to bind to (default: {config.DEFAULT_BIND}; use 0.0.0.0 for LAN; "
        "env: RECOVERAGE_BIND)",
    ),
    allow_remote: bool | None = typer.Option(
        None,
        "--allow-remote",
        help="Required with --bind 0.0.0.0: acknowledge that the unauthenticated "
        "API (including raw binary bytes) is exposed on the network "
        "(env: RECOVERAGE_ALLOW_REMOTE)",
    ),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open browser automatically"),
    regen: bool = typer.Option(False, "--regen", help="Regenerate DB before starting"),
    cors: bool | None = typer.Option(
        None,
        "--cors",
        help="Enable CORS processing (allowlisted origins only; env: RECOVERAGE_CORS)",
    ),
    cors_origin: list[str] | None = typer.Option(
        None,
        "--cors-origin",
        help="Origin URL allowed to read the API cross-origin (repeatable, "
        "e.g. http://localhost:5173; env: RECOVERAGE_CORS_ORIGIN, comma-separated)",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Require this bearer token for every request (Authorization: Bearer <token>, "
        "?token=, or open the dashboard as /?token=<token> (or /potato?token=<token>) "
        "to set the browser cookie; env: RECOVERAGE_TOKEN, which keeps the token out "
        "of the process listing)",
    ),
    log_level: str | None = typer.Option(
        None,
        "--log-level",
        help=f"Log threshold (default: {logging.getLevelName(config.DEFAULT_LOG_LEVEL)}; any name "
        "or number logging knows, e.g. DEBUG, INFO, WARN, WARNING, ERROR, CRITICAL; "
        "env: RECOVERAGE_LOG_LEVEL)",
    ),
) -> None:
    """Start the recoverage dashboard server.

    Every setting flag also reads a RECOVERAGE_* environment variable, used as
    its default: RECOVERAGE_PORT, RECOVERAGE_BIND, RECOVERAGE_ALLOW_REMOTE,
    RECOVERAGE_CORS, RECOVERAGE_CORS_ORIGIN, RECOVERAGE_TOKEN,
    RECOVERAGE_LOG_LEVEL and RECOVERAGE_DB (an explicit coverage.db path,
    instead of resolving rebrew-project.toml from the working directory).
    [bold]--no-open[/bold] and [bold]--regen[/bold] are the two flags with no
    variable, because a service that wants the browser or a rebuild asks for
    it in argv, not in the environment.

    A flag always wins over the environment; an unrecognised RECOVERAGE_*
    name is a startup error, and so is a value that is not a valid port,
    boolean, log level, non-empty string, or a CORS origin a browser could
    send.
    """
    import recoverage.server as _server
    from recoverage.server import (
        LOOPBACK_HOSTS,
        _assets_dir,
        _project_dir,
    )
    from recoverage.webapp import app as bottle_app

    resolved = _resolve_serve_config(
        port=port,
        bind=bind,
        allow_remote=allow_remote,
        cors=cors,
        cors_origin=cors_origin,
        token=token,
        log_level=log_level,
    )
    port = resolved.port
    bind = resolved.bind
    allow_remote = resolved.allow_remote
    cors = resolved.cors
    cors_origin = list(resolved.cors_origins)
    token = resolved.token

    # NOTE: "::" is the IPv6 wildcard (binds every interface) — it must NOT
    # be treated as loopback, or --bind :: would silently expose the
    # unauthenticated API without the --allow-remote acknowledgment.
    is_remote = bind not in LOOPBACK_HOSTS
    if is_remote and not allow_remote:
        _secho(
            f"--bind {bind} exposes the unauthenticated recoverage API (including raw "
            "binary bytes and disassembly) to every reachable host on the network. "
            "Pass --allow-remote to confirm you want this.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    if is_remote:
        _secho(
            "warning: serving unauthenticated binary data on the network — "
            "restrict access at the firewall.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if cors and not cors_origin:
        # Every warning in this block goes to stderr, so a deployment that
        # captures stdout for the banner (tools/smoke.py, the harness) still
        # sees the half of the configuration that will not work.
        _secho(
            "warning: --cors without --cors-origin allows no cross-origin reads "
            "(Access-Control-Allow-Origin: * is no longer emitted). "
            "Add --cors-origin URL for each origin you want to allow.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if cors_origin and not cors:
        # cors_origin alone has no effect (CORS processing stays off): a
        # user who passed it must not discover that from silent behavior.
        _secho(
            "warning: --cors-origin has no effect without --cors — "
            "CORS processing is disabled. Pass --cors to enable it.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    # IPv6 hosts need brackets in any URL spelling (::1 bare is parsed as
    # host "" port ::8001).
    display_host = f"[{bind}]" if ":" in bind else bind

    # Configure logging at the resolved level, so a service can turn the
    # per-request chatter down (WARNING) or the detail up (DEBUG) without a
    # code change; the level it runs at is reported in the banner below.
    # The request id is the pivot between a log line and the client that
    # reported it: it is echoed on the X-Request-ID response header, and
    # carried into the traceback line of a failed request.  `defaults` fills
    # it in for records from loggers the app does not own (bottle, rebrew).
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
        logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT, defaults={"request_id": "-"})
    )
    logging.basicConfig(handlers=[handler], level=resolved.log_level)

    allowed_origins = cors_origin
    if token:
        _secho(
            f"token auth enabled — requests need Authorization: Bearer <token> "
            f"(SPA: open as http://{display_host}:{port}/?token=<token>)",
            fg=typer.colors.GREEN,
        )
    # Loopback binds validate the Host header (DNS-rebinding guard); remote
    # binds (user opted in via --allow-remote) skip validation.
    _server.configure_security(
        cors_enabled=cors,
        cors_allowed_origins=allowed_origins,
        auth_token=token or "",
        allowed_hosts=None if is_remote else set(LOOPBACK_HOSTS),
    )

    root = _project_dir()
    assets = _assets_dir()
    listen_url = f"http://{display_host}:{port}"
    # The browser opens against the bound loopback interface: --bind ::1
    # listens on IPv6 loopback only, so the hard-coded http://127.0.0.1 (IPv4)
    # would open a tab that refuses to connect.  Remote binds keep 127.0.0.1 —
    # a wildcard/external address also answers on IPv4 loopback.
    url = listen_url if not is_remote else f"http://127.0.0.1:{port}"

    if regen:
        _run_regen(root)

    _log.info("Starting recoverage server on %s (port=%d, cors=%s)", listen_url, port, cors)

    typer.echo(f"Serving coverage dashboard at {url}")
    typer.echo(f"  Listening on: {listen_url}")
    typer.echo(f"  Assets: {assets}")
    typer.echo(f"  DB: {_db_path()}")
    # The full active configuration, resolved from flags and the environment,
    # so an operator can confirm what the process is actually running with.
    # The token is reported as set/unset, never by value.
    typer.echo(
        "  Config: "
        + " ".join(
            f"{key}={value}"
            for key, value in config.active_config(
                port=port,
                bind=bind,
                allow_remote=allow_remote,
                cors=cors,
                cors_origin=allowed_origins,
                token=token,
                db=resolved.db,
                log_level=resolved.log_level,
            ).items()
        )
    )
    if cors:
        typer.echo("  CORS: enabled")
    typer.echo("  Regen: POST /api/regen or click Reload in UI")
    typer.echo("  Stop: Ctrl+C")

    browser_timer: threading.Timer | None = None
    if not no_open:
        # Daemon + kept reference: a hung opener must never delay interpreter
        # exit, and the bind-failure path below cancels the timer so a failed
        # start does not pop a browser tab pointing at a dead port.
        browser_timer = threading.Timer(0.5, open_browser, args=(url,))
        browser_timer.daemon = True
        browser_timer.start()

    # Start the DB watcher at startup (not on first /api/events connection):
    # without it, external rebuilds leave the target/dropdown caches stale
    # for servers that never receive an SSE client (curl-only automation).
    from recoverage.api import _ensure_db_watcher

    _ensure_db_watcher()

    # Warm the SPA shell cache off the request path: the first page load
    # would otherwise pay the asset read + minify + three full-strength
    # compressions synchronously under INDEX_LOCK.  Daemon thread, started
    # before the listener accepts; failures are logged and stay lazy.
    from recoverage.ui import warm_index_cache

    threading.Thread(target=warm_index_cache, name="recoverage-index-warmup", daemon=True).start()

    try:
        bottle_app.run(
            host=bind,
            port=port,
            quiet=True,
            server="wsgiref",
            server_class=_server_class_for(bind),
            handler_class=_KeepAliveRequestHandler,
        )
    except KeyboardInterrupt:
        # Ctrl+C is the documented way to stop the dashboard; wsgiref's
        # accept loop unwinds with KeyboardInterrupt — exit quietly instead
        # of dumping a traceback.  Cancel the deferred browser opener like
        # the bind-failure path: a Ctrl+C inside the 0.5s scheduling window
        # is also a failed start and must not pop a tab at a dead port.
        if browser_timer is not None:
            browser_timer.cancel()
    except OSError as e:
        # EADDRINUSE is the most common failure for a dashboard tool — a
        # second instance or another dev server on the same port.
        if browser_timer is not None:
            browser_timer.cancel()
        _secho(
            f"Failed to start server on {listen_url}: {e.strerror or e} "
            "(is another instance already running?)",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1) from None


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


@app.command()
def stats(
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Print coverage stats as a table (or JSON with --json)."""
    _use_utf8_stdout()

    from rich.console import Console
    from rich.table import Table

    with _open_targets(target, json_output=json_output) as (conn, targets):
        if json_output:
            typer.echo(
                json.dumps([_get_stats(conn, tid, json_output=True) for tid in targets], indent=2)
            )
            return

        # Rich detects NO_COLOR and TERM=dumb on its own, but not the
        # --no-color flag (a process-wide setting it cannot see), so the
        # resolved opt-out is passed through: a table is the widest colored
        # surface the CLI has, and it must honor the same three opt-outs
        # every _secho caller does.
        console = Console(no_color=True if _color_off() else None)
        for index, tid in enumerate(targets):
            data = _get_stats(conn, tid)
            # Blank line between targets, never before the first one: the
            # same rule `export --format md` follows, so redirected output
            # does not start with an empty line.
            if index:
                console.print()
            console.print(f"[bold cyan]{tid}[/bold cyan]")

            if data["summary"]:
                s = data["summary"]
                total_fn = s.get("totalFunctions", 0)
                matched_fn = s.get("matchedFunctions", 0)
                pct = round(matched_fn / total_fn * 100, 1) if total_fn else 0
                console.print(f"  Functions: {matched_fn}/{total_fn} matched ({pct}%)")

            table = Table(show_header=True, header_style="bold")
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
                    sec_name,
                    f"{size:,} B",
                    str(cells),
                    str(exact),
                    str(reloc),
                    str(near_match),
                    str(stub),
                    f"{coverage_pct:.1f}%",
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
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
) -> None:
    """Export coverage data to stdout.

    JSON verbatim. CSV cells that start with a spreadsheet formula or control
    character are prefixed with an apostrophe, and rows end with a single
    newline so Windows stdout does not double it. Markdown cells escape pipes
    and newlines.
    """
    _use_utf8_stdout()
    json_output = output_format is ExportFormat.json
    with _open_targets(target, json_output=json_output) as (conn, targets):
        all_data = [_get_stats(conn, tid, json_output=json_output) for tid in targets]

    if output_format == ExportFormat.json:
        typer.echo(json.dumps(all_data, indent=2))

    elif output_format == ExportFormat.csv:
        import csv

        # lineterminator="\n": the default "\r\n" would be translated again by
        # Windows' text-mode stdout, corrupting every row to \r\r\n.  One \n
        # here means the platform writes its native ending exactly once.
        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(["target", "section", *_SECTION_COLUMNS])
        for data in all_data:
            for sec_name, sec in sorted(data["sections"].items()):
                writer.writerow(
                    [_csv_safe(data["target"]), _csv_safe(sec_name), *_section_row(sec)]
                )

    elif output_format == ExportFormat.md:

        def _md_safe(s: str) -> str:
            return s.replace("|", "\\|").replace("\n", " ").replace("\r", "")

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
                    f" | {stub} | {coverage_pct:.1f}% |"
                )


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
    99.9997% (stored as 100.0) pass a --min-coverage 100 gate.  Display and
    the JSON payload stay at 2dp so a verdict never quotes numbers that
    disagree with what /stats serves.

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
    # Compare the unrounded ratio, print it rounded to 2dp (see docstring).
    if pct < min_coverage:
        return (
            "FAIL",
            {"coverage_pct": round(pct, 2)},
            f"coverage {pct:.2f}% < {min_coverage:.2f}%",
        )
    return (
        "PASS",
        {"coverage_pct": round(pct, 2)},
        f"coverage {pct:.2f}% >= {min_coverage:.2f}%",
    )


@app.command()
def check(
    min_coverage: float = typer.Option(
        ..., "--min-coverage", "-m", help="Minimum coverage percentage (0-100)"
    ),
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
    section: str | None = typer.Option(None, "--section", "-s", help="Section name (default: all)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check coverage against a threshold (CI gate).

    Exits 0 when every compared section meets the threshold, 1 when one does
    not, and 2 for a bad --min-coverage or an unreadable database.  A section
    the grid never records matches for is reported SKIP, unless --section
    named it, which FAILs.
    """
    _use_utf8_stdout()
    if not 0.0 <= min_coverage <= 100.0:
        # A flag value outside its own documented range is a usage error, the
        # same exit 2 a non-numeric value gets from the parser.
        _fail(
            f"Error: --min-coverage must be between 0 and 100, got {min_coverage!r}.",
            "--min-coverage must be between 0 and 100",
            2,
            json_output,
        )

    with _open_targets(target, missing_exit_code=2, json_output=json_output) as (conn, targets):
        failed = False
        checked = 0
        compared = 0  # sections actually evaluated against the threshold
        verdicts: list[dict[str, Any]] = []  # captured for --json output
        for tid in targets:
            data = _get_stats(conn, tid, json_output=json_output)
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
                status, extra, human = _section_verdict(pct, untracked, bool(section), min_coverage)
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
                    "min_coverage": min_coverage,
                    "results": verdicts,
                },
                indent=2,
            )
        )
    if failed:
        raise typer.Exit(1)


@app.command()
def regen() -> None:
    """Re-run rebrew catalog + build-db to regenerate coverage.db."""
    from recoverage.server import _project_dir

    _check_env_or_exit()
    _run_regen(_project_dir())
    _secho("Done — coverage.db regenerated.", fg=typer.colors.GREEN)


@app.command("open")
def open_cmd(
    port: int | None = typer.Option(
        None,
        "--port",
        "-p",
        help=f"Port of the running server (default: {config.DEFAULT_PORT}; env: RECOVERAGE_PORT)",
    ),
) -> None:
    """Open the dashboard in a browser.

    The port falls back to RECOVERAGE_PORT, the same default [bold]serve[/bold]
    uses, so a deployment that moved the server off 8001 does not need every
    operator to remember the new port as well.
    """
    _check_env_or_exit()
    try:
        resolved_port = config.port() if port is None else _checked_port(port)
    except config.ConfigError as exc:
        _secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    url = f"http://127.0.0.1:{resolved_port}"
    typer.echo(f"Opening {url}")
    open_browser(url)


@app.command("config")
def config_cmd(
    as_json: bool = typer.Option(
        False, "--json", help="Emit the resolved settings as a JSON object"
    ),
) -> None:
    """Print the configuration `serve` would start with, without binding a port.

    The values come from the same merge and validation `serve` runs, so a
    deployment can confirm its environment before the listener opens.  The
    token is reported as `set` or `unset`; its value is never printed.
    """
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
    )
    if as_json:
        typer.echo(json.dumps(settings, indent=2))
        return
    for key, value in settings.items():
        typer.echo(f"{key}={value}")


def main() -> None:
    try:
        app()
    except BrokenPipeError:
        # Downstream closed the pipe early (e.g. `recoverage export | head`):
        # the interpreter flushes stdout at exit and would print a spurious
        # "Exception ignored" traceback.  Point stdout's fd at devnull so the
        # final flush succeeds (no-op when stdout has no real fd), then report
        # the truncation with a non-zero status.
        with contextlib.suppress(OSError, ValueError):
            fd = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(fd, sys.stdout.fileno())
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd)
        raise SystemExit(1) from None
