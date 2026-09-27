"""Typer CLI for recoverage — coverage dashboard for binary-matching projects."""

from __future__ import annotations

import contextlib
import enum
import json
import logging
import os
import platform
import signal
import sqlite3
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, NamedTuple, NoReturn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

import typer

from recoverage import config
from recoverage._paths import _db_path

app = typer.Typer(
    help="Coverage dashboard for binary-matching decompilation projects.",
    add_completion=False,
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
# color=True would make click keep the codes even when stdout is a pipe.
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
_VERDICT_COLORS: dict[str, int] = {
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
    with contextlib.suppress(AttributeError, ValueError, OSError):
        sys.stdout.reconfigure(encoding="utf-8")


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
    """Return *value* if it can be bound, else raise config.ConfigError."""
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
    reaching socket.bind() or the auth layer.
    """
    try:
        config.check_unknown_vars()
        resolved = _ServeConfig(
            port=config.port() if port is None else _checked_port(port),
            bind=config.bind() if bind is None else bind,
            allow_remote=config.allow_remote() if allow_remote is None else allow_remote,
            cors=config.cors() if cors is None else cors,
            cors_origins=list(cors_origin) if cors_origin is not None else config.cors_origins(),
            token=(config.token() or None) if token is None else token,
            # Read for validation only; _db_path() resolves the value again.
            db=config.db_override(),
            log_level=(
                config.log_level() if log_level is None else config.parse_log_level(log_level)
            ),
        )
    except config.ConfigError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    return resolved


def _open_db_or_exit(*, missing_exit_code: int = 1) -> sqlite3.Connection:
    """Open coverage.db read-only, exiting the process on failure.

    Named apart from ``server._open_db`` (which raises instead of exiting):
    a missing database exits with *missing_exit_code* (``check`` passes 2:
    its documented contract classifies a missing/unreadable database as an
    infrastructure error, distinct from "coverage below threshold" = 1);
    sibling commands keep their historical exit 1.
    """
    from recoverage.server import _open_db

    p = _db_path()
    if not p.exists():
        _secho(f"Error: database not found at {p}", fg=typer.colors.RED, err=True)
        raise typer.Exit(missing_exit_code)
    try:
        conn = _open_db(p)
    except sqlite3.Error as exc:
        _secho(
            f"Error: cannot open database {p}: {exc} {_REBUILD_HINT}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2) from exc
    return conn


def _list_targets(conn: sqlite3.Connection) -> list[str]:
    from recoverage.server import db_target_ids

    return db_target_ids(conn.cursor())


def _select_targets(conn: sqlite3.Connection, target: str | None) -> list[str]:
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
                _secho(
                    f"Error: target {target!r} not found in database "
                    f"(have: {', '.join(known) or 'none'}).",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(1)
            return [target]
        return _list_targets(conn)
    except sqlite3.Error as exc:
        _secho(
            f"Error: cannot query coverage database: {exc} {_REBUILD_HINT}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2) from exc


def _get_stats(conn: sqlite3.Connection, target: str) -> dict[str, Any]:
    c = conn.cursor()
    from recoverage.server import _section_stats

    try:
        return {"target": target, **_section_stats(c, target)}
    except sqlite3.Error as exc:
        # A DB that lists targets but cannot answer the stats queries
        # (schema-less / partially rebuilt) must not surface as a traceback —
        # same clean-exit contract as _select_targets.
        _secho(
            f"Error: cannot read coverage statistics for target {target!r}: {exc} {_REBUILD_HINT}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2) from exc


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
    return subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS


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
        help="Port to serve on, 0-65535 (default: 8001; env: RECOVERAGE_PORT)",
    ),
    bind: str | None = typer.Option(
        None,
        "--bind",
        help="Interface to bind to (default: 127.0.0.1; use 0.0.0.0 for LAN; env: RECOVERAGE_BIND)",
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
        "?token=, or open the dashboard as /?token=<token> to set the SPA cookie; "
        "env: RECOVERAGE_TOKEN, which keeps the token out of the process listing)",
    ),
    log_level: str | None = typer.Option(
        None,
        "--log-level",
        help="Log threshold (default: INFO; DEBUG, INFO, WARNING, ERROR, CRITICAL; "
        "env: RECOVERAGE_LOG_LEVEL)",
    ),
) -> None:
    """Start the recoverage dashboard server.

    Every setting flag also reads a RECOVERAGE_* environment variable, used as
    its default: RECOVERAGE_PORT, RECOVERAGE_BIND, RECOVERAGE_ALLOW_REMOTE,
    RECOVERAGE_CORS, RECOVERAGE_CORS_ORIGIN, RECOVERAGE_TOKEN,
    RECOVERAGE_LOG_LEVEL and
    RECOVERAGE_DB (an explicit coverage.db path, instead of resolving
    rebrew-project.toml from the working directory).  ``--no-open`` and
    ``--regen`` are the two flags with no variable, because a service that
    wants the browser or a rebuild asks for it in argv, not in the
    environment.  A flag always wins over
    the environment; an unrecognised RECOVERAGE_* name is a startup error, and
    so is a value that is not a valid port, boolean, log level or non-empty
    string.
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
        )
    if cors and not cors_origin:
        _secho(
            "warning: --cors without --cors-origin allows no cross-origin reads "
            "(Access-Control-Allow-Origin: * is no longer emitted). "
            "Add --cors-origin URL for each origin you want to allow.",
            fg=typer.colors.YELLOW,
        )
    # IPv6 hosts need brackets in any URL spelling (::1 bare is parsed as
    # host "" port ::8001).
    display_host = f"[{bind}]" if ":" in bind else bind
    if cors_origin and not cors:
        # cors_origin alone has no effect (CORS processing stays off): a
        # user who passed it must not discover that from silent behavior.
        _secho(
            "warning: --cors-origin has no effect without --cors — "
            "CORS processing is disabled. Pass --cors to enable it.",
            fg=typer.colors.YELLOW,
        )

    # Configure logging at the resolved level, so a service can turn the
    # per-request chatter down (WARNING) or the detail up (DEBUG) without a
    # code change; the level it runs at is reported in the banner below.
    # The request id is the pivot between a log line and the client that
    # reported it: it is echoed on the X-Request-ID response header, and
    # carried into the traceback line of a failed request.  `defaults` fills
    # it in for records from loggers the app does not own (bottle, rebrew).
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] [rid=%(request_id)s] %(message)s",
            datefmt="%H:%M:%S",
            defaults={"request_id": "-"},
        )
    )
    logging.basicConfig(handlers=[handler], level=resolved.log_level)

    allowed_origins: list[str] = []
    if cors:
        # An origin that fails to normalize must be dropped loudly: a stored
        # "" would match every unparsable request Origin and echo it back as
        # Access-Control-Allow-Origin.
        for origin_url in cors_origin or ():
            normalized = _server._normalize_origin(origin_url)
            if normalized:
                allowed_origins.append(normalized)
            else:
                _secho(
                    f"warning: ignoring unparseable --cors-origin {origin_url!r}",
                    fg=typer.colors.YELLOW,
                )
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
            server_class=_ThreadingWSGIServer,
            handler_class=_QuietTimeoutRequestHandler,
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

    with contextlib.closing(_open_db_or_exit()) as conn:
        targets = _select_targets(conn, target)

        if not targets:
            _secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(1)

        if json_output:
            typer.echo(json.dumps([_get_stats(conn, tid) for tid in targets], indent=2))
            return

        console = Console()
        for tid in targets:
            data = _get_stats(conn, tid)
            console.print(f"\n[bold cyan]{tid}[/bold cyan]")

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
    with contextlib.closing(_open_db_or_exit()) as conn:
        targets = _select_targets(conn, target)

        if not targets:
            _secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(1)

        all_data = [_get_stats(conn, tid) for tid in targets]

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


def _gate_error(
    human: str,
    payload: dict[str, Any],
    json_output: bool,
    fg: int = typer.colors.RED,
    exit_code: int = 1,
) -> NoReturn:
    """Emit a check-gate failure in --json or human form, then exit.

    ONE tail for every `check` failure so the two output modes cannot drift
    (each mode's message/payload stays at its single call site).  *exit_code*
    separates a gate failure (1) from a usage error (2), so a script can tell
    "the build is below threshold" from "I passed a bad flag".
    """
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        _secho(human, fg=fg, err=True)
    raise typer.Exit(exit_code)


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
    not, and 2 for a bad --min-coverage or an unreadable database.  Sections
    the grid never records matches for are reported SKIP, not FAIL.
    """
    _use_utf8_stdout()
    if not 0.0 <= min_coverage <= 100.0:
        # A flag value outside its own documented range is a usage error, the
        # same exit 2 a non-numeric value gets from the parser.
        _gate_error(
            f"Error: --min-coverage must be between 0 and 100, got {min_coverage!r}.",
            {"error": "--min-coverage must be between 0 and 100", "exit_code": 2},
            json_output,
            exit_code=2,
        )

    with contextlib.closing(_open_db_or_exit(missing_exit_code=2)) as conn:
        targets = _select_targets(conn, target)

        if not targets:
            _gate_error(
                "No targets found in database.",
                {"error": "no targets in database", "exit_code": 1},
                json_output,
                fg=typer.colors.YELLOW,
            )

        failed = False
        checked = 0
        compared = 0  # sections actually evaluated against the threshold
        verdicts: list[dict[str, Any]] = []  # captured for --json output
        for tid in targets:
            data = _get_stats(conn, tid)
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
        _gate_error(
            "Error: no sections matched — nothing was checked.",
            {"error": "no sections matched — nothing was checked", "exit_code": 1},
            json_output,
        )
    if compared == 0 and not failed:
        # Every section was skipped as untracked and nothing failed — a
        # project with no recorded coverage must not pass vacuously.  An
        # explicit --section on an untracked section already produced a FAIL
        # verdict above; that verdict (and the JSON results array) must reach
        # the caller instead of being replaced by this generic error.
        _gate_error(
            "Error: no tracked sections — nothing was checked.",
            {"error": "no tracked sections — nothing was checked", "exit_code": 1},
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

    _run_regen(_project_dir())
    _secho("Done — coverage.db regenerated.", fg=typer.colors.GREEN)


@app.command("open")
def open_cmd(
    port: int | None = typer.Option(
        None,
        "--port",
        "-p",
        help="Port of the running server (default: 8001; env: RECOVERAGE_PORT)",
    ),
) -> None:
    """Open the dashboard in a browser.

    The port falls back to RECOVERAGE_PORT, the same default `serve` uses, so
    a deployment that moved the server off 8001 does not need every operator
    to remember the new port as well.
    """
    try:
        resolved_port = config.port() if port is None else _checked_port(port)
    except config.ConfigError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    url = f"http://127.0.0.1:{resolved_port}"
    typer.echo(f"Opening {url}")
    open_browser(url)


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
