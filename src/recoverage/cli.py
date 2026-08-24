"""Typer CLI for recoverage — coverage dashboard for binary-matching projects."""

from __future__ import annotations

import contextlib
import enum
import json
import logging
import os
import platform
import sqlite3
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, NoReturn
from wsgiref.simple_server import WSGIServer

import typer

from recoverage._paths import _db_path, sqlite_ro_uri

app = typer.Typer(
    help="Coverage dashboard for binary-matching decompilation projects.",
    add_completion=False,
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  recoverage serve [dim]— start the dashboard (port 8001)[/dim]\n\n"
        "  recoverage serve --port 3000 [dim]— custom port[/dim]\n\n"
        "  recoverage stats [dim]— print coverage statistics[/dim]\n\n"
        "  recoverage export --format csv [dim]— export as CSV[/dim]\n\n"
        "  recoverage check --min-coverage 50 [dim]— CI gate[/dim]\n\n"
        "  recoverage regen [dim]— re-run catalog + build-db[/dim]\n\n"
        "[bold]Prerequisites:[/bold]\n\n"
        "  Run [dim]rebrew catalog --json && rebrew build-db[/dim] first to create "
        "db/coverage.db.\n\n"
        "[dim]Reads db/coverage.db (SQLite). Serves SPA at http://localhost:8001.[/dim]"
    ),
)

_log = logging.getLogger("recoverage")


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Threaded WSGI server for the dashboard.

    wsgiref's stock WSGIServer handles one connection at a time; the SSE
    /api/events stream stays open indefinitely, which would stall every other
    request.  ThreadingMixIn gives each connection its own daemon thread.
    """

    daemon_threads = True


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version

        typer.echo(f"recoverage {version('recoverage')}")
        raise typer.Exit


@app.callback()
def _app_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


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
_REBUILD_HINT = "(run 'rebrew catalog --json && rebrew build-db' to rebuild it)"


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


def _open_db_or_exit(*, missing_exit_code: int = 1) -> sqlite3.Connection:
    """Open coverage.db read-only, exiting the process on failure.

    Named apart from ``server._open_db`` (which raises instead of exiting):
    a missing database exits with *missing_exit_code* (``check`` passes 2:
    its documented contract classifies a missing/unreadable database as an
    infrastructure error, distinct from "coverage below threshold" = 1);
    sibling commands keep their historical exit 1.
    """
    p = _db_path()
    if not p.exists():
        typer.secho(f"Error: database not found at {p}", fg=typer.colors.RED, err=True)
        raise typer.Exit(missing_exit_code)
    try:
        conn = sqlite3.connect(sqlite_ro_uri(p), uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        typer.secho(
            f"Error: cannot open database {p}: {exc} {_REBUILD_HINT}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2) from exc
    return conn


def _list_targets(conn: sqlite3.Connection) -> list[str]:
    c = conn.cursor()
    from recoverage.server import SCHEMA_TARGET

    c.execute(
        "SELECT DISTINCT target FROM metadata WHERE target != ? ORDER BY target",
        (SCHEMA_TARGET,),
    )
    return [row[0] for row in c.fetchall()]


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
                typer.secho(
                    f"Error: target {target!r} not found in database "
                    f"(have: {', '.join(known) or 'none'}).",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(1)
            return [target]
        return _list_targets(conn)
    except sqlite3.Error as exc:
        typer.secho(
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
        typer.secho(
            f"Error: cannot read coverage statistics for target {target!r}: {exc} {_REBUILD_HINT}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2) from exc


def _run_regen(root: Path) -> None:
    """Run rebrew catalog + build-db to regenerate coverage.db."""
    from recoverage.regen import REGEN_TIMEOUT, run_regen_step

    for step in ("catalog", "build-db"):
        typer.echo(f"Running rebrew {step}...")
        try:
            run_regen_step(step, root)
        except FileNotFoundError:
            typer.secho("Error: 'uv' not found — is it installed?", fg=typer.colors.RED, err=True)
            raise typer.Exit(1) from None
        except OSError as e:
            # uv exists but cannot be launched (not executable, ENOEXEC, a
            # PATH entry that is a plain file): same clean-exit contract as
            # the API's regen endpoint instead of a raw traceback.
            typer.secho(
                f"Error: could not run 'uv' for 'rebrew {step}': {type(e).__name__}: {e}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1) from None
        except subprocess.CalledProcessError as e:
            typer.secho(
                f"Error: 'rebrew {step}' failed (exit code {e.returncode})",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1) from None
        except subprocess.TimeoutExpired:
            typer.secho(
                f"Error: 'rebrew {step}' timed out after {REGEN_TIMEOUT}s",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1) from None


# ── Browser opener ─────────────────────────────────────────────────

# Openers exit in well under a second; the bound only guards a wedged one.
_BROWSER_OPEN_TIMEOUT = 10


def _open_and_reap(url: str, args: list[str], shell: bool = False) -> None:
    """Launch the opener for *url* fire-and-forget and still reap it.

    Detaching (setsid/shell) does NOT keep a child from becoming a zombie —
    only a wait() does, and nothing else ever waits on these openers.  The
    wait is bounded so a hung opener cannot stall serve startup; past the
    deadline it is killed and reaped.
    """
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # Windows 'start' needs cmd.exe; args are internally generated
            shell=shell,
            start_new_session=(os.name == "posix"),
        )
        proc.wait(timeout=_BROWSER_OPEN_TIMEOUT)
    except subprocess.TimeoutExpired:
        # Group kill, not just the direct opener: xdg-open wrappers can spawn
        # a grandchild that would otherwise survive the deadline.
        from recoverage.regen import _kill_and_reap

        _kill_and_reap(proc)
    except (OSError, subprocess.SubprocessError) as exc:
        # Expected on minimal installs (no xdg-open/open); say why before
        # falling back — "no browser ever appeared" must be diagnosable from
        # the log alone instead of failing silently.
        _log.warning(
            "Browser opener %s failed (%s: %s) — falling back to webbrowser",
            args[0],
            type(exc).__name__,
            exc,
        )
        if not webbrowser.open(url):
            _log.warning("webbrowser.open(%s): no usable browser found", url)


def open_browser(url: str) -> None:
    system = platform.system()
    if system == "Linux":
        _open_and_reap(url, ["xdg-open", url])
    elif system == "Darwin":
        _open_and_reap(url, ["open", url])
    elif system == "Windows":
        _open_and_reap(url, ["start", url], shell=True)
    else:
        webbrowser.open(url)


# ── Commands ───────────────────────────────────────────────────────


@app.command()
def serve(
    # min/max keep an out-of-range --port from reaching socket.bind(), which
    # would otherwise surface as a raw OverflowError traceback after the
    # startup banner has already printed.
    port: int = typer.Option(8001, "--port", "-p", min=0, max=65535, help="Port to serve on"),
    bind: str = typer.Option(
        "127.0.0.1", "--bind", help="Interface to bind to (default: 127.0.0.1; use 0.0.0.0 for LAN)"
    ),
    allow_remote: bool = typer.Option(
        False,
        "--allow-remote",
        help="Required with --bind 0.0.0.0: acknowledge that the unauthenticated "
        "API (including raw binary bytes) is exposed on the network",
    ),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open browser automatically"),
    regen: bool = typer.Option(False, "--regen", help="Regenerate DB before starting"),
    cors: bool = typer.Option(
        False, "--cors", help="Enable CORS processing (allowlisted origins only)"
    ),
    cors_origin: list[str] | None = typer.Option(
        None,
        "--cors-origin",
        help="Origin URL allowed to read the API cross-origin (repeatable, "
        "e.g. http://localhost:5173)",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Require this bearer token for every request (Authorization: Bearer <token>, "
        "?token=, or open the dashboard as /?token=<token> to set the SPA cookie)",
    ),
) -> None:
    """Start the recoverage dashboard server."""
    import recoverage.server as _server
    from recoverage.server import (
        LOOPBACK_HOSTS,
        _assets_dir,
        _project_dir,
    )
    from recoverage.webapp import app as bottle_app

    # NOTE: "::" is the IPv6 wildcard (binds every interface) — it must NOT
    # be treated as loopback, or --bind :: would silently expose the
    # unauthenticated API without the --allow-remote acknowledgment.
    is_remote = bind not in LOOPBACK_HOSTS
    if is_remote and not allow_remote:
        typer.secho(
            f"--bind {bind} exposes the unauthenticated recoverage API (including raw "
            "binary bytes and disassembly) to every reachable host on the network. "
            "Pass --allow-remote to confirm you want this.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    if is_remote:
        typer.secho(
            "warning: serving unauthenticated binary data on the network — "
            "restrict access at the firewall.",
            fg=typer.colors.YELLOW,
        )
    if cors and not cors_origin:
        typer.secho(
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
        typer.secho(
            "warning: --cors-origin has no effect without --cors — "
            "CORS processing is disabled. Pass --cors to enable it.",
            fg=typer.colors.YELLOW,
        )

    # Configure logging — show INFO+ by default so operational messages are visible
    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
        level=logging.INFO,
    )

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
                typer.secho(
                    f"warning: ignoring unparseable --cors-origin {origin_url!r}",
                    fg=typer.colors.YELLOW,
                )
    if token:
        typer.secho(
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
        typer.secho(
            f"Failed to start server on {listen_url}: {e.strerror or e} "
            "(is another instance already running?)",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1) from None


@app.command()
def stats(
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Print coverage stats as a table (or JSON with --json)."""
    from rich.console import Console
    from rich.table import Table

    with contextlib.closing(_open_db_or_exit()) as conn:
        targets = _select_targets(conn, target)

        if not targets:
            typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
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
                size_str = f"{sec.get('size_bytes', 0):,} B"
                table.add_row(
                    sec_name,
                    size_str,
                    str(sec["total_cells"]),
                    str(sec["exact"]),
                    str(sec["reloc"]),
                    str(sec["near_match"]),
                    str(sec["stub"]),
                    f"{sec['coverage_pct']:.1f}%",
                )

            console.print(table)


@app.command()
def export(
    output_format: ExportFormat = typer.Option(
        ExportFormat.json, "--format", "-f", help="Output format"
    ),
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
) -> None:
    """Export coverage data to stdout."""
    with contextlib.closing(_open_db_or_exit()) as conn:
        targets = _select_targets(conn, target)

        if not targets:
            typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
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
        writer.writerow(
            [
                "target",
                "section",
                "size_bytes",
                "total_cells",
                "exact",
                "reloc",
                "near_match",
                "stub",
                "coverage_pct",
            ]
        )
        for data in all_data:
            for sec_name, sec in sorted(data["sections"].items()):
                writer.writerow(
                    [
                        _csv_safe(data["target"]),
                        _csv_safe(sec_name),
                        sec.get("size_bytes", 0),
                        sec["total_cells"],
                        sec["exact"],
                        sec["reloc"],
                        sec["near_match"],
                        sec["stub"],
                        sec["coverage_pct"],
                    ]
                )

    elif output_format == ExportFormat.md:
        for data in all_data:
            typer.echo(f"\n## {data['target']}\n")
            typer.echo("| Section | Size | Cells | Exact | Reloc | Match | Stub | Coverage |")
            typer.echo("|---------|------|-------|-------|-------|-------|------|----------|")
            for sec_name, sec in sorted(data["sections"].items()):
                typer.echo(
                    f"| {sec_name} | {sec.get('size_bytes', 0):,} B | {sec['total_cells']} "
                    f"| {sec['exact']} | {sec['reloc']} | {sec['near_match']} "
                    f"| {sec['stub']} | {sec['coverage_pct']:.1f}% |"
                )


def _section_verdict(
    pct: float,
    untracked: bool,
    section_requested: bool,
    min_coverage: float,
) -> tuple[str, dict[str, Any], str]:
    """Classify one section against the gate: (status, JSON extras, human text).

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
    # Display at the same precision used for the comparison — a gate failing
    # on raw 99.49% must not print "99.5% < 99.5%".
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
    human: str, payload: dict[str, Any], json_output: bool, fg: int = typer.colors.RED
) -> NoReturn:
    """Emit a check-gate failure in --json or human form, then exit 1.

    ONE tail for every `check` failure so the two output modes cannot drift
    (each mode's message/payload stays at its single call site).
    """
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        typer.secho(human, fg=fg, err=True)
    raise typer.Exit(1)


@app.command()
def check(
    min_coverage: float = typer.Option(
        ..., "--min-coverage", "-m", help="Minimum coverage percentage (0-100)"
    ),
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
    section: str | None = typer.Option(None, "--section", "-s", help="Section name (default: all)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check coverage against a threshold (CI gate)."""
    if not 0.0 <= min_coverage <= 100.0:
        _gate_error(
            f"Error: --min-coverage must be between 0 and 100, got {min_coverage!r}.",
            {"error": "--min-coverage must be between 0 and 100", "exit_code": 1},
            json_output,
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
                    typer.secho(
                        f"SKIP: {tid} has no section {section}",
                        fg=typer.colors.YELLOW,
                        err=True,
                    )
                    continue
                sections_to_check = {section: sections_to_check[section]}

            for sec_name, sec in sorted(sections_to_check.items()):
                checked += 1
                untracked = sec.get("covered_bytes", 0) <= 0
                if not untracked:
                    compared += 1
                status, extra, human = _section_verdict(
                    sec["coverage_pct"], untracked, bool(section), min_coverage
                )
                if status == "FAIL":
                    failed = True
                verdicts.append({"target": tid, "section": sec_name, "status": status, **extra})
                if not json_output:
                    typer.secho(f"{status}: {tid} {sec_name} {human}", fg=_VERDICT_COLORS[status])

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
    typer.secho("Done — coverage.db regenerated.", fg=typer.colors.GREEN)


@app.command("open")
def open_cmd(
    port: int = typer.Option(
        8001, "--port", "-p", min=0, max=65535, help="Port of the running server"
    ),
) -> None:
    """Open the dashboard in a browser."""
    url = f"http://127.0.0.1:{port}"
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
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(1) from None
