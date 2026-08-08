"""Typer CLI for recoverage — coverage dashboard for binary-matching projects."""

from __future__ import annotations

import contextlib
import enum
import json
import logging
import sqlite3
import subprocess
import threading
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from wsgiref.simple_server import WSGIServer

import typer

from recoverage._paths import _db_path

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
        "  Run [dim]rebrew catalog --json && rebrew build-db[/dim] first to create db/coverage.db.\n\n"
        "[dim]Reads db/coverage.db (SQLite). Serves SPA at http://localhost:8001.[/dim]"
    ),
)


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
        raise typer.Exit()


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


def _open_db(db_path: Path | None = None) -> sqlite3.Connection:
    p = db_path or _db_path()
    if not p.exists():
        typer.secho(f"Error: database not found at {p}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _list_targets(conn: sqlite3.Connection) -> list[str]:
    c = conn.cursor()
    from recoverage.server import SCHEMA_TARGET

    c.execute(
        "SELECT DISTINCT target FROM metadata WHERE target != ? ORDER BY target",
        (SCHEMA_TARGET,),
    )
    return [row[0] for row in c.fetchall()]


def _resolve_targets(conn: sqlite3.Connection, target: str | None) -> list[str]:
    """Return the targets to operate on, validating a requested --target.

    A requested target that is not in the DB exits 1 with a clear error —
    sibling commands must not silently succeed on a typo'd target.
    """
    if target is not None:
        known = _list_targets(conn)
        if target not in known:
            typer.secho(
                f"Error: target {target!r} not found in database (have: {', '.join(known) or 'none'}).",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1)
        return [target]
    return _list_targets(conn)


def _get_stats(conn: sqlite3.Connection, target: str) -> dict[str, Any]:
    c = conn.cursor()
    from recoverage.server import _section_stats  # noqa: PLC0415

    stats = _section_stats(c, target)
    return {"target": target, **stats, "by_status": stats["by_status"]}


def _run_regen(root: Path) -> None:
    """Run rebrew catalog + build-db to regenerate coverage.db."""
    from recoverage.server import REGEN_TIMEOUT  # noqa: PLC0415

    for step in ("catalog", "build-db"):
        cmd = ["uv", "run", "rebrew", step]
        typer.echo(f"Running rebrew {step}...")
        try:
            subprocess.check_call(cmd, cwd=str(root), timeout=REGEN_TIMEOUT)
        except FileNotFoundError:
            typer.secho("Error: 'uv' not found — is it installed?", fg=typer.colors.RED, err=True)
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


# ── Commands ───────────────────────────────────────────────────────


@app.command()
def serve(
    port: int = typer.Option(8001, "--port", "-p", help="Port to serve on"),
    bind: str = typer.Option(
        "127.0.0.1", "--bind", help="Interface to bind to (default: 127.0.0.1; use 0.0.0.0 for LAN)"
    ),
    allow_remote: bool = typer.Option(
        False,
        "--allow-remote",
        help="Required with --bind 0.0.0.0: acknowledge that the unauthenticated API (including raw binary bytes) is exposed on the network",
    ),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open browser automatically"),
    regen: bool = typer.Option(False, "--regen", help="Regenerate DB before starting"),
    cors: bool = typer.Option(
        False, "--cors", help="Enable CORS processing (allowlisted origins only)"
    ),
    cors_origin: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--cors-origin",
        help="Origin URL allowed to read the API cross-origin (repeatable, e.g. http://localhost:5173)",
    ),
) -> None:
    """Start the recoverage dashboard server."""
    import recoverage.server as _server
    from recoverage._paths import (
        _db_path as server_db_path,
    )
    from recoverage.server import (
        _assets_dir,
        _project_dir,
        open_browser,
    )
    from recoverage.server import (
        app as bottle_app,
    )

    # NOTE: "::" is the IPv6 wildcard (binds every interface) — it must NOT
    # be treated as loopback, or --bind :: would silently expose the
    # unauthenticated API without the --allow-remote acknowledgment.
    loopback_binds = ("127.0.0.1", "localhost", "::1")
    is_remote = bind not in loopback_binds
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

    # Configure logging — show INFO+ by default so operational messages are visible
    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
        level=logging.INFO,
    )
    _log = logging.getLogger("recoverage")

    if cors:
        _server.CORS_ENABLED = True
        if cors_origin:
            _server.CORS_ALLOWED_ORIGINS = [_server._normalize_origin(o) for o in cors_origin]
    # Loopback binds validate the Host header (DNS-rebinding guard); remote
    # binds (user opted in via --allow-remote) skip validation.
    if is_remote:
        _server.ALLOWED_HOSTS = None
    else:
        _server.ALLOWED_HOSTS = set(loopback_binds)

    root = _project_dir()
    assets = _assets_dir()
    url = f"http://127.0.0.1:{port}"
    # The browser always opens against loopback; --bind only controls the
    # listening interface (e.g. 0.0.0.0 for LAN access to the dashboard).
    listen_url = f"http://{bind}:{port}" if bind != "127.0.0.1" else url

    if regen:
        _run_regen(root)

    _log.info("Starting recoverage server on %s (port=%d, cors=%s)", listen_url, port, cors)

    typer.echo(f"Serving coverage dashboard at {url}")
    typer.echo(f"  Listening on: {listen_url}")
    typer.echo(f"  Assets: {assets}")
    typer.echo(f"  DB: {server_db_path()}")
    if cors:
        typer.echo("  CORS: enabled")
    typer.echo("  Regen: POST /api/regen or click Reload in UI")
    typer.echo("  Stop: Ctrl+C")

    if not no_open:
        threading.Timer(0.5, open_browser, args=(url,)).start()

    try:
        bottle_app.run(
            host=bind,
            port=port,
            quiet=True,
            server="wsgiref",
            server_class=_ThreadingWSGIServer,
        )
    except OSError as e:
        # EADDRINUSE is the most common failure for a dashboard tool — a
        # second instance or another dev server on the same port.
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
) -> None:
    """Print coverage stats as a table."""
    from rich.console import Console
    from rich.table import Table

    with contextlib.closing(_open_db()) as conn:
        targets = _resolve_targets(conn, target)

        if not targets:
            typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(1)

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
    output_format: ExportFormat = typer.Option(  # noqa: B008
        ExportFormat.json, "--format", "-f", help="Output format"
    ),
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
) -> None:
    """Export coverage data to stdout."""
    with contextlib.closing(_open_db()) as conn:
        targets = _resolve_targets(conn, target)

        if not targets:
            typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(1)

        all_data = [_get_stats(conn, tid) for tid in targets]

    if output_format == ExportFormat.json:
        typer.echo(json.dumps(all_data, indent=2))

    elif output_format == ExportFormat.csv:
        import csv  # noqa: PLC0415
        import sys  # noqa: PLC0415

        writer = csv.writer(sys.stdout)
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
                        data["target"],
                        sec_name,
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


@app.command()
def check(
    min_coverage: float = typer.Option(
        ..., "--min-coverage", "-m", help="Minimum coverage percentage (0-100)"
    ),
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
    section: str | None = typer.Option(None, "--section", "-s", help="Section name (default: all)"),
) -> None:
    """Check coverage against a threshold (CI gate)."""
    if not 0.0 <= min_coverage <= 100.0:
        typer.secho(
            f"Error: --min-coverage must be between 0 and 100, got {min_coverage!r}.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)

    with contextlib.closing(_open_db()) as conn:
        targets = _resolve_targets(conn, target)

        if not targets:
            typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(1)

        failed = False
        checked = 0
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
                pct = sec["coverage_pct"]
                if pct < min_coverage:
                    typer.secho(
                        f"FAIL: {tid} {sec_name} coverage {pct:.1f}% < {min_coverage:.1f}%",
                        fg=typer.colors.RED,
                    )
                    failed = True
                else:
                    typer.secho(
                        f"PASS: {tid} {sec_name} coverage {pct:.1f}% >= {min_coverage:.1f}%",
                        fg=typer.colors.GREEN,
                    )

    if not checked:
        typer.secho(
            "Error: no sections matched — nothing was checked.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
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
    port: int = typer.Option(8001, "--port", "-p", help="Port of the running server"),
) -> None:
    """Open the dashboard in a browser."""
    from recoverage.server import open_browser

    url = f"http://127.0.0.1:{port}"
    typer.echo(f"Opening {url}")
    open_browser(url)


def main() -> None:
    app()
