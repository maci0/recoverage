"""Typer CLI for recoverage — coverage dashboard for binary-matching projects."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import subprocess
import threading
from pathlib import Path
from typing import Any

import typer

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


# ── Helpers ────────────────────────────────────────────────────────


def _db_path() -> Path:
    return Path.cwd().resolve() / "db" / "coverage.db"


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
    c.execute("SELECT DISTINCT target FROM metadata")
    return [row[0] for row in c.fetchall()]


def _get_stats(conn: sqlite3.Connection, target: str) -> dict[str, Any]:
    c = conn.cursor()

    # Summary from metadata
    summary: dict[str, Any] = {}
    c.execute("SELECT value FROM metadata WHERE target = ? AND key = 'summary'", (target,))
    row = c.fetchone()
    if row:
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            summary = json.loads(row[0])

    # Per-section stats
    sections: dict[str, dict[str, Any]] = {}
    c.execute(
        "SELECT section_name, total_cells, exact_count, reloc_count, "
        "matching_count, stub_count, data_count, thunk_count FROM section_cell_stats WHERE target = ?",
        (target,),
    )
    for row in c.fetchall():
        total = row["total_cells"]
        matched = row["exact_count"] + row["reloc_count"]
        sections[row["section_name"]] = {
            "total_cells": total,
            "exact": row["exact_count"],
            "reloc": row["reloc_count"],
            "matching": row["matching_count"],
            "stub": row["stub_count"],
            "data": row["data_count"],
            "thunk": row["thunk_count"],
            "matched": matched,
            "coverage_pct": round(matched / total * 100, 2) if total else 0.0,
        }

    # Section byte sizes
    c.execute("SELECT name, size FROM sections WHERE target = ?", (target,))
    for row in c.fetchall():
        if row["name"] in sections:
            sections[row["name"]]["size_bytes"] = row["size"]

    # Function counts by status
    by_status: dict[str, int] = {}
    c.execute(
        "SELECT status, COUNT(*) as cnt FROM functions WHERE target = ? GROUP BY status",
        (target,),
    )
    for row in c.fetchall():
        by_status[row["status"] or "unknown"] = row["cnt"]

    return {"target": target, "summary": summary, "sections": sections, "by_status": by_status}


# ── Commands ───────────────────────────────────────────────────────


@app.command()
def serve(
    port: int = typer.Option(8001, help="Port to serve on"),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open browser automatically"),
    regen: bool = typer.Option(False, "--regen", help="Regenerate DB before starting"),
    cors: bool = typer.Option(False, "--cors", help="Enable CORS headers for cross-origin access"),
) -> None:
    """Start the recoverage dashboard server."""
    import recoverage.server as _server
    from recoverage.server import (
        _assets_dir,
        _project_dir,
        open_browser,
    )
    from recoverage.server import (
        _db_path as server_db_path,
    )
    from recoverage.server import (
        app as bottle_app,
    )

    if cors:
        _server.CORS_ENABLED = True

    root = _project_dir()
    assets = _assets_dir()
    url = f"http://127.0.0.1:{port}"

    if regen:
        typer.echo("Regenerating coverage data...")
        subprocess.check_call(["uv", "run", "rebrew", "catalog"], cwd=str(root), timeout=60)
        subprocess.check_call(["uv", "run", "rebrew", "build-db"], cwd=str(root), timeout=60)

    typer.echo(f"Serving coverage dashboard at {url}")
    typer.echo(f"  Assets: {assets}")
    typer.echo(f"  DB: {server_db_path()}")
    if cors:
        typer.echo("  CORS: enabled")
    typer.echo("  Regen: POST /regen or click Reload in UI")
    typer.echo("  Stop: Ctrl+C")

    if not no_open:
        threading.Timer(0.5, open_browser, args=(url,)).start()

    bottle_app.run(host="127.0.0.1", port=port, quiet=True, server="wsgiref")


@app.command()
def stats(
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
) -> None:
    """Print coverage stats as a table."""
    from rich.console import Console
    from rich.table import Table

    with contextlib.closing(_open_db()) as conn:
        targets = [target] if target else _list_targets(conn)

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
                    str(sec["matching"]),
                    str(sec["stub"]),
                    f"{sec['coverage_pct']:.1f}%",
                )

            console.print(table)


@app.command()
def export(
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, csv, md"),
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
) -> None:
    """Export coverage data to stdout."""
    with contextlib.closing(_open_db()) as conn:
        targets = [target] if target else _list_targets(conn)

        if not targets:
            typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(1)

        all_data = [_get_stats(conn, tid) for tid in targets]

    if format == "json":
        typer.echo(json.dumps(all_data, indent=2))

    elif format == "csv":
        typer.echo("target,section,size_bytes,total_cells,exact,reloc,matching,stub,coverage_pct")
        for data in all_data:
            for sec_name, sec in sorted(data["sections"].items()):
                typer.echo(
                    f"{data['target']},{sec_name},{sec.get('size_bytes', 0)},"
                    f"{sec['total_cells']},{sec['exact']},{sec['reloc']},"
                    f"{sec['matching']},{sec['stub']},{sec['coverage_pct']}"
                )

    elif format == "md":
        for data in all_data:
            typer.echo(f"\n## {data['target']}\n")
            typer.echo("| Section | Size | Cells | Exact | Reloc | Match | Stub | Coverage |")
            typer.echo("|---------|------|-------|-------|-------|-------|------|----------|")
            for sec_name, sec in sorted(data["sections"].items()):
                typer.echo(
                    f"| {sec_name} | {sec.get('size_bytes', 0):,} B | {sec['total_cells']} "
                    f"| {sec['exact']} | {sec['reloc']} | {sec['matching']} "
                    f"| {sec['stub']} | {sec['coverage_pct']:.1f}% |"
                )
    else:
        typer.secho(
            f"Unknown format: {format}. Use json, csv, or md.", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(1)


@app.command()
def check(
    min_coverage: float = typer.Option(..., "--min-coverage", help="Minimum coverage percentage"),
    target: str | None = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
    section: str | None = typer.Option(None, "--section", "-s", help="Section name (default: all)"),
) -> None:
    """Check coverage against a threshold (CI gate)."""
    with contextlib.closing(_open_db()) as conn:
        targets = [target] if target else _list_targets(conn)

        if not targets:
            typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(1)

        failed = False
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

    if failed:
        raise typer.Exit(1)


@app.command()
def regen() -> None:
    """Re-run rebrew catalog + build-db to regenerate coverage.db."""
    from recoverage.server import _project_dir

    root = _project_dir()
    typer.echo("Running rebrew catalog...")
    subprocess.check_call(["uv", "run", "rebrew", "catalog"], cwd=str(root), timeout=120)
    typer.echo("Running rebrew build-db...")
    subprocess.check_call(["uv", "run", "rebrew", "build-db"], cwd=str(root), timeout=120)
    typer.secho("Done — coverage.db regenerated.", fg=typer.colors.GREEN)


@app.command("open")
def open_cmd(
    port: int = typer.Option(8001, help="Port of the running server"),
) -> None:
    """Open the dashboard in a browser."""
    from recoverage.server import open_browser

    url = f"http://127.0.0.1:{port}"
    typer.echo(f"Opening {url}")
    open_browser(url)


def main() -> None:
    app()
