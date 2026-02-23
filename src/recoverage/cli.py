"""Typer CLI for recoverage — coverage dashboard for binary-matching projects."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    help="Coverage dashboard for binary-matching decompilation projects.",
    add_completion=False,
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


def _get_stats(conn: sqlite3.Connection, target: str) -> dict:
    """Fetch coverage stats for a single target."""
    c = conn.cursor()

    # Summary from metadata
    summary: dict = {}
    c.execute("SELECT value FROM metadata WHERE target = ? AND key = 'summary'", (target,))
    row = c.fetchone()
    if row:
        try:
            summary = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            pass

    # Per-section stats
    sections: dict = {}
    c.execute(
        "SELECT section_name, total_cells, exact_count, reloc_count, "
        "matching_count, stub_count FROM section_cell_stats WHERE target = ?",
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
    from recoverage.server import (
        _assets_dir,
        _db_path as server_db_path,
        _project_dir,
        app as bottle_app,
        open_browser,
    )
    import recoverage.server as _server

    if cors:
        _server.CORS_ENABLED = True

    root = _project_dir()
    assets = _assets_dir()
    url = f"http://127.0.0.1:{port}"

    if regen:
        typer.echo("Regenerating coverage data...")
        subprocess.check_call(["uv", "run", "rebrew", "catalog"], cwd=str(root))
        subprocess.check_call(["uv", "run", "rebrew", "build-db"], cwd=str(root))

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
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
) -> None:
    """Print coverage stats as a table."""
    from rich.console import Console
    from rich.table import Table

    conn = _open_db()
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
            console.print(
                f"  Functions: {matched_fn}/{total_fn} matched ({pct}%)"
            )

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

    conn.close()


@app.command()
def export(
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, csv, md"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
) -> None:
    """Export coverage data to stdout."""
    conn = _open_db()
    targets = [target] if target else _list_targets(conn)

    if not targets:
        typer.secho("No targets found in database.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1)

    all_data = [_get_stats(conn, tid) for tid in targets]
    conn.close()

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
        typer.secho(f"Unknown format: {format}. Use json, csv, or md.", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


@app.command()
def check(
    min_coverage: float = typer.Option(..., "--min-coverage", help="Minimum coverage percentage"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target ID (default: all)"),
    section: Optional[str] = typer.Option(None, "--section", "-s", help="Section name (default: all)"),
) -> None:
    """Check coverage against a threshold (CI gate)."""
    conn = _open_db()
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
                    fg=typer.colors.YELLOW, err=True,
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

    conn.close()
    if failed:
        raise typer.Exit(1)


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
