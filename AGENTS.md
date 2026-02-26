# AGENTS.md — recoverage

## Overview

**recoverage** is a coverage dashboard for binary-matching decompilation projects.
It serves a VanJS + SQLite dashboard visualising per-byte match status across
PE sections (`.text`, `.data`, `.bss`). Two modes: a modern SPA (default) and
a retro "Potato Mode" that renders entirely in server-side HTML tables.

This package is a **consumer** of data produced by `rebrew`. It has no
dependency on rebrew — it only needs a valid `coverage.db` file.

## Project Structure

```
recoverage/
├── pyproject.toml          # Package config, entry point: recoverage
├── README.md               # User-facing docs
├── LICENSE                  # MIT
├── docs/                   # Screenshots & design doc
│   └── DESIGN.md           # Architecture and design decisions
├── tests/
│   ├── test_potato.py      # Potato Mode unit tests
│   └── test_playwright.py  # Browser integration tests
└── src/recoverage/
    ├── __init__.py
    ├── __main__.py          # python -m recoverage
    ├── cli.py               # Typer CLI entry point (serve, stats, export, check, open)
    ├── server.py            # Bottle app, shared helpers & compression
    ├── api.py               # REST API routes (/api/*, /regen)
    ├── ui.py                # UI routes (/, /potato, static files)
    ├── potato.py            # Potato Mode renderer
    └── assets/
        ├── index.html       # SPA shell
        ├── style.css        # All styles
        ├── app.js           # VanJS frontend
        └── van.min.js       # VanJS library
```

## Commands

```bash
# Install
uv pip install -e .

# Run
recoverage serve             # start dashboard on :8001
recoverage serve --port 9000 # custom port
recoverage serve --regen     # re-run rebrew catalog + build-db first
recoverage serve --no-open   # don't auto-open browser
recoverage serve --cors      # enable CORS headers
recoverage stats             # print coverage stats
recoverage export --format csv  # export coverage data
recoverage check --min-coverage 60  # CI gate

# Tests
uv run pytest tests/ -v
```

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Main SPA dashboard |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, DB info, installed extras |
| `/api/targets` | GET | List available targets |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats |
| `/api/targets/<target>/data` | GET | Full section + cell data |
| `/api/targets/<target>/functions` | GET | Paginated function list |
| `/api/targets/<target>/functions/<va>` | GET | Function/global detail |
| `/api/targets/<target>/asm` | GET | Disassembly (requires capstone) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice |
| `/regen` | POST | Re-run catalog + build-db (localhost only) |

## Data Pipeline

1. `rebrew catalog --json` → writes `db/data_*.json` in the project workspace
   - Absorbs jump table / switch data bytes into parent function sizes
   - Links data and thunk cells to their parent function via `parent_function` field
   - `rebrew catalog --export-ghidra-labels` → generates `ghidra_data_labels.json` for round-trip Ghidra sync
2. `rebrew build-db` → reads JSON, builds `db/coverage.db` (SQLite), generates CATALOG.md
   - Cells table includes `label` (Ghidra data label) and `parent_function` columns
3. `recoverage` → serves the DB as a web dashboard
   - Cell detail panel shows parent function as a clickable navigation link

## Dependencies

- `bottle>=0.12` (web server)
- Optional: `capstone` (disassembly), `pygments` (Potato Mode syntax highlighting)

## Code Style

- Python 3.12+, ruff for linting, 100-char line length
- HTML/CSS/JS in `assets/` — no build step, VanJS for reactivity
