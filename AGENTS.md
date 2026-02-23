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
├── DESIGN.md               # Architecture and design decisions
├── LICENSE                  # MIT
├── docs/                   # Screenshots
├── tests/
│   ├── test_potato.py      # Potato Mode unit tests
│   └── test_playwright.py  # Browser integration tests
└── src/recoverage/
    ├── __init__.py
    ├── __main__.py          # python -m recoverage
    ├── server.py            # Bottle app + CLI entry point
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
recoverage                  # start dashboard on :8001
recoverage --port 9000      # custom port
recoverage --regen           # re-run rebrew catalog + build-db first
recoverage --no-open         # don't auto-open browser

# Tests
uv run pytest tests/ -v
```

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Main SPA dashboard |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/targets` | GET | List available targets |
| `/api/targets/<target>/data` | GET | Full section + cell data |
| `/api/targets/<target>/functions/<va>` | GET | Function/global detail |
| `/api/targets/<target>/asm?va=…&size=…` | GET | Disassembly (requires capstone) |
| `/regen` | POST | Re-run catalog + build-db (localhost only) |

## Data Pipeline

1. `rebrew-catalog --json` → writes `db/data_*.json` in the project workspace
2. `rebrew-build-db` → reads JSON, builds `db/coverage.db` (SQLite), generates CATALOG.md
3. `recoverage` → serves the DB as a web dashboard

## Dependencies

- `bottle>=0.12` (web server)
- Optional: `rjsmin`/`rcssmin` (minification), `brotli`/`zstandard` (compression)

## Code Style

- Python 3.12+, ruff for linting, 100-char line length
- HTML/CSS/JS in `assets/` — no build step, VanJS for reactivity
