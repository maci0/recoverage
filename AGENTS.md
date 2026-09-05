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
│   ├── DESIGN.md           # Architecture and design decisions
│   ├── DESIGN_PRINCIPLES.md  # Core operational philosophies
│   ├── USER_STORIES.md     # User stories with acceptance criteria
│   └── ideas.md            # Future improvement ideas
├── tests/
│   ├── conftest.py           # Shared fixtures (synthetic coverage.db)
│   ├── test_api.py           # API validation, security, SQL injection tests
│   ├── test_cli.py           # CSV export, formatting, edge case tests
│   ├── test_lifecycle.py     # Process lifecycle: regen timeouts, browser-opener reaping
│   ├── test_paths.py         # DB path resolution tests
│   ├── test_server.py        # Compression, encoding, path helper tests
│   ├── test_potato.py        # Potato Mode unit tests
│   └── test_playwright.py    # Browser integration tests
└── src/recoverage/
    ├── __init__.py
    ├── __main__.py          # python -m recoverage
    ├── _paths.py            # DB path resolution (rebrew-project.toml db_dir)
    ├── cli.py               # Typer CLI entry point (serve, stats, export, check, regen, open)
    ├── server.py            # Bottle app, shared helpers & compression
    ├── regen.py             # rebrew regen subprocess lifecycle (group kill + reap)
    ├── api.py               # REST API routes (/api/*)
    ├── ui.py                # UI routes (/, /potato, static files)
    ├── potato.py            # Potato Mode renderer
    ├── webapp.py            # Composition root: imports api+ui so app has every route
    └── assets/
        ├── index.html       # SPA shell
        ├── style.css        # All styles
        ├── print.css        # Print stylesheet
        ├── app.js           # VanJS frontend
        ├── detail.js        # Deferred panel logic (hex dump, modal, live reload)
        ├── van.min.js       # VanJS library
        ├── favicon.svg      # Retro "R" logo favicon
        ├── hljs.min.js / hljs-c.min.js / hljs-x86asm.min.js  # Highlight.js core + grammars
        └── hljs.css         # Highlight.js theme (custom hex language)
```

Frontend lint tooling lives at the repo root: `package.json` (oxlint, `@oxlint/plugins`, `@rikalabs/oxlint-standards`, vnu-jar), `oxlint.config.ts` (JS/TS lint config), `tools/lint-html.mjs` (vnu check of the static HTML/CSS assets), `tools/lint-served-html.py` (vnu check of the documents the server actually serves: the SPA shell with injected CSS/JS and Potato Mode), `tools/smoke.py` (end-to-end server smoke run by the CI `smoke` job), and `tools/oxlint/`:

- `tools/oxlint/anti-slop/` — vendored copy of dmmulroy/anti-slop (keep in sync with upstream).
- `tools/oxlint/rikalabs-strict.json` — flattened copy of the `strict` preset from `@rikalabs/oxlint-standards`, regenerated with `tools/flatten-rikalabs-strict.py` (bump the package, re-run the script, re-run `bun run lint:js`). It is flattened because the published presets reference rules oxlint 1.79.0 does not implement. `oxlint.config.ts` documents the platform exceptions (browser-only SPA: `env.browser`, `typeAware: false`, style off-list with rationale).

## Commands

```bash
# Install
uv pip install -e .            # runtime deps only
uv pip install -e .[dev]       # + pytest, ruff (CI runs uv sync --frozen --extra dev)
uv pip install -e .[playwright]  # browser tests: playwright, pytest-playwright

# Run
recoverage serve             # start dashboard on :8001
recoverage serve --port 9000 # custom port
recoverage serve --regen     # re-run rebrew catalog + build-db first
recoverage serve --no-open   # don't auto-open browser
recoverage serve --cors      # enable CORS processing (allowlist origins with --cors-origin)
recoverage stats             # print coverage stats
recoverage export --format csv  # export coverage data
recoverage check --min-coverage 60  # CI gate

# Tests
uv run pytest tests/ -v

# Frontend linting (requires node + java on PATH)
bun install                 # one-time: oxlint, @oxlint/plugins, @rikalabs/oxlint-standards, vnu-jar
bun run lint                # oxlint (Rika-Labs strict preset + vendored anti-slop) + vnu HTML/CSS
bun run lint:js             # oxlint only
bun run lint:html           # vnu only: static assets + served pages (SPA shell, Potato Mode)
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
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order |
| `/api/targets/<target>/functions/<va>` | GET | Function/global detail |
| `/api/targets/<target>/asm` | GET | Disassembly (requires capstone) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice |
| `/api/events` | GET | Server-Sent Events: `db-updated` when coverage.db changes (SPA auto-refresh) |
| `/api/regen` | POST | Re-run catalog + build-db (localhost only, rate-limited) |

## Data Pipeline

1. `rebrew catalog --json` → writes `db/data_*.json` in the project workspace
   - Absorbs jump table / switch data bytes into parent function sizes
   - Links data and thunk cells to their parent function via `parent_function` field
   - `rebrew catalog --export-ghidra-labels` → generates `ghidra_data_labels.json` for round-trip Ghidra sync
2. `rebrew build-db` → reads JSON, builds `db/coverage.db` (SQLite)
   - Cells table includes `label` (Ghidra data label) and `parent_function` columns
3. `recoverage` → serves the DB as a web dashboard
   - Cell detail panel shows parent function as a clickable navigation link

## Dependencies

Required:
- `bottle>=0.13` (web server)
- `brotli>=1.1` (Brotli compression)
- `rcssmin>=1.1` (CSS minification)
- `rich>=13.0` (terminal tables)
- `rjsmin>=1.2` (JS minification)
- `typer>=0.9` (CLI framework)
- `zstandard>=0.22` (Zstandard compression)

Optional:
- `capstone` (disassembly)
- `pygments` (Potato Mode syntax highlighting)

## Code Style

- Python 3.12+, ruff for linting, 100-char line length
- HTML/CSS/JS in `assets/` — no build step, VanJS for reactivity
- JS is linted with oxlint under the `@rikalabs/oxlint-standards` strict preset
  plus the vendored anti-slop rules; the webui is a classic-script SPA, so
  `app.js`/`detail.js` are wrapped in IIFEs and share state via `window.RC`.
  Rationale-bearing `oxlint-disable` comments are the sanctioned escape hatch
  for UI error boundaries and VanJS idioms (see `oxlint.config.ts`).
