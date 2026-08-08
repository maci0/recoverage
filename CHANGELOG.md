# Changelog

All notable user-visible changes to Recoverage are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `/api/events` SSE stream — pushes `db-updated` when `coverage.db` changes;
  the SPA auto-refreshes (server now runs on a threaded WSGI server so the
  stream never blocks the dashboard).
- Batch function lookup: `POST /api/targets/<target>/functions` with
  `{"vas": [...]}` returns details in input order (incl. `last_verify`).

### Changed

- All API error responses are standardized to
  `{"error", "code", "detail"}` (e.g. `not_found`, `rate_limited`).

## [0.1.0] - 2026-08-08

First tagged release.  Recoverage is a coverage dashboard for binary-matching
decompilation projects: it serves the `coverage.db` produced by
`rebrew build-db` as a web dashboard, with a modern SPA and a retro
server-rendered "Potato Mode".

### Added

- **Dashboard**: VanJS SPA with a per-byte coverage grid (exact / reloc /
  near-match / stub / padding / data / thunk states), section tabs, search,
  status filters, and function detail panels (badges, C source, disassembly,
  hex inspector).
- **Potato Mode**: `/potato` — a pure server-side HTML table fallback with
  keyboard accesskeys, prev/next navigation, and the same detail panels.
- **REST API**: `/api/health`, `/api/targets`, per-target
  `stats`/`data`/`functions`/`functions/<va>`/`asm`/`sections/<section>/bytes`,
  and localhost-only `/api/regen` (re-runs `rebrew catalog` + `build-db`).
- **CLI**: `recoverage serve` (`--port`, `--bind`, `--no-open`, `--regen`,
  `--cors`), `stats`, `export` (JSON/CSV/Markdown), `check` (CI gate),
  `open`, `regen`.
- **Coverage DB support**: schema v4 (cells with label/parent_function,
  `section_cell_stats` view, functions with Ghidra/list names and thunk
  markers, verify_results imported by `build-db`).
- Function detail surfaces the last `rebrew verify` record (`last_verify`).

### Changed

- DB-gated tests now run in CI: a synthetic `coverage.db` is built by the
  test conftest when none exists (previously 57 tests silently skipped).
- C-source paths resolve against the project dir via `paths.sourceRoot` from
  `rebrew catalog` (previously anchored inside the package and never loaded).
- `/api/regen` has a server-side cooldown (429 + `retry_after`) matching the
  UI's throttle; the functions list and by-status stats exclude GLOBAL/DATA
  marker rows; search also matches hex `vaStart`.

### Fixed

- Potato Mode detail panel: `% if` template directives are now line-scoped
  (the Label row no longer always renders), and cell function entries (VA
  strings) are looked up by VA like the SPA/API, not by name.
- ETag caching: header lookup is case-insensitive; stale potato test
  assertions (accesskeys, detail markup) corrected to the shipped renderer.
