# Changelog

All notable user-visible changes to Recoverage are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Function detail panels (SPA **and** Potato mode) now show the latest
  `rebrew verify` record: `last_verify.similarity` (0–100 code-similarity
  score) alongside the existing byte-delta / diff-line count.  The score is
  read from the new `verify_results.similarity` column.

## [0.2.0] - 2026-08-18

### Added

- `/api/events` SSE stream — pushes `db-updated` when `coverage.db` changes;
  the SPA auto-refreshes (server now runs on a threaded WSGI server so the
  stream never blocks the dashboard).
- Batch function lookup: `POST /api/targets/<target>/functions` with
  `{"vas": [...]}` returns details in input order (incl. `last_verify`).
- Optional `--token` auth: `Authorization: Bearer`, `?token=`, or open
  `/?token=<token>` to set an HttpOnly cookie so the SPA works unchanged.
- `recoverage check --json` / `stats --json` — machine-readable output;
  infra errors exit 2 (database missing/unreadable).

### Changed

- All API error responses are standardized to
  `{"error", "code", "detail"}` (e.g. `not_found`, `rate_limited`).
- `--allow-remote` required to bind non-loopback; SSE streams capped at 32
  concurrent clients (thread-DoS guard); ETags are hashes of their
  components (no raw request strings in headers); static `/src`/`/original`
  serving resolves symlinks and verifies containment; JSON errors carry
  `Cache-Control: no-store`.
- `/api/targets/<t>/functions/<va>` accepts decimal VAs (the list emits
  `va` as an int — the round-trip previously 404'd); `/data?section=`
  with an unknown section 404s; memo/ETag/watcher are WAL-aware.

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

### Fixed

- Potato Mode now emits a `<main>` landmark (with the existing skip-link) and
  `<caption>` on the coverage-map and functions tables — screen readers get
  table semantics instead of anonymous grids (impeccable audit).
- Icon buttons get a 44×44px touch target on coarse pointers
  (`@media (pointer: coarse)`) — desktop layout unchanged, WCAG 2.5.8 met on
  mobile (impeccable audit).

### Added

- Schema parity with rebrew is now pinned on the rebrew side:
  `tests/test_recoverage_contract.py` runs the real `catalog --data-json` →
  `build-db` pipeline on the fixture binary and asserts every table/column
  recoverage queries exists (cells.label/parent_function, verify_results,
  section_cell_stats view, ...), so a rebrew change that would break the
  dashboard is caught in rebrew's own suite.

### Added

- `tools/smoke.py` — end-to-end server smoke for CI: builds a synthetic
  `db/coverage.db` (the shared rebrew build-db schema v4), boots
  `recoverage serve`, and probes the SPA shell, health, targets/data/stats/
  functions APIs, and Potato Mode (7 probes).  `--expect-failure` asserts a
  corrupt DB is reported as `degraded` health rather than served as healthy.
  Wired into CI as a `smoke` job.

### Added

- **Deep-linking** — the SPA reads `?target=&fn=&section=&q=` from the URL
  (restoring state on load, `fn` winning over the localStorage last-function)
  and keeps the URL in sync on every change via `history.replaceState`.
  Reloads restore the selected function/section/search; links are shareable.
