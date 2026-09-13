# Changelog

All notable user-visible changes to Recoverage are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0] - 2026-09-13

### Changed

- Workspace resolution moved from the standalone `rebrew-workspace`
  distribution into `rebrew.workspace`; recoverage imports `rebrew.workspace`
  for `rebrew-project.toml` + coverage.db resolution.
- rebrew is now a required dependency rather than the optional `regen` extra.
  The `regen` extra is gone, `recoverage regen`, `serve --regen` and
  `POST /api/regen` work on a plain install, and the "install the extra" hint
  is gone.  A regen failure still exits 1 (or answers HTTP 500).

## [1.2.0] - 2026-09-13

### Changed

- **Regen calls rebrew in-process instead of spawning its CLI.**  `recoverage
  regen`, `serve --regen` and `POST /api/regen` load `rebrew-project.toml` once
  and call rebrew's `run_catalog` + `build_db` module functions inside the
  dashboard process, replacing the `rebrew` console-script subprocess (and its
  120-second timeout and process-group kill) introduced in 1.1.1.
  `RECOVERAGE_REBREW` is gone.  There is no timeout any more, so a regen always
  runs to completion, and the dashboard's threaded server keeps answering
  requests while it works.  `POST /api/regen` reports a failure as HTTP 500;
  the 504 timeout response is gone.
- rebrew is now an optional dependency, the `regen` extra (`pip install
  'recoverage[regen]'`).  Without it the regen commands exit 1 (or answer HTTP
  500) with an install hint; every other command keeps working without rebrew.

## [1.1.1] - 2026-09-13

### Fixed

- **Regen runs `rebrew` directly instead of `uv run rebrew`.**  The dashboard
  and `POST /api/regen` invoke the `rebrew` console script resolved from `PATH`
  (`RECOVERAGE_REBREW` overrides it), the way reportal resolves its engine.
  `uv run` is a developer toolchain runner: it resolves and may rewrite the
  workspace environment, needs uv and the network, and fails outright when the
  workspace pins a uv other than the installed one.  A missing `rebrew` now
  reports `rebrew not found on PATH; install it or set RECOVERAGE_REBREW`.

## [1.1.0] - 2026-09-13

### Changed

- Recoverage resolves `rebrew-project.toml`, the `db/coverage.db` path, the
  schema stamp and the read-only DB URI through the shared `rebrew-workspace`
  package, so the dashboard and rebrew cannot drift on the same workspace.  No
  command, route or on-disk format changes.
- The inlined index payload is back inside the initial TCP congestion window.
  The assembly fetch, its error formatting, and the highlight.js loading and
  highlighting moved from the inlined `app.js` into the deferred `detail.js`
  (about 500 compressed bytes).  Nothing changes visually: the Assembly pane
  fills in as soon as `detail.js` lands, the way the hex and data panes already
  did, and asm operand links still jump to their address.

### Added

- `/api/targets/<target>/data` carries `known_schema`: the schema versions this
  build understands (the server's `KNOWN_SCHEMA_VERSIONS`).  The addition is
  additive; the existing fields are unchanged.

### Fixed

- The SPA no longer hardcodes the schema versions it accepts.  It was pinned at
  3/4, so a v5 or v6 database with no section rows was reported as "this build
  does not understand the schema" (rebrew writes 6 today).  It now reads the
  payload's `known_schema`, and uses the neutral wording when the server does
  not send one.

## [1.0.0] - 2026-09-12

First stable release.  From 1.0.0 the HTTP API, the CLI, and the
`coverage.db` schema recoverage reads are frozen: a breaking change takes a
major version bump.

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
- Schema parity with rebrew is now pinned on the rebrew side:
  `tests/test_recoverage_contract.py` runs the real `catalog --data-json` →
  `build-db` pipeline on the fixture binary and asserts every table/column
  recoverage queries exists (cells.label/parent_function, verify_results,
  section_cell_stats view, ...), so a rebrew change that would break the
  dashboard is caught in rebrew's own suite.
- `tools/smoke.py` — end-to-end server smoke for CI: builds a synthetic
  `db/coverage.db` (the shared rebrew build-db schema v4), boots
  `recoverage serve`, and probes the SPA shell, health, targets/data/stats/
  functions APIs, and Potato Mode (7 probes).  `--expect-failure` asserts a
  corrupt DB is reported as `degraded` health rather than served as healthy.
  Wired into CI as a `smoke` job.
- **Deep-linking** — the SPA reads `?target=&fn=&section=&q=` from the URL
  (restoring state on load, `fn` winning over the localStorage last-function)
  and keeps the URL in sync on every change via `history.replaceState`.
  Reloads restore the selected function/section/search; links are shareable.

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
- Potato Mode now emits a `<main>` landmark (with the existing skip-link) and
  `<caption>` on the coverage-map and functions tables — screen readers get
  table semantics instead of anonymous grids (impeccable audit).
- Icon buttons get a 44×44px touch target on coarse pointers
  (`@media (pointer: coarse)`) — desktop layout unchanged, WCAG 2.5.8 met on
  mobile (impeccable audit).
