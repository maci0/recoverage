# Changelog

All notable user-visible changes to Recoverage are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Tag this **2.0.0**: `server.resolve_targets` changed its return shape and the
module ships in the published package. See *Breaking*.

### Added

- **`recoverage serve` reads its configuration from the environment.**
  `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN` and
  `RECOVERAGE_DB` supply the default for the matching flag; the flag still
  wins. `RECOVERAGE_TOKEN` keeps the bearer token out of the process listing
  that `--token` exposes it to, and `RECOVERAGE_DB` serves a
  `coverage.db` the process was not started from the root of. Values are
  validated at startup: a bad port, boolean or empty value, and a misspelled
  `RECOVERAGE_*` name, each exit 2 naming the variable. The resolved settings
  are printed on startup, the token as `token=set`.

### Breaking

- **`server.resolve_targets` returns the one ordered target list, not a
  `(target_ids, targets)` pair.** Before: a two-element tuple whose first
  element was raw DB order and whose second was config-declared first. After:
  the second element alone, so `target_ids, targets = resolve_targets(c)`
  raises `ValueError: not enough values to unpack`. Drop the unpacking and use
  the returned list. Every in-tree caller already discarded the first
  element, which is what left a second ordering alive for the SPA and Potato
  Mode to agree not to use.

### Fixed

- **`--no-color`, `NO_COLOR`, and `TERM=dumb` are honored.** Colorized errors,
  warnings, and `check` verdicts carried ANSI escapes on a terminal even with
  `NO_COLOR` set, because click only strips escapes from a non-TTY stream. The
  global `--no-color` flag is the explicit opt-out; the environment variables
  are the convention. The opt-outs only ever force color off, so a piped run
  stays plain as before.
- **`check` keeps one report on one stream.** A section skipped for not
  existing was written to stderr while the PASS/FAIL verdicts went to stdout,
  so `check 2>/dev/null` silently dropped the sections it declined to gate.
  The skip note now follows the output mode: stdout with the other verdicts,
  stderr under `--json`, where stdout carries the payload alone.
- **`export --format md` no longer starts with a blank line.** The first
  target's heading was preceded by the separator newline that separates
  targets, so `recoverage export --format md > coverage.md` produced a file
  opening on an empty line.
- **`export --help` renders as prose.** The docstring's line-ending note was
  read as a line break by the rich help renderer, splitting the sentence
  about CSV row endings and leaving a stray quote in the help text.
- **Coverage buckets reconcile with `total_cells`.** `/stats` and `/data`
  section objects carry an `other` bucket matching rebrew's catch-all
  (`compile_error`, `extract_error`, `invalid_va`, `missing_file`,
  `missing_size`, `skip`, `unknown`, `drift`, `unchecked`). A consumer summing
  the documented buckets now gets `total_cells` instead of a residual it read
  as zero-sized. Both query paths compute it, and a `section_cell_stats` that
  predates the column reports 0 rather than dropping the key.
- **Every cell state rebrew can write is colored.** `verified`, `drift`,
  `unchecked` and the nine problem states fell through to the `none` color and
  painted as undocumented gaps, which contradicts the number printed beside
  them: `build_db` counts `verified` as an exact match and `covered_bytes`
  covers every state that is not `none`. Both legends gained a `problem` row,
  and Potato Mode's gained a `proven` row.
- **The SPA search box reports and acts on its own state.** It gained a clear
  button, a live match count, Enter to jump to the first match, and Escape to
  clear. Clearing the state alone left the typed text in the (uncontrolled)
  input while the map stopped filtering.
- **A failed function lookup no longer leaves stale panes.** The Assembly pane
  read "Loading assembly..." forever and Copy/Open stayed enabled, so a
  lookup for a VA the database does not carry copied that literal.
- **Potato Mode hex search matches the addresses it prints.** Both the
  function-list filter and the cell dimming test built the VA string with
  `printf('0x%x', va)`, which emits no `0x` prefix, so an address copied out
  of a VA column never matched when pasted back. They now emit the same
  `0x`-prefixed spelling the column prints.
- **SSE client slots are released on every exit path.** A peer that hung up
  between the handler returning and the first write lost a slot, a file
  descriptor and a handler thread for the process's remaining lifetime,
  permanently eroding the concurrent-client cap.
- **Potato Mode never publishes a stale read into its caches.** The grid-cell
  and section-stats memos filed a payload under the new snapshot fingerprint
  even when the cursor's read snapshot predated a rebuild that a broadcast had
  already invalidated, so the stale entry survived until the next rebuild.
- **The regen cooldown notice times itself out.** "Regenerating from cache"
  and "regenerate unavailable" replaced the stats row and, unlike the loading
  state, had nothing clearing them, so a second click in quick succession
  looked like it did nothing.
- **`export --format md` emits a well-formed table.** Each section row wrote
  eleven cells (the exact/reloc/near-match triple twice) under an
  eight-column header. A test asserts every data row has the header's count.
- **`rebrew catalog --json` no longer appears in the documented pipeline.**
  That flag suppresses the data-JSON write: it only prints a summary. The
  quickstart, the pipeline diagram, the design docs, the user stories, and
  the CLI's own rebuild hint all named the summary-only form. Every one now
  shows the bare `rebrew catalog`, which is what `regen` actually runs.
- **Potato Mode responses carry a cache directive.** `/potato` was the one
  DB-derived response sent with no `Cache-Control` at all, leaving
  heuristic freshness to the browser and leaving a shared cache free to
  store and replay a page rendered for a token-bearing client. It now
  sends `no-cache, must-revalidate`, keeping the ETag's cheap 304s.
  The Potato 500 page and the HTML 401 token challenge now say `no-store`
  like every other error response.
- **Target ids are escaped in the DLL loader's warnings.** `target` is
  routable request data and originates in analyzed binary names, so a
  control character in it could forge a log line; the loader's warnings
  now route it through `_log_safe` like the rest of the request log.

### Changed

- **Static assets revalidate instead of re-downloading.** The ten
  compressed assets sent `Cache-Control: no-cache` with no validator, so a
  repeat visit re-sent 55 KB and every asm-pane opening re-sent
  `hljs.min.js` and its grammars. Each now carries a strong ETag (per
  content-encoding, so a brotli and a zstd body never share one) and answers
  304 to a matching `If-None-Match`. `max-age` stays at 0 on purpose: the URLs
  are not content-hashed, so an upgrade changes the bytes under the same name.
- **Syntax highlighting follows the documented palette.** Every highlight.js
  token color in both themes was a hand-picked literal outside the palette and
  now derives from it, so the code and hex panes restyle with the theme
  instead of drifting from it.
- **Badge, link, and progress-track colors derive from the palette** rather
  than repeating hex literals, including the empty progress-bar track, which
  is `--none` composited over the panel color.

### Removed

- `app.js` `detailBound()` and its two spread sites: both `disabled` and
  `title` were overwritten in the same object literal, so it contributed
  nothing.
- `detail.js` `walk()`'s return value, never read; the row count is derived in
  `layout()` where the map is sized.
- `potato.py`'s `TRANSPARENT_GIF=TRANSPARENT_GIF` render kwarg: the variable
  appears in no template, so bottle discarded it.
- `server.py`'s `_STATUS_ERROR_CODES[504]`: no code path returns 504.
- The `--cell-border` custom property in both `style.css` themes: never read.

## [1.6.0] - 2026-09-27

Requires `rebrew>=2.10.0`.

### Fixed

- **Regen imports `run_catalog` from `rebrew.catalog.cli`.** Since rebrew 2.7
  the `rebrew.catalog` package does not re-export it, so `recoverage regen`,
  `serve --regen`, and `POST /api/regen` raised `ImportError` against current
  rebrew.
- **The function list skips `VTABLE` and `STRING` rows.** Potato and the
  stats query already treated those markers as data. `/api/targets/<target>/functions`
  only excluded `GLOBAL` and `DATA`, so vtable and string rows were listed
  as functions.
- **Schema v8, v9, and v10 are accepted.** Current rebrew stamps `db_version`
  `"10"`. v8 CHECK-constrains `functions.status`, v9 CHECK-constrains
  `cells.state` and adds `idx_metadata_key`, and v10 stores `extract_error`
  and `invalid_va` as cell states. None of those add or remove a column this
  server queries. The column gate applies to every known version except v3.
- **The live cell-JSON fallback uses `SECTION_CELLS_AGG_SQL`.** That is the
  ordered aggregate `build-db` writes into `section_cells_json`
  (`json_group_array` of the shared projection, `ORDER BY start`).
- **Database reads use the same read-only setup as `open_sqlite_ro` and
  hold `coverage_db_lock` shared until `close`.** `mode=ro` and `query_only`
  reject writes. `build-db --force` waits for the shared lock before
  unlinking the file.

## [1.5.0] - 2026-09-17

Requires `rebrew>=2.4.0`: the cell projection, the `cells_zstd` codec and the
v7 schema objects all ship from `rebrew.workspace`, and `server.py` imports
`CELLS_JSON_OBJECT_SQL` at module scope.

### Fixed

- **Potato Mode and the SPA now open the same target.** `resolve_targets`
  returns two differently-ordered lists — `target_ids` (raw DB order) and
  `targets` (config-declared first) — and Potato rendered its dropdown from the
  second while defaulting from `target_ids[0]`.  On a project whose config order
  differs from its metadata order the two surfaces disagreed, and Potato's
  selected target was not even its own dropdown's first entry.  Potato now
  defaults from the same list the SPA's `/api/targets` serves.

### Changed

- **Static assets are compressed and memoized.** `detail.js`, `app.js`,
  `style.css`, `print.css`, `van.min.js`, `favicon.svg` and the three
  `hljs` files were served raw by `static_file`; they now ship with the same
  content negotiation as every other response, compressed once per encoding at
  maximum brotli effort and cached for the process. `detail.js` drops from
  25 KB to 9 KB on the first-paint path and the asm-pane set from 153 KB to
  45 KB.  Requests without a supported `Accept-Encoding` still fall through to
  `static_file`, so Range and `If-Modified-Since` behave as before.
- **Cell JSON no longer carries `cells.id`.**  No consumer read it, and as the
  only high-entropy column per row it was defeating compression: the 39k-cell
  `.text` payload goes from 322 KB to 74 KB on the wire (a 39k-cell section's
  full-target payload from 518 KB to 124 KB).  The projection is now the shared
  `rebrew.workspace.CELLS_JSON_OBJECT_SQL`.
- **`/data` and Potato read rebrew's materialized objects.**  The per-section
  cell JSON (`section_cells_json`, schema v7) and coverage buckets
  (`section_cell_stats`) are read directly instead of being re-derived, and the
  server falls back to the equivalent live queries when a database predates
  them, so a v6 database keeps serving.  The cache's codec is identified by its
  column name (`cells_zstd`), not by `db_version`, so a table written in an
  older codec is declined rather than mis-decoded.  Cold `/data` build:
  24.8 ms → 3.4 ms for one section and 38.9 ms → 6.8 ms for all sections, with
  payloads identical apart from the `db_version` stamp.
- **Schema v7 accepted.**  `known_schema` in the `/data` payload now advertises
  `3`–`7`, so a v7 database is not reported as an unknown schema.
- **`/stats` reads the materialized coverage buckets.**  Per-section byte
  counts come from `section_cell_stats` in one query instead of a 13-branch
  `CASE` aggregate over every cell, falling back to that aggregate for a
  database without the table.  Cold `/stats`: 17.1 ms → 7.2 ms (p95 19.0 →
  8.5 ms), field-for-field identical — `exact_count` still counts only
  `'exact'`, while the grid legend keeps folding `'verified'` into it.
- **The SPA's detail panel fills in when you select something.**  At first
  paint nothing is selected, so the three code panes used to lay out stand-in
  text and copy buttons for nobody; the panel body now holds one muted line
  until there is a selection.  The boot layout walks 147 objects instead of
  205 and the document starts 58 nodes smaller.  Selecting a block, a
  function, or a `?fn=` deep link renders the panes as before.

## [1.4.1] - 2026-09-16

### Fixed

- **SPA progress stats never clip.** The stats sit above the bar as wrapping
  plain text and the bar is a slim 14px segment strip, so every viewport —
  1440px desktop to 390px phone — shows `size · matched · coverage %` where
  the old in-bar overlay truncated mid-word.
- **SPA Copy/Open stay disabled on empty panes.** Copying `(select a
  function)` or opening a modal of it is never useful; the buttons disable
  with a "Select a block first" hint until a real selection lands (and while
  `detail.js` is still loading).
- **Canvas map no longer paints a phantom row.** Sections whose cells fill
  the last row exactly rendered one extra blank row (~250px of empty grid on
  the test DB). Row count now matches the layout walk.
- **Potato progress bar fits phones.** The fixed 700px bar overflowed narrow
  screens and clipped its stats; it is fluid-width with the stats in a cell
  below, and the map header stats wrap to their own line.
- **Potato layout stacks map over panel.** The fixed 75/25 split forced the
  page past 500px on a 390px phone, clipping both columns; stacked, each
  takes the full width (like the SPA below 1300px). Grid cells are 12px.
- **Potato detail panel drops empty rows.** NULL/empty fields (`ghidra_name
  None`, `similarity None`, …) no longer bury the populated rows; the
  duplicate `Functions for .text` caption is gone; the legend is a
  two-column nowrap lattice; section tabs lead with `.text` (PE load order).

## [1.4.0] - 2026-09-15

### Fixed

- Python floor is now 3.13 (was 3.12): the required `rebrew` dependency
  raised its own floor, and fresh installs on 3.12 could no longer resolve.
  CI matrix and classifiers follow.

### Changed

- **Coverage map paints on a canvas.**  The SPA no longer builds one DOM node
  per cell (tens of thousands on a real target).  The map is packed into typed
  arrays and drawn in one pass; click, keyboard, tooltip, filters, and print
  still work.  First paint no longer waits on the original binary download.
- **`/data` skips a JSON round-trip of the cells table.**  SQLite already
  emits each section's cells as JSON; the envelope splices those arrays in
  instead of `json.loads` + `json.dumps` (~70 ms saved on an 80k-cell DB).
- **SPA first paint fetches one section.**  `GET /data?section=.text` still
  lists every section (tabs, stats) but omits sibling cell arrays; the map
  loads the rest when you switch tabs or jump to an address.
- **Potato grid merge avoids per-cell dict copies.**  One copy per merged
  output row instead of one per input cell; `?section=.text` stats query is
  filtered too (first paint `/data` 27 ms → 22 ms on a 64k-cell DB).
- **Canvas map caches layout and palette.**  Hit-map, row table, canvas size,
  and CSS palette are built once per section and reused; filter/search/focus
  repaints only redraw rects, and jump-to-cell scroll is O(1).  Repaint
  ≈ 21 ms med in Chromium on a 39k-cell map (incl. a frame wait).
- **Live reload no longer flashes the map.**  Background refresh (SSE
  `db-updated`, regen) keeps the old map visible and swaps when new data
  lands; the loading overlay and error panel are first-paint only.  Verified
  in Chromium: zero overlay flashes across a real rebuild.
- **Original binary loads on first click, not first paint.**  The multi-MB
  `/original` download moved from `loadData` to first cell selection, cutting
  first-load transfer ~3.2 MB → ~0.35 MB on a real target; the bytes pane
  shows loading state until the slice arrives.

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
