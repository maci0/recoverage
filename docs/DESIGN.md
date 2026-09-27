# ReCoverage UI Design Document

How the dashboard is built. The requirements it implements are
[USER_STORIES.md](USER_STORIES.md), the operating philosophies are
[DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md), and the attack surface is
[THREAT_MODEL.md](THREAT_MODEL.md). Last verified against the code: 2026-09-27.

## Overview
ReCoverage is a reactive, high-performance web dashboard for visualizing binary reverse-engineering progress. It maps compiled C functions and data segments (`.text`, `.rdata`, `.data`, `.bss`) to their original binary offsets, providing a visual "defrag" style grid of the decompilation status.

## Architecture
The UI is built using a lightweight, dependency-free stack to ensure fast load times and easy maintainability:
* **Frontend Framework**: [VanJS](https://vanjs.org/) (a ~2 kB reactive UI framework).
* **Styling**: Vanilla CSS with CSS Variables for theming.
* **Backend/Data**: [Bottle](https://bottlepy.org/) web framework serving a SQLite database (`coverage.db`).
* **Syntax Highlighting**: Highlight.js (C, x86 ASM, custom Hex language), vendored in `assets/` and served from this origin so the dashboard works air-gapped.

## Data Pipeline
1. `rebrew catalog` parses the target binary (`target.dll`) and C source annotations (`// FUNCTION:`, `// GLOBAL:`).
2. `rebrew build-db` converts the resulting JSON into a structured SQLite database with tables for metadata, functions, globals, sections, and cells. It also pre-calculates coverage statistics for all sections to save frontend processing time.
3. The Bottle app (`webapp.py` wires `server.py` + `api.py` + `ui.py` + `potato.py` into the fully routed application; importing `recoverage.server` alone yields a routeless app) serves:
   * Static files (index.html, app.js, style.css, van.min.js) which are **inlined and compressed** into a single response for the root `/` path to achieve a "first draw in the first TCP packet".
   * `/api/targets` endpoint that returns available targets from the database plus any target declared under `[targets.*]` in `rebrew-project.toml` (a configured-but-not-yet-built target stays addressable).
   * `/api/targets/<target>/stats` endpoint with per-section byte-based coverage statistics (shared implementation with the `recoverage stats` CLI).
   * `/api/targets/<target>/data` endpoint that queries SQLite for a specific target and returns lightweight metadata and section layouts (compressed via zstd/brotli/gzip).
   * `/api/targets/<target>/functions/<va>` endpoint to fetch specific function/global details on-demand, plus `GET`/`POST /api/targets/<target>/functions` for the paginated function list (`?status=&search=&sort=&limit=&offset=`) and batch lookups by VA list. The batch POST takes `application/json` (or any `application/*+json`); a declared non-JSON `Content-Type` is a 415 `unsupported_media_type`, an absent one is accepted.
   * `/api/targets/<target>/sections/<section>/bytes` endpoint serving raw hex-dumped byte slices from the original binary (`?offset=&size=`).
   * `/api/targets/<target>/asm?va=...&size=...` endpoint that dynamically disassembles binary chunks using Capstone (with LRU caching and in-memory cached binary reads).
   * `/api/events` Server-Sent Events stream that pushes a `db-updated` event whenever `coverage.db` changes on disk, so the SPA auto-refreshes without a manual reload (requires the threaded WSGI server, which gives each connection its own thread).
   * `/api/regen` POST endpoint to run rebrew's catalog + build-db in-process (`regen.run_regen`, gated on a loopback peer plus a same-origin `Origin` when one is sent, rate-limited). The rebuild is convergent, so a duplicate run converges rather than corrupts; an optional `Idempotency-Key` header turns a retry of an already-completed key into a ledger lookup instead of a second pipeline run (bounded by age and count in `api.py`).
   * With `--token`, an unauthenticated request is answered by content type: browsers asking for `text/html` get a short page explaining that `?token=` must be appended (it never echoes the token), and API clients keep the `{error, code, detail}` JSON contract. A run of failed tokens inside `_AUTH_FAIL_WINDOW_SECONDS` is throttled to `429` with `Retry-After`, which bounds online guessing on a network bind. A share link (`?token=`) authenticates once and `server.set_auth_cookie` writes the HttpOnly cookie both page routes need: every link on `/` and on `/potato` is relative, so without it the reader lost the credential on their first click.
   * Proxied paths: `/src/*` → `project_dir/src/`, `/original/*` → `project_dir/original/`

## State Management (VanJS)
The application state is managed using VanJS reactive primitives (`van.state`):
* `data`: Holds the fetched SQLite data (sections, globals, functions, summary).
* `originalDll`: The original DLL's raw ArrayBuffer for byte slicing, stored as `{path, buf}` so a target switch mid-download cannot install the previous target's bytes.  Fetched from `paths.originalDll` when the DB carries that metadata, otherwise from `/original/<target>.dll`, which the server proxies anyway; when neither exists the hex pane says so instead of failing silently.
* `activeSection`: Tracks the currently selected PE section (`.text`, `.rdata`, `.data`, `.bss`).
* `activeFilters`: A `Set` tracking which match statuses are currently visible (exact, reloc, near_match, stub, padding, proven, problem).
* `searchQuery`: The current text in the search input (debounced 250ms).
* `currentFn` / `currentCellIndex`: Tracks the currently selected block in the grid.
* `isLightMode`: Tracks the current theme (persisted to `localStorage` as `recoverage_theme`).
* `showModal` / `modalTitle` / `modalContent` / `modalLang`: Modal dialog state for expanded code viewing.
* `isLoading`: Tracks network request states to show a pulsing loading overlay.
* `activeTarget`: Current target ID (e.g., "SERVER", "Europa1400Gold").
* `availableTargets`: List of available targets fetched from `/api/targets`.
* `filteredFnNames`: Derived state for search filtering (Set of function names matching search query).
* `emptyState`: `{title, detail}` when there is no map to draw — no database, no sections, an unreadable schema version, or a failed fetch.  The map area renders it in place of the grid and suppresses the legend, hint, and progress bar, all of which describe a grid that is not there.  Every load path clears `isLoading`, including the early return when no target is selected: leaving it set was what produced a spinner that never stopped on first run.

  Note for future bindings: these render an empty `div()` rather than `null` when they have nothing to show.  A VanJS binding whose first result is `null` never renders again — van keeps no node to replace, so later updates are dropped.

### Async writes are generation-guarded

`loadData` has four independent triggers (first paint, target switch, SSE `db-updated`, regen) and fetches a multi-MB payload, so two calls routinely overlap.  The browser does not resolve them in issue order, so without a guard a slow response for the previous target lands after the new one and the map shows one target's data under another's name.

Each call therefore takes a generation number and an `AbortController`.  Only the call whose generation is still current may write `data`, `summaryData`, `activeSection`, the error panel, or `isLoading`; a superseded call writes nothing and lets the call that replaced it report the outcome.  `selectFunction` uses the same rule through its controller's `signal.aborted`.  Every state write made after an `await` belongs behind one of these two checks.

## Components
The UI is broken down into functional VanJS components. `app.js` builds the
shell (topbar, progress bar, and the containers for the grid and the panel);
the grid, the panel's body, and the modal are defined in `detail.js` and
mounted by the shell once it has loaded, as each section below marks.

### 1. Topbar (`header.topbar`)
* **Logo & Title**: Retro-futuristic "R" logo with CRT scanline effects.
* **Surface**: Opaque `--panel` with a 1px bottom border, no `backdrop-filter`. The topbar was the last translucent, blurred surface in the theme: over the near-black ground the blur showed nothing, and it repainted on every scroll frame, which is the same argument the sticky panel header already records for dropping its own blur.
* **Tabs**: Dynamic segment selectors generated from the active target's sections, ordered by ascending VA so PE load order (`.text`, `.rdata`, `.data`, `.bss`) holds and the section carrying the work leads, instead of an alphabetical row ending in `.text`.
* **ProgressBar**: A stats row (`size · matched · coverage %`) above a slim 14px segmented bar. The stats live outside the bar as plain text so they can never clip; the bar itself is a pure segment strip. **Every segment is a share of one denominator**: `.text` divides function counts by `totalFunctions` (its `matched` stat is a function count), every other section divides cell bytes by the section size. Padding is a cell state with no function counterpart, so it is a segment only on the byte-denominated bars; on `.text` those bytes are already inside the unmatched remainder, and adding them as a byte share of a function bar pushed the total past 100%. **Each segment is a filter toggle**, reachable by keyboard and carrying `aria-pressed`; segments under 0.5% are not rendered at all, since a zero-width toggle is a focus stop with nothing to point at.
* **Target Selector**: Dropdown to switch between targets (e.g., `SERVER`, `GOLD`, `GOLDTL`). Persists selection to URL (`?target=XXX`) and localStorage.
* **Search & Filters**: Debounced search input and toggleable filter buttons (All, E, R, M, S, P, V, X). V isolates `proven` cells and X the problem states, so every row the legend prints is reachable as a filter instead of only through a pixel. The set is written to the URL as `?filter=` (the parameter Potato Mode already used) on every toggle, so a filtered map survives a reload and can be shared; a name outside the set is dropped, since it would dim every painted cell and light no button.
* **Actions**: Theme toggle (sun/moon icons) and Reload data buttons with a 5-second cooldown to prevent spam.

### 2. Grid (`.map`, mounted by `detail.js`)
* A canvas map that always renders every declared column: the section's `columns` value is stored on the element as `data-cols` and drives the lattice, the row height, and the arrow-key row step. Narrow screens shrink the cells (floor 6px desktop, 12px phone) instead of re-wrapping them onto extra rows, which left a blank band under short sections. Reading the column count from one place is what keeps the track count, row height, and keyboard step from drifting.
* Cells are colored based on their status:
  * **Exact** (green) — byte-for-byte match
  * **Reloc** (blue/teal) — match after masking relocations
  * **Near-match** (yellow) — near-miss with structural differences (DB state `near_match`; legacy DBs may spell it `near_matching`, which renders identically)
  * **Proven** (bold cyan) — post-verify semantic-equivalence promotion (`proven`)
  * **Size mismatch** (yellow) — compiled size differs from the original (`size_mismatch`)
  * **Stub** (red) — far off or placeholder
  * **Padding** (silver) — alignment padding
  * **Problem** (violet) — tooling failures and unclassified annotations (`compile_error`, `extract_error`, `invalid_va`, `missing_file`, `missing_size`, `skip`, `unknown`, plus the data `drift` / `unchecked` verdicts)
  * **None** (gray) — undocumented block

  Data and thunk cells keep their DB states but render with the undocumented gray here: their dedicated purple/orange tints were removed together with the data/thunk filters. Potato Mode still colors those states.

  Every state `build_db` can write has a slot. An unlisted state used to fall through to the undocumented gray, which contradicted `/stats`: `covered_bytes` covers every state but `none`, and `verified` is folded into `exact_count`, so those bytes were counted as covered while drawn as gaps. `verified` therefore packs as an exact match; the problem states share one violet.
* **Grid Caching**: Each section's layout (cell walk, row packing, hit-map, canvas size) is computed once and cached, and only the active section is painted, making tab switching instantaneous even for sections with 6,000+ chunks.
* **Canvas Painting**: Each section's grid is a single `<canvas>` painted from precomputed per-cell rectangles, one batched path per state (~12 ms to ~2.6 ms at 39k cells), rather than thousands of individual DOM nodes.
* **Canvas-Based Filtering**: Filter and search dimming are a second alpha pass (`globalAlpha = 0.15`) over the same rectangles, not CSS class toggling and not a per-cell DOM walk.
* **Keyboard & semantics**: the canvas wrapper is a `listbox` carrying a single `tabindex="0"`, so the grid is one tab stop no matter how many thousands the section holds. The wrapper handles the keys itself: arrows move the selection (left/right by one, up/down by a full row), Home/End jump to the ends, Enter/Space select. The cells are painted, not DOM nodes, so the selection is a canvas stroke rather than an `aria-selected` attribute.

### 3. Side Panel (`.panel`, metadata grid and code panes mounted by `detail.js`)
* **Sticky Header**: The panel header stays visible while scrolling through long code blocks, on an opaque panel background (no backdrop blur: it is sticky, so a blur would repaint on every scroll frame over a grid of thousands of cells).  It sticks at `top: var(--topbar-h)`, a custom property app.js keeps in sync with the measured topbar height, and `.panel` uses `overflow: clip` rather than `hidden` so the sticky offset resolves against the viewport instead of a box that never scrolls.
* **Metadata Grid**: Displays key-value pairs in an auto-filling grid with tightened vertical spacing for a cohesive look:
  * VA (Clickable link that jumps to the corresponding address in the grid)
  * Size, Offset, Symbol, Status, Module, Compiler flags, Marker type
  * Ghidra/radare2 names (if different from primary name)
  * SHA256 hash (for matched functions)
  * Type badges: "IAT thunk (not reversible)", "Exported function"
  * Parent function link: For data and thunk cells, a clickable link to the parent function that owns the data block
* **Source Links**: Clickable links to the original `.c` files.
* **Copy Buttons**: "Copy VA" and "Copy Symbol" in the panel header.
* **Code Blocks**: Three distinct sections for **C Source**, **Assembly** (or **Data Inspector**), and **Original Bytes** (hex dump). Each features a custom hexagon logo and has:
  * **Copy** button to copy content to clipboard
  * **Open** button to launch a centered modal for expanded viewing
* **Data Inspector**: When viewing `.rdata`, `.data`, or `.bss` sections, the Assembly view is replaced by a Data Inspector that instantly interprets the raw bytes as `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`, `float32`, `float64`, and `string (ascii)`.
* **Documentation**: Extracts annotation comments from C source (`// FUNCTION:`, `// STATUS:`, `// NOTE:`, `// BLOCKER:`, etc.) and displays them in the metadata grid.

### 4. Modal (`modal`, mounted by `detail.js`)
* Custom-built modal using plain VanJS divs (no external UI library)
* Focus moves to the Close button on open, retried across frames because the class that reveals the dialog is applied by van's batched update and `focus()` on a still-hidden element is a no-op
* Everything outside the dialog is marked `inert` while it is open, which removes the background from both the tab order and the accessibility tree
* Centered, floating dialog with backdrop blur
* Displays expanded C source, ASM, or hex bytes
* Copy button and Close button
* Smooth scale/fade animation on open/close

### 5. Legend & Hint
* Color legend showing status → color mapping
* Usage hint: "Click a block to view function details. Use filters to show specific statuses."

## Styling & Theming
* **CSS Variables**: Core colors are defined in `:root` (e.g., `--bg`, `--panel`, `--text`, `--border`).
* **Dark Mode (Default)**: Cool slate/cyan/blue hacker aesthetic (`#0f1216` background) with subtle CRT glow effects (text-shadows and box-shadows using cyan `rgba(6, 182, 212, 0.3)`).
* **Light Mode**: Triggered by the `.light-mode` class on the `body`. It re-grounds the same neutral family a shade short of the accent (`#c3ccd0` background, `#dbe3e5` panels) rather than inverting the dark theme: a stock blue-gray ground put a second hue between the surface and a cyan accent, and the two renderers disagreed about what color a border is. Light mode also drops the two phosphor effects rather than fading them, a cyan text bloom behind every glyph and a diffuse box-shadow halo, and replaces the latter with a tight tinted ring: a hover mark wants an edge, and bloom on a light ground reads as blur.
* **CRT Scanlines**: A global scanline overlay (`body::after`) using a hard-stop linear gradient tiled every 3px. It is dark-mode only, at `0.05` opacity: the line is the dark ground's texture, and over a light one it reads as dirt on the screen. `body.light-mode::after` removes it.
* **Match Status Colors**:
  * **Exact**: Green (`rgba(16, 185, 129, 0.75)`)
  * **Reloc**: Blue/Teal (`rgba(2, 132, 199, 0.65)`)
  * **Near-match**: Yellow/Amber (`rgba(255, 200, 0, 0.65)`)
  * **Size mismatch**: Yellow/Amber, the same hue as near-match (the SPA's `STATE_ID` packs both to slot 3)
  * **Proven**: Bold Cyan (`rgba(6, 182, 212, 0.65)`, `--proven-bg`)
  * **Stub**: Red (`rgba(255, 0, 0, 0.65)`)
  * **Padding**: Silver (`rgba(200, 200, 220, 0.55)`)
  * **Problem**: Violet (`--other-bg`, `rgba(168, 85, 247, 0.55)`, the same `#a855f7` Potato Mode uses)
* **One palette, not two**: every other color is drawn from the same source. Status badges tint their fill with the state hue at 0.2 alpha (border 0.4) and take their text from the same hue, lightened where 4.5:1 needs it. Links use the cyan family (`--link`), not a stock blue. The highlight.js theme in `assets/hljs.css` reads the app tokens by `var()` rather than restating their hexes — `--text`, `--muted`, `--link`, `--badge-stub-text` for keywords, `--badge-near-text` for strings, `--badge-exact-text` for names, `--c` for section markers — so a code pane follows a palette change instead of trailing one release behind it. Four values are the deliberate exception, a lightened step of a status hue that clears 4.5:1 as 12px text where the cell fill's own value does not; the file says which. Potato Mode derives its own colors from its module constants (`BG_COLOR`, `PANEL_COLOR`, `TRACK_COLOR`, `BORDER_COLOR`); no hex literal in `potato.py` is a stock framework neutral.
* **Transitions**: Smooth `0.3s ease` transitions on background colors, borders, and opacities ensure fluid theme switching and filter toggling.
* **Scrollbars**: Custom WebKit scrollbars styled to match the active theme, with `scrollbar-gutter: stable` applied to code blocks to prevent layout shifts.
* **Loading Overlay**: A pulsing, vertically-centered overlay on an opaque `--panel` ground, with large text (`font-size: 32px`, `font-weight: 700`), provides immediate visual feedback during data fetches. It carries no `backdrop-filter`: it sits over the lattice, and a blur there re-filters on every repaint of the grid beneath it. The pulse is the signal.
* **Print**: `assets/print.css`, linked with `media="print"` so it costs nothing at first paint.  Paper drops the controls, the scanline overlay, and the copy/open affordances, keeps the status colours (`print-color-adjust: exact`), unclamps the code panes, and appends link targets after source links.
* **Favicon**: `assets/favicon.svg`, matching the retro-futuristic "R" logo with a cyan glow and scanline pattern.  It is a served file rather than an inline data URI so it stays out of the first-packet budget.
* **Responsive**: Two-column layout on wide screens, single-column below 1300px.  Below 700px the topbar stops being sticky (its wrapped controls would otherwise hold a quarter of a phone viewport for the whole scroll).  Under `pointer: coarse` the controls grow to a 44px hit area; the progress bar stays slim, and its filter segments keep the desktop size.
* **Reduced motion**: `prefers-reduced-motion` kills animation and transition durations globally, but the loading overlay keeps an opacity-only pulse: it is the only "still working" signal during regen, and removing motion should not remove feedback.
* **Contrast**: text-bearing tokens clear 4.5:1 on the surface they sit on, in both themes.  `--c` doubles as the focus-ring colour, so its light-mode value is tuned for text contrast rather than the 3:1 non-text floor.

## Key Implementation Details

### Request Observability
* **One request, one id.** `server._start_request` (a `before_request` hook registered ahead of the auth hook) mints an id, or takes the caller's `X-Request-ID` when one is sent, and `server._finish_request` (an `after_request` hook) echoes it on the response, times the handler, and files the outcome.  A logging filter on the `recoverage` logger stamps the id onto every record as `[rid=...]`, and the CLI format defaults the field to `-` for records from loggers the app does not own (bottle, rebrew).  The id stays on the thread-local after the hook returns on purpose: bottle runs the 500 handler after `after_request`, and its traceback line is the one that has to be correlatable.  A caller's id is capped at 64 characters and control-char escaped, so it cannot forge log lines or bloat the log.
* **Status, not intent.** The counters record what the client got, which is not always what the hook could see: bottle hands an escaped exception to the error handler only after `after_request` has run, so a request that ends in a 500 or a 503 was counted as the 200 it was still carrying.  `_handle_unexpected_error` therefore calls `_reclassify_request` with the status it is about to answer, which is the only thing keeping the error rate from reading zero while the database is corrupt or mid-rebuild.
* **RED counters, in process.** `metrics.RequestStats` keeps totals, 5xx count, slow count, in-flight count, the latency extremes, and breakdowns by status class and by route.  Routes are keyed by the bottle rule that matched (`/api/targets/<target>/data`), never by the raw path, so the map cannot be grown by a caller inventing target names.  A request that matched no rule has no such key and falls back to its first path segment, which the caller chose; `ROUTE_LABEL_MAX` caps the map, and a fallback is dropped rather than admitted to a full one.  Oldest-first eviction on its own is not enough: 64 invented first segments would push out a real route row and blank the breakdown, so the two kinds of label are treated differently.  A dropped fallback still counts in the totals and in the status buckets.  `/api/events` is excluded from the latency numbers because its response is held open by design and its "duration" is connection lifetime.  The snapshot is read by `/api/health` and reset with the process; there is no metrics backend to configure, and keeping every sample for percentiles would cost more than the number is worth on a single-process dashboard.
* **The pipeline is not a request.** A regen runs for minutes, so the per-request numbers are one sample and none at all while it is still going, and nothing in them says the in-flight request is a rebuild.  `metrics.RegenStats` tracks runs, failures, refusals, in-flight count, and the last duration, on the same in-process `/api/health` snapshot.  A refused POST (`_REGEN_LOCK` held, or inside `_REGEN_COOLDOWN_SECONDS`) counts under `rejected` rather than `failures`: the SPA throttles Reload clicks, so refusals are routine and counting them as failures would report a broken pipeline for a double-clicked button.  Every `_do_regen` outcome closes out the counters through one place, so the elapsed time in the log line and the one in the snapshot are the same read.
* **Saturation, not just errors.** `/api/events` pins a server thread per connected client for the life of the stream and answers 503 to the connection after `_SSE_MAX_CLIENTS`.  That refusal is logged with the count that caused it (a health snapshot says the cap is full, not that it has been full since 10:04), and `/api/health` reports `streams.clients` against `max_clients` so the distance to the refusal is visible before a tab hits it.  A registered client whose watcher thread is not alive answers `degraded`: every page still renders and none of them will ever refresh, which a `healthy` 200 would hide.
* **Noise floor.** The per-request line is DEBUG (one line, on completion, carrying status and duration, which is everything the old line on the way in lacked).  Past `metrics.SLOW_REQUEST_MS` (1 s, above the slowest cold read the dashboard makes) it is one WARNING line, which is the only per-request line an operator running at the default INFO threshold can act on.
* **Log lines carry a date and an offset.** The `asctime` field is formatted `%Y-%m-%d %H:%M:%S%z`, not a bare time of day: `HH:MM:SS` cannot place a line on a timeline (23:59 and 00:01 read alike) and prints the repeated hour of a fall-back transition twice with nothing to tell the two apart.  Elapsed times never come from this stamp, only from `clock.monotonic()`; see *Clocks and Instants*.

### Clocks and Instants
* **One module owns every clock read.** `clock.py` exposes exactly two: `monotonic()` for elapsed-time arithmetic (request durations, the regen cooldown, the idempotency-key TTL, the auth-failure window, SSE heartbeats and the poller's wait) and `wall_time()` for a stamp a human reads.  Nothing under `src/recoverage/` calls `time` directly.  The split is the correctness rule: an NTP step or a manual clock change must not be able to make a duration negative or a cooldown expire early, and a monotonic reading is never persisted or shown to anyone.
* **Nothing is scheduled against a wall clock.** There is no cron, no daily rollup, and no "tomorrow" anywhere in the package, so no surface depends on a wall-clock time that a DST transition or a year boundary can move.  The one wall-clock instant the server publishes is the DB freshness stamp, and it is the file's own mtime, not a clock reading: a rebuild changes it because the file changed, and the server's clock is not involved.
* **A nanosecond mtime is converted with integer arithmetic.** `server.mtime_ns_to_utc` is the one definition both freshness surfaces use (`/api/health`'s `mtime_utc`, Potato Mode's footer).  `datetime.fromtimestamp(mtime_ns / 1e9)` looks equivalent and is not: a float second holds about 15 significant digits, so it cannot hold a nanosecond, and `fromtimestamp` rounds to the nearest one — a file stamped `12:34:59.999999999` was reported as `12:35:00`, a rebuild announced before it happened, and Potato's `HH:MM` rendering carried that into the displayed minute.  Whole seconds plus a microsecond remainder truncate, which is the only direction a freshness stamp may err in: the data served never lags the stamp that describes it.  The epoch float and the ISO string come from that one conversion, so the two fields in the same JSON object cannot disagree.
* **Instants are published in UTC with the offset spelled out.** `mtime_utc` is always `+00:00` regardless of the host's `TZ`, so a client never has to guess a zone, and a server moved between regions renders the same instant.  The log stamp is the exception, deliberately: it is local time with its numeric offset attached (`%z`), because an operator comparing it against their own wall clock needs to see their own clock, and the offset is what makes that comparison unambiguous across a DST change.

### Performance Optimizations
* **First Draw in First TCP Packet**: `ui.py` intercepts requests to `/` and inlines `index.html`, `style.css`, `app.js`, and `van.min.js` into a single response. This response is minified (using `rjsmin` and `rcssmin`) and compressed to the smallest representation the client accepts (see *Smallest-Wins Static Compression* below), which for every current browser is brotli at 14,075 B, inside the initial congestion window (10 x 1460-byte MSS), so the browser parses and renders the UI shell without any render-blocking network request.  The headroom is deliberately thin: `app.js` builds the whole UI (`index.html` carries no static markup), so a new byte has to come out of `detail.js` rather than out of the window, and `ui._check_payload_budget` prints the exact overage if the shell does outgrow it while `tests/test_api.py` fails on it, so crossing the window is a regression and not only a log line.  That leaves 525 bytes of headroom today.
* **Smallest-Wins Static Compression**: The precompressed responses (the inlined shell and the packaged assets) are not served under a fixed encoding preference.  Every encoding the client accepts is produced at maximum effort and the smallest body wins, because those bytes are compressed once per accepted set and then served from a dict, so the extra passes cost nothing per request and guarantee the winner is the real minimum.  This matters on the wire: measured on the shell, brotli q11 gives 14,075 B against zstd's 15,178 B at level 19 and 17,056 B at the level the dynamic path uses.  A fixed `zstd`-first preference therefore handed every zstd-capable browser 1,103 B more than necessary and pushed the shell 578 B *past* the congestion window, costing a whole extra round trip before the first paint to buy decoding speed on a one-off document.  Static zstd runs at level 19 (where it stops returning a smaller frame on these bodies) and static gzip at 9.  The dynamic path keeps its fixed order and its cheap settings, because there a preference avoids compressing one multi-megabyte request body two or three ways per request.  Brotli is what buys the budget on this shell: zstd is 15,178 B and gzip 15,686 B, both past the window, so a client accepting neither needs a second round trip whatever the server does. Every browser that has zstd also has brotli, so no browser shipping today is in that position.
* **Advanced Compression**: Dynamic responses compress brotli at quality 5, not the default 11: measured on a 5.6 MB coverage payload, q=11 costs 5.9 s of CPU for 334 KB while q=5 costs 68 ms for 444 KB, and that cost is paid per request because API responses are not cached compressed.  Clients without zstd (Safari) would otherwise stall about six seconds on every load and every live reload.
* **Shell Revalidation**: The shell is built once from the package's own assets and cannot change under a running server, so it carries a strong `ETag` (from the source bytes and the chosen encoding) and answers `If-None-Match` with a 304.  It used to be the one response served `no-store` with no validator, which made it the only response in a dashboard visit that a repeat load could never skip: every reload re-downloaded all 14,075 B of it while `detail.js` and the rest answered 304.  `max-age` stays off for the same reason as on the assets below.
* **HTTP/1.1 Keep-Alive, Threaded Connections**: The server is wsgiref on a `ThreadingMixIn` server class, so each connection gets its own daemon thread — without that, the long-lived `/api/events` SSE stream would stall every other request. wsgiref itself is HTTP/1.0 and serves exactly one request per connection, so `devserver._KeepAliveRequestHandler` restores the stock `BaseHTTPRequestHandler` request loop and `devserver._KeepAliveServerHandler` announces 1.1. Measured over one connection: `/` (15,686 B), `detail.js`, `favicon.svg`, `/api/targets` and `/potato` all answered on a single socket, where each used to pay its own TCP handshake. Two rules keep the framing honest: a response with neither `Content-Length` nor `Transfer-Encoding` — the streamed `/api/events` and nothing else, since bottle sets `Content-Length` on every body it returns — is sent with `Connection: close`, because under 1.1 a client would otherwise read into the next response; and a connection idle between requests falls back to a 15 s deadline instead of the 120 s per-request one, so an open tab does not pin a handler thread.
* **ETag Caching**: The heavy `/api/targets/<target>/data` endpoint calculates an `ETag` from a WAL-aware snapshot of `coverage.db` (`mtime_ns` + size, folding in `-wal` so a rebuild that only committed to the WAL still invalidates; raw `st_mtime` served stale 304s). If the database hasn't changed, the server responds with a `304 Not Modified` (0 bytes), making page reloads instantaneous. Every other DB-derived read endpoint reuses that same `server._etag_or_304` tail over its own request identity: `/stats` (snapshot + target), `/asm` (snapshot + target, section, raw VA spelling, size, format) and `/sections/<s>/bytes` (snapshot + target, section, offset, size). The two surfaces that *render* the freshness time rather than key a cache on it (`/api/health`'s `db.mtime`/`db.mtime_utc` and Potato Mode's footer stamp) read the newest stamp across `coverage.db` and `-wal` through `server._newest_mtime_ns`, so a WAL-only rebuild moves them too, and both spell the instant in UTC rather than the host's zone.
* **Memo publish watermark**: every DB-derived memo (`/data` payloads, `/stats`, Potato's grid and section stats) is keyed on the snapshot taken *before* its queries run, so a rebuild committing mid-build would file a pre-rebuild payload under the post-rebuild key — after the `db-updated` broadcast had already cleared the memo, leaving it pinned until the next rebuild.  Each publish re-stats the DB and drops the write when the watermark moved.  The disassembly memo cannot re-stat (its source is the original binary, not the DB), so its key carries a generation counter that `clear_disassembly_cache()` bumps: a build already in flight writes its text under the retired generation and is never served again.
* **Static Asset Revalidation**: The packaged assets (`detail.js`, the `hljs*` bundles, `favicon.svg`, the stylesheets) carry a strong `ETag` derived from the file's bytes and the negotiated encoding, and answer `If-None-Match` with a 304.  They are served `no-cache`, so without a validator the browser re-downloaded the whole set on every visit: a repeat dashboard load re-fetched `detail.js` and a repeat asm-pane open re-fetched `hljs.min.js` plus its grammars.  Measured with brotli, the static half of a dashboard visit (`detail.js`, `print.css`, `favicon.svg`: 11,400 B) drops to 0 B, and so does the highlight bundle.  The encoding is part of the tag because brotli and zstd bodies are different representations, and `max-age` is deliberately not raised: the URLs are not content-hashed, so a package upgrade changes the bytes under the same name.
* **Request Cancellation**: The UI uses `AbortController` to cancel in-flight network requests if the user clicks through multiple cells rapidly, saving bandwidth and preventing race conditions.
* **Deferred Highlight.js**: The heavy `highlight.js` library and its CSS are not loaded initially. They are fetched from this origin (`/hljs.min.js`, `/hljs-c.min.js`, `/hljs-x86asm.min.js`) the first time a user clicks a code block.  A chunk that fails to load clears the in-flight memo, so the next code pane opened retries, and the pane says `(syntax highlighting unavailable — the code below is unhighlighted)` rather than leaving plain text with no explanation; the disassembly itself is untouched.
* **Deferred failure is visible, not silent**: `detailFailed` is set when `/detail.js` cannot be fetched.  The panes it owns say so, and every control that delegates to it (Copy, Open, Copy VA, Copy Symbol, Reload) goes `disabled` with the same message as its tooltip.  Optional chaining alone made each deferral crash-safe but user-hostile: the buttons looked enabled and did nothing.
* **Deferred detail rendering**: `detail.js` carries the grid (per-section canvas, layout walk, hit-map and painting), the panel's three code sections (hex logo, Copy/Open, the Data Inspector frame), the hex dump, the data inspector, the selected function's metadata grid, the C annotation extractor, the custom hex highlight language, the live-reload subscription, the regen/reload handler, the clipboard helper, and the code-viewer modal with its focus and `inert` handling: everything that is not needed to paint the first frame.  app.js keeps the modal's four states so the panel's Open buttons can set them; `window.RC.mountModal` attaches the dialog once detail.js lands. It is preloaded by the shell (`<link rel="preload" as="script">` in `index.html`, alongside a `as="fetch"` preload of `/api/targets`; the two lines together cost 9 brotli bytes) and requested by app.js on its last line, so the fetch overlaps the shell's own download instead of starting a round trip after it; that keeps the inlined shell inside the congestion window without a visible delay. app.js publishes `window.RC` for it to read and write; until it lands, the panes it owns show a loading message and resolve reactively when it arrives.
* **On-Demand Data Fetching**: The `/api/targets/<target>/data` endpoint only returns lightweight grid layouts and metadata. Detailed function information is fetched on-demand via `/api/targets/<target>/functions/<va>` when a user clicks a cell, drastically reducing memory usage and initial load times.
* **One Click Listener Per Section**: The grid is a canvas, so the click handler hit-tests a packed row/column map instead of attaching 2,500+ individual listeners.
* **Grid Caching & Canvas Repaint**: To handle sections with 6,000+ chunks (like `.bss`), the per-section layout is computed once and cached. Filtering, search, selection and focus changes only repaint from those cached rectangles.
* **Precomputed Cell Geometry**: Per-cell x/y/width and the row hit-map are computed once per layout and reused by every repaint, so the UI never recomputes geometry during a state change.
* **SQL-Side Cell Grouping**: Cells leave SQLite as one `json_group_array` string per section (`json_object` shapes each cell), not one row per cell, so a 25k-cell section crosses into Python as a handful of strings instead of tens of thousands of rows.  The projection deliberately omits `cells.id`: no consumer reads it, and as the only high-entropy column per row it cost 4.3x on the wire (the 39k-cell `.text` payload compressed 322 KB with it and 74 KB without).  The projection lives in `rebrew.workspace.CELLS_JSON_OBJECT_SQL`, shared by `build-db` and this server so the two cannot drift.
* **Precomputed Cell JSON and Section Stats**: `rebrew build-db` materializes the per-section cell JSON (`section_cells_json`, zstd level 3) and the coverage buckets (`section_cell_stats`, a view through schema v6 and a build-time table from v7).  Reading them costs ~0.3 ms where re-running the group-by cost 10.7 ms and re-aggregating the stats view cost 17.3 ms — together 92% of a cold `/data` build.  Measured cold `/data`: 24.8 ms → 3.4 ms for one section and 38.9 ms → 6.8 ms for all sections, with payloads identical apart from the `db_version` stamp.  Both are derived from `cells` and rebuilt whole on every build, so they cannot go stale between builds; recoverage prefers them and falls back to the live queries when a database predates them, so a pre-v7 database stays readable even though `build-db` itself requires `--force` to migrate it.
* **SQLite WAL Mode**: The database uses Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and read-only connections (`?mode=ro`), allowing the dev server to serve data concurrently without locking while the database is being regenerated in the background.
* **LRU Caching & Memory I/O**: The `/api/asm` endpoint uses Python's `@functools.lru_cache` to store disassembled chunks in memory. The target DLL is also read into memory once (with thread-safe locking), preventing redundant disk I/O and Capstone disassembly calls during a session.  The DLL memo is keyed by target alone, so it carries the `rebrew-project.toml` stat alongside: re-pointing a target's `binary` is an operator edit that reaches no server code and moves no DB file, and without that token `/asm` and `/bytes` served the replaced binary until the next `build-db`.  The same token keys the parsed config and the resolved target list, so the three config-derived memos cannot disagree about whether the file changed.
* **Progress Bar Rendering**: The progress bar uses `overflow: hidden` on the parent container to handle border-radius clipping, avoiding brittle JavaScript calculations for segment visibility.

### Dynamic Assembly & Clickable Links
* Assembly is generated on-demand by the backend using the `capstone` library when a chunk in the `.text` section is clicked.
* The frontend parses the highlighted assembly and converts hex addresses (e.g., `0x10003da0`) into clickable `<a class="asm-link">` tags.
* The `VA` field in the metadata grid is also a clickable link.
* Clicking an address automatically switches to the correct section tab, selects the corresponding chunk, updates the side panel, and smoothly scrolls the grid to bring the target chunk into view.

### Data Inspector
* For data sections (`.rdata`, `.data`, `.bss`), the UI uses a `DataView` to instantly parse the raw ArrayBuffer.
* It safely reads the first few bytes and displays them in various formats (integers, floats, and a 64-byte ASCII string scan) without requiring a backend round-trip.

### Hex Dump Formatting
Custom `formatBytes()` function displays 16 bytes per line with:
* 8-digit offset (hex)
* Two groups of 8 hex bytes
* ASCII representation (printable chars or `.`)

### Highlight.js Custom Language
Registered custom `hex` language with patterns for:
* Meta (offset): `^[0-9A-Fa-f]{8}`
* String (ASCII): `\|.*\|$`
* Number (hex bytes): `\b[0-9A-Fa-f]{2}\b`

### Original DLL Byte Slicing
On function/global selection:
1. Fetch original binary as ArrayBuffer (`/original/target.dll`)
2. Calculate raw file offset from VA using section info
3. Slice the relevant bytes and format as hex dump

### Documentation Extraction
`extractDocs()` parses C source for annotation comments:
```javascript
// NOTE:, // BLOCKER:, // FUNCTION:, // STATUS:, // ORIGIN:, // SIZE:, // CFLAGS:, // SYMBOL:
```

### Search & Filtering
* **Search**: Matches against function name, VA, and symbol (case-insensitive)
* **Filters**: Set-based toggling; progress bar segments are clickable to quick-filter
* **Dimming**: Non-matching cells are dimmed (opacity 0.15) rather than hidden, preserving grid layout.  Undocumented blocks dim too: they are not matches either, and exempting them left most of the map lit during a search

### Theme Persistence
* Checks `localStorage` for `recoverage_theme` ("light" or "dark")
* Falls back to `prefers-color-scheme` media query
* Theme changes are saved immediately

## Database Schema

The database is rebrew's `coverage.db` (see [DB_FORMAT.md](../../rebrew/docs/DB_FORMAT.md)). This server reads schema v3 through v10. v10 is the stamp current rebrew writes.

### Schema Compatibility

| Schema version | Recoverage support |
|---|---|
| v3 | Readable — v4 adds CHECK constraints and view fixes that do not affect reads of v3 data |
| v4 | Fully supported |
| v5 | Fully supported — `verify_results` gained `reg_delta` and `effective_match` |
| v6 | Fully supported — `functions` gained `updated_by`/`updated_at`, `globals` gained `status`, `history` gained `updated_by` |
| v7 | Fully supported. `section_cell_stats` became a table and `section_cells_json` was added, both materialized by `build-db` |
| v8 | Fully supported. `functions.status` is CHECK-constrained to the known status set. No new columns |
| v9 | Fully supported. `cells.state` is CHECK-constrained, and `metadata` gained `idx_metadata_key`. No new columns |
| v10 | Fully supported (current). The cell-state CHECK set follows `KNOWN_STATUSES`, so `extract_error` and `invalid_va` are stored as themselves. No new columns |

Recoverage performs a soft version check on every database open and logs a warning if the stored `db_version` is not one of the known-compatible versions (`3` through `10`). It never aborts on an unexpected version. `/data` carries the accepted set as `known_schema` so the SPA can tell a stale server from an empty database.

### Tables
* `metadata`: Key-value pairs per target — coverage summaries, paths, `db_version` stamp
* `functions`: All reversed functions — va (INTEGER), name, vaStart, size, fileOffset, status, module, cflags, symbol, markerType, files JSON, `detected_by` JSON, `size_by_tool` JSON, `textOffset`, ghidra_name, list_name, is_thunk, is_export, sha256, blocker, blockerDelta, size_reason, similarity
* `globals`: Global variables — va (INTEGER), name, decl, files JSON, `module`, `size`
* `sections`: PE sections — name, va, size, fileOffset, unitBytes, columns
* `cells`: Grid cells per section — section_name, start, end, state (none/exact/verified/reloc/near_match/stub/padding/data/thunk/proven/size_mismatch/drift/unchecked plus the tooling-failure group compile_error/extract_error/invalid_va/missing_file/missing_size/skip/unknown; legacy DBs may spell near_match as near_matching), functions JSON, label, parent_function
* `history`: Status change log (persistent, never dropped) — target, va, old_status, new_status, changed_at
* `verify_results`: Verification results (persistent, never dropped) — target, va, verified_at, byte_delta, diff_lines, similarity
* `section_cell_stats`: Coverage buckets per target+section — total_cells, exact_count, reloc_count, near_match_count, stub_count, padding_count, data_count, thunk_count, none_count, proven_count, size_mismatch_count, other_count.  `other_count` is the producer's catch-all for the states no named bucket claims (tooling failures, unclassified annotations, the data drift/unchecked verdicts), so `total_cells` equals the sum of the buckets; `/stats` and `/data` serve it as `other`, and their live-query fallback builds the same catch-all from the same state list, `verified` counted in `exact_count` on both paths, so the two sources cannot disagree and the bucket sum reconciles with `total_cells` either way.  A `section_cell_stats` written before that column reports `other: 0` rather than omitting the key.
* `section_cells_json`: Per target+section cell JSON, pre-aggregated and zstd-compressed — target, section_name, `cells_zstd`

### Views
None as of schema v7.  `section_cell_stats` **was** a view; from v7 `rebrew build-db` writes it as a table, because as a view every reader re-aggregated the whole `cells` table (13 `SUM(CASE state = …)` over 64k rows ≈ 17.3 ms per request).  A v6 database still carries the view and is still *served*: every consumer queries it as `SELECT … FROM section_cell_stats WHERE target = ?`, which is indifferent to table-vs-view.  (`build-db` itself needs `--force` to move such a database to v7.)

### Derived objects
`section_cell_stats` and `section_cells_json` are both derived from `cells` and rebuilt whole by `rebrew build-db`.  `build_db` is the only writer of `cells`, so neither can go stale between builds.  Both are named in the v7 integrity check, which is what makes the `db_version` stamp meaningful; the live-query fallback is what keeps a pre-v7 database readable.  The blob codec is identified by its column name (`cells_zstd`), not by the version, so a cache written in an older codec is declined rather than mis-decoded.

Presence is not coverage.  A derived table can exist, carry the current codec, and still omit a section `cells` has (a scoped rebuild, or a database assembled by hand).  A reader that trusted presence dropped what the cache did not carry: the section vanished from `/stats` and the Potato map header, and `_dumps_with_cells` spliced an empty array, so the SPA and the grid painted a whole section as `none` bytes.  Every read therefore takes the union.  `_read_data_raw` already holds the section list inside the same pinned snapshot and passes it as `_cells_json_rows`'s `expected_sections`; the missing names are re-aggregated from `cells` (`server._live_cells_json_rows`, narrowed with an `IN` list so the gap does not re-scan the target).  `server.section_bucket_rows` does the same for `section_cell_stats`, once for every reader: `/stats` through `_per_section_buckets`, the Potato map header through `_compute_section_stats` and the `/data` payload through `_read_data_raw` each pass the section set they already hold as `expected`, and each reads only the columns it renders.  The extra query runs only when a section is actually missing, so the complete-cache path is unchanged.

Absent is not unreadable.  Every one of those fallbacks is scoped to a schema object the database does not carry, and each used to catch the whole `sqlite3.Error` to do it.  That widened "this is a pre-v7 database" to "this database cannot be read", so a locked or truncated `coverage.db` produced a correct-looking cells-derived payload with nothing in the log and nothing in the response to say the read had failed.  `server._is_absent_object` is the one test that separates them, and the derived-table readers route through it: a `no such table`/`no such column` degrades, anything else propagates to the 503 `db_unavailable` contract that `/stats`, `/data` and `/potato` already give the same database.  The two probes that never raise for a missing object need no branch at all — `PRAGMA table_info` and `pragma_table_info` both answer an unknown name with zero rows — so `_table_columns` and `_has_materialized_cells` lost their handlers outright.

### One response, one read snapshot

`coverage.db` is a WAL database and rebrew is its only writer, so a reader never blocks one.  What a reader can do is mix two builds: python's sqlite3 opens a deferred transaction per statement, so a multi-statement read that a `rebrew build-db` commits through answers with rows that no single build ever held.  `server.read_snapshot` is the fix — `BEGIN` a read transaction, roll it back at the end — and every reader that builds one answer from several statements takes it.  That is `server._section_stats` (`/stats`, `recoverage stats`), `api._build_data_raw` (`/data`), the paginated function list (the `total` beside the page it paginates), the two function lookup routes (`/functions/<va>` resolves through up to six statements before the `verify_results` read that becomes `last_verify`, and the batch POST runs one statement per table), and the whole `potato.render_potato` render, which is the widest window in the package: it reads metadata, sections, cells, `section_cell_stats`, functions, globals and the detail panels' `verify_results`, and building the grid takes long enough that the rebuild lands mid-page.  Unpinned, that page paired one build's section rows with the next build's cells, which is a grid whose coverage legend disagrees with its own bytes.

The pin is cheap precisely because the database is read-only and WAL: no writer waits on it, and the transaction is rolled back rather than committed.  Two tests record `connection.in_transaction` at every statement a handler issues (`TestLookupSnapshotsArePinned`, `TestRenderIsPinnedToOneSnapshot`), so dropping the pin fails the suite rather than silently reopening the window.

## Future Ideas / TODOs
* [ ] **Minimap**: A global minimap of the entire PE file on the side.
* [ ] **XREFs**: Show cross-references for data segments (which functions read/write to this `.data` block).
* [ ] **Diff View**: Integrate the `rebrew match --diff-only` output directly into the UI for "Near-match" and "Stub" blocks.
* [x] **Jump table absorption**: Switch/jump table bytes adjacent to functions are absorbed into the parent function's size rather than tracked as separate cells.
* [x] **Parent function linking**: Data and thunk cells automatically link to their parent function (detected via `func_end_va == data_start_va`).
* [x] **Ghidra label export**: `rebrew catalog --export-ghidra-labels` generates `ghidra_data_labels.json` from detected tables for round-trip sync.

---

# Potato Mode

Potato Mode is a pure HTML 5 alternative UI that works **without any CSS or JavaScript**. It's designed to work on severely constrained environments while providing near-visual-parity with the main VanJS dark-mode UI.

## Constraints
- **NO CSS** - All styling uses only HTML attributes (`bgcolor`, `cellpadding`, `cellspacing`, `border`, `background`, etc.)
- **NO JavaScript** - All interactivity uses plain HTML forms and links
- **HTML 5** - Uses `<!DOCTYPE html>` for modern parsing, with `lang="en"`, `<meta charset="utf-8">`, and a viewport meta so phones render at device width instead of zooming a 980px canvas out
- **Semantics within the constraint** - `<h1>`/`<h2>` carry the document outline (no `style=` attribute anywhere, which `tests/test_potato.py` enforces), and each grid cell's `alt` repeats its address range so links are individually identifiable rather than thousands named "none"

## Features
- **Full coverage grid visualization** with colored cells and cell merging for large blocks
- **Paginated grid** — a real `.text` section is ~25k cells, which unpaginated is ~7.7 MB of table markup and ~74k DOM nodes on exactly the weak clients this mode exists for.  Pages are 32 grid rows; `?page=N` navigates, and a selected `?idx=` pulls its own page into view
- **Section navigation** (`.text`, `.data`, `.rdata`, `.bss`)
- **Multi-select filters** (toggle multiple filters simultaneously)
- **Search functionality** (matches function name, VA, and symbol)
- **Segmented progress bar** (coverage breakdown by status)
- **A color and a legend row for every cell state** `build_db` can write, shared with the SPA's `STATE_ID` vocabulary.  A legend row covers every state that shares it, so a state with no row of its own still has a color and a filter
- **Cell selection with detail panel**
- **Target selector**
- **Data Inspector** for `.data`, `.rdata`, and `.bss` sections
- **Hex Dump** view for original bytes
- **Assembly View** via Capstone for `.text` cells
- **Global Variables** support
- **Annotation Extraction** (`// NOTE:`, `// BLOCKER:`, etc.)
- **Inline Images** (data URIs for retro CRT scanlines, gradients, and status dots)
- **W3C Nu HTML Validator** compliant

## URL Parameters
| Parameter | Description | Example |
|----------|-------------|---------|
| `target` | Target binary | `?target=SERVER` |
| `section` | PE section | `?section=.text` |
| `filter` | Comma-separated filters; both renderers read and write it | `?filter=exact,reloc` |
| `idx` | Cell index | `?idx=42` |
| `search` | Search query | `?search=adler32` |
| `view` | `functions` renders the function list instead of the grid | `?view=functions` |
| `sort` | Function list sort key (`name`, `va`, `size`, `status`) | `?sort=name` |
| `status` | Function list status filter | `?status=exact` |
| `page` | Grid page (32 rows per page) | `?page=2` |

## Filter Toggle Behavior
Each filter link toggles that filter on/off while preserving other active filters:
- Click `E` → shows only exact matches
- Click `R` with `E` active → shows exact + reloc
- Click `E` again → removes exact, shows only reloc
- The `All` pill removes all filters (`[Clear search]` clears the search box)

The keys are `exact`, `reloc`, `near_match`, `stub`, `padding`, `proven` and
`problem`, and a key stands for every cell state that shares its legend row,
not just for the state it is named after: `exact` also keeps `verified` cells
lit, `near_match` also keeps `near_matching` and `size_mismatch`, and `problem`
stands for all nine tooling-failure states. The SPA packs those states onto one
cell state before painting, so the two renderers dim the same cells. An
undocumented cell is never dimmed by a status filter; it is the ground the
statuses are read against.

## Color Scheme & Styling (matches main UI)
Cell states are the keys of `potato.COLORS`, spelled as `cells.state` spells them.

| Cell state | Color | Hex |
|------------|-------|-----|
| `exact`, `verified` | Green | `#10b981` |
| `reloc` | Blue | `#0ea5e9` |
| `near_match`, `near_matching`, `size_mismatch` | Yellow | `#f59e0b` |
| `proven` | Cyan | `#06b6d4` |
| `stub` | Red | `#ef4444` |
| `padding` | Silver | `#C0C0D4` |
| `data` | Purple | `#8b5cf6` |
| `thunk` | Orange | `#f97316` |
| `drift`, `unchecked`, `compile_error`, `extract_error`, `invalid_va`, `missing_file`, `missing_size`, `skip`, `unknown` | Violet | `#a855f7` |
| `none` | Dark Gray | `#3F4958` |
| Background | Dark | `#0f1216` |
| Panel | Slate | `#151a21` |
| Progress track | Dark Slate | `#22272e` |
| Code Block | Darker | `#0a0d14` |
| Border | Cyan-tinted | `#1c2a38` |
| Accent | Cyan | `#06b6d4` |
| Pane accent: C Source | Blue | `#3b82f6` |
| Pane accent: Assembly | Red | `#ef4444` |
| Pane accent: Data Inspector | Violet | `#a855f7` |
| Pane accent: Original Bytes | Green | `#10b981` |

The four pane accents are `potato.ACCENT_C_SOURCE`, `ACCENT_ASM`, `ACCENT_DATA`,
and `ACCENT_BYTES`, the same four values the SPA reads from
`--accent-c-source`, `--accent-asm`, `--accent-data`, and `--accent-bytes`.
Potato Mode spells them as constants because it has no CSS; the two lists are
pinned to each other by `TestSectionAccentsMatchSpa` in `tests/test_potato.py`,
so a pane cannot change hue in one renderer and not the other.

The status rows are `potato.COLORS`, one row per colour. A state `build_db` can write that this table does not name is a bug: the legend beside the grid would be short a row, and `tests/test_potato.py` fails on it.

### Typography
- **Body text**: `system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif` — proportional font for labels, headings, and UI chrome, matching the normal UI's body font stack.
- **Code & metadata values**: `SFMono-Regular, Consolas, Liberation Mono, Courier New, monospace` — used for section tabs, filter labels, code blocks, hex values, and VA addresses.

### Layout Parity with Normal UI
- **Stacked topbar**: Logo and section tabs share the first `<tr>`; search, target selector and the progress bar sit in a second `#controls` row (matches the normal UI's topbar, which wraps the same way).
- **Progress bar stats below the bar**: Coverage stats (`bytes · matched · %`) sit in their own row under the bar image, as in the SPA's stats row, rather than overlaid on it.
- **Topbar separator**: A 1px `#1c2a38` standalone table between topbar and layout, simulating `border-bottom: 1px solid var(--border)`.
- **Card wrappers**: Map and Panel sections use `border="1" bordercolor="#1c2a38"` to simulate the normal UI's card containers with subtle cyan-tinted borders.
- **Grid container**: The grid table is wrapped in an additional bordered table with `cellpadding="8"` and `bgcolor="#0f1216"`, simulating the `.map` card effect.
- **Panel header separator**: A 1px border row between "Block Details" header and panel body.
- **Grid cells**: a fixed 12px lattice, `cell_w` and `cell_h` in `_build_grid_html`. A sizing row of transparent `<td>`s carries the width so the browser allocates uniform columns. 12px keeps 64 columns at 768px, which scrolls on a phone rather than fitting it, the same trade the SPA's fluid bar makes; narrow sections render at the same size, so every section shares one predictable block size.
- **Status badge pills**: The section tabs and the filter pills are bordered `<table>` cells, the one pill treatment the retro constraints allow. The detail panel's State value is plain text in the status colour, because a table border can only take one fixed pair of colours and the state changes per block.
- **Thinner selected-cell highlight**: `border="1"` cyan outline on the selected cell (vs. the original `border="2"`).
- **Metadata label hierarchy**: Labels and values in the detail panel are both `<font size="1">`; the panel's column width carries the hierarchy. The function list's values are the `<font size="2">` ones.
- **Darker code blocks**: `bgcolor="#0a0d14"` for `<pre>` containers, matching `var(--code-bg)`.

## Implementation

Potato Mode uses [Bottle](https://bottlepy.org/) for both the dev server and HTML templating:

- **`server.py`** — shared Bottle application (`app`: hooks, auth, error handlers, CORS preflight catch-all) and infrastructure: compression (brotli/zstd/gzip), DB helpers, DLL loading, target resolution, and response utilities.
- **`disasm.py`** — the optional capstone capability: the loadability probe, the thread-local `Cs` handle, the per-slice memo, and its invalidation hook. The probe imports capstone once and memoizes the verdict, because `find_spec` answers "is a distribution on the path", not "does it load": a wrong-architecture wheel or a missing `libcapstone.so` used to reach the operator as a 500 traceback where `/asm` documents a 501, and `/api/health` advertised an extra the process could not use. Both renderers gate on that verdict, so a broken extra answers 501 with the reason (`/asm`) or omits the panel (Potato Mode). It reads target bytes through `server._load_dll`, so the two assembly renderers (`api.py`'s `/asm` and `potato.py`'s panel) depend on this module rather than on a capstone wrapper inside the transport module.
- **`regen.py`** — in-process rebrew regen (`run_regen`): loads `rebrew-project.toml` once and calls rebrew's `run_catalog` + `build_db` module functions; shared by the CLI's regen paths and POST /api/regen.  rebrew is a required dependency, but its catalog/build-db imports are deferred into `run_regen` so only the regen paths pay for the heavy rebrew stack.
- **`api.py`** — REST API routes (`/api/*`) with `@app.get`/`@app.post` decorators and `request` globals.
- **`ui.py`** — UI routes (`/`, static files) with index caching and minification (using `rjsmin` and `rcssmin`).  The inlined shell is compressed once per accepted-encoding set under `INDEX_LOCK` and served from `CACHED_INDEX_COMPRESSED` as `(body, encoding, etag)`, answering `If-None-Match` with a 304; the standalone assets (`detail.js`, the `hljs` set, CSS, favicon) take the same smallest-wins compression and are memoized per `(filename, accepted-encoding set)` in `_STATIC_CACHE`, falling through to `static_file()` only when the client advertises no supported encoding, so Range and `If-Modified-Since` still work there.
- **`webapp.py`** — composition root: imports `api`, `ui` and `potato` so their routes mount on the shared `app`; this is the module the CLI actually serves.
- **`potato.py`** — Potato Mode: the `/potato` route plus the renderer behind it.  It uses Bottle's `SimpleTemplate` engine (stpl) for the markup; only the thin route handler touches the Bottle web server.

### Template Architecture

Two compiled `SimpleTemplate` instances handle all HTML layout:

| Template | Purpose |
|----------|---------|
| `_PAGE_TPL` | Full page: topbar, section tabs, filter buttons, legend, progress bar, grid, panel container |
| `_PANEL_TPL` | Detail panel: function details, annotations, source code, assembly, hex dump, data inspector, globals |

Templates use `% for`/`% if`/`% end` control flow and `{{!expr}}` for raw HTML output. Business logic (SQL queries, cell merging, stats computation, syntax highlighting) stays in Python — only HTML structure lives in templates.

### Key Design Decisions

- **Filtering is visual dimming, not data exclusion.** The grid is a spatial map where position = memory address. All cells are always fetched from the DB; filtered cells render with a muted background color. This preserves spatial context and avoids grid layout disruption.
- **Grid and cell merging stay in Python.** The merging algorithm (adjacent same-state cells within a row) and per-cell dimming/selection logic are too complex for template loops.
- **Pygments highlighting stays in Python.** Token-level `<font color>` tag generation requires iterating over lexer output, which is cleaner as helper functions than inline template code.

## Testing
Run the test harness to verify all rendering paths:
```bash
uv run --locked python -m pytest tests/test_potato.py -v
```

This suite covers:
- All sections (`.text`, `.data`, `.rdata`, `.bss`)
- Single and multi-filter combinations
- Cell selection at various indices
- Invalid/unknown parameters (graceful fallbacks)

HTML validation is a separate gate: `bun run lint:html` (`tools/lint-html.py`) validates the static assets plus the served SPA shell and Potato Mode page.

Playwright comparison tests verify visual and behavioral parity with the main UI:
```bash
uv run --locked python -m pytest tests/test_playwright.py
```
