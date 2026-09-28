# ReCoverage UI Design Document

How the dashboard is built. The requirements it implements are
[USER_STORIES.md](USER_STORIES.md), the operating philosophies are
[DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md), and the attack surface is
[THREAT_MODEL.md](THREAT_MODEL.md). Last verified against the code: 2026-09-29.

## Overview
ReCoverage is a reactive, high-performance web dashboard for visualizing binary reverse-engineering progress. It maps compiled C functions and data segments (`.text`, `.rdata`, `.data`, `.bss`) to their original binary offsets, providing a visual "defrag" style grid of the decompilation status.

## Architecture
The UI is built to keep first paint cheap while carrying a canvas grid and a three-pane detail view:
* **Frontend Framework**: [Preact](https://preactjs.com/) through `preact/compat` (hooks and `createPortal`, React-shaped so shadcn/ui primitives work), authored in TypeScript under `web/app/` and built by Vite into the single `assets/app.js` bundle. Preact rather than React is most of why the inlined shell is ~48 KB brotli.
* **Build**: [Vite](https://vite.dev) library build (`web/vite.config.ts`) into one IIFE, `assets/app.js`, with `process.env.NODE_ENV` pinned to production. An IIFE rather than an ES module is what the classic `<script>` in the inlined shell can run.
* **Styling**: Tailwind CSS 4 compiled into `assets/style.css`, over a CSS-variable token layer (`--bg`, `--panel`, `--border`, the per-state fills) defined in `web/app/index.css`, which is what the light-mode overrides re-ground.
* **Backend/Data**: [Bottle](https://bottlepy.org/) web framework serving rebrew's clear-text coverage documents (`db/coverage-<target>.toml`).
* **Syntax Highlighting**: Highlight.js (C, x86 ASM, custom Hex language) imported from the npm package in `web/app/lib/highlight.ts` and compiled into the bundle, so a code pane never renders unhighlighted, the dashboard needs no network fetch to highlight, and it works air-gapped.

## Data Pipeline
1. `rebrew build-db` parses the target binary (`target.dll`) and C source annotations (`// FUNCTION:`, `// GLOBAL:`) in-process, then writes one clear-text TOML document per target (`db/coverage-<target>.toml`), holding the sections and their cells, the functions, the globals, the verify results, the history and `[metadata].paths`.  It stores no aggregate: `rebrew.coverage_toml` derives the per-section bucket counts, the per-section byte totals and the function stats at load, so the file and the reader cannot disagree about a number the file does not hold (see *Coverage Documents*).  There is no separate `rebrew catalog` step to run first; `rebrew catalog` is rebrew's own validation pipeline, and recoverage's regen calls the same `run_catalog` and writer the CLI command does.
2. The Bottle app (`webapp.py` wires `server.py` + `api.py` + `ui.py` + `potato.py` into the fully routed application; importing `recoverage.server` alone yields a routeless app) serves:
   * Static files (index.html, the built app.js and style.css) which are **inlined and compressed** into a single response for the root `/` path, so the first draw needs no render-blocking subresource request.
   * `/api/targets` endpoint that returns available targets found in the coverage directory plus any target declared under `[targets.*]` in `rebrew-project.toml` (a configured-but-not-yet-built target stays addressable).
   * `/api/targets/<target>/stats` endpoint with per-section byte-based coverage statistics (shared implementation with the `recoverage stats` CLI).
   * `/api/targets/<target>/data` endpoint that serves a specific target's snapshot and returns lightweight metadata and section layouts (compressed via zstd/brotli/gzip).
   * `/api/targets/<target>/functions/<va>` endpoint to fetch specific function/global details on-demand, plus `GET`/`POST /api/targets/<target>/functions` for the paginated function list (`?status=&search=&sort=&limit=&offset=`) and batch lookups by VA list. The batch POST takes `application/json` (or any `application/*+json`); a declared non-JSON `Content-Type` is a 415 `unsupported_media_type`, an absent one is accepted.
   * `/api/targets/<target>/sections/<section>/bytes` endpoint serving raw hex-dumped byte slices from the original binary (`?offset=&size=`).
   * `/api/targets/<target>/asm?va=...&size=...` endpoint that dynamically disassembles binary chunks using Capstone (with LRU caching and in-memory cached binary reads).
   * `/api/events` Server-Sent Events stream that pushes a `db-updated` event whenever the coverage documents change on disk, so the SPA auto-refreshes without a manual reload (requires the threaded WSGI server, which gives each connection its own thread).
   * `/api/regen` POST endpoint to run rebrew's catalog + build-db in-process (`regen.run_regen`, gated on a loopback peer plus a same-origin `Origin` when one is sent, rate-limited). The rebuild is convergent, so a duplicate run converges rather than corrupts; an optional `Idempotency-Key` header turns a retry of an already-completed key into a ledger lookup instead of a second pipeline run (bounded by age and count in `api.py`). Convergent is a claim about two runs in sequence. Two runs *concurrent* interleave, because the writer replaces each `coverage-<target>.toml` whole and a reader can land between one writer's truncate and its write, so `run_regen` holds an advisory lock (`.recoverage-regen.lock`) in the coverage directory for the length of the pipeline. That lock is what covers the duplicates this process's own `_REGEN_LOCK` and ledger cannot see: a `recovery regen` at a terminal beside a running dashboard, or a cron job over the same tree. A refusal is non-blocking (it exits 1, or answers 429) because the caller is a duplicate, not a queue; and the lock lives on an open descriptor, so a killed regen releases it rather than wedging the next one.
   * With `--token`, an unauthenticated request is answered by content type: browsers asking for `text/html` get a short page explaining that `?token=` must be appended (it never echoes the token), and API clients keep the `{error, code, detail}` JSON contract. A run of failed tokens inside `_AUTH_FAIL_WINDOW_SECONDS` is throttled to `429` with `Retry-After`, which bounds online guessing on a network bind. The window is per requesting peer: a shared one would let any unauthenticated client lock the operator out by never stopping, and would let the operator's own successful requests refill a guesser's allowance, so a verified request clears only the peer's own window. A share link (`?token=`) authenticates once and `server.set_auth_cookie` writes the HttpOnly cookie both page routes need: every link on `/` and on `/potato` is relative, so without it the reader lost the credential on their first click.
   * Proxied paths: `/src/*` → `project_dir/src/`, `/original/*` → `project_dir/original/`. Both are answered under a `sandbox`ed, `default-src 'none'` policy rather than the dashboard's own, because the content type is guessed from the file's suffix: an `.html` or `.svg` in the project tree would otherwise be a document at the dashboard's origin, under a policy that allows inline script.

## Frontend layering
`web/app/` is four levels, and every import runs downward: `lib/`, `grid/` and
`api.ts` are leaves (formatting and search folding, cell geometry, the fetch
surface), `hooks/` sits above them and is the only thing that fetches,
`components/` sits above that, `App.tsx` composes and `main.tsx` mounts. A
component takes what it needs from a hook as a prop or a type, never by calling
it, and nothing under `lib/` knows a hook exists. The bundler accepts any of
these directions, so `tests/test_frontend_import_graph.py` holds the order and
the acyclicity, the same rule `tests/test_import_graph.py` holds for the Python
package.

## State Management (Preact hooks)
`web/app/App.tsx` is the shell and owns the state the chrome needs; the rest
lives in hooks under `web/app/hooks/`. Preact `useState`/`useMemo`/`useRef`,
not a global store: the shell is the only subscriber, and the four data hooks
are the only things that fetch.
* `useCoverage(target, section)` (`hooks/useCoverage.ts`): the fetched snapshot as `sections`, `searchIndex` and `paths`, plus `loading`, `loadError`, a per-section `cellError` with an `ensureCells` lazy fetch, and `reload`. Every payload carries all section rows but only the requested one's cells, so a sibling tab fetches its cells on first visit; a tab that silently painted nothing would be unusable, so a failed fetch is remembered with the reason.
* `useOriginalBinary(path, enabled)` (`hooks/useOriginalBinary.ts`): the original DLL's raw ArrayBuffer, keyed on the resolved path so a target switch mid-download cannot install the previous target's bytes. Fetched from `paths.originalDll` when the document carries that metadata, otherwise from `/original/<target>.dll`, which the server proxies anyway; when neither exists the hex pane says so instead of failing silently. `enabled` is the first selection, not the resolved target: this is the page's largest download and only the byte pane reads it (see *Original DLL Byte Slicing*).
* `useSelection(...)` (`hooks/useSelection.ts`): the selected cell, its panes' fetch state, and the modal's `showModal` / `title` / `content` / `lang` state.
* `useLiveReload(...)` (`hooks/useLiveReload.ts`): the `/api/events` subscription, the Reload/Regenerate action, and its 5 s cooldown (`busy` while a run is in flight).
* Shell-local state in `App.tsx`: `targets` and the current `target` (persisted to URL `?target=XXX` and `localStorage`), `section`, the search `query` and its debounce (round-tripped through `?q=`), the `filters` `Set` (round-tripped through `?filter=`, a key outside the toolbar's list is dropped, since it would dim every painted cell and light no button), the selected cell index, the `theme` (`recoverage_theme` in `localStorage`, falling back to `prefers-color-scheme`), the nav `notice`, and the `loadError` banner. `foldedIndex` / `matchedNames` / `matchedFns` are `useMemo` derivations, not stored state. The rows of `searchIndex` are folded ONCE per index (`foldedIndex`, keyed on the index alone) and the query only substring-tests them, because folding per keystroke re-ran `normalize` + `toLowerCase` + the full-fold replace over every function in the target on every character typed, on the main thread, inside the render that keystroke triggered. The first paint is not blocked on the target list: `target` is seeded from `?target=` or from the remembered id in `localStorage` before the shell mounts, so `/data` and `/stats` leave in parallel with `/api/targets` rather than one round trip behind it, and `targetReady` then only validates the seed (replacing a remembered id the server no longer serves, which is what it already did). The shell cannot know the target id at all when neither carries one, and that is the only path the list answer blocks.

When there is no map to draw (no coverage documents, no sections, an unreadable format version, or a failed fetch), `useCoverage` reports it as `loadError` or `cellError` and the map area renders that message in place of the grid, suppressing the legend, hint, and progress bar, all of which describe a grid that is not there. Every load path clears `loading`, including the early return when no target is selected: leaving it set was what produced a spinner that never stopped on first run.

### Async writes are generation-guarded

`useCoverage.load` has four independent triggers (first paint, target switch, SSE `db-updated`, regen) and fetches a multi-MB payload, so two calls routinely overlap. The browser does not resolve them in issue order, so without a guard a slow response for the previous target lands after the new one and the map shows one target's data under another's name.

Each call therefore takes its own `AbortController`, and every state write made after an `await` sits behind that controller's `signal.aborted` check. A superseded call writes nothing and lets the call that replaced it report the outcome. `useSelection` uses the same rule, one controller per selection, because a newer selection supersedes an older one. Every state write after an `await` in `web/app/` belongs behind one of these two checks.

## Components
The UI is broken down into functional components. `web/app/App.tsx` is the
shell (topbar, search, filters, actions, and the containers for the grid, the
panel and the modal); each section below names the `web/app/components/` module
it is mounted from.

### 1. Topbar (`header.topbar`)
* **Logo & Title**: Retro-futuristic "R" logo with CRT scanline effects.
* **Surface**: Opaque `--panel` with a 1px bottom border, no `backdrop-filter`. The topbar was the last translucent, blurred surface in the theme: over the near-black ground the blur showed nothing, and it repainted on every scroll frame, which is the same argument the sticky panel header already records for dropping its own blur.
* **Tabs**: Dynamic segment selectors generated from the active target's sections, ordered by ascending VA so PE load order (`.text`, `.rdata`, `.data`, `.bss`) holds and the section carrying the work leads, instead of an alphabetical row ending in `.text`.
* **StatsStrip**: The row above the map: `size · matched · coverage %` as plain text, followed by one pill per cell state. The figures are the ones `/stats` serves, never a second division over the same counts, so the strip cannot disagree with the map beside it. **Each pill is the filter toggle for its state** (`STATE_FILTERS` in `web/app/grid/pack.ts`, the same table the toolbar is built from), reachable by keyboard and carrying `aria-pressed`; there is no separate segment strip, and no arithmetic over denominators to disagree with.
* **Target Selector**: Dropdown to switch between targets (e.g., `SERVER`, `GOLD`, `GOLDTL`). Persists selection to URL (`?target=XXX`) and localStorage.
* **Search & Filters**: A search input and toggleable filter buttons (All, E, R, M, S, P, V, X). V isolates `proven` cells and X the problem states, so every row the legend prints is reachable as a filter instead of only through a pixel. The set is written to the URL as `?filter=` (the parameter Potato Mode already used) on every toggle, so a filtered map survives a reload and can be shared; a name outside the set is dropped, since it would dim every painted cell and light no button.
* **Actions**: Theme toggle (sun/moon icons) and Reload data buttons with a 5-second cooldown to prevent spam.

### 2. Grid (`.map`, mounted by `components/CoverageMap.tsx`)
* A canvas map that always renders every declared column: the section's `columns` value is stored on the element as `data-cols` and drives the lattice, the row height, and the arrow-key row step. Narrow screens shrink the cells (floor 6px desktop, 12px phone) instead of re-wrapping them onto extra rows, which left a blank band under short sections. Reading the column count from one place is what keeps the track count, row height, and keyboard step from drifting.
* Cells are colored based on their status:
  * **Exact** (green) — byte-for-byte match
  * **Reloc** (blue/teal) — match after masking relocations
  * **Near-match** (yellow) — near-miss with structural differences (stored state `near_match`; a document may spell it `near_matching`, which renders identically)
  * **Proven** (bold cyan) — post-verify semantic-equivalence promotion (`proven`)
  * **Size mismatch** (yellow) — compiled size differs from the original (`size_mismatch`)
  * **Stub** (red) — far off or placeholder
  * **Padding** (silver) — alignment padding
  * **Problem** (violet) — tooling failures and unclassified annotations (`compile_error`, `extract_error`, `invalid_va`, `missing_file`, `missing_size`, `skip`, `unknown`, plus the data `drift` / `unchecked` verdicts)
  * **None** (gray) — undocumented block

  Data and thunk cells keep their stored states but render with the undocumented gray here: their dedicated purple/orange tints were removed together with the data/thunk filters. Potato Mode still colors those states.

  Every state `build_db` can write has a slot. An unlisted state used to fall through to the undocumented gray, which contradicted `/stats`: `covered_bytes` covers every state but `none`, and `verified` is folded into `exact_count`, so those bytes were counted as covered while drawn as gaps. `verified` therefore packs as an exact match; the problem states share one violet.
* **Grid Caching**: Each section's layout (cell walk, row packing, hit-map, canvas size) is computed once and cached, and only the active section is painted, making tab switching instantaneous even for sections with 6,000+ chunks.
* **Canvas Painting**: Each section's grid is a single `<canvas>` painted from precomputed per-cell rectangles, one batched path per state (~12 ms to ~2.6 ms at 39k cells), rather than thousands of individual DOM nodes.
* **Canvas-Based Filtering**: Filter and search dimming are a second alpha pass (`globalAlpha = 0.15`) over the same rectangles, not CSS class toggling and not a per-cell DOM walk.
* **One filter rule, and it reads the cell, not the slot**: `pack.ts`'s `survivesFilter(slot, ground, active)` is the map's whole status-filter rule, and Potato Mode's `_state_survives_filter` is the same rule over the raw state; `tests/test_server.py` (`TestSpaStateVocabulary`) runs one against the other cell for cell. The exemption for the undocumented ground is the reason it takes a per-cell `ground` column rather than reading the filter key off `FILTER_KEY[states[i]]`: palette slot 0 is a projection of THREE states (the ground plus the data and thunk states), and only the ground is exempt, so a rule keyed on the paint slot cannot express the difference. The three shared the slot, and therefore the empty filter key, correctly: a data or thunk cell is dimmed by every status filter in both renderers, and no pill isolates it.
* **Keyboard & semantics**: the canvas wrapper is a `role="application"` region carrying a single `tabindex="0"`, named by `aria-label` and described by the hidden key map, so the grid is one tab stop no matter how many thousands the section holds. It is deliberately not a `listbox`: that role promises `option` descendants a canvas cannot have. The wrapper handles the keys itself: arrows move the selection (left/right by one, up/down by a full row), Home/End jump to the ends, Enter/Space select. The cells are painted, not DOM nodes, so the selection is a canvas stroke, and the cursor's value is announced through a hidden `role="status"` paragraph instead of an `aria-selected` attribute.

### 3. Side Panel (`.panel`, metadata grid and code panes mounted by `components/CoveragePanel.tsx`)
* **Sticky Header**: The panel header stays visible while scrolling through long code blocks, on an opaque panel background (no backdrop blur: it is sticky, so a blur would repaint on every scroll frame over a grid of thousands of cells).  It sticks at `top: var(--topbar-h)`, a custom property `App.tsx` keeps in sync with the measured topbar height (a `ResizeObserver`, because the topbar wraps), and `.panel` uses `overflow: clip` rather than `hidden` so the sticky offset resolves against the viewport instead of a box that never scrolls.
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

### 4. Modal (`modal`, mounted by `components/CodeModal.tsx`)
* Rendered through `createPortal` into `document.body`, not into the panel: the modal makes the page behind it `inert`, and a dialog inside an inert region could not be focused
* Focus moves to the Close button on open, retried across frames because the class that reveals the dialog is applied by the batched update and `focus()` on a still-hidden element is a no-op
* Everything outside the dialog is marked `inert` while it is open, which removes the background from both the tab order and the accessibility tree
* Escape closes it, through one `closeOnEscape` handler so the listener added and the one removed are the same reference
* Centered, floating dialog over a dimmed backdrop
* Displays expanded C source, ASM, or hex bytes
* Copy button and Close button (the shadcn/ui `Button` primitive in `components/ui/button.tsx`)

### 5. Legend & Hint
* Color legend showing status → color mapping
* Usage hint: "Click a block to view function details. Use filters to show specific statuses."

## Styling & Theming
* **CSS Variables**: Core colors are defined in `:root` (e.g., `--bg`, `--panel`, `--text`, `--border`).
* **Dark Mode (Default)**: Cool slate/cyan/blue hacker aesthetic (`#0f1216` background) with subtle CRT glow effects (text-shadows and box-shadows using cyan `rgba(6, 182, 212, 0.3)`).
* **Light Mode**: Triggered by the `.light-mode` class on the `body`. It re-grounds the same neutral family a shade short of the accent (`#c3ccd0` background, `#dbe3e5` panels) rather than inverting the dark theme: a stock blue-gray ground put a second hue between the surface and a cyan accent, and the two renderers disagreed about what color a border is. Light mode also drops the two phosphor effects rather than fading them, a cyan text bloom behind every glyph and a diffuse box-shadow halo, and replaces the latter with a tight tinted ring: a hover mark wants an edge, and bloom on a light ground reads as blur.
* **Phosphor Glow, Not a Scanline Overlay**: the CRT effect is light, not a texture. Cyan text-shadows and box-shadows on the tokens that earn them, dropped in light mode; the only scanlines in the package are drawn into `assets/favicon.svg`, where a repaint per frame is not paid. An overlay across the whole page was dropped: at `0.05` opacity it was a repaint on every scroll frame for a texture no one could name.
* **Match Status Colors**:
  * **Exact**: Green (`rgba(16, 185, 129, 0.75)`)
  * **Reloc**: Blue/Teal (`rgba(2, 132, 199, 0.8)`)
  * **Near-match**: Yellow/Amber (`rgba(255, 200, 0, 0.65)`)
  * **Size mismatch**: Yellow/Amber, the same hue as near-match (the SPA's `STATE_SLOTS` in `web/app/grid/pack.ts` packs both to slot 3)
  * **Proven**: Bold Cyan (`rgba(6, 182, 212, 0.65)`, `--proven-bg`)
  * **Stub**: Red (`rgba(255, 0, 0, 0.8)`)
  * **Padding**: Silver (`rgba(200, 200, 220, 0.55)`)
  * **Problem**: Violet (`--other-bg`, `rgba(168, 85, 247, 0.55)` dark and `#6a3bc7` light, the same hue Potato Mode paints at `#a855f7`)
* **Cell fills are drawn per theme, not tinted per theme**: the eight fills above are alpha colours tuned to composite over a near-black ground. Over the light ground they washed out: a 0.65-alpha near-match landed at 1.0:1 against the map background, so an exact cell and a near-match cell read as the same pale wash and the map stopped being the signal. `.light-mode` therefore declares its own eight, deeper steps of the same hues, opaque rather than translucent, because a tint's value is whatever is behind it. Every one clears 3:1 against the surface a cell is painted on (`--grid-bg` over `--bg`, `#bdc6ca`), and the light text tokens are steps of these same hues.
* **One palette, not two**: every other color is drawn from the same source. Status badges tint their fill with the state hue at 0.2 alpha (border 0.4) and take their text from the same hue, lightened where 4.5:1 needs it. Links use the cyan family (`--link`), not a stock blue. The highlight.js theme in `web/app/index.css` reads the app tokens by `var()` rather than restating their hexes — `--text`, `--muted`, `--link`, `--badge-stub-text` for keywords, `--badge-near-text` for strings, `--badge-exact-text` for names, `--c` for section markers — so a code pane follows a palette change instead of trailing one release behind it. Four values are the deliberate exception, a lightened step of a status hue that clears 4.5:1 as 12px text where the cell fill's own value does not; the file says which. Potato Mode derives its own colors from its module constants (`BG_COLOR`, `PANEL_COLOR`, `TRACK_COLOR`, `BORDER_COLOR`); no hex literal in `potato.py` is a stock framework neutral.
* **Transitions**: Smooth `0.3s ease` transitions on background colors, borders, and opacities ensure fluid theme switching and filter toggling.
* **Scrollbars**: every scrolling region gets the standard thin scrollbar the theme's `--scroll-thumb` token names (`scrollbar-width`/`scrollbar-color`), so both engine families follow the palette.
* **Loading Overlay**: A centered, muted label on an opaque `--panel` ground gives immediate visual feedback during data fetches. It carries no `backdrop-filter`: it sits over the lattice, and a blur there re-filters on every repaint of the grid beneath it.
* **Print**: `assets/print.css`, linked with `media="print"` so it costs nothing at first paint.  Paper drops the controls and the copy/open affordances, keeps the status colours (`print-color-adjust: exact`), unclamps the code panes, and appends link targets after source links.
* **Favicon**: `assets/favicon.svg`, matching the retro-futuristic "R" logo with a cyan glow and scanline pattern.  It is a served file rather than an inline data URI so it stays out of the first-packet budget.
* **Responsive**: one breakpoint, Tailwind's `lg:` (64rem), and no `pointer` media queries. The topbar is a single flex row that wraps, the map takes the width it is given, and the two panes stack below it: `flex-col` becomes `flex-row` at `lg`, where the panel also takes a fixed 460px capped at 45vw.
* **Reduced motion**: the theme cross-fade is the only page-wide animation, and it sits inside a `prefers-reduced-motion: no-preference` wrapper, so a reader who asked for less motion gets the instant switch.
* **Contrast**: text-bearing tokens clear 4.5:1 on the surface they sit on, in both themes.  `--c` doubles as the focus-ring colour, so its light-mode value is tuned for text contrast rather than the 3:1 non-text floor. The cell fills are the 3:1 arm: they are graphics, they are the map, and each theme has its own set rather than one alpha set read over two grounds.

## Key Implementation Details

### Request Observability
* **One request, one id.** `server._start_request` (a `before_request` hook registered ahead of the auth hook) mints an id, or takes the caller's `X-Request-ID` when one is sent, and `server._finish_request` (an `after_request` hook) echoes it on the response, times the handler, and files the outcome.  A logging filter on the `recoverage` logger stamps the id onto every record as `[rid=...]`, and the CLI format defaults the field to `-` for records from loggers the app does not own (bottle, rebrew).  The id stays on the thread-local after the hook returns on purpose: bottle runs the 500 handler after `after_request`, and its traceback line is the one that has to be correlatable.  A caller's id is capped at 64 characters and control-char escaped, so it cannot forge log lines or bloat the log.
* **Status, not intent.** The counters record what the client got, which is not always what the hook could see: bottle hands an escaped exception to the error handler only after `after_request` has run, so a request that ends in a 500 or a 503 was counted as the 200 it was still carrying.  `_handle_unexpected_error` therefore calls `_reclassify_request` with the status it is about to answer, which is the only thing keeping the error rate from reading zero while a coverage document is unreadable or mid-rebuild.
* **RED counters, in process.** `metrics.RequestStats` keeps totals, 5xx count, slow count, in-flight count, the latency extremes and a bounded window of recent durations, and breakdowns by status class and by route.  Routes are keyed by the bottle rule that matched (`/api/targets/<target>/data`), never by the raw path, so the map cannot be grown by a caller inventing target names.  A request that matched no rule has no such key and falls back to its first path segment, which the caller chose; `ROUTE_LABEL_MAX` caps the map, and a fallback is dropped rather than admitted to a full one.  Oldest-first eviction on its own is not enough: 64 invented first segments would push out a real route row and blank the breakdown, so the two kinds of label are treated differently.  A dropped fallback still counts in the totals and in the status buckets.  `/api/events` is excluded from the latency numbers because its response is held open by design and its "duration" is connection lifetime.  The snapshot is read by `/api/health` and reset with the process; there is no metrics backend to configure. `p50_ms` and `p95_ms` are quantiles of the most recent `LATENCY_WINDOW` (512) timed requests, with `latency_window` reporting how many samples they were taken from: a mean over a mostly-fast window and a lifetime `max_ms` cannot tell one slow request from every request getting slower, and a bounded window answers the question an operator has during an incident (is it slow now) for one deque append per request and a sort only when health is polled. Each `by_route` row carries the same figures over its own window, which is the second half of the diagnosis: a process-wide p95 that moved names the process, and the row whose p95 sits at `SLOW_REQUEST_MS` names the endpoint. The per-route windows are bounded the same way (`ROUTE_LABEL_MAX` rows of `LATENCY_WINDOW` samples), so a caller cannot grow them.
* **The pipeline is not a request.** A regen runs for minutes, so the per-request numbers are one sample and none at all while it is still going, and nothing in them says the in-flight request is a rebuild.  `metrics.RegenStats` tracks runs, failures, refusals, in-flight count, and the last duration, on the same in-process `/api/health` snapshot.  A refused POST (`_REGEN_LOCK` held, or inside `_REGEN_COOLDOWN_SECONDS`) counts under `rejected` rather than `failures`: the SPA throttles Reload clicks, so refusals are routine and counting them as failures would report a broken pipeline for a double-clicked button.  Every `_do_regen` outcome closes out the counters through one place, so the elapsed time in the log line and the one in the snapshot are the same read.  An interrupted run (Ctrl+C at the terminal running `serve`) closes them on its own arm and re-raises: `in_flight` is a gauge, and nothing would ever close it again, so health would report a rebuild that is not running for the rest of the process.
* **Saturation, not just errors.** `/api/events` pins a server thread per connected client for the life of the stream and answers 503 to the connection after `_SSE_MAX_CLIENTS`.  That refusal is logged with the count that caused it (a health snapshot says the cap is full, not that it has been full since 10:04), and `/api/health` reports `streams.clients` against `max_clients` so the distance to the refusal is visible before a tab hits it.  A registered client whose watcher thread is not alive answers `degraded`: every page still renders and none of them will ever refresh, which a `healthy` 200 would hide.
* **The admission cap is visible too.**  `devserver._MAX_CONNECTIONS` is the widest of the three bounds and the one that was invisible: a server at it answers 503 to every new request, including a fresh tab, while the connections already open keep rendering, so a health probe reading the documents and the streams called that `healthy`.  `metrics.CONNECTIONS` is the single counter — the accept path takes and releases slots through it and `/api/health` reads it — so the admission decision and the published gauge cannot disagree.  `connections.refused` is a lifetime count and answers `degraded`, which separates a cap that has been full once from a server refusing everything since the operator last looked.  `connections.max` is 0 until the first admission, so a mounted WSGI app that never reached `serve` reports no cap rather than one it is not enforcing.
* **Transport rejections are logged like everything else.**  A request the HTTP layer refuses before a Bottle route exists — an over-long request line, a malformed one, an unsupported version, headers past the limit — reaches no handler, so nothing downstream logs it.  `http.server` funnels both access and error reporting through one `log_message`, which the handler overrides: the access half is dropped because the app already emits a per-request line with a request id, and the error half goes to the `recoverage` logger at WARNING with the peer address.  Left at the stdlib default, a client stuck in a rejection loop wrote unparseable lines to `sys.stderr` in another format while the rejection reached the client, and the operator reading the server's own log saw nothing.  There is no request id on these lines, and there cannot be: the id is minted in `before_request`, which a transport rejection never reaches.  The peer address is what stands in for it, since it is the only thing separating one misbehaving client from a scanner.
* **Noise floor.** The per-request line is DEBUG (one line, on completion, carrying status and duration, which is everything the old line on the way in lacked).  Past `metrics.SLOW_REQUEST_MS` (1 s, above the slowest cold read the dashboard makes) it is one WARNING line, which is the only per-request line an operator running at the default INFO threshold can act on.
* **Log lines carry a date and an offset.** The `asctime` field is formatted `%Y-%m-%d %H:%M:%S%z`, not a bare time of day: `HH:MM:SS` cannot place a line on a timeline (23:59 and 00:01 read alike) and prints the repeated hour of a fall-back transition twice with nothing to tell the two apart.  Elapsed times never come from this stamp, only from `clock.monotonic()`; see *Clocks and Instants*.
* **The counters' values ride on the lines too.**  The request id says WHICH request a line is about; the numbers an operator pivots from say how many.  `server.request_log_fields` builds the `extra=` for the request-path records (the per-request line, the 500, the 503 `db_unavailable`, the two security rejections) and `api._regen_log_fields` for the regen lifecycle, and `cli.StructuredFormatter` renders them after the message as `key=JSON` pairs, sorted, so a field value cannot forge a second field.  A record with no fields renders exactly as before, which is every record from a logger this package does not own.  Without them the pivot is a regular expression over prose, and a slow-request or 5xx anomaly in `/api/health` cannot be turned into the list of requests behind it.

### Clocks and Instants
* **One module owns every clock read.** `clock.py` exposes exactly two: `monotonic()` for elapsed-time arithmetic (request durations, the regen cooldown, the idempotency-key TTL, the auth-failure window, SSE heartbeats and the poller's wait) and `wall_time()` for a stamp a human reads.  No decision under `src/recoverage/` calls `time` directly.  The split is the correctness rule: an NTP step or a manual clock change must not be able to make a duration negative or a cooldown expire early, and a monotonic reading is never persisted or shown to anyone.
* **The log stamp comes from the seam too.** `%(asctime)s` renders `record.created`, which `logging` fills from `time.time()` when the record is built, so the one instant an operator reads on every line was the one wall-clock reading the module above did not own: a run driven from a single patched clock wrote two different stamps for the same event, and a replay of it could not be diffed against the run it replays.  `cli.ClockStampedFilter` re-stamps each record from `clock.wall_time()` as the handler takes it, which leaves `%(asctime)s` rendering `record.created` exactly as the format string says it does (a test that sets `created` by hand still reads its own instant back) and touches only the records that reach this process's stderr.  The stamp is then the instant the handler reached the record rather than the instant the caller built it, which is the same reading to within the emit for the unqueued `StreamHandler` it is attached to; nothing in the package orders, expires or rate-limits on `created`.  Pinned by `tests/test_cli.py` (`TestClockStampedFilter`), including that `_configure_logging` is where the filter is actually attached: a filter nothing adds is a class no run reaches, and the tests would pass against a seam production does not use.
* **The string-hash seed is pinned where the interpreter starts.**  CPython seeds `hash()` of a `str` from the environment once, at startup, so a `set` or `frozenset` iterates in a different order in every process.  Every value reaching an assertion, a served payload or a log line through an unsorted collection is then a coin flip, and two runs of one seed cannot be diffed against each other.  Pinning the seed does not make those collections sorted: it makes their order a function of the values alone, so a leak is a defect to find rather than noise to re-run.  It cannot live in a fixture, because the seed is read before any import this tree controls, so two places declare it and `tests/test_supply_chain.py` fails when they disagree: the Makefile's `PYTHON_HASH_SEED` (exported, so every local recipe sees it) and the test job's `env:`, which spells its pytest command out because the Windows runner has no make.
* **Nothing is scheduled against a wall clock.** There is no cron, no daily rollup, and no "tomorrow" anywhere in the package, so no surface depends on a wall-clock time that a DST transition or a year boundary can move.  The one wall-clock instant the server publishes is the coverage-freshness stamp, and it is the documents' own mtime, not a clock reading: a rebuild changes it because the files changed, and the server's clock is not involved.
* **A nanosecond mtime is converted with integer arithmetic.** `server.mtime_ns_to_utc` is the one definition both freshness surfaces use (`/api/health`'s `mtime_utc`, Potato Mode's footer).  `datetime.fromtimestamp(mtime_ns / 1e9)` looks equivalent and is not: a float second holds about 15 significant digits, so it cannot hold a nanosecond, and `fromtimestamp` rounds to the nearest one — a file stamped `12:34:59.999999999` was reported as `12:35:00`, a rebuild announced before it happened, and Potato's `HH:MM` rendering carried that into the displayed minute.  Whole seconds plus a microsecond remainder truncate, which is the only direction a freshness stamp may err in: the data served never lags the stamp that describes it.  The epoch float and the ISO string come from that one conversion, so the two fields in the same JSON object cannot disagree.
* **An unrepresentable mtime is clamped, not raised.** The mtime is filesystem input, so a restored tree, a bad RTC, a `touch -d` or a FAT volume can carry a value outside the years `datetime` spans (`os.utime` writes a year-10000 stamp on any Linux host).  `fromtimestamp` raises `ValueError` on one, which took `/api/health` and Potato's footer with it: a perfectly readable coverage directory reported as a broken server, over a stamp the clock cannot name.  The seconds are clamped to `datetime`'s range first, and the extremes are the right answer for a freshness surface — "as far from now as a timestamp can say" is what such an mtime means.  Pinned at `tests/test_api.py` (`TestHealthDbMtime`) and `tests/test_potato.py` (`TestDbUpdatedLabel`).
* **The socket deadline is per operation, not a budget for the connection.** `config.client_timeout`'s floor, the README, `.env.example` and a config test once claimed that a deadline under the SSE heartbeat closes a healthy `/api/events` stream.  It does not, and the claim was false in a way that mattered: it made a 5s floor look like a 15s rule, so the documented range and the documented reason contradicted each other.  A socket timeout bounds one `recv`/`send`, and an idle stream blocks on its event queue rather than on the socket, so the heartbeat interval never reaches the deadline.  What the value does decide is how slow a client may be before a write is cut mid-body, which is what the floor now says.  Pinned by `tests/test_lifecycle.py` (`TestClientConnectionDeadline::test_a_deadline_under_the_heartbeat_does_not_close_a_healthy_stream`), which drives the real handler stack with the deadline at a third of the heartbeat.
* **Instants are published in UTC with the offset spelled out.** `mtime_utc` is always `+00:00` regardless of the host's `TZ`, so a client never has to guess a zone, and a server moved between regions renders the same instant.  The log stamp is the exception, deliberately: it is local time with its numeric offset attached (`%z`), because an operator comparing it against their own wall clock needs to see their own clock, and the offset is what makes that comparison unambiguous across a DST change.

### Performance Optimizations
* **First Draw Without a Render-Blocking Request**: `ui.py` intercepts requests to `/` and inlines `index.html`, the built `style.css` and the built `app.js` into a single response. That response is minified (`rjsmin`, `rcssmin`) and compressed to the smallest representation the client accepts (see *Smallest-Wins Static Compression* below): ~48 KB brotli today.  It is one Preact + Tailwind bundle rather than the ~14 KB shell it replaced, so it no longer fits RFC 6928's initial congestion window, and `ui._TCP_CWND_BUDGET` is a 90 KB ceiling over the measurement rather than the protocol constant. `ui._check_payload_budget` prints the exact overage if the shell outgrows it while `tests/test_api.py` fails on it, so crossing the ceiling is a regression and not only a log line.
* **Smallest-Wins Static Compression**: The precompressed responses (the inlined shell and the packaged assets) are not served under a fixed encoding preference.  Every encoding the client accepts is produced at maximum effort and the smallest body wins, because those bytes are compressed once per accepted set and then served from a dict, so the extra passes cost nothing per request and guarantee the winner is the real minimum.  This matters on the wire: measured on the current shell, brotli q11 gives 48,267 B against zstd's 51,655 B at level 19 and gzip's 56,077 B at level 9, so a fixed `zstd`-first preference would hand every zstd-capable browser 3,388 B more than necessary.  Static zstd runs at level 19 (where it stops returning a smaller frame on these bodies) and static gzip at 9.  The dynamic path keeps its fixed order and its cheap settings, because there a preference avoids compressing one multi-megabyte request body two or three ways per request.  Brotli is what buys the budget on this shell: every browser that has zstd also has brotli, so no browser shipping today is served the larger pair.  Re-derive the three numbers with `make payload-budget`; measured 2026-09-29 against the committed bundle.
* **Advanced Compression**: Dynamic responses compress brotli at quality 5, not the default 11: measured on a 5.6 MB coverage payload, q=11 costs 5.9 s of CPU for 334 KB while q=5 costs 68 ms for 444 KB, and that cost is paid per request because API responses are not cached compressed.  Clients without zstd (Safari) would otherwise stall about six seconds on every load and every live reload.
* **Shell Revalidation**: The shell is built once from the package's own assets and cannot change under a running server, so it carries a strong `ETag` (from the source bytes and the chosen encoding) and answers `If-None-Match` with a 304.  It used to be the one response served `no-store` with no validator, which made it the only response in a dashboard visit that a repeat load could never skip: every reload re-downloaded the whole ~48 KB document while the bundle and the rest answered 304.  `max-age` stays off for the same reason as on the assets below.
* **A first frame before the bundle runs**: the shell's `#root` is not empty. It ships the wordmark, the `R` mark and a `Loading coverage…` status line, because the app cannot mount until the document's own inline bundle has been parsed and run, and the dashboard it draws is serialized behind `/api/targets` and `/data` — an empty root paints a blank screen for the whole of that. `web/app/main.tsx` clears the host before `render`, because Preact's `render` mounts *beside* whatever the host already holds. The boot block's rules are in the shell rather than in the injected stylesheet, which is the built Tailwind output and carries no class for markup that never went through the bundler; they read the type scale, the accent and the terminal face from the token layer (with literal fallbacks, because this markup paints before that sheet has loaded), so the way into the dashboard is a typeface the dashboard itself uses rather than a system default. The other two unstyled first paints follow the same rule: the 401 page (`server._UNAUTHORIZED_HTML`, attribute-only, no stylesheet behind it either) prints the terminal face and the token layer's own colors, pinned to `web/app/index.css` by `TestUnauthorizedPageMatchesTheTokenLayer`.
* **Target List Revalidation**: `/api/targets` is the one request the SPA cannot avoid (the shell preloads it, `web/app/api.ts` fetches it with `cache: "no-cache"`), and it was the one response served `no-store` with no validator, so every reload re-downloaded the whole list. It carries a strong `ETag` over *both* inputs `resolve_targets` merges — the coverage snapshot and `server._config_stat_fingerprint` — because the config-only fallback path reads no document, and a key over the snapshot alone would answer 304 after a target was added to `rebrew-project.toml`. `max-age` stays at zero: the list changes under a running server.
* **HTTP/1.1 Keep-Alive, Threaded Connections**: The server is wsgiref on a `ThreadingMixIn` server class, so each connection gets its own daemon thread — without that, the long-lived `/api/events` SSE stream would stall every other request. wsgiref itself is HTTP/1.0 and serves exactly one request per connection, so `devserver._KeepAliveRequestHandler` restores the stock `BaseHTTPRequestHandler` request loop and `devserver._KeepAliveServerHandler` announces 1.1. Measured over one connection: `/`, `favicon.svg`, `/api/targets` and `/potato` all answered on a single socket, where each used to pay its own TCP handshake. Two rules keep the framing honest: a response with neither `Content-Length` nor `Transfer-Encoding` — the streamed `/api/events` and nothing else, since bottle sets `Content-Length` on every body it returns — is sent with `Connection: close`, because under 1.1 a client would otherwise read into the next response; and a connection idle between requests falls back to a 15 s deadline instead of the 120 s per-request one, so an open tab does not pin a handler thread.
* **ETag Caching**: The heavy `/api/targets/<target>/data` endpoint calculates an `ETag` from a snapshot of the coverage documents (`server._snapshot_db_mtime`: every `coverage-*.toml`'s name, `mtime_ns` and size folded into one opaque token, plus their total size). Folding in every document, not one file's mtime, is what the SQLite version got from also stat'ing `-wal`: a rebuild writes one document per target, so a target added, removed or rewritten anywhere in the directory has to move the token. If the documents haven't changed, the server responds with a `304 Not Modified` (0 bytes), making page reloads instantaneous. Every other coverage-derived read endpoint reuses that same `server._etag_or_304` tail over its own request identity: `/stats` (snapshot + target), `/asm` (snapshot + target, section, raw VA spelling, size, format) and `/sections/<s>/bytes` (snapshot + target, section, offset, size). The two surfaces that *render* the freshness time rather than key a cache on it (`/api/health`'s `db.mtime`/`db.mtime_utc` and Potato Mode's footer stamp) read the newest document mtime through `server._newest_mtime_ns`, so a rebuild of any one target moves them too, and both spell the instant in UTC rather than the host's zone.
* **Memo publish watermark**: every coverage-derived memo (`/data` payloads, `/stats`, Potato's grid and section stats) is keyed on the snapshot taken *before* the documents are read, so a rebuild landing mid-build would file a pre-rebuild payload under the post-rebuild key — after the `db-updated` broadcast had already cleared the memo, leaving it pinned until the next rebuild.  Each publish re-stats the documents and drops the write when the watermark moved.  The disassembly memo cannot re-stat (its source is the original binary, not a coverage document), so its key carries a generation counter that `clear_disassembly_cache()` bumps: a build already in flight writes its text under the retired generation and is never served again.
* **Static Asset Revalidation**: The packaged assets (`app.js`, `style.css`, `print.css`, `favicon.svg`) carry a strong `ETag` derived from the file's bytes and the negotiated encoding, and answer `If-None-Match` with a 304.  They are served `no-cache`, so without a validator the browser re-downloaded the whole set on every visit: a repeat dashboard load re-fetched the stylesheet and the bundle.  Measured with brotli, the static half of a dashboard visit (`style.css`, `print.css`, `favicon.svg`: ~5 KB) drops to 0 B.  The encoding is part of the tag because brotli and zstd bodies are different representations, and `max-age` is deliberately not raised: the URLs are not content-hashed, so a package upgrade changes the bytes under the same name.
* **Request Cancellation**: The UI uses `AbortController` to cancel in-flight network requests if the user clicks through multiple cells rapidly, saving bandwidth and preventing race conditions.
* **Bundled Highlight.js**: `highlight.js` (core plus the `c` and `x86asm` grammars, and the dashboard's own `hex` language) is compiled into `app.js`, so a code pane never renders unhighlighted and there is no first-use fetch to fail. Its theme lives in the same token layer as the rest of the dashboard (`web/app/index.css`), so a palette change moves the code panes with it. That is a deliberate trade and it costs, measured on the committed bundle: the highlighter and its two grammars are 96,520 of `app.js`'s 136,807 raw bytes, and 29,315 of the 42,381 B brotli body — 69% of the bundle, and therefore about 29 KB of the ~48 KB first-paint document, on every load. Nothing reads it until a cell is selected (`HighlightedCode` is reached only from `CoveragePanel` and `CodeModal`), so a visitor who never selects a block never pays for it. It cannot be split out under the current build: `web/vite.config.ts` is a lib build in `iife` format, and Rollup refuses code splitting for `iife`, so a dynamic `import()` in `web/app/lib/highlight.ts` would either error or be inlined back into the one file. Splitting it therefore means emitting ES with a hashed chunk, serving that chunk as a packaged asset, and giving the lazy path a visible state while the chunk is in flight (the panes already render `MSG.LOADING`), which is a build-output contract change rather than a one-attribute fix. Re-derive both numbers with `make payload-budget` and a brotli pass over the segment.
* **A pane with nothing to show is honest about it**: Copy and Open go `disabled` while a pane holds an empty-state message, with the message as the tooltip, so a control never looks live while it has nothing to act on.
* **One bundle, one render path**: the map (per-section canvas, layout walk, hit-map and painting), the panel's three code sections, the hex dump, the data inspector, the selected function's metadata grid, the annotation extractor, the `hex` highlight language, the live-reload subscription, the regen handler, the clipboard helper and the code-viewer modal all live in `web/app/`, compiled into the single inlined bundle. There is no `window.RC` hand-off and no deferred half: nothing can render before anything else, and the shell preloads `/api/targets` (`as="fetch"`) so the target list arrives while the bundle is parsed.
* **The target's data request does not queue behind the target list**: the shell preloads `/api/targets` (`as="fetch"`), but `/api/targets/<target>/data` used to start only once that list answered, because the id to ask for was in it. A `?target=` in the URL is the page's own state and is written there by every reload, so `App.tsx` seeds the selection from it and the two requests run in parallel. The name is still validated against the list when it lands; one the server no longer serves falls back to the remembered target or the first it offers, exactly as a stale `localStorage` entry does, at the cost of a single 404 on the speculative request.
* **The search index travels once per build**: `search_index` is target-wide, so it is the one part of `/data` that grows with the function count rather than with the section. The `?section=` request exists to add one section's cells to a map the SPA already holds, and it used to re-send the whole index on every tab click: ~29 KB brotli at 8,000 functions, measured over a synthetic index of that size. `?index=0` omits the key, the same absence convention `cells` already uses, and the key is part of both the ETag inputs and the memo key so the two shapes never share a validator or a cached body. `useCoverage` tracks which (target, build) the index in state belongs to, so a target change or a `reload()` asks for a fresh one and nothing else re-sends it.
* **On-Demand Data Fetching**: The `/api/targets/<target>/data` endpoint only returns lightweight grid layouts and metadata. Detailed function information is fetched on-demand via `/api/targets/<target>/functions/<va>` when a user clicks a cell, drastically reducing memory usage and initial load times.
* **One Click Listener Per Section**: The grid is a canvas, so the click handler hit-tests a packed row/column map instead of attaching 2,500+ individual listeners.
* **Grid Caching & Canvas Repaint**: To handle sections with 6,000+ chunks (like `.bss`), the per-section layout is computed once and cached. Filtering, search, selection and focus changes only repaint from those cached rectangles.
* **Precomputed Cell Geometry**: Per-cell x/y/width and the row hit-map are computed once per layout and reused by every repaint, so the UI never recomputes geometry during a state change.
* **Cells Cross as One Array, Not One Row at a Time**: each section's cells are inline tables inside one `cells` array in the document — one row per line, so the file stays diffable — and the reader hands the section over as one tuple.  The SQLite writer grouped a section's cells into one `json_group_array` string per section for the same reason (a 25k-cell section crossing into Python as a handful of strings instead of tens of thousands of rows), and the document keeps that property while giving up nothing to it.  The row shape deliberately omits the surrogate `cells.id` the SQLite table carried: no consumer reads it, and as the only high-entropy column per row it cost 4.3x on the wire when the served payload still carried it (the 39k-cell `.text` payload compressed 322 KB with it and 74 KB without).  The normalizers that shape a row are `rebrew.build_db`'s, imported by the writer rather than restated, so the document and the retired database cannot report different facts about the same catalog JSON.
* **Derived at Load Instead of Materialized**: `rebrew build-db` used to materialize the per-section cell JSON (`section_cells_json`, zstd level 3) and the coverage buckets (`section_cell_stats`, a view through schema v6 and a build-time table from v7), because reading them cost ~0.3 ms where re-running the group-by cost 10.7 ms and re-aggregating the stats view cost 17.3 ms — together 92% of a cold `/data` build (measured cold `/data`: 24.8 ms → 3.4 ms for one section and 38.9 ms → 6.8 ms for all sections).  The document format removes both, and the reason is the one that chose the format: a stored aggregate is a second answer, correct only while nobody derives it differently and nothing writes the cache without the rows beside it, and both were derived from `cells` and rebuilt whole on every build to stay honest.  `rebrew.coverage_toml` derives every one of them in `Section.__post_init__` and `_derive_function_stats` at load, so there is one answer and nothing to invalidate, and the reader memoizes on the documents' own stat so one parse serves every request until a file moves.
* **No Lock, No Transaction**: the SQLite design used Write-Ahead Logging (`PRAGMA journal_mode=WAL`) with read-only connections (`?mode=ro`) so the dev server could serve while a rebuild ran in the background, and a read transaction per response so one answer could not mix two builds.  The document format needs neither: `rebrew build-db` writes each document through a temporary sibling and an atomic rename, so a reader sees the previous document or the new one and never a torn write, and the snapshot it parsed is frozen, so a response cannot mix two builds.  Nothing is held open between requests, and no lock or journal file sits beside the coverage directory.
* **LRU Caching & Memory I/O**: The `/api/asm` endpoint uses Python's `@functools.lru_cache` to store disassembled chunks in memory. The target DLL is also read into memory once (with thread-safe locking), preventing redundant disk I/O and Capstone disassembly calls during a session.  The DLL memo is keyed by target alone, so it carries the `rebrew-project.toml` stat alongside: re-pointing a target's `binary` is an operator edit that reaches no server code and moves no coverage document, and without that token `/asm` and `/bytes` served the replaced binary until the next `build-db`.  The same token keys the parsed config and the resolved target list, so the three config-derived memos cannot disagree about whether the file changed.
* **Stats Rendering**: The stats row is text plus buttons, so nothing is measured, clipped or laid out from JavaScript: the figures arrive computed in `/stats` and the pills carry no share of any denominator.

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
1. Fetch original binary as ArrayBuffer (`/original/target.dll`). This is the
   largest response the page ever requests, so the fetch is gated on the
   selection rather than on the target resolving: a visit that reads the map
   and leaves never transfers it, and the pane says `Loading...` while the one
   that does need the bytes waits for them. The buffer is then kept for the
   rest of the (path, build) pair, so a second selection costs nothing.
2. Calculate raw file offset from VA using section info
3. Slice the relevant bytes and format as hex dump

### Documentation Extraction
`extractDocs()` parses C source for annotation comments:
```javascript
// NOTE:, // BLOCKER:, // FUNCTION:, // STATUS:, // ORIGIN:, // SIZE:, // CFLAGS:, // SYMBOL:
```

### Search & Filtering
* **Search**: Matches against function name, VA, and symbol (case-insensitive)
* **Filters**: Set-based toggling; the state pills in the stats strip are the same toggles
* **Dimming**: Non-matching cells are dimmed (opacity 0.15) rather than hidden, preserving grid layout.  A search dims undocumented blocks too: they are not matches either, and exempting them left most of the map lit during a search. A status filter does not dim them, and that is the one place the two dimming rules differ: see *Canvas-Based Filtering* above.

### Theme Persistence
* Checks `localStorage` for `recoverage_theme` ("light" or "dark")
* Falls back to `prefers-color-scheme` media query
* Theme changes are saved immediately

## Coverage Documents

recoverage reads [rebrew's coverage documents](../../rebrew/docs/COVERAGE_DOCUMENT.md), `db/coverage-<target>.toml`, through `rebrew.coverage_toml`'s reader.  One document holds one target's facts: its sections with their cells, its functions, its globals, its verify results, its history, and `[metadata].paths`.  `version = 1` is the document-format version the reader accepts; a document whose `version` is anything else, that does not parse as TOML, or that names a target other than its filename is unreadable.  There is no schema to migrate and no `--force` to pass: every `rebrew build-db` run replaces each document whole.

### Derived at Load

Nothing below is stored.  `rebrew.coverage_toml` computes each one once, at load, and recoverage reads the derived value rather than computing a second answer to the same question:

| Derived value | Computed in | From |
|---|---|---|
| `Section.buckets` (bytes per state), `covered_bytes`, `coverage_pct`, `cell_count` | `rebrew.coverage_toml.Section.__post_init__` | the section's cells |
| `Section.bucket_counts` — the served cell counts, `total_cells` and the `other` catch-all included | `rebrew.coverage_toml._bucket_counts` | the section's cells |
| `CoverageSnapshot.function_stats` (`total`, `covered_bytes`, `matched_bytes`, `total_bytes`, `by_status`, `by_module_counts`) | `rebrew.coverage_toml._derive_function_stats` | the stored code rows and the `.text` size |
| `CoverageSnapshot.functions_by_va`, the index every lookup and the search read | `CoverageSnapshot.__post_init__` | the `functions` array |

Two served shapes are recoverage's own, and each has one definition so it cannot drift:

* `server._bucket_row` serves the bucket dict `/stats`, `/data` and Potato Mode's map header all read, as a copy of `Section.bucket_counts` — the same fold the reader derived at load, not a second pass over the cells.  `other` is the producer's catch-all, so the buckets still reconcile with `total_cells`.
* `server._summary` rebuilds the catalog `summary` blob, which the writer does not store.  `/stats` and `/data` serve the rebuild, so a change there is a change to a served payload.  Its counts and byte sums come from the derived `Section` fields; only `totalFunctions`, which counts the function NAMES the covered cells carry, still walks them.

Re-deriving what the load already derived costs a pass over the largest section per request: 2-6 ms on a 40k-cell `.text`, once per `/stats`, `/data` and Potato render.  `tests/test_server.py` (`TestBucketReconciliation`) pins the served rows against an independent per-cell walk, so reading the derived value and computing it cannot silently diverge.

A stored aggregate is a second place for two writers to disagree: the number would have to be computed on the way in and trusted on the way out, and a change to what counts as covered or as matched would have to be applied to the stored copy too, or the file and the reader would report different coverage for the same rows.  Each number above is a pure function of rows already in the document, so one pass at load is the whole cost and no file can hold a figure that contradicts its own cells.  That is the decision the SQLite format made the other way (see *Derived at Load Instead of Materialized*): materializing them was worth it when reading them back cost one query where re-deriving them cost a group-by.

### One response, one snapshot

`rebrew.coverage_toml.load_all_coverage_from` memoizes on the documents' own stat, so an unchanged directory returns the *same* snapshot objects, and a snapshot is frozen: every collection is a tuple or a `MappingProxyType`.  A handler that builds its answer from several collections therefore reads them all from one build and cannot pair one build's cells with the next build's functions.  That is the guarantee the SQLite read transaction used to buy, held by the type instead: a document rewritten on disk cannot be edited into a snapshot a caller already holds.  The readers are `api._target_snapshot` (`/stats`, `/data`, the function list, both lookup routes, `/asm`, `/bytes`), `cli._open_targets` (`recoverage stats`/`export`/`check`) and the whole `potato.render_potato` render, the widest window in the package.  Pinned at `tests/test_api.py` (the lookup pin classes) and `tests/test_potato.py` (`TestRenderIsPinnedToOneSnapshot`), which drive a rebuild from inside the read and require the page to stay the first build's.  One unreadable document beside readable ones is skipped by the reader with a warning naming the file, and the other targets keep serving.

### A declared target no build has written

A target that `rebrew-project.toml` declares but no build has written is served from an empty snapshot (`server.coverage_for`), which is what the SQLite reader got from an empty table set.  A document that exists but does not parse is the opposite case and stays distinguishable: it raises `CoverageTomlError`, which is the 503 `db_unavailable` contract, never a target that silently reads as having no sections (`tests/test_server.py`, `TestUnreadableDocumentIsNotAnEmptyTarget`).

## Future Ideas / TODOs
* [ ] **Minimap**: A global minimap of the entire PE file on the side.
* [ ] **XREFs**: Show cross-references for data segments (which functions read/write to this `.data` block).
* [ ] **Diff View**: Integrate the `rebrew match --diff-only` output directly into the UI for "Near-match" and "Stub" blocks.
* [x] **Jump table absorption**: Switch/jump table bytes adjacent to functions are absorbed into the parent function's size rather than tracked as separate cells.
* [x] **Parent function linking**: Data and thunk cells automatically link to their parent function (detected via `func_end_va == data_start_va`).
* [x] **Ghidra label export**: `rebrew catalog --export-ghidra-labels` generates `ghidra_data_labels.json` from detected tables for round-trip sync.

---

# Potato Mode

Potato Mode is a pure HTML 5 alternative UI that works **without any CSS or JavaScript**. It's designed to work on severely constrained environments while providing near-visual-parity with the main SPA's dark theme.

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
- **A color and a legend row for every cell state** `build_db` can write, shared with the SPA's `STATE_SLOTS` vocabulary in `web/app/grid/pack.ts`.  A legend row covers every state that shares it, so a state with no row of its own still has a color and a filter
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

- **`server.py`** — shared Bottle application (`app`: hooks, auth, error handlers, CORS preflight catch-all) and infrastructure: compression (brotli/zstd/gzip), coverage snapshot helpers, DLL loading, target resolution, and response utilities.
- **`disasm.py`** — the optional capstone capability: the loadability probe, the thread-local `Cs` handle, the per-slice memo, and its invalidation hook. The probe imports capstone once and memoizes the verdict, because `find_spec` answers "is a distribution on the path", not "does it load": a wrong-architecture wheel or a missing `libcapstone.so` used to reach the operator as a 500 traceback where `/asm` documents a 501, and `/api/health` advertised an extra the process could not use. Both renderers gate on that verdict, so a broken extra answers 501 with the reason (`/asm`) or omits the panel (Potato Mode). It reads target bytes through `server._load_dll`, so the two assembly renderers (`api.py`'s `/asm` and `potato.py`'s panel) depend on this module rather than on a capstone wrapper inside the transport module.
- **`regen.py`** — in-process rebrew regen (`run_regen`): loads `rebrew-project.toml` once and calls rebrew's `run_catalog` (which runs the catalog analysis) and then the `write_coverage_toml` writer, both as library functions; shared by the CLI's regen paths and POST /api/regen.  rebrew is a required dependency, but its catalog/build-db imports are deferred into `run_regen` so only the regen paths pay for the heavy rebrew stack.  It owns the cross-process half of the rebuild's duplicate-safety too (`RegenBusyError` and the coverage-directory lock), which is the one property a caller's in-process lock cannot provide.
- **`api.py`** — REST API routes (`/api/*`) with `@app.get`/`@app.post` decorators and `request` globals.
- **`ui.py`** — UI routes (`/`, static files) with index caching and minification (using `rjsmin` and `rcssmin`).  The inlined shell is compressed once per accepted-encoding set under `INDEX_LOCK` and served from `CACHED_INDEX_COMPRESSED` as `(body, encoding, etag)`, answering `If-None-Match` with a 304; the standalone assets (`app.js`, `style.css`, `print.css`, `favicon.svg`) take the same smallest-wins compression and are memoized per `(filename, accepted-encoding set)` in `_STATIC_CACHE`, falling through to `static_file()` only when the client advertises no supported encoding, so Range and `If-Modified-Since` still work there.
- **`webapp.py`** — composition root: imports `api`, `ui` and `potato` so their routes mount on the shared `app`; this is the module the CLI actually serves.
- **`potato.py`** — Potato Mode: the `/potato` route plus the renderer behind it.  It uses Bottle's `SimpleTemplate` engine (stpl) for the markup; only the thin route handler touches the Bottle web server.

### Template Architecture

Two compiled `SimpleTemplate` instances handle all HTML layout:

| Template | Purpose |
|----------|---------|
| `_PAGE_TPL` | Full page: topbar, section tabs, filter buttons, legend, progress bar, grid, panel container |
| `_PANEL_TPL` | Detail panel: function details, annotations, source code, assembly, hex dump, data inspector, globals |

Templates use `% for`/`% if`/`% end` control flow and `{{!expr}}` for raw HTML output. Business logic (snapshot reads, cell merging, stats computation, syntax highlighting) stays in Python — only HTML structure lives in templates.

### Key Design Decisions

- **Filtering is visual dimming, not data exclusion.** The grid is a spatial map where position = memory address. All cells are always read from the snapshot; filtered cells render with a muted background color. This preserves spatial context and avoids grid layout disruption.
- **Grid and cell merging stay in Python.** The merging algorithm (adjacent same-state cells within a row) and per-cell dimming/selection logic are too complex for template loops.
- **Pygments highlighting stays in Python.** Token-level `<font color>` tag generation requires iterating over lexer output, which is cleaner as helper functions than inline template code.

## Testing
Run the test harness to verify all rendering paths:
```bash
uv run --locked --extra dev python -m pytest tests/test_potato.py -v
```

This suite covers:
- All sections (`.text`, `.data`, `.rdata`, `.bss`)
- Single and multi-filter combinations
- Cell selection at various indices
- Invalid/unknown parameters (graceful fallbacks)

HTML validation is a separate gate: `bun run lint:html` (`tools/lint_html.py`) validates the static assets plus the served SPA shell and Potato Mode page.

Playwright comparison tests verify visual and behavioral parity with the main UI:
```bash
uv run --locked --extra dev python -m pytest tests/test_playwright.py
```
