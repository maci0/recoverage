# ReCoverage UI Design Document

## Overview
ReCoverage is a reactive, high-performance web dashboard for visualizing binary reverse-engineering progress. It maps compiled C functions and data segments (`.text`, `.rdata`, `.data`, `.bss`) to their original binary offsets, providing a visual "defrag" style grid of the decompilation status.

## Architecture
The UI is built using a lightweight, dependency-free stack to ensure fast load times and easy maintainability:
* **Frontend Framework**: [VanJS](https://vanjs.org/) (a ~2 kB reactive UI framework).
* **Styling**: Vanilla CSS with CSS Variables for theming.
* **Backend/Data**: [Bottle](https://bottlepy.org/) web framework serving a SQLite database (`coverage.db`).
* **Syntax Highlighting**: Highlight.js (C, x86 ASM, custom Hex language), vendored in `assets/` and served from this origin so the dashboard works air-gapped.

## Data Pipeline
1. `rebrew catalog --json` parses the target binary (`target.dll`) and C source annotations (`// FUNCTION:`, `// GLOBAL:`).
2. `rebrew build-db` converts the resulting JSON into a structured SQLite database with tables for metadata, functions, globals, sections, and cells. It also pre-calculates coverage statistics for all sections to save frontend processing time.
3. The Bottle app (`webapp.py` wires `server.py` + `api.py` + `ui.py` into the fully routed application; importing `recoverage.server` alone yields a routeless app) serves:
   * Static files (index.html, app.js, style.css, van.min.js) which are **inlined and compressed** into a single response for the root `/` path to achieve a "first draw in the first TCP packet".
   * `/api/targets` endpoint that returns available targets from the database plus any target declared under `[targets.*]` in `rebrew-project.toml` (a configured-but-not-yet-built target stays addressable).
   * `/api/targets/<target>/stats` endpoint with per-section byte-based coverage statistics (shared implementation with the `recoverage stats` CLI).
   * `/api/targets/<target>/data` endpoint that queries SQLite for a specific target and returns lightweight metadata and section layouts (compressed via zstd/brotli/gzip).
   * `/api/targets/<target>/functions/<va>` endpoint to fetch specific function/global details on-demand, plus `GET`/`POST /api/targets/<target>/functions` for the paginated function list (`?status=&search=&sort=&limit=&offset=`) and batch lookups by VA list.
   * `/api/targets/<target>/sections/<section>/bytes` endpoint serving raw hex-dumped byte slices from the original binary (`?offset=&size=`).
   * `/api/targets/<target>/asm?va=...&size=...` endpoint that dynamically disassembles binary chunks using Capstone (with LRU caching and in-memory cached binary reads).
   * `/api/events` Server-Sent Events stream that pushes a `db-updated` event whenever `coverage.db` changes on disk, so the SPA auto-refreshes without a manual reload (requires the threaded WSGI server, which gives each connection its own thread).
   * `/api/regen` POST endpoint to trigger `rebrew catalog --json` + `rebrew build-db` regeneration.
   * With `--token`, an unauthenticated request is answered by content type: browsers asking for `text/html` get a short page explaining that `?token=` must be appended (it never echoes the token), and API clients keep the `{error, code, detail}` JSON contract.
   * Proxied paths: `/src/*` → `project_dir/src/`, `/original/*` → `project_dir/original/`

## State Management (VanJS)
The application state is managed using VanJS reactive primitives (`van.state`):
* `data`: Holds the fetched SQLite data (sections, globals, functions, summary).
* `originalDll`: Raw ArrayBuffer of the original DLL for byte slicing.  Fetched from `paths.originalDll` when the DB carries that metadata, otherwise from `/original/<target>.dll`, which the server proxies anyway; when neither exists the hex pane says so instead of failing silently.
* `activeSection`: Tracks the currently selected PE section (`.text`, `.rdata`, `.data`, `.bss`).
* `activeFilters`: A `Set` tracking which match statuses are currently visible (exact, reloc, near_match, stub, padding).
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

## Components
The UI is broken down into functional VanJS components in `app.js`:

### 1. Topbar (`header.topbar`)
* **Logo & Title**: Retro-futuristic "R" logo with CRT scanline effects.
* **Tabs**: Dynamic segment selectors generated from the active target's sections, ordered by ascending VA so PE load order (`.text`, `.rdata`, `.data`, `.bss`) holds and the section carrying the work leads, instead of an alphabetical row ending in `.text`.
* **ProgressBar**: A dynamic, segmented progress bar showing coverage percentages. It takes its own full-width row below 900px (sharing the topbar row leaves it a few dozen pixels), and drops the byte count below 700px so the two headline stats fit inside the bar. **Each segment is a filter toggle**, reachable by keyboard and carrying `aria-pressed`; segments under 0.5% are not rendered at all, since a zero-width toggle is a focus stop with nothing to point at. Text stats overlay the segments, each on its own scrim so they stay legible over any status colour.
* **Target Selector**: Dropdown to switch between targets (e.g., `SERVER`, `GOLD`, `GOLDTL`). Persists selection to URL (`?target=XXX`) and localStorage.
* **Search & Filters**: Debounced search input and toggleable filter buttons (All, E, R, M, S, P).
* **Actions**: Theme toggle (sun/moon icons) and Reload data buttons with a 5-second cooldown to prevent spam.

### 2. Grid (`.map`)
* A CSS Grid layout that keeps blocks square: the section's `columns` value is stored on the element as `data-cols` and the `ResizeObserver` derives the rendered count into `--cols`, which drives the CSS track count, the row height, and the arrow-key row step.  Below 700px the rendered count drops so cells stay at least 12px (64 columns on a 352px phone would give 2.8px cells); above it the section keeps every column it declares.  Reading it from one place is what keeps them from drifting (the track count was previously hard-coded to 64 while the row height followed the declared value, so cells were not square for any section declaring anything else).
* Cells are colored based on their status:
  * **Exact** (green) — byte-for-byte match
  * **Reloc** (blue/teal) — match after masking relocations
  * **Near-match** (yellow) — near-miss with structural differences (DB state `near_match`; legacy DBs may spell it `near_matching`, which renders identically)
  * **Proven** (bold cyan) — post-verify semantic-equivalence promotion (`proven`)
  * **Size mismatch** (yellow) — compiled size differs from the original (`size_mismatch`)
  * **Stub** (red) — far off or placeholder
  * **Padding** (silver) — alignment padding
  * **None** (gray) — undocumented block

  Data and thunk cells keep their DB states but render with the undocumented gray here: their dedicated purple/orange tints were removed together with the data/thunk filters. Potato Mode still colors those states.
* **Grid Caching**: Each section's grid is built once and cached in the DOM. Switching tabs simply toggles `display: none` vs `display: grid`, making tab switching instantaneous even for sections with 6,000+ chunks.
* **Fast HTML Building**: Grids are constructed using a single massive HTML string injection (`innerHTML`) rather than creating thousands of individual DOM nodes, drastically reducing initial render time.
* **CSS-Based Filtering**: Filtering and search dimming are handled by applying classes to the parent grid container (e.g., `.has-filters.show-exact`), allowing the browser's highly optimized CSS engine to instantly update thousands of cells without JavaScript loops.
* **Keyboard & semantics**: the grid is a `listbox` of `option` cells with a roving tabindex, so exactly one cell is in the tab order no matter how many thousands the section holds. Arrow keys move focus (left/right by one, up/down by a full row), Home/End jump to the ends, Enter/Space selects, and `aria-selected` tracks the selected block.

### 3. Side Panel (`.panel`)
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
* **Light Mode**: Triggered by the `.light-mode` class on the `body`. Overrides CSS variables to softer grays (`#cbd5e1` background, `#e2e8f0` panels) to reduce eye strain while maintaining contrast.
* **CRT Scanlines**: A global scanline overlay (`body::after`) using a repeating linear gradient. It is kept very faint (`0.05` opacity in dark mode, `0.02` in light mode via `body.light-mode::after`) to add texture without overpowering the UI.
* **Match Status Colors**:
  * **Exact**: Green (`rgba(16, 185, 129, 0.75)`)
  * **Reloc**: Blue/Teal (`rgba(2, 132, 199, 0.65)`)
  * **Near-match**: Yellow/Amber (`rgba(255, 200, 0, 0.65)`)
  * **Proven**: Bold Cyan (`rgba(6, 182, 212, 0.8)`)
  * **Stub**: Red (`rgba(255, 0, 0, 0.65)`)
  * **Padding**: Silver (`rgba(200, 200, 220, 0.55)`)
* **Transitions**: Smooth `0.3s ease` transitions on background colors, borders, and opacities ensure fluid theme switching and filter toggling.
* **Scrollbars**: Custom WebKit scrollbars styled to match the active theme, with `scrollbar-gutter: stable` applied to code blocks to prevent layout shifts.
* **Loading Overlay**: A pulsing, vertically-centered overlay with large text (`font-size: 32px`, `font-weight: 700`) provides immediate visual feedback during data fetches.
* **Print**: `assets/print.css`, linked with `media="print"` so it costs nothing at first paint.  Paper drops the controls, the scanline overlay, and the copy/open affordances, keeps the status colours (`print-color-adjust: exact`), unclamps the code panes, and appends link targets after source links.
* **Favicon**: `assets/favicon.svg`, matching the retro-futuristic "R" logo with a cyan glow and scanline pattern.  It is a served file rather than an inline data URI so it stays out of the first-packet budget.
* **Responsive**: Two-column layout on wide screens, single-column below 1300px.  Below 700px the topbar stops being sticky (its wrapped controls would otherwise hold a quarter of a phone viewport for the whole scroll).  Under `pointer: coarse` the controls and the progress bar grow to a 44px hit area.
* **Reduced motion**: `prefers-reduced-motion` kills animation and transition durations globally, but the loading overlay keeps an opacity-only pulse: it is the only "still working" signal during regen, and removing motion should not remove feedback.
* **Contrast**: text-bearing tokens clear 4.5:1 on the surface they sit on, in both themes.  `--c` doubles as the focus-ring colour, so its light-mode value is tuned for text contrast rather than the 3:1 non-text floor.

## Key Implementation Details

### Performance Optimizations
* **First Draw in First TCP Packet**: `ui.py` intercepts requests to `/` and inlines `index.html`, `style.css`, `app.js`, and `van.min.js` into a single response. This response is minified (using `rjsmin` and `rcssmin`) and compressed using **Brotli (`br`)** or **Zstandard (`zstd`)** (falling back to `gzip`) to ~14.5KB, fitting perfectly into the initial TCP congestion window (`cwnd`). This allows the browser to parse and render the UI shell instantly without any render-blocking network requests.
* **Advanced Compression**: The server picks the best algorithm the client accepts, preferring `zstd`, then `br`, then `gzip`.  Dynamic responses compress brotli at quality 5, not the default 11: measured on a 5.6 MB coverage payload, q=11 costs 5.9 s of CPU for 334 KB while q=5 costs 68 ms for 444 KB, and that cost is paid per request because API responses are not cached compressed.  Clients without zstd (Safari) would otherwise stall about six seconds on every load and every live reload.  The inlined index keeps q=11: it is compressed once per encoding, cached, and has a hard byte budget.
* **HTTP/1.0, Threaded Connections**: The server is wsgiref, which speaks HTTP/1.0 and closes the connection after each response (no keep-alive). It runs on a `ThreadingMixIn` server class so each connection gets its own daemon thread — without that, the long-lived `/api/events` SSE stream would stall every other request.
* **ETag Caching**: The heavy `/api/targets/<target>/data` endpoint calculates an `ETag` from a WAL-aware snapshot of `coverage.db` (`mtime_ns` + size, folding in `-wal` so a rebuild that only committed to the WAL still invalidates; raw `st_mtime` served stale 304s). If the database hasn't changed, the server responds with a `304 Not Modified` (0 bytes), making page reloads instantaneous.
* **Request Cancellation**: The UI uses `AbortController` to cancel in-flight network requests if the user clicks through multiple cells rapidly, saving bandwidth and preventing race conditions.
* **Deferred Highlight.js**: The heavy `highlight.js` library and its CSS are not loaded initially. They are fetched from this origin (`/hljs.min.js`, `/hljs-c.min.js`, `/hljs-x86asm.min.js`) the first time a user clicks a code block.
* **Deferred failure is visible, not silent**: `detailFailed` is set when `/detail.js` cannot be fetched.  The panes it owns say so, and every control that delegates to it (Copy, Open, Copy VA, Copy Symbol, Reload) goes `disabled` with the same message as its tooltip.  Optional chaining alone made each deferral crash-safe but user-hostile: the buttons looked enabled and did nothing.
* **Deferred detail rendering**: `detail.js` carries the hex dump, the data inspector, the C annotation extractor, the custom hex highlight language, the live-reload subscription, the regen/reload handler, the clipboard helper, and the code-viewer modal with its focus and `inert` handling: everything that is not needed to paint the first frame.  app.js keeps the modal's four states so the panel's Open buttons can set them; `window.RC.mountModal` attaches the dialog once detail.js lands. It is fetched immediately after first paint, which keeps the inlined shell inside the congestion window without a visible delay. app.js publishes `window.RC` for it to read and write; until it lands, the panes it owns show a loading message and resolve reactively when it arrives.
* **On-Demand Data Fetching**: The `/api/targets/<target>/data` endpoint only returns lightweight grid layouts and metadata. Detailed function information is fetched on-demand via `/api/targets/<target>/functions/<va>` when a user clicks a cell, drastically reducing memory usage and initial load times.
* **DOM Optimizations**: The grid uses **Event Delegation** (a single click listener on the parent container instead of 2,500+ individual listeners), **CSS Containment** (`contain: strict` on cells to prevent global layout recalculations), and **Content Visibility** (`content-visibility: auto` on the grid container to skip rendering it while off-screen).
* **Grid Caching & CSS Filtering**: To handle sections with 6,000+ chunks (like `.bss`), grids are built once via fast HTML string injection and cached. Tab switching toggles `display: none`. Filtering and search dimming are handled entirely by CSS classes on the parent container, avoiding slow JavaScript loops over thousands of DOM nodes. CSS transitions on cells were removed to eliminate GPU overhead during mass state changes.
* **Precomputed Cell Properties**: Cell CSS classes and states are precomputed immediately after the JSON payload is fetched, preventing the UI from recalculating these strings thousands of times during the render loop.
* **SQL-Side Cell Grouping**: Cells leave SQLite as one `json_group_array` string per section (`json_object` shapes each cell), not one row per cell, so a 25k-cell section crosses into Python as a handful of strings instead of tens of thousands of rows.
* **SQLite WAL Mode**: The database uses Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and read-only connections (`?mode=ro`), allowing the dev server to serve data concurrently without locking while the database is being regenerated in the background.
* **LRU Caching & Memory I/O**: The `/api/asm` endpoint uses Python's `@functools.lru_cache` to store disassembled chunks in memory. The target DLL is also read into memory once (with thread-safe locking), preventing redundant disk I/O and Capstone disassembly calls during a session.
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

The database uses a v4 schema (see [DB_FORMAT.md](../../rebrew/docs/DB_FORMAT.md) for the canonical reference).

### Schema Compatibility

| Schema version | Recoverage support |
|---|---|
| v3 | Readable — v4 adds CHECK constraints and view fixes that do not affect reads of v3 data |
| v4 | Fully supported (current) |

Recoverage performs a soft version check on every database open and logs a warning if the stored `db_version` is not one of the known-compatible versions (`3` or `4`). It never aborts on an unexpected version.

### Tables
* `metadata`: Key-value pairs per target — coverage summaries, paths, `db_version` stamp
* `functions`: All reversed functions — va (INTEGER), name, vaStart, size, fileOffset, status, module, cflags, symbol, markerType, files JSON, `detected_by` JSON, `size_by_tool` JSON, `textOffset`, ghidra_name, list_name, is_thunk, is_export, sha256, blocker, blockerDelta, size_reason, similarity
* `globals`: Global variables — va (INTEGER), name, decl, files JSON, `module`, `size`
* `sections`: PE sections — name, va, size, fileOffset, unitBytes, columns
* `cells`: Grid cells per section — section_name, start, end, state (none/exact/reloc/near_match/stub/padding/data/thunk/proven/size_mismatch; legacy DBs may spell near_match as near_matching), functions JSON, label, parent_function
* `history`: Status change log (persistent, never dropped) — target, va, old_status, new_status, changed_at
* `verify_results`: Verification results (persistent, never dropped) — target, va, verified_at, byte_delta, diff_lines, similarity

### Views
* `section_cell_stats`: Aggregated counts per target+section — total_cells, exact_count, reloc_count, near_match_count, stub_count, padding_count, data_count, thunk_count, none_count, proven_count, size_mismatch_count

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
| `filter` | Comma-separated filters | `?filter=exact,reloc` |
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
- `[Clear]` link removes all filters

## Color Scheme & Styling (matches main UI)
| Status | Color | Hex |
|---------|-------|-----|
| Exact | Green | `#10b981` |
| Reloc | Blue | `#0ea5e9` |
| Near-match | Yellow | `#f59e0b` |
| Stub | Red | `#ef4444` |
| None | Dark Gray | `#3F4958` |
| Background | Dark | `#0f1216` |
| Panel | Slate | `#151a21` |
| Code Block | Darker | `#0a0d14` |
| Border | Cyan-tinted | `#1c2a38` |
| Accent | Cyan | `#06b6d4` |

### Typography
- **Body text**: `system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif` — proportional font for labels, headings, and UI chrome, matching the normal UI's body font stack.
- **Code & metadata values**: `SFMono-Regular, Consolas, Liberation Mono, Courier New, monospace` — used for section tabs, filter labels, code blocks, hex values, and VA addresses.

### Layout Parity with Normal UI
- **Single-row topbar**: Logo, section tabs, search/filters, target selector, and progress bar all on one `<tr>` (matches the normal UI's single flex topbar).
- **Progress bar stats inline**: Coverage stats (`bytes · matched · %`) rendered inside the bar row rather than below it.
- **Topbar separator**: A 1px `#1c2a38` standalone table between topbar and layout, simulating `border-bottom: 1px solid var(--border)`.
- **Card wrappers**: Map and Panel sections use `border="1" bordercolor="#1c2a38"` to simulate the normal UI's card containers with subtle cyan-tinted borders.
- **Grid container**: The grid table is wrapped in an additional bordered table with `cellpadding="8"` and `bgcolor="#0f1216"`, simulating the `.map` card effect.
- **Panel header separator**: A 1px border row between "Block Details" header and panel body.
- **Grid cells**: `CELL_W` is 18px, `CELL_H` is 15px (slightly shorter to compensate for the browser baseline gap below inline images).
- **Status badge pills**: The State value in the detail panel is wrapped in a bordered `<table>` with the status color as border, simulating the pill badge rendering.
- **Thinner selected-cell highlight**: `border="1"` cyan outline on the selected cell (vs. the original `border="2"`).
- **Metadata label hierarchy**: Labels use `<font size="1">` while values use `<font size="2">`, replicating the 10px/12px label-value ratio of the normal UI.
- **Darker code blocks**: `bgcolor="#0a0d14"` for `<pre>` containers, matching `var(--code-bg)`.

## Implementation

Potato Mode uses [Bottle](https://bottlepy.org/) for both the dev server and HTML templating:

- **`server.py`** — shared Bottle application (`app`: hooks, auth, error handlers, CORS preflight catch-all) and infrastructure: compression (brotli/zstd/gzip), DB helpers, DLL loading, target resolution, and response utilities.
- **`regen.py`** — rebrew regen subprocess lifecycle (`run_regen_step`, group kill + reap): shared by the CLI's regen paths and POST /api/regen; no dependency on the web stack.
- **`api.py`** — REST API routes (`/api/*`) with `@app.get`/`@app.post` decorators and `request` globals.
- **`ui.py`** — UI routes (`/`, `/potato`, static files) with index caching and minification (using `rjsmin` and `rcssmin`) and `static_file()` serving.
- **`webapp.py`** — composition root: imports `api` and `ui` so their routes mount on the shared `app`; this is the module the CLI actually serves.
- **`potato.py`** — Uses Bottle's `SimpleTemplate` engine (stpl) standalone, with no dependency on the Bottle web server for rendering.

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
pytest tests/test_potato.py -v
```

This tests over 190 different rendering paths and assertions including:
- All sections (`.text`, `.data`, `.rdata`, `.bss`)
- Single and multi-filter combinations
- Cell selection at various indices
- Invalid/unknown parameters (graceful fallbacks)
- W3C Nu HTML validation for all generated pages

Playwright comparison tests verify visual and behavioral parity with the main UI:
```bash
pytest tests/test_playwright.py
```
