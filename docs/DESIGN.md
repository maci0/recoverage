# ReCoverage UI Design Document

## Overview
ReCoverage is a reactive, high-performance web dashboard for visualizing binary reverse-engineering progress. It maps compiled C functions and data segments (`.text`, `.rdata`, `.data`, `.bss`) to their original binary offsets, providing a visual "defrag" style grid of the decompilation status.

## Architecture
The UI is built using a lightweight, dependency-free stack to ensure fast load times and easy maintainability:
* **Frontend Framework**: [VanJS](https://vanjs.org/) (a 1.0kB reactive UI framework).
* **Styling**: Vanilla CSS with CSS Variables for theming.
* **Backend/Data**: [Bottle](https://bottlepy.org/) web framework serving a SQLite database (`coverage.db`).
* **Syntax Highlighting**: Highlight.js (C, x86 ASM, custom Hex language).

## Data Pipeline
1. `rebrew catalog --json` parses the target binary (`target.dll`) and C source annotations (`// FUNCTION:`, `// GLOBAL:`).
2. `rebrew build-db` converts the resulting JSON into a structured SQLite database with tables for metadata, functions, globals, sections, and cells. It also pre-calculates coverage statistics for all sections to save frontend processing time.
3. `server.py` (Bottle app) serves:
   * Static files (index.html, app.js, style.css, van.min.js) which are **inlined and compressed** into a single response for the root `/` path to achieve a "first draw in the first TCP packet".
   * `/api/targets` endpoint that returns available targets (SERVER, Europa1400Gold, etc.) from the database.
   * `/api/targets/<target>/data` endpoint that queries SQLite for a specific target and returns lightweight metadata and section layouts (with gzip compression).
   * `/api/targets/<target>/functions/<va>` endpoint to fetch specific function/global details on-demand.
   * `/api/targets/<target>/asm?va=...&size=...` endpoint that dynamically disassembles binary chunks using Capstone (with LRU caching and in-memory cached binary reads).
   * `/regen` POST endpoint to trigger `rebrew catalog --json` + `rebrew build-db` regeneration.
   * Proxied paths: `/src/target_name/*` → project root, `/original/*` → project root

## State Management (VanJS)
The application state is managed using VanJS reactive primitives (`van.state`):
* `data`: Holds the fetched SQLite data (sections, globals, functions, summary).
* `originalDll`: Raw ArrayBuffer of the original DLL for byte slicing.
* `activeSection`: Tracks the currently selected PE section (`.text`, `.rdata`, `.data`, `.bss`).
* `activeFilters`: A `Set` tracking which match statuses are currently visible (Exact, Reloc, Matching, Stub).
* `searchQuery`: The current text in the search input (debounced 250ms).
* `currentFn` / `currentCellIndex`: Tracks the currently selected block in the grid.
* `isLightMode`: Tracks the current theme (persisted to `localStorage` as `recoverage_theme`).
* `showModal` / `modalTitle` / `modalContent` / `modalLang`: Modal dialog state for expanded code viewing.
* `isLoading`: Tracks network request states to show a pulsing loading overlay.
* `activeTarget`: Current target ID (e.g., "SERVER", "Europa1400Gold").
* `availableTargets`: List of available targets fetched from `/api/targets`.
* `filteredFnNames`: Derived state for search filtering (Set of function names matching search query).

## Components
The UI is broken down into functional VanJS components in `app.js`:

### 1. Topbar (`header.topbar`)
* **Logo & Title**: Retro-futuristic "R" logo with CRT scanline effects.
* **Tabs**: Dynamic segment selectors (e.g., `.text`, `.rdata`, `.data`, `.bss`) generated based on the active target's sections.
* **ProgressBar**: A dynamic, segmented progress bar showing coverage percentages. Text stats are overlaid on top of the colored segments. **Each segment is clickable** to toggle the corresponding filter.
* **Target Selector**: Dropdown to switch between targets (e.g., `SERVER`, `GOLD`, `GOLDTL`). Persists selection to URL (`?target=XXX`) and localStorage.
* **Search & Filters**: Debounced search input and toggleable filter buttons (All, E, R, M, S).
* **Actions**: Theme toggle (sun/moon icons) and Reload data buttons with a 5-second cooldown to prevent spam.

### 2. Grid (`.map`)
* A CSS Grid layout that dynamically calculates column widths using a `ResizeObserver` to keep blocks perfectly square.
* Cells are colored based on their status:
  * **Exact** (green) — byte-for-byte match
  * **Reloc** (blue/teal) — match after masking relocations
  * **Matching** (yellow) — near-miss with structural differences
  * **Stub** (red) — far off or placeholder
  * **ASM** (purple) — pure assembly (not reversible C)
  * **None** (gray) — undocumented block
* **Grid Caching**: Each section's grid is built once and cached in the DOM. Switching tabs simply toggles `display: none` vs `display: grid`, making tab switching instantaneous even for sections with 6,000+ chunks.
* **Fast HTML Building**: Grids are constructed using a single massive HTML string injection (`innerHTML`) rather than creating thousands of individual DOM nodes, drastically reducing initial render time.
* **CSS-Based Filtering**: Filtering and search dimming are handled by applying classes to the parent grid container (e.g., `.has-filters.show-exact`), allowing the browser's highly optimized CSS engine to instantly update thousands of cells without JavaScript loops.

### 3. Side Panel (`.panel`)
* **Sticky Header**: The panel header remains visible while scrolling through long code blocks, featuring a backdrop blur.
* **Metadata Grid**: Displays key-value pairs in an auto-filling grid with tightened vertical spacing for a cohesive look:
  * VA (Clickable link that jumps to the corresponding address in the grid)
  * Size, Offset, Symbol, Status, Origin, Compiler flags, Marker type
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

### 4. Modal (`modal`)
* Custom-built modal using plain VanJS divs (no external UI library)
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
* **CRT Scanlines**: A global scanline overlay (`body::after`) using a repeating linear gradient. It is kept very faint (`0.05` opacity in dark mode, `0.02` in light mode) to add texture without overpowering the UI.
* **Match Status Colors**:
  * **Exact**: Green (`rgba(51, 255, 0, 0.75)`)
  * **Reloc**: Blue/Teal (`rgba(2, 132, 199, 0.65)`)
  * **Matching**: Yellow/Amber (`rgba(255, 200, 0, 0.65)`)
  * **Stub**: Red (`rgba(255, 0, 0, 0.65)`)
* **Transitions**: Smooth `0.3s ease` transitions on background colors, borders, and opacities ensure fluid theme switching and filter toggling.
* **Scrollbars**: Custom WebKit scrollbars styled to match the active theme, with `scrollbar-gutter: stable` applied to code blocks to prevent layout shifts.
* **Loading Overlay**: A pulsing, vertically-centered overlay with large text (`font-size: 32px`, `font-weight: 700`) provides immediate visual feedback during data fetches.
* **Favicon**: A custom SVG data URI favicon that matches the retro-futuristic "R" logo with a cyan glow and scanline pattern.
* **Responsive**: Two-column layout on wide screens, single-column on screens <1300px.

## Key Implementation Details

### Performance Optimizations
* **First Draw in First TCP Packet**: `server.py` intercepts requests to `/` and inlines `index.html`, `style.css`, `app.js`, and `van.min.js` into a single response. This response is minified (using `rjsmin` and `rcssmin`) and compressed using **Brotli (`br`)** or **Zstandard (`zstd`)** (falling back to `gzip`) to ~14.5KB, fitting perfectly into the initial TCP congestion window (`cwnd`). This allows the browser to parse and render the UI shell instantly without any render-blocking network requests.
* **Advanced Compression**: The server dynamically selects the best compression algorithm based on the `Accept-Encoding` header, prioritizing `zstd`, then `br`, and falling back to `gzip`. Brotli cuts the massive JSON payload size in half compared to gzip (e.g., 119KB down to 58KB).
* **HTTP/1.1 Keep-Alive**: The Python server uses wsgiref which supports HTTP/1.1 keep-alive connections, eliminating handshake overhead for rapid subsequent API requests.
* **ETag Caching**: The heavy `/api/data` endpoint calculates an `ETag` based on the `coverage.db` file's modification time. If the database hasn't changed, the server responds with a `304 Not Modified` (0 bytes), making page reloads instantaneous.
* **Request Cancellation**: The UI uses `AbortController` to cancel in-flight network requests if the user clicks through multiple cells rapidly, saving bandwidth and preventing race conditions.
* **Deferred Highlight.js**: The heavy `highlight.js` library and its CSS are not loaded initially. They are dynamically fetched from a CDN only when a user clicks on a code block for the first time.
* **On-Demand Data Fetching**: The `/api/targets/<target>/data` endpoint only returns lightweight grid layouts and metadata. Detailed function information is fetched on-demand via `/api/targets/<target>/functions/<va>` when a user clicks a cell, drastically reducing memory usage and initial load times.
* **DOM Optimizations**: The grid uses **Event Delegation** (a single click listener on the parent container instead of 2,500+ individual listeners), **CSS Containment** (`contain: strict` on cells to prevent global layout recalculations), and **Content Visibility** (`content-visibility: auto` to skip rendering off-screen cells).
* **Grid Caching & CSS Filtering**: To handle sections with 6,000+ chunks (like `.bss`), grids are built once via fast HTML string injection and cached. Tab switching toggles `display: none`. Filtering and search dimming are handled entirely by CSS classes on the parent container, avoiding slow JavaScript loops over thousands of DOM nodes. CSS transitions on cells were removed to eliminate GPU overhead during mass state changes.
* **Precomputed Cell Properties**: Cell CSS classes and states are precomputed immediately after the JSON payload is fetched, preventing the UI from recalculating these strings thousands of times during the render loop.
* **Zero-Allocation JSON**: The backend pushes JSON serialization down into the SQLite C-engine (`json_group_array`, `json_object`), allowing Python to serve the `/api/data` endpoint with almost zero memory allocation overhead.
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
* **Dimming**: Non-matching cells are dimmed (opacity 0.15) rather than hidden, preserving grid layout

### Theme Persistence
* Checks `localStorage` for `recoverage_theme` ("light" or "dark")
* Falls back to `prefers-color-scheme` media query
* Theme changes are saved immediately

## Database Schema

The database uses a v2 schema (see [DB_FORMAT.md](../../rebrew/docs/DB_FORMAT.md) for the canonical reference).

### Tables
* `metadata`: Key-value pairs per target — coverage summaries, paths, `db_version` stamp
* `functions`: All reversed functions — va (INTEGER), name, vaStart, size, status, origin, cflags, symbol, files JSON, `detected_by` JSON, `size_by_tool` JSON, `textOffset`, ghidra_name, r2_name, is_thunk, is_export, sha256
* `globals`: Global variables — va (INTEGER), name, decl, files JSON, `origin`, `size`
* `sections`: PE sections — name, va, size, fileOffset, unitBytes, columns
* `cells`: Grid cells per section — section_name, start, end, state (none/exact/reloc/matching/matching_reloc/stub/padding/data/thunk), functions JSON, label, parent_function

### Views
* `section_cell_stats`: Aggregated counts per target+section — total_cells, exact_count, reloc_count, matching_count, stub_count, padding_count, data_count, thunk_count, none_count

## Future Ideas / TODOs
* [ ] **Minimap**: A global minimap of the entire PE file on the side.
* [ ] **XREFs**: Show cross-references for data segments (which functions read/write to this `.data` block).
* [ ] **Diff View**: Integrate the `matcher.py --diff` output directly into the UI for "Matching" and "Stub" blocks.
* [x] **Jump table absorption**: Switch/jump table bytes adjacent to functions are absorbed into the parent function's size rather than tracked as separate cells.
* [x] **Parent function linking**: Data and thunk cells automatically link to their parent function (detected via `func_end_va == data_start_va`).
* [x] **Ghidra label export**: `rebrew catalog --export-ghidra-labels` generates `ghidra_data_labels.json` from detected tables for round-trip sync.

---

# Potato Mode

Potato Mode is a pure HTML 5 alternative UI that works **without any CSS or JavaScript**. It's designed to work on severely constrained environments while providing near-visual-parity with the main VanJS dark-mode UI.

## Constraints
- **NO CSS** - All styling uses only HTML attributes (`bgcolor`, `cellpadding`, `cellspacing`, `border`, `background`, etc.)
- **NO JavaScript** - All interactivity uses plain HTML forms and links
- **HTML 5** - Uses `<!DOCTYPE html>` for modern parsing, with `lang="en"` and `<meta charset="utf-8">`

## Features
- **Full coverage grid visualization** with colored cells and cell merging for large blocks
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
| Matching | Yellow | `#f59e0b` |
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

- **`server.py`** — Bottle web application with `@app.get`/`@app.post` route decorators, `request`/`response` globals, and `static_file()` for serving assets. Handles compression (brotli/zstd/gzip).
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
python3 tests/test_potato.py
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
