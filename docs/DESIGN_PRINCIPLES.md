# Recoverage Design Principles

This document outlines the core architectural and operational philosophies that guide the development of the Recoverage UI dashboard.

How the dashboard is built is [DESIGN.md](DESIGN.md); the requirements these
principles serve are [USER_STORIES.md](USER_STORIES.md). Last verified against
the code: 2026-09-29.

## 1. A Lightweight Frontend and a Minimal Backend
The UI is built to be as light and fast as possible. The frontend is one built bundle, Preact (through `preact/compat`) with Tailwind CSS 4 over a CSS-variable token layer, compiled by Vite into `assets/app.js` and `assets/style.css` and inlined into the shell; Preact rather than React is most of why it is small. The backend uses the minimal Bottle framework to serve data. The goal is uncompromising speed and low maintenance overhead.

## 2. First Draw in First TCP Packet
Initial page load time is critical. The entire Single Page Application (SPA) shell, `index.html` with `style.css` and `app.js` inlined, minified and compressed (Brotli, Zstd or gzip, smallest wins), is one response, so the first paint needs no render-blocking subresource request. Since the frontend became one Preact + Tailwind bundle the shell measures ~43 KB brotli (42,795 B on 2026-10-27), which cannot fit RFC 6928's initial congestion window; the budget in `ui._TCP_CWND_BUDGET` is therefore a 90,000-byte checked ceiling with headroom over that measurement rather than the protocol constant. `ui._check_payload_budget` prints the overage on every start and `tests/test_api.py` fails when the shipped shell crosses the ceiling, so unbounded growth is still a regression. The three compressed sizes behind that claim are re-derived by `make payload-budget`.

## 3. Decoupled Architecture
Recoverage is a pure data consumer. Its serving path never links the `rebrew` matching tools: it reads canonical project inputs through `rebrew.coverage_project.load_project_coverage`, or the portable coverage documents `RECOVERAGE_SNAPSHOTS` selects, and writes neither. `rebrew` is a runtime dependency for workspace resolution (`rebrew.workspace`), function metadata (`rebrew.metadata`), the live coverage model (`rebrew.coverage_project`) and the document reader (`rebrew.coverage_toml`). This one-way data flow guarantees that the dashboard never interferes with the underlying decompilation pipeline.

## 4. Shift Computation to the Reader & the Backend
The frontend should be as "dumb" as possible regarding data processing. Coverage statistics, cell matching states, and the JSON grouping the API serves must be computed before transmission — in the document reader (`rebrew.coverage_toml`'s derived fields) or in the backend — never in the browser. This ensures the UI remains fluid even when rendering binaries with tens of thousands of functions.

## 5. Aggressive Render Optimization
Rendering grids with thousands of cells (e.g., `.text` or `.bss` sections) requires strict render management:
- **Canvas Painting**: Each section's grid is one `<canvas>` painted from precomputed per-cell rectangles, one batched path per state, rather than thousands of DOM nodes.
- **Cached Layout**: The cell walk, row packing and hit-map are computed once per section and reused by every repaint; only the active section is painted.
- **Filter Repaint**: Search and status dimming are a second alpha pass over the cached rectangles, so a filter change costs a repaint rather than a DOM walk.

## 6. On-Demand Fetching
Memory and bandwidth are preserved by fetching heavy payloads only when explicitly needed:
- Detailed function metadata (`/api/targets/<target>/functions/<va>`) and assembly (`/api/targets/<target>/asm`) are fetched only when a cell is clicked.
- Section cells are fetched only when a section tab is first opened: every `/data` payload carries all section rows but only the requested one's cells, so a tab switch fetches what it is about to paint rather than the whole target, and a tab is one request rather than four up front.
- The original binary is downloaded once per target, not once per selection, and the byte slices come out of that buffer client-side.
- highlight.js (core, the two grammars the dashboard shows and the custom `hex` language) is the second bundle `assets/highlight.js`, fetched from the dashboard's own origin the first time a code pane renders, so the shell does not carry it.
- Assembly generation (via Capstone) is performed on-demand and cached in memory using LRU caching.

## 7. Graceful Degradation (Potato Mode)
The dashboard must remain accessible even in the most constrained environments. "Potato Mode" is a first-class citizen—a pure HTML5/Table fallback requiring **zero JavaScript and zero CSS**. It provides near-visual-parity with the main SPA, ensuring the coverage data can be viewed on old setups, restricted browsers, or via terminal browsers.

## 8. Spatial Consistency
The coverage grid is a spatial map where grid position correlates linearly to the virtual memory address. When applying filters (e.g., showing only "Exact" matches), unmatched cells are visually dimmed (opacity changes), never removed. Exposing missing data by collapsing the grid ruins the spatial context of the memory layout.
