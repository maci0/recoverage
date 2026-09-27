# Recoverage Design Principles

This document outlines the core architectural and operational philosophies that guide the development of the Recoverage UI dashboard.

How the dashboard is built is [DESIGN.md](DESIGN.md); the requirements these
principles serve are [USER_STORIES.md](USER_STORIES.md). Last verified against
the code: 2026-09-27.

## 1. Lightweight & Dependency-Free Stack
The UI is built to be as light and fast as possible. We avoid heavy frontend frameworks, relying instead on VanJS (a ~2 kB reactive library) and Vanilla CSS. The backend uses the minimal Bottle framework to serve data. The goal is uncompromising speed and low maintenance overhead.

## 2. First Draw in First TCP Packet
Initial page load time is critical. The entire Single Page Application (SPA) shell, including `index.html`, `style.css`, `app.js`, and `van.min.js`, must be inlined, minified, and aggressively compressed (via Brotli or Zstd), and must fit inside the initial TCP congestion window (10 x 1460-byte MSS). The shell sits at 14,090 B compressed, 510 bytes under the budget, so it fits with little to spare: `index.html` carries no static markup, which means the only way to hold that line is to leave deferrable work in `detail.js`, where the grid, hex dump, data inspector, function metadata grid, annotation extractor, code viewer, asm fetch, highlighting, and regen handler already live. `ui._check_payload_budget` prints the overage on every start; treat further growth as a regression.

## 3. Decoupled Architecture
Recoverage is a pure data consumer. Its serving path never links the `rebrew` matching tools: it expects a structured SQLite database (`coverage.db`) and never modifies it. `rebrew` is a runtime dependency only for the shared, stdlib-only workspace resolution (`rebrew.workspace`) and the in-process regen commands. This one-way data flow guarantees that the dashboard never interferes with the underlying decompilation pipeline.

## 4. Shift Computation to the Backend & Database
The frontend should be as "dumb" as possible regarding data processing. Coverage statistics, cell matching states, and JSON grouping must be pre-calculated by the database (`SQLite json_group_array`) or the backend before transmission. This ensures the UI remains fluid even when rendering binaries with tens of thousands of functions.

## 5. Aggressive Render Optimization
Rendering grids with thousands of cells (e.g., `.text` or `.bss` sections) requires strict render management:
- **Canvas Painting**: Each section's grid is one `<canvas>` painted from precomputed per-cell rectangles, one batched path per state, rather than thousands of DOM nodes.
- **Cached Layout**: The cell walk, row packing and hit-map are computed once per section and reused by every repaint; only the active section is painted.
- **Filter Repaint**: Search and status dimming are a second alpha pass over the cached rectangles, so a filter change costs a repaint rather than a DOM walk.

## 6. On-Demand Hydration & Lazy Loading
Memory and bandwidth are preserved by fetching heavy assets only when explicitly needed:
- Detailed function metadata (`/api/targets/<target>/functions/<va>`) and assembly (`/api/targets/<target>/asm`) are fetched only when a cell is clicked.
- Heavy libraries like `highlight.js` are deferred and loaded from this origin (vendored in `assets/`, so the dashboard works air-gapped) only upon the first code block interaction.
- Assembly generation (via Capstone) is performed on-demand and cached in memory using LRU caching.

## 7. Graceful Degradation (Potato Mode)
The dashboard must remain accessible even in the most constrained environments. "Potato Mode" is a first-class citizen—a pure HTML5/Table fallback requiring **zero JavaScript and zero CSS**. It provides near-visual-parity with the main SPA, ensuring the coverage data can be viewed on old setups, restricted browsers, or via terminal browsers.

## 8. Spatial Consistency
The coverage grid is a spatial map where grid position correlates linearly to the virtual memory address. When applying filters (e.g., showing only "Exact" matches), unmatched cells are visually dimmed (opacity changes), never removed. Exposing missing data by collapsing the grid ruins the spatial context of the memory layout.
