# Recoverage Design Principles

This document outlines the core architectural and operational philosophies that guide the development of the Recoverage UI dashboard.

## 1. Lightweight & Dependency-Free Stack
The UI is built to be as light and fast as possible. We avoid heavy frontend frameworks, relying instead on VanJS (a 1.0kB reactive library) and Vanilla CSS. The backend uses the minimal Bottle framework to serve data. The goal is uncompromising speed and low maintenance overhead.

## 2. First Draw in First TCP Packet
Initial page load time is critical. The entire Single Page Application (SPA) shell—including `index.html`, `style.css`, `app.js`, and `van.min.js`—must be inlined, minified, and aggressively compressed (via Brotli or Zstd). The total payload should fit within the initial TCP congestion window (~14.5 KB), ensuring instantaneous rendering without render-blocking network round-trips.

## 3. Decoupled Architecture
Recoverage is a pure data consumer. It must remain strictly decoupled from the `rebrew` matching tools. It expects a structured SQLite database (`coverage.db`) and never modifies it. This one-way data flow guarantees that the dashboard never interferes with the underlying decompilation pipeline.

## 4. Shift Computation to the Backend & Database
The frontend should be as "dumb" as possible regarding data processing. Coverage statistics, cell matching states, and JSON grouping must be pre-calculated by the database (`SQLite json_group_array`) or the backend before transmission. This ensures the UI remains fluid even when rendering binaries with tens of thousands of functions.

## 5. Aggressive DOM Optimization
Rendering grids with thousands of cells (e.g., `.text` or `.bss` sections) requires strict DOM management:
- **String Injection**: Grids are built via massive HTML string injection (`innerHTML`) rather than appending individual DOM nodes.
- **Event Delegation**: Use a single click listener on the parent container instead of thousands of individual listeners.
- **CSS Filtering**: Search and status filtering (dimming cells) apply CSS classes to the parent container. The browser's optimized CSS engine handles the visual update instantly, avoiding slow JavaScript loops over DOM nodes.

## 6. On-Demand Hydration & Lazy Loading
Memory and bandwidth are preserved by fetching heavy assets only when explicitly needed:
- Detailed function metadata and assembly are fetched via `/api/targets/<target>/functions/<va>` only when a cell is clicked.
- Heavy libraries like `highlight.js` are deferred and loaded from a CDN only upon the first code block interaction.
- Assembly generation (via Capstone) is performed on-demand and cached in memory using LRU caching.

## 7. Graceful Degradation (Potato Mode)
The dashboard must remain accessible even in the most constrained environments. "Potato Mode" is a first-class citizen—a pure HTML5/Table fallback requiring **zero JavaScript and zero CSS**. It provides near-visual-parity with the main SPA, ensuring the coverage data can be viewed on old setups, restricted browsers, or via terminal browsers.

## 8. Spatial Consistency
The coverage grid is a spatial map where grid position correlates linearly to the virtual memory address. When applying filters (e.g., showing only "Exact" matches), unmatched cells are visually dimmed (opacity changes), never removed. Exposing missing data by collapsing the grid ruins the spatial context of the memory layout.
