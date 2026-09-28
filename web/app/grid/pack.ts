/** The coverage map's geometry: packing, layout and hit testing.
 *
 * Ported from `assets/app.js` (`STATE_ID`, `packSection`) and `assets/detail.js`
 * (`walk`, `layout`, `hit`).  The lattice is one canvas per section drawn from
 * parallel typed arrays: an array of `{start, span, state}` objects thrashes the
 * cache on every paint and hit test, and these columns stay hot.
 *
 * Nothing here touches the DOM.  `layoutSection` needs the wrapper's usable
 * width and declared column count, and returns the geometry plus the canvas
 * size in CSS pixels. */

import type { Cell, Section } from "@/api";

/** Cells are packed into eight palette slots.
 *
 * Every state rebrew can write is listed: an unlisted one must not fall through
 * to 0, because `build_db` counts `verified` as an exact match and covered
 * bytes cover every state except `none`, so painting one as an undocumented gap
 * contradicts the number beside it.  The tooling-failure states share slot 7
 * ("other"): distinguishable from a gap without spending a palette entry each. */
const STATE_SLOTS = new Map<string, number>([
  ["none", 0],
  ["data", 0],
  ["thunk", 0],
  ["exact", 1],
  ["verified", 1],
  ["reloc", 2],
  ["near_match", 3],
  ["near_matching", 3],
  ["size_mismatch", 3],
  ["stub", 4],
  ["padding", 5],
  ["proven", 6],
  ["compile_error", 7],
  ["extract_error", 7],
  ["invalid_va", 7],
  ["missing_file", 7],
  ["missing_size", 7],
  ["skip", 7],
  ["unknown", 7],
  ["drift", 7],
  ["unchecked", 7],
]);

/** The palette slot a raw cell state paints as.
 *
 * Every state rebrew can write is listed: an unlisted one must not fall through
 * to 0, because `build_db` counts `verified` as an exact match and covered
 * bytes cover every state except `none`, so painting one as an undocumented gap
 * contradicts the number beside it. The tooling-failure states share slot 7
 * ("other"): distinguishable from a gap without spending a palette entry each,
 * and the fallback for a state a newer producer wrote. */
export function stateSlot(state: string): number {
  return STATE_SLOTS.get(state) ?? 7;
}

/** The words for each packed slot, in palette order. The grid tooltip shows
 * one, so hovering a cell says what the cell is instead of a raw index. */
export const STATE_LABEL = [
  "undocumented",
  "exact match",
  "reloc match",
  "near-match",
  "stub",
  "padding",
  "proven",
  "problem",
];

/** Legend rows: the words the UI uses for each slot, in the order the stylesheet
 * swatches them. */
export const LEGEND: Array<[number, string]> = [
  [0, "undocumented"],
  [1, "exact match"],
  [2, "reloc match"],
  [3, "near-match"],
  [4, "stub"],
  [5, "padding"],
  [6, "proven"],
  [7, "problem"],
];

/** The palette variables, in slot order. The canvas reads them off the wrapper
 * so a theme switch is a token swap rather than a repaint from literals. */
export const PALETTE_VARS = [
  "--none",
  "--exact-bg",
  "--reloc-bg",
  "--near-match-bg",
  "--stub-bg",
  "--padding-bg",
  "--proven-bg",
  "--other-bg",
];

/** A packed state's filter key. A state the grid can paint but no button can
 * isolate would be unreachable by filter. */
export const FILTER_KEY = ["", "exact", "reloc", "near_match", "stub", "padding", "proven", "problem"];

/** Packed section: parallel columns, one slot per cell. */
export type Packed = {
  n: number;
  starts: Uint32Array;
  ends: Uint32Array;
  spans: Uint16Array;
  states: Uint8Array;
  /** The first function per cell — its name, or a VA spelling — which is the
   * key both the search dimming and the selection outline compare against. */
  fns: Array<string | number>;
};

export function packSection(section: Section): Packed {
  const cells: Array<Cell> = section.cells ?? [];
  const n = cells.length;
  const starts = new Uint32Array(n);
  const ends = new Uint32Array(n);
  const spans = new Uint16Array(n);
  const states = new Uint8Array(n);
  const fns: Array<string | number> = Array.from({ length: n }, (): string => "");
  for (let i = 0; i < n; i += 1) {
    const cell = cells[i];
    if (cell === undefined) {
      continue;
    }
    starts[i] = cell.start ?? 0;
    ends[i] = cell.end ?? 0;
    spans[i] = cell.span === 0 ? 1 : (cell.span ?? 1);
    states[i] = stateSlot(cell.state);
    fns[i] = cell.functions?.[0] ?? "";
  }
  return { n, starts, ends, spans, states, fns };
}

export type Placement = {
  cell: number;
  col: number;
  row: number;
  span: number;
};

/** What one walk of the lattice measures. */
type Lattice = {
  parts: number;
  rows: number;
};

/** The lattice walk, and the two numbers it measures. A block lays out like a
 * line of text: it fills the columns left on its row and continues on the next.
 *
 * One placement per line a block touches, so the rect geometry is per placement
 * while the hit map answers every dot of the block with the same cell. A span
 * never occupies less than one dot.
 *
 * `parts` and `rows` come out of the same pass that emits the placements, so
 * sizing the geometry and filling it cannot disagree about the lattice, and
 * an empty section reports 0 lines and 0 placements rather than 1 line. */
function forEachPlacement(pack: Packed, cols: number, visit?: (p: Placement) => void): Lattice {
  let col = 0;
  let row = 0;
  let parts = 0;
  for (let i = 0; i < pack.n; i += 1) {
    let left = pack.spans[i] ?? 1;
    if (left < 1) {
      left = 1;
    }
    while (left > 0) {
      const take = Math.min(left, cols - col);
      visit?.({ cell: i, col, row, span: take });
      parts += 1;
      left -= take;
      col += take;
      if (col >= cols) {
        col = 0;
        row += 1;
      }
    }
  }
  return { parts, rows: parts === 0 ? 0 : row + (col > 0 ? 1 : 0) };
}

export type Geometry = {
  cols: number;
  gap: number;
  pad: number;
  cell: number;
  rows: number;
  parts: number;
  width: number;
  height: number;
  /** Row-major cell index per dot, -1 for an unpainted dot. */
  map: Int32Array;
  /** First placement of each cell, and the rest of its placements by
   * construction are consecutive from it. */
  cellFirst: Int32Array;
  cellRow: Int32Array;
  cellX: Float32Array;
  cellY: Float32Array;
  cellW: Float32Array;
  pCell: Int32Array;
  pX: Float32Array;
  pY: Float32Array;
  pW: Float32Array;
};

const GAP = 2;
const PAD = 8;
/** Cell size the map aims for, in CSS px. The section's declared column count
 * is the floor, not the target: a 64-column section in a wide wrapper would
 * otherwise draw blocks too large to read a function's shape from. */
const TARGET_CELL_PX = 10;

function minCellPx(viewportWidth: number): number {
  return viewportWidth < 700 ? 12 : 6;
}

export function layoutSection(
  pack: Packed,
  usable: number,
  declaredColumns: number,
  viewportWidth: number,
): Geometry {
  const usableWidth = Math.max(0, usable - PAD * 2);
  const min = minCellPx(viewportWidth);
  // Never render fewer columns than the section declares: shrinking the
  // lattice below that count re-wraps cells onto extra rows and leaves a blank
  // band under a short canvas. Narrow screens shrink the cells to `min`.
  // The floor of 1 is load-bearing, not a default: `declaredColumns` comes
  // from the coverage document, so a section declaring a negative count drops
  // the first term, and a wrapper narrower than one cell drops the second
  // (a hidden tab measures 0 wide). A zero-column lattice makes
  // forEachPlacement's `take = min(left, cols - col)` zero on every pass, so
  // `left` never reaches 0 and the walk spins forever in the render.
  const cols = Math.max(1, declaredColumns, Math.floor((usableWidth + GAP) / (TARGET_CELL_PX + GAP)));
  const cell = Math.max(min, (usableWidth - GAP * (cols - 1)) / cols);
  const { parts, rows } = forEachPlacement(pack, cols);
  const map = new Int32Array(Math.max(1, rows) * cols);
  map.fill(-1);
  const cellFirst = new Int32Array(pack.n);
  cellFirst.fill(-1);
  const cellRow = new Int32Array(pack.n);
  const cellX = new Float32Array(pack.n);
  const cellY = new Float32Array(pack.n);
  const cellW = new Float32Array(pack.n);
  const pCell = new Int32Array(parts);
  const pX = new Float32Array(parts);
  const pY = new Float32Array(parts);
  const pW = new Float32Array(parts);
  let placed = 0;
  forEachPlacement(pack, cols, ({ cell: i, col, row, span }) => {
    const base = row * cols + col;
    for (let k = 0; k < span; k += 1) {
      map[base + k] = i;
    }
    const x = PAD + col * (cell + GAP);
    const y = PAD + row * (cell + GAP);
    const w = span * cell + (span - 1) * GAP;
    if (cellFirst[i] === -1) {
      cellFirst[i] = placed;
      cellRow[i] = row;
      cellX[i] = x;
      cellY[i] = y;
      cellW[i] = w;
    }
    pCell[placed] = i;
    pX[placed] = x;
    pY[placed] = y;
    pW[placed] = w;
    placed += 1;
  });
  return {
    cols,
    gap: GAP,
    pad: PAD,
    cell,
    rows,
    parts,
    width: PAD * 2 + cols * cell + Math.max(0, cols - 1) * GAP,
    height: PAD * 2 + rows * cell + Math.max(0, rows - 1) * GAP,
    map,
    cellFirst,
    cellRow,
    cellX,
    cellY,
    cellW,
    pCell,
    pX,
    pY,
    pW,
  };
}

/** The cell under a canvas-relative point, or -1.
 *
 * Resolved against the canvas, which already carries the wrapper's scroll
 * offset: measured against the wrapper, a map scrolled sideways puts the click
 * on whichever cell sits under the same viewport coordinates. */
export function hitTest(geometry: Geometry | null, px: number, py: number): number {
  if (geometry === null) {
    return -1;
  }
  const { cols, gap, pad, cell, rows, map } = geometry;
  const gx = px - pad;
  const gy = py - pad;
  if (gx < 0 || gy < 0) {
    return -1;
  }
  const stride = cell + gap;
  const col = Math.floor(gx / stride);
  const row = Math.floor(gy / stride);
  if (col < 0 || row < 0 || col >= cols || row >= rows) {
    return -1;
  }
  if (gx - col * stride > cell || gy - row * stride > cell) {
    return -1;
  }
  const idx = map[row * cols + col] ?? -1;
  return idx < 0 ? -1 : idx;
}
