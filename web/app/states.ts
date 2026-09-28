/** The cell-state vocabulary every surface renders through.
 *
 * rebrew owns the vocabulary (`rebrew.build_db._KNOWN_CELL_STATES`); this is
 * the SPA's one spelling of it, and it is shared rather than per-surface
 * because a state the map paints but the toolbar cannot filter, or a figure the
 * strip prints beside a differently painted cell, reads as two dashboards. The
 * geometry that consumes a slot lives in `@/grid/pack`; nothing here touches
 * the DOM, and nothing here depends on the geometry.
 */

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

/** The palette slot a raw cell state paints as, slot 7 for a state a newer
 * producer wrote. */
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

/** Whether a cell survives the active status filter.
 *
 * `FILTER_KEY` is indexed by the PAINT slot, and slot 0 is a projection of
 * three different states: the undocumented ground and the two data/thunk
 * states. They cannot share a filter answer, so the exemption is carried per
 * cell as a fact of the cell's own state rather than inferred from the slot it
 * happens to paint into. Potato Mode reaches the same answer through
 * `potato._state_survives_filter`, which tests the raw state; the two rules
 * are pinned to each other by
 * `test_the_status_filter_agrees_with_potato_mode_cell_for_cell` in
 * tests/test_server.py, because the ground is the one cell a status filter
 * must not dim: it is the background the statuses are read against, and dimming
 * it makes a filtered map look like the cell does not exist. */
export function survivesFilter(slot: number, ground: number, active: ReadonlySet<string>): boolean {
  if (active.size === 0 || ground === 1) {
    return true;
  }
  return active.has(FILTER_KEY[slot] ?? "");
}

/** The state filters the toolbar and the stats strip offer, in palette order.
 * A state the grid can paint but no control can isolate is unreachable, so
 * this list covers every slot but the first (undocumented, which is the absence
 * of a match and has no filter). It is the one place the key, the pill's label
 * and the words on its tooltip are written, so the two surfaces that print
 * them cannot drift. */
export const STATE_FILTERS = [
  { key: "exact", label: "E", aria: "Filter exact", title: "Exact match" },
  { key: "reloc", label: "R", aria: "Filter reloc", title: "Reloc match" },
  { key: "near_match", label: "M", aria: "Filter near-match", title: "Near-match" },
  { key: "stub", label: "S", aria: "Filter stub", title: "Stub" },
  { key: "padding", label: "P", aria: "Filter padding", title: "Padding" },
  {
    key: "proven",
    label: "V",
    aria: "Filter proven",
    title: "Proven (verified equivalent)",
  },
  {
    key: "problem",
    label: "X",
    aria: "Filter problem",
    title: "Problem (build or classification failure)",
  },
] as const;

/** The palette variable a filter's cells paint with. FILTER_KEY is in slot
 * order and PALETTE_VARS is in slot order, so the two index alike. */
export function paletteVarForFilter(key: string): string {
  return PALETTE_VARS[FILTER_KEY.indexOf(key)] ?? "--none";
}
