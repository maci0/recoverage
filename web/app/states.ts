/** The cell-state vocabulary every surface renders through.
 *
 * rebrew owns the vocabulary (a private `_KNOWN_CELL_STATES`; the module
 * holding it moved from `build_db` to `coverage_db`); this is
 * the SPA's one spelling of it, and it is shared rather than per-surface
 * because a state the map paints but the toolbar cannot filter, or a figure the
 * strip prints beside a differently painted cell, reads as two dashboards. The
 * geometry that consumes a slot lives in `@/grid/pack`; nothing here touches
 * the DOM, and nothing here depends on the geometry.
 *
 * `@/lib/format` is the one import, and it is a leaf (it imports nothing), so
 * the dim caption below prints through `count` and `plural` the way every other
 * figure on the page does instead of formatting a number by hand.
 */

import { count, plural } from "@/lib/format";

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
 * one, so hovering a cell says what the cell is instead of a raw index.
 * Verdicts keep their code casing (relumea brand guide, "Terminology"). */
export const STATE_LABEL = [
  "undocumented",
  "EXACT",
  "RELOC",
  "NEAR",
  "STUB",
  "padding",
  "PROVEN",
  "problem",
];

/** The face a state word is set in. A verdict is a code token (relumea brand
 * guide, "Terminology"), so it takes the mono the status chip and the CLI
 * print it in; the descriptive words (`undocumented`, `padding`, `problem`)
 * are prose and stay in the sans. One rule for the pills and the legend, so
 * the two keys to one map cannot set one word two ways. */
export function verdictFace(label: string): string {
  return label === label.toUpperCase() ? "font-mono tracking-chip" : "";
}

/** The verdict fill tokens, in slot order. The canvas resolves them on the map
 * element, so a theme switch is a token swap rather than a repaint from
 * literals. The brand has no padding verdict; padding is alignment filler, so
 * it takes the strong hairline, the quietest fill that is not the unlit cell. */
export const PALETTE_VARS = [
  "--color-cell-unlit",
  "--color-cell-exact",
  "--color-cell-reloc",
  "--color-cell-near",
  "--color-cell-stub",
  "--color-border-strong",
  "--color-cell-proven",
  "--color-cell-fail",
];

/** The same fills as utility classes, in slot order, for the legend and the
 * filter swatches. Spelled out rather than built from `PALETTE_VARS`, because
 * Tailwind only generates a class it can read in the source. */
export const SWATCH_CLASS = [
  "bg-cell-unlit",
  "bg-cell-exact",
  "bg-cell-reloc",
  "bg-cell-near",
  "bg-cell-stub",
  "bg-border-strong",
  "bg-cell-proven",
  "bg-cell-fail",
];

/** The mark each slot draws over its fill, in slot order, as the utility the
 * legend and filter swatches use (`index.css`); the map draws the same tile on
 * the canvas. The relumea fills separate verdicts by hue at one lightness, and
 * EXACT, RELOC and PROVEN share its green while STUB and padding share its
 * grey, so a colour-blind reader, or anyone at a glance, cannot tell those
 * apart by fill alone (WCAG 1.4.1). Every pair of fills closer than the ΔE
 * floor in tests/test_server.py carries different marks. */
export type Mark = "" | "mark-dots" | "mark-hatch" | "mark-rule";
export const MARK_CLASS: ReadonlyArray<Mark> = ["", "", "mark-dots", "", "", "mark-rule", "mark-hatch", ""];

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

/** Whether a block is dimmed: either rule the reader armed excludes it.
 *
 * `CoverageMap.paint` was the only place either dimming rule was spelled out,
 * and nothing counted what survived them, so a filter naming states this
 * section does not hold painted an empty map that read as "this section is
 * empty", with the way back a hunt for the "All states" pill. One predicate
 * answers both the paint and the count the caption reports, so the sentence
 * under the lattice and the lattice itself cannot disagree.
 *
 * A block both rules dim is one the reader excluded twice; there is nothing for
 * the answer to disambiguate, which is why this is a boolean and `dimSummary`
 * names the armed rules from the two inputs instead of from this one.
 *
 * The search answer arrives already resolved (`searchHit`), not as a name to
 * look up: the paint walks every placement twice per palette slot, and a
 * `Set.has` of a freshly built string there allocated one string per part per
 * pass per slot. The caller builds the column once. */
export function isDimmed(
  slot: number,
  ground: number,
  searchHit: boolean,
  filters: ReadonlySet<string>,
  searching: boolean,
): boolean {
  if (filters.size > 0 && !survivesFilter(slot, ground, filters)) {
    return true;
  }
  return searching && !searchHit;
}

/** What `dimSummary` says about each combination of the two armed rules: the
 * clause naming what dimmed the lattice, and the clause naming what undoes it.
 * Indexed by the one key each combination has. */
const DIM_CAUSE = {
  filter: ["the status filter", "turn off the status filter"],
  search: ["the search", "clear the search"],
  both: [
    "the status filter and the search",
    "turn off the status filter and clear the search",
  ],
} as const satisfies Record<string, readonly [string, string]>;

/** Which of the two armed rules the caption is describing. */
function dimCauseKey(filtering: boolean, searching: boolean): keyof typeof DIM_CAUSE {
  if (filtering) {
    return searching ? "both" : "filter";
  }
  return "search";
}

/** The caption a partially dimmed lattice shows under itself, or null when
 * nothing is dimming it.
 *
 * The moment this answers: a reader picks a status (or types a term) and the
 * map goes blank. Dimming alone reads as "this section has no blocks", and the
 * status strip's counts are per state over the whole target rather than over
 * the section on screen, so neither the map nor the strip said how much of
 * THIS section was still shown or which rule hid the rest.
 *
 * It names the rule and not its value: the search box above the map carries the
 * term and the pills carry the states, so repeating either here is one more
 * line that can fall out of step with the control it mirrors. The counts go
 * through `count` and `plural` like every other number on the page.
 *
 * `groundLit` is how many of the `lit` blocks are undocumented ground, which a
 * status filter never dims (`survivesFilter`). Under a filter alone those
 * blocks are lit without matching it, so a section holding none of the chosen
 * states read "Showing 268 of 821 blocks" beside a pill that counted 0. */
export function dimSummary(
  lit: number,
  total: number,
  groundLit: number,
  filters: ReadonlySet<string>,
  searching: boolean,
): string | null {
  if (total === 0 || lit >= total) {
    return null;
  }
  const cause = DIM_CAUSE[dimCauseKey(filters.size > 0, searching)];
  const blocks = plural(total, { one: "block", other: "blocks" });
  const shown = `Showing ${count(lit)} of ${count(total)} ${blocks}, dimmed by ${cause[0]}.`;
  if (lit === 0) {
    return `${shown} Every block here is dimmed; ${cause[1]} to see them again.`;
  }
  const exempt = filters.size > 0 && !searching ? groundLit : 0;
  if (exempt === 0) {
    return shown;
  }
  const verb = plural(exempt, { one: "is", other: "are" });
  if (exempt === lit) {
    return `No block here matches the status filter. The ${count(exempt)} lit ${plural(exempt, {
      one: "block",
      other: "blocks",
    })} ${verb} undocumented, which a status filter never dims; ${cause[1]} to see the rest.`;
  }
  return `${shown} ${count(exempt)} of them ${verb} undocumented, which a status filter never dims.`;
}
/** The state filters the stats strip offers, in palette order. A state the grid
 * can paint but no control can isolate is unreachable, so this list covers
 * every slot but the first (undocumented, which is the absence of a match and
 * has no filter). It is the one place the key, the pill's word and its
 * description are written. `label` is the word `STATE_LABEL` gives the same
 * slot, so the pill, the legend and the map tooltip say one thing. */
export const STATE_FILTERS = [
  { key: "exact", label: "EXACT", title: "Recompiled bytes identical" },
  { key: "reloc", label: "RELOC", title: "Identical except linker-filled addresses" },
  { key: "near_match", label: "NEAR", title: "Close; the diff names the rest" },
  { key: "stub", label: "STUB", title: "Control flow still diverges" },
  { key: "padding", label: "padding", title: "Alignment filler between functions" },
  { key: "proven", label: "PROVEN", title: "Semantic equivalence proven" },
  { key: "problem", label: "problem", title: "Build or classification failure" },
] as const;

/** The swatch classes (fill and mark) a filter's cells paint with.
 * FILTER_KEY, SWATCH_CLASS and MARK_CLASS are all in slot order, so they
 * index alike. */
export function swatchForFilter(key: string): string {
  const slot = FILTER_KEY.indexOf(key);
  return `${SWATCH_CLASS[slot] ?? "bg-cell-unlit"} ${MARK_CLASS[slot] ?? ""}`.trim();
}
