import type { ComponentChildren } from "preact";

import type { SearchEntry } from "@/api";
import { cn } from "@/lib/cn";
import { count, hex, isolate, plural, toVa } from "@/lib/format";

/** One match, as the result list draws it. */
export type SearchResult = {
  name: string;
  symbol: string | null;
  va: number;
  /** The section holding the address, or null when no section claims it. */
  section: string | null;
};

export type SearchResultsProps = {
  /** The search status sentence (count and guidance), shown as the list's
   * head. The shell's live region announces it, so the head is not re-read. */
  status: string;
  results: ReadonlyArray<SearchResult>;
  /** How many matched in all, so a capped list can say what it left out. */
  total: number;
  /** The section on screen, named beside the rows that are in it. */
  section: string | null;
  /** The row the arrow keys walked to, or null while none is. Named by the
   * search box's `aria-activedescendant` rather than by focus, because focus
   * stays in the field while the list is read from (ARIA 1.2 combobox). */
  activeIndex: number | null;
  /** The element id the listbox carries, the target of the field's
   * `aria-controls`. */
  listId: string;
  /** The row's own id, which `aria-activedescendant` points at. Derived from
   * the row's position so it is stable across a re-render. */
  optionId: (index: number) => string;
  onPick: (result: SearchResult) => void;
};

/** The matches a live search found, as a list the reader can pick from.
 *
 * The status line at the head of this list counts the matches and Enter jumps to
 * the first one, which left a target-wide term ("Init") matching 400 names with
 * no way to reach any but the first: the reader had to narrow the term until
 * one match survived, guessing a spelling. The list is that answer, ordered by
 * address so it reads in the same order the map does, and capped by
 * `SEARCH_RESULT_LIMIT` in the shell. */
export function SearchResults({
  status,
  results,
  total,
  section,
  activeIndex,
  listId,
  optionId,
  onPick,
}: SearchResultsProps): ComponentChildren {
  const hidden = total - results.length;
  return (
    // Positioned under the box rather than in the topbar's flow: the topbar is
    // sticky and measured into `--topbar-h`, so a list that grew it would move
    // the map the reader is looking at every keystroke. Wider than the field
    // from `lg`, where the field is 20rem: a decompiled name and its symbol
    // were both truncated to a few letters at that width.
    <div className="search-results absolute top-full start-0 z-30 mt-1 w-full min-w-72 max-w-form overflow-hidden rounded-card bg-surface shadow-lift lg:w-form">
      <p className="m-0 border-0 border-b border-border px-3 py-2 text-micro text-text-muted" aria-hidden="true">
        {status}
      </p>
      {/* A listbox, not an ordered list of buttons: the search box is the
          combobox that owns it, the arrow keys move the option through
          `aria-activedescendant` rather than through focus, and a list of
          buttons under a plain text field is announced as a list the reader has
          no relationship to (WCAG 4.1.2, 2.1.1). The rows are `<div>`s
          because an option is not a control and must not be in the tab order:
          a second set of tab stops behind the field the reader is typing in is
          the pattern ARIA 1.2 exists to avoid. With no match there is no
          listbox, only the head saying so. */}
      {results.length === 0 ? null : (
        <div
          className="max-h-72 overflow-y-auto p-1"
          id={listId}
          role="listbox"
          aria-label="Search matches"
        >
          {results.map((result, index) => (
            <div
              key={`${result.name}-${result.va}`}
              id={optionId(index)}
              role="option"
              aria-selected={index === activeIndex}
              className={cn(
                // The active row wears the FIELD's focus ring, not a fill. The
                // option is never focused, so the ring the reader can see on the
                // field is the one that says where the arrows are, and the fills
                // a selection could use (`surface-2` on `surface` is 1.05:1)
                // told a low-vision reader nothing (WCAG 1.4.11). The 3px inset
                // keeps it inside the list's own padding, so no row shifts when
                // the arrow moves.
                "search-result flex min-h-8 w-full cursor-pointer items-baseline gap-2 rounded-chip px-2 py-1.5 text-start font-mono text-micro text-text",
                index === activeIndex && "is-active",
              )}
              data-active={index === activeIndex ? "" : undefined}
              onClick={() => onPick(result)}
            >
              <span className="min-w-0 grow truncate" dir="auto">
                {isolate(result.name)}
              </span>
              {/* Below `sm` the symbol column truncated the name to a few
                  letters, and the symbol is usually the name with a linker
                  decoration, so a phone row keeps the name; the panel shows
                  the symbol once the row is picked. */}
              {result.symbol === null || result.symbol === result.name ? null : (
                <span className="min-w-0 shrink truncate text-text-muted max-sm:hidden" dir="auto">
                  {result.symbol}
                </span>
              )}
              <span className="shrink-0 text-text-muted">{hex(result.va, 8)}</span>
              {/* Which section each hit is in, on every row that has one. A
                  target-wide term matches `.rdata` and `.text` alike, and the
                  rows that were not in the section on screen carried nothing at
                  all, so two rows in different sections read identically and the
                  pick silently switched tabs. The current section is marked in
                  the accent and says "in", so a row that needs a tab switch is
                  the one that looks like it. */}
              {result.section === null ? null : (
                <span
                  className={
                    result.section === section ? "shrink-0 text-st-exact" : "shrink-0 text-text-faint"
                  }
                >
                  {result.section === section ? `in ${isolate(section)}` : isolate(result.section)}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
      {hidden > 0 ? (
        <p className="m-0 border-0 border-t border-border px-3 py-2 text-micro text-text-muted">
          {count(hidden)} more {plural(hidden, { one: "match", other: "matches" })} not shown. Narrow
          the search to see them.
        </p>
      ) : null}
    </div>
  );
}

/** The rows a match set draws, in the order the list shows them: address
 * ascending, which is the order the lattice reads top to bottom, and the order
 * the search box's Enter already picked its first jump from. An entry the index
 * carries no address for is left out rather than listed as a row that cannot
 * be jumped to. */
export function searchResultRows(
  names: ReadonlySet<string>,
  index: Record<string, SearchEntry>,
  sectionOf: (va: number) => string | null,
  limit: number,
): Array<SearchResult> {
  const rows: Array<SearchResult> = [];
  for (const name of names) {
    const entry = index[name];
    if (entry === undefined) {
      continue;
    }
    const va = toVa(entry.va);
    if (!Number.isFinite(va)) {
      continue;
    }
    // The section is filled after the cap, below. Resolving it here walked
    // every section per match, over all 40k hits of a broad term, to label the
    // 50 rows the list draws (p50 1.68 ms against 1.37 ms, p95 7.82 ms against
    // 3.63 ms, bun, 21 runs).
    rows.push({ name, symbol: entry.symbol ?? null, va, section: null });
  }
  rows.sort((left, right) => left.va - right.va || left.name.localeCompare(right.name));
  const shown = rows.length > limit ? rows.slice(0, limit) : rows;
  for (const row of shown) {
    row.section = sectionOf(row.va);
  }
  return shown;
}
