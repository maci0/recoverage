import type { ComponentChildren } from "preact";

import type { SearchEntry } from "@/api";
import { count, hex, isolate, toVa } from "@/lib/format";

/** One match, as the result list draws it. */
export type SearchResult = {
  name: string;
  symbol: string | null;
  va: number;
  /** The section holding the address, or null when no section claims it. */
  section: string | null;
};

export type SearchResultsProps = {
  results: ReadonlyArray<SearchResult>;
  /** How many matched in all, so a capped list can say what it left out. */
  total: number;
  /** The section on screen, named beside the rows that are in it. */
  section: string | null;
  onPick: (result: SearchResult) => void;
};

/** The matches a live search found, as a list the reader can pick from.
 *
 * The status line beside the search box counts the matches and Enter jumps to
 * the first one, which left a target-wide term ("Init") matching 400 names with
 * no way to reach any but the first: the reader had to narrow the term until
 * one match survived, guessing a spelling. The list is that answer, ordered by
 * address so it reads in the same order the map does, and capped by
 * `SEARCH_RESULT_LIMIT` in the shell. */
export function SearchResults({
  results,
  total,
  section,
  onPick,
}: SearchResultsProps): ComponentChildren {
  if (results.length === 0) {
    return null;
  }
  const hidden = total - results.length;
  return (
    // Positioned under the box rather than in the topbar's flow: the topbar is
    // sticky and measured into `--topbar-h`, so a list that grew it would move
    // the map the reader is looking at every keystroke.
    <div className="search-results absolute top-full start-0 z-30 mt-1 w-[min(28rem,90vw)] rounded-hair border border-line bg-panel shadow-text">
      <ol className="m-0 max-h-64 list-none overflow-y-auto p-0">
        {results.map((result) => (
          <li key={`${result.name}-${result.va}`}>
            <button
              type="button"
              className="search-result flex w-full items-baseline gap-2 border-0 bg-transparent px-2 py-1 text-left font-mono text-micro text-text hover:bg-btn-hover"
              onClick={() => onPick(result)}
            >
              <span className="min-w-0 grow truncate" dir="auto">
                {isolate(result.name)}
              </span>
              {result.symbol === null || result.symbol === result.name ? null : (
                <span className="min-w-0 shrink truncate text-muted" dir="auto">
                  {result.symbol}
                </span>
              )}
              <span className="shrink-0 text-muted">{hex(result.va, 8)}</span>
              {section !== null && result.section === section ? (
                <span className="shrink-0 text-accent">in {section}</span>
              ) : null}
            </button>
          </li>
        ))}
      </ol>
      {hidden > 0 ? (
        <p className="border-0 border-t border-line px-2 py-1 font-mono text-micro text-muted">
          {count(hidden)} more match{hidden === 1 ? "es" : ""} - narrow the search to see them.
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
    rows.push({ name, symbol: entry.symbol ?? null, va, section: sectionOf(va) });
  }
  rows.sort((left, right) => left.va - right.va || left.name.localeCompare(right.name));
  return rows.length > limit ? rows.slice(0, limit) : rows;
}
