import type { ComponentChildren } from "preact";

import type { StatsPayload } from "@/api";
import { Button } from "@/components/ui/button";
import { count, percentLabel } from "@/lib/format";
import { STATE_FILTERS, paletteVarForFilter } from "@/states";

/** The bucket `/stats` counts a state under. Only the tooling failures differ:
 * the server folds them into `other`, which is the state the map paints as slot
 * 7 and the toolbar calls "problem". */
const BUCKET_KEY = {
  exact: "exact",
  reloc: "reloc",
  near_match: "near_match",
  stub: "stub",
  padding: "padding",
  proven: "proven",
  problem: "other",
} as const satisfies Record<string, string>;

export type StatsStripProps = {
  stats: StatsPayload | null;
  /** Why the numbers are missing, when they are. */
  error: string | null;
  /** A load is in flight, which is also the state a regen puts the strip in
   * while it runs for minutes. */
  loading: boolean;
  /** The section the map is showing, or null before one is known. */
  section: string | null;
  filters: ReadonlySet<string>;
  onToggleFilter: (key: string) => void;
};

/** The numbers above the map: how much of the target is covered, and how the
 * section on screen breaks down.
 *
 * Potato Mode prints the same two lines from the same `/stats` payload (its
 * progress bar and its map header), so the two views of one target cannot
 * disagree about the map below them. Each state count is also the filter pill
 * for that state: "where are the stubs" is one click, and it answers with the
 * pill the toolbar already draws rather than a second vocabulary to learn. */
export function StatsStrip({
  stats,
  error,
  loading,
  section,
  filters,
  onToggleFilter,
}: StatsStripProps): ComponentChildren {
  if (stats === null) {
    // The numbers are dropped while a rebuild runs and come back after it, and
    // a strip that is simply gone says nothing about the minutes in between:
    // the line holds the place the figures occupied and says they are on their
    // way. A failed read says the same thing about itself rather than leaving
    // the reader to assume a target has no coverage yet.
    if (error !== null) {
      return <p className="stats font-mono text-micro text-muted">Coverage summary unavailable.</p>;
    }
    return loading ? (
      <p className="stats font-mono text-micro text-muted">Coverage summary loading...</p>
    ) : null;
  }
  const row = section === null ? undefined : stats.sections[section];
  return (
    <div className="stats font-mono text-micro text-muted flex flex-wrap items-center gap-x-4 gap-y-1">
      <span className="stats-target">
        <b className="text-label text-text">{percentLabel(stats.summary.coveragePercent)}</b>{" "}
        covered · {count(stats.summary.matchedFunctions)}/{count(stats.summary.totalFunctions)}{" "}
        functions matched
      </span>
      {row === undefined ? null : (
        <span className="stats-section flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-text">{section}</span>
          {STATE_FILTERS.map((entry) => {
            const bucket = BUCKET_KEY[entry.key] ?? entry.key;
            const blocks = row[bucket] ?? 0;
            const on = filters.has(entry.key);
            return (
              <Button
                key={entry.key}
                className="stat-count min-h-6 min-w-6 px-1.5 py-0.5 text-micro"
                active={on}
                aria-label={`${entry.title}: ${blocks} blocks, filter ${on ? "on" : "off"}`}
                aria-pressed={on}
                title={`${entry.title}: ${blocks} blocks`}
                onClick={() => onToggleFilter(entry.key)}
              >
                <span
                  className="swatch"
                  aria-hidden="true"
                  style={{ background: `var(${paletteVarForFilter(entry.key)})` }}
                />
                {entry.label}
                <span className="text-text">{count(blocks)}</span>
              </Button>
            );
          })}
          <span>{percentLabel(row.coverage_pct)} covered</span>
        </span>
      )}
    </div>
  );
}
