import type { ComponentChildren } from "preact";

import type { StatsPayload } from "@/api";
import { Button } from "@/components/ui/button";
import { STATE_FILTERS, paletteVarForFilter } from "@/grid/pack";

/** The numbers above the map: how much of the target is covered, and how the
 * section on screen breaks down.
 *
 * Potato Mode prints the same two lines from the same `/stats` payload (its
 * progress bar and its map header), so the two views of one target cannot
 * disagree about the map below them. Each state count is also the filter pill
 * for that state: "where are the stubs" is one click, and it answers with the
 * pill the toolbar already draws rather than a second vocabulary to learn. */

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

/** A block or function count, grouped the way a reader scans one. */
function tally(amount: number): string {
  return amount.toLocaleString();
}

export type StatsStripProps = {
  stats: StatsPayload | null;
  /** Why the numbers are missing, when they are. */
  error: string | null;
  /** The section the map is showing, or null before one is known. */
  section: string | null;
  filters: ReadonlySet<string>;
  onToggleFilter: (key: string) => void;
};

export function StatsStrip({
  stats,
  error,
  section,
  filters,
  onToggleFilter,
}: StatsStripProps): ComponentChildren {
  if (stats === null) {
    // Nothing to say until the numbers land; a failed read says so in place
    // rather than leaving the reader to assume a target has no coverage yet.
    return error === null ? null : (
      <p className="stats font-mono text-micro text-muted">Coverage summary unavailable.</p>
    );
  }
  const row = section === null ? undefined : stats.sections[section];
  return (
    <div className="stats font-mono text-micro text-muted flex flex-wrap items-center gap-x-4 gap-y-1">
      <span className="stats-target">
        <b className="text-label text-text">{stats.summary.coveragePercent.toFixed(1)}%</b>{" "}
        covered · {tally(stats.summary.matchedFunctions)}/{tally(stats.summary.totalFunctions)}{" "}
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
                className="stat-count px-1.5 py-0 text-micro"
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
                <span className="text-text">{tally(blocks)}</span>
              </Button>
            );
          })}
          <span>{row.coverage_pct.toFixed(1)}% covered</span>
        </span>
      )}
    </div>
  );
}
