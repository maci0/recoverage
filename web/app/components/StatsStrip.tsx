import type { ComponentChildren } from "preact";

import type { StatsPayload } from "@/api";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { count, percentLabel, plural } from "@/lib/format";
import { STATE_FILTERS, swatchForFilter, verdictFace } from "@/states";

/** The bucket `/stats` counts a state under. Only the tooling failures differ:
 * the server folds them into `other`, which is the state the map paints as slot
 * 7 and the filter calls "problem". */
const BUCKET_KEY = {
  exact: "exact",
  reloc: "reloc",
  near_match: "near_match",
  stub: "stub",
  padding: "padding",
  proven: "proven",
  problem: "other",
} as const satisfies Record<string, string>;

/** The section `summary.coveragePercent` measures (`server._summary` divides
 * `.text`'s covered bytes by its size), so the headline names it: "of the
 * target" claimed the data sections too, which the figure never counts. */
const TEXT_SECTION = ".text";

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

/** The numbers above the map and the filter row under them.
 *
 * Potato Mode prints the same two lines from the same `/stats` payload (its
 * progress bar and its map header), so the two views of one target cannot
 * disagree about the map below them. Each state is one pill: its fill, its
 * word and, once `/stats` has answered, its block count in the section on
 * screen. The pill is the filter for that state, so "where are the stubs" is
 * one click. The pills render before the counts arrive and when they never do,
 * because a filter does not depend on the numbers. */
export function StatsStrip({
  stats,
  error,
  loading,
  section,
  filters,
  onToggleFilter,
}: StatsStripProps): ComponentChildren {
  const row = stats === null || section === null ? undefined : stats.sections[section];
  return (
    <div className="stats mb-3 flex flex-col gap-3">
      <Summary
        stats={stats}
        error={error}
        loading={loading}
        section={row === undefined ? null : section}
        sectionPct={row?.coverage_pct ?? null}
      />
      <div
        className="filters flex flex-wrap items-center gap-1.5"
        role="group"
        aria-label="Filter the map by state"
      >
        <Button
          className="filter-btn"
          size="sm"
          active={filters.size === 0}
          aria-pressed={filters.size === 0}
          title="Show every state"
          onClick={() => onToggleFilter("all")}
        >
          All states
        </Button>
        {STATE_FILTERS.map((entry) => {
          const bucket = BUCKET_KEY[entry.key];
          const blocks = row === undefined ? null : (row[bucket] ?? 0);
          const on = filters.has(entry.key);
          return (
            <Button
              key={entry.key}
              className="filter-btn"
              size="sm"
              active={on}
              aria-pressed={on}
              aria-label={
                blocks === null
                  ? entry.label
                  : `${entry.label}, ${count(blocks)} ${plural(blocks, {
                      one: "block",
                      other: "blocks",
                    })}`
              }
              title={entry.title}
              onClick={() => onToggleFilter(entry.key)}
            >
              <span
                className={cn("swatch size-2.5 rounded-cell", swatchForFilter(entry.key))}
                aria-hidden="true"
              />
              <span className={verdictFace(entry.label)}>{entry.label}</span>
              {blocks === null ? null : (
                <span className="font-mono tabular-nums text-text-muted">{count(blocks)}</span>
              )}
            </Button>
          );
        })}
      </div>
    </div>
  );
}

/** The target's headline figure, or the line that stands in for it. The line
 * holds the place while a rebuild runs for minutes and says why when the read
 * failed, rather than leaving the reader to assume a target has no coverage.
 *
 * The headline is `.text`'s figure and says so. Another section's own figure
 * closes the line, scoped by its name: on a complete project both read
 * "100.0%", and a figure a reader cannot scope is a figure they cannot use. On
 * `.text` the second figure is left out when it would repeat the first; it
 * differs only when the cells do not span the declared section, since the
 * headline divides by the declared size and the section row by the bytes its
 * cells cover. */
function Summary({
  stats,
  error,
  loading,
  section,
  sectionPct,
}: {
  stats: StatsPayload | null;
  error: string | null;
  loading: boolean;
  section: string | null;
  sectionPct: number | null;
}): ComponentChildren {
  if (stats === null) {
    if (error !== null) {
      return <p className="m-0 text-data text-text-muted">Coverage summary unavailable: {error}</p>;
    }
    return loading ? (
      <p className="m-0 text-data text-text-muted">Loading the coverage summary…</p>
    ) : null;
  }
  const { summary } = stats;
  return (
    <p className="m-0 flex flex-wrap items-baseline gap-x-3 gap-y-1">
      <b className="text-figure font-semibold leading-title tracking-figure tabular-nums text-text">
        {percentLabel(summary.coveragePercent)}
      </b>
      <span className="text-data text-text-muted">
        of <span className="font-mono text-text">{TEXT_SECTION}</span> covered,{" "}
        {count(summary.matchedFunctions)} of {count(summary.totalFunctions)}{" "}
        {plural(summary.matchedFunctions, { one: "function", other: "functions" })}{" "}
        matched
        {section === null ||
        sectionPct === null ||
        (section === TEXT_SECTION && percentLabel(sectionPct) === percentLabel(summary.coveragePercent)) ? null : (
          <>
            {" · "}
            <span className="font-mono text-text">{section}</span> {percentLabel(sectionPct)}
          </>
        )}
      </span>
    </p>
  );
}
