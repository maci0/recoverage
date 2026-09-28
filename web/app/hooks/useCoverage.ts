import { useCallback, useEffect, useRef, useState } from "preact/compat";

import { fetchData, fetchStats, type DataPayload, type SearchEntry, type Section, type StatsPayload } from "@/api";

/** The dashboard's coverage data.
 *
 * Every payload carries all section rows but only the requested one's cells —
 * an absent `cells` key is the lazy-load signal, not an empty grid — so the hook
 * keeps one merged section map and fetches a sibling's cells when its tab asks
 * for them. A failed fetch is remembered per section, because a tab that
 * silently paints nothing is unusable. */

export type Coverage = {
  sections: Record<string, Section>;
  searchIndex: Record<string, SearchEntry>;
  paths: { sourceRoot?: string; originalDll?: string };
  /** The target's headline numbers and per-section rows, or null while they
   * load and after a rebuild asks for them again. */
  stats: StatsPayload | null;
  statsError: string | null;
  loading: boolean;
  error: string | null;
  /** A section whose cells could not be fetched, with the reason. */
  cellError: { section: string; detail: string } | null;
  /** Fetch the cells of a section that has none yet. */
  ensureCells: (name: string) => void;
  /** Refetch after a regen or a `db-updated` event. */
  reload: () => void;
  /** Counts the reloads, so a consumer memoizing its own build-derived data
   * can key it on the build it fetched against. A rebuild that rewrites the
   * target without changing the target id or the paths leaves both of those
   * unchanged, so the token is the only thing that moves. */
  reloadToken: number;
};

export function useCoverage(target: string, section: string): Coverage {
  const [sections, setSections] = useState<Record<string, Section>>({});
  const [searchIndex, setSearchIndex] = useState<Record<string, SearchEntry>>({});
  const [paths, setPaths] = useState<{ sourceRoot?: string; originalDll?: string }>({});
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [cellError, setCellError] = useState<{ section: string; detail: string } | null>(null);
  const [stats, setStats] = useState<StatsPayload | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const inflight = useRef(new Map<string, AbortController>());
  const [reloadToken, setReloadToken] = useState(0);
  // The search index is target-wide, so it is asked for once per (target,
  // build) and every later section request passes `index=0`. A ref, not state:
  // it decides what the NEXT request sends, so a re-render from landing the
  // index must not restart the load that fetched it.
  const reloadTokenRef = useRef(reloadToken);
  reloadTokenRef.current = reloadToken;
  const indexed = useRef<{ target: string; token: number } | null>(null);
  const indexIsCurrent = useCallback(
    (name: string): boolean =>
      indexed.current !== null &&
      indexed.current.target === name &&
      indexed.current.token === reloadTokenRef.current,
    [],
  );

  // `token` is the build the request was ISSUED under, read before the await.
  // The memo below is only published when it is still the current one, which is
  // what stops a response for a superseded build from being filed under the
  // build that replaced it: `reload()` bumps the token to retire the index, and
  // reading the token after the await would hand the retired slot back the
  // index of the build it retired. The same watermark re-check every server-side
  // coverage memo publishes through.
  const merge = useCallback((payload: DataPayload, wanted: string, token: number): void => {
    setSections((current) => {
      const merged = { ...current };
      for (const [name, row] of Object.entries(payload.sections)) {
        const { [name]: prior } = current;
        // A sibling row arrives without cells; keep the cells already loaded
        // rather than replacing a painted section with an empty one.
        merged[name] =
          row.cells === undefined && prior?.cells !== undefined
            ? { ...row, cells: prior.cells }
            : row;
      }
      return merged;
    });
    // An absent key means the request already holds the index, not that the
    // target has none, so a section switch keeps the one it has.
    if (payload.search_index !== undefined && token === reloadTokenRef.current) {
      setSearchIndex(payload.search_index);
      indexed.current = { target, token };
    }
    setPaths(payload.paths ?? {});
    if (payload.sections[wanted]?.cells !== undefined) {
      setCellError((current) => (current?.section === wanted ? null : current));
    }
  }, [indexed, reloadTokenRef, target]);

  const load = useCallback(
    async (name: string, signal: AbortSignal): Promise<void> => {
      const token = reloadTokenRef.current;
      try {
        merge(await fetchData(target, name, signal, !indexIsCurrent(target)), name, token);
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- the failure is surfaced as the header's error line, and the map keeps its last good frame
      } catch (error: unknown) {
        if (!signal.aborted) {
          setLoadError(error instanceof Error ? error.message : String(error));
        }
      } finally {
        if (!signal.aborted) {
          setLoading(false);
        }
      }
    },
    [merge, target],
  );

  useEffect(() => {
    if (target === "") {
      return;
    }
    const control = new AbortController();
    setLoading(true);
    // A superseded load's error goes with it. The effect re-runs on a target
    // switch, a section switch and a rebuild, and each of those starts a
    // request for a different document: a stale target the server no longer
    // serves answers 404 here, and without the clear the red line for THAT
    // target stayed up over the real target's map while it loaded.
    setLoadError(null);
    void load(section, control.signal);
    return () => control.abort();
  }, [load, reloadToken, section, target]);

  // The stats are target-wide, so this asks once per (target, build) and not
  // per section: the section cells come from /data, the numbers from here.
  useEffect(() => {
    if (target === "") {
      setStats(null);
      return;
    }
    const control = new AbortController();
    void (async () => {
      try {
        const payload = await fetchStats(target, control.signal);
        if (!control.signal.aborted) {
          setStats(payload);
          setStatsError(null);
        }
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- the failure is reported on the stats strip itself; the map above and below it is unaffected, so it does not take the page's error line
      } catch (error: unknown) {
        if (!control.signal.aborted) {
          setStats(null);
          setStatsError(error instanceof Error ? error.message : String(error));
        }
      }
    })();
    return () => control.abort();
  }, [reloadToken, target]);

  const ensureCells = useCallback(
    (name: string): void => {
      if (sections[name]?.cells !== undefined || target === "") {
        return;
      }
      if (inflight.current.has(name)) {
        return;
      }
      const control = new AbortController();
      const token = reloadTokenRef.current;
      const fetchCells = async (): Promise<void> => {
        try {
          merge(
            await fetchData(target, name, control.signal, !indexIsCurrent(target)),
            name,
            token,
          );
          // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- the failure is reported on the tab itself, with a retry, and kept per section
        } catch (error: unknown) {
          if (control.signal.aborted) {
            return;
          }
          setCellError({
            section: name,
            detail: error instanceof Error ? error.message : String(error),
          });
        } finally {
          // Only this request's own claim: a reload aborts and clears the map,
          // and the next fetch for this section installs a new one that this
          // finally must not delete.
          if (inflight.current.get(name) === control) {
            inflight.current.delete(name);
          }
        }
      };
      inflight.current.set(name, control);
      void fetchCells();
    },
    [indexIsCurrent, merge, sections, target],
  );

  // Every cell fetch the tab strip started is aborted when the hook goes away.
  // `reload` is the only other path that releases them, and it is not reached
  // on a target switch or on unmount: without this, each abandoned section
  // kept a multi-megabyte /data response downloading to a `merge` nothing will
  // read, one per section per switch, and the last reader to switch targets
  // walked away with all of them still open.
  useEffect(() => {
    const claims = inflight.current;
    return () => {
      for (const control of claims.values()) {
        control.abort();
      }
      claims.clear();
    };
  }, []);

  const reload = useCallback(() => {
    // Every section's cells are refetched, not just the visible one: a rebuild
    // re-spans cells, so the loaded siblings are as stale as the map on screen.
    // The token bump retires the search index with them, so the next request
    // asks for a fresh one rather than passing `index=0` against a stale index.
    // Aborting first is what keeps a cell fetch already in flight from landing
    // after the bump: it would repaint a superseded build's cells and, carrying
    // its search index, fill the slot `reload` just retired with the build it
    // replaced. The token check in `merge` refuses the index; only the abort
    // keeps the cells out.
    for (const control of inflight.current.values()) {
      control.abort();
    }
    inflight.current.clear();
    // The numbers a rebuild is about to replace are dropped with the cells, so
    // the strip never states a coverage figure for a map it is no longer over.
    setStats(null);
    setSections((current) => {
      const next: Record<string, Section> = {};
      for (const [name, row] of Object.entries(current)) {
        const { cells: _dropped, ...rest } = row;
        next[name] = rest;
      }
      return next;
    });
    setReloadToken((token) => token + 1);
  }, []);

  return {
    sections,
    searchIndex,
    paths,
    stats,
    statsError,
    loading,
    error: loadError,
    cellError,
    ensureCells,
    reload,
    reloadToken,
  };
}
