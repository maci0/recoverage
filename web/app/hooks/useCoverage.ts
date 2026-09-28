import { useCallback, useEffect, useRef, useState } from "preact/compat";

import { fetchData, type DataPayload, type SearchEntry, type Section } from "@/api";

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
  loading: boolean;
  error: string | null;
  /** A section whose cells could not be fetched, with the reason. */
  cellError: { section: string; detail: string } | null;
  /** Fetch the cells of a section that has none yet. */
  ensureCells: (name: string) => void;
  /** Refetch after a regen or a `db-updated` event. */
  reload: () => void;
};

export function useCoverage(target: string, section: string): Coverage {
  const [sections, setSections] = useState<Record<string, Section>>({});
  const [searchIndex, setSearchIndex] = useState<Record<string, SearchEntry>>({});
  const [paths, setPaths] = useState<{ sourceRoot?: string; originalDll?: string }>({});
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [cellError, setCellError] = useState<{ section: string; detail: string } | null>(null);
  const inflight = useRef(new Map<string, Promise<void>>());
  const [reloadToken, setReloadToken] = useState(0);

  const merge = useCallback((payload: DataPayload, wanted: string): void => {
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
    setSearchIndex(payload.search_index ?? {});
    setPaths(payload.paths ?? {});
    if (payload.sections[wanted]?.cells !== undefined) {
      setCellError((current) => (current?.section === wanted ? null : current));
    }
  }, []);

  const load = useCallback(
    async (name: string, signal: AbortSignal): Promise<void> => {
      try {
        merge(await fetchData(target, name, signal), name);
        if (!signal.aborted) {
          setLoadError(null);
        }
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
    void load(section, control.signal);
    return () => control.abort();
  }, [load, reloadToken, section, target]);

  const ensureCells = useCallback(
    (name: string): void => {
      if (sections[name]?.cells !== undefined || target === "") {
        return;
      }
      if (inflight.current.has(name)) {
        return;
      }
      const control = new AbortController();
      const fetchCells = async (): Promise<void> => {
        try {
          merge(await fetchData(target, name, control.signal), name);
          // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- the failure is reported on the tab itself, with a retry, and kept per section
        } catch (error: unknown) {
          setCellError({
            section: name,
            detail: error instanceof Error ? error.message : String(error),
          });
        } finally {
          inflight.current.delete(name);
        }
      };
      inflight.current.set(name, fetchCells());
    },
    [merge, sections, target],
  );

  const reload = useCallback(() => {
    // Every section's cells are refetched, not just the visible one: a rebuild
    // re-spans cells, so the loaded siblings are as stale as the map on screen.
    inflight.current.clear();
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
    loading,
    error: loadError,
    cellError,
    ensureCells,
    reload,
  };
}
