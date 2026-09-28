import { useCallback, useEffect, useMemo, useRef, useState } from "preact/compat";

import type { ComponentChildren, TargetedKeyboardEvent } from "preact";

import { fetchTargets, type Section, type TargetInfo } from "@/api";
import { CoverageMap } from "@/components/CoverageMap";
import { CoveragePanel } from "@/components/CoveragePanel";
import { StatsStrip } from "@/components/StatsStrip";
import { Button, controlVariants } from "@/components/ui/button";
import { FILTER_KEY, LEGEND, PALETTE_VARS, STATE_FILTERS } from "@/grid/pack";
import { useCoverage, type Coverage } from "@/hooks/useCoverage";
import { useLiveReload } from "@/hooks/useLiveReload";
import { originalDllPath, useOriginalBinary } from "@/hooks/useOriginalBinary";
import { cellIndexForVa, useSelection } from "@/hooks/useSelection";
import { cn } from "@/lib/cn";
import { MSG, foldForSearch, hex, sameOriginPath, toVa } from "@/lib/format";
import { readStored, writeStored } from "@/lib/storage";

/** The dashboard shell: the document, the topbar's controls, and the map.
 *
 * The query string is the dashboard's state — `target`, `section`, `q`,
 * `filter` — so a link to a search or a section is shareable and a reload lands
 * where it left. The panel beside the map is the selected block's detail. */

const TARGET_KEY = "recoverage_target";
const THEME_KEY = "recoverage_theme";
const NAV_NOTICE_MS = 4000;

/** The filters the toolbar offers: "all" first, then one per state the grid
 * can paint. The state half is `STATE_FILTERS`, which the stats strip draws the
 * same words from. */
const FILTERS: Array<{ key: string; label: string; aria: string; title: string }> = [
  { key: "all", label: "All", aria: "Filter all", title: "Show all statuses" },
  ...STATE_FILTERS,
];

/** Sections in PE load order (ascending VA), which puts `.text` first instead
 * of leaving the section that carries the work at the end of an alphabetical
 * row. Sections without a VA sort last, keeping their relative order. */
function sectionNames(sections: Record<string, { va: number | null }>): Array<string> {
  return Object.keys(sections).toSorted(
    (left, right) => (sections[left]?.va ?? 1e18) - (sections[right]?.va ?? 1e18),
  );
}

function initialTheme(): "dark" | "light" {
  const saved = readStored(THEME_KEY);
  if (saved === "light" || saved === "dark") {
    return saved;
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches === true ? "light" : "dark";
}

/** The Potato Mode link for the current view. Potato reads `search` for the
 * query and a comma-joined `filter`, so both are translated rather than
 * appended verbatim, and an empty value is left out. */
function potatoUrl(state: {
  target: string;
  section: string;
  search: string;
  filters: ReadonlySet<string>;
}): string {
  const params = new URLSearchParams();
  for (const [key, value] of [
    ["target", state.target],
    ["section", state.section],
    ["search", state.search],
  ] as const) {
    if (value !== "") {
      params.set(key, value);
    }
  }
  if (state.filters.size > 0) {
    params.set("filter", [...state.filters].toSorted().join(","));
  }
  return `/potato?${params.toString()}`;
}

export function App() {
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const [targets, setTargets] = useState<Array<TargetInfo>>([]);
  // A `?target=` in the URL is the page's own state, so it seeds the selection
  // before the target list arrives: `/api/targets/<t>/data` then starts in
  // parallel with `/api/targets` instead of one round trip behind it, which is
  // the path every reload and every shared link takes. It is still validated
  // against the list below, and a name the server no longer serves falls back
  // the same way a stale remembered one does.
  const [urlTarget] = useState<string>(() => params.get("target") ?? "");
  const [target, setTarget] = useState<string>(urlTarget);
  const [targetReady, setTargetReady] = useState(false);
  const [section, setSection] = useState<string>(() => params.get("section") ?? ".text");
  const [query, setQuery] = useState<string>(() => params.get("q") ?? "");
  const [filters, setFilters] = useState<ReadonlySet<string>>(() => {
    // A `?filter=` seeds the same closed set the toolbar toggles, so a name no
    // pill offers is dropped rather than kept: an unknown key matches no packed
    // state, so keeping it dims every painted block and lights no pill. Potato
    // Mode draws the same line (`potato._parse_filters`), so a link copied
    // between the two surfaces lands in the same state on both.
    const known = new Set(FILTER_KEY.filter((key) => key !== ""));
    return new Set(params.getAll("filter").filter((key) => known.has(key)));
  });
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">(initialTheme);
  const [notice, setNotice] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const gridFocus = useRef<((index: number) => void) | null>(null);
  const noticeTimer = useRef<number | null>(null);
  const topbarRef = useRef<HTMLElement | null>(null);
  // The address a jump is waiting on: a sibling section's cells are fetched
  // before the map can say which block covers it.
  const deferredJump = useRef<number | null>(null);

  // A notice that is a result rather than a state: a jump that found no
  // block, a regen that finished. It expires on its own. A notice that IS the
  // state (a regen in flight, a failure) is set directly and stays until
  // something replaces it.
  const flash = useCallback((text: string) => {
    setNotice(text);
    if (noticeTimer.current !== null) {
      window.clearTimeout(noticeTimer.current);
    }
    noticeTimer.current = window.setTimeout(() => setNotice(null), NAV_NOTICE_MS);
  }, []);

  const coverage = useCoverage(target, section);
  // The fallback carries the target id verbatim: rebrew names the tree
  // `src/<target>` with the target's own spelling, and a lowercased request
  // only resolves on a case-insensitive filesystem (macOS, Windows).
  const sourceRoot = sameOriginPath(
    coverage.paths.sourceRoot ?? "",
    `/src/${encodeURIComponent(target)}`,
  );
  // The original binary is the largest thing this page will ever download —
  // a built PE of several megabytes — and only the byte pane and the
  // inspector read it, through useSelection, which runs for a SELECTION. It
  // used to be gated on the target resolving, so every visit paid for it
  // before anything was selected and most visits never select anything. The
  // pane shows MSG.LOADING while the fetch is in flight, so the one visit
  // that does need the bytes waits a moment longer and no other notice moves.
  const dll = useOriginalBinary(
    originalDllPath(coverage.paths.originalDll, target),
    selectedIndex !== null,
    coverage.reloadToken,
  );
  const panes = useSelection({
    target,
    section,
    sections: coverage.sections,
    sourceRoot,
    cellIndex: selectedIndex,
    dll,
  });
  const { reload, busy } = useLiveReload({
    enabled: target !== "",
    onDbUpdated: coverage.reload,
    onNotice: setNotice,
    onDone: flash,
  });

  useEffect(() => {
    // The tab is a second surface for the same selection the topbar shows, and
    // a flat "ReCoverage" left it reading as a marketing page in every state.
    const parts = ["ReCoverage"];
    if (target !== "") {
      parts.push(target);
    }
    if (section !== "") {
      parts.push(section);
    }
    if (query !== "") {
      parts.push(`"${query}"`);
    }
    document.title = parts.join(" · ");
  }, [target, section, query]);

  useEffect(() => {
    document.body.classList.toggle("light-mode", theme === "light");
    const topbar = topbarRef.current;
    if (topbar === null) {
      return;
    }
    // The topbar is sticky, so the panel header parks below its measured height
    // instead of underneath it.
    const measure = (): void => {
      document.documentElement.style.setProperty(
        "--topbar-h",
        `${topbar.getBoundingClientRect().height}px`,
      );
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(topbar);
    return () => observer.disconnect();
  }, [theme]);

  useEffect(() => {
    const control = new AbortController();
    void (async () => {
      try {
        setTargets(await fetchTargets(control.signal));
        setTargetReady(true);
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- the failure is surfaced in the header's error line, and the dashboard still renders its empty state
      } catch (error: unknown) {
        if (!control.signal.aborted) {
          setLoadError(error instanceof Error ? error.message : String(error));
          setTargetReady(true);
        }
      }
    })();
    return () => control.abort();
  }, []);

  // Pick a target once the list is known: a URL target that the server still
  // serves stays, then the remembered one, then the first the server offers.
  useEffect(() => {
    if (!targetReady || targets.length === 0) {
      return;
    }
    const served = targets.some((entry) => entry.id === target);
    if (target !== "" && served) {
      return;
    }
    setTarget(
      [urlTarget, readStored(TARGET_KEY)].find(
        (candidate) => candidate !== null && targets.some((entry) => entry.id === candidate),
      ) ??
        targets[0]?.id ??
        "",
    );
  }, [target, targetReady, targets, urlTarget]);

  // The URL carries the state a reload or a shared link has to restore.
  useEffect(() => {
    if (!targetReady) {
      return;
    }
    const url = new URL(window.location.href);
    if (target === "") {
      url.searchParams.delete("target");
    } else {
      url.searchParams.set("target", target);
    }
    url.searchParams.set("section", section);
    if (query === "") {
      url.searchParams.delete("q");
    } else {
      url.searchParams.set("q", query);
    }
    url.searchParams.delete("filter");
    for (const key of filters) {
      url.searchParams.append("filter", key);
    }
    window.history.replaceState({}, "", url);
  }, [filters, query, section, target, targetReady]);

  const { sections } = coverage;
  const names = useMemo(() => sectionNames(sections), [sections]);
  const active = sections[section] ?? sections[names[0] ?? ""] ?? null;

  // A section's cells arrive lazily, so switching tabs asks for them.
  useEffect(() => {
    if (section !== "" && sections[section] !== undefined) {
      coverage.ensureCells(section);
    }
  }, [coverage, section, sections]);

  // A `section` the target does not have (a stale link) falls back to the first.
  useEffect(() => {
    if (section !== "" && sections[section] === undefined && names.length > 0) {
      setSection(names[0] ?? "");
    }
  }, [names, section, sections]);

  // Names first, then the VA spellings: `.text` cells store the function's name
  // in `cell.functions`, while a search hit is keyed by name and carries the VA
  // — the dimming test compares against both, so both go in the set. Both sides
  // fold through `foldForSearch`, the SPA's half of `server.fold_text`, so a
  // term and a symbol agree on `ß`/`ss` and on an NFD spelling alike.
  const matchedNames = useMemo(() => {
    const needle = foldForSearch(query.trim());
    if (needle === "") {
      return null;
    }
    const matched = new Set<string>();
    for (const [name, entry] of Object.entries(coverage.searchIndex)) {
      // The four columns `/api/.../functions?search=` folds the same term over:
      // name, symbol, the decimal VA and the hex spelling. `entry.va` crosses
      // as a HEX STRING, so `hex()` on it hands back "0X0X10001000" and a term
      // naming an address matches nothing here while the API lists the row.
      const va = toVa(entry.va);
      const haystack = `${name} ${entry.symbol ?? ""} ${entry.name ?? ""} ${va} ${hex(va, 8)}`;
      if (foldForSearch(haystack).includes(needle)) {
        matched.add(name);
      }
    }
    return matched;
  }, [coverage.searchIndex, query]);

  const matchedFns = useMemo(() => {
    if (matchedNames === null) {
      return null;
    }
    const matched = new Set<string | number>(matchedNames);
    for (const name of matchedNames) {
      const va = coverage.searchIndex[name]?.va;
      if (va !== undefined) {
        matched.add(String(va));
      }
    }
    return matched;
  }, [coverage.searchIndex, matchedNames]);

  // The address a parent-function name resolves to, or null when the index
  // does not carry it. `parent_function` is a NAME (see `Cell`), so the jump
  // the detail panel's Parent link offers is a name lookup, not the address it
  // used to be handed.
  const parentVaFor = useCallback(
    (name: string): number | null => {
      const entry = coverage.searchIndex[name];
      return entry === undefined ? null : toVa(entry.va);
    },
    [coverage.searchIndex],
  );

  const jumpToAddress = useCallback(
    (address: number) => {
      // Every section is a candidate: an asm operand, a parent-function link or
      // a search hit can point into a sibling, and the jump switches the tab
      // to it. The section that HOLDS the address is decided from its row,
      // which every /data payload carries, so a sibling whose cells are not
      // loaded yet is a request, not a dead end.
      let unloaded: string | null = null;
      for (const [name, row] of Object.entries(coverage.sections)) {
        const base = row.va ?? 0;
        if (address < base || address >= base + (row.size ?? 0)) {
          continue;
        }
        if (row.cells === undefined) {
          unloaded = name;
          continue;
        }
        const index = cellIndexForVa(row, address);
        if (index < 0) {
          continue;
        }
        setSection(name);
        setSelectedIndex(index);
        gridFocus.current?.(index);
        deferredJump.current = null;
        return;
      }
      if (unloaded !== null && deferredJump.current !== address) {
        // One deferred attempt per address: the cells are fetched and the
        // effect below retries when they land. A fetch that never lands (the
        // tab's own retry) falls through to the notice on the next attempt
        // rather than deferring forever.
        deferredJump.current = address;
        setSection(unloaded);
        coverage.ensureCells(unloaded);
        return;
      }
      deferredJump.current = null;
      flash(MSG.JUMP_NO_BLOCK(hex(address, 8)));
    },
    [coverage, flash],
  );

  // A jump deferred for cells that were not loaded: retried when the section
  // the address is in has them. The marker stays until then, so the retry
  // cannot defer itself a second time, and nothing is reported while the
  // section is still on its way (its own error line and Retry own that wait).
  useEffect(() => {
    const address = deferredJump.current;
    if (address === null) {
      return;
    }
    const loaded = Object.values(coverage.sections).some(
      (row) =>
        row.cells !== undefined &&
        address >= (row.va ?? 0) &&
        address < (row.va ?? 0) + (row.size ?? 0),
    );
    if (!loaded) {
      return;
    }
    deferredJump.current = null;
    jumpToAddress(address);
  }, [coverage.sections, jumpToAddress]);

  const onSearchKeyDown = (event: TargetedKeyboardEvent<HTMLInputElement>): void => {
    if (event.key !== "Enter" || matchedNames === null) {
      return;
    }
    const [first] = matchedNames;
    if (first === undefined) {
      flash("Search matched nothing in this target.");
      return;
    }
    const cell = active?.cells?.findIndex((entry) => entry.functions?.[0] === first) ?? -1;
    if (cell < 0) {
      const entry = coverage.searchIndex[first];
      if (entry === undefined) {
        flash("Search matched nothing in this target.");
        return;
      }
      jumpToAddress(toVa(entry.va));
      return;
    }
    setSelectedIndex(cell);
    gridFocus.current?.(cell);
  };

  const toggleFilter = (key: string): void => {
    setFilters((current) => {
      if (key === "all") {
        return new Set<string>();
      }
      const toggled = new Set(current);
      if (toggled.has(key)) {
        toggled.delete(key);
      } else {
        toggled.add(key);
      }
      return toggled;
    });
  };

  const onTarget = (next: string): void => {
    writeStored(TARGET_KEY, next);
    // A query belongs to the binary it was typed for: keeping it would dim the
    // whole new map against a name that does not exist there.
    setQuery("");
    setSelectedIndex(null);
    setTarget(next);
  };

  const noTargets = targetReady && targets.length === 0;

  // Potato Mode reads `search` and a comma-joined `filter`, so the link carries
  // the reader's position across instead of dropping them on the default view.
  const potatoHref = useMemo(
    () => potatoUrl({ target, section, search: query, filters }),
    [filters, query, section, target],
  );

  return (
    <>
      <a
        href="#main-content"
        className="skip-link sr-only focus:not-sr-only focus:absolute focus:start-2 focus:top-2 focus:z-30 focus:rounded-hair focus:border focus:border-line focus:bg-panel focus:px-2 focus:py-1"
      >
        Skip to main content
      </a>
      <header
        ref={topbarRef}
        className="topbar sticky top-0 z-20 flex flex-wrap items-center gap-3 border-b border-line bg-topbar px-4 py-2"
      >
        <div className="topbar-left flex flex-wrap items-center gap-3">
          <div className="title-container flex items-center gap-2">
            <div
              className="logo-r inline-flex items-center justify-center rounded-hair border-2 border-accent bg-accent/5 px-2 py-0.5 font-mono text-mark font-extrabold text-accent shadow-glow"
              aria-hidden="true"
            >
              R
            </div>
            <h1 className="title font-mono text-wordmark font-bold tracking-wide">ReCoverage</h1>
          </div>
          <nav className="tabs flex flex-wrap gap-1" aria-label="Sections">
            {names.map((name) => (
              <Button
                key={name}
                className="tab-btn"
                active={name === section}
                // The active tab is painted, not announced: without the state
                // the screen reader reads eight identical buttons and nothing
                // says which section the map below is showing.
                aria-pressed={name === section}
                onClick={() => {
                  setSection(name);
                  setSelectedIndex(null);
                }}
              >
                {name}
              </Button>
            ))}
          </nav>
        </div>
        <div className="topbar-right ms-auto flex flex-wrap items-center gap-3">
          <div className="search flex flex-col gap-1">
            <div className="search-row flex items-center gap-2">
              <input
                type="search"
                className="input-el rounded-hair border border-line bg-btn px-2 py-1 font-mono text-label text-text"
                placeholder="Search function name or VA..."
                aria-label="Search functions"
                value={query}
                onChange={(event) => setQuery(event.currentTarget.value)}
                onKeyDown={onSearchKeyDown}
              />
              {query !== "" && (
                <Button
                  className="search-clear"
                  aria-label="Clear search"
                  title="Clear search"
                  onClick={() => setQuery("")}
                >
                  Clear
                </Button>
              )}
            </div>
            {/* The live region stays in the tree while the query is empty: a
                status element INSERTED together with its text is announced by
                some screen readers and dropped by others, so the region every
                keystroke writes into has to exist before the write (WCAG 4.1.3). */}
            <div
              className={
                query !== "" && matchedNames !== null
                  ? "search-status font-mono text-micro text-muted"
                  : "sr-only"
              }
              role="status"
              aria-live="polite"
            >
              {query !== "" && matchedNames !== null && (
                <>
                Searching: "{query}" ({matchedNames.size}{" "}
                {matchedNames.size === 1 ? "match" : "matches"})
                {matchedNames.size === 0
                  ? " - no matches. Check the spelling, or search by VA."
                  : " - press Enter to jump to the first one."}
                </>
              )}
            </div>
          </div>
          <div className="filters flex flex-wrap gap-1">
            {FILTERS.map((entry) => {
              const on = entry.key === "all" ? filters.size === 0 : filters.has(entry.key);
              return (
                <Button
                  key={entry.key}
                  className={`filter-btn filter-${entry.key}`}
                  aria-label={entry.aria}
                  aria-pressed={on}
                  title={entry.title}
                  active={on}
                  onClick={() => toggleFilter(entry.key)}
                >
                  {entry.label}
                </Button>
              );
            })}
          </div>
          <div className="actions flex items-center gap-2">
            {targets.length > 0 && (
              <select
                className="input-el target-select rounded-hair border border-line bg-btn px-2 py-1 font-mono text-label text-text"
                aria-label="Select target binary"
                value={target}
                onChange={(event) => onTarget(event.currentTarget.value)}
              >
                {targets.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {entry.name}
                  </option>
                ))}
              </select>
            )}
            <Button
              className="icon-btn reload-btn"
              // "Reload" is the word the button shows, so it leads the name too:
              // a voice-control user saying "click Reload" has to find it
              // (WCAG 2.5.3).
              aria-label={busy ? MSG.REGEN_IN_PROGRESS : "Reload coverage data"}
              title={busy ? MSG.REGEN_IN_PROGRESS : "Regenerate coverage data"}
              disabled={busy}
              onClick={reload}
            >
              {busy ? MSG.REGEN_IN_PROGRESS : "Reload"}
            </Button>
            <a
              className={cn(controlVariants(), "potato-link")}
              href={potatoHref}
              aria-label="HTML: open this view in Potato Mode"
              title="Open this view in Potato Mode (server-rendered HTML)"
            >
              HTML
            </a>
            <Button
              className="icon-btn"
              aria-label={theme === "light" ? "Switch to Dark Mode" : "Switch to Light Mode"}
              title={theme === "light" ? "Switch to Dark Mode" : "Switch to Light Mode"}
              onClick={() => {
                setTheme(theme === "light" ? "dark" : "light");
                writeStored(THEME_KEY, theme === "light" ? "dark" : "light");
              }}
            >
              {theme === "light" ? "Dark" : "Light"}
            </Button>
          </div>
        </div>
      </header>

      <main className="layout mx-auto flex max-w-[1600px] flex-col gap-4 px-4 py-4 lg:flex-row" id="main-content">
        <div className="grid-area min-w-0 flex-1">
          <StatsStrip
            stats={coverage.stats}
            error={coverage.statsError}
            section={active?.name ?? null}
            filters={filters}
            onToggleFilter={toggleFilter}
          />
          {/* Always mounted, for the same reason as the search status above: a
              regen that finished or a jump that found nothing has to be
              announced, and a region inserted with its text is not reliably
              announced (WCAG 4.1.3). Empty, it is visually nothing. */}
          <p
            className={
              notice === null
                ? "sr-only"
                : "nav-notice mb-2 rounded-hair border border-line bg-panel px-3 py-2 font-mono text-label"
            }
            role="status"
            aria-live="polite"
          >
            {notice ?? ""}
          </p>
          {(loadError ?? coverage.error) !== null && (
            <p
              className="grid-error mb-2 rounded-hair border border-line bg-panel px-3 py-2 font-mono text-label text-badge-stub-text"
              role="alert"
            >
              {loadError ?? coverage.error}
            </p>
          )}
          <MapArea
            noTargets={noTargets}
            coverage={coverage}
            active={active}
            sectionEmpty={!coverage.loading && target !== "" && names.length === 0}
            filters={filters}
            matchedFns={matchedFns}
            selectedIndex={selectedIndex}
            activeFn={panes.fnKey}
            theme={theme}
            onSelect={setSelectedIndex}
            onGridReady={(focus) => {
              gridFocus.current = focus;
            }}
          />
          <ul className="legend mt-3 flex flex-wrap gap-3 font-mono text-micro text-muted">
            {LEGEND.map(([slot, label]) => (
              <li key={label} className="flex items-center gap-1.5">
                <span
                  className={`swatch swatch-${label.replaceAll(" ", "-")}`}
                  style={{ background: `var(${PALETTE_VARS[slot] ?? "--none"})` }}
                />
                {label}
              </li>
            ))}
          </ul>
        </div>
        <CoveragePanel
          section={active}
          cellIndex={selectedIndex}
          panes={panes}
          sourceRoot={sourceRoot}
          parentVaFor={parentVaFor}
          onJumpToAddress={jumpToAddress}
        />
      </main>
    </>
  );
}

/** What the map area shows: the lattice, a loading line, a failure with a
 * retry, or the empty state. A component rather than a chain of ternaries in
 * the shell's own JSX, which is where the reader has to look for the data flow. */
function MapArea({
  noTargets,
  coverage,
  active,
  sectionEmpty,
  filters,
  matchedFns,
  selectedIndex,
  activeFn,
  theme,
  onSelect,
  onGridReady,
}: {
  noTargets: boolean;
  coverage: Coverage;
  active: Section | null;
  sectionEmpty: boolean;
  filters: ReadonlySet<string>;
  matchedFns: ReadonlySet<string | number> | null;
  selectedIndex: number | null;
  activeFn: string | number | null;
  theme: "dark" | "light";
  onSelect: (index: number) => void;
  onGridReady: (focus: (index: number) => void) => void;
}): ComponentChildren {
  if (noTargets) {
    return (
      <div className="empty-state rounded-control border border-line bg-panel p-6 text-center font-mono text-label text-muted">
        <p className="font-bold text-text">No coverage database</p>
        <p>Run rebrew build-db to create db/coverage-*.toml, then reload this page.</p>
      </div>
    );
  }
  if (active === null) {
    return pending(sectionEmpty ? "No sections in this target." : "Loading coverage data…");
  }
  if (active.cells === undefined) {
    if (coverage.cellError?.section !== active.name) {
      return pending(`Loading ${active.name}…`);
    }
    return (
      <div
        className="grid-error rounded-control border border-line bg-panel p-4 font-mono text-label"
        role="status"
      >
        <p>
          Could not load the {active.name} map: {coverage.cellError.detail}
        </p>
        <Button className="mt-2" onClick={() => coverage.ensureCells(active.name)}>
          Retry
        </Button>
      </div>
    );
  }
  return (
    <CoverageMap
      key={active.name}
      section={active}
      filters={filters}
      matchedFns={matchedFns}
      selectedIndex={selectedIndex}
      activeFn={activeFn}
      theme={theme}
      onSelect={onSelect}
      onGridReady={onGridReady}
    />
  );
}

function pending(text: string): ComponentChildren {
  return (
    <div
      className="loading-overlay rounded-control border border-line bg-panel p-6 text-center font-mono text-label text-muted"
      role="status"
      aria-live="polite"
    >
      {text}
    </div>
  );
}
