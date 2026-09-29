import { useCallback, useEffect, useMemo, useRef, useState } from "preact/compat";

import type { ComponentChildren, TargetedKeyboardEvent } from "preact";

import { fetchTargets, type Section, type TargetInfo } from "@/api";
import { CoverageMap, type CoverageMapProps } from "@/components/CoverageMap";
import { CoveragePanel } from "@/components/CoveragePanel";
import { SearchResults, searchResultRows } from "@/components/SearchResults";
import { StatsStrip } from "@/components/StatsStrip";
import { Button, controlVariants } from "@/components/ui/button";
import { useCoverage, type Coverage } from "@/hooks/useCoverage";
import { useLiveReload } from "@/hooks/useLiveReload";
import { originalDllPath, useOriginalBinary } from "@/hooks/useOriginalBinary";
import { cellIndexForVa, useSelection } from "@/hooks/useSelection";
import { cn } from "@/lib/cn";
import {
  MSG,
  count,
  errorMessage,
  foldForSearch,
  hex,
  isolate,
  sameOriginPath,
  toVa,
  trimSearch,
} from "@/lib/format";
import { readStored, writeStored } from "@/lib/storage";
import { FILTER_KEY, PALETTE_VARS, STATE_FILTERS, STATE_LABEL } from "@/states";

/** The dashboard shell: the document, the topbar's controls, and the map.
 *
 * The query string is the dashboard's state — `target`, `section`, `q`,
 * `filter` — so a link to a search or a section is shareable and a reload lands
 * where it left. The panel beside the map is the selected block's detail. */

const TARGET_KEY = "recoverage_target";
const THEME_KEY = "recoverage_theme";
const NAV_NOTICE_MS = 4000;
/** How many matches the result list shows before it says how many it left out.
 * A target-wide term can match thousands of names, and the list is there to be
 * scanned, not to be a second index: past the cap it narrows the term. */
const SEARCH_RESULT_LIMIT = 20;

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

/** One navigation key of the section tab row, mapped to the index it moves
 * to. A key the row does not own is absent, which is how the handler tells a
 * navigation key from a key it should leave alone. */
type SectionTabStep = (at: number, last: number) => number;

const SECTION_TAB_STEP = new Map<string, SectionTabStep>([
  ["ArrowRight", (at, last) => (at + 1) % (last + 1)],
  ["ArrowLeft", (at, last) => (at + last) % (last + 1)],
  ["Home", () => 0],
  ["End", (_at, last) => last],
]);

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

/** The guidance the search status adds after its count: no hits at all, none of
 * them in the section on screen, or what Enter will select. The list is named
 * only while it is on screen, since the reader closes it and the line keeps
 * counting. */
function searchHint(
  matches: number,
  sectionMatches: number | null,
  section: string | null,
  resultsOpen: boolean,
): string {
  if (matches === 0) {
    return " - no matches. Check the spelling, or search by VA.";
  }
  if (sectionMatches === 0) {
    return ` - none of them in ${isolate(section ?? "this section")}; press Enter to jump to the first one.`;
  }
  if (!resultsOpen) {
    return " - press Enter to jump, or click the box to list the matches.";
  }
  return " - press Enter, or pick a name from the list below.";
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
  //
  // The REMEMBERED target seeds it for the same reason, and it is already in
  // hand: `localStorage` is synchronous, while the validation effect below
  // needed the network to say what to pick, so every reload without a `?target=`
  // — the plain `recoverage serve` visit, which is most of them — sat out one
  // full round trip of `/api/targets` before `/data` and `/stats` were even
  // requested. The validation is the one that runs either way, and it was
  // already written to replace a remembered id the server no longer serves,
  // so a stale entry costs the same 404 it costs when the list arrives and
  // corrects itself; `useCoverage` clears the error that one raises, so the
  // switch to the real target starts on a clean line rather than under the
  // previous target's refusal.
  const [urlTarget] = useState<string>(() => params.get("target") ?? "");
  const [target, setTarget] = useState<string>(
    () => params.get("target") ?? readStored(TARGET_KEY) ?? "",
  );
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
  // Whether the match list under the search box is showing. It is the reader's
  // to close: it is an overlay over the map, so a pointerdown anywhere else, a
  // pick from it, or Escape puts the map back. It used to stay until the query
  // itself changed, which left twenty rows floating over the lattice for the
  // rest of the visit after one search.
  const [resultsOpen, setResultsOpen] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">(initialTheme);
  const [notice, setNotice] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const gridFocus = useRef<((index: number) => void) | null>(null);
  const searchBoxRef = useRef<HTMLDivElement | null>(null);
  const noticeTimer = useRef<number | null>(null);
  const topbarRef = useRef<HTMLElement | null>(null);
  // The address a jump is waiting on: a sibling section's cells are fetched
  // before the map can say which block covers it.
  const deferredJump = useRef<number | null>(null);
  const sectionTabRef = useRef<HTMLDivElement | null>(null);

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

  // The pending expiry is cancelled on unmount. It is the one timer here with
  // no other stop path: `flash` clears its predecessor, but the last one
  // outlives the shell, and the `setNotice` it closes over keeps the whole
  // component state alive until it fires.
  useEffect(
    () => () => {
      if (noticeTimer.current !== null) {
        window.clearTimeout(noticeTimer.current);
        noticeTimer.current = null;
      }
    },
    [],
  );

  const coverage = useCoverage(target, section);
  // The fallback carries the target id verbatim: rebrew names the tree
  // `src/<target>` with the target's own spelling, and a lowercased request
  // only resolves on a case-insensitive filesystem (macOS, Windows).
  const sourceRoot = sameOriginPath(coverage.paths.sourceRoot ?? "", `/src/${target}`);
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
    // The measured height, so whatever parks below the topbar reads the height
    // it is actually wrapped to at this viewport rather than a guess.
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

  // The target list's own controller, held so the error line's Retry can start
  // a fresh request. The first load is driven by the effect below, which
  // aborts its own controller on unmount; a retry outlives that effect, so a
  // retry left to an unmounted shell would write state into a dead component.
  const targetsControl = useRef<AbortController | null>(null);

  const loadTargets = useCallback((signal: AbortSignal): void => {
    void (async () => {
      try {
        setTargets(await fetchTargets(signal));
        setLoadError(null);
        setTargetReady(true);
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- the failure is surfaced in the header's error line, which carries the Retry, and the dashboard still renders its empty state
      } catch (error: unknown) {
        if (!signal.aborted) {
          setLoadError(errorMessage(error));
          setTargetReady(true);
        }
      }
    })();
  }, []);

  useEffect(() => {
    const control = new AbortController();
    targetsControl.current = control;
    loadTargets(control.signal);
    return () => {
      control.abort();
      targetsControl.current = null;
    };
  }, [loadTargets]);

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

  /** The arrow keys move the section selection, as a tablist promises: they
   * wrap, skip nothing, and land the focus on the tab they selected, which is
   * the only way a keyboard user learns the tab row moved at all. Home and
   * End are the row's own ends. */
  const onSectionTabKeyDown = (
    event: TargetedKeyboardEvent<HTMLButtonElement>,
    name: string,
  ): void => {
    if (names.length === 0) {
      return;
    }
    const at = names.indexOf(name);
    const last = names.length - 1;
    const next = SECTION_TAB_STEP.get(event.key)?.(at, last);
    if (next === undefined) {
      return;
    }
    const chosen = names[next];
    if (chosen === undefined) {
      return;
    }
    event.preventDefault();
    setSection(chosen);
    setSelectedIndex(null);
    sectionTabRef.current
      ?.querySelector<HTMLButtonElement>(`#${CSS.escape(`section-tab-${chosen}`)}`)
      ?.focus();
  };

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

  // The four columns `/api/.../functions?search=` folds the same term over:
  // name, symbol, the decimal VA and the hex spelling. `entry.va` crosses as a
  // HEX STRING, so `hex()` on it hands back "0X0X10001000" and a term naming an
  // address matches nothing here while the API lists the row.
  //
  // Folded ONCE per index rather than once per keystroke. The haystack depends
  // only on the index, so rebuilding it per query re-ran `normalize` +
  // `toLowerCase` + the full-fold replace over every function in the target on
  // every character typed, on the main thread, inside the render the keystroke
  // triggered. Measured in `bun` over a synthetic index: 8.5 ms per keystroke
  // at 2k entries, 17 ms at 5k, 90 ms at 20k, against 0.1 / 0.3 / 1.4 ms for the
  // substring test alone. A large target is exactly the case where the index is
  // big enough for that to be the long task that drops the frames the search
  // status line is animating into.
  const foldedIndex = useMemo(() => {
    const rows: Array<[string, string]> = [];
    for (const [name, entry] of Object.entries(coverage.searchIndex)) {
      const va = toVa(entry.va);
      rows.push([
        name,
        foldForSearch(`${name} ${entry.symbol ?? ""} ${entry.name ?? ""} ${va} ${hex(va, 8)}`),
      ]);
    }
    return rows;
  }, [coverage.searchIndex]);

  // Names first, then the VA spellings: `.text` cells store the function's name
  // in `cell.functions`, while a search hit is keyed by name and carries the VA
  // — the dimming test compares against both, so both go in the set. Both sides
  // fold through `foldForSearch`, the SPA's half of `server.fold_text`, so a
  // term and a symbol agree on `ß`/`ss` and on an NFD spelling alike. The
  // needle is folded here and the rows above: folding is what decides the match
  // set, and both halves now run it once each rather than once per row.
  const matchedNames = useMemo(() => {
    const needle = foldForSearch(trimSearch(query));
    if (needle === "") {
      return null;
    }
    const matched = new Set<string>();
    for (const [name, haystack] of foldedIndex) {
      if (haystack.includes(needle)) {
        matched.add(name);
      }
    }
    return matched;
  }, [foldedIndex, query]);

  const matchedFns = useMemo(() => {
    if (matchedNames === null) {
      return null;
    }
    // Set<string>, not Set<string | number>: every member is added as a
    // string (a name, or a VA run through String), and every lookup below
    // passes a String of a cell's `functions[0]`, so the number arm was a
    // type wider than any call site could satisfy.
    const matched = new Set<string>(matchedNames);
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

  /** How many of the matched blocks are in the section on screen, or null when
   * the search index is not there or the section's cells are still loading. A
   * search spans the whole target, so the count beside the input says nothing
   * about the map under it: without this, a reader who switches to a section
   * the hits are not in reads a "12 matches" line over a wholly dimmed grid. */
  const sectionMatches = useMemo(() => {
    const cells = active?.cells;
    if (matchedFns === null || cells === undefined) {
      return null;
    }
    return cells.filter((cell) => matchedFns.has(String(cell.functions?.[0] ?? ""))).length;
  }, [active, matchedFns]);

  /** What the search status line says, or null when no query is typed. The
   * index a search reads is target-wide and arrives with the first `/data`, so
   * a reader who types before it lands got a blank line and an Enter that did
   * nothing: the third arm says the index is still coming rather than letting
   * a typed query read as a query that matched nothing. */
  const searchStatus = useMemo(() => {
    if (query === "") {
      return null;
    }
    if (matchedNames === null) {
      return `Searching: "${query}" (loading the function index...)`;
    }
    return `Searching: "${query}" (${count(matchedNames.size)} ${
      matchedNames.size === 1 ? "match" : "matches"
    })${searchHint(matchedNames.size, sectionMatches, active?.name ?? null, resultsOpen)}`;
  }, [active?.name, matchedNames, query, resultsOpen, sectionMatches]);

  /** The section an address falls in, for a search result's own row. Every
   * section is a candidate, so this reads the same ranges `jumpToAddress`
   * does; an address no section claims is listed without one rather than
   * hidden, because a hit the map cannot select is still a hit. */
  const sectionOfAddress = useCallback(
    (va: number): string | null => {
      for (const [name, row] of Object.entries(coverage.sections)) {
        const base = row.va ?? 0;
        if (va >= base && va < base + (row.size ?? 0)) {
          return name;
        }
      }
      return null;
    },
    [coverage.sections],
  );

  const searchResults = useMemo(
    () =>
      matchedNames === null
        ? []
        : searchResultRows(
            matchedNames,
            coverage.searchIndex,
            sectionOfAddress,
            SEARCH_RESULT_LIMIT,
          ),
    [coverage.searchIndex, matchedNames, sectionOfAddress],
  );

  const onSearchKeyDown = (event: TargetedKeyboardEvent<HTMLInputElement>): void => {
    if (event.key === "Escape") {
      // Escape is the way out of a search box everywhere else, and here it had
      // to be hunted for the Clear button: the typed term, the result list and
      // the dimming on the map all clear together.
      if (query !== "") {
        event.preventDefault();
        setQuery("");
      }
      setResultsOpen(false);
      return;
    }
    if (event.key !== "Enter") {
      return;
    }
    if (matchedNames === null) {
      // The Enter that has nothing to jump to says so, rather than leaving the
      // keypress with no effect beside a line that has not counted the matches
      // yet.
      if (query.trim() !== "") {
        flash(`The function index is still loading; press Enter again for "${query.trim()}".`);
      }
      return;
    }
    // The section on screen wins over the target-wide set, whose iteration order
    // is whatever order the index was served in: taking its first entry could
    // put the hit in a sibling, and Enter then switched tabs away from the
    // section the reader was reading. Within the section the cell order is the
    // map's own top-to-bottom order.
    const local =
      active?.cells?.findIndex((cell) => matchedFns?.has(String(cell.functions?.[0] ?? ""))) ?? -1;
    if (local >= 0) {
      setSelectedIndex(local);
      gridFocus.current?.(local);
      return;
    }
    // Otherwise the lowest address among the matches, so the jump lands where
    // the reader's eye would start on the lattice.
    const vaOf = (name: string): number => {
      const entry = coverage.searchIndex[name];
      return entry === undefined ? Number.POSITIVE_INFINITY : toVa(entry.va);
    };
    const [first] = [...matchedNames].toSorted((left, right) => vaOf(left) - vaOf(right));
    if (first === undefined) {
      flash("Search matched nothing in this target.");
      return;
    }
    const entry = coverage.searchIndex[first];
    if (entry === undefined) {
      flash(`"${first}" is not at an address this map can select.`);
      return;
    }
    jumpToAddress(toVa(entry.va));
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
    setResultsOpen(false);
    setSelectedIndex(null);
    setTarget(next);
  };

  /** Where a selection on a narrow viewport leaves the reader.
   *
   * The panel is beside the map at `lg` and below it under that, and the map is
   * a lattice as tall as the page, so a tap on a phone selected a block whose
   * detail was thousands of pixels below the fold: the tap looked like it did
   * nothing at all. The panel is brought into view only when it is not already
   * on screen, so the arrow-key walk (which scrolls the map on every move) is
   * untouched, and the scroll is instant under `prefers-reduced-motion`. */
  useEffect(() => {
    if (selectedIndex === null) {
      return;
    }
    const panel = document.querySelector<HTMLElement>("#panel");
    if (panel === null) {
      return;
    }
    const box = panel.getBoundingClientRect();
    if (box.top < window.innerHeight && box.bottom > 0) {
      return;
    }
    const smooth = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches !== true;
    panel.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
  }, [selectedIndex]);

  const onGridSelect = useCallback((index: number): void => {
    setSelectedIndex(index);
  }, []);

  const noTargets = targetReady && targets.length === 0;

  /** Re-run the read the error line is reporting. The target list and the
   * section data are separate requests and a reader cannot tell from the line
   * which one failed, so the line's retry answers for the one the shell
   * actually holds: the list when `/api/targets` was refused, everything
   * otherwise. */
  const retryFailedLoad = useCallback((): void => {
    if (loadError !== null) {
      if (targetsControl.current === null) {
        targetsControl.current = new AbortController();
      }
      loadTargets(targetsControl.current.signal);
      return;
    }
    coverage.reload();
  }, [coverage, loadError, loadTargets]);

  // Potato Mode reads `search` and a comma-joined `filter`, so the link carries
  // the reader's position across instead of dropping them on the default view.
  const potatoHref = useMemo(
    () => potatoUrl({ target, section, search: query, filters }),
    [filters, query, section, target],
  );

  /** What the map area is doing, for the live region above it. A section
   * switch and a lazy cell load both replace the canvas with no focusable
   * element, so without this the only signal that anything happened is the
   * pixels changing. */
  const mapStatus = describeMapArea(noTargets, active, coverage.cellError, filters);

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
        // Pinned only where it is one or two rows tall. A narrow viewport
        // wraps the section tabs, the filter pills and the actions into a
        // block that can take half the screen, and a sticky block that size
        // scrolls the map out from under the reader who is trying to read it.
        className="topbar z-20 flex flex-wrap items-center gap-3 border-b border-line bg-topbar px-4 py-2 lg:sticky lg:top-0"
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
          {/* A tablist, not a row of toggle buttons: the section tabs select
              what the ONE panel below them shows, which is what `tablist` is
              for, and the pattern pairs the active tab's state with the
              `tabpanel` the map is. `aria-pressed` announced the state but not
              the relationship, and read as eight independent toggles. */}
          <div
            ref={sectionTabRef}
            className="tabs flex flex-wrap gap-1"
            role="tablist"
            aria-label="Sections"
            aria-orientation="horizontal"
          >
            {names.map((name) => {
              const current = name === section;
              return (
                <Button
                  key={name}
                  className="tab-btn"
                  active={current}
                  role="tab"
                  id={`section-tab-${name}`}
                  aria-selected={current}
                  // Roving tabindex: one stop for the whole row, and the arrow
                  // keys move within it, which is what a tablist promises.
                  // Without it Tab walks all eight and the arrow keys do
                  // nothing (WCAG 2.1.1).
                  tabIndex={current ? 0 : -1}
                  aria-controls="section-panel"
                  onClick={() => {
                    setSection(name);
                    setSelectedIndex(null);
                  }}
                  onKeyDown={(event) => onSectionTabKeyDown(event, name)}
                >
                  {name}
                </Button>
              );
            })}
          </div>
        </div>
        <div className="topbar-right ms-auto flex flex-wrap items-center gap-3">
          {/* Both rows below WRAP, and the search box may shrink. The topbar
              clips its overflow (`body { overflow-x: clip }`), so a row that
              cannot break is not scrolled off to the side: at the 320 CSS px
              1.4.10 asks for, the actions row (target picker, Regenerate, HTML,
              theme) is about 350px wide as one unbreakable item, and the
              theme toggle at its end was clipped away with nothing to scroll
              it back into reach. `min-w-0` is what lets the search column
              shrink to its box's own minimum rather than to the widest fixed
              width any child declares. */}
          <div className="search relative flex min-w-0 flex-col gap-1" ref={searchBoxRef}>
            <div className="search-row flex flex-wrap items-center gap-2">
              {/* A real <label> element rather than the input's own hint
                  attribute: that hint is the field's only visible name and it
                  disappears the moment a reader types, which is the
                  hint-as-label antipattern (WCAG 3.3.2). It is visually
                  hidden so the topbar keeps its one-row shape, and
                  `aria-label` is dropped so the accessible name is this
                  element's own text and the two cannot drift apart
                  (WCAG 2.5.3). */}
              <label className="sr-only" for="search-input">
                Search functions by name or address
              </label>
              <input
                id="search-input"
                type="search"
                className="input-el w-56 max-w-full rounded-hair border border-line bg-btn px-2 py-1 font-mono text-label text-text sm:w-72"
                placeholder="Search function name or VA..."
                value={query}
                onChange={(event) => {
                  setQuery(event.currentTarget.value);
                  setResultsOpen(true);
                }}
                onFocus={() => setResultsOpen(true)}
                // The list is an overlay on the map, so the reader closes it by
                // going somewhere else: focus leaving the box for anything
                // outside it (a block on the map, a filter pill, another
                // control) puts the map back, and focus moving to a row of the
                // list itself does not, since the pick closes it in turn.
                onBlur={(event) => {
                  const { relatedTarget: next } = event;
                  const box = searchBoxRef.current;
                  if (next instanceof Node && box !== null && box.contains(next)) {
                    return;
                  }
                  setResultsOpen(false);
                }}
                onKeyDown={onSearchKeyDown}
              />
              {query !== "" && (
                <Button
                  className="search-clear"
                  aria-label="Clear search"
                  title="Clear search"
                  onClick={() => {
                    setQuery("");
                    setResultsOpen(false);
                  }}
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
                searchStatus === null ? "sr-only" : "search-status font-mono text-micro text-muted"
              }
              role="status"
              aria-live="polite"
            >
              {searchStatus}
            </div>
            {resultsOpen && (
              <SearchResults
                results={searchResults}
                total={matchedNames?.size ?? 0}
                section={active?.name ?? null}
                onPick={(result) => {
                  setResultsOpen(false);
                  jumpToAddress(result.va);
                }}
              />
            )}
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
          <div className="actions flex flex-wrap items-center gap-2">
            {targets.length > 0 && (
              <select
                className="input-el target-select max-w-full min-w-0 rounded-hair border border-line bg-btn px-2 py-1 font-mono text-label text-text"
                aria-label="Select target binary"
                value={target}
                onChange={(event) => onTarget(event.currentTarget.value)}
              >
                {targets.map((entry) => (
                  <option key={entry.id} value={entry.id} dir="auto">
                    {entry.name}
                  </option>
                ))}
              </select>
            )}
            <Button
              className="icon-btn reload-btn"
              // "Regenerate" leads the accessible name for the same reason
              // (WCAG 2.5.3), and is also the honest name for what the click
              // runs: rebrew's catalog analysis, for minutes at a time, which
              // "Reload" (the browser's own word for a refresh) does not tell a
              // reader to expect.
              aria-label={busy ? MSG.REGEN_IN_PROGRESS : "Regenerate coverage data"}
              title={busy ? MSG.REGEN_IN_PROGRESS : "Re-run the coverage analysis (takes minutes)"}
              // `aria-disabled`, not `disabled`: a disabled button leaves the
              // tab order, so the reader who just activated it is dropped to
              // <body> and has to walk the whole page back to find where they
              // were, for the minutes the regen runs (WCAG 2.4.3).
              // `aria-disabled` keeps the control focusable and announced as
              // unavailable, and `useLiveReload.reload` refuses the click.
              aria-disabled={busy ? "true" : undefined}
              onClick={reload}
            >
              {busy ? MSG.REGEN_IN_PROGRESS : "Regenerate"}
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
        {/* The tabpanel the section tabs control: the map and everything that
            describes it. The tab row is outside it so the panel is the one
            thing a tab switch replaces. */}
        <div
          className="grid-area min-w-0 flex-1"
          id="section-panel"
          role="tabpanel"
          // The tab that selected this panel, so its name is the one on screen
          // (WCAG 4.1.2). A target whose document names no section renders no
          // tab to point at, and an `aria-labelledby` naming a missing id
          // resolves to nothing at all, which is a panel with no name rather
          // than one carrying the label it is asking for.
          aria-labelledby={names.length > 0 ? `section-tab-${active?.name ?? section}` : undefined}
          aria-label={names.length > 0 ? undefined : "Coverage map"}
        >
          <StatsStrip
            stats={coverage.stats}
            error={coverage.statsError}
            loading={coverage.loading}
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
              {/* The next action the line did not offer. A refused read left
                  the reader with a reason and nothing to do about it, and the
                  only way back was reloading the whole page. It re-runs the
                  read that failed: the target list when that is what was
                  refused, the current section's data otherwise. */}
              <Button className="ms-3" onClick={retryFailedLoad}>
                Retry
              </Button>
            </p>
          )}
          {/* The map area's own live region, mounted for the life of the shell
              like the notice above it. A section switch, a lazy cell load and a
              cell load that failed each replace the map, and a `role="status"`
              inserted together with its text is announced by some screen
              readers and dropped by others; this region exists before the
              write (WCAG 4.1.3). Empty and visible, it is a line of text
              naming the section the map is showing, which is the one thing a
              reader who cannot see the tab row cannot work out. */}
          <p className="map-status sr-only" role="status" aria-live="polite">
            {mapStatus}
          </p>
          <MapArea
            noTargets={noTargets}
            target={target}
            coverage={coverage}
            active={active}
            sectionEmpty={!coverage.loading && target !== "" && names.length === 0}
            loadError={loadError ?? coverage.error}
            onRetry={retryFailedLoad}
            filters={filters}
            matchedFns={matchedFns}
            selectedIndex={selectedIndex}
            activeFn={panes.fnKey}
            theme={theme}
            onSelect={onGridSelect}
            onGridReady={(focus) => {
              gridFocus.current = focus;
            }}
          />
          <ul className="legend mt-3 flex flex-wrap gap-3 font-mono text-micro text-muted">
            {STATE_LABEL.map((label, slot) => (
              <li key={label} className="flex items-center gap-1.5">
                <span
                  aria-hidden="true"
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
 * the shell's own JSX, which is where the reader has to look for the data flow.
 *
 * The grid's own props come from `CoverageMapProps` rather than a second copy of
 * the table: this component forwards them unchanged, so a field the map gains
 * reaches it through the type instead of through a spelling kept in step by
 * hand. `section` is narrowed to the row the map area resolved, and
 * `onGridReady` is required here because the shell always supplies it. */
type MapAreaProps = Omit<CoverageMapProps, "section" | "onGridReady"> & {
  noTargets: boolean;
  target: string;
  coverage: Coverage;
  active: Section | null;
  sectionEmpty: boolean;
  /** A read the shell could not recover from, or null. */
  loadError: string | null;
  /** Re-run the read behind `loadError`. */
  onRetry: () => void;
  onGridReady: (focus: (index: number) => void) => void;
};

function MapArea({
  noTargets,
  target,
  coverage,
  active,
  sectionEmpty,
  loadError,
  onRetry,
  filters,
  matchedFns,
  selectedIndex,
  activeFn,
  theme,
  onSelect,
  onGridReady,
}: MapAreaProps): ComponentChildren {
  if (noTargets) {
    return (
      <div className="empty-state rounded-control border border-line bg-panel p-6 text-center font-mono text-label text-muted">
        <p className="font-bold text-text">No coverage database</p>
        <p>Run rebrew build-db to create db/coverage-*.toml, then press Regenerate.</p>
      </div>
    );
  }
  // A target the project config declares but no build has written yet lands
  // here rather than in the case above: it is in the dropdown, so the reader
  // chose it deliberately, and "no sections" on its own names neither the
  // missing document nor the command that writes it.
  if (sectionEmpty) {
    return (
      <div className="empty-state rounded-control border border-line bg-panel p-6 text-center font-mono text-label text-muted">
        <p className="font-bold text-text">No coverage data for {target}</p>
        <p>Run rebrew build-db to write db/coverage-{target}.toml, then press Regenerate.</p>
      </div>
    );
  }
  // A read the shell could not recover from answers with the reason and the
  // retry rather than a loading line that never resolves: with no target
  // resolved, `/data` was never requested, so "Loading coverage data…" sat
  // above an empty map for as long as the reader waited.
  if (active === null) {
    if (loadError !== null) {
      return (
        <div className="grid-error rounded-control border border-line bg-panel p-4 font-mono text-label">
          <p>Coverage data unavailable: {loadError}</p>
          <Button className="mt-2" onClick={onRetry}>
            Retry
          </Button>
        </div>
      );
    }
    return pending("Loading coverage data…");
  }
  if (active.cells === undefined) {
    if (coverage.cellError?.section !== active.name) {
      return pending(`Loading ${isolate(active.name)}…`);
    }
    return (
      <div
        className="grid-error rounded-control border border-line bg-panel p-4 font-mono text-label"
        aria-busy="true"
      >
        <p>
          Could not load the {isolate(active.name)} map: {coverage.cellError.detail}
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

/** What the map area is doing, as one sentence for its live region. The
 * loading arms name the section so a reader following a jump into a sibling
 * hears which one landed; the loaded arm names the block count, which is the
 * figure the map header shows beside it. */
function describeMapArea(
  noTargets: boolean,
  active: Section | null,
  cellError: { section: string; detail: string } | null,
  filters: ReadonlySet<string>,
): string {
  if (noTargets) {
    return "No coverage database.";
  }
  if (active === null) {
    return "Loading coverage data.";
  }
  if (active.cells === undefined) {
    if (cellError?.section === active.name) {
      return `Could not load the ${isolate(active.name)} map.`;
    }
    return `Loading ${isolate(active.name)}.`;
  }
  const filtered =
    filters.size > 0 ? ` Filtered by ${[...filters].toSorted().join(", ")}.` : "";
  return `${isolate(active.name)} map, ${count(active.cells.length)} blocks.${filtered}`;
}

function pending(text: string): ComponentChildren {
  // The live region is the map area's own, which stays mounted across a
  // section switch: a `role="status"` element inserted together with the text
  // it carries is announced by some screen readers and dropped by others, and
  // this is the one place a section change lands with nothing else to say
  // (WCAG 4.1.3). `aria-busy` marks the map as replacing itself instead.
  return (
    <div
      className="loading-overlay rounded-control border border-line bg-panel p-6 text-center font-mono text-label text-muted"
      aria-busy="true"
    >
      {text}
    </div>
  );
}
