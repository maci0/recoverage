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
  foldCellName,
  foldForSearch,
  hex,
  isolate,
  plural,
  sameOriginPath,
  toVa,
  trimSearch,
} from "@/lib/format";
import { readStored, writeStored } from "@/lib/storage";
import { FILTER_KEY, MARK_CLASS, STATE_LABEL, SWATCH_CLASS } from "@/states";
import { Icon } from "@/system/icons/Icon";

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

/** The id the list's row N carries, which is what the search box's
 * `aria-activedescendant` names. One derivation, so the field and the list
 * cannot spell the same row two different ways (an `aria-activedescendant`
 * pointing at nothing names nothing). */
const searchResultOptionId = (index: number): string => `search-result-${index}`;

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

type Theme = "dark" | "light";

/** The theme the reader pinned with the toggle, or null to follow the OS. */
function pinnedTheme(): Theme | null {
  const saved = readStored(THEME_KEY);
  return saved === "light" || saved === "dark" ? saved : null;
}

function systemTheme(): Theme {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches === true ? "dark" : "light";
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
    return ". Check the spelling, or search by address.";
  }
  if (sectionMatches === 0) {
    return `, none in ${isolate(section ?? "this section")}. Press Enter to jump to the first.`;
  }
  if (!resultsOpen) {
    return ". Press Enter to jump, or click the box to list them.";
  }
  return ". Press Enter for the first, or pick one below.";
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
  // The row the arrow keys walked to inside the open list, or null while the
  // reader has not moved through it. It is announced with
  // `aria-activedescendant` rather than by moving focus: focus stays in the
  // field, so a reader can keep typing while walking the list (ARIA 1.2
  // combobox), and a list that took focus would strand the term mid-word.
  const [activeResult, setActiveResult] = useState<number | null>(null);
  const [pinned, setPinned] = useState<Theme | null>(pinnedTheme);
  const [system, setSystem] = useState<Theme>(systemTheme);
  const theme = pinned ?? system;
  const otherTheme: Theme = theme === "light" ? "dark" : "light";
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
    const parts = ["recoverage"];
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

  // The tokens resolve through `color-scheme`, which `data-theme` on <html>
  // pins; with no attribute they follow the OS. The shell sets the same
  // attribute before the first paint, from the same stored value.
  useEffect(() => {
    if (pinned === null) {
      delete document.documentElement.dataset.theme;
    } else {
      document.documentElement.dataset.theme = pinned;
    }
  }, [pinned]);

  // While the OS decides, the map still has to repaint when it changes its
  // mind: the canvas resolves its fills once per theme.
  useEffect(() => {
    const scheme = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (scheme === undefined) {
      return;
    }
    const control = new AbortController();
    scheme.addEventListener("change", () => setSystem(scheme.matches ? "dark" : "light"), {
      signal: control.signal,
    });
    return () => control.abort();
  }, []);

  useEffect(() => {
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
  }, []);

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
  //
  // `token` is the one parameter that is NOT state, and it is dropped from the
  // address bar here. The share link is the only way a browser hands this page
  // a credential, and `server.set_auth_cookie` (called by `/` before this
  // renders) has already turned it into an HttpOnly cookie by the time this
  // effect runs, which is what every later fetch, EventSource and relative
  // link authenticates with. Leaving the value in `window.location` therefore
  // bought nothing and cost a credential that sits in the history entry, in
  // the address bar over a screenshot or a screen share, and in the bookmark a
  // reader saves the page under, for as long as the tab is open. The
  // `Referrer-Policy: no-referrer` the server sends keeps it off the wire; this
  // keeps it off the screen.
  useEffect(() => {
    if (!targetReady) {
      return;
    }
    const url = new URL(window.location.href);
    url.searchParams.delete("token");
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
    // Members are FOLDED (`foldCellName`), the form the search that filled
    // `matchedNames` compared in, so a cell's raw `functions[0]` — matched
    // through `foldCellName` at every call site — agrees with the set. A
    // digit VA folds to itself, so the bare-VA arm needs no special case.
    const matched = new Set<string>();
    for (const name of matchedNames) {
      matched.add(foldCellName(name));
      const va = coverage.searchIndex[name]?.va;
      // Both spellings are digits: a function entry stores the number, a
      // global stores `hex(va)`. `foldCellName` is NFC plus lower plus the
      // full-fold table, and none of those move a digit, so `String(va)` is
      // the fold. Running the fold per hit measured 0.82 ms against 0.65 ms
      // over 11k hits (bun, 21 runs), on the keystroke.
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

  // A deferred jump is a bare address, so it only means anything for the target
  // it was issued against. The retry below keys on `coverage.sections`, which a
  // target switch replaces, so a marker left behind by the previous target
  // resolved against the new one's rows and selected a block at that address
  // in a binary the reader never asked about. Declared first so the clear wins.
  useEffect(() => {
    deferredJump.current = null;
  }, [target]);

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
  // Folded once per section, not once per keystroke. `sectionMatches` used to
  // call `foldCellName` on every cell inside the memo the query rebuilds:
  // 0.49 ms p50 over 40k cells (bun, 21 runs), on the keystroke that also
  // repaints the map. The names do not change until the cells do.
  const foldedCellNames = useMemo(() => {
    const cells = active?.cells;
    if (cells === undefined) {
      return null;
    }
    return cells.map((cell) => foldCellName(cell.functions?.[0]));
  }, [active]);

  const sectionMatches = useMemo(() => {
    if (matchedFns === null || foldedCellNames === null) {
      return null;
    }
    return foldedCellNames.reduce((n, name) => n + (matchedFns.has(name) ? 1 : 0), 0);
  }, [foldedCellNames, matchedFns]);

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
      return `Searching for "${query}": loading the function index…`;
    }
    return `${count(matchedNames.size)} ${plural(matchedNames.size, {
      one: "match",
      other: "matches",
    })} for "${query}"${searchHint(matchedNames.size, sectionMatches, active?.name ?? null, resultsOpen)}`;
  }, [active?.name, matchedNames, query, resultsOpen, sectionMatches]);

  /** The match count the field shows at its end, or null with no term typed or
   * before the index has arrived (the status line says it is loading). */
  const matchCount =
    query === "" || matchedNames === null
      ? null
      : `${count(matchedNames.size)} ${plural(matchedNames.size, { one: "match", other: "matches" })}`;

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

  // The row `aria-activedescendant` and Enter both name, clamped to the list
  // that is on screen. The arrows and the reset sites keep `activeResult` in
  // step with the rows they walk, but the list is not derived from the term
  // alone: a live reload (`reload()` retires the index and refetches it) or a
  // section switch replaces `coverage.searchIndex` and `coverage.sections`
  // while the term and the walked row stand, so a rebuild that dropped a
  // match left the index pointing past the end of a shorter list. The id it
  // named was then carried by no row, which is the one thing
  // `searchResultOptionId` documents it cannot do, and Enter fell through the
  // `chosen === undefined` arm to the map's own first match — the exact row the
  // reader did not aim at. Clamping here rather than resetting makes the
  // invariant hold for every future path that rebuilds the list, not only for
  // the ones that also remember to clear the row.
  const activeRow =
    activeResult !== null && activeResult < searchResults.length ? activeResult : null;

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
      setActiveResult(null);
      return;
    }
    // The list's own navigation, which the combobox role promises and which a
    // pointer-only list did not: without it a keyboard user who has not
    // pressed Enter has no way to reach a match beyond the first
    // (WCAG 2.1.1). Down opens the list on an unopened one, so the arrow key
    // is the whole affordance a reader needs to discover.
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      const rows = searchResults.length;
      if (rows === 0) {
        return;
      }
      event.preventDefault();
      setResultsOpen(true);
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActiveResult((current) => {
        if (current === null) {
          return event.key === "ArrowDown" ? 0 : rows - 1;
        }
        // Wraps, like the section tab row: the list is a ring, not a queue.
        return (current + step + rows) % rows;
      });
      return;
    }
    if (event.key !== "Enter") {
      return;
    }
    // A row the arrow keys walked to is the one Enter picks. A listbox's
    // contract is that the active option is the selection, so Enter has to
    // take it; falling through to the map's own first match would answer a
    // keypress the reader aimed at one row with a different one.
    if (resultsOpen && activeRow !== null) {
      const chosen = searchResults[activeRow];
      if (chosen !== undefined) {
        event.preventDefault();
        setResultsOpen(false);
        setActiveResult(null);
        jumpToAddress(chosen.va);
        return;
      }
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
    let local = -1;
    if (foldedCellNames !== null && matchedFns !== null) {
      for (let i = 0; i < foldedCellNames.length; i += 1) {
        const name = foldedCellNames[i];
        if (name !== undefined && matchedFns.has(name)) {
          local = i;
          break;
        }
      }
    }
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
    setActiveResult(null);
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

  // Clicking the block already open closes it, which is the one way back from
  // the detail panel to the whole map. Without it the only ways out were a
  // section or target switch: a reader who mis-clicked a block, or finished
  // reading one, had nothing to press to dismiss the panel and no clue that
  // switching tabs was the intended escape. Every other panel here leaves on a
  // click outside or on Escape, so this was the one dead end in the flow.
  const onGridSelect = useCallback((index: number): void => {
    setSelectedIndex((current) => (current === index ? null : index));
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
  const sectionEmpty = !coverage.loading && target !== "" && names.length === 0;
  /** The map area is a loading line whose height is not the map's. Whatever
   * sits under it (the legend, and the panel once the layout stacks below
   * `lg`) would jump down when the map lands, which Lighthouse scores as
   * layout shift, so it stays out of the flow until then. */
  const mapPending =
    !noTargets &&
    !sectionEmpty &&
    (active === null
      ? (loadError ?? coverage.error) === null
      : active.cells === undefined && coverage.cellError?.section !== active.name);
  /** The summary above the map is still a loading line. It grows by a figure
   * and a wrapped sentence when `/stats` answers, and its filter pills gain
   * their counts and wrap onto another row, so a loading line under it would
   * move twice. While both are loading the summary's own line is the one
   * loading message on screen. */
  const holdMapArea =
    mapPending && target !== "" && coverage.stats === null && coverage.statsError === null;

  return (
    <>
      <a
        href="#main-content"
        className="skip-link sr-only focus:not-sr-only focus:absolute focus:start-2 focus:top-2 focus:z-30 focus:rounded-control focus:border focus:border-control-line focus:bg-surface focus:px-3 focus:py-2 focus:text-data"
      >
        Skip to main content
      </a>
      <header
        ref={topbarRef}
        // Pinned only where it is one row tall. A narrow viewport wraps the
        // tabs, the search and the actions into a block that can take half
        // the screen, and a sticky block that size scrolls the map out from
        // under the reader who is trying to read it.
        className="topbar z-20 flex flex-wrap items-center gap-x-5 gap-y-3 border-b border-border bg-surface px-4 py-3 lg:sticky lg:top-0 lg:px-6"
      >
        {/* Below `sm` the tabs take a row of their own from the first frame:
            beside the wordmark, a target with several sections wrapped them
            onto a new row when the list arrived and pushed the page down. */}
        <div className="flex min-w-0 flex-col items-start gap-x-5 gap-y-3 sm:flex-row sm:flex-wrap sm:items-center">
          <div className="flex items-center gap-2">
            <Mark />
            <h1 className="title m-0 text-intro font-bold leading-title tracking-logo">recoverage</h1>
          </div>
          {/* A tablist, not a row of toggle buttons: the section tabs select
              what the ONE panel below them shows, and the pattern pairs the
              active tab's state with the `tabpanel` the map is. */}
          <div
            ref={sectionTabRef}
            // min-h-8.5 is one row of tabs (a 28px tab, the padding and the
            // border), held before the section list arrives so the topbar does
            // not grow under the reader when it does (CLS).
            className="tabs flex min-h-8.5 flex-wrap gap-0.5 rounded-control border border-border bg-surface-2 p-0.5"
            role="tablist"
            aria-label="Sections"
            aria-orientation="horizontal"
          >
            {names.map((name) => {
              const current = name === section;
              return (
                <Button
                  key={name}
                  variant="ghost"
                  size="sm"
                  className="tab-btn rounded-chip font-mono data-active:border-border-strong data-active:bg-surface"
                  active={current}
                  role="tab"
                  id={`section-tab-${name}`}
                  aria-selected={current}
                  // Roving tabindex: one stop for the whole row, and the arrow
                  // keys move within it, which is what a tablist promises
                  // (WCAG 2.1.1).
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
        <div className="flex min-w-0 grow flex-wrap items-start justify-end gap-x-3 gap-y-3">
          {/* The search column may shrink and the rows wrap: the body clips
              horizontal overflow, so a row that cannot break at 320 CSS px
              (WCAG 1.4.10) would lose its last control with no scroll
              position that brings it back. */}
          <div className="search relative flex min-w-0 grow flex-col gap-1 sm:max-w-80" ref={searchBoxRef}>
            <div className="search-row flex flex-wrap items-center gap-1.5">
              {/* A real <label>: the hint inside the field is gone once a reader types
                  (WCAG 3.3.2), and the name is this element's own text so the
                  two cannot drift apart (WCAG 2.5.3). Visually hidden so the
                  topbar keeps its one-row shape. */}
              <label className="sr-only" for="search-input">
                Search functions by name or address
              </label>
              <div className="relative min-w-0 grow">
                <span className="pointer-events-none absolute start-2.5 top-2 text-text-faint">
                  <Icon name="search" />
                </span>
                <input
                  id="search-input"
                  type="search"
                  className="h-8 w-full min-w-0 rounded-control border border-control-line bg-surface ps-8 pe-2 text-data text-text hover:border-control-line-hover data-filled:pe-32"
                  // With a term typed, `data-filled` widens the end padding so
                  // the text stays clear of the count and Clear drawn there.
                  data-filled={query === "" ? undefined : ""}
                  placeholder="Function name or address"
                  value={query}
                  // The editable-combobox pattern (ARIA 1.2): the field owns the
                  // list, the arrows walk it, and the row the reader is on is
                  // named by `aria-activedescendant` rather than by focus. A
                  // plain `type="search"` announced nothing about the list at
                  // all, so a screen-reader user had no way to know matches
                  // existed or how many (WCAG 4.1.2).
                  role="combobox"
                  aria-expanded={resultsOpen && searchResults.length > 0}
                  // Only while the list is in the DOM. The `SearchResults`
                  // element renders only when `resultsOpen`, so naming it
                  // unconditionally left `aria-controls` pointing at an id
                  // that did not exist for as long as the field was collapsed
                  // — a dangling reference a screen reader either ignored or
                  // announced as an empty popup. `aria-expanded="false"` is
                  // what conveys the closed state (ARIA 1.2 combobox pattern;
                  // WCAG 4.1.2).
                  aria-controls={
                    resultsOpen && searchResults.length > 0 ? "search-results-list" : undefined
                  }
                  aria-autocomplete="list"
                  aria-activedescendant={
                    resultsOpen && activeRow !== null
                      ? searchResultOptionId(activeRow)
                      : undefined
                  }
                  onChange={(event) => {
                    setQuery(event.currentTarget.value);
                    setResultsOpen(true);
                    // A new term is a new list; the row the arrows were on
                    // belonged to the old one and would name a row that is no
                    // longer there.
                    setActiveResult(null);
                  }}
                  onFocus={() => setResultsOpen(true)}
                  // The list is an overlay on the map, so focus leaving the box
                  // for anything outside it puts the map back. The rows are
                  // not tab stops, so this fires on leaving the widget itself.
                  onBlur={(event) => {
                    const { relatedTarget: next } = event;
                    const box = searchBoxRef.current;
                    if (next instanceof Node && box !== null && box.contains(next)) {
                      return;
                    }
                    setResultsOpen(false);
                    setActiveResult(null);
                  }}
                  onKeyDown={onSearchKeyDown}
                />
                {/* The count and Clear sit inside the field, so typing costs
                    the topbar no row: beside it, Clear wrapped onto a line of
                    its own at the field's full width. The count is hidden from
                    assistive technology; the live region above says it, with
                    the guidance this abbreviates. */}
                {matchCount === null ? null : (
                  <span
                    className="pointer-events-none absolute inset-y-0 end-9 flex items-center font-mono text-micro tabular-nums text-text-muted"
                    aria-hidden="true"
                  >
                    {matchCount}
                  </span>
                )}
                {query !== "" && (
                  <Button
                    className="absolute inset-y-0 end-0"
                    variant="ghost"
                    size="icon"
                    aria-label="Clear search"
                    title="Clear search"
                    onClick={() => {
                      setQuery("");
                      setResultsOpen(false);
                      setActiveResult(null);
                    }}
                  >
                    <Icon name="x" />
                  </Button>
                )}
              </div>
            </div>
            {/* The live region stays in the tree while the query is empty: a
                status element inserted together with its text is announced by
                some screen readers and dropped by others (WCAG 4.1.3). It is
                read, not seen: a visible line here grew the sticky topbar on
                the first keystroke and pushed the map down. Sighted readers
                get the same sentence at the head of the match list, and the
                count inside the field while the list is closed. */}
            <div className="sr-only" role="status" aria-live="polite">
              {searchStatus}
            </div>
            {resultsOpen && searchStatus !== null && (
              <SearchResults
                status={searchStatus}
                results={searchResults}
                total={matchedNames?.size ?? 0}
                section={active?.name ?? null}
                activeIndex={activeRow}
                listId="search-results-list"
                optionId={searchResultOptionId}
                onPick={(result) => {
                  setResultsOpen(false);
                  setActiveResult(null);
                  jumpToAddress(result.va);
                }}
              />
            )}
          </div>
          <div className="actions flex flex-wrap items-center gap-1.5">
            {/* Rendered while the target list loads, disabled, and a row of its
                own below `sm`: sized to its longest option, the arrival of
                the list moved the buttons after it onto or off a second line
                on a phone and the page with them (CLS). A list that loaded
                empty removes it. */}
            {!noTargets && (
              <select
                className="h-8 w-full min-w-0 max-w-full rounded-control border border-control-line bg-surface px-2 font-mono text-micro text-text hover:border-control-line-hover sm:w-auto"
                aria-label="Target binary"
                value={target}
                disabled={targets.length === 0}
                onChange={(event) => onTarget(event.currentTarget.value)}
              >
                {targets.length === 0 ? (
                  <option value="">Loading targets…</option>
                ) : (
                  targets.map((entry) => (
                    <option key={entry.id} value={entry.id} dir="auto">
                      {entry.name}
                    </option>
                  ))
                )}
              </select>
            )}
            <Button
              // "Regenerate" leads the accessible name (WCAG 2.5.3), and it is
              // the honest name for what the click runs: rebrew's catalog
              // analysis, for minutes at a time.
              aria-label={busy ? MSG.REGEN_IN_PROGRESS : "Regenerate coverage data"}
              title={busy ? MSG.REGEN_IN_PROGRESS : "Re-run the coverage analysis. Takes minutes."}
              // `aria-disabled`, not `disabled`: a disabled button leaves the
              // tab order and drops the reader who just pressed it to <body>
              // for the minutes the regen runs (WCAG 2.4.3).
              // `useLiveReload.reload` refuses the click instead.
              aria-disabled={busy ? "true" : undefined}
              onClick={reload}
            >
              {busy ? MSG.REGEN_IN_PROGRESS : "Regenerate"}
            </Button>
            <a
              className={cn(controlVariants({ variant: "ghost" }), "no-underline")}
              href={potatoHref}
              title="Potato Mode: this view as plain server-rendered HTML, with no JavaScript"
            >
              Potato Mode
            </a>
            <Button
              variant="ghost"
              aria-label={`Switch to the ${otherTheme} theme`}
              onClick={() => {
                setPinned(otherTheme);
                writeStored(THEME_KEY, otherTheme);
              }}
            >
              {otherTheme === "dark" ? "Dark theme" : "Light theme"}
            </Button>
          </div>
        </div>
      </header>

      {/* `tabIndex={-1}` below is the skip link's target: `<main>` is not
          focusable by default, so activating the link moved the reading
          position without moving the focus ring, and the next Tab landed on a
          control somewhere inside the page with nothing focused to announce as
          its start (WCAG 2.4.1). A programmatic destination only, so it is not
          a tab stop. */}
      <main
        className="flex flex-col gap-6 px-4 py-6 lg:flex-row lg:items-start lg:px-6"
        id="main-content"
        tabIndex={-1}
      >
        {/* The tabpanel the section tabs control: the map and everything that
            describes it. The tab row is outside it so the panel is the one
            thing a tab switch replaces. */}
        <div
          className="min-w-0 flex-1"
          id="section-panel"
          role="tabpanel"
          // The tab that selected this panel names it (WCAG 4.1.2). A target
          // whose document names no section renders no tab to point at, and
          // an `aria-labelledby` naming a missing id names nothing.
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
          {/* Always mounted, like the search status: a finished regen or a
              jump that found nothing has to be announced (WCAG 4.1.3). Empty,
              it is visually nothing. */}
          <p
            className={
              notice === null
                ? "sr-only"
                : "mb-3 rounded-control border border-border bg-live-soft px-3 py-2 text-data text-text"
            }
            role="status"
            aria-live="polite"
          >
            {notice ?? ""}
          </p>
          {(loadError ?? coverage.error) !== null && (
            <p
              className="mb-3 flex flex-wrap items-center gap-3 rounded-control border border-border bg-fail-soft px-3 py-2 text-data text-st-fail"
              role="alert"
            >
              <span className="min-w-0">{loadError ?? coverage.error}</span>
              {/* Re-runs the read that failed: the target list when that is
                  what was refused, the current section's data otherwise. */}
              <Button size="sm" onClick={retryFailedLoad}>
                Retry
              </Button>
            </p>
          )}
          {/* The map area's own live region, mounted for the life of the shell.
              A section switch, a lazy cell load and a failed cell load each
              replace the map, and this region exists before the write
              (WCAG 4.1.3). */}
          <p className="sr-only" role="status" aria-live="polite">
            {mapStatus}
          </p>
          {!holdMapArea && (
            <MapArea
              noTargets={noTargets}
              target={target}
              coverage={coverage}
              active={active}
              sectionEmpty={sectionEmpty}
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
          )}
          <ul
            className={cn(
              "legend m-0 mt-3 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-micro text-text-muted",
              mapPending && "hidden",
            )}
          >
            {STATE_LABEL.map((label, slot) => (
              <li key={label} className="flex items-center gap-1.5">
                <span
                  aria-hidden="true"
                  className={cn("swatch size-2.5 rounded-cell", SWATCH_CLASS[slot], MARK_CLASS[slot])}
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
          hiddenWhenStacked={mapPending}
        />
      </main>
    </>
  );
}

/** The relumea mark (brand guide, "The mark"): a lowercase r in coverage-map
 * cells, one of them lit. Ink cells follow the text colour. */
function Mark(): ComponentChildren {
  const cells: Array<[number, number, string]> = [
    [1.5, 1.5, "fill-current"],
    [9, 1.5, "fill-current"],
    [16.5, 1.5, "fill-accent"],
    [1.5, 9, "fill-current"],
    [9, 9, "fill-border-strong"],
    [16.5, 9, "fill-border-strong"],
    [1.5, 16.5, "fill-current"],
    [9, 16.5, "fill-border-strong"],
    [16.5, 16.5, "fill-border-strong"],
  ];
  return (
    <svg className="shrink-0 text-text" viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
      {cells.map(([x, y, fill]) => (
        <rect key={`${x}-${y}`} className={fill} x={x} y={y} width="6" height="6" rx="1.5" />
      ))}
    </svg>
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
      <div className="flex flex-col items-center gap-2 rounded-card border border-border bg-surface px-6 py-12 text-center text-data text-text-muted">
        <p className="m-0 text-intro font-semibold text-text">No coverage database</p>
        <p className="m-0 max-w-prose">
          Run <code className="font-mono text-micro text-text">rebrew coverage build</code> to write{" "}
          <code className="font-mono text-micro text-text">db/coverage-*.toml</code>, then press Regenerate.
        </p>
      </div>
    );
  }
  // A target the project config declares but no build has written yet lands
  // here rather than in the case above: it is in the dropdown, so the reader
  // chose it deliberately, and "no sections" on its own names neither the
  // missing document nor the command that writes it.
  if (sectionEmpty) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-card border border-border bg-surface px-6 py-12 text-center text-data text-text-muted">
        <p className="m-0 text-intro font-semibold text-text">
          No coverage data for <span className="font-mono">{target}</span>
        </p>
        <p className="m-0 max-w-prose">
          Run <code className="font-mono text-micro text-text">rebrew coverage build</code> to write{" "}
          <code className="font-mono text-micro text-text">db/coverage-{target}.toml</code>, then press Regenerate.
        </p>
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
        <div className="flex flex-col items-start gap-3 rounded-card border border-border bg-fail-soft p-4 text-data text-st-fail">
          <p className="m-0">Coverage data unavailable: {loadError}</p>
          <Button size="sm" onClick={onRetry}>
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
        className="flex flex-col items-start gap-3 rounded-card border border-border bg-fail-soft p-4 text-data text-st-fail"
        aria-busy="true"
      >
        <p className="m-0">
          Could not load the {isolate(active.name)} map: {coverage.cellError.detail}
        </p>
        <Button size="sm" onClick={() => coverage.ensureCells(active.name)}>
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
  return `${isolate(active.name)} map, ${count(active.cells.length)} ${plural(
    active.cells.length,
    { one: "block", other: "blocks" },
  )}.${filtered}`;
}

function pending(text: string): ComponentChildren {
  // The live region is the map area's own, which stays mounted across a
  // section switch: a `role="status"` element inserted together with the text
  // it carries is announced by some screen readers and dropped by others, and
  // this is the one place a section change lands with nothing else to say
  // (WCAG 4.1.3). `aria-busy` marks the map as replacing itself instead.
  return (
    <div
      className="rounded-card border border-border bg-surface px-6 py-12 text-center text-data text-text-muted"
      aria-busy="true"
    >
      {text}
    </div>
  );
}
