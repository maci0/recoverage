(() => {
const { a, aside, button, div, h1, h2, h3, header, input, main, p, pre, section, span, code } = van.tags;

// Every DB-derived value spliced into a URL is percent-encoded first: a
// target id, section name or source path holding a space, '#', '?' or a
// non-ASCII character otherwise truncates the URL, opens a new query, or
// (once the server decodes the path) misses the row.  Path segments are
// encoded one at a time so the '/' separators survive.
const enc = encodeURIComponent;
const encPath = (path) => String(path).split("/").map((seg) => enc(seg)).join("/");

const DATA_URL = (t, secName) => `/api/targets/${enc(t)}/data${secName ? `?section=${enc(secName)}` : ""}`;
const ASM_URL = (t) => `/api/targets/${enc(t)}/asm`;
const FN_URL = (t, va) => `/api/targets/${enc(t)}/functions/${enc(va)}`;

// ============================================================================
// Constants
// ============================================================================
const MSG = {
  LOADING: "Loading…",
  ERROR_PREFIX: "Error: ",
  SELECT_FUNCTION: "(select a function)",
  NO_C_SOURCE: "(no C implementation for this function yet)",
  NO_DOCS: "No documentation comments in source file",
  NO_C_FOR_BLOCK: "(no C implementation)",
  UNDOCUMENTED_BLOCK: "(undocumented block)",
  ASM_PLACEHOLDER: "(no disassembly for this block)",
  DATA_SECTION_NO_ASM: "(Data section - no assembly)",
  BYTES_FAILED: "(byte range falls outside the original binary)",
  BYTES_BSS: "(uninitialized data - no raw bytes)",
  BYTES_LOAD_FAILED: "(original binary not found: expected it at /original/ in the project directory)",
  GLOBAL_VAR: "Global variable",
  REGEN_USING_CACHE: (r) => `Using cached data. Regen available in ${r}s...`,
  REGEN_IN_PROGRESS: "Regenerating…",
  REGEN_UNAVAILABLE: "Regen unavailable",
  NA: "(n/a)",
  FETCH_FAILED: (url) => `(failed to load: ${url})`,
  NO_DECL: "(no declaration found)",
  DETAIL_UNAVAILABLE: "(detail view failed to load — reload the page)",
  HIGHLIGHT_UNAVAILABLE: "(syntax highlighting unavailable — the code below is unhighlighted)",
};

function hex(n, width) {
  return `0x${n.toString(16).toUpperCase().padStart(width, "0")}`;
}

// VAs cross the API boundary as hex strings ("0x10001000" from TEXT columns)
// or plain numbers (from INTEGER columns; /functions/<va> emits va as a
// decimal number).  Parse only strings as hex: routing a number through
// parseInt(x, 16) reads its DECIMAL digits as base-16 and returns an address
// off by orders of magnitude.
function toVa(v) {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the boundary contract is exactly "hex string | number"; decode here so no call site re-parses
  return typeof v === "string" ? Number.parseInt(v, 16) : v;
}

// The hex dump and data inspector live in detail.js, which the shell preloads
// (see index.html) and which app.js requests on the next line, so the fetch
// overlaps the shell's own download instead of starting a round trip later.
// The inlined shell stays inside the initial congestion window.  Until it
// lands, panes that need it show MSG.LOADING.
const detailReady = van.state(false);
const detailFailed = van.state(false);

function loadDetail() {
  window.RC = { van, MetaItem, MSG, hex, enc, encPath, STATE_LABEL, onReady: () => { detailReady.val = true; } };
  const el = document.createElement("script");
  el.src = "/detail.js";
  // Without this the panes it owns would sit on "Loading…" forever.
  el.addEventListener("error", () => { detailFailed.val = true; });
  document.head.append(el);
}

async function fetchTextSafe(url) {
  if (!url) return MSG.NA;
  const res = await fetch(url);
  if (!res.ok) return MSG.FETCH_FAILED(url);
  return await res.text();
}

async function fetchArrayBufferSafe(url) {
  if (!url) return null;
  const res = await fetch(url);
  if (!res.ok) return null;
  return await res.arrayBuffer();
}

// Section name -> grid element id.  Every dot goes so the id is a valid CSS
// selector.  Names that differ only in their dots (`.rsrc.1` vs `.rsrc1`)
// still normalize to the same id.
const gridId = (secName) => `grid-${secName.replaceAll('.', '')}`;

// Legend rows: cell state -> the words used for it in the UI.
const LEGEND = [["none", "undocumented"], ["exact", "exact match"], ["reloc", "reloc match"],
  ["near_match", "near-match"], ["stub", "stub"], ["padding", "padding"],
  ["compile_error", "problem"]];

// Sections in PE load order (ascending VA), which puts .text first instead of
// leaving the section that carries all the work at the end of an alphabetical
// row.  Sections without a VA sort last, keeping their relative order.
const sectionNames = (s) => Object.keys(s).toSorted((x, y) => (s[x].va ?? 1e18) - (s[y].va ?? 1e18));

// Packed SoA for the coverage map: parallel typed arrays, one slot per cell.
// AoS (array of {state, span, ...}) thrashes the cache on every paint/hit-test;
// these columns stay hot.  Built lazily per section on first paint.
// State ids index CSS vars at paint time so light-mode tokens still apply.
// Packs every state rebrew can write to cells.state.  An unlisted state must
// not fall through to 0: build_db counts 'verified' as an exact match and
// covered_bytes covers every state != 'none', so painting it as an
// undocumented gap contradicts the number beside it.  The tooling-failure
// states share slot 7 ("other") — distinguishable from a gap, without
// spending a palette entry on each.
const STATE_ID = {
  none: 0, data: 0, thunk: 0,
  exact: 1, verified: 1, reloc: 2,
  near_match: 3, near_matching: 3, size_mismatch: 3,
  stub: 4, padding: 5, proven: 6,
  compile_error: 7, extract_error: 7, invalid_va: 7,
  missing_file: 7, missing_size: 7, skip: 7, unknown: 7,
  drift: 7, unchecked: 7,
};

// The words for each packed state id, in the same slot order detail.js reads
// its palette in.  The grid tooltip shows one, so hovering a cell says what
// the cell is instead of a raw index.
const STATE_LABEL = ["undocumented", "exact match", "reloc match", "near-match",
  "stub", "padding", "proven", "problem"];

function packSection(sec) {
  if (sec._pack) return sec._pack;
  const cells = sec.cells || [];
  const n = cells.length;
  const starts = new Uint32Array(n);
  const ends = new Uint32Array(n);
  const spans = new Uint16Array(n);
  const states = new Uint8Array(n);
  const fns = [];
  for (let i = 0; i < n; i += 1) {
    const cell = cells[i];
    starts[i] = cell.start ?? 0;
    ends[i] = cell.end ?? 0;
    spans[i] = cell.span || 1;
    states[i] = STATE_ID[cell.state] || 0;
    fns.push(cell.functions && cell.functions[0] ? cell.functions[0] : "");
  }
  sec._pack = { n, starts, ends, spans, states, fns };
  return sec._pack;
}

// Stroke styling lives in CSS (.icon svg), so the markup carries geometry only.
const Icon = (body) => span({ class: "icon", "aria-hidden": "true", innerHTML: `<svg viewBox="0 0 24 24">${body}</svg>` });
const SunIcon = () => Icon(`<circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>`);
const MoonIcon = () => Icon(`<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>`);
const ReloadIcon = () => Icon(`<path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>`);

// One key/value tile in a .meta-grid.  `valueText` is either a plain string,
// which gets the default .meta-value treatment, or a prebuilt node when it
// needs its own classes or behaviour (links, badges, the annotations block).
const MetaItem = (label, valueText, extraClass = "") => div({ class: `meta-item ${extraClass}` },
  span({ class: "meta-label" }, label),
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- API values arrive string|number; shape-check when rendering
  (typeof valueText === "string" || typeof valueText === "number") ? span({ class: "meta-value" }, valueText) : valueText
);

const HexLogo = (label, color, titleText) => div({ class: "section-title-left" },
  span({ class: "hex-logo", "aria-hidden": "true", style: `color: ${color};`, innerHTML: `<svg viewBox="0 0 100 100"><polygon points="50,5 90,27.5 90,72.5 50,95 10,72.5 10,27.5" fill="currentColor" fill-opacity="0.15" stroke="currentColor" stroke-width="6" stroke-linejoin="round"/><text x="50" y="54" dominant-baseline="middle" text-anchor="middle" fill="currentColor" font-weight="800" font-size="${label.length > 2 ? '26' : '42'}">${label}</text></svg>` }),
  h3({ class: "section-title-text" }, titleText)
);

const App = () => {
  const data = van.state(null);
  const originalDll = van.state(null); // {path, buf} | null — see loadedDll()
  const activeFilters = van.state(new Set());
  const activeSection = van.state(".text");
  const searchQuery = van.state("");
  const currentFn = van.state(null);
  const currentCellIndex = van.state(null);
  const activeFnName = van.state("");
  const summaryData = van.state(null);
  const loadingMsg = van.state(MSG.LOADING);
  const showModal = van.state(false);
  const modalTitle = van.state("");
  const modalContent = van.state("");
  const modalLang = van.state("");

  const cSourceText = van.state(MSG.SELECT_FUNCTION);
  const docText = van.state(MSG.SELECT_FUNCTION);
  const bytesText = van.state(MSG.SELECT_FUNCTION);
  const asmText = van.state(MSG.ASM_PLACEHOLDER);

  // Every write to the hex pane goes through these two, so a selection made
  // before detail.js has landed still resolves once formatBytes shows up, and
  // a later message-only write cancels the pending dump instead of being
  // overwritten by it.
  const pendingHex = van.state(null); // {buf, base} | null
  const showBytes = (buf, base) => { pendingHex.val = { buf, base }; };
  const showBytesMessage = (msg) => { pendingHex.val = null; bytesText.val = msg; };
  van.derive(() => {
    const pending = pendingHex.val;
    if (!pending) return;
    if (detailReady.val) bytesText.val = window.RC.formatBytes(pending.buf, pending.base);
    else bytesText.val = detailFailed.val ? MSG.DETAIL_UNAVAILABLE : MSG.LOADING;
  });
  const savedTheme = localStorage.getItem('recoverage_theme');
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  const isLightMode = van.state(savedTheme === 'light' || (!savedTheme && prefersLight));

  van.derive(() => {
    document.body.classList.toggle('light-mode', isLightMode.val);
    localStorage.setItem('recoverage_theme', isLightMode.val ? 'light' : 'dark');
  });

  const isLoading = van.state(true);

  const currentBuf = van.state(null);

  // Installed by Grid(); lets jumpToAddress move the grid's roving tab stop.
  let gridFocus = null;

  const activeTarget = van.state("");
  const availableTargets = van.state([]);

  // Set when there is nothing to draw: no database, no sections, or a failed
  // fetch.  The map area renders this instead of a spinner that never stops.
  const emptyState = van.state(null); // {title, detail} | null
  const stopLoading = (state) => { emptyState.val = state; isLoading.val = false; };

  // A section's cells arrive lazily (first paint fetches only the visible
  // one), so switching to a sibling tab can fail on its own.  {section, detail}
  // | null, read by the grid, which would otherwise sit on an empty frame with
  // no way back: the tab is unusable and nothing says why.
  const cellLoadError = van.state(null);

  const loadTargets = async () => {
    try {
      const res = await fetch("/api/targets");
      if (res.ok) {
        const d = await res.json();
        availableTargets.val = d.targets || [];

        // Check URL params first, then localStorage, then default
        const urlTarget = URL_PARAMS.get("target");
        const savedTarget = localStorage.getItem("recoverage_target");

        if (availableTargets.val.length === 0) {
          // First run: serve started before the database was built.
          activeTarget.val = "";
          stopLoading({ title: "No coverage database", detail: "Run rebrew build-db to create db/coverage.db, then reload this page." });
          return;
        }
        if (urlTarget && availableTargets.val.some(t => t.id === urlTarget)) {
          activeTarget.val = urlTarget;
        } else if (savedTarget && availableTargets.val.some(t => t.id === savedTarget)) {
          activeTarget.val = savedTarget;
        } else {
          activeTarget.val = availableTargets.val[0].id;
        }
        syncUrl();
      }
    } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- failure is shown to the user via the empty state
      // oxlint-disable-next-line eslint/no-console -- keep diagnostics in the browser console
      console.error("Failed to load targets:", error);
      availableTargets.val = [];
      activeTarget.val = "";
      stopLoading({ title: "Could not reach the server", detail: error.message });
    }
  };

  // loadData is triggered from four independent places (first paint, target
  // switch, SSE db-updated, regen) and its payload is multi-MB, so two calls
  // routinely overlap.  The later-resolving response wins by default, which
  // paints the previous target's map under the newly selected target.  One
  // generation counter decides which call still owns the state: a superseded
  // call writes nothing, and the in-flight fetch is aborted so it stops
  // occupying the connection.
  let loadGeneration = 0;
  let loadController = null;

  const loadData = async () => {
    // Without this the initial isLoading=true would never be cleared and the
    // map would spin forever with nothing to load.
    if (!activeTarget.val) { isLoading.val = false; return; }
    loadController?.abort();
    loadController = new AbortController();
    const { signal } = loadController;
    loadGeneration += 1;
    const generation = loadGeneration;
    const superseded = () => generation !== loadGeneration;
    // Background refresh (SSE db-updated, regen) keeps the old map on
    // screen and swaps when new data lands.  Full-overlay loading is only
    // for first paint — flashing the whole map on every rebuild is jank.
    const firstPaint = !data.val;
    if (firstPaint) {
      isLoading.val = true;
      emptyState.val = null;
    }
    try {
      // "no-cache" (not "no-store") so the server's ETag/304 path works:
      // with no-store the browser never sends If-None-Match and the whole
      // multi-MB dataset is re-transferred on every load.
      // First paint only needs the visible section's cells.  Sibling tabs
      // still get their metadata; cells arrive on switchTab / jumpToAddress.
      const wanted = URL_PARAMS.get("section") || activeSection.val || ".text";
      let res = await fetch(DATA_URL(activeTarget.val, wanted), { cache: "no-cache", signal });
      if (!res.ok) res = await fetch(DATA_URL(activeTarget.val), { cache: "no-cache", signal });
      if (!res.ok) throw new Error(`failed to load data`);
      const d = await res.json();
      if (superseded()) return;
      data.val = d;
      cellLoadError.val = null;

      const secNames = sectionNames(d.sections || {});
      if (secNames.length === 0) {
        const ver = String(d.db_version ?? "");
        // The accepted set comes from the payload (api.known_schema), so the
        // message tracks the server's schema support instead of a copy that
        // goes stale.  Without it, fall back to the benign wording rather than
        // accuse a schema this build was never told about.
        const known = d.known_schema ?? [];
        const unknownSchema = ver !== "" && known.length > 0 && !known.includes(ver);
        emptyState.val = {
          title: "This target has no sections",
          detail: unknownSchema
            ? `The database reports schema v${ver}, which this build does not understand. Rebuild it with a matching rebrew.`
            : "The database has no section rows yet. Rerun rebrew build-db.",
        };
      } else if (!d.sections[activeSection.val]) {
        const [firstSection] = secNames;
        activeSection.val = firstSection;
      }
      // URL section param wins over the default when valid.
      const secParam = URL_PARAMS.get("section");
      if (secParam && secNames.includes(secParam)) {
        activeSection.val = secParam;
      }

      // The original binary (multi-MB) loads lazily on first cell selection
      // (see ensureOriginalDll) — fetching it here would put megabytes on
      // first paint that only the hex/asm panes ever need.

      const summary = d.summary || {};
      summaryData.val = { ...summary, textSize: d.sections[".text"]?.size || 0 };

      // URL ?q= restores the search query into the box and the filter.
      const qParam = URL_PARAMS.get("q");
      if (qParam) {
        searchQuery.val = qParam;
        const inputEl = document.querySelector(".search input");
        if (inputEl) inputEl.value = qParam;
      }

      // Restore last visited function — URL ?fn= wins over localStorage.
      setTimeout(() => {
        if (superseded()) return;
        const lastFn = URL_PARAMS.get("fn") || localStorage.getItem(`recoverage_last_fn_${activeTarget.val}`);
        if (lastFn && data.val?.search_index?.[lastFn]) {
          const info = data.val.search_index[lastFn];
          jumpToAddress(toVa(info.va));
          setTimeout(() => { if (!superseded()) selectFunction(lastFn); }, 50);
        } else if (lastFn) {
          selectFunction(lastFn);
        }
      }, 50);
    } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- failure is shown to the user as an error panel
      // A superseded call (or the abort that superseded it) owns no state:
      // the call that replaced it reports its own outcome.
      if (superseded() || error.name === "AbortError") return;
      // Background refresh must not replace a good map with an error panel
      // on a transient failure — log it and keep the stale map.
      if (firstPaint) {
        loadingMsg.val = MSG.ERROR_PREFIX + error.message;
        summaryData.val = null;
        emptyState.val = { title: "Could not load coverage data", detail: error.message };
      } else {
        // oxlint-disable-next-line eslint/no-console -- a failed background refresh is otherwise invisible
        console.error("Background refresh failed:", error);
      }
    } finally {
      if (!superseded()) isLoading.val = false;
    }
  };

  // The regen handler lives in detail.js: it only runs on a Reload click, long
  // after that file lands.  It gets the two states it writes plus the reloader.
  const reloadData = () => window.RC.reloadData?.({ loadingMsg, summaryData, loadData, MSG });

  let searchTimeout = null;
  const applySearch = (text) => {
    clearTimeout(searchTimeout);
    searchQuery.val = text;
    syncUrl();
  };
  const onSearchInput = (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      searchQuery.val = e.target.value;
      syncUrl();
    }, 250);
  };
  // Clearing has to reach the input element too: it is uncontrolled, so the
  // state alone would leave the typed text sitting in the box while the map
  // stops filtering.
  const clearSearch = (inputEl) => {
    applySearch("");
    if (inputEl) inputEl.value = "";
  };
  // Enter jumps to the first match.  Dimming alone leaves the user hunting
  // for a lit cell that may be in a section that is not on screen; the
  // `?q=` deep link and localStorage restore both land the user in the same
  // spot without typing, so typing should go there too.
  const onSearchKeydown = (e) => {
    if (e.key === "Escape" && searchQuery.val) {
      e.preventDefault();
      clearSearch(e.target);
      return;
    }
    if (e.key !== "Enter") return;
    e.preventDefault();
    applySearch(e.target.value);
    const first = firstMatchName.val;
    if (!first) return;
    const va = data.val?.search_index?.[first]?.va;
    if (va) jumpToAddress(toVa(va));
    selectFunction(first);
  };

  // Deep-linking: keep target/function/section/search in the URL so reloads
  // restore state and links are shareable.  replaceState (not pushState) so
  // the URL tracks state without spamming history.
  const URL_PARAMS = new URLSearchParams(window.location.search);
  const syncUrl = () => {
    const params = new URLSearchParams();
    if (activeTarget.val) params.set("target", activeTarget.val);
    if (currentFn.val && (currentFn.val.name || currentFn.val.vaStart)) {
      params.set("fn", currentFn.val.name || currentFn.val.vaStart);
    }
    if (activeSection.val) params.set("section", activeSection.val);
    if (searchQuery.val) params.set("q", searchQuery.val);
    const qs = params.toString();
    history.replaceState(null, "", qs ? `?${qs}` : window.location.pathname);
  };

  // Initialize: load targets then data (NOT in derive - that's an anti-pattern)
  (async () => {
    await loadTargets();
    loadData();
  })();

  // Live-reload: refresh the grid when coverage.db changes on disk.  The
  // subscription lives in detail.js, so it starts once that lands rather than
  // competing with first paint.  connectEvents returns the disposer that closes
  // the EventSource: the stream pins a server-side /api/events slot, a bounded
  // resource, until it is closed.  A pagehide releases it explicitly, and the
  // derive must not open a second stream when it re-runs.
  let closeEvents = null;
  window.addEventListener("pagehide", () => {
    closeEvents?.();
    closeEvents = null;
  }, { once: true });
  van.derive(() => {
    if (!detailReady.val || closeEvents) return;
    closeEvents = window.RC.connectEvents(() => loadData());
  });

  const matchesSearch = (name, query) => {
    if (!query) return true;
    const q = query.toLowerCase();
    if (name.toLowerCase().includes(q)) return true;

    // Check search index if available
    if (data.val && data.val.search_index && data.val.search_index[name]) {
      const info = data.val.search_index[name];
      if (info.va && info.va.toLowerCase().includes(q)) return true;
      if (info.symbol && info.symbol.toLowerCase().includes(q)) return true;
    }
    return false;
  };

  // Names only, in index order: the search status line reports the count and
  // Enter jumps to the first entry, so this cannot carry the VA spellings the
  // dimming set below needs.
  const matchedFnNames = van.derive(() => {
    if (!data.val || !data.val.search_index) return new Set();
    const query = searchQuery.val;
    if (!query) return new Set();

    const matched = new Set();
    for (const [name, info] of Object.entries(data.val.search_index)) {
      if (matchesSearch(name, query) || (info && matchesSearch(info.va || "", query))) {
        matched.add(name);
      }
    }
    return matched;
  });

  // The first hit, or "" when nothing matches.  Read by onSearchKeydown.
  const firstMatchName = van.derive(() => matchedFnNames.values().next().value ?? "");

  const filteredFnNames = van.derive(() => {
    const names = matchedFnNames.val;
    if (names.size === 0) return new Set(); // Empty set means "no filter"
    // Grid .text cells store the function's vaStart string (not the
    // name) in cell.functions / pack.fns — the dimming test compares
    // against this set, so VA spellings must be included too.
    const matched = new Set(names);
    for (const name of names) {
      const va = data.val?.search_index?.[name]?.va;
      if (va) matched.add(va);
    }
    return matched;
  });

  // Start the original-binary download once, on first need.  When it lands,
  // re-slice the active selection if its bytes pane is still waiting — the
  // null-DLL branches below show LOADING until then, LOAD_FAILED on error.
  // The buffer is stored against the path it came from: a target switch while
  // a multi-MB download is in flight would otherwise install the previous
  // target's bytes, and every later slice would read the wrong binary at the
  // current target's offsets.
  const currentDllPath = () => {
    const d = data.val;
    return (d && d.paths && d.paths.originalDll) || `/original/${enc(activeTarget.val.toLowerCase())}.dll`;
  };
  // The loaded buffer, but only while it belongs to the target on screen.
  const loadedDll = () => (originalDll.val?.path === currentDllPath() ? originalDll.val.buf : null);

  const ensureOriginalDll = () => {
    const dllPath = currentDllPath();
    if (originalDll.val?.path === dllPath || ensureOriginalDll.inflight) return;
    ensureOriginalDll.inflight = fetchArrayBufferSafe(dllPath)
      // A rejected fetch never reaches .then, which would strand the inflight
      // slot and leave the bytes pane reading LOADING for the rest of the
      // session.  Release the slot and let the next selection retry.
      .catch(() => null)
      .then((buf) => {
        ensureOriginalDll.inflight = null;
        if (dllPath !== currentDllPath()) return; // superseded by a target switch
        originalDll.val = buf ? { path: dllPath, buf } : null;
        if (currentCellIndex.val == null || currentBuf.val != null) return;
        if (buf) selectChunk(currentCellIndex.val);
        else showBytesMessage(MSG.BYTES_LOAD_FAILED);
      });
  };

  // Bytes pane message when slicing failed: out-of-range vs binary
  // missing.  A missing binary still downloading reads as LOADING.
  const bytesMissMessage = () => {
    if (loadedDll()) return MSG.BYTES_FAILED;
    if (ensureOriginalDll.inflight) return MSG.LOADING;
    return MSG.BYTES_LOAD_FAILED;
  };

  const sliceOriginalBytes = (cell) => {
    const buf = loadedDll();
    if (!buf || !data.val?.sections) return null;
    const sec = data.val.sections[activeSection.val];
    if (!sec || activeSection.val === ".bss") return null;

    const va = toVa(cell.va);
    const start = activeSection.val === ".text" ? cell.fileOffset : sec.fileOffset + (va - sec.va);
    const size = activeSection.val === ".text" ? cell.size : 16;

    // fileOffset/size are nullable (a section with no file backing, a
    // function of unknown size).  `null < 0` and `null + n > len` are both
    // false, so the arithmetic below would pass a null start straight into
    // ArrayBuffer.slice and label the first bytes of the binary with this
    // function's VA.  Refuse instead, exactly as the server's
    // _file_backed_section does for sections.
    if (!Number.isInteger(start) || !Number.isInteger(size) || size < 0) return null;
    if (start < 0 || start + size > buf.byteLength) return null;
    return buf.slice(start, start + size);
  };

  let currentAbortController = null;

  // Every pane a failed selection filled must be cleared, or the pane keeps
  // showing the previously selected entry next to the error, "Loading
  // assembly..." never resolves, and Copy/Open hand out that literal.
  const failSelection = (error, signal, asmFallback) => {
    // A superseded selection owns no state: fetchTextSafe is not
    // signal-bound, so a stale request can still fail after a newer
    // selection has rendered, and clearing here would wipe it.
    if (error.name === 'AbortError' || signal.aborted) return;
    currentFn.val = null;
    currentBuf.val = null;
    cSourceText.val = MSG.ERROR_PREFIX + error.message;
    showBytesMessage(bytesMissMessage());
    docText.val = MSG.NO_DOCS;
    asmText.val = asmFallback;
  };

  const selectFunction = async (id) => {
    ensureOriginalDll();
    if (currentAbortController) {
      currentAbortController.abort();
    }
    currentAbortController = new AbortController();
    const { signal } = currentAbortController;

    if (activeSection.val === ".text") {
      // Set initial loading state synchronously
      currentFn.val = { name: "Loading..." };
      cSourceText.val = "Loading...";
      docText.val = "Loading...";
      asmText.val = "Loading assembly...";

      try {
        const res = await fetch(FN_URL(activeTarget.val, id), { signal });
        if (!res.ok) throw new Error("Not found");
        const fn = await res.json();

        if (signal.aborted) return;
        currentFn.val = fn;
        localStorage.setItem(`recoverage_last_fn_${activeTarget.val}`, id);
        syncUrl();

        const buf = sliceOriginalBytes(fn);
        currentBuf.val = buf;
        if (buf) showBytes(buf, toVa(fn.vaStart || fn.va));
        else showBytesMessage(bytesMissMessage());

        const sourceRoot = (data.val && data.val.paths && data.val.paths.sourceRoot) ? data.val.paths.sourceRoot : `/src/${enc(activeTarget.val.toLowerCase())}`;
        const cPath = (fn.files && fn.files[0]) ? `${encPath(sourceRoot)}/${encPath(fn.files[0])}` : null;
        const va = fn.vaStart || fn.va;
        const { size } = fn;

        // Fetch C source here; the disassembly loads through detail.js, which
        // owns the /asm formatting (and is not in the inlined shell).
        const newCSource = cPath ? await fetchTextSafe(cPath) : MSG.NO_C_SOURCE;
        window.RC.loadAsm?.({
          url: `${ASM_URL(activeTarget.val)}?va=${enc(va)}&size=${size}&section=${enc(activeSection.val)}`,
          set: (text) => { asmText.val = text; },
          signal,
        });

        if (signal.aborted) return;

        const newDocs = window.RC.extractDocs ? window.RC.extractDocs(newCSource) : null;

        // Update all state synchronously to trigger a single re-render
        cSourceText.val = newCSource;
        docText.val = newDocs || MSG.NO_DOCS;
      } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- AbortError is a cancellation; other failures become error text
        failSelection(error, signal, MSG.ASM_PLACEHOLDER);
      }

    } else {
      // Global variable
      try {
        const res = await fetch(FN_URL(activeTarget.val, id), { signal });
        if (!res.ok) throw new Error("Not found");
        const g = await res.json();

        if (signal.aborted) return;
        currentFn.val = { ...g, isGlobal: true };
        localStorage.setItem(`recoverage_last_fn_${activeTarget.val}`, id);
        const buf = sliceOriginalBytes(g);
        currentBuf.val = buf;
        if (buf) showBytes(buf, toVa(g.va));
        else if (activeSection.val === ".bss") showBytesMessage(MSG.BYTES_BSS);
        else showBytesMessage(bytesMissMessage());
        cSourceText.val = g.decl || MSG.NO_DECL;
        docText.val = MSG.GLOBAL_VAR;
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- AbortError is a cancellation; other failures become error text
        failSelection(error, signal, MSG.DATA_SECTION_NO_ASM);
      }
    }
  };

  const selectChunk = (i) => {
    currentCellIndex.val = i;
    // Selecting a cell supersedes whatever selection was still in flight.
    // Both the function fetch and the undocumented-block /asm request resume
    // after an await and write their panes unconditionally on resume, so
    // without this the previous selection lands on top of this one whenever
    // the user clicks faster than the network answers.  selectFunction
    // installs its own controller for the function branch; the controller
    // here is the one that guards the branch below.
    currentAbortController?.abort();
    currentAbortController = new AbortController();
    const { signal } = currentAbortController;
    ensureOriginalDll();
    if (!data.val || !data.val.sections) return;
    const sec = data.val.sections[activeSection.val];
    if (!sec) return;

    const cells = sec.cells || [];
    const cell = cells[i];
    if (!cell) return;

    const pack = packSection(sec);
    activeFnName.val = pack.fns[i] || "";

    if (cell.functions && cell.functions.length > 0) {
      selectFunction(cell.functions[0]);
    } else {
      currentFn.val = null;
      cSourceText.val = MSG.NO_C_FOR_BLOCK;
      docText.val = MSG.UNDOCUMENTED_BLOCK;
      asmText.val = MSG.ASM_PLACEHOLDER;

      const dll = activeSection.val === ".bss" ? null : loadedDll();
      if (activeSection.val === ".bss") {
        currentBuf.val = null;
        showBytesMessage(MSG.BYTES_BSS);
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      } else if (dll) {
        const start = sec.fileOffset + cell.start;
        const size = cell.end - cell.start;
        const end = start + size;
        if (start >= 0 && end <= dll.byteLength) {
          const buf = dll.slice(start, end);
          currentBuf.val = buf;
          showBytes(buf, sec.va + cell.start);

          if (activeSection.val === ".text") {
            // Fetch ASM for undocumented block in .text
            asmText.val = "Loading assembly...";
            window.RC.loadAsm?.({
              url: `${ASM_URL(activeTarget.val)}?va=${enc(sec.va + cell.start)}&size=${size}&section=${enc(activeSection.val)}`,
              set: (text) => { asmText.val = text; },
              signal,
            });
          } else {
            asmText.val = MSG.DATA_SECTION_NO_ASM;
          }
        } else {
          showBytesMessage(MSG.BYTES_FAILED);
          asmText.val = MSG.DATA_SECTION_NO_ASM;
        }
      } else {
        showBytesMessage(ensureOriginalDll.inflight ? MSG.LOADING : MSG.BYTES_LOAD_FAILED);
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      }
    }
  };

  // Copy, Open, Copy VA and Copy Symbol all delegate to detail.js.  If that
  // file never arrives they would look enabled and do nothing at all, so they
  // go disabled and say why — the panes it owns already report the same
  // failure.  Same while it is still loading: copyToClipboard is a no-op until
  // it lands.  Reload is the exception: it gates on detailFailed only, so a
  // click in the window before detail.js lands is a silent no-op.
  const detailTitle = () => {
    if (detailFailed.val) return MSG.DETAIL_UNAVAILABLE;
    if (detailReady.val) return "";
    return MSG.LOADING;
  };
  const copyToClipboard = (text, e) => window.RC.copyToClipboard?.(text, e);

  const SearchHint = () => (searchQuery.val
    ? div({ class: "hint" }, "Click a highlighted block to view its details, or press Enter in the search box to jump to the first match.")
    : div({ class: "hint" }, "Click a block to view function details. Use filters to show specific statuses."));

  const toggleFilter = (filter) => {
    const newFilters = new Set(activeFilters.val);
    if (filter === "all") {
      newFilters.clear();
    } else if (newFilters.has(filter)) {
      newFilters.delete(filter);
    } else {
      newFilters.add(filter);
    }
    activeFilters.val = newFilters;
  };

  const jumpToAddress = (targetVa) => {
    if (!data.val || !data.val.sections) return;
    const focusCellAfterPaint = (secName, cellIndex) => {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          gridFocus?.(secName, cellIndex);
          const grid = document.querySelector(`#${gridId(secName)}`);
          if (grid) grid.scrollIntoView({ behavior: "smooth", block: "nearest" });
        });
      });
    };
    const locate = (secName, sec) => {
      const offset = targetVa - sec.va;
      const pack = packSection(sec);
      for (let i = 0; i < pack.n; i += 1) {
        if (offset >= pack.starts[i] && offset < pack.ends[i]) {
          activeSection.val = secName;
          selectChunk(i);
          focusCellAfterPaint(secName, i);
          return true;
        }
      }
      return false;
    };
    for (const [secName, sec] of Object.entries(data.val.sections)) {
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- API section rows carry number|null va/size (.bss has no base address); shape-check before the range math
      if (typeof sec.va !== "number" || typeof sec.size !== "number") continue;
      if (targetVa < sec.va || targetVa >= sec.va + sec.size) continue;
      if (sec.cells != null) { locate(secName, sec); return; }
      void ensureSectionCells(secName).then(() => {
        const fresh = data.val?.sections?.[secName];
        if (fresh) locate(secName, fresh);
      });
      return;
    }
    // oxlint-disable-next-line eslint/no-console -- an address outside every section deserves a console warning
    console.warn("Address not found in any section:", targetVa.toString(16));
  };

  const HighlightedCode = ({ lang, text }) => {
    const codeEl = code({ class: lang ? `language-${lang}` : "" }, text);
    setTimeout(() => { window.RC.highlightInto?.(codeEl, lang); }, 0);
    // detail.js rewrites asm operands into .asm-link anchors during the
    // highlight pass; following one is app.js's job (it owns the selection).
    codeEl.addEventListener("click", (e) => {
      if (e.target.classList.contains("asm-link")) {
        e.preventDefault();
        const addrStr = e.target.dataset.addr;
        if (addrStr) {
          jumpToAddress(Number.parseInt(addrStr, 16));
        }
      }
    });
    return pre({ class: "code" }, codeEl);
  };


  // oxlint-disable-next-line eslint/arrow-body-style -- explicit return reads clearly for a component factory closure
  const ProgressBar = () => {
    return () => {
      // The empty state already explains the situation; a bar reading
      // "Section not found" beside it just contradicts it.
      if (emptyState.val) return div({ class: "progress-container" });
      if (isLoading.val) {
        return div({ class: "progress-container" },
          div({ class: "progress-stats" },
            span({ class: "stat-item" }, "Loading...")
          )
        );
      }

      // A message set while the map is already on screen (the regen cooldown
      // notice) used to be dropped here: the old test only covered the
      // no-data case, so clicking Reload again in quick succession looked
      // like nothing happened.
      if (!data.val || !data.val.sections || !summaryData.val || loadingMsg.val !== MSG.LOADING) {
        return div({ class: "progress-container" },
          div({ class: "progress-stats" },
            span({ class: "stat-item" }, loadingMsg.val)
          )
        );
      }

      const secName = activeSection.val;
      const sec = data.val.sections[secName];
      if (!sec) return div({ class: "subtitle" }, "Section not found");

      let exactCount = 0;
      let relocCount = 0;
      let nearMatchCount = 0;
      let stubCount = 0;
      let exactBytes = 0;
      let relocBytes = 0;
      let nearMatchBytes = 0;
      let stubBytes = 0;
      let paddingBytes = 0;
      let totalItems = 0;
      let coveredBytes = 0;

      const s = summaryData.val[secName] || summaryData.val; // Fallback for .text if not nested
      if (s) {
        exactCount = s.exactMatches || 0;
        relocCount = s.relocMatches || 0;
        nearMatchCount = s.nearMatchCount || 0;
        stubCount = s.stubCount || 0;
        exactBytes = s.exactBytes || 0;
        relocBytes = s.relocBytes || 0;
        nearMatchBytes = s.nearMatchBytes || 0;
        stubBytes = s.stubBytes || 0;
        paddingBytes = s.paddingBytes || 0;
        totalItems = s.totalFunctions || 0;
        coveredBytes = s.coveredBytes || 0;
      }

      const total = secName === ".text" ? (totalItems || 1) : (sec.size || 1);
      const exactPct = ((secName === ".text" ? exactCount : exactBytes) / total) * 100;
      const relocPct = ((secName === ".text" ? relocCount : relocBytes) / total) * 100;
      const nearMatchPct = ((secName === ".text" ? nearMatchCount : nearMatchBytes) / total) * 100;
      const stubPct = ((secName === ".text" ? stubCount : stubBytes) / total) * 100;
      const paddingPct = (secName === ".text" && sec.size > 0 ? paddingBytes / sec.size : paddingBytes / total) * 100;

      const coveragePct = sec.size > 0 ? (coveredBytes / sec.size * 100) : 0;

      const getClasses = (type) => {
        const cls = `progress-segment ${type}`;
        return () => `${cls} ${activeFilters.val.has(type) ? "active" : ""}`;
      };

      // Keyboard access for the clickable progress segments: they are
      // div-based filter toggles, so give them a button role, tabindex, and
      // Enter/Space activation (P1 a11y — previously mouse-only).
      const segKeydown = (e, filter) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggleFilter(filter);
        }
      };

      // A segment at 0% renders zero-wide but would still be a tab stop and a
      // screen-reader toggle with nothing to point at.  Below half a percent it
      // is not a usable target either, so it is dropped; the E/R/M/S/P buttons
      // remain the reliable way to reach every filter.
      const Segment = (type, pct, label, titleText) => pct < 0.5 ? null : div({
        class: getClasses(type), role: "button", tabindex: "0",
        "aria-pressed": () => activeFilters.val.has(type),
        "aria-label": label, style: `width: ${pct}%`, title: titleText,
        onclick: () => toggleFilter(type), onkeydown: (e) => segKeydown(e, type)
      });

      return div({ class: "progress-container" },
        div({ class: "progress-stats" },
          span({ class: "stat-item stat-bytes" }, `${sec.size} bytes`),
          // "Matched" counts exact + reloc only: a near-match is a miss and
          // a stub is a stand-in, so neither counts. Same contract as
          // Potato Mode's progress bar. (/stats' per-section `matched`
          // additionally counts proven, the semantic-equivalence promotion.)
          span({ class: "stat-item stat-matched" }, `${exactCount + relocCount} / ${totalItems} matched`),
          span({ class: "stat-item stat-coverage" }, `${coveragePct.toFixed(2)}% coverage`)
        ),
        div({ class: "progress-bar" },
          div({ class: "progress-segments" },
            Segment("exact", exactPct, "Toggle exact filter", `Exact: ${exactCount}`),
            Segment("reloc", relocPct, "Toggle reloc filter", `Reloc: ${relocCount}`),
            Segment("near_match", nearMatchPct, "Toggle near-match filter", `Near-match: ${nearMatchCount}`),
            Segment("stub", stubPct, "Toggle stub filter", `Stub: ${stubCount}`),
            Segment("padding", paddingPct, "Toggle padding filter", `Padding: ${paddingBytes}B`)
          )
        )
      );
    };
  };

  const Grid = () => {
    const container = div({ class: "grid-container", style: "position: relative; min-height: 120px;" });
    let mounted = false;
    van.derive(() => {
      if (!detailReady.val || mounted) return;
      mounted = true;
      window.RC.mountGrid({
        container, data, isLoading, emptyState, activeSection, activeFilters,
        searchQuery, filteredFnNames, currentCellIndex, activeFnName, isLightMode,
        selectChunk, packSection, gridId, cellLoadError, retrySectionCells,
        setGridFocus: (fn) => { gridFocus = fn; },
      });
    });
    return container;
  };

  const Panel = () => {
    const fn = currentFn.val;
    const cellIdx = currentCellIndex.val;

    let title = "No selection";
    let metaContent = null;

    if (fn) {
      title = fn.name;
      const sourceRoot = (data.val && data.val.paths && data.val.paths.sourceRoot) ? data.val.paths.sourceRoot : `/src/${enc(activeTarget.val.toLowerCase())}`;

      const SourceItem = () => fn.files && fn.files.length > 0
        ? MetaItem("Source", span({ class: "meta-value" }, ...fn.files.map((file, i) =>
            span(i > 0 ? ", " : "", a({ href: `${encPath(sourceRoot)}/${encPath(file)}`, target: "_blank", rel: "noopener noreferrer", class: "source-link" }, file)))))
        : null;

      if (fn.isGlobal) {
        metaContent = div({ class: "meta-grid" },
          MetaItem("VA", a({
            href: "#",
            class: "meta-value asm-link",
            onclick: (e) => { e.preventDefault(); jumpToAddress(toVa(fn.va)); }
          }, `0x${fn.va.toString(16).toUpperCase()}`)),
          MetaItem("Type", "Global Variable"),
          SourceItem()
        );
      } else {
        const statusClass = fn.status ? `status-${fn.status.toLowerCase().replace('_', '-')}` : '';

        metaContent = div({ class: "meta-grid" },
          MetaItem("VA", a({
            href: "#",
            class: "meta-value asm-link",
            onclick: (e) => { e.preventDefault(); jumpToAddress(toVa(fn.vaStart || fn.va)); }
          }, fn.vaStart || fn.va)),
          MetaItem("Size", `${fn.size} bytes`),
          MetaItem("Offset", `0x${(fn.fileOffset || 0).toString(16).toUpperCase()}`),
          MetaItem("Symbol", fn.symbol || MSG.NA),
          MetaItem("Status", span({ class: `meta-value status-badge ${statusClass}` }, fn.status || "?")),
          MetaItem("Module", fn.module || "?"),
          MetaItem("Compiler", fn.cflags || MSG.NA),
          MetaItem("Marker", fn.markerType || "?"),
          fn.blocker ? MetaItem("Blocker", span({ class: "meta-value blocker-value" }, fn.blocker), "full-width") : null,
          fn.blockerDelta == null ? null : MetaItem("Delta", span({ class: "meta-value delta-value" }, `${fn.blockerDelta} bytes`)),
          fn.ghidra_name && fn.ghidra_name !== fn.name ? MetaItem("Ghidra", fn.ghidra_name) : null,
          fn.list_name && fn.list_name !== fn.name ? MetaItem("Func List", fn.list_name) : null,
          fn.size_reason ? MetaItem("Size Source", fn.size_reason) : null,
          fn.last_verify ? MetaItem("Verified", `${fn.last_verify.verified_at}${fn.last_verify.byte_delta == null ? "" : ` (Δ${fn.last_verify.byte_delta}B)`}`) : null,
          fn.last_verify && fn.last_verify.similarity != null ? MetaItem("Code Sim", `${fn.last_verify.similarity.toFixed(1)}%`) : null,
          fn.last_verify && fn.last_verify.reg_delta != null ? MetaItem("Reg Delta", `${fn.last_verify.reg_delta}`) : null,
          fn.last_verify && fn.last_verify.effective_match ? MetaItem("Effective", "register-only delta — prove candidate") : null,
          fn.updated_by ? MetaItem("Updated By", `${fn.updated_by}${fn.updated_at ? ` (${fn.updated_at})` : ""}`) : null,
          fn.similarity == null ? null : MetaItem("Similarity", `${(fn.similarity * 100).toFixed(1)}%`),
          fn.is_thunk ? MetaItem("Type", "IAT thunk (not reversible)") : null,
          fn.is_export ? MetaItem("Type", "Exported function") : null,
          fn.sha256 ? MetaItem("SHA256", `${fn.sha256.slice(0, 16)}...`) : null,
          SourceItem(),
          docText.val && docText.val !== MSG.SELECT_FUNCTION && docText.val !== MSG.NO_DOCS
            ? MetaItem("Annotations", pre({ class: "meta-docs" }, docText.val), "full-width") : null
        );
      }
    } else if (cellIdx !== null && data.val && data.val.sections) {
      const sec = data.val.sections[activeSection.val];
      if (sec && sec.cells) {
        const cell = sec.cells[cellIdx];
        title = cell.label ? `Block ${cellIdx}: ${cell.label}` : `Block ${cellIdx}`;
        // NULL-va (.bss-style) sections have no base address: fall back to 0
        // so the range row shows file-relative offsets, matching the grid
        // titles' `sec.va || 0`, instead of rendering hex(NaN).
        const secVa = sec.va || 0;
        metaContent = div({ class: "meta-grid" },
          MetaItem("Range", `${hex(secVa + cell.start, 8)}..${hex(secVa + cell.end, 8)}`, "nowrap"),
          MetaItem("State", cell.state || "none"),
          cell.label ? MetaItem("Label", cell.label) : null,
          cell.parent_function ? MetaItem("Parent", span({ class: "meta-value" },
            a({ href: "#", onclick: (e) => { e.preventDefault(); selectFunction(cell.parent_function); } }, cell.parent_function))) : null
        );
      }
    }

    // C Source, Assembly, and Original Bytes are the same panel section with a
    // different logo, language, and body: title row, Copy, Open-in-modal.
    // Copy/Open go disabled while the pane holds an empty-state message —
    // copying "(select a function)" or opening a modal of it is never what
    // the user wants; the tooltip says what to do instead.
    const isEmptyMessage = (text) => text === MSG.SELECT_FUNCTION || text === MSG.ASM_PLACEHOLDER
      || text === MSG.NO_C_SOURCE || text === MSG.NO_C_FOR_BLOCK || text === MSG.UNDOCUMENTED_BLOCK
      || text === MSG.DATA_SECTION_NO_ASM || text === MSG.BYTES_FAILED || text === MSG.BYTES_BSS
      || text === MSG.BYTES_LOAD_FAILED || text === MSG.GLOBAL_VAR || text === MSG.NO_DECL
      || text === MSG.NA || text === MSG.LOADING || text === MSG.DETAIL_UNAVAILABLE
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- pane text is string|derived-state; guard before .startsWith, not a type contract
      || (typeof text === "string" && (text.startsWith(MSG.ERROR_PREFIX) || text.startsWith("(failed to load:")));
    const CodeSection = (logo, color, heading, lang, text) => div({ class: "section" },
      div({ class: "section-title" },
        HexLogo(logo, color, heading),
        div({ class: "section-actions" },
          button({ class: "btn copy-btn", "aria-label": `Copy ${heading}`, disabled: () => !detailReady.val || detailFailed.val || isEmptyMessage(text), title: () => isEmptyMessage(text) ? "Select a block first" : detailTitle(), onclick: (e) => copyToClipboard(text, e) }, "Copy"),
          button({
            class: "btn copy-btn", "aria-label": `Open ${heading} in a larger view`, disabled: () => !detailReady.val || detailFailed.val || isEmptyMessage(text), title: () => isEmptyMessage(text) ? "Select a block first" : detailTitle(),
            onclick: () => {
              // cellIdx is null when nothing is selected, which used to render
              // as the literal "Block null".
              const subject = cellIdx === null ? activeSection.val : `Block ${cellIdx}`;
              const headingTarget = fn ? fn.name : subject;
              modalTitle.val = `${heading}: ${headingTarget}`;
              modalContent.val = text;
              modalLang.val = lang;
              showModal.val = true;
            }
          }, "Open")
        )
      ),
      HighlightedCode({ lang, text })
    );

    // Hint for the copy buttons when they have nothing to copy.
    const copyHint = (copied, what) => {
      if (copied == null) return `Select a ${what} first`;
      if (detailFailed.val) return MSG.DETAIL_UNAVAILABLE;
      if (detailReady.val) return "";
      return MSG.LOADING;
    };

    // Compute copyable VA: prefer fn fields, fall back to cell address range.
    // Copy VA / Copy Symbol delegate to detail.js: until it lands there is
    // nothing to copy with, so they stay disabled instead of looking live.
    let copyVA = null;
    if (fn) {
      copyVA = fn.vaStart || (fn.va == null ? null : hex(fn.va, 8));
    } else if (cellIdx !== null && data.val?.sections) {
      const sec = data.val.sections[activeSection.val];
      if (sec?.cells?.[cellIdx]) {
        const cell = sec.cells[cellIdx];
        const secVa = sec.va || 0;
        copyVA = `${hex(secVa + cell.start, 8)}..${hex(secVa + cell.end, 8)}`;
      }
    }

    return aside({ class: "panel", id: "panel", style: "position: relative;" },
      () => isLoading.val ? div({ class: "loading-overlay", role: "status", "aria-live": "polite" }, "Loading...") : null,
      div({ class: "panel-head" },
        h2({ class: "panel-title" }, title),
        div({ class: "panel-actions" },
          button({ class: "btn copy-btn", "aria-label": "Copy VA", disabled: () => !detailReady.val || detailFailed.val || copyVA == null, title: () => copyHint(copyVA, "block"), onclick: (e) => copyToClipboard(copyVA, e) }, "Copy VA"),
          button({ class: "btn copy-btn", "aria-label": "Copy Symbol", disabled: () => !detailReady.val || detailFailed.val || fn?.symbol == null, title: () => copyHint(fn?.symbol, "function"), onclick: (e) => copyToClipboard(fn?.symbol, e) }, "Copy Symbol")
        ),
        div({ class: "panel-meta" }, metaContent)
      ),
      div({ class: "panel-body" },
        // Nothing is selected at first paint, so the three code sections would
        // lay out stand-in text and copy buttons for nobody: the boot layout
        // walks 205 objects, 61 of them these.  One muted line until there is
        // something to show.
        (fn || cellIdx !== null)
          ? [
              CodeSection("C", "var(--accent-c-source)", "C Source", "c", cSourceText.val),
              activeSection.val === ".text"
                ? CodeSection("ASM", "var(--accent-asm)", "Assembly", "x86asm", asmText.val)
                : div({ class: "section" },
                    div({ class: "section-title" }, HexLogo("{}", "var(--accent-data)", "Data Inspector")),
                    () => detailReady.val
                      ? window.RC.DataInspector(currentBuf.val)
                      : div({ class: "code" }, detailFailed.val ? MSG.DETAIL_UNAVAILABLE : MSG.LOADING)
                  ),
              CodeSection("01", "var(--accent-bytes)", "Original Bytes", "hex", bytesText.val)
            ]
          : div({ class: "hint" }, MSG.SELECT_FUNCTION)
      )
    );
  };

  const ensureSectionCells = async (name) => {
    const d = data.val;
    const sec = d?.sections?.[name];
    if (!sec || sec.cells != null) return;
    if (sec._cellsInflight) { await sec._cellsInflight; return; }
    sec._cellsInflight = (async () => {
      const res = await fetch(DATA_URL(activeTarget.val, name), { cache: "no-cache" });
      if (!res.ok) throw new Error(`failed to load ${name}`);
      const slice = await res.json();
      const incoming = slice.sections?.[name];
      if (incoming && incoming.cells != null && data.val?.sections?.[name] === sec) {
        sec.cells = incoming.cells;
        delete sec._pack;
        data.val = { ...data.val, sections: { ...data.val.sections, [name]: sec } };
      }
    })();
    try {
      await sec._cellsInflight;
      if (cellLoadError.val?.section === name) cellLoadError.val = null;
    } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- the failure is reported on the tab itself, with a retry, and logged so a dead tab is diagnosable
      // oxlint-disable-next-line eslint/no-console -- keep diagnostics in the browser console
      console.error("Failed to load section cells:", name, error);
      if (data.val?.sections?.[name] === sec) {
        cellLoadError.val = { section: name, detail: error.message };
      }
    } finally { delete sec._cellsInflight; }
  };

  // Retry from the grid's failure notice.  A settled failed fetch has already
  // cleared its inflight slot, so this starts a fresh request.
  const retrySectionCells = (name) => { void ensureSectionCells(name); };

  const switchTab = (name) => {
    activeSection.val = name;
    currentFn.val = null;
    currentCellIndex.val = null;
    syncUrl();
    void ensureSectionCells(name);
  };

  const isFilterOn = (key) => key === "all" ? activeFilters.val.size === 0 : activeFilters.val.has(key);
  const FilterButton = (key, label, ariaLabel, titleText) => button({
    class: () => `btn filter-btn filter-${key} ${isFilterOn(key) ? "active" : ""}`,
    "aria-label": ariaLabel, "aria-pressed": () => isFilterOn(key), title: titleText,
    onclick: () => toggleFilter(key)
  }, label);

  van.add(document.body,
    a({ href: "#main-content", class: "skip-link" }, "Skip to main content"),
    header({ class: "topbar" },
      div({ class: "topbar-left" },
        div({ class: "title-container" },
          div({ class: "logo-r", "aria-hidden": "true" }, "R"),
          h1({ class: "title" }, "ReCoverage")
        ),
        () => {
          if (!data.val || !data.val.sections) return div({ class: "tabs" });
          return div({ class: "tabs" },
            ...sectionNames(data.val.sections).map(secName =>
              button({ class: () => `btn tab-btn ${activeSection.val === secName ? "active" : ""}`, onclick: () => switchTab(secName) }, secName)
            )
          );
        },
        ProgressBar()
      ),
      div({ class: "topbar-right" },
        div({ class: "search" },
          div({ class: "search-row" },
            input({
              type: "search", class: "input-el",
              placeholder: "Search function name or VA...",
              "aria-label": "Search functions",
              oninput: onSearchInput,
              onkeydown: onSearchKeydown
            }),
            () => searchQuery.val
              ? button({
                  class: "btn search-clear", "aria-label": "Clear search", title: "Clear search",
                  onclick: (e) => { clearSearch(document.querySelector(".search input")); e.currentTarget.blur(); }
                }, "Clear")
              : div()
          ),
          // Potato Mode prints the query, the hit count, and a clear link
          // above its grid.  The SPA dimmed cells and said nothing, so a
          // query that matched nothing looked like a broken map.
          () => searchQuery.val
            ? div({ class: "search-status", role: "status", "aria-live": "polite" },
                span(`Searching: "${searchQuery.val}"`),
                span({ class: "search-count" },
                  `(${matchedFnNames.val.size} ${matchedFnNames.val.size === 1 ? "match" : "matches"})`),
                matchedFnNames.val.size === 0
                  ? span(" - no matches. Check the spelling, or search by VA.")
                  : span(" - press Enter to jump to the first one."))
            : div()
        ),
        div({ class: "filters" },
          // aria-pressed, not just an `active` class: the pressed state is
          // otherwise carried by colour alone.
          FilterButton("all", "All", "Filter all", "Show all statuses"),
          FilterButton("exact", "E", "Filter exact", "Exact match"),
          FilterButton("reloc", "R", "Filter reloc", "Reloc match"),
          FilterButton("near_match", "M", "Filter near-match", "Near-match"),
          FilterButton("stub", "S", "Filter stub", "Stub"),
          FilterButton("padding", "P", "Filter padding", "Padding")
        ),
        div({ class: "actions" },
          () => {
            if (availableTargets.val.length > 0) {
              return van.tags.select({
                class: "input-el target-select",
                "aria-label": "Select target binary",
                onchange: (e) => {
                  const newTarget = e.target.value;
                  activeTarget.val = newTarget;

                  // Update URL without reloading
                  const url = new URL(window.location);
                  url.searchParams.set("target", newTarget);
                  window.history.pushState({}, "", url);

                  // Save to localStorage
                  localStorage.setItem("recoverage_target", newTarget);

                  // Reset UI state.  Dropping the old target's data makes
                  // loadData treat this as a first paint (overlay + errors),
                  // not a background refresh of the same map.
                  data.val = null;
                  // A query belongs to the binary it was typed for.  Keeping
                  // it would dim the whole new map against a name that does
                  // not exist there, and the status line would report it as a
                  // live, empty result.
                  clearSearch(document.querySelector(".search input"));
                  currentFn.val = null;
                  currentCellIndex.val = null;
                  cSourceText.val = MSG.SELECT_FUNCTION;
                  docText.val = MSG.SELECT_FUNCTION;
                  showBytesMessage(MSG.SELECT_FUNCTION);
                  asmText.val = MSG.ASM_PLACEHOLDER;
                  currentBuf.val = null;

                  // Load new data
                  loadData();

                  // Remove focus to hide glow
                  e.target.blur();
                }
              }, ...availableTargets.val.map(t =>
                van.tags.option({ value: t.id, selected: t.id === activeTarget.val }, t.name)
              ));
            }
            return span({ style: "display: none;" });
          },
          button({ class: "btn icon-btn", "aria-label": () => isLightMode.val ? "Switch to Dark Mode" : "Switch to Light Mode", title: () => isLightMode.val ? "Switch to Dark Mode" : "Switch to Light Mode", onclick: () => { isLightMode.val = !isLightMode.val; localStorage.setItem('recoverage_theme', isLightMode.val ? 'light' : 'dark'); } }, () => isLightMode.val ? MoonIcon() : SunIcon()),
          button({ class: "btn icon-btn", "aria-label": "Reload data", disabled: () => detailFailed.val, title: () => detailFailed.val ? MSG.DETAIL_UNAVAILABLE : "Reload", onclick: reloadData }, ReloadIcon())
        )
      )
    ),
    main({ class: "layout", id: "main-content" },
      section({ class: "map", "aria-label": "Coverage map" },
        // These bindings return an empty div rather than null when they have
        // nothing to show: a VanJS binding whose first result is null never
        // renders again, because the update path has no node to replace.
        () => emptyState.val ? div() : div({ class: "legend" }, ...LEGEND.map(([state, label]) =>
          div({ class: "key" }, span({ class: `swatch swatch-${state}` }), span(label))
        )),
        () => emptyState.val
          ? div({ class: "empty-state", role: "status" },
              h2(emptyState.val.title), p(emptyState.val.detail))
          : div(),
        Grid(),
        () => emptyState.val ? div() : SearchHint()
      ),
      () => Panel()
    ),
  );

  // The panel header sticks below the topbar, whose height changes as the
  // controls wrap.  Publish the measured height as --topbar-h.
  const topbarEl = document.querySelector('.topbar');
  if (topbarEl) {
    new ResizeObserver(([entry]) => {
      // The entry already carries the border-box height; measuring with
      // getBoundingClientRect() inside the callback forces a second layout.
      const borderBox = entry.borderBoxSize?.[0]?.blockSize;
      const h = borderBox ?? entry.target.getBoundingClientRect().height;
      document.documentElement.style.setProperty('--topbar-h', `${Math.round(h)}px`);
    }).observe(topbarEl);
  }

  // The code viewer, its focus handling, and its inert backdrop live in
  // detail.js: nothing about it is reachable until a click, long after that
  // file lands.  Mounting is deferred with it.
  van.derive(() => {
    if (detailReady.val) {
      window.RC.mountModal({ showModal, modalTitle, modalContent, modalLang, HighlightedCode });
    }
  });
};

van.add(document.body, App());
loadDetail();
})();
