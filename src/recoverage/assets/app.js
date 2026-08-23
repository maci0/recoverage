(() => {
const { a, aside, button, div, h1, h2, h3, header, input, main, p, pre, section, span, code } = van.tags;

const DATA_URL = (t) => `/api/targets/${t}/data`;
const ASM_URL = (t) => `/api/targets/${t}/asm`;
const FN_URL = (t, va) => `/api/targets/${t}/functions/${va}`;

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
};

function hex(n, width) {
  return `0x${n.toString(16).toUpperCase().padStart(width, "0")}`;
}

function escAttr(s) {
  return String(s).replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
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

// The hex dump and data inspector live in detail.js, which is fetched right
// after first paint so the inlined shell stays inside the initial congestion
// window.  Until it lands, panes that need it show MSG.LOADING.
const detailReady = van.state(false);
const detailFailed = van.state(false);

function loadDetail() {
  window.RC = { van, MetaItem, MSG, hex, onReady: () => { detailReady.val = true; } };
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

const KNOWN_SCHEMA = new Set(["3", "4"]);

const VALID_STATES = new Set(["exact", "reloc", "near_match", "stub", "padding", "data", "thunk", "none"]);

// Section name -> grid element id.  Every dot goes, so `.rsrc.1` and `.rsrc1`
// cannot collide the way replacing only the first one allowed.
const gridId = (secName) => `grid-${secName.replaceAll('.', '')}`;

// Legend rows: cell state -> the words used for it in the UI.
const LEGEND = [["none", "undocumented"], ["exact", "exact match"], ["reloc", "reloc match"],
  ["near_match", "near-match"], ["stub", "stub"], ["padding", "padding"]];

// Sections in PE load order (ascending VA), which puts .text first instead of
// leaving the section that carries all the work at the end of an alphabetical
// row.  Sections without a VA sort last, keeping their relative order.
const sectionNames = (s) => Object.keys(s).toSorted((a, b) => (s[a].va ?? 1e18) - (s[b].va ?? 1e18));

// The /asm endpoint answers failures with {error, detail}; showing that beats a
// generic fallback, which would blame the wrong cause.
function asmMessage(payload) {
  if (!payload) return MSG.ASM_PLACEHOLDER;
  if (payload.asm) return payload.asm;
  if (payload.error) return `(${payload.error}${payload.detail ? `: ${payload.detail}` : ""})`;
  return MSG.ASM_PLACEHOLDER;
}

function computeCellClass(cell) {
  const s = cell.state;
  if (!s || !VALID_STATES.has(s)) return "cell";
  return `cell ${s}`;
}

let hljsLoaded = false;
let hljsLoadingPromise = null;

function loadHighlightJs() {
  if (hljsLoaded) return;
  if (hljsLoadingPromise) return hljsLoadingPromise;

  if (!document.querySelector("#hljs-theme")) {
    const link = document.createElement("link");
    link.id = "hljs-theme";
    link.rel = "stylesheet";
    link.href = "/hljs.css";
    document.head.append(link);
  }

  // Served from this origin, not a CDN: reverse-engineering work routinely
  // happens on air-gapped or locked-down machines, where a CDN fetch fails
  // silently and every code pane renders unhighlighted.
  const loadScript = (src) => new Promise((resolve) => {
    const el = document.createElement("script");
    el.src = src;
    el.addEventListener("load", resolve);
    el.addEventListener("error", resolve);
    document.head.append(el);
  });

  hljsLoadingPromise = (async () => {
    await loadScript("/hljs.min.js");
    await Promise.all([loadScript("/hljs-c.min.js"), loadScript("/hljs-x86asm.min.js")]);
    window.RC.initHighlighting?.();
    hljsLoaded = true;
  })();

  return hljsLoadingPromise;
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
  const originalDll = van.state(null);
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
    const p = pendingHex.val;
    if (!p) return;
    if (detailReady.val) bytesText.val = window.RC.formatBytes(p.buf, p.base);
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

  const loadData = async () => {
    // Without this the initial isLoading=true would never be cleared and the
    // map would spin forever with nothing to load.
    if (!activeTarget.val) { isLoading.val = false; return; }
    isLoading.val = true;
    emptyState.val = null;
    try {
      // "no-cache" (not "no-store") so the server's ETag/304 path works:
      // with no-store the browser never sends If-None-Match and the whole
      // multi-MB dataset is re-transferred on every load.
      const res = await fetch(DATA_URL(activeTarget.val), { cache: "no-cache" });
      if (!res.ok) throw new Error(`failed to load data`);
      const d = await res.json();

      // Precompute cell properties for fast rendering
      if (d.sections) {
        for (const sec of Object.values(d.sections)) {
          if (!sec.cells) continue;
          for (const cell of sec.cells) {
            cell._baseClass = computeCellClass(cell);
            cell._fnName = cell.functions && cell.functions[0] ? cell.functions[0] : "";
            cell._state = cell.state || "";
          }
        }
      }

      data.val = d;

      const secNames = sectionNames(d.sections || {});
      if (secNames.length === 0) {
        const ver = String(d.db_version ?? "");
        emptyState.val = {
          title: "This target has no sections",
          detail: ver && !KNOWN_SCHEMA.has(ver)
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

      // `paths.originalDll` is optional metadata written by rebrew build-db.
      // Without a fallback the whole Original Bytes pane goes dead, so default
      // to the path the server already proxies (ui.py: /original/<file>).
      const dllPath = (d.paths && d.paths.originalDll) || `/original/${activeTarget.val.toLowerCase()}.dll`;
      originalDll.val = await fetchArrayBufferSafe(dllPath);

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
        const lastFn = URL_PARAMS.get("fn") || localStorage.getItem(`recoverage_last_fn_${activeTarget.val}`);
        if (lastFn && data.val?.search_index?.[lastFn]) {
          const info = data.val.search_index[lastFn];
          jumpToAddress(toVa(info.va));
          setTimeout(() => selectFunction(lastFn), 50);
        } else if (lastFn) {
          selectFunction(lastFn);
        }
      }, 50);
    } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- failure is shown to the user as an error panel
      loadingMsg.val = MSG.ERROR_PREFIX + error.message;
      summaryData.val = null;
      emptyState.val = { title: "Could not load coverage data", detail: error.message };
    } finally {
      isLoading.val = false;
    }
  };

  // The regen handler lives in detail.js: it only runs on a Reload click, long
  // after that file lands.  It gets the two states it writes plus the reloader.
  const reloadData = () => window.RC.reloadData?.({ loadingMsg, summaryData, loadData, MSG });

  let searchTimeout = null;
  const onSearchInput = (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      searchQuery.val = e.target.value;
      syncUrl();
    }, 250);
  };

  // Deep-linking: keep target/function/section/search in the URL so reloads
  // restore state and links are shareable.  replaceState (not pushState) so
  // the URL tracks state without spamming history.
  const URL_PARAMS = new URLSearchParams(window.location.search);
  const syncUrl = () => {
    const p = new URLSearchParams();
    if (activeTarget.val) p.set("target", activeTarget.val);
    if (currentFn.val && (currentFn.val.name || currentFn.val.vaStart)) {
      p.set("fn", currentFn.val.name || currentFn.val.vaStart);
    }
    if (activeSection.val) p.set("section", activeSection.val);
    if (searchQuery.val) p.set("q", searchQuery.val);
    const qs = p.toString();
    history.replaceState(null, "", qs ? `?${qs}` : window.location.pathname);
  };

  // Initialize: load targets then data (NOT in derive - that's an anti-pattern)
  (async () => {
    await loadTargets();
    loadData();
  })();

  // Live-reload: refresh the grid when coverage.db changes on disk.  The
  // subscription lives in detail.js, so it starts once that lands rather than
  // competing with first paint.
  van.derive(() => { if (detailReady.val) window.RC.connectEvents(() => loadData()); });

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

  const filteredFnNames = van.derive(() => {
    if (!data.val || !data.val.search_index) return new Set();
    const query = searchQuery.val;
    if (!query) return new Set(); // Empty set means "no filter"

    const matched = new Set();
    for (const [name, info] of Object.entries(data.val.search_index)) {
      if (matchesSearch(name, query) || (info && matchesSearch(info.va || "", query))) {
        matched.add(name);
        // Grid .text cells store the function's vaStart string (not the
        // name) in cell.functions / _fnName — the dimming test compares
        // against this set, so VA spellings must be included too.
        if (info && info.va) matched.add(info.va);
      }
    }
    return matched;
  });

  const sliceOriginalBytes = (cell) => {
    if (!originalDll.val || !data.val?.sections) return null;
    const sec = data.val.sections[activeSection.val];
    if (!sec || activeSection.val === ".bss") return null;

    const va = toVa(cell.va);
    const start = activeSection.val === ".text" ? cell.fileOffset : sec.fileOffset + (va - sec.va);
    const size = activeSection.val === ".text" ? cell.size : 16;

    if (start < 0 || start + size > originalDll.val.byteLength) return null;
    return originalDll.val.slice(start, start + size);
  };

  let currentAbortController = null;

  const selectFunction = async (id) => {
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
        else showBytesMessage(originalDll.val ? MSG.BYTES_FAILED : MSG.BYTES_LOAD_FAILED);

        const sourceRoot = (data.val && data.val.paths && data.val.paths.sourceRoot) ? data.val.paths.sourceRoot : `/src/${activeTarget.val.toLowerCase()}`;
        const cPath = (fn.files && fn.files[0]) ? `${sourceRoot}/${fn.files[0]}` : null;
        const va = fn.vaStart || fn.va;
        const { size } = fn;

        // Fetch C source and ASM concurrently
        const [cSourceRes, asmRes] = await Promise.allSettled([
          cPath ? fetchTextSafe(cPath) : Promise.resolve(MSG.NO_C_SOURCE),
          fetch(`${ASM_URL(activeTarget.val)}?va=${va}&size=${size}&section=${activeSection.val}`, { signal }).then(r => r.json()).catch(() => null)
        ]);

        if (signal.aborted) return;

        const newCSource = cSourceRes.status === 'fulfilled' ? cSourceRes.value : MSG.NO_C_SOURCE;
        const newAsm = asmRes.status === 'fulfilled' ? asmMessage(asmRes.value) : MSG.ASM_PLACEHOLDER;
        const newDocs = window.RC.extractDocs ? window.RC.extractDocs(newCSource) : null;

        // Update all state synchronously to trigger a single re-render
        cSourceText.val = newCSource;
        docText.val = newDocs || MSG.NO_DOCS;
        asmText.val = newAsm;
      } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- AbortError is a cancellation; other failures become error text
        if (error.name === 'AbortError') return;
        currentFn.val = null;
        cSourceText.val = MSG.ERROR_PREFIX + error.message;
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
        else showBytesMessage(originalDll.val ? MSG.BYTES_FAILED : MSG.BYTES_LOAD_FAILED);
        cSourceText.val = g.decl || MSG.NO_DECL;
        docText.val = MSG.GLOBAL_VAR;
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- AbortError is a cancellation; other failures become error text
        if (error.name === 'AbortError') return;
        currentFn.val = null;
        cSourceText.val = MSG.ERROR_PREFIX + error.message;
      }
    }
  };

  const selectChunk = (i) => {
    currentCellIndex.val = i;
    if (!data.val || !data.val.sections) return;
    const sec = data.val.sections[activeSection.val];
    if (!sec) return;

    const cells = sec.cells || [];
    const cell = cells[i];
    if (!cell) return;

    activeFnName.val = cell._fnName || "";

    if (cell.functions && cell.functions.length > 0) {
      selectFunction(cell.functions[0]);
    } else {
      currentFn.val = null;
      cSourceText.val = MSG.NO_C_FOR_BLOCK;
      docText.val = MSG.UNDOCUMENTED_BLOCK;
      asmText.val = MSG.ASM_PLACEHOLDER;

      if (activeSection.val === ".bss") {
        currentBuf.val = null;
        showBytesMessage(MSG.BYTES_BSS);
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      } else if (originalDll.val) {
        const start = sec.fileOffset + cell.start;
        const size = cell.end - cell.start;
        const end = start + size;
        if (start >= 0 && end <= originalDll.val.byteLength) {
          const buf = originalDll.val.slice(start, end);
          currentBuf.val = buf;
          showBytes(buf, sec.va + cell.start);

          if (activeSection.val === ".text") {
            // Fetch ASM for undocumented block in .text
            asmText.val = "Loading assembly...";
            fetch(`${ASM_URL(activeTarget.val)}?va=${sec.va + cell.start}&size=${size}&section=${activeSection.val}`)
              .then(r => r.json())
              .then(asmData => { asmText.val = asmMessage(asmData); })
              .catch(() => { asmText.val = MSG.ASM_PLACEHOLDER; });
          } else {
            asmText.val = MSG.DATA_SECTION_NO_ASM;
          }
        } else {
          showBytesMessage(MSG.BYTES_FAILED);
          asmText.val = MSG.DATA_SECTION_NO_ASM;
        }
      } else {
        showBytesMessage(MSG.BYTES_LOAD_FAILED);
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      }
    }
  };

  // Copy, Open, and Reload all delegate to detail.js.  If that file never
  // arrives they would look enabled and do nothing at all, so they go disabled
  // and say why — the panes it owns already report the same failure.
  const detailBound = () => ({
    disabled: () => detailFailed.val,
    title: () => detailFailed.val ? MSG.DETAIL_UNAVAILABLE : "",
  });

  const copyToClipboard = (text, e) => window.RC.copyToClipboard?.(text, e);

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
          if (grid && grid.children[cellIndex]) {
            grid.children[cellIndex].scrollIntoView({ behavior: "smooth", block: "center" });
          }
        });
      });
    };
    for (const [secName, sec] of Object.entries(data.val.sections)) {
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- API section rows carry number|null va/size (.bss has no base address); shape-check before the range math
      if (typeof sec.va !== "number" || typeof sec.size !== "number") continue;
      if (targetVa >= sec.va && targetVa < sec.va + sec.size) {
        const offset = targetVa - sec.va;
        const cells = sec.cells || [];
        for (let i = 0; i < cells.length; i += 1) {
          const cell = cells[i];
          if (offset >= cell.start && offset < cell.end) {
            activeSection.val = secName;
            selectChunk(i);
            focusCellAfterPaint(secName, i);
            return;
          }
        }
      }
    }
    // oxlint-disable-next-line eslint/no-console -- an address outside every section deserves a console warning
    console.warn("Address not found in any section:", targetVa.toString(16));
  };

  const HighlightedCode = ({ lang, text }) => {
    const codeEl = code({ class: lang ? `language-${lang}` : "" }, text);

    const highlightCode = async () => {
      if (lang) {
        await loadHighlightJs();
        delete codeEl.dataset.highlighted;
        try {
          window.hljs.highlightElement(codeEl);
          if (lang === "x86asm") {
            codeEl.innerHTML = codeEl.innerHTML.replaceAll(/(?<addr>0x[0-9a-fA-F]+)/gu, '<a href="#" class="asm-link" data-addr="$<addr>">$<addr></a>');
          }
        } catch { /* highlight failures are cosmetic; the pane keeps plain text */ } // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- highlight failures are cosmetic; plain text remains
      }
    };

    setTimeout(() => { highlightCode(); }, 0);

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
          div({ class: "progress-bar" },
            div({ class: "progress-text-overlay", style: "justify-content: center;" },
              span({ class: "stat-item" }, "Loading...")
            )
          )
        );
      }

      if (!data.val || !data.val.sections || !summaryData.val) {
        return div({ class: "progress-container" },
          div({ class: "progress-bar" },
            div({ class: "progress-text-overlay", style: "justify-content: center;" },
              span({ class: "stat-item" }, loadingMsg.val)
            )
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
        div({ class: "progress-bar" },
          div({ class: "progress-segments" },
            Segment("exact", exactPct, "Toggle exact filter", `Exact: ${exactCount}`),
            Segment("reloc", relocPct, "Toggle reloc filter", `Reloc: ${relocCount}`),
            Segment("near_match", nearMatchPct, "Toggle near-match filter", `Near-match: ${nearMatchCount}`),
            Segment("stub", stubPct, "Toggle stub filter", `Stub: ${stubCount}`),
            Segment("padding", paddingPct, "Toggle padding filter", `Padding: ${paddingBytes}B`)
          ),
          div({ class: "progress-text-overlay" },
            span({ class: "stat-item" }, `${sec.size} bytes`),
            span({ class: "stat-item" }, `${exactCount + relocCount + nearMatchCount + stubCount} / ${totalItems} matched`),
            span({ class: "stat-item" }, `${coveragePct.toFixed(2)}% coverage`)
          )
        )
      );
    };
  };

  const Grid = () => {
    const container = div({ class: "grid-container", style: "position: relative; min-height: 400px;" });
    const grids = {}; // secName -> div element
    const focusIdx = {}; // secName -> index of the cell holding tabindex="0"
    const selectedEl = {}; // secName -> element currently aria-selected
    let ro = null;

    // Roving tabindex: exactly one cell per grid is in the tab order, and the
    // arrow keys move both focus and that tab stop.  Without it the grid is
    // unreachable by keyboard entirely (WCAG 2.1.1) — thousands of cells each
    // carrying tabindex="0" would be the other, unusable, extreme.
    const setRoving = (gridEl, secName, to, alsoFocus) => {
      const next = gridEl.children[to];
      if (!next) return;
      const cur = gridEl.children[focusIdx[secName] ?? 0];
      if (cur) cur.setAttribute("tabindex", "-1");
      next.setAttribute("tabindex", "0");
      focusIdx[secName] = to;
      if (alsoFocus) next.focus();
    };
    const moveFocus = (gridEl, secName, to) => setRoving(gridEl, secName, to, true);

    // Address jumps (VA links, asm operands) move the selection, so the tab
    // stop has to follow or the keyboard position and the panel disagree.
    // Actual focus only moves when the user was already in the grid, so
    // clicking a link does not yank focus away from where they were reading.
    gridFocus = (secName, idx) => {
      const gridEl = grids[secName];
      if (gridEl) setRoving(gridEl, secName, idx, gridEl.contains(document.activeElement));
    };

    // The column count is resolved once, when a grid is built, and stored on
    // the element as --cols.  The CSS track count, the square-cell row height
    // below, and the arrow keys all read it from there, so they cannot drift
    // apart the way three separate `sec.columns || 64` defaults did.
    const colsOf = (gridEl) => Number(gridEl.style.getPropertyValue("--cols")) || Number(gridEl.dataset.cols) || 64;

    // The declared column count is a desktop figure: at 64 columns a 352px
    // phone renders 2.8px cells, unreadable and untappable.  Below the same
    // 700px breakpoint the stylesheet uses, the grid drops columns and grows
    // taller so cells stay square and touch-sized; wider than that the section
    // keeps every column it declares.
    const minCellPx = () => (window.innerWidth < 700 ? 12 : 6);

    const resize = () => {
      const activeGrid = grids[activeSection.val];
      if (!activeGrid) return;

      const styles = window.getComputedStyle(activeGrid);
      const gap = Number.parseFloat(styles.columnGap || styles.gap || "2") || 2;
      const padL = Number.parseFloat(styles.paddingLeft || "0") || 0;
      const padR = Number.parseFloat(styles.paddingRight || "0") || 0;
      const usable = Math.max(0, activeGrid.clientWidth - padL - padR);

      // Widest column count whose cells still clear MIN_CELL_PX, capped at the
      // section's own value so a wide viewport never invents extra columns.
      const min = minCellPx();
      const declared = Number(activeGrid.dataset.cols) || 64;
      const fits = Math.floor((usable + gap) / (min + gap));
      const columns = Math.max(1, Math.min(declared, fits));
      const colW = (usable - gap * (columns - 1)) / columns;
      activeGrid.style.setProperty("--cols", columns);
      activeGrid.style.gridAutoRows = `${Math.max(min, Math.floor(colW))}px`;
    };

    ro = new ResizeObserver(resize);

    const updateCellClasses = (gridEl, secName) => {
      const sec = data.val?.sections?.[secName];
      if (!sec || !sec.cells) return;
      const {cells} = sec;

      const query = searchQuery.val;
      const matchedNames = filteredFnNames.val;
      const activeIdx = secName === activeSection.val ? currentCellIndex.val : null;
      const activeFn = secName === activeSection.val ? activeFnName.val : "";

      const {children} = gridEl;
      const len = Math.min(children.length, cells.length);

      for (let i = 0; i < len; i += 1) {
        const child = children[i];
        const cell = cells[i];

        let cls = cell._baseClass;
        if (i === activeIdx || (activeFn && cell._fnName === activeFn)) cls += " active";

        if (query && !matchedNames.has(cell._fnName)) {
          cls += " dimmed";
        }

        if (child.className !== cls) {
          child.className = cls;
        }
      }

      // aria-selected tracks the single selected option; touching only the old
      // and new elements keeps this off the hot path over thousands of cells.
      const prev = selectedEl[secName];
      const next = activeIdx !== null && activeIdx !== undefined ? children[activeIdx] : null;
      if (prev !== next) {
        if (prev) prev.setAttribute("aria-selected", "false");
        if (next) next.setAttribute("aria-selected", "true");
        selectedEl[secName] = next;
      }
    };

    van.derive(() => {
      // A reload (button or SSE db-updated) drops every cached grid, so the
      // per-section focus index and the selected-cell reference have to go with
      // them: otherwise they keep pointing into detached DOM.
      const dropGrids = () => {
        container.innerHTML = "";
        for (const k of Object.keys(grids)) { delete grids[k]; delete focusIdx[k]; delete selectedEl[k]; }
      };

      if (isLoading.val) {
        dropGrids();
        van.add(container, div({ class: "loading-overlay", role: "status", "aria-live": "polite" }, "Loading coverage data..."));
        return;
      }

      if (emptyState.val || !data.val || !data.val.sections) {
        dropGrids();
        return;
      }

      const secName = activeSection.val;
      const sec = data.val.sections[secName];

      // Overlay comes down first: returning above it left "Loading coverage
      // data..." on screen after loading had finished.
      const overlay = container.querySelector('.loading-overlay');
      if (overlay) overlay.remove();
      if (!sec) return;

      // Hide all grids
      for (const [name, el] of Object.entries(grids)) {
        el.style.display = name === secName ? "grid" : "none";
      }

      // Create grid if it doesn't exist
      if (grids[secName]) {
        // Grid already exists, just resize and update classes
        resize();
        updateCellClasses(grids[secName], secName);
      } else {
        const gridEl = div({
          class: "grid",
          id: gridId(secName),
          "data-cols": sec.columns || 64,
          role: "listbox",
          "aria-label": `${secName} coverage map`,
          onmousedown: (e) => {
            const cell = e.target.closest('.cell');
            if (cell) e.preventDefault();
          },
          onclick: (e) => {
            const cell = e.target.closest('.cell');
            if (cell) {
              const idx = Number.parseInt(cell.dataset.index, 10);
              if (!Number.isNaN(idx)) { selectChunk(idx); moveFocus(gridEl, secName, idx); }
            }
          },
          onkeydown: (e) => {
            // Enter/Space selects; arrows move by one cell horizontally and by
            // a full row vertically; Home/End jump to the ends of the section.
            const cell = e.target.closest('.cell');
            if (!cell || e.ctrlKey || e.metaKey || e.altKey) return;
            const idx = Number.parseInt(cell.dataset.index, 10);
            if (Number.isNaN(idx)) return;
            const cols = colsOf(gridEl);
            const last = gridEl.children.length - 1;
            const clamp = (n) => Math.max(0, Math.min(last, n));
            const step = {
              ArrowRight: idx + 1, ArrowLeft: idx - 1,
              ArrowDown: idx + cols, ArrowUp: idx - cols,
              Home: 0, End: last,
            }[e.key];
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              selectChunk(idx);
            } else if (step !== undefined) {
              e.preventDefault();
              moveFocus(gridEl, secName, clamp(step));
            }
          }
        });

        grids[secName] = gridEl;
        container.append(gridEl);
        ro.observe(gridEl);

        const cells = sec.cells || [];

        // Show loading state for this specific grid
        gridEl.style.opacity = "0.5";

        setTimeout(() => {
          const query = searchQuery.val;
          const matchedNames = filteredFnNames.val;
          const activeIdx = currentCellIndex.val;
          const activeFn = activeFnName.val;
          const roving = Math.max(0, Math.min(cells.length - 1, focusIdx[secName] ?? activeIdx ?? 0));
          focusIdx[secName] = roving;

          let html = "";
          for (let i = 0; i < cells.length; i += 1) {
            const cell = cells[i];
            // oxlint-disable-next-line anti-slop/no-runtime-typeof -- span is a number when a cell spans grid columns; shape-check when rendering
            const style = typeof cell.span === "number" ? `grid-column: span ${cell.span};` : "";
            const secVa = sec.va || 0;
            const title = `${i}  ${hex(secVa + cell.start, 8)}..${hex(secVa + cell.end, 8)}  ${cell.functions ? cell.functions.length : 0} fn`;

            let cls = cell._baseClass;
            if (i === activeIdx || (activeFn && cell._fnName === activeFn)) cls += " active";

            if (query && !matchedNames.has(cell._fnName)) {
              cls += " dimmed";
            }

            // Exactly one cell carries tabindex="0" (the roving tab stop);
            // the rest are reachable from it with the arrow keys.
            const label = cell._fnName ? `${cell._fnName} at ${title}` : title;
            const tab = i === roving ? "0" : "-1";
            html += `<div class="${escAttr(cls)}" data-index="${i}" role="option" aria-selected="${i === activeIdx}" tabindex="${tab}" aria-label="${escAttr(label)}" style="${style}" title="${escAttr(title)}"></div>`;
          }

          gridEl.innerHTML = html;
          gridEl.style.opacity = "1";
          resize();
        }, 0);
      }
    });

    van.derive(() => {
      // Depend on these states to trigger updates — the bare .val read is a
      // VanJS idiom: it subscribes this derive to the state without using it.
      // oxlint-disable no-unused-expressions -- bare .val reads subscribe this derive to state
      searchQuery.val;
      filteredFnNames.val;
      currentCellIndex.val;
      activeFnName.val;
      // oxlint-enable no-unused-expressions

      const activeGrid = grids[activeSection.val];
      if (activeGrid && activeGrid.children.length > 0 && activeGrid.children[0].classList.contains('cell')) {
        updateCellClasses(activeGrid, activeSection.val);
      }
    });

    van.derive(() => {
      // Handle CSS-based filtering
      const filters = activeFilters.val;
      let cls = "grid";
      if (filters.size > 0) {
        cls += " has-filters";
        for (const f of filters) {
          cls += ` show-${f}`;
        }
      }

      // Apply to all cached grids
      for (const gridEl of Object.values(grids)) {
        gridEl.className = cls;
      }
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
      const sourceRoot = (data.val && data.val.paths && data.val.paths.sourceRoot) ? data.val.paths.sourceRoot : `/src/${activeTarget.val.toLowerCase()}`;

      const SourceItem = () => fn.files && fn.files.length > 0
        ? MetaItem("Source", span({ class: "meta-value" }, ...fn.files.map((file, i) =>
            span(i > 0 ? ", " : "", a({ href: `${sourceRoot}/${file}`, target: "_blank", rel: "noopener noreferrer", class: "source-link" }, file)))))
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
          MetaItem("Range", `${hex(secVa + cell.start, 8)}..${hex(secVa + cell.end, 8)}`),
          MetaItem("State", cell.state || "none"),
          cell.label ? MetaItem("Label", cell.label) : null,
          cell.parent_function ? MetaItem("Parent", span({ class: "meta-value" },
            a({ href: "#", onclick: (e) => { e.preventDefault(); selectFunction(cell.parent_function); } }, cell.parent_function))) : null
        );
      }
    }

    // C Source, Assembly, and Original Bytes are the same panel section with a
    // different logo, language, and body: title row, Copy, Open-in-modal.
    const CodeSection = (logo, color, heading, lang, text) => div({ class: "section" },
      div({ class: "section-title" },
        HexLogo(logo, color, heading),
        div({ class: "section-actions" },
          button({ class: "btn copy-btn", "aria-label": `Copy ${heading}`, ...detailBound(), onclick: (e) => copyToClipboard(text, e) }, "Copy"),
          button({
            class: "btn copy-btn", "aria-label": `Open ${heading} in a larger view`, ...detailBound(),
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

    // Compute copyable VA: prefer fn fields, fall back to cell address range
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
          button({ class: "btn copy-btn", "aria-label": "Copy VA", ...detailBound(), onclick: (e) => copyToClipboard(copyVA, e) }, "Copy VA"),
          button({ class: "btn copy-btn", "aria-label": "Copy Symbol", ...detailBound(), onclick: (e) => copyToClipboard(fn?.symbol, e) }, "Copy Symbol")
        ),
        div({ class: "panel-meta" }, metaContent)
      ),
      div({ class: "panel-body" },
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
      )
    );
  };

  const switchTab = (name) => { activeSection.val = name; currentFn.val = null; currentCellIndex.val = null; syncUrl(); };

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
          input({
            type: "search", class: "input-el",
            placeholder: "Search function name or VA...",
            "aria-label": "Search functions",
            oninput: onSearchInput
          })
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

                  // Reset UI state
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
        () => emptyState.val ? div() : div({ class: "hint" }, "Click a block to view function details. Use filters to show specific statuses.")
      ),
      () => Panel()
    ),
  );

  // The panel header sticks below the topbar, whose height changes as the
  // controls wrap.  Publish the measured height as --topbar-h.
  const topbarEl = document.querySelector('.topbar');
  if (topbarEl) {
    new ResizeObserver(([entry]) => {
      const h = entry.target.getBoundingClientRect().height;
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
