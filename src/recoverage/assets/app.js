const { a, aside, button, div, header, input, main, pre, section, span, code } = van.tags;

const DATA_URL = (t) => `/api/targets/${t}/data`;
const ASM_URL = (t) => `/api/targets/${t}/asm`;
const FN_URL = (t, va) => `/api/targets/${t}/functions/${va}`;

// Debug flag - set to false in production

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
  ASM_PLACEHOLDER: "(use matcher.py --diff for disassembly)",
  DATA_SECTION_NO_ASM: "(Data section - no assembly)",
  BYTES_FAILED: "(failed to slice bytes from original DLL)",
  BYTES_BSS: "(uninitialized data - no raw bytes)",
  BYTES_LOAD_FAILED: "(original DLL not loaded)",
  GLOBAL_VAR: "Global variable",
  REGEN_USING_CACHE: (r) => `Using cached data. Regen available in ${r}s...`,
  REGEN_IN_PROGRESS: "Regenerating…",
  REGEN_UNAVAILABLE: "Regen unavailable",
  REGEN_AVAILABLE_IN: "Regen available in",
  SECONDS: "s",
  NA: "(n/a)",
  FETCH_FAILED: (url) => `(failed to load: ${url})`,
  NO_DECL: "(no declaration found)",
};

function hex(n, width) {
  return "0x" + n.toString(16).toUpperCase().padStart(width, "0");
}

function formatBytes(buf, baseOffset = 0) {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.subarray(i, i + 16);
    const offset = (baseOffset + i).toString(16).toUpperCase().padStart(8, "0");
    const hexParts = Array.from({ length: 16 }, (_, j) => j < slice.length ? slice[j].toString(16).toUpperCase().padStart(2, "0") : "  ");
    const ascii = Array.from(slice, b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".").join("");
    out += `${offset}  ${hexParts.slice(0, 8).join(" ")}  ${hexParts.slice(8, 16).join(" ")}  |${ascii}|\n`;
  }
  return out.trimEnd();
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

function computeCellClass(cell) {
  const s = cell.state;
  return "cell" + (s ? " " + (s === "matching_reloc" ? "matching" : s) : "");
}

let hljsLoaded = false;
let hljsLoadingPromise = null;

async function loadHighlightJs() {
  if (hljsLoaded) return;
  if (hljsLoadingPromise) return hljsLoadingPromise;

  let resolvePromise;
  hljsLoadingPromise = new Promise((resolve) => {
    resolvePromise = resolve;
  });

  const script = document.createElement('script');
  script.src = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.11.1/highlight.min.js';
  script.onload = () => {
    const cScript = document.createElement('script');
    cScript.src = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.11.1/languages/c.min.js';

    const asmScript = document.createElement('script');
    asmScript.src = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.11.1/languages/x86asm.min.js';

    let loadedCount = 0;
    const checkDone = () => {
      loadedCount++;
      if (loadedCount === 2) {
        initHighlighting();
        hljsLoaded = true;
        resolvePromise();
      }
    };

    cScript.onload = checkDone;
    asmScript.onload = checkDone;

    document.head.appendChild(cScript);
    document.head.appendChild(asmScript);
  };
  document.head.appendChild(script);

  return hljsLoadingPromise;
}

function initHighlighting() {
  if (!window.hljs) return;
  if (window.hljs.getLanguage && window.hljs.getLanguage("hex")) return;

  window.hljs.registerLanguage("hex", () => ({
    name: "Hex",
    contains: [
      { className: "meta", begin: /^[0-9A-Fa-f]{8}/ },
      { className: "string", begin: /\|.*\|$/ },
      { className: "number", begin: /\b[0-9A-Fa-f]{2}\b/ },
    ],
  }));
}

function extractDocs(cSourceText) {
  if (!cSourceText || cSourceText.startsWith("(no C") || cSourceText.startsWith("(failed")) {
    return null;
  }
  const lines = cSourceText.split("\n");
  const docs = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("// NOTE:") || trimmed.startsWith("// BLOCKER:") ||
      trimmed.startsWith("// FUNCTION:") || trimmed.startsWith("// STATUS:") ||
      trimmed.startsWith("// ORIGIN:") || trimmed.startsWith("// SIZE:") ||
      trimmed.startsWith("// CFLAGS:") || trimmed.startsWith("// SYMBOL:")) {
      docs.push(trimmed);
    }
  }
  return docs.length > 0 ? docs.join("\n") : null;
}


const SunIcon = () => span({ class: "icon", innerHTML: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>` });
const MoonIcon = () => span({ class: "icon", innerHTML: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>` });
const ReloadIcon = () => span({ class: "icon", innerHTML: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>` });

const HexLogo = (label, color, titleText) => div({ class: "section-title-left" },
  span({ class: "hex-logo", style: `color: ${color};`, innerHTML: `<svg viewBox="0 0 100 100" width="20" height="20"><polygon points="50,5 90,27.5 90,72.5 50,95 10,72.5 10,27.5" fill="currentColor" fill-opacity="0.15" stroke="currentColor" stroke-width="6" stroke-linejoin="round"/><text x="50" y="54" dominant-baseline="middle" text-anchor="middle" fill="currentColor" font-family="system-ui, -apple-system, sans-serif" font-weight="800" font-size="${label.length > 2 ? '26' : '42'}">${label}</text></svg>` }),
  span({ class: "section-title-text" }, titleText)
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
  const savedTheme = localStorage.getItem('recoverage_theme');
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  const isLightMode = van.state(savedTheme === 'light' || (!savedTheme && prefersLight));

  let lastRegenTime = 0;
  const REGEN_COOLDOWN_MS = 5000;

  initHighlighting();

  van.derive(() => {
    document.body.classList.toggle('light-mode', isLightMode.val);
    localStorage.setItem('recoverage_theme', isLightMode.val ? 'light' : 'dark');
  });

  const isLoading = van.state(true);

  const currentBuf = van.state(null);

  const activeTarget = van.state("");
  const availableTargets = van.state([]);

  const loadTargets = async () => {
    try {
      const res = await fetch("/api/targets");
      if (res.ok) {
        const d = await res.json();
        availableTargets.val = d.targets || [];

        // Check URL params first, then localStorage, then default
        const urlParams = new URLSearchParams(window.location.search);
        const urlTarget = urlParams.get("target");
        const savedTarget = localStorage.getItem("recoverage_target");

        if (urlTarget && availableTargets.val.some(t => t.id === urlTarget)) {
          activeTarget.val = urlTarget;
        } else if (savedTarget && availableTargets.val.some(t => t.id === savedTarget)) {
          activeTarget.val = savedTarget;
        } else {
          activeTarget.val = availableTargets.val[0].id;
        }
      }
    } catch (e) {
      console.error("Failed to load targets:", e);
      availableTargets.val = [];
      activeTarget.val = "";
    }
  };

  const loadData = async () => {
    if (!activeTarget.val) return;
    isLoading.val = true;
    try {
      const res = await fetch(DATA_URL(activeTarget.val), { cache: "no-store" });
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
            if (cell._state === "matching_reloc") cell._state = "matching";
          }
        }
      }

      data.val = d;

      if (d.sections && !d.sections[activeSection.val]) {
        const sections = Object.keys(d.sections);
        if (sections.length > 0) {
          activeSection.val = sections[0];
        }
      }

      if (d.paths && d.paths.originalDll) {
        originalDll.val = await fetchArrayBufferSafe(d.paths.originalDll);
      }

      const summary = d.summary || {};
      summaryData.val = { ...summary, textSize: d.sections[".text"]?.size || 0 };

      // Restore last visited function
      setTimeout(() => {
        const lastFn = localStorage.getItem('recoverage_last_fn_' + activeTarget.val);
        if (lastFn && data.val?.search_index?.[lastFn]) {
          const info = data.val.search_index[lastFn];
          jumpToAddress(parseInt(info.va, 16));
          setTimeout(() => selectFunction(lastFn), 50);
        } else if (lastFn) {
          selectFunction(lastFn);
        }
      }, 50);
    } catch (e) {
      loadingMsg.val = MSG.ERROR_PREFIX + e.message; summaryData.val = null;
    } finally {
      isLoading.val = false;
    }
  };

  const tryRegen = async () => {
    try {
      const res = await fetch("/regen", { method: "POST", cache: "no-store" });
      return res.ok;
    } catch (e) {
      console.error("Regen failed:", e);
      return false;
    }
  };

  const handleReload = async () => {
    const now = Date.now();
    const timeSinceLastRegen = now - lastRegenTime;
    if (timeSinceLastRegen < REGEN_COOLDOWN_MS) {
      const remaining = Math.ceil((REGEN_COOLDOWN_MS - timeSinceLastRegen) / 1000);
      loadingMsg.val = MSG.REGEN_USING_CACHE(remaining);
      await loadData();
    } else {
      lastRegenTime = now;
      loadingMsg.val = MSG.REGEN_IN_PROGRESS; summaryData.val = null;
      const ok = await tryRegen();
      if (!ok) {
        loadingMsg.val = MSG.REGEN_UNAVAILABLE;
      }
      await loadData();
    }
  };

  let searchTimeout;
  const handleSearch = (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      searchQuery.val = e.target.value;
    }, 250);
  };

  // Initialize: load targets then data (NOT in derive - that's an anti-pattern)
  loadTargets().then(() => {
    loadData();
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

  const filteredFnNames = van.derive(() => {
    if (!data.val || !data.val.search_index) return new Set();
    const query = searchQuery.val;
    if (!query) return new Set(); // Empty set means "no filter"

    const matched = new Set();
    for (const name of Object.keys(data.val.search_index)) {
      if (matchesSearch(name, query)) {
        matched.add(name);
      }
    }
    return matched;
  });

  const sliceOriginalBytes = (item) => {
    if (!originalDll.val || !data.val?.sections) return null;
    const sec = data.val.sections[activeSection.val];
    if (!sec || activeSection.val === ".bss") return null;

    const va = typeof item.va === 'string' ? parseInt(item.va, 16) : item.va;
    let start = activeSection.val === ".text" ? item.fileOffset : sec.fileOffset + (va - sec.va);
    let size = activeSection.val === ".text" ? item.size : 16;

    if (start < 0 || start + size > originalDll.val.byteLength) return null;
    return originalDll.val.slice(start, start + size);
  };

  let currentAbortController = null;

  const selectFunction = async (id) => {
    if (currentAbortController) {
      currentAbortController.abort();
    }
    currentAbortController = new AbortController();
    const signal = currentAbortController.signal;

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
        localStorage.setItem('recoverage_last_fn_' + activeTarget.val, id);

        const buf = sliceOriginalBytes(fn);
        currentBuf.val = buf;
        bytesText.val = buf ? formatBytes(buf, parseInt(fn.vaStart || fn.va, 16)) : MSG.BYTES_FAILED;

        const sourceRoot = (data.val && data.val.paths && data.val.paths.sourceRoot) ? data.val.paths.sourceRoot : `/src/${activeTarget.val.toLowerCase()}`;
        const cPath = (fn.files && fn.files[0]) ? `${sourceRoot}/${fn.files[0]}` : null;
        const va = fn.vaStart || fn.va;
        const size = fn.size;

        // Fetch C source and ASM concurrently
        const [cSourceRes, asmRes] = await Promise.allSettled([
          cPath ? fetchTextSafe(cPath) : Promise.resolve(MSG.NO_C_SOURCE),
          fetch(`${ASM_URL(activeTarget.val)}?va=${va}&size=${size}&section=${activeSection.val}`, { signal }).then(r => r.ok ? r.json() : null)
        ]);

        if (signal.aborted) return;

        const newCSource = cSourceRes.status === 'fulfilled' ? cSourceRes.value : MSG.NO_C_SOURCE;
        const newAsm = (asmRes.status === 'fulfilled' && asmRes.value && asmRes.value.asm) ? asmRes.value.asm : MSG.ASM_PLACEHOLDER;
        const newDocs = extractDocs(newCSource);

        // Update all state synchronously to trigger a single re-render
        cSourceText.val = newCSource;
        docText.val = newDocs ? newDocs : MSG.NO_DOCS;
        asmText.val = newAsm;
      } catch (e) {
        if (e.name === 'AbortError') return;
        currentFn.val = null;
        cSourceText.val = MSG.ERROR_PREFIX + e.message;
      }

    } else {
      // Global variable
      try {
        const res = await fetch(FN_URL(activeTarget.val, id), { signal });
        if (!res.ok) throw new Error("Not found");
        const g = await res.json();

        if (signal.aborted) return;
        currentFn.val = { ...g, isGlobal: true };
        localStorage.setItem('recoverage_last_fn_' + activeTarget.val, id);
        const buf = sliceOriginalBytes(g);
        currentBuf.val = buf;
        bytesText.val = buf ? formatBytes(buf, parseInt(g.va, 16)) : (activeSection.val === ".bss" ? MSG.BYTES_BSS : MSG.BYTES_FAILED);
        cSourceText.val = g.decl || MSG.NO_DECL;
        docText.val = MSG.GLOBAL_VAR;
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      } catch (e) {
        if (e.name === 'AbortError') return;
        currentFn.val = null;
        cSourceText.val = MSG.ERROR_PREFIX + e.message;
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

    if (cell.functions && cell.functions.length) {
      selectFunction(cell.functions[0]);
    } else {
      currentFn.val = null;
      cSourceText.val = MSG.NO_C_FOR_BLOCK;
      docText.val = MSG.UNDOCUMENTED_BLOCK;
      asmText.val = MSG.ASM_PLACEHOLDER;

      if (activeSection.val === ".bss") {
        currentBuf.val = null;
        bytesText.val = MSG.BYTES_BSS;
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      } else if (originalDll.val) {
        const start = sec.fileOffset + cell.start;
        const size = cell.end - cell.start;
        const end = start + size;
        if (start >= 0 && end <= originalDll.val.byteLength) {
          const buf = originalDll.val.slice(start, end);
          currentBuf.val = buf;
          bytesText.val = formatBytes(buf, sec.va + cell.start);

          if (activeSection.val === ".text") {
            // Fetch ASM for undocumented block in .text
            asmText.val = "Loading assembly...";
            fetch(`${ASM_URL(activeTarget.val)}?va=${sec.va + cell.start}&size=${size}&section=${activeSection.val}`)
              .then(r => r.ok ? r.json() : null)
              .then(asmData => {
                if (asmData && asmData.asm) {
                  asmText.val = asmData.asm;
                } else {
                  asmText.val = MSG.ASM_PLACEHOLDER;
                }
              })
              .catch(() => {
                asmText.val = MSG.ASM_PLACEHOLDER;
              });
          } else {
            asmText.val = MSG.DATA_SECTION_NO_ASM;
          }
        } else {
          bytesText.val = MSG.BYTES_FAILED;
          asmText.val = MSG.DATA_SECTION_NO_ASM;
        }
      } else {
        bytesText.val = MSG.BYTES_LOAD_FAILED;
        asmText.val = MSG.DATA_SECTION_NO_ASM;
      }
    }
  };

  const copyToClipboard = (text, e) => {
    const btn = e.currentTarget || e.target;
    const original = btn.textContent;
    const flash = (msg) => { btn.textContent = msg; setTimeout(() => btn.textContent = original, 1000); };
    if (text == null || text === undefined) { flash("Nothing"); return; }
    const str = String(text);
    if (!str) { flash("Empty"); return; }
    navigator.clipboard.writeText(str).then(() => flash("Copied!")).catch(() => flash("Failed"));
  };

  const toggleFilter = (filter) => {
    const newFilters = new Set(activeFilters.val);
    if (filter === "all") {
      newFilters.clear();
    } else {
      if (newFilters.has(filter)) {
        newFilters.delete(filter);
      } else {
        newFilters.add(filter);
      }
    }
    activeFilters.val = newFilters;
  };

  const jumpToAddress = (targetVa) => {
    if (!data.val || !data.val.sections) return;
    for (const [secName, sec] of Object.entries(data.val.sections)) {
      if (targetVa >= sec.va && targetVa < sec.va + sec.size) {
        const offset = targetVa - sec.va;
        const cells = sec.cells || [];
        for (let i = 0; i < cells.length; i++) {
          const cell = cells[i];
          if (offset >= cell.start && offset < cell.end) {
            activeSection.val = secName;
            selectChunk(i);
            requestAnimationFrame(() => {
              requestAnimationFrame(() => {
                const grid = document.getElementById(`grid-${secName.replace('.', '')}`);
                if (grid && grid.children[i]) {
                  grid.children[i].scrollIntoView({ behavior: "smooth", block: "center" });
                }
              });
            });
            return;
          }
        }
      }
    }
    console.warn("Address not found in any section:", targetVa.toString(16));
  };

  const HighlightedCode = ({ lang, text }) => {
    const codeEl = code({ class: lang ? `language-${lang}` : "" }, text);

    const doHighlight = async () => {
      if (lang) {
        await loadHighlightJs();
        codeEl.removeAttribute("data-highlighted");
        try {
          window.hljs.highlightElement(codeEl);
          if (lang === "x86asm") {
            codeEl.innerHTML = codeEl.innerHTML.replace(/(0x[0-9a-fA-F]+)/g, '<a href="#" class="asm-link" data-addr="$1">$1</a>');
          }
        } catch (_) { }
      }
    };

    setTimeout(doHighlight, 0);

    codeEl.onclick = (e) => {
      if (e.target.classList.contains("asm-link")) {
        e.preventDefault();
        const addrStr = e.target.getAttribute("data-addr");
        if (addrStr) {
          jumpToAddress(parseInt(addrStr, 16));
        }
      }
    };

    return pre({ class: "code" }, codeEl);
  };


  const ProgressBar = () => {
    return () => {
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

      let exactCount = 0, relocCount = 0, matchingCount = 0, stubCount = 0;
      let exactBytes = 0, relocBytes = 0, matchingBytes = 0, stubBytes = 0;
      let paddingBytes = 0, thunkBytes = 0;
      let totalItems = 0;
      let coveredBytes = 0;

      const s = summaryData.val[secName] || summaryData.val; // Fallback for .text if not nested
      if (s) {
        exactCount = s.exactMatches || 0;
        relocCount = s.relocMatches || 0;
        matchingCount = s.matchingMatches || 0;
        stubCount = s.stubCount || 0;
        exactBytes = s.exactBytes || 0;
        relocBytes = s.relocBytes || 0;
        matchingBytes = s.matchingBytes || 0;
        stubBytes = s.stubBytes || 0;
        paddingBytes = s.paddingBytes || 0;
        thunkBytes = s.thunkBytes || 0;
        totalItems = s.totalFunctions || 0;
        coveredBytes = s.coveredBytes || 0;
      }

      let exactPct = 0, relocPct = 0, matchingPct = 0, stubPct = 0, paddingPct = 0, thunkPct = 0;
      if (secName === ".text") {
        const total = totalItems || 1;
        exactPct = (exactCount / total) * 100;
        relocPct = (relocCount / total) * 100;
        matchingPct = (matchingCount / total) * 100;
        stubPct = (stubCount / total) * 100;
        paddingPct = sec.size > 0 ? (paddingBytes / sec.size * 100) : 0;
        thunkPct = sec.size > 0 ? (thunkBytes / sec.size * 100) : 0;
      } else {
        const total = sec.size || 1;
        exactPct = (exactBytes / total) * 100;
        relocPct = (relocBytes / total) * 100;
        matchingPct = (matchingBytes / total) * 100;
        stubPct = (stubBytes / total) * 100;
        paddingPct = (paddingBytes / total) * 100;
      }

      const coveragePct = sec.size > 0 ? (coveredBytes / sec.size * 100) : 0;

      const segments = [
        { type: "exact", pct: exactPct, count: exactCount },
        { type: "reloc", pct: relocPct, count: relocCount },
        { type: "matching", pct: matchingPct, count: matchingCount },
        { type: "stub", pct: stubPct, count: stubCount },
        { type: "padding", pct: paddingPct, count: 0 },
        { type: "thunk", pct: thunkPct, count: 0 }
      ];

      const getClasses = (type) => {
        let cls = `progress-segment ${type}`;
        return () => `${cls} ${activeFilters.val.has(type) ? "active" : ""}`;
      };

      return div({ class: "progress-container" },
        div({ class: "progress-bar" },
          div({ class: "progress-segments" },
            div({ class: getClasses("exact"), style: `width: ${exactPct}%`, title: `Exact: ${exactCount}`, onclick: () => toggleFilter("exact") }),
            div({ class: getClasses("reloc"), style: `width: ${relocPct}%`, title: `Reloc: ${relocCount}`, onclick: () => toggleFilter("reloc") }),
            div({ class: getClasses("matching"), style: `width: ${matchingPct}%`, title: `Matching: ${matchingCount}`, onclick: () => toggleFilter("matching") }),
            div({ class: getClasses("stub"), style: `width: ${stubPct}%`, title: `Stub: ${stubCount}`, onclick: () => toggleFilter("stub") }),
            div({ class: getClasses("padding"), style: `width: ${paddingPct}%`, title: `Padding: ${paddingBytes}B`, onclick: () => toggleFilter("padding") }),
            div({ class: getClasses("thunk"), style: `width: ${thunkPct}%`, title: `Thunk: ${thunkBytes}B`, onclick: () => toggleFilter("thunk") })
          ),
          div({ class: "progress-text-overlay" },
            span({ class: "stat-item" }, `${sec.size} bytes`),
            span({ class: "stat-item" }, `${exactCount + relocCount + matchingCount + stubCount} / ${totalItems} matched`),
            span({ class: "stat-item" }, `${coveragePct.toFixed(2)}% coverage`)
          )
        )
      );
    };
  };

  const Grid = () => {
    const container = div({ class: "grid-container", style: "position: relative; min-height: 400px;" });
    const grids = {}; // secName -> div element
    let ro = null;

    const resize = () => {
      const activeGrid = grids[activeSection.val];
      if (!activeGrid) return;

      const sec = data.val?.sections?.[activeSection.val];
      const columns = sec?.columns || 64;

      const styles = window.getComputedStyle(activeGrid);
      const gap = parseFloat(styles.columnGap || styles.gap || "2") || 2;
      const padL = parseFloat(styles.paddingLeft || "0") || 0;
      const padR = parseFloat(styles.paddingRight || "0") || 0;
      const usable = Math.max(0, activeGrid.clientWidth - padL - padR);
      const colW = (usable - gap * (columns - 1)) / columns;
      const px = Math.max(6, Math.floor(colW));
      activeGrid.style.gridAutoRows = `${px}px`;
    };

    ro = new ResizeObserver(resize);

    const updateCellClasses = (gridEl, secName) => {
      const sec = data.val?.sections?.[secName];
      if (!sec || !sec.cells) return;
      const cells = sec.cells;

      const query = searchQuery.val;
      const matchedNames = filteredFnNames.val;
      const activeIdx = secName === activeSection.val ? currentCellIndex.val : null;
      const activeFn = secName === activeSection.val ? activeFnName.val : "";

      const children = gridEl.children;
      const len = Math.min(children.length, cells.length);

      for (let i = 0; i < len; i++) {
        const child = children[i];
        const cell = cells[i];

        let cls = cell._baseClass;
        if (i === activeIdx || (activeFn && cell._fnName === activeFn)) cls += " active";

        if (query && cell._fnName && !matchedNames.has(cell._fnName)) {
          cls += " dimmed";
        }

        if (child.className !== cls) {
          child.className = cls;
        }
      }
    };

    van.derive(() => {
      if (isLoading.val) {
        container.innerHTML = "";
        for (const k in grids) delete grids[k];
        van.add(container, div({ class: "loading-overlay" }, "Loading coverage data..."));
        return;
      }

      if (!data.val || !data.val.sections) {
        container.innerHTML = "";
        for (const k in grids) delete grids[k];
        return;
      }

      const secName = activeSection.val;
      const sec = data.val.sections[secName];
      if (!sec) return;

      // Hide all grids
      for (const [name, el] of Object.entries(grids)) {
        el.style.display = name === secName ? "grid" : "none";
      }

      // Remove loading overlay if present
      const overlay = container.querySelector('.loading-overlay');
      if (overlay) overlay.remove();

      // Create grid if it doesn't exist
      if (!grids[secName]) {
        const gridEl = div({
          class: "grid",
          id: `grid-${secName.replace('.', '')}`,
          onmousedown: (e) => {
            const cell = e.target.closest('.cell');
            if (cell) e.preventDefault();
          },
          onclick: (e) => {
            const cell = e.target.closest('.cell');
            if (cell) {
              const idx = parseInt(cell.getAttribute('data-index'), 10);
              if (!isNaN(idx)) selectChunk(idx);
            }
          }
        });

        grids[secName] = gridEl;
        container.appendChild(gridEl);
        ro.observe(gridEl);

        const cells = sec.cells || [];

        // Show loading state for this specific grid
        gridEl.style.opacity = "0.5";

        setTimeout(() => {
          const query = searchQuery.val;
          const matchedNames = filteredFnNames.val;
          const activeIdx = currentCellIndex.val;
          const activeFn = activeFnName.val;

          let html = "";
          for (let i = 0; i < cells.length; i++) {
            const cell = cells[i];
            const style = typeof cell.span === "number" ? `grid-column: span ${cell.span};` : "";
            const secVa = sec.va || 0;
            const title = `${i}  ${hex(secVa + cell.start, 8)}..${hex(secVa + cell.end, 8)}  ${cell.functions ? cell.functions.length : 0} fn`;

            let cls = cell._baseClass;
            if (i === activeIdx || (activeFn && cell._fnName === activeFn)) cls += " active";

            if (query && cell._fnName && !matchedNames.has(cell._fnName)) {
              cls += " dimmed";
            }

            html += `<div class="${cls}" data-index="${i}" style="${style}" title="${title}"></div>`;
          }

          gridEl.innerHTML = html;
          gridEl.style.opacity = "1";
          resize();
        }, 0);
      } else {
        // Grid already exists, just resize and update classes
        resize();
        updateCellClasses(grids[secName], secName);
      }
    });

    van.derive(() => {
      // Depend on these states to trigger updates
      searchQuery.val;
      filteredFnNames.val;
      currentCellIndex.val;
      activeFnName.val;

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

  const DataInspector = (buf) => {
    if (!buf || buf.byteLength === 0) {
      return div({ class: "code", style: "padding: 14px; color: var(--muted);" }, MSG.BYTES_BSS);
    }
    const dv = new DataView(buf);
    const len = buf.byteLength;
    const safeRead = (size, readFn) => len >= size ? readFn() : "N/A";

    const items = [
      { label: "int8", val: safeRead(1, () => dv.getInt8(0)) },
      { label: "uint8", val: safeRead(1, () => dv.getUint8(0)) },
      { label: "int16", val: safeRead(2, () => dv.getInt16(0, true)) },
      { label: "uint16", val: safeRead(2, () => dv.getUint16(0, true)) },
      { label: "int32", val: safeRead(4, () => dv.getInt32(0, true)) },
      { label: "uint32", val: safeRead(4, () => { const v = dv.getUint32(0, true); return `${v} (${hex(v, 8)})`; }) },
      { label: "float32", val: safeRead(4, () => { const v = dv.getFloat32(0, true); return Number.isFinite(v) ? v.toPrecision(7) : v; }) },
      { label: "float64", val: safeRead(8, () => { const v = dv.getFloat64(0, true); return Number.isFinite(v) ? v.toPrecision(15) : v; }) },
    ];

    let str = "";
    for (let i = 0; i < Math.min(len, 64); i++) {
      const charCode = dv.getUint8(i);
      if (charCode === 0) break;
      if (charCode >= 32 && charCode <= 126) str += String.fromCharCode(charCode);
      else str += ".";
    }
    items.push({ label: "string (ascii)", val: `"${str}"`, full: true });

    return div({ class: "meta-grid", style: "margin-top: 0; background: rgba(0,0,0,0.2); padding: 10px; border-radius: 12px; border: 1px solid var(--border);" },
      ...items.map(item => div({ class: `meta-item ${item.full ? 'full-width' : ''}` },
        span({ class: "meta-label" }, item.label),
        span({ class: "meta-value" }, item.val)
      ))
    );
  };

  const Panel = () => {
    const fn = currentFn.val;
    const cellIdx = currentCellIndex.val;

    let title = "No selection";
    let metaContent = null;
    let cPath = null;

    if (fn) {
      title = fn.name;
      const sourceRoot = (data.val && data.val.paths && data.val.paths.sourceRoot) ? data.val.paths.sourceRoot : `/src/${activeTarget.val.toLowerCase()}`;
      cPath = (fn.files && fn.files[0]) ? `${sourceRoot}/${fn.files[0]}` : null;

      if (fn.isGlobal) {
        metaContent = div({ class: "meta-grid" },
          div({ class: "meta-item" }, span({ class: "meta-label" }, "VA"), a({
            href: "#",
            class: "meta-value asm-link",
            onclick: (e) => { e.preventDefault(); jumpToAddress(parseInt(fn.va)); }
          }, `0x${fn.va.toString(16).toUpperCase()}`)),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Type"), span({ class: "meta-value" }, "Global Variable")),
          fn.files && fn.files.length > 0 ? div({ class: "meta-item" }, span({ class: "meta-label" }, "Source"), span({ class: "meta-value" }, ...fn.files.map((file, i) => span(i > 0 ? ", " : "", a({ href: `${sourceRoot}/${file}`, target: "_blank", class: "source-link" }, file))))) : null
        );
      } else {
        const statusClass = fn.status ? `status-${fn.status.toLowerCase().replace('_', '-')}` : '';

        metaContent = div({ class: "meta-grid" },
          div({ class: "meta-item" }, span({ class: "meta-label" }, "VA"), a({
            href: "#",
            class: "meta-value asm-link",
            onclick: (e) => { e.preventDefault(); jumpToAddress(parseInt(fn.vaStart || fn.va)); }
          }, fn.vaStart || fn.va)),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Size"), span({ class: "meta-value" }, `${fn.size} bytes`)),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Offset"), span({ class: "meta-value" }, `0x${(fn.fileOffset || 0).toString(16).toUpperCase()}`)),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Symbol"), span({ class: "meta-value" }, fn.symbol || "(n/a)")),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Status"), span({ class: `meta-value status-badge ${statusClass}` }, fn.status || "?")),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Origin"), span({ class: "meta-value" }, fn.origin || "?")),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Compiler"), span({ class: "meta-value" }, fn.cflags || "(n/a)")),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Marker"), span({ class: "meta-value" }, fn.markerType || "?")),
          fn.ghidra_name && fn.ghidra_name !== fn.name ? div({ class: "meta-item" }, span({ class: "meta-label" }, "Ghidra"), span({ class: "meta-value" }, fn.ghidra_name)) : null,
          fn.r2_name && fn.r2_name !== fn.name ? div({ class: "meta-item" }, span({ class: "meta-label" }, "radare2"), span({ class: "meta-value" }, fn.r2_name)) : null,
          fn.is_thunk ? div({ class: "meta-item" }, span({ class: "meta-label" }, "Type"), span({ class: "meta-value" }, "IAT thunk (not reversible)")) : null,
          fn.is_export ? div({ class: "meta-item" }, span({ class: "meta-label" }, "Type"), span({ class: "meta-value" }, "Exported function")) : null,
          fn.sha256 ? div({ class: "meta-item" }, span({ class: "meta-label" }, "SHA256"), span({ class: "meta-value" }, `${fn.sha256.substring(0, 16)}...`)) : null,
          fn.files && fn.files.length > 0 ? div({ class: "meta-item" }, span({ class: "meta-label" }, "Source"), span({ class: "meta-value" }, ...fn.files.map((file, i) => span(i > 0 ? ", " : "", a({ href: `${sourceRoot}/${file}`, target: "_blank", class: "source-link" }, file))))) : null,
          docText.val && docText.val !== "(select a function)" && docText.val !== "No documentation comments in source file" ?
            div({ class: "meta-item full-width" }, span({ class: "meta-label" }, "Annotations"), pre({ class: "meta-docs" }, docText.val)) : null
        );
      }
    } else if (cellIdx !== null && data.val && data.val.sections) {
      const sec = data.val.sections[activeSection.val];
      if (sec && sec.cells) {
        const cell = sec.cells[cellIdx];
        title = cell.label ? `Block ${cellIdx}: ${cell.label}` : `Block ${cellIdx}`;
        metaContent = div({ class: "meta-grid" },
          div({ class: "meta-item" }, span({ class: "meta-label" }, "Range"), span({ class: "meta-value" }, `${hex(sec.va + cell.start, 8)}..${hex(sec.va + cell.end, 8)}`)),
          div({ class: "meta-item" }, span({ class: "meta-label" }, "State"), span({ class: "meta-value" }, cell.state || "none")),
          cell.label ? div({ class: "meta-item" }, span({ class: "meta-label" }, "Label"), span({ class: "meta-value" }, cell.label)) : null,
          cell.parent_function ? div({ class: "meta-item" }, span({ class: "meta-label" }, "Parent"), span({ class: "meta-value" }, a({ href: "#", onclick: (e) => { e.preventDefault(); selectFunction(cell.parent_function); } }, cell.parent_function))) : null
        );
      }
    }

    // Compute copyable VA: prefer fn fields, fall back to cell address range
    let copyVA = null;
    if (fn) {
      copyVA = fn.vaStart || (fn.va != null ? hex(fn.va, 8) : null);
    } else if (cellIdx !== null && data.val?.sections) {
      const sec = data.val.sections[activeSection.val];
      if (sec?.cells?.[cellIdx]) {
        const cell = sec.cells[cellIdx];
        copyVA = `${hex(sec.va + cell.start, 8)}..${hex(sec.va + cell.end, 8)}`;
      }
    }

    return aside({ class: "panel", id: "panel", style: "position: relative;" },
      () => isLoading.val ? div({ class: "loading-overlay" }, "Loading...") : null,
      div({ class: "panel-head" },
        div({ class: "panel-title" }, title),
        div({ class: "panel-actions" },
          button({ class: "btn copy-btn", "aria-label": "Copy VA", onclick: (e) => copyToClipboard(copyVA, e) }, "Copy VA"),
          button({ class: "btn copy-btn", "aria-label": "Copy Symbol", onclick: (e) => copyToClipboard(fn?.symbol, e) }, "Copy Symbol")
        ),
        div({ class: "panel-meta" }, metaContent)
      ),
      div({ class: "panel-body" },
        div({ class: "section" },
          div({ class: "section-title" },
            HexLogo("C", "#3b82f6", "C Source"),
            div({ class: "section-actions" },
              button({ class: "btn copy-btn", "aria-label": "Copy C Source", onclick: (e) => copyToClipboard(cSourceText.val, e) }, "Copy"),
              button({ class: "btn copy-btn", "aria-label": "Open C Source in Modal", onclick: () => { const label = fn ? fn.name : "Block " + cellIdx; modalTitle.val = "C Source: " + label; modalContent.val = cSourceText.val; modalLang.val = "c"; showModal.val = true; } }, "Open")
            )
          ),
          HighlightedCode({ lang: "c", text: cSourceText.val })
        ),
        activeSection.val === ".text" ?
          div({ class: "section" },
            div({ class: "section-title" },
              HexLogo("ASM", "#ef4444", "Assembly"),
              div({ class: "section-actions" },
                button({ class: "btn copy-btn", "aria-label": "Copy ASM", onclick: (e) => copyToClipboard(asmText.val, e) }, "Copy"),
                button({ class: "btn copy-btn", "aria-label": "Open ASM in Modal", onclick: () => { const label = fn ? fn.name : "Block " + cellIdx; modalTitle.val = "ASM: " + label; modalContent.val = asmText.val; modalLang.val = "x86asm"; showModal.val = true; } }, "Open")
              )
            ),
            HighlightedCode({ lang: "x86asm", text: asmText.val })
          ) :
          div({ class: "section" },
            div({ class: "section-title" },
              HexLogo("{}", "#a855f7", "Data Inspector")
            ),
            () => DataInspector(currentBuf.val)
          ),
        div({ class: "section" },
          div({ class: "section-title" },
            HexLogo("01", "#10b981", "Original Bytes"),
            div({ class: "section-actions" },
              button({ class: "btn copy-btn", "aria-label": "Copy Original Bytes", onclick: (e) => copyToClipboard(bytesText.val, e) }, "Copy"),
              button({ class: "btn copy-btn", "aria-label": "Open Original Bytes in Modal", onclick: () => { const label = fn ? fn.name : "Block " + cellIdx; modalTitle.val = "Original Bytes: " + label; modalContent.val = bytesText.val; modalLang.val = "hex"; showModal.val = true; } }, "Open")
            )
          ),
          HighlightedCode({ lang: "hex", text: bytesText.val })
        )
      )
    );
  };

  const switchTab = (name) => { activeSection.val = name; currentFn.val = null; currentCellIndex.val = null; };

  van.add(document.body,
    header({ class: "topbar layout-grid" },
      div({ class: "topbar-left" },
        div({ class: "title-container" },
          div({ class: "logo-r" }, "R"),
          div({ class: "title" }, "ReCoverage")
        ),
        () => {
          if (!data.val || !data.val.sections) return div({ class: "tabs" });
          return div({ class: "tabs" },
            ...Object.keys(data.val.sections).map(secName =>
              button({ class: () => `btn tab-btn ${activeSection.val === secName ? "active" : ""}`, onclick: () => switchTab(secName) }, secName)
            )
          );
        },
        ProgressBar()
      ),
      div({ class: "topbar-right" },
        div({ class: "search" },
          input({
            type: "text", class: "input-el",
            placeholder: "Search function name or VA...",
            "aria-label": "Search functions",
            oninput: handleSearch
          })
        ),
        div({ class: "filters" },
          button({ class: () => `btn filter-btn filter-all ${activeFilters.val.size === 0 ? "active" : ""}`, "aria-label": "Filter all", onclick: () => toggleFilter("all") }, "All"),
          button({ class: () => `btn filter-btn filter-exact ${activeFilters.val.has("exact") ? "active" : ""}`, "aria-label": "Filter exact", onclick: () => toggleFilter("exact") }, "E"),
          button({ class: () => `btn filter-btn filter-reloc ${activeFilters.val.has("reloc") ? "active" : ""}`, "aria-label": "Filter reloc", onclick: () => toggleFilter("reloc") }, "R"),
          button({ class: () => `btn filter-btn filter-matching ${activeFilters.val.has("matching") ? "active" : ""}`, "aria-label": "Filter matching", onclick: () => toggleFilter("matching") }, "M"),
          button({ class: () => `btn filter-btn filter-stub ${activeFilters.val.has("stub") ? "active" : ""}`, "aria-label": "Filter stub", onclick: () => toggleFilter("stub") }, "S"),
          button({ class: () => `btn filter-btn filter-padding ${activeFilters.val.has("padding") ? "active" : ""}`, "aria-label": "Filter padding", onclick: () => toggleFilter("padding") }, "P"),
          button({ class: () => `btn filter-btn filter-data ${activeFilters.val.has("data") ? "active" : ""}`, "aria-label": "Filter data", onclick: () => toggleFilter("data") }, "J"),
          button({ class: () => `btn filter-btn filter-thunk ${activeFilters.val.has("thunk") ? "active" : ""}`, "aria-label": "Filter thunk", onclick: () => toggleFilter("thunk") }, "T")
        ),
        div({ class: "actions" },
          () => {
            if (availableTargets.val.length > 0) {
              return van.tags.select({
                class: "input-el target-select",
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
                  bytesText.val = MSG.SELECT_FUNCTION;
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
          button({ class: "btn icon-btn", "aria-label": "Reload data", title: "Reload", onclick: handleReload }, ReloadIcon())
        )
      )
    ),
    main({ class: "layout" },
      section({ class: "map" },
        div({ class: "legend" },
          div({ class: "key" }, span({ class: "swatch swatch-none" }), span("undocumented")),
          div({ class: "key" }, span({ class: "swatch swatch-exact" }), span("exact match")),
          div({ class: "key" }, span({ class: "swatch swatch-reloc" }), span("reloc match")),
          div({ class: "key" }, span({ class: "swatch swatch-matching" }), span("near-miss")),
          div({ class: "key" }, span({ class: "swatch swatch-stub" }), span("stub")),
          div({ class: "key" }, span({ class: "swatch swatch-padding" }), span("padding")),
          div({ class: "key" }, span({ class: "swatch swatch-data" }), span("data")),
          div({ class: "key" }, span({ class: "swatch swatch-thunk" }), span("thunk"))
        ),
        Grid(),
        div({ class: "hint" }, "Click a block to view function details. Use filters to show specific statuses.")
      ),
      () => Panel()
    ),
    // Modal - always in DOM for CSS transitions
    div({
      class: () => `modal ${showModal.val ? "show" : ""}`,
      onclick: (e) => { if (e.target.classList.contains("modal")) showModal.val = false; }
    },
      div({ class: "modal-content" },
        div({ class: "modal-header" },
          span({ class: "modal-title" }, () => modalTitle.val),
          div({ class: "modal-actions" },
            button({ class: "btn copy-btn", "aria-label": "Copy Modal Content", onclick: (e) => copyToClipboard(modalContent.val, e) }, "Copy"),
            button({ class: "btn modal-close", "aria-label": "Close Modal", onclick: () => showModal.val = false }, "Close")
          )
        ),
        div({ class: "modal-body" },
          () => HighlightedCode({ lang: modalLang.val, text: modalContent.val })
        )
      )
    )
  );
};

van.add(document.body, App());
