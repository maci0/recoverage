// Deferred SPA work kept out of the inlined index payload (TCP congestion window):
// hex dump, data inspector, the function metadata grid, and the canvas
// coverage map.  app.js publishes what this file needs on window.RC and reads
// the results back from it.
(() => {
  const { MetaItem, MSG, hex, encPath } = window.RC;
  const { a, canvas, div, button, h3, pre, p, span } = van.tags;

  const formatBytes = (buf, baseOffset = 0) => {
    const bytes = new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.subarray(i, i + 16);
      const offset = (baseOffset + i).toString(16).toUpperCase().padStart(8, "0");
      const hexParts = Array.from({ length: 16 }, (_, j) => j < slice.length ? slice[j].toString(16).toUpperCase().padStart(2, "0") : "  ");
      const ascii = Array.from(slice, b => (b >= 32 && b <= 126) ? String.fromCodePoint(b) : ".").join("");
      out += `${offset}  ${hexParts.slice(0, 8).join(" ")}  ${hexParts.slice(8, 16).join(" ")}  |${ascii}|\n`;
    }
    return out.trimEnd();
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
    for (let i = 0; i < Math.min(len, 64); i += 1) {
      const charCode = dv.getUint8(i);
      if (charCode === 0) break;
      str += (charCode >= 32 && charCode <= 126) ? String.fromCodePoint(charCode) : ".";
    }
    items.push({ label: "string (ascii)", val: `"${str}"`, full: true });

    return div({ class: "meta-grid inspector-grid" },
      ...items.map(item => MetaItem(item.label, String(item.val), item.full ? "full-width" : ""))
    );
  };

  const extractDocs = (cSourceText) => {
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

  // The custom hex language for the byte dump: registered on the hljs instance
  // once its bundles land, which is always after this file.
  const initHighlighting = () => {
    if (!window.hljs) return;
    if (window.hljs.getLanguage && window.hljs.getLanguage("hex")) return;
    window.hljs.registerLanguage("hex", () => ({
      name: "Hex",
      contains: [
        { className: "meta", begin: /^[0-9A-Fa-f]{8}/u },
        { className: "string", begin: /\|.*\|$/u },
        { className: "number", begin: /\b[0-9A-Fa-f]{2}\b/u },
      ],
    }));
  };

  // Highlight.js, the /asm formatting, and the code-pane highlighting live
  // here rather than in app.js: none of them is needed to paint the first
  // frame, and the inlined shell has to fit the initial TCP congestion window.
  // app.js keeps the pane and its text; it calls in for both.
  let hljsLoaded = false;
  let hljsLoadingPromise = null;

  // A failed chunk must not be silent: the pane would sit on plain text with
  // no hint that the highlighter is missing, and (before this reset) no retry
  // either, because a resolved promise was cached as success for the session.
  // Drop the memo on failure so the next pane opened tries again.
  const loadHighlightJs = async () => {
    if (hljsLoaded) return true;
    if (!hljsLoadingPromise) {
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
      const loadScript = (src) => new Promise((resolve, reject) => {
        const el = document.createElement("script");
        el.src = src;
        el.addEventListener("load", resolve);
        el.addEventListener("error", () => reject(new Error(`failed to load ${src}`)));
        document.head.append(el);
      });

      hljsLoadingPromise = (async () => {
        await loadScript("/hljs.min.js");
        await Promise.all([loadScript("/hljs-c.min.js"), loadScript("/hljs-x86asm.min.js")]);
        initHighlighting();
        hljsLoaded = true;
      })();
      hljsLoadingPromise.catch(() => { hljsLoadingPromise = null; });
    }
    let failed = false;
    try {
      await hljsLoadingPromise;
    } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- "failed" is the contract, not a swallow: the caller renders MSG.HIGHLIGHT_UNAVAILABLE and the memo above is cleared so the next pane retries
      failed = true;
      // oxlint-disable-next-line eslint/no-console -- a chunk that never arrived is worth a console trace alongside the in-pane notice
      console.warn("recoverage: highlight.js failed to load", error);
    }
    return !failed && window.hljs != null;
  };

  const highlightInto = async (codeEl, lang) => {
    if (!lang) return;
    if (!await loadHighlightJs()) {
      // Say so instead of dropping the reader into unhighlighted text with no
      // explanation; the disassembly itself is left intact.
      codeEl.dataset.highlightState = "unavailable";
      codeEl.dataset.highlightNote = MSG.HIGHLIGHT_UNAVAILABLE;
      codeEl.title = MSG.HIGHLIGHT_UNAVAILABLE;
      return;
    }
    delete codeEl.dataset.highlighted;
    try {
      window.hljs.highlightElement(codeEl);
      if (lang === "x86asm") {
        codeEl.innerHTML = codeEl.innerHTML.replaceAll(/(?<addr>0x[0-9a-fA-F]+)/gu, '<a href="#" class="asm-link" data-addr="$<addr>">$<addr></a>');
      }
    } catch { /* highlight failures are cosmetic; the pane keeps plain text */ } // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- highlight failures are cosmetic; plain text remains
  };

  // The /asm endpoint answers failures with {error, detail}; showing that beats a
  // generic fallback, which would blame the wrong cause.
  const asmMessage = (payload) => {
    if (!payload) return MSG.ASM_PLACEHOLDER;
    if (payload.asm) return payload.asm;
    if (payload.error) return `(${payload.error}${payload.detail ? `: ${payload.detail}` : ""})`;
    return MSG.ASM_PLACEHOLDER;
  };

  // Fetch disassembly for the current selection and hand the text back through
  // *set*: the pane's state belongs to app.js.  An aborted request (a newer
  // selection superseded this one) writes nothing.
  const loadAsm = ({ url, set, signal }) => {
    if (!url) return;
    fetch(url, { signal })
      .then((r) => r.json())
      .then((data) => { if (!signal?.aborted) set(asmMessage(data)); })
      .catch(() => { if (!signal?.aborted) set(MSG.ASM_PLACEHOLDER); });
  };

  // Live reload via Server-Sent Events: subscribes to /api/events, where a
  // db-updated event (coverage.db rewritten by rebrew build-db) triggers a grid
  // refresh.  EventSource reconnects on its own, so stream drops self-heal.
  let eventsDebounceTimer = null;
  const connectEvents = (onDbUpdated) => {
    const es = new EventSource("/api/events");
    es.addEventListener("db-updated", () => {
      // Coalesce bursts — build-db may rewrite the DB in stages.
      clearTimeout(eventsDebounceTimer);
      eventsDebounceTimer = setTimeout(onDbUpdated, 300);
    });
    return () => es.close();
  };

  // Reload button: regenerate the DB (rate-limited) then refetch.  The cooldown
  // state lives here because this is the only thing that touches it.
  const REGEN_COOLDOWN_MS = 5000;
  const REGEN_NOTICE_MS = 4000;
  // null, not 0: performance.now() counts from page load, so a first Reload
  // clicked within the cooldown of loading the page would read as a click
  // inside the window and silently skip the regen.
  let lastRegenTime = null;
  let noticeTimer = null;
  // A message set while a good map is on screen replaces the stats row, so it
  // has to time itself out; the "Regenerating…" state does not, because
  // summaryData is null for its whole duration and the map is loading anyway.
  const showNotice = (loadingMsg, message, MSG_MESSAGES) => {
    loadingMsg.val = message;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => { loadingMsg.val = MSG_MESSAGES.LOADING; }, REGEN_NOTICE_MS);
  };
  const reloadData = async ({ loadingMsg, summaryData, loadData, MSG: messages }) => {
    // performance.now() is monotonic: a wall-clock step (NTP correction,
    // manual change) between clicks would make the Date.now() delta negative
    // and lock regen out until real time caught back up.
    const now = performance.now();
    const since = lastRegenTime === null ? Infinity : now - lastRegenTime;
    if (since < REGEN_COOLDOWN_MS) {
      showNotice(loadingMsg, messages.REGEN_USING_CACHE(Math.ceil((REGEN_COOLDOWN_MS - since) / 1000)), messages);
      await loadData();
      return;
    }
    lastRegenTime = now;
    loadingMsg.val = messages.REGEN_IN_PROGRESS;
    summaryData.val = null;
    let ok = false;
    try {
      // One key per click: a request the browser or a proxy replays, or a
      // response that never arrives, re-sends the same key and is answered
      // from the server's ledger instead of regenerating a second time.
      // randomUUID needs a secure context, which a plain-HTTP LAN visit is not.
      const key = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const { ok: regenOk } = await fetch("/api/regen", { method: "POST", cache: "no-store", headers: { "Idempotency-Key": key } });
      ok = regenOk;
    } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- regen failure is reported to the user via REGEN_UNAVAILABLE
      // oxlint-disable-next-line eslint/no-console -- keep diagnostics in the browser console
      console.error("Regen failed:", error);
    }
    if (ok) {
      clearTimeout(noticeTimer);
      loadingMsg.val = messages.LOADING;
    } else {
      showNotice(loadingMsg, messages.REGEN_UNAVAILABLE, messages);
    }
    await loadData();
  };

  // Copy buttons: flash the outcome on the button itself, then restore it.
  const copyToClipboard = (text, e) => {
    const btn = e.currentTarget || e.target;
    const original = btn.textContent;
    const flash = (msg) => { btn.textContent = msg; setTimeout(() => { btn.textContent = original; }, 1000); };
    const str = text == null ? "" : String(text);
    if (!str) { flash(text == null ? "Nothing" : "Empty"); return; }
    navigator.clipboard.writeText(str).then(() => flash("Copied!")).catch(() => flash("Failed"));
  };

  // The metadata grid under the panel title for a selected function.  Deferred
  // with the rest of the detail pane: nothing is selected at first paint, so
  // this grid is work the shell would have downloaded to render nothing.
  // VAs arrive as hex strings or numbers, so they go through the same decode
  // app.js uses rather than parseInt(v, 16), which would read a numeric VA as
  // base-16 digits.
  const functionMeta = ({ fn, sourceRoot, docText, jumpToAddress }) => {
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the boundary contract is exactly "hex string | number"; decode here so no call site re-parses
    const toVa = (v) => (typeof v === "string" ? Number.parseInt(v, 16) : v);

    const SourceItem = () => fn.files && fn.files.length > 0
      ? MetaItem("Source", span({ class: "meta-value" }, ...fn.files.map((file, i) =>
          span(i > 0 ? ", " : "", a({ href: `${encPath(sourceRoot)}/${encPath(file)}`, target: "_blank", rel: "noopener noreferrer", class: "source-link" }, file)))))
      : null;

    if (fn.isGlobal) {
      return div({ class: "meta-grid" },
        MetaItem("VA", a({
          href: "#",
          class: "meta-value asm-link",
          onclick: (e) => { e.preventDefault(); jumpToAddress(toVa(fn.va)); }
        }, `0x${fn.va.toString(16).toUpperCase()}`)),
        MetaItem("Type", "Global Variable"),
        SourceItem()
      );
    }

    const statusClass = fn.status ? `status-${fn.status.toLowerCase().replace('_', '-')}` : '';
    return div({ class: "meta-grid" },
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
      // verify_results.similarity is a 0-1 fraction, like functions.similarity
      // below it; rendered unscaled it read 100x low (87.3% as "0.9%").
      fn.last_verify && fn.last_verify.similarity != null ? MetaItem("Code Sim", `${(fn.last_verify.similarity * 100).toFixed(1)}%`) : null,
      fn.last_verify && fn.last_verify.reg_delta != null ? MetaItem("Reg Delta", `${fn.last_verify.reg_delta}`) : null,
      fn.last_verify && fn.last_verify.effective_match ? MetaItem("Effective", "register-only delta — prove candidate") : null,
      fn.updated_by ? MetaItem("Updated By", `${fn.updated_by}${fn.updated_at ? ` (${fn.updated_at})` : ""}`) : null,
      fn.similarity == null ? null : MetaItem("Similarity", `${(fn.similarity * 100).toFixed(1)}%`),
      fn.is_thunk ? MetaItem("Type", "IAT thunk (not reversible)") : null,
      fn.is_export ? MetaItem("Type", "Exported function") : null,
      fn.sha256 ? MetaItem("SHA256", `${fn.sha256.slice(0, 16)}...`) : null,
      SourceItem(),
      docText && docText !== MSG.SELECT_FUNCTION && docText !== MSG.NO_DOCS
        ? MetaItem("Annotations", pre({ class: "meta-docs" }, docText), "full-width") : null
    );
  };

  // The hexagon logo every code section is titled with.  It lives here, not in
  // app.js, because its only callers are panes this file owns: keeping it in
  // the shell spent ~450 minified bytes of a payload with a hard budget
  // (see the header comment) on markup that cannot paint before this file
  // lands anyway.
  const HexLogo = (label, color, titleText) => div({ class: "section-title-left" },
    span({ class: "hex-logo", "aria-hidden": "true", style: `color: ${color};`, innerHTML: `<svg viewBox="0 0 100 100"><polygon points="50,5 90,27.5 90,72.5 50,95 10,72.5 10,27.5" fill="currentColor" fill-opacity="0.15" stroke="currentColor" stroke-width="6" stroke-linejoin="round"/><text x="50" y="54" dominant-baseline="middle" text-anchor="middle" fill="currentColor" font-weight="800" font-size="${label.length > 2 ? '26' : '42'}">${label}</text></svg>` }),
    h3({ class: "section-title-text" }, titleText)
  );

  // C Source, Assembly, and Original Bytes are the same panel section with a
  // different logo, language, and body: title row, Copy, Open-in-modal.
  // Copy/Open go disabled while the pane holds an empty-state message —
  // copying "(select a function)" or opening a modal of it is never what
  // the user wants; the tooltip says what to do instead.  detailReady and
  // detailFailed are not consulted: this body only renders once this file has
  // loaded, so both are known-false at every call site.
  const isEmptyMessage = (text) => text === MSG.SELECT_FUNCTION || text === MSG.ASM_PLACEHOLDER
    || text === MSG.NO_C_SOURCE || text === MSG.NO_C_FOR_BLOCK || text === MSG.UNDOCUMENTED_BLOCK
    || text === MSG.DATA_SECTION_NO_ASM || text === MSG.BYTES_FAILED || text === MSG.BYTES_BSS
    || text === MSG.BYTES_LOAD_FAILED || text === MSG.GLOBAL_VAR || text === MSG.NO_DECL
    || text === MSG.NA || text === MSG.LOADING || text === MSG.DETAIL_UNAVAILABLE
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- pane text is string|derived-state; guard before .startsWith, not a type contract
    || (typeof text === "string" && (text.startsWith(MSG.ERROR_PREFIX) || text.startsWith("(failed to load:")));

  const CodeSection = (logo, color, heading, lang, text, openModal, HighlightedCode) => div({ class: "section" },
    div({ class: "section-title" },
      HexLogo(logo, color, heading),
      div({ class: "section-actions" },
        button({ class: "btn copy-btn", "aria-label": `Copy ${heading}`, disabled: () => isEmptyMessage(text), title: () => isEmptyMessage(text) ? "Select a block first" : "", onclick: (e) => copyToClipboard(text, e) }, "Copy"),
        button({
          class: "btn copy-btn", "aria-label": `Open ${heading} in a larger view`, disabled: () => isEmptyMessage(text), title: () => isEmptyMessage(text) ? "Select a block first" : "",
          onclick: () => openModal(heading, text, lang),
        }, "Open")
      )
    ),
    HighlightedCode({ lang, text })
  );

  // The panel body, rebuilt by the shell's reactive `() => Panel()` binding.
  // Nothing is selected at first paint, so the three code sections would lay
  // out stand-in text and copy buttons for nobody: the boot layout walks 205
  // objects, 61 of them these.  One muted line until there is something to
  // show.
  const panelBody = ({ fn, cellIdx, activeSection, cSourceText, asmText, bytesText, currentBuf, showModal, modalTitle, modalContent, modalLang, HighlightedCode }) => {
    const openModal = (heading, text, lang) => {
      // cellIdx is null when nothing is selected, which used to render
      // as the literal "Block null".
      const subject = cellIdx === null ? activeSection.val : `Block ${cellIdx}`;
      modalTitle.val = `${heading}: ${fn ? fn.name : subject}`;
      modalContent.val = text;
      modalLang.val = lang;
      showModal.val = true;
    };
    const section = (logo, color, heading, lang, text) =>
      CodeSection(logo, color, heading, lang, text, openModal, HighlightedCode);
    return div({ class: "panel-body" },
      (fn || cellIdx !== null)
        ? [
            section("C", "var(--accent-c-source)", "C Source", "c", cSourceText.val),
            activeSection.val === ".text"
              ? section("ASM", "var(--accent-asm)", "Assembly", "x86asm", asmText.val)
              : div({ class: "section" },
                  div({ class: "section-title" }, HexLogo("{}", "var(--accent-data)", "Data Inspector")),
                  DataInspector(currentBuf.val)
                ),
            section("01", "var(--accent-bytes)", "Original Bytes", "hex", bytesText.val)
          ]
        : div({ class: "hint" }, MSG.SELECT_FUNCTION)
    );
  };

  // The expanded code viewer.  Mounted once, on first paint of detail.js, and
  // kept in the DOM afterwards so the CSS open/close transition has something
  // to animate.
  const mountModal = ({ showModal, modalTitle, modalContent, modalLang, HighlightedCode }) => {
    if (document.querySelector(".modal")) return;

    van.add(document.body, div({
      class: () => `modal ${showModal.val ? "show" : ""}`,
      role: "dialog",
      "aria-modal": () => showModal.val ? "true" : "false",
      "aria-label": () => modalTitle.val || "Code viewer",
      onclick: (e) => { if (e.target.classList.contains("modal")) showModal.val = false; },
    },
      div({ class: "modal-content" },
        div({ class: "modal-header" },
          span({ class: "modal-title" }, () => modalTitle.val),
          div({ class: "modal-actions" },
            button({ class: "btn copy-btn", "aria-label": "Copy Modal Content", onclick: (e) => copyToClipboard(modalContent.val, e) }, "Copy"),
            button({ class: "btn modal-close", "aria-label": "Close Modal", onclick: () => { showModal.val = false; } }, "Close"),
          ),
        ),
        div({ class: "modal-body" }, () => HighlightedCode({ lang: modalLang.val, text: modalContent.val })),
      ),
    ));

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && showModal.val) showModal.val = false;
    });

    // The class that reveals the dialog is applied by van's batched DOM update,
    // so a single requestAnimationFrame can run while it is still
    // `visibility: hidden`, and focus() on a hidden element is a silent no-op.
    // Retry until it takes.
    // Retry is bounded at 10 frames; if focus has not landed by then the
    // dialog is not being shown at all, and looping further would just spin.
    const focusWhenVisible = (el, framesLeft = 10) => {
      if (!el) return;
      el.focus();
      if (document.activeElement !== el && framesLeft > 0) {
        requestAnimationFrame(() => focusWhenVisible(el, framesLeft - 1));
      }
    };

    // `inert` on the page behind the dialog is what actually contains focus: it
    // removes the background from the tab order and the accessibility tree,
    // which a hand-rolled Tab handler can only approximate.
    const pageRegions = () => document.querySelectorAll(".skip-link, .topbar, .layout");

    let lastFocused = null;
    van.derive(() => {
      const open = showModal.val;
      for (const el of pageRegions()) el.inert = open;
      if (open) {
        lastFocused = document.activeElement;
        focusWhenVisible(document.querySelector(".modal-close"));
      } else if (lastFocused) {
        const el = lastFocused;
        lastFocused = null;
        requestAnimationFrame(() => { if (el && el.focus) el.focus(); });
      }
    });
  };


  const mountGrid = ({
    container, data, isLoading, emptyState, activeSection, activeFilters,
    searchQuery, filteredFnNames, currentCellIndex, activeFnName, isLightMode,
    selectChunk, packSection, gridId, cellLoadError, retrySectionCells, setGridFocus,
  }) => {
    const PALETTE_VARS = ["--none", "--exact-bg", "--reloc-bg", "--near-match-bg", "--stub-bg", "--padding-bg", "--proven-bg", "--other-bg"];
    const FILTER_KEY = ["", "exact", "reloc", "near_match", "stub", "padding", "proven", "problem"];
    const grids = {};
    let ro = null;

    // One getComputedStyle for all eight variables: each call returns a live
    // declaration, and reading a property off a *new* one re-flushes style.
    // Reading them off a single object costs one flush instead of eight.
    const paletteOf = (el) => {
      const cs = getComputedStyle(el);
      return {
        pal: PALETTE_VARS.map((v) => cs.getPropertyValue(v).trim()),
        accent: cs.getPropertyValue("--c").trim()
      };
    };
    const minCellPx = () => (window.innerWidth < 700 ? 12 : 6);

    const layoutOf = (wrap) => {
      const gap = 2;
      const pad = 8;
      const usable = Math.max(0, wrap.clientWidth - pad * 2);
      const min = minCellPx();
      // Never render fewer columns than the section declares: shrinking the
      // lattice below the declared count re-wraps cells onto extra rows and
      // leaves a blank band under a short canvas (an 8-cell section at 8
      // declared columns painted one row of 6px cells, then ~250px of grid
      // background).  Narrow screens shrink the cells to `min` instead.
      const cols = Number(wrap.dataset.cols) || 64;
      const cell = Math.max(min, (usable - gap * (cols - 1)) / cols);
      return { cols, gap, pad, cell };
    };

    // A run of dots is drawn inside ONE row, so its usable length is bounded
    // by the column count, and a run never occupies less than one dot.  Both
    // ends matter: a span wider than the row wrote its hit-map entries off the
    // end of that row and into the next (Int32Array drops the overflow, so the
    // tail was unpaintable and unclickable), and pack.spans is a Uint16Array,
    // so a span of 65536 stored as 0 there — cellW then computed 0 * cell +
    // (0 - 1) * gap, a negative-width rect that claimed no column at all.
    const spanAt = (pack, i, cols) => {
      const s = pack.spans[i];
      if (s < 1) return 1;
      return s > cols ? cols : s;
    };

    const walk = (pack, cols, fn) => {
      let col = 0;
      let row = 0;
      for (let i = 0; i < pack.n; i += 1) {
        const s = spanAt(pack, i, cols);
        if (col + s > cols && col > 0) { row += 1; col = 0; }
        fn(i, col, row, s);
        col += s;
        if (col >= cols) { col = 0; row += 1; }
      }
    };

    // Layout (walk, rows, hit-map, canvas size) is cached per section and
    // recomputed only when the packed cells or the column count change;
    // filter/search/active/focus changes just redraw rects.  getComputedStyle
    // reads are cached too — the palette only changes on theme toggle.
    //
    // The memo keys on the pack OBJECT, not on (cols, cell count).  A rebuild
    // re-spans cells without necessarily changing how many there are, and that
    // pair would then match while the spans differ: the stale hit-map and rect
    // geometry would mis-paint the section and hand a click the wrong cell.
    // packSection returns a fresh object per section version and after a lazy
    // cells fetch (it deletes sec._pack), so identity is exactly "the cells
    // changed" — a superset of what the old key caught, and it drops the
    // per-paint string build.  The wrapper's width joins the key below.
    const layout = (secName, pack, force) => {
      const g = grids[secName];
      // The wrapper's own width is part of the key, not just the cell count: a
      // hidden section (`display: none`) reports clientWidth 0, so the
      // ResizeObserver never relaid it out, and a section first laid out before
      // a window resize came back painted (and hit-mapped) at the old geometry.
      const width = g.wrap.clientWidth;
      if (!force && g.layPack === pack && g.layWidth === width) return g;
      const lay = layoutOf(g.wrap);
      g.lay = lay;
      g.layPack = pack;
      g.layWidth = width;
      g.cols = lay.cols;
      const { cols, gap, pad, cell } = lay;
      // Row count first: walk is cheap, and sizing the map needs it upfront.
      // A trailing row filled exactly is already counted, so an empty
      // section (n == 0) is 0 rows, not 1.
      let rows = 0;
      {
        let col = 0;
        for (let i = 0; i < pack.n; i += 1) {
          const s = spanAt(pack, i, cols);
          if (col + s > cols && col > 0) { rows += 1; col = 0; }
          col += s;
          if (col >= cols) { col = 0; rows += 1; }
        }
        if (col > 0) rows += 1;
      }
      g.rows = rows;
      const map = new Int32Array(Math.max(1, rows) * cols);
      map.fill(-1);
      const cellRow = new Int32Array(pack.n);
      // Per-cell rect geometry, filled once per layout: the batched paint
      // below draws one path per state instead of one fillRect per cell
      // (~12ms -> ~2.6ms at 39k cells), and reuses these coords so it never
      // re-walks.
      const cellX = new Float32Array(pack.n);
      const cellY = new Float32Array(pack.n);
      const cellW = new Float32Array(pack.n);
      walk(pack, cols, (i, col, row, s) => {
        cellRow[i] = row;
        const base = row * cols + col;
        for (let k = 0; k < s; k += 1) map[base + k] = i;
        cellX[i] = pad + col * (cell + gap);
        cellY[i] = pad + row * (cell + gap);
        cellW[i] = s * cell + (s - 1) * gap;
      });
      g.map = map;
      g.cellRow = cellRow;
      g.cellX = cellX;
      g.cellY = cellY;
      g.cellW = cellW;
      const w = pad * 2 + cols * cell + Math.max(0, cols - 1) * gap;
      const h = pad * 2 + rows * cell + Math.max(0, rows - 1) * gap;
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      g.canvas.style.width = `${w}px`;
      g.canvas.style.height = `${h}px`;
      g.canvas.width = Math.max(1, Math.round(w * dpr));
      g.canvas.height = Math.max(1, Math.round(h * dpr));
      g.cssW = w;
      g.cssH = h;
      g.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      return g;
    };

    const palette = (secName, force) => {
      const g = grids[secName];
      if (!force && g.pal) return g;
      const { pal, accent } = paletteOf(g.wrap);
      g.pal = pal;
      g.accent = accent;
      return g;
    };

    const paint = (secName, opts = {}) => {
      const g = grids[secName];
      const sec = data.val?.sections?.[secName];
      if (!g || !sec) return;
      if (sec.cells == null) return;
      // A rebuild can change a section's declared column count.  The wrap was
      // built with the old value and layout reads it back off the DOM, so a
      // background refresh would otherwise keep wrapping at the old width.
      const declared = String(sec.columns || 64);
      let { relayout } = opts;
      if (g.wrap.dataset.cols !== declared) {
        g.wrap.dataset.cols = declared;
        relayout = true;
      }
      // oxlint-disable-next-line @rikalabs/no-pass-through-intermediate-vars -- pack feeds layout + the draw below, not a single passthrough
      const pack = packSection(sec);
      layout(secName, pack, relayout);
      palette(secName, opts.retheme);
      const { cell } = g.lay;
      const { ctx, pal, accent, cellX, cellY, cellW } = g;
      const filters = activeFilters.val;
      const filtering = filters.size > 0;
      const query = searchQuery.val;
      const matched = filteredFnNames.val;
      const activeIdx = currentCellIndex.val;
      const activeFn = activeFnName.val;
      const focusIdx = g.focus ?? 0;
      const { n, states, fns } = pack;
      ctx.clearRect(0, 0, g.cssW, g.cssH);
      // One path per state instead of one fillRect per cell: fillStyle
      // assignment per cell dominated repaint (~12ms -> ~2.6ms at 39k
      // cells).  Opaque cells fill in the first pass, dimmed cells (filter
      // mismatch or search miss) in a second alpha pass, so globalAlpha
      // changes twice per state instead of once per cell.
      const isDim = (i) => ((filtering && !filters.has(FILTER_KEY[states[i]] || ""))
        || (query !== "" && !matched.has(fns[i])));
      for (let pass = 0; pass < 2; pass += 1) {
        ctx.globalAlpha = pass === 0 ? 1 : 0.15;
        for (let st = 0; st < pal.length; st += 1) {
          ctx.fillStyle = pal[st] || pal[0];
          ctx.beginPath();
          for (let i = 0; i < n; i += 1) {
            if (states[i] !== st || (pass === 0) === isDim(i)) continue;
            ctx.rect(cellX[i], cellY[i], cellW[i], cell);
          }
          ctx.fill();
        }
      }
      ctx.globalAlpha = 1;
      // Selection + focus strokes stay per-cell: at most two rects.
      const strokeActive = (i, dashed) => {
        ctx.strokeStyle = accent;
        ctx.lineWidth = dashed ? 1 : 2;
        if (dashed) ctx.setLineDash([2, 2]);
        ctx.strokeRect(cellX[i] + 0.5, cellY[i] + 0.5, cellW[i] - 1, cell - 1);
        if (dashed) ctx.setLineDash([]);
      };
      if (activeIdx != null && activeIdx >= 0 && activeIdx < n) strokeActive(activeIdx, false);
      else if (activeFn) {
        for (let i = 0; i < n; i += 1) {
          if (fns[i] === activeFn) { strokeActive(i, false); break; }
        }
      }
      if (document.activeElement === g.wrap && focusIdx >= 0 && focusIdx < n && focusIdx !== activeIdx) {
        strokeActive(focusIdx, true);
      }
    };

    const hit = (secName, px, py) => {
      const g = grids[secName];
      if (!g || !g.lay || !g.map) return -1;
      const { cols, gap, pad, cell } = g.lay;
      const gx = px - pad;
      const gy = py - pad;
      if (gx < 0 || gy < 0) return -1;
      const stride = cell + gap;
      const col = Math.floor(gx / stride);
      const row = Math.floor(gy / stride);
      if (col < 0 || row < 0 || col >= cols || row >= (g.rows || 0)) return -1;
      if (gx - col * stride > cell || gy - row * stride > cell) return -1;
      const idx = g.map[row * cols + col];
      return idx < 0 ? -1 : idx;
    };

    const scrollCell = (secName, idx) => {
      const g = grids[secName];
      if (!g || !g.lay || !g.cellRow || idx < 0 || idx >= g.cellRow.length) return;
      const { gap, pad, cell } = g.lay;
      const y = pad + g.cellRow[idx] * (cell + gap);
      const top = g.wrap.getBoundingClientRect().top + window.scrollY + y;
      window.scrollTo({ top: Math.max(0, top - window.innerHeight / 3), behavior: "smooth" });
      // Vertically the lattice is as tall as the page, so the window is the
      // scrollport.  Horizontally it is the wrapper: on a narrow viewport the
      // 12px minimum cell makes the lattice wider than the frame, and a jump
      // (search Enter, an asm link, an arrow-key walk) otherwise leaves the
      // cell it just selected off-screen.
      const x = g.cellX[idx];
      const right = x + g.cellW[idx];
      if (x < g.wrap.scrollLeft || right > g.wrap.scrollLeft + g.wrap.clientWidth) {
        g.wrap.scrollTo({ left: Math.max(0, x - g.wrap.clientWidth / 3), behavior: "smooth" });
      }
    };

    setGridFocus((secName, idx) => {
      const g = grids[secName];
      if (!g) return;
      g.focus = idx;
      if (g.wrap.contains(document.activeElement)) g.wrap.focus();
      paint(secName);
      scrollCell(secName, idx);
    });

    ro = new ResizeObserver(() => {
      if (grids[activeSection.val]) paint(activeSection.val, { relayout: true });
    });

    van.derive(() => {
      const dropGrids = () => {
        // A ResizeObserver holds every observed target strongly until it is
        // unobserved or disconnected, so tearing the wrappers out of the DOM
        // without this pins each one (canvas, 2D context, and the per-section
        // hit-map and geometry typed arrays) for the rest of the session.
        // Every reload drops the grids, and live reload fires on each
        // coverage.db rebuild, so the observed set would grow without bound.
        // New wrappers re-observe on creation, so a disconnect here is safe.
        ro.disconnect();
        container.innerHTML = "";
        for (const k of Object.keys(grids)) delete grids[k];
      };
      if (isLoading.val) {
        dropGrids();
        van.add(container, div({ class: "loading-overlay", role: "status", "aria-live": "polite" }, "Loading coverage data…"));
        return;
      }
      if (emptyState.val || !data.val || !data.val.sections) {
        dropGrids();
        return;
      }
      const secName = activeSection.val;
      const sec = data.val.sections[secName];
      const overlay = container.querySelector(".loading-overlay");
      if (overlay) overlay.remove();
      container.querySelector(".grid-error")?.remove();
      if (!sec) return;
      // Sibling tabs fetch their cells on switch, so a tab can be in flight or
      // have failed.  Either way there is no lattice to draw: say which, rather
      // than leaving an empty frame the user cannot act on.
      if (sec.cells == null) {
        const failed = cellLoadError.val?.section === secName ? cellLoadError.val : null;
        if (failed) {
          van.add(container, div({ class: "grid-error", role: "status" },
            p(`Could not load the ${secName} map: ${failed.detail}`),
            button({ class: "btn", onclick: () => retrySectionCells(secName) }, "Retry")));
        } else {
          van.add(container, div({ class: "loading-overlay", role: "status", "aria-live": "polite" }, `Loading ${secName}…`));
        }
        return;
      }
      for (const [name, g] of Object.entries(grids)) {
        g.wrap.style.display = name === secName ? "block" : "none";
      }
      if (grids[secName]) { paint(secName); return; }

      const wrap = div({
        class: "grid",
        id: gridId(secName),
        "data-cols": sec.columns || 64,
        role: "listbox",
        tabindex: "0",
        "aria-label": `${secName} coverage map`,
        // Pointer position is resolved against the CANVAS, not the wrapper: the
        // lattice's own coordinates are canvas-relative, and the canvas rect
        // already carries the wrapper's scroll offset and excludes the wrapper's
        // 1px border. Measured against the wrapper, a map scrolled sideways
        // (every narrow viewport, where the 12px minimum cell makes the lattice
        // wider than the frame) put the click on whichever cell happened to sit
        // under the same viewport coordinates.
        onclick: (e) => {
          const rect = grids[secName].canvas.getBoundingClientRect();
          const idx = hit(secName, e.clientX - rect.left, e.clientY - rect.top);
          if (idx >= 0) { grids[secName].focus = idx; selectChunk(idx); wrap.focus(); paint(secName); }
        },
        onmousemove: (e) => {
          const rect = grids[secName].canvas.getBoundingClientRect();
          const idx = hit(secName, e.clientX - rect.left, e.clientY - rect.top);
          if (idx < 0) { wrap.title = ""; wrap.style.cursor = "default"; return; }
          wrap.style.cursor = "pointer";
          const pack = packSection(sec);
          const secVa = sec.va || 0;
          const label = window.RC.STATE_LABEL[pack.states[idx]];
          wrap.title = [`Block ${idx}`,
            `${hex(secVa + pack.starts[idx], 8)}..${hex(secVa + pack.ends[idx], 8)}`,
            label, pack.fns[idx] || "no function"].filter(Boolean).join("  ");
        },
        onkeydown: (e) => {
          if (e.ctrlKey || e.metaKey || e.altKey) return;
          const pack = packSection(sec);
          const last = pack.n - 1;
          if (last < 0) return;
          const g = grids[secName];
          const cols = g?.cols || Number(wrap.dataset.cols) || 64;
          const idx = g?.focus ?? 0;
          const step = { ArrowRight: idx + 1, ArrowLeft: idx - 1, ArrowDown: idx + cols, ArrowUp: idx - cols, Home: 0, End: last }[e.key];
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            selectChunk(idx);
            paint(secName);
          } else if (step !== undefined) {
            e.preventDefault();
            g.focus = Math.max(0, Math.min(last, step));
            wrap.focus();
            paint(secName);
            scrollCell(secName, g.focus);
          }
        },
      });
      // oxlint-disable-next-line @rikalabs/no-pass-through-intermediate-vars -- canvas is stored and appended; ctx is a second use, not an alias
      const mapCanvas = canvas({ class: "grid-canvas" });
      wrap.append(mapCanvas);
      grids[secName] = { wrap, canvas: mapCanvas, ctx: mapCanvas.getContext("2d"), cols: Number(wrap.dataset.cols) || 64, lay: null, layPack: null, focus: 0 };
      container.append(wrap);
      ro.observe(wrap);
      requestAnimationFrame(() => paint(secName));
    });

    let lastTheme = null;
    van.derive(() => {
      // oxlint-disable no-unused-expressions -- bare .val reads subscribe this derive to state
      searchQuery.val;
      filteredFnNames.val;
      currentCellIndex.val;
      activeFnName.val;
      activeFilters.val;
      const theme = isLightMode.val;
      // oxlint-enable no-unused-expressions
      const name = activeSection.val;
      const retheme = theme !== lastTheme;
      lastTheme = theme;
      if (grids[name]) paint(name, { retheme });
    });
  };

  Object.assign(window.RC, { formatBytes, functionMeta, DataInspector, extractDocs, initHighlighting, highlightInto, loadAsm, connectEvents, reloadData, copyToClipboard, mountModal, mountGrid, panelBody });
  window.RC.onReady();
})();
