// Detail rendering for a selected block: the hex dump and the data inspector.
// Both are needed only after the first cell click, so they are kept out of the
// inlined index payload (which has to fit the initial TCP congestion window)
// and fetched immediately after first paint instead.  app.js publishes what
// this file needs on window.RC and reads the results back from it.
(() => {
  const { MetaItem, MSG, hex } = window.RC;
  const { div } = van.tags;

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
  let lastRegenTime = 0;
  const reloadData = async ({ loadingMsg, summaryData, loadData, MSG: messages }) => {
    const now = Date.now();
    const since = now - lastRegenTime;
    if (since < REGEN_COOLDOWN_MS) {
      loadingMsg.val = messages.REGEN_USING_CACHE(Math.ceil((REGEN_COOLDOWN_MS - since) / 1000));
      await loadData();
      return;
    }
    lastRegenTime = now;
    loadingMsg.val = messages.REGEN_IN_PROGRESS;
    summaryData.val = null;
    let ok = false;
    try {
      const { ok: regenOk } = await fetch("/api/regen", { method: "POST", cache: "no-store" });
      ok = regenOk;
    } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- regen failure is reported to the user via REGEN_UNAVAILABLE
      // oxlint-disable-next-line eslint/no-console -- keep diagnostics in the browser console
      console.error("Regen failed:", error);
    }
    if (!ok) loadingMsg.val = messages.REGEN_UNAVAILABLE;
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

  // The expanded code viewer.  Mounted once, on first paint of detail.js, and
  // kept in the DOM afterwards so the CSS open/close transition has something
  // to animate.
  const mountModal = ({ showModal, modalTitle, modalContent, modalLang, HighlightedCode }) => {
    if (document.querySelector(".modal")) return;
    const { button, span } = van.tags;

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
    // ponytail: bounded at 10 frames; if focus has not landed by then the
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

  Object.assign(window.RC, { formatBytes, DataInspector, extractDocs, initHighlighting, connectEvents, reloadData, copyToClipboard, mountModal });
  window.RC.onReady();
})();
