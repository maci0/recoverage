/** Syntax highlighting, loaded on first use rather than inlined.
 *
 * The VanJS build loaded `/hljs.min.js` and its grammars as separate scripts
 * after first paint, because the shell had a hard byte budget. The bundle kept
 * that split in name only: highlight.js was a STATIC import here, so the core
 * plus the `c` and `x86asm` grammars rode in `app.js`, which `ui.py` inlines
 * into the one document on the critical path. Measured on the committed
 * bundle that was ~10 KB brotli of the shell's ~54 KB, downloaded and parsed
 * on every visit by readers who never open a code pane — a selection, and
 * therefore the only thing that highlights anything, has to happen first.
 *
 * So the highlighter is a second build (`highlight-entry.ts`, see
 * `vite.config.ts`) that registers itself on `window.__recoverageHljs`, pulled
 * in here the first time a pane renders. An IIFE cannot code-split and a CSP
 * without `unsafe-eval` forbids evaluating fetched text, so a `<script src>` is
 * the mechanism: the shell's `script-src 'self'` allows it.
 *
 * `loadHighlighter` memoises the in-flight load, so a reader with two panes
 * open fetches it once, and a load that FAILS rejects: the pane says the
 * highlighting is unavailable rather than leaving the reader with permanently
 * plain text they cannot tell from a finished render. */

import { HIGHLIGHT_GLOBAL, type Highlighter } from "@/lib/highlight-global";

/** The script the second build emits; `ui.py` serves it beside `app.js`. */
const HIGHLIGHT_SRC = "/highlight.js";

/** What went wrong loading the highlighter, named rather than carried as an
 * `unknown`: the failures below are the only two, and a pane that cannot load
 * the highlighter is a real state the reader has to be told about rather than a
 * parse of an arbitrary thrown value. */
export type HighlightLoadError =
  /** The script was refused, blocked, or did not arrive. */
  | { readonly kind: "unreachable"; readonly source: string }
  /** The script ran and registered nothing, which is a stale `highlight.js`
   * beside a newer `app.js`: what a half-updated asset set serves. Resolving
   * with the fallback would render every pane unhighlighted for ever, so this
   * is the same failure a 404 is. */
  | { readonly kind: "not-registered"; readonly source: string };

/** Builds the rejection, so both sites name the same failure. */
function loadFailure(kind: HighlightLoadError["kind"]): HighlightLoadError {
  return { kind, source: HIGHLIGHT_SRC };
}

let pending: Promise<Highlighter> | null = null;

function present(): Highlighter | null {
  return window[HIGHLIGHT_GLOBAL] ?? null;
}

/** The document the script is inserted into.
 *
 * `head` is null only for a document parsed without one, which cannot happen
 * for the served shell; the guard is here so a bad host environment leaves the
 * pane reporting a failure rather than throwing inside the effect. */
function head(): HTMLHeadElement {
  const found = document.head;
  if (found === null) {
    throw new Error("recoverage: the document has no head to load the highlighter into");
  }
  return found;
}

async function loadScript(): Promise<Highlighter> {
  const script = document.createElement("script");
  script.src = HIGHLIGHT_SRC;
  script.async = true;
  const loaded = new Promise<void>((resolve) => {
    script.addEventListener("load", () => {
      resolve();
    });
  });
  // `error` fires for a 404, a blocked request and a parse failure alike;
  // either way nothing waits on this promise for ever.
  const failed = new Promise<void>((_resolve, reject) => {
    script.addEventListener("error", () => {
      reject(loadFailure("unreachable"));
    });
  });
  head().append(script);
  await Promise.race([loaded, failed]);
  const hljs = present();
  if (hljs === null) {
    throw loadFailure("not-registered");
  }
  return hljs;
}

/** The registered highlighter, fetched on first call and shared after that. */
export function loadHighlighter(): Promise<Highlighter> {
  const already = present();
  if (already !== null) {
    return Promise.resolve(already);
  }
  // A failed load must not be memoised as the answer: the reader reloads the
  // page or clicks a second cell, and the retry is what lets the pane recover
  // without one. The rejection passes through unchanged — `loadScript` rejects
  // with a `HighlightLoadError` and nothing else, so there is nothing to parse
  // and nothing to re-wrap.
  pending ??= loadScript().catch(() => {
    pending = null;
    throw loadFailure("unreachable");
  });
  return pending;
}

export type HighlightLanguage = "c" | "x86asm" | "hex";

/** The pane's HTML for *text*, highlighted by a loaded *hljs*.
 *
 * An address in a disassembly line becomes an `.asm-link` with the address in
 * `data-addr`, which is what makes a jump target clickable; the anchor is added
 * after the highlight pass, exactly as the VanJS code did, because escaping
 * would otherwise turn the inserted markup into text. */
export function highlightCode(
  hljs: Highlighter,
  text: string,
  language: HighlightLanguage,
): string {
  if (text === "" || hljs.getLanguage(language) === undefined) {
    return escapeHtml(text);
  }
  const html = hljs.highlight(text, { language, ignoreIllegals: true }).value;
  if (language !== "x86asm") {
    return html;
  }
  return html.replaceAll(
    /(?<address>0x[0-9a-fA-F]+)/gu,
    // The link is reachable by Tab and by the screen reader's link list, where
    // it read as a bare hex number with no indication of what activating it
    // does: a disassembly is hundreds of lines, so the link list was hundreds
    // of rows of "0x00401000". The name says the action and names the target
    // it jumps to; the visible text stays the address, so nothing on screen
    // changes and the name never drifts from what is shown.
    '<a href="#" class="asm-link" data-addr="$<address>" title="Jump to $<address>" aria-label="Jump to address $<address>">$<address></a>',
  );
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
