/** Syntax highlighting, bundled rather than fetched.
 *
 * The VanJS build loaded `/hljs.min.js` and its grammars as separate scripts
 * after first paint, because the shell had a hard byte budget. The bundle has
 * no such split: highlight.js is imported here, and only the two grammars the
 * dashboard actually shows (`c`, `x86asm`) plus the custom `hex` language for
 * the byte dump are registered, which is a fraction of the full build. */

import hljs from "highlight.js/lib/core";
import c from "highlight.js/lib/languages/c";
import x86asm from "highlight.js/lib/languages/x86asm";

let registered = false;

function register(): void {
  if (registered) {
    return;
  }
  hljs.registerLanguage("c", c);
  hljs.registerLanguage("x86asm", x86asm);
  // The byte dump: an offset, the hex columns, and the ASCII gutter. The
  // classes are the theme's, so the dump is coloured like every other pane.
  hljs.registerLanguage("hex", () => ({
    name: "Hex",
    contains: [
      { className: "meta", begin: /^[0-9A-Fa-f]{8}/u },
      { className: "string", begin: /\|.*\|$/u },
      { className: "number", begin: /\b[0-9A-Fa-f]{2}\b/u },
    ],
  }));
  registered = true;
}

export type HighlightLanguage = "c" | "x86asm" | "hex";

/** The pane's HTML for *text*.
 *
 * An address in a disassembly line becomes an `.asm-link` with the address in
 * `data-addr`, which is what makes a jump target clickable; the anchor is added
 * after the highlight pass, exactly as the VanJS code did, because escaping
 * would otherwise turn the inserted markup into text. */
export function highlightCode(text: string, language: HighlightLanguage): string {
  if (text === "" || !hljs.getLanguage(language)) {
    return escapeHtml(text);
  }
  register();
  const html = hljs.highlight(text, { language, ignoreIllegals: true }).value;
  if (language !== "x86asm") {
    return html;
  }
  return html.replaceAll(
    /(?<address>0x[0-9a-fA-F]+)/gu,
    '<a href="#" class="asm-link" data-addr="$<address>">$<address></a>',
  );
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
