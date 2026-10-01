/** The highlighter, as its own bundle.
 *
 * `app.js` is a single IIFE (the shell inlines it into a classic `<script>`),
 * and an IIFE cannot code-split: Vite defaults `codeSplitting` to false for
 * the format, so a dynamic `import()` of highlight.js is flattened straight
 * back into the entry. The only way to keep ~10 KB brotli of a library used
 * by no first frame out of the one document on the critical path is to build it
 * separately and load it later.
 *
 * This entry is that second build. It registers highlight.js and the three
 * grammars the dashboard shows on a global, and `lib/highlight.ts` pulls it in
 * with a `<script src>` the first time a code pane renders. A `<script src>`
 * rather than `eval`/`new Function` because the shell's CSP is
 * `script-src 'self' 'unsafe-inline'` with no `unsafe-eval`: same-origin
 * script is allowed, string-to-code is not.
 *
 * The global name is namespaced so it cannot collide with anything the page or
 * a future dependency puts on `window`. */

import hljs from "highlight.js/lib/core";
import c from "highlight.js/lib/languages/c";
import x86asm from "highlight.js/lib/languages/x86asm";

import { HIGHLIGHT_GLOBAL } from "@/lib/highlight-global";

hljs.registerLanguage("c", c);
hljs.registerLanguage("x86asm", x86asm);
// The byte dump: an offset, the hex columns, and the ASCII gutter. The classes
// are the theme's, so the dump is coloured like every other pane.
hljs.registerLanguage("hex", () => ({
  name: "Hex",
  contains: [
    { className: "meta", begin: /^[0-9A-Fa-f]{8}/u },
    { className: "string", begin: /\|.*\|$/u },
    { className: "number", begin: /\b[0-9A-Fa-f]{2}\b/u },
  ],
}));

window[HIGHLIGHT_GLOBAL] = hljs;
