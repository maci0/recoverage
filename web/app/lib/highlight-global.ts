/** Where the highlighter bundle publishes itself.
 *
 * `highlight-entry.ts` and `lib/highlight.ts` are two SEPARATE bundles, so the
 * name they agree on cannot live in either of them: the second would have to
 * import the first, which puts the highlighter back in the entry. It is
 * therefore declared here, in a module both can import without pulling any code
 * along — a type and a string constant compile away, so importing this from the
 * entry costs nothing.
 *
 * The name is namespaced: it lands on `window`, and the page may one day carry
 * a dependency that wants the same short name. */

import type { HLJSApi } from "highlight.js";

/** The registered highlighter.
 *
 * Read from highlight.js's own declaration rather than restated as a
 * hand-written subset: this is a TYPE-ONLY import, erased at compile time, so
 * it costs the entry bundle no code while keeping the two halves of the split
 * agreeing about the library's shape. A restated interface would be a second
 * copy of a signature to drift, and the cast needed to reconcile it would be a
 * promise this file cannot check. */
export type Highlighter = HLJSApi;

/** The `window` property `highlight-entry.ts` sets and `loadHighlighter`
 * reads. A namespace, not a bare name: this is a global. */
export const HIGHLIGHT_GLOBAL = "__recoverageHljs";

declare global {
  // oxlint-disable-next-line typescript/consistent-type-definitions -- (perf, first-paint) `Window` is the DOM's own interface; the only way to add a property to it is to merge into that name, and a type alias cannot be reopened. See AGENTS.md, the payload budget note.
  interface Window {
    /** The registered highlighter, set by the highlighter bundle. */
    [HIGHLIGHT_GLOBAL]?: Highlighter;
  }
}
