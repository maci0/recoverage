/** Build the dashboard bundle and the highlighter bundle.
 *
 * `web/vite.config.ts` carries both configs and `default` is the dashboard's,
 * so `vite build` alone would emit `app.js` and stop. The highlighter is a
 * second build because `app.js` is an IIFE — the format the SPA shell inlines
 * into a classic `<script>` — and an IIFE cannot code-split, so the ~10 KB
 * brotli of highlight.js can only stay out of the critical path as its own
 * file. Vite 8 reads a config file as one object, so the second build is
 * driven through its `builder` API here.
 *
 * Run through `bun run build:web` from the repository root.
 */

import { build } from "vite";

import { configs } from "./vite.config.ts";

/** Both builds, in order. */
async function buildAll(): Promise<void> {
  for (const config of configs) {
    // `configFile: false` because the config is passed INLINE: Vite would
    // otherwise look for a config file under `root` (`web/`), find this one and
    // build its default export a second time.
    await build({ ...config, configFile: false });
  }
}

// oxlint-disable-next-line node/no-top-level-await -- a build script run by `bun run build:web` and imported by nothing, which is the case the rule exempts; a failed build still exits non-zero because this is the last statement
await buildAll();
