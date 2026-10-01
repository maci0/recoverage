import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import { preact } from "@preact/preset-vite";
import { defineConfig, type LibraryOptions } from "vite";

/** The dashboard bundle.
 *
 * The Python server inlines this output into its SPA shell, so the build is a
 * library build with fixed names rather than a hashed multi-file app: `ui.py`
 * reads `assets/app.js` and `assets/style.css` by name and the shell keeps its
 * `<!-- INJECT_JS -->` / `<!-- INJECT_CSS -->` markers.  An IIFE (not an ES
 * module) is what a classic `<script>` in that shell can run.
 *
 * Output lands flat in `src/recoverage/assets`, which is where the server reads
 * it from: `pyproject.toml`'s package data is `assets/*`, so a nested output
 * directory would be packaged as nothing at all. `emptyOutDir` stays off
 * because that directory also holds `index.html`, `favicon.svg` and
 * `print.css`, which Vite does not emit.
 *
 * The export is an ARRAY because the highlighter is a second build. `app.js`
 * is an IIFE, and an IIFE cannot code-split: the format has no module loader,
 * so Vite defaults `codeSplitting` to false for it and a dynamic `import()` of
 * highlight.js is flattened straight back into the entry. The highlighter is
 * therefore built on its own and loaded on demand by `app/lib/highlight.ts`
 * through a `<script src>`. Only a selection renders a code pane, and the
 * highlighter measured ~10 KB brotli of the shell's ~54 KB, so it is not
 * something to hand every visitor before the first frame.
 *
 * The two configs differ ONLY in their lib entry and output name, so the
 * shared settings live in one object rather than being written twice and
 * drifting.
 */
const outDir = resolve(import.meta.dirname, "../src/recoverage/assets");

/** Everything the dashboard bundle and the highlighter bundle agree on. */
export const shared = {
  root: import.meta.dirname,
  plugins: [preact(), tailwindcss()],
  // `@/` is the alias the components import through; tsconfig carries it for
  // tsc and Vite needs it spelled out for both dev and build.
  // The source directory is `app/`, not `src/`: the SPA fetches C source over
  // `/src/<sourceRoot>/...`, so a dev server whose own modules live under `/src`
  // has its entry shadowed by the API proxy.
  resolve: { alias: { "@": resolve(import.meta.dirname, "app") } },
  // React ships both branches of every `process.env.NODE_ENV` test, so without
  // this define the development branch survives the build: the bundle measured
  // 679 KB against 190 KB with it.
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
};

/** The lib-build half both configs share: one named IIFE per entry. */
function libBuild(entry: string, fileName: string) {
  return {
    outDir,
    emptyOutDir: false,
    target: "es2022",
    // The dashboard's CSS is the one stylesheet the shell inlines; the
    // highlighter ships no styles of its own (the classes it emits are the
    // theme's, declared in `index.css`).
    cssCodeSplit: false,
    sourcemap: false,
    lib: {
      entry: resolve(import.meta.dirname, entry),
      name: "ReCoverage",
      // `satisfies` rather than a cast: it keeps the literal `"iife"` narrow
      // enough for Vite's `LibraryFormats[]` without widening it to `string[]`
      // and failing the whole config.
      formats: ["iife"] satisfies LibraryOptions["formats"],
      fileName: () => fileName,
      cssFileName: "style",
    },
  };
}

/* oxlint-disable node/no-process-env -- a Vite config runs in Node, where the dev
   API target is read from the environment; the bundle itself never sees
   process.env, and the built app talks to its own origin.

   One read of the knob, because it was spelled once per proxied path and an
   edit to two of them is how a contributor ends up proxying /api to one server
   and /src to another. The fallback restates `config.DEFAULT_BIND` /
   `config.DEFAULT_PORT` in `src/recoverage/config.py`: this config runs in Node
   before the package is importable, so the value cannot be read off the
   constant it mirrors, and
   `tests/test_config.py::TestBindValidation::test_the_dev_proxy_target_matches_the_server_default`
   holds the two in step instead. */
const devApi = process.env.RECOVERAGE_DEV_API ?? "http://127.0.0.1:8001";

const devServer = {
  // Binds the IPv4 literal: the default `localhost` resolves to ::1 here,
  // which a browser pointed at 127.0.0.1 cannot reach.
  host: "127.0.0.1",
  // Development talks to a running `recoverage serve` over the same paths the
  // bundled app uses, so no code branch knows which one is serving it. The
  // highlighter's own file goes through it too: the dev server serves the app,
  // and that app asks the dashboard for the script, so the entry has to be the
  // running server's asset rather than this server's.
  proxy: {
    "/api": { target: devApi },
    "/src": { target: devApi },
    "/original": { target: devApi },
    "/highlight.js": { target: devApi },
  },
} as const;

/** The dashboard config: the entry bundle `ui.py` inlines, plus the dev
 * server `dev:web` serves. */
export const dashboard = {
  ...shared,
  build: libBuild("app/main.tsx", "app.js"),
  server: devServer,
};

/** The highlighter config: a second lib build whose output the dashboard
 * fetches on the first code pane. No dev server, because the file is served by
 * the running `recoverage serve` the dev proxy points at, not by this one. */
export const highlighter = {
  ...shared,
  build: libBuild("app/highlight-entry.ts", "highlight.js"),
};

/** Both builds, in the order `web/build.ts` runs them.
 *
 * Exported as a pair of named configs rather than as a literal array in the
 * default export because Vite reads a config FILE as one config object and
 * rejects an array (Vite 8 dropped the array config file). */
export const configs = [dashboard, highlighter] as const;

export default defineConfig(dashboard);
