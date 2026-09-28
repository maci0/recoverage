import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import { preact } from "@preact/preset-vite";
import { defineConfig } from "vite";

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
 */
const outDir = resolve(import.meta.dirname, "../src/recoverage/assets");

/* oxlint-disable node/no-process-env -- a Vite config runs in Node, where the dev
   API target is read from the environment; the bundle itself never sees
   process.env, and the built app talks to its own origin. */
export default defineConfig({
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
  build: {
    outDir,
    emptyOutDir: false,
    target: "es2022",
    cssCodeSplit: false,
    sourcemap: false,
    lib: {
      entry: resolve(import.meta.dirname, "app/main.tsx"),
      name: "ReCoverage",
      formats: ["iife"],
      fileName: () => "app.js",
      cssFileName: "style",
    },
  },
  server: {
    // Binds the IPv4 literal: the default `localhost` resolves to ::1 here,
    // which a browser pointed at 127.0.0.1 cannot reach.
    host: "127.0.0.1",
    // Development talks to a running `recoverage serve` over the same paths the
    // bundled app uses, so no code branch knows which one is serving it.
    proxy: {
      "/api": { target: process.env.RECOVERAGE_DEV_API ?? "http://127.0.0.1:8001" },
      "/src": { target: process.env.RECOVERAGE_DEV_API ?? "http://127.0.0.1:8001" },
      "/original": { target: process.env.RECOVERAGE_DEV_API ?? "http://127.0.0.1:8001" },
    },
  },
});
