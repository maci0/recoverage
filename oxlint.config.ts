import strictPreset from "./tools/oxlint/rikalabs-strict.json" with { type: "json" };
import { defineConfig } from "oxlint";
import { fileURLToPath } from "node:url";

/**
 * JS/TS linting for the dashboard frontend.
 *
 * Two strict layers on top of oxlint's default categories:
 *
 * 1. `tools/oxlint/rikalabs-strict.json` — a flattened, checked-in copy of the
 *    `strict` preset from @rikalabs/oxlint-standards (see
 *    tools/flatten-rikalabs-strict.py). It is flattened because the published
 *    presets reference a few rules oxlint 1.79.0 does not implement, and oxlint
 *    rejects configs that mention unknown rules even as "off".
 * 2. The vendored anti-slop plugin (tools/oxlint/anti-slop — a curated copy of
 *    dmmulroy/anti-slop, MIT) that rejects low-evidence patterns typical of
 *    AI-generated code. Keep it in sync with upstream dmmulroy/anti-slop.
 *
 * The Rika-Labs standards are TypeScript-first (they assume type-aware rules).
 * This webui is a plain-JS VanJS SPA with no tsconfig, so type-aware rules are
 * disabled (options.typeAware: false in the flattened preset) and the few
 * platform exceptions below are documented.
 */
export default defineConfig({
  extends: [strictPreset],
  ignorePatterns: [
    "node_modules/**",
    // Vendored third-party assets — not our code.
    "src/recoverage/assets/van.min.js",
    "src/recoverage/assets/hljs*.js",
    // The vendored anti-slop plugin itself.
    "tools/oxlint/anti-slop/**",
  ],
  // The webui is browser-only; its JS runs against browser globals. `van` is
  // a script-level global provided by the vendored van.min.js.
  env: { browser: true },
  globals: { van: "readonly" },
  jsPlugins: [
    // oxlint passes plugin specifiers to Node `import()` verbatim, so use
    // absolute paths resolved from this config file rather than bare names.
    {
      name: "@rikalabs",
      specifier: fileURLToPath(
        new URL(
          "./node_modules/@rikalabs/oxlint-standards/dist/plugin/index.js",
          import.meta.url,
        ),
      ),
    },
    {
      name: "anti-slop",
      specifier: fileURLToPath(
        new URL("./tools/oxlint/anti-slop/index.ts", import.meta.url),
      ),
    },
  ],
  rules: {
    // The preset's oxc/no-new-buffer does not exist in oxlint 1.79.0; the
    // same rule lives under unicorn. Keep the preset's intent.
    "unicorn/no-new-buffer": "error",
    // Browser-only SPA: `window` is the precise, self-documenting global;
    // globalThis buys nothing when there is no non-browser runtime.
    "unicorn/prefer-global-this": "off",
    // The SPA loads app.js/detail.js as classic <script>s, not ES modules.
    "import/unambiguous": "off",
    // Pedantic nesting heuristic; 40+ low-signal sites in UI glue code.
    "unicorn/max-nested-calls": "off",
    // `!= null` is the idiomatic nullish check (catches null and undefined);
    // strict comparisons there would only add noise. eqeqeq keeps enforcing
    // === everywhere else.
    "eslint/eqeqeq": ["error", "always", { "null": "ignore" }],
    "eslint/no-eq-null": "off",
    // Style choices that are deliberate conventions in this codebase:
    // - one-var "always" would merge section-organized declarations into one
    //   giant chain; "never" still enforces single-declarator statements.
    "eslint/one-var": ["error", "never"],
    // - single-line `if (x) return y;` guards stay brace-free; multi-line
    //   blocks must use braces (no dangling-else hazards).
    "eslint/curly": ["error", "multi-line"],
    // - comment capitalization/placement is editorial, not contractual.
    "eslint/capitalized-comments": "off",
    "eslint/no-inline-comments": "off",
    // - hoisted function declarations for helpers, const arrows for
    //   callbacks; declarations grouped by domain order, not alphabet.
    "eslint/func-style": "off",
    "eslint/sort-vars": "off",
    // VanJS components are closures over shared state; the main App component
    // is ~900 lines of orchestration and the 60-line cap would force
    // artificial fragmentation.
    "eslint/max-lines-per-function": "off",
    // _-prefixed fields (cell._baseClass etc.) mark derived caches written
    // onto data objects; the underscore is the convention that separates them
    // from the API fields (cell.state, cell.start, ...).
    "eslint/no-underscore-dangle": "off",
    // Classic-script IIFE pattern: these helpers are scoped to the IIFE, and
    // "module level" would mean the global scope — worse, not better.
    "unicorn/consistent-function-scoping": "off",
    // Script loading has no non-Promise await; new Promise(resolve) on
    // el.onload is the standard idiom.
    "promise/avoid-new": "off",
    // Plain-object dictionaries cleared via delete; a TypeScript-targeted
    // rule with no type info here.
    "typescript/no-dynamic-delete": "off",
    // The rule's suggested fix (Number(x) for parseFloat(x)) breaks computed
    // CSS lengths: Number("12px") is NaN while parseFloat("12px") is 12.
    "unicorn/prefer-number-coercion": "off",
    // oxlint misreports the top-level `const { a, p, ... } = van.tags`
    // destructure as shadowing globals that do not exist; real shadows (the
    // reloadData param, mountModal's copyToClipboard) are fixed by rename.
    "eslint/no-shadow": "off",
    // Vendored anti-slop rules (dmmulroy), enforced on top of the preset.
    "anti-slop/no-chained-type-assertions": "error",
    "anti-slop/no-conditional-empty-object-spread": "error",
    "anti-slop/no-known-value-widening": "error",
    "anti-slop/no-module-mocking": "error",
    "anti-slop/no-object-parameters": "error",
    "anti-slop/no-reflect-apply": "error",
    "anti-slop/no-reflect-get": "error",
    "anti-slop/no-runtime-typeof": "error",
    "anti-slop/no-shape-in-symbol-names": "error",
    "anti-slop/no-unknown-parameters": "error",
    "anti-slop/no-unknown-returns": "error",
    "anti-slop/no-unknown-type-aliases": "error",
    "anti-slop/no-unsafe-dictionary-type": "error",
    "anti-slop/no-widen-then-assert": "error",
    "anti-slop/require-safety-comment-for-type-assertion": "error",
  },
  overrides: [
    {
      // vitest rules only apply to test files; the webui assets are never
      // tests, and oxlint does not scope vitest rules by file pattern itself.
      files: ["src/recoverage/assets/**"],
      rules: {
        "vitest/no-conditional-tests": "off",
        "vitest/no-import-node-test": "off",
        "vitest/prefer-called-once": "off",
        "vitest/consistent-test-filename": "off",
        "vitest/prefer-called-times": "off",
        "vitest/prefer-to-be-falsy": "off",
        "vitest/prefer-to-be-truthy": "off",
        "vitest/prefer-to-be-object": "off",
        "vitest/require-hook": "off",
      },
    },
    {
      // CLI tooling may log to stdout/stderr, use Node builtins, sync fs and
      // `./`-relative URLs (the Rika preset already makes this exception for
      // tools, but only for .ts/.mts/.cts — cover .js too).
      files: ["tools/**", "*.config.{ts,js,mjs,cjs}"],
      rules: {
        "eslint/no-console": "off",
        "import/no-nodejs-modules": "off",
        "node/no-sync": "off",
        "unicorn/import-style": "off",
        "unicorn/prefer-import-meta-properties": "off",
        "unicorn/relative-url-style": "off",
        "vitest/no-conditional-tests": "off",
        "vitest/no-import-node-test": "off",
        "vitest/prefer-called-once": "off",
        "vitest/consistent-test-filename": "off",
        "vitest/prefer-called-times": "off",
        "vitest/prefer-to-be-falsy": "off",
        "vitest/prefer-to-be-truthy": "off",
        "vitest/prefer-to-be-object": "off",
        "vitest/require-hook": "off",
      },
      globals: { process: "readonly" },
    },
  ],
});
