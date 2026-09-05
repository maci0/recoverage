#!/usr/bin/env node
// Lint the dashboard's HTML and CSS with the Nu Html Checker (vnu.jar).
//
//   HTML files are validated directly.
//   CSS files are validated with `--css`, which forces the checker into
//     CSS-validation mode (vnu cannot parse a bare .css file as HTML).
//
// The gate fails on any vnu message of any severity — nothing is skipped.
//
// Every HTML/CSS file shipped in the assets directory is covered, including
// the vendored highlight.js theme (hljs.css) — it is served as our CSS too.
// The served documents (SPA shell with injected CSS/JS, Potato Mode) are
// validated separately by tools/lint-served-html.py.
//
// Requires: java on PATH, and `bun install` already run (for vnu-jar).
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const assetsDir = join(root, "src", "recoverage", "assets");
const vnuJar = join(root, "node_modules", "vnu-jar", "build", "dist", "vnu.jar");

const HTML_FILES = ["index.html"];
const CSS_FILES = ["hljs.css", "print.css", "style.css"];

if (!existsSync(vnuJar)) {
  console.error("vnu.jar not found; run `bun install` first.");
  process.exit(2);
}

/** Run vnu over the given asset files, exiting non-zero on any message. */
function runVnu(args, files) {
  const paths = files.map((f) => join(assetsDir, f));
  const cmd = ["-jar", vnuJar, ...args, ...paths];
  console.log(`vnu: java ${cmd.join(" ")}`);
  try {
    execFileSync("java", cmd, { stdio: "inherit" });
  } catch (error) { // oxlint-disable-line @rikalabs/no-silent-catch-fallback -- CLI: log the failure and exit with vnu's status code
    console.error(`HTML/CSS lint failed: ${error.status ?? "unknown"} exit code.`);
    process.exit(error.status ?? 1);
  }
}

runVnu([], HTML_FILES);
runVnu(["--css"], CSS_FILES);
console.log("HTML/CSS lint passed.");
