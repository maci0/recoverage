/** Formatting helpers and the shared user-facing strings.
 *
 * `hex` upper-cases and zero-pads, which is the spelling every address, byte
 * offset and size in the dashboard uses; `percent1`, `count` and
 * `foldForSearch` are the locale-aware spellings the numbers and the search
 * read through; `MSG` is the one vocabulary the shell
 * and the detail panes share, so a loading pane and a loading overlay read the
 * same way. */

export function hex(address: number, width: number): string {
  return `0x${address.toString(16).toUpperCase().padStart(width, "0")}`;
}

/** Decimal places every percentage is printed at, and the scale that floors it. */
const PERCENT_DECIMALS = 1;
const PERCENT_SCALE = 10 ** PERCENT_DECIMALS;

/** The slack `server.pct_1dp` gets from `"%.1f"` in C: multiplying by the
 * scale and flooring has to absorb the binary error, or 0.7 arrives as
 * 6.999999999999999 and the last digit drops. One part in 10^9 of a percentage
 * point is below anything the server can serve (it floors to 2dp first), so it
 * cannot turn a real 99.99 into 100.0. */
const PERCENT_SLACK = 1e-9;

/** A served percentage, floored and written the way the reader's locale writes
 * a decimal. `toFixed` would do neither: it rounds 99.99 up to "100.0", which
 * is the figure `server.coverage_pct` exists to keep off the page, and it emits
 * a `.` decimal separator to a reader whose locale writes a `,`. */
export function percent1(percentage: number): string {
  const floored = Math.floor(percentage * PERCENT_SCALE + PERCENT_SLACK) / PERCENT_SCALE;
  return floored.toLocaleString(undefined, {
    minimumFractionDigits: PERCENT_DECIMALS,
    maximumFractionDigits: PERCENT_DECIMALS,
  });
}

/** A count, grouped the way the reader's locale groups digits. */
export function count(amount: number): string {
  return amount.toLocaleString();
}

/** The case fold `server.fold_text` performs, as far as JavaScript can. NFC
 * composition and `toLowerCase` cover every one-code-point-to-one mapping;
 * full case folding also has the one-to-many ones, and `toLowerCase` has no
 * operator for those, so `straße` and a search for `ss` never meet. The map is
 * the Latin, Greek and punctuation set a PE symbol name can carry, and both
 * sides of a search go through it, so the SPA agrees with the API on which
 * rows a term matches. */
const FULL_FOLD = new Map<string, string>([
  ["ß", "ss"],
  ["ŉ", "ʼn"],
  ["ς", "σ"],
  ["ﬀ", "ff"],
  ["ﬁ", "fi"],
  ["ﬂ", "fl"],
  ["ﬃ", "ffi"],
  ["ﬄ", "ffl"],
  ["ﬅ", "st"],
  ["ﬆ", "st"],
]);

const FULL_FOLD_PATTERN = /[ßŉςﬀ-ﬆ]/gu;

/** The one form a name is searched in, on both sides of the comparison.
 *
 * The dashboard's search runs here, over the `search_index` the server served,
 * while `/functions?search=` and the Potato list run `server.fold_match`. Two
 * surfaces answering the same question have to compare in the same form, or
 * the SPA reports "0 matches" beside a row the API lists.
 *
 * `normalize("NFC")` is the step `toLowerCase` does not do: a coverage
 * document written from macOS spells a name NFD ("cafe" + U+0301), the NFC
 * spelling is what a user types, and the two are different strings to a
 * substring test. Composition also runs first because composing after
 * lowercasing is not the same thing on every input. */
export function foldForSearch(text: string): string {
  return text
    .normalize("NFC")
    .toLowerCase()
    .replace(FULL_FOLD_PATTERN, (character) => FULL_FOLD.get(character) ?? character);
}

/** VAs cross the API boundary as hex strings ("0x10001000") or plain numbers
 * (/functions/<va> emits a decimal number). Parse only strings as hex: routing
 * a number through parseInt(x, 16) reads its decimal digits as base-16. */
export function toVa(raw: string | number): number {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the boundary contract is exactly "hex string | number"; decode here so no call site re-parses
  return typeof raw === "string" ? Number.parseInt(raw, 16) : raw;
}

/** The annotation comments a decompiled C file carries, in the order they
 * appear: what the analyst recorded about the function. `null` when the source
 * is a pane message rather than source. */
export function extractDocs(source: string): string | null {
  if (source === "" || source.startsWith("(no C") || source.startsWith("(failed")) {
    return null;
  }
  const prefixes = [
    "// NOTE:",
    "// BLOCKER:",
    "// FUNCTION:",
    "// STATUS:",
    "// ORIGIN:",
    "// SIZE:",
    "// CFLAGS:",
    "// SYMBOL:",
  ];
  const docs = source
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => prefixes.some((prefix) => line.startsWith(prefix)));
  return docs.length > 0 ? docs.join("\n") : null;
}

export const MSG = {
  LOADING: "Loading...",
  ASM_LOADING: "Loading assembly...",
  ERROR_PREFIX: "Error: ",
  SELECT_FUNCTION: "(select a function)",
  NO_C_SOURCE: "(no C implementation for this function yet)",
  NO_DOCS: "No documentation comments in source file",
  NO_C_FOR_BLOCK: "(no C implementation)",
  UNDOCUMENTED_BLOCK: "(undocumented block)",
  ASM_PLACEHOLDER: "(no disassembly for this block)",
  DATA_SECTION_NO_ASM: "(Data section - no assembly)",
  BYTES_FAILED: "(byte range falls outside the original binary)",
  BYTES_BSS: "(uninitialized data - no raw bytes)",
  BYTES_LOAD_FAILED:
    "(original binary not found: expected it at /original/ in the project directory)",
  GLOBAL_VAR: "Global variable",
  NA: "(n/a)",
  REGEN_USING_CACHE: (remaining: number) => `Using cached data. Regeneration available in ${remaining}s...`,
  REGEN_IN_PROGRESS: "Regenerating...",
  REGEN_DONE: "Coverage data regenerated.",
  REGEN_UNAVAILABLE: "Regeneration unavailable",
  FETCH_FAILED: (url: string) => `(failed to load: ${url})`,
  JUMP_NO_BLOCK: (address: string) =>
    `No block covers ${address} in this target, so there is nothing to select.`,
  NO_DECL: "(no declaration found)",
  DETAIL_UNAVAILABLE: "(detail view failed to load — reload the page)",
} as const;

/** `paths.sourceRoot` and `paths.originalDll` come out of the coverage
 * documents, so a document built from a hostile binary can hold any string.
 * Spliced into an href or a fetch, "//evil.example" is a protocol-relative URL
 * and "/\\evil.example" is the same thing once a browser normalizes the
 * backslash: either one sends the analyst's browser off-origin. Only a
 * same-origin path is accepted — a leading "/" or a relative one, carrying no
 * backslash, no scheme and no control character — and anything else falls back
 * to the server-proxied default. The colon test is positional: after the first
 * "/" a colon is an ordinary character in a path segment, before it a colon
 * starts a scheme. */
export function sameOriginPath(rawPath: string, fallback: string): string {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the boundary is exactly "string from the coverage document"; a number here is a document that cannot be linked to, so it falls back
  if (typeof rawPath !== "string" || rawPath === "") {
    return fallback;
  }
  if (rawPath.startsWith("//") || rawPath.includes("\\")) {
    return fallback;
  }
  for (const character of rawPath) {
    const point = character.codePointAt(0) ?? 0;
    if (point <= 0x1F || point === 0x7F) {
      return fallback;
    }
  }
  const colon = rawPath.indexOf(":");
  if (colon !== -1 && (!rawPath.includes("/") || colon < rawPath.indexOf("/"))) {
    return fallback;
  }
  return rawPath;
}

/** The URL of one file under an accepted `sourceRoot`. Each segment is
 * encoded on its own, so a file name carrying a slash or a space survives
 * the round trip and a separator stays a separator. */
export function sourceFileUrl(sourceRoot: string, file: string): string {
  return `${sourceRoot}/${file.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`;
}
