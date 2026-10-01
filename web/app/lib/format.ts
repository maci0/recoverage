/** Formatting helpers and the shared user-facing strings.
 *
 * `hex` upper-cases and zero-pads, which is the spelling every address, byte
 * offset and size in the dashboard uses; `percent1`, `percentLabel`, `count`, `dateTime` and
 * `foldForSearch` are the locale-aware spellings the numbers, the timestamps
 * and the search read through; `MSG` is the one vocabulary the shell
 * and the detail panes share, so a loading pane and a loading overlay read the
 * same way; `errorMessage` is the one narrowing a `catch (error: unknown)`
 * reads through. */

/** The message a caught failure is reported by.
 *
 * A `catch` binding is `unknown`, so every call site has to narrow it before
 * it can render, and the narrowings drift: one wrote the message and four
 * wrote a different form of it, and `isPaneMessage` decides whether a pane
 * holds a resting message or a failure by the `Error: ` prefix alone. ONE
 * narrowing, so a site cannot spell it a second way. A thrown non-Error (a
 * `fetch` rejection carries a `TypeError`, a `throw "..."` from a caller does
 * not) reads as its own text, which is what the previous copies rendered. */
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- a `catch` binding IS the boundary this narrows, and narrowing it once here is what stops five call sites narrowing it five ways
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

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

/** A percentage carrying its own sign, as one directional run.
 *
 * The sign is a bidi NEUTRAL, and the digits it sits against are not Latin:
 * `toLocaleString` spells them in the reader's script (Arabic-Indic digits for
 * an Arabic reader, a comma decimal for a German one), so the one character
 * that decides which end of the figure the run reads from has no script of its
 * own. Left alone in a sentence, a reader whose text runs right to left saw the
 * `%` travel to the other side of the number, and a figure stood in a cell did
 * the same beside its label. The isolate keeps number and sign together and
 * hands the surrounding sentence its own direction, which is the half
 * `dir="auto"` cannot cover: it applies to a value standing alone, and every
 * percentage the dashboard prints is interpolated into words the page owns
 * ("NN.N% covered", "similarity NN.N%"). */
export function percentLabel(percentage: number): string {
  return isolate(`${percent1(percentage)}%`);
}

/** A count, grouped the way the reader's locale groups digits. */
export function count(amount: number): string {
  return amount.toLocaleString();
}

/** A raw float reading, written the way the reader's locale writes a decimal.
 *
 * The Data Inspector's `float32` / `float64` cells print the value a PE image
 * stores, and `toPrecision` printed it with a `.` and applied no grouping: a
 * de-DE reader had `3.141593` beside the `count`-formatted integers of the
 * same control, and an ar-EG reader had Latin digits in a row the rest of wrote
 * in Arabic-Indic ones. Grouping is deliberately NOT added here, unlike
 * `count`: a reading of the bytes at an address is a field read digit by digit
 * beside a hex dump, and `1.234.567,5` is harder to read there than
 * `1234567,5` is. The separator is the locale's and the digits are the
 * value's.
 *
 * `maximumFractionDigits: 20` is as many as a double carries, so the reading
 * is the one stored rather than a rounded one. `toPrecision` rounded, and
 * rounded a value a reader can check: a `float64` of `1234567.5` printed as
 * `1234568` beside a hex dump that says otherwise. */
export function reading(measurement: number, locale?: string | ReadonlyArray<string>): string {
  return measurement.toLocaleString(locale, {
    useGrouping: false,
    maximumFractionDigits: 20,
  });
}

/** A count and the noun that agrees with it, in the reader's locale.
 *
 * The forms are supplied by the caller, which is where the English copy lives.
 *
 * A two-form test is not the whole of pluralization: Polish, Russian and
 * Arabic select between categories `count === 1 ? "" : "es"` cannot name
 * (`one`, `few`, `many`, and Arabic's six), so a UI served in one of them
 * printed "1 matches" or "5 match" beside a count that was itself right.
 * `Intl.PluralRules` is the one implementation of those rules the platform
 * already carries, and the omitted *locale* is its own default: the reader's,
 * read from the browser rather than from a locale this package would have to
 * be told about, which is what a caller that names no locale wants. Naming one
 * renders in that locale instead, which is what a language switcher passes and
 * what the test drives. A category the caller supplied no form for falls back
 * to `other` rather than dropping the noun, because a missing form is a
 * missing translation and a missing noun is a broken sentence. */
export function plural(
  amount: number,
  forms: Readonly<Partial<Record<Intl.LDMLPluralRule, string>>>,
  locale?: string | ReadonlyArray<string>,
): string {
  const category = new Intl.PluralRules(locale, { type: "cardinal" }).select(amount);
  return forms[category] ?? forms.other ?? "";
}

/** A bare calendar day, `YYYY-MM-DD`, with no time and no offset. The `u` flag
 * is the Unicode-aware parser; `\d` stays ASCII digits under it, so a
 * non-ASCII digit spelling still fails the test and the stamp falls back to
 * the raw string. */
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/u;

/** A stored timestamp, written the way the reader's locale writes a date and
 * in their own timezone. The documents carry ISO 8601, which is a wire format
 * and not one anyone reads: a German reader gets `29.09.2026, 14:03` and a
 * Japanese one `2026/09/29 14:03`, where the raw string is the same wall time
 * in the writer's zone for both. `Date` parses the string the document holds
 * and `toLocaleString` renders it, so a document that spells the stamp
 * without an offset is read in the reader's zone rather than in the server's
 * (a naive ISO string is local time to whoever wrote it, and the writer is
 * not the reader). A stamp no engine can parse comes back as it arrived: a
 * coverage document is untrusted input, and an unreadable timestamp is worth
 * showing raw, not worth rendering as "Invalid Date".
 *
 * A DATE-ONLY value names a calendar day, not an instant, and the two forms
 * `Date` reads them by are not the same: a bare `2026-09-29` is UTC midnight
 * while a naive `2026-09-29T00:00:00` is the reader's own midnight, so a
 * day-only stamp rendered as parsed read as the 28th for every reader west of
 * UTC (UTC-3 through UTC-11, most of the Americas and the Pacific) and as the
 * 29th only in the zone that wrote it. Appending the time half without an
 * offset puts the day back on the calendar day it names, which is the only
 * reading a value carrying no time of day can support. */
export function dateTime(stamp: string): string {
  const parsed = new Date(DATE_ONLY.test(stamp) ? `${stamp}T00:00:00` : stamp);
  if (Number.isNaN(parsed.getTime())) {
    return stamp;
  }
  return parsed.toLocaleString();
}

/** A 0-1 similarity FRACTION as a rendered percentage, or null when the value
 * is not one.
 *
 * Both similarity columns store a fraction, so the caller scales by 100 and
 * `percent1` floors the result: the same scale-then-floor `potato.
 * _similarity_pct` performs on the Potato side, and for the same reason
 * (a bare `toFixed` there rounded 99.99% up to a "100.0%" the dashboard read
 * as 99.9).
 *
 * The width of the value is the document's, not the declared
 * `similarity?: number` type: `server._plain` only maps a non-finite FLOAT to
 * null, so a string reaches the panel untouched and `"87.3" * 100` is 8730 —
 * a row reading `8,730.0%` where Potato omits the row entirely.  A bool is the
 * same shape (`true * 100 === 100`) and rendered as a real `100.0%`.  A value
 * this cannot scale is one the caller omits, which is what both surfaces do
 * for the same field. */
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- the declared `similarity?: number` is the caller's assumption; the value arrives from the coverage document with whatever width it spells, and narrowing it here is the point
export function similarityPct(fraction: unknown): string | null {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the boundary is exactly "whatever the coverage document carried", and the declared type is the caller's assumption, not this one
  if (typeof fraction !== "number" || !Number.isFinite(fraction)) {
    return null;
  }
  return percentLabel(fraction * 100);
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

/** The spaces a search box rounds off, and only those.
 *
 * `String.prototype.trim` removes every character Unicode calls whitespace:
 * U+00A0, U+2000-U+200A, U+3000 and U+FEFF among them. A term made of a
 * non-breaking space is a real term, not an empty one, and trimming it away
 * made the box search for everything instead of the rows whose name carries
 * that space. Only the space and the six ASCII controls are what a reader
 * types around a term by accident, and they are what
 * `server.strip_ascii_whitespace` removes on the API and Potato side. */
const ASCII_SPACE = /^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/gu;

export function trimSearch(text: string): string {
  return text.replace(ASCII_SPACE, "");
}

/** FIRST STRONG ISOLATE / POP DIRECTIONAL ISOLATE, the pair HTML's `<bdi>`
 * carries. */
const FSI = "\u2068";
const PDI = "\u2069";

/** A value out of a coverage document, isolated from the text around it.
 *
 * Every name the dashboard shows comes from a PE image, so a target whose
 * symbols are Arabic, Hebrew or a mix of both renders text the page's own
 * direction (LTR) does not describe. The Unicode bidirectional algorithm then
 * reorders the run: a cell label next to its address range puts the punctuation
 * on the wrong end, and a trailing digit run moves to the other side of the
 * name. Wrapping the value in an isolate keeps the reordering inside it, where
 * it belongs, and leaves the surrounding sentence alone.
 *
 * `dir="auto"` is the other half and not a substitute: it picks the base
 * direction for an element whose value stands ALONE (a table cell, a panel
 * title), while a value interpolated into a sentence with fixed English around
 * it needs the isolate. Isolates are formatting controls, so a screen reader
 * passes them over rather than announcing them. */
export function isolate(documentText: string): string {
  return `${FSI}${documentText}${PDI}`;
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
  LOADING: "Loading…",
  ASM_LOADING: "Loading the disassembly…",
  ERROR_PREFIX: "Error: ",
  SELECT_FUNCTION: "(select a function)",
  NO_C_SOURCE: "(no C implementation for this function yet)",
  NO_DOCS: "No documentation comments in source file",
  NO_C_FOR_BLOCK: "(no C implementation)",
  UNDOCUMENTED_BLOCK: "(undocumented block)",
  ASM_PLACEHOLDER: "(no disassembly for this block)",
  DATA_SECTION_NO_ASM: "(data section: no disassembly)",
  BYTES_FAILED: "(byte range falls outside the original binary)",
  BYTES_BSS: "(uninitialized data: no bytes in the file)",
  BYTES_LOAD_FAILED:
    "(original binary not found: expected it at /original/ in the project directory)",
  GLOBAL_VAR: "Global variable",
  NA: "(n/a)",
  REGEN_USING_CACHE: (remaining: number) => `Using cached data. Regeneration available in ${remaining}s...`,
  REGEN_IN_PROGRESS: "Regenerating…",
  REGEN_ALREADY_RUNNING:
    "This regeneration is already running. The map refreshes by itself when it finishes.",
  REGEN_DONE: "Coverage data regenerated.",
  REGEN_UNAVAILABLE: "Regeneration unavailable",
  FETCH_FAILED: (url: string) => `(failed to load: ${url})`,
  JUMP_NO_BLOCK: (address: string) =>
    `No block covers ${address} in this target, so there is nothing to select.`,
  NO_DECL: "(no declaration found)",
  DETAIL_UNAVAILABLE: "(the detail view did not load; reload the page)",
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

/** One value percent-encoded for a URL path segment or query value.
 *
 * `encodeURIComponent` throws `URIError: URI malformed` on a lone surrogate,
 * and a target id is a FILENAME: the server reads it with `os.fsdecode`, which
 * is `surrogateescape`, so `coverage-GAME\xff.toml` — legal on ext4, and what a
 * checkout, an archive or a copy from a Windows tool produces — arrives as
 * `GAME\uDCFF`. The list in `/api/targets` carries it, and every request for
 * that target threw on the way out: one undecodable byte in the coverage
 * directory took the dashboard down rather than one row of the picker.
 *
 * `TextEncoder` writes the lone surrogate as the three bytes of U+FFFD, which
 * is what `server.fs_url_quote` would have to invert to land back on the byte
 * the filesystem holds; so the byte is encoded directly instead, one escape
 * per unpaired code unit, which is the exact inverse of the server's
 * `fs_url_quote` (`quote(fs_text_bytes(...))`). Both ends must agree: the
 * server leaves a segment whose escapes are not valid UTF-8 percent-encoded
 * rather than raising (`server.path_param`), and `/potato` reads its own query
 * with `errors="surrogateescape"`.
 *
 * `encodeURIComponent` is still called for everything else, so the escaping
 * alphabet, and every URL this package builds, is unchanged for every value
 * that decodes — which is every value a document can hold, since TOML rejects
 * `\uD800`. */
export function encodeUrlValue(text: string): string {
  let encoded = "";
  for (const character of text) {
    // A lone surrogate is the one character `encodeURIComponent` refuses; the
    // iterator hands it over whole only as a paired unit, so an unpaired half
    // here IS the one case the UTF-16 unit stands alone for.
    const point = character.codePointAt(0) ?? 0;
    if (point >= 0xDC_80 && point <= 0xDC_FF) {
      encoded += percentEscapeFilesystemByte(point);
      continue;
    }
    // Outside the recoverable range — an unpaired HIGH surrogate, which
    // `os.fsdecode` never produces — the byte it stands for does not exist and
    // is not invented here: masking to a byte would spell it `%00`, and a NUL
    // injected into a URL is worse than the escape the server answers with.
    // U+FFFD is what the server's own `errors="surrogateescape"` cannot avoid
    // either, and such a target resolves to nothing on both ends rather than to
    // something else.
    encoded += point >= 0xD8_00 && point <= 0xDF_FF ? "%EF%BF%BD" : encodeURIComponent(character);
  }
  return encoded;
}

/** The byte a lone low surrogate stands for, percent-encoded.
 *
 * U+DC80..U+DCFF is `surrogateescape`'s whole alphabet: it maps that code unit
 * onto the byte it carries in its low eight bits, which is the inverse of the
 * server's `server.fs_text_bytes`. The caller narrows to that range, because
 * nothing outside it is recoverable and the same mask on an unpaired high
 * surrogate spells `%00`. */
function percentEscapeFilesystemByte(codePoint: number): string {
  const byte = codePoint - 0xDC_00;
  return `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
}

/** Every `/`-separated segment of *path* percent-encoded, separators intact.
 *
 * One segment at a time because `/` is the only structure in the value: encode
 * the whole string and a separator becomes a `%2F` inside a path segment. An
 * empty segment (a leading `/`, a trailing one) encodes to the empty string, so
 * both spellings of the same root survive. */
export function encodePathSegments(path: string): string {
  return path.split("/").map((segment) => encodeUrlValue(segment)).join("/");
}

/** The URL of one file under an accepted `sourceRoot`. Both halves are encoded,
 * segment by segment, so a slash or a space survives the round trip and a
 * separator stays a separator.
 *
 * The root is encoded for the same reason the file is, and a `#` is what makes
 * that visible: a document whose `paths.sourceRoot` is `src/a#b` reached the
 * fetch as `src/a#b/a.c`, and the browser resolved the fragment away, so the
 * request went to `/src/a` and the source pane 404'd a file that is sitting on
 * disk. The same `#` inside a file name was already encoded to `%23`. One
 * encoder over the whole value is what stops the two halves disagreeing again;
 * a caller handing in a root it has already encoded double-encodes it, so the
 * fallback roots in `App.tsx` and `originalDllPath` are spelled raw. */
export function sourceFileUrl(sourceRoot: string, file: string): string {
  return `${encodePathSegments(sourceRoot)}/${encodePathSegments(file)}`;
}
