/** The dashboard's API surface.
 *
 * One module owns every path, so a component never spells a URL and the field
 * names the server serves live in one place.  The payloads are the ones
 * `recoverage.api` builds: `sections` always carries every section row, a
 * `?section=` request omits its siblings' `cells` (an absent key, which is the
 * lazy-load signal, not an empty grid), and `?index=0` omits `search_index` the
 * same way, for the caller that already holds it. */

import { MSG } from "@/lib/format";

/** One coverage cell, in spatial order. Optional keys are omitted by the
 * server rather than sent as null (`server._cell_json`). */
export type Cell = {
  start: number;
  end: number;
  span: number;
  state: string;
  /** The function(s) covering the cell: a name, or a VA spelling. */
  functions?: Array<string | number>;
  label?: string;
  /** The NAME of the function a data or thunk cell belongs to, not its VA:
   * `rebrew.catalog.grid` writes `func_end_to_name[off]` here, and the Potato
   * panel beside this one resolves it the same way (`potato._parent_url`).
   * A reader that treats it as an address jumps nowhere. */
  parent_function?: string;
};

export type Section = {
  target: string;
  name: string;
  /** A section the document does not place (`rebrew` writes NULL for a
   * section with no VA, and a .bss with no file backing carries no
   * `fileOffset`), so both are null rather than 0. A reader that adds them
   * without a guard maps a section at address 0. */
  va: number | null;
  size: number;
  fileOffset: number | null;
  unitBytes: number;
  columns: number;
  /** Absent when the request named another section. */
  cells?: Array<Cell>;
};

export type CellBucket = {
  total_cells: number;
} & Record<string, number>;

/** One section's row from `/stats`: the buckets `/data` serves, plus the byte
 * sums only the stats reader computes. */
export type SectionStats = CellBucket & {
  matched: number;
  covered_bytes: number;
  total_bytes: number;
  coverage_pct: number;
  size_bytes: number;
};

/** The `.text` grid block of `/stats`'s `summary`, plus one entry per non-`.text`
 * section keyed by the section name (`server._section_summary`). */
export type SummaryBlock = {
  totalFunctions: number;
  matchedFunctions: number;
  exactMatches: number;
  relocMatches: number;
  nearMatchCount: number;
  stubCount: number;
  coveredBytes: number;
  paddingBytes: number;
  dataBytes: number;
  thunkBytes: number;
  coveragePercent: number;
  textSize: number;
};

export type SectionSummary = {
  exactMatches: number;
  relocMatches: number;
  nearMatchCount: number;
  stubCount: number;
  paddingCount: number;
  exactBytes: number;
  relocBytes: number;
  nearMatchBytes: number;
  stubBytes: number;
  paddingBytes: number;
  coveredBytes: number;
  totalFunctions: number;
  size: number | null;
};

export type StatsPayload = {
  target: string;
  /** The fixed keys, and one `SectionSummary` per non-`.text` section, named
   * by the section. */
  summary: SummaryBlock & Record<string, number | SectionSummary>;
  sections: Record<string, SectionStats>;
  /** Function counts by rebrew's status vocabulary (`server._section_stats`),
   * which is the same vocabulary `?status=` filters on. */
  functions_by_status: Record<string, number>;
};

export type SearchEntry = {
  /** The entry's address as the server spells it, and the two spellings are
   * NOT the same: `api._build_search_index` writes `vaStart` (a number) for a
   * function entry and `hex(va)` (a string) for a global one, so this is
   * `string | number` rather than either. Read through `toVa`; `hex(entry.va)`
   * on the number arm hands back `0X0X10001000` and matches nothing. */
  va: string | number;
  symbol?: string;
  name?: string;
};

export type DataPayload = {
  sections: Record<string, Section>;
  section_cell_stats?: Record<string, CellBucket>;
  /** Absent when the request asked with `index=0`. */
  search_index?: Record<string, SearchEntry>;
  known_schema?: Array<string>;
  db_version?: number;
  paths?: { sourceRoot?: string; originalDll?: string };
};

export type TargetInfo = {
  id: string;
  name: string;
};

export type TargetsPayload = {
  targets: Array<TargetInfo>;
};

/** `cache: "no-cache"` on every read: the server answers 304 from its ETag, so
 * a rebuild is picked up on the next request instead of after a freshness
 * lifetime. This is the SPA's contract with `/api/targets/*\/data`. */
const NO_CACHE: RequestInit = { cache: "no-cache" };

function init(signal?: AbortSignal): RequestInit {
  // `exactOptionalPropertyTypes` is on, so an absent signal is an absent key
  // rather than an explicit `undefined`.
  return signal === undefined ? NO_CACHE : { ...NO_CACHE, signal };
}

export async function fetchTargets(signal?: AbortSignal): Promise<Array<TargetInfo>> {
  const res = await fetch("/api/targets", init(signal));
  if (!res.ok) {
    throw new Error(await refusal(res));
  }
  // SAFETY: the response is this origin's own JSON, whose shape
  // `recoverage.api.handle_api_targets` pins to `{"targets": [...]}`.
  const body = (await res.json()) as TargetsPayload;
  return body.targets ?? [];
}

export async function fetchData(
  target: string,
  section: string | null,
  signal?: AbortSignal,
  withSearchIndex = true,
): Promise<DataPayload> {
  const query = new URLSearchParams();
  if (section !== null) {
    query.set("section", section);
  }
  if (!withSearchIndex) {
    // The index is target-wide, so the section-switch request says it already
    // has one and the server omits the key rather than re-sending it.
    query.set("index", "0");
  }
  const suffix = query.size === 0 ? "" : `?${query.toString()}`;
  const res = await fetch(`/api/targets/${encodeURIComponent(target)}/data${suffix}`, init(signal));
  if (!res.ok) {
    throw new Error(await refusal(res));
  }
  // SAFETY: this origin's own JSON, whose shape
  // `recoverage.api._build_data_raw` pins: the fields read below are the ones
  // it writes, and the cells splice never changes the envelope.
  return (await res.json()) as DataPayload;
}

export async function fetchStats(target: string, signal?: AbortSignal): Promise<StatsPayload> {
  const res = await fetch(`/api/targets/${encodeURIComponent(target)}/stats`, init(signal));
  if (!res.ok) {
    throw new Error(await refusal(res));
  }
  // SAFETY: this origin's own JSON, whose shape
  // `recoverage.api.handle_api_stats` pins: `summary` and `sections` are the
  // rows `recoverage.server._section_stats` writes.
  return (await res.json()) as StatsPayload;
}

/** A function or global as `/api/targets/<t>/functions/<va>` serves it. */
export type FunctionDetail = {
  va: string | number;
  /** Set by the dashboard for a `/functions/<va>` row in a non-.text section. */
  isGlobal?: boolean;
  name: string;
  vaStart?: string | number;
  size?: number;
  fileOffset?: number | null;
  symbol?: string | null;
  status?: string;
  module?: string;
  cflags?: string | null;
  markerType?: string | null;
  blocker?: string | null;
  blockerDelta?: number | null;
  ghidra_name?: string | null;
  list_name?: string | null;
  size_reason?: string | null;
  similarity?: number | null;
  is_thunk?: boolean;
  is_export?: boolean;
  sha256?: string | null;
  files?: Array<string>;
  /** Every key `server.function_json` writes is declared here, so a field the
   * server serves is never out of this type's reach. */
  detected_by?: Array<string>;
  size_by_tool?: string | null;
  textOffset?: number | null;
  updated_by?: string | null;
  updated_at?: string | null;
  decl?: string | null;
  last_verify?: {
    verified_at?: string;
    byte_delta?: number | null;
    diff_lines?: number | null;
    similarity?: number | null;
    reg_delta?: number | null;
    effective_match?: boolean;
  } | null;
};

export type AsmPayload = { asm?: string; error?: string; detail?: string };

/** The part of `server._json_err`'s envelope a pane quotes. */
type ErrorEnvelope = { error?: string; detail?: string };

/** What a body that is not the error contract parses to: the status line is
 * the only thing left to read, and the caller already has it. */
const NO_ENVELOPE: ErrorEnvelope = {};

/** The regen POST's own body shape, and the error envelope's: one response
 * carries one of them, and a caller reading a refusal needs both the status
 * and the words that came with it. */
type RegenEnvelope = ErrorEnvelope & { ok?: boolean; in_progress?: boolean };

/** The reason a JSON endpoint refused, read as the pane states it.
 *
 * `server._json_err` sends `{error, code, detail}` for every failure, so the
 * reason is in the body rather than in the status alone. */
async function refusal(res: Response): Promise<string> {
  // SAFETY: this origin's own JSON, whose shape `recoverage.server._json_err`
  // pins. A body outside that contract (a proxy's HTML error page) parses to
  // nothing to read, which is the empty envelope, not a wrong answer.
  return describeRefusal(res, await res.json().catch(() => NO_ENVELOPE));
}

/** Render a refusal from a body that has already been read.
 *
 * Split from `refusal` because a `Response` body is a stream: reading it
 * twice throws, so a caller that needs the envelope for its own decision
 * (the regen POST) and the message for the reader has to read once and render
 * from what it read. */
function describeRefusal(res: Response, payload: ErrorEnvelope): string {
  const status = `${res.status} ${res.statusText}`;
  const headline = payload.error ?? status;
  const reason = payload.detail ? `${headline}: ${payload.detail}` : headline;
  // The server mints a correlation id on every response and stamps it on
  // every log line it writes (`server._RequestIdFilter`). Carrying it in the
  // message is what lets a reader who reports "the map failed to load" hand
  // the operator something they can grep: without it the browser holds the
  // error and the server holds the line, and nothing joins them. Absent only
  // when something between here and the app answered (a proxy's own error
  // page), where the header is not the one this dashboard minted.
  const id = res.headers.get("X-Request-ID");
  return id === null ? reason : `${reason} [request ${id}]`;
}

export async function fetchFunction(
  target: string,
  va: string | number,
  signal?: AbortSignal,
): Promise<FunctionDetail> {
  const res = await fetch(
    `/api/targets/${encodeURIComponent(target)}/functions/${encodeURIComponent(String(va))}`,
    init(signal),
  );
  if (!res.ok) {
    // The server's own reason, not a fixed "Not found": this route answers 404
    // for an unknown VA and also 401 without a token and 503 when the coverage
    // document is unreadable, and a pane reading "Not found" for either of
    // those names the wrong cause. `fetchAsm` reads the same envelope.
    throw new Error(await refusal(res));
  }
  // SAFETY: this origin's own JSON, whose shape `recoverage.server.function_json`
  // pins: the fields read below are the ones it writes.
  return (await res.json()) as FunctionDetail;
}

export async function fetchAsm(
  target: string,
  address: string | number,
  size: number,
  section: string,
  signal?: AbortSignal,
): Promise<string> {
  const query = `?va=${encodeURIComponent(String(address))}&size=${size}&section=${encodeURIComponent(section)}`;
  const res = await fetch(`/api/targets/${encodeURIComponent(target)}/asm${query}`, init(signal));
  // SAFETY: this origin's own JSON, whose shape `recoverage.api.handle_api_asm`
  // pins to `{asm}` or `{error, detail}`.
  const payload = (await res.json()) as AsmPayload;
  if (payload.asm !== undefined && payload.asm !== "") {
    return payload.asm;
  }
  if (payload.error !== undefined) {
    // The endpoint answers failures with {error, detail}; showing that beats a
    // generic fallback, which would blame the wrong cause.
    return `(${payload.error}${payload.detail === undefined ? "" : `: ${payload.detail}`})`;
  }
  return MSG.ASM_PLACEHOLDER;
}

/** C source and the original binary are not API routes: they are the project's
 * own files, served from `/src/...` and `/original/...`. A failure is a pane
 * message, not an exception, because both panes render their own state. */
export async function fetchTextSafe(url: string | null, signal?: AbortSignal): Promise<string> {
  if (url === null) {
    return MSG.NO_C_SOURCE;
  }
  try {
    const res = await fetch(url, init(signal));
    if (!res.ok) {
      return MSG.FETCH_FAILED(url);
    }
    return await res.text();
    // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a missing source file renders as the pane's own "(failed to load: …)" text; only an abort is re-thrown
  } catch (error: unknown) {
    if (signal?.aborted === true) {
      throw error;
    }
    return MSG.FETCH_FAILED(url);
  }
}

export async function fetchArrayBufferSafe(
  url: string,
  signal?: AbortSignal,
): Promise<ArrayBuffer | null> {
  try {
    const res = await fetch(url, init(signal));
    if (!res.ok) {
      return null;
    }
    return await res.arrayBuffer();
    // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a missing binary is a supported state: the bytes pane says so, and callers read null
  } catch {
    return null;
  }
}

/** The outcome of one regenerate action.
 *
 * `reason` is set only when the server refused the POST: it carries the
 * envelope's own words and the request id, so the notice the reader is left
 * looking at is the one an operator can grep in the server log. */
export type RegenResult = { ok: boolean; inProgress: boolean; reason?: string };

/** The ledger key for one regenerate action. */
export type RegenKey = string;

/** Mint the key for ONE regenerate action, at the action site.
 *
 * The server keeps a completed key for a bounded window and answers a later
 * request carrying it from that ledger instead of re-running the pipeline, so
 * the key identifies the action, not the request: a re-send of the same action
 * has to present the same key or the ledger never engages.  A key minted per
 * request would make every re-send a fresh one.
 *
 * `randomUUID` needs a secure context, which a plain-HTTP LAN visit is not.
 */
export function newRegenKey(): RegenKey {
  return crypto.randomUUID === undefined
    ? `${Date.now()}-${Math.random().toString(36).slice(2)}`
    : crypto.randomUUID();
}

function sendRegen(key: RegenKey): Promise<Response> {
  return fetch("/api/regen", {
    method: "POST",
    cache: "no-store",
    headers: { "Idempotency-Key": key },
  });
}

/** Regenerate, re-sending once on a transport failure with the SAME *key*.
 *
 * A `fetch` that throws never got an answer, and the answer is the only thing
 * that says whether the pipeline ran: the run is minutes long, the response
 * can be lost on the way back, and the documents on disk are already the new
 * ones.  The re-send is answered from the ledger when the first run completed,
 * answered 202 when the first run is still going, and runs the pipeline once
 * when the first request never arrived.  It never re-sends an answered
 * request, because re-sending a refusal the server gave on purpose would turn
 * a 429 into a second pipeline.
 */
export async function postRegen(key: RegenKey): Promise<RegenResult> {
  const res = await sendRegen(key).catch(() => sendRegen(key));
  // SAFETY: this origin's own JSON; `handle_regen` answers `{"ok": bool}` and,
  // for a retry of a run still going, `{"ok": true, "in_progress": true}`.
  // Guarded, because a refusal is not that body: a 401 page from an expired
  // share link, a proxy's 502 HTML, or the endpoint's own 403/429/500
  // envelope. An unguarded `res.json()` threw a SyntaxError out of this
  // function, and every one of those reached the reader as the same
  // "regeneration unavailable" line with no status, no reason and no id.
  const payload: RegenEnvelope = await res.json().catch(() => NO_ENVELOPE);
  if (!res.ok) {
    // The reason rides along in the notice rather than being dropped: a 429
    // means somebody else's run is going, a 403 means this page was not
    // allowed to ask, and a 500 names the failure the server logged. The
    // request id is what turns any of them into a line in the server log.
    return {
      ok: false,
      inProgress: res.status === 202,
      reason: describeRefusal(res, payload),
    };
  }
  // `in_progress` is not `ok`: the run was accepted and has not finished, so
  // reporting it as done would claim documents the pipeline has not written.
  return { ok: payload.ok === true && payload.in_progress !== true, inProgress: payload.in_progress === true };
}
