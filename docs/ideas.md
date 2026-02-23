# Recoverage API Improvement Ideas

Ideas for extending and improving the recoverage REST API and CLI.

---

## New API Endpoints

### `GET /api/targets/<target>/stats`
Lightweight summary endpoint returning only coverage stats (percentages, byte counts, function counts by status) without any cell/grid data. Useful for CI badges, external dashboards, and quick terminal checks.

```json
{
  "target": "SERVER",
  "total_bytes": 524288,
  "matched_bytes": 312000,
  "coverage_pct": 59.5,
  "by_status": { "exact": 120, "reloc": 45, "matching": 30, "stub": 80 }
}
```

### `GET /api/targets/<target>/functions`
Paginated function listing with optional filters. Currently the only way to get function data is the heavy `/data` endpoint (all cells) or the per-function `/functions/<va>` endpoint (one at a time). This middle ground enables search UIs and external tooling.

```
?status=stub&limit=50&offset=0&sort=size:desc&search=render
```

### `GET /api/targets/<target>/diff/<va>`
Return a structural diff between the compiled output and the original bytes for `MATCHING` and `STUB` functions. Wraps the existing `matcher.py --diff` logic. The frontend could render this inline instead of requiring the user to run CLI commands.

### `GET /api/targets/<target>/xrefs/<va>`
Cross-reference lookup — which functions call this VA, and which VAs does this function call. Requires building a call graph from the disassembly (Capstone) or from annotation metadata (`// CALLERS:`, `// CALLEES:`).

### `GET /api/targets/<target>/sections/<section>/bytes`
Raw byte slice endpoint with `?offset=N&size=M` params. Currently the frontend fetches the entire DLL as an ArrayBuffer via `/original/target.dll`. This endpoint would avoid the full download for tools that only need small ranges.

### `GET /api/health`
Simple health check returning server version, DB path, DB size, DB mtime, optional extras installed (capstone, brotli, etc.), and available targets count. Useful for monitoring and scripting.

```json
{
  "version": "0.1.0",
  "db": "db/coverage.db",
  "db_size_bytes": 2097152,
  "db_mtime": "2026-02-23T12:00:00Z",
  "extras": { "capstone": true, "brotli": true, "zstd": false, "minify": true },
  "targets_count": 3
}
```

### `POST /api/targets/<target>/functions/<va>/annotate`
Write-back annotations to source files. Accept a JSON body with annotation key-value pairs (`NOTE`, `BLOCKER`, `STATUS`, etc.) and patch the corresponding `.c` file. Enables in-browser editing of annotations without leaving the dashboard.

---

## Existing Endpoint Improvements

### `/api/targets/<target>/data` — Partial Loading
The `/data` endpoint currently returns *all* sections and cells for a target. For large binaries this can be 500KB+. Add a `?section=.text` query param to load one section at a time, and let the frontend fetch sections lazily on tab switch.

### `/api/targets/<target>/functions/<va>` — Batch Mode
Support batch function lookups via POST with a JSON array of VAs:
```json
{ "vas": ["0x10001000", "0x10001050", "0x10001100"] }
```
Returns an array of function details in one round-trip. Useful for preloading adjacent cells.

### `/api/targets/<target>/asm` — Output Formats
Add `?format=json` to return structured instruction objects instead of plain text:
```json
[
  { "addr": "0x10003da0", "mnemonic": "push", "op_str": "ebp", "size": 1 },
  { "addr": "0x10003da1", "mnemonic": "mov", "op_str": "ebp, esp", "size": 2 }
]
```
Enables richer frontend rendering (per-instruction highlighting, jump arrows, register tracking).

### Error Responses — Consistency
Standardize all error responses to include `{ "error": "...", "code": "...", "detail": "..." }`. Currently some return `{"ok": false, "error": "..."}` and others return `{"error": "..."}`.

### CORS Headers
Add optional CORS support (`--cors` flag) so external tools and browser extensions can query the API from other origins.

---

## CLI Improvements (Typer)

### `recoverage stats` Subcommand
Print a terminal-friendly coverage summary table (using `rich.table`) without starting the web server. Reads `coverage.db` directly.

```
$ recoverage stats
┌────────┬───────────┬─────────┬──────────┐
│ Section│ Total     │ Matched │ Coverage │
├────────┼───────────┼─────────┼──────────┤
│ .text  │ 524288 B  │ 312000  │ 59.5%    │
│ .data  │ 65536 B   │ 65536   │ 100.0%   │
└────────┴───────────┴─────────┴──────────┘
```

### `recoverage export` Subcommand
Export coverage data to JSON, CSV, or Markdown for use in CI pipelines, READMEs, and reports.

```
$ recoverage export --format json --target SERVER > coverage.json
$ recoverage export --format md --target SERVER >> README.md
```

### `recoverage check` Subcommand
CI-oriented: exits non-zero if coverage drops below a threshold.

```
$ recoverage check --min-coverage 60 --target SERVER
ERROR: .text coverage 59.5% is below threshold 60%
```

### `recoverage open` Subcommand
Just open the browser to an existing running server (useful when `--no-open` was used at startup).

---

## WebSocket / SSE Support

### Live Reload via Server-Sent Events
Add a `/api/events` SSE stream that pushes `db-updated` events when `coverage.db` is modified (using `watchdog` or inotify). The frontend can auto-refresh the grid without polling or manual reload clicks.

### Regen Progress
Stream `/regen` progress as SSE events instead of blocking until completion (which can timeout for large projects).

---

## Performance

### Response Streaming
For very large targets, stream the `/data` JSON response using chunked transfer encoding instead of materializing the entire payload in memory.

### Pre-compressed Cache Files
Write `.br` and `.gz` cache files to disk for the inlined index and large JSON payloads. Avoids re-compressing on every cold start.

### Connection Pooling
Replace per-request `sqlite3.connect()` calls with a thread-local connection pool to avoid connection setup overhead.

---

## Security

### `--bind` Flag
Allow binding to a specific interface (default: `127.0.0.1`). Some users may want `0.0.0.0` for LAN access; the current hardcoded localhost is correct for security but inflexible.

### Rate Limiting on `/regen`
The 5-second cooldown exists in the frontend but not the backend. Add server-side rate limiting to prevent abuse via direct API calls.
