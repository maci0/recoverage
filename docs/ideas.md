# Recoverage API Improvement Ideas

Ideas for extending and improving the recoverage REST API and CLI.

---

## New API Endpoints

### ~~`GET /api/targets/<target>/stats`~~ ✅ Implemented
Lightweight summary endpoint returning only coverage stats (percentages, byte counts, function counts by status) without any cell/grid data. Useful for CI badges, external dashboards, and quick terminal checks.

### ~~`GET /api/targets/<target>/functions`~~ ✅ Implemented
Paginated function listing with optional filters (`?status=&search=&sort=&limit=&offset=`).

### `GET /api/targets/<target>/diff/<va>`
Return a structural diff between the compiled output and the original bytes for `MATCHING` and `STUB` functions. Wraps the existing `matcher.py --diff` logic. The frontend could render this inline instead of requiring the user to run CLI commands.

### `GET /api/targets/<target>/xrefs/<va>`
Cross-reference lookup — which functions call this VA, and which VAs does this function call. Requires building a call graph from the disassembly (Capstone) or from annotation metadata (`// CALLERS:`, `// CALLEES:`).

### ~~`GET /api/targets/<target>/sections/<section>/bytes`~~ ✅ Implemented
Raw byte slice endpoint with `?offset=N&size=M` params.

### ~~`GET /api/health`~~ ✅ Implemented
Simple health check returning server version, DB path, DB size, DB mtime, optional extras installed, and available targets count.

### `POST /api/targets/<target>/functions/<va>/annotate`
Write-back annotations to source files. Accept a JSON body with annotation key-value pairs (`NOTE`, `BLOCKER`, `STATUS`, etc.) and patch the corresponding `.c` file. Enables in-browser editing of annotations without leaving the dashboard.

---

## Existing Endpoint Improvements

### ~~`/api/targets/<target>/data` — Partial Loading~~ ✅ Implemented
The `/data` endpoint supports `?section=.text` to load one section at a time.

### `/api/targets/<target>/functions/<va>` — Batch Mode
Support batch function lookups via POST with a JSON array of VAs:
```json
{ "vas": ["0x10001000", "0x10001050", "0x10001100"] }
```
Returns an array of function details in one round-trip. Useful for preloading adjacent cells.

### ~~`/api/targets/<target>/asm` — Output Formats~~ ✅ Implemented
Supports `?format=json` for structured instruction objects.

### Error Responses — Consistency
Standardize all error responses to include `{ "error": "...", "code": "...", "detail": "..." }`. Currently some return `{"ok": false, "error": "..."}` and others return `{"error": "..."}`.

### ~~CORS Headers~~ ✅ Implemented
Optional CORS support via `--cors` flag.

---

## CLI Improvements (Typer)

### ~~`recoverage stats` Subcommand~~ ✅ Implemented
Print a terminal-friendly coverage summary table (using `rich.table`) without starting the web server.

### ~~`recoverage export` Subcommand~~ ✅ Implemented
Export coverage data to JSON, CSV, or Markdown for use in CI pipelines, READMEs, and reports.

### ~~`recoverage check` Subcommand~~ ✅ Implemented
CI-oriented: exits non-zero if coverage drops below a threshold.

### ~~`recoverage open` Subcommand~~ ✅ Implemented
Open the browser to an existing running server (useful when `--no-open` was used at startup).

---

## WebSocket / SSE Support

### Live Reload via Server-Sent Events
Add a `/api/events` SSE stream that pushes `db-updated` events when `coverage.db` is modified (using `watchdog` or inotify). The frontend can auto-refresh the grid without polling or manual reload clicks.

### Regen Progress
Stream `/api/regen` progress as SSE events instead of blocking until completion (which can timeout for large projects).

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

### ~~Rate Limiting on `/api/regen`~~ ✅ Implemented
The 5-second cooldown now exists server-side too: `/api/regen` returns 429
with `retry_after` when called within `_REGEN_COOLDOWN_SECONDS` of the last
accepted attempt, so direct API calls cannot hammer `rebrew catalog`/`build-db`.
