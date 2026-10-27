# Recoverage API Improvement Ideas

Open ideas for extending the recoverage REST API and CLI. Shipped behavior is
documented in [REFERENCE.md](REFERENCE.md) and recorded in the
[changelog](../CHANGELOG.md).

---

## New API Endpoints

### `GET /api/targets/<target>/diff/<va>`
Return a structural diff between the compiled output and the original bytes for `MATCHING` and `STUB` functions. Wraps the existing `rebrew diff` logic. The frontend could render this inline instead of requiring the user to run CLI commands. Tracked as **Diff View** in [DESIGN.md](DESIGN.md#future-ideas--todos), which is the canonical list.

### `GET /api/targets/<target>/xrefs/<va>`
Cross-reference lookup: which functions call this VA, and which VAs this function calls. Requires building a call graph from the disassembly (Capstone) or from annotation metadata (`// CALLERS:`, `// CALLEES:`). Tracked as **XREFs** in [DESIGN.md](DESIGN.md#future-ideas--todos), which is the canonical list.

### `POST /api/targets/<target>/functions/<va>/annotate`
Write annotations back from the dashboard. Accept a JSON body with annotation key-value pairs (`note`, `blocker`, `STATUS`, etc.) and write them through Rebrew's metadata owners; function documentation lives in dedicated Rebrew metadata, not in source comments. Enables in-browser editing of annotations without leaving the dashboard.

---

## WebSocket / SSE Support

### Regen Progress
Stream `/api/regen` progress as SSE events instead of blocking the request until completion (a long regen keeps the connection open for its whole run).

---

## Performance

### Response Streaming
For very large targets, stream the `/data` JSON response using chunked transfer encoding instead of materializing the entire payload in memory.

### Pre-compressed Cache Files
Write `.br` and `.gz` cache files to disk for the inlined index and large JSON payloads. Avoids re-compressing on every cold start.
