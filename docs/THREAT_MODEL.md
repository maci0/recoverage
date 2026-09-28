# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-29, against
`__version__ = "3.0.0"` (`src/recoverage/__init__.py:31`).

What ReCoverage is: a read-mostly web dashboard over the clear-text coverage
documents (`db/coverage-<target>.toml`) that rebrew's pipeline prints, served by
Bottle on a threaded `wsgiref` whose transport half lives in `devserver.py`
(`devserver.py:46-370`, wired at `cli.py:989-996`). The intended audience is a
single developer on their own machine, viewing a decompilation project they
control. Everything below is scoped to that deployment, plus the explicitly
supported LAN case (`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:889-892`, `server.py:2273-2336`, `api.py:1701`, `api.py:1870` | Acknowledgement only: a red message and `typer.Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:1187` (`/data`), `potato.py:1179` (`/potato`), `api.py:1701` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server.py:1874-1888`; caps at `api.py:210`, `api.py:306`, `api.py:323`); the only per-route cap below the process-wide connection cap is on `/api/events` (`api.py:550`). The static-asset memo `ui._STATIC_CACHE` (`ui.py:330`) has no count cap; it is bounded structurally by the route-matched filename and encoding variant instead |
| 3 | Global auth throttle: 10 failures per 60 s per process, not per source, so any one client can 429 the operator and every other client | `server.py:2219-2222`, `server.py:2225-2244` | The cap is intentional and the window is a documented module constant; the check, the cap and the slot reservation share one lock, so a burst of concurrent bad tokens cannot slip past it |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:199-230`, `potato.py:1179-1185`, `server.py:2053-2088` | `Referrer-Policy: no-referrer` (`server.py:2509`), `HttpOnly; SameSite=Strict` cookie (`server.py:2077-2079`), constant-time compare (`server.py:2036-2044`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which coverage directory is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:34-73`, `server.py:1045-1080`, `ui.py:264-266` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `ThreadingMixIn` runs one daemon thread per connection, so a flood of ordinary requests, or a set of idle keep-alive connections, spends a thread each while they are held | `devserver.py:46-159`, `devserver.py:171`, `devserver.py:180` | Connections are admitted against `_MAX_CONNECTIONS` (128, `devserver.py:43`) and refused at the cap with a 503 and a `Retry-After`, before a thread is created (`devserver.py:76-132`); a 120 s per-socket deadline on every read and write in flight (`devserver.py:171`, `devserver.py:200`, `devserver.py:305`) and a 15 s idle deadline between requests (`devserver.py:180`, `devserver.py:309`); `/api/events` carries its own lower cap (`api.py:550`) |
| 7 | Any local process can trigger a full re-catalog and coverage rebuild (disk and CPU), repeatedly within the cooldown | `api.py:1952-2073` | Loopback peer check, same-origin (`server.origin_is_this_dashboard`) and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`api.py:142-186`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, TOML parser messages, echoed user input) to the client | `server.py:1977-2002`, `server.py:2369-2396`, `api.py:1968-2010` | Tracebacks never reach a response body (`server.py:2417-2434`); only the one-line exception class and a rebuild hint do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:1197-1270`, `api.py:1701-1866` | `_MAX_DLL_SIZE` (512 MiB, `server.py:987`) checked on `stat()` (`server.py:1232-1240`) and again post-read (`server.py:1242-1251`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:2273-2336` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:2314-2317`, `server.py:2453-2460`); regen start, replay, completion and failure are logged (`api.py:2086`, `api.py:2026`, `api.py:2140`, `api.py:2149`) |
| 11 | Twelve `RECOVERAGE_*` environment variables select the bind address, the token, the coverage directory, the log level, the CORS allowlist and the transport bounds, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) reads as unset rather than rejected, and two of the twelve (`RECOVERAGE_FUZZ_SEED`, `RECOVERAGE_FUZZ_ITERATIONS`) are accepted under the prefix but consumed only by the test suite | `config.py:45-58`, `config.py:103-110`, `config.py:153-303`, `cli.py:360` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:305-318`); a SET-but-empty value is an error everywhere except `RECOVERAGE_TOKEN`, where it means "auth off" on purpose |

Owner and review cadence: not stated in the repository.

## Entry points

Transport, before any route runs:

- `cli._server_class_for` (`cli.py:120-137`) picks the socket family from the
  bind address through `getaddrinfo`, and `cli._ThreadingWSGIServer6`
  (`cli.py:104-117`) is the `AF_INET6` class. On Linux a wildcard `AF_INET6`
  socket also accepts IPv4-mapped peers, which is the case
  `server._peer_is_loopback` (`server.py:99-122`) has to answer correctly for
  `POST /api/regen`.
- `devserver._ThreadingWSGIServer` (`devserver.py:46-159`): one daemon thread
  per connection, admitted against `_MAX_CONNECTIONS` and refused with a 503
  above it.
- `devserver._KeepAliveRequestHandler` (`devserver.py:246-328`): HTTP/1.1
  keep-alive, so one connection carries many requests. The 65537-byte request
  line read (`devserver.py:293`, `devserver.py:310`) and the 414 on overflow
  (`devserver.py:295-300`) are the only framing limits.
- `devserver._KeepAliveServerHandler` (`devserver.py:331-370`): a response with
  no `Content-Length` and no `Transfer-Encoding` is sent with `Connection:
  close`, which is what keeps the unframed `/api/events` stream from
  misframing the next response on the socket.

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:199-201`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:207`,
  `server.set_auth_cookie`).
- `GET /potato` - `potato.py:1179-1180`, which owns both the route and the
  renderer (`render_potato`, `potato.py:1095`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:264-266`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:369-370`. Package-shipped
  JS/CSS/SVG.
- `GET /api/health` `api.py:846`, `GET /api/targets` `api.py:995`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `api.py:1019-1020`, `api.py:1187`, `api.py:1370`, `api.py:1664`, `api.py:1701`,
  `api.py:1870`.
- `POST /api/targets/<t>/functions` - `api.py:1623`, the only body-carrying
  endpoint.
- `GET /api/events` - `api.py:754`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:1952`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:2535-2538`, CORS preflight catch-all.
- `@app.error(500)` - `server.py:2399`. The response surface for every
  unhandled exception, and the only place `_reclassify_request` is called
  (`server.py:2419`, `server.py:2426`).
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `webapp.py:112-121`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `webapp.py:128-138`, the JSON/HTML
  split by `/api/` prefix.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `X-Request-ID`, `Accept-Encoding`,
`If-None-Match` are headers; `token`, `target`, `va`, `section`, `status`,
`search`, `sort`, `limit`, `offset`, `size`, `offset`, `format` are query
values; `{"vas": [...]}` is the only request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open`, `config`
  (`cli.py:790`, `cli.py:1057`, `cli.py:1129`, `cli.py:1251`, `cli.py:1358`,
  `cli.py:1368`, `cli.py:1405`), plus the global `--no-color` / `--version`
  callback (`cli.py:153-177`). The operator's shell is the trust source.
  `recoverage config` prints every resolved setting including whether a token
  is set (`cli.py:1405-1443`), so it reaches the same secret-presence question as
  `serve`.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL`, `RECOVERAGE_MAX_CONNECTIONS`,
  `RECOVERAGE_CLIENT_TIMEOUT`, `RECOVERAGE_FUZZ_SEED`,
  `RECOVERAGE_FUZZ_ITERATIONS` (`config.py:45-58`). Flags win over the
  environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`config.py:305-318`). `RECOVERAGE_TOKEN`
  is the only secret; `RECOVERAGE_LOG_LEVEL` is the only one that changes what
  an operator can see, since at DEBUG the per-request lines
  (`server.py:2180-2190`) reach the log. `NO_COLOR` and `TERM`
  (`cli.py:68-73`) are the only non-prefixed environment reads and are
  cosmetic.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:34-73`, `server.py:1045-1080`).
- The target binary named by `[targets.*].filename`, resolved by
  `_target_filename` / `_find_dll_path` (`server.py:1091-1101`,
  `server.py:1151-1167`).
- Filesystem: `db/coverage-<target>.toml` (read as UTF-8 text through
  `rebrew.coverage_toml`, `rebrew/coverage_toml.py:1197-1214`, reached at
  `server.py:618-632`; nothing is held open between requests), `<project>/src`,
  `<project>/original`, and the function source files Potato Mode reads directly
  through its own resolve-and-contain check (`potato.py:2472-2563`).
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:635-644`), argv list, own session, killed and reaped on a 10 s
  timeout (`cli.py:519`, `cli.py:536-572`).
- Startup threads, all daemon and none joined: the coverage watcher
  (`api._ensure_db_watcher`, `cli.py:976-978`) and the SPA shell warm-up
  (`ui.warm_index_cache`, `cli.py:984-986`, which builds 8 compression
  variants before the listener accepts). Both are started before the bind, so
  either can fail after a port is chosen but before anything answers; each logs
  and stays lazy rather than aborting the start.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`regen.py:44-79` for `recoverage regen`, `serve --regen` and
`POST /api/regen`.

`recoverage serve` is not the only way in: `python -m recoverage` reaches the
same Typer app (`__main__.py:5-8`), and every command validates the
`RECOVERAGE_*` environment before consuming a setting, not just `serve`
(`cli.py:360-374`). The in-process capstone parse behind `/asm` lives in
`disasm.py`, reached from the route at `api.py:1701` and called at
`api.py:1849`; the JSON branch in the route itself is the only disassembly it
performs.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: the `before_request` hooks in registration
   order - `_start_request`, `_require_auth`, then the Host allowlist
   (installed from `cli.py:918-923`) - then per-handler
   bounds (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at `api.py:1247-1253`;
   `_MAX_PAGE_OFFSET` at `api.py:1259`; `_MAX_SLICE_SIZE` at `api.py:1264`;
   `_MAX_SEARCH_CHARS` at `api.py:1269`). Auth runs before the Host check, so
   a request with neither is answered 401 and a bad Host on an unauthenticated
   deployment is answered 400.
   The one request `_require_auth` passes without a credential is a browser CORS
   preflight (`server._is_cors_preflight`: `OPTIONS` carrying both `Origin` and
   `Access-Control-Request-Method`), because a browser sends no credential on
   the handshake and the gate otherwise answered 401 to every one of them,
   leaving the documented `--cors` + `--token` combination unable to send a
   request. It reads nothing: the preflight answers from the same
   `OPTIONS <path>` catch-all that returns an empty body for every path. A bare
   `OPTIONS` carries no `Origin` and stays gated, the request the preflight
   precedes is authenticated by the same hook, and an exempt preflight does not
   clear the failed-token window (only a verified token does).
2. **App to coverage documents.** `db/coverage-<target>.toml` is printed by
   `rebrew build-db` and read here, never written (`server.coverage_snapshots`,
   `server.py:618-632`; the reader is `rebrew.coverage_toml`,
   `rebrew/coverage_toml.py:1197-1214`). The documents are attacker-supplied in
   the same sense the database file was: whoever can write into the coverage
   directory decides what every dashboard shows, and the values are trusted as
   data, never as code. Parsing is `tomllib`, so a malformed document raises
   instead of executing; the reader validates the format version, the shape of
   every array and table, and that the document's `target` matches its filename,
   and every failure is one `CoverageTomlError`.
   Unreadable is not empty, and the two answers stay distinguishable. A document
   that exists and does not parse raises `CoverageTomlError`, which is the 503
   `db_unavailable` contract (`server._db_unavailable_err`, `server.py:2369-2396`);
   a target `rebrew-project.toml` declares that no build has written is served
   from an empty snapshot (`server.coverage_for`, `server.py:647-678`), which is
   what the SQLite reader got from an empty table set. Collapsing the first into
   the second would show a truncated or hostile document as a project with no
   sections, with nothing in the response or the log to say the read had failed
   (`tests/test_server.py`, `TestUnreadableDocumentIsNotAnEmptyTarget`).
   Nothing JSON-decodes a stored blob any more, so the SQLite-era 1 MiB
   metadata-value cap is gone with the metadata row it guarded; what a document
   costs is one `tomllib` parse, bounded by the size of the documents the
   project's own pipeline wrote.
   The documents are also liveness: a rewritten one is picked up live (the
   snapshot memo keys on the directory's own stat), and the SSE watcher
   (`api.py:604-647`) pushes `db-updated` so the SPA re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:266-300`).
   Potato Mode's source panel repeats the containment check independently
   (`potato.py:2520-2545`).
4. **App to local process (regen).** The only privilege transition: a POST makes
   the server import rebrew and rebuild the coverage documents, with the
   process's own filesystem authority (`regen.py:44-79`).
5. **Config to runtime.** `rebrew-project.toml` and the `RECOVERAGE_*`
   environment select the coverage directory, the target binary path, the served
   trees, the log level and the bind address, with no signature or allowlist.
6. **CLI to host.** The browser opener and the bind address are operator
   decisions, not attacker input.

## Assets

- Project C sources under `<project>/src`, original binaries under
  `<project>/original`, and the coverage documents under the project's coverage
  directory (`db/coverage-<target>.toml`: reverse-engineering output, the thing
  worth stealing).
- The `--token` / `RECOVERAGE_TOKEN` bearer value, the only credential the
  system holds.
- Server process availability and the host's CPU, memory and disk, all consumed
  by `/data`, `/potato`, `/asm` and regen.
- The integrity of the coverage documents: a wrong or stale map misdirects hours
  of decompilation work, which is the reputation-shaped asset here.

## Threats per boundary

**Client to app.** Spoofing: a page on any origin can drive a loopback browser
at the dashboard; mitigated by the Host allowlist on loopback binds
(`server.py:90`, `server.py:96`, `server.py:2437-2468`, installed at
`cli.py:918-923`) and by the `Sec-Fetch-Site` rejection on regen
(`api.py:2002-2010`). Tampering: only regen writes, and only from loopback.
Information disclosure: `/src` and `/original` proxy the whole project tree,
and the byte and asm endpoints serve arbitrary offsets of the original binary
(`api.py:1870`, `api.py:1701`) with no per-resource authorization. Denial of
service: no per-client quota anywhere; only `/api/events` and the auth window
are bounded. Repudiation: every action is attributable only to a shared token
and a socket peer, never to a client. Elevation of privilege: an
unauthenticated remote peer reaching a non-loopback bind gets every read the
operator gets, which is the whole asset set.

**Client to transport.** HTTP/1.1 keep-alive means a client that opens
connections without closing them holds a thread each until the 15 s idle
deadline, which is longer than a slow page load and much shorter than the 120 s
in-flight one (`devserver.py:171-180`, `devserver.py:246-328`). A connection
past the cap is refused before it gets a thread, with a 503, a `Retry-After`
and a WARNING line naming the count (`devserver.py:76-132`, `_MAX_CONNECTIONS`
at `devserver.py:43`), so the ceiling on live threads is that cap and the
refusal is visible to the operator rather than a silent stall. A
request line over 65536 bytes is answered 414 and the connection dropped
(`devserver.py:295-300`), which is the only framing resource bound.

**App to coverage documents.** Tampering is bounded by the direction of the
dependency: this server only reads, and the only writer is `rebrew build-db`,
which replaces each document whole through a temporary sibling and an atomic
rename (`rebrew/coverage_toml.py:697-700`), so a reader sees the previous
document or the new one and never a torn write. A document the reader cannot use
is answered 503 rather than half-served. Denial of service remains: a large
function list with a `search` term is walked per request (`api.py:383-413`,
`api.py:1436-1437`), bounded only by a 64-entry memo (`api.py:321-323`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:283-300`, `potato.py:2520-2545`); what remains is that the trees are
served in full, so a `.env` or a key committed under `src/` is published to
every client.

**App to local process.** A local, unauthenticated process can trigger regen.
The `Origin` and `Sec-Fetch-Site` checks stop the browser-shaped version; they
do not stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely
when an `Origin` is sent that the same-origin test accepts
(`server.origin_is_this_dashboard`, `server.py:252-273`: the origin's host and
port against the request's own `Host`, so a page on another loopback port is
refused). Regen runs with no timeout by design (`regen.py:13-17`).

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the coverage directory or the listener.
There is no prompt and no warning when a config changes under a running server;
the memoized path just recomputes (`_paths.py:34-73`, `server.py:1103-1149`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `server.py:2006-2014`, `server.py:2237-2300` | Spoofing, unauthorized read |
| Global failure throttle with 429 + `Retry-After`, check and reservation under one lock | `server.py:1922-1947`, `server.py:2266-2271` | Online token guessing, check-then-act races under concurrency, and audit logging of each failure |
| Host header allowlist on loopback binds | `server.py:90`, `server.py:96`, `server.py:2401-2432` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:885-890` | Accidental LAN exposure |
| Every request-supplied integer goes through `server.parse_ascii_int` — ASCII digits in the stated base and nothing else — with `api._parse_byte_count` and `api._page_int` on top | `server.py:361`, `api.py:1270`, `api.py:1289` | Digit-set smuggling: `int(x, base)` also accepts the whole Unicode Nd/Nl/No sets and the `_` separator, so `?size=٤٠٩٦` served a 4096-byte slice and `?page=1_0` opened page 10; a chunked body took the same route for its chunk size line, so `1_0` read 16 bytes of a connection it had no framing for |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:305-319`, `config.py:153-302`, `cli.py:360-376` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and same-origin `Origin` gate on regen | `api.py:1960-1990` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:120`, `api.py:126`, `api.py:2016-2053` | Concurrent torn rebuilds, regen flood |
| `Idempotency-Key` ledger: charset-validated, 600 s TTL, 128-slot eviction, replay answered before the cooldown | `api.py:142-186`, `api.py:1997-2008` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:2441-2452`, `server.py:2467-2474` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `server.py:2455-2496`, `cli.py:650-681` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `ui.py:288-308` | Path traversal |
| Independent containment check on Potato Mode's source panel | `potato.py:2526-2537` | Path traversal through a second reader |
| Allowlist regex for package assets | `ui.py:376` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:1226-1247`, `api.py:1366-1385`, `api.py:1457-1596` | Memory and CPU exhaustion per request |
| A request body is read through `server.read_request_body` (declared `Content-Length` compared against the cap first, a chunked body decoded under the same cap) and every refusal answers `Connection: close` through `api._body_rejected` | `server.py:431-523`, `api.py:1562` | A declared length that is never allocated, an unbounded chunked decode, and a refused body left in a keep-alive socket where the next request would be parsed out of it |
| `sort` field and direction whitelisted against `_ALLOWED_SORT` and applied as an in-memory sort key | `api.py:373`, `api.py:1387-1416` | Arbitrary field access through the sort parameter. The SQLite-era `ORDER BY` interpolation this row used to name is gone with the query builder: the rows are Python objects, so there is no statement for a sort value to reach |
| Search is a folded substring test in Python (`server.fold_match`) | `server.py:1515-1548`, `api.py:395-404` | Wildcard abuse and non-ASCII misses in search. There is no SQL `LIKE` pattern any more, so the escape helper and the `rc_fold` disjunct beside the ASCII `LIKE` are gone with the SQL |
| `SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `api.py:547-560`, `api.py:696-749` | Thread exhaustion via event streams, slow-client memory growth |
| Connection cap: `_MAX_CONNECTIONS` slots taken before the thread, refused with a hand-written 503 plus `Retry-After` above it, released on every exit including thread-creation failure | `devserver.py:42`, `devserver.py:70-147` | Thread and descriptor exhaustion from a flood of stalled peers. Refusing at accept rather than in the handler keeps the bound on the resource: a connection that never got a thread cannot pin one. The refusal is a `WARNING` naming the count, so the ceiling is legible to the operator |
| Per-socket 120 s in-flight deadline and 15 s keep-alive idle deadline | `devserver.py:169`, `devserver.py:178`, `devserver.py:237-271` | Threads pinned by half-open or non-reading peers, and by idle keep-alive connections |
| 65536-byte request-line cap, answered 414 | `devserver.py:254-261` | Unbounded per-connection read |
| Documents are read as UTF-8 text and never written by this server; the only writer is `rebrew build-db`, which replaces each document whole through an atomic rename | `server.py:618-670`, `rebrew/coverage_toml.py:574-587` | Accidental writes, and a torn read of a document being rebuilt |
| Document gate: the format `version` must be the one this build reads, every array and table must have its documented shape, and the document's `target` must match its filename; a failure is answered 503 | `server.py:2333-2382`, `rebrew/coverage_toml.py:1181-1188` | A truncated, foreign or hand-edited document reading as an empty target, and query-time 500s from a document the reader cannot use |
| Basename-only coverage-directory name in health and SSE payloads | `api.py:859`, `api.py:585` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `server.py:1924-1972`, `server.py:2363-2398`, `server.py:1011-1021` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store` on the 401 page | `server.py:704-744`, `server.py:2288-2296` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `server.py:2067-2082`, `server.py:2134-2135` | Untraceable incidents; forged log lines |
| Status reclassification inside the 500 handler | `server.py:2162-2174`, `server.py:2389`, `server.py:2381` | An error rate that silently reads zero. Note the scope: the two call sites are the 503 (coverage documents unavailable) and the 500 itself, both inside `@app.error(500)`; there is no 4xx reclassification path |

## Unmitigated, ranked

1. No enforced pairing of `--allow-remote` with `--token` (risk 1 above). A
   warning is printed and the process starts anyway; nothing stops
   `--bind 0.0.0.0 --allow-remote` from publishing sources and binaries.
2. No per-client rate limiting or quota on the read endpoints; `ThreadingMixIn`
   will serve a flood of `/data` or `/potato` renders, one thread each, until
   the connection cap refuses the next one.
3. The connection cap bounds how many threads exist, not how much work each one
   does: 128 connections of concurrent `/data` renders is 128 grid builds, and
   the 15 s idle and 120 s in-flight deadlines are what free the slots
   afterwards. A client that reconnects as fast as the server refuses stays at
   the ceiling rather than above it, which is the intended behaviour, and costs
   the operator a full thread pool for as long as it keeps trying.
4. Global auth throttle with no per-source key, so one client can lock out the
   operator for the rest of the 60 s window.
5. No TLS and no token transport hardening; the token is a URL parameter by
   design, which puts it in browser history, shell history and any proxy log.
   The auth cookie is set without `Secure` (`server.py:2077-2079`), so it crosses a
   plaintext non-loopback bind intact.
6. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
7. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:1241`
   performs an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:1242-1251`). A target binary that grows between the `stat()` at
   `server.py:1232` and the read is fully loaded into memory.
8. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
9. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:2180-2190`), and nothing distinguishes one
   holder of the shared token from another. The in-process RED counters
   (`metrics.py`) are a live gauge, not a record, and are lost on restart.
10. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
    crafted target is a worker-level availability and memory-safety risk that
    only the size cap touches, and that cap is post-read.
11. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`server.py:2477-2488`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.
12. `ui._STATIC_CACHE` (`ui.py:330`) has no count cap and no eviction, unlike
    the three `api.py` memos. It is bounded by the allowlisted filename regex
    and the accepted-encoding set rather than by a constant, so it is a
    structural bound today and an unguarded dict if the regex ever widens.
13. Two daemon threads start before the listener binds and are never joined
    (`cli.py:976-986`). A failure in either is logged and the start continues,
    so a server can be serving with a dead coverage watcher, which reads `healthy`
    while no SSE client refreshes.

## Abuse cases

- A hostile but authenticated LAN user with the shared token can scrape the
  whole project: `/src` for sources, `/original/<t>.dll` and
  `/api/targets/<t>/sections/<s>/bytes?size=4096` for the binary,
  `/api/targets/<t>/data` for the map. Nothing distinguishes browsing from bulk
  extraction; the only bound is the page and slice caps.
- A local process without any token can loop `POST /api/regen` to consume the
  host's CPU and rewrite `db/`, degrading the dashboard for the operator. The
  cooldown bounds rate, not volume; the `Idempotency-Key` ledger absorbs a
  *retry* of one key, not a caller that mints a fresh key per attempt, which is
  bounded only by the 5 s cooldown and the single-flight 429.
- Any webpage a developer visits can hold 32 `/api/events` connections to their
  own loopback dashboard (`api.py:550`) without any credential, because the
  SPA's EventSource is same-origin and no-cors from a cross-site page. A
  sixth of the process-wide connection budget goes to it, the socket deadlines
  (`devserver.py:171`, `devserver.py:180`) reclaim each slot eventually, and
  the rest of the budget stays open to the operator's own browser.
- The same page can hold the threads without any stream at all: a keep-alive
  connection that sends one cheap request and then goes quiet holds its thread
  for 15 s, and a page that opens a few hundred of them in that window meets
  the connection cap and gets 503s for the rest (`devserver.py:87-132`).
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.
- A caller who sets `X-Request-ID` picks its own correlation id
  (`server.py:2105-2112`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:2314-2317`), rejected Host header
  (`server.py:2453-2460`), unhandled errors with a request id and traceback
  (`server.py:2417-2434`), coverage-document unavailability (`server.py:2369-2396`), oversized
  or unconfigured target binary (`server.py:1170-1194`), regen start, replay,
  completion and failure (`api.py:2086`, `api.py:2026`, `api.py:2140`,
  `api.py:2149`), slow requests at WARNING (`server.py:2174-2179`), and
  health-state transitions (`api.py:823-842`). Everything else is DEBUG and
  off by default.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`server.py:2097-2112`), echoed on the response (`server.py:2163-2164`), so a
  report of "the export was slow" is matchable to a specific line.
- `SECURITY.md` records the supported version line and the fact that no
  reporting address is defined in the repository.
