# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-29, against
`__version__ = "3.0.0"` (`src/recoverage/__init__.py:40`).

What ReCoverage is: a read-mostly web dashboard over the clear-text coverage
documents (`db/coverage-<target>.toml`) that rebrew's pipeline prints, served by
Bottle on a threaded `wsgiref` whose transport half lives in `devserver.py`
(`devserver.py:103-436`, wired at `cli.py:1134-1141`). The intended audience is a
single developer on their own machine, viewing a decompilation project they
control. Everything below is scoped to that deployment, plus the explicitly
supported LAN case (`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:1025-1028`, `server.py:2382-2450`, `api.py:1903`, `api.py:2072` | Acknowledgement only: a red message and `typer.Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:1365` (`/data`), `potato.py:1213` (`/potato`), `api.py:1903` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server.py:1965-1977`; caps at `api.py:257`, `api.py:475`, `api.py:458`); the only per-route cap below the process-wide connection cap is on `/api/events` (`api.py:697`). The static-asset memo `ui._STATIC_CACHE` (`ui.py:457`) has no count cap; it is bounded structurally by the route-matched filename and encoding variant instead |
| 3 | Global auth throttle: 10 failures per 60 s per process, not per source, so any one client can 429 the operator and every other client | `server.py:2328-2329`, `server.py:2334-2353` | The cap is intentional and the window is a documented module constant; the check, the cap and the slot reservation share one lock, so a burst of concurrent bad tokens cannot slip past it |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:201-209`, `potato.py:1213-1219`, `server.py:2160-2202` | `Referrer-Policy: no-referrer` (`server.py:2635`), `HttpOnly; SameSite=Strict` cookie (`server.py:2186`), constant-time compare (`server.py:2143-2151`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which coverage directory is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:34-73`, `server.py:1117-1170`, `ui.py:266-268` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `ThreadingMixIn` runs one daemon thread per connection, so a flood of ordinary requests, or a set of idle keep-alive connections, spends a thread each while they are held | `devserver.py:103-217`, `devserver.py:371`, `devserver.py:375` | Connections are admitted against `_MAX_CONNECTIONS` (128, `devserver.py:52`) and refused at the cap with a 503 and a `Retry-After`, before a thread is created (`devserver.py:148-204`); a 120 s per-socket deadline on every read and write in flight (`devserver.py:267`, `devserver.py:371`) and a 15 s idle deadline between requests (`devserver.py:375`); `/api/events` carries its own lower cap (`api.py:697`) |
| 7 | Any local process can trigger a full re-catalog and coverage rebuild (disk and CPU), repeatedly within the cooldown | `api.py:2155-2302` | Loopback peer check, same-origin (`server.origin_is_this_dashboard`) and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`api.py:128-233`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, TOML parser messages, echoed user input) to the client | `server.py:2084-2109`, `server.py:2483-2515`, `api.py:2305-2396` | Tracebacks never reach a response body (`server.py:2518-2554`); only the one-line exception class and a rebuild hint do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:1287-1360`, `api.py:1903-2069` | `_MAX_DLL_SIZE` (512 MiB, `server.py:1040`) checked on `stat()` (`server.py:1312-1331`) and again post-read (`server.py:1333-1341`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:2382-2450` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:2425-2432`, `server.py:2577-2585`); regen start, replay, completion and failure are logged (`api.py:2324`, `api.py:2233`, `api.py:2394`, `api.py:2437`) |
| 11 | Twelve `RECOVERAGE_*` environment variables select the bind address, the token, the coverage directory, the log level, the CORS allowlist and the transport bounds, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) reads as unset rather than rejected, and two of the twelve (`RECOVERAGE_FUZZ_SEED`, `RECOVERAGE_FUZZ_ITERATIONS`) are accepted under the prefix but consumed only by the test suite | `config.py:45-60`, `config.py:103-107`, `config.py:151-313`, `cli.py:429` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:368-381`); a SET-but-empty value is an error everywhere except `RECOVERAGE_TOKEN`, where it means "auth off" on purpose |

Owner and review cadence: not stated in the repository.

## Entry points

Transport, before any route runs:

- `cli._server_class_for` (`cli.py:126-143`) picks the socket family from the
  bind address through `getaddrinfo`, and `cli._ThreadingWSGIServer6`
  (`cli.py:110-123`) is the `AF_INET6` class. On Linux a wildcard `AF_INET6`
  socket also accepts IPv4-mapped peers, which is the case
  `server._peer_is_loopback` (`server.py:99-122`) has to answer correctly for
  `POST /api/regen`.
- `devserver._ThreadingWSGIServer` (`devserver.py:103-216`): one daemon thread
  per connection, admitted against `_MAX_CONNECTIONS` and refused with a 503
  above it.
- `devserver._KeepAliveRequestHandler` (`devserver.py:312-394`): HTTP/1.1
  keep-alive, so one connection carries many requests. The 65537-byte request
  line read (`devserver.py:359`, `devserver.py:376`) and the 414 on overflow
  (`devserver.py:365`) are the only framing limits.
- `devserver._KeepAliveServerHandler` (`devserver.py:397-436`): a response with
  no `Content-Length` and no `Transfer-Encoding` is sent with `Connection:
  close`, which is what keeps the unframed `/api/events` stream from
  misframing the next response on the socket.

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:201-203`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:209`,
  `server.set_auth_cookie`).
- `GET /potato` - `potato.py:1213`, which owns both the route and the
  renderer (`render_potato`, `potato.py:1129`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:266-268`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:486`. Package-shipped
  JS/CSS/SVG.
- `GET /api/health` `api.py:1014`, `GET /api/targets` `api.py:1167`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `api.py:1192`, `api.py:1365`, `api.py:1566`, `api.py:1866`, `api.py:1903`,
  `api.py:2072`.
- `POST /api/targets/<t>/functions` - `api.py:1825`, the only body-carrying
  endpoint.
- `GET /api/events` - `api.py:919`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:2155`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:2665`, CORS preflight catch-all.
- `@app.error(500)` - `server.py:2518`. The response surface for every
  unhandled exception, and the only place `_reclassify_request` is called
  (`server.py:2536`, `server.py:2544`).
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `webapp.py:112-113`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `webapp.py:128-139`, the JSON/HTML
  split by `/api/` prefix.

The one body-carrying endpoint parses the message framing as well as the
payload, and the framing is the part a client chooses freely:
`server.read_request_body` (`server.py:477`), its chunked arm
`server._read_chunked_body` (`server.py:431`), its declared-length arm
`server._declared_content_length` (`server.py:408`) and the `Transfer-Encoding`
sniff `server._body_is_chunked` (`server.py:426`). So `Content-Length`,
`Transfer-Encoding`, `Content-Type` and the chunk-size lines are entry points
in their own right, and the framing errors they produce
(`server.RequestBodyError` and its two subclasses, `server.py:379-394`) are
one of the answers a client can elicit before the payload is ever parsed.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `X-Request-ID`, `Accept-Encoding`,
`If-None-Match`, `Content-Length`, `Transfer-Encoding`, `Content-Type` are
headers; `token`, `target`, `va`, `section`, `status`, `search`, `sort`,
`limit`, `offset`, `size`, `offset`, `format` are query values;
`{"vas": [...]}` is the only request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open`, `config`
  (`cli.py:907`, `cli.py:1202`, `cli.py:1283`, `cli.py:1451`, `cli.py:1567`,
  `cli.py:1593`, `cli.py:1642`), plus the global `--no-color` / `--version`
  callback (`cli.py:200-216`). The operator's shell is the trust source.
  `recoverage config` prints every resolved setting including whether a token
  is set (`cli.py:1642-1686`), so it reaches the same secret-presence question as
  `serve`.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL`, `RECOVERAGE_MAX_CONNECTIONS`,
  `RECOVERAGE_CLIENT_TIMEOUT`, `RECOVERAGE_FUZZ_SEED`,
  `RECOVERAGE_FUZZ_ITERATIONS` (`config.py:45-60`). Flags win over the
  environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`config.py:368-381`). `RECOVERAGE_TOKEN`
  is the only secret; `RECOVERAGE_LOG_LEVEL` is the only one that changes what
  an operator can see, since at DEBUG the per-request lines
  (`server.py:2281-2304`) reach the log. `NO_COLOR` and `TERM`
  (`cli.py:74-79`) are the only non-prefixed environment reads and are
  cosmetic.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:34-73`, `server.py:1117-1170`).
- The target binary named by `[targets.*].filename`, resolved by
  `_target_filename` / `_find_dll_path` (`server.py:1181-1190`,
  `server.py:1241-1257`).
- Filesystem: `db/coverage-<target>.toml` (read as UTF-8 text through
  `rebrew.coverage_toml`, `rebrew/coverage_toml.py:1205-1223`, reached at
  `server.py:639-653`; nothing is held open between requests), `<project>/src`,
  `<project>/original`, and the function source files Potato Mode reads directly
  through its own resolve-and-contain check (`potato.py:2514-2587`).
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:710-719`), argv list, own session, killed and reaped on a 10 s
  timeout (`cli.py:594`, `cli.py:611-647`).
- Startup threads, all daemon and none joined: the coverage watcher
  (`api._ensure_db_watcher`, `cli.py:1121-1123`) and the SPA shell warm-up
  (`ui.warm_index_cache`, `cli.py:1129-1131`, which builds 8 compression
  variants before the listener accepts). Both are started before the bind, so
  either can fail after a port is chosen but before anything answers; each logs
  and stays lazy rather than aborting the start.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`regen.py:87-126` for `recoverage regen`, `serve --regen` and
`POST /api/regen`.

`recoverage serve` is not the only way in: `python -m recoverage` reaches the
same Typer app (`__main__.py:5-8`), and every command validates the
`RECOVERAGE_*` environment before consuming a setting, not just `serve`
(`cli.py:429-443`). The in-process capstone parse behind `/asm` lives in
`disasm.py`, reached from the route at `api.py:1903` and called at
`api.py:2044`; the JSON branch in the route itself is the only disassembly it
performs.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: the `before_request` hooks in registration
   order - `_start_request`, `_require_auth`, then the Host allowlist
   (installed from `cli.py:1054-1059`) - then per-handler
   bounds (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at `api.py:1440-1450`;
   `_MAX_PAGE_OFFSET` at `api.py:1456`; `_MAX_SLICE_SIZE` at `api.py:1461`;
   `_MAX_SEARCH_CHARS` at `api.py:1466`). The body cap is enforced where the
   body is read, not in the handler: `api._batch_request_vas` calls
   `server.read_request_body(_MAX_BATCH_BODY_BYTES)` (`api.py:1713`), which
   compares the declared `Content-Length` before a byte is read, reads a
   framed body to its declared length and no further, and bounds a chunked
   body on the DECODED bytes (`server.py:477-528`). Auth runs before the Host check, so
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
   `server.py:639-653`; the reader is `rebrew.coverage_toml`,
   `rebrew/coverage_toml.py:1205-1221`). The documents are attacker-supplied in
   the same sense the database file was: whoever can write into the coverage
   directory decides what every dashboard shows, and the values are trusted as
   data, never as code. Parsing is `tomllib`, so a malformed document raises
   instead of executing; the reader validates the format version, the shape of
   every array and table, and that the document's `target` matches its filename,
   and every failure is one `CoverageTomlError`.
   Unreadable is not empty, and the two answers stay distinguishable. A document
   that exists and does not parse raises `CoverageTomlError`, which is the 503
   `db_unavailable` contract (`server._db_unavailable_err`, `server.py:2483-2515`);
   a target `rebrew-project.toml` declares that no build has written is served
   from an empty snapshot (`server.coverage_for`, `server.py:668-699`), which is
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
   (`api.py:758-800`) pushes `db-updated` so the SPA re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:266-302`).
   Potato Mode's source panel repeats the containment check independently
   (`potato.py:2568-2587`).
4. **App to local process (regen).** The only privilege transition: a POST makes
   the server import rebrew and rebuild the coverage documents, with the
   process's own filesystem authority (`regen.py:87-126`).
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

## Secrets

One secret exists, the bearer token, and it has exactly three carriers:

- **Enters** as `--token` on the command line or `RECOVERAGE_TOKEN` in the
  environment (`cli.py`, `config.py`). The command-line form is world-readable
  in the process table for the life of the process; the environment form is
  visible to anything that can read the parent environment, which is the same
  trust as every other `RECOVERAGE_*` value.
- **Lives** in `_AUTH_TOKEN`, a module-level string set once by
  `server.configure_security` (`server.py:125`, assigned at `server.py:125-149`,
  called from `cli.py:1054`) and held for the process lifetime. It is never
  written to disk by this package. It is echoed in neither direction: a
  successful compare and a failed one both answer the same 401
  (`server._require_auth`, `server.py:2382`), and the log records the peer
  address, never the value (`server.py:2425-2432`).
- **Leaves** in three forms, all of them places the value is recoverable
  rather than exchanged: the `?token=` query parameter on a share link
  (`ui.py:201-209`), the `recoverage_token` cookie
  (`server.AUTH_COOKIE_NAME`, `server.py:2157`, set `HttpOnly; SameSite=Strict`
  and without `Secure`, `server.py:2184-2187`), and the `Authorization: Bearer`
  header. A wrong value is rate-limited but the value itself is not protected
  in transit on a non-loopback bind.

Rotation is a restart: `configure_security` is called once from `serve` and
nothing reloads `_AUTH_TOKEN` afterwards, so a rotated token is the new
process's, and the old one stays valid until every client has been given the
new one. The set/unset rendering (`config.active_config`,
`config.py:384-415`, surfaced by `recoverage config` and by the `config` block
of `GET /api/health`, `api.py:1099`) confirms presence to anyone who can reach
those, and nothing else about the value.

## Threats per boundary

**Client to app.** Spoofing: a page on any origin can drive a loopback browser
at the dashboard; mitigated by the Host allowlist on loopback binds
(`server.py:90`, `server.py:96`, `server.py:2557-2593`, installed at
`cli.py:1054-1059`) and by the `Sec-Fetch-Site` rejection on regen
(`api.py:2201-2216`). Tampering: only regen writes, and only from loopback.
Information disclosure: `/src` and `/original` proxy the whole project tree,
and the byte and asm endpoints serve arbitrary offsets of the original binary
(`api.py:2072`, `api.py:1903`) with no per-resource authorization.
`GET /api/health` additionally hands any authenticated client the process's
resolved deployment: bind address, `allow_remote`, the CORS allowlist, log
level, connection and timeout caps, and whether a token is set
(`api.py:1014`, `config.py:384-415`). Every field is a setting the operator
chose and none is the token's value, so this is a configuration-disclosure
read and a `token: set` / `unset` oracle for a client that does not already
know the answer. Denial of
service: no per-client quota anywhere; only `/api/events` and the auth window
are bounded. Repudiation: every action is attributable only to a shared token
and a socket peer, never to a client. Elevation of privilege: an
unauthenticated remote peer reaching a non-loopback bind gets every read the
operator gets, which is the whole asset set.

**Client to app, message framing.** Tampering and denial of service both
live here, before the payload exists. A client controls `Content-Length`,
`Transfer-Encoding` and the chunk-size lines, and a naive reader of either is
a request-smuggling primitive; the two answers a second HTTP hop would give
for one connection are the whole prize, and this listener is a
single-`wsgiref` process with no proxy in front of it by default, so a smuggle
has no second parser to disagree with here. A declared length that never
arrives is a handler parked in `read()` until the 120 s in-flight socket
deadline (`devserver.py:233`) takes it, and the read is bounded by the frame,
not by EOF, precisely so that stall cannot run to the client. The residual
gap is that the cap is a length comparison and a byte count, not a
concurrent-bytes-per-connection budget: `_MAX_BATCH_BODY_BYTES` is per request
(`api.py:1450`), so `_MAX_CONNECTIONS` requests of the maximum size are
admitted at once.

**Client to transport.** HTTP/1.1 keep-alive means a client that opens
connections without closing them holds a thread each until the 15 s idle
deadline, which is longer than a slow page load and much shorter than the 120 s
in-flight one (`devserver.py:371-375`, `devserver.py:359-375`). A connection
past the cap is refused before it gets a thread, with a 503, a `Retry-After`
and a WARNING line naming the count (`devserver.py:148-204`, `_MAX_CONNECTIONS`
at `devserver.py:52`), so the ceiling on live threads is that cap and the
refusal is visible to the operator rather than a silent stall. A
request line over 65536 bytes is answered 414 and the connection dropped
(`devserver.py:359-365`), which is the only framing resource bound.

**App to coverage documents.** Tampering is bounded by the direction of the
dependency: this server only reads, and the only writer is `rebrew build-db`,
which replaces each document whole through a temporary sibling and an atomic
rename (`rebrew/coverage_toml.py:701-704`), so a reader sees the previous
document or the new one and never a torn write. A document the reader cannot use
is answered 503 rather than half-served. Denial of service remains: a large
function list with a `search` term is walked per request (`api.py:530-559`,
`api.py:1636`), bounded only by a 64-entry memo (`api.py:475`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:266-302`, `potato.py:2568-2587`); what remains is that the trees are
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
the memoized path just recomputes (`_paths.py:34-73`, `server.py:1117-1170`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `server.py:2143-2151`, `server.py:2382-2450` | Spoofing, unauthorized read |
| Global failure throttle with 429 + `Retry-After`, check and reservation under one lock | `server.py:2328-2353`, `server.py:2425-2432` | Online token guessing, check-then-act races under concurrency, and audit logging of each failure |
| Host header allowlist on loopback binds | `server.py:90`, `server.py:96`, `server.py:2557-2593` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:1025-1028` | Accidental LAN exposure |
| Every request-supplied integer goes through `server.parse_ascii_int`: ASCII digits in the stated base and nothing else, with `api._parse_byte_count` and `api._page_int` on top | `server.py:361`, `api.py:1489`, `api.py:1508` | Digit-set smuggling: `int(x, base)` also accepts the whole Unicode Nd/Nl/No sets and the `_` separator, so `?size=٤٠٩٦` served a 4096-byte slice and `?page=1_0` opened page 10 |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:368-381`, `config.py:151-313`, `cli.py:429-443` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and same-origin `Origin` gate on regen | `api.py:2186-2216` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:120`, `api.py:126`, `api.py:2248-2282` | Concurrent torn rebuilds, regen flood |
| `Idempotency-Key` ledger: charset-validated, 600 s TTL, 128-slot eviction, replay answered before the cooldown | `api.py:142-233`, `api.py:2218-2234` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:2602-2613`, `server.py:2628-2662` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `server.py:2616-2662`, `cli.py:725-768` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `ui.py:266-302` | Path traversal |
| Independent containment check on Potato Mode's source panel | `potato.py:2568-2587` | Path traversal through a second reader |
| Allowlist regex for package assets | `ui.py:486` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:1438-1466`, `api.py:1489-1516`, `api.py:1681-1781` | Memory and CPU exhaustion per request |
| Body read through `server.read_request_body`, never `request.body`: the declared `Content-Length` is compared before a byte is read, a framed body is read to its declared length and no further, a chunked body is bounded on the DECODED bytes, a chunk-size line is capped at 1 KiB and read through `parse_ascii_int` | `server.py:477-528`, `api.py:1713` | A declared 4 GB body allocated before the endpoint's own cap could look at it; a `read()` to EOF parking the handler until the client hangs up; a chunk line smuggling a length through a non-ASCII digit set or the `_` separator. Bottle's `request.body` drains the whole declared body into a `BytesIO` and spills past 100 KiB into a `NamedTemporaryFile`, so the resource the cap exists to bound was allocated first |
| Every body refusal answers `Connection: close` through `api._body_rejected`, the one helper that puts the header there | `api.py:1669-1678` | Request smuggling: the reader stops at its cap, so the bytes after the stop point are still in the socket and a keep-alive handler would parse them as the next request |
| Chunked and unframed framing refused rather than guessed: a non-hex chunk size, an unterminated chunk, a missing CRLF or an oversize trailer line is `RequestBodyMalformedError` | `server.py:431-474` | A framing this reader cannot account for, silently accepted as a shorter body |
| `sort` field and direction whitelisted against `_ALLOWED_SORT` and applied as an in-memory sort key | `api.py:527`, `api.py:1609-1641` | Arbitrary field access through the sort parameter. The SQLite-era `ORDER BY` interpolation this row used to name is gone with the query builder: the rows are Python objects, so there is no statement for a sort value to reach |
| Search is a folded substring test in Python (`server.fold_match`) | `server.py:1629-1637`, `api.py:530-559` | Wildcard abuse and non-ASCII misses in search. There is no SQL `LIKE` pattern any more, so the escape helper and the `rc_fold` disjunct beside the ASCII `LIKE` are gone with the SQL |
| `SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `api.py:697`, `api.py:919-977` | Thread exhaustion via event streams, slow-client memory growth |
| Connection cap: `_MAX_CONNECTIONS` slots taken before the thread, refused with a hand-written 503 plus `Retry-After` above it, released on every exit including thread-creation failure | `devserver.py:52`, `devserver.py:103-217` | Thread and descriptor exhaustion from a flood of stalled peers. Refusing at accept rather than in the handler keeps the bound on the resource: a connection that never got a thread cannot pin one. The refusal is a `WARNING` naming the count, so the ceiling is legible to the operator |
| Per-socket 120 s in-flight deadline and 15 s keep-alive idle deadline | `devserver.py:233`, `devserver.py:242`, `devserver.py:371-376` | Threads pinned by half-open or non-reading peers, and by idle keep-alive connections |
| 65536-byte request-line cap, answered 414 | `devserver.py:247`, `devserver.py:361-366` | Unbounded per-connection read |
| Documents are read as UTF-8 text and never written by this server; the only writer is `rebrew build-db`, which replaces each document whole through an atomic rename | `server.py:639-653`, `rebrew/coverage_toml.py:701-704` | Accidental writes, and a torn read of a document being rebuilt |
| Document gate: the format `version` must be the one this build reads, every array and table must have its documented shape, and the document's `target` must match its filename; a failure is answered 503 | `server.py:2483-2515`, `rebrew/coverage_toml.py:1170-1176` | A truncated, foreign or hand-edited document reading as an empty target, and query-time 500s from a document the reader cannot use |
| Basename-only coverage-directory name in health and SSE payloads | `api.py:1029`, `api.py:726` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `server.py:2084-2109`, `server.py:2518-2554`, `server.py:1072-1074` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store` on the 401 page | `server.py:745-772`, `server.py:2437-2446` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `server.py:2212-2219`, `server.py:2272` | Untraceable incidents; forged log lines |
| Status reclassification inside the 500 handler | `server.py:2307-2319`, `server.py:2536`, `server.py:2544` | An error rate that silently reads zero. Note the scope: the two call sites are the 503 (coverage documents unavailable) and the 500 itself, both inside `@app.error(500)`; there is no 4xx reclassification path |

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
   The auth cookie is set without `Secure` (`server.py:2186`), so it crosses a
   plaintext non-loopback bind intact.
6. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
7. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:1332`
   performs an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:1333-1341`). A target binary that grows between the `stat()` at
   `server.py:1322` and the read is fully loaded into memory.
8. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
9. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:2296-2304`), and nothing distinguishes one
   holder of the shared token from another. The in-process RED counters
   (`metrics.py`) are a live gauge, not a record, and are lost on restart.
10. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
    crafted target is a worker-level availability and memory-safety risk that
    only the size cap touches, and that cap is post-read.
11. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`server.py:2602-2613`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.
12. `ui._STATIC_CACHE` (`ui.py:457`) has no count cap and no eviction, unlike
    the three `api.py` memos. It is bounded by the allowlisted filename regex
    and the accepted-encoding set rather than by a constant, so it is a
    structural bound today and an unguarded dict if the regex ever widens.
13. Two daemon threads start before the listener binds and are never joined
    (`cli.py:1118-1131`). A failure in either is logged and the start continues,
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
  own loopback dashboard (`api.py:697`) without any credential, because the
  SPA's EventSource is same-origin and no-cors from a cross-site page. A
  quarter of the process-wide connection budget goes to it, the socket deadlines
  (`devserver.py:375`, `devserver.py:371`) reclaim each slot eventually, and
  the rest of the budget stays open to the operator's own browser.
- The same page can hold the threads without any stream at all: a keep-alive
  connection that sends one cheap request and then goes quiet holds its thread
  for 15 s, and a page that opens a few hundred of them in that window meets
  the connection cap and gets 503s for the rest (`devserver.py:148-204`).
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.
- A caller who sets `X-Request-ID` picks its own correlation id
  (`server.py:2212-2219`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:2425-2432`), rejected Host header
  (`server.py:2577-2585`), unhandled errors with a request id and traceback
  (`server.py:2518-2554`), coverage-document unavailability (`server.py:2483-2515`), oversized
  or unconfigured target binary (`server.py:1313-1341`), regen start, replay,
  completion and failure (`api.py:2324`, `api.py:2233`, `api.py:2393`,
  `api.py:2437`), slow requests at WARNING (`server.py:2281-2289`), and
  health-state transitions (`api.py:992-1012`). Everything else is DEBUG and
  off by default.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`server.py:2212-2219`), echoed on the response (`server.py:2272`), so a
  report of "the export was slow" is matchable to a specific line.
- `SECURITY.md` records the supported version line and the fact that no
  reporting address is defined in the repository.
