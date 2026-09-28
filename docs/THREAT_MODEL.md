# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-29, against
`__version__ = "3.0.0"` (`src/recoverage/__init__.py:40`).

What ReCoverage is: a read-mostly web dashboard over the clear-text coverage
documents (`db/coverage-<target>.toml`) that rebrew's pipeline prints, served by
Bottle on a threaded `wsgiref` whose transport half lives in `devserver.py`
(`devserver.py:135-472`, wired at `cli.py:1195-1200`). The intended audience is a
single developer on their own machine, viewing a decompilation project they
control. Everything below is scoped to that deployment, plus the explicitly
supported LAN case (`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:794-812`, `cli.py:1074-1077`, `server.py:2625-2690`, `api.py:1999`, `api.py:2168` | Acknowledgement only: a red message and `typer.Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:1408` (`/data`), `potato.py:1238` (`/potato`), `api.py:1999` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server._evict_oldest`, `server.py:2151`; caps at `api.py:253`, `api.py:453`, `api.py:470`); the only per-route cap below the process-wide connection cap is on `/api/events` (`api.py:696`). The static-asset memo `ui._STATIC_CACHE` (`ui.py:504`) has no count cap; it is bounded structurally by the route-matched filename and encoding variant instead |
| 3 | The failed-token window is keyed on the requesting peer, and the key is the raw `REMOTE_ADDR` string, so a client that can choose its source address gets a fresh window per spelling: 10 attempts per key per 60 s, not per identity, and every host behind one NAT shares a window | `server.py:2564-2588`, `server.py:2650` | The window is per peer rather than process-wide, so one client can no longer answer 429 to the operator (`server.py:2639-2642`); the prune, the cap check and the slot reservation share one lock, so a burst of concurrent bad tokens from one key cannot slip past the cap; the peer map is bounded at 1024 keys by `_evict_oldest` (`server.py:2554`, `server.py:2580`); a verified request clears only its own peer's window (`server._clear_auth_failures`, `server.py:2591-2601`), so a success is not a reset button for a guesser. See gap 4 below for what the keying does not bound |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:201-209`, `potato.py:1244`, `server.py:2360-2391` | `Referrer-Policy: no-referrer` (`server.py:2917`), `HttpOnly; SameSite=Strict` cookie (`server.py:2389`), constant-time compare (`server.py:2346-2361`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which coverage directory is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:34-73`, `server.py:1265-1323`, `ui.py:266-268` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `ThreadingMixIn` runs one daemon thread per connection, so a flood of ordinary requests, or a set of idle keep-alive connections, spends a thread each while they are held | `devserver.py:135-270`, `devserver.py:407`, `devserver.py:411` | Connections are admitted against `_MAX_CONNECTIONS` (128, `devserver.py:52`) and refused at the cap with a 503 and a `Retry-After`, before a thread is created (`devserver.py:180-236`); a 120 s per-socket deadline on every read and write in flight (`devserver.py:303`, `devserver.py:407`) and a 15 s idle deadline between requests (`devserver.py:278`, `devserver.py:411`); `/api/events` carries its own lower cap (`api.py:696`) |
| 7 | Any local process can trigger a full re-catalog and coverage rebuild (disk and CPU), repeatedly within the cooldown | `api.py:2251-2414` | Loopback peer check, same-origin (`server.origin_is_this_dashboard`) and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`api.py:123-233`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, TOML parser messages, echoed user input) to the client | `server.py:2270-2296`, `server.py:2736`, `api.py:2305-2414` | Tracebacks never reach a response body (`server.py:2771-2809`); only the one-line exception class and a rebuild hint do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:1440-1475`, `api.py:1999-2167` | `_MAX_DLL_SIZE` (512 MiB, `server.py:1170`) checked on `stat()` (`server.py:1453-1461`) and again post-read (`server.py:1462-1470`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:2625-2690` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:2678-2685`, `server.py:2828-2837`); regen start, replay, completion and failure are logged (`api.py:2433`, `api.py:2488`, `api.py:2503`, `api.py:2550`) |
| 11 | Twelve `RECOVERAGE_*` environment variables select the bind address, the token, the coverage directory, the log level, the CORS allowlist and the transport bounds, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) reads as unset rather than rejected, and two of the twelve (`RECOVERAGE_FUZZ_SEED`, `RECOVERAGE_FUZZ_ITERATIONS`) are accepted under the prefix but consumed only by the test suite | `config.py:45-60`, `config.py:103-107`, `config.py:151-313`, `cli.py:433` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:453-461`); a SET-but-empty value is an error everywhere except `RECOVERAGE_TOKEN`, where it means "auth off" on purpose |

Owner and review cadence: not stated in the repository.

## Entry points

Transport, before any route runs:

- `cli._server_class_for` (`cli.py:127-143`) picks the socket family from the
  bind address through `getaddrinfo`, and `cli._ThreadingWSGIServer6`
  (`cli.py:111-124`) is the `AF_INET6` class. On Linux a wildcard `AF_INET6`
  socket also accepts IPv4-mapped peers, which is the case
  `server._peer_is_loopback` (`server.py:101-124`) has to answer correctly for
  `POST /api/regen`.
- `devserver._ThreadingWSGIServer` (`devserver.py:135-270`): one daemon thread
  per connection, admitted against `_MAX_CONNECTIONS` and refused with a 503
  above it.
- `devserver._KeepAliveRequestHandler` (`devserver.py:348-430`): HTTP/1.1
  keep-alive, so one connection carries many requests. The 65537-byte request
  line read (`devserver.py:395`, `devserver.py:412`) and the 414 on overflow
  (`devserver.py:397-401`) are the only framing limits.
- `devserver._KeepAliveServerHandler` (`devserver.py:433-472`): a response with
  no `Content-Length` and no `Transfer-Encoding` is sent with `Connection:
  close`, which is what keeps the unframed `/api/events` stream from
  misframing the next response on the socket.

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:201-203`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:209`,
  `server.set_auth_cookie`).
- `GET /potato` - `potato.py:1238`, which owns both the route and the
  renderer (`render_potato`, `potato.py:1154`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:266-267`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:533`. Package-shipped
  JS/CSS/SVG.
- `GET /api/health` `api.py:1027`, `GET /api/targets` `api.py:1180`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `api.py:1235`, `api.py:1408`, `api.py:1644`, `api.py:1962`, `api.py:1999`,
  `api.py:2168`.
- `POST /api/targets/<t>/functions` - `api.py:1921`, the only body-carrying
  endpoint.
- `GET /api/events` - `api.py:932`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:2251`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:2947-2950`, CORS preflight catch-all.
- `@app.error(500)` - `server.py:2771`. The response surface for every
  unhandled exception, and the only place `_reclassify_request` is called
  (`server.py:2789`, `server.py:2797`).
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `webapp.py:112-113`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `webapp.py:128-146`, the JSON/HTML
  split by `/api/` prefix.

The one body-carrying endpoint parses the message framing as well as the
payload, and the framing is the part a client chooses freely:
`server.read_request_body` (`server.py:543`), its chunked arm
`server._read_chunked_body` (`server.py:471`), its declared-length arm
`server._declared_content_length` (`server.py:448`) and the `Transfer-Encoding`
sniff `server._body_is_chunked` (`server.py:466`). So `Content-Length`,
`Transfer-Encoding`, `Content-Type` and the chunk-size lines are entry points
in their own right, and the framing errors they produce
(`server.RequestBodyError` and its two subclasses, `server.py:408-441`) are
one of the answers a client can elicit before the payload is ever parsed.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `X-Request-ID`, `Accept-Encoding`,
`If-None-Match`, `Content-Length`, `Transfer-Encoding`, `Content-Type` are
headers; `token`, `target`, `va`, `section`, `status`, `search`, `sort`,
`limit`, `offset`, `size`, `offset`, `format` are query values;
`{"vas": [...]}` is the only request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open`, `config`
  (`cli.py:954`, `cli.py:1262`, `cli.py:1350`, `cli.py:1549`, `cli.py:1665`,
  `cli.py:1691`, `cli.py:1740`), plus the global `--no-color` / `--version`
  callback (`cli.py:185-193`). The operator's shell is the trust source.
  `recoverage config` prints every resolved setting including whether a token
  is set (`cli.py:1740-1800`), so it reaches the same secret-presence question as
  `serve`.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL`, `RECOVERAGE_MAX_CONNECTIONS`,
  `RECOVERAGE_CLIENT_TIMEOUT`, `RECOVERAGE_FUZZ_SEED`,
  `RECOVERAGE_FUZZ_ITERATIONS` (`config.py:45-60`). Flags win over the
  environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`config.py:453-461`). `RECOVERAGE_TOKEN`
  is the only secret; `RECOVERAGE_LOG_LEVEL` is the only one that changes what
  an operator can see, since at DEBUG the per-request lines
  (`server.py:2494-2517`) reach the log. `NO_COLOR` and `TERM`
  (`cli.py:66-79`) are the only non-prefixed environment reads and are
  cosmetic.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:34-73`, `server.py:1265-1323`).
- The target binary named by `[targets.*].filename`, resolved by
  `_target_filename` / `_find_dll_path` (`server.py:1311`,
  `server.py:1371`).
- Filesystem: `db/coverage-<target>.toml` (read as UTF-8 text through
  `rebrew.coverage_toml`, `rebrew/coverage_toml.py:1205-1223`, reached at
  `server.py:727`; nothing is held open between requests), `<project>/src`,
  `<project>/original`, and the function source files Potato Mode reads directly
  through its own resolve-and-contain check (`potato.py:2660-2690`).
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:718`), argv list, own session, killed and reaped on a 10 s
  timeout (`cli.py:654`).
- Startup threads, all daemon and none joined: the coverage watcher
  (`api._ensure_db_watcher`, `cli.py:1171-1187`) and the SPA shell warm-up
  (`ui.warm_index_cache`, `cli.py:1177-1190`, which builds 8 compression
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
(`cli.py:433`). The in-process capstone parse behind `/asm` lives in
`disasm.py`, reached from the route at `api.py:1999` and called at
`api.py:2155`; the JSON branch in the route itself is the only disassembly it
performs.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: the `before_request` hooks in registration
   order - `_start_request`, `_require_auth`, then the Host allowlist
   (installed from `cli.py:1104-1109`) - then per-handler
   bounds (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at `api.py:1498-1514`;
   `_MAX_PAGE_OFFSET` at `api.py:1520`; `_MAX_SLICE_SIZE` at `api.py:1525`;
   `_MAX_SEARCH_CHARS` at `api.py:1530`). The body cap is enforced where the
   body is read, not in the handler: `api._batch_request_vas` calls
   `server.read_request_body(_MAX_BATCH_BODY_BYTES)` (`api.py:1777`), which
   compares the declared `Content-Length` before a byte is read, reads a
   framed body to its declared length and no further, and bounds a chunked
   body on the DECODED bytes (`server.py:448-541`). Auth runs before the Host check, so
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
   `server.py:727`; the reader is `rebrew.coverage_toml`,
   `rebrew/coverage_toml.py:1205-1221`). The documents are attacker-supplied in
   the same sense the database file was: whoever can write into the coverage
   directory decides what every dashboard shows, and the values are trusted as
   data, never as code. Parsing is `tomllib`, so a malformed document raises
   instead of executing; the reader validates the format version, the shape of
   every array and table, and that the document's `target` matches its filename,
   and every failure is one `CoverageTomlError`.
   Unreadable is not empty, and the two answers stay distinguishable. A document
   that exists and does not parse raises `CoverageTomlError`, which is the 503
   `db_unavailable` contract (`server._db_unavailable_err`, `server.py:2736`);
   a target `rebrew-project.toml` declares that no build has written is served
   from an empty snapshot (`server.coverage_for`, `server.py:756-787`), which is
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
   (`api.py:757-800`) pushes `db-updated` so the SPA re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:266-320`).
   Potato Mode's source panel repeats the containment check independently
   (`potato.py:2681-2690`).
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
  `server.configure_security` (`server.py:127`, assigned at `server.py:143-150`,
  called from `cli.py:1104`) and held for the process lifetime. It is never
  written to disk by this package. It is echoed in neither direction: a
  successful compare and a failed one both answer the same 401
  (`server._require_auth`, `server.py:2625-2690`), and the log records the peer
  address, never the value (`server.py:2678-2685`).
- **Leaves** in three forms, all of them places the value is recoverable
  rather than exchanged: the `?token=` query parameter on a share link
  (`ui.py:201-209`, `potato.py:1244`), the `recoverage_token` cookie
  (`server.AUTH_COOKIE_NAME`, `server.py:2360`, set `HttpOnly; SameSite=Strict`
  and without `Secure`, `server.py:2389`), and the `Authorization: Bearer`
  header. A wrong value is rate-limited per peer, and the value itself is not
  protected in transit on a non-loopback bind.

Rotation is a restart: `configure_security` is called once from `serve` and
nothing reloads `_AUTH_TOKEN` afterwards, so a rotated token is the new
process's, and the old one stays valid until every client has been given the
new one. The set/unset rendering (`config.active_config`,
`config.py:465`, surfaced by `recoverage config` (`cli.py:1762`) and by the
`config` block of `GET /api/health` (`api.py:1112`), confirms presence to
anyone who can reach those, and nothing else about the value.

## Threats per boundary

**Client to app.** Spoofing: a page on any origin can drive a loopback browser
at the dashboard; mitigated by the Host allowlist on loopback binds
(`server.py:92`, `server.py:2811-2844`, installed at
`cli.py:1104-1109`) and by the `Sec-Fetch-Site` rejection on regen
(`api.py:2310-2325`). Tampering: only regen writes, and only from loopback.
Information disclosure: `/src` and `/original` proxy the whole project tree,
and the byte and asm endpoints serve arbitrary offsets of the original binary
(`api.py:2168`, `api.py:1999`) with no per-resource authorization.
`GET /api/health` additionally hands any authenticated client the process's
resolved deployment: bind address, `allow_remote`, the CORS allowlist, log
level, connection and timeout caps, and whether a token is set
(`api.py:1027`, `config.py:465`). Every field is a setting the operator
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
deadline (`devserver.py:303`) takes it, and the read is bounded by the frame,
not by EOF, precisely so that stall cannot run to the client. The residual
gap is that the cap is a length comparison and a byte count, not a
concurrent-bytes-per-connection budget: `_MAX_BATCH_BODY_BYTES` is per request
(`api.py:1530`), so `_MAX_CONNECTIONS` requests of the maximum size are
admitted at once.

**Client to transport.** HTTP/1.1 keep-alive means a client that opens
connections without closing them holds a thread each until the 15 s idle
deadline, which is longer than a slow page load and much shorter than the 120 s
in-flight one (`devserver.py:407-412`, `devserver.py:395-412`). A connection
past the cap is refused before it gets a thread, with a 503, a `Retry-After`
and a WARNING line naming the count (`devserver.py:180-236`, `_MAX_CONNECTIONS`
at `devserver.py:52`), so the ceiling on live threads is that cap and the
refusal is visible to the operator rather than a silent stall. A
request line over 65536 bytes is answered 414 and the connection dropped
(`devserver.py:395-401`), which is the only framing resource bound.

**App to coverage documents.** Tampering is bounded by the direction of the
dependency: this server only reads, and the only writer is `rebrew build-db`,
which replaces each document whole through a temporary sibling and an atomic
rename (`rebrew/coverage_toml.py:701-704`), so a reader sees the previous
document or the new one and never a torn write. A document the reader cannot use
is answered 503 rather than half-served. Denial of service remains: a large
function list with a `search` term is walked per request (`api.py:525-560`,
`api.py:1650`), bounded only by a 64-entry memo (`api.py:470`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:266-320`, `potato.py:2681-2690`); what remains is that the trees are
served in full, so a `.env` or a key committed under `src/` is published to
every client.

**App to local process.** A local, unauthenticated process can trigger regen.
The `Origin` and `Sec-Fetch-Site` checks stop the browser-shaped version; they
do not stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely
when an `Origin` is sent that the same-origin test accepts
(`server.origin_is_this_dashboard`, `server.py:265-287`: the origin's host and
port against the request's own `Host`, so a page on another loopback port is
refused). Regen runs with no timeout by design (`regen.py:13-17`).

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the coverage directory or the listener.
There is no prompt and no warning when a config changes under a running server;
the memoized path just recomputes (`_paths.py:34-73`, `server.py:1265-1323`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `server.py:2346-2361`, `server.py:2625-2690` | Spoofing, unauthorized read |
| Per-peer failure throttle with 429 + `Retry-After` (10 per 60 s, keyed on `REMOTE_ADDR`), prune, cap check and slot reservation under one lock, peer map bounded at 1024 keys, a verified request clearing only its own peer's window | `server.py:2564-2588`, `server.py:2591-2601`, `server.py:2644-2690` | Online token guessing, check-then-act races under concurrency, an operator locked out by one hostile client, and a guesser reset by the operator's own traffic |
| Host header allowlist on loopback binds, with a warning naming the rejected value and the peer | `server.py:92`, `server.py:2811-2844` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:794-812`, `cli.py:1074-1077` | Accidental LAN exposure |
| Every request-supplied integer goes through `server.parse_ascii_int`: ASCII digits in the stated base and nothing else, with `api._parse_byte_count` and `api._page_int` on top | `server.py:390`, `api.py:1555`, `api.py:1574` | Digit-set smuggling: `int(x, base)` also accepts the whole Unicode Nd/Nl/No sets and the `_` separator, so `?size=٤٠٩٦` served a 4096-byte slice and `?page=1_0` opened page 10 |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:453-461`, `config.py:151-313`, `cli.py:433` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and same-origin `Origin` gate on regen | `api.py:2296-2325` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:123`, `api.py:129`, `api.py:2340-2400` | Concurrent torn rebuilds, regen flood |
| `Idempotency-Key` ledger: charset-validated (`[A-Za-z0-9._:-]`, 128 chars), 600 s TTL, 128-slot eviction, a completed run replayed and an in-flight run answered 202 with `in_progress` before the cooldown | `api.py:145-233`, `api.py:2320-2356` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:2887-2945` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `server.py:2898-2945`, `cli.py:729-766` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `ui.py:266-320` | Path traversal |
| Independent containment check on Potato Mode's source panel | `potato.py:2681-2690` | Path traversal through a second reader |
| Allowlist regex for package assets | `ui.py:533` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:1498-1530`, `api.py:1555-1600`, `api.py:1777-1960` | Memory and CPU exhaustion per request |
| Body read through `server.read_request_body`, never `request.body`: the declared `Content-Length` is compared before a byte is read, a framed body is read to its declared length and no further, a chunked body is bounded on the DECODED bytes, a chunk-size line is capped at 1 KiB and read through `parse_ascii_int` | `server.py:448-541`, `api.py:1777` | A declared 4 GB body allocated before the endpoint's own cap could look at it; a `read()` to EOF parking the handler until the client hangs up; a chunk line smuggling a length through a non-ASCII digit set or the `_` separator. Bottle's `request.body` drains the whole declared body into a `BytesIO` and spills past 100 KiB into a `NamedTemporaryFile`, so the resource the cap exists to bound was allocated first |
| Every body refusal answers `Connection: close` through `api._body_rejected`, the one helper that puts the header there | `api.py:1765-1775` | Request smuggling: the reader stops at its cap, so the bytes after the stop point are still in the socket and a keep-alive handler would parse them as the next request |
| Chunked and unframed framing refused rather than guessed: a non-hex chunk size, an unterminated chunk, a missing CRLF or an oversize trailer line is `RequestBodyMalformedError` | `server.py:471-541` | A framing this reader cannot account for, silently accepted as a shorter body |
| `sort` field and direction whitelisted against `_ALLOWED_SORT` and applied as an in-memory sort key | `api.py:522`, `api.py:1685-1700` | Arbitrary field access through the sort parameter. The SQLite-era `ORDER BY` interpolation this row used to name is gone with the query builder: the rows are Python objects, so there is no statement for a sort value to reach |
| Search is a folded substring test in Python (`server.fold_match`) | `server.py:1771-1794`, `api.py:525-560` | Wildcard abuse and non-ASCII misses in search. There is no SQL `LIKE` pattern any more, so the escape helper and the `rc_fold` disjunct beside the ASCII `LIKE` are gone with the SQL |
| `SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `api.py:696`, `api.py:932-1000` | Thread exhaustion via event streams, slow-client memory growth |
| Connection cap: `_MAX_CONNECTIONS` slots taken before the thread, refused with a hand-written 503 plus `Retry-After` above it, released on every exit including thread-creation failure | `devserver.py:52`, `devserver.py:180-236` | Thread and descriptor exhaustion from a flood of stalled peers. Refusing at accept rather than in the handler keeps the bound on the resource: a connection that never got a thread cannot pin one. The refusal is a `WARNING` naming the count, so the ceiling is legible to the operator |
| Per-socket 120 s in-flight deadline and 15 s keep-alive idle deadline | `devserver.py:269`, `devserver.py:278`, `devserver.py:407-411` | Threads pinned by half-open or non-reading peers, and by idle keep-alive connections |
| 65536-byte request-line cap, answered 414 | `devserver.py:283`, `devserver.py:395-401` | Unbounded per-connection read |
| Documents are read as UTF-8 text and never written by this server; the only writer is `rebrew build-db`, which replaces each document whole through an atomic rename | `server.py:727`, `rebrew/coverage_toml.py:701-704` | Accidental writes, and a torn read of a document being rebuilt |
| Document gate: the format `version` must be the one this build reads, every array and table must have its documented shape, and the document's `target` must match its filename; a failure is answered 503 | `server.py:2736`, `rebrew/coverage_toml.py:1170-1176` | A truncated, foreign or hand-edited document reading as an empty target, and query-time 500s from a document the reader cannot use |
| Basename-only coverage-directory name in health and SSE payloads | `api.py:1042`, `api.py:725` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `server.py:2270-2296`, `server.py:2771-2809`, `server.py:1202` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store` on the 401 page | `server.py:833-860`, `server.py:2625-2690` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `server.py:2407-2437`, `server.py:2437` | Untraceable incidents; forged log lines |
| Status reclassification inside the 500 handler | `server.py:2520-2531`, `server.py:2789`, `server.py:2797` | An error rate that silently reads zero. Note the scope: the two call sites are the 503 (coverage documents unavailable) and the 500 itself, both inside `@app.error(500)`; there is no 4xx reclassification path |

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
4. The token throttle is keyed on the raw `REMOTE_ADDR` string
   (`server.py:2650`), so the bound is 10 attempts per KEY, not per client. A
   process that can choose its source address (any local process against a
   loopback bind, and the internet behind a proxy that folds a client-supplied
   forwarded address into `REMOTE_ADDR`) walks `127.0.0.0/8`, or the
   IPv4-mapped and plain spellings of one address, for `_AUTH_FAIL_MAX` fresh
   windows apiece (`server.py:2547-2559`). One window is one key, so it does
   not bound a distributed guessing rate. Requests whose environ carries no
   `REMOTE_ADDR` share the single `_UNKNOWN_PEER` bucket (`server.py:2559`,
   `server.py:2650`), which is one shared window for every such client by
   design, so a WSGI harness in front of the app degrades the per-peer property
   back to the process-wide one. Every host behind one NAT also shares one
   window, so 10 failures anywhere on that network answer 429 to the operator
   for the rest of the 60 s.
5. No TLS and no token transport hardening; the token is a URL parameter by
   design, which puts it in browser history, shell history and any proxy log.
   The auth cookie is set without `Secure` (`server.py:2389`), so it crosses a
   plaintext non-loopback bind intact.
6. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
7. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:1462`
   performs an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:1463-1470`). A target binary that grows between the size check at
   `server.py:1453` and the read is fully loaded into memory.
8. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
9. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:2494-2517`), and nothing distinguishes one
   holder of the shared token from another. The in-process RED counters
   (`metrics.py`) are a live gauge, not a record, and are lost on restart.
10. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
    crafted target is a worker-level availability and memory-safety risk that
    only the size cap touches, and that cap is post-read.
11. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`server.py:2887-2909`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.
12. `ui._STATIC_CACHE` (`ui.py:504`) has no count cap and no eviction, unlike
    the three `api.py` memos. It is bounded by the allowlisted filename regex
    and the accepted-encoding set rather than by a constant, so it is a
    structural bound today and an unguarded dict if the regex ever widens.
13. Two daemon threads start before the listener binds and are never joined
    (`cli.py:1171-1190`). A failure in either is logged and the start continues,
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
  own loopback dashboard (`api.py:696`) without any credential, because the
  SPA's EventSource is same-origin and no-cors from a cross-site page. A
  quarter of the process-wide connection budget goes to it, the socket deadlines
  (`devserver.py:411`, `devserver.py:407`) reclaim each slot eventually, and
  the rest of the budget stays open to the operator's own browser.
- The same page can hold the threads without any stream at all: a keep-alive
  connection that sends one cheap request and then goes quiet holds its thread
  for 15 s, and a page that opens a few hundred of them in that window meets
  the connection cap and gets 503s for the rest (`devserver.py:180-236`).
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.
- A caller who sets `X-Request-ID` picks its own correlation id
  (`server.py:2407-2437`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:2678-2685`), rejected Host header
  (`server.py:2828-2837`), unhandled errors with a request id and traceback
  (`server.py:2771-2809`), coverage-document unavailability (`server.py:2736`), oversized
  or unconfigured target binary (`server.py:1440-1475`), regen start, replay,
  completion and failure (`api.py:2433`, `api.py:2488`, `api.py:2503`,
  `api.py:2550`), slow requests at WARNING (`server.py:2494-2517`), and
  health-state transitions (`api.py:1005`). Everything else is DEBUG and
  off by default.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`server.py:2407-2437`), echoed on the response, so a
  report of "the export was slow" is matchable to a specific line.
- `SECURITY.md` records the supported version line and the fact that no
  reporting address is defined in the repository.
