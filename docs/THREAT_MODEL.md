# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-29, against
`__version__ = "4.1.2"` (`src/recoverage/__init__.py`).

What ReCoverage is: a read-mostly web dashboard over the clear-text coverage
documents (`db/coverage-<target>.toml`) that rebrew's pipeline prints, served by
Bottle on a threaded `wsgiref` whose transport half lives in `src/recoverage/devserver.py`
(`src/recoverage/devserver.py`, wired at `src/recoverage/cli.py`). The intended audience is a
single developer on their own machine, viewing a decompilation project they
control. Everything below is scoped to that deployment, plus the explicitly
supported LAN case (`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `src/recoverage/cli.py`, `src/recoverage/server.py`, `src/recoverage/api.py` | Acknowledgement only: a red message and `typer.Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `src/recoverage/api.py` (`/data`), `src/recoverage/potato.py` (`/potato`), `src/recoverage/api.py` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server._evict_oldest`, `src/recoverage/server.py`; caps at `src/recoverage/api.py`); the only per-route cap below the process-wide connection cap is on `/api/events` (`src/recoverage/api.py`). The static-asset memo `ui._STATIC_CACHE` (`src/recoverage/ui.py`) has no count cap; it is bounded structurally by the route-matched filename and encoding variant instead |
| 3 | The failed-token window is keyed on the requesting peer, and the key is the raw `REMOTE_ADDR` string, so a client that can choose its source address gets a fresh window per spelling: 10 attempts per key per 60 s, not per identity, and every host behind one NAT shares a window | `src/recoverage/server.py` | The window is per peer rather than process-wide, so one client can no longer answer 429 to the operator (`src/recoverage/server.py`); the prune, the cap check and the slot reservation share one lock, so a burst of concurrent bad tokens from one key cannot slip past the cap; the peer map is bounded at 1024 keys by `_evict_oldest` (`src/recoverage/server.py`); a verified request clears only its own peer's window (`server._clear_auth_failures`, `src/recoverage/server.py`), so a success is not a reset button for a guesser. See gap 4 below for what the keying does not bound |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `src/recoverage/ui.py`, `src/recoverage/potato.py`, `src/recoverage/server.py` | `Referrer-Policy: no-referrer` (`src/recoverage/server.py`), `HttpOnly; SameSite=Strict` cookie carrying `Secure` only where the request itself arrived over TLS (`server.set_auth_cookie`, through `server.request_is_https`), constant-time compare (`src/recoverage/server.py`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which coverage directory is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `src/recoverage/_paths.py`, `src/recoverage/server.py`, `src/recoverage/ui.py` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `ThreadingMixIn` runs one daemon thread per connection, so a flood of ordinary requests, or a set of idle keep-alive connections, spends a thread each while they are held | `src/recoverage/devserver.py` | Connections are admitted against `_MAX_CONNECTIONS` (128, `src/recoverage/devserver.py`) and refused at the cap with a 503 and a `Retry-After`, before a thread is created (`src/recoverage/devserver.py`); a 120 s per-socket deadline on every read and write in flight (`src/recoverage/devserver.py`) and a 15 s idle deadline between requests (`src/recoverage/devserver.py`); `/api/events` carries its own lower cap (`src/recoverage/api.py`) |
| 7 | Any local process can trigger a full re-catalog and coverage rebuild (disk and CPU), repeatedly within the cooldown | `src/recoverage/api.py` | Loopback peer check, same-origin (`server.origin_is_this_dashboard`) and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`src/recoverage/api.py`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, TOML parser messages, echoed user input) to the client | `src/recoverage/server.py`, `src/recoverage/api.py` | Tracebacks never reach a response body (`src/recoverage/server.py`); only the one-line exception class and a rebuild hint do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `src/recoverage/server.py`, `src/recoverage/api.py` | `_MAX_DLL_SIZE` (512 MiB, `src/recoverage/server.py`) checked on `stat()` (`src/recoverage/server.py`) and again post-read (`src/recoverage/server.py`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `src/recoverage/server.py` | Rejected-token and rejected-Host events are logged with the peer address (`src/recoverage/server.py`); regen start, replay, completion and failure are logged (`src/recoverage/api.py`) |
| 11 | Twelve `RECOVERAGE_*` environment variables select the bind address, the token, the coverage directory, the log level, the CORS allowlist and the transport bounds, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) reads as unset rather than rejected, and two of the twelve (`RECOVERAGE_FUZZ_SEED`, `RECOVERAGE_FUZZ_ITERATIONS`) are accepted under the prefix but consumed only by the test suite | `src/recoverage/config.py`, `src/recoverage/cli.py` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`src/recoverage/config.py`); a SET-but-empty value is an error everywhere except `RECOVERAGE_TOKEN`, where it means "auth off" on purpose |

Owner and review cadence: not stated in the repository.

## Entry points

Transport, before any route runs:

- `cli._server_class_for` (`src/recoverage/cli.py`) picks the socket family from the
  bind address through `getaddrinfo`, and `cli._ThreadingWSGIServer6`
  (`src/recoverage/cli.py`) is the `AF_INET6` class. On Linux a wildcard `AF_INET6`
  socket also accepts IPv4-mapped peers, which is the case
  `server._peer_is_loopback` (`src/recoverage/server.py`) has to answer correctly for
  `POST /api/regen`.
- `devserver._ThreadingWSGIServer` (`src/recoverage/devserver.py`): one daemon thread
  per connection, admitted against `_MAX_CONNECTIONS` and refused with a 503
  above it.
- `devserver._KeepAliveRequestHandler` (`src/recoverage/devserver.py`): HTTP/1.1
  keep-alive, so one connection carries many requests. The 65537-byte request
  line read (`src/recoverage/devserver.py`) and the 414 on overflow
  (`src/recoverage/devserver.py`) are the only framing limits.
- `devserver._KeepAliveServerHandler` (`src/recoverage/devserver.py`): a response with
  no `Content-Length` and no `Transfer-Encoding` is sent with `Connection:
  close`, which is what keeps the unframed `/api/events` stream from
  misframing the next response on the socket.

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `src/recoverage/ui.py`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`src/recoverage/ui.py`,
  `server.set_auth_cookie`).
- `GET /potato` - `src/recoverage/potato.py`, which owns both the route and the
  renderer (`render_potato`, `src/recoverage/potato.py`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `src/recoverage/ui.py`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `src/recoverage/ui.py`. Package-shipped
  JS/CSS/SVG.
- `GET /api/health` `src/recoverage/api.py`, `GET /api/targets` `src/recoverage/api.py`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `src/recoverage/api.py`,
  `src/recoverage/api.py`.
- `POST /api/targets/<t>/functions` - `src/recoverage/api.py`, the only body-carrying
  endpoint.
- `GET /api/events` - `src/recoverage/api.py`, Server-Sent Events, long-lived.
- `POST /api/regen` - `src/recoverage/api.py`, the only state-changing endpoint.
- `OPTIONS <path>` - `src/recoverage/server.py`, CORS preflight catch-all.
- `@app.error(500)` - `src/recoverage/server.py`. The response surface for every
  unhandled exception, and the only place `_reclassify_request` is called
  (`src/recoverage/server.py`).
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `src/recoverage/webapp.py`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `src/recoverage/webapp.py`, the JSON/HTML
  split by `/api/` prefix.

The one body-carrying endpoint parses the message framing as well as the
payload, and the framing is the part a client chooses freely:
`server.read_request_body` (`src/recoverage/server.py`), its chunked arm
`server._read_chunked_body` (`src/recoverage/server.py`), its declared-length arm
`server._declared_content_length` (`src/recoverage/server.py`) and the `Transfer-Encoding`
sniff `server._body_is_chunked` (`src/recoverage/server.py`). So `Content-Length`,
`Transfer-Encoding`, `Content-Type` and the chunk-size lines are entry points
in their own right, and the framing errors they produce
(`server.RequestBodyError` and its two subclasses, `src/recoverage/server.py`) are
one of the answers a client can elicit before the payload is ever parsed.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `X-Request-ID`, `Accept-Encoding`,
`If-None-Match`, `Content-Length`, `Transfer-Encoding`, `Content-Type` are
headers; `token`, `target`, `va`, `section`, `status`, `search`, `sort`,
`limit`, `offset`, `size`, `format`, `index` (the `/data` flag that omits
`search_index`, a flag of `0`, `1` or absent) are API query values, and Potato
Mode adds `filter`, `idx`, `view` and `page` over the same
`request.query_string` (`src/recoverage/potato.py`); `{"vas": [...]}` is the only
request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open`, `config`
  (`src/recoverage/cli.py`,
  `src/recoverage/cli.py`), plus the global `--no-color` / `--version`
  callback (`src/recoverage/cli.py`). The operator's shell is the trust source.
  `recoverage config` prints every resolved setting including whether a token
  is set (`src/recoverage/cli.py`), so it reaches the same secret-presence question as
  `serve`.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL`, `RECOVERAGE_MAX_CONNECTIONS`,
  `RECOVERAGE_CLIENT_TIMEOUT`, `RECOVERAGE_FUZZ_SEED`,
  `RECOVERAGE_FUZZ_ITERATIONS` (`src/recoverage/config.py`). Flags win over the
  environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`src/recoverage/config.py`). `RECOVERAGE_TOKEN`
  is the only secret; `RECOVERAGE_LOG_LEVEL` is the only one that changes what
  an operator can see, since at DEBUG the per-request lines
  (`src/recoverage/server.py`) reach the log. `NO_COLOR` and `TERM`
  (`src/recoverage/cli.py`) are the only non-prefixed environment reads and are
  cosmetic.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`src/recoverage/_paths.py`, `src/recoverage/server.py`).
- The target binary named by `[targets.*].filename`, resolved by
  `_target_filename` / `_find_dll_path` (`src/recoverage/server.py`,
  `src/recoverage/server.py`).
- Filesystem: `db/coverage-<target>.toml` (read as UTF-8 text through
  `rebrew.coverage_toml`, `rebrew/coverage_toml.py`, reached at
  `src/recoverage/server.py`; nothing is held open between requests), `<project>/src`,
  `<project>/original`, and the function source files Potato Mode reads directly
  through its own resolve-and-contain check (`src/recoverage/potato.py`).
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`src/recoverage/cli.py`), argv list, own session, killed and reaped on a 10 s
  timeout (`src/recoverage/cli.py`).
- Startup threads, all daemon and none joined: the coverage watcher
  (`api._ensure_db_watcher`, `src/recoverage/cli.py`) and the SPA shell warm-up
  (`ui.warm_index_cache`, `src/recoverage/cli.py`, which builds 8 compression
  variants before the listener accepts). Both are started before the bind, so
  either can fail after a port is chosen but before anything answers; each logs
  and stays lazy rather than aborting the start.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`src/recoverage/regen.py` for `recoverage regen`, `serve --regen` and
`POST /api/regen`.

`recoverage serve` is not the only way in: `python -m recoverage` reaches the
same Typer app (`src/recoverage/__main__.py`), and every command validates the
`RECOVERAGE_*` environment before consuming a setting, not just `serve`
(`src/recoverage/cli.py`). The in-process capstone parse behind `/asm` lives in
`src/recoverage/disasm.py`, reached from the route at `src/recoverage/api.py` and called at
`src/recoverage/api.py`; the JSON branch in the route itself is the only disassembly it
performs.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: the `before_request` hooks in registration
   order - `_start_request`, `_require_auth`, `_reject_broken_project_config`
   (`src/recoverage/server.py`), then the Host allowlist
   (installed from `src/recoverage/cli.py`) - then per-handler
   bounds (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at `src/recoverage/api.py`;
   `_MAX_PAGE_OFFSET` at `src/recoverage/api.py`; `_MAX_SLICE_SIZE` at `src/recoverage/api.py`;
   `_MAX_SEARCH_CHARS` at `src/recoverage/api.py`). The body cap is enforced where the
   body is read, not in the handler: `api._batch_request_vas` calls
   `server.read_request_body(_MAX_BATCH_BODY_BYTES)` (`src/recoverage/api.py`), which
   compares the declared `Content-Length` before a byte is read, reads a
   framed body to its declared length and no further, and bounds a chunked
   body on the DECODED bytes (`src/recoverage/server.py`). Auth runs before the Host check, so
   a request with neither is answered 401 and a bad Host on an unauthenticated
   deployment is answered 400. The third hook is a data-source check rather
   than a credential one: a present `rebrew-project.toml` that does not parse
   answers 503 for every route, because the alternative is serving a `db/`
   directory the file never named (`server._reject_broken_project_config`,
   `src/recoverage/server.py`). `RECOVERAGE_DB` is resolved first, so an
   explicit coverage directory keeps serving an unreadable project file.
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
   The other requests it passes are a `GET` or `HEAD` of the two brand fonts,
   `/archivo.woff2` and `/jetbrains-mono.woff2` (`server._UNGATED_ASSETS`),
   which the 401 page draws in. They are OFL files, byte-identical in every
   wheel and credited in `NOTICE`, and none of the assets listed below: a peer
   fetching one learns only that recoverage is listening, which the 401 page
   already tells it. The fetch neither charges nor clears the failed-token
   window, and every other static asset (`style.css`, `app.js`, `print.css`,
   `favicon.svg`) stays gated.
2. **App to coverage documents.** `db/coverage-<target>.toml` is printed by
   `rebrew build-db` and read here, never written (`server.coverage_snapshots`,
   `src/recoverage/server.py`; the reader is `rebrew.coverage_toml`,
   `rebrew/coverage_toml.py`). The documents are attacker-supplied in
   the same sense the database file was: whoever can write into the coverage
   directory decides what every dashboard shows, and the values are trusted as
   data, never as code. Parsing is `tomllib`, so a malformed document raises
   instead of executing; the reader validates the format version, the shape of
   every array and table, and that the document's `target` matches its filename,
   and every failure is one `CoverageTomlError`.
   The parse is cached as JSON under `$XDG_CACHE_HOME/recoverage/documents/`
   (`src/recoverage/documents.py`), and a cached parse goes through the same
   validation as a fresh one, and an entry that validation refuses is discarded
   for a parse of the document itself, so whoever can write that directory can
   do no more than whoever can write the coverage directory. It is JSON, not pickle,
   because loading a pickle runs code.
   Unreadable is not empty, and the two answers stay distinguishable. A document
   that exists and does not parse raises `CoverageTomlError`, which is the 503
   `db_unavailable` contract (`server._db_unavailable_err`, `src/recoverage/server.py`);
   a target `rebrew-project.toml` declares that no build has written is served
   from an empty snapshot (`server.coverage_for`, `src/recoverage/server.py`), which is
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
   (`src/recoverage/api.py`) pushes `db-updated` so the SPA re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`src/recoverage/ui.py`).
   Potato Mode's source panel repeats the containment check independently
   (`src/recoverage/potato.py`).
4. **App to local process (regen).** The only privilege transition: a POST makes
   the server import rebrew and rebuild the coverage documents, with the
   process's own filesystem authority (`src/recoverage/regen.py`).
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
  environment (`src/recoverage/cli.py`, `src/recoverage/config.py`). The command-line form is world-readable
  in the process table for the life of the process; the environment form is
  visible to anything that can read the parent environment, which is the same
  trust as every other `RECOVERAGE_*` value.
- **Lives** in `_AUTH_TOKEN`, a module-level string set once by
  `server.configure_security` (`src/recoverage/server.py`, assigned at `src/recoverage/server.py`,
  called from `src/recoverage/cli.py`) and held for the process lifetime. It is never
  written to disk by this package. It is echoed in neither direction: a
  successful compare and a failed one both answer the same 401
  (`server._require_auth`, `src/recoverage/server.py`), and the log records the peer
  address, never the value (`src/recoverage/server.py`).
- **Leaves** in three forms, all of them places the value is recoverable
  rather than exchanged: the `?token=` query parameter on a share link
  (`src/recoverage/ui.py`, `src/recoverage/potato.py`), the `recoverage_token` cookie
  (`server.AUTH_COOKIE_NAME`, `src/recoverage/server.py`, set `HttpOnly; SameSite=Strict`
  and `Secure` only where `server.request_is_https` reads the request as
  TLS, `src/recoverage/server.py`), and the `Authorization: Bearer`
  header. A wrong value is rate-limited per peer, and the value itself is not
  protected in transit on a non-loopback bind.

Rotation is a restart: `configure_security` is called once from `serve` and
nothing reloads `_AUTH_TOKEN` afterwards, so a rotated token is the new
process's, and the old one stays valid until every client has been given the
new one. The set/unset rendering (`config.active_config`,
`src/recoverage/config.py`, surfaced by `recoverage config` (`src/recoverage/cli.py`) and by the
`config` block of `GET /api/health` (`src/recoverage/api.py`), confirms presence to
anyone who can reach those, and nothing else about the value.

## Threats per boundary

**Client to app.** Spoofing: a page on any origin can drive a loopback browser
at the dashboard; mitigated by the Host allowlist on loopback binds
(`src/recoverage/server.py`, installed at
`src/recoverage/cli.py`) and by the `Sec-Fetch-Site` rejection on regen
(`src/recoverage/api.py`). Tampering: only regen writes, and only from loopback.
Information disclosure: `/src` and `/original` proxy the whole project tree,
and the byte and asm endpoints serve arbitrary offsets of the original binary
(`src/recoverage/api.py`) with no per-resource authorization.
`GET /api/health` additionally hands any authenticated client the process's
resolved deployment: bind address, `allow_remote`, the CORS allowlist, log
level, connection and timeout caps, and whether a token is set
(`src/recoverage/api.py`, `src/recoverage/config.py`; the `config` block drops
`db`, which the `db` block beside it already answers by basename). It also
carries the live counters: request and error rates, cache hits, the regen
lifecycle, stream and connection saturation, and the `auth` block's failed
attempts and `locked_peers` gauge (`src/recoverage/api.py`,
`src/recoverage/metrics.py`). Every field is a setting the operator chose or a
count the process made, and none is the token's value, so this is a
configuration-disclosure read, a `token: set` / `unset` oracle for a client that
does not already know the answer, and a live view of whether someone is
working through the token gate. Denial of
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
deadline (`src/recoverage/devserver.py`) takes it, and the read is bounded by the frame,
not by EOF, precisely so that stall cannot run to the client. The residual
gap is that the cap is a length comparison and a byte count, not a
concurrent-bytes-per-connection budget: `_MAX_BATCH_BODY_BYTES` is per request
(`src/recoverage/api.py`), so `_MAX_CONNECTIONS` requests of the maximum size are
admitted at once.

**Client to transport.** HTTP/1.1 keep-alive means a client that opens
connections without closing them holds a thread each until the 15 s idle
deadline, which is longer than a slow page load and much shorter than the 120 s
in-flight one (`src/recoverage/devserver.py`). A connection
past the cap is refused before it gets a thread, with a 503, a `Retry-After`
and a WARNING line naming the count (`src/recoverage/devserver.py`, `_MAX_CONNECTIONS`
at `src/recoverage/devserver.py`), so the ceiling on live threads is that cap and the
refusal is visible to the operator rather than a silent stall. A
request line over 65536 bytes is answered 414 and the connection dropped
(`src/recoverage/devserver.py`), which is the only framing resource bound.

**App to coverage documents.** Tampering is bounded by the direction of the
dependency: this server only reads, and the only writer is `rebrew build-db`,
which replaces each document whole through a temporary sibling and an atomic
rename (`rebrew/coverage_toml.py`), so a reader sees the previous
document or the new one and never a torn write. A document the reader cannot use
is answered 503 rather than half-served. Denial of service remains: a large
function list with a `search` term is walked per request (`src/recoverage/api.py`,
`src/recoverage/api.py`), bounded only by a 64-entry memo (`src/recoverage/api.py`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`src/recoverage/ui.py`, `src/recoverage/potato.py`); what remains is that the trees are
served in full, so a `.env` or a key committed under `src/` is published to
every client.

**App to local process.** A local, unauthenticated process can trigger regen.
The `Origin` and `Sec-Fetch-Site` checks stop the browser-shaped version; they
do not stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely
when an `Origin` is sent that the same-origin test accepts
(`server.origin_is_this_dashboard`, `src/recoverage/server.py`: the origin's host and
port against the request's own `Host`, so a page on another loopback port is
refused). Regen runs with no timeout by design (`src/recoverage/regen.py`). The
in-process lock and cooldown are not the whole answer, because a second writer
this process cannot see (another terminal, a cron job) is a duplicate rather
than a flood: `regen._exclusive_regen` takes an advisory lock on an open
descriptor and refuses rather than queues (`src/recoverage/regen.py`), so a
second pipeline cannot interleave a whole-document replace with the first.

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the coverage directory or the listener.
There is no prompt and no warning when a config changes under a running server;
the memoized path just recomputes (`src/recoverage/_paths.py`, `src/recoverage/server.py`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `src/recoverage/server.py` | Spoofing, unauthorized read |
| Per-peer failure throttle with 429 + `Retry-After` (10 per 60 s, keyed on `REMOTE_ADDR`), prune, cap check and slot reservation under one lock, peer map bounded at 1024 keys, a verified request clearing only its own peer's window | `src/recoverage/server.py` | Online token guessing, check-then-act races under concurrency, an operator locked out by one hostile client, and a guesser reset by the operator's own traffic |
| Host header allowlist on loopback binds, with a warning naming the rejected value and the peer | `src/recoverage/server.py` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `src/recoverage/cli.py` | Accidental LAN exposure |
| Every request-supplied integer goes through `server.parse_ascii_int`: ASCII digits in the stated base and nothing else, with `api._parse_byte_count` and `api._page_int` on top | `src/recoverage/server.py`, `src/recoverage/api.py` | Digit-set smuggling: `int(x, base)` also accepts the whole Unicode Nd/Nl/No sets and the `_` separator, so `?size=٤٠٩٦` served a 4096-byte slice and `?page=1_0` opened page 10 |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `src/recoverage/config.py`, `src/recoverage/cli.py` | Misconfigured deployment, misspelled env var |
| Present-but-unreadable `rebrew-project.toml` refused on every route by a `before_request` hook, after auth and before any read | `src/recoverage/server.py` | Serving a `db/` directory the project file never named, which reads as a project with no coverage rather than as a broken config |
| Grid lattice width from a document's `columns` clamped to `_MAX_GRID_COLUMNS` (256) before the table is sized | `src/recoverage/potato.py` (`layoutSection`), `web/app/grid/pack.ts` (`MAX_GRID_COLUMNS`) | A document carrying an unbounded `columns` asking the renderer for gigabytes of table. The document's numbers are read as plain ints with no ceiling, so the bound is the only thing between a hostile document and the allocation |
| `Sec-Fetch-Site: cross-site` and same-origin `Origin` gate on regen | `src/recoverage/api.py` | Cross-site POST |
| Regen refuses to run when rebrew would write a coverage directory the dashboard does not read (`regen._check_writes_where_the_dashboard_reads`, `RECOVERAGE_DB` compared against `rebrew.workspace.db_dir`), raised as `RegenDbMismatchError` and answered as exit 2 by the CLI or a JSON 500 by the API | `src/recoverage/regen.py`, `src/recoverage/cli.py`, `src/recoverage/api.py` | A regen that reports `Done` after rewriting documents no served directory reads: a silent staleness, which reads as a dashboard that simply never refreshes |
| Single-flight lock + cooldown on regen | `src/recoverage/api.py` | Concurrent torn rebuilds, regen flood |
| Cross-process advisory lock on regen (`.recoverage-regen.lock`, taken on an open descriptor in the directory `rebrew.workspace.db_dir` resolves, non-blocking, released by the kernel when a holder dies; a held lock raises `RegenBusyError`, answered as exit 1 by the CLI and as the 429 the in-process lock sends, counted under `rejected`) | `src/recoverage/regen.py`, `src/recoverage/api.py` | A duplicate this process cannot see: a `recoverage regen` at another terminal, or a cron job over the same tree. The writer replaces each `coverage-<target>.toml` whole, so two writers interleave and a reader can land between one truncate and its write. Taking it on a descriptor is what releases it when a regen is killed mid-run, which a lock file's mere presence could not do |
| `Idempotency-Key` ledger: charset-validated (`[A-Za-z0-9._:-]`, 128 chars), 600 s TTL, 128-slot eviction, a completed run replayed and an in-flight run answered 202 with `in_progress` before the cooldown | `src/recoverage/api.py` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `src/recoverage/server.py` | Injection, framing, token leak via Referer |
| `Secure` on the auth cookie and `Strict-Transport-Security` beside it, both read off the request through `server.request_is_https` (`wsgi.url_scheme`, or `X-Forwarded-Proto` behind a TLS-terminating proxy) | `server.set_auth_cookie`, `src/recoverage/server.py` | A cookie handed to whoever was on the wire when a reader followed an http link to a host that also answers https. A constant `Secure` would instead stop the cookie being stored at all on the plaintext loopback bind the bundled listener serves, and neither answer is a bypass: a client that claims https over plaintext only ever makes the response stricter |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `src/recoverage/server.py`, `src/recoverage/cli.py` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `src/recoverage/ui.py` | Path traversal |
| Independent containment check on Potato Mode's source panel | `src/recoverage/potato.py` | Path traversal through a second reader |
| Allowlist regex for package assets | `src/recoverage/ui.py` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `src/recoverage/api.py` | Memory and CPU exhaustion per request |
| `/data` single flight: one leader builds a cold payload while followers park on its claim, with the claim reclaimed on `_DATA_CACHE_BUILD_WAIT_SECONDS` and a reclaimed stale claim counted as `requests.stale_claims` with a log line naming the target and section | `src/recoverage/api.py` | A herd of simultaneous cold misses paying for the same grid build once each, and an in-flight marker whose owner was killed holding a claim no `finally` will ever release |
| Body read through `server.read_request_body`, never `request.body`: the declared `Content-Length` is compared before a byte is read, a framed body is read to its declared length and no further, a chunked body is bounded on the DECODED bytes, a chunk-size line is capped at 1 KiB and read through `parse_ascii_int` | `src/recoverage/server.py`, `src/recoverage/api.py` | A declared 4 GB body allocated before the endpoint's own cap could look at it; a `read()` to EOF parking the handler until the client hangs up; a chunk line smuggling a length through a non-ASCII digit set or the `_` separator. Bottle's `request.body` drains the whole declared body into a `BytesIO` and spills past 100 KiB into a `NamedTemporaryFile`, so the resource the cap exists to bound was allocated first |
| Every body refusal answers `Connection: close` through `api._body_rejected`, the one helper that puts the header there | `src/recoverage/api.py` | Request smuggling: the reader stops at its cap, so the bytes after the stop point are still in the socket and a keep-alive handler would parse them as the next request |
| Chunked and unframed framing refused rather than guessed: a non-hex chunk size, an unterminated chunk, a missing CRLF or an oversize trailer line is `RequestBodyMalformedError` | `src/recoverage/server.py` | A framing this reader cannot account for, silently accepted as a shorter body |
| `sort` field and direction whitelisted against `_ALLOWED_SORT` and applied as an in-memory sort key | `src/recoverage/api.py` | Arbitrary field access through the sort parameter. The SQLite-era `ORDER BY` interpolation this row used to name is gone with the query builder: the rows are Python objects, so there is no statement for a sort value to reach |
| Search is a folded substring test in Python (`server.fold_match`) | `src/recoverage/server.py`, `src/recoverage/api.py` | Wildcard abuse and non-ASCII misses in search. There is no SQL `LIKE` pattern any more, so the escape helper and the `rc_fold` disjunct beside the ASCII `LIKE` are gone with the SQL |
| `_SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `src/recoverage/api.py` | Thread exhaustion via event streams, slow-client memory growth |
| Connection cap: `_MAX_CONNECTIONS` slots taken before the thread, refused with a hand-written 503 plus `Retry-After` above it, released on every exit including thread-creation failure | `src/recoverage/devserver.py` | Thread and descriptor exhaustion from a flood of stalled peers. Refusing at accept rather than in the handler keeps the bound on the resource: a connection that never got a thread cannot pin one. The refusal is a `WARNING` naming the count, so the ceiling is legible to the operator |
| Per-socket 120 s in-flight deadline and 15 s keep-alive idle deadline | `src/recoverage/devserver.py` | Threads pinned by half-open or non-reading peers, and by idle keep-alive connections |
| 65536-byte request-line cap, answered 414 | `src/recoverage/devserver.py` | Unbounded per-connection read |
| Documents are read as UTF-8 text and never written by this server; the only writer is `rebrew build-db`, which replaces each document whole through an atomic rename | `src/recoverage/server.py`, `rebrew/coverage_toml.py` | Accidental writes, and a torn read of a document being rebuilt |
| Document gate: the format `version` must be the one this build reads, every array and table must have its documented shape, and the document's `target` must match its filename; a failure is answered 503 | `src/recoverage/server.py`, `rebrew/coverage_toml.py` | A truncated, foreign or hand-edited document reading as an empty target, and query-time 500s from a document the reader cannot use |
| Basename-only coverage-directory name in health and SSE payloads | `src/recoverage/api.py` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `src/recoverage/server.py` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store` on the 401 page | `src/recoverage/server.py` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `src/recoverage/server.py` | Untraceable incidents; forged log lines |
| Status reclassification inside the 500 handler | `src/recoverage/server.py` | An error rate that silently reads zero. Note the scope: the two call sites are the 503 (coverage documents unavailable) and the 500 itself, both inside `@app.error(500)`; there is no 4xx reclassification path |

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
   (`src/recoverage/server.py`), so the bound is 10 attempts per KEY, not per client. A
   process that can choose its source address (any local process against a
   loopback bind, and the internet behind a proxy that folds a client-supplied
   forwarded address into `REMOTE_ADDR`) walks `127.0.0.0/8`, or the
   IPv4-mapped and plain spellings of one address, for `_AUTH_FAIL_MAX` fresh
   windows apiece (`src/recoverage/server.py`). One window is one key, so it does
   not bound a distributed guessing rate. Requests whose environ carries no
   `REMOTE_ADDR` share the single `_UNKNOWN_PEER` bucket (`src/recoverage/server.py`,
   `src/recoverage/server.py`), which is one shared window for every such client by
   design, so a WSGI harness in front of the app degrades the per-peer property
   back to the process-wide one. Every host behind one NAT also shares one
   window, so 10 failures anywhere on that network answer 429 to the operator
   for the rest of the 60 s.
5. No TLS and no token transport hardening; the token is a URL parameter by
   design, which puts it in browser history, shell history and any proxy log.
   The cookie is `Secure` only on a request that already arrived over TLS
   (`server.set_auth_cookie`, through `server.request_is_https`), so on the
   plaintext non-loopback bind the bundled listener speaks, it crosses
   unflagged.
6. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
7. `_MAX_DLL_SIZE` does not bound the read it guards: `src/recoverage/server.py`
   performs an unbounded `read_bytes()` and only checks the length afterwards
   (`src/recoverage/server.py`). A target binary that grows between the size check at
   `src/recoverage/server.py` and the read is fully loaded into memory.
8. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
9. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`src/recoverage/server.py`), and nothing distinguishes one
   holder of the shared token from another. The counters in
   `GET /api/health` (requests, caches, regen, streams, connections, auth;
   `src/recoverage/metrics.py`, `src/recoverage/api.py`) are a live gauge served
   to anyone who can read the endpoint, not a record: they reset on restart, so
   a brute-force run that finished an hour ago leaves nothing to investigate
   from.
10. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
    crafted target is a worker-level availability and memory-safety risk that
    only the size cap touches, and that cap is post-read.
11. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`src/recoverage/server.py`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.
12. `ui._STATIC_CACHE` (`src/recoverage/ui.py`) has no count cap and no eviction, unlike
    the three `src/recoverage/api.py` memos. It is bounded by the allowlisted filename regex
    and the accepted-encoding set rather than by a constant, so it is a
    structural bound today and an unguarded dict if the regex ever widens.
13. Two daemon threads start before the listener binds and are never joined
    (`src/recoverage/cli.py`). A failure in either is logged and the start continues,
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
  bounded only by the 5 s cooldown, the single-flight 429 and the advisory
  lock's refusal (`src/recoverage/regen.py`), which stops a second pipeline
  rather than slowing the first.
- Any webpage a developer visits can hold 32 `/api/events` connections to their
  own loopback dashboard (`src/recoverage/api.py`) without any credential, because the
  SPA's EventSource is same-origin and no-cors from a cross-site page. A
  quarter of the process-wide connection budget goes to it, the socket deadlines
  (`src/recoverage/devserver.py`) reclaim each slot eventually, and
  the rest of the budget stays open to the operator's own browser.
- The same page can hold the threads without any stream at all: a keep-alive
  connection that sends one cheap request and then goes quiet holds its thread
  for 15 s, and a page that opens a few hundred of them in that window meets
  the connection cap and gets 503s for the rest (`src/recoverage/devserver.py`).
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.
- A caller who sets `X-Request-ID` picks its own correlation id
  (`src/recoverage/server.py`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `src/recoverage/server.py`), rejected Host header
  (`src/recoverage/server.py`), unhandled errors with a request id and traceback
  (`src/recoverage/server.py`), coverage-document unavailability (`src/recoverage/server.py`), oversized
  or unconfigured target binary (`src/recoverage/server.py`), regen start, replay,
  completion and failure (`src/recoverage/api.py`,
  `src/recoverage/api.py`), slow requests at WARNING (`src/recoverage/server.py`), and
  health-state transitions (`src/recoverage/api.py`). Everything else is DEBUG and
  off by default.
- Two classes of event reach no route at all, so no per-request line names
  them. A request the HTTP transport refused (over-long or malformed request
  line, oversized headers, a client stalled past the socket deadline) is
  counted as `requests.transport_rejected`, and a rejected or throttled token as
  `auth.failures` / `auth.throttled` beside the live `auth.locked_peers` gauge
  (`src/recoverage/metrics.py`, filed at `src/recoverage/devserver.py` and
  `src/recoverage/server.py`). Both surface in the `GET /api/health` blocks
  (`src/recoverage/api.py`), which log a state TRANSITION rather than a state, so
  a monitor pointed at a server being scanned sees one line per change instead
  of one per poll.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`src/recoverage/server.py`), echoed on the response, so a
  report of "the export was slow" is matchable to a specific line.
- `SECURITY.md` records the supported version line and the fact that no
  reporting address is defined in the repository.
