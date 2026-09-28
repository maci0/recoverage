# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-29, against
`__version__ = "4.0.0"` (`src/recoverage/__init__.py:31`).

What ReCoverage is: a read-mostly web dashboard over the clear-text coverage
documents (`db/coverage-<target>.toml`) that rebrew's pipeline prints, served by
Bottle on a threaded `wsgiref` whose transport half lives in `devserver.py`
(`devserver.py:31-228`, wired at `cli.py:900-907`). The intended audience is a
single developer on their own machine, viewing a decompilation project they
control. Everything below is scoped to that deployment, plus the explicitly
supported LAN case (`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:751-760`, `server.py:1955-1964`, `api.py:1593`, `api.py:1762` | Acknowledgement only: a red message and `typer.Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:1124` (`/data`), `potato.py:1153` (`/potato`), `api.py:1593` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server.py:1583`; caps at `api.py:207`, `api.py:307`, `api.py:325`); the only hard connection cap is on `/api/events` (`api.py:553`). The static-asset memo `ui._STATIC_CACHE` (`ui.py:337`) has no count cap; it is bounded structurally by the route-matched filename and encoding variant instead |
| 3 | Global auth throttle: 10 failures per 60 s per process, not per source, so any one client can 429 the operator and every other client | `server.py:1922-1923`, `server.py:1928-1947` | The cap is intentional and the window is a documented module constant; the check, the cap and the slot reservation share one lock, so a burst of concurrent bad tokens cannot slip past it |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:206-214`, `potato.py:1159`, `server.py:1762-1797` | `Referrer-Policy: no-referrer` (`server.py:2184`), `HttpOnly; SameSite=Strict` cookie (`server.py:1788`), constant-time compare (`server.py:1745-1753`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which coverage directory is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:34-73`, `server.py:851-882`, `ui.py:271-273` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `ThreadingMixIn` runs one daemon thread per connection with no connection cap, so a flood of ordinary requests, or a set of idle keep-alive connections, spawns unbounded threads | `devserver.py:31-39`, `devserver.py:66`, `devserver.py:75` | A 120 s per-socket deadline on every read and write in flight (`devserver.py:66`, `devserver.py:95`, `devserver.py:163`) and a 15 s idle deadline between requests (`devserver.py:75`, `devserver.py:167`); only `/api/events` is capped (`api.py:553`) |
| 7 | Any local process can trigger a full re-catalog and coverage rebuild (disk and CPU), repeatedly within the cooldown | `api.py:1845-1966` | Loopback peer check, same-origin (`server.origin_is_this_dashboard`) and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`api.py:121-187`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, TOML parser messages, echoed user input) to the client | `server.py:1686-1711`, `server.py:2043-2092`, `api.py:1865-1903` | Tracebacks never reach a response body (`server.py:2099-2108`); only the one-line exception class and a rebuild hint do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:1021-1094`, `api.py:1593-1759` | `_MAX_DLL_SIZE` (512 MiB, `server.py:811`) checked on `stat()` (`server.py:1056-1065`) and again post-read (`server.py:1066-1075`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:1955-2012` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:1990-1994`, `server.py:2131-2135`); regen start, replay, completion and failure are logged (`api.py:1920`, `api.py:1979`, `api.py:2020`, `api.py:2037`) |
| 11 | Ten `RECOVERAGE_*` environment variables select the bind address, the token, the coverage directory, the log level and the CORS allowlist, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) reads as unset rather than rejected, and two of the ten (`RECOVERAGE_FUZZ_SEED`, `RECOVERAGE_FUZZ_ITERATIONS`) are accepted under the prefix but consumed only by the test suite | `config.py:45-62`, `config.py:103-112`, `config.py:153-303`, `cli.py:335` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:306-320`); a SET-but-empty value is an error everywhere except `RECOVERAGE_TOKEN`, where it means "auth off" on purpose |

Owner and review cadence: not stated in the repository.

## Entry points

Transport, before any route runs:

- `cli._server_class_for` (`cli.py:94-111`) picks the socket family from the
  bind address through `getaddrinfo`, and `cli._ThreadingWSGIServer6`
  (`cli.py:78-91`) is the `AF_INET6` class. On Linux a wildcard `AF_INET6`
  socket also accepts IPv4-mapped peers, which is the case
  `server._peer_is_loopback` (`server.py:100-123`) has to answer correctly for
  `POST /api/regen`.
- `devserver._ThreadingWSGIServer` (`devserver.py:31-39`): one daemon thread
  per connection, no cap on threads or connections.
- `devserver._KeepAliveRequestHandler` (`devserver.py:104-186`): HTTP/1.1
  keep-alive, so one connection carries many requests. The 65537-byte request
  line read (`devserver.py:151`, `devserver.py:168`) and the 414 on overflow
  (`devserver.py:157`) are the only framing limits.
- `devserver._KeepAliveServerHandler` (`devserver.py:189-228`): a response with
  no `Content-Length` and no `Transfer-Encoding` is sent with `Connection:
  close`, which is what keeps the unframed `/api/events` stream from
  misframing the next response on the socket.

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:206-208`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:214`,
  `server.set_auth_cookie`).
- `GET /potato` - `potato.py:1153-1154`, which owns both the route and the
  renderer (`render_potato`, `potato.py:1070`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:271-273`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:376-379`. Package-shipped
  JS/CSS/SVG.
- `GET /api/health` `api.py:837`, `GET /api/targets` `api.py:943`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `api.py:968`, `api.py:1124`, `api.py:1295`, `api.py:1551`, `api.py:1593`,
  `api.py:1762`.
- `POST /api/targets/<t>/functions` - `api.py:1513`, the only body-carrying
  endpoint.
- `GET /api/events` - `api.py:745`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:1845`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:2209`, CORS preflight catch-all.
- `@app.error(500)` - `server.py:2073`. The response surface for every
  unhandled exception, and the only place `_reclassify_request` is called
  (`server.py:2091`, `server.py:2099`).
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `webapp.py:112`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `webapp.py:128-139`, the JSON/HTML
  split by `/api/` prefix.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `X-Request-ID`, `Accept-Encoding`,
`If-None-Match` are headers; `token`, `target`, `va`, `section`, `status`,
`search`, `sort`, `limit`, `offset`, `size`, `offset`, `format` are query
values; `{"vas": [...]}` is the only request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open`, `config`
  (`cli.py:653`, `cli.py:958`, `cli.py:1026`, `cli.py:1142`, `cli.py:1248`,
  `cli.py:1258`, `cli.py:1284`), plus the global `--no-color` / `--version`
  callback (`cli.py:135-160`). The operator's shell is the trust source.
  `recoverage config` prints every resolved setting including whether a token
  is set (`cli.py:1284-1311`), so it reaches the same secret-presence question as
  `serve`.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL`, `RECOVERAGE_FUZZ_SEED`,
  `RECOVERAGE_FUZZ_ITERATIONS` (`config.py:45-62`). Flags win over the
  environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`config.py:306-320`). `RECOVERAGE_TOKEN`
  is the only secret; `RECOVERAGE_LOG_LEVEL` is the only one that changes what
  an operator can see, since at DEBUG the per-request lines
  (`server.py:1883-1898`) reach the log. `NO_COLOR` and `TERM`
  (`cli.py:69-71`) are the only non-prefixed environment reads and are
  cosmetic.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:34-73`, `server.py:851-882`).
- The target binary named by `[targets.*].filename`, resolved by
  `_target_filename` / `_find_dll_path` (`server.py:915-925`,
  `server.py:975-991`).
- Filesystem: `db/coverage-<target>.toml` (read as UTF-8 text through
  `rebrew.coverage_toml`, `rebrew/coverage_toml.py:1218-1230`, reached at
  `server.py:461-513`; nothing is held open between requests), `<project>/src`,
  `<project>/original`, and the function source files Potato Mode reads directly
  through its own resolve-and-contain check (`potato.py:2475-2517`).
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:603-616`), argv list, own session, killed and reaped on a 10 s
  timeout (`cli.py:495`, `cli.py:512-549`).
- Startup threads, all daemon and none joined: the coverage watcher
  (`api._ensure_db_watcher`, `cli.py:887-889`) and the SPA shell warm-up
  (`ui.warm_index_cache`, `cli.py:895-897`, which builds 8 compression
  variants before the listener accepts). Both are started before the bind, so
  either can fail after a port is chosen but before anything answers; each logs
  and stays lazy rather than aborting the start.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`regen.py:25-56` for `recoverage regen`, `serve --regen` and
`POST /api/regen`.

`recoverage serve` is not the only way in: `python -m recoverage` reaches the
same Typer app (`__main__.py:5-8`), and every command validates the
`RECOVERAGE_*` environment before consuming a setting, not just `serve`
(`cli.py:335-350`). The in-process capstone parse behind `/asm` lives in
`disasm.py`, reached from the route at `api.py:1593` and called at
`api.py:1742`; the JSON branch in the route itself is the only disassembly it
performs.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: the `before_request` hooks in registration
   order - `_start_request` (`server.py:1840`), `_require_auth` (installed at
   `server.py:2015`, body `server.py:1955-2012`), then the Host allowlist
   (`server.py:2111-2142`, installed from `cli.py:826-831`) - then per-handler
   bounds (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at `api.py:1174-1180`;
   `_MAX_PAGE_OFFSET` at `api.py:1185`; `_MAX_SLICE_SIZE` at `api.py:1190`;
   `_MAX_SEARCH_CHARS` at `api.py:1195`). Auth runs before the Host check, so
   a request with neither is answered 401 and a bad Host on an unauthenticated
   deployment is answered 400.
2. **App to coverage documents.** `db/coverage-<target>.toml` is printed by
   `rebrew build-db` and read here, never written (`server.coverage_snapshots`,
   `server.py:461-513`; the reader is `rebrew.coverage_toml`,
   `rebrew/coverage_toml.py:1218-1230`). The documents are attacker-supplied in
   the same sense the database file was: whoever can write into the coverage
   directory decides what every dashboard shows, and the values are trusted as
   data, never as code. Parsing is `tomllib`, so a malformed document raises
   instead of executing; the reader validates the format version, the shape of
   every array and table, and that the document's `target` matches its filename,
   and every failure is one `CoverageTomlError`.
   Unreadable is not empty, and the two answers stay distinguishable. A document
   that exists and does not parse raises `CoverageTomlError`, which is the 503
   `db_unavailable` contract (`server._db_unavailable_err`, `server.py:2043-2092`);
   a target `rebrew-project.toml` declares that no build has written is served
   from an empty snapshot (`server.coverage_for`, `server.py:490-513`), which is
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
   (`api.py:565-579`) pushes `db-updated` so the SPA re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:273-305`).
   Potato Mode's source panel repeats the containment check independently
   (`potato.py:2497-2504`).
4. **App to local process (regen).** The only privilege transition: a POST makes
   the server import rebrew and rebuild the coverage documents, with the
   process's own filesystem authority (`regen.py:25-56`).
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
(`server.py:91`, `server.py:97`, `server.py:2111-2142`, installed at
`cli.py:826-831`) and by the `Sec-Fetch-Site` rejection on regen
(`api.py:1895-1903`). Tampering: only regen writes, and only from loopback.
Information disclosure: `/src` and `/original` proxy the whole project tree,
and the byte and asm endpoints serve arbitrary offsets of the original binary
(`api.py:1762`, `api.py:1593`) with no per-resource authorization. Denial of
service: no per-client quota anywhere; only `/api/events` and the auth window
are bounded. Repudiation: every action is attributable only to a shared token
and a socket peer, never to a client. Elevation of privilege: an
unauthenticated remote peer reaching a non-loopback bind gets every read the
operator gets, which is the whole asset set.

**Client to transport.** HTTP/1.1 keep-alive means a client that opens
connections without closing them holds a thread each until the 15 s idle
deadline, which is longer than a slow page load and much shorter than the 120 s
in-flight one (`devserver.py:66-75`, `devserver.py:134-168`). There is no
cap on concurrent connections, so the cap that exists is the idle timer. A
request line over 65536 bytes is answered 414 and the connection dropped
(`devserver.py:153-158`), which is the only framing resource bound.

**App to coverage documents.** Tampering is bounded by the direction of the
dependency: this server only reads, and the only writer is `rebrew build-db`,
which replaces each document whole through a temporary sibling and an atomic
rename (`rebrew/coverage_toml.py:574-587`), so a reader sees the previous
document or the new one and never a torn write. A document the reader cannot use
is answered 503 rather than half-served. Denial of service remains: a large
function list with a `search` term is walked per request (`api.py:334-361`,
`api.py:1354-1356`), bounded only by a 64-entry memo (`api.py:323-325`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:285-305`, `potato.py:2497-2504`); what remains is that the trees are
served in full, so a `.env` or a key committed under `src/` is published to
every client.

**App to local process.** A local, unauthenticated process can trigger regen.
The `Origin` and `Sec-Fetch-Site` checks stop the browser-shaped version; they
do not stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely
when an `Origin` is sent that the same-origin test accepts
(`server.origin_is_this_dashboard`, `server.py:226-247`: the origin's host and
port against the request's own `Host`, so a page on another loopback port is
refused). Regen runs with no timeout by design (`regen.py:13-17`).

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the coverage directory or the listener.
There is no prompt and no warning when a config changes under a running server;
the memoized path just recomputes (`_paths.py:34-73`, `server.py:851-882`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `server.py:1745-1753`, `server.py:1955-2012` | Spoofing, unauthorized read |
| Global failure throttle with 429 + `Retry-After`, check and reservation under one lock | `server.py:1922-1947`, `server.py:1978-1983` | Online token guessing, check-then-act races under concurrency, and audit logging of each failure |
| Host header allowlist on loopback binds | `server.py:91`, `server.py:97`, `server.py:2111-2142` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:751-760` | Accidental LAN exposure |
| Every request-supplied integer goes through `server.parse_ascii_int` — ASCII digits in the stated base and nothing else — with `api._parse_byte_count` and `api._page_int` on top | `server.py:335`, `api.py:1218`, `api.py:1237` | Digit-set smuggling: `int(x, base)` also accepts the whole Unicode Nd/Nl/No sets and the `_` separator, so `?size=٤٠٩٦` served a 4096-byte slice and `?page=1_0` opened page 10 |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:306-320`, `config.py:153-303`, `cli.py:335-350` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and same-origin `Origin` gate on regen | `api.py:1873-1903` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:121`, `api.py:127`, `api.py:1929-1966` | Concurrent torn rebuilds, regen flood |
| `Idempotency-Key` ledger: charset-validated, 600 s TTL, 128-slot eviction, replay answered before the cooldown | `api.py:143-187`, `api.py:1910-1921` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:2151-2162`, `server.py:2177-2184` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `server.py:2165-2206`, `cli.py:618-649` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `ui.py:285-305` | Path traversal |
| Independent containment check on Potato Mode's source panel | `potato.py:2497-2504` | Path traversal through a second reader |
| Allowlist regex for package assets | `ui.py:376-379` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:1174-1195`, `api.py:1314-1333`, `api.py:1385-1512` | Memory and CPU exhaustion per request |
| `sort` field and direction whitelisted against `_ALLOWED_SORT` and applied as an in-memory sort key | `api.py:367`, `api.py:1335-1356` | Arbitrary field access through the sort parameter. The SQLite-era `ORDER BY` interpolation this row used to name is gone with the query builder: the rows are Python objects, so there is no statement for a sort value to reach |
| Search is a folded substring test in Python (`server.fold_match`) | `server.py:1330-1362`, `api.py:389-397` | Wildcard abuse and non-ASCII misses in search. There is no SQL `LIKE` pattern any more, so the escape helper and the `rc_fold` disjunct beside the ASCII `LIKE` are gone with the SQL |
| `SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `api.py:540-553`, `api.py:689-742` | Thread exhaustion via event streams, slow-client memory growth |
| Per-socket 120 s in-flight deadline and 15 s keep-alive idle deadline | `devserver.py:66`, `devserver.py:75`, `devserver.py:134-168` | Threads pinned by half-open or non-reading peers, and by idle keep-alive connections |
| 65536-byte request-line cap, answered 414 | `devserver.py:151-158` | Unbounded per-connection read |
| Documents are read as UTF-8 text and never written by this server; the only writer is `rebrew build-db`, which replaces each document whole through an atomic rename | `server.py:461-513`, `rebrew/coverage_toml.py:574-587` | Accidental writes, and a torn read of a document being rebuilt |
| Document gate: the format `version` must be the one this build reads, every array and table must have its documented shape, and the document's `target` must match its filename; a failure is answered 503 | `server.py:2043-2092`, `rebrew/coverage_toml.py:1181-1188` | A truncated, foreign or hand-edited document reading as an empty target, and query-time 500s from a document the reader cannot use |
| Basename-only coverage-directory name in health and SSE payloads | `api.py:852`, `api.py:578` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `server.py:1663-1711`, `server.py:2073-2108`, `server.py:835-845` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store` on the 401 page | `server.py:547-587`, `server.py:2000-2008` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `server.py:1806-1821`, `server.py:1873-1874` | Untraceable incidents; forged log lines |
| Status reclassification inside the 500 handler | `server.py:1901-1913`, `server.py:2099`, `server.py:2091` | An error rate that silently reads zero. Note the scope: the two call sites are the 503 (coverage documents unavailable) and the 500 itself, both inside `@app.error(500)`; there is no 4xx reclassification path |

## Unmitigated, ranked

1. No enforced pairing of `--allow-remote` with `--token` (risk 1 above). A
   warning is printed and the process starts anyway; nothing stops
   `--bind 0.0.0.0 --allow-remote` from publishing sources and binaries.
2. No per-client rate limiting or quota on the read endpoints; `ThreadingMixIn`
   will serve a flood of `/data` or `/potato` renders, one thread each.
3. No cap on concurrent connections. The 15 s idle and 120 s in-flight
   deadlines bound how long a thread is held, not how many exist: a few
   thousand open connections is a few thousand threads before anything is
   refused.
4. Global auth throttle with no per-source key, so one client can lock out the
   operator for the rest of the 60 s window.
5. No TLS and no token transport hardening; the token is a URL parameter by
   design, which puts it in browser history, shell history and any proxy log.
   The auth cookie is set without `Secure` (`server.py:1788`), so it crosses a
   plaintext non-loopback bind intact.
6. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
7. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:1066`
   performs an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:1067-1075`). A target binary that grows between the `stat()` at
   `server.py:1056` and the read is fully loaded into memory.
8. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
9. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:1883-1898`), and nothing distinguishes one
   holder of the shared token from another. The in-process RED counters
   (`metrics.py`) are a live gauge, not a record, and are lost on restart.
10. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
    crafted target is a worker-level availability and memory-safety risk that
    only the size cap touches, and that cap is post-read.
11. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`server.py:2151-2162`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.
12. `ui._STATIC_CACHE` (`ui.py:337`) has no count cap and no eviction, unlike
    the three `api.py` memos. It is bounded by the allowlisted filename regex
    and the accepted-encoding set rather than by a constant, so it is a
    structural bound today and an unguarded dict if the regex ever widens.
13. Two daemon threads start before the listener binds and are never joined
    (`cli.py:887-897`). A failure in either is logged and the start continues,
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
  own loopback dashboard (`api.py:553`), exhausting the process's threads
  without any credential, because the SPA's EventSource is same-origin and
  no-cors from a cross-site page. The socket deadlines
  (`devserver.py:66`, `devserver.py:75`) reclaim each slot eventually, not
  promptly.
- The same page can hold the threads without any stream at all: a keep-alive
  connection that sends one cheap request and then goes quiet holds its thread
  for 15 s, and a page that opens a few hundred of them in that window
  multiplies out against a server with no connection cap.
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.
- A caller who sets `X-Request-ID` picks its own correlation id
  (`server.py:1814-1821`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:1990-1994`), rejected Host header
  (`server.py:2131-2135`), unhandled errors with a request id and traceback
  (`server.py:2099-2105`), coverage-document unavailability (`server.py:2043-2092`), oversized
  or unconfigured target binary (`server.py:994-1018`), regen start, replay,
  completion and failure (`api.py:1920`, `api.py:1979`, `api.py:2020`,
  `api.py:2037`), slow requests at WARNING (`server.py:1883-1890`), and
  health-state transitions (`api.py:811-834`). Everything else is DEBUG and
  off by default.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`server.py:1806-1821`), echoed on the response (`server.py:1873-1874`), so a
  report of "the export was slow" is matchable to a specific line.
- `SECURITY.md` records the supported version line and the fact that no
  reporting address is defined in the repository.
