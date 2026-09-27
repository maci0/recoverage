# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-27, against
`__version__ = "1.6.0"` (`src/recoverage/__init__.py:31`) with the `2.0.0`
changes in `CHANGELOG.md` still unreleased.

What ReCoverage is: a read-mostly web dashboard over one local SQLite database
(`coverage.db`) that rebrew's pipeline produces, served by Bottle on a threaded
`wsgiref` whose transport half lives in `devserver.py` (`devserver.py:21-161`,
wired at `cli.py:876-883`). The intended audience is a single developer on their
own machine, viewing a decompilation project they control. Everything below is
scoped to that deployment, plus the explicitly supported LAN case
(`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:727-736`, `server.py:2289-2298`, `api.py:1636`, `api.py:1805` | Acknowledgement only: a red message and `typer.Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:1078` (`/data`), `potato.py:1143` (`/potato`), `api.py:1636` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server.py:1589`; caps at `api.py:214`, `api.py:302`, `api.py:320`); the only hard connection cap is on `/api/events` (`api.py:493`). The static-asset memo `ui._STATIC_CACHE` (`ui.py:318`) has no count cap; it is bounded structurally by the route-matched filename and encoding variant instead |
| 3 | Global auth throttle: 10 failures per 60 s per process, not per source, so any one client can 429 the operator and every other client | `server.py:2256-2257`, `server.py:2262-2281` | The cap is intentional and the window is a documented module constant; the check, the cap and the slot reservation share one lock, so a burst of concurrent bad tokens cannot slip past it |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:185-191`, `potato.py:1149`, `server.py:2096-2131` | `Referrer-Policy: no-referrer` (`server.py:2494`), `HttpOnly; SameSite=Strict` cookie (`server.py:2122`), constant-time compare (`server.py:2079-2087`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which DB is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:37-62`, `server.py:825-853`, `ui.py:252-253` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `ThreadingMixIn` runs one daemon thread per connection with no connection cap, so a flood of ordinary requests, or a set of idle keep-alive connections, spawns unbounded threads | `devserver.py:21-29`, `devserver.py:41`, `devserver.py:50` | A 120 s per-socket deadline on every read and write in flight (`devserver.py:41`, `devserver.py:70`, `devserver.py:117`) and a 15 s idle deadline between requests (`devserver.py:50`, `devserver.py:121`); only `/api/events` is capped (`api.py:493`) |
| 7 | Any local process can trigger a full re-catalog and DB rebuild (disk and CPU), repeatedly within the cooldown | `api.py:1888-2009` | Loopback peer check, same-origin (`server.origin_is_this_dashboard`) and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`api.py:133-208`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, sqlite messages, echoed user input) to the client | `server.py:2020-2045`, `server.py:2352-2380`, `api.py:1908-1946` | Tracebacks never reach a response body (`server.py:2409-2418`); only the one-line exception class and a rebuild hint do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:987-1060`, `api.py:1636-1803` | `_MAX_DLL_SIZE` (512 MiB, `server.py:767`) checked on `stat()` (`server.py:1022-1031`) and again post-read (`server.py:1032-1041`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:2289-2346` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:2324-2328`, `server.py:2441-2445`); regen start, replay, completion and failure are logged (`api.py:1963`, `api.py:2022`, `api.py:2063`, `api.py:2080`) |
| 11 | Ten `RECOVERAGE_*` environment variables select the bind address, the token, the DB path, the log level and the CORS allowlist, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) reads as unset rather than rejected, and two of the ten (`RECOVERAGE_FUZZ_SEED`, `RECOVERAGE_FUZZ_ITERATIONS`) are accepted under the prefix but consumed only by the test suite | `config.py:45-62`, `config.py:103-112`, `config.py:153-303`, `cli.py:309` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:305-319`); a SET-but-empty value is an error everywhere except `RECOVERAGE_TOKEN`, where it means "auth off" on purpose |

Owner and review cadence: not stated in the repository.

## Entry points

Transport, before any route runs:

- `cli._server_class_for` (`cli.py:92-109`) picks the socket family from the
  bind address through `getaddrinfo`, and `cli._ThreadingWSGIServer6`
  (`cli.py:76-89`) is the `AF_INET6` class. On Linux a wildcard `AF_INET6`
  socket also accepts IPv4-mapped peers, which is the case
  `server._peer_is_loopback` (`server.py:103-127`) has to answer correctly for
  `POST /api/regen`.
- `devserver._ThreadingWSGIServer` (`devserver.py:21-29`): one daemon thread
  per connection, no cap on threads or connections.
- `devserver._KeepAliveRequestHandler` (`devserver.py:79-129`): HTTP/1.1
  keep-alive, so one connection carries many requests. The 65537-byte request
  line read (`devserver.py:105`, `devserver.py:122`) and the 414 on overflow
  (`devserver.py:111`) are the only framing limits.
- `devserver._KeepAliveServerHandler` (`devserver.py:132-161`): a response with
  no `Content-Length` and no `Transfer-Encoding` is sent with `Connection:
  close`, which is what keeps the unframed `/api/events` stream from
  misframing the next response on the socket.

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:183-185`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:191`,
  `server.set_auth_cookie`).
- `GET /potato` - `potato.py:1143-1144`, which owns both the route and the
  renderer (`render_potato`, `potato.py:1074`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:249-251`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:357-361`. Package-shipped
  JS/CSS/SVG.
- `GET /api/health` `api.py:777`, `GET /api/targets` `api.py:883`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `api.py:910`, `api.py:1078`, `api.py:1241`, `api.py:1584`, `api.py:1636`,
  `api.py:1805`.
- `POST /api/targets/<t>/functions` - `api.py:1514`, the only body-carrying
  endpoint.
- `GET /api/events` - `api.py:685`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:1888`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:2519`, CORS preflight catch-all.
- `@app.error(500)` - `server.py:2383`. The response surface for every
  unhandled exception, and the only place `_reclassify_request` is called
  (`server.py:2401`, `server.py:2409`).
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
  (`cli.py:629`, `cli.py:934`, `cli.py:1000`, `cli.py:1112`, `cli.py:1215`,
  `cli.py:1225`, `cli.py:1251`), plus the global `--no-color` / `--version`
  callback (`cli.py:133-158`). The operator's shell is the trust source.
  `recoverage config` prints every resolved setting including whether a token
  is set (`cli.py:827-844`), so it reaches the same secret-presence question as
  `serve`.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL`, `RECOVERAGE_FUZZ_SEED`,
  `RECOVERAGE_FUZZ_ITERATIONS` (`config.py:45-62`). Flags win over the
  environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`config.py:305-319`). `RECOVERAGE_TOKEN`
  is the only secret; `RECOVERAGE_LOG_LEVEL` is the only one that changes what
  an operator can see, since at DEBUG the per-request lines
  (`server.py:2217-2232`) reach the log. `NO_COLOR` and `TERM`
  (`cli.py:67-69`) are the only non-prefixed environment reads and are
  cosmetic.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:28-62`, `server.py:807-823`).
- The target binary named by `[targets.*].filename`, resolved by
  `_target_filename` / `_find_dll_path` (`server.py:864-882`,
  `server.py:941-957`).
- Filesystem: `db/coverage.db` (opened `mode=ro` with `PRAGMA query_only`,
  `server.py:1880-1912`), `<project>/src`, `<project>/original`, and the
  function source files Potato Mode reads directly through its own
  resolve-and-contain check (`potato.py:2447-2482`).
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:579-592`), argv list, own session, killed and reaped on a 10 s
  timeout (`cli.py:471`, `cli.py:488-525`).
- Startup threads, all daemon and none joined: the DB watcher
  (`api._ensure_db_watcher`, `cli.py:863-865`) and the SPA shell warm-up
  (`ui.warm_index_cache`, `cli.py:871-873`, which builds 8 compression
  variants before the listener accepts). Both are started before the bind, so
  either can fail after a port is chosen but before anything answers; each logs
  and stays lazy rather than aborting the start.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`regen.py:24-46` for `recoverage regen`, `serve --regen` and
`POST /api/regen`.

`recoverage serve` is not the only way in: `python -m recoverage` reaches the
same Typer app (`__main__.py:6`), and every command validates the
`RECOVERAGE_*` environment before consuming a setting, not just `serve`
(`cli.py:309-324`). The in-process capstone parse behind `/asm` lives in
`disasm.py`, reached from the route at `api.py:1636` and called at
`api.py:1785`; the JSON branch in the route itself is the only disassembly it
performs.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: the `before_request` hooks in registration
   order - `_start_request` (`server.py:2173`), `_require_auth` (installed at
   `server.py:2349`, body `server.py:2289-2346`), then the Host allowlist
   (`server.py:2421-2452`, installed from `cli.py:802-807`) - then per-handler
   bounds (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at `api.py:1130-1136`;
   `_MAX_PAGE_OFFSET` at `api.py:1141`; `_MAX_SLICE_SIZE` at `api.py:1146`;
   `_MAX_SEARCH_CHARS` at `api.py:1151`). Auth runs before the Host check, so
   a request with neither is answered 401 and a bad Host on an unauthenticated
   deployment is answered 400.
2. **App to database.** `coverage.db` is written by rebrew and read-only here
   (`server.py:1880-1912`). The app trusts row content as data, never as SQL:
   values are bound parameters throughout, and the only interpolated fragments
   are `where_sql` assembled from constants (`api.py:1301-1324`) and a
   whitelisted `ORDER BY` field and direction (`api.py:1279-1295`). LIKE
   searches are escaped at `server.py:1255-1266` and still bound, with a folded
   disjunct beside the ASCII one (`server.py:1295-1332`, used at
   `api.py:1310-1322`).
   The DB file is also a size and shape boundary: values over 1 MiB are kept as
   raw strings instead of being JSON-decoded (`server.py:1630-1651`), and a
   known-but-incomplete schema is answered 503 at open rather than a per-query
   500 (`server.py:1667-1694`, `server.py:1697-1780`, raised at
   `server.py:1941-1955`).
   The DB file is also liveness: a rewritten `coverage.db` is picked up live,
   and the SSE watcher (`api.py:536-579`) pushes `db-updated` so the SPA
   re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:253-285`).
   Potato Mode's source panel repeats the containment check independently
   (`potato.py:2469-2476`).
4. **App to local process (regen).** The only privilege transition: a POST makes
   the server import rebrew and rebuild the DB, with the process's own
   filesystem authority (`regen.py:24-46`).
5. **Config to runtime.** `rebrew-project.toml` and the `RECOVERAGE_*`
   environment select the DB path, the target binary path, the served trees, the
   log level and the bind address, with no signature or allowlist.
6. **CLI to host.** The browser opener and the bind address are operator
   decisions, not attacker input.

## Assets

- Project C sources under `<project>/src` and original binaries under
  `<project>/original` and `db/coverage.db` (reverse-engineering output, the
  thing worth stealing).
- The `--token` / `RECOVERAGE_TOKEN` bearer value, the only credential the
  system holds.
- Server process availability and the host's CPU, memory and disk, all consumed
  by `/data`, `/potato`, `/asm` and regen.
- The integrity of `coverage.db`: a wrong or stale map misdirects hours of
  decompilation work, which is the reputation-shaped asset here.

## Threats per boundary

**Client to app.** Spoofing: a page on any origin can drive a loopback browser
at the dashboard; mitigated by the Host allowlist on loopback binds
(`server.py:94`, `server.py:100`, `server.py:2421-2452`, installed at
`cli.py:802-807`) and by the `Sec-Fetch-Site` rejection on regen
(`api.py:1938-1946`). Tampering: only regen writes, and only from loopback.
Information disclosure: `/src` and `/original` proxy the whole project tree,
and the byte and asm endpoints serve arbitrary offsets of the original binary
(`api.py:1805`, `api.py:1636`) with no per-resource authorization. Denial of
service: no per-client quota anywhere; only `/api/events` and the auth window
are bounded. Repudiation: every action is attributable only to a shared token
and a socket peer, never to a client. Elevation of privilege: an
unauthenticated remote peer reaching a non-loopback bind gets every read the
operator gets, which is the whole asset set.

**Client to transport.** HTTP/1.1 keep-alive means a client that opens
connections without closing them holds a thread each until the 15 s idle
deadline, which is longer than a slow page load and much shorter than the 120 s
in-flight one (`devserver.py:41-50`, `devserver.py:104-122`). There is no
cap on concurrent connections, so the cap that exists is the idle timer. A
request line over 65536 bytes is answered 414 and the connection dropped
(`devserver.py:107-112`), which is the only framing resource bound.

**App to database.** Tampering is bounded by the read-only URI, `query_only`
(`server.py:1901`) and the shared `coverage_db_lock` held until close
(`server.py:1855-1877`, `server.py:1880-1912`). Denial of service remains: a
large `functions` table with a `search` term is served by a counting query and
a page query per request (`api.py:329-360`, `api.py:1334-1346`), bounded only
by a 64-entry memo (`api.py:319-320`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:264-285`, `potato.py:2469-2476`); what remains is that the trees are
served in full, so a `.env` or a key committed under `src/` is published to
every client.

**App to local process.** A local, unauthenticated process can trigger regen.
The `Origin` and `Sec-Fetch-Site` checks stop the browser-shaped version; they
do not stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely
when an `Origin` is sent that the same-origin test accepts
(`server.origin_is_this_dashboard`, `server.py:229-251`: the origin's host and
port against the request's own `Host`, so a page on another loopback port is
refused). Regen runs with no timeout by design (`regen.py:12-16`).

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the database or the listener. There is no
prompt and no warning when a config changes under a running server; the
memoized path just recomputes (`_paths.py:37-62`, `server.py:807-823`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `server.py:2079-2087`, `server.py:2289-2346` | Spoofing, unauthorized read |
| Global failure throttle with 429 + `Retry-After`, check and reservation under one lock | `server.py:2256-2281`, `server.py:2312-2317` | Online token guessing, check-then-act races under concurrency, and audit logging of each failure |
| Host header allowlist on loopback binds | `server.py:94`, `server.py:100`, `server.py:2421-2452` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:727-736` | Accidental LAN exposure |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:305-319`, `config.py:153-303`, `cli.py:309-324` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and same-origin `Origin` gate on regen | `api.py:1916-1946` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:133`, `api.py:139`, `api.py:1972-2009` | Concurrent torn rebuilds, regen flood |
| `Idempotency-Key` ledger: charset-validated, 600 s TTL, 128-slot eviction, replay answered before the cooldown | `api.py:155-208`, `api.py:1953-1964` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:2461-2472`, `server.py:2487-2494` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `server.py:2475-2516`, `cli.py:594-627` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `ui.py:259-285` | Path traversal |
| Independent containment check on Potato Mode's source panel | `potato.py:2469-2476` | Path traversal through a second reader |
| Allowlist regex for package assets | `ui.py:357-361` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:1130-1151`, `api.py:1259-1277`, `api.py:1385-1512` | Memory and CPU exhaustion per request |
| `sort` field and direction whitelisted, not interpolated raw | `api.py:1279-1295` | SQL injection via sort |
| LIKE metacharacter escaping plus a folded casefold clause | `server.py:1255-1266`, `server.py:1295-1332` | Wildcard abuse and non-ASCII misses in search |
| `SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `api.py:486-502`, `api.py:629-683` | Thread exhaustion via event streams, slow-client memory growth |
| Per-socket 120 s in-flight deadline and 15 s keep-alive idle deadline | `devserver.py:41`, `devserver.py:50`, `devserver.py:104-122` | Threads pinned by half-open or non-reading peers, and by idle keep-alive connections |
| 65536-byte request-line cap, answered 414 | `devserver.py:105-112` | Unbounded per-connection read |
| Read-only DB connection, `query_only`, 30 s busy timeout, shared lock held to close | `server.py:1852-1912` | Accidental writes, lock contention |
| 1 MiB metadata value cap before JSON decoding | `server.py:1630-1651` | Parse cost from an oversized value in a foreign DB |
| Schema gate: known versions 3-10, missing required objects answered 503 | `server.py:1657-1780`, `server.py:1941-1955` | Query-time 500s from a truncated or foreign `coverage.db` |
| Basename-only DB path in health and SSE payloads | `api.py:792`, `api.py:518` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `server.py:2002-2045`, `server.py:2383-2418`, `server.py:791-806` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store` on the 401 page | `server.py:395-451`, `server.py:2334-2342` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `server.py:2140-2155`, `server.py:2207-2208` | Untraceable incidents; forged log lines |
| Status reclassification inside the 500 handler | `server.py:2235-2247`, `server.py:2401`, `server.py:2409` | An error rate that silently reads zero. Note the scope: the two call sites are the 503 (DB unavailable) and the 500 itself, both inside `@app.error(500)`; there is no 4xx reclassification path |

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
   The auth cookie is set without `Secure` (`server.py:2122`), so it crosses a
   plaintext non-loopback bind intact.
6. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
7. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:1032`
   performs an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:1033-1041`). A target binary that grows between the `stat()` at
   `server.py:1022` and the read is fully loaded into memory.
8. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
9. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:2217-2232`), and nothing distinguishes one
   holder of the shared token from another. The in-process RED counters
   (`metrics.py`) are a live gauge, not a record, and are lost on restart.
10. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
    crafted target is a worker-level availability and memory-safety risk that
    only the size cap touches, and that cap is post-read.
11. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`server.py:2461-2472`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.
12. `ui._STATIC_CACHE` (`ui.py:318`) has no count cap and no eviction, unlike
    the three `api.py` memos. It is bounded by the allowlisted filename regex
    and the accepted-encoding set rather than by a constant, so it is a
    structural bound today and an unguarded dict if the regex ever widens.
13. Two daemon threads start before the listener binds and are never joined
    (`cli.py:863-873`). A failure in either is logged and the start continues,
    so a server can be serving with a dead DB watcher, which reads `healthy`
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
  own loopback dashboard (`api.py:493`), exhausting the process's threads
  without any credential, because the SPA's EventSource is same-origin and
  no-cors from a cross-site page. The socket deadlines
  (`devserver.py:41`, `devserver.py:50`) reclaim each slot eventually, not
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
  (`server.py:2148-2155`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:2324-2328`), rejected Host header
  (`server.py:2441-2445`), unhandled errors with a request id and traceback
  (`server.py:2409-2415`), DB unavailability (`server.py:2352-2380`), oversized
  or unconfigured target binary (`server.py:960-985`), regen start, replay,
  completion and failure (`api.py:1963`, `api.py:2022`, `api.py:2063`,
  `api.py:2080`), slow requests at WARNING (`server.py:2217-2224`), and
  health-state transitions (`api.py:751-775`). Everything else is DEBUG and
  off by default.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`server.py:2140-2155`), echoed on the response (`server.py:2207-2208`), so a
  report of "the export was slow" is matchable to a specific line.
- `SECURITY.md` records the supported version line and the fact that no
  reporting address is defined in the repository.
