# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-27, against
`__version__ = "1.6.0"` (`__init__.py:29`) with the `2.0.0` changes in
`CHANGELOG.md` still unreleased.

What ReCoverage is: a read-mostly web dashboard over one local SQLite database
(`coverage.db`) that rebrew's pipeline produces, served by Bottle on a threaded
`wsgiref` (`cli.py:73`, `cli.py:767`). The intended audience is a single
developer on their own machine, viewing a decompilation project they control.
Everything below is scoped to that deployment, plus the explicitly supported LAN
case (`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:618-627`, `server.py:1993-2030`, `api.py:1584`, `api.py:1421` | Acknowledgement only: a red message and `typer.Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:941` (`/data`), `potato.py:1077` (`/potato`), `api.py:1421` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server.py:1342`, caps at `api.py:197`, `api.py:278`, `api.py:296`); the only hard connection cap is on `/api/events` (`api.py:469`). The static-asset memo `ui._STATIC_CACHE` (`ui.py:316`) has no count cap; it is bounded structurally by the route-matched filename and encoding variant instead |
| 3 | Global auth throttle: 10 failures per 60 s per process, not per source, so any one client can 429 the operator and every other client | `server.py:1960-1986` | The cap is intentional and the window is a documented module constant (`server.py:1960-1963`); it bounds online guessing but has no per-source key |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:193-199`, `server.py:1993-2030` | `Referrer-Policy: no-referrer` (`server.py:2198`), `HttpOnly; SameSite=Strict` cookie, constant-time compare (`server.py:1827-1834`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which DB is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:37-62`, `server.py:680-707`, `ui.py:259-262` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `wsgiref` runs one daemon thread per connection with no connection cap, so a flood of ordinary requests spawns unbounded threads | `cli.py:73`, `cli.py:767` | A 120 s per-socket deadline on every read and write (`cli.py:93`, `cli.py:105`); only `/api/events` is capped (`api.py:469`, `api.py:663-696`) |
| 7 | Any local process can trigger a full re-catalog and DB rebuild (disk and CPU), repeatedly within the cooldown | `api.py:1667-1700` | Loopback peer check, loopback-`Origin` and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`api.py:116-181`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, sqlite messages, echoed user input) to the client | `server.py:2056-2084`, `server.py:2080`, `api.py:1690` | Tracebacks never reach a response body (`server.py:2086-2113`); only the one-line exception class and message do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:842-915`, `api.py:1421-1582` | `_MAX_DLL_SIZE` (512 MiB, `server.py:632`) checked on `stat()` and again post-read (`server.py:878`, `server.py:888-896`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:1993-2030` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:2028-2032`, `server.py:2140-2145`); regen start and completion are logged (`api.py:1796`, `api.py:1825`) |
| 11 | Ten `RECOVERAGE_*` environment variables select the bind address, the token, the DB path, the log level and the CORS allowlist, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) reads as unset rather than rejected, and two of the ten (`RECOVERAGE_FUZZ_SEED`, `RECOVERAGE_FUZZ_ITERATIONS`) are accepted under the prefix but consumed only by the test suite | `config.py:42-54`, `config.py:94-101`, `config.py:127-211`, `cli.py:247` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:225-240`) |

Owner and review cadence: not stated in the repository.

## Entry points

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:184-185`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:193-199`).
- `GET /potato` - `potato.py:1077-1078`, which owns both the route and the
  renderer (`render_potato`, `potato.py:1027`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:256-257`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:355-358`. Package-shipped
  JS/CSS/SVG.
- `GET /api/health` `api.py:698`, `GET /api/targets` `api.py:757`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `api.py:776`, `api.py:941`, `api.py:1073`, `api.py:1378`, `api.py:1421`,
  `api.py:1584`.
- `POST /api/targets/<t>/functions` - `api.py:1316`, the only body-carrying
  endpoint.
- `GET /api/events` - `api.py:649`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:1667`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:2223`, CORS preflight catch-all.
- `@app.error(500)` - `server.py:2087`. The response surface for every
  unhandled exception, and the only place `_reclassify_request` is called
  (`server.py:2105`, `server.py:2113`).
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `webapp.py:103`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `webapp.py:119-130`, the JSON/HTML
  split by `/api/` prefix.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `X-Request-ID`, `Accept-Encoding` are headers;
`token`, `target`, `va`, `section`, `status`, `search`, `sort`, `limit`,
`offset`, `size`, `format` are query values; `{"vas": [...]}` is the only
request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open`, `config`
  (`cli.py:522`, `cli.py:825`, `cli.py:897`, `cli.py:1020`, `cli.py:1134`,
  `cli.py:1144`, `cli.py:1170`), plus the global `--no-color` / `--version`
  callback (`cli.py:122-183`). The operator's shell is the trust source.
  `recoverage config` prints every resolved setting including whether a token
  is set, so it reaches the same secret-presence question as `serve`.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL`, `RECOVERAGE_FUZZ_SEED`,
  `RECOVERAGE_FUZZ_ITERATIONS` (`config.py:42-54`). Flags win over the
  environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`config.py:225-240`). `RECOVERAGE_TOKEN`
  is the only secret; `RECOVERAGE_LOG_LEVEL` is the only one that changes
  what an operator can see, since at DEBUG the per-request lines
  (`server.py:1930-1936`) reach the log. `NO_COLOR` and `TERM`
  (`cli.py:64`, `cli.py:66`) are the only non-prefixed environment reads and
  are cosmetic.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:25-62`, `server.py:662-693`).
- The target binary named by `[targets.*].filename`, resolved by
  `_target_filename` / `_find_dll_path` (`server.py:719-728`,
  `server.py:796-812`).
- Filesystem: `db/coverage.db` (opened `mode=ro` with `PRAGMA query_only`,
  `server.py:1630-1660`), `<project>/src`, `<project>/original`, and the
  function source files Potato Mode reads directly through its own
  resolve-and-contain check (`potato.py:2299-2334`).
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:455-516`, 10 s timeout at `cli.py:420`), argv list, own session, killed and reaped on a 10 s
  timeout.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`regen.py:40-42` for `recoverage regen`, `serve --regen` and `POST /api/regen`.

`recoverage serve` is not the only way in: `python -m recoverage` reaches the
same Typer app (`__main__.py:6`), and every command validates the
`RECOVERAGE_*` environment before consuming a setting, not just `serve`
(`cli.py:284-292`). The in-process capstone parse behind `/asm` lives in
`disasm.py`, reached from `api.py:1571`; the JSON branch in `api.py:1556-1565`
is the only disassembly the route itself performs.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: the `before_request` hooks, request
   instrumentation (`server.py:1878-1888`), auth (hook installed at `server.py:2053`, body
   `server.py:1993-2030`), then the Host allowlist
   (hook installed at `server.py:2125`, enforced at `server.py:2140-2145`, installed at `cli.py:697`), then
   per-handler bounds (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at
   `api.py:992-998`; `_MAX_PAGE_OFFSET` at `api.py:1003`; `_MAX_SLICE_SIZE` at
   `api.py:1008`; `_MAX_SEARCH_CHARS` at `api.py:1013`).
2. **App to database.** `coverage.db` is written by rebrew and read-only here
   (`server.py:1630-1660`). The app trusts row content as data, never as SQL:
   values are bound parameters throughout, and the only interpolated fragments
   are `where_sql` assembled from constants (`api.py:1143-1146`) and a
   whitelisted `ORDER BY` field and direction (`api.py:1099-1117`). LIKE
   searches are escaped at `server.py:1110-1121` and still bound
   (`server.py:1150-1180`).
   The DB file itself is a boundary: a rewritten `coverage.db` is picked up
   live, and the SSE watcher (`api.py:517-542`) pushes `db-updated` so the SPA
   re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:268-283`).
   Potato Mode's source panel repeats the containment check independently
   (`potato.py:2320-2327`).
4. **App to local process (regen).** The only privilege transition: a POST makes
   the server import rebrew and rebuild the DB, with the process's own
   filesystem authority (`regen.py:24-40`).
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
(`server.py:104`, `server.py:156`, `server.py:2140-2145`, installed at
`cli.py:697`) and by the `Sec-Fetch-Site` rejection on regen
(`api.py:1711-1721`). Tampering: only regen writes, and only from loopback.
Information disclosure: `/src` and `/original` proxy the whole project tree,
and the byte and asm endpoints serve arbitrary offsets of the original binary
(`api.py:1584`, `api.py:1421`) with no per-resource authorization. Denial of
service: no per-client quota anywhere; only `/api/events` and the auth window
are bounded. Repudiation: every action is attributable only to a shared token
and a socket peer, never to a client. Elevation of privilege: an
unauthenticated remote peer reaching a non-loopback bind gets every read the
operator gets, which is the whole asset set.

**App to database.** Tampering is bounded by the read-only URI, `query_only`
(`server.py:1651`) and the shared `coverage_db_lock` held until close
(`server.py:1605-1660`). Denial of service remains: a large `functions` table
with a `search` term is served by a counting query and a page query per request
(`api.py:1144-1168`), bounded only by a 64-entry memo (`api.py:296`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:268-283`, `potato.py:2320-2327`); what remains is that the trees are
served in full, so a `.env` or a key committed under `src/` is published to
every client.

**App to local process.** A local, unauthenticated process can trigger regen.
Origin and `Sec-Fetch-Site` checks stop the browser-shaped version; they do not
stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely when an
`Origin` is sent that passes the loopback test (`api.py:1692-1721`). Regen runs
with no timeout by design (`regen.py:12-16`).

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the database or the listener. There is no
prompt and no warning when a config changes under a running server; the
memoized path just recomputes (`_paths.py:56-62`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `server.py:1827-1834`, `server.py:1993-2030` | Spoofing, unauthorized read |
| Global failure throttle with 429 + `Retry-After` | `server.py:1960-1986`, `server.py:2012-2021` | Online token guessing, and audit logging of each failure |
| Host header allowlist on loopback binds | `server.py:104`, `server.py:156`, `server.py:2140-2145` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:618-627` | Accidental LAN exposure |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:225-240`, `config.py:127-211`, `cli.py:239`, `cli.py:253` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and loopback-`Origin` gate on regen | `api.py:1692-1721` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:122`, `api.py:1748-1783` | Concurrent torn rebuilds, regen flood |
| `Idempotency-Key` ledger: charset-validated, 600 s TTL, 128-slot eviction, replay answered before the cooldown | `api.py:138-181`, `api.py:1736-1741` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:2165`, `server.py:2193-2198` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `server.py:2180-2217`, `cli.py:671-684` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `ui.py:268-283` | Path traversal |
| Independent containment check on Potato Mode's source panel | `potato.py:2320-2327` | Path traversal through a second reader |
| Allowlist regex for package assets | `ui.py:355-358` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:992-1013`, `api.py:1201-1244` | Memory and CPU exhaustion per request |
| `sort` field and direction whitelisted, not interpolated raw | `api.py:1099-1117` | SQL injection via sort |
| LIKE metacharacter escaping plus a folded casefold clause | `server.py:1110-1121`, `server.py:1147-1180` | Wildcard abuse and non-ASCII misses in search |
| `SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `api.py:468-472`, `api.py:596-696` | Thread exhaustion via event streams, slow-client memory growth |
| Per-socket 120 s deadline on every read and write | `cli.py:93`, `cli.py:105` | Threads pinned by half-open or non-reading peers |
| Read-only DB connection, `query_only`, 30 s busy timeout, shared lock held to close | `server.py:1605-1660` | Accidental writes, lock contention |
| Basename-only DB path in health and SSE payloads | `api.py:708`, `api.py:496-500` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `server.py:1770-1778`, `server.py:2086-2113`, `server.py:654-656` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store`/`no-cache` on the 401 page | `server.py:338-358`, `server.py:2038-2046` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `server.py:1844-1888`, `server.py:1911` | Untraceable incidents; forged log lines |
| Status reclassification inside the 500 handler | `server.py:1939-1945`, `server.py:2105`, `server.py:2113` | An error rate that silently reads zero. Note the scope: the two call sites are the 503 (DB unavailable) and the 500 itself, both inside `@app.error(500)`; there is no 4xx reclassification path |

## Unmitigated, ranked

1. No enforced pairing of `--allow-remote` with `--token` (risk 1 above). A
   warning is printed and the process starts anyway; nothing stops
   `--bind 0.0.0.0 --allow-remote` from publishing sources and binaries.
2. No per-client rate limiting or quota on the read endpoints; `wsgiref` will
   serve a flood of `/data` or `/potato` renders, one thread each.
3. Global auth throttle with no per-source key, so one client can lock out the
   operator for the rest of the 60 s window.
4. No TLS and no token transport hardening; the token is a URL parameter by
   design, which puts it in browser history, shell history and any proxy log.
   The auth cookie is set without `Secure` (`ui.py:196-199`), so it crosses a
   plaintext non-loopback bind intact.
5. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
6. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:887` performs
   an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:888-896`). A target binary that grows between the `stat()` at
   `server.py:878` and the read is fully loaded into memory.
7. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
8. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:1930-1936`), and nothing distinguishes one
   holder of the shared token from another. The in-process RED counters
   (`metrics.py`) are a live gauge, not a record, and are lost on restart.
9. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
   crafted target is a worker-level availability and memory-safety risk that
   only the size cap touches, and that cap is post-read.
10. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`server.py:2165`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.
11. `ui._STATIC_CACHE` (`ui.py:316`) has no count cap and no eviction, unlike
    the three `api.py` memos. It is bounded by the allowlisted filename regex
    and the accepted-encoding set rather than by a constant, so it is a
    structural bound today and an unguarded dict if the regex ever widens.

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
  own loopback dashboard (`api.py:469`), exhausting the process's threads
  without any credential, because the SPA's EventSource is same-origin and
  no-cors from a cross-site page. The 120 s socket deadline
  (`cli.py:93`, `cli.py:105`) reclaims each slot eventually, not promptly.
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.
- A caller who sets `X-Request-ID` picks its own correlation id
  (`server.py:1845-1858`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:2028-2032`), rejected Host header
  (`server.py:2140-2145`), unhandled errors with a request id and traceback
  (`server.py:2086-2113`), DB unavailability (`server.py:2056-2084`), regen
  start, replay, rejection and completion (`api.py:1739`, `api.py:1748-1783`,
  `api.py:1796`, `api.py:1825`), slow requests at WARNING
  (`server.py:1921-1928`). Everything else is DEBUG and off by default.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`server.py:1844-1888`), echoed on the response (`server.py:1911`), so a
  report of "the export was slow" is matchable to a specific line.
- `SECURITY.md` records the supported version line and the fact that no
  reporting address is defined in the repository.
