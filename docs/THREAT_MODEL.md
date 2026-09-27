# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-27.

What ReCoverage is: a read-mostly web dashboard over one local SQLite database
(`coverage.db`) that rebrew's pipeline produces, served by Bottle on a threaded
`wsgiref` (`cli.py:73-79`, `cli.py:665-672`). The intended audience is a single
developer on their own machine, viewing a decompilation project they control.
Everything below is scoped to that deployment, plus the explicitly supported LAN
case (`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:505-529`, `server.py:1741-1990`, `api.py:1578`, `api.py:1415` | Acknowledgement only: a red message and `Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:938` (`/data`), `potato.py:1069` (`/potato`), `api.py:1415` (`/asm`) | Bounded per-process memos with oldest-entry eviction (`server.py:1273`, caps at `api.py:197`, `api.py:278`, `api.py:296`, `ui.py:316`); the only hard connection cap is on `/api/events` (`api.py:469`) |
| 3 | Global auth throttle: 10 failures per 60 s per process, not per source, so any one client can 429 the operator and every other client | `server.py:1896-1927` | The cap is intentional and documented as global (`server.py:1888-1895`); it bounds online guessing but has no per-source key |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:193-199`, `server.py:1929-1990` | `Referrer-Policy: no-referrer` (`server.py:2134`), `HttpOnly; SameSite=Strict` cookie, constant-time compare (`server.py:1763-1771`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which DB is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:37-62`, `server.py:652-684`, `ui.py:261-262` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `wsgiref` runs one daemon thread per connection with no connection cap, so a flood of ordinary requests spawns unbounded threads | `cli.py:73-79`, `cli.py:665-672` | A 120 s per-socket deadline on every read and write (`cli.py:91`, `cli.py:100-101`); only `/api/events` is capped (`api.py:469`, `api.py:661-690`) |
| 7 | Any local process can trigger a full re-catalog and DB rebuild (disk and CPU), repeatedly within the cooldown | `api.py:1661-1700` | Loopback peer check, loopback-`Origin` and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS`, and an `Idempotency-Key` ledger (`api.py:124-177`) |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, sqlite messages, echoed user input) to the client | `server.py:1992-2022`, `server.py:2024-2061`, `api.py:1684` | Tracebacks never reach a response body (`server.py:2046-2061`); only the one-line exception class and message do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:792-836`, `server.py:627`, `api.py:1415-1419` | `_MAX_DLL_SIZE` (512 MiB) checked on `stat()` and again post-read (`server.py:817`, `server.py:825-833`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:1929-1990` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:1964-1968`, `server.py:2081-2085`); regen start and completion are logged (`api.py:1790`, `api.py:1819`) |
| 11 | Eight `RECOVERAGE_*` environment variables select the bind address, the token, the DB path, the log level and the CORS allowlist, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) turns auth off, and an empty value is treated as unset rather than rejected | `config.py:37-48`, `config.py:88-96`, `config.py:127-211`, `cli.py:589-593` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:216-231`) |

Owner and review cadence: not stated in the repository. No disclosure contact or
supported-versions table exists either (there is no `SECURITY.md`).

## Entry points

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:183-185`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:193-199`).
- `GET /potato` - `potato.py:1069-1070`, which owns both the route and the
  renderer (`render_potato`, `potato.py:1019`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:259-261`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:347-351`. Package-shipped JS/CSS/SVG.
- `GET /api/health` `api.py:698`, `GET /api/targets` `api.py:757`.
- `GET /api/targets/<t>/stats|data|functions|functions/<va>|asm|sections/<s>/bytes`
  - `api.py:776`, `api.py:938`, `api.py:1070`, `api.py:1372`, `api.py:1415`,
  `api.py:1578`.
- `POST /api/targets/<t>/functions` - `api.py:1310-1311`, the only
  body-carrying endpoint.
- `GET /api/events` - `api.py:649-650`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:1661-1662`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:2160-2162`, CORS preflight catch-all.
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `webapp.py:92-93`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `webapp.py:114-122`, the JSON/HTML
  split by `/api/` prefix.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `X-Request-ID`, `Accept-Encoding` are headers;
`token`, `target`, `va`, `section`, `status`, `search`, `sort`, `limit`,
`offset`, `size`, `format` are query values; `{"vas": [...]}` is the only
request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open` (`cli.py:469`,
  `cli.py:770`, `cli.py:830`, `cli.py:968`, `cli.py:1078`, `cli.py:1087`).
  The operator's shell is the trust source.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB`, `RECOVERAGE_LOG_LEVEL` (`config.py:37-48`). Flags win over
  the environment, values are validated before the listener binds, an unknown
  prefixed name is a startup error (`config.py:216-231`).
  `RECOVERAGE_TOKEN` is the only secret, so it is the only reason the
  environment is on this list; `RECOVERAGE_LOG_LEVEL` is the only one that
  changes what an operator can see, since at DEBUG the per-request lines
  (`server.py:1861-1873`) reach the log.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:25-62`, `server.py:649-651`).
- The target binary named by `[targets.*].filename` (`server.py:756-773`).
- Filesystem: `db/coverage.db` (opened `mode=ro` with `PRAGMA query_only`,
  `server.py:1561-1595`), `<project>/src`, `<project>/original`.
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:402-463`), argv list, own session, killed and reaped on a 10 s
  timeout.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`regen.py:34-36` for `recoverage regen`, `serve --regen` and `POST /api/regen`.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: three `before_request` hooks in order, request
   instrumentation (`server.py:1814-1825`), auth (`server.py:1986-1990`, hook
   body `server.py:1929-1990`), then the Host allowlist
   (`server.py:2065-2093`), then per-handler bounds
   (`_MAX_BATCH_LOOKUP` / `_MAX_BATCH_BODY_BYTES` at `api.py:989-997`;
   `_MAX_PAGE_OFFSET` at `api.py:1000`; `_MAX_SLICE_SIZE` at `api.py:1005`;
   `_MAX_SEARCH_CHARS` at `api.py:1010`).
2. **App to database.** `coverage.db` is written by rebrew and read-only here
   (`server.py:1561-1595`). The app trusts row content as data, never as SQL:
   values are bound parameters throughout, and the only interpolated fragments
   are `where_sql` assembled from constants (`api.py:1141-1143`) and a
   whitelisted `ORDER BY` field and direction (`api.py:1097-1115`). LIKE
   searches are escaped at `server.py:1041-1052` and still bound
   (`api.py:1043-1049`, `server.py:1081-1125`).
   The DB file itself is a boundary: a rewritten `coverage.db` is picked up
   live, and the SSE watcher (`api.py:517-544`) pushes `db-updated` so the SPA
   re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:281-288`).
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
(`server.py:2070-2093`, installed at `cli.py:642`) and by the `Sec-Fetch-Site`
rejection on regen (`api.py:1705-1717`). Tampering: only regen writes, and only
from loopback. Information disclosure: `/src` and `/original` proxy the whole
project tree, and the byte and asm endpoints serve arbitrary offsets of the
original binary (`api.py:1578`, `api.py:1415`) with no per-resource
authorization. Denial of service: no per-client quota anywhere; only
`/api/events` and the auth window are bounded. Repudiation: every action is
attributable only to a shared token and a socket peer, never to a client.
Elevation of privilege: an unauthenticated remote peer reaching a non-loopback
bind gets every read the operator gets, which is the whole asset set.

**App to database.** Tampering is bounded by the read-only URI, `query_only`
(`server.py:1580-1582`) and the shared `coverage_db_lock` (`server.py:1572`).
Denial of service remains: a large `functions` table with a `search` term is
served by a counting query and a page query per request (`api.py:1141-1165`),
bounded only by a 64-entry memo (`api.py:296`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:279-288`); what remains is that the trees are served in full, so a
`.env` or a key committed under `src/` is published to every client.

**App to local process.** A local, unauthenticated process can trigger regen.
Origin and `Sec-Fetch-Site` checks stop the browser-shaped version; they do not
stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely when an
`Origin` is sent that passes the loopback test (`api.py:1688-1718`). Regen runs
with no timeout by design (`regen.py:12-16`).

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the database or the listener. There is no
prompt and no warning when a config changes under a running server; the
memoized path just recomputes (`_paths.py:56-62`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare, three credential sources | `server.py:1763-1771`, `server.py:1929-1990` | Spoofing, unauthorized read |
| Global failure throttle with 429 + `Retry-After` | `server.py:1902-1927`, `server.py:1952-1957` | Online token guessing, and audit logging of each failure |
| Host header allowlist on loopback binds | `server.py:98-101`, `server.py:161-172`, `server.py:2070-2093` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:560-578` | Accidental LAN exposure |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:216-231`, `config.py:127-211`, `cli.py:239`, `cli.py:253` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and loopback-`Origin` gate on regen | `api.py:1688-1718` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:116-122`, `api.py:1745-1766` | Concurrent torn rebuilds, regen flood |
| `Idempotency-Key` ledger: format-validated, 600 s TTL, 128-slot eviction, replay answered before the cooldown | `api.py:124-177`, `api.py:1720-1735` | Duplicated pipeline runs from retries, double-clicks, proxy replay |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:2101-2113`, `server.py:2128-2134` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted, `Vary: Origin` on every response | `server.py:2128-2157`, `server.py:2115-2126`, `cli.py:497-505`, `cli.py:580-596` | Cross-origin reads |
| Symlink-resolving containment plus NUL rejection on `/src`, `/original` | `ui.py:272-288` | Path traversal |
| Allowlist regex for package assets | `ui.py:347-350` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:989-1012`, `api.py:1197-1240` | Memory and CPU exhaustion per request |
| `sort` field and direction whitelisted, not interpolated raw | `api.py:1097-1115` | SQL injection via sort |
| LIKE metacharacter escaping plus a folded casefold clause | `server.py:1041-1052`, `server.py:1081-1125` | Wildcard abuse and non-ASCII misses in search |
| `SSE_MAX_CLIENTS` cap, bounded per-client queue, idempotent unregistering | `api.py:468-472`, `api.py:596-690` | Thread exhaustion via event streams, slow-client memory growth |
| Per-socket 120 s deadline on every read and write | `cli.py:89-101` | Threads pinned by half-open or non-reading peers |
| Read-only DB connection, `query_only`, 30 s busy timeout, shared lock held to close | `server.py:1533-1595` | Accidental writes, lock contention |
| Basename-only DB path in health and SSE payloads | `api.py:708`, `api.py:496-500` | Home-directory layout disclosure |
| JSON error contract, `Cache-Control: no-store` on errors, no tracebacks in bodies, control-char-escaped logs | `server.py:1699-1731`, `server.py:2046-2061`, `server.py:641-647` | Information disclosure, stale cached errors, log forgery |
| ETag revalidation and `no-store`/`no-cache` on the 401 page | `server.py:340-402`, `server.py:1974-1985` | Serving stale data, replaying a pre-auth body from a shared cache |
| `X-Request-ID` on every request and response, capped and log-escaped when client-supplied | `server.py:1780-1825`, `server.py:1845-1847` | Untraceable incidents; forged log lines |
| Status reclassification for post-hook failures | `server.py:1875-1893`, `server.py:2042`, `server.py:2050` | An error rate that silently reads zero |

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
6. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:824` performs
   an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:825-833`). A target binary that grows between the `stat()` at
   `server.py:817` and the read is fully loaded into memory.
7. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
8. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:1861-1873`), and nothing distinguishes one
   holder of the shared token from another. The in-process RED counters
   (`metrics.py`) are a live gauge, not a record, and are lost on restart.
9. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
   crafted target is a worker-level availability and memory-safety risk that
   only the size cap touches, and that cap is post-read.
10. `CSP` allows `'unsafe-inline'` for scripts and styles
    (`server.py:2101-2113`), which the inlined SPA shell requires, so an
    injection sink in the shell would execute. No such sink is known; the
    policy is the weak link if one appears.

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
  (`cli.py:89-101`) reclaims each slot eventually, not promptly.
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.
- A caller who sets `X-Request-ID` picks its own correlation id
  (`server.py:1788-1795`), so the log line's id is attacker-chosen. It is
  capped at 64 characters and control-char escaped, which bounds forgery, but
  two different clients can share an id.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:1964-1968`), rejected Host header
  (`server.py:2081-2085`), unhandled errors with a request id and traceback
  (`server.py:2050-2055`), DB unavailability (`server.py:1992-2022`), regen
  start, rejection and completion (`api.py:1790`, `api.py:1819`, and the 429
  paths), slow requests at WARNING (`server.py:1857-1863`). Everything else is
  DEBUG and off by default.
- Every request carries an `X-Request-ID` from the client or a minted one
  (`server.py:1780-1825`), echoed on the response, so a report of "the export was
  slow" is matchable to a specific line.
- No documented path from "a vulnerability was reported" to "a fix shipped"
  exists in the repository, and there is no `SECURITY.md`: no disclosure
  contact, no supported-versions table. Left for a human to fill in; not
  invented here.
