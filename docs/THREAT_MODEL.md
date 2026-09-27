# ReCoverage Threat Model

Scope: the `recoverage` package as shipped (`src/recoverage/`) and the way it is
started (`recoverage serve`). Every claim below carries a file reference so a
later pass can re-verify it. Last reviewed: 2026-09-27.

What ReCoverage is: a read-mostly web dashboard over one local SQLite database
(`coverage.db`) that rebrew's pipeline produces, served by Bottle on a threaded
`wsgiref` (`cli.py:651-658`). The intended audience is a single developer on
their own machine, viewing a decompilation project they control. Everything
below is scoped to that deployment, plus the explicitly supported LAN case
(`--allow-remote`).

## Risk-ranked summary

| # | Risk | Where | Mitigation in code |
|---|------|-------|--------------------|
| 1 | Default deployment is unauthenticated: on `--allow-remote` without `--token` every host on the network reads project sources, original binaries, hex bytes and disassembly | `cli.py:514-529`, `server.py:1523-1582`, `api.py:1434`, `api.py:1246` | Acknowledgement only: a red message and `Exit(1)` without `--allow-remote`; `--token` is opt-in and never required alongside a remote bind |
| 2 | No request rate limit on the expensive read endpoints; a multi-MB grid build plus brotli/zstd compression is CPU- and memory-bound per request | `api.py:839` (`/data`), `potato.py:1023` (`/potato`), `api.py:1246` (`/asm`) | Bounded per-process caches with oldest-entry eviction (`server.py:989`, sizes at `api.py:127,206,224`); the only hard connection cap is on `/api/events` (`api.py:395`) |
| 3 | Global auth throttle: 10 failures per 60 s per process, not per source, so any one client can 429 the operator and every other client | `server.py:1486-1507` | The cap is intentional and documented as global; it bounds online guessing but has no per-source key |
| 4 | No transport security. The token travels as `?token=` in a URL and in a cookie, in cleartext on any non-loopback bind | `ui.py:158-163`, `server.py:1534-1542` | `Referrer-Policy: no-referrer` (`server.py:1720`), `HttpOnly; SameSite=Strict` cookie, constant-time compare (`server.py:1473-1480`) |
| 5 | `rebrew-project.toml` is trusted input: it decides which DB is read, which binaries are disassembled, and which directories `/src` and `/original` serve from | `_paths.py:37-62`, `server.py:556-618`, `ui.py:201-207` | None beyond TOML parsing; the file is assumed to come from the operator's own checkout |
| 6 | Thread exhaustion: `wsgiref` runs one thread per connection with no connection cap, so a flood of ordinary requests spawns unbounded threads | `cli.py:71-79`, `cli.py:651-658` | A 120 s per-socket idle timeout (`cli.py:91`, `cli.py:103`); only `/api/events` is capped (`api.py:395`, `api.py:588-597`) |
| 7 | Any local process can trigger a full re-catalog and DB rebuild (disk and CPU), repeatedly within the cooldown | `api.py:1536-1612` | Loopback peer check, loopback-`Origin` and `Sec-Fetch-Site: cross-site` rejection, single-flight lock, `_REGEN_COOLDOWN_SECONDS` |
| 8 | Response `detail` fields carry raw exception and request text (filesystem paths, sqlite messages, echoed user input) to the client | `server.py:1419-1423`, `server.py:1588-1604`, `api.py:1647` | Tracebacks never reach a response body (`server.py:1606-1646`); only the one-line exception class and message do |
| 9 | Untrusted native binary is parsed in-process by capstone and by the DLL reader, and the size cap is enforced only *after* an unbounded `read_bytes()` | `server.py:737-754`, `server.py:773-836`, `api.py:1405-1413` | `_MAX_DLL_SIZE` checked on `stat()` and again post-read (`server.py:740`, `server.py:749-754`); a file that grows inside that window is fully read into RAM first |
| 10 | No per-client identity: every action is attributable only to a shared token, and only to the socket peer | `server.py:1523-1582` | Rejected-token and rejected-Host events are logged with the peer address (`server.py:1559`, `server.py:1667`); regen start and completion are logged (`api.py:1624`, `api.py:1651`) |
| 11 | Seven `RECOVERAGE_*` environment variables select the bind address, the token, the DB path and the CORS allowlist, so a compromised parent environment silently republishes the project. `RECOVERAGE_TOKEN=` (set but empty) turns auth off, and an empty value is treated as unset rather than rejected | `config.py:36-46`, `config.py:71-78`, `config.py:114-170`, `cli.py:578-582` | Every value is validated at startup before the listener binds, and an unrecognised `RECOVERAGE_*` name is a hard startup error (`config.py:173-186`) |

Owner and review cadence: not stated in the repository. No disclosure contact or
supported-versions table exists either (there is no `SECURITY.md`).

## Entry points

Network (all on the single Bottle app, all threaded):

- `GET /` and `GET /index.html` - `ui.py:149-151`. Inlines and compresses the
  whole SPA; sets the auth cookie from `?token=` (`ui.py:158-163`).
- `GET /potato` - `potato.py:1023-1024`, which owns both the route and the
  renderer (`render_potato`, `potato.py:973`). Full server-side HTML of the
  entire coverage map.
- `GET /src/<path>`, `GET /original/<path>` - `ui.py:197-199`. Proxies the
  project's source tree and original binaries to the browser.
- `GET /<asset>` (allowlist regex) - `ui.py:268-272`. Package-shipped JS/CSS/SVG.
- `GET /api/health` `api.py:618`, `GET /api/targets` `api.py:662`.
- `GET /api/targets/<t>/stats|functions|functions/<va>|asm|data|sections/<s>/bytes`
  - `api.py:681`, `api.py:917`, `api.py:1188`, `api.py:1246`, `api.py:839`,
  `api.py:1434`.
- `POST /api/targets/<t>/functions` - `api.py:1128-1129`, the only
  body-carrying endpoint.
- `GET /api/events` - `api.py:575-576`, Server-Sent Events, long-lived.
- `POST /api/regen` - `api.py:1536-1537`, the only state-changing endpoint.
- `OPTIONS <path>` - `server.py:1733-1736`, CORS preflight catch-all.
- `GET|POST|PUT|DELETE|PATCH <path>` catch-all - `webapp.py:92-93`, 404/405.
- `@app.error(404)` / `@app.error(405)` - `webapp.py:114-131`, the JSON/HTML
  split by `/api/` prefix.

Request-controlled values that matter: `Host`, `Origin`, `Sec-Fetch-Site`,
`Authorization`, `Cookie`, `Accept-Encoding` are headers; `token`, `target`,
`va`, `section`, `status`, `search`, `sort`, `limit`, `offset`, `size`,
`format` are query values; `{"vas": [...]}` is the only request body.

Non-network entry points:

- CLI: `serve`, `stats`, `export`, `check`, `regen`, `open` (`cli.py:428`,
  `cli.py:681`, `cli.py:739`, `cli.py:897`, `cli.py:1006`, `cli.py:1015`). The
  operator's shell is the trust source.
- Environment: `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN`,
  `RECOVERAGE_DB` (`config.py:36-46`). Flags win over the environment, values
  are validated before the listener binds, an unknown prefixed name is a
  startup error (`config.py:173-186`). `RECOVERAGE_TOKEN` is the only secret
  and is the only reason the environment is on this list.
- `rebrew-project.toml` in the working directory, re-read on mtime+size change
  (`_paths.py:25-62`, `server.py:590`).
- The target binary named by `[targets.*].binary` (`server.py:728-736`).
- Filesystem: `db/coverage.db` (opened `mode=ro` with `PRAGMA query_only`,
  `server.py:1277-1294`), `<project>/src`, `<project>/original`.
- Browser opener subprocess `xdg-open` / `open` / `cmd /c start`
  (`cli.py:363-410`), argv list, own session, killed and reaped on a 10 s
  timeout.

Dependency and deployment surface: `wsgiref`'s threading mixin (no TLS, no
connection cap), Bottle, and rebrew, which is imported in-process by
`regen.py:34-36` for `recoverage regen`, `serve --regen` and `POST /api/regen`.

## Trust boundaries

1. **Browser or LAN client to the app.** Everything in the request above is
   untrusted. Validation point: two `before_request` hooks in order, auth
   (`server.py:1582-1585`, hook body `server.py:1523-1582`) then the Host
   allowlist (`server.py:1648-1679`), then per-handler bounds
   (`_MAX_BATCH_BODY_BYTES` / `_MAX_BATCH_LOOKUP` at `api.py:889-895`;
   `_MAX_PAGE_OFFSET` at `api.py:900`; `_MAX_SLICE_SIZE` at `api.py:905`;
   `_MAX_SEARCH_CHARS` at `api.py:910`).
2. **App to database.** `coverage.db` is written by rebrew and read-only here
   (`server.py:1284-1294`). The app trusts row content as data, never as SQL:
   values are bound parameters throughout, and the only interpolated fragments
   are `where_sql` assembled from constants (`api.py:991-996`) and a
   whitelisted `ORDER BY` field and direction (`api.py:946-959`). LIKE
   searches are escaped at `server.py:844-854` and still bound (`api.py:974-980`).
   The DB file itself is a boundary: a rewritten `coverage.db` is picked up
   live, and the SSE watcher (`api.py:443-468`) pushes `db-updated` so the SPA
   re-reads it.
3. **App to project filesystem.** `/src` and `/original` are served from the
   project directory with an explicit resolve-and-contain check, because
   Bottle's own prefix check does not resolve symlinks (`ui.py:201-207`).
4. **App to local process (regen).** The only privilege transition: a POST makes
   the server import rebrew and rebuild the DB, with the process's own
   filesystem authority (`regen.py:24-40`).
5. **Config to runtime.** `rebrew-project.toml` and the `RECOVERAGE_*`
   environment select the DB path, the target binary path, the served trees and
   the bind address, with no signature or allowlist.
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
(`server.py:1658-1679`, installed at `cli.py:582`) and by the `Sec-Fetch-Site`
rejection on regen (`api.py:1572-1580`). Tampering: only regen writes, and only
from loopback. Information disclosure: `/src` and `/original` proxy the whole
project tree, and the byte and asm endpoints serve arbitrary offsets of the
original binary (`api.py:1434`, `api.py:1246`) with no per-resource
authorization. Denial of service: no per-client quota anywhere; only
`/api/events` and the auth window are bounded. Elevation of privilege: an
unauthenticated remote peer reaching a non-loopback bind gets every read the
operator gets, which is the whole asset set.

**App to database.** Tampering is bounded by the read-only URI, `query_only`
(`server.py:1288-1294`) and the shared `coverage_db_lock` (`server.py:1284`).
Denial of service remains: a large `functions` table with a `search` term is
served by a counting query and a page query per request (`api.py:987-996`),
bounded only by a 64-entry memo (`api.py:226`).

**App to filesystem.** Traversal and symlink escape are handled explicitly
(`ui.py:206-207`); what remains is that the trees are served in full, so a
`.env` or a key committed under `src/` is published to every client.

**App to local process.** A local, unauthenticated process can trigger regen.
Origin and `Sec-Fetch-Site` checks stop the browser-shaped version; they do not
stop a local binary, and the `Sec-Fetch-Site` check is skipped entirely when an
`Origin` is sent that passes the loopback test (`api.py:1552-1580`). Regen runs
with no timeout by design (`regen.py:12-16`).

**Config to runtime.** A `rebrew-project.toml` from a cloned or shared project,
or a `RECOVERAGE_DB` / `RECOVERAGE_BIND` inherited from a parent environment,
silently redirects the served trees, the database or the listener. There is no
prompt and no warning when a config changes under a running server; the
memoized path just recomputes (`_paths.py:56-62`).

## Mitigations present, mapped

| Control | File | Covers |
|---------|------|--------|
| Optional bearer token, constant-time compare | `server.py:1473-1480`, `server.py:1523-1582` | Spoofing, unauthorized read |
| Global failure throttle with 429 + `Retry-After` | `server.py:1486-1507`, `server.py:1545-1550` | Online token guessing, and audit logging of each failure |
| Host header allowlist on loopback binds | `server.py:96`, `server.py:156-171`, `server.py:1658-1679` | DNS rebinding |
| Remote-bind acknowledgement, hard exit 1 without `--allow-remote` | `cli.py:514-529` | Accidental LAN exposure |
| Startup validation of every `RECOVERAGE_*`, unknown name rejected | `config.py:173-186`, `cli.py:578-583` | Misconfigured deployment, misspelled env var |
| `Sec-Fetch-Site: cross-site` and loopback-`Origin` gate on regen | `api.py:1542-1580` | Cross-site POST |
| Single-flight lock + cooldown on regen | `api.py:107-109`, `api.py:1588-1611` | Concurrent torn rebuilds, regen flood |
| CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `server.py:1687-1697`, `server.py:1714-1720` | Injection, framing, token leak via Referer |
| CORS allowlist, no wildcard ever emitted | `server.py:1721-1730`, `server.py:174-176`, `cli.py:456-466` | Cross-origin reads |
| Symlink-resolving containment on `/src`, `/original` | `ui.py:201-207` | Path traversal |
| Allowlist regex for package assets | `ui.py:268-271` | Arbitrary file read from the assets dir |
| Bounded request body, VA list, page offset, slice size, search length | `api.py:889-910`, `api.py:1046` | Memory and CPU exhaustion per request |
| `sort` field and direction whitelisted, not interpolated raw | `api.py:946-959` | SQL injection via sort |
| LIKE metacharacter escaping, `ESCAPE '\'` clause | `server.py:844-854`, `api.py:974-980` | Wildcard abuse in search |
| `SSE_MAX_CLIENTS` cap and idempotent unregistering | `api.py:395`, `api.py:588-610`, `api.py:539-572` | Thread exhaustion via event streams |
| Read-only DB connection, `query_only`, busy timeout, shared lock | `server.py:1277-1304` | Accidental writes, lock contention |
| Basename-only DB path in health and SSE payloads | `api.py:626`, `api.py:423-425` | Home-directory layout disclosure |
| JSON error contract, no tracebacks in bodies, control-char-escaped logs | `server.py:1409-1426`, `server.py:1636-1646`, `server.py:570` | Information disclosure, log forgery |

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
   The auth cookie is set without `Secure` (`ui.py:163`), so it crosses a
   plaintext non-loopback bind intact.
5. Trusted-by-assumption `rebrew-project.toml` and `RECOVERAGE_*`; the served
   trees follow them with no confirmation.
6. `_MAX_DLL_SIZE` does not bound the read it guards: `server.py:747` performs
   an unbounded `read_bytes()` and only checks the length afterwards
   (`server.py:749-754`). A target binary that grows between the `stat()` at
   `server.py:740` and the read is fully loaded into memory.
7. No per-resource authorization anywhere: the token is all-or-nothing, so a
   read-only viewer and the operator have identical reach.
8. No audit persistence: the only trail is stderr at INFO and above, request
   logging is DEBUG (`server.py:1648-1653`), and nothing distinguishes one
   holder of the shared token from another.
9. Capstone and the DLL reader parse attacker-shaped binaries in-process; a
   crafted target is a worker-level availability and memory-safety risk that
   only the size cap touches, and that cap is post-read.

## Abuse cases

- A hostile but authenticated LAN user with the shared token can scrape the
  whole project: `/src` for sources, `/original/<t>.dll` and
  `/api/targets/<t>/sections/<s>/bytes?size=4096` for the binary,
  `/api/targets/<t>/data` for the map. Nothing distinguishes browsing from bulk
  extraction; the only bound is the page and slice caps.
- A local process without any token can loop `POST /api/regen` to consume the
  host's CPU and rewrite `db/`, degrading the dashboard for the operator. The
  cooldown bounds rate, not volume.
- Any webpage a developer visits can hold 32 `/api/events` connections to their
  own loopback dashboard (`api.py:395`), exhausting the process's threads
  without any credential, because the SPA's EventSource is same-origin and
  no-cors from a cross-site page.
- Client-side enforcement is trusted nowhere except the grid's filter toggles;
  every filter is re-derived server-side in `/data` and `/functions`, so the
  client cannot widen its own view. The server-side `status` and `search`
  filters are the real boundary, and they are unfiltered when the request omits
  them.

## Response readiness

- Security-relevant events that reach the log: rejected token (peer address
  only, never the value, `server.py:1559`), rejected Host header
  (`server.py:1667`), unhandled errors (`server.py:1639-1644`), DB
  unavailability (`server.py:1631-1632`), regen start and completion
  (`api.py:1624`, `api.py:1651`). Everything else is DEBUG and off by default.
- No documented path from "a vulnerability was reported" to "a fix shipped"
  exists in the repository, and there is no `SECURITY.md`: no disclosure
  contact, no supported-versions table. Left for a human to fill in; not
  invented here.
