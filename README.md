# recoverage

<p align="center">
  <img src="docs/mascot.png" alt="recoverage mascot — a raccoon detective investigating code coverage" width="200">
  <br>
  <strong>Coverage dashboard for binary-matching decompilation projects.</strong>
  <br>
  <em>See every byte. Track every match. Ship the decomp.</em>
</p>

<p align="center">
  <a href="#installation">Install</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#potato-mode">Potato Mode</a> ·
  <a href="#continuous-integration">CI</a>
</p>

---

## What is recoverage?

**recoverage** serves a local web dashboard that visualises per-byte match
status across `.text`, `.data`, `.bss`, and other PE sections of a
decompilation project. Think of it as a **defrag map for your decomp** —
every byte of the original binary is a cell in a grid, colored by how
closely your C code matches the original compiled output.

### Features

- **Byte comparison**: See where your C matches the original compiled output, byte for byte, and where it drifts.
- **Divergence triage**: Find the part of a function that stopped matching, whether that is register allocation, instruction reordering, or padding.
- **Source next to output**: Click any block to read its C, its disassembly, and the raw bytes side by side.

### Details

| What | How |
|---|---|
| Defrag-style grid | One cell per chunk, colored by state: Exact (green), Reloc (blue), Near-match (yellow), Proven (cyan), Stub (red), None (gray) |
| Function detail panel | Click any cell for metadata, C source, disassembly, and hex dump side by side |
| Light and dark themes | Retro CRT dark mode by default, clean light mode one click away |
| Clickable cross-references | Hex addresses in the disassembly are live links that jump to that chunk |
| Interactive progress bar | Segmented by state; click a segment to filter the grid |
| First draw without a subrequest | HTML, CSS, and the JS bundle inlined and compressed (Brotli/Zstd) to ~46 KB |
| Potato Mode | Zero-JS server-rendered fallback for constrained environments |
| Live regen | Re-catalog and rebuild from the browser without restarting the server |

## Screenshots

### Main Dashboard

![Main dashboard — coverage grid with section tabs and filter buttons](docs/recoverage_main.png)

### Function Detail

![Function detail panel showing metadata, C source, and disassembly](docs/recoverage_detail.png)

### Dark Mode

![Dark mode with function detail panel](docs/recoverage_dark.png)

### Potato Mode

![Potato Mode — retro pure-HTML table view](docs/recoverage_potato.png)

Potato Mode is a **zero-JavaScript**, server-side rendered HTML fallback.
Every view is a plain HTML table — no CSS, no JS — so it works on
low-spec machines, restricted browsers, or anywhere you just want a quick
glance without loading the full SPA.

---

## Installation

> [!IMPORTANT]
> The wheel declares `rebrew>=2.16.0` as a hard runtime dependency, and rebrew
> is not on the package index yet, so `pip install recoverage` stops at
> resolution with "No matching distribution found for rebrew>=2.16.0". The
> commands below are the install that works today: recoverage resolves rebrew
> from a sibling checkout, so the tree must sit beside one. `git clone`
> recoverage on its own, or any git worktree of it, leaves `uv sync` failing
> with `Distribution not found at file:///.../rebrew`. This section becomes
> `pip install recoverage` when rebrew is published.

```bash
make clone-rebrew   # the sibling rebrew into ../rebrew, at the pin in tools/ci_clone_rebrew.sh
make setup          # uv sync --locked --extra dev
make test           # or: make test-one T=tests/test_api.py
uv run recoverage serve
```

CONTRIBUTING.md covers the rest of the contributor bootstrap, and
`[tool.uv.sources]` in `pyproject.toml` points the dependency at a rebrew you
already have.

### Optional runtime extras

Add an extra to enable its feature: `uv sync --extra <extra>`.

| Extra | Package | What it does |
|-------|---------|--------------|
| `capstone` | capstone | Enables on-demand disassembly in the detail panel |
| `pygments` | pygments | Syntax highlighting in Potato Mode |
| `playwright` | playwright, pytest-playwright | Browser integration tests (`tests/test_playwright.py`) |

---

## Quick Start

```bash
# 1. Generate the coverage documents (from your project directory)
uv run rebrew build-db
# Analyzes the target binary and your annotations, then writes one clear-text
# coverage document per target (db/coverage-<target>.toml) for the dashboard.
# The catalog analysis runs inside this command, so there is nothing to run
# before it.

# 2. Start the dashboard
recoverage
# Same as `recoverage serve`: starts a lightweight Bottle web server serving
# the frontend SPA and providing the API backend
```

> [!NOTE]
> The server resolves the coverage **directory** from the **current working
> directory**: `[project] db_dir` in `rebrew-project.toml` when set, falling back
> to `<root>/db` — so run it from your project root. A `rebrew-project.toml` that
> is present but not valid TOML is an error, not a fallback.
> `RECOVERAGE_DB` still selects an explicit coverage directory.
>
> Serving the dashboard needs one readable `coverage-<target>.toml` document in
> that directory, not a database file: rebrew's pipeline produces the documents
> and recoverage only reads them.

---

## CLI Commands

The wheel installs a man page with the entry point, so an installed copy
answers `man recoverage` without this README at hand.

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--version` | | Print the version and exit |
| `--no-color` | off | Disable colored output; also disabled by `NO_COLOR` or `TERM=dumb`. Accepted before or after the subcommand |
| `--install-completion` | | Install shell completion for bash, zsh, fish or PowerShell |
| `--show-completion` | | Print the completion script instead of installing it |

Errors, warnings, and gate verdicts are colored on a terminal and plain
everywhere else (a pipe, a file, `NO_COLOR`, `TERM=dumb`), the `stats` table
included. Under `--json`, stdout carries the machine payload only and every
human note goes to stderr.

### `recoverage serve`

Start the dashboard web server. `recoverage` on its own, with no subcommand, is
this command with its default settings.

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8001` | HTTP port to serve on; `0` binds a free port and prints the one it got |
| `--bind` | `127.0.0.1` | Interface to bind to (use `0.0.0.0` for LAN access) |
| `--allow-remote` | off | Required with a non-loopback `--bind`: acknowledge the API is reachable on the network |
| `--token` | off | Require this token for every request (`Authorization: Bearer`, `?token=`, or open `/?token=<token>` or `/potato?token=<token>` to set the browser cookie) |
| `--no-open` | off | Don't auto-open the browser |
| `--regen` | off | Re-run rebrew's catalog analysis and rewrite the documents before starting |
| `--cors` | off | Enable CORS processing (allowlisted origins only; the wildcard is never emitted) |
| `--cors-origin` | none | Origin URL allowed to read the API cross-origin (repeatable; without it `--cors` allows no cross-origin reads) |
| `--log-level` | `INFO` | Log threshold: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive) |

#### Environment

Every flag above also reads a `RECOVERAGE_*` variable, used as its default, so
a service can be configured without putting anything in its argv (and, for the
token, without exposing it in the process listing). A flag on the command line
always wins over the environment.

| Variable | Default | Accepts |
|----------|---------|---------|
| `RECOVERAGE_PORT` | `8001` | integer `0`-`65535` |
| `RECOVERAGE_BIND` | `127.0.0.1` | an interface address or hostname; no whitespace, no `host:port` (the port belongs to `RECOVERAGE_PORT`) |
| `RECOVERAGE_ALLOW_REMOTE` | `false` | `1`/`0`, `true`/`false`, `yes`/`no`, `on`/`off` |
| `RECOVERAGE_CORS` | `false` | same booleans |
| `RECOVERAGE_CORS_ORIGIN` | none | comma-separated origin URLs; each must be one a browser could send (`scheme://host[:port]`, no userinfo, path or whitespace) |
| `RECOVERAGE_TOKEN` | none | the bearer token; set it empty to run unauthenticated |
| `RECOVERAGE_LOG_LEVEL` | `INFO` | a `logging` level name, or its number |
| `RECOVERAGE_MAX_CONNECTIONS` | `128` | integer `1`-`65536`: concurrent client connections admitted, one thread and one descriptor each |
| `RECOVERAGE_CLIENT_TIMEOUT` | `120` | integer `5`-`86400`: per-connection socket deadline in seconds; must outlast the 15s SSE heartbeat or live reload is cut short |
| `RECOVERAGE_DB` | resolved from the working directory | path to the coverage directory (the one holding `coverage-<target>.toml`) |
| `RECOVERAGE_FUZZ_SEED` | unset | seed for the mutation campaigns (`make fuzz`); read by the test suite, not the server |
| `RECOVERAGE_FUZZ_ITERATIONS` | unset | round count for those campaigns; same reader |

```bash
# A service that is not run from the project root, on a LAN interface,
# with a token that never reaches the process listing:
export RECOVERAGE_DB=/srv/project/db
export RECOVERAGE_BIND=0.0.0.0
export RECOVERAGE_ALLOW_REMOTE=1
export RECOVERAGE_TOKEN="$(cat /run/secrets/recoverage_token)"
recoverage serve --no-open
```

The same service in PowerShell, where `export` is not how a variable is set
and there is no `/run/secrets`:

```powershell
$env:RECOVERAGE_DB = "D:\project\db"
$env:RECOVERAGE_BIND = "0.0.0.0"
$env:RECOVERAGE_ALLOW_REMOTE = "1"
$env:RECOVERAGE_TOKEN = (Get-Content C:\secrets\recoverage_token -Raw).Trim()
recoverage serve --no-open
```

`.env.example` carries the same surface in a copy-pasteable form: every
variable above, commented out, each with the stock value beside it and a note
on what it accepts. It is what a `systemd` `EnvironmentFile` or a container
spec is drafted from, and `tests/test_config.py` fails when a variable reaches
this table and misses it.

`RECOVERAGE_DB` is read through `Path.expanduser()`, so a leading `~` and the
`USERPROFILE` it resolves against on Windows work as they do on POSIX.

`RECOVERAGE_ALLOW_REMOTE` is still yours to set: a non-loopback bind without
it exits 1, whether the address came from the flag or the environment.

`RECOVERAGE_DB` moves what is *read*, and rebrew resolves what a regen
*writes* from `rebrew-project.toml` alone. A regen with the two pointing at
different directories is refused with exit 2 rather than run: it would report
success while the dashboard kept serving the documents it already had. To make
them agree, point `[project].db_dir` at the same directory, or leave
`RECOVERAGE_DB` unset and run from the project root.

Every value is validated at startup. An out-of-range port, a non-boolean flag,
an unknown log level, an empty value where one is required, a bind address no
resolver can answer (`0.0.0.0 `, `host:8001`), a CORS origin no browser could
send, or a misspelled `RECOVERAGE_*` name (`RECOVERAGE_PRT`) exits 2 with the
variable named, instead of starting with a default you did not ask for. The
same check runs for every command that reads the environment (`stats`,
`export`, `check`, `open`, `regen`), so a typo cannot quietly leave those on
their defaults. The `--port` and `--min-coverage` flags are held to the floor
their variables get, so a non-ASCII digit or a `1_0` spelling is the same exit
2 whichever source it came through. `RECOVERAGE_PORT=0` binds a free port, and
the banner, `/api/health` and the browser URL all report the one that was
bound rather than the 0.
The two `RECOVERAGE_FUZZ_*` variables are the test suite's, not the server's;
they carry the prefix so an operator who exported one to drive a campaign is
not stopped by the unknown-name check, and they change nothing `serve` does.
`recoverage serve` prints the settings it resolved on startup, with the token
reported as `token=set`. `recoverage config` prints the same settings without
binding a port, as `key=value` lines or `--json`, and ends the way `serve`
ends: a non-loopback bind without `RECOVERAGE_ALLOW_REMOTE` exits 1, the CORS
warnings go to stderr, and the token is never printed. Use it as the preflight
a unit file can gate on.

The running server answers the same question over HTTP: `GET /api/health`
carries a `config` block with the settings that process resolved (`db` is left
to the endpoint's own basename-only `db` block). Unlike `recoverage config`, it
reads the server's environment, not the shell's, which under a unit file or a
container spec are not the same thing. It is `null` in a process that never ran
`serve`, and it is behind the token when one is set.

### `recoverage config`

Print the configuration `serve` would start with, without binding a port.
Useful for confirming a service's environment, or for diffing two of them.

```bash
recoverage config                     # key=value, token as set/unset
recoverage config --json              # the same settings as a JSON object
```

```
bind=0.0.0.0
port=8001
allow_remote=true
cors=false
cors_origin=none
db=auto
log_level=INFO
token=set
max_connections=128
client_timeout=120
```

### `recoverage stats`

Print per-section coverage stats as a Rich table, or as JSON with `--json`.

```bash
recoverage stats                    # all targets
recoverage stats --target SERVER    # single target
recoverage stats --json             # machine-readable
```

With `--json`, a failure is reported on stdout as
`{"error": "...", "exit_code": N}` rather than as a stderr line, so a script
parses one shape whether the run failed or not.  `check --json` and
`export --format json` report the same envelope.

### `recoverage export`

Export coverage data to stdout.

```bash
recoverage export --format json     # JSON (default)
recoverage export --format csv      # CSV
recoverage export --format md       # Markdown table
```

### `recoverage check`

CI gate — exits non-zero if coverage is below a threshold.  Sections the
grid never records matches for (e.g. `.bss`/`.data` when only `.text`
matches are tracked) are skipped, not failed.

```bash
recoverage check --min-coverage 60                              # all targets, all sections
recoverage check --min-coverage 60 --target SERVER --section .text   # specific
recoverage check --min-coverage 60 --json                       # machine-readable verdict
```

Exit codes: 0 = gate passed, 1 = coverage below threshold (or a target/section
that matched nothing), 2 = bad `--min-coverage` value or an unreadable coverage
document.

### `recoverage regen`

Re-run the catalog analysis to regenerate the coverage documents.

```bash
recoverage regen
```

recoverage calls rebrew's catalog and build-db functions as a library, in its
own process, not by spawning the `rebrew` console script.  The run has no
timeout, so it always runs to completion; the dashboard's threaded server keeps
serving while it is busy.  A failure exits 1.

### `recoverage open`

Open the dashboard in a browser (useful when `--no-open` was used).

```bash
recoverage open --port 8001
```

`--port` defaults to `RECOVERAGE_PORT`, the same port `serve` uses, so a
deployment that moved off `8001` needs no second place to configure. A port of
`0` is refused with exit 2: it names the free port `serve` picked, which only
the banner that run printed holds.

---

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Main SPA dashboard |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, the settings this process resolved, coverage directory info, installed extras, request/regen/stream counters |
| `/api/targets` | GET | List available targets |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats with percentages |
| `/api/targets/<target>/data` | GET | Section + cell data (`?section=.text` for partial, `?index=0` to omit the search index) |
| `/api/targets/<target>/functions` | GET | Paginated list (`?status=&search=&sort=&limit=&offset=`; a `status` outside rebrew's vocabulary is a 400) |
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order |
| `/api/targets/<target>/functions/<va>` | GET | Single function/global detail |
| `/api/targets/<target>/asm` | GET | Disassembly (`?format=json` for structured output) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice (`?offset=&size=`) |
| `/api/events` | GET | Server-Sent Events: `db-updated` when the coverage documents change (SPA auto-refresh) |
| `/api/regen` | POST | Re-run catalog + build-db (loopback peer and, when present, same-origin only; rate-limited; optional `Idempotency-Key` header) |

A regen rebuilds the coverage documents from scratch, so running it twice leaves the
same state as running it once. Send an `Idempotency-Key` header with the
request and a repeat of that key is answered with the recorded result
(`Idempotent-Replay: true`) instead of running the pipeline again; keys are
remembered for 10 minutes (the ledger holds more slots than the rate limit
admits in that window, so a key is only ever dropped by its own age), and a
failed run is not remembered.

### Query parameters

Every `/api/` endpoint that takes a query parameter lists it here; anything
else in the query string is ignored.

| Endpoint | Parameter | Default | Accepted | Rejected with 400 |
|----------|-----------|---------|----------|------------------|
| `/api/targets/<target>/data` | `section` | all sections | one section name | an unknown name is a 404 |
| `/api/targets/<target>/data` | `index` | `1` | `0` omits `search_index`, `1` includes it | any other value |
| `/api/targets/<target>/functions` | `status` | no filter | rebrew's function-status vocabulary, matched case-sensitively | any other value |
| `/api/targets/<target>/functions` | `search` | no filter | up to 500 characters | anything longer |
| `/api/targets/<target>/functions` | `sort` | `va` | `va`, `name`, `size`, `status`, `symbol`, `module`, each optionally suffixed `:desc` | never; an unknown field ignores the whole parameter |
| `/api/targets/<target>/functions` | `limit` | `50` | clamped to 1..500 | never; an unparseable value falls back to the default |
| `/api/targets/<target>/functions` | `offset` | `0` | clamped to 0..10000000 | never; an unparseable value falls back to the default |
| `/api/targets/<target>/asm` | `va` | required | hex with or without `0x`, or a decimal address | unparseable or outside the section |
| `/api/targets/<target>/asm` | `size` | required | 1..4096, decimal or `0x`-prefixed hex | zero, negative or unparseable |
| `/api/targets/<target>/asm` | `section` | `.text` | one section name | an unknown name is a 404 |
| `/api/targets/<target>/asm` | `format` | `text` | `text`, `json` | any other value |
| `/api/targets/<target>/sections/<section>/bytes` | `offset` | `0` | decimal or `0x`-prefixed hex | negative or unparseable |
| `/api/targets/<target>/sections/<section>/bytes` | `size` | `256` | 1..4096, decimal or `0x`-prefixed hex | zero, negative or unparseable |

An enum the server does not have (`status`, `format`, `index`) is a 400: the caller
asked for a value the server cannot honour, and answering 200 with an empty
or differently-shaped body reads as "there are none". A numeric parameter
that only bounds the page (`limit`, `offset`) falls back to its default
instead, because the response shape and its meaning are the same either way.

`status` is matched case-sensitively against rebrew's vocabulary, which is
spelled in upper case: `EXACT` filters, `exact` is a 400. The set is read
from rebrew rather than restated here, so it tracks whatever the installed
rebrew writes; `GET /api/targets/<target>/functions` answers 400 naming every
accepted value. `format` is the exception, lowercased before it is matched.

`va` is spelled two ways by design: `GET /functions/<va>` and `/asm` read an
all-digit string as decimal first, while the `POST /functions` batch body
reads every VA as hexadecimal with an optional `0x` prefix. A VA that fits
both readings resolves to the decimal one on the two path routes.

Real output from the sample target the smoke harness serves
(`tools/smoke.py`), truncated at two rows:

```console
$ curl -s 'localhost:8001/api/targets/FAKEDLL/functions?limit=2'
{"target": "FAKEDLL", "total": 3, "limit": 2, "offset": 0, "functions": [
  {"va": 268439552, "name": "_func_a", "vaStart": "0x10001000", "size": 48,
   "status": "EXACT", "module": "T", "symbol": "_func_a", "markerType": "FUNCTION"},
  {"va": 268439568, "name": "_func_b", "vaStart": "0x10001010", "size": 16,
   "status": "RELOC", "module": "T", "symbol": "_func_b", "markerType": "FUNCTION"}
]}
```

`total` counts every row the filters match; `functions` holds at most `limit`
of them, starting at `offset`. `va` is a decimal number, `vaStart` the hex
spelling of the same address, and `module`, `symbol` and `markerType` are
null when rebrew recorded nothing for the row.

### Observing a running server

Every response carries an `X-Request-ID` header, and every log line for that
request repeats it as `[rid=...]`, including the traceback of a failed one.
Send your own `X-Request-ID` and the server uses it instead of minting one,
so a report from a client can be matched to the server log. Raise the detail
with `--log-level DEBUG` to get one line per request with its status and
duration; a request slower than a second is one `WARNING` line at any level.

`/api/health` carries the counters for the process:

```json
{
  "status": "healthy",
  "requests": {
    "total": 412, "errors": 1, "slow": 0, "in_flight": 1,
    "slow_threshold_ms": 1000.0, "mean_ms": 4.812, "max_ms": 91.204,
    "by_status": {"2xx": 409, "4xx": 2, "5xx": 1},
    "by_route": {"/api/targets/<target>/data": {"requests": 12, "errors": 0, "max_ms": 91.2}}
  },
  "regen": {
    "runs": 3, "failures": 0, "rejected": 1, "in_flight": 0,
    "last_duration_ms": 84210.4, "last_ok": true
  },
  "streams": {
    "clients": 1, "max_clients": 32, "queue_max": 32, "watcher_alive": true
  }
}
```

Routes are counted by their rule, never by the raw path, so the map stays
bounded whatever a caller asks for. The snapshot is taken before the reading
request is filed, so it describes everything up to it. There is no metrics
backend to configure: these numbers live in the process and reset with it.

`regen` covers the rebuild pipeline, which is the one request that runs for
minutes: the request counters can say a request is in flight but not that it
is a rebuild, how long the last one took, or whether failures are climbing.
`rejected` counts POSTs the cooldown or the run lock refused, which is a
double-clicked Reload button rather than a broken pipeline, so it is kept off
`failures`. `streams` reports live-reload saturation: each connected SSE
stream pins a server thread for its whole life, so `clients` against
`max_clients` is the distance to the 503 the next tab gets.
`watcher_alive` is `null` until the first client connects, since the poller
starts lazily. A connected client with a dead poller answers `degraded`: every
page still renders, none of them will ever refresh again.

### Error responses

Every `/api/*` failure answers the same JSON envelope, and every error body
is sent with `Cache-Control: no-store`:

```json
{
  "error": "Method not allowed",
  "code": "method_not_allowed",
  "detail": "POST is not allowed on /api/health; allowed: GET, HEAD"
}
```

`code` is the stable machine-readable key: `bad_request`, `unauthorized`,
`forbidden`, `not_found`, `method_not_allowed`, `payload_too_large`,
`unsupported_media_type`, `unprocessable_entity`, `rate_limited`, `internal`,
`not_implemented`, `db_unavailable`. `detail` names the parameter or
constraint at fault, and some errors add one more key (`retry_after`, on a
429 and on the 503 `/api/events` answers once its connection cap is full),
which repeats the `Retry-After` header.

A wrong verb on a real path answers **405 with an `Allow` header**; a path no
route matches answers **404**. A `405` never means "not found" here.

### Caching

Every coverage-derived read endpoint (`/data`, `/stats`, `/asm`,
`/sections/<section>/bytes` and `/potato`) carries an `ETag` over the
freshness stamp of the coverage documents plus the request's own identity
(target, section, VA, offset, format), and `Cache-Control: no-cache,
must-revalidate`. Send `If-None-Match` and unchanged documents answer
**304** with no body. `/health` and `/targets` are `no-store` instead: they
report the server's own state, not the coverage documents'.

Query-parameter rules, the same on every endpoint:

- `/asm` requires `va` and `size`, and accepts `format=text` (default) or
  `format=json`. An unrecognized `format` is a 400, not a silent fall back to
  text. `size` is a byte count, decimal or 0x-prefixed, clamped to 4096.
- `/sections/<section>/bytes` takes `offset` (default 0) and `size` (default
  256, clamped to 4096); both are decimal unless 0x-prefixed. A slice that
  would run past the section end is a 400 naming the section's size.
- Both of those read the original binary, and a target whose binary is
  missing or has no `[targets.<id>].binary` in `rebrew-project.toml` is a 404
  (`DLL not found`, detail naming the key to add) whichever `format` you ask
  for. A 422 means the binary loaded and the requested window ran past its
  end.
- `/functions` (list) takes `limit` (1..500, default 50) and `offset` (>= 0,
  default 0). An unparseable or out-of-range value is clamped, and the
  response echoes the `limit` and `offset` actually used.
- `/functions` (POST) takes `{"vas": [...]}`, at most 500 entries, each a hex
  string (with or without `0x`) or an integer. The body must be under 64 KiB
  (413) and the list non-empty (400). VAs with no match are omitted from the
  response rather than reported as an error. A `Content-Type` header, if
  sent, must be `application/json` (or any `application/*+json`); anything
  else is a 415 `unsupported_media_type`. Omitting the header entirely is
  allowed, so a `curl -d` client must add `-H 'Content-Type: application/json'`
  to stay off that path.

With `--cors`, an allowlisted origin may send `Content-Type`, `Authorization`
(the `--token` bearer check) and `If-None-Match` (the conditional GET every
ETag-bearing endpoint above expects); a preflight naming any other request
header is refused. `ETag` and `Retry-After` are exposed as readable response
headers, so a cross-origin client can revalidate and honour a 429's wait.
Every 429 the server emits carries `Retry-After` alongside the `retry_after`
body key.

---

## Architecture & How it works

**recoverage** is designed as a standalone **consumer** of the data that [rebrew](../rebrew) produces — the two packages are intentionally decoupled.

```text
rebrew build-db (catalog in-process)  recoverage (Bottle)
              │                             │
  db/coverage-<target>.toml  ─────────────▶  Preact dashboard
```

1. **`rebrew build-db`**: Scans your project's source annotations, runs the catalog analysis in process (jump table / switch data bytes are absorbed into their parent function's size, and data and thunk cells link to their parent through `parent_function`) and writes one clear-text TOML document per target, `db/coverage-<target>.toml` (`version = 1`), holding the facts: the sections with their cells, the functions (`detected_by`, `size_by_tool`, `textOffset`, …), the globals (`module`, `size`), the verify results, the history, and `[metadata].paths`.  Nothing derivable is stored: the per-section buckets, the per-section byte totals, the coverage percentages, the function-stats summary and the by-VA index are all computed at load by `rebrew.coverage_toml`, the same reader rebrew's own dashboard uses.  There is no intermediate snapshot between the analysis and the document, so a document cannot describe an older tree than the one that produced it.  Every run replaces each document whole, so `--force` has nothing to migrate.  See [DB_FORMAT.md](../rebrew/docs/DB_FORMAT.md) for the full document shape.  `rebrew catalog --export-ghidra-labels` remains a separate command, generating `ghidra_data_labels.json` for round-trip Ghidra sync.
2. **`recoverage`**: Starts a **Bottle** web server. The backend serves API endpoints built from the parsed coverage documents, while the frontend is a **Preact** + Tailwind Single Page Application built from `web/` by `make web-build` (Vite, TypeScript, Tailwind CSS 4) into `assets/app.js` and `assets/style.css`, which the server inlines into the `/` shell, rendering the interactive defrag grid.

You can run `recoverage` independently on any machine (or even host it remotely, see the caveat below) as long as it has access to a readable `coverage-<target>.toml` document.  rebrew is a required dependency (it provides the shared workspace/config resolution, the document reader, and the in-process regen), but no project workspace or compiler toolchain is required to serve the dashboard.

### Hosting it on a network

`recoverage serve` binds `127.0.0.1` and serves, unauthenticated, the project's
`src/` tree, its `original/` binaries, raw byte slices and disassembly. That is
fine on your own machine and is the reason the default is loopback. Serving it
beyond that needs both `--allow-remote` (the acknowledgement the CLI requires
for any non-loopback `--bind`) and `--token` (the bearer check every request
then has to pass); `--cors` is for a separate local frontend origin and is never
needed for the dashboard's own page. There is no TLS, so a token on a network
bind travels in cleartext. The full picture, including what the code does not
cover, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Project layout

```
recoverage/
├── pyproject.toml
├── README.md
├── CHANGELOG.md             # Release history
├── CONTRIBUTING.md          # Bootstrap, edit-test loop, local/CI parity
├── Makefile                 # Contributor targets (`make help`); wraps the CI commands
├── LICENSE                  # MIT
├── man/recoverage.1       # Man page for the console script, installed by the wheel
├── NOTICE                   # Grants for the third-party code the web build bundles
├── docs/                    # Screenshots, mascot & design doc
│   ├── DESIGN.md            # Detailed architecture & design doc
│   ├── DESIGN_PRINCIPLES.md # Core operational philosophies
│   ├── USER_STORIES.md      # User stories with acceptance criteria
│   ├── THREAT_MODEL.md      # Attack surface, trust boundaries, risks
│   └── ideas.md             # Future improvement ideas
├── web/                     # Frontend sources built into the assets (Vite + Preact + Tailwind)
│   ├── app/                 # SPA components, hooks, grid geometry, tokens
│   ├── index.html           # The `vite dev` shell
│   ├── tsconfig.json        # Strict tsc settings, including the `@/` alias
│   └── vite.config.ts       # The build that emits src/recoverage/assets/app.js and style.css
├── tools/                    # Lint and CI harness scripts
│   ├── lint_html.py          # Nu Html Checker over the static and served assets
│   ├── smoke.py              # End-to-end server smoke run
│   ├── _serve_harness.py     # Shared boot-and-probe harness for the two above
│   ├── ci_clone_rebrew.sh    # Clones the ../rebrew path dep at a pinned commit
│   ├── normalize_sdist.py     # Pins the sdist's mtimes/order/header for a reproducible build
│   ├── flatten_rikalabs_strict.py  # Regenerates tools/oxlint/rikalabs-strict.json (MIT) from @rikalabs/oxlint-standards 0.8.1
│   ├── vendor_manifest.py    # Inventories the vendored anti-slop tree file by file
│   ├── payload_budget.py     # Re-derives the inlined shell size at each static encoding (make payload-budget)
│   └── oxlint/               # Vendored anti-slop rules + the flattened strict preset
├── tests/
│   ├── conftest.py           # Shared fixtures (synthetic coverage TOML)
│   ├── coverage_fixture.py   # Builders for synthetic coverage documents
│   ├── test_api.py           # API validation & security tests
│   ├── test_build.py         # Shipped files and reproducible build bytes
│   ├── test_cli.py           # CSV export, formatting tests
│   ├── test_config.py        # RECOVERAGE_* parsing, precedence, fail-fast
│   ├── test_import_graph.py  # The import rules the modules rely on
│   ├── test_lifecycle.py     # Lifecycle (regen ordering, opener reaping, deadlines)
│   ├── test_paths.py         # Coverage directory resolution tests
│   ├── test_server.py        # Compression, encoding tests
│   ├── test_potato.py        # Potato Mode rendering tests
│   ├── test_perf.py          # Deterministic perf regression gates (work counters, not wall clock)
│   ├── test_metrics.py       # Request id, RED counters, slow-request log line
│   ├── test_release.py       # Release contract (version, changelog, declared floors)
│   ├── test_supply_chain.py  # Pins: rebrew ref/sha, declared-vs-imported deps, vendored-asset grants
│   ├── test_fuzz.py          # Seeded mutation campaigns over the untrusted-input surfaces
│   ├── test_serve_harness.py # The smoke + lint_html harness contract
│   └── test_playwright.py    # Browser integration tests
└── src/recoverage/
    ├── __init__.py
    ├── __main__.py           # python -m recoverage
    ├── _paths.py             # Coverage directory resolution (RECOVERAGE_DB, db_dir)
    ├── clock.py              # The one time source the request path reads
    ├── config.py             # RECOVERAGE_* env: defaults, validation, startup banner
    ├── metrics.py            # In-process RED counters, read by /api/health
    ├── devserver.py          # WSGI serving stack: threading server, keep-alive handlers
    ├── cli.py                # Typer CLI entry point
    ├── server.py             # Bottle app, shared helpers & compression
    ├── disasm.py             # Capstone disassembly (optional extra)
    ├── regen.py              # In-process rebrew regen (catalog analysis + document writer)
    ├── api.py                # REST API routes (/api/*)
    ├── ui.py                 # UI routes (/, static files)
    ├── potato.py             # Potato Mode renderer + the /potato route
    ├── webapp.py             # Composition root: imports api+ui+potato so app has every route
    └── assets/                # Built bundle + the static files the server serves
        ├── index.html        # SPA shell (the bundle is inlined into it)
        ├── app.js            # Built dashboard bundle (Preact + Tailwind)
        ├── style.css         # Built Tailwind output
        ├── print.css         # Print stylesheet
        └── favicon.svg       # Retro "R" logo favicon
```

The frontend sources are in `web/`, not in `assets/`: `app/` holds the Preact
components, hooks and the grid geometry, `index.html` is the `vite dev` shell,
and `vite.config.ts` builds `app/main.tsx` into the two files above.

---

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request against `main`. A new push to a PR branch cancels the run in flight
on that branch; runs on `main` are never cancelled, so no commit loses a
check.

| Job | Runner | What it enforces |
|-----|--------|------------------|
| `lint` | ubuntu, Python 3.13 | `ruff format --check`, `ruff check` and `mypy` (strict) over `src/`, `tools/`, plus `ruff check` over `tests/`, then `shellcheck` and `yamllint` |
| `web-lint` | ubuntu, Python 3.13, bun 1.4.2, temurin 17 | oxlint (Rika-Labs strict + anti-slop) over the SPA sources, the Nu Html Checker over every static and served HTML/CSS asset, then `tsc --noEmit` over the strict `web/tsconfig.json` |
| `test` | ubuntu 3.13 + 3.14, macos 3.13, windows 3.13 | `pytest tests/`, warnings-as-errors. Browser tests (`tests/test_playwright.py`) stay out of the default run and are not run in CI |
| `build` | ubuntu, Python 3.13 | `make build` twice, the second time from a copy of the tree under a different path, locale and timezone, and fails when the two archives differ. Uploads the wheel and sdist |
| `smoke` | ubuntu, Python 3.13 | boots `recoverage serve` against synthetic coverage documents and probes the SPA shell, health, target data/stats/functions and Potato Mode, then repeats with a corrupt document to prove it reports `degraded` instead of healthy |
| `sbom` | ubuntu | `uv export --frozen --all-extras --hashes` as a build artifact: the exact resolved tree behind a given build, plus the rebrew tag and commit the path dependency was pinned at |

Every job but `sbom` installs with `uv sync --locked --extra dev` and then runs
tools through `uv run --locked`. `--locked` never rewrites `uv.lock` and also
refuses to install one that no longer matches `pyproject.toml`, so a dependency
edit that skipped `uv lock` fails the run instead of testing a tree the manifest
does not describe. `sbom` skips the sync, and its one `uv export --frozen` stays
frozen, because it is the job with no sibling `../rebrew` to resolve and reads
the lock alone. Playwright and the
`capstone`/`pygments` extras are never installed, so the
matrix is the same set on every runner.

### The sibling rebrew checkout

`uv sync` resolves rebrew from `../rebrew`, which no GitHub runner has, so
each job that installs the environment first runs
`tools/ci_clone_rebrew.sh` (the same script `make clone-rebrew` wraps): it
clones the tag in `REBREW_REF` into the workspace parent and fails unless the
tag still resolves to the commit in `REBREW_SHA`, so a moved tag cannot
silently change the path dependency. Those defaults are the one place the pin
lives, and `tests/test_supply_chain.py` fails when a job
grows a second way to fetch the sibling. The commit has to keep
matching `uv.lock`. When rebrew's own dependencies change, `uv sync --locked`
fails with a lock mismatch, and the fix is to re-lock in a tree laid out with
the sibling and bump `REBREW_REF`/`REBREW_SHA` in the script.

---

## Third-party code in the distribution

The dashboard ships no vendored blob under `src/recoverage/assets/`: the
`app.js` and `style.css` it serves are built by `make web-build` from the npm
dependencies declared in `package.json`, so what the build folds into those two
files is distributed with the wheel whether or not anyone records where it came
from. The grants ship in [`NOTICE`](NOTICE), which `license-files` puts in the
distribution metadata next to the MIT license, and which is the file to read
and amend when a dependency is added to `web/`:

| Library | Compiled into | License |
|---------|---------------|---------|
| [Preact](https://github.com/preactjs/preact) (and `preact/compat`) | `assets/app.js` | MIT |
| [Highlight.js](https://highlightjs.org) (core plus the `c` and `x86asm` grammars) | `assets/app.js` | BSD-3-Clause |
| [Tailwind CSS](https://github.com/tailwindlabs/tailwindcss) | `assets/style.css` | MIT |
| `clsx`, `tailwind-merge`, `class-variance-authority` (the shadcn/ui primitives' own dependencies) | `assets/app.js` | MIT |

Nothing is fetched from a CDN at runtime, so the dashboard works air-gapped.
The remaining npm packages in `package.json` (vite, typescript, oxlint,
`@oxlint/plugins`, `@rikalabs/oxlint-standards`, `vnu-jar` and the build plugins)
are build-time tools and are not shipped. `tests/test_supply_chain.py` fails
when a library enters the bundle without joining this table and NOTICE.

Two pieces of lint config are checked in as copies, and their provenance is the
other direction:

| Path | Origin | License |
|------|--------|---------|
| `tools/oxlint/rikalabs-strict.json` | Generated by `tools/flatten_rikalabs_strict.py` from the `strict` preset of the pinned `@rikalabs/oxlint-standards` 0.8.1; regenerate, do not hand-edit | MIT (the package's `LICENSE` and `license` field); `tools/flatten_rikalabs_strict.py` fails if a bump changes it |
| `tools/oxlint/anti-slop/` | Vendored copy of [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop) | MIT (`LICENSE` in that directory) |
| `tools/oxlint/anti-slop.manifest.json` | Generated by `tools/vendor_manifest.py`: the upstream, the license, every vendored file with its sha256, and the paths left out | first-party record of the row above |

The anti-slop copy is the one checked-in dependency no registry manifest
covers, so its own record is `anti-slop.manifest.json`: a re-vendor or a
local edit that skipped it fails the suite instead of landing. The upstream
rule tests are deliberately not copied (they import `oxlint/plugins-dev`, a
subpath no declared dependency provides, and nothing here runs TypeScript
tests); the manifest names them as excluded. To re-vendor, replace the
directory from upstream, run `uv run python tools/vendor_manifest.py`, then
`bun run lint:js` to confirm the rule set still passes.

---

## License

MIT

The wheel also bundles the third-party code listed above. Their grants ship
as [`NOTICE`](NOTICE), which `license-files` puts in the distribution metadata
next to the MIT license.
