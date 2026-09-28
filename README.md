# recoverage

![recoverage mascot: a raccoon detective reading a coverage grid](https://raw.githubusercontent.com/relumea/recoverage/main/docs/mascot.png)

Coverage dashboard for binary-matching decompilation projects, for the person
whose decomp stopped matching the original binary and has to find out which part.

[Install](#installation) · [Quick Start](#quick-start) · [Screenshots](#screenshots) ·
[Potato Mode](#potato-mode) · [CI](#continuous-integration)

---

## What is recoverage?

**recoverage** serves a local web dashboard that visualises per-byte match
status across `.text`, `.data`, `.bss`, and other PE sections of a
decompilation project. Think of it as a **defrag map for your decomp**: every
byte of the original binary is a cell in a grid, colored by how closely your C
matches the original compiled output, and the blocks that stopped matching are
the ones you fix next. Click a block to read its C, its disassembly and its raw
bytes side by side, and a search or an address in the disassembly jumps to the
block that covers it.

| What | How |
|---|---|
| Defrag-style grid | One cell per chunk, colored by state: Exact (green), Reloc (blue), Near-match (yellow), Proven (cyan), Stub (red), None (gray) |
| Function detail panel | Click any cell for metadata, C source, disassembly, and hex dump side by side |
| Light and dark themes | Retro CRT dark mode by default, clean light mode one click away |
| Clickable cross-references | Hex addresses in the disassembly are live links that jump to that chunk |
| Interactive progress bar | Segmented by state; click a segment to filter the grid |
| First draw without a subrequest | HTML, CSS, and the JS bundle inlined and compressed (Brotli/Zstd) to ~48 KB |
| Potato Mode | Zero-JS server-rendered fallback for constrained environments |
| Live regen | Re-catalog and rebuild from the browser without restarting the server |

## Screenshots

### Dark Mode (the default)

![Main dashboard, the coverage grid with section tabs and filter buttons](https://raw.githubusercontent.com/relumea/recoverage/main/docs/recoverage_main.png)

### Function Detail

![Function detail panel showing metadata, C source, and disassembly](https://raw.githubusercontent.com/relumea/recoverage/main/docs/recoverage_detail.png)

### Dark Mode

![Dark mode with function detail panel](https://raw.githubusercontent.com/relumea/recoverage/main/docs/recoverage_dark.png)

### Potato Mode

![Potato Mode, the retro pure-HTML table view](https://raw.githubusercontent.com/relumea/recoverage/main/docs/recoverage_potato.png)

Potato Mode is a **zero-JavaScript**, server-side rendered HTML fallback.
Every view is a plain HTML table (no CSS, no JS) so it works on
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

`make` is not part of a stock Windows toolchain, and Windows is a supported
host, so the two lines there are the Linux and macOS bootstrap. On Windows the
clone runs under the Git-for-Windows bash and the rest is the same `uv`; see
the bootstrap section of `CONTRIBUTING.md` for the PowerShell spelling.

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

### Upgrading

The HTTP API, the CLI and the coverage document are frozen from 1.0.0, so a
change that breaks a consumer takes a major version. Before upgrading, run
`recoverage config`: it resolves the environment `serve` resolves and ends the
way `serve` ends, so a raised floor, a malformed token or a bind that needs an
acknowledgment shows up there rather than at the next restart.

[docs/UPGRADING.md](https://github.com/relumea/recoverage/blob/main/docs/UPGRADING.md)
carries the before, the after and the thing to change for every major that
broke something, and
[CHANGELOG.md](https://github.com/relumea/recoverage/blob/main/CHANGELOG.md)
is the full record.

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
> to `<root>/db`, so run it from your project root. A `rebrew-project.toml` that
> is present but not valid TOML is an error, not a fallback.
> `RECOVERAGE_DB` still selects an explicit coverage directory.
>
> Serving the dashboard needs one readable `coverage-<target>.toml` document in
> that directory, not a database file: rebrew's pipeline produces the documents
> and recoverage only reads them.

---

## CLI Commands

The wheel installs a man page with the entry point, at
`<prefix>/share/man/man1/recoverage.1`. A system or user prefix puts that on
the man path, so such an installed copy answers `man recoverage` without this
README at hand; a virtualenv prefix does not, and `MANPATH` has to name that
directory for `man` to find the page there.

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
| `--allow-remote` / `--no-allow-remote` | off | Required with a non-loopback `--bind`: acknowledge the API is reachable on the network |
| `--token` | off | Require this token for every request (`Authorization: Bearer`, `?token=`, or open `/?token=<token>` or `/potato?token=<token>` to set the browser cookie) |
| `--no-open` | off | Don't auto-open the browser |
| `--regen` | off | Re-run rebrew's catalog analysis and rewrite the documents before starting |
| `--cors` / `--no-cors` | off | Enable CORS processing (allowlisted origins only; the wildcard is never emitted) |
| `--cors-origin` | none | Origin URL allowed to read the API cross-origin (repeatable; without it `--cors` allows no cross-origin reads) |
| `--log-level` | `INFO` | Log threshold: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive) |

#### Environment

Every flag above except `--no-open` and `--regen` also reads a `RECOVERAGE_*`
variable, used as its default, so
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
| `RECOVERAGE_TOKEN` | none | the bearer token; set it empty to run unauthenticated, and give it no surrounding or interior whitespace (headers arrive trimmed, so a padded value locks every reader out) |
| `RECOVERAGE_LOG_LEVEL` | `INFO` | a `logging` level name, or its number (`0`, `10`, `20`, `30`, `40`, `50`; any other number is a startup error, because a threshold no record clears logs nothing at all) |
| `RECOVERAGE_MAX_CONNECTIONS` | `128` | integer `1`-`65536`: concurrent client connections admitted, one thread and one descriptor each |
| `RECOVERAGE_CLIENT_TIMEOUT` | `120` | integer `16`-`86400`: per-socket-operation deadline in seconds; a client that cannot absorb a write inside it is cut mid-body |
| `RECOVERAGE_DB` | resolved from the working directory | path to the coverage directory (the one holding `coverage-<target>.toml`); a path that is a file is a startup error, not an empty dashboard |
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
it exits 1, whether the address came from the flag or the environment. Set
against a loopback bind it does the opposite of what it says, so both `serve`
and `recoverage config` warn: the dashboard stays reachable only from that
machine, and a `systemctl stop` or `docker stop` reaches it.

Stopping is `SIGINT` or `SIGTERM`; both unwind the accept loop, cancel the
deferred browser opener and exit 0, so a unit file's `TimeoutStopSec` drains
instead of cutting the requests in flight. Windows has no `SIGTERM` a handler
can see, so there the stop signal is `CTRL_BREAK` (`SIGBREAK`), with `Ctrl+C`
as the always-available one.

`RECOVERAGE_DB` moves what is *read*, and rebrew resolves what a regen
*writes* from `rebrew-project.toml` alone. A regen with the two pointing at
different directories is refused with exit 2 rather than run: it would report
success while the dashboard kept serving the documents it already had. To make
them agree, point `[project].db_dir` at the same directory, or leave
`RECOVERAGE_DB` unset and run from the project root.

Every value is validated at startup. An out-of-range port, a non-boolean flag,
an unknown log level, an empty value where one is required, a bind address no
resolver can answer (`0.0.0.0 `, `host:8001`), a CORS origin no browser could
send, a token carrying whitespace a trimmed header could never present, a
`RECOVERAGE_DB` that is a file rather than the coverage directory, or a
misspelled `RECOVERAGE_*` name (`RECOVERAGE_PRT`) exits 2 with the
variable named, instead of starting with a default you did not ask for. The
same check runs for every command that reads the environment (`stats`,
`export`, `check`, `open`, `regen`), so a typo cannot quietly leave those on
their defaults. The `--port`, `--min-coverage` and `--token` flags are held to
the floor their variables get, so a non-ASCII digit, a `1_0` spelling or a
padded token is the same exit 2 whichever source it came through.
`RECOVERAGE_PORT=0` binds a free port, and the banner, `/api/health` and the
browser URL all report the one that was bound rather than the 0.
The two `RECOVERAGE_FUZZ_*` variables are the test suite's, not the server's;
they carry the prefix so an operator who exported one to drive a campaign is
not stopped by the unknown-name check, and they change nothing `serve` does.
`recoverage serve` prints the settings it resolved on startup, with the token
reported as `token=set`. `recoverage config` prints the same settings without
binding a port, as `key=value` lines or `--json`, and ends the way `serve`
ends: a non-loopback bind without `RECOVERAGE_ALLOW_REMOTE` exits 1, the CORS
and empty-coverage-directory warnings go to stderr, and the token is never
printed. Use it as the preflight a unit file can gate on.

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

Exit codes: 0 = the table (or the JSON) was printed, 1 = the coverage
directory holds no document, or `--target` names a target no build has
written, 2 = an invalid flag or `RECOVERAGE_*` value.

### `recoverage export`

Export coverage data to stdout.

```bash
recoverage export --format json     # JSON (default)
recoverage export --json            # same, the spelling stats/check/config take
recoverage export --format csv      # CSV
recoverage export --format md       # Markdown table
```

The rows are the only thing on stdout, so `> coverage.csv` and a pipe get clean
data. Exit codes: 0 = the rows were written, 1 = the coverage directory holds
no document, or `--target` names a target no build has written, 2 = an invalid
flag or `RECOVERAGE_*` value. Under `--format json` the failure envelope goes
to stdout, as it does for `stats --json`. `--json` with a `--format` that is
not `json` is a usage error (exit 2), not a silent winner.

### `recoverage check`

CI gate, exits non-zero if coverage is below a threshold.  Sections the
grid never records matches for (e.g. `.bss`/`.data` when only `.text`
matches are tracked) are skipped, not failed.

```bash
recoverage check --min-coverage 60                              # all targets, all sections
recoverage check --min-coverage 60 --target SERVER --section .text   # specific
recoverage check --min-coverage 60 --json                       # machine-readable verdict
```

Exit codes: 0 = gate passed, 1 = coverage below threshold (or a target/section
that matched nothing), 2 = bad `--min-coverage` value, an unreadable coverage
document, or a coverage directory holding no `coverage-*.toml`.

### `recoverage regen`

Re-run the catalog analysis to regenerate the coverage documents.

```bash
recoverage regen
```

recoverage calls rebrew's catalog and build-db functions as a library, in
process, rather than spawning the `rebrew` console script.  The run has no
timeout, so it always runs to completion.

Nothing reaches stdout: the progress line, the completion line and every error
are status, and they go to stderr, so a script reads the outcome from the exit
code.  `serve --regen` runs the same pipeline, so its progress stays off the
stdout the startup banner is written to.

Exit codes: 0 = the documents were written (or rebrew had no built target to
write for), 1 = rebrew failed or another regen of the same project already
holds its lock, 2 = `RECOVERAGE_DB` names a directory rebrew
would not write to.  That mismatch is refused rather than reported as a done
regen that left the dashboard stale, because rebrew resolves what it writes
from `rebrew-project.toml` alone.

Running it a second time *while the first is still going* is refused rather
than run: two writers of one `coverage-<target>.toml` interleave instead of
converging, and the dashboard can read the gap. The guard is a lock in the
coverage directory, so it also covers a `recoverage regen` run beside a
running dashboard or from a cron job, which this process's own lock cannot
see. The lock is released by the operating system when its holder exits, so a
regen that is killed does not block the next one.

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
| `/index.html` | GET | The same document, for a URL that names it |
| `/src/<filepath:path>` | GET | A file under the target's `src/` tree, for the code panes |
| `/original/<filepath:path>` | GET | A file under the original binary's tree |
| `/app.js`, `/style.css`, `/print.css`, `/favicon.svg` | GET | The packaged static assets (`no-cache` with a strong `ETag`) |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, the settings this process resolved, coverage directory info, installed extras, request/regen/stream/connection counters, cache hit-miss |
| `/api/targets` | GET | List available targets. Revalidates: an `ETag` over the coverage snapshot and the project config's stat, so a repeat is a 304 |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats with percentages (no query parameters) |
| `/api/targets/<target>/data` | GET | Section + cell data (`?section=.text` for partial, `?index=0` to omit the search index) |
| `/api/targets/<target>/functions` | GET | Paginated list (`?status=&search=&sort=&limit=&offset=`; a `status` outside rebrew's vocabulary, or a `sort` column the list does not carry, is a 400). Revalidates: an `ETag` over the snapshot and every parameter, so a repeat is a 304 |
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order |
| `/api/targets/<target>/functions/<va>` | GET | Single function/global detail. Revalidates like the list: the tag names the snapshot, the target and the requested spelling |
| `/api/targets/<target>/asm` | GET | Disassembly (`?format=json` for structured output) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice (`?offset=&size=`) |
| `/api/events` | GET | Server-Sent Events: `db-updated` when the coverage documents change (SPA auto-refresh) |
| `/api/regen` | POST | Re-run catalog + build-db (loopback peer and, when present, same-origin only; rate-limited; optional `Idempotency-Key` header) |

A regen rebuilds the coverage documents from scratch, so running it twice leaves the
same state as running it once. Send an `Idempotency-Key` header with the
request and a repeat of that key is answered with the recorded result
(`Idempotent-Replay: true`) instead of running the pipeline again; a repeat that
lands while the first run is still going is answered `202` with
`{"ok": true, "in_progress": true}` (`Idempotent-Replay: in-progress`), since
a regen runs for minutes and a proxy gives up long before it finishes. Keys are
remembered for 10 minutes (the ledger holds more slots than the rate limit
admits in that window, so a key is only ever dropped by its own age), and a
failed run is not remembered.

Both of those are this process's own bookkeeping. A regen under way in another
process (a `recoverage regen` at a terminal, a cron job over the same tree) is a
duplicate none of them can see, so the pipeline takes a lock in the coverage
directory and the POST is answered `429` with the same body the in-process lock
sends, counting as a refusal rather than a failure.

### Query parameters

Every `/api/` endpoint that takes a query parameter lists it here; anything
else in the query string is ignored.

| Endpoint | Parameter | Default | Accepted | Rejected with 400 |
|----------|-----------|---------|----------|------------------|
| `/api/targets/<target>/data` | `section` | all sections | one section name | an unknown name is a 404 |
| `/api/targets/<target>/data` | `index` | `1` | `0` omits `search_index`, `1` includes it | any other value |
| `/api/targets/<target>/functions` | `status` | no filter | rebrew's function-status vocabulary, matched case-sensitively | any other value |
| `/api/targets/<target>/functions` | `search` | no filter | up to 500 characters | anything longer |
| `/api/targets/<target>/functions` | `sort` | `va` | `va`, `name`, `size`, `status`, `symbol`, `module`, each optionally suffixed `:asc` or `:desc` | an unknown column or direction |
| `/api/targets/<target>/functions` | `limit` | `50` | clamped to 1..500 | never; an unparseable value falls back to the default |
| `/api/targets/<target>/functions` | `offset` | `0` | clamped to 0..10000000 | never; an unparseable value falls back to the default |
| `/api/targets/<target>/asm` | `va` | required | hex with or without `0x`, or a decimal address | unparseable or outside the section |
| `/api/targets/<target>/asm` | `size` | required | 1..4096, decimal or `0x`-prefixed hex | zero, negative or unparseable |
| `/api/targets/<target>/asm` | `section` | `.text` | one section name | an unknown name is a 404 |
| `/api/targets/<target>/asm` | `format` | `text` | `text`, `json` | any other value |
| `/api/targets/<target>/sections/<section>/bytes` | `offset` | `0` | decimal or `0x`-prefixed hex | negative or unparseable |
| `/api/targets/<target>/sections/<section>/bytes` | `size` | `256` | 1..4096, decimal or `0x`-prefixed hex | zero, negative or unparseable |

An enum the server does not have (`status`, `sort`, `format`, `index`) is a
400: the caller asked for a value the server cannot honour, and answering 200
with an empty, differently-shaped or differently-ordered body reads as "there
are none". A numeric parameter that only bounds the page (`limit`, `offset`)
falls back to its default instead, because the response shape and its meaning
are the same either way.

`status` is matched case-sensitively against rebrew's vocabulary, which is
spelled in upper case: `EXACT` filters, `exact` is a 400. The set is read
from rebrew rather than restated here, so it tracks whatever the installed
rebrew writes; `GET /api/targets/<target>/functions` answers 400 naming every
accepted value. `format` is the exception, lowercased before it is matched.
`sort` columns are case-sensitive too, and its direction is not: `:asc` and
`:desc` either case, and a bare column sorts ascending.

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
    "latency_window": 96, "p50_ms": 4.102, "p95_ms": 91.204,
    "by_status": {"2xx": 409, "4xx": 2, "5xx": 1},
    "by_route": {"/api/targets/<target>/data": {"requests": 12, "errors": 0,
      "max_ms": 91.2, "latency_window": 12, "p50_ms": 62.1, "p95_ms": 91.2}}
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
double-clicked Regenerate button rather than a broken pipeline, so it is kept off
`failures`. `streams` reports live-reload saturation: each connected SSE
stream pins a server thread for its whole life, so `clients` against
`max_clients` is the distance to the 503 the next tab gets.
`serve` starts the poller at startup rather than on the first stream, so an
external rebuild refreshes a server that never has an SSE client (curl-only
automation); `watcher_alive` is `null` only in a process that never ran
`serve`. A connected client with a dead poller answers `degraded`: every
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
which is the same whole number of seconds the `Retry-After` header carries.

A wrong verb on a real path answers **405 with an `Allow` header**; a path no
route matches answers **404**. A `405` never means "not found" here.

### Caching

Every coverage-derived read endpoint (`/data`, `/stats`, `/asm`,
`/sections/<section>/bytes`, the function list, the function detail route and
`/potato`) carries an `ETag` over the
freshness stamp of the coverage documents plus the request's own identity
(target, section, VA, offset, format, and the list's filters and page window),
and `Cache-Control: no-cache,
must-revalidate`. Send `If-None-Match` and unchanged documents answer
**304** with no body. `/api/health` is `no-store` instead: it
reports the server's own state, not the coverage documents'.
`/api/targets` revalidates as well: its tag names both the coverage snapshot
and the project config's stat, because the list merges the two, and it falls
back to `no-store` when the coverage directory cannot be read, since there is
then nothing to revalidate against.

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

**recoverage** is designed as a standalone **consumer** of the data that [rebrew](https://github.com/maci0/rebrew) produces. The two packages are intentionally decoupled.

```text
rebrew build-db (catalog in-process)  recoverage (Bottle)
              │                             │
  db/coverage-<target>.toml  ─────────────▶  Preact dashboard
```

1. **`rebrew build-db`**: Scans your project's source annotations, runs the catalog analysis in process (jump table / switch data bytes are absorbed into their parent function's size, and data and thunk cells link to their parent through `parent_function`) and writes one clear-text TOML document per target, `db/coverage-<target>.toml` (`version = 1`), holding the facts: the sections with their cells, the functions (`detected_by`, `size_by_tool`, `textOffset`, …), the globals (`module`, `size`), the verify results, the history, and `[metadata].paths`.  Nothing derivable is stored: the per-section buckets, the per-section byte totals, the coverage percentages, the function-stats summary and the by-VA index are all computed at load by `rebrew.coverage_toml`, the same reader rebrew's own dashboard uses.  There is no intermediate snapshot between the analysis and the document, so a document cannot describe an older tree than the one that produced it.  Every run replaces each document whole, so `--force` has nothing to migrate.  See [COVERAGE_DOCUMENT.md](https://github.com/maci0/rebrew/blob/main/docs/COVERAGE_DOCUMENT.md) for the full document shape.  `rebrew catalog --export-ghidra-labels` remains a separate command, generating `ghidra_data_labels.json` for round-trip Ghidra sync.
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
cover, is in [docs/THREAT_MODEL.md](https://github.com/relumea/recoverage/blob/main/docs/THREAT_MODEL.md).

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
├── SECURITY.md              # Supported version line and where a vulnerability report goes
├── docs/                    # Screenshots, mascot & design doc
│   ├── DESIGN.md            # Detailed architecture & design doc
│   ├── DESIGN_PRINCIPLES.md # Core operational philosophies
│   ├── USER_STORIES.md      # User stories with acceptance criteria
│   ├── THREAT_MODEL.md      # Attack surface, trust boundaries, risks
│   ├── UPGRADING.md         # Before/after for every major that broke a consumer
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
│   ├── bundled_js_inventory.py  # The browser-bundle half of the SBOM, from bun.lock (make browser-sbom)
│   ├── license_inventory.py   # The license every resolved Python package is under, and the refusal (make license-inventory)
│   ├── check_wheel_assets.py  # Reads BUNDLE_ASSETS back off the built wheel
│   └── oxlint/               # Vendored anti-slop rules + the flattened strict preset
├── tests/
│   ├── conftest.py           # Shared fixtures (synthetic coverage TOML)
│   ├── coverage_fixture.py   # Builders for synthetic coverage documents
│   ├── test_api.py           # API validation & security tests
│   ├── test_build.py         # Shipped files and reproducible build bytes
│   ├── test_cli.py           # CSV export, formatting tests
│   ├── test_concurrency.py   # Barrier-driven races: single flight, counters, the admission cap
│   ├── test_config.py        # RECOVERAGE_* parsing, precedence, fail-fast
│   ├── test_import_graph.py  # The import rules the modules rely on
│   ├── test_frontend_import_graph.py  # The same rules over web/app
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
| `sbom` | ubuntu | Two build artifacts: `make python-sbom` (`uv export --frozen --all-extras --hashes`) for the exact resolved Python tree behind a given build plus the rebrew tag and commit the path dependency was pinned at, and `make browser-sbom` for the npm packages `make web-build` compiles into the shipped browser assets, each with the version and tarball digest `bun.lock` pinned. The `lint` job runs `make license-inventory`, which reads the licenses off the resolved tree's own metadata and refuses anything that is not permissive |

Every job but `sbom` installs with `uv sync --locked --extra dev` and then runs
tools through `uv run --locked`. `--locked` never rewrites `uv.lock` and also
refuses to install one that no longer matches `pyproject.toml`, so a dependency
edit that skipped `uv lock` fails the run instead of testing a tree the manifest
does not describe. `sbom` skips the sync, and its one `uv export --frozen` stays
frozen, because it is the job with no sibling `../rebrew` to resolve and reads
the lock alone. Its browser half needs no environment at all: the wheel ships
`src/recoverage/assets/`, which is compiled from six npm devDependencies, and
`uv.lock` cannot see them. Playwright and the
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
from. The grants ship in [`NOTICE`](https://github.com/relumea/recoverage/blob/main/NOTICE), which `license-files` puts in the
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
as [`NOTICE`](https://github.com/relumea/recoverage/blob/main/NOTICE), which `license-files` puts in the distribution metadata
next to the MIT license.
