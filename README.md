# recoverage

![recoverage mascot: a raccoon detective reading a coverage grid](https://raw.githubusercontent.com/maci0/recoverage/main/docs/mascot.jpg)

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
| Defrag-style grid | One cell per chunk, colored by verdict: `EXACT` (green), `RELOC` (teal), `PROVEN` (pale green), `NEAR` (steel blue), `STUB` (grey), problem (red), undocumented (unlit) |
| Function detail panel | Click any cell for metadata, C source, disassembly, and hex dump side by side |
| Light and dark themes | Follows the OS, with a one-click override; both use the relumea brand tokens |
| Clickable cross-references | Hex addresses in the disassembly are live links that jump to that chunk |
| Filter by verdict | One pill per state with its block count; click one to dim every other block |
| First draw without a subrequest | HTML, CSS, and the JS bundle inlined and compressed to the smallest of Brotli/Zstd/gzip the client accepts, ~40 KB today (`make payload-budget` re-derives it against the 90 KB `ui._TCP_CWND_BUDGET` ceiling) |
| Potato Mode | Zero-JS server-rendered fallback for constrained environments |
| Live regen | Refresh the project view from the browser without restarting the server |

## Screenshots

> [!NOTE]
> These four shots are captured from a running `recoverage serve` against a
> synthetic project: an invented `DEMO` target whose coverage document was
> written with `tests/coverage_fixture.py`'s writer, beside generated C files
> and generated x86 code bytes. Every name and figure in them is made up; the
> layout, the palette and the states on the grid are the product's own.

### Main dashboard

![Main dashboard, the coverage grid with section tabs and filter buttons](https://raw.githubusercontent.com/maci0/recoverage/main/docs/recoverage_main.png)

### Function detail

![Function detail panel showing metadata, C source, and disassembly](https://raw.githubusercontent.com/maci0/recoverage/main/docs/recoverage_detail.png)

### Function detail, dark theme

![Dark mode with function detail panel](https://raw.githubusercontent.com/maci0/recoverage/main/docs/recoverage_dark.png)

### Potato Mode

![Potato Mode, the retro pure-HTML table view](https://raw.githubusercontent.com/maci0/recoverage/main/docs/recoverage_potato.png)

Potato Mode is a **zero-JavaScript**, server-side rendered HTML fallback.
Every view is a plain HTML table (no CSS, no JS) so it works on
low-spec machines, restricted browsers, or anywhere you just want a quick
glance without loading the full SPA.

---

## Installation

Install the published GitHub wheel into a virtual environment. Its dependency
metadata fetches the exact hash-pinned Rebrew 5 wheel automatically; no local
Rebrew checkout is required.

```bash
uv venv --python 3.13
uv pip install "https://github.com/maci0/recoverage/releases/download/v8.4.1/recoverage-8.4.1-py3-none-any.whl"
.venv/bin/recoverage serve
```

On Windows, launch `.venv\Scripts\recoverage.exe serve` instead. Run the
server from your Rebrew project directory to view its canonical coverage.

For contributors, clone this repository and run:

```bash
make setup          # uv sync --locked --extra dev
make test           # or: make test-one T=tests/test_api.py
uv run recoverage serve
```

On Windows, use `uv sync --locked --extra dev` and the pytest command from
[CONTRIBUTING.md](https://github.com/maci0/recoverage/blob/main/CONTRIBUTING.md). That guide also covers opt-in editable
Rebrew development; a normal sync restores the public dependency.

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

[docs/UPGRADING.md](https://github.com/maci0/recoverage/blob/main/docs/UPGRADING.md)
carries the before, the after and the thing to change for every major that
broke something, and
[CHANGELOG.md](https://github.com/maci0/recoverage/blob/main/CHANGELOG.md)
is the full record.

---

## Quick Start

From anywhere inside an existing Rebrew project:

```bash
recoverage serve
```

The dashboard reads canonical metadata, binaries, sources and discovery inventory
through Rebrew's shared live coverage model. No generated coverage files or
`db_dir` setting is required. Input changes refresh the view automatically;
`recoverage regen` explicitly refreshes it without writing files.

For portable, offline viewing:

```bash
rebrew coverage export --output snapshots/
RECOVERAGE_SNAPSHOTS=/absolute/path/to/snapshots recoverage serve
```

Before retiring older generated exports, preserve their history:

```bash
rebrew coverage import-history --snapshots db/ --dry-run
rebrew coverage import-history --snapshots db/
```

The import does not change current verdicts or bindings. Keep configured inventory
files even if they live under `db/`. Status transitions now live in canonical
function metadata and survive dashboard restarts and export removal.

---

## CLI Commands

The examples below write `recoverage` bare. Prefix it with `uv run` (as the
installation section does) when you have no activated environment, or activate
the one `make setup` synced so the entry point is on `PATH`.

The wheel installs a man page with the entry point, at
`<prefix>/share/man/man1/recoverage.1`. A system or user prefix puts that on
the man path, so such an installed copy answers `man recoverage` without this
README at hand; a virtualenv prefix does not, and `MANPATH` has to name that
directory for `man` to find the page there.

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `-h`, `--help` | | Show the help and exit; accepted on the command group and on every subcommand |
| `-V`, `--version` | | Print the version and exit |
| `--no-color` | off | Disable colored output; also disabled by `NO_COLOR` or `TERM=dumb`. Accepted before or after the subcommand |
| `--install-completion` | | Install shell completion for bash, zsh, fish or PowerShell |
| `--show-completion` | | Print the completion script instead of installing it |

The per-command tables below give the long spelling; each of these also has a
short form: `--port`/`-p` (`serve`, `open`), `--target`/`-t` (`stats`,
`export`, `check`), `--format`/`-f` (`export`), `--min-coverage`/`-m`
(`check`) and `--section`/`-s` (`check`).

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
| `--regen` | off | Refresh the live project view before starting |
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
| `RECOVERAGE_BIND` | `127.0.0.1` | an interface address or hostname; no whitespace, no `host:port` (the port belongs to `RECOVERAGE_PORT`), and none of the characters no address or hostname can hold — a `0.0.0.0%eth0` interface spec and a URL pasted into the unit file are startup errors naming this variable, not a bind error blaming another instance. A `%` is legal in exactly one place: the zone of a link-local IPv6 literal (`fe80::1%1`) |
| `RECOVERAGE_ALLOW_REMOTE` | `false` | `1`/`0`, `true`/`false`, `yes`/`no`, `on`/`off` |
| `RECOVERAGE_CORS` | `false` | same booleans |
| `RECOVERAGE_CORS_ORIGIN` | none | comma-separated origin URLs; each must be one a browser could send (`scheme://host[:port]`, no userinfo, path or whitespace). A value naming no origin at all (empty, or only commas and whitespace) is a startup error, so an environment that spells "not configured" as an empty value cannot start a server that refuses every cross-origin read |
| `RECOVERAGE_TOKEN` | none | the bearer token; set it empty to run unauthenticated, and give it no surrounding or interior whitespace (headers arrive trimmed, so a padded value locks every reader out) |
| `RECOVERAGE_LOG_LEVEL` | `INFO` | a `logging` level name, or its number (`0`, `10`, `20`, `30`, `40`, `50`; any other number is a startup error, because a threshold no record clears logs nothing at all) |
| `RECOVERAGE_MAX_CONNECTIONS` | `128` | integer `1`-`65536`: concurrent client connections admitted, one thread and one descriptor each |
| `RECOVERAGE_CLIENT_TIMEOUT` | `120` | integer `16`-`86400`: per-socket-operation deadline in seconds; a client that cannot absorb a write inside it is cut mid-body |
| `RECOVERAGE_SNAPSHOTS` | unset (live project) | explicit portable snapshot directory; a file path is a startup error |
| `RECOVERAGE_BACKUP_DIR` | a `backups/` beside the coverage directory | directory `recoverage backup` writes its archive into; read by that command and by nothing else. Never point it inside the coverage directory: the next backup would copy the previous archive as if it were a document. A scheduled job cannot pass `--to`, so this is the channel that reaches it |
| `RECOVERAGE_FUZZ_SEED` | unset | seed for the mutation campaigns (`make fuzz`); read by the test suite, not the server |
| `RECOVERAGE_FUZZ_ITERATIONS` | unset | round count for those campaigns; same reader |
| `RECOVERAGE_DEV_API` | `http://127.0.0.1:8001` | the running server the `make web-dev` Vite proxy forwards `/api`, `/files`, `/src` and `/original` to; read by `web/vite.config.ts`, not by any subcommand (the same rule the two fuzz knobs follow: the name is accepted so exporting it cannot refuse a command, and it changes nothing `serve` does) |

Portable-mode parsed coverage documents persist under `$XDG_CACHE_HOME/recoverage/documents/`
(`~/.cache/recoverage/documents/` when it is unset or relative), one file per
document, so a restart skips the TOML parse for every document whose bytes have
not changed. It keeps the 64 most recently used documents, and deleting the
directory is always safe. Live project reads bypass this persisted parse cache.

```bash
# A service that is not run from the project root, on a LAN interface,
# with a token that never reaches the process listing:
export RECOVERAGE_SNAPSHOTS=/srv/project/db
export RECOVERAGE_BIND=0.0.0.0
export RECOVERAGE_ALLOW_REMOTE=1
export RECOVERAGE_TOKEN="$(cat /run/secrets/recoverage_token)"
recoverage serve --no-open
```

The same service in PowerShell, where `export` is not how a variable is set
and there is no `/run/secrets`:

```powershell
$env:RECOVERAGE_SNAPSHOTS = "D:\project\db"
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

`RECOVERAGE_SNAPSHOTS` is read through `Path.expanduser()`, so a leading `~` and the
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

`RECOVERAGE_SNAPSHOTS` selects portable exports instead of the live project.
Portable mode is read-only: `regen` and `serve --regen` refuse it. To run a live
service, set its working directory inside the project and leave this variable
unset. `backup` / `restore` operate only on explicitly selected portable exports;
canonical project metadata remains managed by Rebrew.

Every value is validated at startup. An out-of-range port, a non-boolean flag,
an unknown log level, an empty value where one is required, a bind address no
resolver can answer (`0.0.0.0 `, `host:8001`), a CORS origin no browser could
send, a token carrying whitespace a trimmed header could never present, a
`RECOVERAGE_SNAPSHOTS` that is a file rather than the coverage directory, or a
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

Against the synthetic coverage document the test suite builds
(`tests/coverage_fixture.py`):

```console
$ recoverage stats
FAKEDLL
  Functions: 2 of 3 matched (66.6%)

  Section      Size   Cells   EXACT   RELOC   NEAR   STUB   Coverage
 ────────────────────────────────────────────────────────────────────
  .text     4,096 B       8       2       1      0      1      87.5%
  .data     1,024 B       1       0       0      0      0     100.0%
```

The verdict columns use the dashboard's words, and the sections follow the
document's load order, `.text` first.

With `--json`, a failure is reported on stdout as
`{"error": "...", "exit_code": N}` rather than as a stderr line, so a script
parses one shape whether the run failed or not.  `check --json` and
`export --format json` report the same envelope.

Exit codes: 0 = the table (or JSON) was printed, 1 = no readable coverage or an
unavailable selected target, 2 = an invalid flag or `RECOVERAGE_*` value.

### `recoverage export`

Export coverage data to stdout.

```bash
recoverage export --format json     # JSON (default)
recoverage export --json            # same, the spelling stats/check/config take
recoverage export --format csv      # CSV
recoverage export --format md       # Markdown table
```

The rows are the only thing on stdout, so `> coverage.csv` and a pipe get clean
data. Exit codes: 0 = the rows were written, 1 = no readable coverage or an
unavailable selected target, 2 = an invalid flag or `RECOVERAGE_*` value. Under `--format json` the failure envelope goes
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

Refresh the live project view immediately without generating files:

```bash
recoverage regen
```

Progress and errors go to stderr; stdout stays empty. `serve --regen` uses the
same operation. Normal reads also detect input changes automatically. Portable
snapshots are read-only, so unset `RECOVERAGE_SNAPSHOTS` to refresh a project.
Status transitions are canonical metadata; refresh does not create history from
what the dashboard happened to observe. The API retains its in-process admission
and idempotency rules; there is no cross-process snapshot writer or lock.

### `recoverage backup`

Copy every coverage document into one verified archive, and read it back.

```bash
recoverage backup                                  # backups/coverage-<stamp>.tar
recoverage backup --to /srv/backups/nightly.tar
recoverage backup --json                           # for a scheduled job
```

Backup and restore require an explicit `RECOVERAGE_SNAPSHOTS` directory. Live
project history and verification evidence belong to the canonical Rebrew metadata,
which these commands never overwrite. Before retiring old exports, preserve their
history with `rebrew coverage import-history --snapshots <directory>`.

So the backup is verified rather than merely written. Every archive carries a
manifest of its members' sha256 digests, and the command reads the archive back
and recomputes them before reporting success, so a green exit means a restore
could read it rather than that a write returned. The archive itself is written
through a temp file, fsynced, and only then published by an atomic rename, so
a crash mid-run leaves the previous backup rather than a truncated one.

`--to` takes a file, or a directory to get the stamped default name: one
that exists, or any path ending in `/`, which is created. The
default directory is `$RECOVERAGE_BACKUP_DIR`, else a `backups/` beside the
coverage directory - never inside it, because the next run would copy the
previous archive as if it were a document. Exits 1 when there is nothing to
back up: an empty archive verifies, and restoring one empties the dashboard,
so a failed build must read as an alert rather than as a green run.

### `recoverage restore`

Put a verified backup's documents into the explicitly selected offline directory.

```bash
recoverage restore /srv/backups/nightly.tar
recoverage restore /srv/backups/nightly.tar --force
```

The archive is verified in full - every member read, its size and digest
checked - before the first document is written, and each document then lands
through an atomic replace. A restore therefore either completes or leaves the
coverage directory exactly as it was; half a restore is a dashboard that reads
healthy and shows half a project.

`--force` replaces differing selected offline snapshots; the refusal names every
document it would overwrite. Canonical live verdicts and `status_history` stay
unchanged. A corrupt archive, a member that is not a coverage document, a
member name that would escape the directory and an unreadable file are refused
either way.

Offline readers detect restored bytes automatically; `regen` is a live-project operation. The full procedure is in
[the recovery runbook](https://github.com/maci0/recoverage/blob/main/docs/RECOVERY.md).

### `recoverage open`

Open the dashboard in a browser (useful when `--no-open` was used).

```bash
recoverage open --port 8001 --bind 127.0.0.1
```

`--port` defaults to `RECOVERAGE_PORT` and `--bind` to `RECOVERAGE_BIND`, the
same settings `serve` uses, so a deployment that moved off `127.0.0.1:8001`
needs no second place to configure. The URL opened is the address the listener
holds: a wildcard bind (`0.0.0.0`, `::`) opens through loopback, which every
such listener answers on, and a named interface (`--bind 10.0.0.5`) opens on
that interface, because loopback is a socket that bind never reached. A port of
`0` is refused with exit 2: it names the free port `serve` picked, which only
the banner that run printed holds.

When nothing accepts a connection at that address, `open` warns on stderr and
opens the tab anyway, since a dashboard about to start serves it on the first
reload; the exit code stays 0.

---

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Main SPA dashboard |
| `/index.html` | GET | The same document, for a URL that names it |
| `/files/<target>/source/<filepath:path>` | GET | A file under the selected target's configured, project-contained source root |
| `/files/<target>/binary` | GET | The selected target's configured, project-contained binary |
| `/src/<filepath:path>` | GET | A file under the project's fixed `src/` tree |
| `/original/<filepath:path>` | GET | A file under the original binary's tree |
| `/app.js`, `/style.css`, `/print.css`, `/favicon.svg`, `/highlight.js`, `/archivo.woff2`, `/jetbrains-mono.woff2` | GET | The packaged static assets (`no-cache` with a strong `ETag`). `/highlight.js` is the standalone highlighter the code panes load on demand; it is emitted as a second bundle beside `app.js` because the dashboard bundle is an IIFE and cannot code-split |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, the settings this process resolved, coverage-source info (`db.unreadable` names failed live targets or unreadable portable documents, and any one degrades the status), installed extras, request/regen/stream/connection counters, cache hit-miss |
| `/api/targets` | GET | List configured/readable targets, plus failed live targets or unreadable portable documents under `unreadable` (`file`, `target`, `error`; no absolute paths). Revalidates: an `ETag` over the coverage snapshot and the project config's stat, so a repeat is a 304 |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats with percentages (no query parameters) |
| `/api/targets/<target>/data` | GET | Section + cell data (`?section=.text` for partial, `?index=0` to omit the search index) |
| `/api/targets/<target>/functions` | GET | Paginated list (`?status=&search=&sort=&limit=&offset=`; a `status` outside rebrew's vocabulary, or a `sort` column the list does not carry, is a 400). Revalidates: an `ETag` over the snapshot and every parameter, so a repeat is a 304 |
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order |
| `/api/targets/<target>/functions/<va>` | GET | Single function/global detail. Revalidates like the list: the tag names the snapshot, the target and the requested spelling |
| `/api/targets/<target>/asm` | GET | Disassembly (`?format=json` for structured output) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice (`?offset=&size=`) |
| `/api/events` | GET | Server-Sent Events: `db-updated` when the live view or selected portable exports change (SPA auto-refresh) |
| `/api/regen` | POST | Refresh the live project view (loopback peer and, when present, same-origin only; rate-limited; optional `Idempotency-Key` header) |

A refresh derives a read-only view from the current project inputs. Send an `Idempotency-Key` header with the
request and a repeat of that key is answered with the recorded result
(`Idempotent-Replay: true`) instead of running the pipeline again; a repeat that
lands while the first run is still going is answered `202` with
`{"ok": true, "in_progress": true}` (`Idempotent-Replay: in-progress`), since
a regen runs for minutes and a proxy gives up long before it finishes. A key is
recorded the moment the pipeline completes, not when the answer is sent, so a
retry still replays after a connection that died on the way back. Keys are
remembered for 10 minutes (the ledger holds more slots than the rate limit
admits in that window, so a key is only ever dropped by its own age), and a
failed or interrupted run is not remembered — retrying a failure retries for
real.

Admission and idempotency are local to this process. Independent processes read
canonical project inputs without acquiring a shared snapshot writer lock.

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

`regen` measures explicit read-only refresh: its duration, completion and
failures are separate from ordinary request counts. Changed-input reads may also
perform analysis without a POST refresh.
`rejected` counts POSTs the cooldown or the run lock refused, which is a
double-clicked Regenerate button rather than a broken pipeline, so it is kept off
`failures`. `streams` reports live-reload saturation: each connected SSE
stream pins a server thread for its whole life, so `clients` against
`max_clients` is the distance to the 503 the next tab gets.
`serve` starts the poller at startup rather than on the first stream, so an
external project or snapshot changes refresh a server that never has an SSE client (curl-only
automation); `watcher_alive` is `null` only in a process that never ran
`serve`. A connected client with a dead poller answers `degraded`: every
page still renders, none of them will ever refresh again.

In portable mode, `status` also answers `degraded` when the newest document mtime
is more than `config.DEFAULT_MAX_DB_AGE_HOURS` (24) hours old. Live reads instead
rederive changed project inputs; they do not depend on a scheduled export job.
Broken live targets and unreadable portable documents are reported explicitly.

`serve --regen` opens the same `regen` counters and writes the same
`event=regen` lifecycle lines `POST /api/regen` does, so one filter over that
field finds explicit refreshes whichever entry point started them.
The standalone `recoverage regen` command does not: it prints its outcome to a
terminal that exits, so there would be nothing left to read the counter back.

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
(the `--token` bearer check), `If-None-Match` (the conditional GET every
ETag-bearing endpoint above expects), `Idempotency-Key` (the regen retry) and
`X-Request-ID` (the correlation id described under *Observing a running server*
below, so a cross-origin client can send its own and match it to the server
log); a preflight naming any other request header is refused. `ETag`,
`Retry-After`, `Idempotent-Replay` and `X-Request-ID` are exposed as readable
response headers, so a cross-origin client can revalidate, honour a 429's wait,
tell a replayed regen from a fresh one, and quote the request id when it
reports a failure. Every 429 the server emits carries `Retry-After` alongside
the `retry_after` body key.

---

## Architecture & How it works

Recoverage consumes Rebrew's immutable coverage model. Normal project mode uses
`rebrew.coverage_project.load_project_coverage`, deriving functions, data, grid
cells and history directly from canonical project inputs. Both dashboards share
the same catalog and normalization rules. Input fingerprints invalidate cached
views; one failed target does not hide healthy siblings. Views never compile or
write project files.

Explicit portable mode reads `coverage-<target>.toml` from `RECOVERAGE_SNAPSHOTS`.
Only that mode uses the persisted TOML parse cache; it can serve offline without
a project workspace or compiler toolchain. Rebrew remains a library dependency.
The Bottle backend serves the Preact dashboard and API in both modes.

### Hosting it on a network

`recoverage serve` binds `127.0.0.1` and serves, unauthenticated, the project's
`src/` tree, its `original/` binaries, raw byte slices and disassembly. That is
fine on your own machine and is the reason the default is loopback. Serving it
beyond that needs both `--allow-remote` (the acknowledgement the CLI requires
for any non-loopback `--bind`) and `--token` (the bearer check every request
then has to pass); `--cors` is for a separate local frontend origin and is never
needed for the dashboard's own page. There is no TLS, so a token on a network
bind travels in cleartext. The full picture, including what the code does not
cover, is in [docs/THREAT_MODEL.md](https://github.com/maci0/recoverage/blob/main/docs/THREAT_MODEL.md).

### Mounting the app in your own WSGI server

`recoverage.webapp.app` is the fully wired Bottle application: importing it
mounts every route (`/api/*`, `/`, the static assets, `/potato`) on the shared
`app` object. A WSGI host can serve it directly.

```python
from recoverage.webapp import app  # a WSGI callable

# `recoverage.server.app` ALONE is routeless: it is the shared kernel the
# route modules mount on, so importing it registers no route and every path
# answers 404. Import `recoverage.webapp` (or run the CLI), never bare
# `recoverage.server`.
```

Two things the CLI does are yours to do when you mount the app yourself:

- **Request policy.** `recoverage.server.configure_security(...)` installs the
  bearer token, the CORS allowlist and the `Host` allowlist, which live in
  process-wide state read by every worker thread without a lock. Call it once
  before the host accepts requests; without it the app runs with no token, no
  CORS and no `Host` allowlist at all, which is the loopback posture and safe
  for nothing else. Pass the loopback allowlist for a local bind, and a token
  for a remote one, the way `serve` does for `--allow-remote`.
  `configure_startup(...)` publishes the settings `/api/health` reports;
  skip it and the health block's `config` reads `null` rather than a
  configuration that was never resolved.
- **Transport bounds.** The admission cap (`RECOVERAGE_MAX_CONNECTIONS`), the
  per-connection deadline (`RECOVERAGE_CLIENT_TIMEOUT`) and keep-alive framing
  live in the bundled listener (`recoverage.devserver`), not in the app, so a
  WSGI host enforces its own. `/api/events` holds one connection open per
  browser tab, so the host has to be threaded or asynchronous; a single-threaded
  server serves the dashboard and then hangs on the first tab that opens.

The API under `/api/*` is the same either way: see
[API Endpoints](#api-endpoints) for the routes, their query parameters and the
error envelope.

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
│   ├── ideas.md             # Future improvement ideas
│   ├── RECOVERY.md          # Backup/restore runbook: RPO/RTO and the restore drill
│   ├── mascot.jpg           # The raccoon detective the README shows
│   └── *.png                # Screenshots for the README
├── web/                     # Frontend sources built into the assets (Vite + Preact + Tailwind)
│   ├── app/                 # SPA components, hooks, grid geometry, tokens
│   ├── index.html           # The `vite dev` shell
│   ├── tsconfig.json        # Strict tsc settings, including the `@/` alias
│   ├── build.ts             # The second build: assets/highlight.js, out of the IIFE bundle
│   └── vite.config.ts       # The build that emits src/recoverage/assets/app.js and style.css
├── tools/                    # Lint and CI harness scripts
│   ├── lint_html.py          # Nu Html Checker over the static and served assets
│   ├── smoke.py              # End-to-end server smoke run
│   ├── _serve_harness.py     # Shared boot-and-probe harness for the two above
│   ├── ci_clone_rebrew.sh    # Optional guarded upstream source checkout
│   ├── normalize_sdist.py     # Pins the sdist's mtimes/order/header for a reproducible build
│   ├── flatten_rikalabs_strict.py  # Regenerates tools/oxlint/rikalabs-strict.json (MIT) from @rikalabs/oxlint-standards 0.8.1
│   ├── vendor_manifest.py    # Inventories the vendored anti-slop tree file by file
│   ├── payload_budget.py     # Re-derives the inlined shell size at each static encoding (make payload-budget)
│   ├── bundled_js_inventory.py  # The browser-bundle half of the SBOM, from bun.lock (make browser-sbom, make browser-sbom-spdx)
│   ├── license_inventory.py   # The license every resolved Python package is under, and the refusal (make license-inventory)
│   ├── check_wheel_assets.py  # Reads BUNDLE_ASSETS back off the built wheel
│   └── oxlint/               # Vendored anti-slop rules + the flattened strict preset
├── tests/
│   ├── conftest.py           # Shared fixtures (synthetic coverage TOML)
│   ├── coverage_fixture.py   # Builders for synthetic coverage documents
│   ├── test_api.py           # API validation & security tests
│   ├── test_backup.py        # Backup/restore: verification, all-or-nothing, the rollback refusal
│   ├── test_build.py         # Shipped files and reproducible build bytes
│   ├── test_cli.py           # CSV export, formatting tests
│   ├── test_concurrency.py   # Barrier-driven races: single flight, counters, the admission cap
│   ├── test_config.py        # RECOVERAGE_* parsing, precedence, fail-fast
│   ├── test_documents.py     # Per-document reload, the persisted parse, the cold herd
│   ├── test_import_graph.py  # The import rules the modules rely on
│   ├── test_lint_html.py     # The vnu gate's start-up failures (no jar, no JRE)
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
    ├── py.typed              # PEP 561 marker: the package ships its own annotations
    ├── _paths.py             # Live project or explicit portable snapshot resolution
    ├── clock.py              # The one time source the request path reads
    ├── config.py             # RECOVERAGE_* env: defaults, validation, startup banner
    ├── documents.py          # Coverage documents read per file; the TOML parse persisted
    │                         #   under $XDG_CACHE_HOME/recoverage/documents/
    ├── backup.py             # Verified backup/restore of explicit portable snapshots
    ├── metrics.py            # In-process RED counters, read by /api/health
    ├── devserver.py          # WSGI serving stack: threading server + its IPv6 class, keep-alive
    │                         #   handlers
    ├── cli.py                # Typer CLI entry point
    ├── server.py             # Bottle app, shared helpers & compression
    ├── disasm.py             # Capstone disassembly (optional extra)
    ├── regen.py              # Read-only live project refresh
    ├── api.py                # REST API routes (/api/*)
    ├── ui.py                 # UI routes (/, static files)
    ├── potato.py             # Potato Mode renderer + the /potato route
    ├── webapp.py             # Composition root: imports api+ui+potato so app has every route
    └── assets/                # Built bundle + the static files the server serves
        ├── index.html        # SPA shell (the bundle is inlined into it)
        ├── app.js            # Built dashboard bundle (Preact + Tailwind)
        ├── highlight.js      # The standalone highlighter, a SECOND build (web/build.ts)
        ├── style.css         # Built Tailwind output
        ├── print.css         # Print stylesheet
        ├── favicon.svg       # Retro "R" logo favicon
        ├── archivo.woff2     # Brand sans face (OFL, credited in NOTICE)
        └── jetbrains-mono.woff2  # Terminal face for the hex and asm panes
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
| `web-lint` | ubuntu, Python 3.13, bun 1.4.3, temurin 27 | oxlint (Rika-Labs strict + anti-slop) over the SPA sources, the Nu Html Checker over every static and served HTML/CSS asset, then `tsc --noEmit` over the strict `web/tsconfig.json` |
| `test` | ubuntu 3.13 + 3.14, macos 3.13, windows 3.13 | `pytest tests/`, warnings-as-errors. Browser tests (`tests/test_playwright.py`) stay out of the default run and are not run in CI |
| `build` | ubuntu, Python 3.13 | `make build` twice, the second time from a copy of the tree under a different path, locale and timezone, and fails when the two archives differ. Uploads the wheel and sdist |
| `smoke` | ubuntu, Python 3.13 | boots `recoverage serve` against synthetic coverage documents and probes the SPA shell, health, target data/stats/functions and Potato Mode, then repeats with a corrupt document to prove it reports `degraded` instead of healthy |
| `sbom` | ubuntu | Three build artifacts: `make python-sbom` (`uv export --locked --all-extras --hashes`) for the exact resolved Python tree behind a given build plus the Rebrew public artifact’s source tag and commit, and `make browser-sbom` for the npm packages `make web-build` compiles into the shipped browser assets, each with the version and tarball digest `bun.lock` pinned, plus the same browser half as an SPDX 2.3 document (`recoverage-browser-spdx`) a vulnerability scanner ingests, which carries the resolved versions, the digests and the grants `NOTICE` credits. The `lint` job runs `make license-inventory`, which reads the licenses off the resolved tree's own metadata and refuses anything that is not permissive |

Every job but `sbom` installs with `uv sync --locked --extra dev` and then runs
tools through `uv run --locked`. `--locked` never rewrites `uv.lock` and also
refuses to install one that no longer matches `pyproject.toml`, so a dependency
edit that skipped `uv lock` fails the run instead of testing a tree the manifest
does not describe. `sbom` skips installation and exports the validated lock
with `uv export --locked`. Its browser half needs no environment at all: the wheel ships
`src/recoverage/assets/`, which is compiled from six npm devDependencies, and
`uv.lock` cannot see them. Playwright and the
`capstone`/`pygments` extras are never installed, so the
matrix is the same set on every runner.

### The sibling rebrew checkout

A sibling checkout is optional for upstream development. Normal installs and
CI use the public hash-pinned wheel. `tools/ci_clone_rebrew.sh`, wrapped by
`make clone-rebrew`, verifies its source tag/full commit and refuses to overwrite
uncommitted work. See [the contributor setup](https://github.com/maci0/recoverage/blob/main/CONTRIBUTING.md) for explicitly
installing an editable checkout and keeping that development session unsynced.

---

## Third-party code in the distribution

The dashboard ships no vendored blob under `src/recoverage/assets/`: the
`app.js` and `style.css` it serves are built by `make web-build` from the npm
dependencies declared in `package.json`, so what the build folds into those two
files is distributed with the wheel whether or not anyone records where it came
from. The grants ship in [`NOTICE`](https://github.com/maci0/recoverage/blob/main/NOTICE), which `license-files` puts in the
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
| `tools/oxlint/anti-slop.manifest.json` | Generated by `tools/vendor_manifest.py` (`make vendor-manifest`): the upstream, the license, every vendored file with its sha256, and the paths left out | first-party record of the row above |

The anti-slop copy is the one checked-in dependency no registry manifest
covers, so its own record is `anti-slop.manifest.json`: a re-vendor or a
local edit that skipped it fails the suite instead of landing. The upstream
rule tests are deliberately not copied (they import `oxlint/plugins-dev`, a
subpath no declared dependency provides, and nothing here runs TypeScript
tests); the manifest names them as excluded. To re-vendor, replace the
directory from upstream, run `make vendor-manifest`, then
`make web-lint` to confirm the rule set still passes.

---

## License

MIT

The wheel also bundles the third-party code listed above. Their grants ship
as [`NOTICE`](https://github.com/maci0/recoverage/blob/main/NOTICE), which `license-files` puts in the distribution metadata
next to the MIT license.
