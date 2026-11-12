# recoverage reference

The CLI, its configuration and the HTTP API in detail. Installation and a first
run are in the [README](../README.md); `man recoverage` carries the same CLI
surface for an installed copy.

## CLI Commands

The examples below write `recoverage` bare. Prefix it with `uv run` when you
have no activated environment, or activate the one `make setup` synced so the
entry point is on `PATH`.

The wheel installs a man page with the entry point, at
`<prefix>/share/man/man1/recoverage.1`. A system or user prefix puts that on
the man path, so an installed copy answers `man recoverage`; a virtualenv
prefix does not, and `MANPATH` has to name that directory for `man` to find the
page there.

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `-h`, `--help` | | Show the help and exit; accepted on the command group and on every subcommand |
| `-V`, `--version` | | Print the version and exit |
| `-o`, `--output` | `auto` | Output mode before the subcommand: `auto`, `text` or `json`. `auto` stays text, including when stdout is not a terminal; `-o text` wins over `--json` |
| `--json` | off | Before the subcommand: the same as `-o json` |
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
| `--allow-remote` / `--no-allow-remote` | off | Required with a non-loopback `--bind`: acknowledge the API is reachable on the network; a remote bind also requires `--token` |
| `--token` | off | Require this token for every request (`Authorization: Bearer`, `?token=`, or open `/?token=<token>` or `/potato?token=<token>` to set the browser cookie) |
| `--no-open` | off | Don't auto-open the browser |
| `--regen` | off | Refresh the live project view before starting |
| `--cors` / `--no-cors` | off | Enable CORS processing (allowlisted origins only; the wildcard is never emitted) |
| `--cors-origin` | none | Origin URL allowed to read the API cross-origin (repeatable; without it `--cors` allows no cross-origin reads) |
| `--log-level` | `INFO` | Log threshold: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive) |

#### Environment

Every flag above except `--no-open` and `--regen` also reads a `RECOVERAGE_*`
variable as its default; a flag on the command line always wins. The variables,
their defaults and what each accepts are in the README's
[configuration table](../README.md#configuration).

Portable-mode parsed coverage documents persist under `$XDG_CACHE_HOME/recoverage/documents/`
(`~/.cache/recoverage/documents/` when it is unset or relative; on Windows
`%LOCALAPPDATA%\recoverage\documents\`), one file per document, so a restart
skips the TOML parse for every document whose bytes have not changed. It keeps
the 64 most recently used documents, and deleting the directory is always safe.
Live project reads bypass this persisted parse cache.

```bash
# A service serving portable exports on a LAN interface,
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

`RECOVERAGE_SNAPSHOTS` is read through `Path.expanduser()`, so a leading `~` and the
`USERPROFILE` it resolves against on Windows work as they do on POSIX.

`RECOVERAGE_ALLOW_REMOTE` is still yours to set: a non-loopback bind without
it, or without a token, exits 1, whether the address came from the flag or
the environment. Set
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
`RECOVERAGE_SNAPSHOTS` that is a file rather than the portable snapshot directory, or a
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
ends: a non-loopback bind without `RECOVERAGE_ALLOW_REMOTE` or without
`RECOVERAGE_TOKEN` exits 1, the CORS
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
source=live project
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

With `--json` (or `-o json`), a failure is one JSON line on stderr,
`{"error": {"kind": "...", "message": "...", "hint": "..."}}`, and stdout stays
empty. `check --json` and `export --format json` report the same envelope.

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
unavailable selected target, 2 = an invalid flag or `RECOVERAGE_*` value. Under
`--format json` a failure is the stderr envelope `stats --json` writes. `--json`
with a `--format` that is not `json` is a usage error (exit 2), not a silent
winner.

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
document, or a coverage source holding no `coverage-*.toml`.

### `recoverage regen`

Refresh the live project view immediately without writing coverage files:

```bash
recoverage regen
```

Progress and errors go to stderr; stdout stays empty. `serve --regen` uses the
same operation. Normal reads also detect input changes automatically. Portable
snapshots are read-only, so unset `RECOVERAGE_SNAPSHOTS` to refresh a project.
Status transitions are canonical metadata; refresh does not create history from
what the dashboard happened to observe. The API retains its in-process admission
and idempotency rules; the run also takes a cross-process lock
(``.recoverage-regen.lock`` beside ``rebrew-project.toml``), so a second
process converges to a refusal instead of interleaving. The only file
written is that lock file.

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
portable snapshot directory, never inside it, because the next run would copy the
previous archive as if it were a document. Exits 1 when there is nothing to
back up: an empty archive verifies, and restoring one empties the dashboard,
so a failed build must read as an alert rather than as a green run.

### `recoverage restore`

Put a verified backup's documents into the explicitly selected offline directory.

```bash
recoverage restore /srv/backups/nightly.tar
recoverage restore /srv/backups/nightly.tar --force
```

The archive is verified in full (every member read, its size and digest
checked) before the first document is written, and each document then lands
through an atomic replace. A restore therefore either completes or leaves the
portable snapshot directory exactly as it was; half a restore is a dashboard that reads
healthy and shows half a project.

`--force` replaces differing selected offline snapshots; the refusal names every
document it would overwrite. Canonical live verdicts and `status_history` stay
unchanged. A corrupt archive, a member that is not a coverage document, a
member name that would escape the directory and an unreadable file are refused
either way.

Offline readers detect restored bytes automatically; `regen` is a live-project
operation. The full procedure is in [the recovery runbook](RECOVERY.md).

### `recoverage verify`

Check every member of a backup archive against its manifest without restoring
it — the standalone proof a scheduled job or a drill runs against an archive
older runs wrote or that was copied elsewhere. Exits 1 naming the member whose
size or digest disagrees; writes nothing and needs no `RECOVERAGE_SNAPSHOTS`.

```bash
recoverage verify /srv/backups/nightly.tar
recoverage verify /srv/backups/nightly.tar --json
```

### `recoverage verify-backups`

Verify every stamped archive in a backup directory, not only the newest.
`check-backup` reads back only the newest archive, so a corrupt older
archive — the one a logical-corruption restore would reach for — stays
invisible until that restore. Exits 1 naming the first archive that fails;
exits 0 only when every stamped archive in the directory is one a restore
could load. Writes nothing and needs no `RECOVERAGE_SNAPSHOTS`.

```bash
recoverage verify-backups /srv/backups
recoverage verify-backups /srv/backups --json
```

### `recoverage check-backup`

Refuse when a backup directory has no fresh stamped backup. Exits 1 when
the newest stamped archive is older than `--max-age-hours` (default 25),
when the directory holds none, or when it does not exist, naming the
directory and the age so a cron alert says where the backup was expected.
It also verifies the newest archive before reporting fresh; writes nothing
and needs no `RECOVERAGE_SNAPSHOTS`.

```bash
recoverage check-backup /srv/backups
recoverage check-backup /srv/backups --max-age-hours 25 --json
```

### `recoverage restore-drill`

Prove a backup archive restores, into a fresh drill directory, serving
nothing live. The archive is verified in full, restored into the empty
`--into` directory, and the restored set is read back through the coverage
loader the dashboard serves, so a restore landing bytes the reader refuses
is a drill failure. Refuses a drill directory that already holds files, and
neither reads nor requires `RECOVERAGE_SNAPSHOTS` — the drill target is
`--into`, so it cannot point at the live directory by mistake. Exits 1
naming the archive or directory on a corrupt archive, a dirty drill
directory, or a restored set no reader can serve.

```bash
recoverage restore-drill /srv/backups/nightly.tar --into /tmp/drill/snapshots
recoverage restore-drill /srv/backups/nightly.tar --into /tmp/drill/snapshots --json
```

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

### `recoverage schema`

Print the clispec 0.3 JSON document that describes this CLI. It reads no
project, no token and no network, and it prints JSON even under `-o text`.

```bash
recoverage schema                   # every command
recoverage schema serve             # only the serve command
```

A command path that matches no command exits 2.

### `recoverage ops call`

Answer one of the relumea backend's coverage ops: the JSON request on stdin,
the JSON reply on stdout. This is the transport the backend's dispatch worker
uses; a person running the CLI wants `check` or `export` instead.

```bash
recoverage ops call recoverage.coverage_gate < gate.json
recoverage ops call recoverage.coverage_export < export.json
```

The worker answers `recoverage.coverage_plan`, `coverage_map`, `coverage_gate`,
and `coverage_export`. The plan op requires retained inputs and returns the
sorted staged readset with path, presence, digest and size, plus effective target
config and the Rebrew-discovered source and header paths. The backend must
verify custody for each planned input before using the readset.
`recoverage.coverage_map` returns the target section and cell map.
`recoverage.coverage_gate` takes `project_dir`,
`sha256`, `min_coverage`, an optional `section` and `metric` (`identified`, the
default, or `verified`), and replies with the
document `check --json` prints plus a `reason` when nothing was checked.
`recoverage.coverage_export` takes `project_dir`, `sha256` and `format` (`json`,
`csv`, `md` or `decomp.dev`), and replies with `format`, `content_type` and the rendered
`body`. Both name a target by the SHA-256 of its binary, resolved through
rebrew's project config rather than by `--target` name.

For retained inputs, each request also supplies `rebrew_target`, `files` (objects
with `path`, `digest`, `size`, and exactly one of `key` or `url`), and exactly
one of `binary_key` or `binary_url`. The worker verifies and stages these
objects privately and checks them again after the operation. Set `--workspace`
and, for object keys, `--filestore` (or `RECOVERAGE_OPS_FILESTORE`). Snapshot
requests use the Rebrew dependency pinned in `pyproject.toml`, which carries
`retained_target_snapshot` and `coverage_input_contract`.
The backend must verify the published source, analysis capture and current
verification records, then pass `coverage_input`, `coverage_input_digest` and
`verification_records` for retained scoring. The worker checks the readset and
evidence digests before and after scoring. Missing or partial envelopes are
refused. Retained scoring is not yet fully qualified for relocation matches, all include
assets or portable raw-link inputs. Identified coverage counts all tracked
cells; verified coverage counts only authenticated exact-match bytes. Retained
map and exports label `coverage_metric` as `identified` and expose
`verified_bytes` and `verified_pct` separately from the unchanged identified
fields. The verified gate requires retained evidence and
a positive threshold fails when verified bytes are zero. Requests without
snapshot fields read the live project through `project_dir` as before.

`recoverage ops serve --port N --workspace DIR [--filestore DIR]` answers the same
ops over HTTP: `POST /<op>` with `Content-Type: application/json` and
`Authorization: Bearer $RECOVERAGE_OPS_TOKEN` (at least 32 bytes; it is read only
from the environment). It is rebrew's ops server serving recoverage's `dispatch`,
so `--allowed-hosts`, `--concurrency` (default 2; the next call is refused 503
with `Retry-After`) and `/health` behave as in `rebrew ops serve`. Replies and
refusals are the ones `ops call` prints, with the refusal status as the HTTP
status. A retained request does not read its `project_dir` (it need not exist);
the worker writes its private snapshots under the workspace.

With `--otlp-endpoint URL` (or `RECOVERAGE_OTLP_ENDPOINT`, an `http(s)` URL without
credentials; empty leaves export off) each `POST` exports one OTLP/HTTP server
span to `URL/v1/traces`, resource `service.name=relumea-recoverage`, continuing
the caller's `traceparent`. The span is named `POST /<op>` for a recoverage op
and `POST /unknown` for anything else (a refusal before dispatch, an unknown
op), with `http.request.method`, `http.route` and `http.response.status_code`;
a 5xx marks it failed. A full export queue drops spans and a request never
waits for the collector. The cluster collector derives the RED metrics from
these spans. An invalid endpoint stops `serve` before it binds.

A request is refused, with a JSON `{"error", "code", "detail", "status"}` on stdout and
exit 2, when it is not JSON, names an unknown field, misses a required one, or
names an op that does not exist. The `code` is the machine-readable key
(`invalid_request`, `engine_error`, `target_unavailable`, or the refusal code
the engine attached), matching the HTTP envelope shape. `--workspace` (or `RECOVERAGE_OPS_WORKSPACE`)
confines every `project_dir` to that directory; without it the worker trusts
any absolute path. Nothing is written to stderr except a log line for a failure
the worker could not classify.

---

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Main SPA dashboard |
| `/index.html` | GET | The same document, for a URL that names it |
| `/files/<target>/source/<filepath:path>` | GET | A file under the selected target's configured, project-contained source root |
| `/files/<target>/binary` | GET | The selected target's configured, project-contained binary |
| `/src/<filepath:path>` | GET | A file under the project's fixed `src/` tree |
| `/original/<filepath:path>` | GET | A file under the project's fixed `original/` tree |
| `/app.js`, `/style.css`, `/print.css`, `/favicon.svg`, `/highlight.js`, `/archivo.woff2`, `/jetbrains-mono.woff2` | GET | The packaged static assets (`no-cache` with a strong `ETag`). `/highlight.js` is the standalone highlighter the code panes load on demand; it is emitted as a second bundle beside `app.js` because the dashboard bundle is an IIFE and cannot code-split |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, the settings this process resolved, coverage-source info (`db.unreadable` names failed live targets or unreadable portable documents, and any one degrades the status), installed extras, request/regen/stream/connection counters, cache hit-miss |
| `/api/targets` | GET | List configured/readable targets, plus failed live targets or unreadable portable documents under `unreadable` (`file`, `target`, `error`; no absolute paths). Revalidates: an `ETag` over the coverage snapshot and the project config's stat, so a repeat is a 304 |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats with percentages (no query parameters) |
| `/api/targets/<target>/data` | GET | Section + cell data (`?section=.text` for partial, `?index=0` to omit the search index) |
| `/api/targets/<target>/functions` | GET | Paginated list (`?status=&search=&sort=&limit=&offset=`; a `status` outside rebrew's vocabulary, or a `sort` column the list does not carry, is a 400). Revalidates: an `ETag` over the snapshot and every parameter, so a repeat is a 304 |
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order; any other top-level key is a 400 |
| `/api/targets/<target>/functions/<va>` | GET | Single function/global detail. Revalidates like the list: the tag names the snapshot, the target and the requested spelling |
| `/api/targets/<target>/asm` | GET | Disassembly (`?format=json` for structured output) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice (`?offset=&size=`) |
| `/api/events` | GET | Server-Sent Events: `db-updated` when the live view or selected portable exports change (SPA auto-refresh) |
| `/api/regen` | POST | Refresh the live project view (loopback peer and, when present, same-origin only; rate-limited; optional `Idempotency-Key` header) |

A refresh derives an in-memory view from the current project inputs. Send an `Idempotency-Key` header with the
request and a repeat of that key is answered with the recorded result
(`Idempotent-Replay: true`) instead of running the pipeline again; a repeat that
lands while the first run is still going is answered `202` with
`{"ok": true, "in_progress": true}` (`Idempotent-Replay: in-progress`), since
a regen runs for minutes and a proxy gives up long before it finishes. A key is
recorded the moment the pipeline completes, not when the answer is sent, so a
retry still replays after a connection that died on the way back. Keys are
remembered for 10 minutes (the ledger holds more slots than the rate limit
admits in that window, so a key is only ever dropped by its own age), and a
failed or interrupted run is not remembered: retrying a failure retries for
real.

Admission and idempotency are local to this process. The run itself takes the
cross-process regen lock (``regen.run_regen``), so independent processes
serialize on that lock rather than interleaving.

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
| `/api/targets/<target>/asm` | `va` | required | hex with or without `0x`, or a decimal address | unparseable (400) or outside the section (422) |
| `/api/targets/<target>/asm` | `size` | required | 1..4096, decimal or `0x`-prefixed hex | zero, negative or unparseable |
| `/api/targets/<target>/asm` | `section` | `.text` | one section name | an unknown name is a 404 |
| `/api/targets/<target>/asm` | `format` | `text` | `text`, `json` | any other value |
| `/api/targets/<target>/sections/<section>/bytes` | `offset` | `0` | decimal or `0x`-prefixed hex | negative or unparseable (400); past the section end (422) |
| `/api/targets/<target>/sections/<section>/bytes` | `size` | `256` | 1..4096, decimal or `0x`-prefixed hex | zero, negative or unparseable (400); slice past the section end (422) |

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

`regen` measures explicit refresh: its duration, completion and
failures are separate from ordinary request counts. Changed-input reads may also
perform analysis without a POST refresh.
`rejected` counts POSTs the cooldown or the run lock refused, which is a
double-clicked Regenerate button rather than a broken pipeline, so it is kept off
`failures`. `streams` reports live-reload saturation: each connected SSE
stream pins a server thread for its whole life, so `clients` against
`max_clients` is the distance to the 503 the next tab gets.
`serve` starts the poller thread at startup. While no `/api/events` client is
connected, that thread does not wait on the poll interval; the first subscriber
wakes it, and a connected client keeps the interval. An interval already in
progress ends when the last client disconnects. `watcher_alive` is `null`
only in a process that never ran `serve`. A connected client with a dead poller
answers `degraded`: every page still renders, none of them will ever refresh
again.

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
back to `no-store` when the coverage source cannot be read, since there is
then nothing to revalidate against.

Query-parameter rules, the same on every endpoint:

- `/asm` requires `va` and `size`, and accepts `format=text` (default) or
  `format=json`. An unrecognized `format` is a 400, not a silent fall back to
  text. `size` is a byte count, decimal or 0x-prefixed, clamped to 4096.
- `/sections/<section>/bytes` takes `offset` (default 0) and `size` (default
  256, clamped to 4096); both are decimal unless 0x-prefixed. A slice that
  would run past the section end is a 422 naming the section's size.
- Both of those read the original binary, and a target whose binary is
  missing or has no `[targets.<id>].binary` in `rebrew-project.toml` is a 404
  (`DLL not found`, detail naming the key to add) whichever `format` you ask
  for. A 422 means the binary loaded and the requested window ran past its
  end, or the section has no file backing to slice.
- `/functions` (list) takes `limit` (1..500, default 50) and `offset`
  (0..10000000, default 0). A numeric value outside its range is clamped, an
  unparseable one falls back to the default, and the response echoes the
  `limit` and `offset` actually used.
- `/functions` (POST) takes `{"vas": [...]}`, at most 500 entries, each a hex
  string (with or without `0x`) or an integer. Only a single `chunked` transfer coding is supported, matched case-insensitively; unsupported or malformed `Transfer-Encoding` headers are refused with 400 and `Connection: close` before reading the body. A body shorter than its declared `Content-Length` is refused with 400 and
  `Connection: close`, even when the received prefix is valid JSON. The body must be under 64 KiB
  (413), the list at most 500 entries (413) and non-empty (400). VAs with no
  match are omitted from the
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

## Hosting it on a network

`recoverage serve` binds `127.0.0.1` and serves, unauthenticated, the project's
configured source and binary files, its `src/` and `original/` trees, raw byte
slices and disassembly. Serving it beyond loopback needs both `--allow-remote`
(the acknowledgement the CLI requires for any non-loopback `--bind`) and
`--token` (the bearer check every request then has to pass); `--cors` is for a
separate local frontend origin and is never needed for the dashboard's own page.
There is no TLS, so a token on a network bind travels
in cleartext. [SECURITY.md](../SECURITY.md#deployment-assumption) states the
deployment assumption and [THREAT_MODEL.md](THREAT_MODEL.md) what the code does
not cover.

## Mounting the app in your own WSGI server

`recoverage.webapp.app` is the fully wired Bottle application: importing it
mounts every route (`/api/*`, `/`, the static assets, `/potato`) on the shared
`app` object. A WSGI host can serve it directly.

```python
from recoverage.server import LOOPBACK_HOSTS, configure_security
from recoverage.webapp import app  # a WSGI callable

# `recoverage.server.app` ALONE is routeless: it is the shared kernel the
# route modules mount on, so importing it registers no route and every path
# answers 404. Import `recoverage.webapp` (or run the CLI), never bare
# `recoverage.server`.

# The two calls below are the CLI's own startup wiring, and they are the
# minimum a mount needs: without `configure_security` the app runs with no
# token, no CORS and no `Host` allowlist (the loopback posture, see below).
# `configure_security` is fail-fast: it raises `config.ConfigError` on a
# token no client could present or an origin no browser could send, the
# same floor `serve` applies to its flags.
configure_security(allowed_hosts=set(LOOPBACK_HOSTS))
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
