# Upgrading recoverage

recoverage follows [Semantic Versioning](https://semver.org/): the HTTP API,
the CLI and the coverage document it reads are frozen from 1.0.0, so a
breaking change takes a major version. This file is the operator's view of
those changes: what was true before, what is true now, and what to change
because of it. The [changelog](../CHANGELOG.md) is the full record, one entry
per change, including the fixes and additions that need nothing of a reader.

Which versions still get fixes is [SECURITY.md](../SECURITY.md)'s answer, not
this file's.

A section below exists for every release whose changelog entry is under
`### Breaking`, plus the pending one. If a major ships with a breaking change
and no section here, `tests/test_release.py` (`TestUpgradeGuideCoversEveryMajor`)
fails: the gap is a release-blocking gap, not a documentation nicety.

## Before upgrading

Run the preflight. It resolves the same environment `serve` resolves, without
binding a listener, and ends the way `serve` ends: exit 2 for a value outside a
documented range or a validation refusal (a `RECOVERAGE_CLIENT_TIMEOUT` under
16, a malformed `RECOVERAGE_TOKEN`, an origin no browser could send), exit 1
for a non-loopback bind with no `RECOVERAGE_ALLOW_REMOTE` acknowledgment, and
warnings on stderr for the rest.

```bash
recoverage config
recoverage config --json   # the same object, for a script to diff
```

So a deployment that upgrades onto a raised floor finds out here rather than at
the next restart.

## [Unreleased]

Three changes break a consumer, and one changes a field's presence on the wire
without changing what the dashboard does with it; everything else in this
release of the changelog is additive or a fix.

### rebrew 2.23.0 is the floor, and its coverage commands live under `coverage`

Before: recoverage ran against rebrew 2.16.0 or later, and its hints named
`rebrew build-db`.

After: it needs rebrew 2.23.0. The function-detail panels read a row's note
and blocker from `rebrew-functions.toml` through an API 2.22.0 added, and
every rebuild hint names `rebrew coverage build`, the command that replaced
`rebrew build-db` in 2.22.0.

Do: update the sibling rebrew checkout (`make clone-rebrew`). Change scripts
that run `rebrew build-db` to `rebrew coverage build`, and `rebrew catalog`
to `rebrew coverage catalog`. `recoverage regen` and `POST /api/regen` call
rebrew's generator in process and need no change. Existing coverage documents
need no migration, and recoverage's CLI and dashboard URLs stay the same.

### `/data`'s `search_index` omits a redundant `symbol`

`GET /api/targets/<target>/data` answers a `search_index` object mapping a name
to `{ "va": ..., "symbol": ... }`. An entry now omits `symbol` when it is a copy
of the name it is keyed on, which is every function whose symbol IS its name
(what rebrew stores for a C symbol) and every global, whose `symbol` was the
empty string.

Before:

```json
"search_index": {
  "_ZN3Foo3barEv": { "va": "0x10001000", "symbol": "_ZN3Foo3barEv" },
  "g_counter":     { "va": "0x10002000", "symbol": "" }
}
```

After:

```json
"search_index": {
  "_ZN3Foo3barEv": { "va": "0x10001000" },
  "g_counter":     { "va": "0x10002000" }
}
```

What to change: read the field through its own fallback, `entry.symbol ?? ""` in
JavaScript and `entry.get("symbol")` in Python. A client that assumed the key
was present lost every search row on such a document; the shipped SPA already
read it that way and is unchanged.

This is a wire-shape change rather than a behaviour change, so it ships in a
minor: the dashboard folds the name and the symbol into one haystack and
labels a result row with the name, so a copy of the name matched nothing and
showed nothing. A demangled symbol, the case that carries what the name does
not, still travels. On a 40,000-function target of mangled C++ names the
response went 180,576 B to 149,921 B compressed; the index rides the first load
whether or not the search box is ever opened.

### `recoverage regen` exits 2, not 1, on an unreadable `rebrew-project.toml`

Before: a missing or unreadable project file was reported as
`Error: rebrew regen failed: ConfigNotFoundError: …` and exited 1 — the code
this package uses for a rebrew pipeline that ran and failed.

After: the same file exits 2, the code every other command uses for a setting
or a file the operator has to change, with the same one-line message `stats`,
`export` and `check` give and without rebrew's internal class name. Nothing was
rebuilt in either case (rebrew reads the file before any of its own work), so
this is a misconfiguration rather than a failed rebuild.

If a script retried `regen` on any non-zero exit, it now also retries a case
that cannot succeed until the file is fixed:

```bash
recoverage regen
case $? in
  0) ;;                        # documents written, or nothing to write
  2) echo "fix rebrew-project.toml, then retry"; exit 1 ;;
  *) echo "the rebuild failed; retrying is reasonable" ;;
esac
```

`POST /api/regen` is unchanged: it answered 500 for this case already, and a
client cannot tell it apart from a pipeline failure there. This change moves
the distinction to the CLI only.

### `recoverage open` writes its status line to stderr

Before: `Opening <url>` was the command's stdout, so a caller that captured it
got the URL, and an entrypoint that treated "stdout was non-empty" as "a tab
opened" was told the tab was open on a headless run that exits 1.

After: the line goes to stderr and stdout carries nothing. The URL is
unchanged and `open` still exits 0 when a browser was launched and 1 when none
could be.

If you read the URL from stdout, take it from the log line or from
`dashboard_url()`-shaped output instead:

```bash
# before
url=$(recoverage open | awk '{print $2}')
# after
url=$(recoverage open 2>&1 >/dev/null | awk '{print $2}')
```

Only `open` changed. `export` still writes its document to stdout, `regen`
still writes no data at all, and `stats --json` is unaffected.

## [4.0.0]

Seven changes break a consumer; everything else in this release of the
changelog is additive or a fix.

### The dashboard is a Preact bundle, not VanJS

Before: `app.js` and `detail.js`, with `van.min.js`, `hljs*.js` and
`hljs.css` fetched as separate assets, and static markup inside `/`.

After: one built bundle at `/app.js` and one compiled `/style.css`.
`/detail.js`, `/van.min.js`, `/hljs.min.js`, `/hljs-c.min.js`,
`/hljs-x86asm.min.js` and `/hljs.css` are not answered. Only `/app.js`,
`/style.css`, `/print.css` and `/favicon.svg` are served from the assets
directory.

Do: drop any proxy rule, cache key, CSP entry or bookmark that names one of the
removed URLs. A rule left in place answers 404 for every page load.

`/` now carries `<div id="root">` and no static markup, so anything that
scraped the served HTML for a value has to read `/api/targets` instead. The
inlined shell is about 46 KB brotli rather than about 14 KB, so the server's
own congestion-window ceiling (`ui._TCP_CWND_BUDGET`) rose to 90 KB; a proxy
with a small response header buffer may need the same.

### `?sort=` on `/api/targets/<target>/functions` is checked

Before: a column the list does not carry, or a direction other than `desc`,
answered `200` with a full page in the default `va` order and nothing in the
answer to say so. A client that had its own column list, or spelled the
direction its UI label showed, got data in an order it never asked for.

After: the parameter is validated like `?status=`, `?format=` and `?index=`.
An unknown column or a direction outside `:asc`/`:desc` is a `400` with
`{"code": "bad_request", "error": "invalid sort"}` and a `detail` naming every
accepted spelling. A bare column, an empty `?sort=` and an absent parameter are
still the default. Columns are matched case-sensitively; the direction is not.

Do: read the accepted columns from the 400's `detail`, or from the table in
the README, and spell the direction `:asc` or `:desc`. A client passing
`?sort=` through from a user-supplied field name has to check it first.

### `?index=` on `/api/targets/<target>/data` takes `0`, `1` or nothing

Before: `?index=false` and `?index=no` both read as "on", so a caller asking
for the omitted payload got the whole `search_index` back with nothing in the
answer saying so.

After: anything but `0`, `1` or an absent parameter is a `400` with
`{"code": "bad_request", "error": "invalid index"}`, the same status a bad
`?format=` or `?status=` gives. `?index=0` omits `search_index`; `?index=1` is
the old default.

Do: send `?index=1`, or drop the parameter. A client that sent `true` gets a
400 and no payload.

### The 503 for an unreadable `rebrew-project.toml` changed its `error` string

Before: `{"code": "db_unavailable", "error": "..."}` with a message that
differed from every other coverage-read 503.

After: `error` is the string `"Database unavailable"`, the one every other
coverage-read 503 already carried. `code` is still `db_unavailable`.

Do: nothing, if you match on `code`. A client matching the human-readable
`error` text has to compare the new string.

### Connections past 128 concurrent ones are refused

Before: every accepted connection had a socket deadline, which bounds how long
a handler thread lives but not how many exist. A server could be opened past
its own memory.

After: past `_MAX_CONNECTIONS` (128) a new connection is refused with a 503
and a log line naming the count. The connections already open keep serving.

Do: raise `RECOVERAGE_MAX_CONNECTIONS` (integer `1`-`65536`) if the
deployment really holds more than 128, and read `/api/health`'s `connections`
block (open, max, refused) to see whether it is happening. A server at the cap
answers `degraded` with the count.

## [3.0.0]

### The storage is rebrew's coverage TOML, not `db/coverage.db`

Before: the dashboard read a SQLite database at `db/coverage.db`, and
`RECOVERAGE_DB` named that file.

After: it reads `db/coverage-<target>.toml`, and `RECOVERAGE_DB` names the
*directory* holding those documents. Run `rebrew coverage build` to write them; the
catalog analysis runs inside that command, so there is no step before it. A
directory holding no `coverage-*.toml` is not an error: `serve` warns that the
dashboard will list no targets and every figure reads as a healthy zero, which
is the empty table set the SQLite reader answered from. The 503
`db_unavailable` is reserved for a document that exists and does not parse.

Do: run `rebrew coverage build` once after upgrading, then point `RECOVERAGE_DB` at
the directory. A value that exists and is not a directory used to resolve to a
path no `coverage-*.toml` glob could match, serving an empty target list that
reads as a healthy zero; the next major makes that a startup error instead.

Two served values change with the storage:
`/api/targets/<target>/data`'s `db_version` is the document's own format
version (`"1"`), and `known_schema` lists the format versions this build can
read (`["1"]`) instead of the old SQLite schema numbers. Every other route,
status code, field name and value is unchanged against the same project.

### rebrew 2.16.0 is a hard floor

recoverage reads and writes the documents through `rebrew.coverage_toml`, which
no earlier rebrew release ships, so an older rebrew can neither write a
document nor parse one. rebrew is resolved from a sibling checkout rather than
an index, so this is a checkout to update, not a version to pin.

## [2.0.0]

### `server.resolve_targets()` returns the list

Before: `resolve_targets(c: sqlite3.Cursor) -> tuple[list[str], list[dict[str,
str]]]`, a two-element tuple whose first element was raw database order and
whose second was config-declared first. Every in-tree caller discarded the
first, which is what left a second ordering alive for the SPA and Potato Mode
to agree not to use.

After: `resolve_targets() -> list[dict[str, str]]`, the ordered target list.
The cursor argument is gone with the database, so the function no longer
touches SQLite at all.

Do: drop both the argument and the unpacking. `target_ids, targets =
server.resolve_targets(c)` raises `ValueError: not enough values to unpack` at
call time and passing `c` raises `TypeError`;
`targets = server.resolve_targets()` is the whole change.

### `recoverage check --min-coverage` out of range exits 2

Before: a threshold outside 0-100 exited 1, the same code as a genuine
coverage failure, so a CI job could not tell a mistyped flag from a build that
dropped below the gate.

After: it exits 2, the usage-error code, and the `--json` error object reports
`"exit_code": 2` with it. A real coverage failure still exits 1.

Do: a CI job gating on exit 1 alone now also has to treat 2 as "the job is
misconfigured", which is what it already had to do for a non-numeric value.

### A CORS origin no browser could send is refused at startup

Before: `--cors-origin http://user@host.test` (or the same entry in
`RECOVERAGE_CORS_ORIGIN`) printed a warning and started with an allowlist one
entry short of what was written, so the server refused exactly the reads that
entry was there to allow.

After: it exits 2 with the offending origin named, for the flag and the
variable alike. An origin is checked only while CORS is on, which is the only
case where it would have been installed. A normalizable origin is still stored
normalized.

Do: an allowlist entry must be `scheme://host[:port]` and nothing else. Drop
userinfo, a path, a query and a trailing slash.

### `RECOVERAGE_CORS_ORIGIN` set to an empty value is a startup error

A unit file, a container environment and a CI job all spell "not configured"
as an empty value, and it used to start a server with CORS on and an allowlist
of nothing.

Do: unset the variable rather than setting it empty.
`RECOVERAGE_TOKEN` is the one deliberate exception: empty there means
authentication is off, and that is intended.
