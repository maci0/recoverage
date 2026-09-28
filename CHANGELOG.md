# Changelog

All notable user-visible changes to Recoverage are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- The dashboard's detail panel carries a `Copy SHA` control for the SHA256 the
  panel abbreviates to 16 characters. The abbreviated row is enough to
  recognise a digest beside another report, and there was no way to read or
  take the rest of it; the full digest is now also on the row's tooltip.
- The Data Inspector pane in the detail panel carries the same `Copy` and
  `Open` controls the three text panes carry. A data block's readings (the
  int/uint columns, the string prefix) were the one pane a reader could only
  read off the screen, and a copy now hands over one `label: value` per line.
- Every row of the search result list names the section its match is in, not
  only the rows already in the section on screen. A target-wide term matches
  `.text` and `.rdata` alike, and two rows in different sections read
  identically, with the pick switching tabs as a surprise. The section on
  screen is still the one marked in the accent, as "in <section>".
- The `sbom` job publishes the browser half of the dependency tree as an SPDX
  2.3 document (`recoverage-browser-spdx`) beside the text inventory. The
  Python half was already a hashed export a vulnerability scanner reads, and
  the browser half was a line per package, so the Preact and highlight.js that
  run compiled inside the wheel were described in a shape no tool ingests. The
  document names each shipped package's resolved version, its `bun.lock`
  tarball digest, and the license `NOTICE` credits. `make browser-sbom-spdx`
  prints it without CI.
- `GET /api/health` reports an `auth` block (`failures`, `throttled`,
  `locked_peers`) and a `requests.transport_rejected` counter. A peer working
  through the `--token` gate is answered 401 and then 429, neither of which is
  a 5xx, and a request the HTTP transport refused (an over-long request line, a
  malformed one, a client that stalled) never reaches a route at all: both were
  visible only as log lines, so nothing an operator polls said a
  network-reachable server was being scanned. `locked_peers` is a gauge that
  drops with the throttle window, so an active lockout reads `degraded` and
  recovers on its own rather than degrading every probe until a restart.
- The dashboard lists what a search matched, under the search box in address
  order, and a row jumps to that block. The count and Enter-to-the-first were
  the only answers, so a term matching hundreds of functions could be reached
  no other way than narrowing the spelling until one match survived. The list
  is capped at 20 and says how many it left out.
- `Escape` in the dashboard's search box clears the query, the list and the
  map's dimming, the way it does in a search box everywhere else.
- A failed read in the dashboard carries a Retry, and the map area shows the
  failure in place of the grid instead of a "Loading coverage data..." line
  that never resolved. The retry re-runs the read that failed; the only way
  back before was reloading the page, which threw away the target, the section
  and the search with it.
- The wheel and the sdist ship `recoverage/py.typed`, so a project that imports
  `recoverage.server`, `recoverage.config` or `recoverage.metrics` gets the
  annotations this package ships instead of having them dropped at the package
  boundary. Importing recoverage from a typed codebase previously checked
  nothing, because the installed package was unannotated as far as any type
  checker could tell.
- `recoverage export --json` is the shorthand for `--format json`, the
  spelling `stats`, `check` and `config` already take. Naming both, with a
  `--format` that is not `json`, is a usage error (exit 2) rather than a flag
  silently winning.
- `SIGTERM` stops the dashboard the way Ctrl+C does. `systemctl stop`,
  `docker stop` and a pod eviction all send it, and its default disposition
  killed the process where it stood: the accept loop never unwound, the
  deferred browser opener was not cancelled, and every request in flight was
  cut mid-body. A stop signal now takes the same path the keystroke takes and
  exits 0.
- `GET /api/health` reports `p50_ms` and `p95_ms` beside the existing
  `mean_ms` and `max_ms`, taken over the most recent 512 timed requests
  (`latency_window` says how many). A mean over a mostly-fast window and a
  worst-since-start maximum cannot tell one slow request from every request
  getting slower, which is the question an operator has while the dashboard
  is slow.
- `GET /api/health` carries a `caches` block: hits and misses for the `/data`
  payload memo, the `/stats` memo and the `If-None-Match` revalidation every
  cacheable endpoint answers. A dashboard whose response time grew used to
  look identical whether the coverage build got bigger or the cache stopped
  being consulted; the counters say which.
- A `/data` payload build whose leader thread is killed leaves a claim no
  waiter can wake on. The follower that times out on it already reclaimed the
  key and rebuilt; it now also logs one line naming the target and section
  whose build it took over, and `requests.stale_claims` in `/api/health`
  counts them, so a killed builder is not just a slow dashboard.
- Each release now ships a browser-bundle inventory alongside the Python one.
  The `sbom` job uploads `recoverage-browser-sbom`: the npm packages
  `make web-build` compiles into `src/recoverage/assets/` (preact, highlight.js,
  tailwindcss, clsx, tailwind-merge, class-variance-authority), each with the
  version and tarball digest `bun.lock` pinned. The wheel ships that directory,
  so the browser half of the dependency tree runs in a reader's browser with
  nothing on disk to identify it by, and the existing `recoverage-python-sbom`
  export reads `uv.lock`, which cannot see it. `make browser-sbom` prints the
  same inventory, and `NOTICE` names both artifacts.
- The wheel installs a man page (`<prefix>/share/man/man1/recoverage.1`) for
  the `recoverage` entry point, covering every subcommand, flag and
  `RECOVERAGE_*` setting `recoverage --help` lists, with the exit codes and the
  environment each flag defaults from. A system or user prefix puts that
  directory on the man path, so `man recoverage` works on such an installed
  copy; a virtualenv prefix does not, and a reader who installs into one finds
  the page at `$VIRTUAL_ENV/share/man/man1/recoverage.1` and can add that
  directory to `MANPATH`. An installed copy previously shipped the entry point
  and no documentation for it at all.
- The dashboard prints the target's coverage and the section on screen above
  the map: `82.4% covered, 1,234/1,500 functions matched` and the active
  section's per-state block counts with its own covered percentage. Potato Mode
  already showed both from the same numbers, so the two views of one target
  could not disagree about the map below them. Each state count is also the
  filter pill for that state, so "where are the stubs" is one click on the
  number that answers it.
- The server log's request and regen lines now carry their counters as named
  fields (`method`, `path`, `status`, `duration_ms`, `route` on a request;
  `event=regen`, `outcome`, `duration_s` on a rebuild), rendered as
  `key=JSON` pairs after the message. The prose is unchanged, so reading the
  terminal is unaffected, but a log aggregator can now filter on a status or
  an outcome and pivot from a `/api/health` anomaly to the requests behind it
  without a regular expression. Lines that carry no fields, including every
  record from bottle and rebrew, render exactly as before.
- `GET /api/health` carries a `connections` block (open, max, refused) for the
  connection cap, the same saturation reading `streams` already gave for the
  event-stream cap. A server at that cap answers 503 to every new request
  while the connections it already holds keep rendering, so health read
  `healthy` while refusing every new tab. A refused connection now also
  answers `degraded`, naming the count and the cap.
- `GET /api/health` carries a `config` block with the settings the running
  process resolved at startup, so a deployment can ask the server itself what it
  is running with. `recoverage config` re-resolves the environment of the shell
  that runs it, which is not the server's environment under a unit file or a
  container spec. The token is reported as `set`/`unset` as everywhere else,
  the coverage directory stays in the endpoint's own basename-only `db` block,
  and the block is `null` in a process that never ran `serve`.
- The dashboard toolbar carries an **HTML** link to Potato Mode carrying the
  current target, section, search and filters. Potato already linked back to the
  SPA; the SPA had no way out to it.

### Breaking

- **The dashboard frontend is a Preact + Tailwind bundle.** The VanJS SPA is
  gone: `app.js` and `detail.js` are replaced by one built bundle, `style.css`
  is compiled by Tailwind, and the vendored `van.min.js`, `hljs*.js` and
  `hljs.css` assets are no longer shipped. Anyone serving or caching those URLs
  by name has to update: only `/app.js`, `/style.css`, `/print.css` and
  `/favicon.svg` are still answered from the assets directory.
- **The inlined shell is ~50 KB brotli, not ~14 KB.** It cannot fit RFC 6928's
  initial congestion window, so `ui._TCP_CWND_BUDGET` is now a 90 KB ceiling
  with headroom over the measurement rather than the protocol constant. The
  shell still paints without a render-blocking subresource request, and
  highlight.js is inside the bundle instead of being fetched on first use.
- **`/` carries `<div id="root">` and no static markup.** The shell markup a
  scraper or a stylesheet hook matched before is gone with the script that built
  it.
- **`?index=` on `GET /api/targets/<target>/data` is `0`, `1` or absent, and
  anything else is a 400.** `?index=false` and `?index=no` used to read as
  "on", so a caller asking for the omitted payload got the whole `search_index`
  back with nothing in the answer saying so. They now get the same 400
  `?format=` and `?status=` already answer. Send `?index=1` for the old
  behavior, or drop the parameter.
- **`?sort=` on `GET /api/targets/<target>/functions` is checked.** A column
  the list does not carry, or a direction other than `:asc`/`:desc`, answered
  `200` with a full page in the default `va` order and nothing in the answer
  to say so, so a client that had its own column list, or spelled the direction
  its own UI label showed, silently got data in an order it never asked for. It
  is now a 400 with `{"code": "bad_request", "error": "invalid sort"}` and a
  `detail` naming every accepted spelling, the contract `?status=`, `?format=`
  and `?index=` already had. A bare column, an empty `?sort=` and an absent
  parameter are still the default.
- **The 503 an unreadable `rebrew-project.toml` answers now reads
  `error: "Database unavailable"`, the string every other coverage-read 503
  already carried.** Its `code` was `db_unavailable` and is unchanged, so a
  client matching on `code` is unaffected; one matching the human-readable
  `error` text has to compare the new string.
- **A server refuses connections past 128 concurrent ones with a 503 and a log
  line.** Every accepted connection already had a socket deadline, which bounds
  how long a handler thread lives but not how many exist. A deployment that
  held more than 128 (SSE clients, browser connections, a crawler) is now
  refused past the cap; `RECOVERAGE_MAX_CONNECTIONS` raises it, and
  `/api/health`'s `connections` block reports the reading.

### Changed

- `RECOVERAGE_CORS_ORIGIN` set to a value that names no origin, where before
  only an empty one was refused (`,` and `" , "` parsed to an empty list, since
  the empty items between separators are dropped), is a startup error like the
  empty value already was. A unit file, a container env or a CI job that spells
  "not configured" as an empty value started a server with CORS on and an
  allowlist of nothing, which refused every cross-origin read it was configured
  for. The two CORS startup warnings and the loopback-bind acknowledgment now
  name the `RECOVERAGE_*` spelling beside the flag, so an operator who
  configured through the environment is not sent to argv.
- `recoverage regen` writes nothing to stdout. Its progress line and its
  "Done — N coverage document(s) written to ..." completion line are status,
  and they now go to stderr with the errors that were already there, so a
  script reads the outcome from the exit code and `serve --regen` keeps the
  startup banner alone on stdout.
- The dashboard's rebuild button reads "Regenerate" rather than "Reload". It
  runs rebrew's catalog analysis for minutes, which is not what "Reload", the
  browser's own word for a page refresh, told a reader to expect. The empty
  states name the same button instead of telling the reader to reload the page
  by hand.
- Tapping a block in the dashboard on a narrow viewport brings the detail
  panel into view. The panel sits below the map there, and the map is as tall
  as the page, so the tap appeared to do nothing.
- The dashboard's detail panel names how to open a block (click one, or press
  Enter in the search box) instead of showing "(select a function)".
- The strict mypy gate now covers `tests/conftest.py` and
  `tests/coverage_fixture.py` beside `src/` and `tools/`. Those two are the
  slice every other test file is built on, and a checker that skipped them
  checked the tests against no contract at all.
- `GET /api/targets/<target>/functions/<va>` revalidates. It was the one
  DB-derived read served `no-store` with no validator, so a client watching a
  cell re-downloaded the whole row on every poll while `/stats`, `/data`, the
  function list, `/asm` and `/bytes` all answered 304. The tag covers the
  coverage snapshot, the target and the requested spelling, and the response
  body is unchanged.
- `serve` and `recoverage config` now warn when the coverage directory holds
  no `coverage-*.toml`, or does not exist. Both serve an empty target list,
  which reads as a healthy zero on every figure the dashboard shows; the
  likeliest cause is a service started from a directory that is not the project
  root, and the only clue used to be a map with nothing on it.
- A `RECOVERAGE_TOKEN` (or `--token`) carrying surrounding whitespace, an
  interior space or a control character is now a startup error, where it
  started a server that answered 401 to every reader. Request headers arrive
  trimmed and the gate compares the extracted credential byte for byte, so such
  a value is one no client can present, and the banner still read `token=set`.
  The message names the problem, never the value. An empty token is unchanged:
  it is the documented way to run unauthenticated.
- `RECOVERAGE_DB` naming something that exists and is not a directory is now a
  startup error, where it resolved to a path no `coverage-*.toml` glob can
  match and the dashboard served an empty target list, which reads as a healthy
  zero rather than as a wrong path. A path that does not exist is still
  allowed: a service may start before its first `rebrew build-db`.
- A request id the server mints for itself is now a per-process counter
  (`000000000001`, `000000000002`, ...) rather than 12 hex digits of OS
  entropy. The value is a correlation label on the log line, the
  `X-Request-ID` header and the RED counters, and nothing is authorized by it;
  the same sequence of requests now produces the same ids, so two runs of it
  can be compared field for field. An `X-Request-ID` the caller sends is
  still used, capped and escaped as before.
- `RECOVERAGE_CLIENT_TIMEOUT` now accepts `16` seconds and above, where it
  accepted `5`. A deadline at or under the 15 s SSE heartbeat closes healthy
  `/api/events` streams on the clock instead of on the peer going away, so the
  values in between were accepted configurations that cut live reload short.
  The default (120) is unchanged.
- `POST /api/regen` with an `Idempotency-Key` whose run is still going now
  answers `202` with `{"ok": true, "in_progress": true}` and
  `Idempotent-Replay: in-progress`, where it answered `429` before. A regen
  runs for minutes and a proxy gives up long before that, so the client's
  retry reaches the server while the first run still holds it: the 429 read as
  a failed regenerate, the Reload button said regeneration was unavailable,
  and the next click started a second full pipeline. The 202 says the work is
  under way, and the dashboard holds its in-progress line. A key that has
  completed still replays its recorded result, a run that failed is still
  retried for real, and a request carrying no key still re-runs.
- `GET /api/targets` revalidates instead of being re-downloaded. It is the one
  request the dashboard cannot avoid (the shell preloads it and the app fetches
  it with `cache: "no-cache"`), and it was served `Cache-Control: no-store`
  with no `ETag`, so a reloading browser had nothing to revalidate against and
  fetched the whole list again every load. It now carries a strong `ETag` over
  both inputs the list is built from (the coverage documents and the stat of
  `rebrew-project.toml`, so a target added to the config is visible before any
  build writes a document for it) and answers `304 Not Modified` when neither
  has moved. `max-age` stays at zero: the list changes under a running server.
- The dashboard shows a first frame before its bundle runs. The page was blank
  from the first byte until the inlined script had been parsed and run and the
  data behind `/api/targets` and `/data` had arrived, because `#root` was
  empty. The shell now ships a `Loading coverage…` status line inside it, which
  the app clears as it mounts.
- `GET /api/targets/<target>/functions` revalidates instead of answering
  `no-store`: the page is a pure function of the coverage snapshot and its
  query string, so it carries a hashed `ETag` and answers `304` on
  `If-None-Match`, the same contract `/stats`, `/data`, `/asm` and `/bytes`
  already had. Every parameter that shapes the page is in the validator, so a
  page the client does not hold can never be answered as the one it does.
- The `304` a revalidating API read answers now carries `Vary:
  Accept-Encoding`, the header its `200` already sent. Every one of those
  bodies is content-negotiated, and a shared cache keyed without it could hand
  a compressed body to a client that accepted none.
- Every command's `--help` names the value a flag takes (`--port PORT`,
  `--target TARGET`, `--min-coverage MIN_COVERAGE`, `--log-level LEVEL`,
  `--bind ADDRESS`, `--cors-origin ORIGIN`, `--token TOKEN`, `--section
  SECTION`) instead of the `<str>` a text option defaults to, and every
  command now states the exit codes it can end on. `check`, `open` and
  `config` documented theirs; `serve`, `stats`, `export` and `regen` did not,
  so the contract a script depends on was readable from three of seven
  commands.
- `lucide-react` is no longer a devDependency. Nothing imported it: the
  dashboard runs on preact/compat and draws no icon from the package, so the
  only thing it did was pull `react` into `bun.lock` for every contributor and
  CI runner. NOTICE and the README's bundled-library table drop it for the same
  reason, and `tests/test_supply_chain.py` now holds the npm half of the
  reachability rule the Python side already had: a devDependency that no source
  imports and no gate runs has to name the mechanism that still needs it.
- Batch VA lookups (`POST /api/targets/<target>/functions`) and the
  cell-detail panel's verify rows resolve through a per-snapshot index instead
  of scanning the globals and `verify_results` arrays per requested VA, and a
  search term is folded once per query rather than once per row and column.
  Answers are unchanged, including which global wins a repeated VA.
- The README no longer opens its install section with `pip install recoverage`.
  The wheel declares `rebrew>=2.16.0` as a runtime dependency and rebrew is
  resolved from a sibling checkout, so that command stops at resolution with an
  error naming a distribution rather than the checkout that fixes it. The
  section now leads with the bootstrap that works and says what the one-line
  install becomes.
- `make all` now also builds the distribution and checks the committed
  dashboard bundle against `web/`, so the two CI jobs it did not mirror
  (`build`) fail on a workstation instead of after a push. The new
  `make check-bundle-clean` is the check on its own: `make build` regenerates
  `src/recoverage/assets/app.js` and `style.css` before packaging, so a commit
  carrying a stale bundle still produced a good artifact and passed every other
  gate. The CI `build` job runs it too, because the two-build reproducibility
  comparison cannot tell a stale commit from a fresh one.
- `GET /api/targets/<target>/data` takes `?index=0`, which omits the
  target-wide `search_index` from the payload. The dashboard passes it on the
  section-switch request, which already holds the index, so a tab click stops
  re-sending a payload that grows with the target's function count. The key is
  part of the ETag inputs and the memo key, so the two shapes stay separate
  representations. A request without the parameter is unchanged.
- The dashboard starts `/api/targets/<target>/data` as soon as the page names a
  target in its URL, in parallel with `/api/targets` instead of behind it, so a
  reload or a shared link spends one round trip less before the map appears. A
  target the server no longer serves falls back the way it always did.
- An empty `vas` array on `POST /api/targets/<target>/functions` now carries
  the `detail` field every other API error does.
- The README documents every `/api/` query parameter (default, accepted range,
  what is rejected) and a real `/functions` response, and names the SSE
  connection-cap 503 as one of the errors carrying `retry_after`.
- The detail panel stacks under the map below 1024px instead of taking a fixed
  460px beside it, which squeezed the map to an unusable column on a phone.
- The Reload button reads "Regenerating..." while a regen is in flight, and the
  code viewer's Copy button reports "Copied!" or "Failed" like every other Copy
  button. It was the one copy control that gave no sign of having run.
- The Potato Mode function list says "first N of M results" and names the cap
  when the list is truncated. It read the capped row count as the total, so a
  truncated page looked complete.
- The "database unavailable" page and the 503 `detail` string tell the reader to
  run `rebrew build-db`, which runs the catalog itself, rather than a
  two-command sequence with no first step to run.
- The dashboard is built from `web/` with Vite, Preact (through
  `preact/compat`), TypeScript, Tailwind CSS 4 and shadcn/ui primitives, all
  themed from the same token layer the VanJS stylesheet carried. `make web-build` produces
  `src/recoverage/assets/app.js` and `style.css`; `make build` runs it first,
  and the CI build job rebuilds in both trees to prove the committed bundle
  matches its sources.
- Syntax highlighting is compiled in from the `highlight.js` npm package (core
  plus the `c` and `x86asm` grammars and the dashboard's own `hex` language)
  instead of being fetched as three separate scripts, so the pane no longer
  has a state where it renders unhighlighted.
- `NOTICE` credits the libraries compiled into the bundle.
- `RECOVERAGE_MAX_CONNECTIONS` and `RECOVERAGE_CLIENT_TIMEOUT` make the two
  serving limits a deployment chooses instead of a constant in the source. The
  cap is an integer `1`-`65536` defaulting to `128`, the cap this release
  introduces; the deadline is an integer `16`-`86400` seconds defaulting to
  `120`, a per-socket-operation bound rather than a lifetime any live stream
  has to clear. Both resolve at startup like every other `RECOVERAGE_*`
  setting, so a value outside the range is the exit 2 a deployment finds at
  boot rather than a refused connection later. `recoverage config` prints the
  resolved pair.
- `/src/<file>` and `/original/<file>` negotiate their encoding like every other
  body in the package. A text file over 1 KB answers brotli, zstd or gzip
  according to the request's `Accept-Encoding`, carries a strong `ETag` hashed
  from the file's bytes and its accepted-encoding key, and
  `Cache-Control: no-cache, must-revalidate`, so a conditional request answers
  304. The code panes download a whole `src/<target>` file on a selection and
  the tree is text, so the transfer is where the time was. A `Range` request, a
  file under the floor, a suffix that is not text, and a client that cannot
  decode any of the three are still bottle's `static_file` answer, headers and
  404 included. The dashboard also stops fetching `/original/<target>.dll`
  with the page and defers it to the first selection that needs it.

### Fixed

- A regeneration the server answers 202 for (a re-send that reached the run its
  own first request started) left the dashboard's notice line reading
  "Regenerating..." with nothing running behind it and the button already back
  to "Regenerate", so the only move left was to ask for a second pipeline. The
  line now says the regeneration is already under way and that the map
  refreshes by itself when it finishes, which is what the `db-updated` event
  then does.
- **A refused `POST /api/regen` raised `NameError` and answered 500.** Every
  arm of the endpoint's security gate (a peer that is not loopback, an `Origin`
  that is not this dashboard, a failed token) routes through the one helper
  that logs the refusal, counts it and answers the 403, and that helper named
  a peer accessor that does not exist. The refusal therefore logged nothing,
  counted nothing and escaped the handler as an unhandled error, which is the
  opposite of what it was written to do.
- `src/recoverage/assets/.scratch_head.js`, a minified scratch copy of the
  bundle, was committed into the directory `make web-build` writes and
  `pyproject.toml` packages. It was not in `BUNDLE_ASSETS`, so `make build` and
  `make web-lint` both failed on it.
- **The deferred browser opener slept on the wall clock, not on `clock`.**
  `serve --open` probes the listener before it opens a tab, and the loop read
  its deadline through `recoverage.clock` but parked between attempts on
  `time.sleep`, so a start whose listener never came up took real seconds the
  test that drives the probe has to wait out, and two runs of the same request
  sequence differed by however long the wall clock decided. `clock` carries
  `sleep` beside its two reads and the loop uses it, so the whole poll is
  driven from one place. Production behaviour is unchanged: the function is
  `time.sleep` under another name.
- **A `[targets.X].binary` outside the project tree was read and served.**
  The disassembly and raw-byte endpoints load the binary a project's
  `rebrew-project.toml` names, and the value was joined onto the project root
  without a containment check: a parent hop or an absolute path in the file
  made `/asm` and `/bytes` answer with the bytes of any file the process can
  open. A configured binary now has to resolve inside the project tree (a
  symlink out of it is refused too), and the refusal is logged, so a target
  with no binary configured and one whose binary is out of bounds are
  distinguishable in the log.
- **A percentage kept its sign only for a reader whose digits are Latin.** The
  dashboard spells every figure in the reader's own locale, so an Arabic or
  Hindi reader got Arabic-Indic digits beside a `%` that carries no script of
  its own. Interpolated into a sentence, the sign moved to the other end of its
  own number. Every percentage printed with a sign is now one isolated run, the
  same mechanism the dashboard already uses for a name out of a coverage
  document, and a block index is spelled like the counts beside it.
- **A Potato Mode coverage failure could split the log line that records it.**
  The "coverage unavailable" warning names the coverage directory and the
  parse error that made it unavailable, and it claims to mirror the API's
  `db_unavailable` line, which escapes both: the directory comes from
  `RECOVERAGE_DB` or a project's `db_dir`, and the cause quotes a document the
  reader rejected, so either can carry a line break. A target id or a directory
  name holding one turned the single record of a 503 into two entries, the
  second of which reads as an unrelated message. The same escaping now covers
  the "source file unreadable" line in a code panel, whose path and cause come
  out of the document too.

- **An install missing the SPA shell answered `/` as a bare 500.** The shell's
  two siblings degrade to an empty string, because a missing stylesheet or
  bundle still leaves a page that renders, so each is read under a guard that
  logs what is absent. `index.html` has no degraded form and was read bare: a
  package installed without it logged a `FileNotFoundError` naming no file,
  which is the whole of what an operator has when a wheel arrives with an asset
  pruned. It now raises a `MissingAssetError` naming the path, the cause and
  the remedy, while the warm-up keeps deferring the build to the first request
  exactly as it did for any other read failure.

- **A failure to release the cross-process regen lock replaced the regen
  failure.** The advisory lock is dropped by the descriptor close whether or not
  the explicit unlock succeeds, so an `OSError` out of the unlock reported a
  release the kernel was about to perform anyway, and it escaped in place of
  what the run had said: rebrew's exit status, or its traceback. The unlock
  error is now dropped only on the way out of a body that raised, where there
  is a better answer to give, and still surfaces after a run that succeeded,
  since a silent failure there would leave the next regen refusing against a
  lock no process holds.

- **A section name holding a non-breaking space made `/api/.../data` answer
  404.** `?section=` was trimmed with `str.strip()`, which removes every
  character Unicode calls whitespace, so a name ending in U+00A0, a thin space
  or U+FEFF was compared as a name the document does not hold. The filter is
  trimmed of ASCII whitespace only now, like every other term in the package.

- **`recoverage config` died on a coverage directory whose name is not
  UTF-8.** The path is read with `os.fsdecode`'s `surrogateescape`, and stdout
  was pinned to UTF-8 with `strict` encoding, so one undecodable byte in a
  mounted or extracted directory name raised `UnicodeEncodeError` before the
  command printed anything. stdout now uses the same replacing handler the log
  and the warnings already use.

- **The cell detail panel coloured a state the function list did not.** The
  list folded the cell's `state` before looking up its colour and the panel did
  not, so a document spelling a state `Exact` rather than `exact` was drawn in
  the exact-match colour in one place and the default text colour in the other.

- **A refused regenerate was invisible, or filed as a broken pipeline.** The
  four security arms of `POST /api/regen` (a remote peer, a present-but-empty
  `Origin`, a foreign origin, `Sec-Fetch-Site: cross-site`) answered 403 and
  wrote nothing: the request never entered the pipeline, so no regen line was
  produced, and the per-request line is only logged above the slow-request
  threshold. A cross-origin attempt against the one privileged operation
  reached neither the log nor `/api/health`. Each now logs a warning naming
  the reason and the peer, and counts under `regen.rejected`.
- A second `rebrew build-db` over the same tree (`RegenBusyError`) was logged
  as `Regen failed after 0.0s` and counted as a regen failure, so a cron job
  overlapping the dashboard's own regenerate reported a broken pipeline and
  put a red line where there was none. It is now a refusal, logged at info and
  counted under `regen.rejected`; `regen.failures` is the count of runs that
  ran and failed.
- The dashboard's error notices and its regenerate notices no longer throw the
  server's reason away. Every error message a failed request produces carries
  the server's `X-Request-ID`, and a refused regenerate carries its status,
  detail and id, so what a reader reports can be found in the server log
  instead of arriving as one generic "unavailable" line.
- An unreadable coverage directory wrote one warning per page load for as long
  as it stayed unreadable: `/api/targets` is the request the dashboard cannot
  avoid, and the fallback to the config-only list fired the line every time.
  It now logs the outage once, the recovery once, and stays quiet in between.
- The log lines that report an unreadable coverage document (`/api/targets`,
  `/potato`), a source file that cannot be read and a DLL that fails to load
  interpolated the document's or the project's own text unescaped, so a value
  carrying a line break split the entry. They are escaped like every other
  request log argument, and the two that had no fields to pivot from now carry
  the request's status and route.
- A connection that ends on the socket deadline or because the peer vanished
  left no trace at all. Each now writes one debug line naming the peer, so a
  client holding an admission slot without ever sending a request can be told
  apart from an idle browser tab.
- A failed rebuild logged the exception's class and message with no traceback,
  so a pipeline that died inside rebrew after two minutes left nothing to
  locate the cause with. The failure line now carries the frames.

- **`RECOVERAGE_LOG_LEVEL` accepted a number no record clears.** The name arm
  already refused an unknown level, because it reaches `basicConfig` and leaves
  the logger quieter than the operator asked for; the numeric arm took any
  digit run, so `RECOVERAGE_LOG_LEVEL=9999` started a server whose every record
  sat below the threshold. The start banner, the request lines and the health
  transitions were all gone, and `recoverage config` printed
  `log_level=Level 9999` as though the level had been asked for by name. A
  number is now read through the same `logging.getLevelNamesMapping()` table
  the names come from, so `0`, `10`, `20`, `30`, `40` and `50` are what the
  numeric arm accepts, and anything else is a startup error naming the variable.

- **An `assert` guarded the WSGI application lookup and the smoke test's
  sample document, and `python -O` strips both.** The request handler would
  have handed `wsgiref` a `None` application, and the smoke run would have
  probed a server built from a document that was never written. Both are
  explicit failures now, and `S101` is on outside the test suite, where
  `assert` is the mechanism a test is written in.

- **A symbol written right to left read in the wrong order.** Every name on
  the dashboard comes from a PE image, so a target whose symbols are Arabic or
  Hebrew is a document the reader can have, and both surfaces laid such a value
  out against the page's own left-to-right direction: the name was reordered
  against the numbers and punctuation beside it, and a metadata cell or a
  function-list row filled the wrong way round. A value that stands alone in a
  cell now takes its own direction, and one interpolated into a sentence of the
  page's copy is isolated from it. Potato Mode's footer stamp also carries the
  instant in ISO 8601 beside the fixed-pattern text, so a reader's own tooling
  can re-render it in their locale.

- **Two regens of the same project running at once could interleave their
  writes.** A rebuild is convergent, so a second run after the first finished
  ends in the same state, but the writer replaces each `coverage-<target>.toml`
  whole: a second run truncating one the first is halfway through left a
  truncated document, which the dashboard reports as a corrupt db rather than
  as a concurrent rebuild. The in-process lock and the `Idempotency-Key` ledger
  live in one server's memory, so neither could see a `recovery regen` run at
  another terminal beside a running dashboard, or a cron job over the same
  tree. The pipeline now holds an advisory lock (`.recoverage-regen.lock`) in
  the coverage directory for its length; `recoverage regen` exits 1 with a
  message naming the holder, and `POST /api/regen` answers the same 429 body
  the in-process lock sends and counts it as a refusal rather than a failure.
  The lock is held on an open descriptor, so a regen that is killed releases it
  instead of blocking every regen after it.

- **`retry_after` in a 429 body and the `Retry-After` beside it could
  disagree.** Every limit the server reports now puts the header's own whole
  number of seconds in the JSON, and the key is an integer wherever it
  appears. The regen cooldown sent a rounded float (`4.2`) beside a ceiled
  header (`5`), so a client that read the body waited 4.2 seconds and was
  refused again by the cooldown it had just been told about; the lock and the
  event-stream cap sent the same value as a float the header spelled as an
  integer, leaving a client reading the key to handle both types.

- **A `/bytes` refusal for an impossible file offset carried no reason.** The
  negative-file-offset guard answered `{"error": "offset beyond section
  bounds"}` with an empty `detail`, the one answer in that endpoint a caller
  could not act on. It now names the section and the offset the document
  carries, like the two bounds refusals beside it.

- **Potato Mode's search ignored the address it had just printed.** The cell
  panel renders an address padded to eight hex digits, and the grid's search
  matched only the unpadded `vaStart` spelling a `.text` cell stores, so for a
  target whose functions sit below `0x10000000` a reader who copied the
  address off the page highlighted nothing. It now matches both spellings, as
  the functions view and the API's `?search=` already did.

- **A section name carrying a Unicode line separator broke the Markdown
  export's table.** `recoverage export --format md` escaped `|`, CR and LF in a
  section or target name, but not U+2028 or U+2029, which are the line
  terminators a Markdown reader breaks on. One such name turned a single table
  row into two, so the export rendered ragged and the second row read as a
  section that does not exist. Those two are folded to a space now, beside the
  CR and LF they were missed by.

- **A malformed `Content-Length` was read as no `Content-Length` at all.** A
  header the ASCII parse refuses (`1_0`, a non-ASCII digit run, a negative or
  a non-numeric value) fell through to the unframed read, so the request was
  answered on the JSON it happened to contain rather than on the framing it
  was sent in, and the endpoint's rejection named the wrong thing. It is now
  refused as a malformed body with the connection closed, the same answer a
  bad chunk-size line or a body cut short of its declared size already gets.

- **`recoverage --no-color` exited 2 with `Missing command` instead of serving
  the dashboard.** The group flags are documented as accepted before the
  subcommand, but the default-command rewrite only fired on a bare argv, so the
  flag alone had no subcommand to attach to. A command line carrying nothing
  but group flags now serves, while `--help`, `--version` and every spelling
  that names a subcommand keep click's own answer.
- **`--allow-remote` and `--cors` could not be switched off from the command
  line.** Both read a `RECOVERAGE_*` variable as their default, and the
  documented precedence is that a flag on the command line always wins, but
  neither had a spelling that passed `False`. `--no-allow-remote` and
  `--no-cors` turn them back off against an exported variable.
- **A static asset fetched with no shared encoding carried no validator.**
  `app.js`, `style.css`, `print.css` and `favicon.svg` are documented as
  `no-cache` with a strong `ETag`, and a client sending `Accept-Encoding:
  identity` (or naming no encoding the server offers) is answered by bottle's
  `static_file`, which sends neither header: it got heuristic freshness and a
  full body on every load. That path now mints the `identity` tag, answers a
  matching `If-None-Match` with a 304, and sends `Vary: Accept-Encoding`.
- **The rebuild advice was printed twice in the database error of `stats`,
  `export` and `check`** when rebrew's own message already ended with it.
- **`recoverage export --format md` and `--format json` reported a failed
  write as a traceback.** Only the CSV arm caught the OSError a full disk, a
  quota or a closed pipe raises, and named how many rows landed before the
  output was truncated. The other two arms let it escape, so a redirected
  `export --format md > out.md` on a full disk left the operator with a
  truncated file and a stack trace and nothing naming the operation that
  failed. All three formats report it the same way now, and a broken pipe
  still reaches the `export | head` handling rather than being reported as a
  disk that is not full.

- **`recoverage export | head` could exit with a traceback instead of 1.** The
  handler for a closed pipe repoints stdout at `/dev/null` so the
  interpreter's final flush stays quiet, and the `open` of that file sat
  outside the suppression that already covered the `dup2` and the `close`
  beside it. On a host that cannot open `/dev/null` the OSError escaped the
  handler and replaced the exit status: the one report that existed to be
  clean was the one that raised.

- **`GET /api/targets/<target>/functions` ordered the whole match set to
  answer one page.** The page is a window on the sorted rows, so the endpoint
  now selects the `offset + limit` rows it serves instead of sorting every
  match and discarding all but the page, and the sort column is resolved once
  for the list rather than per row. A search keystroke against a 6000-function
  target went from 3.3 ms to 2.1 ms, and an unfiltered page from 1.5 ms to
  0.7 ms. Potato Mode's function table takes the same resolved key.
- **Potato Mode folded every function to build a highlight set the functions
  view never renders.** The grid is what dims the cells whose function
  matched; `?view=functions` prints the matched rows in full, so the pass was
  pure waste on the one view that does not draw a grid.
- **The shipped stylesheet did not match `web/`.** `src/recoverage/assets/style.css`
  is a build output committed to the tree, and the committed copy had drifted from
  what `make web-build` produces from the same sources under the pinned Tailwind:
  its theme layer was missing `--font-mono` and `--shadow-glow`, both declared in
  `web/app/index.css`. `make build` regenerates the file and
  `make check-bundle-clean` fails on the difference, so the dashboard served CSS
  that no longer came from the source it is built from. The committed copy is the
  rebuilt one.
- **`make build` would have packaged a stray file out of the asset directory.**
  The wheel's package data is the glob `assets/*` and Vite cannot police that
  directory (`emptyOutDir` is off, because it also holds the hand-written
  `index.html`, `print.css` and `favicon.svg`), so anything left in it rides into
  the wheel. The build now refuses a directory holding anything other than the
  five shipped assets, and one missing from it, before `uv build` runs.
- **`make -j all` ran the gates against a half-written tree.** Every target shares
  one `.venv`, one `node_modules` and one `dist/`, and `all` chains work that
  writes to all three in the order it declares them, but make orders a
  prerequisite list under `-j` by nothing. The Makefile is now `.NOTPARALLEL:`.
- **The index page rendered every README link as a 404, and the Potato Mode
  screenshot never rendered at all.** `README.md` is the wheel's long
  description, so it is the project page, and every target in it was relative
  (`docs/mascot.png`, `NOTICE`, `../rebrew`): a target that resolves against
  the repository on GitHub resolves against `pypi.org/project/recoverage/` on
  the page that ships the package. All of them are absolute URLs now. The
  Potato Mode image pointed at `docs/recovery_potato.png` where the file is
  `docs/recoverae_potato.png`, so that screenshot was broken in both places.
  `tests/test_build.py` holds every target in the README: none relative, and
  every repository URL naming a file this commit has.
- **The wheel's metadata named no author and the license named no holder.**
  `pyproject.toml` declared no `authors`, so the index page listed the package
  as authored by nobody, and the MIT `LICENSE` the wheel and the sdist carry
  read `Copyright (c) 2026` with nothing after it, a notice that grants its
  permission to no one. Both name the project's author now, and the two are
  held against each other by `tests/test_build.py`.
- **`recoverage serve` exited on a `TypeError` before it bound a port.** The
  command passed the raw `--cors-origin` flag to the security configuration
  instead of the resolved allowlist, and the flag is `None` whenever it was
  not given, so every `serve` raised `TypeError: 'NoneType' object is not
  iterable`. Where a flag was given it was not the list either: an allowlist
  named only by `RECOVERAGE_CORS_ORIGIN` was never installed, so the server
  came up with an empty one and refused precisely the reads the entry was
  written for. `serve` and `recoverage config` now install and report the same
  resolved list.
- **`serve` installed the raw `--cors-origin` list as the request-path
  allowlist, so an origin the page actually sends was refused by the entry
  written to allow it.** The request path normalizes the `Origin` it is given
  (host lowercased, scheme-default port dropped) and compares it to the
  installed list, but the installed list was the operator's spelling: a host
  written `http://App.test` and one written `http://app.test:80` both stored
  an entry no browser ever emits. `serve` now installs the resolved,
  normalized allowlist, the same one `recoverage config` and the startup
  banner already reported, so all three name the list the matcher holds.
- The failed-token throttle's 429 carried the wait only in the `Retry-After`
  header. Every other refusal the server rate-limits (the regen cooldown and
  lock, the event-stream cap) puts `retry_after` in the JSON envelope as well,
  so a client reading the documented error contract gets the same field
  whichever limit it hit, with one value in both places.
- **The dashboard printed timestamps as the wire spells them.** `updated_at`
  and `verified_at` were shown as the raw ISO string the coverage document
  carries, which is a wall time in the writer's format and zone; they are now
  rendered in the reader's own locale and timezone, and a stamp no date engine
  can parse comes back unchanged rather than as "Invalid Date".
- **Several served counts were printed with `String()`**, where the rest of the
  dashboard groups digits the reader's locale groups them: the integer readings
  in the data inspector, a function's size and blocker delta, the verify diff
  line and register deltas, and the search-status match count.
- `RECOVERAGE_ALLOW_REMOTE` set against a loopback `RECOVERAGE_BIND` does
  nothing, and said so nowhere: an operator who exported it expecting a
  reachable dashboard got one only that machine reaches, and the only clue was
  a refused connection. `serve` and `recoverage config` now warn, beside the
  CORS warnings they already print.
- **A retry of `POST /api/regen` could run a second full rebuild.** The
  `Idempotency-Key` ledger was consulted before the regen lock was taken, so a
  duplicate that arrived while its predecessor was still running saw no entry
  and reached the pipeline after the predecessor released it. The cooldown
  could not catch it either: it counts from the previous run's start, and a
  regen runs for minutes, so it had long expired. The key is now read again
  under the lock, so claiming it is atomic with the run, and a retry of a
  completed regenerate is answered with `Idempotent-Replay: true` instead of
  rebuilding the documents a second time.
- **`make build` stamped a sdist with the wrong date, or crashed, when
  `SOURCE_DATE_EPOCH` was not plain ASCII digits.** The value was checked with
  `str.isdigit`, which accepts every Unicode decimal digit and every
  superscript: a run of Arabic-Indic digits pasted through a non-ASCII locale
  parsed as a different epoch and stamped every archive member with it, and a
  superscript digit raised out of `int()` as a traceback instead of the
  refusal. The stamp is now parsed as the ASCII decimal run it is required to
  be, matching how every `RECOVERAGE_*` integer is read, and a value past
  CPython's conversion limit is refused rather than raising.
- **Clearing a criterion in Potato Mode's function list dropped the reader back
  into the grid.** The `[Clear]` link beside the status note, and the topbar's
  `[Clear search]`, both built their href without `view=functions`, so clearing
  the criterion that narrowed the list also navigated out of the list. The
  topbar's `[Clear search]` also discarded a status filter, quietly widening a
  list the reader had narrowed. Every link inside the function list now carries
  the view, and the clear-search link carries the status criterion like the two
  forms beside it.
- **Two Potato Mode controls answered to the same keyboard shortcut.** The
  Stub filter pill and the search box both wrote `accesskey="s"`, and a
  browser resolves a duplicated letter to the first control in the document,
  so one of them had no shortcut while showing the same `s` as the other.
  Every letter is now claimed once, in document order, and a control that
  loses a claim takes none. The footer also prints the shortcuts the page
  actually handed out, which were previously on the page only as attributes.
- **The code modal had two focusable regions under one name.** Its body and
  the `<pre>` inside it each declared a `region` labelled the same, so
  keyboard focus stopped twice on the same text and a screen reader read the
  same line twice. The body keeps the region; the `<pre>` hands it over.
- **A copy button's outcome was not in its accessible name.** The visible
  label flashes `Copied!` for a second, so a voice-control user saying "click
  Copied" had no name to match. The outcome now joins the name as well as
  the live region.
- **The 401 page announced a table before its message.** The one-cell table
  that centres the "access token required" text carried no
  `role="presentation"`, the one every layout table in Potato Mode already
  carries.
- The legend's colour swatch in the SPA is `aria-hidden`, as the identical
  swatch in the stats strip already was.
- **A regen was refused on macOS and Windows for a mismatch that did not
  exist.** `RECOVERAGE_DB` and the directory rebrew writes to were compared as
  path strings, and on the two filesystems that ignore case by default
  `/proj/DB` and `/proj/db` are one directory under two spellings, so the guard
  exited 2 and the only way out was to respell the variable. The comparison asks
  the operating system which directory a path names, and is still exact on a
  case-sensitive filesystem.
- **A source file's `Content-Type` depended on the host.** `/src/<file>` read
  its type from the machine's mime database, so a `.c` file arrived as
  `text/plain` on Linux (which ships an entry for it), as whatever the Windows
  registry holds, and `.def`/`.inc`/`.asm` as `application/octet-stream`, the
  one answer that says "download me" for a body the route had just decided was
  text. The type now follows the same suffix set that decides a file is text,
  so it is the same on every machine and cannot disagree with the compression
  decision. An `.xml` file was the one suffix the two tables disagreed on: the
  type table named it and the text set did not, so it was served untyped and
  uncompressed while every other named suffix was neither.
- `--port 0` could publish a port the listener then failed to bind. The probe
  that resolves the ephemeral port took whichever address family the resolver
  listed first, while the listener took IPv6 only when every answer was IPv6,
  so on a dual-stack host the port came off the IPv6 socket and the AF_INET
  listener then failed on it. One definition of the family is now read by both.
- **Potato Mode reported a near-perfect match as a perfect one.** A function's
  code-similarity (both the function row and the latest `rebrew verify` record)
  is a 0-1 fraction, and the dashboard renders it through the flooring helper
  every other percentage goes through. The two Potato Mode detail rows
  formatted it with a bare `%.1f`, which rounds to nearest and rounds up: a
  99.99% match printed as `100.0%` beside a function that is not an exact
  match, while the dashboard beside it showed `99.9`. Both now floor, so the
  two views of one function cannot disagree, and a stored value that is not a
  finite number is left alone rather than formatted as `nan%`.
- A chunked request body whose trailers were cut off mid-section is now refused
  as a malformed framing instead of being served. The reader treated the end of
  the input where the trailer section's final CRLF was due as the end of the
  trailers, so a truncated message was answered `200` with a body whose framing
  the reader knew was incomplete, and whatever the client sent next was read as
  the rest of it. Every other read in that reader already refuses a short
  input; the trailer loop was the one that did not.
- **One client could lock every other client out of a token-protected
  dashboard, and a verified request handed a guesser a fresh allowance.** The
  failed-token window behind the 429 was one deque for the whole process, and
  any successful authentication emptied it. Ten wrong tokens from anyone
  answered 429 to the operator for the rest of the window, so an unauthenticated
  peer could keep the dashboard unreachable by never stopping, and on a network
  bind the operator's own page loads reset a guesser's count on another host
  without bound. The window is keyed on the requesting peer now, and a verified
  request clears only that peer's.
- **A file in the project tree could run as a page on the dashboard's own
  origin.** `/src/*` and `/original/*` are served with the content type guessed
  from the file's own suffix, so an `.html` or `.svg` anywhere under `src/` was a
  document the browser rendered at the dashboard's origin, under a policy that
  allows inline script, with the auth cookie riding along on its same-origin
  requests. Both paths are answered under a `sandbox`ed, `default-src 'none'`
  policy now; the files are otherwise unchanged.
- **One bad cell in a verify row took the whole Potato Mode detail panel down.**
  A `similarity` that was not a number made the `× 100` and the one-decimal
  format raise, which escaped as a 500; a boolean there rendered as a real
  100.0% match. The row is omitted instead, which is what the functions view
  already did with the same value.
- **A cell's parent link in the dashboard went nowhere.** `parent_function` is
  the NAME rebrew gives the function a data or thunk block belongs to, and the
  panel printed it as if it were an address: the link read `0X_FUNC_A` and
  every click answered "no block covers 0X_FUNC_A". It now shows the name and
  jumps to the function's own block, resolved through the search index the
  search box already holds; a parent the index does not carry is shown as text
  rather than as a link that leads nowhere.
- **Searching the dashboard for an address matched nothing.** The search index
  carries each address as a hex string, and the search folded it through the
  hex formatter, which reads a string as a string: `0x10001000` was compared as
  `0X0X10001000`. The box now folds the decimal and the hex spelling, the two
  columns `/api/targets/<target>/functions?search=` folds beside the name and
  the symbol, so a term that lists a row through the API highlights it here too.
- **A coverage document with an mtime outside the calendar took the freshness
  surfaces down with it.** The mtime is filesystem input, so a restored tree, a
  bad RTC, a `touch -d` or a FAT volume can carry a stamp past the last year
  `datetime` can name (`os.utime` writes a year-10000 stamp on any Linux host).
  Converting one raised `ValueError`, which turned `/api/health` and Potato
  Mode's footer into a 500 over a perfectly readable coverage directory. The
  stamp is now clamped to the representable range, and the extreme renders as
  the extreme.
- **The dashboard's copy of the target binary survived a rebuild.** The byte
  panes download the original DLL once per target and slice it locally, and the
  download was remembered by path alone. A `rebrew build-db` after a recompile
  rewrites that file under the same path and announces itself with a
  `db-updated` frame, which moved neither the path nor the target id, so the
  cached bytes stayed the previous build's for as long as the tab was open:
  the hex and disassembly panes read one build while `/asm` and `/bytes`, whose
  server-side caches the rebuild does clear, served the next. The download is
  now remembered per build as well as per path, so a reload frame refetches it.
- **A chunked request body was framed by a number `int()` widened.** A chunk
  size of `1_0` is 16 to `int(x, 16)`, which also reads the `_` separator, so
  the body reader consumed 16 bytes of a connection it had no framing for and
  left the rest of the stream to the next request on a keep-alive socket. The
  size line takes the same ASCII-only parse as every other request-supplied
  number, and anything else is refused as malformed with the connection closed.
- **`serve` opened a browser tab at a dead port when a startup step failed.**
  The database watcher and the cache warm-up thread start after the deferred
  browser opener is armed, and both are `Thread.start`, so a process that is
  out of threads raised between the two and unwound past the block that cancels
  the opener. Half a second after the traceback a tab opened on a port nothing
  was listening on. Every startup step now runs inside that block, so a start
  that never reached the listener never pops a tab.
- **`recoverage export --format csv` unwound on a failed write, leaving a
  truncated file and a closed stdout.** The redirect a user is looking at is
  the file being written, so a failure part-way through (no space left, a
  quota, an unreachable mount) left a half-written export with a raw traceback
  and nothing saying the file was cut short; the encoding wrapper this path
  builds also owns stdout's buffer, and leaving it attached on the failure path
  closed the real stdout. The command now reports how many section rows landed
  out of how many, exits 1, and always detaches the wrapper.
- **`serve --port 0` reported port 0 everywhere it printed the port.** Port 0
  is the documented floor and means "bind a free port", but the banner, the
  `config` block and the URL handed to the browser all named the 0 that was
  asked for, so the browser opened a tab nothing answers on and
  `/api/health`'s `config.port` was not a port the listener held. The port is
  now resolved from the OS before the listener binds, and every reader of the
  value reports the one that was bound. `recoverage open --port 0` is refused
  with exit 2 instead, naming the banner that holds it: the command has no way
  to know which free port a server running elsewhere picked.
- **An address in a section whose cells are not loaded yet was reported as
  unmapped.** A search hit, an assembly operand or a parent link pointing into
  a sibling section switched to that section and then answered "no block
  covers it", because the map had no cells to locate the block in. The section
  is fetched and the jump completes when its cells arrive.
- **A regenerate that finished said nothing.** The dashboard showed
  "Regenerating..." while the pipeline ran and then went silent, leaving a
  reader to tell a completed rebuild from a failed one out of the map's own
  repaint. The success is now stated; a failure still holds its line until
  something replaces it.
- **A Potato Mode line could start with a combining mark.** The detail panel
  and the disassembly pane hard-wrap their text at a fixed column count, and
  the wrap landed between a character and a combining mark that followed it,
  moving the accent onto the first character of the next line. A value spelled
  NFD (what a macOS-side tool writes into a coverage document) is one code
  point longer than the precomposed spelling and hit it; the wrap now keeps
  the two together.
- **A dropped `db-updated` event was logged identically for every wedged
  dashboard.** The warning named the queue depth and nothing else, so N stalled
  event-stream clients produced N indistinguishable lines and no way to tell
  which tab to reload. The line names the peer the frame was dropped for.
- **The rejected-`Host` and rejected-token audit lines interpolated
  `REMOTE_ADDR` raw** while every other untrusted argument in the package's log
  calls is control-char escaped. A reverse proxy that folds a header into
  `REMOTE_ADDR` made it as forgeable as `Host` on the very lines an incident
  investigation reads.
- **`make shell-lint` failed on the tree it was meant to gate.**
  `tools/ci_clone_rebrew.sh` declares its dialect to shellcheck now, so the
  array and `pipefail` below the header stop reading as an unknown shell
  (SC2148) and the `lint` job's shell gate passes.
- **A Linux CI job ran on a moving runner image.** Every job named
  `ubuntu-latest`, which follows the runner fleet, and the image is where the
  two linters the tree pins no version of come from (`shellcheck` and
  `yamllint`) as well as `diffoscope`. The jobs name `ubuntu-24.04` now, and
  `tests/test_supply_chain.py` fails a return to the floating label.
- **A reproducibility failure in the `build` job said only that the artifact
  differed.** The step called `diffoscope`, which the runner image does not
  ship, and swallowed the resulting `command not found`, so the one failure
  that needs a diff produced none. It prints both hashes now and adds
  diffoscope's breakdown where the image carries it.
- **The Regenerate button minted a fresh `Idempotency-Key` on every request,
  so a retry re-ran the whole pipeline.** The key was generated inside the
  fetch helper, which made every attempt a new logical operation to the
  server's ledger. A response lost on the way back (the run is minutes long)
  therefore cost a second full catalog + build-db when the reader clicked
  Reload again. The key is now minted once per click and the request is
  re-sent once on a transport failure with that same key, so the server
  answers the re-send from the ledger instead of running the pipeline again.
- **A `/api/targets/<target>/data` build killed mid-flight left its
  single-flight claim registered for the life of the process.** The claim is
  released in the building thread's `finally`, and a thread killed between
  the claim and that `finally` never released it, so every later request for
  that key waited the full 30 seconds on an event nobody would ever set,
  rebuilt the payload anyway, and the entry never drained. A claim now carries
  the instant it stops being answerable: it is dropped on the next checkout
  of the same key, and the request that finds an expired one takes the build
  over rather than waiting on it.
- **The rebuild advice named a command that does not have to run.** `rebrew
  build-db` runs the catalog analysis in process, so the `--help` prerequisites
  line, the database-error hint in `stats`, `export` and `check`, and the 503
  message the server logs for a coverage directory with no document told an
  operator to run `rebrew catalog && rebrew build-db` first. All three now name
  `rebrew build-db` alone, which is what writes `db/coverage-<target>.toml`.
- **`POST /api/targets/<target>/functions` never answered over a real
  connection.** The body reader drained the request to EOF whatever
  `Content-Length` said, and under the serving stack `wsgi.input` is the
  socket's buffered reader, so a read past the last declared byte blocked until
  the client hung up. A client that sent its body and waited, which is every
  HTTP client, waited for the socket deadline (120 s) and then got its answer.
  A framed body is now read to its declared length.
- **`recoverage regen` wrote to a directory the dashboard never reads.**
  rebrew resolves the coverage directory from `rebrew-project.toml` alone and
  has no environment override, so with `RECOVERAGE_DB` set the regen rewrote
  documents under `./db` and then reported `Done` while `stats`, `export`,
  `check` and `serve` read the other directory. A regen whose output the
  served directory would not pick up is now refused with exit 2, naming both
  directories. `regen` also names the directory it wrote into, and how many
  documents that was, rather than reporting a bare `Done`.
- **`RECOVERAGE_CORS_ORIGIN` accepted entries no browser could send.** The
  allowlist validated through the same reducer that reads a request `Origin`,
  and that reducer drops a path and synthesizes a missing scheme: the operator
  wrote `http://localhost:5173/foo` or a bare `notaurl`, the server stored
  `http://localhost:5173` and `http://notaurl`, and the mismatch surfaced as a
  browser refusing a read rather than as startup refusing an origin. A path, a
  query, a fragment, a non-HTTP scheme, userinfo, whitespace or a non-numeric
  port is now the exit 2 the documentation already promised.
- **The "`--cors-origin` has no effect without `--cors`" warning was
  unreachable.** Both `serve` and `recoverage config` passed the installed
  allowlist, which is empty whenever CORS is off, so the arm that needed it
  could never fire. Both now pass what the operator wrote.
- **`--port` and `--min-coverage` accepted spellings their environment
  variables refuse.** Click's `INT`/`FLOAT` run the value through `int()` and
  `float()`, so `--port 1_0` opened port 10, `--port ٤٠٩٦` opened 4096, and
  `--min-coverage inf` was a threshold no percentage satisfies. Both flags are
  now held to the floor `RECOVERAGE_PORT` already had, so a non-ASCII digit,
  a `_` separator, `inf` and `nan` are the same exit 2 whichever source the
  number came through.
- **A chunked request size line was read with `int(x, 16)`.** That takes
  digits from every Unicode Nd set and reads `_` as a separator, so a chunk
  line the framing does not allow was accepted as a length and the decoded
  body disagreed with what the client sent. It goes through the same
  `parse_ascii_int` as every other request-supplied number.
- **A request the HTTP layer refused left no trace in the server log.** An
  over-long request line, a malformed one, an unsupported version, or headers
  past the limit are all rejected before a route exists, so nothing downstream
  logged them; the stdlib wrote them to stderr in its own format, with no level
  and no timestamp the server's log uses. A client stuck in a rejection loop
  was invisible to an operator reading the server's own log while the rejection
  reached the client. These are now WARNING lines on the `recoverage` logger
  naming the peer address.
- **A coverage percentage no longer rounds up to "complete".** The per-section
  figure was rounded to 2 decimal places, so 999,997 of 1,000,000 covered bytes
  was served as `coverage_pct: 100.0` by `/api/targets/<target>/stats`, printed
  as `100.0%` by `recoverage stats` and Potato Mode, and quoted as `100.00%` by
  `recoverage check` on a project with three bytes still unmatched. It is now
  floored, the way rebrew's own match figures are, so the section row, the
  summary and Potato's header are the same number and none of them claims a
  build is finished before it is. `recoverage stats` also floors the function
  match line for the same reason (2809 of 2810 functions is 99.96%, not
  100.0%).
- **A section declaring a negative column count no longer hangs the dashboard.**
  The coverage map sized its lattice from the document's `columns` value with no
  lower bound, so a negative count (or a wrapper too narrow to fit one cell)
  produced a zero-column grid whose cell-by-cell walk never advanced, freezing
  the tab. The lattice is now at least one column wide.
- **`serve` no longer opens a browser tab at a port nothing is listening on.**
  The deferred opener is now cancelled on every way out of the listener, not
  just a bind failure and a Ctrl+C: any other exit (an out-of-range address, a
  server with no application installed) left the timer armed, so half a second
  after the failure the opener fired on its own.
- **`/api/health` no longer reports a rebuild that is not running.** A
  `KeyboardInterrupt` (or any other `BaseException`) out of the regen pipeline
  unwound past the arms that close the `regen` counters, and `in_flight` is a
  gauge nothing closes again, so the block read 1 for the rest of the process.
  The run now closes its own counters on that path and the interruption is
  logged with the elapsed time.
- **A broken Pygments install no longer takes the Potato page down with it.**
  Only the `find_spec` probe was guarded, so a distribution present on the path
  but unloadable raised out of the import and answered a raw 500 for a page
  that renders perfectly well without colour. The pane now renders plain and
  one warning names the install to fix.
- A dropped `db-updated` frame is a WARNING rather than a debug line. It is the
  only notice a client gets that the coverage documents moved, and the client
  it was dropped for goes on rendering the previous build.
- **The committed dashboard bundle matches `web/` again.** `style.css` still
  carried the pre-phosphor `--bg-grad-1`/`--bg-grad-2` values and `app.js` a
  Highlight.js grammar from before the accent change, so `make build` (and any
  `make all`) rewrote both and `make check-bundle-clean` failed on a clean
  clone. Both files are regenerated from the current sources; the rebuild is
  byte-identical across runs, so the staleness was a missed commit rather than
  a drifting build.
- **A CORS preflight no longer 401s on a `--token` server.** A browser sends
  no credential on the preflight handshake, so the token gate answered 401 to
  every one of them and a browser aborted before sending the request: the
  `--cors` + `--token` combination the API documents could not be used at all.
  The handshake now passes the gate. It reads nothing (it answers from the
  empty `OPTIONS <path>` catch-all), a bare `OPTIONS` stays gated, the request
  the preflight precedes is still authenticated, and an exempt preflight does
  not clear the failed-token window.
- **A deeply nested batch lookup body no longer answers 500.**
  `POST /api/targets/<target>/functions` caught the two ways a body fails to
  parse (bad UTF-8, bad JSON) and reported them as a 400, but `json.loads`
  also raises `RecursionError` on nesting, one frame per bracket. The 64 KiB
  read cap bounds the body, not the depth inside it: `{"vas": [[[...` nests
  past the limit in a body under a kilobyte. The decoder running out of stack
  became an unhandled exception and a 500. It is a parse failure like the
  other two and now answers the same 400.
- **Potato Mode refused a source root it could not contain, on every platform.**
  A `paths.sourceRoot` that was anchored (`C:src`, `C:/Windows`, `\Windows`) or
  carried a parent hop (`../..`) replaced the containment base outright, so the
  `is_relative_to` check that guards the C-source read passed on whatever the
  document named. Stripping a leading `/` is a POSIX assumption, so on Linux
  those spellings were ordinary relative names and were refused anyway: the
  guard answered for its host rather than for the document. The source root now
  takes the same plain-relative rule as the file name under it, and an empty
  one (which would have made the whole project directory the source tree) is
  refused too.
- **The fallback source and original-DLL paths no longer lowercase the target
  id.** rebrew names the tree `src/<target>` and `original/<target>.dll` with
  the target's own spelling, so a lowercased request resolved only on a
  case-insensitive filesystem: a mixed-case target showed its sources and
  disassembly on macOS and Windows and 404'd on Linux. Documents that name
  `paths.sourceRoot` or `paths.originalDll` (every current build) are unaffected.
- **`--no-color` is accepted after the subcommand too.** It was declared only
  on the root group, so `recoverage stats --no-color` died with "No such
  option" (exit 2) while `recoverage --no-color stats` worked. Every command
  now carries the flag, in the position all the other flags use.
- **`recoverage open` exits 1 when no browser could be launched.** It reported
  success on a headless machine where `xdg-open` is missing and the fallback
  found nothing, which is the run a container entrypoint does.
- `recoverage config` now ends the way `serve` ends: a non-loopback
  `RECOVERAGE_BIND` without `RECOVERAGE_ALLOW_REMOTE` exits 1, and the CORS
  warnings go to stderr after the settings. A preflight that exited 0 for a
  configuration `serve` refuses is a deployment that finds out at boot.
- The function list's memoized `total` cannot outlive the build it counted. A
  `rebrew build-db` committing while the endpoint was loading its snapshot left
  the pre-rebuild count filed under the post-rebuild fingerprint, and every
  later `/functions` request answered that number until the next rebuild.

### Removed

- VanJS, the deferred `detail.js` split, and the vendored Highlight.js blobs.
- The six duplicate pill-cap images in `recoverage.potato`
  for `FILTER_ACT_L`, `FILTER_ACT_R`, `FILTER_ACT_MID`, `FILTER_INACT_L`,
  `FILTER_INACT_R`, `FILTER_INACT_MID`). A filter pill and a section tab are
  the same widget painted from the same palette pair, and the two sets were
  byte-identical strings built twice, so the filter pills take the section
  tabs' `ACTIVE_L` / `ACTIVE_R` / `ACTIVE_MID` and `INACTIVE_*` instead. A
  rendered page is unchanged. Anything importing the `FILTER_*` names reaches
  for `FILTER_OPTS`, which is now the one place the pills are spelled.
- `.scratch_a`, a truncated second copy of the dashboard bundle left in
  `src/recoverage/assets/` by an interrupted build. It is in neither
  `BUNDLE_ASSETS` nor anything the server reads, and `pyproject.toml`'s
  `assets/*` glob is a glob, so the 63 KB rode into every wheel built from the
  tree. The `make build` asset check and `tests/test_build.py` both refused the
  tree over it, so `make build` could not run at all.

### Security

- The auth cookie is now `Secure` on any request that arrived over TLS, and
  every response to one carries `Strict-Transport-Security`. The cookie was
  written without the flag whatever the connection was, so on a deployment
  that answers both `http://` and `https://` the token rode along with every
  plaintext request to the same host, and a browser was never told to prefer
  TLS for the next one. Both are read off the request (`wsgi.url_scheme`, or
  `X-Forwarded-Proto` behind a TLS-terminating proxy), so the loopback install
  the bundled listener serves is unaffected: a fixed `Secure` there would stop
  the cookie being stored at all.
- `POST /api/regen` no longer reads an `Origin` header that arrived empty as
  the header's absence. The same-origin check fails open on an absent Origin
  because every non-browser client omits one, and a blank value took that same
  path, admitting a privileged POST on the strength of the one header that
  should have named it. No browser sends a blank Origin, so a present but
  empty one is refused with the other cross-origin requests.
- The batch function-lookup endpoint bounds the request body BEFORE reading
  it. Bottle's own body reader drains the whole declared `Content-Length` into
  memory (and past 100 KiB into a temporary file on tmpfs) before a handler
  sees any of it, so a request declaring a gigabyte cost that gigabyte before
  the endpoint's 64 KiB cap could apply. The declared length is now compared
  first, a chunked body is decoded under the same cap, and every refusal
  answers `Connection: close`.

## [3.0.0] - 2026-09-28

### Added

- **`recoverage` on its own starts the dashboard.** Invoked with no
  subcommand it runs `recoverage serve` with the default settings, so in a
  rebrew project directory it is one command instead of two. The subcommand
  spelling is unchanged, and any argument at all (`recoverage --help`,
  `recoverage serve --port 9000`) keeps its current meaning.

### Breaking

- **The required `rebrew` is 2.16.0.** Recoverage reads and writes the coverage
  documents through `rebrew.coverage_toml`, which no earlier release ships, so
  an older rebrew can neither write a document nor parse one. Installing rebrew
  from a package index rather than a sibling checkout now needs that release.
- **The dashboard reads rebrew's clear-text coverage TOML, not
  `db/coverage.db`.** Run `rebrew build-db` to write `db/coverage-<target>.toml`
  beside the database; the dashboard reads those documents and nothing else.
  `RECOVERAGE_DB` now names the directory holding them rather than a
  `coverage.db` file, and a directory that holds no `coverage-*.toml` is the
  503 the dashboard used to report for a missing database. Two served values
  change with the storage: `/api/targets/<target>/data`'s `db_version` is the
  document's own format version (`"1"`), and `known_schema` lists the format
  versions this build can read (`["1"]`) instead of the SQLite schema numbers.
  Every other route, status code, field name and value is unchanged —
  `/stats`, `/functions`, `/functions/<va>`, the batch POST and `/potato` are
  byte-identical against the same project.

## [2.1.0] - 2026-09-28

### Changed

- **Schema v11 is accepted.** Current rebrew stamps `db_version` `"11"`.
  The `cells` table is `WITHOUT ROWID`, keyed by
  `(target, section_name, start)`, and no longer has an `id` column.
  Databases stamped `"3"` through `"10"` stay servable. A database whose
  stamp is not `"11"` is migrated with `rebrew build-db --force`.
- **A broken `rebrew-project.toml` is reported instead of ignored.** A file
  that is present but not valid TOML used to be skipped, and the dashboard
  then opened `db/coverage.db`, which can be a different database than the
  one the file named. Commands that read the database now exit 2 with the
  parse error, and a request answers 503. A missing config file still uses
  `db/coverage.db`. Setting `RECOVERAGE_DB` still selects that file.

## [2.0.0] - 2026-09-27

### Added

- **The type checker runs in CI.** `mypy` is a dev dependency and
  `make type-check` gates `src/` and `tools/` at `strict`, three checks off
  with their reason in `pyproject.toml`. The annotations were already there
  and nothing checked them; wiring the gate also fixed what it found, from a
  metrics route row typed `dict[str, int]` that stores a float to a
  `HTTPResponse = cast(Any, bottle.HTTPResponse)` alias that made the
  response helper uncheckable.

- **`make build` builds the wheel and sdist reproducibly.** The distribution
  is stamped with the commit's own date and a fixed locale and timezone, and
  the sdist is normalized (mtimes, owner, permissions, entry order, gzip
  header), so two builds of one commit produce identical artifacts. Build
  through the target rather than a bare `uv build`; `make build
  SOURCE_DATE_EPOCH=<unix seconds>` overrides the stamp. The build backend is
  pinned in `build-constraints.txt`, `dist/` is cleared first so an artifact
  from an earlier version cannot ship beside a new one, and CI builds the
  distribution twice and diffs it.
- **`/api/health` reports the rebuild pipeline and live-reload saturation.**
  `regen` carries runs, failures, refusals, in-flight count, and the last run's
  duration: a regen takes minutes, so the per-request counters could show one
  request in flight without saying it was a rebuild, or how long the last one
  took. `streams` carries connected event-stream clients against the cap that
  answers 503 to the next one, plus whether the poller thread is alive; a
  connected client with no poller now answers `degraded` instead of a healthy
  200, because every page still renders and none of them will refresh again.
- **Shell completion.** `recoverage --install-completion` installs completion
  for bash, zsh, fish or PowerShell, and `--show-completion` prints the script
  for a shell the installer does not cover. Command and flag names now
  complete; they did not before.
- **`recoverage config` prints the configuration `serve` would start with.**
  Same merge, same validation, no listener bound, so a deployment can confirm
  its environment (or diff two of them) before anything listens. `--json`
  emits the same object for a script. The token is reported as `set`/`unset`,
  and the CORS allowlist is reported as installed (default port dropped, host
  lowercased) rather than as typed, so the checked value is the value the
  server matches against.
- **Every command validates the `RECOVERAGE_*` environment, not just
  `serve`.** `stats`, `export`, `check`, `open` and `regen` read it too, and a
  misspelled variable there was a silent no-op: the command ran with a
  default the operator did not ask for. They now exit 2 with the variable
  named, the same contract `serve` already had, and an empty `RECOVERAGE_DB`
  is a one-line error instead of a traceback.
- **Every response carries a request id, and the log repeats it.** The server
  logged the method and path on the way in but never the status, the duration,
  or which client asked, so a report of "the export was slow" could not be
  matched to anything in the log. Each response now carries `X-Request-ID`
  (minted per request, or taken from the caller's own `X-Request-ID` when one
  is sent), and every log line for the request repeats it as `[rid=...]`,
  including the traceback of an unhandled error. `--log-level DEBUG` gives one
  line per request with its status and duration; a request over a second is
  one `WARNING` line at any level. The per-request line that used to be
  emitted on the way in is not repeated on the way out.
- **`/api/health` reports the request counters for the process.** `total`,
  `errors` (5xx), `slow`, `in_flight`, the latency extremes, and a breakdown
  by status class and by route rule, so the error rate and the slowest
  endpoint are readable without attaching a debugger. Routes are counted by
  their rule rather than the raw path, keeping the breakdown bounded.
- **`GET /api/targets/<target>/stats` revalidates.** It was the only
  DB-derived read endpoint with no validator: every other one (`/data`, `/asm`,
  `/sections/<section>/bytes`, `/potato`) sends an `ETag` over the WAL-aware
  freshness stamp of `coverage.db` plus the request's own identity, and answers
  `If-None-Match` with a 304. `/stats` sent `Cache-Control: no-store` and
  re-ran its full-cells-table aggregation on every poll. It now sends the same
  `ETag` and `Cache-Control: no-cache, must-revalidate`, so a polling consumer
  gets an empty 304 while the database is unchanged.
- **`POST /api/targets/<target>/functions` checks the request's media type.**
  A `Content-Type` of `application/json` or any `application/*+json` is
  accepted; a declared non-JSON type is a `415` naming the type and the one
  expected, instead of a body that happened to parse and a `400` that read as
  "your JSON is broken" when the bytes were fine. Omitting the header is still
  accepted, so a header-less client keeps working (`curl -d` needs
  `-H 'Content-Type: application/json'`). The error `code` is the new
  `unsupported_media_type`; `415` had no entry in the status-to-code map and
  would have been labelled `internal`.
- **`recoverage serve` reads its configuration from the environment.**
  `RECOVERAGE_PORT`, `RECOVERAGE_BIND`, `RECOVERAGE_ALLOW_REMOTE`,
  `RECOVERAGE_CORS`, `RECOVERAGE_CORS_ORIGIN`, `RECOVERAGE_TOKEN` and
  `RECOVERAGE_DB` supply the default for the matching flag; the flag still
  wins. `RECOVERAGE_TOKEN` keeps the bearer token out of the process listing
  that `--token` exposes it to, and `RECOVERAGE_DB` serves a
  `coverage.db` the process was not started from the root of. Values are
  validated at startup: a bad port, boolean or empty value, and a misspelled
  `RECOVERAGE_*` name, each exit 2 naming the variable. The resolved settings
  are printed on startup, the token as `token=set`.
- **`POST /api/regen` accepts an `Idempotency-Key` header.** A regen is a
  convergent rebuild, so a duplicate ends in the same state as the first run,
  but a client retrying the request it never saw answered (a replayed proxy
  hop, a lost response, a double-clicked Reload) paid for a second full
  catalog + build-db. Send a key: once the run completes the server remembers
  it and answers a later request carrying it with `{"ok": true}` and
  `Idempotent-Replay: true` without regenerating. A failed run is not
  remembered, so retrying a failure retries for real. The Reload button sends
  a fresh key per click. Keys are held for 10 minutes, 128 at a time, and a key
  outside 1-128 characters of `[A-Za-z0-9._:-]` is a 400.
- **`--log-level` and `RECOVERAGE_LOG_LEVEL` set the server's log threshold.**
  Previously the level was hardcoded to `INFO`, so a deployment could not turn
  the per-request chatter down or the detail up without a code change. Accepts
  a `logging` level name, case-insensitively, or its number; an unknown name
  exits 2 naming the variable instead of silently leaving the logger at
  `WARNING`. The resolved level is printed with the other startup settings.
- **`recoverage open` reads `RECOVERAGE_PORT`.** It defaulted to `8001` while
  `serve` read the environment, so a deployment off the default port had to be
  repeated in every `open` invocation. The flag still wins.
- **The distribution ships a `NOTICE`.** The wheel bundles the vendored
  VanJS and Highlight.js assets, whose grants travelled only in the GitHub
  README, so an installed copy carried the MIT license and no way back to
  either. `NOTICE` names each bundled blob with its source and license, and is
  listed in `license-files` so it ships alongside `LICENSE`.

### Breaking

- **`server.resolve_targets` returns the one ordered target list, not a
  `(target_ids, targets)` pair.** Before: a two-element tuple whose first
  element was raw DB order and whose second was config-declared first. After:
  the second element alone, so `target_ids, targets = resolve_targets(c)`
  raises `ValueError: not enough values to unpack`. Drop the unpacking and use
  the returned list. Every in-tree caller already discarded the first
  element, which is what left a second ordering alive for the SPA and Potato
  Mode to agree not to use.
- **`recoverage check --min-coverage` out of range exits 2, not 1.** A
  threshold outside 0-100 is a usage error, and a non-numeric value already
  exited 2 from the parser; the range check exited 1, the same code as a
  genuine coverage failure, so a CI job could not tell a mistyped flag from a
  build that dropped below the gate. The `--json` error object reports
  `"exit_code": 2` with it. A gate failure still exits 1.
- **A CORS origin no browser could send is refused at startup, not dropped
  with a warning.** `--cors-origin http://user@host.test` (or the same entry
  in `RECOVERAGE_CORS_ORIGIN`) used to print a warning and start with an
  allowlist one entry short of what was written, so the server refused
  exactly the cross-origin reads that entry was there to allow and the only
  clue was a browser console. It now exits 2 with the offending origin named,
  for the flag and the variable alike. An origin is still only checked while
  CORS is on, because that is the only case where it would have been
  installed; a normalizable origin is stored normalized, as before.
- **`RECOVERAGE_CORS_ORIGIN` set to an empty value is a startup error.** A
  unit file, a container environment and a CI job all spell "not configured"
  as an empty value, and it used to start a server with CORS on and an
  allowlist of nothing. Unset it instead. Every other `RECOVERAGE_*` string
  setting already drew this line.

### Changed

- **The dashboard dropped its frosted surfaces.** The topbar and the loading
  overlay are opaque now, with no `backdrop-filter`: over the near-black
  ground the blur showed nothing, and both sit over content that repaints
  (the whole map), so the blur cost a re-filter per frame. The loading
  overlay's pulse was always the signal, not the glass. The modal scrim keeps
  its blur, which is the one place the effect carries an affordance.

- **The code theme follows the app palette.** `assets/hljs.css` reads
  `--text`, `--muted`, `--link` and the status text tokens from `style.css`
  instead of restating their hexes, so a palette change reaches the code pane
  rather than leaving it on last release's hue. The four values that stay
  literals are lightened steps of a status hue, which a status hue tuned as a
  cell fill cannot be.

- **`?status=` on the paginated function list rejects a status rebrew does not
  define.** `GET /api/targets/<target>/functions?status=` answers `400` naming
  the accepted values for anything outside rebrew's status vocabulary, where it
  used to answer `200` with an empty page. A filter that can match no row and a
  typo were indistinguishable, and a client filtering on `EXACT` against a
  target that has none had no way to tell the two apart. Every status the
  database can hold is still accepted, and the accepted set is read from rebrew
  rather than restated, so a status rebrew adds is filterable as soon as it
  lands.
- **A stale `uv.lock` now fails the run instead of installing anyway.** Every
  `uv sync` and `uv run` in the Makefile, in `package.json` and in CI moved
  from `--frozen` to `--locked`. Both refuse to rewrite the lockfile, but
  `--frozen` installs it even when `pyproject.toml` no longer matches, so a
  dependency edit that skipped `uv lock` passed CI while testing the previous
  tree. Run `uv lock` after changing a dependency, and bump
  `REBREW_REF`/`REBREW_SHA` in `tools/ci_clone_rebrew.sh` if rebrew moved. The
  `sbom` job keeps `--frozen`: it is the one job with no sibling `../rebrew` to
  resolve the path dependency against.
- **The rebrew tag, commit and clone URL are written in one file.** The
  composite action's `clone-url` input had a URL default duplicating
  `tools/ci_clone_rebrew.sh`, and `README.md`, `CONTRIBUTING.md` and
  `AGENTS.md` each restated the pinned tag and commit in prose. The input stays
  for a fork or a mirror, with an empty default; the documents now name the
  script that holds the pin. `CONTRIBUTING.md` no longer tells a contributor to
  reassemble the clone by hand, which is how the uncommitted-work guard and the
  tag-moved check get skipped.
- **The SBOM upload fails when the export is missing or empty.**
  `upload-artifact` defaults to warning and would have left a green job with no
  inventory attached.
- **Potato Mode's detail panel resolves a cell's parent without walking the
  section.** Opening a block whose cell names a parent function searched every
  cell of the section for that name on each request, which on a large `.text`
  cost more than the render that asked for it (4.7 ms against a ~4 ms page on
  40k cells). The name-to-cell index is now derived once per decoded section,
  under the same snapshot key as the grid it reads, and rebuilt only when
  coverage.db changes. Blocks without a parent never build it.
- **The dashboard loads measurably less on every visit.** The inlined shell
  and the packaged assets are now served as the *smallest* representation the
  browser accepts, rather than under a fixed `zstd`-first preference, and both
  compress at maximum effort instead of the per-request settings. The shell
  drops from 17,568 to 14,537 bytes, which puts it back inside the initial
  congestion window (14,600) and saves a second round trip before the first
  paint on any zstd-capable browser (and to 14,090 once the metadata grid below
  moved out of it); `hljs.min.js` drops 45,575 to 37,714 and
  `detail.js` 10,468 to 8,583. The shell also gained a strong `ETag` and
  answers `If-None-Match` with a 304, so a repeat visit re-downloads none of
  it: it was the one response still served `no-store`, so every reload pulled
  the full document while the assets beneath it revalidated to nothing.
- **The selected function's metadata grid moved into `detail.js`.** The grid
  under the panel title renders nothing at first paint (no function is
  selected then), so the shell was downloading and parsing it to draw an
  empty panel. `detail.js` already owns the rest of that pane and is preloaded
  alongside it. The shell is now 14,090 brotli bytes, 510 under the congestion
  window; `detail.js` is 10,186.
  Dynamic API responses are unchanged: they keep the fixed preference order and
  the cheap settings, because there the extra compression passes are paid per
  request.
- **`make shell-lint` and `make yaml-lint` check the tree's non-Python
  sources.** The `tools/*.sh` scripts ran under `bash` with no shellcheck and
  the `.github/` definitions were read by no linter at all; both now run in
  the `lint` CI job, alongside the ruff targets in `make all`. The yamllint
  settings live in `.yamllint.yaml`. ruff additionally selects the `PTH`
  and `RUF` groups, both clean on this tree.
- **The `/potato` route lives in `recoverage.potato`, next to the renderer it
  serves.** `ui.handle_potato` imported the renderer inside the handler body
  and reached back for a private helper; the route now sits with
  `render_potato` and `webapp` imports `potato` alongside `api` and `ui`.
  Same responses, same headers, same 503 and 500 bodies.
- **`_db_path` is imported from `recoverage._paths`, not re-exported through
  `recoverage.server`.** `api`, `potato` and `cli` now name the same module as
  the helper's owner.

- **One mechanism pins the sibling `rebrew` checkout.** Every CI job ran the
  `sibling-rebrew` composite action and then `tools/ci_clone_rebrew.sh`, which
  deletes the clone the action made and fetches the tag again. The action
  carried its own ref, a moving `main` commit that no check compared against
  the tag-and-SHA pair the script verifies. The action is gone; the script is
  the single pin, and `tests/test_supply_chain.py` fails if a second mechanism
  comes back or if the `Makefile` pin drifts from the script.

- **`tools/oxlint/rikalabs-strict.json` records where it came from.** The
  checked-in copy of the Rika-Labs `strict` preset carried no license, so the
  README now names the package version and its MIT license, and
  `tools/flatten_rikalabs_strict.py` refuses to regenerate the preset if a
  bump changes that license.

- **The design docs describe the code as it is.** `USER_STORIES.md` and
  `DESIGN.md` still described a DOM grid of per-cell nodes, CSS-class
  filtering, a bare `recoverage` command that serves on its own, and an
  inlined shell of 14.55 KB; the SPA paints one canvas per section, filters
  with a second alpha pass over cached rects, is launched as
  `recoverage serve`, and the shell compresses to 14.1 KB. The cell-state
  colour list, Potato Mode's colour table, the Potato test counts and the
  payload budget now match the code, and a test fails when a cell state
  drops out of the documented table.
- **Static assets revalidate instead of re-downloading.** The ten
  compressed assets sent `Cache-Control: no-cache` with no validator, so a
  repeat visit re-sent 55 KB and every asm-pane opening re-sent
  `hljs.min.js` and its grammars. Each now carries a strong ETag (per
  content-encoding, so a brotli and a zstd body never share one) and answers
  304 to a matching `If-None-Match`. `max-age` stays at 0 on purpose: the URLs
  are not content-hashed, so an upgrade changes the bytes under the same name.
- **Syntax highlighting follows the documented palette.** Every highlight.js
  token color in both themes was a hand-picked literal outside the palette and
  now derives from it, so the code and hex panes restyle with the theme
  instead of drifting from it.
- **Badge, link, and progress-track colors derive from the palette** rather
  than repeating hex literals, including the empty progress-bar track, which
  is `--none` composited over the panel color.
- **The function list's row total is memoized, and the disassembly memo is
  bounded.** The paginated list ran `COUNT(*)` over `functions` on every
  filter, status and page change (7.2 ms unfiltered on a 20k-function
  target), for a number the database had not changed; it is now keyed by the
  same WAL-aware snapshot the other memos use plus the exact filter triple, so
  a rebuild or a different filter misses. The disassembly memo was sized at
  2048 entries against a worst case of ~72 KB of rendered text per entry
  (4096 bytes of x86, the `?size=` clamp the SPA sends), so it could retain
  ~148 MB for a cache whose hits are rare: the ETag answers the browser's
  repeat clicks with a 304 first. It is capped at 128 entries, near 9 MB.
- **The dashboard's corners and headings match its own logo.** Border radii
  came from nine different values, none of them a token, so the panels and
  grids read as rounded web cards over a phosphor grid. Three steps now
  (`--radius-hair`, `--radius`, `--radius-pill`) at terminal scale, and the
  wordmark, section titles and panel titles wear the monospace face the
  favicon already ships, so the product is recognizable with the logo
  removed. The soft drop shadow under the map and panel is gone; the
  border does that work.

### Fixed

- **`/api/targets/<target>/data` lost per-section stats to a partial cache.**
  The endpoint read the materialized `section_cell_stats` table with a query
  of its own instead of the shared reader every other surface uses, so a cache
  covering only some of a target's sections served buckets for those and none
  for the rest, and a database predating the table failed with `no such table`
  where `/api/targets/<target>/stats` still answered. Both now fall back to the
  live `cells` aggregation, as `/stats` and Potato Mode already did.
- **Numbers in a query string were read in whatever digits the operator's
  locale used.** `?size=٤٠٩٦` served a 4096-byte slice, `?page=1_0` opened
  page 10, and a batch VA list accepted `"١٠"` as address 16, because `int()`
  takes digits from the whole Unicode Nd/Nl/No sets and the `_` separator.
  Every integer a request supplies now goes through one ASCII-only parse
  (`?size=`, `?offset=`, `?limit=`, the batch VA list, and Potato Mode's
  `?page=` and `?idx=`), matching the rule every `RECOVERAGE_*` integer
  already followed; anything else is the 400 or the default it always was.
- **Potato Mode could cache a grid from before a rebuild under the fingerprint
  that superseded it.** The grid and per-section-stats memos took their change
  token from inside the render's pinned read snapshot, so a `rebrew build-db`
  committing midway was read as the new fingerprint on both sides of the
  publish check, matched, and filed the previous build's cells where every
  later request looked for the new ones. The grid then showed pre-rebuild
  coverage with no rebuild left to invalidate it. The render now takes its
  token before the connection opens, as the API surfaces already did.
- **`POST /api/regen` no longer 500s on a non-UTF-8 `Idempotency-Key`.** Every
  other request header goes through the guarded reader, which answers absent
  for a value the WSGI layer cannot decode; this one read the environ entry
  directly, so a client sending a latin-1 byte in the header got a traceback in
  the log and an HTML 500 instead of the documented 400.
- **Potato Mode's function list renders an empty Size cell for a row with no
  size** instead of the literal text `None`; the Module column beside it
  already did.
- **The type gate is green.** `make type-check` failed on the tree it was
  introduced with: the serving stack's handler and server classes read four
  attributes wsgiref assigns without declaring them, and the vendored-plugin
  manifest tool read a count out of a `dict[str, object]`. Both now name what
  they rely on.
- **A Potato Mode filter pill reported the wrong state.** Each pill's row
  identity was its accesskey letter rather than the filter key, so the
  "every filter key has a pill" and "a pill toggles only its own filter"
  checks could not pass and no caller could tell the two apart. The pill
  renders and links exactly as before.
- **An IPv6 `--bind` could never listen.** `RECOVERAGE_BIND` and `--bind`
  deliberately keep the colons of an IPv6 address, but the listener inherited
  wsgiref's `AF_INET` and failed in `socket.bind()` on every platform, then
  reported "is another instance already running?" for what was an
  address-family mismatch. The server now opens an IPv6 socket when the bind
  address resolves to IPv6, so `recoverage serve --bind ::1` and `--bind ::`
  work.
- **The inlined SPA shell had outgrown the initial congestion window.** The
  three code sections and their hexagon logo, whose Copy/Open controls cannot
  paint before `detail.js` loads, had stayed in `app.js`, so the shell measured
  14,652 B brotli against the 14,600 B window: a second round trip before the
  first paint, on every visit, and one a startup log line said nothing about.
  They moved to `detail.js` alongside the grid and the hex dump, where the rest
  of the deferred work already lived, bringing the shell back to 14,075 B. The
  suite now fails on a shell that crosses the window, so it is a gate and not
  only a warning.
- **A dead database watcher is now visible in the server log.** The poller's
  first snapshot ran outside the guard that protects each poll, so a
  `coverage.db` that could not be stat'ed killed the thread with its traceback
  going to a stream nobody reads. Live reload was then off for the rest of the
  process, and `/api/health` still answered `healthy` whenever no
  event-stream client was connected. The whole loop is guarded now, and an
  escape names the condition and says live reload needs a restart.
- **`/api/health` logs a state change, not one line per probe.** The endpoint
  logged a warning on every check while the database was unreadable, so a
  monitor pointed at it filled the log with the same line and the operator
  learned to skip it. The entry into the state and the recovery are the two
  lines that carry news; every reason a probe found is named in the first one,
  and repeats stay silent.
- **Potato Mode's filter pills report their filter key again.** A pill row
  carried the filter's display letter in the slot that names which filter it
  toggles, so nothing could tell an `exact` pill from a `stub` one by key.
  The lowercase accesskey that occupied the same tuple was never read by
  anything and is gone.
- **A bind address nothing could resolve started the server anyway.**
  `RECOVERAGE_BIND` rejected an empty value but nothing else, so a trailing
  space from a unit-file quoting slip, an embedded control character, or a
  `host:port` spelling passed validation and printed in the startup banner.
  The failure arrived from the resolver inside the listener, after the DB
  watcher, the cache warmup and the browser opener had started, as an
  "is another instance already running?" message. Both sources are validated
  at startup now and exit 2 with the variable named.
- **An unreadable database answered with a plausible payload.** Every
  derived-table fallback (`section_cell_stats`, `section_cells_json`, the
  optional v6 columns) caught the whole `sqlite3.Error` to degrade on a
  database that predates them, which quietly widened "this table is absent" to
  "this database cannot be read". A locked or truncated `coverage.db`
  therefore produced a correct-looking cells-derived `/stats`, `/data` or
  Potato map header, with no log line and nothing in the response saying the
  read had failed. The fallbacks now apply only to a genuinely missing schema
  object; anything else reaches the 503 `db_unavailable` contract those
  surfaces already give the same database, and a function panel renders
  without its verification rows only when there is genuinely no verify record.
- **A broken request body was reported as malformed JSON.** `POST
  /api/targets/<target>/functions` turned a failed body read into an empty
  body, so a client whose connection dropped mid-transfer was told "Body must
  be a JSON object" and pointed at its own payload for a fault it could not
  see. A read that fails is now named as one, and logged.
- **A rejected auth cookie was silent.** If the `Set-Cookie` for a share link
  was refused, the reader was authenticated for exactly one request and 401'd
  on every link after it, which reads as a broken server. The page still
  renders; the log now says what happened.
- **`/api/targets` and Potato Mode's open failure logged no cause.** Both
  reported "database unavailable" with the path alone, so a missing, locked
  and corrupt database were indistinguishable without reading the source. Both
  now log the exception class and message, as the API's 503 path already did.
- **A partially populated cache dropped whole sections.** The dashboard
  prefers `section_cell_stats` and `section_cells_json` over re-deriving them
  from `cells`, and it decided which to use by asking whether they exist. A
  database carrying a current-codec cache that covers only some of a target's
  sections passed that check, so the sections it omitted were never read from
  anywhere: they reported no coverage in `/stats` or the Potato map header, and
  their grid rendered as a section of entirely `none` bytes. Every read now
  takes the union of the cache and the sections it should have covered, filling
  only the gap and only from `cells`.
- **Potato Mode lost the `--token` credential on the first click.** The
  share link (`?token=`) set the browser cookie on `/` only, and every link
  Potato Mode renders is relative, so a reader who arrived at
  `/potato?token=...` got the page once and the 401 page on every link
  afterwards. Both page routes now set the cookie, from one shared helper.
- **A byte count was read with the wrong base.** `?size=` and `?offset=` went
  through `int(value, 0)`, which rejects a zero-padded decimal (`size=064`)
  and accepts the `0b`/`0o` spellings these endpoints never documented. Both
  now take a decimal count or a `0x`-prefixed hex one, as the query-parameter
  rules say.
- **`/asm` reported a missing original binary as a 422 in its text form.**
  The text representation and `format=json` disagreed for the same request:
  against a target with no binary configured, `format=json` answered 404
  `DLL not found` (as `/sections/<section>/bytes` does) and the default text
  form answered 422 "not enough bytes in DLL". That reads as an address past
  the end of the section and sends the caller looking in the wrong place. The
  binary is now resolved once, before the format branch, so both forms answer
  the same 404 with the `[targets.<id>].binary` hint, and the 422 is left to
  mean what it says: the window really did run past the loaded binary's end.
- **A refused `/src/` or `/original/` path answered a bare word under
  `text/html`, with no `Cache-Control`.** The traversal and NUL refusals wrote
  `b"forbidden"` / `b"not found"` directly, so a shared cache was free to store
  and replay the refusal, and a client parsing the server's error contract had
  a second format to special-case. Both now answer the same
  `{"error", "code", "detail"}` envelope every other failure uses, with
  `Cache-Control: no-store`.
- **The DB freshness stamp could report a rebuild before it happened.** The
  stamp is the database file's mtime, converted with `mtime_ns / 1e9`, and a
  float second cannot hold a nanosecond: the conversion rounded to the nearest
  whole second, so a file written at `12:34:59.999999999` was reported as
  `12:35:00`, and Potato Mode's `HH:MM` footer carried that into the displayed
  minute. Both surfaces now convert with integer arithmetic, which truncates,
  the only direction a freshness stamp may err in. `/api/health`'s `mtime` and
  `mtime_utc` also come off that one conversion, so the two fields in the same
  object can no longer disagree by a rounding step.
- **Log lines carried a time of day and nothing else.** `23:59` and `00:01`
  read alike, and a log spanning a fall-back transition printed its repeated
  hour twice with nothing to tell the two apart. The stamp is now
  `YYYY-MM-DD HH:MM:SS+ZZZZ`, so a line can be placed on a timeline and the
  local zone is on the line rather than assumed.
- **A drive-relative `files[0]` read the wrong file on Windows.** Potato
  Mode's C-source loader rejected absolute paths and `..`, but a
  drive-relative name (`C:foo.c`) is neither, and joining it onto the
  source root resolved it against the drive's own working directory. The
  guard now keys on the path's `anchor`, which covers the drive, the
  leading separator, and a UNC share alike.
- **`/api/health`'s `mean_ms` averaged in the requests it excludes.**
  `/api/events` holds its response open by design, so its "duration" is
  connection lifetime; it is already kept out of `max_ms` and the slow count.
  The mean divided by every finished request anyway, so a browser tab left on
  the dashboard for an hour dragged the reported average down to a fraction of
  the real service time. It now averages the timed requests only.
- **A function the search box finds can be opened by name.** The name form of
  `GET /api/targets/<target>/functions/<va>` compared the symbol byte for byte,
  so a name spelled the way the user has it failed: the NFD spelling a macOS
  clipboard hands over (`e` + U+0301 against the stored `é`), a different case,
  or the ASCII spelling of a name whose `ß` casefolds to `ss`. The row the
  search highlighted 404'd on open. The lookup now compares through the same
  NFC + case fold every search uses, so all three resolve, and the stored name
  is still what comes back.
- **A crafted request could add a line to the log without a newline.** The
  escaping of control characters in request-derived log fields covered C0 and
  DEL but not the C1 controls or U+2028/U+2029, which a header value carries
  literally. A `X-Request-ID` ending in U+2028 followed by a forged line read
  as two log entries in most viewers.
- **A non-ASCII request no longer costs the log line under `LC_ALL=C`.** The
  log stream carried the locale's codec, so a CJK target id or an accented
  symbol name turned the record into a `--- Logging error ---` traceback that
  said nothing about the request. Unencodable characters are now written as
  escapes, the same treatment stdout already had.
- **A `db/coverage.db` left by an older checkout no longer fails the suite.**
  The synthetic database the DB-gated tests read is gitignored, so a copy
  written before a schema change survived with the old column units (a
  `verify_results.similarity` on the 0-100 scale) and the tests then asserted
  against data this tree no longer produces, while CI, which never has the
  file, stayed green. Outside a real rebrew project the file is now rebuilt
  every session.
- **A `Host` or `Origin` header carrying whitespace or a C1 control byte was
  parsed as a hostname.** The parser behind the DNS-rebinding allowlist, the
  CORS allowlist and the localhost-only guard on `POST /api/regen` rejected
  userinfo, escapes and C0 control bytes, but let a space, a tab or U+0080
  through to `urlsplit`, which carries it into the hostname. Such a value is
  not one a browser sends, and the normalized form could be stored in the
  allowlist and echoed back as `Access-Control-Allow-Origin`. The whole
  control range (C0, DEL, C1) and whitespace are refused now.
- **A `RECOVERAGE_PORT` in non-ASCII digits bound a port instead of
  reporting the mistake.** `int()` reads every Unicode decimal digit, so a
  fullwidth or Arabic-Indic port resolved to the number it looked like, and
  `1_0` was accepted too. The readers now require an ASCII decimal run, which
  is what the error message always claimed to want.
- **`RECOVERAGE_LOG_LEVEL` could raise a bare `ValueError` instead of a
  `ConfigError`.** A number longer than CPython's conversion limit fails the
  conversion, not the parse, so it escaped as a traceback out of every
  command. It is a bad value now, reported as one.
- **`RECOVERAGE_CORS_ORIGIN` stored an origin no browser can send.** An item
  carrying a control character can never match a request `Origin`, so `--cors`
  came up with an allowlist one entry short of what was written, silently. It
  is a startup error now.
- **The verified code-similarity reads 100x low.** `verify_results.similarity`
  is stored as a 0-1 fraction (the column CHECKs the unit interval, and
  rebrew's verify import divides its percent scale by 100), but the SPA and
  Potato Mode printed it unscaled: an 87.3% match showed as `0.9%`. Both now
  scale by 100, like the `functions.similarity` field beside it.
- **A section at file offset 0 lost its Original Bytes.** Potato Mode treated
  a `fileOffset` of 0 as "not file-backed" and dropped the byte dump and data
  inspector for every cell in such a section, while `/api/.../bytes` serves
  the same section happily. Only a NULL `fileOffset` means unbacked now.
- **`--no-color`, `NO_COLOR` and `TERM=dumb` silence every colored path.** The
  exit-2 configuration errors (a bad `--port`, a bad `RECOVERAGE_*` value) went
  out through `typer.secho` instead of the `_secho` wrapper that applies the
  opt-outs, so a red escape was written into a log that had asked for no color.
  The `stats` table is the other half: Rich detects `NO_COLOR` and
  `TERM=dumb` itself but cannot see the `--no-color` flag, so the flag now
  reaches its `Console` as well.
- **The supply-chain pin test reads the mechanism CI actually uses.** CI
  fetches the sibling rebrew through the `sibling-rebrew` composite action,
  which is the one place a job may run `tools/ci_clone_rebrew.sh`. The test
  still looked for the script path in each job body and asserted that no local
  action existed, so it failed on the correct CI configuration. It now checks
  that every installing job uses the action, that the action runs the pinned
  script, and that neither the job nor the action carries a pin of its own.
- **`--json` reports every failure in the same envelope.** `check --json`
  already answered a failed gate, a bad `--min-coverage` and an empty result
  set with `{"error": ..., "exit_code": N}` on stdout, but a missing or
  unreadable database and an unknown `--target` still printed a plain stderr
  line, leaving `recoverage check --json | jq` to fail on empty input.
  `stats --json` and `export --format json` had no envelope at all. Every
  failure in a machine-readable mode now answers the same shape on stdout;
  the human form is unchanged.
- **`recoverage stats` no longer starts its output with a blank line.** The
  first target's heading carried a leading newline that no later heading did,
  so redirected output opened with an empty line, the rule `export --format
  md` already followed.
- **`recoverage serve --help` and `recoverage open --help` no longer show raw
  reStructuredText markup.** Their descriptions wrapped flag and command names
  in double backticks, which Rich rendered literally.
- **The per-section buckets reconcile again, and `/stats` agrees with `/data`.**
  `/api/targets/<t>/stats` overwrote the materialized `exact_count` with a
  `cells`-side count of `exact` alone, while `rebrew build-db`, `/data`, Potato
  Mode and the grid palette all fold `verified` in (it is a match, and its
  bytes were already counted as covered). A database holding `VERIFIED` cells
  therefore reported a `total_cells` its buckets could not sum to, and the same
  database answered two different stats depending on whether `build-db` had
  run. The endpoint now reads rebrew's bucket definitions instead of
  restating one of them, and the live-query fallback (a database predating the
  materialized table) computes the same ones, so both paths return the same
  numbers and `total_cells` equals the sum of the buckets.
- **A failed request stays counted on its route in `/api/health`.** A request
  that failed after `after_request` had filed it as a 200 is re-bucketed into
  its real status class, but the per-route row retracted it instead of moving
  it: a route whose every request failed reported `requests: 0, errors: 3`,
  and the per-route request counts no longer summed to `total`. The route's
  error count now also follows the same 500 threshold as the process-wide one.
- **`/src/<path>` and `/original/<path>` answer 404 instead of 500 for a path
  holding a NUL.** `os.realpath` raises `ValueError` on an embedded NUL, and
  the containment check resolves the candidate before serving it, so
  `GET /src/%00` raised out of the route and returned bottle's 500 page with a
  traceback. No filename holds a NUL, so the request is now refused before the
  filesystem is touched.
- **`/api/health` reports a rebuild that committed only to the WAL.** Its
  `db.mtime` was the main file's `st_mtime`, the one remaining raw-mtime read
  in a freshness field: `coverage.db` runs in WAL mode, so a `rebrew build-db`
  that commits without checkpointing leaves that value where it was, and
  health reported a rebuild that had already happened as not yet done. It now
  reads the newest stamp across `coverage.db` and its `-wal` sibling, the same
  contract the ETags, the memos, the SSE watcher and the Potato Mode footer
  already use, and adds `db.mtime_utc`: the same instant as ISO-8601 with an
  explicit `+00:00`, so a client no longer has to assume the server's zone.
- **The event-stream 503 states one retry time, not two.** Its body said to
  retry after the poll interval while the `Retry-After` header said the
  heartbeat interval, so a client reading the header waited three times as long
  as one reading the body. Both now send the poll interval.
- **`make test` and the other `uv run` targets work on a clean clone without
  `make setup` first.** They now pass `--extra dev` the way `make setup` does,
  so a contributor who runs the loop before the bootstrap gets the tests
  instead of `No module named pytest`.
- **CI installs rebrew one way again.** Every installing job referenced
  `.github/actions/sibling-rebrew` while the file did not exist, so each job
  would have stopped at that step; the action is back, it takes the clone URL
  and never the tag or commit, and the four inline copies of the clone step,
  the second mechanism the pin test rejects, are gone. The pin lives in
  `tools/ci_clone_rebrew.sh` and the action is its only caller.
- **The payload-memo concurrency tests install the request stand-in where
  `api._query_param` reads it**, so a `?section=` filter is no longer dropped
  and the follower's memo key matches the one under test.
- **Search finds a name whatever its accents and spelling.** The search box
  (Potato Mode and the SPA) matched through SQL `LIKE`, which folds case for
  ASCII only, so `CAFÉ` returned nothing for `Café_Render` and the NFD spelling
  a macOS-side tool writes never matched its NFC twin. A term carrying a
  non-ASCII character now also compares NFC + case-folded, and a function with
  no `symbol` is no longer invisible to every search (a NULL in the `OR` chain
  made the whole predicate NULL, so `AND` dropped the row).
- **A request header carrying a non-UTF-8 byte no longer answers 500.** A WSGI
  server hands header bytes over as latin-1, so a peer can send a byte above
  `0x7f`; reading it raised `UnicodeDecodeError`, which turned one junk header
  into a 500 plus a traceback in the log, on any route. Every header read now
  goes through `server._header`, and a value that is not decodable text reads
  as absent, which is what the field-value grammar already implies.
- **The `.text` progress bar no longer mixes two denominators.** Its Exact,
  Reloc, Near-match and Stub segments are shares of `totalFunctions` (the
  `matched` stat beside them is a function count), but Padding was added as
  `paddingBytes / section size`, so a section with 900 of 1000 functions
  matched and a 20 KB padding run in 100 KB summed to 110%. The remainder
  clamped to zero, painting the 100 unmatched functions no grey at all, and
  Potato Mode's bar drew the trailing bands past the end of its track, where
  the rounded-corner clip cut them off. Every segment of a bar now shares one
  denominator, and Padding (a cell state with no function counterpart) is a
  segment only on the byte-counted bars. Potato Mode's bar additionally clamps
  to its own track, so no segment list can draw past it.
- **A grid cell wider than one row no longer overruns it in the SPA.** The hit
  map wrote the run's columns from the cell's position, spilling into the next
  row (where the typed array dropped them, leaving the tail unpaintable and
  unclickable), and a run of 65536 stored as 0 in the `Uint16Array` span column
  drew a negative-width rect. A run is now capped to the column count, which
  is all a single row can show, and floors at one column.
- **The SPA grid is re-laid out when a rebuild re-spans a section.** Layout
  was memoized on `(column count, cell count)`, and a rebuild that moved a
  cell's start without changing how many there are left the key matching: the
  stale hit-map and rect geometry mis-painted the section and handed a click
  the wrong cell. The memo now keys on the packed cell object itself, which
  `packSection` returns fresh per section version and after a lazy cells
  fetch, so identity is exactly "the cells changed". A section that declares
  a different column count after a rebuild also re-wraps, which a
  `getComputedStyle` read of the old width could not catch.
- **The function list's `total` and its page come from one version of the
  database.** The endpoint runs the `COUNT(*)` and the page `SELECT` as two
  separate statements, and Python's sqlite3 opens a deferred transaction per
  statement, so a `rebrew build-db` committing between them answered with one
  build's row count beside the next build's rows: the SPA then paginated
  against a total the rows did not match. Both now run inside a pinned
  snapshot, the same read the `/data` and `/stats` endpoints use.
- **Clicking a cell no longer lets a slower earlier selection win.** Selecting
  a cell with no function started a `/asm` request that was never tied to the
  selection, so a response landing after the user had already clicked
  elsewhere overwrote the assembly pane with the previous block's
  disassembly. Every cell selection now supersedes the one before it, and the
  undocumented-block request is aborted along with the rest.
- **The first Reload click after opening the dashboard regenerates.** The
  client-side cooldown stored the previous click as `0` and compared it
  against `performance.now()`, which counts from page load: a click in the
  first five seconds of a page read as a click inside the window, so the
  regen was skipped and the UI reported the cooldown instead. The server
  had the same shape for `/api/regen`'s cooldown, which counts from boot:
  a process started seconds after a reboot rejected its first POST as rate
  limited. Both now keep "never clicked" as a distinct state.
- **Target ids, section names and file paths with a space or a non-ASCII
  character resolve again.** Bottle routes on the raw request path and
  decodes query values as latin-1, so `/api/targets/caf%C3%A9/stats` looked up
  the target `caf%C3%A9` and `?section=%C3%A9` compared against `Ã©`; every
  such target 404'd, Potato Mode's own escaped links included, and a source
  file named `naïve name.c` was unreachable. Path captures are now
  percent-decoded once as UTF-8 (`server.path_param`, applied before the
  `/src/` containment check) and query values once through
  `server.query_param`, so both halves of a request read the same text. The
  SPA encodes every DB-derived value it splices into a URL the same way.
- **`export` and `check` write UTF-8 whatever the locale says.** Both write
  target ids and section names taken from the PE image; under a non-UTF-8
  stdout codec the write raised `UnicodeEncodeError` part-way through and
  left a truncated file behind the `> coverage.csv` redirect the help text
  documents.
- **Switching to a section tab in the SPA says what is happening.** A sibling
  tab fetches its own cells on the first visit, and until they land the map
  area was an empty frame; a failed fetch left it empty for good, with nothing
  to click and nothing said. The map now shows a loading line while the cells
  are in flight and, when the fetch fails, what went wrong plus a Retry button.
- **The SPA's cell hover title says what the cell is.** It ended in a `1 fn` /
  `0 fn` flag that told the reader nothing; it now carries the state name and
  the function, in the same wording as the legend and as Potato Mode's tooltip.
- **Potato Mode's function list explains an empty result.** It printed "No
  functions found." whatever emptied it, with no sign the active search or
  status filter was the cause; it now names the query and links to the same
  list without it. The grid's search line also gained the SPA's "no matches.
  Check the spelling, or search by VA." guidance.
- **Potato Mode's Parent link opens the parent's block.** It went to a search
  for the parent instead, and the raw name went into the query string, so a
  mangled name carrying `&` or `?` split the URL. It now selects the parent's
  own block, URL-quoted, falling back to a search when the parent has no block
  in that section.
- **Functions with an unknown `markerType` are listed again.** The
  GLOBAL/DATA/VTABLE/STRING exclusion read `markerType NOT IN (...)`, and
  SQLite evaluates `NULL NOT IN (...)` to NULL, which `WHERE` rejects: on a
  `coverage.db` whose `functions.markerType` is nullable, every unmarked
  function dropped out of the SPA list, the Potato Mode function table, and
  the per-status counts. The filter is now one shared SQL fragment
  (`server.NOT_DATA_MARKER_SQL`) that keeps the NULL arm.
- **`/data` and `/stats` read one version of the database.** Both assemble
  their answer from several statements, and Python's sqlite3 opens a
  deferred transaction per statement, so a rebuild committing mid-request
  paired one build's section rows with the next build's cells. Each read now
  runs inside a pinned snapshot.
- **A Potato Mode address copied out of a table now matches in the search
  box.** The address columns print VAs zero-padded to eight digits
  (`0x00401000`) but the search predicate compared against the unpadded
  `0x401000`, so pasting a padded address found nothing. Both the Functions
  view and the grid's global dimming set match either spelling.
- **`--no-color`, `NO_COLOR`, and `TERM=dumb` are honored.** Colorized errors,
  warnings, and `check` verdicts carried ANSI escapes on a terminal even with
  `NO_COLOR` set, because click only strips escapes from a non-TTY stream. The
  global `--no-color` flag is the explicit opt-out; the environment variables
  are the convention. The opt-outs only ever force color off, so a piped run
  stays plain as before.
- **`check` keeps one report on one stream.** A section skipped for not
  existing was written to stderr while the PASS/FAIL verdicts went to stdout,
  so `check 2>/dev/null` silently dropped the sections it declined to gate.
  The skip note now follows the output mode: stdout with the other verdicts,
  stderr under `--json`, where stdout carries the payload alone.
- **`export --format md` no longer starts with a blank line.** The first
  target's heading was preceded by the separator newline that separates
  targets, so `recoverage export --format md > coverage.md` produced a file
  opening on an empty line.
- **`export --help` renders as prose.** The docstring's line-ending note was
  read as a line break by the rich help renderer, splitting the sentence
  about CSV row endings and leaving a stray quote in the help text.
- **A wrong HTTP verb on a real endpoint answers 405, not 404.** The
  path-agnostic catch-all that keeps unknown URLs from answering 405 also
  swallowed the distinction: `POST /api/health` and `GET /api/regen` both
  described resources that exist, and a client branching on 404 (stop, drop
  the resource) against 405 (try another verb) was mis-told either way. They
  now answer `405` with the `Allow` header, in the same JSON envelope as every
  other failure. A verb outside the catch-all's list is rejected before any
  handler runs and used to land on bottle's HTML error page; `/api/*` now gets
  the JSON envelope there too.
- **`?format=` on `/asm` rejects an unknown representation.** `format=jsom`
  answered 200 with the text body, so a client's typo read as a successful
  request carrying a shape it cannot parse. It is a 400 naming the accepted
  values, the value is matched case-insensitively, and an empty `format=` is
  still the default.
- **A rejected query parameter says which one and why.** The `400`s from
  `/asm` and `/sections/<section>/bytes` carried a fixed `error` string
  (`invalid va or size`, `invalid size`, `size must be positive`, `offset
  beyond section bounds`) with an empty `detail`, so a client could tell the
  request failed but not which field to fix. `detail` now carries the
  rejected value and the range it has to satisfy.
- **Coverage buckets reconcile with `total_cells`.** `/stats` and `/data`
  section objects carry an `other` bucket matching rebrew's catch-all
  (`compile_error`, `extract_error`, `invalid_va`, `missing_file`,
  `missing_size`, `skip`, `unknown`, `drift`, `unchecked`). A consumer summing
  the documented buckets now gets `total_cells` instead of a residual it read
  as zero-sized. Both query paths compute it, and a `section_cell_stats` that
  predates the column reports 0 rather than dropping the key.
- **Every cell state rebrew can write is colored.** `verified`, `drift`,
  `unchecked` and the nine problem states fell through to the `none` color and
  painted as undocumented gaps, which contradicts the number printed beside
  them: `build_db` counts `verified` as an exact match and `covered_bytes`
  covers every state that is not `none`. Both legends gained a `problem` row,
  and Potato Mode's gained a `proven` row.
- **The SPA search box reports and acts on its own state.** It gained a clear
  button, a live match count, Enter to jump to the first match, and Escape to
  clear. Clearing the state alone left the typed text in the (uncontrolled)
  input while the map stopped filtering.
- **A failed function lookup no longer leaves stale panes.** The Assembly pane
  read "Loading assembly..." forever and Copy/Open stayed enabled, so a
  lookup for a VA the database does not carry copied that literal.
- **Potato Mode hex search matches the addresses it prints.** Both the
  function-list filter and the cell dimming test built the VA string with
  `printf('0x%x', va)`, which emits no `0x` prefix, so an address copied out
  of a VA column never matched when pasted back. They now emit the same
  `0x`-prefixed spelling the column prints.
- **SSE client slots are released on every exit path.** A peer that hung up
  between the handler returning and the first write lost a slot, a file
  descriptor and a handler thread for the process's remaining lifetime,
  permanently eroding the concurrent-client cap.
- **Potato Mode never publishes a stale read into its caches.** The grid-cell
  and section-stats memos filed a payload under the new snapshot fingerprint
  even when the cursor's read snapshot predated a rebuild that a broadcast had
  already invalidated, so the stale entry survived until the next rebuild.
- **The regen cooldown notice times itself out.** "Regenerating from cache"
  and "regenerate unavailable" replaced the stats row and, unlike the loading
  state, had nothing clearing them, so a second click in quick succession
  looked like it did nothing.
- **`export --format md` emits a well-formed table.** Each section row wrote
  eleven cells (the exact/reloc/near-match triple twice) under an
  eight-column header. A test asserts every data row has the header's count.
- **`rebrew catalog --json` no longer appears in the documented pipeline.**
  That flag suppresses the data-JSON write: it only prints a summary. The
  quickstart, the pipeline diagram, the design docs, the user stories, and
  the CLI's own rebuild hint all named the summary-only form. Every one now
  shows the bare `rebrew catalog`, which is what `regen` actually runs.
- **Potato Mode responses carry a cache directive.** `/potato` was the one
  DB-derived response sent with no `Cache-Control` at all, leaving
  heuristic freshness to the browser and leaving a shared cache free to
  store and replay a page rendered for a token-bearing client. It now
  sends `no-cache, must-revalidate`, keeping the ETag's cheap 304s.
  The Potato 500 page and the HTML 401 token challenge now say `no-store`
  like every other error response.
- **Target ids are escaped in the DLL loader's warnings.** `target` is
  routable request data and originates in analyzed binary names, so a
  control character in it could forge a log line; the loader's warnings
  now route it through `_log_safe` like the rest of the request log.
- **`export --format csv` survives a non-ASCII section name.** Target and
  section names come from analyzed PE binaries, and the CSV writer wrote
  through `sys.stdout` with whatever codec the locale names, so a name with
  one accented character raised `UnicodeEncodeError` part-way through the
  export and left the redirected file truncated mid-row. The writer is now
  pinned to UTF-8, keeping the bare-`\n` line terminator contract.
- **The function source panel survives an undecodable byte.** A C source
  with a single Windows-1252 byte in a comment (0x92 is the common one)
  failed the whole UTF-8 read and the panel rendered empty. The byte now
  decodes to U+FFFD in place and the rest of the file stays readable.
- **SPA search matches non-ASCII spellings.** The grid search compared with
  `toLowerCase()`, so an NFD query from a macOS input method missed the NFC
  name in the database, and `STRASSE` never found `Straße`. Both sides are
  now composed to NFC and compared through a root-collation scan.

### Removed

- `app.js` `detailBound()` and its two spread sites: both `disabled` and
  `title` were overwritten in the same object literal, so it contributed
  nothing.
- `detail.js` `walk()`'s return value, never read; the row count is derived in
  `layout()` where the map is sized.
- `potato.py`'s `TRANSPARENT_GIF=TRANSPARENT_GIF` render kwarg: the variable
  appears in no template, so bottle discarded it.
- `server.py`'s `_STATUS_ERROR_CODES[504]`: no code path returns 504.
- The `--cell-border` custom property in both `style.css` themes: never read.

## [1.6.0] - 2026-09-27

Requires `rebrew>=2.10.0`.

### Fixed

- **Regen imports `run_catalog` from `rebrew.catalog.cli`.** Since rebrew 2.7
  the `rebrew.catalog` package does not re-export it, so `recoverage regen`,
  `serve --regen`, and `POST /api/regen` raised `ImportError` against current
  rebrew.
- **The function list skips `VTABLE` and `STRING` rows.** Potato and the
  stats query already treated those markers as data. `/api/targets/<target>/functions`
  only excluded `GLOBAL` and `DATA`, so vtable and string rows were listed
  as functions.
- **Schema v8, v9, and v10 are accepted.** Current rebrew stamps `db_version`
  `"10"`. v8 CHECK-constrains `functions.status`, v9 CHECK-constrains
  `cells.state` and adds `idx_metadata_key`, and v10 stores `extract_error`
  and `invalid_va` as cell states. None of those add or remove a column this
  server queries. The column gate applies to every known version except v3.
- **The live cell-JSON fallback uses `SECTION_CELLS_AGG_SQL`.** That is the
  ordered aggregate `build-db` writes into `section_cells_json`
  (`json_group_array` of the shared projection, `ORDER BY start`).
- **Database reads use the same read-only setup as `open_sqlite_ro` and
  hold `coverage_db_lock` shared until `close`.** `mode=ro` and `query_only`
  reject writes. `build-db --force` waits for the shared lock before
  unlinking the file.

## [1.5.0] - 2026-09-17

Requires `rebrew>=2.4.0`: the cell projection, the `cells_zstd` codec and the
v7 schema objects all ship from `rebrew.workspace`, and `server.py` imports
`CELLS_JSON_OBJECT_SQL` at module scope.

### Changed

- **Static assets are compressed and memoized.** `detail.js`, `app.js`,
  `style.css`, `print.css`, `van.min.js`, `favicon.svg` and the three
  `hljs` files were served raw by `static_file`; they now ship with the same
  content negotiation as every other response, compressed once per encoding at
  maximum brotli effort and cached for the process. `detail.js` drops from
  25 KB to 9 KB on the first-paint path and the asm-pane set from 153 KB to
  45 KB.  Requests without a supported `Accept-Encoding` still fall through to
  `static_file`, so Range and `If-Modified-Since` behave as before.
- **Cell JSON no longer carries `cells.id`.**  The served cell object lost the
  `id` key, so a consumer reading `cell["id"]` fails from this release on;
  anchor on `start`, which is stable per cell.  A removed response field is a
  major under the release policy, and this one shipped in a minor.  No consumer
  read the key, and as the
  only high-entropy column per row it was defeating compression: the 39k-cell
  `.text` payload goes from 322 KB to 74 KB on the wire (a 39k-cell section's
  full-target payload from 518 KB to 124 KB).  The projection is now the shared
  `rebrew.workspace.CELLS_JSON_OBJECT_SQL`.
- **`/data` and Potato read rebrew's materialized objects.**  The per-section
  cell JSON (`section_cells_json`, schema v7) and coverage buckets
  (`section_cell_stats`) are read directly instead of being re-derived, and the
  server falls back to the equivalent live queries when a database predates
  them, so a v6 database keeps serving.  The cache's codec is identified by its
  column name (`cells_zstd`), not by `db_version`, so a table written in an
  older codec is declined rather than mis-decoded.  Cold `/data` build:
  24.8 ms → 3.4 ms for one section and 38.9 ms → 6.8 ms for all sections, with
  payloads identical apart from the `db_version` stamp.
- **Schema v7 accepted.**  `known_schema` in the `/data` payload now advertises
  `3`–`7`, so a v7 database is not reported as an unknown schema.
- **`/stats` reads the materialized coverage buckets.**  Per-section byte
  counts come from `section_cell_stats` in one query instead of a 13-branch
  `CASE` aggregate over every cell, falling back to that aggregate for a
  database without the table.  Cold `/stats`: 17.1 ms → 7.2 ms (p95 19.0 →
  8.5 ms), field-for-field identical — `exact_count` still counts only
  `'exact'`, while the grid legend keeps folding `'verified'` into it.
- **The SPA's detail panel fills in when you select something.**  At first
  paint nothing is selected, so the three code panes used to lay out stand-in
  text and copy buttons for nobody; the panel body now holds one muted line
  until there is a selection.  The boot layout walks 147 objects instead of
  205 and the document starts 58 nodes smaller.  Selecting a block, a
  function, or a `?fn=` deep link renders the panes as before.

### Fixed

- **Potato Mode and the SPA now open the same target.** `resolve_targets`
  returns two differently-ordered lists — `target_ids` (raw DB order) and
  `targets` (config-declared first) — and Potato rendered its dropdown from the
  second while defaulting from `target_ids[0]`.  On a project whose config order
  differs from its metadata order the two surfaces disagreed, and Potato's
  selected target was not even its own dropdown's first entry.  Potato now
  defaults from the same list the SPA's `/api/targets` serves.

## [1.4.1] - 2026-09-16

### Fixed

- **SPA progress stats never clip.** The stats sit above the bar as wrapping
  plain text and the bar is a slim 14px segment strip, so every viewport —
  1440px desktop to 390px phone — shows `size · matched · coverage %` where
  the old in-bar overlay truncated mid-word.
- **SPA Copy/Open stay disabled on empty panes.** Copying `(select a
  function)` or opening a modal of it is never useful; the buttons disable
  with a "Select a block first" hint until a real selection lands (and while
  `detail.js` is still loading).
- **Canvas map no longer paints a phantom row.** Sections whose cells fill
  the last row exactly rendered one extra blank row (~250px of empty grid on
  the test DB). Row count now matches the layout walk.
- **Potato progress bar fits phones.** The fixed 700px bar overflowed narrow
  screens and clipped its stats; it is fluid-width with the stats in a cell
  below, and the map header stats wrap to their own line.
- **Potato layout stacks map over panel.** The fixed 75/25 split forced the
  page past 500px on a 390px phone, clipping both columns; stacked, each
  takes the full width (like the SPA below 1300px). Grid cells are 12px.
- **Potato detail panel drops empty rows.** NULL/empty fields (`ghidra_name
  None`, `similarity None`, …) no longer bury the populated rows; the
  duplicate `Functions for .text` caption is gone; the legend is a
  two-column nowrap lattice; section tabs lead with `.text` (PE load order).

## [1.4.0] - 2026-09-15

### Changed

- **Coverage map paints on a canvas.**  The SPA no longer builds one DOM node
  per cell (tens of thousands on a real target).  The map is packed into typed
  arrays and drawn in one pass; click, keyboard, tooltip, filters, and print
  still work.  First paint no longer waits on the original binary download.
- **`/data` skips a JSON round-trip of the cells table.**  SQLite already
  emits each section's cells as JSON; the envelope splices those arrays in
  instead of `json.loads` + `json.dumps` (~70 ms saved on an 80k-cell DB).
- **SPA first paint fetches one section.**  `GET /data?section=.text` still
  lists every section (tabs, stats) but omits sibling cell arrays; the map
  loads the rest when you switch tabs or jump to an address.
- **Potato grid merge avoids per-cell dict copies.**  One copy per merged
  output row instead of one per input cell; `?section=.text` stats query is
  filtered too (first paint `/data` 27 ms → 22 ms on a 64k-cell DB).
- **Canvas map caches layout and palette.**  Hit-map, row table, canvas size,
  and CSS palette are built once per section and reused; filter/search/focus
  repaints only redraw rects, and jump-to-cell scroll is O(1).  Repaint
  ≈ 21 ms med in Chromium on a 39k-cell map (incl. a frame wait).
- **Live reload no longer flashes the map.**  Background refresh (SSE
  `db-updated`, regen) keeps the old map visible and swaps when new data
  lands; the loading overlay and error panel are first-paint only.  Verified
  in Chromium: zero overlay flashes across a real rebuild.
- **Original binary loads on first click, not first paint.**  The multi-MB
  `/original` download moved from `loadData` to first cell selection, cutting
  first-load transfer ~3.2 MB → ~0.35 MB on a real target; the bytes pane
  shows loading state until the slice arrives.

### Fixed

- Python floor is now 3.13 (was 3.12): the required `rebrew` dependency
  raised its own floor, and fresh installs on 3.12 could no longer resolve.
  CI matrix and classifiers follow.

## [1.3.0] - 2026-09-13

### Changed

- Workspace resolution moved from the standalone `rebrew-workspace`
  distribution into `rebrew.workspace`; recoverage imports `rebrew.workspace`
  for `rebrew-project.toml` + coverage.db resolution.
- rebrew is now a required dependency rather than the optional `regen` extra.
  The `regen` extra is gone, `recoverage regen`, `serve --regen` and
  `POST /api/regen` work on a plain install, and the "install the extra" hint
  is gone.  A regen failure still exits 1 (or answers HTTP 500).

## [1.2.0] - 2026-09-13

### Changed

- **Regen calls rebrew in-process instead of spawning its CLI.**  `recoverage
  regen`, `serve --regen` and `POST /api/regen` load `rebrew-project.toml` once
  and call rebrew's `run_catalog` + `build_db` module functions inside the
  dashboard process, replacing the `rebrew` console-script subprocess (and its
  120-second timeout and process-group kill) introduced in 1.1.1.
  `RECOVERAGE_REBREW` is gone.  There is no timeout any more, so a regen always
  runs to completion, and the dashboard's threaded server keeps answering
  requests while it works.  `POST /api/regen` reports a failure as HTTP 500;
  the 504 timeout response is gone.
- rebrew is now an optional dependency, the `regen` extra (`pip install
  'recoverage[regen]'`).  Without it the regen commands exit 1 (or answer HTTP
  500) with an install hint; every other command keeps working without rebrew.

## [1.1.1] - 2026-09-13

### Fixed

- **Regen runs `rebrew` directly instead of `uv run rebrew`.**  The dashboard
  and `POST /api/regen` invoke the `rebrew` console script resolved from `PATH`
  (`RECOVERAGE_REBREW` overrides it), the way reportal resolves its engine.
  `uv run` is a developer toolchain runner: it resolves and may rewrite the
  workspace environment, needs uv and the network, and fails outright when the
  workspace pins a uv other than the installed one.  A missing `rebrew` now
  reports `rebrew not found on PATH; install it or set RECOVERAGE_REBREW`.

## [1.1.0] - 2026-09-13

### Added

- `/api/targets/<target>/data` carries `known_schema`: the schema versions this
  build understands (the server's `KNOWN_SCHEMA_VERSIONS`).  The addition is
  additive; the existing fields are unchanged.

### Changed

- Recoverage resolves `rebrew-project.toml`, the `db/coverage.db` path, the
  schema stamp and the read-only DB URI through the shared `rebrew-workspace`
  package, so the dashboard and rebrew cannot drift on the same workspace.  No
  command, route or on-disk format changes.
- The inlined index payload is back inside the initial TCP congestion window.
  The assembly fetch, its error formatting, and the highlight.js loading and
  highlighting moved from the inlined `app.js` into the deferred `detail.js`
  (about 500 compressed bytes).  Nothing changes visually: the Assembly pane
  fills in as soon as `detail.js` lands, the way the hex and data panes already
  did, and asm operand links still jump to their address.

### Fixed

- The SPA no longer hardcodes the schema versions it accepts.  It was pinned at
  3/4, so a v5 or v6 database with no section rows was reported as "this build
  does not understand the schema" (rebrew writes 6 today).  It now reads the
  payload's `known_schema`, and uses the neutral wording when the server does
  not send one.

## [1.0.0] - 2026-09-12

First stable release.  From 1.0.0 the HTTP API, the CLI, and the
`coverage.db` schema recoverage reads are frozen: a breaking change takes a
major version bump.

### Added

- Function detail panels (SPA **and** Potato mode) now show the latest
  `rebrew verify` record: `last_verify.similarity` (0–100 code-similarity
  score) alongside the existing byte-delta / diff-line count.  The score is
  read from the new `verify_results.similarity` column.

## [0.2.0] - 2026-08-18

### Added

- `/api/events` SSE stream — pushes `db-updated` when `coverage.db` changes;
  the SPA auto-refreshes (server now runs on a threaded WSGI server so the
  stream never blocks the dashboard).
- Batch function lookup: `POST /api/targets/<target>/functions` with
  `{"vas": [...]}` returns details in input order (incl. `last_verify`).
- Optional `--token` auth: `Authorization: Bearer`, `?token=`, or open
  `/?token=<token>` to set an HttpOnly cookie so the SPA works unchanged.
- `recoverage check --json` / `stats --json` — machine-readable output;
  infra errors exit 2 (database missing/unreadable).

### Changed

- All API error responses are standardized to
  `{"error", "code", "detail"}` (e.g. `not_found`, `rate_limited`).
- `--allow-remote` required to bind non-loopback; SSE streams capped at 32
  concurrent clients (thread-DoS guard); ETags are hashes of their
  components (no raw request strings in headers); static `/src`/`/original`
  serving resolves symlinks and verifies containment; JSON errors carry
  `Cache-Control: no-store`.
- `/api/targets/<t>/functions/<va>` accepts decimal VAs (the list emits
  `va` as an int — the round-trip previously 404'd); `/data?section=`
  with an unknown section 404s; memo/ETag/watcher are WAL-aware.

## [0.1.0] - 2026-08-08

First tagged release.  Recoverage is a coverage dashboard for binary-matching
decompilation projects: it serves the `coverage.db` produced by
`rebrew build-db` as a web dashboard, with a modern SPA and a retro
server-rendered "Potato Mode".

### Added

- **Dashboard**: VanJS SPA with a per-byte coverage grid (exact / reloc /
  near-match / stub / padding / data / thunk states), section tabs, search,
  status filters, and function detail panels (badges, C source, disassembly,
  hex inspector).
- **Potato Mode**: `/potato` — a pure server-side HTML table fallback with
  keyboard accesskeys, prev/next navigation, and the same detail panels.
- **REST API**: `/api/health`, `/api/targets`, per-target
  `stats`/`data`/`functions`/`functions/<va>`/`asm`/`sections/<section>/bytes`,
  and localhost-only `/api/regen` (re-runs `rebrew catalog` + `build-db`).
- **CLI**: `recoverage serve` (`--port`, `--bind`, `--no-open`, `--regen`,
  `--cors`), `stats`, `export` (JSON/CSV/Markdown), `check` (CI gate),
  `open`, `regen`.
- **Coverage DB support**: schema v4 (cells with label/parent_function,
  `section_cell_stats` view, functions with Ghidra/list names and thunk
  markers, verify_results imported by `build-db`).
- Function detail surfaces the last `rebrew verify` record (`last_verify`).
- Schema parity with rebrew is now pinned on the rebrew side:
  `tests/test_recoverage_contract.py` runs the real `catalog --data-json` →
  `build-db` pipeline on the fixture binary and asserts every table/column
  recoverage queries exists (cells.label/parent_function, verify_results,
  section_cell_stats view, ...), so a rebrew change that would break the
  dashboard is caught in rebrew's own suite.
- `tools/smoke.py` — end-to-end server smoke for CI: builds a synthetic
  `db/coverage.db` (the shared rebrew build-db schema v4), boots
  `recoverage serve`, and probes the SPA shell, health, targets/data/stats/
  functions APIs, and Potato Mode (7 probes).  `--expect-failure` asserts a
  corrupt DB is reported as `degraded` health rather than served as healthy.
  Wired into CI as a `smoke` job.
- **Deep-linking** — the SPA reads `?target=&fn=&section=&q=` from the URL
  (restoring state on load, `fn` winning over the localStorage last-function)
  and keeps the URL in sync on every change via `history.replaceState`.
  Reloads restore the selected function/section/search; links are shareable.

### Changed

- DB-gated tests now run in CI: a synthetic `coverage.db` is built by the
  test conftest when none exists (previously 57 tests silently skipped).
- C-source paths resolve against the project dir via `paths.sourceRoot` from
  `rebrew catalog` (previously anchored inside the package and never loaded).
- `/api/regen` has a server-side cooldown (429 + `retry_after`) matching the
  UI's throttle; the functions list and by-status stats exclude GLOBAL/DATA
  marker rows; search also matches hex `vaStart`.

### Fixed

- Potato Mode detail panel: `% if` template directives are now line-scoped
  (the Label row no longer always renders), and cell function entries (VA
  strings) are looked up by VA like the SPA/API, not by name.
- ETag caching: header lookup is case-insensitive; stale potato test
  assertions (accesskeys, detail markup) corrected to the shipped renderer.
- Potato Mode now emits a `<main>` landmark (with the existing skip-link) and
  `<caption>` on the coverage-map and functions tables — screen readers get
  table semantics instead of anonymous grids (impeccable audit).
- Icon buttons get a 44×44px touch target on coarse pointers
  (`@media (pointer: coarse)`) — desktop layout unchanged, WCAG 2.5.8 met on
  mobile (impeccable audit).
