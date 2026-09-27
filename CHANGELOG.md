# Changelog

All notable user-visible changes to Recoverage are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Tag this **2.0.0**: `server.resolve_targets` changed its return shape and the
module ships in the published package. See *Breaking*.

### Added

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

### Changed

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
  `tools/flatten-rikalabs-strict.py` refuses to regenerate the preset if a
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

### Fixed

- **Potato Mode and the SPA now open the same target.** `resolve_targets`
  returns two differently-ordered lists — `target_ids` (raw DB order) and
  `targets` (config-declared first) — and Potato rendered its dropdown from the
  second while defaulting from `target_ids[0]`.  On a project whose config order
  differs from its metadata order the two surfaces disagreed, and Potato's
  selected target was not even its own dropdown's first entry.  Potato now
  defaults from the same list the SPA's `/api/targets` serves.

### Changed

- **Static assets are compressed and memoized.** `detail.js`, `app.js`,
  `style.css`, `print.css`, `van.min.js`, `favicon.svg` and the three
  `hljs` files were served raw by `static_file`; they now ship with the same
  content negotiation as every other response, compressed once per encoding at
  maximum brotli effort and cached for the process. `detail.js` drops from
  25 KB to 9 KB on the first-paint path and the asm-pane set from 153 KB to
  45 KB.  Requests without a supported `Accept-Encoding` still fall through to
  `static_file`, so Range and `If-Modified-Since` behave as before.
- **Cell JSON no longer carries `cells.id`.**  No consumer read it, and as the
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

### Fixed

- Python floor is now 3.13 (was 3.12): the required `rebrew` dependency
  raised its own floor, and fresh installs on 3.12 could no longer resolve.
  CI matrix and classifiers follow.

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

### Added

- `/api/targets/<target>/data` carries `known_schema`: the schema versions this
  build understands (the server's `KNOWN_SCHEMA_VERSIONS`).  The addition is
  additive; the existing fields are unchanged.

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
