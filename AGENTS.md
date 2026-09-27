# AGENTS.md — recoverage

## Overview

**recoverage** is a coverage dashboard for binary-matching decompilation projects.
It serves a VanJS + SQLite dashboard visualising per-byte match status across
PE sections (`.text`, `.data`, `.bss`). Two modes: a modern SPA (default) and
a retro "Potato Mode" that renders entirely in server-side HTML tables.

This package is a **consumer** of data produced by `rebrew`, which it depends
on as a library: `rebrew.workspace` provides the shared `rebrew-project.toml` +
`coverage.db` resolution (stdlib only), and the regen commands call rebrew's
`run_catalog` (`rebrew.catalog.cli`) and `build_db` in-process; see
`src/recoverage/regen.py`. Serving a dashboard needs no project workspace
or compiler toolchain, only a valid `coverage.db` file.

## Project Structure

```
recoverage/
├── pyproject.toml          # Package config, entry point: recoverage
├── README.md               # User-facing docs
├── CHANGELOG.md            # Release history
├── CONTRIBUTING.md         # Bootstrap, edit-test loop, local/CI parity table
├── Makefile                # Contributor targets (`make help`); wraps the CI commands
├── LICENSE                  # MIT
├── NOTICE                   # Grants for the third-party browser assets bundled in the wheel
├── package.json            # bun scripts: lint, lint:js, lint:html
├── .yamllint.yaml          # yamllint config for .github/ (document-start, 100 cols)
├── oxlint.config.ts        # JS/TS lint config (see the tooling notes below)
├── .github/
│   ├── actions/sibling-rebrew/action.yml  # composite step: runs tools/ci_clone_rebrew.sh
│   └── workflows/ci.yml     # lint, web-lint, test matrix, smoke, sbom
├── docs/                   # Screenshots & design doc
│   ├── DESIGN.md           # Architecture and design decisions
│   ├── DESIGN_PRINCIPLES.md  # Core operational philosophies
│   ├── USER_STORIES.md     # User stories with acceptance criteria
│   ├── THREAT_MODEL.md     # Attack surface, trust boundaries, risk ranking
│   ├── ideas.md            # Future improvement ideas
│   └── *.png               # Screenshots for the README
├── tools/                  # lint-html.py, smoke.py, _serve_harness.py, oxlint/,
│                           # ci_clone_rebrew.sh, flatten-rikalabs-strict.py
├── tests/
│   ├── conftest.py           # Shared fixtures (synthetic coverage.db)
│   ├── test_api.py           # API validation, security, SQL injection tests
│   ├── test_cli.py           # CSV export, formatting, edge case tests
│   ├── test_lifecycle.py     # Lifecycle: regen ordering, browser-opener reaping
│   ├── test_paths.py         # DB path resolution tests
│   ├── test_config.py        # RECOVERAGE_* env: parsing, precedence, fail-fast
│   ├── test_server.py        # Compression, encoding, path helper tests
│   ├── test_serve_harness.py # Shared serve harness (builds the sample db, boots the server)
│   ├── test_potato.py        # Potato Mode unit tests
│   ├── test_perf.py          # Deterministic perf gates (work counters, not wall clock)
│   ├── test_metrics.py       # Request id, RED counters, slow-request log line
│   ├── test_release.py       # Release contract: version, changelog, declared floors
│   ├── test_supply_chain.py  # Pin contracts: rebrew tag/SHA, one clone mechanism, preset
│   │                         #   license, declared-vs-imported deps, npm lock pin + integrity,
│   │                         #   bundled-asset grants
│   ├── test_fuzz.py          # Seeded mutation campaigns over the untrusted-input surfaces
│   └── test_playwright.py    # Browser integration tests
└── src/recoverage/
    ├── __init__.py
    ├── __main__.py          # python -m recoverage
    ├── _paths.py            # DB path resolution (RECOVERAGE_DB, rebrew-project.toml db_dir)
    ├── config.py            # RECOVERAGE_* env: flag defaults, validation, startup banner
    ├── clock.py             # The one time source (monotonic / wall-clock) the request path reads
    ├── metrics.py           # In-process counters: RED requests (REQUESTS) + regen (REGEN), read by /api/health
    ├── cli.py               # Typer CLI entry point (serve, stats, export, check, regen, open)
    ├── server.py            # Bottle app, shared helpers & compression
    ├── disasm.py            # Capstone disassembly (optional extra): probe, thread-local Cs, memo
    ├── regen.py             # In-process rebrew regen (calls rebrew as a library)
    ├── api.py               # REST API routes (/api/*)
    ├── ui.py                # UI routes (/, static files)
    ├── potato.py            # Potato Mode renderer + the /potato route
    ├── webapp.py            # Composition root: imports api+ui+potato so app has every route
    └── assets/
        ├── index.html       # SPA shell
        ├── style.css        # All styles
        ├── print.css        # Print stylesheet
        ├── app.js           # VanJS frontend
        ├── detail.js        # Deferred panel logic (hex dump, metadata grid, modal, live reload)
        ├── van.min.js       # VanJS library
        ├── favicon.svg      # Retro "R" logo favicon
        ├── hljs.min.js / hljs-c.min.js / hljs-x86asm.min.js  # Highlight.js core + grammars
        └── hljs.css         # Highlight.js theme (custom hex language)
```

Frontend lint (bun + a JDK; see `bun run lint:js|html`): `oxlint.config.ts` is
the JS/TS config, `tools/lint-html.py` runs vnu over both the static assets and
the documents the server actually serves, and `tools/oxlint/anti-slop/` is a
vendored upstream copy to keep in sync. `tools/oxlint/rikalabs-strict.json` is
generated: never hand-edit it, bump `@rikalabs/oxlint-standards` then re-run
`tools/flatten-rikalabs-strict.py`. The script's docstring and
`oxlint.config.ts` own the why behind that preset.

## Commands

`make help` lists the contributor targets. Every one wraps the exact command
CI runs; `make all` is the local mirror of the whole pipeline.

```bash
# Bootstrap (clean clone; rebrew is a ../rebrew path dependency)
make clone-rebrew           # clone rebrew v2.13.1 into ../rebrew
make setup                  # uv sync --frozen --extra dev
uv sync --extra playwright   # browser tests: playwright, pytest-playwright

# Checks. Every recipe runs the tool as a module of the locked interpreter
# with the dev extra synced (`uv run --frozen --extra dev python -m <tool>`),
# never the bare name: without the extra, `uv run` installs the runtime
# packages only and `python -m pytest` dies with "No module named pytest",
# while a bare `uv run ruff` falls back to whatever is on PATH.
make test                   # uv run --frozen --extra dev python -m pytest tests/ -v --ignore=tests/test_playwright.py
make test-one T=tests/test_api.py  # one file or pytest node id (FLAGS="-k name" narrows it)
make fuzz                  # wider seeded campaign (SEED=, ITERATIONS= override)
make lint                   # uv run --frozen --extra dev python -m ruff check src/ tests/ tools/
make format-check           # uv run --frozen --extra dev python -m ruff format --check src/ tests/ tools/
make format                 # uv run --frozen --extra dev python -m ruff format (writes)
make shell-lint             # shellcheck -x tools/*.sh (needs shellcheck on PATH)
make yaml-lint              # yamllint -c .yamllint.yaml .github/ (needs yamllint on PATH)
make web-lint               # bun install --frozen-lockfile && bun run lint
make smoke                  # uv run --frozen --extra dev python tools/smoke.py
make smoke-fail             # same, against a deliberately corrupt db
make all                    # every check CI runs, one command

# Frontend lint detail (requires bun and java on PATH)
bun run lint                # oxlint (Rika-Labs strict preset + vendored anti-slop) + vnu HTML/CSS
bun run lint:js             # oxlint only
bun run lint:html           # vnu only: static assets + served pages (SPA shell, Potato Mode)

# Runtime (inside the synced env)
uv sync --extra dev --extra capstone
uv run recoverage serve             # start dashboard on :8001
uv run recoverage serve --port 9000 # custom port
uv run recoverage serve --regen     # re-run rebrew catalog + build-db first
uv run recoverage serve --no-open   # don't auto-open browser
uv run recoverage serve --cors      # enable CORS processing (allowlist origins with --cors-origin)
uv run recoverage config            # print the RECOVERAGE_* settings serve resolves, no listener
uv run recoverage regen             # re-run rebrew catalog + build-db, no server
uv run recoverage open              # open the dashboard in a browser
uv run recoverage --install-completion  # shell completion for the CLI
uv run recoverage stats             # print coverage stats
uv run recoverage export --format csv  # export coverage data
uv run recoverage check --min-coverage 60  # CI gate

# Browser tests
uv sync --extra playwright && uv run playwright install chromium
uv run python -m pytest tests/test_playwright.py
```

`tools/ci_clone_rebrew.sh` backs `make clone-rebrew` and the CI jobs: it pins
rebrew to the tag and commit in the script's defaults, and fails when the tag
does not resolve to that commit. It refuses to remove a destination checkout
that has uncommitted changes unless `REBREW_FORCE=1` is set. The tag and commit
are written in that script only: the Makefile carries no pin of its own (a
command-line `make clone-rebrew REBREW_REF=...` reaches the script through the
environment).

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and pull requests
against it, with a `concurrency` group that cancels superseded PR-branch runs
but never a `main` run, and a per-job `timeout-minutes` so a wedged server
test fails the job instead of holding a runner for six hours.

`rebrew` is an editable path dependency at `../rebrew` (see
`[tool.uv.sources]`), which no runner has, so every job that runs
`uv sync --frozen --extra dev` first uses the `sibling-rebrew` composite action
(`.github/actions/sibling-rebrew`), the one place a job may run
`tools/ci_clone_rebrew.sh "$GITHUB_WORKSPACE/../rebrew"`. It is the same script
`make clone-rebrew` wraps, and the only mechanism that fetches the sibling: a
second one (an inline `git clone`, or a job or action carrying its own ref)
would decide from an unchecked pin which rebrew the suite tested. The action
exists to hold that rule in one place, because every job needs the step and a
job body cannot name a sibling path, and it takes the clone URL as its only
input: a ref or sha input would be a second place to write the pin. The
script's `REBREW_REF`/`REBREW_SHA` defaults are the whole pin: the clone fails
unless the tag still resolves to the commit, so a moved tag cannot change the
dependency silently. Those defaults must keep matching `uv.lock` (checked by
`tests/test_supply_chain.py`, which also asserts that no job or the action
carries a pin of its own, and that no second local action appears): when
rebrew's dependencies change, re-lock in a tree with the sibling present and
bump the script alone. The `sbom` job
deliberately has no such step, because `uv export --frozen` reads the lock
alone.

The interpreter is pinned in `.python-version` (3.13), which is what uv builds
the local venv from and what the lint, web-lint and smoke jobs run: their
`setup-python` steps take `python-version-file: .python-version`, and `bun`
comes from `package.json`'s `packageManager` through `bun-version-file`. No
job restates either version; `tests/test_supply_chain.py` fails if a literal
comes back. The test matrix adds 3.14, and its `include` entries name 3.13
because make is not part of the Windows runner's toolchain, so that job spells
out the pytest command instead of calling `make test`.

## Releases

The release policy is not written down anywhere else, so it is stated here and
`tests/test_release.py` enforces it.

- `src/recoverage/__init__.py` `__version__` is the single source of truth;
  `pyproject.toml` reads it via `[tool.setuptools.dynamic]`. Bump it in the
  release commit, never before, and never in a feature commit.
- `CHANGELOG.md` follows Keep a Changelog. Every released version gets a
  `## [X.Y.Z] - YYYY-MM-DD` section above `[Unreleased]`, whose entries are
  grouped `Added` / `Breaking` / `Changed` / `Deprecated` / `Fixed` /
  `Removed` / `Security` and written for a user, not for a reviewer.
- An entry belongs under `[Unreleased]` until the commit that ships it is
  tagged. Back-filling a released section with a later fix misreports what the
  tag contains, which is the one thing the notes exist to say.
- A raised `requires-python` or dependency floor goes in the notes of the
  release that raises it, with the reason. A floor drop is a breaking change
  for whoever is still on the old one.
- SemVer on a 1.x line: a change to a public HTTP response field, a CLI flag,
  or a function another module imports is breaking and needs a major. A new
  section or endpoint is a minor. Anything else is a patch.
- The release commit is `chore: release X.Y.Z` and the tag is `vX.Y.Z`;
  both land together, and neither is re-cut.

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Main SPA dashboard |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, DB info, installed extras, request/regen/stream counters |
| `/api/targets` | GET | List available targets |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats (ETag-revalidating) |
| `/api/targets/<target>/data` | GET | Full section + cell data |
| `/api/targets/<target>/functions` | GET | Paginated function list |
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order (`application/json`, else 415) |
| `/api/targets/<target>/functions/<va>` | GET | Function/global detail |
| `/api/targets/<target>/asm` | GET | Disassembly (requires capstone) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice |
| `/api/events` | GET | Server-Sent Events: `db-updated` when coverage.db changes (SPA auto-refresh) |
| `/api/regen` | POST | Re-run catalog + build-db (localhost only, rate-limited; optional `Idempotency-Key` header, replayed from a bounded ledger) |

## Data Pipeline

1. `rebrew catalog` (or `--data-json`) → writes `db/data_*.json` in the project
   workspace; `--json` alone only prints a summary, and `recoverage --regen`
   runs the bare form for exactly this reason
   - Absorbs jump table / switch data bytes into parent function sizes
   - Links data and thunk cells to their parent function via `parent_function` field
   - `rebrew catalog --export-ghidra-labels` → generates `ghidra_data_labels.json` for round-trip Ghidra sync
2. `rebrew build-db` → reads JSON, builds `db/coverage.db` (SQLite)
   - Cells table includes `label` (Ghidra data label) and `parent_function` columns
   - Also materializes `section_cell_stats` (coverage buckets per section) and
     `section_cells_json` (per-section cell JSON, zstd), which the server reads
     in preference to re-deriving them. **Keep the live-SQL fallback on every
     read**: a database predating the cached object still has to serve, and the
     fallback is what makes that true. Producer and server share rebrew's
     `CELLS_JSON_OBJECT_SQL` and `SECTION_CELLS_AGG_SQL`, so cached and live
     rows cannot drift. Schema, bucket columns, and the reconciliation that
     makes `other_count` sum to `total_cells` are documented in `docs/DESIGN.md`
     (database schema section); `server._cell_bucket_row` always emits the
     `other` key, 0 when the source predates the column.
   - A cache that is present but covers only SOME of the target's sections is
     the third case, and the one a presence check misses: the reader fills the
     gap from `cells` rather than dropping the section
     (`server._cells_json_rows`'s `expected_sections`, `server._per_section_buckets`,
     `potato._compute_section_stats`). A dropped section reports no coverage at
     all, and a dropped cell payload paints a whole section as `none` bytes.
3. `recoverage` → serves the DB as a web dashboard
   - Cell detail panel shows parent function as a clickable navigation link

## Dependencies

Required (`[project].dependencies`, floors only; `uv.lock` pins the exact set):
- `bottle>=0.13` (web server)
- `brotli>=1.1` (Brotli compression)
- `rcssmin>=1.1` (CSS minification)
- `rebrew>=2.10.0` (sibling path dep pinned in `[tool.uv.sources]`): `rebrew.workspace` for shared `rebrew-project.toml` + coverage.db resolution, plus rebrew's catalog/build-db for in-process regen
- `rich>=15.0.0` (terminal tables)
- `rjsmin>=1.2` (JS minification)
- `typer>=0.27.2` (CLI framework)
- `zstandard>=0.22` (Zstandard compression)

Optional extras:
- `capstone>=5.0` (disassembly)
- `pygments>=2.21.0` (Potato Mode syntax highlighting)
- `playwright` (browser tests: `playwright>=1.62`, `pytest-playwright>=0.9.0`; `tests/test_playwright.py` is excluded from the default `addopts`)

Dev extra (`.[dev]`, what CI installs): `pytest>=9.1.1`, `ruff>=0.16.7`.

`rebrew` is a *runtime* import, not a regen-only one: `src/recoverage/_paths.py`
resolves every `coverage.db` lookup through `rebrew.workspace`, so the path source
in `[tool.uv.sources]` must resolve for `uv sync` to work at all. That source is
a relative `../rebrew`, which only holds in a sibling checkout. `make clone-rebrew`
(populated from `tools/ci_clone_rebrew.sh`, the same script every CI job runs
before `uv sync`) creates it. A git worktree sits elsewhere, so give it the
sibling path itself: symlink `../rebrew` to a rebrew checkout, or point
`[tool.uv.sources]` at one. `make setup REBREW_DIR=<path>` only moves the
Makefile's preflight check; uv still resolves the source in `pyproject.toml`.

## Code Style

- Python 3.13+, ruff for linting, 100-char line length. The selected rule
  groups, the bandit/pylint codes that are named individually instead of by
  prefix, the two ignores (PT006, PT018) and each per-file-ignore set all
  carry their reason next to them in `[tool.ruff.lint]` and
  `[tool.ruff.lint.per-file-ignores]` in pyproject.toml; those comments are
  the record of what the tree is expected to pass
- The bandit security group is on for src/ and tools/, including the S1xx
  wildcard-bind, hardcoded-secret, `/tmp` and urlopen checks; the suite's
  fixtures are the only reason `tests/*` ignores them, and each of those
  fixtures asserts the shape the rule exists to prevent. A new S1xx finding
  under src/ is a real one. S101 (assert), S603/S607 (untrusted argv,
  partial process path) and S608 (string-built SQL) stay off with their
  reason recorded in pyproject.toml
- Every request carries an id (`server._REQUEST_TLS`, echoed as
  `X-Request-ID`, stamped on every log record by `server._RequestIdFilter`),
  and every request is counted in `metrics.REQUESTS` under its route rule.
  A new failure path that answers 4xx/5xx from outside a handler (bottle
  turns an escaped exception into a 500 only *after* `after_request` has
  filed the request as a 200) must call `server._reclassify_request`, or the
  error rate silently reads zero; `test_metrics.py` pins that. The design
  rationale is in `docs/DESIGN.md` (*Request Observability*).
- The regen pipeline is counted in `metrics.REGEN`, not in `REQUESTS`: a regen
  runs for minutes, so the per-request numbers are one sample and none at all
  while it is in flight, and nothing in them says the in-flight request is a
  rebuild. Every `_do_regen` outcome closes the counters through
  `api._regen_failed` (or the success tail), so the elapsed time in the log
  line and the one in `/api/health`'s `regen` block are the same read. A POST
  refused by `_REGEN_LOCK` or the cooldown counts under `rejected`, never
  `failures`: the SPA throttles Reload clicks, so counting them as failures
  reports a broken pipeline for a double-clicked button.
- Saturation that answers 503 is a log line and a health field, not a bare
  status code: `/api/events` refuses past `_SSE_MAX_CLIENTS` and logs the count
  that caused it, and `/api/health` reports `streams` (clients, max, whether
  the watcher is alive). `watcher_alive` is `None` before the first client,
  since the poller starts lazily, and a connected client with a dead watcher
  answers `degraded` because every page still renders and none will refresh.
- Every time read under `src/recoverage/` goes through `clock`: `monotonic()`
  for elapsed-time arithmetic (cooldowns, retention windows, throttles,
  heartbeats) and `wall_time()` only for a stamp a human reads. A direct
  `time.monotonic()` in a request path is a window minutes wide that no test
  can drive and no run can replay; `tests/test_server.py` (`TestClockSeam`)
  drives the regen cooldown, the idempotency-key TTL, the failed-token
  throttle and the `db-updated` stamp from one patched clock, and
  `tests/test_metrics.py` drives the per-request duration window the same
  way, so the slow-request threshold is crossed on the clock rather than on
  a sleep.
- The memos derived from `rebrew-project.toml` all key on the file's stat
  (`server._config_stat_fingerprint`), one token for all of them:
  `_get_targets_config`, `resolve_targets` (keyed on that stat AND the
  WAL-aware DB snapshot, its other input), and the `DLL_DATA` byte cache.
  Editing the config is a write that reaches no server code and moves no DB
  file, so the stat is the only invalidation signal there is, and the rebuild
  broadcast watches `coverage.db` alone. A new config-derived memo names
  `_config_stat_fingerprint` in its key or it will disagree with the other two
  (`tests/test_server.py`, `TestConfigDerivedMemosFollowTheConfigStat`).
  DB-derived memos key on `_snapshot_db_mtime`, and the potato ones re-check
  the watermark before publishing, so a payload read through a pinned
  `read_snapshot` is never filed under a newer fingerprint.
- HTML/CSS/JS in `assets/` — no build step, VanJS for reactivity
- The cell-state vocabulary is owned by rebrew (`rebrew.build_db._KNOWN_CELL_STATES`)
  and must be covered on the rendering side: `potato.COLORS` + `LEGEND_ITEMS`,
  `app.js` `STATE_ID`, and `detail.js` `PALETTE_VARS`/`FILTER_KEY`. An unmapped
  state paints as an undocumented gap, which contradicts `/stats` — `verified`
  is counted there as an exact match. Tests in `test_potato.py`
  (`TestCellStateVocabularyCoverage`) and `test_server.py` (`TestSpaStateVocabulary`)
  fail on a gap; extend all of them together when rebrew adds a state.
- JS is linted with oxlint under the `@rikalabs/oxlint-standards` strict preset
  plus the vendored anti-slop rules; the webui is a classic-script SPA, so
  `app.js`/`detail.js` are wrapped in IIFEs and share state via `window.RC`.
  Rationale-bearing `oxlint-disable` comments are the sanctioned escape hatch
  for UI error boundaries and VanJS idioms (see `oxlint.config.ts`).
- Search compares names through `server.like_match`, never a hand-written
  `OR` chain: SQLite's `LIKE` folds case for ASCII only, so a term carrying a
  non-ASCII character needs `server.folded_like_clause` (NFC + casefold via the
  `rc_fold` function `_open_db` registers) ORed into the same group, and every
  column goes through `COALESCE(col, '')` because one NULL makes the predicate
  NULL and a row with no `symbol` then matches nothing. The SPA folds the same
  way in `app.js` (`foldForSearch`), except that it uses `toLowerCase` where
  the server uses `casefold`, so a case-fold expansion such as `ß` → `ss`
  matches through the API and not in the SPA. Name resolution folds the same
  way: `server._lookup_by_va_or_name` tries the indexed byte equality first
  and falls through to `rc_fold(name) = rc_fold(?)` on a miss, so the NFD
  spelling a user pastes opens the row the search matched. A lookup added
  beside it (globals, labels, anything compared for identity) must fold too;
  byte equality there is the bug this paragraph exists to stop.
- `_log_safe` escapes the characters that end a log line, which is C0, DEL,
  the C1 controls, and U+2028/U+2029 (a header value carries those literally,
  and every viewer that breaks on `\n` breaks on them). It deliberately leaves
  bidi controls alone: those reorder a line rather than split it, which is
  the log-injection question `sec-review` owns.
- The untrusted-input surfaces (query parameters, the batch POST body, request
  headers, the `/potato` query string, the `/src` and `/original` path
  segments, the access-gating headers, the `RECOVERAGE_*` readers) are fuzzed
  by `tests/test_fuzz.py`: a seeded mutation engine over a
  hand-written corpus, driven by `RECOVERAGE_FUZZ_SEED` / `RECOVERAGE_FUZZ_ITERATIONS`
  so a failure replays. Each round asserts an invariant, not just a lack of crash: no 5xx,
  the JSON error envelope on a 4xx, no traceback in a body, and the contract the
  query asked for (a page within `limit`, a slice within `size`, only requested
  VAs back). The `/potato` and repo-file campaigns pass their own grammar tokens
  to `_fuzz(struct_tokens=..., num_tokens=...)`, because byte mutation alone
  never produces `idx=99999999999999999999` or `%2e%2e%2f`; a new surface with
  its own grammar needs its token tuple the same way. HTML-escaping assertions
  come in pairs: the grid view escapes through SimpleTemplate, the functions
  view's empty-result message through `potato._esc`, and a regression in either
  one has to be visible from the response alone. The access-gating headers
  (`Origin`/`Host`, `REMOTE_ADDR`, `X-Request-ID`, `Idempotency-Key`) are the
  one class of surface where a wrong answer is a bypass rather than a bad
  render, so their campaigns assert the security property, not the status code:
  a normalized origin is a fixed point and carries no userinfo, escape, control
  byte or whitespace; a value that matches the CORS allowlist really is the
  allowlisted origin and is the only one echoed as
  `Access-Control-Allow-Origin`; `_peer_is_loopback` accepts `127.0.0.1` and
  `::1` and nothing else, judged against `ipaddress` rather than against the
  parser under test; the request id carries no control byte; an accepted
  idempotency key is inside the ledger's alphabet and length, and the ledger
  stays within `_REGEN_KEY_MAX` however many distinct keys arrive. The
  `RECOVERAGE_*` campaigns hold the module's own contract instead: every reader
  answers a value in its documented range or raises `ConfigError`, and never a
  third thing (a non-ASCII digit is a rejected port, not a bound one). No
  coverage-guided fuzzer is a
  project dependency, so the corpus lives in that file; a new surface gets a
  corpus entry there, not a new dependency.
