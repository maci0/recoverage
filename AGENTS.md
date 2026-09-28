# AGENTS.md — recoverage

## Overview

**recoverage** is a coverage dashboard for binary-matching decompilation projects.
It serves a Preact dashboard over rebrew's clear-text coverage TOML,
visualising per-byte match status across PE sections (`.text`, `.data`,
`.bss`). Two modes: a modern SPA (default) and a retro "Potato Mode" that
renders entirely in server-side HTML tables.

This package is a **consumer** of data produced by `rebrew`, which it depends
on as a library: `rebrew.workspace` provides the shared `rebrew-project.toml` + coverage
directory resolution (stdlib only), `rebrew.coverage_toml` reads the
`coverage-<target>.toml` documents, and the regen commands call rebrew's
`write_coverage_toml` in-process (which runs the catalog analysis itself); see
`src/recoverage/regen.py`. Serving a dashboard needs no project workspace or
compiler toolchain, only a readable coverage document.

## Project Structure

```
recoverage/
├── pyproject.toml          # Package config, entry point: recoverage
├── build-constraints.txt   # Exact pin for the PEP 517 backend (uv.lock does not cover it)
├── MANIFEST.in             # What the sdist carries: the backend pin, and not the test suite
├── man/recoverage.1       # Man page for the console script; installed by the wheel through
│                           #   [tool.setuptools.data-files] (share/man/man1)
├── README.md               # User-facing docs
├── CHANGELOG.md            # Release history
├── CONTRIBUTING.md         # Bootstrap, edit-test loop, local/CI parity table
├── Makefile                # Contributor targets (`make help`); wraps the CI commands
├── LICENSE                  # MIT
├── NOTICE                   # Grants for the third-party browser assets bundled in the wheel
├── package.json            # bun scripts: lint, build:web, dev:web, typecheck:web
├── web/                    # frontend sources: vite.config.ts + app/ (Preact + Tailwind)
├── .yamllint.yaml          # yamllint config for .github/ (document-start, 100 cols)
├── oxlint.config.ts        # JS/TS lint config (see the tooling notes below)
├── .github/
│   ├── actions/sibling-rebrew/action.yml  # composite step: runs tools/ci_clone_rebrew.sh
│   └── workflows/ci.yml     # lint, web-lint, test matrix, build, smoke, sbom
├── docs/                   # Screenshots & design doc
│   ├── DESIGN.md           # Architecture and design decisions
│   ├── DESIGN_PRINCIPLES.md  # Core operational philosophies
│   ├── USER_STORIES.md     # User stories with acceptance criteria
│   ├── THREAT_MODEL.md     # Attack surface, trust boundaries, risk ranking
│   ├── ideas.md            # Future improvement ideas
│   └── *.png               # Screenshots for the README
├── tools/                  # lint_html.py, smoke.py, payload_budget.py,
│                           # _serve_harness.py, oxlint/, ci_clone_rebrew.sh,
│                           # flatten_rikalabs_strict.py, normalize_sdist.py,
│                           # vendor_manifest.py
├── tests/
│   ├── conftest.py           # Shared fixtures (synthetic coverage TOML)
│   ├── coverage_fixture.py   # Builders for synthetic coverage documents
│   ├── test_build.py          # Artifact build: shipped files, the man page, reproducible bytes
│   ├── test_api.py           # API validation, security, SQL injection tests
│   ├── test_cli.py           # CSV export, formatting, edge case tests
│   ├── test_lifecycle.py     # Lifecycle: regen ordering, browser-opener reaping
│   ├── test_paths.py         # Coverage directory resolution tests
│   ├── test_config.py        # RECOVERAGE_* env: parsing, precedence, fail-fast
│   ├── test_server.py        # Compression, encoding, snapshot, path helper tests
│   ├── test_serve_harness.py # Shared serve harness (builds the sample coverage, boots the server)
│   ├── test_potato.py        # Potato Mode unit tests
│   ├── test_perf.py          # Deterministic perf gates (work counters, not wall clock)
│   ├── test_metrics.py       # Request id, RED counters, slow-request log line
│   ├── test_release.py       # Release contract: version, changelog, declared floors
│   ├── test_supply_chain.py  # Pin contracts: rebrew tag/SHA, one clone mechanism, preset
│   │                         #   license, declared-vs-imported deps, npm lock pin + integrity,
│   │                         #   bundled-asset grants
│   ├── test_fuzz.py          # Seeded mutation campaigns over the untrusted-input surfaces
│   ├── test_concurrency.py   # Barrier-driven races: /data single flight, cache invalidation
│   │                         #   under load, counter balance, the admission cap, the auth window
│   ├── test_import_graph.py  # In-package import graph: level order + acyclicity
│   └── test_playwright.py    # Browser integration tests
└── src/recoverage/
    ├── __init__.py
    ├── __main__.py          # python -m recoverage
    ├── _paths.py            # Coverage directory resolution (RECOVERAGE_DB, db_dir)
    ├── config.py            # RECOVERAGE_* env: flag defaults, validation, startup banner
    ├── devserver.py         # WSGI serving stack serve() binds: threading server, keep-alive handlers,
    │                        #   admission cap + socket deadline (RECOVERAGE_MAX_CONNECTIONS/CLIENT_TIMEOUT)
    ├── clock.py             # The one time source (monotonic / wall-clock) the request path reads
    ├── metrics.py           # In-process counters: RED requests (REQUESTS) + regen (REGEN), read by /api/health
    ├── cli.py               # Typer CLI entry point (serve, stats, export, check, regen, open)
    ├── server.py            # Bottle app, shared helpers & compression
    ├── disasm.py            # Capstone disassembly (optional extra): loadability probe,
    │                        #   thread-local Cs, memo
    ├── regen.py             # In-process rebrew regen (calls rebrew as a library)
    ├── api.py               # REST API routes (/api/*)
    ├── ui.py                # UI routes (/, static files)
    ├── potato.py            # Potato Mode renderer + the /potato route
    ├── webapp.py            # Composition root: imports api+ui+potato so app has every route
    └── assets/
        ├── index.html       # SPA shell
        ├── style.css        # built Tailwind output — generated, never hand-edited
        ├── print.css        # Print stylesheet
        ├── app.js           # built bundle — generated, never hand-edited
        └── favicon.svg      # Retro "R" logo favicon
```

Frontend lint (bun + a JDK; see `bun run lint:js|html`): `oxlint.config.ts` is
the JS/TS config, `tools/lint_html.py` runs vnu over both the static assets and
the documents the server actually serves, and `tools/oxlint/anti-slop/` is a
vendored upstream copy to keep in sync. `tools/oxlint/rikalabs-strict.json` is
generated: never hand-edit it, bump `@rikalabs/oxlint-standards` then run
`make regen-oxlint` (which wraps `tools/flatten_rikalabs_strict.py` and the
`bun install` it reads `node_modules` from). The script's docstring and
`oxlint.config.ts` own the why behind that preset. The vendored plugin is
inventoried the same way, because no registry manifest reaches a directory
copied into the repo: `tools/vendor_manifest.py` writes
`tools/oxlint/anti-slop.manifest.json` (upstream, license, every file with its
sha256, the excluded paths), and `tests/test_supply_chain.py` fails when the
tree and that record disagree. Re-vendor by replacing the directory, running
the script, then `bun run lint:js`.

## Commands

`make help` lists the contributor targets. Every one wraps the exact command
CI runs; `make all` is the local mirror of the whole pipeline.

```bash
# Bootstrap (clean clone; rebrew is a ../rebrew path dependency)
make clone-rebrew           # clone the pinned rebrew into ../rebrew (pin: tools/ci_clone_rebrew.sh)
make setup                  # uv sync --locked --extra dev
make build                  # wheel + sdist into dist/, reproducibly
uv sync --extra playwright   # browser tests: playwright, pytest-playwright

# Checks. Every recipe runs the tool as a module of the locked interpreter
# with the dev extra synced (`uv run --locked --extra dev python -m <tool>`),
# never the bare name: without the extra, `uv run` installs the runtime
# packages only and `python -m pytest` dies with "No module named pytest",
# while a bare `uv run ruff` falls back to whatever is on PATH. `--locked`,
# not `--frozen`: both refuse to rewrite uv.lock, but `--frozen` installs the
# committed lock even when pyproject.toml no longer matches it, so a dependency
# edit that skipped `uv lock` would test a tree the manifest does not
# describe. `tests/test_supply_chain.py` pins the flag in the Makefile and in
# every ci.yml job, and `uv export --frozen` is the one exception: the `sbom`
# job has no sibling ../rebrew to resolve the path dependency against.
make test                   # uv run --locked --extra dev python -m pytest tests/ -v --ignore=tests/test_playwright.py
make test-one T=tests/test_api.py  # one file or pytest node id (FLAGS="-k name" narrows it)
make fuzz                  # wider seeded campaign (SEED=, ITERATIONS= override)
make lint                   # uv run --locked --extra dev python -m ruff check src/ tests/ tools/
make type-check             # uv run --locked --extra dev python -m mypy (src/ + tools/, strict)
make format-check           # uv run --locked --extra dev python -m ruff format --check src/ tests/ tools/
make format                 # uv run --locked --extra dev python -m ruff format (writes)
make shell-lint             # shellcheck -x tools/*.sh (needs shellcheck on PATH)
make yaml-lint              # yamllint -c .yamllint.yaml .github/ (needs yamllint on PATH)
make web-build              # bun install --frozen-lockfile && bun run build:web (the dashboard bundle)
make web-lint               # bun install --frozen-lockfile && bun run lint
make typecheck-web          # bun install --frozen-lockfile && bun run typecheck:web (tsc --noEmit)
make smoke                  # uv run --locked --extra dev python tools/smoke.py
make payload-budget         # the inlined shell's size at each static encoding, which the
                            #   payload budget in docs/DESIGN.md quotes
make smoke-fail             # same, against a deliberately corrupt db
make all                    # every check CI runs, one command

# Frontend lint detail (requires bun and java on PATH)
bun run lint                # oxlint (Rika-Labs strict preset + vendored anti-slop) + vnu HTML/CSS
bun run lint:js             # oxlint only
bun run lint:html           # vnu only: static assets + served pages (SPA shell, Potato Mode)
bun run typecheck:web       # tsc --noEmit over web/tsconfig.json (strict)

# Runtime (inside the synced env)
uv sync --extra dev --extra capstone
uv run recoverage                     # same as `serve` (main() appends the subcommand to a bare argv)
uv run recoverage serve             # start dashboard on :8001
uv run recoverage serve --port 9000 # custom port
uv run recoverage serve --regen     # re-run rebrew's catalog analysis first
uv run recoverage serve --no-open   # don't auto-open browser
uv run recoverage serve --cors      # enable CORS processing (allowlist origins with --cors-origin)
uv run recoverage config            # print the RECOVERAGE_* settings serve resolves, no listener (same gate as serve)
uv run recoverage regen             # re-run rebrew's catalog analysis + build-db, no server
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
`uv sync --locked --extra dev` first uses the `sibling-rebrew` composite action
(`.github/actions/sibling-rebrew`), the one place a job may run
`tools/ci_clone_rebrew.sh "$GITHUB_WORKSPACE/../rebrew"`. It is the same script
`make clone-rebrew` wraps, and the only mechanism that fetches the sibling: a
second one (an inline `git clone`, or a job or action carrying its own ref)
would decide from an unchecked pin which rebrew the suite tested. The action
exists to hold that rule in one place, because every job needs the step and a
job body cannot name a sibling path, and it takes the clone URL as its only
input: a ref or sha input would be a second place to write the pin. That
input's default is empty, because the URL is a copy of a value the script
already owns and a moved repository would leave the two disagreeing; the
script's `REBREW_URL` default supplies it. The
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

Every third-party action is a 40-hex commit with a trailing `# vX.Y.Z` naming
the tag it came from, and `tests/test_supply_chain.py`
(`TestActionsArePinned`) fails a mutable `@v7` or a bare SHA: a tag is a moving
target, so two runs of one commit could execute different code. Dependabot
rewrites the ref and leaves the comment, so it is what makes a bump reviewable.
The same class requires `persist-credentials: false` on every
`actions/checkout`, because checkout otherwise leaves the job's token in
`.git/config` and every step in these workflows runs project code, and no job
pushes.

A Linux job names its runner image (`ubuntu-24.04`), never `ubuntu-latest`, and
`tests/test_supply_chain.py` (`TestToolchainPins`) fails the moving label. Every
other input the pipeline reads is pinned in the tree, so the image is the last
one left to the host, and it is where the tools the tree declares no version for
come from: `shellcheck` and `yamllint`, which gate `tools/*.sh` and `.github/`
in the `lint` job, and `diffoscope`, which the `build` job calls when two
builds disagree. A fleet update that added or dropped a rule, or removed a tool,
would change what `make lint` accepts with no commit to review. The macOS and
Windows matrix entries keep floating labels: they exercise the cross-platform
claim and run no pinned tool out of the image.

## Releases

The release policy is not written down anywhere else, so it is stated here and
`tests/test_release.py` enforces it.

- `src/recoverage/__init__.py` `__version__` is the single source of truth;
  `pyproject.toml` reads it via `[tool.setuptools.dynamic]`. Bump it in the
  release commit, never before, and never in a feature commit. The man page's
  `.TH` header is the one place that repeats it, because `man(1)` prints it and
  no build step rewrites it: the release commit bumps both, and
  `tests/test_release.py` (`TestShippedArtifactsNameTheVersion`) fails when
  they disagree.
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
  section or endpoint is a minor. Anything else is a patch. The `### Breaking`
  group is the marker a major is gated on, and
  `tests/test_release.py::TestBreakingEntriesMatchTheVersionBump` fails when a
  shipped section carries that group without the bump (a self-test in the same
  class drives the gate from a synthetic minor, so a guard that cannot fail is
  not one). It reads the changelog, so it cannot see a breaking change filed
  under another group: 1.5.0 dropped the `id` key from the served cell objects
  under `Changed`, and the entry there says so now. Nothing in the Unreleased
  section is release bookkeeping; it is published verbatim under the version,
  so a "tag this as 2.0.0" note would ship to the reader.
- The release commit is `chore: release X.Y.Z` and the tag is `vX.Y.Z`;
  both land together, and neither is re-cut.
- `rebrew` is a hard runtime dependency and is not on the package index, so
  recoverage must not be published first: the wheel would fail to resolve for
  every installer, and it would leave the `rebrew` name unclaimed on the index,
  where the next upload of that name installs into anyone resolving the wheel
  as a dependency. Publish rebrew, confirm it resolves, then release.

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Main SPA dashboard (the bundle inlined) |
| `/index.html` | GET | Same document, for a URL that names it |
| `/src/<filepath:path>` | GET | A file under the target's `src/` tree, for the code panes |
| `/original/<filepath:path>` | GET | A file under the original binary's tree (`web/app/hooks/useOriginalBinary.ts` reads it) |
| `/<filename:app.js, style.css, print.css, favicon.svg>` | GET | The packaged static assets, `no-cache` with a strong `ETag` |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, the settings the process resolved, DB info, installed extras, request/regen/stream counters |
| `/api/targets` | GET | List available targets |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats (ETag-revalidating) |
| `/api/targets/<target>/data` | GET | Full section + cell data. `?section=` narrows the cells (siblings omit the key); `?index=0` omits `search_index`, which the SPA holds already, so a section switch does not re-send it (`index` is a flag: `0`, `1` or absent, anything else a 400) |
| `/api/targets/<target>/functions` | GET | Paginated function list (`?status=` takes rebrew's status vocabulary; anything else is a 400) |
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order (`application/json`, else 415) |
| `/api/targets/<target>/functions/<va>` | GET | Function/global detail |
| `/api/targets/<target>/asm` | GET | Disassembly (requires capstone) |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice |
| `/api/events` | GET | Server-Sent Events: `db-updated` when the coverage documents change (SPA auto-refresh) |
| `/api/regen` | POST | Re-run catalog + build-db (localhost only, rate-limited; optional `Idempotency-Key` header, replayed from a bounded ledger) |

Search folds both sides the same way in Python: `server.fold_text` is NFC
composition plus `str.casefold`, and `server.fold_match` is the substring test
both the API list, the Potato list and the name lookup run every column
through. The SPA folds in JS (the `matchedNames` memo in `web/app/App.tsx`)
with `toLowerCase` where the server uses `casefold`, so a case-fold expansion
such as `ß` → `ss` matches through the API and not in the SPA. This was a SQL split
(LIKE folded ASCII, an `rc_fold` disjunct covered the rest) only because the
comparison happened inside SQLite; one folding over the in-memory rows is both
simpler and strictly wider.

## Data Pipeline

1. `rebrew build-db` → writes `db/coverage-<target>.toml` (via
   `rebrew.coverage_toml.write_coverage_toml`). It runs the catalog analysis
   in-process per target (`rebrew.catalog.pipeline.build_catalog_data`), so
   there is no snapshot file between the analysis and the document and a
   document cannot describe an older tree than the one that produced it.
   `recoverage --regen` and `POST /api/regen` call the same function; there is
   no separate `rebrew catalog` step to run first.
   - Absorbs jump table / switch data bytes into parent function sizes
   - Links data and thunk cells to their parent function via `parent_function` field
   - `rebrew catalog --export-ghidra-labels` → generates `ghidra_data_labels.json` for round-trip Ghidra sync
   - The document stores FACTS only: the sections with their cells, the
     functions, the globals, the verify results and the history. Every aggregate
     the SQLite schema used to materialize (`section_cell_stats`,
     `section_cells_json`, the per-section buckets, the byte coverage) is
     derived by `rebrew.coverage_toml` at load, in `Section.__post_init__` and
     `_derive_function_stats`. **Do not port a reader of a stored aggregate**:
     there is none to read, and a second computation of the same number is
     exactly the drift the format exists to remove.
   - `server._bucket_row` is the ONE mapping from a section's cells to the
     served bucket dict (`total_cells`, the state counts, and `other`, the
     producer's catch-all, always emitted so the buckets reconcile with
     `total_cells`). `/stats`, `/data` and the Potato map header all read it.
   - `server.coverage_pct(covered, total)` is the ONE percentage a covered-byte
     ratio is rendered through: `summary.coveragePercent`, the per-section
     `coverage_pct` and `potato._section_pct` all take it, and it FLOORS to 2dp
     through rebrew's `floor_pct`, because these figures must not round up
     (999,997 of 1,000,000 bytes is not 100%). The `check` gate compares the
     UNROUNDED ratio and quotes this one, so a FAIL line cannot read
     "coverage 100.00% < 100.00%". A new percentage over the same counts calls
     the helper rather than `round`. The surfaces that print one decimal (the
     `stats` table, the Markdown export, Potato's map header) go through
     `server.pct_1dp`, which floors the 2dp figure again: `"%.1f" % 99.99` is
     `"100.0"`, so formatting it directly undid the flooring the helper exists
     for. The SPA's stats strip
     (`web/app/components/StatsStrip.tsx`) renders the SERVED figures
     (`summary.coveragePercent`, a section's `coverage_pct`) and never divides
     its own counts, so a fourth rendering cannot round its way to a different
     number beside the same map; its per-state counts are the `STATE_FILTERS`
     table in `web/app/grid/pack.ts`, which the toolbar's pills are built from,
     and each one is a filter toggle rather than a second vocabulary.
   - The catalog's `summary` blob is NOT stored in the document (the writer
     keeps the facts, not the precomputed answers). `server._summary` rebuilds
     it from the stored cells and functions, and `/stats` and `/data` serve the
     rebuild; a change there is a change to a served payload.
   - A target the project config declares but no build has written is served
     from an EMPTY snapshot (`server.coverage_for`), which is what the SQLite
     reader got from an empty table set. A document that exists but does not
     parse is the opposite case and must stay distinguishable: it raises
     `CoverageTomlError`, which is the 503 `db_unavailable` contract — never a
     target that silently reads as having no sections
     (`tests/test_server.py`, `TestUnreadableDocumentIsNotAnEmptyTarget`).
2. `recoverage` → serves the coverage as a web dashboard
   - Cell detail panel shows parent function as a clickable navigation link

## Dependencies

Required (`[project].dependencies`, floors only; `uv.lock` pins the exact set):
- `bottle>=0.13` (web server)
- `brotli>=1.1` (Brotli compression)
- `rcssmin>=1.1` (CSS minification)
- `rebrew>=2.16.0` (sibling path dep pinned in `[tool.uv.sources]`; the first
  release that ships `rebrew.coverage_toml`): `rebrew.workspace` for shared `rebrew-project.toml` + coverage-directory resolution, `rebrew.coverage_toml` for reading and writing the documents, plus rebrew's catalog for in-process regen
- `rich>=15.0.0` (terminal tables)
- `rjsmin>=1.2` (JS minification)
- `typer>=0.27.2` (CLI framework)
- `zstandard>=0.22` (Zstandard compression)

Optional extras:
- `capstone>=5.0` (disassembly)
- `pygments>=2.21.0` (Potato Mode syntax highlighting)
- `playwright` (browser tests: `playwright>=1.62`, `pytest-playwright>=0.9.0`; `tests/test_playwright.py` is excluded from the default `addopts`)

Dev extra (`.[dev]`, what CI installs): `mypy>=1.14`, `pytest>=9.1.1`, `ruff>=0.16.7`.

`rebrew` is a *runtime* import, not a regen-only one: `src/recoverage/_paths.py`
resolves every coverage-directory lookup through `rebrew.workspace`, so the path source
in `[tool.uv.sources]` must resolve for `uv sync` to work at all. That source is
a relative `../rebrew`, which only holds in a sibling checkout. `make clone-rebrew`
(populated from `tools/ci_clone_rebrew.sh`, the same script every CI job runs
before `uv sync`) creates it. A git worktree sits elsewhere, so give it the
sibling path itself: symlink `../rebrew` to a rebrew checkout, or point
`[tool.uv.sources]` at one. `make setup REBREW_DIR=<path>` only moves the
Makefile's preflight check; uv still resolves the source in `pyproject.toml`.

## Code Style

- `make build` is the one command that produces the distribution, and it is
  reproducible: `SOURCE_DATE_EPOCH` (the commit's own date, `FALLBACK_SOURCE_DATE_EPOCH`
  when there is no git) plus `LC_ALL=C` and `TZ=UTC` around `uv build`, then
  `tools/normalize_sdist.py`. setuptools stamps the *wheel* from
  `SOURCE_DATE_EPOCH` but not the *sdist*, which keeps the working tree's
  mtimes, the building user, the archive order and the gzip header's wall
  clock; the normalizer pins those four so two builds of one commit hash the
  same. Build it through the target, not a bare `uv build`, and
  `tests/test_build.py` (`TestReproducibleBuild`) fails when the recipe stops
  exporting the stamp, when the default is the clock instead of the commit, or
  when a rebuild's bytes move.

  The recipe also passes `--build-constraints build-constraints.txt` and
  `--clear`. The first because `uv.lock` does not describe the PEP 517 build
  environment: uv resolves `build-system.requires` in an isolated env of its
  own, so `setuptools>=84.0.0` is a floor and the artifact bytes would follow
  whatever the index served that day. `build-constraints.txt` is that file, one
  exact `==` per backend, and `tests/test_build.py` fails when a pin stops
  being exact or drops below the floor in `pyproject.toml`. `MANIFEST.in` puts
  that file in the sdist, because an archive that does not carry the pin is
  rebuilt against the index rather than the version its bytes were verified
  under, and it prunes `tests/`, because distutils otherwise ships
  `test_*.py` without `conftest.py` and `coverage_fixture.py`: a suite that
  fails on collection, in a published artifact. The second because
  `uv build` writes into `dist/` without clearing it: a wheel left by the
  previous version sits beside the new one and both get published. `make build`
  also depends on `ensure-rebrew`, because its last step is a `uv run` that
  syncs the environment, and that environment cannot resolve the rebrew path
  dependency without the sibling checkout.

  The `build` job in `.github/workflows/ci.yml` is the only CI job that
  produces the artifact, and it is what makes reproducibility tested rather
  than asserted: it builds twice, the second time from a copy of the tracked
  tree under a different path with `LC_ALL=C.UTF-8` and `TZ=Asia/Tokyo`, and
  fails when the two archives differ, printing both hashes and adding
  `diffoscope`'s breakdown when the runner image carries it (it does not, so
  the hashes are what a reader gets).
  The copy gets `../rebrew` as a symlink for the same reason the preflight
  exists, and `SOURCE_DATE_EPOCH` is pinned to a constant in that job so the
  two builds cannot disagree over anything but the tree. The step removes
  every destination under `RUNNER_TEMP` before it extracts or links into it:
  both merge into what they find, and that directory outlives one execution of
  the step on a self-hosted runner or a retry, so the second build would
  otherwise package a file the tracked tree no longer has and the comparison
  would report a difference that is not one.

- Python 3.13+, ruff for linting, mypy for types, 100-char line length.
  The type gate is `strict = true` over `src/recoverage` and `tools/`, with
  three checks off and the reason next to them in `[tool.mypy]`:
  `disallow_untyped_decorators` (every route handler wears a `@app.route`,
  and bottle is untyped, so the decorator erases the signature),
  `warn_return_any` (the JSON builders read snapshot fields whose shape is
  pinned by rebrew's reader, not by the checker), and
  `no_implicit_reexport` (api.py, ui.py and potato.py import the shared
  `request`/`response`/`HTTPResponse` from `recoverage.server` on purpose).
  `warn_unused_ignores` is ON, which makes every `type: ignore` in
  `src/recoverage` and `tools/` a checked claim: one whose error is gone
  fails `make type-check` instead of outliving the finding it silences. The
  runtime deps ship no `py.typed`, so they are covered tree-wide by
  `ignore_missing_imports` rather than by a per-import
  `# type: ignore[import-untyped]`, which would be redundant under that
  setting and reported as stale. `tests/` is outside the gate until
  its fixtures carry annotations; a suppression added there belongs with
  the first mypy run that covers it, and the existing
  `# type: ignore[...]` comments there are still the record of what needed
  silencing. The selected rule
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
  error rate silently reads zero; `test_metrics.py` pins that. Those counters
  are shared state every request thread mutates, so their balance under
  concurrent requests is pinned separately at `tests/test_concurrency.py`
  (`TestRequestCounters`): a lost update shows up as a total that disagrees
  with the sum of its own buckets, or an `in_flight` that never returns. The
  design rationale is in `docs/DESIGN.md` (*Request Observability*).
- The regen pipeline is counted in `metrics.REGEN`, not in `REQUESTS`: a regen
  runs for minutes, so the per-request numbers are one sample and none at all
  while it is in flight, and nothing in them says the in-flight request is a
  rebuild. Every `_do_regen` outcome closes the counters through
  `api._regen_failed` (or the success tail), so the elapsed time in the log
  line and the one in `/api/health`'s `regen` block are the same read. A
  `BaseException` out of the pipeline (Ctrl+C at the terminal running
  `serve`) is the arm that needs one of its own: it is not a response this
  handler builds, but `in_flight` is a gauge, so letting it through without
  closing strands the reading at 1 for the rest of the process
  (`test_api.py::TestRegenMetrics`). A POST
  refused by `_REGEN_LOCK` or the cooldown counts under `rejected`, never
  `failures`: the SPA throttles Reload clicks, so counting them as failures
  reports a broken pipeline for a double-clicked button.
- The active configuration is rendered ONCE, by `config.active_config`, and the
  result reaches the startup banner and `GET /api/health`'s `config` block
  (`server.configure_startup`, called from `serve` before the listener binds).
  `recoverage config` re-resolves the environment of the shell that runs it,
  which under a unit file or a container spec is not the server's environment:
  same flags, different answer. The health block is the reading that cannot
  drift, and it is `null` in a process that never ran `serve` rather than a
  default nobody set. It drops `db`, because health names the coverage
  directory by basename only and a second, absolute spelling of it here would
  undo that. A new setting `serve` resolves joins the same rendering; a second
  place that formats a setting is a second answer to "what is it running with".
  The port reaching that rendering is the one the listener will hold:
  `devserver.resolve_listen_port` turns the documented `--port 0` ("bind a
  free port") into a concrete number before either surface renders, because
  every reader of it (the banner, health, the URL `open_browser` is handed) is
  printed rather than fed back into `bind()`. `recoverage config` deliberately
  does NOT resolve it: it reports the configured value, and the free port a
  later `serve` picks is a different one. `open` refuses port 0 for the same
  reason, with a message naming the banner that holds the real number.
- The network-bind acknowledgment and the CORS warnings are ONE rule, in
  `cli._remote_bind_gate` and `cli._cors_warnings`, and both `serve` and
  `recoverage config` run it. `config` is the preflight a deployment gates on:
  a check that exits 0 for a configuration `serve` exits 1 on is a deployment
  that finds out at boot instead of at the check.
- Saturation that answers 503 is a log line and a health field, not a bare
  status code: `/api/events` refuses past `_SSE_MAX_CLIENTS` and logs the count
  that caused it, and `/api/health` reports `streams` (clients, max, whether
  the watcher is alive). `watcher_alive` is `None` before the first client,
  since the poller starts lazily, and a connected client with a dead watcher
  answers `degraded` because every page still renders and none will refresh.
  The same rule governs the wider connection cap
  (`devserver._MAX_CONNECTIONS`): its gauge is `metrics.CONNECTIONS`, which
  the admission path itself updates, so `/api/health`'s `connections` (open,
  max, refused) and the accept decision cannot be two numbers that disagree. A
  refusal answers `degraded` with the count, because a server at that cap keeps
  serving the connections it already has and refuses every new one. `max` is 0
  until the first admission, so a mounted WSGI app that never reached `serve`
  reports no cap rather than one it is not enforcing. The admission check and
  the increment are one critical section for the same reason the auth window's
  prune, cap check and reservation are (`server._auth_throttle`): read apart,
  every accepting thread sees room and the cap admits more than it is
  configured to hold. Both are pinned at `tests/test_concurrency.py`
  (`TestAdmissionCap`, `TestAuthThrottle`), which drive them from threads
  released by one barrier.
- `/api/health` is polled, so it logs a TRANSITION, not a state: the endpoint
  runs every check through `api._log_health_status`, which warns on the first
  probe in a state, infos on the first probe after it, and says nothing on a
  repeat. A per-probe warning is what teaches an operator to skip the line, and
  a monitor pointed at a broken database emitted one every poll. Each check
  appends its own reason to a list and the log names all of them in one line,
  so a second fault is visible in the same entry rather than the first one
  winning. A new degradation reason joins that list; it does not log on its
  own. The same rule governs the poller: `api._db_watcher_loop` guards the
  WHOLE loop including the baseline snapshot, because a guard around the poll
  alone lets a failure in the first snapshot kill a daemon thread nobody joins
  with no line saying so, and a dead poller reads `healthy` while no SSE client
  is connected.
- Every time read under `src/recoverage/` goes through `clock`: `monotonic()`
  for elapsed-time arithmetic (cooldowns, retention windows, throttles,
  heartbeats) and `wall_time()` only for a stamp a human reads. A direct
  `time.monotonic()` in a request path is a window minutes wide that no test
  can drive and no run can replay; `tests/test_server.py` (`TestClockSeam`)
  drives the regen cooldown, the idempotency-key TTL, the failed-token
  throttle and the `db-updated` stamp from one patched clock, and
  `tests/test_metrics.py` drives the per-request duration window the same
  way, so the slow-request threshold is crossed on the clock rather than on
  a sleep. A `st_mtime_ns` becomes an instant through
  `server.mtime_ns_to_utc`, never `fromtimestamp(ns / 1e9)`: a float second
  cannot hold a nanosecond, so that conversion rounds and reports a rebuild
  up to half a second (and Potato's footer a whole minute) before it
  happened. Both freshness surfaces render through the one helper, and
  `tests/test_api.py` (`TestHealthDbMtime`) plus `tests/test_potato.py`
  (`TestDbUpdatedLabel`) pin the truncation. An instant published to a client
  is UTC with the offset spelled out, never a fixed offset or a zone guessed
  from the locale; a log stamp is local time with `%z` attached, because the
  operator comparing it against their own clock needs to see their own clock.
- The memos derived from `rebrew-project.toml` all key on the file's stat
  (`server._config_stat_fingerprint`), one token for all of them:
  `_get_targets_config`, `resolve_targets` (keyed on that stat AND the
  coverage-directory snapshot, its other input), and the `DLL_DATA` byte cache.
  Editing the config is a write that reaches no server code and moves no
  coverage file, so the stat is the only invalidation signal there is, and the
  rebuild broadcast watches the documents alone. A new config-derived memo names
  `_config_stat_fingerprint` in its key or it will disagree with the other two
  (`tests/test_server.py`, `TestConfigDerivedMemosFollowTheConfigStat`).
  Coverage-derived memos key on `server._snapshot_db_mtime`, and the potato ones
  re-check the watermark before publishing, so a payload read from one snapshot
  is never filed under a newer fingerprint. That token is stat'ed BEFORE the
  snapshot is loaded (`render_potato` takes it before `coverage_for`, and hands
  it to `_load_grid_cells` / `_section_stats_cached`), because a stat taken
  after the read reads the post-rebuild value on both sides of the publish
  comparison and matches, filing the previous build's rows under the fingerprint
  that supersedes them. `api.handle_api_data`, `api.handle_api_stats` and
  `api.handle_api_functions_list` stat before their snapshot load for the same
  reason, and `_function_total` re-checks the watermark before publishing, the
  one place a memo of a pure in-memory count needs it (its rows are already a
  frozen snapshot, so nothing but the key can straddle a rebuild); a new
  coverage-derived memo takes its token the same way or states why its read
  cannot straddle a rebuild.
- A path that crosses into the filesystem is read with `PurePath` rules, not
  POSIX string rules. `potato._is_plain_relative` is the one definition, keyed
  on `anchor` (drive, leading separator, UNC) rather than `is_absolute()`, and
  it names the SOURCE ROOT as well as the file under it: the root is the
  containment base, so a value that survives as an anchor or a parent hop
  replaces the base outright and the `is_relative_to` check that follows passes
  trivially. Stripping a leading `/` is a POSIX assumption and answers for the
  host, not for the document: a coverage document built on Windows used to name
  a source root no Linux reader could refuse, and the lowercased `src/<target>`
  fallback (`potato`, `web/app/App.tsx`, `web/app/hooks/useOriginalBinary.ts`)
  only resolved on a case-insensitive filesystem. Target ids are used verbatim
  in every path this package builds, because rebrew names the tree
  `src/<target>` and `db/coverage-<target>.toml` with the target's own spelling.
  Pinned at `tests/test_potato.py` (`TestPathTraversalGuard`); a new path taken
  from a coverage document goes through the same guard.
- One response, one snapshot. A snapshot is frozen — every collection is a
  tuple or a `MappingProxyType` — and `server.load_all_coverage` memoizes on the
  documents' own stat, so an unchanged directory returns THE SAME snapshot
  objects. A handler that builds its answer from several collections therefore
  reads them all from one snapshot and cannot pair one build's cells with the
  next build's functions; that is the guarantee the SQLite read transaction
  used to buy, held by the type instead. The call sites are
  `api._target_snapshot` (`/stats`, `/data`, the function list, both lookup
  routes, `/asm`, `/bytes`), `cli._open_targets` (`recoverage stats`/`export`/
  `check`) and the whole `potato.render_potato` render, the widest window in the
  package. A new multi-collection reader either takes a snapshot or explains why
  its reads cannot straddle a rebuild. Pinned at `tests/test_api.py` (the lookup
  pin classes) and `tests/test_potato.py`
  (`TestRenderIsPinnedToOneSnapshot`), which drive a rebuild from inside the
  read and require the page to stay the first build's.
- The dashboard frontend is `web/` (Vite + Preact + TypeScript + Tailwind CSS 4
  + shadcn/ui primitives), built into `assets/app.js` and `assets/style.css` by
  `make web-build`. The built files are committed, and `make build` runs that
  bundler before `uv build`, so a wheel always carries the current sources. The
  committed bytes are checked by `make check-bundle-clean`, which the CI build
  job runs after its first build and `make all` runs locally: the two-build
  reproducibility comparison cannot tell a stale commit from a fresh one,
  because both trees rebuild the same bytes from the same sources. It fails
  when the build changed a tracked file under `src/recoverage/assets`. Never
  hand-edit them.
- The cell-state vocabulary is owned by rebrew (`rebrew.build_db._KNOWN_CELL_STATES`)
  and must be covered on the rendering side: `potato.COLORS` + `LEGEND_ITEMS`,
  and `web/app/grid/pack.ts` `STATE_SLOTS`/`PALETTE_VARS`/`FILTER_KEY`. An unmapped
  state paints as an undocumented gap, which contradicts `/stats` — `verified`
  is counted there as an exact match. Tests in `test_potato.py`
  (`TestCellStateVocabularyCoverage`) and `test_server.py` (`TestSpaStateVocabulary`)
  fail on a gap; extend all of them together when rebrew adds a state.
- The coverage map is a canvas, so the accessibility of the whole map is
  carried by three things in `CoverageMap.tsx` and one stylesheet rule, and a
  change to any of them is a change to all of them. The wrapper is
  `role="application"` with `aria-label` (section) and `aria-describedby` (the
  key map, in the hidden hint paragraph); it is NOT a listbox, which promises
  `option` descendants a canvas cannot have and announces an empty widget. The
  value lives in the hidden `role="status"` paragraph, written by
  `describe` on every cursor move, selection and jump, so a screen reader
  hears the same block, address range, state and function name the hover
  `title` shows. A new way to move the cursor calls `setCursor` with
  `describe`; a new cell field worth announcing goes in `describe`
  alone, so the tooltip and the announcement cannot drift. A scroll container
  that holds content no other control reaches (the code panes, the modal body)
  carries `tabIndex={0}` and `role="region"`, because an unfocusable scroll
  container is unreachable from the keyboard. Every page-wide animation is
  behind `prefers-reduced-motion`: the cursor's `scrollTo` and the body's
  theme transition, the latter by wrapping it in a `no-preference` media query
  rather than shortening it. Potato's equivalent names are on the pills
  (`aria-label` naming the filter and on/off, `aria-current` on the selected
  one) and its section tabs (`aria-current="page"`), pinned by
  `tests/test_potato.py` (`TestRenderedPageNamesAndStates`); its layout tables
  are the retro surface the design asks for, and its `lang`, its skip link,
  its block `alt` text and its function-list `scope="col"` headers are
  deliberate.
- The listener's socket family comes from the bind address, not from a
  fixed class: `wsgiref`'s `WSGIServer` inherits `http.server.HTTPServer`'s
  `AF_INET` and never changes it, so an IPv6 address `config.validate_bind`
  accepts (`--bind ::1`, `::`) fails in `socket.bind()` on every platform and
  the `serve` OSError handler blames another instance for it. `cli.
  _server_class_for` probes the address with `getaddrinfo` and returns
  `_ThreadingWSGIServer6` when it resolves to IPv6 only, so a hostname that is
  v6-only is covered alongside the literal; a name offering both keeps
  `AF_INET`. Pinned by `tests/test_lifecycle.py` (`TestBindAddressFamily`).
- Every `RECOVERAGE_*` value is converted and validated at startup, and the
  one with no format to convert still has a floor: `config.validate_bind`
  rejects an address carrying whitespace or a control character, and a colon
  outside an IPv6 literal, because those survive the banner and fail later as
  a `getaddrinfo` error raised once the DB watcher, the cache warmup and the
  browser opener are already running. The CLI's `--bind` calls the same
  function with `--bind` as the name in the error, because the flag and the
  variable are one setting with one floor. A new string-valued setting takes
  the same treatment: validated in `config.py`, reached by both sources. An
  INTEGER flag reaches the variable's floor by being declared `str` and parsed
  by `config`'s own reader: click's `INT`/`FLOAT` run the value through
  `int()`/`float()`, which take digits from every Unicode Nd set, read `_` as a
  separator and accept `inf`/`nan`, so `--port 1_0` opened port 10 and
  `--min-coverage inf` was a threshold no percentage satisfies. `--port` goes
  through `_checked_port` and `--min-coverage` through `_checked_min_coverage`;
  a new numeric flag parses its own text the same way.
- `RECOVERAGE_DB` moves what is READ, and rebrew resolves what a regen WRITES
  from `rebrew-project.toml` alone (it has no environment override), so the two
  can name different directories. A regen in that state is refused rather than
  run: it would rewrite documents no served directory reads and report `Done`
  while the dashboard stayed exactly as stale, which is worse than a regen that
  failed loudly. `regen._check_writes_where_the_dashboard_reads` compares
  `rebrew.workspace.db_dir(root)` against `config.db_override()` before rebrew
  runs and raises `RegenDbMismatchError`; the CLI exits 2 (misconfiguration,
  and rebrew never ran) and the API answers the JSON 500 with the refusal. A
  new consumer of the override is on the read side and inherits the refusal.
- A setting whose value is only meaningful in a narrower form is REJECTED
  there, never dropped: `cli._allowed_origins` refuses a CORS origin that is
  not one a browser could send, and the refusal is a `ConfigError` from inside
  `_resolve_serve_config`, so `serve` and `recoverage config` exit 2 on it and
  the banner, `recoverage config` and the request-path allowlist are one list.
  That check is `cli._is_browser_origin` (`scheme://host[:port]` and nothing
  else), NOT `server._normalize_origin`: the reducer exists to READ whatever
  arrives on a request and drops a path, a query and a missing scheme, so
  validating an operator's allowlist through it stores a different entry than
  the one written, and the mismatch surfaces as a browser refusing a read
  rather than as startup refusing an origin. `_cors_warnings` is driven by
  `_ServeConfig.cors_origins_requested`, the list as written, and never by
  `cors_origins`: the installed list is empty whenever CORS is off, which is
  what made the "no effect without --cors" arm unreachable.
  A dropped entry is the worst outcome available: the server comes up an entry
  short and refuses precisely the reads the entry was written for. The same
  holds for a value that is SET but EMPTY, which is how a unit file, a
  container env and a CI job all spell "not configured" — an empty
  `RECOVERAGE_CORS_ORIGIN` starts a server with CORS on and an allowlist of
  nothing. `RECOVERAGE_TOKEN` is the one deliberate exception, and
  `tests/test_config.py` pins it: empty means auth off, on purpose, because
  the same spellings would otherwise leave a token-guarded deployment
  unauthenticated in exactly the way the empty allowlist does.
- The frontend is linted with oxlint under the `@rikalabs/oxlint-standards`
  strict preset plus the vendored anti-slop rules, and type checked by
  `tsc --noEmit` over `web/tsconfig.json` (`strict` plus
  `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` and the rest). The
  oxlint preset is flattened with `typeAware: false`, so that `tsc` run is the
  only thing verifying those type settings, and it is a gate rather than a
  convenience: `make typecheck-web` is in `make all` and the web-lint CI job,
  and `tests/test_supply_chain.py` (`TestFrontendAnalysisIsEnforced`) fails
  when a package.json analysis script has no Makefile target running it, or
  when the target that runs it is in neither `make all` nor CI. Rationale-bearing
  `oxlint-disable` comments are the sanctioned escape hatch where a Preact
  idiom or a platform constraint collides with a rule (see `oxlint.config.ts`).
- Search compares names through `server.fold_match`, never a hand-written
  comparison: both sides go through `server.fold_text` (NFC composition plus
  `str.casefold`), so a non-ASCII term matches, `ß` matches `ss`, and the NFD
  spelling a user pastes matches the NFC one rebrew stored. A NULL column folds
  as the empty string, which no non-empty term matches — the answer
  `COALESCE(col, '')` gave a nullable `symbol`. The SPA folds in
  `web/app/App.tsx` (`matchedNames`) with `toLowerCase` where the server uses
  `casefold`, so a case-fold expansion such as `ß` → `ss` matches through the API
  and not in the SPA. Name resolution folds the same way:
  `server.lookup_function` /
  `server.lookup_global` try the VA arm first, then byte equality on the name,
  then the folded comparison — so the row the search highlighted opens by
  name. A lookup added beside them (globals, labels, anything compared for
  identity) must fold too; byte equality there is the bug this paragraph exists
  to stop.
- `_log_safe` escapes the characters that end a log line, which is C0, DEL,
  the C1 controls, and U+2028/U+2029 (a header value carries those literally,
  and every viewer that breaks on `\n` breaks on them). It deliberately leaves
  bidi controls alone: those reorder a line rather than split it, so escaping
  them is a log-injection question, not a line-splitting one. An exception
  message reaches the same treatment: a coverage document is untrusted input
  like a request path, and its parse error is read precisely when a line must
  stay one line.
- A log line about a request carries the counters as fields, not only as
  prose: `server.request_log_fields` builds the `extra=` for the request-path
  records (per-request line, 500, 503 `db_unavailable`, the two security
  rejections) and `api._regen_log_fields` for the regen lifecycle, and
  `cli.StructuredFormatter` renders them as sorted `key=JSON` pairs after the
  message. The request id names the request, the counters say how many, and
  the fields are what make one pivot into the other without a regular
  expression over prose. A record that carries no fields renders exactly as
  the plain format did (every record from bottle or rebrew). A new log line
  whose values an operator would filter on names the helper; a new formatter
  is not the place to add a second rendering.
- `server.set_auth_cookie` is the one place the `?token=` share-link cookie is
  written, and every page route a share link can land on calls it: `/` and
  `/potato`. Both pages link with relative URLs, so the cookie is what carries
  the credential past the first click; a page route that skips it renders once
  and answers the 401 page on every link the reader follows. The cookie's name
  is `server.AUTH_COOKIE_NAME`, which `_require_auth` reads it back under.
- The authorization model is two principals and no per-object ACL, so a new
  handler does not repeat a check: `server._require_auth` is a `before_request`
  hook, so every route (pages, `/api/*`, `/potato`, static, the `/src` and
  `/original` file trees) is behind the bearer token, and a target/section/VA
  in the path has no owner to authorize against. `POST /api/regen` is the only
  privileged operation, and its gate is local to the handler: the peer must be
  loopback (`_peer_is_loopback`) and, when an `Origin` is present, the origin
  must be *this* dashboard (`server.origin_is_this_dashboard` compares the
  origin's host and port against the request's own `Host`, falling back to
  loopback membership only when the request carries no `Host`). A hostname
  membership test is not the same check: a page served from any other loopback
  port passes it, and the browser refuses to hand that page the reply, so the
  rebuild it starts is one the operator neither asked for nor sees. A new
  privileged operation copies that gate rather than trusting a loopback peer,
  and the fuzz campaign in `tests/test_fuzz.py` (`TestRegenOriginSameOrigin`)
  judges it against `urlsplit` rather than against the helper.
- `POST /api/regen` is the package's one retried side effect, and its
  `Idempotency-Key` names the OPERATION, not the request: the SPA mints the
  key once per click (`api.newRegenKey`) and `postRegen` re-sends the same one
  on a transport failure, because a key minted per request is a new operation
  to `api._REGEN_COMPLETED_KEYS` and a lost response then costs a second full
  pipeline. A new client of that endpoint takes the key from its action site,
  not from inside the send helper, and re-sends on a lost response rather than
  leaving the reader to click again. The other in-flight marker, the `/data`
  single-flight claim in `api._DATA_CACHE_BUILDING`, follows the same rule: an
  in-flight marker whose owner was killed is reclaimed on its deadline
  (`_DATA_CACHE_BUILD_WAIT_SECONDS`), never left registered for a waiter that
  no `finally` will ever wake. Pinned at `tests/test_concurrency.py`
  (`TestDataSingleFlight`), which releases a herd of simultaneous cold misses
  through one barrier and fails when the payload is built more than once.
- Every integer a request supplies goes through `server.parse_ascii_int` (with
  `server.strip_sign` and `api._parse_byte_count` on top): ASCII digits in the
  stated base, and nothing else. `int(x, base)` is not that check, because it
  takes digits from the whole Unicode Nd/Nl/No sets and the `_` separator, so
  `?size=٤٠٩٦` served a 4096-byte slice and `?page=1_0` opened page 10. The
  call sites are `api._parse_byte_count` (`?size=` on `/asm` and `/bytes`,
  `?offset=` on `/bytes`, decimal or `0x`-prefixed hex), `api._page_int`
  (`?limit=` and `?offset=`, no sign and no prefix), the batch POST VA list,
  Potato Mode's `?page=` and `?idx=`, and `server._read_chunked_body`'s chunk
  size line, where a `1_0` the widened parse read as 16 made the reader consume
  16 bytes of a connection it had no framing for. A new request-supplied number
  names
  `server.parse_ascii_int` or explains why it does not, and the rule is the one
  `config._ASCII_INT` already holds every `RECOVERAGE_*` integer to. Pinned at
  `tests/test_api.py` (`TestSliceValidationDetail`) and `tests/test_potato.py`
  (`TestBlockPosition`), with the non-ASCII digit spellings in `_NUM_TOKENS` so the
  fuzz campaigns meet them. `parse_va_candidates`, which `/functions/<va>` and
  `/asm` read a VA through, is rebrew's and parses the same way.
- A request BODY is read through `server.read_request_body(limit)`, never
  through bottle's `request.body`. That property drains the whole declared
  `Content-Length` into a `BytesIO` before the handler sees a byte of it, and
  spills past `MEMFILE_MAX` (100 KiB) into a `NamedTemporaryFile` — on a tmpfs
  `/tmp`, so RAM — so the endpoint's own cap ran long after the resource it
  exists to bound was allocated. `read_request_body` compares the declared
  length first (a 4 GB request costs one header comparison), reads a framed
  body to its DECLARED length and no further, decodes a chunked body under the
  same cap on the DECODED bytes, and stops within one chunk of the limit
  otherwise. The declared length bounds the read, not only the refusal, because
  under the serving stack `wsgi.input` is the socket's buffered reader: a read
  past the last declared byte blocks until the client hangs up, while the
  client is waiting for the response. A `BytesIO` short-reads, so a test over
  one cannot catch a drain to EOF — the read is pinned against a stream that
  refuses to run off the end of the frame (`tests/test_api.py`,
  `TestFramedBodyIsReadToItsDeclaredLength`). A chunk-size line is read through
  `server.parse_ascii_int`, not `int(x, 16)`. Every refusal it raises leaves the
  rest of the body in the socket, so the answer must carry `Connection: close`;
  `api._body_rejected` is the one helper that puts it there. A new endpoint
  reading a body calls the helper for both `RequestBodyTooLargeError` and
  `RequestBodyMalformedError`.
- Connections are capped, not just deadlines. `_CLIENT_SOCKET_TIMEOUT_SECONDS`
  bounds how LONG a handler thread lives and never how MANY there are:
  ThreadingMixIn starts one per accept without asking, and a peer that opens a
  connection and sends nothing parks in the request-line read for the full
  deadline. `_ThreadingWSGIServer.process_request` takes the slot before the
  thread and refuses with a 503 at `_MAX_CONNECTIONS`; the release wraps
  `process_request_thread` and the thread-creation failure, so the counter and
  the descriptors cannot disagree. `_SSE_MAX_CLIENTS` is the same bound one
  level in, for the one route whose response is held open by design. A new
  route that pins a connection for a long time names that constant in its own
  reasoning. Pinned at `tests/test_lifecycle.py`
  (`TestClientConnectionDeadline::test_connections_are_capped_and_the_slot_is_released`)
  and `tests/test_api.py` (`TestBatchFunctionLookup`'s body-cap cases, which
  assert the read COUNT, not just the 413).
- The untrusted-input surfaces (query parameters, the batch POST body, request
  headers, the `/potato` query string, the `/src` and `/original` path
  segments, the access-gating headers, the `--token` gate, the `RECOVERAGE_*`
  readers) are fuzzed
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
  (`Origin`/`Host`, `REMOTE_ADDR`, `X-Request-ID`, `Idempotency-Key`) and the
  `--token` gate (`Authorization: Bearer`, `?token=`, the `recoverage_token`
  cookie) are the
  one class of surface where a wrong answer is a bypass rather than a bad
  render, so their campaigns assert the security property, not the status code:
  a normalized origin is a fixed point and carries no userinfo, escape, control
  byte or whitespace; a value that matches the CORS allowlist really is the
  allowlisted origin and is the only one echoed as
  `Access-Control-Allow-Origin`; `_peer_is_loopback` accepts `127.0.0.1` and
  `::1` and nothing else, judged against `ipaddress` rather than against the
  parser under test; the request id carries no control byte; an accepted
  idempotency key is inside the ledger's alphabet and length, and the ledger
  stays within `_REGEN_KEY_MAX` however many distinct keys arrive. The token
  gate's accept decision is judged against the extraction rules
  `server._require_auth` documents, not against the status code: a carrier
  is served only when the value the gate extracts from it is the configured
  token, with each carrier's own grammar as the oracle (`http.cookies`
  `SimpleCookie` for the cookie, percent-decoding for the query, and the
  latin-1/UTF-8 read `server._header` does for the header), so a
  case-folding, trimming or percent-decoding shortcut in the gate fails the
  campaign. A new credential carrier names the same oracle. The
  `RECOVERAGE_*` campaigns hold the module's own contract instead: every reader
  answers a value in its documented range or raises `ConfigError`, and never a
  third thing (a non-ASCII digit is a rejected port, not a bound one). Two
  campaigns are differential rather than crash-only, because a status code
  cannot see a wrong answer: the search campaigns rebuild the matching set in
  Python (`server.fold_text`, the one folding both sides go through) and demand
  the query agree row for row; the decoder campaigns pin `server.path_param` and
  `server.decode_query_value` against `urllib.parse.unquote`, one pass and
  never a raise, with a 200 on `/src` and `/original` asserted byte-identical
  to the file on disk. A search term cannot be a wildcard: the comparison is a
  Python substring test, so there is no pattern to unwind and no spelling that
  means anything but the literal text. No
  coverage-guided fuzzer is a
  project dependency, so the corpus lives in that file; a new surface gets a
  corpus entry there, not a new dependency.
