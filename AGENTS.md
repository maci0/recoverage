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
├── MANIFEST.in             # What the sdist carries: the backend pin, the man page and the
│                           #   changelog; not the test suite, not the generated egg-info
├── man/recoverage.1       # Man page for the console script; installed by the wheel through
│                           #   [tool.setuptools.data-files] (share/man/man1)
├── README.md               # User-facing docs
├── CHANGELOG.md            # Release history
├── CONTRIBUTING.md         # Bootstrap, edit-test loop, local/CI parity table
├── Makefile                # Contributor targets (`make help`); wraps the CI commands
├── LICENSE                  # MIT
├── NOTICE                   # Grants for the third-party browser assets bundled in the wheel
├── SECURITY.md             # Supported version line and where a report goes
├── package.json            # bun scripts: lint, build:web, dev:web, typecheck:web
├── .env.example            # Every RECOVERAGE_* setting, commented, with the default the
│                           #   server uses. The deployment copy of the surface, drafted from for a
│                           #   unit file or a container spec; pinned to config.KNOWN_VARS and the
│                           #   module's defaults by tests/test_config.py (TestEnvExample)
├── web/                    # frontend sources: vite.config.ts + app/ (Preact + Tailwind)
│                           #   app/system/ is a verbatim copy of relumea.ai's src/system
│                           #   (tokens.css, icons/Icon.tsx, icons/paths.ts): never edit it,
│                           #   re-copy after an upstream change
├── components.json         # shadcn config; @shadcn/lint reads the token set from the
│                           #   stylesheet it names (web/app/index.css)
├── .yamllint.yaml          # yamllint config for .github/ (document-start, 100 cols)
├── oxlint.config.ts        # JS/TS lint config (see the tooling notes below)
├── .github/
│   ├── actions/sibling-rebrew/action.yml  # composite step: caches the sibling checkout, runs
│                           #   tools/ci_clone_rebrew.sh
│   └── workflows/ci.yml     # lint, web-lint, test matrix, build, smoke, sbom
├── docs/                   # Screenshots & design doc
│   ├── DESIGN.md           # Architecture and design decisions
│   ├── DESIGN_PRINCIPLES.md  # Core operational philosophies
│   ├── USER_STORIES.md     # User stories with acceptance criteria
│   ├── THREAT_MODEL.md     # Attack surface, trust boundaries, risk ranking
│   ├── UPGRADING.md        # Before/after for every major that broke a consumer
│   ├── ideas.md            # Future improvement ideas
│   └── *.png               # Screenshots for the README
├── tools/                  # lint_html.py, smoke.py, payload_budget.py,
│                           # _serve_harness.py, oxlint/, ci_clone_rebrew.sh,
│                           # flatten_rikalabs_strict.py, normalize_sdist.py,
│                           # check_wheel_assets.py, vendor_manifest.py,
│                           # bundled_js_inventory.py
├── tests/
│   ├── conftest.py           # Shared fixtures (WSGI request helpers, session document build)
│   ├── coverage_fixture.py   # Builders for synthetic coverage documents, and the shared
│   │                         #   document set `build_synthetic_coverage` writes
│   ├── test_build.py          # Artifact build: shipped files, the man page, reproducible bytes
│   ├── test_api.py           # API validation, security, SQL injection tests
│   ├── test_cli.py           # CSV export, formatting, edge case tests
│   ├── test_lifecycle.py     # Lifecycle: regen ordering, the cross-process regen lock, browser-opener reaping
│   ├── test_paths.py         # Coverage directory resolution tests
│   ├── test_documents.py     # Per-document reload, the persisted parse, the cold herd
│   ├── test_config.py        # RECOVERAGE_* env: parsing, precedence, fail-fast
│   ├── test_server.py        # Compression, encoding, snapshot, path helper tests
│   ├── test_serve_harness.py # Shared serve harness (builds the sample coverage, boots the server)
│   ├── test_lint_html.py     # The vnu gate's start-up failures: no jar, no JRE, a refused exec
│   ├── test_potato.py        # Potato Mode unit tests
│   ├── test_perf.py          # Deterministic perf gates (work counters, not wall clock)
│   ├── test_metrics.py       # Request id, RED counters, slow-request log line
│   ├── test_release.py       # Release contract: version, changelog, declared floors,
│   │                         #   the upgrade guide's coverage of the breaking majors,
│   │                         #   the public-surface baseline the removals are read against
│   ├── public_surface.txt    # The package's public module-level surface at the last
│   │                         #   release that shipped with no unrecorded removal
│   ├── test_supply_chain.py  # Pin contracts: rebrew tag/SHA, one clone mechanism, preset
│   │                         #   license, declared-vs-imported deps, npm lock pin + integrity,
│   │                         #   bundled-asset grants
│   ├── test_fuzz.py          # Seeded mutation campaigns over the untrusted-input surfaces
│   ├── test_concurrency.py   # Barrier-driven races: /data single flight, cache invalidation
│   │                         #   under load, counter balance, the admission cap, the auth window
│   ├── test_import_graph.py  # In-package import graph: level order + acyclicity
│   ├── test_frontend_import_graph.py  # web/app import graph: directory levels + acyclicity
│   └── test_playwright.py    # Browser integration tests
└── src/recoverage/
    ├── __init__.py
    ├── __main__.py          # python -m recoverage
    ├── _paths.py            # Coverage directory resolution (RECOVERAGE_DB, db_dir)
    ├── documents.py         # Coverage documents read per file; the TOML parse persisted
    │                        #   as JSON under $XDG_CACHE_HOME/recoverage/documents/
    ├── config.py            # RECOVERAGE_* env: flag defaults, validation, startup banner
    ├── devserver.py         # WSGI serving stack serve() binds: threading server, keep-alive handlers,
    │                        #   admission cap + socket deadline (RECOVERAGE_MAX_CONNECTIONS/CLIENT_TIMEOUT)
    ├── clock.py             # The one time source (monotonic / wall-clock) the request path reads
    ├── metrics.py           # In-process counters: RED requests (REQUESTS) + regen (REGEN), read by /api/health
    ├── cli.py               # Typer CLI entry point (serve, stats, export, check, regen, open)
    ├── server.py            # Bottle app, shared helpers & compression
    ├── disasm.py            # Capstone disassembly (optional extra): loadability probe,
    │                        #   per-thread Cs per image width (read off the PE/ELF
    │                        #   container header), memo
    ├── regen.py             # In-process rebrew regen (calls rebrew as a library), cross-process lock
    ├── api.py               # REST API routes (/api/*)
    ├── ui.py                # UI routes (/, static files)
    ├── potato.py            # Potato Mode renderer + the /potato route
    ├── webapp.py            # Composition root: imports api+ui+potato so app has every route
    └── assets/
        ├── index.html       # SPA shell
        ├── style.css        # built Tailwind output — generated, never hand-edited
        ├── print.css        # Print stylesheet
        ├── app.js           # built bundle — generated, never hand-edited
        ├── archivo.woff2    # brand fonts (OFL, credited in NOTICE), committed as-is
        ├── jetbrains-mono.woff2
        └── favicon.svg      # the relumea mark
```

Frontend lint (bun + a JDK; see `bun run lint:js|html`): `oxlint.config.ts` is
the JS/TS config, `tools/lint_html.py` runs vnu over both the static assets and
the documents the server actually serves, and `tools/oxlint/anti-slop/` is a
vendored upstream copy to keep in sync. `@shadcn/lint` runs as an oxlint plugin
and refuses raw colours, arbitrary values, inline styles and classes outside the
relumea token set; its allowlist names only hook classes that carry no style. Both of vnu's start-up inputs are
checked by name before it is launched (`tools/lint_html.py`'s
`RUNNER_UNAVAILABLE`), so a missing `bun install` or a missing JRE is a status
of its own rather than a `FileNotFoundError` and a code no reader can tell from
a finding; `tests/test_lint_html.py` holds that. `lint:js` runs oxlint with
`--deny-warnings --report-unused-disable-directives`, so an
`oxlint-disable-next-line` whose rule no longer reports fails the run rather
than outliving the finding it silences: that is the frontend's RUF100 and
`warn_unused_ignores`, and `tests/test_supply_chain.py`
(`TestFrontendAnalysisIsEnforced`) holds both flags in place.
`tools/oxlint/rikalabs-strict.json` is
generated: never hand-edit it, bump `@rikalabs/oxlint-standards` then run
`make regen-oxlint` (which wraps `tools/flatten_rikalabs_strict.py` and the
`bun install` it reads `node_modules` from). The script's docstring and
`oxlint.config.ts` own the why behind that preset. The vendored plugin is
inventoried the same way, because no registry manifest reaches a directory
copied into the repo: `tools/vendor_manifest.py` writes
`tools/oxlint/anti-slop.manifest.json` (upstream, license, every file with its
sha256, the excluded paths), and `tests/test_supply_chain.py` fails when the
tree and that record disagree. Re-vendor by replacing the directory, running
`make vendor-manifest` (the target that wraps the script), then `make web-lint`.

## Commands

`make help` lists the contributor targets. Every one wraps the exact command
CI runs; `make all` is the local mirror of the whole pipeline.

```bash
# Bootstrap (clean clone; rebrew is a ../rebrew path dependency)
make clone-rebrew           # clone the pinned rebrew into ../rebrew (pin: tools/ci_clone_rebrew.sh)
make setup                  # uv sync --locked --extra dev
make build                  # wheel + sdist into dist/, reproducibly
uv sync --locked --extra dev --extra playwright   # browser tests: playwright, pytest-playwright

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
make fuzz                  # the seeded fuzz campaigns (SEED=, ITERATIONS= widen one)
make test-browser          # uv sync --locked --extra dev --extra playwright, the
                            #   chromium install, then pytest tests/test_playwright.py
make check-bundle-clean    # rebuild web/ and fail if a tracked asset changed
make lint                   # uv run --locked --extra dev python -m ruff check src/ tests/ tools/
make type-check             # uv run --locked --extra dev python -m mypy (src/ + tools/ + the annotated test modules, strict)
make format-check           # uv run --locked --extra dev python -m ruff format --check src/ tests/ tools/
make format                 # uv run --locked --extra dev python -m ruff format (writes)
make shell-lint             # shellcheck -x tools/*.sh (needs shellcheck on PATH)
make yaml-lint              # yamllint -c .yamllint.yaml .github/ (needs yamllint on PATH)
make web-build              # bun install --frozen-lockfile && bun run build:web (the dashboard bundle)
make web-dev                # bun install --frozen-lockfile && bun run dev:web (the frontend edit loop)
make web-lint               # bun install --frozen-lockfile && bun run lint
make typecheck-web          # bun install --frozen-lockfile && bun run typecheck:web (tsc --noEmit)
make smoke                  # uv run --locked --extra dev python tools/smoke.py
make payload-budget         # the inlined shell's size at each static encoding, which the
                            #   payload budget in docs/DESIGN.md quotes
make smoke-fail             # same, against a deliberately corrupt db
make browser-sbom           # the npm packages compiled into the shipped browser
                            #   assets, with the version and digest bun.lock pinned
                            #   (the sbom job uploads this as recoverage-browser-sbom)
make browser-sbom-spdx      # the same rows as an SPDX 2.3 document, which is the
                            #   shape a vulnerability scanner ingests
                            #   (recoverage-browser-spdx)
make python-sbom            # the resolved Python tree (uv.lock, every extra, hashed)
                            #   plus the rebrew pin: the sbom job's other artifact
make license-inventory      # the license every package the resolved tree
                            #   installs is under, and a refusal for anything
                            #   not permissive (tools/license_inventory.py)
make all                    # every check CI runs, one command

# Frontend lint detail (requires bun and java on PATH)
bun run lint                # oxlint (Rika-Labs strict preset + vendored anti-slop) + vnu HTML/CSS
bun run lint:js             # oxlint only (warnings fail, unused directives reported)
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
uv sync --locked --extra dev --extra playwright && uv run playwright install chromium
uv run --locked --extra dev python -m pytest tests/test_playwright.py
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
script's `REBREW_URL` default supplies it. The action also restores the
destination from an `actions/cache` entry keyed on
`hashFiles('tools/ci_clone_rebrew.sh')`, so the eight installing jobs of one run
share a clone instead of each fetching the same commit, and a pin bump misses
the key. There is no `restore-keys` fallback: an older rebrew that still
resolves is the failure the tag-and-commit check exists to catch. A restored
tree is therefore not trusted on the cache's word; the script keeps a
destination whose `HEAD` is `REBREW_SHA` and whose tree is clean, and clones
over anything else, which is also what makes a second `make clone-rebrew` a
no-op on a tree the first one fetched. The
script's `REBREW_REF`/`REBREW_SHA` defaults are the whole pin: the clone fails
unless the tag still resolves to the commit, so a moved tag cannot change the
dependency silently. Those defaults must keep matching `uv.lock` (checked by
`tests/test_supply_chain.py`, which also asserts that no job or the action
carries a pin of its own, and that no second local action appears): when
rebrew's dependencies change, re-lock in a tree with the sibling present and
bump the script alone. The `sbom` job
deliberately has no such step, because `uv export --frozen` reads the lock
alone.

The `sbom` job carries the second half of the inventory as well.
`uv export` reads `uv.lock`, which knows nothing about the browser bundle, and
the wheel ships that bundle: `make web-build` compiles preact, highlight.js,
tailwindcss, clsx, tailwind-merge and class-variance-authority into
`src/recoverage/assets/`, which `package-data` globs. So the job also runs
`tools/bundled_js_inventory.py` (stdlib only, hence `setup-python` there rather
than a synced env) and uploads the result as `recoverage-browser-sbom`. That
tool's `SHIPPED` list is the ONE record of which devDependencies reach a
consumer, with the reason each ships; `tests/test_supply_chain.py`
(`TestBrowserBundleInventory`) holds it against `package.json`, `bun.lock`, the
Tailwind version in the committed `style.css` and `NOTICE`'s credit list, and
`make browser-sbom` prints the same inventory without CI. A dependency that
starts reaching the bundle joins that list, `NOTICE` and the test class in the
same change; one that stops reaching it leaves all three.

That text inventory is a line per package, which answers a reader and not a
scanner: `recoverage-python-sbom` is a hashed requirements.txt, and the browser
half had no standard shape, so the code running in a consumer's browser was
described to nobody but this project. The same rows are therefore exported as
an SPDX 2.3 JSON document (`--format spdx`, uploaded as
`recoverage-browser-spdx`), and the grant each entry declares lives on the
`Shipped` record beside the reason it ships, because a package with a version
and a digest and no license is an entry nobody can act on. `created` is read
from `SOURCE_DATE_EPOCH`, the same stamp `make build` exports and the sbom job
sets from the commit's own time, because the job uploads this file and two runs
of one commit have to produce the same bytes; the wall clock is the fallback,
and a `SOURCE_DATE_EPOCH` that is not a timestamp is refused rather than
ignored. `tests/test_supply_chain.py` (`TestBrowserSpdxExport`) holds the
document to the fields an SPDX reader requires, the versions `bun.lock`
resolved, the digests it pinned, the licenses `NOTICE` credits, and the
reproducible stamp.

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
Two bots update this tree and each ecosystem has exactly one of them:
`renovate.json` reads `pyproject.toml` and `bun.lock` (Dependabot aborts on
both, the `bun.lock` with no `package-lock.json` beside it and the
`[tool.uv.sources]` sibling path), and `.github/dependabot.yml` owns the
actions. `tests/test_supply_chain.py` (`TestUpdateBots`) holds the split from
both sides, because the overlap costs two PRs against one pin and whichever
merges first makes the other stale.
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
- A `### Breaking` entry also gets a section in `docs/UPGRADING.md`, written
  while the change is still under `[Unreleased]`: the before, the after, and
  the thing the reader has to change. The changelog is read release by
  release; the upgrade guide is read by someone arriving at a deployment to
  do the upgrade, and notes written after the tag are notes nobody reads.
  `tests/test_release.py` (`TestUpgradeGuideCoversEveryMajor`) holds the two
  against each other, so a major that ships a breaking change without one
  fails the suite in the release commit that has to write the section anyway.
  The guide carries no version literal of its own: its per-release headings
  are the changelog's own `## [X.Y.Z]` spellings, so the release commit
  renames `[Unreleased]` to the version it ships as and the test follows it
  with no second list to update.
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
- The one break the changelog cannot see is one that leaves no prose behind:
  a module-level name deleted in a commit the tree calls a refactor, which
  `CONTRIBUTING.md` says gets no entry. Six constants in `potato.py` went that
  way, and an importer of `recoverage.potato` got an `AttributeError` the
  release notes did not mention. `tests/public_surface.txt` is the package's
  public module-level surface (functions, classes and module-level assignments
  without a leading underscore) as of the last release that shipped with no
  unrecorded removal, and
  `tests/test_release.py::TestPublicSurfaceChangesAreRecorded` fails when a
  name in it is gone and no `Removed` or `Breaking` entry NAMES it. The gate
  matches per symbol rather than per group: one recorded removal used to
  clear every other name in the file, which is how 4.0.0's six `FILTER_*`
  pill caps went on to cover the three asset constants 4.1.0 removed
  unwritten. Adding a name needs neither an entry nor a baseline edit, which
  is why the gate reads one direction: a baseline carried forward on every
  addition would fail constantly and stop being read. Rewriting the baseline
  is the release commit's move, made beside the entry that records what it
  dropped. A name that only this tree imports is private whatever its
  spelling, so it is renamed with a leading underscore rather than recorded.
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
| `/<filename:app.js, style.css, print.css, favicon.svg, archivo.woff2, jetbrains-mono.woff2>` | GET | The packaged static assets, `no-cache` with a strong `ETag` |
| `/potato` | GET | Potato Mode (pure-HTML fallback) |
| `/api/health` | GET | Server version, the settings the process resolved, DB info, installed extras, request/regen/stream/connection counters, cache hit-miss |
| `/api/targets` | GET | List available targets (ETag-revalidating) |
| `/api/targets/<target>/stats` | GET | Per-section coverage stats (ETag-revalidating) |
| `/api/targets/<target>/data` | GET | Full section + cell data. `?section=` narrows the cells (siblings omit the key); `?index=0` omits `search_index`, which the SPA holds already, so a section switch does not re-send it (`index` is a flag: `0`, `1` or absent, anything else a 400) |
| `/api/targets/<target>/functions` | GET | Paginated function list (`?status=` takes rebrew's status vocabulary; anything else is a 400). ETag-revalidating like `/stats` and `/data`: every parameter that shapes the page is in the validator |
| `/api/targets/<target>/functions` | POST | Batch lookup: `{"vas": [...]}` → function/global details in input order (`application/json`, else 415) |
| `/api/targets/<target>/functions/<va>` | GET | Function/global detail (ETag-revalidating: the tag names the snapshot, the target and the requested spelling) |
| `/api/targets/<target>/asm` | GET | Disassembly (requires capstone). `?size=` is capped at `_MAX_SLICE_SIZE` AND at what the section holds from `?va=`, so a va at the section's tail cannot read the next section's bytes |
| `/api/targets/<target>/sections/<section>/bytes` | GET | Raw byte slice |
| `/api/events` | GET | Server-Sent Events: `db-updated` when the coverage documents change (SPA auto-refresh) |
| `/api/regen` | POST | Re-run catalog + build-db (localhost only, rate-limited; optional `Idempotency-Key` header, replayed from a bounded ledger) |

Search folds both sides the same way in Python: `server.fold_text` is NFC
composition plus `str.casefold`, and `server.fold_match` is the substring test
both the API list, the Potato list and the name lookup run every column
through. The SPA folds through `format.foldForSearch` (the `foldedIndex` and
`matchedNames` memos in `web/app/App.tsx`), which is the same NFC composition
and, because `toLowerCase` has no one-to-many mapping, the `FULL_FOLD` table
standing in for the expansions `casefold` has and JavaScript does not. That
table is GENERATED (`tools/gen_full_fold.py`) and is every code point where
`toLowerCase` and `str.casefold` disagree, not a hand-picked sample: it was ten
ligatures, and the 173 it omitted were rows the API listed while the SPA
reported "0 matches" — `µ` (MICRO SIGN) against `μ` (GREEK SMALL MU) and `ſ`
(LATIN SMALL LETTER LONG S) against `s` are both spellings a firmware symbol
carries. A check that derives its own cases FROM the table (each entry is a
correct fold) passes a table that is half empty; only the completeness arm does
not, so `tests/test_server.py`
(`test_the_spa_fold_expansions_cover_every_casefold`) holds the shipped table
against `str.casefold` over every scalar code point, and the generator is the
one thing allowed to write it. One divergence is left standing on purpose:
28 code points where JavaScript's `toLowerCase` applies a SpecialCasing
composition Python's `str.lower` does not (`꟎` U+A7CE lowers to `꟏` in the
browser only), which no table entry can repair because the browser never
presents the character the key would name. The
HAYSTACK is folded once per index, not once per keystroke: it depends only on
`searchIndex`, so `foldedIndex` is keyed on that alone and `matchedNames` runs
a substring test over the folded rows. Folding per query re-ran `normalize` +
`toLowerCase` + the full-fold replace over every function in the target on
every character typed, inside the render the keystroke triggered. A new search
column joins `foldedIndex` rather than the per-keystroke pass, and a new fold
goes through `foldForSearch` (pinned at `tests/test_server.py`,
`TestSpaSearchFoldsLikeTheServer`).
This was a SQL split
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
     It returns a `dict()` COPY of `Section.bucket_counts`, the same fold
     rebrew derived at load, rather than counting the cells again:
     `server._section_summary` likewise reads `Section.buckets`,
     `Section.covered_bytes` and `Section.bucket_counts`, and `_summary` reads
     the `.text` section's, instead of walking the cells per request. A second
     pass over the largest section's cells is 2-6 ms on a 40k-cell `.text`,
     once per `/stats`, `/data` and Potato render. The counts these read are
     rebrew's, so `tests/test_server.py` (`TestBucketReconciliation`) pins
     them against an independent per-cell walk, and a cell-state vocabulary
     change lands in `rebrew.coverage_toml._BUCKET_OF_STATE` first, not here.
     The byte side reads that same fold rather than re-spelling it:
     `server._BUCKET_FOLD` is grouped off rebrew's `_BUCKET_OF_STATE`, because
     `Section.buckets` is keyed by cell STATE and a second hand-written copy of
     the grouping was a vocabulary this package drifted from silently (a state
     rebrew added summed into no counted bucket while `Section.covered_bytes`
     still counted it). A private name is read deliberately: it is the one
     place the fold exists, a rename fails this import loudly where the copy
     failed quietly, and `tests/test_server.py` (`TestBucketReconciliation`)
     holds what it hands over against a literal written in the test.
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
     table in `web/app/states.ts`, which the toolbar's pills are built from,
     and each one is a filter toggle rather than a second vocabulary. Every
     number the SPA prints goes through `format.percent1` or `format.count`
     (`web/app/lib/format.ts`): `percent1` is the JS half of `pct_1dp`, and
     `toFixed` there undid the same flooring the Python helper exists for.
     Both hand the digits to `toLocaleString`, so a served figure reads in the
     reader's own decimal separator and grouping rather than a `.` and a `,`
     that no non-English locale writes. A new served number in a component calls
     the helper rather than `toFixed` or a bare `String(...)`. The two
     similarity figures (the `functions.similarity` row and the
     `verify_results.similarity` one) are 0-1 FRACTIONS, so each surface scales
     before flooring: Potato Mode through `potato._similarity_pct` (which also
     leaves a non-finite stored value alone, since a coverage document is
     untrusted input and `pct_1dp` reaches `math.floor`, which raises on NaN),
     the SPA through `format.similarityPct`, which takes the fraction, scales
     and floors it AND refuses a value the document spelled as something else:
     `_plain` nulls a non-finite float but passes a string through, and
     `"87.3" * 100` is 8730, so a row read `8,730.0%` where Potato omits it. A
     bare `"%.1f"` in Potato rounded 99.99% up to a "100.0%" the dashboard
     showed as 99.9, so a new surface rendering either column calls
     `similarityPct` (SPA) or `potato._similarity_pct` rather than scaling and
     formatting by hand.
     The WIRE has its own rule, `server._plain`: a non-finite float read from a
     document becomes `null`, because `json.dumps` writes `NaN` / `Infinity`
     and no JSON parser outside Python accepts them, so one such figure would
     take the whole payload down at the SPA's `JSON.parse`. A document-derived
     number travelling into a response goes through `_plain`, and a number a
     new response serves raw does not survive the fuzz campaign in
     `tests/test_fuzz.py` (`TestCoverageDocumentContents`).
   - The catalog's `summary` blob is NOT stored in the document (the writer
     keeps the facts, not the precomputed answers). `server._summary` rebuilds
     it from the stored cells and functions, and `/stats` and `/data` serve the
     rebuild; a change there is a change to a served payload. The byte
     figures are the exception and take `Section.buckets` /
     `Section.covered_bytes`, which rebrew derives in `__post_init__`: a
     re-derivation of "every state but `none` counts as covered" here is a
     third copy of a rule rebrew owns, and it drifts silently, because the two
     answers land in the SAME response (`summary.coveredBytes` beside
     `sections[..].covered_bytes`) with a fixed fixture vocabulary to hide it.
     The same holds for a vocabulary: `server.DATA_MARKER_TYPES` is read off
     rebrew's `DATA_MARKERS`, not re-spelled, for the same reason.
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
- `typer>=0.27.2` (CLI framework)
- `zstandard>=0.22` (Zstandard compression)

Optional extras:
- `capstone>=5.0` (disassembly)
- `pygments>=2.21.0` (Potato Mode syntax highlighting)
- `playwright` (browser tests: `playwright>=1.62`, `pytest-playwright>=0.9.0`; `tests/test_playwright.py` is excluded from the default `addopts`)

Dev extra (`.[dev]`, what CI installs): `mypy>=1.14`, `pytest>=9.1.1`, `ruff>=0.16.7`.

`src/recoverage/py.typed` is the PEP 561 marker and ships in both artifacts
through `[tool.setuptools.package-data]`, so the annotations the mypy gate
enforces here reach a consumer's type checker instead of stopping at the
package boundary. It is an empty file on purpose: content in it declares a
package PARTIALLY typed (stubs only), which this one is not.
`tests/test_build.py` (`TestTypingMarker`) holds it in the tree and in the
manifest, because nothing at runtime reads it and a dropped marker is invisible
until someone else's mypy run goes quiet.

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
  `tools/normalize_sdist.py`. `web-build` exports the same two: it is a
  prerequisite of `build`, so it runs in its own shell, and the two bundle
  files it writes are packaged inputs rather than a by-product. setuptools
  stamps the *wheel* from
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
  produces the artifact, it `needs: test` so a red suite never attaches a
  downloadable wheel, and it is what makes reproducibility tested rather
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
  two checks off and the reason next to them in `[tool.mypy]`:
  `disallow_untyped_decorators` (every route handler wears a `@app.route`,
  and bottle is untyped, so the decorator erases the signature), and
  `no_implicit_reexport` (api.py, ui.py and potato.py import the shared
  `request`/`response`/`HTTPResponse` from `recoverage.server` on purpose).
  `warn_return_any` is ON: the four untyped boundaries whose values reach a
  return (bottle's `headers.get` and `SimpleTemplate.render`, `brotli.compress`,
  `json.load`, `socket.getsockname`) are narrowed by an explicit `cast` at the
  call, so a new untyped call returning into a declared type is a finding
  rather than an invisible `Any`.
  `warn_unused_ignores` is ON, which makes every `type: ignore` in
  `src/recoverage` and `tools/` a checked claim: one whose error is gone
  fails `make type-check` instead of outliving the finding it silences. The
  runtime deps ship no `py.typed`, so they are covered tree-wide by
  `ignore_missing_imports` rather than by a per-import
  `# type: ignore[import-untyped]`, which would be redundant under that
  setting and reported as stale. `tests/conftest.py`,
  `tests/coverage_fixture.py` and the test modules that build no fixture and
  passed the same settings on the day they joined
  (`test_concurrency`, `test_frontend_import_graph`, `test_import_graph`,
  `test_lint_html`, `test_paths`) are under the gate; the remaining test files
  are outside it until their fixtures carry annotations, so a suppression added
  there belongs with the first mypy run that covers it, and the existing
  `# type: ignore[...]` comments there are still the record of what needed
  silencing. That remainder is a named deferral list rather than a per-file
  relaxation, and it is read in both directions:
  `tests/test_supply_chain.py` (`TestPythonAnalysisIsEnforced::
  test_a_new_test_module_cannot_join_untyped`) fails when a module under
  `tests/` is neither in `[tool.mypy] files` nor named with its reason in
  `_UNTYPED_TEST_MODULES`, and fails when an entry names no reason, so a new
  test file cannot join the suite untyped by default and a module that retires
  its finding leaves that dict in the same change. The selected rule
  groups, the bandit/pylint codes that are named individually instead of by
  prefix, and each per-file-ignore set all carry their reason next to them in
  `[tool.ruff.lint]` and `[tool.ruff.lint.per-file-ignores]` in pyproject.toml;
  those comments are the record of what the tree is expected to pass. The
  repo-wide `ignore` list is the one severity downgrade nothing reads back —
  a code in it stops reporting, which is indistinguishable from a tree with no
  finding, and no file stops passing — so the reason for each of its entries
  lives in `tests/test_supply_chain.py`
  (`TestPythonAnalysisIsEnforced::test_a_new_repo_wide_ignore_cannot_be_added_silently`),
  which fails when a code joins the list without one. Editing the list means
  editing that dict.
- The bandit security group is on for src/ and tools/, including the S1xx
  wildcard-bind, hardcoded-secret, `/tmp` and urlopen checks; the suite's
  fixtures are the only reason `tests/*` ignores them, and each of those
  fixtures asserts the shape the rule exists to prevent. A new S1xx finding
  under src/ is a real one. S101 (assert) is in that set for the same reason:
  `python -O` strips an assert, so one in the request path is a check that
  silently stops existing, while a test that says what it believes with
  `assert` is the mechanism the suite is written in. S603/S607 (untrusted
  argv, partial process path) and S608 (string-built SQL) stay off with their
  reason recorded in pyproject.toml
- Every request carries an id (`server._REQUEST_TLS`, echoed as
  `X-Request-ID`, stamped on every log record by `server._RequestIdFilter`),
  and every request is counted in `metrics.REQUESTS` under its route rule.
  A minted id (`server._mint_request_id`) is a counter, not OS entropy: the id
  is a correlation label nothing authorizes by, and a run replayed from its
  seed has to produce the same one, so two runs diff field for field instead
  of diverging on the first value compared. A correlation id that must not be
  guessable is a different kind of value and gets `secrets`, not this.
  The filter is installed on the package's `recoverage` logger, and
  `Logger.handle` runs the filters of the logger a record was logged ON and
  never an ancestor's: a module taking `getLogger(__name__)` gets a stream but
  no `rid`, and every line it writes renders `[rid=-]`. `documents.py` did
  that, so the coverage-document warnings — the ones naming which document is
  broken — landed uncorrelatable from the 503 they explain. Every module logs
  on the one logger, and `tests/test_metrics.py` (`TestRequestId`) fails when
  one names itself.
  A new failure path that answers 4xx/5xx from outside a handler (bottle
  turns an escaped exception into a 500 only *after* `after_request` has
  filed the request as a 200) must call `server._reclassify_request`, or the
  error rate silently reads zero; `test_metrics.py` pins that. Those counters
  are shared state every request thread mutates, so their balance under
  concurrent requests is pinned separately at `tests/test_concurrency.py`
  (`TestRequestCounters`): a lost update shows up as a total that disagrees
  with the sum of its own buckets, or an `in_flight` that never returns.
  `p50_ms`/`p95_ms` come from a bounded window of the most recent
  `metrics.LATENCY_WINDOW` timed requests (a deque, one append per request),
  never from an unbounded sample list: a lifetime mean and a lifetime max
  cannot tell one slow request from every request getting slower, and the
  window is what bounds the memory. `latency_window` reports how many samples
  the two figures were taken from, so a quiet server's p95 is not read as a
  verdict on a busy one; a new latency figure in a snapshot names the window
  it was taken over. Every `by_route` row carries the same figures over its
  own window (`_RouteRow.recent_ms`), because a process-wide p95 that moved
  has to name the endpoint that moved it, and a lifetime per-route `max_ms`
  cannot: one slow `/data` read made `/data` the slow route for the rest of
  the process. The row is a dataclass, not a dict, so a new per-route
  counter does not widen a union every read has to narrow. The design
  rationale is in `docs/DESIGN.md` (*Request Observability*).
- A connection that ends on the CLOSE PATH is not a rejection and is not
  counted: `devserver._KeepAliveRequestHandler.handle` catches the idle
  keep-alive deadline and a peer that vanished, because `socketserver` prints
  a full traceback for anything escaping it. It is not silent, though: each
  arm writes one DEBUG line naming the peer, since the same readline carries a
  client that opened a connection, sent no request line and sat on the
  deadline, and nothing else in the log, in `transport_rejected` or in
  `connections.open` named it. DEBUG because the ordinary case is an idle
  browser tab; the peer comes from `_peer()`, which tolerates a handler with
  no `client_address` rather than raising inside a log call.
- Two counters hold events the per-request ones CANNOT file, because both
  happen outside every hook: a request the HTTP transport refused (over-long
  or malformed request line, oversized headers, a client that stalled past the
  socket deadline) reaches no `before_request` and therefore no route, status
  or duration, so it is `metrics.REQUESTS.note_transport_rejection`
  (`requests.transport_rejected`) and nothing else; a rejected or throttled
  token is `metrics.AUTH` (`auth.failures`, `auth.throttled`) with
  `server.auth_locked_peers()` as the live `auth.locked_peers` gauge, which is
  the ONE health reason a brute-force attempt can move. The gauge is a gauge on
  purpose: it drops with the throttle window, where a lifetime count would hold
  the probe at `degraded` from one typo until the process restarted. A new
  refusal that happens before `before_request` counts in the registry that owns
  the event, and the health block names it.
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
  refused by `_REGEN_LOCK`, by the cooldown, by the endpoint's security gate or
  by `RegenBusyError` counts under `rejected`, never `failures`: the SPA
  throttles Reload clicks, so counting them as failures reports a broken
  pipeline for a double-clicked button, and a cron job overlapping a
  dashboard's own regenerate is the same event. A refused run still has to
  close the gauge, which is what `RegenStats.finish(None, ...)` is for: the
  `None` is "neither ok nor failed", so a refusal records its duration without
  filing a failure. Each of those refusals also writes a WARNING naming the
  reason and the peer (`api._regen_forbidden`, `_regen_rejected`), because a
  request that never enters the pipeline produces no regen lifecycle line at
  all and the per-request line is DEBUG: the same reason the bad-`Host` and
  bad-token refusals log. The security arms of `handle_regen` go through
  `api._regen_forbidden` rather than answering `_json_err(403, ...)` inline, so
  the wire message, the log line and the counter cannot be added apart.
- A refused regen is only half the pivot. The browser side has to carry the
  correlation id too, or the operator has a line in the log and a reader with
  nothing to hand over: `web/app/api.ts`'s `refusal()` and `postRegen` both
  render the server's `X-Request-ID` into the message, and a refused regen
  returns its reason rather than collapsing every cause into one
  "unavailable" notice. `describeRefusal` is the renderer both share because a
  `Response` body is a stream and reading it twice throws. A new client-side
  failure surface quotes a request id the same way.
- A resource that degrades rather than fails is logged on a TRANSITION, not
  per request: `api._log_health_status` for the health probe,
  `api._log_targets_fallback` / `_clear_targets_fallback` for the config-only
  target list `/api/targets` serves when the coverage documents cannot be read.
  The second pair exists because `/api/targets` is the request the SPA cannot
  avoid and the shell preloads, so an unreadable coverage directory wrote one
  WARNING per page load for as long as it stayed broken, which is what teaches
  an operator to skip the line. A new degraded-not-failed path joins the same
  pattern rather than logging per call.
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
  `recoverage config` run it. `cli._ack_warnings` is the other direction of
  the first one, and a warning for the same reason: the acknowledgment SET
  against a loopback bind is a no-op, so an operator who exported it expecting
  a reachable dashboard has one only this machine reaches. `config` is the
  preflight a deployment gates on:
  a check that exits 0 for a configuration `serve` exits 1 on is a deployment
  that finds out at boot instead of at the check. It preflights the ENVIRONMENT,
  not the argv: `config_cmd` declares no setting flags, so it resolves
  `_resolve_serve_config()` with none and a flag handed to `serve` is neither
  visible to it nor checked by it. A second option table on `config` would be
  the two tables `_argv_with_default_command` refuses to keep in step, so the
  help and the man page name the limit rather than the command growing flags.
  `cli._db_warnings` joins
  them: a coverage directory that does not exist, or exists and holds no
  `coverage-*.toml`, serves an empty target list, and every figure the
  dashboard renders then reads as a healthy zero. It is a warning and not
  `config.check_db_override`'s refusal because an unbuilt checkout is a normal
  state, and because the file case is already a startup error (a warning there
  would only repeat a refusal `serve` exited on). It reads the override
  `_ServeConfig.db` carries when there is one, so the banner, the check and
  the request path name the same directory.
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
  released by one barrier. The auth window is keyed on the REQUESTING PEER,
  not shared process-wide: one client exhausting its guesses must not answer
  429 to the operator (a denial of service any unauthenticated peer could
  repeat forever), and a verified request clears only its own peer's window,
  because emptying one shared window on every success handed a guesser riding
  alongside the operator's traffic an unbounded supply of attempts. The map is
  bounded by `_AUTH_FAIL_MAX_PEERS` since the key is a peer address, and a
  request with no `REMOTE_ADDR` shares one `_UNKNOWN_PEER` bucket rather than
  getting a fresh window each time. That bound is a memory bound, so the
  eviction drops a window whose newest failure has aged out first
  (`_evict_spent_peer_window`) rather than the oldest key: oldest-first threw
  away a peer still inside its window, and the next distinct address arrived
  to find a fresh one, so a guesser with addresses to spare bought unlimited
  attempts out of a cap that reads as a limit on them. When every window is
  live the oldest still goes, because holding the map open is the worse
  failure (`tests/test_concurrency.py`, `TestAuthThrottle`).
- Every memo and every conditional GET is counted on `metrics.CACHES`, at the
  read the handler actually served from: the `/data` checkout (its follower
  path included, since the memo the leader published is the hit it was
  answered from), the `/stats` lookup, and `server._etag_or_304` for both arms
  of the 304. The names are `metrics.DATA_PAYLOAD_CACHE`,
  `metrics.STATS_CACHE`, `metrics.REVALIDATION_CACHE` and
  `metrics.DOCUMENT_CACHE` (the persisted TOML parse in `documents`), so the
  map is bounded by the call sites rather than by a request. A new memo or a new validator
  names its cache next to the read and not at the call site that happens to
  notice: a rising `mean_ms` with a falling revalidation hit rate is a cache
  that stopped being consulted, and nothing else in the snapshot tells those
  two apart. Pinned at `tests/test_metrics.py` (`TestCacheCounters`).
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
  a sleep. A blocking wait is on the seam too, not just a read of one:
  `api._await_build_event` ends the /data single-flight follower's wait on
  `clock.monotonic()` rather than handing `threading.Event.wait` a timeout,
  because that wait is the one place a request thread parks on wall-clock time,
  and the reclaim of a KILLED leader's claim is therefore reachable by advancing
  the clock (`tests/test_concurrency.py`, `TestDataSingleFlight::test_a_reclaim_releases_the_claim_it_took_over`)
  rather than by shrinking `_DATA_CACHE_BUILD_WAIT_SECONDS`, which a follower
  that still parked on real time would pass against. The slice between two reads
  of the clock bounds only how late a dead claim is reclaimed; a live leader
  wakes its followers on the set. A poll loop's PARKING is on it for the same
  reason, which is why `clock` carries `sleep` beside its two reads and
  `cli._open_when_listening` uses it: a loop that reads the deadline through
  the seam and then parks on `time.sleep` still takes however long the wall
  clock decided between attempts, so a run of it is neither fast to drive nor
  replayable (`tests/test_lifecycle.py`,
  `TestOpenAndReap::test_the_probe_polls_on_the_clock` drives the whole poll
  from the patched clock). The LOG stamp is on the seam too, and it is
  the one that was not:
  `%(asctime)s` renders `record.created`, which `logging` fills from
  `time.time()`, so a run driven from one clock wrote two instants for the
  same event and a replay of it could not be diffed against the run it
  replays. `cli.ClockStampedFilter` re-stamps it from `clock.wall_time()` as
  the handler takes the record, attached in `_configure_logging`; it is a
  filter rather than a `formatTime` override so `%(asctime)s` keeps
  rendering `record.created` exactly as the format string says. A new
  surface that stamps a record, or a second handler on the stack, takes the
  filter with it (`tests/test_cli.py`, `TestClockStampedFilter`).
- Every process in this tree starts with `PYTHONHASHSEED` pinned. CPython
  seeds `hash()` of a `str` from the environment once, at startup, so a `set`
  or `frozenset` iterates in a different order in every process: a value
  reaching an assertion, a served payload or a log line through an unsorted
  collection is a coin flip, and two runs of one seed cannot be diffed. It
  cannot be a fixture (the seed is read before any import this tree
  controls), so ci.yml declares it wherever a job starts an interpreter that
  no make recipe can reach, and the two places must agree with each other and
  with the Makefile's exported `PYTHON_HASH_SEED`: the test job's `env:`,
  which spells its pytest command out because the Windows runner has no make,
  and the sbom job's, which runs `tools/bundled_js_inventory.py` with no make
  at all and whose output is an uploaded artifact
  (`tests/test_supply_chain.py`, `TestToolchainPins`, which finds those steps
  by their `python ` line rather than by job name). Pinning the seed is
  NOT a substitute for sorting: it makes set order a function of the values
  alone, so an unsorted collection reaching output stays a defect to find
  rather than becoming noise to re-run. A new one still gets `sorted()`.
  A `st_mtime_ns` becomes an instant through
  `server.mtime_ns_to_utc`, never `fromtimestamp(ns / 1e9)`: a float second
  cannot hold a nanosecond, so that conversion rounds and reports a rebuild
  up to half a second (and Potato's footer a whole minute) before it
  happened. Both freshness surfaces render through the one helper, and
  `tests/test_api.py` (`TestHealthDbMtime`) plus `tests/test_potato.py`
  (`TestDbUpdatedLabel`) pin the truncation. That helper also clamps the
  seconds to the range `datetime` spans before converting, because an mtime
  is filesystem input (a restored tree, a bad RTC, `touch -d`) and
  `fromtimestamp` raises on one: an unrepresentable stamp must render as the
  extreme, never take a health probe or a Potato render down with it. A
  socket deadline is per OPERATION and bounds no connection's lifetime, so
  it has no relationship to the SSE heartbeat; an idle stream blocks on its
  queue, not the socket, which is what
  `tests/test_lifecycle.py`
  (`TestClientConnectionDeadline::test_a_deadline_under_the_heartbeat_does_not_close_a_healthy_stream`)
  drives against the real handler stack. Do not reintroduce a floor stated
  as "must outlast the heartbeat". An instant published to a client
  is UTC with the offset spelled out, never a fixed offset or a zone guessed
  from the locale; a log stamp is local time with `%z` attached, because the
  operator comparing it against their own clock needs to see their own clock.
  A document's OWN stamp (`updated_at`, `last_verify.verified_at`) is the one
  the reader sees in their own zone rather than UTC, because a naive ISO string
  is local time to whoever wrote it and the writer is not the reader, and
  `format.dateTime` is where that happens. That reading holds only when the
  reader's zone CONTAINS the wall clock reading the literal names, and `Date`
  resolves a naive string leniently instead of refusing the ones it cannot
  place, so `dateTime` round-trips the literal against the parsed value's
  reader-zone fields and returns the raw string when they disagree: a day the
  calendar does not have (`2026-02-30`, which `Date` carries into the next
  month and rendered as a real day the document never named) and an hour a
  spring-forward transition SKIPPED (`2026-03-29T02:30:00` in `Europe/Warsaw`,
  whose clocks jump 02:00 -> 03:00; `Date` moved it past the gap and rendered
  the 03:30, which no clock there ever read either) both come back raw, since
  the document is untrusted input and a wrong-but-plausible date is worth less
  than the string that arrived. A stamp CARRYING an offset names an instant,
  always round-trips, and is untouched by the check. The fall-back REPEATED
  hour is deliberately not refused: it is ambiguous rather than impossible, and
  picking the first occurrence is a policy to name rather than assume. The
  refusal is per ZONE, so the same stamp still renders for a reader whose zone
  has the hour. Pinned at `tests/test_server.py`
  (`TestSpaRefusesAWallTimeTheReadersZoneCannotPlace`), driven under a real
  `TZ`.
- The memos derived from `rebrew-project.toml` all key on the file's stat
  (`_paths.config_fingerprint`), one token for all of them:
  `_get_targets_config`, `resolve_targets` (keyed on that stat AND the
  coverage-directory snapshot, its other input), and the `DLL_DATA` byte cache.
  Editing the config is a write that reaches no server code and moves no
  coverage file, so the stat is the only invalidation signal there is, and the
  rebuild broadcast watches the documents alone. A new config-derived memo names
  `_paths.config_fingerprint` in its key or it will disagree with the other two
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
  frozen snapshot, so nothing but the key can straddle a rebuild).
  `server.resolve_targets` did neither at first, and a rebuild that committed
  between its read and its stat filed the previous build's target list under the
  fingerprint that superseded it, so the target the rebuild added stayed out of
  `/api/targets`, the dropdown and Potato Mode for the rest of that build's
  life: the invalidation that would have cleared the entry had already run. A
  new coverage-derived memo takes its token the same way or states why its read
  cannot straddle a rebuild.
- The machine a binary is decoded at is a fact about the FILE, read from the
  container header, never a constant and never the host's own architecture.
  `disasm._new_cs` built every handle at `CS_MODE_32`, and a 64-bit image
  decoded at 32 bits is not a narrower answer, it is a wrong one: a `REX`
  prefix reads as the start of the next instruction and a RIP-relative
  displacement as a ModRM, so the panel rendered garbage over exactly the bytes
  the reader selected. rebrew builds x86_64 targets (`binary_loader` recognises
  AMD64 PE and ELF64), so a 32-bit-only decode was never safe. The width comes
  from `disasm.binary_width_bits`, which reads the PE `Machine` field or the
  ELF `e_machine` at explicit little-endian offsets out of the first 64 bytes,
  stdlib only because LIEF is rebrew's dependency and not this package's. Two
  properties the reader keeps deliberately: it is a FLOOR, not a guess — a
  header it cannot read, and a machine outside the x86 family, both answer
  `_DEFAULT_WIDTH_BITS` rather than raising, because `/asm` is contracted to
  answer and a 32-bit panel is a better one than a 500; and its answer is
  memoized per binary stamp (`disasm._target_width_bits`), because the mode is
  fixed at handle construction and a rebuild that changes a target's
  architecture must not be decoded at the previous one's width, which is the
  same reason `clear_disassembly_cache` empties that memo beside its own. A
  per-thread handle is kept PER WIDTH, so a project with a target of each width
  decodes both correctly and the cache stays bounded at two objects. Pinned at
  `tests/test_api.py` (`TestImageWidthIsReadFromTheContainerHeader`).
- A path that crosses into the filesystem is read with `PurePath` rules, not
  POSIX string rules. `server.is_plain_relative` is the one definition, keyed
  on `anchor` (drive, leading separator, UNC) rather than `is_absolute()`, and
  it names the SOURCE ROOT as well as the file under it: the root is the
  containment base, so a value that survives as an anchor or a parent hop
  replaces the base outright and the `is_relative_to` check that follows passes
  trivially. It lives in `server`, the shared kernel below the route modules,
  because both the C-source reader (`potato`) and the `/src` and `/original`
  routes (`ui`) guard a path the same way and a route module is not where a
  sibling route module's rule can live. Stripping a leading `/` is a POSIX
  assumption and answers for the
  host, not for the document: a coverage document built on Windows used to name
  a source root no Linux reader could refuse, and the lowercased `src/<target>`
  fallback (`potato`, `web/app/App.tsx`, `web/app/hooks/useOriginalBinary.ts`)
  only resolved on a case-insensitive filesystem. Target ids are used verbatim
  in every path this package builds, because rebrew names the tree
  `src/<target>` and `db/coverage-<target>.toml` with the target's own spelling.
  Pinned at `tests/test_potato.py` (`TestPathTraversalGuard`) and
  `tests/test_fuzz.py` (`TestRepoFileRoute`); a new path taken from a coverage
  document or from a URL goes through the same guard.
- A filename is not a byte string, on either side. `server.
  match_filesystem_spelling` re-spells a requested path the way the tree
  actually spells it, one segment at a time, because macOS stores the DECOMPOSED
  form of any name carrying combining marks whatever the creating program
  passed: the document (and the SPA link built from it) spells NFC, the
  composed path opens no file, and the code pane 404s a source file that is
  sitting on disk. It runs AFTER `is_plain_relative`, never before it, so the
  containment rule still judges the spelling the request supplied. Pinned at
  `tests/test_api.py` (`test_decomposed_filename_is_found_from_the_composed_spelling`)
  and `tests/test_potato.py` (`test_decomposed_source_name_found_from_the_composed_spelling`).
- A filename is also not necessarily valid text. Python reads one with
  `os.fsdecode`, which is `surrogateescape`, so `coverage-ca\xff.toml` (legal on
  ext4, and produced by a checkout, an archive or a Windows tool) reaches Python
  holding U+DCFF. Every digest built from a filename goes through `server.
  fs_text_bytes`, whose `surrogateescape` is the exact inverse: one such file
  used to raise `UnicodeEncodeError` out of `_snapshot_db_mtime`, and the token
  is computed before a handler can answer, so it 500'd every snapshot-keyed
  route. Two names differing only in an undecodable byte still hash apart.
  Pinned at `tests/test_server.py` (`TestDbEtag`).
- A filename that is not valid text is still a value in a URL, and BOTH ends
  encode it the same way. `urllib.parse.quote` encodes a `str` through UTF-8, so
  it raised `UnicodeEncodeError` on that U+DCFF — inside `potato._build_url`,
  every rendered link embeds the target id, and `UnicodeEncodeError` is a
  `ValueError` that `handle_potato` caught, so one `coverage-GAME\xff.toml` in
  the coverage directory answered `/potato` with a 500. The write side is
  `server.fs_url_quote` (`quote(fs_text_bytes(text))`: the name's own bytes, one
  escape for the one byte the filesystem holds) and `format.encodeUrlValue` on
  the SPA side, where `encodeURIComponent` threw `URIError: URI malformed` on
  the same string and took the whole dashboard down rather than the one row of
  the target picker. The read sides are `potato.render_potato`'s
  `parse_qs(..., errors="surrogateescape")` — the default `replace` spelled
  `GAME%FF` as `GAME�`, so the page resolved no target at all — and
  `server.path_param`, which leaves the segment percent-encoded rather than
  raising, an honest 404. Only U+DC80..U+DCFF is recoverable, so
  `encodeUrlValue` spells anything outside it `%EF%BF%BD` rather than masking a
  high surrogate to `%00` and putting a NUL in a URL. A value that DECODES is
  byte-for-byte what the old call spelled, which is what keeps every URL this
  package already builds unchanged. Pinned at `tests/test_server.py`
  (`TestDbEtagSurrogateName`, `TestSpaUrlEncodingSurvivesAFilenameOutsideUtf8`,
  which runs the shipped `format.ts` under bun and drives all 128 code units of
  the range) and `tests/test_potato.py` (`TestBuildUrl`). A new URL built from a
  document value, a target id or a filename goes through the two helpers; the
  test fails if a call site reaches for `encodeURIComponent` again.
  `str.strip` and `String.prototype.trim` also remove U+00A0, U+2000-U+200A,
  U+3000 and U+FEFF, so a term made of a non-breaking space became the EMPTY
  term and the search answered with every row instead of the rows whose name
  carries that space. A new surface that reads a term trims through the helper
  rather than the method. Pinned at `tests/test_server.py`
  (`TestSearchColumnGuards`) and `tests/test_api.py`
  (`test_a_unicode_space_is_a_search_term_not_an_empty_one`).
- A value read out of a coverage document is laid out in its OWN direction.
  Every name the dashboard shows comes from a PE image, so a target whose
  symbols are Arabic, Hebrew, or a mix of those with ASCII is a document the
  reader can have, and the page's base direction is left-to-right, so the
  bidirectional algorithm reorders such a value against the punctuation and
  numbers around it. Two mechanisms, and which one fits is the whole rule: a
  value standing ALONE in an element takes `dir="auto"` (the SPA's
  `MetaItem` value cell and panel title, Potato's `_detail_rows` cell, the
  function-list name cell, the panel's label and parent cells, the section
  tabs), while a value interpolated into a sentence the page owns goes
  through `format.isolate` (the map's `describe`, the panel's modal title, the
  pending and cell-error lines, the search status). No attribute on an
  ancestor can carve a run out of a text node, which is why the second case
  needs the U+2068/U+2069 pair. Pinned at `tests/test_server.py`
  (`TestSpaBidirectionalText`) and `tests/test_potato.py`
  (`TestDocumentNamesCarryTheirOwnDirection`).
- One response, one snapshot. A snapshot is frozen — every collection is a
  tuple or a `MappingProxyType` — and `documents.load_all` (the
  reader `server` imports) memoizes each document on its own stat, so an
  unchanged directory returns THE SAME snapshot objects. The change token
  every memo and ETag keys on (`server._snapshot_db_mtime`) folds each
  document's content digest (`documents.versions`), not its stat: rebrew
  replaces every document on every build, and a build that changed nothing
  writes the same bytes, which must not invalidate a memo, move an ETag or
  broadcast `db-updated` (`tests/test_api.py`,
  `test_a_rebuild_that_rewrote_the_same_bytes_keeps_the_memo_and_the_etag`).
  The original binary is outside that token and keys itself:
  `server.binary_stamp(target)` is part of the `/asm`, `/bytes` and Potato
  validators, the `disasm` memo key and the `DLL_DATA` entry, and a new consumer
  of the binary's bytes takes the stamp the same way
  (`tests/test_server.py`, `TestBinaryIsPartOfTheCacheKey`). A handler that builds
  its answer from several collections therefore reads them all from one
  snapshot and cannot pair one build's cells with the next build's functions;
  that is the guarantee the SQLite read transaction used to buy, held by the
  type instead. The call sites are
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
  hand-edit them. The bytes are bun's, so the bun the bundle was built with is
  part of the artifact: `ensure-bun` reads the pin out of `package.json`'s
  `packageManager` (the one place it is written; `ci.yml`'s setup-bun reads the
  same field) and warns on a mismatch, and `check-bundle-clean` names the bun it
  ran under when it fails, because a different bun bundling unchanged `web/` to
  different bytes is otherwise reported as a stale commit. It is a warning, not a
  refusal, the way the uv floor is: the gate is `check-bundle-clean`, and a bun
  that produces the same bytes is not the contributor's problem.
  `check-bundle-clean` only compares bytes: `emptyOutDir` is off
  in `web/vite.config.ts` (that directory also holds the hand-written
  `index.html`, `print.css` and `favicon.svg`), so nothing clears a stray file
  out of it, and `pyproject.toml`'s `assets/*` glob makes the directory's
  contents the wheel's shipped file list. `BUNDLE_ASSETS` in the Makefile is
  that list, and `build` refuses a member that is missing or is not on it
  before `uv build` runs, and `tools/check_wheel_assets.py` reads the same list
  back off the wheel `uv build` just produced, because three lists sit between
  the directory and the shipped members (the `assets/*` glob, the sdist file
  list, MANIFEST.in) and none of them is the directory. The declared names
  reach the script as `--asset` from `BUNDLE_ASSETS`, so the Makefile stays
  the one place the list is written down. A new file under `assets/` joins
  `BUNDLE_ASSETS` in the same change. `check-bundle-clean` compares the
  rebuilt bytes against the committed ones with `git status`, so it refuses a
  tree git cannot read rather than passing on an empty substitution: outside a
  work tree `git status` writes its error to stderr and yields nothing, which
  read as a clean bundle.
- The cell-state vocabulary is owned by rebrew (`rebrew.build_db._KNOWN_CELL_STATES`)
  and must be covered on the rendering side: `potato.COLORS` + `LEGEND_ITEMS`,
  and `web/app/states.ts` `STATE_SLOTS`/`PALETTE_VARS`/`FILTER_KEY`. An unmapped
  state paints as an undocumented gap, which contradicts `/stats` — `verified`
  is counted there as an exact match. Tests in `test_potato.py`
  (`TestCellStateVocabularyCoverage`) and `test_server.py` (`TestSpaStateVocabulary`)
  fail on a gap; extend all of them together when rebrew adds a state.
- The SPA's own arithmetic over document columns follows four rules, because
  `rebrew.coverage_toml` reads `columns`, `start`, `end` and `span` as plain
  ints with no ceiling, and a value past a JS typed array's range wraps
  silently. A cell's `end` is EXCLUSIVE (rebrew writes `cur = cell_end` for
  the next cell, and a cell's size is `end - start`), so
  `useSelection.cellIndexForVa` compares `relative < cell.end`: inclusive, it
  resolved every boundary address — which is what a function's entry VA is —
  to the block BEFORE the one named. `packSection` stores offsets in
  `Float64Array`, not `Uint32Array`, and saturates `span` into its
  `Uint16Array` with `MAX_SPAN`. The lattice width is clamped to
  `MAX_GRID_COLUMNS`, which is `potato._MAX_GRID_COLUMNS`: `layoutSection`
  sizes a `new Int32Array(rows * cols)` from it, so an unbounded `columns` asks
  the renderer for gigabytes while Potato renders the same document fine. Both
  surfaces apply one bound, and `tests/test_server.py`
  (`TestSpaNumericBoundaries`) pins all four against the sources.
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
- The topbar rows WRAP, and the search column may shrink, because the shell
  clips its overflow: `body { overflow-x: clip }` keeps the decorative radial
  gradient from opening a horizontal scrollbar, and a clip means a row wider
  than the viewport is GONE rather than scrolled off to one side. At the 320
  CSS px 1.4.10 asks for, the actions row (target picker, Regenerate, HTML,
  theme) is about 350px as one unbreakable item, and the theme toggle at its
  end went with it; `min-w-0` on the search column is what lets it shrink to
  its own box's minimum rather than to the widest fixed width any child
  declares. A new topbar row takes `flex-wrap` with the two named ones, and
  `tests/test_server.py` (`TestSpaTopbarReflowsAtTheNarrowViewport`) holds
  them.
- Every text-bearing token clears 4.5:1 on every ground it can land on, in
  BOTH themes, and the two themes are not one palette over two grounds: the
  light ground is a mid gray, so a step tuned for the near-black field sits
  under the floor on it while looking identical in review. `--delta` and
  `--badge-near-text` were the two that did (4.34:1 and 4.20:1 on `--bg` in
  light mode, against 8.74:1 for each in dark). `tests/test_server.py`
  (`TestSpaTextTokensClearTheTextFloor`) computes every pairing off the file
  rather than a restated table, and the colour maths it shares with the cell
  fill gate (`TestCellFillsAreDrawnPerTheme`, 3:1 for a graphic) sits at
  module scope because both answer the same compositing question. A new text
  token joins `TOKENS` in the same change, a new ground joins `GROUNDS`.
- An `aria-labelledby` names an element that EXISTS. The map area is the
  section tablist's `tabpanel`, labelled by the tab that selected it, and a
  target whose document names no section renders no tab to point at: the
  reference then resolves to nothing and the panel has no name at all, which is
  worse than the `aria-label` it should have fallen back to. The two spellings
  are exclusive in `App.tsx`, so the tablist's emptiness is the condition that
  picks between them.
- Potato Mode's `accesskey` letters are CLAIMED, not spelled per control:
  `potato._accesskey_attr` hands each one out in document order (the search
  box, the section tabs, the filter pills) and a control whose letter is
  already held takes none. `.rdata` and `.rsrc` both answer `r`, the Reloc
  pill's own letter is `r`, and the Stub pill's `S` is the search box's `s`, so
  writing the attribute per control put two controls on one letter, and a
  browser resolves that to the first of them while both look identical
  (WCAG 2.1.4). The footer prints the letters that were actually claimed
  (`potato._shortcuts_html`) and nothing else, so a shortcut is discoverable
  and none is listed that does not work. A new control with a shortcut goes
  through the same claim; a new letter is a change to `FILTER_OPTS` or
  `_section_tab_data`, and the collision test in `tests/test_potato.py` is
  what notices a second spelling.
- A control that CHANGES its visible label changes its accessible name with
  it: `web/app/components/ui/copy-button.tsx` flashes `Copied!` in place of
  `Copy`, so a voice-control user saying "click Copied" has a name to match
  (WCAG 2.5.3).
  The outcome still repeats into the button's own `role="status"`, because a
  focused screen reader reads the name and not the text that replaced it.
  A modal is ONE focusable scroll region: `CodeModal`'s body holds the
  `role="region"`, and `HighlightedCode`'s `region={false}` keeps the `<pre>`
  from declaring a second, identically named one over the same content.
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
  the same treatment: validated in `config.py`, reached by both sources. A new
  setting joins `config.KNOWN_VARS`, the README's environment table and
  `.env.example` in the same change, the last being what an operator drafts a
  unit file or a container spec from and the one no gate otherwise kept true
  (`tests/test_config.py`, `TestEnvExample`). An
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
  nothing. `RECOVERAGE_TOKEN` is the one deliberate exception to the
  SET-but-EMPTY rule, and `tests/test_config.py` pins it: empty means auth
  off, on purpose, because the same spellings would otherwise leave a
  token-guarded deployment unauthenticated in exactly the way the empty
  allowlist does. It is still validated, by `config.validate_token`, which
  `--token` calls too: the gate compares the extracted credential byte for byte
  and every carrier arrives stripped, so a value carrying surrounding
  whitespace, an interior space or a control character starts a server that
  answers 401 to every reader while the banner reads `token=set`. The error
  names the class of problem and never the value, because it is printed
  verbatim to stderr.
- `RECOVERAGE_DB` is resolved on the request path (`_paths._db_path`), so
  `config.db_override` stays a bare environment read and `config.
  check_db_override` is the startup-only check that stats the path. A value
  that exists and is not a directory (the SQLite-era `coverage.db` FILE, which
  sat beside the documents rather than holding them) resolves to a path no
  `coverage-*.toml` glob can match, and the dashboard then serves an empty
  target list that reads as a healthy zero rather than as a wrong path. A value
  that does not exist is allowed, because a service may start before its first
  `rebrew build-db`; only a non-directory is a misconfiguration. `serve` and
  `recoverage config` reach it through `_resolve_serve_config`, the sibling
  commands through `_check_env_or_exit`.
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
  `COALESCE(col, '')` gave a nullable `symbol`. The SPA folds both sides of a
  search through `format.foldForSearch`, which mirrors `server.fold_text` as
  far as JavaScript can (`toLowerCase` plus the `FULL_FOLD` expansions), so a
  case-fold expansion such as `ß` → `ss` matches on both sides. Name resolution
  folds the same way:
  `server.lookup_function` /
  `server.lookup_global` try the VA arm first, then byte equality on the name,
  then the folded comparison — so the row the search highlighted opens by
  name. A lookup added beside them (globals, labels, anything compared for
  identity) must fold too; byte equality there is the bug this paragraph exists
  to stop. A search arm over a column the term cannot hold skips building it:
  `server.fold_can_match_hex` and `server.fold_can_match_decimal` answer
  whether a FOLDED needle could occur in a `0x` address or a bare decimal VA,
  and the address arms in `api._filtered_functions` and both Potato search
  readers consult them before formatting and folding two strings per row per
  keystroke. The test is necessary, not sufficient: a term inside the alphabet
  can still match nothing, and then the columns are built and miss as before.
  A new search column follows the same rule, and `fold_can_match_*` is named
  for its own alphabet rather than a shared "is this a number" test. Pinned at
  `tests/test_server.py` (`TestSearchColumnGuards`), which drives the guard
  against the comparison it replaces. The capped search rows
  (`potato._SEARCH_ROW_LIMIT`) are selected with `heapq.nsmallest`, the
  documented equivalent of `sorted(...)[:limit]`, so a match set larger than
  the cap is not fully ordered to keep the first 500.
- The columns a function list can be ordered by are `server.
  FUNCTION_SORT_COLUMNS`, and a surface NARROWS that set rather than spelling
  its own: the API list takes it whole (`api._ALLOWED_SORT` is a name for it)
  and the Potato table takes the columns it renders (`potato.
  FUNCTION_LIST_COLUMNS`, an intersection, because an order a rendered column
  cannot show is one a reader has nothing to check it against). The attribute
  map beside it, `server.FUNCTION_SORT_FIELDS`, is every column but `size`,
  which has a key arm of its own because its NULL needs a tuple. A stale
  spelling of the column list is invisible rather than loud, which is why the
  API list REFUSES one: `?sort=` is validated against `_ALLOWED_SORT` and
  `_SORT_DIRECTIONS` and answers 400 naming both vocabularies, the same
  contract `?status=`, `?format=` and `?index=` give, because a typo'd column
  used to answer 200 with a full page in an order the caller never asked for
  and nothing in the answer to say so. A bare column, an empty `?sort=` and an
  absent one are the default rather than a bad value. The Potato table keeps
  the fallback (it renders a page, and its own header links are the only way a
  reader reaches it), so a surface that no longer carries a column answers that
  surface's reader the default order for it.
  Pinned at `tests/test_server.py` (`TestSortColumnVocabularyIsShared`), which
  holds the two surfaces against the package's list and every column against a
  key that resolves, and at `tests/test_api.py`
  (`TestApiFunctions::test_invalid_sort_field_is_a_400`).
- `_log_safe` escapes the characters that end a log line, which is C0, DEL,
  the C1 controls, and U+2028/U+2029 (a header value carries those literally,
  and every viewer that breaks on `\n` breaks on them). It deliberately leaves
  bidi controls alone: those reorder a line rather than split it, so escaping
  them is a log-injection question, not a line-splitting one. An exception
  message reaches the same treatment: a coverage document is untrusted input
  like a request path, and its parse error is read precisely when a line must
  stay one line.
- The Markdown export folds the same line terminators, through
  `cli._MD_LINE_BREAKS` (`\r`, `\n`, U+2028 and U+2029 to a space) and escapes
  the cell separator through `cli._MD_PIPE`. A section name or target id comes
  out of a PE image, so it is a value a hostile sample plants, and U+2028 in one
  turned a single table row into two: the export rendered ragged and the second
  row read as a section that does not exist. `cli._md_safe` handled only CR and
  LF, which is why the fuzz campaign in `tests/test_fuzz.py`
  (`TestCliRendersHostileDocumentValues`) is the thing that found it. A new
  format the CLI emits folds that table and not a hand-written `.replace`.
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
- The opener a dashboard hands its URL to is named by CAPABILITY, and only the
  two systems whose opener genuinely differs are named at all: macOS's `open`
  is the name of its LaunchServices client, Windows has only `cmd /c start`,
  and every other POSIX host carries `xdg-open`. The POSIX arm used to be keyed
  on `platform.system() == "Linux"`, which is an OS NAME standing in for a
  capability, so a FreeBSD, OpenBSD, NetBSD, Solaris or illumos host fell
  through to `webbrowser.open` and lost every property `_open_and_reap` exists
  to provide: the detached session, the bounded wait and the reap that keeps a
  hung opener off `serve`'s startup. The dispatch is `os.name == "posix"` for
  that arm with the two exceptions first, so a host this tree does not name
  still reaches `webbrowser` rather than a launcher it has no command for. A
  new platform branch names the capability that differs, not the OS. Pinned at
  `tests/test_cli.py` (`TestBrowserOpenerSelection`), which drives the whole
  table on every host instead of asserting only the answer that platform's
  runner gives.
- The deferred browser opener is `cli._open_when_listening`, and it asks the
  listener before it launches anything. `Timer.cancel` sets the timer's event
  and returns without waiting for the thread, so a start that fails while the
  callback is already past its own check (EADDRINUSE from a second instance, a
  Ctrl+C inside the 0.5 s window) still runs it and cancelling does nothing:
  the cancel in `serve`'s `finally` claims an outcome only the probe delivers.
  The probe waits for the listener (`_OPEN_LISTEN_WAIT_SECONDS`) rather than
  trusting the schedule, and it connects to the address the URL names, since a
  wildcard bind address is not connectable. A startup that defers work on a
  timer does not treat `cancel()` as a join
  (`tests/test_lifecycle.py`, `TestOpenAndReap`).
- The way a deployment stops the dashboard is SIGTERM, not Ctrl+C:
  `systemctl stop`, `docker stop` and a pod eviction all send it, and its
  default disposition kills the process where it stands, so the accept loop
  never unwinds and `serve`'s `finally` never runs. `cli._stop_on_sigterm`
  arms the handler for the length of the listener and raises
  `KeyboardInterrupt` from it, which is what puts a signal on the path
  `except KeyboardInterrupt` already covers rather than a second cleanup
  beside it; the callable it returns is the one restore, and `serve`'s
  `finally` calls it. It is installed BEFORE the `try` and not inside it, so
  a `serve()` run from a non-main thread fails the way it did before rather
  than through an unbound name in the cleanup. SIGINT is left to the
  interpreter. The same arm covers Windows, which has no SIGTERM a handler can
  see (`os.kill` with anything but CTRL_C_EVENT/CTRL_BREAK_EVENT calls
  TerminateProcess): there the stop signal is `SIGBREAK`, so the handler is
  installed for every one of `SIGTERM` and `SIGBREAK` the platform defines, and
  the restore puts back all of them. Pinned by `tests/test_cli.py`
  (`TestServeStopSignal`), which delivers a real signal to the test process
  with `os.kill` while the stubbed listener stands in for the accept loop on
  POSIX, and on every platform over the signals the module claims: the
  real-delivery case is skipped where `os.kill` would kill the runner rather
  than raise in the handler.
- `server.set_auth_cookie` is the one place the `?token=` share-link cookie is
  written, and every page route a share link can land on calls it: `/` and
  `/potato`. Both pages link with relative URLs, so the cookie is what carries
  the credential past the first click; a page route that skips it renders once
  and answers the 401 page on every link the reader follows. The cookie's name
  is `server.AUTH_COOKIE_NAME`, which `_require_auth` reads it back under. Its
  `Secure` attribute, and the `Strict-Transport-Security` the after_request
  hook sends beside it, are read off the request through
  `server.request_is_https` (`wsgi.url_scheme`, or `X-Forwarded-Proto` behind a
  TLS-terminating proxy) rather than fixed: the bundled listener speaks no TLS
  and serves a loopback bind over http, where a constant `Secure` would stop
  the cookie being stored at all, and a constant absence of one hands the token
  to whoever was on the wire the moment a reader followed an http link to a host
  that also answers https. Neither is a bypass when a client claims https over
  plaintext: both answers only ever make a response stricter. A new response
  header that depends on the transport asks the same helper rather than the
  environ directly.
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
  judges it against `urlsplit` rather than against the helper. An `Origin`
  that ARRIVED and arrived empty is neither of those two: `server._header`
  reads it as the header's absence, and a gate that admits the absence must
  not admit the blank value, so the handler asks `server.header_present` for
  that one case. No browser sends a blank `Origin`, and a new privileged gate
  treats a present-but-empty header as a refusal. Every one of the gate's
  refusals answers through `api._regen_forbidden`, so the wire message, the
  WARNING that names the reason and the peer, and the `rejected` counter move
  together; a 403 written inline is a refusal nothing in the log or in
  `/api/health` can see. The same rule governs the file routes:
  `ui._repo_file_forbidden` is the one tail for a `/src` or `/original` path
  that escapes the tree, because the per-request line is DEBUG and a scanner
  walking `../../` otherwise left no trace at all. A new privileged or
  file-serving refusal names both the reason and the peer, escaped with
  `server._log_safe`.
- `POST /api/regen` is the package's one retried side effect, and its
  `Idempotency-Key` names the OPERATION, not the request: the SPA mints the
  key once per click (`api.newRegenKey`) and `postRegen` re-sends the same one
  on a transport failure, because a key minted per request is a new operation
  to `api._REGEN_COMPLETED_KEYS` and a lost response then costs a second full
  pipeline. A new client of that endpoint takes the key from its action site,
  not from inside the send helper, and re-sends on a lost response rather than
  leaving the reader to click again. A key has three states, not two: a run
  that COMPLETED replays from `_REGEN_COMPLETED_KEYS`, and a run still going is
  marked in `api._REGEN_ACTIVE_KEYS` and answered 202 with `in_progress`, which
  is the retry that lands while the first run still holds `_REGEN_LOCK` (a
  regen is minutes long, a proxy gives up far sooner). The 429 the lock gives
  was true and useless there: the SPA reads it as a failed regenerate, and the
  reader's next click mints a new key and pays for a second pipeline. A 202
  for someone else's key would be a lie, so the marker is per key, and it is
  cleared in the handler's `finally` and past `_REGEN_KEY_TTL_SECONDS`, because
  a run abandoned by a dead process would otherwise hold its key for the life
  of the server. `_REGEN_LOCK`, not either map, is what keeps two pipelines
  from running, and the completed ledger is read again once the lock is held:
  the read before it cannot be the claim, because a duplicate that arrives
  while its predecessor is still running sees no entry and reaches the lock
  only after the predecessor released, and the cooldown cannot catch that
  window either (it counts from the previous run's START, and a regen runs for
  minutes). Pinned at `tests/test_api.py` (`TestRegenIdempotencyKey`).
  Every one of those is IN this process. A duplicate the ledger cannot see is
  a `recoverage regen` at another terminal beside a running dashboard, or a
  cron job over the same tree, and a rebuild is only convergent when the two
  runs do not overlap: the writer replaces each `coverage-<target>.toml` whole,
  so two writers interleave and a reader can land between one truncate and its
  write. So `regen._exclusive_regen` holds an advisory lock
  (`.recoverage-regen.lock`, named in the directory `rebrew.workspace.db_dir`
  resolves, because `[project].db_dir` can point anywhere) around the pipeline,
  and a holder raises `RegenBusyError`: the CLI exits 1 naming it, the API
  answers the 429 the in-process lock already sends and counts it under
  `rejected`. Two properties the choice of lock carries: it is non-blocking,
  because the second caller is a duplicate and not a queue for a run that takes
  minutes, and it is taken on an OPEN DESCRIPTOR, so a regen killed mid-run
  releases it on process exit, which a lock file's mere presence could not do
  (a stale file wedges every regen after the crash). `msvcrt` is reached
  through `importlib` because typeshed ships its stub only on Windows, so a
  direct import is an unresolved-import error on every other platform and its
  suppression is an unused-ignore error on that one. Pinned at
  `tests/test_lifecycle.py` (`TestRunRegen`), including a forked second process
  and the death that frees the lock.
  The other in-flight marker, the `/data`
  single-flight claim in `api._DATA_CACHE_BUILDING`, follows the same rule: an
  in-flight marker whose owner was killed is reclaimed on its deadline
  (`_DATA_CACHE_BUILD_WAIT_SECONDS`), never left registered for a waiter that
  no `finally` will ever wake. That reclaim is also the only trace of the fault
  that caused it, so it counts on `metrics.REQUESTS.note_stale_claim` (the
  `requests.stale_claims` field) and logs one line carrying the target and
  section the killed build was serving: a claim dropped by `_prune_stale_claims`
  was already past its deadline, which is the free path, and it stays silent.
  Pinned at `tests/test_concurrency.py`
  (`TestDataSingleFlight`), which releases a herd of simultaneous cold misses
  through one barrier and fails when the payload is built more than once, and
  which pins that one of the two ways a claim disappears is loud.
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
  `server.parse_ascii_int`, not `int(x, 16)`. Every read in the chunked reader
  stops at a named bound, the trailer section included
  (`server._TRAILER_MAX_BYTES`, on the running total): the loop consuming
  trailers ended only on the final CRLF, so a peer streaming short trailer
  lines held its handler thread and its admission slot for the whole socket
  deadline, one request per slot. Every refusal it raises leaves the
  rest of the body in the socket, so the answer must carry `Connection: close`;
  `api._body_rejected` is the one helper that puts it there. A new endpoint
  reading a body calls the helper for both `RequestBodyTooLargeError` and
  `RequestBodyMalformedError`. Every read in that reader refuses a SHORT input
  rather than completing on it, the trailer section included: the end of the
  stream where the section's final CRLF was due is a truncated message, and
  serving it answers 200 with a body whose framing is known to be incomplete
  and reads the next request's bytes as the rest of it.
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
  readers, and `rebrew-project.toml`) are fuzzed
  by `tests/test_fuzz.py`: a seeded mutation engine over a
  hand-written corpus, driven by `RECOVERAGE_FUZZ_SEED` / `RECOVERAGE_FUZZ_ITERATIONS`
  so a failure replays. A failure names the seed and the round it failed in,
  because the shrink walk consumes the same stream and a campaign that can
  only be replayed by reading this file for the constant the environment did
  not set is not a replay; it also raises when the shrunk input stops failing
  (a stateful endpoint answers the second identical request differently) rather
  than reporting the campaign as clean. Each round asserts an invariant, not just a lack of crash: no 5xx,
  the JSON error envelope on a 4xx, no traceback in a body, and the contract the
  query asked for (a page within `limit`, a slice within `size`, only requested
  VAs back). The `/potato` and repo-file campaigns pass their own grammar tokens
  to `_fuzz(struct_tokens=..., num_tokens=...)`, because byte mutation alone
  never produces `idx=99999999999999999999` or `%2e%2e%2f`; a new surface with
  its own grammar needs its token tuple the same way. Two surfaces sit outside
  the request campaigns and have their own: the `<va>` segment of
  `/functions/<va>` (`TestFunctionVaSegment`), the one path segment that IS the
  thing the route resolves, so its oracle is rebrew's `parse_va_candidates`
  plus a restatement of the four arms of `server.lookup_function` rather than
  the handler itself; and the CLI (`TestCliRendersHostileDocumentValues`), which
  renders a document's own section and target names into a table, a JSON
  document, a CSV file and a Markdown file. One campaign is not a request at
  all: the request line and header block (`TestRequestLineParser`), which
  arrive on a socket before a WSGI environ exists, so every campaign above
  starts past them. It drives the production
  `devserver._KeepAliveRequestHandler` over a `socket.socketpair` with only
  `_run_wsgi` replaced by a recorder, so the capped read, the 414 refusal,
  `http.server`'s `parse_request` and the keep-alive loop are the code under
  test, and it asserts what a status code cannot show: nothing escapes
  `handle` (which catches only `TimeoutError` and `ConnectionError`), the
  answer is framed, an over-long line is refused with 414 and never reaches the
  app, no attacker byte reaches the log as a line break (the guarantee
  `devserver.log_error` documents), and a well-formed line reaches the route
  with its method, path, version and headers intact. A socketpair, not a
  `BytesIO`: the handler calls `connection.settimeout` between requests, and a
  fake connection would have to reproduce the deadline the code reads.
  The CLI campaign draws from value
  pools and writes through the fixture writer, so every round is a document the
  reader accepts, and it reads `result.output_bytes` rather than
  `result.output`: CliRunner decodes its capture with universal newlines, so a
  CR inside a quoted CSV cell is gone before the round-trip assertion sees it
  and the assertion would be pinning the test runner. HTML-escaping assertions
  come in pairs: the grid view escapes through SimpleTemplate, the functions
  view's empty-result message through `potato._esc`, and a regression in either
  one has to be visible from the response alone. `rebrew-project.toml`
  (`TestProjectConfigDocument`) is the untrusted document that does not arrive
  over a socket: it names the coverage directory, the target ids
  `/api/targets` serves, and the binary `server._load_dll` reads for `/asm`
  and `/bytes`, so its campaign carries the same two arms as the documents'
  (byte mutation onto the parse refusal, drawn values onto the consumers) plus
  the two pair assertions a status code cannot show, that a declared target id
  reaches `/api/targets` byte for byte and that a declared `binary` resolves
  inside the project tree. A `[targets.X].binary` that does not is refused by
  `_find_dll_path` and logged, and the test
  `TestPathHelpers::test_find_dll_path_refuses_a_binary_outside_the_tree` pins
  the shapes it has to refuse. Two more parsers read a FILE rather than a
  request, so no request campaign reaches either of them.
  `disasm.binary_width_bits` (`TestContainerHeaderWidth`) is handed raw image
  bytes and reads the PE `e_lfanew` at a signed 32-bit offset chosen by
  whatever produced the file, so its campaign asserts the answer against the
  two headers RESTATED in the test rather than against the reader itself, and
  pushes every 64-bit answer through `get_capstone_md` to check the handle a
  64-bit mode produces; a header the format fixes no width for must answer the
  documented floor, never a guess. `documents._read_cached`
  (`TestPersistedParseCache`) loads JSON from the cache directory under
  `$XDG_CACHE_HOME`, which is not the coverage directory and so is not covered
  by the document campaign: it stands in for the TOML, and the seed that
  matters is a slot rebrew's schema ACCEPTS describing different coverage under
  a digest naming neither, because every other seed is refused by the schema
  and only that one is where serving the slot would answer with content the
  repository never wrote. The access-gating headers
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
  stays within `_REGEN_LEDGER_MAX_ENTRIES` however many distinct keys arrive.
  The token gate's accept decision is judged against the extraction rules
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
