# Contributing to recoverage

`make help` lists every contributor command. This page is the path: bootstrap,
edit-test loop, and the one command that reproduces CI before you push.

## Bootstrap (clean clone)

Needs [uv](https://docs.astral.sh/uv/) 0.13.1 or newer. The interpreter is
pinned in `.python-version` (3.13); uv downloads it if necessary.

```bash
make setup          # uv sync --locked --extra dev
```

Normal installs and CI resolve the public Rebrew wheel declared with its SHA-256
in `pyproject.toml`; they never inspect or replace a sibling source checkout.
On Windows, where Make is not preinstalled, run:

```powershell
uv sync --locked --extra dev
uv run --locked --extra dev python -m pytest tests/ --ignore=tests/test_playwright.py
```

For explicit upstream development, `make clone-rebrew` uses the guarded
`tools/ci_clone_rebrew.sh` tag/commit pin. The helper refuses to overwrite
uncommitted work. Install a chosen checkout only when you intend to test it:

```bash
uv pip install --editable ../rebrew
uv run --no-sync recoverage serve
```

Use `--no-sync` for that development session. A normal `uv sync` or `uv run`
restores the public hash-pinned wheel. No path override is committed.

Web lint additionally needs [bun](https://bun.sh) (`packageManager` pins
1.4.3) and a JDK 17+ on `PATH`, since `vnu-jar` validates the HTML and CSS
under `java`. `make web-lint` names whichever is missing.

`make shell-lint` and `make yaml-lint` need `shellcheck` and `yamllint` on
`PATH`; both ship on the pinned CI runner image, and each target names the one
that is missing. They cover the two non-Python source sets ruff does not see:
the `tools/*.sh` scripts and the `.github/` Actions definitions. Those two
linters are the one part of the pipeline whose version the tree does not pin,
so a Linux job names its runner image (`ubuntu-24.04`) rather than following
`ubuntu-latest`: the image is where they come from, and a fleet update that
added or dropped a rule would change what `make lint` accepts with no commit
to review. Bump the label in `.github/workflows/ci.yml` the way you bump an
action pin.

## The edit-test loop

```bash
make test                              # full suite
make test-one T=tests/test_api.py      # one file
make test-one T=tests/test_api.py::TestApiFunctions  # one class
make test-one T=tests/test_api.py FLAGS="-k functions"
make build                            # wheel + sdist into dist/
```

`make build` is the only way to produce the distribution. It stamps the
artifacts with the commit's own date and a fixed locale and timezone, pins the
build backend through `build-constraints.txt`, clears `dist/` first, and
normalizes the sdist, so building twice gives two identical hashes. A bare
`uv build` does not: setuptools stamps the wheel from `SOURCE_DATE_EPOCH` but
leaves the sdist carrying your mtimes, your uid and the clock, and it takes
whatever setuptools the index serves, which `uv.lock` does not cover because
uv resolves PEP 517 build requirements in an environment of its own. Override
the stamp with `make build SOURCE_DATE_EPOCH=<unix seconds>` when rebuilding an
artifact from a tree with no git.

Run tools through `uv run` (which the Makefile does) rather than a globally
installed copy: the suite's assertions and the ruff rules are pinned in
`uv.lock`, and an older global ruff formats and lints differently. That is why
the Makefile calls `uv run --locked --extra dev python -m pytest` /
`... -m ruff` instead of `uv run pytest` / `uv run ruff`: the module form runs
the locked interpreter, and `--extra dev` is what installs pytest and ruff
when a target is the first command you run on a clean clone, so `make test-one`
works without `make setup` ahead of it.

`--locked`, not `--frozen`: both refuse to rewrite `uv.lock`, but `--frozen`
installs the committed lock even when `pyproject.toml` no longer matches it, so
editing a dependency without running `uv lock` would test the old tree and pass.
After changing a dependency, run `uv lock` (and bump `REBREW_REF`/`REBREW_SHA`
in `tools/ci_clone_rebrew.sh` if rebrew moved) before the next `make`.

`make fuzz` runs the same seeded campaigns `make test` already runs, from the
run seed and round count in `tests/test_fuzz.py`; `make fuzz SEED=7 ITERATIONS=200000`
widens one from the environment. A campaign that fails under `make fuzz`
reproduces under `make test`, so the default is not a separate corpus.

`SEED` is the one knob for a whole run: every campaign's mutation stream is
derived from it by the campaign's own name, so one value determines the run,
each surface explores independently, and adding a campaign cannot shift another
surface's inputs. A failure names the seed its own campaign drew from, and

```bash
RECOVERAGE_FUZZ_SEED=<that seed> \
  make test-one T=tests/test_fuzz.py FLAGS="-k <campaign>"
```

replays that campaign alone. The `FLAGS=` is not optional: a pytest option
handed bare on the make command line never reaches pytest, because make parses
a leading-dash argument as one of its own. `-k` is make's `--keep-going`, so
`-k <campaign>` runs `test-one` and then whatever make finds for the campaign
name — the whole `tests/test_fuzz.py` file when it matches no target, and the
`test` target (the entire suite) when the campaign is named `test`. Either way
the narrowing is silently dropped, and `make --` does not rescue it either: a
goal list after `--` is still make's, not pytest's.

The suite is hermetic. It builds its own synthetic coverage documents (see
`tests/conftest.py`) and needs no project workspace, compiler toolchain, or
network. `tests/test_playwright.py` is excluded by default (`addopts` in
`pyproject.toml`) and no CI job runs it; `make test-browser` syncs the
`playwright` extra, installs the pinned chromium, and runs it.

The browser tests also need a server to talk to. `BASE_URL` defaults to
`http://localhost:8787`, while `recoverage serve` defaults to port 8001, so
start the server on the port the tests ask for (or point `BASE_URL` at the one
you started):

```bash
uv run recoverage serve --port 8787 --no-open   # in another shell
make test-browser
```

Without either, the module skips with the command it wants rather than
failing.

### The frontend loop

`web/` has a dev server of its own, and it is the fast way to see a change:
`make web-dev` (which is `bun install --frozen-lockfile` then `bun run
dev:web`) serves `web/index.html` on `127.0.0.1:5173` and proxies
`/api`, `/src` and `/original` to a running dashboard on
`http://127.0.0.1:8001` (`RECOVERAGE_DEV_API` points it elsewhere). It needs a
`recoverage serve` in another shell for the API half:

```bash
uv run recoverage serve --no-open   # 127.0.0.1:8001, the proxy's default
make web-dev                        # http://127.0.0.1:5173
```

Without the dev server a `web/` change is only visible after `make web-build`
rewrites the committed `app.js` and `style.css`, because the Python server
inlines those two files rather than serving the sources. `make web-lint` and
`make typecheck-web` are the gates a frontend change still has to pass either
way.

## Before you push

```bash
make all
```

That is the local mirror of CI, and each target is the command CI runs:

| Target | CI job | Command |
|--------|--------|---------|
| `make format-check` | lint | `ruff format --check src/ tests/ tools/` |
| `make lint` | lint | `ruff check src/ tests/ tools/` |
| `make type-check` | lint | `mypy` (paths and settings in `pyproject.toml [tool.mypy]`) |
| `make shell-lint` | lint | `shellcheck -x tools/*.sh` |
| `make yaml-lint` | lint | `yamllint -c .yamllint.yaml .github/` |
| `make test` | test | `pytest tests/ -v --ignore=tests/test_playwright.py` |
| `make web-lint` | web-lint | `bun install --frozen-lockfile && bun run lint` |
| `make typecheck-web` | web-lint | `bun install --frozen-lockfile && bun run typecheck:web` (`tsc --noEmit`) |
| `make web-build` | build | `bun install --frozen-lockfile && bun run build:web` (rebuilds `src/recoverage/assets/app.js` and `style.css`) |
| `make build` | build | `make web-build`, then `uv build` (reproducible) and `tools/normalize_sdist.py` |
| `make check-bundle-clean` | build | `git status --porcelain -- src/recoverage/assets` |
| `make smoke` | smoke | `python tools/smoke.py` |
| `make smoke-fail` | smoke | `python tools/smoke.py --expect-failure` |
| `make browser-sbom` | sbom | `python tools/bundled_js_inventory.py` |
| `make python-sbom` | sbom | `uv export --locked --all-extras --hashes`, then the rebrew tag and commit read from `tools/ci_clone_rebrew.sh` |
| `make license-inventory` | lint | `python tools/license_inventory.py` |

The `sbom` job is the only one that reads a lockfile without installing from
it: the Python half comes from `uv export` over `uv.lock` and the browser half
from `tools/bundled_js_inventory.py` over `bun.lock`, and neither needs a
sibling `../rebrew`. `make python-sbom` and `make browser-sbom` print the two
halves locally, so the artifact a release ships can be reproduced without CI.
The `sbom` job runs those commands rather than spelling the export out again,
so the file it uploads and the one a contributor prints are the same command.

The built bundle is committed, so a change under `web/` is not served until
`make web-build` rewrites `src/recoverage/assets/app.js` and `style.css`. The
`build` job copies the tracked tree and rebuilds in both copies, so a bundle
left stale fails that job rather than shipping.

`check-bundle-clean` is the one target here that is not a linter: `make build`
rebuilds `src/recoverage/assets/app.js` and `style.css` from `web/` before
packaging, so a commit whose committed bundle is out of date still produces a
good artifact and would pass every other check. It fails when the build changed
a tracked file under `src/recoverage/assets`, and names the file.

The `build` job is the only CI job that produces the artifact, and it waits for
`test`, so a commit whose suite fails never attaches a wheel for anything to
download. It builds twice, the second time in a copy of the tree under a
different path with a different locale and timezone, and fails when the two
disagree, printing both hashes and adding `diffoscope`'s field-by-field
breakdown when the image carries it. That is what makes the reproducibility
claim tested rather than asserted, and it uploads the artifacts it built.

Every target is a wrapper around the third column. Only the `test` row runs on
the whole matrix (Linux, macOS, Windows); every other job is Linux-only. `make` itself
is not: it is not preinstalled on Windows or in a bare Git for Windows shell,
so run the command from the table directly there.

`make clone-rebrew` is optional upstream development tooling. The script owns
the source tag, full commit and clone URL, verifies the tag resolves to that
commit, and refuses to overwrite uncommitted work. On Windows it can be run as
`bash tools/ci_clone_rebrew.sh ../rebrew` from Git for Windows. It does not
change the dependency used by `uv sync`.

## Adding to the tree

- Backend modules live in `src/recoverage/`; `webapp.py` is the composition
  root that imports `api.py`, `ui.py` and `potato.py` so the app has every
  route.
- Tests live in `tests/`, one module per source module, and reuse the
  `tests/conftest.py` fixtures for the synthetic coverage documents.
- A change a user of the dashboard or the CLI can see gets a `CHANGELOG.md`
  entry under `[Unreleased]`, in one of the groups `Added` / `Breaking` /
  `Changed` / `Deprecated` / `Fixed` / `Removed` / `Security`. A refactor, a
  test and a doc change do not. `tests/test_release.py` fails on a group
  outside that set, on a group that repeats, and on a `Breaking` marker the
  release has to answer with a major.
- A refactor that deletes a public module-level name is not a refactor as far
  as the changelog is concerned: anything importing it gets an `ImportError`,
  which is a release note. `tests/public_surface.txt` is the package's public
  surface as of the last release that shipped with no unrecorded removal, and
  `tests/test_release.py`
  (`TestPublicSurfaceChangesAreRecorded`) fails when a name in it is gone and
  no `Removed` or `Breaking` entry records the removal. Adding a name needs no
  entry and no baseline edit; removing one is legal once it is written down.
- `filterwarnings = ["error"]` in `pyproject.toml` means a new
  `ResourceWarning` (unclosed socket, file, or connection) fails the build.
  Close the resource instead of filtering the warning.
- `tools/oxlint/rikalabs-strict.json` is generated. After bumping
  `@rikalabs/oxlint-standards`, regenerate it with `make regen-oxlint` and
  re-run `make web-lint`. The target runs the `bun install` the script reads
  `node_modules` from, so it works on a checkout that has only run
  `make setup`.
- `tools/oxlint/anti-slop.manifest.json` is generated the same way. Re-vendoring
  `tools/oxlint/anti-slop/` means replacing the directory from upstream and
  running `make vendor-manifest`, then `make web-lint`.

The inventory targets `make python-sbom`, `make browser-sbom` (and `-spdx`),
and `make vendor-manifest` need no synced environment. Their stdlib-only tools
run through `uv run --no-project`; `python-sbom` validates and exports the lock
with `uv export --locked`. `make web-lint` also imports the application and
therefore uses the normal public dependency environment.

Conventions, architecture, and the design rules are in `AGENTS.md`.
