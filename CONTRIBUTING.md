# Contributing to recoverage

`make help` lists every contributor command. This page is the path: bootstrap,
edit-test loop, and the one command that reproduces CI before you push.

## Bootstrap (clean clone)

Needs [uv](https://docs.astral.sh/uv/) (0.12.14 or newer; the Makefile warns
below that) and the
sibling [rebrew](https://github.com/maci0/rebrew) checkout at `../rebrew`.
The interpreter is pinned in `.python-version` (3.13, the version CI's lint,
web-lint and smoke jobs run); uv downloads it if the host has no 3.13, and
`uv run --python 3.14 …` selects the other version the test matrix covers.

```bash
make clone-rebrew   # rebrew at the pin in tools/ci_clone_rebrew.sh into ../rebrew
make setup          # uv sync --locked --extra dev
```

`REBREW_REF` / `REBREW_SHA` in `tools/ci_clone_rebrew.sh` are the only copy of
the rebrew pin: `make clone-rebrew` and every CI job read them from there, so a
tag that moves, or a pin that disagrees with `uv.lock`, fails the clone rather
than silently changing the path dependency.

The script removes `../rebrew` before cloning. When that directory is a rebrew
checkout with uncommitted changes it stops instead of discarding the work; run
`REBREW_FORCE=1 make clone-rebrew` to overwrite it knowingly.

The sibling checkout is not optional. `pyproject.toml` pins rebrew to
`path = "../rebrew"`, and recoverage imports `rebrew.workspace` for
`rebrew-project.toml` / coverage-directory resolution plus rebrew's coverage
reader and its catalog/build-db for regen, so `uv sync` cannot resolve without
it. Without
`make clone-rebrew` a bare `uv sync` fails with `Distribution not found at
file://…/rebrew`; `make setup` names the missing checkout instead.

In a git worktree the checkout is not beside the tree, so `../rebrew` resolves
to something that is not rebrew. Link the sibling path at a rebrew checkout
from the worktree root:

```bash
ln -s /path/to/rebrew ../rebrew   # macOS and Linux
```

```powershell
New-Item -ItemType Junction -Path ..\rebrew -Target C:\path\to\rebrew
```

A junction, not `New-Item -ItemType SymbolicLink`: creating a Windows symlink
needs either elevation or Developer Mode, so the symlink spelling fails on a
default shell and the worktree bootstrap stops there. A junction needs
neither, and uv resolves `../rebrew` through it the same way.

`make setup REBREW_DIR=<path>` only moves the preflight check; uv still reads
the path out of `pyproject.toml`, so a check that passes there and a sync that
resolves elsewhere would be worse than none.

Web lint additionally needs [bun](https://bun.sh) (`packageManager` pins
1.4.2) and a JDK 17+ on `PATH`, since `vnu-jar` validates the HTML and CSS
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

The `sbom` job is the only one that reads a lockfile without installing from
it: the Python half comes from `uv export` over `uv.lock` and the browser half
from `tools/bundled_js_inventory.py` over `bun.lock`, and neither needs a
sibling `../rebrew`. `make browser-sbom` prints the second half locally.

The built bundle is committed, so a change under `web/` is not served until
`make web-build` rewrites `src/recoverage/assets/app.js` and `style.css`. The
`build` job copies the tracked tree and rebuilds in both copies, so a bundle
left stale fails that job rather than shipping.

`check-bundle-clean` is the one target here that is not a linter: `make build`
rebuilds `src/recoverage/assets/app.js` and `style.css` from `web/` before
packaging, so a commit whose committed bundle is out of date still produces a
good artifact and would pass every other check. It fails when the build changed
a tracked file under `src/recoverage/assets`, and names the file.

The `build` job is the only CI job that produces the artifact. It builds twice,
the second time in a copy of the tree under a different path with a different
locale and timezone, and fails when the two disagree, printing both hashes and
adding `diffoscope`'s field-by-field breakdown when the image carries it. That
is what makes the reproducibility claim tested rather than asserted, and it
uploads the artifacts it built.

Every target is a wrapper around the third column. Only the `test` row runs on
the whole matrix (Linux, macOS, Windows); every other job is Linux-only. `make` itself
is not: it is not preinstalled on Windows or in a bare Git for Windows shell,
so run the command from the table directly there.

The same applies to `make clone-rebrew`: on a shell without `make`, run
`bash tools/ci_clone_rebrew.sh ../rebrew` instead. That is the whole of it, and
it is what CI runs through `.github/actions/sibling-rebrew`, so do not
reassemble the clone by hand from its two `git` moves. The script carries the
moves that matter (read its header) and two of them are load-bearing: it
removes the destination first, so it refuses to run against a checkout with
uncommitted changes unless `REBREW_FORCE=1`, and it fails when the tag it
cloned no longer resolves to the commit the pin names. A hand-run
`git clone --branch <tag>` gets neither. The tag, the commit, and the clone URL
are written once, in that script; read them there rather than copying them
here.

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
- `filterwarnings = ["error"]` in `pyproject.toml` means a new
  `ResourceWarning` (unclosed socket, file, or connection) fails the build.
  Close the resource instead of filtering the warning.
- `tools/oxlint/rikalabs-strict.json` is generated. After bumping
  `@rikalabs/oxlint-standards`, regenerate it with `make regen-oxlint` and
  re-run `make web-lint`. The target runs the `bun install` the script reads
  `node_modules` from, so it works on a checkout that has only run
  `make setup`.

Conventions, architecture, and the design rules are in `AGENTS.md`.
