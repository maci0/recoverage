# Contributing to recoverage

`make help` lists every contributor command. This page is the path: bootstrap,
edit-test loop, and the one command that reproduces CI before you push.

## Bootstrap (clean clone)

Needs [uv](https://docs.astral.sh/uv/) (CI resolves against 0.12.14), Python
3.13+ (`requires-python` in `pyproject.toml`), and the sibling
[rebrew](https://github.com/maci0/rebrew) checkout at `../rebrew`.

```bash
make clone-rebrew   # rebrew v2.13.1 into ../rebrew (rebrew is a path dependency)
make setup          # uv sync --frozen --extra dev
```

The sibling checkout is not optional. `pyproject.toml` pins rebrew to
`path = "../rebrew"`, and recoverage imports `rebrew.workspace` for
`rebrew-project.toml` / `coverage.db` resolution plus rebrew's
catalog/build-db for regen, so `uv sync` cannot resolve without it. Without
`make clone-rebrew` a bare `uv sync` fails with `Distribution not found at
file://…/rebrew`; `make setup` names the missing checkout instead.

To use a rebrew checkout that is not the pinned commit (a sibling you are
developing against, say), point the preflight at it:

```bash
make setup REBREW_DIR=/path/to/rebrew
```

Web lint additionally needs [bun](https://bun.sh) (`packageManager` pins
1.4.2) and a JDK 17+ on `PATH`, since `vnu-jar` validates the HTML and CSS
under `java`. `make web-lint` names whichever is missing.

`make shell-lint` and `make yaml-lint` need `shellcheck` and `yamllint` on
`PATH`; both ship on the CI runner image, and each target names the one that
is missing. They cover the two non-Python source sets ruff does not see: the
`tools/*.sh` scripts and the `.github/` Actions definitions.

## The edit-test loop

```bash
make test                              # full suite
make test-one T=tests/test_api.py      # one file
make test-one T=tests/test_api.py::TestServer  # one test
make test-one T=tests/test_api.py FLAGS="-k functions"
```

Run tools through `uv run` (which the Makefile does) rather than a globally
installed copy: the suite's assertions and the ruff rules are pinned in
`uv.lock`, and an older global ruff formats and lints differently.

The suite is hermetic. It builds its own synthetic `coverage.db` (see
`tests/conftest.py`) and needs no project workspace, compiler toolchain, or
network. `tests/test_playwright.py` is excluded by default (`addopts` in
`pyproject.toml`); run it explicitly after `uv sync --extra playwright` and
`playwright install`.

## Before you push

```bash
make all
```

That is the local mirror of CI, and each target is the command CI runs:

| Target | CI job | Command |
|--------|--------|---------|
| `make format-check` | lint | `ruff format --check src/ tests/ tools/` |
| `make lint` | lint | `ruff check src/ tests/ tools/` |
| `make shell-lint` | lint | `shellcheck -x tools/*.sh` |
| `make yaml-lint` | lint | `yamllint -c .yamllint.yaml .github/` |
| `make test` | test | `pytest tests/ -v --ignore=tests/test_playwright.py` |
| `make web-lint` | web-lint | `bun install --frozen-lockfile && bun run lint` |
| `make smoke` | smoke | `python tools/smoke.py` |
| `make smoke-fail` | smoke | `python tools/smoke.py --expect-failure` |

CI also builds an SBOM from `uv.lock` (`uv export`); it needs no local step.

Every target is a wrapper around the third column, and every one of those
commands runs on the whole test matrix (Linux, macOS, Windows). `make` itself
is not: it is not preinstalled on Windows or in a bare Git for Windows shell,
so run the command from the table directly there. The same applies to
`make clone-rebrew`, whose two moves are `git clone --depth 1 --branch v2.13.1
https://github.com/maci0/rebrew.git ../rebrew` and `git -C ../rebrew checkout
--detach d2d67c870df79214320f16b1cba1b0f6086605a7`; `tools/ci_clone_rebrew.sh`
is the same script CI runs and takes the destination as its first argument.

## Adding to the tree

- Backend modules live in `src/recoverage/`; `webapp.py` is the composition
  root that imports `api.py`, `ui.py` and `potato.py` so the app has every
  route.
- Tests live in `tests/`, one module per source module, and reuse the
  `tests/conftest.py` fixtures for the synthetic database.
- `filterwarnings = ["error"]` in `pyproject.toml` means a new
  `ResourceWarning` (unclosed socket, file, or connection) fails the build.
  Close the resource instead of filtering the warning.
- `tools/oxlint/rikalabs-strict.json` is generated. After bumping
  `@rikalabs/oxlint-standards`, regenerate it with
  `python tools/flatten-rikalabs-strict.py` and re-run `make web-lint`.

Conventions, architecture, and the design rules are in `AGENTS.md`.
