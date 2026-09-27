.PHONY: help setup clean test test-one fuzz lint format format-check web-lint smoke smoke-fail \
	shell-lint yaml-lint all ensure-uv ensure-rebrew warn-uv-version clone-rebrew

# Force POSIX sh for recipes (ignore a caller-exported SHELL=bash).  Version
# compares use ``sort -t. -k…n`` (POSIX), not GNU ``sort -V``.
SHELL := /bin/sh

# Strict mode for every multi-line recipe.  `set -eu` alone still lets a failed
# stage of a pipeline hide behind a succeeding last one; pipefail is not POSIX,
# so probe it once and enable it where the shell has it (bash, including
# /bin/sh on macOS) instead of failing under dash.
SET_STRICT = set -eu; if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi;

.DEFAULT_GOAL := help

# Lockfile-pinned deps, exactly as every CI job installs them.  Override with
# `make setup UV_SYNC_FLAGS=` to add an extra (e.g. `--extra capstone`).
UV_SYNC_FLAGS ?= --frozen --extra dev

# uv version CI resolves against; warn (do not fail) when the local one is
# older, matching the sibling rebrew checkout's policy.
UV_VERSION ?= 0.12.14

# The rebrew tag/commit pin lives in tools/ci_clone_rebrew.sh, the one place
# both `make clone-rebrew` and CI read it from.  Set REBREW_REF / REBREW_SHA to
# develop against a different rebrew; the script then takes them from the
# environment.  The commit must be one whose dependency metadata still matches
# uv.lock, or `uv sync --frozen` fails on the lock check.
REBREW_REF ?=
REBREW_SHA ?=
REBREW_DIR := $(abspath $(CURDIR)/../rebrew)

# The floor in pyproject.toml [project].dependencies; rebrew below it lacks
# rebrew.catalog.cli.run_catalog and the coverage.db shared lock.
REBREW_FLOOR ?= 2.10.0

# Single-file / nodeid override for the edit-test loop:
#   make test-one T=tests/test_api.py
#   make test-one T=tests/test_api.py::TestX
#   make test-one T=tests/test_api.py FLAGS="-k functions"
T ?= tests/test_api.py
FLAGS ?=

help:
	@printf '%s\n' \
		'Contributor targets:' \
		'  make setup              # uv sync (frozen, dev extra): the one bootstrap command' \
		'  make clone-rebrew       # clone the sibling rebrew pin into ../rebrew' \
		'  make test               # full pytest suite (CI test job, minus the matrix)' \
		'  make test-one T=<node>  # one file or nodeid, e.g. T=tests/test_api.py::TestX' \
		'  make fuzz              # longer seeded campaign over the untrusted-input surfaces' \
		'  make lint               # ruff check src/ tests/ tools/ (CI lint job)' \
		'  make format             # ruff format (writes)' \
		'  make format-check       # ruff format --check src/ tests/ tools/ (CI lint job)' \
		'  make web-lint           # oxlint + Nu Html Checker (CI web-lint job)' \
		'  make shell-lint         # shellcheck over tools/*.sh (CI lint job)' \
		'  make yaml-lint          # yamllint over .github/ (CI lint job)' \
		'  make smoke              # boot the dashboard against a sample db and probe it' \
		'  make all                # every check CI runs, in one command' \
		'  make clean              # remove caches and build artifacts' \
		'' \
		'Bootstrap (clean clone):' \
		'  1. Install uv $(UV_VERSION)+ (https://docs.astral.sh/uv/); Python 3.13 is pinned in .python-version' \
		'  2. make clone-rebrew    # ../rebrew must exist: pyproject.toml [tool.uv.sources]' \
		'  3. make setup && make test-one T=tests/test_api.py' \
		'  Before a PR: make all' \
		'' \
		'Web lint additionally needs bun and a JDK on PATH (vnu-jar runs under java).'

# Every recipe that shells out to ``uv run``; without this a contributor who
# skipped `make setup` gets ``uv: not found`` and no pointer at the cause.
ensure-uv:
	@$(SET_STRICT) \
	if ! command -v uv >/dev/null 2>&1; then \
	  echo "ERROR: uv not on PATH (required for setup/test/lint; CI pins UV_VERSION=$(UV_VERSION))."; \
	  echo "Install it from https://docs.astral.sh/uv/ then re-run 'make setup'."; \
	  exit 1; \
	fi

# The sibling rebrew checkout is a hard path dependency, not an optional one:
# recoverage imports rebrew.workspace for db path resolution and rebrew's
# catalog/build-db for regen.  Name the missing checkout before uv reports it
# as "Distribution not found at file://…/rebrew".
ensure-rebrew: ensure-uv
	@$(SET_STRICT) \
	if [ ! -e "$(REBREW_DIR)/pyproject.toml" ]; then \
	  echo "ERROR: sibling rebrew checkout missing at $(REBREW_DIR)"; \
	  echo "pyproject.toml [tool.uv.sources] pins rebrew to path = \"../rebrew\", so 'uv sync'"; \
	  echo "cannot resolve the environment without it (imports rebrew.workspace and regen)."; \
	  echo "Run 'make clone-rebrew'; it checks out the tag/commit pinned in"; \
	  echo "tools/ci_clone_rebrew.sh (REBREW_REF / REBREW_SHA), the same pin CI uses."; \
	  exit 1; \
	fi; \
	ver=$$(awk -F'"' '/^__version__ = "/{print $$2; exit}' "$(REBREW_DIR)/src/rebrew/__init__.py"); \
	lowest=$$(printf '%s\n%s\n' "$$ver" "$(REBREW_FLOOR)" | sort -t. -k1,1n -k2,2n -k3,3n | sed -n '1p'); \
	if [ "$$lowest" != "$(REBREW_FLOOR)" ]; then \
	  echo "ERROR: $(REBREW_DIR) is rebrew $$ver, below the $(REBREW_FLOOR) floor in pyproject.toml."; \
	  echo "Re-run 'make clone-rebrew' to check out the pinned rebrew, then 'make setup'."; \
	  echo "To develop against a different one: make clone-rebrew REBREW_REF=<tag> REBREW_SHA=<commit>"; \
	  exit 1; \
	fi

warn-uv-version: ensure-uv
	@$(SET_STRICT) \
	uv_ver=$$(uv --version | awk '{print $$2}'); \
	lowest=$$(printf '%s\n%s\n' "$$uv_ver" "$(UV_VERSION)" | sort -t. -k1,1n -k2,2n -k3,3n | sed -n '1p'); \
	if [ "$$lowest" != "$(UV_VERSION)" ]; then \
	  echo "WARNING: uv $$uv_ver is older than the CI pin UV_VERSION=$(UV_VERSION)."; \
	  echo "Sync usually still works; upgrade when you can (https://docs.astral.sh/uv/)."; \
	  echo "To silence this: make setup UV_VERSION=$$uv_ver"; \
	fi

clone-rebrew:
	@$(SET_STRICT) \
	REBREW_REF=$(REBREW_REF) REBREW_SHA=$(REBREW_SHA) bash tools/ci_clone_rebrew.sh "$(REBREW_DIR)"

setup: ensure-rebrew warn-uv-version
	uv sync $(UV_SYNC_FLAGS)

# Match CI's invocation so a local pass and a CI pass mean the same thing.
# `python -m`, never the bare tool name: the dev extra is an optional
# dependency, so a `uv run` without `--extra dev` does not install pytest or
# ruff and falls back to whatever `pytest` / `ruff` happens to be on the
# contributor's PATH, testing the tree against an unpinned global. The module
# form uses the locked interpreter or fails with "No module named pytest".
test: ensure-uv
	uv run --frozen python -m pytest tests/ -v --ignore=tests/test_playwright.py

test-one: ensure-uv
	uv run --frozen python -m pytest $(T) $(FLAGS) -v --tb=short

# A wider campaign over the same seeded harnesses `make test` already runs;
# the seed and iteration count come from the environment so no file changes.
SEED ?= 1
ITERATIONS ?= 20000

fuzz: ensure-uv
	RECOVERAGE_FUZZ_SEED=$(SEED) RECOVERAGE_FUZZ_ITERATIONS=$(ITERATIONS) \
		uv run --frozen python -m pytest tests/test_fuzz.py -v --tb=short

lint: ensure-uv
	uv run --frozen python -m ruff check src/ tests/ tools/

format: ensure-uv
	uv run --frozen python -m ruff format src/ tests/ tools/

format-check: ensure-uv
	uv run --frozen python -m ruff format --check src/ tests/ tools/

# shellcheck and yamllint cover the tree's non-Python sources: the CI clone
# script and the Actions definitions. Both ship on the ubuntu runner image CI
# uses; name the missing one rather than letting the recipe fail on a bare
# "not found".
ensure-lint-tools:
	@set -eu; \
	if ! command -v shellcheck >/dev/null 2>&1; then \
	  echo "ERROR: shellcheck not on PATH (required by 'make shell-lint')."; \
	  echo "Install it (Debian/Ubuntu: apt install shellcheck, brew install shellcheck)."; \
	  exit 1; \
	fi; \
	if ! command -v yamllint >/dev/null 2>&1; then \
	  echo "ERROR: yamllint not on PATH (required by 'make yaml-lint')."; \
	  echo "Install it (pipx install yamllint, brew install yamllint)."; \
	  exit 1; \
	fi

shell-lint: ensure-lint-tools
	shellcheck -x tools/*.sh

yaml-lint: ensure-lint-tools
	yamllint -c .yamllint.yaml --list-files .github/

# CI installs bun + a JDK before this; name both rather than failing inside
# oxlint or vnu with a stack trace.
web-lint:
	@$(SET_STRICT) \
	if ! command -v bun >/dev/null 2>&1; then \
	  echo "ERROR: bun not on PATH (package.json pins bun 1.4.2 via packageManager)."; \
	  echo "Install bun (https://bun.sh), then re-run 'make web-lint'."; \
	  exit 1; \
	fi; \
	if ! command -v java >/dev/null 2>&1; then \
	  echo "ERROR: java not on PATH (vnu-jar runs the Nu Html Checker; CI installs temurin 17)."; \
	  echo "Install a JDK 17+, then re-run 'make web-lint'."; \
	  exit 1; \
	fi; \
	bun install --frozen-lockfile
	bun run lint

smoke: ensure-uv
	uv run --frozen python tools/smoke.py

smoke-fail: ensure-uv
	uv run --frozen python tools/smoke.py --expect-failure

# Everything CI checks, in one local command, so nothing fails only after push.
all: format-check lint shell-lint yaml-lint test web-lint smoke smoke-fail
	@printf '%s\n' 'all checks passed (CI: lint, web-lint, test, smoke)'

clean:
	rm -rf .pytest_cache .pytest-tmp .ruff_cache build dist src/recoverage.egg-info recoverage.egg-info
	find src tests tools -type d -name __pycache__ -prune -exec rm -rf {} +
