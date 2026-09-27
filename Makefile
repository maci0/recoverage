.PHONY: help setup clean test test-one lint format format-check web-lint smoke smoke-fail \
	all ensure-uv ensure-rebrew warn-uv-version clone-rebrew

# Force POSIX sh for recipes (ignore a caller-exported SHELL=bash).  Version
# compares use ``sort -t. -k…n`` (POSIX), not GNU ``sort -V``.
SHELL := /bin/sh

.DEFAULT_GOAL := help

# Lockfile-pinned deps, exactly as every CI job installs them.  Override with
# `make setup UV_SYNC_FLAGS=` to add an extra (e.g. `--extra capstone`).
UV_SYNC_FLAGS ?= --frozen --extra dev

# uv version CI resolves against; warn (do not fail) when the local one is
# older, matching the sibling rebrew checkout's policy.
UV_VERSION ?= 0.12.14

# The rebrew tag this repository develops against, and the commit it must
# resolve to.  Keep REBREW_SHA in step with tools/ci_clone_rebrew.sh, which CI
# uses to populate ../rebrew before `uv sync`.
REBREW_REF ?= v2.13.1
REBREW_SHA ?= d2d67c870df79214320f16b1cba1b0f6086605a7
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
		'  make lint               # ruff check src/ tests/ tools/ (CI lint job)' \
		'  make format             # ruff format (writes)' \
		'  make format-check       # ruff format --check src/ tests/ tools/ (CI lint job)' \
		'  make web-lint           # oxlint + Nu Html Checker (CI web-lint job)' \
		'  make smoke              # boot the dashboard against a sample db and probe it' \
		'  make all                # every check CI runs, in one command' \
		'  make clean              # remove caches and build artifacts' \
		'' \
		'Bootstrap (clean clone):' \
		'  1. Install uv $(UV_VERSION)+ (https://docs.astral.sh/uv/) and Python 3.13+' \
		'  2. make clone-rebrew    # ../rebrew must exist: pyproject.toml [tool.uv.sources]' \
		'  3. make setup && make test-one T=tests/test_api.py' \
		'  Before a PR: make all' \
		'' \
		'Web lint additionally needs bun and a JDK on PATH (vnu-jar runs under java).'

# Every recipe that shells out to ``uv run``; without this a contributor who
# skipped `make setup` gets ``uv: not found`` and no pointer at the cause.
ensure-uv:
	@set -eu; \
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
	@set -eu; \
	if [ ! -e "$(REBREW_DIR)/pyproject.toml" ]; then \
	  echo "ERROR: sibling rebrew checkout missing at $(REBREW_DIR)"; \
	  echo "pyproject.toml [tool.uv.sources] pins rebrew to path = \"../rebrew\", so 'uv sync'"; \
	  echo "cannot resolve the environment without it (imports rebrew.workspace and regen)."; \
	  echo "Run 'make clone-rebrew', or clone it yourself:"; \
	  echo "  git clone --depth 1 --branch $(REBREW_REF) https://github.com/maci0/rebrew.git $(REBREW_DIR)"; \
	  echo "then re-run 'make setup'."; \
	  exit 1; \
	fi; \
	ver=$$(sed -n 's/^__version__ = "\([^"]*\)"/\1/p' "$(REBREW_DIR)/src/rebrew/__init__.py" | head -n 1); \
	lowest=$$(printf '%s\n%s\n' "$$ver" "$(REBREW_FLOOR)" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1); \
	if [ "$$lowest" != "$(REBREW_FLOOR)" ]; then \
	  echo "ERROR: $(REBREW_DIR) is rebrew $$ver, below the $(REBREW_FLOOR) floor in pyproject.toml."; \
	  echo "Check out the pin and re-run 'make setup':"; \
	  echo "  git -C $(REBREW_DIR) fetch --depth 1 origin $(REBREW_SHA)"; \
	  echo "  git -C $(REBREW_DIR) checkout $(REBREW_SHA)"; \
	  exit 1; \
	fi

warn-uv-version: ensure-uv
	@set -eu; \
	uv_ver=$$(uv --version | awk '{print $$2}'); \
	lowest=$$(printf '%s\n%s\n' "$$uv_ver" "$(UV_VERSION)" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1); \
	if [ "$$lowest" != "$(UV_VERSION)" ]; then \
	  echo "WARNING: uv $$uv_ver is older than the CI pin UV_VERSION=$(UV_VERSION)."; \
	  echo "Sync usually still works; upgrade when you can (https://docs.astral.sh/uv/)."; \
	  echo "To silence this: make setup UV_VERSION=$$uv_ver"; \
	fi

clone-rebrew:
	@set -eu; \
	REBREW_REF=$(REBREW_REF) REBREW_SHA=$(REBREW_SHA) bash tools/ci_clone_rebrew.sh "$(REBREW_DIR)"

setup: ensure-rebrew warn-uv-version
	uv sync $(UV_SYNC_FLAGS)

# Match CI's invocation so a local pass and a CI pass mean the same thing.
test: ensure-uv
	uv run --frozen pytest tests/ -v --ignore=tests/test_playwright.py

test-one: ensure-uv
	uv run --frozen pytest $(T) $(FLAGS) -v --tb=short

lint: ensure-uv
	uv run --frozen ruff check src/ tests/ tools/

format: ensure-uv
	uv run --frozen ruff format src/ tests/ tools/

format-check: ensure-uv
	uv run --frozen ruff format --check src/ tests/ tools/

# CI installs bun + a JDK before this; name both rather than failing inside
# oxlint or vnu with a stack trace.
web-lint:
	@set -eu; \
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
all: format-check lint test web-lint smoke smoke-fail
	@printf '%s\n' 'all checks passed (CI: lint, web-lint, test, smoke)'

clean:
	rm -rf .pytest_cache .ruff_cache build dist src/recoverage.egg-info recoverage.egg-info
	find src tests tools -type d -name __pycache__ -prune -exec rm -rf {} +
