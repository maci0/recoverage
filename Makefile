.PHONY: help setup clean build test test-one test-browser fuzz lint format format-check web-lint smoke smoke-fail \
	shell-lint yaml-lint type-check all ensure-uv ensure-rebrew warn-uv-version clone-rebrew ensure-lint-tools \
	ensure-bun regen-oxlint typecheck-web

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
# --locked, not --frozen: both refuse to write a new lockfile, but --frozen
# installs uv.lock even when pyproject.toml no longer matches it, so a
# dependency edit that skipped `uv lock` would test a tree the manifest does
# not describe.  --locked fails the run instead, which is what "a stale lock
# fails the build" means.
UV_SYNC_FLAGS ?= --locked --extra dev

# Every recipe that runs a tool out of the project environment.  `--extra dev`
# is what makes the edit-test loop work on a clean clone without `make setup`
# first: `uv run` syncs the environment from uv.lock either way, and without
# the extra it installs the 30 runtime packages and leaves pytest and ruff
# missing, so `make test` dies on "No module named pytest" instead of running.
# Same install as `make setup` and every CI job, so a local pass and a CI pass
# still mean the same thing.
UV_RUN := uv run --locked --extra dev

# uv floor the local toolchain is checked against; warn (do not fail) when the
# installed one is older, matching the sibling rebrew checkout's policy.  CI
# installs the same version: setup-uv has no version-file input, so ci.yml
# carries the literal and tests/test_supply_chain.py fails when the two
# disagree.  Bump both together.
UV_VERSION ?= 0.12.14

# The interpreter pin, read from the file that owns it rather than restated
# here, so `make help` cannot name a version .python-version no longer has.
PYTHON_VERSION := $(shell cat .python-version)

# The rebrew tag/commit pin lives in tools/ci_clone_rebrew.sh and nowhere
# else, so the Makefile does not restate it: `make clone-rebrew
# REBREW_REF=<tag> REBREW_SHA=<commit>` reaches the script as environment
# variables, which the command-line assignment already exports.  The commit
# must be one whose dependency metadata still matches uv.lock, or
# `uv sync --locked` fails on the lock check.
REBREW_DIR := $(abspath $(CURDIR)/../rebrew)

# The floor in pyproject.toml [project].dependencies; rebrew below it lacks
# rebrew.coverage_toml, the module that writes and reads the coverage
# documents this dashboard serves.
REBREW_FLOOR ?= 2.16.0

# Timestamp the built artifacts are stamped with, so two builds of one commit
# agree byte for byte. The commit's own date, which is what a release wants and
# what setuptools bdist_wheel and tools/normalize_sdist.py both read; override
# it to rebuild a published artifact from a tree with no git (an sdist
# unpacked on a build machine, say). FALLBACK_… is fixed, never the clock, so
# a tree without git still produces the same bytes on every run.
FALLBACK_SOURCE_DATE_EPOCH = 315532800
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo $(FALLBACK_SOURCE_DATE_EPOCH))

# Single-file / nodeid override for the edit-test loop:
#   make test-one T=tests/test_api.py
#   make test-one T=tests/test_api.py::TestX
#   make test-one T=tests/test_api.py FLAGS="-k functions"
T ?= tests/test_api.py
FLAGS ?=

help:
	@printf '%s\n' \
		'Contributor targets:' \
		'  make setup              # uv sync (locked, dev extra): the one bootstrap command' \
		'  make build              # build the wheel + sdist reproducibly into dist/' \
		'  make clone-rebrew       # clone the sibling rebrew pin into ../rebrew' \
		'  make test               # full pytest suite (CI test job, minus the matrix)' \
		'  make test-one T=<node>  # one file or nodeid, e.g. T=tests/test_api.py::TestX' \
		'  make test-browser       # browser tests: installs playwright + chromium, then runs them' \
		'  make fuzz              # longer seeded campaign over the untrusted-input surfaces' \
		'  make lint               # ruff check src/ tests/ tools/ (CI lint job)' \
		'  make type-check         # mypy over src/ and tools/ (CI lint job)' \
		'  make format             # ruff format (writes)' \
		'  make format-check       # ruff format --check src/ tests/ tools/ (CI lint job)' \
		'  make web-lint           # oxlint + Nu Html Checker (CI web-lint job)' \
		'  make typecheck-web      # tsc --noEmit over web/ (CI web-lint job)' \
		'  make regen-oxlint       # regenerate tools/oxlint/rikalabs-strict.json after a preset bump' \
		'  make shell-lint         # shellcheck over tools/*.sh (CI lint job)' \
		'  make yaml-lint          # yamllint over .github/ (CI lint job)' \
		'  make smoke              # boot the dashboard against a sample db and probe it' \
		'  make all                # every check CI runs, in one command' \
		'  make clean              # remove caches and build artifacts' \
		'' \
		'Bootstrap (clean clone):' \
		'  1. Install uv $(UV_VERSION)+ (https://docs.astral.sh/uv/); Python $(PYTHON_VERSION) is pinned in .python-version' \
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
	  echo "ERROR: uv not on PATH (required for setup/test/lint; $(UV_VERSION)+ is the tested floor)."; \
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
	if [ -f "$(REBREW_DIR)/src/rebrew/coverage_toml.py" ]; then \
	  :; \
	else \
	  echo "ERROR: $(REBREW_DIR) is rebrew $$ver and ships no src/rebrew/coverage_toml.py,"; \
	  echo "which is what $(REBREW_FLOOR) is the floor for: it writes and reads every"; \
	  echo "coverage-<target>.toml this repository serves and produces."; \
	  echo "Re-run 'make clone-rebrew' to check out the pinned rebrew, then 'make setup'."; \
	  echo "To develop against a different one: make clone-rebrew REBREW_REF=<tag> REBREW_SHA=<commit>"; \
	  exit 1; \
	fi

warn-uv-version: ensure-uv
	@$(SET_STRICT) \
	uv_ver=$$(uv --version | awk '{print $$2}'); \
	lowest=$$(printf '%s\n%s\n' "$$uv_ver" "$(UV_VERSION)" | sort -t. -k1,1n -k2,2n -k3,3n | sed -n '1p'); \
	if [ "$$lowest" != "$(UV_VERSION)" ]; then \
	  echo "WARNING: uv $$uv_ver is older than the tested floor UV_VERSION=$(UV_VERSION)."; \
	  echo "Sync usually still works; upgrade when you can (https://docs.astral.sh/uv/)."; \
	  echo "To silence this: make setup UV_VERSION=$$uv_ver"; \
	fi

clone-rebrew:
	@$(SET_STRICT) \
	bash tools/ci_clone_rebrew.sh "$(REBREW_DIR)"

setup: ensure-rebrew warn-uv-version
	uv sync $(UV_SYNC_FLAGS)

# The shipped artifact. SOURCE_DATE_EPOCH reaches setuptools (which stamps
# the wheel from it) and the sdist normalizer, LC_ALL and TZ keep a locale or
# a timezone out of the build, and the normalizer does what setuptools' sdist
# does not: pin the mtimes, owner, permissions, entry order and gzip header a
# rebuild would otherwise differ on. Run it twice and `sha256sum dist/*` to
# see both artifacts hold their hash.
#
# ensure-rebrew, not just ensure-uv: the recipe ends in a `uv run`, which syncs
# the project environment, and that environment cannot resolve the rebrew path
# dependency without the sibling checkout. Without the preflight the build dies
# on "Distribution not found at file://.../rebrew", which names neither the
# cause nor the fix.
#
# --build-constraints pins the build backend. setuptools is not in uv.lock (uv
# resolves PEP 517 build requirements in an isolated env of its own), so
# without it `uv build` installs whatever setuptools PyPI serves that day, and a
# backend release can change the artifact bytes under a fixed
# SOURCE_DATE_EPOCH. --clear drops artifacts from an earlier version, which
# would otherwise sit in dist/ beside the new ones and be published together.
build: ensure-rebrew ensure-uv web-build
	@$(SET_STRICT) \
	export SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" LC_ALL=C TZ=UTC; \
	uv build --out-dir dist --build-constraints build-constraints.txt --clear; \
	$(UV_RUN) python tools/normalize_sdist.py dist

# The dashboard bundle. It is committed (src/recoverage/assets/app.js and
# style.css) because the CI build job copies the tracked tree and builds it
# twice, and a wheel built without a bundler on the host must still carry a
# frontend. Rebuilding here is what makes the committed bytes reproducible
# rather than merely present: the build job's second tree rebuilds and compares.
web-build: ensure-bun
	bun install --frozen-lockfile
	bun run build:web

# Match CI's invocation so a local pass and a CI pass mean the same thing.
# `python -m`, never the bare tool name: with the dev extra installed a bare
# `uv run pytest` would still fall back to whatever `pytest` happens to be on
# the contributor's PATH, testing the tree against an unpinned global. The
# module form runs the locked interpreter or fails loudly.
test: ensure-rebrew
	$(UV_RUN) python -m pytest tests/ -v --ignore=tests/test_playwright.py

test-one: ensure-rebrew
	$(UV_RUN) python -m pytest $(T) $(FLAGS) -v --tb=short

# The browser tests need the playwright extra (not in the dev extra), the
# chromium build that extra pins, and a server on the port BASE_URL names.
# `make all` and CI leave them out, so the three steps live in one target
# rather than in prose a contributor has to reassemble.
# `--locked`, like every other install here: the extra is declared in
# pyproject.toml and locked, and `--frozen` would install uv.lock even after a
# playwright dependency edit skipped `uv lock`, so the browser tests would
# pass against a package the manifest does not describe.
test-browser: ensure-uv
	uv sync --locked --extra dev --extra playwright
	$(UV_RUN) playwright install chromium
	$(UV_RUN) python -m pytest tests/test_playwright.py -v --tb=short

# A wider campaign over the same seeded harnesses `make test` already runs;
# the seed and iteration count come from the environment so no file changes.
SEED ?= 1
ITERATIONS ?= 20000

fuzz: ensure-rebrew
	RECOVERAGE_FUZZ_SEED=$(SEED) RECOVERAGE_FUZZ_ITERATIONS=$(ITERATIONS) \
		$(UV_RUN) python -m pytest tests/test_fuzz.py -v --tb=short

lint: ensure-uv
	$(UV_RUN) python -m ruff check src/ tests/ tools/

format: ensure-uv
	$(UV_RUN) python -m ruff format src/ tests/ tools/

format-check: ensure-uv
	$(UV_RUN) python -m ruff format --check src/ tests/ tools/

# The type gate.  The paths are the gate's [tool.mypy] files list, not
# a restatement of it: tests/ joins that list when its fixtures are
# annotated, and a second copy of the list here is one that drifts.
type-check: ensure-uv
	$(UV_RUN) python -m mypy

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

# No --list-files: that flag makes yamllint print the paths and exit, so the
# gate passed on every workflow it was pointed at and linted none of them.
yaml-lint: ensure-lint-tools
	yamllint -c .yamllint.yaml .github/

# CI installs bun + a JDK before this; name both rather than failing inside
# oxlint or vnu with a stack trace.
web-lint: ensure-bun
	@$(SET_STRICT) \
	if ! command -v java >/dev/null 2>&1; then \
	  echo "ERROR: java not on PATH (vnu-jar runs the Nu Html Checker under java)."; \
	  echo "Install a JDK, then re-run 'make web-lint'."; \
	  exit 1; \
	fi; \
	bun install --frozen-lockfile
	bun run lint

# The TypeScript gate. web/tsconfig.json is strict plus noUncheckedIndexedAccess,
# exactOptionalPropertyTypes and the rest, so a `bun run lint` that never runs
# tsc leaves every one of those settings unverified: oxlint runs without type
# information (the Rika preset is flattened with typeAware: false), so nothing
# else in the pipeline checks a type. Its own target, run by `make all` and by
# the CI web-lint job, so a frontend type error blocks a merge.
typecheck-web: ensure-bun
	bun install --frozen-lockfile
	bun run typecheck:web

ensure-bun:
	@$(SET_STRICT) \
	if ! command -v bun >/dev/null 2>&1; then \
	  echo "ERROR: bun not on PATH (package.json's packageManager field pins the version)."; \
	  echo "Install that bun (https://bun.sh), then re-run 'make web-lint'."; \
	  exit 1; \
	fi

# tools/oxlint/rikalabs-strict.json is generated from the installed
# @rikalabs/oxlint-standards and is review-blocking, so the install of the
# package it reads is part of the command: the script looks under node_modules,
# which a checkout that has only run `uv sync` does not have.
regen-oxlint: ensure-bun
	bun install --frozen-lockfile
	$(UV_RUN) python tools/flatten-rikalabs-strict.py

smoke: ensure-rebrew
	$(UV_RUN) python tools/smoke.py

smoke-fail: ensure-rebrew
	$(UV_RUN) python tools/smoke.py --expect-failure

# Everything CI checks, in one local command, so nothing fails only after push.
all: format-check lint type-check shell-lint yaml-lint test web-lint typecheck-web smoke smoke-fail
	@printf '%s\n' 'all checks passed (CI: lint, web-lint, test, smoke)'

clean:
	rm -rf .pytest_cache .pytest-tmp .ruff_cache .mypy_cache .scratch build dist \
		src/recoverage.egg-info recoverage.egg-info
	find src tests tools -type d -name __pycache__ -prune -exec rm -rf {} +
