# web-build is in this list like every other target: it produces no file named
# after itself, but a stale `web-build` directory or script in the tree would
# otherwise make make consider it up to date and skip the bundle rebuild, which
# is the one step that keeps the committed assets matching web/.
.PHONY: help setup clean build check-bundle-clean web-build web-dev test test-one test-browser fuzz lint format format-check web-lint smoke smoke-fail \
	shell-lint yaml-lint type-check all ensure-uv ensure-rebrew warn-uv-version clone-rebrew ensure-lint-tools \
	ensure-bun regen-oxlint typecheck-web payload-budget browser-sbom

# Force POSIX sh for recipes (ignore a caller-exported SHELL=bash).  Version
# compares use ``sort -t. -k…n`` (POSIX), not GNU ``sort -V``.
SHELL := /bin/sh

# Strict mode for every multi-line recipe.  `set -eu` alone still lets a failed
# stage of a pipeline hide behind a succeeding last one; pipefail is not POSIX,
# so probe it once and enable it where the shell has it (bash, including
# /bin/sh on macOS) instead of failing under dash.
SET_STRICT = set -eu; if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi;

# Every target here shares one .venv, one node_modules and one dist/, and
# `all` chains work that mutates all three in the order it declares them:
# `build` rewrites src/recoverage/assets/ and dist/, `check-bundle-clean` is
# the gate over what `build` just wrote there, and `format` rewrites the
# sources `test` is reading. Make orders a prerequisite list under `-j` by
# nothing at all, so `make -j8 all` could run the gate against a bundle
# mid-write and `format` against a test mid-read, and the answer would depend
# on the scheduler. Serial for the whole file rather than per target, because
# the shared state is the reason.
.NOTPARALLEL:

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

# The hash seed every Python process in this tree starts with.  CPython
# randomizes `hash()` of a str per process, so `set` and `frozenset` iterate in
# a different order in every run: a value that reaches an assertion, a served
# payload or a log line through an unsorted collection is then a coin flip, and
# two runs of one seed cannot be diffed against each other.  Pinning it to 0
# makes the order a function of the values alone, so a replayed run produces
# the same bytes.  It has to be in the ENVIRONMENT of the interpreter, not in
# conftest.py: the seed is read once, at startup, before any import this tree
# controls.  The value is overridable so a developer chasing an
# order-dependent failure can re-run under a different seed; the default is
# what CI uses, so a local run and a CI run agree.
PYTHON_HASH_SEED ?= 0
export PYTHONHASHSEED := $(PYTHON_HASH_SEED)


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
		'  make type-check         # mypy over src/, tools/ and the shared fixtures (CI lint job)' \
		'  make format             # ruff format (writes)' \
		'  make format-check       # ruff format --check src/ tests/ tools/ (CI lint job)' \
		'  make web-lint           # oxlint + Nu Html Checker (CI web-lint job)' \
		'  make typecheck-web      # tsc --noEmit over web/ (CI web-lint job)' \
		'  make web-build          # rebuild the committed bundle in src/recoverage/assets' \
		'  make web-dev            # vite dev server for web/ on 127.0.0.1:5173 (see CONTRIBUTING)' \
		'  make regen-oxlint       # regenerate tools/oxlint/rikalabs-strict.json after a preset bump' \
		'  make shell-lint         # shellcheck over tools/*.sh (CI lint job)' \
		'  make yaml-lint          # yamllint over .github/ (CI lint job)' \
		'  make smoke              # boot the dashboard against a sample db and probe it' \
		'  make smoke-fail         # the same probe against a corrupt db: must degrade, not lie' \
		'  make payload-budget     # re-derive the inlined shell size at each static encoding' \
		'  make browser-sbom       # list the npm packages compiled into the shipped browser assets' \
		'  make all                # every check CI runs, in one command' \
		'  make check-bundle-clean # fail when the committed web bundle is stale (make all runs it)' \
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
#
# Every target that reaches uv depends on this, not only the ones whose tool
# imports rebrew: `uv run` and `uv sync` both resolve uv.lock, and the lock
# carries the path dependency, so `make lint` on a clone with no sibling
# checkout dies in uv before ruff ever starts.  The tool it would have run is
# beside the point: the answer the contributor gets names neither the missing
# checkout nor the command that fetches it.
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
#
# check_wheel_assets.py reads BUNDLE_ASSETS back off the wheel the build just
# produced. The two loops below judge the bundle DIRECTORY, and three lists sit
# between that directory and the shipped members (the `assets/*` package-data
# glob, the sdist file list, MANIFEST.in), so an asset that stops being packaged
# passes every other gate here and is found by whoever installs the wheel.
build: ensure-rebrew ensure-uv web-build
	@$(SET_STRICT) \
	export SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" LC_ALL=C TZ=UTC; \
	for f in $(BUNDLE_ASSETS); do \
	  if [ ! -f "$(BUNDLE_DIR)/$$f" ]; then \
	    echo "ERROR: $(BUNDLE_DIR)/$$f is missing from the asset directory."; \
	    echo "Run 'make web-build'; a wheel built from a partial bundle serves nothing."; \
	    exit 1; \
	  fi; \
	done; \
	for f in "$(BUNDLE_DIR)"/* "$(BUNDLE_DIR)"/.[!.]*; do \
	  [ -e "$$f" ] || continue; \
	  base=$${f##*/}; \
	  case " $(BUNDLE_ASSETS) " in \
	    *" $$base "*) ;; \
	    *) echo "ERROR: $(BUNDLE_DIR)/$$base is not one of the shipped assets."; \
	       echo "pyproject.toml's package data is the glob 'assets/*', so every file that"; \
	       echo "lands here rides into the wheel. Remove it, or add it to BUNDLE_ASSETS."; \
	       exit 1;; \
	  esac; \
	done; \
	uv build --out-dir dist --build-constraints build-constraints.txt --clear; \
	assets=""; for f in $(BUNDLE_ASSETS); do assets="$$assets --asset $$f"; done; \
	$(UV_RUN) python tools/check_wheel_assets.py dist $$assets; \
	$(UV_RUN) python tools/normalize_sdist.py dist

# The dashboard bundle is committed because a wheel built on a host with no
# bundler must still carry a frontend, and `build` regenerates both files from
# web/ before packaging. That leaves the committed bytes unverified: a
# contributor who edits web/ and ships a stale app.js gets a build that passes
# every other gate here. A rebuild that changes a tracked asset is the signal,
# so the check names the asset directory rather than the whole tree, and a
# contributor with unrelated work in progress can still run it. The CI build
# job runs this after its first build for the same reason: the two-build
# comparison would pass on a tree that was already out of date.
BUNDLE_DIR = src/recoverage/assets

# Exactly what the wheel is allowed to pick up from BUNDLE_DIR. pyproject.toml's
# package data is the glob `assets/*`, so the directory's contents ARE the
# shipped file list, and Vite cannot police it: `emptyOutDir` is off (the
# directory also holds the hand-written index.html, print.css and favicon.svg,
# which Vite does not emit), so a scratch file, an editor backup or a leftover
# from a renamed output stays where it was dropped. The `build` recipe refuses a
# directory holding anything else, and a missing member, so a contaminated
# bundle fails the build instead of shipping.
BUNDLE_ASSETS = app.js favicon.svg index.html print.css style.css

check-bundle-clean:
	@$(SET_STRICT) \
	if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
	  echo "ERROR: check-bundle-clean compares the rebuilt bundle against the"; \
	  echo "committed one, and that is a git comparison: $(BUNDLE_DIR) is not a work tree."; \
	  echo "Run it from a checkout; the copy of the tracked tree a CI rebuild makes is"; \
	  echo "compared by building it twice instead."; \
	  exit 1; \
	fi; \
	if [ -n "$$(git status --porcelain -- $(BUNDLE_DIR))" ]; then \
	  echo "ERROR: the committed frontend bundle does not match web/:"; \
	  git status --porcelain -- $(BUNDLE_DIR); \
	  echo "Run 'make web-build' and commit the result."; \
	  exit 1; \
	fi

# The dashboard bundle. It is committed (src/recoverage/assets/app.js and
# style.css) because the CI build job copies the tracked tree and builds it
# twice, and a wheel built without a bundler on the host must still carry a
# frontend. Rebuilding here is what makes the committed bytes reproducible
# rather than merely present: the build job's second tree rebuilds and compares.
#
# LC_ALL and TZ, the same two the `build` recipe exports: this target is a
# prerequisite of it, so it runs in its own shell, and the two files it writes
# are packaged inputs rather than a by-product. A contributor whose shell
# exports a non-C locale or a non-UTC timezone therefore produced a bundle no
# CI run ever byte-compared, and `check-bundle-clean` would report the
# committed one as stale.
web-build: ensure-bun
	@$(SET_STRICT) \
	export LC_ALL=C TZ=UTC; \
	bun install --frozen-lockfile; \
	bun run build:web

# The frontend edit loop. CONTRIBUTING describes it, but as prose the
# contributor has to reassemble: `bun install` on its own, then `bun run
# dev:web` from the worktree root, against a `recoverage serve` in another
# shell. Every other bun target here runs the install first, and a checkout
# that has only run `make setup` has no node_modules, so the raw pair dies on
# a module vite cannot resolve. Same install, same pin as the gates; the dev
# server itself is a long-lived process the contributor stops with ^C.
web-dev: ensure-bun
	bun install --frozen-lockfile
	bun run dev:web

# Match CI's invocation so a local pass and a CI pass mean the same thing.
# `python -m`, never the bare tool name: with the dev extra installed a bare
# `uv run pytest` would still fall back to whatever `pytest` happens to be on
# the contributor's PATH, testing the tree against an unpinned global. The
# module form runs the locked interpreter or fails loudly.
test: ensure-rebrew
	$(UV_RUN) python -m pytest tests/ -v --ignore=tests/test_playwright.py

# -rs prints each skip's reason. tests/test_playwright.py skips at module
# level when playwright, the pinned chromium or a live server at BASE_URL is
# missing, and CONTRIBUTING promises the skip names the command that fixes it.
# Without -rs pytest reports only "1 skipped", so the promise was invisible and
# the run ended in make's bare "Error 5" with nothing above it to explain.
test-one: ensure-rebrew
	$(UV_RUN) python -m pytest $(T) $(FLAGS) -v -rs --tb=short

# The browser tests need the playwright extra (not in the dev extra), the
# chromium build that extra pins, and a server on the port BASE_URL names.
# `make all` and CI leave them out, so the three steps live in one target
# rather than in prose a contributor has to reassemble.
# `--locked`, like every other install here: the extra is declared in
# pyproject.toml and locked, and `--frozen` would install uv.lock even after a
# playwright dependency edit skipped `uv lock`, so the browser tests would
# pass against a package the manifest does not describe.
test-browser: ensure-rebrew
	uv sync --locked --extra dev --extra playwright
	$(UV_RUN) playwright install chromium
	$(UV_RUN) python -m pytest tests/test_playwright.py -v -rs --tb=short

# A wider campaign over the same seeded harnesses `make test` already runs;
# the seed and iteration count come from the environment so no file changes.
SEED ?= 1
ITERATIONS ?= 20000

fuzz: ensure-rebrew
	RECOVERAGE_FUZZ_SEED=$(SEED) RECOVERAGE_FUZZ_ITERATIONS=$(ITERATIONS) \
		$(UV_RUN) python -m pytest tests/test_fuzz.py -v --tb=short

lint: ensure-rebrew
	$(UV_RUN) python -m ruff check src/ tests/ tools/

format: ensure-rebrew
	$(UV_RUN) python -m ruff format src/ tests/ tools/

format-check: ensure-rebrew
	$(UV_RUN) python -m ruff format --check src/ tests/ tools/

# The type gate.  The paths are the gate's [tool.mypy] files list, not
# a restatement of it: tests/ joins that list when its fixtures are
# annotated, and a second copy of the list here is one that drifts.
type-check: ensure-rebrew
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
regen-oxlint: ensure-rebrew ensure-bun
	bun install --frozen-lockfile
	$(UV_RUN) python tools/flatten_rikalabs_strict.py

smoke: ensure-rebrew
	$(UV_RUN) python tools/smoke.py

smoke-fail: ensure-rebrew
	$(UV_RUN) python tools/smoke.py --expect-failure

# The numbers docs/DESIGN.md and docs/USER_STORIES.md quote about the inlined
# shell move with every bundle rebuild, so the document points here rather than
# at a hand-copied figure.
payload-budget: ensure-rebrew
	$(UV_RUN) python tools/payload_budget.py

# The npm packages `make web-build` compiles into the shipped browser assets.
# The sbom job uploads it as an artifact; this is the same inventory to read
# without CI, and it needs no network and no environment, only bun.lock.
browser-sbom: ensure-rebrew
	$(UV_RUN) python tools/bundled_js_inventory.py

# Everything CI checks, in one local command, so nothing fails only after push.
all: format-check lint type-check shell-lint yaml-lint test web-lint typecheck-web \
	build check-bundle-clean browser-sbom smoke smoke-fail
	@printf '%s\n' 'all checks passed (CI: lint, web-lint, test, build, smoke)'

clean:
	rm -rf .pytest_cache .pytest-tmp .ruff_cache .mypy_cache .scratch build dist \
		src/recoverage.egg-info
	find src tests tools -type d -name __pycache__ -prune -exec rm -rf {} +
