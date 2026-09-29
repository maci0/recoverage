"""Tests for how the tree pins what it depends on.

rebrew is a path dependency, so the checkout that satisfies
`[tool.uv.sources]` is fetched by a script rather than resolved from a
registry. Nothing in the package code runs at test time to check that fetch,
so these pin the invariants a pin can break without any code changing: two
mechanisms that disagree about which rebrew is the dependency, a Makefile
whose pin has drifted from the script CI runs, a runner toolchain version
that has drifted from the manifest that declares it, and a checked-in copy
of a third-party preset whose license and origin are no longer recorded.
"""

from __future__ import annotations

import ast
import base64
import importlib.metadata
import importlib.util
import json
import re
import sys
import tomllib
from itertools import pairwise
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_CI_YML = _ROOT / ".github" / "workflows" / "ci.yml"
_CLONE_SCRIPT = _ROOT / "tools" / "ci_clone_rebrew.sh"
_MAKEFILE = _ROOT / "Makefile"
_README = _ROOT / "README.md"
_PACKAGE_JSON = _ROOT / "package.json"
_BUN_LOCK = _ROOT / "bun.lock"
_MANIFEST = _ROOT / "pyproject.toml"
_TSCONFIG = _ROOT / "web" / "tsconfig.json"
# The two update bots. Renovate reads the Python and JavaScript manifests,
# Dependabot the action pins; tests/test_supply_chain.py holds the split.
_RENOVATE = _ROOT / "renovate.json"
_DEPENDABOT = _ROOT / ".github" / "dependabot.yml"
_PYTHON_VERSION = _ROOT / ".python-version"
_FLATTEN = _ROOT / "tools" / "flatten_rikalabs_strict.py"
_DERIVED_PRESET = _ROOT / "tools" / "oxlint" / "rikalabs-strict.json"
# Third-party code copied into the repo, and the record of what that copy is.
_VENDOR_TREE = _ROOT / "tools" / "oxlint" / "anti-slop"
_VENDOR_MANIFEST = _ROOT / "tools" / "oxlint" / "anti-slop.manifest.json"
# The one place a CI job may fetch the sibling. A job may not clone rebrew
# itself, and the action may not carry a pin: tools/ci_clone_rebrew.sh owns it.
_SIBLING_ACTION = _ROOT / ".github" / "actions" / "sibling-rebrew" / "action.yml"

# Declared distributions that are correct without ever appearing in an import
# statement, and the mechanism that runs them instead. Every entry needs a
# reason: an unexplained one is how a genuinely stale declaration survives.
_CLI_ONLY = {
    "mypy": "the type gate invokes it as `python -m mypy`, never imports it",
    "ruff": "the lint gate invokes it as `python -m ruff`, never imports it",
    "pytest-playwright": "a pytest plugin, loaded by entry point, that only supplies fixtures",
}

# The same for devDependencies, which reach the build without an import: a bin
# on a script's command line, a `types` entry the type checker resolves, or a
# file under node_modules a build step names. Same rule, same reason each.
_JS_CLI_ONLY = {
    "oxlint": "the `oxlint` binary the lint:js script runs",
    "vite": "the `vite` binary the build:web and dev:web scripts run",
    "typescript": "the `tsc` binary the typecheck:web script runs",
    "@types/node": "the `node` entry in web/tsconfig.json's `types` array",
    "vnu-jar": "tools/lint_html.py runs node_modules/vnu-jar/build/dist/vnu.jar under java",
    "@rikalabs/oxlint-standards": (
        "tools/flatten_rikalabs_strict.py reads its preset, and oxlint.config.ts "
        "names the plugin under node_modules"
    ),
    "@shadcn/lint": (
        "oxlint.config.ts names node_modules/@shadcn/lint/dist/index.js as the "
        "`shadcn` JS plugin the lint:js script loads"
    ),
}

# A module specifier in a JS, TS or CSS source: `from "x"`, `import "x"`,
# `import("x")`, `require("x")`, or a stylesheet's `@import "x"`.
_JS_SPECIFIER_RE = re.compile(
    r"""(?:\bfrom|\bimport|\brequire)\s*\(?\s*["'](?P<module>[^"']+)["']|@import\s+["'](?P<css>[^"']+)["']"""
)

# A CI job header: two spaces, a name, a colon, and nothing else on the line.
_JOB_RE = re.compile(r"^  (?P<name>[a-z][a-z0-9-]*):$", re.MULTILINE)
# A job step that reaches the pinned script: the composite action, which
# calls it, or a direct `run:` of the script itself.
_ACTION_USE_RE = re.compile(r"\.github/actions/sibling-rebrew|tools/ci_clone_rebrew\.sh")
_PINS = {"REBREW_REF": "v2.16.0", "REBREW_SHA": "c9064a4dd5f23aa7a82ac96ca2a70c5ff629c6d4"}
# How a job names the composite action that fetches the sibling checkout.
_SIBLING_ACTION_STEP = "uses: ./.github/actions/sibling-rebrew"

# The test modules [tool.mypy] `files` does not name, and what each one is
# waiting on. This is the deferral list, not an approval: a module is here
# because it does not pass the gate yet, and the reason says which finding
# keeps it out. Every entry is one a `make test-one` pass can retire, and
# retiring one means deleting its line here. A new test module cannot join
# tests/ without a decision, because this dict and the gate have to agree
# (TestPythonAnalysisIsEnforced::test_a_new_test_module_cannot_join_untyped).
_UNTYPED_TEST_MODULES = {
    "test_api.py": "untyped WSGI request helpers and a read that cannot be narrowed",
    "test_build.py": "sdist and wheel helpers that hand back untyped values",
    "test_cli.py": "stub buffers passed where the stdlib declares a concrete buffer type",
    "test_config.py": "a PurePosixPath handed to a reader declared to take a Path",
    "test_fuzz.py": "a campaign whose token lists and status arguments vary per surface",
    "test_lifecycle.py": "monkeypatched attributes on rebrew's modules, which carry no py.typed",
    "test_metrics.py": "hand-built log records and counter dicts standing in for the real ones",
    "test_perf.py": "counting stand-ins installed over module-level functions",
    "test_playwright.py": "playwright ships no py.typed, so every page object is Any",
    "test_potato.py": "direct writes into the private grid cache and unannotated helpers",
    "test_release.py": "re.Match results indexed without the None arm",
    "test_serve_harness.py": "a tools/ module imported off sys.path, whose return is Any",
    "test_server.py": "the largest module in the suite; its fixtures are not annotated yet",
    "test_supply_chain.py": "TOML and JSON documents read into bare dicts, which strict rejects",
}


def _bun_lock() -> dict:
    """bun.lock parsed, which is JSONC rather than the JSON bun.lock claims to be.

    Every entry block ends with a trailing comma, so `json.loads` rejects the
    file outright. Only the commas before a closing brace or bracket are
    removed; nothing else is rewritten, so a syntax bun ever adds beyond that
    fails these tests loudly instead of being skipped.
    """
    text = re.sub(r",(\s*[}\]])", r"\1", _BUN_LOCK.read_text(encoding="utf-8"))
    return json.loads(text)


def _jobs() -> dict[str, str]:
    """Workflow text per job name, so a check is scoped to the job that needs it.

    Each job runs to the next header, and the last one to the end of the file:
    `pairwise` alone would key the final job under the name of the job before
    it, and bound its text where the last one starts, so a check scoped to the
    final job would find nothing to read.
    """
    text = _CI_YML.read_text(encoding="utf-8")
    starts = [(m.group("name"), m.start()) for m in _JOB_RE.finditer(text)]
    ends = [end for _, (_, end) in pairwise(starts)] + [len(text)]
    return {name: text[start:end] for (name, start), end in zip(starts, ends, strict=True)}


def _vendor_manifest_module() -> ModuleType:
    """`tools/vendor_manifest.py`, imported so the tree has one definition of
    what it records.  `tools/` is a script directory rather than a package, so
    the loader is how a test reaches in.
    """
    path = _ROOT / "tools" / "vendor_manifest.py"
    spec = importlib.util.spec_from_file_location("vendor_manifest", path)
    assert spec and spec.loader, "tools/vendor_manifest.py is not importable"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _default(text: str, var: str) -> str:
    """The default value of `${VAR:-default}` (shell) or `VAR ?= default` (make)."""
    shell = re.search(rf'^{var}="\$\{{{var}:-([^}}]+)\}}"', text, re.MULTILINE)
    if shell:
        return shell.group(1)
    make = re.search(rf"^{var} \?= (\S+)", text, re.MULTILINE)
    assert make, f"{var} has no default in the file"
    return make.group(1)


class TestRbrewPin:
    def test_ci_populates_the_sibling_only_through_the_pinned_script(self) -> None:
        """Every installing job materializes the sibling rebrew, one way only.

        A second mechanism (an inline `git clone`, or a step or action
        carrying its own ref) fetches the same path dependency from a pin
        nothing else checks, and whichever runs last silently decides which
        rebrew the suite tested. The script is that single mechanism: it holds
        the tag and commit, `make clone-rebrew` runs it, and every job reaches
        it through the `.github/actions/sibling-rebrew` composite action, which
        exists to be the one place a job may run the script and takes the
        clone URL but not the ref and sha. The chain is one link long.
        """
        installing = {n: b for n, b in _jobs().items() if "uv sync" in b}
        assert installing, "no CI job runs uv sync; the check below would pass vacuously"
        for name, body in installing.items():
            assert _SIBLING_ACTION_STEP in body, (
                f"job {name} never materializes the sibling checkout"
            )
            assert "tools/ci_clone_rebrew.sh" not in body, (
                f"job {name} runs the clone script itself; the action is its only caller"
            )
            assert not re.search(r"git clone.*rebrew", body), f"job {name} clones rebrew itself"
            for var in _PINS:
                assert var not in body, f"job {name} carries {var}; the script owns the pin"

    def test_the_sibling_action_carries_no_pin(self) -> None:
        """The action is a caller, not a second place to write the pin.

        A `ref`/`sha` input on the action would restore the moving commit the
        script's tag-and-SHA check exists to reject, so the action may only
        pass through a clone URL.
        """
        action = _SIBLING_ACTION.read_text(encoding="utf-8")
        assert "tools/ci_clone_rebrew.sh" in action, "the action no longer runs the pinned script"
        for var in _PINS:
            assert var not in action, f"the action carries {var}; the script owns the pin"
        inputs = action.split("inputs:", 1)[1].split("runs:", 1)[0] if "inputs:" in action else ""
        assert "ref" not in inputs and "sha" not in inputs.lower(), (
            "the action takes a ref/sha input; that is a second pin"
        )

    def test_the_sibling_checkout_is_cached_on_the_script_that_pins_it(self) -> None:
        """The destination is restored from a cache the pin invalidates.

        Every job that runs `uv sync` materializes the same commit, so a run
        cloned it once per job: eight identical network round trips, each with
        the script's three attempts behind it, for a tree that is the same
        every time. The key hashes `tools/ci_clone_rebrew.sh`, so the cache
        holds exactly the commit the script pins and a pin bump misses it.

        There is deliberately no `restore-keys` fallback: an older rebrew that
        still resolves is the dependency failure the tag-and-commit check
        exists to catch, and a cache that can serve it reopens exactly that
        hole. The key is a hash of the script, so it carries no pin of its own.
        """
        action = _SIBLING_ACTION.read_text(encoding="utf-8")
        assert "actions/cache@" in action, "the sibling checkout is not cached"
        cache = re.search(r"uses: actions/cache@[^\n]*\n(?P<block>(?:\s{4,}[^\n]*\n)+)", action)
        assert cache, "the action's cache step has no block to read"
        block = cache.group("block")
        assert "hashFiles('tools/ci_clone_rebrew.sh')" in block, (
            "the cache key does not hash the script; a pin bump would restore the old rebrew"
        )
        assert "restore-keys" not in block, (
            "the sibling cache has a fallback key; an older rebrew is the failure the pin catches"
        )
        for var in _PINS:
            assert var not in block, f"the sibling cache key carries {var}; the script owns the pin"

    def test_a_destination_already_at_the_pin_is_kept(self) -> None:
        """A restored or already-cloned checkout is not re-cloned, and is verified first.

        The cache restore puts the destination on disk before the script runs,
        so without this the script would delete it and fetch the same commit
        over the network on every job, cache hit or miss. The accept path is
        the same test the clone is held to: HEAD has to be the pinned commit
        and the tree has to be clean, so a stale cache entry falls through to
        the clone rather than being served as the pin.
        """
        script = _CLONE_SCRIPT.read_text(encoding="utf-8")
        accept = re.search(
            r'if \[ -e "\$\{dest\}/\.git" \]; then\n(?P<block>(?:(?!^fi$)[^\n]*\n)*)^fi$',
            script,
            re.MULTILINE,
        )
        assert accept, "the script has no already-at-the-pin path"
        block = accept.group("block")
        assert 'have_sha}" = "${REBREW_SHA}"' in block, (
            "the accept path does not compare HEAD against the pinned commit"
        )
        assert "status --porcelain" in block, (
            "the accept path keeps a checkout with uncommitted changes in it"
        )
        assert block.index("have_sha") < block.index("exit 0"), (
            "the accept path exits before it has checked the commit"
        )

    def test_the_sibling_action_only_runs_the_script(self) -> None:
        """The composite action is a wrapper, not a second pin.

        It exists because every job needs the same step and a job body cannot
        reference a sibling path reliably; the pin must not move into it, and
        the script it calls must be the one `make clone-rebrew` runs.
        """
        action = _SIBLING_ACTION.read_text(encoding="utf-8")
        assert "tools/ci_clone_rebrew.sh" in action, "the action no longer calls the pinned script"
        assert not re.search(r"git clone", action), "the action clones rebrew itself"
        for var in _PINS:
            assert var not in action, f".github/actions/sibling-rebrew: {var} is a second pin"
        other = [p for p in (_ROOT / ".github" / "actions").iterdir() if p.is_dir()]
        assert [p.name for p in other] == ["sibling-rebrew"], (
            f"another local action fetches the sibling: {[p.name for p in other]}"
        )

    def test_makefile_carries_no_pin_of_its_own(self) -> None:
        """The script is the only place the rebrew tag and commit are written.

        `make clone-rebrew REBREW_REF=...` still works: a command-line make
        variable is exported to the recipe's environment, where the script
        reads it. An empty `REBREW_REF ?=` line would only be a second
        mechanism that can never carry a value.
        """
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        for var in _PINS:
            assert not re.search(rf"^{var} \?=", makefile, re.MULTILINE), (
                f"Makefile: {var} is a second pin; the script owns it"
            )
        assert "tools/ci_clone_rebrew.sh" in makefile, (
            "`make clone-rebrew` no longer calls the script"
        )

    def test_script_pin_is_unchanged(self) -> None:
        """The tag and commit `make clone-rebrew` and CI both install."""
        script = _CLONE_SCRIPT.read_text(encoding="utf-8")
        for var, expected in _PINS.items():
            assert _default(script, var) == expected, f"tools/ci_clone_rebrew.sh: {var} moved"

    def test_the_declared_floor_is_the_version_the_script_clones(self) -> None:
        """The floor in the dependency metadata, the tag the script clones and
        the number the Makefile names in its preflight are the same version.

        `[project].dependencies` is what every install of the wheel reads, the
        script's `REBREW_REF` is what fills the path dependency it resolves to,
        and `REBREW_FLOOR` is what `make setup` tells a contributor the missing
        checkout has to be. The tag/commit pair is pinned by `_PINS` above, but
        the version the floor names was written in three places and nothing
        compared them: a rebrew release that raised the module this package
        needs raised the wheel's floor and left the Makefile naming a version
        whose preflight would then accept a checkout that has no
        `coverage_toml.py`, or the reverse.
        """
        declared = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["project"]["dependencies"]
        floors = [d.removeprefix("rebrew>=") for d in declared if d.startswith("rebrew>=")]
        assert len(floors) == 1, f"expected one rebrew floor in the dependencies, got {floors}"
        floor = floors[0]
        assert floor == _default(_CLONE_SCRIPT.read_text(encoding="utf-8"), "REBREW_REF").lstrip(
            "v"
        ), f"pyproject.toml needs rebrew>={floor}, the script clones a different tag"
        makefile_floor = _default(_MAKEFILE.read_text(encoding="utf-8"), "REBREW_FLOOR")
        assert floor == makefile_floor, (
            f"pyproject.toml declares rebrew>={floor}, the Makefile preflight names "
            f"{makefile_floor}"
        )

    def test_the_readme_install_section_carries_the_path_dependency(self) -> None:
        """The install a reader is told to run is one this tree can actually
        satisfy.

        `[tool.uv.sources]` resolves rebrew from a sibling checkout, so
        nothing an index can serve satisfies the wheel's `rebrew` dependency,
        and `pip install recoverage` stops at resolution. An install section
        that leads with it sends every reader to a resolver error, and the
        error names a distribution rather than the sibling checkout that is
        the actual fix. The section is what the packaged dependency points at,
        so the two are read together here.
        """
        manifest = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))
        sources = manifest["tool"]["uv"]["sources"]
        path_deps = {name for name, spec in sources.items() if "path" in spec}
        assert path_deps, "no dependency resolves from a path, so the check would pass vacuously"
        section = _README.read_text(encoding="utf-8").split("\n## Installation\n", 1)[1]
        section = section.split("\n## ", 1)[0]
        for name in path_deps:
            assert name in section, (
                f"the README install section does not mention {name}, the dependency it "
                f"resolves from {'/'.join(sources[name]['path'])}"
            )
        assert not re.search(r"^\s*(uv run )?pip install recoverage", section, re.MULTILINE), (
            "the install section offers `pip install recoverage` as a command, which cannot "
            f"resolve {sorted(path_deps)} while they resolve from a path"
        )

    def test_pinned_commit_is_a_full_sha(self) -> None:
        """A ref that is not a full object id cannot be checked for a moved tag."""
        sha = _default(_CLONE_SCRIPT.read_text(encoding="utf-8"), "REBREW_SHA")
        assert re.fullmatch(r"[0-9a-f]{40}", sha), f"REBREW_SHA {sha!r} is not a full commit id"

    def test_the_clone_url_is_written_once(self) -> None:
        """The script owns the URL, the way it owns the tag and the commit.

        The action used to carry the same URL as a default, which is a copy a
        moved repository leaves disagreeing: `make clone-rebrew` and CI would
        then fetch two different rebrews, and only the lock check would notice.
        The input stays, because a fork or a mirror is a legitimate thing to
        point elsewhere at; its default stays empty so the script's is the one
        that applies.
        """
        url = _default(_CLONE_SCRIPT.read_text(encoding="utf-8"), "REBREW_URL")
        assert url == "https://github.com/maci0/rebrew.git", f"the clone URL moved to {url!r}"
        inputs = _SIBLING_ACTION.read_text(encoding="utf-8").split("inputs:", 1)[1]
        default = re.search(r"^\s+default:\s*(\S+)\s*$", inputs.split("runs:", 1)[0], re.MULTILINE)
        assert default and default.group(1) in ('""', "''"), (
            "the clone-url input grew a default; the URL belongs to the script"
        )

    def test_no_other_file_restates_the_pin(self) -> None:
        """One place writes the tag, the commit and the URL, and it is the script.

        Every other copy is a value the bump would have to reach: the composite
        action's input default, a Makefile line, or a sentence in a document
        telling a contributor which rebrew to clone. A copy that is missed
        sends CI and a workstation to two different rebrews, or sends a reader
        to a commit the script no longer accepts. A document says where the
        pin lives instead.
        """
        script = _CLONE_SCRIPT.read_text(encoding="utf-8")
        pins = {name: _default(script, name) for name in (*_PINS, "REBREW_URL")}
        for name, value in pins.items():
            assert value in script, f"tools/ci_clone_rebrew.sh no longer holds {name}"
        skipped = {
            ".git",
            "node_modules",
            ".venv",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
            ".pytest-tmp",
            ".scratch",
            ".gauntlet",
        }
        for path in sorted(_ROOT.rglob("*")):
            if not path.is_file() or set(path.relative_to(_ROOT).parts) & skipped:
                continue
            if path in (_CLONE_SCRIPT, Path(__file__).resolve(), _BUN_LOCK, _ROOT / "uv.lock"):
                continue
            if path.suffix in {".png", ".ico", ".db", ".pyc"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for name, value in pins.items():
                assert value not in text, f"{path.relative_to(_ROOT)} restates {name} ({value})"

    def test_ci_uv_version_matches_the_makefile(self) -> None:
        """uv runs every install, lint and test, so the runner pins it too.

        setup-uv takes no version file, so the workflow has to name a version
        and that literal is a second copy of the Makefile's UV_VERSION. An
        unpinned installer is worse than the duplication: two runs of one
        commit resolve and cache differently. This test is the tie, so a bump
        is two edits the next run refuses to let disagree.
        """
        steps = re.findall(
            r"- uses: astral-sh/setup-uv@[^\n]*\n(?P<block>(?:\s{8,}[^\n]*\n)+)",
            _CI_YML.read_text(encoding="utf-8"),
        )
        assert steps, "no job sets up uv"
        for block in steps:
            pinned = re.search(r'^\s+version:\s*"([^"]+)"', block, re.MULTILINE)
            assert pinned, "a setup-uv step installs an unpinned uv"
            assert pinned.group(1) == _default(
                _MAKEFILE.read_text(encoding="utf-8"), "UV_VERSION"
            ), "ci.yml installs a different uv than the Makefile's UV_VERSION"


class TestActionsArePinned:
    """Every third-party action is a commit, not a tag, and says which tag.

    A mutable `@v7` resolves to whatever the publisher's release branch points
    at, so a run of one commit can execute different code than the run before
    it, and a compromised tag is indistinguishable from a normal bump. The
    workflows already pin by SHA; nothing read them to keep it that way, so
    the pinning held only as long as every author remembered it.

    The trailing `# vX.Y.Z` comment is part of the contract, not decoration:
    a bare SHA is unreviewable, and dependabot rewrites the ref while leaving
    the comment, so a bump that stops naming the tag it came from is caught
    here instead of in a diff nobody can check.
    """

    _USE_RE = re.compile(
        r"^\s*-?\s*uses:\s*(?P<action>[^@\s]+)@(?P<ref>[^\s#]+)"
        r"(?:\s*#\s*(?P<comment>.*))?$",
        re.MULTILINE,
    )
    _SHA_RE = re.compile(r"^[0-9a-f]{40}$")
    _TAG_COMMENT_RE = re.compile(r"^v\d+(\.\d+)*(-[\w.]+)?$")

    def _action_files(self) -> list[Path]:
        workflows = sorted((_ROOT / ".github" / "workflows").glob("*.y*ml"))
        actions = sorted((_ROOT / ".github" / "actions").glob("*/action.y*ml"))
        assert workflows, "no workflow to check"
        return [*workflows, *actions]

    def _uses_steps(self, path: Path) -> list[re.Match[str]]:
        """Every `uses:` line in *path* the pattern recognizes.

        A local composite action declares none, so the count is not asserted
        per file: both gates below iterate what this returns, and a reformat
        that leaves the pattern matching nothing would skip every assertion
        in the loop and report a pin gate that checked nothing. The callers
        therefore count what they inspected.
        """
        return list(self._USE_RE.finditer(path.read_text(encoding="utf-8")))

    def test_every_action_resolves_to_a_commit(self) -> None:
        third_party = 0
        for path in self._action_files():
            for match in self._uses_steps(path):
                action, ref = match["action"], match["ref"]
                if action.startswith("./"):
                    continue
                where = f"{path.relative_to(_ROOT)}: {action}"
                assert self._SHA_RE.match(ref), f"{where} uses {ref!r}, not a 40-hex commit"
                comment = (match["comment"] or "").strip()
                assert self._TAG_COMMENT_RE.match(comment), (
                    f"{where} pins {ref[:12]} without naming the tag it came from"
                )
                third_party += 1
        assert third_party >= 3, f"only {third_party} third-party actions were pinned"

    def test_the_checkout_token_does_not_outlive_the_checkout(self) -> None:
        """`persist-credentials: false` on every checkout, in every workflow.

        checkout otherwise leaves the job's GITHUB_TOKEN in `.git/config`, and
        every step in this pipeline runs project code (pytest, tools/smoke.py,
        bun) that could read it off disk. No job pushes, so nothing needs it
        after the tree lands.
        """
        checkouts = 0
        for path in self._action_files():
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if not re.match(r"^\s*-?\s*uses:\s*actions/checkout@\S", line):
                    continue
                # The `with:` mapping is the lines indented past the step, so a
                # checkout with no mapping at all is an empty window rather
                # than a skipped step: dropping the key must fail here too.
                indent = len(line) - len(line.lstrip())
                block = [line]
                for follower in lines[index + 1 :]:
                    if not follower.strip() or len(follower) - len(follower.lstrip()) <= indent:
                        break
                    block.append(follower)
                assert any("persist-credentials: false" in b for b in block), (
                    f"{path.relative_to(_ROOT)}: a checkout keeps the job token in .git/config"
                )
                checkouts += 1
        # Every workflow that checks the tree out is covered above; a count
        # proves the pattern still finds those steps rather than skipping them.
        assert checkouts, "no actions/checkout step was found to check"


class TestEnvironmentInstalls:
    """Every environment is installed from uv.lock, and the lock is checked.

    `--frozen` and `--locked` both refuse to write a new lockfile, which is
    the property the pipeline was built around. Only `--locked` also refuses
    to install a lockfile that no longer matches pyproject.toml: under
    `--frozen` a dependency edit that skipped `uv lock` installs the old tree
    and the run is green, so the suite tests a package the manifest does not
    describe. The one job that may not use it is `sbom`, which is the one job
    with no sibling checkout to resolve the path dependency against. These
    read the files rather than running uv, so the check on whether uv.lock is
    current stays where the hermetic suite does not reach: the pipeline.
    """

    def test_ci_installs_with_locked_not_frozen(self) -> None:
        commands = [
            line
            for line in _CI_YML.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#") and re.search(r"\buv (sync|run|export)\b", line)
        ]
        assert commands, "ci.yml runs no uv command; this check would pass vacuously"
        for line in commands:
            flags = " ".join(line.split())
            if "uv export" in flags:
                continue
            assert "--locked" in flags, f"ci.yml installs without --locked: {flags}"
            assert "--frozen" not in flags, f"ci.yml installs with --frozen: {flags}"

    def test_the_sbom_export_stays_frozen(self) -> None:
        """`--locked` re-resolves, and `sbom` is the job without a sibling.

        Reading the lock alone is the point of that job: the path dependency
        `../rebrew` does not exist on the runner that runs it, so the one
        invocation that has to stay `--frozen` is pinned here rather than
        left to a reader to work out. The job reaches the export through
        `make python-sbom`, so the flag lives in the Makefile, and the one
        `uv export` in the tree is the Makefile's.
        """
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        exports = [
            " ".join(line.split())
            for line in makefile.splitlines()
            if re.match(r"\s*uv export\b", line)
        ]
        assert len(exports) == 1, f"expected one uv export, found {exports}"
        assert "--frozen" in exports[0] and "--locked" not in exports[0], exports[0]
        exports_in_ci = [
            " ".join(line.split())
            for line in _CI_YML.read_text(encoding="utf-8").splitlines()
            if "uv export" in line and not line.lstrip().startswith("#")
        ]
        assert not exports_in_ci, (
            f"ci.yml spells its own uv export beside the Makefile's: {exports_in_ci}"
        )

    def test_the_makefile_installs_the_same_way(self) -> None:
        """`make all` is the local mirror of CI, down to the uv flag."""
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        for line in ("UV_SYNC_FLAGS ?=", "UV_RUN :="):
            declaration = re.search(rf"^{re.escape(line)}.*$", makefile, re.MULTILINE)
            assert declaration, f"Makefile no longer defines {line}"
            assert "--locked" in declaration.group(0), declaration.group(0)
            assert "--frozen" not in declaration.group(0), declaration.group(0)

    def test_every_makefile_uv_install_is_locked(self) -> None:
        """A recipe that spells `uv sync` out is covered, not just the two
        variables every other recipe reads.

        `test-browser` runs its own `uv sync` for the playwright extra, and
        the declaration checks above never saw it. A recipe that goes through
        `$(UV_SYNC_FLAGS)` or `$(UV_RUN)` is covered by those declarations;
        only a spelled-out invocation needs the flag here.
        """
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        commands = [
            line
            # Anchored at the start of the line: an invocation is what a recipe
            # runs, while `help` and the preflight's `echo` only name one.
            for line in makefile.splitlines()
            if re.match(r"\s*uv (sync|run)\b", line)
            and "$(UV_SYNC_FLAGS)" not in line
            and "$(UV_RUN)" not in line
        ]
        assert commands, "Makefile runs no uv command; this check would pass vacuously"
        for line in commands:
            flags = " ".join(line.split())
            assert "--locked" in flags, f"Makefile installs without --locked: {flags}"
            assert "--frozen" not in flags, f"Makefile installs with --frozen: {flags}"

    def test_the_python_inventory_is_reproducible_without_ci(self) -> None:
        """The sbom job's Python half has a local command, like its browser half.

        `make browser-sbom` is the local mirror of one of the two artifacts the
        job uploads; without a target for the other, the resolved Python tree
        behind a release could only be reproduced by the job that produced it.
        The job runs that target rather than a second copy of its export, so
        the artifact a release ships and the one a contributor prints are one
        command. `--frozen` is what lets it run where the job runs, without the
        sibling checkout a `--locked` re-resolve would need.
        """
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        exports = [
            " ".join(line.split())
            for line in makefile.splitlines()
            if re.match(r"\s*uv export\b", line)
        ]
        assert len(exports) == 1, f"expected one uv export in the Makefile, found {exports}"
        assert "--frozen" in exports[0] and "--locked" not in exports[0], exports[0]
        assert "--all-extras" in exports[0] and "--hashes" in exports[0], exports[0]
        assert re.search(r"^python-sbom:", makefile, re.MULTILINE), (
            "the Makefile no longer defines the target that runs the export"
        )
        assert re.search(r"^all:.*\bpython-sbom\b", makefile, re.MULTILINE | re.DOTALL), (
            "`make all` does not depend on python-sbom, so it is not the local mirror of CI"
        )
        job = _jobs()["sbom"]
        assert "make python-sbom" in job, (
            "the sbom job no longer produces its artifact through `make python-sbom`, so "
            "the file a release ships and the file `make python-sbom` prints are two "
            "commands that can drift"
        )

    def test_every_package_json_uv_run_keeps_the_dev_extra(self) -> None:
        """A `uv run` outside the Makefile re-syncs the environment, so it
        has to name the same extras the environment was built with.

        `lint:html` runs a Python tool from a bun script, so it is outside
        every Makefile recipe and the checks above never saw it. `uv run`
        syncs `.venv` to what its own flags ask for and uninstalls the rest,
        so the invocation without `--extra dev` left `make web-lint` ending
        with pytest, ruff and mypy removed from the environment, and the next
        `make test` or `make lint` reinstalling them before it ran a line.
        """
        scripts = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["scripts"]
        commands = [
            f"{name}: {command}" for name, command in scripts.items() if "uv run" in command
        ]
        assert commands, "package.json runs no uv command; this check would pass vacuously"
        for line in commands:
            flags = " ".join(line.split())
            assert "--locked" in flags, f"package.json runs uv without --locked: {flags}"
            assert "--frozen" not in flags, f"package.json runs uv with --frozen: {flags}"
            assert "--extra dev" in flags, (
                f"package.json runs uv without --extra dev, so it re-syncs the "
                f"environment and uninstalls the dev tools: {flags}"
            )


class TestToolchainPins:
    """The runner toolchain CI installs is read from the file that owns it.

    Both actions resolve their version from the tree (`.python-version`,
    package.json's packageManager) instead of a copy written into the
    workflow, the same one-pin rule the rebrew clone follows. A test fails
    when a literal version comes back, because a second pin is what a bump
    would have to touch and nobody would remember to.
    """

    def test_the_linux_runner_image_is_named_not_followed(self) -> None:
        """`ubuntu-latest` is a moving label, so no job may name it.

        Every other input the pipeline reads is pinned in the tree: uv by
        version, Python by .python-version, bun by package.json, every action
        by commit, rebrew by tag and sha. The runner image was the one left to
        the host, and it is where the tools nothing in the tree declares come
        from: `shellcheck` and `yamllint` (the lint job's shell and Actions
        gates) and `diffoscope` (the build job's reproducibility diagnostic).
        A fleet update could add a rule, drop one, or remove a tool, and the
        same commit would lint differently on two runs or fail a gate that was
        green a week earlier. Pinning the label is the same decision as an
        action pin and is reviewed the same way.

        The macOS and Windows matrix entries keep their floating labels: they
        exist to exercise the claim that the suite runs on all three, they run
        no pinned tool out of the image, and a version label there would be
        swapped on a schedule this tree does not own.
        """
        for path in sorted((_ROOT / ".github" / "workflows").glob("*.y*ml")):
            for line in path.read_text(encoding="utf-8").splitlines():
                # A comment can name the label it forbids, so only the part
                # of the line the runner reads is checked.
                label = re.search(r"ubuntu[-\w.]*", line.split("#", 1)[0])
                if label is None:
                    continue
                image = label.group(0)
                where = f"{path.relative_to(_ROOT)}: {image}"
                assert not image.endswith("-latest"), (
                    f"{where} follows the runner fleet; name the image version"
                )
                assert re.fullmatch(r"ubuntu-\d\d\.\d\d", image), (
                    f"{where} is not a versioned image label"
                )

    def test_flatten_script_does_not_pin_an_oxlint_version(self) -> None:
        """The preset flattener reads the oxlint version, it does not restate it.

        It names the version in the note beside every dropped rule, so a
        constant there outlives the bump it describes: the script keeps
        reporting the preset was flattened against an oxlint the tree no
        longer installs, which is the one claim a reader cannot check.
        """
        flatten = _FLATTEN.read_text(encoding="utf-8")
        dev = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["devDependencies"]
        oxlint = dev["oxlint"]
        assert f'"{oxlint}"' not in flatten, (
            f"tools/flatten_rikalabs_strict.py restates oxlint {oxlint}; package.json owns it"
        )

    def test_ci_bun_version_comes_from_package_json(self) -> None:
        """setup-bun reads the bun package.json declares, not a copy of it."""
        declared = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["packageManager"]
        assert re.fullmatch(r"bun@\S+", declared), f"unreadable packageManager: {declared!r}"
        ci = _CI_YML.read_text(encoding="utf-8")
        assert "bun-version-file: package.json" in ci, (
            "the web-lint job does not take its bun version from package.json"
        )
        assert not re.search(r'^\s+bun-version:\s*"', ci, re.MULTILINE), (
            "ci.yml carries a second bun pin; package.json owns it"
        )

    def test_ci_python_version_comes_from_the_version_file(self) -> None:
        """setup-python reads .python-version, the interpreter uv builds from.

        The one exception is the test job, whose version comes from the matrix
        so the matrix can vary it; that step names no interpreter of its own.
        """
        ci = _CI_YML.read_text(encoding="utf-8")
        setups = ci.count("uses: actions/setup-python@")
        assert setups, "no job sets up Python"
        resolved = ci.count("python-version-file: .python-version") + len(
            re.findall(r"python-version:\s*\$\{\{", ci)
        )
        assert resolved == setups, (
            "a setup-python step names an interpreter instead of reading .python-version"
        )

    def test_matrix_floor_is_the_pinned_interpreter(self) -> None:
        """A literal in the matrix names the floor, so it must match the pin.

        The matrix expression itself is exempt: it varies by design. The
        literals under `include` are the non-Linux runners, which test the
        floor, so a bump that missed them would run them on an interpreter
        the project no longer claims.
        """
        pinned = _PYTHON_VERSION.read_text(encoding="utf-8").strip()
        literals = set(
            re.findall(r'python-version:\s*"([^"]+)"', _CI_YML.read_text(encoding="utf-8"))
        )
        assert literals, "the matrix pins no interpreter by hand"
        assert literals == {pinned}, (
            f"ci.yml names {sorted(literals)}, .python-version pins {pinned}"
        )

    def test_test_matrix_matches_the_python_classifiers(self) -> None:
        """The versions CI tests are the versions the manifest advertises."""
        project = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["project"]
        claimed = {
            line.rsplit(" ", 1)[1]
            for line in project["classifiers"]
            if line.startswith("Programming Language :: Python :: 3.")
        }
        assert claimed, "pyproject.toml claims no 3.x Python classifier"
        matrix = re.search(r"python-version:\s*\[([^\]]+)\]", _CI_YML.read_text(encoding="utf-8"))
        assert matrix, "the test job has no python-version matrix"
        tested = set(re.findall(r'"([^"]+)"', matrix[1]))
        assert tested == claimed, (
            f"the matrix tests {sorted(tested)}, pyproject.toml claims {sorted(claimed)}"
        )

    def test_every_shell_script_declares_its_interpreter(self) -> None:
        """Every tools/*.sh names the shell it is written for.

        shellcheck reports a script with neither a shebang nor a
        `# shellcheck shell=` directive as SC2148, which is what `make
        shell-lint` runs. It is an optional host tool, so on a checkout
        without it the only gate is the CI lint job, one push after the
        edit; the suite is not optional and runs in the edit-test loop.
        """
        scripts = sorted((_ROOT / "tools").glob("*.sh"))
        assert scripts, "tools/*.sh is empty; the clone script is gone?"
        without = [p.name for p in scripts if not p.read_text(encoding="utf-8").startswith("#!")]
        assert not without, (
            f"tools/{', tools/'.join(without)} has no shebang: "
            "SC2148 fails 'make shell-lint' and the CI lint job"
        )

    def test_the_hash_seed_is_pinned_where_the_interpreter_starts(self) -> None:
        """A replay is only byte-for-byte if `hash()` of a str is a fixed value.

        CPython seeds the str hash from the environment once, at interpreter
        startup, so a `set` or `frozenset` iterates in a different order in
        every process. Every value that reaches an assertion, a served payload
        or a log line through an unsorted collection is then a coin flip, and
        two runs of one seed cannot be diffed against each other, which is the
        property the whole suite is read through. Pinning the seed does not
        make the collections sorted; it makes their order a function of the
        values alone, so a leak is a defect to find rather than noise to
        re-run.

        The value has to be in the environment, which is why this is not a
        conftest fixture: the seed is read before any import this tree
        controls, so a value set once pytest is running is ignored. Two places
        therefore declare it, and they have to agree: the Makefile exports it
        to every local recipe, and the test job spells its pytest command out
        because the Windows runner has no make.  The sbom job is the other
        workflow job that starts an interpreter with no recipe to export it.
        """
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        declared = re.search(r"^PYTHON_HASH_SEED \?= (\S+)$", makefile, re.MULTILINE)
        assert declared, "the Makefile no longer declares PYTHON_HASH_SEED"
        seed = declared.group(1)
        assert "export PYTHONHASHSEED := $(PYTHON_HASH_SEED)" in makefile, (
            "the Makefile declares the seed without exporting it, so no recipe sees it"
        )
        ci = _CI_YML.read_text(encoding="utf-8")
        pinned = set(re.findall(r'PYTHONHASHSEED:\s*"([^"]+)"', ci))
        assert pinned == {seed}, (
            f"ci.yml pins {sorted(pinned) or 'nothing'}, the Makefile exports {seed}"
        )
        # The job that runs the suite must be one of them: a seed pinned on a
        # job that never starts Python is a comment, not a pin.
        job = re.search(
            r"name: Run the suite\n(?:.*\n)*?\s*uv run[^\n]*pytest",
            ci,
        )
        assert job, "the test job's pytest step is gone"
        assert "PYTHONHASHSEED" in job.group(0) or pinned, "the suite runs unpinned"
        # The other interpreter this workflow starts itself, rather than
        # through a make recipe that exports the seed: the sbom job's browser
        # inventory, whose output is an uploaded artifact.  Matching a
        # `python ` line rather than naming the job keeps this catching a
        # third such step instead of pinning the one that exists today, and it
        # does not match the test job, whose command line starts with `uv run`
        # and is covered by the check above.
        for name, text in _jobs().items():
            if re.search(r"^\s+python \S", text, re.MULTILINE):
                assert "PYTHONHASHSEED" in text, (
                    f"the {name} job starts a Python interpreter without the pinned seed"
                )


class TestFrontendAnalysisIsEnforced:
    """Every frontend analyzer package.json declares is run by something.

    `bun run typecheck:web` (tsc --noEmit) is the tree's only type check, and
    oxlint cannot substitute for it: the Rika-Labs preset is flattened with
    typeAware: false, so strict, noUncheckedIndexedAccess and
    exactOptionalPropertyTypes are verified by that script alone. A script no
    target runs is a setting nobody checks, and a type error reaches the
    committed bundle unremarked.
    """

    # `lint` chains the other two, so the check follows the references a
    # script makes rather than assuming the Makefile names each analyzer.
    _ANALYSIS_SCRIPTS = ("lint:js", "lint:html", "typecheck:web")

    @staticmethod
    def _target_running(makefile: str, script: str) -> str | None:
        """The Makefile target whose recipe runs `bun run <script>`, if any."""
        target = None
        for line in makefile.splitlines():
            if not line[:1].isspace():
                head = re.match(r"^([A-Za-z0-9_.%-]+):", line)
                if head:
                    target = head[1]
            elif f"bun run {script}" in line:
                return target
        return None

    @classmethod
    def _reached(cls, makefile: str, scripts: dict[str, str]) -> dict[str, str]:
        """Every script the Makefile reaches, and the target that reaches it.

        `bun run lint` chains lint:js and lint:html, so a script counts as run
        when a target invokes it or a script that target invokes. The walk
        follows only the scripts a target names, so it terminates on the
        package.json graph.
        """
        direct = {
            name: target for name in scripts if (target := cls._target_running(makefile, name))
        }
        reached = dict(direct)
        for name in tuple(direct):
            for chained in re.findall(r"bun run ([\w:-]+)", scripts[name]):
                reached.setdefault(chained, direct[name])
        return reached

    def test_every_analysis_script_has_a_target(self) -> None:
        scripts = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["scripts"]
        reached = self._reached(_MAKEFILE.read_text(encoding="utf-8"), scripts)
        for script in self._ANALYSIS_SCRIPTS:
            assert script in scripts, f"package.json no longer defines a {script} script"
            assert script in reached, (
                f"no Makefile target runs `bun run {script}`; it would never gate a merge"
            )

    def test_the_frontend_type_settings_stay_on(self) -> None:
        """`strict` is a floor, and the settings that make it a floor for this
        tree are only checked by the one script that reads this file.

        oxlint runs without type information (the Rika preset is flattened
        with typeAware: false), so a flag dropped here stops reporting
        anything, which is indistinguishable from a tree with no type error.
        Each of the five ran clean before it was written into tsconfig.json:
        a switch that falls through, a function that can reach the end
        without returning, a file spelled two ways on a case-insensitive
        filesystem, a label nothing jumps to, and unreachable code left
        behind a return.
        """
        options = json.loads(_TSCONFIG.read_text(encoding="utf-8"))["compilerOptions"]
        for flag in (
            "strict",
            "noUncheckedIndexedAccess",
            "exactOptionalPropertyTypes",
            "noImplicitReturns",
            "noFallthroughCasesInSwitch",
            "forceConsistentCasingInFileNames",
        ):
            assert options.get(flag) is True, f"web/tsconfig.json no longer sets {flag}"
        for flag in ("allowUnreachableCode", "allowUnusedLabels"):
            assert options.get(flag) is False, f"web/tsconfig.json no longer sets {flag}: false"

    def test_a_stale_disable_directive_fails_the_frontend_lint(self) -> None:
        """`oxlint-disable-next-line` is the frontend's `# noqa`, and it needs
        the same gate ruff gets from RUF100 and mypy from
        warn_unused_ignores: a directive whose rule no longer reports (the
        site moved, the plugin's rule changed, an override in
        oxlint.config.ts turned the rule off) silences nothing and keeps
        looking reviewed. Without --report-unused-disable-directives those
        three sat in the tree for the life of the file, and without
        --deny-warnings the report that finds them does not fail the run.
        """
        script = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["scripts"]["lint:js"]
        for flag in ("--deny-warnings", "--report-unused-disable-directives"):
            assert flag in script, f"package.json lint:js no longer passes {flag} to oxlint"

    def test_the_type_check_runs_in_make_all_and_in_ci(self) -> None:
        """The gate has to be somewhere a broken type stops a merge."""
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        target = self._target_running(makefile, "typecheck:web")
        assert target is not None, "no Makefile target runs the frontend type check"
        all_recipe = re.search(r"^all:(.*)$", makefile, re.MULTILINE)
        assert all_recipe and target in all_recipe[1].split(), (
            f"`make all` does not depend on {target}, so it is not the local mirror of CI"
        )
        assert f"make {target}" in _jobs()["web-lint"], (
            f"the web-lint job does not run `make {target}`"
        )


class TestPythonAnalysisIsEnforced:
    """The Python gates are configured strict AND the run is what enforces it.

    `TestFrontendAnalysisIsEnforced` covers the frontend half; this is the
    Python half, and it exists because a strict setting that is only described
    in a comment is one edit away from being off. Turning `strict` or
    `warn_unused_ignores` off does not fail a run: it stops reporting, which
    reads exactly like a clean tree. The reason each setting is on belongs in
    [tool.mypy]; the fact that it is still on belongs here.
    """

    @staticmethod
    def _mypy() -> dict:
        return tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["tool"]["mypy"]

    def test_mypy_stays_strict(self) -> None:
        assert self._mypy().get("strict") is True, (
            "`strict` is off in [tool.mypy]; the tree passes it, so a new module "
            "would silently inherit a weaker gate"
        )

    def test_a_type_ignore_that_silences_nothing_fails_the_run(self) -> None:
        """`warn_unused_ignores` is what keeps a suppression a checked claim.

        Without it a `# type: ignore` outlives the error it silenced: the
        annotation moves, the dependency ships `py.typed`, and the comment
        still hides whatever the line reports next.
        """
        assert self._mypy().get("warn_unused_ignores") is True, (
            "`warn_unused_ignores` is off in [tool.mypy], so a stale `type: "
            "ignore` never fails the gate"
        )

    def test_the_checks_strict_leaves_out_are_on(self) -> None:
        """`strict` is a preset, and two of the checks this tree can pass are
        not in it: warn_unreachable and strict_equality. Both find a defect
        (a branch the code cannot take, a literal compared with `is`), and
        both ran clean before they were written here. A preset is a floor,
        not a ceiling.
        """
        mypy = self._mypy()
        for check in ("warn_unreachable", "strict_equality"):
            assert mypy.get(check) is True, f"`{check}` is off in [tool.mypy]"

    def test_no_module_is_exempted_from_the_gate(self) -> None:
        """`strict` is one setting for the tree, so a per-module override is
        a hole in it that nothing else reads back.

        `files` already puts tools/ under the same gate as src/, and the tree
        passes it without an exception, so the one override in the manifest
        exempted the build scripts from the def-annotation check every other
        module is held to. A new override is a new finding written where the
        analyzer runs, where it reads as a settled fact.
        """
        relaxed = {
            table.get("module"): sorted(
                key for key, value in table.items() if key != "module" and value is False
            )
            for table in self._mypy().get("overrides", [])
        }
        assert not relaxed, (
            f"[tool.mypy] overrides switch checks off: {relaxed}; the finding that "
            "needed one is fixed with annotations, not with a weaker gate"
        )

    @staticmethod
    def _ruff() -> dict:
        return tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["tool"]["ruff"]["lint"]

    def test_an_assert_outside_the_suite_fails_the_run(self) -> None:
        """`python -O` strips an assert, so one in the request path is a check
        that silently stops existing: the server keeps answering, with the
        branch gone. S101 is on for src/ and tools/, and the suite is the one
        place that ignores it, because `assert` is how a test says what it
        believes.
        """
        assert "S101" in self._ruff()["select"], (
            "S101 is not selected in [tool.ruff.lint]; an assert under src/ or tools/ "
            "would pass the gate and vanish under `python -O`"
        )
        ignoring = sorted(
            path for path, codes in self._ruff()["per-file-ignores"].items() if "S101" in codes
        )
        assert ignoring == ["tests/*"], (
            f"S101 is ignored for {ignoring}; only the suite asserts by design, so an "
            "ignore anywhere else is a path that opted out of the check"
        )

    def test_a_new_test_module_cannot_join_untyped(self) -> None:
        """`files` is a gate with a hole in it, and the hole is the whole
        point of the exercise: the modules it does not name are unchecked, and
        nothing stopped a new one from being written that way.

        Every module under tests/ is therefore either in the gate or named in
        `_UNTYPED_TEST_MODULES` below, with the reason it is still out. A new
        test file is untyped by default, so without this the gate would ratchet
        the wrong way: each module added to the list is work, and a module
        added without it is silence. The list is checked both ways, so a
        module that joins the gate has to leave it here.
        """
        gated = {
            Path(entry).name
            for entry in self._mypy().get("files", [])
            if str(entry).startswith("tests/")
        }
        present = {path.name for path in (_ROOT / "tests").glob("*.py")}
        assert present - gated == set(_UNTYPED_TEST_MODULES), (
            "the test modules outside the mypy gate and the recorded remainder "
            f"disagree: {sorted(present - gated ^ set(_UNTYPED_TEST_MODULES))}; add the "
            "module to [tool.mypy] files, or record it below with its reason"
        )
        assert not gated - present, (
            f"[tool.mypy] files names test modules that are not in the tree: "
            f"{sorted(gated - present)}"
        )
        unreasoned = sorted(name for name, reason in _UNTYPED_TEST_MODULES.items() if not reason)
        assert not unreasoned, (
            f"these modules are outside the gate with no recorded reason: {unreasoned}; an "
            "unexplained entry is how a genuinely stale deferral survives"
        )

    def test_the_type_check_runs_in_the_lint_job(self) -> None:
        assert "make type-check" in _jobs()["lint"], (
            "the lint job does not run `make type-check`; a type error would reach main"
        )

    def test_the_lint_and_format_gates_run_in_the_lint_job(self) -> None:
        """A configured linter nothing runs is a missing linter."""
        job = _jobs()["lint"]
        for target in ("make lint", "make format-check", "make shell-lint", "make yaml-lint"):
            assert target in job, f"the lint job does not run `{target}`"


class TestCommittedBundleIsVerified:
    """The committed dashboard bundle is rebuilt by every packaging run.

    `make build` runs the bundler before `uv build`, so a wheel always carries
    the current sources, and the CI build job compares two such builds against
    each other. That comparison is over two trees built the same way, so it
    passed on a commit whose `assets/app.js` had not been rebuilt and committed:
    the only thing that can tell the committed bytes from a fresh build is the
    working tree they left behind.
    """

    def test_the_build_job_checks_the_tree_after_building(self) -> None:
        build = _jobs()["build"]
        check = build.find("make check-bundle-clean")
        assert check != -1, "the build job does not check the committed bundle"
        assert build.find("make build") < check, (
            "check-bundle-clean runs before the build it is supposed to judge"
        )

    def test_the_check_is_the_makefile_target_and_make_all_runs_it(self) -> None:
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        recipe = re.search(r"^check-bundle-clean:(.*?)(?=^\S)", makefile, re.MULTILINE | re.DOTALL)
        assert recipe, "the Makefile no longer defines check-bundle-clean"
        assert "git status --porcelain" in recipe.group(1), (
            "check-bundle-clean no longer reads the working tree the build left"
        )
        # Scoped to the built assets: a bare `git status` fails on whatever
        # else the contributor has in progress, which is a gate that reports
        # the wrong thing rather than a stale bundle.
        assert re.search(r"git status --porcelain -- \$\(BUNDLE_DIR\)", recipe.group(1)), (
            "check-bundle-clean reads the whole tree instead of the built assets"
        )
        assert re.search(r"^BUNDLE_DIR = src/recoverage/assets$", makefile, re.MULTILINE), (
            "BUNDLE_DIR no longer names the directory the bundler writes"
        )
        all_recipe = re.search(r"^all:(.*?)(?=^\S)", makefile, re.MULTILINE | re.DOTALL)
        assert all_recipe and "check-bundle-clean" in all_recipe.group(1), (
            "`make all` does not depend on check-bundle-clean, so a stale bundle reaches the push"
        )

    def test_the_check_refuses_a_tree_it_cannot_compare(self) -> None:
        """`git status` outside a work tree writes its error to stderr and
        yields an empty line, so `if [ -n "$(git status ...)" ]` takes the
        false branch and the gate passes without having compared anything: a
        stale bundle read as a clean one, which is the one answer the check
        exists to refuse. Outside a work tree it fails and says so."""
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        recipe = re.search(r"^check-bundle-clean:(.*?)(?=^\S)", makefile, re.MULTILINE | re.DOTALL)
        assert recipe, "the Makefile no longer defines check-bundle-clean"
        assert "git rev-parse --is-inside-work-tree" in recipe.group(1), (
            "check-bundle-clean cannot tell a clean bundle from a tree git cannot read"
        )


class TestNpmLockfile:
    """bun.lock is the JavaScript half of what the sbom job inventories.

    The Python tree is hashed end to end: uv.lock carries a digest per
    artifact and the sbom job re-exports one with `--hashes`. The npm side had
    nothing asserting its two properties, so a range, a stale lock entry, or a
    package resolved without an integrity hash would reach a lint run in
    silence.
    """

    def test_every_dev_dependency_is_pinned_exactly(self) -> None:
        """No range in devDependencies: the lint gate is the same on every run."""
        dev = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["devDependencies"]
        floating = {
            name: version
            for name, version in dev.items()
            if not re.fullmatch(r"\d+\.\d+\.\d+", version)
        }
        assert not floating, f"devDependency versions must be exact: {floating}"

    def test_the_lockfile_resolves_exactly_what_the_manifest_declares(self) -> None:
        """bun.lock and package.json name the same version of the same packages.

        A lockfile that still resolves an older version is a range the pin in
        package.json no longer describes, and `bun install --frozen-lockfile`
        (what `make web-lint` runs) installs the lock's answer, not the
        manifest's.
        """
        declared = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["devDependencies"]
        lock = _bun_lock()
        assert lock["workspaces"][""]["devDependencies"] == declared, (
            "bun.lock's devDependencies differ from package.json; re-lock with `bun install`"
        )
        for name, version in declared.items():
            resolved = lock["packages"][name][0]
            assert resolved == f"{name}@{version}", (
                f"bun.lock resolves {name} to {resolved}, package.json declares {version}"
            )

    def test_every_locked_package_carries_an_integrity_hash(self) -> None:
        """Each entry ends in a digest, so a swapped tarball fails the install."""
        packages = _bun_lock()["packages"]
        assert packages, "bun.lock records no packages"
        unhashed = {
            name: entry[0]
            for name, entry in packages.items()
            if not (isinstance(entry[-1], str) and re.fullmatch(r"sha\d{3}-.+", entry[-1]))
        }
        assert not unhashed, f"bun.lock entries without an integrity hash: {sorted(unhashed)}"


class TestCheckedInLintPreset:
    def test_derived_preset_is_the_scripts_output_not_a_hand_edit(self) -> None:
        """rikalabs-strict.json stays loadable JSON with the keys the script writes."""
        preset = json.loads(_DERIVED_PRESET.read_text(encoding="utf-8"))
        assert set(preset) == {"options", "plugins", "categories", "rules", "overrides"}
        assert preset["rules"], "the flattened preset has no rules"

    def test_readme_records_origin_and_license_of_the_derived_preset(self) -> None:
        """Copied third-party content ships with this repo, so its grant travels too.

        The row must name the pinned package version and its license, so a bump
        that changes either is a visible README edit rather than a silent one.
        """
        row = next(
            line
            for line in _README.read_text(encoding="utf-8").splitlines()
            if "tools/oxlint/rikalabs-strict.json" in line and line.lstrip().startswith("|")
        )
        pin = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["devDependencies"][
            "@rikalabs/oxlint-standards"
        ]
        assert pin in row, f"the README does not record the pinned version {pin}"
        assert "MIT" in row, "the README does not record the license of the copied preset"

    def test_flatten_script_refuses_to_copy_a_license_change(self) -> None:
        """A license change on the npm package must fail, not regenerate quietly."""
        flatten = _FLATTEN.read_text(encoding="utf-8")
        expected = re.search(r'^EXPECTED_LICENSE = "([^"]+)"$', flatten, re.MULTILINE)
        assert expected, "the flatten script no longer pins the upstream license"
        # The comparison itself, not merely the identifier's presence: naming
        # EXPECTED_LICENSE in a message would satisfy a substring check.
        assert re.search(r'manifest\.get\("license"\)\s*!=\s*EXPECTED_LICENSE', flatten), (
            "the flatten script no longer compares the package license against the pin"
        )


def _python_sources() -> list[Path]:
    """Every first-party Python file: the package, the tests, the tools."""
    return [
        path
        for directory in ("src", "tests", "tools")
        for path in sorted((_ROOT / directory).rglob("*.py"))
    ]


def _is_type_checking(test: ast.expr) -> bool:
    """Whether an `if` is the `TYPE_CHECKING` guard.

    Spelled `if TYPE_CHECKING:` (a Name) or `if typing.TYPE_CHECKING:` (an
    Attribute), and under `from __future__ import annotations` the negative
    form reads the same two ways.
    """
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def _type_checking_guarded(tree: ast.AST) -> set[ast.AST]:
    """The import nodes that sit inside a `TYPE_CHECKING` guard's body.

    The `else` branch is runtime code and its imports count; only the guarded
    side is typing-only.  Nested guards are found by the tree walk itself.
    """
    guarded: set[ast.AST] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not _is_type_checking(node.test):
            continue
        for statement in node.body:
            guarded.update(ast.walk(statement))
    return guarded


def _imported_modules_from(tree: ast.AST) -> set[str]:
    """The runtime top-level import names in one parsed module."""
    names: set[str] = set()
    guarded = _type_checking_guarded(tree)
    for node in ast.walk(tree):
        if node in guarded:
            continue
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level:
            assert node.module, "relative or empty from-import"
            names.add(node.module.split(".")[0])
    return names


def _imported_modules() -> set[str]:
    """Top-level names of the runtime imports across those files.

    `ast` rather than a pattern, so a name inside a string or a comment is not
    a dependency and a relative import is not read as a third-party one.
    Imports under `if TYPE_CHECKING:` are excluded: nothing imports them at
    runtime, so requiring a distribution to declare one would force a real
    dependency on a name that only the type checker ever resolves (`_typeshed`
    ships with mypy, not with CPython).
    """
    return {
        name
        for path in _python_sources()
        for name in _imported_modules_from(
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        )
    }


def _probed_modules() -> set[str]:
    """Names passed to `importlib.util.find_spec`, the optional-extra probe.

    An extra whose only use is a capability check is never imported at module
    scope, so the probe is what proves the dependency is still wired up.
    """
    return {
        name.split(".")[0]
        for name in re.findall(
            r'find_spec\(\s*"(?P<name>[A-Za-z0-9_.]+)"',
            "\n".join(p.read_text(encoding="utf-8") for p in _python_sources()),
        )
    }


def _declared_distributions() -> dict[str, str]:
    """Declared distribution name -> the top-level module it provides.

    Runtime dependencies and every extra: an extra that is declared but never
    reached is the same unused dependency with a narrower blast radius.
    """
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    requirements = list(project["dependencies"])
    for extra in project.get("optional-dependencies", {}).values():
        requirements.extend(extra)
    names: dict[str, str] = {}
    for requirement in requirements:
        dist = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", requirement).group()
        names[re.sub(r"[-_.]+", "-", dist).lower()] = dist.lower().replace("-", "_")
    return names


def _js_sources() -> list[Path]:
    """Every first-party JS, TS, TSX and CSS source a gate compiles or bundles.

    `web/` is what `vite build` reads, `oxlint.config.ts` is the lint config,
    and the vendored anti-slop plugin is TypeScript the lint gate compiles, so
    its imports are the tree's too.
    """
    sources = [
        path
        for pattern in ("*.ts", "*.tsx", "*.js", "*.css")
        for path in sorted((_ROOT / "web").rglob(pattern))
    ]
    return [*sources, _ROOT / "oxlint.config.ts", *sorted(_VENDOR_TREE.rglob("*.ts"))]


def _imported_js_packages() -> set[str]:
    """The npm package names those sources name as a module specifier.

    A relative specifier is first-party, a `node:`-prefixed one is the
    platform, and the tsconfig `@/` alias is the first-party `web/app` tree;
    everything else names a package, and only the first segment (two under a
    scope) is the name the manifest declares.
    """
    packages: set[str] = set()
    for path in _js_sources():
        for match in _JS_SPECIFIER_RE.finditer(path.read_text(encoding="utf-8")):
            specifier = match.group("module") or match.group("css")
            if specifier.startswith((".", "/", "@/", "node:")):
                continue
            head = specifier.split("/")
            packages.add("/".join(head[:2]) if specifier.startswith("@") else head[0])
    return packages


class TestDeclaredDependencies:
    def test_type_checking_only_imports_are_not_runtime_dependencies(self) -> None:
        """A guarded import never executes, so it needs no distribution.

        The scanner is what decides the answer for every other import in the
        tree, so it has to be right about the one shape that is not an import
        at runtime.  `devserver` annotates against `_typeshed.wsgi`, which
        ships with mypy and has no PyPI distribution at all: counting it as a
        runtime import demands a dependency that cannot be declared, and
        dropping the exemption wholesale would let a real unguarded import of
        a typing-only name through.
        """
        source = """
from __future__ import annotations
import json
import typing
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from _typeshed.wsgi import InputStream
if typing.TYPE_CHECKING:
    import only_guarded
if not TYPE_CHECKING:
    import in_the_else_branch
"""
        tree = ast.parse(source)
        assert _imported_modules_from(tree) == {
            "__future__",
            "json",
            "typing",
            "in_the_else_branch",
        }, "a guarded import counted as runtime, or the else branch missed"

    def test_every_declared_distribution_is_reachable(self) -> None:
        """No declared dependency is dead weight.

        An unused runtime dependency is installed on every user's machine and
        widens the supply chain for code that never runs; an unused extra is
        the same cost for whoever asks for it. Reachability is an import, an
        `importlib.util.find_spec` probe, or a recorded CLI invocation.
        """
        used = _imported_modules() | _probed_modules()
        unreachable = {
            dist: "no import, find_spec probe, or recorded CLI invocation"
            for dist, module in _declared_distributions().items()
            if module not in used and dist not in _CLI_ONLY
        }
        assert not unreachable, f"declared but never used: {sorted(unreachable)}"
        for dist, reason in _CLI_ONLY.items():
            assert dist in _declared_distributions(), (
                f"_CLI_ONLY lists {dist!r}, which pyproject.toml no longer declares; "
                "its exemption has outlived the dependency"
            )
            assert reason.strip(), f"_CLI_ONLY[{dist!r}] needs the reason it is exempt"

    def test_every_third_party_import_is_declared(self) -> None:
        """No import reaches a package the manifest does not name.

        Importing a package that is only present transitively works until the
        dependency that drags it in changes its own tree, at which point the
        break lands in a release rather than in the pull request that caused
        it. A first-party sibling module is not a dependency.
        """
        first_party = {p.stem for p in _python_sources()} | {"recoverage"}
        declared = set(_declared_distributions().values())
        undeclared = {
            name
            for name in _imported_modules()
            if name not in sys.stdlib_module_names
            and name not in first_party
            and name not in declared
        }
        assert not undeclared, f"imported but not declared in pyproject.toml: {sorted(undeclared)}"


class TestDeclaredFrontendDependencies:
    """The npm half of the reachability rule `TestDeclaredDependencies` holds.

    A devDependency nothing imports and no gate runs is installed on every
    contributor's machine and on every CI runner, and its own dependencies
    with it, for a build that never calls it. `lucide-react` sat there for
    months: the tree uses preact/compat and imports no icon, so the only
    thing it did was drag `react` into the lockfile.
    """

    def test_every_dev_dependency_is_reachable(self) -> None:
        """No devDependency is dead weight.

        Reachability is an import from a source a gate reads, or a recorded
        invocation: a bin on a script, a `types` entry, or a node_modules file
        a build step names. Every exemption carries the mechanism, because an
        unexplained one is how the next stale declaration survives.
        """
        declared = set(json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["devDependencies"])
        used = _imported_js_packages()
        unreachable = {
            name: "no import, or no recorded invocation"
            for name in declared
            if name not in used and name not in _JS_CLI_ONLY
        }
        assert not unreachable, f"declared but never used: {sorted(unreachable)}"
        for name, reason in _JS_CLI_ONLY.items():
            assert name in declared, (
                f"_JS_CLI_ONLY lists {name!r}, which package.json no longer declares; "
                "its exemption has outlived the dependency"
            )
            assert reason.strip(), f"_JS_CLI_ONLY[{name!r}] needs the reason it is exempt"


class TestBundledThirdPartyAssets:
    """The wheel ships vendored browser blobs, so their grants have to ship too.

    `package-data` globs the whole assets directory, so a minified third-party
    blob written there lands in every install whether or not anyone records
    where it came from. README documents the provenance; NOTICE is what a
    consumer of the built wheel actually receives.
    """

    def test_notice_ships_with_the_distribution(self) -> None:
        """A NOTICE nothing packages is a NOTICE no downstream consumer sees."""
        project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        assert "NOTICE" in project["license-files"], (
            "license-files omits NOTICE, so the bundled third-party grants stay out of the wheel"
        )
        assert (_ROOT / "NOTICE").is_file()

    #: Every third-party library compiled into the shipped bundle.  The bundle is
    #: one generated file (`src/recoverage/assets/app.js`, plus the compiled
    #: `style.css`), so a per-file grant cannot express what is inside it: this
    #: list is the boundary, and the check below requires NOTICE to credit each
    #: entry with a license and a source.
    BUNDLED_LIBRARIES = (
        "Preact (and preact/compat)",
        "highlight.js",
        "Tailwind CSS",
        "clsx, tailwind-merge, class-variance-authority",
    )

    def test_every_bundled_library_is_credited(self) -> None:
        """NOTICE must name every third-party library the bundle carries.

        The dashboard ships built assets, so the frontend's dependencies are
        vendored into the wheel in effect: a library compiled into `app.js` with
        no grant beside it is code distributed without its license. The list is
        checked entry by entry rather than globbed, because there is no file
        name left to glob on.
        """
        notice = (_ROOT / "NOTICE").read_text(encoding="utf-8")
        for library in self.BUNDLED_LIBRARIES:
            entry = re.search(rf"^{re.escape(library)}.*\n(?:.*\n)*?\n", notice, re.MULTILINE)
            assert entry, f"NOTICE does not credit {library}, which the bundle carries"
            assert "License:" in entry.group(0), f"NOTICE names {library} without its license"
            assert "Upstream:" in entry.group(0), f"NOTICE names {library} without its source"

    def test_the_bundled_libraries_are_the_frontend_dependencies(self) -> None:
        """The credit list must cover what package.json actually ships.

        A dependency added to the bundle without joining this list would ship
        uncredited again, which is the failure the list exists to catch.
        """
        manifest = json.loads((_ROOT / "package.json").read_text(encoding="utf-8"))
        bundled = {"preact", "highlight.js", "tailwindcss"}
        assert bundled <= set(manifest["devDependencies"]), (
            "a bundled library left package.json; update BUNDLED_LIBRARIES with it"
        )


def _js_inventory_module() -> ModuleType:
    """`tools/bundled_js_inventory.py`, imported so the shipped list has one
    definition and the sbom job, `make browser-sbom` and these read it.
    """
    path = _ROOT / "tools" / "bundled_js_inventory.py"
    spec = importlib.util.spec_from_file_location("bundled_js_inventory", path)
    assert spec and spec.loader, "tools/bundled_js_inventory.py is not importable"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestBrowserBundleInventory:
    """The wheel ships compiled browser code, so that code has an inventory too.

    NOTICE records the grants and `TestBundledThirdPartyAssets` holds the
    credit list to them, but a grant says who owns the code, not which version
    of it a build carried. The Python side answers that with the sbom job's
    hashed export; without a browser equivalent, a consumer or a scanner
    pointed at a wheel sees the Python tree and learns nothing about the
    Preact and highlight.js that run in their browser. These pin that the
    inventory names the shipped packages, that it reads the resolved tree
    rather than the manifest, and that CI produces it.
    """

    def test_the_inventory_names_every_shipped_package_with_its_digest(self) -> None:
        """Each line is a package the bundle carries, at the version bun.lock pinned.

        The version and digest are read from the lock, so a manifest bump that
        skipped `bun install` cannot leave the inventory describing an older
        bundle than the one the wheel ships.
        """
        module = _js_inventory_module()
        body = module.render(module.resolve())
        lines = [
            line
            for line in body.splitlines()
            if line and not line.startswith(("#", "\t")) and " " in line
        ]
        assert len(lines) == len(module.SHIPPED), "a shipped package produced no inventory line"
        for entry, spec, digest in module.resolve():
            assert spec == f"{entry.package}@{_locked_version(entry.package)}", (
                f"{entry.package} resolves to {spec}, bun.lock pins "
                f"{_locked_version(entry.package)}"
            )
            assert f"{spec} {digest} -> {entry.asset}" in body, (
                f"the inventory does not record {spec} with its digest and target asset"
            )
            assert entry.because.strip(), f"{entry.package} is listed without a reason it ships"

    def test_every_shipped_package_is_a_declared_dependency(self) -> None:
        """A package nothing declares is a line describing code that cannot be built."""
        module = _js_inventory_module()
        declared = set(json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))["devDependencies"])
        listed = {entry.package for entry in module.SHIPPED}
        stale = sorted(listed - declared)
        assert not stale, f"the inventory names packages package.json no longer declares: {stale}"

    def test_the_shipped_list_agrees_with_the_credit_list(self) -> None:
        """Every shipped library NOTICE credits, and every credit is inventoried.

        Two records of the same six packages is a drift waiting to happen: a
        dependency added to the bundle would be credited in one and missing
        from the other, and each list on its own would still pass.
        """
        module = _js_inventory_module()
        listed = {entry.package for entry in module.SHIPPED}
        assert {"preact", "highlight.js", "tailwindcss"} <= listed, (
            "the bundle's own credit list (TestBundledThirdPartyAssets) names a library "
            "the inventory does not"
        )
        for name in ("clsx", "tailwind-merge", "class-variance-authority"):
            assert name in listed, f"{name} is compiled into app.js and is not inventoried"

    def test_the_inventory_describes_the_assets_the_wheel_ships(self) -> None:
        """The Tailwind version the inventory prints is the one in the built CSS.

        `src/recoverage/assets/style.css` carries the Tailwind banner, so the
        two can be compared: an inventory that names a version the shipped
        bytes were not built from is worse than none, because it reads as
        coverage.
        """
        version = _locked_version("tailwindcss")
        banner = (_ROOT / "src" / "recoverage" / "assets" / "style.css").read_text(
            encoding="utf-8"
        )[:200]
        assert f"tailwindcss v{version}" in banner, (
            f"the inventory names tailwindcss {version}, which is not the version the "
            "committed style.css was built from; run make web-build"
        )

    def test_the_inventory_is_produced_by_the_sbom_job(self) -> None:
        """CI exports the browser half, or the gap this closes reopens silently.

        The Python export cannot see the bundle, so this job is the only place
        the browser inventory is produced. The tool is named rather than a
        Makefile target because the job has no sibling checkout to sync one
        through, which is the same constraint that pins its `uv export` to
        `--frozen`.
        """
        job = _jobs()["sbom"]
        assert "tools/bundled_js_inventory.py" in job, (
            "the sbom job no longer exports the browser-bundle inventory"
        )
        assert "recoverage-browser-sbom" in job, (
            "the browser inventory is written but not uploaded as an artifact"
        )
        assert "uv export" in job, "the sbom job stopped exporting the Python inventory"

    def test_notice_points_at_the_browser_inventory(self) -> None:
        """A wheel consumer reads NOTICE, so the artifact is named there."""
        notice = (_ROOT / "NOTICE").read_text(encoding="utf-8")
        assert "recoverage-browser-sbom" in notice, (
            "NOTICE does not name the browser inventory, so a consumer reading the "
            "wheel is not told where to find the versions it ships"
        )

    def test_the_artifact_the_job_uploads_is_what_the_tool_writes(self, tmp_path: Path) -> None:
        """`--output` writes the rendered inventory, and `test -s` sees a file.

        The job's whole contract is the file the tool leaves behind, so a
        `--output` that printed to stdout instead would upload nothing and the
        job would go red on `test -s` rather than here.
        """
        module = _js_inventory_module()
        out = tmp_path / "recoverage-browser-sbom.txt"
        assert module.main(["--output", str(out)]) == 0
        assert out.read_text(encoding="utf-8") == module.render(module.resolve())

    def test_a_package_the_manifest_drops_stops_the_export(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A listed package nothing declares is an error, not an inventory line.

        The list outlives a dependency that stopped reaching the bundle until
        somebody removes it, and an inventory naming a package no longer in
        the tree describes code the wheel cannot carry.
        """
        module = _js_inventory_module()
        manifest = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))
        del manifest["devDependencies"]["preact"]
        path = tmp_path / "package.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        monkeypatch.setattr(module, "PACKAGE_JSON", path)
        with pytest.raises(module.InventoryError, match="preact"):
            module.resolve()

    def test_a_lock_entry_without_a_digest_stops_the_export(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unhashed lock entry cannot be audited, so the export refuses it."""
        module = _js_inventory_module()
        lock = _bun_lock()
        lock["packages"]["clsx"] = ["clsx@2.1.1", "", {}, ""]
        path = tmp_path / "bun.lock"
        path.write_text(json.dumps(lock), encoding="utf-8")
        monkeypatch.setattr(module, "BUN_LOCK", path)
        with pytest.raises(module.InventoryError, match="integrity"):
            module.resolve()


def _locked_version(package: str) -> str:
    """The version bun.lock resolves, which is the only one a build can ship."""
    return _bun_lock()["packages"][package][0].split("@", 1)[1]


class TestBrowserSpdxExport:
    """The browser inventory in the shape a vulnerability scanner ingests.

    `TestBrowserBundleInventory` covers the text one, which is a line per
    shipped package and readable by a person. A scanner takes a standard
    document, so the text file is no answer to "what shipped": the same rows
    are exported as SPDX 2.3 JSON, and these hold that document to the fields a
    validator reads, to the versions bun.lock resolved, to the grants NOTICE
    credits, and to the one thing that made it awkward to add at all, which is
    that a `created` stamp taken from the wall clock would make two runs of one
    commit differ in every byte a consumer diffs.
    """

    def test_the_document_carries_the_fields_a_spdx_reader_requires(self) -> None:
        """The 2.3 document header, and a namespace that is unique per stamp."""
        module = _js_inventory_module()
        document = module.spdx_document(module.resolve())
        assert document["spdxVersion"] == "SPDX-2.3"
        assert document["dataLicense"] == "CC0-1.0"
        assert document["SPDXID"] == "SPDXRef-DOCUMENT"
        created = document["creationInfo"]["created"]
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created), (
            f"created is not the UTC form SPDX requires: {created!r}"
        )
        assert document["creationInfo"]["creators"], "a document with no creator names no producer"
        assert document["documentNamespace"].startswith("https://")
        assert document["name"].endswith("-browser-bundle")
        assert _ROOT.name in document["name"] or "recoverage" in document["name"], (
            "the document is not named after the build it describes"
        )

    def test_every_shipped_package_is_described_by_its_resolved_version(self) -> None:
        """One package per shipped entry, at the version bun.lock pinned.

        A package read from package.json would carry a range, and a range is
        not an inventory entry: a scanner resolving it later answers about a
        version this build never shipped.
        """
        module = _js_inventory_module()
        document = module.spdx_document(module.resolve())
        packages = {pkg["name"]: pkg for pkg in document["packages"]}
        assert set(packages) == {entry.package for entry in module.SHIPPED}
        for entry in module.SHIPPED:
            package = packages[entry.package]
            assert package["versionInfo"] == _locked_version(entry.package), (
                f"the SPDX document names {entry.package} {package['versionInfo']}, "
                f"bun.lock pins {_locked_version(entry.package)}"
            )
            assert package["filesAnalyzed"] is False
            assert entry.asset in package["comment"], (
                f"the SPDX entry for {entry.package} does not name the asset it lands in"
            )
        described = {
            rel["relatedSpdxElement"]
            for rel in document["relationships"]
            if rel["spdxElementId"] == "SPDXRef-DOCUMENT"
        }
        assert described == {pkg["SPDXID"] for pkg in document["packages"]}, (
            "a shipped package has no DESCRIBES relationship, so a reader never reaches it"
        )

    def test_every_package_carries_the_digest_bun_lock_pinned(self) -> None:
        """The tarball digest, in the hex spelling a checksum field takes."""
        module = _js_inventory_module()
        document = module.spdx_document(module.resolve())
        for entry, spec, digest in module.resolve():
            package = next(pkg for pkg in document["packages"] if pkg["name"] == entry.package)
            algorithm, _, encoded = digest.partition("-")
            assert package["checksums"] == [
                {
                    "algorithm": {"sha512": "SHA512", "sha256": "SHA256"}[algorithm],
                    "checksumValue": base64.b64decode(encoded).hex(),
                }
            ], f"the SPDX entry for {spec} does not carry the digest bun.lock pinned"
            assert digest in package["comment"], (
                f"the SPDX entry for {spec} does not record the bun.lock integrity string"
            )

    def test_every_package_carries_the_grant_notice_credits(self) -> None:
        """The license a consumer may act on, and the one NOTICE prints.

        The document says what may be done with the compiled code in the
        reader's browser, so a package with no `licenseDeclared` is an entry
        that names a grant nobody can trace. NOTICE is the record the wheel
        ships, so the two cannot name different licenses for one package.
        """
        module = _js_inventory_module()
        document = module.spdx_document(module.resolve())
        notice = (_ROOT / "NOTICE").read_text(encoding="utf-8")
        for entry in module.SHIPPED:
            package = next(pkg for pkg in document["packages"] if pkg["name"] == entry.package)
            assert package["licenseConcluded"] == entry.license_id
            assert package["licenseDeclared"] == entry.license_id
            assert entry.homepage.startswith("https://")
            credited = notice[notice.index(entry.package) :][:400]
            assert entry.license_id in credited, (
                f"NOTICE credits {entry.package} without the {entry.license_id} grant the "
                "SPDX document declares"
            )

    def test_the_stamp_comes_from_the_environment_not_the_clock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One commit renders one document, byte for byte.

        The sbom job uploads this file and asks for the same bytes across runs,
        so `created` is read from SOURCE_DATE_EPOCH, the stamp `make build`
        already exports, and the wall clock is the fallback rather than the
        default. A SOURCE_DATE_EPOCH that is not a timestamp is refused rather
        than silently ignored: the alternative is a document that claims to be
        reproducible and is not.
        """
        module = _js_inventory_module()
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        first = tmp_path / "a.json"
        second = tmp_path / "b.json"
        assert module.main(["--format", "spdx", "--output", str(first)]) == 0
        assert module.main(["--format", "spdx", "--output", str(second)]) == 0
        assert first.read_bytes() == second.read_bytes(), (
            "two runs at one stamp rendered different documents"
        )
        document = json.loads(first.read_text(encoding="utf-8"))
        assert document["creationInfo"]["created"] == "2023-11-14T22:13:20Z", (
            "SOURCE_DATE_EPOCH is ignored, so the document is stamped from the wall clock"
        )
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-timestamp")
        with pytest.raises(module.InventoryError, match="SOURCE_DATE_EPOCH"):
            module.spdx_document(module.resolve())

    def test_the_sbom_job_uploads_the_document(self) -> None:
        """CI produces the machine-readable half, or the gap reopens silently.

        The text export this adds beside is what a person reads; a scanner
        pointed at the release needs the other one, and nothing in the tree
        would produce it if the job stopped naming it.
        """
        job = _jobs()["sbom"]
        assert "--format spdx" in job, "the sbom job no longer exports the SPDX document"
        assert "recoverage-browser-spdx" in job, (
            "the SPDX document is written but not uploaded as an artifact"
        )
        assert "SOURCE_DATE_EPOCH" in job, (
            "the document is stamped from the wall clock, so two runs of one commit differ"
        )

    def test_a_digest_this_document_cannot_carry_stops_the_export(self) -> None:
        """An algorithm outside SPDX's checksum vocabulary is a refusal.

        bun may add a digest the document has no field for, and writing it
        into `checksums` anyway produces a file a validator rejects with no
        line naming the package that caused it.
        """
        module = _js_inventory_module()
        with pytest.raises(module.InventoryError, match="sha999"):
            module._checksum("sha999-not-a-digest")
        with pytest.raises(module.InventoryError, match="base64"):
            module._checksum("sha512-not base64!")


class TestVendoredLintPlugin:
    """`tools/oxlint/anti-slop/` is third-party code that lives in the repo.

    No manifest covers it: package.json pins the npm packages, uv.lock the
    Python ones, and neither reaches a directory copied into the tree.  So the
    manifest is the only record of what the copy contains and where it came
    from, and these fail the suite when the tree and that record disagree.
    """

    @staticmethod
    def _manifest() -> dict:
        manifest = _VENDOR_MANIFEST
        assert manifest.is_file(), (
            f"{manifest.name} is missing; run tools/vendor_manifest.py to record the vendored tree"
        )
        return json.loads(manifest.read_text(encoding="utf-8"))

    def test_the_manifest_names_the_upstream_and_its_grant(self) -> None:
        """A vendored copy whose origin is unrecorded cannot be audited."""
        manifest = self._manifest()
        assert manifest["upstream"].startswith("https://"), "the manifest names no upstream"
        assert manifest["license"] == "MIT", "the upstream grant is not the MIT the LICENSE is"
        assert (_VENDOR_TREE / "LICENSE").is_file(), "the vendored tree ships without its LICENSE"
        for pattern, reason in manifest["excluded"].items():
            assert reason.strip(), f"excluded {pattern} has no reason, so it is not a decision"

    def test_the_manifest_is_the_tree_as_it_stands(self) -> None:
        """An edit, a deletion, or an unrecorded addition fails here.

        The digests are the whole point: an upstream re-vendor and a local
        change look identical in a diff of rule files, and only one of them
        was reviewed against upstream.  A file the manifest does not list is
        an addition nobody checked; a listed file whose bytes moved is a
        change nobody re-vendored.

        The expectation is what `tools/vendor_manifest.py` builds, imported
        rather than restated here, so the two cannot disagree about which
        paths an exclusion covers.
        """
        script = _vendor_manifest_module()
        recorded = self._manifest()
        expected = script.build_manifest()
        assert recorded["files"] == expected["files"], (
            "the vendored tree and its manifest disagree; run tools/vendor_manifest.py "
            "after a re-vendor, and review what changed against upstream"
        )
        assert set(recorded["files"]) == {rel for rel, _ in expected["files"].items()}
        excluded = [
            path.relative_to(_VENDOR_TREE).as_posix()
            for path in _VENDOR_TREE.rglob("*")
            if path.is_file() and script.is_excluded(path.relative_to(_VENDOR_TREE).as_posix())
        ]
        assert not excluded, f"paths the manifest excludes are in the tree: {excluded}"

    def test_readme_and_notice_point_at_the_manifest(self) -> None:
        """The record has to be findable from where a reader starts."""
        notice = (_ROOT / "NOTICE").read_text(encoding="utf-8")
        for doc in (_README.read_text(encoding="utf-8"), notice):
            assert _VENDOR_MANIFEST.name in doc, (
                f"no reference to {_VENDOR_MANIFEST.name}, so the record of the vendored copy "
                f"is unreachable from the documentation"
            )


class TestUpdateBots:
    """Two bots update this tree, and each ecosystem has exactly one of them.

    `renovate.json` reads `pyproject.toml` and `bun.lock`; Dependabot reads the
    action pins and cannot read either of the other two (a `bun.lock` with no
    `package-lock.json` beside it, and a `[tool.uv.sources]` path pointing at a
    sibling checkout, are both errors it aborts on).  The overlap is what
    costs: two PRs against the same pinned action SHA, whichever merges first
    making the other stale, and a reviewer reading two claims about one
    version.  Nothing else in the tree reads either file, so the split is what
    these hold.
    """

    @staticmethod
    def _renovate() -> dict:
        config = _RENOVATE
        assert config.is_file(), f"{config.name} is missing, so nothing updates uv.lock or bun.lock"
        return json.loads(config.read_text(encoding="utf-8"))

    @staticmethod
    def _dependabot_ecosystems() -> list[str]:
        """The `package-ecosystem` values, which is the whole of Dependabot's scope."""
        text = _DEPENDABOT.read_text(encoding="utf-8")
        return re.findall(r'^\s*-\s*package-ecosystem:\s*"([^"]+)"', text, re.MULTILINE)

    def test_renovate_does_not_own_the_actions(self) -> None:
        """The action pins have one owner, and it is Dependabot.

        `config:recommended` does not restrict managers, so dropping the
        `enabledManagers` list is what keeps the second bot out; a rule added
        there later would reopen the same pin to both.
        """
        assert "enabledManagers" in self._renovate(), (
            "renovate.json names no managers, so its default list covers "
            "github-actions and it opens a PR against every pin Dependabot owns"
        )
        assert "github-actions" not in self._renovate()["enabledManagers"], (
            "renovate.json claims github-actions, which .github/dependabot.yml already owns"
        )

    def test_dependabot_owns_the_actions_and_nothing_else(self) -> None:
        """One ecosystem per bot, both directions.

        The other half of the split: an `npm` or `uv` entry here aborts that
        Dependabot job (see the header of the file), which leaves the pin it
        was to raise with no updater at all.
        """
        assert self._dependabot_ecosystems() == ["github-actions"], (
            "dependabot.yml claims an ecosystem renovate.json owns; the two would "
            "open a PR each against the same lockfile"
        )

    def test_bun_lock_is_the_only_javascript_lockfile(self) -> None:
        """No second lockfile beside bun.lock.

        Dependabot keys its npm manager off `package-lock.json` and resolves
        against it, so a file that appears beside bun.lock is a second,
        unreviewed statement of which version builds.
        """
        found = [
            name
            for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")
            if (_ROOT / name).exists()
        ]
        assert not found, f"a second JavaScript lockfile is committed beside bun.lock: {found}"


def _license_inventory_module() -> ModuleType:
    """`tools/license_inventory.py`, imported so the tree has one definition
    of what a license is read from and what counts as allowed.

    `tools/` is a script directory rather than a package, so the loader is how
    a test reaches in, the same one `TestVendoredLintPlugin` uses for
    `tools/vendor_manifest.py`.
    """
    path = _ROOT / "tools" / "license_inventory.py"
    spec = importlib.util.spec_from_file_location("license_inventory", path)
    assert spec and spec.loader, "tools/license_inventory.py is not importable"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestPythonDependencyLicenses:
    """The Python half of the third-party license record.

    NOTICE and `tools/bundled_js_inventory.py` cover the code the wheel
    BUNDLES, and `make python-sbom` covers the resolved Python tree's
    versions and hashes. Nothing covered what a consumer may do with the
    packages recoverage INSTALLS, and that tree is much wider than the eight
    names pyproject.toml spells out: rebrew is a runtime import, and it brings
    certifi, lief, numpy, tree-sitter, python-flirt and five more with it. A
    gate that read only the declared names would have called all of those
    clean without reading one of them.
    """

    def test_the_resolved_tree_is_under_a_permissive_license(self) -> None:
        """Every distribution recoverage resolves is redistributable here.

        The refusal is a hard copyleft license, an id the allowlist does not
        hold, and a package that declares none at all: each is a question about
        what this project may ship, which is a decision rather than something
        the tree can infer from a hash.
        """
        module = _license_inventory_module()
        refused = module._refused(module.inventory())
        assert not refused, "licenses outside the permissive set, or undeclared:\n  " + "\n  ".join(
            refused
        )

    def test_the_closure_is_wider_than_the_declared_dependencies(self) -> None:
        """The gate has to be reading a tree, not eight names.

        A walk that stopped at `[project].dependencies` would answer the same
        way for a runtime dependency that pulled in a copyleft package, which
        is the failure this exists to catch. Transitives are named here so the
        next one to arrive is a test that fails rather than a widened allowlist
        that passes.
        """
        module = _license_inventory_module()
        resolved = {entry.name.lower() for entry in module.inventory()}
        declared = {name.lower() for name in module.declared_roots()}
        assert declared < resolved, (
            "nothing outside pyproject.toml resolved, so the walk is not reaching the "
            "transitive tree and the license check is narrower than it reads"
        )
        for name in ("certifi", "markdown-it-py", "mdurl"):
            assert name in resolved, (
                f"{name} is no longer in the resolved tree; if rebrew dropped it, this is "
                f"the list to update rather than a gap in the gate"
            )

    def test_a_copyleft_or_unknown_license_is_refused(self) -> None:
        """The gate can fail.

        A check that only ever sees permissive licenses passes on the strength
        of the tree rather than the strength of the rule, and a copyleft
        dependency would then ship through it. The synthetic entries are what
        prove the refusal is reachable at all.
        """
        module = _license_inventory_module()
        entry = module.Entry
        assert module._refused([entry("x", "1", "GPL-3.0")]), "a copyleft license was allowed"
        assert module._refused([entry("x", "1", "AGPL-3.0")]), "a copyleft license was allowed"
        assert module._refused([entry("x", "1", "Nonexistent-1.0")]), "an unknown id was allowed"
        assert module._refused([entry("x", "1", "")]), "an undeclared license was allowed"
        assert module._refused([entry("x", "1", "BSD-3-Clause AND GPL-3.0")]), (
            "a compound expression hiding a copyleft license was allowed"
        )
        assert not module._refused([entry("x", "1", "MIT")])
        assert not module._refused([entry("x", "1", "(MIT OR Apache-2.0)")]), (
            "parentheses are in the vocabulary; numpy's expression form is not"
        )

    def test_every_recorded_license_names_a_file_that_is_still_there(self) -> None:
        """`_UNDECLARED_METADATA` is a claim about a file, so the file is checked.

        Five distributions name no license in their METADATA, and the record
        is what the gate reads for them. A bump that moves or renames a LICENSE
        file would otherwise leave a claim standing that nobody re-reads, so
        the recorded path is resolved against what the distribution actually
        ships and a stale entry refuses the run.
        """
        module = _license_inventory_module()
        recorded = module._UNDECLARED_METADATA
        assert recorded, (
            "the table is empty, so the packages without a METADATA license are unchecked"
        )
        for name, (license_id, path) in recorded.items():
            assert license_id in module._ALLOWED, (
                f"{name} records {license_id}, which is not on the allowlist"
            )
            try:
                dist = importlib.metadata.distribution(name)
            except importlib.metadata.PackageNotFoundError:
                continue
            tails = {module._after_dist_info(str(f)) for f in dist.files or ()}
            assert module._after_dist_info(path) in tails, (
                f"{name} no longer ships {path}; the license it is under has to be re-read "
                f"from the file it now does ship"
            )

    def test_the_gate_is_reachable_without_ci(self) -> None:
        """The inventory is a local command, not something only a job can run.

        `make python-sbom` exists for the same reason: the artifact a release
        ships has to be reproducible by the person who changed the tree, or
        nobody reads it before the tag.
        """
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        assert "license-inventory" in makefile, "no Makefile target runs the license gate"
        assert "tools/license_inventory.py" in makefile, "the target does not name the tool it runs"
        for doc in (
            _README.read_text(encoding="utf-8"),
            (_ROOT / "NOTICE").read_text(encoding="utf-8"),
        ):
            assert "license-inventory" in doc, (
                "the license record of the Python half is unreachable from the documentation"
            )
