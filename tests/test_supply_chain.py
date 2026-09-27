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
import json
import re
import sys
import tomllib
from itertools import pairwise
from pathlib import Path

_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_CI_YML = _ROOT / ".github" / "workflows" / "ci.yml"
_CLONE_SCRIPT = _ROOT / "tools" / "ci_clone_rebrew.sh"
_MAKEFILE = _ROOT / "Makefile"
_README = _ROOT / "README.md"
_PACKAGE_JSON = _ROOT / "package.json"
_BUN_LOCK = _ROOT / "bun.lock"
_MANIFEST = _ROOT / "pyproject.toml"
_PYTHON_VERSION = _ROOT / ".python-version"
_FLATTEN = _ROOT / "tools" / "flatten-rikalabs-strict.py"
_DERIVED_PRESET = _ROOT / "tools" / "oxlint" / "rikalabs-strict.json"
# The one place a CI job may fetch the sibling. A job may not clone rebrew
# itself, and the action may not carry a pin: tools/ci_clone_rebrew.sh owns it.
_SIBLING_ACTION = _ROOT / ".github" / "actions" / "sibling-rebrew" / "action.yml"

# Declared distributions that are correct without ever appearing in an import
# statement, and the mechanism that runs them instead. Every entry needs a
# reason: an unexplained one is how a genuinely stale declaration survives.
_CLI_ONLY = {
    "ruff": "the lint gate invokes it as `python -m ruff`, never imports it",
    "pytest-playwright": "a pytest plugin, loaded by entry point, that only supplies fixtures",
}

# A CI job header: two spaces, a name, a colon, and nothing else on the line.
_JOB_RE = re.compile(r"^  (?P<name>[a-z][a-z0-9-]*):$", re.MULTILINE)
# A job step that reaches the pinned script: the composite action, which
# calls it, or a direct `run:` of the script itself.
_ACTION_USE_RE = re.compile(r"\.github/actions/sibling-rebrew|tools/ci_clone_rebrew\.sh")
_PINS = {"REBREW_REF": "v2.13.1", "REBREW_SHA": "d2d67c870df79214320f16b1cba1b0f6086605a7"}
# How a job names the composite action that fetches the sibling checkout.
_SIBLING_ACTION_STEP = "uses: ./.github/actions/sibling-rebrew"


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
    """Workflow text per job name, so a check is scoped to the job that needs it."""
    text = _CI_YML.read_text(encoding="utf-8")
    starts = [(m.group("name"), m.start()) for m in _JOB_RE.finditer(text)]
    return {name: text[start:end] for (name, start), (_, end) in pairwise(starts)}


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

    def test_every_action_resolves_to_a_commit(self) -> None:
        for path in self._action_files():
            for match in self._USE_RE.finditer(path.read_text(encoding="utf-8")):
                action, ref = match["action"], match["ref"]
                if action.startswith("./"):
                    continue
                where = f"{path.relative_to(_ROOT)}: {action}"
                assert self._SHA_RE.match(ref), f"{where} uses {ref!r}, not a 40-hex commit"
                comment = (match["comment"] or "").strip()
                assert self._TAG_COMMENT_RE.match(comment), (
                    f"{where} pins {ref[:12]} without naming the tag it came from"
                )

    def test_the_checkout_token_does_not_outlive_the_checkout(self) -> None:
        """`persist-credentials: false` on every checkout, in every workflow.

        checkout otherwise leaves the job's GITHUB_TOKEN in `.git/config`, and
        every step in this pipeline runs project code (pytest, tools/smoke.py,
        bun) that could read it off disk. No job pushes, so nothing needs it
        after the tree lands.
        """
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
        left to a reader to work out.
        """
        exports = [
            " ".join(line.split())
            for line in _CI_YML.read_text(encoding="utf-8").splitlines()
            if "uv export" in line and not line.lstrip().startswith("#")
        ]
        assert len(exports) == 1, f"expected one uv export, found {exports}"
        assert "--frozen" in exports[0] and "--locked" not in exports[0], exports[0]

    def test_the_makefile_installs_the_same_way(self) -> None:
        """`make all` is the local mirror of CI, down to the uv flag."""
        makefile = _MAKEFILE.read_text(encoding="utf-8")
        for line in ("UV_SYNC_FLAGS ?=", "UV_RUN :="):
            declaration = re.search(rf"^{re.escape(line)}.*$", makefile, re.MULTILINE)
            assert declaration, f"Makefile no longer defines {line}"
            assert "--locked" in declaration.group(0), declaration.group(0)
            assert "--frozen" not in declaration.group(0), declaration.group(0)


class TestToolchainPins:
    """The runner toolchain CI installs is read from the file that owns it.

    Both actions resolve their version from the tree (`.python-version`,
    package.json's packageManager) instead of a copy written into the
    workflow, the same one-pin rule the rebrew clone follows. A test fails
    when a literal version comes back, because a second pin is what a bump
    would have to touch and nobody would remember to.
    """

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
            f"tools/flatten-rikalabs-strict.py restates oxlint {oxlint}; package.json owns it"
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


def _imported_modules() -> set[str]:
    """Top-level names of the absolute imports across those files.

    `ast` rather than a pattern, so a name inside a string or a comment is not
    a dependency and a relative import is not read as a third-party one.
    """
    names: set[str] = set()
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and not node.level:
                assert node.module, f"{path}: relative or empty from-import"
                names.add(node.module.split(".")[0])
    return names


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


class TestDeclaredDependencies:
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

    def test_every_bundled_third_party_blob_is_credited(self) -> None:
        """Every vendored asset is named in NOTICE with a license and a source.

        The vendored blobs are the minified ones: first-party sources (app.js,
        detail.js) are not minified, so the suffix is the boundary between
        "written here" and "copied from somewhere".
        """
        notice = (_ROOT / "NOTICE").read_text(encoding="utf-8")
        bundled = sorted((_ROOT / "src" / "recoverage" / "assets").glob("*.min.js"))
        assert bundled, "no vendored assets found; the glob this check relies on has moved"
        for blob in bundled:
            rel = blob.relative_to(_ROOT).as_posix()
            entry = re.search(rf"^.*{re.escape(rel)}.*?$\n\n", notice, re.MULTILINE | re.DOTALL)
            assert entry, f"NOTICE does not credit {rel}, which ships in the wheel"
            assert "License:" in entry.group(0), f"NOTICE names {rel} without its license"
            assert "Upstream:" in entry.group(0), f"NOTICE names {rel} without its source"
