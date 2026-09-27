"""Tests for how the tree pins what it depends on.

rebrew is a path dependency, so the checkout that satisfies
`[tool.uv.sources]` is fetched by a script rather than resolved from a
registry. Nothing in the package code runs at test time to check that fetch,
so these pin the invariants a pin can break without any code changing: two
mechanisms that disagree about which rebrew is the dependency, a Makefile
whose pin has drifted from the script CI runs, and a checked-in copy of a
third-party preset whose license and origin are no longer recorded.
"""

from __future__ import annotations

import json
import re
from itertools import pairwise
from pathlib import Path

_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_CI_YML = _ROOT / ".github" / "workflows" / "ci.yml"
_CLONE_SCRIPT = _ROOT / "tools" / "ci_clone_rebrew.sh"
_MAKEFILE = _ROOT / "Makefile"
_README = _ROOT / "README.md"
_PACKAGE_JSON = _ROOT / "package.json"
_FLATTEN = _ROOT / "tools" / "flatten-rikalabs-strict.py"
_DERIVED_PRESET = _ROOT / "tools" / "oxlint" / "rikalabs-strict.json"

# A CI job header: two spaces, a name, a colon, and nothing else on the line.
_JOB_RE = re.compile(r"^  (?P<name>[a-z][a-z0-9-]*):$", re.MULTILINE)
_PINS = {"REBREW_REF": "v2.13.1", "REBREW_SHA": "d2d67c870df79214320f16b1cba1b0f6086605a7"}


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
        """Every installing job fetches rebrew by running the pinned script.

        A second mechanism (an inline `git clone`, or an action that carries
        its own ref input) fetches the same path dependency from a pin nothing
        else checks, and whichever runs last silently decides which rebrew
        the suite tested. The script is that single mechanism: it holds the
        tag and commit, `make clone-rebrew` runs it, and every job runs it.
        """
        installing = {n: b for n, b in _jobs().items() if "uv sync" in b}
        assert installing, "no CI job runs uv sync; the check below would pass vacuously"
        for name, body in installing.items():
            assert "tools/ci_clone_rebrew.sh" in body, (
                f"job {name} never materializes the sibling checkout"
            )
            assert not re.search(r"git clone.*rebrew", body), f"job {name} clones rebrew itself"
            for var in _PINS:
                assert var not in body, f"job {name} carries {var}; the script owns the pin"
        assert not (_ROOT / ".github" / "actions").exists(), (
            "a local action fetched the sibling rebrew; the script is the one mechanism"
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
        assert "package.json" in flatten and "EXPECTED_LICENSE" in flatten.split("def main")[-1]
