"""Tests for the artifact build: what ships, and that it ships reproducibly.

`make build` is the one command that produces the distribution, and nothing
else checks it: no CI job builds a wheel, so a file missing from
`[tool.setuptools.package-data]` (a vendored asset the server serves) would
only be found by a user installing the package. These tests pin the two
properties that cannot be seen from the source tree: the manifest covers every
asset that ships, and a rebuild of one commit normalizes to the same bytes.
"""

from __future__ import annotations

import fnmatch
import importlib.util
import io
import os
import re
import stat
import tarfile
import tempfile
import tomllib
from pathlib import Path

import pytest

_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_MAKEFILE = (_ROOT / "Makefile").read_text(encoding="utf-8")
_CI_YML = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
_ASSETS = _ROOT / "src" / "recoverage" / "assets"
_SCRATCH = _ROOT / ".scratch"
#: Arbitrary but fixed, so a normalized archive's bytes are a constant the test
#: can compare across runs: 2001-09-09T01:46:40Z.
EPOCH = 1_000_000_000
_ROOT_NAME = "recoverage-1.6.0"
_BUILD_CONSTRAINTS = _ROOT / "build-constraints.txt"
_ENTRIES = (
    # (name, mode, body); the third entry is executable, the second is not.
    (_ROOT_NAME, 0o700, None),
    (f"{_ROOT_NAME}/pyproject.toml", 0o644, b"[project]\n"),
    (f"{_ROOT_NAME}/src/recovery", 0o755, b"print('x')\n"),
)


def _normalizer():
    """tools/normalize_sdist.py, imported by path (tools/ is a script dir)."""
    spec = importlib.util.spec_from_file_location(
        "normalize_sdist", _ROOT / "tools" / "normalize_sdist.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scratch_dir() -> tempfile.TemporaryDirectory[str]:
    _SCRATCH.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=_SCRATCH)


def _build_sdist(path: Path, mtime: int, uid: int) -> None:
    """An sdist-shaped archive whose only variance is build-host metadata."""
    with tarfile.open(path, "w:gz") as tar:
        for name, mode, body in _ENTRIES:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.uid = info.gid = uid
            info.uname = info.gname = "builder"
            info.mtime = mtime
            if body is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))


class TestManifestCoversShippedFiles:
    def test_every_asset_ships_in_the_wheel(self) -> None:
        """A vendored asset the server serves but the manifest omits is a 404
        for every user of the installed package, while the source tree still
        looks complete."""
        manifest = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        patterns = manifest["tool"]["setuptools"]["package-data"]["recoverage"]
        assets = {p.name for p in _ASSETS.iterdir() if p.is_file()}
        assert assets, "no assets to check; the pattern check would pass vacuously"
        missing = {
            name
            for name in assets
            if not any(
                fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(f"assets/{name}", pattern)
                for pattern in patterns
            )
        }
        assert not missing, f"assets no package-data pattern picks up: {sorted(missing)}"


class TestTypingMarker:
    """The wheel ships a fully annotated package, so it ships the PEP 561
    marker that says so.

    The marker is invisible from the source tree once it is there and easy to
    drop: nothing at runtime reads it, and the module passes either way, so the
    only thing that notices is a consumer's type checker, which then treats
    every import from `recoverage` as unannotated and stops checking the
    signatures this tree gates under mypy --strict.
    """

    @staticmethod
    def _patterns() -> list[str]:
        manifest = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        return manifest["tool"]["setuptools"]["package-data"]["recoverage"]

    def test_the_marker_is_in_the_tree(self) -> None:
        assert (_ROOT / "src" / "recoverage" / "py.typed").is_file(), (
            "src/recoverage/py.typed is gone, so the installed package reads as untyped"
        )

    def test_a_package_data_pattern_ships_it(self) -> None:
        patterns = self._patterns()
        assert any(
            fnmatch.fnmatchcase("py.typed", pattern)
            or fnmatch.fnmatchcase("recoverage/py.typed", pattern)
            for pattern in patterns
        ), f"no package-data pattern picks up py.typed: {patterns}"


class TestSdistContents:
    """The sdist is what a rebuild machine unpacks, so it has to carry the
    inputs the build reads and nothing it cannot run.

    Both directions were wrong and neither is visible from the git checkout:
    distutils' default sdist picks up `tests/test_*.py` and nothing else from
    `tests/`, so the archive carried sixteen modules whose `conftest.py` and
    `coverage_fixture.py` were absent, and it did not carry
    `build-constraints.txt`, so a wheel rebuilt from the published archive
    resolved setuptools against the index instead of the pin the bytes were
    verified under. Read through the file, not by running a build: a test that
    shells out to `uv build` is a test that needs the sibling rebrew checkout
    to have run at all.
    """

    @staticmethod
    def _rules() -> list[str]:
        return (_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()

    def test_the_backend_pin_ships_in_the_sdist(self) -> None:
        assert "include build-constraints.txt" in self._rules(), (
            "build-constraints.txt pins setuptools, which uv resolves outside uv.lock; "
            "an sdist without it cannot be rebuilt under the pin"
        )

    def test_the_unrunnable_test_suite_is_pruned(self) -> None:
        assert "prune tests" in self._rules(), (
            "distutils ships tests/test_*.py without their conftest.py and "
            "coverage_fixture.py, so the sdist carries a suite that cannot collect"
        )

    def test_the_changelog_ships_in_the_sdist(self) -> None:
        """A downstream packager takes the release notes from the archive it
        unpacks, and the wheel metadata already points a reader at one."""
        assert "include CHANGELOG.md" in self._rules(), (
            "the sdist carries the code and no changelog, so a packager writing "
            "an upstream changelog has nothing to summarize"
        )

    def test_the_generated_egg_info_is_pruned(self) -> None:
        """setuptools writes it into the tree it builds from and the default
        sdist ships it: a second PKG-INFO, the unpacked requirements, build
        metadata, all gitignored here. A rebuild regenerates it, so keeping it
        in the archive buys nothing."""
        assert "prune src/recoverage.egg-info" in self._rules(), (
            "the sdist ships a leftover src/recovery.egg-info/ from whichever "
            "build ran last, not what this commit contains"
        )

    def test_the_suite_is_more_than_its_own_fixtures(self) -> None:
        """`prune tests` is only worth having while the default sdist would
        pick up test modules the archive cannot run. A suite reduced to a
        single file is a signal to drop the rule rather than keep it on faith.
        """
        modules = sorted(p.name for p in (_ROOT / "tests").glob("test_*.py"))
        assert len(modules) > 1, (
            f"tests/ holds {modules} and nothing else; `prune tests` in MANIFEST.in "
            "has no reason to exist and neither does the test asserting it"
        )


class TestManPage:
    """The console script is the only thing a package index hands a user, so
    the man page ships with the wheel and names what `--help` names.

    Read through the file and the CLI's own registration rather than by
    rendering one: a man page is the only documentation an installed copy
    has, and it drifts from the flags the moment a flag is added.
    """

    #: The two fuzz knobs are in `config.KNOWN_VARS` so an operator who
    #: exported them can still run a command, but they drive the test suite
    #: and no subcommand reads them.
    _NOT_A_SETTING = frozenset({"RECOVERAGE_FUZZ_ITERATIONS", "RECOVERAGE_FUZZ_SEED"})

    @staticmethod
    def _page() -> str:
        """The page as its reader sees it: roff spells a literal hyphen
        `\\-`, so a flag is matched against the unescaped text."""
        return (_ROOT / "man" / "recoverage.1").read_text(encoding="utf-8").replace("\\-", "-")

    @staticmethod
    def _cli() -> tuple[set[str], set[str]]:
        """The subcommand names and the long flags `recoverage --help`
        renders, read off the click command typer builds from the app."""
        from typer.main import get_command

        from recoverage.cli import app

        group = get_command(app)
        names = set(group.commands)
        flags = {opt for param in group.params for opt in param.opts if opt.startswith("--")}
        for command in group.commands.values():
            flags |= {opt for param in command.params for opt in param.opts if opt.startswith("--")}
        return names, flags

    def test_the_man_page_is_a_man_page(self) -> None:
        raw = (_ROOT / "man" / "recoverage.1").read_text(encoding="utf-8")
        assert raw.startswith(".TH RECOVERAGE 1"), "no man header, so man(1) cannot render it"
        assert ".SH NAME" in raw and ".SH SYNOPSIS" in raw and ".SH DESCRIPTION" in raw

    def test_it_ships_in_the_wheel_and_the_sdist(self) -> None:
        manifest = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        installed = manifest["tool"]["setuptools"]["data-files"]
        assert installed.get("share/man/man1") == ["man/recoverage.1"], (
            f"the man page installs nowhere: {installed}"
        )
        assert "include man/recoverage.1" in TestSdistContents._rules(), (
            "a wheel rebuilt from the sdist ships the entry point and no man page"
        )

    def test_every_subcommand_and_flag_is_documented(self) -> None:
        names, flags = self._cli()
        assert names and flags, "no CLI read from typer; the checks below would pass vacuously"
        page = self._page()
        assert not sorted(name for name in names if f"\n.B {name}\n" not in page), (
            "a subcommand the CLI registers is missing from the man page"
        )
        missing = sorted(flag for flag in flags if flag not in page)
        assert not missing, f"flags the CLI registers that the man page omits: {missing}"

    def test_every_setting_the_server_reads_is_documented(self) -> None:
        from recoverage.config import KNOWN_VARS

        page = self._page()
        missing = sorted(name for name in KNOWN_VARS - self._NOT_A_SETTING if name not in page)
        assert not missing, f"settings the man page does not document: {missing}"


class TestLongDescriptionLinksResolveWhereItIsRendered:
    """README.md is the wheel's long description, and the wheel's long
    description is the index page.

    A relative target (`docs/mascot.png`, `NOTICE`, `../rebrew`) resolves
    against the repository when the README is read on GitHub and against
    `pypi.org/project/<name>/` when the same text is rendered as the project
    page, where every one of them is a 404. The screenshots are the whole
    point of the page, so a link that only works in one of its two homes is a
    broken artifact rather than a style question.
    """

    #: A target the index page can fetch. The blob host serves the file as
    #: stored; the raw host serves its bytes, which is what an image needs.
    _REPO_BLOB = "https://github.com/relumea/recovery/blob/main/"
    _REPO_RAW = "https://raw.githubusercontent.com/relumea/recovery/main/"
    _TARGET_RE = re.compile(r"\]\((?P<target>[^)\s]+)\)")

    @staticmethod
    def _relative_targets() -> list[str]:
        """Every link and image target that is not absolute and not an
        in-page anchor."""
        text = (_ROOT / "README.md").read_text(encoding="utf-8")
        return sorted(
            {
                match["target"]
                for match in TestLongDescriptionLinksResolveWhereItIsRendered._TARGET_RE.finditer(
                    text
                )
                if not match["target"].startswith(("#", "http://", "https://", "mailto:"))
            }
        )

    def test_no_target_is_relative(self) -> None:
        """The whole point: a target the index page cannot fetch is a link
        that works on GitHub and 404s on the page the README ships as.
        """
        assert not self._relative_targets(), (
            "README.md is the wheel's long description, so a relative target "
            f"resolves against the index page and 404s there: {self._relative_targets()}"
        )

    def test_every_repository_target_is_a_file_in_the_tree(self) -> None:
        """An absolute URL is only better than a relative one if the file is
        there: the page renders a broken image either way once the file moves
        and the URL does not.
        """
        text = (_ROOT / "README.md").read_text(encoding="utf-8")
        for match in self._TARGET_RE.finditer(text):
            target = match["target"]
            for prefix in (self._REPO_BLOB, self._REPO_RAW):
                if target.startswith(prefix):
                    path = target.removeprefix(prefix)
                    assert (_ROOT / path).is_file(), (
                        f"{target} names a file this commit does not have"
                    )


class TestShippedMetadataNamesItsAuthor:
    """Who wrote the package, as an installed copy can see it.

    The wheel's METADATA and the LICENSE beside it are the only authorship
    record a consumer gets, and a package with neither names nobody: the index
    page reads "unknown author" and the license grants its permission to
    no one at all.
    """

    #: `Copyright (c) 2026` with nothing after it is the form this tree
    #: shipped: a year and no holder, which is a notice rather than a grant.
    _COPYRIGHT_RE = re.compile(
        r"^Copyright \(c\) (?P<years>\d{4}([-,] *\d{4})*) (?P<holder>\S.*)$", re.MULTILINE
    )

    @classmethod
    def _holder(cls) -> str:
        text = (_ROOT / "LICENSE").read_text(encoding="utf-8")
        match = cls._COPYRIGHT_RE.search(text)
        assert match, (
            "the LICENSE ships in the wheel and carries no "
            f"'Copyright (c) <year> <holder>' line: {text.splitlines()[:3]}"
        )
        holder = match["holder"].strip()
        assert holder, "the LICENSE names a copyright year and nobody to hold it"
        return holder

    def test_the_license_names_its_copyright_holder(self) -> None:
        """Without a holder the MIT permission is granted to no one, so the
        file the artifact ships as its license permits nothing.
        """
        assert self._holder()

    def test_the_declared_author_is_the_license_holder(self) -> None:
        """`authors` is what becomes the wheel's Author field, and LICENSE is
        what a distributor reads to attribute the code. One name, or the
        artifact contradicts itself about who wrote it.
        """
        project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        names = sorted(entry["name"] for entry in project.get("authors", []) if entry.get("name"))
        assert names, (
            "pyproject.toml declares no author, so the index lists the package "
            "as authored by nobody"
        )
        assert names == [self._holder()], (
            f"the declared author(s) {names} and the LICENSE holder "
            f"{self._holder()!r} are not the same name"
        )

    def test_the_python_3_only_classifier_is_declared(self) -> None:
        """`requires-python = ">=3.13"` refuses every other line at install
        time; the classifier is the same statement for a reader browsing the
        index, and a package with only per-minor entries reads as if it also
        supports 2.x.
        """
        project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        assert "Programming Language :: Python :: 3 :: Only" in project["classifiers"]


class TestReproducibleBuild:
    def test_the_build_recipe_pins_time_locale_and_timezone(self) -> None:
        """Without all three the artifact carries the build host's clock,
        locale and timezone, and two builds of one commit disagree."""
        recipe = _MAKEFILE.split("\nbuild:", 1)[1].split("\n\n", 1)[0]
        for var in ("SOURCE_DATE_EPOCH", "LC_ALL=C", "TZ=UTC"):
            assert var in recipe, f"the build recipe does not export {var}"
        assert "normalize_sdist.py" in recipe, "the sdist is not normalized after the build"

    def test_the_bundle_recipe_pins_locale_and_timezone(self) -> None:
        """`web-build` is a prerequisite of `build`, so it runs in its own
        shell and the recipe's exports do not reach it. The two files it writes
        are packaged inputs, so a bundle produced under a non-C locale or a
        non-UTC timezone is a wheel input no CI run byte-compared, and
        `check-bundle-clean` then reports the committed bundle as stale."""
        recipe = _MAKEFILE.split("\nweb-build:", 1)[1].split("\n\n", 1)[0]
        for var in ("LC_ALL=C", "TZ=UTC"):
            assert var in recipe, f"the bundle recipe does not export {var}"
        assert "bun run build:web" in recipe, "the bundle recipe no longer builds the bundle"

    def test_the_two_build_step_clears_what_it_extracts_into(self) -> None:
        """The second tree is extracted with tar and linked with ln, both of
        which MERGE into an existing destination: on a self-hosted runner or a
        retried step, where RUNNER_TEMP survives the run, a file deleted from
        the tracked tree since the last execution is still there and gets
        packaged, so the comparison is between two different trees and reports
        a difference that is not one. `ln -s` fails outright instead. Both
        need the destination gone first, which is what a build step that runs
        more than once has to guarantee."""
        step = _CI_YML.split("Build the distribution twice and compare", 1)[1]
        step = step.split("\n        env:", 1)[0]
        assert 'rm -rf -- "$work" "$first" "$RUNNER_TEMP/rebrew"' in step, (
            "the two-build step extracts and links into whatever RUNNER_TEMP "
            "holds, so a re-run compares two different trees"
        )
        assert 'mkdir -p -- "$first" "$work"' in step, "the cleared trees are not recreated"

    def test_the_build_recipe_refuses_an_asset_it_did_not_declare(self) -> None:
        """`[tool.setuptools.package-data]` is the glob `assets/*`, so the
        contents of the bundle directory ARE the wheel's shipped file list, and
        nothing clears that directory: Vite runs with `emptyOutDir` off because
        it also holds the hand-written `index.html`, `print.css` and
        `favicon.svg`. A scratch file, an editor backup or a leftover from a
        renamed output therefore sits where it was dropped and would ride into
        the artifact. The recipe checks the directory against the declared list
        before `uv build` runs, in both directions: a member that is not on the
        list is contamination, and one that is missing is a wheel serving
        nothing."""
        recipe = _MAKEFILE.split("\nbuild:", 1)[1].split("\n\n", 1)[0]
        assert "BUNDLE_ASSETS" in recipe, "the build recipe no longer checks the bundle directory"
        assert recipe.index("BUNDLE_ASSETS") < recipe.index("uv build"), (
            "the bundle directory is checked after the artifact is built, so a "
            "contaminated asset is already in it"
        )
        declared = set(_MAKEFILE.split("BUNDLE_ASSETS =", 1)[1].split("\n", 1)[0].split())
        assert declared, "BUNDLE_ASSETS is empty, so the check admits nothing and ships nothing"
        present = {p.name for p in _ASSETS.iterdir() if p.is_file()}
        assert present == declared, (
            f"the bundle directory and BUNDLE_ASSETS disagree: "
            f"only on disk {sorted(present - declared)}, only declared {sorted(declared - present)}"
        )

    def test_the_makefile_is_not_parallel(self) -> None:
        """Every target shares one `.venv`, one `node_modules` and one `dist/`,
        and `all` chains work that writes to all three in the order it declares
        them: `build` rewrites the bundle `check-bundle-clean` is the gate over.
        Make orders a prerequisite list under `-j` by nothing, so `make -j all`
        could run that gate against a file mid-write."""
        assert ".NOTPARALLEL:" in _MAKEFILE, (
            "the Makefile is parallel and its targets share the venv, node_modules and dist/"
        )

    def test_the_build_recipe_pins_the_backend_and_clears_stale_artifacts(self) -> None:
        """`uv build` resolves PEP 517 build requirements outside uv.lock, so
        an unconstrained `setuptools>=` is a floor, not a pin: the artifact
        bytes follow whatever PyPI served that day. Without --clear a wheel
        from an earlier version stays in dist/ beside the new one."""
        recipe = _MAKEFILE.split("\nbuild:", 1)[1].split("\n\n", 1)[0]
        assert "--build-constraints build-constraints.txt" in recipe, (
            "the build recipe does not pin the PEP 517 backend"
        )
        assert "--clear" in recipe, "the build recipe keeps artifacts from an earlier version"

    def test_the_build_constraints_file_pins_every_backend_exactly(self) -> None:
        """An exact `==` per backend is what makes the constraint a pin; a
        floor here reproduces the float the file exists to stop."""
        pins = [
            line.strip()
            for line in _BUILD_CONSTRAINTS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert pins, "build-constraints.txt names no backend, so it pins nothing"
        for pin in pins:
            assert "==" in pin, f"not an exact pin: {pin}"

    def test_the_build_constraints_satisfy_the_declared_floor(self) -> None:
        """The constraints file is a second source of truth for the backend
        version, so it can contradict the floor in pyproject.toml. setuptools
        77 is the first release implementing PEP 639, which the SPDX license
        field needs; validating against an older backend fails the build."""
        manifest = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        floor = next(
            req.removeprefix("setuptools>=")
            for req in manifest["build-system"]["requires"]
            if req.startswith("setuptools")
        )
        pins = {
            line.strip().removeprefix("setuptools==")
            for line in _BUILD_CONSTRAINTS.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("setuptools==")
        }
        assert pins, "build-constraints.txt does not pin setuptools"
        for pin in pins:
            assert tuple(int(p) for p in pin.split(".")) >= tuple(
                int(p) for p in floor.split(".")
            ), f"setuptools=={pin} is below the >= {floor} floor in pyproject.toml"

    def test_source_date_epoch_defaults_to_the_commit_not_the_clock(self) -> None:
        assert "git log -1 --format=%ct" in _MAKEFILE
        assert "date +%s" not in _MAKEFILE

    def test_normalizing_twice_yields_the_same_bytes(self) -> None:
        """The point of the normalizer: the host metadata it strips is the
        only thing left that can differ between two builds."""
        normalize = _normalizer()
        with _scratch_dir() as td:
            digests = []
            for index, (mtime, uid) in enumerate(((1_600_000_000, 1000), (1_700_000_000, 0))):
                archive = Path(td) / f"run{index}.tar.gz"
                _build_sdist(archive, mtime, uid)
                normalize.normalize_archive(archive, EPOCH)
                digests.append(archive.read_bytes())
            assert digests[0] == digests[1]

    def test_normalized_members_carry_the_stamp_and_no_owner(self) -> None:
        normalize = _normalizer()
        with _scratch_dir() as td:
            archive = Path(td) / "run.tar.gz"
            _build_sdist(archive, 1_600_000_000, 1000)
            normalize.normalize_archive(archive, EPOCH)
            with tarfile.open(archive) as tar:
                members = tar.getmembers()
                bodies = {m.name: tar.extractfile(m).read() for m in members if m.isreg()}

        assert [m.name for m in members] == sorted(m.name for m in members)
        for member in members:
            assert member.mtime == EPOCH
            assert (member.uid, member.gid, member.uname, member.gname) == (0, 0, "", "")
        modes = {member.name: stat.S_IMODE(member.mode) for member in members}
        assert modes[_ROOT_NAME] == 0o755
        assert modes[f"{_ROOT_NAME}/src/recovery"] == 0o755, "the executable bit is dropped"
        assert modes[f"{_ROOT_NAME}/pyproject.toml"] == 0o644
        assert bodies == {name: body for name, _, body in _ENTRIES if body is not None}

    def test_the_normalizer_refuses_to_run_without_a_stamp(self) -> None:
        normalize = _normalizer()
        with _scratch_dir() as td:
            archive = Path(td) / "run.tar.gz"
            _build_sdist(archive, 1_600_000_000, 1000)
            before = archive.read_bytes()
            saved = os.environ.pop("SOURCE_DATE_EPOCH", None)
            try:
                assert normalize.main(["normalize_sdist.py", td]) == 2
            finally:
                if saved is not None:
                    os.environ["SOURCE_DATE_EPOCH"] = saved
            assert archive.read_bytes() == before, "a refused run still rewrote the archive"

    @pytest.mark.parametrize(
        "raw",
        [
            "abc",
            "17.5",
            "1_700_000_000",  # int() reads this as 1700000000
            "-1",
            " 1700000000",  # str.strip is not applied here
            # Arabic-Indic digits, which int() reads as 1700000000 too. Spelled
            # as escapes so the lint rule that flags confusable characters does
            # not fire on the very string this test is about.
            "\u0661\u0667\u0660\u0660\u0660\u0660\u0660\u0660\u0660\u0660",
            "\N{SUPERSCRIPT TWO}",  # a digit to str.isdigit, not to int()
            "1700000000 ",
        ],
    )
    def test_the_stamp_parser_takes_ascii_decimal_only(self, raw: str) -> None:
        """A stamp that is not a plain ASCII run is refused, not coerced.

        `str.isdigit` accepts every Unicode decimal digit and every superscript,
        so a value pasted through a non-ASCII locale became a DIFFERENT epoch
        and stamped every member with it, and a superscript raised out of
        `int()` as a traceback instead of the refusal this is.
        """
        normalize = _normalizer()
        with _scratch_dir() as td:
            archive = Path(td) / "run.tar.gz"
            _build_sdist(archive, 1_600_000_000, 1000)
            before = archive.read_bytes()
            with pytest.MonkeyPatch.context() as mp:
                mp.setenv("SOURCE_DATE_EPOCH", raw)
                assert normalize.main(["normalize_sdist.py", td]) == 2
            assert archive.read_bytes() == before, "a refused run still rewrote the archive"
