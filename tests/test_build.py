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
import stat
import tarfile
import tempfile
import tomllib
from pathlib import Path

_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_MAKEFILE = (_ROOT / "Makefile").read_text(encoding="utf-8")
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


class TestReproducibleBuild:
    def test_the_build_recipe_pins_time_locale_and_timezone(self) -> None:
        """Without all three the artifact carries the build host's clock,
        locale and timezone, and two builds of one commit disagree."""
        recipe = _MAKEFILE.split("\nbuild:", 1)[1].split("\n\n", 1)[0]
        for var in ("SOURCE_DATE_EPOCH", "LC_ALL=C", "TZ=UTC"):
            assert var in recipe, f"the build recipe does not export {var}"
        assert "normalize_sdist.py" in recipe, "the sdist is not normalized after the build"

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
