"""Tests for the release contract: version, changelog, and declared floors.

The suite cannot see git history, so these pin the invariants a release can
break without any code changing: a version bump with no changelog section (or
the reverse), and a raised dependency floor nobody wrote down.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from recoverage import __version__

# Walk up for the manifest rather than assuming a parent depth: the suite runs
# from the repo root, from tests/, and from an installed package's sdist.
_MANIFEST = (
    next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
    / "pyproject.toml"
)
_CHANGELOG = _MANIFEST.parent / "CHANGELOG.md"

# `## [1.6.0] - 2026-09-27` or `## [1.6.0]`, with or without an Unreleased.
_SECTION_RE = re.compile(r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>[\d-]+))?$", re.MULTILINE)


def _released_versions() -> list[str]:
    """Changelog section versions, newest first, excluding Unreleased."""
    return [
        m["version"]
        for m in _SECTION_RE.finditer(_CHANGELOG.read_text(encoding="utf-8"))
        if m["version"] != "Unreleased"
    ]


def _changelog() -> str:
    return _CHANGELOG.read_text(encoding="utf-8")


def _version_key(value: str) -> tuple[int, ...]:
    """Comparable form of a release segment, so 2.10.0 sorts above 2.9.0."""
    return tuple(int(part) for part in re.findall(r"\d+", value)) or (0,)


class TestChangelogTracksVersion:
    def test_unreleased_is_the_newest_section(self) -> None:
        """Unreleased sits above the shipped notes, so a pending entry is findable."""
        assert _changelog().index("## [Unreleased]") < _changelog().index("## [1.")

    def test_newest_released_section_is_the_package_version(self) -> None:
        """__version__ and the top shipped section cannot disagree.

        The failure this catches is a release commit that bumps one without the
        other: a package published as 1.7.0 whose notes still stop at 1.6.0,
        or notes for 1.7.0 against a package that still says 1.6.0.
        """
        assert _released_versions()[0] == __version__

    def test_every_released_version_appears_once(self) -> None:
        versions = _released_versions()
        assert len(versions) == len(set(versions))

    def test_released_versions_are_descending(self) -> None:
        """A release appended above a newer one misreports the release order."""
        keys = [tuple(int(p) for p in v.split(".")) for v in _released_versions()]
        assert keys == sorted(keys, reverse=True)

    def test_released_sections_are_dated(self) -> None:
        """Keep a Changelog's `- YYYY-MM-DD` on every shipped section."""
        undated = [
            m["version"]
            for m in _SECTION_RE.finditer(_changelog())
            if m["version"] != "Unreleased" and not m["date"]
        ]
        assert undated == []


class TestDeclaredFloorsAreRecorded:
    """A raised floor drops consumers on upgrade; the notes have to say so."""

    def test_python_floor_appears_in_the_changelog(self) -> None:
        floor = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["project"]["requires-python"]
        version = re.search(r">=\s*(\d+\.\d+)", floor)
        assert version, f"unreadable requires-python: {floor!r}"
        assert version[1] in _changelog()

    def test_documented_dependency_floors_match_the_manifest(self) -> None:
        """A release note naming `name>=X` must not understate the manifest's floor.

        The changelog records only the floors a release changed, so the check
        runs in the direction that can fail: every `name>=X` the notes claim has
        to be met or beaten by what pyproject actually requires.
        """
        deps = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["project"]["dependencies"]
        declared = {
            m[1]: _version_key(m[2])
            for m in (re.fullmatch(r"([\w.-]+)>=([\w.]+)", d) for d in deps)
            if m is not None
        }
        changelog = _changelog()
        # The highest floor the notes ever claim is the one to check.
        claimed: dict[str, tuple[int, ...]] = {}
        for name, floor in re.findall(r"`([\w.-]+)>=([\w.]+)`", changelog):
            claimed[name] = max(claimed.get(name, (0,)), _version_key(floor))
        assert claimed, "no dependency floor recorded in the changelog"
        assert [n for n, v in claimed.items() if declared.get(n, ()) < v] == []

    def test_requires_python_matches_the_classifiers(self) -> None:
        """A floor above a claimed classifier, or a classifier below it, misdirects install."""
        project = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["project"]
        floor = re.search(r">=\s*(\d+)\.(\d+)", project["requires-python"])
        assert floor, f"unreadable requires-python: {project['requires-python']!r}"
        minor = int(floor[2])
        classifiers = project["classifiers"]
        assert f"Programming Language :: Python :: {floor[1]}" in classifiers
        assert f"Programming Language :: Python :: {floor[1]}.{minor}" in classifiers
        assert f"Programming Language :: Python :: {floor[1]}.{minor + 1}" in classifiers

    def test_unreleased_uses_canonical_section_headings(self) -> None:
        """Keep a Changelog headings, so a reader's tool groups the entries."""
        unreleased = _changelog().split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        headings = re.findall(r"^### (.+)$", unreleased, re.MULTILINE)
        assert headings
        for heading in headings:
            assert heading in {
                "Added",
                "Breaking",
                "Changed",
                "Deprecated",
                "Fixed",
                "Removed",
                "Security",
            }
