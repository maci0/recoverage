"""Tests for the release contract: version, changelog, and declared floors.

The suite cannot see git history, so these pin the invariants a release can
break without any code changing: a version bump with no changelog section (or
the reverse), and a raised dependency floor nobody wrote down.
"""

from __future__ import annotations

import json
import re
import tomllib
from itertools import pairwise
from pathlib import Path

from recoverage import __version__

# Walk up for the manifest rather than assuming a parent depth: the suite runs
# from the repo root, from tests/, and from an installed package's sdist.
_MANIFEST = (
    next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
    / "pyproject.toml"
)
_CHANGELOG = _MANIFEST.parent / "CHANGELOG.md"
_MAN_PAGE = _MANIFEST.parent / "man" / "recoverage.1"

#: The `.TH` header's version field: `.TH RECOVERAGE 1 "date" "recoverage X.Y.Z" "User Commands"`.
_TH_VERSION_RE = re.compile(
    r'^\.TH\s+\S+\s+\d+\s+"[^"]*"\s+"recoverage\s+(?P<version>[^"]+)"', re.MULTILINE
)


# `## [1.6.0] - 2026-09-27` or `## [1.6.0]`, with or without an Unreleased.
_SECTION_RE = re.compile(r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>[\d-]+))?$", re.MULTILINE)

# Keep a Changelog's impact groups, in the order a reader wants them: what is
# new, what breaks, what moved, what was wrong, what is gone. A release with
# two `### Changed` headings splits one group in two, and a release with
# `Breaking` below `Fixed` buries it.
_CANONICAL_GROUPS = (
    "Added",
    "Breaking",
    "Changed",
    "Deprecated",
    "Fixed",
    "Removed",
    "Security",
)


def _released_versions() -> list[str]:
    """Changelog section versions, newest first, excluding Unreleased."""
    return [
        m["version"]
        for m in _SECTION_RE.finditer(_CHANGELOG.read_text(encoding="utf-8"))
        if m["version"] != "Unreleased"
    ]


def _changelog() -> str:
    return _CHANGELOG.read_text(encoding="utf-8")


def _release_sections() -> list[tuple[str, str]]:
    """Every shipped section as `(version, body)`, newest first.

    The body starts at the end of the heading line, so `## [` in an entry's
    prose cannot end one section early, and it excludes the next heading.
    """
    text = _changelog()
    matches = list(_SECTION_RE.finditer(text))
    sections = []
    for index, match in enumerate(matches):
        if match["version"] == "Unreleased":
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections.append((match["version"], text[match.end() : end]))
    return sections


def _version_key(value: str) -> tuple[int, ...]:
    """Comparable form of a release segment, so 2.10.0 sorts above 2.9.0."""
    return tuple(int(part) for part in re.findall(r"\d+", value)) or (0,)


def _major(value: str) -> int:
    """The SemVer major of a release section heading."""
    return _version_key(value)[0]


def _breaking_in_non_major(sections: list[tuple[str, str]]) -> list[str]:
    """Shipped versions whose `Breaking` group did not come with a major bump.

    The oldest section has no predecessor to bump from, so it is not compared.
    """
    return [
        version
        for (version, body), (previous, _) in pairwise(sections)
        if "### Breaking" in body and _major(version) <= _major(previous)
    ]


def _groups_are_canonical(body: str) -> bool:
    """Keep a Changelog group headings: known names, once each, in impact order.

    A repeated heading splits one group in two, and a reader's tool, and the
    `Breaking` marker a release is gated on, only see the first one.
    """
    headings = re.findall(r"^### (.+)$", body, re.MULTILINE)
    if any(h not in _CANONICAL_GROUPS for h in headings):
        return False
    if len(headings) != len(set(headings)):
        return False
    return headings == sorted(headings, key=_CANONICAL_GROUPS.index)


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

    def test_no_entry_opens_a_blockquote(self) -> None:
        """Every entry is a list item, so a reader's parser sees it as one.

        A stray `>` in front of a bullet makes the whole entry quoted prose: it
        renders as a continuation of the entry above it and disappears from the
        release notes, which is where a reader looks for what to change.
        """
        quoted = [n for n, line in enumerate(_changelog().splitlines(), 1) if line.startswith(">")]
        assert quoted == [], f"changelog line(s) opening a blockquote: {quoted}"


class TestShippedArtifactsNameTheVersion:
    """The man page carries the version in its `.TH` header, and it is the
    only documentation a package index hands an installed copy. Nothing kept it
    with `__version__`, so a release that bumps the package and forgets the
    header ships a wheel whose man page names the release before it.
    """

    def test_the_man_page_names_the_package_version(self) -> None:
        match = _TH_VERSION_RE.match(_MAN_PAGE.read_text(encoding="utf-8"))
        assert match, "no .TH header naming a version, so man(1) renders none"
        assert match["version"] == __version__, (
            f"man page names recoverage {match['version']}, the package is {__version__}"
        )

    def test_the_gate_fires_on_a_header_one_release_behind(self) -> None:
        """A guard nothing has seen fail is not known to work."""
        stale = '.TH RECOVERAGE 1 "2026-09-29" "recoverage 1.0.0" "User Commands"\n.SH NAME\n'
        assert _TH_VERSION_RE.match(stale)["version"] == "1.0.0"
        assert _TH_VERSION_RE.match(".SH NAME\n") is None


class TestBreakingEntriesMatchTheVersionBump:
    """A `Breaking` group and the version that ships it cannot disagree.

    The group is the only record a consumer gets that an upgrade needs
    migration, and the version is what they pin against. A `Breaking` entry
    shipped in a minor or patch tells them a release is safe to take when it
    is not: `server.resolve_targets` losing an element of its return tuple
    raises `ValueError` at import time in the consumer, not a warning.

    The policy this enforces is in `AGENTS.md` (Releases): a change to a
    public HTTP response field, a CLI flag, or a function another module
    imports needs a major. 1.5.0 shipped a dropped response field
    (`cells.id`) under `Changed`, and this class would not have seen it,
    because the mislabel is invisible here; what it does pin is the
    invariant from then on.
    """

    def test_a_breaking_entry_lands_in_a_major_bump(self) -> None:
        offenders = _breaking_in_non_major(_release_sections())
        assert offenders == [], f"Breaking entries in a non-major bump: {offenders}"

    def test_the_gate_fires_on_a_minor_that_ships_a_breaking_entry(self) -> None:
        """A guard nothing has seen fail is not known to work."""
        breaking = "\n\n### Breaking\n\n- a response field went.\n"
        fixed = "\n\n### Fixed\n\n- a fix.\n"
        # A minor and a patch carrying a Breaking group, and a major carrying one.
        assert _breaking_in_non_major([("1.7.0", breaking), ("1.6.0", fixed)]) == ["1.7.0"]
        assert _breaking_in_non_major([("1.6.1", breaking), ("1.6.0", fixed)]) == ["1.6.1"]
        assert _breaking_in_non_major([("2.0.0", breaking), ("1.6.0", fixed)]) == []
        assert _breaking_in_non_major([("1.7.0", fixed), ("1.6.0", fixed)]) == []


class TestSingleVersionSource:
    """`__version__` is the one place a recoverage version is written.

    A second declaration is a second answer: `package.json` carried
    `1.0.0` beside a package at `3.0.0`, and nothing read it, so it stayed
    behind through every release. The root manifest is private tooling that is
    never published, so it declares no version at all rather than one that can
    only drift.
    """

    def test_the_python_manifest_takes_its_version_from_the_package(self) -> None:
        project = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["project"]
        assert project.get("dynamic") == ["version"], "pyproject no longer reads __version__"
        assert "version" not in project, "a literal version in pyproject is a second source"

    def test_the_frontend_manifest_declares_no_version(self) -> None:
        manifest = json.loads((_MANIFEST.parent / "package.json").read_text(encoding="utf-8"))
        assert "version" not in manifest, (
            f"package.json declares version {manifest.get('version')!r}, which the wheel "
            f"does not carry: __version__ is {__version__}"
        )


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
        """Keep a Changelog headings, so a reader's tool groups the entries.

        A release moves every entry into the shipped section, so an empty
        Unreleased block is the steady state, not a missing group.
        """
        unreleased = _changelog().split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        headings = re.findall(r"^### (.+)$", unreleased, re.MULTILINE)
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

    def test_unreleased_groups_appear_once_and_in_canonical_order(self) -> None:
        """One heading per group, in impact order.

        A repeated heading silently splits a group: a reader's tool, and the
        `Breaking` marker a release is gated on, only see the first one. The
        shipped Unreleased section carried two `### Changed` blocks, the
        second holding the asset-ETag and palette notes.
        """
        unreleased = _changelog().split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        headings = re.findall(r"^### (.+)$", unreleased, re.MULTILINE)
        duplicates = sorted({h for h in headings if headings.count(h) > 1})
        assert duplicates == [], f"repeated changelog group(s): {duplicates}"
        assert headings == sorted(headings, key=_CANONICAL_GROUPS.index)


class TestShippedSectionsUseCanonicalGroups:
    """A release moves the Unreleased entries into a section; that is the step
    that can drop a group name, repeat one, or reorder them, and it is the only
    place the move happens. Nothing checked the result: the two Unreleased
    checks above read the block a release is about to empty.
    """

    def test_shipped_sections_group_their_entries_the_same_way(self) -> None:
        offenders = [
            version for version, body in _release_sections() if not _groups_are_canonical(body)
        ]
        assert offenders == [], f"non-canonical group headings in: {offenders}"

    def test_the_gate_fires_on_a_split_and_a_misordered_group(self) -> None:
        """A guard nothing has seen fail is not known to work."""
        good = "\n\n### Added\n\n- a.\n\n### Breaking\n\n- b.\n\n### Fixed\n\n- c.\n"
        assert _groups_are_canonical(good) is True
        split = "\n\n### Changed\n\n- a.\n\n### Changed\n\n- b.\n"
        assert _groups_are_canonical(split) is False
        misordered = "\n\n### Fixed\n\n- a.\n\n### Added\n\n- b.\n"
        assert _groups_are_canonical(misordered) is False
        unknown = "\n\n### Miscellaneous\n\n- a.\n"
        assert _groups_are_canonical(unknown) is False
