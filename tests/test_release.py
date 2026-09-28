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
_INIT = _MANIFEST.parent / "src" / "recoverage" / "__init__.py"

#: The documents that restate the shipped version: the supported-versions table
#: in `SECURITY.md` and the scope line in `docs/THREAT_MODEL.md`. Both name a
#: release a reader is being asked to judge a vulnerability against, so a
#: version bump has to carry them.
_VERSION_DOCS = (_MANIFEST.parent / "SECURITY.md", _MANIFEST.parent / "docs" / "THREAT_MODEL.md")

#: A `src/recoverage/__init__.py:40` style pointer at where the version is
#: written, and a `__version__ = "3.0.0"` literal quoting its value.
_VERSION_LOCATION_RE = re.compile(r"`src/recoverage/__init__\.py:(?P<line>\d+)`")
_VERSION_QUOTE_RE = re.compile(r'`__version__ = "(?P<version>[^"]+)"`')
_VERSION_TAG_RE = re.compile(r"`v(?P<version>\d+\.\d+\.\d+)`")

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


class TestDocumentedVersionTracksThePackage:
    """The documents that restate the version are read by someone deciding
    whether a release is in scope, and a release bump does not touch them.

    `SECURITY.md` answers "which versions get fixes" and `docs/THREAT_MODEL.md`
    answers "which build was reviewed"; both name a version literal, and both
    point at the line in `__init__.py` that holds it. Every release so far
    moved `__version__` and the changelog and left these three numbers behind,
    so they are read here against the package instead.
    """

    def test_the_quoted_version_is_the_package_version(self) -> None:
        quoted: list[str] = []
        for doc in _VERSION_DOCS:
            quoted += _VERSION_QUOTE_RE.findall(doc.read_text(encoding="utf-8"))
        assert quoted, f"no document quotes the `__version__` line: {_VERSION_DOCS}"
        assert set(quoted) == {__version__}, (
            f"a document quotes __version__ {sorted(set(quoted))}, the package is {__version__}"
        )

    def test_the_tag_named_is_the_shipped_release(self) -> None:
        policy = (_MANIFEST.parent / "SECURITY.md").read_text(encoding="utf-8")
        tags = _VERSION_TAG_RE.findall(policy)
        assert tags == [__version__], (
            f"SECURITY.md names the released tag v{tags}, the package is {__version__}"
        )

    def test_the_supported_line_is_the_current_major(self) -> None:
        policy = (_MANIFEST.parent / "SECURITY.md").read_text(encoding="utf-8")
        match = re.search(r"current release line is `(?P<major>\d+)\.x`", policy)
        assert match, "SECURITY.md no longer states the supported release line"
        assert match["major"] == __version__.split(".", 1)[0], (
            f"SECURITY.md supports the {match['major']}.x line, the package is {__version__}"
        )

    def test_the_pointer_lands_on_the_assignment(self) -> None:
        source = _INIT.read_text(encoding="utf-8").splitlines()
        for doc in _VERSION_DOCS:
            for line in _VERSION_LOCATION_RE.findall(doc.read_text(encoding="utf-8")):
                assert source[int(line) - 1].startswith("__version__ = "), (
                    f"{doc.name} points at src/recoverage/__init__.py:{line}, "
                    f"which is {source[int(line) - 1].strip()!r}"
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


def _upgrade_guide() -> str:
    return (_MANIFEST.parent / "docs" / "UPGRADING.md").read_text(encoding="utf-8")


def _unreleased() -> str:
    """The `[Unreleased]` block, without the next section heading."""
    return _changelog().split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]


class TestUpgradeGuideCoversEveryMajor:
    """A `Breaking` group with no upgrade note is a release nobody can take.

    The changelog says what changed; it is read release by release, and a
    reader arriving at a deployment to do an upgrade wants the before, the
    after and the thing to change, gathered in one place. Three majors had
    shipped and nothing carried that, and a fourth breaking release was already
    staged. `docs/UPGRADING.md` is that place, and this class is the gate that
    keeps it one: a major that ships a `Breaking` group and has no section
    there fails the suite rather than shipping an upgrade path nobody wrote.
    """

    def test_the_guide_sections_the_breaking_releases(self) -> None:
        breaking = {version for version, body in _release_sections() if "### Breaking" in body}
        assert breaking, "no shipped section carries a Breaking group to check"
        headings = set(_upgrade_guide_sections())
        assert breaking <= headings, (
            f"docs/UPGRADING.md has no section for {sorted(breaking - headings)}, "
            "whose changes break a consumer"
        )

    def test_the_gate_fires_on_a_major_with_no_section(self) -> None:
        """A guard nothing has seen fail is not known to work."""
        guide = "## Before upgrading\n\n## [2.0.0]\n\n- one\n\n## [3.0.0]\n\n- two\n"
        headings = set(re.findall(r"^## \[([^\]]+)\]$", guide, re.MULTILINE))
        assert headings == {"2.0.0", "3.0.0"}
        assert ({"2.0.0", "4.0.0"} - headings) == {"4.0.0"}

    def test_the_pending_change_is_in_the_guide_before_it_ships(self) -> None:
        """The Unreleased block is the release being prepared, not a draft.

        Its `Breaking` entries are the ones a reader is about to meet, and the
        guide is the only place that gathers the before and the after. Notes
        written after the tag are notes nobody reads, so the section has to
        exist while the changes are still staged.
        """
        if "### Breaking" not in _unreleased():
            return
        assert "Unreleased" in _upgrade_guide_sections(), (
            "the Unreleased section carries a Breaking group and docs/UPGRADING.md "
            "has no section for it"
        )


def _upgrade_guide_sections() -> list[str]:
    """The release headings the upgrade guide carries, in document order.

    The guide writes its per-release headings the way the changelog does, so
    the same parser reads both and a release can be checked against its
    section by version. The guide's own prose headings (`## Before
    upgrading`) are not bracketed and so are not one: matching them here would
    let a heading that names no release satisfy the gate.
    """
    return re.findall(r"^## \[([^\]]+)\]$", _upgrade_guide(), re.MULTILINE)
