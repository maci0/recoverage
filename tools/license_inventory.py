"""The licenses of the Python packages recoverage resolves, and a refusal.

`NOTICE` records the third-party code the wheel BUNDLES (the browser assets),
and `tools/bundled_js_inventory.py` holds that list against package.json,
bun.lock and NOTICE. Nothing did either for the Python half: `make python-sbom`
prints the resolved tree with hashes, which is what a vuln scanner reads, and a
hash says which version shipped without saying what a consumer may do with it.
This is the license half of the same inventory for the packages a consumer
INSTALLS, and the refusal is the point of it.

The closure is walked from `[project].dependencies` over `Requires-Dist`, so the
answer covers the transitive tree rather than the eight names the manifest
spells out, and it is read from the installed distributions' own metadata, so
the version printed is the one the environment resolved. That tree is wider
than the manifest: `rebrew` is a runtime import rather than a regen-only one,
and it brings certifi, lief, numpy, tree-sitter and python-flirt with it. A
license gate that only looked at the declared names would have called all of
those clean without ever reading one of them.

An `extra ==` marker is not followed. Those requirements are only pulled in by
a consumer who asks for the extra, so following one would report a package this
environment never installed (and, for `pygments`, one recoverage already
declares as an extra of its own). Any OTHER marker is followed: a requirement
behind a `python_version` or `sys_platform` guard is a package a consumer on
some other platform does install, and refusing a license is the side that has to
be right.

The allowlist is the permissive set, and an expression is allowed only when
every leaf of it is: numpy declares `BSD-3-Clause AND 0BSD AND MIT AND Zlib
AND CC0-1.0`, which is the bundled-vocabulary form rather than a choice, and
reading it as one unknown id would refuse a package five known licenses deep.
A copyleft id is deliberately absent. MPL-2.0 is the exception and it is named
here rather than smuggled in: certifi is MPL-2.0, it arrives with rebrew, and
MPL-2.0 is file-level copyleft, so a pip-installed dependency that a consumer
does not redistribute leaves recoverage's own MIT grant unaffected. A new
copyleft dependency has to be a decision about this project's licensing, not a
line this file quietly widens to make a run pass.

Usage: `python tools/license_inventory.py`, which prints the inventory to
stdout and exits non-zero naming every license it refuses.
"""

from __future__ import annotations

import sys
import tomllib
from importlib.metadata import Distribution, PackageNotFoundError, distribution
from pathlib import Path
from typing import NamedTuple

_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_MANIFEST = _ROOT / "pyproject.toml"

# The licenses a distribution in this tree may be under, in SPDX spelling.
_ALLOWED = frozenset(
    {
        "0BSD",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC0-1.0",
        "ISC",
        "MIT",
        "MPL-2.0",  # certifi, via rebrew. See the module docstring.
        "PSF-2.0",
        "Python-2.0",
        "Zlib",
    }
)

# A requirement guarded on an extra is only reachable by a consumer who asked
# for that extra, so it is not part of the tree this project resolves.
_EXTRA_MARKER = "extra =="

# `License` is a free-text field and predates the SPDX expression, so the
# spellings the packages in this tree actually use are translated here. A
# string that is neither translated nor already an allowed id is refused rather
# than guessed at, which is what forces a decision for a new dependency
# instead of letting a loose match wave it through. Both of these are the same
# license the two minifiers are read as, spelled the way their authors spelled
# it; neither is a guess.
_LICENSE_TEXT = {
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "ISC License": "ISC",
    "MIT License": "MIT",
}

# Distributions whose METADATA names no license at all, read off the package's
# own LICENSE file rather than assumed. The path is matched as a suffix of the
# distribution's recorded file list, so it survives a version bump instead of
# going stale, and the tool checks it resolved to a real file: an entry whose
# file has moved is a refusal rather than a claim nobody re-reads. Each is a
# reviewed decision; a new entry is not a fallback.
_UNDECLARED_METADATA = {
    "capstone": ("BSD-3-Clause", "capstone-5.0.9.dist-info/LICENSE.TXT"),
    "markdown-it-py": ("MIT", "markdown_it_py-4.2.0.dist-info/licenses/LICENSE"),
    "mdurl": ("MIT", "mdurl-0.1.2.dist-info/LICENSE"),
    "python-flirt": ("Apache-2.0", "python_flirt-0.10.0.dist-info/licenses/LICENSE.txt"),
    "tree-sitter": ("MIT", "tree_sitter-0.26.0.dist-info/licenses/LICENSE"),
}

# The characters that end a distribution name in a requirement line: the
# specifier's comparisons, the environment marker, the comma between several
# on one line, an extras bracket, and whitespace.
_NAME_END = "<>=!~,;([ \t"


class Entry(NamedTuple):
    """One distribution in the resolved tree, and the license it ships under."""

    name: str
    version: str
    license: str


def requirement_name(requirement: str) -> str:
    """The distribution name a requirement names, pin, extras and marker cut off.

    A requirement is `name[extra]specifier ; marker`, and only the first field
    names a distribution. The name ends at the first character that cannot be
    in one, so the manifest's `bottle>=0.13` and a `Requires-Dist` line both
    reduce to a name `importlib.metadata` can resolve.
    """
    end = len(requirement)
    for index, char in enumerate(requirement):
        if char in _NAME_END:
            end = index
            break
    return requirement[:end].strip()


def declared_roots() -> list[str]:
    """The runtime dependency names `[project].dependencies` declares.

    These are distribution names already, so no module-to-distribution mapping
    is needed: a project whose declared names were module names could not
    resolve one, and this tree declares distribution names.
    """
    project = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["project"]
    roots = []
    for specifier in project["dependencies"]:
        name = requirement_name(specifier)
        if name:
            roots.append(name)
    return roots


def _dependencies(dist: Distribution) -> list[str]:
    """The distribution names `dist` requires, minus the extra-guarded ones."""
    names = []
    for requirement in dist.requires or ():
        if _EXTRA_MARKER in requirement:
            continue
        name = requirement_name(requirement)
        if name:
            names.append(name)
    return names


def _walk(roots: list[str]) -> list[Distribution]:
    """Every distribution the roots resolve to, roots and transitives alike.

    Breadth-first over a seen set, so a cycle two packages declare terminates
    rather than recursing. A name the environment does not have is left out:
    the roots come from the manifest but the tree is read from what is actually
    installed, and a root that is missing is a broken environment rather than a
    license question.
    """
    found: dict[str, Distribution] = {}
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in found:
            continue
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            continue
        found[name] = dist
        pending.extend(_dependencies(dist))
    return [found[name] for name in sorted(found, key=str.lower)]


def _after_dist_info(path: str) -> str:
    """The part of a recorded path that follows its `<name>-<version>.dist-info`.

    The version is what changes when the package is bumped, so a check for "the
    LICENSE file is still there" has to drop the directory rather than compare
    it, or every bump invalidates a record that is still true.
    """
    _head, separator, tail = path.partition(".dist-info")
    if not separator:
        return path
    return tail.lstrip("/")


def _declared_license(dist: Distribution) -> str:
    """The license `_UNDECLARED_METADATA` records, once the file it names is checked.

    Returns an empty string when the entry is stale: a distribution that moves
    or renames its LICENSE file fails the run rather than leaving a claim in
    place that nobody re-reads.
    """
    entry = _UNDECLARED_METADATA.get((dist.metadata["Name"] or "").lower())
    if entry is None:
        return ""
    license_id, path = entry
    tail = _after_dist_info(path)
    recorded = [str(f) for f in dist.files or ()]
    if not any(_after_dist_info(f) == tail for f in recorded):
        return ""
    return license_id


def _license_of(dist: Distribution) -> str:
    """The license `dist` ships under, or an empty string when it names none.

    The SPDX expression is read first because it is the machine-readable field
    PEP 639 added; the free-text `License` is the older one and is translated
    through `_LICENSE_TEXT`. `Classifier: License ::` is not read: it is a
    coarse vocabulary a package stops updating, and reading it would accept a
    string the allowlist does not hold. It is what told this tree what
    capstone, python-flirt and tree-sitter actually are, so it is not nothing,
    but the file it points at is what the gate records.
    """
    declared = _declared_license(dist)
    if declared:
        return declared
    expression = dist.metadata.get("License-Expression")
    if expression:
        return str(expression).strip()
    text = dist.metadata.get("License")
    if text:
        return _LICENSE_TEXT.get(str(text).strip(), str(text).strip())
    return ""


def _leaves(expression: str) -> set[str]:
    """The license ids a compound SPDX expression names.

    `AND` and `OR` join them and parentheses group them; the tree uses neither
    grouping, so splitting on both words leaves the ids and nothing else, and an
    expression this cannot read still yields a token the allowlist does not
    hold, which is the refusing answer.
    """
    return {
        part.strip()
        for part in expression.replace("(", " ").replace(")", " ").split()
        if part.strip() not in {"AND", "OR"}
    }


def _refused(entries: list[Entry]) -> list[str]:
    """The entries whose license is not wholly on the allowlist, with the reason."""
    refused = []
    for entry in entries:
        if not entry.license:
            refused.append(f"{entry.name} {entry.version}: no license declared")
            continue
        unknown = sorted(_leaves(entry.license) - _ALLOWED)
        if unknown:
            reason = f"{entry.license} (not allowed: {', '.join(unknown)})"
            refused.append(f"{entry.name} {entry.version}: {reason}")
    return refused


def inventory() -> list[Entry]:
    """The resolved runtime tree, one entry per distribution, name-sorted."""
    return [
        Entry(
            name=dist.metadata["Name"] or "",
            version=dist.version,
            license=_license_of(dist),
        )
        for dist in _walk(declared_roots())
    ]


def main() -> int:
    """Print the inventory, and exit 1 naming every license that is refused."""
    entries = inventory()
    for entry in entries:
        print(f"{entry.name}=={entry.version} {entry.license or 'NO LICENSE DECLARED'}")
    refused = _refused(entries)
    if refused:
        print("\nrefused licenses:", file=sys.stderr)
        for line in refused:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"\n{len(entries)} distributions, every license on the allowlist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
