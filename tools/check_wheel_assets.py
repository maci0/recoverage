"""Check the assets a built wheel actually carries.

``make build`` checks ``BUNDLE_ASSETS`` against the bundle DIRECTORY before
``uv build`` runs, which catches contamination in the source tree and nothing
else. The wheel is the artifact a consumer installs, and it is built from the
sdist through ``[tool.setuptools.package-data]``: a glob, an sdist file list
and a MANIFEST.in rule all sit between the checked directory and the shipped
members, and none of them is the check. A member that stops being packaged
passes every gate here and is discovered by a user who installs the wheel and
gets a dashboard that serves nothing.

This is the one place the shipped list is read off the artifact itself, in
both directions: a declared asset the wheel does not carry, and a carried
asset nobody declared. The declared list comes from the command line, so the
Makefile's ``BUNDLE_ASSETS`` stays the only place it is written down.

Usage::

    python tools/check_wheel_assets.py dist --asset app.js --asset style.css
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

#: Where `[tool.setuptools.package-data]`'s `assets/*` glob puts the bundle in
#: the wheel: the package directory plus the directory name itself.
ASSET_PREFIX = "recoverage/assets/"


def wheel_assets(path: Path) -> set[str]:
    """Return the bundle file names a wheel carries."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    return {
        name[len(ASSET_PREFIX) :]
        for name in names
        if name.startswith(ASSET_PREFIX) and "/" not in name[len(ASSET_PREFIX) :]
    }


def check(wheel: Path, declared: set[str]) -> list[str]:
    """Return the reasons *wheel* fails its asset contract, empty when it holds."""
    carried = wheel_assets(wheel)
    reasons = []
    if carried - declared:
        reasons.append(f"{wheel}: ships {sorted(carried - declared)} which nothing declares")
    if declared - carried:
        reasons.append(
            f"{wheel}: does not ship {sorted(declared - carried)}, which the server reads by name"
        )
    return reasons


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="directory holding the built wheel(s)")
    parser.add_argument(
        "--asset",
        action="append",
        default=[],
        metavar="NAME",
        help="a declared bundle asset, once per member of BUNDLE_ASSETS",
    )
    args = parser.parse_args(argv[1:])

    declared = set(args.asset)
    if not declared:
        print("no --asset was given, so there is nothing the wheel has to carry", file=sys.stderr)
        return 2
    wheels = sorted(args.root.glob("*.whl")) if args.root.is_dir() else []
    if not wheels:
        print(f"no wheel (*.whl) under {args.root}", file=sys.stderr)
        return 1

    reasons = [reason for wheel in wheels for reason in check(wheel, declared)]
    if reasons:
        print("\n".join(reasons), file=sys.stderr)
        print(
            "pyproject.toml's package data is the glob 'assets/*' and MANIFEST.in decides "
            "what the sdist carries, so the wheel is built from a list this check never read.",
            file=sys.stderr,
        )
        return 1
    for wheel in wheels:
        print(f"{wheel} carries {', '.join(sorted(declared))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
