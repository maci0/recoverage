"""Regenerate tools/oxlint/anti-slop.manifest.json for the vendored plugin.

`tools/oxlint/anti-slop/` is a copy of dmmulroy/anti-slop's oxlint plugin,
so the grant that comes with it is the only record of where the code came
from.  Nothing in package.json or uv.lock covers a tree that lives in the
repository rather than in node_modules, and a reviewer reading a diff of
rule files cannot tell an upstream re-vendor from a local edit.

The manifest is that record: every file the tree ships with its sha256, the
upstream the copy was taken from, and the paths deliberately left out.  A
test (tests/test_supply_chain.py) compares the tree against it, so an edit,
a deletion or a re-vendor that skipped this file fails the suite instead of
landing unnoticed.

To re-vendor: replace the directory from upstream, run this script
(`make vendor-manifest`), then `make web-lint` to confirm the rule set still
passes.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from pathlib import Path
from typing import TypedDict

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
TOOLS_DIR = REPO_ROOT / "tools"
TREE = TOOLS_DIR / "oxlint" / "anti-slop"
MANIFEST = TOOLS_DIR / "oxlint" / "anti-slop.manifest.json"

UPSTREAM_URL = "https://github.com/dmmulroy/anti-slop"
UPSTREAM_LICENSE = "MIT"
#: Paths left out of the copy, each with the reason.  A key is a glob matched
#: (fnmatch, so `**` is a plain prefix wildcard) against the path relative to
#: the tree root.  The upstream rule tests import `oxlint/plugins-dev`, a
#: subpath no declared dependency provides, and nothing in this tree runs
#: TypeScript tests: the rules are exercised by `bun run lint:js` over the SPA.
EXCLUDED: dict[str, str] = {
    "**/*.test.ts": (
        "upstream rule tests; they import oxlint/plugins-dev, which no declared "
        "dependency provides, and no runner in this tree executes them"
    ),
}


def is_excluded(rel: str) -> bool:
    return any(fnmatch.fnmatch(rel, pattern) for pattern in EXCLUDED)


class Manifest(TypedDict):
    """The shape of anti-slop.manifest.json, and of :func:`build_manifest`."""

    upstream: str
    license: str
    tree: str
    excluded: dict[str, str]
    files: dict[str, str]


def build_manifest() -> Manifest:
    """The manifest body for the tree as it stands on disk."""
    # Sorted by the RECORD's key, not by the Path: PurePath ordering is
    # case-folded on Windows and byte-wise on POSIX, so the same tree would
    # serialize its keys in a different order per platform and --check would
    # report a manifest mismatch for a tree that did not change.
    files = {
        path.relative_to(TREE).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(TREE.rglob("*"), key=lambda p: p.relative_to(TREE).as_posix())
        if path.is_file() and not is_excluded(path.relative_to(TREE).as_posix())
    }
    return {
        "upstream": UPSTREAM_URL,
        "license": UPSTREAM_LICENSE,
        "tree": TREE.relative_to(TOOLS_DIR).as_posix(),
        "excluded": EXCLUDED,
        "files": files,
    }


def render(manifest: Manifest | None = None) -> str:
    return json.dumps(manifest if manifest is not None else build_manifest(), indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when the manifest does not match the tree",
    )
    args = parser.parse_args(argv)

    if not TREE.is_dir():
        print(f"{TREE} is not a directory; the vendored tree has moved", file=sys.stderr)
        return 1
    if not (TREE / "LICENSE").is_file():
        print(f"{TREE / 'LICENSE'} is missing; the grant has to travel with the code")
        return 1

    manifest = build_manifest()
    body = render(manifest)
    if args.check:
        current = MANIFEST.read_text(encoding="utf-8") if MANIFEST.is_file() else ""
        if current != body:
            print(f"{MANIFEST} does not match the tree; run tools/vendor_manifest.py")
            return 1
        print(f"{MANIFEST.relative_to(REPO_ROOT)}: up to date")
        return 0

    MANIFEST.write_text(body, encoding="utf-8")
    print(f"{MANIFEST.relative_to(REPO_ROOT)}: {len(manifest['files'])} files recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
