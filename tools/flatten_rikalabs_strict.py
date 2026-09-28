"""Regenerate tools/oxlint/rikalabs-strict.json from the installed
@rikalabs/oxlint-standards package.

The Rika-Labs presets reference a handful of rules that the currently
installed oxlint does not implement, and oxlint rejects a config
that mentions an unknown rule even when set to "off" — so the preset chain
cannot be consumed via `extends` until those rules land in oxlint. This
script flattens the `strict` preset chain into a single checked-in JSON that
drops the missing rules. The one whose intent survives, oxc/no-new-buffer, is
dropped here and re-enabled by hand as unicorn/no-new-buffer in
`oxlint.config.ts`.

A drop is unenforced strictness, so every dropped rule is printed and a
MISSING_IN_OXLINT entry that the preset no longer needs fails the run; a
preset cannot lose rules silently on a bump.

To bump: `bun add -d @rikalabs/oxlint-standards`, then run
`make regen-oxlint` (which installs the package this script reads and runs it
through the locked interpreter) and re-run `make web-lint`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
TOOLS_DIR = REPO_ROOT / "tools"
PACKAGE_DIR = REPO_ROOT / "node_modules" / "@rikalabs" / "oxlint-standards"
PRESET_DIR = PACKAGE_DIR / "presets"
OUT = TOOLS_DIR / "oxlint" / "rikalabs-strict.json"
# The oxlint version is reported next to every dropped rule so a reader can see
# which oxlint the checked-in preset was flattened against. It is read from
# package.json rather than repeated here: a constant would keep printing a
# confident claim about a version the tree no longer installs.
_PACKAGE_JSON = REPO_ROOT / "package.json"
# The preset content is copied into this repo, so its grant ships with the
# repo. A license change on a bump is a compliance change nobody reviews by
# reading a diff of rule names, so it has to fail the regeneration instead.
EXPECTED_LICENSE = "MIT"

# Rules referenced by the Rika-Labs presets that do not exist in the
# currently published oxlint. Drop them here; do not try to set them "off" —
# oxlint rejects unknown rule names outright.
MISSING_IN_OXLINT = {
    "import/no-extraneous-dependencies",
    "import/no-reexport",
    "import/no-unresolved",
    "oxc/no-map-object-keys",
    "oxc/no-new-buffer",
    "unicorn/prefer-logical-operator-over-short-circuit",
}
# oxc/no-new-buffer exists in oxlint under unicorn; the consuming config
# enables unicorn/no-new-buffer to preserve the preset's intent.
REMAP = {"oxc/no-new-buffer": "unicorn/no-new-buffer"}


def load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return cast("dict[str, Any]", json.load(fh))


def oxlint_version() -> str:
    """The oxlint this tree lints with, taken from the manifest that owns it."""
    return cast(str, load(_PACKAGE_JSON)["devDependencies"]["oxlint"])


def main() -> int:
    if not PRESET_DIR.is_dir():
        print(f"error: {PRESET_DIR} not found; run `bun install` first", file=sys.stderr)
        return 1

    manifest = load(PACKAGE_DIR / "package.json")
    if manifest.get("license") != EXPECTED_LICENSE:
        print(
            f"error: @rikalabs/oxlint-standards {manifest.get('version')} is licensed "
            f"{manifest.get('license')!r}, not {EXPECTED_LICENSE!r}; the preset copied "
            f"into {OUT.name} would change terms. Record the new license in the "
            f"README vendored-assets table before regenerating.",
            file=sys.stderr,
        )
        return 1

    merged: dict[str, Any] = {"plugins": set(), "categories": {}, "rules": {}, "overrides": []}
    visited: set[str] = set()
    dropped: set[str] = set()

    def walk(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        for key, val in load(PRESET_DIR / name).items():
            if key == "extends":
                for child in val:
                    walk(child)
            elif key == "plugins":
                merged["plugins"].update(val)
            elif key == "categories":
                merged["categories"].update(val)
            elif key == "rules":
                for rule, sev in val.items():
                    if rule in MISSING_IN_OXLINT:
                        dropped.add(rule)
                        continue
                    merged["rules"][REMAP.get(rule, rule)] = sev
            elif key == "overrides":
                merged["overrides"].extend(val)

    walk("strict.json")

    # A dropped rule is unenforced strictness, so MISSING_IN_OXLINT must not
    # outlive the gap it records: once oxlint or the preset implements a rule,
    # the entry goes stale and would keep that rule unenforced. Fail rather
    # than write a silently weaker preset. (The other direction needs no
    # check: a rule kept in the output that oxlint cannot parse is rejected
    # by oxlint itself when the config loads.)
    stale = MISSING_IN_OXLINT - dropped
    if stale:
        print(
            f"error: MISSING_IN_OXLINT entries no longer dropped by the preset: "
            f"{sorted(stale)}; remove them",
            file=sys.stderr,
        )
        return 1
    for rule in sorted(dropped):
        print(f"dropped (not in oxlint {oxlint_version()}): {rule}", file=sys.stderr)

    tsgolint = [r for r in merged["rules"] if "tsgolint" in r]
    if tsgolint:
        print(f"warning: type-aware rules require oxlint-tsgolint: {tsgolint}", file=sys.stderr)

    out = {
        "options": {"typeAware": False},
        "plugins": sorted(merged["plugins"]),
        "categories": merged["categories"],
        "rules": merged["rules"],
        "overrides": merged["overrides"],
    }
    with OUT.open("w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(f"wrote {OUT}: {len(out['rules'])} rules, {len(out['plugins'])} plugins")
    return 0


if __name__ == "__main__":
    sys.exit(main())
