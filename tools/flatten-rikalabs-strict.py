#!/usr/bin/env python3
"""Regenerate tools/oxlint/rikalabs-strict.json from the installed
@rikalabs/oxlint-standards package.

The Rika-Labs presets reference a handful of rules that the currently
published oxlint (1.79.0) does not implement, and oxlint rejects a config
that mentions an unknown rule even when set to "off" — so the preset chain
cannot be consumed via `extends` until those rules land in oxlint. This
script flattens the `strict` preset chain into a single checked-in JSON that
drops the missing rules (remapping oxc/no-new-buffer to its oxlint
equivalent, unicorn/no-new-buffer, which the consuming config enables).

To bump: `npm i -D @rikalabs/oxlint-standards`, then run
`uv run python tools/flatten-rikalabs-strict.py` and re-run `npm run lint:js`.
"""

from __future__ import annotations

import json
import os
import sys

PRESET_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "node_modules",
    "@rikalabs",
    "oxlint-standards",
    "presets",
)
OUT = os.path.join(os.path.dirname(__file__), "oxlint", "rikalabs-strict.json")

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


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    if not os.path.isdir(PRESET_DIR):
        print(f"error: {PRESET_DIR} not found; run `npm install` first", file=sys.stderr)
        return 1

    merged: dict = {"plugins": set(), "categories": {}, "rules": {}, "overrides": []}
    visited: set[str] = set()

    def walk(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        for key, val in load(os.path.join(PRESET_DIR, name)).items():
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
                        continue
                    merged["rules"][REMAP.get(rule, rule)] = sev
            elif key == "overrides":
                merged["overrides"].extend(val)

    walk("strict.json")

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
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(f"wrote {OUT}: {len(out['rules'])} rules, {len(out['plugins'])} plugins")
    return 0


if __name__ == "__main__":
    sys.exit(main())
