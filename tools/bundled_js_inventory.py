"""Write the inventory of the third-party code `make web-build` ships in the wheel.

Every npm dependency in package.json is a devDependency, and the reader of
package.json concludes none of them reach a consumer. That is wrong for six of
them: `vite build` compiles Preact, highlight.js, Tailwind CSS, clsx,
tailwind-merge and class-variance-authority into
`src/recoverage/assets/app.js` and `style.css`, and `[tool.setuptools.package-data]`
ships that directory in the wheel. The code runs in the reader's browser with no
package manager and no lockfile in reach.

The Python inventory the sbom job exports (`uv export --hashes`) cannot name
them: it reads uv.lock, which knows nothing about the browser bundle. So the
shipped half of the dependency tree has no inventory, and a consumer or a
vulnerability scanner pointed at a wheel sees the Python tree and nothing
else. This writes that half: every shipped package with the exact version and
the tarball digest bun.lock pinned, so the browser code a given build carries
is as auditable as the Python it serves.

Reads the tree, writes nothing unless asked. The versions and digests come from
bun.lock, never from package.json, so the inventory describes the resolved
bytes rather than a declared range.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NamedTuple, cast

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
PACKAGE_JSON = REPO_ROOT / "package.json"
BUN_LOCK = REPO_ROOT / "bun.lock"
NOTICE = REPO_ROOT / "NOTICE"

#: The wheel carries the browser code, so this inventory is about the wheel's
#: contents, not the developer's node_modules.  `make all` runs it next to
#: `check-bundle-clean`, which is what says the committed assets still match
#: web/; between the two, a bump in package.json that skips NOTICE or skips
#: this list fails the suite instead of shipping uncredited code.
INVENTORY_FORMAT = (
    "name@version <integrity-digest> -> <shipped asset>\n"
    "\tOne line per npm package whose compiled output `make web-build` writes\n"
    "\tinto src/recoverage/assets/, which the wheel ships. Read from bun.lock,\n"
    "\tso the version and digest are the resolved ones, not a declared range."
)


class Shipped(NamedTuple):
    """One npm package whose code reaches the wheel, and where it lands."""

    package: str
    asset: str
    #: Why this package is in the inventory: which import or build step pulls
    #: it into the asset. A devDependency that stops being imported is
    #: removed from this list in the same change, and tests/test_supply_chain.py
    #: fails when a listed package is no longer declared.
    because: str


APP_JS = "src/recoverage/assets/app.js"
STYLE_CSS = "src/recoverage/assets/style.css"

#: Every devDependency `web/` or the Vite build pulls into the shipped assets.
#: `@preact/preset-vite` and `@tailwindcss/vite` are build plugins, so their
#: own output is Tailwind's and Preact's, and the preact/compat aliasing they
#: configure ships as part of preact. Vite, TypeScript, oxlint and the vnu jar
#: run on this machine and reach no consumer, which is why they are absent.
SHIPPED = (
    Shipped(
        "preact",
        APP_JS,
        "every component imports preact/hooks; preact/compat aliases the React API",
    ),
    Shipped("highlight.js", APP_JS, "the code panes import the c and x86asm grammars"),
    Shipped("clsx", APP_JS, "the shadcn/ui class helper in web/app/lib/cn.ts"),
    Shipped("tailwind-merge", APP_JS, "web/app/lib/cn.ts merges class lists with it"),
    Shipped(
        "class-variance-authority",
        APP_JS,
        "the variant maps in web/app/components/ui/button.tsx",
    ),
    Shipped(
        "tailwindcss", STYLE_CSS, "@tailwindcss/vite compiles the utility classes into style.css"
    ),
)


class InventoryError(Exception):
    """The tree says something the inventory cannot be built from."""


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise InventoryError(f"{path} is missing")
    # `json.loads` is untyped and returns Any; the cast is the declared
    # boundary narrowing, the same one every other json reader in the tree
    # takes. A lockfile or manifest whose top level is not an object raises
    # KeyError below, which is the InventoryError a reader wants.
    return cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))


def _bun_lock() -> dict[str, Any]:
    """bun.lock is JSONC, and its own trailing commas are what uv-free readers trip on.

    A comment or a trailing comma in the lockfile is a syntax error to
    json.loads, and the failure would read as a corrupt lock rather than as
    the parser. Strip both, which is all the file ever carries.
    """
    text = BUN_LOCK.read_text(encoding="utf-8")
    text = re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return cast("dict[str, Any]", json.loads(text))


def resolve() -> list[tuple[Shipped, str, str]]:
    """Pair every shipped package with the version and digest bun.lock pinned."""
    declared = set(_read_json(PACKAGE_JSON)["devDependencies"])
    packages = _bun_lock()["packages"]
    resolved: list[tuple[Shipped, str, str]] = []
    for entry in SHIPPED:
        if entry.package not in declared:
            raise InventoryError(
                f"{entry.package} is in the shipped inventory but not in package.json; "
                "a dependency that stopped reaching the bundle leaves the list with it"
            )
        locked = packages.get(entry.package)
        if locked is None:
            raise InventoryError(f"{entry.package} is declared but bun.lock does not resolve it")
        digest = locked[-1]
        if not (isinstance(digest, str) and re.fullmatch(r"sha\d{3}-.+", digest)):
            raise InventoryError(
                f"{entry.package} resolves without an integrity digest; run `bun install` "
                "so the lock records the tarball hash"
            )
        resolved.append((entry, locked[0], digest))
    return resolved


def render(rows: list[tuple[Shipped, str, str]]) -> str:
    lines = [
        "# recoverage browser-bundle inventory",
        f"# {INVENTORY_FORMAT}",
        "#",
        f"# Licenses and upstream sources for these packages are in {NOTICE.name},",
        "# which ships in the wheel; the Python half of the tree is the",
        "# recoverage-python-sbom artifact from the same job.",
        "",
    ]
    lines += [
        f"{spec} {digest} -> {entry.asset}\n\t{entry.because}" for entry, spec, digest in rows
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="write the inventory here instead of to stdout",
    )
    args = parser.parse_args(argv)

    try:
        body = render(resolve())
    except InventoryError as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.output is None:
        print(body, end="")
    else:
        args.output.write_text(body, encoding="utf-8")
        print(f"{args.output}: {len(SHIPPED)} shipped packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
