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

Two shapes of the same rows: the text inventory above, and `--format spdx`, an
SPDX 2.3 JSON document. The text one is for a reader; the JSON one is for a
tool, because a vulnerability scanner pointed at the wheel takes a standard
document and not a list of lines, so without it the browser half of the tree
is described to nobody but this project.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, NamedTuple

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
PACKAGE_JSON = REPO_ROOT / "package.json"
BUN_LOCK = REPO_ROOT / "bun.lock"
NOTICE = REPO_ROOT / "NOTICE"
PACKAGE_INIT = REPO_ROOT / "src" / "recoverage" / "__init__.py"

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
    #: The SPDX id of the grant covering it, and the upstream that grant comes
    #: from. They sit beside the package rather than in a second table because
    #: NOTICE credits each of these packages and a license nobody recorded is
    #: a grant a consumer cannot trace, which is what the SPDX document claims
    #: about every package it lists.
    license_id: str
    homepage: str


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
        "MIT",
        "https://github.com/preactjs/preact",
    ),
    Shipped(
        "highlight.js",
        APP_JS,
        "the code panes import the c and x86asm grammars",
        "BSD-3-Clause",
        "https://highlightjs.org",
    ),
    Shipped(
        "clsx",
        APP_JS,
        "the shadcn/ui class helper in web/app/lib/cn.ts",
        "MIT",
        "https://github.com/lukeed/clsx",
    ),
    Shipped(
        "tailwind-merge",
        APP_JS,
        "web/app/lib/cn.ts merges class lists with it",
        "MIT",
        "https://github.com/dcastil/tailwind-merge",
    ),
    Shipped(
        "class-variance-authority",
        APP_JS,
        "the variant maps in web/app/components/ui/button.tsx",
        "MIT",
        "https://github.com/joe-bell/cva",
    ),
    Shipped(
        "tailwindcss",
        STYLE_CSS,
        "@tailwindcss/vite compiles the utility classes into style.css",
        "MIT",
        "https://github.com/tailwindlabs/tailwindcss",
    ),
)


class InventoryError(Exception):
    """The tree says something the inventory cannot be built from."""


def _as_object(loaded: Any, path: Path) -> dict[str, Any]:
    """The parsed document, or the failure a caller would otherwise read as a missing key."""
    if not isinstance(loaded, dict):
        raise InventoryError(f"{path} is not a JSON object")
    return loaded


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise InventoryError(f"{path} is missing")
    return _as_object(json.loads(path.read_text(encoding="utf-8")), path)


def _bun_lock() -> dict[str, Any]:
    """bun.lock is JSONC, and its own trailing commas are what uv-free readers trip on.

    A comment or a trailing comma in the lockfile is a syntax error to
    json.loads, and the failure would read as a corrupt lock rather than as
    the parser. Strip both, which is all the file ever carries.
    """
    text = BUN_LOCK.read_text(encoding="utf-8")
    text = re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return _as_object(json.loads(text), BUN_LOCK)


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


#: The SPDX tag a bun.lock digest spells itself with, and the algorithm name
#: the same digest has in a document. bun writes `<algorithm>-<base64>`, SPDX
#: writes the bare hex, so one is decoded into the other rather than filed as a
#: checksum a validator rejects.
_DIGEST_ALGORITHMS = {"sha512": "SHA512", "sha256": "SHA256", "sha1": "SHA1"}


def _checksum(digest: str) -> dict[str, str]:
    """The bun.lock integrity string as an SPDX checksum."""
    algorithm, _, encoded = digest.partition("-")
    name = _DIGEST_ALGORITHMS.get(algorithm)
    if name is None or not encoded:
        raise InventoryError(f"{digest!r} is not a digest this document can carry")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InventoryError(f"{digest!r} is not base64") from exc
    return {"algorithm": name, "checksumValue": raw.hex()}


def created() -> str:
    """The document timestamp, in the UTC form SPDX requires.

    `SOURCE_DATE_EPOCH` is the same stamp `make build` exports, and the sbom
    job's own comment asks for two runs of one commit to produce the same
    bytes: an SPDX document whose `created` reads the wall clock cannot be
    diffed against the run it repeats, so the stamp comes from the environment
    when it is there and from the clock only when it is not.
    """
    raw = os.environ.get("SOURCE_DATE_EPOCH", "")
    try:
        stamp = int(raw)
    except ValueError:
        if raw:
            raise InventoryError(f"SOURCE_DATE_EPOCH={raw!r} is not a Unix timestamp") from None
        stamp = int(datetime.datetime.now(tz=datetime.UTC).timestamp())
    return datetime.datetime.fromtimestamp(stamp, tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _version() -> str:
    """The version this build is, read off the one place it is written."""
    match = re.search(
        r'^__version__ = "([^"]+)"',
        PACKAGE_INIT.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if match is None:
        raise InventoryError(f"{PACKAGE_INIT.name} declares no __version__")
    return match.group(1)


def spdx_document(rows: list[tuple[Shipped, str, str]]) -> dict[str, Any]:
    """The same rows as an SPDX 2.3 document, which is what a scanner reads.

    `documentNamespace` has to be unique per document and `created` is the
    stamp above, so one commit at one instant names one document: the same
    input renders the same namespace, and two different builds cannot collide.
    """
    timestamp = created()
    version = _version()
    name = f"recoverage-{version}-browser-bundle"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"https://spdx.org/spdxdocs/{name}-{timestamp}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: recoverage-tools/bundled_js_inventory.py"],
            "comment": (
                "The third-party code compiled into src/recoverage/assets/ and shipped in "
                "the wheel. The Python half of the tree is the recoverage-python-sbom "
                "artifact; the grants in full are in NOTICE."
            ),
        },
        "packages": [
            {
                "SPDXID": f"SPDXRef-Package-{_spdx_id(entry.package)}",
                "name": entry.package,
                "versionInfo": spec.rsplit("@", 1)[1],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "LIBRARY",
                "supplier": "NOASSERTION",
                "licenseConcluded": entry.license_id,
                "licenseDeclared": entry.license_id,
                "copyrightText": "NOASSERTION",
                "homepage": entry.homepage,
                "checksums": [_checksum(digest)],
                "comment": f"bun.lock integrity {digest}; compiled into {entry.asset}",
            }
            for entry, spec, digest in rows
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": f"SPDXRef-Package-{_spdx_id(entry.package)}",
                "relationshipType": "DESCRIBES",
            }
            for entry, _spec, _digest in rows
        ],
    }


def _spdx_id(package: str) -> str:
    """An SPDXRef element id, whose alphabet is `[A-Za-z0-9.-]+`."""
    return re.sub(r"[^A-Za-z0-9.-]", "-", package)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="write the inventory here instead of to stdout",
    )
    parser.add_argument(
        "--format",
        choices=("text", "spdx"),
        default="text",
        help=(
            "text is the line per shipped package a reader takes; "
            "spdx is the same rows as an SPDX 2.3 JSON document a scanner takes"
        ),
    )
    args = parser.parse_args(argv)

    try:
        rows = resolve()
        if args.format == "spdx":
            body = json.dumps(spdx_document(rows), indent=2) + "\n"
        else:
            body = render(rows)
    except InventoryError as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.output is None:
        print(body, end="")
    else:
        # newline="" for the same reason as the sibling tools: the body is LF by
        # construction, and this file is uploaded as a diffable CI artifact, so
        # the bytes a Windows run writes must match the ones a Linux run does.
        args.output.write_text(body, encoding="utf-8", newline="")
        print(f"{args.output}: {len(SHIPPED)} shipped packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
