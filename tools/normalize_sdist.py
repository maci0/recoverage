"""Rewrite built sdists so two builds of one commit are byte-identical.

``setuptools`` honors ``SOURCE_DATE_EPOCH`` for the wheel (``bdist_wheel``)
but not for the sdist: its ``sdist`` archive keeps the working tree's file
mtimes, writes ``PKG-INFO`` and ``setup.cfg`` with the current time, records
the building user in every member header, and lets ``tarfile`` stamp the gzip
wrapper with the wall clock. Four sources of nondeterminism in one archive,
which is why ``diffoscope`` between two builds of the same commit reports
differing mtimes, uid/gid and a gzip header and nothing else.

This normalizes the members after the fact: one timestamp from the
environment, no owner, fixed permissions, entries in sorted order, and a gzip
header carrying no name and no time. Stdlib only, and portable: GNU tar's
``--sort=name --mtime=... --owner=0 --group=0 --numeric-owner`` would do the
same, but not with the BSD tar macOS ships and not without unpacking first.

Usage::

    SOURCE_DATE_EPOCH=1700000000 python tools/normalize_sdist.py dist

Every ``*.tar.gz`` under the given directories is rewritten in place.
"""

from __future__ import annotations

import gzip
import os
import sys
import tarfile
from pathlib import Path

#: Modes a normalized member is recorded with. The executable bit is kept: a
#: data file and a script must not come out the same.
DIR_MODE = 0o755
FILE_MODE = 0o644
EXEC_MODE = 0o755

#: Fixed so two runs of one input compress identically, rather than leaving
#: the level to whatever the toolchain defaults to.
GZIP_LEVEL = 9


def normalized(member: tarfile.TarInfo, epoch: int) -> tarfile.TarInfo:
    """Return *member* with every field that varies between builds pinned."""
    out = tarfile.TarInfo(member.name)
    out.type = member.type
    out.linkname = member.linkname
    out.size = member.size
    out.mtime = epoch
    out.mode = DIR_MODE if member.isdir() else (EXEC_MODE if member.mode & 0o111 else FILE_MODE)
    out.uid = out.gid = 0
    out.uname = out.gname = ""
    return out


def normalize_archive(path: Path, epoch: int) -> None:
    """Rewrite the sdist at *path* in place, deterministically."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        with (
            gzip.open(path, "rb") as src,
            tmp.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=GZIP_LEVEL, mtime=0
            ) as dst,
            # "r:" rather than "r|": the entries are sorted, so each member's
            # bytes are read out of order, which a stream cannot do. A gzip
            # file object seeks.
            tarfile.open(fileobj=src, mode="r:") as tar_in,
            tarfile.open(fileobj=dst, mode="w|", format=tarfile.PAX_FORMAT) as tar_out,
        ):
            for member in sorted(tar_in, key=lambda m: m.name):
                payload = tar_in.extractfile(member) if member.isreg() else None
                tar_out.addfile(normalized(member, epoch), payload)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(path)


def main(argv: list[str]) -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not raw:
        print(
            "SOURCE_DATE_EPOCH is unset, so the archive would stay nondeterministic.",
            file=sys.stderr,
        )
        print(
            "Build through `make build`, which sets it to the commit's own date.", file=sys.stderr
        )
        return 2
    if not raw.isdigit():
        print(f"SOURCE_DATE_EPOCH={raw!r} is not a Unix timestamp.", file=sys.stderr)
        return 2
    epoch = int(raw)

    roots = [Path(arg) for arg in argv[1:]] or [Path("dist")]
    targets = sorted(p for root in roots if root.is_dir() for p in root.glob("*.tar.gz"))
    if not targets:
        print(f"no sdist (*.tar.gz) under {[str(r) for r in roots]}", file=sys.stderr)
        return 1
    for target in targets:
        normalize_archive(target, epoch)
        print(f"normalized {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
