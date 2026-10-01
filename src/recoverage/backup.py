"""Verified backup and restore of the coverage documents.

The coverage directory is the only durable state this package has.  Everything
else is derived: the parse cache under ``$XDG_CACHE_HOME`` is rebuilt from a
document on first read, the in-process memos die with the process, and rebrew's
catalog outputs are recomputed by the next ``regen``.  The documents themselves
are NOT derivable, because rebrew's ``write_coverage_toml`` is a read-modify-
write over the previous document: ``history`` carries the cumulative status
delta chain forward from the last build, and ``verify_results`` carries the
measured verdicts forward.  Both come from the file being overwritten, not from
the source tree, so a regen over a directory whose documents were lost rebuilds
the current facts and loses both arrays for good.  That makes the document set
the thing to back up, and it is what this module backs up.

Four properties the format has, and why each is here:

* **Verified on write and on read.**  ``manifest.json`` carries the sha256 of
  every member, and :func:`verify_backup` re-reads each member's bytes and
  recomputes them.  A backup whose success is measured by its own exit code is
  a hypothesis; the check that makes it a backup is the same one a restore runs
  before it touches anything.
* **A restore is all-or-nothing.**  Every member is read, digested and size
  checked BEFORE the first file is written, and each document is then replaced
  through a temp file in the destination directory, so a restore either lands
  whole or leaves the previous documents exactly as they were.  Half a restore
  is worse than none: the dashboard answers 200 with half a project's coverage
  and nothing that says which half is missing.
* **A restore will not roll coverage backwards silently.**  It refuses, before
  writing anything, when a document already in the coverage directory differs
  from the one the archive holds unless the caller passes ``force``.  Restoring
  a month-old archive over a tree that has been rebuilt since throws away every
  status transition since, and ``regen`` cannot bring them back.
* **The archive is plain tar.**  Documents and manifest, uncompressed, member
  order fixed, POSIX ``PAX`` format, so ``tar -tf`` lists it and an operator
  reaches into it with the tools they already have.

Where the archive goes is ``RECOVERAGE_BACKUP_DIR``, or the ``--to`` flag, or
:func:`default_backup_dir` — a ``backups/`` beside the coverage directory, never
inside it, because the glob a restore reads would then grow a member that is not
a coverage document and a later backup would carry the earlier one.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from recoverage import clock
from recoverage.documents import COVERAGE_GLOB

#: The manifest's own name inside the archive.  Every other member is named by
#: :data:`COVERAGE_GLOB`, so a member that is neither is this one.
MANIFEST_NAME: Final = "manifest.json"

#: Archive format version, carried in the manifest and refused when it is one
#: this code does not know: a layout change bumps it, and a restore reading a
#: manifest it cannot interpret refuses rather than extracting whatever the
#: older layout happened to put in the tar.
FORMAT_VERSION: Final = 1

#: Directory a backup goes to when nothing names one.
DEFAULT_BACKUP_SUBDIR: Final = "backups"

#: Prefix and suffix of the stamped default archive name.  The stamp sorts the
#: directory chronologically, so the newest backup is the last name in it.
_ARCHIVE_PREFIX: Final = "coverage-"
_ARCHIVE_SUFFIX: Final = ".tar"

#: Most bytes one member of an archive may hold, and most bytes an archive may
#: hold in total.  A verify (and a restore, which verifies first) holds every
#: member's bytes in memory, because that is what makes it one pass; the bound
#: is therefore on the reader rather than on the writer.
#:
#: A tar header carries the member's length and the reader trusts it, so an
#: archive a restore did not write — one an operator downloaded, or one produced
#: by something else entirely — declares whatever size it likes and is read to
#: that figure.  Unbounded, that is a member read into memory before any name
#: or digest has been looked at, which is a denial of service against the
#: command whose whole purpose is to be safe to run on a schedule.  One
#: gigabyte is far above any real coverage directory (the documents are
#: per-target TOML, and a large project's set is tens of megabytes), so the
#: bound is a ceiling against a hostile archive rather than a limit a project
#: reaches; raise it here, which is where the reader lives, rather than adding
#: a knob the backup commands do not otherwise carry.
_MAX_MEMBER_BYTES: Final = 1 << 30
_MAX_ARCHIVE_BYTES: Final = 1 << 30


class BackupError(RuntimeError):
    """A backup could not be taken, verified, or restored.

    One class for both directions: the caller reports the message and exits
    non-zero, and every message here names the file and the reason rather than
    raising something a reader has to translate (a ``KeyError`` from a manifest
    field, an ``OSError`` from a tar member).
    """


@dataclass(frozen=True)
class BackupInfo:
    """What a verified archive holds, and where it was read from."""

    path: Path
    created: str
    members: tuple[tuple[str, int, str], ...]
    total_bytes: int


def default_backup_dir(coverage_dir: Path) -> Path:
    """Where a backup goes when nothing names a directory: ``../backups``."""
    return coverage_dir.resolve().parent / DEFAULT_BACKUP_SUBDIR


def backup_dir_from_env(coverage_dir: Path) -> Path:
    """The backup directory: ``RECOVERAGE_BACKUP_DIR``, else the default.

    Read here rather than through :mod:`recoverage.config` because this is the
    one setting the backup commands take and nothing else in the package reads
    it.  A deployment that schedules ``recoverage backup`` from cron cannot
    pass a flag, so the environment is the only channel that reaches it there.

    The name is in ``config.KNOWN_VARS`` for the same reason the fuzz knobs
    are: that set is what ``check_unknown_vars`` validates against, so a cron
    line carrying this name would otherwise be refused by every command as a
    misspelling — which is the one way an operator finds out that the schedule
    is wrong, at the hour it runs.
    """
    raw = os.environ.get("RECOVERAGE_BACKUP_DIR", "")
    if raw.strip():
        return Path(raw).expanduser()
    return default_backup_dir(coverage_dir)


def _stamp() -> str:
    """A UTC instant, ISO-8601, for the manifest and the default archive name.

    ``clock.wall_time`` rather than ``time.time``: every instant this package
    renders or names comes from that seam, so a replay of a backup run reads
    from one clock, and a restored archive's ``created`` is comparable with
    ``restored_at`` in the same run.  ``%f`` to microseconds and ``Z`` rather
    than ``+00:00``: the name has to survive a filename limit on every host, and
    a colon in a filename is a quote on Windows.
    """
    return datetime.fromtimestamp(clock.wall_time(), tz=UTC).strftime("%Y%m%dT%H%M%S.%fZ")


def _created_stamp() -> str:
    """The manifest's ``created`` field: the same instant, ISO-8601."""
    return datetime.fromtimestamp(clock.wall_time(), tz=UTC).isoformat()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_dir(path: Path) -> None:
    """fsync a directory so a rename inside it survives a power loss.

    POSIX only, and best effort: a directory opened for reading is not
    portable (Windows refuses), and on Windows the replace is metadata the
    filesystem journals without one.  Without it the archive name can be lost
    after a crash even though its bytes are on disk, which is exactly the
    "the backup ran, there is nothing there" case this module exists to close.
    """
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes) -> None:
    """Publish *data* at *path* through a temp file in the same directory.

    A half-written backup is the one artifact this whole module exists to
    prevent, so nothing is ever created in place: it lands by ``os.replace``,
    which is atomic on POSIX and on NTFS, and a reader either sees the previous
    archive or the complete new one.  The temp file is a sibling so the replace
    stays inside one filesystem, and both the file and the directory are fsynced
    before the name is published — a rename whose bytes were never flushed is a
    name pointing at nothing after a crash.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    _fsync_dir(path.parent)


def _members(db_dir: Path) -> list[tuple[str, bytes]]:
    """``(name, bytes)`` for every coverage document in *db_dir*, name-sorted.

    The same glob and the same skip-on-``OSError`` discipline
    :func:`recoverage.documents._stat_key` walks, so a backup covers exactly
    what the server would read, and a document that vanishes mid-backup is one
    fewer member rather than a failed run.
    """
    out: list[tuple[str, bytes]] = []
    for path in sorted(db_dir.glob(COVERAGE_GLOB)):
        try:
            out.append((path.name, path.read_bytes()))
        except OSError:
            continue
    return out


def _tar_bytes(members: list[tuple[str, bytes]], manifest: dict[str, Any]) -> bytes:
    """The archive bytes: every member then the manifest, in that fixed order.

    Written into a buffer because the archive is digested whole and then
    digested again, and a buffer is what makes that second pass a re-encode of
    the same bytes rather than a second walk of the directory.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            # 0600 and a zero mtime: a coverage document holds a project's
            # symbol table, and a backup must not be the copy in a directory
            # someone else can list.  The zero stamp is what makes two backups
            # of identical documents byte-identical.
            info.mode = 0o600
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
        body = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(body)
        info.mode = 0o600
        info.mtime = 0
        tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _manifest(members: list[tuple[str, bytes]], created: str) -> dict[str, Any]:
    """The manifest every verify and restore is read against.

    Member digests are over the member's own bytes, so a single rewritten
    member is named rather than failing the whole archive as "corrupt".
    """
    return {
        "format": FORMAT_VERSION,
        "created": created,
        "members": [
            {"name": name, "size": len(data), "sha256": _digest(data)} for name, data in members
        ],
    }


def write_backup(db_dir: Path, destination: Path | None = None) -> BackupInfo:
    """Copy every coverage document in *db_dir* into one verified archive.

    *destination* is the file to write when it names one, else the directory
    the stamped default name lands in.  The archive is read back and verified
    through :func:`verify_backup` before this returns, so a reported backup has
    been read once already; the cost is one pass over bytes in memory.

    A directory holding no document raises :class:`BackupError` rather than
    writing an empty archive.  An empty archive verifies, and restoring it
    empties the coverage directory, which is a restore that destroys the state
    it was taken from.  The schedule that produced it wants an alert, not a
    green run.
    """
    members = _members(db_dir)
    if not members:
        raise BackupError(
            f"no {COVERAGE_GLOB} document in {db_dir}; nothing to back up. "
            "Run 'rebrew build-db' (or 'recoverage regen') first."
        )
    created = _created_stamp()
    manifest = _manifest(members, created)
    blob = _tar_bytes(members, manifest)
    if destination is None:
        destination = backup_dir_from_env(db_dir) / (
            f"{_ARCHIVE_PREFIX}{_stamp()}{_ARCHIVE_SUFFIX}"
        )
    elif destination.is_dir():
        destination = destination / f"{_ARCHIVE_PREFIX}{_stamp()}{_ARCHIVE_SUFFIX}"
    try:
        _atomic_write(destination, blob)
    except OSError as exc:
        raise BackupError(f"cannot write backup {destination}: {exc}") from exc
    return verify_backup(destination)


def _read_archive(path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """The manifest and every member's bytes, or raise :class:`BackupError`.

    ONE pass over the archive: every member is pulled into memory first, and
    the manifest is read out of that same map.  Two passes over the tar (the
    manifest, then the members it names) read every member's bytes off the
    archive twice, and a restore that verifies through one pass and extracts
    through another writes the copy it did not check.

    The pull-in is BOUNDED, and the bound is checked against the tar HEADERS
    before any member's bytes are read.  ``extractfile().read()`` trusts the
    length a header declares, so an archive recoverage did not write hands the
    reader whatever size it claims to hold; a member's bytes are in memory here
    and a member the manifest never names is in memory for no reason at all.
    :data:`_MAX_MEMBER_BYTES` and :data:`_MAX_ARCHIVE_BYTES` are where that
    stops, and both refusals name the member rather than leaving a traceback in
    a scheduled job's mail.  The total is summed over the headers first because
    a per-member check alone still lets the reader hold the whole cap in memory
    before it notices the next member would cross it; the header pass reads
    fixed 512-byte blocks and no member data, so it costs nothing against the
    data pass that follows.

    Nothing is written anywhere: this is the pass a restore runs before it
    touches the coverage directory, so every refusal it can make is made before
    the first file is replaced.
    """
    members: dict[str, bytes] = {}
    try:
        with tarfile.open(path, mode="r:") as tar:
            # Header pass: every member's declared size, no member data read.
            # Refuse an oversized member or an over-cap total here, before the
            # data pass allocates anything.
            declared: list[tarfile.TarInfo] = []
            total = 0
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                if member.size < 0 or member.size > _MAX_MEMBER_BYTES:
                    raise BackupError(
                        f"{path}: member {member.name!r} declares {member.size} bytes, "
                        f"over the {_MAX_MEMBER_BYTES}-byte limit one member may hold"
                    )
                total += member.size
                if total > _MAX_ARCHIVE_BYTES:
                    raise BackupError(
                        f"{path}: archive declares more than the {_MAX_ARCHIVE_BYTES}-byte "
                        f"total limit once {member.name!r} is counted"
                    )
                declared.append(member)

            for member in declared:
                handle = tar.extractfile(member)
                if handle is None:  # pragma: no cover - getmembers/isfile agree
                    continue
                payload = handle.read(_MAX_MEMBER_BYTES + 1)
                # The header sized the read above; a member that delivers more
                # than it declared is a truncated-then-appended stream, and
                # taking only the declared count would verify a prefix of the
                # member and write a file the manifest never described.
                if len(payload) > member.size:
                    raise BackupError(
                        f"{path}: member {member.name!r} holds more bytes than its header "
                        f"declares ({member.size}); the archive is malformed"
                    )
                # A tar may carry the same name twice; the map would keep the
                # last and the digest would be checked against a member whose
                # predecessor was never compared with anything.  Refuse it
                # rather than pick one.
                if member.name in members:
                    raise BackupError(
                        f"{path}: member {member.name!r} appears twice; "
                        "a recoverage backup names each member once"
                    )
                members[member.name] = payload
    except BackupError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise BackupError(f"{path} is not a readable backup: {exc}") from exc

    manifest_raw = members.get(MANIFEST_NAME)
    if manifest_raw is None:
        raise BackupError(f"{path} holds no {MANIFEST_NAME}; it is not a recoverage backup")
    try:
        manifest: Any = json.loads(manifest_raw)
    except (UnicodeError, ValueError) as exc:
        raise BackupError(f"{path}: {MANIFEST_NAME} is not readable JSON: {exc}") from exc

    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT_VERSION:
        found = manifest.get("format") if isinstance(manifest, dict) else "?"
        raise BackupError(
            f"{path}: manifest format {found!r} is not version {FORMAT_VERSION}; "
            "a backup written by another recoverage is not restored by this one"
        )
    entries = manifest.get("members")
    if not isinstance(entries, list) or not entries:
        raise BackupError(f"{path}: manifest names no members")

    documents: dict[str, bytes] = {}
    try:
        for entry in entries:
            name = entry["name"]
            # The member name is checked against the coverage glob rather
            # than merely joined onto the destination.  A manifest is a
            # file an operator can edit and a tar member is a name an
            # extractor honours, so a `../../etc/x` here would write outside
            # the directory the restore was pointed at.  `Path(name).name !=
            # name` is the containment half: no separator, no drive, no
            # parent hop, whatever the platform's idea of one is.
            if not isinstance(name, str) or Path(name).name != name or not _is_coverage(name):
                raise BackupError(f"{path}: member name {name!r} is not a coverage document")
            data = members.get(name)
            if data is None:
                raise BackupError(f"{path}: member {name} is not a regular file")
            documents[name] = data
    except BackupError:
        raise
    except (KeyError, TypeError) as exc:
        raise BackupError(f"{path} cannot be read: {exc}") from exc
    return manifest, documents


def _is_coverage(name: str) -> bool:
    """Whether *name* is spelled the way rebrew spells a coverage document.

    :data:`recoverage.documents.COVERAGE_GLOB` matched with :mod:`fnmatch`, so
    this is the same rule ``documents._stat_key`` applies to the directory and
    one glob cannot describe a member one way and read it another.
    """
    from fnmatch import fnmatch

    return fnmatch(name, COVERAGE_GLOB)


def _verify_archive(path: Path) -> tuple[BackupInfo, dict[str, bytes]]:
    """:func:`verify_backup` and the member bytes, from ONE read of *path*.

    The bytes are returned beside the description so a restore does not open
    the archive a second time: two reads of one tar parsed twice is the same
    fact held in two places, and a member's bytes a restore then compared
    against a freshly read copy is the copy, not what :func:`verify_backup`
    just checked.
    """
    manifest, members = _read_archive(path)
    described: list[tuple[str, int, str]] = []
    for entry in manifest["members"]:
        name = entry["name"]
        data = members.get(name)
        if data is None:
            raise BackupError(f"{path}: manifest names {name}, which the archive does not hold")
        size = entry["size"]
        digest = _digest(data)
        if not isinstance(size, int) or len(data) != size:
            raise BackupError(f"{path}: {name} is {len(data)} bytes, manifest says {size!r}")
        if digest != entry["sha256"]:
            raise BackupError(
                f"{path}: {name} does not match its manifest digest "
                f"({digest[:12]}…, manifest {str(entry['sha256'])[:12]}…); the backup is corrupt"
            )
        described.append((name, len(data), digest))
    info = BackupInfo(
        path=path,
        created=str(manifest.get("created", "")),
        members=tuple(described),
        total_bytes=sum(size for _n, size, _d in described),
    )
    return info, members


def verify_backup(path: Path) -> BackupInfo:
    """Check every member of *path* against its manifest; describe what it holds.

    Raises :class:`BackupError` naming the member whose bytes do not match, so a
    corrupted archive is one named file rather than a restore that half works.
    This is the function a scheduled job calls after taking a backup, and the
    one :func:`write_backup` calls on its own output — a job that only wrote an
    archive has measured its own exit code, which is not a restore.
    """
    info, _members = _verify_archive(path)
    return info


def restore_backup(archive: Path, db_dir: Path, *, force: bool = False) -> list[Path]:
    """Put every verified member of *archive* into *db_dir*; return the paths.

    Every refusal happens first: the archive is verified in full, then the
    destination is checked, and only then is the first file written.  A refusal
    after a partial write would leave the coverage directory in a state no
    reader can distinguish from a rebuild, which is the one outcome this
    command exists to avoid.

    ``force`` overrides the "a document here differs from the one you are
    restoring" refusal and nothing else: a corrupt archive, a member that is not
    a coverage document and an unreadable file are still refusals, because a
    force flag a reader has to trust about data integrity is the flag that
    eventually turns a routine restore into the disaster.
    """
    info, members = _verify_archive(archive)
    existing = {name: (db_dir / name) for name, _s, _d in info.members}
    if not force:
        clashing = []
        for name, path in existing.items():
            if not path.exists():
                continue
            try:
                current = path.read_bytes()
            except OSError as exc:
                raise BackupError(f"cannot read {path} to compare it: {exc}") from exc
            if current != members[name]:
                clashing.append(path)
        if clashing:
            listed = ", ".join(str(p) for p in sorted(clashing))
            raise BackupError(
                f"refusing to roll coverage back over {len(clashing)} document(s) that "
                f"differ from {archive}: {listed}. The archive was taken {info.created}, and "
                "'recoverage regen' cannot recover what a rollback discards. "
                "Re-run with --force if the rollback is what you want."
            )
    db_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, _size, _digest_hex in info.members:
        destination = db_dir / name
        try:
            _atomic_write(destination, members[name])
        except OSError as exc:
            raise BackupError(f"cannot write {destination}: {exc}") from exc
        written.append(destination)
    return written
