"""Verified backup and restore of the coverage documents.

These helpers archive explicitly selected portable exports. Canonical project
identities, verdicts, history and verification belong to Rebrew's metadata owners
and project backups; these helpers never overwrite those stores. Archives retain
only their exported facts and evidence, not the original source/binary inputs.
Preserve old exported history through ``rebrew coverage import-history`` before
retiring exports. Portable parse caches and process memos are derived data.

A backup also refuses a snapshot set whose documents reference files the
archive does not carry. A portable export names its original binary in
``metadata.paths`` (``originalDll``); that input lives outside the
``coverage-*.toml`` glob, so the glob alone would archive a dashboard that
renders the map but cannot serve disassembly, with no signal until the
restore. ``_referenced_files`` collects every referenced path that resolves
inside the snapshot directory, and ``write_backup`` archives those files
beside the documents (flat, name-sorted, deduplicated by name);
``restore_backup`` puts them back with the same all-or-nothing staging. A
referenced file outside the snapshot directory, or a name collision between
a document and a referenced file, is a refusal rather than a silent omission:
the missing piece is named, so the operator copies the input into the export
or backs the project up through its owners instead of discovering the gap at
restore time. Files no document references are not archived — archiving the
whole directory would also carry stray files an operator left there, which a
restore would then write back as if they were part of the export.

``metadata.paths.sourceRoot`` is the one reference this module refuses
outright rather than archives: it names a tree, not a file, and the archive
format carries one flat member per name. Carrying the tree would need member
names that are paths, which the restore's flat staging cannot hold without
one member writing over another. So a document naming a ``sourceRoot`` is a
backup refusal naming it, and the source tree is backed up through its
owning project like every other input the archive excludes (see
``docs/RECOVERY.md``); a restore of a portable archive never claims the
source pane it did not carry.

Four properties the format has, and why each is here:

* **Verified on write and on read.**  ``manifest.json`` carries the sha256 of
  every member, and :func:`verify_backup` re-reads each member's bytes and
  recomputes them.  A backup whose success is measured by its own exit code is
  a hypothesis; the check that makes it a backup is the same one a restore runs
  before it touches anything.
* **A failed restore rolls back.** Every member is verified and staged before
  publication. Original documents are kept until the last replacement succeeds
  and restored on a handled failure; a failed rollback retains them for manual
  recovery. Stop readers during restore: publication is per file, and a process
  or machine crash can leave an interrupted restore's staging directory behind.
* **A restore will not roll coverage backwards silently.**  It refuses, before
  writing anything, when a document already in the coverage directory differs
  from the one the archive holds unless the caller passes ``force``.  Restoring
  an old archive replaces differing offline facts; canonical live verdicts and
  history are outside this operation.
* **The archive is plain tar.**  Documents and manifest, uncompressed, member
  order fixed, POSIX ``PAX`` format, so ``tar -tf`` lists it and an operator
  reaches into it with the tools they already have.

Where the archive goes is ``RECOVERAGE_BACKUP_DIR``, or the ``--to`` flag, or
:func:`default_backup_dir` — a ``backups/`` beside the coverage directory, never
inside it, because the glob a restore reads would then grow a member that is not
a coverage document and a later backup would carry the earlier one.
* **Re-running backup is safe.**  A repeat at an explicit ``--to`` file
  holding identical bytes verifies and returns that archive; one holding
  different bytes is refused, never overwritten.  A default (stamped)
  name is retried under the next free suffix — a cron retry or two runs
  in one instant still produce a verified archive instead of failing on
  the first run's file.
"""

from __future__ import annotations

import contextlib
import logging
import math
import threading
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
lazy import hashlib
lazy import io
lazy import json
lazy import os
lazy import shutil
lazy import tarfile
lazy import tempfile
lazy from collections.abc import Iterator
lazy from typing import Any, Final

from recoverage.config import RecoError, json_depth_exceeds
lazy from recoverage import clock, metrics
lazy from recoverage.documents import COVERAGE_GLOB

_log = logging.getLogger("recoverage")


def _name_key(name: str) -> str:
    """The case-folded identity of a flat member name: two spellings one name.

    Archives are flat and restored flat, so two members whose names differ only
    by case (or by an NFC/NFD spelling) are one file on a case-insensitive
    filesystem and must be refused as a collision everywhere, not written
    as two members that collide on the restore target.
    """
    return unicodedata.normalize("NFC", name).casefold()


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

#: Bounds the concurrent, per-directory backup/restore operations in this process.
#: ``write_backup`` reads the coverage documents and ``restore_backup`` replaces
#: them; without coordination two in-process threads can interleave their reads
#: or double-publish a restore, while ``_atomic_write`` already makes each
#: individual file publish atomic.  The in-process lock alone cannot see another
#: process, so the critical sections below also take a cross-process advisory
#: lock beside the coverage directory (mirroring ``regen._project_lock``): a
#: cron retry and a CLI run over the same directory converge instead of
#: interleaving reads/publish/prune, and a killed holder releases it because
#: the lock is held on an open descriptor.  The drill takes the same lock
#: beside its drill directory through the restore it runs: two concurrent
#: drills into one directory serialize on it, and the second reads the
#: directory the first left and converges on the comparison rather than
#: racing two restores into it.
_BACKUP_LOCK = threading.Lock()

#: Name of the cross-process lock ``write_backup``/``restore_backup`` take
#: inside the coverage directory.  It is a dot-file so neither the coverage
#: glob nor a restore's doc removal ever treats it as a document.
_BACKUP_LOCK_NAME: Final = ".recoverage-backup.lock"


@contextlib.contextmanager
def _backup_file_lock(db_dir: Path) -> Iterator[None]:
    """Hold the cross-process advisory lock for *db_dir* (blocking).

    Blocking (unlike the regen lock, which refuses): a backup/restore retry
    that must converge cannot fail merely because a healthy sibling is
    mid-write — it waits for that write, then finds the identical archive
    its dedup check names.  The lock is the open descriptor, so a crash
    releases it and the retry proceeds.
    """
    db_dir.mkdir(parents=True, exist_ok=True)
    lock_path = db_dir / _BACKUP_LOCK_NAME
    handle = lock_path.open("a+")
    try:
        if os.name == "posix":
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        else:
            import msvcrt

            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
                    break
                except OSError:
                    clock.sleep(0.05)  # device lock is poll-based on Windows
        try:
            yield
        finally:
            if os.name == "posix":
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                import msvcrt

                with contextlib.suppress(OSError):
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
    finally:
        handle.close()
        # Best-effort cleanup: the lock file is not a document, but a stray
        # per coverage directory breaks the restore no-op/rollback exact-
        # contents invariant and a later prune.  Removing it after the
        # advisory lock is released is safe: the in-process lock serializes
        # this process, and a racing cross-process opener that already
        # opened the old inode simply recreates one on its next run; a
        # failed unlink (another holder raced us) leaves it for next time.
        with contextlib.suppress(OSError):
            lock_path.unlink()


#: How many stamped archives to keep in the backup directory.  Unbounded
#: growth is the silent failure mode of a nightly job: the volume fills
#: until the backup (and then the dashboard) fails.  30 keeps a month of
#: daily backups; older archives are deleted after a successful new one.
_RETENTION_COUNT: Final = 30

#: The tightest cadence a backup schedule may declare before it must name an
#: archive older than this as overdue. Independent of the coverage-staleness
#: bound in recoverage.config (which judges the data): a dashboard can serve
#: fresh documents while every backup job has silently stopped, and the only
#: signal is the newest archive's age. 25 hours is one missed nightly run
#: plus an hour of scheduling slack; a schedule that runs less often than
#: daily names its own threshold instead of inheriting this one.
BACKUP_OVERDUE_HOURS: Final = 25

#: Bounds for the reader vs archive a hostile archive could declare. Both
#: cover DATA members only; ``manifest.json`` is excluded from both because
#: it is the verifier's own metadata, not a payload, and counting it would
#: refuse a legitimately-sized archive whose manifest pushes it over the cap.
_MAX_MEMBER_BYTES: Final = 1 << 30
_MAX_ARCHIVE_BYTES: Final = 1 << 30


class BackupError(RecoError, RuntimeError):
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


def _find_identical_archive(archive_dir: Path, members: list[tuple[str, bytes]]) -> Path | None:
    """Newest stamped archive whose member digests match *members*, or None.

    Compares the manifest's member digests (never the archive bytes, whose
    ``created`` stamp differs per attempt). Unreadable/non-stamped entries
    are skipped. Bounded by _RETENTION_COUNT via the directory contents:
    no ledger grows without bound.
    """
    want = {name: hashlib.sha256(data).hexdigest() for name, data in members}
    try:
        candidates = _stamped_archives(archive_dir)
    except OSError as exc:
        _log.warning(
            "backup: cannot list archives in %r to find an identical one: %r",
            str(archive_dir),
            str(exc),
            extra=metrics.log_fields(
                event="backup_idempotency_failed",
                path=str(archive_dir),
                error=f"{type(exc).__name__}: {exc}",
            ),
        )
        return None
    for _instant, _name, path in reversed(candidates):
        try:
            manifest, _contents = _read_archive(path)
        except BackupError, OSError, ValueError, tarfile.TarError:
            continue
        have = {
            str(m.get("name")): str(m.get("sha256"))
            for m in manifest.get("members", [])
            if isinstance(m, dict)
        }
        if have == want:
            return path
    return None


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

    A set-but-blank value is a misconfiguration, not an unset one: unit
    files and cron environments spell "not configured" as ``""``, and silently
    falling back to the default would write the archive where the operator
    does not look. Raise :class:`BackupError` so the backup command reports it
    and exits non-zero instead.
    """
    raw = os.environ.get("RECOVERAGE_BACKUP_DIR")
    if raw is None:
        return default_backup_dir(coverage_dir)
    if not raw.strip():
        raise BackupError("RECOVERAGE_BACKUP_DIR: set but empty (unset it, or give it a path)")
    try:
        return Path(raw).expanduser()
    except RuntimeError:
        raise BackupError(
            f"RECOVERAGE_BACKUP_DIR: {raw!r} expands a home directory this host cannot determine"
        ) from None


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

#: Epoch second bounds for the same conversion.  ``datetime.fromtimestamp``
#: goes through the C runtime and raises OSError on Windows outside roughly
#: 1970-3000, so an instant is built from the epoch by integer arithmetic
#: instead.  An out-of-range wall clock (bad RTC, frozen replay) clamps to
#: the extreme rather than taking the backup down.
_MIN_WALL_SECONDS = -62_135_596_800  # 0001-01-01T00:00:00Z
_MAX_WALL_SECONDS = 253_402_300_799  # 9999-12-31T23:59:59Z


def _epoch_plus(seconds: float) -> datetime:
    """The UTC instant *seconds* after the epoch, without a C-runtime leap.

    ``datetime.fromtimestamp`` raises OSError on Windows for instants outside
    roughly 1970-3000.  Integer seconds plus a microsecond remainder keeps
    the conversion exact and off that path; out-of-range values clamp.
    """
    if not math.isfinite(seconds):
        # A bad RTC or a frozen replay can hand back inf/nan; divmod on either
        # yields nan and int() on it raises, taking the backup down over a
        # stamp it was meant to clamp.  Pin to the extreme in the direction
        # the sign names, nan to the epoch.
        whole_int = _MAX_WALL_SECONDS if seconds > 0 else _MIN_WALL_SECONDS if seconds < 0 else 0
        return _EPOCH + timedelta(seconds=whole_int)
    whole_float, frac = divmod(seconds, 1.0)
    whole = min(max(int(whole_float), _MIN_WALL_SECONDS), _MAX_WALL_SECONDS)
    micros = int(frac * 1_000_000)
    return _EPOCH + timedelta(seconds=whole, microseconds=micros)


def _stamp(now: float | None = None) -> str:
    """A UTC instant, ISO-8601, for the manifest and the default archive name.

    ``clock.wall_time`` rather than ``time.time``: every instant this package
    renders or names comes from that seam, so a replay of a backup run reads
    from one clock, and a restored archive's ``created`` is comparable with
    ``restored_at`` in the same run.  ``%f`` to microseconds and ``Z`` rather
    than ``+00:00``: the name has to survive a filename limit on every host, and
    a colon in a filename is a quote on Windows.

    UTC, never the host's local time, and fixed width — this name is the
    backup directory's index.  ``docs/RECOVERY.md`` has the operator pin their
    crontab to a stated zone, and the only way that promise holds on a host
    whose ``TZ`` changes (or that observes DST) is for the name to name an
    instant rather than a wall clock reading: a local name would step an hour
    against the crontab at every transition, and two such names sort wrong
    against each other.  ``sorted()`` over the directory is the "newest backup"
    every runbook step assumes, and fixed width is what makes it the same
    order.
    """
    return _instant(now).strftime("%Y%m%dT%H%M%S.%fZ")


def _created_stamp(now: float | None = None) -> str:
    """The manifest's ``created`` field: the same instant, ISO-8601."""
    return _instant(now).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _instant(now: float | None = None) -> datetime:
    """The one instant a backup run names, read once from the clock seam."""
    return _epoch_plus(clock.wall_time() if now is None else now)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_dir(path: Path) -> None:
    """fsync a directory so a rename inside it survives a power loss.

    POSIX only, and best effort; Windows does not attempt directory sync.
    Failures are logged. Without it the archive name can be lost
    after a crash even though its bytes are on disk, which is exactly the
    "the backup ran, there is nothing there" case this module exists to close.
    """
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        _log.warning(
            "Cannot fsync directory %r for durability: %r",
            str(path),
            str(exc),
            extra=metrics.log_fields(
                event="backup_fsync_failed",
                path=str(path),
                error=f"{type(exc).__name__}: {exc}",
            ),
        )


def _atomic_write(path: Path, data: bytes) -> None:
    """Publish *data* at *path* through a temp file in the same directory.

    A half-written backup is the one artifact this whole module exists to
    prevent, so nothing is ever created in place: it lands by ``os.replace``,
    which is atomic on POSIX and on NTFS, and a reader either sees the previous
    archive or the complete new one.  The temp file is a sibling so the replace
    stays inside one filesystem, and both the file and the directory are fsynced
    before the name is published — a rename whose bytes were never flushed is a
    name pointing at nothing after a crash.

    Repeatability: the caller names the destination, and a repeat with the
    same name is refused rather than overwriting. ``tmp.replace(path)`` would
    silently replace an archive an earlier run wrote — the same stamp from a
    frozen/patched clock, a cron retry inside one microsecond, or a deliberate
    re-run at the same output path — losing the earlier backup. The publish
    uses ``os.link`` (fail-if-exists) + unlink so the check and the publish
    are one step, not a check-then-replace race between two backup runs.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise BackupError(
            f"backup {path} already exists; refusing to overwrite it "
            "(a repeat run must not silently replace an earlier backup)"
        )
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        try:
            fh = os.fdopen(fd, "wb")
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
        with fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError as exc:
            raise BackupError(
                f"backup {path} already exists; refusing to overwrite it "
                "(a repeat run must not silently replace an earlier backup)"
            ) from exc
        except OSError:
            # Windows: hard links need privilege / share the volume and
            # fail with PermissionError (EPERM) on some filesystems.
            # Fall back to an atomic exclusive create: open the
            # destination with "xb" so a repeat run still fails if a
            # winner landed first, then copy the temp bytes in.
            if os.name != "nt":
                raise
            try:
                with path.open("xb") as dst:
                    dst.write(tmp.read_bytes())
                    dst.flush()
                    os.fsync(dst.fileno())
            except FileExistsError as exists_exc:
                raise BackupError(
                    f"backup {path} already exists; refusing to overwrite it "
                    "(a repeat run must not silently replace an earlier backup)"
                ) from exists_exc
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    try:
        tmp.unlink()
    except OSError as exc:
        _log.warning(
            "backup: cannot remove temp file %r after publish: %r",
            str(tmp),
            str(exc),
            extra=metrics.log_fields(
                event="backup_cleanup_failed",
                path=str(tmp),
                error=f"{type(exc).__name__}: {exc}",
            ),
        )
    _fsync_dir(path.parent)


def _default_archive_path(directory: Path, now: float | None = None) -> Path:
    """A stamped archive name in *directory* that does not yet exist.

    The stamp alone is not a unique key: a frozen/patched clock, a cron
    retry inside one microsecond, or two runs in the same instant name the
    same file, and the fail-if-exists publish then refuses the retry — the
    first backup survives but the retry reports failure.  Probing for the
    next free suffix keeps the default path retryable: the publish still
    fails if a winner lands between probe and link, so the probe only
    picks which name to attempt, never whether to publish.
    """
    base = f"{_ARCHIVE_PREFIX}{_stamp(now)}{_ARCHIVE_SUFFIX}"
    candidate = directory / base
    if not candidate.exists():
        return candidate
    stem, dot, suffix = base.rpartition(".")
    for n in range(2, 1000):
        candidate = directory / f"{stem}-{n}{dot}{suffix}"
        if not candidate.exists():
            return candidate
    # The stamp has 10^6 subdivisions per second; a thousand collisions
    # in one instant means the directory is being written by many
    # concurrent schedulers.  Let the publish fail-if-exists and report
    # it rather than probing forever.
    return directory / base


def _members(db_dir: Path) -> list[tuple[str, bytes]]:
    """``(name, bytes)`` for every coverage document in *db_dir*, name-sorted.

    An unreadable document is a refusal, not a skip: a backup that silently
    omits one target verifies cleanly yet restores to a dashboard missing
    that target — the gap is invisible until the restore that needs it.
    A scheduled job hitting a transient read error must fail loudly (and
    alert on the non-zero exit) rather than record a partial archive as
    the night's good backup.
    """
    out: list[tuple[str, bytes]] = []
    seen: dict[str, str] = {}
    for path in sorted(db_dir.glob(COVERAGE_GLOB)):
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise BackupError(f"cannot read coverage document {path}: {exc}") from exc
        # A symlinked document must not be followed out of the coverage
        # directory: read only a regular file, and refuse a link whose
        # target escapes (or any link at all, since the glob should name
        # the document itself). ``is_symlink`` first so a dangling link is
        # refused by name rather than as a read error.
        if path.is_symlink():
            raise BackupError(f"coverage document {path} is a symlink; refusing to follow it")
        # Two documents whose names differ only by case are one file on a
        # case-insensitive filesystem (macOS APFS, Windows): the archive is
        # flat, so a second member with the folded name would overwrite the
        # first on restore. Refuse here rather than archive both.
        key = _name_key(path.name)
        if key in seen:
            raise BackupError(
                f"coverage documents {seen[key]!r} and {path.name!r} collide on a "
                "case-insensitive filesystem; the archive names members once"
            )
        seen[key] = path.name
        out.append((path.name, data))
    return out


def _metadata_paths(documents: list[tuple[str, bytes]]) -> list[tuple[str, dict[str, str]]]:
    """Every document's ``metadata.paths`` table, as stored.

    Parsed with the same TOML reader the documents are read with, because a
    document that does not parse cannot name a file this backup must carry
    and is refused here rather than silently treated as referencing nothing:
    a malformed document that verifies as bytes would otherwise archive
    without the binary it needs. Non-string values are refused for the
    same reason - the reader that serves them expects a path spelling.
    """
    import tomllib

    out: list[tuple[str, dict[str, str]]] = []
    for name, data in documents:
        try:
            doc = tomllib.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise BackupError(f"cannot parse coverage document {name}: {exc}") from exc
        metadata = doc.get("metadata", {})
        if not isinstance(metadata, dict):
            raise BackupError(f"{name}: metadata is not a table")
        paths = metadata.get("paths", {})
        if not isinstance(paths, dict):
            raise BackupError(f"{name}: metadata paths is not a table")
        for key, value in paths.items():
            if not isinstance(value, str):
                raise BackupError(f"{name}: metadata.paths.{key} is {value!r}, not a path")
        out.append((name, paths))
    return out


def _referenced_paths(documents: list[tuple[str, bytes]]) -> list[str]:
    """Every paths value a document names under its metadata table, as stored."""
    return [
        value for _name, paths in _metadata_paths(documents) for value in paths.values() if value
    ]


def _source_root_refusal(documents: list[tuple[str, bytes]]) -> None:
    """Refuse a document naming sourceRoot by key, even when absent/empty.

    sourceRoot names a tree, not a file, and the flat archive cannot carry
    it; a backup that archives around it would restore the map and silently
    drop the source pane. The refusal names the exclusion, not "not present".
    """
    for _name, paths in _metadata_paths(documents):
        if "sourceRoot" in paths:
            raise BackupError(
                "referenced path 'sourceRoot' names a source tree, which the flat "
                "archive cannot carry; back the source tree up through its owning "
                "project instead of the portable snapshot"
            )


def _referenced_files(db_dir: Path, documents: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    """Referenced files inside the snapshot directory, as flat name/bytes pairs.

    A referenced path is resolved against db_dir the way the portable
    reader resolves it (leading slash stripped, then contained under the
    snapshot directory). What resolves outside, does not exist, is a
    directory or a symlink is a refusal naming the value: the archive must
    not claim to carry what it does not. Two referenced files that spell
    the same member name, or a referenced file whose name collides with a
    coverage document, is also a refusal - the tar names members once and
    the restore stages them flat, so a collision would silently keep one.

    One value is refused by name before any of that: ``metadata.paths.
    sourceRoot``. It names a directory tree, and the tar carries one flat
    member per file name, so carrying the tree would need path-shaped
    member names the restore cannot stage without collisions. Refusing it
    here, rather than failing on ``is_file()`` with "not present", tells the
    operator the source tree is excluded by design and belongs to the
    project backup, instead of reading as a missing file they could copy in.
    The check is on the paths table, not on the resolved tree, so even an
    empty or absent ``sourceRoot`` refuses: a backup that archives around it
    would restore the map and silently drop the source pane.
    """
    _source_root_refusal(documents)
    found: dict[str, Path] = {}
    for ref in _referenced_paths(documents):
        if "\x00" in ref:
            raise BackupError(f"referenced path {ref!r} carries a NUL byte")
        # A portable export is a cross-platform document: a Windows-written
        # one spells separators as "\\", which is a filename character on
        # POSIX, so normalize before the host Path parses it (the same
        # replace _contained_source_path and _stored_names_source apply).
        relative = Path(ref.replace("\\", "/").removeprefix("/"))
        if ".." in relative.parts or relative.is_absolute():
            raise BackupError(
                f"referenced path {ref!r} escapes the snapshot directory {db_dir}; "
                "copy it into the export or back the project up through its owners"
            )
        candidate = db_dir / relative
        if candidate.is_symlink():
            raise BackupError(f"referenced file {candidate} is a symlink; refusing to follow it")
        if not candidate.is_file():
            raise BackupError(
                f"referenced file {candidate} (from {ref!r}) is not present in the "
                f"snapshot directory {db_dir}; the archive would restore without it"
            )
        key = _name_key(candidate.name)
        if key in found:
            raise BackupError(
                f"referenced files {found[key]} and {candidate} share one name; "
                "the archive names members once and cannot carry both"
            )
        found[key] = candidate
    document_names = {_name_key(name) for name, _data in documents}
    for name in found:
        if name in document_names:
            raise BackupError(
                f"referenced file {name!r} collides with a coverage document of the same name"
            )
    out: list[tuple[str, bytes]] = []
    for _key, path in sorted(found.items(), key=lambda item: item[1].name):
        try:
            out.append((path.name, path.read_bytes()))
        except OSError as exc:
            raise BackupError(f"cannot read referenced file {path}: {exc}") from exc
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


def _require_outside_coverage_dir(db_dir: Path, destination: Path) -> None:
    """Refuse a backup whose archive lands inside the directory it backs up.

    The archive is a tar file, not a ``coverage-*.toml`` member, so a later
    backup would not copy it as a document — but leaving an archive inside
    the snapshot tree mixes backup storage with the data it protects (one
    directory delete destroys both) and puts a file a reader's glob
    directory holds that is not a document.  The default location already
    sits beside the coverage directory; this guards the explicit
    ``--to`` / ``RECOVERAGE_BACKUP_DIR`` spellings that can point inside it.
    """
    try:
        inside = destination.resolve().is_relative_to(db_dir.resolve())
    except OSError as exc:
        # Fail closed: an unresolvable destination (dangling symlink, loop,
        # permission) cannot be proven outside the coverage directory, so
        # admitting it risks the archive landing inside the data it protects.
        raise BackupError(f"cannot resolve backup destination {destination}: {exc}") from exc
    if inside:
        raise BackupError(
            f"backup destination {destination} is inside the coverage directory {db_dir}; "
            "backups must live outside the directory they back up, "
            "or a later restore reads its own archive as a document and one "
            "deletion removes data and backup together"
        )


def _prune_old_archives(archive_dir: Path) -> None:
    """Delete stamped archives beyond _RETENTION_COUNT, oldest first.

    Only names this module writes (prefix+suffix+timestamp shape) are
    considered, so an operator's other files in the directory are never
    removed. Order is the stamped instant, not the lexicographic name:
    ``_default_archive_path`` appends ``-2``..``-999`` for same-microsecond
    collisions, so ``coverage-…000000Z-2.tar`` and ``coverage-…000000Z.tar``
    share one instant and must not be ordered by name alone when pruning.
    Best-effort: a deletion failure is logged, not raised —
    the new backup already verified and must not be reported as failed
    because the old ones could not be pruned.

    Pruning is itself a deletion path, and the oldest archive it deletes
    is the recovery point for a logical corruption discovered later
    ("restore the oldest archive that predates it" — ``docs/RECOVERY.md``).
    A prune that deletes against a directory whose retained edge no
    longer verifies turns recoverable corruption into total loss, so the
    survivors are verified before any non-survivor is deleted; a survivor
    that does not verify skips the prune (logged, not raised) and lets the
    freshness monitor surface the corruption instead.
    """
    try:
        candidates = _stamped_archives(archive_dir)
    except OSError as exc:
        _log.warning(
            "backup: cannot list archives in %r to prune old ones: %r",
            str(archive_dir),
            str(exc),
            extra=metrics.log_fields(
                event="backup_prune_failed",
                path=str(archive_dir),
                error=f"{type(exc).__name__}: {exc}",
            ),
        )
        return
    if len(candidates) <= _RETENTION_COUNT:
        return
    keep = candidates[-_RETENTION_COUNT:]
    stale = [p for _instant, _name, p in candidates[:-_RETENTION_COUNT]]
    # Verify the survivors before deleting anything: the newest archive a
    # logical-corruption restore reaches for is the oldest one retained,
    # and it must still verify.  A corrupt survivor means the directory
    # holds no verified recovery point at its edge; prune then would
    # discard the older (possibly good) archives around it.  Skip the
    # prune and let the freshness monitor surface the corruption.
    # The check stops at the first verified survivor: retention is a
    # deletion path, and the edge the restore reaches for is the newest
    # one, not the whole window.
    for _instant, _name, path in keep:
        try:
            verify_backup(path)
        except BackupError as exc:
            _log.warning(
                "backup: skipping prune of %d archive(s) in %r: %r does not verify (%r)",
                len(stale),
                str(archive_dir),
                str(path),
                str(exc),
            )
            return
        break
    for stale_archive in stale:
        try:
            stale_archive.unlink()
        except OSError as exc:
            _log.warning(
                "backup: cannot prune old archive %r: %r",
                str(stale_archive),
                str(exc),
                extra=metrics.log_fields(
                    event="backup_prune_failed",
                    path=str(stale_archive),
                    archive=stale_archive.name,
                    error=f"{type(exc).__name__}: {exc}",
                ),
            )


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
    green run.  A destination inside *db_dir* is refused for the same reason
    the default is beside it: an archive inside the tree it archives shares
    its failure domain.
    """
    with _BACKUP_LOCK, _backup_file_lock(db_dir):
        return _write_backup(db_dir, destination)


def _write_backup(db_dir: Path, destination: Path | None = None) -> BackupInfo:
    documents = _members(db_dir)
    members = documents + _referenced_files(db_dir, documents)
    if not documents:
        raise BackupError(
            f"no {COVERAGE_GLOB} document in {db_dir}; nothing to back up. "
            "Run 'rebrew coverage export --output <directory>' first, then select that "
            "directory with RECOVERAGE_SNAPSHOTS."
        )
    # Resolve the destination before writing anything, so a blank backup
    # directory fails before the archive is built.  One instant names both
    # the file and the manifest field inside it, so the two cannot straddle
    # a clock step (an NTP correction between the calls would otherwise
    # name the archive by one instant and date it by another).
    now = clock.wall_time()
    stamped_default = destination is None or destination.is_dir()
    if destination is None:
        destination = _default_archive_path(backup_dir_from_env(db_dir), now)
    elif destination.is_dir():
        destination = _default_archive_path(destination, now)
    created = _created_stamp(now)
    manifest = _manifest(members, created)
    blob = _tar_bytes(members, manifest)
    _require_outside_coverage_dir(db_dir, destination)
    # Idempotency: a retry (cron redelivery, replayed drill) whose documents
    # have not changed must not mint a new archive and prune a distinct older
    # one. For a stamped default, return an existing archive holding
    # identical member digests instead. The manifest's created stamp differs
    # per attempt, so compare member digests, not blob bytes.
    if stamped_default:
        found = _find_identical_archive(destination.parent, members)
        if found is not None:
            return verify_backup(found)
    try:
        _atomic_write(destination, blob)
    except BackupError:
        # A repeat at an explicit path holds identical bytes: its retry
        # converged, so verify the existing archive instead of refusing.
        try:
            identical = destination.is_file() and destination.read_bytes() == blob
        except OSError as exc:
            raise BackupError(
                f"cannot read existing backup {destination} to check a repeat: {exc}"
            ) from exc
        if identical:
            return verify_backup(destination)
        raise
    except OSError as exc:
        raise BackupError(f"cannot write backup {destination}: {exc}") from exc
    try:
        info = verify_backup(destination)
    except BackupError:
        # A failed verify must not leave the unverified archive behind: it
        # becomes the newest file in the backup directory, and a freshness
        # monitor reading mtime alone would call it fresh while it cannot
        # be restored. Remove it (best effort) so the directory holds only
        # archives that were read back once. The directory fsync already
        # happened inside ``_atomic_write`` before the name was published;
        # this second fsync covers the removal.
        with contextlib.suppress(OSError):
            destination.unlink()
        _fsync_dir(destination.parent)
        raise
    # Prune only after fsync+verify: retention deletes the oldest archives,
    # so a crash before the new one's directory entry is durable must not
    # have already discarded a previous good backup.
    _prune_old_archives(destination.parent)
    return info


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
                if member.name == MANIFEST_NAME:
                    # The verifier's own metadata: bounded by json_depth_exceeds
                    # below, not by the payload caps. A hostile manifest is
                    # still held in memory, but it is one small JSON document
                    # whose depth is checked before decode.
                    declared.append(member)
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
                # extractfile returns a file-like (ExFileObject) that is not
                # closed by leaving the tar; closing it releases the archive's
                # underlying descriptor on this cold CLI path per member.
                # The manifest is read to its declared size (bounded by the
                # depth check below, not the payload cap); payload members
                # use the cap + 1 sentinel.
                if member.name == MANIFEST_NAME:
                    read_limit = member.size + 1
                else:
                    read_limit = _MAX_MEMBER_BYTES + 1
                with handle:
                    payload = handle.read(read_limit)
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
        if json_depth_exceeds(manifest_raw):
            raise ValueError("manifest JSON nests too deeply")
        manifest: Any = json.loads(manifest_raw)
    except (UnicodeError, ValueError, RecursionError) as exc:
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

    # An archive's manifest is the COMPLETE member list, not a subset:
    # a tar member the manifest never names is bytes no digest covers,
    # and a restore that silently ignores it proves less than it claims.
    # Refuse rather than verify a subset and restore around the rest.
    manifest_names = {entry.get("name") for entry in entries if isinstance(entry, dict)}
    unlisted = sorted(
        name for name in members if name != MANIFEST_NAME and name not in manifest_names
    )
    if unlisted:
        raise BackupError(
            f"{path}: member(s) not in {MANIFEST_NAME}: {', '.join(unlisted)}; "
            "the archive is not a recoverage backup as written"
        )
    # A manifest with no coverage document restores to an empty
    # dashboard; a referenced binary alone is not coverage.
    if not any(
        isinstance(entry, dict)
        and isinstance(entry.get("name"), str)
        and _is_coverage(entry["name"])
        for entry in entries
    ):
        raise BackupError(
            f"{path}: manifest names no {COVERAGE_GLOB} document; "
            "a backup with no coverage document restores to an empty dashboard"
        )

    documents: dict[str, bytes] = {}
    try:
        for entry in entries:
            name = entry["name"]
            # Names come from the archive's editable manifest. Refuse path
            # components in either platform's spelling before joining the destination.
            if (
                not isinstance(name, str)
                or Path(name).name != name
                or PureWindowsPath(name).name != name
                or name == MANIFEST_NAME
            ):
                raise BackupError(f"{path}: member name {name!r} is not a safe flat member name")
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
    from fnmatch import fnmatchcase

    return fnmatchcase(name, COVERAGE_GLOB)


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
        if not isinstance(entry, dict):
            raise BackupError(f"{path}: manifest member {entry!r} is not an object")
        name = entry.get("name")
        if not isinstance(name, str):
            raise BackupError(f"{path}: manifest member name {name!r} is not text")
        data = members.get(name)
        if data is None:
            raise BackupError(f"{path}: manifest names {name}, which the archive does not hold")
        if "size" not in entry or "sha256" not in entry:
            raise BackupError(f"{path}: member {name} is missing size or sha256 in the manifest")
        size = entry["size"]
        digest = _digest(data)
        if not isinstance(size, int) or isinstance(size, bool) or len(data) != size:
            raise BackupError(f"{path}: {name} is {len(data)} bytes, manifest says {size!r}")
        if not isinstance(entry["sha256"], str) or digest != entry["sha256"]:
            raise BackupError(
                f"{path}: {name} does not match its manifest digest "
                f"({digest[:12]}…, manifest {str(entry['sha256'])[:12]}…); the backup is corrupt"
            )
        described.append((str(name), len(data), digest))
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


def verify_archive_command(archive: Path) -> BackupInfo:
    """Verify *archive* without restoring it; the CLI ``verify`` command's core.

    A scheduled job and a restore drill both need to prove an archive is
    readable without putting its documents anywhere. This is the same
    :func:`verify_backup` a restore runs first, exposed as its own
    operation rather than requiring a restore to a scratch directory to
    get the proof.
    """
    return verify_backup(archive)


def _archive_stamp_instant(name: str) -> datetime | None:
    """The instant the stamped archive *name* names, or None when it names none.

    The name is ``coverage-<stamp>.tar`` as :func:`_stamp` wrote it, with an
    optional ``-<n>`` collision suffix (see :func:`_default_archive_path`).
    Only names that parse as that shape count as stamped archives, so an
    operator's other ``coverage-*.tar`` file is never mistaken for the
    backup index this module writes.
    """
    if not (name.startswith(_ARCHIVE_PREFIX) and name.endswith(_ARCHIVE_SUFFIX)):
        return None
    inner = name[len(_ARCHIVE_PREFIX) : -len(_ARCHIVE_SUFFIX)]
    if "-" in inner:
        inner, _, _suffix = inner.rpartition("-")
        if not _suffix.isascii() or not _suffix.isdigit():
            return None
    # ``_stamp`` always writes a fixed-width stamp (``%f`` is six digits), and
    # ``strptime``'s ``%f`` accepts one to six, right-padding a short fraction
    # (``.99999`` reads as 999990 microseconds).  A shorter fraction is a name
    # this module never wrote, so refuse it rather than count an operator's
    # hand-made archive as the backup index.
    if len(inner) != 23 or inner[8] != "T" or inner[15] != "." or inner[22] != "Z":
        return None
    if not inner[:8].isascii() or not inner[:8].isdigit():
        return None
    if not inner[9:15].isascii() or not inner[9:15].isdigit():
        return None
    if not inner[16:22].isascii() or not inner[16:22].isdigit():
        return None
    try:
        return datetime.strptime(inner, "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _stamped_archives(directory: Path) -> list[tuple[datetime, str, Path]]:
    """Regular stamped archives in *directory*, oldest first by stamped instant."""
    entries = [
        (instant, path.name, path)
        for path in directory.glob(f"{_ARCHIVE_PREFIX}*{_ARCHIVE_SUFFIX}")
        if path.is_file()
        and not path.is_symlink()
        and (instant := _archive_stamp_instant(path.name)) is not None
    ]
    entries.sort(key=lambda pair: (pair[0], pair[1]))
    return entries


def _newest_stamped_archive(directory: Path) -> Path | None:
    """The newest stamped archive file in *directory*, or None.

    Only regular files with this module's own name shape count: a symlink
    pointing at an archive is not itself a backup (the prune path and the
    document reader both refuse symlinks), and counting it let a link named
    like a fresh archive pass a freshness monitor for bytes nobody wrote.

    Newest is the instant the NAME stamps, not the file's mtime.  The name
    is a UTC instant :func:`_stamp` wrote; a clock step (an NTP correction,
    a manual change, a host restored from a snapshot) moves the filesystem
    mtime of the next write with it, so keying on mtime let an older-named,
    later-written archive outrank the newest one the name indexes — the
    freshness monitor then read the wrong archive, twice over (its age, and
    the archive ``check_backup_freshness`` verifies).  A name that does not
    parse as a stamp is skipped, so a hand-made ``coverage-*.tar`` never
    becomes "newest" by carrying a fresh mtime.
    """
    try:
        stamped = _stamped_archives(directory)
    except OSError as exc:
        _log.warning(
            "Cannot list backup directory %r for newest archive: %r",
            str(directory),
            str(exc),
            extra=metrics.log_fields(
                event="backup_list_failed",
                path=str(directory),
                error=f"{type(exc).__name__}: {exc}",
            ),
        )
        raise BackupError(f"cannot list backup directory {directory}: {exc}") from exc
    if not stamped:
        return None
    return stamped[-1][2]


def newest_archive_age_hours(directory: Path) -> float | None:
    """Age in hours of the newest stamped archive in *directory*, or None.

    None when the directory holds no stamped archive: no backup has ever
    run there, which is the loudest missing-backup signal and the one a
    scheduled-job monitor must not confuse with a fresh one.  An unreadable
    directory raises :class:`BackupError` via :func:`_newest_stamped_archive`
    rather than reading as "no backup taken", so a permission loss cannot
    masquerade as an empty directory.
    Only names this module writes are considered, so an operator's other
    files never count as a backup. Read through the clock seam so a test
    drives the overdue crossing from a patched clock.
    """
    newest = _newest_stamped_archive(directory)
    if newest is None:
        return None
    instant = _archive_stamp_instant(newest.name)
    if instant is None:
        return None
    seconds, remainder = divmod(clock.wall_time(), 1.0)
    now_ns = int(seconds) * 1_000_000_000 + int(remainder * 1_000_000_000)
    delta = instant - _EPOCH
    instant_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    return max(0.0, (now_ns - instant_ns) / 3_600_000_000_000)


def check_backup_freshness(directory: Path, *, max_age_hours: float = BACKUP_OVERDUE_HOURS) -> None:
    """Raise BackupError when *directory* holds no fresh stamped archive.

    The silent-failure arm a scheduled backup needs: a job that stops
    running still exits nothing, so the directory records it as the newest
    archive ageing past the cadence. A missing directory or an empty one
    is the same refusal, naming the directory so a cron alert says where
    the backup was expected rather than that a file was absent.

    A bound that is not a finite, non-negative number is refused rather
    than compared: ``inf`` and ``nan`` compare False against every age, so
    a monitor handed either reads a stale backup as fresh and exits 0
    forever — the one failure this command exists to catch, masked by its
    own argument. A negative bound fails every archive, including a fresh
    one, which is a false alarm from the same unguarded spelling.
    """
    if not math.isfinite(max_age_hours) or max_age_hours < 0:
        raise BackupError(
            f"invalid --max-age-hours {max_age_hours!r}: "
            "must be a finite, non-negative number of hours"
        )
    if not directory.is_dir():
        raise BackupError(f"no backup directory at {directory}; no backup has been taken there")
    age = newest_archive_age_hours(directory)
    if age is None:
        raise BackupError(f"no stamped backup in {directory}; no backup has been taken there")
    if age > max_age_hours:
        raise BackupError(
            f"newest backup in {directory} is {age:.1f}h old, past the "
            f"{max_age_hours}h overdue bound; the backup schedule may have stopped"
        )
    # Age alone is not freshness: a corrupt or truncated newest archive is the
    # backup that will fail the restore, and it must fail this monitor too.
    # The check that makes a backup a backup is reading it back.
    newest = _newest_stamped_archive(directory)
    if newest is not None:
        try:
            verify_backup(newest)
        except BackupError as exc:
            raise BackupError(
                f"newest backup in {directory} does not verify and cannot be restored: {exc}"
            ) from exc


def verify_all_backups(directory: Path) -> list[Path]:
    """Verify every stamped archive in *directory*; return their paths.

    The one-pass monitor :func:`check_backup_freshness` verifies only the
    newest archive.  Retention keeps 30: a corrupt older archive — the
    one a logical-corruption restore would reach for (``docs/RECOVERY.md``:
    "restoring the oldest archive that predates it") — is invisible until
    that restore, and the next backup's prune can delete the good
    archives around it.  A drill or a scheduled re-proof calls this so
    all 30 are read back, not only the newest.
    """
    if not directory.is_dir():
        raise BackupError(f"no backup directory at {directory}; no backup has been taken there")
    try:
        stamped = _stamped_archives(directory)
    except OSError as exc:
        raise BackupError(f"cannot list backups in {directory}: {exc}") from exc
    if not stamped:
        raise BackupError(f"no stamped backup in {directory}; no backup has been taken there")
    for _instant, _name, archive in stamped:
        verify_backup(archive)
    return [archive for _instant, _name, archive in stamped]


def drill_restore(archive: Path, drill_dir: Path) -> list[Path]:
    """Restore *archive* into a fresh *drill_dir*; return the restored paths.

    The drill-only restore: like :func:`restore_backup` the archive is
    verified in full before anything is written, and the drill directory
    must be empty, so a drill can never overwrite the live snapshot
    directory it was pointed at by mistake. A non-empty drill directory
    is refused rather than merged, so a drill dirtied by a previous run
    reads as a hygiene error instead of silently re-proving a stale set.
    The restored bytes go through the same atomic publish
    :func:`restore_backup` uses.

    Repeatability: the rerun of a completed drill (a scheduled drill
    replayed by its scheduler, a retry after the first answer was lost)
    converges when the directory already holds exactly this archive's
    members byte for byte — the proof the operator asked for is still
    true, and the first run already landed it. Any other entry, or a
    document whose bytes differ from the archive's, is refused as a
    dirty drill: converging on a subset of the directory by deleting
    what a retry did not write could drop an operator's files, so the
    refusal stays the answer for everything but the converged state.
    """
    # Verify here, not in the restore: the comparison below needs the
    # archive's member bytes, and the restore verifies again under its
    # lock exactly as it did before this rerun existed.
    _info, members = _verify_archive(archive)
    return _drill_into(archive, drill_dir, members)


def _drill_into(archive: Path, drill_dir: Path, members: dict[str, bytes]) -> list[Path]:
    """The emptiness/converged check and the restore it guards.

    The restore below takes the advisory lock beside *drill_dir*, so
    two concurrent drills into one directory serialize on it: the
    comparison here and the restore it guards cannot be interleaved
    by a second drill into the same directory.
    """
    target = drill_dir
    if drill_dir.exists():
        if not drill_dir.is_dir():
            raise BackupError(
                f"refusing to drill into {drill_dir}: not a directory; "
                "point the drill at a fresh directory"
            )
        try:
            entries = sorted(drill_dir.iterdir())
        except OSError as exc:
            raise BackupError(f"cannot list drill directory {drill_dir}: {exc}") from exc
        if entries:
            if _is_converged_drill(drill_dir, entries, members):
                return [drill_dir / name for name in sorted(members)]
            listed = ", ".join(str(p) for p in entries[:5])
            more = "" if len(entries) <= 5 else f", and {len(entries) - 5} more"
            raise BackupError(
                f"refusing to drill into {drill_dir}: it already holds {len(entries)} "
                f"entr(ies) ({listed}{more}); a drill needs a fresh directory so a "
                "stale set cannot pass as restored"
            )
        target = drill_dir
    else:
        try:
            drill_dir.mkdir(parents=True)
        except OSError as exc:
            raise BackupError(f"cannot create drill directory {drill_dir}: {exc}") from exc
        target = drill_dir
    return restore_backup(archive, target)


def _is_converged_drill(drill_dir: Path, entries: list[Path], members: dict[str, bytes]) -> bool:
    """Whether *entries* are exactly *members*, byte for byte.

    The rerun of a finished drill converges only on the state the first
    run left: the same names and the same bytes. A differing document is
    a dirty drill the refusal must still catch — a stale set edited
    after the first drill must not re-prove the archive — and any extra
    entry is one a drill cannot adopt. Only regular files count;
    a symlink or a directory is not a document this restore writes.
    """
    if {entry.name for entry in entries} != set(members):
        return False
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            return False
        try:
            if entry.read_bytes() != members[entry.name]:
                return False
        except OSError:
            return False
    return True


def restore_backup(archive: Path, db_dir: Path, *, force: bool = False) -> list[Path]:
    """Put every verified member of *archive* into *db_dir*; return the paths.

    Archive and destination validation finish before publication. Files are
    published one at a time; handled failures attempt rollback. If rollback
    fails, the error identifies the retained originals for manual recovery.

    ``force`` permits replacing differing archived files and removing stale
    coverage documents. A corrupt archive, an unsafe member name and an
    unreadable file are still refusals. Archived members can include original
    binaries as well as coverage documents.

    A leftover staging directory from a killed restore (process or machine
    crash between publication steps) is refused rather than overwritten: its
    ``previous/`` files hold the originals the interrupted run had already
    moved, and deleting them to start again would discard the only copy of
    the pre-restore state.  The error names the directory; recovery is to
    inspect ``previous/`` and retry after it is cleared by hand.

    Coverage documents in *db_dir* the archive does not hold are removed
    (under ``force``) as part of the restore: the restored set is the
    archive's set, so a target deleted from the source or added by a bad
    build does not survive. Non-coverage files absent from the archive are
    untouched.
    """
    with _BACKUP_LOCK, _backup_file_lock(db_dir):
        return _restore_backup(archive, db_dir, force=force)


def _restore_backup(archive: Path, db_dir: Path, *, force: bool = False) -> list[Path]:
    if db_dir.is_dir():
        for leftover in sorted(db_dir.glob(".restore-*")):
            if leftover.is_dir():
                raise BackupError(
                    f"refusing to restore: {leftover} from an interrupted restore is "
                    f"still present in {db_dir}; its previous/ files are the only copy "
                    "of the pre-restore documents. Inspect it, restore those files "
                    "by hand if needed, then remove it and retry"
                )
    info, members = _verify_archive(archive)
    existing = {name: (db_dir / name) for name, _s, _d in info.members}
    for path in existing.values():
        if path.exists() and not path.is_file():
            raise BackupError(f"cannot restore over {path}: not a regular document")
    # Stale documents the archive does not hold are part of the restored
    # set, not neighbours of it: a document deleted from the source between
    # backups, or written by a bad build after the archive, must not
    # survive a restore that claims to re-establish the snapshot. Only
    # coverage-shaped members are in scope — other files in the directory
    # (inventory, operator notes) are not the archive's to delete.
    stale: list[Path] = []
    if db_dir.is_dir():
        try:
            stale = sorted(
                path
                for path in db_dir.glob(COVERAGE_GLOB)
                if _is_coverage(path.name) and path.name not in existing
            )
        except OSError as exc:
            raise BackupError(f"cannot list coverage documents in {db_dir}: {exc}") from exc
        for path in stale:
            if not path.is_file():
                raise BackupError(f"cannot restore over {path}: not a regular document")
    if stale and not force:
        listed = ", ".join(str(p) for p in stale)
        raise BackupError(
            f"refusing to restore: {len(stale)} coverage document(s) in {db_dir} are "
            f"not in {archive} and would be removed: {listed}. "
            "Re-run with --force if removing them is what you want."
        )
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
    # Naturally idempotent: a destination already holding the archive's
    # bytes is left untouched, so a rerun (retry, replayed drill, cron
    # redelivery) converges instead of rewriting every document and moving
    # its mtime, which downstream freshness checks read as a new build.
    # The check runs for every member before any write, so a partial
    # match still publishes the differing members atomically below.
    unchanged: set[str] = set()
    for name, path in existing.items():
        try:
            if path.is_file() and path.read_bytes() == members[name]:
                unchanged.add(name)
        except OSError as exc:
            raise BackupError(f"cannot read {path} to compare it: {exc}") from exc
    if len(unchanged) == len(existing) and not stale:
        return list(existing.values())
    try:
        db_dir.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(dir=db_dir, prefix=".restore-"))
    except OSError as exc:
        raise BackupError(f"cannot stage restore in {db_dir}: {exc}") from exc
    written: list[Path] = []
    published: list[Path] = []
    saved: list[Path] = []
    keep_staging = False
    previous = staging / "previous"
    try:
        previous.mkdir()
        # Finish every allocation before replacing any original document.
        for name, data in members.items():
            if name not in unchanged:
                _atomic_write(staging / name, data)
        for name, destination in existing.items():
            if name in unchanged:
                written.append(destination)
                continue
            if destination.exists() or destination.is_symlink():
                destination.replace(previous / name)
                saved.append(destination)
            (staging / name).replace(destination)
            published.append(destination)
            written.append(destination)
        for destination in stale:
            destination.replace(previous / destination.name)
            saved.append(destination)
        _fsync_dir(db_dir)
    except BaseException as exc:
        rollback_errors: list[str] = []
        for destination in reversed(published):
            if destination in saved:
                continue
            try:
                destination.unlink()
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        for destination in reversed(saved):
            try:
                (previous / destination.name).replace(destination)
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        _fsync_dir(db_dir)
        if rollback_errors:
            keep_staging = True
            raise BackupError(
                f"restore failed; rollback incomplete; original files retained in {previous}: "
                + "; ".join(rollback_errors)
            ) from exc
        if isinstance(exc, OSError):
            raise BackupError(f"cannot restore {db_dir}: {exc}") from exc
        raise
    finally:
        if not keep_staging:
            try:
                shutil.rmtree(staging)
            except OSError as exc:
                _log.warning(
                    "Cannot remove restore staging directory %r: %r",
                    str(staging),
                    str(exc),
                    extra=metrics.log_fields(
                        event="restore_cleanup_failed",
                        path=str(staging),
                        error=f"{type(exc).__name__}: {exc}",
                    ),
                )
    return written
