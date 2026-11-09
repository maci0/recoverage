"""Live project views and portable documents with persisted parse caching.

Live projects bypass the portable persisted-parse cache.

The replacement for ``rebrew.coverage_toml.load_all_coverage_from``'s memo,
which keys the whole directory on one stat tuple: a rebuild that rewrote one
target re-parsed every document, and every restart re-parsed all of them.
``tomllib`` is about 90% of a load (632 ms of 706 ms for an 8 MB document), so
two things change here and nothing else does:

- The memo is per document.  A changed stat re-reads that file alone; a stat
  that moved over the same bytes (``touch``, a ``cp -p`` restore) keeps the
  snapshot object it already had.  An unchanged directory still returns THE
  SAME mapping and snapshot objects, the identity ``server`` documents.
- The parsed TOML (the dict ``tomllib`` returns, not the snapshot) is written
  as JSON under ``$XDG_CACHE_HOME/recoverage/documents/``, keyed by the
  document's sha256, so a restart over unchanged documents pays ``json.loads``
  instead of ``tomllib.loads`` (39 ms against 632 ms).  The cached dict goes
  through rebrew's own ``snapshot_from_document`` exactly as a fresh parse does, so a cache
  file is held to the document's schema and is no more trusted than the TOML
  it stands in for.  JSON rather than pickle for the same reason: loading a
  pickle runs code, and the cache directory is not the coverage directory.

The cache is best effort: an unwritable or missing directory, a corrupt file,
an entry rebrew's schema refuses and a document JSON cannot represent (a TOML
datetime) all fall back to the parse, and the first write failure in a process
logs one WARNING.  It holds one file per document path, and every write keeps
the :data:`_CACHE_MAX_SLOTS` most recently used.

``rebrew.coverage_toml.snapshot_from_document`` is the public shared schema
validator, and ``tests/test_documents.py`` holds every snapshot this module builds
equal to the one ``rebrew.coverage_toml.load_coverage_from`` builds.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
lazy import gc
lazy import hashlib
lazy import io
lazy import json
lazy import os
lazy import tempfile
lazy import tomllib
lazy import unicodedata
lazy from collections.abc import Iterator, Mapping
lazy from typing import Any, Final

from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError, snapshot_from_document
lazy from rebrew.coverage_project import (
    ProjectCoverageError,
    ProjectCoverageView,
    load_project_coverage,
)
lazy from rebrew.workspace import CONFIG_NAME

lazy from recoverage import clock, metrics

# The package logger, NOT getLogger(__name__): a filter is run only for the
# records logged on the logger it is installed on, never for a child's, so
# under "recoverage.documents" the request-id filter (server._RequestIdFilter)
# never ran and every line this module wrote reached the log with no `rid`,
# which LOG_FORMAT renders as the `-` placeholder.  Those lines are the
# unreadable-document skip, the discarded cached parse and an unwritable cache
# directory — the three that name WHICH document is broken, landing mid-request
# and read exactly when an operator is chasing the 503 they explain, and none
# of them joinable to the request that produced it.  One logger name across the
# package is what carries the correlation into every module; pinned by
# tests/test_metrics.py::TestRequestId.
_log = logging.getLogger("recoverage")

#: Glob rebrew's writer names its documents with.
_PREFIX: Final = "coverage-"
_SUFFIX: Final = ".toml"

#: That same glob, for the callers that look at the coverage directory without
#: reading a document: ``server._coverage_file_stats`` (the freshness stamp and
#: the health block's file list) and ``cli``'s db warnings.  ONE definition of
#: how rebrew names a document, in the module that owns that knowledge, so a
#: reader and a stat walk cannot drift onto two spellings of one file.
COVERAGE_GLOB: Final = f"{_PREFIX}*{_SUFFIX}"

#: Version of the cache file's own layout.  Bumped when the layout changes, so
#: a file an older build wrote is a miss rather than a misread.
_CACHE_FORMAT: Final = 1

#: Directory under the XDG cache home this package owns.
_CACHE_SUBDIR: Final = ("recoverage", "documents")

#: Hex digits of the slot name: 128 bits of the document path's sha256.
_SLOT_HEX_CHARS: Final = 32

_SLOT_SUFFIX: Final = ".json"
_TMP_SUFFIX: Final = ".tmp"

#: Cache files kept, most recently used first.  One per document path, so this
#: covers 64 documents across every project and worktree served from this
#: account; at 2-10 MB a slot it bounds the directory near half a gigabyte.
_CACHE_MAX_SLOTS: Final = 64

#: Age in seconds past which a temp file is a killed write's leftover rather
#: than a write in progress (a 10 MB write takes milliseconds).
_STALE_TMP_SECONDS: Final = 3600

#: ``(name, mtime_ns, size, ino, ctime_ns)``: the inode and ctime catch a
#: same-size rename-over inside one mtime tick, which mtime and size alone
#: cannot see.
_StatKey = tuple[str, int, int, int, int]


@dataclass(frozen=True)
class _Doc:
    stat: _StatKey
    digest: str
    snapshot: CoverageSnapshot


#: One directory's state: its path, the stat of every document, each document's
#: memo entry, the mapping handed to callers, and why each document that failed
#: to load did (file name to reason).  One slot, like rebrew's: a scan of
#: another directory drops the previous one's entries.  Swapped as a whole
#: tuple, which is atomic under the GIL; a miss is serialized by
#: :data:`_LOAD_LOCK`.
_State = tuple[
    Path, tuple[_StatKey, ...], dict[str, _Doc], dict[str, CoverageSnapshot], dict[str, str]
]
_STATE: _State | None = None

#: Serializes a reload, so a request herd after a rebuild parses each changed
#: document once and the collector pause below has one owner.  The hit path
#: never takes it.
_LOAD_LOCK = threading.Lock()
_WRITE_WARNED_LOCK = threading.Lock()

#: Whether this process has already warned about a cache write failure.
_WRITE_WARNED = False


@contextlib.contextmanager
def _paused_gc() -> Iterator[None]:
    """Disable the cyclic collector, restoring the prior state on exit.

    The pause restores whether the collector was enabled on entry, so a
    caller that arrived with it disabled keeps it disabled, and an
    exception during the rebuild cannot leave it off for the rest of the
    process.  Caller holds :data:`_LOAD_LOCK`; the pause is process-wide,
    so two overlapping rebuilds must not each restore their own prior
    state.
    """
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def _stat_key(db_dir: Path) -> tuple[_StatKey, ...]:
    """Every document's stat, name-sorted; a file that vanished is skipped."""
    entries: list[_StatKey] = []
    for path in db_dir.glob(COVERAGE_GLOB):
        try:
            st = path.stat()
        except OSError:
            continue
        entries.append((path.name, st.st_mtime_ns, st.st_size, st.st_ino, st.st_ctime_ns))
    entries.sort()
    return tuple(entries)


def cache_dir() -> Path | None:
    """Where parsed documents persist, or None when there is no home to put it in.

    ``$XDG_CACHE_HOME`` when it is set and absolute (the XDG spec says a
    relative value is ignored), else ``%LOCALAPPDATA%`` on Windows or
    ``~/.cache`` elsewhere: a ``.cache`` folder under the profile is not
    where Windows keeps application caches, so there the conforming base is
    the ``LOCALAPPDATA`` directory ``Path.home()`` already resolves to.
    """
    raw = os.environ.get("XDG_CACHE_HOME", "")
    # A Windows-shaped absolute (drive or UNC) carried over from a Windows
    # checkout is not absolute for the POSIX Path: taking it would create a
    # relative "C:\..." directory under the cwd instead of falling back to
    # the platform cache. PureWindowsPath names the drive, so a POSIX host
    # ignores any value Windows would read as anchored to a drive/UNC root;
    # a plain "/tmp/x" has no drive and stays valid on POSIX.
    if raw and Path(raw).is_absolute() and not (os.name != "nt" and PureWindowsPath(raw).drive):
        base = Path(raw)
    else:
        try:
            home = Path.home()
        except RuntimeError:
            # Path.home() raises when neither HOME nor the passwd entry names one.
            return None
        base = (
            Path(os.environ["LOCALAPPDATA"])
            if os.name == "nt" and os.environ.get("LOCALAPPDATA")
            else home / ".cache"
        )
    return base.joinpath(*_CACHE_SUBDIR)


def _slot(root: Path, path: Path) -> Path:
    """The cache file for *path*: one per document, overwritten on each rebuild."""
    name = hashlib.sha256(os.fsencode(path.absolute())).hexdigest()[:_SLOT_HEX_CHARS]
    return root / f"{name}{_SLOT_SUFFIX}"


def _read_cached(path: Path, digest: str) -> dict[str, Any] | None:
    root = cache_dir()
    if root is None:
        return None
    slot = _slot(root, path)
    try:
        with slot.open("rb") as fh:
            entry = json.load(fh)
    except OSError, ValueError, RecursionError:
        # Missing, unreadable, or not JSON: each is a miss, and the parse
        # that follows rewrites the slot.
        return None
    if (
        not isinstance(entry, dict)
        or entry.get("format") != _CACHE_FORMAT
        or entry.get("sha256") != digest
        or not isinstance(entry.get("doc"), dict)
    ):
        return None
    # The mtime is the recency _prune keeps slots by; a read-only cache still
    # serves, it just cannot record the read.
    with contextlib.suppress(OSError):
        os.utime(slot)
    doc: dict[str, Any] = entry["doc"]
    return doc


def _unlink_quiet(path: Path, what: str) -> None:
    """Delete *path*, swallowing only the failures that are not worth a line.

    ``missing_ok=True`` covers the common race (a concurrent prune took it
    first), but not ``PermissionError`` on a slot another process holds open,
    or a read-only or full filesystem.  Those must not escape: this is called
    from the cleanup arms of the write and the prune, where an escaping OSError
    either replaces the exception that brought us there or turns a successful
    write into a failed one.  The cache is an optimisation, so a file that will
    not delete is an operator note, never a failure of the parse.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        _log.debug("coverage cache: cannot remove %s %s: %s", what, path, exc.strerror or exc)


def _fsync_dir(path: Path) -> None:
    """fsync a directory so a rename inside it survives a power loss."""
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
        with contextlib.suppress(OSError):
            os.close(fd)


def _prune(root: Path) -> None:
    """Keep the :data:`_CACHE_MAX_SLOTS` most recently used slots, drop stale temps.

    A slot is per document PATH, so every coverage directory ever served (a
    worktree, a moved checkout) leaves one behind, and a write killed between
    its temp file and the rename leaves the temp.

    A failure to DELETE reports itself and returns: the caller's write has
    already been renamed into place by the time this runs, so letting an
    unlink's OSError escape would make the caller's write-failure warning
    report "documents will be parsed on every start" for a slot that was
    written and read fine.  Only the directory walk itself propagates, because
    that one says the whole cache directory is unusable and the write
    genuinely is not landing.
    """
    # Integer nanoseconds, not the float ``st_mtime``: the rest of the package
    # keys on ``st_mtime_ns`` (see ``server.mtime_ns_to_utc``), and a float
    # second cannot hold that nanosecond, so the stale boundary would depend
    # on the magnitude of the stamp rather than on the age alone.  The
    # seconds and the sub-second remainder are split with divmod so the
    # conversion stays exact (``int(now * 1e9)`` rounds the last ~256 ns
    # at present-day magnitudes from the float's 53-bit mantissa).
    seconds, remainder = divmod(clock.wall_time(), 1.0)
    now_ns = int(seconds) * 1_000_000_000 + int(remainder * 1_000_000_000)
    slots: list[tuple[int, str, Path]] = []
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        _log.debug("coverage cache: cannot list %s to prune it: %s", root, exc.strerror or exc)
        return
    for entry in entries:
        try:
            st = entry.stat()
        except FileNotFoundError:
            # Removed by another process's prune between the listing and here.
            continue
        except OSError as exc:
            _log.debug(
                "coverage cache: cannot stat %s while pruning: %s", entry, exc.strerror or exc
            )
            continue
        if entry.suffix == _TMP_SUFFIX:
            if now_ns - st.st_mtime_ns > _STALE_TMP_SECONDS * 1_000_000_000:
                _unlink_quiet(entry, "stale temp")
        elif entry.suffix == _SLOT_SUFFIX:
            # Name as the tie-breaker: two slots written in one mtime tick
            # order by the directory listing otherwise, and which slot a prune
            # keeps is part of what a replay observes.
            slots.append((st.st_mtime_ns, entry.name, entry))
    slots.sort(key=lambda item: (item[0], item[1]), reverse=True)
    for _mtime, _name, stale in slots[_CACHE_MAX_SLOTS:]:
        _unlink_quiet(stale, "stale slot")


def _write_cached(path: Path, digest: str, doc: dict[str, Any]) -> None:
    global _WRITE_WARNED
    root = cache_dir()
    if root is None:
        return
    try:
        body = json.dumps(
            {"format": _CACHE_FORMAT, "sha256": digest, "doc": doc}, separators=(",", ":")
        ).encode("utf-8")
    except TypeError:
        # A TOML date or time has no JSON spelling; rebrew writes none, and a
        # document that has one is parsed on every start instead.
        _log.debug("coverage cache: %s holds a value JSON cannot carry, not cached", path)
        return
    tmp_name: str | None = None
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(dir=root, suffix=_TMP_SUFFIX, delete=False) as fh:
            tmp_name = fh.name
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        slot = _slot(root, path)
        Path(tmp_name).replace(slot)
        _fsync_dir(root)
        tmp_name = None
        _prune(root)
    except OSError as exc:
        with _WRITE_WARNED_LOCK:
            already_warned = _WRITE_WARNED
            _WRITE_WARNED = True
        if not already_warned:
            _log.warning(
                "coverage cache: cannot write under %s (%s); documents will be "
                "parsed on every start",
                root,
                exc.strerror or exc,
                extra=metrics.log_fields(
                    event="document_cache_write_failed",
                    path=str(root),
                    error=f"{type(exc).__name__}: {exc.strerror or exc}",
                ),
            )
    finally:
        if tmp_name is not None:
            # Through _unlink_quiet, not a bare unlink(missing_ok=True): an
            # OSError raised in a finally REPLACES whatever exception is
            # unwinding through this arm, so a temp file that cannot be
            # deleted (a permission the directory does not grant, a read-only
            # mount) would surface as the cache's failure and hide the write
            # error the operator needs.
            _unlink_quiet(Path(tmp_name), "temp")


def _parse_toml(path: Path, data: bytes, digest: str) -> dict[str, Any]:
    """*data* parsed as TOML, the parse written to the cache."""
    metrics.CACHES.miss(metrics.DOCUMENT_CACHE)
    try:
        # A text wrapper rather than bytes.decode: the universal-newline read
        # rebrew's own reader (Path.read_text) does, so both see one string.
        text = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8").read()
    except UnicodeError as exc:
        raise CoverageTomlError(f"{path}: cannot read ({exc})") from exc
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise CoverageTomlError(f"{path}: malformed TOML ({exc})") from exc
    _write_cached(path, digest, doc)
    return doc


def _load(path: Path, target: str, stat: _StatKey, old: _Doc | None) -> _Doc:
    if old is not None and old.stat == stat:
        return old
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CoverageTomlError(f"{path}: cannot read ({exc})") from exc
    digest = hashlib.sha256(data).hexdigest()
    if old is not None and old.digest == digest:
        return replace(old, stat=stat)
    cached = _read_cached(path, digest)
    if cached is not None:
        try:
            snapshot = snapshot_from_document(path, cached, target)
        except Exception as exc:
            # The cache is not the document.  A slot whose hash matches but whose
            # content rebrew refuses (hand-edited, or written by a build with a
            # bug) must not make a good document read as unreadable: the TOML
            # is parsed instead, and its own error, if any, is the one reported.
            _log.warning(
                "coverage cache: discarding the cached parse of %r: %r",
                str(path),
                str(exc),
                extra=metrics.log_fields(
                    event="document_cache_discarded",
                    path=str(path),
                    document=path.name,
                    error=f"{type(exc).__name__}: {exc}",
                ),
            )
        else:
            metrics.CACHES.hit(metrics.DOCUMENT_CACHE)
            return _Doc(stat, digest, snapshot)
    parsed = _parse_toml(path, data, digest)
    try:
        return _Doc(stat, digest, snapshot_from_document(path, parsed, target))
    except CoverageTomlError:
        raise
    except ArithmeticError as exc:
        # A document integer wider than a float (a cell size of 10**400, spelled
        # out digit for digit in the TOML) overflows the percentage fold rebrew
        # runs while building the snapshot, and that OverflowError is not a shape
        # violation: escaping here it misses _rebuild's unreadable arm, which
        # only files CoverageTomlError, and 500s every snapshot-keyed route
        # instead of answering 503 for one bad file.
        raise CoverageTomlError(f"{path}: {exc}") from exc


def _project_view(source: Path) -> ProjectCoverageView | None:
    from recoverage._paths import current_project_override
    from recoverage.config import snapshot_override

    override = snapshot_override()
    # An op's explicit project wins over the environment: RECOVERAGE_SNAPSHOTS
    # selects the dashboard's portable exports, not the project a request
    # names, so the same directory must still be read live.
    named = current_project_override()
    if (override is not None and named is None and override.resolve() == source.resolve()) or not (
        source / CONFIG_NAME
    ).exists():
        return None
    try:
        return load_project_coverage(source)
    except ProjectCoverageError as exc:
        raise CoverageTomlError(str(exc)) from exc


def load_all(db_dir: Path) -> Mapping[str, CoverageSnapshot]:
    """Every readable document in *db_dir*, keyed by target id.

    The contract of ``rebrew.coverage_toml.load_all_coverage_from``: ``{}`` for
    a directory with no document, one unreadable document skipped with a
    warning naming it, and THE SAME mapping for an unchanged directory.
    """
    return snapshot_set(db_dir)[0]


def snapshot_set(
    db_dir: Path,
) -> tuple[
    Mapping[str, CoverageSnapshot],
    tuple[tuple[str, str, str], ...],
    tuple[tuple[str, str, int], ...],
]:
    """One read of *db_dir*: snapshots, unreadable rows, content versions.

    The three readers below each re-read the directory state on their own:
    in live mode that is a ``load_project_coverage`` poll per call (stat of
    the config plus every input fingerprint walk), and in portable mode a
    ``glob`` plus ``stat`` per document per call.  A handler that needs two
    of the three (``/api/targets``, ``/api/health``) paid that walk two or
    three times per request for one build's data.  One call here returns all
    three from the same state, so the answers cannot straddle a rebuild.
    """
    project = _project_view(db_dir)
    if project is not None:
        return (
            project.snapshots,
            tuple(
                ("rebrew-project.toml", target, reason)
                for target, reason in sorted(project.failures.items())
            ),
            project.versions,
        )
    _dir, key, docs, snapshots, failures = _current(db_dir)
    unreadable_rows = tuple(
        (name, unicodedata.normalize("NFC", name[len(_PREFIX) : -len(_SUFFIX)]), reason)
        for name, reason in sorted(failures.items())
    )
    version_rows = tuple(
        (
            name,
            doc.digest if doc else f"stat:{mtime_ns}:{size}:{ino}:{ctime_ns}",
            size,
        )
        for name, mtime_ns, size, ino, ctime_ns in key
        for doc in (docs.get(name),)
    )
    return snapshots, unreadable_rows, version_rows


def unreadable(db_dir: Path) -> tuple[tuple[str, str, str], ...]:
    """``(file name, target, reason)`` for every document in *db_dir* that failed to load.

    The documents :func:`load_all` skipped, name-sorted, read off the same
    state, so a document is in exactly one of the two answers.  The reason is
    the reader's error without the path it opens with: the file name already
    says which document, and the absolute path is not something a served
    payload names.  It is document-derived text (a parse error can quote a
    value), so a caller renders it as text, never as markup.
    """
    return snapshot_set(db_dir)[1]


def versions(db_dir: Path) -> tuple[tuple[str, str, int], ...]:
    """``(name, version, size)`` for every document in *db_dir*, name-sorted.

    The version is the sha256 of the document's bytes, so a rebuild that
    rewrites a document with the same bytes (rebrew's writer replaces every
    file on every run, and a run that changed nothing writes identical ones)
    leaves it alone.  A document that failed to load has no digest, and its
    version is its stat instead, so rewriting or removing it still moves the
    answer.  Read off the same state :func:`load_all` returns, so a version
    and the snapshot built from those bytes cannot come from two reads.
    """
    return snapshot_set(db_dir)[2]


def _current(db_dir: Path) -> _State:
    key = _stat_key(db_dir)
    state = _STATE
    if state is not None and state[0] == db_dir and state[1] == key:
        return state
    with _LOAD_LOCK:
        # The cyclic collector is paused for the rebuild: a load allocates one
        # frozen object per cell, none of them cyclic, and the collections that
        # allocation triggers were half the warm load (338 ms against 648 ms
        # on 116k cells).  Under the lock because gc.disable is process-wide,
        # and two overlapping loads restoring each other's state could leave
        # it off.
        state = _STATE
        fresh_key = _stat_key(db_dir)
        if state is not None and state[0] == db_dir and state[1] == fresh_key:
            return state
        with _paused_gc():
            return _rebuild(db_dir, fresh_key)


def _rebuild(db_dir: Path, key: tuple[_StatKey, ...]) -> _State:
    """Re-read what changed since the last load of *db_dir*.  Caller holds the lock."""
    global _STATE
    state = _STATE
    if state is not None and state[0] == db_dir and state[1] == key:
        # Another thread finished this load while this one waited for the lock.
        return state
    previous = state[2] if state is not None and state[0] == db_dir else {}
    docs: dict[str, _Doc] = {}
    snapshots: dict[str, CoverageSnapshot] = {}
    failures: dict[str, str] = {}
    for stat in key:
        name = stat[0]
        target = unicodedata.normalize("NFC", name[len(_PREFIX) : -len(_SUFFIX)])
        path = db_dir / name
        try:
            doc = _load(path, target, stat, previous.get(name))
        except CoverageTomlError as exc:
            reason = _reason(path, exc)
            failures[name] = reason
            # %r, not %s: a filename can carry a line break (legal on ext4), and
            # the parse error quotes document values.  repr escapes every
            # character that ends a log line, the guarantee server._log_safe
            # gives the request path, which this level cannot import.
            _log.warning(
                "skipping unreadable coverage document %r: %r",
                str(path),
                reason,
                extra=metrics.log_fields(
                    event="document_unreadable",
                    path=str(path),
                    document=name,
                    target=target,
                    reason=reason,
                ),
            )
            continue
        docs[name] = doc
        snapshots[target] = doc.snapshot
    _STATE = (db_dir, key, docs, snapshots, failures)
    return _STATE


def _reason(path: Path, exc: CoverageTomlError) -> str:
    """*exc*'s message without the ``<path>: `` both readers open it with."""
    return str(exc).removeprefix(f"{path}: ")
