"""Coverage documents, read per file and with the parse persisted across restarts.

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
  through rebrew's own ``_snapshot`` exactly as a fresh parse does, so a cache
  file is held to the document's schema and is no more trusted than the TOML
  it stands in for.  JSON rather than pickle for the same reason: loading a
  pickle runs code, and the cache directory is not the coverage directory.

The cache is best effort: an unwritable or missing directory, a corrupt file,
an entry rebrew's schema refuses and a document JSON cannot represent (a TOML
datetime) all fall back to the parse, and the first write failure in a process
logs one WARNING.  It holds one file per document path, and every write keeps
the :data:`_CACHE_MAX_SLOTS` most recently used.

``rebrew.coverage_toml._snapshot`` is a private name read deliberately: it is
the one place the document schema is enforced, a rename fails this import
loudly, and ``tests/test_documents.py`` holds every snapshot this module builds
equal to the one ``rebrew.coverage_toml.load_coverage_from`` builds.
"""

from __future__ import annotations

import contextlib
import gc
import hashlib
import io
import json
import logging
import os
import tempfile
import threading
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError, _snapshot

from recoverage import clock, metrics

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

#: ``(name, mtime_ns, size, ino)``: the inode catches a same-size rename-over
#: inside one mtime tick, which mtime and size alone cannot see.
_StatKey = tuple[str, int, int, int]


@dataclass(frozen=True)
class _Doc:
    stat: _StatKey
    digest: str
    snapshot: CoverageSnapshot


#: One directory's state: its path, the stat of every document, each document's
#: memo entry, and the mapping handed to callers.  One slot, like rebrew's: a
#: scan of another directory drops the previous one's entries.  Swapped as a
#: whole tuple, which is atomic under the GIL; a miss is serialized by
#: :data:`_LOAD_LOCK`.
_State = tuple[Path, tuple[_StatKey, ...], dict[str, _Doc], dict[str, CoverageSnapshot]]
_STATE: _State | None = None

#: Serializes a reload, so a request herd after a rebuild parses each changed
#: document once and the collector pause below has one owner.  The hit path
#: never takes it.
_LOAD_LOCK = threading.Lock()

#: Whether this process has already warned about a cache write failure.
_WRITE_WARNED = False


def _stat_key(db_dir: Path) -> tuple[_StatKey, ...]:
    """Every document's stat, name-sorted; a file that vanished is skipped."""
    entries: list[_StatKey] = []
    for path in db_dir.glob(COVERAGE_GLOB):
        try:
            st = path.stat()
        except OSError:
            continue
        entries.append((path.name, st.st_mtime_ns, st.st_size, st.st_ino))
    entries.sort()
    return tuple(entries)


def cache_dir() -> Path | None:
    """Where parsed documents persist, or None when there is no home to put it in.

    ``$XDG_CACHE_HOME`` when it is set and absolute (the XDG spec says a
    relative value is ignored), else ``~/.cache``.
    """
    raw = os.environ.get("XDG_CACHE_HOME", "")
    if raw and Path(raw).is_absolute():
        base = Path(raw)
    else:
        try:
            base = Path.home() / ".cache"
        except RuntimeError:
            # Path.home() raises when neither HOME nor the passwd entry names one.
            return None
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
    except (OSError, ValueError, RecursionError):
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
    now = clock.wall_time()
    slots: list[tuple[int, Path]] = []
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
            if now - st.st_mtime > _STALE_TMP_SECONDS:
                _unlink_quiet(entry, "stale temp")
        elif entry.suffix == _SLOT_SUFFIX:
            slots.append((st.st_mtime_ns, entry))
    slots.sort(reverse=True)
    for _mtime, stale in slots[_CACHE_MAX_SLOTS:]:
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
        Path(tmp_name).replace(_slot(root, path))
        tmp_name = None
        _prune(root)
    except OSError as exc:
        if not _WRITE_WARNED:
            _WRITE_WARNED = True
            _log.warning(
                "coverage cache: cannot write under %s (%s); documents will be "
                "parsed on every start",
                root,
                exc.strerror or exc,
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
            snapshot = _snapshot(path, cached, target)
        except Exception as exc:
            # The cache is not the document.  A slot whose hash matches but whose
            # content rebrew refuses (hand-edited, or written by a build with a
            # bug) must not make a good document read as unreadable: the TOML
            # is parsed instead, and its own error, if any, is the one reported.
            _log.warning(
                "coverage cache: discarding the cached parse of %r: %r", str(path), str(exc)
            )
        else:
            metrics.CACHES.hit(metrics.DOCUMENT_CACHE)
            return _Doc(stat, digest, snapshot)
    return _Doc(stat, digest, _snapshot(path, _parse_toml(path, data, digest), target))


def load_all(db_dir: Path) -> dict[str, CoverageSnapshot]:
    """Every readable document in *db_dir*, keyed by target id.

    The contract of ``rebrew.coverage_toml.load_all_coverage_from``: ``{}`` for
    a directory with no document, one unreadable document skipped with a
    warning naming it, and THE SAME mapping for an unchanged directory.
    """
    return _current(db_dir)[3]


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
    _dir, key, docs, _snapshots = _current(db_dir)
    out: list[tuple[str, str, int]] = []
    for name, mtime_ns, size, ino in key:
        doc = docs.get(name)
        out.append((name, doc.digest if doc else f"stat:{mtime_ns}:{size}:{ino}", size))
    return tuple(out)


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
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            return _rebuild(db_dir, key)
        finally:
            if was_enabled:
                gc.enable()


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
    for stat in key:
        name = stat[0]
        target = name[len(_PREFIX) : -len(_SUFFIX)]
        path = db_dir / name
        try:
            doc = _load(path, target, stat, previous.get(name))
        except CoverageTomlError as exc:
            # %r, not %s: a filename can carry a line break (legal on ext4), and
            # the parse error quotes document values.  repr escapes every
            # character that ends a log line, the guarantee server._log_safe
            # gives the request path, which this level cannot import.
            _log.warning("coverage_toml: skipping %r: %r", str(path), str(exc))
            continue
        docs[name] = doc
        snapshots[target] = doc.snapshot
    _STATE = (db_dir, key, docs, snapshots)
    return _STATE
