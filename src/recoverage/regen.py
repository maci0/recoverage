"""In-process rebrew regen.

``recoverage regen``, ``serve --regen`` and ``POST /api/regen`` regenerate
``coverage-<target>.toml`` by calling rebrew's ``run_catalog`` and
``write_coverage_toml`` functions in this process, not by spawning the
``rebrew`` console script.
rebrew is a required dependency, but its catalog/build-db imports stay inside
:func:`run_regen` so the dashboard's hot path does not pull rebrew's heavy
stack (LIEF, capstone, tree-sitter, numpy) on every ``serve``, ``stats`` or
``export`` run.  ``rebrew.workspace`` (all recoverage needs at startup) is
stdlib-only.

The call is synchronous and deliberately has no timeout.  The API serializes
regen behind its lock, so abandoning the caller on a deadline would let a
still-running catalog/writer keep writing the documents after the lock was
released.  The dashboard's server is threaded, so it keeps answering requests
while a regen runs.

Serialization is per PROCESS, and this module is reached from three processes
that no single in-process lock can see: a ``POST /api/regen`` against a running
server, a ``recoverage regen`` typed at another terminal, and a cron job
rebuilding the same tree.  Two pipelines writing the same documents and the
same catalog ``data_*.json`` at once interleave: the writer replaces each
document whole, and a second writer truncating one the first is halfway through
leaves a truncated file, which reads as a corrupt document (503
``db_unavailable``) rather than as a concurrent run.  So the pipeline also holds
an advisory lock on a file in the coverage directory, which the operating
system releases when the holding process dies: a killed regen cannot wedge the
next one, which a lock file's mere presence could.

This module also owns rebrew's failure vocabulary.  rebrew's ``error_exit``
reports the problem itself and raises ``typer.Exit`` (click's ``Exit``, a
``RuntimeError``); that becomes :class:`RegenError` here, so the two callers
map one exception of this package's own instead of each importing a CLI
framework to read that framework's exception.  Every other failure propagates
untouched.
"""

from __future__ import annotations

import contextlib
import importlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import IO

#: The advisory lock every regen holds, named in the coverage directory
#: rebrew writes into, so the processes that share the documents also share the
#: lock.  The directory is resolved through rebrew rather than assumed, because
#: ``[project].db_dir`` can point anywhere.
_REGEN_LOCK_NAME = ".recoverage-regen.lock"
#: rebrew's own default coverage subdirectory, which the resolution below falls
#: back to.  Named because the mismatch message quotes that fallback, so the
#: two have to name the same directory.
_DEFAULT_DB_SUBDIR = "db"
#: Bytes locked at offset 0. Windows takes a byte RANGE rather than a whole
#: file (POSIX flocks the descriptor), so both platforms lock the same one.
_LOCK_BYTE_COUNT = 1


class RegenError(RuntimeError):
    """rebrew reported a regen failure and exited with *exit_code*.

    The code is rebrew's own, and both callers report it rather than deciding
    it: the CLI exits 1, and the API's 500 body says which status rebrew gave.
    """

    def __init__(self, exit_code: int) -> None:
        super().__init__(f"rebrew exited with status {exit_code}")
        self.exit_code = exit_code


class RegenDbMismatchError(RuntimeError):
    """``RECOVERAGE_DB`` names a directory rebrew would not write to.

    A distinct type from :class:`RegenError` because it is not rebrew failing:
    it is this package's own configuration refusing, and the callers map it to
    exit 2 (misconfiguration) rather than exit 1 (a regen that ran and failed).
    """


class RegenBusyError(RuntimeError):
    """Another process is already regenerating this project's documents.

    The one outcome a second concurrent run can produce that a single one
    cannot: two writers truncating and rewriting the same document interleave,
    and a reader can land between the truncate and the write.  The callers
    answer it as the answer they already give a regen of their own that is
    still running: the API's 429, the CLI's exit 1.
    """


def _try_lock(handle: IO[bytes]) -> bool:
    """Take an exclusive OS lock on *handle*; False when another process holds it.

    ``msvcrt`` is reached through ``importlib`` rather than imported directly:
    typeshed ships its stub only on Windows, so a plain ``import msvcrt`` is an
    unresolved-import error under this project's type gate on every other
    platform, and a suppression for it would be an unused-ignore error on the
    one platform that has the module.
    """
    if os.name == "nt":
        msvcrt = importlib.import_module("msvcrt")
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, _LOCK_BYTE_COUNT)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _release_lock(handle: IO[bytes]) -> None:
    """Drop the lock :func:`_try_lock` took. The descriptor close releases it too."""
    if os.name == "nt":
        msvcrt = importlib.import_module("msvcrt")
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, _LOCK_BYTE_COUNT)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _coverage_dir(root: Path) -> Path:
    """The directory rebrew writes the coverage documents into, for the lock.

    Resolution failures fall back to ``root/db``, rebrew's own default: a lock
    in the wrong directory costs two processes the ability to see each other,
    while refusing here would turn a regen rebrew was going to run into one
    this package stops.  :func:`run_regen` calls this after ``load_config``, so
    a config that does not parse has already been reported by rebrew's loader.
    """
    from rebrew.workspace import db_dir

    try:
        return db_dir(root)
    except (OSError, LookupError, ValueError, TypeError):
        return root / _DEFAULT_DB_SUBDIR


@contextlib.contextmanager
def _exclusive_regen(root: Path) -> Iterator[None]:
    """Hold the project's regen lock for the body; raise :class:`RegenBusyError` if taken.

    Non-blocking on purpose: a second regen queues behind a pipeline that runs
    for minutes, and the caller that queued is a script with a timeout or a
    reader who pressed the button again, not a rebuild that was asked for
    twice.  The lock lives on an open descriptor, so a regen killed mid-run
    releases it when the process exits and the next one proceeds; nothing here
    has to be cleaned up by a signal handler or a finally that a SIGKILL skips.
    """
    directory = _coverage_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / _REGEN_LOCK_NAME
    # "a+b" creates the file if it is the first regen and never truncates one
    # another process is holding locked; the lock is on the descriptor, so the
    # bytes in the file are only a marker for a human.
    handle = path.open("a+b")
    try:
        if not _try_lock(handle):
            raise RegenBusyError(
                f"another regen is already writing {directory}; it holds {path.name}. "
                "Wait for it to finish, or stop the process that holds it."
            )
        try:
            yield
        except BaseException:
            # The unlock is best effort here and required on the way out of a
            # SUCCESSFUL body.  It is best effort in fact: the descriptor close
            # in the outer finally drops the lock whatever happens, so an
            # OSError out of the explicit unlock only duplicates a release the
            # kernel is about to perform.  Propagating it would replace what
            # the body raised — a RegenError naming rebrew's exit status, or the
            # rebrew traceback the operator needs — with a message about a lock
            # nobody is left holding.  Split into an except arm rather than a
            # finally because inside a finally the body is not distinguishable
            # from the cleanup error being handled.
            with contextlib.suppress(OSError):
                _release_lock(handle)
            raise
        # Best effort here too, and for the same reason as the arm above: the
        # descriptor close in the outer finally drops the lock whatever happens,
        # so an OSError out of this explicit unlock duplicates a release the
        # kernel is about to perform. Unguarded, it replaced the SUCCESS it was
        # cleaning up after — rebrew wrote every document, and the caller
        # (exit 1, or the API's 500) reported a regen that had failed.
        with contextlib.suppress(OSError):
            _release_lock(handle)
    finally:
        # Best effort: this runs on every exit, including one unwinding a
        # RegenError or a rebrew traceback the operator needs, and a close()
        # that raised (a flush onto a filesystem that went away between the
        # write and here) would replace it with an OSError about a lock file
        # nobody is left holding.
        with contextlib.suppress(OSError):
            handle.close()


def _same_directory(written_to: Path, override: Path) -> bool:
    """Whether two resolved paths name the same directory on THIS host.

    ``Path.__eq__`` compares the spelling, and on the two filesystems that
    ignore case (macOS and Windows by default) ``/proj/DB`` and ``/proj/db``
    are one directory under two spellings.  Compared as strings the guard
    below therefore refused a regen that would have reached the dashboard,
    naming a mismatch that does not exist; the operator's only way out was to
    respell the variable, and nothing said why.

    ``Path.samefile`` asks the operating system, which is the only spelling
    that can answer this: it stats both and compares device and inode, so it
    is right on a case-insensitive filesystem and still exact on a
    case-sensitive one.  It raises when either path does not exist, which is
    the normal state before a project's first ``build-db``; the string
    comparison is the fallback there, and it is the one both hosts already
    agreed on when the spelling is exact.
    """
    if written_to == override:
        return True
    try:
        return written_to.samefile(override)
    except OSError:
        return False


def _check_writes_where_the_dashboard_reads(root: Path) -> None:
    """Refuse a regen whose output no served directory would pick up.

    rebrew resolves the coverage directory from ``rebrew-project.toml`` under
    *root* alone; it has no environment override.  ``RECOVERAGE_DB`` is this
    package's override, and every reader here honours it (``_paths._db_path``).
    So with the variable set, a regen writes documents into a directory that
    ``stats``/``export``/``check``/``serve`` never look at, and reports success
    while the dashboard stays exactly as stale as it was.  That is the one
    outcome worse than a failed regen, so it is refused before rebrew runs.
    """
    from rebrew.workspace import CONFIG_NAME, db_dir

    from recoverage.config import db_override

    override = db_override()
    if override is None:
        return
    try:
        written_to = db_dir(root).resolve()
    except (OSError, LookupError, ValueError, TypeError):
        # A path rebrew resolved but this process could not (a symlink loop, a
        # permission error on a parent).  A config that does not parse is NOT
        # this arm: `db_dir` raises WorkspaceConfigError, which none of these
        # catch, so it propagates to the caller as rebrew's own message.
        return
    if _same_directory(written_to, override.expanduser().resolve()):
        return
    raise RegenDbMismatchError(
        f"RECOVERAGE_DB names {override}, but rebrew writes its coverage "
        f"documents to {written_to} (from {root / CONFIG_NAME}, or {root / _DEFAULT_DB_SUBDIR} "
        f"when it has none). Point [project].db_dir at {override} or unset "
        f"RECOVERAGE_DB; a regen would not reach the dashboard otherwise."
    )


def run_regen(root: Path) -> list[Path]:
    """Regenerate *root*'s coverage documents with rebrew's catalog + writer.

    Loads rebrew-project.toml once, then runs both pipeline steps in this
    process.  Failures propagate as themselves; only rebrew's ``typer.Exit``
    is translated, to :class:`RegenError`.

    Returns the paths written, in dataset order, so a caller can report where
    the documents landed.

    ``run_catalog`` is imported from ``rebrew.catalog.cli``. The
    ``rebrew.catalog`` package does not re-export it.

    Running it twice converges: catalog rewrites its ``data_*.json`` outputs and
    the writer replaces each ``coverage-<target>.toml`` whole, so a second run
    after the first finished ends in the state the first produced.  Callers that
    must not pay for a duplicate pay for it themselves: the API serializes
    regens behind its lock and replays a completed ``Idempotency-Key``.  A
    SECOND run AT THE SAME TIME is a different matter, because two writers of
    one document interleave rather than converge, so the pipeline holds
    :func:`_exclusive_regen` and raises :class:`RegenBusyError` rather than
    overlapping.  That guard crosses processes, which the callers' own locks
    cannot: a ``recoverage regen`` at a terminal beside a running dashboard, or
    a cron job over the same tree, is a duplicate no in-process lock sees.

    ``force=True`` keeps the call shape the SQLite-era regen had: rebrew's
    writer accepts it for signature symmetry with ``build_db`` and a document
    from a previous format is replaced unconditionally either way, so a
    dashboard whose coverage had fallen a version behind still rebuilds itself
    from the Reload button.  The flag is what a future writer that grows a
    version check would honour; passing it here means that addition cannot
    silently break the one job this command exists for.
    """
    import typer
    from rebrew.catalog.cli import run_catalog
    from rebrew.config import load_config
    from rebrew.coverage_toml import write_coverage_toml

    _check_writes_where_the_dashboard_reads(root)
    cfg = load_config(root)
    try:
        with _exclusive_regen(root):
            run_catalog(cfg)
            return write_coverage_toml(root, force=True)
    except typer.Exit as e:
        raise RegenError(e.exit_code) from None
