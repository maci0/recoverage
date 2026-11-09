"""Explicitly refresh the live coverage view without writing coverage files.

``POST /api/regen`` is serialized in-process by ``_REGEN_LOCK``; that lock
cannot see another process, and ``recoverage regen``, ``serve --regen`` and
``POST /api/regen`` all run :func:`run_regen`. It takes a cross-process
advisory lock (``.recoverage-regen.lock`` beside ``rebrew-project.toml``) for
the whole pipeline, so a cron job and a running ``serve`` process cannot run
two pipelines over the same project at once: a second execution converges to
a refusal naming the holder instead of interleaving, and the lock is held on
an open descriptor so a killed run releases it. The only file written is that
lock file; the refresh itself derives an in-memory view from canonical
project inputs.
"""

from __future__ import annotations

import contextlib
import errno
import os
from collections.abc import Iterator
from contextlib import contextmanager
lazy from pathlib import Path

from recoverage.config import RecoError


class RegenError(RecoError, RuntimeError):
    """A live coverage refresh could not produce every configured target."""

    def __init__(self, message: str, exit_code: int = 1, *, precondition: bool = False) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.precondition = precondition


class RegenBusyError(RegenError):
    """Another recoverage process is refreshing the same project.

    Recovery is to re-run this command after that process finishes; a second
    concurrent pipeline is never started here.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=1)
        self.precondition = True


def _regen_lock_path(root: Path) -> Path:
    """The lock file for *root*'s project directory, beside the project file."""
    return root / ".recoverage-regen.lock"


#: The Windows arm locks the first byte of the file, so it must exist before
#: ``msvcrt.locking`` can lock it (the Microsoft CRT refuses to lock a byte
#: past end-of-file). One byte is the whole lock; the file stays beside the
#: config for the next rebuild, which reopens it for the same byte.
_LOCK_BYTE = b"\x00"


@contextmanager
def _project_lock(root: Path) -> Iterator[None]:
    """Hold an exclusive, non-blocking lock for *root* across processes.

    ``POST /api/regen`` is serialized in-process by ``_REGEN_LOCK``; that lock
    cannot see another process. A ``recoverage regen`` cron job and a running
    ``serve`` process therefore run two pipelines at once unless the CLI path
    also takes a cross-process lock. The lock is the file itself and is held
    via ``flock`` (POSIX) or ``msvcrt.locking`` (Windows) for the whole
    pipeline, so a crash releases it and a retry converges.
    """
    root.mkdir(parents=True, exist_ok=True)
    lock_path = _regen_lock_path(root)
    handle = lock_path.open("a+b")
    try:
        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RegenBusyError(
                    f"another recoverage regen is running for {root}; wait for it to finish"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        else:
            import msvcrt

            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    # A fresh lockfile carries no first byte yet, which
                    # ``msvcrt.locking`` refuses; write it and lock the same
                    # byte, so the file's length never changes the result.
                    handle.write(_LOCK_BYTE)
                    handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
                else:
                    raise RegenBusyError(
                        f"another recoverage regen is running for {root}; wait for it to finish"
                    ) from exc
            try:
                yield
            finally:
                with contextlib.suppress(OSError):
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
    finally:
        handle.close()


def run_regen(root: Path) -> None:
    """Refresh canonical project inputs; sole file written is the regen lock."""
    from rebrew.coverage_project import ProjectCoverageError, load_project_coverage

    from recoverage.config import snapshot_override

    if snapshot_override() is not None:
        raise RegenError(
            "Portable snapshots are read-only; unset RECOVERAGE_SNAPSHOTS to refresh a project.",
            2,
            precondition=True,
        )
    with _project_lock(root):
        try:
            view = load_project_coverage(root, refresh=True)
        except ProjectCoverageError as exc:
            raise RegenError(str(exc)) from exc
        if view.failures:
            raise RegenError(
                "; ".join(f"{target}: {reason}" for target, reason in view.failures.items())
            )
        if not view.snapshots:
            raise RegenError("No configured coverage targets")
