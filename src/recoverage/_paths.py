"""Resolve a live project or an explicitly selected portable snapshot directory."""

from __future__ import annotations

import contextlib
import contextvars
lazy from collections.abc import Iterator
lazy from pathlib import Path

lazy from rebrew.workspace import CONFIG_NAME, find_root, read_config

lazy from recoverage import config

#: The project a dispatched op named, for the duration of that call.  An op
#: carries the absolute ``project_dir`` it answers for, and it must win over
#: ``RECOVERAGE_SNAPSHOTS``: the environment selects portable exports for the
#: dashboard's readers, not for a request that names a live project.  A
#: ContextVar keeps that scope per request instead of a module global the next
#: call would inherit.
_project_override: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "recoverage_project_override", default=None
)


def current_project_override() -> Path | None:
    """The project a running op named, or None outside one."""
    return _project_override.get()


@contextlib.contextmanager
def project_override(root: Path) -> Iterator[None]:
    """Resolve coverage from *root* while the block runs, ignoring snapshots."""
    token = _project_override.set(root)
    try:
        yield
    finally:
        _project_override.reset(token)


def config_fingerprint(root: Path) -> tuple[int, int, int, int] | None:
    """``(mtime_ns, size)`` of ``rebrew-project.toml`` under *root*, None if absent.

    The one change token every config-derived memo keys on: this one, the
    parsed target config and the DLL byte cache in :mod:`recoverage.server`.
    Editing the file is a write that reaches no server code and moves no
    coverage document, so the stat is the only invalidation signal there is,
    and naming the same token in every key is what keeps those memos from
    disagreeing about whether the config changed.
    """
    try:
        st = (root / CONFIG_NAME).stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ctime_ns, st.st_ino)


_VALIDATED: tuple[Path, int, int, int, int] | None = None


def coverage_source() -> Path:
    """Use the containing project by default; offline snapshots require an override.

    A running op's explicit project wins over both: it names the project it
    answers for, and an environment setting cannot redirect that call.
    """
    global _VALIDATED
    named = current_project_override()
    if named is not None:
        return named
    override = config.snapshot_override()
    if override is not None:
        return override.resolve()
    root = find_root()
    stamp = (root / CONFIG_NAME).stat()
    key = (root, stamp.st_mtime_ns, stamp.st_ctime_ns, stamp.st_size, stamp.st_ino)
    if key != _VALIDATED:
        read_config(root)
        _VALIDATED = key
    return root
