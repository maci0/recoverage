"""Resolve a live project or an explicitly selected portable snapshot directory."""

from __future__ import annotations

lazy from pathlib import Path

lazy from rebrew.workspace import CONFIG_NAME, find_root, read_config

lazy from recoverage import config


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
    """Use the containing project by default; offline snapshots require an override."""
    global _VALIDATED
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
