"""Path resolution helpers for recoverage.

Provides _db_path(), recoverage's memoized wrapper around the shared
``rebrew.workspace.db_path`` resolution: ``RECOVERAGE_DB`` when set, else
``rebrew-project.toml`` ``[project] db_dir`` when present, ``./db/coverage.db``
otherwise.  The environment override comes first so a service can serve a
project it was not started from the root of.
"""

from __future__ import annotations

from pathlib import Path

from rebrew.workspace import CONFIG_NAME, db_path

from recoverage import config

# Memoized _db_path() result, keyed by cwd + the config file's stat
# fingerprint.  _db_path() runs on every request (each ETag snapshot, DB open,
# Potato render) and on every SSE watcher poll; re-reading and TOML-parsing the
# config each time is pure waste.  The key makes a rewritten/deleted/re-pointed
# rebrew-project.toml take effect on the next call: one stat replaces the
# read+parse on the hot path.  Torn reads are impossible: the tuple swap is
# atomic under the GIL, and a racing recomputation yields the same value.
_DB_PATH_CACHE: tuple[tuple[str, tuple[int, int] | None], Path] | None = None


def _config_fingerprint(cfg: Path) -> tuple[int, int] | None:
    """(mtime_ns, size) of *cfg*, or None when absent/unreadable."""
    try:
        st = cfg.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _db_path() -> Path:
    """Return the path to coverage.db, honouring rebrew-project.toml [project] db_dir.

    Resolution is ``RECOVERAGE_DB`` when that variable is set, else
    ``rebrew.workspace.db_path(cwd)``: ``[project].db_dir`` resolved against
    cwd when present, else ``<cwd>/db/coverage.db``.  A missing config file
    falls back to that default.  A file that is present but not readable
    UTF-8 TOML raises ``WorkspaceConfigError``: falling back would select
    ``db/coverage.db``, which may be a different database than the one the
    file names.  The environment override is applied before the file is read.

    Memoized per (cwd, config stat fingerprint): the config is re-read only when
    the file's mtime/size changes (or cwd moves), so request-rate calls and the
    SSE watcher pay one stat instead of a file read + TOML parse.  The
    environment override is one getenv and stays out of the cache, so the
    process cannot end up mixing the two sources.
    """
    global _DB_PATH_CACHE
    override = config.db_override()
    if override is not None:
        return override
    cwd = Path.cwd()
    fingerprint = (str(cwd), _config_fingerprint(cwd / CONFIG_NAME))
    cached = _DB_PATH_CACHE
    if cached is not None and cached[0] == fingerprint:
        return cached[1]

    resolved = db_path(cwd)
    _DB_PATH_CACHE = (fingerprint, resolved)
    return resolved
