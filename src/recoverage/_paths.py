"""Path resolution helpers for recoverage.

Provides _db_path(), which honours ``rebrew-project.toml``
``[project] db_dir`` when present and falls back to ``./db/coverage.db``
otherwise — matching rebrew's own resolution logic as of build_db commit
2003831.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

# Memoized _db_path() result, keyed by cwd + the config file's stat
# fingerprint.  _db_path() runs on every request (each ETag snapshot, DB open,
# Potato render) and on every SSE watcher poll; re-reading and TOML-parsing the
# config each time is pure waste.  The key makes a rewritten/deleted/re-pointed
# rebrew-project.toml take effect on the next call — one stat replaces the
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


def sqlite_ro_uri(db_path: Path) -> str:
    """Return a SQLite URI that opens *db_path* read-only.

    The path must be percent-encoded (``Path.as_uri()``), not interpolated
    raw into ``file:{p}?mode=ro``: characters reserved by SQLite's URI
    grammar (?, starts the query, # starts the fragment, % introduces a
    percent-escape) would truncate or silently rewrite the filename, and
    Windows backslash separators are not valid URI form.  ``as_uri()``
    emits an absolute forward-slash path on every platform that SQLite
    decodes back to the exact filename on POSIX and win32 alike.
    """
    p = db_path if db_path.is_absolute() else Path.cwd() / db_path
    return f"{p.as_uri()}?mode=ro"


def _db_path() -> Path:
    """Return the path to coverage.db, honouring rebrew-project.toml [project] db_dir.

    Resolution order:

    1. If ``rebrew-project.toml`` exists in cwd and ``[project].db_dir`` is a
       non-empty string, resolve it relative to cwd and append ``coverage.db``.
    2. Otherwise fall back to ``<cwd>/db/coverage.db``.

    This mirrors rebrew's ``config.py`` resolution (``project_raw.get("db_dir", "db")``).
    tomllib is stdlib from Python 3.11 — no extra dependencies required.

    Memoized per (cwd, config stat fingerprint): the config is re-read only when
    the file's mtime/size changes (or cwd moves), so request-rate calls and the
    SSE watcher pay one stat instead of a file read + TOML parse.
    """
    global _DB_PATH_CACHE
    cwd = Path.cwd()
    cfg = cwd / "rebrew-project.toml"
    fingerprint = (str(cwd), _config_fingerprint(cfg))
    cached = _DB_PATH_CACHE
    if cached is not None and cached[0] == fingerprint:
        return cached[1]

    resolved: Path | None = None
    if fingerprint[1] is not None:
        try:
            data = tomllib.loads(cfg.read_text(encoding="utf-8"))
            project = data.get("project", {}) if isinstance(data, dict) else {}
            db_dir = project.get("db_dir") if isinstance(project, dict) else None
            if isinstance(db_dir, str) and db_dir:
                resolved = (cwd / db_dir).resolve() / "coverage.db"
        except OSError as exc:
            logging.warning("Could not read %s: %s", cfg, exc)
        except tomllib.TOMLDecodeError as exc:
            # A corrupt config must not silently switch the dashboard to a
            # different DB than the one the user built — warn loudly.
            logging.warning(
                "rebrew-project.toml is not valid TOML — using default db path: %s", exc
            )
    if resolved is None:
        resolved = cwd.resolve() / "db" / "coverage.db"
    _DB_PATH_CACHE = (fingerprint, resolved)
    return resolved
