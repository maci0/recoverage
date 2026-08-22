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
    """
    cwd = Path.cwd().resolve()
    cfg = cwd / "rebrew-project.toml"
    if cfg.exists():
        try:
            data = tomllib.loads(cfg.read_text(encoding="utf-8"))
            project = data.get("project", {}) if isinstance(data, dict) else {}
            db_dir = project.get("db_dir") if isinstance(project, dict) else None
            if isinstance(db_dir, str) and db_dir:
                return (cwd / db_dir).resolve() / "coverage.db"
        except OSError as exc:
            logging.warning("Could not read %s: %s", cfg, exc)
        except tomllib.TOMLDecodeError as exc:
            # A corrupt config must not silently switch the dashboard to a
            # different DB than the one the user built — warn loudly.
            logging.warning(
                "rebrew-project.toml is not valid TOML — using default db path: %s", exc
            )
    return cwd / "db" / "coverage.db"
