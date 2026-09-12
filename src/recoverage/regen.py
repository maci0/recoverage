"""In-process rebrew regen.

``recoverage regen``, ``serve --regen`` and ``POST /api/regen`` regenerate
``coverage.db`` by calling rebrew's ``run_catalog`` and ``build_db`` module
functions in this process, not by spawning the ``rebrew`` console script.
rebrew is an optional dependency (the ``regen`` extra): the import happens
inside :func:`run_regen`, so recoverage stays importable and every command
that does not regen works without rebrew installed.

The call is synchronous and deliberately has no timeout.  The API serializes
regen behind its lock, so abandoning the caller on a deadline would let a
still-running catalog/build-db keep writing ``coverage.db`` after the lock was
released.  The dashboard's server is threaded, so it keeps answering requests
while a regen runs.
"""

from __future__ import annotations

from pathlib import Path

_INSTALL_HINT = (
    "rebrew is required for regen; install it with 'pip install recoverage[regen]' "
    "(or 'pip install rebrew')"
)


def run_regen(root: Path) -> None:
    """Regenerate *root*'s coverage.db with rebrew's catalog + build-db.

    Loads rebrew-project.toml once, then runs both pipeline steps in this
    process.  Failures propagate: rebrew raises ordinary exceptions, and its
    ``error_exit`` raises ``typer.Exit`` after reporting the problem itself.

    Raises:
        ImportError: rebrew is not installed; the message names the fix.
    """
    try:
        from rebrew.build_db import build_db
        from rebrew.catalog import run_catalog
        from rebrew.config import load_config
    except ImportError as exc:
        raise ImportError(_INSTALL_HINT) from exc

    cfg = load_config(root)
    run_catalog(cfg)
    build_db(root)
