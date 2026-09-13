"""In-process rebrew regen.

``recoverage regen``, ``serve --regen`` and ``POST /api/regen`` regenerate
``coverage.db`` by calling rebrew's ``run_catalog`` and ``build_db`` module
functions in this process, not by spawning the ``rebrew`` console script.
rebrew is a required dependency, but its catalog/build-db imports stay inside
:func:`run_regen` so the dashboard's hot path does not pull rebrew's heavy
stack (LIEF, capstone, tree-sitter, numpy) on every ``serve``, ``stats`` or
``export`` run.  ``rebrew.workspace`` (all recoverage needs at startup) is
stdlib-only.

The call is synchronous and deliberately has no timeout.  The API serializes
regen behind its lock, so abandoning the caller on a deadline would let a
still-running catalog/build-db keep writing ``coverage.db`` after the lock was
released.  The dashboard's server is threaded, so it keeps answering requests
while a regen runs.
"""

from __future__ import annotations

from pathlib import Path


def run_regen(root: Path) -> None:
    """Regenerate *root*'s coverage.db with rebrew's catalog + build-db.

    Loads rebrew-project.toml once, then runs both pipeline steps in this
    process.  Failures propagate: rebrew raises ordinary exceptions, and its
    ``error_exit`` raises ``typer.Exit`` after reporting the problem itself.
    """
    from rebrew.build_db import build_db
    from rebrew.catalog import run_catalog
    from rebrew.config import load_config

    cfg = load_config(root)
    run_catalog(cfg)
    build_db(root)
