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
"""

from __future__ import annotations

from pathlib import Path


def run_regen(root: Path) -> None:
    """Regenerate *root*'s coverage documents with rebrew's catalog + writer.

    Loads rebrew-project.toml once, then runs both pipeline steps in this
    process.  Failures propagate: rebrew raises ordinary exceptions, and its
    ``error_exit`` raises ``typer.Exit`` after reporting the problem itself.

    ``run_catalog`` is imported from ``rebrew.catalog.cli``. The
    ``rebrew.catalog`` package does not re-export it.

    Running it twice converges: catalog rewrites its ``data_*.json`` outputs and
    the writer replaces each ``coverage-<target>.toml`` whole, so the second run
    ends in the state the first produced.  Callers that must not pay for a
    duplicate pay for it themselves: the API serializes regens behind its lock
    and replays a completed ``Idempotency-Key``; the CLI runs them one at a
    time.

    ``force=True`` keeps the call shape the SQLite-era regen had: rebrew's
    writer accepts it for signature symmetry with ``build_db`` and a document
    from a previous format is replaced unconditionally either way, so a
    dashboard whose coverage had fallen a version behind still rebuilds itself
    from the Reload button.  The flag is what a future writer that grows a
    version check would honour; passing it here means that addition cannot
    silently break the one job this command exists for.
    """
    from rebrew.catalog.cli import run_catalog
    from rebrew.config import load_config
    from rebrew.coverage_toml import write_coverage_toml

    cfg = load_config(root)
    run_catalog(cfg)
    write_coverage_toml(root, force=True)
