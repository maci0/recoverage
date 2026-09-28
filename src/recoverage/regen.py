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

This module also owns rebrew's failure vocabulary.  rebrew's ``error_exit``
reports the problem itself and raises ``typer.Exit`` (click's ``Exit``, a
``RuntimeError``); that becomes :class:`RegenError` here, so the two callers
map one exception of this package's own instead of each importing a CLI
framework to read that framework's exception.  Every other failure propagates
untouched.
"""

from __future__ import annotations

from pathlib import Path


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
    except (OSError, LookupError, ValueError, TypeError, KeyError):
        # The config is present but unusable. load_config raises on exactly
        # this with a message naming the key, and that is the better report.
        return
    if _same_directory(written_to, override.expanduser().resolve()):
        return
    raise RegenDbMismatchError(
        f"RECOVERAGE_DB names {override}, but rebrew writes its coverage "
        f"documents to {written_to} (from {root / CONFIG_NAME}, or {root / 'db'} "
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
    import typer
    from rebrew.catalog.cli import run_catalog
    from rebrew.config import load_config
    from rebrew.coverage_toml import write_coverage_toml

    _check_writes_where_the_dashboard_reads(root)
    cfg = load_config(root)
    try:
        run_catalog(cfg)
        return write_coverage_toml(root, force=True)
    except typer.Exit as e:
        raise RegenError(e.exit_code) from None
