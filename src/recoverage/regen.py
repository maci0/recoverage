"""Explicitly refresh the live coverage view without generating files."""

from __future__ import annotations

from pathlib import Path


class RegenError(RuntimeError):
    """A live coverage refresh could not produce every configured target."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def run_regen(root: Path) -> None:
    """Refresh canonical project inputs without writing any files."""
    from rebrew.coverage_project import ProjectCoverageError, load_project_coverage

    from recoverage.config import snapshot_override

    if snapshot_override() is not None:
        raise RegenError(
            "Portable snapshots are read-only; unset RECOVERAGE_SNAPSHOTS to refresh a project.", 2
        )
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
