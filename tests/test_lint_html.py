"""Start-up failure of the HTML/CSS gate.

``tools/lint_html.py`` runs the Nu Html Checker by launching ``java``.  Two
inputs decide whether that can happen at all, and neither of them is a finding:
a checkout with no ``bun install`` and a host with no JRE.  The gate has to name
which one is missing and return a status of its own, because a validator that
never ran and a document it rejected are different answers, and a CI log that
renders them the same is a gate nobody can triage.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())

sys.path.insert(0, str(REPO_ROOT / "tools"))
import lint_html  # noqa: E402 — tools/ is on sys.path on the line above


class _Completed:
    """What ``subprocess.run`` hands back: an exit status and nothing else."""

    def __init__(self, code: int) -> None:
        self.returncode = code


@pytest.fixture
def no_java(monkeypatch: Any) -> None:
    monkeypatch.setattr(lint_html.shutil, "which", lambda _name: None)


def test_a_missing_jar_names_the_install_that_produces_it(monkeypatch: Any, capsys: Any) -> None:
    """No vnu.jar: the message names ``bun install``, the command that fetches it."""
    monkeypatch.setattr(lint_html, "VNU_JAR", REPO_ROOT / "node_modules" / "absent" / "vnu.jar")
    rc = lint_html.main()
    assert rc == 2
    assert "bun install" in capsys.readouterr().out


def test_a_missing_jre_is_not_a_finding(monkeypatch: Any, capsys: Any, no_java: None) -> None:
    """No java: the runner's own status, and vnu is never launched."""
    launched = False

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal launched
        launched = True
        raise AssertionError("vnu was launched with no java on PATH")

    monkeypatch.setattr(lint_html, "VNU_JAR", REPO_ROOT / "package.json")
    monkeypatch.setattr(lint_html.subprocess, "run", refuse)
    assert lint_html.main() == lint_html.RUNNER_UNAVAILABLE
    assert "java" in capsys.readouterr().out
    assert not launched


def test_a_checker_that_will_not_start_returns_the_same_status(
    monkeypatch: Any, capsys: Any
) -> None:
    """A refused exec is not a rejected document.

    ``subprocess.run`` raises ``OSError`` when the exec itself fails, which left
    the run ending in a traceback and a status no reader could tell from a
    finding. It reports the same status as an absent JRE instead: both mean
    nothing was validated, and only vnu's own codes mean the document is wrong.
    """

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("Exec format error")

    monkeypatch.setattr(lint_html.subprocess, "run", refuse)
    assert lint_html.run_vnu([], [REPO_ROOT / "package.json"]) == lint_html.RUNNER_UNAVAILABLE
    assert "could not run vnu" in capsys.readouterr().err


@pytest.mark.parametrize("code", [0, 1])
def test_a_completed_run_reports_the_checkers_own_status(monkeypatch: Any, code: int) -> None:
    """Both vnu outcomes pass through unchanged, so a clean document still says so."""
    monkeypatch.setattr(lint_html.subprocess, "run", lambda *_a, **_k: _Completed(code))
    assert lint_html.run_vnu([], [REPO_ROOT / "package.json"]) == code


def test_the_unavailable_status_is_not_a_code_vnu_returns() -> None:
    """vnu reports a finding as 1 and a clean run as 0; this must read as neither."""
    assert lint_html.RUNNER_UNAVAILABLE not in (0, 1, 2)


def test_vnu_is_launched_with_the_pinned_jar(monkeypatch: Any) -> None:
    """The jar is the one bun.lock installs, passed explicitly rather than found."""
    seen: list[list[str]] = []

    def record(cmd: list[str], **_kwargs: Any) -> _Completed:
        seen.append(cmd)
        return _Completed(0)

    monkeypatch.setattr(lint_html.subprocess, "run", record)
    lint_html.run_vnu(["--css"], [REPO_ROOT / "package.json"])
    assert seen[0][:3] == ["java", "-jar", str(lint_html.VNU_JAR)]
    assert seen[0][3:] == ["--css", str(REPO_ROOT / "package.json")]
