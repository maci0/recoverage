"""Start-up failure of the HTML/CSS gate.

``tools/lint_html.py`` runs the Nu Html Checker by launching ``java``.  Two
inputs decide whether that can happen at all, and neither of them is a finding:
a checkout with no ``bun install`` and a host with no JRE.  The gate has to name
which one is missing and return a status of its own, because a validator that
never ran and a document it rejected are different answers, and a CI log that
renders them the same is a gate nobody can triage.
"""

from __future__ import annotations

import subprocess
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


def test_a_checker_that_never_finishes_is_the_same_unavailable_status(
    monkeypatch: Any, capsys: Any
) -> None:
    """A wedged JVM validates nothing, and must not hold the job until CI kills it.

    Unbounded, ``run_vnu`` waited on a JVM that never answers, so the gate hung
    until the job timeout with nothing naming the command that hung.  The
    timeout is the fix and this is the property it has to keep: the pass is
    killed, and the status is ``RUNNER_UNAVAILABLE`` -- not a finding, because
    nothing was checked, and not 0, which would be a gate that passed without
    having looked at a document.
    """
    seen: list[Any] = []

    def wedge(cmd: list[str], **kwargs: Any) -> _Completed:
        seen.append(kwargs.get("timeout"))
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout") or 0.0)

    monkeypatch.setattr(lint_html.subprocess, "run", wedge)
    assert lint_html.run_vnu([], [REPO_ROOT / "package.json"]) == lint_html.RUNNER_UNAVAILABLE
    assert "nothing was validated" in capsys.readouterr().err
    # The bound has to be the one the module names: a timeout of None, or a
    # value that is not positive, restores the unbounded wait this status
    # exists to report.
    assert seen == [lint_html.VNU_TIMEOUT_SECONDS]
    assert lint_html.VNU_TIMEOUT_SECONDS > 0


def test_every_vnu_launch_is_bounded(monkeypatch: Any) -> None:
    """The bound rides on the call, so no arm of this gate can drop it.

    ``run_vnu`` is the only place the checker is launched and the timeout is an
    argument rather than a wrapper a future arm could bypass, so a second
    launch site written as a bare ``subprocess.run`` would be the unbounded
    wait this test exists to rule out.
    """
    seen: list[Any] = []

    def record(*_args: Any, **kwargs: Any) -> _Completed:
        seen.append(kwargs.get("timeout"))
        return _Completed(0)

    monkeypatch.setattr(lint_html.subprocess, "run", record)
    lint_html.run_vnu([], [REPO_ROOT / "package.json"])
    lint_html.run_vnu(["--css"], [REPO_ROOT / "package.json"])
    assert seen == [lint_html.VNU_TIMEOUT_SECONDS] * 2


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


def test_a_checker_that_validates_nothing_fails_the_css_pass(
    monkeypatch: Any, capsys: Any, tmp_path: Path
) -> None:
    """vnu reported nothing at all on an earlier bundle, a planted typo
    included, so a clean exit is not evidence on its own. The canary copy
    carries a declaration vnu must reject; a checker that accepts it fails the
    gate before the real stylesheet is read."""
    calls: list[list[str]] = []

    def accept_everything(args: list[str], paths: list[str | Path]) -> int:
        calls.append([*args, *(str(p) for p in paths)])
        return 0

    monkeypatch.setattr(lint_html, "run_vnu", accept_everything)
    assert lint_html.lint_static_assets(tmp_path) == 1
    assert "validated nothing" in capsys.readouterr().out
    canary = tmp_path / "style-canary.css"
    assert canary.read_text(encoding="utf-8").endswith(lint_html.CSS_CANARY)
    # The canary ran, and the shipped stylesheets were never passed as clean.
    assert any(str(canary) in call for call in calls)
    assert not any(str(lint_html.ASSETS_DIR / "print.css") in call for call in calls)
