"""Tests for subprocess lifecycle guarantees (reaping, bounded waits, group kills).

Pins the two resource-lifecycle fixes:

- ``run_regen_step`` must kill the WHOLE regen process group on timeout (the
  rebrew worker is uv's grandchild; killing only uv orphans it while it is
  still writing coverage.db) and always reap the child.
- ``_open_and_reap`` must reap the browser-opener child (setsid alone does not
  prevent zombies) and bound its wait so a hung opener cannot stall serve.
"""

from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from recoverage.server import (
    _BROWSER_OPEN_TIMEOUT,
    _open_and_reap,
    run_regen_step,
)

POSIX = os.name == "posix"

FAKE_UV_OK = """\
#!/bin/sh
exit 0
"""

FAKE_UV_FAIL = """\
#!/bin/sh
echo boom >&2
exit 3
"""

# Stays alive past the timeout with a live grandchild; records the
# grandchild's PID so the test can prove the GROUP kill reached it.
# Absolute /bin/sleep: the fake PATH below replaces the real one.
FAKE_UV_HANG = """\
#!/bin/sh
/bin/sleep 60 &
printf '%s\\n' "$!" > "$GRANDCHILD_PID_FILE"
wait
"""


def _install_fake_uv(monkeypatch: Any, tmp_path: Path, body: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    uv = bin_dir / "uv"
    uv.write_text(body)
    uv.chmod(uv.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bin_dir))
    return uv


@pytest.mark.skipif(not POSIX, reason="POSIX process groups")
class TestRunRegenStep:
    def test_success_returns_none(self, monkeypatch: Any, tmp_path: Path) -> None:
        _install_fake_uv(monkeypatch, tmp_path, FAKE_UV_OK)
        assert run_regen_step("catalog", tmp_path) is None

    def test_nonzero_exit_raises_called_process_error(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        _install_fake_uv(monkeypatch, tmp_path, FAKE_UV_FAIL)
        with pytest.raises(subprocess.CalledProcessError) as excinfo:
            run_regen_step("build-db", tmp_path)
        assert excinfo.value.returncode == 3

    def test_missing_uv_raises_file_not_found(self, monkeypatch: Any, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))
        with pytest.raises(FileNotFoundError):
            run_regen_step("catalog", tmp_path)

    def test_timeout_kills_grandchild_and_raises(self, monkeypatch: Any, tmp_path: Path) -> None:
        """SIGKILL to uv alone would leave the rebrew grandchild running; the
        group kill must take it down too."""
        import recoverage.server as srv

        pid_file = tmp_path / "grandchild.pid"
        monkeypatch.setenv("GRANDCHILD_PID_FILE", str(pid_file))
        _install_fake_uv(monkeypatch, tmp_path, FAKE_UV_HANG)
        monkeypatch.setattr(srv, "REGEN_TIMEOUT", 0.5)

        start = time.monotonic()
        with pytest.raises(subprocess.TimeoutExpired):
            run_regen_step("catalog", tmp_path)
        elapsed = time.monotonic() - start
        assert elapsed < 10, "timeout path must not block anywhere near the grandchild lifetime"

        grandchild_pid = int(pid_file.read_text().strip())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild_pid, 0)
            except ProcessLookupError:
                break  # reaped by init after the group kill — the fix works
            time.sleep(0.05)
        else:
            pytest.fail("grandchild survived the regen timeout (process-group leak)")

    def test_timeout_raises_timeout_expired_with_command(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        import recoverage.server as srv

        monkeypatch.setenv("GRANDCHILD_PID_FILE", str(tmp_path / "unused.pid"))
        _install_fake_uv(monkeypatch, tmp_path, FAKE_UV_HANG)
        monkeypatch.setattr(srv, "REGEN_TIMEOUT", 0.3)
        with pytest.raises(subprocess.TimeoutExpired) as excinfo:
            run_regen_step("catalog", tmp_path)
        assert excinfo.value.timeout == 0.3


class TestOpenAndReap:
    def test_missing_opener_falls_back_to_webbrowser(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        opened: list[str] = []
        import webbrowser

        monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
        _open_and_reap("http://127.0.0.1:8001", [str(tmp_path / "no-such-binary")])
        assert opened == ["http://127.0.0.1:8001"]

    @pytest.mark.skipif(not POSIX, reason="uses POSIX sleep/kill")
    def test_hung_opener_is_killed_within_bound(self, monkeypatch: Any) -> None:
        """A wedged opener must not stall serve startup forever: bounded
        wait, then kill + reap (which also prevents the zombie)."""
        import recoverage.server as srv

        monkeypatch.setattr(srv, "_BROWSER_OPEN_TIMEOUT", 0.3)
        start = time.monotonic()
        _open_and_reap("http://127.0.0.1:8001", ["sleep", "60"])
        elapsed = time.monotonic() - start
        assert elapsed < 5, f"hung opener blocked {elapsed:.1f}s (unbounded wait)"
        assert _BROWSER_OPEN_TIMEOUT == 10  # module default untouched for prod

    @pytest.mark.skipif(not POSIX, reason="uses POSIX true")
    def test_exiting_child_is_reaped_no_zombie(self) -> None:
        """The fire-and-forget opener must be waited on: setsid alone leaves
        zombies behind in a long-lived server."""
        _open_and_reap("http://127.0.0.1:8001", ["true"])
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return  # no children at all — nothing leaked
        assert pid == 0, "an opener child was left unreaped (zombie)"
        del status
