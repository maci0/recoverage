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

from recoverage.cli import (
    _BROWSER_OPEN_TIMEOUT,
    _open_and_reap,
)
from recoverage.regen import run_regen_step

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

# Same hang, but also records its own PID so a test can prove the direct uv
# child AND its grandchild are gone after an abandonment path.
FAKE_UV_HANG_RECORD_ALL = """\
#!/bin/sh
printf '%s\\n' "$$" > "$CHILD_PID_FILE"
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
        import recoverage.regen as regen

        pid_file = tmp_path / "grandchild.pid"
        monkeypatch.setenv("GRANDCHILD_PID_FILE", str(pid_file))
        _install_fake_uv(monkeypatch, tmp_path, FAKE_UV_HANG)
        monkeypatch.setattr(regen, "REGEN_TIMEOUT", 0.5)

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
        import recoverage.regen as regen

        monkeypatch.setenv("GRANDCHILD_PID_FILE", str(tmp_path / "unused.pid"))
        _install_fake_uv(monkeypatch, tmp_path, FAKE_UV_HANG)
        monkeypatch.setattr(regen, "REGEN_TIMEOUT", 0.3)
        with pytest.raises(subprocess.TimeoutExpired) as excinfo:
            run_regen_step("catalog", tmp_path)
        assert excinfo.value.timeout == 0.3

    @pytest.mark.skipif(not POSIX, reason="POSIX process groups and signals")
    def test_keyboard_interrupt_kills_regen_tree(self, monkeypatch: Any, tmp_path: Path) -> None:
        """Ctrl+C while proc.wait() blocks must not orphan the regen tree.

        The child runs in its own session (start_new_session), so the
        terminal's SIGINT never reaches it — without a kill on the
        exception path, uv + rebrew survive as orphans and keep writing
        coverage.db behind a restarted dashboard.
        """
        import signal
        import threading

        import recoverage.regen as regen

        child_pid_file = tmp_path / "child.pid"
        grandchild_pid_file = tmp_path / "grandchild.pid"
        monkeypatch.setenv("CHILD_PID_FILE", str(child_pid_file))
        monkeypatch.setenv("GRANDCHILD_PID_FILE", str(grandchild_pid_file))
        _install_fake_uv(monkeypatch, tmp_path, FAKE_UV_HANG_RECORD_ALL)
        monkeypatch.setattr(regen, "REGEN_TIMEOUT", 30)

        def _interrupt() -> None:
            os.kill(os.getpid(), signal.SIGINT)

        # Fires while the main thread is parked in proc.wait(); the generous
        # delay guarantees Popen/wait were already entered.
        timer = threading.Timer(0.5, _interrupt)
        timer.daemon = True
        with pytest.raises(KeyboardInterrupt):
            try:
                timer.start()
                run_regen_step("catalog", tmp_path)
            finally:
                timer.cancel()

        pids = [int(child_pid_file.read_text()), int(grandchild_pid_file.read_text())]

        def _gone(pid: int) -> bool:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True  # reaped by init after the group kill
            return False

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not all(_gone(p) for p in pids):
            time.sleep(0.05)
        assert all(_gone(p) for p in pids), f"regen tree survived Ctrl+C (orphans): {pids}"


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
        import recoverage.cli as cli

        monkeypatch.setattr(cli, "_BROWSER_OPEN_TIMEOUT", 0.3)
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


class TestClientConnectionDeadline:
    """Every accepted client connection's handler thread must have a release
    deadline.

    ThreadingMixIn caps neither threads nor connections: without a socket
    deadline on the request handler, a peer that connects and then goes silent
    (crashed laptop, dropped NAT mapping) pins its handler thread forever in
    the request-line read, and an SSE client that stops reading pins it in the
    response write.  The handler's ``timeout`` turns both stalls into
    socket.timeout so the thread exits and the connection is released.
    """

    def test_silent_peer_releases_handler_thread(self) -> None:
        import socket
        import threading
        from wsgiref.simple_server import WSGIRequestHandler

        from recoverage.cli import _ThreadingWSGIServer

        class _ShortDeadlineHandler(WSGIRequestHandler):
            timeout = 0.5

            def address_string(self) -> str:
                return self.client_address[0]

            def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
                pass

            def log_message(self, *args: Any, **kwargs: Any) -> None:
                pass  # keep "Request timed out" noise out of the test output

        server = _ThreadingWSGIServer(("127.0.0.1", 0), _ShortDeadlineHandler)
        # block_on_close=False keeps a regressed (wedged) handler from turning
        # teardown into a hang; daemon threads die with the test process.
        server.block_on_close = False
        port = server.server_address[1]
        accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
        accept_thread.start()
        try:
            baseline = threading.active_count()
            with socket.create_connection(("127.0.0.1", port), timeout=5):
                # Connected, nothing sent: the handler thread parks in the
                # request-line read on this connection.
                spawned = baseline + 1
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and threading.active_count() < spawned:
                    time.sleep(0.02)
                assert threading.active_count() >= spawned, (
                    "handler thread never started for the accepted connection"
                )

                # The 0.5s deadline must retire that same thread.
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and threading.active_count() > baseline:
                    time.sleep(0.05)
                assert threading.active_count() <= baseline, (
                    "silent-peer handler thread never released (unbounded thread pinning)"
                )
        finally:
            server.shutdown()
            server.server_close()
