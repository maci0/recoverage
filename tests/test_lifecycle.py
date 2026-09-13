"""Tests for lifecycle guarantees (regen ordering, reaping, bounded waits).

Pins:

- ``run_regen`` loads rebrew-project.toml once and calls rebrew's catalog and
  build-db module functions in order, in this process (no subprocess).
- ``_open_and_reap`` must reap the browser-opener child (setsid alone does not
  prevent zombies) and bound its wait so a hung opener cannot stall serve.
"""

from __future__ import annotations

import os
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest

from recoverage.cli import (
    _BROWSER_OPEN_TIMEOUT,
    _open_and_reap,
)
from recoverage.regen import run_regen

POSIX = os.name == "posix"


def _install_fake_rebrew(
    monkeypatch: pytest.MonkeyPatch,
    *,
    load_config: Any,
    run_catalog: Any,
    build_db: Any,
) -> None:
    """Put fake rebrew modules in sys.modules for run_regen's lazy imports."""
    package = types.ModuleType("rebrew")
    package.__path__ = []  # type: ignore[attr-defined]
    config = types.ModuleType("rebrew.config")
    config.load_config = load_config  # type: ignore[attr-defined]
    catalog = types.ModuleType("rebrew.catalog")
    catalog.run_catalog = run_catalog  # type: ignore[attr-defined]
    build = types.ModuleType("rebrew.build_db")
    build.build_db = build_db  # type: ignore[attr-defined]
    for name, module in (
        ("rebrew", package),
        ("rebrew.config", config),
        ("rebrew.catalog", catalog),
        ("rebrew.build_db", build),
    ):
        monkeypatch.setitem(sys.modules, name, module)


class TestRunRegen:
    def test_loads_config_once_then_runs_steps_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        events: list[tuple[str, Any]] = []
        cfg = object()

        def load_config(root: Path) -> object:
            events.append(("load_config", root))
            return cfg

        def run_catalog(c: object) -> None:
            events.append(("run_catalog", c))

        def build_db(project_root: Path) -> None:
            events.append(("build_db", project_root))

        _install_fake_rebrew(
            monkeypatch,
            load_config=load_config,
            run_catalog=run_catalog,
            build_db=build_db,
        )

        run_regen(tmp_path)

        assert events == [
            ("load_config", tmp_path),
            ("run_catalog", cfg),
            ("build_db", tmp_path),
        ]

    def test_missing_rebrew_import_error_propagates(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # None in sys.modules is the deterministic "rebrew cannot be imported"
        # signal.  rebrew is a required dependency, so an ImportError here is a
        # broken install: run_regen lets it propagate and the callers map it to
        # their exit-1 / HTTP-500 contract.
        monkeypatch.setitem(sys.modules, "rebrew", None)
        for name in ("rebrew.config", "rebrew.catalog", "rebrew.build_db"):
            monkeypatch.delitem(sys.modules, name, raising=False)

        with pytest.raises(ImportError):
            run_regen(tmp_path)

    def test_rebrew_failure_propagates(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """run_regen must not swallow rebrew's own exceptions; callers map them."""

        def run_catalog(c: object) -> None:
            raise ValueError("corrupt function_structure.json")

        _install_fake_rebrew(
            monkeypatch,
            load_config=lambda root: object(),
            run_catalog=run_catalog,
            build_db=lambda project_root: None,
        )

        with pytest.raises(ValueError, match="corrupt"):
            run_regen(tmp_path)


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
