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


def _own_zombie_pids() -> set[int]:
    """PIDs of this process's children currently in the zombie state."""
    zombies: set[int] = set()
    me = os.getpid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            fields = stat[stat.rindex(")") + 1 :].split()
            state, ppid = fields[0], int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
        if ppid == me and state == "Z":
            zombies.add(int(entry.name))
    return zombies


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
    catalog.__path__ = []  # type: ignore[attr-defined]
    catalog_cli = types.ModuleType("rebrew.catalog.cli")
    catalog_cli.run_catalog = run_catalog  # type: ignore[attr-defined]
    build = types.ModuleType("rebrew.build_db")
    build.build_db = build_db  # type: ignore[attr-defined]
    for name, module in (
        ("rebrew", package),
        ("rebrew.config", config),
        ("rebrew.catalog", catalog),
        ("rebrew.catalog.cli", catalog_cli),
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
        for name in (
            "rebrew.config",
            "rebrew.catalog",
            "rebrew.catalog.cli",
            "rebrew.build_db",
        ):
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


class TestRebrewSurface:
    """Pins the rebrew call shape run_regen depends on.

    rebrew 2.7 stopped re-exporting ``run_catalog`` from ``rebrew.catalog``.
    A later required argument on any of the three calls would raise TypeError
    inside regen instead of failing this import check.
    """

    def test_regen_entrypoints_match_run_regen(self) -> None:
        import inspect

        from rebrew.build_db import build_db
        from rebrew.catalog.cli import run_catalog
        from rebrew.config import load_config

        catalog_required = [
            name
            for name, param in inspect.signature(run_catalog).parameters.items()
            if param.default is inspect.Parameter.empty
        ]
        assert catalog_required == ["cfg"]
        assert list(inspect.signature(load_config).parameters)[:1] == ["root"]
        project_root = inspect.signature(build_db).parameters["project_root"]
        assert project_root.default is None


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

        # The wait bound the opener actually sees is the module global read at
        # call time, so shortening it here is what shrinks the wall clock.
        monkeypatch.setattr(cli, "_BROWSER_OPEN_TIMEOUT", 0.3)
        start = time.monotonic()
        _open_and_reap("http://127.0.0.1:8001", ["sleep", "60"])
        elapsed = time.monotonic() - start
        assert _BROWSER_OPEN_TIMEOUT > 0, "production opener wait must stay bounded"
        assert elapsed >= 0.3, f"waited {elapsed:.2f}s: the bound was not applied"
        assert elapsed < 5, f"hung opener blocked {elapsed:.1f}s (unbounded wait)"

    @pytest.mark.skipif(not POSIX, reason="uses POSIX /proc and true")
    def test_exiting_child_is_reaped_no_zombie(self) -> None:
        """The fire-and-forget opener must be waited on: setsid alone leaves
        zombies behind in a long-lived server.

        Scans this process's own children instead of ``waitpid(-1)``: a
        bare waitpid would reap (and thereby hide) a child left by another
        test, and would report that foreign child as this test's leak.
        """
        _open_and_reap("http://127.0.0.1:8001", ["true"])
        assert _own_zombie_pids() == set(), "an opener child was left unreaped (zombie)"


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

    def test_production_handler_carries_a_finite_deadline(self) -> None:
        """wsgiref's stock handler has ``timeout = None`` (unbounded).  The
        deadline is the whole guarantee, so pin it on the class serve() runs.
        """
        import recoverage.cli as cli
        from recoverage.api import _SSE_HEARTBEAT_SECONDS

        timeout = cli._QuietTimeoutRequestHandler.timeout
        assert isinstance(timeout, (int, float)), "no socket deadline on the handler"
        assert 0 < timeout <= _SSE_HEARTBEAT_SECONDS * 10, (
            f"deadline {timeout}s must be bounded and well clear of the SSE heartbeat"
        )

    def test_silent_peer_releases_handler_thread(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import socket
        import threading

        import recoverage.cli as cli

        # Drive the PRODUCTION handler, shortened only in the deadline the
        # test would otherwise have to wait 120 s for.  A private stub
        # handler would pass here even with the deadline removed from serve.
        monkeypatch.setattr(cli._QuietTimeoutRequestHandler, "timeout", 0.5)
        monkeypatch.setattr(cli._QuietTimeoutRequestHandler, "log_message", lambda *a, **k: None)

        server = cli._ThreadingWSGIServer(("127.0.0.1", 0), cli._QuietTimeoutRequestHandler)
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
