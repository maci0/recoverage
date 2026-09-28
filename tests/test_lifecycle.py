"""Tests for lifecycle guarantees (regen ordering, reaping, bounded waits).

Pins:

- ``run_regen`` loads rebrew-project.toml once and calls rebrew's catalog and
  build-db module functions in order, in this process (no subprocess), and a
  second run repeats that sequence instead of appending to or skipping it.
- ``_open_and_reap`` must reap the browser-opener child (setsid alone does not
  prevent zombies), bound its wait so a hung opener cannot stall serve, and
  detach the opener from the console on every platform that needs it.
- A client that hangs up on ``/api/events`` must give back both slots it took:
  the ``_SSE_MAX_CLIENTS`` entry and the connection-admission slot behind its
  handler thread. Both are global and neither comes back on its own.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest

from recoverage import devserver
from recoverage.cli import (
    _open_and_reap,
    _server_class_for,
)
from recoverage.regen import run_regen

#: The zombie scan below reads /proc/<pid>/stat, which only Linux provides.
#: Probed, not keyed on os.name: macOS and the BSDs are posix and ship no
#: /proc, so a posix gate sent the scan into a directory that is not there and
#: every macOS run of this file errored on FileNotFoundError before the
#: assertion it exists to make.
HAS_PROC = Path("/proc/self/stat").is_file()


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
    writer = types.ModuleType("rebrew.coverage_toml")
    writer.write_coverage_toml = build_db  # type: ignore[attr-defined]
    for name, module in (
        ("rebrew", package),
        ("rebrew.config", config),
        ("rebrew.catalog", catalog),
        ("rebrew.catalog.cli", catalog_cli),
        ("rebrew.coverage_toml", writer),
    ):
        monkeypatch.setitem(sys.modules, name, module)


def _record_rebrew_calls(monkeypatch: pytest.MonkeyPatch, events: list[tuple[str, Any]]) -> object:
    """Install fake rebrew steps that append their name and argument to *events*.

    Returns the config object ``load_config`` hands back, so a caller can
    assert the catalog step received that same object rather than a path.
    """
    cfg = object()

    def load_config(root: Path) -> object:
        events.append(("load_config", root))
        return cfg

    def run_catalog(c: object) -> None:
        events.append(("run_catalog", c))

    def build_db(project_root: Path, force: bool = False) -> None:
        events.append(("build_db", project_root, force))

    _install_fake_rebrew(
        monkeypatch,
        load_config=load_config,
        run_catalog=run_catalog,
        build_db=build_db,
    )
    return cfg


class TestRunRegen:
    def test_loads_config_once_then_runs_steps_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        events: list[tuple[str, Any]] = []
        cfg = _record_rebrew_calls(monkeypatch, events)

        run_regen(tmp_path)

        assert events == [
            ("load_config", tmp_path),
            ("run_catalog", cfg),
            # force=True: a coverage file from the previous format is the file
            # this command exists to replace, and the writer takes the flag so
            # a later version check cannot silently refuse it.
            ("build_db", tmp_path, True),
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
            "rebrew.coverage_toml",
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

    def test_rebrew_error_exit_becomes_regen_failed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """rebrew's ``error_exit`` raises ``typer.Exit``; the caller must not
        have to import typer to read it, so run_regen translates it."""
        import typer

        from recoverage.regen import RegenError

        def run_catalog(c: object) -> None:
            raise typer.Exit(2)

        _install_fake_rebrew(
            monkeypatch,
            load_config=lambda root: object(),
            run_catalog=run_catalog,
            build_db=lambda project_root: None,
        )

        with pytest.raises(RegenError) as caught:
            run_regen(tmp_path)
        assert caught.value.exit_code == 2

    def test_a_second_run_repeats_the_same_pipeline(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Running it twice runs the same three steps, with no carry-over.

        The docstring claims a second run converges on the first run's state.
        What recoverage owns is the call shape: neither execution appends to,
        skips, or reorders anything, so the second ends where the first did.
        """
        events: list[tuple[str, Any]] = []
        cfg = _record_rebrew_calls(monkeypatch, events)

        one_run = [
            ("load_config", tmp_path),
            ("run_catalog", cfg),
            ("build_db", tmp_path, True),
        ]
        run_regen(tmp_path)
        run_regen(tmp_path)

        assert events == one_run * 2

    def test_refuses_a_db_override_rebrew_would_not_write_to(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """RECOVERAGE_DB set to a directory rebrew will not write to is refused.

        rebrew resolves its coverage directory from rebrew-project.toml alone.
        A regen that ignored the override would write documents no served
        directory reads and still report success, which is worse than failing:
        the dashboard would look refreshed and be exactly as stale.
        """
        from recoverage.regen import RegenDbMismatchError

        events: list[tuple[str, Any]] = []
        _record_rebrew_calls(monkeypatch, events)
        _install_fake_workspace(monkeypatch, tmp_path / "db")

        monkeypatch.setenv("RECOVERAGE_DB", str(tmp_path / "elsewhere"))
        with pytest.raises(RegenDbMismatchError) as excinfo:
            run_regen(tmp_path)

        assert "RECOVERAGE_DB" in str(excinfo.value)
        assert str(tmp_path / "elsewhere") in str(excinfo.value)
        # Refused before rebrew ran: no catalog, no write.
        assert events == []

    def test_db_override_matching_rebrews_directory_runs(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        events: list[tuple[str, Any]] = []
        _record_rebrew_calls(monkeypatch, events)
        _install_fake_workspace(monkeypatch, tmp_path / "db")

        monkeypatch.setenv("RECOVERAGE_DB", str(tmp_path / "db"))
        run_regen(tmp_path)

        assert [name for name, *_ in events] == ["load_config", "run_catalog", "build_db"]

    def test_a_differently_spelled_override_on_a_case_insensitive_fs_runs(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """`/proj/DB` and `/proj/db` are ONE directory on macOS and Windows.

        Compared as strings they are two, and the guard refused a regen that
        would have reached the dashboard, naming a mismatch that does not
        exist.  The comparison asks the OS instead, so it is right on a
        case-insensitive filesystem and still exact on a case-sensitive one.

        Only the case arm is exercised, and only where the host agrees that
        the two spellings are one directory: on a case-sensitive filesystem
        they are genuinely two directories and the refusal is the correct
        answer, so the test skips rather than asserting the wrong thing.
        """
        from recoverage.regen import _same_directory

        upper = tmp_path / "DB"
        upper.mkdir()
        lower = tmp_path / "db"
        if not _same_directory(upper, lower):
            pytest.skip("this filesystem distinguishes the two spellings")

        events: list[tuple[str, Any]] = []
        _record_rebrew_calls(monkeypatch, events)
        _install_fake_workspace(monkeypatch, upper)

        monkeypatch.setenv("RECOVERAGE_DB", str(lower))
        run_regen(tmp_path)

        assert [name for name, *_ in events] == ["load_config", "run_catalog", "build_db"]

    def test_two_directories_that_only_look_alike_are_still_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The OS is asked which directory, not whether the names match.

        A symlink and its target, and a path with `..` in it, are the same
        directory; a hardlink to a directory is not something a filesystem
        hands out, so the two spellings below are genuinely distinct and must
        keep raising.  Without this the samefile fallback would be a way to
        wave a real mismatch through.
        """
        from recoverage.regen import RegenDbMismatchError, _same_directory

        real = tmp_path / "db"
        real.mkdir()
        other = tmp_path / "elsewhere"
        other.mkdir()

        assert _same_directory(real, real / ".." / "db"), "a `..` hop is the same directory"
        assert not _same_directory(real, other)

        events: list[tuple[str, Any]] = []
        _record_rebrew_calls(monkeypatch, events)
        _install_fake_workspace(monkeypatch, real)

        monkeypatch.setenv("RECOVERAGE_DB", str(other))
        with pytest.raises(RegenDbMismatchError):
            run_regen(tmp_path)
        assert events == []


def _install_fake_workspace(monkeypatch: pytest.MonkeyPatch, db_dir: Path) -> None:
    """Fake ``rebrew.workspace`` with *db_dir* as the resolved coverage directory.

    Only the two names ``_check_writes_where_the_dashboard_reads`` imports; the
    real module is a sibling checkout this suite does not control.
    """
    workspace = types.ModuleType("rebrew.workspace")
    workspace.CONFIG_NAME = "rebrew-project.toml"  # type: ignore[attr-defined]
    workspace.db_dir = lambda root: db_dir  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "rebrew.workspace", workspace)


class TestRebrewSurface:
    """Pins the rebrew call shape run_regen depends on.

    rebrew 2.7 stopped re-exporting ``run_catalog`` from ``rebrew.catalog``.
    A later required argument on any of the three calls would raise TypeError
    inside regen instead of failing this import check.
    """

    def test_regen_entrypoints_match_run_regen(self) -> None:
        import inspect

        from rebrew.catalog.cli import run_catalog
        from rebrew.config import load_config
        from rebrew.coverage_toml import write_coverage_toml

        catalog_required = [
            name
            for name, param in inspect.signature(run_catalog).parameters.items()
            if param.default is inspect.Parameter.empty
        ]
        assert catalog_required == ["cfg"]
        assert list(inspect.signature(load_config).parameters)[:1] == ["root"]
        root_parameter = inspect.signature(write_coverage_toml).parameters["root_dir"]
        assert root_parameter.default is inspect.Parameter.empty
        # The three calls run_regen makes, bound against the installed rebrew.
        root = Path("project")
        inspect.signature(load_config).bind(root)
        inspect.signature(run_catalog).bind(object())
        # force=True is the fourth call shape regen depends on: the writer takes
        # it so a coverage file from the previous format is replaced rather than
        # refused, which is the one file a regen exists to replace.
        inspect.signature(write_coverage_toml).bind(root, force=True)


class TestOpenAndReap:
    def test_missing_opener_falls_back_to_webbrowser(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        opened: list[str] = []
        import webbrowser

        monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
        _open_and_reap("http://127.0.0.1:8001", [str(tmp_path / "no-such-binary")])
        assert opened == ["http://127.0.0.1:8001"]

    def test_hung_opener_is_killed_within_bound(self, monkeypatch: Any) -> None:
        """A wedged opener must not stall serve startup forever: bounded
        wait, then kill + reap (which also prevents the zombie).

        The wedged child is this interpreter rather than a `sleep` binary, so
        the bound is exercised on every platform instead of only where a
        POSIX sleep(1) exists.
        """
        import recoverage.cli as cli

        # The wait bound the opener actually sees is the module global read at
        # call time, so shortening it here is what shrinks the wall clock.
        # Read the production value FIRST: after the patch the name resolves
        # to 0.3, so asserting on it afterwards restates what the test wrote.
        production_bound = cli._BROWSER_OPEN_TIMEOUT_SECONDS
        assert 0 < production_bound < 30, f"production opener wait is {production_bound}s"
        monkeypatch.setattr(cli, "_BROWSER_OPEN_TIMEOUT_SECONDS", 0.3)
        start = time.monotonic()
        _open_and_reap(
            "http://127.0.0.1:8001", [sys.executable, "-c", "import time; time.sleep(60)"]
        )
        elapsed = time.monotonic() - start
        assert elapsed >= 0.3, f"waited {elapsed:.2f}s: the bound was not applied"
        assert elapsed < 5, f"hung opener blocked {elapsed:.1f}s (unbounded wait)"

    def test_nothing_listening_means_no_browser(self, monkeypatch: Any) -> None:
        """The deferred opener asks the listener before it launches a tab.

        ``Timer.cancel`` returns without waiting for the timer thread, so a
        start that fails while the callback is already running (EADDRINUSE, a
        Ctrl+C inside the scheduling window) still runs it, and cancelling it
        does nothing.  Without the probe that is a tab at a port nothing will
        ever listen on, which is the outcome the cancel exists to prevent.
        """
        import recoverage.cli as cli

        monkeypatch.setattr(cli, "_OPEN_LISTEN_WAIT_SECONDS", 0.2)
        opened: list[str] = []
        monkeypatch.setattr(cli, "open_browser", lambda url: opened.append(url) or True)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]  # bound, never listening: nothing accepts

            cli._open_when_listening(f"http://127.0.0.1:{port}")

        assert opened == [], "opened a tab at an address with no listener"

    def test_a_listener_is_what_releases_the_browser(self, monkeypatch: Any) -> None:
        """The probe is a liveness check, not a way to suppress the opener.

        The port the banner prints is handed to the browser only once the
        server answers on it, so the ordinary start still opens its tab.
        """
        import recoverage.cli as cli

        opened: list[str] = []
        monkeypatch.setattr(cli, "open_browser", lambda url: opened.append(url) or True)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            cli._open_when_listening(f"http://127.0.0.1:{port}")

        assert opened == [f"http://127.0.0.1:{port}"]

    def test_detach_flags_match_the_platform(self, monkeypatch: Any) -> None:
        """Openers detach everywhere, by the mechanism each platform has.

        POSIX gets start_new_session (passed separately, not here), Windows the
        creation flags, and the flags must stay 0 elsewhere: a stray non-zero
        value makes Popen raise ValueError on every other platform.

        The flags are probed rather than keyed on ``os.name``, because the
        Windows branch is only reachable on Windows and the two facts below
        belong to different platforms: on POSIX the flags must be 0, on Windows
        they must be both creation flags.
        """
        import recoverage.cli as cli

        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", None)
        detached = getattr(subprocess, "DETACHED_PROCESS", None)
        if new_group is None or detached is None:
            # Every non-Windows platform lands here: the flags must not leak
            # into Popen, which rejects a non-zero creationflags off Windows.
            assert cli._windows_detach_flags() == 0
            pytest.skip("Windows creation flags are not defined on this platform")
        # On Windows os.name is already "nt", so the flags come back as-is;
        # the patched os.name just exercises the same string elsewhere.
        assert cli._windows_detach_flags() == new_group | detached
        monkeypatch.setattr(cli.os, "name", "nt")
        assert cli._windows_detach_flags() == new_group | detached

    def test_reap_never_raises_into_the_caller(self, monkeypatch: Any) -> None:
        """A kill or wait that fails is the failure this function is there to
        absorb: both of its callers are error paths, one of them inside a
        daemon Timer, so an exception escaping here prints an unobserved
        "Exception in thread" and leaves the child unreaped."""
        import recoverage.cli as cli

        class _BrokenProc:
            pid = 4242

            def kill(self) -> None:
                raise OSError("ESRCH: no such process")

            def wait(self, timeout: float | None = None) -> int:
                raise OSError("ESRCH: no such process")

        monkeypatch.setattr(cli.os, "name", "nt")  # the direct-kill branch
        cli._kill_and_reap(_BrokenProc())  # type: ignore[arg-type]

    def test_reap_wait_is_bounded(self, monkeypatch: Any, caplog: pytest.LogCaptureFixture) -> None:
        """A SIGKILL that never lands must not trade a hung opener for a
        thread blocked in wait() forever: the reap carries the same bound.

        The stub's ``wait`` raises the moment it is called, so wall clock
        proves nothing here. What the property actually is — the bound is
        handed to ``wait`` at all, and it is the opener's — is pinned by
        recording the timeout argument and by the abandonment warning that
        names the child.
        """
        import recoverage.cli as cli

        seen: list[float | None] = []

        class _StuckProc:
            pid = 4242

            def kill(self) -> None:
                return None

            def wait(self, timeout: float | None = None) -> int:
                seen.append(timeout)
                raise subprocess.TimeoutExpired(cmd="opener", timeout=timeout or 0)

        monkeypatch.setattr(cli, "_BROWSER_OPEN_TIMEOUT_SECONDS", 0.1)
        monkeypatch.setattr(cli.os, "name", "nt")
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            cli._kill_and_reap(_StuckProc())  # type: ignore[arg-type]
        assert seen == [0.1], f"the reap waited on {seen}, not on the opener's bound"
        assert any("4242" in record.getMessage() for record in caplog.records), (
            "the unreaped opener was left without a line naming it"
        )

    @pytest.mark.skipif(not HAS_PROC, reason="the zombie scan reads /proc, which only Linux has")
    def test_exiting_child_is_reaped_no_zombie(self) -> None:
        """The fire-and-forget opener must be waited on: setsid alone leaves
        zombies behind in a long-lived server.

        Scans this process's own children instead of ``waitpid(-1)``: a
        bare waitpid would reap (and thereby hide) a child left by another
        test, and would report that foreign child as this test's leak.
        """
        # This interpreter rather than a `true` binary: the child has to exist
        # on every platform, and /usr/bin/true is not on PATH everywhere.
        _open_and_reap("http://127.0.0.1:8001", [sys.executable, "-c", "pass"])
        assert _own_zombie_pids() == set(), "an opener child was left unreaped (zombie)"


class TestBindAddressFamily:
    """``--bind`` accepts an IPv6 literal, so the listener has to be able to
    take one.

    ``config.validate_bind`` keeps the colons of an IPv6 address (it rejects
    only a ``:`` that is a port), and ``server._peer_is_loopback`` documents a
    dual-stack ``--bind ::`` listener reporting IPv4 peers in mapped form.
    wsgiref's ``WSGIServer`` inherits ``http.server.HTTPServer``'s ``AF_INET``
    and never changes it, so without the family selection below an IPv6 bind
    dies in ``socket.bind()`` on every platform, and serve's OSError handler
    reports "is another instance already running?" for an address-family
    mismatch.
    """

    @pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "no-such-host.invalid"])
    def test_ipv4_and_unresolvable_bind_stay_on_af_inet(self, host: str) -> None:
        assert _server_class_for(host).address_family is socket.AF_INET

    @pytest.mark.skipif(
        not any(
            info[0] is socket.AF_INET6
            for info in socket.getaddrinfo("::1", None, type=socket.SOCK_STREAM)
        ),
        reason="this host has no IPv6 loopback",
    )
    def test_an_ipv6_bind_binds_and_listens(self) -> None:
        server_class = _server_class_for("::1")
        assert server_class.address_family is socket.AF_INET6
        # The whole point: the class the selector returns has to survive a real
        # bind, which AF_INET cannot do for a v6 address on any platform.
        server = server_class(("::1", 0), None)
        try:
            assert server.socket.family is socket.AF_INET6
        finally:
            server.server_close()


class TestListenerReuseOption:
    """SO_REUSEADDR is on POSIX and must be off on Windows.

    wsgiref leaves ``allow_reuse_address = 1`` on the class it hands down, and
    the two platforms read that flag as opposite things: on POSIX it waives a
    TIME_WAIT so a restart binds at once, on Windows it lets a second socket
    bind an address a live socket already holds, splitting the traffic between
    them.  A Windows operator who starts a second ``serve`` on a busy port
    would watch the new one take half the requests, and the "another instance is
    already running" handler would never run because bind() succeeded.
    """

    def test_reuse_is_off_on_windows_and_on_everywhere_else(self) -> None:
        import recoverage.devserver as ds
        from recoverage.cli import _ThreadingWSGIServer6

        # The Windows half of the answer is asserted by the windows-latest
        # entry in the CI matrix, which runs this file; the POSIX half is what
        # the rest of the matrix asserts.  The IPv6 class serve() also returns
        # inherits the flag, and a redefinition there would put two listeners
        # on one setting with different answers.
        expected = os.name != "nt"
        assert ds._ThreadingWSGIServer.allow_reuse_address is expected
        assert _ThreadingWSGIServer6.allow_reuse_address is expected


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
        from recoverage.api import _SSE_HEARTBEAT_SECONDS

        timeout = devserver._QuietTimeoutRequestHandler.timeout
        assert isinstance(timeout, (int, float)), "no socket deadline on the handler"
        assert 0 < timeout <= _SSE_HEARTBEAT_SECONDS * 10, (
            f"deadline {timeout}s must be bounded, and generous next to a slow client's write"
        )

    def test_silent_peer_releases_handler_thread(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import socket
        import threading

        # Drive the PRODUCTION handler, shortened only in the deadline the
        # test would otherwise have to wait 120 s for.  A private stub
        # handler would pass here even with the deadline removed from serve.
        monkeypatch.setattr(devserver._QuietTimeoutRequestHandler, "timeout", 0.5)

        server = devserver._ThreadingWSGIServer(
            ("127.0.0.1", 0), devserver._QuietTimeoutRequestHandler
        )
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

    def test_a_deadline_under_the_heartbeat_does_not_close_a_healthy_stream(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The socket deadline is per OPERATION, not a budget for the stream.

        config.client_timeout's floor, the README and .env.example all once
        claimed a deadline under the SSE heartbeat closes a healthy
        /api/events stream, and a config validation test was named for it.
        The claim is false: an idle stream blocks on its event queue rather
        than on the socket, so nothing about the heartbeat interval reaches
        the deadline.  Driven against the real handler stack, with the
        deadline set well under the heartbeat.
        """
        import threading
        from wsgiref.simple_server import make_server

        from recoverage import api
        from recoverage.webapp import app

        monkeypatch.setattr(api, "_SSE_HEARTBEAT_SECONDS", 3.0)
        monkeypatch.setattr(devserver, "_CLIENT_SOCKET_TIMEOUT_SECONDS", 1)
        monkeypatch.setattr(devserver._QuietTimeoutRequestHandler, "timeout", 1)
        monkeypatch.setattr(
            devserver._QuietTimeoutRequestHandler, "log_message", lambda *a, **k: None
        )

        server = make_server(
            "127.0.0.1",
            0,
            app,
            server_class=_server_class_for("127.0.0.1"),
            handler_class=devserver._QuietTimeoutRequestHandler,
        )
        server.block_on_close = False
        accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
        accept_thread.start()
        try:
            conn = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=30)
            conn.settimeout(30)
            conn.sendall(
                b"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"
            )
            received = b""
            # Two pings at a 3s heartbeat with a 1s socket deadline: the
            # stream has outlived the deadline several times over, so a
            # deadline read as a connection-lifetime budget would have cut it.
            while received.count(b": ping") < 2:
                chunk = conn.recv(4096)
                assert chunk, "server closed a healthy /api/events stream on the clock"
                received += chunk
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_a_dropped_event_stream_gives_its_slot_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A client that hangs up on /api/events must release the map entry it holds.

        The stream registers its queue in `_SSE_CLIENTS` BEFORE the iterable
        exists, so a peer that goes away between the handler returning and the
        first write is unregisterable by the generator's `finally` alone: PEP
        3333 lets a server close the iterable it was handed without ever
        iterating it. `_SSEStream._release` covers both exits, and that release
        is the only thing standing between a dropped tab and a
        `_SSE_MAX_CLIENTS` that erodes by one per disconnect for the life of
        the process.

        The bound is the HEARTBEAT, not the disconnect: a peer that vanishes
        without a FIN the server can see is noticed when the next write fails,
        so a slot is held for at most `_SSE_HEARTBEAT_SECONDS`. The test waits
        one heartbeat and asks for the whole burst back, because that is the
        claim; a per-disconnect assertion would fail on a correct release.

        Driven over real sockets against the real handler stack, in a burst, so
        the number that has to come back is one a leak would make obvious.
        """
        import threading
        from wsgiref.simple_server import make_server

        from recoverage import api, metrics
        from recoverage.webapp import app

        # A short heartbeat, so the release this test waits for arrives in
        # about a second rather than in the production 15. It is the MECHANISM
        # under test (a failed write releases the slot), not the interval: the
        # bound the production value sets is one heartbeat, which is why
        # shortening it shortens the wait and changes nothing else.
        monkeypatch.setattr(api, "_SSE_HEARTBEAT_SECONDS", 1.0)
        monkeypatch.setattr(devserver._QuietTimeoutRequestHandler, "timeout", 5)
        monkeypatch.setattr(
            devserver._QuietTimeoutRequestHandler, "log_message", lambda *a, **k: None
        )

        server = make_server(
            "127.0.0.1",
            0,
            app,
            server_class=_server_class_for("127.0.0.1"),
            handler_class=devserver._QuietTimeoutRequestHandler,
        )
        server.block_on_close = False
        accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
        accept_thread.start()
        port = server.server_address[1]
        # Well under both caps, so the burst is admitted rather than refused.
        burst = 8
        conns: list[socket.socket] = []
        # Each of these takes TWO slots the process never regains by itself: the
        # connection-admission slot behind its handler thread, and its entry in
        # _SSE_CLIENTS. Both are global gauges, so the count this test is
        # asserting against has to be restored before it returns or every later
        # test reads a server that is holding streams nobody opened.
        held_before = metrics.CONNECTIONS.open
        try:
            with api._SSE_CLIENTS_LOCK:
                registered_before = len(api._SSE_CLIENTS)
            for _ in range(burst):
                conn = socket.create_connection(("127.0.0.1", port), timeout=30)
                conn.settimeout(30)
                conn.sendall(
                    b"GET /api/events HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"
                )
                assert b" 200 " in conn.recv(64)
                conns.append(conn)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with api._SSE_CLIENTS_LOCK:
                    if len(api._SSE_CLIENTS) >= registered_before + burst:
                        break
                time.sleep(0.02)
            with api._SSE_CLIENTS_LOCK:
                # A DELTA, not a total: a neighbouring test's stream releases on
                # the same mechanism and can still be registered when this one
                # starts. What has to hold is the count THIS burst added.
                assert len(api._SSE_CLIENTS) == registered_before + burst, (
                    "the streams never registered their slots"
                )
            # Hang up mid-body on every one of them: the response is unframed,
            # so this is the path a browser tab closing takes.
            for conn in conns:
                conn.close()
            conns.clear()
            deadline = time.monotonic() + api._SSE_HEARTBEAT_SECONDS + 10
            while time.monotonic() < deadline:
                with api._SSE_CLIENTS_LOCK:
                    if (
                        len(api._SSE_CLIENTS) <= registered_before
                        and metrics.CONNECTIONS.open <= held_before
                    ):
                        break
                time.sleep(0.05)
            with api._SSE_CLIENTS_LOCK:
                assert len(api._SSE_CLIENTS) <= registered_before, (
                    "disconnected event streams kept their slots; the cap erodes by "
                    "one per dropped tab for the life of the process"
                )
            assert metrics.CONNECTIONS.open <= held_before, (
                "a dropped event stream kept its connection slot"
            )
        finally:
            for conn in conns:
                conn.close()
            server.shutdown()
            server.server_close()
            accept_thread.join(timeout=5)

    def test_connections_are_capped_and_the_slot_is_released(self, monkeypatch) -> None:
        """The deadlines above bound how LONG a handler thread lives, never how
        MANY exist: ThreadingMixIn starts one per accept without asking. Open
        past the cap and the extra connections must be refused with a 503
        rather than each taking a thread and a descriptor for the full
        deadline."""
        import socket
        import threading

        from recoverage import metrics

        monkeypatch.setattr(devserver._QuietTimeoutRequestHandler, "timeout", 5)
        monkeypatch.setattr(devserver, "_MAX_CONNECTIONS", 2)

        server = devserver._ThreadingWSGIServer(
            ("127.0.1", 0), devserver._QuietTimeoutRequestHandler
        )
        server.block_on_close = False
        port = server.server_address[1]
        accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
        accept_thread.start()
        held: list[socket.socket] = []
        try:
            # Two silent peers occupy the cap; both park in the request-line read.
            for _ in range(2):
                sock = socket.create_connection(("127.0.1", port), timeout=5)
                held.append(sock)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and metrics.CONNECTIONS.open < 2:
                time.sleep(0.02)
            assert metrics.CONNECTIONS.open == 2

            # The third is past the cap: refused with a 503, not served.
            with socket.create_connection(("127.0.1", port), timeout=5) as extra:
                extra.settimeout(5)
                reply = extra.recv(64)
            assert reply.startswith(b"HTTP/1.1 503"), reply
            assert metrics.CONNECTIONS.open == 2, "a refused connection took a slot"

            # Freeing one slot admits the next connection again.
            held.pop().close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and metrics.CONNECTIONS.open > 0:
                time.sleep(0.02)
            with socket.create_connection(("127.0.1", port), timeout=5) as again:
                again.settimeout(5)
                again.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                assert again.recv(16).startswith(b"HTTP/")
        finally:
            for sock in held:
                sock.close()
            server.shutdown()
            server.server_close()
            accept_thread.join(timeout=5)

    def test_a_transport_rejection_reaches_the_app_logger(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A request the transport refuses must land in the app's log, not stderr.

        An over-long request line is answered 414 by the handler itself, before
        any Bottle route exists, so nothing downstream logs it. The stdlib
        default writes it to sys.stderr in http.server's own format, which has
        no level and no request id, so a client stuck in a rejection loop left
        no trace in the one place the operator reads.
        """
        import threading

        caplog.set_level(logging.WARNING, logger="recoverage")
        server = devserver._ThreadingWSGIServer(
            ("127.0.0.1", 0), devserver._QuietTimeoutRequestHandler
        )
        server.block_on_close = False
        port = server.server_address[1]
        accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
        accept_thread.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.settimeout(5)
                # Past the 64 KiB request-line cap _serve_requests enforces.
                sock.sendall(b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n")
                reply = sock.recv(64)
            # HTTP/1.0 on the wire: send_error runs before parse_request has
            # accepted the version, so the handler has none to answer with.
            assert reply.startswith(b"HTTP/1.0 414"), reply
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not any(
                "Transport rejected" in r.message for r in caplog.records
            ):
                time.sleep(0.02)
        finally:
            server.shutdown()
            server.server_close()
            accept_thread.join(timeout=5)

        rejections = [r for r in caplog.records if "Transport rejected" in r.message]
        assert rejections, f"the 414 was not logged; captured: {caplog.text}"
        assert rejections[0].levelno == logging.WARNING
        # The peer is the only thing separating one misbehaving client from a
        # scanner here: a transport rejection never reaches a route, so the
        # request-id filter has nothing to stamp.
        assert "127.0.0.1" in rejections[0].message
        # One line per rejection: the stdlib format string is interpolated
        # before logging, and a newline in it would forge a second entry.
        assert "\n" not in rejections[0].message
