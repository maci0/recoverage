"""Tests for recoverage.api — WSGI-level endpoint tests and unit tests for validation logic."""

from __future__ import annotations

import copy
import json
import logging
import os
import queue
import re
import threading
import time
import unicodedata
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from io import BytesIO
from operator import attrgetter
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar
from urllib.parse import quote
from wsgiref.util import setup_testing_defaults

import pytest
from conftest import (
    HAS_DB,
    decode_body,
    get_first_target,
    require_target,
    wsgi_get,
    wsgi_post,
    wsgi_request,
)
from coverage_fixture import cell, coverage_dir, write_coverage
from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError, load_coverage

from recoverage import api, webapp
from recoverage import server as _server

# Typer 0.27 help paints option names with ANSI even under CliRunner
# isolation on CI (FORCE_COLOR / a detected tty). Strip before matching
# flag text so the assertion is about the documented name, not the paint.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_NO_COLOR_ENV = {"NO_COLOR": "1", "FORCE_COLOR": None, "CLICOLOR_FORCE": None}

# time.tzset() is compiled in only where the platform has a C library
# time-zone API, so it does not exist on Windows.  The host-zone test below
# sets TZ and re-reads it, which is exactly what tzset does; without it there
# is no way to move the process into another zone.
HAS_TZSET = hasattr(time, "tzset")


class _CountingStream(BytesIO):
    """A ``wsgi.input`` that records whether anything read from it.

    A body handler that materializes the request body before applying its cap
    is invisible in a status-code assertion, because the refusal still comes
    out a 413. The reads counter is what tells the two apart.
    """

    reads = 0

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        type(self).reads += 1
        return super().read(size)

    def readline(self, size: int = -1) -> bytes:  # type: ignore[override]
        type(self).reads += 1
        return super().readline(size)


def _plain(text: str) -> str:
    return _ANSI_RE.sub("", text)


# ── Test-local coverage documents ──────────────────────────────────
#
# The suite used to build a throwaway SQLite database per fixture.  The
# dashboard reads rebrew's clear-text coverage documents now, so a fixture is a
# document written with coverage_fixture.write_coverage plus the one environment
# variable that points the server at it.


def _snapshot_mapping(
    root: Path, target: str, sections: dict[str, dict[str, Any]], **kwargs: Any
) -> dict[str, CoverageSnapshot]:
    """Write ``<root>/db/coverage-<target>.toml`` and return it as a mapping.

    The shape a patched ``server.load_all`` has to hand back, loaded
    through the real reader so the test asserts against what the server would
    have read.
    """
    write_coverage(coverage_dir(root), target, sections, **kwargs)
    return {target: load_coverage(root, target)}


def _alternating_reader(
    monkeypatch: pytest.MonkeyPatch, mappings: list[dict[str, CoverageSnapshot]]
) -> list[int]:
    """Patch ``server.load_all`` to hand back *mappings* in turn.

    The last mapping repeats once the list runs out, and the returned list
    records the index each call served.  An unchanged directory can never
    produce two different answers, so a response that mixed two reads shows up
    as fields from different builds; this is how a pin to one snapshot is
    observable from the response alone.
    """
    import recoverage.server as server_mod

    served: list[int] = []

    def _reader(_root: Path) -> dict[str, CoverageSnapshot]:
        index = min(len(served), len(mappings) - 1)
        served.append(index)
        return mappings[index]

    monkeypatch.setattr(server_mod, "load_all", _reader)
    return served


def assert_regen_accepted(result: tuple[str, dict[str, str], bytes]) -> None:
    """Assert an accepted /api/regen POST really reached the stubbed
    ``_do_regen``.

    A bare ``not status.startswith("403")`` also passes on a 404, a 405, a
    500 from an unrelated regression, or the 429 cooldown another test left
    behind, so it cannot tell "the guard let it through" from "the endpoint
    broke".  Every caller stubs ``_do_regen`` to answer ``{"ok": true}``, so
    that payload is the accepted response.
    """
    status, headers, body = result
    assert status.startswith("200"), status
    assert json.loads(decode_body(body, headers)) == {"ok": True}


# ── Regen origin validation (actual endpoint) ─────────────────────


class TestRegenErrorBodySanitized:
    """A failed regen must not echo the exception text: a rebrew or OSError
    message quotes absolute paths from the project tree."""

    def test_exception_message_stays_in_the_log(self, monkeypatch, caplog) -> None:
        import logging as _logging

        import recoverage.api as api

        def _boom(_root) -> None:
            raise OSError("/home/someone/private/workspace/src is unreadable")

        monkeypatch.setattr(api, "run_regen", _boom)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/tmp"))
        with caplog.at_level(_logging.ERROR, logger="recoverage"):
            response = api._do_regen("127.0.0.1")
        assert response.status_code == 500
        detail = json.loads(response.body)["detail"]
        assert "OSError" in detail
        assert "/home/someone/private" not in detail
        logged = [rec.getMessage() for rec in caplog.records]
        assert any("Regen failed" in msg and "/home/someone/private" in msg for msg in logged)


class TestRegenOriginValidation:
    """Test origin/remote_addr checks on the actual /api/regen endpoint."""

    @pytest.fixture(autouse=True)
    def _no_real_regen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Accepted requests must not run catalog/build-db: on a machine with
        rebrew installed, `pytest` would rebuild the developer's real DB."""
        import recoverage.api as api

        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))
        # The cooldown timestamp is a module global stamped by every accepted
        # POST, so without this the second accepted test in the file answers
        # 429 and the accepted-path assertion below fails on the shared state.
        monkeypatch.setattr(api, "_regen_last_attempt", None)

    def test_remote_addr_external_rejected(self) -> None:
        """Non-localhost REMOTE_ADDR should be rejected with 403."""
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="192.168.1.100")
        assert status.startswith("403")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Forbidden: localhost only"

    def test_remote_addr_localhost_accepted(self) -> None:
        """Localhost REMOTE_ADDR passes the remote check and runs the regen."""
        assert_regen_accepted(wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1"))

    def test_a_valid_token_does_not_buy_regen_from_a_remote_peer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The two principals are separate, and a credential is only one.

        A --allow-remote --token deployment hands the same bearer token to
        every reader on the network, so the regen gate has to keep refusing a
        non-loopback peer for a request that carries it.  The sibling tests
        run with no token configured at all, which leaves this cell of the
        matrix unpinned: a gate written as "authenticated OR local" would
        pass every one of them and serve a rebuild to anyone holding the
        share link.
        """
        import recoverage.server as server_mod

        monkeypatch.setattr(server_mod, "_AUTH_TOKEN", "unit-test-token")
        auth = {"Authorization": "Bearer unit-test-token"}

        status, headers, body = wsgi_request(
            "POST", "/api/regen", headers=auth, remote_addr="192.168.1.100"
        )
        assert status.startswith("403")
        assert json.loads(decode_body(body, headers))["error"] == "Forbidden: localhost only"

        # The same credential from the operator's own host is the other half
        # of the cell: refusing everything would be a broken gate, not a safe one.
        assert_regen_accepted(
            wsgi_request("POST", "/api/regen", headers=auth, remote_addr="127.0.0.1")
        )

    def test_cross_origin_rejected(self) -> None:
        """Cross-origin request should be rejected with 403."""
        status, headers, body = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://evil.com:8001"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Forbidden: cross-origin"

    @pytest.mark.parametrize(
        ("headers", "remote", "reason"),
        [
            ({}, "192.168.1.100", "not localhost"),
            ({"Origin": ""}, "127.0.0.1", "empty Origin"),
            ({"Origin": "http://evil.com:8001"}, "127.0.0.1", "cross-origin"),
            ({"Sec-Fetch-Site": "cross-site"}, "127.0.0.1", "cross-site request"),
        ],
    )
    def test_every_refusal_is_logged_and_counted(
        self,
        headers: dict[str, str],
        remote: str,
        reason: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A refused regen is the one event on this endpoint with no other trace.

        The request never enters the pipeline, so no regen lifecycle line is
        written and the per-request line is DEBUG unless it was slow: a
        cross-origin POST aimed at the one privileged operation left the log
        saying nothing at all.  Each arm writes a WARNING naming the reason
        and the peer, and counts a rejection so it shows up in /api/health
        beside the runs that did happen.
        """
        import logging

        from recoverage import metrics

        metrics.REGEN.reset()
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            status, _headers, _body = wsgi_request(
                "POST", "/api/regen", headers=headers, remote_addr=remote
            )
        assert status.startswith("403")
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("Refused POST /api/regen" in m and reason in m for m in warnings), warnings
        assert any("192.168.1.100" in m for m in warnings) == (remote == "192.168.1.100")
        assert metrics.REGEN.snapshot()["rejected"] == 1
        assert metrics.REGEN.snapshot()["runs"] == 0

    def test_localhost_origin_accepted(self) -> None:
        """The dashboard's own localhost page passes and runs the regen.

        The Host header travels with it: the WSGI harness defaults it to
        127.0.0.1, so a localhost:8001 Origin addressed at that Host is a
        cross-origin request, and is refused by the sibling test below.
        """
        assert_regen_accepted(
            wsgi_request(
                "POST",
                "/api/regen",
                headers={"Origin": "http://localhost:8001", "Host": "localhost:8001"},
                remote_addr="127.0.0.1",
            )
        )

    def test_evil_subdomain_rejected(self) -> None:
        """Origin like 127.0.0.1.evil.com must be rejected."""
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://127.0.0.1.evil.com"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")

    @pytest.mark.parametrize(
        "origin",
        [
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://localhost",
        ],
    )
    def test_other_loopback_origin_rejected(self, origin: str) -> None:
        """A page on another loopback port is a different origin, not the dashboard.

        It passes a hostname-is-loopback check and the browser cannot read the
        reply, so it would start a minutes-long rebuild the operator never
        asked for and never sees.
        """
        status, headers, body = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": origin, "Host": "localhost:8001"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")
        assert json.loads(decode_body(body, headers))["error"] == "Forbidden: cross-origin"

    @pytest.mark.parametrize(
        ("origin", "host"),
        [
            ("http://localhost:8001", "localhost:8001"),
            ("http://127.0.0.1:8001", "127.0.0.1:8001"),
            # The harness default: a page on 127.0.0.1 is the dashboard.
            ("http://127.0.0.1", "127.0.0.1"),
            # A default port is the same authority spelled two ways.
            ("http://box", "box:80"),
            # A TLS-terminating proxy changes the scheme, not the service.
            ("https://localhost:8001", "localhost:8001"),
        ],
    )
    def test_same_origin_accepted(self, origin: str, host: str) -> None:
        """The dashboard's own page drives the regen however the URL is spelled."""
        assert_regen_accepted(
            wsgi_request(
                "POST",
                "/api/regen",
                headers={"Origin": origin, "Host": host},
                remote_addr="127.0.0.1",
            )
        )

    def test_userinfo_origin_rejected(self) -> None:
        """An unparsable Origin is refused rather than normalized into a match."""
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://localhost:8001@evil.com", "Host": "localhost:8001"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")

    def test_empty_origin_rejected(self) -> None:
        """An Origin that arrived empty is not the header's absence.

        The same-origin check fails open on an absent Origin because every
        non-browser client omits it. Folding an empty one into the same case
        admits a privileged POST on the strength of the one header that should
        have named it, and no browser ever sends a blank Origin.
        """
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "", "Host": "localhost:8001"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")

    def test_absent_origin_still_accepted(self) -> None:
        """curl and scripts send no Origin at all, and are still served."""
        assert_regen_accepted(wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1"))

    def test_cross_site_fetch_metadata_rejected(self) -> None:
        """Sec-Fetch-Site: cross-site must be rejected even without an Origin.

        The Origin check fails open on absence (curl/scripts never send it);
        browsers always attach Sec-Fetch-Site, so a stripped-Origin cross-site
        form POST from a loopback browser still names itself here.
        """
        status, headers, body = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Sec-Fetch-Site": "cross-site"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Forbidden: cross-site request"

    @pytest.mark.parametrize("site", ["same-origin", "same-site", "none"])
    def test_same_site_fetch_metadata_accepted(self, site: str) -> None:
        """Non-cross-site Sec-Fetch-Site values pass (SPA reload button)."""
        assert_regen_accepted(
            wsgi_request(
                "POST",
                "/api/regen",
                headers={"Sec-Fetch-Site": site},
                remote_addr="127.0.0.1",
            )
        )

    def test_ipv6_loopback_remote_addr(self) -> None:
        """::1 REMOTE_ADDR is accepted and runs the regen."""
        assert_regen_accepted(wsgi_request("POST", "/api/regen", remote_addr="::1"))

    def test_ipv4_mapped_loopback_remote_addr_accepted(self) -> None:
        """::ffff:127.0.0.1 REMOTE_ADDR must pass the localhost-only guard.

        Dual-stack listeners (--bind :: on Linux keeps IPv4 accepted on the
        v6 socket) report IPv4 peers through the mapped spelling; a plain
        string comparison would 403 the operator's own browser on reload.
        """
        assert_regen_accepted(wsgi_request("POST", "/api/regen", remote_addr="::ffff:127.0.0.1"))

    @pytest.mark.parametrize(
        "remote_addr",
        [
            "::ffff:192.168.1.100",  # mapped EXTERNAL peer must stay rejected
            "::ffff:c0a8:164",  # same address in hex spelling — classify by value
            "not-an-ip",  # unparseable: reject, never crash
        ],
    )
    def test_ipv4_mapped_and_garbage_non_loopback_rejected(self, remote_addr: str) -> None:
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr=remote_addr)
        assert status.startswith("403")

    @pytest.mark.parametrize(
        "remote_addr",
        [
            "10.0.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "127.0.0.2",
        ],
    )
    def test_non_loopback_remote_addrs_rejected(self, remote_addr: str) -> None:
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr=remote_addr)
        assert status.startswith("403")


# ── API endpoint smoke tests ──────────────────────────────────────


class TestApiHealth:
    """Test /api/health returns valid JSON."""

    def test_health_returns_200(self) -> None:
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "version" in data
        assert "db" in data
        assert "extras" in data

    def test_health_has_security_headers(self) -> None:
        _status, headers, _ = wsgi_get("/api/health")
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"

    def test_health_content_type(self) -> None:
        _, headers, _ = wsgi_get("/api/health")
        assert "application/json" in headers.get("Content-Type", "")

    def test_health_targets_count_counts_the_documents(self) -> None:
        """targets_count counts built targets and nothing else.

        The SQLite schema kept a reserved metadata row carrying the format
        version; the document stamps its own version, so the count is exactly
        the set of targets the coverage directory holds — counting anything
        beside them would report more targets than the dropdown lists.
        """
        import recoverage.server as server_mod

        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        ids = server_mod.db_target_ids()
        assert ids, "fixture coverage directory has no built target"
        assert data["targets_count"] == len(ids)

    def test_health_degraded_when_db_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing coverage directory must be reported as degraded (with
        exists=false), not crash the endpoint or claim healthy."""
        import recoverage.api as api
        import recoverage.server as server_mod

        missing = Path("/nonexistent/coverage-dir")
        monkeypatch.setattr(api, "_db_path", lambda: missing)
        # The freshness probes read server's own binding, so the health answer
        # is only about a directory both halves of the read path agree on.
        monkeypatch.setattr(server_mod, "_db_path", lambda: missing)
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["status"] == "degraded"
        assert data["db"]["exists"] is False
        assert "mtime" not in data["db"]


class TestHealthActiveConfig:
    """/api/health reports the settings the RUNNING process resolved."""

    def test_reports_the_published_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.server as server_mod

        monkeypatch.setattr(
            server_mod,
            "ACTIVE_CONFIG",
            {
                "bind": "0.0.0.0",
                "port": "9000",
                "allow_remote": "true",
                "cors": "false",
                "cors_origin": "none",
                "db": "/srv/secret-project/db",
                "log_level": "WARNING",
                "token": "set",
            },
            raising=False,
        )
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["config"]["bind"] == "0.0.0.0"
        assert data["config"]["port"] == "9000"
        assert data["config"]["log_level"] == "WARNING"
        # The token is reported as set/unset, never by value.
        assert data["config"]["token"] == "set"
        # db is the basename-only block's business: the absolute path is not
        # published on a polled endpoint.
        assert "db" not in data["config"]
        assert "/srv/secret-project/db" not in decode_body(body, headers).decode()

    def test_no_config_before_serve_starts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A mounted WSGI app never resolved a configuration; null says that,
        where a re-resolved default would be a value nobody set."""
        import recoverage.server as server_mod

        monkeypatch.setattr(server_mod, "ACTIVE_CONFIG", None, raising=False)
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["config"] is None


@pytest.mark.skipif(not HAS_DB, reason="No coverage database")
class TestHealthDbMtime:
    """/api/health's freshness stamp names the newest coverage document.

    A rebuild rewrites one ``coverage-*.toml`` per target, so reading any single
    file would report a target that did not move; the stamp is the newest mtime
    across the directory's documents.  ``mtime_utc`` is the same instant with
    the offset spelled out, so a client never has to assume the host's zone.
    """

    @staticmethod
    def _point_at(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """A one-document coverage directory the health probe reads."""
        import recoverage.api as api
        import recoverage.server as server_mod

        directory = coverage_dir(tmp_path)
        write_coverage(
            directory,
            "FRESH",
            {".text": {"va": 0x1000, "size": 16, "cells": [cell(0x1000, 0x1010, "exact")]}},
        )
        monkeypatch.setattr(api, "_db_path", lambda: directory)
        monkeypatch.setattr(server_mod, "_db_path", lambda: directory)
        return directory

    def test_mtime_follows_the_newest_document(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        directory = self._point_at(tmp_path, monkeypatch)
        doc = directory / "coverage-FRESH.toml"
        old_ns = 1_700_000_000_000_000_000
        new_ns = old_ns + 90 * 1_000_000_000
        os.utime(doc, ns=(old_ns, old_ns))

        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))["db"]
        assert data["mtime"] == pytest.approx(old_ns / 1e9)
        assert data["mtime_utc"] == "2023-11-14T22:13:20+00:00"

        # A rebuild rewrites the documents: a second target written beside the
        # first must move the stamp, which is why the stamp cannot be one file's.
        os.utime(doc, ns=(new_ns, new_ns))
        other = write_coverage(
            directory,
            "OTHER",
            {".text": {"va": 0x2000, "size": 16, "cells": [cell(0x2000, 0x2010, "exact")]}},
        )
        os.utime(other, ns=(new_ns, new_ns))
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))["db"]
        assert data["mtime"] == pytest.approx(new_ns / 1e9)
        assert data["mtime_utc"] == "2023-11-14T22:14:50+00:00"
        assert data["mtime_utc"].endswith("+00:00")

    @pytest.mark.skipif(not HAS_TZSET, reason="no time.tzset() on this platform")
    def test_mtime_utc_is_utc_regardless_of_host_tz(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The same coverage stamp must render identically on a host in any zone:
        a server-local rendering would move the reported instant with TZ."""
        monkeypatch.setenv("TZ", "Asia/Tokyo")
        try:
            time.tzset()
            status, headers, body = wsgi_get("/api/health")
        finally:
            monkeypatch.delenv("TZ", raising=False)
            time.tzset()
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))["db"]
        assert data["mtime_utc"].endswith("+00:00")
        assert data["mtime_utc"] == datetime.fromtimestamp(data["mtime"], tz=UTC).isoformat()

    def test_mtime_and_mtime_utc_agree_to_the_microsecond(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The epoch float and the ISO stamp beside it are one instant.

        A float second cannot hold a nanosecond mtime, so converting the two
        fields independently let `mtime_utc` sit up to half a second off
        `mtime`; and fromtimestamp rounds, so a file stamped in the last
        microsecond of a second reported the next one — a rebuild announced
        before it happened.  Both fields now come from one truncating
        conversion, so a client that derives one from the other always agrees.
        """
        directory = self._point_at(tmp_path, monkeypatch)
        doc = directory / "coverage-FRESH.toml"
        # 2023-11-14T22:13:59.999999999Z, the last nanosecond of a second.
        ns = 1_700_000_039_999_999_999
        os.utime(doc, ns=(ns, ns))

        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))["db"]
        assert data["mtime_utc"] == "2023-11-14T22:13:59.999999+00:00"
        assert data["mtime_utc"] == datetime.fromtimestamp(data["mtime"], tz=UTC).isoformat()

    def test_an_mtime_outside_the_calendar_answers_rather_than_raising(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A file mtime past year 9999 is still a freshness stamp, not a 500.

        The mtime comes off the filesystem, so a restored tree, a bad RTC or
        a `touch -d` can carry a value `datetime` cannot represent.  Raising
        took the whole health probe down with it, which reports a perfectly
        readable coverage directory as a broken server; the probe has to
        answer, with the extreme stamp the clock can name.
        """
        directory = self._point_at(tmp_path, monkeypatch)
        doc = directory / "coverage-FRESH.toml"
        # 10000-01-01T00:00:00Z: representable to `os.utime`, not to datetime.
        unrepresentable_ns = 253_402_300_800 * 1_000_000_000
        os.utime(doc, ns=(unrepresentable_ns, unrepresentable_ns))
        if doc.stat().st_mtime_ns != unrepresentable_ns:
            # ext4 stores up to 2446 and APFS up to 2262, so the stamp never
            # reaches the server there; TestMtimeNsToUtc holds the clamp itself.
            pytest.skip("this filesystem clamps a year-10000 mtime on write")

        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))["db"]
        # Clamped to the last second datetime spans, not a traceback.
        assert data["mtime_utc"] == "9999-12-31T23:59:59+00:00"
        # Epoch arithmetic, not fromtimestamp: Windows' C runtime refuses year 9999.
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        assert data["mtime_utc"] == (epoch + timedelta(seconds=data["mtime"])).isoformat()


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiTargets:
    """Test /api/targets returns target list."""

    def test_targets_returns_200(self) -> None:
        status, headers, body = wsgi_get("/api/targets")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "targets" in data
        assert isinstance(data["targets"], list)

    def test_targets_revalidates_instead_of_resending(self) -> None:
        """The one request the SPA cannot avoid revalidates.

        The shell preloads `/api/targets` and `web/app/api.ts` fetches it with
        `cache: "no-cache"`, so it is asked on every page load.  Served
        `no-store` with no validator it was re-downloaded whole every time;
        a strong ETag turns the repeat into a 304 with no body.  `max-age`
        stays at zero, because this list changes under a running server."""
        status, headers, _ = wsgi_get("/api/targets")
        assert status.startswith("200")
        etag = _header(headers, "ETag")
        assert etag and etag.startswith('"') and etag.endswith('"')
        assert "no-store" not in _header(headers, "Cache-Control")
        status, headers, body = wsgi_get("/api/targets", headers={"If-None-Match": etag})
        assert status == "304 Not Modified"
        assert body == b""

    def test_targets_etag_moves_with_the_config(self) -> None:
        """A target added to `rebrew-project.toml` is visible before any build
        writes a document for it, so a tag over the coverage snapshot alone
        would answer 304 for a list that has changed.  The config's stat is
        the other half of the key `resolve_targets` merges."""
        from recoverage import api as api_mod

        before = _header(wsgi_get("/api/targets")[1], "ETag")
        real = api_mod.config_fingerprint
        try:
            api_mod.config_fingerprint = lambda root: (123, 456)  # type: ignore[assignment]
            moved = _header(wsgi_get("/api/targets")[1], "ETag")
        finally:
            api_mod.config_fingerprint = real  # type: ignore[assignment]
        assert moved != before
        assert real is not None


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiFunctions:
    """Test /api/targets/<target>/functions with sort validation."""

    def test_default_sort(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "functions" in data
        assert "total" in data

    def test_valid_sort_field(self) -> None:
        """A whitelisted sort field orders the payload it returns.

        The 200 alone proves nothing: an implementation that accepted
        `name:desc` and then ignored it answered identically. The synthetic
        DB seeds _func_a/_func_b/_func_c, so the descending order is exact.
        """
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?sort=name:desc&limit=50")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        names = [f["name"] for f in data["functions"]]
        assert names == ["_func_c", "_func_b", "_func_a"]
        assert names == sorted(names, reverse=True)
        assert data["total"] == 3

    def test_invalid_sort_field_is_a_400(self) -> None:
        """An unknown sort field is a rejected query, not a silent va-order page.

        The whitelist is still what refuses it, so the SQL-injection spelling
        gets the same answer a typo does, and the answer is the standard error
        envelope: `code` from the status mapping and a `detail` that names the
        columns the list does have.
        """
        target = require_target()
        for value in ("DROP TABLE functions", "vaStart", ":desc", "name:desc:extra"):
            status, headers, body = wsgi_get(f"/api/targets/{target}/functions?sort={quote(value)}")
            assert status.startswith("400"), value
            data = json.loads(decode_body(body, headers))
            assert data["code"] == "bad_request", value
            for column in api._ALLOWED_SORT:
                assert column in data["detail"], value

    def test_an_absent_or_empty_sort_is_the_default(self) -> None:
        """No preference is spelled by leaving the parameter out or empty."""
        target = require_target()
        pages = []
        for query in ("", "?sort=", "?sort=va", "?sort=va:asc", "?sort=va:ASC"):
            status, headers, body = wsgi_get(f"/api/targets/{target}/functions{query}")
            assert status.startswith("200"), query
            pages.append([fn["va"] for fn in json.loads(decode_body(body, headers))["functions"]])
        assert pages[0], "the fixture target holds no functions"
        assert all(page == pages[0] for page in pages)

    def test_pagination(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?limit=5&offset=0")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["limit"] == 5
        assert data["offset"] == 0
        assert len(data["functions"]) <= 5

    def test_count_and_page_share_one_read_snapshot(self, tmp_path: Path, monkeypatch: Any) -> None:
        """`total` and the page it paginates must come from ONE snapshot.

        They are two passes over the function list, and the documents are
        re-read per request: a `rebrew build-db` committing between them served
        a count from one build beside rows from the next (the SPA then
        paginates against a total the rows do not match).  The handler holds one
        frozen CoverageSnapshot; this makes the reader answer with a DIFFERENT
        mapping on every call and requires the response to describe one of them.
        """
        import recoverage.api as api

        first = _snapshot_mapping(
            tmp_path / "one",
            "GAME",
            {".text": {"va": 0x1000, "size": 16, "cells": [cell(0x1000, 0x1010, "exact")]}},
            functions=[
                {"va": va, "name": name, "vaStart": hex(va), "size": 16, "status": "EXACT"}
                for va, name in ((0x1000, "_a"), (0x1010, "_b"), (0x1020, "_c"))
            ],
        )
        second = _snapshot_mapping(
            tmp_path / "two",
            "GAME",
            {".text": {"va": 0x1000, "size": 16, "cells": [cell(0x1000, 0x1010, "exact")]}},
            functions=[{"va": 0x1000, "name": "_only", "vaStart": "0x1000", "size": 16}],
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(coverage_dir(tmp_path / "one")))
        _alternating_reader(monkeypatch, [first, second])
        api._clear_list_total_cache()

        status, headers, body = wsgi_get("/api/targets/GAME/functions?limit=5")
        assert status.startswith("200"), body
        data = json.loads(decode_body(body, headers))
        # `total` and the rows are two reads of the same list: a mixed answer
        # would report three functions with one row (or the reverse).
        assert (data["total"], [fn["name"] for fn in data["functions"]]) in (
            (3, ["_a", "_b", "_c"]),
            (1, ["_only"]),
        )

    @pytest.mark.parametrize(
        ("query", "field", "expected"),
        [
            ("limit=9999", "limit", 500),
            ("limit=abc", "limit", 50),
            ("limit=0", "limit", 1),
            ("offset=-10", "offset", 0),
        ],
        ids=[
            "limit-capped-at-500",
            "limit-invalid-defaults",
            "limit-zero-clamped",
            "offset-negative-clamped",
        ],
    )
    def test_paging_bounds_are_normalized(self, query: str, field: str, expected: int) -> None:
        """A paging value the endpoint cannot use is corrected, not refused.

        The four spellings are the ways a client gets the value wrong: past the
        cap, not a number, zero, and negative. Each is answered 200 with the
        field the server actually used.
        """
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?{query}")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data[field] == expected

    def test_status_filter_narrows_results(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?status=EXACT")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        # Synthetic DB: exactly one EXACT function (_func_a).
        assert [fn["name"] for fn in data["functions"]] == ["_func_a"]
        assert data["total"] == 1

    def test_unknown_status_is_rejected(self) -> None:
        """A status the DB cannot hold is a 400, not a silent empty page.

        The filter is a closed vocabulary (rebrew owns it), so a typo used to
        answer 200 with total 0 — indistinguishable from a target that has no
        functions of that status.
        """
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?status=EXACTX")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"
        assert "EXACT" in data["detail"]

    def test_every_known_status_is_accepted(self) -> None:
        """The guard rejects typos only: no status in the vocabulary 400s."""
        target = require_target()
        for value in sorted(api._FUNCTION_STATUSES):
            status, _, _ = wsgi_get(f"/api/targets/{target}/functions?status={value}")
            assert status.startswith("200"), f"{value} is in the vocabulary but was refused"

    def test_search_matches_name_substring(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?search=_func_b")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data["functions"]] == ["_func_b"]

    def test_a_unicode_space_is_a_search_term_not_an_empty_one(self) -> None:
        """`?search=` holding a non-breaking space is a term, not no filter.

        `str.strip` removed it, the query became the empty term, and the
        endpoint answered with every row: a search for a space returned the
        whole table.
        """
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?search=%C2%A0")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["total"] == 0
        assert data["functions"] == []

    def test_search_like_wildcards_match_literally(self) -> None:
        """% in the search must be escaped, not act as a LIKE wildcard —
        an unescaped pattern would return every row (or inject a pattern)."""
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?search=%25")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["total"] == 0
        assert data["functions"] == []


class TestFunctionStatusVocabulary:
    """The ?status= guard and rebrew's own vocabulary cannot drift.

    api._FUNCTION_STATUSES is built from rebrew at import time, so a rebrew
    that adds a status keeps it filterable. A rebrew that REMOVES one would
    leave this set advertising a value nothing stores, and the endpoint would
    accept a filter that can only ever be empty.
    """

    def test_matches_rebrew(self) -> None:
        from rebrew.workspace import KNOWN_STATUSES

        # The stored vocabulary plus the UNKNOWN default a catalog row falls
        # back to, which is the set the endpoint accepts and the document's
        # ``status`` field can carry.
        assert frozenset({*KNOWN_STATUSES, "UNKNOWN"}) == api._FUNCTION_STATUSES


# ── VA boundary validation (/asm endpoint) ─────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiAsmVaBoundaries:
    """handle_api_asm's VA window checks, exercised through the endpoint.

    Synthetic .text: va=0x10001000, size=0x1000, fileOffset=0x200 — chosen so
    the historical file_offset<0-only check MISSES the below-start case (the
    negative VA delta is smaller than fileOffset, so file_offset stays >= 0).
    """

    @pytest.fixture(autouse=True)
    def _capstone_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The guards run before any disassembly, so faking the capstone probe
        # gets us past the 501 short-circuit without the optional dependency.
        import recoverage.api as api

        monkeypatch.setattr(api, "capstone_unavailable_reason", lambda: None)

    @pytest.fixture
    def disassembly_sizes(self, monkeypatch: pytest.MonkeyPatch) -> list[int]:
        """A binary reaching past the section's last byte, and a disassembler
        that records the size it was handed.

        Opt-in rather than autouse: the guard tests below assert the 404 a
        request gets when the DLL is ABSENT, which is how they prove the guard
        let the request through. 0x200 + 0x1000 is the section's file range,
        so an unbounded slice has real bytes to read past the section end.
        """
        import recoverage.api as api

        seen: list[int] = []
        monkeypatch.setattr(api, "_load_dll", lambda target: bytes(0x200 + 0x1000))

        def record(va: int, size: int, file_offset: int, target: str) -> str:
            seen.append(size)
            return "disassembly"

        monkeypatch.setattr(api, "get_disassembly", record)
        return seen

    def _asm(self, target: str, query: str) -> tuple[str, dict[str, str], bytes]:
        return wsgi_get(f"/api/targets/{target}/asm?{query}")

    def test_va_below_start_with_positive_file_offset_rejected(self) -> None:
        """va=0x10000F80: delta -0x80 so file_offset=0x180 stays >= 0 — only
        the va < sec_va half catches this; disassembling bytes from before
        the section as if they were at va was the bug."""
        target = require_target()
        status, headers, body = self._asm(target, "va=0x10000F80&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is before section start"

    def test_negative_va_rejected(self) -> None:
        target = require_target()
        status, headers, body = self._asm(target, "va=-0x10&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is before section start"

    def test_va_at_exact_section_end_rejected(self) -> None:
        """VA equal to sec_va + sec_size is the first out-of-bounds address."""
        target = require_target()
        status, headers, body = self._asm(target, "va=0x10002000&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is beyond section end"

    def test_va_one_past_end_rejected(self) -> None:
        target = require_target()
        status, headers, body = self._asm(target, "va=0x10002001&size=16")
        assert status.startswith("400")
        # The message, not the 400: a guard that refused for the wrong
        # reason answers the same status code.
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is beyond section end"

    def test_va_far_beyond_end_rejected(self) -> None:
        target = require_target()
        status, headers, body = self._asm(target, "va=0xFFFFFFFF&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is beyond section end"

    def test_last_valid_va_passes_boundary_guard(self) -> None:
        """va = section end - 1 must NOT trip either boundary check; the
        request proceeds far enough to fail later on the missing DLL (404),
        which proves the guard accepted the final in-bounds address."""
        target = require_target()
        status, headers, body = self._asm(target, "va=0x10001FFF&size=1")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "DLL not found"

    def test_slice_running_past_the_section_end_is_clamped(
        self, disassembly_sizes: list[int]
    ) -> None:
        """The last in-bounds VA with a size that leaves the section.

        Only `va` was bounded, so this read the NEXT section's file bytes and
        disassembled them at this VA: the answer depended on where .text sat
        in the file. Clamped to the section rather than refused, because the
        SPA asks for a function's vaStart+size and a function ending on the
        section's last byte must still disassemble.
        """
        assert self._disassembled_size(disassembly_sizes, "va=0x10001FFF&size=2") == 1

    def test_slice_ending_exactly_on_the_section_end_is_untouched(
        self, disassembly_sizes: list[int]
    ) -> None:
        """va + size == sec_size is the last whole slice in the section; a
        clamp of `<` rather than `<=` would shave a byte off it."""
        assert self._disassembled_size(disassembly_sizes, "va=0x10001FF0&size=16") == 16

    def test_oversize_size_is_clamped_to_what_the_section_holds(
        self, disassembly_sizes: list[int]
    ) -> None:
        """`?size=` is capped at _MAX_SLICE_SIZE, but a 4096-byte ask at the
        head of a 0x1000 section leaves the section long before it reaches it;
        the section is the tighter of the two bounds and has to be the one
        applied."""
        assert self._disassembled_size(disassembly_sizes, "va=0x10001000&size=4096") == 0x1000

    def _disassembled_size(self, seen: list[int], query: str) -> int:
        """The size this query reached the disassembler, through the endpoint.

        The section ends inside the fake DLL, so an unbounded slice would read
        whatever followed it there; the recorded argument is the number under
        test, and the response is asserted so a request that never reached the
        disassembler cannot report 0 and pass.
        """
        target = require_target()
        seen.clear()
        status, headers, body = self._asm(target, query)
        assert status.startswith("200"), body
        data = json.loads(decode_body(body, headers))
        assert data["asm"] == "disassembly"
        assert len(seen) == 1
        return seen[0]

    def test_zero_size_still_rejected_at_boundary_class(self) -> None:
        """size clamps/validates before the VA checks: size=0 is its own 400.

        The second arm pairs the bad size with an UNPARSEABLE va, so the
        error it reports is the ordering itself: `size` is read and refused
        before `va` is resolved, and a handler that validated the address
        first answered "invalid va or size" here instead.
        """
        target = require_target()
        for query in ("va=0x10001000&size=0", "va=zzz&size=0"):
            status, headers, body = self._asm(target, query)
            assert status.startswith("400"), query
            data = json.loads(decode_body(body, headers))
            assert data["error"] == "size must be positive", query

    def test_decimal_va_spelling_accepted(self) -> None:
        """The SPA interpolates JS numbers into ?va= — decimal digits.

        268439648 is 0x10001060, inside .text: parsing those digits as base-16
        read an address orders of magnitude past the section and answered 400
        for every undocumented-block disassembly request.
        """
        target = require_target()
        status, headers, body = self._asm(target, "va=268439648&size=16")
        # Past the boundary guards and far enough to fail on the missing DLL.
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "DLL not found"

    def test_decimal_and_hex_spellings_agree(self) -> None:
        """The two spellings must name the same address, not merely fail alike.

        Equality of the status alone would be satisfied by both arms 500ing, so
        the comparison runs over the decoded payload and both are pinned to
        the resolved-then-404 answer `test_decimal_va_spelling_accepted`
        establishes for 0x10001000.
        """
        target = require_target()
        dec_status, dec_headers, dec_body = self._asm(target, "va=268439552&size=1")
        hex_status, hex_headers, hex_body = self._asm(target, "va=0x10001000&size=1")
        assert dec_status == hex_status == "404 Not Found", (dec_status, hex_status)
        assert dec_status.startswith("404")
        assert json.loads(decode_body(dec_body, dec_headers))["error"] == "DLL not found"
        assert decode_body(dec_body, dec_headers) == decode_body(hex_body, hex_headers)

    def test_bare_hex_legacy_caller_still_resolves(self) -> None:
        """All-digit '10001060': decimal spelling sits below section start, so
        the bare-hex fallback candidate must be the one resolved.

        A 404 on its own is the same answer a rejected query gives, so the
        error text is what separates "resolved, then the DLL is missing" from
        "no such VA".
        """
        target = require_target()
        status, headers, body = self._asm(target, "va=10001060&size=16")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "DLL not found"

    def test_unparseable_va_rejected(self) -> None:
        target = require_target()
        status, headers, body = self._asm(target, "va=zzz&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        # One envelope covers both parameters, so the detail is what says
        # which one was unparseable.
        assert data["error"] == "invalid va or size"
        assert "zzz" in data["detail"]


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiAsm:
    """Test /api/targets/<target>/asm request validation via actual endpoint."""

    @pytest.fixture(autouse=True)
    def _capstone_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The validation under test runs before any disassembly, so faking
        # the capstone probe gets us past the 501 short-circuit without the
        # optional dependency.
        import recoverage.api as api

        monkeypatch.setattr(api, "capstone_unavailable_reason", lambda: None)

    def test_missing_params_returns_400(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "missing va or size"

    def test_zero_size_returns_400(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000&size=0")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "size must be positive"

    def test_missing_binary_is_404_in_both_representations(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """?format= is a representation switch, not a different resource.

        A target with no configured original binary answers 404 for the text
        and the json form alike (and the same as /bytes).  The text form used
        to answer 422 "not enough bytes in DLL", which reads as "your address
        is past the end of the section" and sends the caller hunting in the
        wrong place when the operator simply has no binary configured.
        """
        import recoverage.api as api

        monkeypatch.setattr(api, "_load_dll", lambda target: None)
        target = require_target()
        for fmt in ("text", "json"):
            status, headers, body = wsgi_get(
                f"/api/targets/{target}/asm?va=0x10001000&size=16&format={fmt}"
            )
            assert status.startswith("404"), fmt
            data = json.loads(decode_body(body, headers))
            assert data["code"] == "not_found", fmt
            assert data["error"] == "DLL not found", fmt
            assert f"[targets.{target}].binary" in data["detail"], fmt


# ── Raw byte slices (/sections/<section>/bytes) ────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiBytes:
    """GET /api/targets/<t>/sections/<section>/bytes.

    Previously untested end to end: offset/size validation, section
    resolution, NULL-fileOffset (.bss-style) handling, missing-DLL 404s,
    and the hex/raw payload shape.
    """

    DLL_SIZE = 2048

    @pytest.fixture(autouse=True)
    def _fake_dll(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        # Deterministic fake binary large enough for .text's fileOffset
        # (0x200) plus a full clamp-size window.
        self.dll = bytes((i % 251) for i in range(self.DLL_SIZE))
        monkeypatch.setattr(api, "_load_dll", lambda target: self.dll)

    def _get(self, query: str, section: str = ".text") -> tuple[str, dict[str, str], bytes]:
        return wsgi_get(f"/api/targets/FAKEDLL/sections/{section}/bytes?{query}")

    def test_a_replaced_binary_revalidates_the_bytes_etag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A data-section edit leaves every document byte-identical, so the
        content token alone would answer 304 for bytes that changed."""
        import recoverage.server as srv

        binary = tmp_path / "game.dll"
        binary.write_bytes(self.dll)
        monkeypatch.setattr(srv, "_find_dll_path", lambda target: binary)
        status, headers, _ = self._get("offset=0&size=4")
        assert status.startswith("200")
        etag = _header(headers, "ETag")

        status, _, _ = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size=4",
            headers={"If-None-Match": etag},
        )
        assert status == "304 Not Modified"

        binary.write_bytes(self.dll + b"x")
        status, headers, _ = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size=4",
            headers={"If-None-Match": etag},
        )
        assert status.startswith("200")
        assert _header(headers, "ETag") != etag

    def _foreign_section_doc(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        definition: dict[str, Any],
    ) -> None:
        """Point the app at a one-section document whose section row carries an
        offset shape rebrew never writes (no VA, or a negative fileOffset)."""
        directory = coverage_dir(tmp_path)
        write_coverage(directory, "T", {name: {**definition, "cells": []}})
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

    def test_happy_path_serves_slice_as_hex_and_raw(self) -> None:
        status, headers, body = self._get("offset=0&size=16")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        expected = self.dll[0x200 : 0x200 + 16]
        assert data["raw"] == list(expected)
        assert data["offset"] == 0
        assert data["size"] == 16
        # Hex dump shape: offset column + hex bytes + ASCII gutter.
        first_line = data["hex"].splitlines()[0]
        assert first_line.startswith("00000000")
        assert " ".join(f"{b:02x}" for b in expected[:8]) in first_line

    def test_offset_slices_from_deep_in_the_dll(self) -> None:
        status, _, body = self._get("offset=8&size=4")
        assert status.startswith("200")
        data = json.loads(decode_body(body, {}))
        assert data["raw"] == list(self.dll[0x208 : 0x208 + 4])
        assert data["offset"] == 8

    @pytest.mark.parametrize(
        "query",
        [
            "offset=-1&size=4",
            "offset=abc&size=4",
            "size=abc",
            "offset=4096&size=4",  # >= section size (0x1000)
        ],
    )
    def test_bad_offset_or_size_400(self, query: str) -> None:
        status, headers, body = self._get(query)
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"

    def test_oversized_size_is_clamped_not_fatal(self) -> None:
        """An over-long ?size= clamps, it does not truncate to whatever a
        smaller cap would give: `<= 4096` is satisfied by a clamp to 0, so
        the exact window is the contract. `.text` starts at fileOffset 0x200
        in a 2048-byte fake binary, so 1536 bytes are the most that exist
        even though the request and the cap both ask for more."""
        status, _, body = self._get("offset=0&size=999999")
        assert status.startswith("200")
        data = json.loads(decode_body(body, {}))
        assert data["size"] == self.DLL_SIZE - 0x200
        assert data["size"] <= 4096
        assert len(data["raw"]) == data["size"]

    def test_unknown_section_404(self) -> None:
        status, headers, body = self._get("offset=0&size=4", section=".nosuch")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "not_found"
        assert ".nosuch" in data["detail"]

    def test_null_file_offset_returns_422(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A .bss-style section (no VA, no file extent) has nothing on disk to
        slice: the endpoint must answer its JSON 422 contract instead of a
        TypeError 500 from the pointer arithmetic.

        The document stores both absences as ``""``, which rebrew's reader
        keeps as ``None``. A stored 0 is a REAL file offset — a section that
        starts at the beginning of the file — and must not be read as absence,
        so this test writes no ``fileOffset`` key at all.
        """
        self._foreign_section_doc(tmp_path, monkeypatch, ".bss", {"size": 0, "unitBytes": 16})
        status, headers, body = wsgi_get("/api/targets/T/sections/.bss/bytes?offset=0&size=4")
        assert status.startswith("422"), body
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "section has no file backing"

    def test_missing_dll_is_404_with_config_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "_load_dll", lambda target: None)
        status, headers, body = self._get("offset=0&size=4")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert "DLL not found" in data["error"]
        # The unconfigured-target hint tells the operator exactly what to add.
        assert "[targets.FAKEDLL].binary" in data["detail"]

    def test_negative_file_offset_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A foreign document whose section carries a negative fileOffset (a
        rebrew-built one cannot: the writer clamps it >= 0) must get the 400
        contract instead of Python's negative-index slicing silently serving
        tail-of-binary bytes — same guard as /asm.

        The refusal names the offset it refused, like the two bounds refusals
        beside it: an `error` with an empty `detail` is the one answer here a
        caller cannot act on, and the actionable part is the number.
        """
        self._foreign_section_doc(
            tmp_path,
            monkeypatch,
            ".text",
            {"va": 4096, "size": 4096, "fileOffset": -4096, "unitBytes": 16, "columns": 8},
        )
        status, headers, body = wsgi_get("/api/targets/T/sections/.text/bytes?offset=8&size=4")
        assert status.startswith("400"), body
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"
        assert data["error"] == "offset beyond section bounds"
        assert data["detail"], "a refusal with no reason is not actionable"


class TestRegenRateLimit:
    """Server-side cooldown on /api/regen (the UI throttles, the API must too)."""

    def teardown_method(self) -> None:
        import recoverage.api as api

        # Accepted POSTs stamp the module-global cooldown; reset so later
        # tests (and re-runs) start from a neutral state.
        api._regen_last_attempt = None

    def _no_real_regen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))

    def test_rapid_second_call_rate_limited(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_real_regen(monkeypatch)
        import recoverage.api as api

        api._regen_last_attempt = None
        # First call passes the cooldown gate (the patched _do_regen answers
        # 200 — the timestamp is stamped before it runs).
        assert_regen_accepted(wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1"))

        # Immediate second call within the cooldown window → 429.
        status2, headers2, body2 = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        assert status2.startswith("429")
        data = json.loads(decode_body(body2, headers2))
        assert data["error"].startswith("Rate limited")
        assert data["retry_after"] >= 0

    def test_cooldown_expires(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """After the window elapses the endpoint accepts again."""
        import recoverage.api as api

        self._no_real_regen(monkeypatch)
        # Backdate the last attempt past the cooldown window (monkeypatch
        # restores the original global after the test).
        monkeypatch.setattr(
            api,
            "_regen_last_attempt",
            api.clock.monotonic() - api._REGEN_COOLDOWN_SECONDS - 1,
        )
        assert_regen_accepted(wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1"))

    def test_first_call_after_boot_not_rate_limited(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The first POST is accepted even when the monotonic clock is young.

        time.monotonic() counts from boot on Linux, so on a host that came up
        seconds ago the first regen would read as "inside the cooldown" if the
        never-attempted state were 0.0 instead of None.
        """
        import recoverage.api as api

        self._no_real_regen(monkeypatch)
        monkeypatch.setattr(api, "_regen_last_attempt", None)
        monkeypatch.setattr(api.clock, "monotonic", lambda: 1.0)
        assert_regen_accepted(wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1"))


class TestRegenFailureMapping:
    """_do_regen maps in-process rebrew failures to the JSON 500 contract.

    There is no timeout any more, so the ``RegenError`` that ``run_regen``
    raises for rebrew's ``error_exit`` is a failure, never a 504.
    """

    def teardown_method(self) -> None:
        import recoverage.api as api

        api._regen_last_attempt = None

    def _post_regen(self, monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> Any:
        import recoverage.api as api

        def boom(root: Path) -> None:
            raise exc

        # Patch the name api.py bound, and pin _project_dir so the test never
        # touches the real workspace.
        monkeypatch.setattr(api, "run_regen", boom)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        api._regen_last_attempt = None
        return wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")

    def test_rebrew_error_exit_is_500_not_504(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recoverage.regen import RegenError

        status, headers, body = self._post_regen(monkeypatch, RegenError(2))
        assert status.startswith("500")
        data = json.loads(decode_body(body, headers))
        assert data["detail"] == "rebrew exited with status 2"

    def test_missing_rebrew_is_500(self, monkeypatch: pytest.MonkeyPatch) -> None:
        status, headers, body = self._post_regen(monkeypatch, ImportError("rebrew is required"))
        assert status.startswith("500")
        data = json.loads(decode_body(body, headers))
        assert "ImportError" in data["detail"]
        # The message itself stays out of the body: it can name absolute paths
        # in the project tree.  The log line keeps it.
        assert "rebrew is required" not in data["detail"]

    def test_ordinary_rebrew_exception_is_500(self, monkeypatch: pytest.MonkeyPatch) -> None:
        status, headers, body = self._post_regen(monkeypatch, ValueError("corrupt JSON"))
        assert status.startswith("500")
        data = json.loads(decode_body(body, headers))
        assert data["detail"].startswith("ValueError")
        assert "corrupt JSON" not in data["detail"]

    def test_failed_regen_still_invalidates_derived_caches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """build_db can replace coverage.db and THEN fail, so the caches
        repopulated while the run was in flight describe a file the server no
        longer has.  The post-run invalidation must not be the success path's
        privilege."""
        import recoverage.api as api

        cleared: list[str] = []
        monkeypatch.setattr(
            api, "_clear_derived_caches_logged", lambda where: cleared.append(where)
        )
        self._post_regen(monkeypatch, ValueError("corrupt JSON"))
        assert "after regen" in cleared

    def test_a_regen_running_in_another_process_is_the_same_429(self, monkeypatch) -> None:
        """A duplicate this process cannot see still gets the answer a client
        already handles.

        `_REGEN_LOCK` and the idempotency ledger live in this process's memory,
        so a `recoverage regen` at another terminal is a duplicate run neither
        can dedup. `run_regen` refuses it and this endpoint has to answer with
        the shape the in-process lock already sends, not with a 500: the
        pipeline did not break, the work is simply already under way, and a
        reader who sees "Regen failed" presses the button again.
        """
        import recoverage.api as api
        from recoverage.regen import RegenBusyError

        before = api._metrics.REGEN.snapshot()
        status, headers, body = self._post_regen(
            monkeypatch, RegenBusyError("another regen is already writing /p/db")
        )
        assert status.startswith("429")
        assert headers.get("Retry-After") == str(int(api._REGEN_COOLDOWN_SECONDS))
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Rate limited: regeneration already running"
        assert data["code"] == "rate_limited"
        assert "already writing" in data["detail"]
        after = api._metrics.REGEN.snapshot()
        # A refusal, not a pipeline that broke, and the gauge the health
        # endpoint reads is back where it was.  Nothing was written and
        # nothing raised past the lock, so `failures` (the count of runs that
        # RAN and failed) stays put; the run is counted as the rejection it
        # is.  Filing it under `failures` put a red "Regen failed" on the one
        # line that means the pipeline broke every time a cron job overlapped
        # a dashboard's own regenerate.
        assert after["failures"] - before["failures"] == 0
        assert after["rejected"] - before["rejected"] == 1
        assert after["in_flight"] == before["in_flight"]
        assert after["last_ok"] is None


class TestRegenIdempotencyKey:
    """POST /api/regen dedups a retry that carries a completed key.

    A regen is convergent, so a duplicate is not corruption, but it is a
    second full catalog+build-db run. The key is what makes a retry (proxy
    replay, a lost response) cost a lookup instead.
    """

    def setup_method(self) -> None:
        import recoverage.api as api

        api._regen_last_attempt = 0.0
        api._REGEN_COMPLETED_KEYS.clear()
        api._REGEN_ACTIVE_KEYS.clear()

    teardown_method = setup_method

    def _counting_regen(self, monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> list[Path]:
        import recoverage.api as api

        runs: list[Path] = []

        def run(root: Path) -> None:
            runs.append(root)
            if fail:
                raise ValueError("corrupt JSON")

        monkeypatch.setattr(api, "run_regen", run)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        return runs

    def _blocking_regen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[list[Path], threading.Event, threading.Event]:
        """A regen that parks in `run_regen` until the test releases it.

        Returns the run list, the event `run` sets on entry, and the one that
        releases it. The caller waits for `started` before asserting anything
        about the state a run in flight leaves behind.
        """
        import recoverage.api as api

        runs: list[Path] = []
        started = threading.Event()
        release = threading.Event()

        def run(root: Path) -> None:
            runs.append(root)
            started.set()
            assert release.wait(timeout=10), "test never released the regen"

        monkeypatch.setattr(api, "run_regen", run)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        return runs, started, release

    def _post(self, key: str | None = None) -> tuple[str, dict[str, str], bytes]:
        headers = {"Idempotency-Key": key} if key else None
        return wsgi_request("POST", "/api/regen", headers, remote_addr="127.0.0.1")

    def test_retry_with_a_completed_key_does_not_rerun(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runs = self._counting_regen(monkeypatch)

        assert_regen_accepted(self._post("click-1"))
        # Same key, and inside the cooldown window a second run would 429 on.
        status, headers, body = self._post("click-1")

        assert status.startswith("200")
        assert json.loads(decode_body(body, headers)) == {"ok": True}
        assert headers.get("Idempotent-Replay") == "true"
        assert len(runs) == 1

    def test_a_duplicate_arriving_mid_run_is_told_it_is_still_running(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same key arriving while its run is in flight must not start a
        second pipeline, and must not be answered as a completed replay either:
        nothing has finished.  It is answered 202 with ``in_progress``, which is
        the state the client has to act on, where a 429 reads as a failed
        regenerate and sends the reader back to the button for a second run.
        """
        import recoverage.api as api

        runs, started, release = self._blocking_regen(monkeypatch)

        first: list[Any] = []
        worker = threading.Thread(target=lambda: first.append(self._post("click-1")))
        worker.start()
        assert started.wait(timeout=10), "first regen never reached run_regen"

        # Backdate the cooldown so it cannot be what answers the duplicate: the
        # in-flight key is read before the throttle, exactly as the completed
        # ledger is.
        monkeypatch.setattr(
            api,
            "_regen_last_attempt",
            api.clock.monotonic() - api._REGEN_COOLDOWN_SECONDS - 1,
        )
        status, headers, body = self._post("click-1")
        assert status.startswith("202")
        payload = json.loads(decode_body(body, headers))
        assert payload == {"ok": True, "in_progress": True}
        assert headers.get("Idempotent-Replay") == "in-progress"
        assert len(runs) == 1
        assert not api._regen_replayed("click-1")

        release.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
        assert first[0][0].startswith("200")
        assert len(runs) == 1

        # The retry once the first run completed replays it.  It lands inside
        # the cooldown window, so answering 200 at all proves the ledger was
        # consulted before the throttle.
        status, headers, body = self._post("click-1")
        assert status.startswith("200")
        assert headers.get("Idempotent-Replay") == "true"
        assert json.loads(decode_body(body, headers)) == {"ok": True}
        assert len(runs) == 1
        # The run ended, so the key is no longer the run in flight: a marker
        # left behind would answer every later request 202 with nothing behind
        # it, and a second POST with it would never start a run again.
        assert not api._regen_in_progress("click-1")

    def test_a_duplicate_whose_first_ledger_read_raced_the_completion(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A retry that read the ledger too early must not re-run the pipeline.

        The handler reads the key before taking the lock, so a duplicate whose
        predecessor was still running sees no ledger entry and arrives after it
        released.  The cooldown cannot catch it: it counts from the previous
        run's START, and a regen runs for minutes.  The ledger is read again
        under the lock, where the claim becomes atomic with the run.
        """
        import recoverage.api as api

        runs = self._counting_regen(monkeypatch)
        assert_regen_accepted(self._post("click-1"))
        assert len(runs) == 1

        # The duplicate, whose own read of the ledger landed while the
        # predecessor was still running and so saw nothing.
        real_replayed = api._regen_replayed
        reads: list[str] = []

        def replayed(key: str) -> bool:
            reads.append(key)
            return False if len(reads) == 1 else real_replayed(key)

        monkeypatch.setattr(api, "_regen_replayed", replayed)
        api._regen_last_attempt = 0.0
        status, headers, body = self._post("click-1")
        assert status.startswith("200")
        assert headers.get("Idempotent-Replay") == "true"
        assert json.loads(decode_body(body, headers)) == {"ok": True}
        assert len(reads) >= 2, "the ledger was read once, so no claim was made under the lock"
        assert len(runs) == 1

    def test_a_duplicate_racing_its_own_predecessor_is_answered_in_progress(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two requests with ONE key arriving together: the loser is a retry.

        The in-flight read happens before the lock is taken, so a duplicate sent
        in the same instant as the request it retries sees no marker and comes
        up against the held _REGEN_LOCK.  Answering 429 there is the failure the
        202 exists to prevent: the SPA reads it as a failed regenerate, mints a
        NEW key and pays for a second full pipeline.  The marker is read again
        on the far side of the failed acquire, so the duplicate is absorbed.
        """
        import recoverage.api as api

        runs, started, release = self._blocking_regen(monkeypatch)

        # The duplicate's read of the in-flight map lands before the
        # predecessor has recorded its key, which is the race being pinned.
        # Only the reads that happen once the first run is under way are
        # affected: the first read after that point is the duplicate's, the
        # one before the lock is taken, and the second is the re-read on the
        # far side of the failed acquire.
        real_in_progress = api._regen_in_progress
        reads: list[str] = []

        def in_progress(key: str) -> bool:
            if not started.is_set():
                return real_in_progress(key)
            reads.append(key)
            return False if len(reads) == 1 else real_in_progress(key)

        monkeypatch.setattr(api, "_regen_in_progress", in_progress)
        monkeypatch.setattr(
            api,
            "_regen_last_attempt",
            api.clock.monotonic() - api._REGEN_COOLDOWN_SECONDS - 1,
        )

        first: list[Any] = []
        worker = threading.Thread(target=lambda: first.append(self._post("click-1")))
        worker.start()
        assert started.wait(timeout=10), "first regen never reached run_regen"

        status, headers, body = self._post("click-1")
        assert status.startswith("202")
        assert json.loads(decode_body(body, headers)) == {"ok": True, "in_progress": True}
        assert headers.get("Idempotent-Replay") == "in-progress"
        assert len(reads) >= 2, "the marker was read once, so nothing was re-read on the lock"
        assert len(runs) == 1

        release.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
        assert first[0][0].startswith("200")
        assert len(runs) == 1

    def test_another_key_mid_run_is_still_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The 202 names the run in flight, so a DIFFERENT key keeps the 429.

        A second regenerate during a run is somebody's second regenerate, not a
        retry of the first, and it must not be answered as though its work were
        under way.
        """
        import recoverage.api as api

        runs, started, release = self._blocking_regen(monkeypatch)

        first: list[Any] = []
        worker = threading.Thread(target=lambda: first.append(self._post("click-1")))
        worker.start()
        assert started.wait(timeout=10), "first regen never reached run_regen"
        monkeypatch.setattr(
            api,
            "_regen_last_attempt",
            api.clock.monotonic() - api._REGEN_COOLDOWN_SECONDS - 1,
        )

        status, headers, body = self._post("click-2")
        assert status.startswith("429")
        assert json.loads(decode_body(body, headers))["code"] == "rate_limited"
        assert len(runs) == 1

        release.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
        assert len(runs) == 1

    def test_a_failed_run_frees_the_key_for_a_real_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A run that ends is over in progress too.

        A marker left set by a failure would answer the client's re-send 202
        for a pipeline that stopped, and the retry that should have re-run it
        would never run it again.
        """
        import recoverage.api as api

        self._counting_regen(monkeypatch, fail=True)
        status, _, _ = self._post("click-1")
        assert status.startswith("500")
        assert not api._regen_in_progress("click-1")

        api._regen_last_attempt = 0.0
        status, _, _ = self._post("click-1")
        assert status.startswith("500")

    def test_the_in_flight_markers_are_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Markers past the retention window expire on their own.

        A run abandoned by a dead process would otherwise hold its key for the
        life of the server, answering every later request 202 with nothing
        behind it.
        """
        import recoverage.api as api

        now = [api.clock.monotonic()]
        monkeypatch.setattr(api.clock, "monotonic", lambda: now[0])
        for i in range(api._REGEN_LEDGER_MAX_ENTRIES + 5):
            api._record_active_key(f"click-{i}")
        assert len(api._REGEN_ACTIVE_KEYS) <= api._REGEN_LEDGER_MAX_ENTRIES

        now[0] += api._REGEN_KEY_TTL_SECONDS + 1
        assert not api._regen_in_progress("click-0")
        assert api._REGEN_ACTIVE_KEYS == {}

    def test_a_fresh_key_reruns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        runs = self._counting_regen(monkeypatch)
        assert_regen_accepted(self._post("click-1"))
        api._regen_last_attempt = 0.0
        assert_regen_accepted(self._post("click-2"))

        assert len(runs) == 2

    def test_a_failed_run_is_not_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        runs = self._counting_regen(monkeypatch, fail=True)
        status, _, _ = self._post("click-1")
        assert status.startswith("500")

        # The retry must attempt the run again, not replay the failure.
        api._regen_last_attempt = 0.0
        status, _, _ = self._post("click-1")
        assert status.startswith("500")
        assert len(runs) == 2

    def test_malformed_key_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runs = self._counting_regen(monkeypatch)

        status, headers, body = self._post("not a valid key")

        assert status.startswith("400")
        assert json.loads(decode_body(body, headers))["code"] == "bad_request"
        assert runs == []

    def test_ledger_is_bounded_by_age_and_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        self._counting_regen(monkeypatch)
        for i in range(api._REGEN_LEDGER_MAX_ENTRIES + 5):
            api._regen_last_attempt = 0.0
            assert_regen_accepted(self._post(f"click-{i}"))
        assert len(api._REGEN_COMPLETED_KEYS) <= api._REGEN_LEDGER_MAX_ENTRIES

        # Every key is older than the retention window, so none may answer.
        real_now = time.monotonic()
        monkeypatch.setattr(
            api.clock, "monotonic", lambda: real_now + api._REGEN_KEY_TTL_SECONDS + 1
        )
        assert not api._regen_replayed("click-0")
        assert api._REGEN_COMPLETED_KEYS == {}

    def test_the_count_cap_never_shortens_the_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A key survives its whole window under the busiest client the cooldown allows.

        The count backstop exists to bound memory, not to retire keys early:
        if it held fewer slots than the cooldown admits completions inside one
        retention window, a client that regenerates often enough would lose an
        unexpired key and pay a second pipeline run for the retry the ledger
        exists to absorb.
        """
        import recoverage.api as api

        self._counting_regen(monkeypatch)
        completions = int(api._REGEN_KEY_TTL_SECONDS // api._REGEN_COOLDOWN_SECONDS) + 1
        assert completions <= api._REGEN_LEDGER_MAX_ENTRIES, (
            "the count cap would evict a key that is still inside its window"
        )

        for i in range(completions):
            api._regen_last_attempt = 0.0
            assert_regen_accepted(self._post(f"click-{i}"))

        assert len(api._REGEN_COMPLETED_KEYS) == completions
        assert api._regen_replayed("click-0")


class TestServeBindFlag:
    def test_bind_option_help(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--help"], env=_NO_COLOR_ENV)
        assert result.exit_code == 0
        help_text = _plain(result.output)
        assert "--bind" in help_text
        assert "127.0.0.1" in help_text


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestLastVerify:
    """/functions/<va> attaches the last `rebrew verify -o` record.

    Guarded like every other DB-backed class here: the assertions name
    synthetic-fixture addresses (0x10001000), so inside a real rebrew
    workspace they would be checked against unrelated project data.
    """

    def test_function_detail_includes_last_verify(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0x10001000")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["last_verify"]["byte_delta"] == 0
        assert "verified_at" in data["last_verify"]

    def test_function_detail_accepts_decimal_va(self) -> None:
        """The /functions list emits va as a decimal int — taking that value
        straight into the detail route must not 404 (round-trip contract)."""
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0x10001000")
        assert status.startswith("200")
        hex_data = json.loads(decode_body(body, headers))
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/{hex_data['va']}")
        assert status.startswith("200")
        # The 200 alone is half the contract: a reader that parsed the decimal
        # as 0 and then resolved *something* answered identically. The two
        # spellings of one VA must return the same function.
        assert json.loads(decode_body(body, headers)) == hex_data
        assert hex_data["name"] == "_func_a"

    def test_function_without_verify_record_omits_field(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0x10001030")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "last_verify" not in data


def test_an_unmeasured_verify_figure_is_served_as_null() -> None:
    """A verify record writes "" for a figure it did not measure; served as-is,
    the SPA and Potato Mode both drew a labelled row with no value."""
    from recoverage.server import verify_payload

    payload = verify_payload(
        {"verified_at": "", "byte_delta": 0, "diff_lines": "", "similarity": "", "reg_delta": ""}
    )
    assert payload == {
        "verified_at": None,
        "byte_delta": 0,
        "diff_lines": None,
        "similarity": None,
        "reg_delta": None,
        "effective_match": None,
    }


def test_a_verify_count_served_as_a_string_is_null_not_a_figure() -> None:
    """rebrew stores verify rows raw, so a count can reach the wire as a string.

    ``web/app/api.ts`` declares byte_delta/diff_lines/reg_delta ``number | null``
    and ``CoveragePanel`` calls ``count()`` on them, and Potato Mode appends
    "B" -- so a string served as a count rendered as ``"nan"`` in the SPA and
    ``nanB`` in the panel, and a numeric string read as ``8,730`` there against
    ``87.3`` here.  Similarity is left alone: it is a fraction a caller may
    store as a string, and the renderers scale it.
    """
    from recoverage.server import verify_payload

    payload = verify_payload(
        {
            "verified_at": "2026-01-01T00:00:00+00:00",
            "byte_delta": "nan",
            "diff_lines": float("nan"),
            "similarity": "87.3",
            "reg_delta": float("inf"),
            "effective_match": True,
        }
    )
    assert payload["byte_delta"] is None
    assert payload["diff_lines"] is None
    assert payload["reg_delta"] is None
    # A caller may legitimately store the fraction as a string; that one is scaled
    # by the renderer and is not this coercion's business.
    assert payload["similarity"] == "87.3"

    # A real count still reads as the number it is, 0 and 0.0 included, and a
    # bool (which is an int in Python, and is not a count) does not.
    real = verify_payload(
        {"verified_at": "", "byte_delta": 0, "diff_lines": 2.5, "similarity": 0.0, "reg_delta": 1}
    )
    assert real["byte_delta"] == 0
    assert real["diff_lines"] == 2.5
    assert real["reg_delta"] == 1
    assert isinstance(real["byte_delta"], int)
    # A bool is an int in Python, and is not a count.
    bool_row = verify_payload(
        {"verified_at": "", "byte_delta": True, "diff_lines": 0, "similarity": 0.0, "reg_delta": 0}
    )
    assert bool_row["byte_delta"] is None


# ── SSE live reload (/api/events) ─────────────────────────────────


def wsgi_stream(path: str, max_chunks: int = 1) -> tuple[str, dict[str, str], list[bytes], Any]:
    """Call the app directly against /api/events and iterate up to max_chunks.

    Returns (status, headers, chunks, result_iter).  The caller must
    ``close()`` the returned iterator to simulate client disconnect — the
    regular ``wsgi_get`` helper cannot be used here because the stream never
    ends on its own.
    """
    environ: dict[str, Any] = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = "GET"
    environ["PATH_INFO"] = path
    environ["QUERY_STRING"] = ""
    environ["REMOTE_ADDR"] = "127.0.0.1"
    environ["wsgi.input"] = BytesIO(b"")
    environ["CONTENT_LENGTH"] = "0"

    status_holder: dict[str, str | dict[str, str]] = {"status": "", "headers": {}}

    def _start_response(status: str, response_headers, exc_info=None) -> None:
        status_holder["status"] = status
        status_holder["headers"] = dict(response_headers)

    from recoverage.webapp import app

    result = app(environ, _start_response)
    chunks: list[bytes] = []
    for chunk in result:
        chunks.append(chunk)
        if len(chunks) >= max_chunks:
            break
    return str(status_holder["status"]), dict(status_holder["headers"]), chunks, result


class TestSseEvents:
    """SSE stream endpoint, broadcast frames, and disconnect cleanup."""

    def test_stream_headers_and_initial_comment(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            status, headers, chunks, result = wsgi_stream("/api/events", max_chunks=1)
            assert status.startswith("200")
            assert headers["Content-Type"] == "text/event-stream"
            assert headers["Cache-Control"] == "no-cache, no-store, must-revalidate"
            assert chunks == [b": connected\n\n"]
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()

    def test_stream_registers_and_unregisters_client(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            _, _, _, result = wsgi_stream("/api/events", max_chunks=1)
            assert len(api._SSE_CLIENTS) == 1
            result.close()  # client disconnect → generator finally
            assert len(api._SSE_CLIENTS) == 0
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()

    def test_stream_releases_client_on_abrupt_socket_teardown(self) -> None:
        """Drive the real wsgiref request path with a socket that dies
        mid-stream: finish_response must still close the app iterable when
        writes fail, so the client queue is released deterministically.
        A slot that leaked per vanished client would permanently erode the
        _SSE_MAX_CLIENTS cap until restart."""
        from io import StringIO
        from wsgiref.simple_server import ServerHandler

        import recoverage.api as api
        from recoverage.webapp import app

        class DyingSocket:
            """A wfile whose writes fail like a vanished client's."""

            def write(self, data: bytes) -> int:
                raise BrokenPipeError(32, "Broken pipe")

            def flush(self) -> None:
                return None

        api._stop_db_watcher()
        environ: dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ["REQUEST_METHOD"] = "GET"
        environ["PATH_INFO"] = "/api/events"
        environ["QUERY_STRING"] = ""
        environ["REMOTE_ADDR"] = "127.0.0.1"

        # Streaming had started (200 + headers sent) when the write fails;
        # run() must swallow the connection error like the threaded server
        # does and the registry must come back out clean.
        handler = ServerHandler(BytesIO(b""), DyingSocket(), StringIO(), environ)
        handler.run(app)
        assert handler.status == "200 OK"
        assert len(api._SSE_CLIENTS) == 0
        api._stop_db_watcher()

    def test_stream_releases_client_when_never_iterated(self) -> None:
        """A server may close the app iterable without iterating it (the peer
        hangs up between the handler returning and the first write).  The
        client queue is registered before that point, so a generator-only
        finally would skip and leak a slot, an fd and a thread for good."""
        from io import BytesIO
        from wsgiref.util import setup_testing_defaults

        import recoverage.api as api
        from recoverage.webapp import app

        api._stop_db_watcher()
        environ: dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ["REQUEST_METHOD"] = "GET"
        environ["PATH_INFO"] = "/api/events"
        environ["QUERY_STRING"] = ""
        environ["REMOTE_ADDR"] = "127.0.0.1"
        environ["wsgi.input"] = BytesIO(b"")
        environ["CONTENT_LENGTH"] = "0"

        def _start_response(status: str, response_headers, exc_info=None) -> None:
            return None

        try:
            result = app(environ, _start_response)
            assert len(api._SSE_CLIENTS) == 1
            result.close()
            assert len(api._SSE_CLIENTS) == 0
            result.close()  # idempotent: a second close must not raise
            assert len(api._SSE_CLIENTS) == 0
        finally:
            api._stop_db_watcher()

    def test_stream_delivers_db_updated_frame(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            _, _, chunks, result = wsgi_stream("/api/events", max_chunks=1)
            assert chunks == [b": connected\n\n"]
            api._broadcast_db_updated((123456789, 1024))
            frame = next(iter(result))
            assert frame.startswith(b"event: db-updated\n")
            assert b'"event": "db-updated"' in frame
            payload = json.loads(frame.split(b"data: ", 1)[1])
            assert payload["db"]["fingerprint"] == 123456789
            assert payload["db"]["size_bytes"] == 1024
            result.close()
            assert len(api._SSE_CLIENTS) == 0
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()

    def test_broadcast_frame_format(self) -> None:
        import recoverage.api as api

        q: queue.Queue[bytes] = queue.Queue()
        api._SSE_CLIENTS[q] = "test-peer"
        try:
            api._broadcast_db_updated((987654321, 512))
            frame = q.get_nowait()
            assert frame.startswith(b"event: db-updated\ndata: ")
            assert frame.endswith(b"\n\n")
            payload = json.loads(frame.split(b"data: ", 1)[1])
            assert payload["event"] == "db-updated"
            assert payload["db"]["fingerprint"] == 987654321
            assert payload["db"]["size_bytes"] == 512
            assert q.empty()
        finally:
            api._SSE_CLIENTS.pop(q, None)

    def test_a_dropped_frame_names_the_client_it_was_dropped_for(self, caplog: Any) -> None:
        """A full queue means one dashboard stops refreshing; the line must say which.

        Two wedged clients produce two lines, and without the peer they are the
        same line twice: the operator has no way to tell which tab to reload.
        """
        import recoverage.api as api

        wedged: queue.Queue[bytes] = queue.Queue(maxsize=1)
        wedged.put_nowait(b"already full")
        healthy: queue.Queue[bytes] = queue.Queue()
        api._SSE_CLIENTS[wedged] = "10.0.0.7"
        api._SSE_CLIENTS[healthy] = "10.0.0.8"
        try:
            with caplog.at_level(logging.WARNING, logger="recoverage"):
                api._broadcast_db_updated((1, 2))
            dropped = [r.getMessage() for r in caplog.records if "dropping" in r.getMessage()]
            assert len(dropped) == 1
            assert "10.0.0.7" in dropped[0]
            assert "10.0.0.8" not in dropped[0]
            # The client that is reading still got the frame.
            assert healthy.get_nowait().startswith(b"event: db-updated")
        finally:
            api._SSE_CLIENTS.pop(wedged, None)
            api._SSE_CLIENTS.pop(healthy, None)

    def test_snapshot_reads_real_db(self) -> None:
        import recoverage.api as api

        snapshot = api._snapshot_db_mtime()
        assert snapshot is not None
        assert snapshot[1] > 0  # the synthetic DB has a non-zero size

    # WAL-only-commit coverage for _snapshot_db_mtime lives in
    # test_server.py::TestDbEtag (same function object; kept in one place).

    def test_snapshot_ignores_non_coverage_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stray file beside the documents must NOT change the snapshot or
        ETags would be unstable between requests.

        The SQLite era had ``-shm`` touched by every connection; the same
        property now belongs to anything in the directory that is not a
        ``coverage-*.toml`` document.
        """
        import recoverage.api as api

        directory = coverage_dir(tmp_path)
        write_coverage(
            directory,
            "GAME",
            {".text": {"va": 0x1000, "size": 16, "cells": [cell(0x1000, 0x1010, "exact")]}},
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        before = api._snapshot_db_mtime()
        assert before is not None
        (directory / "coverage.db-shm").write_bytes(b"z" * 100)
        (directory / "coverage.db").write_bytes(b"z" * 100)
        (directory / "notes.txt").write_bytes(b"z" * 100)
        after = api._snapshot_db_mtime()
        assert after == before

    def test_ensure_db_watcher_starts_thread(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        try:
            api._ensure_db_watcher()
            assert api._DB_WATCHER_THREAD is not None
            assert api._DB_WATCHER_THREAD.is_alive()
        finally:
            api._stop_db_watcher()

    def test_stop_join_timeout_keeps_reference_and_blocks_duplicate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A watcher wedged past the join deadline must stay referenced.

        Nulling the reference after a timed-out join would let the next
        _ensure_db_watcher clear the stop event and start a SECOND poller
        beside the still-running one; the wedged thread then un-wedges, sees
        stop cleared, and keeps broadcasting duplicates as an untracked
        thread forever. Keeping the reference makes ensure return early and
        leaves stop set, so the wedged loop retires itself once it unwinds.
        """
        import recoverage.api as api

        api._stop_db_watcher()
        unblock = threading.Event()

        def wedged_loop(stop: threading.Event) -> None:
            unblock.wait(timeout=10)

        monkeypatch.setattr(api, "_db_watcher_loop", wedged_loop)
        monkeypatch.setattr(api, "_DB_WATCHER_JOIN_TIMEOUT", 0.05)
        try:
            api._ensure_db_watcher()
            wedged = api._DB_WATCHER_THREAD
            assert wedged is not None
            assert wedged.is_alive()

            api._stop_db_watcher()  # join deadline passes while it is wedged
            assert api._DB_WATCHER_THREAD is wedged
            assert api._DB_WATCHER_THREAD.is_alive()

            api._ensure_db_watcher()  # must not start a second poller
            assert api._DB_WATCHER_THREAD is wedged

            unblock.set()
            wedged.join(timeout=5)
            assert not wedged.is_alive()
        finally:
            unblock.set()
            api._stop_db_watcher()

    def test_ensure_stop_churn_never_strands_clients_without_watcher(self) -> None:
        """Concurrent _ensure_db_watcher/_stop_db_watcher must not leave a
        stopped-but-referenced watcher behind.

        The stop event is set under _DB_WATCHER_LOCK (not before it): set
        outside the lock, an ensure could observe the still-alive thread and
        return just before a stop retired it, leaving connected SSE clients
        with no watcher and no restart until another client connected.
        """
        import recoverage.api as api

        errors: list[BaseException] = []
        barrier = threading.Barrier(4)

        def churn(ensure: bool) -> None:
            try:
                barrier.wait(timeout=5)
                for _ in range(50):
                    if ensure:
                        api._ensure_db_watcher()
                    else:
                        api._stop_db_watcher()
            except BaseException as exc:  # surfaced via errors below
                errors.append(exc)

        threads = [
            threading.Thread(target=churn, args=(i % 2 == 0,), daemon=True) for i in range(4)
        ]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            assert all(not t.is_alive() for t in threads), "churn workers hung"
            assert not errors, f"errors during ensure/stop churn: {errors!r}"
        finally:
            api._stop_db_watcher()

    def test_stream_heartbeat(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        result = None
        try:
            monkeypatch.setattr(api, "_SSE_HEARTBEAT_SECONDS", 0.05)
            _, _, chunks, result = wsgi_stream("/api/events", max_chunks=2)
            assert chunks[0] == b": connected\n\n"
            assert chunks[1] == b": ping\n\n"
        finally:
            if result is not None:
                result.close()
            api._stop_db_watcher()


def _sequential_snapshot(seq: list[tuple[int, int]]) -> Any:
    """Snapshot stub yielding *seq*'s values in order, then repeating the last."""
    state = {"i": 0}

    def fake_snapshot() -> tuple[int, int]:
        i = min(state["i"], len(seq) - 1)
        value = seq[i]
        state["i"] += 1
        return value

    return fake_snapshot


def _start_watcher(
    api: Any, monkeypatch: pytest.MonkeyPatch, snapshot: Any, broadcast: Any
) -> tuple[threading.Event, threading.Thread]:
    """Patch the watcher's inputs and start one loop thread at test speed.

    Caller stops and joins the returned (stop, thread) pair.
    """
    monkeypatch.setattr(api, "_snapshot_db_mtime", snapshot)
    monkeypatch.setattr(api, "_broadcast_db_updated", broadcast)
    monkeypatch.setattr(api, "_SSE_POLL_INTERVAL_SECONDS", 0.01)
    stop = threading.Event()
    thread = threading.Thread(target=api._db_watcher_loop, args=(stop,), daemon=True)
    thread.start()
    return stop, thread


class TestSseDbWatcher:
    """Background watcher: polls mtime and broadcasts on change."""

    def test_watcher_broadcasts_on_mtime_change(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        calls: list[tuple[int, int]] = []
        stop, thread = _start_watcher(
            api,
            monkeypatch,
            _sequential_snapshot([(111, 1), (111, 1), (222, 2)]),
            lambda s: calls.append(s),
        )
        try:
            deadline = time.monotonic() + 2
            while len(calls) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert calls == [(222, 2)]
        finally:
            stop.set()
            thread.join(timeout=2)

    def test_watcher_ignores_unchanged_mtime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        calls: list[tuple[int, int]] = []
        # Wait for the loop to have polled rather than for a duration: a sleep
        # that outlasts the thread's startup leaves this green over a watcher
        # that never ran a second poll, which is the only thing it asserts.
        polled = threading.Event()
        polls = 0

        def snapshot() -> tuple[int, int]:
            nonlocal polls
            polls += 1
            if polls >= 2:
                polled.set()
            return (111, 1)

        stop, thread = _start_watcher(api, monkeypatch, snapshot, lambda s: calls.append(s))
        try:
            assert polled.wait(timeout=2), "the watcher never reached a second poll"
            assert calls == []
        finally:
            stop.set()
            thread.join(timeout=2)


# ── Threaded WSGI server ──────────────────────────────────────────


class TestThreadingServer:
    """The serve command must use a threaded WSGI server: the SSE /api/events
    stream stays open indefinitely, and wsgiref's stock single-threaded server
    would stall every other request while a client is connected."""

    def test_threading_server_subclasses_mixins(self) -> None:
        from socketserver import ThreadingMixIn
        from wsgiref.simple_server import WSGIServer

        from recoverage.devserver import _ThreadingWSGIServer

        assert issubclass(_ThreadingWSGIServer, ThreadingMixIn)
        assert issubclass(_ThreadingWSGIServer, WSGIServer)

    def test_threading_server_daemon_threads(self) -> None:
        from recoverage.devserver import _ThreadingWSGIServer

        assert _ThreadingWSGIServer.daemon_threads is True


# ── Batch function lookup ─────────────────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestBatchFunctionLookup:
    """POST /api/targets/<target>/functions batch VA lookup."""

    def _post(self, target: str, body: str | bytes) -> tuple[str, dict[str, str], bytes]:
        return wsgi_post(
            f"/api/targets/{target}/functions",
            headers={"Content-Type": "application/json"},
            body=body,
        )

    def test_batch_returns_details_with_last_verify(self) -> None:
        target = require_target()
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10001010"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert isinstance(data, list)
        assert [fn["name"] for fn in data] == ["_func_a", "_func_b"]
        assert data[0]["va"] == 0x10001000
        assert data[0]["last_verify"]["byte_delta"] == 0
        assert "last_verify" not in data[1]

    def test_batch_array_is_the_concatenated_row_objects(self) -> None:
        """The response is a hand-joined array of the rows' own JSON text, not
        a re-encode of decoded rows.  Concatenating is only sound if the joined
        document is what the handler used to produce, so pin the decoded
        document itself: every requested VA in input order, each function
        carrying its full field set, and last_verify attached exactly where a
        verify row exists.  A row dropped, reordered, or silently missing a
        field still parses as JSON, so asserting on the parsed array is the
        only thing that catches it."""
        target = require_target()
        vas = ["0x10001010", "0x10001000"]  # reverse order: output follows input
        status, headers, body = self._post(target, json.dumps({"vas": vas}))
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["va"] for fn in data] == [0x10001010, 0x10001000]
        assert [fn["name"] for fn in data] == ["_func_b", "_func_a"]
        # The one with a verify row is the one that gained a key.
        assert "last_verify" not in data[0]
        assert data[1]["last_verify"]["byte_delta"] == 0
        # Fields SQLite wrote into the object survive the passthrough: the
        # projection is the same text either way, so a shortened projection
        # would show up here as a missing key rather than as a parse error.
        for fn in data:
            assert {"va", "name", "size", "fileOffset", "status", "module"} <= set(fn)

    def test_batch_rejects_non_json_content_type(self) -> None:
        """A declared non-JSON media type is a 415, not a body that parses
        by accident: the client set the header wrongly and 'Body must be a
        JSON object' would blame the payload instead."""
        target = require_target()
        for content_type in ("text/plain", "application/x-www-form-urlencoded"):
            status, headers, body = wsgi_post(
                f"/api/targets/{target}/functions",
                headers={"Content-Type": content_type},
                body=json.dumps({"vas": ["0x10001000"]}),
            )
            assert status.startswith("415"), content_type
            data = json.loads(decode_body(body, headers))
            assert data["code"] == "unsupported_media_type"
            assert content_type in data["detail"]

    def test_batch_accepts_json_content_type_variants(self) -> None:
        """A charset parameter and a +json structured suffix are both JSON;
        the check is on the media type, not a byte-exact header match."""
        target = require_target()
        for content_type in (
            "application/json; charset=utf-8",
            "application/vnd.recoverage+json",
            "APPLICATION/JSON",
        ):
            status, headers, body = wsgi_post(
                f"/api/targets/{target}/functions",
                headers={"Content-Type": content_type},
                body=json.dumps({"vas": ["0x10001000"]}),
            )
            assert status.startswith("200"), content_type
            # 200 is not "the body was parsed": a handler that answered 200
            # with the error envelope passes it. The VA is known, so the
            # result names it.
            results = json.loads(decode_body(body, headers))
            assert [r["name"] for r in results] == ["_func_a"], content_type

    def test_batch_accepts_absent_content_type(self) -> None:
        """A client that omits the header entirely is not refused; the body
        is still parsed. Keeps curl -d and other header-less clients working."""
        target = require_target()
        status, headers, body = wsgi_post(
            f"/api/targets/{target}/functions",
            body=json.dumps({"vas": ["0x10001000"]}),
        )
        assert status.startswith("200")
        # 200 is not "the body was parsed": a handler that answered 200 with
        # the error envelope, or with an empty list, passes the status alone.
        results = json.loads(decode_body(body, headers))
        assert [r["name"] for r in results] == ["_func_a"]

    def test_batch_rejects_oversized_body(self) -> None:
        """The batch endpoint is unauthenticated — an oversized body must be
        rejected with 413 before it is parsed, not read into memory."""
        target = require_target()
        status, _, _body = wsgi_post(
            f"/api/targets/{target}/functions",
            body=b'{"vas": ["0x10001000"]' + b" " * 70_000 + b"}",
        )
        assert status.startswith("413")

    def test_batch_refuses_oversize_on_the_declared_length_alone(self) -> None:
        """A declared Content-Length over the cap is refused before ANY read.

        Bottle's own body reader drains the whole declared body before a
        handler sees a byte of it, spilling past 100 KiB into a temp file on
        tmpfs; a peer declaring 4 GB therefore cost 4 GB of RAM before the
        endpoint's 64 KiB cap could look at it. The stream below holds 32 bytes,
        so if the handler reads it at all the count moves; the refusal must
        come from the header alone.
        """
        target = require_target()
        stream = _CountingStream(b'{"vas": ["0x10001000"]}')
        status, headers, _body = wsgi_request(
            "POST",
            f"/api/targets/{target}/functions",
            {"Content-Length": str(4_000_000_000)},
            body=b"",
            wsgi_input=stream,
        )
        assert status.startswith("413")
        assert stream.reads == 0, "the declared length should have refused before any read"
        assert headers.get("Connection") == "close"

    def test_batch_oversize_closes_the_connection(self) -> None:
        """The reader stops at the cap with the rest of the body in the
        socket, so the refusal must close: a keep-alive handler would read
        those bytes as the next request."""
        target = require_target()
        status, headers, _body = wsgi_post(
            f"/api/targets/{target}/functions",
            body=b'{"vas": ["0x10001000"]' + b" " * 70_000 + b"}",
        )
        assert status.startswith("413")
        assert headers.get("Connection") == "close"

    def test_batch_reads_a_chunked_body(self) -> None:
        """A chunked request carries no Content-Length, so the cap can only be
        enforced while reading. The chunks decode to the same JSON."""
        target = require_target()
        payload = json.dumps({"vas": ["0x10001000"]}).encode()
        chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/targets/{target}/functions",
            {"Transfer-Encoding": "chunked"},
            body=chunked,
            wsgi_input=None,
            content_length=None,
        )
        assert status.startswith("200")
        # "decode to the same JSON" is the claim the docstring makes, so it is
        # the claim to assert: the framed request answers with the results the
        # unframed one does, which a 200 from an unparsed body would not.
        _s, plain_headers, plain_body = wsgi_post(f"/api/targets/{target}/functions", body=payload)
        assert json.loads(decode_body(body, headers)) == json.loads(
            decode_body(plain_body, plain_headers)
        )
        assert [r["name"] for r in json.loads(decode_body(body, headers))] == ["_func_a"]

    def test_batch_refuses_an_oversize_chunked_body(self) -> None:
        """The chunked cap is on the DECODED bytes, so a body split into many
        small chunks is refused just the same."""
        target = require_target()
        chunk = b" " * 4096
        framed = b"".join(b"%x\r\n%s\r\n" % (len(chunk), chunk) for _ in range(32))
        status, headers, _body = wsgi_request(
            "POST",
            f"/api/targets/{target}/functions",
            {"Transfer-Encoding": "chunked"},
            body=framed + b"0\r\n\r\n",
            wsgi_input=None,
            content_length=None,
        )
        assert status.startswith("413")
        assert headers.get("Connection") == "close"

    def test_batch_refuses_a_chunk_size_int_would_widen(self) -> None:
        """A chunk size is a request-supplied number, so it takes the ASCII parse.

        `int(x, 16)` reads the `_` separator, so "1_0" is a chunk size of 16 and
        this body decodes whole — a body the client never framed that way, read
        off a socket that is carrying whatever follows it. Refused as malformed
        instead, and the connection closed with it."""
        target = require_target()
        status, headers, _body = wsgi_request(
            "POST",
            f"/api/targets/{target}/functions",
            {"Transfer-Encoding": "chunked"},
            body=b"1_0\r\n" + b'{"vas":["0x10"]}' + b"\r\n0\r\n\r\n",
            wsgi_input=None,
            content_length=None,
        )
        assert status.startswith("400")
        assert headers.get("Connection") == "close"

    def test_batch_refuses_a_content_length_that_is_no_byte_count(self) -> None:
        """A present Content-Length is framing, so a bad one is refused, not dropped.

        Reading it as "no length declared" switched the reader to the unframed
        path, so "1_0" (which `int(x)` widens to 10), an Arabic-Indic digit run
        and a negative length each silently changed the read strategy and the
        endpoint answered 400 about the JSON instead of about the framing."""
        target = require_target()
        for declared in ("1_0", "٤٠", "-1", "abc", "0x10"):
            status, headers, _body = wsgi_request(
                "POST",
                f"/api/targets/{target}/functions",
                body=b'{"vas":["0x10001000"]}',
                content_length=declared,
            )
            assert status.startswith("400"), f"Content-Length: {declared!r} was not refused"
            assert headers.get("Connection") == "close"

    def test_batch_refuses_a_chunk_size_line_carrying_no_size(self) -> None:
        """A chunk-size line is 1*HEXDIG, so a line with no digits frames nothing.

        Read as size 0, a bare CRLF or an extensions-only line (";ext=1") is the
        terminating chunk: the body ended there and the request was answered 200
        with whatever had been accumulated, a truncated message framed as a
        complete one. Refused as malformed instead, and the connection closed
        with it."""
        target = require_target()
        for size_line in (b"\r\n", b";ext=1\r\n", b"   \r\n"):
            status, headers, _body = wsgi_request(
                "POST",
                f"/api/targets/{target}/functions",
                {"Transfer-Encoding": "chunked"},
                body=size_line + b'{"vas":["0x10"]}' + b"\r\n0\r\n\r\n",
                wsgi_input=None,
                content_length=None,
            )
            assert status.startswith("400"), f"{size_line!r} was not refused"
            assert headers.get("Connection") == "close"

    def test_batch_refuses_unbounded_chunk_trailers(self) -> None:
        """The trailer section is the one part of a chunked body with no cap.

        Every other read in the chunked reader stops at a limit: the size line
        at _CHUNK_LINE_MAX, the data at the caller's cap, the declared length
        before a byte is read. The trailer loop ended only on the final CRLF, so
        a peer streaming short trailer lines held its handler thread and its
        admission slot for the whole socket deadline — one request per slot,
        for as long as the client cared to keep writing. Refused past the
        trailer bound, with the read count asserted so a future cap that only
        moved the status code cannot pass for one that moved the read."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        trailer = b"x" * 64 + b"\r\n"
        stream = _CountingStream(b"0\r\n" + trailer * 1024)
        status, headers, _body = wsgi_request(
            "POST",
            f"/api/targets/{target}/functions",
            {"Transfer-Encoding": "chunked"},
            wsgi_input=stream,
            content_length=None,
        )
        assert status.startswith("400")
        assert headers.get("Connection") == "close"
        # 1 read for the terminating chunk's size line, then one per trailer
        # line up to the bound — nowhere near the 1024 the peer offered.
        offered = 1024
        reads_after_one_trailer_line = 1 + _server._TRAILER_MAX_BYTES // len(trailer)
        assert reads_after_one_trailer_line < stream.reads < offered

    def test_batch_omits_unknown_vas(self) -> None:
        target = require_target()
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x99999999"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["va"] for fn in data] == [0x10001000]

    def test_batch_all_unknown_vas_returns_empty_list(self) -> None:
        target = require_target()
        status, headers, body = self._post(target, json.dumps({"vas": ["0x99999999"]}))
        assert status.startswith("200")
        assert json.loads(decode_body(body, headers)) == []

    def test_batch_includes_globals(self) -> None:
        target = require_target()
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10002000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert len(data) == 2
        assert data[1]["name"] == "g_counter"
        assert data[1]["isGlobal"] == 1

    def test_batch_preserves_input_order(self) -> None:
        target = require_target()
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001030", "0x10001000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data] == ["_func_c", "_func_a"]

    def test_batch_accepts_int_vas(self) -> None:
        target = require_target()
        status, headers, body = self._post(target, json.dumps({"vas": [0x10001000]}))
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data] == ["_func_a"]

    def test_batch_dedupes_repeated_vas(self) -> None:
        target = require_target()
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10001000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert len(data) == 1

    def test_batch_empty_vas_400(self) -> None:
        target = require_target()
        status, headers, body = self._post(target, json.dumps({"vas": []}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"
        # Every API error names the constraint at fault in `detail`; an empty
        # list is the one case that used to answer with the field left blank.
        assert data["detail"]

    def test_every_api_error_carries_the_full_envelope(self) -> None:
        """error + code + detail, whatever the endpoint or the status.

        The README documents the trio as the contract every /api/* failure
        answers, so a handler that raises _json_err without one of the keys
        must not be able to ship.
        """
        target = require_target()
        probes: list[str] = [
            "/api/targets/no-such-target/stats",
            f"/api/targets/{target}/functions?status=nope",
            f"/api/targets/{target}/functions/{target}?limit=1&status=nope",
            f"/api/targets/{target}/asm?va=zz&size=8",
            f"/api/targets/{target}/sections/.text/bytes?offset=-1",
            "/api/regen",
        ]
        for url in probes:
            status, headers, body = wsgi_get(url)
            assert not status.startswith("200"), url
            data = json.loads(decode_body(body, headers))
            assert set(data) >= {"error", "code", "detail"}, url
            assert data["error"] and data["code"] and data["detail"], url

    @pytest.mark.parametrize(
        ("body", "error"),
        [
            ("not json at all", "Body must be a JSON object"),
            ("", "Body must be a JSON object"),
            (json.dumps([1, 2, 3]), "Body must be a JSON object"),
            (json.dumps({}), "vas must be an array"),
            (json.dumps({"vas": "0x10001000"}), "vas must be an array"),
            (json.dumps({"vas": []}), "vas must not be empty"),
        ],
        ids=[
            "non-json",
            "empty",
            "not-an-object",
            "no-vas-key",
            "vas-not-a-list",
            "vas-empty",
        ],
    )
    def test_batch_body_shapes_that_are_not_a_va_list_400(self, body: str, error: str) -> None:
        """Every body that is not `{"vas": [...]}` is a 400, not a 500.

        A client that posts the wrong shape gets the error envelope, whether
        it is unparsable, empty, an array, an object without `vas`, or one
        whose `vas` is a string rather than a list. Each shape is named in
        the error: a 400 the reader cannot tell apart from a neighbouring
        shape's is the same page of a log to whoever has to fix the client.
        """
        target = require_target()
        status, headers, body_bytes = self._post(target, body)
        assert status.startswith("400")
        data = json.loads(decode_body(body_bytes, headers))
        assert data["error"] == error, body

    def test_batch_malformed_va_400(self) -> None:
        target = require_target()
        status, headers, body = self._post(target, json.dumps({"vas": ["not-a-va"]}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"
        assert "not-a-va" in data["detail"]

    def test_batch_too_many_vas_400(self) -> None:
        import recoverage.api as api

        target = require_target()
        vas = ["0x10001000"] * (api._MAX_BATCH_LOOKUP + 1)
        status, headers, body = self._post(target, json.dumps({"vas": vas}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert str(api._MAX_BATCH_LOOKUP) in data["error"]

    def test_batch_va_past_the_address_space_is_reported_as_out_of_range(self) -> None:
        """A VA that parsed but does not fit is a range fault, in either spelling.

        The integer arm and the hex arm are one check split across two parse
        paths; reporting the hex one as "unparseable ... expected hex like
        0x10001000" blamed the format for a string that parsed fine.
        """
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        too_big = api.VA_MAX + 1
        for entry in (too_big, f"0x{too_big:x}"):
            status, headers, body = self._post(target, json.dumps({"vas": [entry]}))
            assert status.startswith("400")
            data = json.loads(decode_body(body, headers))
            assert data["detail"] == f"VA out of range (max 0x{api.VA_MAX:x})"

    def test_batch_read_failure_is_not_reported_as_a_malformed_body(self) -> None:
        """A body stream that breaks is a transport failure, not bad JSON.

        The read used to be answered with an empty body, so a client that hung
        up mid-transfer was told "Body must be a JSON object" and pointed at
        its own payload for a failure it could not see or fix.  Driven through
        the real route: the WSGI environ carries the broken stream, and only
        the error label may differ from a genuinely empty body.
        """
        target = require_target()

        class _BrokenStream:
            def read(self, _n: int = -1) -> bytes:
                raise OSError("peer closed the connection mid-body")

        environ: dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ.update(
            REQUEST_METHOD="POST",
            PATH_INFO=f"/api/targets/{target}/functions",
            QUERY_STRING="",
            REMOTE_ADDR="127.0.0.1",
            CONTENT_TYPE="application/json",
            CONTENT_LENGTH="32",
            **{"wsgi.input": _BrokenStream()},
        )
        captured: dict[str, str] = {}

        def _start_response(status: str, headers: list[tuple[str, str]], exc: Any = None) -> Any:
            captured["status"] = status
            return lambda chunk: None

        body = b"".join(webapp.app(environ, _start_response))
        text = body.decode("utf-8")

        assert captured["status"].startswith("400")
        assert "Could not read request body" in text
        assert "Body must be a JSON object" not in text


# ── Error-response consistency ────────────────────────────────────


class TestErrorResponseShape:
    """Every JSON error response carries {error, code, detail} (+ extras)."""

    def teardown_method(self) -> None:
        import recoverage.api as api

        # The 429 test stamps the module-global regen cooldown; reset so
        # later tests POSTing /api/regen start from a neutral state instead
        # of inheriting this test's rate-limit window.
        api._regen_last_attempt = None

    def _check(
        self, status: str, headers: dict[str, str], body: bytes, expected_code: str
    ) -> dict[str, Any]:
        assert status.startswith(("4", "5"))
        data = json.loads(decode_body(body, headers))
        assert set(data) >= {"error", "code", "detail"}
        assert data["code"] == expected_code
        assert isinstance(data["error"], str) and data["error"]
        assert isinstance(data["detail"], str)
        return data

    def test_404_function_detail(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0xdeadbeef")
        data = self._check(status, headers, body, "not_found")
        assert "0xdeadbeef" in data["detail"]

    def test_400_bad_request(self) -> None:
        target = require_target()
        status, headers, body = wsgi_post(f"/api/targets/{target}/functions", body="[]")
        self._check(status, headers, body, "bad_request")

    def test_403_forbidden(self) -> None:
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="192.168.1.100")
        data = self._check(status, headers, body, "forbidden")
        assert data["error"] == "Forbidden: localhost only"

    def test_429_rate_limited_preserves_extras(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        # The first POST must pass the cooldown gate without running a real
        # regen (rebrew would rebuild the developer's coverage.db).
        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))
        api._regen_last_attempt = None
        wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        data = self._check(status, headers, body, "rate_limited")
        assert data["retry_after"] >= 1, f"a zero wait is not a wait: {data['retry_after']}"
        assert data["detail"]
        # The auth throttle answers its 429 with the same header, so a client
        # has one place to read the wait from regardless of which limit hit.
        assert int(_header(headers, "Retry-After") or 0) >= 1

    def test_every_429_carries_the_wait_in_the_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A client reading the JSON contract gets the wait from every limit,
        not just the regen cooldown.

        The 429 family spans two gates (the regen cooldown/lock and the
        failed-token throttle) and each answers with its own wait; the
        throttle's used to be header-only, so a client parsing the documented
        error envelope read ``rate_limited`` with no way to act on it. Both
        places carry the same number.

        The comparison is exact and the type is asserted: the ``int(...) ==
        int(...)`` form this replaced passed against a body reading ``4.2``
        beside a header reading ``5``, which is the disagreement it looked
        like it was ruling out. A client waits on the number, and an int is
        what every ``retry_after`` in the package now sends.
        """
        import recoverage.api as api
        import recoverage.server as server_mod

        def _wait(payload: dict, headers: dict) -> int:
            value = payload["retry_after"]
            assert isinstance(value, int), f"retry_after is not a whole number: {value!r}"
            return int(_header(headers, "Retry-After") or 0) - value

        api._regen_last_attempt = None
        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))
        wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        cooldown = self._check(status, headers, body, "rate_limited")
        assert _wait(cooldown, headers) == 0

        # The lock arm, the other 429 this endpoint sends.
        api._regen_last_attempt = None
        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))
        api._REGEN_LOCK.acquire()
        try:
            status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
            busy = self._check(status, headers, body, "rate_limited")
            assert _wait(busy, headers) == 0
        finally:
            api._REGEN_LOCK.release()

        monkeypatch.setattr(server_mod, "_AUTH_TOKEN", "unit-test-token")
        bad = {"Authorization": "Bearer wrong", "Accept": "application/json"}
        try:
            for _ in range(server_mod._AUTH_FAIL_MAX):
                assert wsgi_request("GET", "/api/health", headers=bad)[0].startswith("401")
            status, headers, body = wsgi_request("GET", "/api/health", headers=bad)
            throttled = self._check(status, headers, body, "rate_limited")
            assert throttled["retry_after"] == int(server_mod._AUTH_FAIL_WINDOW_SECONDS)
            assert _wait(throttled, headers) == 0
        finally:
            server_mod._clear_auth_failures("127.0.0.1")

    def test_501_not_implemented(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "capstone_unavailable_reason", lambda: "capstone is not installed")
        status, headers, body = wsgi_get("/api/targets/FAKEDLL/asm?va=0x10001000&size=16")
        data = self._check(status, headers, body, "not_implemented")
        assert "capstone" in data["error"]

    def test_503_db_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.server as server_mod

        target = require_target()

        def _boom(_root: Path) -> dict[str, CoverageSnapshot]:
            raise CoverageTomlError("no readable coverage document")

        monkeypatch.setattr(server_mod, "load_all", _boom)
        status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        self._check(status, headers, body, "db_unavailable")

    def test_503_db_unavailable_is_logged_with_cause(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A swallowed CoverageTomlError in the shared target snapshot must not
        make an unreadable document invisible: the failure is logged with the
        request context and the cause.  The 503 body names the exception class
        but not its message, which quotes the absolute coverage path and would
        reach any unauthenticated caller (--allow-remote)."""
        import logging as _logging

        import recoverage.api as api
        import recoverage.server as server_mod

        target = require_target()

        def _boom(_root: Path) -> dict[str, CoverageSnapshot]:
            raise CoverageTomlError("coverage-GAME.toml: malformed TOML (torn file)")

        monkeypatch.setattr(server_mod, "load_all", _boom)
        api._clear_stats_cache()
        with caplog.at_level(_logging.WARNING, logger="recoverage"):
            status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        self._check(status, headers, body, "db_unavailable")
        data = json.loads(decode_body(body, headers))
        assert "CoverageTomlError" in data["detail"]
        assert "malformed TOML" not in data["detail"]
        logged = [rec.getMessage() for rec in caplog.records]
        assert any("Coverage unavailable" in msg and "malformed TOML" in msg for msg in logged)


# ── Host-header validation & CORS allowlist (security) ─────────────


class TestHostHeaderValidation:
    """Loopback installs reject unexpected Host headers (DNS-rebinding guard)."""

    def _set_allowed(self, value: set[str] | None) -> None:
        import recoverage.server as srv

        srv.ALLOWED_HOSTS = value

    def teardown_method(self) -> None:
        self._set_allowed(None)

    def test_loopback_host_accepted(self) -> None:
        self._set_allowed({"127.0.0.1", "localhost", "::1"})
        status, _, _ = wsgi_get("/api/health", headers={"Host": "localhost:8001"})
        assert status.startswith("200")

    def test_evil_host_rejected(self) -> None:
        self._set_allowed({"127.0.0.1", "localhost", "::1"})
        status, headers, body = wsgi_get("/api/health", headers={"Host": "evil.example.com"})
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Bad Request"
        assert "evil.example.com" in data["detail"]

    def test_evil_host_rejection_is_audit_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """A rejected Host header on a loopback bind is a DNS-rebinding
        attempt signal; the 400 must leave a WARNING audit trail."""
        import logging

        self._set_allowed({"127.0.0.1", "localhost", "::1"})
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            status, _, _ = wsgi_get("/api/health", headers={"Host": "evil.example.com"})
        assert status.startswith("400")
        assert any("unexpected Host header" in r.getMessage() for r in caplog.records)
        # The hostile value may appear (repr-escaped), but the peer address
        # must be there for investigation.
        assert any("127.0.0.1" in r.getMessage() for r in caplog.records)

    def test_a_forged_peer_cannot_split_the_audit_line(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """REMOTE_ADDR is escaped on both audit lines, like every other untrusted
        argument in this package's log calls.

        A proxy that folds a header into REMOTE_ADDR makes it as hostile as
        ``Host``, and the two lines that name it are the ones an incident
        investigation reads.
        """
        import logging

        self._set_allowed({"127.0.0.1", "localhost", "::1"})
        forged = "10.0.0.9\x1b[2K\rX-Request-ID: 000000000000 forged\nWARN forged"
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            wsgi_request(
                "GET", "/api/health", headers={"Host": "evil.example.com"}, remote_addr=forged
            )
        assert any("unexpected Host header" in r.getMessage() for r in caplog.records)
        for record in caplog.records:
            message = record.getMessage()
            if "unexpected Host header" in message:
                assert forged not in message
                assert "\x1b" not in message
                assert "\r" not in message
                assert "\n" not in message

    def test_no_validation_when_remote_bind(self) -> None:
        # --allow-remote binds leave ALLOWED_HOSTS None → any Host passes.
        self._set_allowed(None)
        status, _, _ = wsgi_get("/api/health", headers={"Host": "anything.example.com"})
        assert status.startswith("200")


class TestCorsOriginAllowlist:
    """--cors never emits the wildcard; only allowlisted origins are echoed."""

    def _enable(self, origins: list[str]) -> None:
        import recoverage.server as srv

        srv.CORS_ENABLED = True
        srv.CORS_ALLOWED_ORIGINS = origins

    def teardown_method(self) -> None:
        import recoverage.server as srv

        srv.CORS_ENABLED = False
        srv.CORS_ALLOWED_ORIGINS = []

    def test_allowed_origin_echoed(self) -> None:
        # Origins are matched at scheme://host[:port] granularity, not hostname.
        self._enable(["http://localhost:5173"])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert status.startswith("200")
        assert headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
        assert "Origin" in headers.get("Vary", "")

    def test_unknown_origin_gets_no_aca_header(self) -> None:
        self._enable(["http://localhost:5173"])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://evil.example.com"})
        assert status.startswith("200")
        assert "Access-Control-Allow-Origin" not in headers

    def test_wildcard_never_emitted(self) -> None:
        """An empty allowlist must never emit Access-Control-Allow-Origin:*."""
        self._enable([])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert status.startswith("200")
        assert "Access-Control-Allow-Origin" not in headers

    def test_different_port_not_allowed(self) -> None:
        self._enable(["http://localhost:5173"])
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:9999"})
        assert status.startswith("200")
        assert "Access-Control-Allow-Origin" not in headers
        status, headers, _ = wsgi_get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert status.startswith("200")
        assert headers.get("Access-Control-Allow-Origin") != "*"

    # ── Preflight: the only OPTIONS route in the app ──────────────────

    def test_preflight_allowed_origin(self) -> None:
        """A browser preflight for an allowlisted origin must carry the
        allowlist echo and the advertised method/header set, with an empty
        preflight body."""
        self._enable(["http://localhost:5173"])
        status, headers, body = wsgi_request(
            "OPTIONS",
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert status.startswith("200")
        assert body == b""
        assert headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
        methods = headers.get("Access-Control-Allow-Methods", "")
        assert "GET" in methods and "POST" in methods and "OPTIONS" in methods
        assert "Content-Type" in headers.get("Access-Control-Allow-Headers", "")

    def test_allow_headers_cover_the_documented_auth_and_validators(self) -> None:
        """--cors must not preflight-fail the credentials the API documents.

        Authorization carries the --token bearer check, If-None-Match carries
        the conditional GET every ETag-bearing endpoint expects, Idempotency-Key
        carries the documented regen retry, and X-Request-ID carries the
        correlation id a client is told to send so its report can be matched to
        the server log; a client sending any of them without it in this list
        never gets a response at all.
        """
        self._enable(["http://localhost:5173"])
        _status, headers, _body = wsgi_get(
            "/api/health", headers={"Origin": "http://localhost:5173"}
        )
        allowed = headers.get("Access-Control-Allow-Headers", "")
        assert "Authorization" in allowed
        assert "If-None-Match" in allowed
        assert "Idempotency-Key" in allowed
        assert "X-Request-ID" in allowed
        exposed = headers.get("Access-Control-Expose-Headers", "")
        assert "ETag" in exposed
        assert "Retry-After" in exposed
        assert "Idempotent-Replay" in exposed
        # The id is on every response and is what joins a client's report to
        # the server log, so a cross-origin client that cannot read it can
        # report a failure with nothing for the operator to grep.
        assert "X-Request-ID" in exposed

    def test_a_client_supplied_request_id_survives_the_preflight(self) -> None:
        """The correlation id round-trips cross-origin, in both directions.

        The header is allowlisted so the preflight admits it, exposed so the
        echo is readable, and echoed back verbatim: a client that sent it gets
        the same id, which is what lets its report name a log line.
        """
        self._enable(["http://localhost:5173"])
        rid = "cors-correlate-1"
        _status, headers, _body = wsgi_get(
            "/api/health",
            headers={"Origin": "http://localhost:5173", "X-Request-ID": rid},
        )
        assert headers.get("X-Request-Id") == rid

    def test_preflight_unknown_origin_gets_no_acao(self) -> None:
        """Preflight for a non-allowlisted origin answers 200 but must not
        grant cross-origin access."""
        self._enable(["http://localhost:5173"])
        status, headers, _ = wsgi_request(
            "OPTIONS",
            "/api/health",
            headers={
                "Origin": "http://evil.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert status.startswith("200")
        assert "Access-Control-Allow-Origin" not in headers

    def test_preflight_without_cors_flag_has_no_cors_headers(self) -> None:
        """Without --cors the OPTIONS route still exists (no 405) but leaks
        no Access-Control-* headers at all."""
        import recoverage.server as srv

        srv.CORS_ENABLED = False
        status, headers, _ = wsgi_request("OPTIONS", "/api/health")
        assert status.startswith("200")
        assert not any(k.startswith("Access-Control") for k in headers)


# ── Unknown target handling (V14) ──────────────────────────────────


class TestUnknownTarget:
    """Target-scoped endpoints 404 on unknown targets instead of empty 200s."""

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_stats_unknown_target_404(self) -> None:
        status, headers, body = wsgi_get("/api/targets/DOESNOTEXIST/stats")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Target not found"
        assert "DOESNOTEXIST" in data["detail"]

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_functions_unknown_target_404(self) -> None:
        status, headers, body = wsgi_get("/api/targets/DOESNOTEXIST/functions")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Target not found"

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_known_target_still_200(self) -> None:
        target = require_target()
        status, _, _ = wsgi_get(f"/api/targets/{target}/stats")
        assert status.startswith("200")


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestConfiguredUnbuiltTarget:
    """A target declared in rebrew-project.toml but absent from coverage.db
    must stay addressable: _require_target counts config membership as valid
    (a never-built target must not 404), and /api/targets lists config-only
    entries even before their first build."""

    NEW_TARGET = "NEWBIE"

    @pytest.fixture(autouse=True)
    def _declared_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.server as srv
        from recoverage.server import clear_target_cache

        monkeypatch.setattr(
            srv,
            "_get_targets_config",
            lambda: {self.NEW_TARGET: {"filename": "bin/newbie.dll"}},
        )
        clear_target_cache()
        # resolve_targets memoises; later tests must not see NEWBIE.
        yield
        clear_target_cache()

    def test_unbuilt_target_functions_list_is_200_not_404(self) -> None:
        status, headers, body = wsgi_get(f"/api/targets/{self.NEW_TARGET}/functions")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["total"] == 0
        assert data["functions"] == []

    def test_unbuilt_target_listed_in_targets_endpoint(self) -> None:
        """Config-declared targets come first and DB targets are still listed."""
        status, headers, body = wsgi_get("/api/targets")
        assert status.startswith("200")
        ids = [t["id"] for t in json.loads(decode_body(body, headers))["targets"]]
        assert ids[0] == self.NEW_TARGET
        assert get_first_target() in ids

    def test_db_down_still_lists_config_only_targets(self, monkeypatch: Any) -> None:
        """With the coverage documents unreadable, /api/targets falls back to
        the config list instead of 500ing — the SPA needs a target dropdown
        either way."""
        import recoverage.server as server_mod

        def _boom(_root: Path) -> dict[str, CoverageSnapshot]:
            raise CoverageTomlError("no readable coverage document")

        monkeypatch.setattr(server_mod, "load_all", _boom)
        status, headers, body = wsgi_get("/api/targets")
        assert status.startswith("200")
        ids = [t["id"] for t in json.loads(decode_body(body, headers))["targets"]]
        assert self.NEW_TARGET in ids


class TestServeBindGuard:
    """--bind on a non-loopback interface requires --allow-remote."""

    def test_non_loopback_refused_without_allow_remote(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--bind", "0.0.0.0", "--port", "8123"])
        assert result.exit_code != 0
        assert "--allow-remote" in result.output

    def test_allow_remote_flag_documented(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--help"], env=_NO_COLOR_ENV)
        assert result.exit_code == 0
        help_text = _plain(result.output)
        assert "--allow-remote" in help_text
        assert "--cors-origin" in help_text


class TestPostResolveReadFailure:
    """A coverage read that fails AFTER the target resolved (the document
    replaced between the stat and the parse) must keep the JSON 503 contract
    instead of surfacing Bottle's HTML 500."""

    @pytest.mark.skipif(not HAS_DB, reason="No coverage database")
    def test_read_failure_returns_json_503(self, monkeypatch: Any) -> None:
        import recoverage.server as server_mod

        target = require_target()

        # A warm /stats memo returns before reading coverage at all; this test
        # exercises the read-failure path, so it must start from a cold memo.
        api._clear_stats_cache()

        def _boom(_target: str) -> CoverageSnapshot:
            raise CoverageTomlError("coverage-GAME.toml: cannot read (torn file)")

        # The target resolves fine (the shared fixture's documents are
        # readable); the read that builds the answer is what fails.
        monkeypatch.setattr(server_mod, "coverage_for", _boom)
        status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        assert status.startswith("503"), body
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Database unavailable"
        assert data["code"] == "db_unavailable"


class _ExactStream(BytesIO):
    """A ``wsgi.input`` that refuses to read past the frame it was given.

    Stands in for the socket's buffered reader under the serving stack, where
    ``read(n)`` blocks until n bytes arrive or the peer goes away.  Every other
    body test uses a plain ``BytesIO``, which short-reads at once and so cannot
    tell a read-to-the-declared-length from a read-to-EOF.
    """

    reads = 0
    overshoot: ClassVar[list[int]] = []

    def __init__(self, frame: bytes, trailer: bytes = b"") -> None:
        super().__init__(frame + trailer)
        self._frame_end = len(frame)

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        self.reads += 1
        if self.tell() >= self._frame_end:
            # A read this size would run off the end of the frame: on a socket
            # it blocks until the client hangs up.
            self.overshoot.append(size)
            raise AssertionError("read past the declared Content-Length")
        return super().read(min(size, self._frame_end - self.tell()))

    def readline(self, size: int = -1) -> bytes:  # type: ignore[override]
        self.reads += 1
        if self.tell() >= self._frame_end:
            self.overshoot.append(size)
            raise AssertionError("readline past the declared Content-Length")
        return super().readline(min(size, self._frame_end - self.tell()))


class TestFramedBodyIsReadToItsDeclaredLength:
    """A Content-Length body is read to that length, never to EOF.

    Under the serving stack ``wsgi.input`` is the socket's buffered reader,
    whose ``read(n)`` returns only once n bytes have arrived or the peer has
    gone away.  A reader that drains to EOF therefore parks the handler until
    the client's socket deadline, while the client waits for the response: a
    batch lookup over a real connection never returns.
    """

    #: Bytes a read-to-EOF loop would swallow past the frame.
    TRAILER = b"x" * 40

    def test_read_stops_at_the_declared_length(self) -> None:
        payload = b'{"vas": ["0x1000"]}'
        stream = _ExactStream(payload, self.TRAILER)
        status, _headers, _body = wsgi_request(
            "POST",
            "/api/targets/NOPE/functions",
            headers={"Content-Type": "application/json"},
            body=payload,
            wsgi_input=stream,
        )
        # The reader returned the framed body and the handler ran, answering
        # 404 for the missing target.  A vacuous "not a 5xx" guard here would
        # pass on any status line, including a handler that never ran.
        assert status.startswith("404"), status
        assert stream.overshoot == []
        assert stream.tell() == len(payload)

    def test_oversize_declaration_reads_nothing(self) -> None:
        stream = _ExactStream(b"x" * 10)
        status, _headers, _body = wsgi_request(
            "POST",
            "/api/targets/NOPE/functions",
            headers={"Content-Type": "application/json"},
            body=b"x" * 10,
            wsgi_input=stream,
            content_length="999999999",
        )
        assert status.startswith("413"), status
        assert stream.reads == 0


class TestChunkedTrailerSection:
    """The trailer section after the last chunk ends on its final CRLF.

    Reaching the end of the input where that CRLF was due is a truncated
    message, not the end of the trailers: the framing is still incomplete, so
    the body is refused rather than served with a connection the next request
    would be read out of.
    """

    PATH = "/api/targets/NOPE/functions"
    BODY = b'{"vas": ["0x1000"]}'  # 19 bytes, 0x13
    HEADERS: ClassVar[dict[str, str]] = {
        "Transfer-Encoding": "chunked",
        "Content-Type": "application/json",
    }

    def _post(self, framing: bytes) -> tuple[str, dict[str, str], bytes]:
        return wsgi_request(
            "POST",
            self.PATH,
            headers=self.HEADERS,
            body=b"",
            wsgi_input=BytesIO(framing),
            content_length=None,
        )

    def test_complete_trailer_section_is_read(self) -> None:
        # 404 is the missing target, which is past the framing: what matters
        # is that the reader returned the body instead of refusing it.  The
        # status is asserted outright because a "not 400 or 413" guard also
        # admits a 500 from a reader that raised inside the handler.
        status, _headers, _body = self._post(b"13\r\n" + self.BODY + b"\r\n0\r\nX-T: v\r\n\r\n")
        assert status.startswith("404"), status

    def test_truncated_trailer_section_is_refused(self) -> None:
        status, headers, _body = self._post(b"13\r\n" + self.BODY + b"\r\n0\r\nX-T: v\r\n")
        assert status.startswith("400"), status
        # The rest of the framing is still in the socket, so a keep-alive
        # reader would take it as a second request.
        assert headers.get("Connection") == "close"


class TestNormalizeOriginEdges:
    def test_default_port_dropped(self) -> None:
        from recoverage.server import _normalize_origin

        assert _normalize_origin("http://localhost:80") == "http://localhost"
        assert _normalize_origin("https://example.com:443") == "https://example.com"
        assert _normalize_origin("http://localhost:5173") == "http://localhost:5173"

    def test_ipv6_brackets_preserved(self) -> None:
        from recoverage.server import _normalize_origin

        assert _normalize_origin("http://[::1]:8001") == "http://[::1]:8001"


def _game_coverage(
    tmp_path: Path,
    cells: tuple[tuple[str, int, int, str], ...] = (),
    functions: tuple[dict[str, Any], ...] = (),
    globals_: tuple[dict[str, Any], ...] = (),
    *,
    sections: dict[str, dict[str, Any]] | None = None,
) -> Path:
    """Write a ``GAME`` coverage document and return the coverage DIRECTORY.

    The SQLite era built a schema-gate-valid database here; the reader takes a
    document now, so the same fixture is a ``coverage-GAME.toml``.  *cells* is
    the compact ``(section, start, end, state)`` tuple list the old helper
    seeded: a section named only there gets a row anchored at its first cell.
    """
    built: dict[str, dict[str, Any]] = {
        name: {**definition, "cells": list(definition.get("cells", []))}
        for name, definition in (sections or {}).items()
    }
    for section_name, start, end, state in cells:
        row = built.setdefault(section_name, {"va": start, "size": end - start, "cells": []})
        row["cells"].append(cell(start, end, state))
    directory = coverage_dir(tmp_path)
    write_coverage(
        directory,
        "GAME",
        built,
        functions=list(functions),
        globals_=list(globals_),
    )
    return directory


def _fake_request(query: dict[str, str] | None = None) -> Any:
    """A thread-independent stand-in for bottle's request local.

    Handlers read ``request`` from *their own* module globals, so one
    stand-in has to be installed in every module that touches it: ``api``
    reads ``request.query`` for ``?section=`` while the shared ETag and
    compression helpers in ``server`` read ``request.headers``. Patching only
    ``api.request`` leaves the server half falling back to bottle's empty
    default environ, which is how a caller-supplied section filter silently
    disappears.
    """
    return type("R", (), {"headers": {}, "query": dict(query or {}), "environ": {}})()


def _point_app_at_coverage(monkeypatch: pytest.MonkeyPatch, directory: Path) -> Any:
    """Point the app at a coverage directory and return the mock request.

    ``RECOVERAGE_DB`` names the directory, which is the one seam both halves of
    the read path resolve through: ``server``'s freshness stats and ``api``'s
    target list.
    """
    import recoverage.api as api
    import recoverage.server as server_mod

    req = _fake_request()
    monkeypatch.setenv("RECOVERAGE_DB", str(directory))
    # Both modules bind `request` at import time, and every header read goes
    # through server._header, so a fake that patched only api.request left the
    # real (empty) request answering Accept-Encoding.
    monkeypatch.setattr(api, "request", req)
    monkeypatch.setattr(server_mod, "request", req)
    return req


class TestDataMarkerFilter:
    """GLOBAL/DATA/VTABLE/STRING rows are data, not functions.

    The marker crosses the document boundary as text, so an absent one arrives
    as ``""`` and lands on the function side — the same verdict rebrew's own
    ``NOT NULL DEFAULT 'FUNCTION'`` column gives.  A filter that dropped the
    unmarked row would silently hide every function from the list, from the
    Potato table and from the by-status counts.
    """

    def _doc(self, tmp_path: Any) -> Path:
        return _game_coverage(
            tmp_path,
            functions=(
                {
                    "va": 0x1000,
                    "name": "_fn",
                    "vaStart": "0x1000",
                    "size": 1,
                    "status": "exact",
                    "markerType": "FUNCTION",
                },
                {
                    "va": 0x1010,
                    "name": "_unmarked",
                    "vaStart": "0x1010",
                    "size": 1,
                    "status": "exact",
                },
                {
                    "va": 0x1020,
                    "name": "_gvar",
                    "vaStart": "0x1020",
                    "size": 1,
                    "status": "exact",
                    "markerType": "GLOBAL",
                },
            ),
        )

    def test_list_keeps_unmarked_functions(self, tmp_path: Any, monkeypatch: Any) -> None:
        import recoverage.api as api

        _point_app_at_coverage(monkeypatch, self._doc(tmp_path))
        body = json.loads(api.handle_api_functions_list("GAME"))
        assert {fn["name"] for fn in body["functions"]} == {"_fn", "_unmarked"}
        assert body["total"] == 2

    def test_by_status_counts_unmarked_functions(self, tmp_path: Any, monkeypatch: Any) -> None:
        import recoverage.api as api

        _point_app_at_coverage(monkeypatch, self._doc(tmp_path))
        body = json.loads(api.handle_api_stats("GAME"))
        assert body["functions_by_status"] == {"exact": 2}


class TestDataSectionBuckets:
    """/data reports a bucket row for every section the document carries.

    The SQLite era preferred a materialized ``section_cell_stats`` cache and
    re-aggregated the sections it omitted, which a presence check missed; the
    document stores cells, so the buckets are always derived from them and no
    section can be dropped.
    """

    #: (section, start, end, state) cells, two sections so a dropped one is
    #: visible.
    CELLS: ClassVar[tuple[tuple[str, int, int, str], ...]] = (
        (".text", 0x1000, 0x1004, "exact"),
        (".data", 0x2000, 0x2002, "none"),
    )

    def _doc(self, tmp_path: Any) -> Path:
        return _game_coverage(tmp_path, cells=self.CELLS)

    def test_every_section_gets_buckets(self, tmp_path: Any, monkeypatch: Any) -> None:
        import recoverage.api as api

        _point_app_at_coverage(monkeypatch, self._doc(tmp_path))
        buckets = json.loads(api.handle_api_data("GAME"))["section_cell_stats"]
        assert set(buckets) == {".text", ".data"}
        assert buckets[".text"]["total_cells"] == 1
        assert buckets[".data"]["none"] == 1

    def test_section_filtered_payload_keeps_the_named_section(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """``?section=`` narrows the cells, not the section set: the one section
        it names is exactly the one a dropped bucket would hide."""
        import recoverage.api as api
        import recoverage.server as server_mod

        _point_app_at_coverage(monkeypatch, self._doc(tmp_path))
        req = _fake_request({"section": ".data"})
        monkeypatch.setattr(api, "request", req)
        monkeypatch.setattr(server_mod, "request", req)
        body = json.loads(api.handle_api_data("GAME"))
        assert body["section_cell_stats"][".data"]["none"] == 1

    def test_builder_derives_buckets_from_the_snapshot(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """The payload builder needs no materialized stats: it derives every
        bucket from the snapshot's own cells rather than raising over a missing
        cache object."""
        import recoverage.api as api

        directory = self._doc(tmp_path)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        payload = json.loads(api._build_data_raw(load_coverage(tmp_path, "GAME"), "GAME", None))
        assert set(payload["section_cell_stats"]) == {".text", ".data"}
        assert payload["section_cell_stats"][".text"]["total_cells"] == 1


class TestDataPayloadMemo:
    """/api/targets/<t>/data memoises the assembled payload per DB fingerprint.

    The endpoint materialises all cells + search index + stats on every
    cache-missing request; the memo (keyed on db mtime_ns/size) serves
    repeat requests without re-querying, and is cleared on rebuild.
    """

    def _make_db(self, tmp_path: Any) -> Any:
        return _game_coverage(tmp_path)

    def _patch(self, tmp_path: Any, monkeypatch: Any) -> Any:
        """Point the app at a synthetic coverage directory and return the mock
        request."""
        import recoverage.api as api

        req = _point_app_at_coverage(monkeypatch, self._make_db(tmp_path))
        api._clear_data_cache()
        return req

    def test_memo_serves_second_request_and_clears(self, tmp_path: Any, monkeypatch: Any) -> None:
        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)

        resp1 = api.handle_api_data("GAME")
        assert isinstance(resp1, bytes)
        assert len(api._DATA_CACHE) == 1
        key = next(iter(api._DATA_CACHE))
        # deepcopy, not dict(): a memo hit writes the stored body back into the
        # entry in place, so a shallow copy would be compared against itself.
        entry_before = copy.deepcopy(api._DATA_CACHE[key])

        # Second request: a memo hit serves the stored body verbatim, so the
        # bytes must be identical and the entry must survive the call. Checking
        # the key the first request actually wrote proves the hit came from
        # the memo rather than from a rebuild under a fresh key.
        resp2 = api.handle_api_data("GAME")
        assert resp2 == resp1
        assert api._DATA_CACHE.get(key) == entry_before
        assert set(api._DATA_CACHE) == {key}

        # Rebuild invalidation path.
        api._clear_data_cache()
        assert len(api._DATA_CACHE) == 0

    def test_memo_self_invalidates_on_db_change(self, tmp_path: Any, monkeypatch: Any) -> None:
        """A document fingerprint change (rebuild) must empty the memo — a memo
        keyed on a constant would pass the explicit-clear test above."""

        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)

        api.handle_api_data("GAME")
        assert len(api._DATA_CACHE) == 1
        # Simulate a rebuild that changed the document: the token keys on
        # the bytes, so the rewrite has to move them.
        doc = api._db_path() / "coverage-GAME.toml"
        doc.write_text(doc.read_text(encoding="utf-8") + "# rebuilt\n", encoding="utf-8")
        api.handle_api_data("GAME")
        # A constant fingerprint would still hold ONE key; two keys prove
        # the snapshot is fingerprint-sensitive (the changed bytes produced
        # a different cache key, a miss rather than a stale hit).
        assert len(api._DATA_CACHE) == 2

    def test_a_rebuild_that_rewrote_the_same_bytes_keeps_the_memo_and_the_etag(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """rebrew replaces every document on every build, and a build that
        changed nothing writes identical bytes.  That rewrite must not cost a
        rebuilt payload or a full re-download: the memo keeps its one entry
        and the old validator still answers 304."""
        import recoverage.api as api

        monkeypatch.setenv("RECOVERAGE_DB", str(self._make_db(tmp_path)))
        api._clear_data_cache()
        status, headers, _ = wsgi_get("/api/targets/GAME/data")
        assert status.startswith("200")
        etag = _header(headers, "ETag")
        assert len(api._DATA_CACHE) == 1

        # A new file renamed over the old one, as rebrew's atomic write does:
        # new inode, new mtime, same bytes.
        doc = api._db_path() / "coverage-GAME.toml"
        tmp = doc.with_name(doc.name + ".tmp")
        tmp.write_bytes(doc.read_bytes())
        st = doc.stat()
        os.utime(tmp, ns=(st.st_atime_ns + 2 * 10**9, st.st_mtime_ns + 2 * 10**9))
        tmp.replace(doc)

        status, _, body = wsgi_get("/api/targets/GAME/data", headers={"If-None-Match": etag})
        assert status == "304 Not Modified"
        assert body == b""
        status, _, _ = wsgi_get("/api/targets/GAME/data")
        assert status.startswith("200")
        assert len(api._DATA_CACHE) == 1

    def test_memo_stores_per_encoding_bodies(self, tmp_path: Any, monkeypatch: Any) -> None:
        """A memo hit must serve the stored per-encoding body instead of
        recompressing the multi-MB payload on every request, and an unseen
        Accept-Encoding must mint its variant from the stored raw JSON."""
        import gzip as gzip_mod

        import zstandard as zstd_mod

        import recoverage.api as api

        req = self._patch(tmp_path, monkeypatch)

        # First request (zstd): populates the memo.
        req.headers["Accept-Encoding"] = "zstd"
        body1 = api.handle_api_data("GAME")
        assert isinstance(body1, bytes)

        # Same encoding again: served bytes are byte-identical (no recompute).
        body2 = api.handle_api_data("GAME")
        assert body2 == body1

        # A new encoding mints its variant from the stored raw JSON.
        req.headers["Accept-Encoding"] = "gzip"
        body3 = api.handle_api_data("GAME")
        assert gzip_mod.decompress(body3) == zstd_mod.ZstdDecompressor().decompress(body1)

        # Identity encoding serves the raw JSON itself.
        req.headers.clear()
        body4 = api.handle_api_data("GAME")
        assert "sections" in json.loads(body4)

        # One fingerprint holds all variants.
        assert len(api._DATA_CACHE) == 1
        entry = next(iter(api._DATA_CACHE.values()))
        assert set(entry) == {"raw", "", "zstd", "gzip"}

    def test_memo_rejects_payload_built_under_a_moved_watermark(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """A build that finishes after a rebuild must not publish.

        The memo key's snapshot is taken before the queries run, so a rebuild
        committing mid-build leaves the payload pre-rebuild while the key says
        post-rebuild.  The db-updated broadcast has already cleared the memo by
        then, so publishing would serve the stale payload to the very refetch
        herd the broadcast woke — until the next rebuild.  The response itself
        is still produced; only the cache write is declined.
        """
        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(api, "_snapshot_db_mtime", _sequential_snapshot([(1, 1), (2, 2)]))

        body = api.handle_api_data("GAME")
        assert isinstance(body, bytes) and b'"sections"' in body
        assert api._DATA_CACHE == {}

    def test_memo_publishes_when_the_watermark_holds(self, tmp_path: Any, monkeypatch: Any) -> None:
        """The watermark re-check must not disable the memo: an unchanged DB
        re-stats to the same snapshot and the payload is cached as before."""
        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(api, "_snapshot_db_mtime", _sequential_snapshot([(7, 7), (7, 7)]))

        api.handle_api_data("GAME")
        assert len(api._DATA_CACHE) == 1

    def test_stats_memo_rejects_payload_built_under_a_moved_watermark(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """Same watermark contract for the /stats memo, which aggregates the
        whole cells table and would otherwise pin pre-rebuild counts."""
        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(api, "_snapshot_db_mtime", _sequential_snapshot([(1, 1), (2, 2)]))

        body = api.handle_api_stats("GAME")
        assert isinstance(body, bytes) and b'"sections"' in body
        assert api._STATS_CACHE == {}

    def test_derived_cache_clear_spares_spa_shell(self, tmp_path: Any, monkeypatch: Any) -> None:
        """_clear_derived_caches (the db-updated / regen invalidation path)
        must empty every DB-derived cache but leave the SPA shell cache
        alone: the shell is built purely from static assets and never goes
        stale on a rebuild, so dropping it would only re-read + re-minify +
        re-compress it under INDEX_LOCK on the next request."""
        import recoverage.api as api
        import recoverage.server as server_mod
        import recoverage.ui as ui

        self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(ui, "CACHED_INDEX_PAYLOAD", b"shell-bytes")
        monkeypatch.setattr(ui, "CACHED_INDEX_COMPRESSED", {"gzip": b"shell-gz"})
        api._DATA_CACHE[((123, 456), "GAME", None)] = {"raw": b"{}"}
        api._STATS_CACHE[(123, "GAME")] = {"summary": {}, "sections": {}, "by_status": {}}

        api._clear_derived_caches()

        assert len(api._DATA_CACHE) == 0
        assert len(api._STATS_CACHE) == 0
        assert server_mod._RESOLVED_TARGETS_CACHE is None
        assert ui.CACHED_INDEX_PAYLOAD == b"shell-bytes"
        assert ui.CACHED_INDEX_COMPRESSED == {"gzip": b"shell-gz"}

    def test_derived_cache_clear_drops_the_potato_grid_memo(self) -> None:
        """The Potato grid memo is api's to invalidate and potato's to own,
        so the composition root wires the two together (webapp registers
        potato.clear_cells_cache). Without that registration a rebuild would
        keep serving the previous build's grid from a route that never learns
        the documents moved, which is the stale-panel bug the shared entry
        point exists to prevent."""
        import recoverage.api as api
        import recoverage.potato as potato

        assert potato.clear_cells_cache in api._EXTRA_INVALIDATORS

        calls: list[int] = []

        def record() -> None:
            calls.append(1)

        api.register_cache_invalidator(record)
        try:
            api._clear_derived_caches()
        finally:
            api._EXTRA_INVALIDATORS.remove(record)
        assert calls == [1]

    def _gated_open(
        self,
        tmp_path: Any,
        monkeypatch: Any,
        release: threading.Event,
        query: dict[str, str] | None = None,
    ) -> tuple[Any, list[int], dict[str, str]]:
        """Patch the coverage read to record every call and park the FIRST
        caller on *release* — freezing the payload build mid-flight so the test
        can observe what concurrent requests do while a build is in progress.

        Also installs thread-independent request/response stand-ins for both
        the ``server`` and ``api`` namespaces: worker threads have no bottle
        request context (thread-local), and the compression/ETag helpers
        resolve those names from server's while ``api._query_param`` resolves
        its own.  Both modules import the one thread-local proxy, so under a
        real request the two names always agree; the stand-ins are separate
        objects, so a test that exercises a ``?section=`` (or any other)
        parameter has to install them in both or the handler would build the
        unfiltered payload.  *query* rides on the stand-in, and the stand-in's
        ``query`` dict is returned so a test can assert on it."""
        import recoverage.api as api
        import recoverage.server as server_mod

        self._patch(tmp_path, monkeypatch)

        open_calls: list[int] = []
        lock = threading.Lock()
        # The payload build reads the target's snapshot through
        # server.coverage_for, which is the one read the build cannot skip.
        real_coverage_for = server_mod.coverage_for

        def counting_coverage_for(t: str) -> Any:
            with lock:
                open_calls.append(1)
                first = len(open_calls) == 1
            if first:
                assert release.wait(timeout=15), "builder parked forever reading coverage"
            return real_coverage_for(t)

        monkeypatch.setattr(server_mod, "coverage_for", counting_coverage_for)

        fake_req: Any = _fake_request(query)
        query = fake_req.query
        fake_resp: Any = type(
            "R", (), {"content_type": None, "set_header": lambda self, k, v: None}
        )()
        # The query-carrying stand-in replaces the one _point_app_at_coverage
        # installed, and it has to go into BOTH namespaces: api._query_param
        # reads request.query from api's globals, and server's header helpers
        # read request.headers from server's. Installing it only in server left
        # a worker thread's ?section= filter invisible to the handler, so the
        # follower built the unfiltered payload under a different memo key and
        # never saw the in-flight build it was supposed to wait on.
        monkeypatch.setattr(api, "request", fake_req)
        monkeypatch.setattr(server_mod, "request", fake_req)
        monkeypatch.setattr(server_mod, "response", fake_resp)
        # api._query_param resolves `request` in api's own namespace (see its
        # docstring), so the stand-in has to be installed there too.  Patching
        # only the server module left the handler reading bottle's empty
        # thread-local, so a `?section=` filter never reached the memo key.
        monkeypatch.setattr(api, "request", fake_req)
        monkeypatch.setattr(api, "response", fake_resp)
        return api, open_calls, query

    def test_concurrent_cold_misses_single_flight(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Simultaneous cold misses share ONE payload build.

        A rebuild broadcast clears the memo and wakes every SSE client, which
        all refetch /data at once; without single-flight each of those misses
        re-runs the full-table queries + serialization.  The first builder is
        frozen inside the coverage read while the rest arrive: each must come
        back with identical bytes having read the documents zero extra times."""
        import recoverage.api as api

        release = threading.Event()
        _, open_calls, _ = self._gated_open(tmp_path, monkeypatch, release)

        workers = 4
        barrier = threading.Barrier(workers + 1)
        results: list[Any] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=15)
                results.append(api.handle_api_data("GAME"))
            except BaseException as exc:  # surfaced below, not swallowed
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for t in threads:
            t.start()
        barrier.wait(timeout=15)

        # Give the followers time to reach the checkout point while the
        # builder sits frozen in the coverage read; a duplicate build would show
        # up as a second read.
        time.sleep(0.3)
        assert len(open_calls) <= 1, "concurrent cold miss started a duplicate build"
        release.set()

        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive(), "worker hung waiting on the build event"

        assert not errors
        assert len(results) == workers
        assert all(isinstance(r, bytes) for r in results)
        assert all(r == results[0] for r in results)
        assert len(open_calls) == 1
        # Every registered build event drains when its owner finishes.
        assert api._DATA_CACHE_BUILDING == {}
        assert len(api._DATA_CACHE) == 1

    def test_follower_waits_for_inflight_build_without_touching_db(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """A request arriving while another thread's build is registered must
        park on the build event — it must not run its own queries."""
        import recoverage.api as api

        never = threading.Event()
        _, open_calls, _ = self._gated_open(tmp_path, monkeypatch, never)
        snap = api._snapshot_db_mtime()
        assert snap is not None
        key: tuple[tuple[int, int], str, None, bool] = (snap, "GAME", None, True)
        built = threading.Event()
        api._DATA_CACHE_BUILDING[key] = (
            built,
            api.clock.monotonic() + api._DATA_CACHE_BUILD_WAIT_SECONDS,
        )

        outcome: list[Any] = []

        def follower() -> None:
            outcome.append(api.handle_api_data("GAME"))

        t = threading.Thread(target=follower)
        t.start()
        try:
            try:
                t.join(timeout=1.0)
                assert t.is_alive(), "follower did not wait for the in-flight build"
                assert open_calls == [], "follower read coverage despite an in-flight build"
                api._DATA_CACHE[key] = {"raw": b'{"memoized": true}'}
            finally:
                built.set()
            t.join(timeout=15)
            assert not t.is_alive(), "follower never woke"
            assert outcome == [b'{"memoized": true}']
            assert open_calls == []
        finally:
            # Both maps are process-global: drop the hand-inserted entry and
            # the manually registered event the way an owner's finally would,
            # so neither leaks into a later test as a real payload.
            api._DATA_CACHE.pop(key, None)
            api._DATA_CACHE_BUILDING.pop(key, None)

    def test_follower_survives_leader_404(self, tmp_path: Any, monkeypatch: Any) -> None:
        """A follower parked on an in-flight build whose owner short-circuits
        (unknown ?section= 404) must wake, find no memo, and produce its own
        404 — not hang, not serve a stale/empty payload."""
        import recoverage.api as api

        release = threading.Event()
        # The section filter is read by api._query_param, which resolves
        # `request` from the *api* module globals, so the stand-in carrying
        # it has to be patched there; a request stand-in on the server module
        # alone would leave the handler building the unfiltered payload and
        # this test would pass on the wrong path. The ETag/compression helpers
        # resolve it from the server globals, so _gated_open installs the one
        # query-carrying stand-in in both namespaces and the follower computes
        # the same memo key this test registers.
        _, open_calls, _ = self._gated_open(tmp_path, monkeypatch, release, {"section": "nope"})
        api._clear_data_cache()

        snap = api._snapshot_db_mtime()
        assert snap is not None
        key: tuple[tuple[int, int], str, str | None, bool] = (snap, "GAME", "nope", True)
        built = threading.Event()
        api._DATA_CACHE_BUILDING[key] = (
            built,
            api.clock.monotonic() + api._DATA_CACHE_BUILD_WAIT_SECONDS,
        )

        outcome: list[Any] = []

        def follower() -> None:
            try:
                outcome.append(("returned", api.handle_api_data("GAME")))
            except Exception as exc:
                outcome.append(("raised", exc))

        t = threading.Thread(target=follower)
        try:
            t.start()
            t.join(timeout=0.3)
            assert t.is_alive(), "follower did not wait for the in-flight build"
            assert open_calls == [], "follower read coverage despite an in-flight build"
            built.set()
            release.set()  # the follower's own build may now read the documents
            t.join(timeout=15)
            assert not t.is_alive(), "404 path deadlocked the follower"
            kind, resp = outcome[0]
            # The unknown-section 404 is raised by _build_data_raw (a raised
            # HTTPResponse is what bottle renders as the response); the direct
            # call observes the raised shape.  Either way the follower must
            # see its own 404, never a stale/empty payload.
            assert kind == "raised" and str(resp.status).startswith("404")
            # Exactly one build ran: the follower's own. A leader build here
            # would mean the follower joined an in-flight payload instead.
            assert open_calls == [1]
            assert api._DATA_CACHE == {}
        finally:
            # The event is process-global state no thread owns (the leader
            # that would have set it never ran), so a failure above must not
            # strand it for a later test.
            built.set()
            api._DATA_CACHE_BUILDING.pop(key, None)

    def test_a_killed_leader_claim_is_reclaimed_not_waited_on_again(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """A leader killed between checkout and its finally leaves a claim with
        no owner: the next request must take it over, not park on its Event.

        The pre-fix claim had no deadline at all, so a leader that never
        reached its finally kept the key registered for the life of the
        process.  Every later request for that key waited the full
        ``_DATA_CACHE_BUILD_WAIT_SECONDS`` on an Event nobody would ever set,
        the single-flight guard was permanently off for it, and the entry
        itself never drained.  The claim now carries the instant it stops
        being answerable, so the request after the kill is a leader again.
        """
        import recoverage.api as api

        release = threading.Event()
        _, open_calls, _ = self._gated_open(tmp_path, monkeypatch, release)
        api._clear_data_cache()

        snap = api._snapshot_db_mtime()
        assert snap is not None
        key: tuple[tuple[int, int], str, None, bool] = (snap, "GAME", None, True)
        # A leader that was killed: registered, never set, never released.
        # The deadline is already past, so the next checkout must drop it.
        dead = threading.Event()
        api._DATA_CACHE_BUILDING[key] = (dead, api.clock.monotonic() - 1.0)
        owned: threading.Event | None = None
        try:
            start = time.monotonic()
            entry, owned = api._data_cache_checkout(key)
            waited = time.monotonic() - start
            assert entry is None, "served a payload from a leader that never published one"
            assert owned is not None, "a reclaimed key must be handed to its new leader"
            assert waited < 1.0, f"waited {waited:.1f}s on a dead leader's Event"
            # Reclaimed, not joined: the key's claim is the new one.
            claim = api._DATA_CACHE_BUILDING.get(key)
            assert claim is not None and claim[0] is owned
            assert claim[0] is not dead
        finally:
            if owned is not None:
                api._data_cache_build_done(key, owned)
            api._DATA_CACHE_BUILDING.pop(key, None)
        assert api._DATA_CACHE_BUILDING == {}
        assert open_calls == []

    def test_a_claim_left_by_a_killed_leader_never_blocks_the_request_path(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """The same claim reached through ``handle_api_data``: the request that
        follows a killed leader serves its own payload, and the claim drains.

        The unit test above pins the checkout; this one pins that the handler
        releases what it was handed, so a reclaim is not just a re-registration
        that the next process restart inherits.
        """
        import recoverage.api as api

        release = threading.Event()
        _, open_calls, _ = self._gated_open(tmp_path, monkeypatch, release)
        api._clear_data_cache()

        snap = api._snapshot_db_mtime()
        assert snap is not None
        key: tuple[tuple[int, int], str, None, bool] = (snap, "GAME", None, True)
        dead = threading.Event()
        api._DATA_CACHE_BUILDING[key] = (dead, api.clock.monotonic() - 1.0)
        release.set()
        try:
            body = api.handle_api_data("GAME")
            assert isinstance(body, bytes) and body.startswith(b"{")
            assert open_calls == [1]
            assert api._DATA_CACHE_BUILDING == {}
        finally:
            api._DATA_CACHE.pop(key, None)
            api._DATA_CACHE_BUILDING.pop(key, None)

    def test_a_claim_whose_leader_is_alive_is_not_reclaimed(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """A leader inside its deadline keeps the key: the next request is a
        follower that waits, which is the whole point of the single-flight."""
        import recoverage.api as api

        release = threading.Event()
        _, open_calls, _ = self._gated_open(tmp_path, monkeypatch, release)
        api._clear_data_cache()

        snap = api._snapshot_db_mtime()
        assert snap is not None
        key: tuple[tuple[int, int], str, None, bool] = (snap, "GAME", None, True)
        live = threading.Event()
        api._DATA_CACHE_BUILDING[key] = (
            live,
            api.clock.monotonic() + api._DATA_CACHE_BUILD_WAIT_SECONDS,
        )

        outcome: list[Any] = []

        def follower() -> None:
            outcome.append(api.handle_api_data("GAME"))

        t = threading.Thread(target=follower)
        try:
            t.start()
            t.join(timeout=0.3)
            assert t.is_alive(), "a live leader's claim was reclaimed out from under it"
            assert open_calls == [], "follower read coverage despite an in-flight build"
            live.set()
            release.set()
            t.join(timeout=15)
            assert not t.is_alive(), "follower never woke"
            assert len(outcome) == 1
            # The follower published a payload but claims nothing: only the
            # leader releases its own claim, so the live leader's Event is
            # still the key's claim rather than one the follower took over.
            assert open_calls == [1]
            assert key in api._DATA_CACHE
            claim = api._DATA_CACHE_BUILDING.get(key)
            assert claim is not None and claim[0] is live
        finally:
            live.set()
            api._DATA_CACHE.pop(key, None)
            api._DATA_CACHE_BUILDING.pop(key, None)


class TestFunctionListTotalMemo:
    """The function list's ``total`` is memoized on the coverage snapshot.

    The same contract every other coverage-derived memo follows: the change
    token is stat'ed BEFORE the read snapshot is loaded, and a value whose
    watermark moved is served but never filed.  A count filed under a
    fingerprint newer than the rows it counted outlives the broadcast's clear
    and is served to every later list request until the next rebuild.
    """

    def _patch(self, tmp_path: Any, monkeypatch: Any) -> Any:
        """Point the app at a synthetic coverage directory, memo emptied."""
        import recoverage.api as api

        req = _point_app_at_coverage(
            monkeypatch,
            _game_coverage(
                tmp_path,
                functions=(
                    {"va": 0x1000, "name": "f1", "status": "exact", "size": 16},
                    {"va": 0x2000, "name": "f2", "status": "stub", "size": 8},
                ),
            ),
        )
        api._clear_list_total_cache()
        return req

    def test_token_is_statted_before_the_snapshot_is_read(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """A rebuild committing between the token and the read must not be
        memoized.

        The endpoint reads build A's snapshot while a rebuild commits build B
        to the documents, so the fingerprint the memo would be filed under
        describes rows the DB no longer holds: every later list request
        answers build A's count until the next rebuild, and the
        db-updated broadcast's clear has already run.
        """
        import recoverage.api as api
        import recoverage.server as server_mod

        self._patch(tmp_path, monkeypatch)
        # Build A, read into a frozen snapshot; the documents move to build B
        # at the moment the endpoint goes looking for them.
        build_a = server_mod.coverage_for("GAME")

        def racing_coverage_for(t: str) -> Any:
            _game_coverage(
                tmp_path,
                functions=(
                    {"va": 0x1000, "name": "f1", "status": "exact", "size": 16},
                    {"va": 0x2000, "name": "f2", "status": "stub", "size": 8},
                    {"va": 0x3000, "name": "f3", "status": "exact", "size": 4},
                ),
            )
            return build_a

        monkeypatch.setattr(server_mod, "coverage_for", racing_coverage_for)

        body = json.loads(api.handle_api_functions_list("GAME"))
        # The response is one build's count over that build's rows, which is
        # what the endpoint owes its caller whatever the DB does mid-read.
        assert body["total"] == 2
        assert len(body["functions"]) == 2
        assert api._LIST_TOTAL_CACHE == {}

    def test_memo_declines_publish_under_a_moved_watermark(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """A rebuild committing after the token was taken: serve, never file."""
        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(api, "_snapshot_db_mtime", _sequential_snapshot([(1, 1), (2, 2)]))

        body = json.loads(api.handle_api_functions_list("GAME"))
        assert body["total"] == 2
        assert api._LIST_TOTAL_CACHE == {}

    def test_memo_publishes_and_serves_when_the_watermark_holds(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """An unchanged DB re-stats to the same token: the memo is kept and
        the second request's total comes from it."""
        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(api, "_snapshot_db_mtime", _sequential_snapshot([(7, 7), (7, 7)]))

        api.handle_api_functions_list("GAME")
        assert len(api._LIST_TOTAL_CACHE) == 1
        key = next(iter(api._LIST_TOTAL_CACHE))
        assert key[0] == (7, 7) and key[1] == "GAME"

        body = json.loads(api.handle_api_functions_list("GAME"))
        assert body["total"] == 2
        assert len(api._LIST_TOTAL_CACHE) == 1


class TestFunctionListPaging:
    """A page is a window on the sorted set, and the window is all that is served.

    The endpoint selects the rows the page needs rather than ordering the whole
    match set, so a 200 carrying plausible names no longer proves the ordering:
    the window has to be the one a full sort would have produced, for every
    column, both directions, and at every offset including one past the end.
    The fixture ties on ``name`` and on ``size`` throughout, so a selection
    that broke a tie differently from the stable sort is visible here.
    """

    ROWS = 40
    PAGE = 5

    @staticmethod
    def _rows() -> list[dict[str, Any]]:
        """The document's rows, in the document's own (ascending va) order."""
        return [
            {
                "va": 0x1000 + i * 0x10,
                "name": f"fn_{i % 5:02d}",
                "status": "exact" if i % 2 else "stub",
                "size": None if i % 7 == 0 else 16 + (i % 3) * 8,
            }
            for i in range(TestFunctionListPaging.ROWS)
        ]

    @classmethod
    def _sortable(cls) -> list[SimpleNamespace]:
        """The same rows shaped like the ``Function`` the sort key reads."""
        return [SimpleNamespace(**row) for row in cls._rows()]

    def _page(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, query: str) -> list[str]:
        import recoverage.api as api

        directory = _game_coverage(tmp_path, functions=tuple(self._rows()))
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        api._clear_list_total_cache()
        status, headers, body = wsgi_get(f"/api/targets/GAME/functions?{query}")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["total"] == self.ROWS
        return [str(fn["name"]) for fn in data["functions"]]

    @pytest.mark.parametrize("field", ["va", "name", "status", "size"])
    @pytest.mark.parametrize("direction", ["asc", "desc"])
    @pytest.mark.parametrize("offset", [0, 1, 7, 30, 39, 40])
    def test_the_window_is_the_one_a_full_sort_gives(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        field: str,
        direction: str,
        offset: int,
    ) -> None:
        from operator import attrgetter

        served = self._page(
            monkeypatch, tmp_path, f"sort={field}:{direction}&limit={self.PAGE}&offset={offset}"
        )
        # The order is spelled out here rather than taken from
        # `server.function_sort_key`, which is the key the handler sorts with:
        # comparing the two is true by construction, and every case above
        # passes on a key whose NULL handling or tie-break is wrong.  The
        # `size` arm pins the documented contract: an unknown size sorts
        # BEFORE every known one, and never compares against an int.
        rows = self._sortable()
        if field == "size":
            key: Callable[[Any], Any] = lambda r: (r.size is not None, r.size or 0)  # noqa: E731
        else:
            key = attrgetter(field)
        ordered = sorted(rows, key=key, reverse=direction == "desc")
        expected = [row.name for row in ordered[offset : offset + self.PAGE]]
        assert served == expected
        assert len(served) == max(0, min(self.PAGE, self.ROWS - offset))

    def test_an_offset_past_the_end_is_an_empty_page(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        assert self._page(monkeypatch, tmp_path, "sort=va&limit=5&offset=100") == []

    def test_a_filtered_page_is_windowed_over_the_match_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The selection runs over the FILTERED rows, so the set the total
        counts and the order the page is windowed in have to be the same one."""
        import recoverage.api as api

        directory = _game_coverage(tmp_path, functions=tuple(self._rows()))
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        api._clear_list_total_cache()
        status, headers, body = wsgi_get(
            "/api/targets/GAME/functions?search=fn_0&sort=name:desc&limit=3&offset=2"
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        matched = [row for row in self._sortable() if "fn_0" in row.name]
        assert data["total"] == len(matched)
        assert [fn["name"] for fn in data["functions"]] == [
            row.name for row in sorted(matched, key=attrgetter("name"), reverse=True)[2:5]
        ]


def _header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup (Bottle sends 'Etag', tests use 'ETag')."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


class TestApiEtagContract:
    """Hashed ETag + If-None-Match 304 round-trip on the /data route."""

    def test_stats_etag_roundtrip(self) -> None:
        """Every DB-derived read endpoint revalidates, /stats included: it is
        a pure function of the DB snapshot and the target, so a polling
        consumer must be able to get a 304 rather than re-run the
        SECTION_STATS_SQL aggregation."""
        target = require_target()
        status, headers, _ = wsgi_get(f"/api/targets/{target}/stats")
        assert status.startswith("200")
        etag = _header(headers, "ETag")
        assert etag and etag.startswith('"') and etag.endswith('"')
        assert "no-store" not in _header(headers, "Cache-Control")
        status, headers, body = wsgi_get(
            f"/api/targets/{target}/stats", headers={"If-None-Match": etag}
        )
        assert status == "304 Not Modified"
        assert body == b""

    def test_stats_etag_differs_from_data_etag(self) -> None:
        """The two same-snapshot routes must not share a validator, or a
        client that revalidated /stats could cache the /data body under it."""
        target = require_target()
        _, stats_headers, _ = wsgi_get(f"/api/targets/{target}/stats")
        _, data_headers, _ = wsgi_get(f"/api/targets/{target}/data")
        assert _header(stats_headers, "ETag") != _header(data_headers, "ETag")

    def test_data_etag_roundtrip(self) -> None:
        target = require_target()
        status, headers, _ = wsgi_get(f"/api/targets/{target}/data")
        assert status.startswith("200")
        etag = _header(headers, "ETag")
        assert etag and etag.startswith('"') and etag.endswith('"')
        # Replay with If-None-Match -> 304, empty body.
        status, headers, body = wsgi_get(
            f"/api/targets/{target}/data", headers={"If-None-Match": etag}
        )
        assert status == "304 Not Modified"
        assert body == b""

    def test_data_etag_differs_by_section(self) -> None:
        target = require_target()
        _, h1, _ = wsgi_get(f"/api/targets/{target}/data")
        _, h2, _ = wsgi_get(f"/api/targets/{target}/data?section=.text")
        assert _header(h1, "ETag") != _header(h2, "ETag")

    def test_functions_list_etag_roundtrip(self) -> None:
        """The function list is a pure function of the snapshot and its query
        string, so it revalidates like /stats and /data instead of answering
        no-store. A polling client must be able to skip the page."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, _ = wsgi_get(f"/api/targets/{target}/functions?limit=2")
        assert status.startswith("200")
        etag = _header(headers, "ETag")
        assert etag and etag.startswith('"') and etag.endswith('"')
        assert "no-store" not in _header(headers, "Cache-Control")
        status, headers, body = wsgi_get(
            f"/api/targets/{target}/functions?limit=2", headers={"If-None-Match": etag}
        )
        assert status == "304 Not Modified"
        assert body == b""

    def test_functions_list_etag_covers_every_query_parameter(self) -> None:
        """A tag that ignored the page it paged would answer 304 for a page the
        client never received: one per input, so each change moves the tag."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        base = f"/api/targets/{target}/functions"
        variants = [
            "",
            "?limit=1",
            "?offset=1",
            "?sort=name:desc",
            "?status=EXACT",
            "?search=_func",
        ]
        tags = set()
        for suffix in variants:
            _, headers, _ = wsgi_get(f"{base}{suffix}")
            tag = _header(headers, "ETag")
            assert tag, suffix
            tags.add(tag)
        assert len(tags) == len(variants), "two different pages share one validator"

    def test_function_detail_etag_roundtrip(self) -> None:
        """The single-function read is a pure function of the snapshot, the
        target and the requested spelling, so it revalidates like every other
        DB-derived read. It used to be the one that could only answer no-store:
        a client watching a cell re-downloaded the row on every poll."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        path = f"/api/targets/{target}/functions/0x10001000"
        status, headers, _ = wsgi_get(path)
        assert status.startswith("200")
        etag = _header(headers, "ETag")
        assert etag and etag.startswith('"') and etag.endswith('"')
        assert "no-store" not in _header(headers, "Cache-Control")
        status, headers, body = wsgi_get(path, headers={"If-None-Match": etag})
        assert status == "304 Not Modified"
        assert body == b""

    def test_function_detail_etag_differs_per_spelling(self) -> None:
        """The tag is over the requested spelling, not the row it resolves to:
        two URLs that answer the same function stay separate identities, and a
        tag from one can never 304 a body the client never received."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        base = f"/api/targets/{target}/functions"
        tags = set()
        for va in ("0x10001000", str(0x10001000), "0x10001030", "_func_a"):
            _, headers, _ = wsgi_get(f"{base}/{va}")
            tag = _header(headers, "ETag")
            assert tag, va
            tags.add(tag)
        assert len(tags) == 4, "two spellings of one row share a validator"

    def test_function_detail_etag_differs_from_the_list(self) -> None:
        """Same snapshot, different route: a client that revalidated the list
        page must not cache the detail row under the list's validator."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        _, list_headers, _ = wsgi_get(f"/api/targets/{target}/functions?limit=1")
        _, detail_headers, _ = wsgi_get(f"/api/targets/{target}/functions/0x10001000")
        assert _header(list_headers, "ETag") != _header(detail_headers, "ETag")

    def test_304_carries_the_vary_of_the_body_it_stands_in_for(self) -> None:
        """Every revalidating body here is content-negotiated, so the 304
        names Accept-Encoding too: a shared cache keyed without it would hand
        a compressed body to a client that accepted none."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        for path in (
            f"/api/targets/{target}/data",
            f"/api/targets/{target}/stats",
            f"/api/targets/{target}/functions",
        ):
            _, headers, _ = wsgi_get(path)
            etag = _header(headers, "ETag")
            assert _header(headers, "Vary") == "Accept-Encoding", path
            status, headers, body = wsgi_get(path, headers={"If-None-Match": etag})
            assert status == "304 Not Modified", path
            assert _header(headers, "Vary") == "Accept-Encoding", path
            assert body == b"", path

    def test_unknown_section_404s(self) -> None:
        """/data?section=<unknown> must 404 (was a silent empty grid)."""
        target = require_target()
        status, _, body = wsgi_get(f"/api/targets/{target}/data?section=.nosuch")
        assert status.startswith("404")
        payload = json.loads(decode_body(body, {}))
        assert payload.get("code") == "not_found"


class TestRegenMetrics:
    """/api/health reports the regen pipeline's own state.

    A regen is the one request that runs for minutes: the RED counters can say
    one request is still in flight but not that it is a rebuild, how long the
    last one took, or whether failures are climbing.  A dashboard whose
    Reload button does nothing must be distinguishable from one whose pipeline
    is broken, and both from one nobody asked to rebuild.
    """

    @pytest.fixture(autouse=True)
    def _reset(self) -> None:
        import recoverage.api as api
        from recoverage import metrics

        api._regen_last_attempt = None
        api._REGEN_COMPLETED_KEYS.clear()
        metrics.REGEN.reset()
        yield
        metrics.REGEN.reset()

    def _health_regen(self) -> dict:
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200"), status
        return json.loads(decode_body(body, headers))["regen"]

    def _post(self) -> tuple[str, dict[str, str], bytes]:
        return wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")

    def test_successful_run_is_counted_with_its_duration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "run_regen", lambda root: None)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        assert_regen_accepted(self._post())
        regen = self._health_regen()
        assert regen["runs"] == 1
        assert regen["failures"] == 0
        assert regen["in_flight"] == 0
        assert regen["last_ok"] is True
        assert regen["last_duration_ms"] >= 0.0

    def test_failed_run_counts_a_failure_and_reports_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.api as api

        def boom(root: Path) -> None:
            raise ValueError("corrupt JSON")

        monkeypatch.setattr(api, "run_regen", boom)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        status, _headers, _body = self._post()
        assert status.startswith("500")
        regen = self._health_regen()
        assert regen["runs"] == 1
        assert regen["failures"] == 1
        assert regen["last_ok"] is False
        assert regen["in_flight"] == 0

    def test_interrupted_run_closes_the_in_flight_gauge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A BaseException out of the pipeline must not strand the gauge.

        ``in_flight`` is a gauge, so an arm that lets a non-Exception through
        (Ctrl+C at the terminal running ``serve``, a SystemExit from inside
        rebrew) leaves it reading 1 for the rest of the process: /api/health
        then reports a rebuild that is not running, and every later reading is
        one ahead of the truth.
        """
        import recoverage.api as api
        from recoverage import metrics

        def interrupted(root: Path) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(api, "run_regen", interrupted)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        with pytest.raises(KeyboardInterrupt):
            api._do_regen("127.0.0.1")
        assert metrics.REGEN.snapshot()["in_flight"] == 0
        assert metrics.REGEN.snapshot()["last_ok"] is False
        assert self._health_regen()["in_flight"] == 0

    def test_cooldown_rejection_is_counted_separately_from_a_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A refused POST is not a failed run.

        The SPA throttles Reload clicks, so refusals are routine; counting them
        as failures would report a broken pipeline for a double-clicked button.
        """
        import recoverage.api as api

        monkeypatch.setattr(api, "run_regen", lambda root: None)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        assert_regen_accepted(self._post())
        status, _headers, _body = self._post()
        assert status.startswith("429")
        regen = self._health_regen()
        assert regen["rejected"] == 1
        assert regen["failures"] == 0
        assert regen["runs"] == 1

    def test_duration_comes_from_the_injected_clock(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The recorded duration is a multiple of the fake step, so a real
        wall-clock read could not have produced it, and the log line names it."""
        import logging as _logging

        import recoverage.api as api

        reads = [0]

        def _fake_monotonic() -> float:
            reads[0] += 1
            return 1.0 + 3.0 * reads[0]

        monkeypatch.setattr(api.clock, "monotonic", _fake_monotonic)
        monkeypatch.setattr(api, "run_regen", lambda root: None)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        with caplog.at_level(_logging.INFO, logger="recoverage"):
            assert_regen_accepted(self._post())
        regen = self._health_regen()
        assert regen["last_duration_ms"] % 3000.0 == 0.0
        assert any("Regen completed successfully in" in r.getMessage() for r in caplog.records)
        # The counter says how many runs failed; the fields say which run and
        # how long it took, so the two can be pivoted between.
        done = next(
            r for r in caplog.records if "Regen completed successfully in" in r.getMessage()
        )
        fields = getattr(done, _server.LOG_FIELDS_ATTR)
        assert fields["event"] == "regen"
        assert fields["outcome"] == "ok"
        assert fields["duration_s"] > 0.0

    def test_in_flight_is_visible_while_the_run_holds_the_lock(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A hung rebuild is the failure the request counters cannot show:
        /api/regen sits in flight forever with no request row to explain it."""
        import recoverage.api as api

        release = threading.Event()
        entered = threading.Event()

        def slow(root: Path) -> None:
            entered.set()
            release.wait(5.0)

        monkeypatch.setattr(api, "run_regen", slow)
        monkeypatch.setattr(api, "_project_dir", lambda: Path("/nonexistent"))
        worker = threading.Thread(
            target=lambda: wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1"),
            daemon=True,
        )
        worker.start()
        try:
            assert entered.wait(5.0), "the regen never started"
            assert self._health_regen()["in_flight"] == 1
        finally:
            release.set()
            worker.join(5.0)
        assert self._health_regen()["in_flight"] == 0


class TestHealthStreams:
    """/api/health reports SSE saturation and whether the poller is alive.

    Every connected stream pins a server thread, and the cap answers 503 to the
    one after it: an operator looking at a dashboard that stopped live-updating
    needs the connection count, not a healthy-looking 200.
    """

    def test_streams_reported_before_any_client_connects(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200"), status
        streams = json.loads(decode_body(body, headers))["streams"]
        assert streams["clients"] == 0
        assert streams["max_clients"] == api._SSE_MAX_CLIENTS
        # Not started yet is not a fault, so it must not read as one.
        assert streams["watcher_alive"] is None

    def test_client_count_tracks_the_connected_streams(self) -> None:
        import recoverage.api as api

        api._stop_db_watcher()
        try:
            _, _, _, result = wsgi_stream("/api/events", max_chunks=1)
            try:
                status, headers, body = wsgi_get("/api/health")
                assert status.startswith("200"), status
                streams = json.loads(decode_body(body, headers))["streams"]
                assert streams["clients"] == 1
                assert streams["watcher_alive"] is True
            finally:
                if result is not None:
                    result.close()
        finally:
            api._stop_db_watcher()

    def test_health_degrades_when_a_connected_client_has_no_poller(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A registered client with a dead poller is stale data served as a
        healthy 200: every page renders, none of them ever refreshes."""
        import recoverage.api as api

        with api._SSE_CLIENTS_LOCK:
            api._SSE_CLIENTS[queue.Queue(maxsize=api._SSE_QUEUE_MAX)] = "test-peer"
        try:
            monkeypatch.setattr(api, "_DB_WATCHER_THREAD", _DeadThread(), raising=False)
            status, headers, body = wsgi_get("/api/health")
            assert status.startswith("200"), status
            data = json.loads(decode_body(body, headers))
            assert data["status"] == "degraded"
            assert data["streams"]["watcher_alive"] is False
        finally:
            with api._SSE_CLIENTS_LOCK:
                api._SSE_CLIENTS.clear()


class _DeadThread:
    """Stands in for a watcher thread that has stopped without unregistering."""

    def is_alive(self) -> bool:
        return False


class TestHealthConnectionCap:
    """/api/health reports the connection cap, the widest saturation bound.

    A server at this cap answers 503 to every new request, including a fresh
    tab, while the connections already open keep rendering. Health read
    "healthy" through that: the documents were fine and the SSE streams were
    within their own cap. The gauge is what turns a refused client into a
    diagnosable server.
    """

    def test_connection_gauge_is_reported_before_any_connection(self) -> None:
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200"), status
        connections = json.loads(decode_body(body, headers))["connections"]
        assert connections["open"] == 0
        assert connections["refused"] == 0
        # No cap has been exercised yet, so none is reported: a mounted WSGI
        # app that never reached serve is not enforcing one.
        assert connections["max"] == 0

    def test_a_refusal_degrades_health_and_counts(self) -> None:
        from recoverage import metrics

        try:
            assert metrics.CONNECTIONS.admit(1) is True
            assert metrics.CONNECTIONS.admit(1) is False, "the cap did not refuse"
            status, headers, body = wsgi_get("/api/health")
            assert status.startswith("200"), status
            data = json.loads(decode_body(body, headers))
            assert data["connections"] == {"open": 1, "max": 1, "refused": 1}
            assert data["status"] == "degraded"
        finally:
            metrics.CONNECTIONS.release()
            metrics.CONNECTIONS.reset()


class TestSseClientCap:
    def test_excess_clients_get_503(self) -> None:
        """More concurrent /api/events clients than the cap must be rejected
        with 503 (thread-DoS guard)."""
        import recoverage.api as api

        with api._SSE_CLIENTS_LOCK:
            for _ in range(api._SSE_MAX_CLIENTS):
                api._SSE_CLIENTS[queue.Queue(maxsize=api._SSE_QUEUE_MAX)] = "test-peer"
        try:
            status, _, _ = wsgi_get("/api/events")
            assert status.startswith("503")
        finally:
            with api._SSE_CLIENTS_LOCK:
                api._SSE_CLIENTS.clear()

    def test_503_retry_after_header_matches_body(self) -> None:
        """The header and the body must state the same wait: a client that
        reads Retry-After (the auth throttle and /api/regen send the same
        header) must not be told a longer or shorter retry than the JSON.

        Exactly, and as an int: the cast form this replaced passed against a
        float the header spelled as an integer, so the key's JSON type was
        pinned to nothing and one client had to handle both.
        """
        import recoverage.api as api

        with api._SSE_CLIENTS_LOCK:
            for _ in range(api._SSE_MAX_CLIENTS):
                api._SSE_CLIENTS[queue.Queue(maxsize=api._SSE_QUEUE_MAX)] = "test-peer"
        try:
            status, headers, body = wsgi_get("/api/events")
            assert status.startswith("503")
            payload = json.loads(decode_body(body, headers))
            assert isinstance(payload["retry_after"], int)
            assert int(headers["Retry-After"]) == payload["retry_after"]
        finally:
            with api._SSE_CLIENTS_LOCK:
                api._SSE_CLIENTS.clear()


class TestDbWatcherResilience:
    """A failing watcher iteration must be logged and retried, not kill the thread."""

    def test_watcher_survives_broadcast_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        calls: list[tuple[int, int]] = []

        def flaky_broadcast(snapshot: tuple[int, int]) -> None:
            calls.append(snapshot)
            if len(calls) == 1:
                raise RuntimeError("boom")

        stop, thread = _start_watcher(
            api,
            monkeypatch,
            _sequential_snapshot([(111, 1), (222, 2), (333, 3)]),
            flaky_broadcast,
        )
        try:
            deadline = time.monotonic() + 2
            while len(calls) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            # First broadcast raised; the loop kept polling and delivered the
            # next change instead of dying silently.
            assert calls == [(222, 2), (333, 3)]
            assert thread.is_alive()
        finally:
            stop.set()
            thread.join(timeout=2)


class TestDataEndpointUnreadableCoverage:
    """/data must answer the shared 503 contract for unreadable coverage, like
    every other endpoint — an unreadable document is not a 500."""

    def test_data_503_when_the_documents_are_unreadable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import recoverage.api as api
        import recoverage.server as server_mod

        api._clear_data_cache()  # drop memo entries earlier tests left behind
        target = require_target()

        def _boom(_root: Path) -> dict[str, CoverageSnapshot]:
            raise CoverageTomlError("coverage-GAME.toml: malformed TOML")

        monkeypatch.setattr(server_mod, "load_all", _boom)
        status, _, body = wsgi_get(f"/api/targets/{target}/data")
        assert status.startswith("503"), body
        data = json.loads(decode_body(body, {}))
        assert data["code"] == "db_unavailable"


class TestKnownSchemaContract:
    """/data carries the accepted schema set, so the SPA's "schema not
    understood" wording tracks the server instead of a stale client copy."""

    def test_data_payload_lists_known_schema(self) -> None:
        from rebrew.coverage_toml import load_coverage_from

        from recoverage import server as server_mod

        target = require_target()
        status, _, body = wsgi_get(f"/api/targets/{target}/data")
        assert status.startswith("200")
        data = json.loads(decode_body(body, {}))
        # Read the document independently of `known_schema_versions`, which is
        # the call the handler makes: comparing the two is true by
        # construction, and an empty list would pass it.
        document = load_coverage_from(server_mod._db_path(), target)
        assert data["known_schema"] == [str(document.version)]
        assert data["known_schema"], "the payload tells the SPA it knows no schema"
        for sec in data["sections"].values():
            assert isinstance(sec["cells"], list)
            for served_cell in sec["cells"]:
                assert {"start", "end", "state"} <= served_cell.keys()

    def test_cells_omit_row_id(self) -> None:
        """No consumer reads cells.id, and as the only high-entropy column it
        cost 4.3x on the wire (322 KB -> 75 KB zstd on a 39k-cell section).
        Re-adding it would silently undo that, so pin the served key set."""
        target = require_target()
        status, _, body = wsgi_get(f"/api/targets/{target}/data")
        assert status.startswith("200")
        data = json.loads(decode_body(body, {}))
        seen = {k for sec in data["sections"].values() for cell in sec["cells"] for k in cell}
        assert seen and "id" not in seen
        # The spine every consumer reads is always present.  The remaining
        # fields (functions/label/parent_function) are OMITTED when they carry
        # no information. CELLS_JSON_OBJECT_SQL drops null and empty
        # values, so they cannot be asserted unconditionally here.
        assert {"start", "end", "span", "state"} <= seen


class TestServedCellsComeFromTheSnapshot:
    """The /data cells are the document's cells, through the ONE serializer.

    rebrew used to materialize a zstd ``section_cells_json`` cache beside the
    ``cells`` table, and the endpoint had to prefer it while falling back to a
    live query — two paths that had to agree byte for byte, and a stale-coded
    cache that had to be declined rather than mis-decoded.  The document IS the
    source now, so what is left to pin is that the endpoint renders every
    section through ``server.cells_json`` rather than encoding cells a second
    way.
    """

    @staticmethod
    def _doc(tmp_path: Path) -> Path:
        """Two sections with a mix of cell states, so a dropped or re-encoded
        cell is visible in the payload."""
        directory = coverage_dir(tmp_path)
        write_coverage(
            directory,
            "GAME",
            {
                ".text": {
                    "va": 0x1000,
                    "size": 32,
                    "fileOffset": 0x200,
                    "unitBytes": 16,
                    "columns": 8,
                    "cells": [
                        cell(0x1000, 0x1004, "exact", functions=("f",)),
                        cell(0x1004, 0x1008, "padding"),
                    ],
                },
                ".data": {
                    "va": 0x2000,
                    "size": 16,
                    "fileOffset": 0x1200,
                    "unitBytes": 16,
                    "columns": 8,
                    "cells": [cell(0x2000, 0x2004, "none")],
                },
            },
        )
        return directory

    def test_served_cells_are_the_document_cells(self, tmp_path: Path, monkeypatch: Any) -> None:
        import recoverage.server as srv

        directory = self._doc(tmp_path)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        snap = load_coverage(tmp_path, "GAME")
        status, headers, body = wsgi_get("/api/targets/GAME/data")
        assert status.startswith("200")
        sections = json.loads(decode_body(body, headers))["sections"]
        assert set(sections) == set(snap.sections)
        for name, section in snap.sections.items():
            assert sections[name]["cells"] == json.loads(srv.cells_json(section.cells))

    def test_served_cells_go_through_the_shared_serializer(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Guard the assertion above against passing vacuously.

        If the endpoint encoded cells some other way, poisoning the one
        serializer would change nothing and the equality test above would still
        pass on a payload the SPA's cell shape never came from.
        """
        import recoverage.api as api
        import recoverage.server as srv

        directory = self._doc(tmp_path)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        api._clear_data_cache()
        monkeypatch.setattr(srv, "cells_json", lambda cells: "[]")

        status, headers, body = wsgi_get("/api/targets/GAME/data")
        assert status.startswith("200")
        payload = json.loads(decode_body(body, headers))
        assert all(sec["cells"] == [] for sec in payload["sections"].values())


class TestDumpsWithCells:
    """The /data serializer splices sqlite json_group_array output instead of
    round-tripping cells through json.loads/dumps."""

    def test_splices_preencoded_arrays(self) -> None:
        from recoverage.api import _dumps_with_cells

        raw = _dumps_with_cells(
            {
                "target": "GAME",
                "sections": {".text": {"name": ".text", "va": 1}, ".data": {"name": ".data"}},
            },
            {".text": '[{"id":1,"state":"exact"}]'},
        )
        data = json.loads(raw)
        assert data["target"] == "GAME"
        assert data["sections"][".text"]["cells"] == [{"id": 1, "state": "exact"}]
        assert data["sections"][".text"]["va"] == 1
        assert data["sections"][".data"]["cells"] == []

    def test_empty_section_dict(self) -> None:
        from recoverage.api import _dumps_with_cells

        data = json.loads(_dumps_with_cells({"sections": {"x": {}}}, {"x": "[1]"}))
        assert data["sections"]["x"] == {"cells": [1]}

    def test_none_omits_cells_key(self) -> None:
        from recoverage.api import _dumps_with_cells

        data = json.loads(
            _dumps_with_cells(
                {"sections": {".text": {"va": 1}, ".data": {"va": 2}}},
                {".text": "[]", ".data": None},
            )
        )
        assert data["sections"][".text"]["cells"] == []
        assert "cells" not in data["sections"][".data"]
        assert data["sections"][".data"]["va"] == 2


class TestSectionFilterKeepsSiblings:
    """?section= omits sibling cell arrays but still lists every section."""

    def test_section_query_keeps_all_section_rows(self) -> None:
        target = require_target()
        status, _, body = wsgi_get(f"/api/targets/{target}/data?section=.text")
        assert status.startswith("200")
        data = json.loads(decode_body(body, {}))
        assert ".text" in data["sections"]
        assert isinstance(data["sections"][".text"].get("cells"), list)
        for name, sec in data["sections"].items():
            if name != ".text":
                assert "cells" not in sec


# ── Repo source-file serving (/src, /original) ─────────────────────


class TestRepoFileServing:
    """GET /src/<filepath> and /original/<filepath> must never escape the
    project root: bottle's static_file string-prefix check does not resolve
    symlinks, so ui.serve_repo_file re-resolves and verifies containment
    itself.  A regression there serves arbitrary host files."""

    def test_file_inside_root_is_served(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.c").write_text("int main(void) { return 0; }", encoding="utf-8")
        status, _headers, body = wsgi_get("/src/main.c")
        assert status.startswith("200")
        assert b"int main" in body

    def test_parent_traversal_blocked(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("top secret", encoding="utf-8")
        status, _, body = wsgi_get("/src/../secret.txt")
        assert status.startswith("403")
        assert b"top secret" not in body

    def test_encoded_traversal_blocked(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "secret.txt").write_text("top secret", encoding="utf-8")
        # The capture is the raw request path, so %2e%2e is decoded here,
        # before the containment check, and reaches it as ../.
        status, _, body = wsgi_get("/src/%2e%2e/secret.txt")
        assert status.startswith("403")
        assert b"top secret" not in body

    def test_symlink_escape_blocked(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A symlink INSIDE src/ pointing outside must be rejected even
        though its textual path stays under the root."""
        monkeypatch.chdir(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "passwd").write_text("root:x:0:0", encoding="utf-8")
        (tmp_path / "src").mkdir()
        try:
            (tmp_path / "src" / "escape").symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable (Windows without developer mode)")
        status, _, body = wsgi_get("/src/escape/passwd")
        assert status.startswith("403")
        assert b"root:x" not in body

    def test_rejections_answer_the_json_error_envelope(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A refused path is a JSON error, like every other failure.

        The traversal and NUL rejections used to answer a bare ``b"forbidden"``
        / ``b"not found"`` under ``text/html`` with no ``Cache-Control``, so a
        shared cache was free to store and replay the refusal, and a client
        parsing the server's error contract had a second format to special-case.
        """
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "secret.txt").write_text("top secret", encoding="utf-8")
        for path, want in (("/src/../secret.txt", 403), ("/src/%00evil", 404)):
            status, headers, body = wsgi_get(path)
            assert status.startswith(str(want)), path
            assert headers["Content-Type"].startswith("application/json"), path
            assert headers["Cache-Control"] == "no-store", path
            data = json.loads(decode_body(body, headers))
            assert set(data) >= {"error", "code", "detail"}, path
            assert b"top secret" not in body, path

    def test_a_refusal_is_logged_with_the_peer_and_the_path(
        self, tmp_path: Path, monkeypatch: Any, caplog: Any
    ) -> None:
        """A 403 on a file route writes an audit line, like the other refusals.

        The per-request line is DEBUG unless the request was slow, so a client
        walking out of the served tree (`/src/../../etc/passwd`) left nothing
        behind at all.  A bad `Host` header and a bad bearer token each write
        one; this is the third.  The path and the peer are escaped, so a
        request carrying a line break cannot forge entries.
        """
        import logging

        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            status, _headers, _body = wsgi_get("/src/..%2Fsecret.txt")
        assert status.startswith("403")
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("Refused GET" in m and "plain-relative" in m for m in warnings), warnings
        assert not any("\n" in m for m in warnings), warnings

    def test_encoded_filename_is_decoded_once(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A source file whose name holds a space or a non-ASCII character.

        The SPA links it as /src/<target>/<file> and the browser escapes it,
        so the capture arrives percent-encoded; without decoding, no such
        file is reachable.
        """
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "src"
        (src / "données").mkdir(parents=True)
        (src / "données" / "naïve name.c").write_text("int x;", encoding="utf-8")
        status, _headers, body = wsgi_get("/src/donn%C3%A9es/na%C3%AFve%20name.c")
        assert status.startswith("200")
        assert b"int x;" in body

    def test_decomposed_filename_is_found_from_the_composed_spelling(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """macOS stores the NFD spelling; the document and the SPA spell NFC.

        A tree written on macOS holds ``cafe`` + U+0301 + ``.c`` whatever the
        program that created it passed, so the composed path the request
        carries opens nothing and the code pane 404s a file that is on disk.
        """
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "src"
        directory = src / unicodedata.normalize("NFD", "données")
        directory.mkdir(parents=True)
        leaf = unicodedata.normalize("NFD", "naïve name.c")
        (directory / leaf).write_text("int x;", encoding="utf-8")
        # The composed spelling is what reaches the route, percent-encoded.
        status, _headers, body = wsgi_get("/src/donn%C3%A9es/na%C3%AFve%20name.c")
        assert status.startswith("200")
        assert b"int x;" in body

    def test_a_name_in_neither_form_still_404s(self, tmp_path: Path, monkeypatch: Any) -> None:
        """The spelling probe does not turn a missing file into a served one."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        status, _headers, _body = wsgi_get("/src/na%C3%AFve%20name.c")
        assert status.startswith("404")

    def test_double_encoded_traversal_blocked(self, tmp_path: Path, monkeypatch: Any) -> None:
        """%252e%252e decodes once to the text "%2e%2e", never to "..".

        Decoding twice would turn it into a parent reference after the
        containment check had already run on the once-decoded text.
        """
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "secret.txt").write_text("top secret", encoding="utf-8")
        status, _, body = wsgi_get("/src/%252e%252e/secret.txt")
        assert status.startswith(("403", "404"))
        assert b"top secret" not in body

    def test_original_prefix_serves_original_dir(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        orig = tmp_path / "original"
        orig.mkdir()
        (orig / "note.txt").write_text("original tree", encoding="utf-8")
        status, _, body = wsgi_get("/original/note.txt")
        assert status.startswith("200")
        assert b"original tree" in body


_ACCEPT_ALL_ENCODINGS = {"Accept-Encoding": "br, gzip, deflate, zstd"}


def _etag_of(headers: dict[str, str]) -> str:
    """The validator, whatever spelling bottle gave the header."""
    return next(value for key, value in headers.items() if key.lower() == "etag")


class TestRepoFileCompression:
    """The code panes download a whole `src/<target>` file on every
    selection, and `static_file` served those bytes raw: a 43 KB header went
    over the wire as 43 KB while every other body in the package is negotiated,
    compressed and validated. Measured on real headers, brotli/zstd takes that
    to about a quarter of the size, so the assertions below pin the contract
    rather than the ratio (the ratio is the compressor's, not this route's).

    The cases that must NOT be compressed are the point of half the class:
    compression here is a decision about the file, and a file the dashboard
    does not read as text, or one too small to benefit, is bottle's again.
    """

    @staticmethod
    def _project(tmp_path: Path, monkeypatch: Any) -> Path:
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "src" / "demo"
        src.mkdir(parents=True)
        return src

    def test_text_file_is_negotiated_and_decodes_to_the_file(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        src = self._project(tmp_path, monkeypatch)
        body = ("int func(int a) { return a * 2; }\n" * 200).encode()
        (src / "main.c").write_bytes(body)

        status, headers, wire = wsgi_get("/src/demo/main.c", _ACCEPT_ALL_ENCODINGS)

        assert status.startswith("200")
        assert headers["Content-Encoding"] in ("br", "zstd", "gzip")
        assert len(wire) < len(body)
        assert headers["Vary"] == "Accept-Encoding"
        assert decode_body(wire, headers) == body, "the compressed body is not the file"

    def test_revalidating_a_text_file_answers_304_with_no_body(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        src = self._project(tmp_path, monkeypatch)
        (src / "main.c").write_bytes(b"int x;\n" * 300)
        _status, headers, _body = wsgi_get("/src/demo/main.c", _ACCEPT_ALL_ENCODINGS)

        status, _headers, body = wsgi_get(
            "/src/demo/main.c",
            {**_ACCEPT_ALL_ENCODINGS, "If-None-Match": _etag_of(headers)},
        )

        assert status.startswith("304"), status
        assert body == b""

    def test_a_rewritten_file_gets_a_new_validator(self, tmp_path: Path, monkeypatch: Any) -> None:
        """The tag is over the content, not the stat: a rebuild replaces the
        bytes under the same path and the same mtime tick, and a validator that
        survived that would answer 304 for a file the pane never received."""
        src = self._project(tmp_path, monkeypatch)
        (src / "main.c").write_bytes(b"int a;\n" * 300)
        _status, headers, _body = wsgi_get("/src/demo/main.c", _ACCEPT_ALL_ENCODINGS)

        (src / "main.c").write_bytes(b"int bbbbbbbbbbbb;\n" * 300)
        status, _headers, body = wsgi_get(
            "/src/demo/main.c",
            {**_ACCEPT_ALL_ENCODINGS, "If-None-Match": _etag_of(headers)},
        )

        assert status.startswith("200"), status
        assert body != b""

    def test_a_file_below_the_floor_is_served_as_is(self, tmp_path: Path, monkeypatch: Any) -> None:
        """gzip's framing costs more than a 7-byte header can pay back."""
        src = self._project(tmp_path, monkeypatch)
        (src / "tiny.h").write_bytes(b"int x;\n")

        status, headers, body = wsgi_get("/src/demo/tiny.h", _ACCEPT_ALL_ENCODINGS)

        assert status.startswith("200")
        assert "Content-Encoding" not in headers
        assert body == b"int x;\n"

    def test_a_binary_suffix_is_left_to_bottle(self, tmp_path: Path, monkeypatch: Any) -> None:
        """`/original/<target>.dll` is a multi-megabyte PE re-read on every
        byte-pane selection: a per-request brotli at that size costs more CPU
        than the bandwidth it saves, so the suffix is not on the list."""
        src = self._project(tmp_path, monkeypatch)
        raw = bytes(range(256)) * 40
        (src / "demo.dll").write_bytes(raw)

        status, headers, body = wsgi_get("/src/demo/demo.dll", _ACCEPT_ALL_ENCODINGS)

        assert status.startswith("200")
        assert "Content-Encoding" not in headers
        assert body == raw

    def test_a_client_that_decodes_nothing_gets_the_raw_file(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        src = self._project(tmp_path, monkeypatch)
        body = b"int y;\n" * 300
        (src / "main.c").write_bytes(body)

        status, headers, wire = wsgi_get("/src/demo/main.c")

        assert status.startswith("200")
        assert "Content-Encoding" not in headers
        assert wire == body

    def test_a_range_request_still_reaches_bottle(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A Range asks for a window of the file on disk, which a compressed
        representation cannot describe, so the request is handed over whole."""
        src = self._project(tmp_path, monkeypatch)
        raw = b"0123456789abcdef" * 200
        (src / "main.c").write_bytes(raw)

        status, _headers, body = wsgi_get(
            "/src/demo/main.c", {**_ACCEPT_ALL_ENCODINGS, "Range": "bytes=0-15"}
        )

        assert status.startswith(("206", "200")), status
        assert raw[:16] in body

    def test_the_content_type_follows_the_file_not_the_host(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A pane's file gets the same header on every machine.

        The type used to come from `mimetypes.guess_type`, which answers from
        the HOST's database: `.c` is `text/plain` only because Linux ships an
        entry for it, `.def`/`.inc`/`.asm` had none at all and fell through to
        `application/octet-stream` — the one answer that says "download me"
        for a body this route had just decided was text.  Windows answers from
        the registry, so the same file arrived with a third header there.

        The type now follows the same suffix set that decided the file is text,
        so a served source file is text on every host and the header cannot
        disagree with the compression decision.
        """
        src = self._project(tmp_path, monkeypatch)
        for name in ("main.c", "header.h", "exports.def", "boiler.inc", "stub.asm"):
            (src / name).write_bytes(b"/* body */\n" * 200)

        for name in ("main.c", "header.h", "exports.def", "boiler.inc", "stub.asm"):
            status, headers, _body = wsgi_get(f"/src/demo/{name}", _ACCEPT_ALL_ENCODINGS)
            assert status.startswith("200"), name
            assert headers["Content-Type"].startswith("text/plain"), name

    def test_a_suffix_with_a_narrower_type_gets_it(self) -> None:
        """`.json` is not text/plain, and the pane still gets the precise type."""
        from recoverage.ui import _repo_file_type

        assert _repo_file_type(".json") == "application/json; charset=utf-8"
        assert _repo_file_type(".css") == "text/css; charset=utf-8"
        assert _repo_file_type(".c") == "text/plain; charset=utf-8"


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestVaOverflowValidation:
    """VAs beyond SQLite's INTEGER range must be rejected (or cleanly miss),
    never reach sqlite3 as an OverflowError 500."""

    def test_batch_rejects_huge_int_va(self) -> None:
        status, headers, body = wsgi_post(
            "/api/targets/FAKEDLL/functions", body=json.dumps({"vas": [2**70]})
        )
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert "out of range" in data["detail"]

    def test_batch_rejects_huge_hex_string_va(self) -> None:
        status, _, _ = wsgi_post(
            "/api/targets/FAKEDLL/functions", body=json.dumps({"vas": ["0x" + "f" * 30]})
        )
        assert status.startswith("400")

    def test_batch_accepts_signed_int64_max(self) -> None:
        """The boundary itself is valid input: a miss, not an error."""
        status, headers, body = wsgi_post(
            "/api/targets/FAKEDLL/functions", body=json.dumps({"vas": [2**63 - 1]})
        )
        assert status.startswith("200")
        # A miss is an empty result list; 2**63-1 is in no section, so any
        # entry here would be a row resolved from a truncated or wrapped VA.
        assert json.loads(decode_body(body, headers)) == []

    def test_get_function_huge_va_is_404_not_500(self) -> None:
        status, headers, body = wsgi_get(f"/api/targets/FAKEDLL/functions/{2**80}")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "not_found"

    def test_functions_offset_beyond_int64_clamped(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?offset={10**25}")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        # Clamped to the page ceiling; the resulting page is simply empty.
        assert data["functions"] == []


class TestCapstoneCapabilityProbe:
    """``find_spec`` says a capstone distribution is on the path; it does not
    say it loads.  A wheel for the wrong architecture, a missing libcapstone or
    a half-unpacked install passes the spec probe and fails on import, which
    used to reach the operator as a bare 500 with a traceback where the 501
    contract promises an answer, and as /api/health advertising an extra the
    process cannot use."""

    @staticmethod
    def _broken_install(monkeypatch: Any) -> None:
        """Present-but-unloadable: the distribution is on the path, the import
        is what fails.  ``None`` in ``sys.modules`` is the standard way to say
        "this module exists and cannot be loaded"."""
        import sys

        import recoverage.disasm as disasm

        monkeypatch.setattr(disasm, "_CAPSTONE_INSTALLED", True)
        monkeypatch.setattr(disasm, "_probed", False)
        monkeypatch.setattr(disasm, "_probe_reason", None)
        # A handle cached by an earlier test would short-circuit the probe.
        monkeypatch.setattr(disasm._CAPSTONE_MD_TLS, "md", None, raising=False)
        monkeypatch.setitem(sys.modules, "capstone", None)

    def test_probe_names_the_failure_and_memoizes(self, monkeypatch: Any) -> None:
        import recoverage.disasm as disasm

        self._broken_install(monkeypatch)

        reason = disasm.capstone_unavailable_reason()
        assert "ModuleNotFoundError" in reason
        assert not disasm.disassembly_available()
        # A broken install costs one failed import per process, not one per
        # request, and the verdict is stable for every later caller.
        assert disasm.capstone_unavailable_reason() == reason

    def test_missing_extra_is_reported_as_not_installed(self, monkeypatch: Any) -> None:
        import recoverage.disasm as disasm

        monkeypatch.setattr(disasm, "_CAPSTONE_INSTALLED", False)
        assert disasm.capstone_unavailable_reason() == "capstone is not installed"
        assert not disasm.disassembly_available()

    def test_unloadable_capstone_raises_instead_of_tracebacking(self, monkeypatch: Any) -> None:
        import recoverage.disasm as disasm

        self._broken_install(monkeypatch)
        with pytest.raises(disasm.CapstoneUnavailableError):
            disasm.get_capstone_md()

    def test_asm_answers_501_with_the_reason(self, monkeypatch: Any) -> None:
        import recoverage.api as api

        monkeypatch.setattr(
            api, "capstone_unavailable_reason", lambda: "OSError: libcapstone.so.5: cannot open"
        )
        status, headers, body = wsgi_get("/api/targets/FAKEDLL/asm?va=0x10001000&size=16")
        data = json.loads(decode_body(body, headers))
        assert status.startswith("501")
        assert data["code"] == "not_implemented"
        assert "capstone" in data["error"]
        # The operator gets WHICH failure, not a bare "not installed": the
        # install hint does not help someone whose capstone is already there.
        assert "libcapstone" in data["detail"]

    def test_health_does_not_advertise_an_unusable_extra(self, monkeypatch: Any) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "disassembly_available", lambda: False)
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["extras"]["capstone"] is False


class TestUnhandledErrorContract:
    """Unexpected (non-sqlite) exceptions must be visible in the log AND keep
    every surface's format contract: JSON on /api/*, HTML on UI routes.  The
    server runs wsgiref with quiet=True, so without the log line the failing
    endpoint is unidentifiable from a bare stderr traceback."""

    def test_api_500_is_json_and_logged(self, monkeypatch: Any, caplog: Any) -> None:
        import logging

        import recoverage.server as server_mod

        def boom(_root: Path) -> dict[str, CoverageSnapshot]:
            raise RuntimeError("exploding reader")

        # An unexpected (non-CoverageTomlError) failure anywhere under the read
        # path is what the 500 contract is about; the shared reader is the one
        # call every target-scoped endpoint makes.
        monkeypatch.setattr(server_mod, "load_all", boom)
        with caplog.at_level(logging.ERROR, logger="recoverage"):
            status, headers, body = wsgi_get("/api/targets/x/stats")
        assert status.startswith("500")
        assert headers.get("Content-Type", "").startswith("application/json")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "internal"
        assert data["error"] == "Internal server error"
        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert any("Unhandled error serving" in r.getMessage() for r in errors)
        assert any(r.exc_info is not None for r in errors)

    def test_500_log_escapes_control_chars_in_path(self, monkeypatch: Any, caplog: Any) -> None:
        """A newline decoded into the path (%0A on the wire) must not forge
        multi-line log entries when the 500 handler reports the failing
        request (log-forging defense — same _log_safe contract as the request
        hook and the 503 path).  The harness passes PATH_INFO through
        undecoded, so the raw control character goes straight into it."""
        import logging

        import recoverage.server as server_mod

        def boom(_root: Path) -> dict[str, CoverageSnapshot]:
            raise RuntimeError("exploding reader")

        monkeypatch.setattr(server_mod, "load_all", boom)
        forged_path = "/api/targets/br\n\nINJECTED: pwned/stats"
        with caplog.at_level(logging.ERROR, logger="recoverage"):
            wsgi_get(forged_path)
        errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
        assert any("Unhandled error serving" in m for m in errors), errors
        # No record may carry the forged second line; the offending bytes are
        # rendered as their \xNN escape so the request stays identifiable.
        assert not any("\nINJECTED" in m for m in errors), errors
        assert any("\\x0a" in m.lower() and "Unhandled error serving" in m for m in errors), errors

    def test_ui_500_stays_html(self, monkeypatch: Any) -> None:
        import recoverage.ui as ui

        def boom() -> bytes:
            raise RuntimeError("broken asset")

        monkeypatch.setattr(ui, "_build_index_payload", boom)
        monkeypatch.setattr(ui, "CACHED_INDEX_PAYLOAD", None)
        status, headers, body = wsgi_get("/")
        assert status.startswith("500")
        assert "text/html" in headers.get("Content-Type", "")
        assert b"Internal Server Error" in decode_body(body, headers)


class TestSectionStatsMemo:
    """/api/targets/<t>/stats memoises per document fingerprint + target.

    One request walks every cell of the target to aggregate its buckets; repeat
    callers (a polling consumer) must not re-pay that walk while the documents
    are unchanged, and a rebuild (fingerprint change) must never serve stale
    buckets.
    """

    def _make_db(self, tmp_path: Any, cells: tuple[tuple[str, int, int, str], ...]) -> Any:
        return _game_coverage(tmp_path, cells)

    def _patch(self, tmp_path: Any, monkeypatch: Any, directory: Any) -> Any:
        """Point the app at *directory* and return the mock request."""
        import recoverage.api as api

        req = _point_app_at_coverage(monkeypatch, directory)
        api._clear_stats_cache()
        return req

    def test_memo_hit_skips_the_read(self, tmp_path: Any, monkeypatch: Any) -> None:
        import recoverage.api as api
        import recoverage.server as server_mod

        directory = self._make_db(tmp_path, ((".text", 0, 16, "exact"), (".text", 16, 32, "none")))
        self._patch(tmp_path, monkeypatch, directory)

        # Count reads at the binding the request path consults: the handler
        # resolves the target's snapshot through server.coverage_for, so that is
        # the call a memo hit must not make.  The real reader is kept
        # underneath, so the counter sees production reads only.
        real_coverage_for = server_mod.coverage_for
        reads: list[str] = []

        def counting_coverage_for(target: str) -> Any:
            reads.append(target)
            return real_coverage_for(target)

        monkeypatch.setattr(server_mod, "coverage_for", counting_coverage_for)

        first = api.handle_api_stats("GAME")
        assert isinstance(first, bytes)
        assert reads, "the miss did not read coverage; the counter is not wired"
        reads_after_miss = len(reads)

        # The second request must not touch the documents at all: the read
        # count is the proof, since the memo answer required no snapshot.
        second = api.handle_api_stats("GAME")
        assert second == first
        assert len(reads) == reads_after_miss, "memo hit re-read the coverage"

        api._clear_stats_cache()
        assert len(api._STATS_CACHE) == 0

    def test_memo_self_invalidates_on_db_change(self, tmp_path: Any, monkeypatch: Any) -> None:
        """A rebuild must change the result: cells rewritten into the document
        plus a fingerprint bump produce fresh buckets; the snapshot keying (not
        an explicit clear) is what makes the fresh result visible."""
        import os

        import recoverage.api as api

        directory = self._make_db(tmp_path, ((".text", 0, 16, "exact"),))
        self._patch(tmp_path, monkeypatch, directory)

        body1 = json.loads(api.handle_api_stats("GAME"))
        assert body1["sections"][".text"]["total_cells"] == 1

        # Simulate a rebuild: the document is rewritten with one more cell,
        # which moves its bytes and so the change token every memo keys on.
        self._make_db(tmp_path, ((".text", 0, 16, "exact"), (".text", 16, 32, "exact")))
        doc = directory / "coverage-GAME.toml"
        st = doc.stat()
        os.utime(doc, ns=(st.st_atime_ns + 2 * 10**9, st.st_mtime_ns + 2 * 10**9))

        body2 = json.loads(api.handle_api_stats("GAME"))
        assert body2["sections"][".text"]["total_cells"] == 2
        # The stale pre-rebuild entry still sits under its own key until
        # eviction; the changed fingerprint produced a second cache entry.
        assert len(api._STATS_CACHE) == 2


class TestIndexWarmup:
    """ui.warm_index_cache pre-builds the SPA shell and every compressed
    variant off the request path so handle_index's first hit is a lookup."""

    def test_a_missing_shell_names_the_file_and_the_cause(
        self, monkeypatch: Any, tmp_path: Any, caplog: Any
    ) -> None:
        """The shell has no degraded form, so its read must say what is absent.

        Its two siblings (style.css, app.js) each degrade to an empty string,
        because a missing one leaves a page that still renders. index.html does
        not: without it there is no page. The bare FileNotFoundError it used to
        raise answered `/` as a 500 whose log entry named no file, which is the
        whole of what an operator has when a wheel arrives with the asset
        pruned.
        """
        import recoverage.ui as ui

        monkeypatch.setattr(ui, "_assets_dir", lambda: tmp_path)
        monkeypatch.setattr(ui, "CACHED_INDEX_PAYLOAD", None)
        monkeypatch.setattr(ui, "CACHED_INDEX_COMPRESSED", {})

        with pytest.raises(ui.MissingAssetError) as caught:
            ui._build_index_payload()
        message = str(caught.value)
        assert "index.html" in message
        # The cause rides along: the type and the OS's own message are what
        # tell a missing file from one this process cannot read.
        assert isinstance(caught.value.__cause__, FileNotFoundError)
        assert isinstance(caught.value, RuntimeError) and not isinstance(caught.value, OSError), (
            "a caller that keeps serving must be able to catch this and not an OSError"
        )

    def test_the_shell_inlines_the_bundle_byte_for_byte(self) -> None:
        """The served shell carries the built app.js unchanged.

        Vite already minifies the bundle.  A second pass with rjsmin, which
        does not parse template literals, dropped the leading space inside
        `` ` (${...})` `` and the detail panel printed "PM(Δ0 B)".
        """
        import recoverage.ui as ui

        bundle = (ui._assets_dir() / "app.js").read_text(encoding="utf-8")
        assert bundle.strip().encode("utf-8") in ui._build_index_payload()

    def test_warm_builds_payload_and_all_encodings(self, monkeypatch: Any) -> None:
        import recoverage.ui as ui

        monkeypatch.setattr(ui, "CACHED_INDEX_PAYLOAD", None)
        monkeypatch.setattr(ui, "CACHED_INDEX_COMPRESSED", {})

        ui.warm_index_cache()

        assert ui.CACHED_INDEX_PAYLOAD
        assert b"<html" in ui.CACHED_INDEX_PAYLOAD.lower()
        # One prebuilt variant per non-empty subset of the supported encodings,
        # plus the identity one, so a cold first hit from any client is a
        # lookup.  Keys name the accepted SET, because the shell is served as
        # the smallest body that set can decode rather than a fixed preference.
        assert set(ui.CACHED_INDEX_COMPRESSED) == {
            "",
            "zstd",
            "br",
            "gzip",
            "zstd, br",
            "zstd, gzip",
            "br, gzip",
            "zstd, br, gzip",
        }
        # The identity variant is the payload itself, sent uncompressed.
        body, encoding, _etag = ui.CACHED_INDEX_COMPRESSED[""]
        assert (body, encoding) == (ui.CACHED_INDEX_PAYLOAD, "")

    def test_shell_variant_is_the_smallest_body_the_client_accepts(self) -> None:
        """The precompressed shell must not hand a zstd-capable browser the
        larger zstd frame when brotli is smaller.

        Measured on the shipped shell, brotli q11 beats zstd at every level
        (14,075 bytes against 15,178 at zstd 19), and the zstd size sits above
        the initial congestion window.  A fixed zstd-first preference put every
        modern browser over that window and cost a second round trip before
        the first paint, for no decoding-speed gain on a one-off document.
        """
        import recoverage.ui as ui

        ui.warm_index_cache()

        all_three = ui.CACHED_INDEX_COMPRESSED["zstd, br, gzip"]
        br_only = ui.CACHED_INDEX_COMPRESSED["br"]
        assert all_three[1] == br_only[1]
        assert all_three[0] == br_only[0]
        assert len(all_three[0]) == min(
            len(body) for _k, (body, _e, _t) in ui.CACHED_INDEX_COMPRESSED.items()
        )

    def test_the_shipped_shell_fits_the_payload_budget(self) -> None:
        """The shell a browser receives must fit `ui._TCP_CWND_BUDGET`.

        Scoped to clients that accept brotli, because brotli is the smallest
        encoding here: zstd 19 and gzip 9 are both larger, so no preference
        order brings them under a budget brotli misses.  Every browser with
        zstd also has brotli, so this is the set that ships.

        The budget no longer has a protocol constant behind it: the frontend is
        one Preact + Tailwind bundle, whose measurement is quoted in
        `ui._TCP_CWND_BUDGET` and in docs/DESIGN.md, and which cannot fit
        RFC 6928's initial window.  The number in `ui.py` is a checked ceiling
        with headroom over that measurement, so a dependency that doubles the
        bundle fails here instead of shipping.  That is a ratchet only while
        something fails when it is crossed: _check_payload_budget WARNS (the
        next test), which is one log line nobody reads, and a warning is not a
        gate.  This is the gate.
        """
        import recoverage.ui as ui

        ui.warm_index_cache()

        brotli_bodies = [
            body
            for key, (body, _encoding, _etag) in ui.CACHED_INDEX_COMPRESSED.items()
            if "br" in key
        ]
        assert brotli_bodies, "no cached shell variant carries brotli"
        smallest = min(len(b) for b in brotli_bodies)
        assert smallest <= ui._TCP_CWND_BUDGET, (
            f"the inlined shell is {smallest} B, {smallest - ui._TCP_CWND_BUDGET} B over the "
            f"{ui._TCP_CWND_BUDGET} B budget; check what the bundle grew by "
            "(see docs/DESIGN.md, 'First Draw Without a Render-Blocking Request')"
        )

    def test_the_ratchet_reports_the_overage_of_the_served_body(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_check_payload_budget must measure the body a real browser receives,
        which is the smallest of the encodings it accepts, and must name the
        overage exactly when the shell no longer fits that window.

        The shipped shell fits (see the test above), so this pins the REPORT
        rather than the state: measured on an inflated payload, the overage it
        prints is the smallest served body's, and it names the budget too.  A
        ratchet that measured something nothing reproduces would read as a
        clean run while the shell sat over the window.
        """
        import recoverage.ui as ui
        from recoverage.server import (
            BROTLI_STATIC_QUALITY,
            GZIP_STATIC_LEVEL,
            ZSTD_STATIC_LEVEL,
            brotli,
            gzip,
            zstd,
        )

        ui.warm_index_cache()

        # An inflated payload stands in for a future shell that does not fit,
        # measured exactly as _check_payload_budget measures the real one: the
        # smallest of the three static encodings.  Random bytes, not a run of
        # one character, which every codec would compress back to nothing.
        inflated = ui.CACHED_INDEX_PAYLOAD + os.urandom(120_000)
        best = min(
            len(gzip.compress(inflated, compresslevel=GZIP_STATIC_LEVEL)),
            len(brotli.compress(inflated, quality=BROTLI_STATIC_QUALITY)),
            len(zstd.ZstdCompressor(level=ZSTD_STATIC_LEVEL).compress(inflated)),
        )
        over = best - ui._TCP_CWND_BUDGET
        assert over > 0, "the inflated payload still fits; inflate it by more"

        with caplog.at_level("WARNING", logger="recoverage"):
            caplog.clear()
            ui._check_payload_budget(inflated)
        assert caplog.records, f"the payload is {over} bytes over the budget and said nothing"
        assert str(over) in caplog.text
        assert str(ui._TCP_CWND_BUDGET) in caplog.text

    def test_warm_is_idempotent(self, monkeypatch: Any) -> None:
        import recoverage.ui as ui

        monkeypatch.setattr(ui, "CACHED_INDEX_PAYLOAD", None)
        monkeypatch.setattr(ui, "CACHED_INDEX_COMPRESSED", {})
        ui.warm_index_cache()
        snapshot = dict(ui.CACHED_INDEX_COMPRESSED)

        ui.warm_index_cache()

        assert snapshot == ui.CACHED_INDEX_COMPRESSED

    def test_warm_failure_is_logged_and_left_lazy(self, monkeypatch: Any, caplog: Any) -> None:
        import logging

        import recoverage.ui as ui

        monkeypatch.setattr(ui, "CACHED_INDEX_PAYLOAD", None)
        monkeypatch.setattr(ui, "CACHED_INDEX_COMPRESSED", {})

        def boom() -> bytes:
            raise OSError("asset gone")

        monkeypatch.setattr(ui, "_build_index_payload", boom)
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            ui.warm_index_cache()

        assert ui.CACHED_INDEX_PAYLOAD is None
        assert any("warm-up failed" in r.getMessage() for r in caplog.records)


# ── Routing error contract (/api/* stays JSON) ─────────────────────


class TestApiRoutingErrors:
    """The catch-all route must keep the 404/405 distinction.

    A catch-all that answers every miss with 404 also swallows the verb: a
    client that PATCHes a read-only resource, or GETs the POST-only
    /api/regen, is told the resource does not exist.  The error envelope is
    already right; the status code is what misleads.
    """

    def test_unknown_api_path_returns_json_404(self) -> None:
        status, headers, body = wsgi_get("/api/does-not-exist")
        assert status.startswith("404")
        assert headers["Content-Type"].startswith("application/json")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "not_found"
        assert "/api/does-not-exist" in data["detail"]

    def test_unknown_nested_api_path_returns_json_404(self) -> None:
        status, headers, body = wsgi_get("/api/targets/NOPE/functions/notaroute")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "not_found"

    def test_wrong_method_returns_json_405_with_allow(self) -> None:
        status, headers, body = wsgi_post("/api/health")
        assert status.startswith("405")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "method_not_allowed"
        # RFC 9110 15.5.6: a 405 must say what is allowed, and Bottle's
        # router omits the header, so the catch-all supplies it.
        allow = {m.strip() for m in headers["Allow"].split(",")}
        assert {"GET", "HEAD"} <= allow

    def test_allow_on_a_path_with_several_methods(self) -> None:
        status, headers, body = wsgi_request("DELETE", "/api/targets/NOPE/functions")
        assert status.startswith("405")
        allow = {m.strip() for m in headers["Allow"].split(",")}
        assert {"GET", "POST", "HEAD"} <= allow
        data = json.loads(decode_body(body, headers))
        assert "DELETE" in data["detail"]

    def test_get_on_the_post_only_regen_is_405(self) -> None:
        status, headers, _ = wsgi_get("/api/regen")
        assert status.startswith("405")
        allow = {m.strip() for m in headers["Allow"].split(",")}
        assert allow == {"POST"}

    def test_api_error_bodies_are_never_cached(self) -> None:
        status, headers, _ = wsgi_get("/api/does-not-exist")
        assert status.startswith("404")
        assert headers["Cache-Control"] == "no-store"

    def test_405_details_escape_control_characters(self) -> None:
        """The Allow/405 path reflects the request method, which is
        attacker-controlled; a raw control character would forge log lines
        and header content."""
        status, headers, body = wsgi_request("GET\nX", "/api/health")
        assert status.startswith("405")
        assert "\n" not in headers["Allow"]
        data = json.loads(decode_body(body, headers))
        assert "\n" not in data["detail"]


# ── /asm and /bytes validation detail ─────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestSliceValidationDetail:
    """Every 400 from the two binary-slice endpoints names the offending
    parameter and its accepted range.

    `error` alone ("invalid va or size", "invalid size") tells an API client
    which request failed but not which field to fix; `detail` carries the
    value that was rejected and the constraint it broke.
    """

    @pytest.fixture(autouse=True)
    def _capstone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api
        import recoverage.server as server

        monkeypatch.setattr(api, "capstone_unavailable_reason", lambda: None)
        self.dll = bytes((i % 251) for i in range(2048))
        monkeypatch.setattr(api, "_load_dll", lambda target: self.dll)
        # api's own _load_dll is only half the path: the text representation
        # renders through disasm.get_disassembly, which reads server's. Every
        # test in this class asserted a 400 raised BEFORE the load, so the
        # missing half went unnoticed and a request that got past validation
        # answered 422. Seed the shared cache both namespaces read (the
        # autouse _clean_derived_caches fixture empties it after each test).
        with server.DLL_LOCK:
            server.DLL_DATA["FAKEDLL"] = self.dll

    def test_asm_missing_param_names_which(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "missing va or size"
        assert "size" in data["detail"]
        assert "va" not in data["detail"].split("size")[0]

    def test_asm_bad_size_quotes_the_value(self) -> None:
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000&size=abc")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "invalid va or size"
        assert "abc" in data["detail"]

    def test_asm_unknown_format_rejected(self) -> None:
        """A typo'd representation must not silently return the text form."""
        target = require_target()
        status, headers, body = wsgi_get(
            f"/api/targets/{target}/asm?va=0x10001000&size=16&format=jsom"
        )
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"
        assert "jsom" in data["detail"]
        assert "json" in data["detail"]

    def test_asm_format_is_case_insensitive(self) -> None:
        """The representation name is normalized, so ?format=TEXT is the
        same request as ?format=text rather than a rejected one.

        `not 400` is a claim any 5xx satisfies, so the two spellings must
        answer 200 with the same disassembly, byte for byte.
        """
        target = require_target()
        lower = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000&size=16&format=text")
        upper = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000&size=16&format=TEXT")
        assert lower[0].startswith("200"), lower[0]
        assert upper[0].startswith("200"), upper[0]
        assert decode_body(upper[2], upper[1]) == decode_body(lower[2], lower[1])

    def test_asm_empty_format_is_the_default(self) -> None:
        target = require_target()
        query = f"/api/targets/{target}/asm?va=0x10001000&size=16"
        default = wsgi_get(query)
        empty = wsgi_get(f"{query}&format=")
        assert empty[0].startswith("200"), empty[0]
        assert decode_body(empty[2], empty[1]) == decode_body(default[2], default[1])

    def test_bytes_bad_size_quotes_the_value(self) -> None:
        status, headers, body = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size=abc"
        )
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "invalid size"
        assert "abc" in data["detail"]
        assert "4096" in data["detail"]

    def test_bytes_out_of_bounds_names_the_section_range(self) -> None:
        status, headers, body = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size=999999"
        )
        # Clamped to _MAX_SLICE_SIZE, which is inside the 0x1000 section.
        assert status.startswith("200")
        status, headers, body = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=4096&size=4"
        )
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "offset beyond section bounds"
        assert ".text" in data["detail"]

    def test_leading_zero_byte_counts_are_decimal(self) -> None:
        """A zero-padded count is decimal, not a base-0 literal.

        int(x, 0) rejects "064" outright, so a client that zero-pads a byte
        count got a 400 for a number the endpoint documents as valid.
        """
        assert api._parse_byte_count("064") == 64
        assert api._parse_byte_count("8") == 8
        status, _headers, _ = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size=016"
        )
        assert status.startswith("200")

    def test_byte_counts_reject_non_documented_bases(self) -> None:
        """Binary and octal spellings are not a documented byte count.

        int(x, 0) accepted both, so ?size=0b1000 silently served 8 bytes to a
        client that meant to send something this endpoint never promised.
        """
        for value in ("0b1000", "0o17"):
            with pytest.raises(ValueError, match="not an ASCII"):
                api._parse_byte_count(value)
        status, headers, body = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size=0b1000"
        )
        assert status.startswith("400")
        assert json.loads(decode_body(body, headers))["error"] == "invalid size"

    @pytest.mark.parametrize(
        "value",
        [
            "\u0664\u0660",  # ARABIC-INDIC DIGIT FOUR, ZERO
            "\uff11_\uff10",  # FULLWIDTH digits, which also carry an underscore
            "\u06f1\u06f0",  # EXTENDED ARABIC-INDIC digits
        ],
    )
    def test_byte_counts_reject_non_ascii_digits(self, value: str) -> None:
        """A byte count is ASCII digits, whatever digits the client's locale has.

        ``int()`` accepts every code point ``str.isdigit()`` calls a digit, so
        a 40-byte slice answered a request that named no such size in any
        spelling the endpoint documents.  ``config._ASCII_INT`` already holds
        the ``RECOVERAGE_*`` side to ASCII; the query string is the same
        number, so it gets the same rule.
        """
        with pytest.raises(ValueError, match="not an ASCII"):
            api._parse_byte_count(value)
        status, headers, body = wsgi_get(
            f"/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size={value}"
        )
        assert status.startswith("400")
        assert json.loads(decode_body(body, headers))["error"] == "invalid size"

    def test_page_parameters_reject_non_ascii_digits(self) -> None:
        """?limit= and ?offset= fall back to their defaults, never to a foreign digit."""
        assert api._page_int("50") == 50
        for value in ("\u0665\u0660", "1_0", "+5"):
            with pytest.raises(ValueError, match="not an ASCII"):
                api._page_int(value)

    def test_batch_vas_reject_non_ascii_hex_digits(self) -> None:
        """A batch VA is ASCII hex; Arabic-Indic digits parsed as one before."""
        status, headers, body = wsgi_post(
            "/api/targets/FAKEDLL/functions",
            body=json.dumps({"vas": ["\u0661\u0660"]}),
        )
        assert status.startswith("400")
        assert json.loads(decode_body(body, headers))["code"] == "bad_request"

    def test_hex_prefixed_byte_counts_still_parse(self) -> None:
        assert api._parse_byte_count("0x40") == 64
        assert api._parse_byte_count(" 0X40 ") == 64
        status, _headers, _ = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=0&size=0x10"
        )
        assert status.startswith("200")

    def test_negative_offset_is_still_rejected(self) -> None:
        status, headers, body = wsgi_get(
            "/api/targets/FAKEDLL/sections/.text/bytes?offset=-1&size=4"
        )
        assert status.startswith("400")
        assert json.loads(decode_body(body, headers))["error"] == "invalid offset"


# ── URL component decoding ─────────────────────────────────────────


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestUnicodeUrlComponents:
    """A target id or section name with a space or a non-ASCII character.

    Bottle routes on PATH_INFO exactly as the WSGI server hands it over, so
    a browser's percent-escapes reach the handler still encoded: the DB
    lookup compared "caf%C3%A9" against "café" and 404'd.  Query values are
    the mirror image, decoded as latin-1, so "section=%C3%A9" arrived as
    "Ã©" while Potato Mode's parse_qs on the same request produced "é".
    """

    TARGET = "café & bar"
    SECTION = ".données"

    @pytest.fixture(autouse=True)
    def _unicode_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        write_coverage(
            coverage_dir(tmp_path),
            self.TARGET,
            {
                self.SECTION: {
                    "va": 0x10003000,
                    "size": 0x100,
                    "fileOffset": 0x300,
                    "unitBytes": 16,
                    "columns": 8,
                    "cells": [
                        cell(0x10003000, 0x10003010, "exact"),
                        cell(0x10003010, 0x10003020, "none"),
                    ],
                }
            },
            functions=[
                {
                    "va": 0x10003000,
                    "name": "func_é",
                    "vaStart": "0x10003000",
                    "size": 16,
                    "status": "EXACT",
                }
            ],
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(coverage_dir(tmp_path)))
        from recoverage.api import _clear_derived_caches

        _clear_derived_caches()

    def _enc(self, value: str) -> str:
        from urllib.parse import quote

        return quote(value, safe="")

    def test_stats_resolves_the_encoded_target(self) -> None:
        status, headers, body = wsgi_get(f"/api/targets/{self._enc(self.TARGET)}/stats")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert self.SECTION in data["sections"]

    def test_data_resolves_the_encoded_section(self) -> None:
        status, headers, body = wsgi_get(
            f"/api/targets/{self._enc(self.TARGET)}/data?section={self._enc(self.SECTION)}"
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert list(data["sections"]) == [self.SECTION]

    def test_function_list_search_matches_the_decoded_name(self) -> None:
        status, headers, body = wsgi_get(
            f"/api/targets/{self._enc(self.TARGET)}/functions?search={self._enc('é')}"
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [f["name"] for f in data["functions"]] == ["func_é"]

    def test_potato_renders_the_encoded_target(self) -> None:
        status, _, body = wsgi_get(
            f"/potato?target={self._enc(self.TARGET)}&section={self._enc(self.SECTION)}"
        )
        assert status.startswith("200")
        assert "café".encode() in body
        assert self.SECTION.encode("utf-8") in body


# ── Search folding ──────────────────────────────────────────────────

#: NFC, and the NFD spelling of the same name (e + U+0301).
#: NFC_ONLY has no NFD twin in the table, so a folded lookup that resolves it
#: has exactly one row it could have matched; SHARP_S_NAME is a global whose
#: name casefolds to an ASCII spelling.
NFC_ONLY = "naïve_render"
SHARP_S_NAME = "g_straße"
NFC_NAME = "caf\u00e9_render"
NFD_NAME = "cafe\u0301_render"


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestSearchCaseFolding:
    """A name the operator can read must be findable by typing it.

    SQLite's ``LIKE`` folds case for ASCII only, so ``CAFÉ`` missed
    ``Café_Render`` and an NFD spelling missed its NFC twin: the search box
    reported "no matches" for a symbol sitting in the table beside it.  Both
    search surfaces now add a folded disjunct (server.fold_text = NFC +
    casefold) whenever the term carries a non-ASCII character.
    """

    TARGET = "FOLDDBL"
    SECTION = ".text"

    @pytest.fixture(autouse=True)
    def _fold_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        write_coverage(
            coverage_dir(tmp_path),
            self.TARGET,
            {
                self.SECTION: {
                    "va": 0x10003000,
                    "size": 0x100,
                    "fileOffset": 0x300,
                    "unitBytes": 16,
                    "columns": 8,
                    "cells": [
                        cell(0x10003000 + i * 16, 0x10003000 + (i + 1) * 16, "exact")
                        for i in range(3)
                    ],
                }
            },
            # The NFD row is what a macOS-side tool writes; the user pastes the
            # NFC spelling they see in a symbol table.
            functions=[
                {
                    "va": 0x10003000,
                    "name": NFC_NAME,
                    "vaStart": "0x10003000",
                    "size": 16,
                    "status": "EXACT",
                },
                {
                    "va": 0x10003010,
                    "name": NFD_NAME,
                    "vaStart": "0x10003010",
                    "size": 16,
                    "status": "EXACT",
                },
                {
                    "va": 0x10003020,
                    "name": "_plain_ascii",
                    "vaStart": "0x10003020",
                    "size": 16,
                    "status": "EXACT",
                },
                {
                    "va": 0x10003030,
                    "name": NFC_ONLY,
                    "vaStart": "0x10003030",
                    "size": 16,
                    "status": "EXACT",
                },
            ],
            globals_=[
                {
                    "va": 0x10004000,
                    "name": SHARP_S_NAME,
                    "decl": "int g_strasse",
                    "module": "T",
                    "size": 4,
                }
            ],
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(coverage_dir(tmp_path)))
        from recoverage.api import _clear_derived_caches

        _clear_derived_caches()

    def _search(self, term: str) -> list[str]:
        from urllib.parse import quote

        status, headers, body = wsgi_get(
            f"/api/targets/{self.TARGET}/functions?search={quote(term, safe='')}"
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        return [f["name"] for f in data["functions"]]

    def _lookup(self, name: str) -> tuple[str, dict[str, Any]]:
        """GET /functions/<name> for a name typed by a user, percent-encoded."""
        from urllib.parse import quote

        status, headers, body = wsgi_get(
            f"/api/targets/{self.TARGET}/functions/{quote(name, safe='')}"
        )
        return status, json.loads(decode_body(body, headers))

    def test_nfd_name_opens_the_row_search_found(self) -> None:
        """The row the search box highlighted must open when named the way the
        user spells it.  The name-form lookup compared bytes, so the NFD
        spelling macOS puts on the clipboard 404'd a row stored in NFC."""
        status, data = self._lookup(unicodedata.normalize("NFD", NFC_ONLY))
        assert status.startswith("200"), data
        assert data["va"] == 0x10003030
        # The stored spelling comes back untouched: the fold is a comparison
        # detail, not a rewrite of the name.
        assert data["name"] == NFC_ONLY

    def test_name_lookup_folds_case_like_the_search_does(self) -> None:
        status, data = self._lookup("_PLAIN_ASCII")
        assert status.startswith("200"), data
        assert data["name"] == "_plain_ascii"

    def test_global_lookup_folds_the_sharp_s_expansion(self) -> None:
        """casefold maps ß to ss, so the ASCII spelling resolves the row too."""
        status, data = self._lookup("g_strasse")
        assert status.startswith("200"), data
        assert data["name"] == SHARP_S_NAME

    def test_unrelated_name_still_404s(self) -> None:
        """The fold must not widen the lookup into matching anything."""
        status, _ = self._lookup("nai_ve_render")
        assert status.startswith("404")

    def test_uppercase_accent_finds_the_lowercase_name(self) -> None:
        # Both spellings are the same name, so both rows are a correct answer.
        assert set(self._search("CAF\u00c9")) == {NFC_NAME, NFD_NAME}

    def test_nfd_term_finds_the_nfc_row(self) -> None:
        assert set(self._search(NFD_NAME)) == {NFC_NAME, NFD_NAME}

    def test_ascii_term_keeps_the_plain_path(self) -> None:
        assert self._search("_PLAIN") == ["_plain_ascii"]

    def test_potato_finds_the_accented_name(self) -> None:
        """Potato Mode's own search box, same DB, same term as above."""
        from urllib.parse import quote

        status, _, body = wsgi_get(
            f"/potato?target={self.TARGET}&section={quote(self.SECTION, safe='')}"
            f"&search={quote('CAF\u00c9', safe='')}"
        )
        assert status.startswith("200")
        assert b" match for &quot;" in body or b" matches for &quot;" in body
        assert b"Check the spelling" not in body


@pytest.mark.skipif(not HAS_DB, reason="No coverage database")
class TestLookupSnapshotsArePinned:
    """A function lookup route answers from ONE frozen CoverageSnapshot.

    ``/functions/<va>`` resolves the VA, the exact name and the folded name for
    functions, then the same three for globals, then reads ``verify_results``
    for the winner; the batch POST resolves VAs across functions and globals.
    A ``rebrew build-db`` committing between those reads used to pair one
    build's function row with the next build's ``last_verify``, which reports a
    size and a diff for a payload that no longer carries them. The pin is the
    snapshot object, so these tests make the reader hand back a DIFFERENT
    mapping on every call and require the answer to describe one of them.
    """

    #: The two builds the reader alternates between.  Name, size and byte_delta
    #: move together, so a response that mixed two snapshots names itself.
    BUILDS: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "_build_one", "size": 16, "byte_delta": 1},
        {"name": "_build_two", "size": 32, "byte_delta": 2},
    )

    @classmethod
    def _mappings(cls, tmp_path: Path) -> list[dict[str, CoverageSnapshot]]:
        return [
            _snapshot_mapping(
                tmp_path / f"build{index}",
                "GAME",
                {
                    ".text": {
                        "va": 0x1000,
                        "size": 64,
                        "fileOffset": 0x200,
                        "unitBytes": 16,
                        "columns": 8,
                        "cells": [cell(0x1000, 0x1010, "exact", functions=(build["name"],))],
                    }
                },
                functions=[
                    {
                        "va": 0x1000,
                        "name": build["name"],
                        "vaStart": "0x1000",
                        "size": build["size"],
                        "status": "EXACT",
                    }
                ],
                verify_results=[
                    {
                        "va": 0x1000,
                        "verified_at": "2026-01-01T00:00:00+00:00",
                        "byte_delta": build["byte_delta"],
                        "diff_lines": 0,
                        "similarity": 0.5,
                    }
                ],
            )
            for index, build in enumerate(cls.BUILDS)
        ]

    @classmethod
    def _expected(cls) -> set[tuple[Any, ...]]:
        return {tuple(build[key] for key in ("name", "size", "byte_delta")) for build in cls.BUILDS}

    def test_single_lookup_reads_one_snapshot(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv("RECOVERAGE_DB", str(coverage_dir(tmp_path / "build0")))
        _alternating_reader(monkeypatch, self._mappings(tmp_path))

        status, headers, body = wsgi_get("/api/targets/GAME/functions/0x1000")
        assert status.startswith("200"), body
        data = json.loads(decode_body(body, headers))
        # The row and its last_verify are read at two different points of the
        # handler; one snapshot means they name the same build.
        served = (data["name"], data["size"], data["last_verify"]["byte_delta"])
        assert served in self._expected(), served

    def test_batch_lookup_reads_one_snapshot(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv("RECOVERAGE_DB", str(coverage_dir(tmp_path / "build0")))
        _alternating_reader(monkeypatch, self._mappings(tmp_path))

        status, headers, body = wsgi_post(
            "/api/targets/GAME/functions",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"vas": ["0x1000"]}).encode(),
        )
        assert status.startswith("200"), body
        data = json.loads(decode_body(body, headers))
        assert len(data) == 1, "the batch lookup found nothing"
        row = data[0]
        served = (row["name"], row["size"], row["last_verify"]["byte_delta"])
        assert served in self._expected(), served


class TestHealthLogging:
    """/api/health logs a transition, not one line per probe.

    A monitor pointed at the endpoint polled a broken database once a second
    and filled the log with the same WARNING, which is what teaches an
    operator to skip it; the entry into the state and the recovery are the
    two lines worth keeping.
    """

    def test_repeat_probes_do_not_relog_the_degradation(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import recoverage.api as api
        import recoverage.server as server_mod

        missing = Path("/nonexistent/coverage-dir")
        monkeypatch.setattr(api, "_health_reported", None)
        monkeypatch.setattr(api, "_db_path", lambda: missing)
        monkeypatch.setattr(server_mod, "_db_path", lambda: missing)
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            for _ in range(5):
                status, headers, body = wsgi_get("/api/health")
                assert status.startswith("200")
                assert json.loads(decode_body(body, headers))["status"] == "degraded"
        degraded = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(degraded) == 1
        assert "no coverage-*.toml document" in degraded[0].getMessage()

    def test_recovery_is_logged_and_ends_the_alert(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import recoverage.api as api
        import recoverage.server as server_mod

        real_api_db_path = api._db_path
        real_server_db_path = server_mod._db_path
        missing = Path("/nonexistent/coverage-dir")
        monkeypatch.setattr(api, "_health_reported", None)
        monkeypatch.setattr(api, "_db_path", lambda: missing)
        monkeypatch.setattr(server_mod, "_db_path", lambda: missing)
        with caplog.at_level(logging.INFO, logger="recoverage"):
            wsgi_get("/api/health")
            monkeypatch.setattr(api, "_db_path", real_api_db_path)
            monkeypatch.setattr(server_mod, "_db_path", real_server_db_path)
            status, headers, body = wsgi_get("/api/health")
            assert status.startswith("200")
            assert json.loads(decode_body(body, headers))["status"] == "healthy"
        messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.INFO]
        assert any("recovered" in m and "degraded" in m for m in messages)

    def test_every_reason_is_named_in_one_line(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A missing coverage directory and a dead watcher name both, not just
        the first."""
        import recoverage.api as api
        import recoverage.server as server_mod

        missing = Path("/nonexistent/coverage-dir")
        monkeypatch.setattr(api, "_health_reported", None)
        monkeypatch.setattr(api, "_db_path", lambda: missing)
        monkeypatch.setattr(server_mod, "_db_path", lambda: missing)
        monkeypatch.setattr(
            api, "_stream_stats", lambda: {"clients": 1, "max": 4, "watcher_alive": False}
        )
        with caplog.at_level(logging.WARNING, logger="recoverage"):
            wsgi_get("/api/health")
        line = next(r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING)
        assert "no coverage-*.toml document" in line
        assert "DB watcher is not running" in line


class TestDbWatcherLogging:
    """The poller is a daemon thread nobody joins, so its death must be loud."""

    def test_baseline_failure_is_logged_before_it_escapes(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The baseline snapshot sat outside the per-iteration guard.

        A ``coverage.db`` path that raises on stat killed the thread with its
        traceback going nowhere, and ``/api/health`` reported ``healthy`` with
        no SSE client connected — live reload dead for the rest of the
        process, and no log line naming it.
        """
        import recoverage.api as api

        def _boom() -> tuple[int, int] | None:
            raise OSError("cannot stat coverage.db")

        monkeypatch.setattr(api, "_snapshot_db_mtime", _boom)
        with (
            caplog.at_level(logging.ERROR, logger="recoverage"),
            pytest.raises(OSError, match=r"cannot stat coverage\.db"),
        ):
            api._db_watcher_loop(threading.Event())
        errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
        assert any("DB watcher stopped" in m and "live reload is off" in m for m in errors)

    def test_iteration_failure_keeps_polling_and_logs_each_round(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import recoverage.api as api

        state = {"n": 0}

        def _flaky() -> tuple[int, int] | None:
            state["n"] += 1
            if state["n"] == 1:
                return (1, 1)
            # Any failure from one poll is retried; the type is not what the
            # loop keys on (a stat of the coverage directory fails like this).
            raise OSError("coverage directory is locked")

        stop = threading.Event()
        monkeypatch.setattr(api, "_snapshot_db_mtime", _flaky)
        monkeypatch.setattr(api, "_SSE_POLL_INTERVAL_SECONDS", 0.0)

        def _stop_after_two() -> None:
            while state["n"] < 3:
                time.sleep(0.001)
            stop.set()

        stopper = threading.Thread(target=_stop_after_two, daemon=True)
        stopper.start()
        with caplog.at_level(logging.ERROR, logger="recoverage"):
            api._db_watcher_loop(stop)
        stopper.join(timeout=1.0)
        assert any("continuing to poll" in r.getMessage() for r in caplog.records)
        assert not any("DB watcher stopped" in r.getMessage() for r in caplog.records)


class TestDataSearchIndexOptOut:
    """`/api/targets/<t>/data?index=0` omits the search index.

    The index is target-wide while the rest of a `?section=` payload is that
    one section, so the section-switch request re-sent a payload that grows
    with the function count on every tab click. The key is omitted rather than
    emptied, the same signal `cells` uses, and the two variants must not share
    a validator or a memo entry.
    """

    def test_full_payload_carries_the_index(self) -> None:
        api._clear_data_cache()
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/data")
        assert status.startswith("200"), status
        assert "search_index" in json.loads(decode_body(body, headers))

    def test_index_zero_omits_the_index_and_keeps_the_cells(self) -> None:
        api._clear_data_cache()
        target = require_target()
        status, headers, body = wsgi_get(f"/api/targets/{target}/data?section=.text&index=0")
        assert status.startswith("200"), status
        payload = json.loads(decode_body(body, headers))
        assert "search_index" not in payload
        # Only the index goes: the section the request asked for still arrives.
        assert payload["sections"][".text"]["cells"]

    def test_the_two_variants_do_not_share_an_etag(self) -> None:
        api._clear_data_cache()
        target = require_target()
        _, full, _ = wsgi_get(f"/api/targets/{target}/data?section=.text")
        _, bare, _ = wsgi_get(f"/api/targets/{target}/data?section=.text&index=0")
        assert full["Etag"] != bare["Etag"]

    def test_index_one_and_an_absent_index_both_carry_it(self) -> None:
        api._clear_data_cache()
        target = require_target()
        for query in ("", "?index=1", "?index=%201%20"):
            status, headers, body = wsgi_get(f"/api/targets/{target}/data{query}")
            assert status.startswith("200"), status
            assert "search_index" in json.loads(decode_body(body, headers))

    def test_an_unrecognised_index_is_a_400(self) -> None:
        """The flag is an enum, and an unknown one is refused like ?format=.

        `?index=false` used to read as "on", so a client spelling the flag the
        way its own language spells booleans got the whole search index back
        with nothing in the answer to say the opt-out was ignored.
        """
        api._clear_data_cache()
        target = require_target()
        for value in ("false", "no", "2", "00"):
            status, headers, body = wsgi_get(f"/api/targets/{target}/data?index={value}")
            assert status.startswith("400"), value
            payload = json.loads(decode_body(body, headers))
            assert payload["code"] == "bad_request"
            assert payload["error"] == "invalid index"


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestSectionFilterKeepsDocumentWhitespace:
    """``?section=`` is trimmed of ASCII whitespace only, like every term here.

    A section name comes out of a PE image, so one carrying a non-breaking
    space is a real document value.  ``str.strip()`` removes U+00A0, the thin
    spaces and U+FEFF along with the ASCII runs, so the filter became a name
    the document does not hold, the request answered with every section's
    ``cells`` omitted, and the SPA rendered an empty map over a target that
    has data.  ``server.strip_ascii_whitespace`` is the rule the rest of the
    package already follows.
    """

    TARGET = "FAKEDLL"
    SECTION = ".text\u00a0"

    @pytest.fixture(autouse=True)
    def _padded_section_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        write_coverage(
            coverage_dir(tmp_path),
            self.TARGET,
            {
                self.SECTION: {
                    "va": 0x10003000,
                    "size": 0x20,
                    "fileOffset": 0x300,
                    "unitBytes": 16,
                    "columns": 2,
                    "cells": [
                        cell(0x10003000, 0x10003010, "exact"),
                        cell(0x10003010, 0x10003020, "none"),
                    ],
                }
            },
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(coverage_dir(tmp_path)))
        from recoverage.api import _clear_derived_caches

        _clear_derived_caches()

    def test_the_padded_name_is_its_own_section(self) -> None:
        from urllib.parse import quote

        status, headers, body = wsgi_get(
            f"/api/targets/{self.TARGET}/data?section={quote(self.SECTION, safe='')}"
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert list(data["sections"]) == [self.SECTION]
        assert data["sections"][self.SECTION]["cells"], "the filtered section carries no cells"

    def test_ascii_whitespace_around_the_name_is_still_trimmed(self) -> None:
        from urllib.parse import quote

        status, headers, body = wsgi_get(
            f"/api/targets/{self.TARGET}/data?section={quote('  ' + self.SECTION + '  ', safe='')}"
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["sections"][self.SECTION]["cells"]
