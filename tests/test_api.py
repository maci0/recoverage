"""Tests for recoverage.api — WSGI-level endpoint tests and unit tests for validation logic."""

from __future__ import annotations

import json
import queue
import sqlite3
import threading
import time
from io import BytesIO
from pathlib import Path
from typing import Any
from wsgiref.util import setup_testing_defaults

import pytest
from conftest import HAS_DB, decode_body, get_first_target, wsgi_get, wsgi_post, wsgi_request

from recoverage._paths import sqlite_ro_uri
from recoverage.server import HAS_CAPSTONE

# ── Regen origin validation (actual endpoint) ─────────────────────


class TestRegenOriginValidation:
    """Test origin/remote_addr checks on the actual /api/regen endpoint."""

    @pytest.fixture(autouse=True)
    def _no_real_regen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Accepted requests must not run catalog/build-db: on a machine with
        rebrew installed, `pytest` would rebuild the developer's real DB."""
        import recoverage.api as api

        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))

    def test_remote_addr_external_rejected(self) -> None:
        """Non-localhost REMOTE_ADDR should be rejected with 403."""
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="192.168.1.100")
        assert status.startswith("403")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Forbidden: localhost only"

    def test_remote_addr_localhost_accepted(self) -> None:
        """Localhost REMOTE_ADDR should pass the remote check (may fail later for other reasons)."""
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        # Should NOT be 403 for remote_addr — may be 500 if rebrew not available, that's fine
        assert not status.startswith("403")

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

    def test_localhost_origin_accepted(self) -> None:
        """localhost Origin should pass origin check."""
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://localhost:8001"},
            remote_addr="127.0.0.1",
        )
        assert not status.startswith("403")

    def test_evil_subdomain_rejected(self) -> None:
        """Origin like 127.0.0.1.evil.com must be rejected."""
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Origin": "http://127.0.0.1.evil.com"},
            remote_addr="127.0.0.1",
        )
        assert status.startswith("403")

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
        status, _, _ = wsgi_request(
            "POST",
            "/api/regen",
            headers={"Sec-Fetch-Site": site},
            remote_addr="127.0.0.1",
        )
        assert not status.startswith("403")

    def test_ipv6_loopback_remote_addr(self) -> None:
        """::1 REMOTE_ADDR should be accepted."""
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr="::1")
        assert not status.startswith("403")

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
        status, headers, _ = wsgi_get("/api/health")
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"

    def test_health_content_type(self) -> None:
        _, headers, _ = wsgi_get("/api/health")
        assert "application/json" in headers.get("Content-Type", "")

    def test_health_degraded_when_db_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing coverage.db must be reported as degraded (with
        exists=false), not crash the endpoint or claim healthy."""
        import recoverage.api as api

        monkeypatch.setattr(api, "_db_path", lambda: Path("/nonexistent/coverage.db"))
        status, headers, body = wsgi_get("/api/health")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["status"] == "degraded"
        assert data["db"]["exists"] is False


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiTargets:
    """Test /api/targets returns target list."""

    def test_targets_returns_200(self) -> None:
        status, headers, body = wsgi_get("/api/targets")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "targets" in data
        assert isinstance(data["targets"], list)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiFunctions:
    """Test /api/targets/<target>/functions with sort validation."""

    def test_default_sort(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "functions" in data
        assert "total" in data

    def test_valid_sort_field(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = wsgi_get(f"/api/targets/{target}/functions?sort=name:desc")
        assert status.startswith("200")

    def test_invalid_sort_field_falls_back(self) -> None:
        """SQL injection in sort field should be rejected by whitelist."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        # Should still return 200 — invalid sort falls back to default "va"
        status, headers, body = wsgi_get(
            f"/api/targets/{target}/functions?sort=DROP%20TABLE%20functions"
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        # The fallback must actually apply: results come back va-ascending,
        # identical to the default sort (a whitelist regression that passed
        # raw SQL through would 500 or reorder here).
        default_status, _, default_body = wsgi_get(f"/api/targets/{target}/functions")
        assert [fn["va"] for fn in data["functions"]] == [
            fn["va"] for fn in json.loads(decode_body(default_body, headers))["functions"]
        ]
        assert data["total"] >= 1

    def test_pagination(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?limit=5&offset=0")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["limit"] == 5
        assert data["offset"] == 0
        assert len(data["functions"]) <= 5

    def test_limit_capped_at_500(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?limit=9999")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["limit"] == 500

    def test_status_filter_narrows_results(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?status=EXACT")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        # Synthetic DB: exactly one EXACT function (_func_a).
        assert [fn["name"] for fn in data["functions"]] == ["_func_a"]
        assert data["total"] == 1

    def test_search_matches_name_substring(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?search=_func_b")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data["functions"]] == ["_func_b"]

    def test_search_like_wildcards_match_literally(self) -> None:
        """% in the search must be escaped, not act as a LIKE wildcard —
        an unescaped pattern would return every row (or inject a pattern)."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?search=%25")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["total"] == 0
        assert data["functions"] == []

    def test_invalid_limit_falls_back_to_default(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?limit=abc")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["limit"] == 50

    def test_limit_zero_clamped_to_one(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?limit=0")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["limit"] == 1

    def test_negative_offset_clamped_to_zero(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?offset=-10")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["offset"] == 0


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

        monkeypatch.setattr(api, "HAS_CAPSTONE", True)

    def _asm(self, target: str, query: str) -> tuple[str, dict[str, str], bytes]:
        return wsgi_get(f"/api/targets/{target}/asm?{query}")

    def test_va_below_start_with_positive_file_offset_rejected(self) -> None:
        """va=0x10000F80: delta -0x80 so file_offset=0x180 stays >= 0 — only
        the va < sec_va half catches this; disassembling bytes from before
        the section as if they were at va was the bug."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._asm(target, "va=0x10000F80&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is before section start"

    def test_negative_va_rejected(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._asm(target, "va=-0x10&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is before section start"

    def test_va_at_exact_section_end_rejected(self) -> None:
        """VA equal to sec_va + sec_size is the first out-of-bounds address."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._asm(target, "va=0x10002000&size=16")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "va is beyond section end"

    def test_va_one_past_end_rejected(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._asm(target, "va=0x10002001&size=16")
        assert status.startswith("400")

    def test_va_far_beyond_end_rejected(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._asm(target, "va=0xFFFFFFFF&size=16")
        assert status.startswith("400")

    def test_last_valid_va_passes_boundary_guard(self) -> None:
        """va = section end - 1 must NOT trip either boundary check; the
        request proceeds far enough to fail later on the missing DLL (422),
        which proves the guard accepted the final in-bounds address."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._asm(target, "va=0x10001FFF&size=1")
        assert status.startswith("422")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "not enough bytes in DLL"

    def test_zero_size_still_rejected_at_boundary_class(self) -> None:
        """size clamps/validates before the VA checks: size=0 is its own 400."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._asm(target, "va=0x10001000&size=0")
        assert status.startswith("400")

    def test_decimal_va_spelling_accepted(self) -> None:
        """The SPA interpolates JS numbers into ?va= — decimal digits.

        268439648 is 0x10001060, inside .text: parsing those digits as base-16
        read an address orders of magnitude past the section and answered 400
        for every undocumented-block disassembly request.
        """
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._asm(target, "va=268439648&size=16")
        # Past the boundary guards and far enough to fail on the missing DLL.
        assert status.startswith("422")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "not enough bytes in DLL"

    def test_decimal_and_hex_spellings_agree(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        dec_status, _, _ = self._asm(target, "va=268439552&size=1")
        hex_status, _, _ = self._asm(target, "va=0x10001000&size=1")
        assert dec_status == hex_status

    def test_bare_hex_legacy_caller_still_resolves(self) -> None:
        """All-digit '10001060': decimal spelling sits below section start, so
        the bare-hex fallback candidate must be the one resolved."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._asm(target, "va=10001060&size=16")
        assert status.startswith("422")

    def test_unparseable_va_rejected(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._asm(target, "va=zzz&size=16")
        assert status.startswith("400")


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiAsm:
    """Test /api/targets/<target>/asm request validation via actual endpoint."""

    @pytest.fixture(autouse=True)
    def _capstone_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The validation under test runs before any disassembly, so faking
        # the capstone probe gets us past the 501 short-circuit without the
        # optional dependency.
        import recoverage.api as api

        monkeypatch.setattr(api, "HAS_CAPSTONE", True)

    def test_missing_params_returns_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "missing va or size"

    def test_zero_size_returns_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000&size=0")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "size must be positive"


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
        status, _, body = self._get("offset=0&size=999999")
        assert status.startswith("200")
        data = json.loads(decode_body(body, {}))
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
        """A .bss-style section (NULL va/fileOffset/size) has nothing on disk
        to slice: the endpoint must answer its JSON 422 contract instead of a
        TypeError 500 from the pointer arithmetic."""
        import recoverage.api as api
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE sections (target TEXT, name TEXT, va INTEGER, size INTEGER,"
            " fileOffset INTEGER, unitBytes INTEGER, columns INTEGER)"
        )
        conn.execute("INSERT INTO sections VALUES ('T', '.bss', NULL, NULL, NULL, 16, 8)")
        conn.commit()
        conn.close()

        def _tmp_db() -> sqlite3.Connection:
            c = sqlite3.connect(sqlite_ro_uri(db), uri=True)
            c.row_factory = sqlite3.Row
            return c

        monkeypatch.setattr(api, "_db", _tmp_db)
        monkeypatch.setattr(srv, "_db_path", lambda: db)
        monkeypatch.setattr(api, "_require_target", lambda c, t: None)
        status, headers, body = wsgi_get("/api/targets/T/sections/.bss/bytes?offset=0&size=4")
        assert status.startswith("422")
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
        """A foreign DB whose sections row carries a negative fileOffset (a
        rebrew-built DB cannot: the schema CHECKs it >= 0) must get the 400
        contract instead of Python's negative-index slicing silently serving
        tail-of-binary bytes — same guard as /asm."""
        import recoverage.api as api
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE sections (target TEXT, name TEXT, va INTEGER, size INTEGER,"
            " fileOffset INTEGER, unitBytes INTEGER, columns INTEGER)"
        )
        conn.execute("INSERT INTO sections VALUES ('T', '.text', 4096, 4096, -4096, 16, 8)")
        conn.commit()
        conn.close()

        def _tmp_db() -> sqlite3.Connection:
            c = sqlite3.connect(sqlite_ro_uri(db), uri=True)
            c.row_factory = sqlite3.Row
            return c

        monkeypatch.setattr(api, "_db", _tmp_db)
        monkeypatch.setattr(srv, "_db_path", lambda: db)
        monkeypatch.setattr(api, "_require_target", lambda c, t: None)
        status, headers, body = wsgi_get("/api/targets/T/sections/.text/bytes?offset=0&size=4")
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"


class TestRegenRateLimit:
    """Server-side cooldown on /api/regen (the UI throttles, the API must too)."""

    def teardown_method(self) -> None:
        import recoverage.api as api

        # Accepted POSTs stamp the module-global cooldown; reset so later
        # tests (and re-runs) start from a neutral state.
        api._regen_last_attempt = 0.0

    def _no_real_regen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        monkeypatch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))

    def test_rapid_second_call_rate_limited(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._no_real_regen(monkeypatch)
        import recoverage.api as api

        api._regen_last_attempt = 0.0
        # First call passes the cooldown gate (the patched _do_regen answers
        # 200 — the timestamp is stamped before it runs).
        status1, _, _ = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        assert not status1.startswith("429")

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
            api.time.monotonic() - api._REGEN_COOLDOWN_SECONDS - 1,
        )
        status, _, _ = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        assert not status.startswith("429")


class TestServeBindFlag:
    def test_bind_option_help(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--bind" in result.output
        assert "127.0.0.1" in result.output


class TestLastVerify:
    """/functions/<va> attaches the last `rebrew verify -o` record."""

    def test_function_detail_includes_last_verify(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0x10001000")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert data["last_verify"]["byte_delta"] == 0
        assert "verified_at" in data["last_verify"]

    def test_function_detail_accepts_decimal_va(self) -> None:
        """The /functions list emits va as a decimal int — taking that value
        straight into the detail route must not 404 (round-trip contract)."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, body = wsgi_get(f"/api/targets/{target}/functions/0x10001000")
        hex_data = json.loads(decode_body(body, {}))
        status, _, body = wsgi_get(f"/api/targets/{target}/functions/{hex_data['va']}")
        assert status.startswith("200")

    def test_function_without_verify_record_omits_field(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0x10001030")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert "last_verify" not in data


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
        status_holder["headers"] = {k: v for k, v in response_headers}

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
        api._SSE_CLIENTS.add(q)
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
            api._SSE_CLIENTS.discard(q)

    def test_snapshot_reads_real_db(self) -> None:
        import recoverage.api as api

        snapshot = api._snapshot_db_mtime()
        assert snapshot is not None
        assert snapshot[1] > 0  # the synthetic DB has a non-zero size

    # WAL-only-commit coverage for _snapshot_db_mtime lives in
    # test_server.py::TestDbEtag (same function object; kept in one place).

    def test_snapshot_ignores_shm_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """-shm is touched by every connection — it must NOT change the
        snapshot or ETags would be unstable between requests."""
        import recoverage.api as api
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        db.write_bytes(b"x" * 100)
        monkeypatch.setattr(srv, "_db_path", lambda: db)
        before = api._snapshot_db_mtime()
        assert before is not None
        shm = tmp_path / "coverage.db-shm"
        shm.write_bytes(b"z" * 100)
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


class TestSseDbWatcher:
    """Background watcher: polls mtime and broadcasts on change."""

    def test_watcher_broadcasts_on_mtime_change(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        seq = [(111, 1), (111, 1), (222, 2)]
        state = {"i": 0}

        def fake_snapshot() -> tuple[int, int]:
            i = min(state["i"], len(seq) - 1)
            value = seq[i]
            state["i"] += 1
            return value

        calls: list[tuple[int, int]] = []
        monkeypatch.setattr(api, "_snapshot_db_mtime", fake_snapshot)
        monkeypatch.setattr(api, "_broadcast_db_updated", lambda s: calls.append(s))
        monkeypatch.setattr(api, "_SSE_POLL_INTERVAL_SECONDS", 0.01)

        stop = threading.Event()
        thread = threading.Thread(target=api._db_watcher_loop, args=(stop,), daemon=True)
        thread.start()
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

        monkeypatch.setattr(api, "_snapshot_db_mtime", lambda: (111, 1))
        calls: list[tuple[int, int]] = []
        monkeypatch.setattr(api, "_broadcast_db_updated", lambda s: calls.append(s))
        monkeypatch.setattr(api, "_SSE_POLL_INTERVAL_SECONDS", 0.01)

        stop = threading.Event()
        thread = threading.Thread(target=api._db_watcher_loop, args=(stop,), daemon=True)
        thread.start()
        try:
            time.sleep(0.05)
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

        from recoverage.cli import _ThreadingWSGIServer

        assert issubclass(_ThreadingWSGIServer, ThreadingMixIn)
        assert issubclass(_ThreadingWSGIServer, WSGIServer)

    def test_threading_server_daemon_threads(self) -> None:
        from recoverage.cli import _ThreadingWSGIServer

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
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
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

    def test_batch_rejects_oversized_body(self) -> None:
        """The batch endpoint is unauthenticated — an oversized body must be
        rejected with 413 before it is parsed, not read into memory."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, body = wsgi_post(
            f"/api/targets/{target}/functions",
            body=b'{"vas": ["0x10001000"]' + b" " * 70_000 + b"}",
        )
        assert status.startswith("413")

    def test_batch_omits_unknown_vas(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x99999999"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["va"] for fn in data] == [0x10001000]

    def test_batch_all_unknown_vas_returns_empty_list(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": ["0x99999999"]}))
        assert status.startswith("200")
        assert json.loads(decode_body(body, headers)) == []

    def test_batch_includes_globals(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10002000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert len(data) == 2
        assert data[1]["name"] == "g_counter"
        assert data[1]["isGlobal"] == 1

    def test_batch_preserves_input_order(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001030", "0x10001000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data] == ["_func_c", "_func_a"]

    def test_batch_accepts_int_vas(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": [0x10001000]}))
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert [fn["name"] for fn in data] == ["_func_a"]

    def test_batch_dedupes_repeated_vas(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(
            target, json.dumps({"vas": ["0x10001000", "0x10001000"]})
        )
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        assert len(data) == 1

    def test_batch_empty_vas_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": []}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"

    def test_batch_non_json_body_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, "not json at all")
        assert status.startswith("400")

    def test_batch_empty_body_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, "")
        assert status.startswith("400")

    def test_batch_body_not_object_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, json.dumps([1, 2, 3]))
        assert status.startswith("400")

    def test_batch_missing_vas_key_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, json.dumps({}))
        assert status.startswith("400")

    def test_batch_vas_not_list_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = self._post(target, json.dumps({"vas": "0x10001000"}))
        assert status.startswith("400")

    def test_batch_malformed_va_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = self._post(target, json.dumps({"vas": ["not-a-va"]}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "bad_request"
        assert "not-a-va" in data["detail"]

    def test_batch_too_many_vas_400(self) -> None:
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        vas = ["0x10001000"] * (api._MAX_BATCH_LOOKUP + 1)
        status, headers, body = self._post(target, json.dumps({"vas": vas}))
        assert status.startswith("400")
        data = json.loads(decode_body(body, headers))
        assert str(api._MAX_BATCH_LOOKUP) in data["error"]


# ── Error-response consistency ────────────────────────────────────


class TestErrorResponseShape:
    """Every JSON error response carries {error, code, detail} (+ extras)."""

    def teardown_method(self) -> None:
        import recoverage.api as api

        # The 429 test stamps the module-global regen cooldown; reset so
        # later tests POSTing /api/regen start from a neutral state instead
        # of inheriting this test's rate-limit window.
        api._regen_last_attempt = 0.0

    def _check(
        self, status: str, headers: dict[str, str], body: bytes, expected_code: str
    ) -> dict[str, Any]:
        assert status.startswith("4") or status.startswith("5")
        data = json.loads(decode_body(body, headers))
        assert set(data) >= {"error", "code", "detail"}
        assert data["code"] == expected_code
        assert isinstance(data["error"], str) and data["error"]
        assert isinstance(data["detail"], str)
        return data

    def test_404_function_detail(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions/0xdeadbeef")
        data = self._check(status, headers, body, "not_found")
        assert "0xdeadbeef" in data["detail"]

    def test_400_bad_request(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_post(f"/api/targets/{target}/functions", body="[]")
        self._check(status, headers, body, "bad_request")

    def test_403_forbidden(self) -> None:
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="192.168.1.100")
        data = self._check(status, headers, body, "forbidden")
        assert data["error"] == "Forbidden: localhost only"

    def test_429_rate_limited_preserves_extras(self) -> None:
        import recoverage.api as api

        api._regen_last_attempt = 0.0
        wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        status, headers, body = wsgi_request("POST", "/api/regen", remote_addr="127.0.0.1")
        data = self._check(status, headers, body, "rate_limited")
        assert data["retry_after"] >= 0
        assert data["detail"]

    def test_501_not_implemented(self) -> None:
        if HAS_CAPSTONE:
            pytest.skip("capstone installed — asm route serves normally")
        status, headers, body = wsgi_get("/api/targets/FAKEDLL/asm?va=0x10001000&size=16")
        data = self._check(status, headers, body, "not_implemented")
        assert "capstone" in data["error"]

    def test_503_db_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")

        def _boom() -> sqlite3.Connection:
            raise sqlite3.OperationalError("no such file")

        monkeypatch.setattr(api, "_db", _boom)
        status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        self._check(status, headers, body, "db_unavailable")

    def test_503_db_unavailable_is_logged_with_cause(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A swallowed sqlite3.Error in the shared target cursor must not make
        a missing/corrupt database invisible: the failure is logged with the
        request context and the 503 detail carries the underlying cause."""
        import logging as _logging

        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")

        def _boom() -> sqlite3.Connection:
            raise sqlite3.OperationalError("unable to open database file")

        monkeypatch.setattr(api, "_db", _boom)
        with caplog.at_level(_logging.WARNING, logger="recoverage"):
            status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        self._check(status, headers, body, "db_unavailable")
        data = json.loads(decode_body(body, headers))
        assert "unable to open database file" in data["detail"]
        logged = [rec.getMessage() for rec in caplog.records]
        assert any(
            "Database unavailable" in msg and "unable to open database file" in msg
            for msg in logged
        )


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
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
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
        """With the DB unreadable, /api/targets falls back to the config list
        instead of 500ing — the SPA needs a target dropdown either way."""
        import recoverage.api as api

        def _boom() -> sqlite3.Connection:
            raise sqlite3.OperationalError("unable to open database file")

        monkeypatch.setattr(api, "_db", _boom)
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

        result = CliRunner().invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--allow-remote" in result.output
        assert "--cors-origin" in result.output


class TestPostConnectSqliteError:
    """Queries that fail after connect (corrupt DB, SQLITE_BUSY) must keep
    the JSON 503 contract instead of surfacing Bottle's HTML 500."""

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_query_failure_returns_json_503(self, monkeypatch: Any) -> None:
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")

        real_conn = api._db()

        class _BoomCursor:
            def __init__(self) -> None:
                pass

            def execute(self, *a, **k):
                raise sqlite3.OperationalError("no such table: section_cell_stats")

            def fetchone(self) -> None:
                return None

            def fetchall(self) -> list:
                return []

        class _BoomConn:
            def cursor(self):
                return _BoomCursor()

            def close(self) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(api, "_db", lambda: _BoomConn())
        try:
            status, headers, body = wsgi_get(f"/api/targets/{target}/stats")
        finally:
            real_conn.close()
        assert status.startswith("503")
        data = json.loads(decode_body(body, headers))
        assert data["error"] == "Database unavailable"
        assert data["code"] == "db_unavailable"


class TestNormalizeOriginEdges:
    def test_default_port_dropped(self) -> None:
        from recoverage.server import _normalize_origin

        assert _normalize_origin("http://localhost:80") == "http://localhost"
        assert _normalize_origin("https://example.com:443") == "https://example.com"
        assert _normalize_origin("http://localhost:5173") == "http://localhost:5173"

    def test_ipv6_brackets_preserved(self) -> None:
        from recoverage.server import _normalize_origin

        assert _normalize_origin("http://[::1]:8001") == "http://[::1]:8001"


class TestDataPayloadMemo:
    """/api/targets/<t>/data memoises the assembled payload per DB fingerprint.

    The endpoint materialises all cells + search index + stats on every
    cache-missing request; the memo (keyed on db mtime_ns/size) serves
    repeat requests without re-querying, and is cleared on rebuild.
    """

    def _make_db(self, tmp_path: Any) -> Any:
        """A minimal but schema-gate-valid v4 DB (passes _db()'s shape check)."""
        import sqlite3

        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        c.execute(
            "CREATE TABLE sections (target TEXT, name TEXT, va INTEGER, size INTEGER, "
            "fileOffset INTEGER, unitBytes INTEGER, columns INTEGER)"
        )
        c.execute(
            "CREATE TABLE cells (id INTEGER, target TEXT, section_name TEXT, start INTEGER, "
            "end INTEGER, span INTEGER, state TEXT, functions TEXT, label TEXT, "
            "parent_function TEXT)"
        )
        c.execute(
            "CREATE TABLE functions (target TEXT, va INTEGER, name TEXT, vaStart TEXT, "
            "size INTEGER, "
            "fileOffset INTEGER, status TEXT, module TEXT, cflags TEXT, symbol TEXT, "
            "markerType TEXT, ghidra_name TEXT, list_name TEXT, is_thunk INTEGER, "
            "is_export INTEGER, sha256 TEXT, files TEXT, detected_by TEXT, size_by_tool TEXT, "
            "textOffset INTEGER, blocker TEXT, blockerDelta INTEGER, size_reason TEXT, "
            "similarity REAL)"
        )
        c.execute(
            "CREATE TABLE globals (target TEXT, name TEXT, va INTEGER, decl TEXT, files TEXT, "
            "module TEXT, size INTEGER)"
        )
        c.execute(
            "CREATE TABLE verify_results (target TEXT, va INTEGER, verified_at TEXT, "
            "byte_delta INTEGER, diff_lines TEXT, similarity REAL)"
        )
        c.execute("CREATE TABLE history (id INTEGER)")
        c.execute(
            "CREATE VIEW section_cell_stats AS SELECT target, section_name, "
            "COUNT(*) AS total_cells, 0 AS exact_count, 0 AS reloc_count, 0 AS near_match_count, "
            "0 AS stub_count, 0 AS padding_count, 0 AS data_count, 0 AS thunk_count, "
            "0 AS none_count, 0 AS proven_count, 0 AS size_mismatch_count "
            "FROM cells GROUP BY target, section_name"
        )
        c.execute("INSERT INTO metadata VALUES ('GAME', 'db_version', '\"4\"')")
        conn.commit()
        conn.close()
        return db

    def _patch(self, tmp_path: Any, monkeypatch: Any) -> Any:
        """Point the app at a synthetic DB and return the mock request."""
        import recoverage.api as api

        db = self._make_db(tmp_path)

        def _open_like(p: Any) -> Any:
            conn = sqlite3.connect(sqlite_ro_uri(p), uri=True)
            conn.row_factory = sqlite3.Row
            return conn

        req = type("R", (), {"headers": {}, "query": {}})()
        monkeypatch.setattr(api, "_db_path", lambda: db)
        monkeypatch.setattr("recoverage.server._db_path", lambda: db)
        monkeypatch.setattr(api, "_open_db", _open_like)
        monkeypatch.setattr(api, "_require_target", lambda c, t: None)
        monkeypatch.setattr(api, "request", req)
        api._clear_data_cache()
        return req

    def test_memo_serves_second_request_and_clears(self, tmp_path: Any, monkeypatch: Any) -> None:
        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)

        resp1 = api.handle_api_data("GAME")
        assert isinstance(resp1, bytes)
        assert len(api._DATA_CACHE) == 1

        # Second request: cache hit (payload identical, no query re-run).
        resp2 = api.handle_api_data("GAME")
        assert isinstance(resp2, bytes)

        # Rebuild invalidation path.
        api._clear_data_cache()
        assert len(api._DATA_CACHE) == 0

    def test_memo_self_invalidates_on_db_change(self, tmp_path: Any, monkeypatch: Any) -> None:
        """A DB fingerprint change (rebuild) must empty the memo — a memo
        keyed on a constant would pass the explicit-clear test above."""
        import os

        import recoverage.api as api

        self._patch(tmp_path, monkeypatch)

        api.handle_api_data("GAME")
        assert len(api._DATA_CACHE) == 1
        # Simulate a rebuild: bump the DB's mtime (same content, new time).
        st = api._db_path().stat()
        os.utime(api._db_path(), (st.st_atime + 2, st.st_mtime + 2))
        api.handle_api_data("GAME")
        # A constant fingerprint would still hold ONE key; two keys prove
        # the snapshot is fingerprint-sensitive (the changed mtime produced
        # a different cache key — a miss, not a stale hit).
        assert len(api._DATA_CACHE) == 2

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

        api._clear_derived_caches()

        assert len(api._DATA_CACHE) == 0
        assert server_mod._RESOLVED_TARGETS_CACHE is None
        assert ui.CACHED_INDEX_PAYLOAD == b"shell-bytes"
        assert ui.CACHED_INDEX_COMPRESSED == {"gzip": b"shell-gz"}

    def _gated_open(
        self, tmp_path: Any, monkeypatch: Any, release: threading.Event
    ) -> tuple[Any, list[int]]:
        """Patch ``_open_db`` to record every call and park the FIRST caller
        on *release* — freezing the payload build mid-flight so the test can
        observe what concurrent requests do while a build is in progress.

        Also installs thread-independent request/response stand-ins for the
        ``server`` module: worker threads have no bottle request context
        (thread-local), and the compression/ETag helpers resolve those names
        from server's namespace."""
        import recoverage.api as api
        import recoverage.server as server_mod

        self._patch(tmp_path, monkeypatch)

        open_calls: list[int] = []
        lock = threading.Lock()
        # The payload build opens its connection through server._db(), whose
        # body resolves _open_db in server's module namespace.
        real_open_db = server_mod._open_db

        def counting_open(p: Any) -> Any:
            with lock:
                open_calls.append(1)
                first = len(open_calls) == 1
            if first:
                assert release.wait(timeout=15), "builder parked forever in _open_db"
            return real_open_db(p)

        monkeypatch.setattr(server_mod, "_open_db", counting_open)

        fake_req: Any = type("R", (), {"headers": {}, "query": {}, "environ": {}})()
        fake_resp: Any = type(
            "R", (), {"content_type": None, "set_header": lambda self, k, v: None}
        )()
        monkeypatch.setattr(server_mod, "request", fake_req)
        monkeypatch.setattr(server_mod, "response", fake_resp)
        return api, open_calls

    def test_concurrent_cold_misses_single_flight(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Simultaneous cold misses share ONE payload build.

        A rebuild broadcast clears the memo and wakes every SSE client, which
        all refetch /data at once; without single-flight each of those misses
        re-runs the full-table queries + serialization.  The first builder is
        frozen inside _open_db while the rest arrive: each must come back with
        identical bytes having opened the DB zero extra times."""
        import recoverage.api as api

        release = threading.Event()
        _, open_calls = self._gated_open(tmp_path, monkeypatch, release)

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
        # builder sits frozen in _open_db; a duplicate build would show up as
        # a second _open_db call.
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
        _, open_calls = self._gated_open(tmp_path, monkeypatch, never)
        snap = api._snapshot_db_mtime()
        assert snap is not None
        key: tuple[tuple[int, int], str, None] = (snap, "GAME", None)
        built = threading.Event()
        api._DATA_CACHE_BUILDING[key] = built

        outcome: list[Any] = []

        def follower() -> None:
            outcome.append(api.handle_api_data("GAME"))

        t = threading.Thread(target=follower)
        t.start()
        try:
            t.join(timeout=1.0)
            assert t.is_alive(), "follower did not wait for the in-flight build"
            assert open_calls == [], "follower opened the DB despite an in-flight build"
            api._DATA_CACHE[key] = {"raw": b'{"memoized": true}'}
        finally:
            built.set()
        t.join(timeout=15)
        assert not t.is_alive(), "follower never woke"
        assert outcome == [b'{"memoized": true}']
        assert open_calls == []
        # The follower owns nothing: the manually registered event is left
        # for its owner, so pop it the way an owner's finally would.
        api._DATA_CACHE_BUILDING.pop(key, None)

    def test_follower_survives_leader_404(self, tmp_path: Any, monkeypatch: Any) -> None:
        """A follower parked on an in-flight build whose owner short-circuits
        (unknown ?section= 404) must wake, find no memo, and produce its own
        404 — not hang, not serve a stale/empty payload."""
        import recoverage.api as api

        release = threading.Event()
        _, open_calls = self._gated_open(tmp_path, monkeypatch, release)
        req = type("R", (), {"headers": {}, "query": {"section": "nope"}})()
        monkeypatch.setattr(api, "request", req)
        api._clear_data_cache()

        snap = api._snapshot_db_mtime()
        assert snap is not None
        key: tuple[tuple[int, int], str, str | None] = (snap, "GAME", "nope")
        built = threading.Event()
        api._DATA_CACHE_BUILDING[key] = built

        outcome: list[Any] = []

        def follower() -> None:
            try:
                outcome.append(("returned", api.handle_api_data("GAME")))
            except Exception as exc:
                outcome.append(("raised", exc))

        t = threading.Thread(target=follower)
        t.start()
        t.join(timeout=0.3)
        assert t.is_alive(), "follower did not wait for the in-flight build"
        built.set()
        release.set()  # the follower's own build may now open the DB
        t.join(timeout=15)
        assert not t.is_alive(), "404 path deadlocked the follower"
        kind, resp = outcome[0]
        # The unknown-section 404 is raised by _build_data_raw (a raised
        # HTTPResponse is what bottle renders as the response); the direct
        # call observes the raised shape.  Either way the follower must see
        # its own 404, never a stale/empty payload.
        assert kind == "raised" and str(resp.status).startswith("404")
        assert open_calls == [1]
        api._DATA_CACHE_BUILDING.pop(key, None)


def _header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup (Bottle sends 'Etag', tests use 'ETag')."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


class TestApiEtagContract:
    """Hashed ETag + If-None-Match 304 round-trip on the /data route."""

    def test_data_etag_roundtrip(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
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
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        _, h1, _ = wsgi_get(f"/api/targets/{target}/data")
        _, h2, _ = wsgi_get(f"/api/targets/{target}/data?section=.text")
        assert _header(h1, "ETag") != _header(h2, "ETag")

    def test_unknown_section_404s(self) -> None:
        """/data?section=<unknown> must 404 (was a silent empty grid)."""
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, body = wsgi_get(f"/api/targets/{target}/data?section=.nosuch")
        assert status.startswith("404")
        payload = json.loads(decode_body(body, {}))
        assert payload.get("code") == "not_found"


class TestSseClientCap:
    def test_excess_clients_get_503(self) -> None:
        """More concurrent /api/events clients than the cap must be rejected
        with 503 (thread-DoS guard)."""
        import recoverage.api as api

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        with api._SSE_CLIENTS_LOCK:
            for _ in range(api._SSE_MAX_CLIENTS):
                api._SSE_CLIENTS.add(queue.Queue(maxsize=api._SSE_QUEUE_MAX))
        try:
            status, _, _ = wsgi_get("/api/events")
            assert status.startswith("503")
        finally:
            with api._SSE_CLIENTS_LOCK:
                api._SSE_CLIENTS.clear()


class TestDbWatcherResilience:
    """A failing watcher iteration must be logged and retried, not kill the thread."""

    def test_watcher_survives_broadcast_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        seq = [(111, 1), (222, 2), (333, 3)]
        state = {"i": 0}

        def fake_snapshot() -> tuple[int, int]:
            i = min(state["i"], len(seq) - 1)
            value = seq[i]
            state["i"] += 1
            return value

        calls: list[tuple[int, int]] = []

        def flaky_broadcast(snapshot: tuple[int, int]) -> None:
            calls.append(snapshot)
            if len(calls) == 1:
                raise RuntimeError("boom")

        monkeypatch.setattr(api, "_snapshot_db_mtime", fake_snapshot)
        monkeypatch.setattr(api, "_broadcast_db_updated", flaky_broadcast)
        monkeypatch.setattr(api, "_SSE_POLL_INTERVAL_SECONDS", 0.01)

        stop = threading.Event()
        thread = threading.Thread(target=api._db_watcher_loop, args=(stop,), daemon=True)
        thread.start()
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


class TestDataEndpointSchemaGate:
    """/data must go through the _db() schema gate like every other endpoint,
    so an incomplete-schema DB yields the clear 503 contract."""

    def test_data_503_when_db_gate_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.api as api

        api._clear_data_cache()  # drop memo entries earlier tests left behind
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")

        def _boom() -> sqlite3.Connection:
            raise sqlite3.OperationalError(
                "coverage.db schema is incomplete (missing tables/views)"
            )

        monkeypatch.setattr(api, "_db", _boom)
        status, _, body = wsgi_get(f"/api/targets/{target}/data")
        assert status.startswith("503")
        data = json.loads(decode_body(body, {}))
        assert data["code"] == "db_unavailable"


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
        status, headers, body = wsgi_get("/src/main.c")
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
        # Bottle decodes %2E%2E%2F before routing, so this arrives as ../.
        status, _, body = wsgi_get("/src/%2e%2e/secret.txt")
        assert status.startswith("403") or status.startswith("404")
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

    def test_original_prefix_serves_original_dir(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        orig = tmp_path / "original"
        orig.mkdir()
        (orig / "note.txt").write_text("original tree", encoding="utf-8")
        status, _, body = wsgi_get("/original/note.txt")
        assert status.startswith("200")
        assert b"original tree" in body


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
        status, _, _ = wsgi_post(
            "/api/targets/FAKEDLL/functions", body=json.dumps({"vas": [2**63 - 1]})
        )
        assert status.startswith("200")

    def test_get_function_huge_va_is_404_not_500(self) -> None:
        status, headers, body = wsgi_get(f"/api/targets/FAKEDLL/functions/{2**80}")
        assert status.startswith("404")
        data = json.loads(decode_body(body, headers))
        assert data["code"] == "not_found"

    def test_functions_offset_beyond_int64_clamped(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/functions?offset={10**25}")
        assert status.startswith("200")
        data = json.loads(decode_body(body, headers))
        # Clamped to the page ceiling; the resulting page is simply empty.
        assert data["functions"] == []


class TestUnhandledErrorContract:
    """Unexpected (non-sqlite) exceptions must be visible in the log AND keep
    every surface's format contract: JSON on /api/*, HTML on UI routes.  The
    server runs wsgiref with quiet=True, so without the log line the failing
    endpoint is unidentifiable from a bare stderr traceback."""

    def test_api_500_is_json_and_logged(self, monkeypatch: Any, caplog: Any) -> None:
        import logging

        import recoverage.api as api

        def boom() -> None:
            raise RuntimeError("exploding cursor")

        monkeypatch.setattr(api, "_db", boom)
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
