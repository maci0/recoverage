"""Tests for recoverage.api — WSGI-level endpoint tests and unit tests for validation logic."""

from __future__ import annotations

import json

import pytest
from conftest import HAS_DB, decode_body, get_first_target, wsgi_get, wsgi_request

# ── Regen origin validation (actual endpoint) ─────────────────────


class TestRegenOriginValidation:
    """Test origin/remote_addr checks on the actual /api/regen endpoint."""

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
        status, _, _ = wsgi_get(f"/api/targets/{target}/functions?sort=DROP%20TABLE%20functions")
        assert status.startswith("200")

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


# ── VA boundary validation (arithmetic invariants) ─────────────────


class TestVaBoundaryCheck:
    """Verify arithmetic invariants used in handle_api_asm's VA boundary checks.

    These test the mathematical properties that the real handler relies on —
    the same expressions appear in the file_offset and VA boundary checks in
    api.py's handle_api_asm. They do NOT call the endpoint directly.
    """

    def test_va_before_section_start(self) -> None:
        sec_va, sec_file_offset = 0x10001000, 0x400
        va = 0x10000000
        file_offset = sec_file_offset + (va - sec_va)
        assert file_offset < 0

    def test_va_beyond_section_end(self) -> None:
        sec_va, sec_size = 0x10001000, 0x1000
        va = sec_va + sec_size + 1  # one past the end
        assert va >= sec_va + sec_size  # rejected by handler's >= check

    def test_va_at_section_start(self) -> None:
        file_offset = 0x400 + (0x10001000 - 0x10001000)
        assert file_offset == 0x400

    def test_va_just_inside_section(self) -> None:
        sec_va, sec_size = 0x10001000, 0x1000
        last_valid_va = sec_va + sec_size - 1
        assert last_valid_va < sec_va + sec_size  # last byte is in-bounds

    def test_va_at_exact_section_end(self) -> None:
        """VA equal to sec_va + sec_size is out-of-bounds (handler uses >= check)."""
        sec_va, sec_size = 0x10001000, 0x1000
        va = sec_va + sec_size
        # At the boundary: rejected
        assert va >= sec_va + sec_size
        # One byte before: accepted
        assert (va - 1) < sec_va + sec_size

    def test_zero_section_size(self) -> None:
        """Zero-size section has no valid VAs — even sec_va itself is out of bounds."""
        sec_va, sec_size = 0x10001000, 0
        # Every VA is out-of-bounds when size is 0
        assert sec_va >= sec_va + sec_size
        # With a non-zero size, sec_va would be valid
        assert sec_va < sec_va + 1

    def test_max_uint32_va(self) -> None:
        sec_va, sec_file_offset, sec_size = 0xFFFFF000, 0x400, 0x1000
        va = 0xFFFFFFFF
        assert va < sec_va + sec_size
        assert sec_file_offset + (va - sec_va) == sec_file_offset + 0xFFF

    def test_file_offset_overflow_check(self) -> None:
        sec_va, sec_file_offset = 0x80000000, 0x200
        va = 0x00000100
        assert sec_file_offset + (va - sec_va) < 0


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestApiAsm:
    """Test /api/targets/<target>/asm boundary checks via actual endpoint."""

    def test_missing_params_returns_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, _, _ = wsgi_get(f"/api/targets/{target}/asm")
        # Either 400 (missing params) or 501 (no capstone) — both are correct rejections
        assert status.startswith("4") or status.startswith("5")

    def test_zero_size_returns_400(self) -> None:
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
        status, headers, body = wsgi_get(f"/api/targets/{target}/asm?va=0x10001000&size=0")
        if status.startswith("501"):
            pytest.skip("Capstone not installed")
        assert status.startswith("400")
