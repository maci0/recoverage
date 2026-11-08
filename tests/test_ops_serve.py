"""``recoverage ops serve`` answers the same ops as ``dispatch`` over rebrew's HTTP server."""

import http.client
import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_ops_retained import request_for

from recoverage import ops

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("rebrew.coverage_input_contract") is None,
    reason="requires the Rebrew 6.22 candidate",
)

START_TIMEOUT = 30.0
CALL_TIMEOUT = 60.0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start(workspace: Path, store: Path, token: str) -> tuple[subprocess.Popen[str], int]:
    port = _free_port()  # the server's Host allow-list names the port it was asked for
    env = {**os.environ, "RECOVERAGE_OPS_TOKEN": token}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "recoverage",
            "ops",
            "serve",
            "--port",
            str(port),
            "--workspace",
            str(workspace),
            "--filestore",
            str(store),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout is not None
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if "serving recoverage ops on" in line:
            return proc, int(line.rsplit(":", 1)[1])
        if proc.poll() is not None:
            break
    proc.kill()
    raise AssertionError("ops serve did not start")


def _post(port: int, path: str, body: bytes, token: str | None) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=CALL_TIMEOUT)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("POST", path, body, headers)
    response = conn.getresponse()
    return response.status, response.read()


def test_serve_answers_ops_with_the_bearer_token(tmp_path: Path) -> None:
    workspace, store = tmp_path / "workspace", tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    request = request_for(workspace / "one", store, "one")
    token = secrets.token_hex(16)
    proc, port = _start(workspace, store, token)
    try:
        body = json.dumps(request).encode()
        status, reply = _post(port, "/recoverage.coverage_plan", body, token)
        assert status == 200, reply
        direct_status, direct = ops.dispatch(
            ops.WorkerConfig(workspace.resolve(), store.resolve()), "recoverage.coverage_plan", body
        )
        assert direct_status == 200
        assert json.loads(reply) == json.loads(direct)
        assert _post(port, "/recoverage.coverage_plan", body, None)[0] == 401
        assert _post(port, "/recoverage.coverage_plan", body, "x" * 32)[0] == 401
        status, reply = _post(port, "/recoverage.nope", b"{}", token)
        assert status == 404 and json.loads(reply)["error"] == "unknown-op"
        outside = json.dumps(
            {"project_dir": str(tmp_path), "sha256": "a" * 64, "min_coverage": 0}
        ).encode()
        status, reply = _post(port, "/recoverage.coverage_gate", outside, token)
        assert status == 400 and json.loads(reply)["error"] == "invalid-request"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        finally:
            assert proc.stdout is not None
            proc.stdout.close()


def test_serve_counts_a_non_utf8_token_by_its_bytes(tmp_path: Path) -> None:
    """The token-length check must not raise on a non-UTF-8 env value."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "recoverage",
            "ops",
            "serve",
            "--port",
            "0",
            "--workspace",
            str(tmp_path / "missing"),
        ],
        env={**os.environ, "RECOVERAGE_OPS_TOKEN": "t" * 40 + "ÿ"},
        capture_output=True,
        text=True,
        timeout=START_TIMEOUT,
        check=False,
    )
    assert "UnicodeEncodeError" not in result.stderr
    assert "must hold at least" not in result.stderr


def test_serve_refuses_a_short_token_and_a_missing_workspace(tmp_path: Path) -> None:
    for token, extra in (("short", ["--workspace", str(tmp_path)]), ("t" * 40, [])):
        result = subprocess.run(
            [sys.executable, "-m", "recoverage", "ops", "serve", "--port", "0", *extra],
            env={**os.environ, "RECOVERAGE_OPS_TOKEN": token},
            capture_output=True,
            text=True,
            timeout=START_TIMEOUT,
            check=False,
        )
        assert result.returncode == ops.EXIT_ERROR, result.stderr
