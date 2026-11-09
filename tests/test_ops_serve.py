"""``recoverage ops serve`` answers the same ops as ``dispatch`` over rebrew's HTTP server."""

import http.client
import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from test_ops_retained import request_for

from recoverage import __version__, ops

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("rebrew.coverage_input_contract") is None,
    reason="requires Rebrew 6.23.1 with coverage_input_contract",
)

START_TIMEOUT = 30.0
SPAN_KIND_SERVER = 2  # OTLP SpanKind
CALL_TIMEOUT = 60.0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start(
    workspace: Path, store: Path, token: str, extra_env: dict[str, str] | None = None
) -> tuple[subprocess.Popen[str], int]:
    port = _free_port()  # the server's Host allow-list names the port it was asked for
    env = {**os.environ, "RECOVERAGE_OPS_TOKEN": token, **(extra_env or {})}
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
            ops.WorkerConfig(workspace=workspace.resolve(), filestore=store.resolve()),
            "recoverage.coverage_plan",
            body,
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


def test_serve_refuses_a_padded_token(tmp_path: Path) -> None:
    for token in (" " + "t" * 40, "t" * 40 + " ", "t" * 20 + " " + "t" * 19):
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
                str(tmp_path),
            ],
            env={**os.environ, "RECOVERAGE_OPS_TOKEN": token},
            capture_output=True,
            text=True,
            timeout=START_TIMEOUT,
            check=False,
        )
        assert result.returncode == ops.EXIT_ERROR, result.stderr
        assert "whitespace" in result.stderr, result.stderr


class _Collector:
    """An OTLP/HTTP collector on a free loopback port that keeps every trace export it receives."""

    def __init__(self) -> None:
        received = self.received = []  # type: list[dict[str, Any]]

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers["Content-Length"])
                if self.path == "/v1/traces":
                    received.append(json.loads(self.rfile.read(length)))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002  # overrides the stdlib name
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(START_TIMEOUT)

    def spans(self) -> list[dict[str, Any]]:
        return [
            span
            for export in self.received
            for resource in export["resourceSpans"]
            for scope in resource["scopeSpans"]
            for span in scope["spans"]
        ]


def _attributes(span: dict[str, Any]) -> dict[str, str]:
    return {item["key"]: next(iter(item["value"].values())) for item in span.get("attributes", [])}


def test_serve_exports_one_server_span_per_post_to_the_collector(tmp_path: Path) -> None:
    workspace, store = tmp_path / "workspace", tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    request = json.dumps(request_for(workspace / "one", store, "one")).encode()
    token = secrets.token_hex(16)
    trace_id, caller_span = secrets.token_hex(16), secrets.token_hex(8)
    collector = _Collector()
    proc, port = _start(workspace, store, token, {"RECOVERAGE_OTLP_ENDPOINT": collector.url})
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=CALL_TIMEOUT)
        conn.request(
            "POST",
            "/recoverage.coverage_plan",
            request,
            {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "traceparent": f"00-{trace_id}-{caller_span}-01",
            },
        )
        assert conn.getresponse().status == 200
        assert _post(port, "/recoverage.nope", b"{}", token)[0] == 404
        assert _post(port, "/recoverage.coverage_plan", request, None)[0] == 401
    finally:
        proc.terminate()  # SIGTERM drains and flushes the exporter
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        finally:
            assert proc.stdout is not None
            proc.stdout.close()
            collector.close()
    resources = [
        {item["key"]: item["value"]["stringValue"] for item in r["resource"]["attributes"]}
        for export in collector.received
        for r in export["resourceSpans"]
    ]
    assert {r["service.name"] for r in resources} == {ops.OTEL_SERVICE_NAME}
    assert all(r["service.version"] == __version__ for r in resources)
    by_name = {}
    for span in collector.spans():
        by_name.setdefault(span["name"], []).append(span)
    assert sorted(by_name) == ["POST /recoverage.coverage_plan", "POST /unknown"]
    (ok,) = by_name["POST /recoverage.coverage_plan"]
    assert _attributes(ok)["http.response.status_code"] == "200"
    assert ok["kind"] == SPAN_KIND_SERVER
    assert ok["traceId"] == trace_id
    assert ok["parentSpanId"] == caller_span
    assert _attributes(ok)["http.route"] == "/recoverage.coverage_plan"
    assert _attributes(ok)["http.request.method"] == "POST"
    # Refusals before dispatch (401) and unknown ops (404) share the bounded "unknown" route.
    statuses = [_attributes(s)["http.response.status_code"] for s in by_name["POST /unknown"]]
    assert sorted(statuses) == ["401", "404"]


def test_serve_refuses_an_endpoint_that_is_not_an_http_url(tmp_path: Path) -> None:
    for endpoint in ("collector:4318", "ftp://collector", "http://user:pw@collector:4318"):
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
                str(tmp_path),
            ],
            env={
                **os.environ,
                "RECOVERAGE_OPS_TOKEN": "t" * 40,
                "RECOVERAGE_OTLP_ENDPOINT": endpoint,
            },
            capture_output=True,
            text=True,
            timeout=START_TIMEOUT,
            check=False,
        )
        assert result.returncode == ops.EXIT_ERROR, result.stderr
        assert "RECOVERAGE_OTLP_ENDPOINT must be an http(s) URL" in result.stderr
        assert "serving recoverage ops" not in result.stdout
