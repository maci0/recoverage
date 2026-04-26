"""Shared test fixtures and helpers for recoverage tests."""

from __future__ import annotations

import sqlite3
from io import BytesIO
from pathlib import Path
from wsgiref.util import setup_testing_defaults

from recoverage.server import app

HAS_DB = (Path.cwd() / "db" / "coverage.db").exists()


def wsgi_request(
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    remote_addr: str = "127.0.0.1",
) -> tuple[str, dict[str, str], bytes]:
    """Issue a WSGI request against the Bottle app and return (status, headers, body)."""
    environ: dict[str, str | BytesIO] = {}
    setup_testing_defaults(environ)
    url_path, _, query = path.partition("?")
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = url_path
    environ["QUERY_STRING"] = query
    environ["REMOTE_ADDR"] = remote_addr
    environ["wsgi.input"] = BytesIO(b"")
    if headers:
        for k, v in headers.items():
            environ[f"HTTP_{k.upper().replace('-', '_')}"] = v

    status_holder: dict[str, str | dict[str, str]] = {"status": "", "headers": {}}

    def _start_response(status: str, response_headers, exc_info=None):
        status_holder["status"] = status
        status_holder["headers"] = {k: v for k, v in response_headers}
        return None

    result = app(environ, _start_response)
    body = b"".join(result)
    return str(status_holder["status"]), dict(status_holder["headers"]), body


def wsgi_get(
    path: str, headers: dict[str, str] | None = None
) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", path, headers)


def wsgi_post(
    path: str,
    headers: dict[str, str] | None = None,
    remote_addr: str = "127.0.0.1",
) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("POST", path, headers, remote_addr=remote_addr)


def decode_body(body: bytes, headers: dict[str, str]) -> bytes:
    """Decompress response body based on Content-Encoding header."""
    encoding = headers.get("Content-Encoding", "")
    if encoding == "gzip":
        import gzip

        return gzip.decompress(body)
    if encoding == "br":
        import brotli

        return brotli.decompress(body)
    if encoding == "zstd":
        import zstandard as zstd

        return zstd.ZstdDecompressor().decompress(body)
    return body


def get_first_target() -> str:
    """Get the first target from the coverage database."""
    from recoverage.server import _db_path

    conn = sqlite3.connect(f"file:{_db_path()}?mode=ro", uri=True)
    try:
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM metadata ORDER BY target LIMIT 1")
        row = c.fetchone()
        return row[0] if row else ""
    finally:
        conn.close()
