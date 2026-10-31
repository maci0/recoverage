"""An opened source file's ETag is hashed once, until its bytes change."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import decode_body, wsgi_get

from recoverage import server, ui


def _etag(headers: dict[str, str]) -> str:
    return next(value for key, value in headers.items() if key.lower() == "etag")


def _source(marker: bytes) -> bytes:
    """A compressible source file. *marker* is one byte, so two calls match in length."""
    return (b"int opened(void) { return " + marker + b"; }\n") * 40


def test_an_opened_file_builds_its_etag_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two requests for one unchanged file hash its body once.

    The validator is the hash of the whole file. A second request, the same
    file and the same selection, used to hash that body again. A rewrite of
    the same length at the same timestamp still has to build a new validator:
    the stat did not move, and the bytes did.
    """
    root = tmp_path
    source = root / "src"
    source.mkdir()
    path = source / "opened.c"
    original = _source(b"1")
    path.write_bytes(original)
    assert len(original) >= 1024

    monkeypatch.setattr(ui, "_project_dir", lambda: root)
    server._OPENED_FILE_ETAGS.clear()
    builds = 0
    real = server._build_opened_file_etag

    def counting(file_path: str, encoding_key: str, raw: bytes) -> str:
        nonlocal builds
        builds += 1
        return real(file_path, encoding_key, raw)

    monkeypatch.setattr(server, "_build_opened_file_etag", counting)
    headers = {"Accept-Encoding": "gzip"}
    try:
        status, first_headers, first_body = wsgi_get("/src/opened.c", headers)
        assert status.startswith("200"), status
        assert builds == 1, f"the first request built the etag {builds} times"
        assert decode_body(first_body, first_headers) == original

        status, second_headers, second_body = wsgi_get("/src/opened.c", headers)
        assert status.startswith("200"), status
        assert second_body == first_body
        assert _etag(second_headers) == _etag(first_headers)
        assert builds == 1, f"two requests for one unchanged file built the etag {builds} times"

        rewritten = _source(b"2")
        assert len(rewritten) == len(original)
        stamp = path.stat()
        path.write_bytes(rewritten)
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        assert path.stat().st_mtime_ns == stamp.st_mtime_ns
        assert path.stat().st_size == stamp.st_size

        status, third_headers, third_body = wsgi_get("/src/opened.c", headers)
        assert status.startswith("200"), status
        assert builds == 2, f"a byte change built the etag {builds} times"
        assert decode_body(third_body, third_headers) == rewritten
        assert _etag(third_headers) != _etag(first_headers)
        assert third_body != first_body
    finally:
        server._OPENED_FILE_ETAGS.clear()
