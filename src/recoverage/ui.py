"""UI routes for the recoverage dashboard."""

from __future__ import annotations

import contextlib
import gzip
import logging
import sqlite3
import threading
from typing import Any
from urllib.parse import urlparse

import brotli  # type: ignore[import-untyped]
import zstandard as zstd

from recoverage.server import (
    BROTLI_STATIC_QUALITY,
    CACHE_NO_STORE,
    HTTPResponse,
    _assets_dir,
    _best_encoding,
    _compressed,
    _etag_or_304,
    _finalized,
    _project_dir,
    app,
    compress_payload,
    minify_css,
    minify_js,
    request,
    response,
    static_file,
)

# ── Index caching ──────────────────────────────────────────────────

CACHED_INDEX_PAYLOAD: bytes | None = None
CACHED_INDEX_COMPRESSED: dict[str, bytes] = {}
INDEX_LOCK = threading.Lock()


def clear_index_cache() -> None:
    global CACHED_INDEX_PAYLOAD, CACHED_INDEX_COMPRESSED
    with INDEX_LOCK:
        CACHED_INDEX_PAYLOAD = None
        CACHED_INDEX_COMPRESSED.clear()


def _build_index_payload() -> bytes:
    """Read the SPA shell, inline minified CSS/JS into it, return it.

    Pure: caching is the caller's job (it already holds INDEX_LOCK).
    """
    assets = _assets_dir()
    html = (assets / "index.html").read_text(encoding="utf-8")
    css = (assets / "style.css").read_text(encoding="utf-8")
    js = (assets / "app.js").read_text(encoding="utf-8")
    try:
        vanjs = (assets / "van.min.js").read_text(encoding="utf-8")
    except OSError:
        # A shipped package asset is missing — the SPA renders but does
        # nothing.  Log it so a broken install is diagnosable.
        _log.warning("van.min.js missing — dashboard SPA will not function")
        vanjs = ""
    html = html.replace("<!-- INJECT_CSS -->", f"<style>{minify_css(css)}</style>")
    html = html.replace(
        "<!-- INJECT_JS -->",
        f"<script>{vanjs}\n{minify_js(js)}</script>",
    )
    payload = html.encode("utf-8")
    _check_payload_budget(payload)
    return payload


_TCP_CWND_BUDGET = 14_600
_log = logging.getLogger("recoverage")


def _check_payload_budget(payload: bytes) -> None:
    """Warn if the inlined index payload exceeds the TCP cwnd budget.

    Tries every available compression method and reports the best result.
    """
    results: list[tuple[str, int]] = [
        ("gzip", len(gzip.compress(payload))),
        ("br", len(brotli.compress(payload))),
        ("zstd", len(zstd.ZstdCompressor(level=3).compress(payload))),
    ]

    best_name, best_size = min(results, key=lambda r: r[1])
    if best_size <= _TCP_CWND_BUDGET:
        return

    over = best_size - _TCP_CWND_BUDGET
    _log.warning(
        "Inlined index payload (%s %d bytes) exceeds TCP cwnd budget (%d bytes) by %d bytes",
        best_name,
        best_size,
        _TCP_CWND_BUDGET,
        over,
    )


# ── Routes ─────────────────────────────────────────────────────────


@app.get("/potato")
def handle_potato() -> bytes | Any:
    try:
        from recoverage.potato import render_potato

        # WAL-aware snapshot (see _snapshot_db_mtime), not raw st_mtime: a
        # rebuild that commits only to -wal must still mint a new ETag or
        # browsers keep a stale 304.  Same contract as /data, /asm, /bytes.
        etag = _etag_or_304(request.query_string)
        body = render_potato(urlparse(request.url)).encode("utf-8")
        resp_body = _compressed(body, "text/html; charset=utf-8")

        if etag:
            response.set_header("ETag", etag)
        return resp_body

    # json.JSONDecodeError needs no entry: it subclasses ValueError.
    except (sqlite3.Error, OSError, ValueError, KeyError):
        _log.exception("Potato mode render failed")
        return HTTPResponse(
            status=500,
            body="<html><body>Internal server error</body></html>",
        )


@app.get("/")
@app.get("/index.html")
def handle_index() -> bytes:
    # When token auth is enabled, opening the dashboard as
    # http://host:port/?token=<TOKEN> sets an HttpOnly SameSite cookie so
    # the SPA's own fetch/EventSource calls authenticate without any
    # frontend change.  API clients can use Authorization: Bearer instead.
    global CACHED_INDEX_PAYLOAD
    from recoverage.server import _AUTH_TOKEN, _auth_token_matches

    if _AUTH_TOKEN and _auth_token_matches(request.query.get("token", "")):
        # Header failure must not break the page.
        with contextlib.suppress(Exception):
            response.set_header(
                "Set-Cookie",
                f"recoverage_token={_AUTH_TOKEN}; Path=/; HttpOnly; SameSite=Strict",
            )

    accept_encoding = request.headers.get("Accept-Encoding", "")
    encoding = _best_encoding(accept_encoding)

    with INDEX_LOCK:
        if CACHED_INDEX_PAYLOAD is None:
            CACHED_INDEX_PAYLOAD = _build_index_payload()
        payload = CACHED_INDEX_PAYLOAD
        if encoding not in CACHED_INDEX_COMPRESSED:
            # Maximum brotli effort here: this runs once per encoding and the
            # result is cached, and the byte budget is the whole point.
            compressed, _ = compress_payload(
                payload, accept_encoding, brotli_quality=BROTLI_STATIC_QUALITY
            )
            CACHED_INDEX_COMPRESSED[encoding] = compressed
        body = CACHED_INDEX_COMPRESSED[encoding]

    return _finalized(body, "text/html; charset=utf-8", encoding, Cache_Control=CACHE_NO_STORE)


# ── Static file serving ────────────────────────────────────────────


@app.get("/src/<filepath:path>")
@app.get("/original/<filepath:path>")
def serve_repo_file(filepath: str) -> Any:
    prefix = "src" if request.path.startswith("/src/") else "original"
    root = (_project_dir() / prefix).resolve()
    # Defense-in-depth: bottle's static_file string-prefix check does NOT
    # resolve symlinks — a symlink inside src/ pointing outside the tree
    # would pass the root check and serve the target.  Resolve and verify
    # containment ourselves.
    candidate = (root / filepath).resolve()
    if not candidate.is_relative_to(root):
        return HTTPResponse(
            status=403,
            body=b"forbidden",
        )
    return static_file(filepath, root=str(root))


@app.get(
    "/<filename:re:(?:app\\.js|detail\\.js|style\\.css|print\\.css|van\\.min\\.js|favicon\\.svg"
    "|hljs\\.css|hljs\\.min\\.js|hljs-c\\.min\\.js|hljs-x86asm\\.min\\.js)>"
)
def serve_static_asset(filename: str) -> Any:
    return static_file(filename, root=str(_assets_dir()))
