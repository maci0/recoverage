"""UI routes for the recoverage dashboard."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import logging
import threading
from pathlib import PurePosixPath
from typing import Any

import brotli  # type: ignore[import-untyped]
import rcssmin  # type: ignore[import-untyped]
import rjsmin  # type: ignore[import-untyped]
import zstandard as zstd

import recoverage.server as _server
from recoverage.server import (
    BROTLI_STATIC_QUALITY,
    CACHE_NO_STORE,
    CACHE_REVALIDATE,
    HTTPResponse,
    _assets_dir,
    _best_encoding,
    _finalized,
    _if_none_match_matches,
    _project_dir,
    _safe_etag,
    app,
    compress_payload,
    request,
    response,
    static_file,
)

# ── Index caching ──────────────────────────────────────────────────

CACHED_INDEX_PAYLOAD: bytes | None = None
CACHED_INDEX_COMPRESSED: dict[str, bytes] = {}
INDEX_LOCK = threading.Lock()


def _build_index_payload() -> bytes:
    """Read the SPA shell, inline minified CSS/JS into it, return it.

    Pure: caching is the caller's job (it already holds INDEX_LOCK).
    """
    assets = _assets_dir()
    html = (assets / "index.html").read_text(encoding="utf-8")
    try:
        css = (assets / "style.css").read_text(encoding="utf-8")
    except OSError:
        _log.warning("style.css missing — dashboard SPA will render unstyled")
        css = ""
    try:
        js = (assets / "app.js").read_text(encoding="utf-8")
    except OSError:
        _log.warning("app.js missing — dashboard SPA will not function")
        js = ""
    try:
        vanjs = (assets / "van.min.js").read_text(encoding="utf-8")
    except OSError:
        # A shipped package asset is missing — the SPA renders but does
        # nothing.  Log it so a broken install is diagnosable.
        _log.warning("van.min.js missing — dashboard SPA will not function")
        vanjs = ""
    html = html.replace("<!-- INJECT_CSS -->", f"<style>{rcssmin.cssmin(css)}</style>")
    html = html.replace(
        "<!-- INJECT_JS -->",
        f"<script>{vanjs}\n{rjsmin.jsmin(js)}</script>",
    )
    payload = html.encode("utf-8")
    _check_payload_budget(payload)
    return payload


_TCP_CWND_BUDGET = 14_600
_log = logging.getLogger("recoverage")


def _check_payload_budget(payload: bytes) -> None:
    """Warn if the inlined index payload exceeds the TCP cwnd budget.

    Tries every available compression method and reports the best result.

    The budget is the initial congestion window (10 x 1460-byte MSS), so the
    payload should arrive in one round trip.  It currently fits with little to
    spare: everything deferrable (the asm fetch, its formatting, the canvas
    coverage map, and the highlight.js load among it) lives in ``detail.js``,
    so a new byte has to come out of there rather than out of the window.  The
    warning is the ratchet that says so, naming the exact overage.
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
        "Inlined index payload (%s %d bytes) exceeds TCP cwnd budget (%d bytes) by %d bytes"
        " (move deferrable work into detail.js instead; see docs/DESIGN.md)",
        best_name,
        best_size,
        _TCP_CWND_BUDGET,
        over,
    )


def warm_index_cache() -> None:
    """Pre-build the SPA shell payload and every compressed variant.

    ``handle_index`` otherwise pays the asset read + minify + three
    full-strength compressions under INDEX_LOCK on the FIRST client's
    request; ``serve`` runs this from a daemon thread before the listener
    starts so every first hit is a pure lookup.  Failures are logged and
    left lazy: the request path rebuilds whatever is missing.
    """
    global CACHED_INDEX_PAYLOAD
    try:
        payload = _build_index_payload()
        compressed_variants: dict[str, bytes] = {}
        for encoding in ("zstd", "br", "gzip", ""):
            c, _ = compress_payload(payload, encoding, brotli_quality=BROTLI_STATIC_QUALITY)
            compressed_variants[encoding] = c
        with INDEX_LOCK:
            if CACHED_INDEX_PAYLOAD is None:
                CACHED_INDEX_PAYLOAD = payload
            for enc, comp in compressed_variants.items():
                CACHED_INDEX_COMPRESSED.setdefault(enc, comp)
    except Exception:
        _log.warning(
            "SPA shell cache warm-up failed — first index request will build it instead",
            exc_info=True,
        )


# ── Routes ─────────────────────────────────────────────────────────
#
# /potato is registered by recoverage.potato, which owns the renderer; only
# the SPA shell and the static assets below belong to this module.


@app.get("/")
@app.get("/index.html")
def handle_index() -> bytes:
    # When token auth is enabled, opening the dashboard as
    # http://host:port/?token=<TOKEN> sets an HttpOnly SameSite cookie so
    # the SPA's own fetch/EventSource calls authenticate without any
    # frontend change.  API clients can use Authorization: Bearer instead.
    global CACHED_INDEX_PAYLOAD

    if _server._AUTH_TOKEN and _server._auth_token_matches(request.query.get("token", "")):
        # Header failure must not break the page.
        with contextlib.suppress(Exception):
            response.set_header(
                "Set-Cookie",
                f"recoverage_token={_server._AUTH_TOKEN}; Path=/; HttpOnly; SameSite=Strict",
            )

    accept_encoding = request.headers.get("Accept-Encoding", "")
    encoding = _best_encoding(accept_encoding)

    with INDEX_LOCK:
        if CACHED_INDEX_PAYLOAD is not None and encoding in CACHED_INDEX_COMPRESSED:
            body = CACHED_INDEX_COMPRESSED[encoding]
            return _finalized(
                body, "text/html; charset=utf-8", encoding, Cache_Control=CACHE_NO_STORE
            )
        # Build the payload only on a true cold miss; otherwise compress the
        # cached payload for this (previously unseen) encoding.
        payload_local = CACHED_INDEX_PAYLOAD
        build = payload_local is None
    if build:
        payload_local = _build_index_payload()
    assert payload_local is not None
    compressed, _ = compress_payload(
        payload_local, accept_encoding, brotli_quality=BROTLI_STATIC_QUALITY
    )
    with INDEX_LOCK:
        if CACHED_INDEX_PAYLOAD is None:
            CACHED_INDEX_PAYLOAD = payload_local
        CACHED_INDEX_COMPRESSED.setdefault(encoding, compressed)
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


# Compressed static assets, memoized per (filename, encoding).  These files
# ship with the package and cannot change under a running server, so the
# compression is paid once per encoding and every later hit is a dict lookup —
# which is why this uses BROTLI_STATIC_QUALITY like the index, not the dynamic
# quality (measured on hljs.min.js: q=11 is 37.7 KB vs q=5's 41.4 KB, and its
# 101 ms runs once instead of per request).
#
# static_file served these raw: detail.js is on the first-paint critical path
# at 27 KB, and hljs.min.js — fetched when a function's asm pane opens — is
# 127 KB.  Both brotli down to roughly a third of that, and the whole set is
# ~150 KB raw.
#
# Each entry carries a strong ETag next to the body.  CACHE_REVALIDATE alone
# ("no-cache") forces the browser back on every load, and with no validator to
# compare, the only answer is to re-send the whole compressed body: a repeat
# visit to the dashboard re-downloaded detail.js and every asm pane opening
# re-downloaded hljs.min.js plus its grammars.  With the ETag those repeat
# visits answer 304: no body, no decompression, no parse.
# max-age is deliberately NOT raised — the URLs are not content-hashed, so a
# package upgrade changes the bytes under the same name and a long-lived
# freshness lifetime would pin the browser to old JS.  Revalidate cheaply
# instead of guessing.
_STATIC_CACHE: dict[tuple[str, str], tuple[str, bytes]] = {}
_STATIC_LOCK = threading.Lock()

_STATIC_TYPES = {
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
}


def _asset_etag(filename: str, encoding: str, raw: bytes) -> str:
    """Strong validator for a static asset, from its bytes and its encoding.

    The encoding is part of the tag because it is part of the representation:
    one file compressed as brotli and as zstd is two different bodies, and a
    strong validator must not match across them.  Vary: Accept-Encoding keeps
    shared caches from mixing them; this keeps client caches honest too.
    """
    return _safe_etag("static", filename, encoding, hashlib.sha256(raw).hexdigest())


def _client_has_asset(etag: str) -> bool:
    """Whether the request's If-None-Match already covers *etag* (RFC 9110 13.1.2).

    Weak comparison, which is what If-None-Match calls for: a browser holding
    the asset as W/"..." still gets its 304.  The accepted spellings come from
    the shared matcher, so static assets and DB-derived responses cannot drift.
    """
    return _if_none_match_matches(request.headers.get("If-None-Match", ""), etag)


@app.get(
    "/<filename:re:(?:app\\.js|detail\\.js|style\\.css|print\\.css|van\\.min\\.js|favicon\\.svg"
    "|hljs\\.css|hljs\\.min\\.js|hljs-c\\.min\\.js|hljs-x86asm\\.min\\.js)>"
)
def serve_static_asset(filename: str) -> Any:
    accept_encoding = request.headers.get("Accept-Encoding", "")
    encoding = _best_encoding(accept_encoding)
    if not encoding:
        # No shared encoding: hand off to bottle, which still does Range and
        # If-Modified-Since on the raw file.
        return static_file(filename, root=str(_assets_dir()))

    key = (filename, encoding)
    with _STATIC_LOCK:
        entry = _STATIC_CACHE.get(key)
    if entry is None:
        path = _assets_dir() / filename
        try:
            raw = path.read_bytes()
        except OSError:
            # Missing/unreadable asset: let bottle produce the 404, don't 500.
            return static_file(filename, root=str(_assets_dir()))
        body, encoding = compress_payload(
            raw, accept_encoding, brotli_quality=BROTLI_STATIC_QUALITY
        )
        # A racing thread may already have filled this key; keep whichever
        # landed first so every client sees one body under one ETag.
        with _STATIC_LOCK:
            entry = _STATIC_CACHE.setdefault(key, (_asset_etag(filename, encoding, raw), body))

    etag, body = entry
    if _client_has_asset(etag):
        return HTTPResponse(
            status=304,
            headers={"ETag": etag, "Vary": "Accept-Encoding", "Cache-Control": CACHE_REVALIDATE},
        )

    suffix = PurePosixPath(filename).suffix.lower()
    content_type = _STATIC_TYPES.get(suffix, "application/octet-stream")
    return _finalized(body, content_type, encoding, ETag=etag, Cache_Control=CACHE_REVALIDATE)
