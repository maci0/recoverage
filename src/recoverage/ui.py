"""UI routes for the recoverage dashboard."""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import PurePosixPath
from typing import NamedTuple

import rcssmin
import rjsmin
from bottle import static_file

import recoverage.server as _server
from recoverage.server import (
    CACHE_REVALIDATE,
    SUPPORTED_ENCODINGS,
    HTTPResponse,
    _assets_dir,
    _finalized,
    _header,
    _if_none_match_matches,
    _project_dir,
    _safe_etag,
    app,
    compress_static_bodies,
    compress_static_variants,
    request,
    response,
    select_static_variant,
    static_variant_key,
)

# ── Index caching ──────────────────────────────────────────────────


class _Variant(NamedTuple):
    """One compressed representation and the headers that name it.

    Both response caches in this module store this, and both are unpacked
    positionally, so the field order is a contract: a bytes and two str slots
    in a bare tuple let a swap compile and serve a body under another
    representation's ETag.
    """

    body: bytes
    encoding: str
    etag: str


#: Keyed by :func:`static_variant_key` (the set of encodings the client
#: accepts), NOT by a single chosen encoding: the shell is served as the
#: smallest body the client can decode, so the accepted set is what determines
#: the response.
CACHED_INDEX_PAYLOAD: bytes | None = None
CACHED_INDEX_COMPRESSED: dict[str, _Variant] = {}
INDEX_LOCK = threading.Lock()


def _index_etag(payload: bytes, encoding: str) -> str:
    """Strong validator for the SPA shell, from its source bytes and encoding.

    Derived from the uncompressed payload, not the served body, so the same
    validator holds for every representation of it; the encoding is folded in
    alongside for the same reason :func:`_asset_etag` folds it in — one shell
    compressed as brotli and as zstd is two bodies, and a strong validator must
    not match across them.
    """
    return _safe_etag("index", encoding, hashlib.sha256(payload).hexdigest())


def _build_index_payload() -> bytes:
    """Read the SPA shell, inline its stylesheet and its bundle, return it.

    The bundle is a single IIFE built by Vite from `web/` (`make web-build`), so
    the shell still paints without a render-blocking subresource request: the
    inline is what the first-paint contract buys, and minifying here keeps the
    served bytes independent of what the bundler already did.

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
        # A shipped package asset is missing — the SPA renders but does
        # nothing.  Log it so a broken install is diagnosable.
        _log.warning("app.js missing — dashboard SPA will not function")
        js = ""
    html = html.replace("<!-- INJECT_CSS -->", f"<style>{rcssmin.cssmin(css)}</style>")
    html = html.replace("<!-- INJECT_JS -->", f"<script>{rjsmin.jsmin(js)}</script>")
    payload = html.encode("utf-8")
    _check_payload_budget(payload)
    return payload


#: The shell's own size budget.  It was 10 x 1460 bytes (RFC 6928's initial
#: congestion window) while the frontend was a ~14 KB script that painted the
#: map itself and deferred the rest.  The current frontend is one Preact +
#: Tailwind bundle: measured ~45 KB brotli for the inlined shell and stylesheet,
#: which no longer fits a round trip's initial window and is the price the port
#: was accepted at.  Preact rather than React is most of why it is that small.
#: The number below is the checked ceiling rather than the measurement, so a
#: dependency that doubles the bundle trips the warning instead of growing
#: silently.
_TCP_CWND_BUDGET = 90_000
_log = logging.getLogger("recoverage")


def _check_payload_budget(payload: bytes) -> None:
    """Warn if the inlined index payload exceeds the TCP cwnd budget.

    Measured on the body a modern browser actually receives: the server sends
    the smallest representation the client accepts, and every current browser
    accepts all three, so the served size is the minimum over the three.  That
    is the number that decides whether the shell fits the initial congestion
    window, so it is the number checked here.

    The shell ships as one inlined document so the first paint needs no
    render-blocking subresource request; this is the ratchet that says when that
    document has grown past its budget, naming the exact overage.  See
    ``_TCP_CWND_BUDGET`` for why the number is what it is, and docs/DESIGN.md
    for the measurement.
    """
    # The same bodies the shell is served from, at the same effort, so the
    # measured figure is the one a client receives.  A tie goes to the earlier
    # name in SUPPORTED_ENCODINGS, the tie-break the rest of the package uses.
    bodies = compress_static_bodies(payload)
    best_name = min(SUPPORTED_ENCODINGS, key=lambda name: len(bodies[name]))
    best_size = len(bodies[best_name])
    if best_size <= _TCP_CWND_BUDGET:
        return

    over = best_size - _TCP_CWND_BUDGET
    _log.warning(
        "Inlined index payload (%s %d bytes) exceeds TCP cwnd budget (%d bytes) by %d bytes"
        " (see docs/DESIGN.md, 'First Draw Without a Render-Blocking Request')",
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
        # One key per non-empty subset of the supported encodings, plus "" for
        # the identity response, so a cold first hit from any client is a
        # lookup rather than three full compressions.
        keys = [""]
        for mask in range(1, 1 << len(SUPPORTED_ENCODINGS)):
            subset = [name for i, name in enumerate(SUPPORTED_ENCODINGS) if mask & (1 << i)]
            keys.append(", ".join(subset))
        # Every key picks the smallest of the same three bodies, so the shell is
        # compressed three times for every key rather than once per key, and
        # brotli at BROTLI_STATIC_QUALITY — the most expensive compression in
        # the package, and the one every warm-up used to run four times over —
        # runs once.
        bodies = compress_static_bodies(payload)
        variants: dict[str, _Variant] = {}
        for key in keys:
            body, encoding = select_static_variant(bodies, key, payload)
            variants[key] = _Variant(body, encoding, _index_etag(payload, encoding))
        with INDEX_LOCK:
            if CACHED_INDEX_PAYLOAD is None:
                CACHED_INDEX_PAYLOAD = payload
            for key, variant in variants.items():
                CACHED_INDEX_COMPRESSED.setdefault(key, variant)
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
    # server.set_auth_cookie owns the spelling; Potato Mode calls it too.
    _server.set_auth_cookie()

    global CACHED_INDEX_PAYLOAD
    accept_encoding = _header("Accept-Encoding", "")
    key = static_variant_key(accept_encoding)

    with INDEX_LOCK:
        cached = CACHED_INDEX_COMPRESSED.get(key)
        if CACHED_INDEX_PAYLOAD is not None and cached is not None:
            return _finalized_shell(cached)
        # Build the payload only on a true cold miss; otherwise compress the
        # cached payload for this (previously unseen) key.
        payload_local = CACHED_INDEX_PAYLOAD
    if payload_local is None:
        payload_local = _build_index_payload()
    body, encoding = compress_static_variants(payload_local, accept_encoding)
    etag = _index_etag(payload_local, encoding)
    with INDEX_LOCK:
        if CACHED_INDEX_PAYLOAD is None:
            CACHED_INDEX_PAYLOAD = payload_local
        CACHED_INDEX_COMPRESSED.setdefault(key, _Variant(body, encoding, etag))
        variant = CACHED_INDEX_COMPRESSED[key]

    return _finalized_shell(variant)


def _finalized_shell(variant: _Variant) -> bytes:
    """Answer a SPA-shell request: 304 when the client's copy is current.

    The shell is built once from the package's own assets and cannot change
    under a running server, so it belongs to the same class as the static
    assets below — but it was served ``no-store`` with no validator, which made
    it the one response in the set that a repeat visit could never skip.  Every
    reload re-downloaded the whole shell while the assets answered
    304.  Revalidate instead: the unchanged case now costs a header round trip
    and no body.

    max-age stays off for the reason the static assets document: the URL is not
    content-hashed, so a package upgrade changes the bytes under the same name
    and a long freshness lifetime would pin the browser to an old shell.
    """
    body, encoding, etag = variant
    if _if_none_match_matches(request.headers.get("If-None-Match", ""), etag):
        raise _not_modified(etag)
    return _finalized(
        response,
        body,
        "text/html; charset=utf-8",
        encoding,
        ETag=etag,
        Cache_Control=CACHE_REVALIDATE,
    )


# ── Static file serving ────────────────────────────────────────────


@app.get("/src/<filepath:path>")
@app.get("/original/<filepath:path>")
def serve_repo_file(filepath: str) -> bytes | HTTPResponse:
    prefix = "src" if request.path.startswith("/src/") else "original"
    root = (_project_dir() / prefix).resolve()
    # The capture is the raw, still percent-encoded request path (PEP 3333),
    # so a source file whose name holds a space or a non-ASCII character
    # arrives as "weird%20name.c" and matches no file.  Decoded once, before
    # the containment check below, which then sees the real path — the
    # reverse order would decode after the check had passed.
    filepath = _server.path_param(filepath)
    # A NUL cannot appear in a filename, and os.realpath rejects one with
    # ValueError, so the containment check below would raise and answer a 500
    # with a traceback for a path no filesystem holds.  404 is the honest
    # answer: there is no such file.
    if "\x00" in filepath:
        return _server._json_err(
            404,
            {
                "error": "Not found",
                "detail": "no such file: the path holds a NUL byte",
            },
        )
    # Defense-in-depth: bottle's static_file string-prefix check does NOT
    # resolve symlinks — a symlink inside src/ pointing outside the tree
    # would pass the root check and serve the target.  Resolve and verify
    # containment ourselves.
    candidate = (root / filepath).resolve()
    if not candidate.is_relative_to(root):
        return _server._json_err(
            403,
            {
                "error": "Forbidden",
                "detail": "path escapes the project tree",
            },
        )
    return static_file(filepath, root=str(root))


# Compressed static assets, memoized per (filename, accepted-encoding set).
# These files ship with the package and cannot change under a running server,
# so the compression is paid once per set and every later hit is a dict lookup
# — which is why this uses the precompressed path (maximum effort on every
# accepted encoding, smallest body wins) rather than the dynamic one.  Measured
# on the built bundle: brotli q=11 is measurably smaller than q=5, and its cost
# runs once instead of per request.
#
# static_file served these raw: the bundle is ~130 KB and the stylesheet ~22 KB,
# both of which brotli down by a third or more, and the set is what the shell
# links beside itself.
#
# Each entry carries a strong ETag next to the body.  CACHE_REVALIDATE alone
# ("no-cache") forces the browser back on every load, and with no validator to
# compare, the only answer is to re-send the whole compressed body: a repeat
# visit to the dashboard re-downloaded them.  With the ETag those repeat visits
# answer 304: no body, no decompression, no parse.
# max-age is deliberately NOT raised — the URLs are not content-hashed, so a
# package upgrade changes the bytes under the same name and a long-lived
# freshness lifetime would pin the browser to old JS.  Revalidate cheaply
# instead of guessing.
#: ``(filename, accepted-encoding key)`` -> ``(etag, body, encoding)``.  The
#: key is the whole accepted set, not one token, so the map is bounded by
#: (route-matched filename) x (server.static_variant_key spellings).  The
#: encoding rides with the entry because the choice is made per accepted set,
#: not once per file: it is what Content-Encoding must name, and the cache hit
#: path needs it just as much as the build path.
_STATIC_CACHE: dict[tuple[str, str], _Variant] = {}
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


def _not_modified(etag: str) -> HTTPResponse:
    """The 304 both revalidating surfaces answer: the shell and the static assets."""
    return HTTPResponse(
        status=304,
        headers={"ETag": etag, "Vary": "Accept-Encoding", "Cache-Control": CACHE_REVALIDATE},
    )


@app.get("/<filename:re:(?:app\\.js|style\\.css|print\\.css|favicon\\.svg)>")
def serve_static_asset(filename: str) -> bytes | HTTPResponse:
    accept_encoding = _header("Accept-Encoding", "")
    variant_key = static_variant_key(accept_encoding)
    if not variant_key:
        # No shared encoding: hand off to bottle, which still does Range and
        # If-Modified-Since on the raw file.
        return static_file(filename, root=str(_assets_dir()))

    key = (filename, variant_key)
    with _STATIC_LOCK:
        entry = _STATIC_CACHE.get(key)
    if entry is None:
        path = _assets_dir() / filename
        try:
            raw = path.read_bytes()
        except OSError:
            # Missing/unreadable asset: let bottle produce the 404, don't 500.
            return static_file(filename, root=str(_assets_dir()))
        body, encoding = compress_static_variants(raw, accept_encoding)
        # A racing thread may already have filled this key; keep whichever
        # landed first so every client sees one body under one ETag.
        with _STATIC_LOCK:
            entry = _STATIC_CACHE.setdefault(
                key, _Variant(body, encoding, _asset_etag(filename, encoding, raw))
            )

    body, encoding, etag = entry
    if _if_none_match_matches(_header("If-None-Match", ""), etag):
        return _not_modified(etag)

    suffix = PurePosixPath(filename).suffix.lower()
    content_type = _STATIC_TYPES.get(suffix, "application/octet-stream")
    return _finalized(
        response, body, content_type, encoding, ETag=etag, Cache_Control=CACHE_REVALIDATE
    )
