"""UI routes for the recoverage dashboard."""

from __future__ import annotations

import threading
from typing import Any
from urllib.parse import urlparse

from recoverage.server import (
    HTTPResponse,
    _assets_dir,
    _best_encoding,
    _compressed,
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
    global CACHED_INDEX_PAYLOAD, CACHED_INDEX_COMPRESSED
    assets = _assets_dir()
    html = (assets / "index.html").read_text(encoding="utf-8")
    css = (assets / "style.css").read_text(encoding="utf-8")
    js = (assets / "app.js").read_text(encoding="utf-8")
    try:
        vanjs = (assets / "van.min.js").read_text(encoding="utf-8")
    except OSError:
        vanjs = ""
    html = html.replace("<!-- INJECT_CSS -->", f"<style>{minify_css(css)}</style>")
    html = html.replace(
        "<!-- INJECT_JS -->",
        f"<script>{vanjs}\n{minify_js(js)}</script>",
    )
    CACHED_INDEX_PAYLOAD = html.encode("utf-8")
    CACHED_INDEX_COMPRESSED.clear()
    return CACHED_INDEX_PAYLOAD


# ── Routes ─────────────────────────────────────────────────────────


@app.get("/potato")
def handle_potato() -> bytes | Any:
    try:
        from recoverage.potato import render_potato  # type: ignore

        parsed = urlparse(request.url)
        body = render_potato(parsed).encode("utf-8")
        return _compressed(body, "text/html; charset=utf-8")
    except Exception as e:
        from html import escape as _esc

        return HTTPResponse(status=500, body=f"Error: {_esc(str(e))}")


@app.get("/")
@app.get("/index.html")
def handle_index() -> bytes:
    accept_encoding = request.headers.get("Accept-Encoding", "")
    encoding = _best_encoding(accept_encoding)

    with INDEX_LOCK:
        if CACHED_INDEX_PAYLOAD is None:
            _build_index_payload()
        payload = CACHED_INDEX_PAYLOAD
        assert payload is not None  # guaranteed by _build_index_payload()
        if encoding not in CACHED_INDEX_COMPRESSED:
            compressed, _ = compress_payload(payload, accept_encoding)
            CACHED_INDEX_COMPRESSED[encoding] = compressed
        body = CACHED_INDEX_COMPRESSED[encoding]

    response.content_type = "text/html; charset=utf-8"
    response.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
    if encoding:
        response.set_header("Content-Encoding", encoding)
    response.set_header("Content-Length", str(len(body)))
    return body


# ── Static file serving ────────────────────────────────────────────


@app.get("/src/<filepath:path>")
@app.get("/original/<filepath:path>")
def serve_repo_file(filepath: str) -> Any:
    prefix = "src" if request.path.startswith("/src/") else "original"
    return static_file(filepath, root=str(_project_dir() / prefix))


@app.get("/<filename:re:(?:app\\.js|style\\.css|van\\.min\\.js)>")
def serve_static_asset(filename: str) -> Any:
    return static_file(filename, root=str(_assets_dir()))
