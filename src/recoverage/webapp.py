"""Composition root — the fully wired Bottle application.

``recoverage.server`` only defines the shared ``app`` (hooks, auth, error
handlers, and the CORS preflight catch-all); ``recoverage.api``,
``recoverage.ui`` and ``recoverage.potato`` mount their routes on it at import
time.  Those three imports live HERE, not at the bottom of server.py, so the
dependency graph stays one-directional:

    config ← _paths ← server ← {potato, ui, api, disasm} ← webapp ← cli

(api and cli additionally import regen — an in-process rebrew catalog/build-db
wrapper with no in-package dependencies; rebrew's heavy imports stay off the
dashboard's start path.)

Import this module (or run the CLI) whenever you need an app with every
route registered; importing bare ``recoverage.server`` yields a routeless app.
"""

from __future__ import annotations

from typing import Any

import bottle  # type: ignore[import-untyped]

import recoverage.api  # mounts /api/* routes on server.app
import recoverage.potato  # mounts /potato on server.app
import recoverage.ui  # noqa: F401 — mounts / and the static routes
from recoverage.server import _json_err, _log_safe, app, request

__all__ = ["app"]


def _build_method_probe(routes: list[bottle.Route]) -> bottle.Router:
    """A second router holding *routes*, for asking which verbs a path takes.

    The catch-all below makes every path "routable", so bottle's own router
    never reaches its 404/405 verdict.  This probe replays the real routes
    through bottle's matcher — the authority on wildcard syntax, filters, and
    the Allow header — so the answer cannot drift from the routing that
    actually serves requests.
    """
    probe = bottle.Router()
    for route in routes:
        declared = route.method
        for method in [declared] if isinstance(declared, str) else declared:
            probe.add(route.rule, method, route.callback, None)
    return probe


_METHOD_PROBE: bottle.Router = _build_method_probe(app.routes)


def _allowed_methods(path: str) -> list[str]:
    """Verbs *path* accepts on the real routes, or ``[]`` when none match it.

    OPTIONS is dropped: the CORS preflight catch-all matches every path, so
    keeping it would put OPTIONS in the Allow of a URL that does not exist.
    HEAD is added alongside GET because the server really does dispatch it,
    while bottle's own router reports only the verbs a rule declares.
    """
    try:
        _METHOD_PROBE.match({"REQUEST_METHOD": request.method, "PATH_INFO": path})
    except bottle.HTTPError as exc:
        if exc.status_code != 405:
            return []
        allow = exc.headers.get("Allow", "")
        methods = {m for m in (part.strip() for part in allow.split(",")) if m and m != "OPTIONS"}
        if "GET" in methods:
            methods.add("HEAD")
        return sorted(methods)
    return []


def _method_not_allowed() -> Any:
    """The shared 405 body: the verb, the path, and the verbs that do work."""
    allow = _allowed_methods(request.path)
    return _json_err(
        405,
        {
            "error": "Method not allowed",
            "detail": f"{_log_safe(request.method)} is not allowed on "
            f"{_log_safe(request.path)}; allowed: {', '.join(allow) or 'none'}",
        },
        **({"Allow": ", ".join(allow)} if allow else {}),
    )


# Registered LAST (after api+ui above), this fallback keeps unmatched paths a
# 404.  Without it, the CORS preflight catch-all in server.py — the only rule
# matching every path — makes bottle answer unknown GETs/POSTs with "405
# Method Not Allowed", which wrongly asserts the resource exists.
@app.route("<path:path>", method=["GET", "POST", "PUT", "DELETE", "PATCH"])
def _unmatched_route(path: str) -> Any:
    # Answering every miss with 404 also swallows the verb: `POST /api/health`
    # and `GET /api/regen` name resources that DO exist, so a client
    # branching on 404 (stop, drop the resource) against 405 (use another
    # verb) is mis-told either way.  A verb the catch-all does not list never
    # reaches it at all, so the two error handlers below cover that half.
    if _allowed_methods(request.path):
        return _method_not_allowed()
    return _json_err(
        404,
        {
            "error": "Not found",
            "detail": f"no such endpoint: {_log_safe(request.path)}",
        },
    )


# A verb outside the catch-all's list (OPTIONS aside, which the preflight rule
# owns) is rejected by bottle's router before any handler runs, so it lands on
# bottle's HTML error page.  /api/* consumers get the JSON envelope every other
# failure uses; browser paths keep the HTML page.
@app.error(405)
def _handle_method_not_allowed(error: Any) -> Any:
    if not request.path.startswith("/api/"):
        return app.default_error_handler(error)
    return _method_not_allowed()


@app.error(404)
def _handle_not_found(error: Any) -> Any:
    if not request.path.startswith("/api/"):
        return app.default_error_handler(error)
    return _json_err(
        404,
        {
            "error": "Not found",
            "detail": f"no such endpoint: {_log_safe(request.path)}",
        },
    )
