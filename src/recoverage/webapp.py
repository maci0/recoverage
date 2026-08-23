"""Composition root — the fully wired Bottle application.

``recoverage.server`` only defines the shared ``app`` (hooks, auth, error
handlers); ``recoverage.api`` and ``recoverage.ui`` mount their routes on it
at import time.  Those two imports live HERE, not at the bottom of
server.py, so the dependency graph stays one-directional:

    _paths ← server ← {potato, ui, api} ← webapp ← cli

(api and cli additionally import regen — a subprocess-lifecycle module with
no in-package dependencies.)

Import this module (or run the CLI) whenever you need an app with every
route registered; importing bare ``recoverage.server`` yields a routeless app.
"""

from __future__ import annotations

from typing import Any

import recoverage.api  # mounts /api/* routes on server.app
import recoverage.ui  # noqa: F401 — mounts / , /potato and static routes
from recoverage.server import _json_err, app

__all__ = ["app"]


# Registered LAST (after api+ui above), this fallback keeps unmatched paths a
# 404.  Without it, the CORS preflight catch-all in server.py — the only rule
# matching every path — makes bottle answer unknown GETs/POSTs with "405
# Method Not Allowed", which wrongly asserts the resource exists.
@app.route("<path:path>", method=["GET", "POST", "PUT", "DELETE", "PATCH"])
def _unmatched_route(path: str) -> Any:
    return _json_err(404, {"error": "Not found", "detail": f"no such endpoint: /{path}"})
