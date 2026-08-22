"""Composition root — the fully wired Bottle application.

``recoverage.server`` only defines the shared ``app`` (hooks, auth, error
handlers); ``recoverage.api`` and ``recoverage.ui`` mount their routes on it
at import time.  Those two imports live HERE, not at the bottom of
server.py, so the dependency graph stays one-directional:

    _paths ← server ← {potato, ui, api} ← webapp ← cli

Import this module (or run the CLI) whenever you need an app with every
route registered; importing bare ``recoverage.server`` yields a routeless app.
"""

from __future__ import annotations

import recoverage.api  # noqa: F401 — mounts /api/* routes on server.app
import recoverage.ui  # noqa: F401 — mounts / , /potato and static routes
from recoverage.server import app

__all__ = ["app"]
