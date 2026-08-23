"""recoverage — coverage dashboard for binary-matching decompilation projects.

Module map (dependencies point one way, left to right):

- ``_paths``      — coverage.db path resolution (no in-package deps)
- ``server``      — Bottle app, hooks/auth, shared helpers (DB open, schema
  check, compression, stats SQL, DLL cache); defines ``app`` but mounts no
  routes itself
- ``potato``      — server-side HTML renderer (imports server)
- ``ui``          — SPA/static routes (imports server; lazily potato)
- ``api``         — /api/* routes (imports server; lazily potato)
- ``webapp``      — composition root: imports api+ui so ``app`` has every
  route; import this when you need a fully wired app
- ``cli``         — Typer entry point (serves ``webapp.app``)

Route modules register on import; there are no cycles.
"""

__version__ = "0.2.0"
