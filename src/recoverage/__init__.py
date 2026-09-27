"""recoverage — coverage dashboard for binary-matching decompilation projects.

Module map (dependencies point one way, left to right):

- ``config``      — RECOVERAGE_* parsing, validation, startup banner (no
  in-package deps)
- ``_paths``      — coverage.db path resolution (imports config)
- ``regen``       — in-process rebrew regen: imports rebrew's catalog/build-db
  lazily and runs both under one call (no in-package deps)
- ``server``      — Bottle app, hooks/auth, shared helpers (DB open, schema
  check, compression, stats SQL, DLL cache); defines ``app`` plus its
  cross-cutting wiring (auth/log/security-header hooks, 500 handler,
  OPTIONS preflight catch-all) but no content routes; configured at
  startup via ``configure_security()``
- ``potato``      — server-side HTML renderer (imports server)
- ``ui``          — SPA/static routes (imports server; /potato is mounted by
  potato)
- ``disasm``      — Capstone disassembly: availability probe, thread-local Cs,
  per-slice memo (imports server; a capability module, so it imports no route)
- ``api``         — /api/* routes (imports server+regen+disasm; lazily potato)
- ``webapp``      — composition root: imports api+ui+potato so ``app`` has
  every route; import this when you need a fully wired app
- ``cli``         — Typer entry point (serves ``webapp.app``; imports
  server+regen for config and stats helpers)

Route modules register on import; there are no cycles.
``tests/test_import_graph.py`` enforces the level order above and the
acyclicity, so a new module has to declare where it sits.
"""

__version__ = "1.6.0"
