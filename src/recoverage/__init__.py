"""recoverage — coverage dashboard for binary-matching decompilation projects.

Module map (dependencies point one way, left to right):

- ``clock``       — the one time source the request path reads (no in-package
  deps)
- ``metrics``     — in-process RED + connection + regen counters (no in-package
  deps)
- ``config``      — RECOVERAGE_* parsing, validation, startup banner (no
  in-package deps)
- ``devserver``   — the WSGI serving stack: socket family, admission cap, socket
  deadline, keep-alive framing (imports config+metrics; stdlib only)
- ``_paths``      — coverage-directory resolution (imports config)
- ``regen``       — in-process rebrew regen: imports rebrew's catalog/build-db
  lazily and runs both under one call (no in-package deps)
- ``server``      — Bottle app, hooks/auth, shared helpers (snapshot access,
  compression, stats, DLL cache, the ``is_plain_relative`` path-containment
  rule every route and the C-source reader share); defines ``app`` plus its
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
- ``__main__``    — ``python -m recoverage``; forwards argv to ``cli.main``

Route modules register on import; there are no cycles.
``tests/test_import_graph.py`` enforces the level order above, the acyclicity,
and that every module here is named in this map, so a new module has to
declare where it sits.
"""

__version__ = "4.1.0"
