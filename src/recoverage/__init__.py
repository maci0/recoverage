"""recoverage — coverage dashboard for binary-matching decompilation projects.

Module map (dependencies point one way, left to right):

- ``clock``       — the one time source the request path reads (no in-package
  deps)
- ``metrics``     — in-process RED + connection + regen counters (no in-package
  deps)
- ``status_colors`` — shared terminal status palette (no in-package deps)
- ``config``      — RECOVERAGE_* parsing, validation, startup banner; also the
  one ASCII-integer parse (``parse_ascii_int``/``strip_sign``) every
  request-supplied number reads — ``int()``'s Unicode digits and ``_``
  separator would otherwise name a value no surface documents (no in-package
  deps)
- ``devserver``   — the WSGI serving stack: socket family, admission cap, socket
  deadline, keep-alive framing (imports config+metrics; stdlib only)
- ``_paths``      — live project or explicit portable snapshot resolution (imports config)
- ``documents``   — immutable live views or portable documents read per file;
  portable TOML parses persist across restarts
- ``backup``      — verified backup/restore of explicitly selected portable exports
- ``regen``       — explicit refresh of Rebrew's shared live project view
  (cross-process regen lock; no in-package deps)
- ``server``      — Bottle app, hooks/auth, shared helpers (snapshot access,
  compression, stats, DLL cache, the ``is_plain_relative`` path-containment
  rule every route and the C-source reader share); defines ``app`` plus its
  cross-cutting wiring (auth/log/security-header hooks, 500 handler,
  OPTIONS preflight catch-all) but no content routes; configured at
  startup via ``configure_security()``
- ``reporting``   — the report's rows, escaping, exports, gate verdict and the
  floored percentage helpers (``coverage_pct``/``pct_1dp``) every surface
  prints, shared by the CLI and the ops so every surface prints the same
  numbers (no in-package deps; a leaf the route modules read directly, never
  through ``server``)
- ``potato``      — server-side HTML renderer (imports server+disasm+_paths)
- ``ui``          — SPA/static routes (imports server; /potato is mounted by
  potato)
- ``disasm``      — Capstone disassembly: availability probe, thread-local Cs,
  per-slice memo (imports server; a capability module, so it imports no route)
- ``api``         — /api/* routes (imports server+regen+disasm+_paths+clock+metrics)
- ``webapp``      — composition root: imports api+ui+potato so ``app`` has
  every route; import this when you need a fully wired app
- ``cli``         — Typer entry point (serves ``webapp.app``; imports
  server+regen for config and stats helpers, and reports through ``reporting``)
- ``ops``         — the ``recoverage.*`` ops the backend dispatches: one JSON
  request on stdin, one reply on stdout (imports reporting+_paths; reaches
  documents and server lazily inside operation bodies)
- ``clispec``     — clispec 0.3 document for the CLI (no in-package imports)
- ``__main__``    — ``python -m recoverage``; forwards argv to ``cli.main``

Route modules register on import; there are no cycles.
``tests/test_import_graph.py`` enforces the level order above, the acyclicity,
and that every module here is named in this map, so a new module has to
declare where it sits.

Public library surface
----------------------
``recoverage.RecoError`` (and its subclasses, listed in ``__all__``), the
``configure_security`` startup policy, and ``recoverage.app`` — the fully
wired WSGI application to mount — are the names a library consumer reaches
for first.  Every name is imported lazily so ``recoverage`` itself stays
importable without its heavy dependencies (Bottle, Rebrew).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recoverage.backup import BackupError
    from recoverage.config import ConfigError, RecoError
    from recoverage.disasm import CapstoneUnavailableError
    from recoverage.ops import OpsError
    from recoverage.regen import RegenBusyError, RegenError
    from recoverage.server import LOOPBACK_HOSTS, RequestBodyError, configure_security
    from recoverage.ui import MissingAssetError
    from recoverage.webapp import app


def __dir__() -> list[str]:
    """Names the package exposes, including the lazy ones.

    Without this, ``dir(recoverage)`` omits ``RecoError`` and ``app`` (they
    are not in the module ``__dict__``), so tab-completion and
    ``help(recoverage)`` do not surface the public library API.
    """
    return sorted({*globals(), *__all__})


def __getattr__(name: str) -> object:
    """Lazy attribute access for the public library surface.

    ``RecoError``/``ConfigError`` come from :mod:`recoverage.config`, the
    five remaining error subclasses from their own modules, ``app`` from
    :mod:`recoverage.webapp` (the composition root that mounts every route),
    and ``configure_security``/``LOOPBACK_HOSTS`` from :mod:`recoverage.server`;
    each is imported only on first access so importing ``recoverage`` does
    not pay for Bottle or Rebrew.
    """
    if name == "RecoError":
        from recoverage.config import RecoError

        return RecoError
    if name == "ConfigError":
        from recoverage.config import ConfigError

        return ConfigError
    if name == "BackupError":
        from recoverage.backup import BackupError

        return BackupError
    if name == "CapstoneUnavailableError":
        from recoverage.disasm import CapstoneUnavailableError

        return CapstoneUnavailableError
    if name == "MissingAssetError":
        from recoverage.ui import MissingAssetError

        return MissingAssetError
    if name == "OpsError":
        from recoverage.ops import OpsError

        return OpsError
    if name == "RegenBusyError":
        from recoverage.regen import RegenBusyError

        return RegenBusyError
    if name == "RegenError":
        from recoverage.regen import RegenError

        return RegenError
    if name == "RequestBodyError":
        from recoverage.server import RequestBodyError

        return RequestBodyError
    if name == "LOOPBACK_HOSTS":
        from recoverage.server import LOOPBACK_HOSTS

        return LOOPBACK_HOSTS
    if name == "configure_security":
        from recoverage.server import configure_security

        return configure_security
    if name == "app":
        from recoverage.webapp import app

        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__version__ = "8.14.0"

__all__ = [
    "LOOPBACK_HOSTS",
    "BackupError",
    "CapstoneUnavailableError",
    "ConfigError",
    "MissingAssetError",
    "OpsError",
    "RecoError",
    "RegenBusyError",
    "RegenError",
    "RequestBodyError",
    "__version__",
    "app",
    "configure_security",
]
