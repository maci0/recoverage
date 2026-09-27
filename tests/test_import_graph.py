"""The in-package import graph must stay acyclic and one-directional.

``recoverage.__init__`` carries the module map and ``recoverage.webapp`` draws
the graph, but prose drifts: this pins the shape those two describe, so a new
module has to declare where it sits and a new import that points the wrong way
fails instead of quietly layering the package the other direction.

Two rules, off one source of truth:

- every edge runs from a module at or above its dependency's level
  (:data:`_LEVELS`), so nothing below the transport imports a route module;
- the graph is acyclic.

:data:`_LEVEL_ORDER_EXCEPTIONS` is the escape hatch and is meant to stay empty.
``disasm`` sits below the route modules and reaches up into ``server`` for the
DLL byte cache; :data:`_CAPABILITY_MODULES` names that band explicitly rather
than hiding the reach in the level numbers, so a SECOND capability module
reaching up the same way is a visible addition instead of a silent one.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PACKAGE = "recoverage"
_SRC = Path(__file__).resolve().parent.parent / "src" / _PACKAGE

#: Layer index per module: 0 is a leaf, higher numbers may import lower ones.
_LEVELS: dict[str, int] = {
    "__init__": 0,
    "clock": 0,
    "config": 0,
    "metrics": 0,
    "regen": 0,
    "_paths": 1,
    "server": 2,
    "disasm": 3,
    "api": 4,
    "potato": 4,
    "ui": 4,
    "webapp": 5,
    "cli": 6,
    "__main__": 7,
}

#: Edges that point the wrong way, and why each is allowed to.  Empty today;
#: a new entry is a deliberate layering decision that says so in its reason.
_LEVEL_ORDER_EXCEPTIONS: dict[tuple[str, str], str] = {}

#: Pure capability modules: one concern each, no routes, no app wiring.  They
#: may reach into the shared kernel below them, and that is the only upward
#: edge they get — importing a route module would invert the graph.
_CAPABILITY_MODULES = frozenset({"disasm"})

#: What a capability module may reach up into.  ``server`` owns the DLL byte
#: cache, the schema check and the compressor handles, so a capability that
#: needs one of those reads it from there.
_CAPABILITY_ALLOWED_UP = frozenset({"server"})

#: Names ``recoverage/__init__.py`` defines; every other ``from recoverage
#: import X`` is a submodule import, not a name.
_PACKAGE_EXPORTS = frozenset({"__version__"})


def _in_package_imports(path: Path) -> set[str]:
    """Modules under test that *path* imports, at any nesting depth.

    Function-local imports count: the CLI reaches for ``api`` and ``ui`` inside
    command bodies, and a wrong-direction import hidden in a function body is
    the same edge as one at the top.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level != 0 or not node.module:
                continue
            head = node.module.split(".")
            if len(head) >= 2 and head[0] == _PACKAGE:
                found.add(head[1])
            elif node.module == _PACKAGE:
                # The original name, not the asname: `from recoverage import
                # server as _server` still names the server module.
                found.update(n.name for n in node.names)
                found -= _PACKAGE_EXPORTS
        elif isinstance(node, ast.Import):
            for alias in node.names:
                head = alias.name.split(".")
                if len(head) >= 2 and head[0] == _PACKAGE:
                    found.add(head[1])
    return found - {path.stem}


def _graph() -> dict[str, set[str]]:
    return {p.stem: _in_package_imports(p) for p in sorted(_SRC.glob("*.py"))}


def test_every_module_declares_its_level() -> None:
    """A module missing from _LEVELS is one nobody has placed in the graph."""
    on_disk = {p.stem for p in _SRC.glob("*.py")}
    assert on_disk == set(_LEVELS), (
        f"unplaced: {sorted(on_disk - set(_LEVELS))}, "
        f"absent from disk: {sorted(set(_LEVELS) - on_disk)}"
    )


@pytest.mark.parametrize("importer", sorted(_LEVELS))
def test_imports_point_one_way(importer: str) -> None:
    for dependency in _graph()[importer]:
        if (importer, dependency) in _LEVEL_ORDER_EXCEPTIONS:
            continue
        assert _LEVELS[importer] >= _LEVELS[dependency], (
            f"{_PACKAGE}.{importer} (level {_LEVELS[importer]}) imports "
            f"{_PACKAGE}.{dependency} (level {_LEVELS[dependency]}), which points "
            f"the wrong way"
        )


@pytest.mark.parametrize("importer", sorted(_CAPABILITY_MODULES))
def test_capability_modules_import_no_route_module(importer: str) -> None:
    for dependency in _graph()[importer]:
        assert dependency in _CAPABILITY_ALLOWED_UP, (
            f"{_PACKAGE}.{importer} is a capability module and may import only "
            f"{sorted(_CAPABILITY_ALLOWED_UP)}, not {_PACKAGE}.{dependency}"
        )


def test_no_import_cycles() -> None:
    graph = _graph()
    cycles: list[tuple[str, ...]] = []
    for start in sorted(graph):
        stack: list[tuple[str, tuple[str, ...]]] = [(start, (start,))]
        while stack:
            node, path = stack.pop()
            for nxt in sorted(graph[node]):
                if nxt in path:
                    cycles.append((*path[path.index(nxt) :], nxt))
                else:
                    stack.append((nxt, (*path, nxt)))
    assert not cycles, f"import cycles: {cycles}"
