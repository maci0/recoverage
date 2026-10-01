"""The frontend import graph must stay acyclic and one-directional.

``tests/test_import_graph.py`` holds the same rule for the Python package, where
``recoverage.__init__``'s module map documents the layers.  The Preact tree has
no such map: nothing in ``web/`` says which directory may import which, so a
``@/hooks`` import inside ``@/lib`` (a hook the presentation layer owns, in the
pure-helper layer) type checks, bundles, and ships.  The bundler accepts it, so
the direction is held here instead.

One rule, one source of truth (:data:`_LEVELS`): every edge runs from a module
at or above its dependency's level, and the graph is acyclic.  A module missing
from the table is one nobody has placed, so :func:`test_every_module_declares_
its_level` fails rather than letting the table quietly under-cover the tree.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parent.parent / "web" / "app"

#: Layer index per module or directory: 0 is a leaf, higher numbers may import
#: lower ones.  A directory entry covers every module beneath it, and a module
#: named explicitly overrides the directory it sits in.
_LEVELS: dict[str, int] = {
    "api": 0,
    "grid": 0,
    "lib": 0,
    "states": 0,
    # The relumea design system, copied verbatim from relumea.ai: tokens,
    # icons and the Icon component, which import nothing of this app.
    "system": 0,
    "hooks": 1,
    "components": 2,
    "App": 3,
    "main": 4,
    # The highlighter's own build entry: a second bundle the dashboard fetches
    # on the first code pane, so it sits with `main` as an entry point. It
    # imports no module of this app, so nothing points at it and nothing is
    # imported through it; the level is here because the table must place every
    # module, and an entry point is the top of the tree by definition.
    "highlight-entry": 4,
}

#: ``import ... from "@/<spec>"`` and the bare ``import "<spec>"`` form, both
#: single-quoted because that is what the tree is formatted with (oxlint's
#: quotemark rule would rewrite the other spelling to this one).
_IMPORT = re.compile(
    r"""^\s*(?:import|export)[^'"\n]*from\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)

_ALIAS = "@/"


def _module_id(path: Path) -> str:
    """The module's key: its path under ``web/app``, extension dropped."""
    return path.relative_to(_APP).with_suffix("").as_posix()


def _level(module_id: str) -> int:
    """The layer of *module_id*, from its own entry or the directory holding it."""
    if module_id in _LEVELS:
        return _LEVELS[module_id]
    return _LEVELS[module_id.split("/", 1)[0]]


def _sources() -> dict[str, str]:
    return {
        _module_id(p): p.read_text(encoding="utf-8")
        for p in sorted(_APP.rglob("*.ts")) + sorted(_APP.rglob("*.tsx"))
    }


def _in_app_imports(source: str) -> set[str]:
    """Modules under ``web/app`` that *source* imports, by module key."""
    found: set[str] = set()
    for groups in _IMPORT.findall(source):
        spec = groups[0] or groups[1]
        if not spec.startswith(_ALIAS):
            continue
        target = spec[len(_ALIAS) :]
        if target.endswith(".css"):
            continue
        found.add(target.removesuffix(".ts").removesuffix(".tsx"))
    return found


def _graph() -> dict[str, set[str]]:
    return {module_id: _in_app_imports(src) for module_id, src in _sources().items()}


def test_every_module_declares_its_level() -> None:
    """A module under no named directory is one the table does not cover."""
    unplaced = sorted(
        m for m in _sources() if m not in _LEVELS and m.split("/", 1)[0] not in _LEVELS
    )
    assert not unplaced, f"unplaced: {unplaced}"


@pytest.mark.parametrize("importer", sorted(_sources()))
def test_imports_point_one_way(importer: str) -> None:
    for dependency in sorted(_graph()[importer]):
        assert _level(importer) >= _level(dependency), (
            f"web/app/{importer} (level {_level(importer)}) imports "
            f"web/app/{dependency} (level {_level(dependency)}), which points "
            f"the wrong way"
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
