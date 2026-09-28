"""Builders for synthetic coverage TOML documents.

The suite used to create a SQLite ``coverage.db`` per fixture: the shared
synthetic database at the repo root, and one throwaway per test that needed a
different shape.  The dashboard reads rebrew's clear-text coverage documents
now, so the fixtures write those instead.  The helpers below are the one place
that knows the document layout — a test states the facts it wants and never the
TOML syntax, so a format change lands here rather than in a hundred tests.

Nothing here imports rebrew's writer: that renders from a catalog snapshot
(``db/data_<target>.json``), which is a different input from the hand-written
shape a test wants to pin.  The documents written here are the same schema,
written directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

#: Schema version the reader accepts.  Spelled out rather than imported so a
#: test that pins the served ``known_schema`` list states the number it expects.
TOML_VERSION = 1

#: ``functions`` columns the reader's ``Function`` dataclass carries.  A test
#: names only the ones it cares about; everything else takes the default below,
#: which is what the writer's own column defaults are.
_FUNCTION_DEFAULTS: dict[str, Any] = {
    "va": 0,
    "name": "",
    "vaStart": "",
    "size": None,
    "fileOffset": None,
    "status": "UNKNOWN",
    "module": "",
    "cflags": "",
    "symbol": "",
    "markerType": "FUNCTION",
    "ghidra_name": "",
    "list_name": "",
    "is_thunk": 0,
    "is_export": 0,
    "sha256": "",
    "files": (),
    "detected_by": (),
    "size_by_tool": {},
    "textOffset": None,
    "blocker": "",
    "blockerDelta": None,
    "size_reason": "",
    "similarity": None,
    "updated_by": "",
    "updated_at": "",
}

_GLOBAL_DEFAULTS: dict[str, Any] = {
    "va": 0,
    "name": "",
    "decl": "",
    "files": (),
    "module": "",
    "size": 4,
    "status": "",
}


def _toml_value(value: Any) -> str:
    """Render one TOML value.

    ``json.dumps`` is a TOML basic string for the escapes TOML shares, and the
    three containers below are rendered structurally.  ``None`` becomes ``""``,
    which is the one spelling this format has for an absent optional field.
    """
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, dict):
        inner = ", ".join(f"{_toml_key(k)} = {_toml_value(v)}" for k, v in value.items())
        return "{" + inner + "}"
    if isinstance(value, list | tuple):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise TypeError(f"cannot render {type(value).__name__} as TOML")


#: Characters a TOML bare key may hold; anything else is quoted.
_BARE_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _toml_key(name: str) -> str:
    if name and all(ch in _BARE_KEY_CHARS for ch in name):
        return name
    return json.dumps(name)


def _function_row(entry: dict[str, Any]) -> dict[str, Any]:
    row = dict(_FUNCTION_DEFAULTS)
    unknown = set(entry) - set(row)
    if unknown:
        raise KeyError(f"unknown function field(s): {sorted(unknown)}")
    row.update(entry)
    return row


def _global_row(entry: dict[str, Any]) -> dict[str, Any]:
    row = dict(_GLOBAL_DEFAULTS)
    unknown = set(entry) - set(row)
    if unknown:
        raise KeyError(f"unknown global field(s): {sorted(unknown)}")
    row.update(entry)
    return row


def _cell_row(entry: dict[str, Any]) -> dict[str, Any]:
    """One cell, from a dict or the compact ``(start, end, state)`` tuple."""
    row = {
        "start": 0,
        "end": 0,
        "span": 1,
        "state": "none",
        "functions": (),
        "label": "",
        "parent_function": "",
    }
    row.update(entry)
    return row


def cell(start: int, end: int, state: str, **extra: Any) -> dict[str, Any]:
    """A cell with the three fields every fixture names, plus any overrides."""
    return _cell_row({"start": start, "end": end, "state": state, **extra})


def render_coverage(
    target: str,
    sections: dict[str, dict[str, Any]],
    *,
    functions: list[dict[str, Any]] = (),
    globals_: list[dict[str, Any]] = (),
    verify_results: list[dict[str, Any]] = (),
    history: list[dict[str, Any]] = (),
    paths: dict[str, Any] | None = None,
    version: int = TOML_VERSION,
) -> str:
    """Render one ``coverage-<target>.toml`` document as text.

    *sections* maps a section name to its scalars (``va``, ``size``,
    ``fileOffset``, ``unitBytes``, ``columns``) and a ``cells`` list.  The
    arrays come before the first table header on purpose: a bare key written
    after a ``[table]`` header belongs to that table, so the document would
    parse into the wrong shape.
    """
    lines = [
        f"# Synthetic coverage document for {target}.",
        f"version = {version}",
        f"target = {_toml_value(target)}",
    ]
    if functions:
        lines.append(
            "functions = [\n  "
            + ",\n  ".join(_toml_value(_function_row(entry)) for entry in functions)
            + "\n]"
        )
    if globals_:
        lines.append(
            "globals = [\n  "
            + ",\n  ".join(_toml_value(_global_row(entry)) for entry in globals_)
            + "\n]"
        )
    if verify_results:
        lines.append(
            "verify_results = [\n  "
            + ",\n  ".join(_toml_value(dict(entry)) for entry in verify_results)
            + "\n]"
        )
    if history:
        lines.append(
            "history = [\n  " + ",\n  ".join(_toml_value(dict(e)) for e in history) + "\n]"
        )
    lines.append("")
    lines.append("[metadata]")
    lines.append(f"paths = {_toml_value(paths or {})}")
    for name, definition in sections.items():
        lines.append("")
        lines.append(f"[sections.{_toml_key(name)}]")
        lines.extend(
            f"{key} = {_toml_value(definition.get(key))}"
            for key in ("va", "size", "fileOffset", "unitBytes", "columns")
        )
        cells = [_cell_row(entry) for entry in definition.get("cells", [])]
        if cells:
            lines.append("cells = [\n  " + ",\n  ".join(_toml_value(row) for row in cells) + "\n]")
    return "\n".join(lines) + "\n"


def write_coverage(
    directory: Path,
    target: str,
    sections: dict[str, dict[str, Any]],
    **kwargs: Any,
) -> Path:
    """Write ``<directory>/coverage-<target>.toml`` and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"coverage-{target}.toml"
    path.write_text(render_coverage(target, sections, **kwargs), encoding="utf-8")
    return path


def coverage_dir(root: Path, *parts: str) -> Path:
    """The coverage directory a fixture's documents belong in, beneath *root*.

    Spelled ``db`` on purpose: ``RECOVERAGE_DB`` names the directory itself,
    while rebrew's reader takes the project ROOT and resolves the configured
    ``db_dir`` (``<root>/db`` by default) beneath it, so the two only agree when
    the directory carries that name.  Extra *parts* give one test several
    independent roots, so a second fixture cannot be read through the first
    one's override.
    """
    return root.joinpath(*parts, "db")
