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
from collections.abc import Sequence
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
    functions: Sequence[dict[str, Any]] = (),
    globals_: Sequence[dict[str, Any]] = (),
    verify_results: Sequence[dict[str, Any]] = (),
    history: Sequence[dict[str, Any]] = (),
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


# ── The shared synthetic document set ───────────────────────────────────────────────────
# Kept here rather than in ``conftest`` so a tool that needs the same documents
# (``tools/_serve_harness.build_sample_db``, behind smoke and the HTML lint)
# imports a module with no pytest wiring and no import-time side effect.

TARGET = "FAKEDLL"

SECTIONS: dict[str, dict[str, Any]] = {
    ".text": {
        "va": 0x10001000,
        "size": 0x1000,
        "fileOffset": 0x200,
        "unitBytes": 16,
        "columns": 8,
        "cells": [
            cell(0, 16, "exact", functions=("_func_a",)),
            cell(16, 32, "reloc", functions=("_func_b",)),
            cell(32, 48, "stub", functions=("_func_c",)),
            cell(48, 64, "padding"),
            cell(64, 80, "data", label="jt_10001060"),
            cell(80, 96, "thunk", parent_function="_func_a"),
            cell(96, 112, "none"),
            cell(112, 128, "exact"),
        ],
    },
    ".data": {
        "va": 0x10002000,
        "size": 0x400,
        "fileOffset": 0x1200,
        "unitBytes": 16,
        "columns": 8,
        "cells": [cell(0, 16, "data", functions=("g_counter",), label="g_counter")],
    },
}

#: The three functions and one global every fixture-driven assertion is written
#: against.  Kept as module data so a test that needs a different shape can
#: write its own document rather than editing the shared one.
FUNCTIONS: list[dict[str, Any]] = [
    {
        "va": 0x10001000,
        "name": "_func_a",
        "vaStart": "0x10001000",
        "size": 48,
        "fileOffset": 0x200,
        "status": "EXACT",
        "module": "T",
        "cflags": "/O2",
        "symbol": "_func_a",
    },
    {
        "va": 0x10001010,
        "name": "_func_b",
        "vaStart": "0x10001010",
        "size": 16,
        "fileOffset": 0x210,
        "status": "RELOC",
        "module": "T",
        "cflags": "/O2",
        "symbol": "_func_b",
    },
    {
        "va": 0x10001030,
        "name": "_func_c",
        "vaStart": "0x10001030",
        "size": 32,
        "fileOffset": 0x230,
        "status": "STUB",
        "module": "T",
        "cflags": "",
        "symbol": "_func_c",
    },
]

GLOBALS: list[dict[str, Any]] = [
    {
        "va": 0x10002000,
        "name": "g_counter",
        "decl": "int g_counter",
        "module": "T",
        "size": 4,
    },
]

VERIFY_RESULTS: list[dict[str, Any]] = [
    {
        "va": 0x10001000,
        "verified_at": "2026-01-01T00:00:00+00:00",
        "byte_delta": 0,
        "diff_lines": 0,
        # 0.873, the unit-interval fraction rebrew's verify import stores
        # (its schema CHECKs 0..1); 87.3 would be 8730%.
        "similarity": 0.873,
    }
]


def build_synthetic_coverage(directory: Path) -> Path:
    """Write the shared synthetic documents into *directory*.

    Rebuilds unconditionally: every file is removed first, so a second run over
    the same directory produces the same documents as the first instead of
    leaving one from a previous run behind.  *directory* is a parameter rather
    than a fixed ``<cwd>/db`` so a caller that imports this module once can
    still build coverage somewhere else.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("coverage-*.toml"):
        stale.unlink()
    return write_coverage(
        directory,
        TARGET,
        SECTIONS,
        functions=FUNCTIONS,
        globals_=GLOBALS,
        verify_results=VERIFY_RESULTS,
    )


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
