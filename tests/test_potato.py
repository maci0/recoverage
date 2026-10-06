"""Potato Mode (`recoverage.potato`): the pure-HTML fallback surface.

Two kinds of case share the file, and which one a test is decides what it can
prove:

- **Rendered.** `render_potato_url` runs the whole render — routing, the
  snapshot, the grid, the panel, the topbar — and the assertion reads the HTML
  a browser would parse. This is the only kind that can observe a bug a reader
  would see: a count on the status line, a row missing from the list, a cell
  that dimmed when it should not have stayed lit. Where a render test and a
  helper test could both exist, the render one is the oracle, because the bug
  was in the render and the helper assertions passed with it in place.
- **Unit.** The formatting and path helpers (`_format_va`, `_build_url`,
  `_esc`, `_wrap_text`, `_parent_url`, `_cell_dim_keys`) are called directly
  with edge-case inputs the render path cannot be steered into cheaply. These
  pin the argument handling and say nothing about the page, so no user-visible
  claim is left resting on one alone.

The organising rule throughout is that a case NAME is a claim about behaviour
and the assertion has to be able to fail: the URL table below states, per
query, what must and must not appear, so a renderer that dropped the filter,
ignored `?search=` or echoed a payload unescaped fails rather than satisfies
the list. The same rule is why the search groups rebuild the expected match
set in Python (or take a hand-written document) instead of asserting that a
string is present somewhere in the page.

Fixtures: `HAS_DB` cases read the shared synthetic document set; everything
else writes its own document into `tmp_path` via `_write_doc`, which also
points `RECOVERAGE_DB` at it. No case reaches a real project or the network.
"""

import base64
import functools
import os
import re
import subprocess
import unicodedata
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import SimpleNamespace
from typing import Any, ClassVar
from urllib.parse import quote, unquote, urlparse

import pytest
from conftest import HAS_DB, path_the_filesystem_holds, require_target, wsgi_get
from coverage_fixture import cell, coverage_dir, known_cell_states, write_coverage
from rebrew.coverage_toml import CoverageSnapshot, load_coverage

from recoverage.potato import (
    _MAX_RENDERED_COLUMNS,
    _RENDER_ERROR_BODY,
    BG_COLOR,
    BORDER_COLOR,
    MUTED_COLOR,
    PANEL_COLOR,
    TRACK_UNITS,
    _AccessKey,
    _build_filter_data,
    _build_progress,
    _build_url,
    _cell_file_offset,
    _compute_section_stats,
    _db_unavailable_page,
    _db_updated_iso,
    _db_updated_label,
    _esc,
    _extract_annotations,
    _format_data_inspector,
    _format_hex_dump,
    _format_va,
    _load_grid_cells,
    _load_section_data,
    _panel_fn_source_text,
    _progress_svg,
    _render_original_bytes,
    _search_functions,
    _section_heading,
    _section_tab_data,
    _wrap_text,
    render_potato,
)
from recoverage.server import (
    _snapshot_db_mtime,
    fold_can_match_hex,
    fold_match_folded,
    fold_needle,
    is_plain_relative,
)


def render_potato_url(url: str) -> str:
    return render_potato(urlparse(url))


# ── Test-local coverage documents ──────────────────────────────────
#
# The suite used to build a throwaway SQLite database per fixture.  The
# dashboard reads rebrew's clear-text coverage documents now, so a fixture is a
# document written with coverage_fixture.write_coverage plus the one environment
# variable that points the server at it.


def _write_doc(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    sections: dict[str, dict[str, Any]],
    **kwargs: Any,
) -> CoverageSnapshot:
    """Write ``<root>/db/coverage-<target>.toml`` and point the server at it.

    Returns the loaded snapshot: every helper this file unit-tests takes one of
    these instead of the cursor it read through when coverage lived in SQLite.
    Each caller names its own *target* so one fixture's snapshot cannot be
    confused with another's.
    """
    directory = coverage_dir(root)
    write_coverage(directory, target, sections, **kwargs)
    monkeypatch.setenv("RECOVERAGE_DB", str(directory))
    return load_coverage(root, target)


def _shared_snapshot() -> CoverageSnapshot:
    """The first target of the shared synthetic documents conftest writes.

    Reads the ambient ``<cwd>/db`` the way the server does, so a
    ``HAS_DB``-gated assertion exercises the same document the render does.
    """
    target = require_target()
    return load_coverage(Path.cwd(), target)


@functools.cache
def _have_html5_tidy() -> bool:
    """HTML Tidy 5 understands <main>; Apple's 2006 tidy does not."""
    try:
        proc = subprocess.run(["tidy", "-version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    text = b"".join((proc.stdout, proc.stderr)).decode("utf-8", "replace").lower()
    return "version 5" in text


def _test_tidy(html: str) -> tuple[bool | None, str]:
    # VNU is the HTML5 gate (bun run lint:html). tidy is extra, and only
    # HTML Tidy 5 can judge this document; Apple tidy rejects <main>.
    if not _have_html5_tidy():
        return None, "html5 tidy not available"
    try:
        proc = subprocess.run(
            ["tidy", "-q", "-e"],
            input=html.encode("utf-8"),
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError:
        return None, "tidy not installed"
    except subprocess.TimeoutExpired:
        return False, "tidy timeout"
    diag = (proc.stderr or b"").decode("utf-8", "replace") or (proc.stdout or b"").decode(
        "utf-8", "replace"
    )
    if proc.returncode > 1:
        if not diag.strip():
            return None, "tidy produced no diagnostics"
        return False, diag
    return True, ""


def test_section_stats_come_from_the_document_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-section stats are derived from the document's own cells.

    The SQLite era materialized a ``section_cell_stats`` table and had to
    re-aggregate from ``cells`` when it was missing; the document stores no
    derived counts at all, so every section is answered from its own cell list
    and the two surfaces cannot disagree about one section's buckets.
    """
    snap = _write_doc(
        tmp_path,
        monkeypatch,
        "T",
        {
            ".text": {
                "size": 3,
                "cells": [cell(0, 1, "exact"), cell(1, 2, "none"), cell(2, 3, "stub")],
            }
        },
    )
    stats = _compute_section_stats(snap, {".text": {"size": 3}}, {})
    assert stats[".text"]["total"] == 3
    assert stats[".text"]["exact"] == 1
    assert stats[".text"]["stub"] == 1


def test_format_va():
    assert _format_va(268439552) == "0x10001000"
    assert _format_va(0) == "0x00000000"
    assert _format_va("0x10003da0") == "0x10003da0"
    assert _format_va("0XABC") == "0XABC"
    assert _format_va("4096") == "0x00001000"
    assert _format_va("not_a_number") == "not_a_number"


def test_section_stats_pct_rounds_like_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The map-header percentage rounds to 2dp (same as /api .../stats).

    int() truncation made 1329/1330 bytes read "99% covered" in the Potato
    map header while the topbar, the SPA overlay, and the API all said
    ~99.92% for the same section.
    """
    snap = _write_doc(
        tmp_path,
        monkeypatch,
        "T",
        {
            ".text": {
                "size": 1330,
                "cells": [
                    cell(0, 1, "exact"),
                    cell(1, 2, "exact"),
                    cell(2, 3, "exact"),
                    cell(3, 4, "none"),
                ],
            }
        },
    )
    sections = {".text": {"size": 1330}}
    data = {"summary": {".text": {"coveredBytes": 1329}}}
    stats = _compute_section_stats(snap, sections, data)
    assert stats[".text"]["pct"] == round(1329 / 1330 * 100, 2)
    assert stats[".text"]["pct"] != int(1329 / 1330 * 100)


def test_section_stats_pct_zero_size_is_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snap = _write_doc(
        tmp_path, monkeypatch, "T", {".bss": {"size": 0, "cells": [cell(0, 1, "none")]}}
    )
    # A zero-size (.bss-style) section must not divide by zero: pct is 0.
    stats = _compute_section_stats(snap, {".bss": {"size": 0}}, {"summary": {}})
    assert stats[".bss"]["pct"] == 0


def test_section_stats_pct_null_size_is_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same contract as the zero-size case above, with an absent size.

    TOML has no null: a section whose size the catalog could not state reads
    back as 0, and ``sections.get(name, {}).get("size")`` returns None for a
    caller that spells the section that way.  ``None > 0`` raised TypeError —
    a raw 500 through handle_potato's except tuple — instead of the pct 0 this
    asserts.
    """
    snap = _write_doc(
        tmp_path, monkeypatch, "T", {".bss": {"size": None, "cells": [cell(0, 1, "none")]}}
    )
    stats = _compute_section_stats(snap, {".bss": {"size": None}}, {"summary": {}})
    assert stats[".bss"]["pct"] == 0
    sec = {"name": ".bss", "va": None, "size": None}
    progress = _build_progress(".bss", sec, {"summary": {}}, {".bss": {}})
    assert progress["coverage_pct"] == 0


def test_every_document_section_reports_stats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every section the document carries reports stats, cells or not.

    The materialized ``section_cell_stats`` a scoped rebuild wrote could cover
    only some sections, and the map header then showed no counts at all for the
    rest.  The counts are derived from each section's own cells now, so a
    section the document holds without cells reports zeroes instead of vanishing
    (and its grid renders empty rather than 500ing — see
    ``test_cell_less_section_renders_an_empty_grid``).
    """
    snap = _write_doc(
        tmp_path,
        monkeypatch,
        "T",
        {
            ".text": {"size": 2, "cells": [cell(0, 1, "exact"), cell(1, 2, "exact")]},
            ".data": {"size": 2, "cells": [cell(0, 1, "exact"), cell(1, 2, "none")]},
            ".bss": {"size": 0},
        },
    )
    sections = {".text": {"size": 2}, ".data": {"size": 2}, ".bss": {"size": 0}}
    stats = _compute_section_stats(snap, sections, {"summary": {}})

    assert set(stats) == {".text", ".data", ".bss"}
    assert stats[".data"]["total"] == 2
    assert stats[".data"]["exact"] == 1
    assert stats[".bss"]["total"] == 0


def test_cell_less_section_renders_an_empty_grid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A section with no cells renders an empty grid, not a 500.

    This is the new spelling of the partial ``section_cell_stats`` degrade: a
    section the document holds with an empty (or absent) ``cells`` array used to
    make the readers that re-aggregated from a table drop it, and a dropped
    section painted nothing at all.
    """
    _write_doc(tmp_path, monkeypatch, "EMPTY_POTATO", {".bss": {"va": 0x2000, "size": 64}})
    html = render_potato_url("/potato?target=EMPTY_POTATO&section=.bss")
    assert '<table id="grid"' in html, "an empty section still renders its grid"
    # The map header counts the section rather than dropping it: zero blocks,
    # not an absent heading.
    assert "(0 blocks)" in html


def test_progress_bar_segments_share_one_denominator():
    """Every segment of a progress bar is a share of ONE denominator.

    The .text bar is function-denominated (its "matched" stat is a function
    count); every other section's is byte-denominated.  Padding is a cell
    state with no function counterpart, so it belongs to the byte bar alone.
    It used to be added as paddingBytes/sec_size on the .text bar as well:
    500+200+100+100 matched of 1000 functions plus a 20 KB padding run in a
    100 KB section summed to 110%, which clamped the "none" remainder to 0
    (the 100 unmatched functions were painted no grey at all) and pushed
    _progress_svg's trailing segments past the 700-unit track, which clips
    them.
    """
    text_summary = {
        "totalFunctions": 1000,
        "exactMatches": 500,
        "relocMatches": 200,
        "nearMatchCount": 100,
        "stubCount": 100,
        "paddingBytes": 20000,
        "coveredBytes": 90000,
    }
    text_sec = {"name": ".text", "va": 4096, "size": 100000}
    data = {"summary": {".text": text_summary}}
    progress = _build_progress(".text", text_sec, data, {".text": text_sec})
    segments = dict(progress["segments"])
    assert segments["exact"] == 50.0
    assert segments["reloc"] == 20.0
    assert segments["near_match"] == 10.0
    assert segments["stub"] == 10.0
    assert segments["padding"] == 0
    assert segments["none"] == 10.0
    assert sum(pct for _, pct in progress["segments"]) == 100.0

    # A byte-denominated section keeps its padding band, against the same
    # denominator as its siblings.
    data_summary = {
        "totalFunctions": 0,
        "exactBytes": 4000,
        "relocBytes": 1000,
        "nearMatchBytes": 500,
        "stubBytes": 500,
        "paddingBytes": 2000,
        "coveredBytes": 6000,
    }
    data_sec = {"name": ".data", "va": 8192, "size": 10000}
    data = {"summary": {".data": data_summary}}
    progress = _build_progress(".data", data_sec, data, {".data": data_sec})
    segments = dict(progress["segments"])
    assert segments["exact"] == 40.0
    assert segments["padding"] == 20.0
    assert segments["none"] == 20.0


def test_progress_svg_segments_stay_inside_the_track():
    """A segment list summing past 100% is drawn off the end of the 700-unit
    track and clipped away by the rounded-corner clipPath: the last band
    silently loses its right-hand end."""
    uri = _progress_svg((("exact", 60.0), ("reloc", 40.0), ("padding", 20.0), ("none", 0.0)))
    svg = base64.b64decode(uri.partition("base64,")[2]).decode("utf-8")
    rects = [
        (float(x), float(w))
        for x, w in re.findall(r'<rect x="([\d.]+)" y="0" width="([\d.]+)"', svg)
    ]
    assert rects
    assert max(x + w for x, w in rects) <= TRACK_UNITS


def test_null_va_section_renders_grid_and_panel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A .bss-style section (no va/fileOffset) must render instead of
    TypeError-500ing on hex(None + start).

    TOML has no null, so a section the catalog left unbacked is written with
    empty ``va``/``fileOffset`` and reads back as None — the normal shape for
    file-unbacked sections, as api.py's /asm and /bytes endpoints document.  The
    Potato grid and panel do the same sec_va + cell.start arithmetic and crashed
    the whole page on it.  Addresses fall back to file-relative offsets (the
    SPA's `sec.va || 0`).
    """
    _write_doc(
        tmp_path,
        monkeypatch,
        "NULLVA_POTATO",
        {
            ".bss": {
                "va": None,
                "size": 64,
                "fileOffset": None,
                "unitBytes": 16,
                "columns": 8,
                "cells": [cell(0, 16, "data"), cell(16, 32, "none")],
            }
        },
    )

    html = render_potato_url("/potato?target=NULLVA_POTATO&section=.bss")
    assert '<table id="grid"' in html, "grid rendered for a NULL-va section"
    # Cell titles show file-relative offsets: hex() of 0..16.
    assert "0x0..0x10 | data" in html

    panel = render_potato_url("/potato?target=NULLVA_POTATO&section=.bss&idx=0")
    assert "Block 0" in panel
    assert "0x0 .. 0x10" in panel


def test_null_columns_section_renders_grid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An absent sections.columns value must fall back to the 64-column default,
    not TypeError on ``None <= 0`` — which escapes handle_potato's except tuple
    as a raw HTML 500.

    The document's optional columns field reads back as 0, so the guard is
    driven directly with the None spelling a caller-supplied section dict still
    carries.  Same crash family as test_null_va_section_renders_grid_and_panel.
    """
    from recoverage.potato import _render_grid_view

    snap = _write_doc(
        tmp_path,
        monkeypatch,
        "NULLCOLS_POTATO",
        {
            ".text": {
                "va": 4096,
                "size": 64,
                "fileOffset": 512,
                "unitBytes": 16,
                "cells": [cell(0, 16, "exact"), cell(16, 32, "none")],
            }
        },
    )
    sections, data = _load_section_data(snap, snap=None)
    # columns omitted from the document (the schema-legal NULL of the SQLite era).
    sec_data = dict(sections[".text"], columns=None)
    grid_html, *_rest = _render_grid_view(
        snap,
        "NULLCOLS_POTATO",
        ".text",
        sec_data=sec_data,
        sections=sections,
        data=data,
        active_filters=set(),
        idx_str="",
        search_query="",
        search_matched_fns=set(),
        page_str="",
        snap=None,
    )
    assert '<table id="grid"' in grid_html, "grid rendered for a NULL-columns section"


def test_render_original_bytes_keeps_dump_lines_intact() -> None:
    """The Original Bytes dump must not be re-wrapped: every 16-byte row is a
    fixed-width line whose offset column and |ascii| column stay on one
    physical line, or _highlight_hex's shape detection silently degrades to
    plain escaping and the ASCII column lands on its own ragged line."""
    raw = bytes(range(64))
    html = _render_original_bytes(raw, 0x200)
    body = html.split("<pre>", 1)[1].split("</pre>", 1)[0]
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assert len(lines) == 4, f"one output line per 16-byte row, got {len(lines)}: {lines!r}"
    for i, line in enumerate(lines):
        offset = f"{0x200 + i * 16:08x}"
        # The offset column is read by name, not by the hex it happens to
        # hold: what this test pins is that the column is colored at all, and
        # the gray it is was retinted with the rest of the code pane.
        assert line.startswith(f'<font color="{MUTED_COLOR}">{offset}</font>'), (
            f"line {i} keeps its coloured offset column: {line!r}"
        )
        assert line.endswith("|</font>"), f"line {i} keeps its ASCII column: {line!r}"


def test_build_url():
    assert _build_url("SERVER", ".text") == "?target=SERVER&section=.text"
    assert "filter=exact%2Creloc" in _build_url("SERVER", ".text", {"reloc", "exact"})
    assert "idx=42" in _build_url("SERVER", ".text", idx=42)
    assert "search=alloc" in _build_url("SERVER", ".text", search="alloc")
    url = _build_url("SERVER", ".text", {"exact"}, idx=5, search="foo")
    assert "target=SERVER" in url
    assert "section=.text" in url
    assert "filter=exact" in url
    assert "idx=5" in url
    assert "search=foo" in url


def test_esc():
    assert _esc("<script>") == "&lt;script&gt;"
    assert _esc("a&b") == "a&amp;b"
    assert _esc('"hello"') == "&quot;hello&quot;"
    assert _esc("hello world") == "hello world"
    assert _esc(12345) == "12345"


def test_wrap_text():
    assert _wrap_text("hello", 10) == "hello"
    # The wrap width is the contract; `"\n" in ...` is satisfied by a single
    # stray break in a 100-character run.
    assert _wrap_text("a" * 100, 45) == "\n".join(["a" * 45, "a" * 45, "a" * 10])
    assert _wrap_text("line1\nline2", 45) == "line1\nline2"


def test_wrap_text_never_opens_a_line_on_a_combining_mark():
    """A wrap never lands between a character and a combining mark that follows it.

    The NFD spelling of a value (an "e" followed by COMBINING ACUTE ACCENT, what
    a macOS-side tool writes into a coverage document) is one code point longer
    than the precomposed one, so a 40-code-point wrap landed between the letter
    and its mark and the accent moved onto the first character of the next line.
    Spelled with escapes throughout: the literals are invisible in a diff.
    """
    combining_acute = "́"
    wrapped = _wrap_text("x" * 39 + "e" + combining_acute + "tail", 40)
    assert not any(line.startswith(combining_acute) for line in wrapped.split("\n"))
    # The precomposed spelling is the same text in one code point, so it wraps
    # on width and is not rejoined.
    assert _wrap_text("x" * 39 + "\u00e9tail", 40) == "\n".join(["x" * 39 + "\u00e9", "tail"])


def test_format_hex_dump():
    dump = _format_hex_dump(b"\x48\x65\x6c\x6c\x6f\x00\xff\x01", base_offset=0x1000)
    assert "00001000" in dump
    assert "48 65 6c 6c" in dump
    assert "Hello" in dump
    assert "." in dump
    assert "\n" in _format_hex_dump(bytes(range(32)), 0)
    assert "more bytes" in _format_hex_dump(bytes(300), 0, max_bytes=256)
    assert "more bytes" not in _format_hex_dump(bytes(16), 0, max_bytes=256)
    assert _format_hex_dump(b"", 0) == ""


def test_extract_annotations():
    code = """// FUNCTION: SERVER 0x10003da0
// STATUS: MATCHING
// NOTE: register alloc differs
// BLOCKER: loop unrolling
// SOURCE: deflate.c:fill_window
int foo(void) { return 0; }
"""
    annotations = _extract_annotations(code)
    assert ("NOTE", "register alloc differs") in annotations
    assert ("BLOCKER", "loop unrolling") in annotations
    assert ("SOURCE", "deflate.c:fill_window") in annotations
    assert len(annotations) == 3
    assert _extract_annotations("") == []
    assert _extract_annotations("int main() { return 0; }") == []


def test_cell_file_offset():
    assert _cell_file_offset({"start": 100}, {"fileOffset": 4096}) == 4196
    # 0 is a file offset, not "no file backing" (api.py serves those bytes);
    # only a NULL fileOffset means the section is not file-backed.
    assert _cell_file_offset({"start": 100}, {"fileOffset": 0}) == 100
    assert _cell_file_offset({"start": 100}, {"fileOffset": None}) is None
    assert _cell_file_offset({"start": 100}, None) is None
    assert _cell_file_offset({}, {"fileOffset": 4096}) == 4096


def test_format_data_inspector():
    import struct

    test_bytes = struct.pack(
        "<bBhHiIfd", -42, 200, -1000, 60000, -100000, 3000000000, 3.14, 2.71828
    )
    inspector = _format_data_inspector(test_bytes)
    assert "int8" in inspector and "-42" in inspector
    assert "uint8" in inspector and "214" in inspector
    assert "int16" in inspector
    assert "int32" in inspector
    assert "float32" in inspector
    assert "float64" in inspector
    assert "<table" in inspector and "</table>" in inspector
    assert _format_data_inspector(b"") == ""
    assert _format_data_inspector(None) == ""

    ascii_inspector = _format_data_inspector(b"Hello\x00World")
    assert "string (ascii)" in ascii_inspector and "Hello" in ascii_inspector


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_grid_structure():
    """Every section's grid sizes its spacer row to the section column count
    and every merged row's colspans sum back to exactly that count."""
    snap = _shared_snapshot()
    target = snap.target
    section_names = list(snap.sections)
    # A targetless query used to make this loop vacuous: the test passed
    # without executing a single assertion (hardcoded target name).
    assert section_names, f"target {target!r} has no sections to check"

    for sec in section_names:
        html = render_potato_url(f"/potato?target={target}&section={sec}")
        m = re.search(r'(<table id="grid"[^>]*>.*?</table>)', html, re.DOTALL)
        assert m, f"grid {sec}: table found"

        table = m.group(1)
        table_rows = [str(r) for r in re.split(r"</tr>\s*<tr[^>]*>", table)]
        first_row_tds = re.findall(r"<td\b", table_rows[0]) or []

        # The document's own columns field, defaulting to the 64 the renderer
        # falls back to for a section that states none, capped at the widest
        # lattice the page draws.
        grid_columns = min(int(snap.sections[sec].columns) or 64, _MAX_RENDERED_COLUMNS)

        assert len(first_row_tds) >= grid_columns, f"grid {sec}: sizing row"

        for ri in range(1, len(table_rows)):
            row = table_rows[ri]
            spans = re.findall(r'colspan="(\d+)"', row) or []
            if spans:
                total = sum(int(s) for s in spans)
                assert total == grid_columns, (
                    f"grid {sec}: row {ri} sums to {total} not {grid_columns}"
                )


# List of URLs to test, with what each render must actually say. A
# well-formed document is the floor, not the claim: the case NAME is a claim
# about behaviour ("search no results", "XSS in search"), and without the
# markers below a renderer that dropped the filter, ignored ?search= or
# echoed the payload unescaped satisfied all of them.
URLS = [
    ("/potato", "default", (), ()),
    ("/potato?section=.text", "section .text", (), ()),
    ("/potato?section=.data", "section .data", (), ()),
    ("/potato?section=.rdata", "section .rdata", (), ()),
    ("/potato?section=.bss", "section .bss", (), ()),
    ("/potato?filter=exact", "filter exact", (), ()),
    ("/potato?filter=reloc,near_match", "filter reloc+near_match", (), ()),
    ("/potato?section=.text&filter=exact", "text + exact", (), ()),
    ("/potato?section=.text&idx=0", "cell 0", (), ()),
    ("/potato?section=.text&idx=100", "cell 100", (), ()),
    ("/potato?section=.data&idx=0", "cell on .data", (), ()),
    ("/potato?section=.bss&idx=0", "cell on .bss", (), ()),
    # The synthetic DB matches no function name against "alloc", but the
    # banner is the contract: a term that finds nothing says so, and says
    # how to fix the spelling.
    (
        "/potato?search=alloc",
        "search alloc",
        ("0 matches for &quot;alloc&quot;", "Check the spelling"),
        (),
    ),
    ("/potato?search=0x1000", "search VA prefix", (" for &quot;",), ()),
    ("/potato?search=g_ServerConfig", "global search", (" for &quot;",), ()),
    (
        "/potato?search=nonexistent_xyz",
        "search no results",
        ("0 matches for", "Check the spelling"),
        (),
    ),
    (
        "/potato?target=SERVER&section=.text&filter=exact,reloc&idx=0&search=alloc",
        "all params combined",
        # SERVER is not in the DB, so the target check answers before the
        # search, section and cell parameters are ever read. A render that
        # drew a grid here would be inventing data for a target that has none.
        ("no data for SERVER",),
        ('id="grid"',),
    ),
    ("/potato?section=.text&idx=-1", "invalid cell (negative)", (), ()),
    ("/potato?section=.text&idx=999999", "invalid cell (too large)", (), ()),
    ("/potato?section=nonexistent", "nonexistent section", (), ()),
    # An unknown target has no grid to draw, and the page title says which
    # target it found nothing for.
    ("/potato?target=NONEXISTENT", "nonexistent target", ("no data for NONEXISTENT",), ()),
    (
        "/potato?search=<script>alert(1)</script>",
        "XSS in search",
        (" for &quot;", "&lt;script&gt;alert(1)&lt;/script&gt;"),
        ("<script>alert(1)</script>",),
    ),
    (
        "/potato?search=%22%3E%3Cimg%20onerror%3Dalert(1)%3E",
        "XSS URL-encoded",
        ("&quot;&gt;&lt;img onerror=alert(1)&gt;"),
        ('"><img onerror=',),
    ),
    ("/potato?view=functions", "view functions", (), ()),
]


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
@pytest.mark.parametrize("url,name,must_contain,must_not_contain", URLS)
def test_rendering_paths(url, name, must_contain, must_not_contain):
    html = render_potato_url(url)
    assert html, "render returned empty"
    assert "<html" in html and "<body" in html, "missing HTML structure"
    ok, err = _test_tidy(html)
    if ok is False:
        pytest.fail(f"Tidy error on {name}: {err[:150]}")
    assert "style=" not in html
    assert "<script" not in html.lower()
    assert "onclick=" not in html.lower()
    for marker in must_contain:
        assert marker in html, f"{name}: render is missing {marker!r}"
    for marker in must_not_contain:
        assert marker not in html, f"{name}: render leaked unescaped {marker!r}"


def _find_cell_idx(target: str, section: str, predicate) -> int | None:
    """Position of the first cell in *section* whose functions satisfy *predicate*.

    ?idx= addresses a cell by its POSITION within the section's cell list
    (_render_panel indexes cells[idx]; grid links carry that position), not by a
    stored id — the document has no id column at all.
    """
    found = load_coverage(Path.cwd(), target).sections.get(section)
    if found is None:
        return None
    for pos, cell_row in enumerate(found.cells):
        if predicate(list(cell_row.functions)):
            return pos
    return None


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_globals_detail_panel():
    snap = _shared_snapshot()
    target = snap.target
    globals_set = {gl.name for gl in snap.globals}

    match: tuple[int, str] | None = None
    for sec in (".data", ".rdata"):
        section = snap.sections.get(sec)
        if section is None:
            continue
        # Same position-not-id contract as _find_cell_idx above.
        for pos, cell_row in enumerate(section.cells):
            if match is None and any(fn in globals_set for fn in cell_row.functions):
                match = (pos, sec)
    if not match:
        pytest.skip("No global-mapped .data/.rdata cell in DB")
    idx, sec = match
    html = render_potato_url(f"/potato?target={target}&section={sec}&idx={idx}")
    assert "Global Variable" in html


@pytest.mark.parametrize(
    ("kind", "owners", "backing", "expected_owner", "expected_type"),
    [
        ("object", ("LIBCMT:crt0dat.obj",), "", "LIBCMT:crt0dat.obj", "Global variable"),
        (
            "import",
            ("linker:KERNEL32.dll!Sleep",),
            "",
            "linker:KERNEL32.dll!Sleep",
            "Import pointer",
        ),
        ("span", (), "", "Layout span", "Layout span"),
        ("alias", (), "g_storage", "View of g_storage", "Storage view"),
    ],
)
def test_global_panel_distinguishes_owners_users_and_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    owners: tuple[str, ...],
    backing: str,
    expected_owner: str,
    expected_type: str,
):
    import recoverage.potato as potato

    _write_doc(
        tmp_path,
        monkeypatch,
        "GLOBAL_ROLES",
        {".data": {"va": 0x2000, "size": 4, "cells": [cell(0, 4, "data", functions=["g_value"])]}},
        globals_=[{"va": 0x2000, "name": "g_value", "files": ["declarations.h"]}],
    )
    # Exercise a newer producer's optional fields while retaining the supported
    # older coverage reader in the consumer's CI environment.
    row = SimpleNamespace(
        va=0x2000,
        name="g_value",
        decl="int g_value",
        files=("declarations.h",),
        module="GLOBAL_ROLES",
        size=4,
        status="UNKNOWN",
        owners=owners,
        storage_kind=kind,
        backing=backing,
        referenced_in=("consumer.c",),
        declared_in=("declarations.h",),
    )
    monkeypatch.setattr(potato, "lookup_global", lambda *_: row)
    html = render_potato_url("/potato?target=GLOBAL_ROLES&section=.data&idx=0")
    assert expected_owner in html
    assert expected_type in html
    assert "consumer.c" in html
    assert "declarations.h" in html
    assert "storage_kind" not in html
    assert "Unknown" not in html


def test_multi_function_cell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A cell carrying two function names is not an empty cell.

    The panel's unknown-first-name branch used to be reached for such a cell in
    a document with no functions rows; the cell lists two names, so it is never
    the "No functions in this block." case.
    """
    _write_doc(
        tmp_path,
        monkeypatch,
        "MULTIFN_POTATO",
        {
            ".text": {
                "va": 4096,
                "size": 32,
                "fileOffset": 512,
                "unitBytes": 16,
                "columns": 8,
                "cells": [cell(0, 16, "exact", functions=("_a", "_b"))],
            }
        },
    )
    html = render_potato_url("/potato?target=MULTIFN_POTATO&section=.text&idx=0")
    # A cell carrying two function names is not an empty cell, so the panel
    # must not take the "No functions in this block." branch.
    assert "No functions in this block." not in html
    # The document seeds no functions/globals rows, so the cell's primary
    # function (_a, first of the two) lands in the Unknown branch.
    assert "Unknown: _a" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_view():
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions")
    assert "Functions" in html
    assert "Origin" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_no_match_says_what_to_do():
    """An empty list must name the query that emptied it and offer a way out.

    The grid view prints the active query and a clear link; the function list
    used to print neither, so a user who searched from the grid and switched
    views saw "No functions found." with no sign the search was the cause.
    """
    target = require_target()
    html = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&search=zzz_no_such_function"
    )
    assert "No functions match" in html
    assert "zzz_no_such_function" in html
    assert "[Clear search]" in html
    # The clear link keeps the view and the status filter, and drops the query.
    assert f'href="?target={quote(target)}&section=.text&view=functions"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_every_clear_link_inside_the_function_list_keeps_the_view():
    # The function list is a view of its own, and a link that omits `view`
    # is a link back to the grid.  Both clear affordances on a status-filtered,
    # searched list therefore have to carry it: the [Clear] beside the status
    # note in the list header, and the topbar's own [Clear search].  Without
    # it, clearing a criterion drops the reader out of the list they are
    # standing in, which is what the topbar's hidden inputs were added to
    # prevent for the two forms beside them.
    target = require_target()
    html = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&status=STUB&search=_func_c"
    )
    clear_links = re.findall(r'<a href="([^"]*)"><font[^>]*>\[Clear(?: search)?\]</font></a>', html)
    assert clear_links, html[:400]
    assert all("view=functions" in href for href in clear_links), clear_links
    # ... and the status criterion is only dropped by the [Clear] beside it,
    # not by the topbar's [Clear search], which clears the query alone.
    status_cleared = [href for href in clear_links if "status=STUB" not in href]
    query_cleared = [href for href in clear_links if "search=" not in href]
    assert status_cleared and query_cleared, clear_links


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_the_topbar_chrome_keeps_the_reader_inside_the_function_list():
    # The clear affordances are not the only links a reader follows from
    # inside the list: the section tabs and the filter pills sit in the same
    # topbar, and each one was built without `view`, so a section switch or a
    # filter toggle silently dropped the reader into the grid.  Rendered
    # through the two builders the page takes its URLs from, so this fails on
    # the wiring rather than on a regex over markup.
    sections = {".text": {}, ".data": {}, ".rdata": {}, ".bss": {}}
    tabs = _section_tab_data("T", ".text", sections, None, "_func_a", set(), "STUB", "functions")
    assert all("view=functions" in url for _name, url, _on, _key in tabs), tabs
    assert all("status=STUB" in url for _name, url, _on, _key in tabs), tabs

    pills = _build_filter_data("T", ".text", {"exact"}, "_func_a", set(), "functions")
    assert all("view=functions" in row[0] for row in pills), pills


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_a_function_row_link_keeps_the_status_it_was_listed_under():
    # A row link is the one link that does leave the list: it opens the
    # function's panel in the grid, which is the point.  It still has to
    # carry the status criterion, or opening a function and stepping back
    # finds the whole list instead of the filtered one the reader chose.
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions&status=STUB")
    row_links = [
        href
        for href in re.findall(r'<a href="([^"]*)"><font color="[^"]*">_func_', html)
        if "status=" not in href
    ]
    assert not row_links, row_links


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_no_match_status_filter_offers_a_way_back():
    target = require_target()
    html = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&status=NO_SUCH_STATUS"
    )
    assert "No functions with status" in html
    assert "[Clear filter]" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_search_status_line_explains_an_empty_result():
    """The SPA's search line spells out what to try; Potato's must match.

    Rendered, not read off _PAGE_SRC: the literal is behind the
    `search_match_count == 0` branch, so a template check alone stays green
    when the count never reaches it (the hint on every search, or on none).
    """
    target = require_target()
    if not target:
        pytest.fail("no coverage target resolved: the synthetic document is missing or unreadable")
    hint = "Check the spelling, or search by address."
    empty = render_potato_url(f"/potato?target={target}&search=zzz_no_such_function")
    assert hint in empty
    assert "0 matches for &quot;zzz_no_such_function&quot;." in empty
    hit = render_potato_url(f"/potato?target={target}&search=_func_a")
    assert hint not in hit


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_search_status_counts_the_rows_the_function_list_prints():
    """The status line sits above both views, so the list has to fill it in.

    Only the grid view built the match set, so a search in the function list
    read "0 matches" and "Check the spelling" directly over a table
    full of the rows it had just matched.
    """
    target = require_target()
    if not target:
        pytest.fail("no coverage target resolved: the synthetic document is missing or unreadable")
    html = render_potato_url(f"/potato?target={target}&view=functions&search=_func_a")
    assert "Check the spelling" not in html
    assert re.search(r"\b[1-9]\d* match(es)? for &quot;_func_a&quot;", html)


def test_parent_url_selects_the_parents_own_block():
    """Parent navigates to the parent, not to a search for it.

    A hand-written href put the raw function name into the query string, so a
    mangled name carrying & or ? truncated or split the URL.
    """
    from recoverage.potato import _PANEL_SRC, _parent_url

    cells = [
        {"start": 0, "end": 16, "functions": ["_other"]},
        {"start": 16, "end": 32, "functions": ["parent_fn"]},
    ]
    url = _parent_url("parent_fn", cells, "tgt", ".text", {"exact"}, "")
    assert url == "?target=tgt&section=.text&filter=exact&idx=1#sel"

    # A parent with no cell here still has to lead somewhere: search for it,
    # quoted, so the URL survives a name with & in it.
    fallback = _parent_url("a&b", cells, "tgt", ".data", None, "")
    assert fallback == "?target=tgt&section=.data&search=a%26b"
    assert _parent_url("", cells, "tgt", ".text", None, "") == ""

    # The template renders the built URL; it does not hand-write one.
    assert 'href="{{parent_url}}"' in _PANEL_SRC
    assert "search={{parent_function}}" not in _PANEL_SRC

    # And the panel really publishes it. Without this, dropping the
    # parent_url assignment in _render_panel renders href="" and both
    # assertions above still pass, because they read the template constant.
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&idx=5")
    assert 'href="?target=FAKEDLL&amp;section=.text&amp;idx=0#sel"' in html
    assert "Parent:" in html


def test_parent_url_index_matches_the_linear_walk():
    """The memoized name->cell index answers exactly what the walk answered.

    The walk walked every cell in the section on each panel render; the index
    is derived from the same cells under the grid's own memo key.  First
    occurrence, no-parent, and the absent-parent fallback must all agree.
    """
    from recoverage.potato import _parent_index, _parent_url

    cells = [
        {"start": 0, "end": 16, "functions": None},
        {"start": 16, "end": 32, "functions": ["dup"]},
        {"start": 32, "end": 48, "functions": []},
        {"start": 48, "end": 64, "functions": ["dup", "parent_fn"]},
    ]
    key = ("fp", "T", ".text", 64)
    index = _parent_index(key, cells)  # type: ignore[arg-type]
    for name in ("parent_fn", "dup", "absent", ""):
        assert _parent_url(name, cells, "t", ".text", None, "", index) == _parent_url(
            name, cells, "t", ".text", None, ""
        ), name
    # First occurrence wins, exactly as the walk's first match did.
    assert index["dup"] == 1

    import recoverage.potato as potato

    # A second call reuses the memo rather than re-walking, and a rebuild
    # drops it with the rest of the grid-derived state.
    assert _parent_index(key, cells) is index  # type: ignore[arg-type]
    potato.clear_cells_cache()
    assert not potato._PARENT_INDEX


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_sort():
    """?sort= orders the function rows.

    `html_name != html_size` is satisfied by any per-request difference, so
    the row order itself is read. The synthetic .text seeds _func_a (48),
    _func_c (32) and _func_b (16): by name reads a, b, c; by size reads
    b, c, a, so a renderer that ignored ?sort= could not satisfy both.
    """
    target = require_target()

    def _first_index(html: str, name: str) -> int:
        return html.index(name)

    by_name = render_potato_url(f"/potato?target={target}&section=.text&view=functions&sort=name")
    by_size = render_potato_url(f"/potato?target={target}&section=.text&view=functions&sort=size")
    order_name = sorted(("_func_a", "_func_b", "_func_c"), key=lambda n: _first_index(by_name, n))
    order_size = sorted(("_func_a", "_func_b", "_func_c"), key=lambda n: _first_index(by_size, n))
    assert order_name == ["_func_a", "_func_b", "_func_c"]
    assert order_size == ["_func_b", "_func_c", "_func_a"]


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_status_filter():
    # The synthetic DB seeds _func_a EXACT, _func_b RELOC, _func_c STUB.  An
    # ignored ?status= would still list all three, so the filtered-out names
    # have to be absent for the filter to be proven.
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions&status=STUB")
    assert "_func_c" in html
    assert "_func_a" not in html
    assert "_func_b" not in html
    assert "No functions found." not in html
    assert "(1 results)" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_the_status_filter_is_named_and_survives_navigation():
    # `?status=` has no control that sets it, so a reader who arrives with one
    # (a link, a shared URL) needs the page to say the list is narrowed and to
    # carry the criterion across the section tabs, the [Grid View] link and the
    # topbar forms.  Dropping it silently changes the rows under the reader.
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions&status=STUB")
    assert "Status:" in html
    assert "[Clear]" in html
    # Section tabs, the grid link and the [Functions] link all keep it.
    assert html.count("status=STUB") >= 4
    unfiltered = render_potato_url(f"/potato?target={target}&section=.text&view=functions")
    assert "Status:" not in unfiltered


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_the_active_filters_survive_navigation_into_and_out_of_the_list():
    # The filter pills are drawn on the function list as well as the grid (they
    # keep `view=functions`), so a reader who narrows the map and opens the list
    # sees controls that read as set. Every link in that view has to carry them
    # the way it already carries `?status=`, or the way back to the grid lands on
    # an unfiltered map with the pills still painted as on.
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&filter=exact,reloc")
    functions_link = re.search(r'href="(\?[^"]*view=functions)"', html)
    assert functions_link is not None, html[:400]
    assert "filter=exact%2Creloc" in functions_link.group(1)

    listed = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&filter=exact,reloc"
    )
    # The [Grid View] link, a row's function link, a sort header and a section tab
    # are the ways out of the list that have to keep them. The "All" pill is the
    # one link that must not: it is the reader turning them off, and it is the
    # only href on the page carrying neither a filter nor a search.
    hrefs = _hrefs(listed)
    clearing = [href for href in hrefs if "filter=" not in href and "search=" not in href]
    assert len(clearing) == 1, clearing
    for href in hrefs:
        # A toggle pill carries the other six-set, the rest carry the pair
        # itself; what no link may do is drop the criterion and land on an
        # unfiltered grid.
        if href not in clearing:
            assert "filter=" in href, href


def _hrefs(html: str) -> list[str]:
    return re.findall(r'href="(\?[^"]*)"', html)


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_reports_the_row_cap(monkeypatch):
    # The list is capped so a large target's page stays a sane size. A header
    # reading the capped length as the total tells the reader the page is the
    # whole result set, and the rows they cannot see are unreachable.
    import recoverage.potato as potato_module

    monkeypatch.setattr(potato_module, "_SEARCH_ROW_LIMIT", 1)
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions")
    found = re.search(r"\(first 1 of (\d+) results\)", html)
    assert found is not None, html[:400]
    assert int(found.group(1)) > 1
    assert "capped at 1 rows" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_prev_next_navigation():
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&idx=5")
    assert "#sel" in html
    assert "Prev" in html
    assert "Next" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_skip_link():
    target = require_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'href="#grid-container"' in html
    # Inside the topbar frame, not above it: the link outside the page wrapper
    # was painted over the viewport's top edge with the header starting below
    # it. Potato Mode ships no stylesheet, so it cannot be hidden until focus
    # the way the SPA hides its own; in flow inside the header it is the
    # document's first focusable control and the header's own first row.
    assert (
        html.index('id="topbar"')
        < html.index('href="#grid-container"')
        < html.index('id="controls"')
    )


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_accesskey_attributes():
    target = require_target()
    html = render_potato_url(f"/potato?target={target}")
    # Search input accesskey + per-section tabs (accesskey = 2nd char of the
    # section name: .text -> "t", .data -> "d").
    assert 'accesskey="s"' in html
    assert 'accesskey="t"' in html  # .text tab
    assert 'accesskey="d"' in html  # .data tab


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_the_search_box_asks_for_what_the_dashboard_asks_for():
    """Both surfaces take a function name or an address, and say so alike."""
    app = (Path(__file__).resolve().parents[1] / "web" / "app" / "App.tsx").read_text(
        encoding="utf-8"
    )
    spa = re.search(r'placeholder="([^"]+)"', app)
    assert spa is not None
    html = render_potato_url(f"/potato?target={require_target()}")
    assert f'placeholder="{spa.group(1)}"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_no_two_controls_claim_one_accesskey():
    # The Stub pill's own letter is "S" and the search box's is "s": both were
    # written before, and a browser resolves a duplicated accesskey to the
    # first control in document order, so one of them answered to a key that
    # was on screen as belonging to the other (WCAG 2.1.4).
    target = require_target()
    html = render_potato_url(f"/potato?target={target}")
    letters = re.findall(r'accesskey="([^"]*)"', html)
    assert letters
    assert len(letters) == len(set(letters))


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_every_accesskey_is_listed_in_the_footer():
    # An accesskey nobody can find is a shortcut only the author knows, so the
    # footer names every letter the page handed out, and only those.
    target = require_target()
    html = render_potato_url(f"/potato?target={target}")
    legend = re.search(r"Key: ([^<]*)", html)
    assert legend is not None
    listed = {part.split()[0] for part in legend.group(1).split(" · ")}
    assert listed == {
        f"Alt+{letter.upper()}" for letter in re.findall(r'accesskey="([^"]*)"', html)
    }


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_functions_nav_link_is_url_quoted():
    # The header [Functions] href is percent-encoded, so a target or section
    # holding "&" cannot append query parameters to it.  Every other href on
    # the page is built by _build_url, which does the same.
    target = require_target()
    html = render_potato_url(f"/potato?target={target}&section=.text")
    assert f'href="?target={target}&amp;section=.text&amp;view=functions"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_clickable_asm_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    from recoverage import potato as _potato

    target = require_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 0)
    if idx is None:
        pytest.skip("No .text function cell found")
    # Production renders the ASM block only when disassembly is available, so
    # a plain HAS_DB gate fails on installs without the optional capstone
    # extra.  Faking
    # the probe (as tests/test_api.py does for the /asm endpoint) keeps the
    # assertion running on every install shape.
    monkeypatch.setattr(_potato, "disassembly_available", lambda: True)
    monkeypatch.setattr(
        _potato, "get_disassembly", lambda *a, **k: "0x10001000  mov eax, 0x10001010"
    )
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}")
    assert "Assembly" in html
    # The section-less shape: the function-detail row also links to
    # `?target=T&section=.text&search=0x...`, which a `.*` regex would have
    # matched, so the assertion held even with the ASM address unlinked.
    assert f'href="?target={target}&search=0x10001000"' in html
    assert f'href="?target={target}&search=0x10001010"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_back_to_main_link():
    target = require_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'href="/"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_footer_db_date():
    target = require_target()
    html = render_potato_url(f"/potato?target={target}")
    assert "DB updated" in html
    assert "recoverage" in html


class TestDbUpdatedLabel:
    """DB-updated footer stamp: wall-clock rendering of the newest document mtime.

    The render reads the instant once and hands it to both renderings, so what
    these test is the two formats over a value the page supplies; which value
    that is is ``_newest_mtime_ns``'s answer, pinned here too.
    """

    @staticmethod
    def _patch_db(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
        """Point the coverage-directory resolution at a fixture's documents."""
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

    @staticmethod
    def _doc(directory: Path, target: str, mtime_ns: int) -> Path:
        """One document, stamped with *mtime_ns* so the assertion is exact."""
        path = write_coverage(
            directory, target, {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}}
        )
        os.utime(path, ns=(mtime_ns, mtime_ns))
        return path

    @staticmethod
    def _patch_db(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
        """Point the coverage-directory resolution at *directory*.

        The footer's read goes through the same `RECOVERAGE_DB` the rest of the
        suite redirects, so a test counting that read has to redirect it too or
        it counts a walk of the checkout's own db directory.
        """
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

    def test_missing_db_renders_empty(self) -> None:
        assert _db_updated_label(None) == ""

    def test_a_same_bytes_rebuild_does_not_revalidate_the_old_stamp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The change token keys on content, so a rebuild that wrote the same
        bytes keeps it.  The footer renders the file time, and a 304 against
        the token alone would keep showing the previous build's stamp."""
        directory = coverage_dir(tmp_path)
        self._patch_db(monkeypatch, directory)
        first_ns = 1_700_000_000 * 10**9
        path = self._doc(directory, "GAME", first_ns)
        status, headers, _ = wsgi_get("/potato?target=GAME")
        assert status.startswith("200")
        etag = {k.lower(): v for k, v in headers.items()}["etag"]

        later_ns = first_ns + 3600 * 10**9
        os.utime(path, ns=(later_ns, later_ns))
        status, _, body = wsgi_get("/potato?target=GAME", headers={"If-None-Match": etag})

        assert status.startswith("200")
        assert _db_updated_label(later_ns).encode() in body

    def test_the_instant_is_the_newest_document_mtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebuild rewrites one target's document, so the stamp must be the
        newest of them: reading any single one shows a stale instant while the
        served data for the rewritten target already changed."""
        from recoverage.server import _newest_mtime_ns

        old_ns = 1_700_000_000_000_000_000
        new_ns = old_ns + 90 * 1_000_000_000
        directory = tmp_path / "db"
        self._doc(directory, "STALE", old_ns)
        self._doc(directory, "FRESH", new_ns)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        assert _newest_mtime_ns() == new_ns

    def test_label_renders_the_instant_it_is_given(self) -> None:
        assert _db_updated_label(1_700_000_000_000_000_000) == "2023-11-14 22:13 UTC"

    def test_label_with_an_unrepresentable_mtime_renders_the_extreme(self) -> None:
        """A footer stamp past year 9999 is a stamp, not a failed render.

        The mtime is filesystem input, so a restored tree or a bad RTC can
        carry one `datetime` cannot represent.  The label is read on the page
        every render, so raising there took Potato Mode down over a stamp the
        clock cannot name.
        """
        assert _db_updated_label(253_402_300_800 * 1_000_000_000) == "9999-12-31 23:59 UTC"

    def test_label_truncates_rather_than_rounds_the_minute(self) -> None:
        """A rebuild in the last microsecond of a minute is stamped with the
        minute it landed in, not the one it has not reached.  A float-second
        conversion rounds 12:34:59.999999999 up to 12:35, and a footer that
        reads ahead of the data it describes is worse than one that lags by a
        fraction of a second."""
        # 2023-11-14T22:13:59.999999999Z: rounds up through a float second.
        assert _db_updated_label(1_700_000_039_999_999_999) == "2023-11-14 22:13 UTC"

    def test_the_footers_time_element_carries_the_same_instant(self) -> None:
        """The label is a fixed pattern on a page whose locale the server never
        learns, so the footer's ``<time>`` publishes the same instant in a form
        a reader's own tooling can re-render, truncated the same way."""
        ns = 1_700_000_039_999_999_999
        iso = _db_updated_iso(ns)
        assert iso == "2023-11-14T22:13:00+00:00"
        assert datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC") == _db_updated_label(ns)

    def test_no_db_leaves_the_time_element_out(self) -> None:
        assert _db_updated_iso(None) == ""

    def test_the_page_reads_the_coverage_directory_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The label and the ``datetime`` attribute are one instant.

        Each renderer used to call ``_newest_mtime_ns`` itself, and that is a
        fresh walk of the coverage directory: a rebuild landing between the
        two walks filed the text a reader sees and the value their tooling
        reads under different builds.
        """
        import recoverage.potato as potato_mod

        calls: list[None] = []
        monkeypatch.setattr(
            potato_mod,
            "_newest_mtime_ns",
            lambda: (calls.append(None), 1_700_000_000_000_000_000)[1],
        )
        html = potato_mod.render_potato(urlparse("/potato"))
        assert len(calls) == 1
        assert "2023-11-14 22:13 UTC" in html
        assert 'datetime="2023-11-14T22:13:00+00:00"' in html

    def test_the_footer_renders_from_one_directory_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both footer renderings come out of ONE walk of the coverage directory.

        The label and the ISO value are the same instant, and the read behind
        them is a glob plus a stat per document.  Rendering them independently
        made every Potato page walk the directory twice for one footer; this
        counts the walks, so the second one cannot come back unnoticed.
        """
        from recoverage import potato as _potato

        directory = tmp_path / "db"
        self._doc(directory, "ONCE", 1_700_000_000_000_000_000)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

        scans = 0
        real = _potato._newest_mtime_ns

        def counting() -> int | None:
            nonlocal scans
            scans += 1
            return real()

        monkeypatch.setattr(_potato, "_newest_mtime_ns", counting)

        label, iso = _potato._db_updated_stamp()
        assert scans == 1
        assert datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC") == label

    def test_a_rendered_page_scans_the_coverage_directory_once_for_the_footer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A whole Potato page must not pay a second scan for the same footer.

        The pair is what the footer renders, so the page is driven through the
        real render rather than the pair alone: the header, the grid and the
        panel all run, and only the footer read is counted.
        """
        from recoverage import potato as _potato

        scans = 0
        real = _potato._newest_mtime_ns

        def counting() -> int | None:
            nonlocal scans
            scans += 1
            return real()

        monkeypatch.setattr(_potato, "_newest_mtime_ns", counting)
        directory = tmp_path / "db"
        self._doc(directory, "PAGE", 1_700_000_000_000_000_000)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        page = render_potato_url("/potato?target=PAGE")
        assert "DB updated" in page
        assert scans == 1


class TestDocumentNamesCarryTheirOwnDirection:
    """A name out of a coverage document is laid out the way it was written.

    Every symbol, module, section and label on this page comes from a PE image,
    so a target whose names are Arabic or Hebrew is a document the reader can
    have.  The page's own direction is left-to-right, and the bidirectional
    algorithm reorders such a value against the numbers and punctuation around
    it: a name reads in an order its author never wrote, and a trailing digit
    run lands on the other side of the cell.  ``dir="auto"`` on the cell reads
    the value's own first strong character, and leaves an ASCII value laid out
    exactly as it was.
    """

    def test_the_detail_rows_take_their_own_direction(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_doc(
            tmp_path,
            monkeypatch,
            "RTL_POTATO",
            {".text": {"size": 32, "cells": [cell(0, 32, "exact", functions=("_مرحبا",))]}},
            functions=[
                {
                    "va": 256,
                    "name": "_مرحبا",
                    "vaStart": "0x100",
                    "size": 32,
                    "fileOffset": 16,
                    "status": "EXACT",
                    "module": "النواة",
                }
            ],
        )
        panel = render_potato_url("/potato?target=RTL_POTATO&section=.text&idx=0")
        assert f'<td bgcolor="{PANEL_COLOR}" dir="auto">' in panel
        assert "النواة" in panel

    def test_the_function_list_name_cell_takes_its_own_direction(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_doc(
            tmp_path,
            monkeypatch,
            "RTLLIST_POTATO",
            {".text": {"size": 32, "cells": [cell(0, 32, "exact", functions=("_שלום",))]}},
            functions=[
                {
                    "va": 256,
                    "name": "_שלום",
                    "vaStart": "0x100",
                    "size": 32,
                    "fileOffset": 16,
                    "status": "EXACT",
                }
            ],
        )
        listed = render_potato_url("/potato?target=RTLLIST_POTATO&section=.text&view=functions")
        assert '<td dir="auto">' in listed
        assert "_שלום" in listed


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_detail_panel_label_value_rows():
    # The detail panel renders label/value rows as <td> pairs, not <th>:
    # potato.py's panel template has no header cells at all.
    target = require_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 0)
    if idx is None:
        pytest.skip("No function cell found")
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}")
    assert "<b>Range:</b>" in html
    assert "<b>State:</b>" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_detail_shows_verify_similarity():
    """The function data panel surfaces the `rebrew verify -o` record — byte
    delta, diff-line count, and the code-similarity score."""
    target = require_target()
    # The synthetic DB seeds a verify_results row for 0x10001000 (_func_a) with
    # similarity 0.873 — the unit-interval fraction the column stores, rendered
    # as 87.3%.  The render's per-cell `idx` is the grid position (not the
    # cells.id), so scan render indices for the one that reaches _func_a's detail
    # rows and carries the verify similarity.
    for idx in range(32):
        html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}")
        if "last_verify_similarity" in html and "87.3%" in html:
            return
    pytest.fail("no .text cell rendered the verified function's code-similarity (87.3%)")


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_label_for_search():
    target = require_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'label for="search-input"' in html
    assert 'label for="target-select"' in html


def test_function_detail_similarity_fraction_rendered_as_percent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """functions.similarity is stored as a 0-1 fraction (rebrew's own unit
    interval) and the SPA renders it scaled by 100 with a "%" (app.js).  Potato
    Mode's detail rows must show the same percentage, not the bare fraction."""
    _write_doc(
        tmp_path,
        monkeypatch,
        "SIMFRAC_POTATO",
        {
            ".text": {
                "va": 256,
                "size": 64,
                "fileOffset": 16,
                "unitBytes": 16,
                "columns": 8,
                "cells": [cell(0, 32, "exact", functions=("_func_sim",))],
            }
        },
        functions=[
            {
                "va": 256,
                "name": "_func_sim",
                "vaStart": "0x100",
                "size": 32,
                "fileOffset": 16,
                "status": "EXACT",
                "similarity": 0.8734,
            }
        ],
    )

    panel = render_potato_url("/potato?target=SIMFRAC_POTATO&section=.text&idx=0")
    assert "<b>similarity</b>" in panel
    assert "87.3%" in panel
    assert "0.8734" not in panel


def test_similarity_near_complete_does_not_render_as_100(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A similarity short of 1.0 must not read as a perfect match.

    Both similarity columns are 0-1 fractions, and the SPA renders them through
    `format.percent1`, which floors.  Potato Mode formatted them with a bare
    ``"%.1f"``, which rounds to nearest and rounds UP: 0.9999 (99.99%) printed
    as "100.0%", beside a function that is not an exact match, while the SPA
    beside it showed 99.9.  The map header already went through
    `server.pct_1dp`; these two detail rows did not.
    """
    _write_doc(
        tmp_path,
        monkeypatch,
        "SIMNEAR_POTATO",
        {
            ".text": {
                "va": 256,
                "size": 64,
                "fileOffset": 16,
                "unitBytes": 16,
                "columns": 8,
                "cells": [cell(0, 32, "exact", functions=("_func_near",))],
            }
        },
        functions=[
            {
                "va": 256,
                "name": "_func_near",
                "vaStart": "0x100",
                "size": 32,
                "fileOffset": 16,
                "status": "EXACT",
                "similarity": 0.9999,
            }
        ],
    )

    panel = render_potato_url("/potato?target=SIMNEAR_POTATO&section=.text&idx=0")
    assert "99.9%" in panel
    assert "100.0%" not in panel


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.873, "87.3%"),
        (0.9999, "99.9%"),
        (0.99999, "99.9%"),
        (1.0, "100.0%"),
        (0.0, "0.0%"),
        (float("nan"), None),
        (float("inf"), None),
        (True, None),
        ("0.5", None),
    ],
)
def test_similarity_pct_helper(value: object, expected: str | None) -> None:
    """The one rendering both similarity columns go through.

    A non-finite fraction returns None rather than reaching `math.floor` (which
    raises on NaN) or printing a literal "nan%": a coverage document is
    untrusted input, and the caller falls back to showing the stored value.
    """
    from recoverage.potato import _similarity_pct

    assert _similarity_pct(value) == expected


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_etag_caching():
    target = require_target()

    def _etag(headers: dict[str, str]) -> str | None:
        # Bottle emits the header as "Etag"; HTTP headers are case-insensitive.
        return next((v for k, v in headers.items() if k.lower() == "etag"), None)

    status, headers, _ = wsgi_get(f"/potato?target={target}&section=.text")
    assert status.startswith("200")
    etag = _etag(headers)
    assert etag

    status2, _, _ = wsgi_get(
        f"/potato?target={target}&section=.text",
        headers={"If-None-Match": etag},
    )
    assert status2.startswith("304")


# ── _format_va edge cases ──────────────────────────────────────────


class TestFormatVa:
    def test_large_int(self) -> None:
        assert _format_va(0xFFFFFFFF) == "0xffffffff"

    def test_zero(self) -> None:
        assert _format_va(0) == "0x00000000"

    def test_negative_string(self) -> None:
        """A negative VA is document data, and it renders as an address.

        `f"{-1:08x}"` is `-0000001`, so the sign landed INSIDE the field and
        the panel printed `0x-0000001` -- a string that is not a hex address
        and that resolves to nothing in a debugger. The unsigned reading of the
        same bits keeps both the value and the column width, and is what every
        other surface in the package spells it as.
        """
        assert _format_va("-1") == "0xffffffff"
        assert _format_va(-1) == "0xffffffff"
        assert _format_va(-0x1000_1000) == "0xeffff000"

    # ── _format_va fuzz ───────────────────────────────────────────

    def test_hex_prefix_passthrough(self) -> None:
        assert _format_va("0xDEADBEEF") == "0xDEADBEEF"

    def test_non_numeric_string(self) -> None:
        assert _format_va("not_a_number") == "not_a_number"

    def test_int_one(self) -> None:
        assert _format_va(1) == "0x00000001"

    def test_string_numeric(self) -> None:
        assert _format_va("4096") == "0x00001000"

    def test_empty_string(self) -> None:
        result = _format_va("")
        assert result == ""  # empty passthrough

    @pytest.mark.parametrize(
        "val,expected_prefix",
        [
            (0x10001000, "0x"),
            (255, "0x"),
            (0, "0x"),
        ],
    )
    def test_int_always_has_hex_prefix(self, val: int, expected_prefix: str) -> None:
        assert _format_va(val).startswith(expected_prefix)


# ── Build URL helper (edge cases) ────────────────────────────────


class TestBuildUrl:
    def test_basic(self) -> None:
        url = _build_url("SERVER", ".text")
        assert "target=SERVER" in url
        assert "section=.text" in url

    def test_with_special_chars(self) -> None:
        url = _build_url("SERVER", ".text", search="<script>")
        assert "<script>" not in url  # should be URL-encoded
        assert "search=" in url

    # ── URL encoding fuzz ─────────────────────────────────────────

    def test_ampersand_in_search(self) -> None:
        url = _build_url("SERVER", ".text", search="a&b")
        assert "a&b" not in url  # & must be encoded
        assert "search=" in url

    def test_spaces_in_search(self) -> None:
        url = _build_url("SERVER", ".text", search="hello world")
        assert " " not in url.split("search=")[1]  # space must be encoded

    def test_unicode_in_target(self) -> None:
        from urllib.parse import quote

        url = _build_url("ターゲット", ".text")
        assert f"target={quote('ターゲット')}" in url

    def test_target_named_by_a_byte_outside_utf8(self) -> None:
        """A target id is a FILENAME, so it can be one ``os.fsdecode`` spells
        with a surrogate.

        ``urllib.parse.quote`` encodes a ``str`` through UTF-8 and raised
        ``UnicodeEncodeError`` here, which is a ``ValueError``:
        ``handle_potato`` caught it and answered 500. One
        ``coverage-GAME\xff.toml`` - legal on ext4, and what a checkout, an
        archive or a copy off a Windows tool produces - took the whole page
        down rather than narrowing the target picker to one row.

        The escape is the byte the filesystem holds, not U+FFFD: the reader
        below resolves the link back to the id the filesystem already resolved
        it to, and a U+FFFD would resolve to no target at all.
        """
        url = _build_url("GAME\udcff", ".text")
        assert "target=GAME%FF" in url
        assert "\udcff" not in url

    def test_a_target_named_by_a_byte_outside_utf8_round_trips(self) -> None:
        """The pair that makes the link above worth building.

        ``parse_qs``'s default ``replace`` decoded ``GAME%FF`` to
        ``GAME\ufffd``, so the page resolved no target at all, and two ids that
        differed only in the byte stopped being distinguishable.
        ``surrogateescape`` is the exact inverse of the spelling the link is
        written with.
        """
        from urllib.parse import parse_qs

        target = "GAME\udcff"
        query = _build_url(target, ".text").lstrip("?")
        assert parse_qs(query, keep_blank_values=True, encoding="utf-8", errors="surrogateescape")[
            "target"
        ] == [target]
        # ...and the decode that was in place instead did not round-trip.
        assert parse_qs(query, keep_blank_values=True)["target"] != [target]

    def test_filter_sorting_deterministic(self) -> None:
        """Filters are sorted for deterministic URLs.

        Comparing two set literals spelled in a different order is not a
        check: CPython iterates either of them in the same per-process order
        whether or not `sorted()` runs, so an unsorted `_build_url` would pass
        it. The expected URL is spelled out instead, which is the only
        spelling a join in set order cannot produce.
        """
        url1 = _build_url("S", ".t", {"exact", "reloc", "stub"})
        url2 = _build_url("S", ".t", {"stub", "exact", "reloc"})
        assert url1 == url2
        assert url1 == "?target=S&section=.t&filter=exact%2Creloc%2Cstub", url1

    def test_idx_zero(self) -> None:
        url = _build_url("S", ".t", idx=0)
        assert "idx=0" in url

    def test_no_optional_params(self) -> None:
        url = _build_url("S", ".t")
        assert "filter=" not in url
        assert "idx=" not in url
        assert "search=" not in url


# ── HTML escaping (edge cases) ─────────────────────────────────


class TestHtmlEscaping:
    """Verify _esc prevents XSS in all contexts."""

    def test_script_tag(self) -> None:
        assert "<script>" not in _esc("<script>alert(1)</script>")
        assert "&lt;" in _esc("<script>")

    def test_double_quotes(self) -> None:
        assert '"' not in _esc('"onmouseover="alert(1)"')
        assert "&quot;" in _esc('"test"')

    def test_ampersand(self) -> None:
        assert _esc("a&b") == "a&amp;b"

    def test_int_input(self) -> None:
        assert _esc(42) == "42"

    def test_none_input(self) -> None:
        assert _esc(None) == "None"

    @pytest.mark.parametrize(
        "payload",
        [
            "<img src=x onerror=alert(1)>",
            '"><svg/onload=alert(1)>',
            "javascript:alert(document.domain)",
            "' onclick='alert(1)",
            '<iframe src="javascript:alert(1)">',
        ],
    )
    def test_xss_payloads_escaped(self, payload: str) -> None:
        escaped = _esc(payload)
        assert "<" not in escaped
        assert ">" not in escaped


class TestPygmentsLoadFailure:
    """A pygments that is installed but cannot be imported is UNAVAILABLE.

    ``find_spec`` answers "is there a distribution", the import is what loads
    it, and only the probe was guarded: a half-unpacked install raised out of
    the import and took the whole render with it, because ImportError is no
    OSError and handle_potato's except tuple did not catch it either.  A code
    pane without colour is a page that renders; a raw 500 is not.
    """

    @pytest.fixture
    def _broken_pygments(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        import sys

        import recoverage.potato as potato

        def boom(name: str) -> Any:
            if name == "pygments.lexers":
                return object()
            raise AssertionError(name)

        monkeypatch.setattr(potato.importlib.util, "find_spec", boom)
        # A None entry makes the import raise ImportError, which is what a
        # distribution present on the path but unloadable raises.
        monkeypatch.setitem(sys.modules, "pygments.lexers", None)
        monkeypatch.setitem(sys.modules, "pygments.lexers.lexers", None)
        potato._pygments.cache_clear()
        yield
        potato._pygments.cache_clear()

    @pytest.mark.usefixtures("_broken_pygments")
    def test_the_pane_still_renders_unhighlighted(self, caplog: pytest.LogCaptureFixture) -> None:
        import recoverage.potato as potato

        with caplog.at_level("WARNING", logger="recoverage"):
            assert potato._pygments() is None
            assert potato._highlight_c("int main(void) { return 0; }") == (
                "int main(void) { return 0; }"
            )
        assert any("pygments is installed but unusable" in r.message for r in caplog.records)


class TestSectionHeadingEscapesTitle:
    """_section_heading builds element content by concatenation, so it owns
    the escape: a DB-sourced section or file name must not become live markup
    because one caller forgot."""

    def test_title_is_escaped(self) -> None:
        html = _section_heading("C", "#fff", "<script>alert(1)</script>")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_quote_in_title_cannot_break_an_attribute(self) -> None:
        html = _section_heading("C", "#fff", '" onmouseover="alert(1)')
        assert '" onmouseover="alert(1)' not in html
        assert "&quot;" in html

    def test_plain_title_is_unchanged(self) -> None:
        assert "Original Bytes" in _section_heading("01", "#fff", "Original Bytes")


class TestSectionTabAccesskey:
    """A one-character section name indexes past the end of the string and
    used to 500 the page; the accesskey falls back to the first character.
    Two sections landing on the same letter, and a section landing on one the
    search box or a filter pill already holds, take no shortcut at all."""

    def test_second_character_when_available(self) -> None:
        assert _section_tab_data("T", ".text", {".text": {}}, None, "", set()) == [
            (".text", "?target=T&section=.text", True, _AccessKey("t", 'accesskey="t"'))
        ]

    def test_single_character_name_falls_back_to_first(self) -> None:
        assert _section_tab_data("T", "x", {"x": {}}, None, "", set()) == [
            ("x", "?target=T&section=x", True, _AccessKey("x", 'accesskey="x"'))
        ]

    def test_an_already_claimed_letter_is_withheld(self) -> None:
        assert _section_tab_data("T", ".text", {".text": {}}, None, "", {"s", "t"}) == [
            (".text", "?target=T&section=.text", True, _AccessKey("", ""))
        ]

    def test_two_sections_sharing_a_letter_claim_it_once(self) -> None:
        # .rdata and .rsrc both answer "r", and "r" is the Reloc pill's own
        # letter: whichever comes first in the document keeps it.
        first, second = _section_tab_data(
            "T", ".rdata", {".rdata": {}, ".rsrc": {}}, None, "", {"s"}
        )
        assert first[3].letter == "r"
        assert second[3].letter == ""


# ── Index parsing (potato.py idx handling, via the real render) ────


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
class TestIdxParsing:
    """?idx= handling through the real render path.

    A valid index selects a block (Range:/State: rows); anything unparsable
    or out of range falls back to the empty "Select a block" panel instead of
    raising or rendering another block's details.
    """

    EMPTY_PANEL_MARKER = "Select a block"
    CELL_MARKER = "<b>Range:</b>"

    def _render(self, idx_value: str) -> str:
        target = require_target()
        return render_potato_url(
            f"/potato?target={target}&section=.text&idx={quote(idx_value, safe='')}"
        )

    def test_valid_idx_selects_block(self) -> None:
        html = self._render("0")
        assert self.CELL_MARKER in html
        assert self.EMPTY_PANEL_MARKER not in html

    @pytest.mark.parametrize(
        "idx",
        [
            "",  # absent/empty -> no selection
            "-1",  # negative
            "abc",  # non-numeric
            "3.14",  # float string
            "1e5",  # scientific notation
            "NaN",
            "inf",
            "-inf",
            "++1",  # int() rejects; must arrive URL-encoded
            "999999",  # beyond the cell count
            "99999999999999999999999999999",  # parses as bigint, out of range
        ],
    )
    def test_invalid_idx_falls_back_to_empty_panel(self, idx: str) -> None:
        html = self._render(idx)
        assert self.CELL_MARKER not in html
        assert self.EMPTY_PANEL_MARKER in html


# ── Merge cells invariant ─────────────────────────────────────────


class TestMergeCellsInvariant:
    """Verify _merge_cells preserves total span count."""

    def test_no_merge_different_states(self) -> None:
        from recoverage.potato import _merge_cells

        cells = [
            {"state": "exact", "span": 1, "functions": ["a"]},
            {"state": "reloc", "span": 1, "functions": ["b"]},
            {"state": "stub", "span": 1, "functions": ["c"]},
        ]
        merged = _merge_cells(cells, 64)
        total_span = sum(c.get("span", 1) for c in merged)
        assert total_span == 3
        assert len(merged) == 3

    def test_merge_same_state(self) -> None:
        from recoverage.potato import _merge_cells

        cells = [
            {"state": "exact", "span": 1, "functions": ["a"]},
            {"state": "exact", "span": 1, "functions": ["a"]},
            {"state": "exact", "span": 1, "functions": ["a"]},
        ]
        merged = _merge_cells(cells, 64)
        total_span = sum(c.get("span", 1) for c in merged)
        assert total_span == 3  # span preserved
        assert len(merged) == 1  # all merged into one

    def test_no_merge_across_row_boundary(self) -> None:
        from recoverage.potato import _merge_cells

        cells = [
            {"state": "exact", "span": 1, "functions": ["a"]},
        ] * 65  # exceeds 64-column boundary
        merged = _merge_cells(cells, 64)
        total_span = sum(c.get("span", 1) for c in merged)
        assert total_span == 65
        # The span sum is 65 whether or not the boundary was honoured, so it
        # is the ROW COUNT that pins the property: 64 cells merge into one
        # run, the 65th starts a second row that must not join it.
        assert len(merged) == 2, merged
        assert [c.get("span", 1) for c in merged] == [64, 1], merged

    def test_empty_cells(self) -> None:
        from recoverage.potato import _merge_cells

        assert _merge_cells([], 64) == []

    def test_a_non_positive_span_is_floored_at_one_column(self) -> None:
        """A document may spell `span` zero or negative, and both are arithmetic
        here: `curr_col += span` walks the column cursor backwards, and the
        renderer emits the value as a `colspan` and a pixel width. The reader
        passes an int through with no floor (rebrew.coverage_toml._cell), so
        this is a value a hand-edited document really can carry. `packSection`
        applies the same floor on the SPA side, and both surfaces draw one
        document at one lattice."""
        from recoverage.potato import _cell_span, _merge_cells

        assert _cell_span({"span": -3}) == 1
        assert _cell_span({"span": 0}) == 1
        assert _cell_span({"span": 7}) == 7
        assert _cell_span({}) == 1

        cells = [
            {"state": "exact", "span": 4, "functions": ["a"]},
            {"state": "exact", "span": -2, "functions": ["a"]},
            {"state": "exact", "span": 1, "functions": ["a"]},
        ]
        merged = _merge_cells([dict(cell) for cell in cells], 64)
        spans = [_cell_span(cell) for cell in merged]
        assert sum(spans) == 6, spans
        assert all(span >= 1 for span in spans), spans

    def test_a_negative_span_never_reaches_the_rendered_colspan(self) -> None:
        """The no-merge fast path hands the parsed cells back by reference, so
        the renderer reads the document's own `span` for every row the walk did
        not touch. A negative one rendered `colspan="-2"` and a negative image
        width, and walked the cursor back so the rest of the row was laid out
        from the wrong column."""
        from recoverage.potato import _build_grid_html

        cells = [
            {"state": "exact", "span": -2, "start": 0, "end": 0, "functions": ["a"]},
            {"state": "exact", "span": 1, "start": 2, "end": 3, "functions": ["b"]},
        ]
        html = _build_grid_html(
            merged_cells=cells,
            sec_data={"va": 0x1000, "fileOffset": 0},
            grid_columns=4,
            active_filters=set(),
            search_query="",
            search_matched_fns=set(),
            idx_str="",
            target="t",
            section=".text",
        )
        assert 'colspan="-2"' not in html
        assert 'colspan="1"' in html

    def test_matches_the_closure_reference(self) -> None:
        """The inlined emit must agree with the original ``flush()`` closure.

        The loop emits a finished run at two sites (mid-loop and after the
        loop) rather than through one closure, so the two spellings can drift.
        This pins them against a transcription of the closure form over
        randomized inputs covering both emit sites: ``none`` cells (which never
        merge, exercising the ``out is None`` guard) and mergeable runs.
        """
        import random

        from recoverage.potato import _merge_cells

        def reference(cells: list, grid_columns: int) -> list:
            """_merge_cells as it read with the flush() closure."""
            if not cells:
                return []
            out = None
            start_idx = acc_span = acc_col = 0
            acc_end = acc_state = acc_fns = acc_cell = None

            def flush() -> None:
                if out is not None and acc_cell is not None:
                    out.append(
                        {**acc_cell, "orig_idx": start_idx, "span": acc_span, "end": acc_end}
                    )

            for i, row in enumerate(cells):
                state = row.get("state")
                fns = row.get("functions")
                span = int(row.get("span", 1))
                if (
                    acc_cell is not None
                    and state not in ("none", None)
                    and state == acc_state
                    and fns == acc_fns
                    and acc_col + span <= grid_columns
                ):
                    if out is None:
                        out = cells[:start_idx]
                    acc_span += span
                    acc_end = row.get("end")
                    acc_col += span
                    continue
                flush()
                start_idx = i
                acc_cell = row
                acc_state = state
                acc_fns = fns
                acc_span = span
                acc_end = row.get("end")
                acc_col += span
                if acc_col > grid_columns:
                    acc_col = span
            if out is None:
                return cells
            flush()
            return out

        rnd = random.Random(11)
        states = ["none", "exact", "reloc", "stub", "padding", "data", "thunk", None]
        for _ in range(2000):
            cells = [
                {
                    "start": i,
                    "end": i + rnd.choice([1, 2, 4]),
                    "span": rnd.choice([1, 1, 1, 2, 4]),
                    "state": rnd.choice(states),
                    "functions": [
                        f"f{rnd.randrange(6)}" for _ in range(rnd.choice([0, 0, 0, 1, 1, 2]))
                    ],
                }
                for i in range(rnd.randrange(0, 40))
            ]
            columns = rnd.choice([1, 2, 3, 4, 8, 16, 64])
            assert _merge_cells([dict(x) for x in cells], columns) == reference(
                [dict(x) for x in cells], columns
            )

    def test_none_state_never_merged(self) -> None:
        from recoverage.potato import _merge_cells

        cells = [
            {"state": "none", "span": 1, "functions": []},
            {"state": "none", "span": 1, "functions": []},
        ]
        merged = _merge_cells(cells, 64)
        assert len(merged) == 2  # "none" state cells are never merged


class TestBlockPosition:
    """_block_position must agree with a linear walk over every merged row.

    The binary search it replaced read the same sequence (orig_idx when the
    row carries one, its own position when _merge_cells left it unannotated),
    so both spellings have to resolve the same block — including on the rows
    before the first merge, where the two spellings disagree and the position
    is the answer.
    """

    @staticmethod
    def _linear(merged: list[dict], idx: int) -> int | None:
        for pos, row in enumerate(merged):
            if row.get("orig_idx", pos) == idx:
                return pos
        return None

    @staticmethod
    def _lists() -> list[list[dict]]:
        unmerged = [{"state": "none", "span": 1, "functions": []} for _ in range(12)]
        runs = [
            {"state": "exact", "span": 1, "functions": ["a"]},
            {"state": "exact", "span": 1, "functions": ["a"]},
            {"state": "none", "span": 1, "functions": []},
            {"state": "reloc", "span": 1, "functions": ["b"]},
            {"state": "reloc", "span": 1, "functions": ["b"]},
            {"state": "reloc", "span": 1, "functions": ["b"]},
            {"state": "none", "span": 1, "functions": []},
        ]
        # A merge that begins past the first row: the prefix stays unannotated
        # while the tail carries orig_idx, so both spellings are live at once.
        return [unmerged, runs, unmerged + runs, runs + unmerged]

    def test_matches_linear_walk(self) -> None:
        from recoverage.potato import _block_position, _merge_cells

        for cells in self._lists():
            for columns in (2, 3, 8, 64):
                merged = _merge_cells(cells, columns)
                for idx in range(-2, len(cells) + 2):
                    assert _block_position(merged, idx) == self._linear(merged, idx), (
                        f"columns={columns} idx={idx}"
                    )

    def test_absent_index_returns_none(self) -> None:
        from recoverage.potato import _block_position, _merge_cells

        merged = _merge_cells([{"state": "exact", "span": 1, "functions": ["a"]}] * 4, 64)
        assert len(merged) == 1
        assert _block_position(merged, 1) is None
        assert _block_position([], 0) is None

    def test_grid_page_uses_block_position(self) -> None:
        from recoverage.potato import _grid_page, _merge_cells

        cells = [
            {"state": "exact", "span": 1, "functions": ["a"]},
            {"state": "exact", "span": 1, "functions": ["a"]},
            {"state": "none", "span": 1, "functions": []},
        ]
        merged = _merge_cells(cells, 64)
        # One row per page: block 2 sits on page 2 even though it is row 1.
        assert _grid_page("", "2", merged, 1, 3) == 2
        # An ?idx= naming no block falls back to the first page.
        assert _grid_page("", "99", merged, 1, 3) == 1
        assert _grid_page("", "not-a-number", merged, 1, 3) == 1
        # An explicit ?page= still wins.
        assert _grid_page("3", "2", merged, 1, 3) == 3

    def test_grid_page_rejects_non_ascii_digits(self) -> None:
        """?page= and ?idx= are ASCII, so a foreign digit names no page at all.

        ``int()`` reads every code point ``str.isdigit()`` calls a digit, so
        an ARABIC-INDIC 3 in ``?page=`` opened page 3 and an ARABIC-INDIC 2 in
        ``?idx=`` selected a block, out of a query that spells no such number
        in any documented form.
        """
        from recoverage.potato import _grid_page, _merge_cells

        cells = [{"state": "exact", "span": 1, "functions": ["a"]}] * 3
        merged = _merge_cells(cells, 64)
        for value in ("\u0663", "1_0", "0x2", "+2"):
            assert _grid_page(value, "", merged, 1, 3) == 1
            assert _grid_page("", value, merged, 1, 3) == 1


class TestFunctionListLinks:
    """Every function row links into the grid for the SAME name it prints."""

    def test_row_link_carries_the_printed_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recoverage.potato import _render_function_list

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 32, "cells": [cell(0, 32, "exact")]}},
            functions=[
                {
                    "va": 4096,
                    "name": "sub_401000",
                    "vaStart": "0x1000",
                    "size": 12,
                    "status": "EXACT",
                    "module": "T",
                },
                {
                    "va": 4100,
                    "name": "a name/with?chars",
                    "vaStart": "0x1004",
                    "size": 8,
                    "status": "STUB",
                    "module": "B",
                },
            ],
        )
        html = _render_function_list(snap, "T", ".text", None, "", "va", "")[0]
        assert f'<a href="?target=T&section=.text&search={quote("sub_401000")}">' in html
        spaced = f'<a href="?target=T&section=.text&search={quote("a name/with?chars")}">'
        assert spaced in html


class TestV4StateColors:
    """Every v4 cell state renders with its own COLORS entry, never the
    undocumented gray: proven (post-verify promotion) and legacy
    near_matching / size_mismatch previously fell through to COLORS["none"],
    hiding verified work as holes in the map while /stats counted them."""

    @staticmethod
    def _cell_bgcolor(state: str) -> str:
        from recoverage.potato import _build_grid_html

        html = _build_grid_html(
            [{"state": state, "span": 1, "functions": ["f"], "start": 0, "end": 1}],
            {},
            64,
            set(),
            "",
            set(),
            "",
            "t",
            ".text",
        )
        # Anchor on this cell's own alt text: the sizing row in front of the
        # data row also carries bgcolor attributes.
        anchor = html.index(f"0x0..0x1 | {state}")
        marker = html.rindex('bgcolor="', 0, anchor) + len('bgcolor="')
        return html[marker : html.index('"', marker)]

    def test_proven_renders_the_proven_fill(self) -> None:
        assert self._cell_bgcolor("proven") == "#3f7a63"

    def test_legacy_near_matching_renders_the_near_fill(self) -> None:
        assert self._cell_bgcolor("near_matching") == "#8a6c2c"

    def test_size_mismatch_renders_the_near_fill(self) -> None:
        assert self._cell_bgcolor("size_mismatch") == "#8a6c2c"

    def test_unknown_state_still_falls_back_to_the_unlit_fill(self) -> None:
        assert self._cell_bgcolor("some_future_state") == "#212124"


class TestRawByteRange:
    """`_get_raw_bytes` must refuse a range that escapes the buffer at EITHER
    end, and a negative size is the end the file_offset check never sees.

    A negative-index slice counts back from the END of the buffer, so
    `_get_raw_bytes(0, -4096)` on a 25600-byte binary answered with 21504
    bytes of unrelated code, which the function panel rendered as that
    function's "Original Bytes" dump and Data Inspector. The clamp above the
    slice is a no-op against a negative value, so a size of -1_000_000_000
    asked the slice for a gigabyte rather than the 1 MiB bound. The document is
    untrusted input: `rebrew.coverage_toml.Function.size` is `int | None` with
    no floor, and the function panel hands that value straight through, so
    this is the tail both callers arrive at.
    """

    #: 1 MiB + 100 bytes, so a read clamped to :data:`_MAX_RAW_READ` still
    #: lands inside it and the clamp is observable rather than refused.
    BINARY = bytes(range(256)) * 4100

    @pytest.fixture(autouse=True)
    def _loaded(self, monkeypatch: Any) -> None:
        from recoverage import potato, server

        monkeypatch.setattr(potato, "_load_dll", lambda target: self.BINARY)
        with server.DLL_LOCK:
            server.DLL_DATA.clear()
        yield
        with server.DLL_LOCK:
            server.DLL_DATA.clear()

    @pytest.mark.parametrize(
        ("offset", "size"),
        [
            (0, -4096),  # the whole binary but its tail
            (0, -20000),
            (0, -1_000_000_000),  # the clamp is a no-op on a negative
            (100, -10),
            (0, 0),  # nothing to read
            (-1, 16),  # the offset end, which was already refused
        ],
    )
    def test_a_range_outside_the_buffer_is_refused(self, offset: int, size: int) -> None:
        from recoverage.potato import _get_raw_bytes

        assert _get_raw_bytes(offset, size, "target") is None

    def test_the_in_bounds_range_is_the_exact_slice(self) -> None:
        from recoverage.potato import _get_raw_bytes

        assert _get_raw_bytes(100, 16, "target") == self.BINARY[100:116]

    def test_a_size_past_the_read_bound_is_clamped(self) -> None:
        from recoverage.potato import _MAX_RAW_READ, _get_raw_bytes

        got = _get_raw_bytes(0, _MAX_RAW_READ + 1, "target")
        assert got == self.BINARY[:_MAX_RAW_READ]


class TestGridColumnsValidation:
    """grid_columns <= 0 now raises ValueError (not assert)."""

    def test_zero_raises(self):
        from recoverage.potato import _build_grid_html

        with pytest.raises(ValueError, match="grid_columns must be positive"):
            _build_grid_html([], {}, 0, set(), "", set(), "", "t", ".text")

    def test_negative_raises(self):
        from recoverage.potato import _build_grid_html

        with pytest.raises(ValueError, match="grid_columns must be positive"):
            _build_grid_html([], {}, -1, set(), "", set(), "", "t", ".text")


class TestGridFitsADesktopWindow:
    """A 64-column section, which is what rebrew writes, renders narrower.

    At 27px a column the declared 64 made a 1728px lattice, so Potato Mode
    scrolled sideways on a 1440px desktop.  The page reflows the same blocks
    into at most ``_MAX_RENDERED_COLUMNS`` columns.
    """

    def test_a_64_column_section_renders_at_the_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        states = ("exact", "stub")
        cells = [cell(i * 16, i * 16 + 16, states[i % 2]) for i in range(100)]
        _write_doc(
            tmp_path,
            monkeypatch,
            "WIDE",
            {".text": {"size": 1600, "columns": 64, "unitBytes": 16, "cells": cells}},
        )
        html = render_potato_url("/potato?target=WIDE&section=.text")
        grid = re.search(r'<table id="grid"[^>]*>(.*?)</table>', html, re.DOTALL)
        assert grid is not None
        rows = re.split(r"</tr><tr>", grid.group(1))
        assert len(re.findall(r"<td\b", rows[0])) == _MAX_RENDERED_COLUMNS
        for row in rows[1:]:
            spans = [int(v) for v in re.findall(r'colspan="(\d+)"', row)]
            assert sum(spans) == _MAX_RENDERED_COLUMNS, row[:120]
        # Every block is still drawn: 100 alternating cells, none merged.
        assert len(re.findall(r'href="\?target=WIDE&section=\.text&idx=\d+"', grid.group(1))) == 100


class TestGridWrapsACellWiderThanTheLattice:
    """No rendered cell may be wider than the lattice, and a cell that is has
    to be SPLIT rather than clipped.

    `catalog/grid._build_cells` guarantees `span <= columns`, so a wider cell is
    only a hand-edited or byte-mutated document, but it reached the renderer: a
    200-span cell in a 64-column section emitted `<td colspan="200">` into a
    table whose sizing row declares 64 cells, so the browser resolved the table
    to 200 columns and every cell after the wide one was laid out against a
    different column count. The SPA already wraps the same cell
    (`pack.forEachPlacement`), so the two surfaces disagreed about one cell's
    width; the two now agree, and no colspan escapes `grid_columns`.
    """

    def _grid(self, cells: list[dict[str, object]], columns: int, idx: str = "") -> str:
        from recoverage.potato import _build_grid_html

        return _build_grid_html(cells, {}, columns, set(), "", set(), idx, "t", ".text")

    def test_a_wide_cell_is_split_across_rows(self) -> None:
        html = self._grid(
            [
                {"state": "exact", "span": 200, "start": 0, "end": 200, "functions": ["f"]},
                {"state": "stub", "span": 1, "start": 200, "end": 201, "functions": []},
            ],
            64,
        )
        widths = [int(value) for value in re.findall(r'colspan="(\d+)"', html)]
        assert widths == [64, 64, 64, 8, 1, 55]
        assert max(widths) <= 64

    def test_the_selection_id_stays_unique_when_a_cell_is_split(self) -> None:
        html = self._grid(
            [{"state": "exact", "span": 200, "start": 0, "end": 200, "functions": ["f"]}],
            64,
            idx="0",
        )
        assert html.count('id="sel"') == 1

    def test_a_wide_cell_still_carries_its_whole_address_range(self) -> None:
        html = self._grid(
            [{"state": "exact", "span": 200, "start": 0, "end": 200, "functions": ["f"]}],
            64,
        )
        # Every piece links the same cell, so the whole run stays reachable.
        assert re.findall(r'href="([^"]*)"', html) == ["?target=t&section=.text&idx=0"] * 4

    def test_an_ordinary_cell_is_one_cell_still(self) -> None:
        html = self._grid(
            [{"state": "exact", "span": 3, "start": 0, "end": 3, "functions": ["f"]}],
            64,
        )
        assert re.findall(r'colspan="(\d+)"', html) == ["3", "61"]
        assert html.count("<tr>") == html.count("</tr>")


class TestGridTargetSize:
    """Every lattice cell is one link, so the cell is a pointer target and
    WCAG 2.2 SC 2.5.8 puts its floor at 24x24 CSS pixels. The selected cell
    draws an inset to expose the accent border, so it is the one that could
    quietly land under the floor while the rest of the lattice stayed over it."""

    #: SC 2.5.8, Target Size (Minimum).
    MINIMUM = 24

    def _sizes(self, html: str) -> list[tuple[int, int]]:
        return [
            (int(width), int(height))
            for width, height in re.findall(r'<img [^>]*?width="(\d+)" height="(\d+)"', html)
        ]

    def test_every_link_meets_the_floor(self):
        from recoverage.potato import _CELL_SIZE, _build_grid_html

        assert _CELL_SIZE >= self.MINIMUM
        html = _build_grid_html(
            [{"state": "exact", "start": 0, "end": 4, "span": 1, "functions": ["fn"]}],
            {"va": 0x1000},
            4,
            set(),
            "",
            set(),
            "",
            "t",
            ".text",
        )
        sizes = self._sizes(html)
        assert sizes, "grid rendered no images"
        assert all(width >= self.MINIMUM and height >= self.MINIMUM for width, height in sizes), (
            f"undersized grid targets: {sizes}"
        )

    def test_the_selected_cell_meets_the_floor_too(self):
        from recoverage.potato import _build_grid_html

        cells = [
            {"state": "stub", "start": i * 4, "end": i * 4 + 4, "span": 1, "functions": []}
            for i in range(4)
        ]
        plain = _build_grid_html(cells, {"va": 0}, 4, set(), "", set(), "", "t", ".text")
        selected = _build_grid_html(cells, {"va": 0}, 4, set(), "", set(), "2", "t", ".text")
        assert self._sizes(selected) != self._sizes(plain), "selection did not inset anything"
        selected_sizes = self._sizes(selected)
        assert all(
            width >= self.MINIMUM and height >= self.MINIMUM for width, height in selected_sizes
        ), f"undersized selected target: {selected_sizes}"


class TestPathTraversalGuard:
    """_panel_fn_source_text must refuse to read files outside the source root.

    The production guard resolves the candidate path and requires it to stay
    inside the source tree:
        base = (Path.cwd().resolve() / source_root.lstrip("/")).resolve()
        c_path = (base / files[0]).resolve()
        if not c_path.is_relative_to(base): return None

    These tests drive that function directly, so a regression in potato.py
    (dropping resolve(), dropping the containment check) fails here.
    """

    @staticmethod
    def _read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rel: str, source_root: str = "src"):
        monkeypatch.chdir(tmp_path)
        data: dict = {"paths": {"sourceRoot": source_root}}
        return _panel_fn_source_text(data, "T", {"files": [rel]})

    def test_traversal_blocked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Attacker-controlled filename with ../ must be rejected."""
        (tmp_path / "src").mkdir()
        assert self._read(tmp_path, monkeypatch, "../../secret.txt") is None

    def test_anchored_source_root_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A sourceRoot that is anchored or traverses is refused.

        sourceRoot is the containment base, so a value that survives the
        leading-"/" strip as an anchor (``C:src``) or a parent hop
        (``../..``) makes the join REPLACE the base, and the
        ``c_path.is_relative_to(base)`` check that follows passes trivially —
        the whole filesystem becomes the source tree. Stripping only "/" is a
        POSIX assumption: on a POSIX host these spellings are inert, so the
        guard answered to its host rather than to the document.
        """
        (tmp_path / "src").mkdir()
        for source_root in ("C:src", "../..", "/../..", "src/../..", ""):
            assert self._read(tmp_path, monkeypatch, "main.c", source_root) is None, source_root

    def test_windows_shaped_source_root_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Windows spellings specifically, whatever the host flavour.

        A POSIX host reads ``C:/Windows`` and ``\\Windows`` as ordinary
        relative names, so the case only bites on the platform that has them;
        asserting the refusal through the production guard on every host
        keeps the Windows build from being the only place it is exercised.
        """
        (tmp_path / "src").mkdir()
        for source_root in ("C:/Windows", "C:\\Windows", "\\Windows\\System32"):
            assert self._read(tmp_path, monkeypatch, "main.c", source_root) is None, source_root

    def test_symlinked_source_root_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A sourceRoot that is plain-relative but RESOLVES out of the project.

        ``is_plain_relative`` is a lexical rule: it holds "src/evil" whatever
        src/evil is, and ``resolve()`` follows a symlink. The check on the
        resolved base against the project root is what refuses it: every
        ``is_relative_to`` below that is measured against ``base``, which is
        the directory that already escaped, so those pass trivially. Git
        preserves a symlink in a checkout, so this is a file the tree ships,
        not one a reader has to plant.

        The escape target is a SIBLING of the project root, because that is
        what the guard measures. A target under the project root is not an
        escape at all: the panel may read the project's own files, and the
        fixture would then assert a refusal the guard does not owe (it read
        the file, and the test failed on a correct guard).
        """
        outside = tmp_path.parent / f"{tmp_path.name}-outside"
        outside.mkdir()
        (outside / "passwd").write_text("root:x:0:0", encoding="utf-8")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "evil").symlink_to(outside, target_is_directory=True)
        assert self._read(tmp_path, monkeypatch, "passwd", "src/evil") is None

    def test_non_string_and_nul_file_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A document spells ``files`` with no type on its elements.

        ``files = [1]`` reaches Path() as a TypeError and a NUL-bearing name
        makes resolve() raise ValueError; the second is caught and the first
        escaped handle_potato's except tuple as a raw 500. ui.py refuses both
        on the same value. The answer is the panel without its source.
        """
        (tmp_path / "src").mkdir()
        assert self._read(tmp_path, monkeypatch, 1) is None  # type: ignore[arg-type]
        assert self._read(tmp_path, monkeypatch, "a\x00b") is None

    def test_absolute_path_blocked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """An absolute files[0] replaces the base entirely (Path join
        semantics) and must be rejected even when the file exists."""
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        (tmp_path / "src").mkdir()
        assert self._read(tmp_path, monkeypatch, str(outside)) is None

    def test_normal_file_allowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A file inside the source tree is read and returned."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.c").write_text("int main(void) { return 0; }", encoding="utf-8")
        result = self._read(tmp_path, monkeypatch, "main.c")
        assert result == "int main(void) { return 0; }"

    def test_missing_file_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "src").mkdir()
        assert self._read(tmp_path, monkeypatch, "nope.c") is None

    def test_undecodable_byte_does_not_blank_the_panel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A source file with one latin-1 byte must still render.

        Decompiled projects carry Windows-1252 bytes in comments; a strict
        UTF-8 decode used to raise and drop the whole file, so one 0x92
        emptied the panel.  The undecodable byte becomes U+FFFD in place.
        """
        src = tmp_path / "src"
        src.mkdir()
        # 0x92 is a Windows-1252 right single quote, not valid UTF-8.
        (src / "main.c").write_bytes(b"int main(void) { /* don\x92t */ return 0; }")
        result = self._read(tmp_path, monkeypatch, "main.c")
        assert result is not None
        assert "\ufffd" in result
        assert "int main(void) { /* don" in result
        assert "return 0; }" in result

    def test_no_files_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        data: dict = {"paths": {"sourceRoot": "src"}}
        assert _panel_fn_source_text(data, "T", {"files": []}) is None
        assert _panel_fn_source_text(data, "T", {}) is None

    def test_source_root_escape_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A source root that resolves outside the project is refused.

        The second input, and the one the caller controls: ``sourceRoot`` falls
        back to ``/src/<target>`` built from the request's ``?target=``, and
        ``?target=../../../..`` moved the root outside the project.  The
        per-file check then held THAT root as its baseline and passed, so the
        panel rendered a file from outside the tree.  A file name with no
        ``..`` in it is enough, which is why the file-name tests above do not
        catch it.
        """
        (tmp_path / "src").mkdir()
        (tmp_path / "secret.c").write_text("TOP SECRET", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        for source_root in ("..", "../..", "/../.."):
            data: dict = {"paths": {"sourceRoot": source_root}}
            assert _panel_fn_source_text(data, "T", {"files": ["secret.c"]}) is None

    def test_decomposed_source_name_found_from_the_composed_spelling(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A macOS tree holds the NFD name; the document spells it composed.

        The document records the path rebrew saw, the panel joined that string
        onto the root, and a decomposed file was not found by its composed
        name, so the source pane rendered empty beside a file that was there.
        """
        monkeypatch.chdir(tmp_path)
        directory = tmp_path / "src" / unicodedata.normalize("NFD", "données")
        directory.mkdir(parents=True)
        leaf = unicodedata.normalize("NFD", "naïve.c")
        (directory / leaf).write_text("int main(void) { return 0; }", encoding="utf-8")
        composed = f"{unicodedata.normalize('NFC', 'données')}/{unicodedata.normalize('NFC', leaf)}"
        data: dict = {"paths": {"sourceRoot": "src"}}
        text = _panel_fn_source_text(data, "T", {"files": [composed]})
        assert text is not None
        assert "int main(void)" in text

    def test_source_root_escape_via_target_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same escape with no ``sourceRoot`` in the document.

        ``paths`` without the key takes the ``/src/<target>`` fallback, and
        *target* is the raw query value, so the traversal needs no document
        data at all — only a request.
        """
        (tmp_path / "src").mkdir()
        (tmp_path / "secret.c").write_text("TOP SECRET", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        for paths in ({}, {"paths": {}}, {"paths": []}):
            assert _panel_fn_source_text(paths, "../../..", {"files": ["secret.c"]}) is None

    @pytest.mark.parametrize(
        "name",
        ["main.c", "a/b.c", "a\\b.c", "..foo.c", "foo..c", "./main.c"],
    )
    def test_plain_relative_names_accepted(self, name: str) -> None:
        """Both flavours read a name as plain when the host agrees; a POSIX
        host cannot see a Windows drive-relative name at all, so the
        cross-platform rule is pinned through PureWindowsPath below."""
        assert is_plain_relative(PurePosixPath(name))

    @pytest.mark.parametrize(
        ("name", "why"),
        [
            ("/etc/passwd", "absolute"),
            ("//srv/share/main.c", "UNC share"),
            ("C:foo.c", "drive-relative: joins as <drive>:/foo.c, not the named file"),
            ("../secret.txt", "parent traversal"),
            ("a/../../secret.txt", "parent traversal mid-path"),
            (r"a\..\..\secret.txt", "parent traversal with Windows separators"),
        ],
    )
    def test_anchored_or_traversing_names_refused(self, name: str, why: str) -> None:
        """The guard keys on ``anchor``, not ``is_absolute()``: on Windows
        ``C:foo.c`` is not absolute, yet joining it onto the source root
        reads a different file than the database named.  Pinned through
        PureWindowsPath so the rule is tested on every host, not only where
        the flavour is the native one."""
        assert why  # the case table documents intent, not behaviour
        assert not is_plain_relative(PureWindowsPath(name))

    def test_symlink_escape_blocked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Symlink pointing outside the source tree must be caught by resolve()."""
        (tmp_path / "src").mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "passwd").write_text("secret", encoding="utf-8")
        try:
            (tmp_path / "src" / "escape").symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable (Windows without developer mode)")
        assert self._read(tmp_path, monkeypatch, "escape/passwd") is None


class TestSearchLimit:
    """_search_functions should limit results."""

    @pytest.mark.skipif(not HAS_DB, reason="No coverage document")
    def test_search_returns_bounded_results(self):
        """_search_functions caps at 500 rows per query (500 functions +
        500 globals, so at most 1000 entries in the returned set)."""
        from recoverage.potato import _search_functions

        snap = _shared_snapshot()
        # Empty search returns empty set (short-circuit)
        assert _search_functions(snap, "") == set()
        # Search with a single common letter — should be bounded.  The
        # 1000-entry bound (500 functions + 500 globals) is pinned by the cap
        # tests below against >500-row fixtures; against this 3-function
        # document the only thing left to show is that a non-empty query
        # matches and stays inside the bound.
        results = _search_functions(snap, "a")
        assert 0 < len(results) <= 1000

    def test_search_empty_returns_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Empty search query short-circuits to the empty set.

        The short-circuit is before any name comparison, so it holds for a
        document whose rows would otherwise match every term.
        """
        from recoverage.potato import _search_functions

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[{"va": 0x1000, "name": "aaa"}],
            globals_=[{"va": 0x2000, "name": "aaa_global"}],
        )
        assert _search_functions(snap, "") == set()

    def test_an_address_the_page_printed_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Pasting the address the cell panel shows must highlight the row.

        The panel prints an address through `_format_va`, which pads to eight
        hex digits, and a target whose functions sit below 0x10000000 spells
        the same address differently in `vaStart` (the string a .text cell
        stores, and the one the dimming set is compared against).  Matching
        `vaStart` alone meant the address on screen highlighted nothing while
        the functions view, which matches both spellings, found the row.  Both
        spellings match here, and the search still has to agree with the API
        list, which matches `vaStart` too.
        """
        from recoverage.potato import _search_functions

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[{"va": 0x401000, "vaStart": "0x401000", "name": "_low"}],
            globals_=[{"va": 0x402000, "name": "_low_global"}],
        )
        for spelling in ("0x00401000", "0x401000", "0X401000"):
            assert "_low" in _search_functions(snap, spelling), spelling
        # The global the panel shows, same rule.
        for spelling in ("0x00402000", "0x402000"):
            assert "_low_global" in _search_functions(snap, spelling), spelling

    def test_functions_cap_is_deterministic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """The functions half of the 1000-entry bound: with >500 matches the
        cap must keep exactly the first 500 by name, vaStart.  A cap without the
        ordering keeps whichever rows the document happened to list first."""
        from recoverage.potato import _search_functions

        names = [f"func_{i:04d}" for i in range(600)]
        # Listed in REVERSE name order, with no vaStart, so the result is the
        # capped name set alone (each matching row contributes one entry).
        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[
                {"va": 0x10000000 + i * 4, "name": n} for i, n in enumerate(reversed(names))
            ],
        )
        result = _search_functions(snap, "func_")
        assert len(result) == 500
        assert result == set(sorted(names)[:500])

    def test_the_match_set_counts_rows_and_the_dim_set_carries_addresses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """One match, one count; the grid's own key set is the wider one.

        A ``.text`` cell stores its function's ``vaStart`` string, not its
        name, so the dimming test compares cell entries against a set that
        carries both spellings.  That set was the one `_search_functions`
        returned, and the topbar's "N matches" line counts it: a single
        function found by its address read "2 matches".  The count therefore
        takes the names alone and `_cell_dim_keys` derives the grid's set, so
        neither the count nor the dimming can drift apart again.

        The RENDER is the oracle, not `_search_functions` alone: the defect was
        one line in the render, counting the widened dim set, and every
        assertion on the two helpers below still passed with it in place. So
        the page is rendered and the count the reader is actually shown is
        compared, by NAME and by ADDRESS, because the address arm is the one
        that reached two keys.
        """
        from recoverage.potato import _cell_dim_keys, _search_functions

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"va": 0x401000, "size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[{"va": 0x401000, "vaStart": "0x401000", "name": "matched_row"}],
            globals_=[{"va": 0x402000, "name": "g_counter"}],
        )
        matched = _search_functions(snap, "matched_row")
        assert matched == {"matched_row"}, matched
        assert len(matched) == 1
        # The grid still dims the cells, which carry the address spelling.
        assert _cell_dim_keys(snap, matched) == {"matched_row", "0x401000"}
        # A global names no function row, so it carries no address with it.
        assert _cell_dim_keys(snap, {"g_counter"}) == {"g_counter"}
        assert _cell_dim_keys(snap, set()) == set()

    def test_the_status_line_counts_one_match_for_a_row_found_by_its_address(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The rendered "N matches" line counts ROWS, by name or by address.

        The bug the arm above repairs was visible here and nowhere else in the
        rendered page: the topbar counted the grid's dim set, which carries
        each function's ``vaStart`` beside its name, so one function found by
        its address read "2 matches". Asserting the two helpers let that
        through; asserting the line the reader sees does not. A test on the
        helpers alone cannot distinguish a caller that takes the names alone
        from one that counts the widened set, which is the whole decision.
        """
        _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {
                ".text": {
                    "va": 0x401000,
                    "size": 16,
                    # The spelling a `.text` cell really stores, so the grid
                    # has a key to dim on and the count has two to count.
                    "cells": [cell(0, 16, "exact", functions=("0x401000",))],
                }
            },
            functions=[{"va": 0x401000, "vaStart": "0x401000", "name": "matched_row"}],
            globals_=[{"va": 0x402000, "name": "g_counter"}],
        )
        by_name = render_potato_url("/potato?target=T&section=.text&search=matched_row")
        by_address = render_potato_url("/potato?target=T&section=.text&search=0x401000")
        # The singular label is itself the assertion: "2 matches" is the bug's
        # exact rendering, and `1 match` is the only one that is not.
        assert "1 match for &quot;matched_row&quot;" in by_name, by_name[-3000:]
        assert "1 match for &quot;0x401000&quot;" in by_address, by_address[-3000:]
        assert "2 matches" not in by_address, by_address[-3000:]

    def test_globals_cap_is_deterministic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """With >500 matches, which globals enter the dimming set must be
        reproducible: the 500-row cap is only deterministic with an ordering,
        same invariant as the functions case above."""
        from recoverage.potato import _search_functions

        names = [f"glob_{i:04d}" for i in range(600)]
        # Listed in REVERSE name order: a cap without an ordering keeps the
        # rows the document lists first and the wrong half of the set.
        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            globals_=[{"va": 0x10000000 + i * 4, "name": n} for i, n in enumerate(reversed(names))],
        )
        result = _search_functions(snap, "glob_")
        assert len(result) == 500
        assert result == set(sorted(names)[:500])


class TestFunctionListOrdering:
    """The API page and the Potato table order the same rows the same way.

    Both go through ``server.function_sort_key``, so a row copied from one
    surface is where the other surface says it is.  An unknown size sorts
    before every known one (the ordering both lists have always had), and the
    `va` tiebreak keeps the Potato table stable where the API reverses.
    """

    # Declared in ascending va, which is the order the document holds them in:
    # the API breaks a tie on the sorted column with Python's stable sort (so
    # with document order) and the Potato table breaks it with an explicit
    # ascending va, and the two agree only when document order IS that.
    FUNCTIONS: ClassVar[list[dict[str, Any]]] = [
        {"va": 0x401000, "name": "sized_too", "vaStart": "0x401000", "size": 40, "status": "EXACT"},
        {"va": 0x401010, "name": "unsized", "vaStart": "0x401010", "size": None, "status": "STUB"},
        {"va": 0x401020, "name": "sized", "vaStart": "0x401020", "size": 40, "status": "EXACT"},
    ]

    def _snapshot(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CoverageSnapshot:
        return _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 64, "cells": [cell(0, 64, "exact")]}},
            functions=self.FUNCTIONS,
        )

    def test_the_memoized_row_filter_matches_the_per_request_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The memo answers the same rows the walk did, and hands back a copy.

        The render sorts in place, so a shared list would be reordered by one
        request for every other: the memo returns a tuple, and the render
        copies before it sorts.

        The memo itself moved to :func:`server.function_rows` when the API
        list endpoint started reading the same derived set rather than
        re-deriving it per request; this pins it there now.
        """
        from recoverage import server as _server

        function_rows = _server.function_rows
        _is_data_marker = _server._is_data_marker

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 64, "cells": [cell(0, 64, "exact")]}},
            functions=[
                *self.FUNCTIONS,
                {
                    "va": 0x401030,
                    "name": "g_marker",
                    "vaStart": "0x401030",
                    "size": 4,
                    "status": "EXACT",
                    "markerType": "GLOBAL",
                },
            ],
        )
        expected = [fn.name for fn in snap.functions if not _is_data_marker(fn)]
        rows = function_rows(snap)
        assert [fn.name for fn in rows] == expected
        assert "g_marker" not in expected, "the fixture must exercise a real marker row"
        assert function_rows(snap) is rows, "a second call must hit the memo"
        assert isinstance(rows, tuple), "the render sorts, so a shared list would be mutated"

    @pytest.mark.parametrize("field", ["va", "name", "status", "size"])
    def test_both_surfaces_produce_one_order(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
    ) -> None:
        from recoverage.potato import _render_function_list
        from recoverage.server import function_sort_key

        snap = self._snapshot(tmp_path, monkeypatch)
        # The Potato table's rendered row order, read back out of its row links
        # in document order.  Ties on the sorted column break by va there (the
        # cap has to be deterministic), so the shared key is what the rendered
        # order is non-decreasing on, and the API's page order is the same key
        # applied to the same rows.
        html = _render_function_list(snap, "T", ".text", None, "", field, "")[0]
        rendered = [
            unquote(match) for match in re.findall(r"&section=\.text&search=([^\"]+)", html)
        ]
        api_order = [fn.name for fn in sorted(snap.functions, key=function_sort_key(field))]
        assert rendered == api_order, f"{field}: the two surfaces disagree"

    def test_an_unknown_size_sorts_before_every_known_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recoverage.server import function_sort_key

        snap = self._snapshot(tmp_path, monkeypatch)
        keys = [function_sort_key("size")(fn) for fn in snap.functions]
        assert keys.index((0, 0)) == 1, "the unsized row must sort first"
        assert keys[0] == keys[2] == (1, 40)


class TestSearchAddressSpelling:
    """Both address spellings _format_va can print must match.

    _format_va pads to eight digits (``0x00401000``) while printf('%x') does
    not (``0x401000``), so matching only one of them means an address copied
    out of a rendered VA column silently matches nothing."""

    @staticmethod
    def _snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CoverageSnapshot:
        return _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[{"va": 0x401000, "name": "sub_401000", "status": "exact"}],
            globals_=[{"va": 0x402000, "name": "g_cfg"}],
        )

    @pytest.mark.parametrize("query", ["0x00401000", "0x401000"])
    def test_padded_and_bare_function_va_both_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str
    ) -> None:
        """The Functions view prints the VA through _format_va, so pasting that
        same string back into its search box must find the row."""
        from recoverage.potato import _render_function_list

        snap = self._snapshot(tmp_path, monkeypatch)
        assert "sub_401000" in _render_function_list(snap, "T", ".text", None, query, "va", "")[0]

    @pytest.mark.parametrize("query", ["0x00402000", "0x402000"])
    def test_padded_and_bare_global_va_both_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str
    ) -> None:
        from recoverage.potato import _search_functions

        snap = self._snapshot(tmp_path, monkeypatch)
        assert _search_functions(snap, query) == {"g_cfg"}

    @pytest.mark.parametrize("query", ["0x00403000", "0x403000"])
    def test_a_different_address_does_not_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str
    ) -> None:
        from recoverage.potato import _search_functions

        snap = self._snapshot(tmp_path, monkeypatch)
        assert _search_functions(snap, query) == set()


class TestSearchAgreesWithThePerRowFold:
    """The snapshot-folded search must select the rows the per-row fold did.

    ``_search_functions`` reads its name and address columns from the
    snapshot's folded tables rather than folding each column of every row on
    every keystroke.  This is the differential that keeps that a refactor: for
    every term the two paths must return the same name set, including the
    ``vaStart`` spellings the grid's dimming test compares against and the
    global rows, whose arm is the one that broke when a single memo was shared
    between the two arrays.
    """

    @staticmethod
    def _snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CoverageSnapshot:
        return _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[
                {"va": 0x401000, "name": "sub_401000", "symbol": "Sym_1", "status": "exact"},
                {"va": 0x402000, "name": "Straße", "symbol": "STRASSE", "status": "exact"},
                {"va": 0x403000, "name": "café", "status": "exact"},
            ],
            globals_=[{"va": 0x402000, "name": "g_cfg"}, {"va": 0x999000, "name": "g_zzz"}],
        )

    @staticmethod
    def _per_row(snap: CoverageSnapshot, search_query: str) -> set[str]:
        """The pre-fold implementation: fold every column of every row."""
        needle = fold_needle(search_query)
        match_hex = fold_can_match_hex(needle)
        matched: set[str] = set()
        for fn in snap.functions:
            if (
                fold_match_folded(fn.name, needle)
                or (match_hex and fold_match_folded(fn.vaStart, needle))
                or fold_match_folded(fn.symbol, needle)
                or (
                    match_hex
                    and (
                        fold_match_folded(f"0x{fn.va:08x}", needle)
                        or fold_match_folded(f"0x{fn.va:x}", needle)
                    )
                )
            ):
                matched.add(fn.name)
                if fn.vaStart:
                    matched.add(fn.vaStart)
        for gl in snap.globals:
            if fold_match_folded(gl.name, needle) or (
                match_hex
                and (
                    fold_match_folded(f"0x{gl.va:08x}", needle)
                    or fold_match_folded(f"0x{gl.va:x}", needle)
                )
            ):
                matched.add(gl.name)
        return matched

    @pytest.mark.parametrize(
        "query",
        [
            "sub",
            "SUB_401000",
            "0x00401000",
            "0x401000",
            "0x999000",
            "0x000999000",
            "stras",
            "STRASSE",
            "café",
            "g_cfg",
            "sym_1",
            "zzz",
            "nope",
        ],
    )
    def test_the_folded_search_returns_what_the_per_row_fold_did(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str
    ) -> None:
        snap = self._snapshot(tmp_path, monkeypatch)
        assert _search_functions(snap, query) == self._per_row(snap, query), query


class TestFunctionListSearchFolding:
    """The Functions view must fold a non-ASCII term the way the grid does.

    A byte comparison folds case for ASCII only, so a bare name match returns
    nothing for "CAFÉ" against a "Café_Render" row, and an NFD spelling misses
    its NFC twin.  Both readers now fold through ``server.fold_match``, so the
    list and the grid that sits beside it return the same rows for one term.
    """

    @staticmethod
    def _snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CoverageSnapshot:
        return _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[{"va": 0x401000, "name": "Café_Render"}],
        )

    @pytest.mark.parametrize(
        "query",
        [
            "CAFÉ",  # uppercase
            "CAFE\u0301",  # NFD spelling: same term, decomposed
            "café",  # lowercase
        ],
    )
    def test_case_folded_term_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str
    ) -> None:
        from recoverage.potato import _render_function_list

        snap = self._snapshot(tmp_path, monkeypatch)
        assert "Café_Render" in _render_function_list(snap, "T", ".text", None, query, "va", "")[0]

    def test_grid_and_list_agree_on_the_same_term(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recoverage.potato import _render_function_list, _search_functions

        snap = self._snapshot(tmp_path, monkeypatch)
        assert _search_functions(snap, "CAFÉ") == {"Café_Render"}
        assert "Café_Render" in _render_function_list(snap, "T", ".text", None, "CAFÉ", "va", "")[0]

    def test_a_va_start_only_spelling_matches_on_both_views(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The address a row carries in `vaStart` alone is a search term.

        `va` and `vaStart` are independent document columns, so a row whose
        `va` is 0 and whose `vaStart` names the address is one the two hex
        spellings cannot match. This view spelled its name columns out by
        index and left `vaStart` out, so such a row matched here and nowhere
        else: the API list matches `vaStart`, and the grid does too.
        """
        from recoverage.potato import (
            _cell_dim_keys,
            _render_function_list,
            _search_functions,
        )

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            functions=[{"va": 0, "vaStart": "0x401000", "name": "no_va_row"}],
        )
        # `_search_functions` returns NAMES only — the topbar counts this set,
        # so a row that also carried its address would read as "2 matches".
        # The grid's dimming test needs the address spelling a `.text` cell
        # stores, and `_cell_dim_keys` derives it from this set.
        matched = _search_functions(snap, "0x401000")
        assert "no_va_row" in matched, "the vaStart-only row did not match by address"
        assert "0x401000" not in matched, "the set is names-only; a second entry double-counts"
        # The address the grid compares a cell's `functions` field against is
        # derived here, so the dimming still finds the cell.
        assert {"no_va_row", "0x401000"} <= _cell_dim_keys(snap, matched)
        html, count = _render_function_list(snap, "T", ".text", None, "0x401000", "va", "")
        assert count == 1, count
        assert "no_va_row" in html


class TestCellsCacheInvalidation:
    """The grid memo must invalidate when a document is rewritten.

    The fingerprint folds every coverage-*.toml's name, mtime and size, so a
    rebuild that rewrites one target moves it — same contract as /data's memo
    and the SSE watcher."""

    @staticmethod
    def _snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CoverageSnapshot:
        """One .text cell (start 0, exact): the payload every case below caches."""
        return _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "columns": 64, "cells": [cell(0, 16, "exact")]}},
        )

    def test_document_change_forces_refetch(self, tmp_path, monkeypatch) -> None:
        import recoverage.potato as potato
        import recoverage.server as srv

        snap = self._snapshot(tmp_path, monkeypatch)
        potato.clear_cells_cache()
        try:
            _load_grid_cells(snap, ".text", 64, snap=srv._snapshot_db_mtime())
            assert len(potato._GRID_CACHE) == 1
            # A rebuild that rewrites the target's document: the file's stat
            # moves, so the next render must read fresh cells rather than take
            # the memoized pair.
            fresh = _write_doc(
                tmp_path,
                monkeypatch,
                "T",
                {
                    ".text": {
                        "size": 32,
                        "columns": 64,
                        "cells": [cell(0, 16, "exact"), cell(16, 32, "none")],
                    }
                },
            )
            cells, _merged, _key = _load_grid_cells(
                fresh, ".text", 64, snap=srv._snapshot_db_mtime()
            )
            # Two keys prove fingerprint sensitivity: the rewrite produced a
            # cache miss (fresh read), not a stale hit.
            assert len(potato._GRID_CACHE) == 2
            assert len(cells) == 2
        finally:
            potato.clear_cells_cache()

    def test_rebuild_mid_read_is_not_cached(self, tmp_path, monkeypatch) -> None:
        """A rebuild between the read and the publish must not be memoized.

        *snap* is the token the render pinned BEFORE its read, so a fingerprint
        that has moved by the time the rows are read means a rebuild committed
        mid-render.  Filing that payload under the NEW fingerprint poisons the
        memo: the broadcast that cleared it can be overtaken by this insert, and
        nothing invalidates it afterwards.
        """
        import recoverage.potato as potato

        snap = self._snapshot(tmp_path, monkeypatch)
        # The publish re-check: the render's token still reads (1, 64)...
        monkeypatch.setattr(potato, "_snapshot_db_mtime", lambda: (2, 64))

        potato.clear_cells_cache()
        try:
            cells, _merged, _key = _load_grid_cells(snap, ".text", 64, snap=(1, 64))
            assert cells  # this request still gets its payload
            assert not potato._GRID_CACHE  # filed under no fingerprint
        finally:
            potato.clear_cells_cache()

    def test_snapshot_taken_inside_the_read_is_not_the_key(self, tmp_path, monkeypatch) -> None:
        """The key must come from the caller's token, never from a fresh stat.

        Deriving it here would read the post-rebuild value on both sides of the
        publish comparison, so a render whose rows predate a rebuild caches them
        under the fingerprint that supersedes them and every later request is
        served stale cells.
        """
        import recoverage.potato as potato

        snap = self._snapshot(tmp_path, monkeypatch)
        # A stat inside the memo would report the newer fingerprint; the caller's
        # token says the render pinned its read before the rebuild.
        monkeypatch.setattr(potato, "_snapshot_db_mtime", lambda: (2, 64))

        potato.clear_cells_cache()
        try:
            cells, _merged, key = _load_grid_cells(snap, ".text", 64, snap=(1, 64))
            assert key is not None
            # Keyed on the caller's token, never on the value a stat inside the
            # memo would have read.
            assert key[:2] == (1, 64)
            # The fixture seeds one .text cell (start 0, state exact), so
            # "this request still gets its payload" is that row, not a
            # truthy list: a payload of the wrong cells passes `assert cells`.
            assert len(cells) == 1
            assert cells[0]["start"] == 0
            assert cells[0]["state"] == "exact"
            assert not potato._GRID_CACHE  # the re-check failed, so nothing filed
        finally:
            potato.clear_cells_cache()

    def test_clear_cells_cache_drops_entries(self) -> None:
        import recoverage.potato as potato

        k = ("fp", "T", ".text", 64)
        potato._GRID_CACHE[k] = ([], [], k)  # type: ignore[assignment]
        potato.clear_cells_cache()
        assert not potato._GRID_CACHE


class TestSectionDataCacheInvalidation:
    """The section-data memo must invalidate when a document is rewritten.

    ``_load_section_data`` reaches ``server._summary``, whose per-section arm
    walks every non-``.text`` cell to count the function names they carry, so
    it is memoized on the same token the grid memo is.  The cell counts it
    derives are exactly the ones a rebuild changes, so a memo that outlived one
    would render a previous build's progress bars and section table.
    """

    @staticmethod
    def _snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CoverageSnapshot:
        return _write_doc(
            tmp_path,
            monkeypatch,
            "SD",
            {
                ".text": {
                    "va": 4096,
                    "size": 16,
                    "fileOffset": 512,
                    "unitBytes": 16,
                    "columns": 8,
                    "cells": [cell(0, 16, "exact")],
                },
                ".rdata": {
                    "va": 8192,
                    "size": 32,
                    "fileOffset": 4096,
                    "unitBytes": 16,
                    "columns": 8,
                    # totalFunctions counts the NAMES the cells carry, so a
                    # cell with no name contributes nothing: the fixtures
                    # below name theirs, or the count reads 0 either way and
                    # pins nothing.
                    "cells": [
                        cell(0, 16, "exact", functions=["r0"]),
                        cell(16, 32, "exact", functions=["r1"]),
                    ],
                },
            },
        )

    def test_a_rebuild_forces_a_fresh_walk(self, tmp_path, monkeypatch) -> None:
        import recoverage.potato as potato
        import recoverage.server as srv

        snap = self._snapshot(tmp_path, monkeypatch)
        potato.clear_cells_cache()
        try:
            _sections, data = _load_section_data(snap, snap=srv._snapshot_db_mtime())
            assert data["summary"][".rdata"]["totalFunctions"] == 2
            assert len(potato._SECTION_DATA_CACHE) == 1

            # The rebuild adds a .rdata cell, which is the only input
            # totalFunctions reads. A stale hit keeps the old count.
            fresh = _write_doc(
                tmp_path,
                monkeypatch,
                "SD",
                {
                    ".text": {
                        "va": 4096,
                        "size": 16,
                        "fileOffset": 512,
                        "unitBytes": 16,
                        "columns": 8,
                        "cells": [cell(0, 16, "exact")],
                    },
                    ".rdata": {
                        "va": 8192,
                        "size": 48,
                        "fileOffset": 4096,
                        "unitBytes": 16,
                        "columns": 8,
                        "cells": [
                            cell(0, 16, "exact", functions=["r0"]),
                            cell(16, 32, "exact", functions=["r1"]),
                            cell(32, 48, "exact", functions=["r2"]),
                        ],
                    },
                },
            )
            _sections2, data2 = _load_section_data(fresh, snap=srv._snapshot_db_mtime())
            assert data2["summary"][".rdata"]["totalFunctions"] == 3, (
                "the memo served the previous build's cell count"
            )
            assert len(potato._SECTION_DATA_CACHE) == 2
        finally:
            potato.clear_cells_cache()

    def test_rebuild_mid_read_is_not_cached(self, tmp_path, monkeypatch) -> None:
        """A rebuild between the read and the publish must not be memoized.

        The same watermark contract as the grid memo, for the same reason: the
        broadcast that cleared the cache can be overtaken by an insert filed
        under the fingerprint that superseded the rows it holds.
        """
        import recoverage.potato as potato

        snap = self._snapshot(tmp_path, monkeypatch)
        monkeypatch.setattr(potato, "_snapshot_db_mtime", lambda: (2, 64))

        potato.clear_cells_cache()
        try:
            _sections, data = _load_section_data(snap, snap=(1, 64))
            assert data["summary"][".rdata"]["totalFunctions"] == 2
            assert not potato._SECTION_DATA_CACHE
        finally:
            potato.clear_cells_cache()

    def test_clear_cells_cache_drops_section_data_entries(self) -> None:
        import recoverage.potato as potato

        potato._SECTION_DATA_CACHE[(1, 64, "SD")] = ({}, {})  # type: ignore[assignment]
        potato.clear_cells_cache()
        assert not potato._SECTION_DATA_CACHE

    def test_unknown_section_yields_empty_cells(self, tmp_path, monkeypatch) -> None:
        import recoverage.potato as potato

        snap = self._snapshot(tmp_path, monkeypatch)
        potato.clear_cells_cache()
        try:
            cells, merged, _key = _load_grid_cells(snap, ".missing", 64, snap=_snapshot_db_mtime())
            assert cells == []
            assert merged == []
        finally:
            potato.clear_cells_cache()


class TestDbUnavailableContract:
    """A missing or unreadable coverage document must signal 503, not a 200 page."""

    @staticmethod
    def _point_at_empty_dir(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "db"
    ) -> Path:
        """Point the server at a coverage directory holding no readable document."""
        directory = tmp_path / name
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        return directory

    def test_render_potato_raises_503_without_db(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import bottle

        self._point_at_empty_dir(tmp_path, monkeypatch, "nope")
        with pytest.raises(bottle.HTTPResponse) as excinfo:
            render_potato_url("/potato")
        assert excinfo.value.status_code == 503
        assert "Database unavailable" in excinfo.value.body

    def test_potato_route_returns_503_when_db_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The render's coverage_for and the ETag's _snapshot_db_mtime both read
        # the directory _db_path resolves, so one override redirects both.
        self._point_at_empty_dir(tmp_path, monkeypatch, "nope")
        status, _, body = wsgi_get("/potato")
        assert status.startswith("503")
        assert b"Database unavailable" in body

    @pytest.mark.parametrize(
        "document",
        [
            # Malformed TOML: the file a half-written or torn rebuild leaves.
            'version = 1\ntarget = "BROKEN"\n[sections.text\n',
            # A version this reader does not know: a document from a newer (or
            # older, pre-migration) writer, whose layout it must not guess at.
            'version = 99\ntarget = "FUTURE"\n',
        ],
    )
    def test_unreadable_document_answers_503(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: str
    ) -> None:
        """A document that cannot be read must not render a 200 page.

        The SQLite equivalent opened the file and then failed every read, and
        the section-stats fallbacks caught every sqlite3.Error doing it — so a
        truncated database rendered a full page whose header reported no
        per-section stats, with nothing saying the store was unreadable.  A
        skipped document leaves the directory empty, and an empty directory is
        the 503 contract, not an empty dashboard.
        """
        directory = self._point_at_empty_dir(tmp_path, monkeypatch)
        directory.mkdir()
        (directory / "coverage-BROKEN.toml").write_text(document, encoding="utf-8")
        status, _, body = wsgi_get("/potato")
        assert status.startswith("503")
        assert b"Database unavailable" in body

    def test_the_coverage_read_warning_stays_one_log_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The "coverage unavailable" line must not be splittable by a document.

        It is the record of a 503, and it is what an operator reads to find the
        broken document: the directory comes from ``RECOVERAGE_DB`` or a
        project's ``db_dir``, and the cause quotes the file the reader rejected.
        Either can carry a line break, and a split here turns one outage into
        two entries, the second of which reads as an unrelated message.  The
        API's twin (``server._db_unavailable_err``) escapes both; this line
        claimed to mirror it and did not.
        """
        import bottle

        if path_the_filesystem_holds(tmp_path, "d\nb") is None:
            pytest.skip("the filesystem refuses a line break in a name")
        directory = self._point_at_empty_dir(tmp_path, monkeypatch, "d\nb")
        directory.mkdir()
        # A document whose target id (and so whose parse error) carries a break.
        (directory / "coverage-BR\nOKEN.toml").write_text("[sections.text\n", encoding="utf-8")

        with (
            caplog.at_level("WARNING", logger="recoverage"),
            pytest.raises(bottle.HTTPResponse) as excinfo,
        ):
            render_potato_url("/potato")
        assert excinfo.value.status_code == 503
        lines = [r for r in caplog.records if "coverage unavailable" in r.message]
        assert lines, [r.message for r in caplog.records]
        for record in lines:
            assert "\ndb" not in record.message
            assert "\nOKEN" not in record.message
            # The escaped form is still identifiable, which is the point.
            assert "\\x0a" in record.message

    def test_the_failure_lines_name_the_request_and_carry_its_fields(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A render failure is pivotable, like the API's.

        Potato answers a 503 (or a 500) to the one client that asked, so the
        log is the only record of it. A line reading "render failed" with no
        path and no fields cannot be matched to a /potato failure in a scan of
        the log, which is the same defect server._db_unavailable_err avoids by
        naming the request and carrying method/path/status as fields.
        """
        from rebrew.coverage_toml import CoverageTomlError

        from recoverage import potato as potato_mod

        def unreadable(url: Any) -> str:
            raise CoverageTomlError("synthetic unreadable document")

        monkeypatch.setattr(potato_mod, "render_potato", unreadable)
        with caplog.at_level("ERROR", logger="recoverage"):
            status, _, _ = wsgi_get("/potato?target=FAKEDLL")
        assert status.startswith("503")
        line = next(r for r in caplog.records if "coverage read failed" in r.message)
        assert "/potato" in line.message
        assert line.log_fields["method"] == "GET"
        assert line.log_fields["path"] == "/potato"
        assert line.log_fields["status"] == 503

        def broken(url: Any) -> str:
            raise ValueError("synthetic render failure")

        monkeypatch.setattr(potato_mod, "render_potato", broken)
        with caplog.at_level("ERROR", logger="recoverage"):
            status, _, _ = wsgi_get("/potato?target=FAKEDLL")
        assert status.startswith("500")
        line = next(r for r in caplog.records if "render failed" in r.message)
        assert line.log_fields["status"] == 500

    def test_verify_panel_attaches_the_snapshot_record(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A verify record rides on the snapshot; its absence omits the rows.

        The two answers used to be one `return` in a try/except around a query,
        so a document the server could not read rendered a panel that looked
        exactly like a function nobody had verified.  The unreadable case is the
        503 page now (``test_unreadable_document_answers_503``); this pins that a
        readable one still attaches what it holds.
        """
        from recoverage.potato import _panel_fn_attach_verify

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            verify_results=[
                {
                    "va": 0x1000,
                    "verified_at": "2026-01-01T00:00:00+00:00",
                    "byte_delta": 4,
                    "diff_lines": 1,
                    "similarity": 0.5,
                }
            ],
        )
        fn_data: dict[str, Any] = {"va": 0x1000}
        _panel_fn_attach_verify(snap, fn_data)
        assert fn_data["last_verify_similarity"] == "50.0%"
        assert fn_data["last_verify_delta"] == "4B"

        absent: dict[str, Any] = {"va": 0x2000}
        _panel_fn_attach_verify(snap, absent)
        assert "last_verify_similarity" not in absent

    @pytest.mark.parametrize("value", ["0.5", True, [0.5]])
    def test_a_similarity_this_panel_cannot_scale_is_omitted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: Any
    ) -> None:
        """A non-numeric similarity omits the row instead of failing the panel.

        The scaling is a multiplication and a ``:.1f`` on the value, so a
        document carrying a string made the first a hundred-fold repetition of
        it and the second a ValueError that escaped as a 500: one bad cell in
        one verify row cost the reader the whole function.  A bool is the quieter
        version of the same hole (``True * 100`` is 100, so it rendered as a
        real 100.0% match), and it is why the test is not a bool-free one.  The
        functions view already guards the same field this way; both do now.
        """
        from recoverage.potato import _panel_fn_attach_verify

        snap = _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}},
            verify_results=[{"va": 0x1000, "similarity": value}],
        )
        fn_data: dict[str, Any] = {"va": 0x1000}
        _panel_fn_attach_verify(snap, fn_data)
        assert "last_verify_similarity" not in fn_data


class TestDefaultTargetMatchesSpa:
    """Potato and the SPA must open on the same target.

    Both render the list resolve_targets returns and default to its first
    entry; a project whose config order differs from its metadata order must
    not open the two surfaces on different targets — and the default must be
    chosen BEFORE the snapshot is loaded, or the page renders the empty
    document for the empty target name (a "no data" page on a project with
    data) while the target list already names the right one.
    """

    def test_potato_defaults_to_first_listed_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.potato as potato_mod

        targets = [{"id": "CONFIG_FIRST", "name": "a"}, {"id": "FROM_DB_FIRST", "name": "b"}]
        monkeypatch.setattr(potato_mod, "resolve_targets", lambda: targets)

        chosen: list[str] = []
        real_coverage_for = potato_mod.coverage_for

        def _recording_coverage_for(target: str) -> CoverageSnapshot:
            chosen.append(target)
            # The never-built target's empty snapshot short-circuits the render
            # on its "no data" page right after the choice this test is about.
            return real_coverage_for(target)

        monkeypatch.setattr(potato_mod, "coverage_for", _recording_coverage_for)
        potato_mod.render_potato(urlparse("/potato"))

        # /api/targets serves `targets`, and the SPA picks entry [0] from it.
        assert chosen == [targets[0]["id"]]


class TestCellStateVocabularyCoverage:
    """Every state rebrew can write to cells.state has a Potato colour.

    A missing key made the grid fall back to COLORS["none"], so a cell the
    pipeline could not classify rendered as an undocumented gap. That is a
    data-fidelity bug, not cosmetics: /stats reports covered_bytes over
    "state != 'none'" and folds 'verified' into exact_count, so those cells
    were counted as covered while drawn as holes.
    """

    def test_every_known_cell_state_has_a_color(self) -> None:

        from recoverage.potato import COLORS

        missing = sorted(known_cell_states() - set(COLORS))
        assert missing == [], f"cell states with no color (render as undocumented): {missing}"

    def test_verified_renders_as_a_match_not_a_gap(self) -> None:
        """build_db counts 'verified' as exact; it must not read as 'none'."""
        from recoverage.potato import COLORS

        assert COLORS["verified"] == COLORS["exact"]
        assert COLORS["verified"] != COLORS["none"]

    def test_problem_states_are_distinguishable_from_none(self) -> None:
        from recoverage.potato import COLORS

        for state in ("compile_error", "extract_error", "invalid_va", "skip"):
            assert COLORS[state] != COLORS["none"], state

    def test_legend_names_the_problem_group(self) -> None:
        """A state nobody can identify is the defect this class started from."""
        from recoverage.potato import COLORS, LEGEND_ITEMS

        keys = [k for k, _ in LEGEND_ITEMS]
        assert "compile_error" in keys
        # No legend row may point at a colour the map cannot paint.
        assert set(keys) <= set(COLORS)

    def test_design_doc_names_every_state_it_lists(self) -> None:
        """The DESIGN.md colour table copies COLORS; keep it from going short."""
        from recoverage.potato import COLORS

        root = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
        design = (root / "docs" / "DESIGN.md").read_text(encoding="utf-8")
        table = design.split("## Color Scheme & Styling")[1].split("\n## ")[0]
        unnamed = sorted(state for state in COLORS if state not in table)
        assert unnamed == [], f"DESIGN.md colour table does not name: {unnamed}"


class TestFilterKeysCoverTheLegend:
    """Every status the legend prints can be filtered down to.

    A state the grid paints and the legend names but no filter isolates is
    reachable only by reading pixels: the operator looking for the cells the
    build failed on had no control to narrow the map with, and every pill
    they pressed dimmed those cells along with everything else.
    """

    # data and thunk are excluded: the SPA greys them into the undocumented
    # row and Potato keeps the colour, so neither renderer offers a filter
    # for them and the two agree.  none is excluded because a status filter
    # never dims it; it is the ground the statuses are read against.
    UNFILTERED = frozenset({"data", "thunk", "none"})

    def test_every_legend_state_survives_its_filter(self) -> None:
        from recoverage.potato import FILTER_STATES, LEGEND_ITEMS

        keys = {k for k, _ in LEGEND_ITEMS} - self.UNFILTERED
        unreachable = sorted(
            key for key in keys if not any(key in states for states in FILTER_STATES.values())
        )
        assert unreachable == [], f"legend states no filter keeps lit: {unreachable}"

    def test_legacy_spellings_survive_the_filter_they_render_as(self) -> None:
        """The SPA packs these onto the exact and near-match cell states."""
        from recoverage.potato import _state_survives_filter

        assert _state_survives_filter("verified", {"exact"})
        assert _state_survives_filter("near_matching", {"near_match"})
        assert _state_survives_filter("size_mismatch", {"near_match"})

    def test_every_problem_state_survives_the_problem_filter(self) -> None:
        from recoverage.potato import COLORS, _state_survives_filter

        problems = [s for s, color in COLORS.items() if color == COLORS["compile_error"]]
        assert len(problems) > 1
        for state in problems:
            assert _state_survives_filter(state, {"problem"}), state
        # And they are the only thing it keeps: the point of the filter is
        # finding the failures, not a second way to read the whole map.
        assert not _state_survives_filter("exact", {"problem"})

    def test_undocumented_cells_are_never_dimmed_by_a_status_filter(self) -> None:
        from recoverage.potato import FILTER_STATES, _state_survives_filter

        for key in FILTER_STATES:
            assert _state_survives_filter("none", {key}), key

    def test_unknown_filter_name_is_dropped(self) -> None:
        from recoverage.potato import _parse_filters, _state_survives_filter

        # It matches no cell state, so honouring it would dim every painted
        # cell and light no pill.
        assert _parse_filters("bogus") == set()
        assert _parse_filters("exact,bogus") == {"exact"}
        assert _state_survives_filter("exact", _parse_filters("bogus"))

    def test_the_per_page_lit_set_answers_what_the_per_cell_test_answers(self) -> None:
        """The grid resolves the filter union once; it must not drift from the
        per-cell form, which the SPA parity tests read as the spec."""
        from recoverage.potato import COLORS, _lit_states, _state_survives_filter

        for active in ({}, {"exact"}, {"problem"}, {"exact", "near_match"}, {"stub"}):
            lit = _lit_states(active)
            for state in COLORS:
                expected = _state_survives_filter(state, active)
                actual = True if lit is None else state == "none" or state in lit
                assert actual is expected, (state, active)

    def test_every_filter_key_has_a_pill_with_a_title(self) -> None:
        from recoverage.potato import FILTER_STATES, _build_filter_data

        pills = _build_filter_data("SERVER", ".text", set(), "", {"s"})
        assert len(pills) == len(FILTER_STATES) + 1  # plus "All"
        keys = {key for _, _, _, _, key, _, _ in pills}
        assert keys - {"0"} == set(FILTER_STATES)
        for href, label, _color, _active, _key, title, _acc in pills:
            assert title, f"pill {label} has no title to explain the letter"
            assert href.startswith("?")

    def test_pill_toggles_only_its_own_filter(self) -> None:
        from recoverage.potato import _build_filter_data

        pills = {
            key: href
            for href, _, _, _, key, _, _ in _build_filter_data("S", ".text", {"reloc"}, "", {"s"})
        }
        # Turning one on keeps the others; turning the active one off clears it,
        # which leaves no filter= at all rather than an empty one, so the link
        # is the "All" pill's and carries no other filter.
        assert "filter=exact%2Creloc" in pills["exact"]
        # Toggling the active filter off leaves an empty set, and _build_url
        # omits the parameter for an empty one: the "reloc" pill is the "All"
        # link with the same target, so the assertion is the ABSENCE of a
        # filter, not a filter that still names reloc.
        assert "filter=" not in pills["reloc"]
        assert pills["reloc"] == "?target=S&section=.text"
        assert pills["reloc"] == pills["0"]
        assert "exact" not in pills["reloc"]


def _dark_token(name: str) -> str:
    """The dark half of ``--color-<name>`` in the relumea token file.

    Potato Mode is a dark page that cannot read CSS variables, so it spells the
    dark values of the tokens the SPA reads. Every token is declared once as
    ``light-dark(<light>, <dark>)``; this returns ``<dark>``, lowercased.
    """
    tokens = (
        Path(__file__).resolve().parents[1] / "web" / "app" / "system" / "tokens.css"
    ).read_text(encoding="utf-8")
    match = re.search(
        rf"--color-{re.escape(name)}:\s*light-dark\(\s*(#[0-9a-fA-F]{{6}}),\s*(#[0-9a-fA-F]{{6}})\s*\);",
        tokens,
    )
    assert match is not None, f"tokens.css declares no --color-{name}"
    return match.group(2).lower()


class TestSectionAccentsMatchSpa:
    """The pane headings wear the muted ink in both renderers.

    The SPA titles each pane with an icon in `text-muted` (the brand has one
    accent, so a pane kind is no longer a hue). Potato Mode has no CSS and
    spells the value as module constants; a pane heading in a hue of its own
    in one renderer is drift a screenshot would not catch.
    """

    PANE_ACCENTS = ("ACCENT_C_SOURCE", "ACCENT_ASM", "ACCENT_DATA", "ACCENT_BYTES")

    @pytest.mark.parametrize("constant", PANE_ACCENTS)
    def test_pane_accent_is_the_muted_ink(self, constant: str) -> None:
        from recoverage import potato

        assert getattr(potato, constant).lower() == _dark_token("text-muted")

    def test_every_accent_the_renderers_use_is_pinned(self) -> None:
        """A new pane kind must be added to PANE_ACCENTS, not left unpinned."""
        from recoverage import potato

        declared = {
            name
            for name, value in vars(potato).items()
            if name.startswith("ACCENT_") and isinstance(value, str)
        }
        # ACCENT_COLOR is the brand accent, not a pane accent.
        assert declared - {"ACCENT_COLOR"} == set(self.PANE_ACCENTS)

    @pytest.mark.parametrize(
        ("constant", "token"),
        [
            ("BG_COLOR", "bg"),
            ("PANEL_COLOR", "surface"),
            ("RAISED_COLOR", "raised"),
            ("TRACK_COLOR", "surface-3"),
            ("CODE_BG_COLOR", "code"),
            ("BORDER_COLOR", "border"),
            ("TEXT_COLOR", "text"),
            ("MUTED_COLOR", "text-muted"),
            ("ACCENT_COLOR", "accent"),
        ],
    )
    def test_page_colours_are_the_dark_tokens(self, constant: str, token: str) -> None:
        from recoverage import potato

        assert getattr(potato, constant).lower() == _dark_token(token)

    @pytest.mark.parametrize(
        ("state", "fill", "word"),
        [
            ("exact", "cell-exact", "st-exact"),
            ("reloc", "cell-reloc", "st-reloc"),
            ("near_match", "cell-near", "st-near"),
            ("proven", "cell-proven", "st-proven"),
            ("stub", "cell-stub", "st-stub"),
            ("thunk", "cell-thunk", "st-thunk"),
            ("data", "cell-live", "st-live"),
            ("none", "cell-unlit", "text-muted"),
            ("padding", "border-strong", "text-muted"),
            ("compile_error", "cell-fail", "st-fail"),
        ],
    )
    def test_state_fill_and_word_are_the_dark_tokens(
        self, state: str, fill: str, word: str
    ) -> None:
        """A cell takes the fill, a printed state takes the word: the fills
        are graphics and do not clear 4.5:1 as text on the dark grounds."""
        from recoverage import potato

        assert potato.COLORS[state].lower() == _dark_token(fill)
        assert potato.STATE_INK[state].lower() == _dark_token(word)

    def test_every_state_has_a_word_colour(self) -> None:
        from recoverage import potato

        assert set(potato.STATE_INK) == set(potato.COLORS)


class TestPageIdentityMatchesTheSpa:
    """The two renderers are one product and carry one mark.

    The SPA serves the relumea mark as ``assets/favicon.svg`` and draws it
    again in its topbar; Potato Mode embeds the same file as ``R_LOGO_SVG``
    for its tab icon, and draws the mark in its dark-ground colours as
    ``MARK_ON_DARK_SVG`` in its topbar. An unrelated glyph on the Potato tab
    strip meant the same product wore a different icon depending on which view
    a browser tab was showing, and nothing caught it because both pages
    rendered.
    """

    def test_a_pane_heading_carries_the_mark_and_not_a_generated_badge(self) -> None:
        """No initials avatar where the logo belongs.

        A pane heading drew a hexagon holding a caller-chosen label (``01``,
        ``C``, ``ASM``), which is the placeholder-avatar pattern: a generated
        tile standing in for a mark nobody bothered to draw, and the same
        ``01`` on two unrelated panes. The page already carries the real mark
        in its topbar and its tab icon, so a second invented one contradicted
        both. The mark is the product's subject, so it is what a heading
        carries now, on every pane.
        """
        from recoverage import potato

        heading = potato._section_heading("01", potato.ACCENT_BYTES, "Original Bytes")
        assert "polygon" not in heading, "a pane heading drew a generated hexagon again"
        assert "<text" not in heading, "a pane heading drew an initials badge again"
        assert "<img" in heading

        for label, color, title in (
            ("01", potato.ACCENT_BYTES, "Original Bytes"),
            ("C", potato.ACCENT_C_SOURCE, "C Source (server.c)"),
            ("ASM", potato.ACCENT_ASM, "Assembly"),
            ("{}", potato.ACCENT_DATA, "Data Inspector"),
        ):
            # The mark this page already draws, not a fourth spelling of it.
            assert potato.MARK_ON_DARK_SVG in potato._section_heading(label, color, title)

    def test_a_pane_heading_marks_itself_decoratively(self) -> None:
        """The mark beside a heading carries no name of its own.

        The icon is aria-hidden and every cell of it is a colour square, so a
        screen reader announcing "Data Inspector mark" before the heading
        reads a decoration aloud. An empty alt is the whole reason.
        """
        from recoverage import potato

        heading = potato._section_heading("01", potato.ACCENT_BYTES, "Original Bytes")
        assert 'alt=""' in heading
        assert "Original Bytes" in heading

    def test_no_generated_hex_avatar_is_left_to_be_drawn(self) -> None:
        """The generator itself, not just one call site.

        The four call sites each spelled their own label, so a rule held on
        one heading would leave the others free; the hexagon has to be gone
        from the module.
        """
        from recoverage import potato

        source = Path(potato.__file__).read_text(encoding="utf-8")
        assert "_hex_logo_svg" not in source, "the generated hex avatar is back"
        assert "polygon points=" not in source, "a hexagon is drawn again"

    def test_the_topbar_mark_is_the_same_nine_cells(self) -> None:
        """The dark-ground mark is the favicon's geometry, not a lookalike."""
        from recoverage import potato

        root = Path(__file__).resolve().parents[1]
        favicon = (root / "src" / "recoverage" / "assets" / "favicon.svg").read_text(
            encoding="utf-8"
        )
        mark = base64.b64decode(potato.MARK_ON_DARK_SVG.split(",", 1)[1]).decode("utf-8")
        cells = re.compile(r"""x=['"]([\d.]+)['"] y=['"]([\d.]+)['"]""")
        assert sorted(cells.findall(mark)) == sorted(cells.findall(favicon))
        assert potato.ACCENT_COLOR in mark

    def test_potato_tab_icon_is_the_shared_logo(self) -> None:
        from recoverage import potato

        assert '<link rel="icon" href="{{R_LOGO_SVG}}">' in potato._PAGE_SRC
        assert "data:image/svg+xml,%3Csvg" not in potato._PAGE_SRC

    def test_the_shared_logo_is_the_spa_favicon(self) -> None:
        """R_LOGO_SVG is the same drawing, not a lookalike."""
        from recoverage import potato

        root = Path(__file__).resolve().parents[1]
        favicon = (root / "src" / "recoverage" / "assets" / "favicon.svg").read_text(
            encoding="utf-8"
        )
        encoded = base64.b64decode(potato.R_LOGO_SVG.split(",", 1)[1]).decode("utf-8")
        # The SPA's shell is the one that names the file; the two drawings are
        # compared by their canonical form, not by byte layout. The data URI
        # spells its attributes with single quotes, the file with double.
        # A lambda, not a def: it is used on the two lines below and nowhere
        # else, and a named local for a one-call helper reads as scope.
        canonical = lambda text: re.sub(r"""[\s'"]""", "", text)  # noqa: E731
        assert canonical(encoded) == canonical(favicon)


class TestCodePaneColorsMatchTheSpa:
    """A code pane is one pane, and both renderers paint it one way.

    Both read the shared listing palette (`syn-*` in the relumea tokens): the
    SPA's highlight.js rules through `var(--color-syn-*)`, Potato Mode's
    Pygments map through these constants, which spell the dark values.
    """

    PAIRS = (
        ("syn-register", "HLJS_SYMBOL"),
        ("syn-string", "HLJS_STRING"),
        ("syn-call", "HLJS_TITLE"),
        ("syn-type", "HLJS_SECTION"),
        ("text", "HLJS_NAME"),
        ("syn-comment", "HLJS_COMMENT"),
        ("syn-keyword", "HLJS_KEYWORD"),
        ("syn-type", "HLJS_ATTR"),
    )

    @pytest.mark.parametrize(("token", "constant"), PAIRS)
    def test_spa_token_matches_potato_constant(self, token: str, constant: str) -> None:
        from recoverage import potato

        assert _dark_token(token) == getattr(potato, constant).lower()

    @pytest.mark.parametrize("token", sorted({token for token, _ in PAIRS} - {"text"}))
    def test_the_spa_highlight_rules_read_the_same_token(self, token: str) -> None:
        css = (Path(__file__).resolve().parents[1] / "web" / "app" / "index.css").read_text(
            encoding="utf-8"
        )
        assert f"var(--color-{token})" in css

    def test_the_pygments_map_holds_no_unpinned_hue(self) -> None:
        """Every colour the lexer map reaches is one of the pinned tokens.

        The map is what actually paints, so a hex added to it and not to PAIRS
        is the drift this class exists to catch, whatever it is named.
        """
        from recoverage import potato

        pg = potato._pygments()
        assert pg is not None
        _, c_colors, _, asm_colors = pg
        pinned = {getattr(potato, name).lower() for _, name in self.PAIRS}
        pinned |= {potato.TEXT_COLOR.lower(), potato.MUTED_COLOR.lower()}
        for colors in (c_colors, asm_colors):
            assert {value.lower() for value in colors.values()} <= pinned

    def test_the_hex_dump_reads_the_same_palette(self) -> None:
        """The dump draws its filler and its printable ASCII by name.

        The coloring is ``_highlight_hex`` over the shared plain dump, and the
        dump carried two stock hexes beside the gray filler, so this drives the
        colored form the panel actually renders rather than the raw rows.
        """
        from recoverage import potato

        raw = potato._format_hex_dump(b"\x00\x41\xff", 0x1000)
        dump = potato._highlight_hex(raw)
        assert "#858585" not in dump
        assert "#4ec9b0" not in dump
        assert "#6a9955" not in dump
        assert potato.MUTED_COLOR in dump
        assert potato.HLJS_NAME in dump


class TestSelectionIsOneControlState:
    """A pressed control looks the same in both renderers.

    The SPA's pressed button is `bg-surface-3` inside `border-control-line-hover`
    (`web/app/components/ui/button.tsx`); Potato Mode's active pill images
    draw the dark values of the same two tokens, and its resting pills the
    3:1 control edge a control is told apart by.
    """

    def test_the_spa_pressed_variant_names_the_two_tokens(self) -> None:
        button = (
            Path(__file__).resolve().parents[1] / "web" / "app" / "components" / "ui" / "button.tsx"
        ).read_text(encoding="utf-8")
        active = re.search(r'active:\s*"([^"]+)"', button)
        assert active is not None
        assert {"bg-surface-3", "border-control-line-hover"} <= set(active.group(1).split())

    @pytest.mark.parametrize(
        ("names", "fill", "edge"),
        [
            (("ACTIVE_L", "ACTIVE_R", "ACTIVE_MID"), "surface-3", "control-line-hover"),
            (("INACTIVE_L", "INACTIVE_R", "INACTIVE_MID"), "surface", "control-line"),
        ],
    )
    def test_potato_pills_draw_the_same_tokens(
        self, names: tuple[str, ...], fill: str, edge: str
    ) -> None:
        from recoverage import potato

        for name in names:
            svg = base64.b64decode(getattr(potato, name).split(",", 1)[1]).decode("utf-8")
            assert _dark_token(fill) in svg.lower(), name
            assert _dark_token(edge) in svg.lower(), name


class TestRenderIsPinnedToOneSnapshot:
    """A Potato page is built from one frozen CoverageSnapshot.

    ``render_potato`` loads the snapshot once and hands it to every reader —
    sections, cells, functions, globals and (for the detail panels)
    verify_results — and the grid is the most expensive render in the package,
    so a ``rebrew coverage build`` committing midway is a real window.  The
    snapshot's immutability is what the SQLite read transaction used to buy:
    the page cannot pair one build's section rows with the next build's cells,
    which would be a grid whose coverage legend disagrees with its own bytes.
    Same contract /data, /stats and the function list already follow.
    """

    def test_the_render_cannot_see_a_rebuild_committed_mid_page(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recoverage import potato

        target = "SPLIT_POTATO"

        def _doc(state: str, size: int, end: int) -> None:
            write_coverage(
                coverage_dir(tmp_path),
                target,
                {
                    ".text": {
                        "size": size,
                        "columns": 8,
                        "cells": [cell(0, end, state)],
                    }
                },
            )

        monkeypatch.setenv("RECOVERAGE_DB", str(coverage_dir(tmp_path)))
        _doc("exact", 16, 16)

        # One snapshot per render: the target is resolved once and the document
        # is read once, not re-read per section or per panel.
        loaded: list[str] = []
        real_coverage_for = potato.coverage_for

        def _counted_coverage_for(name: str) -> CoverageSnapshot:
            loaded.append(name)
            return real_coverage_for(name)

        # The rebuild lands mid-render: _search_functions runs after the
        # snapshot was loaded and before the grid and panel are built.
        rewritten: list[bool] = []
        real_search = potato._search_functions

        def _rewrite_then_search(coverage: CoverageSnapshot, query: str) -> set[str]:
            _doc("stub", 32, 32)
            rewritten.append(True)
            return real_search(coverage, query)

        monkeypatch.setattr(potato, "coverage_for", _counted_coverage_for)
        monkeypatch.setattr(potato, "_search_functions", _rewrite_then_search)

        html = render_potato_url(f"/potato?target={target}&section=.text")
        assert rewritten, "the mid-render rewrite never ran"
        assert loaded == [target], "the render loaded the documents more than once"
        assert "0x0..0x10 | exact" in html, "the page paired the second build's cells"
        assert "0x0..0x20 | stub" not in html

        # And the rewrite was a real rebuild: the next render reads it.
        monkeypatch.setattr(potato, "_search_functions", real_search)
        after = render_potato_url(f"/potato?target={target}&section=.text")
        assert "0x0..0x20 | stub" in after, "the mid-render rewrite was not a real rebuild"

    @pytest.mark.skipif(not HAS_DB, reason="No coverage document")
    def test_rebuild_after_the_token_is_taken_is_not_memoized(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebuild committing after the render pinned its token caches nothing.

        The token is stat'ed BEFORE the snapshot is loaded, so the first read is
        the one the render pinned against and every later read sees the
        post-rebuild fingerprint.  A memo that took its own stat would read that
        same post-rebuild value on both sides of its publish comparison, match,
        and file cells from the previous build under the fingerprint that
        supersedes them — a grid every later request is served stale from, with
        no rebuild left to invalidate it.
        """
        from recoverage import potato

        target = require_target()

        # Call 1: the render's token, before it loads the snapshot.  Every call
        # after it sees a `rebrew coverage build` that committed mid-render.
        tokens = iter([(1, 64), *[(2, 64)] * 64])
        monkeypatch.setattr(potato, "_snapshot_db_mtime", lambda: next(tokens))

        potato.clear_cells_cache()
        try:
            html = render_potato_url(f"/potato?target={target}&section=.text")
            # A non-empty page is not a correct one: a grid built from the
            # pre-rebuild rows serves this request happily. The fixture's
            # first .text cell is the thing that distinguishes them.
            assert "0x10001000.." in html, "the page came back without the section's cells"
            assert not potato._GRID_CACHE, "cells from before the rebuild were memoized"
            assert not potato._POTATO_STATS_CACHE, "stats from before the rebuild were memoized"
        finally:
            potato.clear_cells_cache()


class TestRenderedPageNamesAndStates:
    """What the rendered page tells a screen reader, not just what it paints.

    Every one of these controls draws its state (the active image pair, the
    bold label, the on-color), so a sighted reader sees the current section and
    the current filter while assistive technology is told neither. The names
    and the current-state attributes are what close that gap (WCAG 4.1.2,
    2.4.4).
    """

    def _render(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str) -> str:
        import recoverage.potato as potato_mod

        _write_doc(
            tmp_path,
            monkeypatch,
            "T",
            {".text": {"size": 32, "va": 0x1000, "cells": [cell(0, 32, "exact")]}},
            functions=[{"va": 0x1000, "name": "sub_401000", "vaStart": "0x1000", "size": 32}],
        )
        monkeypatch.setattr(potato_mod, "resolve_targets", lambda: [{"id": "T", "name": "a"}])
        return render_potato_url(f"/potato?target=T&section=.text{query}")

    def test_every_filter_link_names_its_filter_and_its_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        html = self._render(tmp_path, monkeypatch, "&filter=exact")
        assert 'aria-label="Exact match, on"' in html
        assert 'aria-label="Stub, off"' in html
        # Exactly one pill is current: the one the query selected.
        assert html.count('aria-current="true"') == 1

    def test_no_filter_current_without_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        html = self._render(tmp_path, monkeypatch, "")
        assert 'aria-current="true"' in html  # the "All" pill
        assert 'aria-label="Show all statuses, on"' in html

    def test_active_section_tab_is_marked_current(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        html = self._render(tmp_path, monkeypatch, "")
        assert html.count('aria-current="page"') == 1

    def test_function_list_headers_scope_their_column(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        html = self._render(tmp_path, monkeypatch, "&view=functions")
        assert html.count('<th scope="col">') >= 5

    def test_only_the_tables_that_carry_data_keep_the_table_role(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Layout is presented as structure otherwise (WCAG 1.3.1).

        The page is nested layout tables, and a screen reader in table mode is
        read twenty wrappers instead of the coverage map. The grid container
        (its caption names the skip-link target) and the function list (its
        headers relate its columns) are the two tables that carry meaning, and
        they are the two that keep the role.
        """
        grid = self._render(tmp_path, monkeypatch, "")
        functions = self._render(tmp_path, monkeypatch, "&view=functions")
        assert re.findall(r"<table(?![^>]*role=)[^>]*>", grid) == [
            (
                '<table id="grid-container" border="1" cellpadding="8" cellspacing="0" '
                f'bordercolor="{BORDER_COLOR}" bgcolor="{BG_COLOR}" width="100%">'
            ),
        ]
        assert re.findall(r"<table(?![^>]*role=)[^>]*>", functions) == [
            (
                '<table width="100%" border="1" cellpadding="6" cellspacing="0" '
                f'bordercolor="{BORDER_COLOR}">'
            ),
        ]

    def test_the_lattice_is_not_announced_as_a_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The grid is a picture of a byte range, not rows and columns."""
        html = self._render(tmp_path, monkeypatch, "")
        assert '<table id="grid" role="presentation"' in html

    def test_grid_caption_names_the_keyboard_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every block is a real link, so Enter works; the caption said click."""
        html = self._render(tmp_path, monkeypatch, "")
        assert "press Enter" in html

    def test_page_declares_its_language(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """A wrong voice on every control: no lang means no speech synthesiser."""
        html = self._render(tmp_path, monkeypatch, "")
        assert '<html lang="en">' in html

    @pytest.mark.parametrize(
        ("document", "heading"),
        [
            (_RENDER_ERROR_BODY, "Internal server error"),
            (_db_unavailable_page().body, "Database unavailable"),
        ],
    )
    def test_every_page_this_route_answers_carries_the_same_structure(
        self, document: object, heading: str
    ) -> None:
        """The fallback pages, not only the 200 one.

        The gate in ``tools/lint_html.py`` fetches ``/potato`` and validates
        what came back, so every page the route answers on an error reached a
        browser and no reader's assistive technology untested. The 500 arm was
        a bare ``<html><body>Internal server error</body></html>``: no language
        (WCAG 3.1.1), no title (2.4.2), no heading and no landmark (1.3.1), and
        a document vnu rejects outright.

        The landmark is ``<body role="main">`` rather than a ``<main>``
        element: the retro centring table holds this content in a ``<td>``,
        where ``<main>`` is invalid, and that table is what every page on this
        route but the served one stands inside.
        """
        body = document if isinstance(document, str) else bytes(document).decode("utf-8")
        assert body.startswith("<!DOCTYPE html>")
        assert '<html lang="en">' in body
        assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in body
        assert "<title>recoverage · " in body
        # A `<main>` landmark, and NOT the retro centring table: ARIA in HTML
        # forbids `<main>` as a descendant of a `<td>` at any depth, and
        # `role="main"` on the `<body>` is rejected the same way, so a page
        # laid out in a table has no way to carry one.
        assert "<body><main>" in body
        assert "<table" not in body
        assert "<font" not in body
        assert "<h1>" in body
        assert f"<h1>{heading}</h1>" in body
        # Nothing here may leak a detail the log line owns.
        assert "Traceback" not in body

    def test_the_no_data_page_carries_the_same_structure(self) -> None:
        """The empty-target arm is a document too, not a bare paragraph."""
        html = render_potato_url("/potato?target=NONEXISTENT")
        assert '<html lang="en">' in html
        assert "<body><main>" in html
        assert "<table" not in html
        assert "<font" not in html
        assert "No data for target NONEXISTENT" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
class TestCellStateSpellingInTheDetailPanel:
    """The panel and the list must colour one value the same way.

    ``cell.state`` is free text in the document (rebrew writes the canonical
    lowercase vocabulary, nothing validates a hand-edited or older document),
    and the function list already folded it: ``COLORS.get(st.lower(), ...)``.
    The detail panel looked the same value up unfolded, so a cell spelled
    ``Exact`` was drawn in the exact-match colour in the grid and in the
    default text colour in the panel opened from it.
    """

    def test_a_mixed_case_state_keeps_its_colour_in_the_panel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recoverage.potato import STATE_INK

        _write_doc(
            tmp_path,
            monkeypatch,
            "MIXED",
            {
                ".text": {
                    "va": 0x1000,
                    "size": 0x10,
                    "fileOffset": 0x200,
                    "unitBytes": 16,
                    "columns": 1,
                    "cells": [cell(0x1000, 0x1010, "Exact")],
                }
            },
        )
        html = render_potato_url("/potato?target=MIXED&section=.text&idx=0")
        assert f'color="{STATE_INK["exact"]}"><b>EXACT</b>' in html
