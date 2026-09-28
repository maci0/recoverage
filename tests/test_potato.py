import base64
import functools
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import quote, urlparse

import pytest
from conftest import HAS_DB, get_first_target, wsgi_get
from coverage_fixture import cell, write_coverage
from rebrew.coverage_toml import CoverageSnapshot, load_coverage

from recoverage.potato import (
    TRACK_UNITS,
    _build_progress,
    _build_url,
    _cell_file_offset,
    _compute_section_stats,
    _db_updated_label,
    _esc,
    _extract_annotations,
    _format_data_inspector,
    _format_hex_dump,
    _format_va,
    _is_plain_relative,
    _load_grid_cells,
    _panel_fn_source_text,
    _progress_svg,
    _render_original_bytes,
    _section_heading,
    _section_tab_data,
    _wrap_text,
    render_potato,
)
from recoverage.server import _snapshot_db_mtime


def render_potato_url(url: str) -> str:
    return render_potato(urlparse(url))


# ── Test-local coverage documents ──────────────────────────────────
#
# The suite used to build a throwaway SQLite database per fixture.  The
# dashboard reads rebrew's clear-text coverage documents now, so a fixture is a
# document written with coverage_fixture.write_coverage plus the one environment
# variable that points the server at it.


def _coverage_dir(root: Path) -> Path:
    """The coverage directory a test-local fixture lives in.

    Spelled ``db`` beneath *root* on purpose: ``RECOVERAGE_DB`` names the
    directory itself, while rebrew's reader takes the project ROOT and resolves
    the configured ``db_dir`` (``<root>/db`` by default) beneath it, so the two
    only agree on the same directory when it is named this way.
    """
    return root / "db"


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
    directory = _coverage_dir(root)
    write_coverage(directory, target, sections, **kwargs)
    monkeypatch.setenv("RECOVERAGE_DB", str(directory))
    return load_coverage(root, target)


def _shared_snapshot() -> CoverageSnapshot:
    """The first target of the shared synthetic documents conftest writes.

    Reads the ambient ``<cwd>/db`` the way the server does, so a
    ``HAS_DB``-gated assertion exercises the same document the render does.
    """
    target = get_first_target()
    if not target:
        pytest.skip("No targets in DB")
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
    from recoverage.potato import _load_section_data, _render_grid_view

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
    sections, data = _load_section_data(snap)
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
        assert line.startswith(f'<font color="#858585">{offset}</font>'), (
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
        # falls back to for a section that states none.
        grid_columns = int(snap.sections[sec].columns) or 64

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
    ("/potato?search=alloc", "search alloc", ("Searching: ", "(0 matches)", "no matches"), ()),
    ("/potato?search=0x1000", "search VA prefix", ("Searching: ",), ()),
    ("/potato?search=g_ServerConfig", "global search", ("Searching: ",), ()),
    ("/potato?search=nonexistent_xyz", "search no results", ("(0 matches)", "no matches"), ()),
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
        ("Searching: ", "&lt;script&gt;alert(1)&lt;/script&gt;"),
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
    target = get_first_target()
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
    target = get_first_target()
    html = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&search=zzz_no_such_function"
    )
    assert "No functions match" in html
    assert "zzz_no_such_function" in html
    assert "[Clear search]" in html
    # The clear link keeps the view and the status filter, and drops the query.
    assert f'href="?target={quote(target)}&section=.text&view=functions"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_no_match_status_filter_offers_a_way_back():
    target = get_first_target()
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
    target = get_first_target()
    if not target:
        pytest.skip("No targets in DB")
    hint = "no matches. Check the spelling, or search by VA."
    empty = render_potato_url(f"/potato?target={target}&search=zzz_no_such_function")
    assert hint in empty
    assert "(0 matches)" in empty
    hit = render_potato_url(f"/potato?target={target}&search=_func_a")
    assert hint not in hit


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
    from conftest import get_first_target

    target = get_first_target()
    if not target:
        pytest.skip("No targets in DB")
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
    target = get_first_target()

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
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions&status=STUB")
    assert "_func_c" in html
    assert "_func_a" not in html
    assert "_func_b" not in html
    assert "No functions found." not in html
    assert "(1 results)" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_function_list_reports_the_row_cap(monkeypatch):
    # The list is capped so a large target's page stays a sane size. A header
    # reading the capped length as the total tells the reader the page is the
    # whole result set, and the rows they cannot see are unreachable.
    import recoverage.potato as potato_module

    monkeypatch.setattr(potato_module, "_SEARCH_ROW_LIMIT", 1)
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions")
    found = re.search(r"\(first 1 of (\d+) results\)", html)
    assert found is not None, html[:400]
    assert int(found.group(1)) > 1
    assert "capped at 1 rows" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_prev_next_navigation():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&idx=5")
    assert "#sel" in html
    assert "Prev" in html
    assert "Next" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_skip_link():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'href="#grid-container"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_accesskey_attributes():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    # Search input accesskey + per-section tabs (accesskey = 2nd char of the
    # section name: .text -> "t", .data -> "d").
    assert 'accesskey="s"' in html
    assert 'accesskey="t"' in html  # .text tab
    assert 'accesskey="d"' in html  # .data tab


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_functions_nav_link_is_url_quoted():
    # The header [Functions] href is percent-encoded, so a target or section
    # holding "&" cannot append query parameters to it.  Every other href on
    # the page is built by _build_url, which does the same.
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text")
    assert f'href="?target={target}&amp;section=.text&amp;view=functions"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_clickable_asm_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    from recoverage import potato as _potato

    target = get_first_target()
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
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'href="/"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_footer_db_date():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    assert "DB updated" in html
    assert "recoverage" in html


class TestDbUpdatedLabel:
    """DB-updated footer stamp: wall-clock rendering of the newest document mtime."""

    @staticmethod
    def _patch_db(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
        # The stamp is read through server._newest_mtime_ns, whose one input is
        # the coverage directory _db_path resolves — the same directory the
        # renderer globs for its documents.
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))

    @staticmethod
    def _doc(directory: Path, target: str, mtime_ns: int) -> Path:
        """One document, stamped with *mtime_ns* so the assertion is exact."""
        path = write_coverage(
            directory, target, {".text": {"size": 16, "cells": [cell(0, 16, "exact")]}}
        )
        os.utime(path, ns=(mtime_ns, mtime_ns))
        return path

    def test_missing_db_renders_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_db(monkeypatch, tmp_path / "nope")
        assert _db_updated_label() == ""

    def test_label_reflects_the_newest_document_mtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebuild rewrites one target's document, so the stamp must be the
        newest of them: reading any single one shows a stale instant while the
        served data for the rewritten target already changed."""
        directory = tmp_path / "db"
        old_ns = 1_700_000_000_000_000_000
        new_ns = old_ns + 90 * 1_000_000_000
        self._doc(directory, "STALE", old_ns)
        self._doc(directory, "FRESH", new_ns)
        self._patch_db(monkeypatch, directory)
        expected = datetime.fromtimestamp(new_ns // 1_000_000_000, tz=UTC).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        assert _db_updated_label() == expected

    def test_label_with_a_single_document_uses_its_mtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        directory = tmp_path / "db"
        ns = 1_700_000_000_000_000_000
        self._doc(directory, "ONLY", ns)
        self._patch_db(monkeypatch, directory)
        expected = datetime.fromtimestamp(ns // 1_000_000_000, tz=UTC).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        assert _db_updated_label() == expected

    def test_label_truncates_rather_than_rounds_the_minute(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebuild in the last microsecond of a minute is stamped with the
        minute it landed in, not the one it has not reached.  A float-second
        conversion rounds 12:34:59.999999999 up to 12:35, and a footer that
        reads ahead of the data it describes is worse than one that lags by a
        fraction of a second."""
        directory = tmp_path / "db"
        # 2023-11-14T22:13:59.999999999Z: rounds up through a float second.
        ns = 1_700_000_039_999_999_999
        self._doc(directory, "TRUNC", ns)
        self._patch_db(monkeypatch, directory)
        assert _db_updated_label() == "2023-11-14 22:13 UTC"


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_detail_panel_label_value_rows():
    # The detail panel renders label/value rows as <td> pairs, not <th>:
    # potato.py's panel template has no header cells at all.
    target = get_first_target()
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
    target = get_first_target()
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
    target = get_first_target()
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
def test_etag_caching():
    target = get_first_target()

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
        assert _format_va("-1") == "0x-0000001"

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

    def test_filter_sorting_deterministic(self) -> None:
        """Filters should be sorted for deterministic URLs."""
        url1 = _build_url("S", ".t", {"exact", "reloc", "stub"})
        url2 = _build_url("S", ".t", {"stub", "exact", "reloc"})
        assert url1 == url2

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
    used to 500 the page; the accesskey falls back to the first character."""

    def test_second_character_when_available(self) -> None:
        assert _section_tab_data("T", ".text", {".text": {}}, None, "") == [
            (".text", "?target=T&section=.text", True, "t")
        ]

    def test_single_character_name_falls_back_to_first(self) -> None:
        assert _section_tab_data("T", "x", {"x": {}}, None, "") == [
            ("x", "?target=T&section=x", True, "x")
        ]


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
        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")
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

    def test_empty_cells(self) -> None:
        from recoverage.potato import _merge_cells

        assert _merge_cells([], 64) == []

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
        html = _render_function_list(snap, "T", ".text", "", "va", "")
        assert f'<a href="?target=T&section=.text&search={quote("sub_401000")}">' in html
        spaced = f'<a href="?target=T&section=.text&search={quote("a name/with?chars")}">'
        assert spaced in html


class TestV4StateColors:
    """Every v4 cell state renders with its DB_FORMAT.md color, never the
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

    def test_proven_renders_cyan(self) -> None:
        assert self._cell_bgcolor("proven") == "#06b6d4"

    def test_legacy_near_matching_renders_yellow(self) -> None:
        assert self._cell_bgcolor("near_matching") == "#f59e0b"

    def test_size_mismatch_renders_yellow(self) -> None:
        assert self._cell_bgcolor("size_mismatch") == "#f59e0b"

    def test_unknown_state_still_falls_back_to_none_gray(self) -> None:
        assert self._cell_bgcolor("some_future_state") == "#3F4958"


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

    @pytest.mark.parametrize(
        "name",
        ["main.c", "a/b.c", "a\\b.c", "..foo.c", "foo..c", "./main.c"],
    )
    def test_plain_relative_names_accepted(self, name: str) -> None:
        """Both flavours read a name as plain when the host agrees; a POSIX
        host cannot see a Windows drive-relative name at all, so the
        cross-platform rule is pinned through PureWindowsPath below."""
        assert _is_plain_relative(PurePosixPath(name))

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
        assert not _is_plain_relative(PureWindowsPath(name))

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
        assert "sub_401000" in _render_function_list(snap, "T", ".text", query, "va", "")

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
        assert "Café_Render" in _render_function_list(snap, "T", ".text", query, "va", "")

    def test_grid_and_list_agree_on_the_same_term(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recoverage.potato import _render_function_list, _search_functions

        snap = self._snapshot(tmp_path, monkeypatch)
        assert _search_functions(snap, "CAFÉ") == {"Café_Render"}
        assert "Café_Render" in _render_function_list(snap, "T", ".text", "CAFÉ", "va", "")


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
        from rebrew.build_db import _KNOWN_CELL_STATES

        from recoverage.potato import COLORS

        missing = sorted(_KNOWN_CELL_STATES - set(COLORS))
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

    def test_every_filter_key_has_a_pill_with_a_title(self) -> None:
        from recoverage.potato import FILTER_STATES, _build_filter_data

        pills = _build_filter_data("SERVER", ".text", set(), "")
        assert len(pills) == len(FILTER_STATES) + 1  # plus "All"
        keys = {key for _, _, _, _, key, _ in pills}
        assert keys - {"0"} == set(FILTER_STATES)
        for href, label, _color, _active, _key, title in pills:
            assert title, f"pill {label} has no title to explain the letter"
            assert href.startswith("?")

    def test_pill_toggles_only_its_own_filter(self) -> None:
        from recoverage.potato import _build_filter_data

        pills = {
            key: href for href, _, _, _, key, _ in _build_filter_data("S", ".text", {"reloc"}, "")
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


class TestSectionAccentsMatchSpa:
    """The two renderers paint the four pane accents from separate files.

    Potato Mode has no CSS, so it spells the hexes as module constants while
    the SPA reads them from :root. A pane whose heading changed hue in one
    renderer is drift a screenshot would not catch and a user sees as the
    dashboard and its fallback disagreeing about what kind of pane this is.
    """

    PAIRS = (
        ("--accent-c-source", "ACCENT_C_SOURCE"),
        ("--accent-asm", "ACCENT_ASM"),
        ("--accent-data", "ACCENT_DATA"),
        ("--accent-bytes", "ACCENT_BYTES"),
    )

    @staticmethod
    def _spa_tokens() -> dict[str, str]:
        css = (Path(__file__).resolve().parents[1] / "web" / "app" / "index.css").read_text(
            encoding="utf-8"
        )
        # :root only: .light-mode restates the same names with darker values
        # for light surfaces, which Potato Mode has no counterpart for.
        root = css.split(":root {", 1)[1].split("\n}", 1)[0]
        return dict(re.findall(r"(--accent-[a-z-]+):\s*(#[0-9a-fA-F]{6});", root))

    @pytest.mark.parametrize(("token", "constant"), PAIRS)
    def test_spa_token_matches_potato_constant(self, token: str, constant: str) -> None:
        from recoverage import potato

        assert self._spa_tokens()[token] == getattr(potato, constant)

    def test_every_accent_the_renderers_use_is_pinned(self) -> None:
        """A new pane kind must be added to PAIRS, not left unpinned."""
        from recoverage import potato

        pane_accents = {name for _, name in self.PAIRS}
        declared = {
            name
            for name, value in vars(potato).items()
            if name.startswith("ACCENT_") and isinstance(value, str)
        }
        # ACCENT_COLOR is the phosphor accent, not a pane accent.
        assert declared - {"ACCENT_COLOR"} == pane_accents


def _rgb_triplet(hex_color: str) -> tuple[int, int, int]:
    """``#06b6d4`` as the ``6, 182, 212`` a CSS ``rgb()`` stop spells."""
    raw = hex_color.lstrip("#")
    return (int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16))


class TestPageIdentityMatchesTheSpa:
    """The two renderers are one product and carry one mark.

    The SPA serves the phosphor R as ``assets/favicon.svg`` and draws it again
    in its topbar; Potato Mode embeds the same drawing as ``R_LOGO_SVG`` for
    its topbar. A third, unrelated glyph on the Potato tab strip meant the same
    product wore a different icon depending on which view a browser tab was
    showing, and nothing caught it because both pages rendered.
    """

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
        canonical = lambda text: re.sub(r"""[\s'"]""", "", text)  # noqa: E731
        assert canonical(encoded) == canonical(favicon)


class TestSelectionIsTheAccent:
    """Every selected control in both renderers wears ``--c``.

    The SPA's active button and Potato Mode's active pill were blue
    (``rgba(42, 111, 219, ...)``, ``#2a6fdb``) while the accent beside them was
    phosphor cyan, so the one state an operator reads at a glance was the one
    state the theme did not own.
    """

    @staticmethod
    def _root_block() -> str:
        css = (Path(__file__).resolve().parents[1] / "web" / "app" / "index.css").read_text(
            encoding="utf-8"
        )
        return css.split(":root {", 1)[1].split("\n}", 1)[0]

    @pytest.mark.parametrize(
        "token",
        ["--btn-active-bg", "--btn-active-border", "--c-shadow-active", "--bg-grad-1"],
    )
    def test_dark_active_tokens_are_the_accent_hue(self, token: str) -> None:
        from recoverage import potato

        match = re.search(rf"{token}:\s*([^;]+);", self._root_block())
        assert match is not None, token
        value = match.group(1).lower().replace(" ", "")
        red, green, blue = _rgb_triplet(potato.ACCENT_COLOR)
        assert f"{red},{green},{blue}" in value or potato.ACCENT_COLOR in value, token

    def test_potato_active_pills_use_the_accent(self) -> None:
        from recoverage import potato

        for name in ("FILTER_ACT_L", "FILTER_ACT_R", "FILTER_ACT_MID", "ACTIVE_L", "ACTIVE_R"):
            svg = base64.b64decode(getattr(potato, name).split(",", 1)[1]).decode("utf-8")
            assert potato.ACCENT_COLOR in svg, name


class TestRenderIsPinnedToOneSnapshot:
    """A Potato page is built from one frozen CoverageSnapshot.

    ``render_potato`` loads the snapshot once and hands it to every reader —
    sections, cells, functions, globals and (for the detail panels)
    verify_results — and the grid is the most expensive render in the package,
    so a ``rebrew build-db`` committing midway is a real window.  The
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
                _coverage_dir(tmp_path),
                target,
                {
                    ".text": {
                        "size": size,
                        "columns": 8,
                        "cells": [cell(0, end, state)],
                    }
                },
            )

        monkeypatch.setenv("RECOVERAGE_DB", str(_coverage_dir(tmp_path)))
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

        target = get_first_target()
        if not target:
            pytest.skip("No targets in DB")

        # Call 1: the render's token, before it loads the snapshot.  Every call
        # after it sees a `rebrew build-db` that committed mid-render.
        tokens = iter([(1, 64), *[(2, 64)] * 64])
        monkeypatch.setattr(potato, "_snapshot_db_mtime", lambda: next(tokens))

        potato.clear_cells_cache()
        try:
            html = render_potato_url(f"/potato?target={target}&section=.text")
            assert html  # this request still gets its page
            assert not potato._GRID_CACHE, "cells from before the rebuild were memoized"
            assert not potato._POTATO_STATS_CACHE, "stats from before the rebuild were memoized"
        finally:
            potato.clear_cells_cache()
