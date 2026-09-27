import base64
import functools
import json
import os
import re
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote, urlparse

import pytest
from conftest import HAS_DB, get_first_target, wsgi_get
from rebrew.workspace import sqlite_ro_uri

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
from recoverage.server import _db_path as get_db_path


def render_potato_url(url: str) -> str:
    return render_potato(urlparse(url))


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


def test_section_stats_fall_back_to_cells_without_materialized_table():
    """A database with no section_cell_stats still reports per-section stats.

    /stats and /data compute the buckets live from `cells` for such a
    database; /potato read the materialized table and nothing else, so the
    same database answered the API and 503'd the page.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "CREATE TABLE cells (target TEXT, section_name TEXT,"
        " start INTEGER, end INTEGER, state TEXT)"
    )
    c.executemany(
        "INSERT INTO cells (target, section_name, start, end, state)"
        " VALUES ('T', '.text', ?, ?, ?)",
        [(0x1000, 0x1001, "exact"), (0x1001, 0x1002, "none"), (0x1002, 0x1003, "stub")],
    )
    stats = _compute_section_stats(c, "T", {".text": {"size": 3}}, {})
    assert stats[".text"]["total"] == 3
    assert stats[".text"]["exact"] == 1
    assert stats[".text"]["stub"] == 1
    conn.close()


def test_format_va():
    assert _format_va(268439552) == "0x10001000"
    assert _format_va(0) == "0x00000000"
    assert _format_va("0x10003da0") == "0x10003da0"
    assert _format_va("0XABC") == "0XABC"
    assert _format_va("4096") == "0x00001000"
    assert _format_va("not_a_number") == "not_a_number"


def test_section_stats_pct_rounds_like_api():
    """The map-header percentage rounds to 2dp (same as /api .../stats).

    int() truncation made 1329/1330 bytes read "99% covered" in the Potato
    map header while the topbar, the SPA overlay, and the API all said
    ~99.92% for the same section.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("CREATE TABLE cells (target TEXT, section_name TEXT, state TEXT)")
    c.execute(
        "CREATE VIEW section_cell_stats AS"
        " SELECT target, section_name,"
        " COUNT(*) as total_cells,"
        " SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,"
        " 0 as reloc_count, 0 as near_match_count, 0 as stub_count, 0 as padding_count"
        " FROM cells GROUP BY target, section_name"
    )
    c.executemany(
        "INSERT INTO cells (target, section_name, state) VALUES ('T', '.text', ?)",
        [("exact",), ("exact",), ("exact",), ("none",)],
    )
    sections = {".text": {"size": 1330}}
    data = {"summary": {".text": {"coveredBytes": 1329}}}
    stats = _compute_section_stats(c, "T", sections, data)
    assert stats[".text"]["pct"] == round(1329 / 1330 * 100, 2)
    assert stats[".text"]["pct"] != int(1329 / 1330 * 100)
    conn.close()


def test_section_stats_pct_zero_size_is_zero():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("CREATE TABLE cells (target TEXT, section_name TEXT, state TEXT)")
    c.execute(
        "CREATE VIEW section_cell_stats AS"
        " SELECT target, section_name,"
        " COUNT(*) as total_cells,"
        " 0 as exact_count, 0 as reloc_count, 0 as near_match_count,"
        " 0 as stub_count, 0 as padding_count"
        " FROM cells GROUP BY target, section_name"
    )
    c.execute("INSERT INTO cells (target, section_name, state) VALUES ('T', '.bss', 'none')")
    # A NULL-size (.bss-style) section must not divide by zero: pct is 0.
    stats = _compute_section_stats(c, "T", {".bss": {"size": 0}}, {"summary": {}})
    assert stats[".bss"]["pct"] == 0
    conn.close()


def test_section_stats_pct_null_size_is_zero():
    """Same contract as the zero-size case above, with an actual NULL.

    dict.get("size", 0) returns None for a schema-legal NULL column, and
    `None > 0` raised TypeError — a raw 500 through handle_potato's except
    tuple — instead of the pct 0 this asserts.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("CREATE TABLE cells (target TEXT, section_name TEXT, state TEXT)")
    c.execute(
        "CREATE VIEW section_cell_stats AS"
        " SELECT target, section_name,"
        " COUNT(*) as total_cells,"
        " 0 as exact_count, 0 as reloc_count, 0 as near_match_count,"
        " 0 as stub_count, 0 as padding_count"
        " FROM cells GROUP BY target, section_name"
    )
    c.execute("INSERT INTO cells (target, section_name, state) VALUES ('T', '.bss', 'none')")
    stats = _compute_section_stats(c, "T", {".bss": {"size": None}}, {"summary": {}})
    assert stats[".bss"]["pct"] == 0
    sec = {"name": ".bss", "va": None, "size": None}
    progress = _build_progress(".bss", sec, {"summary": {}}, {".bss": {}})
    assert progress["coverage_pct"] == 0
    conn.close()


def test_section_stats_fills_a_partial_section_cell_stats():
    """A materialized section_cell_stats covering only some sections still
    reports the rest.

    The table is a cache over `cells`; a scoped rebuild or a hand-made database
    can carry one that omits a section, and the map header then showed no counts
    for it at all.  The gap is re-aggregated from `cells`, the same fallback
    /api .../stats uses, so the two surfaces agree on the section set.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "CREATE TABLE cells (target TEXT, section_name TEXT, start INT, end INT,"
        " span INT, state TEXT)"
    )
    c.execute(
        "CREATE TABLE section_cell_stats (target TEXT, section_name TEXT,"
        " total_cells INT, exact_count INT, reloc_count INT, near_match_count INT,"
        " stub_count INT, padding_count INT)"
    )
    c.executemany(
        "INSERT INTO cells (target, section_name, start, end, span, state)"
        " VALUES ('T', ?, ?, ?, 1, ?)",
        [
            (".text", 0, 1, "exact"),
            (".text", 1, 2, "exact"),
            (".data", 0, 1, "exact"),
            (".data", 1, 2, "none"),
        ],
    )
    # Only .text made it into the cache.
    c.execute(
        "INSERT INTO section_cell_stats"
        " SELECT target, section_name, COUNT(*),"
        " SUM(state IN ('exact','verified')), 0, 0, 0, 0"
        " FROM cells WHERE section_name = '.text' GROUP BY target, section_name"
    )

    sections = {".text": {"size": 2}, ".data": {"size": 2}}
    stats = _compute_section_stats(c, "T", sections, {"summary": {}})

    assert set(stats) == {".text", ".data"}
    assert stats[".data"]["total"] == 2
    assert stats[".data"]["exact"] == 1
    # .text still answers from the cache it was already answered from.
    assert stats[".text"]["total"] == 2
    conn.close()


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
    """A .bss-style section (NULL va/fileOffset) must render instead of
    TypeError-500ing on hex(None + start).

    The api.py /asm and /bytes endpoints document NULL va/fileOffset as the
    normal shape for file-unbacked sections; the Potato grid and panel do the
    same sec_va + cell.start arithmetic and crashed the whole page on it.
    Addresses fall back to file-relative offsets (the SPA's `sec.va || 0`).
    """
    db = tmp_path / "coverage.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE metadata (target TEXT NOT NULL, key TEXT NOT NULL,"
        " value TEXT, PRIMARY KEY (target, key))"
    )
    conn.execute(
        "CREATE TABLE sections (target TEXT NOT NULL, name TEXT NOT NULL,"
        " va INTEGER, size INTEGER, fileOffset INTEGER, unitBytes INTEGER,"
        " columns INTEGER, PRIMARY KEY (target, name))"
    )
    conn.execute(
        "CREATE TABLE cells (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " target TEXT NOT NULL, section_name TEXT NOT NULL,"
        " start INTEGER NOT NULL, end INTEGER NOT NULL,"
        " span INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL,"
        " functions TEXT NOT NULL DEFAULT '[]', label TEXT, parent_function TEXT)"
    )
    conn.execute(
        "CREATE VIEW section_cell_stats AS"
        " SELECT target, section_name, COUNT(*) as total_cells,"
        " SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,"
        " 0 as reloc_count, 0 as near_match_count, 0 as stub_count,"
        " 0 as padding_count"
        " FROM cells GROUP BY target, section_name"
    )
    # Unique target so the shared resolve-targets/cells caches cannot leak
    # rows from the project coverage.db other tests use.
    t = "NULLVA_POTATO"
    conn.executemany(
        "INSERT INTO metadata VALUES (?,?,?)",
        [
            (t, "db_version", '"4"'),
            (t, "summary", '{"totalFunctions": 0}'),
        ],
    )
    conn.execute("INSERT INTO sections VALUES (?, '.bss', NULL, 64, NULL, 16, 8)", (t,))
    conn.executemany(
        "INSERT INTO cells (target, section_name, start, end, span, state) VALUES (?,?,?,?,?,?)",
        [(t, ".bss", 0, 16, 1, "data"), (t, ".bss", 16, 32, 1, "none")],
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr("recoverage.potato._db_path", lambda: db)

    html = render_potato_url(f"/potato?target={t}&section=.bss")
    assert '<table id="grid"' in html, "grid rendered for a NULL-va section"
    # Cell titles show file-relative offsets: hex() of 0..16.
    assert "0x0..0x10 | data" in html

    panel = render_potato_url(f"/potato?target={t}&section=.bss&idx=0")
    assert "Block 0" in panel
    assert "0x0 .. 0x10" in panel


def test_null_columns_section_renders_grid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A NULL sections.columns value (schema-legal) must fall back to the
    64-column default, not TypeError on ``None <= 0`` — which escapes
    ui.handle_potato's except tuple as a raw HTML 500.  Same crash family
    as test_null_va_section_renders_grid_and_panel."""
    db = tmp_path / "coverage.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE metadata (target TEXT NOT NULL, key TEXT NOT NULL,"
        " value TEXT, PRIMARY KEY (target, key))"
    )
    conn.execute(
        "CREATE TABLE sections (target TEXT NOT NULL, name TEXT NOT NULL,"
        " va INTEGER, size INTEGER, fileOffset INTEGER, unitBytes INTEGER,"
        " columns INTEGER, PRIMARY KEY (target, name))"
    )
    conn.execute(
        "CREATE TABLE cells (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " target TEXT NOT NULL, section_name TEXT NOT NULL,"
        " start INTEGER NOT NULL, end INTEGER NOT NULL,"
        " span INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL,"
        " functions TEXT NOT NULL DEFAULT '[]', label TEXT, parent_function TEXT)"
    )
    conn.execute(
        "CREATE VIEW section_cell_stats AS"
        " SELECT target, section_name, COUNT(*) as total_cells,"
        " SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,"
        " 0 as reloc_count, 0 as near_match_count, 0 as stub_count,"
        " 0 as padding_count"
        " FROM cells GROUP BY target, section_name"
    )
    t = "NULLCOLS_POTATO"
    conn.executemany(
        "INSERT INTO metadata VALUES (?,?,?)",
        [
            (t, "db_version", '"4"'),
            (t, "summary", '{"totalFunctions": 0}'),
        ],
    )
    # columns IS NULL; everything else normal.
    conn.execute("INSERT INTO sections VALUES (?, '.text', 4096, 64, 512, 16, NULL)", (t,))
    conn.executemany(
        "INSERT INTO cells (target, section_name, start, end, span, state) VALUES (?,?,?,?,?,?)",
        [(t, ".text", 0, 16, 1, "exact"), (t, ".text", 16, 32, 1, "none")],
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr("recoverage.potato._db_path", lambda: db)

    html = render_potato_url(f"/potato?target={t}&section=.text")
    assert '<table id="grid"' in html, "grid rendered for a NULL-columns section"


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
    assert "\n" in _wrap_text("a" * 100, 45)
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_grid_structure():
    """Every section's grid sizes its spacer row to the section column count
    and every merged row's colspans sum back to exactly that count."""
    target = get_first_target()
    if not target:
        pytest.skip("No targets in DB")
    db_path = get_db_path()
    conn = sqlite3.connect(sqlite_ro_uri(db_path), uri=True)
    try:
        c = conn.cursor()
        c.execute("SELECT DISTINCT name FROM sections WHERE target=?", (target,))
        section_names = [r[0] for r in c.fetchall()]
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

            c.execute("SELECT columns FROM sections WHERE target=? AND name=?", (target, sec))
            row_data = c.fetchone()
            grid_columns = int(row_data[0]) if row_data and row_data[0] is not None else 64

            assert len(first_row_tds) >= grid_columns, f"grid {sec}: sizing row"

            for ri in range(1, len(table_rows)):
                row = table_rows[ri]
                spans = re.findall(r'colspan="(\d+)"', row) or []
                if spans:
                    total = sum(int(s) for s in spans)
                    assert total == grid_columns, (
                        f"grid {sec}: row {ri} sums to {total} not {grid_columns}"
                    )
    finally:
        conn.close()


# List of URLs to test
URLS = [
    ("/potato", "default"),
    ("/potato?section=.text", "section .text"),
    ("/potato?section=.data", "section .data"),
    ("/potato?section=.rdata", "section .rdata"),
    ("/potato?section=.bss", "section .bss"),
    ("/potato?filter=exact", "filter exact"),
    ("/potato?filter=reloc,near_match", "filter reloc+near_match"),
    ("/potato?section=.text&filter=exact", "text + exact"),
    ("/potato?section=.text&idx=0", "cell 0"),
    ("/potato?section=.text&idx=100", "cell 100"),
    ("/potato?section=.data&idx=0", "cell on .data"),
    ("/potato?section=.bss&idx=0", "cell on .bss"),
    ("/potato?search=alloc", "search alloc"),
    ("/potato?search=0x1000", "search VA prefix"),
    ("/potato?search=g_ServerConfig", "global search"),
    ("/potato?search=nonexistent_xyz", "search no results"),
    (
        "/potato?target=SERVER&section=.text&filter=exact,reloc&idx=0&search=alloc",
        "all params combined",
    ),
    ("/potato?section=.text&idx=-1", "invalid cell (negative)"),
    ("/potato?section=.text&idx=999999", "invalid cell (too large)"),
    ("/potato?section=nonexistent", "nonexistent section"),
    ("/potato?target=NONEXISTENT", "nonexistent target"),
    ("/potato?search=<script>alert(1)</script>", "XSS in search"),
    ("/potato?search=%22%3E%3Cimg%20onerror%3Dalert(1)%3E", "XSS URL-encoded"),
    ("/potato?view=functions", "view functions"),
]


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
@pytest.mark.parametrize("url,name", URLS)
def test_rendering_paths(url, name):
    html = render_potato_url(url)
    assert html, "render returned empty"
    assert "<html" in html and "<body" in html, "missing HTML structure"
    ok, err = _test_tidy(html)
    if ok is False:
        pytest.fail(f"Tidy error on {name}: {err[:150]}")
    assert "style=" not in html
    assert "<script" not in html.lower()
    assert "onclick=" not in html.lower()


def _find_cell_idx(target: str, section: str, predicate) -> int | None:
    conn = sqlite3.connect(sqlite_ro_uri(get_db_path()), uri=True)
    try:
        c = conn.cursor()
        c.execute(
            "SELECT functions FROM cells WHERE target = ? AND section_name = ? ORDER BY id",
            (target, section),
        )
        # ?idx= addresses a cell by its POSITION within the section's cell
        # list (_render_panel indexes cells[idx]; grid links carry that
        # position), not the cells.id column.
        for pos, (funcs_json,) in enumerate(c.fetchall()):
            funcs = []
            if funcs_json:
                funcs = json.loads(funcs_json)
            if predicate(funcs):
                return pos
    finally:
        conn.close()
    return None


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_globals_detail_panel():
    target = get_first_target()
    conn = sqlite3.connect(sqlite_ro_uri(get_db_path()), uri=True)
    try:
        c = conn.cursor()
        c.execute("SELECT name FROM globals WHERE target = ?", (target,))
        globals_set = {row[0] for row in c.fetchall()}
        c.execute(
            "SELECT section_name, functions FROM cells "
            "WHERE target = ? AND section_name IN ('.data', '.rdata') ORDER BY id",
            (target,),
        )
        match: tuple[int, str] | None = None
        # Same position-not-id contract as _find_cell_idx above.
        positions: dict[str, int] = {}
        for sec, funcs_json in c.fetchall():
            funcs = json.loads(funcs_json) if funcs_json else []
            pos = positions.get(sec, 0)
            positions[sec] = pos + 1
            if match is None and any(fn in globals_set for fn in funcs):
                match = (pos, sec)
    finally:
        conn.close()
    if not match:
        pytest.skip("No global-mapped .data/.rdata cell in DB")
    idx, sec = match
    html = render_potato_url(f"/potato?target={target}&section={sec}&idx={idx}")
    assert "Global Variable" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_multi_function_cell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import recoverage.server as _server

    target = get_first_target()
    synthetic = False
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 1)
    if idx is None:
        synthetic = True
        db = tmp_path / "coverage.db"
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE metadata (target TEXT NOT NULL, key TEXT NOT NULL,"
            " value TEXT, PRIMARY KEY (target, key))"
        )
        conn.execute(
            "CREATE TABLE sections (target TEXT NOT NULL, name TEXT NOT NULL,"
            " va INTEGER, size INTEGER, fileOffset INTEGER, unitBytes INTEGER,"
            " columns INTEGER, PRIMARY KEY (target, name))"
        )
        conn.execute(
            "CREATE TABLE cells (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " target TEXT NOT NULL, section_name TEXT NOT NULL,"
            " start INTEGER NOT NULL, end INTEGER NOT NULL,"
            " span INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL,"
            " functions TEXT NOT NULL DEFAULT '[]', label TEXT, parent_function TEXT)"
        )
        conn.execute(
            "CREATE VIEW section_cell_stats AS"
            " SELECT target, section_name, COUNT(*) as total_cells,"
            " SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,"
            " 0 as reloc_count, 0 as near_match_count, 0 as stub_count,"
            " 0 as padding_count"
            " FROM cells GROUP BY target, section_name"
        )
        t = "MULTIFN_POTATO"
        conn.executemany(
            "INSERT INTO metadata VALUES (?,?,?)",
            [(t, "db_version", '"4"'), (t, "summary", '{"totalFunctions": 0}')],
        )
        conn.execute("INSERT INTO sections VALUES (?, '.text', 4096, 32, 512, 16, 8)", (t,))
        conn.execute(
            "INSERT INTO cells (target, section_name, start, end, span, state, functions)"
            " VALUES (?,?,?,?,?,?,?)",
            (t, ".text", 0, 16, 1, "exact", '["_a", "_b"]'),
        )
        conn.execute(
            "CREATE TABLE functions (target TEXT NOT NULL, va INTEGER NOT NULL,"
            " name TEXT NOT NULL DEFAULT '', vaStart TEXT NOT NULL DEFAULT '',"
            " size INTEGER, fileOffset INTEGER, status TEXT NOT NULL DEFAULT 'UNKNOWN',"
            " module TEXT NOT NULL DEFAULT '', cflags TEXT, symbol TEXT,"
            " markerType TEXT NOT NULL DEFAULT 'FUNCTION',"
            " ghidra_name TEXT, list_name TEXT,"
            " is_thunk INTEGER NOT NULL DEFAULT 0, is_export INTEGER NOT NULL DEFAULT 0,"
            " sha256 TEXT, files TEXT NOT NULL DEFAULT '[]',"
            " detected_by TEXT NOT NULL DEFAULT '[]', size_by_tool TEXT NOT NULL DEFAULT '{}',"
            " textOffset INTEGER, blocker TEXT, blockerDelta INTEGER,"
            " size_reason TEXT, similarity REAL, PRIMARY KEY (target, va))"
        )
        conn.execute(
            "CREATE TABLE globals (target TEXT NOT NULL, va INTEGER NOT NULL,"
            " name TEXT NOT NULL DEFAULT '', decl TEXT NOT NULL DEFAULT '',"
            " files TEXT NOT NULL DEFAULT '[]', module TEXT NOT NULL DEFAULT '',"
            " size INTEGER NOT NULL DEFAULT 4, PRIMARY KEY (target, va))"
        )
        conn.execute(
            "CREATE TABLE verify_results (target TEXT NOT NULL, va INTEGER NOT NULL,"
            " verified_at TEXT NOT NULL, byte_delta INTEGER, diff_lines INTEGER,"
            " similarity REAL, PRIMARY KEY (target, va))"
        )
        conn.commit()
        conn.close()
        monkeypatch.setattr("recoverage.potato._db_path", lambda: db)
        monkeypatch.setattr("recoverage.server._db_path", lambda: db)
        _server.clear_target_cache()
        target, idx = t, 0
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}")
    # A cell carrying two function names is not an empty cell, so the panel
    # must not take the "No functions in this block." branch.
    assert "No functions in this block." not in html
    if synthetic:
        # The synthetic DB seeds no functions/globals rows, so the cell's
        # primary function (_a, first of the two) lands in the Unknown branch.
        assert "Unknown: _a" in html
    else:
        assert "Function Details" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_view():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions")
    assert "Functions" in html
    assert "Origin" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_no_match_status_filter_offers_a_way_back():
    target = get_first_target()
    html = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&status=NO_SUCH_STATUS"
    )
    assert "No functions with status" in html
    assert "[Clear filter]" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_sort():
    target = get_first_target()
    html_name = render_potato_url(f"/potato?target={target}&section=.text&view=functions&sort=name")
    html_size = render_potato_url(f"/potato?target={target}&section=.text&view=functions&sort=size")
    assert html_name != html_size


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_prev_next_navigation():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&idx=5")
    assert "#sel" in html
    assert "Prev" in html
    assert "Next" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_skip_link():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'href="#grid-container"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_accesskey_attributes():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    # Search input accesskey + per-section tabs (accesskey = 2nd char of the
    # section name: .text -> "t", .data -> "d").
    assert 'accesskey="s"' in html
    assert 'accesskey="t"' in html  # .text tab
    assert 'accesskey="d"' in html  # .data tab


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_functions_nav_link_is_url_quoted():
    # The header [Functions] href is percent-encoded, so a target or section
    # holding "&" cannot append query parameters to it.  Every other href on
    # the page is built by _build_url, which does the same.
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text")
    assert f'href="?target={target}&amp;section=.text&amp;view=functions"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_clickable_asm_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    from recoverage import potato as _potato

    target = get_first_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 0)
    if idx is None:
        pytest.skip("No .text function cell found")
    # Production renders the ASM block under `if HAS_CAPSTONE`, so a plain
    # HAS_DB gate fails on installs without the optional capstone extra.  Faking
    # the probe (as tests/test_api.py does for the /asm endpoint) keeps the
    # assertion running on every install shape.
    monkeypatch.setattr(_potato, "HAS_CAPSTONE", True)
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_back_to_main_link():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'href="/"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_footer_db_date():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    assert "DB updated" in html
    assert "recoverage" in html


class TestDbUpdatedLabel:
    """DB-updated footer stamp: WAL-aware wall-clock rendering of the DB mtime."""

    @staticmethod
    def _patch_db(monkeypatch: pytest.MonkeyPatch, db: Path) -> None:
        # The stamp is read through server._db_mtime_ns, so the path both the
        # renderer and that helper resolve is the one to redirect.
        monkeypatch.setattr("recoverage.potato._db_path", lambda: db)
        monkeypatch.setattr("recoverage.server._db_path", lambda: db)

    def test_missing_db_renders_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_db(monkeypatch, tmp_path / "nope.db")
        assert _db_updated_label() == ""

    def test_label_reflects_newer_wal_mtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebuild that commits only to -wal must advance the stamp: the main
        file keeps its old mtime, and a main-file-only read would show a stale
        instant while the served data already changed."""
        db = tmp_path / "coverage.db"
        wal = Path(f"{db}-wal")
        db.write_bytes(b"SQLite format 3\x00")
        wal.write_bytes(b"wal")
        old_ns = 1_700_000_000_000_000_000
        new_ns = old_ns + 90 * 1_000_000_000
        os.utime(db, ns=(old_ns, old_ns))
        os.utime(wal, ns=(new_ns, new_ns))
        self._patch_db(monkeypatch, db)
        expected = datetime.fromtimestamp(new_ns / 1e9, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
        assert _db_updated_label() == expected

    def test_label_without_wal_file_uses_main_mtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "coverage.db"
        db.write_bytes(b"SQLite format 3\x00")
        ns = 1_700_000_000_000_000_000
        os.utime(db, ns=(ns, ns))
        self._patch_db(monkeypatch, db)
        expected = datetime.fromtimestamp(ns / 1e9, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
        assert _db_updated_label() == expected

    def test_label_truncates_rather_than_rounds_the_minute(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebuild in the last microsecond of a minute is stamped with the
        minute it landed in, not the one it has not reached.  A float-second
        conversion rounds 12:34:59.999999999 up to 12:35, and a footer that
        reads ahead of the data it describes is worse than one that lags by a
        fraction of a second."""
        db = tmp_path / "coverage.db"
        db.write_bytes(b"SQLite format 3\x00")
        # 2023-11-14T22:13:59.999999999Z: rounds up through a float second.
        ns = 1_700_000_039_999_999_999
        os.utime(db, ns=(ns, ns))
        self._patch_db(monkeypatch, db)
        assert _db_updated_label() == "2023-11-14 22:13 UTC"


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_label_for_search():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}")
    assert 'label for="search-input"' in html
    assert 'label for="target-select"' in html


def test_function_detail_similarity_fraction_rendered_as_percent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """functions.similarity is stored as a 0-1 fraction (schema CHECK) and the
    SPA renders it scaled by 100 with a "%" (app.js).  Potato Mode's detail
    rows must show the same percentage, not the bare fraction."""
    db = tmp_path / "coverage.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE metadata (target TEXT NOT NULL, key TEXT NOT NULL,"
        " value TEXT, PRIMARY KEY (target, key))"
    )
    conn.execute(
        "CREATE TABLE sections (target TEXT NOT NULL, name TEXT NOT NULL,"
        " va INTEGER, size INTEGER, fileOffset INTEGER, unitBytes INTEGER,"
        " columns INTEGER, PRIMARY KEY (target, name))"
    )
    conn.execute(
        "CREATE TABLE cells (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " target TEXT NOT NULL, section_name TEXT NOT NULL,"
        " start INTEGER NOT NULL, end INTEGER NOT NULL,"
        " span INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL,"
        " functions TEXT NOT NULL DEFAULT '[]', label TEXT, parent_function TEXT)"
    )
    conn.execute(
        "CREATE TABLE functions ("
        " target TEXT NOT NULL, va INTEGER NOT NULL CHECK (va >= 0),"
        " name TEXT NOT NULL DEFAULT '', vaStart TEXT NOT NULL DEFAULT '',"
        " size INTEGER NOT NULL DEFAULT 0 CHECK (size >= 0), fileOffset INTEGER,"
        " status TEXT NOT NULL DEFAULT 'UNKNOWN', module TEXT NOT NULL DEFAULT '',"
        " cflags TEXT, symbol TEXT, markerType TEXT NOT NULL DEFAULT 'FUNCTION',"
        " ghidra_name TEXT, list_name TEXT,"
        " is_thunk INTEGER NOT NULL DEFAULT 0, is_export INTEGER NOT NULL DEFAULT 0,"
        " sha256 TEXT, files TEXT NOT NULL DEFAULT '[]',"
        " detected_by TEXT NOT NULL DEFAULT '[]', size_by_tool TEXT NOT NULL DEFAULT '{}',"
        " textOffset INTEGER, blocker TEXT, blockerDelta INTEGER, size_reason TEXT,"
        " similarity REAL CHECK (similarity IS NULL OR"
        " (similarity >= 0.0 AND similarity <= 1.0)),"
        " PRIMARY KEY (target, va))"
    )
    conn.execute(
        "CREATE VIEW section_cell_stats AS"
        " SELECT target, section_name, COUNT(*) as total_cells,"
        " SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,"
        " 0 as reloc_count, 0 as near_match_count, 0 as stub_count,"
        " 0 as padding_count"
        " FROM cells GROUP BY target, section_name"
    )
    # Unique target so the shared resolve-targets/cells caches cannot leak
    # rows from the project coverage.db other tests use.
    t = "SIMFRAC_POTATO"
    conn.executemany(
        "INSERT INTO metadata VALUES (?,?,?)",
        [
            (t, "db_version", '"4"'),
            (t, "summary", '{"totalFunctions": 1}'),
        ],
    )
    conn.execute("INSERT INTO sections VALUES (?, '.text', 256, 64, 16, 16, 8)", (t,))
    conn.execute(
        "INSERT INTO cells (target, section_name, start, end, span, state, functions)"
        " VALUES (?, '.text', 0, 32, 1, 'exact', '[\"_func_sim\"]')",
        (t,),
    )
    conn.execute(
        "INSERT INTO functions (target, va, name, vaStart, size, fileOffset, status,"
        " similarity) VALUES (?, 256, '_func_sim', '0x100', 32, 16, 'EXACT', 0.8734)",
        (t,),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr("recoverage.potato._db_path", lambda: db)

    panel = render_potato_url(f"/potato?target={t}&section=.text&idx=0")
    assert "<b>similarity</b>" in panel
    assert "87.3%" in panel
    assert "0.8734" not in panel


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
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

            for i, cell in enumerate(cells):
                state = cell.get("state")
                fns = cell.get("functions")
                span = int(cell.get("span", 1))
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
                    acc_end = cell.get("end")
                    acc_col += span
                    continue
                flush()
                start_idx = i
                acc_cell = cell
                acc_state = state
                acc_fns = fns
                acc_span = span
                acc_end = cell.get("end")
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
        for pos, cell in enumerate(merged):
            if cell.get("orig_idx", pos) == idx:
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


class TestFunctionListLinks:
    """Every function row links into the grid for the SAME name it prints."""

    def test_row_link_carries_the_printed_name(self) -> None:
        from recoverage.potato import _render_function_list

        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        c = con.cursor()
        c.execute(
            "CREATE TABLE functions (target TEXT, va INTEGER, name TEXT, vaStart TEXT,"
            " size INTEGER, status TEXT, module TEXT, markerType TEXT)"
        )
        c.execute(
            "INSERT INTO functions VALUES ('T', 4096, 'sub_401000', '0x1000', 12,"
            " 'EXACT', 'T', 'FUNCTION')"
        )
        c.execute(
            "INSERT INTO functions VALUES ('T', 4100, 'a name/with?chars', '0x1004', 8,"
            " 'STUB', 'B', 'FUNCTION')"
        )
        html = _render_function_list(c, "T", ".text", "", "va", "")
        try:
            assert f'<a href="?target=T&section=.text&search={quote("sub_401000")}">' in html
            spaced = f'<a href="?target=T&section=.text&search={quote("a name/with?chars")}">'
            assert spaced in html
        finally:
            con.close()


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

    @pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
    def test_search_returns_bounded_results(self):
        """_search_functions caps at 500 rows per query (500 functions +
        500 globals, so at most 1000 entries in the returned set)."""
        from recoverage.potato import _search_functions
        from recoverage.server import _db_path

        conn = sqlite3.connect(sqlite_ro_uri(_db_path()), uri=True)
        try:
            c = conn.cursor()
            c.execute("SELECT DISTINCT target FROM metadata LIMIT 1")
            row = c.fetchone()
            if not row:
                pytest.skip("No targets in DB")
            target = row[0]
            # Empty search returns empty set (short-circuit)
            results = _search_functions(c, target, "")
            assert len(results) == 0
            # Search with a single common letter — should be bounded
            results = _search_functions(c, target, "a")
            # The 1000-entry bound (500 functions + 500 globals) is pinned by
            # the cap tests below against >500-row fixtures; against this
            # 3-function DB the only thing left to show is that a non-empty
            # query matches and stays inside the bound.
            assert 0 < len(results) <= 1000
        finally:
            conn.close()

    def test_search_empty_returns_empty(self):
        """Empty search query short-circuits to empty set (no DB needed)."""
        from recoverage.potato import _search_functions

        # Create an in-memory DB with no tables needed — empty search returns early
        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        result = _search_functions(c, "TEST", "")
        assert result == set()
        conn.close()

    def test_functions_cap_is_deterministic(self):
        """The functions half of the 1000-entry bound: with >500 matches the
        cap must keep exactly the first 500 by ORDER BY name, vaStart.  A cap
        without the ORDER BY follows scan order and keeps the wrong half."""
        from recoverage.potato import _search_functions

        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        c.execute(
            "CREATE TABLE functions (target TEXT, name TEXT, vaStart TEXT DEFAULT '',"
            " symbol TEXT DEFAULT '')"
        )
        c.execute(
            "CREATE TABLE globals (target TEXT, va INTEGER, name TEXT,"
            " decl TEXT DEFAULT '', files TEXT DEFAULT '[]',"
            " module TEXT DEFAULT '', size INTEGER DEFAULT 4)"
        )
        names = [f"func_{i:04d}" for i in range(600)]
        # Insert in REVERSE name order, with no vaStart, so the result is the
        # capped name set alone (each matching row contributes one entry).
        c.executemany(
            "INSERT INTO functions (target, name) VALUES ('T', ?)",
            [(n,) for n in reversed(names)],
        )
        try:
            result = _search_functions(c, "T", "func_")
            assert len(result) == 500
            assert result == set(sorted(names)[:500])
        finally:
            conn.close()

    def test_globals_cap_is_deterministic(self):
        """With >500 matches, which globals enter the dimming set must be
        reproducible: the 500-row cap is only deterministic with an ORDER BY,
        same invariant as the functions query above."""
        from recoverage.potato import _search_functions

        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        c.execute(
            "CREATE TABLE functions (target TEXT, name TEXT, vaStart TEXT DEFAULT '',"
            " symbol TEXT DEFAULT '')"
        )
        c.execute(
            "CREATE TABLE globals (target TEXT, va INTEGER, name TEXT,"
            " decl TEXT DEFAULT '', files TEXT DEFAULT '[]',"
            " module TEXT DEFAULT '', size INTEGER DEFAULT 4)"
        )
        names = [f"glob_{i:04d}" for i in range(600)]
        # Insert in REVERSE name order: a cap without ORDER BY follows scan
        # order (rowid) and keeps the wrong half.
        c.executemany(
            "INSERT INTO globals (target, va, name) VALUES ('T', ?, ?)",
            [(0x10000000 + i * 4, n) for i, n in enumerate(reversed(names))],
        )
        try:
            result = _search_functions(c, "T", "glob_")
            assert len(result) == 500
            assert result == set(sorted(names)[:500])
        finally:
            conn.close()


class TestSearchAddressSpelling:
    """Both address spellings _format_va can print must match.

    _format_va pads to eight digits (``0x00401000``) while printf('%x') does
    not (``0x401000``), so matching only one of them means an address copied
    out of a rendered VA column silently matches nothing."""

    @staticmethod
    def _cursor() -> tuple[sqlite3.Connection, sqlite3.Cursor]:
        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        c.execute(
            "CREATE TABLE functions (target TEXT, name TEXT, va INTEGER,"
            " vaStart TEXT DEFAULT '', symbol TEXT DEFAULT '', size INTEGER DEFAULT 4,"
            " status TEXT DEFAULT 'exact', module TEXT DEFAULT '',"
            " markerType TEXT DEFAULT 'FUNCTION')"
        )
        c.execute(
            "CREATE TABLE globals (target TEXT, va INTEGER, name TEXT,"
            " decl TEXT DEFAULT '', files TEXT DEFAULT '[]',"
            " module TEXT DEFAULT '', size INTEGER DEFAULT 4)"
        )
        c.execute(
            "INSERT INTO functions (target, name, va) VALUES ('T', 'sub_401000', ?)", (0x401000,)
        )
        c.execute("INSERT INTO globals (target, va, name) VALUES ('T', ?, 'g_cfg')", (0x402000,))
        return conn, c

    @pytest.mark.parametrize("query", ["0x00401000", "0x401000"])
    def test_padded_and_bare_function_va_both_match(self, query: str) -> None:
        """The Functions view prints the VA through _format_va, so pasting that
        same string back into its search box must find the row."""
        from recoverage.potato import _render_function_list

        conn, c = self._cursor()
        try:
            assert "sub_401000" in _render_function_list(c, "T", ".text", query, "va", "")
        finally:
            conn.close()

    @pytest.mark.parametrize("query", ["0x00402000", "0x402000"])
    def test_padded_and_bare_global_va_both_match(self, query: str) -> None:
        from recoverage.potato import _search_functions

        conn, c = self._cursor()
        try:
            assert _search_functions(c, "T", query) == {"g_cfg"}
        finally:
            conn.close()

    @pytest.mark.parametrize("query", ["0x00403000", "0x403000"])
    def test_a_different_address_does_not_match(self, query: str) -> None:
        from recoverage.potato import _search_functions

        conn, c = self._cursor()
        try:
            assert _search_functions(c, "T", query) == set()
        finally:
            conn.close()


class TestFunctionListSearchFolding:
    """The Functions view must fold a non-ASCII term the way the grid does.

    SQLite's LIKE folds case for ASCII only, so a bare ``name LIKE ?`` chain
    returns nothing for "CAFÉ" against a "Café_Render" row, and an NFD spelling
    misses its NFC twin.  _search_functions (grid) ORs a folded disjunct in;
    the function list used a hand-written chain without it, so the same query
    matched in one view and not the other.
    """

    @staticmethod
    def _cursor() -> tuple[sqlite3.Connection, sqlite3.Cursor]:
        from recoverage.server import FOLD_SQL, fold_text

        conn = sqlite3.connect(":memory:")
        # _open_db registers the folding function on every read connection;
        # a bare connect() has to do the same or the folded clause cannot run.
        conn.create_function(FOLD_SQL, 1, fold_text, deterministic=True)
        c = conn.cursor()
        c.execute(
            "CREATE TABLE functions (target TEXT, name TEXT, va INTEGER,"
            " vaStart TEXT DEFAULT '', symbol TEXT DEFAULT '', size INTEGER DEFAULT 4,"
            " status TEXT DEFAULT 'exact', module TEXT DEFAULT '',"
            " markerType TEXT DEFAULT 'FUNCTION')"
        )
        c.execute(
            "CREATE TABLE globals (target TEXT, va INTEGER, name TEXT,"
            " decl TEXT DEFAULT '', files TEXT DEFAULT '[]',"
            " module TEXT DEFAULT '', size INTEGER DEFAULT 4)"
        )
        c.execute(
            "INSERT INTO functions (target, name, va) VALUES ('T', 'Café_Render', ?)",
            (0x401000,),
        )
        return conn, c

    @pytest.mark.parametrize(
        "query",
        [
            "CAFÉ",  # uppercase
            "CAFE\u0301",  # NFD spelling: same term, decomposed
            "café",  # lowercase
        ],
    )
    def test_case_folded_term_matches(self, query: str) -> None:
        from recoverage.potato import _render_function_list

        conn, c = self._cursor()
        try:
            assert "Café_Render" in _render_function_list(c, "T", ".text", query, "va", "")
        finally:
            conn.close()

    def test_grid_and_list_agree_on_the_same_term(self) -> None:
        from recoverage.potato import _render_function_list, _search_functions

        conn, c = self._cursor()
        try:
            assert _search_functions(c, "T", "CAFÉ") == {"Café_Render"}
            assert "Café_Render" in _render_function_list(c, "T", ".text", "CAFÉ", "va", "")
        finally:
            conn.close()


class TestCellsCacheInvalidation:
    """The grid memo must invalidate on a WAL-committed rebuild.

    Main-file mtime alone misses it (the writer can commit to coverage.db-wal
    without checkpointing), so the fingerprint uses the WAL-aware snapshot —
    same contract as /data's memo and the SSE watcher."""

    @staticmethod
    def _cells_cursor() -> sqlite3.Cursor:
        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        c.execute(
            "CREATE TABLE cells ("
            " id INTEGER PRIMARY KEY, target TEXT NOT NULL, section_name TEXT NOT NULL,"
            " start INTEGER NOT NULL, end INTEGER NOT NULL, span INTEGER NOT NULL,"
            " state TEXT NOT NULL, functions TEXT NOT NULL DEFAULT '[]',"
            " label TEXT, parent_function TEXT)"
        )
        c.execute(
            "INSERT INTO cells (target, section_name, start, end, span, state)"
            " VALUES ('T', '.text', 0, 16, 1, 'exact')"
        )
        return c

    def test_wal_only_change_forces_refetch(self, tmp_path, monkeypatch) -> None:
        import recoverage.potato as potato
        import recoverage.server as srv

        db = tmp_path / "coverage.db"
        db.write_bytes(b"x" * 64)
        wal = tmp_path / "coverage.db-wal"
        wal.write_bytes(b"")
        monkeypatch.setattr(srv, "_db_path", lambda: db)

        potato.clear_cells_cache()
        c = self._cells_cursor()
        try:
            _load_grid_cells(c, "T", ".text", 64)
            assert len(potato._GRID_CACHE) == 1
            # Simulate a rebuild that commits only to -wal: main file untouched.
            wal.write_bytes(b"y" * 64)
            _load_grid_cells(c, "T", ".text", 64)
            # Two keys prove fingerprint sensitivity: the WAL change produced
            # a cache miss (fresh query), not a stale hit.
            assert len(potato._GRID_CACHE) == 2
        finally:
            potato.clear_cells_cache()
            c.connection.close()

    def test_rebuild_mid_read_is_not_cached(self, tmp_path, monkeypatch) -> None:
        """A rebuild between the read and the publish must not be memoized.

        The cursor's read snapshot can predate the fingerprint taken at the
        top of _load_grid_cells.  Filing that payload under the NEW
        fingerprint poisons the memo: the broadcast that cleared it can be
        overtaken by this insert, and nothing invalidates it afterwards.
        """
        import recoverage.potato as potato

        db = tmp_path / "coverage.db"
        db.write_bytes(b"x" * 64)
        # First call is the key's watermark, second is the publish re-check.
        snapshots = iter([(1, 64), (2, 64)])
        monkeypatch.setattr(potato, "_snapshot_db_mtime", lambda: next(snapshots))

        potato.clear_cells_cache()
        c = self._cells_cursor()
        try:
            cells, _merged, _key = _load_grid_cells(c, "T", ".text", 64)
            assert cells  # this request still gets its payload
            assert not potato._GRID_CACHE  # filed under no fingerprint
        finally:
            potato.clear_cells_cache()
            c.connection.close()

    def test_clear_cells_cache_drops_entries(self) -> None:
        import recoverage.potato as potato

        k = ("fp", "T", ".text", 64)
        potato._GRID_CACHE[k] = ([], [], k)  # type: ignore[assignment]
        potato.clear_cells_cache()
        assert not potato._GRID_CACHE

    def test_unknown_section_yields_empty_cells(self) -> None:
        import recoverage.potato as potato

        potato.clear_cells_cache()
        c = self._cells_cursor()
        try:
            cells, merged, _key = _load_grid_cells(c, "T", ".missing", 64)
            assert cells == []
            assert merged == []
        finally:
            potato.clear_cells_cache()
            c.connection.close()


class TestDbUnavailableContract:
    """A missing/unopenable DB must signal 503, not a 200 error page."""

    def test_render_potato_raises_503_without_db(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import bottle

        monkeypatch.setattr("recoverage.potato._db_path", lambda: tmp_path / "nope.db")
        with pytest.raises(bottle.HTTPResponse) as excinfo:
            render_potato_url("/potato")
        assert excinfo.value.status_code == 503
        assert "Database unavailable" in excinfo.value.body

    def test_potato_route_returns_503_when_db_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # potato._db_path (render) and server._db_path (_snapshot_db_mtime for
        # the ETag) must both point at the missing file.
        missing = tmp_path / "nope.db"
        monkeypatch.setattr("recoverage.potato._db_path", lambda: missing)
        monkeypatch.setattr("recoverage.server._db_path", lambda: missing)
        status, _, body = wsgi_get("/potato")
        assert status.startswith("503")
        assert b"Database unavailable" in body


class TestDefaultTargetMatchesSpa:
    """Potato and the SPA must open on the same target.

    Both render the list resolve_targets returns and default to its first
    entry; a project whose config order differs from its metadata order must
    not open the two surfaces on different targets.
    """

    def test_potato_defaults_to_first_listed_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recoverage.potato as potato_mod

        targets = [{"id": "CONFIG_FIRST", "name": "a"}, {"id": "FROM_DB_FIRST", "name": "b"}]
        monkeypatch.setattr(potato_mod, "resolve_targets", lambda _c: targets)

        chosen: list[str] = []

        def _fake_load(_c: object, target: str) -> tuple[dict, dict]:
            chosen.append(target)
            return {}, {}

        monkeypatch.setattr(potato_mod, "_load_section_data", _fake_load)
        # target="": render must fall back to the default.  _load_section_data
        # returns no data, so the render short-circuits on its "no data" page
        # right after the choice this test is about.
        potato_mod._render_potato_inner(None, "", ".text", set(), "", "", "", "", "", "1")

        # /api/targets serves `targets`, and the SPA picks entry [0] from it.
        assert chosen == [targets[0]["id"]]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


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
        import importlib.resources

        css = (
            importlib.resources.files("recoverage.assets")
            .joinpath("style.css")
            .read_text(encoding="utf-8")
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
