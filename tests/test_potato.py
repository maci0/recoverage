import json
import os
import re
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlparse

import pytest
from conftest import HAS_DB, get_first_target, wsgi_get

from recoverage._paths import sqlite_ro_uri
from recoverage.potato import (
    _build_url,
    _cell_file_offset,
    _compute_section_stats,
    _db_updated_label,
    _esc,
    _extract_annotations,
    _format_data_inspector,
    _format_hex_dump,
    _format_va,
    _load_cells_cached,
    _panel_fn_source_text,
    _render_original_bytes,
    render_potato,
    wrap_text,
)
from recoverage.server import _db_path as get_db_path


def render_potato_url(url: str) -> str:
    return render_potato(urlparse(url))


def _test_tidy(html: str) -> tuple[bool | None, str]:
    try:
        proc = subprocess.run(
            ["tidy", "-q", "-e", "--show-warnings", "no", "--show-errors", "no"],
            input=html.encode("utf-8"),
            capture_output=True,
            timeout=30,
        )
        if proc.returncode > 1:
            return False, proc.stderr.decode("utf-8")
        return True, ""
    except FileNotFoundError:
        return None, "tidy not installed"
    except subprocess.TimeoutExpired:
        return False, "tidy timeout"


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
    assert wrap_text("hello", 10) == "hello"
    assert "\n" in wrap_text("a" * 100, 45)
    assert wrap_text("line1\nline2", 45) == "line1\nline2"


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
    assert _cell_file_offset({"start": 100}, {"fileOffset": 0}) is None
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
def test_multi_function_cell():
    target = get_first_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 1)
    if idx is None:
        pytest.skip("No multi-function cell found")
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}")
    assert "Block Details" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_view():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions")
    assert "Functions" in html
    assert "Origin" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_sort():
    target = get_first_target()
    html_name = render_potato_url(f"/potato?target={target}&section=.text&view=functions&sort=name")
    html_size = render_potato_url(f"/potato?target={target}&section=.text&view=functions&sort=size")
    assert html_name != html_size


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_status_filter():
    target = get_first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions&status=stub")
    assert ("STUB" in html) or ("No functions found." in html)


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
def test_clickable_asm_addresses():
    target = get_first_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 0)
    if idx is None:
        pytest.skip("No .text function cell found")
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}")
    if "Assembly" not in html:
        pytest.skip("Assembly panel unavailable (missing DLL/capstone)")
    assert re.search(r'href="\?target=.*&search=0x[0-9a-f]{8}"', html)


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
        monkeypatch.setattr("recoverage.potato._db_path", lambda: db)

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


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_th_scope_row():
    target = get_first_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 0)
    if idx is None:
        pytest.skip("No function cell found")
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}")
    # The detail panel renders label/value rows as <td> pairs (Range:, State:).
    assert "<b>Range:</b>" in html
    assert "<b>State:</b>" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_detail_shows_verify_similarity():
    """The function data panel surfaces the `rebrew verify -o` record — byte
    delta, diff-line count, and the code-similarity score."""
    target = get_first_target()
    # The synthetic DB seeds a verify_results row for 0x10001000 (_func_a) with
    # similarity 87.3.  The render's per-cell `idx` is the grid position (not the
    # cells.id), so scan render indices for the one that reaches _func_a's detail
    # rows and carries the verify similarity.
    for idx in range(0, 32):
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
        url = _build_url("ターゲット", ".text")
        assert "target=" in url

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

    def test_none_state_never_merged(self) -> None:
        from recoverage.potato import _merge_cells

        cells = [
            {"state": "none", "span": 1, "functions": []},
            {"state": "none", "span": 1, "functions": []},
        ]
        merged = _merge_cells(cells, 64)
        assert len(merged) == 2  # "none" state cells are never merged


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
            assert len(results) <= 1000  # 500 from functions + 500 from globals
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


class TestCellsCacheInvalidation:
    """The cells memo must invalidate on a WAL-committed rebuild.

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
            _load_cells_cached(c, "T")
            assert len(potato._POTATO_CELLS_CACHE) == 1
            # Simulate a rebuild that commits only to -wal: main file untouched.
            wal.write_bytes(b"y" * 64)
            _load_cells_cached(c, "T")
            # Two keys prove fingerprint sensitivity: the WAL change produced
            # a cache miss (fresh query), not a stale hit.
            assert len(potato._POTATO_CELLS_CACHE) == 2
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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
