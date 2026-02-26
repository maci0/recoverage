import json
import os
import re
import sqlite3
import subprocess
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse
from wsgiref.util import setup_testing_defaults

import pytest

from recoverage.potato import (
    _build_url,
    _cell_file_offset,
    _esc,
    _extract_annotations,
    _format_data_inspector,
    _format_hex_dump,
    _format_va,
    get_db_path,
    render_potato,
    wrap_text,
)
from recoverage.server import app

HAS_DB = os.path.exists(Path.cwd() / "db" / "coverage.db")


def render_potato_url(url: str, name: str) -> str:
    return render_potato(urlparse(url))


def _test_tidy(html: str, name: str) -> tuple[bool | None, str]:
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


def test_build_url():
    assert _build_url("SERVER", ".text") == "?target=SERVER&section=.text"
    assert "filter=exact,reloc" in _build_url("SERVER", ".text", {"reloc", "exact"})
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
    inspector = _format_data_inspector(test_bytes, "#151a21", "#334155", "#8b949e")
    assert "int8" in inspector and "-42" in inspector
    assert "uint8" in inspector and "214" in inspector
    assert "int16" in inspector
    assert "int32" in inspector
    assert "float32" in inspector
    assert "float64" in inspector
    assert "<table" in inspector and "</table>" in inspector
    assert _format_data_inspector(b"", "#000", "#111", "#222") == ""
    assert _format_data_inspector(None, "#000", "#111", "#222") == ""

    ascii_inspector = _format_data_inspector(b"Hello\x00World", "#000", "#111", "#222")
    assert "string (ascii)" in ascii_inspector and "Hello" in ascii_inspector


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_grid_structure():
    db_path = get_db_path()
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    c = conn.cursor()
    c.execute("SELECT DISTINCT name FROM sections WHERE target='SERVER'")
    rows = c.fetchall() or []
    section_names = [r[0] for r in rows]

    for sec in section_names:
        html = render_potato_url(f"/potato?section={sec}", f"grid-{sec}")
        m = re.search(r'(<table id="grid"[^>]*>.*?</table>)', html, re.DOTALL)
        assert m, f"grid {sec}: table found"

        table = m.group(1)
        table_rows = [str(r) for r in re.split(r"</tr>\s*<tr[^>]*>", table)]
        first_row_tds = re.findall(r"<td\b", table_rows[0]) or []

        c.execute("SELECT columns FROM sections WHERE target='SERVER' AND name=?", (sec,))
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
    conn.close()


# List of URLs to test
URLS = [
    ("/potato", "default"),
    ("/potato?section=.text", "section .text"),
    ("/potato?section=.data", "section .data"),
    ("/potato?section=.rdata", "section .rdata"),
    ("/potato?section=.bss", "section .bss"),
    ("/potato?filter=exact", "filter exact"),
    ("/potato?filter=reloc,matching", "filter reloc+matching"),
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
    html = render_potato_url(url, name)
    assert html, "render returned empty"
    assert "<html" in html and "<body" in html, "missing HTML structure"
    ok, err = _test_tidy(html, name)
    if ok is False:
        pytest.fail(f"Tidy error on {name}: {err[:150]}")
    assert "style=" not in html
    assert "<script" not in html.lower()
    assert "onclick=" not in html.lower()


def _first_target() -> str:
    conn = sqlite3.connect(f"file:{get_db_path()}?mode=ro", uri=True)
    try:
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM metadata ORDER BY target LIMIT 1")
        row = c.fetchone()
        return row[0] if row else ""
    finally:
        conn.close()


def _find_cell_idx(target: str, section: str, predicate) -> int | None:
    conn = sqlite3.connect(f"file:{get_db_path()}?mode=ro", uri=True)
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id, functions FROM cells WHERE target = ? AND section_name = ? ORDER BY id",
            (target, section),
        )
        for idx, funcs_json in c.fetchall():
            funcs = []
            if funcs_json:
                funcs = json.loads(funcs_json)
            if predicate(funcs):
                return int(idx)
    finally:
        conn.close()
    return None


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_globals_detail_panel():
    target = _first_target()
    conn = sqlite3.connect(f"file:{get_db_path()}?mode=ro", uri=True)
    try:
        c = conn.cursor()
        c.execute("SELECT name FROM globals WHERE target = ?", (target,))
        globals_set = {row[0] for row in c.fetchall()}
        c.execute(
            "SELECT id, section_name, functions FROM cells WHERE target = ? AND section_name IN ('.data', '.rdata')",
            (target,),
        )
        match: tuple[int, str] | None = None
        for idx, sec, funcs_json in c.fetchall():
            funcs = json.loads(funcs_json) if funcs_json else []
            if any(fn in globals_set for fn in funcs):
                match = (int(idx), sec)
                break
    finally:
        conn.close()
    if not match:
        pytest.skip("No global-mapped .data/.rdata cell in DB")
    idx, sec = match
    html = render_potato_url(f"/potato?target={target}&section={sec}&idx={idx}", "globals")
    assert "Global Variable" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_multi_function_cell():
    target = _first_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 1)
    if idx is None:
        pytest.skip("No multi-function cell found")
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}", "multi-fn")
    assert "Block Details" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_view():
    target = _first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&view=functions", "fn-list")
    assert "Functions" in html
    assert "Origin" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_sort():
    target = _first_target()
    html_name = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&sort=name", "fn-sort-name"
    )
    html_size = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&sort=size", "fn-sort-size"
    )
    assert html_name != html_size


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_function_list_status_filter():
    target = _first_target()
    html = render_potato_url(
        f"/potato?target={target}&section=.text&view=functions&status=stub", "fn-status"
    )
    assert ("STUB" in html) or ("No functions found." in html)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_prev_next_navigation():
    target = _first_target()
    html = render_potato_url(f"/potato?target={target}&section=.text&idx=5", "prev-next")
    assert "#sel" in html
    assert "Prev" in html
    assert "Next" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_skip_link():
    target = _first_target()
    html = render_potato_url(f"/potato?target={target}", "skip")
    assert 'href="#grid"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_accesskey_attributes():
    target = _first_target()
    html = render_potato_url(f"/potato?target={target}", "accesskeys")
    assert 'accesskey="s"' in html
    assert 'accesskey="0"' in html
    assert 'accesskey="1"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_clickable_asm_addresses():
    target = _first_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 0)
    if idx is None:
        pytest.skip("No .text function cell found")
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}", "asm-links")
    if "Assembly" not in html:
        pytest.skip("Assembly panel unavailable (missing DLL/capstone)")
    assert re.search(r'href="\?target=.*&search=0x[0-9a-f]{8}"', html)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_back_to_main_link():
    target = _first_target()
    html = render_potato_url(f"/potato?target={target}", "main-link")
    assert 'href="/"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_footer_db_date():
    target = _first_target()
    html = render_potato_url(f"/potato?target={target}", "footer")
    assert "DB: " in html
    assert "recoverage" in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_th_scope_row():
    target = _first_target()
    idx = _find_cell_idx(target, ".text", lambda funcs: len(funcs) > 0)
    if idx is None:
        pytest.skip("No function cell found")
    html = render_potato_url(f"/potato?target={target}&section=.text&idx={idx}", "scope-row")
    assert '<th scope="row"' in html


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_label_for_search():
    target = _first_target()
    html = render_potato_url(f"/potato?target={target}", "labels")
    assert 'label for="search-input"' in html
    assert 'label for="target-select"' in html


def _wsgi_get(
    path: str, headers: dict[str, str] | None = None
) -> tuple[str, dict[str, str], bytes]:
    environ: dict[str, str | BytesIO] = {}
    setup_testing_defaults(environ)
    url_path, _, query = path.partition("?")
    environ["REQUEST_METHOD"] = "GET"
    environ["PATH_INFO"] = url_path
    environ["QUERY_STRING"] = query
    environ["wsgi.input"] = BytesIO(b"")
    if headers:
        for k, v in headers.items():
            environ[f"HTTP_{k.upper().replace('-', '_')}"] = v

    status_holder = {"status": "", "headers": {}}

    def _start_response(status: str, response_headers, exc_info=None):
        status_holder["status"] = status
        status_holder["headers"] = {k: v for k, v in response_headers}
        return None

    result = app(environ, _start_response)
    body = b"".join(result)
    return status_holder["status"], status_holder["headers"], body


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
def test_etag_caching():
    target = _first_target()
    status, headers, _ = _wsgi_get(f"/potato?target={target}&section=.text")
    assert status.startswith("200")
    etag = headers.get("ETag")
    assert etag

    status2, _, _ = _wsgi_get(
        f"/potato?target={target}&section=.text",
        headers={"If-None-Match": etag},
    )
    assert status2.startswith("304")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
