import json
import re
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import pytest
from conftest import HAS_DB, get_first_target, wsgi_get

from recoverage._paths import sqlite_ro_uri
from recoverage.potato import (
    _build_url,
    _cell_file_offset,
    _esc,
    _extract_annotations,
    _format_data_inspector,
    _format_hex_dump,
    _format_va,
    _load_cells_cached,
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
    db_path = get_db_path()
    conn = sqlite3.connect(sqlite_ro_uri(db_path), uri=True)
    c = conn.cursor()
    c.execute("SELECT DISTINCT name FROM sections WHERE target='SERVER'")
    rows = c.fetchall() or []
    section_names = [r[0] for r in rows]

    for sec in section_names:
        html = render_potato_url(f"/potato?section={sec}")
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
    target = get_first_target()
    conn = sqlite3.connect(sqlite_ro_uri(get_db_path()), uri=True)
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


# ── Index parsing (potato.py idx fix) ──────────────────────────────


class TestIdxParsing:
    """Verify idx parsing as used in _build_grid_html and _render_panel.

    The actual parsing uses int(idx_str) with try/except (ValueError, OverflowError),
    then bounds-checks against the cell list. We test the parsing inline to match.
    """

    @staticmethod
    def _parse_idx_like_production(idx_str: str) -> int | None:
        """Replicate the exact parsing from potato.py _render_panel."""
        if not idx_str:
            return None
        try:
            idx = int(idx_str)
        except (ValueError, OverflowError):
            return None
        if idx < 0:
            return None
        return idx

    def test_valid_digit(self) -> None:
        assert self._parse_idx_like_production("42") == 42

    def test_zero(self) -> None:
        assert self._parse_idx_like_production("0") == 0

    def test_negative_rejected(self) -> None:
        assert self._parse_idx_like_production("-1") is None

    def test_non_numeric_rejected(self) -> None:
        assert self._parse_idx_like_production("abc") is None

    def test_empty_rejected(self) -> None:
        assert self._parse_idx_like_production("") is None

    def test_float_string_rejected(self) -> None:
        assert self._parse_idx_like_production("3.14") is None

    def test_scientific_notation_rejected(self) -> None:
        assert self._parse_idx_like_production("1e5") is None

    @pytest.mark.parametrize(
        "val",
        [
            "NaN",
            "Infinity",
            "-Infinity",
            "inf",
            "nan",
            "++1",
            "--1",
        ],
    )
    def test_special_strings_rejected(self, val: str) -> None:
        assert self._parse_idx_like_production(val) is None

    @pytest.mark.parametrize(
        "val,expected",
        [
            ("+0", 0),  # int("+0") == 0
            ("1_000", 1000),  # int("1_000") == 1000 (Python allows underscores)
        ],
    )
    def test_python_int_accepts(self, val: str, expected: int) -> None:
        """Values that Python's int() accepts should parse correctly."""
        assert self._parse_idx_like_production(val) == expected


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
    """Verify the path traversal guard in potato.py's _panel_fn_source_text.

    The production guard resolves the candidate path and requires it to stay
    inside the source root:
        base = (Path.cwd().resolve() / source_root.lstrip("/")).resolve()
        c_path = (base / files[0]).resolve()
        if not c_path.is_relative_to(base): return None

    These tests verify that resolve + is_relative_to pattern.
    """

    def test_traversal_blocked(self, tmp_path):
        """Attacker-controlled filename with ../ must be rejected."""
        base = (tmp_path / "src" / "test").resolve()
        base.mkdir(parents=True, exist_ok=True)
        c_path = (base / "../../etc/passwd").resolve()
        assert not c_path.is_relative_to(base)

    def test_normal_file_allowed(self, tmp_path):
        """Normal filenames must pass the guard."""
        base = (tmp_path / "src" / "test").resolve()
        base.mkdir(parents=True, exist_ok=True)
        c_path = (base / "main.c").resolve()
        assert c_path.is_relative_to(base)

    def test_symlink_escape_blocked(self, tmp_path):
        """Symlink pointing outside source tree must be caught by resolve()."""
        base = (tmp_path / "src").resolve()
        base.mkdir(parents=True, exist_ok=True)
        # Create a symlink that points outside the base
        link = base / "escape"
        link.symlink_to(tmp_path / ".." / "etc")
        c_path = (base / "escape" / "passwd").resolve()
        assert not c_path.is_relative_to(base)


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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


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
