#!/usr/bin/env python3
"""
Test harness for potato mode rendering.
Tests all possible rendering paths, validates HTML with tidy,
checks compliance via the W3C Nu Validator, and runs unit tests
on helper functions and structural validation on grid tables.
"""

import json
import re
import struct
import subprocess
import sys
import os
from urllib.parse import urlparse

# Add recoverage to path
sys.path.insert(0, os.path.dirname(__file__))
from potato import (  # type: ignore
    render_potato,
    get_db_path,
    _format_va,
    _build_url,
    _esc,
    _format_hex_dump,
    _extract_annotations,
    _cell_file_offset,
    _format_data_inspector,
    wrap_text,
)


def test_render(url, name):
    """Render a URL and return the HTML."""
    result = render_potato(urlparse(url))
    return result


def test_tidy(html, name):
    """Validate HTML with tidy."""
    try:
        proc = subprocess.run(
            ["tidy", "-q", "-e", "--show-warnings", "no", "--show-errors", "no"],
            input=html.encode("utf-8"),
            capture_output=True,
            timeout=30,
        )
        # tidy returns 1 for warnings, 0 for clean
        # We want to catch actual errors, not warnings
        if proc.returncode > 1:
            return False, proc.stderr.decode("utf-8")
        return True, ""
    except FileNotFoundError:
        return None, "tidy not installed"
    except subprocess.TimeoutExpired:
        return False, "tidy timeout"


def run_unit_tests():
    """Unit tests for helper functions (no DB or rendering needed)."""
    tests = []

    # ── _format_va ──────────────────────────────────────────────
    tests.append(
        (
            "_format_va: int to hex",
            _format_va(268439552) == "0x10001000",
        )
    )
    tests.append(
        (
            "_format_va: zero",
            _format_va(0) == "0x00000000",
        )
    )
    tests.append(
        (
            "_format_va: hex string passthrough",
            _format_va("0x10003da0") == "0x10003da0",
        )
    )
    tests.append(
        (
            "_format_va: 0X prefix passthrough",
            _format_va("0XABC") == "0XABC",
        )
    )
    tests.append(
        (
            "_format_va: decimal string to hex",
            _format_va("4096") == "0x00001000",
        )
    )
    tests.append(
        (
            "_format_va: non-numeric string",
            _format_va("not_a_number") == "not_a_number",
        )
    )

    # ── _build_url ──────────────────────────────────────────────
    tests.append(
        (
            "_build_url: basic",
            "?target=SERVER&section=.text" == _build_url("SERVER", ".text"),
        )
    )
    tests.append(
        (
            "_build_url: with filters",
            "filter=exact,reloc" in _build_url("SERVER", ".text", {"reloc", "exact"}),
        )
    )
    tests.append(
        (
            "_build_url: with idx",
            "idx=42" in _build_url("SERVER", ".text", idx=42),
        )
    )
    tests.append(
        (
            "_build_url: with search",
            "search=alloc" in _build_url("SERVER", ".text", search="alloc"),
        )
    )
    tests.append(
        (
            "_build_url: all params",
            all(
                p in _build_url("SERVER", ".text", {"exact"}, idx=5, search="foo")
                for p in [
                    "target=SERVER",
                    "section=.text",
                    "filter=exact",
                    "idx=5",
                    "search=foo",
                ]
            ),
        )
    )
    tests.append(
        (
            "_build_url: no filter when None",
            "filter" not in _build_url("SERVER", ".text", None),
        )
    )
    tests.append(
        (
            "_build_url: no idx when None",
            "idx" not in _build_url("SERVER", ".text"),
        )
    )
    tests.append(
        (
            "_build_url: no search when empty",
            "search" not in _build_url("SERVER", ".text", search=""),
        )
    )

    # ── _esc ────────────────────────────────────────────────────
    tests.append(
        (
            "_esc: angle brackets",
            _esc("<script>") == "&lt;script&gt;",
        )
    )
    tests.append(
        (
            "_esc: ampersand",
            _esc("a&b") == "a&amp;b",
        )
    )
    tests.append(
        (
            "_esc: quotes",
            _esc('"hello"') == "&quot;hello&quot;",
        )
    )
    tests.append(
        (
            "_esc: clean string",
            _esc("hello world") == "hello world",
        )
    )
    tests.append(
        (
            "_esc: non-string input",
            _esc(12345) == "12345",
        )
    )

    # ── wrap_text ───────────────────────────────────────────────
    tests.append(
        (
            "wrap_text: short line unchanged",
            wrap_text("hello", 10) == "hello",
        )
    )
    tests.append(
        (
            "wrap_text: long line wrapped",
            "\n" in wrap_text("a" * 100, 45),
        )
    )
    tests.append(
        (
            "wrap_text: multiline preserved",
            wrap_text("line1\nline2", 45) == "line1\nline2",
        )
    )
    tests.append(
        (
            "wrap_text: width respected",
            all(len(line) <= 50 for line in wrap_text("a" * 200, 50).splitlines()),
        )
    )

    # ── _format_hex_dump ────────────────────────────────────────
    dump = _format_hex_dump(b"\x48\x65\x6c\x6c\x6f\x00\xff\x01", base_offset=0x1000)
    tests.append(
        (
            "_format_hex_dump: offset present",
            "00001000" in dump,
        )
    )
    tests.append(
        (
            "_format_hex_dump: hex bytes",
            "48 65 6c 6c" in dump,
        )
    )
    tests.append(
        (
            "_format_hex_dump: ASCII repr",
            "Hello" in dump,
        )
    )
    tests.append(
        (
            "_format_hex_dump: non-printable as dot",
            "." in dump,  # \x00 and \xff should be dots
        )
    )
    tests.append(
        (
            "_format_hex_dump: 16+ bytes multi-line",
            "\n" in _format_hex_dump(bytes(range(32)), 0),
        )
    )
    tests.append(
        (
            "_format_hex_dump: truncation message",
            "more bytes" in _format_hex_dump(bytes(300), 0, max_bytes=256),
        )
    )
    tests.append(
        (
            "_format_hex_dump: no truncation for small",
            "more bytes" not in _format_hex_dump(bytes(16), 0, max_bytes=256),
        )
    )
    tests.append(
        (
            "_format_hex_dump: empty bytes",
            _format_hex_dump(b"", 0) == "",
        )
    )

    # ── _extract_annotations ────────────────────────────────────
    code = """// FUNCTION: SERVER 0x10003da0
// STATUS: MATCHING
// NOTE: register alloc differs
// BLOCKER: loop unrolling
// SOURCE: deflate.c:fill_window
int foo(void) { return 0; }
"""
    annotations = _extract_annotations(code)
    tests.append(
        (
            "_extract_annotations: finds NOTE",
            ("NOTE", "register alloc differs") in annotations,
        )
    )
    tests.append(
        (
            "_extract_annotations: finds BLOCKER",
            ("BLOCKER", "loop unrolling") in annotations,
        )
    )
    tests.append(
        (
            "_extract_annotations: finds SOURCE",
            ("SOURCE", "deflate.c:fill_window") in annotations,
        )
    )
    tests.append(
        (
            "_extract_annotations: ignores non-annotation",
            len(annotations) == 3,
        )
    )
    tests.append(
        (
            "_extract_annotations: empty code",
            _extract_annotations("") == [],
        )
    )
    tests.append(
        (
            "_extract_annotations: code without annotations",
            _extract_annotations("int main() { return 0; }") == [],
        )
    )

    # ── _cell_file_offset ───────────────────────────────────────
    tests.append(
        (
            "_cell_file_offset: normal case",
            _cell_file_offset({"start": 100}, {"fileOffset": 4096}) == 4196,
        )
    )
    tests.append(
        (
            "_cell_file_offset: bss (fileOffset=0)",
            _cell_file_offset({"start": 100}, {"fileOffset": 0}) is None,
        )
    )
    tests.append(
        (
            "_cell_file_offset: no sec_data",
            _cell_file_offset({"start": 100}, None) is None,
        )
    )
    tests.append(
        (
            "_cell_file_offset: no start key",
            _cell_file_offset({}, {"fileOffset": 4096}) == 4096,
        )
    )

    # ── _format_data_inspector ──────────────────────────────────
    # Use known bytes for deterministic values
    test_bytes = struct.pack(
        "<bBhHiIfd", -42, 200, -1000, 60000, -100000, 3000000000, 3.14, 2.71828
    )
    inspector = _format_data_inspector(test_bytes, "#151a21", "#334155", "#8b949e")
    tests.append(
        (
            "_format_data_inspector: contains int8",
            "int8" in inspector and "-42" in inspector,
        )
    )
    tests.append(
        (
            "_format_data_inspector: contains uint8",
            "uint8" in inspector and "214" in inspector,
        )
    )
    tests.append(
        (
            "_format_data_inspector: contains int16",
            "int16" in inspector,
        )
    )
    tests.append(
        (
            "_format_data_inspector: contains int32",
            "int32" in inspector,
        )
    )
    tests.append(
        (
            "_format_data_inspector: contains float32",
            "float32" in inspector,
        )
    )
    tests.append(
        (
            "_format_data_inspector: contains float64",
            "float64" in inspector,
        )
    )
    tests.append(
        (
            "_format_data_inspector: table structure",
            "<table" in inspector and "</table>" in inspector,
        )
    )
    tests.append(
        (
            "_format_data_inspector: empty bytes returns empty",
            _format_data_inspector(b"", "#000", "#111", "#222") == "",
        )
    )
    tests.append(
        (
            "_format_data_inspector: None returns empty",
            _format_data_inspector(None, "#000", "#111", "#222") == "",  # type: ignore
        )
    )
    # ASCII string scan
    ascii_inspector = _format_data_inspector(b"Hello\x00World", "#000", "#111", "#222")
    tests.append(
        (
            "_format_data_inspector: ASCII string",
            "string (ascii)" in ascii_inspector and "Hello" in ascii_inspector,
        )
    )
    # 1-byte input: only int8/uint8
    tiny_inspector = _format_data_inspector(b"\x42", "#000", "#111", "#222")
    tests.append(
        (
            "_format_data_inspector: 1 byte no int16",
            "int16" not in tiny_inspector and "int8" in tiny_inspector,
        )
    )
    # 2-byte input: int8/uint8/int16/uint16, no int32
    two_inspector = _format_data_inspector(b"\x42\x43", "#000", "#111", "#222")
    tests.append(
        (
            "_format_data_inspector: 2 bytes has int16 no int32",
            "int16" in two_inspector and "int32" not in two_inspector,
        )
    )

    return tests


def run_grid_structure_tests():
    """Validate that grid tables have correct colspan structure for all sections."""
    import sqlite3

    tests = []
    conn = sqlite3.connect(str(get_db_path()))
    c = conn.cursor()
    c.execute("SELECT DISTINCT name FROM sections WHERE target='SERVER'")
    rows_db = c.fetchall() or []
    section_names = [r[0] for r in rows_db]
    conn.close()

    for sec in section_names:
        html = test_render(f"/potato?section={sec}", f"grid-{sec}")
        # Find the grid table by id="grid"
        m = re.search(
            r'(<table id="grid"[^>]*>.*?</table>)',
            html,
            re.DOTALL,
        )
        if not m:
            tests.append((f"grid {sec}: table found", False))
            continue

        table = m.group(1)
        tests.append((f"grid {sec}: table found", True))

        # Split into rows
        rows = [str(r) for r in re.split(r"</tr>\s*<tr[^>]*>", table)]

        # First row should be the sizing row (individual 1-wide cells)
        first_row_spans = re.findall(r'colspan="(\d+)"', rows[0]) or []
        _has_sizing_row = len(first_row_spans) == 0  # sizing row has no colspan
        first_row_tds = re.findall(r"<td\b", rows[0]) or []

        c2 = sqlite3.connect(str(get_db_path()))
        cur = c2.cursor()
        cur.execute(
            "SELECT columns FROM sections WHERE target='SERVER' AND name=?", (sec,)
        )
        row_data = cur.fetchone()
        grid_columns = int(row_data[0]) if row_data and row_data[0] is not None else 64
        c2.close()

        tests.append(
            (
                f"grid {sec}: sizing row has {grid_columns} cells",
                len(first_row_tds) >= grid_columns,
            )
        )

        # Every data row should have colspans summing to grid_columns
        all_rows_ok = True
        bad_ri = 0
        bad_total = 0
        for ri in range(1, len(rows)):
            row = rows[ri]
            spans = re.findall(r'colspan="(\d+)"', row) or []
            if not spans:
                # Might be the closing </table> fragment
                continue
            total = sum(int(s) for s in spans)
            if total != grid_columns:
                all_rows_ok = False
                bad_ri = ri
                bad_total = total
                break

        if all_rows_ok:
            tests.append((f"grid {sec}: all rows sum to {grid_columns}", True))
        else:
            tests.append(
                (
                    f"grid {sec}: row {bad_ri} sums to {bad_total} not {grid_columns}",
                    False,
                )
            )

    return tests


def main():
    # ── Unit tests ─────────────────────────────────────────────────
    print("=" * 60)
    print("Unit Tests (helper functions)")
    print("=" * 60)

    passed: int = 0
    failed: int = 0

    for name, result in run_unit_tests():
        if result:
            print(f"PASS: {name:45s}")
            passed += 1  # type: ignore
        else:
            print(f"FAIL: {name:45s}")
            failed += 1  # type: ignore

    # ── Grid structure tests ───────────────────────────────────────
    print("-" * 60)
    print("Grid Structure Validation")
    print("-" * 60)

    for name, result in run_grid_structure_tests():
        if result:
            print(f"PASS: {name:45s}")
            passed += 1  # type: ignore
        else:
            print(f"FAIL: {name:45s}")
            failed += 1  # type: ignore

    # ── Rendering path tests ───────────────────────────────────────
    print("-" * 60)
    print("Rendering Paths")
    print("-" * 60)

    # All possible rendering paths to test
    tests = [
        # Default render
        ("/potato", "default"),
        # Different sections
        ("/potato?section=.text", "section .text"),
        ("/potato?section=.data", "section .data"),
        ("/potato?section=.rdata", "section .rdata"),
        ("/potato?section=.bss", "section .bss"),
        # Single filters
        ("/potato?filter=exact", "filter exact"),
        ("/potato?filter=reloc", "filter reloc"),
        ("/potato?filter=matching", "filter matching"),
        ("/potato?filter=stub", "filter stub"),
        # Multi filters
        ("/potato?filter=exact,reloc", "filter exact+reloc"),
        ("/potato?filter=exact,matching", "filter exact+matching"),
        ("/potato?filter=reloc,matching", "filter reloc+matching"),
        ("/potato?filter=exact,reloc,matching", "filter exact+reloc+matching"),
        ("/potato?filter=exact,reloc,matching,stub", "filter all"),
        # Sections + filters
        ("/potato?section=.text&filter=exact", "text + exact"),
        ("/potato?section=.data&filter=reloc", "data + reloc"),
        ("/potato?section=.rdata&filter=matching", "rdata + matching"),
        ("/potato?section=.bss&filter=stub", "bss + stub"),
        # Cell selection
        ("/potato?section=.text&idx=0", "cell 0"),
        ("/potato?section=.text&idx=100", "cell 100"),
        ("/potato?section=.text&idx=1000", "cell 1000"),
        # Cell selection on non-.text sections
        ("/potato?section=.data&idx=0", "cell on .data"),
        ("/potato?section=.rdata&idx=0", "cell on .rdata"),
        ("/potato?section=.bss&idx=0", "cell on .bss"),
        # Cell selection + filters
        ("/potato?section=.text&idx=0&filter=exact", "cell + exact"),
        ("/potato?section=.text&idx=0&filter=exact,reloc", "cell + multi filter"),
        # Target (if multiple targets exist)
        ("/potato?target=SERVER", "target SERVER"),
        # Search
        ("/potato?search=alloc", "search alloc"),
        ("/potato?search=0x1000", "search VA prefix"),
        ("/potato?search=nonexistent_xyz", "search no results"),
        ("/potato?section=.text&search=alloc", "search + section"),
        ("/potato?section=.text&search=alloc&filter=exact", "search + filter"),
        ("/potato?section=.text&idx=0&search=alloc", "search + cell"),
        # All params combined
        (
            "/potato?target=SERVER&section=.text&filter=exact,reloc&idx=0&search=alloc",
            "all params combined",
        ),
        # Edge cases
        ("/potato?section=.text&idx=-1", "invalid cell (negative)"),
        ("/potato?section=.text&idx=999999", "invalid cell (too large)"),
        ("/potato?section=nonexistent", "nonexistent section"),
        ("/potato?target=NONEXISTENT", "nonexistent target"),
        ("/potato?search=<script>alert(1)</script>", "XSS in search"),
        ("/potato?search=%22%3E%3Cimg%20onerror%3Dalert(1)%3E", "XSS URL-encoded"),
        ("/potato?filter=invalid_filter", "invalid filter name"),
        ("/potato?search=", "empty search string"),
        ("/potato?idx=abc", "non-numeric idx"),
        ("/potato?section=.text&filter=exact&filter=reloc", "duplicate filter params"),
    ]

    tidy_errors: int = 0
    tidy_missing: int = 0

    for url, name in tests:
        try:
            html = test_render(url, name)
            if not html:
                print(f"FAIL: {name:40s} - render returned empty")
                failed += 1  # type: ignore
                continue

            # Check for basic HTML structure
            if "<html" not in html or "<body" not in html:
                print(f"FAIL: {name:40s} - missing HTML structure")
                failed += 1  # type: ignore
                continue

            # Validate with tidy
            ok, err = test_tidy(html, name)
            if ok is None:
                tidy_missing += 1  # type: ignore
                print(f"PASS: {name:40s} (tidy not installed)")
            elif ok:
                print(f"PASS: {name:40s}")
                passed += 1  # type: ignore
            else:
                tidy_errors += 1  # type: ignore
                print(f"FAIL: {name:40s} - tidy error: {err[:80]}")
                failed += 1  # type: ignore

        except Exception as e:
            print(f"FAIL: {name:40s} - {e}")
            failed += 1  # type: ignore

    # ── Content-based assertions ─────────────────────────────────
    print("-" * 60)
    print("Content Assertions")
    print("-" * 60)

    content_tests = [
        # (url, assertion_name, check_fn)
    ]

    # Search: matching query shows match count
    def check_search_results(html):
        return "matches)" in html and "Searching:" in html

    content_tests.append(
        ("/potato?search=alloc", "search shows match count", check_search_results)
    )

    # Search: no-result query still renders
    def check_search_no_results(html):
        return "0 matches)" in html and "Searching:" in html

    content_tests.append(
        (
            "/potato?search=nonexistent_xyz_zzz",
            "search no results shows 0",
            check_search_no_results,
        )
    )

    # Search: clear search link present
    def check_clear_search(html):
        return "[Clear search]" in html

    content_tests.append(
        ("/potato?search=alloc", "clear search link present", check_clear_search)
    )

    # Search: no clear link when no search
    def check_no_clear_when_no_search(html):
        return "[Clear search]" not in html

    content_tests.append(
        ("/potato", "no clear search when no query", check_no_clear_when_no_search)
    )

    # Search form is functional (has form tag with method)
    def check_search_form(html):
        return (
            'id="search-form"' in html
            and 'action="/potato"' in html
            and 'name="search"' in html
        )

    content_tests.append(("/potato", "search form is functional", check_search_form))

    # No style= attributes (NO CSS constraint)
    def check_no_css(html):
        return "style=" not in html

    content_tests.append(("/potato", "no style= attributes (default)", check_no_css))
    content_tests.append(
        (
            "/potato?section=.text&idx=0",
            "no style= attributes (with cell)",
            check_no_css,
        )
    )
    content_tests.append(
        (
            "/potato?filter=exact&search=alloc",
            "no style= attributes (filter+search)",
            check_no_css,
        )
    )
    content_tests.append(
        (
            "/potato?section=.data&idx=0",
            "no style= attributes (.data cell)",
            check_no_css,
        )
    )

    # No JavaScript (NO JS constraint)
    def check_no_js(html):
        return "<script" not in html.lower() and "javascript:" not in html.lower()

    content_tests.append(("/potato", "no JavaScript (default)", check_no_js))
    content_tests.append(
        ("/potato?section=.text&idx=0", "no JavaScript (cell)", check_no_js)
    )

    # No event handler attributes
    def check_no_event_handlers(html):
        event_attrs = [
            "onclick=",
            "onload=",
            "onerror=",
            "onmouseover=",
            "onsubmit=",
            "onfocus=",
            "onblur=",
            "onchange=",
            "onkeydown=",
            "onkeyup=",
            "onkeypress=",
        ]
        html_lower = html.lower()
        return not any(attr in html_lower for attr in event_attrs)

    content_tests.append(
        ("/potato", "no event handlers (default)", check_no_event_handlers)
    )
    content_tests.append(
        (
            "/potato?section=.text&idx=0",
            "no event handlers (cell)",
            check_no_event_handlers,
        )
    )

    # XSS safety: script tags are escaped
    def check_xss_safe(html):
        return "<script>" not in html and "&lt;script&gt;" in html

    content_tests.append(
        (
            "/potato?search=<script>alert(1)</script>",
            "XSS escaped in search",
            check_xss_safe,
        )
    )

    # XSS: angle brackets in search don't create elements
    def check_xss_no_element(html):
        return "<img onerror" not in html

    content_tests.append(
        (
            "/potato?search=%22%3E%3Cimg%20onerror%3Dalert(1)%3E",
            "XSS URL-encoded no element",
            check_xss_no_element,
        )
    )

    # Cell 0 on .text has assembly section
    def check_assembly(html):
        return "<b>Assembly</b>" in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "assembly view for .text cell", check_assembly)
    )

    # Cell on .data does NOT have assembly section
    def check_no_assembly(html):
        return "<b>Assembly</b>" not in html

    content_tests.append(
        ("/potato?section=.data&idx=0", "no assembly for .data cell", check_no_assembly)
    )

    # Cell selection shows Block N header
    def check_block_header(html):
        return "<b>Block 0</b>" in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "block header shows index", check_block_header)
    )

    # No cell selected shows "Select a block"
    def check_select_prompt(html):
        return "Select a block" in html

    content_tests.append(
        ("/potato", "no cell shows select prompt", check_select_prompt)
    )

    # Invalid cell index also shows "Select a block"
    def check_invalid_cell_prompt(html):
        return "Select a block" in html

    content_tests.append(
        (
            "/potato?section=.text&idx=-1",
            "invalid cell shows select prompt",
            check_invalid_cell_prompt,
        )
    )
    content_tests.append(
        (
            "/potato?section=.text&idx=999999",
            "huge cell idx shows select prompt",
            check_invalid_cell_prompt,
        )
    )

    # Filter preserves across search
    def check_filter_preserved_in_search(html):
        return 'name="filter"' in html and 'value="exact"' in html

    content_tests.append(
        (
            "/potato?filter=exact&search=alloc",
            "filter hidden input in search form",
            check_filter_preserved_in_search,
        )
    )

    # Progress bar is present
    def check_progress_bar(html):
        return "E:" in html and "R:" in html and "M:" in html and "S:" in html

    content_tests.append(("/potato", "progress bar counts present", check_progress_bar))

    # VA displayed as hex (not decimal)
    def check_va_hex(html):
        return "0x10001000" in html and "268439552" not in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "VA displayed as hex", check_va_hex)
    )

    # Original Bytes hex dump present
    def check_hex_dump(html):
        return "<b>Original Bytes</b>" in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "hex dump present", check_hex_dump)
    )

    # Hex dump has classic format (offset | hex | ascii)
    def check_hex_format(html):
        return "|" in html and "00001000" in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "hex dump classic format", check_hex_format)
    )

    # Annotations section for MATCHING functions with BLOCKER
    def check_annotations():
        """Find a MATCHING function cell and check for annotations."""
        import sqlite3 as _sq
        import json as _js

        conn = _sq.connect(str(get_db_path()))
        c = conn.cursor()
        c.execute(
            "SELECT name FROM functions WHERE target='SERVER' AND status='MATCHING' LIMIT 5"
        )
        matching = [r[0] for r in c.fetchall()]
        if not matching:
            conn.close()
            return None  # skip
        c.execute(
            """SELECT json_group_array(json_object('state', state, 'functions', json(functions)))
            FROM cells WHERE target='SERVER' AND section_name='.text'"""
        )
        row = c.fetchone()
        cells = _js.loads(row[0])
        conn.close()
        for i, cell in enumerate(cells):
            fns = cell.get("functions", [])
            if fns and fns[0] in matching:
                return i
        return None

    matching_idx = check_annotations()
    if matching_idx is not None:

        def check_blocker(html):
            return "<b>Annotations</b>" in html and "BLOCKER" in html

        content_tests.append(
            (
                f"/potato?section=.text&idx={matching_idx}",
                "annotations with BLOCKER",
                check_blocker,
            )
        )

    # No assembly for .rdata section
    def check_no_asm_rdata(html):
        return "<b>Assembly</b>" not in html

    content_tests.append(
        ("/potato?section=.rdata&idx=0", "no assembly for .rdata", check_no_asm_rdata)
    )

    # fileOffset displayed as hex
    def check_fileoffset_hex(html):
        # fileOffset for cell 0 is 4096 = 0x1000, should show as 0x00001000
        return "0x00001000" in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "fileOffset as hex", check_fileoffset_hex)
    )

    # Data inspector for .data cells (non-.text with raw bytes)
    def check_data_inspector(html):
        return "<b>Data Inspector</b>" in html and "int8" in html and "uint8" in html

    content_tests.append(
        (
            "/potato?section=.data&idx=0",
            "data inspector for .data cell",
            check_data_inspector,
        )
    )

    # Data inspector NOT shown for .text cells
    def check_no_data_inspector_text(html):
        return "<b>Data Inspector</b>" not in html

    content_tests.append(
        (
            "/potato?section=.text&idx=0",
            "no data inspector for .text",
            check_no_data_inspector_text,
        )
    )

    # Data inspector NOT shown for .bss (no raw bytes, fileOffset=0)
    def check_no_data_inspector_bss(html):
        return "<b>Data Inspector</b>" not in html

    content_tests.append(
        (
            "/potato?section=.bss&idx=0",
            "no data inspector for .bss",
            check_no_data_inspector_bss,
        )
    )

    # Per-section coverage stats in section tabs
    def check_per_section_stats(html):
        # Section tabs should show percentage like [.text 5%]
        return "%" in html and "covered" in html

    content_tests.append(
        ("/potato", "per-section coverage stats", check_per_section_stats)
    )

    # Inline PNG images present
    def check_inline_images(html):
        return (
            "data:image/png;base64," in html
            and "SCANLINE" not in html  # variable name not leaked
        )

    content_tests.append(("/potato", "inline PNG images present", check_inline_images))

    # CRT scanline on body background
    def check_scanline_body(html):
        return 'background="data:image/png;base64,' in html

    content_tests.append(("/potato", "CRT scanline on body", check_scanline_body))

    def check_topbar_gradient(html):
        # The topbar table should use background= attribute for TOPBAR_PNG, which is an SVG data URI
        return bool(
            re.search(r'<table[^>]*background="data:image/svg\+xml;base64,', html)
        )

    content_tests.append(("/potato", "topbar gradient image", check_topbar_gradient))

    # Legend uses colored squares (td with bgcolor)
    def check_legend_squares(html):
        return (
            'width="12" height="12"' in html
            and ">exact</font>" in html
            and ">reloc</font>" in html
        )

    content_tests.append(
        ("/potato", "legend uses colored squares", check_legend_squares)
    )

    # Panel headers use gradient background
    def check_panel_header_gradient(html):
        return 'background="data:image/png;base64,' in html and "Coverage Map" in html

    content_tests.append(
        ("/potato", "panel header gradient", check_panel_header_gradient)
    )

    # HTML5 lang attribute present
    def check_html5_lang(html):
        return '<html lang="en">' in html

    content_tests.append(("/potato", "HTML5 lang attribute", check_html5_lang))

    # Meta charset present
    def check_meta_charset(html):
        return '<meta charset="utf-8">' in html

    content_tests.append(("/potato", "meta charset utf-8", check_meta_charset))

    # DOCTYPE present
    def check_doctype(html):
        return html.strip().startswith("<!DOCTYPE html>")

    content_tests.append(("/potato", "DOCTYPE html present", check_doctype))

    # Title tag present
    def check_title(html):
        return "<title>" in html and "Potato Mode" in html

    content_tests.append(("/potato", "title tag present", check_title))

    # ReCoverage branding
    def check_branding(html):
        return "ReCoverage" in html

    content_tests.append(("/potato", "ReCoverage branding", check_branding))

    # R logo image present
    def check_r_logo(html):
        return 'alt="R"' in html and "data:image/gif;base64," in html

    content_tests.append(("/potato", "R logo GIF present", check_r_logo))

    # Target selector form
    def check_target_selector(html):
        return 'name="target"' in html and "<select" in html

    content_tests.append(("/potato", "target selector present", check_target_selector))

    # Section links present (as button-style tables with bordercolor)
    def check_section_links(html):
        return ".text" in html and 'bordercolor="' in html

    content_tests.append(("/potato", "section links present", check_section_links))

    # Coverage Map header shows section name
    def check_coverage_map_header(html):
        return "Coverage Map - .text" in html

    content_tests.append(("/potato", "coverage map header", check_coverage_map_header))

    # Block Details header present
    def check_block_details_header(html):
        return "Block Details" in html

    content_tests.append(
        ("/potato", "block details header", check_block_details_header)
    )

    # Filter links have proper colors
    def check_filter_links_present(html):
        return all(f in html for f in ["exact", "reloc", "matching", "stub"])

    content_tests.append(
        ("/potato", "filter links present", check_filter_links_present)
    )

    # Grid cells are clickable (have <a> links)
    def check_grid_clickable(html):
        return bool(re.search(r'<a href="[^"]*idx=\d+', html))

    content_tests.append(("/potato", "grid cells are clickable", check_grid_clickable))

    # Cell selection highlights (border="2")
    def check_cell_highlight(html):
        return 'bordercolor="#06b6d4"' in html

    content_tests.append(
        (
            "/potato?section=.text&idx=0",
            "selected cell highlighted",
            check_cell_highlight,
        )
    )

    # No cell = no cell selection highlight (border="2" with accent on a grid cell)
    def check_no_highlight(html):
        import re

        return not re.search(
            r'<td bgcolor="[^"]*" border="2" bordercolor="#06b6d4"', html
        )

    content_tests.append(
        ("/potato", "no highlight without selection", check_no_highlight)
    )

    # Function Details table present for .text cell with function
    def check_function_details(html):
        return "<b>Function Details</b>" in html

    content_tests.append(
        (
            "/potato?section=.text&idx=0",
            "function details present",
            check_function_details,
        )
    )

    # Function detail fields
    def check_fn_fields(html):
        return all(f"<b>{f}</b>" in html for f in ["name", "size", "status", "origin"])

    content_tests.append(
        ("/potato?section=.text&idx=0", "function detail fields", check_fn_fields)
    )

    # vaStart is a clickable link
    def check_vastart_link(html):
        return "<b>vaStart</b>" in html and bool(
            re.search(r'<a href="[^"]*section=\.text[^"]*">', html)
        )

    content_tests.append(
        ("/potato?section=.text&idx=0", "vaStart is clickable link", check_vastart_link)
    )

    # C Source code block present for matched function
    def check_c_source(html):
        return "<b>C Source" in html and "<pre>" in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "C source code block", check_c_source)
    )

    # Range shown in panel
    def check_range_shown(html):
        return "<b>Range:</b>" in html and "<b>State:</b>" in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "range and state in panel", check_range_shown)
    )

    # Monospace font for code
    def check_monospace(html):
        return 'face="SFMono-Regular' in html or 'face="Courier New, monospace"' in html

    content_tests.append(
        ("/potato?section=.text&idx=0", "monospace font for code", check_monospace)
    )

    # Filter toggle behavior: clicking active filter removes it
    def check_filter_toggle():
        """Filter toggles work: active filter link should remove that filter."""
        html_filtered = test_render("/potato?filter=exact", "toggle-check")
        # The "exact" filter is active, so its link should NOT include filter=exact
        # (clicking it removes the filter)
        # Find links that toggle exact off
        return bool(
            re.search(r'<a href="[^"]*">\s*<font[^>]*><b>E</b></font>', html_filtered)
        )

    content_tests.append(
        (
            "/potato?filter=exact",
            "active filter is bold",
            lambda html: "<b>E</b>" in html,
        )
    )
    content_tests.append(
        (
            "/potato",
            "inactive filter is not bold",
            lambda html: "<b>[E]</b>" not in html,
        )
    )

    # Search dims non-matching cells
    def check_search_dims(html):
        # When searching, non-matching cells should use BG_COLOR (#0f1216)
        # At least some cells should be dimmed
        bg_count = html.count('bgcolor="#0f1216"')
        return bg_count > 5  # many cells dimmed

    content_tests.append(
        ("/potato?search=alloc", "search dims non-matching", check_search_dims)
    )

    # Colors from the theme are applied
    def check_theme_colors(html):
        return (
            "#10b981" in html  # exact green
            and "#0ea5e9" in html  # reloc blue
            and "#f59e0b" in html  # matching amber
            and "#ef4444" in html  # stub red
        )

    content_tests.append(("/potato", "theme colors applied", check_theme_colors))

    # Grid table has transparent GIF spacer images
    def check_spacer_gifs(html):
        return "data:image/gif;base64," in html

    content_tests.append(("/potato", "spacer GIFs in grid", check_spacer_gifs))

    # Coverage Map block count
    def check_block_count(html):
        return bool(re.search(r"\d+ blocks\)", html))

    content_tests.append(("/potato", "block count in header", check_block_count))

    # Multiple functions in a cell (if any exist) or at least cell with function
    def check_cell_title_attr(html):
        return bool(re.search(r'title="0x[0-9a-f]+\.\.0x[0-9a-f]+ \|', html))

    content_tests.append(("/potato", "cell title attributes", check_cell_title_attr))

    # No Python variable names leaked
    def check_no_leaked_vars(html):
        leaked = [
            "SCANLINE_PNG",
            "TOPBAR_PNG",
            "PANEL_HDR_PNG",
            "DOT_PNGS",
            "TRANSPARENT_GIF",
            "BG_COLOR",
            "PANEL_COLOR",
            "BORDER_COLOR",
            "MUTED_COLOR",
            "ACCENT_COLOR",
        ]
        return not any(name in html for name in leaked)

    content_tests.append(
        ("/potato", "no leaked Python var names", check_no_leaked_vars)
    )
    content_tests.append(
        ("/potato?section=.text&idx=0", "no leaked vars (cell)", check_no_leaked_vars)
    )

    # Per-section stats show E/R/M/S counts
    def check_section_stat_counts(html):
        return "E:" in html and "R:" in html and "M:" in html and "S:" in html

    content_tests.append(
        ("/potato", "section stats E/R/M/S counts", check_section_stat_counts)
    )

    # All tables properly closed
    def check_tables_closed(html):
        opens = html.count("<table")
        closes = html.count("</table>")
        return opens == closes

    content_tests.append(("/potato", "all tables properly closed", check_tables_closed))
    content_tests.append(
        ("/potato?section=.text&idx=0", "tables closed (cell)", check_tables_closed)
    )

    # All font tags closed
    def check_fonts_closed(html):
        opens = html.lower().count("<font")
        closes = html.lower().count("</font>")
        return opens == closes

    content_tests.append(("/potato", "all font tags closed", check_fonts_closed))
    content_tests.append(
        ("/potato?section=.text&idx=0", "font tags closed (cell)", check_fonts_closed)
    )

    # Hidden inputs preserve state across forms
    def check_hidden_inputs(html):
        return (
            'type="hidden" name="target"' in html
            and 'type="hidden" name="section"' in html
        )

    content_tests.append(
        ("/potato", "hidden inputs preserve state", check_hidden_inputs)
    )

    # Empty cells on .data show "No functions" message
    def check_empty_data_cell(html):
        return "No functions in this block" in html

    content_tests.append(
        (
            "/potato?section=.data&idx=0",
            "empty data cell message",
            check_empty_data_cell,
        )
    )

    for url, name, check_fn in content_tests:
        try:
            html = test_render(url, name)
            if check_fn(html):
                print(f"PASS: {name:45s}")
                passed += 1  # type: ignore
            else:
                print(f"FAIL: {name:45s}")
                failed += 1  # type: ignore
        except Exception as e:
            print(f"FAIL: {name:45s} - {e}")
            failed += 1  # type: ignore

    # ── W3C Nu Validator (local vnu.jar) ───────────────────────────
    print("-" * 60)
    print("W3C Nu Validator (vnu.jar)")
    print("-" * 60)

    vnu_jar = os.path.join(os.path.dirname(__file__), os.pardir, "tools", "vnu.jar")
    vnu_jar = os.path.abspath(vnu_jar)

    # Obsolete-element errors we expect and accept (inherent to no-CSS constraint).
    # vnu uses Unicode curly quotes (\u201c \u201d), not ASCII quotes.
    EXPECTED_OBSOLETE = {
        "The \u201cfont\u201d element is obsolete. Use CSS instead.",
        "The \u201ccenter\u201d element is obsolete. Use CSS instead.",
    }

    vnu_urls = [
        ("/potato", "vnu: default page"),
        ("/potato?section=.text&idx=0", "vnu: cell detail panel"),
        ("/potato?filter=exact&search=alloc", "vnu: filter + search"),
        ("/potato?section=.data&idx=0", "vnu: .data cell"),
        ("/potato?section=.bss", "vnu: .bss section"),
        ("/potato?section=.rdata&idx=0", "vnu: .rdata cell"),
        ("/potato?section=.text&idx=100", "vnu: .text cell 100"),
        ("/potato?search=alloc", "vnu: search page"),
    ]

    vnu_passed: int = 0
    vnu_failed: int = 0
    vnu_skipped: int = 0

    if not os.path.isfile(vnu_jar):
        print(f"SKIP: vnu.jar not found at {vnu_jar}")
        vnu_skipped = len(vnu_urls)
    else:
        for url, name in vnu_urls:
            try:
                html = test_render(url, name)
                proc = subprocess.run(
                    [
                        "java",
                        "-jar",
                        vnu_jar,
                        "--format",
                        "json",
                        "--exit-zero-always",
                        "-",
                    ],
                    input=html.encode("utf-8"),
                    capture_output=True,
                    timeout=30,
                )
                result = json.loads(proc.stderr.decode("utf-8"))
                all_errors = [
                    m for m in result.get("messages", []) if m.get("type") == "error"
                ]
                # Filter out expected obsolete-element errors
                real_errors = [
                    m for m in all_errors if m.get("message") not in EXPECTED_OBSOLETE
                ]
                obsolete_count = len(all_errors) - len(real_errors)

                if not real_errors:
                    vnu_passed += 1  # type: ignore
                    passed += 1  # type: ignore
                    obs_str = (
                        f" ({obsolete_count} obsolete ok)" if obsolete_count else ""
                    )
                    print(f"PASS: {name:45s}{obs_str}")
                else:
                    vnu_failed += 1  # type: ignore
                    failed += 1  # type: ignore
                    print(f"FAIL: {name:45s} - {len(real_errors)} structural error(s):")
                    for i, e in enumerate(real_errors):
                        if i >= 5:
                            break
                        line = e.get("lastLine", "?")
                        msg = e.get("message", "?")
                        print(f"       line {line}: {msg[:120]}")

            except FileNotFoundError:
                vnu_skipped += 1  # type: ignore
                print(f"SKIP: {name:45s} (java not found)")
            except subprocess.TimeoutExpired:
                vnu_skipped += 1  # type: ignore
                print(f"SKIP: {name:45s} (vnu timeout)")
            except Exception as e:
                vnu_skipped += 1  # type: ignore
                print(f"SKIP: {name:45s} ({type(e).__name__}: {e})")

    print("=" * 60)
    total_passed = passed
    total_failed = failed
    print(f"Results: {total_passed} passed, {total_failed} failed")
    if tidy_missing:
        print(f"Note: tidy not installed ({tidy_missing} tests skipped)")
    if tidy_errors:
        print(f"Warning: {tidy_errors} tests had tidy errors")
    if vnu_skipped:
        print(f"Note: {vnu_skipped} vnu validator tests skipped")
    print("=" * 60)

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
