import os
import re
from typing import Any

import pytest
from playwright.sync_api import expect

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8787")

# Skip cleanly (not error) when the pinned playwright browser is not
# installed — e.g. CI without `uv run playwright install chromium`, or a
# version mismatch between the cache and the installed playwright package.
try:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as _p:
        _p.chromium.launch(headless=True)
    _HAS_BROWSER = True
except Exception:
    _HAS_BROWSER = False
if not _HAS_BROWSER:
    pytest.skip(
        "playwright browser not installed — run 'uv run playwright install chromium'",
        allow_module_level=True,
    )

# The tests also need a live server at BASE_URL; skip (not fail) when it
# is not running — e.g. CI that builds but does not launch the dashboard.
try:
    import urllib.request

    urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=2).close()
except Exception:
    pytest.skip(
        f"no recoverage server at {BASE_URL} — start it with 'uv run recoverage serve'",
        allow_module_level=True,
    )


def test_titles(page: Any):
    # Original UI
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".grid")
    expect(page).to_have_title("ReCoverage")

    # Potato UI
    page.goto(f"{BASE_URL}/potato")
    expect(page).to_have_title("ReCoverage - Potato Mode")


def test_sections_present(page: Any):
    # Original UI
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".tab-btn")
    og_tabs = page.locator(".tab-btn").all_inner_texts()

    # Potato UI
    page.goto(f"{BASE_URL}/potato")
    pt_tabs_text = page.locator("#section-tabs").inner_text()

    # Both should have the same sections
    for tab in og_tabs:
        assert tab in pt_tabs_text


def test_text_section_cells(page: Any):
    # Original UI
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".grid")
    page.locator(".tab-btn", has_text=".text").click()
    page.wait_for_timeout(500)  # wait for render
    og_cells = page.locator(".cell").count()

    # Potato UI
    page.goto(f"{BASE_URL}/potato?section=.text")
    pt_cells = page.locator("#grid td[bgcolor]").count()

    # The cell counts might differ slightly due to merging in potato mode,
    # but they should both be substantial (e.g. > 500)
    assert og_cells > 500
    assert pt_cells > 500


def test_filters_present(page: Any):
    # Original UI
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".filter-btn")
    og_filters = page.locator(".filter-btn").all_inner_texts()

    # Potato UI
    page.goto(f"{BASE_URL}/potato")
    pt_filters_text = page.locator("#filters").inner_text()

    # Check E, R, M, S
    for f in ["E", "R", "M", "S"]:
        assert f in og_filters
        assert f in pt_filters_text


def test_cell_selection_panel(page: Any):
    # Potato UI cell selection
    page.goto(f"{BASE_URL}/potato?section=.text&idx=0")
    panel_text = page.locator("#panel").inner_text()

    # Should show block details
    assert "Block Details" in panel_text
    assert "State:" in panel_text
    assert (
        "Function Details" in panel_text
        or "undocumented" in panel_text.lower()
        or "no functions in this block" in panel_text.lower()
        or "original bytes" in panel_text.lower()
        or "range" in panel_text.lower()
    )


def test_asm_pane_renders_disassembly(page: Any):
    """The asm fetch, formatting, and highlight live in detail.js (out of the
    inlined shell), so selecting a function must still fill the Assembly
    section — text first, then the highlight pass."""
    page.goto(f"{BASE_URL}/?section=.text")
    page.wait_for_selector(".grid")
    page.locator(".tab-btn", has_text=".text").click()
    page.wait_for_timeout(500)

    matched = page.locator(".cell.exact, .cell.reloc, .cell.near_match").first
    if matched.count() == 0:
        pytest.skip("no matched cell in .text to select")
    matched.click()

    asm = page.locator("#panel .section", has_text="Assembly").first
    expect(asm).to_contain_text(
        re.compile(r"\b(push|mov|pop|ret|call|lea|xor|add|sub|cmp|jmp|test|inc|dec)\b"),
        timeout=15000,
    )
    # highlightInto() adds hljs's class; unhighlighted plain text would not.
    expect(asm.locator("code.hljs")).to_have_count(1, timeout=15000)
