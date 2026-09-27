import os
import re
from typing import Any
from urllib.parse import urlsplit

import pytest

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8787")

# The playwright extra is not in the dev extra `make setup` installs, so a
# clean clone reaches this file with no playwright at all. A bare import would
# turn that into a ModuleNotFoundError traceback, which names the missing
# package but not the command that provides it; skip with the command instead.
try:
    from playwright.sync_api import expect, sync_playwright
except ModuleNotFoundError:
    pytest.skip(
        "playwright is not installed — run 'uv sync --extra playwright'"
        " (or 'make test-browser', which also installs chromium)",
        allow_module_level=True,
    )

# Skip cleanly (not error) when the pinned playwright browser is not
# installed — e.g. CI without `uv run playwright install chromium`, or a
# version mismatch between the cache and the installed playwright package.
try:
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
        f"no recoverage server at {BASE_URL} — start one with "
        f"'uv run recoverage serve --port {urlsplit(BASE_URL).port or 8000}'"
        f" (serve defaults to 8001, BASE_URL to {BASE_URL}), or point BASE_URL at it",
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
    # Original UI — the map is one canvas, not one DOM node per cell.
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".grid-canvas")
    page.locator(".tab-btn", has_text=".text").click()
    page.wait_for_timeout(500)  # wait for render
    canvas = page.locator(".grid-canvas")
    box = canvas.bounding_box()
    assert box is not None and box["width"] > 50 and box["height"] > 50

    # Potato UI still paints one <td> per merged cell.
    page.goto(f"{BASE_URL}/potato?section=.text")
    pt_cells = page.locator("#grid td[bgcolor]").count()
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
    page.wait_for_selector(".grid-canvas")
    page.locator(".tab-btn", has_text=".text").click()
    page.wait_for_timeout(500)

    canvas = page.locator(".grid-canvas")
    box = canvas.bounding_box()
    if box is None:
        pytest.skip("coverage map canvas did not layout")
    # Click the first cell (padding 8 + half a cell). Selecting whatever
    # lives at 0,0 is enough to exercise the asm pane.
    canvas.click(position={"x": min(12, box["width"] / 2), "y": min(12, box["height"] / 2)})

    asm = page.locator("#panel .section", has_text="Assembly").first
    expect(asm).to_contain_text(
        re.compile(r"\b(push|mov|pop|ret|call|lea|xor|add|sub|cmp|jmp|test|inc|dec)\b"),
        timeout=15000,
    )
    # highlightInto() adds hljs's class; unhighlighted plain text would not.
    expect(asm.locator("code.hljs")).to_have_count(1, timeout=15000)
