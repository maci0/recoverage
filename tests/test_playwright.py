from typing import Any

from playwright.sync_api import expect  # type: ignore

BASE_URL = "http://localhost:8787"


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
    assert "Function Details" in panel_text or "undocumented" in panel_text.lower()
