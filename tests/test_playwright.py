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
    # Original UI: the tab names the binary and section the map is showing, so
    # two open tabs on two sections are distinguishable. The map is what says
    # the target resolved, and the target is part of the title.
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".grid")
    expect(page).to_have_title(re.compile(r"^recoverage · .+ · \S+$"))

    # Potato UI
    page.goto(f"{BASE_URL}/potato")
    expect(page).to_have_title("recoverage · Potato Mode")


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
    assert box is not None and box["width"] > 50 and box["height"] > 5
    # Laid out and painted, not merely sized: a section with a handful of cells
    # is one short row, so height alone would read as a sliver either way. The
    # painted alpha channel is what says the map drew something.
    lit = page.evaluate(
        """() => {
          const c = document.querySelector('.grid-canvas');
          const { data } = c.getContext('2d').getImageData(0, 0, c.width, c.height);
          let lit = 0;
          for (let i = 3; i < data.length; i += 4) if (data[i] !== 0) lit += 1;
          return lit;
        }"""
    )
    assert lit > 0, "the coverage map painted nothing"

    # Potato UI still paints one <td> per merged cell.  The count is the
    # section's cell count read back from the API, not a magic number: the
    # synthetic sample database carries a handful of cells, so a hard-coded
    # threshold asserted a scale this fixture never had and failed on every
    # run.  Comparing against the data is the invariant the test names.
    page.goto(f"{BASE_URL}/potato?section=.text")
    pt_cells = page.locator("#grid td[bgcolor]").count()
    cell_count = page.evaluate(
        """async (base) => {
            const targets = await (await fetch(`${base}/api/targets`)).json();
            const target = targets.targets?.[0]?.id;
            if (!target) return -1;
            const slice = await (await fetch(
                `${base}/api/targets/${encodeURIComponent(target)}/data?section=.text`
            )).json();
            return slice.sections?.[".text"]?.cells?.length ?? -1;
        }""",
        BASE_URL,
    )
    assert cell_count > 0, "the sample database has no .text cells to compare against"
    assert pt_cells >= cell_count, (
        f"potato painted {pt_cells} cells for a section holding {cell_count}"
    )


def test_filters_present(page: Any):
    # Original UI
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".filter-btn")
    og_filters = page.locator(".filter-btn").all_inner_texts()

    # Potato UI
    page.goto(f"{BASE_URL}/potato")
    pt_filters_text = page.locator("#filters").inner_text()

    # The SPA's pills print the verdict words, Potato Mode its one-letter keys,
    # one pill per state in both.
    og_text = " ".join(og_filters)
    for word, letter in [("EXACT", "E"), ("RELOC", "R"), ("NEAR", "M"), ("STUB", "S")]:
        assert word in og_text
        assert letter in pt_filters_text


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
    """Selecting a function must fill the Assembly section — text first,
    then the highlight pass."""
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


def test_search_lists_its_matches(page: Any):
    """A search that counts its matches must be able to reach them.

    Enter jumped to the first one and nothing else did, so a term matching
    hundreds of functions was only reachable by narrowing the spelling until
    one match survived. The list under the box is that answer, and a row has
    to jump: the point of the list is reaching a match that is not the first.
    """
    page.goto(f"{BASE_URL}/?section=.text")
    page.wait_for_selector(".grid-canvas")

    term = page.evaluate(
        """async (base) => {
            const targets = await (await fetch(`${base}/api/targets`)).json();
            const target = targets.targets?.[0]?.id;
            if (!target) return null;
            const data = await (await fetch(
                `${base}/api/targets/${encodeURIComponent(target)}/data?section=.text`
            )).json();
            const names = Object.keys(data.search_index ?? {});
            // A prefix shared by more than one name, so "first match" and
            // "any match" are different rows.
            const counts = new Map();
            for (const name of names) {
                const head = name.slice(0, 3).toLowerCase();
                counts.set(head, (counts.get(head) ?? 0) + 1);
            }
            for (const [head, n] of counts) {
                if (n > 1) return head;
            }
            return null;
        }""",
        BASE_URL,
    )
    if term is None:
        pytest.skip("no shared name prefix in the sample database to search for")

    page.fill("#search-input", term)
    results = page.locator(".search-results .search-result")
    expect(results.first).to_be_visible(timeout=15000)
    assert results.count() > 1, f"a term matching {results.count()} rows listed one"

    # A row selects a block: the panel leaves its no-selection state.
    results.nth(1).click()
    panel = page.locator("#panel")
    expect(panel).not_to_contain_text("Click a block on the map", timeout=15000)

    # Escape clears the query, the list and the map's dimming together.
    page.focus("#search-input")
    page.keyboard.press("Escape")
    expect(page.locator("#search-input")).to_have_value("")
    expect(page.locator(".search-results")).to_have_count(0)


def test_a_selected_block_can_be_closed(page: Any):
    """Selecting a block has to be undoable from the map.

    Once a block was open the detail panel had no way out: Escape cleared the
    search box and did nothing here, clicking the open block selected it
    again, and clicking off the lattice did nothing at all. The only escapes
    were a section or target switch, which a reader who mis-clicked a block or
    finished reading one would not think to try, so the panel stayed open over
    the map for the rest of the session.
    """
    page.goto(f"{BASE_URL}/?section=.text")
    page.wait_for_selector(".grid-canvas")

    canvas = page.locator(".grid-canvas")
    box = canvas.bounding_box()
    if box is None:
        pytest.skip("coverage map canvas did not layout")
    corner = {"x": min(12, box["width"] / 2), "y": min(12, box["height"] / 2)}

    def panel_is_open() -> bool:
        return "Select a block on the map" not in page.locator("#panel").inner_text()

    # The same block again closes it, rather than re-selecting it.
    canvas.click(position=corner)
    expect(page.locator("#panel")).not_to_contain_text("Select a block on the map", timeout=15000)
    canvas.click(position=corner)
    expect(page.locator("#panel")).to_contain_text("Select a block on the map", timeout=15000)

    # And so does Escape from the map, the way every other panel on this page
    # leaves.
    canvas.click(position=corner)
    assert panel_is_open()
    page.locator(".grid[role=application]").focus()
    page.keyboard.press("Escape")
    expect(page.locator("#panel")).to_contain_text("Select a block on the map", timeout=15000)


def test_a_block_panel_states_its_length_in_bytes(page: Any):
    """The block panel's Size is the block's byte length, `end - start`.

    It printed `span`, the cell's width in lattice units, so a 16-byte block
    read "1 bytes" beside a range and a byte dump that both said 16. The
    sample's fourth `.text` block is 16 bytes of padding with no function.
    """
    page.goto(f"{BASE_URL}/?section=.text")
    page.wait_for_selector(".grid-canvas")
    page.locator(".grid[role=application]").focus()
    for _ in range(3):
        page.keyboard.press("ArrowRight")
    page.keyboard.press("Enter")
    panel = page.locator("#panel")
    expect(panel).to_contain_text("Block 3", timeout=15000)
    expect(panel).to_contain_text("16 bytes")
    expect(panel).not_to_contain_text("1 bytes")


def test_typing_a_search_does_not_move_the_page(page: Any):
    """The search status is not a row of the topbar.

    It sat under the field and grew the sticky topbar by a wrapped line on
    the first keystroke, pushing the map down under the reader. The topbar
    keeps its height while a term is typed and the matches are listed.
    """
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{BASE_URL}/?section=.text")
    page.wait_for_selector(".grid-canvas")
    header = page.locator("header")
    before = header.bounding_box()
    assert before is not None
    page.fill("#search-input", "_func")
    expect(page.locator(".search-results")).to_be_visible(timeout=15000)
    expect(page.locator(".search-results")).to_contain_text("matches")
    after = header.bounding_box()
    assert after is not None
    assert after["height"] == before["height"], (
        f"the topbar grew from {before['height']}px to {after['height']}px on a keystroke"
    )


def test_code_modal_names_one_scroll_region(page: Any):
    """The modal's body is the pane's scroll container, so it carries the
    focusable region and its name. The <pre> inside used to declare a second
    region under the same name over the same content: two tab stops where one
    scrolls, and a screen reader reading the same line twice.

    The pane has to hold real text, because Open (like Copy) is deliberately
    off for every placeholder a pane shows. The sample document's `.text`
    functions carry no `files`, so their C Source pane holds "(no C
    implementation for this function yet)" and the button is correctly
    disabled; the `.data` block's global carries a `decl`, which is the pane's
    text. A test that clicks a block and waits 15s for a source the fixture
    never had is asserting the fixture, not the modal."""
    page.goto(f"{BASE_URL}/?section=.data")
    page.wait_for_selector(".grid-canvas")

    canvas = page.locator(".grid-canvas")
    box = canvas.bounding_box()
    if box is None:
        pytest.skip("coverage map canvas did not layout")
    canvas.click(position={"x": min(12, box["width"] / 2), "y": min(12, box["height"] / 2)})

    opener = page.locator("#panel .section", has_text="C Source").locator("button", has_text="Open")
    expect(opener).to_be_enabled(timeout=15000)
    opener.click()

    body = page.locator(".modal-body")
    expect(body).to_have_attribute("role", "region")
    expect(body).to_have_attribute("tabindex", "0")
    # Exactly one focusable region, and it is the one that scrolls.
    expect(page.locator('.modal-body [role="region"]')).to_have_count(0)
    expect(page.locator('.modal-body[role="region"]')).to_have_count(1)


# Web Vitals' "good" ceiling for cumulative layout shift; Lighthouse scores
# the load against it.
GOOD_CLS = 0.1
PHONE_VIEWPORT = {"width": 412, "height": 823}

# Sums the load's layout shifts and notes whether the empty state ever painted.
_LOAD_PROBE = """
window.__cls = 0;
window.__emptyStateSeen = false;
new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    if (!entry.hadRecentInput) window.__cls += entry.value;
  }
}).observe({ type: "layout-shift", buffered: true });
new MutationObserver(() => {
  const map = document.getElementById("section-panel");
  if (map?.textContent.includes("No coverage data for")) window.__emptyStateSeen = true;
}).observe(document, { childList: true, subtree: true, characterData: true });
"""


def test_phone_load_holds_its_layout(page: Any):
    """On a phone the panel and legend stack under the map, and the summary
    and the topbar sit above it, so a loading line or a control whose size
    changes when data arrives moved everything below it. The first frame that
    named a target also drew "No coverage data" before its load started."""
    page.set_viewport_size(PHONE_VIEWPORT)
    page.add_init_script(_LOAD_PROBE)
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector(".grid-canvas")
    page.wait_for_selector(".stats b")
    page.wait_for_timeout(500)

    assert page.evaluate("window.__emptyStateSeen") is False
    assert page.evaluate("window.__cls") < GOOD_CLS


def test_an_empty_project_shows_one_empty_state(page: Any):
    """A project with no documents is one card, not a dashboard of dead parts.

    The empty state used to sit among the filter pills, the legend, an empty
    section-tab frame and a detail panel offering Copy VA and Copy Symbol, all
    describing a map that did not exist.
    """
    page.route(
        "**/api/targets",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body='{"targets": []}'
        ),
    )
    page.goto(f"{BASE_URL}/")
    expect(page.locator("#section-panel")).to_contain_text("No coverage documents yet")
    expect(page.locator(".filter-btn")).to_have_count(0)
    expect(page.locator(".legend")).to_be_hidden()
    expect(page.locator(".tabs")).to_be_hidden()
    expect(page.locator("#panel")).to_have_count(0)


def test_a_failed_target_list_is_reported_once(page: Any):
    """A refused target list is the failure, not an empty project.

    It drew the error line, then the "no coverage" empty state under it telling
    the reader to build documents, and a target picker stuck on "Loading
    targets" beside both.
    """
    page.route(
        "**/api/targets",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error": "Database unavailable", "code": "db_unavailable", "detail": "x"}',
        ),
    )
    page.goto(f"{BASE_URL}/")
    alerts = page.locator("[role=alert]")
    expect(alerts).to_have_count(1)
    expect(alerts).to_contain_text("Database unavailable")
    expect(alerts.get_by_role("button", name="Retry")).to_have_count(1)
    # The empty state is the card that tells the reader to run the build.
    expect(page.locator("#section-panel code", has_text="rebrew coverage build")).to_have_count(0)
    expect(page.get_by_label("Target binary")).to_have_count(0)


def test_enter_on_a_search_closes_its_list(page: Any):
    """Enter jumps to a match, and the list that offered it goes with it.

    Left open, it lay over the head of the detail panel the jump had just
    filled, hiding the name of the function the reader asked for.
    """
    page.goto(f"{BASE_URL}/?section=.text")
    page.wait_for_selector(".grid-canvas")
    name = page.evaluate(
        """async (base) => {
            const targets = await (await fetch(`${base}/api/targets`)).json();
            const target = targets.targets?.[0]?.id;
            if (!target) return null;
            const data = await (await fetch(
                `${base}/api/targets/${encodeURIComponent(target)}/data?section=.text`
            )).json();
            return Object.keys(data.search_index ?? {})[0] ?? null;
        }""",
        BASE_URL,
    )
    if name is None:
        pytest.skip("the sample database has no function to search for")
    page.fill("#search-input", name)
    expect(page.locator(".search-results")).to_have_count(1, timeout=15000)
    page.keyboard.press("Enter")
    expect(page.locator(".search-results")).to_have_count(0)
    expect(page.locator("#panel-title")).to_be_visible(timeout=15000)


def test_the_panel_head_appears_with_a_selection(page: Any):
    """Before a selection the panel is its hint alone.

    Its head named the section the tabs already name, over Copy VA and Copy
    Symbol buttons with nothing to copy.
    """
    page.goto(f"{BASE_URL}/?section=.text")
    page.wait_for_selector(".grid-canvas")
    panel = page.locator("#panel")
    expect(panel).to_have_attribute("aria-label", "Block detail")
    expect(panel.locator(".panel-head")).to_have_count(0)
    expect(panel.get_by_role("button", name="Copy VA")).to_have_count(0)

    page.locator(".grid[role=application]").focus()
    page.keyboard.press("Enter")
    expect(panel.locator(".panel-head")).to_have_count(1, timeout=15000)
    expect(panel).to_have_attribute("aria-labelledby", "panel-title")
