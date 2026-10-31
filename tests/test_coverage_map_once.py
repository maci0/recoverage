"""A block selection reuses the coverage map of the opened file."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import HAS_DB, decode_body, wsgi_get

from recoverage import potato as _potato

pytestmark = pytest.mark.skipif(not HAS_DB, reason="needs the synthetic coverage documents")


def test_two_selections_of_one_file_build_the_coverage_map_once() -> None:
    """Two block selections in one file build the coverage map once.

    The click names a byte range or a span. The outline is the only part of
    the map that changes. A second selection must not walk the cells again,
    and the page bytes for a selection must match a render that built the
    map for that selection alone.
    """
    _potato.clear_cells_cache()
    calls = 0
    orig = _potato._coverage_map

    def counting(
        merged_cells: list[dict[str, Any]],
        sec_data: dict[str, Any],
        grid_columns: int,
        active_filters: set[str],
        search_query: str,
        search_matched_fns: set[str],
        target: str,
        section: str,
        page_offset: int,
    ) -> _potato._CoverageMap:
        nonlocal calls
        calls += 1
        return orig(
            merged_cells,
            sec_data,
            grid_columns,
            active_filters,
            search_query,
            search_matched_fns,
            target,
            section,
            page_offset,
        )

    _potato._coverage_map = counting
    second = b""
    try:
        status, headers, body = wsgi_get("/potato?target=FAKEDLL&section=.text&idx=0")
        assert status.startswith("200"), status
        assert calls == 1, f"the probe never saw a cold build ({calls} calls)"
        first = decode_body(body, headers)

        status, headers, body = wsgi_get("/potato?target=FAKEDLL&section=.text&idx=1")
        assert status.startswith("200"), status
        second = decode_body(body, headers)
        assert calls == 1, f"a second selection rebuilt the map ({calls} builds)"
        assert first != second, "the two selections rendered one page"

        status, headers, body = wsgi_get("/potato?target=FAKEDLL&section=.text&idx=0")
        assert status.startswith("200"), status
        assert decode_body(body, headers) == first
        assert calls == 1, f"revisiting a selection rebuilt the map ({calls} builds)"
    finally:
        _potato._coverage_map = orig
        _potato.clear_cells_cache()

    status, headers, body = wsgi_get("/potato?target=FAKEDLL&section=.text&idx=1")
    assert status.startswith("200"), status
    assert decode_body(body, headers) == second
