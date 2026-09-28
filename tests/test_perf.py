"""Deterministic perf regression gates (work counters, never wall clock)."""

from __future__ import annotations

from conftest import decode_body, wsgi_get

from recoverage import api as _api
from recoverage import potato as _potato


def test_data_memo_skips_rebuild():
    _api._DATA_CACHE.clear()
    s, _, _b = wsgi_get("/api/targets/FAKEDLL/data")
    assert s.startswith("200"), s
    calls = 0
    orig = _api._build_data_raw

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    _api._build_data_raw = counting  # type: ignore[method-assign]
    try:
        s2, _, _ = wsgi_get("/api/targets/FAKEDLL/data")
    finally:
        _api._build_data_raw = orig
    assert s2.startswith("200"), s2
    assert calls == 0, f"memo miss: rebuilt {calls}x"


def test_function_list_total_memo_skips_count():
    """A repeat of the same list query must not re-run the full-table COUNT."""
    _api._clear_list_total_cache()
    s, _, b = wsgi_get("/api/targets/FAKEDLL/functions?limit=50")
    assert s.startswith("200"), s
    calls = 0
    orig = _api._function_total

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    _api._function_total = counting  # type: ignore[method-assign]
    try:
        s2, _, b2 = wsgi_get("/api/targets/FAKEDLL/functions?limit=50")
    finally:
        _api._function_total = orig
    assert s2.startswith("200"), s2
    assert b2 == b
    assert calls == 1, f"memo miss: counted {calls}x for one request"


def test_potato_grid_memo_skips_decode():
    _potato._GRID_CACHE.clear()
    s, h, b = wsgi_get("/potato?target=FAKEDLL&section=.text")
    assert s.startswith("200"), s
    body1 = decode_body(b, h)
    calls = 0
    orig = _potato._cell_object

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    # The cells come from the frozen snapshot now, so the work a memo miss
    # would repeat is building the grid's cell objects — one call per cell.
    _potato._cell_object = counting  # type: ignore[method-assign]
    try:
        s2, h2, b2 = wsgi_get("/potato?target=FAKEDLL&section=.text")
    finally:
        _potato._cell_object = orig
    assert s2.startswith("200"), s2
    assert decode_body(b2, h2) == body1
    assert calls == 0, f"grid memo miss: cell fetch {calls}x"
