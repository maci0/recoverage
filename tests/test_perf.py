"""Deterministic perf regression gates (work counters, never wall clock)."""

from __future__ import annotations

import json

from conftest import decode_body, wsgi_get

from recoverage import api as _api
from recoverage import potato as _potato


def test_data_memo_skips_rebuild():
    _api._DATA_CACHE.clear()
    calls = 0
    orig = _api._build_data_raw

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    # The cold arm runs under the counter too: a probe that only ever watched
    # the warm request passes for the same `0` whether the memo answers or the
    # render path stopped building the payload at all, so the count has to be
    # shown to move once before it is trusted to stay still.
    _api._build_data_raw = counting  # type: ignore[method-assign]
    try:
        s, _, _b = wsgi_get("/api/targets/FAKEDLL/data")
        assert s.startswith("200"), s
        assert calls == 1, f"the probe never saw a cold build ({calls} calls)"
        calls = 0
        s2, _, _ = wsgi_get("/api/targets/FAKEDLL/data")
    finally:
        _api._build_data_raw = orig
    assert s2.startswith("200"), s2
    assert calls == 0, f"memo miss: rebuilt {calls}x"


#: A total no real filter produces, so a served `total` of it can only have
#: come out of the memo the test poisoned.
_POISON_TOTAL = 999_999


def test_function_list_total_memo_serves_the_repeat():
    """A repeat of the same list query must answer its total from the memo.

    The rows the endpoint paginates are one page; the total is the size of the
    whole match, so without the memo every request re-scans the full function
    table.  The memo is probed by poisoning it, because counting
    `_function_total` calls proves nothing: the endpoint calls it exactly once
    per request whether the memo answers or the count is recomputed from the
    rows it already filtered.
    """
    query = "/api/targets/FAKEDLL/functions?limit=50"
    _api._clear_list_total_cache()
    s, h, b = wsgi_get(query)
    assert s.startswith("200"), s
    first = json.loads(decode_body(b, h))
    try:
        assert _api._LIST_TOTAL_CACHE, "the first request filed no total to memoize"
        with _api._LIST_TOTAL_CACHE_LOCK:
            for key in _api._LIST_TOTAL_CACHE:
                _api._LIST_TOTAL_CACHE[key] = _POISON_TOTAL

        s2, h2, b2 = wsgi_get(query)
        assert s2.startswith("200"), s2
        second = json.loads(decode_body(b2, h2))
        assert second["total"] == _POISON_TOTAL, (
            f"memo miss: total {second['total']} was recomputed, not served"
        )
        # Only the count is memoized: the page is still built from the rows
        # the request filtered, so poisoning the count changes nothing else.
        assert second["functions"] == first["functions"]
    finally:
        _api._clear_list_total_cache()


def test_potato_grid_memo_skips_decode():
    _potato._GRID_CACHE.clear()
    calls = 0
    orig = _potato._cell_json

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    # The cells come from the frozen snapshot now, so the work a memo miss
    # would repeat is building the grid's cell objects — one call per cell.
    # The cold render is counted too: a probe that never saw the count move
    # reads the same `0` whether the memo answers or the render path stopped
    # asking for cells at all.
    _potato._cell_json = counting  # type: ignore[method-assign]
    try:
        s, h, b = wsgi_get("/potato?target=FAKEDLL&section=.text")
        assert s.startswith("200"), s
        assert calls > 0, "the probe never saw a cold build, so it cannot see a warm one"
        body1 = decode_body(b, h)
        calls = 0
        s2, h2, b2 = wsgi_get("/potato?target=FAKEDLL&section=.text")
    finally:
        _potato._cell_json = orig
    assert s2.startswith("200"), s2
    assert decode_body(b2, h2) == body1
    assert calls == 0, f"grid memo miss: cell fetch {calls}x"
