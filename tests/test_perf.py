"""Deterministic perf regression gates (work counters, never wall clock)."""

from __future__ import annotations

import json

from conftest import decode_body, wsgi_get

from recoverage import api as _api
from recoverage import potato as _potato
from recoverage import server as _server


def test_function_list_does_not_rewalk_the_functions_table():
    """A list request must not run the marker predicate over every row.

    The data-marker rows (`server.DATA_MARKER_TYPES`) live in the functions
    array, and both the API list endpoint and `server._section_stats` drop
    them.  Dropping them is a per-row test, and the SPA's search box is a
    request per keystroke, so a per-request pass put one walk of the whole
    function table on every character typed to drop a set that cannot change
    until the next build — measured at 2.05 ms over a 40,000-function target,
    and ~20% of a search request on top of the search itself.

    A WORK COUNTER, not a clock: the arm is proven by counting calls, so this
    holds on any machine.  A search is included because that is the path the
    cost was actually paid on.
    """
    calls: list[object] = []
    real = _server._is_data_marker

    def counting(fn: object) -> bool:
        calls.append(fn)
        return real(fn)  # pyright: ignore[reportArgumentType]

    _api._clear_list_total_cache()
    snapshot_len = len(_server.coverage_for("FAKEDLL").functions)
    queries = (
        "/api/targets/FAKEDLL/functions?limit=50",
        "/api/targets/FAKEDLL/functions?limit=50&search=FAKEDLL",
    )
    for query in queries:
        # The first request builds the snapshot and the memo, so it may run the
        # predicate over the table once.  Every request after it must run it
        # ZERO times: that is the whole content of the memo.
        status, _h, _b = wsgi_get(query)
        assert status.startswith("200"), status

        calls.clear()
        _server._is_data_marker = counting  # pyright: ignore[reportAttributeAccessIssue]
        try:
            status, _h, _b = wsgi_get(query)
        finally:
            _server._is_data_marker = real  # pyright: ignore[reportAttributeAccessIssue]
        assert status.startswith("200"), status
        assert not calls, (
            f"{query} ran the marker predicate {len(calls)} times on a repeat "
            f"request over a {snapshot_len}-row functions table; the "
            "per-request pass is back"
        )


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


def test_potato_section_data_memo_skips_the_cell_walk():
    """A repeat Potato render must not re-walk every non-``.text`` cell.

    ``_load_section_data`` reaches ``server._summary``, whose per-section arm
    counts the function names every non-``.text`` cell carries — the whole cost
    of the call, over a ``.rdata`` or ``.rsrc`` of tens of thousands of cells.
    It is a pure function of the frozen snapshot, so the two memos beside it
    (``_GRID_CACHE``, ``_POTATO_STATS_CACHE``) already keyed on the same token.
    """
    _potato._SECTION_DATA_CACHE.clear()
    calls = 0
    orig = _potato.load_metadata

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    _potato.load_metadata = counting  # type: ignore[method-assign]
    try:
        s, h, b = wsgi_get("/potato?target=FAKEDLL&section=.text")
        assert s.startswith("200"), s
        assert calls > 0, "the probe never saw a cold build, so it cannot see a warm one"
        body1 = decode_body(b, h)
        calls = 0
        s2, h2, b2 = wsgi_get("/potato?target=FAKEDLL&section=.text")
    finally:
        _potato.load_metadata = orig
        _potato._SECTION_DATA_CACHE.clear()
    assert s2.startswith("200"), s2
    assert decode_body(b2, h2) == body1
    assert calls == 0, f"section-data memo miss: metadata rebuilt {calls}x"


def test_resolve_targets_memo_skips_the_coverage_reader():
    """A repeat target resolution must not walk the coverage directory again.

    ``coverage_snapshots`` is a fresh ``glob`` plus a ``stat`` per document on
    every call, whatever rebrew memoized underneath it, and the merged list is
    exactly what the memo key already proved unchanged.  Every target-scoped
    request reaches this through ``_target_snapshot``, so paying it on a hit is
    paid by the whole dashboard.
    """
    from recoverage import server as _server

    _server.clear_target_cache()
    calls = 0
    orig = _server.coverage_snapshots

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    _server.coverage_snapshots = counting  # type: ignore[method-assign]
    try:
        first = _server.resolve_targets()
        assert calls > 0, "the probe never saw a cold resolve, so it cannot see a warm one"
        calls = 0
        second = _server.resolve_targets()
    finally:
        _server.coverage_snapshots = orig
        _server.clear_target_cache()
    assert second == first
    assert calls == 0, f"target memo miss: coverage reader called {calls}x on a hit"


def test_function_detail_memo_skips_the_rebuild():
    """A repeat click of one cell must not rebuild its detail body.

    The body is `function_json` plus the verify record, then `json.dumps`.
    The ETag saves the browser that already
    holds it; this memo saves the next request, which arrives without the
    validator (a second dashboard, a prefetch, a client that dropped the tag).
    """
    _api._clear_function_cache()
    calls = 0
    orig = _server.function_json

    def counting(*a, **k):
        nonlocal calls
        calls += 1
        return orig(*a, **k)

    path = "/api/targets/FAKEDLL/functions/0x10001000"
    _server.function_json = counting  # type: ignore[method-assign]
    try:
        status, _headers, first = wsgi_get(path)
        assert status.startswith("200"), status
        assert calls == 1, f"the probe never saw a cold build ({calls} calls)"
        calls = 0
        status, _headers, second = wsgi_get(path)
    finally:
        _server.function_json = orig
        _api._clear_function_cache()
    assert status.startswith("200"), status
    assert second == first
    assert calls == 0, f"function-detail memo miss: body rebuilt {calls}x on a hit"
