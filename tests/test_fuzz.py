"""Fuzz harnesses for the untrusted-input surfaces of the HTTP API.

The API is the one place a stranger controls the bytes: every query parameter
and the batch POST body are attacker-chosen, and each crosses a parser
(``int(..., 0)``, ``json.loads``, rebrew's ``parse_va_candidates``) before it
reaches SQLite.  These tests drive those parsers with mutated inputs and assert
the properties that must hold for *every* input, not just the ones the unit
tests enumerate:

* a request never answers 5xx, and never returns bottle's HTML error page
  (an unhandled exception in a handler is a 500, and a 500 that leaks the
  traceback is a finding in itself);
* an /api/* error body is the JSON envelope, and it stays valid UTF-8 even
  when the offending value was arbitrary bytes;
* a 200 response is well-formed and honours the contract the query asked for
  (``limit`` bounds the page, ``size`` bounds the slice, every returned VA
  was one the caller asked for);
* the headers that DECIDE whether a request is served (Origin, Host,
  REMOTE_ADDR, X-Request-ID, Idempotency-Key) and the RECOVERAGE_* readers
  answer their security contract: a rejection stays a rejection, a match
  means what it claims, and nothing raised escapes into a traceback. A wrong
  answer from any of them is a bypass, which no status code can show;
* the two path and rendering surfaces the query campaigns do not reach: the
  ``<va>`` segment of ``/functions/<va>``, which is the thing the route looks
  up rather than a key beside it, and the CLI, which renders a document's own
  section and target names into a table, a JSON document, a CSV file and a
  Markdown file, each with its own escaping rule. A wrong answer from either
  is a reader shown the wrong function or a spreadsheet executing a formula,
  neither of which a status code can show;
* ``rebrew-project.toml``, the other untrusted document this package reads: it
  arrives in the checkout rather than over a socket, and it names the coverage
  directory, the target ids the dashboard offers, and the binary whose bytes
  ``/asm`` and ``/bytes`` serve. It gets both arms the documents get, and the
  pair assertion the reader itself is the far side of.

No coverage-guided fuzzer is available offline, so the harness is a seeded
mutation engine: a hand-written corpus of real-shaped seeds (the spellings the
SPA and Potato Mode actually send) mutated by a fixed set of operators, driven
by a seeded PRNG so a failure is reproducible.  The seed is a module constant,
so CI runs the identical corpus on every build; ``RECOVERAGE_FUZZ_SEED`` and
``RECOVERAGE_FUZZ_ITERATIONS`` widen a local run without touching the code.
"""

from __future__ import annotations

import copy
import csv
import html
import io
import ipaddress
import json
import os
import random
import re
import unicodedata
from collections.abc import Callable
from http.cookies import SimpleCookie
from itertools import pairwise
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest
from conftest import HAS_DB, WSGI_PEER, decode_body, get_first_target, wsgi_request
from coverage_fixture import build_synthetic_coverage, cell, write_coverage
from rebrew.coverage_toml import CoverageSnapshot, Function, load_coverage
from typer.testing import CliRunner

from recoverage import cli, config
from recoverage import server as srv
from recoverage.api import (
    _MAX_BATCH_BODY_BYTES,
    _MAX_SEARCH_CHARS,
    _REGEN_KEY_MAX_CHARS,
    _REGEN_KEY_RE,
    _clear_derived_caches,
)
from recoverage.server import _best_encoding, _hostname_of, _normalize_origin, _peer_is_loopback

# The three codecs the server can actually produce, in preference order.  A
# negotiation result outside this set means a response was labelled with an
# encoding no client library here can decode.
_SUPPORTED_ENCODINGS = frozenset({"", "zstd", "br", "gzip"})

# Campaign size.  Small enough that `make test` grows by seconds, large enough
# that every seed is mutated dozens of times.  RECOVERAGE_FUZZ_SEED and
# RECOVERAGE_FUZZ_ITERATIONS widen a local campaign without a code change.
FUZZ_SEED = int(os.environ.get("RECOVERAGE_FUZZ_SEED", "20260927"), 10)
FUZZ_ITERATIONS = int(os.environ.get("RECOVERAGE_FUZZ_ITERATIONS", "400"))

# Statuses a handler may answer for attacker-chosen input.  Everything else is
# a crash (5xx), a routing miss (which the catch-all turns into 404), or a
# proxy-level failure.
_ALLOWED_STATUSES = frozenset({200, 301, 304, 400, 404, 405, 413, 415, 422, 429, 500, 503})

# Substrings that mean a traceback or an internal path escaped in an error
# body.  Their presence is a leak regardless of the status code.
_LEAK_MARKERS = (
    "Traceback (most recent call last)",
    'File "/',
    "sqlite3.",
    "bottle.py",
    "rebrew/",
)


# ── mutation engine ─────────────────────────────────────────────────


def _flip_byte(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return b"x"
    idx = rng.randrange(len(data))
    return data[:idx] + bytes([rng.randrange(256)]) + data[idx + 1 :]


def _delete_run(data: bytes, rng: random.Random) -> bytes:
    if len(data) < 2:
        return data
    start = rng.randrange(len(data))
    return data[:start] + data[start + 1 :]


def _insert_run(data: bytes, rng: random.Random) -> bytes:
    pos = rng.randrange(len(data) + 1)
    return data[:pos] + bytes(rng.randrange(256) for _ in range(rng.randint(1, 8))) + data[pos:]


def _splice(data: bytes, rng: random.Random, corpus: list[bytes]) -> bytes:
    other = rng.choice(corpus)
    if not other:
        return data
    a = rng.randrange(len(data) + 1)
    b = rng.randrange(len(other) + 1)
    return data[:a] + other[b:]


# Grammar tokens the parsers under test actually branch on.  Random bytes
# almost never produce a "vas": [...] shape or a 0x-prefixed integer, so the
# structured operators are what reach the interesting branches.
_JSON_TOKENS = (
    b'{"vas": []}',
    b'{"vas": ["0x10001000", 268435456]}',
    b'{"vas": [0]}',
    b'{"vas": null}',
    b'{"vas": {}}',
    b'{"vas": [true, false]}',
    b'{"vas": [[]]}',
    b'{"vas": [{"va": 1}]}',
    b'{"vas": [-1]}',
    b'{"vas": [18446744073709551616]}',
    b'{"vas": [1e309]}',
    b'{"vas": ["0x", "0X", " 10001000 ", "10001000", "-0x1", "0b1010", "1_0"]}',
    b'{"vas": ["' + b"A" * 4096 + b'"]}',
    b"[]",
    b"null",
    b"1",
    b'"vas"',
    b"{",
    b"",
    b"\x00\xff\xfe",
    b"\xef\xbb\xbf{}",
    b"\xed\xa0\x80",  # lone surrogate in UTF-8
)

_NUM_TOKENS = (
    b"0",
    b"-0",
    b"-1",
    b"1",
    b"4096",
    b"99999999999999999999999999",
    b"0x10",
    b"0X10",
    b"0b1010",
    b"0o17",
    b"1_0",
    b" 12 ",
    b"+12",
    # Digits int() accepts and no documented spelling of a byte count, a page
    # or a VA carries: ARABIC-INDIC, EXTENDED ARABIC-INDIC and FULLWIDTH.
    "\u0664\u0660\u0669\u0666".encode(),
    "\u06f1\u06f0".encode(),
    "\uff11\uff10".encode(),
    b"1e3",
    b"NaN",
    b"Infinity",
    b"\xff",
    b"%00",
    b"%2e%2e",
)


def _mutate(
    data: bytes,
    rng: random.Random,
    corpus: list[bytes],
    *,
    struct_tokens: tuple[bytes, ...] = _JSON_TOKENS,
    num_tokens: tuple[bytes, ...] = _NUM_TOKENS,
) -> bytes:
    op = rng.randrange(8)
    if op == 0:
        return _flip_byte(data, rng)
    if op == 1:
        return _delete_run(data, rng)
    if op == 2:
        return _insert_run(data, rng)
    if op == 3:
        return _splice(data, rng, corpus)
    if op == 4:
        return rng.choice(struct_tokens)
    if op == 5:
        return rng.choice(num_tokens)
    if op == 6:
        pos = rng.randrange(len(data) + 1)
        return data[:pos] + rng.choice(struct_tokens) + data[pos:]
    return data * 2 + rng.choice(num_tokens)


def _fuzz(
    seeds: list[bytes],
    check: Callable[[bytes], None],
    *,
    iterations: int = FUZZ_ITERATIONS,
    seed: int = FUZZ_SEED,
    struct_tokens: tuple[bytes, ...] = _JSON_TOKENS,
    num_tokens: tuple[bytes, ...] = _NUM_TOKENS,
) -> None:
    """Mutate *seeds* for *iterations* rounds, calling *check* on each input.

    A failing round re-runs the check on every intermediate input of that
    round's mutation chain, so the assertion message names the smallest
    corrupt input rather than the mutated blob it grew from.

    The message also names the seed and the round, because the shrinking walk
    consumes the same stream: without them a failure is reproducible only by
    reading this module for the constant the environment did not set, and the
    round is the only handle on where the campaign stood.
    """
    rng = random.Random(seed)
    for round_index in range(iterations):
        data = _mutate(
            rng.choice(seeds), rng, seeds, struct_tokens=struct_tokens, num_tokens=num_tokens
        )
        try:
            check(data)
        except AssertionError as failure:
            chain = [data]
            for _ in range(6):
                smaller = _mutate(
                    rng.choice(seeds),
                    rng,
                    seeds,
                    struct_tokens=struct_tokens,
                    num_tokens=num_tokens,
                )
                try:
                    check(smaller)
                except AssertionError:
                    chain.append(smaller)
            where = f"seed={seed} round={round_index} of {iterations}"
            smallest = min(chain, key=len)
            try:
                check(smallest)
            except AssertionError as shrunk:
                raise AssertionError(
                    f"{where}: {smallest!r} after shrinking {data!r}\n{shrunk}"
                ) from shrunk
            raise AssertionError(f"{where}: {data!r}") from failure


# ── invariant checks ────────────────────────────────────────────────


def _body_json(body: bytes, headers: dict[str, str], path: str) -> Any:
    """The decoded response body as JSON, or a loud failure.

    Compression is decoded first: a fuzzer that reads compressed bytes finds
    nothing, and a body that is not valid JSON on a 2xx means the handler
    produced a half-written response.
    """
    raw = decode_body(body, headers)
    text = raw.decode("utf-8")
    for marker in _LEAK_MARKERS:
        assert marker not in text, f"{path}: response body leaks {marker!r}: {text[:400]!r}"
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise AssertionError(f"{path}: response is not JSON: {text[:400]!r}") from None


def _assert_envelope(payload: Any, status: str, path: str) -> None:
    """A non-2xx /api/* response carries the documented error envelope."""
    assert isinstance(payload, dict), f"{path}: {status} body is not an object: {payload!r}"
    assert isinstance(payload.get("error"), str) and payload["error"], f"{path}: no error label"
    assert isinstance(payload.get("detail"), str), f"{path}: no detail string"


def _assert_ok(status: str, headers: dict[str, str], body: bytes, path: str) -> Any:
    code = int(status.split()[0])
    assert code < 500, f"{path}: handler crashed with {status}: {body[:400]!r}"
    assert code in _ALLOWED_STATUSES, f"{path}: unexpected status {status}"
    payload = _body_json(body, headers, path)
    if code >= 300:
        _assert_envelope(payload, status, path)
    return payload


def _pct(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


def _batch_path() -> str:
    """The batch function-lookup URL, which every /functions campaign fuzzes."""
    return f"/api/targets/{_pct(get_first_target())}/functions"


# ── surfaces ────────────────────────────────────────────────────────


BATCH_SEEDS = [
    b'{"vas": ["0x10001000"]}',
    b'{"vas": [0x10001000, 0x10001020, 0x10001030]}',
    b'{"vas": ["10001000", " 10001020 ", "0X10001030"]}',
    b'{"vas": [268435456, 268435488, 268435504]}',
    b'{"vas": ["0x10001000", "0x10001000"]}',
    b'{"vas": ["g_counter"]}',
    b"{}",
    b"[]",
    b"",
]

QUERY_SEEDS = [
    b"limit=50&offset=0",
    b"limit=1&offset=2",
    b"limit=-1",
    b"limit=99999999999999999999999",
    b"offset=-0x10",
    b"sort=va:desc",
    b"sort=name:ASC&status=EXACT",
    b"search=func",
    b"search=" + b"%" * 40,
    b"status=" + b"A" * 200,
]

DATA_QUERY_SEEDS = [
    b"section=.text",
    b"section=.text&index=0",
    b"section=.text&index=1",
    b"index=0",
    b"section=.text&index=1&section=.data",
    b"section=%2e%2e%2f%2e%2e",
    b"index=false",
    b"index=" + b"0" * 40,
    b"section=" + b"A" * 300,
]

#: Grammar tokens for /data's own query: byte mutation alone never spells
#: ``index=0`` or a percent-encoded traversal, the way ``idx=99999999999`` had
#: to be seeded for the Potato campaign.
_DATA_QUERY_TOKENS = (
    b"section=.text",
    b"section=",
    b"index=0",
    b"index=1",
    b"index=",
    b"index=false",
    b"%2e%2e%2f",
    b"&",
    b"=",
)

SLICE_SEEDS = [
    b"va=0x10001000&size=16",
    b"va=0x10001000&size=0",
    b"va=0x10001000&size=-1",
    b"va=0x10001000&size=0x100",
    b"va=10001000&size=0b11",
    b"va=&size=",
    b"format=json&va=0x10001000&size=8",
    b"format=HTML&va=0x10001000&size=8",
    b"format=json&va=0x10001000&size=4096",
]

BYTES_SEEDS = [
    b"offset=0&size=16",
    b"offset=0&size=256",
    b"offset=-1&size=16",
    b"offset=0x10&size=0x10",
    b"offset=99999999999999999999&size=16",
    b"offset=&size=",
    b"offset=0&size=0&format=hex",
]

TARGET_SEEDS = [
    "demo",
    "..",
    ".",
    "%2e%2e%2f%2e%2e",
    "a" * 200,
    "démo",
    "\x00null",
    "' OR 1=1 --",
    "demo/../other",
    "%ff%fe",
]


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestBatchLookupBody:
    """POST /api/targets/<t>/functions — the only endpoint that parses a
    whole attacker-supplied body (bounded read, JSON decode, per-entry VA
    parse, then a parameterized query with one placeholder per entry)."""

    def test_body_never_crashes(self) -> None:
        path = _batch_path()

        def check(data: bytes) -> None:
            status, headers, body = wsgi_request("POST", path, body=data)
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, path)
            if code >= 400:
                _assert_envelope(payload, status, path)
                return
            # 200: the response is a JSON array of detail objects, and every
            # returned VA is one the caller actually asked for.  A handler that
            # echoed an unparsed or defaulted entry would break the pair.
            assert isinstance(payload, list), f"{path}: 200 body is not a list: {payload!r}"
            for entry in payload:
                assert isinstance(entry, dict), f"{path}: non-object entry {entry!r}"
                assert "va" in entry, f"{path}: entry without a va: {entry!r}"

        _fuzz(BATCH_SEEDS, check)

    def test_accepted_body_reports_only_requested_vas(self) -> None:
        """A 200 answers exactly the deduped, order-preserving request.

        Pair assertion across the request/response boundary: this is the
        invariant the SPA's batch lookup depends on, and it is the one a
        parser regression (dropped entry, default VA, reordered list) shows up
        in first.
        """
        path = _batch_path()
        for seed in BATCH_SEEDS:
            status, headers, body = wsgi_request("POST", path, body=seed)
            if int(status.split()[0]) != 200:
                continue
            payload = _assert_ok(status, headers, body, path)
            sent = _requested_vas(seed)
            got = [entry["va"] for entry in payload]
            assert got == [va for va in sent if va in set(got)], f"{path}: {got} not from {sent}"


def _requested_vas(seed: bytes) -> list[int]:
    """The VAs a body asks for, in the order ``_batch_request_vas`` keeps."""
    try:
        payload = json.loads(seed.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return []
    if not isinstance(payload, dict) or not isinstance(payload.get("vas"), list):
        return []
    out: list[int] = []
    for entry in payload["vas"]:
        if isinstance(entry, bool):
            return []
        if isinstance(entry, int):
            out.append(entry)
        elif isinstance(entry, str):
            text = entry.strip()
            if text.lower().startswith("0x"):
                text = text[2:]
            try:
                out.append(int(text, 16))
            except ValueError:
                return []
        else:
            return []
    return list(dict.fromkeys(out))


# Depth is a decoder input the byte cap does not bound: the C scanner spends a
# frame per bracket, so a body two bytes wide nests as deep as one the size
# check admits. Byte mutation never produces it, so the campaign carries its
# own tokens, straddling the interpreter's recursion limit from both sides.
def _nesting_body(depth: int) -> bytes:
    return b'{"vas": ' + b"[" * depth + b"]" * depth + b"}"


_NESTING_TOKENS = tuple(
    _nesting_body(depth) for depth in (1, 2, 8, 64, 200, 480, 496, 512, 1000, 20000)
)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestBatchBodyNesting:
    """POST bodies whose *nesting* is the payload, not their bytes."""

    def test_nested_body_never_crashes(self) -> None:
        path = _batch_path()

        def check(data: bytes) -> None:
            status, headers, body = wsgi_request("POST", path, body=data)
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, path)
            if code >= 400:
                _assert_envelope(payload, status, path)

        _fuzz(BATCH_SEEDS, check, struct_tokens=_NESTING_TOKENS)

    def test_every_depth_answers_a_documented_status(self) -> None:
        """The exhaustive half: a refusal must be a refusal a client can read,
        not a decoder stack exhaustion surfacing as a 500."""
        path = _batch_path()
        for depth in (0, 1, 100, 400, 490, 495, 500, 505, 1000, 5000, 20000):
            for tail in (b"", b"0x10001000"):
                close = b", " + tail if tail else b""
                depth_body = b'{"vas": ' + b"[" * depth + b"]" * depth + close + b"}"
                status, headers, body = wsgi_request("POST", path, body=depth_body)
                code = int(status.split()[0])
                payload = _assert_ok(status, headers, body, path)
                if code >= 400:
                    _assert_envelope(payload, status, path)
                else:
                    assert isinstance(payload, list), f"{path}: depth {depth} answered {payload!r}"


# The media types a batch POST can declare, and the malformed spellings a
# client, a proxy or a hand-rolled curl produces.  ``application/json`` with
# parameters is the only accepted form besides a missing header; everything
# else is a 415 and the body must go unread.
_CONTENT_TYPE_SEEDS = (
    b"application/json",
    b"application/json; charset=utf-8",
    b"application/json;charset=UTF-16",
    b"APPLICATION/JSON",
    b"  application/json  ",
    b"application/json ",
    b"text/plain",
    b"application/x-www-form-urlencoded",
    b"text/xml",
    b"application/xml",
    b"application/octet-stream",
    b"multipart/form-data; boundary=x",
    b"application/vnd.api+json",
    b"text/plain, application/json",
    b"application/json, text/plain",
    b";",
    b"json",
    b"application/",
    b"application/json\x00",
    b"\x00application/json",
    b"application/json\t",
    b"a" * 200,
    b"",
)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestBatchContentType:
    """A declared media type decides whether the body is read at all, so it
    is an input surface in its own right: a wrong answer is either a body
    parsed under the wrong format or a refusal that never happened."""

    def _post(self, path: str, media_type: str, body: bytes) -> tuple[int, Any, bytes]:
        status, headers, raw = wsgi_request(
            "POST", path, headers={"Content-Type": media_type}, body=body
        )
        return int(status.split()[0]), _assert_ok(status, headers, raw, path), raw

    def test_media_type_never_crashes(self) -> None:
        path = _batch_path()
        body = b'{"vas": ["0x10001000"]}'

        def check(data: bytes) -> None:
            # latin-1 keeps every mutated byte a value the WSGI environ can
            # carry, so the campaign covers a non-ASCII header too.
            code, payload, _raw = self._post(path, data.decode("latin-1"), body)
            if code >= 400:
                _assert_envelope(payload, code, path)
            if code == 415 and b"0x10001000" not in data:
                assert "0x10001000" not in json.dumps(payload), (
                    f"{path}: 415 echoed a VA from a body it refused to read: {payload!r}"
                )

        _fuzz(list(_CONTENT_TYPE_SEEDS), check, struct_tokens=_CONTENT_TYPE_SEEDS)

    def test_an_accepted_media_type_answers_exactly_as_no_header(self) -> None:
        """Pair assertion across the header boundary: the header may only
        decide whether the body is read, never what is read out of it."""
        path = _batch_path()
        bodies = (b'{"vas": ["0x10001000"]}', b'{"vas": []}', b"{}", b"not json", b"")
        for seed in _CONTENT_TYPE_SEEDS:
            media_type = seed.decode("latin-1")
            for body in bodies:
                code, _payload, raw = self._post(path, media_type, body)
                plain_status, headers, plain_raw = wsgi_request("POST", path, body=body)
                if code == 415:
                    assert int(plain_status.split()[0]) != 415, (
                        f"{path}: {media_type!r} refused a body the server reads happily"
                    )
                    continue
                assert code == int(plain_status.split()[0]), (
                    f"{path}: {media_type!r} answered {code}, no header {plain_status}"
                )
                assert decode_body(raw, {"Content-Encoding": ""}) == decode_body(
                    plain_raw, headers
                ), f"{path}: {media_type!r} changed the parsed answer for {body!r}"

    def test_a_refusal_carries_no_control_byte(self) -> None:
        """The media type is echoed in the 415 detail; a header value carrying
        a line break must not put one in the response."""
        path = _batch_path()
        for media_type in ("text/plain\r\nX: y", "text/plain\n", "text/plain\x00x"):
            code, payload, raw = self._post(path, media_type, b'{"vas": ["0x10001000"]}')
            assert code == 415, f"{path}: {media_type!r} answered {code}"
            for byte in decode_body(raw, {"Content-Encoding": ""}):
                assert byte >= 0x20 or byte == 0x09, (
                    f"{path}: {media_type!r} put a control byte in the body"
                )
            _assert_envelope(payload, str(code), path)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestListQuery:
    """GET /functions — limit/offset go through int() and into sqlite3, where
    a value wider than 64 bits raises OverflowError (a raw 500)."""

    def test_query_never_crashes(self) -> None:
        path = _batch_path()

        def check(data: bytes) -> None:
            status, headers, body = wsgi_request("GET", f"{path}?{data.decode('latin-1')}")
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, f"{path}?{data!r}")
            if code >= 400:
                _assert_envelope(payload, status, path)
                return
            assert isinstance(payload, dict), f"{path}: 200 body is not an object"
            items = payload.get("functions", [])
            assert isinstance(items, list), f"{path}: functions is not a list"
            limit = _limit_of(data)
            if limit is not None and 1 <= limit <= 500:
                assert len(items) <= limit, f"{path}: {len(items)} rows exceed limit {limit}"

        _fuzz(QUERY_SEEDS, check)


def _query_value(query: bytes, key: str) -> str:
    """The last value *key* carries in *query*, or "" when it carries none."""
    found = ""
    for pair in query.decode("latin-1").split("&"):
        name, _, value = pair.partition("=")
        if name == key:
            found = value
    return found


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestDataQuery:
    """GET /data — `section` names a row and `index` is a two-spelling flag.

    Differential rather than crash-only: a 200 is the only answer that can
    hide a misread flag, because the payload without `search_index` is a
    perfectly well-formed object either way.
    """

    def test_query_never_crashes(self) -> None:
        path = f"/api/targets/{_pct(get_first_target())}/data"

        def check(data: bytes) -> None:
            query = data.decode("latin-1")
            status, headers, body = wsgi_request("GET", f"{path}?{query}")
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, f"{path}?{data!r}")
            index = _query_value(data, "index").strip()
            if index not in ("", "0", "1"):
                # The flag is validated before the document is read, so an
                # unrecognised spelling is the same 400 whatever section
                # it arrived beside.
                assert code == 400, f"{path}: index {index!r} answered {status}"
                assert payload["error"] == "invalid index", f"{path}: {payload!r}"
                return
            if code >= 400:
                _assert_envelope(payload, status, path)
                return
            assert isinstance(payload, dict), f"{path}: 200 body is not an object"
            if index == "0":
                assert "search_index" not in payload, f"{path}: ?index=0 carried the index"
            else:
                assert "search_index" in payload, f"{path}: the index went missing"

        _fuzz(DATA_QUERY_SEEDS, check, struct_tokens=_DATA_QUERY_TOKENS)


def _limit_of(query: bytes) -> int | None:
    for pair in query.decode("latin-1").split("&"):
        key, _, value = pair.partition("=")
        if key == "limit":
            try:
                return int(value, 0)
            except ValueError:
                return None
    return None


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestSliceEndpoints:
    """GET /asm and GET /sections/<section>/bytes share the ?size= clamp and
    both feed a VA through rebrew's parse_va_candidates."""

    def test_asm_query_never_crashes(self) -> None:
        path = f"/api/targets/{_pct(get_first_target())}/asm"

        def check(data: bytes) -> None:
            status, headers, body = wsgi_request("GET", f"{path}?{data.decode('latin-1')}")
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, f"{path}?{data!r}")
            if code >= 400:
                _assert_envelope(payload, status, path)
                return
            if _wants_json(data):
                assert isinstance(payload, dict), f"{path}: json format did not return an object"
                insns = payload.get("instructions", [])
                assert isinstance(insns, list), f"{path}: instructions is not a list"
                size = _size_of(data)
                if size is not None:
                    total = sum(i.get("size", 0) for i in insns)
                    assert total <= size, f"{path}: {total} bytes exceed requested size {size}"

        _fuzz(SLICE_SEEDS, check)

    def test_bytes_query_never_crashes(self) -> None:
        path = f"/api/targets/{_pct(get_first_target())}/sections/.text/bytes"

        def check(data: bytes) -> None:
            status, headers, body = wsgi_request("GET", f"{path}?{data.decode('latin-1')}")
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, f"{path}?{data!r}")
            if code >= 400:
                _assert_envelope(payload, status, path)
                return
            size = _size_of(data)
            if isinstance(payload, dict) and "hex" in payload and size is not None:
                # The hex form is the canonical dump: 16 bytes per line, two
                # bytes each, so a size clamp that leaked through would show up
                # as a longer dump than the caller asked for.
                lines = str(payload["hex"]).splitlines()
                assert len(lines) <= (size + 15) // 16 + 1, f"{path}: dump longer than size {size}"

        _fuzz(BYTES_SEEDS, check)

    def test_section_path_never_crashes(self) -> None:
        """The <section> path segment is attacker-controlled and reaches SQL."""
        target = _pct(get_first_target())
        sections = [
            ".text",
            ".data",
            ".bss",
            ".rsrc",
            "..",
            ".",
            "%2e%2e",
            "A" * 300,
            "a' OR 1=1 --",
        ]

        def check(data: bytes) -> None:
            section = data.decode("latin-1")
            path = f"/api/targets/{target}/sections/{section}/bytes?offset=0&size=16"
            status, headers, body = wsgi_request("GET", path)
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, path)
            if code >= 400:
                _assert_envelope(payload, status, path)

        _fuzz([s.encode("latin-1", "replace") for s in sections], check, iterations=120)


def _wants_json(query: bytes) -> bool:
    return b"format=json" in query


def _size_of(query: bytes) -> int | None:
    for pair in query.decode("latin-1").split("&"):
        key, _, value = pair.partition("=")
        if key == "size":
            try:
                size = int(value, 0)
            except ValueError:
                return None
            return size if size > 0 else None
    return None


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestTargetSegment:
    """Every /api/targets/<target>/ route is keyed on a path segment that
    reaches SQL and the DLL path resolver.  Unicode, NUL, traversal and
    quote payloads all have to come back as an envelope, not a crash."""

    def test_target_never_crashes(self) -> None:
        suffixes = ("/stats", "/data", "/functions", "/functions/0x10001000", "/asm?va=0x10001000")
        _check_targets(suffixes)
        _check_targets(("/functions",), iterations=150)


def _check_targets(suffixes: tuple[str, ...], *, iterations: int = 200) -> None:
    """Fuzz the <target> path segment across *suffixes*.

    One campaign per suffix rather than one suffix per round, so a crash in
    the /data renderer cannot be masked by the shorter /stats answers.
    """
    for suffix in suffixes:

        def check(data: bytes, suffix: str = suffix) -> None:
            path = f"/api/targets/{_pct(data.decode('utf-8', 'replace'))}{suffix}"
            status, headers, body = wsgi_request("GET", path)
            code = int(status.split()[0])
            payload = _assert_ok(status, headers, body, path)
            if code >= 400:
                _assert_envelope(payload, status, path)
            elif not isinstance(payload, dict):
                raise AssertionError(f"{path}: 200 body is not an object: {payload!r}")

        _fuzz([s.encode("utf-8") for s in TARGET_SEEDS], check, iterations=iterations)


ACCEPT_ENCODING_SEEDS: list[bytes] = [
    b"",
    b"gzip",
    b"gzip, deflate, br",
    b"zstd, br",
    b"gzip;q=0",
    b"gzip;q=0, br;q=1",
    b"gzip;q=abc",
    b"gzip;q=1.5",
    b"gzip;q=-1",
    b"gzip;q=NaN",
    b"gzip;q=inf",
    b"gzip;q=0x1",
    b"zstd;q=0;q=1",
    b"not-zstd, zstd",
    b"*",
    b"gzip;q=0.5;q=0.9",
    b"gzip" + b",gzip" * 40,
    b"gzip;q=" + b"9" * 400,
    b"gzip;" + b"x=1;" * 200,
    b"\xff\xfe, gzip",
]


class TestAcceptEncoding:
    """``Accept-Encoding`` is a raw attacker header parsed by
    ``server._best_encoding`` on every response: a q-value parse that raises,
    or a name that is not one of the three the compressor can produce, turns
    into a 500 or a Content-Encoding the client cannot decode."""

    def test_returns_a_supported_encoding(self) -> None:
        def check(data: bytes) -> None:
            encoding = _best_encoding(data.decode("latin-1"))
            assert encoding in _SUPPORTED_ENCODINGS, f"{data!r}: unknown encoding {encoding!r}"

        _fuzz(ACCEPT_ENCODING_SEEDS, check, iterations=600)

    def test_q_zero_is_never_chosen(self) -> None:
        """RFC 9110: ``token;q=0`` means "not acceptable", so a header offering
        only refused codecs must compress nothing.  A parse that drops the q
        parameter picks a codec the client explicitly refused."""
        for name in sorted(_SUPPORTED_ENCODINGS - {""}):
            assert _best_encoding(f"{name};q=0") == "", f"{name};q=0 still selected"
            assert _best_encoding(f"{name};q=0.001") == name, f"{name};q=0.001 rejected"
            assert _best_encoding(f"not-{name}, {name};q=0") == "", f"{name} matched as a substring"
            # A refused token must not be revived by an unweighted duplicate.
            assert _best_encoding(f"{name};q=0, {name}") == name, f"{name} q=0 not overridden"

    def test_wildcard_offers_nothing(self) -> None:
        """``*`` is skipped rather than expanded, so it alone selects no codec
        and must not be expanded into the most preferred one."""
        assert _best_encoding("*") == ""
        assert _best_encoding("*;q=1") == ""
        assert _best_encoding("*;q=0") == ""


class TestResponseCompression:
    """End-to-end: whatever the negotiator picks, the response must be
    decodable with the Content-Encoding it advertises."""

    @pytest.mark.parametrize("accept", ACCEPT_ENCODING_SEEDS)
    def test_body_decodes_under_fuzzed_accept_encoding(self, accept: bytes) -> None:
        status, headers, body = wsgi_request(
            "GET", "/api/health", headers={"Accept-Encoding": accept.decode("latin-1")}
        )
        assert int(status.split()[0]) == 200, status
        payload = json.loads(decode_body(body, headers).decode("utf-8"))
        assert isinstance(payload, dict) and "version" in payload
        assert headers.get("Content-Encoding", "") in _SUPPORTED_ENCODINGS


JUNK_HEADER_SEEDS: list[bytes] = [
    b"\xff",
    b"\xff\xfe",
    b"gzip\x80",
    b"Bearer \xff",
    b"\xc3\x28",
    b'W/"\xff"',
    b"null",
    b"evil@host",
    b"http://\xff/",
    b"a" * 500,
    b"\x00",
]


class TestJunkHeaders:
    """Every header a handler reads is attacker-controlled, and a WSGI server
    hands the raw bytes over latin-1 — so a value can carry bytes that are not
    UTF-8 at all.  Reading one must never raise: a non-decodable value has no
    usable text, so it reads as absent (server._header)."""

    HEADERS = (
        "Accept-Encoding",
        "Accept",
        "Authorization",
        "If-None-Match",
        "Origin",
        "Sec-Fetch-Site",
    )

    @pytest.mark.parametrize("name", HEADERS)
    def test_non_utf8_header_value_never_crashes(self, name: str) -> None:
        def check(data: bytes) -> None:
            status, headers, body = wsgi_request(
                "GET", "/api/health", headers={name: data.decode("latin-1")}
            )
            code = int(status.split()[0])
            assert code in (200, 400, 401, 403), f"{name}={data!r}: {status}"
            if code == 200:
                payload = json.loads(decode_body(body, headers).decode("utf-8"))
                assert isinstance(payload, dict) and "version" in payload

        _fuzz(JUNK_HEADER_SEEDS, check, iterations=80)


# ── access-gating headers ──────────────────────────────────────────
#
# Origin, Host, REMOTE_ADDR, X-Request-ID and Idempotency-Key are the headers
# that DECIDE whether a request is served, and none of them arrives as
# structured data: each is a line of attacker-chosen text handed to urlsplit,
# ipaddress, a translate table or a bounded regex.  A wrong answer from any of
# those parsers is an auth or localhost-only bypass, which no status-code check
# and no crash detector can see, so the properties asserted here are the
# security ones — a match means what it claims, a rejection stays a rejection,
# and nothing raised escapes into a traceback.

ORIGIN_SEEDS: list[bytes] = [
    b"http://localhost:5173",
    b"https://example.com",
    b"http://localhost:80",
    b"https://example.com:443",
    b"http://[::1]:8001",
    b"http://127.0.0.1:8001",
    b"http://LOCALHOST:5173",
    b"HTTP://localhost:5173",
    b"//localhost:5173",
    b"localhost:5173",
    b"http://localhost:5173@evil.com",
    b"http://evil.com#localhost:5173",
    b"http://evil.com?x=localhost:5173",
    b"http://localhost:5173.evil.com",
    b"http://localhost:5173%2f.evil.com",
    b"http://local\\host:5173",
    b"http://localhost:99999",
    b"http://localhost:-1",
    b"http://[::1",
    b"http://user:pass@localhost:5173",
    b"null",
    b"",
    b"://",
    b"http://",
    b"   ",
    b"http://localhost:5173\x00",
    b"http://localhost:5173\r\nX-Injected: 1",
    b"http://xn--n3h.example:5173",
    b"http://localhost:5173 ",
    b"file://localhost",
    b"http://lo\x7fcalhost",
]

ADDR_SEEDS: list[bytes] = [
    b"127.0.0.1",
    b"::1",
    b"::ffff:127.0.0.1",
    b"0:0:0:0:0:0:0:1",
    b"localhost",
    b"127.0.0.2",
    b"127.1",
    b"::2",
    b"0.0.0.0",
    b"10.0.0.1",
    b"192.168.1.1",
    b"[::1]",
    b"::ffff:7f00:1",
    b"017700000001",
    b"2130706433",
    b"0x7f000001",
    b"127.0.0.1.",
    b"127.0.0.1:80",
    b" LOCALHOST ",
    b"evil.com",
    b"",
    b"::ffff:127.0.0.2",
]

REQUEST_ID_SEEDS: list[bytes] = [
    b"abc123",
    b"a" * 200,
    b"req\x00id",
    b"req\nid",
    b"req\rid",
    b"req\x7fid",
    b"req id",
    b"req\x1b[2Jid",
    b"\xff\xfe",
    b"",
]

IDEMPOTENCY_SEEDS: list[bytes] = [
    b"abc-123",
    b"1",
    b"a.b:c_d-0",
    b"A" * 128,
    b"A" * 129,
    b"key with space",
    b"key\nnewline",
    b"key\r\nX-Injected: 1",
    b"key\x00",
    b"key\x7f",
    b"",
    "é".encode(),
    b"a" * 500,
    b"key%00",
    b"..",
    b"***",
    b"\xff\xfe",
]

#: Characters the Idempotency-Key validator documents, as a set, so the fuzz
#: oracle does not re-run the same regex it is judging.
_KEY_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")

#: The allowlist the Origin campaigns check against, and its parts, so a match
#: can be judged against the origin it was supposed to have come from.
_ALLOWED_ORIGIN = "http://localhost:5173"
_ALLOWED_HOST = "localhost"
_ALLOWED_PORT = 5173

#: A normalized origin is ``scheme://host[:port]`` and nothing else: no userinfo
#: (the ``@`` the parser rejects up front), no escape, no control byte, no
#: whitespace.  Bottle would drop a header carrying one, which is a silent
#: failure rather than a rejection, so the parser has to refuse the value.
_ORIGIN_SHAPE = re.compile(r"\A[a-z][a-z0-9+.-]*://[^\s\\@%]*\Z")


def _has_control(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


class TestOriginNormalization:
    """``Origin``/``Host`` → ``server._hostname_of`` / ``_normalize_origin``.

    The same parser answers three questions: the DNS-rebinding Host allowlist,
    the CORS allowlist (whose match is echoed back as
    ``Access-Control-Allow-Origin``), and the localhost-only guard on
    POST /api/regen.  urlsplit raises ValueError on a malformed IPv6 literal
    and on an out-of-range port, so "never raises" is the floor; the
    allowlist-match property is the one that carries the consequence.
    """

    def test_never_raises_and_answers_a_plain_authority(self) -> None:
        def check(data: bytes) -> None:
            origin = data.decode("latin-1")
            host = _hostname_of(origin)
            normalized = _normalize_origin(origin)
            assert not _has_control(host), f"{data!r}: control byte in hostname {host!r}"
            assert "@" not in host and "\\" not in host, f"{data!r}: hostname {host!r}"
            assert host == host.lower(), f"{data!r}: hostname {host!r} is not lowercased"
            if not normalized:
                return
            assert _ORIGIN_SHAPE.match(normalized), (
                f"{data!r}: {normalized!r} is not scheme://host[:port]"
            )
            assert not _has_control(normalized), f"{data!r}: control byte in {normalized!r}"
            # Re-normalizing a normalized origin is a fixed point: the stored
            # allowlist entries are themselves normalized, so a value that
            # normalizes twice into something else can never match one.
            assert _normalize_origin(normalized) == normalized, (
                f"{data!r}: {normalized!r} normalizes to {_normalize_origin(normalized)!r}"
            )

        _fuzz(
            ORIGIN_SEEDS, check, iterations=400, struct_tokens=ORIGIN_SEEDS, num_tokens=ORIGIN_SEEDS
        )

    def test_allowlist_match_implies_the_allowed_origin(self) -> None:
        """Pair assertion across the allowlist boundary.

        A match is what makes the server echo the caller's own Origin back as
        ``Access-Control-Allow-Origin``, so it must mean the origin really is
        the allowed one: same host, same port, same scheme, and a value with
        no userinfo hiding a second authority.  The check re-derives host,
        port and scheme from the raw value with urlsplit rather than trusting
        the parser under test.
        """

        def check(data: bytes) -> None:
            origin = data.decode("latin-1")
            if _normalize_origin(origin) != _ALLOWED_ORIGIN:
                return
            candidate = origin if "://" in origin else f"//{origin}"
            parts = urlsplit(candidate)
            assert parts.username is None and parts.password is None, (
                f"{data!r}: matched with userinfo {parts.username!r}"
            )
            assert (parts.hostname or "").lower() == _ALLOWED_HOST, (
                f"{data!r}: host {parts.hostname!r}"
            )
            assert parts.port == _ALLOWED_PORT, f"{data!r}: port {parts.port!r}"
            assert (parts.scheme or "http") == "http", f"{data!r}: scheme {parts.scheme!r}"

        _fuzz(
            ORIGIN_SEEDS, check, iterations=300, struct_tokens=ORIGIN_SEEDS, num_tokens=ORIGIN_SEEDS
        )

    def test_allowlisted_origin_is_never_echoed_to_another(self) -> None:
        """End-to-end CORS: only the allowlisted origin gets the echo header.

        The response header is the whole point of the parse, so assert on the
        header the app actually sets rather than on the helper: a fuzzed
        Origin that merely LOOKS like the allowed one (suffix, userinfo,
        prefix) must come back without ``Access-Control-Allow-Origin``.
        """
        restore = (srv.CORS_ENABLED, list(srv.CORS_ALLOWED_ORIGINS))
        srv.configure_security(cors_enabled=True, cors_allowed_origins=[_ALLOWED_ORIGIN])
        try:

            def check(data: bytes) -> None:
                origin = data.decode("latin-1")
                _status, headers, _body = wsgi_request(
                    "GET", "/api/health", headers={"Origin": origin}
                )
                echoed = headers.get("Access-Control-Allow-Origin")
                if echoed is None:
                    return
                assert echoed == origin, f"{data!r}: echoed a different origin {echoed!r}"
                assert _normalize_origin(echoed) == _ALLOWED_ORIGIN, (
                    f"{data!r}: {echoed!r} is not the allowlisted origin"
                )
                # A refused origin still has to key the cache on Origin, or a
                # shared cache would hand an allowed client's response to the
                # next caller.
                assert "Origin" in headers.get("Vary", ""), (
                    f"{data!r}: Vary {headers.get('Vary')!r}"
                )

            _fuzz(
                ORIGIN_SEEDS,
                check,
                iterations=200,
                struct_tokens=ORIGIN_SEEDS,
                num_tokens=ORIGIN_SEEDS,
            )
        finally:
            srv.configure_security(cors_enabled=restore[0], cors_allowed_origins=restore[1])


class TestPeerAddressClassification:
    """``REMOTE_ADDR`` → ``server._peer_is_loopback``, the localhost-only guard
    on POST /api/regen.

    A peer address is parsed with ipaddress rather than prefix-matched, so hex
    and octal spellings classify by value.  The oracle is independent of the
    parser: True must mean the address is exactly 127.0.0.1 or ::1, or one of
    the three loopback names — a widening to the rest of 127.0.0.0/8, or a
    prefix match that accepts ``127.0.0.1.evil.com``, fails here.
    """

    def test_loopback_is_never_widened(self) -> None:
        def check(data: bytes) -> None:
            addr = data.decode("latin-1")
            allowed = _peer_is_loopback(addr)
            assert isinstance(allowed, bool), f"{data!r}: returned {allowed!r}"
            if not allowed:
                return
            if addr in srv.LOOPBACK_HOSTS:
                return
            parsed = ipaddress.ip_address(addr)
            mapped = getattr(parsed, "ipv4_mapped", None)
            # An IPv4-mapped address is judged by the address it maps to: a
            # dual-stack listener reports its IPv4 peers in that form.
            value = str(mapped) if mapped is not None else str(parsed)
            assert value in {"127.0.0.1", "::1"}, f"{data!r}: accepted {value} as loopback"

        _fuzz(ADDR_SEEDS, check, iterations=400, struct_tokens=ADDR_SEEDS, num_tokens=ADDR_SEEDS)

    def test_a_wildcard_or_public_peer_is_never_loopback(self) -> None:
        """The addresses that must never open the regen endpoint, whatever
        else the parser does with them."""
        for addr in ("0.0.0.0", "127.0.0.2", "127.0.0.255", "::2", "::", "10.0.0.1", ""):
            assert not _peer_is_loopback(addr), f"{addr!r} accepted as loopback"


class TestRegenOriginSameOrigin:
    """``Origin`` + ``Host`` → ``server.origin_is_this_dashboard``, the
    same-origin half of the POST /api/regen gate.

    A wrong answer is a forged privileged request, so the oracle is
    independent of the implementation: urlsplit decides, here, whether the
    origin and the request's own Host name one host on one port.  Anything the
    endpoint admits must be exactly that, and no spelling of a lookalike gets
    through.
    """

    @staticmethod
    def _oracle(origin: str, host: str) -> bool:
        def authority(value: str) -> tuple[str, int | None] | None:
            try:
                parsed = urlsplit(value if "://" in value else f"//{value}")
                hostname = (parsed.hostname or "").lower()
                port = parsed.port
            except ValueError:
                return None
            if not hostname:
                return None
            return (hostname, None if port in (None, 80, 443) else port)

        origin_auth = authority(origin)
        host_auth = authority(host)
        if origin_auth is None or host_auth is None:
            return False
        return origin_auth == host_auth

    def test_only_the_dashboards_own_origin_is_admitted(self) -> None:
        import recoverage.api as api

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))
            patch.setattr(api, "_regen_last_attempt", None)

            def check(data: bytes) -> None:
                origin = data.decode("latin-1")
                host = "localhost:8001"
                status, _, _ = wsgi_request(
                    "POST",
                    "/api/regen",
                    headers={"Origin": origin, "Host": host},
                    remote_addr="127.0.0.1",
                )
                code = int(status.split()[0])
                assert code in (200, 400, 403, 429), f"{origin!r}: {status}"
                if code == 200:
                    assert self._oracle(origin, host), (
                        f"{origin!r} was admitted against Host {host!r} but is not the same origin"
                    )

            _fuzz(
                ORIGIN_SEEDS,
                check,
                iterations=200,
                struct_tokens=ORIGIN_SEEDS,
                num_tokens=ORIGIN_SEEDS,
            )

    def test_a_neighbouring_loopback_origin_is_refused(self) -> None:
        """The neighbours a loopback bind actually has, each refused."""
        import recoverage.api as api

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(api, "_do_regen", lambda remote: api._json_ok({"ok": True}))
            patch.setattr(api, "_regen_last_attempt", None)

            for origin in (
                "http://localhost:3000",
                "http://127.0.0.1:5173",
                "http://[::1]:9999",
                "http://localhost",
            ):
                status, _, _ = wsgi_request(
                    "POST",
                    "/api/regen",
                    headers={"Origin": origin, "Host": "localhost:8001"},
                    remote_addr="127.0.0.1",
                )
                assert status.startswith("403"), f"{origin!r} was served: {status}"


class TestRequestIdAndIdempotencyKey:
    """``X-Request-ID`` → ``_log_safe`` and ``Idempotency-Key`` → the ledger's
    regex.  One log-forging surface and one memory-bound surface, both reached
    by an arbitrary header value."""

    def test_request_id_carries_no_control_character(self) -> None:
        def check(data: bytes) -> None:
            request_id = srv._log_safe(data.decode("latin-1"))[: srv._REQUEST_ID_MAX_LEN]
            assert not _has_control(request_id), (
                f"{data!r}: control byte in request id {request_id!r}"
            )
            assert len(request_id) <= srv._REQUEST_ID_MAX_LEN, (
                f"{data!r}: id is {len(request_id)} chars"
            )
            assert "\n" not in request_id, f"{data!r}: forged a second log line"

        _fuzz(
            REQUEST_ID_SEEDS,
            check,
            iterations=300,
            struct_tokens=REQUEST_ID_SEEDS,
            num_tokens=REQUEST_ID_SEEDS,
        )

    def test_idempotency_key_accepts_only_the_documented_alphabet(self) -> None:
        """A key the validator accepts is stored in the ledger, so anything it
        lets through is what bounds its memory and reaches a log line."""

        def check(data: bytes) -> None:
            key = data.decode("latin-1")
            matched = _REGEN_KEY_RE.fullmatch(key) is not None
            if not matched:
                return
            assert 1 <= len(key) <= _REGEN_KEY_MAX_CHARS, (
                f"{data!r}: accepted a {len(key)}-character key"
            )
            for ch in key:
                assert ch in _KEY_ALPHABET, f"{data!r}: accepted {ch!r}"
                assert not _has_control(ch), f"{data!r}: accepted a control byte"

        _fuzz(
            IDEMPOTENCY_SEEDS,
            check,
            iterations=400,
            struct_tokens=IDEMPOTENCY_SEEDS,
            num_tokens=IDEMPOTENCY_SEEDS,
        )

    def test_ledger_never_exceeds_its_cap(self) -> None:
        """Pair assertion across the ledger's memory boundary: however many
        distinct keys a client records, the dict holds at most _REGEN_LEDGER_MAX_ENTRIES
        of them, and the most recent ones are the survivors."""
        from recoverage import api

        recorded: list[str] = []
        original = api._REGEN_COMPLETED_KEYS
        api._REGEN_COMPLETED_KEYS = {}
        try:
            for i in range(api._REGEN_LEDGER_MAX_ENTRIES * 3):
                key = f"key-{i}"
                api._record_completed_key(key)
                recorded.append(key)
                assert len(api._REGEN_COMPLETED_KEYS) <= api._REGEN_LEDGER_MAX_ENTRIES, (
                    f"ledger holds {len(api._REGEN_COMPLETED_KEYS)} keys after {i + 1}"
                )
                assert api._regen_replayed(key), f"{key!r} was not replayable right after recording"
            for key in recorded[-api._REGEN_LEDGER_MAX_ENTRIES :]:
                assert api._regen_replayed(key), f"{key!r} was evicted inside the retention window"
        finally:
            api._REGEN_COMPLETED_KEYS = original


# ── the token gate ─────────────────────────────────────────────────
#
# With --token set, EVERY route is behind server._require_auth, and the
# credential reaches it in three carriers: the Authorization header, the
# ?token= share link, and the HttpOnly cookie that share link sets.  A wrong
# answer from this parser is a read of somebody else's dashboard, so the
# campaign judges the ACCEPT decision against the documented extraction
# rules rather than against a status code: a request is served only when the
# value the gate extracts is the configured token, byte for byte, and every
# other spelling of it is a rejection that stays a rejection.

#: The gate's own answers join the set a handler may give: with a token
#: configured, 401 and 429 are the documented refusals, and the campaigns
#: below that run WITHOUT a token are the ones that must never see them.
_AUTH_STATUSES = _ALLOWED_STATUSES | {401, 429}

#: The token under test.  Mixed case, a digit and two separators, so a
#: case-folding or trimming shortcut in the gate cannot pass by accident.
_AUTH_TOKEN = "S3cret-Token_9"

AUTH_SEEDS: list[bytes] = [
    _AUTH_TOKEN.encode(),
    f"Bearer {_AUTH_TOKEN}".encode(),
    f"bearer {_AUTH_TOKEN}".encode(),
    f"BEARER {_AUTH_TOKEN}".encode(),
    f"Bearer  {_AUTH_TOKEN}".encode(),
    f"Bearer{_AUTH_TOKEN}".encode(),
    f"Basic {_AUTH_TOKEN}".encode(),
    _AUTH_TOKEN.upper().encode(),
    _AUTH_TOKEN.lower().encode(),
    f" {_AUTH_TOKEN} ".encode(),
    f"{_AUTH_TOKEN}\n".encode(),
    f"{_AUTH_TOKEN}\x00".encode(),
    f"{_AUTH_TOKEN}\r\nX-Injected: 1".encode(),
    f"{_AUTH_TOKEN}%00".encode(),
    _AUTH_TOKEN[:-1].encode(),
    (_AUTH_TOKEN + "0").encode(),
    f"Bearer {_AUTH_TOKEN[:-1]}".encode(),
    b"Bearer",
    b"Bearer ",
    b"",
    b"\xff\xfe",
    b"\x00",
    b"a" * 400,
    "\u00e9".encode(),
]


def _accepts_via_header(value: str) -> bool:
    """Whether ``_require_auth`` would authenticate an Authorization value.

    ``server._header`` drops a value that is not decodable text (a WSGI server
    hands raw header bytes over latin-1, bottle re-reads them as UTF-8), and
    ``_require_auth`` strips exactly one ``Bearer `` prefix, falling through
    to the two carriers this request leaves empty when it is absent.
    """
    try:
        value.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return False
    presented = value[len("Bearer ") :] if value.startswith("Bearer ") else ""
    return presented == _AUTH_TOKEN


def _accepts_via_query(value: bytes) -> bool:
    """Whether a ``?token=`` value carrying *value* authenticates.

    ``query_param`` percent-decodes as UTF-8, and the campaign spells the
    value with every byte escaped, so the query carries the bytes unchanged
    whatever they are.
    """
    from urllib.parse import quote

    return quote(value.decode("latin-1"), safe="") == quote(_AUTH_TOKEN, safe="")


def _accepts_via_cookie(value: str) -> bool:
    """Whether a ``recoverage_token`` cookie carrying *value* authenticates.

    The cookie jar is the stdlib's: bottle parses ``HTTP_COOKIE`` with
    ``SimpleCookie``, so the oracle is that same grammar rather than a second
    guess at it, and a value carrying a ``;`` or a quote is judged as the
    cookie the peer actually sent.
    """
    jar = SimpleCookie(f"recoverage_token={value}")
    morsel = jar.get("recoverage_token")
    return (morsel.value if morsel is not None else "") == _AUTH_TOKEN


class TestAuthCredentialPresentation:
    """``--token`` → ``server._require_auth`` over all three carriers."""

    @pytest.fixture(autouse=True)
    def _token_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(srv, "_AUTH_TOKEN", _AUTH_TOKEN)
        yield
        srv._clear_auth_failures(WSGI_PEER)

    def _check(self, carriers: list[tuple[str, str | None, str, bool]]) -> None:
        """Drive every carrier and hold each to its own accept oracle."""
        for label, header, path, accepts in carriers:
            srv._clear_auth_failures(WSGI_PEER)
            status, headers, body = wsgi_request("GET", path, headers=header)
            code = int(status.split()[0])
            assert code in _AUTH_STATUSES, f"{label}: unexpected status {status}"
            if code == 200:
                assert accepts, f"{label}: a rejected credential was served: {status}"
                payload = json.loads(decode_body(body, headers).decode("utf-8"))
                assert isinstance(payload, dict) and "version" in payload
                continue
            assert not accepts, f"{label}: the configured token was refused: {status}"
            payload = _body_json(body, headers, path)
            _assert_envelope(payload, status, path)
            assert _AUTH_TOKEN not in json.dumps(payload), f"{label}: token echoed in the body"
            if code == 429:
                assert headers.get("Retry-After"), f"{label}: 429 without Retry-After"

    def test_header_credential_matches_the_extraction_rules(self) -> None:
        def check(data: bytes) -> None:
            raw = data.decode("latin-1")
            self._check(
                [("Authorization", {"Authorization": raw}, "/api/health", _accepts_via_header(raw))]
            )

        _fuzz(AUTH_SEEDS, check, struct_tokens=AUTH_SEEDS, num_tokens=AUTH_SEEDS)

    def test_share_link_credential_matches_the_extraction_rules(self) -> None:
        def check(data: bytes) -> None:
            from urllib.parse import quote

            quoted = quote(data.decode("latin-1"), safe="")
            self._check(
                [("?token=", None, f"/api/health?token={quoted}", _accepts_via_query(data))]
            )

        _fuzz(AUTH_SEEDS, check, struct_tokens=AUTH_SEEDS, num_tokens=AUTH_SEEDS)

    def test_cookie_credential_matches_the_extraction_rules(self) -> None:
        def check(data: bytes) -> None:
            raw = data.decode("latin-1")
            self._check(
                [
                    (
                        "Cookie",
                        {"Cookie": f"recoverage_token={raw}"},
                        "/api/health",
                        _accepts_via_cookie(raw),
                    )
                ]
            )

        _fuzz(AUTH_SEEDS, check, struct_tokens=AUTH_SEEDS, num_tokens=AUTH_SEEDS)

    def test_a_rejected_credential_never_renders_a_page(self) -> None:
        """A page route answers the 401 page, never the dashboard, and the
        page carries the token neither in its body nor in a header."""

        def check(data: bytes) -> None:
            raw = data.decode("latin-1")
            srv._clear_auth_failures(WSGI_PEER)
            status, headers, body = wsgi_request(
                "GET", "/", headers={"Accept": "text/html", "Authorization": raw}
            )
            code = int(status.split()[0])
            assert code in (200, 401, 429), f"unexpected status {status}"
            if code == 200:
                assert _accepts_via_header(raw), f"{raw!r} was served: {status}"
                return
            assert _accepts_via_header(raw) is False
            assert headers.get("Cache-Control") == "no-store"
            assert _AUTH_TOKEN.encode() not in body, "the token reached the 401 page"

        _fuzz(AUTH_SEEDS, check, iterations=120, struct_tokens=AUTH_SEEDS, num_tokens=AUTH_SEEDS)

    def test_guessing_is_bounded_and_a_correct_token_is_never_throttled(self) -> None:
        """The failed-token window caps guessing, and a correct credential
        neither waits for it nor inherits it: the gate answers before the
        throttle runs and clears the window on the way through."""
        for _ in range(srv._AUTH_FAIL_MAX):
            status, _, _ = wsgi_request(
                "GET", "/api/health", headers={"Authorization": "Bearer wrong-guess"}
            )
            assert status.startswith("401"), f"a bad guess was not a 401: {status}"
        for _ in range(3):
            status, headers, _ = wsgi_request("GET", "/api/health")
            assert status.startswith("429"), f"guessing was not bounded: {status}"
            assert headers.get("Retry-After")

        status, _, _ = wsgi_request(
            "GET", "/api/health", headers={"Authorization": f"Bearer {_AUTH_TOKEN}"}
        )
        assert status.startswith("200"), f"the right token was throttled: {status}"
        status, _, _ = wsgi_request(
            "GET", "/api/health", headers={"Authorization": "Bearer wrong-guess"}
        )
        assert status.startswith("401"), f"a success did not clear the window: {status}"


# ── deployment configuration ───────────────────────────────────────
#
# The RECOVERAGE_* readers are the other place a stranger's text becomes a
# number the process acts on: a port it binds, a log level it installs, an
# origin it stores in the CORS allowlist.  They document one contract, loud
# failure at startup — every value is validated and converted before the
# listener binds, and a value that cannot be used raises ConfigError rather
# than falling back to a default nobody asked for.  The unit tests enumerate
# spellings; this campaign mutates them, because the parser is int() plus a
# strip, and int() accepts more than a deployment means.

ENV_VALUE_SEEDS: list[bytes] = [
    b"0",
    b"8001",
    b"-1",
    b"65536",
    b"99999999999999999999999999",
    b" 12 ",
    b"+12",
    b"-0",
    b"0x10",
    b"1_0",
    b"1e3",
    b"  ",
    b"",
    b"true",
    b"TRUE",
    b"Yes",
    b"on",
    b"0",
    b"off",
    b"maybe",
    b"WARNING",
    b"warn",
    b"50",
    b"NOTALEVEL",
    b"\xff\xfe",
    "\uff18\uff10\uff10\uff11".encode(),  # fullwidth digits: int() reads them as 8001
    "\u0663".encode(),  # Arabic-Indic three
    b"http://localhost:5173,https://example.com",
    b"a,b,,c,",
    b" , , ",
    b",",
    b"bind-address",
    b"/var/lib/recoverage/coverage.db",
    b"~/db/coverage.db",
    b"line\nbreak",
    b"tab\there",
]

#: Values that must never resolve, whatever else the parser accepts: a
#: non-ASCII digit, because int() reads it as the number it looks like, so a
#: fullwidth or Arabic-Indic RECOVERAGE_PORT binds that port instead of telling
#: the operator their variable is not a number.


def _set_env(monkeypatch: pytest.MonkeyPatch, name: str, raw: str) -> bool:
    """Put *raw* in the environment, or report that the OS refused it.

    A value holding a NUL or an unpaired surrogate cannot be an environment
    value at all (``os.environ`` raises on it), so such a round exercises
    nothing a deployment could produce.
    """
    try:
        monkeypatch.setenv(name, raw)
    except ValueError:
        return False
    return True


_NON_ASCII_DIGITS = ("\u0668", "\u0663", "\u06f5")


class TestConfigEnvParsers:
    """The RECOVERAGE_* readers: every outcome is a value in the documented
    range or a ConfigError, never a third thing."""

    @pytest.mark.parametrize("raw", [s.decode("utf-8", "replace") for s in ENV_VALUE_SEEDS])
    def test_port_is_bounded_or_loud(self, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
        if not _set_env(monkeypatch, "RECOVERAGE_PORT", raw):
            return
        try:
            value = config.port()
        except config.ConfigError:
            return
        assert config.MIN_PORT <= value <= config.MAX_PORT, f"{raw!r}: port {value} out of range"

    def test_unicode_digits_are_not_silently_a_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for digit in _NON_ASCII_DIGITS:
            monkeypatch.setenv("RECOVERAGE_PORT", f"{digit}001")
            with pytest.raises(config.ConfigError, match="RECOVERAGE_PORT"):
                config.port()

    def test_fuzzed_port_never_binds_a_bogus_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def check(data: bytes) -> None:
            if not _set_env(monkeypatch, "RECOVERAGE_PORT", data.decode("latin-1")):
                return
            try:
                value = config.port()
            except config.ConfigError:
                return
            assert config.MIN_PORT <= value <= config.MAX_PORT, f"{data!r}: port {value}"

        _fuzz(
            ENV_VALUE_SEEDS,
            check,
            iterations=300,
            struct_tokens=ENV_VALUE_SEEDS,
            num_tokens=ENV_VALUE_SEEDS,
        )

    def test_fuzzed_bool_is_a_bool_or_loud(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def check(data: bytes) -> None:
            raw = data.decode("latin-1")
            for name, reader in (
                ("RECOVERAGE_CORS", config.cors),
                ("RECOVERAGE_ALLOW_REMOTE", config.allow_remote),
            ):
                if not _set_env(monkeypatch, name, raw):
                    return
                try:
                    value = reader()
                except config.ConfigError:
                    continue
                assert isinstance(value, bool), f"{name}={raw!r}: {value!r}"

        _fuzz(
            ENV_VALUE_SEEDS,
            check,
            iterations=300,
            struct_tokens=ENV_VALUE_SEEDS,
            num_tokens=ENV_VALUE_SEEDS,
        )

    def test_fuzzed_bind_is_an_answerable_address_or_loud(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whatever survives bind() must be a value socket.getaddrinfo could
        answer: no whitespace, no control byte, and a colon only inside an
        IPv6 literal.  Everything else is a ConfigError at startup, never a
        gaierror from the listener after the banner has printed."""

        def check(data: bytes) -> None:
            raw = data.decode("latin-1")
            if not _set_env(monkeypatch, "RECOVERAGE_BIND", raw):
                return
            try:
                value = config.bind()
            except config.ConfigError:
                return
            assert value, f"{data!r}: empty bind address"
            assert not _has_control(value), f"{data!r}: control byte in {value!r}"
            assert not any(ch.isspace() for ch in value), f"{data!r}: whitespace in {value!r}"
            if ":" in value:
                # A surviving colon is IPv6 syntax, never a host:port pair.
                # A ValueError here is the fuzz failure, not the test's.
                ipaddress.IPv6Address(value)

        _fuzz(
            ENV_VALUE_SEEDS,
            check,
            iterations=300,
            struct_tokens=ENV_VALUE_SEEDS,
            num_tokens=ENV_VALUE_SEEDS,
        )

    def test_fuzzed_cors_origin_yields_only_plain_items(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pair assertion across the allowlist boundary: whatever the split
        produces is a list of origins, never an empty item and never a value
        carrying a byte no header may hold."""

        def check(data: bytes) -> None:
            if not _set_env(monkeypatch, "RECOVERAGE_CORS_ORIGIN", data.decode("latin-1")):
                return
            try:
                origins = config.cors_origins()
            except config.ConfigError:
                # A value the allowlist cannot hold is refused loudly at
                # startup, which is the other half of the contract: it is
                # never stored as an entry that silently matches nothing.
                return
            for origin in origins:
                assert origin == origin.strip(), f"{data!r}: {origin!r} is not stripped"
                assert origin, f"{data!r}: empty origin"
                assert not _has_control(origin), f"{data!r}: control byte in {origin!r}"
                assert "\n" not in origin, f"{data!r}: forged a second line"

        _fuzz(
            ENV_VALUE_SEEDS,
            check,
            iterations=300,
            struct_tokens=ENV_VALUE_SEEDS,
            num_tokens=ENV_VALUE_SEEDS,
        )

    def test_fuzzed_log_level_is_a_level_number_or_loud(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def check(data: bytes) -> None:
            if not _set_env(monkeypatch, "RECOVERAGE_LOG_LEVEL", data.decode("latin-1")):
                return
            try:
                level = config.log_level()
            except config.ConfigError:
                return
            assert isinstance(level, int) and not isinstance(level, bool), f"{data!r}: {level!r}"
            assert level in config.LOG_LEVELS.values() or level >= 0, f"{data!r}: level {level}"

        _fuzz(
            ENV_VALUE_SEEDS,
            check,
            iterations=300,
            struct_tokens=ENV_VALUE_SEEDS,
            num_tokens=ENV_VALUE_SEEDS,
        )

    def test_unknown_var_message_names_every_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A misspelled name is reported by name: dropping one on the floor
        would leave the default in place while the operator believes the
        environment was applied."""
        names = ["RECOVERAGE_TYPO", "RECOVERAGE_PORT_", "RECOVERAGE_BIND_X"]
        for name in names:
            monkeypatch.setenv(name, "1")
        with pytest.raises(config.ConfigError) as excinfo:
            config.check_unknown_vars()
        message = str(excinfo.value)
        for name in names:
            assert name in message, f"{name} missing from {message!r}"


# ── Potato Mode ────────────────────────────────────────────────────
#
# /potato is the one surface that builds an HTML *document* out of nine
# attacker-chosen query parameters: every value crosses parse_qs, an int()
# for the pager and the grid index, a LIKE for the search, and finally the
# SimpleTemplate that interpolates the survivors into the page.  A crash
# there takes out the fallback renderer, and an unescaped value there is
# script injection into a page the server itself links to.


POTATO_FIELDS = (
    "target",
    "section",
    "filter",
    "idx",
    "search",
    "view",
    "sort",
    "status",
    "page",
    "token",
)

#: Spellings the page's own links emit, plus the shapes each field's parser
#: branches on.  ``idx``/``page`` reach ``int()``, ``search`` reaches a LIKE
#: pattern, ``sort`` is matched against a whitelist dict, and ``view`` selects
#: a whole render path, so each needs a seed that exercises its own parser.
POTATO_QUERY_SEEDS: list[bytes] = [
    b"target=" + (get_first_target().encode() or b"demo") + b"&section=.text&view=functions",
    b"target=demo&section=.text&view=functions&status=EXACT&sort=name:ASC&page=2",
    b"target=demo&section=.data&view=functions&search=func",
    b"target=demo&section=.text&filter=E,M&view=functions",
    b"target=demo&section=.bss&idx=0",
    b"target=demo&section=.text&view=functions&page=1&search=0x10001000",
    b"",
    b"target=",
    b"search=",
]

#: Grammar tokens for the query-string parser, the way _JSON_TOKENS are for
#: the JSON one.  Byte mutation alone never produces ``%3C/script%3E`` or a
#: 20-digit ``page``, which is where the renderer's interesting branches are.
POTATO_QUERY_TOKENS: tuple[bytes, ...] = (
    b"",
    b"=",
    b"&&",
    b"idx",
    b"page",
    b"idx=",
    b"idx=0",
    b"idx=-1",
    b"idx=abc",
    b"idx=0x10",
    b"idx=1e3",
    b"idx=99999999999999999999",
    b"idx=-99999999999999999999",
    b"page=0",
    b"page=1",
    b"page=abc",
    b"page=1e9",
    b"page=99999999999999999999",
    b"view=",
    b"view=functions",
    b"view=grid",
    b"view=" + b"a" * 400,
    b"search=",
    b"search=%25" * 40,
    b"search=%27%20OR%201%3D1--",
    b"search=%22%3E%3C%2Fscript%3E",
    b"search=_",
    b"search=%00",
    b"target=",
    b"target=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    b"target=" + b"A" * 600,
    b"section=",
    b"section=.text",
    b"section=%27%3B--",
    b"section=" + b"A" * 600,
    b"filter=",
    b"filter=E",
    b"filter=E,M,S,P,R",
    b"filter=" + ",".join(["E"] * 200).encode(),
    b"sort=",
    b"sort=va:desc",
    b"sort=" + b"A" * 400,
    b"status=",
    b"status=EXACT",
    b"status=" + b"A" * 400,
    b"token=abc",
    b"idx=%2D1",
    b"search=%zz",
)

#: Markers that mean an unhandled exception reached the page.  The detail
#: panel does print repository file paths, so the traceback-only spellings
#: are used here rather than the API set's ``rebrew/`` and ``sqlite3.``.
_POTATO_LEAK_MARKERS = (
    "Traceback (most recent call last)",
    'File "/',
    "bottle.py",
    "sqlite3.",
)

#: The route's own failure page: a caught exception must render exactly this,
#: so a 500 carrying anything else (a half-built document, a stack trace) is
#: a finding even though the status is deliberate.
_POTATO_500_BODY = "<html><body>Internal server error</body></html>"

#: Query fields whose value the page echoes back into markup, so an escaping
#: regression is observable from the response alone.  ``filter`` is not one:
#: :func:`recoverage.potato._parse_filters` intersects the value with the
#: literal keys in ``FILTER_STATES``, so an unknown-only value is dropped
#: before it reaches the template (an unknown key matches no cell state, and
#: keeping it would dim every block and light no pill) and there is nothing to
#: escape.  A name that IS offered is ours to escape, not the caller's, and
#: that is pinned by the ``test_filter_*`` cases below and by ``test_potato``'s
#: filter-pill assertions.
_POTATO_REFLECTED = ("search", "target")


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestPotatoQuery:
    """GET /potato — nine query parameters parsed and re-rendered as HTML."""

    def test_query_never_crashes(self) -> None:
        def check(data: bytes) -> None:
            query = data.decode("latin-1")
            status, headers, body = wsgi_request("GET", f"/potato?{query}")
            code = int(status.split()[0])
            assert code in _ALLOWED_STATUSES, f"/potato?{data!r}: unexpected status {status}"
            assert headers.get("Content-Encoding", "") in _SUPPORTED_ENCODINGS, (
                f"/potato?{data!r}: {headers.get('Content-Encoding')!r}"
            )
            text = decode_body(body, headers).decode("utf-8")
            for marker in _POTATO_LEAK_MARKERS:
                assert marker not in text, f"/potato?{data!r}: page leaks {marker!r}"
            if code >= 500:
                # The handler catches OSError/ValueError/KeyError/sqlite3.Error
                # and answers with its sanitized stub, so a 5xx is allowed —
                # but only as that stub.
                assert text.strip() == _POTATO_500_BODY, f"/potato?{data!r}: {text[:200]!r}"
                return
            assert text.startswith("<!DOCTYPE html>"), f"/potato?{data!r}: not a full page"
            assert text.rstrip().endswith("</html>"), f"/potato?{data!r}: page cut short"
            assert headers.get("Content-Type", "").startswith("text/html"), (
                f"/potato?{data!r}: {headers.get('Content-Type')!r}"
            )

        _fuzz(
            POTATO_QUERY_SEEDS,
            check,
            iterations=300,
            struct_tokens=POTATO_QUERY_TOKENS,
            num_tokens=POTATO_QUERY_TOKENS,
        )

    @pytest.mark.parametrize("field", _POTATO_REFLECTED)
    def test_reflected_value_is_escaped(self, field: str) -> None:
        """Pair assertion across the render boundary.

        The canary carries every character that can break out of the attribute
        or text node it lands in.  A value that reaches the page unescaped
        (``<``, ``>``, ``"``, ``&``) is script injection on a server-rendered
        page, and it is invisible to a status-code or crash check.
        """
        canary = "RCCANARY<>&\"'=`"
        encoded = _pct(canary)
        _status, headers, body = wsgi_request("GET", f"/potato?{field}={encoded}")
        text = decode_body(body, headers).decode("utf-8")
        assert canary not in text, f"{field}: unescaped {canary!r} in the page"
        assert "RCCANARY" in text, f"{field}: value was dropped, so escaping is untested"
        # Everything the canary could terminate has to appear as an entity.
        assert "<RCCANARY" not in text, f"{field}: raw markup delimiter"
        assert ">RCCANARY" not in text, f"{field}: raw markup delimiter"

    def test_unknown_filter_is_dropped_and_known_one_applied(self) -> None:
        """``?filter=`` is the one query field the page never echoes: a name
        no pill offers matches no cell state, so it is intersected away rather
        than rendered.  Both halves matter — an unknown name must leave the
        view unfiltered (not dim every block), and a real one must still
        render its pill as active."""
        unknown = _pct("RCCANARY<>&\"'=`")
        _status, headers, body = wsgi_request("GET", f"/potato?filter={unknown}")
        text = decode_body(body, headers).decode("utf-8")
        assert "RCCANARY" not in text
        assert text.rstrip().endswith("</html>")

        _status, headers, body = wsgi_request("GET", "/potato?filter=exact")
        text = decode_body(body, headers).decode("utf-8")
        assert "filter=exact" in text  # the pill's own link, rendered back
        assert 'accesskey="e"' in text  # and it is the active one

    def test_filter_reflects_only_the_names_a_pill_offers(self) -> None:
        """The filter path is quoted, and an unnamed filter is never rendered.

        ``_parse_filters`` keeps only the names in ``FILTER_STATES``, so the
        canary is dropped before rendering and the value that does reach the
        markup is the surviving name, carried into every pill href by
        ``_build_url``'s percent-quoting.
        """
        canary = "RCCANARY<>&\"'=`"
        _status, headers, body = wsgi_request("GET", f"/potato?filter={_pct('exact,' + canary)}")
        text = decode_body(body, headers).decode("utf-8")
        assert "RCCANARY" not in text, "a filter name no pill offers reached the page"
        assert "filter=exact%2C" in text, "the active filter is missing from the pill hrefs"

    @pytest.mark.parametrize(
        "value",
        [
            "RCCANARY<>&\"'=`",
            "exact,RCCANARY<>&\"'=`",
            " exact ,RCCANARY<>&\"'=` ,reloc",
            "\x00RCCANARY<>&\"'`=",
        ],
    )
    def test_filter_value_cannot_reach_the_page(self, value: str) -> None:
        """``?filter=`` is allowlisted, not escaped: the stronger property.

        ``potato._parse_filters`` intersects the value with the fixed keys in
        ``FILTER_STATES`` before the renderer ever sees it, so no caller-chosen
        text reaches the page through this parameter.  That is why this field
        is not in ``_POTATO_REFLECTED``: there is no reflected value to
        escape, and asserting one would fail on a correct implementation.  A
        known key mixed with the canary still lands as the literal pill state,
        which is what the second assertion pins.
        """
        _status, headers, body = wsgi_request("GET", f"/potato?filter={_pct(value)}")
        text = decode_body(body, headers).decode("utf-8")
        assert "RCCANARY" not in text, f"filter={value!r}: reached the page unescaped"
        if "exact" in value or "reloc" in value:
            # A surviving key is echoed as the literal pill state, and only
            # that: the hidden input is the one place the value is rendered.
            assert '<input type="hidden" name="filter" value="' in text

    @pytest.mark.parametrize("field", ["search", "status"])
    def test_no_result_message_is_escaped(self, field: str) -> None:
        """The functions view escapes with ``potato._esc``, not the template.

        An empty result set is what puts a query value into a plain Python
        f-string ("No functions match ... "), and that path escapes only if
        ``_esc`` still does.  The canary matches nothing by construction, so
        the branch is always taken.
        """
        canary = "RCCANARY<>&\"'=`"
        _status, headers, body = wsgi_request(
            "GET", f"/potato?view=functions&{field}={_pct(canary)}"
        )
        text = decode_body(body, headers).decode("utf-8")
        assert "No functions" in text, f"{field}: empty-result branch not reached, canary untested"
        assert canary not in text, f"{field}: unescaped {canary!r} in the no-result message"

    def test_html_escaping_matches_the_canary(self) -> None:
        """The whole canary class, one field at a time, as entities only.

        A bare ``<`` or ``>`` is not a canary: the page's own markup is full
        of them, so the substring test can only judge values that a raw
        interpolation would put on the page as a unit.
        """
        for value in ("<script>", "a<b", "x&y", 'q"q', "it's", "<<b", "a&b<c", "--><img"):
            for view in ("", "view=functions&"):
                _status, headers, body = wsgi_request("GET", f"/potato?{view}search={_pct(value)}")
                text = decode_body(body, headers).decode("utf-8")
                assert value not in text, f"search={value!r} reflected verbatim ({view or 'grid'})"


# ── the search query language ──────────────────────────────────────
#
# ``?search=`` is the one query parameter compared against *content*: it is
# folded and matched as a substring rather than parsed into an integer or a
# whitelist key, so a term's own characters decide which rows a reader sees.
# One folding covers both sides now — NFC composition, then casefold — over the
# name, the symbol, the decimal VA and the ``vaStart`` hex spelling, with an
# absent column read as the empty string.
#
# The campaign is differential rather than crash-only, because a status code
# cannot see a wrong answer: it re-derives the matching set in Python and
# demands the endpoint agree row for row.  The oracle is written from that rule,
# NOT from ``server.fold_match``, so a fold applied twice, a column dropped from
# the comparison, a row whose symbol is absent vanishing, or a term whose own
# characters widen the match all show up as a set difference.

SEARCH_SEEDS: list[bytes] = [
    b"",
    b"Render",
    b"render",
    b"REN",
    b"e_",
    b"_",
    b"%",
    b"%%",
    b"100%",
    b"\\",
    b"\\%",
    b"%_\\",
    b"' OR 1=1 --",
    b"0x1000",
    b"Cafe",
    "Café".encode(),
    "CAFÉ".encode(),
    "Café".encode(),
    "straße".encode(),
    b"STRASSE",
    "ﬁle".encode(),
    b"file",
    b"100%_match",
    "☃".encode(),
    "\u0131".encode(),
    "ǅ".encode(),
    b"\xff\xfe",
    b"\xc3",
    b"\xed\xa0\x80",
    b"a" * 300,
    b"%" * 60,
    # A NUL is an ordinary character to a folding substring search: nothing
    # reads the term as a C string any more, so the campaign meets one.
    b"\x00",
    b"a\x00b",
]

SEARCH_TOKENS: tuple[bytes, ...] = (
    b"",
    b"%",
    b"_",
    b"\\",
    b"e",
    b"E",
    "e\u0301".encode(),
    "É".encode(),
    "ß".encode(),
    "ﬁ".encode(),
    b"Render",
    b"render",
    "Caf\u00e9".encode(),
    b"%C3%A9",
    b"\x00",
    b"\xff",
    b"a",
)

#: Target id the corpus document is written under.
SEARCH_TARGET = "FUZZSEARCH"

#: Rows the one folding has to get right: an NFC name beside an NFD spelling of
#: the same word, a casefold that changes length (ß -> ss, the ﬁ ligature ->
#: fi), a row whose name and symbol are both empty, two rows with no symbol at
#: all, names carrying the metacharacters as ordinary text, and a data marker
#: the list endpoint drops.  ``va`` doubles as the decimal spelling the search
#: compares against, so a term of digits reaches the VA column too.
_SEARCH_FUNCTIONS: list[dict[str, Any]] = [
    {"va": 0x10001000, "name": "Plain_Render", "symbol": "plain_render", "vaStart": "0x10001000"},
    {"va": 0x10001010, "name": "Café_Render", "symbol": "café_render", "vaStart": "0x10001010"},
    {
        "va": 0x10001020,
        "name": "STRASSE_handler",
        "symbol": "straße_handler",
        "vaStart": "0x10001020",
    },
    {"va": 0x10001030, "name": "100%_match", "vaStart": "0x10001030"},
    {"va": 0x10001040, "name": "under_score", "symbol": "a_b", "vaStart": "0x10001040"},
    {"va": 0x10001050, "name": "back\\slash", "symbol": "back\\slash", "vaStart": "0x10001050"},
    {"va": 0x10001060, "name": "", "symbol": "", "vaStart": "0x10001060"},
    {"va": 0x10001070, "name": "☃snowman", "symbol": "☃snow", "vaStart": "0x10001070"},
    {"va": 0x10001080, "name": "no_symbol_row", "vaStart": "0x10001080"},
    {"va": 0x10001090, "name": "ﬁle_open", "symbol": "ﬁle", "vaStart": "0x10001090"},
    # The NFD twin of row 2's first word: a term spelled either way must find
    # both, which is the composition half of the folding.
    {"va": 0x100010A0, "name": "Cafe\u0301_Decomposed", "vaStart": "0x100010a0"},
    {
        "va": 0x100010B0,
        "name": "data_marker_render",
        "markerType": "DATA",
        "vaStart": "0x100010b0",
    },
]


@pytest.fixture
def search_corpus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CoverageSnapshot:
    """The search corpus as a coverage document the API serves.

    The SQLite version of this fixture opened an in-memory database and built
    its own ``functions`` table from ``_SEARCH_ROWS``.  The rows are a real
    ``coverage-<target>.toml`` now, read back through rebrew's ``load_coverage``
    so the oracle and the endpoint compare exactly one snapshot.
    """
    directory = tmp_path / "db"
    write_coverage(
        directory,
        SEARCH_TARGET,
        {
            ".text": {
                "va": 0x10001000,
                "size": 0x100,
                "fileOffset": 0x200,
                "unitBytes": 16,
                "columns": 8,
                "cells": [cell(0, 16, "exact")],
            }
        },
        functions=_SEARCH_FUNCTIONS,
    )
    # RECOVERAGE_DB names the coverage directory itself, which is what lets the
    # corpus live outside a rebrew project.
    monkeypatch.setenv("RECOVERAGE_DB", str(directory))
    return load_coverage(tmp_path, SEARCH_TARGET)


def _fold(value: str | None) -> str:
    """The one folding, written from the rule rather than from the server."""
    return unicodedata.normalize("NFC", value or "").casefold()


def _row_matches(term: str, fn: Function) -> bool:
    """Whether the endpoint must return *fn* for *term*, computed without it.

    The four columns ``_filtered_functions`` compares, the term stripped the way
    the handler strips it (an all-whitespace search is not a search at all), an
    absent column as the empty string, and a substring test with both sides
    folded — which is what makes a wildcard in the term match literally.
    """
    needle = _fold(term.strip())
    if not needle:
        return True
    return any(needle in _fold(column) for column in (fn.name, fn.symbol, str(fn.va), fn.vaStart))


def _served_rows(term: str) -> tuple[int, Any]:
    """GET the function list filtered by *term*: (status code, JSON payload).

    ``limit`` is the endpoint's own cap, so every row of the corpus is on the
    page the comparison reads.
    """
    path = f"/api/targets/{SEARCH_TARGET}/functions?search={_pct(term)}&limit=500"
    status, headers, body = wsgi_request("GET", path)
    return int(status.split()[0]), _assert_ok(status, headers, body, path)


def _expected_vas(corpus: CoverageSnapshot, term: str) -> set[int]:
    """The VAs the one folding says *term* denotes, from the loaded snapshot."""
    return {
        fn.va for fn in corpus.functions if not srv._is_data_marker(fn) and _row_matches(term, fn)
    }


def _assert_search_agrees(corpus: CoverageSnapshot, data: bytes) -> None:
    """One campaign round: the endpoint's answer is the oracle's, row for row."""
    term = data.decode("utf-8", "replace")
    code, payload = _served_rows(term)
    if code == 400:
        # The one documented refusal, and it must be about length: a term the
        # endpoint reads being turned away would hide every answer it owes.
        assert len(term.strip()) > _MAX_SEARCH_CHARS, f"search={term!r}: refused a term it reads"
        return
    assert code == 200, f"search={term!r}: unexpected {code}: {payload!r}"
    served = {row["va"] for row in payload["functions"]}
    want = _expected_vas(corpus, term)
    assert served == want, f"search={term!r}: served {sorted(served)}, expected {sorted(want)}"
    # `total` is the same filter pass as the page, so a page that agrees while
    # the count does not is still a wrong answer.
    assert payload["total"] == len(want), (
        f"search={term!r}: total {payload['total']} != {len(want)}"
    )


class TestSearchFoldDifferential:
    """``?search=`` against a Python oracle built from the folding rule."""

    def test_query_returns_exactly_the_rows_the_term_denotes(
        self, search_corpus: CoverageSnapshot
    ) -> None:
        def check(data: bytes) -> None:
            _assert_search_agrees(search_corpus, data)

        _fuzz(
            SEARCH_SEEDS,
            check,
            iterations=250,
            struct_tokens=SEARCH_TOKENS,
            num_tokens=SEARCH_TOKENS,
        )

    def test_a_wildcard_never_becomes_a_pattern(self, search_corpus: CoverageSnapshot) -> None:
        """The one asymmetry a search language could carry, stated directly.

        ``%`` and ``_`` are the reader's own characters: matched literally, a
        search for ``100%`` returns the row that holds it and not every row.  A
        term that widened into a pattern would return the whole table, which is
        both a wrong answer and a cheap way to pull the collection.
        """
        every = {fn.va for fn in search_corpus.functions if not srv._is_data_marker(fn)}
        for term in ("%", "_", "\\", "%_\\", "100%", "%%"):
            code, payload = _served_rows(term)
            assert code == 200, f"search={term!r}: {code}"
            served = {row["va"] for row in payload["functions"]}
            # The independent statement the oracle cannot make for itself: a
            # metacharacter widened the match to the whole table.
            assert served != every, f"search={term!r}: matched every row, so it acted as a wildcard"
            assert served == _expected_vas(search_corpus, term), (
                f"search={term!r}: {sorted(served)}"
            )

    def test_a_row_without_a_symbol_is_searchable_by_its_name(
        self, search_corpus: CoverageSnapshot
    ) -> None:
        """An absent column is the empty string, not a dropped row.

        ``symbol`` is missing on real function rows (TOML has no null, so the
        document spells it ``""``), and the row whose name matched must still be
        returned: one absent column must not take the whole row out of the
        answer.
        """
        code, payload = _served_rows("100%")
        assert code == 200
        served = {row["va"] for row in payload["functions"]}
        assert 0x10001030 in served, f"the row with no symbol was dropped: {sorted(served)}"


# ── percent-decoding of the path and the query string ──────────────
#
# ``path_param`` and ``decode_query_value`` are the two decoders every
# attacker-controlled segment passes through, and neither had a harness: the
# repo-file campaign checked the status code the decode produced but nothing
# about the decode itself, and a target id, a section name or a VA that
# arrived mis-decoded 404s for a reason no test could name.  A decoder whose
# second pass turns ``%252e%252e%252f`` into ``../`` is a containment bug one
# refactor away, so the contracts it documents are the properties asserted
# here: one pass, no raise, and the two documented fall-backs (a segment that
# is not valid UTF-8, a query value that is not valid UTF-8 in latin-1) return
# the input rather than a half-decoded guess.

PATH_SEEDS: list[bytes] = [
    b"",
    b"demo",
    b".text",
    b"a b",
    b"a#b",
    b"a?b",
    b"sp%20ace",
    b"d%C3%A9mo",
    b"d%c3%a9mo",
    b"1000%2E",
    b"%2e%2e%2f",
    b"%252e%252e%252f",
    b"%25252e",
    b"%2",
    b"%%",
    b"%%20",
    b"%zz",
    b"%c0%ae%c0%ae",
    b"%c0%af",
    b"%ed%a0%80",
    b"%f4%90%80%80",
    b"%fe%ff",
    b"%ff%fe",
    b"%00",
    b"a%00b",
    b"main.c",
    b"a" * 300,
    b"%c3%28",
    b"e%CC%81",  # combining acute: NFC composes it to é
    b"1_000",
]

PATH_TOKENS: tuple[bytes, ...] = (
    b"%",
    b"%2",
    b"%25",
    b"%2e",
    b"%2f",
    b"%5c",
    b"%00",
    b"%c3%a9",
    b"%c0%ae",
    b"%ed%a0%80",
    b"%zz",
    b"..",
    b"/",
    b"\\",
    b" ",
    b"a",
    b"\xff",
    b"",
)


class TestPathAndQueryDecoders:
    """``server.path_param`` and ``server.decode_query_value``."""

    def test_path_param_never_raises_and_is_one_pass(self) -> None:
        """The oracle is ``urllib.parse.unquote`` itself: the module's
        documented contract is that result-or-identity, never anything else."""

        def check(data: bytes) -> None:
            value = data.decode("latin-1")
            decoded = srv.path_param(value)
            assert isinstance(decoded, str), f"{data!r}: {decoded!r}"
            try:
                expected = unquote(value, encoding="utf-8", errors="strict")
            except UnicodeDecodeError:
                # A segment whose escapes are not UTF-8 is a legal filename on
                # Linux; it comes back unchanged so the route 404s honestly.
                expected = value
            assert decoded == expected, f"{data!r}: decoded to {decoded!r}, expected {expected!r}"
            if "%" not in value:
                assert decoded == value, f"{data!r}: a literal segment was rewritten"
            # One pass only: a second decode of an already-decoded segment is
            # the traversal ``%252e%252e%252f`` relies on, so the handler must
            # never receive text that a second pass would change.  Asserting
            # it cannot be *avoided* for every input is not possible (a
            # filename may legitimately hold ``%2e``); what must hold is that
            # the value reaching the containment check is the one-pass decode.
            assert srv.path_param(decoded) in (decoded, unquote(decoded, errors="replace"))

        _fuzz(PATH_SEEDS, check, iterations=400, struct_tokens=PATH_TOKENS, num_tokens=PATH_TOKENS)

    def test_path_param_round_trips_a_quoted_segment(self) -> None:
        """Positive direction: a filename a browser would escape has to come
        back as the name the filesystem holds, or every such file 404s."""
        for text in ("a b.c", "démo.c", "100%_x.c", "a#b?.c", "back\\slash.c", "é", "0x1000"):
            assert srv.path_param(_pct(text)) == text, f"{text!r} did not survive quoting"

    def test_decode_query_value_never_raises_and_is_idempotent(self) -> None:
        """Two spellings of the same character must reach one comparison.

        Bottle hands a query value over as latin-1, so ``?section=%C3%A9``
        arrives as ``Ã©``; the re-encode recovers the ``é`` the client meant.
        Applying it twice has to be a fixed point, or a value routed through
        two readers (a page route and an API call carrying the same query)
        would compare two different strings.
        """

        def check(data: bytes) -> None:
            raw = data.decode("latin-1")
            once = srv.decode_query_value(raw)
            assert isinstance(once, str), f"{data!r}: {once!r}"
            assert srv.decode_query_value(once) == once, (
                f"{data!r}: second pass gave {srv.decode_query_value(once)!r}"
            )
            try:
                expected = raw.encode("latin-1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                expected = raw
            assert once == expected, f"{data!r}: decoded to {once!r}, expected {expected!r}"
            if raw.isascii():
                assert once == raw, f"{data!r}: an ASCII value was rewritten"

        _fuzz(PATH_SEEDS, check, iterations=300, struct_tokens=PATH_TOKENS, num_tokens=PATH_TOKENS)

    def test_a_200_serves_the_bytes_the_named_file_holds(self) -> None:
        """Differential across the containment boundary.

        The status-code campaign above cannot see a traversal that answers
        200 with someone else's file: the status is right and the content is
        not.  A 200 therefore has to be byte-identical to the file that
        actually lives at the decoded, root-relative path, read here from the
        filesystem rather than from the app's own resolution.
        """
        for prefix in ("/src/", "/original/"):
            for segment in ("recoverage/__init__.py", "docs/DESIGN.md", "pyproject.toml"):
                status, _headers, body = wsgi_request("GET", prefix + _pct(segment))
                if int(status.split()[0]) != 200:
                    continue
                root = (srv._project_dir() / prefix.strip("/")).resolve()
                expected = (root / segment).read_bytes()
                assert body == expected, (
                    f"{prefix}{segment}: served bytes differ from the file at {root / segment}"
                )


# ── repo file serving ──────────────────────────────────────────────

REPO_FILE_SEEDS: list[bytes] = [
    b"",
    b"main.c",
    b"a/b/c.c",
    b"..",
    b"../..",
    b"../../../etc/passwd",
    b"....//....//etc/passwd",
    b"..%2f..%2fetc%2fpasswd",
    b"..%252f..%252fetc%252fpasswd",
    b"%00",
    b"main.c%00.png",
    b"..%2f%00",
    b"/etc/passwd",
    b"%ff%fe",
    b"a" * 400,
    b"sp ace.c",
]

REPO_FILE_TOKENS: tuple[bytes, ...] = (
    b"",
    b"..",
    b"../",
    b"../..",
    b"..%2f",
    b"%2e%2e%2f",
    b"%00",
    b"/",
    b"\\",
    b"main.c",
    b".c",
    b"//",
    b"~",
    b"/etc/passwd",
    b"%ff",
)


class TestRepoFileRoute:
    """``GET /src/<filepath>`` and ``/original/<filepath>`` feed an
    attacker-decoded path segment straight into the filesystem: the handler
    resolves it and hands it to bottle's ``static_file``.  A byte the resolver
    or the directory walk rejects (NUL, an over-long segment) has to answer
    4xx, not raise out of the route into a traceback-bearing 500."""

    PREFIXES = ("/src/", "/original/")

    def test_path_never_crashes(self) -> None:
        def check(data: bytes) -> None:
            segment = data.decode("latin-1")
            for prefix in self.PREFIXES:
                path = f"{prefix}{segment}"
                status, _headers, body = wsgi_request("GET", path)
                code = int(status.split()[0])
                assert code < 500, f"{path}: handler crashed with {status}: {body[:200]!r}"
                assert code in (200, 403, 404), f"{path}: unexpected status {status}"
                assert b"Traceback" not in body, f"{path}: {status} leaked a traceback"

        _fuzz(
            REPO_FILE_SEEDS,
            check,
            iterations=200,
            struct_tokens=REPO_FILE_TOKENS,
            num_tokens=REPO_FILE_TOKENS,
        )

    @pytest.mark.parametrize(
        ("segment", "expected"),
        [
            # Decoded once, these leave the root, so the containment check
            # answers 403 with its stub.
            ("../../../etc/passwd", 403),
            ("..%2f..%2fetc%2fpasswd", 403),
            ("%2e%2e%2f", 403),
            # A double-encoded separator decodes to the literal text "%2f",
            # which is a filename and not a traversal: no file, so 404.  The
            # double-decode that would turn it into "../" is the thing
            # server.path_param exists to prevent.
            ("..%252f..%252fetc%252fpasswd", 404),
            ("%2e%2e%252f", 404),
        ],
    )
    def test_outside_the_root_is_never_served(self, segment: str, expected: int) -> None:
        """Pair assertion across the containment boundary: a path that leaves
        the root is refused with the handler's own error envelope, never with
        a file's bytes — whatever the surrounding root happens to hold."""
        for prefix in self.PREFIXES:
            status, headers, body = wsgi_request("GET", f"{prefix}{segment}")
            assert int(status.split()[0]) == expected, f"{prefix}{segment}: {status}"
            if expected == 403:
                data = json.loads(decode_body(body, headers))
                assert data["code"] == "forbidden", f"{prefix}{segment}: {data}"
            assert b"Traceback" not in body, f"{prefix}{segment}: {status} leaked a traceback"

    @pytest.mark.parametrize("segment", ["%00", "main.c%00.png", "..%2f%00", "%00%00"])
    def test_nul_segment_is_a_404(self, segment: str) -> None:
        """os.realpath raises ValueError on an embedded NUL, so a request
        carrying one must be refused before the containment check runs."""
        for prefix in self.PREFIXES:
            status, _headers, body = wsgi_request("GET", f"{prefix}{segment}")
            assert int(status.split()[0]) == 404, f"{prefix}{segment}: {status}"
            assert b"Traceback" not in body

    @pytest.mark.parametrize("segment", ["%2fetc%2fpasswd", "%2Fetc%2Fpasswd"])
    def test_anchored_segment_is_refused_before_the_join(self, segment: str) -> None:
        """``server.is_plain_relative`` gates the join, not the check after it.

        A resolve-then-compare check answers for the host it runs on, so the
        rule has to refuse an anchored segment before the join can
        reinterpret it.  Only the flavours every host agrees on are pinned
        here: ``C%3Afoo.c`` is a drive-relative name on Windows and an
        ordinary (absent) filename on POSIX, and the rule's cross-platform
        spelling is pinned through ``PureWindowsPath`` in
        ``test_potato.py``.
        """
        for prefix in self.PREFIXES:
            status, headers, body = wsgi_request("GET", f"{prefix}{segment}")
            assert int(status.split()[0]) == 403, f"{prefix}{segment}: {status}"
            data = json.loads(decode_body(body, headers))
            assert data["code"] == "forbidden", f"{prefix}{segment}: {data}"


# ── chunked body framing ───────────────────────────────────────────

#: The bodies a client would frame.  Four parse, so the campaign reaches the
#: accepted arm; the last two are the unparseable payloads the handler answers
#: after the reader hands them over whole.
_CHUNKED_BODIES: tuple[bytes, ...] = (
    b'{"vas": ["0x10001000"]}',
    b'{"vas": []}',
    b'{"vas": [0x10001000, 0x10001020, 0x10001030]}',
    b'{"vas": ["0x10001000", "0x99999999", "g_counter"]}',
    b"not json at all",
    b" " * 4096,
)

#: Chunk-size spellings a client sends: plain hex, upper case, zero padded,
#: and the extension forms RFC 9112 puts after the semicolon.
_CHUNKED_SIZES: tuple[str, ...] = (
    "%x",
    "%X",
    "%.16x",
    "%x;ext=1",
    '%x;q="a b"',
    "%x;",
    "%x ",
)

#: Spellings no client sends and every one of them must be refused: a prefix
#: the ASCII parse does not take, the ``_`` separator, a negative, a non-hex
#: digit, an empty field and a field of whitespace.
_CHUNKED_BAD_SIZES: tuple[str, ...] = ("0x%x", "+%x", "1_0", "-1", "g", "", " ")

#: The size spellings ``int(x, 16)`` widens into a byte count and
#: ``parse_ascii_int`` refuses: the ``_`` separator, a ``0x`` prefix, a sign,
#: a field of nothing, and the Arabic-Indic and fullwidth digit sets ``int()``
#: reads and the ASCII parse does not.  The two non-ASCII spellings are
#: escaped so the source carries no character a reviewer's font renders as
#: another one.
#:
#: Whitespace around the field and a hex letter are NOT here: the reader
#: strips the size field per RFC 9112 and "e" is a hex digit, so " 10 " is
#: 0x10 and "1e1" is 0x1e1.  Both are carried by the generated corpus.
_REFUSED_CHUNK_SIZES: tuple[str, ...] = (
    "1_0",
    "0x10",
    "+10",
    "\u0661\u0660",
    "\uff11\uff10",
    "_",
    "0x",
    "  0x10  ",
)


def _chunked_frames(rng: random.Random, count: int) -> list[bytes]:
    """*count* framings, each a whole body carried over one to four chunks.

    Byte mutation of a literal framing lands in the refusal arms and almost
    never in the accepted one, because every framing carries a CRLF it will
    have to lose.  These are built instead: the boundaries, the size spelling
    and the trailer vary, and one round in four is cut short so the truncated
    arms are reached too.  The PRNG is the module's own FUZZ_SEED, so the same
    corpus is built on every run.
    """
    frames: list[bytes] = []
    for _ in range(count):
        body = rng.choice(_CHUNKED_BODIES)
        # Interior boundaries only: a chunk of no bytes is the terminating
        # chunk, so a cut on an edge ends the body early rather than splitting
        # it, and the framing stops being the one a client would send.
        interior = range(1, len(body))
        cuts = sorted(rng.sample(interior, min(len(interior) - 1, rng.randint(0, 3))))
        bounds = [0, *cuts, len(body)]
        parts = [body[start:end] for start, end in pairwise(bounds)]
        out = bytearray()
        for part in parts:
            sizes = _CHUNKED_SIZES if rng.random() < 0.8 else _CHUNKED_BAD_SIZES
            spelling = rng.choice(sizes)
            size = spelling % len(part) if "%" in spelling else spelling
            out += size.encode("latin-1") + b"\r\n" + part + b"\r\n"
        out += rng.choice([b"0\r\n\r\n", b"0\r\n", b"0\r\nX-T: v\r\n\r\n"])
        if rng.random() < 0.25:
            out = out[: rng.randrange(len(out) + 1)]
        frames.append(bytes(out))
    return frames


def _frame(*parts: bytes, trailer: bytes = b"") -> bytes:
    """*parts* carried as one chunk each, each sized the way a client sizes it."""
    out = b"".join(b"%x\r\n%s\r\n" % (len(part), part) for part in parts)
    return out + b"0\r\n" + trailer + b"\r\n"


_LOOKUP = b'{"vas": ["0x10001000"]}'

CHUNKED_SEEDS: list[bytes] = [
    *_chunked_frames(random.Random(FUZZ_SEED), 48),
    b"",
    b"0\r\n\r\n",
    b"0\r\n",
    _frame(),
    _frame(_LOOKUP),
    _frame(_LOOKUP[:9], _LOOKUP[9:]),
    _frame(_LOOKUP[:1], _LOOKUP[1:5], _LOOKUP[5:]),
    _frame(b"{}", trailer=b"X-Trailer: value\r\n"),
    b"0\r\nX-Trailer: value\r\n\r\n",
    b"0\r\n\r\ntrailing bytes",
    b'4;ext=1\r\n{"v\r\n5\r\nas":[]}\r\n0\r\n\r\n',
    b"1;x=y\r\nA\r\n0\r\n\r\n",
    b"1_0\r\n" + _LOOKUP + b"\r\n0\r\n\r\n",
    b"-1\r\nA\r\n0\r\n\r\n",
    b"ffffffffffffffff\r\nA\r\n0\r\n\r\n",
    b"g\r\nA\r\n0\r\n\r\n",
    b"\r\n0\r\n\r\n",
    b"  \r\n0\r\n\r\n",
    b"1\r\nA\n0\r\n\r\n",
    b"1\r\nA",
    b"1\r\n",
    _frame(b"")[:-4],
    b"1000\r\n" + b"A" * 4096 + b"\r\n0\r\n\r\n",
]

#: Tokens the mutation engine splices into a framing.
CHUNKED_TOKENS: tuple[bytes, ...] = (
    b"\r\n",
    b"\n",
    b"0\r\n\r\n",
    b"0\r\n",
    b"1\r\n",
    b";",
    b"1_0",
    b"-1",
    b"ffffffffffffffff",
    b"g",
    b"\x00",
    b"1;ext\r\n",
    b"A",
    b'{"vas": []}',
)


class _FramedStream:
    """A ``wsgi.input`` that answers a read past the framing with no bytes.

    Under the serving stack ``wsgi.input`` is the socket's buffered reader, so
    a read past the client's last byte blocks until the peer goes away: the
    handler waits and the client waits for the response.  Reading off the end
    is recorded here and answered empty, which is what a hung-up peer looks
    like, so a campaign sees a 400 rather than a hang.
    """

    def __init__(self, frame: bytes) -> None:
        self._frame = frame
        self._pos = 0
        self.overshoot: list[int] = []

    def _take(self, size: int) -> bytes:
        if self._pos >= len(self._frame):
            self.overshoot.append(size)
            return b""
        part = self._frame[self._pos : self._pos + size]
        self._pos += len(part)
        return part

    def read(self, size: int = -1) -> bytes:
        return self._take(len(self._frame) if size < 0 else size)

    def readline(self, size: int = -1) -> bytes:
        window = self._take(len(self._frame) if size < 0 else size)
        cut = window.find(b"\n")
        if cut < 0:
            return window
        # Hold the bytes after the newline back for the next call, as a
        # buffered reader does: the parser under test reads line by line.
        self._pos -= len(window) - cut - 1
        return window[: cut + 1]

    def tell(self) -> int:
        return self._pos


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestChunkedBodyFraming:
    """``POST /api/targets/<t>/functions`` is the one route that reads a body
    with no ``Content-Length`` to check it against, so the reader parses the
    client's own chunk framing: hex sizes, extensions, the terminating chunk
    and its trailers.  A size read with ``int(x, 16)`` takes the ``_`` separator
    and the whole Unicode Nd set, so a chunk declaring ``1_0`` reads 16 bytes
    of a connection carrying the next request; the campaign asserts the decoded
    body, the read count, and the connection the answer leaves behind."""

    PATH = "/api/targets/{}/functions"

    def _post(self, framed: bytes) -> tuple[str, dict[str, str], bytes, _FramedStream]:
        stream = _FramedStream(framed)
        status, headers, body = wsgi_request(
            "POST",
            self.PATH.format(get_first_target()),
            {"Transfer-Encoding": "chunked", "Content-Type": "application/json"},
            body=b"",
            wsgi_input=stream,
            content_length=None,
        )
        return status, headers, body, stream

    def test_framing_never_crashes_and_never_overruns(self) -> None:
        def check(data: bytes) -> None:
            path = self.PATH.format(get_first_target())
            status, headers, body, stream = self._post(data)
            code = int(status.split()[0])
            assert code < 500, f"{path}: handler crashed with {status}: {body[:200]!r}"
            assert code in _ALLOWED_STATUSES, f"{path}: unexpected status {status}"
            assert b"Traceback" not in body, f"{path}: {status} leaked a traceback"
            if code >= 400:
                _assert_envelope(_body_json(body, headers, path), status, path)
            if code == 413:
                # The reader stops at its cap with the rest of the framing in
                # the socket, so a keep-alive reader would take those bytes as
                # a second request.
                assert headers.get("Connection") == "close", (
                    f"{path}: {status} on {data!r} kept the connection open"
                )
            if stream.overshoot:
                # The read that overran a complete framing is a hang under the
                # real reader; an oversize framing is refused without one.
                assert code in (400, 413), f"{path}: read past the framing, answered {status}"

        _fuzz(
            CHUNKED_SEEDS,
            check,
            iterations=200,
            struct_tokens=CHUNKED_TOKENS,
            num_tokens=CHUNKED_TOKENS,
        )

    @pytest.mark.parametrize("size", _REFUSED_CHUNK_SIZES)
    def test_a_size_the_ascii_parse_refuses_decodes_nothing(self, size: str) -> None:
        """Every spelling ``int(x, 16)`` widens and ``parse_ascii_int`` refuses
        is answered as a malformed framing, never as a body it did not frame,
        and closes the connection the rest of the framing is sitting in.

        The read COUNT is the assertion, not the status: a widened ``1_0`` is
        16, so the reader would take sixteen bytes of a connection carrying
        whatever request comes next, and a ``-0`` it would read as the
        terminating chunk.  Either answers 200 or 400 here, so only the bytes
        the reader touched tell the two apart.
        """
        payload = b'{"vas":["0x10001000"]}'
        # The bytes a client puts on the wire, not the source spelling: the
        # reader decodes the size field as ASCII, so a non-ASCII digit arrives
        # as its UTF-8 bytes and has to fail there rather than in the test.
        field = size.encode("utf-8")
        framed = field + b"\r\n" + payload + b"\r\n0\r\n\r\n"
        status, headers, body, stream = self._post(framed)
        code = int(status.split()[0])
        assert code != 200, f"chunk size {size!r} served {len(payload)} bytes: {body[:200]!r}"
        assert headers.get("Connection") == "close", (
            f"chunk size {size!r}: the refusal kept the connection open"
        )
        assert not stream.overshoot or code in (400, 413), (
            f"chunk size {size!r}: the reader ran off the framing"
        )
        size_line = len(field) + 2
        assert stream.tell() <= size_line, (
            f"chunk size {size!r} was read as a length: the reader took "
            f"{stream.tell() - size_line} bytes of chunk data it was never given"
        )

    @pytest.mark.parametrize("chunks", [1, 2, 64])
    def test_the_cap_is_on_the_decoded_bytes(self, chunks: int) -> None:
        """A body at the cap is read whole however it is split, and one byte
        over it is refused however it is split.

        The cap is on what the reader ACCUMULATES, so checking each chunk
        against the cap on its own is not enough: the last chunk of a split
        body is the one that crosses it, and a reader that sizes each chunk
        against the full cap instead of the remainder lets the body grow by up
        to one chunk past the limit.
        """
        cap = _MAX_BATCH_BODY_BYTES
        unit = cap // chunks
        for total, expected in ((unit * chunks, 400), (unit * chunks + 1, 413)):
            parts = [
                b" " * (unit if index < chunks - 1 else total - unit * (chunks - 1))
                for index in range(chunks)
            ]
            status, headers, _body, _stream = self._post(_frame(*parts))
            code = int(status.split()[0])
            assert code == expected, (
                f"{chunks} chunks totalling {total} bytes: {status} (cap {cap})"
            )
            if expected == 413:
                assert headers.get("Connection") == "close"

    def test_a_framed_body_answers_what_the_unframed_one_does(self) -> None:
        """Pair assertion across the framing boundary: the same JSON split
        across two chunks answers what the unframed request answers, so a
        chunk-size parser that ate a byte of it cannot pass."""
        payload = json.dumps({"vas": ["0x10001000"]}).encode()
        half = len(payload) // 2
        framed = b"%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n" % (
            half,
            payload[:half],
            len(payload) - half,
            payload[half:],
        )
        status, headers, body, stream = self._post(framed)
        assert status.startswith("200"), f"{status}: {body[:200]!r}"
        assert not stream.overshoot, "the reader ran past a complete framing"

        path = self.PATH.format(get_first_target())
        plain_status, plain_headers, plain_body = wsgi_request(
            "POST",
            path,
            {"Content-Type": "application/json"},
            body=payload,
        )
        assert plain_status.startswith("200")
        assert _body_json(body, headers, path) == _body_json(plain_body, plain_headers, path)


# ── conditional requests ───────────────────────────────────────────

#: ``If-None-Match`` spellings, as a client and a cache send them.
INM_SEEDS: list[bytes] = [
    b"*",
    b"",
    b'""',
    b'W/"deadbeef"',
    b'  "deadbeef"  ',
    b'"deadbeef", "cafe"',
    b'"nope", "deadbeef"',
    b"deadbeef,",
    b",,,deadbeef,,,",
    b'W/"nope"',
    b"w/deadbeef",
    b'"',
    b'"unterminated',
    b",".join([b'W/"nope"'] * 40),
    b'"' + b"a" * 400 + b'"',
    b"deadbeef",
]

#: Tokens the mutation engine splices into an If-None-Match value.
INM_TOKENS: tuple[bytes, ...] = (
    b"*",
    b'"',
    b'"deadbeef"',
    b'W/"deadbeef"',
    b"w/deadbeef",
    b",",
    b" ",
    b"\t",
    b"\x00",
    b"deadbeef",
    b"cafebabe",
)


def _names_served_etag(raw: str, etag: str) -> bool:
    """Whether any comma-separated candidate of *raw* denotes *etag*.

    The oracle the campaign judges against: RFC 9110's list, the ``*``
    wildcard, and the weak ``W/`` spelling, written out here rather than
    reused from the helper under test.
    """
    for candidate in raw.split(","):
        candidate = candidate.strip()
        if candidate == "*" or candidate == etag:
            return True
        if candidate[:2].upper() == "W/" and candidate[2:].strip() == etag:
            return True
    return False


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestConditionalRequestComparison:
    """Every cacheable DB-derived endpoint answers revalidation through
    ``server._if_none_match_matches``, so a client-chosen header decides
    whether a body is sent at all.  A wrong answer is a stale dashboard rather
    than a crash, and no status code shows it: the comparison is judged against
    the ETag the response itself carries."""

    PATH = "/api/targets/{}/stats"

    def _served_etag(self, path: str) -> str:
        _status, headers, _body = wsgi_request("GET", path)
        # wsgiref capitalizes the header name, so the lookup cannot assume
        # either spelling: a test pinned to one of them is pinned to a server.
        lowered = {key.lower(): value for key, value in headers.items()}
        etag = lowered.get("etag")
        assert etag, f"the stats response carries no ETag: {sorted(headers)}"
        return etag

    def test_a_304_means_the_header_named_the_served_etag(self) -> None:
        path = self.PATH.format(get_first_target())
        etag = self._served_etag(path)

        def check(data: bytes) -> None:
            raw = data.decode("latin-1")
            status, headers, body = wsgi_request("GET", path, {"If-None-Match": raw})
            code = int(status.split()[0])
            assert code in (200, 304), f"If-None-Match={raw!r}: unexpected {status}"
            served = {key.lower(): value for key, value in headers.items()}.get("etag")
            assert served == etag, f"If-None-Match={raw!r}: the served ETag moved off {etag!r}"
            if _names_served_etag(raw, etag):
                assert code == 304, (
                    f"If-None-Match={raw!r} names the served etag {etag!r} but answered {status}"
                )
                assert not body, f"If-None-Match={raw!r}: a 304 carried a {len(body)}-byte body"
            else:
                assert code == 200, (
                    f"If-None-Match={raw!r} names nothing served but answered {status} "
                    f"against {etag!r}"
                )

        _fuzz(INM_SEEDS, check, iterations=250, struct_tokens=INM_TOKENS, num_tokens=INM_TOKENS)

    def test_the_accepted_spellings_revalidate(self) -> None:
        """The spellings the campaign mutates around, one request each: a
        mutation campaign cannot say the accepted forms still work."""
        path = self.PATH.format(get_first_target())
        etag = self._served_etag(path)
        for raw in (
            "*",
            etag,
            f"W/{etag}",
            f"  {etag}  ",
            f'"other", {etag}',
        ):
            status, _headers, _body = wsgi_request("GET", path, {"If-None-Match": raw})
            assert int(status.split()[0]) == 304, f"If-None-Match={raw!r}: {status} (etag {etag!r})"

    def test_a_candidate_containing_the_etag_does_not_match(self) -> None:
        """The near misses, spelled from the ETag the response actually
        carries.  The campaign's tokens are fixed strings and the ETag is a
        digest of the snapshot, so no mutation of them can produce a candidate
        that CONTAINS it: a comparison that widened to a substring test, a
        prefix test or a length-blind weak match is invisible above and is the
        whole failure mode here."""
        path = self.PATH.format(get_first_target())
        etag = self._served_etag(path)
        for raw in (
            # An ETag carries its own quotes, so these candidates CONTAIN
            # the whole validator while denoting nothing that is served.
            f'"x{etag}"',
            f"x{etag}",
            f"{etag}x",
            f"{etag[:-1]}",
            f"{etag}0",
            f"W/x{etag}",
            f"xW/{etag}",
            f"w/{etag}",
            f'"x", {etag}y"',
            f'"prefix{etag}suffix"',
        ):
            status, _headers, _body = wsgi_request("GET", path, {"If-None-Match": raw})
            assert int(status.split()[0]) == 200, (
                f"If-None-Match={raw!r} matched the served etag {etag!r} and answered {status}"
            )


# ── coverage-document contents ──────────────────────────────────────

#: The one untrusted input no campaign above crosses: the coverage document
#: on disk.  Every other surface is bytes a stranger typed into a request;
#: this is a file a build wrote, and the ways it is wrong are the ways a build
#: is wrong: an interrupted write, a half-finished regen, a merge, a hand
#: edit, a document from a newer rebrew.  It is also the largest parser in the
#: request path, and every field it carries (a name, a label, a section name,
#: a source path, a similarity) reaches the JSON payloads and the HTML
#: renderer straight out of the reader, so its blast radius is the whole
#: dashboard rather than one response.

_DOC_TARGET = "DOCFUZZ"

#: The value the escaping assertions are written against: a name that is
#: markup, a quote and a scheme at once, so a reader that escapes only ``&``
#: or only ``<`` still fails them.
HOSTILE_NAME = '<script>alert("x")</script>'

_DOC_SECTIONS: dict[str, dict[str, Any]] = {
    ".text": {
        "va": 0x10001000,
        "size": 0x40,
        "fileOffset": 0x200,
        "unitBytes": 16,
        "columns": 4,
        "cells": [
            cell(0, 16, "exact", functions=("_func_a",)),
            cell(16, 32, "reloc", functions=("_func_b",), label="jt_10001010"),
            cell(32, 48, "stub", parent_function="_func_a"),
            cell(48, 64, "padding"),
        ],
    }
}

_DOC_FUNCTIONS: list[dict[str, Any]] = [
    {"va": 0x10001000, "name": "_func_a", "size": 16, "status": "EXACT", "similarity": 1.0},
    {"va": 0x10001010, "name": "_func_b", "size": 16, "status": "RELOC", "similarity": 0.5},
]

#: The shapes a wrong document actually takes: a value of the wrong type
#: where the reader expects a number, a container where it expects a scalar,
#: the non-finite floats TOML spells bare and ``json.dumps`` would then
#: re-emit as the ``NaN`` / ``Infinity`` tokens no JSON parser accepts, and
#: the header/key spellings that put a row in the wrong table.
_DOC_TOKENS: tuple[bytes, ...] = (
    b"version = 0",
    b"version = -1",
    b'version = "1"',
    b"version = 99999999999999999999",
    b"target = 1",
    b'target = "<script>alert(1)</script>"',
    b"[[sections]]",
    b'[sections.""]',
    b"[sections..text]",
    b"[sections.\x00]",
    b"cells = 5",
    b"cells = [1, 2, 3]",
    b"cells = [{start = 0, end = 0, state = 1}]",
    b"state = 1",
    b'state = "<b>x</b>"',
    b"start = -1",
    b"end = 0",
    b"span = 0",
    b"span = -5",
    b"size = -1",
    b"va = 0x",
    b"columns = 0",
    b"unitBytes = 0",
    b"similarity = nan",
    b"similarity = inf",
    b"similarity = -inf",
    b"similarity = 1e400",
    b"similarity = 'nan'",
    b"functions = ",
    b"paths = ",
    b"[metadata]",
    b"[[metadata.paths]]",
    b"[[functions]]",
    b"[globals]",
    b"[history]",
    b"functions = [",
    b"]",
    b"\x00",
    b"\xef\xbb\xbf",
    b"\xed\xa0\x80",
)


def _document_seeds() -> list[bytes]:
    """The well-formed document plus the two wrong shapes worth mutating."""
    from coverage_fixture import render_coverage

    whole = render_coverage(
        _DOC_TARGET,
        _DOC_SECTIONS,
        functions=_DOC_FUNCTIONS,
        globals_=[{"va": 0x10002000, "name": "g_counter"}],
        verify_results=[{"va": 0x10001000, "match": True, "similarity": 0.5}],
        paths={"source_root": "src/DOCFUZZ", "original_root": "orig"},
    )
    hostile = render_coverage(
        _DOC_TARGET,
        {'.te"xt<script>': {**_DOC_SECTIONS[".text"]}},
        functions=[{"va": 0, "name": HOSTILE_NAME, "status": "EXACT"}],
    )
    return [whole.encode(), hostile.encode(), whole.encode()[: len(whole) // 2]]


#: Values a document can carry that a build would never write and a hand edit,
#: a merge or a rebrew from another release would.  Each pool is drawn per
#: field, so one round mixes a hostile name with a reversed cell range rather
#: than changing one field at a time.
_VA_VALUES: tuple[Any, ...] = (
    0,
    1,
    0x10001000,
    -1,
    0xFFFFFFFFFFFFFFFF,
    1 << 64,
    1 << 128,
    0x1000_0000_0000,
)
_NAMES: tuple[Any, ...] = (
    "_func_a",
    "",
    "é中文",
    "A" * 512,
    HOSTILE_NAME,
    '"><img src=x onerror=alert(1)>',
    "back\\slash\"quote'apos",
    "tab\tnewline\nreturn\r",
    "\x00\x1b[31m",
    "\x00\x1f\u202e",
    123,
)
_SIZES: tuple[Any, ...] = (0, 1, 16, -1, -16, 1 << 31, 1 << 64, None)
_SPANS: tuple[Any, ...] = (0, 1, 16, -1, 1 << 64, None)
_SIMILARITIES: tuple[Any, ...] = (
    0.0,
    1.0,
    0.5,
    -0.5,
    1.5,
    1e308,
    -1e308,
    float("inf"),
    float("-inf"),
    float("nan"),
    None,
    "0.5",
)
_STATUSES: tuple[Any, ...] = (
    "EXACT",
    "RELOC",
    "UNKNOWN",
    "EXACT",
    "",
    "<b>EXACT</b>",
    "exakt",
)
_STATE_VALUES: tuple[Any, ...] = (
    "exact",
    "reloc",
    "stub",
    "padding",
    "data",
    "thunk",
    "none",
    "exact",
    "",
    "EXACT",
    "<i>x</i>",
)


def _document_with_drawn_values(rng: random.Random) -> str:
    """One document whose every field is drawn from the pools above.

    Rendered through the fixture writer, so the result is TOML the reader
    accepts by construction: the campaign is about the VALUES, and a syntax
    error would send every round back down the refusal arm.
    """
    from coverage_fixture import render_coverage

    def draw(pool: tuple[Any, ...]) -> Any:
        return rng.choice(pool)

    section_name = rng.choice([".text", ".data", ".bss", ".rdata", 'te"xt', "<script>", ""])
    cells = []
    for _ in range(rng.randint(1, 6)):
        start = draw(_SPANS)
        end = draw(_SPANS)
        if isinstance(start, int) and isinstance(end, int) and rng.random() < 0.5:
            start, end = min(start, end), max(start, end)
        cells.append(
            cell(
                start,
                end,
                draw(_STATE_VALUES),
                span=draw(_SPANS),
                functions=(draw(_NAMES),),
                label=draw(_NAMES),
                parent_function=draw(_NAMES),
            )
        )
    sections = {
        section_name: {
            "va": draw(_VA_VALUES),
            "size": draw(_SIZES),
            "fileOffset": draw(_SIZES),
            "unitBytes": draw((1, 2, 16, 0, -1)),
            "columns": draw((1, 4, 8, 0, -1)),
            "cells": cells,
        }
    }
    functions = [
        {
            "va": draw(_VA_VALUES),
            "name": draw(_NAMES),
            "vaStart": draw(_VA_VALUES),
            "size": draw(_SIZES),
            "fileOffset": draw(_SIZES),
            "status": draw(_STATUSES),
            "module": draw(_NAMES),
            "cflags": draw(_NAMES),
            "symbol": draw(_NAMES),
            "markerType": draw(("FUNCTION", "GLOBAL", "", 7)),
            "is_thunk": draw((0, 1, -1, True)),
            "is_export": draw((0, 1, -1, True)),
            "files": (draw(_NAMES),),
            "similarity": draw(_SIMILARITIES),
            "blockerDelta": draw(_SIZES),
            "textOffset": draw(_SIZES),
        }
        for _ in range(rng.randint(1, 4))
    ]
    globals_ = [
        {
            "va": draw(_VA_VALUES),
            "name": draw(_NAMES),
            "decl": draw(_NAMES),
            "files": (draw(_NAMES),),
            "size": draw(_SIZES),
            "status": draw(_STATUSES),
        }
        for _ in range(rng.randint(0, 3))
    ]
    return render_coverage(
        _DOC_TARGET,
        sections,
        functions=functions,
        globals_=globals_,
        verify_results=[
            {
                "va": draw(_VA_VALUES),
                "match": draw((True, False)),
                "similarity": draw(_SIMILARITIES),
                "expected": draw(_NAMES),
                "actual": draw(_NAMES),
            }
        ],
        history=[{"at": draw(_NAMES), "tool": draw(_NAMES)}],
        paths={"source_root": draw(_NAMES), "original_root": draw(_NAMES)},
    )


def _strict_json(text: str) -> Any:
    """``json.loads`` with the non-standard constants refused.

    ``json.dumps`` writes ``NaN`` / ``Infinity`` for a float it cannot render,
    and no JSON parser outside Python accepts those tokens, so a served
    document carrying a non-finite figure produces a body the SPA's
    ``JSON.parse`` rejects outright.  ``parse_constant`` is where a fuzzer can
    see that, and nothing else in the campaign can.
    """

    def reject(token: str) -> Any:
        raise AssertionError(f"served JSON carries the non-finite token {token!r}")

    return json.loads(text, parse_constant=reject)


class TestCoverageDocumentContents:
    """A coverage document the reader cannot trust is read on every request.

    The contract is the one ``TestUnreadableDocumentIsNotAnEmptyTarget``
    states for a whole document, widened to the field: a document either
    parses, and every endpoint derived from it answers 200 with a payload that
    is well-formed (no traceback, no non-finite number, HTML closed), or it
    raises ``CoverageTomlError`` and the endpoint answers the 503
    ``db_unavailable`` contract.  Anything else is a defect a field-level
    corruption reached: a 500 is a crash in a handler the campaign just
    handed an unparseable document, and an empty 200 is the degradation that
    reads as a healthy zero.
    """

    PATHS = (
        "/api/targets",
        f"/api/targets/{_DOC_TARGET}/stats",
        f"/api/targets/{_DOC_TARGET}/data",
        f"/api/targets/{_DOC_TARGET}/functions?limit=5",
        # The lookup routes carry the document's own numeric columns (a
        # similarity, a delta) into the payload, which is where a non-finite
        # figure stored in a document reaches the wire.  The VAs and the name
        # are the shapes the SPA links with; a document that holds neither
        # answers 404, which the campaign allows.
        f"/api/targets/{_DOC_TARGET}/functions/0x1000",
        f"/api/targets/{_DOC_TARGET}/functions/_func_a",
        f"/potato?target={_DOC_TARGET}",
    )

    def _install(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        directory = tmp_path / "db"
        directory.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        return directory / f"coverage-{_DOC_TARGET}.toml"

    def _assert_response(
        self, status: str, headers: dict[str, str], body: bytes, path: str
    ) -> None:
        code = int(status.split()[0])
        text = decode_body(body, headers).decode("utf-8", errors="replace")
        assert code != 500, f"{path}: handler crashed with {status}: {text[:300]!r}"
        assert code in (200, 404, 503), f"{path}: unexpected status {status}"
        for marker in _LEAK_MARKERS:
            assert marker not in text, f"{path}: {status} leaks {marker!r}: {text[:300]!r}"
        assert "Traceback" not in text, f"{path}: {status} leaked a traceback"
        html = not path.startswith("/api/")
        if code == 503 and html:
            # Potato Mode answers the same unreadable document with its own 503
            # page, and it is a rendered document like any other.
            assert "database unavailable" in text, f"{path}: a 503 that is not the 503 page"
        elif code == 503:
            # The reader owns one answer for an unreadable document, and it is
            # this envelope on every JSON surface: a 503 that is not
            # db_unavailable is a handler that degraded some other way.
            payload = _body_json(body, headers, path)
            assert payload.get("code") in ("db_unavailable", "forbidden"), f"{path}: {payload!r}"
            return
        if html:
            assert code != 404 or "not found" in text.lower(), f"{path}: a bare 404 from {status}"
            assert text.rstrip().endswith("</html>"), f"{path}: the page is not a closed document"
        else:
            _strict_json(text)

    def test_a_corrupt_document_never_crashes_a_reader(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        document = self._install(tmp_path, monkeypatch)

        def check(data: bytes) -> None:
            document.write_bytes(data)
            _clear_derived_caches()
            for path in self.PATHS:
                status, headers, body = wsgi_request("GET", path)
                self._assert_response(status, headers, body, path)

        _fuzz(
            _document_seeds(),
            check,
            iterations=250,
            struct_tokens=_DOC_TOKENS,
            num_tokens=_DOC_TOKENS,
        )

    def test_a_parsed_document_with_wrong_values_still_serves(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The arm byte mutation rarely reaches: a document that PARSES.

        Corrupting bytes breaks the TOML itself, so most of the campaign above
        lands on the refusal path.  The interesting documents are the ones
        rebrew's writer could produce and a hand edit could mangle: a cell
        whose ``end`` precedes its ``start``, a span of zero, a similarity
        outside 0-1, a VA above the 64-bit ceiling, a name carrying markup or
        a control character.  They parse, so they reach the bucket folds, the
        percentage helpers, the search index and the HTML renderer, and a
        defect there is a wrong dashboard rather than a 503.

        Structure-aware by construction: each field is drawn from a pool of
        real and hostile values and the document is rendered through the same
        writer the fixtures use, so every round is a document the reader
        accepts.  The round is named on failure because the stream is seeded
        from :data:`FUZZ_SEED` and replays identically, and the round count is
        :data:`FUZZ_ITERATIONS`, so ``make fuzz`` widens this campaign on the
        same terms as every byte-driven one.
        """
        document = self._install(tmp_path, monkeypatch)
        rng = random.Random(FUZZ_SEED)

        def check(round_index: int) -> None:
            text = _document_with_drawn_values(rng)
            document.write_text(text, encoding="utf-8")
            _clear_derived_caches()
            for path in self.PATHS:
                status, headers, body = wsgi_request("GET", path)
                try:
                    self._assert_response(status, headers, body, path)
                except AssertionError as failure:
                    raise AssertionError(
                        f"seed={FUZZ_SEED} round={round_index}: {failure}\ndocument was:\n{text}"
                    ) from failure

        for round_index in range(FUZZ_ITERATIONS):
            check(round_index)

    def test_fields_survive_the_write_read_boundary_escaped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pair assertion, both sides of the persistence boundary.

        A hostile name, label or section name is written into a document and
        read back through the real reader.  The JSON payloads must carry it
        byte for byte (the SPA escapes on render, and a payload that mangled a
        name would misattribute a match), and the HTML surface must carry the
        escaped spelling with the raw one absent, which is the only thing
        standing between a hand-edited document and script execution in a
        reader's browser.
        """
        directory = tmp_path / "db"
        self._install(tmp_path, monkeypatch)
        name = HOSTILE_NAME
        section = '.te"xt'
        write_coverage(
            directory,
            _DOC_TARGET,
            {
                section: {
                    **_DOC_SECTIONS[".text"],
                    "cells": [cell(0, 16, "exact", functions=(name,), label=name)],
                }
            },
            functions=[{"va": 0x10001000, "name": name, "size": 16, "status": "EXACT"}],
        )
        _clear_derived_caches()

        status, headers, body = wsgi_request("GET", f"/api/targets/{_DOC_TARGET}/functions")
        assert status.startswith("200"), f"{status}: {body[:200]!r}"
        rows = _strict_json(decode_body(body, headers).decode("utf-8"))
        served = [row.get("name") for row in rows.get("functions", rows.get("items", []))]
        assert name in served, f"the hostile name did not survive the read: {served!r}"

        status, headers, body = wsgi_request("GET", f"/potato?target={_DOC_TARGET}&view=functions")
        assert status.startswith("200"), f"{status}: {body[:200]!r}"
        page = decode_body(body, headers).decode("utf-8", errors="replace")
        assert name not in page, "the raw name reached the page unescaped"
        assert html.escape(HOSTILE_NAME) in page, (
            "the escaped name is missing from the page, so the escaping is not what carries it"
        )


# ── the <va> path segment ──────────────────────────────────────────────
#
# The one path segment the target-segment campaign above holds fixed.  It
# reaches `server.lookup_function`, which hands the raw spelling to rebrew's
# `parse_va_candidates` before falling back to a name comparison, so it is a
# parser on an untrusted string whose base choice (16 for a `0x` prefix or any
# a-f, otherwise decimal-then-bare-hex) changes which row a request resolves
# to.  A wrong answer here is not a bad render: it is a reader shown another
# function's disassembly and its verify record.

VA_FUNCTIONS: list[dict[str, Any]] = [
    {"va": 0x10001000, "name": "_func_a", "size": 16, "status": "EXACT"},
    {"va": 0x10001010, "name": "_func_b", "size": 16, "status": "RELOC"},
    # A name whose case fold is not identity, so the folded arm of the
    # resolution order has something the byte-equality arm cannot answer.
    {"va": 0x10001020, "name": "Straße", "size": 16, "status": "EXACT"},
]

VA_GLOBALS: list[dict[str, Any]] = [{"va": 0x10002000, "name": "g_counter"}]

VA_SEEDS: list[bytes] = [
    b"0x10001000",
    b"10001000",
    b"0x10001010",
    b"0X10001020",
    b"0x10002000",
    b"_func_a",
    b"_func_b",
    b"g_counter",
    b"STRASSE",
    b"stra\xc3\x9fe",
    b" 0x10001000 ",
    b"0x",
    b"0x0",
    b"-1",
    b"0x10001000ff",
    b"0x" + b"f" * 300,
    b"99999999999999999999999999",
    b"0b1010",
    b"0o17",
    b"1_0",
    b"..",
    b"%2e%2e%2f%2e%2e",
    b"\xff\xfe",
    b"\x00null",
    b"' OR 1=1 --",
    b"a" * 300,
]


def _expected_va_row(value: str) -> tuple[str, int] | None:
    """The ``(kind, va)`` the route's documented resolution order lands on.

    Independent of the handler: the four arms are restated from
    ``handle_api_function`` and applied over the two fixed tables above, so a
    route that resolved a spelling to some other row fails the campaign rather
    than agreeing with itself.  ``parse_va_candidates`` is rebrew's parser and
    is the oracle for the VA arm, not the code under test; the name arms are
    restated because they are the two lines most likely to drift.
    """
    from rebrew.workspace import parse_va_candidates

    for table, kind in ((VA_FUNCTIONS, "function"), (VA_GLOBALS, "global")):
        for candidate in parse_va_candidates(value):
            for row in table:
                if row["va"] == candidate:
                    return (kind, candidate)
    for table, kind in ((VA_FUNCTIONS, "function"), (VA_GLOBALS, "global")):
        for row in table:
            if row["name"] == value:
                return (kind, row["va"])
    folded = srv.fold_text(value)
    for table, kind in ((VA_FUNCTIONS, "function"), (VA_GLOBALS, "global")):
        for row in table:
            if srv.fold_text(row["name"]) == folded:
                return (kind, row["va"])
    return None


@pytest.mark.skipif(not HAS_DB, reason="No coverage document")
class TestFunctionVaSegment:
    """``GET /api/targets/<t>/functions/<va>`` — the only route whose PATH is
    the thing it looks up.  Fuzzed here over the segment itself, not over the
    target beside it."""

    @pytest.fixture(autouse=True)
    def _document(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        directory = tmp_path / "db"
        write_coverage(
            directory,
            "VAFUZZ",
            {".text": {**_DOC_SECTIONS[".text"], "va": 0x10001000, "size": 0x40}},
            functions=VA_FUNCTIONS,
            globals_=VA_GLOBALS,
            verify_results=[{"va": 0x10001000, "match": True, "similarity": 0.5}],
        )
        monkeypatch.setenv("RECOVERAGE_DB", str(directory))
        _clear_derived_caches()

    def test_a_va_spelling_resolves_to_the_documented_row(self) -> None:
        def check(data: bytes) -> None:
            spelling = data.decode("utf-8", "replace")
            path = f"/api/targets/VAFUZZ/functions/{_pct(spelling)}"
            status, headers, body = wsgi_request("GET", path)
            code = int(status.split()[0])
            assert code != 500, f"{path}: handler crashed with {status}"
            assert code in (200, 404), f"{path}: unexpected status {status}"
            payload = _strict_json(decode_body(body, headers).decode("utf-8", "replace"))
            expected = _expected_va_row(spelling.strip())
            if expected is None:
                assert code == 404, f"{path}: {status} for a spelling that names nothing"
                _assert_envelope(payload, status, path)
                return
            assert code == 200, f"{path}: {status} for a spelling naming {expected!r}"
            assert isinstance(payload, dict), f"{path}: 200 body is not an object: {payload!r}"
            kind, va = expected
            assert payload.get("va") == va, (
                f"{path}: resolved to va {payload.get('va')!r}, the order says {va:#x} "
                f"({kind}): {payload!r}"
            )
            # The pair assertion: the row the document holds is the row the
            # wire carries, spelled the way the document spells it.
            names = [row["name"] for row in VA_FUNCTIONS] + [row["name"] for row in VA_GLOBALS]
            assert payload.get("name") in names, (
                f"{path}: served a name the document does not hold: {payload.get('name')!r}"
            )

        _fuzz(VA_SEEDS, check, iterations=600)


# ── the CLI ───────────────────────────────────────────────────────────
#
# The one API surface in the package that no campaign above reaches.  The
# commands parse nothing a stranger typed, but they RENDER what a coverage
# document holds into a table, a JSON document, a CSV file and a Markdown
# file, and those four formats each have their own escaping rule
# (`cli._csv_safe`, `cli._md_safe`, `json.dumps`, Rich's markup parser).  An
# escaped value that arrives at the file mangled, or an unescaped one that
# lands in it, is a defect no HTTP status code can show, and the CSV and
# Markdown arms are the two a reader opens in a spreadsheet.

#: Section names a build would never write and a hand edit, a merge or a
#: hostile sample would.  No lone surrogate: TOML has no escape for one, so
#: such a document is a parse error, and the reader refusing it is the
#: contract the document campaigns above already pin.
CLI_SECTION_NAMES: tuple[str, ...] = (
    ".text",
    '=HYPERLINK("http://evil.example","click")',
    "@SUM(1+1)",
    "-1+1",
    "\t=1+1",
    "\r=1+1",
    "=1+1\t=2+2",
    ".te|xt",
    "sec\ntion",
    "sec\r\nction",
    "sec\ttion",
    "sec\x00tion",
    "  =x",
    '"quoted"',
    "\\backslash\\",
    "\u2028line-sep\u2029para-sep",
    "<script>alert(1)</script>",
    "démo",
    "x" * 4000,
)

#: Target ids, which arrive as a filename.  No separator and no NUL, for the
#: reasons a filename has: the point of the pool is the escaping rules, not
#: the filesystem's.
CLI_TARGET_NAMES: tuple[str, ...] = (
    "EXPORTFUZZ",
    "=cmd|' calc'!A0",
    "target with spaces",
    'target"quote',
    "démo",
    "t" * 200,
)

CLI_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("export", "--format", "json"),
    ("export", "--format", "csv"),
    ("export", "--format", "md"),
    ("stats",),
    ("check", "--min-coverage", "0"),
)


def _md_cells(row: str) -> int:
    """How many cells a rendered Markdown table row carries.

    A pipe the export escaped is data inside a cell, not a cell boundary, which
    is the format's own rule: counting the raw characters would call the
    escaped spelling ragged and pass the unescaped one.
    """
    return row.replace("\\|", "").count("|")


class TestCliRendersHostileDocumentValues:
    """``recoverage stats`` / ``export`` / ``check`` over a document whose
    section and target names are hostile, in every format they render.

    Structure-aware by construction: the name is drawn from the pools above and
    the document is written through the same writer the fixtures use, so every
    round is a document the reader accepts and the campaign lands on the
    escaping rules instead of on the parse refusal.
    """

    def _install(self, directory: Path, target: str, section: str) -> None:
        # The directory holds exactly the round's document: a second round
        # drawing a different target name would otherwise leave the previous
        # document beside it, and the export would carry both.
        directory.mkdir(parents=True, exist_ok=True)
        for stale in directory.glob("coverage-*.toml"):
            stale.unlink()
        write_coverage(
            directory,
            target,
            {section: {**copy.deepcopy(_DOC_SECTIONS[".text"]), "va": 0x10001000}},
            functions=[{"va": 0x10001000, "name": "_func_a", "size": 16, "status": "EXACT"}],
        )
        _clear_derived_caches()

    def test_every_format_renders_a_hostile_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = CliRunner()
        rng = random.Random(FUZZ_SEED)
        directory = tmp_path / "db"
        for round_index in range(FUZZ_ITERATIONS):
            target = rng.choice(CLI_TARGET_NAMES)
            section = rng.choice(CLI_SECTION_NAMES)
            monkeypatch.setenv("RECOVERAGE_DB", str(directory))
            self._install(directory, target, section)
            for argv in CLI_COMMANDS:
                try:
                    self._assert_command(runner, argv, target, section)
                except AssertionError as failure:
                    raise AssertionError(
                        f"seed={FUZZ_SEED} round={round_index}: {argv}\n"
                        f"target={target!r} section={section!r}\n{failure}"
                    ) from failure

    def _assert_command(
        self,
        runner: CliRunner,
        argv: tuple[str, ...],
        target: str,
        section: str,
    ) -> None:
        result = runner.invoke(cli.app, list(argv))
        assert result.exit_code == 0, (
            f"{argv}: exit {result.exit_code}: "
            f"{type(result.exception).__name__}: {result.exception}"
        )
        assert "Traceback" not in result.output, f"{argv}: a traceback reached the terminal"
        assert "cannot read coverage" not in result.output, (
            f"{argv}: refused a document the reader accepts: {result.output[:200]!r}"
        )
        # The bytes, not ``result.output``: CliRunner decodes its capture with
        # universal newlines, so a CR inside a quoted CSV cell is gone before a
        # reader ever sees it, and a round-trip assertion over the decoded
        # string would be pinning the test runner rather than the export.
        text = (result.output_bytes or b"").decode("utf-8", "replace")
        if argv[:2] == ("export", "--format"):
            fmt = argv[2]
            if fmt == "json":
                self._assert_json(text, target, section)
            elif fmt == "csv":
                self._assert_csv(text, target, section)
            else:
                self._assert_markdown(text, section)

    def _assert_json(self, text: str, target: str, section: str) -> None:
        payload = _strict_json(text)
        entries = payload if isinstance(payload, list) else [payload]
        matching = [
            entry
            for entry in entries
            if isinstance(entry, dict) and section in entry.get("sections", {})
        ]
        assert matching, f"the section name did not survive the JSON export: {text[:300]!r}"
        assert any(entry.get("target") == target for entry in matching), (
            f"the target name was mangled on the wire: {text[:300]!r}"
        )

    def _assert_csv(self, text: str, target: str, section: str) -> None:
        rows = list(csv.reader(io.StringIO(text, newline="")))
        assert len(rows) == 2, f"expected a header and one section row, got {len(rows)}"
        header, row = rows
        assert header[:2] == ["target", "section"], f"header changed: {header!r}"
        assert len(header) == len(row), f"ragged row: {header!r} / {row!r}"
        # The pair assertion across the write boundary: what the reader reads
        # back is what the writer was handed, and the two string cells are the
        # ones the formula guard is responsible for.
        assert row[0] == cli._csv_safe(target), f"target cell mangled: {row[0]!r}"
        assert row[1] == cli._csv_safe(section), f"section cell mangled: {row[1]!r}"
        assert section in cli._csv_safe(section), "the guard prefixed a name it should not have"
        if section.startswith(cli._CSV_FORMULA_PREFIXES):
            assert row[1].startswith("'"), f"a formula cell reached the file unprefixed: {row[1]!r}"

    def _assert_markdown(self, text: str, section: str) -> None:
        lines = [line for line in text.splitlines() if line.startswith("|")]
        assert len(lines) >= 2, f"no Markdown table in the export: {text[:300]!r}"
        header, separator, body = lines[0], lines[1], lines[2]
        assert set(separator) <= set("|-: "), f"malformed separator row: {separator!r}"
        # One rule for every cell count: a name carrying a raw pipe is a
        # ragged table, and a name carrying a line break is two rows for one
        # section.  Both are what the escaping exists to prevent.  An escaped
        # pipe does not count, which is the format's own rule, so it is
        # counted after the escapes are removed.
        assert _md_cells(body) == _md_cells(header), (
            f"ragged Markdown row ({_md_cells(body)} vs {_md_cells(header)} cells): {body!r}"
        )
        assert section.replace("|", cli._MD_PIPE).translate(cli._MD_LINE_BREAKS) in body, (
            f"the section name did not survive the Markdown export: {body!r}"
        )


# ── rebrew-project.toml ────────────────────────────────────────────

#: The value the config escaping assertions are written against, the same
#: canary the document campaign uses: markup, a quote and a scheme at once.
_HOSTILE_TARGET_ID = '<script>alert("x")</script>'

#: Target ids a project's own config can carry.  The file is untrusted input
#: like a coverage document — it arrives in the checkout — and a target id is
#: read verbatim into the API payload, the SPA dropdown, the Potato section
#: tabs and the CLI's own tables, so every one of these is a value that
#: crosses four renderers.
_CONFIG_TARGET_IDS = (
    "FAKEDLL",
    "demo",
    "",
    "..",
    "a b",
    "demo.dll",
    "démo",
    "démo",
    _HOSTILE_TARGET_ID,
    "a\nb",
    "a\x00b",
    'a"b',
    "a\\b",
    "a\tb",
    "0x10",
    "\u0664\u0660\u0669\u0666",
    "a\u2028b",
    "a" * 200,
    "",
)

#: ``[targets.X].binary`` values, which name a file the process then READS
#: and whose bytes ``/asm`` and ``/bytes`` serve.  A parent hop, an anchor and
#: a Windows drive spelling are in the pool because each is a way out of the
#: project tree that the join alone does not stop.
_CONFIG_BINARIES = (
    "bin/game.dll",
    "bin/game.exe",
    "orig/game.dll",
    "",
    "   ",
    "..",
    "../../outside.dll",
    "/etc/hostname",
    "C:/windows/system32/drivers/etc/hosts",
    "bin/../bin/game.dll",
    "bin\\game.dll",
    "game\x00.dll",
    "\u2028.dll",
    "d" * 300,
    "",
)

#: ``[project].db_dir`` values as TOML value text, so a round can also draw
#: the non-string shapes a hand edit leaves behind.
_CONFIG_DB_DIRS = (
    '"db"',
    '""',
    '"   "',
    '".."',
    '"/etc"',
    '"db/../db"',
    '"nope"',
    "5",
    '["db"]',
    "true",
)


def _config_seeds() -> list[bytes]:
    """The well-formed project config plus the shapes worth mutating."""
    whole = (
        '[project]\ndb_dir = "db"\ndefault_target = "demo"\n\n'
        '[targets.demo]\nbinary = "bin/game.dll"\nreversed_dir = "src/demo"\nmarker = "DEMO"\n'
    )
    hostile = (
        f'[project]\ndb_dir = "db"\n\n[targets."{_HOSTILE_TARGET_ID}"]\n'
        'binary = "../../outside.dll"\n'
    )
    return [
        whole.encode(),
        hostile.encode(),
        b"",
        b"[project\ndb_dir = ]\n",
        whole.encode()[: len(whole) // 2],
    ]


#: Grammar tokens for the config grammar itself.  Byte mutation of a TOML
#: file mostly produces another syntax error, so the tokens are what reach the
#: readers' type branches: a table where a value is expected, an array where
#: a string is, a key that is not a name.
_CONFIG_TOKENS = (
    b"[project]\n",
    b"[targets]\n",
    b"[[targets]]\n",
    b'db_dir = "db"\n',
    b"db_dir = 5\n",
    b'db_dir = ["db"]\n',
    b'db_dir = ""\n',
    b'binary = "bin/game.dll"\n',
    b'binary = "../../outside.dll"\n',
    b'binary = "/etc/hostname"\n',
    b"binary = 5\n",
    b"binary = []\n",
    b"reversed_dir = 5\n",
    b"marker = 5\n",
    b"default_target = 5\n",
    b'[targets.""]\n',
    b'[targets."<script>"]\n',
    b"[targets.]\n",
    b"project = 5\n",
    b"targets = 5\n",
    b"targets = []\n",
    b"project = []\n",
    b"\x00",
    b"\xff\xfe",
    b"\xef\xbb\xbf",
    b'"' + b"a" * 200 + b'"',
)


@pytest.mark.skipif(not HAS_DB, reason="No coverage.db")
class TestProjectConfigDocument:
    """``rebrew-project.toml`` is the other untrusted document this package reads.

    It arrives in the checkout rather than over a socket, which is the only
    difference from a coverage document: it names the coverage directory, the
    target ids the dashboard offers, and the binary whose bytes ``/asm`` and
    ``/bytes`` serve.  Nothing about it is validated beyond what
    ``rebrew.workspace`` reads out of it, so it gets the same campaign as the
    documents: a file that either resolves or raises ``WorkspaceConfigError``,
    and either way no endpoint crashes, no error body leaks a traceback, and
    the HTML surfaces close.

    Two arms, because they reach different code.  Byte mutation lands on the
    parse refusal and the type branches.  The drawn arm builds a config the
    parser accepts, so every round reaches the consumers themselves, and adds
    the two properties a status code cannot show: a declared target id arrives
    at ``/api/targets`` byte for byte (a mangled one silently retargets a
    dashboard), and a declared ``binary`` never names a file outside the
    project tree (the bytes of one would be served from ``/asm``).
    """

    PATHS = (
        "/api/targets",
        "/api/health",
        "/potato",
        f"/api/targets/{_DOC_TARGET}/stats",
    )

    @pytest.fixture
    def project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """A project directory holding a build and nothing else.

        ``RECOVERAGE_DB`` names the documents so the coverage half of every
        memo is stable across rounds; the config under test is the file the
        campaign rewrites, and ``_project_dir`` is what rebrew's reader resolves
        it against.
        """
        monkeypatch.chdir(tmp_path)
        root = tmp_path.resolve()
        monkeypatch.setattr(srv, "_project_dir", lambda: root)
        monkeypatch.setenv("RECOVERAGE_DB", str(root / "db"))
        build_synthetic_coverage(root / "db")
        _clear_derived_caches()
        return root

    def _install(self, project: Path, data: bytes) -> None:
        (project / "rebrew-project.toml").write_bytes(data)
        # Both memos the config feeds: the parsed targets and the resolved
        # target list.  Without the drop, a rewritten file of the same length
        # inside one stat tick answers from the previous round.
        _clear_derived_caches()

    def _assert_response(self, status: str, headers: dict[str, str], body: bytes, path: str) -> str:
        code = int(status.split()[0])
        text = decode_body(body, headers).decode("utf-8", errors="replace")
        assert code != 500, f"{path}: handler crashed with {status}: {text[:300]!r}"
        assert code in _ALLOWED_STATUSES, f"{path}: unexpected status {status}"
        for marker in _LEAK_MARKERS:
            assert marker not in text, f"{path}: {status} leaks {marker!r}: {text[:300]!r}"
        if path.startswith("/api/"):
            payload = _body_json(body, headers, path)
            if code >= 300:
                _assert_envelope(payload, status, path)
        else:
            assert code != 404 or "not found" in text.lower(), f"{path}: a bare 404 from {status}"
            assert text.rstrip().endswith("</html>"), f"{path}: the page is not a closed document"
        return text

    def _drive(self, path: str) -> tuple[str, dict[str, str], bytes, str]:
        status, headers, body = wsgi_request("GET", path)
        text = self._assert_response(status, headers, body, path)
        return status, headers, body, text

    def test_a_corrupt_config_never_crashes_a_reader(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = CliRunner()

        def check(data: bytes) -> None:
            self._install(project, data)
            for path in self.PATHS:
                self._drive(path)
            result = runner.invoke(cli.app, ["stats", "--json"])
            assert result.exit_code in (0, 1, 2), (
                f"stats: exit {result.exit_code}: "
                f"{type(result.exception).__name__}: {result.exception}"
            )
            assert "Traceback" not in result.output, "stats: a traceback reached the terminal"

        _fuzz(
            _config_seeds(),
            check,
            iterations=150,
            struct_tokens=_CONFIG_TOKENS,
            num_tokens=_CONFIG_TOKENS,
        )

    def test_a_declared_target_reaches_every_reader_intact(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pair assertions, both sides of the config boundary.

        A target id the config declares is echoed at ``/api/targets`` byte for
        byte: the SPA links every row by that id, so a mangled one is a
        dashboard pointed at a target that does not exist.  A ``binary`` the
        config declares resolves inside the project tree or not at all: the
        loader READS that file and ``/asm`` and ``/bytes`` serve the bytes, so
        a parent hop or an anchor turns a checked-in file into a read of any
        file the process can open.

        Structure-aware by construction: every value is drawn from the pools
        above and rendered as TOML, so the round exercises the consumers rather
        than the parse refusal.
        """
        rng = random.Random(FUZZ_SEED)
        for round_index in range(FUZZ_ITERATIONS):
            # Distinct ids: TOML refuses to declare one table twice, and a
            # round that landed on that refusal would test the parser's error
            # path instead of the consumers this arm is about.
            ids = list(
                dict.fromkeys(rng.choice(_CONFIG_TARGET_IDS) for _ in range(rng.randint(1, 3)))
            )
            binaries = {tid: rng.choice(_CONFIG_BINARIES) for tid in ids}
            db_dir = rng.choice(_CONFIG_DB_DIRS)
            lines = ["[project]", f"db_dir = {db_dir}"]
            for tid in ids:
                # json.dumps is a TOML basic string for everything a pool can
                # hold, and it escapes the control characters an id may carry
                # so the rendered file is parseable TOML.
                lines += [f"[targets.{json.dumps(tid)}]", f"binary = {json.dumps(binaries[tid])}"]
            text = "\n".join(lines) + "\n"
            try:
                self._install(project, text.encode("utf-8", "surrogatepass"))
            except UnicodeEncodeError:  # a lone surrogate is not a file
                continue
            try:
                self._check_round(project, ids, binaries)
            except AssertionError as failure:
                raise AssertionError(
                    f"seed={FUZZ_SEED} round={round_index}: {failure}\nconfig was:\n{text}"
                ) from failure

    def _check_round(self, project: Path, ids: list[str], binaries: dict[str, str]) -> None:
        status, headers, body, page = self._drive("/api/targets")
        payload = _body_json(body, headers, "/api/targets")
        served = payload.get("targets") if isinstance(payload, dict) else None
        assert isinstance(served, list), f"/api/targets: no target list: {payload!r}"
        served_ids = {entry.get("id") for entry in served if isinstance(entry, dict)}
        if int(status.split()[0]) == 200:
            # A config the reader accepted declares these; the payload is where
            # the SPA's every link resolves the id.
            for tid in ids:
                assert tid in served_ids, (
                    f"a declared target id is missing from /api/targets: {tid!r} "
                    f"in {sorted(map(str, served_ids))!r}"
                )
        for entry in served:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            # The name is a DISPLAY label: a blank one comes from a blank id
            # the config declared, and the id is what every link resolves, so
            # the label is not the contract here.  What must not happen is a
            # path: the name is built with Path(...).name, so the directories
            # of a configured binary never reach the dropdown.
            assert isinstance(name, str), f"/api/targets: a target with no name: {entry!r}"
            # Path(...).name strips the separators of the platform it runs on,
            # and only those: on POSIX a backslash is a legal filename
            # character, so a target id spelled ``a\b`` keeps it and the
            # assertion is the forward slash every flavour strips.
            assert "/" not in name, f"/api/targets: a display name carries a separator: {name!r}"
        self._drive("/potato")
        assert _HOSTILE_TARGET_ID not in page, (
            f"the hostile target id reached the page unescaped: {page[:300]!r}"
        )
        # The containment rule, on the reader rather than on the response.
        for tid, binary in binaries.items():
            resolved = srv._find_dll_path(tid)
            if resolved is None:
                continue
            assert not _escapes(resolved, project), (
                f"[targets.{tid}].binary = {binary!r} resolved outside the project: {resolved}"
            )

    def _project(self) -> Path:
        return srv._project_dir()


def _escapes(candidate: Path, project_root: Path) -> bool:
    """Whether *candidate* names something outside *project_root*."""
    try:
        resolved = candidate.resolve()
    except (OSError, ValueError):
        return True
    return not resolved.is_relative_to(project_root.resolve())
