#!/usr/bin/env python3
"""Recoverage server — coverage dashboard for binary-matching projects.

Bottle WSGI app serving a VanJS + SQLite dashboard.
Reads the coverage database from the path resolved by
``recoverage._paths._db_path()``, which honours
``rebrew-project.toml [project] db_dir`` when present and falls back to
``./db/coverage.db`` otherwise.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import logging
import sqlite3
import threading
import unicodedata
import uuid
from collections import deque
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlsplit

import brotli  # type: ignore[import-untyped]
import zstandard as zstd
from bottle import Bottle, HTTPResponse, request, response  # type: ignore[import-untyped]

# SCHEMA_TARGET is the reserved metadata target holding the schema-level
# db_version stamp (written by rebrew build-db).  It is NOT a real project
# target and must never appear in target enumeration, stats, or the dashboard
# dropdown.
from rebrew.workspace import (
    CONFIG_NAME,
    SCHEMA_TARGET,
    SECTION_CELLS_AGG_SQL,
    SECTION_CELLS_COLUMN,
    SECTION_CELLS_TABLE,
    coverage_db_lock,
    decode_section_cells,
    parse_va_candidates,
    read_config,
    sqlite_ro_uri,
    target_binary,
    targets_table,
)

from recoverage import clock, metrics
from recoverage._paths import _db_path

# Thread-local compressor — python-zstandard gives ZstdCompressor instances NO
# thread-safety guarantees ("do not operate on the same instance from different
# threads") and releases the GIL inside compress(), so a shared instance raced
# on one ZSTD_CCtx and reproducibly segfaulted the server under concurrent
# requests.  One context per request thread (same pattern as
# disasm.get_capstone_md).
_ZSTD_COMPRESSOR_TLS = threading.local()


def _get_zstd_compressor() -> Any:
    compressor = getattr(_ZSTD_COMPRESSOR_TLS, "compressor", None)
    if compressor is None:
        compressor = _ZSTD_COMPRESSOR_TLS.compressor = zstd.ZstdCompressor(level=3)
    return compressor


# The shared Bottle application.  Defined up front — above the helpers and
# the auth/hooks section below — so a first top-down read of this module
# finds its central object early: api.py/ui.py import it and mount routes on
# it at import time; webapp.py composes both onto it.
app = Bottle()

HAS_PYGMENTS = importlib.util.find_spec("pygments") is not None

# CORS — configured once at startup by the CLI before the server starts
# accepting requests.  Thread-safe: set before any worker threads exist.
CORS_ENABLED = False

# Origins allowed to read the API cross-origin (normalized scheme://host[:port]
# from --cors-origin).  Empty = no cross-origin reads; the wildcard "*" is
# never emitted.
CORS_ALLOWED_ORIGINS: list[str] = []

# Expected Host-header hostnames.  Loopback binds validate the Host header
# to defeat DNS rebinding (an attacker's domain resolving to 127.0.0.1);
# None = remote bind (user opted in via --allow-remote) — skip validation.
ALLOWED_HOSTS: set[str] | None = None

# Loopback hostnames, ONE definition shared by the CLI's --bind guard, the
# regen endpoint's remote-addr/Origin checks, and the DNS-rebinding Host
# allowlist above.  Membership tests only — order carries no meaning.
LOOPBACK_HOSTS: tuple[str, ...] = ("127.0.0.1", "::1", "localhost")


def _peer_is_loopback(addr: str) -> bool:
    """True when socket peer address *addr* connects from the local host.

    Exact LOOPBACK_HOSTS membership plus IPv4-mapped IPv6 spellings
    (``::ffff:127.0.0.1``): a dual-stack listener (e.g. ``--bind ::`` on
    Linux, where the OS default keeps IPv4 accepted on the v6 socket)
    reports IPv4 peers in mapped form, and plain string comparison would
    then 403 the operator's own browser on POST /api/regen.  Parsed with
    ipaddress rather than prefix-matching so hex spellings classify by
    value, not text.  Deliberately NOT wider than LOOPBACK_HOSTS: other
    127.x addresses stay rejected (pinned by tests).
    """
    if addr in LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # .ipv4_mapped exists only on IPv6Address.
    if isinstance(ip, ipaddress.IPv6Address):
        v4 = ip.ipv4_mapped
        if v4 is not None:
            return str(v4) == "127.0.0.1"
    return str(ip) == "::1"


def configure_security(
    *,
    cors_enabled: bool = False,
    cors_allowed_origins: Sequence[str] = (),
    auth_token: str = "",
    allowed_hosts: set[str] | None = None,
) -> None:
    """Install the startup request-policy state: CORS, bearer token, Host allowlist.

    ONE public entry point for the process-wide globals defined above.  The
    CLI configures them through this function instead of assigning server
    module attributes by name (one of which is private), so this module owns
    both the storage and when/how it may change.  Call it once at startup,
    BEFORE the WSGI server starts accepting requests — request worker threads
    read these values without a lock.
    """
    global CORS_ENABLED, CORS_ALLOWED_ORIGINS, _AUTH_TOKEN, ALLOWED_HOSTS
    CORS_ENABLED = cors_enabled
    # Only normalized origins reach storage: an unparsable stored value would
    # match every unparsable request Origin and echo itself back as an
    # allow-origin.
    CORS_ALLOWED_ORIGINS = list(cors_allowed_origins)
    _AUTH_TOKEN = auth_token
    ALLOWED_HOSTS = allowed_hosts


def _hostname_of(origin: str) -> str:
    """Lowercased hostname of an Origin/Host header value ("" if unparsable).

    Origins carry a scheme (``http://localhost:5173``); bare Host headers
    (``localhost:8001``) get a synthetic scheme so urlsplit parses both.
    Values containing userinfo/escape characters (``evil@host``, backslash,
    percent-encoding, control bytes, whitespace) are rejected — browsers never
    emit them in Host/Origin, so their presence means the value is not a plain
    header.

    The control range is C0, DEL and C1, not just ``ord < 32``: urlsplit
    carries U+0080-U+009F through into the hostname, so a value carrying one
    parses to a "host" no browser can address, and :func:`_normalize_origin`
    would then store and echo it as an allowlist entry.
    """
    if any(ch in origin for ch in ("@", "\\", "%")) or any(
        ch.isspace() or ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in origin
    ):
        return ""
    try:
        candidate = origin if "://" in origin else f"//{origin}"
        return (urlsplit(candidate).hostname or "").lower()
    except ValueError:
        return ""


def _normalize_origin(origin: str) -> str:
    """Normalize an Origin URL to ``scheme://host[:port]`` for allowlist matching.

    ``http://localhost:5173`` → ``http://localhost:5173``; a scheme-default
    port is dropped (``http://localhost:80`` → ``http://localhost``) so both
    spellings match; IPv6 hosts keep their brackets
    (``http://[::1]:8001`` → ``http://[::1]:8001``).  Returns "" for
    unparsable or userinfo-bearing values.
    """
    if _hostname_of(origin) == "":
        return ""
    try:
        u = urlsplit(origin if "://" in origin else f"//{origin}")
        host = (u.hostname or "").lower()
        port = u.port
        scheme = u.scheme or "http"
        default_port = {"http": 80, "https": 443}.get(scheme)
        if port == default_port:
            port = None
        host_part = f"[{host}]" if ":" in host else host
        return f"{scheme}://{host_part}" + (f":{port}" if port else "")
    except ValueError:
        return ""


def _safe_etag(*parts: object) -> str:
    """Deterministic ETag from arbitrary parts.

    Parts include request-controlled strings (VA, section, format) — they
    are hashed so no raw request data can ever reach a response header
    (bottle rejects control characters, but that is a library property,
    not the app's contract).
    """
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:32]
    return f'"{digest}"'


def path_param(value: str) -> str:
    """Percent-decode one URL path component, as UTF-8, exactly once.

    Bottle routes on ``PATH_INFO`` as the WSGI server hands it over, which
    per PEP 3333 is the *raw* request target: a browser's ``%C3%A9`` and
    ``%20`` arrive still encoded.  Every route capture (``target``,
    ``va``, ``section``, ``filepath``) is therefore percent-encoded text, and a
    target id or filename holding a space, ``#``, ``?`` or a non-ASCII
    character never matches the database row, the section, or the file.
    Potato Mode already emits ``urllib.parse.quote``-escaped links, so the
    two halves disagreed.

    One pass only, and never a second: the result feeds path containment
    checks, so decoding twice would let ``%252e%252e%252f`` reach them as
    ``../``.  A segment whose escapes are not valid UTF-8 (a legal
    non-UTF-8 filename on Linux) is returned unchanged, which 404s honestly
    instead of raising on a request the server could have served.
    """
    try:
        return unquote(value, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return value


def decode_query_value(raw: str) -> str:
    """Recover the UTF-8 a client sent for one already-decoded query value.

    Bottle hands query values over as latin-1 text, so ``?section=%C3%A9``
    arrives as ``Ã©``; re-encoding recovers the ``é`` the client meant.
    ASCII (the overwhelming majority: tokens, integers, format names) comes
    back byte-identical.

    A value that is not valid UTF-8 in latin-1, or already holds a character
    above U+00FF (a client that sent raw UTF-8 rather than escapes), is
    returned unchanged: it is already the text the caller meant.
    """
    try:
        return raw.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return raw


def query_param(name: str, default: str = "") -> str:
    """One query-string value, percent-decoded as UTF-8.

    Bottle decodes query values with ``encoding='latin1'`` (see its module
    import of ``urlunquote``), so ``?section=%C3%A9`` reaches a handler as
    ``Ã©`` and matches no section while ``parse_qs`` on the same raw
    ``request.url`` — the path Potato Mode uses — yields ``é``.  The
    latin-1 round trip in :func:`decode_query_value` is what recovers it.
    """
    return decode_query_value(request.query.get(name, default))


def _snapshot_db_mtime() -> tuple[int, int] | None:
    """Return (fingerprint, main-file size) of coverage.db, or None when unreadable.

    The fingerprint folds the DB's identity into one int (main-file
    mtime_ns + size, plus -wal's when present); element 1 is the main file's
    size alone.  Callers must treat the fingerprint as an opaque change
    token, never as an mtime.

    WAL-aware: the DB runs in ``journal_mode=wal``, so a writer can commit
    to ``coverage.db-wal`` without checkpointing the main file — main-file
    mtime/size alone would miss the change (stale memo/ETag/watcher).  Fold
    the -wal stat in.  (NOT -shm: sqlite touches the shared-memory index on
    every connection, so including it would make the snapshot — and thus
    every ETag — change between requests.)

    EVERY DB-derived cache key and ETag must be built on this snapshot, not
    raw ``st_mtime`` — raw mtimes served stale 304s after rebuilds that only
    touched the WAL.
    """
    db = _db_path()
    try:
        st = db.stat()
    except OSError:
        return None
    acc = (st.st_mtime_ns << 32) ^ (st.st_size & 0xFFFFFFFF)
    try:
        w = Path(f"{db}-wal").stat()
        acc ^= (w.st_mtime_ns << 32) ^ (w.st_size & 0xFFFFFFFF)
    except OSError:
        pass
    return acc, st.st_size


#: Nanoseconds in a second, and in a microsecond: the two constants the
#: file-mtime conversion below is written in.
_NS_PER_SECOND = 1_000_000_000
_NS_PER_MICROSECOND = 1_000


def mtime_ns_to_utc(mtime_ns: int) -> datetime:
    """The instant *mtime_ns* names, as an aware UTC datetime.

    One definition of the file-mtime rendering both freshness surfaces use
    (``/api/health``'s ``mtime_utc`` and Potato Mode's footer stamp), and
    integer arithmetic all the way through: ``mtime_ns / 1e9`` is a float
    second, which cannot hold a nanosecond, so ``fromtimestamp`` rounds to
    the nearest one and reports a stamp up to half a second LATE.  Potato
    renders that rounded value to the minute, so a file written at
    12:34:59.999999999 is stamped "12:35 UTC" for a rebuild that has not
    happened yet.  Splitting into whole seconds plus a microsecond remainder
    truncates instead, which is the only direction a freshness stamp may
    err in: the served data never lags the stamp.
    """
    seconds, nanoseconds = divmod(mtime_ns, _NS_PER_SECOND)
    return datetime.fromtimestamp(seconds, tz=UTC) + timedelta(
        microseconds=nanoseconds // _NS_PER_MICROSECOND
    )


def _newest_mtime_ns(db: Path) -> int | None:
    """Newest mtime_ns across *db* and its -wal sibling, or None.

    The same WAL-awareness contract as :func:`_snapshot_db_mtime`, as a
    plain instant instead of a folded token: for the surfaces that RENDER the
    freshness time (``/api/health``, Potato Mode's footer stamp) rather than
    key a cache on it.
    """
    try:
        newest = db.stat().st_mtime_ns
    except OSError:
        return None
    with contextlib.suppress(OSError):
        newest = max(newest, Path(f"{db}-wal").stat().st_mtime_ns)
    return newest


def _if_none_match_matches(raw: str, etag: str) -> bool:
    """Whether an ``If-None-Match`` header value already covers *etag*.

    ONE spelling of RFC 9110's conditional-request comparison: a
    comma-separated list, the ``*`` wildcard, and weak validators
    (``W/"..."``) matched weakly.  Every ETag-bearing surface answers
    revalidation through here, so the accepted spellings cannot drift.
    """
    for cand in raw.split(","):
        cand = cand.strip()
        if cand == "*":
            return True
        if cand == etag:
            return True
        # Strip the weak prefix W/ per RFC 9110.
        if cand.startswith("W/") and cand[2:].strip() == etag:
            return True
    return False


def _etag_or_304(snap: tuple[int, int] | None, *parts: object) -> str | None:
    """DB-freshness ETag over the WAL-aware snapshot *snap* + *parts*; 304 on match.

    Shared tail of every cacheable DB-derived endpoint (/data, /stats, /asm,
    /bytes, /potato): compute ``_safe_etag(snap[0], parts...)``, answer
    ``If-None-Match`` with a 304, else hand the ETag back for the caller to
    attach to its response.  Callers pass their own
    :func:`_snapshot_db_mtime` result — endpoints that also key a memo on
    that snapshot (/data) stat the DB exactly once.  Returns None when *snap*
    is None (DB unreadable) — the caller then sends no ETag (the endpoint
    itself fails with 503 shortly after).
    """
    if snap is None:
        return None
    etag = _safe_etag(snap[0], *parts)
    if _if_none_match_matches(_header("If-None-Match", ""), etag):
        raise HTTPResponse(
            status=304,
            headers={"ETag": etag, "Cache-Control": CACHE_REVALIDATE},
        )
    return etag


#: `functions.markerType` values that name data, not a function (rebrew ADR 023
#: widened the set past GLOBAL/DATA).  ONE definition: the SPA function list,
#: the Potato function list, and the by-status counts all filter on it, and
#: three copies of the literal is three chances to disagree.
DATA_MARKER_TYPES: tuple[str, ...] = ("GLOBAL", "DATA", "VTABLE", "STRING")

#: WHERE fragment excluding data markers from a `functions` query.
#:
#: The `markerType IS NULL OR` arm is load-bearing.  rebrew's own column is
#: ``NOT NULL DEFAULT 'FUNCTION'``, but a hand-made or older database can leave
#: it nullable (the columns the server requires are checked for presence, not
#: nullability), and SQLite evaluates ``NULL NOT IN (...)`` to NULL, which
#: WHERE rejects: every unmarked function would vanish from the list, from the
#: Potato table, and from the by-status counts.  An unknown marker type is a
#: function, exactly as rebrew's default says.
NOT_DATA_MARKER_SQL = "(markerType IS NULL OR markerType NOT IN ({types}))".format(
    types=", ".join(f"'{t}'" for t in DATA_MARKER_TYPES)
)


# Byte-based per-section stats query shared by /api/targets/<target>/stats and
# the `recoverage stats` CLI.  ONE definition, so the two callers cannot drift
# apart (see _section_stats for what the copies used to get wrong).
#
# Only the two values that need `cells` are computed here.  Every cell count
# comes from section_cell_stats, which rebrew materializes per section
# (~0.01 ms); adding the twelve SUM(CASE ...) expressions and a COUNT(*) to
# this scan cost ~15 ms on a 64k-cell target against ~6 ms for these two.  That
# includes exact_count: the cells-side copy that used to sit here counted
# 'exact' alone while every other surface (rebrew's materialized table, /data,
# Potato Mode, and the grid's own palette, which paints 'verified' in the exact
# slot) folds 'verified' in, so the two disagreed on the same database and the
# buckets failed to reconcile with total_cells.  rebrew owns the definition;
# this endpoint reads it rather than restating it.
SECTION_STATS_SQL = """
    SELECT section_name,
      SUM(CASE WHEN state != 'none' THEN end - start ELSE 0 END) AS covered_bytes,
      SUM(end - start) AS total_bytes
    FROM cells WHERE target = ? GROUP BY section_name
"""

# The per-section cell counts, already aggregated by rebrew.
_SECTION_BUCKETS_SQL = "SELECT * FROM section_cell_stats WHERE target = ?"

# Every bucket computed from `cells` in one pass.  Used ONLY when
# section_cell_stats is absent or empty — a hand-made or partial database (the
# CLI's own fixtures build exactly that), which the pre-split single-query
# version handled and which must keep working.
#
# other_count is the same catch-all rebrew's build_db writes into
# section_cell_stats, and the bucket definitions match it one for one
# (including 'verified' counted as exact, not as other), so the two sources
# cannot disagree and total_cells reconciles with the bucket sum on this path
# exactly as it does on the materialized one.
_SECTION_STATS_FULL_SQL = """
    SELECT section_name,
      SUM(CASE WHEN state != 'none' THEN end - start ELSE 0 END) AS covered_bytes,
      SUM(end - start) AS total_bytes,
      COUNT(*) AS total_cells,
      SUM(CASE WHEN state IN ('exact', 'verified') THEN 1 ELSE 0 END) AS exact_count,
      SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) AS reloc_count,
      SUM(CASE WHEN state IN ('near_match','near_matching') THEN 1 ELSE 0 END) AS near_match_count,
      SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) AS stub_count,
      SUM(CASE WHEN state = 'padding' THEN 1 ELSE 0 END) AS padding_count,
      SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) AS data_count,
      SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) AS thunk_count,
      SUM(CASE WHEN state = 'none' THEN 1 ELSE 0 END) AS none_count,
      SUM(CASE WHEN state = 'proven' THEN 1 ELSE 0 END) AS proven_count,
      SUM(CASE WHEN state = 'size_mismatch' THEN 1 ELSE 0 END) AS size_mismatch_count,
      SUM(CASE WHEN state NOT IN (
        'exact', 'verified', 'reloc', 'near_match', 'near_matching', 'stub',
        'padding', 'data', 'thunk', 'none', 'proven', 'size_mismatch'
      ) THEN 1 ELSE 0 END) AS other_count
    FROM cells WHERE target = ? GROUP BY section_name
"""


def _per_section_buckets(
    c: sqlite3.Cursor, target: str, cell_side: dict[str, sqlite3.Row]
) -> Iterator[tuple[str, dict[str, Any], int, int]]:
    """Yield ``(section_name, buckets, covered_bytes, total_bytes)`` per section.

    Every cell count comes from rebrew's materialized ``section_cell_stats``;
    the byte sums come from *cell_side*, computed from `cells`, because no
    materialized column carries them.  When that table is absent or empty, every
    bucket comes from `cells` instead — the single-query path this endpoint used
    before the split — using the definitions _SECTION_STATS_FULL_SQL keeps in
    step with build_db's.  When it is present but covers only some of the
    sections `cells` has, the missing ones are filled from `cells` too, so a
    partial cache never drops a section from the response.

    The two paths return the same numbers for the same database.  They did
    not: the materialized `exact_count` (which counts 'verified' as exact, like
    /data, Potato Mode and the grid palette) was overwritten with a cells-side
    'exact'-only count, so a database carrying VERIFIED cells reported a total
    its buckets could not sum to, and the same DB answered two different stats
    depending on whether build_db had run.
    """
    try:
        c.execute(_SECTION_BUCKETS_SQL, (target,))
        rows = c.fetchall()
    except sqlite3.OperationalError as exc:
        # A pre-v7 database has no section_cell_stats; the live path below is
        # what keeps it serving.  A database that could not be READ takes the
        # same branch if the guard is dropped, answering with cells-derived
        # buckets and no signal, so it goes to the 503 contract instead.
        if not _is_absent_object(exc):
            raise
        rows = []
    if rows:
        covered: set[str] = set()
        for row in rows:
            name = row["section_name"]
            covered.add(name)
            side = cell_side.get(name)
            yield (
                name,
                _cell_bucket_row(row),
                (side["covered_bytes"] if side is not None else 0) or 0,
                (side["total_bytes"] if side is not None else 0) or 0,
            )
        # A section_cell_stats that is present but PARTIAL (a scoped rebuild, a
        # hand-made database) must not drop the sections it omits: the cells
        # scan already in *cell_side* proves they exist, and a section missing
        # from /stats reports no coverage at all.  Re-aggregate the gap from
        # `cells`, which is the source of truth, so the response covers the same
        # sections either way.
        gap = [name for name in cell_side if name not in covered]
        if gap:
            c.execute(_SECTION_STATS_FULL_SQL, (target,))
            for row in c.fetchall():
                if row["section_name"] not in gap:
                    continue
                yield (
                    row["section_name"],
                    _cell_bucket_row(row),
                    cell_side[row["section_name"]]["covered_bytes"] or 0,
                    cell_side[row["section_name"]]["total_bytes"] or 0,
                )
        return
    c.execute(_SECTION_STATS_FULL_SQL, (target,))
    for row in c.fetchall():
        yield (
            row["section_name"],
            _cell_bucket_row(row),
            row["covered_bytes"] or 0,
            row["total_bytes"] or 0,
        )


def _cell_bucket_row(row: sqlite3.Row) -> dict[str, Any]:
    """Map a per-section bucket row to the short-key dict served by /stats, /data
    and Potato Mode.  ONE definition so the response shapes cannot drift.

    *row* is a ``section_cell_stats`` row (``_SECTION_BUCKETS_SQL``) or the
    same columns computed live from `cells` (``_SECTION_STATS_FULL_SQL``); the
    two must select an identical column set, since the mapping below subscripts
    every one of them by name.  It is never a ``SECTION_STATS_SQL`` row, which
    carries only the two byte sums and the exact count.

    ``other`` is the producer's catch-all (rebrew counts compile_error,
    extract_error, invalid_va, missing_file, missing_size, skip, unknown and
    the data drift/unchecked verdicts there so total_cells reconciles with the
    bucket sum).  Both query paths compute it; a database whose
    section_cell_stats predates the column reports 0 rather than dropping the
    key, so the served shape is the same either way.
    """
    buckets: dict[str, Any] = {
        "total_cells": row["total_cells"],
        "exact": row["exact_count"],
        "reloc": row["reloc_count"],
        "near_match": row["near_match_count"],
        "stub": row["stub_count"],
        "padding": row["padding_count"],
        "data": row["data_count"],
        "thunk": row["thunk_count"],
        "none": row["none_count"],
        "proven": row["proven_count"],
        "size_mismatch": row["size_mismatch_count"],
    }
    # row.keys(), not a bare subscript: a v6-era section_cell_stats (or the
    # pre-other_count view a hand-made DB carries) has no such column, and
    # sqlite3.Row raises IndexError on a missing name.  `in row` is NOT the
    # spelling: sqlite3.Row.__contains__ iterates the row's VALUES, not its
    # keys, so it answers False for a column that is present.
    has_other = "other_count" in row.keys()  # noqa: SIM118 -- Row membership is by value
    buckets["other"] = row["other_count"] if has_other else 0
    return buckets


def _section_stats(c: sqlite3.Cursor, target: str) -> dict[str, Any]:
    """Byte-based per-section stats + summary + by_status for *target*.

    ONE implementation shared by the ``/api/targets/<target>/stats`` endpoint
    and the ``recoverage stats`` CLI.  The summary parse, the SECTION_STATS_SQL
    loop, the section-size lookup, and the by-status count were copy-pasted in
    both (and drifted twice — cell-count vs byte-based, covered_bytes presence,
    key names); this is the single source of truth.
    """
    # Five statements across four tables: without a pinned snapshot a rebuild
    # committing between them yields stats that describe no build at all.
    with read_snapshot(c):
        return _read_section_stats(c, target)


def _read_section_stats(c: sqlite3.Cursor, target: str) -> dict[str, Any]:
    # Pre-computed summary, read from the target's own metadata row
    summary: dict[str, Any] = {}
    c.execute("SELECT value FROM metadata WHERE target = ? AND key = 'summary'", (target,))
    row = c.fetchone()
    if row:
        try:
            summary = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            # Target ids are routable request data (/api/targets/<id>/stats)
            # and originate in analyzed binary names, so they get the same
            # control-char escaping as method/path before hitting the log.
            _log.warning("Corrupt summary metadata for target %s", _log_safe(target))
        else:
            if not isinstance(summary, dict):
                # Valid JSON but not an object (foreign/hand-edited DB): the
                # CLI reads totalFunctions off it with .get() and would crash
                # with AttributeError.  Treat like corrupt JSON above.
                _log.warning(
                    "Summary metadata for target %s is not an object",
                    _log_safe(target),
                )
                summary = {}

    # Per-section stats.  Coverage is BYTE-based: covered = every cell span
    # whose state is not "none", over the section's total cell bytes.
    cell_side: dict[str, sqlite3.Row] = {}
    c.execute(SECTION_STATS_SQL, (target,))
    for row in c.fetchall():
        cell_side[row["section_name"]] = row

    sections: dict[str, Any] = {}
    for name, buckets, covered, total in _per_section_buckets(c, target, cell_side):
        # PROVEN is a semantic-equivalence promotion, so it counts as matched
        # HERE only; rebrew's catalog grid counts byte-identical EXACT/RELOC
        # alone, so this number is not the grid's matchedFunctions.
        matched = buckets["exact"] + buckets["reloc"] + buckets["proven"]
        sections[name] = {
            **buckets,
            "matched": matched,
            "covered_bytes": covered,
            "total_bytes": total,
            "coverage_pct": round(covered / total * 100, 2) if total else 0.0,
        }

    # Section byte sizes, which the schema allows to be NULL
    c.execute("SELECT name, size FROM sections WHERE target = ?", (target,))
    for row in c.fetchall():
        name = row["name"]
        if name in sections:
            # `or 0`, not raw: a NULL size is schema-legal (the .bss shape),
            # and the CLI formats size_bytes with `:,` — None would crash
            # `recoverage stats`/`export` with a TypeError.  A section of
            # unknown size has zero known bytes, same treatment as
            # total_bytes/covered_bytes above.
            sections[name]["size_bytes"] = row["size"] or 0

    # Function counts by status.  GLOBAL/DATA/VTABLE/STRING marker rows live in
    # the functions table but are data markers, not functions — exclude them.
    by_status: dict[str, int] = {}
    c.execute(
        "SELECT status, COUNT(*) as cnt FROM functions"
        f" WHERE target = ? AND {NOT_DATA_MARKER_SQL} GROUP BY status",
        (target,),
    )
    for row in c.fetchall():
        by_status[row["status"] or "unknown"] = row["cnt"]

    return {"summary": summary, "sections": sections, "by_status": by_status}


# ── Path helpers ───────────────────────────────────────────────────


def _assets_dir() -> Path:
    """Return the directory containing recoverage UI files (HTML/CSS/JS).
    These ship as package data inside the recoverage package."""
    return Path(__file__).resolve().parent / "assets"


def _project_dir() -> Path:
    return Path.cwd().resolve()


# ── DLL loading ────────────────────────────────────────────────────

DLL_DATA: dict[str, bytes | None] = {}
DLL_LOCK = threading.Lock()
#: Config stat the current DLL_DATA was filled under, or None before the
#: first load (and for a project with no rebrew-project.toml, which is also a
#: state entries get cached under).  The rebuild broadcast empties DLL_DATA
#: under the same lock and deliberately leaves this alone: the config did not
#: change, so the next request reloads under a fingerprint that still matches.
_DLL_CONFIG_MTIME: tuple[int, int] | None = None
_MAX_DLL_SIZE = 512 * 1024 * 1024  # 512 MiB — reject unreasonably large binaries


_TOML_CONFIG_CACHE: dict[str, Any] | None = None
#: Key for :data:`_RESOLVED_TARGETS_CACHE`: the config stat and the WAL-aware
#: DB snapshot, the two inputs of the merge, so the memo self-invalidates on
#: either.  The DB half the rebuild broadcast already covered; the config half
#: nothing did (see :func:`resolve_targets`).
_ResolvedTargetsKey = tuple[tuple[int, int] | None, tuple[int, int] | None]
_RESOLVED_TARGETS_CACHE: tuple[_ResolvedTargetsKey, list[dict[str, str]]] | None = None
_RESOLVED_TARGETS_CACHE_LOCK = threading.RLock()


_log = logging.getLogger("recoverage")

# Control characters (C0, DEL, C1) and the two Unicode line terminators,
# which would otherwise let a crafted URL or header forge multi-line entries
# in the request log (%0A in the path percent-decodes to a raw newline).  Each
# is replaced by its \xNN escape so the offending request stays identifiable
# while remaining one log line.  C1 and U+2028/U+2029 are in the table for the
# same reason as C0: every consumer that breaks a log on \n breaks on them
# too, and a percent-escaped %C2%85 (NEL) or %E2%80%A8 reaches _log_safe
# decoded.  Bidi controls stay out: they reorder a line rather than split it,
# so escaping them is a log-injection question, not a line-splitting one.
_LOG_CONTROL_CHARS = (
    {c: f"\\x{c:02x}" for c in range(32)}
    | {127: "\\x7f"}
    | {c: f"\\x{c:02x}" for c in range(0x80, 0xA0)}
    | {0x2028: "\\x2028", 0x2029: "\\x2029"}
)


def _log_safe(value: str) -> str:
    """Escape line-breaking control characters in untrusted text for the log."""
    return value.translate(_LOG_CONTROL_CHARS)


_TOML_CACHE_MTIME: tuple[int, int] | None = None


def _config_stat_fingerprint(root: Path) -> tuple[int, int] | None:
    """``(mtime_ns, size)`` of the project config under *root*, None when absent.

    The one definition of the change token every config-derived memo keys on:
    the parsed config (:func:`_get_targets_config`), the resolved target list
    (:func:`resolve_targets`), and the DLL byte cache (:func:`_load_dll`).
    Editing ``rebrew-project.toml`` is a write that reaches no server code, so
    a stat is the only invalidation signal available; naming the same one in
    every key is what keeps those memos from disagreeing about whether the
    config changed.
    """
    try:
        st = (root / CONFIG_NAME).stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _get_targets_config() -> dict[str, Any]:
    """Load target configuration from rebrew-project.toml (thread-safe, cached).

    Each value's ``filename`` is the target binary resolved against the project
    root ("" when the target configures none), the shape ``_target_filename``
    and ``_find_dll_path`` consume.
    """
    global _TOML_CONFIG_CACHE, _TOML_CACHE_MTIME
    root = _project_dir()
    toml_path = root / CONFIG_NAME
    current = _config_stat_fingerprint(root)
    with _RESOLVED_TARGETS_CACHE_LOCK:
        if _TOML_CONFIG_CACHE is not None and current == _TOML_CACHE_MTIME:
            return _TOML_CONFIG_CACHE

        config = read_config(root)
        if toml_path.is_file() and not config:
            # read_config swallows the read/decode error and returns {}; a
            # present file that yields nothing is unreadable or not valid TOML.
            _log.warning("Failed to load %s: unreadable or invalid TOML", CONFIG_NAME)
        targets_info: dict[str, Any] = {}
        for tid, entry in targets_table(config).items():
            binary = target_binary(root, entry)
            targets_info[tid] = {"filename": str(binary) if binary is not None else ""}

        _TOML_CONFIG_CACHE = targets_info
        _TOML_CACHE_MTIME = current
        return targets_info


def clear_target_cache() -> None:
    global _TOML_CONFIG_CACHE, _TOML_CACHE_MTIME, _RESOLVED_TARGETS_CACHE, _SCHEMA_VERSION_CACHE
    with _RESOLVED_TARGETS_CACHE_LOCK:
        _TOML_CONFIG_CACHE = None
        _TOML_CACHE_MTIME = None
        _RESOLVED_TARGETS_CACHE = None
        _SCHEMA_VERSION_CACHE = None


def _target_filename(tid: str, t_info: Any) -> str:
    """Binary filename configured for target *tid* (*tid* when unset).

    ONE definition of the defensive shape check used for display names —
    the config loader stores the binary path already resolved against the
    project root ("" when the target configures none), and both target-list
    builders fall back to the id here.
    """
    filename = t_info.get("filename", tid) if isinstance(t_info, dict) else tid
    return filename or tid


#: Every built target id, excluding the reserved schema-version row.  ONE
#: definition: the SPA dropdown, /api/health's target count, and the CLI's
#: ``--target`` validation all read the same set from the same place.  Most
#: tables carry a ``target`` column too, but ``metadata`` is the one stamped
#: for every built target (build_db writes a per-target ``db_version`` row), so
#: a target whose payload tables came out empty is still listed.  Sorted so
#: every consumer gets a deterministic list (SQLite's DISTINCT order is
#: arbitrary).
_DB_TARGETS_SQL = "SELECT DISTINCT target FROM metadata WHERE target != ? ORDER BY target"


def db_target_ids(c: sqlite3.Cursor) -> list[str]:
    """Target ids with build data in *c*, schema row excluded, sorted.

    The read-only counterpart to :func:`resolve_targets`: the ids the database
    alone knows about, before the project config contributes any target that has
    never been built.
    """
    c.execute(_DB_TARGETS_SQL, (SCHEMA_TARGET,))
    return [row[0] for row in c.fetchall()]


def resolve_targets(c: sqlite3.Cursor) -> list[dict[str, str]]:
    """Resolve available targets from DB + config (thread-safe, cached via RLock).

    Config-declared targets first, then any DB-only target, so the SPA
    dropdown and Potato Mode render and default to the same first entry.

    Memoized per (config stat, WAL-aware DB snapshot) — both inputs to the
    merge, the same contract every other DB-derived memo follows.  Keying on
    the config alone would have been the obvious half: the parsed config
    self-invalidates on its stat, so without the config half in this key the
    two disagreed.  Adding a target to ``rebrew-project.toml`` while the
    server ran left ``_get_targets_config`` reporting it (and
    ``_require_target`` accepting it) while the dropdown, ``/api/targets`` and
    Potato Mode's list omitted it until the next coverage.db rebuild cleared
    the memo.  The DB half is what the rebuild broadcast already covered; both
    are named here so neither depends on an event that may never fire.
    """
    global _RESOLVED_TARGETS_CACHE
    key: _ResolvedTargetsKey = (
        _config_stat_fingerprint(_project_dir()),
        _snapshot_db_mtime(),
    )
    with _RESOLVED_TARGETS_CACHE_LOCK:
        cached = _RESOLVED_TARGETS_CACHE
        if cached is not None and cached[0] == key:
            return cached[1]

        target_ids = db_target_ids(c)
        targets_info = _get_targets_config()

        # Config-declared targets come first and are always addressable, even
        # before their first build — _require_target treats "declared in the
        # project config" as valid, so a never-built target must not 404.
        targets_list = [
            {"id": tid, "name": Path(_target_filename(tid, t_info)).name}
            for tid, t_info in targets_info.items()
        ]
        targets_list += [{"id": tid, "name": tid} for tid in target_ids if tid not in targets_info]

        _RESOLVED_TARGETS_CACHE = (key, targets_list)
        return targets_list


def _find_dll_path(target: str) -> Path | None:
    """Find the DLL path for a target from project config.

    Returns ``None`` when *target* has no ``[targets.<tid>].binary`` entry —
    the caller then reports a target-specific error instead of silently
    serving a different target's DLL (previously fell back to SERVER's
    binary, which produced plausible-but-wrong disassembly for config-less
    targets).
    """
    targets = _get_targets_config()
    if target not in targets:
        return None
    t_info = targets.get(target)
    filename = t_info.get("filename", "") if isinstance(t_info, dict) else ""
    if not filename:
        return None
    return _project_dir() / filename


def _cache_dll_unavailable(
    target: str, config_fp: tuple[int, int] | None, warning: str, *args: object
) -> bytes | None:
    """Record *target*'s DLL as unloadable, logging *warning* once.

    The failure paths that are permanent for as long as the config is
    unchanged (no configured binary, an oversize read) end here so the
    double-checked insert lives in one place instead of once per path: another
    thread may have loaded the binary while this thread was doing the work
    that failed, and that successful load wins.  A read that raises OSError is
    the exception: it is not cached, so a transient failure costs a retry
    rather than pinning the target to no DLL for the config's lifetime.
    Nothing is recorded once *config_fp* has moved on: the verdict describes
    the config this load resolved against, and recording it would pin it past
    the edit that fixes it.  String arguments are control-char escaped
    on the way to the log; numbers are passed through for %d.
    """
    with DLL_LOCK:
        if config_fp != _DLL_CONFIG_MTIME:
            return None
        if target in DLL_DATA:
            return DLL_DATA[target]
        _log.warning(warning, *(_log_safe(a) if isinstance(a, str) else a for a in args))
        DLL_DATA[target] = None
        return None


def _load_dll(target: str) -> bytes | None:
    """Load DLL bytes for a target into DLL_DATA (thread-safe).

    Why no outer check: reading DLL_DATA[target] outside the lock races with
    dict resize triggered by __setitem__ in another thread.  The GIL protects
    individual bytecodes but not multi-step dict operations during resize.

    DLL_DATA is keyed by target alone, so a config edit that re-points
    ``[targets.X].binary`` — or gives a target one it had none of — left the
    old bytes (or the ``None`` of a not-yet-configured target) served to /asm
    and /bytes until the next coverage.db rebuild.  Re-pointing a binary is an
    operator edit to rebrew-project.toml: it reaches no server code, and the
    rebuild broadcast that clears this dict fires on the DB alone.  The memo
    therefore carries the same config stat its path resolution keys on
    (:func:`_config_stat_fingerprint`) and drops every entry when that moves,
    the contract :func:`_get_targets_config` already follows.
    """
    global _DLL_CONFIG_MTIME
    config_fp = _config_stat_fingerprint(_project_dir())
    with DLL_LOCK:
        if config_fp != _DLL_CONFIG_MTIME:
            _DLL_CONFIG_MTIME = config_fp
            DLL_DATA.clear()
        elif target in DLL_DATA:
            return DLL_DATA[target]
    dll_path = _find_dll_path(target)
    if dll_path is None:
        return _cache_dll_unavailable(
            target,
            config_fp,
            "No [targets.%s].binary configured — cannot load DLL for target %s",
            target,
            target,
        )
    try:
        file_size = dll_path.stat().st_size
        if file_size > _MAX_DLL_SIZE:
            return _cache_dll_unavailable(
                target,
                config_fp,
                "DLL %s (%d MiB) exceeds %d MiB limit, skipping",
                str(dll_path),
                file_size >> 20,
                _MAX_DLL_SIZE >> 20,
            )
        data = dll_path.read_bytes()
        if len(data) > _MAX_DLL_SIZE:
            return _cache_dll_unavailable(
                target,
                config_fp,
                "DLL %s (%d MiB) exceeds %d MiB limit after read, skipping",
                str(dll_path),
                len(data) >> 20,
                _MAX_DLL_SIZE >> 20,
            )
    except OSError as exc:
        _log.warning(
            "Failed to load DLL for target %s at %s: %s: %s",
            _log_safe(target),
            _log_safe(str(dll_path)),
            type(exc).__name__,
            exc,
        )
        return None
    with DLL_LOCK:
        # A config edit landing during the read resolves this load against a
        # path that is no longer current; caching its bytes would serve the
        # binary the edit just replaced.  Hand them back uncached instead.
        if config_fp != _DLL_CONFIG_MTIME:
            return data
        if target in DLL_DATA:
            return DLL_DATA[target]
        DLL_DATA[target] = data
        return data


# ── Compression ────────────────────────────────────────────────────


def _header(name: str, default: str = "") -> str:
    """A request header as text, or *default* when the value is not text.

    A WSGI server decodes raw header bytes as latin-1, so a peer can send a
    byte above 0x7f.  bottle re-reads environ values as UTF-8 and raises
    UnicodeDecodeError on one, which would turn a junk header into a 500 and a
    traceback in the log on every request.  A header that is not decodable text
    carries no usable value, so it reads as absent — the same answer the
    RFC 9110 grammar gives for a value that is not a valid field value.
    """
    try:
        return request.headers.get(name, default)
    except UnicodeDecodeError:
        return default


#: Every encoding this server can produce, most preferred first.  ONE list:
#: :func:`_best_encoding` walks it in order, and the precompressed static path
#: (:func:`static_variant_key`, :func:`compress_static_variants`) reads the same
#: order for its cache key, so a client cannot be offered a representation the
#: dynamic path would refuse or vice versa.
SUPPORTED_ENCODINGS: tuple[str, ...] = ("zstd", "br", "gzip")


def accepted_encodings(accept_encoding: str) -> frozenset[str]:
    """Which of :data:`SUPPORTED_ENCODINGS` the client will accept.

    Parses comma-separated tokens to avoid false substring matches (e.g.
    'not-zstd' must not match 'zstd'), and honours q-values as an exclusion
    gate only — ``gzip;q=0`` means "not acceptable" (RFC 9110).  A bare ``*``
    matches nothing here: it names no specific encoding, and answering it with
    a guess is the dynamic path's job to make explicitly.

    Relative q-values are NOT ranked.  Every modern browser sends
    ``gzip, deflate, br, zstd`` with flat q-values, so ordering by q would pick
    by header order, not by merit.
    """
    candidates: dict[str, float] = {}
    for t in accept_encoding.split(","):
        parts = [p.strip().lower() for p in t.split(";")]
        name = parts[0]
        if not name or name == "*":
            continue
        q = 1.0
        for param in parts[1:]:
            if param.startswith("q="):
                try:
                    q = float(param[2:])
                except ValueError:
                    q = 0.0
        if q > 0:
            candidates[name] = max(candidates.get(name, 0.0), q)
    return frozenset(name for name in SUPPORTED_ENCODINGS if candidates.get(name, 0.0) > 0)


def _best_encoding(accept_encoding: str) -> str:
    """Return the best available compression encoding name, or empty string.

    Applies a fixed preference order (:data:`SUPPORTED_ENCODINGS`) to the
    encodings the client accepts.  This is the DYNAMIC policy, for payloads
    built per request: a fixed order keeps one compressor hot instead of
    compressing the same request body two or three ways.

    The precompressed path cannot use it — see :func:`static_variant_key`.
    """
    accepted = accepted_encodings(accept_encoding)
    for name in SUPPORTED_ENCODINGS:
        if name in accepted:
            return name
    return ""


# Brotli quality is the difference between a fast response and a stalled one.
# On a 5.6 MB coverage payload, measured: q=11 gives 334 KB in 5.9 s, q=5 gives
# 444 KB in 68 ms.  Dynamic responses pay that cost on every request (there is
# no compressed-response cache), and clients without zstd — Safari, older
# browsers — land on brotli, so q=11 there means a six-second stall on every
# load and every live reload.  110 KB is cheaper than 5.8 s on any real link.
BROTLI_DYNAMIC_QUALITY = 5
# The inlined index is compressed once and cached per encoding, and it has a
# hard byte budget (the initial congestion window), so it keeps maximum effort.
BROTLI_STATIC_QUALITY = 11

# zstd effort for the same precompressed surfaces.  The dynamic compressor
# above is level 3 because a multi-megabyte /data payload pays that cost on
# every request; the shell and the static assets are compressed once per
# encoding and then served from a dict, so they take the same "pay once, keep
# the effort" trade BROTLI_STATIC_QUALITY already makes.  Measured on the
# shipped assets: hljs.min.js 45,575 -> 39,773 bytes and detail.js
# 10,468 -> 9,555 (both zstd), for ~20 ms paid once instead of 6 ms per
# request.  Level 19 is where zstd stops returning a smaller frame on these
# bodies (level 22 matches it exactly), so this is the knee, not a guess.
ZSTD_STATIC_LEVEL = 19

# gzip's own maximum.  gzip is the fallback a scripted client lands on
# (python-requests advertises only gzip), and there it is the ONLY
# representation on the wire, so it is worth the highest level gzip offers.
# It still loses to both modern encodings on every payload measured here.
GZIP_STATIC_LEVEL = 9


def static_variant_key(accept_encoding: str) -> str:
    """Cache key naming the encodings a precompressed body may be chosen from.

    A precompressed response picks the SMALLEST representation the client can
    decode rather than a fixed preference, so its body is a function of the
    client's whole accepted set — not of any one token.  This key names that
    set, which is what makes the cache (and the ``Vary: Accept-Encoding``
    contract) sound: two clients with the same key get byte-identical
    responses, and a client can never be handed a body it did not ask for.

    The key is drawn from :data:`SUPPORTED_ENCODINGS` in that fixed order, so
    it is at most 2**3 spellings no matter what the client sends.  It is
    itself a valid ``Accept-Encoding`` value naming exactly that subset, which
    is what lets a cache pre-build a key without a client header to hand.
    """
    accepted = accepted_encodings(accept_encoding)
    return ", ".join(name for name in SUPPORTED_ENCODINGS if name in accepted)


def compress_static_variants(body: bytes, accept_encoding: str) -> tuple[bytes, str]:
    """Compress *body* to the smallest representation the client accepts.

    The precompressed counterpart of :func:`compress_payload`, for bytes built
    once and served many times (the SPA shell, the static assets).  Two
    differences from the dynamic path, both of which only make sense off the
    per-request path:

    * EVERY accepted encoding is produced and the smallest body wins, at
      maximum effort.  Compressing the same static bytes two or three ways
      costs nothing per request and guarantees the winner is the real minimum.
      The dynamic path cannot afford that, and must not: it keeps a fixed
      order and compresses once.
    * zstd runs at :data:`ZSTD_STATIC_LEVEL` rather than the dynamic level 3.

    Measured on the SPA shell: brotli q11 gives 14,090 bytes against zstd's
    17,052 at the dynamic level and 15,145 even at level 19.  zstd wins on
    throughput, not on this payload, and a fixed zstd-first preference handed
    every zstd-capable browser 3 KB more than necessary and pushed the shell
    past the initial congestion window (14,600), costing a second round trip
    before the first paint.  Choosing by size puts it back inside the window.

    Returns (body, "") when the client accepts none of the supported
    encodings, so the caller sets Content-Encoding only on a truthy name.
    """
    accepted = accepted_encodings(accept_encoding)
    if not accepted:
        return body, ""
    best: tuple[bytes, str] | None = None
    for name in SUPPORTED_ENCODINGS:
        if name not in accepted:
            continue
        if name == "zstd":
            candidate = zstd.ZstdCompressor(level=ZSTD_STATIC_LEVEL).compress(body)
        elif name == "br":
            candidate = brotli.compress(body, quality=BROTLI_STATIC_QUALITY)
        else:
            candidate = gzip.compress(body, compresslevel=GZIP_STATIC_LEVEL)
        if best is None or len(candidate) < len(best[0]):
            best = (candidate, name)
    assert best is not None  # accepted is non-empty and drawn from SUPPORTED_ENCODINGS
    return best


def compress_payload(body: bytes, accept_encoding: str) -> tuple[bytes, str]:
    """Compress body with the best algorithm the client accepts.

    Returns (compressed_body, encoding_name). encoding_name is "" if no
    compression was applied, guaranteeing the caller can always set
    Content-Encoding only when encoding is truthy.
    """
    encoding = _best_encoding(accept_encoding)
    if encoding == "zstd":
        return _get_zstd_compressor().compress(body), "zstd"
    if encoding == "br":
        return brotli.compress(body, quality=BROTLI_DYNAMIC_QUALITY), "br"
    if encoding == "gzip":
        # Level 6, not gzip.compress's default 9: measured on a ~9 MB /data
        # payload, -9 costs 2x the CPU of -6 for ~9% fewer bytes (96 ms ->
        # 707 KB vs 45 ms -> 774 KB).  Dynamic responses pay this on every
        # request, and scripted clients (python-requests advertises only
        # gzip) always land here.  Same reasoning as BROTLI_DYNAMIC_QUALITY.
        return gzip.compress(body, compresslevel=6), "gzip"
    return body, ""


# ── SQL helpers ────────────────────────────────────────────────────


def _escape_like(search: str) -> str:
    """Escape SQL LIKE wildcards (% and _) for safe parameterized queries.

    Returns the escaped pattern wrapped in % for substring matching.
    Uses backslash as the ESCAPE character — all callers must include
    ``ESCAPE '\\\\'`` in their LIKE clauses.

    Backslash itself must be escaped first, since it is the ESCAPE character
    and would otherwise consume the next character as a literal.
    """
    return "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def fold_text(text: str | None) -> str | None:
    """NFC + full case folding: the one form a name is searched in.

    ``LIKE`` folds case for ASCII only, so ``name LIKE '%CAFÉ%'`` does not
    match ``Café_Render`` and a search that a user can see in the symbol table
    returns nothing.  NFC first, so the NFD spelling of the same name (what a
    macOS-side tool writes) matches the NFC one.  ``casefold``, not ``lower``:
    it is the folding operators for caseless matching, and it maps ß to ss
    the way a reader expects.  Compatibility folding is deliberately not
    applied: NFKC would make a superscript or a circled digit compare equal to
    a plain letter, which is not what a substring search should claim.

    NULL passes through: this is registered as a SQL function and a nullable
    column (``functions.symbol``) reaches it as NULL, which a ``str`` call
    would raise on, failing the whole query.
    """
    if text is None:
        return None
    return unicodedata.normalize("NFC", text).casefold()


#: SQL name of :func:`fold_text`, registered on every read connection by
#: :func:`_open_db`.  One name for the one folding, so the SPA, the API list
#: and Potato Mode cannot drift onto different definitions.
FOLD_SQL = "rc_fold"


def like_match(columns: Sequence[str]) -> tuple[str, int]:
    """``(sql, param_count)`` for an OR chain of LIKE tests over *columns*.

    Every column goes through ``COALESCE(col, '')`` and that is load-bearing,
    not defensive: ``functions.symbol`` is nullable, and SQL's three-valued
    logic turns one NULL in an ``OR`` chain into a NULL predicate.  ANDed
    against another match (``AND (a OR NULL) AND (folded match)``), the row is
    dropped even though its name matched — a row with no symbol was invisible
    to every search.

    A NULL therefore compares as the empty string, which no non-empty search
    term can match: :func:`_escape_like` always wraps the term in ``%``.
    """
    disjunct = " OR ".join(f"COALESCE({col}, '') LIKE ? ESCAPE '\\'" for col in columns)
    return f"({disjunct})", len(columns)


def folded_like_clause(columns: Sequence[str], search: str) -> tuple[str, list[str]]:
    """``(sql, params)`` for a Unicode-correct disjunct over *columns*.

    ``LIKE`` already folds ASCII correctly, so a pure-ASCII term needs
    nothing extra and the common path keeps its single predicate.  A term
    carrying any non-ASCII character is one SQLite's folding cannot judge, so
    the caller adds this disjunct alongside its ``LIKE``: the columns and the
    pattern both go through :data:`FOLD_SQL` before the comparison.

    Returns ``("", [])`` for an ASCII term or no columns, so callers can test
    the clause rather than the term.  The pattern is escaped after folding, so
    a wildcard character the fold produced cannot act as one.
    """
    if not columns or search.isascii():
        return "", []
    folded = _escape_like(cast(str, fold_text(search)))
    disjunct = " OR ".join(f"COALESCE({FOLD_SQL}({col}), '') LIKE ? ESCAPE '\\'" for col in columns)
    return f"({disjunct})", [folded] * len(columns)


# ── SQL fragments ──────────────────────────────────────────────────

#: SQLite's wording for a schema object the database does not carry.
_ABSENT_OBJECT_MARKERS = ("no such table", "no such column")


def _is_absent_object(exc: sqlite3.Error) -> bool:
    """Whether *exc* is SQLite reporting a schema object the database lacks.

    The one test every "this older or foreign database has no such table"
    fallback routes through.  A degrade-on-older-schema path answers
    ``no such table``/``no such column`` from ``cells`` so a pre-v7 database
    still serves; any other ``sqlite3.Error`` means the file could not be read,
    which propagates to the 503 ``db_unavailable`` contract rather than
    producing a fallback payload that looks like a successful read.
    """
    message = str(exc).lower()
    return any(marker in message for marker in _ABSENT_OBJECT_MARKERS)


#: Optional v6 columns, probed per connection: older DBs (v5 and below)
#: lack them, and the endpoints degrade instead of 500ing.
_V6_FUNCTION_COLS = ("updated_by", "updated_at")
_V6_GLOBAL_COLS = ("status",)
_V6_VERIFY_COLS = ("reg_delta", "effective_match")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Column names of *table*; empty set when the table is missing.

    ``PRAGMA table_info`` answers a name no table carries with zero rows, not
    an error, so a missing table needs no guard and every ``sqlite3.Error``
    raised here is a database that could not be read.  Returning an empty set
    for one would drop every optional v6 column from the function, global and
    verify payloads — a silently short response, where the 503 contract says
    the failure belongs.
    """
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1] for r in rows}


def _fn_json_sql(conn: sqlite3.Connection) -> str:
    """Function detail projection, extended with v6 columns when present."""
    cols = _table_columns(conn, "functions")
    extra = "".join(f", '{c}', {c}" for c in _V6_FUNCTION_COLS if c in cols)
    return _FN_JSON_SQL[:-1] + extra + ")"


def _global_json_sql(conn: sqlite3.Connection) -> str:
    """Global detail projection, extended with v6 status when present."""
    cols = _table_columns(conn, "globals")
    extra = "".join(f", '{c}', {c}" for c in _V6_GLOBAL_COLS if c in cols)
    return _GLOBAL_JSON_SQL[:-1] + extra + ")"


def _verify_select(conn: sqlite3.Connection) -> str:
    """verify_results column list, extended with v6 columns when present."""
    cols = _table_columns(conn, "verify_results")
    extra = "".join(f", {c}" for c in _V6_VERIFY_COLS if c in cols)
    return "SELECT va, verified_at, byte_delta, diff_lines, similarity" + extra


def _verify_one_select(conn: sqlite3.Connection) -> str:
    """Single-row verify_results projection, extended when v6 is present."""
    cols = _table_columns(conn, "verify_results")
    extra = "".join(f", {c}" for c in _V6_VERIFY_COLS if c in cols)
    return "SELECT verified_at, byte_delta, diff_lines, similarity" + extra


_FN_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'vaStart', vaStart, 'size', size, "
    "'fileOffset', fileOffset, 'status', status, 'module', module, "
    "'cflags', cflags, 'symbol', symbol, 'markerType', markerType, "
    "'ghidra_name', ghidra_name, 'list_name', list_name, "
    "'is_thunk', is_thunk, 'is_export', is_export, 'sha256', sha256, "
    "'files', json(files), "
    "'detected_by', json(detected_by), 'size_by_tool', json(size_by_tool), "
    "'textOffset', textOffset, 'blocker', blocker, 'blockerDelta', blockerDelta, "
    "'size_reason', size_reason, 'similarity', similarity"
    ")"
)

_GLOBAL_JSON_SQL = (
    "json_object("
    "'va', va, 'name', name, 'decl', decl, "
    "'files', json(files), 'module', module, 'size', size, 'isGlobal', 1"
    ")"
)

# Cell shape for the SPA /data payload and the Potato grid. SECTION_CELLS_AGG_SQL
# is the ordered aggregate build_db writes into section_cells_json (the
# CELLS_JSON_OBJECT_SQL projection, json_group_array ... ORDER BY start). The
# live fallback uses that same expression so a database without the cache cannot
# drift into a different cell shape or into planner row order. `id` is omitted
# from the projection: no consumer reads it.
_CELLS_JSON_SQL = f"SELECT section_name, {SECTION_CELLS_AGG_SQL} FROM cells WHERE target = ?"


def _lookup_by_va_or_name(
    c: sqlite3.Cursor, table: str, json_sql: str, target: str, value: str
) -> sqlite3.Row | None:
    """First row of *table* matching *value* as a VA, else as a folded name.

    ONE resolution order for the /functions/<va> route and both Potato Mode
    detail panels: callers name a function by VA ("0x10001000") or, for
    legacy cells, by the symbol outright.  A VA-shaped entry that matches no
    row still falls through to the name lookup, so the route and the panels
    cannot disagree about what a value names.  *table* and *json_sql* are
    literals from the call sites; target and the value are parameterized.

    The name is first compared byte for byte, which is what
    ``idx_functions_name``/``idx_globals_name`` serve.  Only a miss falls
    through to the folded comparison through :data:`FOLD_SQL`, the same NFC +
    case fold every search uses: the exact spelling is a prefix of nothing
    but itself, so a row the database spells one way is found by that index,
    and the fold runs once, on the way a user spelled something else.  Byte
    equality alone made a symbol the user could find through
    /functions?search= unresolvable by name: the NFD spelling macOS puts on
    the clipboard (``e`` + U+0301 COMBINING ACUTE) is a different byte string
    from the NFC one rebrew stores, so the row the search highlighted 404'd
    when it was opened.  Folding in SQL rather than in Python keeps the
    stored name untouched, so a database predating this lookup needs no
    migration.  The fallback cannot use the name index, so it scans the
    target's rows; a VA-shaped value, which is what nearly every cell carries,
    never reaches it.

    SAFETY: the interpolated parts are the table name, the projection and the
    registered function name, all supplied by this module or the caller as
    literals.
    """
    prefix = f"SELECT {json_sql} FROM {table} WHERE target=? AND "
    for candidate in parse_va_candidates(value):
        c.execute(prefix + "va=?", (target, candidate))
        row = c.fetchone()
        if row:
            return row
    c.execute(prefix + "name=?", (target, value))
    row = c.fetchone()
    if row is not None:
        return row
    c.execute(prefix + f"{FOLD_SQL}(name)={FOLD_SQL}(?)", (target, fold_text(value)))
    return c.fetchone()


def _has_materialized_cells(c: sqlite3.Cursor) -> bool:
    """Whether this DB carries rebrew's precomputed cell JSON in the current codec.

    One query answers all three cases, because it asks for the COLUMN rather than
    the table: no table (pre-v7 database), a table in the old zlib codec (a
    database built before the codec switch), and the current zstd column.  Only
    the last is decoded; the others are served by the live query, which is
    correct — just slower — and self-heals on the next ``build-db``.  Probing the
    column is also why the codec needs no version check here.

    Deliberately NOT memoized.  The check costs 0.002 ms against the ~9 ms it
    saves, and memoizing it would have to be keyed by something — a bare
    module global assumes one DB per process, which is false for the tests and
    for any caller that re-points _db_path, and it fails *loudly and wrongly*
    by querying a table that is not there.  A fingerprint-keyed memo would cost
    about as much as the query it replaces.
    """
    # No guard for a table the database does not carry: pragma_table_info
    # answers an unknown name with zero rows, which is the False this returns.
    # A sqlite3.Error here is a database that could not be read, and answering
    # "no cache, use the live query" would be a slow but plausible response
    # where the 503 contract says the failure belongs.
    c.execute(
        "SELECT 1 FROM pragma_table_info(?) WHERE name = ?",
        (SECTION_CELLS_TABLE, SECTION_CELLS_COLUMN),
    )
    return c.fetchone() is not None


def _cells_json_rows(
    c: sqlite3.Cursor,
    target: str,
    section: str | None = None,
    expected_sections: set[str] | None = None,
) -> list[tuple[str, str]]:
    """Per-section cell JSON payloads as (section_name, cells_json) rows.

    Prefers rebrew's materialized ``section_cells_json`` table — reading and
    decompressing one pre-aggregated zstd blob (measured 0.3 ms to read, ~0.47 ms
    to inflate the largest 4.13 MB section) beats re-running
    ``json_group_array`` over every cell (10.7 ms on a 39k-cell section).
    Falls back to the live query when the table is absent or written in an older
    codec, so a pre-v7 database keeps working and self-heals on its next build.

    *expected_sections* is the section-name set the caller already read from
    ``sections``.  When the materialized table is PARTIAL (present and current
    codec, but missing a section, as a scoped rebuild or a hand-made database
    leaves it), the
    missing sections are re-aggregated from ``cells`` rather than dropped: a
    dropped section renders as an empty grid, and every one of its bytes reads
    as ``none`` in the SPA and Potato Mode, which is a wrong answer rather than
    a slow one.  The caller already holds the section list inside the same
    pinned snapshot, so the extra query only runs when a section is actually
    missing.
    """
    clause = " AND section_name = ?" if section else ""
    params: list[Any] = [target, *([section] if section else [])]
    if _has_materialized_cells(c):
        c.execute(
            f"SELECT section_name, {SECTION_CELLS_COLUMN} FROM {SECTION_CELLS_TABLE}"
            f" WHERE target = ?{clause}",
            params,
        )
        rows = [(row[0], decode_section_cells(row[1])) for row in c.fetchall()]
        missing = _uncovered_sections({name for name, _ in rows}, expected_sections)
        if not missing:
            return rows
        rows += _live_cells_json_rows(c, target, missing)
        return rows

    return _live_cells_json_rows(c, target, None, section)


def _uncovered_sections(present: set[str], expected: set[str] | None) -> list[str]:
    """Expected section names *present* does not cover, in a stable order."""
    if not expected:
        return []
    return sorted(name for name in expected if name not in present)


def _live_cells_json_rows(
    c: sqlite3.Cursor,
    target: str,
    only: list[str] | None,
    section: str | None = None,
) -> list[tuple[str, str]]:
    """``json_group_array`` over ``cells`` for *target*, narrowed by *section*
    and/or *only*.

    *only* names the sections to aggregate; every other section is skipped, so
    filling the gap a partial cache left does not re-aggregate the whole target.
    """
    clause = ""
    params: list[Any] = [target]
    if section is not None:
        clause = " AND section_name = ?"
        params.append(section)
    if only is not None:
        if not only:
            return []
        # SAFETY: placeholders is only "?,?,...", its length comes from *only*,
        # and every value reaches the statement parameterized.
        clause += f" AND section_name IN ({','.join('?' * len(only))})"
        params.extend(only)
    c.execute(_CELLS_JSON_SQL + f"{clause} GROUP BY section_name", params)
    return [(row[0], row[1]) for row in c.fetchall()]


def _evict_oldest(cache: dict[Any, Any], max_size: int) -> None:
    """Drop oldest entries (dict insertion order) until *cache* holds < max_size.

    ONE definition of the bounded-cache arithmetic behind every per-DB-snapshot
    memo in the package (/data payloads, /stats, the function list totals, and
    Potato's cells and per-section stats).  They are keyed by a snapshot that
    changes on every rebuild, so a long-running server would otherwise
    accumulate an entry per snapshot forever.
    Caller holds the cache's own lock.
    """
    if len(cache) >= max_size:
        for old_key in list(cache)[: len(cache) - max_size + 1]:
            cache.pop(old_key, None)


def _format_hex_dump(raw_bytes: bytes, base_offset: int = 0, max_bytes: int | None = 256) -> str:
    """Format bytes as the canonical 16-bytes-per-line hex dump.

    ONE definition shared by the /bytes endpoint's ``hex`` payload and
    Potato Mode's Original Bytes block (the two inline copies had already
    drifted: a single 48-char hex column vs 8+8 byte columns).  Layout:
    8-hex-digit offset, hex bytes in two 8-byte columns, ASCII gutter —
    matching detail.js's client-side dump.  *max_bytes* caps the dump and
    appends a ``... (N more bytes)`` tail; ``None`` dumps everything.
    """
    data = raw_bytes if max_bytes is None else raw_bytes[:max_bytes]
    lines: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        offset = f"{base_offset + i:08x}"
        hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset}  {hex_left:<23s}  {hex_right:<23s}  |{ascii_repr}|")
    if max_bytes is not None and len(raw_bytes) > max_bytes:
        lines.append(f"... ({len(raw_bytes) - max_bytes} more bytes)")
    return "\n".join(lines)


_METADATA_VALUE_MAX_BYTES = 1 * 1024 * 1024


def _load_metadata(c: sqlite3.Cursor, target: str) -> dict[str, Any]:
    """Load *target*'s metadata rows as a dict, JSON-decoding values when valid.

    ONE loader for every consumer of the metadata table (SPA /data, Potato
    summary/paths): malformed JSON falls back to the raw string instead of
    failing the whole response.  Values larger than 1 MiB are kept as raw
    strings to bound json.loads work per-row.
    """
    data: dict[str, Any] = {}
    c.execute("SELECT key, value FROM metadata WHERE target = ?", (target,))
    for key, value in c.fetchall():
        if isinstance(value, str) and len(value.encode("utf-8")) > _METADATA_VALUE_MAX_BYTES:
            data[key] = value
            continue
        try:
            data[key] = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            data[key] = value
    return data


# v8 CHECK-constrains functions.status, v9 CHECK-constrains cells.state and
# adds idx_metadata_key, v10 widens the cell-state set (extract_error,
# invalid_va). None of those add or remove a column this server queries.
KNOWN_SCHEMA_VERSIONS: frozenset[str] = frozenset({"3", "4", "5", "6", "7", "8", "9", "10"})

# Schema check memoized per DB (mtime_ns, size): the check is two queries
# (metadata + full sqlite_master scan) that would otherwise run on every
# request; the DB only changes when build-db rewrites it, which the SSE
# watcher already detects and funnels through clear_target_cache().
_SCHEMA_VERSION_CACHE: tuple[tuple[int, int], str] | None = None


def _check_schema_version(conn: sqlite3.Connection) -> str:
    """Read the stored db_version metadata; warn if it is not a known-compatible version.

    Known-compatible versions: 3 through 10.  Version 3 is still readable
    because none of the v4 constraints affect reads of existing data.  Any other
    version is logged as a warning. recoverage does not abort.

    The version stamp alone is not proof of shape: a DB stamped "4" can be
    missing required objects (e.g. the ``history`` table) and pass this gate,
    then 500 at query time.  A known version with missing objects is reported
    as ``"<incomplete>"`` so endpoints can respond with a clear 503 instead.

    Returns the version string (or ``"<unknown>"`` / ``"<incomplete>"``).
    """
    global _SCHEMA_VERSION_CACHE
    # WAL-aware snapshot, not raw st_mtime: a rebuild that commits only to
    # -wal must invalidate the memo or a stale verdict (e.g. "<incomplete>")
    # survives the fix — same contract as every other DB-derived cache key.
    fingerprint = _snapshot_db_mtime()
    if fingerprint is not None:
        with _RESOLVED_TARGETS_CACHE_LOCK:
            if _SCHEMA_VERSION_CACHE is not None and _SCHEMA_VERSION_CACHE[0] == fingerprint:
                return _SCHEMA_VERSION_CACHE[1]
    version = _check_schema_version_uncached(conn)
    if fingerprint is not None:
        with _RESOLVED_TARGETS_CACHE_LOCK:
            _SCHEMA_VERSION_CACHE = (fingerprint, version)
    return version


def _missing_required_columns(conn: sqlite3.Connection) -> set[str]:
    """Query-critical columns a v4 DB must have; ``table.column`` for gaps.

    The name-only shape gate passes a DB stamped "4" whose ``functions``
    table lacks ``textOffset``/``similarity`` (queried by the function
    detail endpoint) or whose ``section_cell_stats`` table is missing a
    counted bucket — those fail at query time instead of at open.  The sets
    below are the columns recoverage itself subscripts, not a copy of
    build_db's schema: a column build_db added after these endpoints were
    written is not required here, and optional columns the live readers probe
    for are left out on purpose (the v6 additions noted in
    _check_schema_version_uncached).
    """
    required_columns: dict[str, set[str]] = {
        "metadata": {"target", "key", "value"},
        "sections": {"target", "name", "va", "size", "fileOffset", "unitBytes", "columns"},
        "cells": {
            "target",
            "section_name",
            "start",
            "end",
            "span",
            "state",
            "functions",
            "label",
            "parent_function",
        },
        "functions": {
            "target",
            "va",
            "name",
            "vaStart",
            "size",
            "fileOffset",
            "status",
            "module",
            "cflags",
            "symbol",
            "markerType",
            "ghidra_name",
            "list_name",
            "is_thunk",
            "is_export",
            "sha256",
            "files",
            "detected_by",
            "size_by_tool",
            "textOffset",
            "blocker",
            "blockerDelta",
            "size_reason",
            "similarity",
        },
        "globals": {"target", "va", "name", "decl", "files", "module", "size"},
        "verify_results": {"target", "va", "verified_at", "byte_delta", "diff_lines", "similarity"},
        "section_cell_stats": {
            "target",
            "section_name",
            "total_cells",
            "exact_count",
            "reloc_count",
            "near_match_count",
            "stub_count",
            "padding_count",
            "data_count",
            "thunk_count",
            "none_count",
            "proven_count",
            "size_mismatch_count",
        },
    }
    missing: set[str] = set()
    for obj, cols in required_columns.items():
        try:
            rows = conn.execute(f"PRAGMA table_info({obj})").fetchall()
        except sqlite3.Error:
            missing.add(obj)
            continue
        actual = {r[1] for r in rows}
        for col in cols - actual:
            missing.add(f"{obj}.{col}")
    return missing


def _check_schema_version_uncached(conn: sqlite3.Connection) -> str:
    """Uncached schema version read; see :func:`_check_schema_version`."""
    try:
        # Prefer the SCHEMA_TARGET stamp (deterministic across targets); fall
        # back to any per-target stamp for legacy DBs.
        row = conn.execute(
            "SELECT value FROM metadata WHERE target = ? AND key = 'db_version' LIMIT 1",
            (SCHEMA_TARGET,),
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = 'db_version' LIMIT 1"
            ).fetchone()
        if row is None:
            return "<unknown>"
        v = row[0]
        if isinstance(v, str):
            v = v.strip('"')
        version = str(v)
        if version in KNOWN_SCHEMA_VERSIONS:
            present = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master"
                    " WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            required = {
                "metadata",
                "sections",
                "cells",
                "functions",
                "globals",
                "verify_results",
                "history",
                "section_cell_stats",
            }
            missing = required - present
            if not missing and version != "3":
                # Object names present. Verify the query-critical columns.
                # v3 predates that column set. v4 through v10 share it:
                # v8 through v10 add CHECK constraints and an index, not
                # columns these queries name. v6 additions (updated_by /
                # updated_at, globals.status, verify reg_delta /
                # effective_match) are read when present and omitted when
                # absent, so a missing one degrades rather than 503s. The
                # shape gate still reports a missing required column.
                missing |= _missing_required_columns(conn)
            if missing:
                _log.warning(
                    "recoverage: db_version %r but missing schema objects: %s",
                    version,
                    ", ".join(sorted(missing)),
                )
                return "<incomplete>"
        else:
            _log.warning(
                "recoverage: unexpected db_version %r (known: %s) — "
                "some features may not work correctly",
                version,
                ", ".join(sorted(KNOWN_SCHEMA_VERSIONS)),
            )
        return version
    except sqlite3.Error as exc:
        _log.warning("recoverage: could not read db_version: %s", exc)
        return "<unknown>"


# Same busy wait as rebrew.workspace.open_sqlite_ro. A reader blocked on
# build-db's write lock should wait out a short transaction, not the
# sqlite default of 5s.
_SQLITE_RO_TIMEOUT_SECONDS = 30.0


class _LockedReadConnection(sqlite3.Connection):
    """Read-only connection that releases the shared coverage lock on close.

    ``sqlite3.Connection.close`` cannot be replaced on an instance, and the
    stock connection cannot be weak-referenced, so the lock lives on this
    subclass. ``contextlib.closing`` calls ``close``. There is no ``__del__``:
    sqlite forbids ``close`` from a thread other than the one that opened
    the connection, and a failed ``connect`` still finalizes the subclass.
    Dropping the connection without ``close`` drops the lock object, and
    that generator's cleanup unlocks the file. ``build-db --force`` waits
    on the lock before unlinking the file.
    """

    _coverage_lock: Any = None

    def close(self) -> None:
        lock = getattr(self, "_coverage_lock", None)
        self._coverage_lock = None
        try:
            super().close()
        finally:
            if lock is not None:
                lock.__exit__(None, None, None)


def _open_db(db_path: Path) -> sqlite3.Connection:
    """Open *db_path* read-only, holding ``coverage_db_lock`` until close.

    Same reader setup as ``rebrew.workspace.open_sqlite_ro`` (``mode=ro``
    URI, ``query_only``, 30s busy timeout). The connection is a
    :class:`_LockedReadConnection` so the shared lock survives for the open.

    :data:`FOLD_SQL` is registered here so every surface searching through
    this connection folds names the same way; a clause naming it against a
    connection that lacks it would fail the whole query.
    """
    lock = coverage_db_lock(db_path, shared=True)
    lock.__enter__()
    try:
        conn = sqlite3.connect(
            sqlite_ro_uri(db_path),
            uri=True,
            timeout=_SQLITE_RO_TIMEOUT_SECONDS,
            factory=_LockedReadConnection,
        )
        try:
            conn.execute("PRAGMA query_only=ON")
            conn.create_function(FOLD_SQL, 1, fold_text, deterministic=True)
        except BaseException:
            # The lock is not attached yet, so close() does not release it.
            conn.close()
            raise
    except BaseException:
        lock.__exit__(None, None, None)
        raise
    conn._coverage_lock = lock
    conn.row_factory = sqlite3.Row
    return conn


@contextlib.contextmanager
def read_snapshot(c: sqlite3.Cursor) -> Iterator[None]:
    """Run every statement in the block against ONE database snapshot.

    Python's sqlite3 opens a deferred transaction per statement, so a
    multi-query read (metadata + cells + sections + stats) sees a rebuild
    that commits midway through: the payload can pair section rows from one
    build with cells from the next.  ``BEGIN`` here pins the read snapshot
    for the whole block, so the answer is internally consistent or the
    request fails.

    No-op when the caller is already inside a transaction (the CLI reuses
    one connection across commands): SQLite has no nested BEGIN, and the
    outer transaction already pins the snapshot.
    """
    conn = c.connection
    if conn.in_transaction:
        yield
        return
    conn.execute("BEGIN")
    try:
        yield
    finally:
        conn.rollback()


def _db() -> sqlite3.Connection:
    conn = _open_db(_db_path())
    version = _check_schema_version(conn)
    # DEBUG: this runs on every DB-touching request; an INFO line here makes
    # the operational log one "opened coverage.db" entry per request.
    _log.debug("recoverage: opened coverage.db (schema v%s)", version)
    if version == "<incomplete>":
        # Stamped with a known version but missing required objects — every
        # query would 500.  Fail fast with the standard 503 JSON contract.
        conn.close()
        raise sqlite3.OperationalError(
            "coverage.db schema is incomplete (missing tables/views) — "
            "run rebrew build-db --force to rebuild"
        )
    return conn


# ── Response helpers ───────────────────────────────────────────────

# The two cache policies for DB-derived responses.  NO_STORE: payloads with
# no validator the client can cheaply re-check — /api/health, /api/targets,
# the function list/detail routes and /api/events — which must never survive a
# rebuild.  REVALIDATE: the ETag-bearing payloads (the SPA shell, /stats,
# /data, /asm, /bytes, /potato) that a browser may keep but must re-verify with
# If-None-Match every time.
CACHE_NO_STORE = "no-cache, no-store, must-revalidate"
CACHE_REVALIDATE = "no-cache, must-revalidate"


def _finalized(
    resp: HTTPResponse, body: bytes, content_type: str, encoding: str, **headers: str
) -> bytes:
    """Set payload headers on *resp* for an already-final *body* and return it."""
    resp.content_type = content_type
    if encoding:
        resp.set_header("Content-Encoding", encoding)
    resp.set_header("Vary", "Accept-Encoding")
    resp.set_header("Content-Length", str(len(body)))
    for k, v in headers.items():
        resp.set_header(k.replace("_", "-"), v)
    return body


def _compressed(body: bytes, content_type: str, **headers: str) -> bytes:
    """Compress body, set response headers, return final body."""
    accept_enc = _header("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    return _finalized(response, body, content_type, encoding, **headers)


def _json_ok(data: dict[str, Any] | list[Any] | bytes, **headers: str) -> bytes:
    """Return compressed JSON 200."""
    body = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
    return _compressed(body, "application/json", **headers)


def _json_ok_precompressed(body: bytes, encoding: str, **headers: str) -> bytes:
    """Return a JSON 200 from an already-compressed body (no recompression)."""
    return _finalized(response, body, "application/json", encoding, **headers)


# Every JSON error response carries this trio: `error` (human message),
# `code` (stable machine-readable string), `detail` (extra context, often "").
_STATUS_ERROR_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "unprocessable_entity",
    429: "rate_limited",
    500: "internal",
    501: "not_implemented",
    503: "db_unavailable",
}


def _json_err(status: int, data: dict[str, Any], **headers: str) -> Any:
    """Return a JSON error response.

    Body is always ``{"error": <human message>, "code": <machine code>,
    "detail": <context>}``.  ``code`` defaults to a status-based mapping
    (call sites may override it) and any extra keys in ``data`` (e.g.
    ``retry_after``) are preserved alongside the standard trio.  Extra
    response headers (e.g. ``Retry_After=...``, underscores become dashes)
    ride along for statuses that carry them (429).
    """
    body_data: dict[str, Any] = {
        "error": data.get("error", "error"),
        "code": data.get("code", _STATUS_ERROR_CODES.get(status, "internal")),
        "detail": data.get("detail", ""),
    }
    for key, value in data.items():
        if key not in body_data:
            body_data[key] = value
    body = json.dumps(body_data).encode("utf-8")
    accept_enc = _header("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    # Errors must never be cached by intermediaries: a proxy could serve a
    # stale 503 after the DB recovers.
    resp = HTTPResponse(status=status, body=body)
    _finalized(resp, body, "application/json", encoding, Cache_Control="no-store", **headers)
    return resp


# ── Token auth ─────────────────────────────────────────────────────

# Optional token auth for the dashboard (--token): when set, every request
# from every peer must present it via Authorization: Bearer <token>, ?token=,
# or the HttpOnly cookie :func:`set_auth_cookie` writes for the page routes
# (both / and /potato; every link on either page is relative, so the cookie is
# what carries the credential past the first click).  There is no loopback
# exemption, which is why --allow-remote pairs with --token rather than
# replacing it.
_AUTH_TOKEN: str = ""


# Deliberately does not echo the expected token, and carries no CSS of its own
# beyond the handful of attributes needed to be readable on a dark background.
_UNAUTHORIZED_HTML = (
    b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
    b'<meta name="viewport" content="width=device-width, initial-scale=1">'
    b"<title>ReCoverage - access token required</title></head>"
    b'<body bgcolor="#0f1216" text="#e7edf4">'
    b'<table width="100%" height="90%" border="0"><tr><td align="center" valign="middle">'
    b'<font face="system-ui, sans-serif">'
    b"<h1>Access token required</h1>"
    b"<p>This dashboard was started with <tt>--token</tt>. Open it with the token"
    b" appended to the URL:</p>"
    b'<p><tt bgcolor="#151a21">?token=YOUR_TOKEN</tt></p>'
    b'<p><font color="#8b949e" size="2">The person who started the server has the token.'
    b" It is stored in a cookie afterwards, so you only need the URL once.</font></p>"
    b"</font></td></tr></table></body></html>"
)


def _auth_token_matches(provided: str) -> bool:
    # Constant-time comparison: a plain == leaks the token one byte at a
    # time to a client measuring response latency on a network-reachable
    # server (--allow-remote).  Both sides are encoded because
    # hmac.compare_digest raises TypeError on non-ASCII str — and *provided*
    # comes straight from request headers.
    return bool(_AUTH_TOKEN) and hmac.compare_digest(
        provided.encode("utf-8"), _AUTH_TOKEN.encode("utf-8")
    )


#: Name of the HttpOnly cookie the ``?token=`` share-link flow sets, and the one
#: :func:`_require_auth` reads it back under.  ONE name, so the surface that
#: sets it and the gate that consumes it cannot drift apart.
AUTH_COOKIE_NAME = "recoverage_token"


def set_auth_cookie() -> None:
    """Set the auth cookie when this request carried ``?token=<token>``.

    The share link (``http://host:port/?token=TOKEN``) is the only way a
    browser hands the SPA a credential, and the cookie is what makes every
    later ``fetch``/``EventSource`` call and every relative link
    (``?target=...``, ``?idx=...``) authenticate without the query string
    riding along.  EVERY page surface that a share link can land on must set
    it: /potato renders only relative URLs, so a reader who arrived there with
    the token in the query lost it on the first click and got the 401 page
    back.

    No-op when no token is configured, when the request carries no ``?token=``,
    or when the value does not match; the 401 itself is :func:`_require_auth`'s
    job, which runs first.
    """
    if not _AUTH_TOKEN or not _auth_token_matches(query_param("token")):
        return
    # A header the peer will not accept must not break the page it rides on —
    # but it must not be invisible either.  A dropped Set-Cookie leaves the
    # reader authenticated for exactly one request and 401 on every link they
    # follow after it, which reads as a broken server and is diagnosable only
    # from this line.  The value is the server's own token, never the request's.
    try:
        response.set_header(
            "Set-Cookie",
            f"{AUTH_COOKIE_NAME}={_AUTH_TOKEN}; Path=/; HttpOnly; SameSite=Strict",
        )
    except Exception:
        _log.warning(
            "Set-Cookie rejected for %s %s — the share link will 401 on every "
            "follow-on request (the page itself still renders)",
            _log_safe(request.method),
            _log_safe(request.path),
            exc_info=True,
        )


# -- Request instrumentation ------------------------------------------------
# One correlation id per request, carried on the log line, the response
# header, and the RED counters.  Without it a report of "the export was slow"
# can only be matched against a wall of undated, unlabelled lines, because
# the request log records neither the status nor how long anything took.

_REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_MAX_LEN = 64
#: Per-thread so concurrent requests do not overwrite each other's id; the
#: serving threads are per-request, and a background thread (the SSE poller)
#: simply has none.
_REQUEST_TLS = threading.local()


def _new_request_id() -> str:
    """Reuse the caller's correlation id, or mint one."""
    provided = _header(_REQUEST_ID_HEADER, "")
    if provided:
        # Untrusted: capped and control-char escaped so a crafted header
        # cannot forge log lines (same rule as _log_safe) or bloat the log.
        return _log_safe(provided)[:_REQUEST_ID_MAX_LEN]
    return uuid.uuid4().hex[:12]


class _RequestIdFilter(logging.Filter):
    """Stamp the current request id onto every record the app logs.

    Records from other loggers (bottle, rebrew) never pass this filter, so
    the formatter supplies the same field's default for them.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = getattr(_REQUEST_TLS, "request_id", "-")
        return True


_log.addFilter(_RequestIdFilter())


@app.hook("before_request")
def _start_request() -> None:
    """Open the request's timing window and correlation id.

    Registered before the auth hook so a rejected request is still counted
    and still carries an id in its 401 line.  The id is left on the
    thread-local afterwards: the error handler runs after ``after_request``
    and its traceback line must carry the same id.
    """
    _REQUEST_TLS.request_id = _new_request_id()
    _REQUEST_TLS.started_at = clock.monotonic()
    metrics.REQUESTS.start()


@app.hook("after_request")
def _finish_request() -> None:
    """Record status and duration, and surface the id on the response.

    The counters answer "did it succeed, how long did it take"; a request
    past SLOW_REQUEST_MS is one line at WARNING instead of a number in a
    snapshot, because that is the only one an operator watching the log can
    act on.
    """
    request_id = getattr(_REQUEST_TLS, "request_id", None)
    started_at = getattr(_REQUEST_TLS, "started_at", None)
    _REQUEST_TLS.started_at = None
    _REQUEST_TLS.counted = None
    status = response.status_code
    # bottle raises from request.route when no route matched (a request
    # rejected in a before_request hook never reaches the router), so the
    # environ copy is the one that answers with None instead.
    matched = request.environ.get("bottle.route")
    rule = getattr(matched, "rule", None) if matched else None
    route = metrics.route_label(request.path, rule)
    if request_id:
        response.set_header(_REQUEST_ID_HEADER, request_id)
    if started_at is None:
        # before_request never ran (an error raised ahead of it, or a request
        # the WSGI harness issued without the hook): nothing to time.
        return
    duration_ms = (clock.monotonic() - started_at) * 1000.0
    timed = route not in metrics.UNBOUNDED_ROUTES
    metrics.REQUESTS.finish(route, status, duration_ms, timed=timed)
    _REQUEST_TLS.counted = (route, status)
    if timed and duration_ms >= metrics.SLOW_REQUEST_MS:
        _log.warning(
            "Slow request: %s %s -> %d in %.0fms",
            _log_safe(request.method),
            _log_safe(request.path),
            status,
            duration_ms,
        )
    else:
        _log.debug(
            "%s %s -> %d in %.0fms",
            _log_safe(request.method),
            _log_safe(request.path),
            status,
            duration_ms,
        )


def _reclassify_request(status: int) -> None:
    """Correct the counted status of a request that failed after the hook.

    ``after_request`` runs before bottle hands an escaped exception to the
    error handler, so it counted the request as the 200 it was still
    carrying.  Without this, every 500 and 503 (a corrupt or rebuilding
    coverage.db, the failure the operator most needs to see) would land in
    the 2xx bucket and the error rate would read zero.
    """
    counted = getattr(_REQUEST_TLS, "counted", None)
    if counted is not None:
        metrics.REQUESTS.reclassify(counted[0], counted[1], status)
        _REQUEST_TLS.counted = None


# Failed-token-attempt throttle: without it, a network-reachable server
# (--allow-remote + --token) accepts unlimited online guesses at the bearer
# token.  Global (per-process), not per-source-IP — behind NAT every client
# shares one address anyway, and the dashboard's threat model is "someone on
# the LAN is guessing", not "multi-tenant fairness".  A success clears the
# counter so the operator never trips their own limit.
_AUTH_FAIL_WINDOW_SECONDS = 60.0
_AUTH_FAIL_MAX = 10
_auth_failures: deque[float] = deque()
_AUTH_FAILURES_LOCK = threading.Lock()


def _auth_throttle(now: float, reserve_slot: bool) -> bool:
    """Prune expired failures, enforce the window cap, optionally take a slot.

    The prune, the cap check, and *reserve_slot*'s append must share ONE
    critical section: as separate steps, a burst of concurrent bad-token
    requests all observe ``len < max`` before any of them records, and every
    one of them slips past the cap (check-then-act TOCTOU).  The slot is
    therefore taken BEFORE the token is verified; a verified request releases
    everything again via :func:`_clear_auth_failures`.

    Returns True when the window is full — the caller answers 429.
    """
    with _AUTH_FAILURES_LOCK:
        while _auth_failures and now - _auth_failures[0] > _AUTH_FAIL_WINDOW_SECONDS:
            _auth_failures.popleft()
        if len(_auth_failures) >= _AUTH_FAIL_MAX:
            return True
        if reserve_slot:
            _auth_failures.append(now)
        return False


def _clear_auth_failures() -> None:
    with _AUTH_FAILURES_LOCK:
        _auth_failures.clear()


def _require_auth() -> None:
    """Enforce the configured bearer token, or pass when none is set.

    Credentials, in order: ``Authorization: Bearer``, ``?token=``, the
    ``recoverage_token`` cookie.  A page request (Accept: text/html, non-/api
    path) gets the 401 HTML page; every other client gets the JSON 401
    contract, or the 429 once the fail window is full.
    """
    if not _AUTH_TOKEN:
        return

    provided = _header("Authorization", "")
    if provided.startswith("Bearer "):
        provided = provided[len("Bearer ") :]
    else:
        provided = query_param("token")
        if not provided:
            provided = request.get_cookie(AUTH_COOKIE_NAME, default="")
    if _auth_token_matches(provided):
        _clear_auth_failures()
        return

    now = clock.monotonic()
    if _auth_throttle(now, reserve_slot=True):
        raise _json_err(
            429,
            {"error": "rate limited", "detail": "too many failed token attempts; retry later"},
            Retry_After=str(int(_AUTH_FAIL_WINDOW_SECONDS)),
        )

    # Audit trail for brute-force visibility: on a network-reachable server
    # (--allow-remote --token) the throttle bounds guessing, but a silent 401
    # gives the operator no way to see the attempt happened.  The provided
    # value is never logged (it may be someone's near-miss guess at a
    # secret); REMOTE_ADDR comes from the socket peer.
    _log.warning(
        "Rejected %s auth token from %s",
        "missing" if not provided else "invalid",
        request.environ.get("REMOTE_ADDR", "") or "unknown peer",
    )
    # A browser asking for a page gets a page; API clients keep the JSON
    # error contract.  Someone handed a share URL who dropped the query
    # string used to land on a raw JSON blob with no way to tell what to do.
    wants_html = "text/html" in _header("Accept", "") and not request.path.startswith("/api/")
    if wants_html:
        raise HTTPResponse(
            status=401,
            body=_UNAUTHORIZED_HTML,
            content_type="text/html; charset=utf-8",
            # The JSON error contract already sets no-store (_json_err); this
            # page is the one 401 that did not, so a shared cache could store
            # and replay a pre-auth body.
            headers={"Cache-Control": "no-store"},
        )
    raise _json_err(
        401,
        {"error": "unauthorized", "detail": "missing or invalid token"},
    )


app.add_hook("before_request", _require_auth)


def _db_unavailable_err(exc: sqlite3.Error) -> Any:
    """JSON 503 for an unreadable coverage.db, logged so the failure is visible.

    ONE tail for every DB-open failure path (the shared target cursor and the
    unexpected-error handler): without the log line a missing or corrupt
    database is invisible in the server log — the 503 only reaches the one
    client that happened to make the request.  The log line carries the full
    OS/SQLite cause; the body carries the exception class and the rebuild hint
    and nothing else, because every read endpoint is unauthenticated unless
    the operator passed --token and --allow-remote puts it on a network, and
    sqlite3 messages routinely quote the absolute database path.  Potato Mode's
    503 page carries the same hint.
    """
    _log.warning(
        "Database unavailable serving %s %s: %s: %s",
        _log_safe(request.method),
        _log_safe(request.path),
        type(exc).__name__,
        exc,
    )
    return _json_err(
        503,
        {
            "error": "Database unavailable",
            "detail": f"{type(exc).__name__} — "
            "run 'rebrew catalog && rebrew build-db' to create or rebuild it; "
            "the server log has the full cause",
        },
    )


@app.error(500)
def _handle_unexpected_error(error: Any) -> Any:
    """Keep every surface's error contract when a handler raises unexpectedly.

    ``_db()`` open failures already return 503 JSON, but every query after
    connect was unguarded — a corrupt/incompatible DB or SQLITE_BUSY during a
    concurrent build-db raised inside ``c.execute`` and surfaced as Bottle's
    HTML 500.  All sqlite3 errors become a 503 JSON response instead.

    Non-DB exceptions are logged here with their request context: bottle only
    dumps the raw traceback to wsgi.errors (and ``serve`` runs wsgiref with
    quiet=True), so without this the failing endpoint is hard to identify from
    the log alone.  /api/* requests get the standard JSON 500 contract — the
    SPA's fetch() handlers and API consumers parse JSON, not Bottle's HTML
    error page — while UI routes keep Bottle's HTML error page.
    """
    exc = getattr(error, "exception", None)
    if isinstance(exc, sqlite3.Error):
        _reclassify_request(503)
        return _db_unavailable_err(exc)
    # Returning the HTTPError itself would make _cast re-enter the error
    # handler (recursion until the wsgi catch-all); returning None would emit
    # an empty 500 body.  Method/path are attacker-controlled and this fires
    # on arbitrary unhandled exceptions, so they get the same control-char
    # escaping as every other request log (%0A in the path would otherwise
    # forge multi-line entries exactly when the operator reads the traceback).
    _reclassify_request(500)
    _log.error(
        "Unhandled error serving %s %s",
        _log_safe(request.method),
        _log_safe(request.path),
        exc_info=exc or error,
    )
    if request.path.startswith("/api/"):
        return _json_err(500, {"error": "Internal server error"})
    return app.default_error_handler(error)


@app.hook("before_request")
def _log_request() -> None:
    """Reject requests carrying a Host this bind does not answer for.

    (The method/path line for every request, with its status and duration,
    is emitted once by the after_request hook.)
    """
    # Method/path are attacker-controlled (the path is percent-decoded), so
    # control characters are escaped to keep the log line-per-request.
    if ALLOWED_HOSTS is not None:
        # DNS-rebinding guard for loopback installs: the Host header must name
        # a loopback host.  Requests without a Host header (non-HTTP/1.1
        # clients, WSGI test harnesses) are left to the server's own address
        # handling.
        host = _header("Host", "")
        if host and _hostname_of(host) not in ALLOWED_HOSTS:
            # Audit trail: a rejected Host on a loopback bind is a
            # DNS-rebinding attempt signal; without it the 400 leaves no
            # trace for incident investigation.  %r escapes control
            # characters, so the hostile value cannot forge log lines.
            _log.warning(
                "Rejected request with unexpected Host header %r from %s",
                host,
                request.environ.get("REMOTE_ADDR", "") or "unknown peer",
            )
            raise _json_err(
                400,
                {
                    "error": "Bad Request",
                    "detail": f"unexpected Host header {host!r}",
                },
            )


# Content-Security-Policy for the dashboard.  The SPA inlines VanJS + app.js
# into the HTML shell and uses inline styles, so 'unsafe-inline' is required
# for scripts/styles; everything else is same-origin (detail.js, hljs assets,
# fetch/EventSource to /api/*) or data: images (grid sprites, SVG badges).
# The policy still pins the useful gates: no plugins, no base-element hijack,
# no framing, no off-host exfil from any future injection sink.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def _merge_vary(origin: str) -> None:
    """Add "Origin" to the response's Vary without dropping what is there.

    Compressed responses already carry "Accept-Encoding"; a shared cache must
    key on both, so the token is appended rather than replacing the header.
    """
    existing = [v.strip() for v in response.headers.get("Vary", "").split(",") if v.strip()]
    if origin not in existing:
        existing.append(origin)
    response.set_header("Vary", ", ".join(existing))


@app.hook("after_request")
def _security_headers() -> None:
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("X-Frame-Options", "DENY")
    response.set_header("Content-Security-Policy", _CSP)
    # Tokens travel in URLs (?token= share links); never let them leak to a
    # third party via Referer if the dashboard ever navigates off-host.
    response.set_header("Referrer-Policy", "no-referrer")
    origin = _header("Origin", "")
    if CORS_ENABLED and origin and _normalize_origin(origin) in CORS_ALLOWED_ORIGINS:
        response.set_header("Access-Control-Allow-Origin", origin)
        _merge_vary("Origin")
        response.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        # The two credential/validator headers the API itself documents.
        # Without Authorization in this list a --cors frontend cannot use the
        # --token auth the README advertises (the preflight fails, so the
        # request is never sent), and without If-None-Match it cannot do the
        # conditional GET that every ETag-bearing endpoint (/data, /asm,
        # /bytes, /potato) is built around.
        response.set_header(
            "Access-Control-Allow-Headers", "Content-Type, Authorization, If-None-Match"
        )
        # ETag and Retry-After are response headers a cross-origin client
        # cannot read unless they are exposed; without this the validator the
        # server sends is invisible to the client that needs it.
        response.set_header("Access-Control-Expose-Headers", "ETag, Retry-After")
        response.set_header("Access-Control-Allow-Credentials", "true")
    elif origin:
        # Ensure caches key on Origin even when not allowed.
        _merge_vary("Origin")


@app.route("<path:path>", method="OPTIONS")
def _cors_preflight(path: str) -> str:
    """Handle CORS preflight requests. Headers are set by the after_request hook."""
    return ""
