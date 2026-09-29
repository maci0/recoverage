"""Recoverage server — coverage dashboard for binary-matching projects.

Bottle WSGI app serving the dashboard over rebrew's clear-text coverage
TOML.  The ``coverage-*.toml`` documents are read from the directory resolved
by ``recoverage._paths._db_path()``, which honours ``rebrew-project.toml
[project] db_dir`` when present and falls back to ``./db`` otherwise.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import importlib.util
import ipaddress
import itertools
import json
import logging
import math
import threading
import unicodedata
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from operator import attrgetter, itemgetter
from pathlib import Path, PurePath
from types import MappingProxyType
from typing import Any, Final, NamedTuple, cast
from urllib.parse import unquote, urlsplit

import brotli
import zstandard as zstd
from bottle import Bottle, HTTPResponse, request, response
from rebrew.annotation import DATA_MARKERS
from rebrew.coverage_toml import (
    _BUCKET_OF_STATE,
    Cell,
    CoverageSnapshot,
    CoverageTomlError,
    Function,
    Global,
    load_all_coverage_from,
)
from rebrew.utils import floor_pct
from rebrew.workspace import (
    CONFIG_NAME,
    MATCHED_STATUSES,
    WorkspaceConfigError,
    parse_va_candidates,
    read_config,
    target_binary,
    targets_table,
)

from recoverage import clock, metrics
from recoverage._paths import _db_path, config_fingerprint

# Thread-local compressor — python-zstandard gives ZstdCompressor instances NO
# thread-safety guarantees ("do not operate on the same instance from different
# threads") and releases the GIL inside compress(), so a shared instance raced
# on one ZSTD_CCtx and reproducibly segfaulted the server under concurrent
# requests.  One context per request thread (same pattern as
# disasm.get_capstone_md).
_ZSTD_COMPRESSOR_TLS = threading.local()


def _get_zstd_compressor() -> zstd.ZstdCompressor:
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
# regen endpoint's peer check and its no-Host fallback (see
# origin_is_this_dashboard), and the DNS-rebinding Host allowlist above.
# Membership tests only — order carries no meaning.
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
            return str(v4) in LOOPBACK_HOSTS
    return str(ip) in LOOPBACK_HOSTS


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


# The settings the process started with, exactly as ``config.active_config``
# rendered them for the startup banner, with the token as set/unset and
# never by value.  None until ``configure_startup`` runs, which only a real
# ``serve`` does: a WSGI harness that mounts the app reports None rather
# than a configuration it never resolved.
#
# Published so the RUNNING process can be asked what it is running with
# (``GET /api/health``).  ``recoverage config`` re-resolves the environment of
# the shell that runs it, which under a unit file or a container spec is not
# the server's environment: same flags, different answer.  This is the
# reading that cannot drift, and it is behind the auth hook like every other
# route.
ACTIVE_CONFIG: dict[str, str] | None = None


def configure_startup(settings: Mapping[str, str]) -> None:
    """Publish the resolved startup settings for /api/health to report.

    Takes the ALREADY RENDERED banner mapping rather than the individual
    flags, so the banner and the health report are the same rendering of the
    same values and cannot disagree.  Call it once at startup, before the
    listener binds.
    """
    global ACTIVE_CONFIG
    ACTIVE_CONFIG = dict(settings)


def _origin_candidate(value: str) -> str:
    """*value* in the spelling :func:`urlsplit` parses as an authority.

    Origins carry a scheme (``http://localhost:5173``); a bare Host header
    (``localhost:8001``) is a network-path reference, so the ``//`` prefix is
    what tells urlsplit to read the host out of it rather than treating the
    whole value as a path.  ONE spelling for all three header readers below
    (:func:`_hostname_of`, :func:`_normalize_origin`, :func:`_authority_of`):
    a change to how a bare authority is read has to reach all of them or they
    stop agreeing on which host a request was addressed to.
    """
    return value if "://" in value else f"//{value}"


def _hostname_of(origin: str) -> str:
    """Lowercased hostname of an Origin/Host header value ("" if unparsable).

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
        return (urlsplit(_origin_candidate(origin)).hostname or "").lower()
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
        u = urlsplit(_origin_candidate(origin))
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


def _authority_of(value: str) -> str:
    """Normalized ``host[:port]`` of a Host/Origin value, or "" when unparsable.

    Scheme-independent on purpose: a dashboard behind a TLS-terminating proxy
    is reached as ``Origin: https://box`` with ``Host: box``, and the question
    this answers is which service the page came from, not which scheme it used
    to get here.  A default port collapses away on both sides so
    ``http://box:80`` and ``box`` name one authority.
    """
    if _hostname_of(value) == "":
        return ""
    try:
        parsed = urlsplit(_origin_candidate(value))
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return ""
    if port in (None, 80, 443):
        port = None
    host_part = f"[{host}]" if ":" in host else host
    return f"{host_part}:{port}" if port else host_part


def origin_is_this_dashboard(origin: str, host: str) -> bool:
    """Whether *origin* is the same service the request was addressed to.

    The authority allowed to drive a privileged operation is the page the
    operator is looking at, so this is a same-origin test against the request's
    own ``Host``, not a membership test against LOOPBACK_HOSTS.  Every other
    loopback port is a different origin with its own operator, and on a
    loopback bind that neighbour is exactly what the gate exists to exclude:
    a dev server, another local app, or anything an attacker can get a browser
    to load from one.  A page there passes a hostname check while being unable
    to read the response, so the request is both forged and silent.

    A request with no ``Host`` header (HTTP/1.0, some WSGI harnesses) cannot be
    compared, and browsers never send one, so the loopback-hostname rule
    stands in for it rather than refusing every such client.
    """
    if _hostname_of(origin) == "":
        return False
    request_host = _authority_of(host)
    if not request_host:
        return _hostname_of(origin) in LOOPBACK_HOSTS
    return _authority_of(origin) == request_host


def fs_text_bytes(text: str) -> bytes:
    """*text* as the bytes the filesystem named it in, for hashing.

    Python reads a filename with ``os.fsdecode``, which is ``surrogateescape``:
    a name Linux holds as raw bytes outside UTF-8 (``coverage-ca\\xff.toml``,
    legal on ext4 and produced by a checkout, an archive or a copy from a
    Windows tool) reaches Python carrying U+DCFF, and ``str.encode("utf-8")``
    raises ``UnicodeEncodeError`` on it.  Every digest in this package is built
    from filenames or from values the documents derived from them, so the
    strict encode turned one such file in the coverage directory into a 500
    with a traceback on every request: the snapshot token, and every ETag
    derived from it, are computed before the handler can answer.

    ``surrogateescape`` on the way out is the exact inverse of ``os.fsdecode``,
    so the two distinct files stay distinct in the digest (the token still
    moves when either is rewritten or removed) and the round trip is lossless.
    A surrogate from anywhere else — a document cannot hold one, ``tomllib``
    rejects ``\\uD800`` — still raises, because only the filesystem's own
    spelling is recoverable.
    """
    return text.encode("utf-8", "surrogateescape")


#: What separates one length-prefixed :func:`_safe_etag` part from the next.
#: The length prefix is what makes the framing unambiguous, since a part can
#: carry a NUL: a search term reaches the validator percent-decoded, and
#: ``?search=%00`` is one.  A printable delimiter would not survive a part
#: holding the same byte, so the separator is one a document and a query cannot
#: spell at all.
_ETAG_PART_SEP = "\0"


def _safe_etag(*parts: object) -> str:
    """Deterministic ETag from arbitrary parts.

    Parts include request-controlled strings (VA, section, format) — they
    are hashed so no raw request data can ever reach a response header
    (bottle rejects control characters, but that is a library property,
    not the app's contract).  Hashed through :func:`fs_text_bytes`, so a target
    id that came off the filesystem as a surrogate-escaped name is a value
    rather than a 500.

    Every part is LENGTH-PREFIXED, not merely separated.  A separator alone
    makes the encoding ambiguous: the parts are a flat list, so a value
    carrying the separator reads as several parts, and two different requests
    that shaped two different responses hash the same string.  The function
    list is the reachable case — ``?search=`` and ``?sort=`` are free text, so
    ``search=a&sort=va:asc|5|3&limit=5&offset=3`` and ``search=a|va:asc|5|3
    &sort=va&limit=5&offset=3`` joined to one identical string and answered
    both requests with the same strong validator.  A client that had the
    first page cached revalidating the second got a 304 and kept rendering
    the first page's rows under the second page's controls.  Prefixing each
    part with its own length makes the encoding injective, so a validator
    names exactly one response and a 304 is only ever the answer to the
    request that earned it.
    """
    payload = _ETAG_PART_SEP.join(f"{len(text)}:{text}" for text in (str(p) for p in parts))
    digest = hashlib.sha256(fs_text_bytes(payload)).hexdigest()[:32]
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


def is_plain_relative(path: PurePath) -> bool:
    """Whether *path* is a plain relative name, safe to join onto a base directory.

    ``anchor`` rather than ``is_absolute()``: on Windows a drive-relative name
    (``C:foo.c``) is not absolute, and joining one onto a base silently
    reinterprets it as ``<drive>:/foo.c`` instead of the file the caller named.
    An anchor covers every such form (the drive, the leading separator, and a
    UNC share) and is empty for a plain name on both path flavours.

    The one definition for every path that crosses into the filesystem from a
    request or from a coverage document, so a second spelling of the rule
    cannot answer for a different host than the one the guard was written for.
    """
    return not path.anchor and ".." not in path.parts


def _existing_spelling(directory: Path, name: str) -> str:
    """*name* under *directory* as the filesystem itself spells it."""
    try:
        if (directory / name).exists():
            return name
    except OSError:
        return name
    other = unicodedata.normalize("NFD", name)
    if other == name:
        other = unicodedata.normalize("NFC", name)
    if other == name:
        # No combining mark: the same string in both forms, so there is no
        # other spelling to try.
        return name
    try:
        return other if (directory / other).exists() else name
    except OSError:
        return name


def match_filesystem_spelling(base: Path, relative: str) -> str:
    """*relative* re-spelled the way the tree under *base* actually spells it.

    macOS stores what a checkout or a decompiler wrote in the DECOMPOSED form
    of any filename carrying combining marks, and hands the decomposed bytes
    back from a directory listing: ``café.c`` lands as ``cafe`` + U+0301 +
    ``.c``.  A coverage document holds the COMPOSED spelling rebrew wrote, and
    a composed path does not open a decomposed file, so the code panes 404 for
    a source file that is sitting there and the Potato source panel comes back
    empty.  Byte equality is the wrong test for a path on a filesystem that
    normalizes the bytes it stores.

    Each segment is probed in turn and the one that exists wins, so a tree
    that mixes the two forms resolves segment by segment instead of needing
    the whole path in one form.  A segment that exists under the spelling it
    was given is kept as it is, and a name that exists in neither form is
    returned unchanged, so a genuinely missing file still reads as missing and
    the caller still 404s.

    Callers run this AFTER :func:`is_plain_relative`, never before: the
    containment rule is checked on the spelling the request (or the document)
    supplied, and normalization only re-spells combining marks, so a path that
    was refused stays refused and one that was allowed can only become a name
    that exists inside the same root.
    """
    parts = PurePath(relative).parts
    if not parts:
        return relative
    spelled: list[str] = []
    current = base
    for part in parts:
        chosen = _existing_spelling(current, part)
        spelled.append(chosen)
        current = current / chosen
    return str(PurePath(*spelled))


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


#: The characters a reader types around a search term by accident.  Not
#: ``str.strip``'s set: that removes every character Unicode calls whitespace,
#: so a term made of a non-breaking space (U+00A0), a thin space or U+FEFF
#: became the empty term and the search answered with every row instead of the
#: rows whose name carries that space.  The SPA's ``format.trimSearch`` removes
#: exactly this run, so both sides of one search drop the same characters.
_ASCII_SPACE: Final = " \t\n\r\f\v"


def strip_ascii_whitespace(value: str) -> str:
    """*value* without its leading and trailing ASCII spaces.

    ``str.strip`` is not that: it strips every code point ``str.isspace``
    accepts, which on the search term silently changed the question being
    asked.  Every character outside this run is part of the term, including
    the Unicode spaces a symbol name can carry.
    """
    return value.strip(_ASCII_SPACE)


#: Longest ``?search=`` either surface accepts.  A longer term is compared
#: against every row of every function, and names nothing a user types.
#: Lives here, beside the trimming helper the term is read through, because
#: BOTH surfaces take the same term and the cap is the one bound on it: the
#: Potato grid copies the term into the link of every cell on the page, so an
#: uncapped one there is a multiplier rather than a per-row comparison, and
#: api.py's cap alone left the page a request could inflate by the cell count.
MAX_SEARCH_CHARS: Final = 500


def query_param(name: str, default: str = "") -> str:
    """One query-string value, percent-decoded as UTF-8.

    Bottle decodes query values with ``encoding='latin1'`` (see its module
    import of ``urlunquote``), so ``?section=%C3%A9`` reaches a handler as
    ``Ã©`` and matches no section while ``parse_qs`` on the same raw
    ``request.url`` — the path Potato Mode uses — yields ``é``.  The
    latin-1 round trip in :func:`decode_query_value` is what recovers it.
    """
    return decode_query_value(request.query.get(name, default))


#: The digits every integer a request may spell is written in.  ``int()``
#: accepts any Unicode Nd digit, so ``?size=٤٠٩٦`` served a
#: 4096-byte slice and ``?page=1_0`` opened page 10: spellings no client sends
#: and no response documents, drawn from a repertoire the operator's locale
#: picks.  ASCII only, the same rule ``config._ASCII_INT`` holds every
#: ``RECOVERAGE_*`` integer to, so one number means one thing at both edges.
_ASCII_DIGITS: Final = "0123456789"
_ASCII_HEX_DIGITS: Final = "0123456789abcdef"


def strip_sign(text: str) -> tuple[int, str]:
    """Split a leading ``+``/``-`` off *text*: the sign, and the rest."""
    if text[:1] == "-":
        return -1, text[1:]
    if text[:1] == "+":
        return 1, text[1:]
    return 1, text


def parse_ascii_int(text: str, base: int = 10) -> int:
    """*text* as an integer written in *base* with ASCII digits, else ValueError.

    The one integer parse for every request-supplied number: ``?size=``,
    ``?offset=``, ``?limit=``, the batch VA list, and Potato Mode's ``?page=``
    and ``?idx=``.  ``int(text, base)`` is not that check on its own: it takes
    digits from the whole Unicode Nd set plus the ``_`` separator, so a
    request could name a byte count, a page or a VA in a spelling the endpoint
    never documented and that no other surface accepts.  Callers already turn
    :class:`ValueError` into their own 400 or their own default, so the reason
    never reaches the client as one shape.
    """
    digits = _ASCII_HEX_DIGITS[:base] if base == 16 else _ASCII_DIGITS
    if not text or any(c.lower() not in digits for c in text):
        raise ValueError(f"not an ASCII base-{base} integer: {text!r}")
    return int(text, base)


class RequestBodyError(Exception):
    """The request body could not be handed to the caller as bytes.

    Both subclasses leave the connection's framing untrustworthy — the bytes
    after the stop point are still in the socket, and a keep-alive handler
    would read them as the next request — so a caller MUST answer with
    ``Connection: close`` whatever it says in the body.
    """


class RequestBodyTooLargeError(RequestBodyError):
    """The body is over the caller's cap."""


class RequestBodyMalformedError(RequestBodyError):
    """The body is framed in a way this reader will not accept."""


#: Bytes pulled from ``wsgi.input`` per read.  A body under the caller's cap is
#: a few reads either way, and an over-cap one stops within one chunk of the
#: cap, so this only bounds how much is in memory mid-read.
_BODY_READ_CHUNK = 64 * 1024

#: Longest a chunked size line may be before the body is refused outright: a
#: client sending megabytes of hex with no CRLF in sight is not one whose body
#: this reader is going to finish parsing.
_CHUNK_LINE_MAX = 1024

#: Total bytes a chunked body's TRAILER section may occupy before the body is
#: refused.  RFC 9112 7.1.2 allows trailers, and no client this dashboard talks
#: to sends one, but the loop that consumes them had no bound of its own: it
#: ended only on the final CRLF or on the socket deadline, so a peer streaming
#: 1 KiB trailer lines held its handler thread and its admission slot for the
#: whole :data:`devserver._CLIENT_SOCKET_TIMEOUT_SECONDS` — the one part of a
#: chunked body that outlived every other cap in this reader.  Bounded on the
#: running total rather than on a line count, so the bound is bytes of input
#: rather than bytes of a parse this does not perform.
_TRAILER_MAX_BYTES = 8 * 1024


def _declared_content_length() -> int | None:
    """The request's declared body length in bytes, or None when it has none.

    Read from ``CONTENT_LENGTH`` directly rather than through
    ``request.content_length``: that property returns -1 for a chunked request
    and for a body whose header the peer omitted, and a caller that treats -1
    as a length reads the socket until it blocks.

    A header that is PRESENT and unparsable raises
    :class:`RequestBodyMalformedError` rather than reading as "no length
    declared".  Returning None there was a fallback standing in for a failure
    the caller should have seen: ``read_request_body`` switches to the unframed
    read on a None, so ``Content-Length: 1_0``, ``Content-Length: ٤٠٩٦`` and
    ``Content-Length: -1`` each silently changed the read strategy instead of
    being refused, and the endpoint answered 400 about the JSON it found
    rather than about the framing it was sent in.  Every other ill-framed
    thing this reader meets — a chunk size line that is not hex, a body cut
    short of its declared size, a missing final CRLF — is already refused, and
    the connection is already framed to expect one, so this is the same answer
    for the same class of fault.  The value is a run of ASCII digits and
    nothing else: ``parse_ascii_int`` rejects a sign, and a negative declared
    length is not a length at all.
    """
    raw = request.environ.get("CONTENT_LENGTH", "")
    if not raw:
        return None
    try:
        return parse_ascii_int(raw)
    except ValueError as exc:
        raise RequestBodyMalformedError(f"Content-Length is not a byte count: {raw!r}") from exc


def _body_is_chunked() -> bool:
    """Whether the request declares a chunked transfer encoding (RFC 9112 7.1)."""
    return "chunked" in request.environ.get("HTTP_TRANSFER_ENCODING", "").lower()


def _read_chunked_body(limit: int) -> bytes:
    """Read a chunked body, refusing once the DECODED size passes *limit*.

    The bound is on the decoded bytes, not on what was read, so a client
    cannot smuggle an oversize body past it in one large ``read()``: every
    chunk is checked as it arrives and the excess is never accumulated.
    """
    stream = request.environ["wsgi.input"]
    body = bytearray()
    while True:
        line = stream.readline(_CHUNK_LINE_MAX + 1)
        if not line or len(line) > _CHUNK_LINE_MAX or not line.endswith(b"\r\n"):
            raise RequestBodyMalformedError("unterminated chunk size line")
        size_field = line[:-2].split(b";", 1)[0].strip()
        if not size_field:
            # An empty size field is not the terminating chunk: a chunk-size
            # line is 1*HEXDIG (RFC 9112 7.1), so a bare CRLF or a line that is
            # only chunk extensions (";ext=1") carries no size at all. Reading
            # it as 0 ended the body here and answered 200 with whatever had
            # been accumulated so far, framing a truncated message as a
            # complete one.
            raise RequestBodyMalformedError("chunk size line carries no size")
        try:
            # parse_ascii_int, not int(x, 16): the latter takes digits from the
            # whole Unicode Nd set and accepts "_" as a separator, so a chunk
            # size of "1_0" declared 16 bytes where the client sent 2 and the
            # reader consumed the next 16 bytes of the connection, bytes
            # belonging to whatever request follows this one on a keep-alive
            # socket.  It also rejects every character outside the base's own
            # digit set, so the size is never negative and needs no sign check.
            size = parse_ascii_int(size_field.decode("ascii"), 16)
        except (UnicodeDecodeError, ValueError) as exc:
            raise RequestBodyMalformedError(f"not a hex chunk size: {size_field!r}") from exc
        if size > limit - len(body):
            raise RequestBodyTooLargeError(f"body over the {limit}-byte limit")
        if size == 0:
            # The terminating chunk, then optional trailers to the final CRLF.
            # The accumulated length is the bound: one trailer line under
            # _CHUNK_LINE_MAX can be read in a loop forever, and every line it
            # reads is another moment this handler thread and its connection
            # slot are held against a peer that will never finish.
            trailer_bytes = 0
            while True:
                trailer = stream.readline(_CHUNK_LINE_MAX + 1)
                if trailer in (b"\r\n", b"\n"):
                    break
                if not trailer:
                    # End of input where the trailer section's final CRLF was
                    # due, not the end of it: the message is truncated, and
                    # answering it 200 would hand the caller a body whose
                    # framing this reader knows is incomplete, with whatever
                    # the client sends next read as the rest of it.
                    raise RequestBodyMalformedError("truncated trailer section")
                if len(trailer) > _CHUNK_LINE_MAX:
                    raise RequestBodyMalformedError("oversize trailer line")
                trailer_bytes += len(trailer)
                if trailer_bytes > _TRAILER_MAX_BYTES:
                    raise RequestBodyMalformedError(
                        f"chunk trailers over the {_TRAILER_MAX_BYTES}-byte limit"
                    )
            return bytes(body)
        remaining = size
        while remaining:
            part = stream.read(min(remaining, _BODY_READ_CHUNK))
            if not part:
                raise RequestBodyMalformedError("chunk ended before its declared size")
            body += part
            remaining -= len(part)
        if stream.read(2) != b"\r\n":
            raise RequestBodyMalformedError("chunk not CRLF terminated")


def read_request_body(limit: int) -> bytes:
    """Read the request body, refusing anything over *limit* bytes.

    This replaces ``request.body`` on every path that reads a client-supplied
    payload.  Bottle's property drains the WHOLE declared body before the
    caller sees a byte of it, holding it in a ``BytesIO`` up to 100 KiB and
    spilling to a ``NamedTemporaryFile`` past that — so a request declaring
    ``Content-Length: 4000000000`` wrote 4 GB (to a tmpfs ``/tmp``, so RAM)
    before the endpoint's own 64 KiB cap could look at it, and that temporary
    file was released only when the environ dict holding it was collected.
    The cap was real; the resource it was meant to bound was allocated before
    the cap ran.

    Here the declared length is checked BEFORE a byte is read, so the oversized
    request costs one header comparison, and the read itself stops within one
    chunk of *limit* whatever the client sends after that.

    A framed body is read to its DECLARED length and no further.  Under the
    serving stack ``wsgi.input`` is the socket's buffered reader, and a
    ``read(n)`` on it returns only once *n* bytes have arrived or the peer has
    gone away: reading to EOF would park the handler until the client's socket
    deadline, while the client is itself waiting for the response.

    Raises :class:`RequestBodyTooLargeError` past *limit* and
    :class:`RequestBodyMalformedError` on framing this will not accept, which
    includes a ``Content-Length`` that is present but is not a byte count; see
    :class:`RequestBodyError` for what the caller owes the connection.
    """
    chunked = _body_is_chunked()
    declared = None if chunked else _declared_content_length()
    if declared is not None and declared > limit:
        raise RequestBodyTooLargeError(f"declared {declared} bytes over the {limit}-byte limit")
    stream = request.environ["wsgi.input"]
    if chunked:
        return _read_chunked_body(limit)
    body = bytearray()
    if declared is not None:
        while len(body) < declared:
            part = stream.read(min(_BODY_READ_CHUNK, declared - len(body)))
            if not part:
                # The peer closed mid-body: hand back what arrived and let the
                # caller reject it as the unparseable payload it is.
                break
            body += part
        return bytes(body)
    # No Content-Length to compare: read up to the cap and one byte, so an
    # unframed oversize body is detectable rather than read to its end.
    while len(body) <= limit:
        part = stream.read(min(_BODY_READ_CHUNK, limit + 1 - len(body)))
        if not part:
            return bytes(body)
        body += part
    raise RequestBodyTooLargeError(f"body over the {limit}-byte limit")


#: Glob rebrew's writer names its documents with, and the reader globs for.
_COVERAGE_FILE_PREFIX = "coverage-"
_COVERAGE_FILE_SUFFIX = ".toml"


def _coverage_file_stats() -> tuple[tuple[str, int, int], ...]:
    """``(name, mtime_ns, size)`` for every coverage document, name-sorted.

    ONE directory scan behind both freshness surfaces (:func:`_snapshot_db_mtime`
    and :func:`_newest_mtime_ns`) and behind the SSE watcher, so the change
    token, the rendered stamp and the broadcast cannot disagree about what the
    coverage directory holds.  Sorted because a directory listing's order is not
    a fact about the files; a file that vanishes between the listing and the
    stat is skipped, and the next call's differing key catches the miss.
    """
    entries: list[tuple[str, int, int]] = []
    for path in _db_path().glob(f"{_COVERAGE_FILE_PREFIX}*{_COVERAGE_FILE_SUFFIX}"):
        try:
            st = path.stat()
        except OSError:
            continue
        entries.append((path.name, st.st_mtime_ns, st.st_size))
    entries.sort()
    return tuple(entries)


def _snapshot_db_mtime() -> tuple[int, int] | None:
    """Return (fingerprint, total size) of the coverage documents, or None.

    The replacement for the WAL-aware ``coverage.db`` snapshot: the token
    folds every ``coverage-*.toml`` — its name, mtime_ns and size — into one int,
    and element 1 is their total size, which `/api/health` publishes as the
    coverage size.  Callers must treat the fingerprint as an opaque change
    token, never as an mtime.

    A directory holding no document reads as None, which is the old missing-file
    answer: every DB-derived memo keys on this, every ETag is built from it, and
    the endpoints answer the 503 ``db_unavailable`` contract a moment later.
    A single file's mtime is not enough here the way it was for SQLite: a
    rebuild writes one document per target, so a target added, removed or
    rewritten anywhere in the directory has to move the token.

    EVERY coverage-derived cache key and ETag must be built on this snapshot,
    not raw ``st_mtime`` on one file.
    """
    entries = _coverage_file_stats()
    if not entries:
        return None
    # The name is the only free-text field and comes first, so it absorbs every
    # colon before the two trailing integers: the NUL between entries makes the
    # entry list unambiguous and the trailing ints make the fields inside one
    # entry unambiguous, even for a target id carrying a colon.
    payload = "\0".join(f"{name}:{mtime_ns}:{size}" for name, mtime_ns, size in entries)
    # fs_text_bytes, not encode("utf-8"): a name the filesystem spelled as raw
    # bytes outside UTF-8 reaches this as a surrogate-escaped str and the
    # strict encode raised, so one such file in the coverage directory turned
    # every endpoint that keys on this token into a 500.
    digest = hashlib.sha256(fs_text_bytes(payload)).digest()
    return int.from_bytes(digest[:8], "big"), sum(size for _n, _m, size in entries)


#: Nanoseconds in a second, and in a microsecond: the two constants the
#: file-mtime conversion below is written in.
_NS_PER_SECOND = 1_000_000_000
_NS_PER_MICROSECOND = 1_000

#: The first and last instants :class:`datetime` can represent, as whole
#: seconds since the epoch.  An mtime is attacker-adjacent input: it comes off
#: the filesystem, so a restored tree, a bad RTC, a ``touch -d`` or a
#: filesystem whose own clock runs ahead can carry a value outside this range
#: (a year-10000 stamp is reachable with ``os.utime`` on any Linux box, and
#: FAT's own 2-byte year field tops out in 2107).  ``fromtimestamp`` raises
#: ``ValueError`` on one, which took ``/api/health`` and Potato's footer down
#: with it -- a freshness stamp is never worth a 500 over a stamp the clock
#: cannot name.  Clamping reports the extreme instead, and the extremes are
#: the right answer: both surfaces are rendering "as far from now as a
#: timestamp can say", which is what an unrepresentable mtime means.
_MIN_MTIME_SECONDS = -62_135_596_800  # 0001-01-01T00:00:00Z
_MAX_MTIME_SECONDS = 253_402_300_799  # 9999-12-31T23:59:59Z


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

    The seconds are clamped to the range :class:`datetime` spans before the
    conversion, because the value comes off the filesystem and an mtime
    outside that range raises rather than rendering (see
    :data:`_MIN_MTIME_SECONDS`).  The remainder rides on top of the clamped
    second, which stays inside the range: the last representable whole second
    still has a microsecond field to add to.
    """
    seconds, nanoseconds = divmod(mtime_ns, _NS_PER_SECOND)
    seconds = min(max(seconds, _MIN_MTIME_SECONDS), _MAX_MTIME_SECONDS)
    return datetime.fromtimestamp(seconds, tz=UTC) + timedelta(
        microseconds=nanoseconds // _NS_PER_MICROSECOND
    )


def _newest_mtime_ns() -> int | None:
    """Newest mtime_ns across the coverage documents, or None when there are none.

    The same directory scan :func:`_snapshot_db_mtime` folds, as a plain instant
    instead of an opaque token: for the surfaces that RENDER the freshness time
    (``/api/health``, Potato Mode's footer stamp) rather than key a cache on it.
    """
    entries = _coverage_file_stats()
    if not entries:
        return None
    return max(mtime_ns for _name, mtime_ns, _size in entries)


# ── Coverage snapshots ─────────────────────────────────────────────
#
# Every fact the dashboard serves comes from one call to rebrew's coverage TOML
# reader.  That call parses each `coverage-<target>.toml` and derives what the
# SQLite schema used to materialize (per-section buckets, byte coverage, the
# by-VA index), and it is memoized on the files' own stat — so an unchanged
# directory returns THE SAME mapping and the SAME snapshot objects.  That
# identity is the change token every DB-derived cache here keys on, exactly the
# role the WAL-aware fingerprint played against SQLite.
#
# The snapshot replaces `read_snapshot`'s pin as well: a snapshot is frozen
# (every collection is a tuple or a MappingProxyType), so a response built from
# one can never pair one build's cells with the next build's functions — the
# consistency the SQLite read transaction bought, now held by the type.


def coverage_snapshots() -> Mapping[str, CoverageSnapshot]:
    """Every target's snapshot, keyed by target id.

    Raises :class:`CoverageTomlError` when the directory holds no readable
    document at all, which is the missing-or-corrupt database of the
    SQLite era: a project with nothing to serve answers 503, not an empty
    dashboard.  One unreadable document beside readable ones is skipped by the
    reader with a warning naming the file, and the other targets keep serving.
    """
    snapshots = load_all_coverage_from(_db_path())
    if not snapshots:
        raise CoverageTomlError(
            f"{_db_path()}: no coverage-*.toml document — run 'rebrew build-db'"
        )
    return snapshots


def db_target_ids() -> list[str]:
    """Target ids the coverage directory alone knows about, sorted.

    The read-only counterpart to :func:`resolve_targets`: the ids written by the
    last build, before the project config contributes a target that has never
    been built.  An empty directory is an empty list here rather than an error,
    because this is also what the config-only fallback target list is built
    from.
    """
    return sorted(load_all_coverage_from(_db_path()))


def coverage_for(target: str) -> CoverageSnapshot:
    """The snapshot for *target*, or an empty one it has never been built.

    A target the project config declares but no build has written is still
    addressable — :func:`resolve_targets` lists it, so the endpoints must answer
    it.  The SQLite reader answered those from an empty table set (every query
    returned no rows); the TOML equivalent is a snapshot with no sections, no
    cells and no functions, so the response shapes are the same empty ones.
    """
    snapshot = load_all_coverage_from(_db_path()).get(target)
    if snapshot is not None:
        return snapshot
    return CoverageSnapshot(
        target=target,
        version=0,
        sections=MappingProxyType({}),
        functions=(),
        globals=(),
        verify_results=(),
        history=(),
        function_stats=MappingProxyType(
            {
                "total": 0,
                "covered_bytes": 0,
                "matched_bytes": 0,
                "total_bytes": 0,
                "by_status": MappingProxyType({}),
                "by_module_counts": MappingProxyType({}),
            }
        ),
        paths=MappingProxyType({}),
    )


def coverage_version(snap: CoverageSnapshot) -> str:
    """The schema version of *snap*, as the string the SPA compares.

    `db_version` used to be a metadata row; the TOML document stamps its own
    format version, and it is the only version a client can be told.  Spelled as
    a string because that is what the served payload always carried and what the
    SPA compares against ``known_schema``.
    """
    return str(snap.version)


def known_schema_versions() -> list[str]:
    """The format versions of the coverage documents this server just read, sorted.

    The served ``known_schema`` list, so the format version reaches the client
    from the server rather than from a copy hardcoded in the bundle, which
    would drift as rebrew advances the format.

    Read off the snapshots, NOT off what the reader supports, and that is a
    tautology today: ``rebrew.coverage_toml`` raises on any document whose
    ``version`` is not the one it reads, so every snapshot that exists carries
    that single version and this list can only ever name it. An empty list means
    no readable document, which is the 503 ``db_unavailable`` contract the
    caller answers before a payload is ever serialized. The field therefore
    cannot tell a client "this build does not understand the file" — that
    document is never readable, so it never reaches a client. Making it carry
    that meaning needs the reader's ACCEPTED set, which rebrew does not export.
    Both ``/data`` and ``/potato`` answer the unreadable case with the 503
    ``db_unavailable`` contract instead, which is where the reader's own
    message naming the file surfaces.

    Pinned by ``tests/test_server.py::TestCoverageVersionGate``, which fails if
    a version the reader refuses can ever reach this list.
    """
    return sorted({str(snap.version) for snap in load_all_coverage_from(_db_path()).values()})


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
    """DB-freshness ETag over the document snapshot *snap* + *parts*; 304 on match.

    Shared tail of every cacheable DB-derived endpoint (/api/targets, /stats,
    /data, the function list, the function detail route, /asm, /bytes,
    /potato): compute ``_safe_etag(snap[0], parts...)``, answer
    ``If-None-Match`` with a 304, else hand the ETag back for the caller to
    attach to its response.  Callers pass their own
    :func:`_snapshot_db_mtime` result — endpoints that also key a memo on
    that snapshot (/data) stat the DB exactly once.  Returns None when *snap*
    is None (DB unreadable) — the caller then sends no ETag (the endpoint
    itself fails with 503 shortly after).

    Counts the conditional GET both ways on ``metrics.CACHES``: a 304 is a hit
    and a full answer is a miss, which is what tells an operator reading a
    rising mean duration whether the build got slower or the validators
    stopped revalidating.

    The 304 carries the same ``Vary: Accept-Encoding`` the 200 it stands in for
    carries, which :func:`recoverage.ui._not_modified` already sent: every body
    here is content-negotiated, and a shared cache that keyed this resource
    without that header would hand a brotli body to a client that asked for
    none.
    """
    if snap is None:
        return None
    etag = _safe_etag(snap[0], *parts)
    if _if_none_match_matches(_header("If-None-Match", ""), etag):
        metrics.CACHES.hit(metrics.REVALIDATION_CACHE)
        raise HTTPResponse(
            status=304,
            headers={
                "ETag": etag,
                "Vary": "Accept-Encoding",
                "Cache-Control": CACHE_REVALIDATE,
            },
        )
    metrics.CACHES.miss(metrics.REVALIDATION_CACHE)
    return etag


#: `functions.markerType` values that name data, not a function (rebrew ADR 023
#: widened the set past GLOBAL/DATA).  ONE definition: the SPA function list,
#: the Potato function list, and the by-status counts all filter on it, and
#: three copies of the literal is three chances to disagree.
#:
#: Read off rebrew's ``DATA_MARKERS`` rather than re-spelled, because that
#: constant is rebrew's declared single home for the set and rebrew says so
#: next to it ("do not re-spell the tuple at call sites").  A copy here was
#: correct at the moment it was written and silently wrong the day rebrew
#: widened the marker vocabulary again: ``/stats``' ``by_status`` would then
#: count a new data marker as a function, while ``summary.totalFunctions`` —
#: derived by rebrew from ``FUNCTION_MARKERS``, and served in the same
#: response — would not, so one payload would answer "how many functions" two
#: ways.  Sorted, so the name is stable in a traceback; a set would answer the
#: same and read worse.
DATA_MARKER_TYPES: tuple[str, ...] = tuple(sorted(DATA_MARKERS))


def _is_data_marker(fn: Any) -> bool:
    """Whether *fn* names data rather than a function.

    The predicate replaces `NOT_DATA_MARKER_SQL`.  An unknown marker type is a
    function, exactly as rebrew's ``NOT NULL DEFAULT 'FUNCTION'`` says: the
    stored marker crosses the TOML boundary as text, so an absent one arrives
    as ``""`` and lands on the function side, which is the same verdict the
    SQL's ``markerType IS NULL OR`` arm gave a nullable column.

    That is the complement of rebrew's ``FUNCTION_MARKERS`` rule only over
    rebrew's VALID_MARKERS; outside it the two disagree on purpose, and the
    disagreement is this package's.  rebrew's ``function_stats`` counts a row
    as a function when its marker is in ``FUNCTION_MARKERS``, so a NULL or
    out-of-vocabulary marker is dropped from ``summary.totalFunctions`` and
    kept here.  Recoverage keeps it because the SQL did (an unmarked row used
    to vanish from the function lists entirely, which is a worse wrong answer
    than a row counted that the producer did not count).  The two numbers are
    therefore not the same quantity and are not formatted as though they were;
    rebrew's writer validates every marker against ``VALID_MARKERS``, so a
    document that parses can only reach the disagreement through an absent one.
    """
    return fn.markerType in DATA_MARKER_TYPES


#: Cell states folded into each BYTE bucket :func:`_section_summary` sums, read
#: off rebrew's own fold rather than spelled out here.  The served cell COUNTS
#: are rebrew's too (``Section.bucket_counts``, read by :func:`_bucket_row`);
#: the byte side needed the same states named, because ``Section.buckets`` is
#: keyed by cell STATE and the states sharing a bucket have to be grouped before
#: their bytes are summed.  A second hand-written copy of that grouping was a
#: vocabulary this package silently drifted from: a state rebrew added was
#: absent here, so it contributed no bytes to a counted bucket while
#: ``Section.covered_bytes`` still counted it, and the served byte figures
#: stopped reconciling with no error anywhere.  Reading the owner makes that
#: state unreachable — a rebrew that renames the mapping fails this import
#: loudly, where the copy failed quietly.
#: ``_BUCKET_OF_STATE`` is underscore-named on rebrew's side and is read
#: deliberately: it is the one place the fold exists, and
#: ``tests/test_server.py`` (``TestBucketReconciliation``) pins what it holds
#: against a literal written in the test.
_BUCKET_FOLD: dict[str, tuple[str, ...]] = {
    bucket: tuple(state for state, _ in grouped)
    for bucket, grouped in itertools.groupby(
        sorted(_BUCKET_OF_STATE.items(), key=lambda pair: (pair[1], pair[0])),
        key=itemgetter(1),
    )
}
#: The buckets ``_section_summary`` reports a count and a byte sum for.  The
#: other five (``data``, ``thunk``, ``none``, ``proven``, ``size_mismatch``)
#: contribute covered bytes and nothing else, which is why the summary carries
#: no key for them.  This is the served shape rather than a vocabulary, so it
#: is spelled out here rather than read: which buckets get a response key is
#: this package's decision, and adding one to a released payload is a change
#: the release notes have to make.
_SUMMARY_COUNTED_BUCKETS: tuple[str, ...] = ("exact", "reloc", "near_match", "stub", "padding")


def _bucket_row(section: Any) -> dict[str, Any]:
    """The short-key bucket dict served by /stats, /data and Potato Mode.

    ONE definition so the response shapes cannot drift, and a copy of what
    rebrew derived at load (``Section.bucket_counts``, the same fold under
    rebrew's name) rather than a second walk of the cells: the counts are
    CELL counts, byte-identical to what the materialized ``section_cell_stats``
    table carried, and that table was dropped from the coverage format for the
    reason this reader does not re-derive them either.  Measured on a 40k-cell
    ``.text``: 2.3 ms to walk the cells against 1 us to copy the derived
    counts, once per section per /stats, /data and Potato render.

    ``dict()`` and not the mapping proxy itself, because the served dict is
    splatted into a response payload and a caller that mutates it must not be
    editing the snapshot.  ``other`` is the producer's catch-all
    (compile_error, extract_error, invalid_va, missing_file, missing_size,
    skip, unknown and the data drift/unchecked verdicts), so total_cells still
    reconciles with the bucket sum.
    """
    return dict(section.bucket_counts)


def _section_summary(section: Any) -> dict[str, Any]:
    """One section's entry in the ``summary`` blob :func:`_summary` rebuilds.

    Rebuilt rather than read, because the TOML format stores facts: every field
    here is a count or a byte sum over the section's own cells, which is
    exactly how the producer computed it.  The counts come from rebrew's
    ``Section.bucket_counts``; the byte sums re-bucket rebrew's ``Section
    .buckets``, which is keyed by cell STATE, through :data:`_BUCKET_FOLD`,
    because no derived field carries a per-bucket byte total and the grouping
    itself is rebrew's.  The walk this replaces cost 5.8 ms on a 40k-cell
    section against 1.8 ms here.

    ``coveredBytes`` is ``Section.covered_bytes``, the reader's own
    total-minus-``none``; ``totalFunctions`` still walks the cells, because it
    counts the function NAMES they carry and no derived field holds it.
    Non-``none`` cells only, which is the ``totalFunctions`` the progress bars
    divide by.
    """
    counts_of = section.bucket_counts
    bytes_of_state = section.buckets
    sizes = {
        bucket: sum(bytes_of_state.get(state, 0) for state in states)
        for bucket, states in _BUCKET_FOLD.items()
        if bucket in _SUMMARY_COUNTED_BUCKETS
    }
    counts = {bucket: counts_of[bucket] for bucket in _SUMMARY_COUNTED_BUCKETS}
    total_functions = sum(len(cell.functions) for cell in section.cells if cell.state != "none")
    return {
        "exactMatches": counts["exact"],
        "relocMatches": counts["reloc"],
        "nearMatchCount": counts["near_match"],
        "stubCount": counts["stub"],
        "paddingCount": counts["padding"],
        "exactBytes": sizes["exact"],
        "relocBytes": sizes["reloc"],
        "nearMatchBytes": sizes["near_match"],
        "stubBytes": sizes["stub"],
        "paddingBytes": sizes["padding"],
        "coveredBytes": section.covered_bytes,
        "totalFunctions": total_functions,
        "size": section.size,
    }


def coverage_pct(covered: int, total: int) -> float:
    """Byte coverage of *covered* of *total*, as a percentage floored to 2dp.

    Floored, not rounded to nearest, and that is the whole point: 999_997 of
    1_000_000 covered bytes round to ``100.0`` while three bytes are still
    unmatched, so a project one short of complete reads as complete in every
    surface that shows the number.  ``summary.coveragePercent`` and the
    per-section ``coverage_pct`` are the same quantity, so they take the same
    rounding, from here (rebrew's ``floor_pct``) rather than each one calling
    ``round``.  A *total* of 0 has no ratio and answers 0.0.
    """
    return floor_pct(covered, total, 2)


def pct_1dp(value: float) -> float:
    """*value* (a :func:`coverage_pct` figure) at 1dp, floored like it was.

    The narrow surfaces — `recoverage stats`, the Markdown export, the Potato
    map header — print one decimal, and formatting the 2dp value with
    ``%.1f`` rounded it back UP: 99.999% of 100_000 bytes floors to 99.99 and
    then printed as ``100.0%`` in all three, while ``check --min-coverage
    100`` failed the same section on the unrounded ratio.  Flooring once more
    is what keeps "one byte short of complete" from reading as complete in
    every surface that shows the number, which is why
    :func:`coverage_pct` floors at all.

    Takes the percentage, not the counts: the callers hold the 2dp figure
    :func:`coverage_pct` already produced, and a second division here would be
    a second rounding of the same ratio.
    """
    return floor_pct(value, 100, 1)


def _summary(snap: CoverageSnapshot) -> dict[str, Any]:
    """The ``summary`` blob ``build_db`` stored, rebuilt from the snapshot.

    ``build_db`` took rebrew's catalog-grid summary, added one entry per
    non-``.text`` section, and stored the result; the TOML writer stores the
    facts and drops the blob, because every number in it is a pure function of
    the cells and functions beside it.  The top level is the grid summary (the
    ``.text`` fallback the SPA and Potato read) and the section entries are
    :func:`_section_summary`, so a client sees the keys and the values it always
    did.

    The `.text` byte figures are read off the section rather than recomputed
    here: ``Section.__post_init__`` already folds the cells into ``buckets`` and
    ``covered_bytes``, and folding them a second time (with the ``"none"`` rule
    spelled out as a literal a third time) is a copy that moves when rebrew's
    cell-state vocabulary moves, and it moved silently — this blob and the
    ``sections[".text"].covered_bytes`` of the same ``/data`` response are two
    answers to one question.  ``textSize`` stays the section's DECLARED size,
    not its cell bytes, because that is the denominator the producer used and
    the number the served key has always carried.
    """
    stats = snap.function_stats
    by_status = stats["by_status"]
    text = snap.sections.get(".text")
    text_size = text.size if text is not None else 0
    # `Section.buckets` is the reader's own bytes-per-state over the .text
    # cells, and `Section.covered_bytes` its total-minus-`none`; walking the
    # cells here to arrive at the same two numbers was 1.5 ms of every /stats,
    # /data and Potato render on a 40k-cell target.
    text_buckets: Mapping[str, int] = text.buckets if text is not None else {}
    covered = text.covered_bytes if text is not None else 0
    matched = sum(count for status, count in by_status.items() if status in MATCHED_STATUSES)
    summary: dict[str, Any] = {
        "totalFunctions": stats["total"],
        "matchedFunctions": matched,
        "exactMatches": by_status.get("EXACT", 0),
        "relocMatches": by_status.get("RELOC", 0),
        "nearMatchCount": by_status.get("NEAR_MATCHING", 0),
        "stubCount": by_status.get("STUB", 0),
        "coveredBytes": covered,
        "paddingBytes": text_buckets.get("padding", 0),
        "dataBytes": text_buckets.get("data", 0),
        "thunkBytes": text_buckets.get("thunk", 0),
        "coveragePercent": coverage_pct(covered, text_size),
        "textSize": text_size,
    }
    for name, section in snap.sections.items():
        if name != ".text":
            summary[name] = _section_summary(section)
    return summary


def _section_stats(snap: CoverageSnapshot) -> dict[str, Any]:
    """Byte-based per-section stats + summary + by_status for *snap*.

    ONE implementation shared by the ``/api/targets/<target>/stats`` endpoint
    and the ``recoverage stats`` CLI.  The summary parse, the per-section bucket
    loop, the section-size lookup, and the by-status count were copy-pasted in
    both (and drifted twice — cell-count vs byte-based, covered_bytes presence,
    key names); this is the single source of truth.

    A section with no cells is absent from ``sections``, which is the shape the
    old ``GROUP BY section_name`` produced: a section row the catalog built
    without any cell is a section with nothing to report, not one reporting
    zero coverage over its whole size.
    """
    sections: dict[str, Any] = {}
    for name, section in snap.sections.items():
        if not section.cell_count:
            continue
        buckets = _bucket_row(section)
        # PROVEN is a semantic-equivalence promotion, so it counts as matched
        # HERE only; rebrew's catalog grid counts byte-identical EXACT/RELOC
        # alone, so this number is not the grid's matchedFunctions.
        matched = buckets["exact"] + buckets["reloc"] + buckets["proven"]
        covered = section.covered_bytes
        # The bytes per state the reader derived, summed: the same total a
        # per-cell `sum(cell.size ...)` walked every section to reach, once per
        # /stats, /data and CLI stats call.
        total = sum(section.buckets.values())
        sections[name] = {
            **buckets,
            "matched": matched,
            "covered_bytes": covered,
            "total_bytes": total,
            "coverage_pct": coverage_pct(covered, total),
            # The section row's declared size, which the schema allowed to be
            # NULL (.bss carries no file extent).  A section of unknown size
            # has zero known bytes, same treatment as the byte sums above.
            "size_bytes": section.size or 0,
        }

    # Function counts by status.  The data-marker rows (DATA_MARKER_TYPES) live
    # in the functions array but are data, not functions — exclude them.
    by_status: dict[str, int] = {}
    for fn in snap.functions:
        if _is_data_marker(fn):
            continue
        # "UNKNOWN" is the spelling the rest of the package uses for an
        # absent status: rebrew's writer canonicalizes to it
        # (`rebrew.coverage_toml`), its reader derives these counts with the
        # same default, and `api._FUNCTION_STATUSES` — the vocabulary
        # `?status=` filters on — has no lowercase "unknown" in it, so a
        # lowercase key here would be a bucket the API cannot select.
        key = fn.status or "UNKNOWN"
        by_status[key] = by_status.get(key, 0) + 1

    return {"summary": _summary(snap), "sections": sections, "by_status": by_status}


# ── Path helpers ───────────────────────────────────────────────────


def _assets_dir() -> Path:
    """The UI files, which ship as package data inside the recoverage package."""
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
#: Key for :data:`_RESOLVED_TARGETS_CACHE`: the config stat and the
#: coverage-document snapshot, the two inputs of the merge, so the memo
#: self-invalidates on either.  The document half the rebuild broadcast
#: already covered; the config half nothing did (see :func:`resolve_targets`).
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


def peer_label() -> str:
    """The requesting peer, escaped for a log line, ``unknown peer`` without one.

    ``REMOTE_ADDR`` is peer-supplied only through a proxy, but a raw value in
    a log line can carry control bytes either way, so it goes through
    :func:`_log_safe` like every other request log argument.  One definition
    for the label every request-path record names its peer by, so a log line
    and the ``peer`` field beside it cannot spell it two ways.
    """
    return _log_safe(request.environ.get("REMOTE_ADDR", "") or "unknown peer")


#: Name of the record attribute carrying the structured fields, read by
#: ``cli.StructuredFormatter`` and ignored by a plain one.  ONE name, so the
#: writer (here) and the reader (the formatter) cannot drift apart.
LOG_FIELDS_ATTR = "log_fields"


def request_log_fields(
    status: int,
    duration_ms: float | None = None,
    **fields: object,
) -> dict[str, dict[str, object]]:
    """The ``extra=`` for a record about the request being served.

    The request id is the pivot from a log line to a client, but on its own it
    only says WHICH request; an operator pivoting from a metric anomaly ("three
    slow reads on /data", "a 5xx in the status buckets") has to read the
    rendered message to learn the method, path, status and duration, and a
    log aggregator cannot index what it has to parse out of prose.  The same
    values ride on the record as named fields, rendered as JSON scalars after
    the message (``cli.StructuredFormatter``), so one grep over the fields
    answers "which requests" without reading a line.

    Untrusted values are escaped exactly as they are in the message, and
    *fields* is for the extra context a particular call site has (a route, a
    target) and is not escaped here: every caller passes literals it owns.
    """
    context: dict[str, object] = {
        "method": _log_safe(request.method),
        "path": _log_safe(request.path),
        "status": status,
    }
    if duration_ms is not None:
        context["duration_ms"] = round(duration_ms, 1)
    context.update(fields)
    return {LOG_FIELDS_ATTR: context}


_TOML_CACHE_MTIME: tuple[int, int] | None = None


def _get_targets_config() -> dict[str, Any]:
    """Load target configuration from rebrew-project.toml (thread-safe, cached).

    Each value's ``filename`` is the target binary resolved against the project
    root ("" when the target configures none), the shape ``_target_filename``
    and ``_find_dll_path`` consume.
    """
    global _TOML_CONFIG_CACHE, _TOML_CACHE_MTIME
    root = _project_dir()
    toml_path = root / CONFIG_NAME
    current = config_fingerprint(root)
    with _RESOLVED_TARGETS_CACHE_LOCK:
        if _TOML_CONFIG_CACHE is not None and current == _TOML_CACHE_MTIME:
            return _TOML_CONFIG_CACHE

        try:
            config = read_config(root)
        except WorkspaceConfigError as exc:
            # A present file that is not readable UTF-8 TOML. The shared
            # reader raises rather than returning {}: the defaults that
            # would fill in name a different workspace. Targets contributed
            # by the file are dropped; an explicit RECOVERAGE_DB still serves.
            _log.warning("Failed to load %s: %s", CONFIG_NAME, exc)
            config = {}
        else:
            if toml_path.is_file() and not config:
                # A present file that parses to nothing names no targets.
                _log.warning("Failed to load %s: unreadable or invalid TOML", CONFIG_NAME)
        targets_info: dict[str, Any] = {}
        for tid, entry in targets_table(config).items():
            binary = target_binary(root, entry)
            targets_info[tid] = {"filename": str(binary) if binary is not None else ""}

        _TOML_CONFIG_CACHE = targets_info
        _TOML_CACHE_MTIME = current
        return targets_info


def clear_target_cache() -> None:
    global _TOML_CONFIG_CACHE, _TOML_CACHE_MTIME, _RESOLVED_TARGETS_CACHE
    with _RESOLVED_TARGETS_CACHE_LOCK:
        _TOML_CONFIG_CACHE = None
        _TOML_CACHE_MTIME = None
        _RESOLVED_TARGETS_CACHE = None


def _target_filename(tid: str, t_info: Any) -> str:
    """Binary filename configured for target *tid* (*tid* when unset).

    ONE definition of the defensive shape check used for display names —
    the config loader stores the binary path already resolved against the
    project root ("" when the target configures none), and both target-list
    builders fall back to the id here.
    """
    filename = t_info.get("filename", tid) if isinstance(t_info, dict) else tid
    return filename or tid


def resolve_targets() -> list[dict[str, str]]:
    """Resolve available targets from the coverage directory + config.

    Config-declared targets first, then any target the last build wrote, so the
    SPA dropdown and Potato Mode render and default to the same first entry.

    Memoized per (config stat, coverage snapshot) — both inputs to the merge,
    the same contract every other coverage-derived memo follows.  Keying on the
    config alone would have been the obvious half: the parsed config
    self-invalidates on its stat, so without the config half in this key the
    two disagreed.  Adding a target to ``rebrew-project.toml`` while the
    server ran left ``_get_targets_config`` reporting it (and every target
    check accepting it) while the dropdown, ``/api/targets`` and Potato Mode's
    list omitted it until the next rebuild cleared the memo.  Both halves are
    named here so neither depends on an event that may never fire.

    The coverage half is stat'ed before ``coverage_snapshots`` reads, and
    re-checked before the entry is published, so a rebuild that commits during
    the read is answered by the next request rather than by a list filed under
    the fingerprint that superseded it.  That reader runs only on a miss: a hit
    is answered from the memo, because reaching it costs a directory walk and
    the merged list is exactly what the key already proved unchanged.

    Raises :class:`CoverageTomlError` when the directory holds no readable
    document: that is not "a project with no built targets", it is a project
    with nothing to serve, and every caller answers it with the 503 contract.
    """
    global _RESOLVED_TARGETS_CACHE
    # The snapshot token is taken BEFORE the read it describes, and re-checked
    # at publish, like every other coverage-derived memo.  Taken after
    # ``coverage_snapshots()`` it names the build that landed during the read
    # while the list is built from the previous one, and a rebuild whose
    # ``clear_target_cache`` has already run never comes back to clear it: the
    # next build's target is missing from /api/targets, the dropdown and Potato
    # until the build after that.
    key: _ResolvedTargetsKey = (
        config_fingerprint(_project_dir()),
        _snapshot_db_mtime(),
    )
    with _RESOLVED_TARGETS_CACHE_LOCK:
        cached = _RESOLVED_TARGETS_CACHE
        if cached is not None and cached[0] == key:
            return cached[1]

    # Past the cache check, because a hit needs neither the reader nor the
    # merge, and ``coverage_snapshots`` is a fresh ``glob`` plus a ``stat`` per
    # document on every call.  Held outside the lock: rebrew's reader memoizes
    # the parse itself, so the walk is the whole cost, and serializing it behind
    # the package lock made every concurrent target-scoped request queue on it
    # for a value the previous one had already produced.  The read still happens
    # after the token it is published under is stat'ed, and the re-check below
    # still covers a rebuild committing across it.
    snapshots = coverage_snapshots()
    with _RESOLVED_TARGETS_CACHE_LOCK:
        # A racing thread may have filled this key while the reader ran; keep
        # whichever landed first, so every caller sees one list.
        cached = _RESOLVED_TARGETS_CACHE
        if cached is not None and cached[0] == key:
            return cached[1]

        targets_info = _get_targets_config()

        # Config-declared targets come first and are always addressable, even
        # before their first build — "declared in the project config" is what
        # makes a never-built target valid, so it must not 404.
        targets_list = [
            {"id": tid, "name": Path(_target_filename(tid, t_info)).name}
            for tid, t_info in targets_info.items()
        ]
        targets_list += [
            {"id": tid, "name": tid} for tid in sorted(snapshots) if tid not in targets_info
        ]

        if _snapshot_db_mtime() == key[1]:
            _RESOLVED_TARGETS_CACHE = (key, targets_list)
        return targets_list


def _find_dll_path(target: str) -> Path | None:
    """Find the DLL path for a target from project config.

    Returns ``None`` when *target* has no ``[targets.<tid>].binary`` entry —
    the caller then reports a target-specific error instead of silently
    serving a different target's DLL (previously fell back to SERVER's
    binary, which produced plausible-but-wrong disassembly for config-less
    targets) — and when the configured path names something outside the
    project tree, which is a refusal of the file rather than of the target.
    """
    targets = _get_targets_config()
    if target not in targets:
        return None
    t_info = targets.get(target)
    filename = t_info.get("filename", "") if isinstance(t_info, dict) else ""
    if not filename:
        return None
    root = _project_dir()
    candidate = root / filename
    # rebrew-project.toml is untrusted input like a coverage document: it
    # arrives in the checkout, and `[targets.X].binary` is read here and its
    # bytes served from /asm and /bytes. The loader already joined the value
    # onto the root, so containment is the rule left: an absolute value, a
    # parent hop, or a symlink out of the tree would otherwise name any file
    # the process can read. The resolve settles all three at once, and a
    # non-strict resolve normalizes a path that does not exist, which is the
    # common case for a stale config.
    try:
        resolved = candidate.resolve()
    except (OSError, ValueError):
        # A name the platform cannot resolve at all (a NUL byte) is a
        # refusal, not a path.
        resolved = None
    if resolved is None or not resolved.is_relative_to(root.resolve()):
        _log.warning(
            "Refusing [targets.%s].binary outside the project tree: %s",
            _log_safe(target),
            _log_safe(filename),
        )
        return None
    return candidate


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
    and /bytes until the next coverage rebuild.  Re-pointing a binary is an
    operator edit to rebrew-project.toml: it reaches no server code, and the
    rebuild broadcast that clears this dict fires on the DB alone.  The memo
    therefore carries the same config stat its path resolution keys on
    (:func:`config_fingerprint`) and drops every entry when that moves,
    the contract :func:`_get_targets_config` already follows.
    """
    global _DLL_CONFIG_MTIME
    config_fp = config_fingerprint(_project_dir())
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
            # An OSError message quotes the path that failed, which here comes
            # from rebrew-project.toml; escaped so a project file carrying a
            # control byte cannot split the line.
            _log_safe(str(exc)),
            extra=request_log_fields(500),
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
    byte above 0x7f.  Bottle re-reads environ values as UTF-8 and raises
    UnicodeDecodeError on one, which would turn a junk header into a 500 and a
    traceback in the log on every request.  A header that is not decodable text
    carries no usable value, so it reads as absent — the same answer the
    RFC 9110 grammar gives for a value that is not a valid field value.

    The guard is UnicodeError, not UnicodeDecodeError, because bottle's
    re-decode fails in both directions: it encodes the environ value back to
    latin-1 before decoding it as UTF-8, so a value that already holds a
    character above U+00FF raises UnicodeEncodeError from that encode.  The
    latin-1 reading the WSGI server hands over cannot produce one, but a
    harness (or any server that decodes headers as UTF-8) can, and the answer
    has to be the same "absent" either way: this runs in the before_request
    hook, so the failure would be a 500 on every path, before the auth hook.
    """
    try:
        return cast(str, request.headers.get(name, default))
    except UnicodeError:
        return default


def header_present(name: str) -> bool:
    """Whether the request carries *name* at all, whatever its value.

    :func:`_header` cannot answer that: a header sent with an empty value and
    one not sent are the same ``""`` to it.  A gate that admits the second must
    not admit the first, so the two are read apart here.
    """
    return name in request.headers


#: How long a browser is told to reach this dashboard over HTTPS only.
#: One year, the value the preload list expects, and deliberately WITHOUT
#: ``includeSubDomains``: a deployment that serves this dashboard from a
#: subdomain of a host running other services would otherwise pin THOSE to
#: HTTPS for a year over a decision taken here, where the operator cannot see
#: it.  The dashboard's own name is what this response protects.
HSTS_MAX_AGE_SECONDS = 31_536_000


def request_is_https() -> bool:
    """Whether this request reached the process over TLS.

    Two sources, and neither is trusted for anything but this one answer.
    ``wsgi.url_scheme`` is what the server itself saw, which is the whole
    truth for the bundled ``wsgiref`` listener (always ``http``, it speaks no
    TLS) and for a mount behind a TLS-terminating server that sets it.  A
    reverse proxy that terminates TLS in front of this process and forwards
    plain HTTP leaves it ``http``, so ``X-Forwarded-Proto`` is read as well:
    without it a TLS deployment is indistinguishable from a plaintext one and
    never gets the transport rules below.

    A client can send ``X-Forwarded-Proto: https`` over plaintext, and that is
    harmless rather than a bypass: both answers here make a response STRICTER
    (a ``Secure`` cookie the plaintext client then cannot use, an HSTS header a
    browser ignores because it arrived over ``http``).  Nothing is relaxed by
    believing the header, and a deployment that strips it at the edge is the
    deployment that already terminates TLS itself and sets the scheme.
    """
    if request.environ.get("wsgi.url_scheme", "http").lower() == "https":
        return True
    return _header("X-Forwarded-Proto", "").strip().lower() == "https"


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
    by header order, not by merit.  Where a name is spelled twice the LOWER q
    wins, so a ``gzip;q=0`` anywhere in the list still refuses gzip: a ``max``
    here let any other spelling of the same token re-admit an encoding the
    client excluded.
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
        candidates[name] = min(candidates.get(name, 1.0), q)
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
# shipped assets: the bundle is ~131 KB and style.css ~21 KB, and the extra
# effort is paid once per encoding rather than on every request.  Level 19 is
# where zstd stops returning a smaller frame on these bodies (level 22 matches
# it exactly), so this is the knee, not a guess.
ZSTD_STATIC_LEVEL = 19

# gzip's own maximum.  gzip is the fallback a scripted client lands on
# (python-requests advertises only gzip), and there it is the ONLY
# representation on the wire, so it is worth the highest level gzip offers.
# It still loses to both modern encodings on every payload measured here.
GZIP_STATIC_LEVEL = 9

# gzip's dynamic level: level 6, not gzip.compress's default 9.  Measured on a
# ~9 MB /data payload, -9 costs 2x the CPU of -6 for ~9% fewer bytes (96 ms ->
# 707 KB vs 45 ms -> 774 KB).  Dynamic responses pay this on every request, and
# scripted clients (python-requests advertises only gzip) always land here.
# Same reasoning as BROTLI_DYNAMIC_QUALITY.
GZIP_DYNAMIC_LEVEL = 6


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

    Measured on the committed bundle, with the shipped levels
    (``tools/payload_budget.py`` prints these): the inlined shell is 167,249 B
    raw, and brotli q11 gives 49,684 B against zstd's 53,112 B at level 19 and
    gzip's 57,741 B at level 9.  zstd wins on throughput, not on this payload,
    so choosing by size hands every client the brotli body and hands a
    zstd-first client 3.4 KB more than necessary.  The smallest body no longer
    fits one initial congestion window (14,600 B); ``ui._TCP_CWND_BUDGET`` is
    the checked ceiling the bundle is held under.

    Returns (body, "") when the client accepts none of the supported
    encodings, so the caller sets Content-Encoding only on a truthy name.

    One body, one accepted set.  A caller serving the same bytes under several
    sets compresses once with :func:`compress_static_bodies` and selects per set
    with :func:`select_static_variant`, rather than calling this per set.
    """
    accepted = accepted_encodings(accept_encoding)
    if not accepted:
        return body, ""
    return select_static_variant(
        {name: compress_static_body(body, name) for name in accepted}, accept_encoding, body
    )


def compress_static_body(body: bytes, encoding: str) -> bytes:
    """Compress *body* once, at static effort, in *encoding*."""
    if encoding == "zstd":
        return zstd.ZstdCompressor(level=ZSTD_STATIC_LEVEL).compress(body)
    if encoding == "br":
        return cast("bytes", brotli.compress(body, quality=BROTLI_STATIC_QUALITY))
    return gzip.compress(body, compresslevel=GZIP_STATIC_LEVEL)


def compress_static_bodies(body: bytes) -> dict[str, bytes]:
    """Compress *body* once per supported encoding, at static effort.

    One body is served under every accepted-encoding set the shell and the
    static assets are keyed on, and the answer for a set is always one of these
    three bodies: a set selects among them and never needs a fourth
    compression.  A caller that wants many sets at once therefore pays three
    compressions rather than one per set, and the expensive one runs once —
    brotli at :data:`BROTLI_STATIC_QUALITY` is milliseconds per call on the
    shell, and zstd allocates a fresh :data:`ZSTD_STATIC_LEVEL` context on
    every call.
    """
    return {name: compress_static_body(body, name) for name in SUPPORTED_ENCODINGS}


def select_static_variant(
    candidates: dict[str, bytes], accept_encoding: str, identity: bytes
) -> tuple[bytes, str]:
    """Smallest of *candidates* the client accepts, and its encoding.

    *identity* is the uncompressed body, returned with an empty encoding when
    the client accepts none of the supported encodings, so the caller can set
    Content-Encoding only on a truthy name.  A tie goes to the earlier name in
    :data:`SUPPORTED_ENCODINGS`, so bytes that compress to the same length two
    ways are always served under the same encoding.
    """
    accepted = accepted_encodings(accept_encoding)
    best: tuple[bytes, str] | None = None
    for name in SUPPORTED_ENCODINGS:
        if name not in accepted:
            continue
        candidate = candidates[name]
        if best is None or len(candidate) < len(best[0]):
            best = (candidate, name)
    if best is None:
        return identity, ""
    return best


#: Below this size the framing costs more than the squeeze saves, so the
#: response is sent as it is.  Measured: zstd spends 9 bytes on a frame and 13
#: more building its dictionary, so a 47-byte empty target list came back as 56
#: on the wire, and every 4xx envelope (the refusal bodies are one short line of
#: JSON) paid the same tax.  The saving above the floor is real and the CPU is
#: what compress_payload exists to spend; below it neither is true.  The
#: repo-file route makes the same trade at its own size
#: (:data:`recoverage.ui._REPO_MIN_COMPRESS_BYTES`).
MIN_COMPRESS_BYTES = 256


def compress_payload(body: bytes, accept_encoding: str) -> tuple[bytes, str]:
    """Compress body with the best algorithm the client accepts.

    Returns (compressed_body, encoding_name). encoding_name is "" if no
    compression was applied, guaranteeing the caller can always set
    Content-Encoding only when encoding is truthy — which includes a body under
    :data:`MIN_COMPRESS_BYTES`, served whole rather than grown by a frame.
    """
    if len(body) < MIN_COMPRESS_BYTES:
        return body, ""
    encoding = _best_encoding(accept_encoding)
    if encoding == "zstd":
        return _get_zstd_compressor().compress(body), "zstd"
    if encoding == "br":
        return brotli.compress(body, quality=BROTLI_DYNAMIC_QUALITY), "br"
    if encoding == "gzip":
        return gzip.compress(body, compresslevel=GZIP_DYNAMIC_LEVEL), "gzip"
    return body, ""


# ── Search folding ─────────────────────────────────────────────────


def fold_text(text: str | None) -> str | None:
    """NFC + full case folding: the one form a name is searched in.

    ONE folding for every server-side search and name lookup.  It used to be a
    SQL function (``rc_fold``) ORed beside an ASCII-only ``LIKE``, because the
    comparison happened inside SQLite and a ``LIKE`` folds case for ASCII alone;
    the coverage documents are read into Python now, so both sides fold here and
    the split has no reason to exist.  The guarantee it protected is unchanged
    and stronger: a term that matches what the SPA highlights matches a row
    here, ß folds to ss, and the NFD spelling of a name (what a macOS-side tool
    writes) matches its NFC twin.

    ``casefold``, not ``lower``: it is the folding operator for caseless
    matching.  Compatibility folding is deliberately not applied — NFKC would
    make a superscript or a circled digit compare equal to a plain letter, which
    is not what a substring search should claim.  NULL passes through for
    callers holding an absent optional column; a text column read from a
    document is never NULL.
    """
    if text is None:
        return None
    return unicodedata.normalize("NFC", text).casefold()


def fold_match(haystack: str | None, needle: str) -> bool:
    """Whether *needle* occurs in *haystack* under the one folding.

    The in-memory replacement for ``COALESCE(col, '') LIKE ? ESCAPE '\\'``
    ORed with ``rc_fold(col) LIKE ?``.  A NULL column folds as the empty
    string, which no non-empty term matches — the answer ``COALESCE`` gave a
    nullable ``symbol``.
    """
    return fold_match_folded(haystack, fold_needle(needle))


def fold_needle(needle: str) -> str:
    """:func:`fold_text` of *needle*, for the loop arms of :func:`fold_match`.

    A search term is loop-invariant across every column of every row, and
    NFC composition plus ``casefold`` is not free: folding it once per call
    made a filtered list pay four normalizations of the same string per
    function.  Callers that test a whole collection fold once and pass the
    result to :func:`fold_match_folded`.
    """
    return cast(str, fold_text(needle))


def fold_match_folded(haystack: str | None, folded_needle: str) -> bool:
    """:func:`fold_match` against a needle :func:`fold_needle` already folded.

    Same comparison, same NULL answer: a caller holding a folded term must
    not reach for :func:`fold_text` itself, because a second fold of an
    already-folded string is not guaranteed to be a fixed point for every
    input.
    """
    return folded_needle in (fold_text(haystack) or "")


#: The characters a hexadecimal address can hold, plus the ``0x`` prefix's
#: ``x``, which is what the spelling itself contributes.  Folding is
#: case-independent, so the folded form of a hex address is drawn from this set
#: and nothing else.
_HEX_SPELLING_CHARS = frozenset("0123456789abcdefx")


def fold_can_match_hex(folded_needle: str) -> bool:
    """Whether *folded_needle* could occur in a ``0x``-prefixed hex address.

    A search that matches one of a row's hex address columns has to build that
    column to test it, and there are two spellings per row (``_format_va``
    prints both) plus a fold of each.  A term holding a character no hex
    address can contain cannot match either spelling, so the whole arm is
    skipped: the common case, a name the reader typed, stops formatting and
    folding two strings per row per keystroke.

    The test is on the FOLDED needle, which is what the comparison uses, and
    it is necessary rather than sufficient: a term inside this alphabet can
    still match nothing, and then the columns are built and miss as before.  A
    term outside it cannot match one, so skipping is the same answer the
    comparison would have given.
    """
    return _HEX_SPELLING_CHARS.issuperset(folded_needle)


def fold_can_match_decimal(folded_needle: str) -> bool:
    """:func:`fold_can_match_hex` for a bare decimal number.

    ``str(va)`` is ASCII digits alone, so the folded needle must be ASCII
    digits.  ``str.isdigit`` also accepts every Unicode ``Nd`` digit, which
    the column it guards can never hold: an Arabic-Indic needle passes the
    guard, pays for the folded column and then matches nothing.
    """
    return bool(folded_needle) and all(ch in _ASCII_DIGITS for ch in folded_needle)


# ── Function list ordering ─────────────────────────────────────────
#
# ONE key table for both function lists (the API page and the Potato table),
# because a page boundary is a page boundary: the two surfaces must not be able
# to order the same rows differently and hand a reader a different row 1.

#: Every column a function list can be ordered by, and the ONE spelling of
#: that vocabulary in the package.  Each surface narrows it (the API list takes
#: the whole set, the Potato table the columns it renders) rather than writing
#: its own: three lists of the same six names is three places a renamed or
#: dropped column leaves a spelling behind, and a stale spelling does not fail
#: loudly, it silently answers the default order for a column the reader asked
#: for.  Membership is the whole contract; the order here is documentation.
FUNCTION_SORT_COLUMNS: tuple[str, ...] = (
    "va",
    "name",
    "size",
    "status",
    "symbol",
    "module",
)

#: The columns :func:`function_sort_key` reads through ``getattr``, mapped to
#: the attribute each one names.  ``size`` is absent because it is handled by
#: an arm of its own: its NULL needs a tuple the rest do not, and a key whose
#: attribute is not in this table would raise rather than sort.  An unknown
#: field is the caller's to reject, not this table's.  Every key is a
#: :data:`FUNCTION_SORT_COLUMNS` member, and every one but ``size`` is a plain
#: attribute, which is what keeps the two tables from disagreeing about what
#: the package can sort by.
FUNCTION_SORT_FIELDS: dict[str, str] = {
    "va": "va",
    "name": "name",
    "status": "status",
    "symbol": "symbol",
    "module": "module",
}


def _size_sort_key(fn: Function) -> Any:
    """``size`` order, with the NULL ordering both lists have always had.

    An unknown size sorts before every known one, so a global whose size rebrew
    could not determine stays where it was rather than raising a comparison
    against an int.  The leading flag is what carries that: ``(0, 0)`` against
    ``(1, n)`` is decided on the flag, so the unsized row never meets the int.
    Every other column is a non-optional attribute, so it needs no such arm.
    """
    return (0, 0) if fn.size is None else (1, fn.size)


def function_sort_key(field: str) -> Callable[[Function], Any]:
    """The key *field* orders a function list by, resolved once per list.

    The column a list is sorted by is part of the ORDER, not of the row, so it
    is resolved here rather than inside the per-row key: a list endpoint builds
    a key for every row of the match set to answer a page of 50, and a dict
    lookup plus a branch per row is half the cost of the sort itself (measured
    4.5 ms of a 10.7 ms request against a 6000-function match set).

    The key is the bare attribute for every column but ``size``, where the flag
    tuple above is the value.  That is the same order the 1-tuple wrapper gave:
    it compared identically, and comparing the value costs no allocation.
    """
    if field == "size":
        return _size_sort_key
    return attrgetter(FUNCTION_SORT_FIELDS.get(field, "va"))


# ── Snapshot projections ───────────────────────────────────────────
#
# Every served object is built here from the snapshot, in the order and with
# the key names the SQLite projections used.  The JSON builders are dicts, not
# SQL: the documents are already parsed, so a `json_object(...)` shape would be
# a string built to be parsed back.


def _plain(value: Any) -> Any:
    """*value* as plain JSON-serializable containers.

    A snapshot is frozen (tuples and ``MappingProxyType``), and ``json.dumps``
    refuses a mapping proxy — so every value travelling into a response is
    thawed here, in one place, rather than at each call site.  Tuples become
    lists, which is what the JSON arrays they replace always were.

    A non-finite float becomes ``None`` here for the same reason: JSON has no
    spelling for one, ``json.dumps`` writes the ``NaN`` / ``Infinity`` tokens
    anyway, and every parser outside Python rejects the body, so one figure a
    hand edit or a divide-by-zero left in a document would take the whole
    payload down with it.  ``null`` is the answer both renderers already read
    as "no figure" (``potato._similarity_pct`` leaves it alone, and the SPA
    tests ``== null``).
    """
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _cell_json(cell: Cell) -> dict[str, Any]:
    """One coverage cell as the SPA and Potato Mode read it.

    The optional keys are OMITTED rather than null, which is what the SQLite
    reader this replaced emitted: `json_patch` removed a key whose patch value
    was null, and every consumer reads them with a truthiness test, so absent
    and null are the same thing to them.  Keeping the omission keeps the served
    bytes of a multi-megabyte payload where they were.
    """
    obj: dict[str, Any] = {"start": cell.start, "end": cell.end, "span": cell.span}
    obj["state"] = cell.state
    if cell.functions:
        obj["functions"] = list(cell.functions)
    if cell.label:
        obj["label"] = cell.label
    if cell.parent_function:
        obj["parent_function"] = cell.parent_function
    return obj


def cells_json(cells: Sequence[Cell]) -> str:
    """One section's cells as a JSON array in spatial order.

    The replacement for ``SECTION_CELLS_AGG_SQL``: a section's cells arrive in
    spatial order (the writer sorts them), and the array is serialized once so
    the response builder can splice the text instead of re-encoding it.
    ``ensure_ascii=False`` matches the SQLite JSON functions, which emit UTF-8
    rather than escapes.
    """
    return json.dumps(
        [_cell_json(cell) for cell in cells], ensure_ascii=False, separators=(",", ":")
    )


def function_json(fn: Function) -> dict[str, Any]:
    """The function-detail object, one key per ``functions`` column.

    The same names and the same order as ``build_db``'s ``json_object``
    projection, including the two v6 columns (`updated_by`/`updated_at`) that
    used to be added only when the database carried them: a coverage document
    always carries every column, so the shape is the full one.
    """
    return {
        "va": fn.va,
        "name": fn.name,
        "vaStart": fn.vaStart,
        "size": fn.size,
        "fileOffset": fn.fileOffset,
        "status": fn.status,
        "module": fn.module,
        "cflags": _plain(fn.cflags),
        "symbol": fn.symbol,
        "markerType": fn.markerType,
        "ghidra_name": fn.ghidra_name,
        "list_name": fn.list_name,
        "is_thunk": fn.is_thunk,
        "is_export": fn.is_export,
        "sha256": fn.sha256,
        "files": list(fn.files),
        "detected_by": list(fn.detected_by),
        "size_by_tool": _plain(fn.size_by_tool),
        "textOffset": fn.textOffset,
        "blocker": fn.blocker,
        "blockerDelta": fn.blockerDelta,
        "size_reason": fn.size_reason,
        "similarity": _plain(fn.similarity),
        "updated_by": fn.updated_by,
        "updated_at": fn.updated_at,
    }


def global_json(gl: Global) -> dict[str, Any]:
    """The global-detail object, one key per ``globals`` column.

    ``isGlobal`` is the discriminator the batch and detail responses have always
    carried, so a client can tell a data symbol from a function without a second
    request.
    """
    return {
        "va": gl.va,
        "name": gl.name,
        "decl": gl.decl,
        "files": list(gl.files),
        "module": gl.module,
        "size": gl.size,
        "isGlobal": 1,
        "status": gl.status,
    }


def _name_match[NamedRow: (Function, Global)](
    index: NameIndex[NamedRow], value: str
) -> NamedRow | None:
    """The first row whose ``name`` equals *value*, else the first folded match.

    One definition for both arrays, so a function and a global cannot resolve a
    name two different ways.

    Byte equality first, then the folded comparison, which is the order the SQL
    lookup used: the exact spelling resolves without paying the fold, and only a
    miss falls through to the NFC + case fold that makes the NFD spelling a user
    pastes open the row the search matched.  Both arms are dict lookups into
    :func:`_name_index`; walking the rows instead folded every name on the
    target on a miss, which a 404 paid in full on both arrays.
    """
    found = index.exact.get(value)
    if found is not None:
        return found
    return index.folded.get(fold_text(value))


#: The two maps a name lookup reads, built once per snapshot: the exact
#: spelling, and the folded one.  A repeated name keeps the FIRST row, which is
#: what the linear scan this replaced returned.
class NameIndex[NamedRow: (Function, Global)](NamedTuple):
    exact: Mapping[str, NamedRow]
    #: Keyed by :func:`fold_text` of the name, which is ``None`` only for an
    #: absent name; a NULL key can never be looked up (the query value is a
    #: ``str`` that folds to a ``str``), so it is unreachable rather than a
    #: silently-wrong answer.
    folded: Mapping[str | None, NamedRow | None]


def _name_index[NamedRow: (Function, Global)](
    snap: CoverageSnapshot, kind: str, rows: Sequence[NamedRow]
) -> NameIndex[NamedRow]:
    """The :class:`NameIndex` over *rows*, memoized per snapshot and kind.

    Bounded by :data:`_SNAPSHOT_INDEX_MAX` and dropped with the other
    snapshot indices, so a name lookup cannot pin a snapshot of its own.
    """

    def build() -> NameIndex[NamedRow]:
        exact: dict[str, NamedRow] = {}
        folded: dict[str | None, NamedRow | None] = {}
        for row in rows:
            exact.setdefault(row.name, row)
            folded.setdefault(fold_text(row.name), row)
        return NameIndex(exact, folded)

    return _snapshot_index(snap, kind, build)


def functions_by_name(snap: CoverageSnapshot) -> NameIndex[Function]:
    """``functions`` indexed by name, one index per snapshot."""
    return _name_index(snap, "functions_by_name", snap.functions)


def globals_by_name(snap: CoverageSnapshot) -> NameIndex[Global]:
    """``globals`` indexed by name, one index per snapshot."""
    return _name_index(snap, "globals_by_name", snap.globals)


def lookup_function(snap: CoverageSnapshot, value: str) -> Function | None:
    """The function *value* names, as a VA first and then as a name.

    ONE resolution order for the /functions/<va> route and both Potato Mode
    detail panels: callers name a function by VA ("0x10001000") or, for legacy
    cells, by the symbol outright.  A VA-shaped entry that matches no row still
    falls through to the name lookup, so the route and the panels cannot
    disagree about what a value names.

    The VA arm is an index hit on the snapshot; the name arms are index hits
    too (:func:`functions_by_name`), so neither costs a walk of the target's
    rows.
    """
    for candidate in parse_va_candidates(value):
        found = snap.functions_by_va.get(candidate)
        if found is not None:
            return found
    return _name_match(functions_by_name(snap), value)


def lookup_global(snap: CoverageSnapshot, value: str) -> Global | None:
    """:func:`lookup_function` over the globals array."""
    index = globals_by_va(snap)
    for candidate in parse_va_candidates(value):
        found = index.get(candidate)
        if found is not None:
            return found
    return _name_match(globals_by_name(snap), value)


#: The by-VA indices a snapshot does not carry, keyed by its identity.
#: rebrew's snapshot has ``functions_by_va`` and nothing for globals or
#: ``verify_results``, and the batch endpoint and the cell-detail panel both
#: walk those arrays per request: a 500-VA batch against 50k globals was
#: 25M comparisons, and one cell click was a full scan of the verify rows.
#: Entries hold the snapshot they were built from, which is what makes
#: ``id()`` a sound key: the object is pinned, so its id cannot be reused by
#: a later one while the entry lives.  The bound is therefore a memory bound
#: as well as a cache bound — 4 entries is at most two retained snapshots,
#: the same order as Potato's per-snapshot grid memo.  A snapshot is
#: ``slots=True`` and its fields are mapping proxies, so a ``WeakKeyDictionary``
#: cannot key it and a field-derived hash cannot be computed; holding the
#: object is the only sound alternative.
_SNAPSHOT_INDEX_LOCK = threading.Lock()
#: The derived value of any kind, so one bounded store holds the by-VA
#: mappings and the name indices alike; :func:`_snapshot_index` casts it back
#: to the type its builder produced.
_SNAPSHOT_INDEX: dict[tuple[int, str], tuple[CoverageSnapshot, Any]] = {}
_SNAPSHOT_INDEX_MAX = 4


def _snapshot_index[IndexT](
    snap: CoverageSnapshot, kind: str, build: Callable[[], IndexT]
) -> IndexT:
    """The memo for *kind* over *snap*, building it on the first call."""
    key = (id(snap), kind)
    with _SNAPSHOT_INDEX_LOCK:
        hit = _SNAPSHOT_INDEX.get(key)
    if hit is not None:
        return cast(IndexT, hit[1])
    index = build()
    with _SNAPSHOT_INDEX_LOCK:
        _evict_oldest(_SNAPSHOT_INDEX, _SNAPSHOT_INDEX_MAX)
        _SNAPSHOT_INDEX[key] = (snap, index)
    return index


def globals_by_va(snap: CoverageSnapshot) -> Mapping[int, Global]:
    """``globals`` indexed by VA, one entry per snapshot.

    A repeated VA keeps the FIRST row, which is what the linear scan this
    replaced returned.
    """

    def build() -> dict[int, Any]:
        index: dict[int, Any] = {}
        for gl in snap.globals:
            index.setdefault(gl.va, gl)
        return index

    return _snapshot_index(snap, "globals_by_va", build)


def verify_by_va(snap: CoverageSnapshot) -> Mapping[int, Mapping[str, Any]]:
    """``verify_results`` indexed by VA, one entry per snapshot.

    A row whose ``va`` is not an int cannot be a match for an int VA, so it is
    skipped here exactly as the per-request builds did.
    """

    def build() -> dict[int, Any]:
        return {row["va"]: row for row in snap.verify_results if isinstance(row.get("va"), int)}

    return _snapshot_index(snap, "verify_by_va", build)


def verify_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """Shape a ``verify_results`` row as the ``last_verify`` object.

    ONE definition shared by the single-VA and batch endpoints so the two
    response shapes cannot drift apart.  ``similarity`` is passed through as the
    0-1 fraction the writer stores, like ``functions.similarity``; the percent
    scaling belongs to the renderers.  Every key is always present and null when
    the document does not carry the value, which is the shape Potato Mode's
    verify rows read (``fields["reg_delta"] is not None``) and the shape the
    SPA's ``== null`` tests are written against. An empty string is how a
    verify record leaves a figure unmeasured, so it is null here too: served
    as ``""`` it passed both ``is not None`` tests and printed a blank row.
    """

    def figure(key: str) -> Any:
        value = row.get(key)
        return None if value == "" else _plain(value)

    return {
        "verified_at": row.get("verified_at") or None,
        "byte_delta": figure("byte_delta"),
        "diff_lines": figure("diff_lines"),
        "similarity": figure("similarity"),
        "reg_delta": figure("reg_delta"),
        "effective_match": bool(row["effective_match"])
        if row.get("effective_match") is not None
        else None,
    }


def load_metadata(snap: CoverageSnapshot) -> dict[str, Any]:
    """The metadata the /data payload carries, rebuilt from the snapshot.

    ``build_db`` wrote four metadata rows per target — ``db_version``, the
    derived ``function_stats``, the catalog's ``summary`` blob and ``paths`` —
    and the TOML writer stores the facts instead, so two of the four are
    recomputed here (:func:`_summary`, :func:`coverage_version`) and the other
    two (``function_stats``, which rebrew derives at load, and ``paths``) are
    read straight off the document.
    """
    return {
        "db_version": coverage_version(snap),
        "function_stats": _plain(snap.function_stats),
        "summary": _summary(snap),
        "paths": _plain(snap.paths),
    }


# ── Shared caches ──────────────────────────────────────────────────


def _evict_oldest(cache: dict[Any, Any], max_size: int) -> None:
    """Drop oldest entries (dict insertion order) until *cache* holds < max_size.

    ONE definition of the bounded-cache arithmetic behind every per-snapshot
    memo in the package (/data payloads, /stats, the function list totals, and
    Potato's cells and per-section stats).  They are keyed by a snapshot that
    changes on every rebuild, so a long-running server would otherwise
    accumulate an entry per snapshot forever.
    Caller holds the cache's own lock.
    """
    if len(cache) >= max_size:
        for old_key in list(cache)[: len(cache) - max_size + 1]:
            cache.pop(old_key, None)


def _format_hex_dump(raw_bytes: bytes, base_offset: int, max_bytes: int | None = 256) -> str:
    """Format bytes as the canonical 16-bytes-per-line hex dump.

    ONE definition shared by the /bytes endpoint's ``hex`` payload and
    Potato Mode's Original Bytes block (the two inline copies had already
    drifted: a single 48-char hex column vs 8+8 byte columns).  Layout:
    8-hex-digit offset, hex bytes in two 8-byte columns, ASCII gutter —
    the same layout as the dashboard's client-side dump, which upper-cases the
    hex, so the two renderings of one slice differ in case.  *max_bytes*
    caps the dump and appends a ``... (N more bytes)`` tail; ``None`` dumps
    everything.
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


# ── Response helpers ───────────────────────────────────────────────

# The two cache policies for DB-derived responses.  NO_STORE: payloads the
# client must never reuse — /api/health, /api/events and the batch POST, none
# of which carries a validator — and the one ETag-less fallback, an
# /api/targets list served from an unreadable DB.  REVALIDATE: the
# ETag-bearing payloads (the SPA shell and the packaged assets, /api/targets,
# /stats, /data, the function list and detail routes, /asm, /bytes, /potato)
# that a browser may keep but must re-verify with If-None-Match every time.
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
    """Return compressed JSON 200.

    A 2xx that is not 200 is a different status, not an error body, so it
    arrives as an :class:`HTTPResponse` from the caller: the one the regen
    route needs is "your retry names the run happening right now" (202).
    """
    body = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
    return _compressed(body, "application/json", **headers)


def _json_accepted(data: dict[str, Any], **headers: str) -> HTTPResponse:
    """Return compressed JSON 202: accepted, the work is not done yet."""
    body = json.dumps(data).encode("utf-8")
    accept_enc = _header("Accept-Encoding", "")
    body, encoding = compress_payload(body, accept_enc)
    resp = HTTPResponse(status=202)
    _finalized(resp, body, "application/json", encoding, **headers)
    resp.body = body
    return resp


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


def _json_err(status: int, data: dict[str, Any], **headers: str) -> HTTPResponse:
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
#
# It is also a page of this product, not a generic error screen: it is the
# first thing a locked-out operator sees. The colours are the dark values of the
# relumea tokens the SPA reads (web/app/system/tokens.css: bg, surface, border,
# text, text-muted), the faces are the ones Potato Mode names (Archivo for
# prose, JetBrains Mono for the flag and the URL), and the sizes are the rungs
# the rest of the product uses (<font size="5|3|1">).
# TestUnauthorizedPageMatchesTheTokenLayer holds the values against that file.
_UNAUTHORIZED_HTML = (
    b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
    b'<meta name="viewport" content="width=device-width, initial-scale=1">'
    b"<title>recoverage \xc2\xb7 access token required</title></head>"
    b'<body bgcolor="#0b0b0c" text="#ededef">'
    # role="presentation" for the same reason every layout table in potato.py
    # carries it: a one-cell centring table is announced as a table with no
    # headers before the message it exists to centre (WCAG 1.3.1).
    b'<table role="presentation" width="100%" height="90%" border="0">'
    b'<tr><td align="center" valign="middle">'
    b'<font face="Archivo, Arial, Helvetica Neue, Liberation Sans, sans-serif">'
    b'<h1><font size="5" color="#ededef"><b>recoverage</b></font></h1>'
    b'<font size="3" color="#a3a3ab">Access token required</font>'
    b"<p>This dashboard was started with"
    b' <font face="JetBrains Mono, Consolas, Liberation Mono, Courier New, monospace"'
    b' size="3">--token</font>. Open it with the token appended to the URL:</p>'
    b'<table border="1" bordercolor="#28282e" cellpadding="4" cellspacing="0"'
    b' align="center" bgcolor="#131316"><tr><td>'
    b'<font face="JetBrains Mono, Consolas, Liberation Mono, Courier New, monospace"'
    b' size="3" color="#ededef"><tt>?token=YOUR_TOKEN</tt></font>'
    b"</td></tr></table>"
    b'<p><font color="#a3a3ab" size="1">The person who started the server has the token.'
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
    #
    # Secure rides along only where the request arrived over TLS
    # (:func:`request_is_https`), because the cookie without it rides along
    # with every plaintext request to the same host: a reader who followed an
    # http:// link to a host that also answers https:// had their token handed
    # to whoever was on that connection.  The bundled listener speaks no TLS
    # and is reached over http on a loopback bind, where the flag would only
    # stop the cookie from ever being stored, so it is a property of the
    # request, not a fixed spelling.
    secure = "; Secure" if request_is_https() else ""
    try:
        response.set_header(
            "Set-Cookie",
            f"{AUTH_COOKIE_NAME}={_AUTH_TOKEN}; Path=/; HttpOnly; SameSite=Strict{secure}",
        )
    except Exception:
        _log.warning(
            "Set-Cookie rejected for %s %s — the share link will 401 on every "
            "follow-on request (the page itself still renders)",
            _log_safe(request.method),
            _log_safe(request.path),
            exc_info=True,
        )


# ── Request instrumentation ─────────────────────────────────────────────────────────────
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
#: The minted ids come from a per-process counter rather than OS entropy, so a
#: replay of the same request sequence produces the same ids and two runs can be
#: diffed line for line.  The id is a correlation label, not a credential:
#: nothing is authorized by it, and every value it can carry from outside comes
#: from the caller's own ``X-Request-ID`` header.
_REQUEST_ID_LOCK = threading.Lock()
_REQUEST_ID_SEQ = itertools.count(1)


def _mint_request_id() -> str:
    """A fresh correlation id: a zero-padded counter, 12 hex digits wide."""
    with _REQUEST_ID_LOCK:
        seq = next(_REQUEST_ID_SEQ)
    return f"{seq:012x}"


def _new_request_id() -> str:
    """Reuse the caller's correlation id, or mint one."""
    provided = _header(_REQUEST_ID_HEADER, "")
    if provided:
        # Untrusted: capped and control-char escaped so a crafted header
        # cannot forge log lines (same rule as _log_safe) or bloat the log.
        return _log_safe(provided)[:_REQUEST_ID_MAX_LEN]
    return _mint_request_id()


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
    metrics.REQUESTS.finish(route, status, duration_ms, timed=timed, rule_matched=rule is not None)
    _REQUEST_TLS.counted = (route, status)
    if timed and duration_ms >= metrics.SLOW_REQUEST_MS:
        level, template = logging.WARNING, "Slow request: %s %s -> %d in %.0fms"
    # `_log_safe` is two `str.translate` calls over the control-character
    # table, and the arguments are evaluated before logging can discard them:
    # every request paid it whether or not DEBUG was enabled.  The guard is the
    # same check logging does internally, hoisted so the escaping is skipped
    # with it.
    elif _log.isEnabledFor(logging.DEBUG):
        level, template = logging.DEBUG, "%s %s -> %d in %.0fms"
    else:
        return
    _log.log(
        level,
        template,
        _log_safe(request.method),
        _log_safe(request.path),
        status,
        duration_ms,
        extra=request_log_fields(status, duration_ms, route=route),
    )


def _reclassify_request(status: int) -> None:
    """Correct the counted status of a request that failed after the hook.

    ``after_request`` runs before bottle hands an escaped exception to the
    error handler, so it counted the request as the 200 it was still
    carrying.  Without this, every 500 and 503 (a corrupt or rebuilding
    unreadable coverage, the failure the operator most needs to see) would land in
    the 2xx bucket and the error rate would read zero.
    """
    counted = getattr(_REQUEST_TLS, "counted", None)
    if counted is not None:
        metrics.REQUESTS.reclassify(counted[0], counted[1], status)
        _REQUEST_TLS.counted = None


# Failed-token-attempt throttle: without it, a network-reachable server
# (--allow-remote + --token) accepts unlimited online guesses at the bearer
# token.  PER PEER, not one window for the process: a single global window
# handed two unrelated parties the same lever in both directions.  Ten failures
# from anyone locked EVERYONE out for the rest of the window, so an
# unauthenticated peer could deny the operator the dashboard indefinitely by
# never stopping, and any one successful request emptied the window, so the
# operator's own page loads handed a guesser on another host an unbounded supply
# of attempts.  Keyed on the socket peer, which a client cannot forge.
#
# A success clears its OWN peer's window and no other, so the operator who
# mistypes and retypes is forgiven without the guesser next to them being reset.
_AUTH_FAIL_WINDOW_SECONDS = 60.0
_AUTH_FAIL_MAX = 10
#: How many peers the map holds.  It is bounded because the key is a peer
#: address: a server accepting connections from a wide range cannot grow it
#: without limit, and each entry is a deque bounded by :data:`_AUTH_FAIL_MAX`
#: anyway.  Far above the number of machines on the LAN this is deployed on;
#: over it, a window whose failures have all aged out goes first, then the
#: oldest (see :func:`_evict_spent_peer_window`).
_AUTH_FAIL_MAX_PEERS = 1024
#: The throttle key for a request that carries no REMOTE_ADDR.  ONE bucket for
#: every such client, so an environ that never names a peer degrades to the one
#: shared window this used to be, rather than to no throttle at all (a fresh key
#: per request would hand every guesser a full window of its own).
_UNKNOWN_PEER = ""
_auth_failures: dict[str, deque[float]] = {}
_AUTH_FAILURES_LOCK = threading.Lock()


def _evict_spent_peer_window(now: float) -> None:
    """Make room for one more peer window, dropping a spent one if any exists.

    Caller holds :data:`_AUTH_FAILURES_LOCK`, and the map is already at
    :data:`_AUTH_FAIL_MAX_PEERS`.

    Evicting oldest-first regardless of the window's age throws away the
    throttle of a peer still inside it, and the address that arrives next
    resets a guesser that has already spent its ten attempts: an attacker with
    addresses to spare buys unlimited guesses out of a cap that reads as a
    limit on them.  Only a window whose NEWEST failure has aged out holds no
    state, so those go first, and the oldest still goes when every window is
    live, because the cap is a memory bound and keeping it costs one slow
    guess rather than an unbounded map.
    """
    for key, window in _auth_failures.items():
        if not window or now - window[-1] > _AUTH_FAIL_WINDOW_SECONDS:
            del _auth_failures[key]
            return
    _evict_oldest(_auth_failures, _AUTH_FAIL_MAX_PEERS)


def _auth_throttle(peer: str, now: float, reserve_slot: bool) -> bool:
    """Prune expired failures, enforce the window cap, optionally take a slot.

    The prune, the cap check, and *reserve_slot*'s append must share ONE
    critical section: as separate steps, a burst of concurrent bad-token
    requests from one peer all observe ``len < max`` before any of them records,
    and every one of them slips past the cap (check-then-act TOCTOU).  The slot
    is therefore taken BEFORE the token is verified; a verified request releases
    its peer's window again via :func:`_clear_auth_failures`.

    Returns True when that peer's window is full — the caller answers 429.
    """
    with _AUTH_FAILURES_LOCK:
        window = _auth_failures.get(peer)
        if window is None:
            window = deque()
            if len(_auth_failures) >= _AUTH_FAIL_MAX_PEERS:
                _evict_spent_peer_window(now)
            _auth_failures[peer] = window
        while window and now - window[0] > _AUTH_FAIL_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= _AUTH_FAIL_MAX:
            return True
        if reserve_slot:
            window.append(now)
        return False


def auth_locked_peers() -> int:
    """How many peers are answering 429 right now, on the clock.

    A GAUGE, and the only reading of the throttle an operator can watch: the
    lifetime counters (:data:`metrics.AUTH`) say a guess happened, this says one
    is still in progress, which is the state a health probe should answer
    ``degraded`` for.  Expired windows are dropped first, on the same window and
    the same clock the gate enforces, so a lockout that ended between two probes
    does not keep the dashboard degraded for the rest of the process.
    """
    now = clock.monotonic()
    with _AUTH_FAILURES_LOCK:
        for key, window in list(_auth_failures.items()):
            if not window or now - window[-1] > _AUTH_FAIL_WINDOW_SECONDS:
                del _auth_failures[key]
        return sum(1 for window in _auth_failures.values() if len(window) >= _AUTH_FAIL_MAX)


def _clear_auth_failures(peer: str) -> None:
    """Forget *peer*'s failures, and only that peer's.

    Called on a verified request, so a mistyped-then-retyped token does not
    count twice against the person who owns the token.  It is keyed by peer
    precisely so it is not a reset button for anyone else: emptying the one
    shared window on every success is what let a guesser riding alongside the
    operator's own traffic guess without a bound.
    """
    with _AUTH_FAILURES_LOCK:
        _auth_failures.pop(peer, None)


#: The two headers a browser sends on a CORS preflight and on no other
#: request.  ``Origin`` names the page asking, ``Access-Control-Request-Method``
#: the verb it wants to use next; the actual request follows with its
#: credentials, this handshake carries none.
_PREFLIGHT_ORIGIN_HEADER = "Origin"
_PREFLIGHT_METHOD_HEADER = "Access-Control-Request-Method"


def _is_cors_preflight() -> bool:
    """Whether this request is a browser CORS preflight.

    Both headers are required, so a bare ``OPTIONS`` (which carries no
    ``Origin``) is not one and stays behind the token gate.  The preflight
    itself reaches no handler that reads coverage: it answers from
    :func:`_cors_preflight`, which returns an empty body for every path.
    """
    return request.method == "OPTIONS" and bool(
        _header(_PREFLIGHT_ORIGIN_HEADER, "") and _header(_PREFLIGHT_METHOD_HEADER, "")
    )


def _require_auth() -> None:
    """Enforce the configured bearer token, or pass when none is set.

    Credentials, in order: ``Authorization: Bearer``, ``?token=``, the
    ``recoverage_token`` cookie.  A page request (Accept: text/html, non-/api
    path) gets the 401 HTML page; every other client gets the JSON 401
    contract, or the 429 once the fail window is full.

    A CORS preflight is exempt (:func:`_is_cors_preflight`): a browser sends
    no credential on it, so a token-gated server answered 401 to every
    preflight and the ``--cors`` + ``--token`` combination the API documents
    could never send a request at all.  Only the handshake is exempt; the
    request it precedes is authenticated by this same gate.

    The throttle window is the requesting peer's alone (see
    :func:`_auth_throttle`), so one client exhausting its guesses cannot
    answer 429 to the operator, and one operator's traffic cannot reset
    another client's count.
    """
    if not _AUTH_TOKEN or _is_cors_preflight():
        return

    # The peer key for the throttle. REMOTE_ADDR is the socket peer here (the
    # same value the regen gate trusts), and the fallback keeps a harness that
    # omits it in one shared window rather than minting a fresh one per request.
    peer = request.environ.get("REMOTE_ADDR") or _UNKNOWN_PEER

    provided = _header("Authorization", "")
    if provided.startswith("Bearer "):
        provided = provided[len("Bearer ") :]
    else:
        provided = query_param("token")
        if not provided:
            provided = request.get_cookie(AUTH_COOKIE_NAME, default="")
    if _auth_token_matches(provided):
        _clear_auth_failures(peer)
        return

    now = clock.monotonic()
    if _auth_throttle(peer, now, reserve_slot=True):
        # Counted separately from a failed attempt: one is a typo answered
        # 401, the other is a peer the gate has stopped reading.  Nothing else
        # counts the 429 arm, because the per-request line is DEBUG below the
        # slow-request threshold, so without this the attempts past a full
        # window left no trace at all.
        metrics.AUTH.note_throttled()
        # `retry_after` in the body as well as the header: the two 429s the
        # regen route sends and the 503 the SSE cap sends both put the wait in
        # the envelope, so a client reading the documented JSON contract gets
        # the same field whichever limit it hit.  One value in both places.
        raise _json_err(
            429,
            {
                "error": "rate limited",
                "detail": "too many failed token attempts; retry later",
                "retry_after": int(_AUTH_FAIL_WINDOW_SECONDS),
            },
            Retry_After=str(int(_AUTH_FAIL_WINDOW_SECONDS)),
        )

    # Audit trail for brute-force visibility: on a network-reachable server
    # (--allow-remote --token) the throttle bounds guessing, but a silent 401
    # gives the operator no way to see the attempt happened.  The provided
    # value is never logged (it may be someone's near-miss guess at a
    # secret); REMOTE_ADDR comes from the socket peer and is escaped, because
    # behind a proxy that folds a header into it, it is as hostile as any
    # other untrusted value and a %0A in it would forge the line below.
    metrics.AUTH.note_failure()
    logged_peer = peer_label()
    _log.warning(
        "Rejected %s auth token from %s",
        "missing" if not provided else "invalid",
        logged_peer,
        extra=request_log_fields(401, peer=logged_peer),
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


def _reject_broken_project_config() -> None:
    """Refuse a request when the project file is present but unreadable.

    Registered after the auth hook, so a missing token still answers 401.
    ``_db_path`` raises ``WorkspaceConfigError`` for a present file that is
    not UTF-8 TOML; serving anyway would read ``db/``, which may be a
    different project's coverage than the one the file named. ``RECOVERAGE_DB``
    is applied first, so an explicit coverage directory still serves.
    """
    try:
        _db_path()
    except WorkspaceConfigError as exc:
        _log.warning("recoverage: %s", exc)
        # "error" is the human message and every other 503 spells it the same
        # way; the machine-readable key is carried by the status mapping.
        raise _json_err(
            503,
            {
                "error": "Database unavailable",
                "detail": f"{CONFIG_NAME} cannot be read; fix the file or set RECOVERAGE_DB",
            },
        ) from None


app.add_hook("before_request", _reject_broken_project_config)


def _db_unavailable_err(exc: Exception) -> HTTPResponse:
    """JSON 503 for unreadable coverage, logged so the failure is visible.

    ONE tail for every coverage-read failure path (the shared target snapshot
    and the unexpected-error handler): without the log line a missing or
    malformed document is invisible in the server log — the 503 only reaches
    the one client that happened to make the request.  The log line carries the
    full cause and the absolute path; the body carries the exception class and
    the rebuild hint and nothing else, because every read endpoint is
    unauthenticated unless the operator passed --token, and --allow-remote puts
    it on a network.  Potato Mode's 503 page carries the same hint.
    """
    _log.warning(
        "Coverage unavailable serving %s %s: %s: %s",
        _log_safe(request.method),
        _log_safe(request.path),
        type(exc).__name__,
        # The cause comes from a document on disk, which is as untrusted as a
        # request path: a malformed file whose error text carries a newline
        # would otherwise split this one line into two, and the split is
        # exactly what an operator is reading to find the broken document.
        _log_safe(str(exc)),
        extra=request_log_fields(503),
    )
    return _json_err(
        503,
        {
            "error": "Database unavailable",
            "detail": f"{type(exc).__name__} — "
            "run 'rebrew build-db' to create or rebuild it; "
            "the server log has the full cause",
        },
    )


@app.error(500)
def _handle_unexpected_error(error: Any) -> HTTPResponse:
    """Keep every surface's error contract when a handler raises unexpectedly.

    Snapshot loading already returns 503 JSON, but a document that turns out to
    be unreadable while a handler walks it (a file replaced between the stat and
    the read) raised inside the handler and surfaced as Bottle's HTML 500.
    Every :class:`CoverageTomlError` becomes a 503 JSON response instead.

    Non-coverage exceptions are logged here with their request context: bottle
    only dumps the raw traceback to wsgi.errors (and ``serve`` runs wsgiref with
    quiet=True), so without this the failing endpoint is hard to identify from
    the log alone.  /api/* requests get the standard JSON 500 contract — the
    SPA's fetch() handlers and API consumers parse JSON, not Bottle's HTML
    error page — while UI routes keep Bottle's HTML error page.
    """
    exc = getattr(error, "exception", None)
    if isinstance(exc, CoverageTomlError):
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
        extra=request_log_fields(500),
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
            logged_peer = peer_label()
            _log.warning(
                "Rejected request with unexpected Host header %r from %s",
                host,
                logged_peer,
                extra=request_log_fields(
                    400,
                    host=_log_safe(host),
                    peer=logged_peer,
                ),
            )
            raise _json_err(
                400,
                {
                    "error": "Bad Request",
                    "detail": f"unexpected Host header {host!r}",
                },
            )


# Content-Security-Policy for the dashboard.  The SPA inlines its built bundle
# into the HTML shell and uses inline styles, so 'unsafe-inline' is required
# for scripts/styles; everything else is same-origin (the bundle and the assets,
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

#: The two route prefixes whose responses are files out of the PROJECT tree
#: rather than the dashboard's own documents (see ``recoverage.ui.serve_repo_file``).
_REPO_FILE_PREFIXES: tuple[str, ...] = ("/src/", "/original/")

#: Policy for a served project file.  It exists because those files carry a
#: content type guessed from their own suffix, so an ``.html`` or an ``.svg``
#: anywhere under ``src/`` or ``original/`` is rendered AS a document by the
#: browser, at this origin, under the policy above — and that policy allows
#: inline script.  A file the project tree picked up (a vendored page, a
#: generated report) would then run with the dashboard's own authority: it can
#: read every ``/api/*`` response, and when ``--token`` is on, the auth cookie
#: rides along on those requests even though the script cannot read it.
#:
#: ``sandbox`` puts the document in an opaque origin with scripting, forms and
#: plugins off, and ``default-src 'none'`` denies everything it could still ask
#: for.  The files stay readable — the code panes fetch them, and a reader who
#: opens one sees the text, which is what a source file under a coverage
#: dashboard is for.
_INERT_CSP = "default-src 'none'; sandbox; base-uri 'none'; form-action 'none'"


def csp_for_path(path: str) -> str:
    """The Content-Security-Policy *path* is answered under.

    ONE place, so the hook cannot answer a project file with the dashboard's own
    policy while the constant beside it says otherwise.
    """
    if path.startswith(_REPO_FILE_PREFIXES):
        return _INERT_CSP
    return _CSP


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
    response.set_header("Content-Security-Policy", csp_for_path(request.path))
    # Tokens travel in URLs (?token= share links); never let them leak to a
    # third party via Referer if the dashboard ever navigates off-host.
    response.set_header("Referrer-Policy", "no-referrer")
    if request_is_https():
        # Only where the request arrived over TLS: an HSTS header delivered
        # over http is discarded by every browser, so sending it
        # unconditionally buys nothing, and a browser that honours it is
        # asserting a fact about the connection this response came in on.
        response.set_header("Strict-Transport-Security", f"max-age={HSTS_MAX_AGE_SECONDS}")
    origin = _header("Origin", "")
    if CORS_ENABLED and origin and _normalize_origin(origin) in CORS_ALLOWED_ORIGINS:
        response.set_header("Access-Control-Allow-Origin", origin)
        _merge_vary("Origin")
        response.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        # The credential/validator headers the API itself documents.  Without
        # Authorization in this list a --cors frontend cannot use the
        # --token auth the README advertises (the preflight fails, so the
        # request is never sent), without If-None-Match it cannot do the
        # conditional GET that every ETag-bearing endpoint (/data, /asm,
        # /bytes, /potato) is built around, and without Idempotency-Key the
        # retry POST /api/regen documents never reaches the handler that
        # reads it.
        response.set_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, If-None-Match, Idempotency-Key",
        )
        # ETag and Retry-After are response headers a cross-origin client
        # cannot read unless they are exposed; without this the validator the
        # server sends is invisible to the client that needs it, and so is the
        # `Idempotent-Replay: true` that is the whole answer to a replayed
        # Idempotency-Key.
        response.set_header("Access-Control-Expose-Headers", "ETag, Retry-After, Idempotent-Replay")
        response.set_header("Access-Control-Allow-Credentials", "true")
    elif origin:
        # Ensure caches key on Origin even when not allowed.
        _merge_vary("Origin")


@app.route("<path:path>", method="OPTIONS")
def _cors_preflight(path: str) -> str:
    """Handle CORS preflight requests. Headers are set by the after_request hook."""
    return ""
