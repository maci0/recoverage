"""Shared test fixtures and helpers for recoverage tests."""

from __future__ import annotations

import os
from io import BytesIO
from pathlib import Path
from wsgiref.util import setup_testing_defaults

import pytest
from coverage_fixture import TARGET, build_synthetic_coverage

from recoverage.api import _clear_derived_caches
from recoverage.webapp import app


@pytest.fixture(autouse=True)
def _clean_recovery_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop every RECOVERAGE_* variable before each test.

    `serve` reads its defaults from the environment, so an ambient
    RECOVERAGE_DB (or a leftover token) would silently redirect a test's
    database path.  The suite must depend on the code, not the shell it runs
    from.
    """
    for name in [n for n in os.environ if n.startswith("RECOVERAGE_")]:
        monkeypatch.delenv(name)


@pytest.fixture(autouse=True)
def _clean_startup_policy() -> None:
    """Restore the startup request policy to its module defaults before each test.

    `cli.serve` calls `server.configure_security` once per run, so a test that
    drives `serve` (the CLI suite does) leaves the process-wide CORS flag, the
    origin allowlist, the bearer token and the Host allowlist installed for the
    rest of the session.  The leak is silent in file order and fatal in any
    other: with a loopback `ALLOWED_HOSTS` left over, the regen origin
    validation's `Host: box:80` case answers 400 where it means to answer 202.
    `configure_security` with no arguments IS the default state, so one call
    resets all four through the module's own entry point.
    """
    from recoverage import server

    server.configure_security()


@pytest.fixture(autouse=True)
def _clean_regen_gate() -> None:
    """Reset the regen gate's process globals before each test.

    `api._regen_last_attempt` is stamped by every accepted POST, and the two
    idempotency ledgers outlive the request that filed them, so a test that
    drives `/api/regen` leaves a live cooldown timestamp and whatever keys it
    used behind it for every test that runs next.  The damage is invisible in
    file order and fatal in any other: the accepted-path assertions ask for a
    200 and a surviving timestamp answers 429, and a surviving completed key
    replays a stubbed run as a real one.  A few classes reset what they touch
    in their own fixtures; the rest of the file did not, and the suite only
    stayed green because the next regen test happened to reset the same
    global before it posted.
    """
    from recoverage import api

    api._regen_last_attempt = None
    api._REGEN_COMPLETED_KEYS.clear()
    api._REGEN_ACTIVE_KEYS.clear()


@pytest.fixture(autouse=True)
def _clean_derived_caches() -> None:
    """Drop every coverage.db-derived cache before each test.

    Those caches are process globals keyed on nothing DB-specific, so a test
    that re-points `_db_path` at its own fixture database (the Potato Mode
    NULL-va cases do) leaves its rows behind for the next test: the resolved
    target list memoized the fixture's single target, and the next test's
    `/api/targets/<id>/...` came back 404 against a target the memo no longer
    listed.  The suite only runs green when file order happens to hide it.
    """
    _clear_derived_caches()


# ── Synthetic coverage documents ────────────────────────────────────────────────────────
# The document-gated tests below read the directory `_db_path()` resolves, and
# CI has no real rebrew project — so they silently never ran.  Write a minimal
# set of coverage documents matching rebrew's schema so those tests execute
# everywhere.  The files are gitignored (see .gitignore).  The documents
# themselves and the builder live in ``coverage_fixture``, which
# ``tools/_serve_harness`` imports for the same set without this module's
# pytest wiring or its import-time write.

_DB_DIR = Path.cwd() / "db"
_DB_FILE = _DB_DIR / f"coverage-{TARGET}.toml"


# Build the synthetic documents only when we are NOT inside a real rebrew
# workspace: a real project has a rebrew-project.toml and its own coverage,
# which the document-gated tests must never read (assertions would depend on
# unrelated project data, and building a synthetic set here could clobber the
# real one).
#
# Everywhere else the files are rebuilt on every session, not only when they
# are missing: db/coverage-*.toml is gitignored, so a copy left by an older
# checkout survives a rebase and a document-gated test then asserts against
# data this tree no longer produces while CI, which never has the file, stays
# green.
_IN_REAL_PROJECT = (Path.cwd() / "rebrew-project.toml").exists()

if not _IN_REAL_PROJECT:
    build_synthetic_coverage(_DB_DIR)

HAS_DB = _DB_FILE.exists() and not _IN_REAL_PROJECT

#: The peer :data:`wsgi_request` addresses by default, named because the auth
#: failure window is keyed on it (``server._auth_throttle``): a test that
#: reserves or clears that window has to say which peer it means, or it is
#: clearing a bucket no request will ever land in.
WSGI_PEER = "127.0.0.1"


def wsgi_request(
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    remote_addr: str = WSGI_PEER,
    body: bytes | str = b"",
    wsgi_input: BytesIO | None = None,
    content_length: str | None = "",
    environ_extra: dict[str, str] | None = None,
) -> tuple[str, dict[str, str], bytes]:
    """Issue a WSGI request against the Bottle app and return (status, headers, body).

    *wsgi_input* replaces the ``wsgi.input`` stream (a test that needs to watch
    whether the handler read at all passes its own), and *content_length*
    overrides the ``CONTENT_LENGTH`` entry: None omits it entirely, which is
    what a chunked request looks like to a WSGI app.  *environ_extra* sets
    further WSGI entries verbatim (``wsgi.url_scheme`` for a request that
    reached the app over TLS), which no header spelling can express.
    """
    environ: dict[str, str | BytesIO] = {}
    setup_testing_defaults(environ)
    if environ_extra:
        environ.update(environ_extra)
    url_path, _, query = path.partition("?")
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = url_path
    environ["QUERY_STRING"] = query
    environ["REMOTE_ADDR"] = remote_addr
    if isinstance(body, str):
        body = body.encode("utf-8")
    environ["wsgi.input"] = wsgi_input if wsgi_input is not None else BytesIO(body)
    if content_length is None:
        environ.pop("CONTENT_LENGTH", None)
    else:
        environ["CONTENT_LENGTH"] = content_length or str(len(body))
    if headers:
        for k, v in headers.items():
            # PEP 3333: Content-Type and Content-Length are not HTTP_*
            # headers, they are their own environ entries. Everything else
            # keeps the HTTP_ prefix a real WSGI server assigns.
            key = k.upper().replace("-", "_")
            if key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                environ[key] = v
            else:
                environ[f"HTTP_{key}"] = v

    status_holder: dict[str, str | dict[str, str]] = {"status": "", "headers": {}}

    def _start_response(status: str, response_headers, exc_info=None):
        status_holder["status"] = status
        status_holder["headers"] = dict(response_headers)

    result = app(environ, _start_response)
    # PEP 3333: the server MUST call close() on the returned iterable when
    # provided — that is what closes handles behind responses like
    # static_file's open file object. Skipping it leaks fds until GC.
    try:
        body = b"".join(result)
    finally:
        close = getattr(result, "close", None)
        if close is not None:
            close()
    return str(status_holder["status"]), dict(status_holder["headers"]), body


def wsgi_get(path: str, headers: dict[str, str] | None = None) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", path, headers)


def wsgi_post(
    path: str,
    headers: dict[str, str] | None = None,
    remote_addr: str = "127.0.0.1",
    body: bytes | str = b"",
) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("POST", path, headers, remote_addr=remote_addr, body=body)


def decode_body(body: bytes, headers: dict[str, str]) -> bytes:
    """Decompress response body based on Content-Encoding header."""
    encoding = headers.get("Content-Encoding", "")
    if encoding == "gzip":
        import gzip

        return gzip.decompress(body)
    if encoding == "br":
        import brotli

        return brotli.decompress(body)
    if encoding == "zstd":
        import zstandard as zstd

        return zstd.ZstdDecompressor().decompress(body)
    return body


def get_first_target() -> str:
    """The first target the coverage directory holds."""
    from recoverage.server import db_target_ids

    found = db_target_ids()
    return found[0] if found else ""


def require_target() -> str:
    """The first target, failing the test when the coverage directory holds none.

    Every caller sits behind ``@pytest.mark.skipif(not HAS_DB)``, so an empty
    target list is not an absent fixture: it is a regression in the synthetic
    documents or in the directory resolution. A skip there reported a green
    suite with every assertion behind it unrun.
    """
    target = get_first_target()
    if not target:
        pytest.fail(f"no coverage target resolved from {Path.cwd() / 'db'}")
    return target
