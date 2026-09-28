"""Runtime configuration for ``recoverage serve``, read from ``RECOVERAGE_*``.

The environment supplies the DEFAULTS for the serve flags; a flag passed on
the command line always wins.  Reading them here — one module, one lookup per
setting — keeps deployment settings out of argv, so a systemd unit or a
container spec states them in the environment and nothing has to parse ``ps``
output to learn how the server was started.

Two rules make a misconfigured deployment loud instead of surprising:

* every value is validated (and converted) at startup, before the listener
  binds, so a typo is a clear error rather than a socket or auth failure
  minutes later.  :func:`validate_bind` is the shared floor the CLI's ``--bind``
  calls too, because the flag and the variable are one setting;
* an unrecognised ``RECOVERAGE_*`` name is an error too, because a misspelled
  variable is otherwise indistinguishable from an unset one and silently
  leaves a default in place.

``RECOVERAGE_TOKEN`` is the only secret read here.  It is never echoed in an
error, a log line, or the startup banner, and setting it in the environment
keeps the token out of the process listing that ``--token`` would expose it to.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping, Sequence
from ipaddress import IPv6Address
from pathlib import Path
from typing import Final

#: Prefix every configuration variable carries.  Namespaced so a stray
#: environment variable cannot be mistaken for one of ours.
ENV_PREFIX: Final = "RECOVERAGE_"

#: Every variable this module reads.  Anything else under the prefix is a
#: misspelling and is rejected by :func:`check_unknown_vars`.
#:
#: The two fuzz knobs are listed because they carry the prefix but belong to
#: the test suite (``tests/test_fuzz.py``, the ``fuzz`` make target), not to
#: the server: without them an operator who exported them once to drive a
#: campaign could not run any command until the shell was cleaned up.
KNOWN_VARS: Final[frozenset[str]] = frozenset(
    {
        "RECOVERAGE_ALLOW_REMOTE",
        "RECOVERAGE_BIND",
        "RECOVERAGE_CLIENT_TIMEOUT",
        "RECOVERAGE_CORS",
        "RECOVERAGE_CORS_ORIGIN",
        "RECOVERAGE_DB",
        "RECOVERAGE_FUZZ_ITERATIONS",
        "RECOVERAGE_FUZZ_SEED",
        "RECOVERAGE_LOG_LEVEL",
        "RECOVERAGE_MAX_CONNECTIONS",
        "RECOVERAGE_PORT",
        "RECOVERAGE_TOKEN",
    }
)


# Command-line defaults, the single definition the environment defaults and
# the CLI --help strings share: each of those renders its default from the
# constant rather than restating it, so a change here cannot leave the help
# text advertising a default the server no longer uses.
DEFAULT_PORT: Final = 8001
DEFAULT_BIND: Final = "127.0.0.1"

#: Log level the server runs at.  INFO, not DEBUG: the operational lines a
#: deployment needs (start, regen, database) without the per-request chatter
#: DEBUG adds.
DEFAULT_LOG_LEVEL: Final = logging.INFO

#: Level names accepted from the environment, and the values they resolve to.
#: Read from the stdlib's own table rather than restated here, so the accepted
#: spellings are exactly the ones ``logging.getLevelNamesMapping`` understands.
LOG_LEVELS: Final[Mapping[str, int]] = logging.getLevelNamesMapping()

#: A port of 0 asks the OS for an ephemeral port; both bounds are the ones
#: socket.bind() enforces, checked here so a bad value is a startup error.
MIN_PORT: Final = 0
MAX_PORT: Final = 65535

#: Concurrent client connections the listener admits, and the per-connection
#: socket deadline.  Both are deployment-sized quantities, not properties of
#: the dashboard: the same binary serves one developer on a laptop and a team
#: behind a reverse proxy on a container with a 512 MiB limit, and each of
#: those admits a different number of connections and wants a different stall
#: deadline.  The deadline is a per-socket-operation bound, not a budget for a
#: connection's life (see ``client_timeout``), and its floor is a slow-but-live
#: reader that cannot absorb a large payload inside one operation.
MIN_CLIENT_TIMEOUT_SECONDS: Final = 16
MAX_CLIENT_TIMEOUT_SECONDS: Final = 24 * 60 * 60
DEFAULT_CLIENT_TIMEOUT_SECONDS: Final = 120

#: The default admission cap.  Generous next to what a real client needs (a
#: browser tab holds one, a page loading assets and polling holds a handful,
#: and every open /api/events stream holds one for its whole life) and low
#: enough that a flood of stalled peers is refused rather than spawning a
#: thread per accept until the process cannot make one.
DEFAULT_MAX_CONNECTIONS: Final = 128

#: An upper bound on the admission cap, so a typo reads as a rejection rather
#: than as a server that admits four billion connections and is killed by the
#: first flood.  It bounds nothing real: a thread costs stack and a
#: descriptor, so a cap past this is a typo, not a deployment.
MAX_MAX_CONNECTIONS: Final = 65_536

_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})

#: An integer setting is an ASCII decimal run with an optional sign, optional
#: surrounding whitespace.  ``int()`` alone is not that test: it reads any
#: Unicode decimal digit, so a fullwidth or Arabic-Indic one in a deployment
#: variable resolves to a number instead of reporting the mistake.  ``int()``
#: also accepts ``1_0``, and a run of digits past CPython's conversion limit
#: raises ValueError from the limit rather than from the parse.
_ASCII_INT: Final = re.compile(r"\A[+-]?[0-9]+\Z")


class ConfigError(ValueError):
    """An unset or invalid ``RECOVERAGE_*`` value.

    Carries only the variable name and, for non-secret settings, the value it
    could not use.  The message is printed verbatim to stderr by the CLI, so
    it must never interpolate a secret.
    """


def _raw(name: str) -> str | None:
    """Raw value of *name*, or None when unset.

    An empty string is a SET value, not an unset one: ``RECOVERAGE_TOKEN=``
    turns auth off on purpose, while ``RECOVERAGE_PORT=`` is a mistake the
    caller must hear about rather than have silently defaulted.
    """
    return os.environ.get(name)


def _as_int(name: str, raw: str) -> int:
    """*raw* as an integer, or a ConfigError naming *name*."""
    text = raw.strip()
    if not _ASCII_INT.match(text):
        raise ConfigError(f"{name}: {raw!r} is not an integer")
    try:
        return int(text)
    except ValueError:  # more digits than CPython's int() accepts
        raise ConfigError(f"{name}: {raw!r} is not an integer") from None


def _int_var(name: str, default: int) -> int:
    raw = _raw(name)
    if raw is None:
        return default
    return _as_int(name, raw)


def _str_var(name: str, default: str) -> str:
    raw = _raw(name)
    if raw is None:
        return default
    if not raw:
        raise ConfigError(f"{name}: set but empty (unset it, or give it a value)")
    return raw


def _bool_var(name: str, default: bool) -> bool:
    raw = _raw(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    allowed = ", ".join(sorted(_TRUE_VALUES | _FALSE_VALUES))
    raise ConfigError(f"{name}: {raw!r} is not a boolean (use one of: {allowed})")


def port() -> int:
    """HTTP port to listen on."""
    value = _int_var("RECOVERAGE_PORT", DEFAULT_PORT)
    if not MIN_PORT <= value <= MAX_PORT:
        raise ConfigError(f"RECOVERAGE_PORT: {value} is not in the range {MIN_PORT}-{MAX_PORT}")
    return value


def max_connections() -> int:
    """Concurrent client connections the listener admits.

    One thread and one descriptor per admitted connection, so this is the
    process's largest single cost and the one an operator most often has to
    change: a container with a small memory limit needs a lower cap than a
    workstation, and a team sharing one dashboard needs a higher one than the
    default.  A cap of 0 would refuse every connection including the first, so
    the floor is 1.
    """
    value = _int_var("RECOVERAGE_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS)
    if not 1 <= value <= MAX_MAX_CONNECTIONS:
        raise ConfigError(
            f"RECOVERAGE_MAX_CONNECTIONS: {value} is not in the range 1-{MAX_MAX_CONNECTIONS}"
        )
    return value


def client_timeout() -> int:
    """Per-connection socket deadline, in seconds.

    Bounds how LONG one handler thread lives on a half-open peer.

    The floor is not a relationship to the SSE heartbeat.  A socket timeout
    is PER OPERATION, not a budget for the connection's life, and an idle
    ``/api/events`` stream blocks on its event queue rather than on the
    socket, so the heartbeat interval never enters it: a deadline under the
    15s heartbeat still serves the stream for as long as the client reads
    (verified against the real handler stack).  What a deadline too low does
    cost is a slow client: a response the peer cannot absorb in that window
    is cut mid-body, and a wedged SSE reader's queue is drained into a
    socket that will not take it.  So the floor is "long enough to write a
    large payload to a slow-but-live reader", and nothing about live reload
    depends on it.

    """
    value = _int_var("RECOVERAGE_CLIENT_TIMEOUT", DEFAULT_CLIENT_TIMEOUT_SECONDS)
    if not MIN_CLIENT_TIMEOUT_SECONDS <= value <= MAX_CLIENT_TIMEOUT_SECONDS:
        raise ConfigError(
            f"RECOVERAGE_CLIENT_TIMEOUT: {value} is not in the range "
            f"{MIN_CLIENT_TIMEOUT_SECONDS}-{MAX_CLIENT_TIMEOUT_SECONDS} seconds"
        )
    return value


def validate_bind(value: str, name: str = "RECOVERAGE_BIND") -> str:
    """Return *value* when it is an address the resolver can answer, else raise.

    The one binding setting with no format to convert still has a floor: an
    address carrying whitespace or a control character, or one written as
    ``host:port``, resolves to nothing.  Without this the mistake survives
    validation and the startup banner, and surfaces from
    ``socket.getaddrinfo`` inside the listener, after the DB watcher, the
    cache warmup and the browser opener have already started, with a message
    that blames a port already in use.

    An IPv6 literal keeps its colons; only a ``:`` outside one is a port the
    caller should have passed to ``--port``/``RECOVERAGE_PORT`` instead.
    *name* is the spelling the error quotes, so the flag path names the flag
    and the environment path names the variable.
    """
    if not value:
        raise ConfigError(f"{name}: set but empty (unset it, or give it an address)")
    if any(ch.isspace() or ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value):
        raise ConfigError(
            f"{name}: {value!r} is not an interface address "
            "(it carries whitespace or a control character; quote it in the unit file)"
        )
    if ":" in value:
        try:
            IPv6Address(value)
        except ValueError:
            raise ConfigError(
                f"{name}: {value!r} is not an interface address "
                "(drop the port; it belongs to RECOVERAGE_PORT/--port)"
            ) from None
    return value


def bind() -> str:
    """Interface to bind to."""
    return validate_bind(_str_var("RECOVERAGE_BIND", DEFAULT_BIND))


def allow_remote() -> bool:
    """Whether the operator acknowledged a network-exposed API."""
    return _bool_var("RECOVERAGE_ALLOW_REMOTE", False)


def validate_token(value: str | None, name: str = "RECOVERAGE_TOKEN") -> str | None:
    """Return *value* when a client could actually present it, else raise.

    The one secret read here, so the error names the problem and never the
    value: a token that cannot travel is still a token in the operator's
    configuration file, and the message is printed verbatim to stderr.

    An empty value is untouched: it is the documented "auth off" spelling, and
    :func:`token` turns it into "no token" rather than into a gate nothing can
    pass.

    Everything else is refused, because the gate compares the extracted
    credential for byte equality (``server._auth_token_matches``) and every
    carrier arrives stripped:

    * leading or trailing whitespace (``RECOVERAGE_TOKEN="$(cat token_file)"``
      on a file with a trailing space, a paste into a unit file) survives this
      check and is matched against a header the HTTP parser has already
      trimmed, so the server comes up reporting ``token=set`` and answers 401
      to every reader including the operator's own browser;
    * an interior space, tab, newline or control character is the same lockout,
      and a C0/DEL/C1 byte additionally cannot appear in a header at all.

    Both configurations start a server that no client can authenticate to, and
    the only clue is a 401 in a browser.  Refusing them at startup is the same
    rule the CORS allowlist and the bind address already follow.
    """
    if value is None or not value:
        return value
    if value != value.strip():
        raise ConfigError(
            f"{name}: leading or trailing whitespace; a request header is trimmed "
            "before it is compared, so no client could present this value"
        )
    if any(ch.isspace() or ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value):
        raise ConfigError(
            f"{name}: contains whitespace or a control character, which no request "
            "header, query value or cookie can carry"
        )
    return value


def token() -> str | None:
    """Bearer token, or None when no token is configured.

    The value is never logged, never rendered and never interpolated into an
    error: :func:`validate_token` reports what is wrong with it by class, not
    by content.
    """
    return validate_token(_raw("RECOVERAGE_TOKEN"))


def cors() -> bool:
    """Whether cross-origin requests are processed at all."""
    return _bool_var("RECOVERAGE_CORS", False)


def cors_origins() -> list[str]:
    """Origins allowed to read the API, from a comma-separated list.

    Splits on commas and drops empty items so a trailing comma
    (``a,b,``) is the two origins it looks like, not a third empty one.

    An item carrying a control character is an error, not an entry: it can
    never equal a browser's Origin, so storing it would leave --cors on with
    an allowlist one item short of what the operator wrote.

    A variable that is set but empty is an error for the same reason
    (:func:`db_override` and :func:`_str_var` draw the line there): the unit
    file, the container env and the CI job all spell "not configured" as an
    empty value, and this is the one that would otherwise start a server with
    CORS on and an allowlist of nothing, so every cross-origin read is refused
    and the only clue is a browser console the operator may not open.
    """
    raw = _raw("RECOVERAGE_CORS_ORIGIN")
    if raw is None:
        return []
    if not raw:
        raise ConfigError(
            "RECOVERAGE_CORS_ORIGIN: set but empty (unset it, or name at least one origin)"
        )
    origins: list[str] = []
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in item):
            raise ConfigError(f"RECOVERAGE_CORS_ORIGIN: {item!r} contains a control character")
        origins.append(item)
    return origins


def parse_log_level(raw: str) -> int:
    """Resolve a log level *raw* to its ``logging`` level number.

    Accepts a level name, case-insensitively (``WARNING``, ``Warn``, ``warn``),
    or a bare ASCII number, so a service can pass whatever ``logging`` calls a
    level.  Rejecting an unknown name matters: it would otherwise reach
    ``basicConfig`` and leave the logger at WARNING, quieter than the operator
    asked for, with nothing on stderr to say so.
    """
    name = raw.strip().upper()
    if name in LOG_LEVELS:
        return LOG_LEVELS[name]
    if name.isascii() and name.isdigit():
        # _as_int, not int(): a run of digits past CPython's conversion limit
        # fails the conversion, not the parse, and that is a bad value, not a
        # crash.  Re-raised in this module's own wording, so the caller wraps
        # one message rather than two.
        try:
            return _as_int("log level", raw)
        except ConfigError:
            pass
    allowed = ", ".join(sorted(LOG_LEVELS))
    raise ConfigError(f"{raw!r} is not a log level (use one of: {allowed})")


def log_level() -> int:
    """Threshold of the root logger, as a ``logging`` level number."""
    raw = _raw("RECOVERAGE_LOG_LEVEL")
    if raw is None:
        return DEFAULT_LOG_LEVEL
    try:
        return parse_log_level(raw)
    except ConfigError as exc:
        raise ConfigError(f"RECOVERAGE_LOG_LEVEL: {exc}") from None


def db_override() -> Path | None:
    """Explicit coverage directory, or None to resolve it from the project.

    Overrides the cwd-relative resolution (``[project] db_dir`` in
    ``rebrew-project.toml``, else ``db/``) so a service can run from a
    directory that is not the project root.  It names the directory holding the
    ``coverage-*.toml`` documents, which is the directory ``coverage.db`` was in.
    """
    raw = _raw("RECOVERAGE_DB")
    if raw is None:
        return None
    if not raw:
        raise ConfigError("RECOVERAGE_DB: set but empty (unset it, or give it a path)")
    return Path(raw).expanduser()


def check_db_override() -> None:
    """Refuse a coverage-directory override that cannot hold documents.

    A path that does not exist is left alone: a service may be started before
    the first ``rebrew build-db``, and the resolved directory is a default for
    the next run.  A path that exists and is NOT a directory has no such
    reading.  The likeliest spelling is the one the SQLite era taught:
    ``RECOVERAGE_DB=/srv/coverage.db`` pointing at the old database FILE after
    the documents moved beside it.  The glob for ``coverage-*.toml`` then
    matches nothing, the dashboard serves an empty target list forever, and
    every served number reads as a healthy zero rather than as a wrong path.

    One stat, at startup only: :func:`db_override` is on the request path
    (through ``_paths._db_path``) and must stay a bare environment read.
    """
    override = db_override()
    if override is None:
        return
    try:
        if override.exists() and not override.is_dir():
            raise ConfigError(
                f"RECOVERAGE_DB: {override} is not a directory; the variable names the "
                "directory holding the coverage-<target>.toml documents"
            )
    except OSError as exc:
        raise ConfigError(f"RECOVERAGE_DB: {override} is not readable ({exc.strerror})") from None


def check_unknown_vars() -> None:
    """Fail on any ``RECOVERAGE_*`` variable this module does not read.

    A misspelled name would otherwise be a silent no-op: the server starts
    with its defaults and the operator believes the environment was applied.
    """
    unknown = sorted(
        name for name in os.environ if name.startswith(ENV_PREFIX) and name not in KNOWN_VARS
    )
    if unknown:
        raise ConfigError(
            f"unknown configuration variable(s): {', '.join(unknown)} "
            f"(known: {', '.join(sorted(KNOWN_VARS))})"
        )


def active_config(
    *,
    port: int,
    bind: str,
    allow_remote: bool,
    cors: bool,
    cors_origin: Sequence[str],
    token: str | None,
    db: Path | None,
    log_level: int,
    max_connections: int,
    client_timeout: int,
) -> dict[str, str]:
    """Render the settings `serve` runs with, for the startup banner.

    Takes the ALREADY RESOLVED values rather than re-reading the environment,
    so the banner reports what the flags overrode and cannot drift from the
    behavior.  The token is rendered as ``set``/``unset``: its presence changes
    what the server does, its value is a secret.
    """
    return {
        "bind": bind,
        "port": str(port),
        "allow_remote": str(allow_remote).lower(),
        "cors": str(cors).lower(),
        "cors_origin": ",".join(cors_origin) or "none",
        "db": str(db) if db is not None else "auto",
        "log_level": logging.getLevelName(log_level),
        "token": "set" if token else "unset",
        "max_connections": str(max_connections),
        "client_timeout": str(client_timeout),
    }
