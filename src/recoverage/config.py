"""Runtime configuration for ``recoverage serve``, read from ``RECOVERAGE_*``.

The environment supplies the DEFAULTS for the serve flags; a flag passed on
the command line always wins.  Reading them here — one module, one lookup per
setting — keeps deployment settings out of argv, so a systemd unit or a
container spec states them in the environment and nothing has to parse ``ps``
output to learn how the server was started.

Two rules make a misconfigured deployment loud instead of surprising:

* every value is validated (and converted) at startup, before the listener
  binds, so a typo is a clear error rather than a socket or auth failure
  minutes later;
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
        "RECOVERAGE_CORS",
        "RECOVERAGE_CORS_ORIGIN",
        "RECOVERAGE_DB",
        "RECOVERAGE_FUZZ_ITERATIONS",
        "RECOVERAGE_FUZZ_SEED",
        "RECOVERAGE_LOG_LEVEL",
        "RECOVERAGE_PORT",
        "RECOVERAGE_TOKEN",
    }
)

# Command-line defaults, the single definition the environment defaults and
# the CLI epilog share.  The --port help string reads DEFAULT_PORT from here;
# the --bind and --log-level ones spell their default out in text, so a change
# to those two constants needs those strings updated alongside it.
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


def bind() -> str:
    """Interface to bind to."""
    return _str_var("RECOVERAGE_BIND", DEFAULT_BIND)


def allow_remote() -> bool:
    """Whether the operator acknowledged a network-exposed API."""
    return _bool_var("RECOVERAGE_ALLOW_REMOTE", False)


def token() -> str | None:
    """Bearer token, or None when no token is configured.

    The value is returned, never inspected: there is no format to validate and
    nothing derived from it may be logged.
    """
    return _raw("RECOVERAGE_TOKEN")


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
    """
    raw = _raw("RECOVERAGE_CORS_ORIGIN")
    if raw is None:
        return []
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
            allowed = ", ".join(sorted(LOG_LEVELS))
            raise ConfigError(f"{raw!r} is not a log level (use one of: {allowed})") from None
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
    """Explicit coverage.db path, or None to resolve it from the project.

    Overrides the cwd-relative resolution (``[project] db_dir`` in
    ``rebrew-project.toml``, else ``db/coverage.db``) so a service can run
    from a directory that is not the project root.
    """
    raw = _raw("RECOVERAGE_DB")
    if raw is None:
        return None
    if not raw:
        raise ConfigError("RECOVERAGE_DB: set but empty (unset it, or give it a path)")
    return Path(raw).expanduser()


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
    }
