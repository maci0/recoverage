"""Tests for recoverage.config — RECOVERAGE_* env, precedence, validation."""

from __future__ import annotations

import logging
import re
from pathlib import Path, PurePosixPath

import pytest

from recoverage import config

# Rich wraps a CliRunner's stderr output in a box and pads every line, so a
# message compared across two widths has to be unwrapped first.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# The deployment copy of the configuration surface. Nothing in the package
# reads it, so nothing keeps it true: a setting added to config.KNOWN_VARS
# lands in the man page and the README table and misses the one file an
# operator copies into a unit file or a container spec.
_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_ENV_EXAMPLE = _ROOT / ".env.example"
_ASSIGNMENT = re.compile(r"\A#?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)\Z")


def _plain(text: str) -> str:
    """The message text of a boxed CliRunner result, unwrapped."""
    return " ".join(_ANSI_RE.sub("", text).replace("│", " ").split())


class TestDefaults:
    def test_defaults_match_the_flag_help(self) -> None:
        assert config.port() == 8001
        assert config.bind() == "127.0.0.1"
        assert config.allow_remote() is False
        assert config.cors() is False
        assert config.cors_origins() == []
        assert config.db_override() is None
        assert config.token() is None


class TestScalarParsing:
    def test_port_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_PORT", "9000")
        assert config.port() == 9000

    @pytest.mark.parametrize(
        "raw,expected", [("1", True), ("true", True), ("YES", True), ("on", True)]
    )
    def test_bool_true_spellings(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
    ) -> None:
        monkeypatch.setenv("RECOVERAGE_CORS", raw)
        assert config.cors() is expected

    @pytest.mark.parametrize(
        "raw,expected", [("0", False), ("false", False), ("No", False), ("off", False)]
    )
    def test_bool_false_spellings(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
    ) -> None:
        monkeypatch.setenv("RECOVERAGE_ALLOW_REMOTE", raw)
        assert config.allow_remote() is expected

    def test_cors_origins_split_on_commas(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://a.test, http://b.test,")
        assert config.cors_origins() == ["http://a.test", "http://b.test"]

    @pytest.mark.parametrize("raw", [",", " , ", ",,", "  "])
    def test_cors_origins_with_no_origin_is_set_but_empty(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """Separators and whitespace leave the same empty list the empty
        value does, and start the same server: CORS on, nothing allowed."""
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", raw)
        with pytest.raises(config.ConfigError, match="set but empty"):
            config.cors_origins()

    def test_token_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_TOKEN", "s3cret")
        assert config.token() == "s3cret"

    def test_empty_token_means_no_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty value is a deliberate "off", distinct from never being set."""
        monkeypatch.setenv("RECOVERAGE_TOKEN", "")
        assert config.token() == ""

    def test_db_override_expands_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_DB", "~/proj/db/coverage.db")
        assert config.db_override() == Path("~/proj/db/coverage.db").expanduser()

    @pytest.mark.parametrize(
        "raw", ["s3cret ", " s3cret", "s3cret\n", "  ", "two words", "tok\x01en", "tok\x7fen"]
    )
    def test_token_a_client_cannot_present_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """A token with whitespace or a control byte locks every reader out.

        The gate compares the extracted credential byte for byte and every
        carrier arrives stripped, so such a value starts a server that answers
        401 to everyone while the banner still reads ``token=set``.
        """
        monkeypatch.setenv("RECOVERAGE_TOKEN", raw)
        with pytest.raises(config.ConfigError) as excinfo:
            config.token()
        assert "RECOVERAGE_TOKEN" in str(excinfo.value)

    def test_token_refusal_does_not_echo_the_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The message reaches stderr verbatim, so it must not carry the secret."""
        monkeypatch.setenv("RECOVERAGE_TOKEN", "s3cret-value ")
        with pytest.raises(config.ConfigError) as excinfo:
            config.token()
        assert "s3cret" not in str(excinfo.value)

    def test_db_override_naming_a_file_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The SQLite-era spelling: a file where the documents' directory goes.

        The glob for ``coverage-*.toml`` then matches nothing and the dashboard
        serves an empty target list, which reads as a healthy zero rather than
        as a wrong path.
        """
        db_file = tmp_path / "coverage.db"
        db_file.write_text("not a directory")
        monkeypatch.setenv("RECOVERAGE_DB", str(db_file))
        with pytest.raises(config.ConfigError) as excinfo:
            config.check_db_override()
        assert "not a directory" in str(excinfo.value)

    def test_db_override_that_does_not_exist_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A service may start before the first ``rebrew build-db``."""
        override = tmp_path / "not-built-yet"
        monkeypatch.setenv("RECOVERAGE_DB", str(override))
        config.check_db_override()
        # "Allowed" is not "ignored": the read path still resolves the name
        # the reader configured, which is the half a deleted check could take.
        assert config.db_override() == override

    def test_db_override_unset_is_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RECOVERAGE_DB", raising=False)
        config.check_db_override()
        assert config.db_override() is None

    @pytest.mark.parametrize(
        "raw,expected", [("DEBUG", logging.DEBUG), ("warning", logging.WARNING), ("30", 30)]
    )
    def test_log_level_from_env(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: int
    ) -> None:
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", raw)
        assert config.log_level() == expected

    def test_log_level_defaults_to_info(self) -> None:
        assert config.log_level() == logging.INFO


class TestLogLevelRejectsBadValues:
    """An unknown level would otherwise leave the logger at WARNING, in silence."""

    def test_unknown_name_names_the_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", "chatty")
        with pytest.raises(config.ConfigError, match="RECOVERAGE_LOG_LEVEL"):
            config.log_level()

    def test_a_run_of_digits_past_the_int_limit_is_a_bad_level(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A value that looks like a number but cannot be converted is rejected.

        CPython's `int()` refuses a run of digits past its conversion limit,
        and that is a bad level, not a crash. The refusal is re-raised in this
        module's own wording, so the reader wraps ONE message naming the
        variable rather than nesting `RECOVERAGE_LOG_LEVEL:` inside itself.
        """
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", "9" * 5000)
        with pytest.raises(config.ConfigError) as excinfo:
            config.log_level()
        message = str(excinfo.value)
        assert message.startswith("RECOVERAGE_LOG_LEVEL:"), message[:80]
        assert "is not a log level" in message
        assert "WARNING" in message
        assert message.count("RECOVERAGE_LOG_LEVEL") == 1, message

    @pytest.mark.parametrize("raw", ["-1", "0x10", "1_0", "30.0", "٤٠"])
    def test_a_numeric_lookalike_is_not_a_level(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """Only a bare ASCII digit run converts; int()'s wider grammar does not.

        `int()` takes signs, underscores, a base prefix and the whole Unicode
        Nd set, so a level spelled with one of those would reach `basicConfig`
        as a number the operator never asked for.
        """
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", raw)
        with pytest.raises(config.ConfigError, match="is not a log level"):
            config.log_level()

    def test_error_lists_the_accepted_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", "chatty")
        with pytest.raises(config.ConfigError) as excinfo:
            config.log_level()
        assert "DEBUG" in str(excinfo.value) and "WARNING" in str(excinfo.value)

    @pytest.mark.parametrize("raw", ["9999", "3", "25", "100"])
    def test_a_number_outside_the_table_is_not_a_level(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """The numeric arm is held to the floor the name arm has.

        `logging` renders a threshold it does not know as `Level 9999` and
        then drops every record below it, so a valid-digit value the stdlib
        never calls a level silences the whole process: the start banner, the
        request lines and the health transitions all disappear, and the only
        clue is a deployment that got quieter at the moment someone asked it
        to say more.  The name arm was already refused for exactly this, and
        `logging.getLevelNamesMapping()` is the one table both arms read.
        """
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", raw)
        with pytest.raises(config.ConfigError, match="is not a log level"):
            config.log_level()

    @pytest.mark.parametrize("raw", ["0", "10", "20", "30", "40", "50"])
    def test_every_level_the_table_names_is_also_reachable_by_number(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """The floor is the table, not a hand-written list of accepted numbers."""
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", raw)
        assert config.log_level() == int(raw)

    def test_serve_exits_2_on_a_bad_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        from recoverage.cli import _resolve_serve_config

        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", "chatty")
        with pytest.raises(typer.Exit) as excinfo:
            _resolve_serve_config()
        assert excinfo.value.exit_code == 2


class TestRejectsBadValues:
    def test_non_integer_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_PORT", "eighty")
        with pytest.raises(config.ConfigError, match="RECOVERAGE_PORT"):
            config.port()

    @pytest.mark.parametrize("raw", ["-1", "65536"])
    def test_out_of_range_port(self, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
        monkeypatch.setenv("RECOVERAGE_PORT", raw)
        with pytest.raises(config.ConfigError, match="not in the range"):
            config.port()

    def test_unparseable_bool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_CORS", "maybe")
        with pytest.raises(config.ConfigError, match="RECOVERAGE_CORS"):
            config.cors()

    @pytest.mark.parametrize("name", ["RECOVERAGE_BIND", "RECOVERAGE_DB"])
    def test_empty_value_is_not_silently_defaulted(
        self, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        """Set-but-empty is a mistake for these, not "use the default"."""
        monkeypatch.setenv(name, "")
        reader = config.bind if name == "RECOVERAGE_BIND" else config.db_override
        with pytest.raises(config.ConfigError, match=name):
            reader()


class TestBindValidation:
    """The one binding setting with no conversion still has a floor."""

    @pytest.mark.parametrize("raw", ["0.0.0.0", "127.0.0.1", "::", "::1", "localhost", "host.lan"])
    def test_addresses_the_resolver_could_answer_pass(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        monkeypatch.setenv("RECOVERAGE_BIND", raw)
        assert config.bind() == raw

    @pytest.mark.parametrize(
        "raw,reason",
        [
            (" 127.0.0.1", "whitespace"),
            ("127.0.0.1\n", "control character"),
            ("local host", "whitespace"),
            ("0.0.0.0\x7f", "control character"),
            ("127.0.0.1:8001", "drop the port"),
            ("host.lan:80", "drop the port"),
        ],
    )
    def test_unanswerable_address_is_a_startup_error(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, reason: str
    ) -> None:
        """These reach socket.getaddrinfo as gaierror after the banner, the
        DB watcher and the browser opener have already started."""
        monkeypatch.setenv("RECOVERAGE_BIND", raw)
        with pytest.raises(config.ConfigError, match=reason):
            config.bind()

    def test_the_dev_proxy_target_matches_the_server_default(self) -> None:
        """`web/vite.config.ts` restates the server's default address.

        The Vite config runs in Node, where the package is not importable, so
        the fallback cannot be read off `config.DEFAULT_BIND` /
        `config.DEFAULT_PORT` and has to be written out. A contributor who
        moved `serve` off 8001 in `config.py` and forgot this string points the
        dev proxy at a port nothing is listening on, and the frontend dev loop
        fails with a connection error that names neither file. This is the test
        that fails instead.
        """
        vite = (_ROOT / "web" / "vite.config.ts").read_text(encoding="utf-8")
        expected = f'"http://{config.DEFAULT_BIND}:{config.DEFAULT_PORT}"'
        assert expected in vite, f"the dev proxy default moved off {expected}"

    def test_validate_bind_rejects_empty(self) -> None:
        with pytest.raises(config.ConfigError, match="set but empty"):
            config.validate_bind("")

    @pytest.mark.parametrize("raw", ["localhost/api", "ho@st", "ho#st"])
    def test_a_character_no_address_can_hold_is_a_startup_error(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """The floor is structural, so it costs no resolver call.

        The ways a URL pasted into a unit file brings its authority's
        delimiters along with it all reach `socket.bind()` as `gaierror` when
        they get past here, and `serve`'s `OSError` handler reports that as "is
        another instance already running?" — naming neither the variable nor
        the remedy, after the DB watcher, the cache warmup and the browser
        opener have started. The percent sign gets its own test below because
        an IPv6 literal is allowed to hold it.
        """
        monkeypatch.setenv("RECOVERAGE_BIND", raw)
        with pytest.raises(config.ConfigError, match="not an interface address"):
            config.bind()

    @pytest.mark.parametrize(
        "raw", ["0.0.0.0", "127.0.0.1", "::", "::1", "host.lan", "a-b", "a_b", "fe80::1%1"]
    )
    def test_the_floor_keeps_every_address_the_resolver_could_answer(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """The point of a floor: it refuses what cannot work, and nothing else.

        `_NOT_IN_AN_ADDRESS` is a list of characters, not a hostname grammar.
        Validating labels, length or the IDNA rules here would refuse a name
        the host's own resolver answers, which is a startup error for a
        deployment that would have served.
        """
        assert not set(raw) & config._NOT_IN_AN_ADDRESS, raw
        assert config.PERCENT not in raw or ":" in raw, raw
        monkeypatch.setenv("RECOVERAGE_BIND", raw)
        assert config.bind() == raw

    @pytest.mark.parametrize("raw", ["0.0.0.0%eth0", "0.0.0.0%lo"])
    def test_an_interface_spec_is_a_startup_error_but_a_zone_is_not(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """The percent sign is the one character with two right answers.

        `0.0.0.0` with an interface name after it is the systemd spelling and
        no resolver answers it; `fe80::1` with a zone after it is a real
        link-local literal, the only route a host with no other one has to that
        network. A floor that refused both would break the second to catch the
        first, so the two are judged apart — and the flag path reaches the same
        verdict, because `--bind` and `RECOVERAGE_BIND` are one setting.
        """
        monkeypatch.setenv("RECOVERAGE_BIND", raw)
        with pytest.raises(config.ConfigError, match="percent sign"):
            config.bind()
        with pytest.raises(config.ConfigError, match="percent sign"):
            config.validate_bind(raw, "--bind")

    def test_the_flag_path_shares_the_floor(self) -> None:
        with pytest.raises(config.ConfigError, match="not an interface address"):
            config.validate_bind("localhost/api", "--bind")

    def test_validate_bind_is_what_the_flag_path_uses(self) -> None:
        """--bind and RECOVERAGE_BIND are one setting; the flag skips bind()
        and must not skip its floor.  Its error names the flag, the way
        _checked_port names --port."""
        with pytest.raises(config.ConfigError, match=re.escape("--bind: '127.0.0.1 '")):
            config.validate_bind("127.0.0.1 ", "--bind")


class TestHelpTextRendersTheConstants:
    def test_serve_help_advertises_the_current_defaults(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--help"])
        assert result.exit_code == 0, result.output
        # Rich wraps at word boundaries, so each rendered default is one token.
        for token in (
            str(config.DEFAULT_PORT),
            config.DEFAULT_BIND,
            logging.getLevelName(config.DEFAULT_LOG_LEVEL),
        ):
            assert token in result.output, f"{token} missing from serve --help"

    def test_error_message_never_carries_the_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_TOKEN", "s3cret-value")
        monkeypatch.setenv("RECOVERAGE_PORT", "nope")
        with pytest.raises(config.ConfigError) as excinfo:
            config.port()
        assert "s3cret-value" not in str(excinfo.value)


class TestUnknownVars:
    def test_misspelled_var_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A typo is otherwise indistinguishable from unset, and silently default."""
        monkeypatch.setenv("RECOVERAGE_TYPO", "1")
        with pytest.raises(config.ConfigError, match="RECOVERAGE_TYPO"):
            config.check_unknown_vars()

    def test_known_vars_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_PORT", "9000")
        monkeypatch.setenv("RECOVERAGE_TOKEN", "s3cret")
        config.check_unknown_vars()

    def test_unrelated_prefixed_name_is_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOT_RECOVERY_X", "1")
        config.check_unknown_vars()

    def test_known_vars_and_prefix_agree(self) -> None:
        """check_unknown_vars can only pass if the reader set is complete."""
        for name in config.KNOWN_VARS:
            assert name.startswith(config.ENV_PREFIX)

    def test_the_frontend_dev_proxy_target_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`RECOVERAGE_DEV_API` must not lock the dev loop out of the CLI.

        `web/vite.config.ts` reads it to point the dev server's proxy at a
        `serve` that is not on the default port, and CONTRIBUTING.md documents
        it beside that loop. A developer who exported it once ran `serve` on a
        non-default port from the same shell, and every `recoverage` command
        exited 2 naming it as a misspelling — a tool knob the repo itself owns
        read as a typo in a setting. It changes nothing `serve` does, so it
        belongs in KNOWN_VARS for the same reason the fuzz knobs do.
        """
        monkeypatch.setenv("RECOVERAGE_DEV_API", "http://127.0.0.1:9000")
        config.check_unknown_vars()
        # And it is not a server setting the merge may pick up by accident.
        assert config.port() == config.DEFAULT_PORT

    def test_no_server_reader_consumes_a_tool_knob(self) -> None:
        """Membership in KNOWN_VARS is not a claim that `serve` reads it.

        The two fuzz knobs and the dev proxy target are listed so exporting one
        does not refuse every command; none is a setting, and a reader added
        later would make the startup banner and `recoverage config` name a
        variable the CLI cannot resolve from a flag.
        """
        from recoverage import cli

        resolved = cli._resolve_serve_config()
        rendered = config.active_config(
            port=resolved.port,
            bind=resolved.bind,
            allow_remote=resolved.allow_remote,
            cors=resolved.cors,
            cors_origin=resolved.cors_origins,
            token=resolved.token,
            db=resolved.db,
            log_level=resolved.log_level,
            max_connections=resolved.max_connections,
            client_timeout=resolved.client_timeout,
        )
        tool_knobs = {"RECOVERAGE_DEV_API", "RECOVERAGE_FUZZ_ITERATIONS", "RECOVERAGE_FUZZ_SEED"}
        assert not rendered.keys() & tool_knobs


class TestTransportBounds:
    """The admission cap and the per-connection deadline are deployment-sized,
    so they are validated settings rather than constants in the transport."""

    def test_defaults(self) -> None:
        assert config.max_connections() == config.DEFAULT_MAX_CONNECTIONS
        assert config.client_timeout() == config.DEFAULT_CLIENT_TIMEOUT_SECONDS

    def test_read_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_MAX_CONNECTIONS", "512")
        monkeypatch.setenv("RECOVERAGE_CLIENT_TIMEOUT", "300")
        assert config.max_connections() == 512
        assert config.client_timeout() == 300

    @pytest.mark.parametrize("raw", ["0", "-1", "999999"])
    def test_an_unusable_cap_is_rejected(self, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
        """A cap of 0 refuses every connection including the first; a negative
        one refuses every connection too, silently, since every accept is past
        it.  A value past the ceiling is a typo, not a deployment."""
        monkeypatch.setenv("RECOVERAGE_MAX_CONNECTIONS", raw)
        with pytest.raises(config.ConfigError, match="RECOVERAGE_MAX_CONNECTIONS"):
            config.max_connections()

    def test_a_cap_of_one_is_the_lowest_usable_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_MAX_CONNECTIONS", "1")
        assert config.max_connections() == 1

    @pytest.mark.parametrize("raw", ["0", "1", "4", "-30"])
    def test_a_deadline_under_the_floor_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """A deadline below the floor cuts a slow-but-live reader's response
        mid-body, so it is a setting that breaks large payloads rather than
        one that merely retires threads sooner.  Nothing here is about the
        SSE heartbeat: the socket deadline is per operation and an idle
        stream blocks on its queue, so a low value does not close a healthy
        /api/events stream (see config.client_timeout)."""
        monkeypatch.setenv("RECOVERAGE_CLIENT_TIMEOUT", raw)
        with pytest.raises(config.ConfigError, match="RECOVERAGE_CLIENT_TIMEOUT"):
            config.client_timeout()

    def test_a_non_numeric_bound_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECOVERAGE_CLIENT_TIMEOUT", "forever")
        with pytest.raises(config.ConfigError, match="RECOVERAGE_CLIENT_TIMEOUT"):
            config.client_timeout()

    def test_serve_installs_the_resolved_bounds_on_the_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cap validated and then not installed is a config the banner lies
        about, so the resolved values reach the module the accept path reads.

        Driven through `serve` itself: the wiring this names is the CLI's, and
        a test that calls `configure_transport` itself passes with a `serve`
        that stopped calling it.
        """
        from typing import Any

        from typer.testing import CliRunner

        import recoverage.devserver as devserver
        from recoverage.cli import app as cli_app
        from recoverage.server import app as server_app

        monkeypatch.setenv("RECOVERAGE_MAX_CONNECTIONS", "7")
        monkeypatch.setenv("RECOVERAGE_CLIENT_TIMEOUT", "300")
        monkeypatch.setattr("recoverage.api._ensure_db_watcher", lambda: None)

        def raise_interrupt(self: Any, **kwargs: Any) -> None:
            raise KeyboardInterrupt

        # Stop at the accept loop: everything before it is the wiring under
        # test, and the KeyboardInterrupt is the documented clean stop.
        monkeypatch.setattr(type(server_app), "run", raise_interrupt)
        try:
            result = CliRunner().invoke(cli_app, ["serve", "--no-open", "--port", "8123"])
            assert result.exit_code == 0, result.output
            assert devserver._MAX_CONNECTIONS == 7
            assert devserver._CLIENT_SOCKET_TIMEOUT_SECONDS == 300
            # http.server reads `timeout` at handler construction.
            assert devserver._QuietTimeoutRequestHandler.timeout == 300
            # So /api/health names the enforced cap before the first accept.
            assert devserver.metrics.CONNECTIONS.snapshot()["max"] == 7
        finally:
            devserver.configure_transport(
                max_connections=config.DEFAULT_MAX_CONNECTIONS,
                client_timeout_seconds=config.DEFAULT_CLIENT_TIMEOUT_SECONDS,
            )

    def test_a_bad_bound_exits_2_like_every_other_setting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        from recoverage.cli import _resolve_serve_config

        monkeypatch.setenv("RECOVERAGE_MAX_CONNECTIONS", "0")
        with pytest.raises(typer.Exit) as excinfo:
            _resolve_serve_config()
        assert excinfo.value.exit_code == 2


class TestActiveConfig:
    def test_reports_resolved_values_not_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The banner takes what serve resolved, so a flag override cannot drift."""
        monkeypatch.setenv("RECOVERAGE_PORT", "9000")
        rendered = config.active_config(
            port=8001,
            bind="127.0.0.1",
            allow_remote=False,
            cors=False,
            cors_origin=[],
            token=None,
            db=None,
            log_level=logging.INFO,
            max_connections=config.DEFAULT_MAX_CONNECTIONS,
            client_timeout=config.DEFAULT_CLIENT_TIMEOUT_SECONDS,
        )
        assert rendered["port"] == "8001"
        assert rendered["db"] == "auto"
        assert rendered["cors_origin"] == "none"
        assert rendered["log_level"] == "INFO"
        assert rendered["max_connections"] == str(config.DEFAULT_MAX_CONNECTIONS)
        assert rendered["client_timeout"] == str(config.DEFAULT_CLIENT_TIMEOUT_SECONDS)

    def test_token_is_reported_as_set_without_its_value(self) -> None:
        rendered = config.active_config(
            port=8001,
            bind="127.0.0.1",
            allow_remote=False,
            cors=False,
            cors_origin=["http://a.test"],
            token="s3cret-value",
            # A PURE posix path on purpose: the banner renders whatever path
            # object it is handed, and str() of an absolute path is not
            # portable — str(PureWindowsPath("/tmp/x.db")) is "\tmp\x.db", so
            # Path("/tmp/x.db") renders differently on Windows. The value
            # asserted below is the string this object carries.
            db=PurePosixPath("/tmp/x.db"),
            log_level=logging.WARNING,
            max_connections=512,
            client_timeout=45,
        )
        assert rendered["log_level"] == "WARNING"
        assert rendered["max_connections"] == "512"
        assert rendered["client_timeout"] == "45"
        assert rendered["token"] == "set"
        assert "s3cret-value" not in " ".join(rendered.values())
        assert rendered["cors_origin"] == "http://a.test"
        assert rendered["db"] == "/tmp/x.db"


class TestServeResolution:
    """The flags-over-environment merge `serve` starts from."""

    def test_defaults_when_nothing_is_set(self) -> None:
        from recoverage.cli import _resolve_serve_config

        resolved = _resolve_serve_config()
        assert resolved.port == 8001
        assert resolved.bind == "127.0.0.1"
        assert resolved.allow_remote is False
        assert resolved.token is None
        assert resolved.db is None
        assert resolved.log_level == logging.INFO

    def test_environment_supplies_every_setting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recoverage.cli import _resolve_serve_config

        monkeypatch.setenv("RECOVERAGE_PORT", "9001")
        monkeypatch.setenv("RECOVERAGE_BIND", "0.0.0.0")
        monkeypatch.setenv("RECOVERAGE_ALLOW_REMOTE", "true")
        monkeypatch.setenv("RECOVERAGE_CORS", "true")
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://a.test")
        monkeypatch.setenv("RECOVERAGE_TOKEN", "env-token")
        monkeypatch.setenv("RECOVERAGE_DB", "/srv/coverage.db")
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", "WARNING")
        resolved = _resolve_serve_config()
        assert resolved.port == 9001
        assert resolved.bind == "0.0.0.0"
        assert resolved.allow_remote is True
        assert resolved.cors is True
        assert resolved.cors_origins == ["http://a.test"]
        assert resolved.token == "env-token"
        assert resolved.db == Path("/srv/coverage.db")
        assert resolved.log_level == logging.WARNING

    def test_flag_beats_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recoverage.cli import _resolve_serve_config

        monkeypatch.setenv("RECOVERAGE_PORT", "9001")
        monkeypatch.setenv("RECOVERAGE_BIND", "0.0.0.0")
        monkeypatch.setenv("RECOVERAGE_TOKEN", "env-token")
        resolved = _resolve_serve_config(port=8500, bind="127.0.0.1", token="flag-token")
        assert resolved.port == 8500
        assert resolved.bind == "127.0.0.1"
        assert resolved.token == "flag-token"

    def test_log_level_flag_beats_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recoverage.cli import _resolve_serve_config

        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", "WARNING")
        resolved = _resolve_serve_config(log_level="debug")
        assert resolved.log_level == logging.DEBUG

    def test_out_of_range_flag_port_exits_2(self) -> None:
        import typer

        from recoverage.cli import _resolve_serve_config

        with pytest.raises(typer.Exit) as excinfo:
            _resolve_serve_config(port=99999)
        assert excinfo.value.exit_code == 2

    def test_unanswerable_flag_bind_exits_2(self) -> None:
        import typer

        from recoverage.cli import _resolve_serve_config

        with pytest.raises(typer.Exit) as excinfo:
            _resolve_serve_config(bind="0.0.0.0 ")
        assert excinfo.value.exit_code == 2

    def test_bad_environment_value_exits_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        from recoverage.cli import _resolve_serve_config

        monkeypatch.setenv("RECOVERAGE_PORT", "eighty")
        with pytest.raises(typer.Exit) as excinfo:
            _resolve_serve_config()
        assert excinfo.value.exit_code == 2


class TestServeStartup:
    """`serve` command behavior driven by the environment (exits before binding)."""

    def test_unknown_env_var_is_a_startup_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_PRT", "9001")
        result = CliRunner().invoke(app, ["serve", "--no-open"])
        assert result.exit_code == 2
        assert "RECOVERAGE_PRT" in result.output

    def test_env_bind_still_needs_the_remote_acknowledgment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The env supplies the value; the acknowledgment stays a human decision."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_BIND", "0.0.0.0")
        result = CliRunner().invoke(app, ["serve", "--no-open"])
        assert result.exit_code == 1
        assert "--allow-remote" in result.output

    def test_invalid_env_port_never_reaches_the_listener(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_PORT", "70000")
        result = CliRunner().invoke(app, ["serve", "--no-open"])
        assert result.exit_code == 2
        assert "RECOVERAGE_PORT" in result.output

    def test_env_token_no_client_can_present_never_binds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A token that cannot travel is refused before the listener, not after."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_TOKEN", "s3cret ")
        result = CliRunner().invoke(app, ["serve", "--no-open"])
        assert result.exit_code == 2
        assert "RECOVERAGE_TOKEN" in result.output
        assert "s3cret" not in result.output

    def test_the_token_flag_gets_the_same_floor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One setting, two sources, one validator, as --bind has."""
        import typer

        from recoverage.cli import _resolve_serve_config

        with pytest.raises(typer.Exit) as excinfo:
            _resolve_serve_config(token="s3cret\n")
        assert excinfo.value.exit_code == 2

    def test_env_db_naming_a_file_never_binds(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        db_file = tmp_path / "coverage.db"
        db_file.write_text("not a directory")
        monkeypatch.setenv("RECOVERAGE_DB", str(db_file))
        result = CliRunner().invoke(app, ["serve", "--no-open"])
        assert result.exit_code == 2
        assert "RECOVERAGE_DB" in result.output


class TestConfigCommand:
    """`recoverage config` reports what `serve` would resolve, without binding."""

    def test_reports_environment_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_PORT", "9000")
        monkeypatch.setenv("RECOVERAGE_LOG_LEVEL", "WARNING")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0
        assert "port=9000" in result.output
        assert "log_level=WARNING" in result.output

    def test_defaults_when_the_environment_is_empty(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0
        assert f"port={config.DEFAULT_PORT}" in result.output
        assert "db=auto" in result.output

    def test_token_is_reported_without_its_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_TOKEN", "s3cret-value")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0
        assert "token=set" in result.output
        assert "s3cret-value" not in result.output

    def test_json_output_is_the_same_object(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS", "1")
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://localhost:5173")
        result = CliRunner().invoke(app, ["config", "--json"])
        assert result.exit_code == 0
        # A literal, not config.active_config(...): rendering both sides with
        # the same function makes any change to the rendered shape (the token
        # mask, db="auto", "none" for an empty origin list) pass unnoticed.
        assert json.loads(result.output) == {
            "bind": config.DEFAULT_BIND,
            "port": str(config.DEFAULT_PORT),
            "allow_remote": "false",
            "cors": "true",
            "cors_origin": "http://localhost:5173",
            "db": "auto",
            "log_level": "INFO",
            "token": "unset",
            "max_connections": str(config.DEFAULT_MAX_CONNECTIONS),
            "client_timeout": str(config.DEFAULT_CLIENT_TIMEOUT_SECONDS),
        }

    def test_the_text_form_carries_every_field_the_json_form_does(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The two spellings are one rendering, so neither may drop a setting.

        Substring assertions on the text form (`"port=9000" in output`) pass
        just as happily over a banner that silently lost `log_level` or
        `cors_origin`, which is the field an operator reads to learn why their
        cross-origin read is refused. Parsed and compared as a mapping, the
        text form is held to the same key set the `--json` form is.
        """
        import json

        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS", "1")
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://localhost:5173")
        runner = CliRunner()
        text = runner.invoke(app, ["config"])
        as_json = runner.invoke(app, ["config", "--json"])
        assert text.exit_code == 0
        assert as_json.exit_code == 0

        pairs = dict(line.split("=", 1) for line in text.output.splitlines() if "=" in line.strip())
        assert pairs == json.loads(as_json.output)

    def test_allowlist_is_reported_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The checked value is the value the server matches: a default port
        dropped and the host lowercased, or an operator reads an allowlist
        that differs from the installed one by spelling alone."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS", "1")
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://LocalHost:80,http://app.test:5173")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0
        assert "cors_origin=http://localhost,http://app.test:5173" in result.output

    def test_unusable_origin_exits_2_rather_than_dropping_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A refused entry is not a shorter allowlist, it is a deployment that
        refuses exactly the reads the entry was written for.  Same for the
        variable and the flag, so the exit code does not depend on the source."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS", "1")
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://user@host.test")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 2
        assert "user@host.test" in result.output
        assert "Traceback" not in result.output

    def test_bad_flag_origin_exits_2_too(self) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["serve", "--cors", "--cors-origin", "http://a b"])
        assert result.exit_code == 2
        assert "http://a b" in result.output

    def test_origin_is_ignored_while_cors_is_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With CORS off the allowlist is never installed, so an entry that
        could not be installed is not a mistake the operator has to hear
        about; serve already reports that the origins do nothing."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://user@host.test")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0
        assert "cors=false" in result.output

    def test_empty_cors_origin_exits_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A unit file, a container env and a CI job all spell "not
        configured" as an empty value.  Taken as an empty allowlist it starts
        a server whose every cross-origin read is refused."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 2
        assert "RECOVERAGE_CORS_ORIGIN" in result.output
        assert "Traceback" not in result.output

    def test_unset_cors_origin_is_not_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unset stays unset: the error is about the value, not the absence."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.delenv("RECOVERAGE_CORS_ORIGIN", raising=False)
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0
        assert "cors_origin=none" in result.output

    def test_bad_value_exits_2_without_a_traceback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_PORT", "eighty")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 2
        assert "RECOVERAGE_PORT" in result.output
        assert "Traceback" not in result.output

    def test_remote_bind_without_ack_exits_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A preflight that exits 0 for a bind `serve` exits 1 on is a
        deployment that finds out at boot, not at the check.  The settings are
        still printed, so the operator sees which bind was refused."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_BIND", "0.0.0.0")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 1
        assert "bind=0.0.0.0" in result.output
        assert "allow-remote" in result.output
        assert "Traceback" not in result.output

    def test_remote_bind_with_acknowledgment_exits_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_BIND", "0.0.0.0")
        monkeypatch.setenv("RECOVERAGE_ALLOW_REMOTE", "1")
        result = CliRunner().invoke(app, ["config", "--json"])
        assert result.exit_code == 0
        assert "allow-remote" not in result.output

    def test_ipv6_wildcard_is_not_loopback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`::` binds every interface, so it is refused exactly like
        0.0.0.0; reading it as loopback is the silent exposure."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_BIND", "::")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 1
        assert "Traceback" not in result.output

    def test_cors_without_an_allowlist_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The same warning `serve` prints, so the check reports a setting
        that will refuse every cross-origin read rather than only the one
        that would not start at all."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS", "1")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0
        assert "--cors without --cors-origin" in result.output

    def test_cors_origin_without_cors_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The entry that has no effect without --cors is the one
        _allowed_origins did not install, so the warning has to be driven by
        what the operator wrote.  Reading the installed list instead made the
        arm unreachable and the warning silent."""
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", "http://localhost:5173")
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0, result.output
        assert "--cors-origin has no effect without --cors" in result.output


class TestCoverageDirectoryWarnings:
    """A coverage directory with nothing in it serves an empty target list,
    which every rendered figure reads as a healthy zero. `serve` and
    `recoverage config` say so from one rule rather than leaving the operator
    to infer it from a blank map."""

    def test_a_directory_with_documents_warns_about_nothing(self, tmp_path: Path) -> None:
        from recoverage.cli import _db_warnings

        (tmp_path / "coverage-demo.toml").write_text("[target]\n")
        assert _db_warnings(tmp_path) == []

    def test_an_empty_directory_warns_and_names_it(self, tmp_path: Path) -> None:
        from recoverage.cli import _db_warnings

        warnings = _db_warnings(tmp_path)
        assert len(warnings) == 1
        assert str(tmp_path) in warnings[0]
        assert "rebrew build-db" in warnings[0]

    def test_a_missing_directory_warns_too(self, tmp_path: Path) -> None:
        """The service-started-in-the-wrong-directory case: the resolved
        default is a directory that was never created."""
        from recoverage.cli import _db_warnings

        warnings = _db_warnings(tmp_path / "never-created")
        assert len(warnings) == 1
        assert "does not exist" in warnings[0]

    def test_a_path_that_is_a_file_is_left_to_the_startup_refusal(self, tmp_path: Path) -> None:
        from recoverage.cli import _db_warnings

        db_file = tmp_path / "coverage.db"
        db_file.write_text("not a directory")
        assert _db_warnings(db_file) == []

    def test_the_config_command_reports_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_DB", str(tmp_path))
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0, result.output
        assert "RECOVERAGE_DB" in result.output


class TestCorsOriginIsWhatABrowserCouldSend:
    """RECOVERAGE_CORS_ORIGIN is validated as an Origin header, not merely as
    something _normalize_origin can reduce.  That reducer exists to READ
    whatever arrives on a request: it drops a path and synthesizes a scheme,
    so through it the allowlist would hold a different entry than the operator
    wrote, and the refusal they get comes from a browser instead of from
    startup."""

    @pytest.mark.parametrize(
        "origin",
        [
            "http://localhost:5173/foo",
            "http://localhost:5173/",
            "https://box/app",
            "http://box?x=1",
            "http://box#f",
            "notaurl",
            "ftp://box",
            "http://user:pw@box",
            "http://box:notaport",
            "http://local host:5173",
        ],
    )
    def test_refused_with_exit_2(self, monkeypatch: pytest.MonkeyPatch, origin: str) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS", "1")
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", origin)
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 2, (origin, result.output)
        assert "not a URL the browser could send" in _plain(result.output)

    @pytest.mark.parametrize(
        "origin", ["http://localhost:5173", "https://box", "http://box:80", "http://[::1]:8001"]
    )
    def test_accepted(self, monkeypatch: pytest.MonkeyPatch, origin: str) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_CORS", "1")
        monkeypatch.setenv("RECOVERAGE_CORS_ORIGIN", origin)
        result = CliRunner().invoke(app, ["config"])
        assert result.exit_code == 0, (origin, result.output)


class TestFlagIntegersGetTheEnvironmentFloor:
    """--port and --min-coverage are text at the parser for the same reason
    RECOVERAGE_PORT is: click's INT/FLOAT run the value through int()/float(),
    which read every Unicode Nd digit, the "_" separator, and inf/nan.  One
    setting, two sources, one floor."""

    @pytest.mark.parametrize("value", ["1_0", "٤٠٩٦", "0x10", "", " ", "8 0"])
    def test_port_rejected(self, value: str) -> None:
        from recoverage.cli import _checked_port

        with pytest.raises(config.ConfigError, match="--port"):
            _checked_port(value)

    def test_port_accepts_plain_digits_and_an_int(self) -> None:
        from recoverage.cli import _checked_port

        assert _checked_port("9001") == 9001
        assert _checked_port(9001) == 9001
        assert _checked_port("0") == 0

    @pytest.mark.parametrize("value", ["1_0", "inf", "nan", "٤٠", "1.2.3", "", "5%"])
    def test_min_coverage_rejected(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        result = CliRunner().invoke(app, ["check", "--min-coverage", value])
        assert result.exit_code == 2, (value, result.output)
        assert "--min-coverage" in _plain(result.output)

    def test_min_coverage_range_still_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        for value in ("200", "-1", "0.0.0"):
            result = CliRunner().invoke(app, ["check", "--min-coverage", value])
            assert result.exit_code == 2, (value, result.output)


class TestEnvValidatedByEveryCommand:
    """`serve` is not the only consumer of the environment."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["stats"],
            ["export"],
            ["check", "--min-coverage", "0"],
            ["open"],
            ["regen"],
        ],
    )
    def test_misspelled_var_exits_2(self, monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_DB_PATH", "/tmp/other.db")
        result = CliRunner().invoke(app, argv)
        assert result.exit_code == 2
        assert "RECOVERAGE_DB_PATH" in result.output

    def test_empty_db_override_exits_2_not_a_traceback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from recoverage.cli import app

        monkeypatch.setenv("RECOVERAGE_DB", "")
        result = CliRunner().invoke(app, ["stats"])
        assert result.exit_code == 2
        assert "RECOVERAGE_DB" in result.output
        assert "Traceback" not in result.output


class TestEnvExample:
    """`.env.example` is a deployment artifact, so it is pinned like one.

    It is the file an operator diffs against a running unit: every line names
    one setting and its stock value, an uncommented line is a change from that
    value, and the file's own header says a name it does not carry is a
    startup error. Nothing in the package reads it, so nothing else would
    notice a setting that reached config.KNOWN_VARS and never reached here.
    """

    #: The one name in ``config.KNOWN_VARS`` this file does NOT carry: the
    #: frontend dev server's proxy target, which points a Vite dev server at a
    #: `serve` the same contributor is running. It is in KNOWN_VARS so
    #: exporting it does not refuse every command, but it is not a deployment
    #: setting, and a line naming it here would tell an operator to set a
    #: variable no subcommand reads. The man page omits the same name, for the
    #: same reason and with the same list (tests/test_build.py,
    #: ``_NOT_A_SETTING``), so the two artifacts cannot drift apart.
    _NOT_A_SETTING = frozenset({"RECOVERAGE_DEV_API"})

    @staticmethod
    def _documented() -> dict[str, str]:
        """Every ``NAME=value`` line in the example, commented or not."""
        documented: dict[str, str] = {}
        for line in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            match = _ASSIGNMENT.match(line.strip())
            if match:
                documented[match["name"]] = match["value"].strip()
        return documented

    def test_it_names_every_known_variable_and_nothing_else(self) -> None:
        named = {name for name in self._documented() if name.startswith(config.ENV_PREFIX)}
        assert named == config.KNOWN_VARS - self._NOT_A_SETTING

    def test_no_line_actually_sets_a_variable(self) -> None:
        """A checked-in value is a value every deployment starts from.

        The header states nothing in the file is read automatically, and an
        uncommented line contradicts that: a sourced EnvironmentFile would
        apply the example's stock value, or its placeholder token, to every
        host that copied it.
        """
        for line in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            if line.strip():
                assert line.lstrip().startswith("#"), line

    def test_the_stated_defaults_are_the_defaults_the_server_uses(self) -> None:
        # The settings with a default the module owns a constant for. The
        # three with none (DB, CORS_ORIGIN, TOKEN) are absent or a
        # placeholder there, which is the same statement: unset means the
        # stock behavior.
        documented = self._documented()
        assert documented["RECOVERAGE_PORT"] == str(config.DEFAULT_PORT)
        assert documented["RECOVERAGE_BIND"] == config.DEFAULT_BIND
        assert documented["RECOVERAGE_MAX_CONNECTIONS"] == str(config.DEFAULT_MAX_CONNECTIONS)
        assert documented["RECOVERAGE_CLIENT_TIMEOUT"] == str(config.DEFAULT_CLIENT_TIMEOUT_SECONDS)
        assert documented["RECOVERAGE_LOG_LEVEL"] == logging.getLevelName(config.DEFAULT_LOG_LEVEL)
        assert documented["RECOVERAGE_CORS"] == "false"
        assert documented["RECOVERAGE_ALLOW_REMOTE"] == "false"

    def test_the_token_is_a_placeholder_rather_than_a_value(self) -> None:
        # The one secret the file names. A placeholder an operator replaces is
        # the contract; a token that looks usable is a credential in version
        # control that every reader of the repository holds.
        token = self._documented()["RECOVERAGE_TOKEN"]
        assert "replace" in token.lower(), token
