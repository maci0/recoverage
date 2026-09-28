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

    def test_validate_bind_rejects_empty(self) -> None:
        with pytest.raises(config.ConfigError, match="set but empty"):
            config.validate_bind("")

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
    def test_a_deadline_under_the_sse_heartbeat_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """A deadline at or under the heartbeat closes healthy /api/events
        streams on the clock instead of on the peer going away, so it breaks
        live reload rather than merely retiring threads sooner."""
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
        about, so the resolved values reach the module the accept path reads."""
        import recoverage.devserver as devserver
        from recoverage.cli import _resolve_serve_config

        monkeypatch.setenv("RECOVERAGE_MAX_CONNECTIONS", "7")
        monkeypatch.setenv("RECOVERAGE_CLIENT_TIMEOUT", "300")
        resolved = _resolve_serve_config()
        devserver.configure_transport(
            max_connections=resolved.max_connections,
            client_timeout_seconds=resolved.client_timeout,
        )
        try:
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
        assert named == config.KNOWN_VARS

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
