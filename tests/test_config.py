"""Tests for recoverage.config — RECOVERAGE_* env, precedence, validation."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from recoverage import config


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
        )
        assert rendered["port"] == "8001"
        assert rendered["db"] == "auto"
        assert rendered["cors_origin"] == "none"
        assert rendered["log_level"] == "INFO"

    def test_token_is_reported_as_set_without_its_value(self) -> None:
        rendered = config.active_config(
            port=8001,
            bind="127.0.0.1",
            allow_remote=False,
            cors=False,
            cors_origin=["http://a.test"],
            token="s3cret-value",
            db=Path("/tmp/x.db"),
            log_level=logging.WARNING,
        )
        assert rendered["log_level"] == "WARNING"
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
        }

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
