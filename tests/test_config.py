"""Tests for recoverage.config — RECOVERAGE_* env, precedence, validation."""

from __future__ import annotations

import logging
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
