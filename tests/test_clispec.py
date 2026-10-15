"""clispec 0.3 for the recoverage CLI. Drives the real entry point."""

from __future__ import annotations

import json
from json import JSONDecodeError

import pytest
from typer.testing import CliRunner

from recoverage import __version__
from recoverage.cli import app

runner = CliRunner()

_EFFECTS = {"read_only", "idempotent", "non_idempotent"}


def test_schema_is_json_without_config(monkeypatch) -> None:
    monkeypatch.setenv("RECOVERAGE_TOKEN", "")
    monkeypatch.delenv("RECOVERAGE_SNAPSHOTS", raising=False)
    result = runner.invoke(app, ["schema"], env={})
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["clispec"] == "0.3"
    assert document["name"] == "recoverage"
    assert document["version"] == __version__
    assert document["output"] == {"tty": "text", "piped": "text"}
    assert document["commands"]
    assert document["errors"]
    names = {arg["name"] for arg in document["global_args"]}
    assert "--output" in names
    assert "--json" in names
    assert {command["effects"] for command in document["commands"]} <= _EFFECTS
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "schema" in help_result.stdout


def test_schema_filters_to_one_command() -> None:
    result = runner.invoke(app, ["schema", "stats"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert [command["name"] for command in document["commands"]] == ["stats"]
    assert document["commands"][0]["cardinality"] == "bounded"
    fields = {field["name"] for field in document["commands"][0]["output_fields"]}
    assert fields == {"items", "total"}


def test_stats_json_is_an_items_envelope(monkeypatch, tmp_path) -> None:
    from coverage_fixture import write_coverage

    directory = tmp_path / "db"
    write_coverage(directory, "GAME", {".text": {"va": 0x1000, "size": 16, "cells": []}})
    monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(directory))
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["-o", "json", "stats"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["total"] == 1
    assert payload["items"][0]["target"] == "GAME"
    assert isinstance(payload["items"][0]["sections"], dict)


def test_text_stats_is_not_json(monkeypatch, tmp_path) -> None:
    from coverage_fixture import write_coverage

    directory = tmp_path / "db"
    write_coverage(directory, "GAME", {".text": {"va": 0x1000, "size": 16, "cells": []}})
    monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(directory))
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["-o", "text", "stats", "--json"])
    assert result.exit_code == 0, result.output
    with pytest.raises(JSONDecodeError):
        json.loads(result.stdout)


def test_json_failure_envelope_is_the_last_stderr_line(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(tmp_path / "missing"))
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["-o", "json", "stats"])
    assert result.exit_code == 1
    assert result.stdout == ""
    line = [item for item in result.stderr.splitlines() if item.strip()][-1]
    body = json.loads(line)
    assert body["error"]["kind"] == "failure"
    assert "coverage not found" in body["error"]["message"]
    assert "hint" in body["error"]
