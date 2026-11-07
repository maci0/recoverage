"""Tests for recoverage.ops — the JSON op worker the relumea backend dispatches.

Every test drives the real command: a request is written to stdin, and the
reply (or refusal) is read off stdout.  The live project view is the one seam a
test replaces: it recompiles the reversed sources, so a fixture would need a
toolchain to produce the numbers the assertions name.  The documents it reads
are real ones, written from ``coverage_fixture``.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from coverage_fixture import SECTIONS, cell, coverage_dir, write_coverage
from typer.testing import CliRunner

from recoverage import documents
from recoverage._paths import coverage_source, project_override
from recoverage.cli import app

runner = CliRunner()

PROJECT = "FAKEDLL"
BINARY = b"MZ synthetic target\x00" * 8
SHA256 = hashlib.sha256(BINARY).hexdigest()


def _project(
    root: Path,
    *,
    target: str = PROJECT,
    sections: dict[str, dict[str, Any]] = SECTIONS,
    document: bool = True,
) -> Path:
    """A rebrew project at *root* with one target and a binary named *target*."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / f"{target}.dll").write_bytes(BINARY)
    (root / "rebrew-project.toml").write_text(
        "[project]\n"
        'name = "live"\n'
        f'default_target = "{target}"\n'
        'shared_dir = ""\n'
        "[compiler]\n"
        'profile = "msvc-6.0"\n'
        'includes = ""\n'
        'libs = ""\n'
        f"[targets.{target}]\n"
        f'binary = "{target}.dll"\n'
        'reversed_dir = "src"\n'
        f'module = "{target}"\n'
        'format = "pe"\n',
        encoding="utf-8",
    )
    if document:
        write_coverage(coverage_dir(root), target, sections)
    return root


def _load(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make the project's live view the document set just written."""
    snapshots = documents.load_all(coverage_dir(root))
    monkeypatch.setattr(documents, "load_all", lambda _source: snapshots)
    monkeypatch.setattr(documents, "unreadable", lambda _source: ())
    monkeypatch.delenv("RECOVERAGE_SNAPSHOTS", raising=False)
    return root


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A project whose live view is the synthetic document set."""
    return _load(_project(tmp_path), monkeypatch)


#: A section whose only cell is "none": it carries no coverage signal, so the
#: gate skips it instead of failing a project that never recorded it.
UNTRACKED = {
    **SECTIONS,
    ".bss": {
        "va": 0x10003000,
        "size": 0x1000,
        "fileOffset": 0,
        "unitBytes": 16,
        "columns": 8,
        "cells": [cell(0, 16, "none")],
    },
}


def _call(
    request: Mapping[str, Any] | str,
    *args: str,
    op: str = "recoverage.coverage_gate",
) -> tuple[int, str]:
    """Invoke ``ops call`` over stdin, returning the exit code and stdout."""
    body = request if isinstance(request, str) else json.dumps(request)
    result = runner.invoke(app, ["ops", "call", op, *args], input=body)
    return result.exit_code, result.stdout


def _reply(
    request: Mapping[str, Any] | str, *args: str, op: str = "recoverage.coverage_gate"
) -> dict[str, Any]:
    code, out = _call(request, *args, op=op)
    assert code == 0, out
    parsed: dict[str, Any] = json.loads(out)
    return parsed


def _refusal(
    request: Mapping[str, Any] | str, *args: str, op: str = "recoverage.coverage_gate"
) -> dict[str, Any]:
    code, out = _call(request, *args, op=op)
    assert code == 2, out
    body: dict[str, Any] = json.loads(out)
    assert set(body) == {"error", "detail", "status"}
    return body


def _gate(root: Path, **extra: Any) -> dict[str, Any]:
    return {"project_dir": str(root), "sha256": SHA256, "min_coverage": 0, **extra}


def _export(root: Path, output_format: str = "json") -> dict[str, Any]:
    return {"project_dir": str(root), "sha256": SHA256, "format": output_format}


class TestGate:
    def test_pass(self, project: Path) -> None:
        """.text is 112 of its 4096 bytes; .data is 16 of 1024."""
        reply = _reply(_gate(project, min_coverage=0))
        assert reply["passed"] is True
        assert reply["min_coverage"] == 0.0
        assert [(row["target"], row["section"], row["status"]) for row in reply["results"]] == [
            (PROJECT, ".text", "PASS"),
            (PROJECT, ".data", "PASS"),
        ]
        assert reply["results"][0]["coverage_pct"] == 2.73
        assert reply["results"][1]["coverage_pct"] == 1.56
        assert "reason" not in reply

    def test_failure_is_a_reply_not_a_refusal(self, project: Path) -> None:
        reply = _reply(_gate(project, min_coverage=100))
        assert reply["passed"] is False
        assert [row["status"] for row in reply["results"]] == ["FAIL", "FAIL"]
        assert reply["results"][0]["coverage_pct"] == 2.73

    def test_whole_number_threshold_is_accepted(self, project: Path) -> None:
        reply = _reply(_gate(project, min_coverage=50))
        assert reply["min_coverage"] == 50.0
        assert reply["passed"] is False

    def test_section_filter_narrows_the_verdicts(self, project: Path) -> None:
        reply = _reply(_gate(project, min_coverage=0, section=".text"))
        assert [row["section"] for row in reply["results"]] == [".text"]

    def test_untracked_sections_are_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """.bss has cells but none of them records a match state."""
        root = _load(_project(tmp_path, sections=UNTRACKED), monkeypatch)
        reply = _reply(_gate(root, min_coverage=0))
        assert reply["passed"] is True
        skipped = [row for row in reply["results"] if row["status"] == "SKIP"]
        assert skipped == [
            {
                "target": PROJECT,
                "section": ".bss",
                "status": "SKIP",
                "reason": "no tracked cells; coverage is not recorded",
            }
        ]

    def test_untracked_section_fails_when_requested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _load(_project(tmp_path, sections=UNTRACKED), monkeypatch)
        reply = _reply(_gate(root, min_coverage=0, section=".bss"))
        assert reply["passed"] is False
        assert reply["results"] == [
            {
                "target": PROJECT,
                "section": ".bss",
                "status": "FAIL",
                "reason": "no tracked cells; coverage is not recorded for this section",
            }
        ]

    def test_only_untracked_sections_check_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _load(_project(tmp_path, sections={".bss": UNTRACKED[".bss"]}), monkeypatch)
        reply = _reply(_gate(root, min_coverage=0))
        assert reply["passed"] is False
        assert reply["reason"] == "no tracked sections; nothing was checked"

    def test_missing_section_checks_nothing(self, project: Path) -> None:
        reply = _reply(_gate(project, min_coverage=0, section=".rodata"))
        assert reply["passed"] is False
        assert reply["reason"] == "no sections matched; nothing was checked"

    def test_threshold_out_of_range(self, project: Path) -> None:
        body = _refusal(_gate(project, min_coverage=200))
        assert body["error"] == "invalid-request"
        assert body["status"] == 400
        assert "min_coverage" in body["detail"]

    def test_negative_threshold(self, project: Path) -> None:
        body = _refusal(_gate(project, min_coverage=-1))
        assert body["error"] == "invalid-request"


class TestExport:
    def test_json(self, project: Path) -> None:
        reply = _reply(_export(project), op="recoverage.coverage_export")
        assert reply["format"] == "json"
        assert reply["content_type"] == "application/json"
        parsed = json.loads(reply["body"])
        assert parsed["total"] == 1
        assert [row["target"] for row in parsed["items"]] == [PROJECT]
        assert set(parsed["items"][0]["sections"]) == {".text", ".data"}

    def test_csv(self, project: Path) -> None:
        reply = _reply(_export(project, "csv"), op="recoverage.coverage_export")
        assert reply["content_type"] == "text/csv; charset=utf-8"
        rows = list(csv.reader(io.StringIO(reply["body"])))
        assert rows[0] == [
            "target",
            "section",
            "size_bytes",
            "total_cells",
            "exact",
            "reloc",
            "near_match",
            "stub",
            "coverage_pct",
        ]
        assert [row[1] for row in rows[1:]] == [".text", ".data"]

    def test_markdown(self, project: Path) -> None:
        reply = _reply(_export(project, "md"), op="recoverage.coverage_export")
        assert reply["content_type"] == "text/markdown; charset=utf-8"
        lines = reply["body"].splitlines()
        assert lines[0] == f"## {PROJECT}"
        assert "| Section | Size | Cells | EXACT | RELOC | NEAR | STUB | Coverage |" in lines
        assert any(line.startswith("| .text") for line in lines)

    @pytest.mark.parametrize("output_format", ["JSON", "yaml", ""])
    def test_unknown_format(self, project: Path, output_format: str) -> None:
        body = _refusal(_export(project, output_format), op="recoverage.coverage_export")
        assert body["error"] == "invalid-request"
        assert body["status"] == 400


class TestTargetResolution:
    def test_unknown_digest(self, project: Path) -> None:
        request = {**_gate(project), "sha256": "0" * 64}
        body = _refusal(request)
        assert body["error"] == "target-not-found", body
        assert body["status"] == 404

    @pytest.mark.parametrize("digest", ["abc", "A" * 64, "g" * 64])
    def test_malformed_digest(self, project: Path, digest: str) -> None:
        body = _refusal({**_gate(project), "sha256": digest})
        assert body["error"] == "invalid-request"
        assert "sha256" in body["detail"]

    def test_missing_document(self, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(documents, "load_all", lambda _source: {})
        body = _refusal(_gate(project))
        assert body["error"] == "coverage-not-found"
        assert body["status"] == 404

    def test_unreadable_document(self, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(documents, "load_all", lambda _source: {})
        monkeypatch.setattr(
            documents, "unreadable", lambda _source: (("coverage-FAKEDLL.toml", PROJECT, "bad"),)
        )
        body = _refusal(_gate(project))
        assert body["error"] == "engine-error"
        assert body["status"] == 500
        assert "unreadable" in body["detail"]


class TestProjectConfinement:
    def test_relative_project_dir(self, project: Path) -> None:
        body = _refusal({**_gate(project), "project_dir": "relative"})
        assert body["error"] == "invalid-request"
        assert "absolute" in body["detail"]

    def test_not_a_rebrew_project(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        body = _refusal(_gate(empty))
        assert body["error"] == "invalid-request"
        assert "rebrew-project.toml" in body["detail"]

    def test_outside_the_workspace(self, project: Path) -> None:
        other = project.with_name(f"{project.name}-outside")
        other.mkdir()
        body = _refusal(_gate(project), "--workspace", str(other))
        assert body["error"] == "invalid-request"
        assert "workspace" in body["detail"]

    def test_workspace_must_be_absolute(self, project: Path) -> None:
        code, _out = _call(_gate(project), "--workspace", "relative")
        assert code == 2

    def test_workspace_containing_the_project(self, project: Path) -> None:
        reply = _reply(_gate(project, min_coverage=0), "--workspace", str(project.parent))
        assert reply["passed"] is True


class TestRequests:
    def test_unknown_op(self, project: Path) -> None:
        body = _refusal(_gate(project), op="recoverage.nope")
        assert body["error"] == "unknown-op"
        assert body["status"] == 404

    @pytest.mark.parametrize("body", ["not json", "", '{"a": }'])
    def test_not_json(self, project: Path, body: str) -> None:
        refusal = _refusal(body)
        assert refusal["error"] == "invalid-request"
        assert "JSON" in refusal["detail"]

    def test_missing_field(self, project: Path) -> None:
        body = _refusal({"project_dir": str(project), "sha256": SHA256})
        assert body["error"] == "invalid-request"
        assert "min_coverage" in body["detail"]

    def test_unknown_field(self, project: Path) -> None:
        body = _refusal(_gate(project, min_coverage=0, extra=True))
        assert body["error"] == "invalid-request"
        assert "extra" in body["detail"]

    def test_wrong_type(self, project: Path) -> None:
        body = _refusal(_gate(project, min_coverage="50"))
        assert body["error"] == "invalid-request"
        assert "min_coverage" in body["detail"]

    def test_request_must_be_an_object(self, project: Path) -> None:
        body = _refusal("[1, 2]")
        assert body["error"] == "invalid-request"


class TestProjectOverride:
    """A request's project wins over RECOVERAGE_SNAPSHOTS for its own call."""

    def test_coverage_source_prefers_the_override(
        self, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exported = tmp_path / "offline"
        exported.mkdir()
        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(exported))
        with project_override(project):
            assert coverage_source() == project

    def test_load_all_sees_the_requested_project(
        self, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exported = tmp_path / "offline"
        exported.mkdir()
        seen: list[Path] = []
        original = documents.load_all
        snapshots = original(coverage_dir(project))

        def fake_load_all(source: Path) -> Mapping[str, Any]:
            seen.append(source)
            return snapshots

        monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(exported))
        monkeypatch.setattr(documents, "load_all", fake_load_all)
        reply = _reply(_gate(project, min_coverage=0))
        assert reply["passed"] is True
        assert seen == [project.resolve()]


def test_map_matches_dashboard_and_json_export(project: Path) -> None:
    request = {"project_dir": str(project), "sha256": SHA256}
    result = _reply(request, op="recoverage.coverage_map")
    exported = _reply(_export(project), op="recoverage.coverage_export")
    row = json.loads(exported["body"])["items"][0]
    assert result["stats"] == {k: v for k, v in row.items() if k != "target"}
    assert result["sections"][".text"]["cells"]
    assert result["section_cell_stats"][".text"]["total_cells"] == len(
        result["sections"][".text"]["cells"]
    )


def test_decomp_dev_export_uses_rebrew_report(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.report

    def report(cfg: Any, output: Path) -> dict[str, Any]:
        assert cfg.target_name == PROJECT
        output.write_text('{"version": 2, "measures": {}, "units": []}', encoding="utf-8")
        return {}

    monkeypatch.setattr(rebrew.report, "generate_decomp_dev_report", report)
    result = _reply(_export(project, "decomp.dev"), op="recoverage.coverage_export")
    assert result["content_type"] == "application/json"
    assert json.loads(result["body"]) == {"version": 2, "measures": {}, "units": []}


def test_decomp_dev_export_real_project(tmp_path: Path) -> None:
    """The wire body is Rebrew's real objdiff report, not cell coverage."""
    import shutil

    from rebrew.config import load_config
    from rebrew.report import generate_decomp_dev_report

    retained = next(
        (
            parent / "rebrew-test-projects/bench-rebrew"
            for parent in Path(__file__).resolve().parents
            if (parent / "rebrew-test-projects/bench-rebrew").is_dir()
        ),
        Path(),
    )
    if not (retained / "original/bench.exe").is_file():
        pytest.skip("retained rebrew-test-projects fixture is unavailable")
    root = tmp_path / "project"
    shutil.copytree(retained, root, ignore=shutil.ignore_patterns(".rebrew", "*.lock"))
    binary = root / "original/bench.exe"
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    output = tmp_path / "report.json"
    summary = generate_decomp_dev_report(load_config(root, target="bench"), output)
    expected = json.loads(output.read_text(encoding="utf-8"))
    reply = _reply(
        {"project_dir": str(root), "sha256": digest, "format": "decomp.dev"},
        op="recoverage.coverage_export",
    )
    report = json.loads(reply["body"])
    assert reply["format"] == "decomp.dev"
    assert reply["content_type"] == "application/json"
    assert report == expected
    assert set(report) == {"version", "measures", "units"}
    assert report["version"] == 2
    measures = report["measures"]
    assert measures["total_functions"] == summary["total_functions"] > 0
    assert measures["matched_functions"] == summary["matched_functions"]
    assert measures["total_code"] == summary["total_code"] > 0
    assert measures["matched_code"] == summary["matched_code"]
    assert isinstance(report["units"], list)
    assert len(report["units"]) == summary["units"] > 0
    for unit in report["units"]:
        assert isinstance(unit["name"], str)
        assert isinstance(unit["measures"], dict)
        assert unit["functions"]
        for function in unit["functions"]:
            assert isinstance(function["name"], str)
            assert isinstance(function["address"], int)
            assert function["size"] > 0
            assert 0 <= function["fuzzy_match_percent"] <= 100


def test_gate_metric_requires_verified_evidence(project: Path) -> None:
    assert _reply(_gate(project))["metric"] == "identified"
    assert _refusal(_gate(project, metric="verified"))["status"] == 409
    assert _refusal(_gate(project, metric="other"))["status"] == 400
