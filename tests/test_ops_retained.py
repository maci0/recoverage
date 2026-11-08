"""The op worker consumes retained, verified inputs, not the live workspace."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from coverage_fixture import coverage_dir
from test_ops import BINARY, SHA256, _project

from recoverage import documents, ops

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("rebrew.coverage_input_contract") is None,
    reason="requires the Rebrew 6.22 candidate",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_for(root: Path, store: Path, marker: str) -> dict:
    _project(root)
    source = root / "src" / "marker.c"
    source.write_text(marker)
    (root / "rebrew-functions.toml").write_text("")
    (root / "src/function_structure.json").write_text("[]")
    files = []
    for path in (
        root / "rebrew-project.toml",
        source,
        root / "rebrew-functions.toml",
        root / "src/function_structure.json",
    ):
        data = path.read_bytes()
        key = digest(data)
        (store / key).write_bytes(data)
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "digest": key,
                "size": len(data),
                "key": key,
            }
        )
    (store / SHA256).write_bytes(BINARY)
    return {
        "project_dir": str(root),
        "sha256": SHA256,
        "files": files,
        "rebrew_target": "FAKEDLL",
        "binary_key": SHA256,
    }


def call(config, op, request):
    status, body = ops.dispatch(config, op, json.dumps(request).encode())
    return status, json.loads(body)


def bound_request(config, request):
    """Model the trusted dispatch envelope; backend custody is tested separately."""
    from rebrew.coverage_input_contract import coverage_input_digest

    status, plan = call(config, "recoverage.coverage_plan", request)
    assert status == 200, plan
    source_paths = set(plan["source_paths"]) | {"rebrew-project.toml"}
    entries = [
        {**row, "origin": "source" if row["path"] in source_paths else "analysis"}
        for row in plan["readset"]
    ]
    envelope = {
        "version": 1,
        "source_revision": digest(b"source revision"),
        "analysis_manifest": digest(b"analysis capture"),
        "generation": "a" * 32,
        "binary_sha256": request["sha256"],
        "target": request["rebrew_target"],
        "verification_digest": digest(b"[]"),
        "readset": entries,
    }
    return {
        **request,
        "coverage_input": envelope,
        "coverage_input_digest": coverage_input_digest(envelope),
        "verification_records": [],
    }


@pytest.mark.parametrize(
    "op,extra",
    [
        ("recoverage.coverage_map", {}),
        ("recoverage.coverage_gate", {"min_coverage": 0}),
        ("recoverage.coverage_export", {"format": "json"}),
        ("recoverage.coverage_export", {"format": "decomp.dev"}),
    ],
)
def test_ops_use_project_specific_retained_snapshot(tmp_path, monkeypatch, op, extra):
    workspace = tmp_path / "workspace"
    store = tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    one = request_for(workspace / "one", store, "one")
    two = request_for(workspace / "two", store, "two")
    snapshots = documents.load_all(coverage_dir(workspace / "one"))
    seen = []

    def load(root, _target, _trusted):
        root = Path(root)
        seen.append((root / "src/marker.c").read_text())
        assert root not in (workspace / "one", workspace / "two")
        return snapshots["FAKEDLL"]

    monkeypatch.setattr(ops, "_trusted_snapshot", load)
    if extra.get("format") == "decomp.dev":
        import rebrew.report

        def report(cfg, output, *, trusted):
            assert trusted is not None
            seen.append((cfg.root / "src/marker.c").read_text())
            output.write_text("{}")

        monkeypatch.setattr(rebrew.report, "generate_decomp_dev_report", report)
    # The live files have changed after publication.
    for root in (workspace / "one", workspace / "two"):
        (root / "src/marker.c").write_text("live")
    config = ops.WorkerConfig(workspace=workspace, filestore=store)
    for request in (one, two):
        status, body = call(config, op, {**bound_request(config, request), **extra})
        assert status == 200, body
    assert seen == ["one", "two"]


def test_snapshot_tamper_and_changed_during_operation_are_refused(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = tmp_path / "store"
    store.mkdir()
    req = request_for(workspace / "project", store, "original")
    config = ops.WorkerConfig(workspace=workspace, filestore=store)
    entry = req["files"][1]
    (store / entry["key"]).write_text("tampered")
    assert call(config, "recoverage.coverage_map", req)[0] == 400
    (store / entry["key"]).write_text("original")
    assert call(config, "recoverage.coverage_map", {**req, "rebrew_target": "other"})[0] == 400
    (store / SHA256).write_bytes(b"tampered binary")
    assert call(config, "recoverage.coverage_map", req)[0] == 400
    (store / SHA256).write_bytes(BINARY)
    snapshots = documents.load_all(coverage_dir(workspace / "project"))
    req = bound_request(config, req)

    def mutate(root, _target, _trusted):
        (Path(root) / "src/marker.c").write_text("changed")
        return snapshots["FAKEDLL"]

    monkeypatch.setattr(ops, "_trusted_snapshot", mutate)
    assert call(config, "recoverage.coverage_map", req)[0] == 409
    assert (workspace / "project/src/marker.c").read_text() == "original"


def test_snapshot_without_helper_fails_closed(tmp_path, monkeypatch):
    import rebrew.ops

    workspace = tmp_path / "workspace"
    store = tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    request = request_for(workspace / "project", store, "retained")
    monkeypatch.delattr(rebrew.ops, "retained_target_snapshot")
    status, body = call(
        ops.WorkerConfig(workspace=workspace, filestore=store), "recoverage.coverage_map", request
    )
    assert status == 500
    assert "pinned rebrew" in body["detail"]


def test_external_inventory_is_refused(tmp_path):
    workspace = tmp_path / "workspace"
    store = tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    request = request_for(workspace / "project", store, "retained")
    config = Path(request["project_dir"]) / "rebrew-project.toml"
    config.write_text(config.read_text() + f'\ninventory_file = "{tmp_path}/external.json"\n')
    data = config.read_bytes()
    key = digest(data)
    (store / key).write_bytes(data)
    request["files"][0] = {
        "path": "rebrew-project.toml",
        "digest": key,
        "size": len(data),
        "key": key,
    }
    status, body = call(
        ops.WorkerConfig(workspace=workspace, filestore=store), "recoverage.coverage_map", request
    )
    assert status == 400, body


def test_real_retained_project_map(tmp_path):
    fixture = next(
        (
            parent / "rebrew-test-projects/bench-rebrew"
            for parent in Path(__file__).resolve().parents
            if (parent / "rebrew-test-projects/bench-rebrew").is_dir()
        ),
        Path(),
    )
    if not (fixture / "original/bench.exe").is_file():
        pytest.skip("retained rebrew-test-projects fixture is unavailable")
    import shutil

    source = tmp_path / "fixture"
    shutil.copytree(fixture, source, ignore=shutil.ignore_patterns(".rebrew", "*.lock"))
    project_config = source / "rebrew-project.toml"
    project_config.write_text(
        project_config.read_text().replace(
            '[targets."bench".crt_sources]\n'
            'MSVCRT = "../../../../zine/tools/MSVC600/VC98/CRT/SRC"\n',
            "",
        )
    )
    fixture = source
    workspace = tmp_path / "workspace"
    store = tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    files = []
    for path in fixture.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.suffix == ".lock":
            continue
        relative = path.relative_to(fixture)
        if relative.parts[0] not in ("src", "db") and path.name not in (
            "rebrew-project.toml",
            "rebrew-functions.toml",
            "rebrew-data.toml",
        ):
            continue
        data = path.read_bytes()
        if len(data) > 1024 * 1024:
            continue
        key = digest(data)
        (store / key).write_bytes(data)
        files.append({"path": relative.as_posix(), "digest": key, "size": len(data), "key": key})
    binary = (fixture / "original/bench.exe").read_bytes()
    binary_sha = digest(binary)
    (store / binary_sha).write_bytes(binary)
    request = {
        "project_dir": str(workspace / "unused"),
        "sha256": binary_sha,
        "files": files,
        "rebrew_target": "bench",
        "binary_key": binary_sha,
    }
    config = ops.WorkerConfig(workspace=workspace, filestore=store)
    request = bound_request(config, request)
    status, body = call(config, "recoverage.coverage_map", request)
    assert status == 200, body
    assert body["sections"]
    assert any(section["cells"] for section in body["sections"].values())

    from rebrew.workspace.status import TrustedCoverage

    live = ops.coverage_map(
        ops.WorkerConfig(),
        ops.MapRequest(project_dir=str(fixture), sha256=binary_sha),
        TrustedCoverage(()),
    )
    assert body["stats"] == live["stats"]
    assert body["sections"] == live["sections"]
    assert body["stats"]["by_status"].get("EXACT", 0) == 0
    assert body["stats"]["coverage_metric"] == "identified"
    section = body["stats"]["sections"][".text"]
    assert section["verified_bytes"] == 0 and section["verified_pct"] == 0
    gate_base = {**request, "min_coverage": 1, "section": ".text"}
    identified_status, identified = call(config, "recoverage.coverage_gate", gate_base)
    assert (
        identified_status == 200 and identified["metric"] == "identified" and identified["passed"]
    )
    verified_status, verified = call(
        config, "recoverage.coverage_gate", {**gate_base, "metric": "verified"}
    )
    assert verified_status == 200 and verified["metric"] == "verified" and not verified["passed"]
    assert verified["results"][0]["verified_bytes"] == 0
    assert verified["results"][0]["coverage_pct"] == verified["results"][0]["verified_pct"] == 0
    export_status, exported = call(
        config, "recoverage.coverage_export", {**request, "format": "json"}
    )
    assert export_status == 200
    assert json.loads(exported["body"])["items"][0]["sections"] == body["stats"]["sections"]
    csv_status, csv = call(config, "recoverage.coverage_export", {**request, "format": "csv"})
    assert csv_status == 200 and "coverage_metric,verified_bytes,verified_pct" in csv["body"]
    md_status, md = call(config, "recoverage.coverage_export", {**request, "format": "md"})
    assert md_status == 200 and "Verified bytes | Verified %" in md["body"]
    assert "Identified coverage" in md["body"]
    table_lines = [line for line in md["body"].splitlines() if line.startswith("|")]
    assert table_lines and len({len(line.split("|")) for line in table_lines}) == 1
    untrusted = ops.coverage_map(
        ops.WorkerConfig(), ops.MapRequest(project_dir=str(fixture), sha256=binary_sha)
    )
    assert untrusted["stats"]["by_status"].get("EXACT", 0) > 0


def test_coverage_plan_reports_staged_readset_and_absences(tmp_path):
    workspace = tmp_path / "workspace"
    store = tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    request = request_for(workspace / "project", store, "retained")
    other = request_for(workspace / "other", store, "different")
    config = ops.WorkerConfig(workspace=workspace, filestore=store)
    (workspace / "project/src/marker.c").write_text("live modified")
    status, body = call(config, "recoverage.coverage_plan", request)
    assert status == 200, body
    assert body["source_paths"] == ["src/marker.c"]
    assert body["config"]["target"] == "FAKEDLL"
    assert body["config"]["binary"] == "FAKEDLL.dll"
    assert body["config"]["reversed_dir"] == "src"
    assert body["config"]["inventory"] == "src/function_structure.json"
    rows = {row["path"]: row for row in body["readset"]}
    assert rows["rebrew-project.toml"]["present"]
    assert rows["FAKEDLL.dll"]["digest"] == SHA256
    assert rows["src/marker.c"]["digest"] == digest(b"retained")
    other_status, other_body = call(config, "recoverage.coverage_plan", other)
    assert other_status == 200, other_body
    other_rows = {row["path"]: row for row in other_body["readset"]}
    assert other_rows["FAKEDLL.dll"]["digest"] == SHA256
    assert other_rows["src/marker.c"]["digest"] == digest(b"different")
    assert any(
        not row["present"] and not row["digest"] and row["size"] == 0 for row in rows.values()
    )
    assert [row["path"] for row in body["readset"]] == sorted(rows)
    assert (
        call(
            config,
            "recoverage.coverage_plan",
            {"project_dir": str(workspace / "project"), "sha256": SHA256},
        )[0]
        == 400
    )


def test_retained_scoring_requires_bound_envelope(tmp_path):
    from rebrew.coverage_input_contract import coverage_input_digest

    workspace, store = tmp_path / "workspace", tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    request = request_for(workspace / "project", store, "source")
    config = ops.WorkerConfig(workspace=workspace, filestore=store)
    status, body = call(config, "recoverage.coverage_map", request)
    assert status == 409 and body["error"] == "coverage-input-invalid"
    partial = {**request, "coverage_input_digest": "a" * 64}
    assert call(config, "recoverage.coverage_map", partial)[0] == 409
    bound = bound_request(config, request)
    without_records = {key: val for key, val in bound.items() if key != "verification_records"}
    assert call(config, "recoverage.coverage_map", without_records)[0] == 409
    empty = {"project_dir": request["project_dir"], "sha256": SHA256, "coverage_input": {}}
    assert call(config, "recoverage.coverage_map", empty)[0] != 200
    changed = {**bound["coverage_input"], "binary_sha256": "a" * 64}
    assert (
        call(
            config,
            "recoverage.coverage_map",
            {
                **bound,
                "coverage_input": changed,
                "coverage_input_digest": coverage_input_digest(changed),
            },
        )[0]
        == 409
    )
    assert (
        call(config, "recoverage.coverage_map", {**bound, "coverage_input_digest": "b" * 64})[0]
        == 409
    )


def test_recorded_real_exact_result_passes_verified_gate(tmp_path):
    from rebrew.coverage_input_contract import coverage_input_digest, verification_records_digest

    fixtures = Path(__file__).parent / "fixtures/coverage"
    recorded = json.loads((fixtures / "worker-comparisons.json").read_text())
    item = next(value for value in recorded["outcomes"] if value["result"]["status"] == "EXACT")
    binary = (fixtures / "comparison-reference.elf").read_bytes()
    assert digest(binary) == recorded["binary_sha256"]
    workspace, store = tmp_path / "workspace", tmp_path / "store"
    workspace.mkdir()
    store.mkdir()
    source = item["candidate"].encode()
    config_bytes = (
        b'[project]\nname="candidate"\ndefault_target="sample"\nshared_dir=""\n'
        b'[targets.sample]\nbinary="original/sample"\nformat="elf"\narch="x86_64"\n'
        b'reversed_dir="src"\nmodule="SAMPLE"\n[compiler]\nprofile="gcc-14.2.0"\n'
        b'cflags="-O2"\nbase_cflags="-c"\n'
    )
    metadata = (
        b'format = 3\n["SAMPLE.0x00401120"]\nsize = 4\nstatus = "STUB"\n'
        b'file = "src/add.c"\nsymbol = "add"\nkind = "FUNCTION"\nname = "add"\n'
    )
    inventory = json.dumps([{"va": 0x401120, "size": 4, "name": "add"}]).encode()
    entries = []
    for path, data in (
        ("rebrew-project.toml", config_bytes),
        ("src/add.c", source),
        ("src/function_structure.json", inventory),
        ("rebrew-functions.toml", metadata),
    ):
        key = digest(data)
        (store / key).write_bytes(data)
        entries.append({"path": path, "digest": key, "size": len(data), "key": key})
    binary_sha = digest(binary)
    (store / binary_sha).write_bytes(binary)
    request = {
        "project_dir": str(workspace / "unused"),
        "sha256": binary_sha,
        "files": entries,
        "rebrew_target": "sample",
        "binary_key": binary_sha,
    }
    worker = ops.WorkerConfig(workspace=workspace, filestore=store)
    request = bound_request(worker, request)
    result = item["result"]
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    record = {
        "verification_id": "actual-worker-result",
        "source": result["source"],
        "source_sha256": digest(source),
        "va": int(result["va"], 0),
        "size": result["size"],
        "status": result["status"],
        "match_count": result["match_count"],
        "total": result["total"],
        "obj_size": result["obj_size"],
        "reloc_count": result["reloc_count"],
        "result_digest": digest(encoded),
    }
    envelope = {
        **request["coverage_input"],
        "verification_digest": verification_records_digest([record]),
    }
    request = {
        **request,
        "coverage_input": envelope,
        "coverage_input_digest": coverage_input_digest(envelope),
        "verification_records": [record],
    }
    status, body = call(worker, "recoverage.coverage_map", request)
    assert status == 200, body
    assert body["stats"]["by_status"].get("EXACT") == 1
    assert body["stats"]["sections"][".text"]["verified_bytes"] == 4
    status, gate = call(
        worker,
        "recoverage.coverage_gate",
        {**request, "min_coverage": 0.01, "section": ".text", "metric": "verified"},
    )
    assert status == 200 and gate["passed"] and gate["metric"] == "verified"
    assert gate["results"][0]["verified_bytes"] == 4
    assert gate["results"][0]["coverage_pct"] == gate["results"][0]["verified_pct"] > 0


def test_verified_bytes_are_clipped_to_authenticated_extents():
    from types import SimpleNamespace

    from rebrew.workspace.status import TrustedCoverage, TrustedVerification

    section = SimpleNamespace(
        va=0x1000,
        cells=(
            SimpleNamespace(start=0, end=12, state="exact"),
            SimpleNamespace(start=12, end=16, state="unknown"),
        ),
    )
    trusted = TrustedCoverage((TrustedVerification("src/a.c", 0x1000, 4, "EXACT", 4),))
    assert ops._verified_section_bytes(section, trusted) == 4
    assert ops._verified_section_bytes(section, TrustedCoverage(())) == 0
    assert ops._verified_section_bytes(SimpleNamespace(va=None, cells=section.cells), trusted) == 0
