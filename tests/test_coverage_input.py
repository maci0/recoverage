"""The coverage envelope binds a closed set of staged inputs."""

import copy
import hashlib
import json

import pytest

contract = pytest.importorskip(
    "rebrew.coverage_input_contract", reason="requires Rebrew 6.23.1 with coverage_input_contract"
)
CoverageInputError = contract.CoverageInputError
canonical_coverage_input = contract.canonical_coverage_input
coverage_input_digest = contract.coverage_input_digest
verify_coverage_readset = contract.verify_coverage_readset


def envelope():
    return {
        "version": 1,
        "analysis_manifest": "d" * 64,
        "verification_digest": hashlib.sha256(b"[]").hexdigest(),
        "source_revision": "a" * 64,
        "generation": "c" * 32,
        "binary_sha256": "b" * 64,
        "target": "target",
        "readset": [
            {
                "path": "src/a.c",
                "present": True,
                "origin": "source",
                "digest": hashlib.sha256(b"source").hexdigest(),
                "size": 6,
            },
            {
                "path": "src/missing.json",
                "present": False,
                "origin": "analysis",
                "digest": "",
                "size": 0,
            },
        ],
    }


def test_codec_is_canonical_and_deterministic():
    value = envelope()
    canonical = canonical_coverage_input(value)
    assert json.loads(canonical) == value
    assert canonical.startswith(b'{"analysis_manifest":')
    assert coverage_input_digest(value) == hashlib.sha256(canonical).hexdigest()
    assert canonical == canonical_coverage_input(dict(reversed(list(value.items()))))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v.update(version=True),
        lambda v: v.update(source_revision="bad"),
        lambda v: v.update(extra=1),
        lambda v: v["readset"].reverse(),
        lambda v: v["readset"].append(copy.deepcopy(v["readset"][-1])),
        lambda v: v["readset"][0].update(path="../outside"),
        lambda v: v["readset"][0].update(path="src/e\u0301.c"),
        lambda v: v["readset"][0].update(path="a" * 1025),
        lambda v: v["readset"][0].update(size=True),
        lambda v: v["readset"][0].update(origin=["source"]),
        lambda v: v["readset"][1].update(digest="a" * 64),
    ],
)
def test_malformed_envelopes_are_refused(mutate):
    value = envelope()
    mutate(value)
    with pytest.raises(CoverageInputError):
        canonical_coverage_input(value)


def test_presence_content_omission_and_symlink(tmp_path):
    value = envelope()
    source = tmp_path / "src"
    source.mkdir()
    file = source / "a.c"
    file.write_bytes(b"source")
    paths = {e["path"] for e in value["readset"]}
    verify_coverage_readset(tmp_path, value, paths)
    with pytest.raises(CoverageInputError):
        verify_coverage_readset(tmp_path, value, {"src/a.c"})
    file.write_bytes(b"forged")
    with pytest.raises(CoverageInputError):
        verify_coverage_readset(tmp_path, value, paths)
    file.write_bytes(b"source")
    (source / "missing.json").write_bytes(b"")
    with pytest.raises(CoverageInputError):
        verify_coverage_readset(tmp_path, value, paths)
    (source / "missing.json").unlink()
    file.unlink()
    file.symlink_to(tmp_path / "external")
    with pytest.raises(CoverageInputError):
        verify_coverage_readset(tmp_path, value, paths)


def test_match_credit_requires_consistent_real_result():
    from rebrew.coverage_input_contract import verified_match_status

    result = {
        "va": "0x1000",
        "size": 4,
        "status": "EXACT",
        "match_count": 4,
        "total": 4,
        "obj_size": 4,
        "reloc_count": 0,
        "mismatches": [],
    }
    assert verified_match_status(result, 0x1000, 4) == "EXACT"
    with pytest.raises(CoverageInputError):
        verified_match_status({**result, "status": "RELOC", "reloc_count": 1}, 0x1000, 4)
    assert verified_match_status({**result, "status": "STUB"}, 0x1000, 4) is None
    for forged in (
        {**result, "match_count": 3},
        {**result, "va": "0x1001"},
        {**result, "obj_size": 3},
        {**result, "reloc_count": 1},
        {**result, "mismatches": [{}]},
    ):
        with pytest.raises(CoverageInputError):
            verified_match_status(forged, 0x1000, 4)


def test_rebrew_reader_discovers_present_and_absent_inputs(tmp_path):
    from rebrew.coverage_input_contract import rebrew_coverage_paths
    from test_ops import _project

    root = _project(tmp_path / "project")
    (root / "rebrew-functions.toml").write_text("")
    inventory = root / "src/function_structure.json"
    inventory.write_text("{}")
    paths = rebrew_coverage_paths(root, "FAKEDLL")
    assert "rebrew-project.toml" in paths
    assert "FAKEDLL.dll" in paths
    assert "src/function_structure.json" in paths
    assert "rebrew-functions.toml" in paths
    assert any("verify" in name for name in paths)
    assert any(not (root / name).exists() for name in paths)


def test_raw_link_compile_commands_are_confined_before_discovery(tmp_path):
    from rebrew.coverage_input_contract import rebrew_coverage_paths
    from test_ops import _project

    root = _project(tmp_path / "project")
    config = root / "rebrew-project.toml"
    config.write_text(config.read_text() + '\nraw_link = "build/output.exe"\n')
    build = root / "build"
    build.mkdir()
    source = root / "src/a.c"
    source.write_text("int x;")
    commands = build / "compile_commands.json"
    commands.write_text(json.dumps([{"directory": str(root), "file": "src/a.c"}]))
    paths = rebrew_coverage_paths(root, "FAKEDLL")
    assert "build/compile_commands.json" in paths
    assert "src/a.c" in paths
    commands.write_text(json.dumps([{"directory": str(tmp_path), "file": "outside.c"}]))
    with pytest.raises(CoverageInputError):
        rebrew_coverage_paths(root, "FAKEDLL")
    commands.write_text(json.dumps([{"directory": ".", "file": "src/a.c"}]))
    with pytest.raises(CoverageInputError):
        rebrew_coverage_paths(root, "FAKEDLL")


def test_verification_record_set_requires_qualified_exact_results():
    from rebrew.coverage_input_contract import verification_records_digest

    row = {
        "verification_id": "v1",
        "source": "src/a.c",
        "source_sha256": "a" * 64,
        "va": 4096,
        "size": 4,
        "status": "EXACT",
        "match_count": 4,
        "total": 4,
        "obj_size": 4,
        "reloc_count": 0,
        "result_digest": "b" * 64,
    }
    assert verification_records_digest([]) == hashlib.sha256(b"[]").hexdigest()
    assert len(verification_records_digest([row])) == 64
    for forged in (
        {**row, "source": "../other"},
        {**row, "status": "RELOC"},
        {**row, "match_count": 3},
        {**row, "reloc_count": 1},
        {**row, "result_digest": "bad"},
    ):
        with pytest.raises(CoverageInputError):
            verification_records_digest([forged])
    with pytest.raises(CoverageInputError):
        verification_records_digest([row, row])
    with pytest.raises(CoverageInputError):
        verification_records_digest([row, {**row, "verification_id": "v2"}])


def test_execution_rechecks_plan_target_and_verification_set(tmp_path):
    from rebrew.coverage_input_contract import (
        coverage_input_digest,
        plan_coverage_readset,
        validate_coverage_execution,
    )
    from test_ops import SHA256, _project

    root = _project(tmp_path / "project")
    (root / "rebrew-functions.toml").write_text("")
    (root / "src/function_structure.json").write_text("[]")
    entries = [
        {
            **entry,
            "origin": "analysis" if entry["path"] == "src/function_structure.json" else "source",
        }
        for entry in plan_coverage_readset(root, "FAKEDLL")
    ]
    value = {**envelope(), "target": "FAKEDLL", "binary_sha256": SHA256, "readset": entries}
    digest = coverage_input_digest(value)
    validate_coverage_execution(root, "FAKEDLL", SHA256, value, digest, [])
    with pytest.raises(CoverageInputError):
        validate_coverage_execution(root, "FAKEDLL", "f" * 64, value, digest, [])
    with pytest.raises(CoverageInputError):
        validate_coverage_execution(root, "FAKEDLL", SHA256, value, "f" * 64, [])
    from rebrew.coverage_input_contract import verification_records_digest

    row = {
        "verification_id": "v",
        "source": "rebrew-functions.toml",
        "source_sha256": "a" * 64,
        "va": 4096,
        "size": 4,
        "status": "EXACT",
        "match_count": 4,
        "total": 4,
        "obj_size": 4,
        "reloc_count": 0,
        "result_digest": "b" * 64,
    }
    unowned = {
        **value,
        "verification_digest": verification_records_digest([row]),
        "readset": [
            {**entry, "origin": "analysis"} if entry["path"] == row["source"] else entry
            for entry in value["readset"]
        ],
    }
    with pytest.raises(CoverageInputError):
        validate_coverage_execution(
            root, "FAKEDLL", SHA256, unowned, coverage_input_digest(unowned), [row]
        )
    (root / "rebrew-functions.toml").write_text("forged")
    with pytest.raises(CoverageInputError):
        validate_coverage_execution(root, "FAKEDLL", SHA256, value, digest, [])


def test_execution_requires_unambiguous_analysis_inventory_extent(tmp_path):
    from rebrew.coverage_input_contract import (
        coverage_input_digest,
        plan_coverage_readset,
        validate_coverage_execution,
        verification_records_digest,
    )
    from test_ops import SHA256, _project

    root = _project(tmp_path / "project")
    (root / "rebrew-functions.toml").write_text("")
    (root / "src/a.c").write_text("source")
    inventory = root / "src/function_structure.json"
    row = {
        "verification_id": "v",
        "source": "src/a.c",
        "source_sha256": hashlib.sha256(b"source").hexdigest(),
        "va": 4096,
        "size": 4,
        "status": "EXACT",
        "match_count": 4,
        "total": 4,
        "obj_size": 4,
        "reloc_count": 0,
        "result_digest": "b" * 64,
    }

    def value_for(items):
        inventory.write_text(json.dumps(items))
        entries = [
            {
                **entry,
                "origin": "analysis"
                if entry["path"] == "src/function_structure.json"
                else "source",
            }
            for entry in plan_coverage_readset(root, "FAKEDLL")
        ]
        return {
            **envelope(),
            "target": "FAKEDLL",
            "binary_sha256": SHA256,
            "readset": entries,
            "verification_digest": verification_records_digest([row]),
        }

    good = value_for([{"va": "0x1000", "size": 4}])
    validate_coverage_execution(root, "FAKEDLL", SHA256, good, coverage_input_digest(good), [row])
    wrong_source = {**row, "source_sha256": "a" * 64}
    changed = {**good, "verification_digest": verification_records_digest([wrong_source])}
    with pytest.raises(CoverageInputError):
        validate_coverage_execution(
            root, "FAKEDLL", SHA256, changed, coverage_input_digest(changed), [wrong_source]
        )
    for items in (
        [{"va": 4096, "size": 5}],
        [{"va": 4096, "size": 4}, {"va": 4096, "size": 4}],
        [{"va": 4096, "size": 4, "_generated_by": "rebrew coverage catalog"}],
    ):
        value = value_for(items)
        with pytest.raises(CoverageInputError):
            validate_coverage_execution(
                root, "FAKEDLL", SHA256, value, coverage_input_digest(value), [row]
            )
