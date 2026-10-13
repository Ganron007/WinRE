import hashlib
import json
from pathlib import Path

import pytest

from winre import corpus_registry as C


RUN1 = "0123456789abcdef0123456789abcdef"
RUN2 = "1123456789abcdef0123456789abcdef"


def _minimal_pe(machine=0x8664, magic=0x20B, characteristics=0x0002):
    raw = bytearray(0x80 + 4 + 20 + 2)
    raw[:2] = b"MZ"
    raw[0x3C:0x40] = (0x80).to_bytes(4, "little")
    raw[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    raw[coff:coff + 2] = machine.to_bytes(2, "little")
    raw[coff + 16:coff + 18] = (0xF0).to_bytes(2, "little")
    raw[coff + 18:coff + 20] = characteristics.to_bytes(2, "little")
    raw[coff + 20:coff + 22] = magic.to_bytes(2, "little")
    return bytes(raw)


SHA = hashlib.sha256(_minimal_pe()).hexdigest()


def test_inventory_deduplicates_bytes_and_preserves_aliases(tmp_path):
    source = tmp_path / "corpus"
    (source / "first").mkdir(parents=True)
    (source / "second").mkdir()
    content = _minimal_pe()
    (source / "first" / "renamed.exe").write_bytes(content)
    (source / "second" / "sample.vir").write_bytes(content)
    registry_path = tmp_path / "internal" / "registry.json"

    result = C.inventory(source, registry_path, "fixture-corpus")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    record = registry["samples"][SHA]
    assert result["files_seen"] == 2
    assert len(registry["samples"]) == 1
    assert len(record["aliases"]) == 2
    assert record["family"] == "unknown"
    assert record["format"] == "pe32_plus"
    assert record["architecture"] == "x64"
    assert record["automatic_execution"] is False


def test_stage_is_hash_keyed_and_verifies_the_copy(tmp_path):
    source = tmp_path / "strange name.vir"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    result = C.stage_sample(source, tmp_path / "stage", registry, "fixture")
    assert result["sha256"] == SHA
    assert Path(result["path"]).read_bytes() == source.read_bytes()
    assert Path(result["path"]).parent.name == SHA
    record = json.loads(registry.read_text(encoding="utf-8"))["samples"][SHA]
    assert record["aliases"][0]["source_path"] == str(source.resolve())


def test_record_run_requires_reason_for_same_mode_repeat(tmp_path):
    source = tmp_path / "one.exe"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    C.inventory(source.parent, registry, "fixture")
    C.record_run(registry, SHA, mode="static", run_id=RUN1,
                 code_revision="abc1234", config_digest="sha256:cfg1",
                 outcome="completed")
    with pytest.raises(ValueError, match="repeat requires --repeat-reason"):
        C.record_run(registry, SHA, mode="static", run_id=RUN2,
                     code_revision="abc1235", config_digest="sha256:cfg2",
                     outcome="completed")
    C.record_run(registry, SHA, mode="agentic", run_id=RUN2,
                 code_revision="abc1235", config_digest="sha256:cfg2",
                 outcome="completed")


def test_history_attestation_is_scoped_and_cannot_claim_no_runs_after_one(tmp_path):
    source = tmp_path / "one.exe"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    C.inventory(source.parent, registry, "fixture")
    att = C.attest_history(registry, SHA,
                           status="no_recorded_winre_run_in_this_registry",
                           operator="analyst", basis="registry import review")
    assert att["attestation"]["scope"] == "this_registry_only"
    C.record_run(registry, SHA, mode="static", run_id=RUN1,
                 code_revision="abc1234", config_digest="sha256:cfg1",
                 outcome="completed")
    with pytest.raises(ValueError, match="cannot attest no recorded runs"):
        C.attest_history(registry, SHA,
                         status="no_recorded_winre_run_in_this_registry",
                         operator="analyst", basis="invalid restatement")


def test_family_classification_requires_cited_evidence(tmp_path):
    source = tmp_path / "one.exe"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    C.inventory(source.parent, registry, "fixture")
    with pytest.raises(ValueError, match="family, operator, basis and evidence"):
        C.classify_family(registry, SHA, family="Example", operator="analyst",
                          basis="", evidence_ref="report.json")
    C.classify_family(registry, SHA, family="Example", operator="analyst",
                      basis="vendor label confirmed against report",
                      evidence_ref="report.json#/family")
    record = json.loads(registry.read_text(encoding="utf-8"))["samples"][SHA]
    assert record["family"] == "Example"
    assert record["family_evidence"][0]["evidence_ref"] == "report.json#/family"


def test_imported_history_requires_evidence_reference(tmp_path):
    source = tmp_path / "one.exe"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    C.inventory(source.parent, registry, "fixture")
    with pytest.raises(ValueError, match="history_imported requires an evidence reference"):
        C.attest_history(registry, SHA, status="history_imported", operator="analyst",
                         basis="reviewed external ledger")


def test_import_history_is_sample_bound_cited_and_preserves_unknowns(tmp_path):
    source = tmp_path / "one.exe"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    C.inventory(source.parent, registry, "fixture")
    history_file = tmp_path / "history.json"
    history_file.write_text(json.dumps({
        "schema": "winre-corpus-run-history/v1",
        "sha256": SHA,
        "runs": [{"legacy_id": "old-pack/static", "mode": "static",
                  "outcome": "unknown", "recorded_at": None}],
    }), encoding="utf-8")
    imported = C.import_history(registry, SHA, history_file,
                                operator="analyst", basis="reviewed old packs",
                                evidence_ref="history.json#/runs")
    assert imported["imported"] == 1
    record = json.loads(registry.read_text(encoding="utf-8"))["samples"][SHA]
    run = record["run_history"][0]
    assert run["legacy_id"] == "old-pack/static"
    assert run["recorded_at"] is None
    assert run["code_revision"] is None
    assert run["history_source"]["evidence_ref"] == "history.json#/runs"
    assert run["history_source"]["history_file_sha256"]
    assert record["history_attestation"]["status"] == "history_imported"
    again = C.import_history(registry, SHA, history_file,
                             operator="analyst", basis="idempotent import",
                             evidence_ref="history.json#/runs")
    assert again["imported"] == 0


def test_conflicting_family_evidence_is_not_silently_overwritten(tmp_path):
    source = tmp_path / "one.exe"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    C.inventory(source.parent, registry, "fixture")
    C.classify_family(registry, SHA, family="FamilyA", operator="analyst",
                      basis="source one", evidence_ref="source-one")
    C.classify_family(registry, SHA, family="FamilyB", operator="analyst",
                      basis="source two", evidence_ref="source-two")
    C.classify_family(registry, SHA, family="FamilyA", operator="analyst",
                      basis="source three", evidence_ref="source-three")
    record = json.loads(registry.read_text(encoding="utf-8"))["samples"][SHA]
    assert record["family"] == "conflicting_evidence"
    assert len(record["family_evidence"]) == 3


def test_import_history_rejects_wrong_sample_hash(tmp_path):
    source = tmp_path / "one.exe"
    source.write_bytes(_minimal_pe())
    registry = tmp_path / "registry.json"
    C.inventory(source.parent, registry, "fixture")
    history_file = tmp_path / "history.json"
    history_file.write_text(json.dumps({
        "schema": "winre-corpus-run-history/v1", "sha256": "0" * 64,
        "runs": [],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="must use the supported schema"):
        C.import_history(registry, SHA, history_file, operator="analyst",
                         basis="test", evidence_ref="history.json")
