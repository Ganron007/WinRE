from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from winre import casepack, reporting, remote_driver, run_nonce, snapshot_gate, vm_gate  # noqa: E402
from winre.evidence import EvidencePack  # noqa: E402


SHA = "a" * 64
RUN_ID = "b" * 32


def test_external_run_id_is_normalized_and_validated():
    assert run_nonce.normalize_run_id(RUN_ID.upper()) == RUN_ID
    with pytest.raises(ValueError, match="32 hexadecimal"):
        run_nonce.normalize_run_id("not-a-run-id")


def test_evidencepack_stamps_stage_artifacts_from_run_meta(tmp_path):
    pack = EvidencePack(tmp_path, SHA, mode="agentic").ensure()
    (pack.root / "META.json").write_text(json.dumps({"run_id": RUN_ID}))

    artifact = pack.write("deep", "deep.json", {"verdict": "malicious"})

    assert json.loads(artifact.read_text())["run_id"] == RUN_ID
    assert pack.manifest()["run_id"] == RUN_ID


def test_case_archive_carries_execution_identity_in_manifest_and_timeline(
    tmp_path, monkeypatch
):
    pack = EvidencePack(tmp_path / "logs", SHA, mode="dynamic").ensure()
    (pack.root / "META.json").write_text(json.dumps({
        "sha256": SHA, "mode": "dynamic", "pack_mode": "dynamic",
        "run_id": RUN_ID, "status": "completed",
    }))
    (pack.root / "audit.json").write_text(json.dumps({"run_id": RUN_ID}))
    (pack.stages["dynamic"] / "STAGE.json").write_text(json.dumps({
        "run_id": RUN_ID, "ok": True,
    }))
    (pack.stages["dynamic"] / "network_intel.json").write_text(
        json.dumps({"events": []}))
    monkeypatch.setattr(casepack, "find_7z", lambda: None)

    result = casepack.build_case(pack.root, SHA, mode="dynamic")

    assert result["ok"] is True
    assert result["run_id"] == RUN_ID
    import zipfile
    with zipfile.ZipFile(result["path"]) as archive:
        manifest = json.loads(archive.read("case_manifest.json"))
        timeline = json.loads(archive.read("case_timeline.json"))
    assert manifest["run_id"] == RUN_ID
    assert timeline["run_id"] == RUN_ID


def test_published_case_index_carries_execution_identity(tmp_path):
    pack = EvidencePack(tmp_path / "logs", SHA, mode="agentic").ensure()
    (pack.root / "META.json").write_text(json.dumps({
        "sha256": SHA, "mode": "agentic", "run_id": RUN_ID,
    }))

    result = reporting.publish_case(pack.root, tmp_path / "published")

    case = json.loads((Path(result["dest"]) / "CASE.json").read_text())
    assert case["run_id"] == RUN_ID


def test_remote_driver_preserves_parent_execution_identity_before_gate(
    tmp_path, monkeypatch
):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ test sample")
    monkeypatch.setattr(remote_driver, "LOCAL_LOGS", tmp_path / "logs")
    monkeypatch.setattr(remote_driver, "flare_cfg", lambda: {})
    monkeypatch.setattr(snapshot_gate, "reset_session", lambda: None)
    monkeypatch.setattr(snapshot_gate, "execution_plan", lambda **_kw: {
        "ok": False, "error": "test refusal",
    })
    monkeypatch.setattr(vm_gate, "require_clean_vm", lambda *_a, **_kw: (True, None))

    result = remote_driver.run_remote_pipeline(
        sample, mode="static", run_id=RUN_ID,
    )

    assert result["aborted"] is True
    sha = result["sha"]
    meta = json.loads((tmp_path / "logs" / sha / "static" / "META.json").read_text())
    assert meta["run_id"] == RUN_ID
