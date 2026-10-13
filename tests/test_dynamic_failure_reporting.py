from winre import remote_driver
from winre.evidence import EvidencePack
from winre.manifest import write_pack_manifests
from winre.pipeline import _report


def test_dynamic_label_distinguishes_failed_run_from_not_run():
    assert remote_driver._dynamic_status_label({
        "ok": False, "detonation_ran": True,
    }) == "failed-after-start"
    assert remote_driver._dynamic_status_label({
        "ok": False, "detonation_ran": False,
    }) == "not-run"
    assert remote_driver._dynamic_status_label(None) == "not-requested"


def test_inventory_diff_names_missing_unexpected_and_mismatched_paths():
    h1, h2 = "a" * 64, "b" * 64
    diff = remote_driver._inventory_diff(
        {"missing.bin": (1, h1), "changed.bin": (2, h1),
         "same.bin": (3, h1)},
        {"extra.bin": (1, h1), "changed.bin": (2, h2),
         "same.bin": (3, h1)},
    )

    assert diff == {
        "missing_local_count": 1,
        "unexpected_local_count": 1,
        "content_mismatch_count": 1,
        "missing_local": ["missing.bin"],
        "unexpected_local": ["extra.bin"],
        "content_mismatch": ["changed.bin"],
        "truncated": False,
    }


def test_pipeline_report_labels_a_launched_but_incomplete_dynamic_run(tmp_path):
    sha = "a" * 64
    pack = EvidencePack(tmp_path, sha, "dynamic").ensure()
    dynamic = {
        "ok": False,
        "detonation_ran": True,
        "job_timeout": True,
        "error": "remote and received file inventories differ",
        "frida_events": 635,
        "findings": {
            "run_observed": True,
            "evidence_complete": False,
            "verdict": {"level": "unknown", "confidence": "low"},
        },
    }

    report = _report(pack, sha, {}, dynamic, {}, composition={"level": "unknown"})

    assert report["phase"] == "static+dynamic-incomplete"
    assert report["dynamic"]["run_observed"] is True
    assert report["dynamic"]["evidence_complete"] is False
    assert report["dynamic"]["job_timeout"] is True
    assert any("coverage gaps" in x for x in report["analyst_next"])
    assert any("Restore FlareVM" in x for x in report["analyst_next"])


def test_failed_dynamic_manifest_uses_stage_pid_when_job_meta_is_missing(tmp_path):
    sha = "b" * 64
    pack = EvidencePack(tmp_path, sha, "dynamic").ensure()
    stage = {
        "run_id": "c" * 32,
        "ok": False,
        "detonation_ran": True,
        "sample_pid": 5536,
        "job_timeout": True,
    }
    pack.write("dynamic", "STAGE.json", stage)

    result = write_pack_manifests(
        pack.root, run_id="c" * 32, sha256=sha, mode="dynamic",
        dynamic_requested=True)
    memory = result["stage_manifests"]["dynamic"]["coverage"]["memory"]

    assert memory["status"] == "partial"
    assert "no sample process" not in memory["reason"]
    assert "timed out" in memory["collector_reason"]
    root_memory = result["artifact_manifest"]["coverage"]["memory"]
    assert root_memory["status"] == "partial"
    assert "no sample process" not in root_memory["reason"]
