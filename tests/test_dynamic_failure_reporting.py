import inspect
from pathlib import Path

from winre import remote_driver
from winre import orchestrator
from winre.evidence import EvidencePack
from winre.manifest import write_pack_manifests
from winre.pipeline import _report


def test_local_detonation_skips_zip_but_ssh_job_keeps_archive_support():
    local_runner = inspect.getsource(orchestrator._run_local_windows)
    job = (Path(orchestrator.LOCAL_JOB_PS1)
           .read_text(encoding="utf-8"))

    assert 'job_args.append("-SkipZip")' in local_runner
    assert "[switch]$SkipZip" in job
    assert 'if ($SkipZip)' in job
    assert 'Log "DONE ok=true zip_skipped=true"' in job
    assert "ZipFile]::Open($ZipPath, 'Create')" in job
    assert "CompressionLevel]::Fastest" in job
    assert 'Log "META.job.json written"' in job
    assert 'Log "copying current job log into archive"' in job


def test_local_job_wait_does_not_depend_on_descendant_pipe_eof(tmp_path, monkeypatch):
    job_script = tmp_path / "flare_dynamic_job.ps1"
    job_script.write_text("# test stub", encoding="utf-8")
    work_root = tmp_path / "local-runs"
    dynamic_dir = tmp_path / "dynamic"
    dynamic_dir.mkdir()
    monkeypatch.setattr(orchestrator, "LOCAL_JOB_PS1", job_script)
    monkeypatch.setenv("FLARE_LOCAL_WORK_ROOT", str(work_root))
    monkeypatch.setattr(orchestrator, "_kill_stale_local", lambda: None)
    monkeypatch.setattr(orchestrator, "_apply_detonation_verdict",
                        lambda meta, trace, dyn_dir: None)

    class FakeProcess:
        pid = 4242
        returncode = None

        def __init__(self, stdout, stderr):
            self.stdout = stdout
            self.stderr = stderr

        def wait(self, timeout):
            assert timeout == 301
            self.stdout.write(b"job completed")
            self.stderr.write(b"diagnostic warning")
            self.returncode = 0
            return 0

    def fake_popen(args, *, stdout, stderr):
        assert stdout is not orchestrator.subprocess.PIPE
        assert stderr is not orchestrator.subprocess.PIPE
        assert "-SkipZip" in args
        assert args[11] == str(work_root / ("a" * 64) / ("c" * 32))
        return FakeProcess(stdout, stderr)

    monkeypatch.setattr(orchestrator.subprocess, "Popen", fake_popen)
    meta = {"artifacts": {}, "run_id": "c" * 32}
    result = orchestrator._run_local_windows(
        "a" * 64, tmp_path / "sample.exe", dynamic_dir,
        1, "CreateFileW", False, meta)

    assert result["job_rc"] == 0
    assert result["job_stdout_tail"] == "job completed"
    assert result["job_stderr_tail"] == "diagnostic warning"
    assert "job_timeout" not in result


def test_local_job_refuses_to_reuse_a_run_workspace(tmp_path, monkeypatch):
    job_script = tmp_path / "flare_dynamic_job.ps1"
    job_script.write_text("# test stub", encoding="utf-8")
    work_base = tmp_path / "local-runs"
    sha = "a" * 64
    run_id = "c" * 32
    existing = work_base / sha / run_id
    existing.mkdir(parents=True)
    dynamic_dir = tmp_path / "dynamic"
    dynamic_dir.mkdir()
    monkeypatch.setattr(orchestrator, "LOCAL_JOB_PS1", job_script)
    monkeypatch.setenv("FLARE_LOCAL_WORK_ROOT", str(work_base))

    def unexpected_popen(*args, **kwargs):
        raise AssertionError("reused run ID must not launch a job")

    monkeypatch.setattr(
        orchestrator.subprocess, "Popen", unexpected_popen,
    )

    result = orchestrator._run_local_windows(
        sha, tmp_path / "sample.exe", dynamic_dir,
        1, "CreateFileW", False, {"artifacts": {}, "run_id": run_id})

    assert result["ok"] is False
    assert "already exists" in result["error"]


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
        "content_mismatch_details": [{
            "path": "changed.bin",
            "remote_size_bytes": 2,
            "received_size_bytes": 2,
            "remote_sha256": h1,
            "received_sha256": h2,
        }],
        "truncated": False,
    }


def test_remote_inventory_preserves_zero_byte_file_size(monkeypatch):
    empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    class Result:
        returncode = 0
        stdout = (
            '[{"path":"frida.stdout.txt","size_bytes":0,'
            f'"sha256":"{empty_hash}"}}]'
        )
        stderr = ""

    monkeypatch.setattr(remote_driver, "ssh_ps",
                        lambda cfg, script, timeout: Result())

    inventory = remote_driver.remote_file_inventory({}, "C:/WinRE/out")

    assert inventory == {"frida.stdout.txt": (0, empty_hash)}


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
