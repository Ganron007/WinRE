"""Skipped network summarization must not suppress behavior summaries."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from winre import summarize_dynamic


def test_skip_network_preserves_network_record_and_writes_behavior_summaries(
        tmp_path, monkeypatch, capsys):
    delegated = {
        "status": "delegated_external",
        "collector": "FakeNet-NG guest capture",
    }
    network_path = tmp_path / "network.json"
    network_path.write_text(json.dumps(delegated), encoding="utf-8")
    marker_before = network_path.read_bytes()

    write_path = r"C:\Windows\System32\wlogon.dll"
    trace = [
        {"type": "call", "api": "WriteFile", "invocation_id": "w-1",
         "pid": 4242, "decoded": {"path": write_path,
                                    "write_intent": True, "writes": True}},
        {"type": "ret", "api": "WriteFile", "invocation_id": "w-1",
         "success": True, "write_succeeded": True, "bytes_written": 73728,
         "effect": "written"},
    ]
    (tmp_path / "frida_trace.jsonl").write_text(
        "\n".join(json.dumps(event) for event in trace), encoding="utf-8")
    (tmp_path / "procmon.csv").write_text(
        'Process Name,Operation,Path\n'
        'sample.exe,WriteFile,C:\\Windows\\System32\\wlogon.dll\n',
        encoding="utf-8")

    monkeypatch.setattr(sys, "argv", [
        "summarize_dynamic.py", "--out-dir", str(tmp_path),
        "--sample-name", "sample.exe", "--skip-network",
    ])
    assert summarize_dynamic.main() == 0
    printed = json.loads(capsys.readouterr().out)

    assert printed == {"frida": "ok", "procmon": "ok", "network": "preserved"}
    assert network_path.read_bytes() == marker_before

    frida = json.loads((tmp_path / "frida_summary.json").read_text(encoding="utf-8"))
    assert frida["file_effects"][write_path]["successful_writes"] == 1
    assert frida["file_effects"][write_path]["bytes_written"] == 73728

    procmon = json.loads((tmp_path / "procmon_summary.json").read_text(encoding="utf-8"))
    assert procmon["rows_sample"] == 1
    assert procmon["top_operations"] == [["WriteFile", 1]]


def test_default_summary_still_writes_guest_network_summary(
        tmp_path, monkeypatch, capsys):
    raw = tmp_path / "network_raw"
    raw.mkdir()
    (raw / "fakenet.txt").write_text(
        "callback.example", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "summarize_dynamic.py", "--out-dir", str(tmp_path),
        "--sample-name", "sample.exe",
    ])

    assert summarize_dynamic.main() == 0
    capsys.readouterr()
    network = json.loads((tmp_path / "network.json").read_text(encoding="utf-8"))
    assert network["status"] == "ok"
    assert network["domains_guess"] == ["callback.example"]


def test_remote_capture_job_keeps_guest_network_summarization_enabled():
    script = (Path(__file__).resolve().parents[1]
              / "winre" / "flare_dynamic_job.ps1").read_text(encoding="utf-8")
    assert '$summaryArgs += "--skip-network"' not in script
    assert "& $Python $summaryPy @summaryArgs" in script
    assert "status = \"delegated_external\"" not in script
    assert 'external_capture_requested = ($NetworkMode -eq "passive")' in script
    assert 'if (-not (Test-Path $FakeNetExe))' in script
    assert '$summaryErrors += "$summaryName missing"' in script
    assert "$jobOk = (-not $jobError)" in script
    assert "ok = $jobOk" in script
    assert 'Log ("DONE ok={0}' in script
