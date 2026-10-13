import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from winre import debug_monitor as D
from winre import remote_driver


RUN_ID = "a" * 32
SESSION = "WinREDbg" + RUN_ID[:12]
ETL = D._REMOTE_ROOT + "\\" + RUN_ID + r"\process.etl"
XML = D._REMOTE_ROOT + "\\" + RUN_ID + r"\process.xml"


def _result(payload, rc=0):
    return SimpleNamespace(returncode=rc, stdout=json.dumps(payload), stderr="")


def _xml():
    return b'''<?xml version="1.0"?>
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-14T10:00:00Z"/></System>
  <EventData><Data Name="ProcessID">123</Data><Data Name="ParentProcessID">1</Data><Data Name="ImageName">C:\\Samples\\sample.exe</Data><Data Name="CommandLine">sample.exe --secret token</Data></EventData></Event>
 <Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-14T10:00:01Z"/></System>
  <EventData><Data Name="ProcessID">124</Data><Data Name="ParentProcessID">123</Data><Data Name="ImageName">C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>
 <Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>2</EventID><TimeCreated SystemTime="2026-10-14T10:00:02Z"/></System>
  <EventData><Data Name="ProcessID">123</Data><Data Name="ParentProcessID">1</Data><Data Name="ImageName">C:\\Samples\\sample.exe</Data></EventData></Event>
 <Event><System><Provider Name="Other-Provider"/><EventID>1</EventID></System>
  <EventData><Data Name="ProcessID">999</Data><Data Name="ImageName">ignored.exe</Data></EventData></Event>
</Events>'''


def test_start_rejects_non_nonce_before_remote_call(monkeypatch):
    called = []
    monkeypatch.setattr("winre.remote_driver.ssh_ps",
                        lambda *a, **k: called.append(True))
    with pytest.raises(D.DebugMonitorError, match="32-character"):
        D.start_remote({"host": "flare"}, "bad")
    assert not called


def test_start_requires_identity_pinned_etw_response(monkeypatch):
    response = {"ok": True, "status": "started", "run_id": RUN_ID,
                "session": SESSION, "etl_path": ETL}
    seen = {}

    def fake_ssh(_cfg, script, timeout):
        seen["script"] = script
        seen["timeout"] = timeout
        return _result(response)

    monkeypatch.setattr("winre.remote_driver.ssh_ps", fake_ssh)
    started = D.start_remote({"host": "flare"}, RUN_ID)
    assert started["session"] == SESSION
    assert "Microsoft-Windows-Kernel-Process" in seen["script"]
    assert "'0x10'" in seen["script"]
    assert "Procmon64" not in seen["script"]
    assert seen["timeout"] == 60


def test_etw_xml_parser_correlates_target_and_children_without_command_lines(tmp_path):
    path = tmp_path / "process.xml"
    path.write_bytes(_xml())
    events, summary = D._parse_events(path, "sample.exe")
    assert summary["target_observed"] is True
    assert summary["target_process_ids"] == [123]
    assert summary["related_process_ids"] == [124]
    assert [e["event"] for e in events] == [
        "process_start", "process_start", "process_stop"]
    assert events[0]["target_process"] is True
    assert events[1]["descendant_of_target"] is True
    assert "command_line" not in events[0]
    assert "secret" not in json.dumps(events)


def test_stop_pulls_hash_checked_etl_and_correlated_jsonl(tmp_path, monkeypatch):
    etl_bytes = b"native ETW trace bytes"
    xml_bytes = _xml()
    remote = {
        "ok": True, "status": "collected", "run_id": RUN_ID,
        "session": SESSION, "etl_path": ETL, "xml_path": XML,
        "etl_bytes": len(etl_bytes), "etl_sha256": hashlib.sha256(etl_bytes).hexdigest(),
        "xml_bytes": len(xml_bytes), "xml_sha256": hashlib.sha256(xml_bytes).hexdigest(),
        "stop_rc": 0, "convert_rc": 0,
    }
    uploaded = {}
    calls = []

    def fake_scp_to(_cfg, local, remote_path):
        uploaded["path"] = remote_path
        uploaded["script"] = Path(local).read_text(encoding="utf-8")

    def fake_ssh(_cfg, command, timeout):
        calls.append((command, timeout))
        return _result(remote)

    def fake_scp_from(_cfg, source, local):
        Path(local).write_bytes(etl_bytes if str(source).endswith("process.etl")
                                else xml_bytes)

    monkeypatch.setattr("winre.remote_driver.scp_to", fake_scp_to)
    monkeypatch.setattr("winre.remote_driver.ssh_run", fake_ssh)
    monkeypatch.setattr("winre.remote_driver.scp_from", fake_scp_from)
    monkeypatch.setattr("winre.remote_driver.ssh_ps",
                        lambda *a, **k: SimpleNamespace(returncode=0,
                                                       stdout="CLEANUP_OK", stderr=""))

    result = D.stop_and_pull(
        {"host": "flare"},
        {"run_id": RUN_ID, "session": SESSION, "etl_path": ETL},
        tmp_path, target_image="sample.exe")
    assert result["status"] == "collected"
    assert set(result["artifacts"]) == {"process.etl", "process_events.jsonl"}
    assert result["summary"]["target_observed"] is True
    assert result["summary"]["related_process_ids"] == [124]
    assert uploaded["path"].endswith("WinRE-debug-stop-" + RUN_ID + ".ps1")
    assert "logman stop" in uploaded["script"]
    assert calls[0][0].startswith("powershell -NoProfile -ExecutionPolicy Bypass -File ")
    assert len(calls[0][0]) < 1000
    assert not (tmp_path / ".process.xml").exists()
    assert json.loads((tmp_path / "META.json").read_text())["run_id"] == RUN_ID


def test_stop_rejects_wrong_session_before_remote_call(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr("winre.remote_driver.scp_to",
                        lambda *a, **k: called.append(True))
    with pytest.raises(D.DebugMonitorError, match="does not match"):
        D.stop_and_pull({}, {"run_id": RUN_ID, "session": "other",
                             "etl_path": ETL}, tmp_path)
    assert not called


def test_monitor_matches_the_debug_safe_staged_sample_name():
    agent = {"debug_run": {"target": {
        "sample_name": "unsafe-sample.exe",
        "staged_path": r"C:\samples\run\x64_unsafe_sample_abc.exe"}}}
    assert remote_driver._debug_target_image(agent, "unsafe-sample.exe") == (
        "x64_unsafe_sample_abc.exe")


def test_monitor_collection_is_not_green_when_the_target_was_not_observed():
    assert remote_driver._debug_monitor_failure({
        "status": "collected", "summary": {"target_observed": False}}) == (
            "target_process_not_observed")
    assert remote_driver._debug_monitor_failure({
        "status": "collected", "summary": {"target_observed": True}}) is None
