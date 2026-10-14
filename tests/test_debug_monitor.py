import base64
import hashlib
import json
import re
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
    assert summary["active_sample_processes"][0]["process_id"] == 124
    assert summary["active_sample_processes"][0]["descendant_of_target"] is True
    assert [e["event"] for e in events] == [
        "process_start", "process_start", "process_stop"]
    assert events[0]["target_process"] is True
    assert events[1]["descendant_of_target"] is True
    assert "command_line" not in events[0]
    assert "secret" not in json.dumps(events)


def test_etw_parser_does_not_inherit_relationship_after_pid_reuse(tmp_path):
    rows = [
        ("1", 123, 1, r"C:\Samples\sample.exe"),
        ("1", 124, 123, r"C:\Temp\child.exe"),
        ("2", 123, 1, "sample.exe"),
        ("2", 124, 123, "child.exe"),
        ("1", 124, 1, r"C:\Windows\System32\sshd.exe"),
        ("1", 125, 124, r"C:\Windows\System32\cmd.exe"),
    ]
    body = ['<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">']
    for i, (event_id, pid, ppid, image) in enumerate(rows):
        body.append(
            '<Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/>'
            f'<EventID>{event_id}</EventID><TimeCreated SystemTime="2026-10-14T10:00:0{i}Z"/>'
            '</System><EventData>'
            f'<Data Name="ProcessID">{pid}</Data>'
            f'<Data Name="ParentProcessID">{ppid}</Data>'
            f'<Data Name="ImageName">{image}</Data>'
            '</EventData></Event>')
    body.append('</Events>')
    path = tmp_path / "reuse.xml"
    path.write_text("".join(body), encoding="utf-8")

    events, summary = D._parse_events(path, "sample.exe")

    assert summary["related_process_ids"] == [124]
    assert summary["active_sample_processes"] == []
    grandchild = next(e for e in events
                      if e["event"] == "process_start" and e["process_id"] == 125)
    assert grandchild["descendant_of_target"] is False


def test_etw_parser_matches_truncated_stop_image_name(tmp_path):
    rows = [
        ("1", 6552, 2684,
         r"C:\Samples\x64_sample_a59b2cb9f6c7.exe"),
        ("2", 6552, 2684, "x64_sample_a59"),
    ]
    body = ['<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">']
    for i, (event_id, pid, ppid, image) in enumerate(rows):
        body.append(
            '<Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/>'
            f'<EventID>{event_id}</EventID><TimeCreated SystemTime="2026-10-14T10:00:0{i}Z"/>'
            '</System><EventData>'
            f'<Data Name="ProcessID">{pid}</Data>'
            f'<Data Name="ParentProcessID">{ppid}</Data>'
            f'<Data Name="ImageName">{image}</Data>'
            '</EventData></Event>')
    body.append('</Events>')
    path = tmp_path / "truncated-stop.xml"
    path.write_text("".join(body), encoding="utf-8")

    events, summary = D._parse_events(path, "x64_sample_a59b2cb9f6c7.exe")

    assert summary["target_observed"] is True
    assert summary["active_sample_processes"] == []
    assert events[-1]["event"] == "process_stop"
    assert events[-1]["target_process"] is True


def test_cleanup_skips_remote_work_when_no_sample_process_remains(monkeypatch):
    called = []
    monkeypatch.setattr("winre.remote_driver.ssh_run", lambda *a, **k: called.append(True))
    result = D.cleanup_active_processes({}, RUN_ID, {"active_sample_processes": []})
    assert result == {"ok": True, "status": "clean", "checked": 0,
                      "terminated_process_ids": [], "results": []}
    assert not called


def test_cleanup_uses_run_scoped_pid_and_creation_identity(tmp_path, monkeypatch):
    uploaded = {}
    response = {"run_id": RUN_ID, "ok": True, "status": "terminated",
                "checked": 2, "terminated_process_ids": [2280, 2281],
                "results": [{"process_id": 2280, "status": "terminated"},
                            {"process_id": 2281, "status": "terminated"}]}

    def fake_scp_to(_cfg, local, remote_path):
        uploaded["path"] = remote_path
        uploaded["script"] = Path(local).read_text(encoding="utf-8")

    monkeypatch.setattr("winre.remote_driver.scp_to", fake_scp_to)
    monkeypatch.setattr("winre.remote_driver.ssh_run", lambda *a, **k: _result(response))
    monkeypatch.setattr("winre.remote_driver.ssh_ps",
                        lambda *a, **k: SimpleNamespace(returncode=0,
                                                       stdout="CLEANUP_OK", stderr=""))
    result = D.cleanup_active_processes({"host": "flare"}, RUN_ID, {
        "active_sample_processes": [
            {
                "process_id": 2280, "parent_process_id": 5060,
                "image_name": r"\Device\HarddiskVolume3\Users\Flare-VM\AppData\Local\Temp\ghyted.exe",
                "timestamp_utc": "2026-10-14T06:03:10.912226300-07:00",
                "depth": 2, "target_process": False,
                "descendant_of_target": True,
            },
            {
                "process_id": 2281, "parent_process_id": 2280,
                "image_name": r"\Device\HarddiskVolume3\Windows\System32\conhost.exe",
                "timestamp_utc": "2026-10-14T06:03:11.912226300-07:00",
                "depth": 3, "target_process": False,
                "descendant_of_target": True,
            },
        ],
    })
    assert result["ok"] is True
    assert result["terminated_process_ids"] == [2280, 2281]
    assert uploaded["path"].endswith("WinRE-debug-cleanup-" + RUN_ID + ".ps1")
    assert "CreationDate" in uploaded["script"]
    assert "Stop-Process -Id $processId" in uploaded["script"]
    assert "$candidates=ConvertFrom-Json -InputObject $raw" in uploaded["script"]
    assert "$candidates=@(ConvertFrom-Json" not in uploaded["script"]
    match = re.search(r"FromBase64String\('([^']+)'\)", uploaded["script"])
    assert match
    payload = json.loads(base64.b64decode(match.group(1)))
    assert [item["process_id"] for item in payload] == [2280, 2281]
    assert "taskkill /IM" not in uploaded["script"]


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
        "status": "collected", "summary": {"target_observed": True},
        "cleanup": {"ok": True, "status": "clean"}}) is None


def test_debug_monitor_cannot_be_green_without_process_cleanup():
    assert remote_driver._debug_monitor_failure({
        "status": "collected", "summary": {"target_observed": True}}) == (
            "active_process_cleanup_failed")
