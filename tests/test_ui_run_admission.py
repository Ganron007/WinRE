"""UI run-admission controls (2026-11-07 full review + 2026-11-08 Brief 4).

F1: the /run POST reserved the single-run lock and THEN validated the
sample path - the early return leaked `running=True` and every later run
409'd until the console restarted. The validation must happen before the
reservation, and any pre-spawn failure must release it.

F2: the live board tracked the ENGINE mode ("agentic"), so a dbg or
dynamic run's status read the wrong pack section (dbg//dynamic/). The
POST must store the capability-resolved PACK mode - the driver's own
resolve_pack_mode is the one authority.

Brief 4 (2026-11-08): Bind UI admission directly to snapshot gate ledger.
If snapshot gate is blocked in enforce mode, /run (with dynamic/dbg) and
/stages/<sha>/dynamic must reject with 412 Precondition Failed.
"""
from __future__ import annotations

import json
from pathlib import Path

from winre.ui import app as ui_app

SHA = "d" * 64


def _client(tmp_path, monkeypatch):
    ui_app._run_state["running"] = False
    monkeypatch.setattr(ui_app, "LOGS_DIR", tmp_path)
    monkeypatch.setattr(ui_app, "_run_pipeline_in_thread",
                        lambda *a, **k: ui_app._run_state.update({"running": False}))
    # never touch the real VM from these tests
    monkeypatch.setattr(ui_app.remote_driver, "run_remote_pipeline",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("no pipeline in admission tests")))
    from winre import snapshot_gate
    monkeypatch.setattr(snapshot_gate, "mode", lambda: "enforce")
    monkeypatch.setattr(snapshot_gate, "gate_status", lambda *a, **k: {
        "mode": "enforce", "marker": True, "ledger_clean": True, "blocked": False,
        "reason": "armed (test mock)", "vm_state": {"last_action": "verified_clean"}
    })
    return ui_app.create_app().test_client()


def test_a_bad_sample_path_does_not_leak_the_run_reservation(tmp_path,
                                                             monkeypatch):
    """F1 (2026-11-07): a typo'd path bricked the runner until restart."""
    client = _client(tmp_path, monkeypatch)
    r = client.post("/run", data={"sample": str(tmp_path / "missing.exe")})
    assert r.status_code == 400
    assert not ui_app._run_state["running"], (
        "the reservation must be released (or never taken) on validation "
        "failure")
    # the console is still usable: a valid admission path is no longer 409
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r2 = client.post("/run", data={"sample": str(sample)})
    assert r2.status_code == 303, r2.get_data(as_text=True)
    assert not ui_app._run_state["running"] or ui_app._run_state["running"]


def test_run_admission_stores_the_pack_mode_not_the_engine_mode(tmp_path,
                                                                monkeypatch):
    """F2 (2026-11-07): dbg/dynamic runs must track the dbg/dynamic section
    from intake, not the agentic section."""
    client = _client(tmp_path, monkeypatch)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = client.post("/run", data={
        "sample": str(sample), "mode": "agentic", "agentic_dbg": "on"})
    assert r.status_code == 303
    assert ui_app._run_state["mode"] == "dbg", ui_app._run_state["mode"]
    # cleanup for the next test in the same session
    ui_app._run_state["running"] = False


def test_dynamic_admission_resolves_the_dynamic_section(tmp_path,
                                                        monkeypatch):
    client = _client(tmp_path, monkeypatch)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = client.post("/run", data={
        "sample": str(sample), "mode": "agentic", "dynamic": "on"})
    assert r.status_code == 303
    assert ui_app._run_state["mode"] == "dynamic", ui_app._run_state["mode"]
    ui_app._run_state["running"] = False


def test_conflicting_capabilities_are_refused_before_reservation(tmp_path,
                                                                 monkeypatch):
    """dbg + dynamic in one run is over-budget; refuse with 400 and keep
    the console usable."""
    client = _client(tmp_path, monkeypatch)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = client.post("/run", data={
        "sample": str(sample), "mode": "agentic",
        "agentic_dbg": "on", "dynamic": "on"})
    assert r.status_code == 400
    assert not ui_app._run_state["running"]


def test_run_dynamic_or_dbg_refused_with_412_when_gate_blocked(tmp_path,
                                                               monkeypatch):
    """Brief 4: /run with dynamic or dbg returns 412 when gate is blocked."""
    client = _client(tmp_path, monkeypatch)
    from winre import snapshot_gate
    monkeypatch.setattr(snapshot_gate, "gate_status", lambda *a, **k: {
        "mode": "enforce", "marker": False, "ledger_clean": False, "blocked": True,
        "reason": "dirty (detonated previously)", "vm_state": {"last_action": "detonated"}
    })
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")

    # dynamic request when blocked -> 412
    r_dyn = client.post("/run", data={
        "sample": str(sample), "mode": "agentic", "dynamic": "on"})
    assert r_dyn.status_code == 412
    j_dyn = r_dyn.get_json()
    assert j_dyn["ok"] is False
    assert j_dyn["blocked"] is True
    assert "VM snapshot gate blocked" in j_dyn["error"]
    assert not ui_app._run_state["running"]

    # dbg request when blocked -> 412
    r_dbg = client.post("/run", data={
        "sample": str(sample), "mode": "agentic", "agentic_dbg": "on"})
    assert r_dbg.status_code == 412
    j_dbg = r_dbg.get_json()
    assert j_dbg["ok"] is False
    assert j_dbg["blocked"] is True
    assert "VM snapshot gate blocked" in j_dbg["error"]
    assert not ui_app._run_state["running"]

    # static mode when blocked -> proceeds (303)
    r_static = client.post("/run", data={
        "sample": str(sample), "mode": "agentic"})
    assert r_static.status_code == 303
    ui_app._run_state["running"] = False


def test_stage_dynamic_refused_with_412_when_gate_blocked(tmp_path,
                                                          monkeypatch):
    """Brief 4: /stages/<sha>/dynamic returns 412 when gate is blocked."""
    client = _client(tmp_path, monkeypatch)
    from winre import snapshot_gate
    monkeypatch.setattr(snapshot_gate, "gate_status", lambda *a, **k: {
        "mode": "enforce", "marker": False, "ledger_clean": False, "blocked": True,
        "reason": "dirty (detonated previously)", "vm_state": {"last_action": "detonated"}
    })
    pack_dir = tmp_path / SHA
    pack_dir.mkdir(parents=True, exist_ok=True)

    r = client.post(f"/stages/{SHA}/dynamic", json={"mode": "agentic", "confirm_snapshot": True})
    assert r.status_code == 412
    j = r.get_json()
    assert j["ok"] is False
    assert j["blocked"] is True
    assert "VM snapshot gate blocked" in j["error"]
    assert not ui_app._run_state["running"]
