"""UI run-admission controls (2026-11-07 full review).

F1: the /run POST reserved the single-run lock and THEN validated the
sample path - the early return leaked `running=True` and every later run
409'd until the console restarted. The validation must happen before the
reservation, and any pre-spawn failure must release it.

F2: the live board tracked the ENGINE mode ("agentic"), so a dbg or
dynamic run's status read the wrong pack section (dbg//dynamic/). The
POST must store the capability-resolved PACK mode - the driver's own
resolve_pack_mode is the one authority.
"""
from __future__ import annotations

import json

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
