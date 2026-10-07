"""Phase 3: the analysis must run on the CONTROL PLANE, not the VM.

The rule from docs/internal/DESIGN.md section 2: the FlareVM is an evidence
producer and nothing else. A box that has just executed arbitrary malware -
whose Python, tshark and libraries are all fair game for a sample that wanted to
tamper with them - must not be the thing that interprets the evidence.

Before this, `orchestrator._post_pull_enrich` ran tshark enrich, beacon
analysis, the Procmon persistence catalog and the emulation diff inside the
orchestrator process, which in remote mode is `ssh flare "python
orchestrator.py --mode local ..."` - i.e. ON THE VM.
"""
import os
import pathlib

import pytest

from winre import analysis, orchestrator


# ------------------------------------------------- the split is declared

def test_the_analysis_module_declares_the_four_host_side_steps():
    src = pathlib.Path(analysis.__file__).read_text(encoding="utf-8")
    for step in ("enrich_pcap", "beacon", "procmon_catalog",
                 "emulation_diff"):
        assert f"def {step}(" in src, f"{step} is not a host-side step"


def test_no_vm_only_analysis_is_reachable_from_the_host_module():
    """windbg_post needs the VM's localhost mcp-windbg; post_mortem needs a live
    process. Neither may be pulled into the control-plane analysis."""
    src = pathlib.Path(analysis.__file__).read_text(encoding="utf-8")
    for bad in ("from winre.windbg_post", "from winre.post_mortem",
                "import windbg_post", "import post_mortem"):
        assert bad not in src, f"{bad} would run on the VM"


# ------------------------------------------------- the orchestrator defers

def test_the_orchestrator_defers_when_told(tmp_path, monkeypatch):
    """WINRE_POST_PULL_OFF_VM=1 is what the driver sets for remote runs."""
    monkeypatch.setenv("WINRE_POST_PULL_OFF_VM", "1")
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)

    called = []

    def _spy(*a, **k):
        called.append(a or k)
        raise AssertionError("the local analysis half must not run off-VM")

    monkeypatch.setattr(orchestrator, "_post_pull_enrich_local", _spy)
    notes = orchestrator._post_pull_enrich(d, "f" * 64, sample_pid=None)
    assert not called, "_post_pull_enrich_local ran on a remote VM"
    assert "deferred_to_control_plane" in notes
    assert set(notes["deferred_to_control_plane"]) == {
        "enrich_pcap", "pcap_beacon", "procmon_post", "emu_diff"}
    assert all("control plane" in v
               for v in notes["deferred_to_control_plane"].values())


def test_the_orchestrator_still_collects_vm_side_evidence(tmp_path, monkeypatch):
    """The live capture and the localhost dump triage are EVIDENCE, so they stay."""
    monkeypatch.setenv("WINRE_POST_PULL_OFF_VM", "1")
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)
    seen = []
    monkeypatch.setattr(orchestrator, "_post_pull_enrich_local",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("must not run")))
    import winre.post_mortem as pm
    import winre.windbg_post as wb
    monkeypatch.setattr(pm, "run_all", lambda *a, **k: seen.append("post_mortem")
                        or {"ok": True})
    monkeypatch.setattr(wb, "analyze_dump", lambda *a, **k: seen.append(
        "windbg_dump") or {"ok": True})
    notes = orchestrator._post_pull_enrich(d, "e" * 64, sample_pid=None)
    assert seen == ["post_mortem", "windbg_dump"], (
        "the VM-side evidence collection was skipped")
    assert "post_mortem" in notes and "windbg_dump" in notes


def test_local_driver_mode_runs_the_analysis_in_process(tmp_path, monkeypatch):
    """With the flag unset (`--driver local`, which is already host-side), the
    analysis runs inline - there is no VM to defer to."""
    monkeypatch.delenv("WINRE_POST_PULL_OFF_VM", raising=False)
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)
    monkeypatch.setattr(orchestrator, "_post_pull_enrich_local",
                        lambda *a, **k: {"emu_diff": {"ok": True}})
    monkeypatch.setattr(orchestrator, "_local_tool", lambda *a, **k: None)
    notes = orchestrator._post_pull_enrich(d, "d" * 64, sample_pid=None)
    assert "deferred_to_control_plane" not in notes
    assert notes.get("emu_diff") == {"ok": True}


# ------------------------------------------------------- the driver sets it

def test_the_driver_tells_the_vm_to_defer():
    """The env var must reach the remote orchestrator, or nothing changes."""
    from winre import remote_driver
    assert 'env["WINRE_POST_PULL_OFF_VM"] = "1"' in \
        pathlib.Path(remote_driver.__file__).read_text(encoding="utf-8")
    # and it must be in the embedded helper that actually gets shipped
    assert "WINRE_POST_PULL_OFF_VM" in remote_driver.REMOTE_DYNAMIC_HELPER


def test_the_driver_runs_the_analysis_locally_after_the_pull():
    from winre import remote_driver
    drv = pathlib.Path(remote_driver.__file__).read_text(encoding="utf-8")
    assert "from . import analysis as _analysis" in drv
    assert "_analysis.run(" in drv
    assert 'stage_meta["post_analysis"]' in drv


# --------------------------------------------------------- it works for real

def test_analysis_run_records_best_effort_and_never_raises(tmp_path):
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)
    out = analysis.run(d)
    assert out["ran_on"] == "control-plane"
    assert set(out["steps"]) == {"enrich_pcap", "pcap_beacon",
                                 "procmon_post", "emu_diff"}
    # every step either succeeded or said why not - none is silently absent
    for name, step in out["steps"].items():
        assert isinstance(step, dict), name
        keys = set(step)
        assert keys & {"ok", "rc", "error", "skipped", "beacons",
                       "persistence", "highlights", "anomalies"}, (
            f"{name}: nothing actionable in {step}")


def test_a_degraded_step_says_so(tmp_path):
    """The failure mode this whole redesign exists to kill: green run, no
    evidence. Every step must be able to say 'skipped: <reason>'."""
    out = analysis.run(tmp_path / "empty")
    skipped = [s for s in out["steps"].values()
               if isinstance(s, dict) and s.get("skipped")]
    assert skipped, "steps that cannot run must report why, not vanish"


def test_the_tshark_step_checks_the_host_not_the_vm(tmp_path, monkeypatch):
    """tshark on the analysis host is OUR tshark. If absent, say so - do not
    silently fall back to whatever the VM left behind."""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
    d = tmp_path / "dynamic"
    (d / "network_raw").mkdir(parents=True)
    got = analysis.enrich_pcap(d)
    assert got.get("skipped") and "analysis host" in got["reason"]