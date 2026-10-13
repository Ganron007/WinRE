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

def test_the_analysis_module_declares_host_side_steps():
    src = pathlib.Path(analysis.__file__).read_text(encoding="utf-8")
    for step in ("enrich_pcap", "beacon", "procmon_catalog",
                 "emulation_diff", "analyst_next", "windbg_dump"):
        assert f"def {step}(" in src, f"{step} is not a host-side step"


def test_memory_collection_is_not_reached_from_the_host_analysis_module():
    """post_mortem needs a live process and remains an evidence-plane step."""
    src = pathlib.Path(analysis.__file__).read_text(encoding="utf-8")
    for bad in ("from winre.post_mortem", "import post_mortem"):
        assert bad not in src, f"{bad} would run on the VM"


# ------------------------------------------------- the orchestrator defers

def test_the_orchestrator_always_defers_interpretation(tmp_path, monkeypatch):
    """The evidence producer cannot opt itself into post-run analysis."""
    monkeypatch.delenv("WINRE_POST_PULL_OFF_VM", raising=False)
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)

    notes = orchestrator._post_pull_enrich(d, "f" * 64, sample_pid=None)
    assert "deferred_to_control_plane" in notes
    assert set(notes["deferred_to_control_plane"]) == {
        "enrich_pcap", "pcap_beacon", "procmon_post", "emu_diff",
        "analyst_next", "windbg_dump"}
    assert all("control plane" in v
               for v in notes["deferred_to_control_plane"].values())


def test_the_orchestrator_collects_without_guest_interpretation(tmp_path, monkeypatch):
    """Raw memory/process collection stays; dump interpretation is deferred."""
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)
    seen = []
    import winre.post_mortem as pm
    monkeypatch.setattr(pm, "run_all", lambda *a, **k: seen.append("post_mortem")
                        or {"ok": True})
    notes = orchestrator._post_pull_enrich(d, "e" * 64, sample_pid=None)
    assert seen == ["post_mortem"]
    assert "post_mortem" in notes
    assert notes["deferred_to_control_plane"]["windbg_dump"]


def test_environment_cannot_enable_guest_side_analysis(tmp_path, monkeypatch):
    """Even an explicit false env value cannot weaken the trust boundary."""
    monkeypatch.setenv("WINRE_POST_PULL_OFF_VM", "0")
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)
    notes = orchestrator._post_pull_enrich(d, "d" * 64, sample_pid=None)
    assert "deferred_to_control_plane" in notes
    assert notes["emu_diff"] is None
    assert "emu_diff" in notes["deferred_to_control_plane"]


def test_the_driver_runs_the_analysis_locally_after_the_pull():
    from winre import remote_driver
    drv = pathlib.Path(remote_driver.__file__).read_text(encoding="utf-8")
    assert "from . import analysis as _analysis" in drv
    assert "_analysis.run(" in drv
    # stage_meta must exist BEFORE this block: the ordering defect that made a
    # successful detonation report "did not run" over 32 files of evidence
    assert "post_analysis=post_analysis" in drv
    assert 'stage_meta["post_analysis"]' not in drv


# --------------------------------------------------------- it works for real

def test_analysis_run_records_best_effort_and_never_raises(tmp_path):
    d = tmp_path / "dynamic"
    d.mkdir(parents=True)
    out = analysis.run(d)
    assert out["ran_on"] == "control-plane"
    assert set(out["steps"]) == {"enrich_pcap", "pcap_beacon",
                                 "procmon_post", "emu_diff", "analyst_next",
                                 "windbg_dump"}
    # every step either succeeded or said why not - none is silently absent
    for name, step in out["steps"].items():
        assert isinstance(step, dict), name
        keys = set(step)
        assert keys & {"ok", "rc", "error", "skipped", "beacons",
                       "persistence", "highlights", "anomalies", "items"}, (
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
