#!/usr/bin/env python3
"""tests/test_contracts.py — machine-checked contracts for the RevAI handoff
of 2026-09-27 (items 1-6).

These are the assertions that used to be eyeballed run by run. Each test
names the contract and the failure it prevents, so a regression is a red
test with a sentence attached, not a surprise on the next sample.

Run:  python -m pytest tests/ -q          (no VM, no network, no samples)

Covered:
  1. execution plan  - `enforce` allows ONE execution per clean restore; a
     --dynamic + --agentic-dbg run is refused UP FRONT, and the plan is
     recorded for audit.json.
  2. verdict contract- a deep dive (or report) with no verdict is NOT green;
     unmet_expectations names it; the flat verdict fields are readable at
     the top level of deep.json.
  3. append-only     - a static-only run never destroys a previous dynamic
     pack in the same mode section; it is moved to previous_runs/ and
     pointed at.
  4. clock skew      - recorded as a diagnostic, never used as the freshness
     gate; the VM-side clock state file contract is documented in setup.
  5. run nonce       - freshness is a VALUE comparison: correct stamp passes,
     wrong stamp fails, missing stamp fails CLOSED with a sync hint, and no
     code path compares timestamps any more.
  6. applicability   - an unpacked stub records x64dbg as not_applicable
     rather than as a tool failure; the run line distinguishes "unknown"
     from "no verdict".
"""
from __future__ import annotations

import inspect
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from winre import audit as audit_mod            # noqa: E402
from winre import evidence as ev               # noqa: E402
from winre import run_nonce                    # noqa: E402
from winre import snapshot_gate as gate        # noqa: E402
from winre.evidence import EvidencePack        # noqa: E402


# --- helpers ---------------------------------------------------------------

def _pack(tmp_path: Path, mode: str = "agentic") -> EvidencePack:
    return EvidencePack(tmp_path, "a" * 64, mode=mode).ensure()


def _stage(pack: EvidencePack, stage: str, **payload) -> None:
    base = {"stage": stage, "ok": True, "error": None}
    base.update(payload)
    pack.write(stage, "META.json", base)


_MISSING = object()   # sentinel: "report has no verdict" vs "use deep's"


def _green_section(pack: EvidencePack, *, verdict: str | None = "benign",
                   source: str = "llm_judge",
                   report_verdict=_MISSING) -> None:
    """A section that WOULD be green if the verdict contract holds."""
    _stage(pack, "intake", summary="pe")
    _stage(pack, "quick", summary="ok", verdict="unknown")
    _stage(pack, "dynamic", ran=False, skipped="not requested")
    _stage(pack, "yara", summary="rule")
    agent = {"source": source, "verdict": ({"verdict": verdict} if verdict
                                           else None),
             "llm_analysis": "…", "tool_calls": 3, "history": []}
    deep = {"mcp": {}, "agent": agent, "engine": "langgraph",
            "verdict": verdict, "verdict_obj": agent["verdict"],
            "source": source, "key_evidence": [], "no_verdict": verdict is None}
    pack.write("deep", "deep.json", deep)
    _stage(pack, "deep", summary="deep", fallback=(source != "llm_judge"),
           verdict=verdict, no_verdict=verdict is None)
    rv = verdict if report_verdict is _MISSING else report_verdict
    pack.write("report", "report.json", {
        "source": source, "verdict": rv, "phase": "static",
        "analyst_next": []})
    _stage(pack, "report", summary="report", source=source, verdict=rv,
           no_verdict=rv is None)


@pytest.fixture(autouse=True)
def _gate_env(monkeypatch):
    """Deterministic gate posture for the plan tests (no hypervisor)."""
    for k in ("WINRE_HYPERVISOR", "WINRE_VM_PATH", "WINRE_SNAPSHOT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("WINRE_SNAPSHOT_GATE", "enforce")
    gate._debug_consumed.clear()


# --- item 1: execution plan -------------------------------------------------

def test_enforce_allows_one_execution_per_clean_restore():
    p = gate.execution_plan(dynamic=True)
    assert p["ok"] is True
    assert p["executions_requested"] == 1
    assert p["executions_available"] == 1
    assert p["execution_sites"] == ["dynamic"]


def test_two_executions_are_refused_with_one_clear_message():
    """The exact RevAI report: --mode agentic --dynamic --agentic-dbg
    half-executed (debug ate the marker), then dynamic was refused."""
    p = gate.execution_plan(dynamic=True, debug=True)
    assert p["ok"] is False
    assert p["executions_requested"] == 2
    assert p["executions_available"] == 1
    assert p["execution_sites"] == ["debug", "dynamic"]
    err = p["error"]
    assert "2 VM executions" in err and "allows 1" in err
    # the message must tell the operator the three real ways forward
    assert "--dynamic" in err and "restore" in err
    assert "WINRE_SNAPSHOT_GATE=observe" in err
    assert "WINRE_HYPERVISOR" in err


def test_observe_mode_is_advisory_and_needs_no_restore(monkeypatch):
    monkeypatch.setenv("WINRE_SNAPSHOT_GATE", "observe")
    p = gate.execution_plan(dynamic=True, debug=True)
    assert p["ok"] is True
    assert p["executions_available"] == 2


def test_hypervisor_auto_restore_unlimited_executions(monkeypatch):
    monkeypatch.setenv("WINRE_HYPERVISOR", "vmware")
    monkeypatch.setenv("WINRE_VM_PATH", r"C:\vm\flare.vmx")
    monkeypatch.setenv("WINRE_SNAPSHOT", "clean")
    p = gate.execution_plan(dynamic=True, debug=True)
    assert p["ok"] is True
    assert p["auto_restore"] is True
    assert p["executions_available"] == 2


def test_static_only_run_requests_no_executions():
    p = gate.execution_plan()
    assert p["ok"] is True
    assert p["executions_requested"] == 0


def test_execution_plan_is_recorded_for_audit(tmp_path):
    pack = _pack(tmp_path)
    plan = gate.execution_plan(dynamic=True)
    ev.write_execution_plan(pack, plan)
    _green_section(pack)
    res = audit_mod.audit(pack.root)
    assert res["execution_plan"]["executions_requested"] == 1
    assert res["execution_plan"]["gate_mode"] == "enforce"


# --- item 2: no verdict is never green --------------------------------------

def test_deep_without_verdict_is_not_green(tmp_path):
    pack = _pack(tmp_path)
    _green_section(pack, verdict=None, source="llm_judge")
    res = audit_mod.audit(pack.root)
    assert res["truly_green"] is False
    assert any("deep verdict missing" in u for u in res["unmet_expectations"])


def test_report_without_verdict_is_not_green(tmp_path):
    pack = _pack(tmp_path)
    _green_section(pack, verdict="benign", report_verdict=None)
    res = audit_mod.audit(pack.root)
    assert res["truly_green"] is False
    assert any("report verdict missing" in u for u in res["unmet_expectations"])


def test_report_fallback_source_is_flagged(tmp_path):
    pack = _pack(tmp_path)
    _green_section(pack, verdict="benign", source="deterministic_fallback")
    res = audit_mod.audit(pack.root)
    assert res["truly_green"] is False
    assert any("deterministic_fallback" in u for u in res["unmet_expectations"])


def test_verdict_present_stays_green(tmp_path):
    pack = _pack(tmp_path)
    _green_section(pack, verdict="benign")
    res = audit_mod.audit(pack.root)
    assert res["unmet_expectations"] == []
    assert res["truly_green"] is True
    assert res["deep_verdict"] == "benign"
    assert res["static_verdict"] == "benign"


@pytest.mark.parametrize("raw,label,missing", [
    (None, None, True),
    ("", None, True),
    ({}, None, True),
    ({"verdict": ""}, None, True),
    ("benign", "benign", False),
    ({"verdict": "malicious", "key_evidence": ["yara"]}, "malicious", False),
])
def test_verdict_fields(raw, label, missing):
    obj, got, is_missing = ev.verdict_fields(raw)
    assert got == label
    assert is_missing is missing
    if not missing:
        assert obj is not None


def test_deep_json_carries_flat_verdict_for_third_parties(tmp_path):
    """RevAI read deep.json top-level `verdict`/`source`/`key_evidence` and
    got nulls because they only existed under `agent`."""
    pack = _pack(tmp_path)
    d = {"agent": {"source": "llm_judge",
                   "verdict": {"verdict": "malicious", "confidence": "high",
                               "key_evidence": ["pe_sieve_hollow", "yara"]}},
         "verdict": "malicious", "verdict_obj": {"verdict": "malicious"},
         "source": "llm_judge", "key_evidence": ["pe_sieve_hollow", "yara"],
         "tool_failures": [], "no_verdict": False}
    pack.write("deep", "deep.json", d)
    raw = json.loads((pack.stages["deep"] / "deep.json").read_text())
    assert raw["verdict"] == "malicious"
    assert raw["source"] == "llm_judge"
    assert len(raw["key_evidence"]) == 2
    assert raw["no_verdict"] is False
    assert ev.pack_verdict(pack.root)["present"] is True


# --- item 3: evidence is append-only ---------------------------------------

def test_static_only_run_preserves_previous_dynamic_pack(tmp_path):
    pack = _pack(tmp_path)
    dyn = pack.stages["dynamic"]
    (dyn / "procmon.csv").write_text("a,b,c\n", encoding="utf-8")
    (dyn / "memory").mkdir(parents=True, exist_ok=True)
    (dyn / "memory" / "dump.dmp").write_bytes(b"\x00\x01")
    (dyn / "META.json").write_text(json.dumps({"ok": True, "frida_events": 533}),
                                  encoding="utf-8")

    out = ev.mark_dynamic_not_requested(pack)
    assert out["ok"] is True
    assert out["preserved_previous"], "previous dynamic pack must be kept"
    # this run's stage record is honest: nothing detonated here
    stg = pack.read("dynamic", "STAGE.json")
    assert stg["ran"] is False
    assert stg["skipped"] == "not requested"
    assert stg["cleared_previous"] is False
    assert stg["preserved_previous"] == out["preserved_previous"]
    # …and the evidence itself still exists, moved not deleted
    kept = pack.root / out["preserved_previous"]
    assert (kept / "procmon.csv").is_file()
    assert (kept / "memory" / "dump.dmp").is_file()
    # a fresh, empty dynamic/ for this run
    assert not (dyn / "procmon.csv").exists()


def test_static_only_run_does_not_look_gate_blocked(tmp_path):
    pack = _pack(tmp_path)
    # previous run was refused by the gate
    pack.write("dynamic", "STAGE.json", {
        "stage": "dynamic", "ok": False,
        "error": "snapshot gate: VM dirty (no clean marker)"})
    ev.mark_dynamic_not_requested(pack)
    res = audit_mod.audit(pack.root)
    assert res["dynamic_blocked"] is False


def test_mark_dynamic_not_requested_is_idempotent(tmp_path):
    pack = _pack(tmp_path)
    ev.mark_dynamic_not_requested(pack)
    ev.mark_dynamic_not_requested(pack)   # nothing left to preserve
    stg = pack.read("dynamic", "STAGE.json")
    assert stg["ran"] is False
    assert stg["preserved_previous"] is None


# --- item 4: clock skew is a diagnostic, not a gate -------------------------

def test_clock_skew_records_both_clocks():
    from winre import remote_driver
    src = inspect.getsource(remote_driver.clock_skew_s)
    assert "clock_skew_s" in src
    # the probe must report VM time AND control-plane time so a human can see
    # which host is off
    live = remote_driver.clock_skew_s.__doc__ or ""
    assert "DIAGNOSTIC" in live
    # and nothing else in the module may gate on it
    dyn_src = inspect.getsource(remote_driver.remote_dynamic)
    assert "clock_skew_s" in dyn_src
    assert "fresh = bool(nonce[\"fresh\"])" in dyn_src


def test_setup_and_verify_cover_clock_state():
    setup = (REPO / "install" / "setup-flarevm.ps1").read_text(encoding="utf-8")
    verify = (REPO / "install" / "verify-flarevm.ps1").read_text(encoding="utf-8")
    assert "w32time" in setup and "Automatic" in setup
    assert "/resync" in setup
    assert "vm_clock.json" in setup and "w32tm.exe /query /status" in setup
    # verify must WARN, never FAIL, and must stay side-effect free
    assert "w32time" in verify and "vm_clock.json" in verify
    clock_block = verify.split("--- clock")[1].split("--- cleanup")[0]
    assert "Fail(" not in clock_block


# --- item 5: nonce-based freshness -----------------------------------------

def test_nonce_accepts_only_this_run():
    rid = run_nonce.new_run_id()
    assert run_nonce.check({"run_id": rid, "ok": True}, rid)["fresh"] is True


def test_nonce_rejects_a_pack_from_another_run():
    a, b = run_nonce.new_run_id(), run_nonce.new_run_id()
    res = run_nonce.check({"run_id": a, "ok": True}, b)
    assert res["fresh"] is False
    assert "mismatch" in res["reason"]


def test_nonce_fails_closed_when_vm_code_is_stale():
    rid = run_nonce.new_run_id()
    res = run_nonce.check({"ok": True, "finished_at": "2099-01-01T00:00:00Z"},
                          rid)
    assert res["fresh"] is False
    assert "sync_to_flare" in res["reason"]


def test_freshness_never_compares_timestamps():
    """The regression guard for the original bug: a clock-based decision."""
    from winre import remote_driver
    src = inspect.getsource(remote_driver.remote_dynamic)
    assert 'meta.get("finished_at", "") >=' not in src
    assert "run_nonce.check(meta, run_id)" in src
    orch = (REPO / "winre" / "orchestrator.py").read_text(encoding="utf-8")
    assert '"run_id"' in orch and "WINRE_RUN_ID" in orch


def test_orchestrator_and_helper_pass_the_nonce():
    orch = (REPO / "winre" / "orchestrator.py").read_text(encoding="utf-8")
    assert "--run-id" in orch
    helper = (REPO / "winre" / "_remote_dynamic_helper.py").read_text(
        encoding="utf-8")
    assert "--run-id=" in helper and "WINRE_RUN_ID" in helper
    # the embedded copy the driver ships must not drift from the tracked file
    from winre import remote_driver
    assert remote_driver.REMOTE_DYNAMIC_HELPER.strip() == helper.strip()


# --- item 6: applicability, not a fake failure -----------------------------

def test_x64dbg_records_not_applicable_for_unpacked_stub():
    from winre import orchestrator
    # unpacked stub: no OEP signal, nothing to dump -> applicability, not failure
    status, reason = orchestrator._dump_outcome(None, False, "not paused", True)
    assert status == "not_applicable"
    assert "no OEP signal" in reason
    # a real dump is ok
    assert orchestrator._dump_outcome("0x401000", True, None, True) == ("ok", None)
    # packed + failed dump stays a real failure
    st, why = orchestrator._dump_outcome("0x401000", False, "access denied", True)
    assert st == "failed" and "access denied" in why
    # dump reported ok but no file landed -> still a failure
    assert orchestrator._dump_outcome("0x401000", True, None, False)[0] == "failed"
    # the terminal record must be WRITTEN (regression: the not-applicable
    # branch computed the record but never assigned it, leaving the pack's
    # x64dbg_dump at the pre-run "not-run" value)
    src = inspect.getsource(orchestrator._x64dbg_oep_dump)
    assert 'meta["x64dbg_dump"] = rec' in src
    assert 'meta["x64dbg_mcp"]["not_applicable"] = reason' in src


def test_orchestrator_labels_its_nonce_origin():
    from winre import orchestrator
    src = inspect.getsource(orchestrator.run_dynamic)
    assert "control-plane nonce" in src
    assert "orchestrator-local" in src


def test_run_line_distinguishes_unknown_from_no_verdict():
    from winre import remote_driver
    src = inspect.getsource(remote_driver.run_remote_pipeline)
    assert "deep stage produced no verdict" in src
    # a bare `unknown` placeholder must no longer be printed as a verdict
    assert "or results['quick'].get('verdict')" not in src


def test_casepack_is_documented_as_a_pack_level_file():
    doc = (REPO / "docs" / "EVIDENCE.md").read_text(encoding="utf-8")
    assert "case-" in doc and "DFIR-Nexus ingest pack" in doc
    bridge = (REPO / "docs" / "REVAI-BRIDGE.md").read_text(encoding="utf-8")
    assert "case-" in bridge
