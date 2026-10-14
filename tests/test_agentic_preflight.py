from __future__ import annotations

from winre import agentic


def test_langgraph_mode_runs_required_static_preflights_before_planning(monkeypatch):
    calls: list[tuple[str, dict]] = []

    class FakeRegistry:
        def __init__(self, *args, **kwargs) -> None:
            self.remote_sample = "C:/samples/sample.exe"

        def call(self, name: str, args: dict) -> dict:
            calls.append((name, dict(args)))
            return {"ok": True, "status": "clear",
                    "reason_code": "clear", "hint": "static evidence is usable"}

    monkeypatch.setattr(agentic, "ToolRegistry", FakeRegistry)

    result = agentic.run_langgraph_deep_dive(
        "sample.exe", "a" * 64, dry=True, mode="remote")

    assert calls == [("decrypt_gate", {}), ("capa", {})]
    failures = result["capability_census"]["required_failures"]
    assert not any(failure.startswith("decrypt_gate:") for failure in failures)
    assert not any(failure.startswith("capa:") for failure in failures)
    gate = next(row for row in result["capability_census"]["summary"]
                if row["tool"] == "decrypt_gate")
    assert gate["status"] == "completed"
    readiness = [event for event in result["history"]
                 if event.get("tool") == "decrypt_gate"]
    assert len(readiness) == 1
    assert readiness[0]["reason"] == (
        "mandatory deterministic analysis-readiness preflight")
    capa = next(row for row in result["capability_census"]["summary"]
                if row["tool"] == "capa")
    assert capa["status"] == "completed"
    capa_preflight = [event for event in result["history"]
                      if event.get("tool") == "capa"]
    assert len(capa_preflight) == 1
    assert capa_preflight[0]["reason"] == (
        "mandatory deterministic capa evidence preflight")


def test_agentic_dbg_runs_a_deterministic_oep_probe_when_no_packer_signal(monkeypatch):
    calls: list[tuple[str, dict]] = []

    class FakeRegistry:
        _dbg_ensure_info = {"arch": 32, "debugger": "x32dbg.exe",
                            "launched": True}

        def __init__(self, *args, **kwargs) -> None:
            self.remote_sample = "C:/samples/sample.exe"

        def _dbg_gate(self):
            return None

        def call(self, name: str, args: dict) -> dict:
            calls.append((name, dict(args)))
            if name == "decrypt_gate":
                return {"ok": True, "status": "clear",
                        "reason_code": "clear"}
            if name == "capa":
                return {"ok": True, "capabilities": []}
            if name == "x64dbg_oep":
                return {"ok": True, "oep": "0x401000"}
            if name == "x64dbg_run_window":
                return {"ok": True, "status": "completed",
                        "requested_seconds": 30, "observed_seconds": 30}
            if name == "windbg_analyze_dump":
                return {"ok": False, "status": "not_applicable",
                        "note": "no memory dump available"}
            raise AssertionError(f"unexpected tool call: {name}")

    monkeypatch.setattr(agentic, "ToolRegistry", FakeRegistry)
    result = agentic.run_langgraph_deep_dive(
        "sample.exe", "a" * 64, dry=True, mode="remote", dynamic=True)

    assert [name for name, _ in calls] == [
        "decrypt_gate", "capa", "x64dbg_oep", "x64dbg_run_window",
        "windbg_analyze_dump"]
    probe = next(row for row in result["history"]
                 if row.get("tool") == "x64dbg_oep")
    assert probe["reason"] == "agentic-dbg deterministic target-load/OEP probe"
    assert result["debug_run"]["attempted"] is True
    assert result["debug_run"]["status"] == "completed"
    window = next(row for row in result["history"]
                  if row.get("tool") == "x64dbg_run_window")
    assert window["reason"] == "mandatory bounded debugger observation window"
