"""Controls for the EP-breakpoint flow (2026-10-29, s08 dbg investigation).

The 2026-10-27 s08 dbg run lost its debuggee before any observation: the EP
breakpoint never registered ('bp mod.entry(<stem>:0)' on an unmapped
module), the eval fallback armed 'bp 0x0' from a failed eval, and
ep_break free-ran the target anyway - an instant-exit console binary was
gone in seconds ('debug session ended before EP pause'). s02's identical
expression form had registered fine, proving the form works when the
module is mapped. The flow now waits for the module, tries the basename
form, never arms bp 0x0, and FAILS CLOSED when the EP bp did not register.
"""
from __future__ import annotations

import re

from winre import debug_loops

SAMPLE = "C:/samples/winre/x64_sample_980b377b3f8b.exe"


class FakeEpXc:
    def __init__(self, *, register_when=None, module_present=True,
                 eval_addr="0x0"):
        self.commands: list[str] = []
        self.run_calls = 0
        self.register_when = register_when  # substring that makes bps show
        self.module_present = module_present
        self.eval_addr = eval_addr

    # --- commands the flow uses ------------------------------------------
    def call(self, name, arguments=None):
        return {"ok": True, "result": {}}

    def load_binary(self, path):
        return {"ok": True}

    def execute_command(self, cmd):
        self.commands.append(cmd)
        return {"ok": True, "result": {}}

    def eval(self, expr):
        return {"ok": True, "result": {"content": [{"text": self.eval_addr}]}}

    def list_breakpoints(self):
        if self.register_when and any(self.register_when in c
                                      for c in self.commands):
            return {"ok": True, "result": {"content": [
                {"text": "Breakpoints:\nentry bp at 0x401000"}]}}
        return {"ok": True, "result": {"content": [{"text": "Breakpoints:"}]}}

    def list_modules(self):
        names = "Modules:\n" + ("x64_sample_980b377b3f8b.exe"
                                if self.module_present else "")
        return {"ok": True, "result": {"content": [{"text": names}]}}

    def get_state(self):
        return {"ok": True, "result": {"content": [{"text":
                "isDebugging: false\nisRunning: false\nstatus: NO_TARGET"}]}}

    def get_event_log(self):
        return {"ok": True, "result": {"content": [{"text": "Events: none"}]}}

    def run(self):
        self.run_calls += 1
        return {"ok": True}


def _advancing_clock(monkeypatch):
    """A clock that advances one second per read: _wait_for_module and
    _await_pause both loop on time.time(), so a frozen fake never exits."""
    monkeypatch.setattr(debug_loops.time, "sleep", lambda s: None)
    box = {"t": 0.0}

    def fake_time():
        box["t"] += 1.0
        return box["t"]

    monkeypatch.setattr(debug_loops.time, "time", fake_time)


def test_ep_break_refuses_to_free_run_when_the_bp_does_not_register(monkeypatch):
    _advancing_clock(monkeypatch)
    xc = FakeEpXc(module_present=False)  # bp can never register
    r = debug_loops.ep_break(SAMPLE, xc=xc)
    assert r.get("ok") is False
    assert "did not register" in str(r.get("error")), r.get("error")
    assert xc.run_calls == 0, (
        "the flow must not free-run the target without an EP breakpoint")


def test_set_entry_bp_never_arms_bp_zero(monkeypatch):
    xc = FakeEpXc(eval_addr="0x0")
    out = debug_loops._set_entry_bp(xc, SAMPLE)
    assert not any(c.startswith("bp 0x0") for c in xc.commands), xc.commands
    assert out.get("registered") is False
    assert any(t.get("refused") for t in out.get("tried") or []), out


def test_set_entry_bp_falls_back_to_the_full_basename(monkeypatch):
    # only the basename form registers (module name includes the extension)
    xc = FakeEpXc(register_when="x64_sample_980b377b3f8b.exe")
    out = debug_loops._set_entry_bp(xc, SAMPLE)
    assert out.get("registered") is True, out
    assert any(c.startswith("bp mod.entry(x64_sample_980b377b3f8b.exe:0)")
               for c in xc.commands), xc.commands


def test_ep_break_happy_path_still_runs_when_the_bp_registers(monkeypatch):
    _advancing_clock(monkeypatch)
    xc = FakeEpXc(register_when="mod.entry")
    # after run(), the target pauses at EP with a readable RIP
    def state_after_run():
        if xc.run_calls:
            return {"ok": True, "result": {"content": [{"text":
                    "isDebugging: true\nisRunning: false\nstatus: LOCKED\n"
                    "currentAddress: 0x401000\n"
                    "currentModule: x64_sample_980b377b3f8b.exe"}]}}
        return FakeEpXc.get_state(xc)
    xc.get_state = state_after_run  # type: ignore[assignment]
    monkeypatch.setattr(debug_loops, "_pause_evidence",
                        lambda xc, label, rip: {"label": label})
    r = debug_loops.ep_break(SAMPLE, xc=xc)
    assert r.get("ok") is True, r.get("error")
    assert r.get("oep") == 0x401000
    assert xc.run_calls == 1
