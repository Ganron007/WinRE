import pytest

from winre import debug_loops


class _Debugger:
    def __init__(self, breakpoints=""):
        self.breakpoints = breakpoints
        self.command = None
        self.hardware_breakpoint = None
        self.ran = False

    def execute_command(self, command):
        self.command = command
        return {"ok": True, "result": {"content": [
            {"text": "Command executed successfully."},
        ]}}

    def list_breakpoints(self):
        return {"result": {"content": [{"text": self.breakpoints}]}}

    def set_hw_breakpoint(self, address, dr_index=0, bp_type="x", size=1):
        self.hardware_breakpoint = (address, dr_index, bp_type, size)
        return {"ok": True}

    def run(self):
        self.ran = True
        return {"ok": True}

    def get_state(self):
        return {"result": {"content": [{"text": "currentModule: packed.exe"}]}}


def test_section_oep_uses_x64dbg_range_breakpoint_command(monkeypatch):
    target = 0x1001000
    probe_start = target + 0x1000
    client = _Debugger(f"[Memory] {probe_start:#x} nsp0 (enabled)")
    monkeypatch.setattr(debug_loops, "ep_break",
                        lambda *args: {"ok": True, "oep": target + 0x1b,
                                       "evidence": []})
    monkeypatch.setattr(
        debug_loops, "_module_base_and_sections",
        lambda *args: (0x1000000, [{
            "name": "nsp1", "start": target, "size": 0x3000,
            "perm": "XRW",
        }]),
    )
    monkeypatch.setattr(debug_loops, "_regs", lambda *_: "")
    monkeypatch.setattr(debug_loops, "_await_pause",
                        lambda *_: {"paused": True, "rip": probe_start + 0x10})
    monkeypatch.setattr(debug_loops, "_pause_evidence",
                        lambda *args: {"label": args[1], "rip": hex(args[2])})

    result = debug_loops.oep_by_section("nspack.exe", client)

    assert client.command == "bpmrange 0x1002000, 0x2000, x"
    assert result["ok"] is True
    assert result["oep"] == probe_start + 0x10
    assert result["entrypoint"] == hex(target + 0x1b)
    registration = next(e for e in result["evidence"]
                        if e["label"] == "oep_membp_set")
    assert registration["registered"] is True
    assert registration["command_result"] == "Command executed successfully."
    target_evidence = next(e for e in result["evidence"]
                           if e["label"] == "oep_membp_target")
    assert target_evidence["entrypoint_page_excluded"] == {
        "start": "0x1001000", "size": "0x1000",
    }


def test_section_oep_fails_closed_when_no_probe_page_remains(monkeypatch):
    target = 0x1001000
    client = _Debugger()
    monkeypatch.setattr(debug_loops, "ep_break",
                        lambda *args: {"ok": True, "oep": target + 0x1b,
                                       "evidence": []})
    monkeypatch.setattr(
        debug_loops, "_module_base_and_sections",
        lambda *args: (0x1000000, [{
            "name": "nsp0", "start": target, "size": 0x800,
            "perm": "XRW",
        }]),
    )
    monkeypatch.setattr(debug_loops, "_regs", lambda *_: "")

    result = debug_loops.oep_by_section("packed.exe", client)

    assert result["ok"] is False
    assert "no range outside" in result["error"]
    assert client.command is None


def test_section_oep_rejects_pause_outside_selected_probe_ranges(monkeypatch):
    target = 0x1001000
    probe_start = target + 0x1000
    client = _Debugger(f"[Memory] {probe_start:#x} nsp0 (enabled)")
    monkeypatch.setattr(debug_loops, "ep_break",
                        lambda *args: {"ok": True, "oep": target + 0x1b,
                                       "evidence": []})
    monkeypatch.setattr(
        debug_loops, "_module_base_and_sections",
        lambda *args: (0x1000000, [{
            "name": "nsp0", "start": target, "size": 0x3000,
            "perm": "XRW",
        }]),
    )
    monkeypatch.setattr(debug_loops, "_regs", lambda *_: "")
    # Even if the debugger/plugin reports an unexpected pause on the excluded
    # EP page, this cannot be accepted as an unpacked OEP.
    monkeypatch.setattr(debug_loops, "_await_pause",
                        lambda *_: {"paused": True, "rip": target + 0x800})
    monkeypatch.setattr(
        debug_loops, "_pause_evidence",
        lambda _xc, label, rip: {"label": label, "rip": hex(rip),
                                 "regs": "eip: 0x1001800",
                                 "disasm": "0x1001800: 90 | nop"},
    )

    result = debug_loops.oep_by_section("nspack.exe", client)

    assert result["ok"] is False
    assert "outside the selected" in result["error"]
    rejection = next(e for e in result["evidence"]
                     if e["label"] == "oep_rejected")
    assert rejection["rip"] == hex(target + 0x800)
    assert rejection["regs"] == "eip: 0x1001800"
    assert rejection["disasm"] == "0x1001800: 90 | nop"
    assert rejection["allowed_ranges"] == [{
        "start": "0x1002000", "size": "0x2000",
    }]


def test_unpack_tool_preserves_oep_and_dump_evidence(monkeypatch):
    from winre.agentic import ToolRegistry

    evidence = [{"label": "oep_membp_set", "cmd": "bpmrange 0x1001000, 0x3000, x",
                 "registered": True},
                {"label": "oep_membp_hit", "rip": "0x1002010"}]
    registry = ToolRegistry("packed.exe", "a" * 64, cfg={"host": "flare"})
    registry._dbg_gate = lambda: None
    registry._dbg_sample = lambda: r"C:\samples\run\packed.exe"
    registry._dbg_client = lambda: _Debugger()
    monkeypatch.setattr(
        debug_loops, "agentic_unpack",
        lambda *args, **kwargs: {"ok": True, "oep": "0x1002010",
                                 "dump_path": r"C:\samples\run\packed_unpacked.exe",
                                 "evidence": evidence},
    )

    result = registry.x64dbg_unpack()

    assert result["evidence"] == evidence


@pytest.mark.parametrize(
    ("register", "address", "size"),
    [("esp", "0xDFF74", 4), ("rsp", "0x7FFDE000", 8)],
)
def test_stack_oep_accepts_x86_and_x64_register_contracts(
        monkeypatch, register, address, size):
    client = _Debugger(f"[Hardware] {address} stack (enabled)")
    monkeypatch.setattr(debug_loops, "ep_break",
                        lambda *args: {"ok": True, "oep": "0x401000",
                                       "evidence": []})
    monkeypatch.setattr(debug_loops, "_regs",
                        lambda *_: f"{register}: {address}\n")
    monkeypatch.setattr(debug_loops, "_await_pause",
                        lambda *_: {"paused": True, "rip": 0x401234})
    monkeypatch.setattr(debug_loops, "_pause_evidence",
                        lambda *args: {"label": args[1], "rip": hex(args[2])})

    result = debug_loops.oep_by_esp("packed.exe", client)

    assert result["ok"] is True
    assert client.hardware_breakpoint == (int(address, 16), 0, "r", size)
    pointer = next(e for e in result["evidence"]
                   if e["label"] == "stack_pointer_at_ep")
    assert pointer == {
        "label": "stack_pointer_at_ep",
        "register": register,
        "address": address.lower(),
    }


def test_stack_breakpoint_cannot_report_the_original_entrypoint_as_oep(
        monkeypatch):
    entrypoint = 0x401000
    client = _Debugger(f"[Hardware] {0xDFF74:#x} stack (enabled)")
    monkeypatch.setattr(debug_loops, "ep_break",
                        lambda *args: {"ok": True, "oep": hex(entrypoint),
                                       "evidence": []})
    monkeypatch.setattr(debug_loops, "_regs", lambda *_: "esp: 0xDFF74\n")
    monkeypatch.setattr(debug_loops, "_await_pause",
                        lambda *_: {"paused": True, "rip": entrypoint})
    monkeypatch.setattr(
        debug_loops, "_pause_evidence",
        lambda _xc, label, rip: {"label": label, "rip": hex(rip),
                                 "regs": "eip: 0x401000",
                                 "disasm": "0x401000: 90 | nop"},
    )

    result = debug_loops.oep_by_esp("packed.exe", client)

    assert result["ok"] is False
    assert result["entrypoint"] == hex(entrypoint)
    assert "original entry point" in result["error"]
    rejection = next(e for e in result["evidence"]
                     if e["label"] == "oep_rejected")
    assert rejection["disasm"] == "0x401000: 90 | nop"
