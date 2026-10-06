"""P1-F1: the debugger launcher must be bitness-aware.

Finding, 2026-10-06 (first live agentic-dbg run, sample s01):

    OEP failed: OEP unresolved: section=debug session ended before EP pause
    (debuggee exited/crashed?); esp=debug session ended before EP pause

s01 is PE32. Every launch path hardcoded
``release\\x64\\x64dbg.exe`` — x64dbg.exe cannot debug a 32-bit image — so
the debuggee never reached its entry breakpoint and every OEP method failed
identically. Nothing in the codebase selected x32dbg.exe at all.

These tests pin the fix from both sides, so the regression cannot come back
as a silent "unpack quietly does nothing" again.
"""
import os
import pathlib
import struct
import inspect

import pytest

from winre.mcp import x64dbg_manager as mgr


def _mkpe(tmp_path: pathlib.Path, name: str, machine: int,
          size: int = 0x400) -> str:
    """A minimal PE header carrying the given Machine field."""
    b = bytearray(b"\x00" * size)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", b, 0x84, machine)
    p = tmp_path / name
    p.write_bytes(bytes(b))
    return str(p)


I386 = 0x014C
AMD64 = 0x8664


# --- the two binaries actually exist and are the right ones -----------------

def test_both_x64dbg_flavours_are_known_and_distinct():
    assert mgr.XDBG_BIN[64].lower().endswith(r"release\x64\x64dbg.exe")
    assert mgr.XDBG_BIN[32].lower().endswith(r"release\x32\x32dbg.exe")
    assert mgr.XDBG_BIN[32] != mgr.XDBG_BIN[64]
    assert mgr.XDBG_PROCS == {64: "x64dbg.exe", 32: "x32dbg.exe"}


# --- bitness detection -----------------------------------------------------

@pytest.mark.parametrize("machine,bits", [(I386, 32), (AMD64, 64)])
def test_pe_bitness_reads_the_machine_field(tmp_path, machine, bits):
    mgr._arch_cache.clear()
    assert mgr.pe_bitness(_mkpe(tmp_path, "s.exe", machine)) == bits


def test_xdbg_arch_picks_the_matching_flavour(tmp_path):
    mgr._arch_cache.clear()
    p32 = _mkpe(tmp_path, "pe32.exe", I386)
    p64 = _mkpe(tmp_path, "pe64.exe", AMD64)
    assert mgr.xdbg_arch(p32) == 32
    assert mgr.xdbg_arch(p64) == 64
    # the whole point: a PE32 sample must NOT go to x64dbg.exe
    assert mgr.XDBG_BIN[mgr.xdbg_arch(p32)] == mgr.XDBG_BIN[32]
    assert mgr.XDBG_BIN[mgr.xdbg_arch(p64)] == mgr.XDBG_BIN[64]


def test_unknown_architecture_falls_back_to_64_not_a_crash(tmp_path):
    """An unrecognised Machine (ARM64, or a non-PE) must not raise."""
    mgr._arch_cache.clear()
    arm = _mkpe(tmp_path, "arm64.exe", 0xAA64)
    assert mgr.pe_bitness(arm) is None
    assert mgr.xdbg_arch(arm) == mgr.DEFAULT_ARCH      # pre-P1-F1 behaviour
    txt = tmp_path / "notes.txt"
    txt.write_bytes(b"not a pe at all" * 8)
    assert mgr.pe_bitness(str(txt)) is None
    assert mgr.xdbg_arch(str(txt)) == mgr.DEFAULT_ARCH


@pytest.mark.parametrize("body,label", [
    (b"MZ", "header only"),
    (b"MZ" + b"\xff" * 0x3C, "absurd e_lfanew"),
    (b"MZ" + struct.pack("<I", 0x7FFFFFFF) + b"\x00" * 8, "e_lfanew 2GB"),
    (b"", "empty file"),
])
def test_hostile_headers_never_raise(tmp_path, body, label):
    mgr._arch_cache.clear()
    p = tmp_path / "trunc.bin"
    p.write_bytes(body)
    assert mgr.pe_bitness(str(p)) is None, label


def test_missing_path_and_junk_input_never_raise(tmp_path):
    mgr._arch_cache.clear()
    for bad in (str(tmp_path / "nope.exe"), str(tmp_path), None, "", 12345):
        assert mgr.pe_bitness(bad) is None
        assert mgr.xdbg_arch(bad) == mgr.DEFAULT_ARCH


def test_bitness_is_cached_per_path(tmp_path):
    """A run asks once per sample; a cache miss costs an SSH round trip."""
    mgr._arch_cache.clear()
    p = _mkpe(tmp_path, "pe32.exe", I386)
    assert mgr.pe_bitness(p) == 32
    assert mgr._arch_cache[p] == 32
    # a negative result is cached too, so a non-PE is not re-asked over SSH
    f = tmp_path / "plain.txt"
    f.write_bytes(b"nope")
    assert mgr.pe_bitness(str(f)) is None
    assert mgr._arch_cache[str(f)] is None


# --- the operator override -------------------------------------------------

def test_winre_xdbg_arch_overrides_detection(tmp_path, monkeypatch):
    mgr._arch_cache.clear()
    p32 = _mkpe(tmp_path, "pe32.exe", I386)
    p64 = _mkpe(tmp_path, "pe64.exe", AMD64)
    monkeypatch.setenv("WINRE_XDBG_ARCH", "32")
    assert mgr.xdbg_arch(p64) == 32
    monkeypatch.setenv("WINRE_XDBG_ARCH", "64")
    assert mgr.xdbg_arch(p32) == 64
    monkeypatch.setenv("WINRE_XDBG_ARCH", "x32dbg")
    assert mgr.xdbg_arch(p64) == 32


# --- every launch/kill path must be bitness-aware --------------------------

def test_the_launcher_takes_an_arch_and_every_call_site_passes_one():
    """Regression guard: the bug was a hardcoded path in the launcher.

    If a call site goes back to launching without an arch, the sample is
    handed to the wrong debugger again and the failure is silent.
    """
    import inspect
    for fn in (mgr._launch_on_vm, mgr._launch_local):
        sig = inspect.signature(fn)
        assert "arch" in sig.parameters, fn.__name__
        assert sig.parameters["arch"].default == mgr.DEFAULT_ARCH, fn.__name__
    src = pathlib.Path(inspect.getsourcefile(mgr)).read_text(encoding="utf-8")
    assert src.count("_launch_on_vm(cfg, arch)") == 1
    assert src.count("_launch_local(arch)") == 1


def test_debugger_exe_paths_are_declared_exactly_once():
    """Every literal path to a debugger binary lives in XDBG_BIN and nowhere
    else, so the flavour can only ever be chosen by arch.

    The P1-F1 bug was precisely a launch path written inline at a call site.
    """
    src = pathlib.Path(inspect.getsourcefile(mgr)).read_text(encoding="utf-8")
    head, marker, tail = src.partition("XDBG_BIN = {")
    assert marker, "XDBG_BIN table not found"
    table, closed, after = tail.partition("\n}")
    assert closed, "XDBG_BIN table is not closed by a bare brace"
    for lit in (r"release\x64\x64dbg.exe", r"release\x32\x32dbg.exe"):
        assert lit in table, f"{lit} missing from the table"
        assert lit not in head, f"{lit} declared outside the table (head)"
        assert lit not in after, f"{lit} declared outside the table (after)"

    # debug_loops must never name a debugger BINARY, only its processes
    dl = pathlib.Path("winre/debug_loops.py").read_text(encoding="utf-8")
    assert r"release\x64" not in dl and r"release\x32" not in dl


def test_teardown_kills_both_flavours():
    """A 32-bit session leaves x32dbg.exe; killing only x64dbg.exe would let
    the next run attach to a debugger that still holds a stale debuggee."""
    import inspect
    src = inspect.getsource(mgr.teardown)
    assert "_kill_all_vm(cfg)" in src
    kill = inspect.getsource(mgr._kill_all_vm)
    assert "x32dbg.exe" in kill and "x64dbg.exe" in kill


def test_debug_loops_restart_kills_both_flavours():
    import inspect
    from winre import debug_loops
    src = inspect.getsource(debug_loops._restart_debugger)
    assert "x32dbg.exe" in src and "x64dbg.exe" in src
    # and it must forward the sample so the relaunch keeps the right flavour
    assert "restart_mcp(sample=sample)" in src
    assert "ensure_mcp_local(wait_s=60, sample=sample)" in src
    sig = inspect.signature(debug_loops._restart_debugger)
    assert "sample" in sig.parameters


def test_callers_thread_the_sample_through():
    """agentic (control plane) and orchestrator (on the VM) must both pass the
    sample, or the arch resolves to the 64-bit default."""
    import inspect
    from winre import agentic, orchestrator
    assert "sample=self._dbg_sample()" in inspect.getsource(agentic)
    assert "sample=str(sample)" in inspect.getsource(orchestrator)


def test_start_servers_can_preheat_the_right_flavour():
    src = pathlib.Path("winre/mcp/start_servers.ps1").read_text(encoding="utf-8")
    assert "[int]$X64dbgArch = 64" in src
    assert "x32dbg.exe" in src
    assert "X64dbgArch -eq 32" in src


def test_health_reports_which_flavour_is_serving():
    import inspect
    src = inspect.getsource(mgr.health)
    assert "_running_arch_vm(cfg)" in src
    assert "debugger" in src