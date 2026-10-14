from types import SimpleNamespace

import pytest

from winre import debug_loops
from winre.agentic import ToolRegistry
from winre.mcp import x64dbg_manager


def test_debug_copy_is_distinct_even_for_expression_safe_sample(monkeypatch):
    seen = {}

    def fake_ssh_ps(_cfg, script, timeout):
        seen["script"] = script
        seen["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="DEBUG_COPY_OK", stderr="")

    monkeypatch.setattr(x64dbg_manager.remote_driver, "ssh_ps", fake_ssh_ps)
    original = r"C:\samples\run-123\sample.exe"
    result = x64dbg_manager.stage_safe_sample({"host": "flare"}, original,
                                              tag="abcdef123456")

    assert result == r"C:\samples\run-123\x64_sample_abcdef123456.exe"
    assert result != original
    assert "Copy-Item -LiteralPath $src" in seen["script"]
    assert "Get-FileHash" in seen["script"]
    assert "DEBUG_COPY_OK" in seen["script"]
    assert seen["timeout"] == 60


def test_debug_copy_fails_closed_when_copy_is_not_verified(monkeypatch):
    monkeypatch.setattr(
        x64dbg_manager.remote_driver, "ssh_ps",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="copy failed"))

    with pytest.raises(RuntimeError, match="isolated x64dbg copy"):
        x64dbg_manager.stage_safe_sample(
            {"host": "flare"}, r"C:\samples\run-123\sample.exe", "abc")


def test_unpacked_route_loads_entrypoint_without_memory_breakpoint(monkeypatch):
    registry = ToolRegistry("sample.exe", "a" * 64, cfg={"host": "flare"},
                            remote_sample=r"C:\samples\run\sample.exe")
    registry._dbg_gate = lambda: None
    registry._dbg_sample = lambda: r"C:\samples\run\x64_sample.exe"
    registry._dbg_client = lambda: object()
    observed = {}

    def fake_ep_break(sample, xc):
        observed.update(sample=sample, client=xc)
        return {"ok": True, "oep": "0x401000", "evidence": [{"label": "ep_break"}]}

    monkeypatch.setattr(debug_loops, "ep_break", fake_ep_break)
    monkeypatch.setattr(debug_loops, "oep_by_section",
                        lambda *a, **k: pytest.fail("unpacked image must not get an unpack BP"))

    result = registry.x64dbg_oep()

    assert result["ok"] is True
    assert result["method"] == "entrypoint_observation"
    assert result["entrypoint"] == "0x401000"
    assert observed["sample"].endswith("x64_sample.exe")


def test_packed_route_keeps_memory_execute_oep_probe(monkeypatch):
    registry = ToolRegistry("sample.exe", "a" * 64, cfg={"host": "flare"})
    registry._dbg_gate = lambda: None
    registry._dbg_sample = lambda: r"C:\samples\run\x64_sample.exe"
    registry._dbg_client = lambda: object()
    registry.packed_signal = {"diec": ["UPX"]}
    monkeypatch.setattr(debug_loops, "oep_by_section",
                        lambda sample, xc: {"ok": True, "oep": "0x402000",
                                            "target": {"why": "upx0"}})

    result = registry.x64dbg_oep()

    assert result["ok"] is True
    assert result["method"] == "memory_execute_oep"
    assert result["oep"] == "0x402000"
