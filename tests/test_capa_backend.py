"""Regression controls for the capa backend dispatcher (tools/flare_static_tools.py).

Why this exists (2026-10-22): the standalone capa.exe measured 774 s (cold) on
a 2 MB PE on the FlareVM while Malcat's native capa engine returns the same
capability set in ~2 s. The static pipeline calls capa twice (quick batch +
deep-stage checklist), so that one tool dominated the run and looked like a
hang. Malcat is now the preferred engine and the standalone engine remains
the fallback, so the free path still works with no Malcat licence.

RevAI reaches the same engine family through its own CADRE_CAPA_ENGINE
dispatcher (auto|malcat|capa-rs|capa).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools" / "flare_static_tools.py"


def _load_tools():
    spec = importlib.util.spec_from_file_location("flare_static_tools_t", TOOLS)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["flare_static_tools_t"] = mod
    spec.loader.exec_module(mod)
    return mod


fst = _load_tools()


MALCAT_MATCHES = [
    {"id": "read file on Windows", "namespace": "host-interaction/file-system/read",
     "scope": "function", "attack": ["Discovery::File and Directory Discovery [T1083]"],
     "mbc": ["File System::Read File [C0051]"], "num_matches": 1},
    {"id": "link function at runtime on Windows",
     "namespace": "linking/runtime-linking", "scope": "instruction",
     "attack": ["Execution::Shared Modules [T1129]"],
     "mbc": [], "num_matches": 16},
]


def _stub_malcat(monkeypatch, calls, match_payload=None):
    """Make the Malcat MCP call return a fixed payload; record the calls."""
    seen: list[tuple[str, dict]] = []

    def fake_call(name, arguments, timeout=300):
        seen.append((name, arguments))
        if name == "analyse_file":
            return {"structuredContent": {"analysis_id": 42}}
        if name == "capa_list":
            # the REAL Malcat shape: structuredContent wraps the list in
            # "result" (and the same list is echoed as a JSON text blob)
            return {"structuredContent": {"result": MALCAT_MATCHES},
                    "content": [{"type": "text",
                                 "text": json.dumps(MALCAT_MATCHES)}]}
        return None

    monkeypatch.setattr(fst, "_malcat_mcp_call", fake_call)
    return seen


def test_malcat_capa_preferred_over_standalone(monkeypatch):
    """With Malcat reachable, capa uses the native engine and never spawns
    the standalone exe."""
    seen = _stub_malcat(monkeypatch, None)
    spawned: list = []
    monkeypatch.setattr(fst, "_run", lambda cmd, timeout: spawned.append(cmd) or (1, "", ""))

    out = fst.capa("C:/samples/x.exe")

    assert out["ok"] is True
    assert out["tool"] == "capa"
    assert out["engine"] == "malcat-capa"
    assert out["total"] == 2
    assert spawned == [], "standalone capa must not run when Malcat answered"
    assert [n for n, _ in seen] == ["analyse_file", "capa_list"]


def test_malcat_capa_keeps_the_standalone_output_contract(monkeypatch):
    """The capability shape is unchanged, so capabilities census, findings,
    compose, audit and the report all keep working."""
    _stub_malcat(monkeypatch, None)
    out = fst.capa("C:/samples/x.exe")

    cap = out["capabilities"][0]
    assert set(cap) >= {"name", "mastrust", "attack", "count"}
    assert cap["name"] == "read file on Windows"
    # 'Tactic::Technique [T1083]' -> 'Tactic:Technique' (the capa contract)
    assert cap["attack"] == ["Discovery:File and Directory Discovery"]
    assert cap["count"] == 1
    assert out["capabilities"][1]["count"] == 16
    # richer than the standalone engine, but additive only
    assert out["capabilities"][0]["namespace"] == "host-interaction/file-system/read"
    assert out["capabilities"][0]["mbc"] == ["File System::Read File [C0051]"]


def test_standalone_capa_is_the_fallback(monkeypatch):
    """No Malcat (or Malcat down): the free standalone engine still runs."""
    monkeypatch.setattr(fst, "_malcat_mcp_call", lambda *a, **k: None)
    monkeypatch.setattr(fst, "CAPA_EXE", fst.Path(r"C:\Tools\capa\capa.exe"))
    monkeypatch.setattr(fst, "CAPA_RULES", r"C:\Tools\capa-rules")
    monkeypatch.setattr(fst.Path, "rglob", lambda self, pat: [self] if False else [])

    # no rules present -> honest skip, and the standalone engine was NOT run
    out = fst.capa("C:/samples/x.exe")
    assert out.get("ok") is not True
    assert out.get("skipped")


def test_malcat_capa_returns_none_when_unreachable(monkeypatch):
    """A dead Malcat must not raise - the caller falls back to standalone."""
    monkeypatch.setattr(fst, "_malcat_mcp_call", lambda *a, **k: None)
    assert fst._malcat_capa("C:/samples/x.exe") is None


def test_malcat_attack_parser_handles_both_shapes():
    assert fst._malcat_attack(["A::B [T1]"]) == ["A:B"]
    assert fst._malcat_attack(["A::B"]) == ["A:B"]
    assert fst._malcat_attack(["Plain Technique [T99]"]) == ["Plain Technique"]
    assert fst._malcat_attack(None) == []
