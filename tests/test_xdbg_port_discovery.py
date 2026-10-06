"""The x64dbg MCP port must be discovered, not assumed (P1-F1 follow-on).

Measured on the FlareVM 2026-10-06, with both debuggers closed:

    x32dbg.exe (pid 4300)  Listen :9095     <- dp32 build
    x64dbg.exe (pid 2452)  Listen :9094     <- dp64 build

The 32-bit and 64-bit builds of the MCP server plugin do not share a port.
WinRE hardcoded 9094 in fifteen places, so every x32dbg session reported
"x64dbg MCP :9094 not up after 45s" while the server was up and answering on
9095 - the same silent-no-evidence failure class as P1-F1 itself.

These tests pin discovery, the positive-evidence rule for a candidate port,
and the removal of the hardcoded literals from live code.
"""
import ast
import inspect
import pathlib

import pytest

from winre.mcp import x64dbg_client as cl
from winre.mcp import x64dbg_manager as mgr


def test_both_plugin_ports_are_candidates():
    assert 9094 in cl.X64DbgClient.MCP_PORTS
    assert 9095 in cl.X64DbgClient.MCP_PORTS


def test_discovery_prefers_a_port_that_answers(monkeypatch):
    """Only the second candidate answers -> that is the port we must use."""
    asked = []

    def fake_answers(base, timeout=3):
        asked.append(base)
        return ":9095" in base

    monkeypatch.setattr(cl.X64DbgClient, "_answers", staticmethod(fake_answers))
    cl.X64DbgClient.forget_port()
    assert cl.X64DbgClient.resolve_port("10.0.0.5") == 9095
    assert cl.X64DbgClient.resolve_base("10.0.0.5") == "http://10.0.0.5:9095"
    # 9094 is tried first and fails, so the fallback is what saves us
    assert asked == ["http://10.0.0.5:9094", "http://10.0.0.5:9095"]


def test_discovery_takes_the_first_answer(monkeypatch):
    monkeypatch.setattr(cl.X64DbgClient, "_answers",
                        staticmethod(lambda base, timeout=3: True))
    cl.X64DbgClient.forget_port()
    assert cl.X64DbgClient.resolve_port("h") == 9094


def test_nothing_answering_falls_back_without_raising(monkeypatch):
    """Before the debugger is launched nothing answers; the caller is about to
    launch it, so this must return a usable default, not None/raise."""
    monkeypatch.setattr(cl.X64DbgClient, "_answers",
                        staticmethod(lambda base, timeout=3: False))
    cl.X64DbgClient.forget_port()
    assert cl.X64DbgClient.resolve_port("h") is None
    assert cl.X64DbgClient.resolve_base("h") == "http://h:9094"


def test_the_port_is_cached_and_survives_reuse(monkeypatch):
    calls = []

    def fake_answers(base, timeout=3):
        calls.append(base)
        return ":9095" in base

    monkeypatch.setattr(cl.X64DbgClient, "_answers", staticmethod(fake_answers))
    cl.X64DbgClient.forget_port()
    cl.X64DbgClient.resolve_port("cachehost")
    n = len(calls)
    cl.X64DbgClient.resolve_port("cachehost")
    assert len(calls) == n, "a cached port must not re-probe"
    # forget_port drops it, which is what the manager does after a launch
    cl.X64DbgClient.forget_port("cachehost")
    cl.X64DbgClient.resolve_port("cachehost")
    assert len(calls) > n


def test_forget_port_clears_every_host_when_unscoped():
    cl.X64DbgClient._port_cache.update({"a": 9094, "b": 9095})
    cl.X64DbgClient.forget_port()
    assert cl.X64DbgClient._port_cache == {}


def test_a_candidate_counts_only_on_positive_mcp_evidence():
    """A bare open socket is NOT evidence - that mistake previously made dead
    servers report healthy.

    The probe must be the product's own is_up() (GetDebugState). An earlier
    version invented a fake tool name and demanded ok=True; the server
    correctly answered "unknown tool", which is proof of life, so every port
    was reported dead and 32-bit debugging stayed unreachable."""
    src = inspect.getsource(cl.X64DbgClient._answers)
    assert ".is_up()" in src, "must reuse the validated liveness probe"
    # is_up() itself must still be a real MCP call, not a socket check
    assert 'call("GetDebugState")' in inspect.getsource(cl.X64DbgClient.is_up)
    # no invented tool names in the CODE (the docstring names the old bug on
    # purpose, so the docstring is stripped before this check)
    import ast as _ast
    tree = _ast.parse(inspect.cleandoc(src).replace("@classmethod", "", 1))
    body_src = _ast.unparse(tree)
    body_src = body_src.split('"""', 2)[-1]      # drop the module/func docstring
    assert "__winre" not in body_src, "no invented tool names"
    assert "port_probe" not in body_src, "no invented tool names"


def test_discovery_uses_a_real_client_not_a_hand_built_one(monkeypatch):
    """A __new__ hack would skip __init__ and can silently lose attributes."""
    src = inspect.getsource(cl.X64DbgClient._answers)
    assert "__new__" not in src
    # end to end: a server that answers on 9095 must be selected
    monkeypatch.setattr(cl.X64DbgClient, "is_up",
                        lambda self: self.base.endswith(":9095"))
    cl.X64DbgClient.forget_port()
    assert cl.X64DbgClient.resolve_port("real.host") == 9095


def test_client_accepts_a_host_and_discovers_the_port(monkeypatch):
    monkeypatch.setattr(cl.X64DbgClient, "_answers",
                        staticmethod(lambda base, timeout=3: ":9095" in base))
    cl.X64DbgClient.forget_port()
    c = cl.X64DbgClient(host="192.168.77.42")
    assert c.base == "http://192.168.77.42:9095"


def test_an_explicit_base_still_wins(monkeypatch):
    monkeypatch.setattr(cl.X64DbgClient, "_answers",
                        staticmethod(lambda base, timeout=3: True))
    cl.X64DbgClient.forget_port()
    c = cl.X64DbgClient(base="http://1.2.3.4:1234/")
    assert c.base == "http://1.2.3.4:1234"


# --- no hardcoded 9094 left in live code ----------------------------------

@pytest.mark.parametrize("rel", [
    "winre/mcp/x64dbg_client.py", "winre/mcp/x64dbg_manager.py",
    "winre/agentic.py", "winre/debug_loops.py", "winre/remote_driver.py",
    "ops/smoke_flare.py",
])
def test_no_client_is_constructed_with_a_hardcoded_port(rel):
    """`X64DbgClient(base=f"http://{host}:9094")` is the exact pattern that
    made x32dbg unreachable. It must not exist anywhere."""
    tree = ast.parse(pathlib.Path(rel).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "X64DbgClient"):
            continue
        for kw in node.keywords:
            if kw.arg == "base" and ast.dump(kw.value).find("9094") != -1:
                pytest.fail(f"{rel}:{node.lineno}: hardcoded 9094 in base=")
            if kw.arg in ("port",) :
                pytest.fail(f"{rel}:{node.lineno}: unexpected port kwarg")


def test_manager_never_hardcodes_the_mcp_port():
    """The manager must reach the client through discovery, not a literal."""
    src = inspect.getsource(mgr)
    # literals are fine in prose; they must not build a URL
    for bad in ('"http://127.0.0.1:9094"', 'f"http://{host}:9094"'):
        assert bad not in src, f"manager still builds {bad}"
    assert "forget_port()" in src


def test_the_not_up_error_names_the_ports_and_the_debugger():
    """The old message said ':9094 not up', which is what made the dp32-on-9095
    case read as a dead server instead of a wrong-port client."""
    msg = mgr._not_up(45, 32)
    assert "9094" in msg and "9095" in msg
    assert "x32dbg.exe" in msg
    assert "45" in msg
    assert mgr._not_up(90, 64).count("x64dbg.exe") == 1


def test_ensure_info_reports_the_port():
    for fn in (mgr.ensure_mcp, mgr.ensure_mcp_local):
        src = inspect.getsource(fn)
        assert '"port": _port_of(xc)' in src, fn.__name__


def test_remote_mcp_health_probes_every_candidate():
    from winre import remote_driver
    src = inspect.getsource(remote_driver.remote_mcp_health)
    assert "X64DbgClient.MCP_PORTS" in src
    assert "xdbg_ports" in src
    assert "any(xdbg_ports.values())" in src, (
        "out['x64dbg'] must be the OR over candidates, not the last probe")