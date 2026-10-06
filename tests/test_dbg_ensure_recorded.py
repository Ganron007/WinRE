"""The pack must record WHICH debugger produced the unpack evidence (P1-F1).

x64dbg.exe cannot debug a PE32 image. Before P1-F1 every launch path used it
unconditionally, and the resulting "debug session ended before EP pause"
failure was indistinguishable from a genuine "the sample refused to unpack".
A pack that does not name its debugger cannot be audited on that point.

These tests also pin the projection chain end to end, because that chain has
already silently dropped a field once (verdict_judged_by, P-A1/audit 2026-09-28).
"""
import ast
import inspect
import pathlib

from winre import agentic, pipeline, remote_driver


def test_tool_registry_captures_the_ensure_info_on_success():
    """Discarded-on-success is exactly how this went unnoticed."""
    src = inspect.getsource(agentic.ToolRegistry._dbg_gate)
    # the assignment must NOT be inside the `if not ok:` branch
    assert "self._dbg_ensure_info = info" in src
    guard = src.split("self._dbg_ensure_info = info", 1)[1].split("\n", 1)[0]
    assert "if not ok" not in guard, (
        "the ensure info is recorded inside the failure branch only")
    assert 'self._dbg_ensure_error = info' in src


def test_agent_result_carries_dbg_ensure():
    src = pathlib.Path(inspect.getsourcefile(agentic)).read_text(encoding="utf-8")
    assert "dbg_ensure: dict | None = None" in src
    # every return that reports windbg_dump must report the debugger too
    n = src.count('"windbg_dump": windbg_dump, "dbg_ensure": dbg_ensure')
    assert n >= 4, f"only {n} return sites carry dbg_ensure"
    # and it must be trimmed to the fields that matter, not dumped raw
    assert "replaced_wrong_arch" in src


def test_both_projections_carry_dbg_ensure():
    """pipeline.py and remote_driver.py build deep.json; a field present in
    only one of them vanishes for half the drivers."""
    for mod in (pipeline, remote_driver):
        src = inspect.getsource(mod)
        assert '"dbg_ensure": agent_result.get("dbg_ensure")' in src, mod.__name__


def test_the_projection_chain_keeps_dbg_ensure():
    """deep.json is the analyst-facing artefact. Prove the key survives a
    projection from the agent result, rather than trusting three string greps."""
    for mod in (pipeline, remote_driver):
        tree = ast.parse(pathlib.Path(inspect.getsourcefile(mod)).read_text("utf-8"))
        # find the dict literal whose "dbg_ensure" entry reads from agent_result
        hit = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, val in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == "dbg_ensure"
                        and isinstance(val, ast.Call)
                        and isinstance(val.func, ast.Attribute)
                        and val.func.attr == "get"
                        and val.args
                        and isinstance(val.args[0], ast.Constant)
                        and val.args[0].value == "dbg_ensure"):
                    hit = node
                    break
            if hit is not None:
                break
        assert hit is not None, (
            f"{mod.__name__}: deep.json is built without a "
            f'"dbg_ensure": agent_result.get("dbg_ensure") entry')


def test_dbg_ensure_records_the_replacement_of_a_wrong_flavour():
    from winre.mcp import x64dbg_manager as mgr
    src = inspect.getsource(mgr.ensure_mcp)
    assert "replaced_wrong_arch" in src
    # :9094 cannot distinguish flavours, so the process list must be consulted
    assert "_running_arch_vm(cfg)" in src