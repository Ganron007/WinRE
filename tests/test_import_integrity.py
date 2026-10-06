"""Every module must import, and every name a function uses must resolve.

Context: the port-discovery fix (P1-F1 follow-on) shipped a green suite and
then died on the first real run with

    File "winre/remote_driver.py", line 903, in remote_mcp_health
      for port in X64DbgClient.MCP_PORTS:
    NameError: name 'X64DbgClient' is not defined

The tests passed because they inspected the AST and the source text. Neither
proves the name exists at runtime. These tests do.

Scope note: this is deliberately broad and cheap. A missing import is the
cheapest possible defect to catch and the most embarrassing one to ship.
"""
import importlib
import inspect
import pathlib
import pkgutil

import pytest

import winre

# modules that are scripts-only or need a live appliance
_SKIP = {"winre.pipeline"}

# VM-side helpers: standalone scripts the driver uploads and runs on the VM
# with `python <file> <args>`. They parse sys.argv at import time, so they are
# not importable as library modules - they get a syntax check instead.
def _is_vm_helper(mod: str) -> bool:
    leaf = mod.rsplit(".", 1)[-1]
    return leaf.startswith("_") or "helper" in leaf


def _importable():
    return [m for m in _all_modules() if m not in _SKIP and not _is_vm_helper(m)]


def _helpers():
    root = pathlib.Path(winre.__file__).parent
    return [p for p in sorted(root.rglob("*.py"))
            if _is_vm_helper(p.stem)]


def _all_modules():
    root = pathlib.Path(winre.__file__).parent
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root).with_suffix("")
        mod = ".".join(("winre",) + rel.parts)
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        if mod in _SKIP:
            continue
        yield mod


@pytest.mark.parametrize("mod", _importable())
def test_module_imports_cleanly(mod):
    importlib.import_module(mod)


@pytest.mark.parametrize("mod", _importable())
def test_names_in_functions_resolve(mod):
    """Every LOAD_GLOBAL in every function must resolve.

    A NameError is a *runtime* failure, so importing the module does not
    prove it away. co_names is the wrong tool here (it also holds attribute
    names); the bytecode's LOAD_GLOBAL set is exactly the set of globals a
    function will look up when it runs.
    """
    import builtins
    import dis
    m = importlib.import_module(mod)
    ns = vars(m)
    for fname, fn in list(vars(m).items()):
        if not inspect.isfunction(fn) or fn.__module__ != mod:
            continue
        code = getattr(fn, "__code__", None)
        if code is None:
            continue
        globals_used = {i.argval for i in dis.get_instructions(code)
                        if i.opname in ("LOAD_GLOBAL", "LOAD_NAME")}
        missing = sorted(g for g in globals_used
                         if g not in ns and not hasattr(builtins, g))
        assert not missing, (
            f"{mod}.{fname}() does a LOAD_GLOBAL on names that do not exist "
            f"in the module: {missing}  <- this is a runtime NameError")


@pytest.mark.parametrize("path", _helpers(),
                         ids=lambda p: p.name)
def test_vm_helper_scripts_parse(path):
    """Not importable (they read sys.argv at import), but they must still be
    syntactically valid Python - the driver runs them on the VM verbatim."""
    import ast
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_the_modules_touched_by_the_port_fix_import():
    """Named explicitly so a regression points straight at the change."""
    for mod in ("winre.mcp.x64dbg_client", "winre.mcp.x64dbg_manager",
                "winre.remote_driver", "winre.agentic", "winre.debug_loops"):
        importlib.import_module(mod)


def test_remote_mcp_health_sees_the_client_class():
    """The exact defect: the function referenced a class it never imported."""
    from winre import remote_driver
    assert hasattr(remote_driver, "X64DbgClient")
    assert remote_driver.X64DbgClient.MCP_PORTS


def test_remote_mcp_health_runs_against_a_dead_port(monkeypatch):
    """Execute it for real: every candidate refuses, so the OR must be False
    and the per-port map must still be populated."""
    from winre import remote_driver

    def dead(self, *a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(remote_driver.X64DbgClient, "call", dead)
    monkeypatch.setattr(remote_driver, "malcat_remote_is_up", lambda: False)
    monkeypatch.setattr(remote_driver, "vm_port_listening",
                        lambda *a, **k: False)
    out = remote_driver.remote_mcp_health({"host": "127.0.0.1"})
    assert out["x64dbg"] is False
    assert set(out["x64dbg_ports"]) == {
        str(p) for p in remote_driver.X64DbgClient.MCP_PORTS}
    assert all(v is False for v in out["x64dbg_ports"].values())