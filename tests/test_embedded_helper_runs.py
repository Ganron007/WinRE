"""The embedded VM helper must be EXECUTABLE, not just byte-identical.

The bug this closes: `MODES` was substituted into the embedded helper but the
helper never imported it, so the VM helper died with

    in _remote_dynamic_helper.py, at module level
      if _a.startswith("--section=") and _a.split("=", 1)[1] in MODES:
    NameError: name 'MODES' is not defined

The existing contract test only asserted the embedded text matched the tracked
file, so it compared my two copies of the same mistake and stayed green. The
history file is regenerated on every run, so a bad embedded string was invisible
until the VM ran it - and the dynamic stage then reported "detonation did not
run" while STAGE.json still carried a stage result.

These tests regenerate the helper from the source of truth and RUN it.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "winre" / "_remote_dynamic_helper.py"


@pytest.fixture(scope="module")
def helper_src():
    from winre import remote_driver
    src = remote_driver.REMOTE_DYNAMIC_HELPER
    # write it where every other test expects to find it
    HELPER.write_text(src, encoding="utf-8")
    return src


def test_the_helper_compiles(helper_src):
    compile(helper_src, "<embedded>", "exec")


def test_the_helper_runs_as_a_script(helper_src, tmp_path):
    """Executed, not inspected: the NameError was a module-level failure that
    only appears when the VM actually runs the file."""
    r = subprocess.run(
        [sys.executable, str(HELPER), "a" * 64,
         r"C:\samples\x.exe", "1", "--section=dynamic"],
        capture_output=True, text=True, cwd=str(REPO), timeout=120)
    err = r.stderr or ""
    for bad in ("NameError", "TypeError", "ModuleNotFoundError", "ImportError"):
        assert bad not in err, f"embedded helper fails at runtime: {err[-600:]}"


def test_the_helper_imports_the_four_modes(helper_src):
    """The exact defect: `MODES` must be imported, not assumed."""
    assert "from winre.evidence import MODES" in helper_src
    # and the path bootstrap must precede it
    assert helper_src.index("sys.path.insert") < helper_src.index(
        "from winre.evidence import MODES")


def test_every_name_the_helper_uses_resolves(helper_src):
    """A byte-for-byte contract is not enough when both sides are mine."""
    import ast
    import builtins
    tree = ast.parse(helper_src)
    # names the interpreter itself provides at runtime
    provided = {"__file__", "__name__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                provided.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                provided.add(a.asname or a.name)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            provided.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    provided.add(t.id)
        elif isinstance(node, ast.For):
            for _t in ast.walk(node.target):
                if isinstance(_t, ast.Name):
                    provided.add(_t.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            provided.add(node.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in provided or hasattr(builtins, node.id):
                continue
            pytest.fail(f"helper uses {node.id!r} which is never provided")


def test_the_detonation_command_is_not_a_nested_inline_command():
    """The second defect: `powershell -Command "..."` with a quoted sample path
    does not survive the cmd  ssh  powershell nesting, so the detonation never
    ran while STAGE.json still reported a stage result.
    ssh_ps() (-EncodedCommand) exists for exactly this and the rest of the VM
    plumbing uses it."""
    from winre import remote_driver
    src = Path(remote_driver.__file__).read_text(encoding="utf-8")
    i = src.find("def remote_dynamic(")
    j = src.find("\ndef ", i + 10)
    body = src[i:j] if j != -1 else src[i:]
    assert "ssh_ps(cfg, _script" in body, (
        "remote_dynamic must send its script via -EncodedCommand")
    # the old shape must be gone: a `-Command "` opening the helper invocation
    assert "Bypass -Command \"" not in body, (
        "an inline -Command with nested quotes is still being built")