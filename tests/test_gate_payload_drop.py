"""The file gate must fire only on a PROVEN payload drop (P1-F6).

Finding, 2026-10-06 (b104, WinX.OperationDianxun, a .NET loader):

    effective_s: 2.8   requested 150   stop_reason: detached
    gate: {fired: true, kind: file, api: WriteFile, at_s: 1.1}
    memory_harvest: {ok: false, dumps: [], count: 0}

The gate fired at 1.1s on WriteFile and cut the window to 2.8s, losing the
memory dump - the single most valuable artefact for a reflective-loading
sample. Resolving the handle offline from the SAME trace (pairing CreateFile
onEnter with its onLeave retval) showed 0 of 9 WriteFile calls could be
attributed to any file: all used handle 0xafc, which no hooked CreateFile*
ever opened. That is a console/stdout handle.

So the gate was firing on a write it could not attribute to anything. That is
the exact rule P1-F2 fixed for CreateFile ("never claim a drop you cannot
prove"), violated again one level down in WriteFile.

The fix is a handle->path map in the tracer plus classify_path(), and these
tests replay the REAL evidence from the real runs so the regression cannot be
argued away with synthetic cases.
"""
import importlib.util
import pathlib

import pytest

_FAT = pathlib.Path("tools/frida_api_trace.py")


def _load():
    spec = importlib.util.spec_from_file_location("fat_under_test", _FAT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def fat():
    return _load()


# --- the three real incidents, replayed ----------------------------------

def test_b104_console_write_does_not_fire(fat):
    """Handle 0xafc was never opened by any CreateFile we hook."""
    k, a = fat.parse_stop_on("network,file")
    assert fat.gate_for("WriteFile", k, a,
                        ["0xafc", "0x1", "0x2", "0x3"], None) is None


def test_b107_disk_shred_still_fires(fat):
    r"""CWipeNew opened \\.\PhysicalDrive0 - a device write is destructive."""
    k, a = fat.parse_stop_on("network,file")
    got = fat.gate_for("WriteFile", k, a,
                       ["0xafc", "0x1", "0x2", "0x3"],
                       "\\\\.\\PhysicalDrive0")
    assert got == "device"


def test_s01_locale_read_does_not_fire(fat):
    """The P1-F2 incident: GENERIC_READ of the sort table."""
    k, a = fat.parse_stop_on("network,file")
    assert fat.gate_for(
        "CreateFileW", k, a,
        ["0x19af46c", "0x80000000", "0x1", "0x0"],
        "C:\\Windows\\Globalization\\Sorting\\sortdefault.nls") is None


def test_a_real_appdata_drop_fires(fat):
    k, a = fat.parse_stop_on("network,file")
    assert fat.gate_for(
        "CreateFileW", k, a,
        ["0x1", "0x40000000", "0x2", "0x0"],
        "C:\\Users\\x\\AppData\\Roaming\\payload.exe") == "drop"


def test_startup_pdb_write_does_not_fire(fat):
    """b104's own startup wrote ConsoleApp2.pdb. Scratch is not a drop."""
    k, a = fat.parse_stop_on("network,file")
    assert fat.gate_for(
        "CreateFileW", k, a,
        ["0x1", "0x40000000", "0x2", "0x0"],
        "C:\\Windows\\ConsoleApp2.pdb") is None


def test_resolved_writetofile_to_staging_fires(fat):
    k, a = fat.parse_stop_on("network,file")
    assert fat.gate_for(
        "WriteFile", k, a, ["0x2", "0x1", "0x2", "0x3"],
        "C:\\Users\\x\\AppData\\Roaming\\dropped.dll") == "drop"


# --- classify_path: the decision table -----------------------------------

@pytest.mark.parametrize("path,kind", [
    ("\\\\.\\PhysicalDrive0", "device"),
    ("\\\\.\\C:", "device"),
    ("\\Device\\Harddisk0\\DR0", "device"),
    ("C:\\Users\\x\\AppData\\Roaming\\p.exe", "drop"),
    ("C:\\Users\\x\\AppData\\Roaming\\p.dll", "drop"),
    ("C:\\Windows\\System32\\a.exe", "drop"),
    ("C:\\ProgramData\\a.ps1", "drop"),
    ("C:\\Temp\\p.exe", "drop"),
    ("C:\\Users\\x\\Start Menu\\Programs\\Startup\\run.bat", "drop"),
    ("C:\\Windows\\ConsoleApp2.pdb", None),
    ("C:\\a\\b.pdb", None),
    ("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\config\\machine.config", None),
    ("C:\\Windows\\Globalization\\Sorting\\sortdefault.nls", None),
    ("C:\\samples\\b104.exe.config", None),
    # a scratch file PLANTED in a staging dir is a drop
    ("C:\\Users\\x\\AppData\\Roaming\\x.pdb", "drop"),
    ("", None),
    (None, None),
])
def test_classify_path_table(fat, path, kind):
    assert fat.classify_path(path) == kind


def test_classify_path_normalises_slashes(fat):
    assert fat.classify_path("C:/Users/x/AppData/Roaming/p.exe") == "drop"


# --- the soundness rule itself -------------------------------------------

def test_an_unattributable_write_never_fires(fat):
    """This is the P1-F6 rule. No path, no claim."""
    k, a = fat.parse_stop_on("network,file")
    for args in (["0xafc", "0x1", "0x2", "0x3"], ["0x0"], None, []):
        assert fat.gate_for("WriteFile", k, a, args, None) is None
        assert fat.gate_for("WriteFile", k, a, args, "") is None


def test_writetofile_is_in_the_handle_apis(fat):
    """WriteFile's arg0 is a HANDLE; it must be routed through the map."""
    src = _FAT.read_text(encoding="utf-8")
    assert "WriteFile: 0" in src
    assert "NtWriteFile: 0" in src
    assert "handlePaths[" in src
    assert "pendingPathByTid[" in src
    # CloseHandle must release, or the map grows unbounded in a 150s window
    assert "forgetHandle" in src and "CloseHandle" in src


def test_the_gate_records_the_target_not_the_handle(fat):
    """An auditable hit must name what was written."""
    src = _FAT.read_text(encoding="utf-8")
    assert '"path": _dec.get("path")' in src
    assert "gate.get('path')" in src


def test_createfile_still_requires_write_access(fat):
    """P1-F2 must survive: a read is still not a drop."""
    k, a = fat.parse_stop_on("network,file")
    assert fat.gate_for("CreateFileW", k, a,
                        ["0x1", "0x80000000", "0x1", "0x0"],
                        "C:\\Users\\x\\AppData\\Roaming\\p.exe") is None
    assert fat.gate_for("CreateFileW", k, a,
                        ["0x1", "0x20000", "0x1", "0x0"],
                        "C:\\Users\\x\\AppData\\Roaming\\p.exe") is None
    assert fat.gate_for("CreateFileW", k, a,
                        None, "C:\\Users\\x\\AppData\\Roaming\\p.exe") is None


def test_network_gate_is_unchanged(fat):
    k, a = fat.parse_stop_on("network,file")
    assert fat.gate_for("WSAConnect", k, a, ["0x1", "0x2"], None) == "network"
    assert fat.gate_for("connect", k, a, ["0x1", "0x2"], None) == "network"


# --- the tracer side: the JS must actually build --------------------------

def _render_js():
    """Render the f-string template exactly as the tracer does."""
    import ast
    src = _FAT.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(_FAT))
    hits = [n for n in ast.walk(tree)
            if isinstance(n, ast.JoinedStr)
            and any(isinstance(v, ast.Constant)
                    and "Interceptor.attach" in str(v.value) for v in n.values)]
    assert len(hits) == 1, f"expected 1 hook template, found {len(hits)}"
    names = {x.id for x in ast.walk(hits[0]) if isinstance(x, ast.Name)}
    mod = ast.Module(body=[ast.Assign(
        targets=[ast.Name(id="JS", ctx=ast.Store())], value=hits[0],
        type_comment=None)], type_ignores=[])
    ns = {}
    if "args" in names:
        class Args:
            max_calls = 1000
            apis = "WriteFile"
        ns["args"] = Args()
    if "apis_js" in names:
        ns["apis_js"] = '"WriteFile"'
    exec(compile(ast.fix_missing_locations(mod), "<js>", "exec"), ns)
    return ns["JS"]


def test_the_tracer_js_builds_with_the_handle_map():
    """A broken template is silent at runtime - the probe just stops firing."""
    js = _render_js()
    assert "{{" not in js and "}}" not in js, "unrendered f-string escapes"
    assert js.count("{") == js.count("}"), "unbalanced braces"
    for needle in ("handlePaths", "pendingPathByTid", "createApiSet",
                   "closeApiSet", "rememberOpenedHandle", "forgetHandle",
                   "decoded['path']"):
        assert needle in js, f"missing from the generated JS: {needle}"