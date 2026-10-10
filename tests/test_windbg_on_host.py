"""The WinDbg dump analysis belongs on the analysis host.

`windbg_dump` is passive - it opens a `.dmp` file and never attaches to a live
target - so there was never a technical reason for it to run on the box that had
just executed the sample. It ran there anyway, because the only WinDbg it could
reach was mcp-windbg on `127.0.0.1:9097`, deliberately localhost-bound so
nothing off-box can drive the VM's debugger.

That left the one step of the post-detonation window with no reason to be there:
a sample that had just controlled the machine was analysed BY that machine.

It now runs on the host with `cdb.exe` against the pulled dump. The VM path
stays as a fallback for `--driver local`, where there is no local cdb but the MCP
server is localhost anyway.

These tests pin the host path, and pin that its output is not decorative - a
split that returns empty blocks would silently produce a pack with a
`windbg_analysis.json` and nothing in it.
"""
import json
import pathlib

import pytest

from winre import windbg_post as W


def test_the_host_path_is_preferred():
    """The order is the whole point: host first, VM only as a fallback."""
    src = pathlib.Path(W.__file__).read_text(encoding="utf-8")
    i = src.find("def analyze_dump(")
    body = src[i:]
    host = body.find("_analyze_with_local_cdb(")
    mcp = body.find("WinDbgMCPClient(")
    assert host != -1, "no host-side path"
    assert mcp != -1, "the VM fallback was removed; --driver local needs it"
    assert host < mcp, (
        "the mcp-windbg (VM) path runs before the local one - the analysis "
        "still happens on the box that executed the sample")


def test_the_vm_path_is_kept_for_local_runs():
    """Removing it would break `--driver local`, where cdb is absent but the MCP
    server is localhost anyway."""
    src = pathlib.Path(W.__file__).read_text(encoding="utf-8")
    assert "WinDbgMCPClient" in src
    assert "_ensure_mcp_server" in src


def test_local_cdb_is_found_on_this_host():
    """`cdb.exe` was already installed here - in the Windows SDK's Debuggers
    directory, not on PATH - which is exactly why a PATH-only probe missed it."""
    exe = W.local_cdb()
    if exe is None:
        pytest.skip("no cdb.exe on this host (ops/provision_host.ps1 stages it)")
    assert exe.is_file()
    assert exe.name.lower().startswith(("cdb", "kd"))


def test_the_transcript_split_is_not_degenerate():
    """The defect this pins: the first version split on the command text and
    returned blocks a few dozen characters long, because cdb echoes the whole
    `-c` string once (in `Reading initial command '...'`) and every marker
    appears in it. `find()` landed in that line; `rfind()` gets the real one.
    """
    text = (
        "0:000> cdb: Reading initial command '.echo ===WINRE_CMD_0===; "
        "!analyze -v; .echo ===WINRE_CMD_1===; .ecxr; q'\n"
        "===WINRE_CMD_0===\n"
        "EXCEPTION_RECORD: a real analysis line that must survive\n"
        "===WINRE_CMD_1===\n"
        "rax=0000000000000000\n"
    )
    out = W._split_output(text)
    assert "EXCEPTION_RECORD" in out["!analyze -v"], (
        f"the real output was lost: {out['!analyze -v']!r}")
    assert "Reading initial command" not in out["!analyze -v"], (
        "the split landed inside cdb's echo of the -c string, so the block is "
        "the command line rather than its output")
    assert "rax=" in out[".ecxr"]


def test_a_missing_command_is_recorded_as_absent_not_merged():
    text = "===WINRE_CMD_0===\nonly the first command produced output\n"
    out = W._split_output(text)
    assert out["!analyze -v"], "the command that did produce output was lost"
    for cmd in W.COMMANDS[1:]:
        assert out[cmd] == "", (
            f"{cmd} was attributed output it never produced")


def test_a_dump_cdb_cannot_open_is_an_honest_failure():
    """cdb exits non-zero on a dump it cannot read. That is reported, not
    swallowed into an empty success."""
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    bad = d / "empty.dmp"
    bad.write_bytes(b"")
    r = W._run_cdb(W.local_cdb() or pathlib.Path("cdb.exe"), bad, timeout=30)
    assert r.get("ok") is False, "an unopenable dump was reported as success"


def test_the_output_note_says_where_it_ran():
    """A reader must be able to tell the analysis happened off the VM."""
    src = pathlib.Path(W.__file__).read_text(encoding="utf-8")
    assert "ANALYSIS HOST" in src, (
        "the result does not state that it ran on the analysis host")
