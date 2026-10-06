"""RevAI handoff items 8/9/10 (2026-10-06) - behavioural guards.

Item 8  unpacked dump cannot be re-analysed statically
Item 9  no detonation-window calibration
Item 10 dump not emitted in a form RevAI can import

Each test pins a property that a third party (RevAI's `load_dynamic_pack`)
depends on, so a future refactor cannot quietly change the contract.
"""
import importlib.util
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _load_frida():
    """frida_api_trace.py is a script, not a package member."""
    spec = importlib.util.spec_from_file_location(
        "fat", REPO / "tools" / "frida_api_trace.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # `import frida` is inside main()
    return mod


# --- item 10: the import-facing dump schema -------------------------------

def test_every_dump_record_carries_the_import_schema():
    """RevAI's loader reads dump_kind / oep_target / a PE-validity flag.

    `dump_path` alone left the artifact unimportable, and the record existed on
    only one of the two dump paths.
    """
    orch = _src("winre/orchestrator.py")
    assert "dump_schema_block" in orch, (
        "the --dynamic path must emit the shared dump schema, not a "
        "hand-rolled subset")
    loops = _src("winre/debug_loops.py")
    assert "def dump_schema_block(" in loops
    for field in ("dump_kind", "oep_target", "pe_valid", "is_pe",
                  "imports_count", "importable_by_pefile"):
        assert f'"{field}"' in loops, f"{field} missing from the schema block"


def test_schema_distinguishes_unknown_from_invalid():
    """'we could not check' must never read as 'this dump is broken'."""
    from winre import debug_loops

    checked_false = {"parses": False, "checked": False, "where": "driver",
                     "error": "pefile not importable locally"}
    orig = debug_loops._dump_parse_check
    try:
        debug_loops._dump_parse_check = lambda p: dict(checked_false)
        blk = debug_loops.dump_schema_block("x.dmp", dump_kind="module")
        assert blk["pe_valid"] is None, (
            "an unavailable probe must report pe_valid=None, not False")
        assert blk["pe_valid_known"] is False
        assert blk["rebuild_hint"] is None, (
            "it must NOT tell a consumer to go rebuild a dump nobody checked")
        assert blk["pe_valid_unknown_reason"]

        debug_loops._dump_parse_check = lambda p: {
            "parses": False, "checked": True, "where": "local",
            "error": "PEFormatError"}
        blk2 = debug_loops.dump_schema_block("x.dmp", dump_kind="module")
        assert blk2["pe_valid"] is False, "a real negative must stay False"
        assert blk2["rebuild_hint"], "a real negative must be actionable"
    finally:
        debug_loops._dump_parse_check = orig


def test_heap_dumps_are_labelled_non_pe():
    """The 2026-09-11 artifact was a heap blob: not a PE, no .idata to rebuild.

    An IAT rebuild could never have fixed it, so the record must say so rather
    than implying a corrupt module.
    """
    from winre import debug_loops
    blk = debug_loops.dump_schema_block(
        "heap.bin", dump_kind="heap", oep="0x7ff0",
        rebuild_applicable=False,
        rebuild_reason="a heap region is not a PE")
    assert blk["dump_kind"] == "heap"
    assert blk["is_pe"] is False or blk["pe_valid"] is None
    assert blk["imports_rebuild_applicable"] is False
    hint = (blk.get("rebuild_hint") or "") + (blk.get("consumer_note") or "")
    assert "not a PE" in hint or blk["pe_valid"] is None


def test_module_dump_says_it_is_not_the_unpacked_payload():
    """The --dynamic path never runs the sample, so its dump is the packed stub.

    Without this a consumer re-analyses the packer and concludes the payload
    was missed - which is exactly what RevAI reported.
    """
    from winre import debug_loops
    orig = debug_loops._dump_parse_check
    try:
        debug_loops._dump_parse_check = lambda p: {
            "parses": True, "checked": True, "imports": 2,
            "machine": "0x8664", "where": "local"}
        blk = debug_loops.dump_schema_block("packed.dmp", dump_kind="module",
                                            ran_to_oep=False)
        assert blk["pe_valid"] is True
        assert blk["payload_unpacked"] is False
        assert blk["rebuild_hint"] is None, (
            "2 imports on a still-packed image is the packer, not damage")
        assert "packed stub" in blk["consumer_note"]
        assert "--agentic-dbg" in blk["consumer_note"], (
            "the note must point at the path that DOES rebuild")

        blk2 = debug_loops.dump_schema_block("unpacked.dmp",
                                             dump_kind="module",
                                             ran_to_oep=True)
        assert blk2["payload_unpacked"] is True
        assert "consumer_note" not in blk2
    finally:
        debug_loops._dump_parse_check = orig


def test_parse_check_always_says_whether_it_checked():
    src = _src("winre/debug_loops.py")
    body = src.split("def _dump_parse_check(")[1].split("\ndef ")[0]
    returns = [ln for ln in body.splitlines() if "return {" in ln]
    assert returns, "no returns found - the probe was restructured"
    for ln in returns:
        assert '"checked"' in ln, f"return without a `checked` discriminator: {ln.strip()}"


def test_existing_rebuild_hint_no_longer_fires_on_an_unavailable_probe():
    src = _src("winre/debug_loops.py")
    assert 'if dump_parse.get("checked") and (not dump_parse.get("parses")' in src, (
        "agentic_unpack's rebuild hint must be guarded by `checked`; "
        "unguarded, a missing pefile told consumers to rebuild a good dump")


# --- item 9: the detonation window follows the sample ---------------------

def test_gate_classification_is_correct():
    fat = _load_frida()
    kinds, apis = fat.parse_stop_on("network,file")
    assert kinds == {"network", "file"} and apis == set()
    for api, want in (("WSAConnect", "network"), ("connect", "network"),
                      ("WinHttpSendRequest", "network"),
                      ("CreateFileW", "file"), ("WriteFile", "file"),
                      ("MoveFileW", "file"), ("NtCreateFile", "file")):
        assert fat.gate_for(api, kinds, apis) == want, api
    # not interesting on their own
    for api in ("VirtualAlloc", "CreateThread", "GetTickCount", "LoadLibraryW"):
        assert fat.gate_for(api, kinds, apis) is None, api


def test_gate_can_be_disabled_or_narrowed():
    fat = _load_frida()
    assert fat.gate_for("WSAConnect", *fat.parse_stop_on("")) is None
    kinds, apis = fat.parse_stop_on("api:VirtualAlloc")
    assert kinds == set() and apis == {"VIRTUALALLOC"}
    assert fat.gate_for("VirtualAlloc", kinds, apis) == "api:VirtualAlloc"
    assert fat.gate_for("CreateThread", kinds, apis) is None


def test_the_window_cap_is_no_longer_the_45s_that_missed_the_dga():
    """2026-09-11: 45s -> 497 events, no DGA. 150s -> 694,692 events, live C2."""
    for rel in ("winre/pipeline.py", "winre/remote_driver.py",
                "winre/orchestrator.py"):
        src = _src(rel)
        assert 'default=45' not in src.split("add_argument")[0] or True
        import re
        caps = re.findall(r'--max-seconds"[^)]*default=(\d+)', src)
        assert caps, f"{rel}: no --max-seconds default found"
        assert int(caps[0]) >= 150, (
            f"{rel}: default cap is still {caps[0]}s - that is the window that "
            "missed the DGA in RevAI's measurement")


def test_idle_stop_is_off_by_default_because_sleeping_samples_look_idle():
    """The gate exists BECAUSE idle-stop truncates a sleeping sample.

    If idle-stop silently comes back as the default mechanism the gate never
    gets a chance to fire, and the window ends before the sample wakes up.
    """
    for rel in ("winre/pipeline.py", "winre/remote_driver.py",
                "winre/orchestrator.py"):
        import re
        got = re.findall(r'--idle-stop-seconds"[^)]*default=(\d+)', _src(rel))
        assert got, f"{rel}: no --idle-stop-seconds default"
        assert int(got[0]) == 0, (
            f"{rel}: idle-stop default is {got[0]}s - it must be 0 (off); the "
            "behaviour gate is the default mechanism")
    ps = _src("winre/flare_dynamic_job.ps1")
    assert "[int]$IdleStopSeconds = 0" in ps, (
        "the VM job must default idle-stop to 0 as well")


def test_gate_is_wired_end_to_end():
    """Flag -> frida trace -> job -> orchestrator -> control-plane driver."""
    fat = _src("tools/frida_api_trace.py")
    assert '"--stop-on"' in fat and '"--stop-on-settle"' in fat
    assert "stop_reason = \"gate:\"" in fat, (
        "a gated stop must be distinguishable from a cap stop in the telemetry")
    for field in ("gate_fired", "gate_kind", "gate_at_s"):
        assert f'"{field}"' in fat, f"{field} missing from run.json telemetry"

    job = _src("winre/flare_dynamic_job.ps1")
    assert "[string]$StopOn = \"network,file\"" in job
    assert '"--stop-on"' in job, "the VM job must forward --stop-on to frida"
    assert '"-StopOn"' in _src("winre/orchestrator.py"), (
        "the orchestrator must forward -StopOn to the VM job")

    for rel in ("winre/pipeline.py", "winre/remote_driver.py",
                "winre/orchestrator.py"):
        src = _src(rel)
        assert '"--stop-on"' in src, f"{rel}: no --stop-on flag"
        assert "stop_on=stop_on" in src or "stop_on=args.stop_on" in src, (
            f"{rel}: the flag is parsed but never passed down")

    helper = _src("winre/_remote_dynamic_helper.py")
    assert "--stop-on" in helper, "the VM helper must forward the gate"
    from winre import remote_driver
    assert "--stop-on" in remote_driver.REMOTE_DYNAMIC_HELPER, (
        "the embedded helper copy drifted from the file again")


def test_gate_verdict_reaches_the_pack():
    job = _src("winre/flare_dynamic_job.ps1")
    assert "gate_spec" in job and "gate_settle_s" in job, (
        "the job result must say which gate was requested")
    orch = _src("winre/orchestrator.py")
    assert 'meta["window_gate"]' in orch and 'meta["window_stop_reason"]' in orch, (
        "a reader must be able to tell 'the sample did nothing' from 'we "
        "stopped right after it did' without digging through window.*")


# --- the docs must not contradict the new behaviour ------------------------

def test_docs_describe_the_gate_and_the_dump_schema():
    bridge = _src("docs/REVAI-BRIDGE.md")
    assert "stop-on" in bridge or "behaviour gate" in bridge.lower(), (
        "REVAI-BRIDGE is the contract for the third-party consumer; the "
        "window semantics changed and it must say so")
    ev = _src("docs/EVIDENCE.md")
    assert "dump_kind" in ev, (
        "docs/EVIDENCE.md is the public artifact map; x64dbg_dump gained "
        "fields and it must list them")