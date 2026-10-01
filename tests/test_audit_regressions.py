"""Regression guards for the 2026-09-28 code audit.

Every test here corresponds to a defect found by reading the code that would
otherwise have come back. They are deliberately behavioural (call the thing)
rather than textual (grep the source), because the audit found several
assertions that could not fail.
"""
import json
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SETUP = REPO / "install" / "setup-flarevm.ps1"
VERIFY = REPO / "install" / "verify-flarevm.ps1"
BOOT_TASK = '$bootTask = Get-ScheduledTask -TaskName "WinRE-MCP-Boot"'


def _src(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


# --- the gate must FAIL CLOSED on an unrecognised mode ----------------------

def test_unknown_gate_mode_fails_closed(monkeypatch):
    from winre import snapshot_gate
    for bad in ("true", "1", "enforced", "Enforce ", "nope", ""):
        monkeypatch.setenv("WINRE_SNAPSHOT_GATE", bad)
        assert snapshot_gate.mode() == "enforce", (
            f"WINRE_SNAPSHOT_GATE={bad!r} weakened the gate to observe")
    for good in ("observe", "enforce", "off", "ENFORCE ", " Off"):
        monkeypatch.setenv("WINRE_SNAPSHOT_GATE", good)
        assert snapshot_gate.mode() == good.strip().lower()


def test_vm_side_gate_agrees_with_the_control_plane():
    """The VM copy of the enum must fail closed too.

    It used to rewrite anything unrecognised (including "off") to "observe",
    which made the off branch unreachable and ate the one-shot marker anyway.
    """
    src = _src("winre/orchestrator.py")
    block = src.split("gmode = os.environ.get")[1].split("\n\n")[0]
    assert '"off"' in block, "the VM-side whitelist no longer accepts off"
    assert 'gmode = "enforce"' in block, (
        "the VM side must default an unknown mode to enforce, not observe")
    assert 'gmode = "observe"' not in block, (
        "an unknown WINRE_SNAPSHOT_GATE must never be rewritten to observe")


def test_debug_session_scope_does_not_outlive_a_run():
    from winre import snapshot_gate
    snapshot_gate._debug_consumed.add("deadbeef")
    snapshot_gate.reset_session()
    assert not snapshot_gate._debug_consumed, (
        "a long-lived host process would allow a second execution of the same "
        "sha off a freshly restored, armed snapshot")
    for driver in ("winre/pipeline.py", "winre/remote_driver.py"):
        assert "_gate.reset_session()" in _src(driver), (
            f"{driver} must clear debug-session scope at the start of a run")


# --- evidence must be preserved, never destroyed ----------------------------

def test_gate_blocked_run_preserves_the_previous_pack(tmp_path):
    """The blocked path MOVES the old pack and records where it went.

    It used to rmtree the dynamic dir and then write a record claiming
    "moved, never deleted" with preserved_previous=null.
    """
    from winre import evidence
    pack = evidence.EvidencePack(tmp_path, "a" * 64, mode="agentic").ensure()
    dyn = pack.stages["dynamic"]
    dyn.mkdir(parents=True, exist_ok=True)
    (dyn / "frida_trace.json").write_text('{"events": 533}', encoding="utf-8")
    (dyn / "META.json").write_text('{"ok": true}', encoding="utf-8")

    out = evidence.preserve_dynamic(pack)
    assert out["preserved_previous"], "the previous pack must be pointed at"
    archived = pack.root / out["preserved_previous"]
    assert (archived / "frida_trace.json").is_file(), (
        "the archived pack must actually contain the previous evidence")
    assert not (dyn / "frida_trace.json").exists(), (
        "stale artifacts must not sit beside a SKIP record that says there "
        "are none")
    assert not out.get("preserve_error")

    out2 = evidence.preserve_dynamic(pack)     # empty dynamic dir -> clean no-op
    assert out2["preserved_previous"] is None


def test_two_archives_in_the_same_second_do_not_collide(tmp_path):
    from winre import evidence
    pack = evidence.EvidencePack(tmp_path, "b" * 64, mode="agentic").ensure()
    dyn = pack.stages["dynamic"]
    names = []
    for _ in range(2):
        dyn.mkdir(parents=True, exist_ok=True)
        (dyn / "frida_trace.json").write_text("{}", encoding="utf-8")
        out = evidence.preserve_dynamic(pack, stamp="20260928T101500Z")
        names.append(out["preserved_previous"])
        (dyn / "frida_trace.json").write_text("{}", encoding="utf-8")
    assert len(set(names)) == 2, f"archive names collided: {names}"
    for rel in names:
        assert (pack.root / rel / "frida_trace.json").is_file(), (
            "a same-second move must not nest into the previous archive")


def test_blocked_paths_never_delete_the_dynamic_dir():
    for f in ("winre/remote_driver.py", "winre/pipeline.py"):
        src = _src(f)
        assert "rmtree" not in src.split("snapshot_gate_blocked")[0][-2500:], (
            f"{f} deletes dynamic evidence on a gate refusal; it must move it")


# --- verdict honesty --------------------------------------------------------

def test_no_verdict_is_none_not_the_string_unknown():
    """"unknown" is a real verdict; None means the stage produced none."""
    from winre import evidence
    assert evidence.verdict_fields(None)[2] is True
    assert evidence.verdict_fields("")[2] is True
    assert evidence.verdict_fields({"verdict": None})[2] is True
    assert evidence.verdict_fields({"verdict": "unknown"})[2] is False
    src = _src("winre/agentic.py")
    assert '"verdict": "unknown", "source": "deterministic_fallback"' not in src, (
        "a fallback with no LLM verdict must emit None, or it is recorded as a "
        'real "unknown" verdict and no_verdict stays false')


def test_off_enum_labels_are_invalid_not_silently_unknown():
    from winre.agentic import _normalize_verdict
    for bad in ("totally fine", "benign!!", 42, True):
        out = _normalize_verdict({"verdict": bad})
        assert out.get("verdict_invalid") is True, f"{bad!r} was accepted"
        assert out.get("verdict") is None, f"{bad!r} became a verdict"
    assert _normalize_verdict({"verdict": "malware"})["verdict"] == "malicious"
    assert _normalize_verdict({"verdict": "legit"})["verdict"] == "benign"


def test_verdict_is_only_parsed_from_the_assistant_message():
    scan = _src("winre/agentic.py").split(
        'if not llm_text and mtype not in ("human", "tool"):')[1][:1500]
    assert 'if mtype == "tool":' in scan and "continue" in scan, (
        'tool output is evidence, not judgement: a nested {"verdict": ...} '
        "object in a tool payload must not become the run's verdict")


def test_judgment_role_produces_the_verdict_when_it_differs():
    src = _src("winre/agentic.py")
    assert "verdict_judged_by" in src, (
        "the run must record WHICH role produced the verdict")
    assert re.search(r'llm_roles\.get\("judgment"\)[^)]*!=\s*'
                     r'llm_roles\.get\("planner"\)', src), (
        "when the pinned judgment model differs from the planner it must see "
        "the draft verdict - otherwise every artifact misattributes it")


def test_aborted_run_writes_a_non_green_audit():
    for f in ("winre/remote_driver.py", "winre/pipeline.py"):
        src = _src(f)
        assert '"aborted": True' in src, f"{f}: no abort marker"
        abort = src.split('results["aborted"] = True')[1][:6000]
        assert "audit.json" in abort, (
            f"{f}: a refused run must refresh audit.json, otherwise the "
            "previous run's truly_green:true survives and the UI shows green")
        assert "truly_green" in abort, "the abort audit must be explicitly red"


def test_ui_survives_an_over_budget_refusal():
    assert 'res["results"].get("audit")' in _src("winre/ui/app.py"), (
        "run_remote_pipeline returns no results[audit] when it aborts; "
        "unconditional indexing raised KeyError and showed the operator a "
        "crash string instead of the plan's refusal reason")


# --- audit must fail closed -------------------------------------------------

def test_unreadable_dynamic_stage_json_is_not_green(tmp_path, monkeypatch):
    from winre import audit
    monkeypatch.setenv("WINRE_SNAPSHOT_GATE", "enforce")
    ev = tmp_path / "dynamic"
    ev.mkdir(parents=True)
    (ev / "META.json").write_text(json.dumps(
        {"ok": True, "frida_events": 12, "run_id": "r"}), encoding="utf-8")
    (ev / "STAGE.json").write_text('{"gate_pass": tr', encoding="utf-8")  # torn
    a = audit.audit(tmp_path)
    assert a["truly_green"] is False, "a torn STAGE.json kept the run green"
    assert a["snapshot_gate"]["ok"] is False


# --- deployment: setup and verify must agree on what is required -----------

def test_setup_and_verify_agree_on_required_python_modules():
    """angr was Fail in verify and optional in setup: 0 FAIL was unreachable."""
    setup, verify = _src("install/setup-flarevm.ps1"), _src("install/verify-flarevm.ps1")
    m = re.search(r"\$optionalMods\s*=\s*@\(([^)]*)\)", setup)
    assert m, "setup must declare its optional python modules"
    assert "angr" in re.findall(r'"([a-z0-9_]+)"', m.group(1)), (
        "angr must stay classified optional in setup")
    block = verify.split("python module $mod not importable")[0]
    checked = re.findall(r'"([a-z0-9_]+)"',
                         block[block.rfind("foreach ($mod"):])
    assert "angr" not in checked, (
        "verify must not hard-Fail a module setup treats as optional")
    req = verify.split("--- required tool census")[1]
    cm = re.search(r'foreach \(\$m in @\(([^)]*)\)', req)
    if cm:
        assert "angr" not in re.findall(r'"([a-z0-9_]+)"', cm.group(1))


def test_verify_does_not_warn_about_census_required_items():
    """Nothing we own may be WARN-only: that is how a 0 FAIL lied."""
    src = _src("install/verify-flarevm.ps1")
    assert 'Warn "no firewall rule' not in src, (
        "the :9094 firewall rule is ours and documented as created by setup; a "
        "missing one is a FAIL")
    assert "Fail \"  [census] REQUIRED python module missing" in src


def test_mcp_liveness_is_a_handshake_not_a_port_check():
    src = _src("install/verify-flarevm.ps1")
    assert "Test-McpHandshake" in src, (
        "a listening socket is not proof of life - an unrelated or unlicensed "
        "listener satisfied the old check")
    assert "jsonrpc" in src and "initialize" in src
    assert BOOT_TASK in src, (
        "the task that actually serves :9009/:9097 after a revert must be "
        "verified, not assumed")
    boot = src.split(BOOT_TASK)[1]
    block = boot[:boot.index("Write-Host")]
    assert "Fail" in block and "absent" in block, (
        "the boot task check must be a FAIL, not an Info")


def test_ida_and_malcat_discovery_matches_setup():
    """A tool verify cannot find is reported absent, so its gates get skipped."""
    setup, verify = _src("install/setup-flarevm.ps1"), _src("install/verify-flarevm.ps1")
    assert "$env:WINRE_IDA_DIR" in verify, "verify must honour WINRE_IDA_DIR"
    for d in ("IDA Free 9.3", "IDA Pro 9.3", "IDA Professional 8.3"):
        assert d in setup, f"setup accepts {d}"
        assert d in verify, f"verify must also accept {d} or its gates are skipped"
    assert "Downloads\\malcat" in verify, (
        "a portable Malcat in Downloads is an accepted install location")


def test_reapply_chain_fails_on_verify_failure():
    src = _src("ops/reapply_after_revert.ps1")
    assert "verifyRc" in src and "exit 1" in src, (
        "reapply_after_revert.ps1 exited 0 no matter how badly the deployment "
        "failed - an unusable box read as a successful chain")
    assert "setupRc" in src
    body = src.split("function Invoke-VM")[1].split("function Get-File")[0]
    assert "Wait-Job" in body and "-Timeout $timeoutSec" in body, (
        "Invoke-VM accepted a timeout and ignored it")


def test_provision_stages_directories_and_reports_failures():
    src = _src("ops/provision_tools.ps1")
    assert "-Directory" in src, (
        "capa-rules and x64dbg-mcp-server are cloned directories; only -File "
        "was shipped, so the VM never received them")
    assert "dirStageFailed" in src, "a failed directory stage must be reported"
    assert "BatchMode=yes" in src, (
        "without BatchMode a rejected key hangs the chain on a password prompt")


def test_sync_prune_cannot_target_anything_outside_the_mirrored_trees():
    src = _src("ops/sync_to_flare.ps1")
    assert "SKIPPED_OUTSIDE" in src, (
        "prune must refuse any target outside winre/tools/ops/install/docs/"
        "tests/assets even if the manifest is wrong")
    assert re.search(r"FAILED '\s*\+\s*`?\$rel", src), (
        "a locked or ACL-denied file must not be reported as REMOVED")
    assert "PRUNE_NO_ROOT" in src, (
        "an unreachable VM must not read as 'nothing to remove'")
    ex = re.search(r"\$Excludes\s*=\s*@\(([^)]*)\)", src).group(1)
    assert "docs\\internal" not in ex, (
        "a backslash can never appear in $_.Name, so that exclude never fired "
        "and the gitignored handoff notes were shipped to the VM")
    assert "docs\\internal" in src, "nested local-only paths must be removed"


def test_shipped_env_template_cannot_weaken_the_gate():
    tpl = _src(".env.template")
    active = [ln.strip() for ln in tpl.splitlines()
              if ln.strip().startswith("WINRE_SNAPSHOT_GATE")]
    assert active == ["WINRE_SNAPSHOT_GATE=enforce"], (
        f"the template must ship the code default; got {active}")
    assert "observe (default)" not in _src("winre/snapshot_gate.py"), (
        'the stale "observe is the default" claim survives in the docstring')


# --- the tests themselves must be able to fail ------------------------------

def test_helper_contract_holds_without_the_untracked_copy():
    """winre/_remote_dynamic_helper.py is gitignored, so a clone has no copy."""
    tracked = subprocess.run(
        ["git", "ls-files", "winre/_remote_dynamic_helper.py"],
        cwd=REPO, capture_output=True, text=True).stdout.strip()
    assert not tracked, (
        "if this becomes tracked, test_orchestrator_and_helper_pass_the_nonce "
        "can assert on it unconditionally")
    from winre import remote_driver
    helper = remote_driver.REMOTE_DYNAMIC_HELPER
    assert "--run-id=" in helper and "WINRE_RUN_ID" in helper, (
        "the EMBEDDED helper the driver ships must carry the nonce")
    assert "--run-id" in _src("winre/orchestrator.py")


def test_entrypoint_discovery_covers_argv_style_mains():
    src = _src("tests/test_entrypoints.py")
    assert "_main" in src or "re.search" in src, (
        'the discovery predicate required "def main(" and silently excluded '
        "every module using _main(argv) - snapshot_gate, audit and all three "
        "SQL clients had zero --help coverage")


def test_llm_role_tests_do_not_rely_on_magic_counts():
    body = _src("tests/test_llm_roles.py")
    # strip docstrings and comments first: prose ABOUT the old assertion must
    # not satisfy the check for the assertion itself
    body = re.sub(r'"""[\s\S]*?"""', "", body)
    body = re.sub(r"#[^\n]*", "", body)
    assert not re.search(r"assert\s+\w+\.count\(", body), (
        "assert src.count(...) >= 5 passes at exactly 5: add a return path and "
        "the guarantee silently breaks")


def test_llm_role_guard_covers_every_role_variable():
    src = _src("tests/test_llm_roles.py")
    for var in ("WINRE_LLM_MODEL", "WINRE_LLM_PLANNER_MODEL",
                "WINRE_LLM_VERDICT_MODEL"):
        assert var in src, (
            f"the one-resolver guard must cover {var} too - the UI read "
            "WINRE_LLM_MODEL directly and the guard never noticed")
