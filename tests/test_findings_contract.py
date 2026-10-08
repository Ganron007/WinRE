"""The analysis plane must never read a name it cannot see.

W3 raised this file into existence; the defect it guards against has now bitten
four times, which is four more times than it should have:

  * `stage_meta["post_analysis"]` before `stage_meta` was assigned - a successful
    detonation reported "did not run" over 32 files of evidence
  * `findings["route"]` before the `findings` dict existed
  * `name 'api' is not defined` in `_backfill_provenance`
  * NxOpenDbgEngine etc. - see below

Each was caught only by running real data, and each was swallowed by a
try/except into a `limitations[]` entry, so the run looked merely incomplete
instead of obviously broken.

The first guard written for this was a hand-rolled AST sweep. It was wrong three
separate ways (it counted names bound in nested scopes, missed nested `def`
names, and only checked read-before-write so it could not see the `api`
NameError at all). It has been replaced by `ruff`'s F821 - the same class of
check, by a tool that does not get the scoping wrong - proven against the exact
defect that shipped.
"""
import pathlib
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _ruff() -> str | None:
    return shutil.which("ruff") or shutil.which("ruff.exe")


requires_ruff = pytest.mark.skipif(not _ruff(), reason="ruff is not installed")


# ------------------------------------------------- the real control

@requires_ruff
def test_the_analysis_plane_has_no_undefined_names():
    """F821 covers both defect classes that bit this codebase.

    Verified against the real bug: removing
    `api = str(ev.get("api") or "")` from `_backfill_provenance` yields

        winre/findings.py:632: Undefined name `api`

    and reintroducing `findings["route"]` before the `findings` assignment
    yields the same rule against `findings`. One rule, both classes.
    """
    r = subprocess.run(
        ["ruff", "check", "--select", "F821", "--output-format", "concise",
         "winre"],
        capture_output=True, text=True, cwd=str(REPO), timeout=300)
    out = (r.stdout or "") + (r.stderr or "")
    assert "F821" not in out, (
        "these names are read that nothing defines - the exact defect that made "
        "a successful detonation report 'did not run':\n" + out[:1200])


@requires_ruff
def test_the_vm_side_tool_has_no_undefined_names():
    """The tracer runs on the VM; an undefined name there loses the evidence at
    the source, before the control plane can fail closed on it."""
    r = subprocess.run(
        ["ruff", "check", "--select", "F821", "--output-format", "concise",
         "tools"],
        capture_output=True, text=True, cwd=str(REPO), timeout=300)
    out = (r.stdout or "") + (r.stderr or "")
    offending = [ln for ln in out.splitlines() if "F821" in ln]
    assert not offending, (
        "undefined names in the VM-side tracer:\n" + "\n".join(offending[:10]))


def test_ruff_really_catches_the_defect_it_guards():
    """A guard that passes on broken code is worse than no guard: it buys
    exactly the confidence this file exists to withhold. So prove it fails by
    writing the defect into a scratch copy and checking ruff reports it.

    Both the NameError shape (`api`) and the read-before-write shape
    (`findings["route"]` before `findings: dict`) must be caught.
    """
    if not _ruff():
        pytest.skip("ruff is not installed")
    scratch = REPO / "winre" / "_ruff_probe.py"

    BUGS = {
        "NameError (the real _backfill_provenance bug)": '''
def f(dyn_dir):
    out = []
    for line in open(dyn_dir):
        if api.lower() == "createfilew":
            out.append(api)
    return out
''',
        "read-before-write (the real route bug)": '''
def f(mode_root):
    findings["route"] = {"managed": True}
    findings: dict = {"unpack": {}}
    return findings
''',
    }
    try:
        for label, src in BUGS.items():
            scratch.write_text(src, encoding="utf-8")
            r = subprocess.run(
                ["ruff", "check", "--select", "F821", "--output-format",
                 "concise", "winre/_ruff_probe.py"],
                capture_output=True, text=True, cwd=str(REPO), timeout=120)
            assert "F821" in (r.stdout or ""), (
                f"ruff did NOT catch {label} - this guard is decorative")
    finally:
        scratch.unlink(missing_ok=True)


# ------------------------------------------------- the scoping traps

def test_the_exception_closure_trap_is_avoided():
    """Python unbinds `except ... as e` when the handler exits, so a function
    defined INSIDE the handler that closes over it raises NameError when called
    later - even though the module reads correctly and every unit test passes.

    orchestrator._dump_schema_block hit exactly this: its comment promised the
    fallback "can never raise NameError", and it was the source of one.
    """
    src = (REPO / "winre" / "orchestrator.py").read_text(
        encoding="utf-8-sig")
    # the fallback must not interpolate the except-bound name at call time
    assert "dump_schema_error\": f\"{type(_schema_err" not in src, (
        "the dump-schema fallback closes over the exception variable, which "
        "Python deletes when the except clause exits")
    assert "_err_text=_schema_err_text" in src, (
        "bind the message into a default argument instead")


def test_lazy_imports_are_imported_where_they_are_used():
    """`remote_driver` is imported lazily inside one entry point of pipeline.py
    to break a circular import. A second entry point referenced it WITHOUT
    importing it, so every VM-gate call raised NameError.

    A lazy import is correct here and a module-level one would not be, so the
    rule this pins is narrower: if you reference a lazily-imported module, you
    import it in that function too.
    """
    src = (REPO / "winre" / "pipeline.py").read_text(encoding="utf-8")
    i = src.find("def run_pipeline(")
    assert i != -1
    body = src[i:]
    assert "from . import remote_driver as _remote_driver" in body[:4000], (
        "run_pipeline uses remote_driver.flare_cfg() but does not import it")
    # and the call site must use the imported name
    assert "_remote_driver.flare_cfg()" in body


def test_a_parameter_that_is_passed_is_a_parameter_that_exists():
    """`stop_on` / `stop_on_settle` were passed to _dynamic() but were never
    declared on run_pipeline - a NameError on the dynamic path, invisible to
    any static read of _dynamic itself.

    Narrow on purpose: only a keyword whose VALUE is a bare undefined name
    counts. `json.dumps(indent=2)` and `_findings.build(evidence_dir=pack.stages[...])`
    pass constants and attributes, which are fine.
    """
    import ast
    tree = ast.parse((REPO / "winre" / "pipeline.py").read_text(encoding="utf-8"))
    rp = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
              and n.name == "run_pipeline")
    local = {a.arg for a in
             list(rp.args.args) + list(rp.args.kwonlyargs)
             + list(rp.args.posonlyargs)}
    for n in ast.walk(rp):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            local.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local.add(n.name)

    missing = []
    for call in (n for n in ast.walk(rp) if isinstance(n, ast.Call)):
        for kw in call.keywords:
            v = kw.value
            if kw.arg and isinstance(v, ast.Name) and v.id not in local:
                missing.append((kw.arg, v.id, getattr(v, "lineno", 0)))
    assert not missing, (
        f"run_pipeline passes these names that nothing defines: {missing}")


# ------------------------------------------------- the location contract

def test_dynamic_findings_takes_the_mode_root_and_descends_itself(tmp_path):
    """dynamic_findings is handed logs/<sha>/<mode>/ and finds the stage dir
    under it. A caller that hands it the stage dir directly gets a second
    descent into a path that does not exist, which reads as an empty
    detonation - the exact symptom that made a successful run look dead."""
    from winre import findings as F
    stage = tmp_path / "agentic" / "dynamic"
    stage.mkdir(parents=True)
    (stage / "META.job.json").write_text(
        '{"sample_pid": 1, "window": {"effective_s": 12}}', encoding="utf-8")

    f = F.dynamic_findings(tmp_path / "agentic", sha="f" * 64)
    assert f["ok"] is True, f"mode root not accepted: {f['limitations'][:1]}"
    assert f["findings"]["window"]["effective_s"] == 12
    assert "META.job.json" in f["evidence_used"]


def test_the_route_is_recorded_not_left_as_a_silent_unknown(tmp_path):
    """A .NET assembly has no native OEP. Reporting the debug section as
    'unknown' for it reads as 'we never tried', which is how this mode looked
    across a whole real run. The route is a property of the sample, so it is
    recorded, and the reason native unpack does not apply is stated."""
    from winre import findings as F
    mode_root = tmp_path / "dbg"
    (mode_root / "quick").mkdir(parents=True)
    (mode_root / "deep").mkdir(parents=True)
    (mode_root / "quick" / "quick.json").write_text(
        '{"evidence": {"pe": {"is_dotnet": true}}, "verdict": {}}',
        encoding="utf-8")
    (mode_root / "deep" / "deep.json").write_text(
        '{"agent": {"dbg_ensure": {"arch": 64, "launched": true},'
        ' "unpack_prepass": {}}}', encoding="utf-8")

    f = F.dbg_findings(mode_root, sha="e" * 64)
    route = f["findings"]["route"]
    assert route["managed"] is True
    assert route["native_unpack_applies"] is False
    assert "dotnet" in route["method"]
    assert f["ok"] is True
    assert f["verdict"]["level"] != F.UNKNOWN
    assert any(".NET" in x for x in f["limitations"])


def test_native_route_still_reports_a_missing_oep():
    """The route record must not become a blanket excuse."""
    import inspect
    from winre import findings as F
    src = inspect.getsource(F.dbg_findings)
    assert 'if managed and not up.get("ok"):' in src
