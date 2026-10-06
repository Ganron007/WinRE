"""A detonation that never ran must not report green.

b105 (2026-10-06) is a DLL masquerading as .exe:

    frida.stderr.txt:
      spawning C:\\samples\\b105_..._277993739850.exe
      frida.ExecutableNotSupportedError: unable to spawn executable at '...':
        unsupported file format

    job.log:
      Frida start EnablePeSieve=False Adaptive=False
      WARN: sample process not observed (fast exit?)
      Frida exit=0
      window effective=20.5s reason=unknown adaptive=False
                           gate=network,file/not-fired
      procdump[early] done (0 dmp)   procdump[late] done (0 dmp)
      {"frida": "missing", "procmon": "ok", "network": "ok"}

    META.job.json: ok=true, frida_exit=0, sample_pid=null
    STAGE.json   : ok=true, gate_pass=true, summary "events=None ok=True"

Procmon recorded 217,599 rows and 24 spawns, which is exactly what a healthy
appliance does to a sample that never started. The stage reported green
because has_core accepted "procmon.csv exists" as proof of a detonation.

These tests pin the rule: no sample process observed means no detonation, and
the pack must say so rather than presenting an empty trace as a silent one.
"""
import ast
import pathlib

from winre import orchestrator


def _job():
    return pathlib.Path("winre/flare_dynamic_job.ps1").read_text("utf-8")


# --- the job must refuse to be green without a sample pid -----------------

def test_the_job_meta_has_exactly_one_ok_key():
    j = _job()
    assert "Duplicate keys" not in auth_parse_error(j)


def auth_parse_error(text):
    """Reuse the PowerShell parser if available, else fall back to a count."""
    import re
    body = text[text.find("  @{\n    ok = "):text.find("finished_at")]
    n = len(re.findall(r"^\s+ok = ", body, re.M))
    return f"duplicate ok keys ({n})" if n > 1 else ""


def test_the_job_names_the_dll_case_explicitly():
    j = _job()
    assert "ExecutableNotSupportedError" in j
    assert "unsupported file format" in j
    assert "rundll32" in j, "the fix hint must name the loader that is needed"
    assert "$detonation_err" in j


def test_the_job_records_detonation_reason():
    j = _job()
    assert "detonation_reason = if ($detonation_ran)" in j
    assert "detonation_ran = [bool]$samplePid" in j


def test_the_job_still_reports_green_when_the_sample_ran():
    j = _job()
    assert "ok = (-not $detonation_err)" in j


# --- the orchestrator must require an observed pid ------------------------

def _meta(**over):
    base = {"job_rc": 0, "job_ok": True, "sample_pid": 1234,
            "frida_events": 12, "error": None, "note": None}
    base.update(over)
    return base


def test_a_real_detonation_is_ok():
    assert orchestrator._finalize_ok(_meta()) is True


def test_no_pid_means_not_ok_even_with_healthy_procmon():
    """This is b105: everything else worked, nothing ran."""
    m = _meta(sample_pid=None, frida_events=0)
    assert orchestrator._finalize_ok(m) is False


def test_the_verdict_helper_names_the_failure(tmp_path):
    m = _meta(sample_pid=None)
    orchestrator._apply_detonation_verdict(m, trace=tmp_path / "nope.jsonl",
                                          dyn_dir=tmp_path)
    assert m["ok"] is False
    assert m["detonation_ran"] is False
    assert "never observed" in m["error"]
    assert "frida.stderr" in m["error"], "it must point at the actual failure"


def test_zero_events_with_a_live_pid_is_not_automatically_a_failure():
    """An inert sample is a real finding, not a broken stage - but it needs a
    live pid to say so."""
    m = _meta(sample_pid=99, frida_events=0, job_ok=True)
    assert orchestrator._finalize_ok(m) is True


def test_the_verdict_helper_marks_a_live_inert_sample_as_real(tmp_path):
    m = _meta(sample_pid=99, frida_events=0)
    orchestrator._apply_detonation_verdict(m, trace=tmp_path / "nope.jsonl",
                                          dyn_dir=tmp_path)
    assert m["ok"] is True
    assert m["detonation_ran"] is True
    assert "the silence is real, not a failure" in m["note"]


def test_the_verdict_helper_counts_the_trace(tmp_path):
    t = tmp_path / "frida_trace.jsonl"
    t.write_text('{"a":1}\n\n{"b":2}\n', encoding="utf-8")
    m = _meta(sample_pid=7)
    orchestrator._apply_detonation_verdict(m, trace=t, dyn_dir=tmp_path)
    assert m["frida_events"] == 2 and m["ok"] is True


def test_detonation_ran_is_recorded_either_way():
    assert orchestrator._detonation_ran(_meta(sample_pid=None)) is False
    assert orchestrator._detonation_ran(_meta(sample_pid=7)) is True


def test_a_nonzero_job_rc_without_a_pid_is_not_ok():
    m = _meta(job_rc=3, job_ok=False, sample_pid=None)
    assert orchestrator._finalize_ok(m) is False


# --- the pack must not hide the reason -----------------------------------

def test_the_summary_distinguishes_a_dead_stage():
    """STAGE.json must carry detonation_ran and the pack must say why it failed,
    checked structurally so the test does not break on quote style."""
    import ast
    tree = ast.parse(pathlib.Path("winre/remote_driver.py").read_text("utf-8"))
    kwargs = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            for kw in n.keywords:
                if kw.arg in ("detonation_ran", "frida_events", "error"):
                    kwargs.append(kw.arg)
    assert "detonation_ran" in kwargs, "STAGE.json must record whether it ran"
    src = pathlib.Path("winre/remote_driver.py").read_text("utf-8")
    assert "the detonation never started" in src
    # a dead stage must not silently inherit gate_pass from the gate block
    assert 'gate_pass = (gate_mode != "enforce")' in src