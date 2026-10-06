"""The post-run dump must not blame privileges for a dead process.

procdump prints, for a PID that no longer exists:

    Try elevating the command prompt or using PsExec to make one as SYSTEM.
        psexec.exe -s -d -i cmd.exe
        procdump.exe -accepteula ...

Reproduced live on the FlareVM against a stopped PID on 2026-10-06, and matched
verbatim to the `error` recorded for b104, b107 and b108. All three packs
therefore claim a privilege problem that does not exist, while the real cause
is that the sample exited before the dump - and that the in-run capture was
scheduled at 70% of a window the behaviour gate had already ended.

memory_harvest() now checks the pid and, if it is gone, says so plainly. The
real fix is upstream (two in-run dump passes), but this is what stops an
analyst chasing the wrong bug.
"""
import pathlib

import pytest

from winre import post_mortem
from winre.post_mortem import memory_harvest


def test_no_pid_is_reported_plainly(tmp_path):
    d = memory_harvest(tmp_path, sample_pid=None)
    assert d["ok"] is False
    assert "no sample pid" in d["error"]


def _stub_procdump(tmp_path, monkeypatch):
    p = tmp_path / "Procdump64.exe"
    p.write_text("stub")
    monkeypatch.setattr(post_mortem, "PROCDUMP", str(p))
    return p


def test_a_nonexistent_pid_is_reported_as_exited(tmp_path, monkeypatch):
    """A pid that cannot exist; psutil.pid_exists is False for it.

    procdump must be present or the 'missing' guard fires first and this path
    is never reached - which is itself the real ordering on the appliance,
    where it always exists.
    """
    import psutil
    _stub_procdump(tmp_path, monkeypatch)
    assert psutil.pid_exists(4_000_000) is False
    d = memory_harvest(tmp_path, sample_pid=4_000_000)
    assert d["ok"] is False
    assert d["reason"] == "pid-exited"
    assert "had already exited" in d["error"]
    # and it must NOT look like the privilege problem it really was
    low = (d["error"] or "").lower()
    for word in ("psexec", "elevat", "system"):
        assert word not in low, f"error still blames '{word}': {d['error']}"


def test_a_missing_procdump_is_still_reported_plainly(tmp_path, monkeypatch):
    monkeypatch.setattr(post_mortem, "PROCDUMP",
                        str(tmp_path / "no-such-procdump.exe"))
    d = memory_harvest(tmp_path, sample_pid=1)
    assert d["ok"] is False and "procdump missing" in d["error"]


def test_in_run_captures_short_circuit_the_post_run_fallback(tmp_path):
    """An in-run dump is the reliable path; it must not be overwritten."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True)
    (mem / "sample_early_1234.dmp").write_bytes(b"MZ...")
    d = memory_harvest(tmp_path, sample_pid=1)
    assert d["ok"] is True
    assert d["count"] == 1
    assert "in-run capture" in d["note"]


def test_the_procdump_hint_is_not_presented_as_the_cause(tmp_path, monkeypatch):
    """When a dump still cannot be written, the raw hint stays for diagnosis
    but a reason and a note always accompany it, so 'no dump' is never silent."""
    import psutil
    _stub_procdump(tmp_path, monkeypatch)
    monkeypatch.setattr(psutil, "pid_exists", lambda p: True)

    def _fake_run(cmd, timeout):
        return (1, "", "ProcDump v12.01 ...\nTry elevating the command prompt "
                       "or using PsExec to make one as SYSTEM.")

    monkeypatch.setattr(post_mortem, "_run", _fake_run)
    d = memory_harvest(tmp_path, sample_pid=1)
    assert d["ok"] is False and d["count"] == 0
    assert d["reason"] == "no-dump-written"
    assert d["note"]
    # the hint survives for diagnosis, but it is not the stated cause
    assert "psexec" in d["error"].lower()


# --- the dynamic job must schedule two dump passes -----------------------

def _job():
    return pathlib.Path("winre/flare_dynamic_job.ps1").read_text("utf-8")


def test_two_dump_passes_are_scheduled():
    j = _job()
    assert '"early", "late"' in j
    assert "$pdProcs" in j
    assert "$memDir\\sample_$tag" in j, "dumps are named per pass"
    # the old single-dump-at-70% behaviour must be gone
    assert "sample_full" not in j, (
        "a single dump at 70% of the cap always lands after the sample exits")


def test_the_early_pass_is_short_enough_to_survive_a_gate_stop():
    """The behaviour gate stopped b108's window at 20.8s and b104's at 2.8s.
    b103 exits 1.8s after spawn, so the early pass must also come in under
    that - a 3s early dump missed it completely."""
    j = _job()
    assert "$delayEarly = 1" in j
    assert "* 0.02" not in j


def test_the_late_pass_is_still_the_70_percent_of_cap():
    j = _job()
    assert "$delayLate = [Math]::Max($delayEarly + 5, " \
           "[Math]::Floor($MaxSeconds * 0.7))" in j
    assert "0.7" in j


def test_each_pass_logs_its_own_outcome():
    j = _job()
    assert 'Log ("procdump[$tag] done ({0} dmp)" -f $n)' in j
    assert 'Log ("procdump total ({0} dmp)"' in j


def test_stale_dumps_are_cleaned_with_the_new_filter():
    j = _job()
    assert 'Filter "sample_*.dmp"' in j
    # the narrower 70%-only filter must be gone
    assert 'sample_full*.dmp' not in j


@pytest.mark.parametrize("tag", ["early", "late"])
def test_both_filenames_are_reachable_from_the_loop(tag):
    j = _job()
    assert f'$memDir\\sample_$tag' in j