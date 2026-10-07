"""Phase 5: a detonated VM is not a trustworthy analysis host.

Verified live before this file was written: on the VM left dirty by the
10-sample campaign, `require_clean_vm` blocks `--agentic-dbg` and `--dynamic`,
allows `--mode static` and `--mode agentic`, and an unreachable VM is treated
as NOT clean (unknown is not an invitation to execute).
"""
import pathlib

import pytest

from winre import vm_gate


class _FakeSSH:
    """Stands in for remote_driver.ssh_run so no VM is needed."""

    def __init__(self, marker=True, boom=False):
        self.marker = marker
        self.boom = boom
        self.calls = []

    def __call__(self, cfg, cmd, timeout=60):
        self.calls.append(cmd)
        if self.boom:
            raise OSError("VM unreachable")
        out = "True" if self.marker else "False"

        class R:
            returncode = 0
            stdout = out
            stderr = ""
        return R()


@pytest.fixture
def ssh(monkeypatch):
    def _mk(marker=True, boom=False):
        fake = _FakeSSH(marker, boom)

        def _run(cfg, cmd, timeout=60):
            return fake(cfg, cmd, timeout)
        monkeypatch.setattr(vm_gate.remote_driver, "ssh_run", _run,
                            raising=False)
        return fake
    return _mk


# --------------------------------------------------------- the gate itself

def test_clean_vm_allows_an_executing_mode(ssh):
    ssh(marker=True)
    ok, blocker = vm_gate.require_clean_vm({}, mode="agentic",
                                           agentic_dbg=True)
    assert ok and blocker is None


def test_dirty_vm_blocks_an_executing_mode(ssh):
    ssh(marker=False)
    ok, blocker = vm_gate.require_clean_vm({}, mode="agentic",
                                           agentic_dbg=True)
    assert ok is False and blocker
    assert "VM is dirty" in blocker["reason"]


def test_dynamic_is_blocked_too(ssh):
    ssh(marker=False)
    ok, _ = vm_gate.require_clean_vm({}, mode="agentic", dynamic=True)
    assert ok is False


def test_read_only_modes_run_on_a_dirty_vm(ssh):
    """A read-only analysis executes nothing, so it must not need a revert."""
    ssh(marker=False)
    for mode in ("static", "agentic"):
        ok, blocker = vm_gate.require_clean_vm({}, mode=mode)
        assert ok and blocker is None, mode


def test_an_unreachable_vm_fails_closed(ssh):
    """Unknown is not clean. Executing on a VM we cannot inspect is the one
    condition this gate exists to prevent."""
    ssh(boom=True)
    assert vm_gate.vm_is_clean({}) is False
    ok, _ = vm_gate.require_clean_vm({}, mode="agentic", dynamic=True)
    assert ok is False


# ------------------------------------------------------------- the message

def test_the_probe_command_survives_the_ssh_cmd_powershell_hop():
    """The bug this closes: the first `_probe` wrapped `Test-Path` in an
    if/else inside `powershell -Command "..."`. The nested quoting did not
    survive ssh -> cmd -> powershell, so PowerShell echoed the script text
    and stdout was never "True" - the gate reported every CLEAN VM as dirty
    and would have blocked every run. The stubbed unit tests could not catch
    it, because a stub agrees with whatever the implementation says.
    """
    from winre import vm_gate

    seen = {}

    def _cap(cfg, cmd, timeout=60):
        seen["cmd"] = cmd

        class R:
            returncode = 0
            stdout = "True"
            stderr = ""
        return R()

    orig = vm_gate.remote_driver.ssh_run
    vm_gate.remote_driver.ssh_run = _cap
    try:
        assert vm_gate.vm_is_clean({}) is True
        cmd = seen["cmd"]
        assert "Test-Path C:\\WinRE\\.clean_snapshot" in cmd
        assert "{ 'True' }" not in cmd, "an if/else inside the quotes is the bug"
    finally:
        vm_gate.remote_driver.ssh_run = orig


def test_a_malformed_probe_answer_is_not_read_as_clean():
    """A stdout that is the script text rather than True/False must read as
    dirty: fail closed on shape, not only on content."""
    from winre import vm_gate

    class Echo:
        returncode = 0
        stdout = "if (Test-Path C:\\WinRE\\.clean_snapshot) { 'True' } else { 'False' }"
        stderr = ""

    orig = vm_gate.remote_driver.ssh_run
    vm_gate.remote_driver.ssh_run = lambda *a, **k: Echo()
    try:
        assert vm_gate.vm_is_clean({}) is False
    finally:
        vm_gate.remote_driver.ssh_run = orig
def test_the_blocker_says_what_to_do(ssh):
    ssh(marker=False)
    b = vm_gate.dirty_blocker({})
    steps = " ".join(b["how_to_clear"])
    assert "revert" in steps
    # and it must say WinRE does NOT do this itself
    assert "not a product feature" in steps or "deliberately" in steps
    assert b["last_action"]


# -------------------------------------------------------- the refusal record

def test_a_refusal_is_recorded_and_the_prior_pack_is_kept(tmp_path, ssh):
    """A refusal must be visible. It must NOT delete the run it refused over."""
    from winre.evidence import EvidencePack
    pack = EvidencePack(tmp_path, "a" * 64, mode="agentic").ensure()
    pack.write("intake", "intake.json", {"sha256": "a" * 64})
    ssh(marker=False)
    b = vm_gate.dirty_blocker({})
    vm_gate.record_refusal(pack, b)
    # the previous run's evidence is untouched
    assert (pack.stages["intake"] / "intake.json").is_file()
    rec = pack.read("intake", "REFUSED.json")
    assert rec["ok"] is False and "VM is dirty" in rec["error"]
    assert rec["note"] == "the pack from the previous run is left in place"


def test_a_clean_vm_records_nothing(tmp_path, ssh):
    from winre.evidence import EvidencePack
    pack = EvidencePack(tmp_path, "b" * 64, mode="agentic").ensure()
    ssh(marker=True)
    b = vm_gate.dirty_blocker({})
    assert b is None
    vm_gate.record_refusal(pack, b or {})
    assert pack.read("intake", "REFUSED.json") is None


# ------------------------------------------------- it is actually wired in

def test_the_driver_consults_the_gate():
    src = pathlib.Path("winre/remote_driver.py").read_text(encoding="utf-8")
    assert "require_clean_vm(" in src
    assert "record_refusal(pack, blocker)" in src
    assert '"vm_gate": blocker' in src


def test_the_pipeline_consults_the_gate():
    src = pathlib.Path("winre/pipeline.py").read_text(encoding="utf-8")
    assert "require_clean_vm(" in src
    assert "record_refusal(pack, blocker)" in src


def test_both_abort_with_the_fix_printed():
    """An abort that says only 'ABORT' costs an operator a round trip."""
    for rel in ("winre/remote_driver.py", "winre/pipeline.py"):
        src = pathlib.Path(rel).read_text(encoding="utf-8")
        assert "how_to_clear" in src, rel


def test_the_module_has_no_hypervisor_dependency():
    """WinRE must never revert the VM. The gate only OBSERVES the marker."""
    src = pathlib.Path(vm_gate.__file__).read_text(encoding="utf-8")
    # the word "revert" is fine - the docstring says we do NOT do it. What
    # must not exist is code that performs a restore.
    for bad in ("vmrun", "subprocess.run", "Restore-Snapshot",
                "hypervisor_restore", "revert_snapshot"):
        assert bad not in src, f"{bad} would make the gate a revert feature"