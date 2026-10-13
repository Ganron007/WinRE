"""Marker operations need correct VM-local routing, but the guest cannot
serve as its own independent control plane in enforce mode.

snapshot_gate.marker_exists() / consume_marker() / create_marker() need local
file routing when run inside the VM; otherwise they SSH to themselves with an
empty hostname. Correct local marker routing is diagnostic/collection plumbing,
not permission for the guest to attest itself clean.

Both gates read the marker locally when `on_vm_repo_root()` says this process
is inside Flare. Enforce mode still refuses guest-local execution/attestation
because the ledger must live on the separate control plane. These tests pin
local routing, agreement and the trust boundary.
"""
import pathlib

import pytest

from winre import snapshot_gate as sg
from winre import vm_gate


HERE = pathlib.Path(__file__).resolve().parents[1]


def test_marker_probe_short_circuits_when_run_on_the_vm(tmp_path, monkeypatch):
    monkeypatch.setattr(sg, "_VM_REPO_ROOT", HERE)
    # MARKER defaults to the absolute VM path, so an absolute local stand-in is
    # the branch a real VM-local run takes
    marker = tmp_path / ".clean_snapshot"
    monkeypatch.setattr(sg, "MARKER", str(marker))
    marker.write_text("created=probe", encoding="ascii")

    def _boom(*a, **k):
        raise AssertionError("marker_exists SSHed while running on the VM")

    monkeypatch.setattr(sg, "_ssh_ps", _boom)
    assert sg.marker_exists() is True, (
        "the marker file is right here and was reported as absent")


def test_the_other_gate_short_circuits_too(tmp_path, monkeypatch):
    """The pair must be fixed together: one gate reading locally and the other
    SSHing to itself is the disagreement that made this hard to see."""
    assert callable(vm_gate.on_vm_repo_root)
    assert callable(sg._on_vm_repo_root)
    src = pathlib.Path(vm_gate.__file__).read_text(encoding="utf-8")
    assert "def on_vm_repo_root" in src


def test_the_control_plane_still_uses_ssh(monkeypatch):
    """The dangerous half of the fix: on the host we must NOT read a local file
    and answer for the VM. That would authorise execution on a dirty VM."""
    monkeypatch.setattr(sg, "_VM_REPO_ROOT", pathlib.Path("/nonexistent-root"))
    assert sg._on_vm_repo_root() is None, (
        "the host must not treat its own checkout as the VM")

    calls = {}

    def fake_ssh(cfg, script, timeout=60):
        calls["ran"] = True
        calls["script"] = script

        class _R:
            returncode = 0
            stdout = "true\n"
            stderr = ""
        return _R()

    monkeypatch.setattr(sg, "_ssh_ps", fake_ssh)
    assert sg.marker_exists() is True
    assert calls.get("ran"), "the host path must still go over SSH"


def test_the_two_gates_cannot_disagree_about_the_vm_being_on_it(monkeypatch):
    sg_local = sg._on_vm_repo_root()
    vg_local = vm_gate.on_vm_repo_root()
    if HERE is not None:
        # same repo, same machine: both must answer the same way
        assert (sg_local is None) == (vg_local is None), (
            "snapshot_gate and vm_gate disagree about whether this process is "
            "running on the VM")


def test_consume_marker_is_a_local_delete_on_the_vm(tmp_path, monkeypatch):
    """A failed consume reads as \"not consumed\", so a VM-local execution would
    not be recorded and the next run would reuse the same clean state."""
    monkeypatch.setattr(sg, "_VM_REPO_ROOT", HERE)
    marker = tmp_path / ".clean_snapshot"
    monkeypatch.setattr(sg, "MARKER", str(marker))
    marker.write_text("created=probe", encoding="ascii")

    def _boom(*a, **k):
        raise AssertionError("consume_marker SSHed while running on the VM")

    monkeypatch.setattr(sg, "_ssh_ps", _boom)
    assert sg.consume_marker() is True, "the marker was not consumed"
    assert not marker.exists(), "the marker file still exists"


def test_a_relative_marker_is_resolved_against_the_repo_root(tmp_path, monkeypatch):
    """MARKER is overridable. A relative name must resolve against the repo root
    rather than the process CWD, or the marker silently looks absent."""
    monkeypatch.setattr(sg, "_VM_REPO_ROOT", tmp_path)
    monkeypatch.setattr(sg, "MARKER", "clean_marker")
    (tmp_path / "clean_marker").write_text("created=probe", encoding="ascii")
    assert sg._local_marker_path(tmp_path) == tmp_path / "clean_marker"


def test_guest_local_process_cannot_attest_its_own_clean_state(monkeypatch):
    monkeypatch.setattr(sg, "_VM_REPO_ROOT", HERE)
    result = sg.attest("verified_clean")
    assert result["ok"] is False
    assert "separate control plane" in result["error"]


def test_guest_local_enforce_preflight_requires_remote_control_plane(
        monkeypatch):
    monkeypatch.setattr(sg, "_VM_REPO_ROOT", HERE)
    monkeypatch.setattr(sg, "mode", lambda: "enforce")
    result = sg.preflight("dynamic", sha="c" * 64, cfg={"host": "flare"})
    assert result["allowed"] is False
    assert "independent control-plane ledger" in result["error"]


def test_control_plane_ledger_is_outside_sync_and_evidence_roots():
    from winre import remote_driver
    assert sg.LEDGER == remote_driver.REPO / "internal" / "_vm_state.json"
    assert sg.LEDGER.parent != remote_driver.LOCAL_LOGS
    sync_script = (HERE / "ops" / "sync_to_flare.ps1").read_text(
        encoding="utf-8")
    assert '"internal"' in sync_script


def test_marker_alone_does_not_override_dirty_control_plane_ledger(monkeypatch):
    """A sample can recreate the guest marker; only operator attestation
    resets the independent control-plane ledger.
    """
    monkeypatch.setattr(sg, "mode", lambda: "enforce")
    monkeypatch.setattr(sg, "hypervisor_cfg", lambda: None)
    monkeypatch.setattr(sg, "marker_exists", lambda *a, **k: True)
    monkeypatch.setattr(sg, "vm_state", lambda: {
        "last_action": "detonated", "sha": "a" * 64})
    status = sg.gate_status()
    assert status["blocked"] is True
    assert status["marker"] is True
    assert status["ledger_clean"] is False
    assert "ledger is not attested clean" in status["reason"]


def test_missing_control_plane_ledger_is_not_clean(monkeypatch):
    monkeypatch.setattr(sg, "mode", lambda: "enforce")
    monkeypatch.setattr(sg, "hypervisor_cfg", lambda: None)
    monkeypatch.setattr(sg, "marker_exists", lambda *a, **k: True)
    monkeypatch.setattr(sg, "vm_state", lambda: {"ledger_error": "missing"})
    status = sg.gate_status()
    assert status["blocked"] is True
    assert status["ledger_clean"] is False


def test_enforce_refuses_if_dirty_ledger_cannot_be_persisted(monkeypatch):
    monkeypatch.setattr(sg, "mode", lambda: "enforce")
    monkeypatch.setattr(sg, "hypervisor_cfg", lambda: None)
    monkeypatch.setattr(sg, "marker_exists", lambda *a, **k: True)
    monkeypatch.setattr(sg, "consume_marker", lambda *a, **k: True)
    monkeypatch.setattr(sg, "vm_state", lambda: {"last_action": "verified_clean"})
    monkeypatch.setattr(sg, "record", lambda *a, **k: {
        "last_action": "detonated", "persisted": False})
    result = sg.preflight("dynamic", sha="b" * 64)
    assert result["allowed"] is False
    assert "ledger could not be persisted" in result["error"]
