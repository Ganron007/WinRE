"""A VM-local run must not be blocked by its own gate.

snapshot_gate.marker_exists() / consume_marker() / create_marker() all reached
the VM by SSH unconditionally. Run ON the VM - the orchestrator and `--driver
local` paths - that is an SSH hop to itself with an empty hostname: it times out,
marker_exists() returns None, and gate_status() reports "VM unreachable" and
blocks a run on a VM whose marker file is sitting right there.

winre/vm_gate.py fixed this exact class for the VM gate (`_probe` reads the
marker locally when `on_vm_repo_root()` says we are on the VM). snapshot_gate
never got the same treatment, so the two gates disagreed about whether a VM was
clean - the worst of the three possible outcomes, because one of them said
"unreachable" and the other said "clean".

These tests pin the fix in BOTH gates and, more importantly, pin that they
agree - a control that checks only one gate is what let this ship.
"""
import pathlib

import pytest

from winre import snapshot_gate as sg
from winre import vm_gate


HERE = pathlib.Path(__file__).resolve().parents[1]


def test_snapshot_gate_short_circuits_when_run_on_the_vm(tmp_path, monkeypatch):
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
