r"""Phase 5: a detonated VM is not a trustworthy analysis host - so it is a gate.

DESIGN.md section 7. After a detonation the VM has executed arbitrary code.
Any *analysis* performed on it after that point is suspect - that is why phase 3
moved interpretation off the box entirely. The operator reverting it is the
reset, and WinRE must not do that itself: reverting a hypervisor snapshot is
explicitly not a product feature, and auto-restore was removed from the product
for exactly that reason.

What is missing today is that `restore_required` is advisory. The pipeline sets
it and prints a notice, but nothing REFUSES. A run on a dirty VM is the one
condition this whole redesign exists to prevent, so it has to be a gate:

  * after a detonation the VM is dirty and no run may start on it;
  * the CLI says so, names the sample that dirtied it, and says exactly what to
    do (revert, then confirm);
  * the refusal is recorded in the pack as a non-green audit, never by deleting
    the previous run's evidence;
  * every pipeline mode requires a guest marker plus a separate
    control-plane ledger attestation. Static and agentic modes still invoke
    guest tools; read-only use does not prove those tools survived a prior
    sample intact.

Boundary, stated plainly: enforce mode requires the guest marker and a
separate control-plane ledger attestation. The marker is guest-writable, so it
cannot prove cleanliness by itself. The product never restores a hypervisor
snapshot, and a guest-local process cannot supply the independent attestation.
"""
from __future__ import annotations

import json
from pathlib import Path

# module-level so a test can stub ssh_run; the lazy import inside _probe made
# the gate untestable without a live VM
from winre import remote_driver

# the marker that says "this VM is in a known-clean state"
CLEAN_MARKER = ".clean_snapshot"


def vm_is_clean(cfg: dict) -> bool:
    """Is the VM's clean marker present? This is only one gate input."""
    try:
        p = _probe(cfg)
        return bool(getattr(p, "returncode", None) == 0
                    and str(p.stdout or "").strip() == "True")
    except Exception:
        # fail closed: if we cannot see the VM we must not execute on it
        return False



ON_VM_REPO = Path("C:/WinRE")


def on_vm_repo_root() -> Path | None:
    """The VM's repo root when this process runs ON the VM, else None.

    control plane the checkout is elsewhere, and reading a marker locally there
    would silently answer for the wrong machine - so it must return None and
    let the SSH path stand.
    """
    try:
        here = Path(__file__).resolve().parents[1]
    except (NameError, OSError):
        return None
    return here if str(here).upper() == str(ON_VM_REPO).upper() else None


def _probe(cfg: dict):
    """One SSH call; stdout is exactly "True" or "False".

    Caught by the re-audit: the first version wrapped the test in an
    if/else inside `powershell -Command "..."`. The nested quoting did not
    survive the ssh->cmd->powershell hop, and PowerShell echoed the script
    text instead of running it, so stdout was never "True" and the gate
    reported every CLEAN VM as dirty - which would have blocked every run.
    `Test-Path` alone is the form that works; the unit tests did not catch
    it because they stub ssh_run and so validated my own mistake.
    """
    # Running ON the VM (the orchestrator / `--driver local` path), the marker
    # is a local file and an SSH hop would be ssh-to-self. Read it directly for
    # accurate diagnostics, but dirty_blocker still refuses because the local
    # ledger cannot act as an independent control-plane attestation.
    local = on_vm_repo_root()
    if local is not None:
        # This process is running inside the guest, so the marker is local and
        # no SSH hop is needed for this diagnostic probe.
        class _Local:
            returncode = 0
            stdout = "True" if (local / CLEAN_MARKER).is_file() else "False"
            stderr = ""
        return _Local()

    ps = ('powershell -NoProfile -Command '
          '"Test-Path C:\\WinRE\\' + CLEAN_MARKER + '"')
    return remote_driver.ssh_run(cfg, ps, timeout=60)


def dirty_blocker(cfg: dict) -> dict | None:
    """Why this run cannot start, or None when the VM is clean.

    Enforce requires a guest marker plus the independent control-plane ledger.
    A process running inside Flare cannot use its own guest-local ledger as an
    independent trust anchor, so it must hand execution to the remote driver.
    Returns a record with `reason`, `last_action` and `how_to_clear` so the CLI
    can print one clear message rather than "it broke".
    """
    local = on_vm_repo_root()
    last = None
    state = {}
    try:
        from winre import snapshot_gate
        state = snapshot_gate.vm_state() or {}
        last = state.get("last_action")
    except Exception:
        state = {"ledger_error": "control-plane ledger could not be read"}
    marker = vm_is_clean(cfg)
    if local is not None:
        reason = ("WinRE is running inside the Flare guest, so its local "
                  "ledger cannot independently attest that the guest is "
                  "clean. Run this pipeline from the separate control plane "
                  "with --driver remote.")
    elif marker and last in ("restored", "verified_clean"):
        return None
    elif marker:
        reason = ("The guest clean marker is present, but the independent "
                  "control-plane ledger is not attested clean "
                  f"(last_action={last!r}, ledger={state.get('ledger_error')!r}). "
                  "A guest process can recreate its marker; restore the "
                  "snapshot and attest from the control plane.")
    else:
        reason = ("The analysis VM has no verifiable clean marker. Its state "
                  "or analysis tools may have been modified by a previous "
                  "sample, so no guest-side tool may run until the operator "
                  "restores and attests a verified clean snapshot.")
    return {
        "reason": reason,
        "last_action": last,
        "marker_present": marker,
        "ledger_clean": last in ("restored", "verified_clean"),
        "ledger_error": state.get("ledger_error"),
        "how_to_clear": [
            "revert the FlareVM to the GOLD snapshot in VMware",
            "WinRE does not revert the VM itself - that is deliberately not a "
            "product feature",
            "from the separate control plane, verify the restored marker and "
            "attest it: python -m winre.snapshot_gate attest --action verified_clean",
            "use --driver remote; a guest-local ledger is not an independent "
            "trust boundary",
        ],
    }


def require_clean_vm(cfg: dict, *, mode: str, agentic_dbg: bool = False,
                     dynamic: bool = False) -> tuple[bool, dict | None]:
    """Gate a run. (ok, blocker).

    Every pipeline mode invokes guest-side analysis tools. Read-only use does
    not protect those tools from prior sample tampering, so static and agentic
    are gated too. Enforce requires both the guest marker and a clean ledger
    on the separate control plane; this function never restores a snapshot.
    """
    blocker = dirty_blocker(cfg)
    return blocker is None, blocker


def record_refusal(pack, blocker: dict | None) -> None:
    """Non-green audit naming the refusal. Never deletes the prior run's pack:
    a refusal must be distinguishable from 'nothing happened'. A None/empty
    blocker is a clean run and writes nothing."""
    if not blocker:
        return
    from winre.evidence import stage_result
    try:
        pack.write("intake", "REFUSED.json", stage_result(
            "refused", False, error=blocker.get("reason"),
            last_action=blocker.get("last_action"),
            how_to_clear=blocker.get("how_to_clear"),
            note="the pack from the previous run is left in place"))
    except Exception:
        pass


if __name__ == "__main__":
    from winre import remote_driver
    cfg = remote_driver.flare_cfg()
    b = dirty_blocker(cfg)
    print(json.dumps(b or {"clean": True}, indent=2, default=str))
    raise SystemExit(1 if b else 0)
