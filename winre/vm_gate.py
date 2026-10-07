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
  * a *non*-executing mode (static / agentic) may still run on a dirty VM
    without executing anything: it reads files and calls no debugger. That is
    safe, and forbidding it would make every static run require a revert.

Boundary, stated plainly: static-on-dirty is safe *because it does not execute
the sample*. Debug and dynamic both execute. Those are what the gate blocks.
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
    """Is the VM's clean marker present?

    Presence-only: the marker's content is audit-only, so an empty marker
    created by hand is still valid.
    """
    try:
        p = _probe(cfg)
        return bool(getattr(p, "returncode", None) == 0
                    and str(p.stdout or "").strip() == "True")
    except Exception:
        # fail closed: if we cannot see the VM we must not execute on it
        return False


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
    ps = ('powershell -NoProfile -Command '
          '"Test-Path C:\\WinRE\\' + CLEAN_MARKER + '"')
    return remote_driver.ssh_run(cfg, ps, timeout=60)


def dirty_blocker(cfg: dict) -> dict | None:
    """Why this run cannot start, or None when the VM is clean.

    Returns a record with `reason`, `last_action` and `how_to_clear` so the CLI
    can print one clear message rather than "it broke".
    """
    if vm_is_clean(cfg):
        return None
    last = None
    try:
        from winre import snapshot_gate
        last = (snapshot_gate.vm_state() or {}).get("last_action")
    except Exception:
        last = None
    return {
        "reason": "VM is dirty: a previous run executed a sample on it and the "
                  "clean marker is gone. Nothing may run on it until it is "
                  "reverted.",
        "last_action": last,
        "how_to_clear": [
            "revert the FlareVM to the GOLD snapshot in VMware, then confirm",
            "WinRE does not revert the VM itself - that is deliberately not a "
            "product feature",
            "re-arm the marker: python -m winre.snapshot_gate marker-create",
        ],
    }


def require_clean_vm(cfg: dict, *, mode: str, agentic_dbg: bool = False,
                     dynamic: bool = False) -> tuple[bool, dict | None]:
    """Gate a run. (ok, blocker).

    Static and agentic do NOT execute the sample, so they may run on a dirty VM
    - requiring a revert for them would mean a revert before every read-only
    analysis. Debug and dynamic execute, so they may not.
    """
    executes = dynamic or agentic_dbg
    if not executes:
        return True, None
    return (not dirty_blocker(cfg)), dirty_blocker(cfg)


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