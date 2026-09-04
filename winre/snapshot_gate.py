#!/usr/bin/env python3
"""snapshot_gate.py — VM snapshot-restore gate for WinRE.

Three layers, per the 2026-09-03 design:

L1  In-VM clean marker (the real enforcement primitive).
    `C:\\WinRE\\.clean_snapshot` exists ONLY in the pristine snapshot.
    The dynamic job / debug preflight requires it, then deletes it
    (consume). Restoring the snapshot re-creates it. Consequence: two
    executions without a real restore in between are physically
    impossible, regardless of what any ledger or operator claims.

L2  Hypervisor auto-restore (convenience that re-arms L1).
    If WINRE_HYPERVISOR / WINRE_VM_PATH / WINRE_SNAPSHOT are configured,
    preflight reverts the snapshot (vmrun / VBoxManage), waits for SSH,
    and verifies the marker before allowing execution.

L3  Global VM-state ledger + HITL attestation (fallback bookkeeping).
    The VM is ONE shared resource, so state is global (logs/_vm_state.json),
    never per-sha. last_action ∈ {restored, verified_clean} = clean;
    detonated/debugged = dirty. Attestation is single-use by construction:
    the next execution consumes it. Attest via UI button or CLI; in
    enforce mode the MARKER — not the attestation — is the arbiter, so a
    false claim gets a blocked run, never a contaminated VM.

Modes (WINRE_SNAPSHOT_GATE):
    observe (default) — compute + record everything, never block.
                        Exists so the gate ships without hampering the
                        current testing phase; flip to enforce for release.
    enforce           — block execution when the gate is not satisfied.
    off               — gate fully inert (ledger still written).

Deterministic spine only — the gate is NEVER an agentic decision.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from pathlib import Path

from .envfile import load_dotenv  # noqa: F401  (ensures .env is loaded)
from .remote_driver import LOCAL_LOGS, flare_cfg, ssh_run

MARKER = os.environ.get("WINRE_SNAPSHOT_MARKER", r"C:\WinRE\.clean_snapshot")
LEDGER = LOCAL_LOGS / "_vm_state.json"
CLEAN_ACTIONS = ("restored", "verified_clean")
DIRTY_ACTIONS = ("detonated", "debugged")


def mode() -> str:
    m = os.environ.get("WINRE_SNAPSHOT_GATE", "observe").strip().lower()
    if m not in ("observe", "enforce", "off"):
        # fail-open would silently weaken enforcement - pin to observe but
        # shout, since the operator typed something we don't know
        print(f"[snapshot_gate] WARN unknown WINRE_SNAPSHOT_GATE={m!r}; "
              f"using observe", flush=True)
        return "observe"
    return m


# Debug-execution session scope: the FIRST debug preflight in this process
# consumes the marker; later debug calls in the same agent run are allowed
# against the in-memory flag (the VM is already dirty from call #1).
_debug_consumed: set = set()


def _enc(ps: str) -> str:
    return base64.b64encode(ps.encode("utf-16-le")).decode("ascii")


def _ssh_ps(cfg: dict, script: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return ssh_run(cfg, f"powershell -NoProfile -EncodedCommand {_enc(script)}",
                   timeout=timeout)


# --- L1: marker -------------------------------------------------------------

def marker_exists(cfg: dict | None = None, timeout: int = 45) -> bool | None:
    """True/False per the VM; None when SSH/marker probe fails."""
    cfg = cfg or flare_cfg()
    try:
        p = _ssh_ps(cfg, f"Test-Path -LiteralPath '{MARKER}'", timeout=timeout)
        out = (p.stdout or "").strip().lower()
        if p.returncode == 0 and out in ("true", "false"):
            return out == "true"
    except Exception:
        pass
    return None


def consume_marker(cfg: dict | None = None, timeout: int = 45) -> bool | None:
    """Delete the marker iff present; True=consumed, False=absent, None=unknown."""
    cfg = cfg or flare_cfg()
    try:
        p = _ssh_ps(cfg, f"if (Test-Path -LiteralPath '{MARKER}') "
                         f"{{ Remove-Item -LiteralPath '{MARKER}' -Force; 'consumed' }} "
                         f"else {{ 'absent' }}", timeout=timeout)
        out = (p.stdout or "").strip().lower()
        if p.returncode == 0 and out in ("consumed", "absent"):
            return out == "consumed"
    except Exception:
        pass
    return None


def create_marker(cfg: dict | None = None, timeout: int = 45) -> bool:
    """One-time setup helper: create the marker (run BEFORE taking the snapshot)."""
    cfg = cfg or flare_cfg()
    p = _ssh_ps(cfg, f"New-Item -ItemType File -Path '{MARKER}' -Force | Out-Null; "
                     f"Test-Path -LiteralPath '{MARKER}'", timeout=timeout)
    return (p.stdout or "").strip().lower() == "true"


# --- L3: global ledger --------------------------------------------------------

def vm_state() -> dict:
    try:
        d = json.loads(LEDGER.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def record(action: str, *, sha: str = "", detail: str = "") -> dict:
    if action not in CLEAN_ACTIONS + DIRTY_ACTIONS:
        raise ValueError(f"bad action: {action}")
    st = {"last_action": action, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                      time.gmtime()),
          "sha": sha, "detail": detail, "gate_mode": mode()}
    try:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        LEDGER.write_text(json.dumps(st, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass
    return st


def ledger_clean() -> bool:
    return vm_state().get("last_action") in CLEAN_ACTIONS


def attest(action: str, *, sha: str = "", verify_marker: bool = True) -> dict:
    """HITL attestation (UI button / CLI). Single-use: next execution dirties.

    In any active mode, a `verified_clean` attestation is only accepted when
    the marker probe agrees (None/False → refused) — the operator's claim
    must match the VM's fact.
    """
    if action not in CLEAN_ACTIONS:
        return {"ok": False, "error": f"action must be one of {CLEAN_ACTIONS}"}
    m = mode()
    if m == "off":
        return {"ok": False, "error": "gate is off (WINRE_SNAPSHOT_GATE=off)"}
    marker = marker_exists() if (verify_marker and action == "verified_clean") \
        else None
    if action == "verified_clean" and marker is not True:
        return {"ok": False,
                "error": "marker probe does not confirm clean "
                         f"(marker={marker}) — restore the snapshot first",
                "marker": marker}
    st = record(action, sha=sha,
                detail="attested" + ("" if marker is not True
                                     else " (marker verified)"))
    return {"ok": True, "state": st, "marker": marker}


# --- L2: hypervisor auto-restore ---------------------------------------------

def hypervisor_cfg() -> dict | None:
    hv = os.environ.get("WINRE_HYPERVISOR", "").strip().lower()
    vmp = os.environ.get("WINRE_VM_PATH", "").strip()
    snap = os.environ.get("WINRE_SNAPSHOT", "").strip()
    if hv in ("vmware", "vbox") and vmp and snap:
        return {"hypervisor": hv, "vm_path": vmp, "snapshot": snap}
    return None


def hypervisor_restore(hc: dict, timeout: int = 420) -> dict:
    """Revert to the clean snapshot, wait for SSH, verify the marker."""
    if hc["hypervisor"] == "vmware":
        cmd = ["vmrun", "revertToSnapshot", hc["vm_path"], hc["snapshot"]]
    else:
        cmd = ["VBoxManage", "snapshot", hc["vm_path"], "restore", hc["snapshot"]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            return {"ok": False,
                    "error": f"{hc['hypervisor']} revert failed: "
                             f"{(r.stderr or r.stdout or '')[:200]}"}
    except FileNotFoundError:
        return {"ok": False, "error": f"{hc['hypervisor']} CLI not found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"{hc['hypervisor']} revert timed out"}

    deadline = time.time() + timeout
    marker = None
    while time.time() < deadline:
        marker = marker_exists(timeout=20)
        if marker is True:
            break
        time.sleep(10)
    if marker is not True:
        return {"ok": False,
                "error": "VM did not come back with clean marker after revert",
                "marker": marker}
    st = record("restored", detail=f"auto ({hc['hypervisor']}): {hc['snapshot']}")
    return {"ok": True, "state": st, "marker": True}


# --- preflight (the one call sites use) ---------------------------------------

def gate_status(cfg: dict | None = None, *, probe: bool = True) -> dict:
    """Full gate picture for UI/CLI/audit.

    Enforce semantics: the MARKER is the arbiter (L1 fact, not a claim).
    allowed = auto-restored now (L2) OR marker present right now.
    The ledger (L3) is an audit trail + UX; it can never substitute for the
    marker in enforce mode. Observe mode: everything allowed, all recorded.
    """
    m = mode()
    hc = hypervisor_cfg()
    marker = marker_exists(cfg) if (probe and m != "off") else None
    state = vm_state()
    clean_ledger = state.get("last_action") in CLEAN_ACTIONS
    if m == "off":
        blocked, reason = False, "gate off"
    elif not hc and marker is None and not probe:
        # status-only call (no probe): report ledger posture, never claim armed
        blocked, reason = (m == "enforce"), (
            "armed per ledger" if clean_ledger
            else "no ledger yet — attest or configure auto-restore")
    elif marker is True:
        blocked, reason = False, "armed (clean marker on VM)"
    elif marker is None and not hc:
        blocked, reason = (m == "enforce"), "VM unreachable / marker unknown"
    else:
        blocked, reason = (m == "enforce"), "VM dirty (no clean marker)"
    return {"mode": m, "marker": marker, "vm_state": state,
            "ledger_clean": clean_ledger, "hypervisor": hc,
            "blocked": blocked, "reason": reason,
            "marker_path": MARKER}


def preflight(kind: str, *, sha: str = "", cfg: dict | None = None,
              consume: bool = True) -> dict:
    """Gate check before executing anything on the VM (detonation or debug).

    Enforce-mode contract: `allowed=True` is returned ONLY when the marker
    was atomically consumed this call (consumed=True), a hypervisor
    auto-restore just re-created and consumed it, or (debug) the marker was
    already consumed earlier in THIS process run. A consume that reports
    absent/unknown fails closed — two executions off one restore are
    impossible, which is the entire point of L1.
    """
    cfg = cfg or flare_cfg()
    m = mode()
    hc = hypervisor_cfg()
    action_taken = None
    consumed = None
    if m == "enforce" and hc:
        r = hypervisor_restore(hc)
        if not r.get("ok"):
            return {"allowed": False, "gate": gate_status(cfg, probe=False),
                    "action": None, "consumed": None, "error": r.get("error")}
        action_taken = "auto_restored"
        consumed = consume_marker(cfg) if consume else None
        if consume and consumed is not True:
            return {"allowed": False, "gate": gate_status(cfg, probe=False),
                    "action": action_taken, "consumed": consumed,
                    "error": "snapshot gate: marker consume not confirmed "
                             f"({consumed}) after restore"}
    else:
        # debug calls in this same process already consumed the marker for
        # this sha: the VM is dirty from call #1, but this agent run's
        # trajectory continues against the SAME dirty session — allow it.
        if m == "enforce" and kind == "debug" and consume \
                and sha in _debug_consumed:
            consumed = "session"
        else:
            st = gate_status(cfg)
            blocked = st["blocked"] and m == "enforce"
            if blocked:
                # refusal consumes nothing — ledger stays an honest trail
                return {"allowed": False, "gate": st, "action": None,
                        "consumed": None,
                        "error": f"snapshot gate: {st['reason']}"}
            if m == "enforce" and consume:
                consumed = consume_marker(cfg)
                if consumed is not True:
                    return {"allowed": False, "gate": st, "action": None,
                            "consumed": consumed,
                            "error": "snapshot gate: marker consume not "
                                     f"confirmed ({consumed})"}
                if kind == "debug":
                    _debug_consumed.add(sha)
    if m != "off":
        record("detonated" if kind == "dynamic" else "debugged", sha=sha,
               detail=action_taken or "gate pass")
    # coherent post-decision status: blocked=False is the truth here
    gate = gate_status(cfg, probe=False)
    gate["blocked"] = False
    gate["reason"] = ("executing (auto-restored)" if action_taken
                      else f"executing (marker {consumed})")
    return {"allowed": True, "gate": gate, "action": action_taken,
            "consumed": consumed, "error": None}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="WinRE snapshot gate")
    ap.add_argument("cmd", choices=["status", "attest", "marker-create"])
    ap.add_argument("--action", default="restored",
                    choices=["restored", "verified_clean"])
    ap.add_argument("--sha", default="")
    a = ap.parse_args()
    if a.cmd == "status":
        print(json.dumps(gate_status(), indent=2))
    elif a.cmd == "attest":
        print(json.dumps(attest(a.action, sha=a.sha), indent=2, default=str))
    else:
        print(json.dumps({"marker_created": create_marker()}, indent=2))
