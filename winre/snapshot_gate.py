#!/usr/bin/env python3
"""snapshot_gate.py — VM snapshot-restore gate for WinRE.

Three layers, per the 2026-09-03 design:

L1  In-VM clean marker (the real enforcement primitive).
    `C:\\WinRE\\.clean_snapshot` exists ONLY in the pristine snapshot.
    The dynamic job / debug preflight requires it, then deletes it
    (consume). Restoring the snapshot re-creates it. Consequence: two
    executions without a real restore in between are physically
    impossible, regardless of what any ledger or operator claims.

L2  Hypervisor auto-restore: REMOVED, deliberately not a feature.
    If WINRE_HYPERVISOR / WINRE_VM_PATH / WINRE_SNAPSHOT are configured,
    Reverting a snapshot re-arms the one-shot marker, which would let one
    run execute the sample repeatedly with no operator deciding the VM was
    clean again. Restoring is an OPERATOR action and stays outside the
    product (operator directive 2026-10-06):
    and verifies the marker before allowing execution.

L3  Global VM-state ledger + HITL attestation (fallback bookkeeping).
    The VM is ONE shared resource, so state is global (logs/_vm_state.json),
    never per-sha. last_action ∈ {restored, verified_clean} = clean;
    detonated/debugged = dirty. Attestation is single-use by construction:
    the next execution consumes it. Attest via UI button or CLI; in
    enforce mode the MARKER — not the attestation — is the arbiter, so a
    false claim gets a blocked run, never a contaminated VM.

Modes (WINRE_SNAPSHOT_GATE):
    enforce (DEFAULT) — one execution per clean restore; an over-budget
                        run is refused BEFORE any stage runs.
    observe           — compute + record everything, never block. For
                        iterating on analysis, not for evidence.
    off               — gate fully inert (ledger still written).
    Anything else     — FAILS CLOSED to enforce: a typo must never be
                        able to weaken enforcement.

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
    """Resolve the gate mode. FAIL CLOSED on anything we do not understand.

    A typo must never weaken enforcement: `WINRE_SNAPSHOT_GATE=true` used to
    fall back to `observe`, which silently disabled the marker, the budget and
    the audit gate check (code audit 2026-09-28, CRITICAL). Unknown -> enforce.
    """
    m = os.environ.get("WINRE_SNAPSHOT_GATE", "enforce").strip().lower()
    if m not in ("observe", "enforce", "off"):
        print(f"[snapshot_gate] ERROR unknown WINRE_SNAPSHOT_GATE={m!r} "
              f"(expected observe|enforce|off) - FAILING CLOSED to enforce",
              flush=True)
        return "enforce"
    return m


# Debug-execution session scope: the FIRST debug preflight in this process
# consumes the marker; later debug calls in the SAME run are allowed against
# the in-memory flag (the VM is already dirty from call #1).
#
# This state must never outlive a run: a long-lived host process (the Flask
# console) that debugged sha X once would otherwise allow a SECOND run of the
# same sha with no marker probe and no consume - i.e. execution straight off
# an armed, freshly restored snapshot (code audit 2026-09-28, HIGH). Every
# driver therefore calls reset_session() before the first execution site.
_debug_consumed: set = set()


def reset_session() -> None:
    """Forget debug-session scope. Called at the start of every pipeline run."""
    _debug_consumed.clear()


# --- run-level execution plan (RevAI handoff 2026-09-27, item 1) --------------
# Under `enforce` the clean marker is a
# one-shot: the first execution consumes it, so ONE clean restore buys
# exactly ONE execution. A run that asks for two (`--dynamic` +
# `--agentic-dbg`) used to half-execute — debug consumed the marker, then
# dynamic was refused mid-run. The plan is computed BEFORE any stage runs so
# the driver can fail fast with one clear message, and it is recorded in the
# pack (`execution_plan.json` → `audit.json`) so a third party can see how
# many executions the run intended.
def execution_plan(*, dynamic: bool = False, debug: bool = False) -> dict:
    """How many VM executions does this run intend, and can the gate honor it?

    No I/O: pure function of (requested flags, gate mode, hypervisor config).
    `budget` is the number of executions the current posture allows per clean
    restore — 1 for a bare `enforce`, one-per-execution when a hypervisor
    re-arms the marker (L2), and unlimited when the gate is not enforcing.
    """
    m = mode()
    hc = hypervisor_cfg()
    sites: list[str] = []
    if debug:
        sites.append("debug")        # agentic-dbg: x64dbg executes the sample
    if dynamic:
        sites.append("dynamic")      # detonation: FakeNet/Procmon/Frida
    requested = len(sites)
    if m != "enforce":
        budget, why = requested, f"gate={m} (advisory — no execution budget)"
    else:
        # Unconditional. It USED to be `budget = requested` whenever a
        # hypervisor was configured, on the theory that auto-restore
        # re-armed the marker per execution. That re-arming is not a
        # product feature (operator directive 2026-10-06): it moves the
        # "this VM is clean again" decision out of the operator's hands.
        budget, why = (1 if requested else 0), (
            "gate=enforce: the clean marker is one-shot, so exactly 1 "
            "execution per clean restore. Restoring the snapshot is an "
            "OPERATOR action - WinRE never reverts the VM for you.")
    plan = {
        "gate_mode": m,
        "auto_restore": False,
        "auto_restore_note": "not a product capability: WinRE never "
                             "reverts the VM; restore the snapshot "
                             "yourself between executions",
        "hypervisor": (hc or {}).get("hypervisor"),
        "execution_sites": sites,
        "executions_requested": requested,
        "executions_available": budget,
        "budget_rationale": why,
        "ok": requested <= budget,
    }
    if not plan["ok"]:
        plan["error"] = (
            f"this run requests {requested} VM executions "
            f"({' + '.join(sites)}) but the current posture allows {budget}: "
            f"{why}. Restore the snapshot between them and run them as "
            f"separate runs (--dynamic … restore … --agentic-dbg), or set "
            f"WINRE_SNAPSHOT_GATE=observe for a deliberate benign test loop, "
            f"or configure WINRE_HYPERVISOR/WINRE_VM_PATH/WINRE_SNAPSHOT so "
            f"each execution re-arms the marker.")
    return plan


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
    """One-time setup helper: create the marker (run BEFORE taking the snapshot).

    Content is audit-only (`created` + `boot_epoch`); the gate contract stays
    presence-based so pre-existing empty markers remain valid.
    """
    cfg = cfg or flare_cfg()
    p = _ssh_ps(cfg, "$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime; "
                     f"$v='created=' + (Get-Date -Format o) + ';boot_epoch=' + $boot.ToString('o'); "
                     f"Set-Content -LiteralPath '{MARKER}' -Value $v -Encoding ASCII; "
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


# --- L2 (REMOVED): hypervisor auto-restore -------------------------------
# Deliberately not a product capability. Reverting the VM re-arms the
# one-shot clean marker, which would let one run execute the sample many
# times with no operator deciding the VM was clean again. Restoring a
# snapshot is an operator action (operator directive 2026-10-06).
# hypervisor_cfg() below is report-only and exists purely so `gate status`
# can say so out loud.
# -------------------------------------------------------------------------

def hypervisor_cfg() -> dict | None:
    """Report-only. WinRE does NOT revert snapshots (operator directive).

    Kept so `gate status` can tell an operator who left these variables in
    their .env that they buy no automatic restore and no extra execution
    budget - silence would let them believe enforcement is weaker than it
    is. Nothing in this module acts on it.
    """
    hv = os.environ.get("WINRE_HYPERVISOR", "").strip().lower()
    vmp = os.environ.get("WINRE_VM_PATH", "").strip()
    snap = os.environ.get("WINRE_SNAPSHOT", "").strip()
    if hv in ("vmware", "vbox") and vmp and snap:
        return {"hypervisor": hv, "vm_path": vmp, "snapshot": snap,
                "product_capability": False,
                "note": "reported for visibility only - WinRE never "
                        "reverts the VM. Restoring the snapshot is an "
                        "OPERATOR action, and it buys no extra execution "
                        "budget."}
    return None


# --- preflight (the one call sites use) ---------------------------------------

def gate_status(cfg: dict | None = None, *, probe: bool = True) -> dict:
    """Full gate picture for UI/CLI/audit.

    Enforce semantics: the MARKER is the arbiter (L1 fact, not a claim).
    allowed = the marker is present right now; nothing re-arms it.
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
            else "no ledger yet - attest, or restore the snapshot yourself")
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
    (debug) the marker was
    already consumed earlier in THIS process run. A consume that reports
    absent/unknown fails closed — two executions off one restore are
    impossible, which is the entire point of L1.
    """
    cfg = cfg or flare_cfg()
    m = mode()
    hc = hypervisor_cfg()
    action_taken = None
    consumed = None
    # NOTE: there is deliberately NO auto-restore branch here. An earlier
    # version reverted the snapshot from inside preflight() whenever
    # WINRE_HYPERVISOR/VM_PATH/SNAPSHOT were set. That made the product
    # re-arm its own one-shot clean marker, so a single run could execute
    # the sample repeatedly with nobody deciding the VM was clean again.
    # Snapshot restore is an OPERATOR action and stays outside the product
    # (operator directive 2026-10-06).
    if True:
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
    gate["reason"] = ("executing" if not action_taken
                      else f"executing (marker {consumed})")
    return {"allowed": True, "gate": gate, "action": action_taken,
            "consumed": consumed, "error": None}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="WinRE snapshot gate")
    ap.add_argument("cmd", choices=["status", "attest", "marker-create", "plan"])
    ap.add_argument("--action", default="restored",
                    choices=["restored", "verified_clean"])
    ap.add_argument("--sha", default="")
    ap.add_argument("--dynamic", action="store_true",
                    help="plan: count a detonation execution")
    ap.add_argument("--agentic-dbg", action="store_true",
                    help="plan: count a debugger execution")
    a = ap.parse_args()
    if a.cmd == "status":
        print(json.dumps(gate_status(), indent=2))
    elif a.cmd == "plan":
        plan = execution_plan(dynamic=a.dynamic, debug=a.agentic_dbg)
        print(json.dumps(plan, indent=2))
        raise SystemExit(0 if plan["ok"] else 1)
    elif a.cmd == "attest":
        print(json.dumps(attest(a.action, sha=a.sha), indent=2, default=str))
    else:
        print(json.dumps({"marker_created": create_marker()}, indent=2))
