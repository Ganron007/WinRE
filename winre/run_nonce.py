#!/usr/bin/env python3
"""run_nonce.py — per-run nonce for dynamic-pack freshness (no clocks).

WHY (RevAI handoff 2026-09-27, item 5): `remote_dynamic` used to decide
"is this META from THIS run?" by string-comparing `meta["finished_at"]`
(VM clock) with the control plane's `started_at` (UTC). Any skew between the
two hosts makes that decision wrong in BOTH directions — a fresh run looks
stale (fail-safe refusal) or an old run looks fresh (fail-open: stale
evidence sold as this run's detonation).

CONTRACT NOW:

  1. the control plane generates `run_id` and passes it down
     (`--run-id` → `_remote_dynamic_helper.py` → `orchestrator.py`),
  2. the orchestrator stamps `meta["run_id"]` on the pack it writes,
  3. freshness is `meta["run_id"] == run_id` — a VALUE comparison. Clocks
     never enter the decision.

Timestamps stay in META (humans read them) and clock skew is recorded
separately as a diagnostic (`remote_driver.clock_skew_s`).

Fail CLOSED: a META with no `run_id` (VM running pre-nonce code, i.e. not
synced) is not trusted — the run is reported as "no fresh META" with an
explicit "sync the VM" reason rather than silently believed.
"""
from __future__ import annotations

import uuid

FIELD = "run_id"


def new_run_id() -> str:
    """Fresh per-execution nonce (opaque, 32 hex chars)."""
    return uuid.uuid4().hex


def check(meta: dict | None, run_id: str) -> dict:
    """Decide whether `meta` came from THIS run. Clock-free.

    Returns {"fresh": bool, "reason": str, "stamped": str|None,
             "expected": str}. Never raises.
    """
    expected = str(run_id or "")
    stamped = None
    if isinstance(meta, dict):
        stamped = meta.get(FIELD) or None
    if not expected:
        return {"fresh": False, "reason": "no run_id issued by the control plane",
                "stamped": stamped, "expected": None}
    if not meta:
        return {"fresh": False, "reason": "no META.json from this run",
                "stamped": None, "expected": expected}
    if not stamped:
        return {"fresh": False,
                "reason": f"META has no {FIELD} (VM code predates the nonce "
                          f"contract — run ops/sync_to_flare.ps1)",
                "stamped": None, "expected": expected}
    if str(stamped) != expected:
        return {"fresh": False,
                "reason": f"META {FIELD} mismatch (stamped={stamped}) — the "
                          f"pack on the VM is from another run",
                "stamped": str(stamped), "expected": expected}
    return {"fresh": True, "reason": f"run_id match ({expected})",
            "stamped": str(stamped), "expected": expected}
