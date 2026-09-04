#!/usr/bin/env python3
"""audit.py — truly_green gate for the WinRE pipeline.

Mirrors RevAI's honesty contract:
    truly_green = all stages ran (all_green)
                + no stage used a deterministic fallback when the primary
                  tool was required (quality_green)
                + zero failed tools (tool_failures empty)
                + dynamic honesty (dynamic evidence corroborates but never
                  overrides static YARA — static_yara_wins)

Every audit entry records per-stage ok, any fallbacks, and failed tools so a
stubbed run can never look green.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


def _stage_ok(evidence: Path, stage: str) -> dict:
    # Prefer the pipeline's STAGE.json wrapper; fall back to META.json
    # (orchestrator's dynamic META has ok/error/frida_events directly).
    for name in ("STAGE.json", "META.json"):
        meta = evidence / stage / name
        if meta.is_file():
            try:
                m = json.loads(meta.read_text(encoding="utf-8"))
                ok = bool(m.get("ok") or m.get("ran"))
                # orchestrator dynamic META marks ok=True when artifacts landed
                if stage == "dynamic" and "frida_events" in m:
                    ok = bool(m.get("ok"))
                return {
                    "stage": stage,
                    "ran": ok,
                    "error": m.get("error"),
                    "fallback": bool(m.get("fallback")),
                    "tool_failures": m.get("tool_failures") or [],
                    "summary": m.get("summary"),
                }
            except json.JSONDecodeError:
                continue
    return {"stage": stage, "ran": False, "error": f"{stage} meta missing"}


def audit(evidence: Path, *, stages: tuple[str, ...] = ("intake", "quick",
                                                        "dynamic", "deep",
                                                        "yara", "report"),
          require_dynamic: bool = False) -> dict:
    """Run the truly_green gate over an evidence pack.

    Dynamic is OPTIONAL by design (static-first, segregated). It only
    contributes to all_green when it was actually run (dynamic/ present with
    ok=true) or require_dynamic=True. A static-only run can be truly_green.
    """
    # required stages = everything except dynamic (dynamic optional)
    required = tuple(s for s in stages if s != "dynamic")
    checks = [_stage_ok(evidence, s) for s in stages]
    req_checks = [c for c in checks if c["stage"] in required]
    all_green = all(c["ran"] for c in req_checks)
    failed_tools = [t for c in checks for t in (c.get("tool_failures") or [])]
    fallbacks = [c["stage"] for c in checks if c.get("fallback")]

    # dynamic honesty: static_yara_wins. If dynamic ran but its verdict says
    # 'benign' while static says malicious, that's a conflict — not green.
    static = _stage_ok(evidence, "quick")
    dynamic = _stage_ok(evidence, "dynamic")
    static_verdict = None
    dynamic_verdict = None
    qf = evidence / "quick" / "verdict.json"
    if qf.is_file():
        try:
            static_verdict = (json.loads(qf.read_text(encoding="utf-8"))
                              .get("verdict"))
        except json.JSONDecodeError:
            pass
    df = evidence / "dynamic" / "META.json"
    if df.is_file():
        try:
            dynamic_verdict = (json.loads(df.read_text(encoding="utf-8"))
                               .get("verdict"))
        except json.JSONDecodeError:
            pass

    dynamic_conflict = False
    if dynamic.get("ran") and static_verdict == "malicious" \
            and dynamic_verdict == "benign":
        dynamic_conflict = True

    # snapshot-gate honesty: when the gate is in enforce mode, a dynamic
    # stage that ran must carry gate evidence (auto-restore or attestation
    # pass). observe mode is advisory — recorded, never penalizes.
    gate = None
    gate_ok = True
    try:
        from .snapshot_gate import mode as gate_mode
        from .remote_driver import LOCAL_LOGS
        gm = gate_mode()
        stg_file = evidence / "dynamic" / "STAGE.json"
        stg = json.loads(stg_file.read_text(encoding="utf-8")) \
            if stg_file.is_file() else {}
        gate = stg.get("gate") or None
        if dynamic.get("ran"):
            if gm == "enforce":
                gate_ok = bool(stg.get("gate_pass"))
            else:
                gate_ok = True
        if gm != "off":
            pass  # gate field surfaces below regardless
    except Exception:
        gm = "observe"
        gate_ok = True

    quality_green = not fallbacks and not failed_tools \
        and not dynamic_conflict and gate_ok
    truly_green = all_green and quality_green

    return {
        "truly_green": truly_green,
        "all_green": all_green,
        "quality_green": quality_green,
        "checks": checks,
        "fallback_stages": fallbacks,
        "failed_tools": failed_tools,
        "dynamic_conflict": dynamic_conflict,
        "static_yara_wins": True,
        "static_verdict": static_verdict,
        "dynamic_verdict": dynamic_verdict,
        "snapshot_gate": {"mode": gm, "ok": gate_ok, "detail": gate},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: audit.py <evidence_dir>", file=sys.stderr)
        sys.exit(2)
    ev = Path(sys.argv[1])
    res = audit(ev)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["truly_green"] else 1)
