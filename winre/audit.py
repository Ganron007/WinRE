#!/usr/bin/env python3
"""audit.py — truly_green gate for the WinRE pipeline.

Mirrors RevAI's honesty contract:
    truly_green = all stages ran (all_green)
                + no stage used a deterministic fallback when the primary
                  tool was required (quality_green)
                + no unmet expectation (a stage that ran but produced
                  nothing usable — e.g. a deep dive with verdict: null)
                + zero failed tools (tool_failures empty)
                + dynamic honesty (dynamic evidence corroborates but never
                  overrides static YARA — static_yara_wins)

Every audit entry records per-stage ok, any fallbacks, failed tools and
`unmet_expectations`, so a stubbed or verdict-less run can never look green.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

try:
    from .evidence import pack_verdict
except ImportError:  # direct `python winre/audit.py <evidence_dir>`
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from winre.evidence import pack_verdict  # type: ignore


def _stage_ok(evidence: Path, stage: str) -> dict:
    # Prefer the pipeline's STAGE.json wrapper; fall back to META.json
    # (orchestrator's dynamic META has ok/error/frida_events directly).
    for name in ("STAGE.json", "META.json"):
        meta = evidence / stage / name
        if meta.is_file():
            try:
                m = json.loads(meta.read_text(encoding="utf-8"))
                # explicit "not requested"/skipped stages are NOT "ran"
                if m.get("ran") is False or m.get("skipped"):
                    ok = False
                else:
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

    Dynamic is OPTIONAL by design (static-first, segregated), so a static-only
    run can be truly_green - that is a deliberate product decision and it stays.

    W4 (RevAI review 2026-10-08): `require_dynamic=True` was accepted and
    documented, then never read. `required` unconditionally excluded dynamic, so
    a caller that explicitly required the dynamic stage got the same all_green
    as one that did not - successful static stages plus a FAILED dynamic stage
    both returned green. A parameter that does not do what its name and its
    docstring say is worse than no parameter: it is an assurance the caller
    believes they have and did not.

    It is honoured now. The default is unchanged, so no existing static-only
    green verdict moves.
    """
    # The persisted execution plan is authoritative for what this run asked
    # the system to do. A caller/UI that forgets the argument must not turn an
    # explicitly requested but failed detonation into optional evidence.
    execution_plan = None
    ep = evidence / "execution_plan.json"
    if ep.is_file():
        try:
            execution_plan = json.loads(ep.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            execution_plan = {"error": "execution_plan.json unreadable"}
    dynamic_requested = bool(
        require_dynamic or
        (isinstance(execution_plan, dict)
         and "dynamic" in (execution_plan.get("execution_sites") or [])))
    run_id = (execution_plan.get("run_id")
              if isinstance(execution_plan, dict) else None)
    composition = None
    composition_path = evidence / "composite.json"
    if composition_path.is_file():
        try:
            composition = json.loads(composition_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            composition = {"error": "composite.json unreadable"}
    required = tuple(stages if dynamic_requested
                     else (s for s in stages if s != "dynamic"))
    checks = [_stage_ok(evidence, s) for s in stages]
    req_checks = [c for c in checks if c["stage"] in required]
    all_green = all(c["ran"] for c in req_checks)
    deep_check = next((c for c in checks if c["stage"] == "deep"), {})
    failed_tools = [t for c in checks for t in (c.get("tool_failures") or [])]
    fallbacks = [c["stage"] for c in checks if c.get("fallback")]

    # dynamic honesty: static_yara_wins. If dynamic ran but its verdict says
    # 'benign' while static says malicious, that's a conflict — not green.
    # Reads the CURRENT writers: static verdict from quick/quick.json (written
    # by pipeline._quick AND remote_quick), dynamic verdict from the
    # dynamic STAGE.json wrapper (frida_events/verdict kwargs) then META.json.
    static = _stage_ok(evidence, "quick")
    dynamic = _stage_ok(evidence, "dynamic")
    static_verdict = None
    dynamic_verdict = None
    qf = evidence / "quick" / "quick.json"
    if qf.is_file():
        try:
            static_verdict = (json.loads(qf.read_text(encoding="utf-8"))
                              .get("verdict"))
        except json.JSONDecodeError:
            pass
    if static_verdict is None:
        qm = evidence / "quick" / "META.json"
        if qm.is_file():
            try:
                static_verdict = (json.loads(qm.read_text(encoding="utf-8"))
                                  .get("verdict"))
            except json.JSONDecodeError:
                pass
    # The REAL static verdict is produced by the deep stage
    # (deep/deep.json -> agent.verdict). remote_quick writes a placeholder
    # 'unknown', so prefer the deep verdict when present.
    deepf = evidence / "deep" / "deep.json"
    if deepf.is_file():
        try:
            _dv = ((json.loads(deepf.read_text(encoding="utf-8"))
                    .get("agent") or {}).get("verdict"))
            if isinstance(_dv, dict) and _dv.get("verdict"):
                static_verdict = _dv.get("verdict")
            elif isinstance(_dv, str):
                static_verdict = _dv
        except json.JSONDecodeError:
            pass
    for dyn_name in ("STAGE.json", "META.json"):
        df = evidence / "dynamic" / dyn_name
        if df.is_file():
            try:
                dynamic_verdict = (json.loads(df.read_text(encoding="utf-8"))
                                   .get("verdict"))
                if dynamic_verdict is not None:
                    break
            except json.JSONDecodeError:
                pass

    dynamic_conflict = False
    if dynamic.get("ran") and static_verdict == "malicious" \
            and dynamic_verdict == "benign":
        dynamic_conflict = True

    # snapshot-gate honesty: when the gate is in enforce mode, a dynamic
    # stage that ran must carry proof that the guest marker and independent
    # control-plane ledger passed. observe mode is advisory — recorded,
    # never penalizes.
    # Fail CLOSED: if the gate mode cannot be resolved at all, enforce
    # posture is assumed (missing evidence then fails the audit).
    gate = None
    gate_ok = True
    try:
        from .snapshot_gate import mode as gate_mode
        gm = gate_mode()
    except Exception as e:
        gm = "enforce"  # fail closed
        gate = {"error": f"gate mode unresolved: {e}"}
    try:
        stg_file = evidence / "dynamic" / "STAGE.json"
        stg = json.loads(stg_file.read_text(encoding="utf-8")) \
            if stg_file.is_file() else {}
        gate = stg.get("gate") or gate
        if dynamic.get("ran"):
            if gm == "enforce":
                gate_ok = bool(stg.get("gate_pass"))
            else:
                gate_ok = True
    except json.JSONDecodeError:
        # FAIL CLOSED: an unreadable STAGE.json used to leave gate_ok at its
        # initialiser True, so a truncated file could keep a run green even
        # though the dynamic stage ran with no gate evidence (code audit
        # 2026-09-28).
        gate = gate or {"error": "dynamic STAGE.json unreadable"}
        if gm == "enforce" and dynamic.get("ran"):
            gate_ok = False

    quality_green = not fallbacks and not failed_tools \
        and not dynamic_conflict and gate_ok

    # Unmet expectations (RevAI handoff 2026-09-27 item 2). A stage can be
    # "ran" and still have produced nothing usable — the deep dive finishing
    # with verdict: null used to be written ok=true, so `truly_green: true`
    # sat next to a missing verdict. These are named, recorded, and they DO
    # consume truly_green.
    unmet: list[str] = []
    if deep_check.get("ran"):
        if not isinstance(composition, dict) or composition.get("error"):
            unmet.append("current-run composite selection missing or unreadable")
        elif run_id and composition.get("run_id") != run_id:
            unmet.append("composite selection is not pinned to this pipeline run")
        else:
            pack_meta_path = evidence / "META.json"
            try:
                pack_meta = json.loads(pack_meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pack_meta = {}
            pack_mode = (pack_meta.get("pack_mode") or pack_meta.get("mode")
                         if isinstance(pack_meta, dict) else None)
            current_selection = ((composition.get("selection") or {})
                                 .get(str(pack_mode)) or {})
            if (pack_mode and current_selection.get("selected") is not True
                    and not current_selection.get("reason", "").startswith("current run candidate")):
                unmet.append("current mode is absent from composite selection")
    floor = ((composition or {}).get("curated_yara_floor") or {}) \
        if isinstance(composition, dict) else {}
    static_yara_wins = (not floor.get("applied")
                        or (composition or {}).get("level") == "malicious")
    if not static_yara_wins:
        unmet.append("composite verdict fell below the curated-YARA malicious floor")
    capability_census = None
    capability_failures: list[str] = []
    quick_json = evidence / "quick" / "quick.json"
    if quick_json.is_file():
        try:
            quick_record = json.loads(quick_json.read_text(encoding="utf-8"))
            quick_census = quick_record.get("capability_census")
        except json.JSONDecodeError:
            quick_census = None
            capability_failures.append("quick/quick.json unreadable")
        quick_check = next((c for c in checks if c["stage"] == "quick"), {})
        if quick_check.get("ran"):
            if not isinstance(quick_census, dict) or \
                    quick_census.get("schema") != "winre-quick-capability-census/v1":
                capability_failures.append("quick capability census missing or invalid")
            else:
                quick_required = set(quick_census.get("required") or [])
                quick_rows = {str(row.get("tool")): row
                              for row in quick_census.get("capabilities") or []
                              if isinstance(row, dict) and row.get("tool")}
                for tool in sorted(quick_required):
                    status = (quick_rows.get(tool) or {}).get("status", "not_attempted")
                    if status != "completed":
                        capability_failures.append(
                            f"required quick capability {tool} status={status}")
    deep_json = evidence / "deep" / "deep.json"
    if deep_json.is_file():
        try:
            deep_record = json.loads(deep_json.read_text(encoding="utf-8"))
            capability_census = deep_record.get("capability_census")
        except json.JSONDecodeError:
            capability_failures.append("deep/deep.json unreadable")
    if deep_check.get("ran"):
        from winre.capabilities import CORE_REQUIRED_TOOLS
        if not isinstance(capability_census, dict) or \
                capability_census.get("schema") != "winre-capability-census/v1":
            capability_failures.append("deep capability census missing or invalid")
        else:
            declared = set(capability_census.get("required") or [])
            summary = {str(row.get("tool")): row
                       for row in capability_census.get("summary") or []
                       if isinstance(row, dict) and row.get("tool")}
            undeclared = sorted(set(CORE_REQUIRED_TOOLS) - declared)
            if undeclared:
                capability_failures.append(
                    "required capabilities omitted from declaration: "
                    + ", ".join(undeclared))
            for tool in CORE_REQUIRED_TOOLS:
                status = (summary.get(tool) or {}).get("status", "not_attempted")
                if status != "completed":
                    capability_failures.append(
                        f"required capability {tool} status={status}")
    unmet.extend(capability_failures)

    # Collection coverage is a separate contract from tool exit status. Stage
    # manifests pin the collector terminal record and primary artifact format
    # to this run; a present file alone is never enough to mark it complete.
    artifact_coverage: dict[str, dict] = {}
    coverage_failures: list[str] = []
    try:
        from .manifest import read_manifest
        coverage_stages = ["intake", "quick", "deep", "yara", "report"]
        if dynamic_requested:
            coverage_stages.append("dynamic")
        for stage_name in coverage_stages:
            stage_manifest = read_manifest(evidence / stage_name)
            artifact_coverage[stage_name] = stage_manifest.get("coverage") or {}
            if not stage_manifest:
                coverage_failures.append(f"{stage_name} artifact manifest missing")
                continue
            if run_id and stage_manifest.get("run_id") != run_id:
                coverage_failures.append(
                    f"{stage_name} artifact manifest is not pinned to this run")
            for source, row in artifact_coverage[stage_name].items():
                if (row.get("requested") and row.get("required")
                        and row.get("status") != "complete"):
                    coverage_failures.append(
                        f"required artifact source {stage_name}/{source} "
                        f"status={row.get('status')}: {row.get('reason')}")
    except Exception as e:
        coverage_failures.append(f"artifact coverage could not be audited: {e}")
    unmet.extend(coverage_failures)

    if dynamic_requested:
        dynamic_stage_file = evidence / "dynamic" / "STAGE.json"
        try:
            dynamic_stage_meta = json.loads(
                dynamic_stage_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            dynamic_stage_meta = {}
        if not run_id or dynamic_stage_meta.get("run_id") != run_id:
            unmet.append("requested dynamic stage is not pinned to this pipeline run")

    deep_v = pack_verdict(evidence)
    if deep_check.get("ran") and not deep_v["present"]:
        unmet.append("deep verdict missing (deep stage produced no verdict)")
    # report stage: source says a judge produced it, but no verdict in it
    rep = None
    rf = evidence / "report" / "report.json"
    if rf.is_file():
        try:
            rep = json.loads(rf.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            rep = None
    if isinstance(rep, dict):
        if not rep.get("verdict"):
            unmet.append("report verdict missing (report carries no verdict)")
        if rep.get("source") == "deterministic_fallback":
            unmet.append("report source is deterministic_fallback")
    truly_green = all_green and quality_green and not unmet

    # A dynamic stage that was REQUESTED but refused by the snapshot gate is
    # recorded explicitly (the stage file exists with ok=False + gate error).
    # It does not fail truly_green (the gate acted correctly; dynamic is
    # optional), but reports must not look like detonation happened.
    dynamic_blocked = False
    try:
        stg_file = evidence / "dynamic" / "STAGE.json"
        if stg_file.is_file():
            _s = json.loads(stg_file.read_text(encoding="utf-8"))
            dynamic_blocked = bool(
                _s.get("ok") is False
                and "snapshot gate" in str(_s.get("error") or ""))
    except (OSError, json.JSONDecodeError):
        pass

    return {
        "truly_green": truly_green,
        "all_green": all_green,
        "quality_green": quality_green,
        "checks": checks,
        "fallback_stages": fallbacks,
        "failed_tools": failed_tools,
        "capability_census": capability_census,
        "capability_failures": capability_failures,
        "artifact_coverage": artifact_coverage,
        "artifact_coverage_failures": coverage_failures,
        "unmet_expectations": unmet,
        "dynamic_conflict": dynamic_conflict,
        "dynamic_blocked": dynamic_blocked,
        "static_yara_wins": static_yara_wins,
        "static_verdict": static_verdict,
        "deep_verdict": deep_v["verdict"],
        "deep_verdict_source": deep_v["source"],
        "llm_roles": deep_v.get("llm_roles"),
        "dynamic_verdict": dynamic_verdict,
        "execution_plan": execution_plan,
        "dynamic_requested": dynamic_requested,
        "run_id": run_id,
        "composite": composition,
        "selected_verdict": ((composition or {}).get("level")
                             if isinstance(composition, dict) else None),
        "snapshot_gate": {"mode": gm, "ok": gate_ok, "detail": gate},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("usage: audit.py <evidence_dir>")
        sys.exit(0 if len(sys.argv) > 1 else 2)
    ev = Path(sys.argv[1])
    res = audit(ev)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["truly_green"] else 1)
