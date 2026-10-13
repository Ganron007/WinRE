"""Phase 4: the composite verdict, dynamic-weighted.

DESIGN.md section 5. RevAI is static-oriented RE on Linux tooling. WinRE runs
the malware on Windows, under a debugger and in a live detonation. That is the
differentiator, and the architecture has to say so out loud:

  * when a dynamic mode ran and produced a level, IT is the deciding voice;
  * static evidence can raise confidence and supply context, but cannot
    outvote execution;
  * when static and dynamic disagree, that disagreement is a NAMED finding -
    the single most useful output WinRE has over static-only RE - not
    something averaged into mush;
  * if no dynamic mode ran, the report says so and labels the verdict
    static-derived.

Static stays first-class. Windows static RE with Windows emulation (capa,
Ghidra/IDA, speakeasy, floss) is materially stronger than the Remnux
equivalent, and those findings are what justify keeping it in the pipeline at
all. It is simply not the deciding voice.
"""
from __future__ import annotations

import json
from pathlib import Path

from winre.evidence import MODES
from winre.findings import (BENIGN, MALICIOUS, SUSPICIOUS, UNKNOWN)

# rank, for "which is the deciding voice" and "did they disagree"
_RANK = {UNKNOWN: 0, BENIGN: 1, SUSPICIOUS: 2, MALICIOUS: 3}
_CONF = {"low": 0, "medium": 1, "high": 2}

# a detonation's judgement outranks a static one; dbg outranks static but does
# not outrank the detonation
_WEIGHT = {"dynamic": 3, "dbg": 2, "static": 1, "agentic": 1}


def load_selection(sha: str, logs_dir: Path, *,
                   pending: dict[str, dict] | None = None
                   ) -> tuple[dict[str, dict], dict]:
    """Load only findings pinned to each mode's latest non-aborted run.

    `pending` is the current mode's in-memory findings record. It is allowed
    before that run's final audit is written; all previously completed modes
    must pass the persisted identity/audit checks below.
    """
    out: dict[str, dict] = {}
    selection: dict[str, dict] = {}
    pending = pending or {}
    for m in MODES:
        root = Path(logs_dir) / sha / m
        if m in pending:
            finding = pending[m]
            valid = (isinstance(finding, dict)
                     and finding.get("schema") == "winre-findings/v1"
                     and finding.get("sha256") == sha
                     and finding.get("mode") == m
                     and bool(finding.get("run_id"))
                     and finding.get("ok") is True)
            if valid and m == "dynamic":
                try:
                    dyn_stage = json.loads((root / "dynamic" / "STAGE.json")
                                           .read_text("utf-8-sig"))
                except (OSError, json.JSONDecodeError):
                    dyn_stage = {}
                valid = (dyn_stage.get("run_id") == finding.get("run_id")
                         and dyn_stage.get("ok") is True)
            selection[m] = {"selected": valid,
                            "run_id": finding.get("run_id") if isinstance(finding, dict) else None,
                            "reason": "current run candidate" if valid
                                      else "current findings candidate failed identity/schema checks"}
            if valid:
                out[m] = finding
            continue
        f = root / "findings.json"
        meta_path, audit_path = root / "META.json", root / "audit.json"
        if not root.is_dir():
            selection[m] = {"selected": False, "reason": "mode pack absent"}
            continue
        try:
            finding = json.loads(f.read_text("utf-8-sig"))
            meta = json.loads(meta_path.read_text("utf-8-sig"))
            audit = json.loads(audit_path.read_text("utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            selection[m] = {"selected": False,
                            "reason": "findings, pack metadata or audit missing/unreadable"}
            continue
        if not all(isinstance(obj, dict) for obj in (finding, meta, audit)):
            selection[m] = {"selected": False,
                            "reason": "findings, pack metadata or audit has invalid shape"}
            continue
        run_id = meta.get("run_id")
        checks = [
            (meta.get("sha256") == sha, "pack sample identity mismatch"),
            (meta.get("mode") == m and meta.get("pack_mode", m) == m,
             "pack mode identity mismatch"),
            (bool(run_id) and audit.get("run_id") == run_id,
             "audit is not pinned to the latest pack run"),
            (not audit.get("aborted") and meta.get("status") != "aborted",
             "latest mode run aborted"),
            (finding.get("schema") == "winre-findings/v1"
             and finding.get("sha256") == sha and finding.get("mode") == m,
             "findings schema/sample/mode mismatch"),
            (finding.get("run_id") == run_id,
             "findings are stale relative to the latest mode run"),
            (finding.get("ok") is True,
             "findings producer did not complete"),
        ]
        reason = next((why for passed, why in checks if not passed), None)
        if not reason and m == "dynamic":
            try:
                dyn_stage = json.loads((root / "dynamic" / "STAGE.json")
                                       .read_text("utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                dyn_stage = {}
            if dyn_stage.get("run_id") != run_id or dyn_stage.get("ok") is not True:
                reason = "dynamic stage is not a successful current-run result"
        selection[m] = {"selected": reason is None, "run_id": run_id,
                        "audit_truly_green": audit.get("truly_green"),
                        "reason": reason or "current valid mode run"}
        if reason is None:
            out[m] = finding
    return out, selection


def load_findings(sha: str, logs_dir: Path) -> dict[str, dict]:
    """{mode: findings} from current, identity-validated mode runs only."""
    return load_selection(sha, logs_dir)[0]


def compose(findings: dict[str, dict]) -> dict:
    """The composite verdict over however many modes ran.

    Returns level/confidence/basis plus `sources` (each mode's own level) and
    `conflicts` (named disagreements). Never averages: a detonation that saw
    the sample drop a payload is not "56% malicious" against a static
    `unknown` - it is malicious, and the static `unknown` is context.
    """
    sources = {}
    for m, f in findings.items():
        v = (f.get("verdict") or {})
        sources[m] = {"level": v.get("level", UNKNOWN),
                      "confidence": v.get("confidence", "low"),
                      "basis": v.get("basis") or [],
                      "run_id": f.get("run_id"),
                      "source": v.get("source")}

    if not sources:
        return {"level": UNKNOWN, "confidence": "low", "basis": [],
                "sources": {}, "conflicts": [],
                "note": "no mode produced findings - no verdict is supportable"}

    # the deciding voice: the highest-weight mode with a level above unknown
    ranked = sorted(
        ((mode, s) for mode, s in sources.items()
         if _RANK.get(s["level"], 0) > _RANK[UNKNOWN]),
        key=lambda kv: (_WEIGHT.get(kv[0], 1),
                        _RANK.get(kv[1]["level"], 0)),
        reverse=True)

    conflicts = []
    if ranked:
        top_mode, top = ranked[0]
        level, conf = top["level"], top["confidence"]
        basis = list(top["basis"])
        weight = _WEIGHT.get(top_mode, 1)
        # Only DEFINITE levels compete: an `unknown` from the detonation means
        # "it ran and we saw nothing actionable", which is weaker than a dbg
        # `suspicious` and must not cancel it.
        for m, s in sources.items():
            if m == top_mode or _RANK.get(s["level"], 0) <= _RANK[UNKNOWN]:
                continue
            if _RANK.get(s["level"], 0) > _RANK.get(level, 0):
                if _WEIGHT.get(m, 1) > _WEIGHT.get(top_mode, 1):
                    conflicts.append({"kind": "escalation", "from": top_mode,
                                      "to": m, "levels": [level, s["level"]]})
                    level, conf = s["level"], s["confidence"]
                    basis = list(s["basis"])
                    top_mode = m
                    weight = _WEIGHT.get(m, 1)
            elif _RANK.get(s["level"], 0) < _RANK.get(level, 0):
                if _WEIGHT.get(m, 1) >= _WEIGHT.get(top_mode, 1):
                    conflicts.append({"kind": "downgrade", "from": top_mode,
                                      "to": m, "levels": [level, s["level"]]})
                    level, conf = s["level"], s["confidence"]
                    basis = list(s["basis"])
                    top_mode = m
                    weight = _WEIGHT.get(m, 1)
    else:
        # nothing above unknown: take the highest-ranked vote, unknown wins
        best = max(sources.items(),
                   key=lambda kv: (_RANK.get(kv[1]["level"], 0),
                                   _WEIGHT.get(kv[0], 1)))
        level = best[1]["level"]
        conf = best[1]["confidence"]
        basis = list(best[1]["basis"])
        weight = _WEIGHT.get(best[0], 1)
        top_mode = best[0]

    # static agreement raises confidence, never the level
    levels = {s["level"] for s in sources.values()}
    if len(levels) > 1 and len(set(s for s in sources)) > 1:
        if "dynamic" in sources:
            detail = ("mode verdicts differ. A definite dynamic verdict has "
                      "precedence by design; an unknown dynamic result does not "
                      "erase definite static or debugger findings")
        elif "dbg" in sources:
            detail = ("static and debugger-assisted mode verdicts differ; "
                      "debugger evidence has higher weight than static-only "
                      "evidence, while an unknown debugger result does not erase "
                      "a definite static finding")
        else:
            detail = ("deterministic and agentic static mode verdicts differ; "
                      "unknown is non-decisive, and when both make definite "
                      "claims the lower-severity result is selected until "
                      "execution evidence is available")
        conflicts.append({
            "kind": "disagreement",
            "sources": {m: s["level"] for m, s in sources.items()},
            "detail": detail})
    elif conf != "high" and len(sources) > 1:
        conf = "medium" if conf == "low" else conf

    # A family-distinctive curated YARA hit is an explicit malicious floor.
    # Dynamic evidence can add a named disagreement but cannot erase it.
    floors = {m: ((f.get("findings") or {}).get("curated_yara_floor") or {})
              for m, f in findings.items()}
    floors = {m: f for m, f in floors.items() if f.get("applied") is True}
    floor_rules = sorted({str(rule) for f in floors.values()
                          for rule in (f.get("rules") or [])})
    if floors and level != MALICIOUS:
        conflicts.append({"kind": "curated_yara_floor", "from": top_mode,
                          "levels": [level, MALICIOUS],
                          "rules": floor_rules,
                          "detail": "family-distinctive curated YARA sets a malicious floor"})
        level, conf = MALICIOUS, "high"
        top_mode = sorted(floors)[0]
        weight = _WEIGHT.get(top_mode, 1)
        basis = list(dict.fromkeys(basis + [f"curated-yara:{r}" for r in floor_rules]))

    return {"level": level, "confidence": conf, "basis": basis,
            "sources": sources, "conflicts": conflicts,
            "deciding_mode": top_mode if level != UNKNOWN else None,
            "dynamic_weight": weight,
            "curated_yara_floor": {"applied": bool(floors),
                                   "modes": sorted(floors),
                                   "rules": floor_rules}}


def compose_for_sample(sha: str, logs_dir: Path, *,
                       pending: dict[str, dict] | None = None) -> dict:
    findings, selection = load_selection(sha, logs_dir, pending=pending)
    result = compose(findings)
    result["selection"] = selection
    return result


if __name__ == "__main__":
    import sys
    logs = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs")
    sha = sys.argv[2] if len(sys.argv) > 2 else None
    if not sha:
        print("usage: python -m winre.compose <logs_dir> <sha>")
        raise SystemExit(2)
    print(json.dumps(compose_for_sample(sha, logs), indent=2, default=str))
