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


def load_findings(sha: str, logs_dir: Path) -> dict[str, dict]:
    """{mode: findings} for every mode that produced one."""
    out = {}
    for m in MODES:
        f = Path(logs_dir) / sha / m / "findings.json"
        if not f.is_file():
            continue
        try:
            out[m] = json.loads(f.read_text("utf-8-sig"))
        except Exception:
            continue
    return out


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
                      "basis": v.get("basis") or []}

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
            elif _RANK.get(s["level"], 0) < _RANK.get(level, 0):
                if _WEIGHT.get(m, 1) >= _WEIGHT.get(top_mode, 1):
                    conflicts.append({"kind": "downgrade", "from": top_mode,
                                      "to": m, "levels": [level, s["level"]]})
                    level, conf = s["level"], s["confidence"]
                    basis = list(s["basis"])
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
        conflicts.append({
            "kind": "disagreement",
            "sources": {m: s["level"] for m, s in sources.items()},
            "detail": "static and dynamic disagree; the dynamic run decides "
                      "by design, and the disagreement is the finding"})
    elif conf != "high" and len(sources) > 1:
        conf = "medium" if conf == "low" else conf

    return {"level": level, "confidence": conf, "basis": basis,
            "sources": sources, "conflicts": conflicts,
            "deciding_mode": top_mode if level != UNKNOWN else None,
            "dynamic_weight": weight}


def compose_for_sample(sha: str, logs_dir: Path) -> dict:
    return compose(load_findings(sha, logs_dir))


if __name__ == "__main__":
    import sys
    logs = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs")
    sha = sys.argv[2] if len(sys.argv) > 2 else None
    if not sha:
        print("usage: python -m winre.compose <logs_dir> <sha>")
        raise SystemExit(2)
    print(json.dumps(compose_for_sample(sha, logs), indent=2, default=str))