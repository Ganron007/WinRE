#!/usr/bin/env python3
"""emu_diff.py — emulation-vs-detonation divergence check.

Compares the APIs speakeasy *predicted* during static emulation against the
APIs Frida *observed* during detonation:

  predicted only  -> emulation saw it, detonation didn't
                    (env-gating / anti-emulation / coverage gap — investigate)
  observed only   -> detonation saw it, emulation missed
                    (emulation coverage gap — expected for UI/network APIs)
  overlap         -> both agree (corroborated behavior)

Inputs (pack section root): deep/deep.json (agent history, speakeasy result),
dynamic/frida_summary.json (top_apis). Output: dynamic/emu_diff.json.
Runs in _post_pull_enrich; read-only, best-effort, never gates anything.
"""
from __future__ import annotations

import json
from pathlib import Path


def _norm_api(name: object) -> str:
    """kernel32.CreateFileW / ntdll!NtCreateFile / CreateFileW -> createfile."""
    if isinstance(name, dict):
        for k in ("api_name", "name", "api"):
            if name.get(k):
                name = name[k]
                break
        else:
            return ""
    s = str(name or "").strip()
    for sep in (".", "!", "::", "\\"):
        if sep in s:
            s = s.rsplit(sep, 1)[-1]
    s = s.lower().rstrip("_")
    if len(s) > 2 and s[-1] in ("a", "w"):
        s = s[:-1]
    return s


def _predicted_apis(deep_json: Path) -> list[str]:
    try:
        deep = json.loads(deep_json.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return []
    agent = deep.get("agent") or {}
    out: list[str] = []
    for h in (agent.get("history") or []):
        if h.get("tool") != "speakeasy_emulate":
            continue
        res = h.get("result") or {}
        for a in (res.get("api_calls") or []):
            n = _norm_api(a)
            if n and n not in out:
                out.append(n)
    return out


def _observed_apis(frida_summary: Path) -> list[str]:
    try:
        summ = json.loads(frida_summary.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return []
    out: list[str] = []
    for pair in (summ.get("top_apis") or []):
        name = pair[0] if isinstance(pair, (list, tuple)) and pair else pair
        n = _norm_api(name)
        if n and n not in out:
            out.append(n)
    return out


def compare(dyn_dir: Path) -> dict:
    """Build the emulation-vs-detonation diff for one dynamic dir."""
    dyn_dir = Path(dyn_dir)
    section = dyn_dir.parent
    predicted = _predicted_apis(section / "deep" / "deep.json")
    observed = _observed_apis(dyn_dir / "frida_summary.json")
    if not predicted and not observed:
        res = {"ok": False,
               "error": "no speakeasy prediction and no frida observation",
               "predicted": 0, "observed": 0}
        try:
            (dyn_dir / "emu_diff.json").write_text(
                json.dumps(res, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        return res
    ps, ob = set(predicted), set(observed)
    inter = sorted(ps & ob)
    only_pred = sorted(ps - ob)
    only_obs = sorted(ob - ps)
    union = len(ps | ob)
    score = round(1 - len(inter) / union, 3) if union else 1.0
    res = {
        "ok": True,
        "predicted": len(predicted),
        "observed": len(observed),
        "overlap": inter[:40],
        "overlap_count": len(inter),
        "only_predicted": only_pred[:40],
        "only_predicted_count": len(only_pred),
        "only_observed": only_obs[:40],
        "only_observed_count": len(only_obs),
        "divergence_score": score,
        "anti_emulation_suspect": bool(only_pred and observed),
        "note": ("divergence 0 = identical API sets; 1 = disjoint. "
                 "predicted-only with a healthy detonation suggests "
                 "env-gating/anti-emulation — investigate, don't conclude."),
    }
    try:
        (dyn_dir / "emu_diff.json").write_text(
            json.dumps(res, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    return res


if __name__ == "__main__":
    import sys
    print(json.dumps(compare(Path(sys.argv[1])), indent=2))
