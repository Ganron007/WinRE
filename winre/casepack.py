#!/usr/bin/env python3
"""casepack.py — pack a mode-section evidence case for DFIR-Nexus ingest.

DFIR-Nexus owns memory post-analysis (Volatility3/MemProcFS on the captured
image) and incident reconstruction (host + memory + malware behavior ->
timeline). WinRE's obligation is the boundary contract:

  * dynamic logs + static context packed as ONE 7z archive per case
  * a case_manifest.json (file -> sha256) for tamper-proofing
  * a case_timeline.json — incident-style ordered events (intake -> quick ->
    deep -> detonation -> yara -> report -> audit) with timestamps, so the
    DFIR side can correlate host activity against the analysis story

Output: <pack_root>/case-<sha16>-<mode>.7z  (7z required; falls back to .zip)

CLI:
    python -m winre.casepack <sha256> [--mode static|agentic] [--out <path>]
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def find_7z() -> str | None:
    env = (os.environ.get("WINRE_7Z") or "").strip()
    if env:
        return env
    for cand in (r"C:\Program Files\7-Zip\7z.exe",
                 r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if Path(cand).is_file():
            return cand
    return shutil.which("7z")


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


_STATIC_CONTEXT_FILES = (
    ("intake", "intake.json"),
    ("intake", "META.json"),
    ("intake", "manifest.json"),
    ("quick", "quick.json"),
    ("quick", "META.json"),
    ("quick", "manifest.json"),
    ("deep", "deep.json"),
    ("deep", "META.json"),
    ("deep", "manifest.json"),
    ("yara", None),          # *.yar / *.yml / rule_report.json handled below
    ("report", "report.json"),
    ("report", "REPORT-TECHNICAL-v3.md"),
    ("report", "iocs.json"),
    ("report", "AUDIT-REPORT.md"),
    ("report", "EVIDENCE-BUNDLE.md"),
    ("report", "manifest.json"),
    ("yara", "manifest.json"),
    ("", "audit.json"),
    ("", "execution_plan.json"),
    ("", "findings.json"),
    ("", "composite.json"),
    ("", "stage_trace.json"),
    ("", "META.json"),
    ("", "artifact-manifest.json"),
)


def _timeline(pack_root: Path, sha: str) -> list[dict]:
    """Incident-style ordered timeline from stage trace + dynamic META."""
    trace = {}
    try:
        trace = json.loads((pack_root / "stage_trace.json").read_text(
            encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        pass
    events: list[dict] = []
    order = ("intake", "quick", "deep", "dynamic", "yara", "report", "audit")
    stages = (trace.get("stages") or {}) if isinstance(trace, dict) else {}
    for name in order:
        m = stages.get(name) or {}
        if not m:
            continue
        events.append({
            "ts": m.get("started_at"),
            "phase": name,
            "event": f"{name} stage",
            "ok": bool(m.get("ok")),
            "detail": (m.get("summary") or "")[:200] or None,
            "elapsed_s": m.get("elapsed_s"),
        })
    dyn_meta = {}
    try:
        dyn_meta = json.loads((pack_root / "dynamic" / "META.json").read_text(
            encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        pass
    if dyn_meta:
        if dyn_meta.get("started_at"):
            events.append({"ts": dyn_meta.get("started_at"), "phase": "dynamic",
                           "event": "detonation start (FakeNet+Procmon+Frida)",
                           "ok": None})
        if dyn_meta.get("finished_at"):
            events.append({"ts": dyn_meta.get("finished_at"), "phase": "dynamic",
                           "event": f"detonation end ok={dyn_meta.get('ok')}",
                           "ok": bool(dyn_meta.get("ok")),
                           "frida_events": dyn_meta.get("frida_events"),
                           "snapshot_restore_required":
                               bool(dyn_meta.get("snapshot_restore_required"))})
    try:
        audit = json.loads((pack_root / "audit.json").read_text(
            encoding="utf-8")) or {}
        events.append({"ts": audit.get("generated_at"), "phase": "audit",
                       "event": f"audit truly_green={audit.get('truly_green')} "
                                f"static={audit.get('static_verdict')} "
                                f"dynamic={audit.get('dynamic_verdict')}",
                       "ok": bool(audit.get("truly_green")),
                       "static_yara_wins": audit.get("static_yara_wins")})
    except (OSError, json.JSONDecodeError):
        pass
    events.sort(key=lambda e: e.get("ts") or "9999")
    return events


def build_case(pack_root: Path, sha: str, mode: str | None = None,
               out_path: Path | None = None) -> dict:
    """Pack a section's dynamic logs + static context into one 7z (or zip).

    Best-effort: never raises on missing pieces; returns an error dict if
    there is literally nothing to pack or no archiver is available.
    """
    pack_root = Path(pack_root)
    if not pack_root.is_dir():
        return {"ok": False, "error": f"pack not found: {pack_root}"}
    try:
        pack_meta = json.loads((pack_root / "META.json").read_text("utf-8-sig"))
        audit = json.loads((pack_root / "audit.json").read_text("utf-8-sig"))
        dynamic_stage = json.loads((pack_root / "dynamic" / "STAGE.json")
                                   .read_text("utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {"ok": False,
                "error": "case export requires finalized pack META, audit and dynamic stage"}
    if not all(isinstance(x, dict) for x in (pack_meta, audit, dynamic_stage)):
        return {"ok": False, "error": "case export metadata has an invalid shape"}
    run_id = pack_meta.get("run_id")
    if (not run_id or pack_meta.get("sha256") != sha
            or pack_meta.get("status") != "completed"
            or pack_meta.get("pack_mode", pack_meta.get("mode")) != pack_root.name
            or audit.get("run_id") != run_id or audit.get("aborted")
            or dynamic_stage.get("run_id") != run_id
            or dynamic_stage.get("ok") is not True):
        return {"ok": False,
                "error": "case export refused: latest run identity/audit/dynamic stage is incomplete"}
    mode = mode if mode in ("static", "agentic", "dbg", "dynamic") else (
        pack_root.name if pack_root.name in ("static", "agentic", "dbg", "dynamic")
        else None)
    dyn = pack_root / "dynamic"
    dyn_files = sorted(f for f in (dyn.rglob("*") if dyn.is_dir() else [])
                       if f.is_file())
    deep_dir = pack_root / "deep" / "x64dbg"
    deep_files = sorted(f for f in (deep_dir.rglob("*")
                                    if deep_dir.is_dir() else [])
                        if f.is_file())
    if not dyn_files and not deep_files:
        return {"ok": False, "error": "no dynamic artifacts or unpack dumps to pack"}

    sevenzip = find_7z()
    suffix = ".7z" if sevenzip else ".zip"
    if out_path is None:
        out_path = pack_root / f"case-{sha[:16]}-{mode or 'pack'}{suffix}"
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    manifest_files: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="winre-case-") as td:
        staging = Path(td)
        # dynamic artifacts (the forensic logs)
        for f in dyn_files:
            rel = f.relative_to(dyn)
            dst = staging / "dynamic" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dst)
            manifest_files.append({"path": f"dynamic/{rel.as_posix()}",
                                   "size": f.stat().st_size,
                                   "sha256": _sha256(f)})
        # static context
        for stage, name in _STATIC_CONTEXT_FILES:
            if name is None:  # yara: rule files + report
                ydir = pack_root / "yara"
                if ydir.is_dir():
                    for f in sorted(ydir.iterdir()):
                        if f.is_file() and f.suffix in (".yar", ".yml"):
                            dst = staging / "yara" / f.name
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(f, dst)
                            manifest_files.append(
                                {"path": f"yara/{f.name}",
                                 "size": f.stat().st_size,
                                 "sha256": _sha256(f)})
                continue
            src = (pack_root / stage / name) if stage else (pack_root / name)
            if not src.is_file():
                continue
            dst = staging / (name if not stage else f"{stage}/{name}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            manifest_files.append({"path": dst.relative_to(staging).as_posix(),
                                   "size": src.stat().st_size,
                                   "sha256": _sha256(src)})
        # deep unpack artifact (pe-sieve-rebuilt x64dbg dump): the PE-valid
        # image RevAI static consumes for unpacked analysis
        for f in deep_files:
            rel = f.relative_to(pack_root / "deep")
            dst = staging / "deep" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dst)
            manifest_files.append({"path": f"deep/{rel.as_posix()}",
                                   "size": f.stat().st_size,
                                   "sha256": _sha256(f)})
        # VM-state HITL ledger (sha-root, mode-independent) — not sectioned
        snap = pack_root.parent / "snapshot.json"
        if snap.is_file():
            shutil.copy2(snap, staging / "snapshot.json")
            manifest_files.append({"path": "snapshot.json",
                                   "size": snap.stat().st_size,
                                   "sha256": _sha256(snap)})

        timeline = _timeline(pack_root, sha)
        manifest = {
            "schema": "winre-case/v1",
            "sha256": sha,
            "mode": mode,
            "run_id": run_id,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "archiver": "7z" if sevenzip else "zip-fallback",
            "notes": ("DFIR-Nexus ingest pack: dynamic logs + static context. "
                      "Memory post-analysis (Volatility3/MemProcFS) is owned "
                      "by DFIR-Nexus on the captured image, not this pack."),
            "files": manifest_files,
            "timeline_event_count": len(timeline),
        }
        (staging / "case_manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (staging / "case_timeline.json").write_text(
            json.dumps({"sha256": sha, "mode": mode,
                        "run_id": run_id,
                        "events": timeline}, indent=2) + "\n",
            encoding="utf-8")

        if sevenzip:
            cmd = [sevenzip, "a", "-t7z", "-mx=5", str(out_path), "."]
            r = subprocess.run(cmd, cwd=staging, capture_output=True, text=True,
                               timeout=1200)
            if r.returncode != 0:
                return {"ok": False,
                        "error": f"7z failed rc={r.returncode}: "
                                 f"{(r.stderr or r.stdout)[-200:]}"}
        else:
            import zipfile
            with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in sorted(staging.rglob("*")):
                    if f.is_file():
                        zf.write(f, f.relative_to(staging))

    return {"ok": True, "path": str(out_path), "mode": mode,
            "run_id": run_id,
            "suffix": suffix,
            "size_bytes": out_path.stat().st_size,
            "files": len(manifest_files),
            "timeline_events": len(timeline)}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinRE DFIR-Nexus case pack")
    ap.add_argument("sha")
    ap.add_argument("--mode", choices=["static", "agentic", "dbg", "dynamic"])
    ap.add_argument("--logs", default=None, help="evidence root (default "
                   "WINRE_PIPELINE_LOGS or repo/logs)")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    logs = Path(args.logs or os.environ.get(
        "WINRE_PIPELINE_LOGS", str(REPO / "logs")))
    sha_dir = logs / args.sha
    if not sha_dir.is_dir():
        print(f"ERROR: no pack {args.sha} under {logs}", file=sys.stderr)
        return 2
    if args.mode:
        roots = [sha_dir / args.mode]
    else:
        roots = [sha_dir / m for m in ("static", "agentic", "dbg", "dynamic")
                 if (sha_dir / m).is_dir()] or [sha_dir]
    rc = 0
    for root in roots:
        res = build_case(root, args.sha, args.mode, args.out)
        print(json.dumps(res, indent=2, default=str))
        if not res.get("ok"):
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
