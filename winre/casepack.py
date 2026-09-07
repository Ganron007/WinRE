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
    ("quick", "quick.json"),
    ("quick", "META.json"),
    ("deep", "deep.json"),
    ("deep", "META.json"),
    ("yara", None),          # *.yar / *.yml / rule_report.json handled below
    ("report", "report.json"),
    ("report", "REPORT-TECHNICAL-v3.md"),
    ("report", "iocs.json"),
    ("report", "AUDIT-REPORT.md"),
    ("report", "EVIDENCE-BUNDLE.md"),
    ("", "audit.json"),
    ("", "stage_trace.json"),
    ("", "META.json"),
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
    mode = mode if mode in ("static", "agentic") else (pack_root.name
                                                        if pack_root.name in
                                                        ("static", "agentic")
                                                        else None)
    dyn = pack_root / "dynamic"
    dyn_files = sorted(f for f in (dyn.rglob("*") if dyn.is_dir() else [])
                       if f.is_file())
    if not dyn_files:
        return {"ok": False, "error": "no dynamic artifacts to pack"}

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
            "suffix": suffix,
            "size_bytes": out_path.stat().st_size,
            "files": len(manifest_files),
            "timeline_events": len(timeline)}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinRE DFIR-Nexus case pack")
    ap.add_argument("sha")
    ap.add_argument("--mode", choices=["static", "agentic"])
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
        roots = [sha_dir / m for m in ("static", "agentic")
                 if (sha_dir / m).is_dir()] or [sha_dir]
    rc = 0
    for root in roots:
        res = build_case(root, args.sha, args.mode, args.out)
        print(json.dumps(res, indent=2, default=str))
        if not res.get("ok"):
            rc = 1
    return rc


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
