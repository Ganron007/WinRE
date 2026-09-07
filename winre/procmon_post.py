#!/usr/bin/env python3
"""procmon_post.py — post-detonation Procmon correlation (KB-derived).

Maldev persistence catalog + Mandiant cheat sheet: turns the raw Procmon
CSV into per-family persistence reports, a high-signal behavior timeline,
and an argument/PPID-spoofing diff (Maldev 47/48: cmdline-in-Procmon vs
real PEB cmdline can diverge when the process spoofs its arguments).

Inputs (dynamic/ dir):
  procmon.csv            raw Sysinternals capture
  frida_summary.json     decoded strings/sockaddrs (for cross-correlation)
Outputs (written into the same dir):
  procmon_summary.json   (extended: persistence + timeline + spoof suspects)
  behavior_timeline.csv  ordered high-signal events (incident-style)

CLI: python procmon_post.py <dynamic_dir> [--baseline-ok]
"""
from __future__ import annotations

import csv
import json
import re
import sys
import time
from pathlib import Path

_RUNKEY_RE = re.compile(r"\\currentversion\\run(?:once)?\\?", re.I)
_SERVICES_RE = re.compile(r"system\\currentcontrolset\\services\\", re.I)
_TASKS_RE = re.compile(r"\\windows\\tasks\\|\\system32\\tasks\\", re.I)
_STARTUP_RE = re.compile(r"\\startup\\", re.I)
_WMI_RE = re.compile(r"wbem\\|wmi\b", re.I)
_APPDATA_RE = re.compile(r"\\appdata\\|\\programdata\\", re.I)
_NON_SYS_DLL = re.compile(r"\\windows\\system32\\.+\.dll$", re.I)
_IMAGE_LOAD = re.compile(r"^Load Image$", re.I)
_CREATE_SUSPENDED = re.compile(r"CREATE_SUSPENDED", re.I)

PERSISTENCE_FAMILIES = {
    "run_key": ("Run-key write", lambda r, p: r == "RegSetValue"
                and _RUNKEY_RE.search(p or "")),
    "service": ("Service create/start", lambda r, p: r in ("CreateFile", "RegSetValue")
                and _SERVICES_RE.search(p or "")),
    "scheduled_task": ("Scheduled task", lambda r, p: r in ("CreateFile", "WriteFile")
                       and _TASKS_RE.search(p or "")),
    "startup_folder": ("Startup-folder write", lambda r, p: r in ("CreateFile", "WriteFile")
                       and _STARTUP_RE.search(p or "")),
    "wmi": ("WMI usage", lambda r, p: r == "RegSetValue"
            and _WMI_RE.search(p or "")),
    "drop_file": ("Payload drop (appdata/programdata)", lambda r, p:
                  r in ("CreateFile", "WriteFile") and _APPDATA_RE.search(p or "")),
    "dll_sideload": ("DLL load from non-system path", lambda r, p:
                     r == "Load Image" and p and ".dll" in p.lower()
                     and not _NON_SYS_DLL.search(p)),
}


def _parse_csv(path: Path, max_rows: int = 3_000_000) -> list[dict]:
    rows = []
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                rows.append({
                    "time": (row.get("Time of Day") or row.get("Time") or "").strip(),
                    "process": (row.get("Process Name") or "").strip(),
                    "pid": (row.get("PID") or "").strip(),
                    "operation": (row.get("Operation") or "").strip(),
                    "path": (row.get("Path") or "").strip(),
                    "detail": (row.get("Detail") or "").strip(),
                    "result": (row.get("Result") or "").strip(),
                })
                if i >= max_rows:
                    break
    except OSError as e:
        print(f"procmon_post: csv open failed: {e}", file=sys.stderr)
    return rows


def build_procmon_report(dyn_dir: Path) -> dict:
    csv_path = dyn_dir / "procmon.csv"
    if not csv_path.is_file():
        return {"ok": False, "error": "no procmon.csv"}
    rows = _parse_csv(csv_path)
    if not rows:
        return {"ok": False, "error": "procmon.csv empty"}

    persistence: dict[str, dict] = {}
    drops: list[str] = []
    spawns: list[dict] = []
    cmdlines: dict[str, str] = {}
    for r in rows:
        path = r["path"]
        for fam, (label, fn) in PERSISTENCE_FAMILIES.items():
            try:
                if fn(r["operation"], path):
                    p = persistence.setdefault(fam, {"label": label, "count": 0,
                                                     "samples": []})
                    p["count"] += 1
                    if len(p["samples"]) < 6 and path:
                        p["samples"].append(path[:160])
            except Exception:
                continue
        if r["operation"] == "Process Create":
            spawns.append(r)
            if r["detail"]:
                # Procmon Detail column carries the command line
                cmdlines.setdefault(r["pid"], r["detail"][:300])
        if r["operation"] in ("WriteFile", "CreateFile") and _APPDATA_RE.search(path or ""):
            if path not in drops:
                drops.append(path[:160])

    # argument-spoofing suspects: processes created with a cmdline that
    # contains the sample or is empty/odd vs the parent chain — heuristic
    spoof_suspects = []
    parent_map: dict[str, str] = {}
    for r in spawns:
        pid = r["pid"]
        parent_map[pid] = r["path"]  # path column of Process Create = parent
    for r in spawns:
        pid, cmd = r["pid"], r["detail"]
        if cmd and (cmd.lower().startswith("powershell") or " -enc " in cmd.lower()
                    or " -e " in cmd.lower() or "%temp%" in cmd.lower()
                    or "rundll32" in cmd.lower()):
            spoof_suspects.append({
                "pid": pid,
                "process": r["process"],
                "parent": parent_map.get(pid, "?"),
                "cmdline_head": cmd[:160],
                "why": "suspicious spawn pattern (PS -enc / temp / rundll32)",
            })

    # behavior timeline: high-signal operations ordered by time
    timeline = []
    for r in rows:
        op = r["operation"]
        if (op in ("Process Create", "RegSetValue", "CreateService",
                   "StartService", "Load Image", "WriteFile", "CreateFile",
                   "NetworkConnect", "TCP Connect", "UDP Send", "UDP Receive")
                and r["process"] and r["result"] not in ("NAME NOT FOUND",)):
            timeline.append({
                "time": r["time"], "process": r["process"], "pid": r["pid"],
                "operation": op, "path": (r["path"] or r["detail"] or "")[:160],
            })
    timeline.sort(key=lambda e: e["time"])
    tl_path = dyn_dir / "behavior_timeline.csv"
    with tl_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["time", "process", "pid",
                                          "operation", "path"])
        w.writeheader()
        for e in timeline[:50_000]:
            w.writerow(e)

    report = {
        "ok": True,
        "rows_scanned": len(rows),
        "persistence": persistence,
        "dropped_files_appdata": drops[:20],
        "process_spawns": len(spawns),
        "spoofing_suspects": spoof_suspects[:10],
        "behavior_timeline_csv": tl_path.name,
        "behavior_timeline_events": len(timeline),
        "note": ("Per-family persistence catalog (Maldev/Mandiant cheat sheet); "
                 "spoof suspects need memory-cmdline confirmation (post_mortem)"),
    }
    (dyn_dir / "procmon_summary.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("dynamic_dir")
    args = ap.parse_args()
    print(json.dumps(build_procmon_report(Path(args.dynamic_dir)), indent=2))