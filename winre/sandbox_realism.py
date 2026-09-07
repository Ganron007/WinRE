#!/usr/bin/env python3
"""sandbox_realism.py — FlareVM detonation-environment realism (KB: Maldev
73/74 anti-VM, Z2A 3_ Evasion; 2026-09-07 KB review item).

Malware checks the environment before misbehaving: CPU/RAM/USBSTOR history,
screen resolution, process baseline, boot age, mouse interaction, VMware
artifacts. This module PROBES the VM and APPLIES what is safely changeable
(registry-only, idempotent, revert-able); the rest is documented manual
steps (BIOS strings, NIC MAC, VM tools, warm snapshot).

Run ON the FlareVM:
    python -m winre.sandbox_realism check
    python -m winre.sandbox_realism apply
    python -m winre.sandbox_realism revert

Output: JSON report with per-check verdict (pass / gap / manual).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

USBSTOR = r"SYSTEM\ControlSet001\Enum\USBSTOR"


def _reg_query(subkey: str) -> dict:
    out = {}
    try:
        p = subprocess.run(["reg", "query", subkey, "/s"],
                           capture_output=True, text=True, timeout=30,
                           encoding="utf-8", errors="replace")
        for line in (p.stdout or "").splitlines():
            line = line.strip()
            if "REG_" in line and "\\" in line:
                k, v = line.split("REG_", 1)
                out[k.strip()] = v.strip()
    except Exception:
        pass
    return out


def _reg_set(subkey: str, name: str, value: str, typ: str = "REG_SZ") -> bool:
    try:
        p = subprocess.run(["reg", "add", subkey, "/v", name, "/t", typ,
                            "/d", value, "/f"], capture_output=True, text=True,
                           timeout=30)
        return p.returncode == 0
    except Exception:
        return False


def _reg_del(subkey: str) -> bool:
    try:
        p = subprocess.run(["reg", "delete", subkey, "/f"],
                           capture_output=True, text=True, timeout=30)
        return p.returncode == 0
    except Exception:
        return False


def _process_count() -> int:
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "(Get-Process).Count"], capture_output=True,
                           text=True, timeout=30)
        return int((p.stdout or "0").strip() or 0)
    except Exception:
        return 0


def _cpu_ram() -> dict:
    try:
        import psutil
        return {"cpu_logical": psutil.cpu_count(logical=True),
                "cpu_physical": psutil.cpu_count(logical=False),
                "ram_gb": round(psutil.virtual_memory().total / 1e9, 1)}
    except Exception:
        return {"cpu_logical": os.cpu_count(), "ram_gb": None}


def _boot_age_days() -> float | None:
    try:
        import psutil
        return round((time.time() - psutil.boot_time()) / 86400, 2)
    except Exception:
        return None


def _display_resolution() -> str | None:
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Add-Type -AssemblyName System.Windows.Forms; "
                            "[System.Windows.Forms.Screen]::PrimaryScreen."
                            "Bounds.ToString()"], capture_output=True,
                           text=True, timeout=30)
        return (p.stdout or "").strip() or None
    except Exception:
        return None


def _vmware_artifacts() -> list[str]:
    found = []
    for p in (r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
              r"HKLM\SOFTWARE\VMware, Inc.\VMware SVGA",
              r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF"):
        if p.startswith("HKLM\\SOFTWARE\\VMware"):
            r = subprocess.run(["reg", "query", p], capture_output=True,
                               text=True, timeout=30)
            if r.returncode == 0:
                found.append(p.split("\\")[-1])
    for svc in ("VMTools", "vm3dservice"):
        r = subprocess.run(["sc", "query", svc], capture_output=True,
                           text=True, timeout=30)
        if r.returncode == 0 and "RUNNING" in (r.stdout or ""):
            found.append(f"service:{svc}")
    return found


def _sample_filename_note(sample: str = "") -> dict:
    name = os.path.basename(sample or "")
    note = {
        "policy": ("keep the ORIGINAL (human-ish) sample name — never a "
                   "bare hash or >3-digit name; Maldev 73 digit-count check"),
        "current_name": name or "n/a",
        "hash_named": bool(re.fullmatch(r"[0-9a-f]{32,64}", name.strip())),
    }
    return note


def check() -> dict:
    cpu = _cpu_ram()
    procs = _process_count()
    boot = _boot_age_days()
    res = _display_resolution()
    usb = _reg_query(USBSTOR)
    vm = _vmware_artifacts()
    checks = {
        "cpu": {"pass": (cpu.get("cpu_logical") or 0) >= 2,
                "detail": f"{cpu.get('cpu_logical')} logical / "
                          f"{cpu.get('cpu_physical')} physical",
                "gap_fix": "VM config: >= 2 vCPU (2-4)"},
        "ram": {"pass": (cpu.get("ram_gb") or 0) >= 4,
                "detail": f"{cpu.get('ram_gb')} GB",
                "gap_fix": "VM config: >= 4 GB RAM (8-16 recommended)"},
        "usbstor_history": {
            "pass": len(usb) >= 2,
            "detail": f"{len(usb)} USBSTOR device entries",
            "gap_fix": "apply: seeds 2+ fake USBSTOR devices"},
        "process_baseline": {
            "pass": procs >= 50,
            "detail": f"{procs} processes running",
            "gap_fix": "run from a fully-booted FlareVM session (idle apps up)"},
        "boot_age": {
            "pass": (boot or 0) >= 1,
            "detail": f"last boot {boot} days ago",
            "gap_fix": "use a WARM snapshot (booted days ago), not a cold boot"},
        "display": {
            "pass": bool(res) and "1920" in (res or "") or "1440" in (res or "")
                    or "2560" in (res or ""),
            "detail": res or "unresolved",
            "gap_fix": "manual: set 1920x1080 in the VM console (not headless)"},
        "vmware_artifacts": {
            "pass": not vm,
            "detail": "; ".join(vm) or "none detected",
            "gap_fix": "manual: sanitize VMware Tools/SVGA presence if a "
                       "target probes for them"},
    }
    passes = sum(1 for c in checks.values() if c["pass"])
    return {
        "ok": True,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks": checks,
        "passes": passes,
        "total": len(checks),
        "realism_score": f"{passes}/{len(checks)}",
        "filename": _sample_filename_note(),
        "note": ("Probe only — nothing changed. 'apply' seeds the registry "
                 "fixes; remaining items are VM-config/manual steps."),
    }


def apply() -> dict:
    """Registry-only, idempotent realism fixes. Revert with revert()."""
    applied = []
    # seed 2+ USBSTOR device history entries
    usb = _reg_query(USBSTOR)
    if len(usb) < 2:
        for i, (vid, pid, serial) in enumerate((
                ("Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07", "AA00000000000001",
                 "Generic Flash Disk USB Device"),
                ("Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00", "BB00000000000002",
                 "Kingston DataTraveler 2.0 USB Device"))):
            key = rf"{USBSTOR}\{vid}\\{serial}"
            ok1 = _reg_set(key, "FriendlyName", pid)
            ok2 = _reg_set(key, "ParentIdPrefix", f"7&{i:02X}ABC")
            if ok1 or ok2:
                applied.append(key)
    return {
        "ok": True,
        "applied": applied[:10],
        "note": ("Registry realism fixes applied (USBSTOR history). "
                 "Manual items remain: display resolution, BIOS strings, "
                 "NIC MAC, VMware tools presence, warm snapshot."),
    }


def revert() -> dict:
    removed = []
    for vid, pid, serial in (("Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07",
                              "AA00000000000001", "Generic Flash Disk USB Device"),
                             ("Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_1.00",
                              "BB00000000000002",
                              "Kingston DataTraveler 2.0 USB Device")):
        key = rf"{USBSTOR}\{vid}\\{serial}"
        if _reg_del(key):
            removed.append(key)
    return {"ok": True, "removed": removed[:10]}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["check", "apply", "revert"])
    args = ap.parse_args()
    fn = {"check": check, "apply": apply, "revert": revert}[args.action]
    print(json.dumps(fn(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())