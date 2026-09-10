#!/usr/bin/env python3
"""post_mortem.py — post-detonation forensic harvest + telemetry integrity
(KB: Volatility Part3 memory discipline + Maldev 83-89 unhooking; DFIR-Nexus
handoff boundary: WinRE harvests process-level memory, DFIR-Nexus owns
full-image analysis).

Steps (run on the VM right after detonation, BEFORE snapshot restore):
  1. memory_harvest  — procdump -ma of the sample process + children
                       (ephemeral malware trap; feeds DFIR-Nexus ingest)
  2. ntdll_integrity — compare loaded ntdll .text hash (read via
                       ReadProcessMemory) vs on-disk -> unhooking detected
  3. process_snapshot — psutil process list (parent/pid/cmdline) for
                       PPID-spoof correlation with procmon_post suspects

CLI: python post_mortem.py <dynamic_dir> [--sample-pid <pid>]
     (dynamic_dir = the case's dynamic/ folder; writes memory/ + files there)
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROCDUMP = r"C:\Tools\sysinternals\Procdump64.exe"


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"not found: {cmd[0]}"


def _disk_ntdll_hash() -> str | None:
    p = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "ntdll.dll"
    if not p.is_file():
        return None
    try:
        with p.open("rb") as f:
            data = f.read()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return None


def _read_memory(pid: int, addr: int, size: int) -> bytes | None:
    """Read process memory via ctypes (NtReadVirtualMemory path)."""
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE
    NtReadVirtualMemory = ntdll.NtReadVirtualMemory
    NtReadVirtualMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_size_t,
                                    ctypes.POINTER(ctypes.c_size_t)]
    h = OpenProcess(0x0010, False, pid)  # PROCESS_VM_READ
    if not h:
        return None
    try:
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        rc = NtReadVirtualMemory(h, ctypes.c_void_p(addr), buf, size,
                                 ctypes.byref(read))
        if rc != 0 or read.value < 64:
            return None
        return buf.raw[:read.value]
    finally:
        kernel32.CloseHandle(h)


def _loaded_ntdll_hash(pid: int) -> str | None:
    """Hash the loaded ntdll .text region of a process (x64 offsets fixed:
    PEB+0x10 -> Ldr; InMemoryOrderModuleList; first entry = exe, second =
    ntdll on win10/11 x64)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    GetModuleHandleW = k32.GetModuleHandleW
    GetModuleHandleW.restype = wintypes.HMODULE
    RtlGetCurrentPeb = ntdll.RtlGetCurrentPeb
    RtlGetCurrentPeb.restype = ctypes.c_void_p
    NtQueryInformationProcess = ntdll.NtQueryInformationProcess
    PROCESS_BASIC_INFORMATION = 0
    OpenProcess = k32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    h = OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ
    if not h:
        return None
    try:
        # PEB via NtQueryInformationProcess
        buf = ctypes.create_string_buffer(8)
        ret = ctypes.c_size_t(0)
        rc = NtQueryInformationProcess(h, PROCESS_BASIC_INFORMATION, buf,
                                       len(buf), ctypes.byref(ret))
        if rc != 0:
            return None
        peb = int.from_bytes(buf.raw[:8], "little")
        # PEB->Ldr (x64 offset 0x18)
        ldr = int.from_bytes(_read_memory(pid, peb + 0x18, 8) or b"\x00" * 8,
                             "little")
        # Ldr->InMemoryOrderModuleList (x64 offset 0x20)
        head = int.from_bytes(_read_memory(pid, ldr + 0x20, 8) or b"\x00" * 8,
                              "little")
        # second entry: Flink of first entry
        first = int.from_bytes(_read_memory(pid, head, 8) or b"\x00" * 8,
                               "little")
        second = int.from_bytes(_read_memory(pid, first, 8) or b"\x00" * 8,
                                "little")
        # entry+0x10 = DllBase (LIST_ENTRY is at offset 0 of entry,
        # DllBase at +0x10)
        base = int.from_bytes(_read_memory(pid, second + 0x10, 8)
                              or b"\x00" * 8, "little")
        # read 2 MB of ntdll image
        mem = _read_memory(pid, base, 2 * 1024 * 1024)
        if not mem:
            return None
        # hash the .text: header -> NT headers -> section table; exec section
        try:
            pe_off = int.from_bytes(mem[0x3C:0x40], "little")
            nsecs = int.from_bytes(mem[pe_off + 6:pe_off + 8], "little")
            opt_size = int.from_bytes(mem[pe_off + 20:pe_off + 22], "little")
            sec_off = pe_off + 24 + opt_size
            for i in range(min(nsecs, 16)):
                s = sec_off + i * 40
                if len(mem) < s + 40:
                    break
                chars = int.from_bytes(mem[s + 36:s + 40], "little")
                if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    vsize = int.from_bytes(mem[s + 8:s + 12], "little")
                    rawsz = int.from_bytes(mem[s + 16:s + 20], "little")
                    rawptr = int.from_bytes(mem[s + 20:s + 24], "little")
                    size = min(vsize, rawsz, 8 * 1024 * 1024)
                    text = mem[rawptr:rawptr + size]
                    return hashlib.sha256(text).hexdigest()
        except (IndexError, ValueError):
            return None
        return None
    finally:
        k32.CloseHandle(h)


def ntdll_integrity(dyn_dir: Path, sample_pid: int | None) -> dict:
    disk = _disk_ntdll_hash()
    if not disk:
        return {"ok": False, "error": "no on-disk ntdll reference"}
    out: dict = {"ok": True, "disk_ntdll_sha256": disk, "processes": []}
    if not sample_pid:
        return {**out, "checked": False,
                "note": "no sample pid — ntdll integrity needs a target process"}
    mem = _loaded_ntdll_hash(sample_pid)
    if mem is None:
        # process already exited (spawned samples usually exit with Frida) —
        # say so; never claim "hooks intact" without a memory hash
        out["checked"] = True
        out["readable"] = False
        out["processes"].append({
            "pid": sample_pid, "memory_ntdll_text_sha256": None,
            "tampered": None,
            "verdict": ("process no longer readable (exited before the check) "
                        "- use the in-run pe-sieve dump for tamper analysis"),
        })
        return out
    tampered = bool(mem != disk)
    out["processes"].append({
        "pid": sample_pid, "memory_ntdll_text_sha256": mem,
        "tampered": tampered,
        "verdict": ("UNHOOKED/mutated ntdll .text — userland hooks dead; "
                    "kernel-side collection required" if tampered
                    else "ntdll .text matches disk — userland hooks intact"),
    })
    out["checked"] = True
    return out


def memory_harvest(dyn_dir: Path, sample_pid: int | None) -> dict:
    """Harvest dumps into memory/: in-run captures first (pe-sieve monitor
    + delayed procdump written by the job while the sample was ALIVE), then
    a post-run procdump fallback for still-running targets."""
    mem_dir = dyn_dir / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)

    # in-run captures (the reliable ones — a dead pid cannot be dumped)
    existing = sorted(str(p) for p in mem_dir.rglob("*.dmp"))
    if existing:
        return {"ok": True,
                "dumps": existing[:20],
                "dump_dir": str(mem_dir),
                "count": len(existing),
                "note": ("in-run capture (pe-sieve minidump / delayed procdump) "
                         "- taken while the sample was alive. Full-image "
                         "memory acquisition remains DFIR-Nexus territory.")}

    if not sample_pid:
        return {"ok": False, "error": "no sample pid - nothing to harvest"}
    if not Path(PROCDUMP).is_file():
        return {"ok": False, "error": f"procdump missing at {PROCDUMP}"}
    rc, out, err = _run([PROCDUMP, "-accepteula", "-ma", str(sample_pid),
                         str(mem_dir / "sample")], 120)
    dumped = sorted(str(p) for p in mem_dir.rglob("*.dmp"))
    return {"ok": rc == 0 and bool(dumped),
            "dumps": dumped[:20],
            "count": len(dumped),
            "dump_dir": str(mem_dir),
            "note": ("post-run procdump (pid must still be alive)"),
            "error": None if dumped else (err or out)[-200:]}


def process_snapshot(dyn_dir: Path) -> dict:
    try:
        import psutil
        rows = []
        for p in psutil.process_iter(["pid", "ppid", "name", "cmdline"]):
            try:
                rows.append({"pid": p.info["pid"], "ppid": p.info["ppid"],
                             "name": p.info["name"],
                             "cmdline": " ".join(p.info["cmdline"] or [])[:240]})
            except Exception:
                continue
        rows.sort(key=lambda r: r["pid"])
        (dyn_dir / "process_snapshot.json").write_text(
            json.dumps(rows, indent=2), encoding="utf-8")
        return {"ok": True, "process_count": len(rows),
                "note": ("PPID/cmdline snapshot for spoof-correlation with "
                         "procmon_summary.json spoofing_suspects")}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def run_all(dyn_dir: Path, sample_pid: int | None = None) -> dict:
    out = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "memory_harvest": memory_harvest(dyn_dir, sample_pid),
        "ntdll_integrity": ntdll_integrity(dyn_dir, sample_pid),
        "process_snapshot": process_snapshot(dyn_dir),
    }
    (dyn_dir / "post_mortem.json").write_text(
        json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("dynamic_dir")
    ap.add_argument("--sample-pid", type=int, default=None)
    args = ap.parse_args()
    print(json.dumps(run_all(Path(args.dynamic_dir), args.sample_pid), indent=2))