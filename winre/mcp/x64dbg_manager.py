#!/usr/bin/env python3
r"""x64dbg_manager.py — on-demand x64dbg + MCP lifecycle (control plane → VM).

The dynamic phase must NOT depend on x64dbg being manually open. This module
ensures the x64dbg MCP (:9094) is available when needed:
    ensure_mcp()   — probe :9094; if down, launch x64dbg on the VM console
                     (scheduled task, interactive session) and wait for MCP
    teardown()     — optionally close the x64dbg session (StopDebug / exit)
    health()       — probe state

Usage (control plane, SSH to FlareVM):
    from winre.mcp.x64dbg_manager import ensure_mcp, teardown
    ok, info = ensure_mcp()          # x64dbg + :9094 guaranteed (or error)
    ...
    teardown()                       # optional cleanup after the debug loop

The MCP server is the x64dbg plugin (in-process); it binds 0.0.0.0:9094 and
the control plane reaches it over the lab NIC. Launch happens via a scheduled
task so x64dbg runs in the autologon console session (GUI apps can't start
from a non-interactive SSH process).
"""
from __future__ import annotations

import os
import threading
import time

from winre import remote_driver
from winre.mcp import X64DbgClient
from winre.mcp.x64dbg_client import module_name_is_safe, safe_module_filename

# --- which debugger can load this sample? (P1-F1, finding of 2026-10-06) ---
#
# x64dbg is TWO programs. x64dbg.exe debugs 64-bit images, x32dbg.exe debugs
# 32-bit ones. Launching x64dbg.exe on a PE32 sample gives a debuggee that
# never reaches its entry breakpoint, and every OEP method fails identically
# with "debug session ended before EP pause" — which is exactly what the first
# live agentic-dbg run (sample s01, PE32) produced. A 32-bit sample must be
# handed to x32dbg or the unpack half of the pipeline is a no-op.
XDBG_BIN = {
    64: r"C:\tools\x64dbg\release\x64\x64dbg.exe",
    32: r"C:\tools\x64dbg\release\x32\x32dbg.exe",
}
# process names, for the flavour check and for teardown (both may be running
# across a run that changed samples)
XDBG_PROCS = {64: "x64dbg.exe", 32: "x32dbg.exe"}
DEFAULT_ARCH = 64

# PE Machine field values (IMAGE_FILE_MACHINE_*). Only the two we debug.
_MACHINE_386 = 0x014C
_MACHINE_AMD64 = 0x8664

_arch_cache: dict[str, int] = {}

# serialize ensure/teardown: two concurrent callers (pipeline + manual stage)
# must not double-launch or race the kill
_lock = threading.Lock()


def stage_safe_sample(cfg: dict, remote_sample: str,
                      tag: str = "") -> str:
    """Return an x64dbg-expression-safe VM path for the sample.

    x64dbg module lookups parse names as expressions — a hyphenated sample
    (`notepad-sys32.exe`) never resolves (`Module "notepad-sys32" not found`,
    verified live), so DetectOEP/DumpModule/AnalyzeModule silently fail.
    Unsafe names are copied once to C:\\samples\\x64_<name>_<tag><ext>.
    Safe names are returned unchanged (no copy).
    """
    name = remote_sample.replace("/", "\\").rsplit("\\", 1)[-1]
    stem = os.path.splitext(name)[0]
    if module_name_is_safe(stem):
        return remote_sample
    safe_name = safe_module_filename(name, tag)
    safe_path = rf"C:\samples\{safe_name}"
    try:
        remote_driver.ssh_ps(
            cfg,
            f"if (-not (Test-Path '{safe_path}')) {{ "
            f"Copy-Item -Force '{remote_sample}' '{safe_path}' }}")
    except Exception:
        return remote_sample  # fall through; caller reports the real error
    return safe_path


def keep_debugger() -> bool:
    """WINRE_KEEP_DEBUGGER=1 preserves x64dbg across runs (interactive work)."""
    import os
    return os.environ.get("WINRE_KEEP_DEBUGGER", "").strip().lower() in ("1", "true", "yes")


# --- P1-F1: resolve the sample's bitness, then launch the right debugger ----

def _pe_bitness_local(path: str) -> int | None:
    """Read the PE Machine field from a file on THIS machine, or None."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x400)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return None
            e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
            if not 0 < e_lfanew <= len(head) - 6:
                return None
            machine = int.from_bytes(head[e_lfanew + 4:e_lfanew + 6], "little")
    except OSError:
        return None
    if machine == _MACHINE_AMD64:
        return 64
    if machine == _MACHINE_386:
        return 32
    return None


def _pe_bitness_vm(cfg: dict, path: str) -> int | None:
    """Read the PE Machine field from a file on the VM (one SSH round trip).

    Reads only the first 512 bytes: a 5 MB sample must not be slurped into
    memory over SSH just to learn its bitness.
    """
    p = path.replace("'", "''")
    ps = (
        f"$f=[IO.File]::Open('{p}','Open','Read','ReadWrite');"
        "$b=New-Object byte[] 512; $n=$f.Read($b,0,512); $f.Close();"
        "if ($n -lt 64) { 'ERR' } else {"
        "$lf=[BitConverter]::ToInt32($b,0x3c);"
        "if ($lf -lt 0 -or ($lf+6) -gt $n) { 'ERR' } else {"
        "[BitConverter]::ToUInt16($b,$lf+4) } }"
    )
    try:
        r = remote_driver.ssh_ps(cfg, ps, timeout=60)
    except Exception:
        return None
    for tok in (r.stdout or "").split():
        try:
            machine = int(tok, 10)
        except ValueError:
            continue
        if machine == _MACHINE_AMD64:
            return 64
        if machine == _MACHINE_386:
            return 32
    return None


def pe_bitness(sample: str | os.PathLike | None,
               cfg: dict | None = None) -> int | None:
    """32 or 64 for a PE, or None if it is not a PE we can read.

    Tries this machine first (the orchestrator/debug loops run ON the VM and
    the path is right there), then the FlareVM over SSH (the control plane
    sees only a remote path). Cached per path: a run asks once.
    """
    if not sample:
        return None
    key = str(sample)
    if key in _arch_cache:
        return _arch_cache[key]
    bits = _pe_bitness_local(key)
    if bits is None:
        try:
            bits = _pe_bitness_vm(cfg or remote_driver.flare_cfg(), key)
        except Exception:
            bits = None
    _arch_cache[key] = bits          # None is cached too: do not re-ask
    return bits


def xdbg_arch(sample: str | os.PathLike | None = None,
              cfg: dict | None = None) -> int:
    """Which x64dbg flavour to launch for this sample: 32 (x32dbg) or 64.

    Falls back to 64 when the bitness cannot be read, which is the
    pre-P1-F1 behaviour — the operator can force either with
    WINRE_XDBG_ARCH=32|64.
    """
    env = os.environ.get("WINRE_XDBG_ARCH", "").strip().lower()
    if env in ("32", "x32", "x32dbg"):
        return 32
    if env in ("64", "x64", "x64dbg"):
        return 64
    bits = pe_bitness(sample, cfg)
    return bits if bits in (32, 64) else DEFAULT_ARCH


def _launch_on_vm(cfg: dict, arch: int = DEFAULT_ARCH) -> bool:
    """Start the right x64dbg on the VM via scheduled task (interactive
    session). `arch` picks x64dbg.exe (64) or x32dbg.exe (32).

    RunLevel=Highest: the Task Scheduler service grants the elevated token
    with NO UAC prompt (x64dbg requires admin; a manual launch would pop
    UAC unless UAC is disabled).
    """
    exe = XDBG_BIN.get(arch, XDBG_BIN[DEFAULT_ARCH])
    task = "WinRE-X64dbg-Once"
    ps = (
        f'powershell -NoProfile -Command "$a = New-ScheduledTaskAction -Execute '
        f'\'{exe}\'; '
        f'$p = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive '
        f'-RunLevel Highest; $s = New-ScheduledTaskSettingsSet; '
        f'Register-ScheduledTask -TaskName \'{task}\' -Action $a -Principal $p '
        f'-Settings $s -Force | Out-Null; Start-ScheduledTask -TaskName \'{task}\'"'
    )
    r = remote_driver.ssh_run(cfg, ps, timeout=60)
    return r.returncode == 0


def _launch_local(arch: int = DEFAULT_ARCH) -> bool:
    """Start the right x64dbg via scheduled task from a process already ON the
    VM (orchestrator local mode) — no SSH hop. $env:USERNAME is the autologon
    user; RunLevel=Highest grants elevation without a UAC prompt."""
    import subprocess
    exe = XDBG_BIN.get(arch, XDBG_BIN[DEFAULT_ARCH])
    task = "WinRE-X64dbg-Once"
    ps = (
        "$a = New-ScheduledTaskAction -Execute "
        f"'{exe}'; "
        "$p = New-ScheduledTaskPrincipal -UserId $env:USERNAME "
        "-LogonType Interactive -RunLevel Highest; "
        "$s = New-ScheduledTaskSettingsSet; "
        f"Register-ScheduledTask -TaskName '{task}' -Action $a -Principal $p "
        f"-Settings $s -Force | Out-Null; Start-ScheduledTask -TaskName '{task}'"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy",
                            "Bypass", "-Command", ps],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return False


def _running_arch_vm(cfg: dict) -> int | None:
    """Which x64dbg flavour, if any, is running on the VM. None if neither.

    :9094 alone cannot answer this: both flavours serve it identically, so a
    32-bit sample would happily attach to an x64dbg left over from the boot
    preheat and fail every OEP method. Ask the process list instead.
    """
    ps = ("$a = @(Get-Process x32dbg -EA SilentlyContinue).Count; "
          "$b = @(Get-Process x64dbg -EA SilentlyContinue).Count; "
          "\"$a $b\"")
    try:
        r = remote_driver.ssh_ps(cfg, ps, timeout=30)
    except Exception:
        return None
    nums = (r.stdout or "").split()
    try:
        n32, n64 = int(nums[0]), int(nums[1])
    except (IndexError, ValueError):
        return None
    if n32 and not n64:
        return 32
    if n64 and not n32:
        return 64
    return None


def _kill_all_vm(cfg: dict) -> None:
    """Force-close BOTH x64dbg flavours on the VM.

    Only x64dbg.exe was ever killed, so after fixing the launcher a 32-bit
    session could leave x32dbg.exe alive and the next run would attach to a
    debugger with a stale debuggee.
    """
    remote_driver.ssh_run(
        cfg,
        "taskkill /F /IM x32dbg.exe /T 2>nul & taskkill /F /IM x64dbg.exe /T 2>nul "
        "& exit /b 0", timeout=30)


def ensure_mcp_local(base: str | None = None, wait_s: int = 90,
                     sample: str | os.PathLike | None = None
                     ) -> tuple[bool, dict]:
    """Ensure :9094 for callers already running ON the VM (dynamic OEP/dump).

    Same scheduled-task launch as ensure_mcp(), minus the SSH hop. Keeps
    dynamic runs honest: heal x64dbg instead of silently skipping the
    OEP/dump pass because the GUI isn't open.

    `sample` selects the flavour: a PE32 sample gets x32dbg.exe, everything
    else x64dbg.exe (P1-F1).
    """
    arch = xdbg_arch(sample)
    with _lock:
        xc = X64DbgClient(base=base or "http://127.0.0.1:9094",
                          default_timeout=10)
        info: dict = {"local": True, "already_up": False, "launched": False,
                      "arch": arch, "debugger": XDBG_PROCS[arch],
                      "exe": XDBG_BIN[arch]}
        if xc.is_up():
            info["already_up"] = True
            return True, info
        if not _launch_local(arch):
            return False, {**info, "error": "scheduled-task launch failed"}
        deadline = time.time() + wait_s
        while time.time() < deadline:
            time.sleep(3)
            if xc.is_up():
                info["launched"] = True
                return True, info
        return False, {**info, "error": f":9094 not up after {wait_s}s"}


def ensure_mcp(base: str | None = None, wait_s: int = 90,
               sample: str | os.PathLike | None = None,
               cfg: dict | None = None) -> tuple[bool, dict]:
    """Ensure x64dbg MCP :9094 is up. Launch on VM if down. Returns (ok, info).

    `sample` selects the debugger flavour (P1-F1). If :9094 is already served
    by the WRONG flavour — the boot preheat launches x64dbg unconditionally —
    it is closed and relaunched as x32dbg, because attaching a PE32 sample to
    x64dbg is the exact failure this function exists to prevent.
    """
    with _lock:
        cfg = cfg or remote_driver.flare_cfg()
        host = cfg["host"]
        arch = xdbg_arch(sample, cfg)
        xc = X64DbgClient(base=base or f"http://{host}:9094", default_timeout=10)
        info: dict = {"host": host, "already_up": False, "launched": False,
                      "arch": arch, "debugger": XDBG_PROCS[arch],
                      "exe": XDBG_BIN[arch]}

        if xc.is_up():
            running = _running_arch_vm(cfg)
            if running in (32, 64) and running != arch:
                # wrong flavour: a 32-bit sample must not be handed to x64dbg
                info["replaced_wrong_arch"] = running
                _kill_all_vm(cfg)
                deadline = time.time() + min(wait_s, 20)
                while time.time() < deadline and xc.is_up():
                    time.sleep(1.5)
            else:
                info["already_up"] = True
                return True, info

        # not up (or we just closed the wrong flavour) — launch the right one
        if not _launch_on_vm(cfg, arch):
            return False, {**info, "error": "scheduled-task launch failed"}

        # wait for MCP to come up
        deadline = time.time() + wait_s
        while time.time() < deadline:
            time.sleep(3)
            if xc.is_up():
                info["launched"] = True
                return True, info
        return False, {**info, "error": f":9094 not up after {wait_s}s"}


def restart_mcp(wait_s: int = 90,
                sample: str | os.PathLike | None = None,
                cfg: dict | None = None) -> tuple[bool, dict]:
    """Kill + relaunch x64dbg for a clean debug session.

    Cold-start sessions can be broken (first run after a scheduled-task
    launch) — a fresh instance fixes the "never paused" failure class.
    `sample` keeps the relaunch on the correct flavour (P1-F1).
    """
    teardown_info: dict = {}
    try:
        teardown_info = teardown(kill_vm=True)
    except Exception as e:
        teardown_info = {"error": str(e)[:150]}
    time.sleep(2)
    ok, info = ensure_mcp(wait_s=wait_s, sample=sample, cfg=cfg)
    return ok, {"teardown": teardown_info, "ensure": info}


def health(base: str | None = None) -> dict:
    cfg = remote_driver.flare_cfg()
    host = cfg["host"]
    xc = X64DbgClient(base=base or f"http://{host}:9094", default_timeout=10)
    if not xc.is_up():
        return {"up": False}
    st = xc.get_state()
    arch = _running_arch_vm(cfg)
    return {"up": True, "state": st.get("result"),
            "arch": arch, "debugger": XDBG_PROCS.get(arch) if arch else None}


def teardown(base: str | None = None, *, kill_vm: bool = True,
             wait_s: int = 8) -> dict:
    """Neatly close the debug session and the x64dbg GUI.

    Order matters: 1) StopDebug terminates the debuggee (the SAMPLE must
    never keep running inside a tool), 2) a graceful 'exit' command closes
    the GUI, 3) only if the GUI is still alive after the wait, a forced
    taskkill. Never raises — cleanup must be best-effort.
    """
    with _lock:
        cfg = remote_driver.flare_cfg()
        host = cfg["host"]
        xc = X64DbgClient(base=base or f"http://{host}:9094", default_timeout=10)
        out: dict = {"stopped": False, "exited": False, "killed": False}

        if xc.is_up():
            try:
                r = xc.stop_debug()
                out["stopped"] = bool(r.get("ok"))
            except Exception as e:
                out["stop_error"] = str(e)[:120]
            # graceful GUI exit; the response may be lost if the GUI closes
            # mid-request — verify by process state, not by return value
            try:
                xc.exit_gui()
            except Exception:
                pass
            deadline = time.time() + wait_s
            while time.time() < deadline:
                time.sleep(1.5)
                if not xc.is_up():
                    out["exited"] = True
                    break

        if kill_vm and not out.get("exited"):
            # forced fallback: every x64dbg on this VM is ours (detonation
            # appliance — operator interactive sessions use --keep to skip).
            # BOTH flavours: a 32-bit run leaves x32dbg.exe, and leaving it
            # alive would poison the next run's session (P1-F1).
            _kill_all_vm(cfg)
            out["killed"] = True
        return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="x64dbg MCP on-demand manager")
    ap.add_argument("cmd", choices=["ensure", "health", "teardown", "arch"])
    ap.add_argument("--sample", default=None,
                    help="sample path; picks x32dbg for a PE32 image, "
                         "x64dbg otherwise (P1-F1)")
    args = ap.parse_args()
    if args.cmd == "ensure":
        ok, info = ensure_mcp(sample=args.sample)
        print(f"ensure: ok={ok} {info}")
        raise SystemExit(0 if ok else 1)
    elif args.cmd == "health":
        print(health())
    elif args.cmd == "arch":
        # no debugger side effects: just report which flavour this file needs
        bits = pe_bitness(args.sample)
        arch = xdbg_arch(args.sample)
        print(f"sample={args.sample} bits={bits} arch={arch} "
              f"exe={XDBG_BIN[arch]}")
    else:
        print(teardown())
