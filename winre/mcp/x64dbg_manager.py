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


def _launch_on_vm(cfg: dict) -> bool:
    """Start x64dbg on the VM via scheduled task (interactive session)."""
    task = "WinRE-X64dbg-Once"
    ps = (
        f'powershell -NoProfile -Command "$a = New-ScheduledTaskAction -Execute '
        f'\'C:\\tools\\x64dbg\\release\\x64\\x64dbg.exe\'; '
        f'$p = New-ScheduledTaskPrincipal -UserId \'FLARE-VM\' -LogonType Interactive '
        f'-RunLevel Limited; $s = New-ScheduledTaskSettingsSet; '
        f'Register-ScheduledTask -TaskName \'{task}\' -Action $a -Principal $p '
        f'-Settings $s -Force | Out-Null; Start-ScheduledTask -TaskName \'{task}\'"'
    )
    r = remote_driver.ssh_run(cfg, ps, timeout=60)
    return r.returncode == 0


def _launch_local() -> bool:
    """Start x64dbg via scheduled task from a process already ON the VM
    (orchestrator local mode) — no SSH hop. $env:USERNAME is the autologon
    user; the task runs x64dbg in the interactive console session."""
    import subprocess
    task = "WinRE-X64dbg-Once"
    ps = (
        "$a = New-ScheduledTaskAction -Execute "
        "'C:\\tools\\x64dbg\\release\\x64\\x64dbg.exe'; "
        "$p = New-ScheduledTaskPrincipal -UserId $env:USERNAME "
        "-LogonType Interactive -RunLevel Limited; "
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


def ensure_mcp_local(base: str | None = None,
                     wait_s: int = 45) -> tuple[bool, dict]:
    """Ensure :9094 for callers already running ON the VM (dynamic OEP/dump).

    Same scheduled-task launch as ensure_mcp(), minus the SSH hop. Keeps
    dynamic runs honest: heal x64dbg instead of silently skipping the
    OEP/dump pass because the GUI isn't open.
    """
    with _lock:
        xc = X64DbgClient(base=base or "http://127.0.0.1:9094",
                          default_timeout=10)
        info: dict = {"local": True, "already_up": False, "launched": False}
        if xc.is_up():
            info["already_up"] = True
            return True, info
        if not _launch_local():
            return False, {**info, "error": "scheduled-task launch failed"}
        deadline = time.time() + wait_s
        while time.time() < deadline:
            time.sleep(3)
            if xc.is_up():
                info["launched"] = True
                return True, info
        return False, {**info, "error": f":9094 not up after {wait_s}s"}


def ensure_mcp(base: str | None = None, wait_s: int = 90) -> tuple[bool, dict]:
    """Ensure x64dbg MCP :9094 is up. Launch on VM if down. Returns (ok, info)."""
    with _lock:
        cfg = remote_driver.flare_cfg()
        host = cfg["host"]
        xc = X64DbgClient(base=base or f"http://{host}:9094", default_timeout=10)
        info: dict = {"host": host, "already_up": False, "launched": False}

        if xc.is_up():
            info["already_up"] = True
            return True, info

        # not up — launch x64dbg on the VM console
        if not _launch_on_vm(cfg):
            return False, {**info, "error": "scheduled-task launch failed"}

        # wait for MCP to come up
        deadline = time.time() + wait_s
        while time.time() < deadline:
            time.sleep(3)
            if xc.is_up():
                info["launched"] = True
                return True, info
        return False, {**info, "error": f":9094 not up after {wait_s}s"}


def health(base: str | None = None) -> dict:
    cfg = remote_driver.flare_cfg()
    host = cfg["host"]
    xc = X64DbgClient(base=base or f"http://{host}:9094", default_timeout=10)
    if not xc.is_up():
        return {"up": False}
    st = xc.get_state()
    return {"up": True, "state": st.get("result")}


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
            # appliance — operator interactive sessions use --keep to skip)
            r = remote_driver.ssh_run(cfg, "taskkill /F /IM x64dbg.exe /T 2>nul "
                                           "& exit /b 0", timeout=30)
            out["killed"] = r.returncode == 0
        return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="x64dbg MCP on-demand manager")
    ap.add_argument("cmd", choices=["ensure", "health", "teardown"])
    args = ap.parse_args()
    if args.cmd == "ensure":
        ok, info = ensure_mcp()
        print(f"ensure: ok={ok} {info}")
        raise SystemExit(0 if ok else 1)
    elif args.cmd == "health":
        print(health())
    else:
        print(teardown())
