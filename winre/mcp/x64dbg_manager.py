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

import time

from winre import remote_driver
from winre.mcp import X64DbgClient


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


def ensure_mcp(base: str | None = None, wait_s: int = 90) -> tuple[bool, dict]:
    """Ensure x64dbg MCP :9094 is up. Launch on VM if down. Returns (ok, info)."""
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


def teardown(base: str | None = None, *, kill_vm: bool = True) -> dict:
    """Stop debugging (if any) and optionally close x64dbg on the VM."""
    cfg = remote_driver.flare_cfg()
    host = cfg["host"]
    xc = X64DbgClient(base=base or f"http://{host}:9094", default_timeout=10)
    out: dict = {}
    if xc.is_up():
        # StopDebug if a session is active
        st = xc.get_state()
        txt = ""
        res = st.get("result") or {}
        if isinstance(res, dict) and res.get("content"):
            txt = res["content"][0].get("text", "")
        if "isDebugging: true" in txt:
            out["stop_debug"] = xc.call("StopDebug")
    if kill_vm:
        r = remote_driver.ssh_run(cfg, "taskkill /F /IM x64dbg.exe", timeout=30)
        out["kill"] = r.returncode == 0
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
