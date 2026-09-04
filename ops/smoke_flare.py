#!/usr/bin/env python3
"""ops/smoke_flare.py — P-B6 smoke test: control plane → FlareVM.

Minimum PASS/FAIL battery over SSH/HTTP (per IMPROVEMENT-PLAN P-B):
  1. ssh probe            — SSH reachable
  2. py_compile           — every winre/*.py on the VM compiles
  3. pipeline layout      — C:\\WinRE\\winre, tools, logs, lock dir present
  4. sample dir           — C:\\samples exists
  5. MCP x64dbg :9094     — direct HTTP (binds 0.0.0.0)
  6. MCP malcat :9009     — SSH-exec bridge (localhost-bound on VM)
  7. MCP windbg :9097     — HTTP from control plane
  8. snapshot gate        — marker probe answers (clean or not is not a
                            failure — the probe working is the check)
  9. LLM endpoint         — llm_client.available() (advisory only)

Usage:  python ops/smoke_flare.py [--json]
Exit 0 = all critical PASS; 1 = any critical FAIL.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from winre.envfile import load_dotenv  # noqa: F401  (loads .env)
from winre.remote_driver import (flare_cfg, ssh_run, ssh_ps, _remote_py,
                                 malcat_remote_is_up)
from winre import snapshot_gate

PY_COMPILE_HELPER = r'''
import json, py_compile, sys
from pathlib import Path
root = Path(r"C:\WinRE")
out = {"ok": True, "compiled": 0, "errors": []}
targets = list((root / "winre").glob("*.py")) + list((root / "tools").glob("*.py"))
for p in targets:
    try:
        py_compile.compile(str(p), doraise=True)
        out["compiled"] += 1
    except Exception as e:
        out["ok"] = False
        out["errors"].append(f"{p.name}: {e}")
print(json.dumps(out))
'''

CHECKS_WIN = [
    ("pipeline layout",
     '@("winre","tools","logs","lock","ops" | ForEach-Object '
     '{ Test-Path ("C:\\WinRE\\" + $_) }) -join ","'),
    ("sample dir", "Test-Path C:\\samples"),
]


def _check(name: str, ok: bool | None, detail: str = "",
           critical: bool = True) -> dict:
    state = "PASS" if ok else ("WARN" if ok is None else "FAIL")
    if ok is None and critical:
        state = "FAIL"
    return {"name": name, "ok": bool(ok), "state": state, "detail": detail,
            "critical": critical}


def run_smoke() -> list[dict]:
    cfg = flare_cfg()
    results: list[dict] = []

    # 1. SSH probe
    try:
        p = ssh_run(cfg, "echo FLARE_OK", timeout=30)
        ok = p.returncode == 0 and "FLARE_OK" in (p.stdout or "")
        results.append(_check("ssh probe", ok, (p.stderr or "")[:120]))
    except Exception as e:
        results.append(_check("ssh probe", False, str(e)[:120]))
        return results  # everything else depends on SSH

    # 2. py_compile all VM-side python
    try:
        py = _remote_py(cfg)
        helper = REPO / "ops" / "_smoke_pycompile.py"
        helper.write_text(PY_COMPILE_HELPER, encoding="utf-8")
        ssh_run(cfg, "New-Item -ItemType Directory -Force -Path C:\\WinRE\\ops "
                     "| Out-Null", timeout=60)
        import subprocess
        scp = subprocess.run(
            ["scp", "-i", cfg["key"], "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=15", str(helper),
             f"{cfg['user']}@{cfg['host']}:C:/WinRE/ops/_smoke_pycompile.py"],
            capture_output=True, text=True, timeout=120)
        if scp.returncode != 0:
            raise RuntimeError(f"scp helper: {scp.stderr[:150]}")
        r = ssh_run(cfg, f'"{py}" C:\\WinRE\\ops\\_smoke_pycompile.py',
                    timeout=300)
        lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
        if not lines:
            raise RuntimeError(f"no output rc={r.returncode} "
                               f"{(r.stderr or '')[:120]}")
        out = json.loads(lines[-1])
        results.append(_check("py_compile (VM)",
                              out.get("ok"), out.get("errors") or
                              f'{out.get("compiled")} files'))
    except Exception as e:
        results.append(_check("py_compile (VM)", False, str(e)[:150]))

    # 3/4. layout checks (encoded-command — inline PS gets mangled over SSH)
    for name, script in CHECKS_WIN:
        try:
            r = ssh_ps(cfg, script, timeout=60)
            val = (r.stdout or "").strip()
            if name == "pipeline layout":
                parts = val.split(",")
                results.append(_check(name, all(x == "True" for x in parts),
                                      f"winre,tools,logs,lock,ops = {val}"))
            else:
                results.append(_check(name, val == "True", f"C:\\samples={val}"))
        except Exception as e:
            results.append(_check(name, False, str(e)[:120]))

    # 5. x64dbg MCP direct
    try:
        from winre.mcp import X64DbgClient
        results.append(_check("MCP x64dbg :9094",
                              X64DbgClient(base=f"http://{cfg['host']}:9094").is_up()))
    except Exception as e:
        results.append(_check("MCP x64dbg :9094", False, str(e)[:120]))

    # 6. malcat via SSH-exec bridge
    try:
        results.append(_check("MCP malcat :9009 (bridge)",
                              malcat_remote_is_up()))
    except Exception as e:
        results.append(_check("MCP malcat :9009 (bridge)", False, str(e)[:120]))

    # 7. windbg — localhost-bound on the VM, so probe the port over SSH
    #    (direct HTTP from the control plane can never reach 127.0.0.1 binds)
    try:
        r = ssh_ps(cfg, "if (Get-NetTCPConnection -LocalPort 9097 -State Listen "
                        "-ErrorAction SilentlyContinue) { 'listening' } "
                        "else { 'down' }", timeout=60)
        val = (r.stdout or "").strip()
        results.append(_check("MCP windbg :9097 (ssh port probe)",
                              val == "listening", val))
    except Exception as e:
        results.append(_check("MCP windbg :9097 (ssh port probe)", False,
                              str(e)[:120]))

    # 8. snapshot gate probe answers
    try:
        m = snapshot_gate.marker_exists(cfg)
        results.append(_check("snapshot-gate probe", m is not None,
                              f"marker={m} (clean-or-not is not a failure)",
                              critical=True))
    except Exception as e:
        results.append(_check("snapshot-gate probe", False, str(e)[:120]))

    # 9. LLM endpoint (advisory — never fails the smoke)
    try:
        from winre import llm_client
        results.append(_check("LLM endpoint (advisory)",
                              llm_client.available(), critical=False))
    except Exception as e:
        results.append(_check("LLM endpoint (advisory)", None, str(e)[:120],
                              critical=False))

    return results


def main() -> int:
    as_json = "--json" in sys.argv
    results = run_smoke()
    if as_json:
        print(json.dumps(results, indent=2))
    else:
        print(f"{'CHECK':<28} {'STATE':<6} DETAIL")
        print("-" * 78)
        for r in results:
            print(f"{r['name']:<28} {r['state']:<6} {r['detail'][:46]}")
        bad = [r for r in results if r["state"] == "FAIL"]
        print("-" * 78)
        print(f"{len(results) - len(bad)}/{len(results)} checks passed"
              + (f" — FAILURES: {[r['name'] for r in bad]}" if bad else ""))
    return 1 if any(r["state"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
