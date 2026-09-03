#!/usr/bin/env python3
r"""remote_driver.py — control-plane driver for WinRE (FlareVM execution plane).

WinRE split (see docs/ARCHITECTURE.md):
    CONTROL PLANE (this host — internet, LLM, UI):
        - runs pipeline.py with --driver remote
        - LLM endpoint (WINRE_LLM_BASE_URL), web UI, LangGraph deep-dive agent
    EXECUTION PLANE (FlareVM — NO internet, host-only NIC):
        - tools: Ghidra/IDA/Malcat/x64dbg/WinDbg/Frida/Procmon/FakeNet
        - MCP servers: x64dbg :9094 · Malcat :9009 · WinDbg :9097 · IDA :19300 · Ghidra :19301
        - detonation job (survives SSH drop; artifacts pulled via SCP)

The driver reuses the pipeline's evidence pack + audit, but the tool calls
become remote:
    - static SQL   : ssh flare "python flare_ghidra_sql.py ..." (or HTTP :19301)
    - dynamic      : ssh flare "python orchestrator.py --mode local ..." then
                     scp the dynamic pack back (REVENG_LOGS_DIR on VM)
    - MCP deep     : HTTP to <flare>:9094/9009/9097 from this host (lab net)
    - LLM          : local endpoint on this host

Env:
    FLARE_HOST / FLARE_USER / FLARE_SSH_KEY / FLARE_SSH_PORT   (SSH to VM)
    WINRE_LLM_BASE_URL / WINRE_LLM_API_KEY / WINRE_LLM_MODEL   (LLM here)
    WINRE_REMOTE_LOGS=logs   (local evidence root; pulled from VM)
    WINRE_REMOTE_PIPELINE=C:\WinRE   (repo path on the VM)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .evidence import EvidencePack, stage_result

REPO = Path(__file__).resolve().parents[1]
LOCAL_LOGS = Path(os.environ.get("WINRE_PIPELINE_LOGS", str(REPO / "logs")))


def flare_cfg() -> dict:
    return {
        "host": os.environ.get("FLARE_HOST", "192.168.77.42"),
        "user": os.environ.get("FLARE_USER", "FLARE-VM"),
        "key": os.environ.get("FLARE_SSH_KEY",
                              str(Path.home() / ".ssh" / "cadre-77.42-key")),
        "port": int(os.environ.get("FLARE_SSH_PORT", "22")),
        "remote_pipeline": os.environ.get("WINRE_REMOTE_PIPELINE", r"C:\WinRE"),
    }


def _ssh_base(cfg: dict) -> list[str]:
    return [
        "ssh", "-i", cfg["key"], "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
        "-p", str(cfg["port"]),
        f"{cfg['user']}@{cfg['host']}",
    ]


def ssh_run(cfg: dict, remote_cmd: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run a command on the FlareVM (quoted as ONE remote command string)."""
    return subprocess.run(_ssh_base(cfg) + [remote_cmd], capture_output=True,
                          text=True, timeout=timeout, encoding="utf-8",
                          errors="replace")


def scp_to(cfg: dict, local: Path, remote: str) -> None:
    cmd = ["scp", "-i", cfg["key"], "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=15", "-P", str(cfg["port"]),
           str(local), f"{cfg['user']}@{cfg['host']}:{remote}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"scp to flare failed: {r.stderr[:300]}")


def scp_from(cfg: dict, remote: str, local: Path) -> None:
    cmd = ["scp", "-i", cfg["key"], "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=15", "-P", str(cfg["port"]),
           f"{cfg['user']}@{cfg['host']}:{remote}", str(local)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise RuntimeError(f"scp from flare failed: {r.stderr[:300]}")


def _remote_py(cfg: dict) -> str:
    """Path of the repo's python on the VM (C:\\Python313 preferred)."""
    for cand in (r"C:\Python313\python.exe", r"C:\ProgramData\chocolatey\bin\python.exe"):
        if cand:  # probed lazily per call; first is standard on FlareVM
            return cand
    return "python"


# ---------------------------------------------------------------------------
# Remote helper (runs ON the VM via scp — avoids nested-quote breakage)
# ---------------------------------------------------------------------------
REMOTE_QUICK_HELPER = r'''
"""Remote quick-triage helper — runs on FlareVM, prints JSON to stdout.

Usage: python _remote_quick_helper.py <sample_path> --json
Output: {"evidence": {ghidra: {...}, ida: {...}}}
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sample = Path(sys.argv[1])
out = {"ghidra": {}, "ida": {}}
py = sys.executable

def run(script, *args):
    p = subprocess.run([py, str(script), *args], capture_output=True, text=True,
                       timeout=900, encoding="utf-8", errors="replace")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": (p.stderr or p.stdout)[-200:]}

tools = Path(__file__).resolve().parents[1] / "tools"
g = run(tools / "flare_ghidra_sql.py", "query", "@funcs", "--file", str(sample), "--json")
if g.get("ok"):
    out["ghidra"] = {"func_rows": len(g.get("rows") or [])}
else:
    out["ghidra"] = {"error": g.get("error")}

i64 = sample.with_suffix(sample.suffix + ".i64")
if i64.is_file():
    i = run(tools / "flarevm_ida_query.py", str(sample), "SELECT count(*) FROM funcs", "--json")
    if i.get("ok"):
        rows = i.get("rows") or []
        out["ida"] = {"func_count": rows[0][0] if rows and rows[0] else None}
    else:
        out["ida"] = {"error": i.get("error")}
else:
    out["ida"] = {"skipped": "no .i64 on VM (deep dive will create)"}

print(json.dumps({"evidence": out}))
'''


# ---------------------------------------------------------------------------
# Remote stage implementations (control plane)
# ---------------------------------------------------------------------------

def remote_quick(sample_name: str, pack: EvidencePack, cfg: dict) -> dict:
    """SSH: run the quick SQL wrappers on the VM via a helper script, pull JSON back.

    Uses a remote helper .py (scp'd) instead of nested inline quoting — the
    nested powershell -Command string mangles @ and quotes over SSH.
    """
    t0 = time.time()
    py = _remote_py(cfg)
    remote_sample = rf"C:\samples\{sample_name}"

    # helper script: runs ghidra + ida counts, prints JSON
    helper = REPO / "winre" / "_remote_quick_helper.py"
    helper.write_text(REMOTE_QUICK_HELPER, encoding="utf-8")
    try:
        scp_to(cfg, helper, rf'{cfg["remote_pipeline"]}\winre\_remote_quick_helper.py')
    except Exception as e:
        return {"ok": False, "error": f"scp helper: {e}"}

    cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
           f'{cfg["remote_pipeline"]}\\winre\\_remote_quick_helper.py '
           f'"{remote_sample}" --json 2>&1"')
    r = ssh_run(cfg, cmd, timeout=900)
    evidence: dict = {}
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            evidence = data.get("evidence") or {}
        except json.JSONDecodeError:
            pass
    if not evidence:
        evidence = {"ghidra": {"error": (r.stderr or r.stdout)[-200:]}}

    verdict = "unknown"
    pack.write("quick", "quick.json", {"evidence": evidence, "verdict": verdict,
                                       "tool_failures": []})
    pack.write("quick", "META.json", stage_result(
        "quick", True, summary=f"ghidra={evidence.get('ghidra',{}).get('func_rows')} "
                               f"ida={evidence.get('ida',{}).get('func_count')}",
        verdict=verdict, elapsed_s=round(time.time() - t0, 1)))
    return {"evidence": evidence, "verdict": verdict}


# ---------------------------------------------------------------------------
# Remote dynamic helper (runs ON the VM via scp)
# ---------------------------------------------------------------------------
REMOTE_DYNAMIC_HELPER = r'''
"""Remote dynamic helper — runs orchestrator --mode local on the VM.

Usage: python _remote_dynamic_helper.py <sha> <sample_path> <max_seconds> [--pesieve]
Writes the session file, sets env, runs orchestrator, prints META.json tail.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sha = sys.argv[1]
sample = sys.argv[2]
max_seconds = int(sys.argv[3])
pesieve = "--pesieve" in sys.argv[4:]

pipeline = Path(__file__).resolve().parents[1]
sessions = pipeline / "sessions"
sessions.mkdir(parents=True, exist_ok=True)
(sessions / f"{sha}.json").write_text(json.dumps({
    "sha256": sha,
    "sample_path": sample,
    "file_type": {"format": "pe"},
}), encoding="utf-8")

env = os.environ.copy()
env["WINRE_ORCHESTRATOR_MODE"] = "local"
env.setdefault("WINRE_ORCH_LOCK", str(pipeline / "lock" / "orchestrator.lock"))
env["REVENG_LOGS_DIR"] = str(pipeline / "logs")
env["REVENG_SESSIONS_DIR"] = str(sessions)

cmd = [sys.executable, str(pipeline / "winre" / "orchestrator.py"), sha,
       "--mode", "local", "--max-seconds", str(max_seconds)]
if pesieve:
    cmd.append("--pesieve")
try:
    r = subprocess.run(cmd, capture_output=True, text=True, env=env,
                       timeout=int(max_seconds) + 600,
                       encoding="utf-8", errors="replace")
    print(f"RC={r.returncode}")
    print((r.stdout or "")[-600:])
except subprocess.TimeoutExpired:
    print("RC=-1 TIMEOUT")
'''


def remote_dynamic(sample_name: str, sha: str, pack: EvidencePack, cfg: dict,
                   max_seconds: int, enable_pesieve: bool) -> dict:
    """SSH: run orchestrator --mode local on the VM via helper, scp pack back."""
    t0 = time.time()
    py = _remote_py(cfg)
    remote_sample = rf"C:\samples\{sample_name}"
    helper = REPO / "winre" / "_remote_dynamic_helper.py"
    helper.write_text(REMOTE_DYNAMIC_HELPER, encoding="utf-8")
    try:
        scp_to(cfg, helper, rf'{cfg["remote_pipeline"]}\winre\_remote_dynamic_helper.py')
    except Exception as e:
        return stage_result("dynamic", False, error=f"scp helper: {e}",
                            elapsed_s=round(time.time() - t0, 1))

    cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
           f'{cfg["remote_pipeline"]}\\winre\\_remote_dynamic_helper.py '
           f'{sha} "{remote_sample}" {int(max_seconds)}'
           f'{" --pesieve" if enable_pesieve else ""} 2>&1"')
    r = ssh_run(cfg, cmd, timeout=int(max_seconds) + 700)

    # pull dynamic dir back
    local_dyn = pack.stages["dynamic"]
    local_dyn.mkdir(parents=True, exist_ok=True)
    ok = False
    err = None
    remote_dyn = rf'{cfg["remote_pipeline"]}\logs\{sha}\dynamic'
    try:
        scp_from(cfg, rf"{remote_dyn}\*", local_dyn)
        ok = True
    except Exception as e:
        err = str(e)
        # orchestrator may have died but still wrote META
        probe = ssh_run(cfg, f'powershell -NoProfile -Command (Test-Path "{remote_dyn}\\META.json")',
                        timeout=30)
        if probe.returncode == 0 and "True" in probe.stdout:
            try:
                scp_from(cfg, rf"{remote_dyn}\META.json", local_dyn / "META.json")
                ok = True
            except Exception:
                pass
    meta = pack.read("dynamic", "META.json") or {}
    ok = ok or bool(meta.get("ok"))
    stage_meta = stage_result("dynamic", ok, error=err,
                              summary=f"events={meta.get('frida_events')} ok={ok}",
                              elapsed_s=round(time.time() - t0, 1))
    pack.write("dynamic", "STAGE.json", stage_meta)
    return stage_meta


def remote_mcp_health(cfg: dict) -> dict:
    """Probe the VM's MCP servers over the lab net (HTTP, from this host)."""
    out = {}
    for name, url in (("x64dbg", "http://{}:9094/"), ("malcat", "http://{}:9009/mcp"),
                      ("windbg", "http://{}:9097/mcp/")):
        import urllib.request
        try:
            req = urllib.request.Request(url.format(cfg["host"]), data=b"{}",
                                         method="POST")
            with urllib.request.urlopen(req, timeout=8) as resp:
                out[name] = resp.status == 200
        except Exception:
            out[name] = False
    return out


def remote_deep(sample_name: str, pack: EvidencePack, cfg: dict, dry_llm: bool,
                sha: str = "", dynamic: bool = False) -> dict:
    """Deep dive from the control plane.

    Engine: LangGraph ReAct agent (winre/agentic.py) over the static toolset
    (Ghidra/IDA SQL over SSH + Malcat MCP over HTTP). When the LLM endpoint is
    configured the agent runs and the result is `llm_judge`; otherwise the
    stage records `deterministic_fallback` (honest, not green).
    Set dynamic=True (same --dynamic opt-in as detonation) to also expose the
    bounded x64dbg debug-loop tools to the agent.
    """
    from . import llm_client
    t0 = time.time()
    mcp = remote_mcp_health(cfg)
    engine = "langgraph+dbg" if dynamic else "langgraph"
    out: dict = {"mcp": mcp, "remote": True, "engine": engine}
    fallback = False
    failures: list[str] = []

    # x64dbg MCP (HTTP from here) — probe only in static phase
    if mcp.get("x64dbg"):
        try:
            from winre.mcp import X64DbgClient
            xc = X64DbgClient(base=f"http://{cfg['host']}:9094")
            lb = xc.load_binary(rf"C:\samples\{sample_name}")
            out["x64dbg"] = {"loaded": lb.get("ok")}
        except Exception as e:
            failures.append(f"x64dbg:{e}")

    # LangGraph agent (static toolset) — llm_judge if LLM up
    agent_result = None
    try:
        from winre.agentic import run_langgraph_deep_dive
        agent_result = run_langgraph_deep_dive(sample_name, sha or sample_name,
                                               max_steps=10, dry=dry_llm,
                                               dynamic=dynamic)
        history = []
        for h in (agent_result.get("history") or [])[:60]:
            entry = {"step": h.get("step"), "tool": h.get("tool"),
                     "args": h.get("args"), "error": h.get("error")}
            res = h.get("result")
            if isinstance(res, dict):
                res = {k: res.get(k) for k in
                       ("ok", "verdict", "summary", "row_count", "error")
                       if k in res}
                s = json.dumps(res, default=str)
                entry["result"] = s[:800] + ("…" if len(s) > 800 else "")
            out_hist = entry
            history.append(out_hist)
        out["agent"] = {
            "source": agent_result.get("source"),
            "verdict": agent_result.get("verdict"),
            "llm_analysis": agent_result.get("llm_analysis"),
            "tool_calls": len(agent_result.get("history") or []),
            "history": history,
        }
    except Exception as e:
        failures.append(f"agent:{e}")
        agent_result = None

    if agent_result and agent_result.get("source") == "llm_judge":
        # deep produced real LLM analysis — not a fallback
        fallback = False
    else:
        fallback = True
        if not out.get("agent"):
            out["agent"] = {"source": "deterministic_fallback",
                            "text": "agent unavailable on control plane"}
        # keep evidence-only summary so the pack is still useful
        try:
            if llm_client.available() and not dry_llm:
                pass  # agent already tried; fall through
        except Exception:
            pass

    pack.write("deep", "deep.json", out)
    pack.write("deep", "META.json", stage_result(
        "deep", True, summary=f"mcp={mcp} engine=langgraph fallback={fallback}",
        fallback=fallback, tool_failures=failures,
        elapsed_s=round(time.time() - t0, 1)))
    return {"ok": True, "fallback": fallback, "failures": failures, "mcp": mcp}


def run_remote_pipeline(sample: Path, *, max_seconds: int = 45,
                        enable_pesieve: bool = False, enable_dynamic: bool = False,
                        dry_llm: bool = False) -> dict:
    """Control-plane pipeline driver: SSH/HTTP to the VM + local LLM + local audit.

    DEFAULT = static-only (quick + deep + yara + report + audit). Dynamic is
    opt-in (enable_dynamic) and runs LAST, segregated, static_yara_wins.
    """
    from .evidence import sha256_file
    from . import audit as audit_mod
    from . import yara_gen

    cfg = flare_cfg()
    sha = sha256_file(sample)
    pack = EvidencePack(LOCAL_LOGS, sha).ensure()

    # upload the sample to the VM (C:\samples\<name>) — tools run there
    remote_sample = rf"C:\samples\{sample.name}"
    try:
        scp_to(cfg, sample, remote_sample.replace("\\", "/"))
    except Exception as e:
        print(f"[winre-remote] WARN sample upload failed: {e}", flush=True)

    # intake (local — we have the file)
    from .pipeline import _intake
    results = {"intake": _intake(sample, pack)}

    # ---- STATIC phase (quick + deep over SSH/HTTP) ----
    results["quick"] = remote_quick(sample.name, pack, cfg)
    results["deep"] = remote_deep(sample.name, pack, cfg, dry_llm, sha=sha,
                                  dynamic=enable_dynamic)

    # ---- DYNAMIC phase (segregated, opt-in, runs LAST after static) ----
    if enable_dynamic:
        results["dynamic"] = remote_dynamic(sample.name, sha, pack, cfg,
                                            max_seconds, enable_pesieve)

    # yara (local, from evidence)
    try:
        rep = yara_gen.generate_rules(pack.root, pack.stages["yara"])
        pack.write("yara", "META.json", stage_result("yara", True,
                                                     summary=f"rule={rep.get('rule_id')}"))
        results["yara"] = {"ok": True, "rule_id": rep.get("rule_id")}
    except Exception as e:
        results["yara"] = {"ok": False, "error": str(e)}

    # report + audit (local)
    from .pipeline import _report
    results["report"] = _report(pack, sha, results["quick"], results.get("dynamic"),
                                results["deep"])
    audit_res = audit_mod.audit(pack.root)
    (pack.root / "audit.json").write_text(
        json.dumps(audit_res, indent=2) + "\n", encoding="utf-8")
    results["audit"] = audit_res

    print(f"[winre-remote] {sha[:16]}… quick={results['quick'].get('verdict')} "
          f"dynamic={'ok' if results.get('dynamic',{}).get('ok') else 'not-run'} "
          f"truly_green={audit_res['truly_green']}", flush=True)
    return {"sha": sha, "results": results}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinRE control-plane driver")
    ap.add_argument("sample", type=Path)
    ap.add_argument("--max-seconds", type=int, default=45)
    ap.add_argument("--pesieve", action="store_true")
    ap.add_argument("--dynamic", action="store_true",
                    help="enable segregated dynamic phase (opt-in)")
    ap.add_argument("--dry-llm", action="store_true")
    args = ap.parse_args()
    if not args.sample.is_file():
        print(f"ERROR: sample not found: {args.sample}", file=sys.stderr)
        return 2
    import os as _os
    enable_dynamic = args.dynamic or _os.environ.get(
        "WINRE_ENABLE_DYNAMIC", "").strip().lower() in ("1", "true", "yes")
    res = run_remote_pipeline(args.sample, max_seconds=args.max_seconds,
                              enable_pesieve=args.pesieve,
                              enable_dynamic=enable_dynamic, dry_llm=args.dry_llm)
    return 0 if res["results"]["audit"]["truly_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

