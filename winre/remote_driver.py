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

from .envfile import load_dotenv  # noqa: F401  (ensures .env is loaded)
from .evidence import EvidencePack, stage_result

REPO = Path(__file__).resolve().parents[1]
LOCAL_LOGS = Path(os.environ.get("WINRE_PIPELINE_LOGS", str(REPO / "logs")))


def flare_cfg() -> dict:
    """Execution-plane connection config. All values from env/.env —
    no lab defaults in code (see .env.template for the full block)."""
    return {
        "host": os.environ.get("FLARE_HOST", ""),
        "user": os.environ.get("FLARE_USER", "FLARE-VM"),
        "key": os.environ.get("FLARE_SSH_KEY",
                              str(Path.home() / ".ssh" / "id_ed25519")),
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


def ssh_ps(cfg: dict, script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a PowerShell script on the VM via -EncodedCommand.

    The ONLY reliable way to send non-trivial PowerShell over SSH — inline
    -Command strings get mangled by the cmd→ssh nesting ($, @, quotes).
    """
    import base64
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return ssh_run(cfg, f"powershell -NoProfile -EncodedCommand {enc}",
                   timeout=timeout)


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
Output: {"evidence": {ghidra: {...}, ida: {...}, malcat: {...}}}

Malcat triage runs HERE on the VM (localhost :9009) — the commercial tool
is optional: absent/down => honest `skipped` annotation, never a failure.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sample = Path(sys.argv[1])
out = {"ghidra": {}, "ida": {}, "malcat": {}}
py = sys.executable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def run(script, *args):
    p = subprocess.run([py, str(script), *args], capture_output=True, text=True,
                       timeout=1800, encoding="utf-8", errors="replace")
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

g_imp = run(tools / "flare_ghidra_sql.py", "query", "@imports", "--file", str(sample), "--json")
if g_imp.get("ok"):
    rows = g_imp.get("rows") or []
    out["ghidra"]["imports"] = [r[0] for r in rows if r][:20]

# Malcat triage (optional commercial): analyse_file for metadata/anomalies/yara.
# The MCP server binds localhost on THIS VM, so the default base is correct.
try:
    sys.path.insert(0, str(tools))
    from malcat_win import MALCAT_BIN_DIR  # type: ignore
    installed = MALCAT_BIN_DIR is not None
except Exception:
    installed = False
if not installed:
    out["malcat"] = {"skipped": "not installed (optional) — Ghidra-primary static path"}
else:
    from winre.mcp import MalcatClient  # noqa: E402 (repo root on sys.path via cwd)
    mc = MalcatClient()
    if mc.is_up():
        r = mc.analyse_file(str(sample))
        if r.get("ok"):
            txt = ""
            res = r.get("result") or {}
            for part in (res.get("content") or []):
                if isinstance(part, dict) and part.get("type") == "text":
                    txt = part.get("text", "")
                    break
            try:
                out["malcat"] = json.loads(txt)
            except json.JSONDecodeError:
                out["malcat"] = {"raw": txt[:2000]}
        else:
            out["malcat"] = {"error": (r.get("error") or "")[:120]}
    else:
        out["malcat"] = {"skipped": "server not running on :9009"}

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
    r = ssh_run(cfg, cmd, timeout=2100)
    evidence: dict = {}
    parsed = False
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            evidence = data.get("evidence") or {}
            parsed = True
        except json.JSONDecodeError:
            pass
    if not evidence:
        evidence = {"ghidra": {"error": (r.stderr or r.stdout)[-200:]}}
    # honesty: ERRORS are tool failures; SKIPS are honest capability gaps
    # (commercial tool absent / no .i64 yet) and must NOT penalize quality
    failed_sources = [k for k, v in evidence.items()
                      if isinstance(v, dict) and v.get("error")]
    tool_failures = [f"{k}:{v.get('error')[:80]}"
                     for k, v in evidence.items()
                     if isinstance(v, dict) and v.get("error")]
    active_sources = [k for k, v in evidence.items()
                      if isinstance(v, dict)
                      and not v.get("error") and not v.get("skipped")]
    ok = parsed and (len(failed_sources) < len(evidence)) and bool(active_sources)

    verdict = "unknown"
    pack.write("quick", "quick.json", {"evidence": evidence, "verdict": verdict,
                                       "tool_failures": tool_failures})
    pack.write("quick", "META.json", stage_result(
        "quick", ok,
        error=None if ok else "quick helper failed or all sources errored",
        summary=f"ghidra={evidence.get('ghidra',{}).get('func_rows')} "
                f"malcat={'yes' if evidence.get('malcat',{}).get('sha256') else 'skip'} "
                f"ida={evidence.get('ida',{}).get('func_count')}",
        verdict=verdict, tool_failures=tool_failures,
        fallback=not ok, elapsed_s=round(time.time() - t0, 1)))
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
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # --- snapshot gate: control plane decides (probe / auto-restore); the
    # VM-side orchestrator does the ATOMIC marker consume at the execution
    # site (its local file op). Control plane never consumes here.
    from . import snapshot_gate
    gate = snapshot_gate.preflight("dynamic", sha=sha, cfg=cfg, consume=False)
    if not gate.get("allowed"):
        return stage_result("dynamic", False, error=gate.get("error"),
                            elapsed_s=round(time.time() - t0, 1),
                            gate=gate.get("gate"))
    py = _remote_py(cfg)
    remote_sample = rf"C:\samples\{sample_name}"
    helper = REPO / "winre" / "_remote_dynamic_helper.py"
    helper.write_text(REMOTE_DYNAMIC_HELPER, encoding="utf-8")
    try:
        scp_to(cfg, helper, rf'{cfg["remote_pipeline"]}\winre\_remote_dynamic_helper.py')
    except Exception as e:
        return stage_result("dynamic", False, error=f"scp helper: {e}",
                            elapsed_s=round(time.time() - t0, 1),
                            gate=gate.get("gate"))

    cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
           f'{cfg["remote_pipeline"]}\\winre\\_remote_dynamic_helper.py '
           f'{sha} "{remote_sample}" {int(max_seconds)}'
           f'{" --pesieve" if enable_pesieve else ""} 2>&1"')
    r = ssh_run(cfg, cmd, timeout=int(max_seconds) + 700)
    # honest RC check: the helper prints RC=<code> as its last line
    helper_rc = None
    for line in reversed((r.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("RC="):
            try:
                helper_rc = int(line[3:])
            except ValueError:
                helper_rc = -1
            break
    job_ran = r.returncode == 0 and helper_rc is not None and helper_rc >= 0

    # delete stale local META BEFORE pull so a failed run can't resurrect
    # a previous run's ok (freshness check below is the second guard)
    stale = pack.stages["dynamic"] / "META.json"
    if stale.exists():
        try:
            stale.unlink()
        except Exception:
            pass

    # pull dynamic dir back
    local_dyn = pack.stages["dynamic"]
    local_dyn.mkdir(parents=True, exist_ok=True)
    ok = False
    err = None
    remote_dyn = rf'{cfg["remote_pipeline"]}\logs\{sha}\dynamic'
    if not job_ran:
        err = (f"detonation did not run: ssh rc={r.returncode} "
               f"helper_rc={helper_rc}; stderr={(r.stderr or '')[:200]}")
    try:
        scp_from(cfg, rf"{remote_dyn}\*", local_dyn)
        ok = True
    except Exception as e:
        if err is None:
            err = str(e)
    meta = pack.read("dynamic", "META.json") or {}
    # freshness: only trust a META produced by THIS run
    fresh = bool(meta) and meta.get("finished_at", "") >= started_at
    gate_mode = snapshot_gate.mode()
    gate_pass = (gate_mode != "enforce") or bool(meta.get("gate_marker_consumed"))
    ok = bool(fresh and meta.get("ok"))
    if not ok and err is None:
        err = ("no fresh META from this run"
               if not fresh else f"orchestrator error: {meta.get('error')}")
    stage_meta = stage_result("dynamic", ok, error=err,
                              summary=f"events={meta.get('frida_events')} ok={ok}",
                              frida_events=meta.get("frida_events"),
                              verdict=meta.get("verdict"),
                              elapsed_s=round(time.time() - t0, 1),
                              gate_pass=gate_pass, gate=gate.get("gate"),
                              helper_rc=helper_rc)
    pack.write("dynamic", "STAGE.json", stage_meta)
    return stage_meta


def malcat_remote_call(name: str, arguments: dict | None = None,
                       timeout: int = 180,
                       method: str = "tools/call") -> dict:
    """Call the VM's Malcat MCP (localhost-bound :9009) via SSH-exec.

    Control-plane-safe transport: the JSON-RPC body is base64'd into a
    `powershell -EncodedCommand` (zero nested-quoting), POSTed to
    http://127.0.0.1:9009/mcp ON the VM, raw JSON printed to stdout.
    Returns the MalcatClient shape: {"ok","result","error","name"}.
    method="tools/list" ignores name/arguments (cheap liveness probe).
    """
    import base64
    import json as _json
    cfg = flare_cfg()
    if method == "tools/list":
        payload: dict = {"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": {}}
    else:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": {"name": name, "arguments": arguments or {}}}
    body = _json.dumps(payload)
    ps = (
        "$ErrorActionPreference='Stop';"
        f"$t={int(timeout)};"
        "$b=[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('"
        + base64.b64encode(body.encode("utf-8")).decode("ascii") + "'));"
        "$r=Invoke-RestMethod -Uri http://127.0.0.1:9009/mcp -Method Post "
        "-ContentType 'application/json' -Body $b -TimeoutSec $t;"
        "$r|ConvertTo-Json -Depth 16 -Compress"
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    try:
        p = ssh_run(cfg, f"powershell -NoProfile -EncodedCommand {enc}",
                    timeout=timeout + 60)
    except Exception as e:
        return {"ok": False, "error": f"ssh-exec malcat failed: {e}",
                "result": None, "name": name}
    if p.returncode != 0:
        return {"ok": False,
                "error": f"malcat remote exit={p.returncode}: "
                         f"{(p.stderr or '')[:300]}",
                "result": None, "name": name}
    try:
        raw = _json.loads(p.stdout)
    except Exception as e:
        return {"ok": False,
                "error": f"malcat remote non-JSON: {e}: "
                         f"{(p.stdout or '')[:200]}",
                "result": None, "name": name}
    if isinstance(raw, dict) and "error" in raw:
        return {"ok": False, "error": str(raw["error"]),
                "result": raw, "name": name}
    res = raw.get("result") if isinstance(raw, dict) else raw
    return {"ok": True, "error": None, "result": res, "name": name}


def malcat_remote_is_up(timeout: int = 20) -> bool:
    """SSH-exec probe: is Malcat MCP answering on the VM's localhost?"""
    r = malcat_remote_call("", None, timeout=timeout, method="tools/list")
    if not r.get("ok"):
        return False
    tools = ((r.get("result") or {}).get("tools")) or []
    return len(tools) > 0


def malcat_installed(cfg: dict | None = None, timeout: int = 30) -> bool:
    """Is Malcat (commercial-optional) present on the VM at all?
    Checks the known bin locations for malcat.mcp.py. 'Not installed' is
    NOT a malfunction - the pipeline degrades to Ghidra-primary."""
    cfg = cfg or flare_cfg()
    script = (
        "@('C:\\Tools\\malcat\\bin', 'C:\\Program Files\\Malcat\\bin', "
        "'C:\\Users\\FLARE-VM\\Downloads\\malcat\\bin') | "
        "Where-Object { Test-Path (Join-Path $_ 'malcat.mcp.py') } | "
        "Select-Object -First 1")
    r = ssh_ps(cfg, script, timeout=timeout)
    return bool((r.stdout or "").strip())


def remote_mcp_health(cfg: dict) -> dict:
    """Probe the VM's MCP servers.

    x64dbg :9094 binds 0.0.0.0 — direct HTTP from this host. Malcat :9009
    and WinDbg :9097 bind 127.0.0.1 on the VM — those go via SSH-exec.
    """
    out = {}
    for name, url in (("x64dbg", "http://{}:9094/"),):
        import urllib.request
        try:
            req = urllib.request.Request(url.format(cfg["host"]), data=b"{}",
                                         method="POST")
            with urllib.request.urlopen(req, timeout=8) as resp:
                out[name] = resp.status == 200
        except Exception:
            out[name] = False
    try:
        out["malcat"] = malcat_remote_is_up()
    except Exception:
        out["malcat"] = False
    try:
        from winre.mcp import WinDbgMCPClient
        out["windbg"] = WinDbgMCPClient(base=f"http://{cfg['host']}:9097/mcp/").is_up()
    except Exception:
        out["windbg"] = False
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
    # commercial-optional: strip Malcat agent tools when Malcat is not
    # installed on the VM (honest degradation, no failures for absence)
    malcat_present = malcat_installed(cfg)
    if not malcat_present:
        mcp["malcat"] = "not-installed"
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
        from winre.agentic import (run_langgraph_deep_dive, TOOL_NAMES)
        names = list(TOOL_NAMES)
        if not malcat_present:
            names = [n for n in names if not n.startswith("malcat_")]
        agent_result = run_langgraph_deep_dive(sample_name, sha or sample_name,
                                               max_steps=10, dry=dry_llm,
                                               dynamic=dynamic,
                                               available_tools=names)
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
        "deep", True, summary=f"mcp={mcp} engine={engine} fallback={fallback}",
        fallback=fallback, tool_failures=failures,
        elapsed_s=round(time.time() - t0, 1)))
    # neat closure: if the agent had debug tools, x64dbg + the sample must
    # not outlive this stage (covers manual single-stage runs; the full
    # pipeline's final sweep is idempotent on top of this)
    if dynamic:
        try:
            from .mcp.x64dbg_manager import teardown, keep_debugger
            if not keep_debugger():
                out["x64dbg_teardown"] = teardown()
        except Exception as e:
            out["x64dbg_teardown"] = {"error": str(e)[:150]}
    # surface the agent block so _report can source-tag correctly
    return {"ok": True, "fallback": fallback, "failures": failures, "mcp": mcp,
            "agent": out.get("agent"), "llm_analysis": out.get("llm_analysis"),
            "x64dbg": out.get("x64dbg")}


def run_remote_pipeline(sample: Path, *, max_seconds: int = 45,
                        enable_pesieve: bool = False, enable_dynamic: bool = False,
                        dry_llm: bool = False,
                        enable_agentic_dbg: bool = False) -> dict:
    """Control-plane pipeline driver: SSH/HTTP to the VM + local LLM + local audit.

    DEFAULT = static-only (quick + deep + yara + report + audit). Dynamic is
    opt-in (enable_dynamic) and runs LAST, segregated, static_yara_wins.
    enable_agentic_dbg is independent: it gives the deep-dive agent the
    bounded x64dbg debug-loop tools (engine langgraph+dbg), without running
    the detonation phase.
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
                                  dynamic=enable_agentic_dbg)

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

    # ---- final tool sweep: nothing keeps running after the pipeline ----
    results["cleanup"] = _final_sweep(cfg, dynamic=enable_dynamic,
                                      debug=enable_agentic_dbg)

    print(f"[winre-remote] {sha[:16]}… quick={results['quick'].get('verdict')} "
          f"dynamic={'ok' if results.get('dynamic',{}).get('ok') else 'not-run'} "
          f"truly_green={audit_res['truly_green']}", flush=True)
    return {"sha": sha, "results": results}


def _final_sweep(cfg: dict, *, dynamic: bool, debug: bool) -> dict:
    """Neat tool closure after a run: no sample, frida helper, or x64dbg GUI
    left alive on the VM. Idempotent, best-effort, never raises. Skipped
    entirely with WINRE_KEEP_DEBUGGER=1 (operator wants the session)."""
    from .mcp.x64dbg_manager import teardown, keep_debugger
    out: dict = {"skipped": keep_debugger()}
    if out["skipped"]:
        return out
    try:
        if debug:
            out["x64dbg"] = teardown()
    except Exception as e:
        out["x64dbg_error"] = str(e)[:150]
    try:
        if dynamic:
            # catch detonation orphans (job-timeout survivors etc.) — the
            # job's own Kill-Stale handles the normal path; this is the net
            images = ["sample.exe", "frida-helper-64.exe", "frida-helper-32.exe",
                      "hollows_hunter.exe", "pe-sieve.exe", "fakenet.exe",
                      "Procmon64.exe"]
            cmd = " & ".join(f"taskkill /F /IM {i} /T 2>nul" for i in images)
            r = ssh_run(cfg, f"{cmd} & exit /b 0", timeout=60)
            out["process_sweep"] = r.returncode == 0
    except Exception as e:
        out["sweep_error"] = str(e)[:150]
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinRE control-plane driver")
    ap.add_argument("sample", type=Path)
    ap.add_argument("--max-seconds", type=int, default=45)
    ap.add_argument("--pesieve", action="store_true")
    ap.add_argument("--dynamic", action="store_true",
                    help="enable segregated dynamic phase (opt-in)")
    ap.add_argument("--agentic-dbg", action="store_true",
                    help="give the deep-dive agent bounded x64dbg tools "
                         "(engine langgraph+dbg; no detonation)")
    ap.add_argument("--dry-llm", action="store_true")
    args = ap.parse_args()
    if not args.sample.is_file():
        print(f"ERROR: sample not found: {args.sample}", file=sys.stderr)
        return 2
    import os as _os
    enable_dynamic = args.dynamic or _os.environ.get(
        "WINRE_ENABLE_DYNAMIC", "").strip().lower() in ("1", "true", "yes")
    enable_agentic_dbg = args.agentic_dbg or _os.environ.get(
        "WINRE_AGENTIC_DBG", "").strip().lower() in ("1", "true", "yes")
    res = run_remote_pipeline(args.sample, max_seconds=args.max_seconds,
                              enable_pesieve=args.pesieve,
                              enable_dynamic=enable_dynamic, dry_llm=args.dry_llm,
                              enable_agentic_dbg=enable_agentic_dbg)
    return 0 if res["results"]["audit"]["truly_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

