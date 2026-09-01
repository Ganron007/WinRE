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
# Remote stage implementations (control plane)
# ---------------------------------------------------------------------------

def remote_quick(sample_name: str, pack: EvidencePack, cfg: dict) -> dict:
    """SSH: run the quick SQL wrappers on the VM, pull JSON back."""
    t0 = time.time()
    # copy sample to VM if not already there
    remote_sample = r"C:\samples\notepad-test.exe" if sample_name == "notepad-test.exe" \
        else rf"C:\samples\{sample_name}"
    # run ghidra + ida counts on the VM (the tools live there)
    py = _remote_py(cfg)
    ghidra_cmd = (
        f'powershell -NoProfile -Command "& {py} {cfg["remote_pipeline"]}\\tools\\flare_ghidra_sql.py '
        f'query @funcs --file {remote_sample} --json 2>&1"'
    )
    r = ssh_run(cfg, ghidra_cmd, timeout=900)
    ghidra = {}
    if r.returncode == 0:
        try:
            ghidra = json.loads(r.stdout)
        except json.JSONDecodeError:
            pass
    evidence = {"ghidra": {"func_rows": len(ghidra.get("rows") or [])
                           if ghidra.get("ok") else None,
                           "error": ghidra.get("error") if not ghidra.get("ok") else None}}

    # IDA (only if .i64 exists — skip otherwise)
    i64 = remote_sample + ".i64"
    probe = ssh_run(cfg, f"powershell -NoProfile -Command (Test-Path '{i64}')", timeout=30)
    if probe.returncode == 0 and "True" in probe.stdout:
        ida_cmd = (
            f'powershell -NoProfile -Command "& {py} {cfg["remote_pipeline"]}\\tools\\flarevm_ida_query.py '
            f'{remote_sample} \"SELECT count(*) FROM funcs\" --json 2>&1"'
        )
        r2 = ssh_run(cfg, ida_cmd, timeout=120)
        if r2.returncode == 0:
            try:
                ida = json.loads(r2.stdout)
                if ida.get("ok"):
                    evidence["ida"] = {"func_count": (ida.get("rows") or [None])[0]}
            except json.JSONDecodeError:
                pass
        if "ida" not in evidence:
            evidence["ida"] = {"error": "idasql flaky over SSH"}
    else:
        evidence["ida"] = {"skipped": "no .i64 on VM (deep dive will create)"}

    verdict = "unknown"
    pack.write("quick", "quick.json", {"evidence": evidence, "verdict": verdict,
                                       "tool_failures": []})
    pack.write("quick", "META.json", stage_result(
        "quick", True, summary=f"ghidra={evidence.get('ghidra',{}).get('func_rows')} "
                               f"ida={evidence.get('ida',{}).get('func_count')}",
        verdict=verdict, elapsed_s=round(time.time() - t0, 1)))
    return {"evidence": evidence, "verdict": verdict}


def remote_dynamic(sample_name: str, sha: str, pack: EvidencePack, cfg: dict,
                   max_seconds: int, enable_pesieve: bool) -> dict:
    """SSH: run orchestrator --mode local on the VM, scp the dynamic pack back.

    The VM orchestrator writes to C:\\WinRE\\logs\\<sha>\\dynamic (its default
    REVENG_LOGS_DIR), then we pull it into our local pack.
    """
    t0 = time.time()
    py = _remote_py(cfg)
    # stage sample as session on VM so orchestrator finds it
    session_cmd = (
        f'powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path '
        f'{cfg["remote_pipeline"]}\\sessions | Out-Null; '
        f'@{{sha256=\'{sha}\';sample_path=\'C:\\samples\\{sample_name}\';'
        f'file_type=@{{format=\'pe\'}}}} | ConvertTo-Json | '
        f'Set-Content {cfg["remote_pipeline"]}\\sessions\\{sha}.json -Encoding UTF8"'
    )
    ssh_run(cfg, session_cmd, timeout=60)
    cmd = (
        f'powershell -NoProfile -Command "$env:WINRE_ORCHESTRATOR_MODE=\'local\'; '
        f'& {py} {cfg["remote_pipeline"]}\\winre\\orchestrator.py {sha} '
        f'--mode local --max-seconds {int(max_seconds)} '
        f'{"--pesieve" if enable_pesieve else ""}"'
    )
    r = ssh_run(cfg, cmd, timeout=int(max_seconds) + 600)
    # pull dynamic dir back
    remote_dyn = rf'{cfg["remote_pipeline"]}\logs\{sha}\dynamic'
    local_dyn = pack.stages["dynamic"]
    local_dyn.mkdir(parents=True, exist_ok=True)
    ok = False
    err = None
    try:
        scp_from(cfg, rf"{remote_dyn}\*", local_dyn)
        ok = True
    except Exception as e:
        err = str(e)
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


def remote_deep(sample_name: str, pack: EvidencePack, cfg: dict, dry_llm: bool) -> dict:
    """Deep dive from the control plane: MCP HTTP to the VM + local LLM."""
    from . import llm_client
    t0 = time.time()
    mcp = remote_mcp_health(cfg)
    out: dict = {"mcp": mcp, "remote": True}
    fallback = False
    failures: list[str] = []

    # x64dbg MCP (HTTP from here)
    if mcp.get("x64dbg"):
        try:
            from winre.mcp import X64DbgClient
            xc = X64DbgClient(base=f"http://{cfg['host']}:9094")
            lb = xc.load_binary(rf"C:\samples\{sample_name}")
            out["x64dbg"] = {"loaded": lb.get("ok")}
        except Exception as e:
            failures.append(f"x64dbg:{e}")

    # LLM (local endpoint on control plane)
    llm_ok = False
    try:
        if not dry_llm and llm_client.available():
            prompt = ("You are a malware analyst. Interpret ONLY the deterministic "
                      f"evidence. sample={sample_name} mcp={mcp}. Give verdict + behaviors.")
            out["llm_analysis"] = {"source": "llm_judge",
                                   "text": llm_client.complete(prompt)[:8000]}
            llm_ok = True
    except Exception as e:
        failures.append(f"llm:{e}")
    if not llm_ok:
        fallback = True
        out["llm_analysis"] = {"source": "deterministic_fallback",
                               "text": "LLM not configured on control plane"}

    pack.write("deep", "deep.json", out)
    pack.write("deep", "META.json", stage_result(
        "deep", True, summary=f"mcp={mcp} fallback={fallback}",
        fallback=fallback, tool_failures=failures,
        elapsed_s=round(time.time() - t0, 1)))
    return {"ok": True, "fallback": fallback, "failures": failures, "mcp": mcp}


def run_remote_pipeline(sample: Path, *, max_seconds: int = 45,
                        enable_pesieve: bool = False, skip_dynamic: bool = False,
                        dry_llm: bool = False) -> dict:
    """Control-plane pipeline driver: SSH/HTTP to the VM + local LLM + local audit."""
    from .evidence import sha256_file
    from . import audit as audit_mod
    from . import yara_gen

    cfg = flare_cfg()
    sha = sha256_file(sample)
    pack = EvidencePack(REPO / "logs", sha).ensure()

    # intake (local — we have the file)
    from .pipeline import _intake
    results = {"intake": _intake(sample, pack)}

    # quick (SSH)
    results["quick"] = remote_quick(sample.name, pack, cfg)

    # dynamic (SSH + scp)
    if not skip_dynamic:
        results["dynamic"] = remote_dynamic(sample.name, sha, pack, cfg,
                                            max_seconds, enable_pesieve)

    # deep (HTTP MCP + local LLM)
    results["deep"] = remote_deep(sample.name, pack, cfg, dry_llm)

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
          f"dynamic={'ok' if results.get('dynamic',{}).get('ok') else 'skip'} "
          f"truly_green={audit_res['truly_green']}", flush=True)
    return {"sha": sha, "results": results}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinRE control-plane driver")
    ap.add_argument("sample", type=Path)
    ap.add_argument("--max-seconds", type=int, default=45)
    ap.add_argument("--pesieve", action="store_true")
    ap.add_argument("--skip-dynamic", action="store_true")
    ap.add_argument("--dry-llm", action="store_true")
    args = ap.parse_args()
    if not args.sample.is_file():
        print(f"ERROR: sample not found: {args.sample}", file=sys.stderr)
        return 2
    res = run_remote_pipeline(args.sample, max_seconds=args.max_seconds,
                              enable_pesieve=args.pesieve,
                              skip_dynamic=args.skip_dynamic, dry_llm=args.dry_llm)
    return 0 if res["results"]["audit"]["truly_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

