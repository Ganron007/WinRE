#!/usr/bin/env python3
r"""pipeline.py — WinRE static+dynamic malware RE pipeline (local-only).

The Windows FlareVM pipeline. Deterministic-first: tools produce evidence,
the LLM (local endpoint) only interprets it. Mirrors RevAI's spine but runs
static AND dynamic on one host and drives debuggers via MCP — the part
RevAI/RevEng cannot do.

Spine (each stage writes logs/<sha>/<stage>/ + META.json):
    1. intake   — hash, format, magic, session record
    2. quick    — deterministic triage: Malcat MCP + IDA/Ghidra SQL
    3. dynamic  — detonation (orchestrator --mode local): FakeNet/Procmon/
                  Frida/pe-sieve + x64dbg OEP dump
    4. deep     — agentic MCP pass: x64dbg (71 tools) / Malcat (45) /
                  WinDbg (10) driven by the LLM via MCP clients
    5. yara     — deterministic YARA + Sigma from evidence
    6. report   — source-tagged report + ANALYST-NEXT
    audit       — truly_green gate (audit.json)

Usage (on FlareVM, fully local):
    python winre/pipeline.py C:\samples\foo.exe --max-seconds 45
    python winre/pipeline.py C:\samples\foo.exe --skip-dynamic --dry-llm
    # env: WINRE_LLM_BASE_URL / WINRE_LLM_API_KEY / WINRE_LLM_MODEL (local)
    #      GHIDRA_HEADLESS_MAXMEM=8G   (16GB host)
    #      WINRE_PIPELINE_LOGS=C:\WinRE\logs
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .evidence import EvidencePack, stage_result, utcnow
from . import audit as audit_mod
from . import yara_gen

# Make `python -m winre.pipeline` work; also allow `python winre/pipeline.py`.
try:
    from . import llm_client
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from winre import llm_client  # type: ignore

LOGS_DIR = Path(os.environ.get("WINRE_PIPELINE_LOGS", r"C:\WinRE\logs"))
SESSIONS_DIR = LOGS_DIR.parent / "sessions"


def _intake(sample: Path, pack: EvidencePack) -> dict:
    t0 = time.time()
    import hashlib
    sha = pack.root.name
    meta = {
        "sha256": sha,
        "file": str(sample),
        "size": sample.stat().st_size,
        "magic": "",
        "format": "pe",
    }
    # magic via file bytes
    try:
        with sample.open("rb") as f:
            head = f.read(5)
        if head[:2] == b"MZ":
            meta["format"] = "pe"
        elif head[:4] == b"\x7fELF":
            meta["format"] = "elf"
        elif head.startswith(b"%PDF"):
            meta["format"] = "pdf"
        else:
            meta["format"] = "unknown"
    except OSError:
        pass
    meta["elapsed_s"] = round(time.time() - t0, 1)
    pack.write("intake", "intake.json", meta)
    pack.write("intake", "META.json", stage_result("intake", True, summary=meta["format"]))
    return meta


def _quick(sample: Path, pack: EvidencePack) -> dict:
    """Deterministic triage: Malcat MCP (if up) + IDA/Ghidra SQL counts."""
    t0 = time.time()
    evidence: dict = {}
    failures: list[str] = []

    # Malcat MCP (best-effort; fail-open)
    try:
        from winre.mcp import MalcatClient
        mc = MalcatClient()
        if mc.is_up():
            r = mc.analyse_file(str(sample))
            if r.get("ok"):
                txt = (r.get("result") or {}).get("text", "")
                try:
                    # analyse_file returns JSON text inside content
                    evidence["malcat"] = json.loads(txt)
                except json.JSONDecodeError:
                    evidence["malcat"] = {"raw": txt[:2000]}
            else:
                failures.append(f"malcat:{r.get('error','')}")
        else:
            evidence["malcat"] = {"skipped": "server not running on :9009"}
    except Exception as e:
        evidence["malcat"] = {"skipped": str(e)}

    # IDA SQL — OPTIONAL. Only if a .i64 already exists AND idasql answers
    # quickly (the -q one-shot path can hang on this idasql build; the
    # reliable path is the HTTP server in the deep dive). Ghidra is the
    # deterministic quick-count source; IDA adds cross-check when healthy.
    i64 = sample.with_suffix(sample.suffix + ".i64")
    if i64.is_file():
        try:
            ida = _run_sql("ida", sample, "SELECT count(*) FROM funcs", timeout=120)
            if ida.get("ok"):
                evidence["ida"] = {"func_count": _first_cell(ida)}
            else:
                evidence["ida"] = {"error": ida.get("error", "")[:80],
                                   "note": "idasql one-shot flaky; use HTTP/deep"}
        except Exception as e:
            evidence["ida"] = {"error": str(e)[:80],
                               "note": "idasql one-shot flaky; use HTTP/deep"}
    else:
        evidence["ida"] = {"skipped": "no .i64 yet (create in deep dive)"}

    # Ghidra SQL (canonical funcs)
    ghidra = _run_sql("ghidra", sample, "@funcs")
    if ghidra.get("ok"):
        evidence["ghidra"] = {"func_rows": len(ghidra.get("rows") or [])}
    else:
        failures.append(f"ghidra:{ghidra.get('error','')[:80]}")
        evidence["ghidra"] = {"error": ghidra.get("error", "")}

    verdict = "malicious" if evidence.get("malcat", {}).get("yara_hits") else "unknown"
    pack.write("quick", "quick.json", {
        "evidence": evidence, "tool_failures": failures, "verdict": verdict,
    })
    malcat_state = "ok" if evidence.get("malcat", {}).get("sha256") else "skip"
    pack.write("quick", "META.json", stage_result(
        "quick", ok=not failures, error=";".join(failures) or None,
        summary=f"malcat={malcat_state} ida={evidence.get('ida',{}).get('func_count')} ghidra={evidence.get('ghidra',{}).get('func_rows')}",
        verdict=verdict, tool_failures=failures,
    ))
    return {"evidence": evidence, "verdict": verdict, "failures": failures}


def _run_sql(engine: str, sample: Path, sql: str, timeout: int | None = None) -> dict:
    """Run one SQL wrapper with its correct CLI, parse JSON output.

    engine: 'ida'  -> tools/flarevm_ida_query.py <db_path> <sql> --json
            'ghidra' -> tools/flare_ghidra_sql.py query <sql> --file <path> --json
    """
    root = Path(__file__).resolve().parents[1]
    if engine == "ida":
        script = root / "tools" / "flarevm_ida_query.py"
        argv = [sys.executable, str(script), str(sample), sql, "--json"]
        timeout = timeout or 900  # first-run .i64 creation can be slow
    else:
        script = root / "tools" / "flare_ghidra_sql.py"
        argv = [sys.executable, str(script), "query", sql,
                "--file", str(sample), "--json"]
        timeout = timeout or 900
    if not script.is_file():
        return {"ok": False, "error": f"missing {script}"}
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                            encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout {timeout}s"}
    if cp.returncode != 0:
        return {"ok": False, "error": (cp.stderr or cp.stdout)[-200:]}
    try:
        return json.loads(cp.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": "non-JSON"}


def _first_cell(result: dict):
    rows = result.get("rows") or []
    if rows and isinstance(rows[0], (list, tuple)) and rows[0]:
        return rows[0][0]
    if rows and isinstance(rows[0], dict):
        return next(iter(rows[0].values()), None)
    return None


def _dynamic(sample: Path, pack: EvidencePack, sha: str,
             max_seconds: int, enable_pesieve: bool) -> dict:
    """Run orchestrator --mode local, copy its dynamic pack into evidence."""
    t0 = time.time()
    orch = Path(__file__).resolve().parent / "orchestrator.py"
    env = os.environ.copy()
    env["WINRE_ORCHESTRATOR_MODE"] = "local"
    env.setdefault("WINRE_ORCH_LOCK", r"C:\WinRE\lock\orchestrator.lock")
    # point orchestrator at our logs so it writes straight into the pack
    env["REVENG_LOGS_DIR"] = str(pack.root.parent)
    env["REVENG_SESSIONS_DIR"] = str(SESSIONS_DIR)
    # write a session so orchestrator finds the sample
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    (SESSIONS_DIR / f"{sha}.json").write_text(json.dumps({
        "sha256": sha, "sample_path": str(sample),
        "file_type": {"format": "pe"},
    }), encoding="utf-8")
    cmd = [sys.executable, str(orch), sha, "--mode", "local",
           "--max-seconds", str(max_seconds)]
    if enable_pesieve:
        cmd.append("--pesieve")
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, env=env,
                            timeout=int(max_seconds) + 600,
                            encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return stage_result("dynamic", False, error="orchestrator timeout",
                            elapsed_s=round(time.time() - t0, 1))
    # orchestrator wrote dynamic/META.json (its own schema). DO NOT clobber it —
    # audit reads THAT file. Write our stage wrapper separately.
    meta = pack.read("dynamic", "META.json") or {}
    ok = bool(meta.get("ok"))
    stage_meta = stage_result("dynamic", ok,
                              error=meta.get("error") or ("" if ok else "no META ok"),
                              summary=f"events={meta.get('frida_events')} ok={ok}",
                              verdict=meta.get("verdict"),
                              elapsed_s=round(time.time() - t0, 1))
    pack.write("dynamic", "STAGE.json", stage_meta)
    return stage_meta


def _deep(sample: Path, pack: EvidencePack, quick: dict, dry_llm: bool = False) -> dict:
    """Agentic deep dive via MCP — driven by the local LLM.

    Best-effort and fail-open: if the LLM or MCP servers are down, we record
    what we could (x64dbg OEP/dump if up) and mark the stage with a fallback
    flag so the audit gate is honest about it.
    """
    t0 = time.time()
    out: dict = {}
    fallback = False
    failures: list[str] = []

    # 1. MCP health probe
    mcp: dict = {}
    try:
        from winre.mcp import MalcatClient, X64DbgClient, WinDbgMCPClient
        mcp["malcat"] = MalcatClient().is_up()
        mcp["x64dbg"] = X64DbgClient().is_up()
        mcp["windbg"] = WinDbgMCPClient().is_up()
    except Exception as e:
        failures.append(f"mcp-probe:{e}")
    out["mcp"] = mcp

    # 2. x64dbg OEP/dump (best-effort, same as orchestrator does post-detonation)
    try:
        from winre.mcp import X64DbgClient
        xc = X64DbgClient()
        if xc.is_up():
            lb = xc.load_binary(str(sample))
            mod = sample.stem
            detect = xc.detect_oep(mod)
            oep = None
            r = detect.get("result") or {}
            if isinstance(r, dict):
                oep = r.get("oep") or r.get("OEP")
            out["x64dbg"] = {"loaded": lb.get("ok"), "oep": oep,
                             "detect_ok": detect.get("ok")}
    except Exception as e:
        failures.append(f"x64dbg:{e}")
        out["x64dbg"] = {"error": str(e)}

    # 3. Malcat deep (decompile top function if available)
    try:
        from winre.mcp import MalcatClient
        mc = MalcatClient()
        if mc.is_up():
            fns = mc.fns_top_list(str(sample), count=5)
            out["malcat_top_fns"] = fns.get("result")
    except Exception as e:
        failures.append(f"malcat:{e}")

    # 4. LLM interpretation (source-tagged). Local endpoint only.
    llm_ok = False
    try:
        if not dry_llm and llm_client.available():
            prompt = _deep_prompt(sample, quick, out)
            text = llm_client.complete(prompt)
            out["llm_analysis"] = {"source": "llm_judge", "text": text[:8000]}
            llm_ok = True
    except Exception as e:
        failures.append(f"llm:{e}")
    if not llm_ok:
        fallback = True
        out["llm_analysis"] = {
            "source": "deterministic_fallback",
            "text": "LLM unavailable; deep dive is evidence-only",
        }

    pack.write("deep", "deep.json", out)
    pack.write("deep", "META.json", stage_result(
        "deep", ok=True, error=None,
        summary=f"mcp={mcp} fallback={fallback}",
        fallback=fallback, tool_failures=failures,
        elapsed_s=round(time.time() - t0, 1)))
    return {"ok": True, "fallback": fallback, "failures": failures, "mcp": mcp}


def _deep_prompt(sample: Path, quick: dict, deep_evidence: dict) -> str:
    q = (quick or {}).get("evidence") or {}
    return (
        "You are a malware analyst. Interpret ONLY the deterministic evidence "
        "below (Windows PE on a FlareVM sandbox). Do not invent behavior; cite "
        "evidence. Give: 1) verdict (malicious/unknown/benign), 2) key behaviors "
        "observed, 3) what is NOT evidenced.\n\n"
        f"sample: {sample.name}\n"
        f"quick: {json.dumps(q, indent=2)[:3000]}\n"
        f"deep mcp: {json.dumps(deep_evidence.get('x64dbg', {}), indent=2)[:1500]}\n"
        f"malcat fns: {json.dumps(deep_evidence.get('malcat_top_fns', {}), indent=2)[:1500]}\n"
    )


def _yara(pack: EvidencePack, quick: dict, dynamic: dict | None) -> dict:
    t0 = time.time()
    try:
        rep = yara_gen.generate_rules(pack.root, pack.stages["yara"])
        pack.write("yara", "META.json", stage_result(
            "yara", True, summary=f"rule={rep.get('rule_id')}",
            rule_id=rep.get("rule_id")))
        return {"ok": True, "rule_id": rep.get("rule_id")}
    except Exception as e:
        pack.write("yara", "META.json", stage_result("yara", False, error=str(e)))
        return {"ok": False, "error": str(e)}


def _report(pack: EvidencePack, sha: str, quick: dict, dynamic: dict | None,
            deep: dict | None) -> dict:
    """Write a source-tagged report + ANALYST-NEXT pointing at next steps."""
    t0 = time.time()
    q = (quick or {}).get("evidence") or {}
    d = dynamic or {}
    report = {
        "sha256": sha,
        "generated_at": utcnow(),
        "source": "llm_judge" if (deep or {}).get("llm_analysis", {}).get("source") == "llm_judge" else "deterministic_fallback",
        "quick": {k: q.get(k) for k in ("ida", "ghidra", "malcat") if k in q},
        "dynamic": {
            "ok": d.get("ok"),
            "frida_events": d.get("frida_events"),
            "verdict": d.get("verdict"),
        },
        "deep": {k: (deep or {}).get(k) for k in ("mcp", "x64dbg") if k in (deep or {})},
        "analyst_next": [
            "Review dynamic artifacts in logs/<sha>/dynamic/ (procmon.csv, pcap)",
            "If packed: x64dbg OEP detect + dump, then Malcat transforms",
            "If network: follow C2 in network_intel.json",
            "Restore FlareVM snapshot after dynamic run",
        ],
    }
    pack.write("report", "report.json", report)
    pack.write("report", "ANALYST-NEXT.md", {
        "md": "\n".join([f"- {a}" for a in report["analyst_next"]]),
    })
    pack.write("report", "META.json", stage_result(
        "report", True, summary=f"source={report['source']}",
        source=report["source"]))
    return report


def run_pipeline(sample: Path, *, max_seconds: int = 45, enable_pesieve: bool = False,
                 skip_dynamic: bool = False, dry_llm: bool = False) -> dict:
    sha = __import__("winre.evidence", fromlist=["sha256_file"]).sha256_file(sample)
    pack = EvidencePack(LOGS_DIR, sha).ensure()
    results: dict = {}

    intake = _intake(sample, pack)
    results["intake"] = intake

    quick = _quick(sample, pack)
    results["quick"] = quick

    dynamic = None
    if not skip_dynamic:
        dynamic = _dynamic(sample, pack, sha, max_seconds, enable_pesieve)
        results["dynamic"] = dynamic

    deep = _deep(sample, pack, quick, dry_llm=dry_llm)
    results["deep"] = deep

    yara = _yara(pack, quick, dynamic)
    results["yara"] = yara

    report = _report(pack, sha, quick, dynamic, deep)
    results["report"] = report

    audit_res = audit_mod.audit(pack.root)
    (pack.root / "audit.json").write_text(
        json.dumps(audit_res, indent=2) + "\n", encoding="utf-8")
    results["audit"] = audit_res

    # summary line
    print(f"[winre-pipeline] {sha[:16]}… "
          f"quick={quick.get('verdict')} dynamic={'ok' if dynamic and dynamic.get('ok') else 'skip'} "
          f"truly_green={audit_res['truly_green']}", flush=True)
    return {"sha": sha, "results": results}


def main() -> int:
    ap = argparse.ArgumentParser(description="WinRE static+dynamic RE pipeline")
    ap.add_argument("sample", type=Path, help="path to sample PE")
    ap.add_argument("--max-seconds", type=int, default=45)
    ap.add_argument("--pesieve", action="store_true")
    ap.add_argument("--skip-dynamic", action="store_true")
    ap.add_argument("--dry-llm", action="store_true",
                    help="never call the LLM (deterministic fallback only)")
    ap.add_argument("--driver", choices=["local", "remote"], default="local",
                    help="local = run on FlareVM itself; remote = control-plane "
                         "driver (SSH to FlareVM + HTTP MCP + local LLM)")
    args = ap.parse_args()
    if not args.sample.is_file():
        print(f"ERROR: sample not found: {args.sample}", file=sys.stderr)
        return 2
    if args.driver == "remote":
        from . import remote_driver
        res = remote_driver.run_remote_pipeline(
            args.sample, max_seconds=args.max_seconds, enable_pesieve=args.pesieve,
            skip_dynamic=args.skip_dynamic, dry_llm=args.dry_llm)
        return 0 if res["results"]["audit"]["truly_green"] else 1
    res = run_pipeline(args.sample, max_seconds=args.max_seconds,
                       enable_pesieve=args.pesieve,
                       skip_dynamic=args.skip_dynamic, dry_llm=args.dry_llm)
    return 0 if res["results"]["audit"]["truly_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
