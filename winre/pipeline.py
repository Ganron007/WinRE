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

Usage (on FlareVM, fully local) — run as a module from the repo root:
    python -m winre.pipeline C:\samples\foo.exe --max-seconds 45
    python -m winre.pipeline C:\samples\foo.exe --dry-llm
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

from .evidence import (EvidencePack, stage_result, utcnow, verdict_fields,
                       write_execution_plan, resolve_pack_mode,
                       archive_stage_for_fresh_run)
from . import audit as audit_mod
from . import yara_gen
from .findings import build as _build_findings   # analysis plane (DESIGN.md 2)

# Make `python -m winre.pipeline` work; also allow `python winre/pipeline.py`.
try:
    from . import llm_client
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from winre import llm_client  # type: ignore

# THE evidence root, and the single answer to "where do my packs go?".
#
# It used to default to the literal C:\\WinRE\\logs, which is right ONLY
# when this file is running from the FlareVM deploy. Run the same command
# from the operator host - which is what `--driver local` and
# `--publish` do - and packs landed somewhere the console never looks.
# Deriving it from the repo root makes it correct on BOTH machines with
# no configuration: <repo> is C:\\WinRE on the VM and the checkout on the
# host, so this yields C:\\WinRE\\logs there and <checkout>\\logs here.
# WINRE_PIPELINE_LOGS overrides both. Always gitignored.
REPO_ROOT = Path(__file__).resolve().parents[1]
# ONE authority: winre.paths.evidence_root(). Do not derive this locally.
# pipeline, remote_driver and the UI each computed it separately and
# disagreed on a real input (a path with whitespace resolved differently
# in the two), making the UI and the CLI show different packs for the
# same run. docs/internal/DESIGN.md section 6.
from .paths import evidence_root as _evidence_root
LOGS_DIR = _evidence_root()
SESSIONS_DIR = LOGS_DIR.parent / "sessions"


def _intake(sample: Path, pack: EvidencePack) -> dict:
    t0 = time.time()
    import hashlib
    # pack.sha, NOT pack.root.name: a mode-scoped pack root ends in the
    # MODE, so intake.json was recording "sha256": "static" (code audit
    # 2026-10-06).
    sha = pack.sha
    meta = {
        "sha256": sha,
        "file": str(sample),
        "size": None,
        "magic": "",
        "format": "unknown",
    }
    # magic + size via file bytes; unreadable sample = honest unknown
    try:
        with sample.open("rb") as f:
            head = f.read(5)
        meta["size"] = sample.stat().st_size
        if head[:2] == b"MZ":
            meta["format"] = "pe"
        elif head[:4] == b"\x7fELF":
            meta["format"] = "elf"
        elif head.startswith(b"%PDF"):
            meta["format"] = "pdf"
    except OSError as e:
        meta["error"] = f"unreadable: {e}"
        pack.write("intake", "intake.json", meta)
        pack.write("intake", "META.json", stage_result(
            "intake", False, error=meta["error"]))
        return meta
    meta["elapsed_s"] = round(time.time() - t0, 1)
    # sandbox-realism filename policy (Maldev 73 digit-count check): a
    # bare-hash sample name is itself a sandbox tell — record it honestly
    import re as _re
    meta["filename_policy"] = {
        "name": sample.name,
        "hash_named": bool(_re.fullmatch(r"[0-9a-f]{32,64}",
                                         sample.name.split(".")[0])),
        "note": ("keep original human-ish names; never run samples as "
                 "bare-hash files"),
    }
    pack.write("intake", "intake.json", meta)
    pack.write("intake", "META.json", stage_result("intake", True, summary=meta["format"]))
    return meta


def _malcat_installed() -> bool:
    """Commercial-tool awareness: Malcat absent (user opted out) is NOT a
    malfunction. Distinguish 'not installed' from 'installed but down' so
    the free-tools path (Ghidra-primary) stays audit-green."""
    try:
        import sys as _sys
        root = Path(__file__).resolve().parents[1]
        if str(root) not in _sys.path:
            _sys.path.insert(0, str(root))
        from tools.malcat_win import MALCAT_BIN_DIR  # type: ignore
        return MALCAT_BIN_DIR is not None
    except Exception:
        return False


def _quick(sample: Path, pack: EvidencePack) -> dict:
    """Deterministic triage: Malcat MCP (if up) + IDA/Ghidra SQL counts."""
    t0 = time.time()
    evidence: dict = {}
    failures: list[str] = []
    warnings: list[str] = []

    # Malcat MCP (best-effort; commercial-optional)
    #   not installed  -> skipped, NO failure (free-tools path, Ghidra-primary)
    #   installed down -> failure (real malfunction)
    # Full triage views (file + anomalies + yara + strings) — same evidence
    # shape as the remote quick helper. Both paths must match.
    try:
        if not _malcat_installed():
            evidence["malcat"] = {"status": "unavailable",
                                  "reason_code": "commercial_tool_not_installed",
                                  "skipped": "not installed (optional) — "
                                             "Ghidra-primary static path"}
        else:
            from winre.mcp import MalcatClient
            mc = MalcatClient(default_timeout=180)
            if mc.is_up():
                def _m(call):
                    r = call()
                    if not r.get("ok"):
                        return {"error": (r.get("error") or "")[:120]}
                    res = r.get("result") or {}
                    sc = res.get("structuredContent")
                    if sc:
                        return sc
                    txt = ""
                    for part in (res.get("content") or []):
                        if isinstance(part, dict) and part.get("type") == "text":
                            txt = part.get("text", "")
                            break
                    try:
                        return json.loads(txt)
                    except json.JSONDecodeError:
                        return {"raw": txt[:1000]}
                evidence["malcat"] = {
                    "file": _m(lambda: mc.analyse_file(str(sample))),
                    "anomalies": _m(lambda: mc.anomalies_list(str(sample))),
                    "yara_hits": _m(lambda: mc.yara_list(str(sample))),
                    "strings": (_m(lambda: mc.strings_top_list(str(sample), 60))
                                .get("strings") if True else []),
                }
            else:
                evidence["malcat"] = {"status": "unavailable",
                                      "reason_code": "malcat_server_unavailable",
                                      "skipped": "server not running on :9009"}
                warnings.append("malcat:malcat_server_unavailable")
    except Exception as e:
        evidence["malcat"] = {"status": "unavailable",
                              "reason_code": "malcat_probe_failed",
                              "skipped": str(e)[:120]}
        warnings.append(f"malcat:malcat_probe_failed:{str(e)[:80]}")

    # IDA SQL — OPTIONAL. Only if a .i64 already exists AND idasql answers
    # quickly (the -q one-shot path can hang on this idasql build; the
    # reliable path is the HTTP server in the deep dive). Ghidra is the
    # deterministic quick-count source; IDA adds cross-check when healthy.
    # IDA runs EQUALLY: flarevm_ida_query.py auto-creates the .i64 via
    # idat auto-analysis on first use (1500s budget for packed samples).
    i64 = sample.with_suffix(sample.suffix + ".i64")
    try:
        ida = _run_sql("ida", sample, "SELECT count(*) FROM funcs", timeout=1500)
        if ida.get("ok"):
            evidence["ida"] = {"func_count": _first_cell(ida)}
            if not i64.is_file():
                # re-check: creation may have landed during the query
                evidence["ida"]["i64_created"] = True
        else:
            evidence["ida"] = {"error": ida.get("error", "")[:200]}
            warnings.append(f"ida:{(ida.get('error') or 'unavailable')[:80]}")
    except Exception as e:
        evidence["ida"] = {"error": str(e)[:200]}
        warnings.append(f"ida:{str(e)[:80]}")

    # Ghidra SQL (canonical funcs + high-signal imports for YARA)
    ghidra = _run_sql("ghidra", sample, "@funcs")
    gh_ev: dict = {}
    if ghidra.get("ok"):
        gh_ev["func_rows"] = len(ghidra.get("rows") or [])
        gh_ev["status"] = "completed"
        gh_ev["reason_code"] = "completed"
    else:
        failures.append(f"ghidra:{ghidra.get('error','')[:80]}")
        gh_ev["error"] = ghidra.get("error", "")
        gh_ev["status"] = "failed"
        gh_ev["reason_code"] = "ghidra_query_failed"
    ghidra_imp = _run_sql("ghidra", sample, "@imports")
    if ghidra_imp.get("ok"):
        rows = ghidra_imp.get("rows") or []
        gh_ev["imports"] = [r[0] for r in rows if r][:20]
    evidence["ghidra"] = gh_ev

    # RevAI-parity static tools (VM-side subprocess — same surface as the
    # remote quick helper). All tolerate absence.
    try:
        import subprocess as _sp
        tools = Path(__file__).resolve().parents[1] / "tools"
        _sp_out = _sp.run(
            [__import__("sys").executable,
             str(tools / "flare_static_tools.py"), "all", str(sample)],
            capture_output=True, text=True, timeout=2700,
            encoding="utf-8", errors="replace")
        try:
            _st = json.loads(_sp_out.stdout)
        except json.JSONDecodeError:
            _st = {}
        for _k in ("capa", "floss", "diec", "yarascan", "strings",
                   "pe_import_signals", "api_hash_resolver",
                   "xor_string_search"):
            _v = _st.get(_k)
            if isinstance(_v, dict):
                evidence[_k] = _v
        _pe = _st.get("lief")
        if isinstance(_pe, dict):
            evidence["pe"] = _pe
    except Exception as e:
        evidence["static_tools_error"] = str(e)[:120]

    verdict = "malicious" if evidence.get("malcat", {}).get("yara_hits") else "unknown"
    capability_census = {
        "schema": "winre-quick-capability-census/v1",
        "required": ["ghidra"],
        "capabilities": [
            {"tool": "ghidra", "required": True,
             "status": evidence.get("ghidra", {}).get("status", "failed"),
             "reason_code": evidence.get("ghidra", {}).get("reason_code")},
            {"tool": "ida", "required": False,
             "status": "completed" if evidence.get("ida", {}).get("func_count") is not None
                      else "unavailable",
             "reason_code": "completed" if evidence.get("ida", {}).get("func_count") is not None
                           else "optional_cross_check_unavailable"},
            {"tool": "malcat", "required": False,
             "status": "completed" if evidence.get("malcat", {}).get("sha256")
                      else str(evidence.get("malcat", {}).get("status") or "unavailable"),
             "reason_code": evidence.get("malcat", {}).get("reason_code")},
        ],
        "required_failures": failures,
        "optional_warnings": warnings,
    }
    pack.write("quick", "quick.json", {
        "evidence": evidence, "tool_failures": failures,
        "capability_census": capability_census, "verdict": verdict,
    })
    malcat_state = "ok" if evidence.get("malcat", {}).get("sha256") else "skip"
    quick_ok = not failures
    pack.write("quick", "META.json", stage_result(
        "quick", ok=quick_ok, error=";".join(failures) or None,
        summary=f"malcat={malcat_state} ida={evidence.get('ida',{}).get('func_count')} ghidra={evidence.get('ghidra',{}).get('func_rows')}",
        verdict=verdict, tool_failures=failures,
        capability_census=capability_census,
        tool_warnings=warnings,
    ))
    return {"evidence": evidence, "verdict": verdict, "failures": failures,
            "warnings": warnings, "capability_census": capability_census}


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
             max_seconds: int, enable_pesieve: bool,
             adaptive: bool = False,
             idle_stop_seconds: int = 0,
             stop_on: str = "network,file",
             stop_on_settle: int = 20,
             run_id: str | None = None) -> dict:
    """Run orchestrator --mode local, copy its dynamic pack into evidence."""
    t0 = time.time()
    orch = Path(__file__).resolve().parent / "orchestrator.py"
    env = os.environ.copy()
    env["WINRE_ORCHESTRATOR_MODE"] = "local"
    env.setdefault("WINRE_ORCH_LOCK", r"C:\WinRE\lock\orchestrator.lock")
    # logs root (NOT the section): the guest helper keeps a diagnostic
    # logs/_vm_state.json; the authoritative gate ledger stays in the separate
    # control-plane internal/ directory. Dynamic artifacts remain mode-pinned.
    env["REVENG_LOGS_DIR"] = str(pack.root.parent.parent)
    env["REVENG_SESSIONS_DIR"] = str(SESSIONS_DIR)
    # per-run nonce: the local driver verifies the stamp by VALUE too, so a
    # stale META from a previous run can never pass as this run's pack
    from .run_nonce import check as nonce_check, new_run_id
    from .evidence import sha256_file
    import shutil
    run_id = run_id or new_run_id()
    # The producer must not write into the accepted evidence directory. A
    # failed/crashed run can then leave only a run-bound partial directory;
    # it cannot mix stale siblings with a fresh META.
    producer_dir = (pack.root.parent / ".winre-producer" /
                    (pack.mode or "legacy") / run_id / "dynamic")
    suffix = sample.suffix.lower()
    if not suffix or len(suffix) > 10 or not suffix[1:].isalnum():
        suffix = ".bin"
    staged_sample = (pack.root.parent / ".winre-staging" / sha / run_id
                     / f"sample{suffix}")
    session_file = SESSIONS_DIR / "runs" / f"{run_id}.json"
    if producer_dir.exists() or session_file.exists() or staged_sample.exists():
        failed = stage_result("dynamic", False,
                              error="run-specific staging/producer/session path already exists",
                              elapsed_s=round(time.time() - t0, 1), run_id=run_id)
        pack.write("dynamic", "STAGE.json", failed)
        return failed
    try:
        archived = archive_stage_for_fresh_run(pack)
        if not archived.get("ok"):
            raise RuntimeError(archived.get("error") or "archive failed")
        source_hash = sha256_file(sample)
        if source_hash != sha:
            raise RuntimeError("input sample changed after intake identity was computed")
        staged_sample.parent.mkdir(parents=True, exist_ok=False)
        shutil.copy2(sample, staged_sample)
        staged_hash = sha256_file(staged_sample)
        source_after_copy = sha256_file(sample)
        if staged_hash != sha or source_after_copy != sha:
            raise RuntimeError("sample staging hash mismatch or source changed during copy")
        pack.write("intake", "LOCAL-STAGING.json", {
            "schema": "winre.local-staging/v1", "ok": True,
            "run_id": run_id, "sha256": sha,
            "source_path": str(sample.resolve()),
            "staged_path": str(staged_sample.resolve()),
            "staged_sha256": staged_hash,
            "source_sha256_after_copy": source_after_copy,
        })
        # Wrappers are not evidence and may remain when the prior directory
        # contained no payload. Remove them explicitly before this attempt.
        dynamic_dir = pack.stages["dynamic"]
        dynamic_dir.mkdir(parents=True, exist_ok=True)
        for name in ("STAGE.json", "SKIP.json", "META.json", "manifest.json"):
            stale = dynamic_dir / name
            if stale.exists():
                stale.unlink()
        producer_dir.mkdir(parents=True, exist_ok=False)
        session_file.parent.mkdir(parents=True, exist_ok=True)
        session_file.write_text(json.dumps({
            "sha256": sha, "sample_path": str(staged_sample.resolve()),
            "file_type": {"format": "pe"},
        }), encoding="utf-8")
    except Exception as e:
        failed = stage_result("dynamic", False,
                              error=f"dynamic run preparation failed: {type(e).__name__}: {e}",
                              elapsed_s=round(time.time() - t0, 1), run_id=run_id,
                              archived=locals().get("archived"))
        pack.write("dynamic", "STAGE.json", failed)
        try:
            pack.write("intake", "LOCAL-STAGING.json", {
                "schema": "winre.local-staging/v1", "ok": False,
                "run_id": run_id, "sha256": sha,
                "source_path": str(sample),
                "staged_path": str(staged_sample),
                "error": f"{type(e).__name__}: {e}"[:240],
            })
        except Exception:
            pass
        return failed

    env["WINRE_DYNAMIC_DIR"] = str(producer_dir)
    env["WINRE_SESSION_FILE"] = str(session_file)
    env["WINRE_RUN_ID"] = run_id
    cmd = [sys.executable, str(orch), sha, "--sample", str(staged_sample.resolve()),
           "--mode", "local", "--max-seconds", str(max_seconds), "--run-id", run_id]
    if enable_pesieve:
        cmd.append("--pesieve")
    if adaptive:
        cmd += ["--adaptive", "--idle-stop-seconds", str(int(idle_stop_seconds))]
    if stop_on is not None:
        cmd += ["--stop-on", str(stop_on),
                "--stop-on-settle", str(int(stop_on_settle))]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, env=env,
                            timeout=int(max_seconds) + 600,
                            encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        cp = None

    # A completed producer is accepted only when the nonce, sample identity,
    # terminal state and finish marker all agree. A valid but red run is still
    # promotable so its partial capture remains inspectable as current evidence.
    meta_path = producer_dir / "META.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        meta = {}
    nonce = nonce_check(meta, run_id)
    metadata_complete = bool(
        meta.get("sha256") == sha and nonce.get("fresh")
        and not meta.get("running") and meta.get("finished_at"))
    promoted = False
    partial_path = None
    if metadata_complete:
        try:
            target = pack.stages["dynamic"]
            target.mkdir(parents=True, exist_ok=True)
            if any(target.iterdir()):
                raise RuntimeError("canonical dynamic stage is not empty")
            target.rmdir()
            shutil.move(str(producer_dir), str(target))
            promoted = True
        except Exception as e:
            meta["acceptance_error"] = f"producer promotion failed: {type(e).__name__}: {e}"
    if not promoted and producer_dir.exists():
        partial_parent = pack.root / "previous_runs"
        partial_parent.mkdir(parents=True, exist_ok=True)
        partial_dest = partial_parent / f"dynamic_partial_{run_id}"
        try:
            shutil.move(str(producer_dir), str(partial_dest))
            partial_path = str(partial_dest.relative_to(pack.root)).replace("\\", "/")
        except OSError as e:
            meta["preserve_error"] = f"{type(e).__name__}: {e}"
    if session_file.exists():
        try:
            session_file.unlink()
        except OSError:
            pass
    ok = bool(promoted and metadata_complete and meta.get("ok"))
    if cp is None:
        error = "orchestrator timeout"
    elif not metadata_complete:
        error = (meta.get("error") or meta.get("acceptance_error")
                 or nonce.get("reason") or "producer META is incomplete or not terminal")
    else:
        error = meta.get("error") if not ok else ""
    stage_meta = stage_result("dynamic", ok,
                              error=error,
                              summary=f"events={meta.get('frida_events')} ok={ok}",
                              frida_events=meta.get("frida_events"),
                              verdict=meta.get("verdict"),
                              elapsed_s=round(time.time() - t0, 1),
                              gate_pass=meta.get("gate_marker_consumed"),
                              run_id=run_id, nonce=nonce,
                              archived=archived, producer_promoted=promoted,
                              sample_staging={"run_id": run_id,
                                              "sha256": sha,
                                              "staged_path": str(staged_sample),
                                              "staged_sha256": staged_hash},
                              partial_evidence=partial_path,
                              producer_exit=(cp.returncode if cp is not None else None))
    # If no producer was accepted, write only a wrapper for this attempt; old
    # detonation artifacts are already retained under previous_runs/.
    pack.stages["dynamic"].mkdir(parents=True, exist_ok=True)
    pack.write("dynamic", "STAGE.json", stage_meta)
    # ---- the artifact manifest (design §8) ---------------------------------
    # Same contract as remote_driver: written after the pull so it describes what
    # actually arrived, and it is what makes "this run produced no network
    # capture" distinguishable from "the network capture is empty".
    try:
        from . import manifest as _manifest
        stage_meta["manifest"] = _manifest.write_manifest(
            pack.stages["dynamic"], run_id=run_id, sha256=sha,
            mode=pack.mode or "dynamic", meta=meta,
            requested={
                "frida": {"requested": True, "required": True},
                "procmon": {"requested": True, "required": True},
                "network": {"requested": True, "required": True},
                "network_enrichment": {"requested": True, "required": False},
                "memory": {"requested": True, "required": False},
                "process_snapshot": {"requested": True, "required": False},
                "malcat": {"requested": True, "required": False},
                "job": {"requested": True, "required": True},
            })
        pack.write("dynamic", "STAGE.json", stage_meta)
    except Exception as e:
        stage_meta["manifest"] = {"schema": "winre-artifact-manifest/v1",
                                  "ok": False,
                                  "error": f"{type(e).__name__}: {e}"}
    # The VM refused the execution (the local driver has no control-plane
    # preflight: the gate acts inside the orchestrator). Preserve any previous
    # pack rather than leaving stale artifacts beside a record that says there
    # are none (code audit 2026-09-28, HIGH).
    if not ok and "snapshot gate" in str(meta.get("error") or ""):
        from .evidence import (dynamic_skip_record, preserve_dynamic,
                               write_dynamic_skip)
        prev = preserve_dynamic(pack)
        write_dynamic_skip(pack, dynamic_skip_record(
            reason="snapshot_gate_blocked", ok=False,
            error=meta.get("error"),
            summary="blocked by snapshot gate (no detonation ran in this run)",
            preserved_previous=(prev.get("preserved_previous")
                                or (archived or {}).get("preserved_previous")),
            preserved_artifacts=prev.get("preserved_artifacts") or None,
            extra={"gate_mode": meta.get("gate_mode"),
                   "preserve_error": prev.get("preserve_error")}))
    return stage_meta


def _deep(sample: Path, pack: EvidencePack, quick: dict, dry_llm: bool = False,
          mode: str = "agentic", enable_agentic_dbg: bool = False) -> dict:
    """Deep dive — mode selects the engine (same contract either way).

    mode="agentic" (default): LangGraph ReAct agent (RevAI agentic).
    mode="static": deterministic fixed-checklist deep dive, zero LLM calls
        (RevAI scripted). dry_llm is orthogonal: agentic+dry_llm falls back
        honestly; static mode never touches the LLM.
    enable_agentic_dbg: give the deep-dive agent the bounded x64dbg
        debug-loop tools (engine langgraph+dbg; agentic mode only — no
        detonation).

    When running on the FlareVM, the agent calls tools via subprocess
    (local mode — no SSH hop). Same 24-tool registry, same LLM, same
    output contract as remote_deep.

    Best-effort fail-open: if the LLM is unavailable, falls back to
    deterministic_fallback (honest, not green).
    """
    t0 = time.time()
    fallback = False
    failures: list[str] = []

    # build the pack dict for the reporting chain (same shape as remote_deep)
    out: dict = {}

    # MCP health probe (local — Malcat on :9009, x64dbg on :9094)
    mcp: dict = {}
    try:
        from winre.mcp import MalcatClient, X64DbgClient, WinDbgMCPClient
        mcp["malcat"] = MalcatClient().is_up()
        mcp["x64dbg"] = X64DbgClient().is_up()
        mcp["windbg"] = WinDbgMCPClient().is_up()
    except Exception as e:
        failures.append(f"mcp-probe:{e}")
    out["mcp"] = mcp

    # LangGraph agent — local mode (subprocess tools, no SSH)
    agent_result = None
    engine = "static_deterministic" if mode == "static" else (
        "langgraph+dbg" if enable_agentic_dbg else "langgraph")
    try:
        if mode == "static":
            from .static_deep import run_static_deep_dive
            agent_result = run_static_deep_dive(
                sample.name, pack.sha,
                mode="local", quick=quick, sample_path=sample.resolve())
        else:
            from .agentic import run_langgraph_deep_dive, TOOL_NAMES
            agent_result = run_langgraph_deep_dive(
                sample.name, pack.sha,
                max_steps=14, dry=dry_llm,
                dynamic=enable_agentic_dbg,
                mode="local", quick=quick)
        history = []
        for h in (agent_result.get("history") or [])[:80]:
            entry = {"step": h.get("step"), "tool": h.get("tool"),
                     "args": h.get("args"), "error": h.get("error"),
                     "reason": h.get("reason"), "status": h.get("status")}
            res = h.get("result")
            if isinstance(res, dict):
                entry["result"] = res
            history.append(entry)
        out["agent"] = {
            "source": agent_result.get("source"),
            "verdict": agent_result.get("verdict"),
            # WHICH role actually produced the verdict. Dropping it here made
            # deep.json unable to show the routing even though the run knew it
            # (code audit 2026-09-28).
            "verdict_judged_by": agent_result.get("verdict_judged_by"),
            "judgment_pass_error": agent_result.get("judgment_pass_error"),
            "planner_draft": agent_result.get("planner_draft"),
            "debug_run": agent_result.get("debug_run"),
            "format_detection": agent_result.get("format_detection"),
            "llm_analysis": agent_result.get("llm_analysis"),
            "fallback_reason": agent_result.get("fallback_reason"),
            "tool_calls": len(agent_result.get("history") or []),
            "history": history,
            "capability_census": agent_result.get("capability_census"),
            "tool_failures": agent_result.get("tool_failures") or [],
            "packed_signal": agent_result.get("packed_signal"),
            "unpack_prepass": agent_result.get("unpack_prepass"),
            "windbg_dump": agent_result.get("windbg_dump"),
            # which debugger served the unpack (x32dbg vs x64dbg, P1-F1): a
            # wrong flavour makes the OEP fail indistinguishably from a
            # genuine "sample refused to unpack", so the pack must say
            "dbg_ensure": agent_result.get("dbg_ensure"),
            # per-role models actually used (default/planner/judgment) so the
            # routing is verifiable per case, not trusted (RevAI item 7)
            "llm_roles": agent_result.get("llm_roles"),
        }
        # pull the unpack artifact into the pack (VM-local mode: plain copy)
        _pa = (agent_result.get("unpack_prepass") or {})
        if _pa.get("ok") and _pa.get("dump_path"):
            try:
                import shutil as _sh
                _nm = str(_pa["dump_path"]).replace("/", "\\").rsplit("\\", 1)[-1]
                _dd = pack.stages["deep"] / "x64dbg"
                _dd.mkdir(parents=True, exist_ok=True)
                _sh.copy2(_pa["dump_path"], _dd / _nm)
                out["unpack_artifact"] = {"vm": _pa["dump_path"],
                                          "local": f"deep/x64dbg/{_nm}",
                                          "bytes": (_dd / _nm).stat().st_size}
            except Exception as e:
                out["unpack_artifact"] = {"error": f"copy: {str(e)[:150]}"}
    except Exception as e:
        failures.append(f"agent:{e}")
        agent_result = None

    # Capability outcomes are audited the same way for both engines.
    if agent_result:
        out["capability_census"] = agent_result.get("capability_census")
        for _tf in (agent_result.get("tool_failures") or []):
            if _tf not in failures:
                failures.append(_tf)

    if agent_result and agent_result.get("source") in ("llm_judge", "static_deterministic"):
        fallback = False
    else:
        fallback = True
        if not out.get("agent"):
            out["agent"] = {"source": "deterministic_fallback",
                            "text": "agent unavailable on this host"}

    # Verdict contract (RevAI handoff 2026-09-27 item 2): a deep dive that
    # produced NO verdict is not a successful stage. ok is gated on a real
    # verdict, and the flat verdict/source/key_evidence fields are mirrored
    # at the TOP level of deep.json for third-party consumers.
    verdict_obj, verdict_label, no_verdict = verdict_fields(
        (out.get("agent") or {}).get("verdict"))
    out.update({
        "verdict": verdict_label,
        "verdict_obj": verdict_obj,
        "source": (out.get("agent") or {}).get("source"),
        "confidence": (verdict_obj or {}).get("confidence"),
        "key_evidence": (verdict_obj or {}).get("key_evidence") or [],
        "llm_analysis": (out.get("agent") or {}).get("llm_analysis"),
        "tool_failures": failures,
        "capability_census": out.get("capability_census"),
        "no_verdict": no_verdict,
        "llm_roles": (out.get("agent") or {}).get("llm_roles"),
    })
    pack.write("deep", "deep.json", out)
    pack.write("deep", "META.json", stage_result(
        "deep", not no_verdict,
        error=(("deep stage produced no verdict"
                + (f" ({(out.get('agent') or {}).get('fallback_reason')})"
                   if (out.get("agent") or {}).get("fallback_reason") else ""))
               if no_verdict else None),
        summary=f"mcp={mcp} engine={engine} mode={mode} fallback={fallback}",
        engine=engine, mode=mode, fallback=fallback, tool_failures=failures,
        verdict=verdict_label, no_verdict=no_verdict,
        elapsed_s=round(time.time() - t0, 1)))
    return {"ok": not no_verdict, "fallback": fallback, "failures": failures,
            "mcp": mcp, "verdict": verdict_label, "no_verdict": no_verdict,
            "agent": out.get("agent"), "llm_analysis": out.get("llm_analysis")}


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
        # honesty: a rule with no evidence (condition: false) is a fallback,
        # not a success — the audit must see it
        pack.write("yara", "META.json", stage_result(
            "yara", True, summary=f"rule={rep.get('rule_id')}",
            rule_id=rep.get("rule_id"),
            fallback=bool(rep.get("empty_rule")),
            error="empty rule (no evidence)" if rep.get("empty_rule") else None))
        return {"ok": True, "rule_id": rep.get("rule_id"),
                "empty_rule": rep.get("empty_rule")}
    except Exception as e:
        pack.write("yara", "META.json", stage_result("yara", False, error=str(e)))
        return {"ok": False, "error": str(e)}


def _report(pack: EvidencePack, sha: str, quick: dict, dynamic: dict | None,
            deep: dict | None, composition: dict | None = None) -> dict:
    """Write a source-tagged report + ANALYST-NEXT pointing at next steps."""
    t0 = time.time()
    q = (quick or {}).get("evidence") or {}
    d = dynamic or {}
    dp = deep or {}
    # source: langgraph agent (agent.source) OR plain llm_analysis.source
    agent = dp.get("agent") or {}
    llm_analysis = dp.get("llm_analysis") or {}
    source = (agent.get("source") or llm_analysis.get("source")
              or "deterministic_fallback")
    dynamic_ran = bool(d.get("ok"))
    dynamic_findings = d.get("findings") or {}
    dynamic_observed = bool(
        d.get("detonation_ran") is True
        or dynamic_findings.get("run_observed") is True)
    analyst_next = [
        "If packed: x64dbg OEP detect + dump, then Malcat transforms",
        "If network: follow C2 in network_intel.json",
    ]
    if dynamic_ran:
        analyst_next.insert(0, "Review dynamic artifacts (procmon.csv, pcap)")
        analyst_next.append("Restore FlareVM snapshot after dynamic run")
    elif dynamic_observed:
        analyst_next.insert(
            0, "Review the failed dynamic collection and its coverage gaps; "
            "do not promote partial evidence")
        analyst_next.append(
            "Restore FlareVM snapshot before the next sample run")
    phase = ("static+dynamic" if dynamic_ran else
             "static+dynamic-incomplete" if dynamic_observed else
             "static+debugger" if (pack.mode or pack.root.name) == "dbg" else
             "static")
    # The verdict is reproduced IN the report (not only in deep.json): a
    # report whose source is llm_judge but that carries no verdict used to be
    # a silent gap (RevAI handoff 2026-09-27 item 2).
    static_obj, static_label, static_missing = verdict_fields(agent.get("verdict"))
    composite = composition if isinstance(composition, dict) else {}
    composite_label = composite.get("level")
    if composite_label:
        v_label = str(composite_label)
        v_obj = {
            "verdict": v_label,
            "confidence": composite.get("confidence") or "low",
            "summary": ("Selected from current, identity-validated mode findings; "
                        f"deciding mode={composite.get('deciding_mode') or 'none'}."),
            "key_evidence": composite.get("basis") or [],
        }
        no_verdict = False
    else:
        v_obj, v_label, no_verdict = static_obj, static_label, static_missing
    report = {
        "sha256": sha,
        "generated_at": utcnow(),
        # honest source tags: llm_judge / static_deterministic / fallback
        "source": source if source in ("llm_judge", "static_deterministic")
        else "deterministic_fallback",
        "verdict": v_label,
        "verdict_obj": v_obj,
        "static_verdict": static_label,
        "static_verdict_obj": static_obj,
        "composite": composite or None,
        "selected_verdict_source": ("mode-composite" if composite_label
                                     else source),
        "no_verdict": no_verdict,
        "llm_roles": dp.get("llm_roles") or (agent.get("llm_roles")),
        "phase": phase,
        "quick": {k: q.get(k) for k in ("ida", "ghidra", "malcat") if k in q},
        "dynamic": {
            "ok": d.get("ok"),
            "run_observed": dynamic_observed,
            "evidence_complete": dynamic_findings.get(
                "evidence_complete", dynamic_ran),
            "job_timeout": bool(d.get("job_timeout")),
            "error": d.get("error"),
            "frida_events": d.get("frida_events"),
            "verdict": d.get("verdict"),
        },
        "deep": {k: dp.get(k) for k in ("mcp", "agent", "x64dbg")
                 if k in dp and dp.get(k) is not None},
        "analyst_next": analyst_next,
    }
    pack.write("report", "report.json", report)
    pack.write("report", "ANALYST-NEXT.md", {
        "md": "\n".join([f"- {a}" for a in report["analyst_next"]]),
    })
    fallback = report["source"] == "deterministic_fallback"
    pack.write("report", "META.json", stage_result(
        "report", not no_verdict,
        error=("report carries no verdict (deep stage produced none)"
               if no_verdict else None),
        summary=f"source={report['source']} phase={report['phase']} "
                f"verdict={v_label or 'none'}",
        source=report["source"], verdict=v_label, no_verdict=no_verdict,
        fallback=fallback))
    report["ok"] = not no_verdict
    return report


def run_pipeline(sample: Path, *, max_seconds: int = 150, enable_pesieve: bool = False,
                 enable_dynamic: bool = False, dry_llm: bool = False,
                 mode: str = "agentic", enable_agentic_dbg: bool = False,
                 adaptive: bool = False, idle_stop_seconds: int = 10,
                  stop_on: str = "network,file",
                  # referenced by the dynamic call below but never declared:
                  # the dynamic path raised NameError on both of these
                  stop_on_settle: int = 20,
                  run_id: str | None = None) -> dict:
    """Run the WinRE pipeline.

    DEFAULT = STATIC-ONLY (mirrors RevEng/RevAI): intake → quick → deep → yara
    → report → audit. Never detonates. Safe on any host.

    mode: "agentic" (default) = LangGraph ReAct deep dive (RevAI agentic);
          "static" = deterministic deep dive, zero LLM calls (RevAI scripted).
    dry_llm stays orthogonal: agentic+dry_llm = honest deterministic_fallback.
    enable_agentic_dbg: deep agent gets bounded x64dbg tools (langgraph+dbg,
        agentic mode only; no detonation).

    enable_dynamic=True appends a SEGREGATED dynamic phase (detonation) that:
      - runs AFTER static completes (never mid-static — no VM contamination
        of the deep static pass)
      - is env-gated (WINRE_ENABLE_DYNAMIC) — opt-in, never default
      - writes to dynamic/ as corroboration; static_yara_wins (can never
        clear a static malicious verdict)
      - requires snapshot restore after (analyst/operator)
    """
    if enable_dynamic or enable_agentic_dbg:
        message = (
            "local pipeline refuses debug/dynamic execution: the local driver "
            "runs on Flare, so it cannot produce trusted post-execution "
            "analysis. Use --driver remote to keep interpretation on the "
            "control plane.")
        print(f"[winre-pipeline] ABORT: {message}", flush=True)
        return {"sha": None, "aborted": True, "error": message,
                "results": {"error": message}}
    sha = __import__("winre.evidence", fromlist=["sha256_file"]).sha256_file(sample)
# one authority decides which pack root this run owns; dbg and dynamic each
    # own one so no run overwrites another (docs/internal/DESIGN.md 3)
    try:
        pack_mode = resolve_pack_mode(mode, agentic_dbg=enable_agentic_dbg,
                                      dynamic=enable_dynamic)
    except ValueError as e:
        return {"sha": sha, "aborted": True, "error": str(e),
                "results": {"audit": {"truly_green": False,
                                       "aborted": True,
                                       "aborted_reason": str(e)}}}
    from .run_nonce import new_run_id, normalize_run_id
    run_id = normalize_run_id(run_id) if run_id else new_run_id()
    pack = EvidencePack(LOGS_DIR, sha, mode=pack_mode).ensure()
    results: dict = {}
    (pack.root / "META.json").write_text(json.dumps({
        "sha256": sha, "mode": pack_mode, "pack_mode": pack_mode,
        "run_id": run_id, "status": "in_progress",
        "generated_at": utcnow(),
    }, indent=2) + "\n", encoding="utf-8")

    # ---- RUN-LEVEL EXECUTION PLAN (fail fast, before any stage) -----------
    # `enforce` + operator-controlled restore = ONE execution per verified
    # clean state. A run asking for two (--dynamic + --agentic-dbg) used to
    # half-execute and then get refused mid-run; it is now refused up front
    # with one clear message, and the plan is recorded for audit.json
    # (RevAI handoff 2026-09-27 item 1).
    from . import snapshot_gate as _gate
    # Debug-session scope is per RUN, never per process: a long-lived host
    # (the console) that debugged this sha earlier must not be allowed to
    # execute again off a freshly restored, armed snapshot.
    _gate.reset_session()
    # phase 5 (DESIGN.md section 7): every mode invokes guest-side tools. A
    # dirty guest can tamper with those tools even when the sample is not
    # re-executed, so all modes require an operator-attested clean marker.
    from . import vm_gate as _vmgate
    # remote_driver is imported lazily in the other entry point below to
    # avoid a circular import (remote_driver imports pipeline._report), so a
    # module-level import would be wrong too - but the bare reference was an
    # undefined name, so EVERY VM-gate call raised NameError. Import it here.
    from . import remote_driver as _remote_driver
    gate_ok, blocker = _vmgate.require_clean_vm(
        _remote_driver.flare_cfg(), mode=mode,
        agentic_dbg=enable_agentic_dbg, dynamic=enable_dynamic)
    if blocker:
        _vmgate.record_refusal(pack, blocker)
    plan = _gate.execution_plan(dynamic=enable_dynamic, debug=enable_agentic_dbg)
    write_execution_plan(pack, plan, run_id=run_id)
    results["execution_plan"] = plan
    results["vm_gate"] = blocker
    if not gate_ok or not plan.get("ok"):
        _msg = blocker.get("reason") if blocker else plan.get("error")
        print(f"[winre-pipeline] ABORT: {_msg}", flush=True)
        if blocker:
            for _step in blocker.get("how_to_clear") or []:
                print(f"[winre-pipeline]   -> {_step}", flush=True)
        results["aborted"] = True
        results["error"] = _msg
        # An audit must ALWAYS reflect the latest attempt. Without this the
        # previous run's truly_green:true survived a refused run, so the UI
        # and AUDIT-REPORT.md showed a green section whose newest run never
        # executed anything (code audit 2026-09-28, HIGH).
        _aborted_audit = {
            "truly_green": False, "all_green": False, "quality_green": False,
            "aborted": True, "aborted_reason": _msg,
            "run_id": run_id,
            "execution_plan": plan,
            "unmet_expectations": [f"run aborted before any stage: {_msg}"],
            "checks": [], "fallback_stages": [], "failed_tools": [],
            "dynamic_conflict": False, "dynamic_blocked": False,
            "static_yara_wins": True, "static_verdict": None,
            "deep_verdict": None, "deep_verdict_source": None,
            "llm_roles": None, "dynamic_verdict": None,
            "snapshot_gate": {"mode": _gate.mode(),
                              "ok": bool(plan.get("ok")),
                              "detail": plan},
            "vm_gate": blocker,
            "generated_at": utcnow(),
        }
        results["audit"] = _aborted_audit
        (pack.root / "audit.json").write_text(
            json.dumps(_aborted_audit, indent=2) + "\n", encoding="utf-8")
        (pack.root / "META.json").write_text(json.dumps({
            "sha256": sha, "mode": pack_mode, "engine_mode": mode,
            "aborted": True,
            "pack_mode": pack_mode, "run_id": run_id,
            "error": plan.get("error"), "truly_green": False,
            "execution_plan": plan,
            "generated_at": utcnow(),
        }, indent=2) + "\n", encoding="utf-8")
        return {"sha": sha, "results": results, "aborted": True}

    # ---- STATIC phase (default, clean) ----
    intake = _intake(sample, pack)
    results["intake"] = intake

    quick = _quick(sample, pack)
    results["quick"] = quick

    deep = _deep(sample, pack, quick, dry_llm=dry_llm, mode=mode,
                 enable_agentic_dbg=enable_agentic_dbg)
    results["deep"] = deep

    yara = _yara(pack, quick, None)
    results["yara"] = yara

    # ---- DYNAMIC phase (segregated, opt-in, LAST) ----
    dynamic = None
    if not enable_dynamic:
        from .evidence import mark_dynamic_not_requested
        mark_dynamic_not_requested(pack)
    if enable_dynamic:
        # static already complete; detonation runs on (restored) VM now.
        # dynamic is corroboration — do not let it fail static artifacts.
        dynamic = _dynamic(sample, pack, sha, max_seconds, enable_pesieve,
                           adaptive=adaptive,
                           idle_stop_seconds=idle_stop_seconds,
                           stop_on=stop_on, stop_on_settle=stop_on_settle,
                           run_id=run_id)
        results["dynamic"] = dynamic

    # Finalize the current mode's findings before any report or export reads
    # them. The pending candidate is trusted only for this in-process run;
    # other modes must pass persisted run/audit identity checks in compose.
    findings_record = _build_findings(
        pack_mode, pack.root, sha=sha, evidence_dir=pack.stages["dynamic"],
        run_id=run_id)
    results["findings"] = findings_record
    if pack_mode == "dynamic":
        dynamic_stage = pack.read("dynamic", "STAGE.json") or {}
        dynamic_stage["findings"] = findings_record
        dynamic_stage["verdict"] = (findings_record.get("verdict") or {}).get("level")
        pack.write("dynamic", "STAGE.json", dynamic_stage)
    from .compose import compose_for_sample
    composite = compose_for_sample(sha, LOGS_DIR,
                                  pending={pack_mode: findings_record})
    composite["run_id"] = run_id
    (pack.root / "composite.json").write_text(
        json.dumps(composite, indent=2, default=str) + "\n", encoding="utf-8")
    results["composite"] = composite

    report = _report(pack, sha, quick, dynamic, deep, composition=composite)
    results["report"] = report

    # Per-stage manifests must exist before audit consumes collector coverage.
    try:
        from .manifest import write_pack_manifests
        results["artifact_manifests"] = write_pack_manifests(
            pack.root, run_id=run_id, sha256=sha, mode=pack_mode,
            dynamic_requested=enable_dynamic)
    except Exception as e:
        results["artifact_manifests"] = {
            "ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}

    # audit: static truly_green independent of dynamic; dynamic is a note
    audit_res = audit_mod.audit(pack.root, require_dynamic=enable_dynamic)
    (pack.root / "audit.json").write_text(
        json.dumps(audit_res, indent=2) + "\n", encoding="utf-8")
    results["audit"] = audit_res

    # RevAI-contract reporting chain (tools-raw, stage_trace, iocs,
    # REPORT-TECHNICAL-v3.md, AUDIT-REPORT, EVIDENCE-BUNDLE)
    try:
        from .reporting import generate_all
        results["reporting"] = generate_all(pack.root)
    except Exception as e:
        results["reporting"] = {"error": str(e)[:200]}

    # pack-level META: mode/engine/source for UI rows + publish paths
    try:
        _deep_meta = pack.read("deep", "META.json") or {}
        (pack.root / "META.json").write_text(json.dumps({
            "sha256": sha,
            "run_id": run_id,
            "status": "completed",
            "mode": pack_mode,
            "engine": _deep_meta.get("engine"),
            "source": (results.get("report") or {}).get("source"),
            "phase": (results.get("report") or {}).get("phase"),
            "verdict": (composite.get("level")
                        or audit_res.get("selected_verdict")
                        or audit_res.get("static_verdict")),
            "mode_verdict": audit_res.get("static_verdict"),
            "selected_verdict_source": (results.get("report") or {})
                                       .get("selected_verdict_source"),
            "truly_green": audit_res["truly_green"],
            "unmet_expectations": audit_res.get("unmet_expectations") or [],
            "execution_plan": plan,
            "pack_mode": pack_mode,
            # findings for THIS mode. Without this a --driver local run of
            # --mode static produced no findings.json at all, so the
            # dynamic-weighted composite (winre.compose) had nothing to
            # consume and the report said "the analysis plane did not run"
            # when it had simply never been invoked.
            "findings": findings_record,
            "composite": composite,
            "llm_roles": audit_res.get("llm_roles"),
            "generated_at": utcnow(),
        }, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass

    # Refresh the delivered-view manifest after audit, rendered reports and
    # pack META have reached their terminal form.
    try:
        from .manifest import write_pack_manifests
        results["artifact_manifests"] = write_pack_manifests(
            pack.root, run_id=run_id, sha256=sha, mode=pack_mode,
            dynamic_requested=enable_dynamic)
    except Exception as e:
        results["artifact_manifests_final"] = {
            "ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}

    # Export only after reports, audit and pack metadata are final and pinned
    # to this run. The archive manifest then hashes the actual delivered view.
    results["case_pack"] = None
    if dynamic and dynamic.get("ok"):
        try:
            from .casepack import build_case
            results["case_pack"] = build_case(pack.root, sha, pack_mode)
        except Exception as e:
            results["case_pack"] = {"ok": False,
                                    "error": f"case pack: {str(e)[:200]}"}

    # summary line: verdict from the deep/rules engine (quick's verdict is a
    # placeholder on remote runs). "no verdict" is spelled out instead of
    # being printed as a bare `unknown` (RevAI handoff item 6).
    phase = "static"
    if dynamic:
        phase += f"+dynamic({'ok' if dynamic.get('ok') else 'FAIL'})"
    _mode_verdict = audit_res.get("static_verdict")
    if not _mode_verdict:
        _mode_verdict = ("none (deep stage produced no verdict)"
               if any("verdict" in str(u) for u in
                      (audit_res.get("unmet_expectations") or []))
               else "none")
    _selected_verdict = (composite.get("level")
                         or audit_res.get("selected_verdict")
                         or _mode_verdict)
    print(f"[winre-pipeline] {sha} [{phase}] "
          f"verdict={_selected_verdict} mode_verdict={_mode_verdict} "
          f"truly_green={audit_res['truly_green']}", flush=True)
    return {"sha": sha, "pack_mode": pack_mode, "run_id": run_id,
            "verdict": _selected_verdict,
            "results": results}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="WinRE RE pipeline. DEFAULT=static-only (RevEng/RevAI-"
                    "mirror). Dynamic detonation is opt-in & segregated.")
    ap.add_argument("sample", type=Path, help="path to sample PE")
    # RevAI handoff item 9: the 2026-09-11 measurement showed a 45s window
# gives 497 Frida events and no DGA, while 150s gives 694,692 events and
# live HTTP POST C2. The cap is therefore 150s by default and the window
# ends EARLY via the behaviour gate (--stop-on), not by guessing short.
    ap.add_argument("--max-seconds", type=int, default=150,
                    help="dynamic detonation length (when --dynamic)")
    ap.add_argument("--pesieve", action="store_true",
                    help="dynamic: run pe-sieve mid-detonation")
    ap.add_argument("--dynamic", action="store_true",
                    help="ENABLE the segregated dynamic phase (opt-in; "
                         "requires snapshot-restored VM; static_yara_wins)")
    ap.add_argument("--adaptive", action="store_true",
                    help="adaptive detonation window: --max-seconds is the CAP; "
                         "stop the Frida trace early after "
                         "--idle-stop-seconds without new events "
                         "(effective window recorded in dynamic META)")
    ap.add_argument("--stop-on", default="network,file",
                    help="behaviour gate: end the window once the sample "
                         "does something notable and settles again "
                         "(network,file, or api:<ExportName>). Empty "
                         "disables. RevAI handoff item 9.")
    ap.add_argument("--stop-on-settle", type=int, default=20,
                    help="seconds to keep tracing after the gate fires")
    ap.add_argument("--idle-stop-seconds", type=int, default=0,
                    help="OFF by default: a sleeping sample looks idle, so "
                         "this truncates the window before it wakes up"),
    ap.add_argument("--dry-llm", action="store_true",
                    help="never call the LLM (deterministic fallback only)")
    ap.add_argument("--agentic-dbg", action="store_true",
                    help="give the deep-dive agent bounded x64dbg tools "
                         "(engine langgraph+dbg; agentic mode only; "
                         "no detonation)")
    ap.add_argument("--mode", choices=["agentic", "static"], default="agentic",
                    help="deep-dive engine: agentic = LangGraph ReAct (RevAI "
                         "agentic); static = deterministic fixed-checklist, "
                         "zero LLM calls (RevAI scripted)")
    ap.add_argument("--driver", choices=["local", "remote"], default="local",
                    help="local = run on FlareVM itself; remote = control-plane "
                         "driver (SSH to FlareVM + HTTP MCP + local LLM)")
    ap.add_argument("--run-id", default=None,
                    help="parent execution ID (RevAI remote-driver integration)")
    ap.add_argument("--publish", action="store_true",
                    help="publish sanitized case to docs/case-studies/<mode>/<sha>/")
    args = ap.parse_args()
    if not args.sample.is_file():
        print(f"ERROR: sample not found: {args.sample}", file=sys.stderr)
        return 2
    # env-gate: WINRE_ENABLE_DYNAMIC=1 also opts in
    import os as _os
    enable_dynamic = args.dynamic or _os.environ.get("WINRE_ENABLE_DYNAMIC", "").strip().lower() in ("1", "true", "yes")
    enable_agentic_dbg = args.agentic_dbg or _os.environ.get(
        "WINRE_AGENTIC_DBG", "").strip().lower() in ("1", "true", "yes")
    if args.driver == "local" and (enable_dynamic or enable_agentic_dbg):
        print("[winre-pipeline] ABORT: local pipeline refuses debug/dynamic "
              "execution because it runs on Flare and cannot perform trusted "
              "post-execution analysis. Use --driver remote.", file=sys.stderr)
        return 2
    if args.driver == "remote":
        from . import remote_driver
        res = remote_driver.run_remote_pipeline(
            args.sample, max_seconds=args.max_seconds, enable_pesieve=args.pesieve,
            enable_dynamic=enable_dynamic, dry_llm=args.dry_llm,
            enable_agentic_dbg=enable_agentic_dbg,
            mode=args.mode,
            adaptive=args.adaptive,
            idle_stop_seconds=args.idle_stop_seconds,
            stop_on=args.stop_on,
            stop_on_settle=args.stop_on_settle,
            run_id=args.run_id)
        if res.get("aborted"):
            return 2   # fail fast before anything executed
        if args.publish:
            from .reporting import publish_case
            from .evidence import EvidencePack as _EP
            pub = publish_case(_EP(LOGS_DIR, res["sha"],
                           mode=res.get("pack_mode") or args.mode).root,
                               mode=res.get("pack_mode") or args.mode)
            print(f"[winre-pipeline] published {pub['dest']}", flush=True)
        return 0 if res["results"]["audit"]["truly_green"] else 1
    res = run_pipeline(args.sample, max_seconds=args.max_seconds,
                       enable_pesieve=args.pesieve,
                       enable_dynamic=enable_dynamic, dry_llm=args.dry_llm,
                       enable_agentic_dbg=enable_agentic_dbg,
                       mode=args.mode,
                       adaptive=args.adaptive,
                       idle_stop_seconds=args.idle_stop_seconds,
                       stop_on=args.stop_on,
                       stop_on_settle=args.stop_on_settle,
                       run_id=args.run_id)
    if res.get("aborted"):
        return 2   # fail fast before anything executed
    if args.publish:
        from .reporting import publish_case
        pub = publish_case(EvidencePack(LOGS_DIR, res["sha"],
                                        mode=res.get("pack_mode") or args.mode).root,
                           mode=res.get("pack_mode") or args.mode)
        print(f"[winre-pipeline] published {pub['dest']}", flush=True)
    return 0 if res["results"]["audit"]["truly_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
