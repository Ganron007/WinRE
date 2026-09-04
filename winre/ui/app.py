#!/usr/bin/env python3
"""app.py — WinRE UI console (control plane).

Serves the WinRE dashboard + pipeline runner + evidence browser + MCP probe.
Runs on the OPERATOR HOST (where the LLM/network lives) and drives the
FlareVM execution plane through winre/remote_driver (SSH + HTTP MCP).

Runs WITHOUT an LLM too: the deterministic spine works; deep/report show
`source: deterministic_fallback` and the audit gate stays honest.

Run:
    python winre/ui/app.py --port 5001
    # env: FLARE_HOST/FLARE_USER/FLARE_SSH_KEY (SSH to VM)
    #      WINRE_LLM_BASE_URL / WINRE_LLM_API_KEY (LLM, optional)
    #      WINRE_PIPELINE_LOGS (local evidence root)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

try:
    from flask import Flask, render_template, request, jsonify, redirect
except ImportError:
    print("ERROR: flask not installed (pip install flask)", file=sys.stderr)
    sys.exit(1)

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from winre import remote_driver  # noqa: E402
from winre.remote_driver import flare_cfg  # noqa: E402

# Evidence packs live on the control plane (pulled by remote driver)
LOGS_DIR = Path(remote_driver.LOCAL_LOGS)

# A single run at a time (deterministic; avoid VM stampede)
_run_lock = threading.Lock()
_run_state: dict = {"running": False, "last": None, "pid": None,
                    "sha": None, "log": []}


def _run_log_tail(n: int = 60) -> list[str]:
    return list(_run_state.get("log") or [])[-n:]


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _pack_verdicts(root: Path) -> dict:
    """quick/deep verdicts + deep source/engine for a pack row (tolerant)."""
    out: dict = {"quick": None, "deep": None, "source": None, "engine": None}
    quick = _read_json(root / "quick" / "quick.json") or {}
    if isinstance(quick.get("verdict"), str):
        out["quick"] = quick["verdict"]
    deep = _read_json(root / "deep" / "deep.json") or {}
    if isinstance(deep.get("engine"), str):
        out["engine"] = deep["engine"]
    agent = deep.get("agent") if isinstance(deep.get("agent"), dict) else None
    if agent:
        v = agent.get("verdict")
        out["deep"] = v.get("verdict") if isinstance(v, dict) else (v if isinstance(v, str) else None)
        if isinstance(agent.get("source"), str):
            out["source"] = agent["source"]
    return out


def _packs() -> list[dict]:
    """List evidence packs (newest first) with audit summaries + verdicts."""
    out = []
    if not LOGS_DIR.is_dir():
        return out
    for d in sorted(LOGS_DIR.iterdir(), key=lambda p: p.stat().st_mtime,
                    reverse=True):
        if not d.is_dir():
            continue
        audit = None
        a = d / "audit.json"
        if a.is_file():
            audit = _read_json(a)
        out.append({
            "sha": d.name,
            "short": d.name[:16],
            "mtime": d.stat().st_mtime,
            "audit": audit,
            "verdicts": _pack_verdicts(d),
        })
    return out


def _pack_detail(sha: str) -> dict | None:
    if not _valid_sha(sha):
        return None
    d = LOGS_DIR / sha
    if not d.is_dir():
        return None
    detail = {"sha": sha, "short": sha[:16], "stages": {}}
    for stage in ("intake", "quick", "dynamic", "deep", "yara", "report"):
        sd = d / stage
        files = {}
        if sd.is_dir():
            for f in sorted(sd.iterdir()):
                if f.is_file() and f.suffix in (".json", ".md", ".yar", ".yml", ".csv"):
                    try:
                        if f.suffix == ".json":
                            files[f.name] = json.loads(f.read_text(
                                encoding="utf-8", errors="replace"))
                        elif f.suffix == ".md":
                            files[f.name] = f.read_text(encoding="utf-8",
                                                        errors="replace")[:4000]
                        else:
                            files[f.name] = f.read_text(
                                encoding="utf-8", errors="replace")[:2000]
                    except Exception:
                        files[f.name] = {"error": "unreadable"}
        detail["stages"][stage] = files
    detail["views"] = _pack_views(d, detail["stages"])
    return detail


def _analyst_next_html(md_path: Path) -> str:
    """ANALYST-NEXT.md may be JSON {"md": ...} or raw markdown. Render HTML.

    XSS-safe: the source text derives from LLM output and sample-controlled
    strings (mutexes, URLs, file names from malware). HTML-escape FIRST so
    raw markup can never survive into the rendered page, then markdown it.
    """
    import html as _html
    try:
        raw = md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    text = raw
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and isinstance(data.get("md"), str):
            text = data["md"]
    except json.JSONDecodeError:
        pass
    text = _html.escape(text)
    try:
        import markdown as _md
        return _md.markdown(text)
    except Exception:
        return "<pre>" + text + "</pre>"


def _pack_views(root: Path, files: dict) -> dict:
    """Designed per-stage view models (parsed data, not raw dumps)."""
    v: dict = {}
    get = lambda st, fn: (files.get(st) or {}).get(fn)

    # intake — fact chips
    intake = get("intake", "intake.json") or {}
    v["intake"] = {
        "chips": [(k, intake.get(k)) for k in
                  ("sha256", "size", "format", "magic", "elapsed_s")
                  if intake.get(k) not in (None, "")] or None,
        "file": intake.get("file"),
        "meta": get("intake", "META.json"),
    }

    # quick — verdict card + evidence
    quick = get("quick", "quick.json") or {}
    ev = quick.get("evidence") if isinstance(quick, dict) else None
    v["quick"] = {
        "verdict": quick.get("verdict") if isinstance(quick, dict) else None,
        "evidence": ev if isinstance(ev, dict) else None,
        "failures": (quick.get("tool_failures") if isinstance(quick, dict) else None) or [],
        "meta": get("quick", "META.json"),
        "missing": not bool(quick),
    }

    # dynamic — detonation summary
    dyn_meta = get("dynamic", "META.json")
    stg = get("dynamic", "STAGE.json")
    fr = get("dynamic", "frida_summary.json") or {}
    pm = get("dynamic", "procmon_summary.json") or {}
    net = get("dynamic", "network.json") or {}
    ni = get("dynamic", "network_intel.json") or {}
    caps = []
    if isinstance(ni, dict):
        for cap in (ni.get("captures") or [])[:4]:
            caps.append({
                "pcap": cap.get("pcap"),
                "counts": cap.get("counts") or {},
                "dns": (cap.get("dns_queries") or [])[:15],
                "http": (cap.get("http_requests") or [])[:10],
                "sni": (cap.get("tls_sni") or [])[:10],
            })
    arts = []
    ddir = root / "dynamic"
    if ddir.is_dir():
        for f in sorted(ddir.iterdir()):
            if f.is_file():
                arts.append({"name": f.name, "size": f.stat().st_size,
                             "big": f.stat().st_size > 65536})
    v["dynamic"] = {
        "ran": bool(dyn_meta),
        "meta": dyn_meta, "stage": stg,
        "frida": {"calls": fr.get("calls"),
                  "top_apis": (fr.get("top_apis") or [])[:12],
                  "decoded_paths": (fr.get("decoded_paths") or [])[:10],
                  "sockaddrs": (fr.get("sockaddrs") or [])[:10]} if fr.get("status") == "ok" else None,
        "procmon": {"rows_total": pm.get("rows_total"),
                    "rows_sample": pm.get("rows_sample"),
                    "top_operations": (pm.get("top_operations") or [])[:12],
                    "top_paths": (pm.get("top_paths") or [])[:10],
                    "top_registry": (pm.get("top_registry") or [])[:10],
                    "process_creates": (pm.get("process_creates") or [])[:10]} if pm.get("status") == "ok" else None,
        "network": {"pcaps": net.get("pcaps") or [],
                    "domains": (net.get("domains_guess") or [])[:20],
                    "captures": caps} if net else None,
        "artifacts": arts,
        "sha": root.name,
    }

    # deep — agent card + timeline + mcp (reuses existing agent block;
    # deep.json already carries agent {source, verdict, llm_analysis,
    # tool_calls, history})
    dj = get("deep", "deep.json") or {}
    agent = dj.get("agent") if isinstance(dj, dict) else None
    hist = (agent.get("history") or []) if isinstance(agent, dict) else []
    v["deep"] = {
        "agent": agent if isinstance(agent, dict) else None,
        "history": hist[:60],
        "mcp": dj.get("mcp") if isinstance(dj, dict) else None,
        "engine": dj.get("engine") if isinstance(dj, dict) else None,
        "meta": get("deep", "META.json"),
    }

    # yara — rules + lineage
    rr = get("yara", "rule_report.json") or {}
    yar_files = []
    ydir = root / "yara"
    if ydir.is_dir():
        for f in sorted(ydir.iterdir()):
            if f.is_file() and f.suffix in (".yar", ".yml"):
                try:
                    yar_files.append({
                        "name": f.name, "size": f.stat().st_size,
                        "head": f.read_text(encoding="utf-8",
                                            errors="replace")[:1500],
                    })
                except OSError:
                    continue
    v["yara"] = {"report": rr if isinstance(rr, dict) else None,
                 "rules": yar_files, "sha": root.name}

    # report — analyst-next markdown + summary
    rep = get("report", "report.json") or {}
    md_html = _analyst_next_html(root / "report" / "ANALYST-NEXT.md")
    v["report"] = {"report": rep if isinstance(rep, dict) else None,
                   "analyst_next_html": md_html}

    # audit — gate checklist
    audit = _read_json(root / "audit.json") or {}
    v["audit"] = {
        "truly_green": audit.get("truly_green"),
        "all_green": audit.get("all_green"),
        "quality_green": audit.get("quality_green"),
        "checks": audit.get("checks") or [],
        "fallback_stages": audit.get("fallback_stages") or [],
        "failed_tools": audit.get("failed_tools") or [],
        "dynamic_conflict": audit.get("dynamic_conflict"),
    }
    return v


_vm_health_cache: dict = {"t": 0.0, "data": None}
_VM_HEALTH_TTL = 20.0  # seconds — reloads are instant; health refreshes slowly
_llm_cache: dict = {"t": 0.0, "value": False}
_LLM_TTL = 120.0  # LLM endpoint rarely changes mid-session; avoid a chat call per refresh

# (name, url, timeout_s): LAN servers answer in ms; dead ports cost one
# TCP retransmit (~2s) as the SYN is dropped — keep the cap tight.
_MCP_ENDPOINTS = (("x64dbg", "http://{}:9094/", 1.5),
                  ("malcat", "http://{}:9009/mcp", 1.5),
                  ("windbg", "http://{}:9097/mcp/", 1.5))


def _llm_cached() -> bool:
    now = time.time()
    if now - _llm_cache["t"] < _LLM_TTL:
        return _llm_cache["value"]
    try:
        from winre import llm_client
        v = bool(llm_client.available())
    except Exception:
        v = False
    _llm_cache.update({"t": now, "value": v})
    return v


def _vm_health_cached() -> dict:
    """Last known health, or neutral defaults — never probes, never blocks.

    Used for instant page renders; the browser then fetches /health (which
    probes + warms the cache) and updates badges via JS.
    """
    if _vm_health_cache["data"]:
        return _vm_health_cache["data"]
    return {"ssh": False, "error": None, "mcp": {}, "llm": False,
            "logs_dir": str(LOGS_DIR), "stale": True}


def _vm_health() -> dict:
    """Fast health probe: parallel SSH + MCP checks, cached for a few seconds.

    A page load must never block on a slow/unreachable VM — the probes run in
    threads with short timeouts and the result is cached (5s TTL).
    """
    now = time.time()
    if _vm_health_cache["data"] and now - _vm_health_cache["t"] < _VM_HEALTH_TTL:
        return _vm_health_cache["data"]

    out: dict = {"ssh": False, "error": None, "mcp": {}, "llm": False,
                 "logs_dir": str(LOGS_DIR)}
    results: dict = {}

    def _probe_ssh():
        cfg = flare_cfg()
        try:
            r = remote_driver.ssh_run(cfg, "echo WINRE_UI_OK", timeout=6)
            results["ssh"] = r.returncode == 0 and "WINRE_UI_OK" in (r.stdout or "")
        except Exception as e:
            results["ssh"] = False
            results["ssh_error"] = str(e)[:200]

    def _probe_mcp():
        cfg = flare_cfg()
        mcp: dict = {}
        lock = threading.Lock()

        def _one(name: str, url: str, timeout_s: float):
            try:
                req = urllib.request.Request(url.format(cfg["host"]), data=b"{}",
                                             method="POST")
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    ok = resp.status == 200
            except Exception:
                ok = False
            with lock:
                mcp[name] = ok

        ts = [threading.Thread(target=_one, args=(n, u, t), daemon=True)
              for n, u, t in _MCP_ENDPOINTS]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=3)
        # anything still missing after the cap counts as down
        for n, _, _ in _MCP_ENDPOINTS:
            mcp.setdefault(n, False)
        results["mcp"] = mcp

    def _probe_llm():
        results["llm"] = _llm_cached()

    threads = [threading.Thread(target=f, daemon=True) for f in
               (_probe_ssh, _probe_mcp, _probe_llm)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=8)  # hard cap on page-load probe time

    out.update(results)
    _vm_health_cache.update({"t": now, "data": out})
    return out


# Actual execution order in run_remote_pipeline: static first, dynamic LAST
# (opt-in; absent in static-only runs). Used for run-page stage display.
STAGE_ORDER = ("intake", "quick", "deep", "dynamic", "yara", "report")


def _valid_sha(sha: str) -> bool:
    """64-hex only - every sha-taking route joins paths with it."""
    import re as _re
    return bool(_re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""))


def _current_stage(sha: str | None) -> str | None:
    """Which stage is the running pipeline currently in (from landed META)."""
    if not sha:
        return None
    root = LOGS_DIR / sha
    if not root.is_dir():
        return "intake"
    landed = {s for s in STAGE_ORDER
              if (root / s / "META.json").is_file()
              or (root / s / "STAGE.json").is_file()}
    for s in STAGE_ORDER:
        if s not in landed:
            # dynamic is optional: skip it for static-only runs
            if s == "dynamic" and "deep" in landed and \
                    not (root / "dynamic" / "STAGE.json").is_file() and \
                    (root / "deep" / "META.json").is_file():
                continue
            return s
    return STAGE_ORDER[-1]


def _stage_timings(sha: str | None) -> dict:
    """elapsed_s per landed stage (from META.json) for the run timeline."""
    if not sha or not _valid_sha(sha):
        return {}
    root = LOGS_DIR / sha
    out = {}
    for stage in STAGE_ORDER:
        for name in ("META.json", "STAGE.json"):
            m = _read_json(root / stage / name) or {}
            if m.get("elapsed_s") is not None:
                out[stage] = m["elapsed_s"]
                break
    return out


def _run_pipeline_in_thread(sample_path: str, max_seconds: int,
                            pesieve: bool, dry_llm: bool, dynamic: bool,
                            agentic_dbg: bool = False) -> None:
    """Run the remote pipeline in a background thread; store the result."""
    import contextlib
    import datetime
    import io
    import traceback

    def _do():
        with _run_lock:
            _run_state["running"] = True
            _run_state["log"] = []
            # set sha up-front so /run/status can report live stage progress
            try:
                from winre.evidence import sha256_file
                _run_state["sha"] = sha256_file(Path(sample_path))
            except Exception:
                pass

            def _emit(line: str):
                _run_state["log"].append(line.rstrip())
                if len(_run_state["log"]) > 400:
                    _run_state["log"] = _run_state["log"][-400:]

            class _Tee(io.TextIOBase):
                """Captures into the ring log AND forwards to the real
                stdout — never swallow other threads' output, and never
                leave a dead stream behind if a handler binds stderr."""

                def __init__(self, real):
                    self._real = real

                def write(self, s):
                    for ln in str(s).splitlines():
                        _emit(ln)
                    try:
                        self._real.write(str(s))
                        self._real.flush()
                    except Exception:
                        pass
                    return len(s)

                def flush(self):
                    try:
                        self._real.flush()
                    except Exception:
                        pass

                def isatty(self):
                    return False

            # capture pipeline stdout into the in-memory ring log
            real_out, real_err = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = _Tee(real_out)
            try:
                started = datetime.datetime.now(datetime.timezone.utc).isoformat()
                res = remote_driver.run_remote_pipeline(
                    Path(sample_path), max_seconds=max_seconds,
                    enable_pesieve=pesieve, enable_dynamic=dynamic,
                    dry_llm=dry_llm, enable_agentic_dbg=agentic_dbg)
                _run_state["sha"] = res["sha"]
                _run_state["last"] = {"ok": True, "sha": res["sha"],
                                      "started": started,
                                      "audit": res["results"]["audit"]}
            except Exception as e:
                print("[winre-ui] run failed:", traceback.format_exc(), flush=True)
                _run_state["last"] = {"ok": False, "error": str(e)}
            finally:
                sys.stdout, sys.stderr = real_out, real_err
                _run_state["running"] = False

    t = threading.Thread(target=_do, daemon=True)
    _run_state["pid"] = t
    t.start()


def create_app() -> "Flask":
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    @app.context_processor
    def _inject_health():
        """Instant health for every template (cached, never probes).

        The browser fetches /health after paint and updates badges via JS,
        so navigation is never blocked by probe latency.
        """
        return {"health": _vm_health_cached()}

    @app.route("/")
    def index():
        pk = _packs()
        greens = sum(1 for p in pk if p.get("audit") and p["audit"].get("truly_green"))
        return render_template("index.html", packs=pk, greens=greens,
                               health=_vm_health_cached(),
                               state={k: _run_state[k] for k in
                                      ("running", "last")})

    @app.route("/health")
    def health():
        return jsonify(_vm_health())

    # --- Snapshot gate (L1 marker / L2 hypervisor / L3 ledger) -------------

    @app.route("/api/gate")
    def api_gate():
        """Live gate picture: mode, marker probe, ledger, blocked?."""
        from winre import snapshot_gate
        try:
            return jsonify(snapshot_gate.gate_status())
        except Exception as e:
            return jsonify({"mode": "observe", "marker": None,
                            "vm_state": {}, "ledger_clean": False,
                            "hypervisor": None, "blocked": False,
                            "reason": f"probe error: {e}"}), 200

    @app.route("/api/gate/attest", methods=["POST"])
    def api_gate_attest():
        """HITL attestation: {"action": "restored"|"verified_clean", "sha"?}.

        `verified_clean` is marker-verified server-side (L1) — a false claim
        is refused. Single-use: the next execution dirties the ledger.
        """
        from winre import snapshot_gate
        body = request.get_json(force=True, silent=True) or {}
        r = snapshot_gate.attest((body.get("action") or "").strip(),
                                 sha=(body.get("sha") or "").strip())
        return jsonify(r), (200 if r.get("ok") else 400)

    @app.route("/run", methods=["GET", "POST"])
    def run():
        if request.method == "POST":
            # admission is atomic: check+reserve under the lock so two rapid
            # POSTs can't both spawn pipelines (execution still serializes)
            with _run_lock:
                if _run_state["running"]:
                    return jsonify({"ok": False,
                                    "error": "pipeline already running"}), 409
                _run_state["running"] = True  # reserved; thread keeps it true
            try:
                sample = request.form.get("sample", "").strip()
                if not sample or not Path(sample).is_file():
                    return jsonify({"ok": False,
                                    "error": f"sample not found: {sample}"}), 400
                try:
                    max_seconds = max(10, min(600,
                                              int(request.form.get("max_seconds", 45))))
                except ValueError:
                    max_seconds = 45
                pesieve = request.form.get("pesieve") == "on"
                dry_llm = request.form.get("dry_llm") == "on"
                dynamic = request.form.get("dynamic") == "on"
                agentic_dbg = request.form.get("agentic_dbg") == "on"
                _run_state["sha"] = None
                _run_state["log"] = []
                _run_state["last"] = None
                _run_pipeline_in_thread(sample, max_seconds, pesieve, dry_llm,
                                        dynamic, agentic_dbg)
                # form POST: redirect back so the browser lands on the live
                # progress board instead of a raw JSON body
                return redirect("/run", 303)
            except Exception:
                with _run_lock:
                    _run_state["running"] = False  # release the reservation
                raise
        return render_template("run.html", running=_run_state["running"],
                               last=_run_state["last"])

    @app.route("/run/status")
    def run_status():
        sha = _run_state.get("sha")
        return jsonify({"running": _run_state["running"],
                        "last": _run_state["last"],
                        "sha": sha,
                        "current_stage": _current_stage(sha) if _run_state["running"] else None,
                        "stage_timings": _stage_timings(sha) if sha else {}})

    @app.route("/api/run/log")
    def run_log():
        """Capped tail of the running (or last) pipeline log."""
        try:
            n = max(10, min(200, int(request.args.get("n", "60"))))
        except ValueError:
            n = 60
        return jsonify({"running": _run_state["running"],
                        "sha": _run_state.get("sha"),
                        "lines": _run_log_tail(n)})

    # --- Manual stage control (RevAI ManualStages equivalent) --------------

    MANUAL_STAGES = ("quick", "dynamic", "deep", "yara", "report", "audit")

    def _stage_sample(pack_root: Path) -> str | None:
        """Sample name on the VM for a pack (basename of intake file)."""
        intake = _read_json(pack_root / "intake" / "intake.json") or {}
        f = intake.get("file") or ""
        name = f.replace("\\", "/").rstrip("/").split("/")[-1]
        return name or None

    @app.route("/api/hitl/snapshot", methods=["POST"])
    def hitl_snapshot():
        """HITL snapshot ledger: {"sha","action":"verified_clean"|"restored"}."""
        from winre.evidence import EvidencePack
        body = request.get_json(force=True, silent=True) or {}
        sha = (body.get("sha") or "").strip()
        action = (body.get("action") or "").strip()
        if action not in ("verified_clean", "restored") or not _valid_sha(sha):
            return jsonify({"ok": False, "error": "need sha + action"}), 400
        root = LOGS_DIR / sha
        if not root.is_dir():
            return jsonify({"ok": False, "error": "pack not found"}), 404
        import datetime
        p = root / "snapshot.json"
        cur = _read_json(p) or {}
        cur[action] = True
        cur[action + "_at"] = datetime.datetime.now(
            datetime.timezone.utc).isoformat()
        p.write_text(json.dumps(cur, indent=2), encoding="utf-8")
        return jsonify({"ok": True, "snapshot": cur})

    @app.route("/stages/<sha>/<stage>", methods=["POST"])
    def run_stage(sha: str, stage: str):
        """Run ONE stage against an existing pack (manual control).

        Dynamic requires the HITL checkpoint: {"confirm_snapshot": true} in
        the body, meaning the operator verified a clean VM snapshot.
        """
        from winre.evidence import EvidencePack
        if stage not in MANUAL_STAGES:
            return jsonify({"ok": False, "error": f"unknown stage {stage}"}), 400
        if not _valid_sha(sha):
            return jsonify({"ok": False, "error": "invalid sha"}), 400
        if _run_state["running"]:
            return jsonify({"ok": False, "error": "pipeline already running"}), 409
        root = LOGS_DIR / sha
        if not root.is_dir():
            return jsonify({"ok": False, "error": "pack not found"}), 404
        body = request.get_json(force=True, silent=True) or {}
        if stage == "dynamic" and not body.get("confirm_snapshot"):
            return jsonify({
                "ok": False,
                "error": ("dynamic refused: confirm a clean VM snapshot first "
                          "(POST /api/hitl/snapshot verified_clean, then "
                          "retry with confirm_snapshot=true)"),
            }), 403

        from winre import remote_driver as _rd

        def _run_one():
            cfg = _rd.flare_cfg()
            pack = EvidencePack(LOGS_DIR, sha).ensure()
            name = _stage_sample(root)
            if not name:
                return {"ok": False, "error": "intake sample unknown"}
            try:
                if stage == "quick":
                    out = _rd.remote_quick(name, pack, cfg)
                    return {"ok": True, "result": out}
                if stage == "dynamic":
                    out = _rd.remote_dynamic(
                        name, sha, pack, cfg,
                        int(body.get("max_seconds", 45)),
                        bool(body.get("pesieve", False)))
                    return {"ok": True, "result": out}
                if stage == "deep":
                    out = _rd.remote_deep(name, pack, cfg,
                                          bool(body.get("dry_llm", False)), sha=sha)
                    return {"ok": True, "result": out}
                if stage == "yara":
                    from winre import yara_gen
                    rep = yara_gen.generate_rules(pack.root, pack.stages["yara"])
                    return {"ok": True, "result": rep}
                if stage == "report":
                    from winre.pipeline import _report
                    quick = pack.read("quick", "quick.json") or {}
                    dynamic = pack.read("dynamic", "STAGE.json")
                    deep = pack.read("deep", "deep.json") or {}
                    rep = _report(pack, sha, quick, dynamic, deep)
                    return {"ok": True, "result": rep}
                if stage == "audit":
                    from winre import audit as audit_mod
                    res = audit_mod.audit(pack.root)
                    (pack.root / "audit.json").write_text(
                        json.dumps(res, indent=2) + "\n", encoding="utf-8")
                    return {"ok": True, "result": res}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": str(e)[:300]}

        def _do():
            with _run_lock:
                _run_state["running"] = True
                _run_state["sha"] = sha
                _run_state["log"] = []
                try:
                    # reuse the same capture helper by calling inline
                    _run_state["last"] = _run_one()
                    if not isinstance(_run_state["last"], dict):
                        _run_state["last"] = {"ok": False, "error": "no result"}
                except Exception as e:  # noqa: BLE001
                    _run_state["last"] = {"ok": False, "error": str(e)}
                finally:
                    _run_state["running"] = False

        threading.Thread(target=_do, daemon=True).start()
        return jsonify({"ok": True, "msg": f"stage {stage} started", "sha": sha})

    @app.route("/packs")
    def packs():
        return render_template("packs.html", packs=_packs())

    @app.route("/api/packs")
    def api_packs():
        """JSON: pack list + phase/source/truly_green for each."""
        out = []
        for p in _packs():
            sha = p["sha"]
            rep = None
            rp = LOGS_DIR / sha / "report" / "report.json"
            if rp.is_file():
                try:
                    rep = json.loads(rp.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    pass
            out.append({
                "sha": sha, "short": p["short"],
                "audit": p["audit"],
                "phase": (rep or {}).get("phase", "static"),
                "source": (rep or {}).get("source", "?"),
            })
        return jsonify(out)

    @app.route("/packs/<sha>")
    def pack(sha: str):
        detail = _pack_detail(sha)
        if detail is None:
            return render_template("packs.html", packs=_packs(),
                                   error=f"pack not found: {sha}"), 404
        return render_template("pack.html", pack=detail)

    @app.route("/packs/<sha>/export")
    def pack_export(sha: str):
        """Zip the whole evidence pack (analyst export)."""
        import io
        import zipfile
        from flask import Response, abort
        if not _valid_sha(sha):
            abort(400, "invalid sha")
        root = (LOGS_DIR / sha).resolve()
        if not root.is_dir():
            return jsonify({"error": "not found"}), 404
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(root.rglob("*")):
                if not f.is_file() or f.stat().st_size > 64 * 1024 * 1024:
                    continue  # skip >64MB monsters (pcaps dumps are separate)
                zf.write(f, f.relative_to(root))
        buf.seek(0)
        return Response(buf.getvalue(), mimetype="application/zip",
                        headers={"Content-Disposition":
                                 f"attachment; filename=winre-{sha[:16]}.zip"})

    @app.route("/packs/<sha>/<stage>/<fname>")
    def pack_file(sha: str, stage: str, fname: str):
        from flask import Response, abort
        # Path-traversal guard: all segments must be plain names, and the
        # resolved path must stay inside the pack's stage directory.
        for seg in (sha, stage, fname):
            if not seg or seg in (".", "..") or "/" in seg or "\\" in seg:
                abort(400, "invalid path segment")
        base = (LOGS_DIR / sha / stage).resolve()
        d = (base / fname).resolve()
        try:
            d.relative_to(base)
        except ValueError:
            abort(400, "path escapes pack directory")
        if not d.is_file():
            return jsonify({"error": "not found"}), 404
        # ?download=1 streams the whole file as an attachment (large CSV/pcap
        # logs). Inline view is capped at 64KB with ?offset= for paging.
        if request.args.get("download") == "1":
            def _stream():
                with d.open("rb") as fh:
                    while True:
                        chunk = fh.read(65536)
                        if not chunk:
                            break
                        yield chunk
            return Response(_stream(), mimetype="application/octet-stream",
                            headers={"Content-Disposition":
                                     f"attachment; filename={fname}"})
        try:
            offset = max(0, int(request.args.get("offset", "0")))
        except ValueError:
            offset = 0
        size = d.stat().st_size
        cap = 65536
        with d.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read(cap + 1)
        truncated = len(chunk) > cap
        text = chunk[:cap].decode("utf-8", errors="replace")
        return jsonify({"sha": sha, "stage": stage, "file": fname,
                        "size": size, "offset": offset,
                        "truncated": truncated,
                        "next_offset": offset + cap if truncated else None,
                        "text": text})

    @app.route("/mcp")
    def mcp():
        return render_template("mcp.html", health=_vm_health_cached())

    @app.route("/settings")
    def settings():
        """Config state (read-only; secrets masked, never shown)."""
        import os as _os
        from winre import envfile as _env  # noqa: F401  (ensures .env loaded)
        from winre import snapshot_gate as _sg
        env_path = Path(_os.environ.get(
            "WINRE_ENV", str(REPO / ".env")))
        cfg = {
            "flare": {
                "host": _os.environ.get("FLARE_HOST", "(set FLARE_HOST)"),
                "port": _os.environ.get("FLARE_SSH_PORT", "22"),
                "user": _os.environ.get("FLARE_USER", "FLARE-VM"),
                "key": _os.environ.get("FLARE_SSH_KEY", "~/.ssh/<your-key>"),
            },
            "llm": {
                "base_url": _os.environ.get("WINRE_LLM_BASE_URL", ""),
                "model": _os.environ.get("WINRE_LLM_MODEL", ""),
                "reasoning": _os.environ.get("WINRE_LLM_REASONING", ""),
                "key_set": bool(_os.environ.get("WINRE_LLM_API_KEY")),
            },
            "gate": {
                "mode": _sg.mode(),
                "marker_path": _sg.MARKER,
                "hypervisor": _sg.hypervisor_cfg(),
            },
            "env_file": {"path": str(env_path), "present": env_path.is_file()},
            "logs_dir": str(LOGS_DIR),
            "ghidra_heap": _os.environ.get("GHIDRA_HEADLESS_MAXMEM", "(ghidra default 2G)"),
        }
        llm_ok = False
        try:
            from winre import llm_client
            llm_ok = llm_client.available()
        except Exception:
            pass
        return render_template("settings.html", cfg=cfg, llm_ok=llm_ok)

    @app.route("/help")
    def help_page():
        """Render the pipeline doc as HTML."""
        try:
            import markdown as _md
            src = (REPO / "docs" / "PIPELINE.md").read_text(encoding="utf-8")
            html = _md.markdown(src)
        except Exception as e:  # noqa: BLE001
            html = f"<p class='muted'>docs unavailable: {e}</p>"
        return render_template("help.html", body=html)

    # ── Error pages (no stack traces, no raw paths) ─────────────────────
    @app.errorhandler(404)
    def nf(e):
        return render_template("error.html", code=404,
                               title="Not found",
                               hint="The page or pack does not exist. "
                                    "It may have been removed."), 404

    @app.errorhandler(500)
    def ise(e):
        return render_template("error.html", code=500,
                               title="Internal error",
                               hint="The console hit an unexpected error. "
                                    "Check the console log on the host."), 500

    return app


def main() -> int:
    ap = argparse.ArgumentParser(description="WinRE UI console (control plane)")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    app = create_app()
    print(f"[winre-ui] serving on http://{args.host}:{args.port} "
          f"(evidence: {LOGS_DIR})", flush=True)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
