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
    from flask import Flask, render_template, request, jsonify
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
_run_state: dict = {"running": False, "last": None, "pid": None}


def _packs() -> list[dict]:
    """List evidence packs (newest first) with audit summaries."""
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
            try:
                audit = json.loads(a.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        out.append({
            "sha": d.name,
            "short": d.name[:16],
            "mtime": d.stat().st_mtime,
            "audit": audit,
        })
    return out


def _pack_detail(sha: str) -> dict | None:
    d = LOGS_DIR / sha
    if not d.is_dir():
        return None
    detail = {"sha": sha, "stages": {}}
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
    return detail


_vm_health_cache: dict = {"t": 0.0, "data": None}
_VM_HEALTH_TTL = 20.0  # seconds — reloads are instant; health refreshes slowly


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
        for name, url in (("x64dbg", "http://{}:9094/"),
                          ("malcat", "http://{}:9009/mcp"),
                          ("windbg", "http://{}:9097/mcp/")):
            try:
                req = urllib.request.Request(url.format(cfg["host"]), data=b"{}",
                                             method="POST")
                with urllib.request.urlopen(req, timeout=4) as resp:
                    mcp[name] = resp.status == 200
            except Exception:
                mcp[name] = False
        results["mcp"] = mcp

    def _probe_llm():
        try:
            from winre import llm_client
            results["llm"] = llm_client.available()
        except Exception:
            results["llm"] = False

    threads = [threading.Thread(target=f, daemon=True) for f in
               (_probe_ssh, _probe_mcp, _probe_llm)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=8)  # hard cap on page-load probe time

    out.update(results)
    _vm_health_cache.update({"t": now, "data": out})
    return out


def _run_pipeline_in_thread(sample_path: str, max_seconds: int,
                            pesieve: bool, dry_llm: bool, dynamic: bool) -> None:
    """Run the remote pipeline in a background thread; store the result."""
    import traceback

    def _do():
        with _run_lock:
            _run_state["running"] = True
            try:
                res = remote_driver.run_remote_pipeline(
                    Path(sample_path), max_seconds=max_seconds,
                    enable_pesieve=pesieve, enable_dynamic=dynamic,
                    dry_llm=dry_llm)
                _run_state["last"] = {"ok": True, "sha": res["sha"],
                                      "audit": res["results"]["audit"]}
            except Exception as e:
                print("[winre-ui] run failed:", traceback.format_exc(), flush=True)
                _run_state["last"] = {"ok": False, "error": str(e)}
            finally:
                _run_state["running"] = False

    t = threading.Thread(target=_do, daemon=True)
    _run_state["pid"] = t
    t.start()


def create_app() -> "Flask":
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    @app.route("/")
    def index():
        return render_template("index.html", packs=_packs(),
                               health=_vm_health(),
                               state={k: _run_state[k] for k in
                                      ("running", "last")})

    @app.route("/health")
    def health():
        return jsonify(_vm_health())

    @app.route("/run", methods=["GET", "POST"])
    def run():
        if request.method == "POST":
            if _run_state["running"]:
                return jsonify({"ok": False, "error": "pipeline already running"}), 409
            sample = request.form.get("sample", "").strip()
            if not sample or not Path(sample).is_file():
                return jsonify({"ok": False, "error": f"sample not found: {sample}"}), 400
            max_seconds = int(request.form.get("max_seconds", 45))
            pesieve = request.form.get("pesieve") == "on"
            dry_llm = request.form.get("dry_llm") == "on"
            dynamic = request.form.get("dynamic") == "on"
            _run_pipeline_in_thread(sample, max_seconds, pesieve, dry_llm, dynamic)
            return jsonify({"ok": True, "msg": "pipeline started",
                            "sample": sample, "dynamic": dynamic})
        return render_template("run.html", running=_run_state["running"],
                               last=_run_state["last"])

    @app.route("/run/status")
    def run_status():
        return jsonify({k: _run_state[k] for k in ("running", "last")})

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

    @app.route("/packs/<sha>/<stage>/<fname>")
    def pack_file(sha: str, stage: str, fname: str):
        d = LOGS_DIR / sha / stage / fname
        if not d.is_file():
            return jsonify({"error": "not found"}), 404
        return d.read_text(encoding="utf-8", errors="replace")

    @app.route("/mcp")
    def mcp():
        return render_template("mcp.html", health=_vm_health())

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
