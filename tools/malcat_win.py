#!/usr/bin/env python3
"""malcat_win.py — Windows Malcat MCP wrapper for FlareVM.

Thin port of Remnux mcp-malcat (Tools/v2-deploy/mcp-malcat/mcp_malcat.py:41)
to the Windows path. Malcat is commercial per-user — binary never
redistributed; this script reads the license key from C:\\WinRE\\.env
(MALCAT_KEY) and shells out to malcat.mcp.py.

Subcommands:
    health                                  — check key + binary
    analyze <path> --profile {triage,deep,minimal} [--views ...] [--json]
    serve --port 9009                       — HTTP shim around malcat.mcp.py
    canary <path>                           — emit canary dict for orchestrator

Output schema mirrors Remnux v2_lib.malcat_analyze (docs/MALCAT.md:53):
    {analysis_id, file_summary, views{...}, functions[], constants[],
     anomalies[], carved_files[], virtual_files[], structures[],
     decompilations{}, script_decompile, unpack_result, errors[]}

Usage (PowerShell on Flare-VM):
    $env:MALCAT_KEY = (Get-Content C:\\WinRE\\.env | Select-String MALCAT_KEY).ToString().Split('=')[1]
    python C:\\WinRE\\tools\\malcat_win.py health
    python C:\\WinRE\\tools\\malcat_win.py analyze C:\\samples\\foo.exe --profile triage --json
    python C:\\WinRE\\tools\\malcat_win.py serve --port 9009
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
def _find_malcat_bin() -> Path:
    env = os.environ.get("MALCAT_BIN_DIR")
    if env:
        return Path(env)
    candidates = [
        Path(r"C:\Users\flare-vm\Downloads\malcat\bin"),
        Path(r"C:\tools\malcat\bin"),
        Path(r"C:\Program Files\Malcat\bin"),
    ]
    for c in candidates:
        if (c / "malcat.mcp.py").is_file():
            return c
    return candidates[0]


MALCAT_BIN_DIR = _find_malcat_bin()
MALCAT_MCP = MALCAT_BIN_DIR / "malcat.mcp.py"
MALCAT_LICENSE = Path(os.environ.get(
    "MALCAT_LICENSE",
    r"C:\Users\FLARE-VM\AppData\Roaming\Malcat\license.dat",
))
ENV_FILE = Path(os.environ.get("WINRE_ENV", r"C:\WinRE\.env"))

# Mirrors v2_lib.MALCAT_TRIAGE_VIEWS / MALCAT_DEEP_VIEWS
TRIAGE_VIEWS = ["anomalies", "strings", "imports", "sections", "yara_hits", "entropy"]
DEEP_VIEWS = TRIAGE_VIEWS + ["decompile", "anomaly_locations", "constants", "functions"]
MINIMAL_VIEWS = ["anomalies", "yara_hits", "imports"]

PROFILES = {
    "triage":  {"views": TRIAGE_VIEWS,  "limits": {"strings": 200, "imports": 200, "anomalies": 100}},
    "deep":    {"views": DEEP_VIEWS,    "limits": {"strings": 1000, "imports": 1000, "anomalies": 500, "decompile": 50}},
    "minimal": {"views": MINIMAL_VIEWS, "limits": {"anomalies": 50}},
}


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------
def _load_env_file() -> dict:
    """Read C:\\WinRE\\.env (KEY=VAL lines, ignore comments). Returns dict."""
    if not ENV_FILE.is_file():
        return {}
    out = {}
    for line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _resolve_key() -> str | None:
    key = os.environ.get("MALCAT_KEY")
    if key:
        return key
    env = _load_env_file()
    return env.get("MALCAT_KEY")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
def health() -> dict:
    out = {
        "ok": True,
        "malcat_mcp": str(MALCAT_MCP),
        "malcat_mcp_exists": MALCAT_MCP.is_file(),
        "license_file": str(MALCAT_LICENSE),
        "license_file_exists": MALCAT_LICENSE.is_file(),
        "key_env": "MALCAT_KEY" in os.environ,
        "key_envfile": bool(_load_env_file().get("MALCAT_KEY")),
        "python": shutil.which("python") or shutil.which("python.exe"),
    }
    out["ok"] = out["malcat_mcp_exists"] and (out["key_env"] or out["key_envfile"])
    if not out["ok"]:
        missing = []
        if not out["malcat_mcp_exists"]:
            missing.append(f"malcat.mcp.py missing at {MALCAT_MCP}")
        if not (out["key_env"] or out["key_envfile"]):
            missing.append("MALCAT_KEY not in env and not in C:\\WinRE\\.env")
        out["error"] = "; ".join(missing)
    return out


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------
def _build_argv(views: list[str], limits: dict, path: Path,
                analysis_id: int) -> list[str]:
    argv = [
        sys.executable, str(MALCAT_MCP),
        "--path", str(path),
        "--analysis-id", str(analysis_id),
        "--views", ",".join(views),
    ]
    for k, v in limits.items():
        argv += [f"--limit-{k}", str(v)]
    return argv


def malcat_analyze(path: Path, views: list[str] | None = None,
                   profile: str = "triage", limits: dict | None = None,
                   analysis_id: int = 0, timeout: int = 300) -> dict:
    """Run malcat.mcp.py once and return its JSON."""
    h = health()
    if not h["ok"]:
        return {"ok": False, "error": h.get("error"),
                "analysis_id": analysis_id, "profile": profile}
    if not path.is_file():
        return {"ok": False, "error": f"sample missing: {path}",
                "analysis_id": analysis_id, "profile": profile}

    if views is None:
        cfg = PROFILES.get(profile, PROFILES["triage"])
        views = cfg["views"]
    if limits is None:
        limits = PROFILES.get(profile, PROFILES["triage"]).get("limits", {})

    key = _resolve_key()
    env = os.environ.copy()
    if key:
        env["MALCAT_KEY"] = key

    argv = _build_argv(views, limits, path, analysis_id)
    t0 = time.time()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"malcat timeout {timeout}s",
                "analysis_id": analysis_id, "profile": profile,
                "elapsed_s": round(time.time() - t0, 1)}
    except FileNotFoundError as e:
        return {"ok": False, "error": f"python or malcat.mcp.py missing: {e}",
                "analysis_id": analysis_id, "profile": profile}

    if proc.returncode != 0:
        return {"ok": False, "returncode": proc.returncode,
                "error": (proc.stderr or proc.stdout)[-600:],
                "analysis_id": analysis_id, "profile": profile,
                "elapsed_s": round(time.time() - t0, 1)}

    # malcat.mcp.py emits one JSON blob (text/plain or application/json);
    # take the last { ... } block on stdout.
    payload = None
    buf = []
    for line in (proc.stdout or "").splitlines():
        if line.strip().startswith("{"):
            buf = [line]
        elif buf:
            buf.append(line)
            if line.strip().endswith("}"):
                try:
                    payload = json.loads("\n".join(buf))
                    buf = []
                except json.JSONDecodeError:
                    pass
    if payload is None:
        # fallback: whole-stdout
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"ok": False, "error": "malcat.mcp.py did not emit JSON",
                    "stdout_tail": (proc.stdout or "")[-400:],
                    "analysis_id": analysis_id, "profile": profile,
                    "elapsed_s": round(time.time() - t0, 1)}

    payload.setdefault("ok", True)
    payload.setdefault("analysis_id", analysis_id)
    payload.setdefault("profile", profile)
    payload.setdefault("elapsed_s", round(time.time() - t0, 1))
    # annotate entropy per docs/MALCAT.md:53
    if "file_summary" in payload and "entropy" not in payload.get("views", {}):
        try:
            payload["entropy_annotated"] = True
        except Exception:
            pass
    return payload


# ---------------------------------------------------------------------------
# Canary (lightweight: just triage views, used by orchestrator pre-flight)
# ---------------------------------------------------------------------------
def canary(path: Path) -> dict:
    """Cheap triage — anomalies + yara + imports only. <1s target."""
    return malcat_analyze(path, views=MINIMAL_VIEWS, profile="minimal", timeout=60)


# ---------------------------------------------------------------------------
# HTTP serve (stdlib http.server shim around malcat.mcp.py — no flask needed)
# ---------------------------------------------------------------------------
def serve(port: int) -> int:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: N802
            sys.stderr.write("[malcat_win] " + (format % args) + "\n")

        def _reply(self, code: int, payload: dict):
            data = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                self._reply(200, health())
            else:
                self._reply(404, {"ok": False, "error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path != "/analyze":
                self._reply(404, {"ok": False, "error": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError as e:
                self._reply(400, {"ok": False, "error": str(e)})
                return
            p = Path(body.get("path", ""))
            if not p.is_file():
                self._reply(400, {"ok": False, "error": f"sample missing: {p}"})
                return
            profile = body.get("profile", "triage")
            views = body.get("views")
            limits = body.get("limits")
            aid = int(body.get("analysis_id", int(time.time())))
            self._reply(200, malcat_analyze(p, views=views, profile=profile,
                                            limits=limits, analysis_id=aid,
                                            timeout=int(body.get("timeout", 300))))

    print(f"[malcat_win] serving on 127.0.0.1:{port}", flush=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Flare-VM Malcat wrapper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_health = sub.add_parser("health", help="check key + binary")
    p_health.add_argument("--json", action="store_true")

    p_an = sub.add_parser("analyze", help="run a malcat analysis pass")
    p_an.add_argument("path", help="file to analyze")
    p_an.add_argument("--profile", choices=list(PROFILES), default="triage")
    p_an.add_argument("--views", help="comma-list override (otherwise profile default)")
    p_an.add_argument("--timeout", type=int, default=300)
    p_an.add_argument("--analysis-id", type=int, default=0)
    p_an.add_argument("--out", help="write JSON to file in addition to stdout")
    p_an.add_argument("--json", action="store_true")

    p_can = sub.add_parser("canary", help="minimal triage pass (anomalies+yara+imports)")
    p_can.add_argument("path")
    p_can.add_argument("--json", action="store_true")

    p_sv = sub.add_parser("serve", help="HTTP shim")
    p_sv.add_argument("--port", type=int, default=9009)

    args = ap.parse_args()

    if args.cmd == "health":
        h = health()
        if args.json:
            print(json.dumps(h, indent=2))
        else:
            for k, v in h.items():
                print(f"  {k}: {v}")
        return 0 if h.get("ok") else 1

    if args.cmd == "analyze":
        views = args.views.split(",") if args.views else None
        out = malcat_analyze(Path(args.path), views=views, profile=args.profile,
                             analysis_id=args.analysis_id, timeout=args.timeout)
        if args.out:
            Path(args.out).write_text(json.dumps(out, indent=2, default=str),
                                      encoding="utf-8")
        if args.json:
            print(json.dumps(out, indent=2, default=str))
        else:
            print(f"ok={out.get('ok')}  analysis_id={out.get('analysis_id')}  "
                  f"profile={out.get('profile')}  elapsed={out.get('elapsed_s')}s")
            if not out.get("ok"):
                print(f"ERROR: {out.get('error')}", file=sys.stderr)
                return 1
        return 0 if out.get("ok") else 1

    if args.cmd == "canary":
        out = canary(Path(args.path))
        if args.json:
            print(json.dumps(out, indent=2, default=str))
        else:
            print(json.dumps({"ok": out.get("ok"),
                              "analysis_id": out.get("analysis_id"),
                              "yara_count": len(out.get("views", {}).get("yara_hits", [])),
                              "anomalies_count": len(out.get("views", {}).get("anomalies", [])),
                              "imports_count": len(out.get("views", {}).get("imports", []))},
                             indent=2))
        return 0 if out.get("ok") else 1

    if args.cmd == "serve":
        return serve(args.port)

    return 0


if __name__ == "__main__":
    sys.exit(main())
