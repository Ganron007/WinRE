#!/usr/bin/env python3
"""malcat_win.py — Windows Malcat MCP wrapper for FlareVM.

Thin port of the Remnux-lineage mcp-malcat wrapper
to the Windows path. Malcat is commercial per-user — binary never
redistributed; this script reads the license key from C:\\WinRE\\.env
(MALCAT_KEY) and shells out to malcat.mcp.py.

Subcommands:
    health                                  — check key + binary
    analyze <path> --profile {triage,deep,minimal} [--views ...] [--json]
    serve --port 9009                       — HTTP shim around malcat.mcp.py
    canary <path>                           — emit canary dict for orchestrator

Output schema mirrors Remnux v2_lib.malcat_analyze (malcat output schema):
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
        Path(r"C:\Tools\malcat\bin"),          # canonical (keep folder name: malcat)
        Path(r"C:\Program Files\Malcat\bin"),
        Path(r"C:\Users\flare-vm\Downloads\malcat\bin"),
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
    # The MALCAT_KEY is ONLY for ONLINE Kesakode. Headless offline analysis
    # works without it (verified live 2026-09-19) - do not gate on the key.
    out["kesakode_online"] = bool(out["key_env"] or out["key_envfile"])
    out["ok"] = out["malcat_mcp_exists"]
    if not out["ok"]:
        out["error"] = f"malcat.mcp.py missing at {MALCAT_MCP}"
    elif not out["kesakode_online"]:
        out["note"] = ("offline only - no MALCAT_KEY: Kesakode lookups are "
                       "unavailable (headless offline Kesakode needs an OEM "
                       "license; online needs -k with a running license)")
    return out


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------
def _build_argv(views: list[str], limits: dict, path: Path,
                analysis_id: int, key: str | None = None) -> list[str]:
    argv = [
        sys.executable, str(MALCAT_MCP),
        "--path", str(path),
        "--analysis-id", str(analysis_id),
        "--views", ",".join(views),
    ]
    for k, v in limits.items():
        argv += [f"--limit-{k}", str(v)]
    if key:
        argv += ["-k", key]  # ONLINE Kesakode only
    return argv


def _extract_mcp_json(result: dict | None) -> dict:
    """Parse a malcat.mcp.py tool result into a dict.

    Newer MCP servers return `structuredContent`; older ones put JSON in
    `content[].text`."""
    if not isinstance(result, dict):
        return {}
    sc = result.get("structuredContent")
    if isinstance(sc, dict) and sc:
        return sc
    for part in (result.get("content") or []):
        if isinstance(part, dict) and part.get("type") == "text":
            try:
                d = json.loads(part.get("text") or "")
                if isinstance(d, dict):
                    return d
            except json.JSONDecodeError:
                continue
    return {}


def _ensure_server(timeout_s: int = 30) -> tuple[bool, str | None]:
    """Start the Malcat headless MCP server (:9009) when it is not running."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from winre.mcp.malcat_client import MalcatClient
    if MalcatClient(default_timeout=5).is_up():
        return True, None
    key = _resolve_key()
    argv = [sys.executable, str(MALCAT_MCP), "-p", "9009"]
    if key:
        argv += ["-k", key]
    flags = 0
    if os.name == "nt":
        flags = (getattr(subprocess, "DETACHED_PROCESS", 0)
                 | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    try:
        subprocess.Popen(argv, creationflags=flags)
    except Exception as e:  # noqa: BLE001
        return False, f"could not start malcat.mcp.py: {e}"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(1)
        if MalcatClient(default_timeout=3).is_up():
            return True, None
    return False, "malcat MCP :9009 did not come up"


_MALCAT_VIEW_METHODS = {
    "anomalies": "anomalies_list",
    "yara_hits": "yara_list",
    "strings": "strings_top_list",
    "functions": "fns_top_list",
    "constants": "constants_list",
    "carved": "file_list_carved",
    "virtual_files": "file_list_virtual_files",
    "imports": "analyse_infos",
}


def malcat_analyze(path: Path, views: list[str] | None = None,
                   profile: str = "triage", limits: dict | None = None,
                   analysis_id: int = 0, timeout: int = 300) -> dict:
    """Analyze through the Malcat headless MCP server (:9009).

    MALCAT_KEY is ONLY for ONLINE Kesakode - offline headless analysis works
    without it. `malcat.mcp.py` is a server (not a one-shot CLI), so this
    wrapper speaks JSON-RPC exactly like the pipeline's MalcatClient.
    """
    h = health()
    if not h["ok"]:
        return {"ok": False, "error": h.get("error"),
                "analysis_id": analysis_id, "profile": profile}
    if not path.is_file():
        return {"ok": False, "error": f"sample missing: {path}",
                "analysis_id": analysis_id, "profile": profile}
    ok, err = _ensure_server()
    if not ok:
        return {"ok": False, "error": err, "analysis_id": analysis_id,
                "profile": profile}

    t0 = time.time()
    from winre.mcp.malcat_client import MalcatClient
    client = MalcatClient(default_timeout=timeout)
    r = client.analyse_file(str(path))
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error"),
                "analysis_id": analysis_id, "profile": profile,
                "elapsed_s": round(time.time() - t0, 1)}
    summary = _extract_mcp_json(r.get("result"))
    aid = summary.get("analysis_id", analysis_id)
    want = views or PROFILES.get(profile, PROFILES["triage"])["views"]
    out_views: dict = {}
    for v in want:
        meth = _MALCAT_VIEW_METHODS.get(v)
        fn = getattr(client, meth, None) if meth else None
        if fn is None:
            continue
        try:
            rr = fn(str(path))
        except Exception as e:  # noqa: BLE001
            out_views[v] = {"error": str(e)[:200]}
            continue
        out_views[v] = (_extract_mcp_json(rr.get("result"))
                        if rr.get("ok") else {"error": rr.get("error")})
    return {"ok": True, "analysis_id": aid, "profile": profile,
            "file_summary": summary, "views": out_views,
            "elapsed_s": round(time.time() - t0, 1)}


# ---------------------------------------------------------------------------
# Canary (lightweight: just triage views, used by orchestrator pre-flight)
# ---------------------------------------------------------------------------
def canary(path: Path) -> dict:
    """Cheap triage — anomalies + yara + imports only. <1s target."""
    return malcat_analyze(path, views=MINIMAL_VIEWS, profile="minimal", timeout=60)


# ---------------------------------------------------------------------------
# HTTP serve — starts the OFFICIAL Malcat headless MCP server
# (malcat.mcp.py -p 9009). Persistent process, 45 tools, JSON-RPC over HTTP
# at http://127.0.0.1:9009/mcp — same MCP contract as x64dbg/WinDbg bridges.
# Doc: https://doc.malcat.fr/ui/mcp.html#headless-mcp-server
# License key (-k) enables online Kesakode; without it headless works but
# Kesakode is offline-only (OEM). Never pass the key on the CLI log line.
# ---------------------------------------------------------------------------
def serve(port: int = 9009) -> int:
    h = health()
    if not h["ok"]:
        print(f"ERROR: {h.get('error')}", file=sys.stderr)
        return 1
    key = _resolve_key()
    argv = [sys.executable, str(MALCAT_MCP), "-p", str(port)]
    if key:
        argv += ["-k", key]
    print(f"[malcat_win] starting headless MCP: {argv[0]} {argv[1]} -p {port} (key: {'set' if key else 'NONE'})", flush=True)
    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(argv)
        proc.wait()
    except KeyboardInterrupt:
        if proc:
            proc.terminate()
    except Exception as e:
        print(f"[malcat_win] server failed: {e}", file=sys.stderr)
        return 1
    return proc.returncode if proc else 1


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
