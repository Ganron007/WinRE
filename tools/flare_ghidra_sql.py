#!/usr/bin/env python3
"""flare_ghidra_sql.py — Windows Ghidra SQL wrapper for FlareVM.

Ports the Remnux ghidra_sql_client.py (Tools/v2-deploy/) to Windows so
FlareVM can answer the same SQL queries the LLM agent uses against
ghidrasql on Remnux.

Two execution paths, chosen at health-check time:

  A. analyzeHeadless + Java post-script (GhidraSql.java) — matches Remnux
     contract exactly, no extra server process. Slower per query (~30s
     JVM cold start for big PEs) but stateless.

  B. LibGhidraHost HTTP server (`java -jar GhidraSql.jar --port 19301`)
     — fast multi-query, requires the extension to be built for Windows.
     Used when --serve is passed.

Spec: docs/SQL-GHIDRA.md (this repo).

Usage (PowerShell on Flare-VM):
    python C:\\WinRE\\tools\\flare_ghidra_sql.py health
    python C:\\WinRE\\tools\\flare_ghidra_sql.py "SELECT count(*) FROM funcs" --file C:\\samples\\foo.exe --json
    python C:\\WinRE\\tools\\flare_ghidra_sql.py --serve --port 19301
    # then:
    #   curl -X POST http://127.0.0.1:19301/query -H "Content-Type: application/json" ^
    #        -d "{\"file\":\"C:\\\\samples\\\\foo.exe\",\"sql\":\"SELECT count(*) FROM funcs\"}"
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
# Paths (override with env: GHIDRA_HOME, GHIDRA_SQL_JAR, GHIDRA_CACHE_DIR)
# ---------------------------------------------------------------------------
GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", r"C:\tools\ghidra_12.2_PUBLIC"))
HEADLESS_BAT = GHIDRA_HOME / "support" / "analyzeHeadless.bat"
LIB_HOST_JAR = Path(os.environ.get(
    "GHIDRA_SQL_JAR",
    str(GHIDRA_HOME / "Ghidra" / "Extensions" / "LibGhidraHost" / "lib" / "GhidraSql.jar"),
))
CACHE_DIR = Path(os.environ.get("GHIDRA_CACHE_DIR", r"C:\WinRE\cache\ghidra"))
HERE = Path(__file__).resolve().parent
SCRIPTS_DIR = HERE / "ghidra_scripts"
GHIDRA_SQL_JAVA = SCRIPTS_DIR / "GhidraSql.java"

CANONICAL_QUERIES = {
    "funcs":      "SELECT name, addr AS address, size FROM funcs ORDER BY size DESC LIMIT 20",
    "imports":    "SELECT name, module FROM imports ORDER BY module",
    "strings":    ("SELECT content, addr AS address FROM strings "
                   "WHERE content LIKE '%http%' OR content LIKE '%cmd%' LIMIT 50"),
    "data_items": "SELECT addr AS address, size, type FROM data_items LIMIT 20",
    "segments":   "SELECT name, start, end, perm FROM segments",
}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
def health() -> dict:
    """Probe Ghidra + LibGhidraHost + CADRE PE Loader presence."""
    out: dict = {
        "ok": True,
        "ghidra_home": str(GHIDRA_HOME),
        "analyze_headless": HEADLESS_BAT.is_file(),
        "lib_ghidra_host": False,
        "cadre_pe_loader": False,
        "java": shutil.which("java") or shutil.which("javaw"),
    }
    if HEADLESS_BAT.is_file():
        out["ok"] = True
    else:
        out["ok"] = False
        out["error"] = f"analyzeHeadless.bat not found at {HEADLESS_BAT}"

    if LIB_HOST_JAR.is_file():
        out["lib_ghidra_host"] = True
    # CADRE PE Loader — heuristic check on Extensions/CADRE or env override
    cadre = os.environ.get("GHIDRA_CADRE_DIR")
    if cadre and Path(cadre).is_dir():
        out["cadre_pe_loader"] = True
    else:
        for cand in (GHIDRA_HOME / "Ghidra" / "Extensions" / "CADRE",
                     GHIDRA_HOME / "Ghidra" / "Extensions" / "CADRE PE Loader"):
            if cand.is_dir():
                out["cadre_pe_loader"] = True
                out["cadre_pe_loader_path"] = str(cand)
                break

    if not out["java"]:
        out["ok"] = False
        out["error"] = out.get("error", "java not on PATH")
    return out


# ---------------------------------------------------------------------------
# Path A — analyzeHeadless + Java post-script
# ---------------------------------------------------------------------------
def _loader_name() -> str:
    """Prefer CADRE PE Loader (packed-sample recovery), fall back to default."""
    cadre = os.environ.get("GHIDRA_CADRE_DIR")
    if cadre and Path(cadre).is_dir():
        return "CADRE PE Loader"
    for cand in (GHIDRA_HOME / "Ghidra" / "Extensions" / "CADRE",
                 GHIDRA_HOME / "Ghidra" / "Extensions" / "CADRE PE Loader"):
        if cand.is_dir():
            return "CADRE PE Loader"
    return "PE Loader"


def run_query_headless(sql: str, sample: Path, timeout: int = 180,
                       persist: bool = False) -> dict:
    """Run one SQL via analyzeHeadless + GhidraSql.java post-script.

    Returns:
        dict {ok, rows, columns, row_count, error, mode, elapsed_s}
    """
    h = health()
    if not h["ok"]:
        return {"ok": False, "error": h.get("error"), "mode": "headless"}
    if not sample.is_file():
        return {"ok": False, "error": f"sample missing: {sample}", "mode": "headless"}
    if not GHIDRA_SQL_JAVA.is_file():
        return {"ok": False,
                "error": f"GhidraSql.java missing: {GHIDRA_SQL_JAVA} "
                         f"(copy from RevEng Tools/v2-deploy/ghidra_sql_client.py or rebuild LibGhidraHost)",
                "mode": "headless"}

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    proj = tempfile.mkdtemp(prefix="winre-ghidra-", dir=str(CACHE_DIR))
    proj_name = f"winre-{sample.stem}"
    t0 = time.time()
    cmd = [
        str(HEADLESS_BAT),
        proj, proj_name,
        "-import", str(sample),
        "-loader", _loader_name(),
        "-scriptPath", str(SCRIPTS_DIR),
        "-postScript", "GhidraSql.java", sql,
        "-noanalysis",
        "-deleteProject",
    ]
    if persist:
        # -w is not a real flag; persist is implemented inside the Java
        # post-script by reading args. We add a marker arg instead.
        cmd.insert(-2, "-postScript")
        cmd.insert(-2, f"GhidraSqlPersist.java {sql}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"analyzeHeadless timeout {timeout}s",
                "mode": "headless", "elapsed_s": round(time.time() - t0, 1)}
    except FileNotFoundError as e:
        return {"ok": False, "error": f"java/analyzeHeadless not invokable: {e}",
                "mode": "headless"}

    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout)[-800:],
                "returncode": proc.returncode, "mode": "headless",
                "elapsed_s": round(time.time() - t0, 1)}

    # GhidraSql.java must print a single line of JSON to stdout.
    payload = None
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
    if payload is None:
        return {"ok": False,
                "error": "GhidraSql.java did not emit a JSON line; "
                         "check postScript logs in analyzeHeadless output",
                "stdout_tail": (proc.stdout or "")[-400:],
                "mode": "headless",
                "elapsed_s": round(time.time() - t0, 1)}

    payload.setdefault("mode", "headless")
    payload.setdefault("elapsed_s", round(time.time() - t0, 1))
    return payload


# ---------------------------------------------------------------------------
# Path B — LibGhidraHost HTTP server
# ---------------------------------------------------------------------------
def _start_libhost(db_path: Path, port: int) -> subprocess.Popen:
    """Start `java -jar GhidraSql.jar --program <i64> --port <port>` detached."""
    cmd = [
        shutil.which("java") or "java",
        "-jar", str(LIB_HOST_JAR),
        "--program", str(db_path),
        "--port", str(port),
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")


def query_http(db_path: str, sql: str, port: int = 19301,
               timeout: int = 60) -> dict:
    """Run one query against a LibGhidraHost server (assumed already running)."""
    body = json.dumps({"sql": sql}).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/query",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"ok": True, "mode": "libhost", **(json.loads(r.read()))}
    except urllib.error.URLError as e:
        return {"ok": False, "error": f"libhost unreachable on :{port}: {e}",
                "mode": "libhost"}


# ---------------------------------------------------------------------------
# HTTP serve mode (libhost front-end OR an inline shim around headless)
# ---------------------------------------------------------------------------
def serve(port: int, mode: str) -> int:
    """Run a tiny HTTP server. mode='libhost' expects LibGhidraHost already
    up on the same port; mode='shim' runs headless per request (slow but
    no extra setup)."""
    try:
        from flask import Flask, request, jsonify  # type: ignore
    except ImportError:
        print("ERROR: flask not installed (pip install flask)", file=sys.stderr)
        return 1

    app = Flask("flare_ghidra_sql")

    @app.get("/health")
    def _h():
        return jsonify(health())

    @app.post("/query")
    def _q():
        body = request.get_json(force=True) or {}
        sql = body.get("sql")
        file_ = body.get("file")
        if not sql or not file_:
            return jsonify({"ok": False, "error": "sql and file required"}), 400
        if mode == "libhost":
            return jsonify(query_http(file_, sql, port=port))
        # shim mode
        return jsonify(run_query_headless(sql, Path(file_), timeout=300,
                                          persist=bool(body.get("persist"))))

    print(f"[flare_ghidra_sql] serving on 127.0.0.1:{port} mode={mode}", flush=True)
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_table(result: dict) -> None:
    if not result.get("ok"):
        print(f"ERROR: {result.get('error', 'unknown')}", file=sys.stderr)
        return
    cols = result.get("columns") or []
    rows = result.get("rows") or []
    if not cols:
        print("(no columns)")
        return
    col_w = [max(len(str(c)), 12) for c in cols]
    for r in rows:
        vals = list(r.values()) if isinstance(r, dict) else r
        for i, v in enumerate(vals):
            if i < len(col_w):
                col_w[i] = max(col_w[i], len(str(v)))
    sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
    print(sep)
    print("| " + " | ".join(str(c).ljust(w) for c, w in zip(cols, col_w)) + " |")
    print(sep)
    for r in rows:
        vals = list(r.values()) if isinstance(r, dict) else r
        print("| " + " | ".join(str(v).ljust(w) for v, w in zip(vals, col_w)) + " |")
    print(sep)
    print(f"{result.get('row_count', len(rows))} row(s)  "
          f"mode={result.get('mode', '?')}  "
          f"elapsed={result.get('elapsed_s', '?')}s")


def main() -> int:
    ap = argparse.ArgumentParser(description="Flare-VM Ghidra SQL wrapper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_health = sub.add_parser("health", help="check tool availability")
    p_health.add_argument("--json", action="store_true")

    p_q = sub.add_parser("query", help="run one SQL against a sample")
    p_q.add_argument("sql", help="SQL string OR @funcs|@imports|@strings|@data_items|@segments")
    p_q.add_argument("--file", required=True, help="PE/ELF/binary path")
    p_q.add_argument("--json", action="store_true")
    p_q.add_argument("--mode", choices=["headless", "libhost"], default="headless")
    p_q.add_argument("--port", type=int, default=19301)
    p_q.add_argument("--persist", "-w", action="store_true",
                     help="persist renames/comments (LibGhidraHost only)")
    p_q.add_argument("--timeout", type=int, default=180)

    p_serve = sub.add_parser("serve", help="HTTP server (POST /query)")
    p_serve.add_argument("--port", type=int, default=19301)
    p_serve.add_argument("--mode", choices=["libhost", "shim"], default="shim")

    args = ap.parse_args()

    if args.cmd == "health":
        h = health()
        print(json.dumps(h, indent=2) if args.json else
              "\n".join(f"  {k}: {v}" for k, v in h.items()))
        return 0 if h.get("ok") else 1

    if args.cmd == "serve":
        return serve(args.port, args.mode)

    # query
    sql = args.sql
    if sql.startswith("@"):
        key = sql.lstrip("@")
        if key not in CANONICAL_QUERIES:
            print(f"ERROR: unknown canonical query '{key}'. "
                  f"Choose from {list(CANONICAL_QUERIES)}", file=sys.stderr)
            return 2
        sql = CANONICAL_QUERIES[key]
    if args.mode == "libhost":
        result = query_http(args.file, sql, port=args.port, timeout=args.timeout)
    else:
        result = run_query_headless(sql, Path(args.file), timeout=args.timeout,
                                    persist=args.persist)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_table(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
