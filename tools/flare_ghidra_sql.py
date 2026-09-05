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
# Auto-detect falls back across the FlareVM choco layout, C:\tools, and the
# local repo layout so the tool works regardless of install method.
# ---------------------------------------------------------------------------
def _find_ghidra_home() -> Path:
    env = os.environ.get("GHIDRA_HOME")
    if env:
        return Path(env)
    candidates = [
        Path(r"C:\tools\ghidra_12.2_PUBLIC"),
        Path(r"C:\tools\ghidra_12.1.3_PUBLIC"),
        Path(r"C:\tools\ghidra_12.1.2_PUBLIC"),
        Path(r"C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_12.1.2_PUBLIC"),
        Path(r"C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_12.1.3_PUBLIC"),
        Path(r"C:\tools\ghidra"),
        Path(r"C:\ghidra"),
    ]
    for c in candidates:
        if (c / "support" / "analyzeHeadless.bat").is_file():
            return c
    # last resort: anything with analyzeHeadless.bat under C:\tools (depth 2)
    try:
        hits = list(Path(r"C:\tools").glob("ghidra*_PUBLIC/support/analyzeHeadless.bat"))
        if hits:
            return hits[0].parents[1]
    except OSError:
        pass
    return candidates[0]


GHIDRA_HOME = _find_ghidra_home()
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
# Path A — analyzeHeadless.bat + Java post-script
# ---------------------------------------------------------------------------
def _loader_name() -> str:
    """Only use the CADRE PE Loader when it is actually installed and
    registered (extension dir contains a built jar + manifest). Otherwise
    return '' so Ghidra auto-detects the loader — in Ghidra 12.1.3 the old
    'PE Loader' name is invalid and an unregistered 'CADRE PE Loader' hangs."""
    def _valid_cadre(dir_: Path) -> bool:
        try:
            if not dir_.is_dir():
                return False
            return any(p.is_file() and p.suffix == ".jar" for p in dir_.rglob("*"))
        except OSError:
            return False

    env_dir = os.environ.get("GHIDRA_CADRE_DIR")
    if env_dir and _valid_cadre(Path(env_dir)):
        return "CADRE PE Loader"
    for cand in (GHIDRA_HOME / "Ghidra" / "Extensions" / "CADRE",
                 GHIDRA_HOME / "Ghidra" / "Extensions" / "CADRE PE Loader"):
        if _valid_cadre(cand):
            return "CADRE PE Loader"
    return ""


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
    # NOTE: analyzeHeadless.bat mangles SQL args via cmd re-parsing (parens,
    # `>`, `*`). Pass the SQL through the GHIDRA_SQL_QUERY env var and have
    # GhidraSql.java read it; the batch only receives a sentinel arg.
    # The .bat launcher (via LaunchSupport) is the only reliable entry point —
    # direct `java ghidra.app.util.headless.AnalyzeHeadless` fails on 12.1.3
    # (no main; requires ghidra.Ghidra launcher setup).
    cmd = [
        str(HEADLESS_BAT),
        proj, proj_name,
        "-import", str(sample),
    ]
    loader = _loader_name()
    if loader:
        cmd += ["-loader", loader]
    cmd += [
        "-scriptPath", str(SCRIPTS_DIR),
        "-postScript", "GhidraSql.java", "GHIDRA_SQL_QUERY",
        "-deleteProject",
    ]
    # Analysis: packed samples (RevAI-parity requirement) need Ghidra's
    # auto-analysis or getFunctionManager() yields ~0 functions. Default ON;
    # WINRE_GHIDRA_ANALYZE=0 opts out for quick-only re-runs on big binaries.
    if os.environ.get("WINRE_GHIDRA_ANALYZE", "1").strip().lower() not in ("0", "false", "no"):
        # -noanalysis omitted -> analyzeHeadless performs auto-analysis
        pass
    else:
        cmd.append("-noanalysis")
    env = os.environ.copy()
    env["GHIDRA_SQL_QUERY"] = sql
    # Heap sizing: default 2G is slow on 16GB hosts; let operators override
    # via GHIDRA_HEADLESS_MAXMEM (e.g. 8G for a 16GB box). Favor an explicit
    # opt-in over assuming a large heap.
    if os.environ.get("GHIDRA_HEADLESS_MAXMEM"):
        env["GHIDRA_HEADLESS_MAXMEM"] = os.environ["GHIDRA_HEADLESS_MAXMEM"]
    if persist:
        # -w is not a real flag; persist is implemented inside the Java
        # post-script by reading args. We add a marker arg instead.
        cmd.insert(-2, "-postScript")
        cmd.insert(-2, f"GhidraSqlPersist.java GHIDRA_SQL_QUERY")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
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

    # GhidraSql.java prints a JSON blob on stdout; Ghidra's own INFO lines may
    # interleave or wrap it, so scan for a balanced { ... } object anywhere.
    payload = None
    out = proc.stdout or ""
    start = out.find("{")
    if start >= 0:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(out)):
            c = out[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        payload = json.loads(out[start : i + 1])
                    except json.JSONDecodeError:
                        payload = None
                    break
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
# Uses stdlib http.server so the VM needs no flask install (VM is offline).
# ---------------------------------------------------------------------------
def serve(port: int, mode: str) -> int:
    """Run a tiny HTTP server. mode='libhost' expects LibGhidraHost already
    up on the same port; mode='shim' runs headless per request (slow but
    no extra setup)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import urllib.parse

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: N802
            sys.stderr.write("[flare_ghidra_sql] " + (format % args) + "\n")

        def _reply(self, code: int, payload: dict):
            data = json.dumps(payload).encode("utf-8")
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
            if self.path != "/query":
                self._reply(404, {"ok": False, "error": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError as e:
                self._reply(400, {"ok": False, "error": str(e)})
                return
            sql = body.get("sql")
            file_ = body.get("file")
            if not sql or not file_:
                self._reply(400, {"ok": False, "error": "sql and file required"})
                return
            if mode == "libhost":
                result = query_http(file_, sql, port=port)
            else:
                result = run_query_headless(sql, Path(file_), timeout=300,
                                            persist=bool(body.get("persist")))
            self._reply(200, result)

    print(f"[flare_ghidra_sql] serving on 127.0.0.1:{port} mode={mode}", flush=True)
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
