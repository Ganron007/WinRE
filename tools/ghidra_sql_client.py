#!/usr/bin/env python3
"""ghidra_sql_client.py - Windows port of RevAI's GhidraSqlClient.

SQL-first Ghidra access for WinRE, mirroring the RevAI architecture:

    GhidraSqlClient.ghidra_query(sample, sql)
        -> urllib POST http://127.0.0.1:18080/query   (text/plain SQL)
            -> ghidrasql --http  (real SQLite-backed SQL engine)
                -> LibGhidraHost extension RPC  (running inside Ghidra headless)

There is NO fallback stub: if the engine (ghidrasql.exe / LibGhidraHost
extension / Java 21) is missing the call fails loudly. Install with
`install/setup-flarevm.ps1` (staged artifacts under C:\\Tools\\ghidrasql,
Ghidra\\Extensions\\LibGhidraHost).

The ghidrasql HTTP server is started lazily per Ghidra project (one project
per sample sha) and kept alive; the client tears down servers it started with
`taskkill /F /T` (Win32-OpenSSH/session trees do not apply here because the
server is a normal child of the helper process).

Read-only by policy: only a single SELECT / WITH..SELECT statement is allowed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths / config (env-overridable)
# ---------------------------------------------------------------------------
GHIDRASQL_BIN = Path(os.environ.get(
    "GHIDRASQL_BIN", r"C:\Tools\ghidrasql\ghidrasql.exe"))


def _find_ghidra_home() -> Path | None:
    env = os.environ.get("GHIDRA_HOME")
    if env and (Path(env) / "support" / "analyzeHeadless.bat").is_file():
        return Path(env)
    for root in (r"C:\ProgramData\chocolatey\lib\ghidra\tools", r"C:\Tools"):
        p = Path(root)
        if not p.is_dir():
            continue
        for cand in sorted(p.glob("ghidra_*")):
            if (cand / "support" / "analyzeHeadless.bat").is_file():
                return cand
    return None


GHIDRA_HOME = _find_ghidra_home()
CACHE_DIR = Path(os.environ.get("WINRE_GHIDRA_CACHE", r"C:\WinRE\cache\ghidra"))
AUDIT_LOG = Path(os.environ.get("WINRE_GHIDRA_SQL_AUDIT",
                                r"C:\WinRE\logs\ghidra-sql-audit.jsonl"))
JAVA_HOME = os.environ.get(
    "WINRE_JAVA_HOME", r"C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot")

HOST = "127.0.0.1"
PORT_DEFAULT = int(os.environ.get("GHIDRASQL_PORT", "18080"))
STARTUP_TIMEOUT = 240     # s; first start loads .gpr + opens program
PROJECT_TIMEOUT = 900     # s; analyzeHeadless import+analysis of a new sample
QUERY_TIMEOUT = 900
SERVER_LIFETIME = 7200    # s; ghidrasql --max-runtime

_SQL_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|"
    r"vacuum|reindex|grant|revoke|truncate|begin|commit|rollback|savepoint|"
    r"release|analyze)\b",
    re.IGNORECASE,
)


def validate_readonly_sql(sql: str) -> None:
    """Raise ValueError unless `sql` is a single read-only SELECT statement."""
    if not sql or not sql.strip():
        raise ValueError("empty SQL")
    stripped = re.sub(r"--[^\n]*", " ", sql)
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.DOTALL).strip()
    body = stripped[:-1] if stripped.endswith(";") else stripped
    structural = re.sub(r"'(?:[^'\\]|\\.|'')*'", " ", body)
    structural = re.sub(r'"(?:[^"\\]|\\.|"")*"', " ", structural)
    if ";" in structural:
        raise ValueError("multi-statement SQL not allowed")
    if not re.match(r"^(select|with)\b", body, re.IGNORECASE):
        raise ValueError("only SELECT queries are allowed")
    m = _SQL_FORBIDDEN_RE.search(structural)
    if m:
        raise ValueError(f"forbidden SQL keyword: {m.group(1).upper()}")


def health() -> dict:
    """Honest readiness probe (no stubs)."""
    out = {
        "ok": False,
        "ghidra_home": str(GHIDRA_HOME) if GHIDRA_HOME else None,
        "ghidrasql": GHIDRASQL_BIN.is_file(),
        "lib_ghidra_host": False,
        "java_home": JAVA_HOME if Path(JAVA_HOME).is_dir() else None,
    }
    if GHIDRA_HOME:
        out["lib_ghidra_host"] = (
            GHIDRA_HOME / "Ghidra" / "Extensions" / "LibGhidraHost").is_dir()
    out["ok"] = bool(GHIDRA_HOME and out["ghidrasql"] and out["lib_ghidra_host"])
    if not out["ok"]:
        missing = [k for k in ("ghidrasql", "lib_ghidra_host") if not out[k]]
        out["error"] = ("SQL engine incomplete: " + ", ".join(missing) +
                        " - run install/setup-flarevm.ps1 (staged SQL artifacts)")
    return out


# ---------------------------------------------------------------------------
# Ghidra project creation (analyzeHeadless import+analysis, once per sample)
# ---------------------------------------------------------------------------
def _project_paths(sample: Path) -> tuple[Path, str, str, str]:
    """Return (project_dir, project_name, program_name, sha16)."""
    import hashlib
    sha = hashlib.sha256(sample.read_bytes()).hexdigest()
    proj_dir = CACHE_DIR / sha[:16]
    return proj_dir, sha[:16], sample.name, sha


def ensure_project(sample: Path, timeout: int = PROJECT_TIMEOUT) -> dict:
    """Create the Ghidra project for `sample` if missing (import + analyze)."""
    if not GHIDRA_HOME:
        return {"ok": False, "error": "Ghidra install not found (GHIDRA_HOME)"}
    proj_dir, proj_name, prog_name, sha = _project_paths(sample)
    gpr = proj_dir / f"{proj_name}.gpr"
    ok_marker = proj_dir / ".winre_program_ok"
    if gpr.exists() and not ok_marker.exists():
        # A hard-killed headless host can leave a project with data but no
        # program (observed: OpenProgram failed -> program not found). The
        # marker is written only after a query actually succeeded; without it
        # the project is treated as corrupt and rebuilt.
        _kill_all_servers()
        import shutil
        shutil.rmtree(proj_dir, ignore_errors=True)
    if gpr.exists():
        return {"ok": True, "created": False, "project_dir": str(proj_dir),
                "project_name": proj_name, "program": prog_name, "sha256": sha,
                "ok_marker": str(ok_marker)}
    proj_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["JAVA_HOME"] = JAVA_HOME
    cmd = [str(GHIDRA_HOME / "support" / "analyzeHeadless.bat"),
           str(proj_dir), proj_name, "-import", str(sample), "-overwrite"]
    try:
        p = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"analyzeHeadless timeout {timeout}s"}
    if not gpr.exists():
        tail = ((p.stdout or "") + "\n" + (p.stderr or ""))[-1200:]
        return {"ok": False, "error": f"project not created (rc={p.returncode}): {tail}"}
    return {"ok": True, "created": True, "project_dir": str(proj_dir),
            "project_name": proj_name, "program": prog_name, "sha256": sha}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
def _probe(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


class GhidraSqlClient:
    """Lazy-start ghidrasql --http server per project + read-only queries."""

    def __init__(self, host: str = HOST, port: int = PORT_DEFAULT):
        self.host = host
        self.port = port
        self._servers: dict[str, dict] = {}

    # ---- public -----------------------------------------------------------
    def ghidra_query(self, sample: str, sql: str, max_rows: int = 200) -> dict:
        validate_readonly_sql(sql)
        h = health()
        if not h["ok"]:
            raise RuntimeError(h["error"])
        sample_p = Path(sample)
        if not sample_p.is_file():
            raise FileNotFoundError(f"sample not found: {sample}")
        proj = ensure_project(sample_p)
        if not proj.get("ok"):
            raise RuntimeError(proj.get("error"))
        base_url = self._ensure_server(proj)

        req = urllib.request.Request(
            f"{base_url}/query", data=sql.encode("utf-8"),
            headers={"Content-Type": "text/plain"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=QUERY_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"ghidrasql HTTP error {e.code}: {e.read().decode(errors='replace')}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"ghidrasql HTTP unreachable: {e}")

        if not payload.get("success"):
            err = (payload.get("first_error") or payload.get("error")
                   or "unknown error")
            results = payload.get("results", [])
            if results and results[0].get("error"):
                err = results[0]["error"]
            raise RuntimeError(f"ghidrasql SQL error: {err}")

        results = payload.get("results", [])
        columns = results[0].get("columns", []) if results else []
        rows_lists = results[0].get("rows", []) if results else []
        row_dicts = [dict(zip(columns, r)) for r in rows_lists]

        try:
            AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            with AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": time.time(), "source": "ghidra_query",
                    "sample": str(sample_p), "sql": sql,
                    "max_rows": max_rows, "result": payload}) + "\n")
        except OSError:
            pass

        try:
            (Path(proj["project_dir"]) / ".winre_program_ok").write_text(
                time.strftime("%Y-%m-%dT%H:%M:%S"), encoding="ascii")
        except OSError:
            pass
        truncated = len(row_dicts) > max_rows
        out_rows = row_dicts[:max_rows]
        return {"ok": True, "columns": columns, "rows": out_rows,
                "row_count": len(out_rows), "total_row_count": len(row_dicts),
                "truncated": truncated, "source": "ghidra_query",
                "session_id": proj["project_name"],
                "audit_path": str(AUDIT_LOG)}

    def close(self, session_id: str) -> None:
        entry = self._servers.pop(session_id, None)
        if not entry:
            return
        pid = entry["proc"].pid
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       stdin=subprocess.DEVNULL, capture_output=True)
        proj_dir = Path(entry["project_dir"])
        for lp in proj_dir.glob("*.lock*"):
            try:
                lp.unlink()
            except OSError:
                pass

    def close_all(self) -> None:
        for sid in list(self._servers):
            self.close(sid)

    # ---- internal ---------------------------------------------------------
    def _ensure_server(self, proj: dict) -> str:
        sid = proj["project_name"]
        entry = self._servers.get(sid)
        if entry and entry["proc"].poll() is None:
            if _probe(f"{entry['base_url']}/health/deep", 2.0):
                return entry["base_url"]
            self.close(sid)

        # single-tenant (RevAI behaviour): only one ghidrasql may hold a
        # project; kill leftovers and clear stale locks before starting.
        _kill_all_servers()
        for lp in Path(proj["project_dir"]).glob("*.lock*"):
            try:
                lp.unlink()
            except OSError:
                pass
        port = self.port
        while _port_in_use(port, self.host):
            port += 1
            if port > self.port + 50:
                raise RuntimeError("no free port for ghidrasql HTTP server")
        log_path = AUDIT_LOG.parent / "ghidrasql-server.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(log_path, "ab")
        env = os.environ.copy()
        env["JAVA_HOME"] = JAVA_HOME
        cmd = [str(GHIDRASQL_BIN),
               "--ghidra", str(GHIDRA_HOME),
               "--project", proj["project_dir"],
               "--project-name", proj["project_name"],
               "--program", proj["program"],
               "--http", "--port", str(port), "--bind", self.host,
               "--rpc-port", str(port + 10),
               "--readonly",
               "--max-runtime", str(SERVER_LIFETIME)]
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=log_fh,
            stderr=subprocess.STDOUT, env=env, cwd=str(AUDIT_LOG.parent))
        base_url = f"http://{self.host}:{port}"
        deadline = time.time() + STARTUP_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                tail = ""
                try:
                    tail = log_path.read_text(errors="replace")[-1200:]
                except OSError:
                    pass
                raise RuntimeError(
                    f"ghidrasql server died during startup (rc={proc.returncode}); "
                    f"log tail:\n{tail}")
            if _probe(f"{base_url}/health/deep", 1.5):
                self._servers[sid] = {"proc": proc, "base_url": base_url,
                                      "project_dir": proj["project_dir"]}
                return base_url
            time.sleep(0.5)
        self.close(sid)
        raise RuntimeError(
            f"ghidrasql server did not become healthy within {STARTUP_TIMEOUT}s")


def _kill_all_servers() -> None:
    """Single-tenant cleanup: stop any leftover ghidrasql.exe (hard kill is
    safe because sessions run read-only)."""
    subprocess.run(["taskkill", "/F", "/IM", "ghidrasql.exe"],
                   stdin=subprocess.DEVNULL, capture_output=True)


def _port_in_use(port: int, host: str) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


# ---------------------------------------------------------------------------
# CLI (used by the remote quick/deep helpers)
# ---------------------------------------------------------------------------
def _main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Ghidra SQL client (real SQL, no stubs)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_h = sub.add_parser("health")
    p_q = sub.add_parser("query")
    p_q.add_argument("sql")
    p_q.add_argument("--file", required=True)
    p_q.add_argument("--max-rows", type=int, default=200)
    p_q.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "health":
        print(json.dumps(health(), indent=2))
        return 0 if health()["ok"] else 1

    client = GhidraSqlClient()
    try:
        out = client.ghidra_query(args.file, args.sql, max_rows=args.max_rows)
    except Exception as e:  # honest failure - no stub rows
        print(json.dumps({"ok": False, "error": str(e)[:400],
                          "source": "ghidra_query"}))
        return 1
    finally:
        client.close_all()
    print(json.dumps(out, indent=None if args.json else 2))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
