#!/usr/bin/env python3
"""ida_sql_client.py - Windows port of RevAI's IdaSqlClient.

SQL-first IDA access for WinRE, mirroring the RevAI architecture:

    IdaSqlClient.ida_query(sample, sql)
        -> urllib POST http://127.0.0.1:19300/query   (text/plain SQL)
            -> idasql --http  (real SQLite-backed SQL engine over the .i64)
                  .i64 is created on demand via `idat -A -c` (IDA Pro)

Writes go through one-shot `idasql -w -q` (persist into the .i64).

No stubs: without idasql.exe / IDA Pro the call fails loudly. idasql is a
free public release (github.com/allthingsida/idasql) - install with
`install/setup-flarevm.ps1` (staged) or `ops/provision_tools.ps1` (auto-fetch).

Read-only by policy for queries: single SELECT / WITH..SELECT only.
"""
from __future__ import annotations

import glob
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
HOST = "127.0.0.1"
PORT_DEFAULT = int(os.environ.get("IDASQL_PORT", "19300"))
STARTUP_TIMEOUT = 120     # s; idasql loads the .i64 on first start
QUERY_TIMEOUT = 300
SERVER_LIFETIME = 7200    # s
I64_TIMEOUT = 900         # s; idat auto-analysis for a new sample

AUDIT_LOG = Path(os.environ.get("WINRE_IDA_SQL_AUDIT",
                                r"C:\WinRE\logs\ida-sql-audit.jsonl"))

_SQL_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|"
    r"vacuum|reindex|grant|revoke|truncate|begin|commit|rollback|savepoint|"
    r"release|analyze)\b",
    re.IGNORECASE,
)


def validate_readonly_sql(sql: str) -> None:
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


def _find_idasql() -> Path | None:
    for env in ("IDASQL", "WINRE_IDASQL"):
        v = os.environ.get(env)
        if v and Path(v).is_file():
            return Path(v)
    ida_dir = os.environ.get("WINRE_IDA_DIR")
    cands = []
    if ida_dir:
        cands.append(Path(ida_dir) / "idasql.exe")
    cands += [Path(p) / "idasql.exe" for p in
              sorted(glob.glob(r"C:\Program Files\IDA*")) +
              sorted(glob.glob(r"C:\Tools\IDA*"))]
    for c in cands:
        if c.is_file():
            return c
    return None


def _find_idat() -> Path | None:
    ida_dir = os.environ.get("WINRE_IDA_DIR")
    cands = []
    if ida_dir:
        cands.append(Path(ida_dir) / "idat.exe")
    cands += [Path(p) / "idat.exe" for p in
              sorted(glob.glob(r"C:\Program Files\IDA*")) +
              sorted(glob.glob(r"C:\Tools\IDA*"))]
    for c in cands:
        if c.is_file():
            return c
    return None


IDASQL_BIN = _find_idasql()
IDAT_BIN = _find_idat()


def health() -> dict:
    out = {"ok": False,
           "idasql": str(IDASQL_BIN) if IDASQL_BIN else None,
           "idat": str(IDAT_BIN) if IDAT_BIN else None}
    out["ok"] = bool(IDASQL_BIN and IDAT_BIN)
    if not out["ok"]:
        out["error"] = ("IDA SQL engine incomplete (needs IDA Pro + idasql.exe; "
                        "idasql is a free release: github.com/allthingsida/idasql)")
    return out


def ensure_i64(sample: Path, timeout: int = I64_TIMEOUT) -> dict:
    """Create `<sample>.i64` via `idat -A -c` when missing."""
    if not IDAT_BIN:
        return {"ok": False, "error": "idat.exe not found (IDA Pro required)"}
    i64 = sample.with_suffix(sample.suffix + ".i64")
    if i64.is_file():
        return {"ok": True, "created": False, "i64": str(i64)}
    try:
        p = subprocess.run([str(IDAT_BIN), "-A", "-c", f"-o{i64}", str(sample)],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"idat analysis timeout {timeout}s"}
    if not i64.is_file():
        tail = ((p.stdout or "") + "\n" + (p.stderr or ""))[-800:]
        return {"ok": False, "error": f"idat did not create .i64 (rc={p.returncode}): {tail}"}
    return {"ok": True, "created": True, "i64": str(i64)}


def _probe(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


class IdaSqlClient:
    """Lazy-start idasql --http server per .i64 + read-only queries."""

    def __init__(self, host: str = HOST, port: int = PORT_DEFAULT):
        self.host = host
        self.port = port
        self._servers: dict[str, dict] = {}

    # ---- public -----------------------------------------------------------
    def ida_query(self, sample: str, sql: str, max_rows: int = 200) -> dict:
        validate_readonly_sql(sql)
        h = health()
        if not h["ok"]:
            raise RuntimeError(h["error"])
        sample_p = Path(sample)
        if not sample_p.is_file():
            raise FileNotFoundError(f"sample not found: {sample}")
        i64 = ensure_i64(sample_p)
        if not i64.get("ok"):
            raise RuntimeError(i64.get("error"))
        base_url = self._ensure_server(Path(i64["i64"]))

        req = urllib.request.Request(
            f"{base_url}/query", data=sql.encode("utf-8"),
            headers={"Content-Type": "text/plain"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=QUERY_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"idasql HTTP error {e.code}: {e.read().decode(errors='replace')}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"idasql HTTP unreachable: {e}")

        if not payload.get("success"):
            err = (payload.get("first_error") or payload.get("error")
                   or "unknown error")
            results = payload.get("results", [])
            if results and results[0].get("error"):
                err = results[0]["error"]
            raise RuntimeError(f"idasql SQL error: {err}")

        results = payload.get("results", [])
        columns = results[0].get("columns", []) if results else []
        rows_lists = results[0].get("rows", []) if results else []
        row_dicts = [dict(zip(columns, r)) for r in rows_lists]

        try:
            AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            with AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": time.time(), "source": "ida_query",
                    "sample": str(sample_p), "sql": sql,
                    "max_rows": max_rows, "result": payload}) + "\n")
        except OSError:
            pass

        truncated = len(row_dicts) > max_rows
        out_rows = row_dicts[:max_rows]
        return {"ok": True, "columns": columns, "rows": out_rows,
                "row_count": len(out_rows), "total_row_count": len(row_dicts),
                "truncated": truncated, "source": "ida_query",
                "session_id": sample_p.stem, "audit_path": str(AUDIT_LOG)}

    def ida_write(self, sample: str, sql: str) -> dict:
        """Persisting write via one-shot `idasql -w -q` (no readonly gate)."""
        h = health()
        if not h["ok"]:
            raise RuntimeError(h["error"])
        i64 = ensure_i64(Path(sample))
        if not i64.get("ok"):
            raise RuntimeError(i64.get("error"))
        try:
            p = subprocess.run(
                [str(IDASQL_BIN), "-s", i64["i64"], "-w", "-q", sql],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=QUERY_TIMEOUT, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"idasql write timeout {QUERY_TIMEOUT}s")
        out = (p.stdout or "") + (p.stderr or "")
        self.close(Path(i64["i64"]).stem)  # server would hold a stale copy
        return {"ok": p.returncode == 0, "output": out[-800:],
                "i64": i64["i64"]}

    def close(self, session_id: str) -> None:
        entry = self._servers.pop(session_id, None)
        if not entry:
            return
        subprocess.run(["taskkill", "/F", "/T", "/PID",
                        str(entry["proc"].pid)],
                       stdin=subprocess.DEVNULL, capture_output=True)

    def close_all(self) -> None:
        for sid in list(self._servers):
            self.close(sid)

    # ---- internal ---------------------------------------------------------
    def _ensure_server(self, i64: Path) -> str:
        sid = i64.stem
        entry = self._servers.get(sid)
        if entry and entry["proc"].poll() is None:
            if _probe(f"{entry['base_url']}/status", 2.0):
                return entry["base_url"]
            self.close(sid)

        port = self.port
        while _port_in_use(port, self.host):
            port += 1
            if port > self.port + 50:
                raise RuntimeError("no free port for idasql HTTP server")
        log_path = AUDIT_LOG.parent / "idasql-server.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(log_path, "ab")
        cmd = [str(IDASQL_BIN), "-s", str(i64), "--http", str(port),
               "--bind", self.host]
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=log_fh,
            stderr=subprocess.STDOUT, cwd=str(AUDIT_LOG.parent))
        base_url = f"http://{self.host}:{port}"
        deadline = time.time() + STARTUP_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                tail = ""
                try:
                    tail = log_path.read_text(errors="replace")[-1000:]
                except OSError:
                    pass
                raise RuntimeError(
                    f"idasql server died during startup (rc={proc.returncode}); "
                    f"log tail:\n{tail}")
            if _probe(f"{base_url}/status", 1.5):
                self._servers[sid] = {"proc": proc, "base_url": base_url}
                return base_url
            time.sleep(0.5)
        self.close(sid)
        raise RuntimeError(
            f"idasql server did not become healthy within {STARTUP_TIMEOUT}s")


def _port_in_use(port: int, host: str) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def _main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="IDA SQL client (real SQL, no stubs)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    p_q = sub.add_parser("query")
    p_q.add_argument("sql")
    p_q.add_argument("--file", required=True)
    p_q.add_argument("--max-rows", type=int, default=200)
    p_w = sub.add_parser("write")
    p_w.add_argument("sql")
    p_w.add_argument("--file", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "health":
        print(json.dumps(health(), indent=2))
        return 0 if health()["ok"] else 1

    client = IdaSqlClient()
    try:
        if args.cmd == "query":
            out = client.ida_query(args.file, args.sql, max_rows=args.max_rows)
        else:
            out = client.ida_write(args.file, args.sql)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)[:400],
                          "source": f"ida_{args.cmd}"}))
        return 1
    finally:
        client.close_all()
    print(json.dumps(out, indent=2))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
