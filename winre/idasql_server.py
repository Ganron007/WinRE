#!/usr/bin/env python3
"""idasql_server.py — tiny Flask HTTP server around idasql.exe (FlareVM).

Mirrors the Linux ghidrasql HTTP pattern so `deep_dive_agentic
ToolRegistry` on Remnux can `POST http://<flare-host>:19300/query`
without spawning idasql per call (cold-start ~30s on a big PE).

Endpoints:
    GET  /health                -> {ok, idasql, version}
    POST /query {file, sql, persist?}  -> idasql --json output verbatim

Run:
    python C:\\WinRE\\winre\\idasql_server.py --port 19300
    # or keep one .i64 open across queries (avoids 30s cold start):
    python C:\\WinRE\\winre\\idasql_server.py --serve-ida-i64 C:\\samples\\foo.i64 --port 19300

Security: bind 127.0.0.1 only (RevEng SSH tunnels via the lab key).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

IDASQL = os.environ.get("IDASQL", r"C:\Program Files\IDA Professional 9.3\idasql.exe")


def _idasql_version() -> str:
    try:
        cp = subprocess.run([IDASQL, "--version"], capture_output=True, text=True,
                            timeout=10, encoding="utf-8", errors="replace")
        return (cp.stdout or cp.stderr).strip().splitlines()[0]
    except Exception as e:
        return f"error: {e}"


def health() -> dict:
    return {
        "ok": Path(IDASQL).is_file(),
        "idasql": IDASQL,
        "idasql_exists": Path(IDASQL).is_file(),
        "version": _idasql_version() if Path(IDASQL).is_file() else None,
    }


def _run_oneshot(db_path: str, sql: str, persist: bool, timeout: int = 120) -> dict:
    p = Path(db_path)
    if not p.is_file():
        return {"ok": False, "error": f"file not found: {db_path}"}
    # idasql can only query an existing .i64 — auto-create it from a raw
    # PE/DLL via idat -A headless analysis if needed.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        from tools.flarevm_ida_query import _ensure_i64
    except Exception:
        _ensure_i64 = None
    if _ensure_i64:
        ok, resolved = _ensure_i64(db_path, timeout=timeout)
        if not ok:
            return {"ok": False, "error": resolved}
        db_path = resolved
    cmd = [IDASQL, "-s", db_path, "-q", sql]
    if persist:
        cmd.append("-w")
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                            encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout {timeout}s"}
    except FileNotFoundError:
        return {"ok": False, "error": f"idasql not found: {IDASQL}"}

    if cp.returncode != 0:
        return {"ok": False, "returncode": cp.returncode,
                "error": (cp.stdout or cp.stderr)[-600:]}

    # idasql prints a table; parse it into rows
    columns, rows = [], []
    for line in (cp.stdout or "").splitlines():
        if line.startswith("|") and "---" not in line and "+" not in line:
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if not columns:
                columns = cells
            else:
                rows.append(cells)
    return {"ok": True, "columns": columns, "rows": rows,
            "row_count": len(rows), "raw_output": cp.stdout}


def _free_port() -> int:
    """Ask the OS for a free ephemeral port (avoids collisions between
    concurrent per-query idasql HTTP servers)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_http(db_path: str, sql: str, port: int, persist: bool,
              timeout: int = 60) -> dict:
    """Start `idasql --http` per call (slow but stateless)."""
    proc = subprocess.Popen(
        [IDASQL, "-s", db_path, "--http", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace",
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(30):
        try:
            urllib.request.urlopen(f"{base}/status", timeout=2).read()
            break
        except Exception:
            time.sleep(1)
    else:
        proc.kill()
        return {"ok": False, "error": "idasql HTTP server did not start in 30s"}

    try:
        req = urllib.request.Request(
            f"{base}/query", data=sql.encode("utf-8"),
            headers={"Content-Type": "text/plain"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read())
    except Exception as e:
        proc.kill()
        return {"ok": False, "error": str(e)}
    finally:
        proc.kill()

    if not payload.get("success"):
        return {"ok": False, "error": payload.get("first_error") or "unknown SQL error"}
    results = payload.get("results") or []
    if not results:
        return {"ok": True, "columns": [], "rows": [], "row_count": 0}
    cols = results[0].get("columns", [])
    rows = [dict(zip(cols, r)) for r in results[0].get("rows", [])]
    return {"ok": True, "columns": cols, "rows": rows, "row_count": len(rows)}


# ---------------------------------------------------------------------------
# Optional persistent mode: keep `idasql --http <port>` running for one .i64
# ---------------------------------------------------------------------------
class _PersistentServer:
    def __init__(self, db_path: str, port: int):
        self.db_path = db_path
        self.port = port
        self.proc: subprocess.Popen | None = None
        self._start()

    def _start(self) -> None:
        self.proc = subprocess.Popen(
            [IDASQL, "-s", self.db_path, "--http", str(self.port), "--bind", "127.0.0.1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace",
        )
        base = f"http://127.0.0.1:{self.port}"
        for _ in range(30):
            try:
                urllib.request.urlopen(f"{base}/status", timeout=2).read()
                return
            except Exception:
                time.sleep(1)
        raise RuntimeError("persistent idasql --http did not start in 30s")

    def query(self, sql: str, persist: bool, timeout: int = 30) -> dict:
        # idasql --http does not support per-query persist; we forward as-is.
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/query", data=sql.encode("utf-8"),
                headers={"Content-Type": "text/plain"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = json.loads(r.read())
        except Exception as e:
            return {"ok": False, "error": str(e)}
        if not payload.get("success"):
            return {"ok": False, "error": payload.get("first_error") or "unknown"}
        results = payload.get("results") or []
        if not results:
            return {"ok": True, "columns": [], "rows": [], "row_count": 0}
        cols = results[0].get("columns", [])
        rows = [dict(zip(cols, r)) for r in results[0].get("rows", [])]
        return {"ok": True, "columns": cols, "rows": rows, "row_count": len(rows)}

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()


# ---------------------------------------------------------------------------
# HTTP server (stdlib http.server — no flask dependency; VM is offline)
# ---------------------------------------------------------------------------
def make_app(persistent_db: str | None, persistent_port: int):
    """Create a stdlib HTTP server around idasql. Returns the ThreadingHTTPServer
    instance (persistent mode keeps one idasql --http open for a single .i64)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    pserver: _PersistentServer | None = None
    if persistent_db:
        try:
            pserver = _PersistentServer(persistent_db, persistent_port)
        except Exception as e:
            print(f"[idasql_server] persistent mode failed: {e}", file=sys.stderr)

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: N802
            sys.stderr.write("[idasql_server] " + (format % args) + "\n")

        def _reply(self, code: int, payload: dict):
            data = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                out = health()
                out["persistent"] = bool(pserver)
                if pserver:
                    out["persistent_db"] = pserver.db_path
                self._reply(200, out)
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
            persist = bool(body.get("persist", False))
            if not sql or not file_:
                self._reply(400, {"ok": False, "error": "sql and file required"})
                return
            if pserver and Path(file_).resolve() == Path(pserver.db_path).resolve():
                self._reply(200, pserver.query(sql, persist))
            elif body.get("use_http"):
                self._reply(200, _run_http(file_, sql, port=_free_port(),
                                           persist=persist))
            else:
                self._reply(200, _run_oneshot(file_, sql, persist))

    httpd = ThreadingHTTPServer(("127.0.0.1", persistent_port if persistent_db else 19300), _Handler)
    return httpd


def main() -> int:
    ap = argparse.ArgumentParser(description="Flare-VM idasql HTTP server")
    ap.add_argument("--port", type=int, default=19300)
    ap.add_argument("--serve-ida-i64", help="keep idasql --http open for this .i64")
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()

    h = health()
    if not h["ok"]:
        print(f"ERROR: {h.get('error', 'idasql not found')}", file=sys.stderr)
        return 1

    persistent_port = args.port + 1 if args.serve_ida_i64 else args.port
    httpd = make_app(args.serve_ida_i64, persistent_port)
    print(f"[idasql_server] listening on http://{args.bind}:{args.port}  "
          f"idasql={IDASQL}  persistent={args.serve_ida_i64 or 'no'}",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if httpd:
            httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
