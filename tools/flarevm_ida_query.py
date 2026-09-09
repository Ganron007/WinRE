#!/usr/bin/env python3
"""flarevm_ida_query.py - Run SQL queries against IDA Pro databases on Flare-VM.

Uses idasql.exe (v0.0.17, same wrapper contract as the Linux lineage).
Supports two modes:
  - One-shot: idasql -s <file> -q "<SQL>"
  - HTTP: idasql -s <file> --http <port> (then POST to /query)

Usage:
  python flarevm_ida_query.py <file> "<SQL>"
  python flarevm_ida_query.py --http <file> [--port 19300]
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# IDA Pro 9.3 install path on Flare-VM
IDASQL = os.environ.get("IDASQL") or os.environ.get("WINRE_IDASQL") or \
    r"C:\Program Files\IDA Professional 9.3\idasql.exe"


def _ida_candidates() -> list[str]:
    """IDA install dirs to probe: env override first, then common
    install-at-preference locations (IDA Pro/Free, any version, C:\\Tools)."""
    env = os.environ.get("WINRE_IDA_DIR") or os.environ.get("IDA_DIR")
    out = [env] if env else []
    out += [r"C:\Program Files\IDA Professional 9.3",
            r"C:\Program Files\IDA Professional 8.3",
            r"C:\Program Files\IDA Free 9.3",
            r"C:\Program Files\IDA Free 8.3",
            r"C:\Tools\IDA Pro 9.3",
            r"C:\Tools\IDA Free 9.3"]
    import glob as _g
    out += sorted(_g.glob(r"C:\Tools\IDA*\*") or [])
    return out


def _find_ida_exe(name: str) -> str | None:
    for d in _ida_candidates():
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def _ida_edition_note() -> dict:
    """License-flavor probe. IDA resolves licenses in the user profile
    (%APPDATA%) BEFORE the install dir — so a stale FREE license in AppData
    shadows a real PRO license in the install dir (same trap users hit).
    Only files ENDING in .hexlic count (backups like *.hexlic.bak* are
    ignored). Checks the install dir first, then the profile."""
    def _pro_in(d: str) -> str | None:
        try:
            for f in os.listdir(d):
                if f.lower().endswith(".hexlic") and "pro" in f.lower():
                    return f
        except OSError:
            return None
        return None

    def _free_in(d: str) -> str | None:
        try:
            for f in os.listdir(d):
                if f.lower().endswith(".hexlic") and f.lower().startswith("idafree"):
                    return f
        except OSError:
            return None
        return None

    for d in _ida_candidates():
        if not os.path.isdir(d):
            continue
        pro = _pro_in(d)
        if pro:
            appdata = os.path.join(os.environ.get("APPDATA", ""),
                                   "Hex-Rays", "IDA Pro")
            free = _free_in(appdata)
            if free:
                return {"edition": "shadowed", "dir": d, "pro": pro,
                        "stale": free,
                        "detail": ("A PRO license is installed but a stale "
                                   "FREE license in the user profile shadows "
                                   "it for headless runs (license resolution "
                                   "checks the profile first). Move/rename "
                                   f"'{free}' in the profile dir (keep a "
                                   "backup) so idalib sees the Pro license. "
                                   "Ghidra remains the canonical engine.")}
            return {"edition": "pro", "dir": d, "pro": pro}
    # no install-dir Pro license anywhere — check the profile alone
    appdata = os.path.join(os.environ.get("APPDATA", ""),
                           "Hex-Rays", "IDA Pro")
    if _free_in(appdata):
        return {"edition": "free", "dir": appdata,
                "detail": ("IDA Free license detected — headless "
                           "ida_query/idalib is unsupported (GUI-only). "
                           "Activate an IDA Professional license (GUI -> "
                           "Help -> activate) or point IDASQL at a Pro "
                           "install.")}
    return {"edition": "missing", "detail": "no IDA license found"}


def _ensure_i64(db_path: str, timeout: int = 900) -> tuple[bool, str]:
    """If the target has no .i64 database yet, run IDA headless auto-analysis
    (`idat -A -c -o<file>.i64`) to create one. idasql can only query an
    existing database — a raw .exe fails with rc=1 after 'Opening:'.
    Returns (ok, path_or_error)."""
    p = Path(db_path)
    if not p.exists():
        return False, f"file not found: {db_path}"
    i64 = p.with_suffix(p.suffix + ".i64")
    if i64.exists():
        return True, str(i64)
    ida = _find_ida_exe("idat.exe")
    if not ida:
        return False, ("idat.exe not found (cannot create .i64). Set "
                       "WINRE_IDA_DIR to your IDA install dir (e.g. "
                       "C:\\Program Files\\IDA Professional 9.3).")
    ed = _ida_edition_note()
    if ed.get("edition") == "free":
        return False, ("IDA Free license detected — headless auto-analysis "
                       "(.i64 creation) is unsupported. ida_query requires "
                       "IDA Professional (activate the Pro license in the "
                       "GUI, or set IDASQL/WINRE_IDA_DIR to a Pro install). "
                       "Ghidra remains the canonical static engine.")
    try:
        r = subprocess.run(
            [ida, "-A", "-c", f"-o{i64}", str(p)],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return False, f"idat -A analysis timeout after {timeout}s"
    except FileNotFoundError:
        return False, f"idat not found at {ida}"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout)[-400:]
    if not i64.exists():
        return False, f"idat completed but {i64} missing"
    return True, str(i64)


def query_oneshot(db_path: str, sql: str, write: bool = False) -> dict:
    """Run a one-shot SQL query against an IDA database or raw binary.

    Args:
        db_path: Path to .i64 / .idb / .exe / .dll (raw binary triggers analysis)
        sql: SQL query string
        write: If True, persist changes (-w flag)

    Returns:
        dict with keys: ok, rows, columns, error
    """
    ok, resolved = _ensure_i64(db_path)
    if not ok:
        return {"ok": False, "error": resolved}
    db_path = resolved

    cmd = [IDASQL, "-s", db_path, "-q", sql]
    if write:
        cmd.append("-w")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout after 600s"}
    except FileNotFoundError:
        return {"ok": False, "error": f"idasql not found at {IDASQL}"}
    stdout = result.stdout
    if result.returncode != 0 or "Error" in stdout:
        return {
            "ok": False,
            "returncode": result.returncode,
            "error": stdout[-500:],
        }

    # Parse the table output from idasql
    # Format:
    #   +-------+
    #   | col   |
    #   +-------+
    #   | val   |
    #   +-------+
    #   1 row(s)
    lines = stdout.splitlines()
    columns = []
    rows = []
    for line in lines:
        if line.startswith("|") and "---" not in line and "+" not in line:
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if not columns:
                columns = cells
            else:
                rows.append(cells)
    return {
        "ok": True,
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "raw_output": stdout,
    }


def query_http(db_path: str, sql: str, port: int = 19300, write: bool = False) -> dict:
    """Start idasql HTTP server and query via REST API.

    Returns same dict as query_oneshot but uses HTTP transport.
    """
    import urllib.request
    import time

    # Start idasql --http server
    ed = _ida_edition_note()
    if ed.get("edition") == "free":
        return {"ok": False,
                "error": ("IDA Free license detected — headless idasql HTTP "
                          "server is unsupported (GUI-only). ida_query "
                          "requires IDA Professional; Ghidra remains the "
                          "canonical static engine.")}
    proc = subprocess.Popen(
        [IDASQL, "-s", db_path, "--http", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    # Wait for /status
    base = f"http://127.0.0.1:{port}"
    for _ in range(30):
        try:
            urllib.request.urlopen(f"{base}/status", timeout=2)
            break
        except Exception:
            time.sleep(1)
    else:
        proc.kill()
        return {"ok": False, "error": "idasql HTTP server did not start in 30s"}

    # Query
    try:
        req = urllib.request.Request(
            f"{base}/query",
            data=sql.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
    except Exception as e:
        proc.kill()
        return {"ok": False, "error": str(e)}
    finally:
        proc.kill()

    if not payload.get("success"):
        return {
            "ok": False,
            "error": payload.get("first_error") or "unknown SQL error",
        }

    results = payload.get("results", [])
    if not results:
        return {"ok": True, "columns": [], "rows": [], "row_count": 0}
    columns = results[0].get("columns", [])
    rows = [dict(zip(columns, r)) for r in results[0].get("rows", [])]
    return {
        "ok": True,
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db_path", help=".i64 / .idb / raw binary")
    ap.add_argument("sql", help='SQL query, e.g. "SELECT count(*) FROM funcs"')
    ap.add_argument("--http", action="store_true",
                    help="Use HTTP transport (slower startup, faster for multiple queries)")
    ap.add_argument("--port", type=int, default=19300)
    ap.add_argument("--write", "-w", action="store_true",
                    help="Persist changes (rename, bookmark, comment)")
    ap.add_argument("--json", action="store_true",
                    help="Output as JSON instead of table")
    args = ap.parse_args()

    if args.http:
        result = query_http(args.db_path, args.sql, args.port, args.write)
    else:
        result = query_oneshot(args.db_path, args.sql, args.write)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        if not result["ok"]:
            print(f"ERROR: {result.get('error', 'unknown')}")
            sys.exit(1)
        cols = result["columns"]
        if not cols:
            print("(no columns)")
            sys.exit(0)
        # Pretty-print table
        col_w = [max(len(c), 12) for c in cols]
        for r in result["rows"]:
            for i, c in enumerate(r):
                if i < len(col_w):
                    col_w[i] = max(col_w[i], len(str(c)))
        sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
        print(sep)
        print("| " + " | ".join(c.ljust(w) for c, w in zip(cols, col_w)) + " |")
        print(sep)
        for r in result["rows"]:
            print("| " + " | ".join(str(c).ljust(w) for c, w in zip(r, col_w)) + " |")
        print(sep)
        print(f"{result['row_count']} row(s)")


if __name__ == "__main__":
    main()