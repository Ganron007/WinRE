#!/usr/bin/env python3
"""flarevm_toolset.py - Unified CLI for the Flare-VM SQL-first RE toolset.

IDA Pro (idasql) front-end. (Binary Ninja support was removed 2026-09-20 -
it is not part of the validated baseline; use tools/flarevm_ida_query.py or
the SQL-first Ghidra path instead.)

Usage:
  python flarevm_toolset.py ida "<SQL>" [--file <.i64|.exe>] [--write]
  python flarevm_toolset.py health

Examples:
  python flarevm_toolset.py ida "SELECT count(*) FROM funcs" --file sample.i64
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
IDA_QUERY = HERE / "flarevm_ida_query.py"


def health() -> dict:
    """Check if the IDA tooling is available on Flare-VM."""
    result = {"ida_pro": {}, "idasql": {}}

    ida_paths = [
        r"C:\Program Files\IDA Professional 9.3\idat.exe",
        r"C:\Program Files\IDA Professional 9.3\ida.exe",
        r"C:\Program Files\IDA Free 9.3\ida.exe",
    ]
    for p in ida_paths:
        if Path(p).exists():
            result["ida_pro"]["path"] = p
            # idat.exe without args opens the GUI and hangs - probe the
            # version via idasql instead (no GUI, no hang).
            idasql_candidate = p.rsplit("\\", 1)[0] + "\\idasql.exe"
            if Path(idasql_candidate).exists():
                try:
                    r = subprocess.run([idasql_candidate, "--version"],
                                       capture_output=True, text=True, timeout=10)
                    result["ida_pro"]["version"] = (r.stderr + r.stdout).strip().split("\n")[0]
                except Exception as e:
                    result["ida_pro"]["error"] = str(e)
            else:
                result["ida_pro"]["error"] = "idasql.exe not found next to idat.exe"
            break
    else:
        result["ida_pro"]["error"] = "not found"

    idasql = r"C:\Program Files\IDA Professional 9.3\idasql.exe"
    if Path(idasql).exists():
        result["idasql"]["path"] = idasql
        try:
            r = subprocess.run([idasql, "--version"], capture_output=True, text=True, timeout=10)
            result["idasql"]["version"] = (r.stderr + r.stdout).strip().split("\n")[0]
        except Exception as e:
            result["idasql"]["error"] = str(e)
    else:
        result["idasql"]["error"] = "not found"

    return result


def run_ida(sql: str, file: str | None, write: bool, http: bool, json_out: bool) -> int:
    """Run a SQL query via idasql (IDA Pro)."""
    if not IDA_QUERY.exists():
        print(f"ERROR: {IDA_QUERY} not found", file=sys.stderr)
        return 1
    if not file:
        print("ERROR: --file required for ida engine", file=sys.stderr)
        return 1
    if not Path(file).exists():
        print(f"ERROR: file not found: {file}", file=sys.stderr)
        return 1
    cmd = [sys.executable, str(IDA_QUERY), file, sql, "--json"]
    if write:
        cmd.append("--write")
    if http:
        cmd.append("--http")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print(f"ERROR: idasql query failed rc={r.returncode}", file=sys.stderr)
        if not json_out:
            print(r.stdout)
        return r.returncode
    try:
        result = json.loads(r.stdout)
    except json.JSONDecodeError:
        print(r.stdout)
        return 1
    if json_out:
        print(json.dumps(result, indent=2, default=str))
    else:
        if not result.get("ok"):
            print(f"ERROR: {result.get('error', 'unknown')}")
            return 1
        cols = result.get("columns", [])
        rows = result.get("rows", [])
        if not cols:
            print("(no results)")
            return 0
        col_w = [max(len(str(c)), 12) for c in cols]
        for row in rows:
            vals = list(row.values()) if isinstance(row, dict) else row
            for i, c in enumerate(vals):
                if i < len(col_w):
                    col_w[i] = max(col_w[i], len(str(c)))
        sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
        print(sep)
        print("| " + " | ".join(str(c).ljust(w) for c, w in zip(cols, col_w)) + " |")
        print(sep)
        for row in rows:
            vals = list(row.values()) if isinstance(row, dict) else row
            print("| " + " | ".join(str(c).ljust(w) for c, w in zip(vals, col_w)) + " |")
        print(sep)
        print(f"{result.get('row_count', 0)} row(s)")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Flare-VM SQL-first RE toolset (IDA Pro)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_health = sub.add_parser("health", help="Check tool availability")
    p_health.add_argument("--json", action="store_true")

    p_ida = sub.add_parser("ida", help="Query IDA Pro database")
    p_ida.add_argument("sql", help="SQL query")
    p_ida.add_argument("--file", help=".i64 / .idb / raw binary")
    p_ida.add_argument("--write", "-w", action="store_true", help="Persist changes")
    p_ida.add_argument("--http", action="store_true", help="Use HTTP transport")
    p_ida.add_argument("--port", type=int, default=19300, help="HTTP port (default 19300)")
    p_ida.add_argument("--json", action="store_true")

    args = ap.parse_args()

    if args.cmd == "health":
        h = health()
        if args.json:
            print(json.dumps(h, indent=2))
        else:
            print("=== Flare-VM toolset health ===")
            for tool, info in h.items():
                if "error" in info:
                    print(f"  {tool}: ERROR - {info['error']}")
                elif "path" in info:
                    v = info.get("version") or info.get("module", "?")
                    print(f"  {tool}: OK - {info['path']} ({v})")
                else:
                    print(f"  {tool}: {info}")
        return 0
    elif args.cmd == "ida":
        return run_ida(args.sql, args.file, args.write, args.http, args.json)


if __name__ == "__main__":
    sys.exit(main())
