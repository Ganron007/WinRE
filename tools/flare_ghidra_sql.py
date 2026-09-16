#!/usr/bin/env python3
"""flare_ghidra_sql.py - Ghidra SQL for WinRE (REAL engine, no stubs).

Architecture (mirrors RevAI exactly):

    flare_ghidra_sql.py  (this file: canonical queries + thin adapter)
        -> tools/ghidra_sql_client.py  (GhidraSqlClient)
            -> POST http://127.0.0.1:18080/query
                -> ghidrasql --http  (SQLite-backed SQL engine)
                    -> LibGhidraHost RPC inside Ghidra headless

Requirements (installed by install/setup-flarevm.ps1 from staged artifacts):
    C:\\Tools\\ghidrasql\\ghidrasql.exe
    <Ghidra>\\Ghidra\\Extensions\\LibGhidraHost   (built extension)
    JDK 21 (temurin21) pinned in Ghidra's launch.properties
    VMARGS=-Duser.name=flare-vm pinned in launch.properties (project ownership)

Output shape (unchanged for callers such as the remote quick helper):
    {"ok": true, "columns": [...], "rows": [[...], ...], "row_count": n,
     "table": "<canonical name>", "mode": "sql", "engine": "ghidrasql-http"}
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghidra_sql_client import (  # noqa: E402
    GhidraSqlClient,
    health as client_health,
)

CANONICAL_QUERIES = {
    "funcs": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 20",
    "imports": "SELECT name, module FROM imports ORDER BY module",
    "strings": ("SELECT content, address FROM strings "
                "WHERE content LIKE '%http%' OR content LIKE '%cmd%' LIMIT 50"),
    "data_items": "SELECT address, size, type FROM data_items LIMIT 20",
    "segments": "SELECT name, start_address, end_address, permissions FROM segments",
}


def _resolve(sql: str) -> tuple[str, str | None]:
    """Accept @name shortcuts or raw SQL."""
    if sql.startswith("@") and sql[1:] in CANONICAL_QUERIES:
        name = sql[1:]
        return CANONICAL_QUERIES[name], name
    return sql, None


def health() -> dict:
    h = client_health()
    out = {"ok": h.get("ok", False), "ghidra_home": h.get("ghidra_home"),
           "ghidrasql": h.get("ghidrasql"),
           "lib_ghidra_host": h.get("lib_ghidra_host"),
           "engine": "ghidrasql-http"}
    if not out["ok"]:
        out["error"] = h.get("error")
    return out


def run_query(sql: str, sample: str, timeout: int = 900,
              max_rows: int = 200) -> dict:
    """Execute SQL through the real engine. Raises on engine/SQL errors."""
    sql, table = _resolve(sql)
    client = GhidraSqlClient()
    try:
        res = client.ghidra_query(sample, sql, max_rows=max_rows)
    finally:
        client.close_all()
    rows = [[r.get(c) for c in res["columns"]] for r in res["rows"]]
    out = {"ok": True, "columns": res["columns"], "rows": rows,
           "row_count": res["row_count"],
           "total_row_count": res["total_row_count"],
           "truncated": res["truncated"],
           "mode": "sql", "engine": "ghidrasql-http"}
    if table:
        out["table"] = table
    return out


def _serve(port: int) -> int:
    """Start a ghidrasql --http for the probe project (used by ops)."""
    print(json.dumps({"error": "serve is managed by tools/ghidra_sql_client.py "
                               "(lazy per-project start)"}))
    return 1


def _main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Ghidra SQL for WinRE (real ghidrasql engine)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    p_q = sub.add_parser("query")
    p_q.add_argument("sql", help="SQL or @funcs/@imports/@strings/@data_items/@segments")
    p_q.add_argument("--file", required=True, help="sample path on the VM")
    p_q.add_argument("--max-rows", type=int, default=200)
    p_q.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "health":
        h = health()
        print(json.dumps(h, indent=2))
        return 0 if h["ok"] else 1

    try:
        out = run_query(args.sql, args.file, max_rows=args.max_rows)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)[:500],
                          "mode": "sql", "engine": "ghidrasql-http"}))
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
