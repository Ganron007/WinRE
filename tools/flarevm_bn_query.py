#!/usr/bin/env python3
"""flarevm_bn_query.py - Run SQL-like queries against Binary Ninja databases.

BN has no native SQL interface. This script writes a small driver
that uses the BN Python API and returns results as JSON.

Supports a SUBSET of SQL:
  - SELECT cols FROM funcs [WHERE size > N] [ORDER BY name|size] [LIMIT N]
  - SELECT cols FROM imports [WHERE name LIKE '%foo%']
  - SELECT cols FROM strings [WHERE content LIKE '%foo%']

Usage:
  python flarevm_bn_query.py <file.bndb> "SELECT name, address FROM funcs LIMIT 5"
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# BN Python paths on Flare-VM (try in order)
BN_PYTHONS = [
    r"C:\Python313\python.exe",
    r"C:\ProgramData\chocolatey\bin\python.exe",
    r"C:\Users\FLARE-VM\AppData\Local\Programs\Vector35\BinaryNinja\plugins\python\python.exe",
]


def find_bn_python():
    for py in BN_PYTHONS:
        if not Path(py).exists():
            continue
        try:
            r = subprocess.run(
                [py, "-c", "import binaryninja; print(binaryninja.__version__)"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0 and "5.1" in r.stdout:
                return py
        except Exception:
            continue
    return None


# This is the driver that runs in the BN Python. It must be self-contained.
DRIVER_TEMPLATE = r'''
import json
import re
import sys
import binaryninja
import fnmatch

def parse_where(where_clause):
    m = re.match(r"(\w+)\s+LIKE\s+'([^']*)'", where_clause, re.IGNORECASE)
    if m:
        return (m.group(1).lower(), "like", m.group(2))
    m = re.match(r"(\w+)\s*(=|>|<|>=|<=)\s*(.+)", where_clause, re.IGNORECASE)
    if m:
        field = m.group(1).lower()
        op = m.group(2)
        val = m.group(3).strip()
        if val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        elif val.startswith("0x"):
            val = int(val, 16)
        else:
            try:
                val = int(val)
            except ValueError:
                pass
        return (field, op, val)
    return (None, None, None)

def query_bn(bv, sql):
    sql_clean = sql.strip().rstrip(";")
    m = re.match(
        r"SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+?))?(?:\s+ORDER BY\s+(\w+)(?:\s+(ASC|DESC))?)?(?:\s+LIMIT\s+(\d+))?$",
        sql_clean, re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return {"ok": False, "error": "unsupported SQL: " + sql}
    columns = [c.strip() for c in m.group(1).split(",")]
    table = m.group(2).lower()
    where = m.group(3)
    order_by = m.group(4)
    order_dir = m.group(5) or "ASC"
    limit = int(m.group(6)) if m.group(6) else None

    rows = []
    if table == "funcs":
        for f in bv.functions:
            row = {"name": f.name, "address": f.start, "size": f.total_bytes}
            if where:
                field, op, val = parse_where(where)
                if field == "size" and op in (">", "<", "=", ">=", "<="):
                    if not eval("f.total_bytes " + op + " " + str(val)):
                        continue
                elif field == "name" and op == "like":
                    if not fnmatch.fnmatch(f.name.lower(), val.lower()):
                        continue
                elif field == "address" and op == "=":
                    if f.start != val:
                        continue
            rows.append(row)
        if order_by == "size":
            rows.sort(key=lambda r: r["size"], reverse=(order_dir == "DESC"))
        elif order_by == "name":
            rows.sort(key=lambda r: r["name"], reverse=(order_dir == "DESC"))
    elif table == "imports":
        for sym in bv.imports:
            for f in sym:
                row = {"name": f.name, "module": sym.name, "address": f.address}
                if where:
                    field, op, val = parse_where(where)
                    if field == "name" and op == "like":
                        if not fnmatch.fnmatch(f.name.lower(), val.lower()):
                            continue
                rows.append(row)
    elif table == "strings":
        for s in bv.strings:
            content = s.value if isinstance(s.value, str) else s.value.decode("utf-8", errors="replace")
            row = {"address": s.start, "content": content}
            if where:
                field, op, val = parse_where(where)
                if field == "content" and op == "like":
                    if not fnmatch.fnmatch(content.lower(), val.lower()):
                        continue
            rows.append(row)
    else:
        return {"ok": False, "error": "unsupported table: " + table}

    if columns != ["*"]:
        rows = [{c: r.get(c) for c in columns} for r in rows]

    if limit:
        rows = rows[:limit]

    return {"ok": True, "columns": columns, "rows": rows, "row_count": len(rows)}

db_path = r"__DB_PATH__"
sql = r"__SQL__"

print("Opening " + db_path + "...", file=sys.stderr)
bv = binaryninja.BinaryView.open(db_path)
if bv is None:
    print("ERROR: could not open " + db_path, file=sys.stderr)
    sys.exit(1)
print("Opened: " + str(len(bv.functions)) + " funcs", file=sys.stderr)

result = query_bn(bv, sql)
print(json.dumps(result, default=str))
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db_path", help=".bndb file or raw binary")
    ap.add_argument("sql", help="SQL query")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    if not Path(args.db_path).exists():
        print(f"ERROR: file not found: {args.db_path}", file=sys.stderr)
        sys.exit(1)

    bn_py = find_bn_python()
    if not bn_py:
        print("ERROR: no python with binaryninja module found", file=sys.stderr)
        sys.exit(1)
    print(f"Using Python: {bn_py}", file=sys.stderr)

    # Substitute paths in the driver template
    driver = DRIVER_TEMPLATE.replace("__DB_PATH__", args.db_path)
    driver = driver.replace("__SQL__", args.sql.replace("\\", "\\\\").replace('"', '\\"'))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False,
                                      dir="C:\\tools\\flarevm-test") as f:
        f.write(driver)
        tmp = f.name

    try:
        r = subprocess.run(
            [bn_py, tmp], capture_output=True, text=True, timeout=300,
        )
    finally:
        Path(tmp).unlink(missing_ok=True)

    sys.stderr.write(r.stderr)

    # Find the JSON line in stdout
    for line in reversed(r.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            if args.json:
                print(json.dumps(result, indent=2, default=str))
            else:
                if not result.get("ok"):
                    print(f"ERROR: {result.get('error', 'unknown')}")
                    sys.exit(1)
                cols = result.get("columns", [])
                if not cols:
                    print("(no columns)")
                    return
                col_w = [max(len(str(c)), 12) for c in cols]
                for row in result["rows"]:
                    vals = list(row.values()) if isinstance(row, dict) else row
                    for i, c in enumerate(vals):
                        if i < len(col_w):
                            col_w[i] = max(col_w[i], len(str(c)))
                sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
                print(sep)
                print("| " + " | ".join(str(c).ljust(w) for c, w in zip(cols, col_w)) + " |")
                print(sep)
                for row in result["rows"]:
                    vals = list(row.values()) if isinstance(row, dict) else row
                    print("| " + " | ".join(str(c).ljust(w) for c, w in zip(vals, col_w)) + " |")
                print(sep)
                print(f"{result.get('row_count', 0)} row(s)")
            return

    print(f"ERROR: no valid JSON in output:\n{r.stdout}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()