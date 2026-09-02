
"""Remote SQL helper for the LangGraph agent — runs on FlareVM.

Usage: python _remote_sql_helper.py <ghidra|ida> <sample_path> <sql>
Prints JSON: {"ok": true, "columns": [...], "rows": [...], "row_count": N}
"""
import json
import subprocess
import sys
from pathlib import Path

engine = sys.argv[1]
sample = Path(sys.argv[2])
sql = sys.argv[3]
py = sys.executable
tools = Path(__file__).resolve().parents[1] / "tools"

if engine == "ghidra":
    p = subprocess.run([py, str(tools / "flare_ghidra_sql.py"), "query", sql,
                        "--file", str(sample), "--json"],
                       capture_output=True, text=True, timeout=900,
                       encoding="utf-8", errors="replace")
else:  # ida
    p = subprocess.run([py, str(tools / "flarevm_ida_query.py"), str(sample),
                        sql, "--json"],
                       capture_output=True, text=True, timeout=120,
                       encoding="utf-8", errors="replace")
try:
    out = json.loads(p.stdout)
    print(json.dumps(out))
except json.JSONDecodeError:
    print(json.dumps({"ok": False, "error": (p.stderr or p.stdout)[-300:]}))
