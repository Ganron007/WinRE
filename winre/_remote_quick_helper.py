
"""Remote quick-triage helper — runs on FlareVM, prints JSON to stdout.

Usage: python _remote_quick_helper.py <sample_path> --json
Output: {"evidence": {ghidra: {...}, ida: {...}}}
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sample = Path(sys.argv[1])
out = {"ghidra": {}, "ida": {}}
py = sys.executable

def run(script, *args):
    p = subprocess.run([py, str(script), *args], capture_output=True, text=True,
                       timeout=900, encoding="utf-8", errors="replace")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": (p.stderr or p.stdout)[-200:]}

tools = Path(__file__).resolve().parents[1] / "tools"
g = run(tools / "flare_ghidra_sql.py", "query", "@funcs", "--file", str(sample), "--json")
if g.get("ok"):
    out["ghidra"] = {"func_rows": len(g.get("rows") or [])}
else:
    out["ghidra"] = {"error": g.get("error")}

i64 = sample.with_suffix(sample.suffix + ".i64")
if i64.is_file():
    i = run(tools / "flarevm_ida_query.py", str(sample), "SELECT count(*) FROM funcs", "--json")
    if i.get("ok"):
        rows = i.get("rows") or []
        out["ida"] = {"func_count": rows[0][0] if rows and rows[0] else None}
    else:
        out["ida"] = {"error": i.get("error")}
else:
    out["ida"] = {"skipped": "no .i64 on VM (deep dive will create)"}

print(json.dumps({"evidence": out}))
