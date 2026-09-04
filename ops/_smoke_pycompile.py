
import json, py_compile, sys
from pathlib import Path
root = Path(r"C:\WinRE")
out = {"ok": True, "compiled": 0, "errors": []}
targets = list((root / "winre").glob("*.py")) + list((root / "tools").glob("*.py"))
for p in targets:
    try:
        py_compile.compile(str(p), doraise=True)
        out["compiled"] += 1
    except Exception as e:
        out["ok"] = False
        out["errors"].append(f"{p.name}: {e}")
print(json.dumps(out))
