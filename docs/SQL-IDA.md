# SQL-IDA — Windows (FlareVM)

> **Status:** EXISTS (Flare) + HTTP WRAPPER (Phase 3, 2026-08-31) — `winre/idasql_server.py` on port 19300.  
> **Sources:** `Tools/flarevm-deploy/flarevm_ida_query.py`, `flarevm_toolset.py`, `SURVEY.md:26`.

## 1. Current state

| File (vendored in `tools/`) | Function |
|-----------------------------|----------|
| `flarevm_ida_query.py` | `idasql.exe v0.0.17` one-shot SQL → JSON/HTTP, verified `607 funcs, 30 imports` (`SURVEY.md:34`) |
| `flarevm_bn_query.py` | BN Python API wrapper (pending `V1.8[ ]` license) |
| `flarevm_toolset.py` | Unified CLI `health | ida | bn` (`SURVEY.md:92`) |

Install paths `SURVEY.md:31`: `C:\Program Files\IDA Professional 9.3\idat.exe`, `idasql.exe`, `C:\Python313\python.exe`.

## 2. CLI (already working — no rebuild)

```powershell
python C:\WinRE\tools\flarevm_toolset.py health
# expect: ido_ida: ok, bninja: pending

python C:\WinRE\tools\flarevm_ida_query.py "SELECT count(*) AS funcs FROM funcs" --file C:\samples\blobrunner.exe --json
# {"rows": [{"funcs": 607}]}

python C:\WinRE\tools\flarevm_toolset.py ida "SELECT name, module FROM imports LIMIT 5" --file C:\samples\foo.i64 --json
python C:\WinRE\tools\flarevm_toolset.py ida "SELECT count(*) FROM funcs" --file C:\samples\foo.i64 --http --port 19300
```

Supported SQL (`SURVEY.md:110`): full `SELECT * FROM funcs|imports|strings|segments|xrefs` + `UPDATE funcs SET name` + `INSERT INTO bookmarks/comments` with `-w` persist.

## 3. HTTP wrapper spec (NEW — to build)

Mirror the Linux `idasql` HTTP pattern so the deep-dive agent's ToolRegistry can call it remotely:

```python
# C:\WinRE\winre\idasql_server.py — tiny FastAPI / Flask wrapper
# POST /query {"file": "C:\\samples\\foo.i64", "sql": "SELECT ...", "persist": false}
# → {"ok": true, "rows": [...]}

from flask import Flask, request, jsonify
import subprocess, json, tempfile

IDASQL = r"C:\Program Files\IDA Professional 9.3\idasql.exe"

@app.post("/query")
def query():
    body = request.json
    sql = body["sql"]
    f = body["file"]
    # one-shot: idasql.exe --json --file <i64> "SELECT ..."
    proc = subprocess.run([IDASQL, "--json", "--file", f, sql], capture_output=True, text=True, timeout=60)
    return jsonify(json.loads(proc.stdout))
```

Run as service: `python C:\WinRE\winre\idasql_server.py --port 19300` (lab-net only). RevEng already has Linux `ida_sql_client.py` HTTP client — Windows side just needs the server.

BN wrapper reuse: `flarevm_bn_query.py` translates `SELECT ... FROM funcs WHERE size > N` to BN API (`SURVEY.md:118`). Keep CLI identical; HTTP endpoint `POST /bn/query` optional (guard `if bn_available()`).

## 4. Verification

```powershell
python C:\WinRE\tools\flarevm_toolset.py ida "SELECT name FROM funcs WHERE size > 100 LIMIT 3" --file C:\samples\foo.i64 --json
curl -X POST http://127.0.0.1:19300/query -H "Content-Type: application/json" -d "{\"file\":\"C:\\samples\\foo.i64\",\"sql\":\"SELECT count(*) FROM imports\"}"
# expect: {"ok": true, "rows": [{"count(*)": 30}]}
```

## References

- `Tools/flarevm-deploy/SURVEY.md:26`, `Tools/flarevm-deploy/README.md`, `CHECKLIST.md:V1.6` IDA verified.
