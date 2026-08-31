# SQL-Ghidra — Windows (FlareVM)

> **Status:** EXISTS — `tools/flare_ghidra_sql.py` (Phase 1, 2026-08-31). Two paths: `headless` (analyzeHeadless + `GhidraSql.java` post-script) and `libhost` (LibGhidraHost HTTP).  
> **Goal:** Windows port of Remnux `ghidra_sql_client.py` + `LibGhidraHost` so Flare can answer the same SQL as `quick_scan_v2.py:GHIDRA_EVIDENCE`.

## 1. What exists to copy

| Source (RevEng) | What to reuse |
|-----------------|---------------|
| `Tools/v2-deploy/ghidra_sql_client.py` | 300-line wrapper: `ensure_ghidra`, `run_ghidra_query(sql, timeout)`, `health` |
| `Tools/v7_deploy/scripts/v2_lib.py` quick_scan GHIDRA_EVIDENCE | 5 canonical queries (see §3) |
| `Tools/v9_deploy/ghidra-extensions/cadre-pe-loader/` | CADRE PE Loader (Apache 2.0) — installed `/opt/ghidra/Ghidra/Extensions/CADRE` on `.41`, same jar on Windows |
| `ops/schema_parity.py` | Parity runner `OK=4 FAIL=0` on `ghidrasql 0.0.4` — reuse for Windows |

Remnux versions: `ghidrasql v0.0.4` CLI (`--program` not `--initial-program`, `V9.20`), `LibGhidraHost v0.0.5` (`/opt/ghidra/Ghidra/Extensions/LibGhidraHost`).

## 2. Windows layout

```
C:\tools\ghidra_12.2_PUBLIC\          # or C:\ghidra — detect via GHIDRA_HOME / registry
  support\analyzeHeadless.bat
  Ghidra\Features\Base\ghidra_scripts\
  Ghidra\Extensions\
    LibGhidraHost\                    # copy from RevEng build or rebuild with Gradle
    CADRE\                            # CADRE PE Loader
C:\WinRE\tools\flare_ghidra_sql.py   # new — this spec
C:\WinRE\cache\ghidra\               # per-sample project dir (gitignored)
```

Install:

```powershell
# 1. Verify Ghidra
dir C:\tools\ghidra*\support\analyzeHeadless.bat
# 2. Install LibGhidraHost (copy built jar from RevEng or rebuild)
xcopy /E /I C:\WinRE\deps\LibGhidraHost C:\tools\ghidra_12.2_PUBLIC\Ghidra\Extensions\LibGhidraHost
# 3. Install CADRE loader
xcopy /E /I C:\WinRE\deps\CADRE C:\tools\ghidra_12.2_PUBLIC\Ghidra\Extensions\CADRE
```

## 3. Canonical queries (must match Remnux)

From `quick_scan_v2.py:GHIDRA_EVIDENCE` (+ `V9.20` `address→addr AS address` fix):

```sql
-- 1. funcs
SELECT name, addr AS address, size FROM funcs ORDER BY size DESC LIMIT 20;

-- 2. imports
SELECT name, module FROM imports ORDER BY module;

-- 3. strings (high-signal)
SELECT content, addr AS address FROM strings WHERE content LIKE '%http%' OR content LIKE '%cmd%' LIMIT 50;

-- 4. data_items (entry, sections entropy via LIEF elsewhere)
SELECT addr AS address, size, type FROM data_items LIMIT 20;

-- 5. segments
SELECT name, start, end, perm FROM segments;
```

Add on Windows (same client):

```sql
SELECT count(*) FROM xrefs WHERE to_addr = 0x401000;
SELECT * FROM funcs WHERE size > 100;
```

## 4. `flare_ghidra_sql.py` spec (new file to build)

```python
# C:\WinRE\tools\flare_ghidra_sql.py
# Usage mirrors Linux client:
#   python flare_ghidra_sql.py health
#   python flare_ghidra_sql.py "SELECT count(*) FROM funcs" --file C:\samples\foo.exe --json
#   python flare_ghidra_sql.py --serve --port 19301   # HTTP for MCP

import subprocess, json, tempfile, pathlib

GHIDRA_HOME = os.environ.get("GHIDRA_HOME", r"C:\tools\ghidra_12.2_PUBLIC")
HEADLESS = pathlib.Path(GHIDRA_HOME) / "support" / "analyzeHeadless.bat"

def run_ghidra_query(sql: str, sample: Path, timeout=120) -> dict:
    with tempfile.TemporaryDirectory() as proj:
        cmd = [
            str(HEADLESS), proj, "WinRE",
            "-import", str(sample),
            "-loader", "CADRE PE Loader",   # fallback to "PE Loader" if CADRE missing
            "-scriptPath", str(Path(__file__).parent / "ghidra_scripts"),
            "-postScript", "GhidraSql.java", sql,
            "-noanalysis", "-deleteProject"
        ]
        # alternative: LibGhidraHost headless via java -jar ghidra-sql.jar --program ...
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        return json.loads(proc.stdout)  # {ok, rows, error}

# CLI: health | query | --serve (Flask/FastAPI tiny HTTP like Linux ghidrasql)
```

Notes:

- Windows `analyzeHeadless.bat` args differ from Linux `analyzeHeadless` shell — use `proj` + `WinRE` naming.
- Prefer `LibGhidraHost` Java server if built: `java -cp GhidraSql.jar com.cadre.LibGhidraHost --port 19301` then `POST /query {sql}` — same as Linux `ghidrasql` HTTP.
- Keep `CADRE PE Loader` fallback (packed samples need import recovery `V9.12`).

## 5. Windows quirks to document while building

- `addr` vs `address` — `ghidrasql 0.0.4` uses `addr` column (aliased `AS address` for parity). Test with `ops/schema_parity.py` Windows port.
- Timeout `120s` for `cff_detect` parity (`V2.37` fix: `cfg_edges` per-func).
- Project `deleteProject` after each query to avoid `C:\WinRE\cache\ghidra` bloat.
- Long paths: `C:\samples\` not `C:\Users\FLARE-VM\Downloads\` (spaces).

## 6. Verification on Flare

```powershell
python C:\WinRE\tools\flare_ghidra_sql.py health
# expect: {"ok": true, "ghidra_home": "C:\\tools\\ghidra_12.2_PUBLIC", "lib_host": "ok", "cadre_loader": "ok"}

python C:\WinRE\tools\flare_ghidra_sql.py "SELECT count(*) as funcs FROM funcs" --file C:\samples\foo.exe --json
# expect: {"ok": true, "rows": [{"funcs": 607}]}

# parity
python C:\WinRE\ops\schema_parity.py --host flare  # reuse RevEng ops/schema_parity.py logic
# expect: OK=4 FAIL=0
```

## 7. What this doc is NOT

- Not Linux Ghidra — that stays `Tools/v2-deploy/ghidra_sql_client.py`.
- Not replacing `speakeasy` emulation — Ghidra SQL is static, not dynamic.

## References

- RevEng `Tools/v2-deploy/ghidra_sql_client.py:1`, `Tools/v9_deploy/PLAN.md:V9.20`, `CHECKLIST.md:V2.36`, `V2.37`.
