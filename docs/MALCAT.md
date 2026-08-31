# Malcat — Windows (FlareVM)

> **Status:** EXISTS (Windows binary) + WRAPPER (Phase 2, 2026-08-31) — `tools/malcat_win.py` mirrors `mcp_malcat.py` with the same `malcat_analyze(path, views[], profile)` facade.  
> **Role:** `WinRE` primary fast triage + script decompilation + unpacking. Remnux already uses `malcat_analyze` (`Tools/v2-deploy/v2_lib.py:3937`) as primary capa/commercial engine (`CHECKLIST.md:V5.11` `malcat PRIMARY`). This doc is the Windows side — same `malcat_analyze` facade but headless on FlareVM.

## 1. What exists

| Host | Binary | Entry | Docs |
|------|--------|-------|------|
| FlareVM `.42` | `C:\tools\malcat\malcat.exe` (or `C:\Program Files\Malcat\`) | GUI + headless lib (`malcat.mcp.py`) | `Tools\malcat-vs-ghidra-rpc.md:7` |
| Remnux `.41` | `/opt/malcat/malcat` + `MCP_MALCAT` (`mcp-malcat/mcp_malcat.py`) | `mcp-malcat` stdio `python mcp_malcat.py` (`Tools/v2-deploy/mcp-malcat/mcp_malcat.py:2`) | `V5.11.11` `malcat.capa.py` |

License: Malcat is commercial per-user (`malcat-vs-ghidra-rpc.md:18`). Headless lib requires personal license (`malcat.fr` → `license.malcat.fr`). Kesakode offline needs OEM — online `malcat.mcp.py -k <key>` works with personal (`malcat-vs-ghidra-rpc.md:141`). Do not bundle binary — installer fetched per-host.

## 2. Capabilities (unique vs Ghidra)

| Area | Ghidra SQL | Malcat |
|------|------------|--------|
| **Script decompile** | none | **VBA, AutoIt 3.26+, VBE, Excel macros, MSI tables, InnoSetup, NSIS** (`malcat-vs-ghidra-rpc.md:42`) |
| **Unpacking** | manual `upx -d` | **built-in UPX, Donut, 80+ transforms** (AES/RC4/base64/XOR/gzip chainable), overlay/carve 30+ archives (`malcat-vs-ghidra-rpc.md:55`) |
| **Signatures** | none | **400k+ constants, 2.5k YARA, 200+ anomalies, Kesakode** (`malcat-vs-ghidra-rpc.md:69`) |
| **Speed** | JVM cold ~30s for 9 MB PE | **<1s** triage, 1-5 min verdict (`malcat-vs-ghidra-rpc.md:81`) |
| **File types** | PE/ELF/MACHO | **60+** including PE/ELF/MACHO/COFF/NSIS/AutoIt/.NET/OLE/CAB/7Z/ZIP/RAR/MSI/InnoSetup/PYINST/PYZ/FAT/UDF/DMG/VHD (`malcat-vs-ghidra-rpc.md:25`) |

## 3. Malcat MCP tool (`mcp_malcat.py`)

Single tool `malcat_analyze(path, views[])` (`Tools/v2-deploy/mcp-malcat/mcp_malcat.py:41`):

```python
ALLOWED_VIEWS = ["anomalies","strings","imports","sections","yara_hits",
                 "entropy","capa_summary","functions","constants","carved",
                 "virtual_files","structures","script_decompile","unpack_donut",
                 "decompile","anomaly_locations","all"]

app = Server("mcp-malcat")
@app.call_tool()
async def call_tool(name, arguments):
    result = malcat_analyze(arguments["path"], views=arguments.get("views") or
                            ["anomalies","strings","imports"])
    return [TextContent(text=json.dumps(result))]
```

Profiles (`v2_lib.py:3972`):

| Profile | Views | Limits |
|---------|-------|--------|
| `triage` | `MALCAT_TRIAGE_VIEWS` | `MALCAT_TRIAGE_LIMITS` |
| `deep` | `MALCAT_DEEP_VIEWS` (+ decompile, anomaly_locations) | `MALCAT_DEEP_LIMITS` |
| `minimal` | `anomalies, yara_hits, imports` | triage |

`malcat_analyze` calls in order (`v2_lib.py:3944`): `analyse_file` → `analyse_infos` → `anomalies_list` → `yara_list` → `strings_top_list` → `symbols_search` → `fns_top_list` → `constants_list` → `file_list_carved` → `file_list_virtual_files` → `structs_list` → `script_decompile` → `unpack_donut` → `anomaly_list_locations` (top-N) → `fn_decompile`.

Output (`v2_lib.py:4009`): `{analysis_id, file_summary, views{}, functions[], constants[], anomalies[], carved_files[], virtual_files[], structures[], decompilations{}, script_decompile, unpack_result, errors[]}`. Always annotated ` _annotate_malcat_entropy` (`V9.5`).

## 4. FlareVM deployment

```powershell
# 1. Install Malcat Windows (once)
# download from malcat.fr, activate https://license.malcat.fr
# license file: C:\Users\FLARE-VM\AppData\Roaming\Malcat\license.dat

# 2. Headless MCP (personal license + Kesakode key)
python C:\tools\malcat\bin\malcat.mcp.py --num_analyses 5 -k <license_key>
# or GUI-attached:
# Malcat GUI > Analysis > Run MCP server → http://127.0.0.1:9009/mcp

# 3. WinRE wrapper (new — mirrors Remnux mcp-malcat)
python C:\WinRE\tools\malcat_win.py health
python C:\WinRE\tools\malcat_win.py "C:\samples\foo.exe" --profile triage --json
# expect: {"analysis_id": 1, "views": {"anomalies": [...], "yara_hits": [...]}, "functions": [...]}
```

`malcat_win.py` spec (to build — 1:1 port of `mcp_malcat.py` but Windows paths):

```python
# C:\WinRE\tools\malcat_win.py — thin wrapper around win malcat.mcp.py
from winre.malcat import malcat_analyze  # calls McpJsonClient(MCP_MALCAT_WIN)
# same signature: malcat_analyze(sample_path, views=None, profile="triage", limits=None)
# Windows: MCP_MALCAT_WIN = [r"C:\tools\malcat\bin\malcat.mcp.py", "-k", os.getenv("MALCAT_KEY")]
```

Env: `MALCAT_KEY` in `C:\WinRE\.env` (never commit). `MCP_MALCAT` on Remnux is `python /opt/scripts/mcp-malcat/mcp_malcat.py` — Windows path differs only.

## 5. Integration with WinRE orchestrator

`winre/orchestrator.py` calls Malcat **first** (fast triage), then Ghidra/IDA deep:

```python
# winre/orchestrator.py stage order on Flare
malcat = malcat_analyze(sample, profile="triage")   # <1s, anomalies+yara
ghidra = flare_ghidra_sql("SELECT * FROM funcs ...") # deep
ida    = flarevm_ida_query("SELECT ...")             # optional cross-check
# artifacts
write_json(f"logs/{sha}/dynamic/malcat-triage.json", malcat)
write_json(f"logs/{sha}/dynamic/malcat-deep.json", malcat_analyze(sample, profile="deep"))
```

Deep profile feeds `x64dbg-MCP` unpack: `malcat.views.capa_summary` → `DetectOEP` → `DumpModule` → second-pass Malcat on dumped file.

## 6. Cross-host parity

| Artifact | Remnux | FlareVM (this repo) |
|----------|--------|---------------------|
| `malcat-triage.json` | `logs/<sha>/malcat-triage.json` (via MCP) | `logs/<sha>/dynamic/malcat-triage.json` |
| `malcat-deep.json` | `logs/<sha>/malcat-deep.json` | `logs/<sha>/dynamic/malcat-deep.json` |
| YARA | `v2_lib.yara_scan()` in-proc `yara-x 1.19.0` `V9.10` | Malcat `yara_hits` + 2.5k built-in |

RevEng `quick_scan_v2.py:329` `malcat deep profile (raw JSON, capped)` appends Malcat JSON to LLM prompt — WinRE JSON is same shape, portable.

## 7. Verification

```powershell
python C:\WinRE\tools\malcat_win.py health
# expect: {"ok": true, "version": "2.x", "kesakode": "online"}

python C:\WinRE\tools\malcat_win.py C:\samples\foo.exe --profile triage --json | jq .views.anomalies[0]
# expect anomaly with locations

# cross-check with Remnux sample already in RevEng bench
# Remnux: Tools/v6_deploy/V6.3/test_run/01-snakekeylogger-931ce634ddb8/malcat-triage.json
# Flare:  C:\WinRE\logs\931ce634...\dynamic\malcat-triage.json — diff capa_summary
```

## 8. What NOT to rebuild

- Do not bundle Malcat binary — licensing forbids redistribution.
- Do not duplicate `mcp-malcat` logic — thin wrapper over `malcat.mcp.py` only.
- Office/VBE/MSI tasks → Malcat only (per `malcat-vs-ghidra-rpc.md:99` "Malcat owns this").

## References

- `Tools/malcat-vs-ghidra-rpc.md:1` (this file is the canonical comparison)
- `Tools/v2-deploy/v2_lib.py:3937` `malcat_analyze` + `Tools/v2-deploy/mcp-malcat/mcp_malcat.py:2`
- `CHECKLIST.md:V5.11` capa-malcat primary bench
