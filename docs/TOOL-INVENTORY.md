# Tool Inventory — FlareVM

> **Refresh of `Tools/v6_deploy/V6.2/FLARE-TOOL-INVENTORY.md` + `Tools/flarevm-deploy/SURVEY.md:50`.** Verify on Flare before building (`docs/TOOL-INVENTORY.md` is the rebuild checklist).

## 1. Lab binaries (Flare-VM image)

| Tool | Flare path | Version / check | Flare host? | WinRE file |
|------|-----------|-----------------|-------------|------------|
| IDA Pro | `C:\Program Files\IDA Professional 9.3\idat.exe` | 9.3 `idasql.exe v0.0.17` `SURVEY.md:31` | ✅ | `tools/flarevm_ida_query.py` |
| Binary Ninja | `C:\Users\FLARE-VM\AppData\Local\Programs\Vector35\BinaryNinja\binaryninja.exe` | 5.1.8104 Personal `SURVEY.md:40` | ✅ GUI, ⏳ Python API `V1.8[ ]` | `tools/flarevm_bn_query.py` |
| Ghidra | `C:\tools\ghidra_12.2_PUBLIC\support\analyzeHeadless.bat` | 12.2 (detect `GHIDRA_HOME`) — stale `SURVEY.md:20` lists ❌ | ✅ if installed | `tools/flare_ghidra_sql.py` (to build) |
| x64dbg | `C:\tools\x64dbg\release\x64\x64dbg.exe` | Flare latest `SURVEY.md:52` | ✅ | `integrations/x64dbg-mcp-server-main` |
| WinDbg | `C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe` | 10.0.22621 | ✅ | `winre/mcp/windbg_bridge.py` (to build) |
| dnSpy | `C:\tools\dnSpy\dnSpy.exe` | `SURVEY.md:53` | ✅ | — |
| Malcat | `C:\tools\malcat\malcat.exe` | license `AppData\Roaming\Malcat\license.dat` `docs/MALCAT.md:4` | ✅ (personal) | `tools/malcat_win.py` (to build) |
| Procmon | `C:\tools\sysinternals\Procmon64.exe` | Sysinternals | ✅ | `winre/summarize_dynamic.py` |
| FakeNet-NG | `C:\tools\fakenet\fakenet3.5\fakenet.exe` | 3.5 `SURVEY.md:55` | ✅ | `winre/enrich_pcap_tshark.py` |
| PE-sieve | `C:\tools\pe-sieve\pe-sieve64.exe` | 0.3.x | ✅ | `--pesieve` flag |
| Frida | `C:\Python313\python.exe` + `pip show frida` | 17.15.3 `SURVEY.md:56` | ✅ | `tools/frida_api_trace.py` |

Missing on fresh Flare: `pe-sieve` (choco `pe-sieve`), Malcat (manual installer), Ghidra (extract `ghidra_12.2_PUBLIC.zip` to `C:\tools\`).

## 2. Flare-side scripts (this repo `tools/` + `winre/`)

| Script | Origin | Purpose |
|--------|--------|---------|
| `frida_api_trace.py` | `Tools/flarevm-deploy/dynamic/` | hook file/reg/proc/net/crypto APIs → `frida_trace.jsonl` |
| `x64dbg_script.py` | same | gen `.x64dbg.txt` (now superseded by MCP) |
| `windbg_script.py` | same | gen `.ws` (superseded by WinDbg-MCP) |
| `apimon_filter.py` | same | gen API Monitor/procmon `.api`/`.pmc` filter |
| `flarevm_ida_query.py` | `SURVEY.md:84` | IDA SQL one-shot/HTTP |
| `flarevm_toolset.py` | `SURVEY.md:84` | unified `health|ida|bn` CLI |
| `flare_ghidra_sql.py` | **EXISTS** `docs/SQL-GHIDRA.md:4` (Phase 1) | Windows Ghidra SQL |
| `malcat_win.py` | **EXISTS** `docs/MALCAT.md:4` (Phase 2) | Windows Malcat MCP wrapper |
| `winre/idasql_server.py` | **EXISTS** `docs/SQL-IDA.md:31` (Phase 3) | IDA HTTP server (port 19300) |
| `winre/mcp/x64dbg_client.py` | **EXISTS** `docs/X64DBG-MCP.md:55` (Phase 5) | x64dbg MCP client |
| `winre/mcp/windbg_bridge.py` | **EXISTS** `docs/WINDBG-MCP.md:4` (Phase 6) | WinDbg 12-tool MVP |
| `tools/build_x64dbg_mcp.ps1` | **EXISTS** (Phase 4) | Zig build wrapper for x64dbg-MCP plugin |
| `ops/schema_parity.py` | **EXISTS** (Phase 8) | cross-host SQL parity test |
| `orchestrator.py` | `Tools/v6_deploy/V6.2/scripts/dynamic_run_v2.py` | detonation orchestrator |
| `flare_dynamic_job.ps1` | same | inner job (Frida+Procmon+FakeNet) |

## 3. Quick health (run on Flare)

```powershell
python C:\WinRE\tools\flarevm_toolset.py health
dir C:\tools\ghidra*\support\analyzeHeadless.bat
python C:\WinRE\tools\flare_ghidra_sql.py health   # after build
python C:\WinRE\tools\malcat_win.py health          # after build
curl http://127.0.0.1:9094/ -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'  # x64dbg-MCP
```

## 4. Not on Flare (Remnux-only, reference)

LibGhidraHost Linux, `ghidrasql` Linux, `speakeasy` (Unicorn), `capa` Linux `malcat.capa` — stay on Remnux (`RevEng Tools/v2-deploy/v2_lib.py:5793`).

## References

- `Tools/flarevm-deploy/SURVEY.md:50`, `Tools/v6_deploy/V6.2/FLARE-TOOL-INVENTORY.md`, `Tools/malcat-vs-ghidra-rpc.md:7`.
