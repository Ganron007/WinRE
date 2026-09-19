# x64dbg-MCP — Windows (FlareVM)

> **Source:** NOT vendored here — fetch upstream (MIT): `https://github.com/duty1g/x64dbg-mcp-server`
> into `integrations/x64dbg-mcp-server-main/` (gitignored), then apply our
> one-line fix from `tools/x64dbg-mcp-winre.patch` (surfacing hardware-BP
> failures as errors instead of success text).
> **Binary:** Zig single-file plugin `x64dbg-MCP-Server.dp64/.dp32` (`build.zig:5`); setup-flarevm.ps1 auto-provisions the toolchain from `C:\Tools-staged\zig-*.zip` (zig 0.14+, `build.zig.zon` minimum) and builds from `C:\WinRE\integrations\x64dbg-mcp-server*`.
> **Status:** implemented - build/deploy is automated by `install/setup-flarevm.ps1`
> (both arches) and `:9094` is scoped to `LocalSubnet` by a firewall rule.
> **Audience:** integrators and agent authors using the debugger MCP.

## 1. What it is

Native MCP plugin living inside `x64dbg.exe` (`src/core/bridge.zig:338` resolves `x64bridge.dll`/`x64dbg.dll` at load). Spins HTTP server on background thread, `POST /` JSON-RPC 2.0 (`src/core/mcp_server.zig`), `streamable HTTP + SSE` (`README.md:31`). Zero deps, auto-starts (`src/main.zig`).

Default ports `README.md:53`: `0.0.0.0:9094` (x64) / `9095` (x32). Config dialog `Plugins > x64dbg-MCP Server > Configure` (`src/core/config.zig` persists `mcp_config.json`).

## 2. 71 tools (`src/mcp/tools.zig:30`)

| Category | Tools |
|----------|-------|
| Always | `GetDebugState`, `LoadBinary`, `ExecuteDebuggerCommand`, `ListCommandsByCategory`, `SearchForStrings`, `GetEventLog` (64-ring), `ClearEventLog`, `EvalExpression`, `AttachProcess`, `Echo` |
| Debug-only | `GetCurrentAddress`, `Disassemble`/`DisassembleFunction`, `ReadMemory`(4096), `WaitForPause`, `run`/`StepInto`/`StepOver`/`StepOut`/`PauseDebug`/`StopDebug`/`RestartDebug`/`RunToAddress`, `SetBreakpoint`/`SetHardwareBreakpoint`/`SetConditionalBreakpoint`/`Enable/Disable/Toggle/Delete/ListBreakpoints`/`DeleteAllBreakpoints`/`ResetHitCount`, `GetAllRegisters`/`SetRegister`, `GetCallStack`/`GetThreads`/`SwitchThread`/`Suspend/ResumeThread`, `ListModules`/`GetMemoryMap`/`GetDumpableRegions`/`AllocateMemory`/`FreeMemory`/`WriteMemToAddress`/`RestorePatches`/`Assemble`, `CommentOrLabelAtAddress`/`Set/Delete/ListBookmark`, `GetImports`/`GetExports`/`SearchSymbols`/`ListSymbols`/`GetPatches`/`FindPattern`/`GetStrings`/`GetReferences`/`GetFunctions`/`AnalyzeModule`/`DetectOEP`/`DumpMemory`/`DumpModule`/`GetSEHChain`/`GetPEB`/`GetArguments`/`FollowPointer`/`WatchExpressions`/`TraceInto(100)` |

Event callbacks 22 (`README.md:37`): `CB_INITDEBUG`, `CB_STOPDEBUG`, `CB_BREAKPOINT`, `CB_EXCEPTION`, etc. — surfaced via `GetEventLog`.

## 3. Install (FlareVM)

```powershell
# build anywhere (Zig 0.14+; setup-flarevm.ps1 uses C:\Tools\zig or the staged zip) — wrapper added Phase 4
powershell -ExecutionPolicy Bypass -File C:\WinRE\tools\build_x64dbg_mcp.ps1
# or directly:
# cd integrations\x64dbg-mcp-server-main
# zig build -Doptimize=ReleaseSafe --prefix dist
# → dist/x64/plugins/x64dbg-MCP-Server.dp64 + dist/x32/plugins/x64dbg-MCP-Server.dp32

# deploy BOTH arches (x64dbg.exe loads only dp64; x32dbg.exe loads dp32).
# setup-flarevm.ps1 does this arch-aware and fails when dp64 is missing.
xcopy /E dist\x64\plugins\x64dbg-MCP-Server.dp64 C:\Tools\x64dbg\release\x64\plugins\
xcopy /E dist\x32\plugins\x64dbg-MCP-Server.dp32 C:\Tools\x64dbg\release\x32\plugins\
# launch x64dbg - server auto-starts, check log: "MCP server listening on 0.0.0.0:9094"
# Exposure: bind stays 0.0.0.0 (the control plane drives :9094 over the LAN);
# setup adds a firewall allow rule scoped to LocalSubnet (default block else).
# Config path quirk: the plugin resolves mcp_config.json via
# GetModuleFileNameA(NULL) -> the x64dbg.exe dir (release\x64|release\x32),
# NOT the plugins dir. Set {"IpAddress":"127.0.0.1"} there for a local-only box.
```

Verify:

```powershell
curl http://127.0.0.1:9094/ -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
# expect 71 tools

# MCP client (.mcp.json)
# {"mcpServers":{"x64dbg":{"type":"http","url":"http://<FLARE_HOST>:9094/"}}}
```

## 4. Usage pattern (agentic)

```
LLM: LoadBinary filePath=C:\samples\foo.exe → Paused at 0x7FF7...
LLM: GetDebugState → isDebugging:true, cip:0x...
LLM: AnalyzeModule module=foo → sections, EP, image size
LLM: DetectOEP module=foo → OEP=0x401000 (packed)
LLM: DumpModule module=foo filePath=C:\WinRE\logs\<sha>\x64dbg\dump\foo.dmp → for Malcat second-pass
LLM: SetBreakpoint target=0x401000 → run → WaitForPause (30s) → GetAllRegisters → ReadMemory address=cip size=64
```

WinRE `winre/mcp/x64dbg_client.py` wraps this HTTP — see [`SSH-CONTRACT.md`](SSH-CONTRACT.md) section 4 (MCP over HTTP).

> **WinRE pipeline note (debug loops):** the deep unpack prepass runs
> `oep_by_section → oep_by_esp` (explicit entry BP, stable-pause gate,
> fresh-session retry, heap-OEP gate) and produces the artifact with
> **pe-sieve `/imp` escalation `1 -> 3 -> 4 -> 5`** at the paused OEP (3/4/5 = documented "build the ImportTable from scratch from found IATs" R0/R1/R2) until the produced image parses with imports; `imp_modes_tried` is recorded in the dump evidence (savedata `DumpModule` stays the fallback). Managed (.NET) samples skip the native OEP/unpack path entirely (no native entry-point pause) - `dotnet_analyze` + `x64dbg_wpm_dump` + `windbg` are used instead, and the MCP ensure waits up to 90 s for the plugin to bind. The dynamic OEP/dump step
> (`orchestrator._x64dbg_oep_dump`) still uses `DumpModule` into
> `dynamic/x64dbg/dump/`.

## 5. Limits

- `TraceInto` max 100 instr (`tools.zig:381`), `ReadMemory` 4096 (`tools.zig:997`).
- In-process — debugger crash kills MCP (use `RestartDebug`).
- `GetPEB`/`GetSEHChain` x32-focused — x64 PEB via `EvalExpression` fallback.

## References

- `integrations/x64dbg-mcp-server-main/README.md:27`, `src/mcp/tools.zig:30`, `src/core/bridge.zig:338`.
