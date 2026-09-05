# x64dbg-MCP — Windows (FlareVM)

> **Source:** NOT vendored here — fetch upstream (MIT): `https://github.com/duty1g/x64dbg-mcp-server`
> into `integrations/x64dbg-mcp-server-main/` (gitignored), then apply our
> one-line fix from `tools/x64dbg-mcp-winre.patch` (surfacing hardware-BP
> failures as errors instead of success text).
> **Binary:** Zig single-file plugin `x64dbg-MCP-Server.dp64/.dp32` (`build.zig:5`); setup-flarevm.ps1 builds it when zig is on PATH.

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
# build anywhere (Zig 0.16-dev) — wrapper added Phase 4
powershell -ExecutionPolicy Bypass -File C:\WinRE\tools\build_x64dbg_mcp.ps1
# or directly:
# cd integrations\x64dbg-mcp-server-main
# zig build -Doptimize=ReleaseSafe --prefix dist
# → dist/x64/plugins/x64dbg-MCP-Server.dp64 + dist/x32/plugins/x64dbg-MCP-Server.dp32

# deploy
xcopy /E dist\x64\plugins\x64dbg-MCP-Server.dp64 C:\tools\x64dbg\x64\plugins\
xcopy /E dist\x32\plugins\x64dbg-MCP-Server.dp32 C:\tools\x64dbg\x32\plugins\
# launch x64dbg — server auto-starts, check log: "MCP server listening on 0.0.0.0:9094"
```

Verify:

```powershell
curl http://127.0.0.1:9094/ -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
# expect 71 tools

# MCP client (Claude/.mcp.json)
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

WinRE `winre/mcp/x64dbg_client.py` wraps this HTTP — see `docs/internal/ARCHITECTURE.md:4` transport.

## 5. Limits

- `TraceInto` max 100 instr (`tools.zig:381`), `ReadMemory` 4096 (`tools.zig:997`).
- In-process — debugger crash kills MCP (use `RestartDebug`).
- `GetPEB`/`GetSEHChain` x32-focused — x64 PEB via `EvalExpression` fallback.

## References

- `integrations/x64dbg-mcp-server-main/README.md:27`, `src/mcp/tools.zig:30`, `src/core/bridge.zig:338`.
