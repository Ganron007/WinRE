# WinDbg-MCP — Windows (FlareVM)

> **Status:** MVP — `winre/mcp/windbg_bridge.py` (Phase 6, 2026-08-31). 12 tools over stdlib `http.server` on port 9096. pykd fast-path if importable; per-process `windbg.exe -c` fallback otherwise.  
> **Source gap:** `Tools/flarevm-deploy/dynamic/windbg_script.py` only generates `.ws` scripts (`dynamic/README.md:13`) — superseded by the bridge but still useful for headless.

## 1. Goal

`| x64dbg-MCP (71 tools, HTTP 9094) | WinDbg-MCP (12-tool MVP, HTTP 9096) |`  
Same JSON-RPC shape so `deep_dive_agentic ToolRegistry` can `POST http://192.168.77.42:9096/` with identical client.

## 2. Architecture

```
WinDbg (C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe)
  └─ pykd (pip install pykd) → DbgEng COM
         └─ windbg_mcp.py (Flask/FastAPI, :9096) — JSON-RPC {method: tools/call}
                └─ Remnux deep_dive_agentic → HTTP (fail-open REVENG_ENABLE_WINDBGMCP=0)
```

No Zig — Python only. Bind `0.0.0.0:9096` lab-net.

## 3. MVP 12 tools (spec)

| Tool | DbgEng / pykd | Args |
|------|---------------|------|
| `GetDebugState` | `isDebugging()` | — |
| `LoadDump` | `.opendump <path>` | `filePath` |
| `AttachProcess` | `.attach <pid>` | `pid` |
| `ExecuteCommand` | `dbgCommand("k; !peb; lm")` | `command` |
| `GetCallStack` | `k` | — |
| `GetRegisters` | `r` | — |
| `ReadMemory` | `db <addr> L<size>` | `address`, `size` |
| `SetBreakpoint` | `bp <addr>` | `target` |
| `Go` | `g` | — |
| `StepInto` | `p` | — |
| `DumpMemory` | `.writemem <file> <range>` | `address`, `size`, `filePath` |
| `ListModules` | `lm` | — |

Full `windbg_script.py` coverage later: conditional bps (`bp <addr> "j @eax==0 'gc'; 'gc'"`), `!analyze -v`.

## 4. Skeleton (`winre/mcp/windbg_bridge.py` to build)

```python
# C:\WinRE\winre\mcp\windbg_bridge.py
import pykd, flask
app = flask.Flask(__name__)

@app.post("/")
def rpc():
    body = flask.request.json
    name = body["params"]["name"]
    args = body["params"]["arguments"]
    if name == "ExecuteCommand":
        out = pykd.dbgCommand(args["command"])
        return {"jsonrpc":"2.0","id": body["id"], "result": {"text": out}}
    # ... dispatch 12 tools
    return {"jsonrpc":"2.0","id": body["id"], "error": {"code": -32601}}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9096)
```

## 5. Verification (after build)

```powershell
pip install pykd flask
python C:\WinRE\winre\mcp\windbg_bridge.py --port 9096
curl http://127.0.0.1:9096/ -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# expect 12 tools
curl -X POST http://127.0.0.1:9096/ -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ExecuteCommand","arguments":{"command":"lm"}}}'
```

## 6. Not in scope for MVP

- Time Travel Debugging, `dx` NatVis — later.
- Kernel debugging — user-mode only.
- SSTORE — pykd requires WinDbg Preview vs classic — pin to `Windows Kits 10 10.0.22621`.

## References

- `Tools/flarevm-deploy/dynamic/windbg_script.py:1`, `Tools/flarevm-deploy/dynamic/README.md:13`, `docs/X64DBG-MCP.md` (API parity).
