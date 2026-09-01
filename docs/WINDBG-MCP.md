# WinDbg-MCP — Windows (FlareVM)

> **Status:** REWIRED (2026-09-01) — official **`mcp-windbg`** (svnscha/mcp-windbg, MIT, PyPI) replaces the homemade 12-tool bridge. 10 tools over MCP streamable-http on :9097. Crash-dump analysis + remote + kernel debugging, driven by `cdb.exe`/`kd.exe` (auto-detected from the Store WinDbg or Windows Kits).

## 1. Why this changed

The old `winre/mcp/windbg_bridge.py` (12-tool per-process `windbg -c` fallback) is **superseded**:
- Per-call windbg spawn hangs without a debug target (no headless attach to a live GUI process from an SSH session).
- Store-version WinDbg path was AppX-discoverable, not fixed.
- pykd doesn't exist on Windows (Linux-only pip package).

`mcp-windbg` solves all of it: it wraps `cdb.exe` with proper session lifecycle (per-session ids, per-call timeouts, CTRL+BREAK resync) and works **headlessly for dump analysis** (the case that matters on the lab VM).

## 2. Install (on FlareVM, internet needed)

```powershell
C:\Python313\python.exe -m pip install mcp-windbg
# → mcp-windbg 1.2.1 + mcp 2.1.1 (streamable-http support)
```

Prereq: WinDbg classic (Windows Kits Debuggers) **or** Store WinDbg — both ship `cdb.exe`/`kd.exe` (auto-detected). Classic was added on FlareVM via `winsdksetup.exe /features OptionId.WindowsDesktopDebuggers /quiet`.

## 3. Run (MCP streamable-http)

```powershell
# operator (VM console) — or winre/mcp/start_servers.ps1
C:\Python313\python.exe -m mcp_windbg --transport streamable-http --host 127.0.0.1 --port 9097
# → MCP WinDbg server running on http://127.0.0.1:9097/mcp
```

Options: `--cdb-path`, `--kd-path`, `--symbols-path`, `--filter-script`, `--timeout`, `--transport {stdio,streamable-http}`.

## 4. 10 tools (verified on FlareVM)

| Tool | Purpose |
|------|---------|
| `list_dumps` | list crash dumps in a directory |
| `open_cdb_dump` | open + triage a crash dump (auto `!analyze`) |
| `open_cdb_remote` | attach to user-mode `cdb -remote` server |
| `open_kd_session` | kernel target (`-k`, KDNET/pipe/serial) |
| `run_cdb_command` | run a command on a user-mode session |
| `run_kd_command` | run a command on a kernel session |
| `close_cdb_session` / `close_kd_session` | close a session |
| `send_ctrl_break` | break into a running live session |
| `wait_for_break` | wait for target to stop after `g` |

Every `open_*` returns an opaque `session_id`; pass it to `run_*`/`close_*`.

## 5. WinRE client

`winre/mcp/windbg_client.py` — `WinDbgMCPClient`, same `{ok, result, error}` shape as `X64DbgClient`/`MalcatClient`. Handles the MCP streamable-http lifecycle (initialize → `Mcp-Session-Id` header → tools/call). Note the **trailing slash** on the base URL (`/mcp/`) — the server 307-redirects `/mcp` → `/mcp/`, which urllib mishandles for POST.

```python
from winre.mcp import WinDbgMCPClient
c = WinDbgMCPClient()
print(c.is_up(), c.list_tools())
r = c.open_cdb_dump(r"C:\dumps\app.dmp")       # session_id in result
r = c.run_cdb_command(sid, "kb")               # call stack
c.close_cdb_session(sid)
```

## 6. Limits

- **Live attach needs the VM console session** (debugger must break into a live process — no headless attach over SSH). Dump analysis is fully headless.
- Kernel debugging needs a KDNET/pipe/serial target — not set up on the lab VM by default.
- `--filter-script` can redact PII/secrets from tool output (use if dumps carry secrets).

## References

- https://github.com/svnscha/mcp-windbg (MIT) · docs https://svnscha.github.io/mcp-windbg/
- PyPI `mcp-windbg` 1.2.1
