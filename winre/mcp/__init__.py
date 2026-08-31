"""winre.mcp — MCP client/bridge package for WinRE.

This package houses the JSON-RPC client wrappers and bridges that
let the orchestrator and downstream LLM agentic loops talk to
local debuggers/analyzers (x64dbg, WinDbg, Malcat) over HTTP without
bundling the tools themselves.

Public surface:
    x64dbg_client  — X64DbgClient (POST http://127.0.0.1:9094/)
    windbg_bridge  — WinDbgBridge (POST http://127.0.0.1:9096/ or
                     direct WinDbg -c invocation when bridge is down)
    malcat_client  — MalcatClient (POST http://127.0.0.1:9009/mcp)
                     Malcat headless MCP server (45 tools)
"""
from .x64dbg_client import X64DbgClient, X64DbgError  # noqa: F401
from .malcat_client import MalcatClient, MalcatError  # noqa: F401
