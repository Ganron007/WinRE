"""winre.mcp — MCP client/bridge package for WinRE.

This package houses the JSON-RPC client wrappers and bridges that
let the orchestrator and downstream LLM agentic loops talk to
local debuggers/analyzers (x64dbg, WinDbg, Malcat) over HTTP without
bundling the tools themselves.

Public surface:
    x64dbg_client  — X64DbgClient (POST http://127.0.0.1:9094/)
    malcat_client  — MalcatClient (POST http://127.0.0.1:9009/mcp)
                     Malcat headless MCP server (45 tools)
    windbg_client  — WinDbgMCPClient (POST http://127.0.0.1:9097/mcp)
                     mcp-windbg server (10 tools: dumps, remote, kernel)
    windbg_bridge  — LEGACY 12-tool per-process bridge (:9096); superseded
                     by mcp-windbg (windbg_client). Kept for reference.
"""
from .x64dbg_client import X64DbgClient, X64DbgError  # noqa: F401
from .malcat_client import MalcatClient, MalcatError  # noqa: F401
from .windbg_client import WinDbgMCPClient, WinDbgError  # noqa: F401
