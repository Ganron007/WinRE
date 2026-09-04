"""windbg_client.py — HTTP JSON-RPC client for mcp-windbg (svnscha/mcp-windbg).

Microsoft-ecosystem MCP server for WinDbg crash-dump analysis. Runs
`python -m mcp_windbg --transport streamable-http --port 9097` (see
winre/mcp/start_servers.ps1), then this client drives the 10 tools:
dump analysis, remote debugging, kernel debugging.

Endpoint: POST http://127.0.0.1:9097/mcp  (MCP streamable HTTP:
initialize -> Mcp-Session-Id header -> tools/list -> tools/call)

All methods return the structured dict used across WinRE:
    {"ok": bool, "result": <raw json-rpc result>, "error": <string or None>}
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class WinDbgError(RuntimeError):
    """Raised on hard failures (transport errors that aren't recoverable)."""


class WinDbgMCPClient:
    DEFAULT_BASE = "http://127.0.0.1:9097/mcp/"

    def __init__(self, base: str | None = None, default_timeout: int = 180):
        # streamable-http server 307s /mcp -> /mcp/ on POST; use trailing slash
        # so urllib never hits the redirect (which it mishandles for POST).
        b = (base or self.DEFAULT_BASE).rstrip("/") + "/"
        self.base = b
        self.default_timeout = default_timeout
        self._id = 0
        self._session_id: str | None = None
        self._initialized = False

    # --- MCP lifecycle -----------------------------------------------------

    def _ensure_session(self) -> None:
        if self._initialized:
            return
        self._id += 1
        body = {
            "jsonrpc": "2.0", "id": self._id, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "winre-windbg", "version": "1.0"},
            },
        }
        req = urllib.request.Request(
            self.base, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                self._session_id = r.headers.get("Mcp-Session-Id")
                raw = json.loads(r.read())
        except Exception as e:
            raise WinDbgError(f"initialize failed: {e}") from e
        if "error" in raw:
            raise WinDbgError(f"initialize error: {raw['error']}")
        # notifications/initialized
        body = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        req = urllib.request.Request(
            self.base, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream",
                     "Mcp-Session-Id": self._session_id or ""},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=20).read()
        except Exception:
            pass  # notification is fire-and-forget
        self._initialized = True

    # --- low-level wire ----------------------------------------------------

    def call(self, name: str, arguments: dict | None = None,
             timeout: int | None = None) -> dict:
        """Invoke one WinDbg MCP tool. Never raises on transport errors."""
        try:
            self._ensure_session()
        except Exception as e:
            return {"ok": False, "error": str(e), "result": None, "name": name}
        self._id += 1
        body = {
            "jsonrpc": "2.0", "id": self._id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(
            self.base, data=json.dumps(body).encode("utf-8"),
            headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.default_timeout) as r:
                raw = json.loads(r.read())
        except urllib.error.URLError as e:
            return {"ok": False, "error": f"WinDbg MCP unreachable on {self.base}: {e}",
                    "result": None, "name": name}
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"WinDbg returned non-JSON: {e}",
                    "result": None, "name": name}
        except Exception as e:
            return {"ok": False, "error": f"WinDbg call failed: {e}",
                    "result": None, "name": name}
        if "error" in raw:
            return {"ok": False, "error": str(raw["error"]),
                    "result": raw, "name": name}
        result = raw.get("result")
        # MCP tool-level failures arrive as isError=true with HTTP 200
        if isinstance(result, dict) and result.get("isError"):
            texts = [c.get("text", "") for c in (result.get("content") or [])
                     if isinstance(c, dict)]
            return {"ok": False, "error": "\n".join(texts)[:500] or "tool isError",
                    "result": result, "name": name}
        # MCP content blocks: result.content[].text
        if isinstance(result, dict) and "content" in result:
            texts = [c.get("text", "") for c in result["content"] if isinstance(c, dict)]
            return {"ok": True, "error": None,
                    "result": {"text": "\n".join(texts), "raw": result}, "name": name}
        return {"ok": True, "error": None, "result": result, "name": name}

    def list_tools(self) -> list[str]:
        try:
            self._ensure_session()
        except Exception as e:
            raise WinDbgError(f"list_tools failed: {e}") from e
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": "tools/list", "params": {}}
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(
            self.base, data=json.dumps(body).encode("utf-8"),
            headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                payload = json.loads(r.read())
        except Exception as e:
            raise WinDbgError(f"list_tools failed: {e}") from e
        tools = ((payload.get("result") or {}).get("tools")) or []
        return [t.get("name") for t in tools if t.get("name")]

    def is_up(self) -> bool:
        try:
            return bool(self.list_tools())
        except Exception:
            return False

    # --- convenience wrappers (10 tools) -----------------------------------

    def list_dumps(self, directory: str) -> dict:
        return self.call("list_dumps", {"directory": directory})

    def open_cdb_dump(self, dump_path: str, **kw) -> dict:
        args = {"dump_path": dump_path}
        args.update(kw)
        return self.call("open_cdb_dump", args)

    def open_cdb_remote(self, connection: str) -> dict:
        return self.call("open_cdb_remote", {"connection": connection})

    def open_kd_session(self, connection: str) -> dict:
        return self.call("open_kd_session", {"connection": connection})

    def run_cdb_command(self, session_id: str, command: str) -> dict:
        return self.call("run_cdb_command",
                         {"session_id": session_id, "command": command})

    def run_kd_command(self, session_id: str, command: str) -> dict:
        return self.call("run_kd_command",
                         {"session_id": session_id, "command": command})

    def close_cdb_session(self, session_id: str) -> dict:
        return self.call("close_cdb_session", {"session_id": session_id})

    def close_kd_session(self, session_id: str) -> dict:
        return self.call("close_kd_session", {"session_id": session_id})

    def send_ctrl_break(self, session_id: str) -> dict:
        return self.call("send_ctrl_break", {"session_id": session_id})

    def wait_for_break(self, session_id: str, timeout_s: int = 30) -> dict:
        return self.call("wait_for_break",
                         {"session_id": session_id, "timeout": timeout_s})
