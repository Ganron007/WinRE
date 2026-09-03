"""x64dbg_client.py — thin HTTP JSON-RPC client for x64dbg-MCP.

x64dbg-MCP is a Zig plugin (integrations/x64dbg-mcp-server-main) that
exposes 71 tools over POST / as JSON-RPC 2.0 (streamable HTTP + SSE).
This client wraps the wire so the orchestrator and the LLM agentic loop
can call them without hand-rolling JSON.

All methods return a dict of the form:
    {"ok": bool, "result": <raw json-rpc result>, "error": <string or None>}

If x64dbg is not running, every method returns:
    {"ok": False, "error": "x64dbg MCP unreachable on http://127.0.0.1:9094", "result": None}

So callers can safely do:
    cli = X64DbgClient()
    out = cli.detect_oep("foo")
    if not out["ok"]:
        log.warning("skipping OEP detect: %s", out["error"])
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class X64DbgError(RuntimeError):
    """Raised by X64DbgClient on hard failures (callers can also check
    the structured return values; this is for raise-and-die paths)."""


class X64DbgClient:
    """HTTP client for x64dbg-MCP (Zig plugin in x64dbg)."""

    DEFAULT_BASE = "http://127.0.0.1:9094"

    def __init__(self, base: str | None = None, default_timeout: int = 60):
        self.base = (base or self.DEFAULT_BASE).rstrip("/")
        self.default_timeout = default_timeout
        # monotonic id; x64dbg-MCP doesn't validate, but JSON-RPC wants one
        self._id = 0

    # --- low-level wire ----------------------------------------------------

    def call(self, name: str, arguments: dict | None = None,
             timeout: int | None = None) -> dict:
        """Invoke one MCP tool. Returns the structured dict described above.

        Never raises on transport errors — returns {"ok": False, ...} so
        callers can chain without try/except.
        """
        self._id += 1
        body = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}/",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.default_timeout) as r:
                raw = json.loads(r.read())
        except urllib.error.URLError as e:
            return {"ok": False, "error": f"x64dbg MCP unreachable on {self.base}: {e}",
                    "result": None, "name": name}
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"x64dbg returned non-JSON: {e}",
                    "result": None, "name": name}
        except Exception as e:
            return {"ok": False, "error": f"x64dbg call failed: {e}",
                    "result": None, "name": name}

        if "error" in raw:
            return {"ok": False, "error": str(raw["error"]),
                    "result": raw, "name": name}
        result = raw.get("result")
        # MCP content envelope: {"content": [{"type": "text", "text": ...}],
        #                        "isError": true} on tool failure. Surface it —
        # otherwise failures look like ok:true (silent-drop).
        if isinstance(result, dict) and result.get("isError"):
            text = ""
            try:
                content = result.get("content") or []
                if content and isinstance(content[0], dict):
                    text = content[0].get("text", "")
            except Exception:
                pass
            return {"ok": False, "error": str(text)[:300] or "tool reported error",
                    "result": result, "name": name}
        return {"ok": True, "error": None, "result": result, "name": name}

    def list_tools(self) -> list[str]:
        """Return the list of tool names advertised by the plugin."""
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": "tools/list", "params": {}}
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}/", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                payload = json.loads(r.read())
        except Exception as e:
            raise X64DbgError(f"list_tools failed: {e}") from e
        tools = ((payload.get("result") or {}).get("tools")) or []
        return [t.get("name") for t in tools if t.get("name")]

    # --- convenience wrappers ---------------------------------------------

    def is_up(self) -> bool:
        try:
            out = self.call("GetDebugState")
            return out.get("ok") or "isDebugging" in (out.get("result") or {})
        except Exception:
            return False

    def get_state(self) -> dict:           return self.call("GetDebugState")
    def load_binary(self, path: str) -> dict:
        return self.call("LoadBinary", {"filePath": path})
    def attach_process(self, pid: int) -> dict:
        return self.call("AttachProcess", {"pid": pid})
    def detect_oep(self, module: str) -> dict:
        return self.call("DetectOEP", {"module": module})
    def dump_module(self, module: str, file_path: str) -> dict:
        return self.call("DumpModule", {"module": module, "filePath": file_path})
    def analyze_module(self, module: str) -> dict:
        return self.call("AnalyzeModule", {"module": module})
    def get_event_log(self) -> dict:       return self.call("GetEventLog")
    def clear_event_log(self) -> dict:    return self.call("ClearEventLog")
    def search_strings(self, module: str, pattern: str) -> dict:
        return self.call("SearchForStrings", {"module": module, "pattern": pattern})
    def list_modules(self) -> dict:       return self.call("ListModules")
    def get_memory_map(self) -> dict:     return self.call("GetMemoryMap")
    def get_call_stack(self) -> dict:     return self.call("GetCallStack")
    def get_all_registers(self) -> dict:  return self.call("GetAllRegisters")
    def read_memory(self, address: int, size: int = 4096) -> dict:
        # plugin schema declares address as string ("Hex address or expression")
        return self.call("ReadMemory", {"address": hex(address), "size": size})
    def disassemble_at(self, address: int, count: int = 16) -> dict:
        # plugin schema declares address as string
        return self.call("Disassemble", {"address": hex(address), "count": count})
    def set_breakpoint(self, target: str) -> dict:
        return self.call("SetBreakpoint", {"target": target})
    def set_hw_breakpoint(self, address: int, dr_index: int = 0,
                            bp_type: str = "x", size: int = 1) -> dict:
        # plugin schema: {"address": string, "type": "x|w|r", "size": 1|2|4|8}
        # (no drIndex — the plugin manages debug registers itself)
        return self.call("SetHardwareBreakpoint",
                         {"address": hex(address), "type": bp_type, "size": size})
    def delete_breakpoint(self, address: int) -> dict:
        # plugin schema: {"target": string}
        return self.call("DeleteBreakpoint", {"target": hex(address)})
    def list_breakpoints(self) -> dict:   return self.call("ListBreakpoints")
    def run(self) -> dict:                return self.call("run")
    def pause(self) -> dict:              return self.call("PauseDebug")
    def step_into(self) -> dict:          return self.call("StepInto")
    def step_over(self) -> dict:          return self.call("StepOver")
    def step_out(self) -> dict:           return self.call("StepOut")
    def run_to(self, address: int) -> dict:
        # plugin schema declares address as string
        return self.call("RunToAddress", {"address": hex(address)})
    def wait_pause(self, timeout_ms: int = 30000) -> dict:
        return self.call("WaitForPause", {"timeout": timeout_ms})
    def eval(self, expression: str) -> dict:
        return self.call("EvalExpression", {"expression": expression})
    def comment(self, address: int, text: str) -> dict:
        return self.call("CommentOrLabelAtAddress",
                         {"address": address, "text": text, "type": "comment"})
    def bookmark(self, address: int, text: str) -> dict:
        return self.call("SetBookmark", {"address": address, "text": text})
    def execute_command(self, command: str) -> dict:
        return self.call("ExecuteDebuggerCommand", {"command": command})
