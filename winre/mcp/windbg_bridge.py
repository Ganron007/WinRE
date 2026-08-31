"""windbg_bridge.py — MVP HTTP bridge for WinDbg (FlareVM).

12-tool JSON-RPC facade (POST / on port 9096) that matches the
x64dbg-MCP shape so `deep_dive_agentic` on Remnux can use the same
HTTP client. Mirrors docs/WINDBG-MCP.md.

Two execution paths, chosen at startup:

    A. pykd fast path — if `pykd` is importable, the bridge runs
       inside a long-lived WinDbg attach (or dump). Each tool maps
       to a pykd call. Lowest latency, one debugger per bridge.

    B. per-process fallback — for each request we spawn
       `windbg.exe -c ".attach <pid>|<.opendump> ; <cmds> ; q"`
       and parse stdout. Slow but reliable; no pykd install needed.

Tools (12, matches docs/WINDBG-MCP.md:23):
    GetDebugState     LoadDump        AttachProcess       ExecuteCommand
    GetCallStack      GetRegisters    ReadMemory          SetBreakpoint
    Go                StepInto        DumpMemory          ListModules

Run:
    python C:\\WinRE\\winre\\mcp\\windbg_bridge.py --port 9096
    # or attach to a target at start:
    python C:\\WinRE\\winre\\mcp\\windbg_bridge.py --port 9096 --attach-pid 1234
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

WINDBG = os.environ.get("WINDBG",
                        r"C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe")
PYTHON3 = shutil.which("python") or shutil.which("python.exe") or sys.executable

# Tool name -> (description, arg schema)
TOOLS: list[dict[str, Any]] = [
    {"name": "GetDebugState",  "description": "is the bridge attached to a target?",
     "args": {}},
    {"name": "LoadDump",       "description": "open a crash/minidump file",
     "args": {"filePath": "string"}},
    {"name": "AttachProcess",  "description": "attach to a live PID",
     "args": {"pid": "int"}},
    {"name": "ExecuteCommand", "description": "run a raw WinDbg command (r, k, lm, !peb, !handle, ...)",
     "args": {"command": "string"}},
    {"name": "GetCallStack",   "description": "k (call stack)",
     "args": {}},
    {"name": "GetRegisters",   "description": "r (registers)",
     "args": {}},
    {"name": "ReadMemory",     "description": "d[b/w/d/q] <addr> [L<size>]",
     "args": {"address": "hex", "size": "int"}},
    {"name": "SetBreakpoint",  "description": "bp <addr>",
     "args": {"target": "string"}},
    {"name": "Go",             "description": "g",
     "args": {}},
    {"name": "StepInto",       "description": "p (step over) / t (step into) via StepInto",
     "args": {"into": "bool"}},
    {"name": "DumpMemory",     "description": ".writemem <file> <range>",
     "args": {"address": "hex", "size": "int", "filePath": "string"}},
    {"name": "ListModules",    "description": "lm",
     "args": {}},
]


# ---------------------------------------------------------------------------
# pykd fast-path (optional)
# ---------------------------------------------------------------------------
def _pykd_attached() -> bool:
    try:
        import pykd  # type: ignore
        return pykd.isConnected() if hasattr(pykd, "isConnected") else False
    except Exception:
        return False


def _pykd_call(name: str, args: dict) -> dict:
    import pykd  # type: ignore
    if name == "GetDebugState":
        return {"ok": True, "result": {"connected": bool(pykd.isConnected())}}
    if name == "ExecuteCommand":
        out = pykd.dbgCommand(args["command"])
        return {"ok": True, "result": {"text": out}}
    if name == "GetCallStack":
        return {"ok": True, "result": {"text": pykd.dbgCommand("k")}}
    if name == "GetRegisters":
        return {"ok": True, "result": {"text": pykd.dbgCommand("r")}}
    if name == "ListModules":
        return {"ok": True, "result": {"text": pykd.dbgCommand("lm")}}
    if name == "ReadMemory":
        size = int(args.get("size", 64))
        return {"ok": True, "result": {"text": pykd.dbgCommand(f"db {args['address']} L{size}")}}
    if name == "SetBreakpoint":
        return {"ok": True, "result": {"text": pykd.dbgCommand(f"bp {args['target']}")}}
    if name == "Go":
        return {"ok": True, "result": {"text": pykd.dbgCommand("g")}}
    if name == "StepInto":
        cmd = "t" if args.get("into", True) else "p"
        return {"ok": True, "result": {"text": pykd.dbgCommand(cmd)}}
    if name == "DumpMemory":
        return {"ok": True, "result": {"text": pykd.dbgCommand(
            f".writemem {args['filePath']} {args['address']} L{args['size']}")}}
    return {"ok": False, "error": f"unknown tool {name}"}


# ---------------------------------------------------------------------------
# per-process fallback
# ---------------------------------------------------------------------------
def _windbg_once(init_cmds: list[str], body_cmds: list[str], timeout: int = 60) -> dict:
    """Spawn one windbg.exe with -c "<init>; <body>; q" and capture output."""
    if not Path(WINDBG).is_file():
        return {"ok": False, "error": f"windbg not found: {WINDBG}"}
    argv = [WINDBG]
    for c in init_cmds:
        argv += ["-c", c]
    for c in body_cmds:
        argv += ["-c", c]
    argv += ["-c", "q"]
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                            encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"windbg timeout {timeout}s"}
    except FileNotFoundError as e:
        return {"ok": False, "error": f"windbg spawn failed: {e}"}
    return {"ok": cp.returncode in (0, 1),
            "result": {"text": (cp.stdout or "")[-4000:]},
            "stderr_tail": (cp.stderr or "")[-400:]}


def _resolve_target(args: dict, state: dict) -> list[str]:
    """Init commands: .attach <pid> or .opendump <path>."""
    if state.get("pid"):
        return [f".attach -p {state['pid']}"]
    if state.get("dump"):
        return [f".opendump {state['dump']}"]
    return []


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def fallback_call(name: str, args: dict, state: dict, timeout: int = 60) -> dict:
    body: list[str] = []
    if name == "GetDebugState":
        pid = state.get("pid")
        dump = state.get("dump")
        connected = bool(pid or dump)
        if pid and not _pid_alive(pid):
            # Process died since attach — don't lie about being attached.
            state.pop("pid", None)
            connected = False
        return {"ok": True, "result": {"connected": connected,
                                        "pid": pid if connected else None,
                                        "dump": dump}}
    if name == "AttachProcess":
        state["pid"] = int(args["pid"])
        return {"ok": True, "result": {"attached_to": state["pid"]}}
    if name == "LoadDump":
        state["dump"] = args["filePath"]
        return {"ok": True, "result": {"loaded": state["dump"]}}

    if name == "ExecuteCommand":
        body = [args["command"]]
    elif name == "GetCallStack":
        body = ["k"]
    elif name == "GetRegisters":
        body = ["r"]
    elif name == "ListModules":
        body = ["lm"]
    elif name == "ReadMemory":
        size = int(args.get("size", 64))
        body = [f"db {args['address']} L{size}"]
    elif name == "SetBreakpoint":
        body = [f"bp {args['target']}"]
    elif name == "Go":
        body = ["g"]
    elif name == "StepInto":
        body = ["t" if args.get("into", True) else "p"]
    elif name == "DumpMemory":
        body = [f".writemem {args['filePath']} {args['address']} L{args['size']}"]
    else:
        return {"ok": False, "error": f"unknown tool {name}"}

    init = _resolve_target(args, state)
    return _windbg_once(init, body, timeout=timeout)


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------
def dispatch(method: str, params: dict, state: dict) -> dict:
    if method == "tools/list":
        return {"ok": True, "result": {"tools": TOOLS}}
    if method != "tools/call":
        return {"ok": False, "error": f"unknown method {method}"}

    name = (params or {}).get("name")
    args = (params or {}).get("arguments") or {}
    if not name:
        return {"ok": False, "error": "params.name required"}

    if _pykd_attached():
        try:
            if name == "AttachProcess":
                pid = int(args["pid"])
                import pykd  # type: ignore
                pykd.attachProcess(pid)
                state["pid"] = pid
                return {"ok": True, "result": {"attached_to": pid}}
            if name == "LoadDump":
                import pykd  # type: ignore
                pykd.loadDump(args["filePath"])
                state["dump"] = args["filePath"]
                return {"ok": True, "result": {"loaded": state["dump"]}}
            return _pykd_call(name, args)
        except Exception as e:
            # fall through to per-process mode
            print(f"[windbg_bridge] pykd failed ({e}); using fallback", file=sys.stderr)
    return fallback_call(name, args, state)


# ---------------------------------------------------------------------------
# HTTP server (stdlib http.server — no flask dep needed)
# ---------------------------------------------------------------------------
def serve(port: int, attach_pid: int | None, dump: str | None) -> int:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    state: dict[str, Any] = {}
    if attach_pid:
        state["pid"] = attach_pid
    if dump:
        state["dump"] = dump

    class _Handler(BaseHTTPRequestHandler):
        # quiet logs
        def log_message(self, format: str, *args):  # noqa: N802
            sys.stderr.write("[windbg_bridge] " + (format % args) + "\n")

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                body = json.dumps({
                    "ok": Path(WINDBG).is_file(),
                    "windbg": WINDBG,
                    "windbg_exists": Path(WINDBG).is_file(),
                    "pykd": _pykd_attached(),
                    "state": {"pid": state.get("pid"), "dump": state.get("dump")},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404); self.end_headers()

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            try:
                msg = json.loads(raw or b"{}")
            except json.JSONDecodeError as e:
                self._reply(400, {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32700, "message": str(e)}})
                return
            method = msg.get("method", "tools/list")
            params = msg.get("params") or {}
            req_id = msg.get("id", 1)
            out = dispatch(method, params, state)
            if out.get("ok"):
                self._reply(200, {"jsonrpc": "2.0", "id": req_id,
                                  "result": out.get("result", out)})
            else:
                self._reply(200, {"jsonrpc": "2.0", "id": req_id,
                                  "error": {"code": -32601,
                                            "message": out.get("error", "unknown")}})

        def _reply(self, code: int, body: dict):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    httpd = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    print(f"[windbg_bridge] listening on 0.0.0.0:{port}  windbg={WINDBG}  "
          f"pykd={'on' if _pykd_attached() else 'off (fallback)'}  "
          f"state={state}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="WinRE WinDbg MCP bridge")
    ap.add_argument("--port", type=int, default=9096)
    ap.add_argument("--attach-pid", type=int, default=None)
    ap.add_argument("--dump", default=None)
    args = ap.parse_args()
    if not Path(WINDBG).is_file():
        print(f"WARN: windbg not at {WINDBG} — tools will fail until installed",
              file=sys.stderr)
    return serve(args.port, args.attach_pid, args.dump)


if __name__ == "__main__":
    sys.exit(main())
