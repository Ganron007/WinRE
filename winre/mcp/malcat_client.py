"""malcat_client.py — HTTP JSON-RPC client for Malcat's headless MCP server.

Malcat ships an official MCP server at <install>/bin/malcat.mcp.py. Start it
persistently (tools/malcat_win.py serve, or `python malcat.mcp.py -p 9009`),
then talk to it here over the same JSON-RPC 2.0 shape as the x64dbg/WinDbg
bridges. Doc: https://doc.malcat.fr/ui/mcp.html#headless-mcp-server

Endpoint: POST http://127.0.0.1:9009/mcp
  body: {"jsonrpc":"2.0","id":1,"method":"tools/list"}
        {"jsonrpc":"2.0","id":1,"method":"tools/call",
         "params":{"name":"analyze","arguments":{"path":"C:\\samples\\foo.exe"}}}

All methods return the structured dict used across WinRE:
    {"ok": bool, "result": <raw json-rpc result>, "error": <string or None>}
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class MalcatError(RuntimeError):
    """Raised on hard failures (transport errors that aren't recoverable)."""


class MalcatClient:
    DEFAULT_BASE = "http://127.0.0.1:9009/mcp"

    def __init__(self, base: str | None = None, default_timeout: int = 120):
        self.base = (base or self.DEFAULT_BASE).rstrip("/")
        self.default_timeout = default_timeout
        self._id = 0
        self._aids: dict[str, int] = {}  # path -> analysis_id cache

    def _resolve_aid(self, path: str) -> tuple[int | None, dict | None]:
        """analyse_file once per path, cache the analysis_id.

        malcat.mcp.py view tools (fns_top_list, fn_decompile, anomalies_list,
        yara_list, strings_*) expect {"analysis_id"}, NOT {"path"}.
        Returns (analysis_id, error_dict).
        """
        if path in self._aids:
            return self._aids[path], None
        r = self.analyse_file(path)
        if not r.get("ok"):
            return None, r
        aid = ((r.get("result") or {}).get("structuredContent") or {}).get("analysis_id")
        if aid is None:
            # fall back to content-text JSON shape
            try:
                res = r.get("result") or {}
                for part in (res.get("content") or []):
                    if isinstance(part, dict) and part.get("type") == "text":
                        aid = (json.loads(part.get("text", "")) or {}).get("analysis_id")
                        break
            except Exception:
                aid = None
        if aid is None:
            return None, {"ok": False, "error": "no analysis_id from analyse_file",
                          "result": r.get("result")}
        self._aids[path] = aid
        return aid, None

    # --- low-level wire ----------------------------------------------------

    def call(self, name: str, arguments: dict | None = None,
             timeout: int | None = None) -> dict:
        """Invoke one Malcat MCP tool. Never raises on transport errors."""
        self._id += 1
        body = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base, data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.default_timeout) as r:
                raw = json.loads(r.read())
        except urllib.error.URLError as e:
            return {"ok": False, "error": f"Malcat MCP unreachable on {self.base}: {e}",
                    "result": None, "name": name}
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"Malcat returned non-JSON: {e}",
                    "result": None, "name": name}
        except Exception as e:
            return {"ok": False, "error": f"Malcat call failed: {e}",
                    "result": None, "name": name}
        if "error" in raw:
            return {"ok": False, "error": str(raw["error"]),
                    "result": raw, "name": name}
        res = raw.get("result")
        # MCP tool-level failures arrive as isError=true with HTTP 200
        if isinstance(res, dict) and res.get("isError"):
            texts = [c.get("text", "") for c in (res.get("content") or [])
                     if isinstance(c, dict)]
            return {"ok": False, "error": "\n".join(texts)[:500] or "tool isError",
                    "result": res, "name": name}
        return {"ok": True, "error": None, "result": res, "name": name}

    def list_tools(self) -> list[str]:
        """Return the tool names advertised by the Malcat MCP server."""
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": "tools/list", "params": {}}
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base, data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                payload = json.loads(r.read())
        except Exception as e:
            raise MalcatError(f"list_tools failed: {e}") from e
        tools = ((payload.get("result") or {}).get("tools")) or []
        return [t.get("name") for t in tools if t.get("name")]

    def is_up(self) -> bool:
        try:
            return bool(self.list_tools())
        except Exception:
            return False

    # --- convenience wrappers (exact tool names from malcat.mcp.py) --------

    def analyse_file(self, path: str, **kw) -> dict:
        """Analyse a file on disk (metadata, regions, entropy, subfiles)."""
        args = {"path": path}
        args.update(kw)
        return self.call("analyse_file", args)

    def analyse_infos(self, path: str) -> dict:
        return self.call("analyse_infos", {"path": path})

    def analyse_carved_file(self, path: str, index: int) -> dict:
        return self.call("analyse_carved_file", {"path": path, "index": index})

    def analyse_virtual_file(self, path: str, subfile: str) -> dict:
        return self.call("analyse_virtual_file", {"path": path, "subfile": subfile})

    def file_list_carved(self, path: str) -> dict:
        return self.call("file_list_carved", {"path": path})

    def file_list_virtual_files(self, path: str) -> dict:
        return self.call("file_list_virtual_files", {"path": path})

    def fn_decompile(self, path: str, address: int) -> dict:
        # NOTE: malcat.mcp.py fn_decompile expects {"analysis_id", "ea"}.
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("fn_decompile", {"analysis_id": aid, "ea": int(address)})

    def fn_disassemble(self, path: str, address: int, count: int = 32) -> dict:
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("fn_disassemble",
                         {"analysis_id": aid, "ea": int(address), "count": count})

    def fn_infos(self, path: str, address: int) -> dict:
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("fn_infos", {"analysis_id": aid, "ea": int(address)})

    def fns_top_list(self, path: str, count: int = 50) -> dict:
        # NOTE: malcat.mcp.py fns_top_list expects {"analysis_id"} only.
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("fns_top_list", {"analysis_id": aid})

    def fns_search(self, path: str, query: str) -> dict:
        return self.call("fns_search", {"path": path, "query": query})

    def script_decompile(self, path: str) -> dict:
        return self.call("script_decompile", {"path": path})

    def anomalies_list(self, path: str) -> dict:
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("anomalies_list", {"analysis_id": aid})

    def yara_list(self, path: str) -> dict:
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("yara_list", {"analysis_id": aid})

    def constants_list(self, path: str) -> dict:
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("constants_list", {"analysis_id": aid})

    def strings_top_list(self, path: str, count: int = 50) -> dict:
        aid, err = self._resolve_aid(path)
        if err is not None:
            return err
        return self.call("strings_top_list", {"analysis_id": aid})

    def strings_search(self, path: str, pattern: str) -> dict:
        return self.call("strings_search", {"path": path, "pattern": pattern})

    def symbols_search(self, path: str, query: str) -> dict:
        return self.call("symbols_search", {"path": path, "query": query})

    def refs_get(self, path: str, address: int) -> dict:
        return self.call("refs_get", {"path": path, "address": address})

    def transforms_search(self, path: str) -> dict:
        return self.call("transforms_search", {"path": path})

    def unpack_donut(self, path: str) -> dict:
        return self.call("unpack_donut", {"path": path})

    def chain_decrypt_analysis(self, path: str, transform: str) -> dict:
        return self.call("chain_decrypt_analysis",
                         {"path": path, "transform": transform})

    def save_file_interval_to_disk(self, path: str, output: str,
                                   start: int, end: int) -> dict:
        return self.call("save_file_interval_to_disk",
                         {"path": path, "output": output,
                          "start": start, "end": end})
