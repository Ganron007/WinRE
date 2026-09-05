#!/usr/bin/env python3
r"""agentic.py — LangGraph ReAct deep-dive agent for WinRE (control plane).

Mirrors RevAI's agentic_langgraph.py, but WinRE's deep-dive toolset spans
STATIC (Ghidra/IDA SQL, Malcat MCP) AND (later) DYNAMIC (x64dbg/WinDbg MCP)
— the deterministic spine (detonation, intake, quick, yara, audit) is never
agentic.

Phase 1 (this file): STATIC tools only — SQL over SSH (Ghidra/IDA on the
FlareVM execution plane) + Malcat MCP over HTTP. Dynamic debug tools get a
separate, careful phase (see internal/IMPROVEMENT-PLAN.md P-A).

Deterministic-first: the agent only READS evidence and deepens the RE. It
can never launch detonation or modify the sample. Every tool call is
journaled (history) with budget + redundant-call discipline.

Run (control plane, needs WINRE_LLM_BASE_URL/KEY):
    python winre/agentic.py <sha> [--sample C:\samples\foo.exe] [--max-steps 10]
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from pydantic import BaseModel, Field  # noqa: E402

from .envfile import load_dotenv  # noqa: F401  (ensures .env is loaded)
from winre import remote_driver  # noqa: E402
from winre.evidence import EvidencePack  # noqa: E402


# ---------------------------------------------------------------------------
# ToolRegistry — wraps the actual WinRE tool calls
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Remote SQL helper (runs ON the VM via scp — avoids nested-quote breakage)
# ---------------------------------------------------------------------------
_REMOTE_SQL_HELPER = r'''
"""Remote SQL helper for the LangGraph agent — runs on FlareVM.

Usage: python _remote_sql_helper.py <b64_engine> <b64_sample> <b64_sql>
Prints JSON: {"ok": true, "columns": [...], "rows": [...], "row_count": N}
Args are base64 (no quoting issues through SSH/powershell).
"""
import base64
import json
import subprocess
import sys
from pathlib import Path

engine = base64.b64decode(sys.argv[1]).decode()
sample = Path(base64.b64decode(sys.argv[2]).decode())
sql = base64.b64decode(sys.argv[3]).decode()
py = sys.executable
tools = Path(__file__).resolve().parents[1] / "tools"

if engine == "ghidra":
    p = subprocess.run([py, str(tools / "flare_ghidra_sql.py"), "query", sql,
                        "--file", str(sample), "--json"],
                       capture_output=True, text=True, timeout=900,
                       encoding="utf-8", errors="replace")
else:  # ida
    # HTTP transport FIRST (idasql --http): the one-shot `idasql -q` spawn
    # hangs on this idasql build (P-B5). Only fall back to one-shot when the
    # HTTP wrapper fails to produce valid JSON.
    out = None
    p = subprocess.run([py, str(tools / "flarevm_ida_query.py"), "--http",
                        str(sample), sql, "--json"],
                       capture_output=True, text=True, timeout=180,
                       encoding="utf-8", errors="replace")
    try:
        out = json.loads(p.stdout)
    except json.JSONDecodeError:
        out = None
    if not (isinstance(out, dict) and out.get("ok")):
        p = subprocess.run([py, str(tools / "flarevm_ida_query.py"),
                            str(sample), sql, "--json"],
                           capture_output=True, text=True, timeout=120,
                           encoding="utf-8", errors="replace")
        try:
            out = json.loads(p.stdout)
        except json.JSONDecodeError:
            out = {"ok": False, "error": (p.stderr or p.stdout)[-300:]}
    print(json.dumps(out))
    raise SystemExit(0)
try:
    out = json.loads(p.stdout)
    print(json.dumps(out))
except json.JSONDecodeError:
    print(json.dumps({"ok": False, "error": (p.stderr or p.stdout)[-300:]}))
'''


class ToolRegistry:
    """Deterministic tool calls the agent may make (static phase).

    ghidra_query  — SQL over SSH to the VM's flare_ghidra_sql.py
    ida_query     — SQL over SSH to the VM's flarevm_ida_query.py (if .i64)
    malcat_analyze— Malcat MCP over HTTP (:9009) — analyse/decompile/etc
    """

    def __init__(self, sample_name: str, sha: str, cfg: dict | None = None):
        self.sample_name = sample_name
        self.sha = sha
        self.cfg = cfg or remote_driver.flare_cfg()
        self.remote_sample = rf"C:\samples\{sample_name}"

    def call(self, name: str, args: dict) -> dict:
        fn = getattr(self, name, None)
        if fn is None:
            return {"error": f"unknown tool {name}"}
        try:
            return fn(**args)
        except TypeError as e:
            return {"error": f"bad args for {name}: {e}"}
        except Exception as e:
            return {"error": f"{name} failed: {e}"}

    # --- static tools ------------------------------------------------------

    def _run_remote_py(self, helper_name: str, *args: str, timeout: int = 900) -> dict:
        """Run a scp'd helper .py on the VM and parse its JSON stdout.

        Args are base64-encoded (single safe tokens) so spaces/quotes/parens
        in SQL can never be mangled by the SSH→powershell nesting. The helper
        decodes them back.
        """
        import base64
        helper_src = _REMOTE_SQL_HELPER
        local = REPO / "winre" / f"_{helper_name}.py"
        local.write_text(helper_src, encoding="utf-8")
        remote = rf'{self.cfg["remote_pipeline"]}\winre\_{helper_name}.py'
        try:
            remote_driver.scp_to(self.cfg, local, remote.replace("\\", "/"))
        except Exception as e:
            return {"error": f"scp helper: {e}"}
        py = r"C:\Python313\python.exe"
        b64args = [base64.b64encode(a.encode("utf-8")).decode() for a in args]
        joined = " ".join(b64args)
        cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
               f'{remote} {joined} 2>&1"')
        r = remote_driver.ssh_run(self.cfg, cmd, timeout=timeout)
        if r.returncode != 0:
            return {"error": (r.stderr or r.stdout)[-300:]}
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"error": f"non-JSON: {r.stdout[-200:]}"}

    def ghidra_query(self, sql: str, max_rows: int = 25) -> dict:
        """SQL against the Ghidra tables on the VM (funcs/strings/imports)."""
        out = self._run_remote_py("_remote_sql_helper", "ghidra",
                                  self.remote_sample, sql)
        if isinstance(out, dict) and out.get("ok") is not None:
            rows = out.get("rows") or []
            if max_rows and len(rows) > max_rows:
                out["rows"] = rows[:max_rows]
                out["row_count"] = len(rows[:max_rows])
        return out

    def ida_query(self, sql: str) -> dict:
        """SQL against the IDA database on the VM (funcs/imports/strings)."""
        return self._run_remote_py("_remote_sql_helper", "ida",
                                   self.remote_sample, sql, timeout=120)

    def malcat_analyze(self, path: str | None = None) -> dict:
        """Malcat analysis (:9009, localhost-bound on VM — SSH-exec bridge)."""
        try:
            return self._malcat("analyse_file",
                                {"path": path or self.remote_sample})
        except Exception as e:
            return {"error": str(e)}

    # --- RevAI-parity static evidence tools (free surface) -----------------

    def _vm_tool(self, tool: str, timeout: int = 1200) -> dict:
        """Run tools/flare_static_tools.py <tool> on the VM (scp-synced)."""
        py = r"C:\Python313\python.exe"
        cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
               f'{self.cfg["remote_pipeline"]}\\tools\\flare_static_tools.py '
               f'{tool} "{self.remote_sample}" 2>&1"')
        r = remote_driver.ssh_run(self.cfg, cmd, timeout=timeout)
        if r.returncode != 0:
            return {"error": (r.stderr or r.stdout)[-250:]}
        try:
            out = json.loads(r.stdout)
            return out.get(tool) or {"error": "no tool payload"}
        except json.JSONDecodeError:
            return {"error": f"non-JSON: {(r.stdout or '')[-200:]}"}

    def capa(self) -> dict:
        """capa capability detection (mandiant rules) — ATT&CK-mapped."""
        return self._vm_tool("capa")

    def floss(self) -> dict:
        """floss decoded strings (stack/string deobfuscation)."""
        return self._vm_tool("floss")

    def pe_parse(self) -> dict:
        """PE structure via pefile: imports, sections+entropy, signature."""
        return self._vm_tool("lief")

    def diec(self) -> dict:
        """Detect It Easy: packer/compiler/protector identification."""
        return self._vm_tool("diec")

    def strings_tool(self) -> dict:
        """ASCII/unicode strings from the sample."""
        return self._vm_tool("strings")

    def yarascan(self) -> dict:
        """yara-x scan against the staged curated ruleset."""
        return self._vm_tool("yarascan")

    def pe_import_signals(self) -> dict:
        """High-signal import→ATT&CK map (pefile; NOT capa)."""
        return self._vm_tool("pe_import_signals")

    def signature_match(self, func_name: str = "", imports: list | None = None,
                        strings: list | None = None, constants: list | None = None,
                        size: int = 0) -> dict:
        """Match a function against crypto/stdlib/winapi signature DBs."""
        payload = json.dumps({"func_name": func_name, "imports": imports or [],
                              "strings": strings or [], "constants": constants or [],
                              "size": size}, default=str)
        import base64
        b64 = base64.b64encode(payload.encode()).decode()
        py = r"C:\Python313\python.exe"
        cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} -c '
               f'"import sys,json,base64; '
               f'sys.path.insert(0, r\'C:\\WinRE\\tools\'); '
               f'import flare_static_tools as fst; '
               f'kw = json.loads(base64.b64decode(\'{b64}\').decode()); '
               f'print(json.dumps({{\'signature_match\': fst.signature_match(**kw)}}))" 2>&1"')
        r = remote_driver.ssh_run(self.cfg, cmd, timeout=300)
        try:
            return json.loads(r.stdout).get("signature_match") or {}
        except Exception:
            return {"error": (r.stderr or r.stdout)[-200:]}

    def xor_string_search(self) -> dict:
        """XOR/ROL/ADD/SHIFT encoded-string brute force (pure python)."""
        return self._vm_tool("xor_string_search")

    def olevba_analyze(self) -> dict:
        """VBA macro extraction (Office docs)."""
        return self._vm_tool("olevba")

    def peepdf_analyze(self) -> dict:
        """PDF analysis (JS/objects/embedded files)."""
        return self._vm_tool("peepdf")

    def speakeasy_emulate(self) -> dict:
        """Windows-native PE emulation (Mandiant Speakeasy)."""
        return self._vm_tool("speakeasy", timeout=1500)

    def frida_static_probe(self) -> dict:
        """Frida availability + PE hook candidates (no injection)."""
        return self._vm_tool("frida_static_probe")

    def r2_decompile(self, function_addrs: list | None = None) -> dict:
        """radare2 disassembly (asm, 2nd engine)."""
        import base64
        if function_addrs:
            b64 = base64.b64encode(json.dumps(function_addrs).encode()).decode()
            py = r"C:\Python313\python.exe"
            cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} -c '
                   f'"import sys,json,base64; '
                   f'sys.path.insert(0, r\'C:\\WinRE\\tools\'); '
                   f'import flare_static_tools as fst; '
                   f'fa = json.loads(base64.b64decode(\'{b64}\').decode()); '
                   f'print(json.dumps({{\'r2_decompile\': fst.r2_decompile(r\'{self.remote_sample}\', fa)}}))" 2>&1"')
            r = remote_driver.ssh_run(self.cfg, cmd, timeout=900)
            try:
                return json.loads(r.stdout).get("r2_decompile") or {}
            except Exception:
                return {"error": (r.stderr or r.stdout)[-200:]}
        return self._vm_tool("r2_decompile")

    def upx_unpack(self) -> dict:
        """Detect + unpack UPX (writes .unpacked beside the sample)."""
        return self._vm_tool("upx")

    def shellcode_extract(self) -> dict:
        """High-entropy exec-section extraction + scdbg emulation."""
        return self._vm_tool("shellcode_extract")

    def dotnet_analyze(self) -> dict:
        """.NET analysis: dnfile metadata + ilspycmd IL + C# decompile."""
        return self._vm_tool("dotnet_analyze")

    def z3_solve(self) -> dict:
        """MBA identity solving (z3 via deobfuscation extension)."""
        return self._vm_tool("z3_solve")

    def angr_analyze(self) -> dict:
        """CFF dispatcher analysis (angr via deobfuscation extension)."""
        return self._vm_tool("angr_analyze")

    def ghidra_decompile(self, function_addr: str = "") -> dict:
        """Ghidra decompile one function (headless post-script; address,
        FUN_ name, or 'entry')."""
        import base64
        b64 = base64.b64encode((function_addr or "entry").encode()).decode()
        py = r"C:\Python313\python.exe"
        cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} -c '
               f'"import sys,json,base64; '
               f'sys.path.insert(0, r\'C:\\WinRE\\tools\'); '
               f'import flare_static_tools as fst; '
               f'fa = base64.b64decode(\'{b64}\').decode(); '
               f'print(json.dumps({{\'ghidra_decompile\': fst.ghidra_decompile(r\'{self.remote_sample}\', fa)}}))" 2>&1"')
        r = remote_driver.ssh_run(self.cfg, cmd, timeout=2400)
        try:
            return json.loads(r.stdout).get("ghidra_decompile") or {}
        except Exception:
            return {"error": (r.stderr or r.stdout)[-200:]}

    def _malcat(self, tool: str, args: dict) -> dict:
        """Malcat MCP via SSH-exec bridge (port is localhost-bound on VM)."""
        from winre.remote_driver import malcat_remote_call
        r = malcat_remote_call(tool, args)
        return r.get("result") or {"error": r.get("error")}

    def malcat_functions(self, count: int = 10) -> dict:
        """Top-N most interesting functions (Malcat heuristics)."""
        try:
            return self._malcat("fns_top_list",
                                {"path": self.remote_sample, "count": count})
        except Exception as e:
            return {"error": str(e)}

    def malcat_decompile(self, address: int) -> dict:
        """Decompile one function by address (Malcat MCP)."""
        try:
            return self._malcat("fn_decompile",
                                {"path": self.remote_sample,
                                 "address": address})
        except Exception as e:
            return {"error": str(e)}

    # --- dynamic tools (x64dbg debug loops; opt-in, bounded) ---------------

    def _dbg_client(self):
        from winre.mcp import X64DbgClient
        return X64DbgClient(base=f"http://{self.cfg['host']}:9094")

    def _dbg_gate(self) -> dict | None:
        """Snapshot-gate check before ANY debugger execution on the VM.

        enforce: the FIRST debug call consumes the marker (same-sha calls
        later in this agent run pass via session scope); blocked -> tools
        return an error, agent falls back to static. observe (default):
        advisory only — never blocks testing.
        """
        from winre import snapshot_gate
        g = snapshot_gate.preflight("debug", sha=self.sha, cfg=self.cfg)
        if g.get("allowed"):
            return None
        return {"error": f"{g.get('error')} — falling back to static analysis"}

    def x64dbg_oep(self) -> dict:
        """Find the unpack OEP via memory-execute BP (verified method)."""
        gate = self._dbg_gate()
        if gate:
            return gate
        try:
            from winre import debug_loops
            r = debug_loops.oep_by_section(self.remote_sample,
                                           xc=self._dbg_client())
            return {"ok": r.get("ok"), "oep": r.get("oep"),
                    "error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}

    def x64dbg_wpm_dump(self, max_hits: int = 3) -> dict:
        """BP WriteProcessMemory, dump written buffers (bounded hits)."""
        gate = self._dbg_gate()
        if gate:
            return gate
        try:
            from winre import debug_loops
            r = debug_loops.wpm_dump(self.remote_sample,
                                     xc=self._dbg_client(),
                                     max_hits=max(1, min(int(max_hits), 5)))
            return {"ok": r.get("ok"), "hits": r.get("hits"),
                    "error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}

    def x64dbg_crypt_dump(self, max_hits: int = 2) -> dict:
        """BP CryptDecrypt, capture ciphertext then plaintext (bounded)."""
        gate = self._dbg_gate()
        if gate:
            return gate
        try:
            from winre import debug_loops
            r = debug_loops.crypt_dump(self.remote_sample,
                                       xc=self._dbg_client(),
                                       max_hits=max(1, min(int(max_hits), 3)))
            return {"ok": r.get("ok"), "hits": r.get("hits"),
                    "error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}

    def x64dbg_unpack(self) -> dict:
        """Full unpack: OEP -> DumpModule -> Malcat compare (deterministic)."""
        gate = self._dbg_gate()
        if gate:
            return gate
        try:
            from winre import debug_loops
            r = debug_loops.agentic_unpack(self.remote_sample,
                                           xc=self._dbg_client())
            return {"ok": r.get("ok"), "oep": r.get("oep"),
                    "dump_path": r.get("dump_path"),
                    "comparison": r.get("comparison"),
                    "error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}


# ---------------------------------------------------------------------------
# LangGraph ReAct (static phase)
# ---------------------------------------------------------------------------
TOOL_NAMES = ("ghidra_query", "ida_query", "malcat_analyze",
              "malcat_functions", "malcat_decompile",
              "capa", "floss", "pe_parse", "diec", "strings_tool", "yarascan",
              "pe_import_signals", "xor_string_search", "olevba_analyze",
              "peepdf_analyze", "speakeasy_emulate", "frida_static_probe",
              "r2_decompile", "upx_unpack", "shellcode_extract",
              "dotnet_analyze", "z3_solve", "angr_analyze", "ghidra_decompile")
# Opt-in dynamic tools: x64dbg debug loops over MCP. Bounded, deterministic
# primitives — the LLM composes them, never free-forms debugger commands.
DYNAMIC_TOOL_NAMES = ("x64dbg_oep", "x64dbg_wpm_dump",
                      "x64dbg_crypt_dump", "x64dbg_unpack")


class GhidraQueryArgs(BaseModel):
    sql: str = Field(..., description="SQL against Ghidra tables (funcs/strings/imports)")
    max_rows: int = Field(25, description="max rows")


class IdaQueryArgs(BaseModel):
    sql: str = Field(..., description="SQL against IDA tables")


class EmptyArgs(BaseModel):
    pass


class MalcatFnArgs(BaseModel):
    count: int = Field(10, description="how many top functions")


class MalcatDecompileArgs(BaseModel):
    address: int = Field(..., description="function address to decompile")


class X64DbgHitsArgs(BaseModel):
    max_hits: int = Field(3, description="max BP hits to service (bounded)")


_ARG_MODELS: dict[str, type[BaseModel]] = {
    "ghidra_query": GhidraQueryArgs,
    "ida_query": IdaQueryArgs,
    "malcat_analyze": EmptyArgs,
    "malcat_functions": MalcatFnArgs,
    "malcat_decompile": MalcatDecompileArgs,
    "capa": EmptyArgs,
    "floss": EmptyArgs,
    "pe_parse": EmptyArgs,
    "diec": EmptyArgs,
    "strings_tool": EmptyArgs,
    "yarascan": EmptyArgs,
    "pe_import_signals": EmptyArgs,
    "xor_string_search": EmptyArgs,
    "olevba_analyze": EmptyArgs,
    "peepdf_analyze": EmptyArgs,
    "speakeasy_emulate": EmptyArgs,
    "frida_static_probe": EmptyArgs,
    "r2_decompile": EmptyArgs,
    "upx_unpack": EmptyArgs,
    "shellcode_extract": EmptyArgs,
    "dotnet_analyze": EmptyArgs,
    "z3_solve": EmptyArgs,
    "angr_analyze": EmptyArgs,
    "ghidra_decompile": EmptyArgs,
    "x64dbg_oep": EmptyArgs,
    "x64dbg_wpm_dump": X64DbgHitsArgs,
    "x64dbg_crypt_dump": X64DbgHitsArgs,
    "x64dbg_unpack": EmptyArgs,
}


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"... (truncated {len(s) - n} chars)"


def run_langgraph_deep_dive(sample_name: str, sha: str, *,
                            max_steps: int = 10,
                            log_dir: Path | None = None,
                            dry: bool = False,
                            dynamic: bool = False,
                            available_tools: "list[str] | None" = None) -> dict:
    """Run the LangGraph ReAct agent over the static toolset.

    available_tools: optional subset filter (commercial-optional tools are
    stripped by the caller when absent on the VM, e.g. Malcat).

    Set dynamic=True to also expose the bounded x64dbg debug-loop tools
    (oep/wpm_dump/crypt_dump/unpack). They run inside the VM snapshot and
    are deterministic primitives — the LLM only composes them.

    Returns {"verdict": ..., "source": "llm_judge"|"deterministic_fallback",
             "history": [...], "llm_analysis": text}
    """
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent
    from langchain_core.tools import StructuredTool
    from langchain_core.messages import HumanMessage

    cfg = remote_driver.flare_cfg()
    registry = ToolRegistry(sample_name, sha, cfg)
    history: list[dict] = []
    findings: dict[str, Any] = {}
    state = {"calls": 0, "redundant": 0, "seen": set()}
    budget = max(10, int(max_steps) * 2)

    def _budget_note() -> str:
        remaining = budget - state["calls"]
        if remaining <= 0:
            return "\n[BUDGET] tool budget exhausted — submit your final answer now."
        if remaining <= 2:
            return f"\n[BUDGET CRITICAL] {remaining} tool call(s) left — final answer NOW."
        return ""

    def _make(name: str) -> StructuredTool:
        model = _ARG_MODELS.get(name, EmptyArgs)

        def _runner(**kwargs):
            sig = json.dumps((name, kwargs), sort_keys=True, default=str)
            if sig in state["seen"]:
                state["redundant"] += 1
                history.append({"step": len(history) + 1, "tool": name, "args": kwargs,
                                "reason": "redundant, skipped"})
                return ("[REDUNDANT] identical call already made — reuse earlier "
                        "output." + _budget_note())
            state["seen"].add(sig)
            state["calls"] += 1
            result = registry.call(name, kwargs)
            history.append({"step": len(history) + 1, "tool": name, "args": kwargs,
                            "result": result})
            findings[f"{name}_{len(history)}"] = result
            return _truncate(json.dumps(result, default=str), 2000) + _budget_note()

        _runner.__name__ = name
        _runner.__doc__ = f"Run tool `{name}` on the current sample."
        return StructuredTool.from_function(func=_runner, name=name,
                                            description=_runner.__doc__,
                                            args_schema=model)

    names = list(TOOL_NAMES)
    if available_tools is not None:
        names = [n for n in names if n in set(available_tools)]
    tools = [_make(n) for n in names]
    dyn_note = ""
    if dynamic:
        tools += [_make(n) for n in DYNAMIC_TOOL_NAMES]
        dyn_note = """
Dynamic debugger tools (x64dbg in the VM snapshot — bounded primitives):
x64dbg_oep (find unpack OEP), x64dbg_wpm_dump (capture process-injected
buffers), x64dbg_crypt_dump (capture pre/post-decrypt buffers),
x64dbg_unpack (full OEP->dump->Malcat-compare in one call — prefer this for
packed samples over composing primitives yourself).
Debugger discipline: prefer x64dbg_unpack for packed binaries; keep hit
counts small (<=3); every dynamic claim needs a dump/evidence field; if a
dynamic tool errors, fall back to static — do not retry more than once.
"""

    if dry:
        # no LLM — deterministic fallback stub
        return {"verdict": "unknown", "source": "deterministic_fallback",
                "history": history, "llm_analysis": None, "dry": True}

    api_key = os.environ.get("WINRE_LLM_API_KEY", "")
    api_url = (os.environ.get("WINRE_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
               ).rstrip("/")
    if api_url.endswith("/chat/completions"):
        api_url = api_url[: -len("/chat/completions")]
    model = os.environ.get("WINRE_LLM_MODEL", "local")
    if not api_key and "127.0.0.1" not in api_url:
        return {"verdict": "unknown", "source": "deterministic_fallback",
                "history": history,
                "llm_analysis": "WINRE_LLM_API_KEY not set for remote endpoint"}

    llm = ChatOpenAI(model=model, api_key=api_key or "none",
                     base_url=api_url, temperature=0.0, max_tokens=4096)
    system_prompt = f"""You are an agentic malware reverse-engineering assistant on a Windows
FlareVM analysis pipeline. Sample: {sample_name} (SHA {sha[:16]}).

Known SQL schemas (do NOT waste turns discovering them — query directly):
Ghidra: tables funcs(name,address,size), imports(name,module/name,library),
  strings(content,address); LIMIT small (25). funcs uses columns
  name, addr AS address, size.
IDA: tables funcs(name,address,size,prototype,arg_count,calling_conv),
  imports(name,module), strings(content,address), segments, names.
  Use LIMIT 20. IDs are strings in most rows.
Malcat (only if reachable): analyse_file / fns_top_list / fn_decompile.

Static evidence tools (no args — call and read the JSON):
capa: ATT&CK-mapped capabilities (e.g. "encode data using XOR") — cite the
  capability name + attack technique. STRONG signal for verdicts.
pe_import_signals: import→ATT&CK high-signal map (pefile). NOT capa.
floss: deobfuscated/stack strings — decoded strings often reveal config,
  URLs, mutexes the raw strings hide.
pe_parse: imports (per-DLL function lists), sections + entropy, digital
  signature (signed true/false) — packing = few imports + high entropy.
diec: packer/protector/compiler identification.
strings_tool: raw ASCII strings (may be garbage if packed).
yarascan: curated-ruleset scan — any hit is a strong family indicator.
xor_string_search: XOR/ROL/ADD encoded-string brute force — finds hidden
  config/URLs when plain strings are garbage.
speakeasy_emulate: Windows-native emulation — API calls/events WITHOUT
  executing the sample (static-adjacent behavioral evidence).
dotnet_analyze: .NET metadata + IL + C# decompile (for .NET samples).
ghidra_decompile: decompile one function (addr/FUN_ name/'entry') — use
  after finding a suspicious function via SQL.
r2_decompile / upx_unpack / shellcode_extract / frida_static_probe:
  second-engine disasm, UPX -d unpack, shellcode+scdbg, hook candidates.
olevba_analyze / peepdf_analyze: Office/PDF triage (not for PE).
signature_match: crypto/stdlib/winapi function signature DBs (pass the
  function's imports/strings/constants from other tool output).
z3_solve / angr_analyze: deobfuscation solvers — only for confirmed
  obfuscation (MBA/CFF), never first-line.

Your job:
1. Ground the verdict first: pe_parse + capa + malcat_analyze
   (+ pe_import_signals). Then 1-3 targeted calls: ghidra/ida SQL for
   functions/strings, floss/xor_string_search if strings are garbage,
   ghidra_decompile on the most suspicious function, speakeasy_emulate
   for behavioral confirmation.
   Do not repeat identical calls — reuse earlier outputs.
2. When done, reply with a FINAL flat JSON object ONLY (no markdown, no extra
   prose) with keys: verdict (malicious/unknown/benign), confidence
   (high/medium/low), summary, key_evidence (list of strings).
Converge quickly: 3-6 tool calls is enough for triage. Cite concrete
tool/SQL evidence. Never claim behavior without tool output.
MASQUERADE AWARENESS: VersionInfo/company metadata is trivially forged. If
Malcat anomalies/YARA/high-signal imports fire, verdict must be malicious
even if strings look legitimate.
BUDGET DISCIPLINE: limited tool calls; when a [BUDGET] note appears, converge
to your final answer immediately.
{dyn_note}"""
    agent = create_react_agent(llm, tools=tools, prompt=system_prompt)
    recursion_limit = max(16, int(max_steps) * 2 + 6)
    try:
        result = agent.invoke(
            {"messages": [HumanMessage(content=(
                f"Analyze sample {sha}. Use SQL + Malcat to deepen, then produce "
                "the final flat JSON verdict."))]},
            config={"recursion_limit": recursion_limit},
        )
    except Exception as e:
        return {"verdict": "unknown", "source": "deterministic_fallback",
                "history": history, "llm_analysis": f"agent error: {e}"}

    # parse final flat JSON from last AI message
    verdict = None
    llm_text = ""
    for msg in reversed(result.get("messages") or []):
        content = getattr(msg, "content", None)
        if isinstance(content, str) and content.strip():
            llm_text = content.strip()
            try:
                start = content.find("{")
                end = content.rfind("}")
                if start >= 0 and end > start:
                    data = json.loads(content[start:end + 1])
                    if isinstance(data, dict) and data.get("verdict"):
                        verdict = data
                        break
            except Exception:
                continue
    if verdict is None:
        return {"verdict": "unknown", "source": "deterministic_fallback",
                "history": history, "llm_analysis": llm_text[:4000]}
    return {"verdict": verdict, "source": "llm_judge",
            "history": history, "llm_analysis": llm_text[:8000]}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="WinRE LangGraph deep dive (static phase)")
    ap.add_argument("sha")
    ap.add_argument("--sample-name", required=True)
    ap.add_argument("--max-steps", type=int, default=10)
    ap.add_argument("--dry", action="store_true",
                    help="no LLM — deterministic fallback only")
    ap.add_argument("--dynamic", action="store_true",
                    help="expose bounded x64dbg debug-loop tools to the agent")
    ap.add_argument("--keep", action="store_true",
                    help="keep x64dbg + sample alive after the run "
                         "(default: neat teardown)")
    args = ap.parse_args()
    out = None
    try:
        out = run_langgraph_deep_dive(args.sample_name, args.sha,
                                      max_steps=args.max_steps, dry=args.dry,
                                      dynamic=args.dynamic)
    finally:
        if args.dynamic and not args.keep:
            # neat closure: no halted sample, no x64dbg GUI left behind
            try:
                from winre.mcp.x64dbg_manager import teardown
                t = teardown()
                print(f"[teardown] stopped={t.get('stopped')} "
                      f"exited={t.get('exited')} killed={t.get('killed')}")
            except Exception as e:
                print(f"[teardown] error: {e}")
    print(json.dumps(out, indent=2, default=str))
