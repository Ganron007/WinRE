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

from winre import remote_driver  # noqa: E402
from winre.evidence import EvidencePack  # noqa: E402


# ---------------------------------------------------------------------------
# ToolRegistry — wraps the actual WinRE tool calls
# ---------------------------------------------------------------------------
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

    def ghidra_query(self, sql: str, max_rows: int = 25) -> dict:
        """SQL against the Ghidra tables on the VM (funcs/strings/imports)."""
        # canonical @funcs or raw SQL — pass through the wrapper CLI
        script = "query"
        if sql.startswith("@"):
            pass
        else:
            sql = sql.strip()
        py = r"C:\Python313\python.exe"
        remote = rf'{self.cfg["remote_pipeline"]}\tools\flare_ghidra_sql.py'
        cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
               f'{remote} query "{sql}" --file {self.remote_sample} --json 2>&1"')
        r = remote_driver.ssh_run(self.cfg, cmd, timeout=900)
        if r.returncode != 0:
            return {"error": (r.stderr or r.stdout)[-300:]}
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"error": f"non-JSON: {r.stdout[-200:]}"}

    def ida_query(self, sql: str) -> dict:
        """SQL against the IDA database on the VM (funcs/imports/strings)."""
        i64 = self.remote_sample + ".i64"
        py = r"C:\Python313\python.exe"
        remote = rf'{self.cfg["remote_pipeline"]}\tools\flarevm_ida_query.py'
        cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
               f'{remote} {self.remote_sample} "{sql}" --json 2>&1"')
        r = remote_driver.ssh_run(self.cfg, cmd, timeout=120)
        if r.returncode != 0:
            return {"error": (r.stderr or r.stdout)[-300:]}
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"error": f"non-JSON: {r.stdout[-200:]}"}

    def malcat_analyze(self, path: str | None = None) -> dict:
        """Malcat analysis over HTTP MCP (:9009) — metadata/anomalies/yara."""
        try:
            from winre.mcp import MalcatClient
            host = self.cfg["host"]
            mc = MalcatClient(base=f"http://{host}:9009/mcp")
            r = mc.analyse_file(path or self.remote_sample)
            return r.get("result") or {"error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}

    def malcat_functions(self, count: int = 10) -> dict:
        """Top-N most interesting functions (Malcat heuristics)."""
        try:
            from winre.mcp import MalcatClient
            host = self.cfg["host"]
            mc = MalcatClient(base=f"http://{host}:9009/mcp")
            r = mc.fns_top_list(self.remote_sample, count=count)
            return r.get("result") or {"error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}

    def malcat_decompile(self, address: int) -> dict:
        """Decompile one function by address (Malcat MCP)."""
        try:
            from winre.mcp import MalcatClient
            host = self.cfg["host"]
            mc = MalcatClient(base=f"http://{host}:9009/mcp")
            r = mc.fn_decompile(self.remote_sample, address=address)
            return r.get("result") or {"error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}


# ---------------------------------------------------------------------------
# LangGraph ReAct (static phase)
# ---------------------------------------------------------------------------
TOOL_NAMES = ("ghidra_query", "ida_query", "malcat_analyze",
              "malcat_functions", "malcat_decompile")


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


_ARG_MODELS: dict[str, type[BaseModel]] = {
    "ghidra_query": GhidraQueryArgs,
    "ida_query": IdaQueryArgs,
    "malcat_analyze": EmptyArgs,
    "malcat_functions": MalcatFnArgs,
    "malcat_decompile": MalcatDecompileArgs,
}


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"... (truncated {len(s) - n} chars)"


def run_langgraph_deep_dive(sample_name: str, sha: str, *,
                            max_steps: int = 10,
                            log_dir: Path | None = None,
                            dry: bool = False) -> dict:
    """Run the LangGraph ReAct agent over the static toolset.

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

    tools = [_make(n) for n in TOOL_NAMES]

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

Your job:
1. Use ghidra_query / ida_query / malcat_* to deepen the RE — imports,
   suspicious functions, strings, anomalies, decompile key functions.
2. When done, reply with a FINAL flat JSON object ONLY (no markdown) with keys:
   verdict (malicious/unknown/benign), confidence (high/medium/low),
   summary, key_evidence (list of strings).
Cite concrete tool/SQL evidence. Never claim behavior without tool output.
MASQUERADE AWARENESS: VersionInfo/company metadata is trivially forged. If
Malcat anomalies/YARA/high-signal imports fire, verdict must be malicious
even if strings look legitimate.
BUDGET DISCIPLINE: limited tool calls; don't repeat identical queries; when a
[BUDGET] note appears, converge to your final answer.
"""
    agent = create_react_agent(llm, tools=tools, prompt=system_prompt)
    recursion_limit = max(8, int(max_steps) * 2 + 4)
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
    args = ap.parse_args()
    out = run_langgraph_deep_dive(args.sample_name, args.sha,
                                  max_steps=args.max_steps, dry=args.dry)
    print(json.dumps(out, indent=2, default=str))
