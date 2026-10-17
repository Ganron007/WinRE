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
import time as _time
from pathlib import Path
from typing import Any, Callable
from collections.abc import Sequence

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


_REMOTE_GHDEC_HELPER = r'''
"""Remote Ghidra-decompile helper — runs on FlareVM via scp.

Usage: python _remote_ghdec_helper.py <b64_sample> <b64_func>
Prints JSON: {"ghidra_decompile": {...}}. Args are base64 (no quoting
issues through SSH/powershell) — same pattern as _remote_sql_helper.
"""
import base64
import json
import sys
from pathlib import Path

sample = base64.b64decode(sys.argv[1]).decode()
func = base64.b64decode(sys.argv[2]).decode()
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import flare_static_tools as fst
try:
    out = fst.ghidra_decompile(sample, func)
except Exception as e:
    out = {"ok": False, "error": str(e)[:250]}
print(json.dumps({"ghidra_decompile": out}, default=str))
'''


def _ps_py(py: str, code: str) -> str:
    """Build a `powershell -EncodedCommand` command that runs a python
    one-liner on the VM, with zero quoting hazards over SSH.

    The encoded payload must be a POWERSHELL script (not the python code):
    the python source rides inside a single-quoted PowerShell here-string
    and is handed to `python -c $c`. This is the only nesting-safe form —
    embedding python directly in -EncodedCommand parses as PowerShell, and
    -Command "..." breaks on the inner quotes.
    """
    import base64 as _b64
    ps = "$c = @'\n" + code + "\n'@\n& " + py + " -c $c\n"
    enc = _b64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    return ("powershell -NoProfile -ExecutionPolicy Bypass "
            f"-EncodedCommand {enc}")



class ToolRegistry:
    """Deterministic tool calls the agent may make (static phase).

    mode="local"  — running ON the FlareVM; tools execute via subprocess
                    (no SSH hop). Malcat MCP at 127.0.0.1:9009.
    mode="remote" — running on the control plane; tools execute via
                    SSH-exec / scp'd helpers (default).

    Both modes produce the SAME evidence — the transport differs only.
    """

    def __init__(self, sample_name: str, sha: str, cfg: dict | None = None,
                 mode: str = "remote", remote_sample: str | None = None):
        self.sample_name = sample_name
        self.sha = sha
        self.cfg = cfg or remote_driver.flare_cfg()
        self.mode = mode  # "local" = VM-side subprocess; "remote" = SSH
        self.remote_sample = remote_sample or rf"C:\samples\{sample_name}"
        self._dbg_ensured = False
        self._dbg_ensure_error: dict | None = None
        self._dbg_ensure_info: dict | None = None
        self._dbg_sample_path: str | None = None
        self.packed_signal: dict | None = None

    def call(self, name: str, args: dict) -> dict:
        fn = getattr(self, name, None)
        if fn is None:
            return {"status": "failed", "reason_code": "unknown_tool",
                    "error": f"unknown tool {name}"}
        try:
            result = fn(**args)
        except TypeError as e:
            result = {"status": "failed", "reason_code": "invalid_arguments",
                      "error": f"bad args for {name}: {e}"}
        except Exception as e:
            result = {"status": "failed", "reason_code": "tool_exception",
                      "error": f"{name} failed: {e}"}
        from .capabilities import decorate_result
        result = decorate_result(name, result)
        # Applicability is based on a producer's structured format field, not
        # on English skip text. Preserve the check itself as an explicit state.
        if isinstance(result, dict) and name == "peepdf_analyze" \
                and result.get("is_pdf") is False:
            result.update(status="not_applicable",
                          reason_code="input_not_pdf")
        if isinstance(result, dict) and name == "olevba_analyze" \
                and result.get("is_office_doc") is False:
            result.update(status="not_applicable",
                          reason_code="input_not_office_document")
        return result

    # --- static tools ------------------------------------------------------

    def _run_remote_py(self, helper_name: str, *args: str, timeout: int = 900,
                       helper_src: str | None = None) -> dict:
        """Run a scp'd helper .py on the VM and parse its JSON stdout.

        Args are base64-encoded (single safe tokens) so spaces/quotes/parens
        in SQL can never be mangled by the SSH→powershell nesting. The helper
        decodes them back.
        """
        import base64
        src = helper_src if helper_src is not None else _REMOTE_SQL_HELPER
        local = REPO / "winre" / f"_{helper_name}.py"
        local.write_text(src, encoding="utf-8")
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
        if self.mode == "local":
            import subprocess as _sp
            tools = Path(r"C:\WinRE\tools")
            p = _sp.run([sys.executable, str(tools / "flare_ghidra_sql.py"),
                         "query", sql, "--file", self.remote_sample, "--json"],
                        capture_output=True, text=True, timeout=900,
                        encoding="utf-8", errors="replace")
            try:
                out = json.loads(p.stdout)
            except json.JSONDecodeError:
                out = {"ok": False, "error": (p.stderr or p.stdout)[-300:]}
        else:
            out = self._run_remote_py("_remote_sql_helper", "ghidra",
                                      self.remote_sample, sql)
        if isinstance(out, dict) and out.get("ok") is not None:
            rows = out.get("rows") or []
            if max_rows and len(rows) > max_rows:
                out["rows"] = rows[:max_rows]
                out["row_count"] = len(rows[:max_rows])
        return out

    def malcat_analyze(self, path: str | None = None) -> dict:
        """Malcat analysis (:9009, localhost-bound on VM)."""
        if self.mode == "local":
            from winre.mcp import MalcatClient
            mc = MalcatClient()
            r = mc.analyse_file(path or self.remote_sample)
            if not r.get("ok"):
                return {"error": r.get("error")}
            return r.get("result") or {}
        try:
            return self._malcat("analyse_file",
                                {"path": path or self.remote_sample})
        except Exception as e:
            return {"error": str(e)}

    # --- RevAI-parity static evidence tools (free surface) -----------------

    def _vm_tool(self, tool: str, timeout: int = 1200) -> dict:
        """Run tools/flare_static_tools.py <tool> on the sample.

        mode="local": subprocess directly (we ARE on the FlareVM — no SSH).
        mode="remote": SSH-exec to the VM.
        Both produce the same JSON — transport differs only.
        """
        import subprocess as _sp
        tools_dir = r"C:\WinRE\tools"
        if self.mode == "local":
            try:
                p = _sp.run([sys.executable, tools_dir + r"\flare_static_tools.py",
                             tool, self.remote_sample],
                            capture_output=True, text=True, timeout=timeout,
                            encoding="utf-8", errors="replace")
                if p.returncode != 0:
                    return {"error": (p.stderr or p.stdout)[-250:]}
                out = json.loads(p.stdout)
                return out.get(tool) or {"error": "no tool payload"}
            except Exception as e:
                return {"error": str(e)[:250]}
        # remote mode: SSH-exec
        py = r"C:\Python313\python.exe"
        cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
               f'{tools_dir}\\flare_static_tools.py '
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

    def threat_intel(self) -> dict:
        """Known-tool/vendor identification: Authenticode signer, version
        info, security-tool markers, Malcat kesakode (when keyed)."""
        return self._vm_tool("threat_intel")

    def strings_tool(self) -> dict:
        """ASCII/unicode strings from the sample."""
        return self._vm_tool("strings")

    def yarascan(self) -> dict:
        """yara-x scan against the staged curated ruleset."""
        return self._vm_tool("yarascan")

    def pe_import_signals(self) -> dict:
        """High-signal import→ATT&CK map (pefile; NOT capa)."""
        return self._vm_tool("pe_import_signals")

    def api_hash_resolver(self) -> dict:
        """Detect runtime API-hash import resolvers (AMAT Track 8 / MalTrak
        Emotet). Scans executable sections for 4-byte constants matching
        known-algorithm hashes of common Windows API names. signal=true =>
        the binary resolves imports by hash at runtime (anti-import-table);
        matched names reveal the resolved API surface."""
        return self._vm_tool("api_hash_resolver")

    def crypto_constants(self) -> dict:
        """FindCrypt-class scan: crypto magic constants + AES S-box in
        executable sections -> crypto_identified tags (config/key recovery
        leads)."""
        return self._vm_tool("crypto_constants")

    def mitigations(self) -> dict:
        """PE mitigation catalog (ASLR/DEP/SEH/CFG...). Low-coverage is a
        weak evasion-pipeline signal, never a verdict driver."""
        return self._vm_tool("mitigations")

    def sink_sites(self) -> dict:
        """Dangerous-API call sites in top functions (r2). Provenance =
        caller function name. Evidence for the report sinks section."""
        return self._vm_tool("sink_sites")

    def rtf_predecode(self) -> dict:
        """RTF container decode (control words/hex/\\bin/OLE2) — run BEFORE
        olevba; embedded OLE2 means extract + olevba that blob."""
        return self._vm_tool("rtf_predecode")

    def string_decode_emulate(self) -> dict:
        """Encoded-config recovery: high-entropy blob windows decoded with
        xor/add/sub/rol keys (1-2 byte + date-seeded) -> plaintext config
        candidates. Seed for the config-extractor deliverable."""
        return self._vm_tool("string_decode_emulate")

    def rolling_xor(self) -> dict:
        """Rolling/date-seeded XOR key recovery via known-plaintext guidance
        (nested PE 'MZ', compile-date keys) — beats fixed single-key
        bruteforce on Qakbot-class loaders."""
        return self._vm_tool("rolling_xor")

    def script_decode(self) -> dict:
        """Script-stage deobfuscation: base64/deflate layers, FromCharCode
        chains, embedded PE/shellcode in scripts (PS/JS/VBS/HTA)."""
        return self._vm_tool("script_decode")

    def ioc_extract(self) -> dict:
        """IOC extraction: wallets (btc/eth/xmr/ltc) + defanged URLs +
        domains/IPs/emails from strings."""
        return self._vm_tool("ioc_extract")

    def goresym_analyze(self) -> dict:
        """Go binary symbol recovery (goresym); honest skip when not Go."""
        return self._vm_tool("goresym_analyze")

    def decrypt_gate(self) -> dict:
        """Analysis-readiness gate (AMAT Track 7): import-stripped + sparse
        strings + packer taxonomy -> 'gated' status. When gated, capa/strings
        evidence is UNRELIABLE and must not drive the verdict."""
        return self._vm_tool("decrypt_gate")

    def signature_match(self, func_name: str = "", imports: list | None = None,
                        strings: list | None = None, constants: list | None = None,
                        size: int = 0) -> dict:
        """Match a function against crypto/stdlib/winapi signature DBs."""
        payload = json.dumps({"func_name": func_name, "imports": imports or [],
                              "strings": strings or [], "constants": constants or [],
                              "size": size}, default=str)
        import base64
        b64 = base64.b64encode(payload.encode()).decode()
        if self.mode == "local":
            # VM-side: run the tool via subprocess (no ssh hop)
            import subprocess as _sp
            import sys as _sys
            tools_dir = r"C:\WinRE\tools"
            try:
                p = _sp.run(
                    [_sys.executable, tools_dir + r"\flare_static_tools.py",
                     "signature_match", self.remote_sample,
                     "--json-args", b64],
                    capture_output=True, text=True, timeout=300,
                    encoding="utf-8", errors="replace")
                if p.returncode != 0:
                    return {"error": (p.stderr or p.stdout)[-250:]}
                return json.loads(p.stdout).get("signature_match") or {}
            except Exception as e:
                return {"error": str(e)[:250]}
        py = r"C:\Python313\python.exe"
        _oneliner = (
            "import sys,json,base64; "
            "sys.path.insert(0, r'C:\\WinRE\\tools'); "
            "import flare_static_tools as fst; "
            f"kw = json.loads(base64.b64decode('{b64}').decode()); "
            "print(json.dumps({'signature_match': "
            "fst.signature_match(**kw)}))")
        cmd = _ps_py(py, _oneliner)
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
            _oneliner = (
                "import sys,json,base64; "
                "sys.path.insert(0, r'C:\\WinRE\\tools'); "
                "import flare_static_tools as fst; "
                f"fa = json.loads(base64.b64decode('{b64}').decode()); "
                f"print(json.dumps({{'r2_decompile': fst.r2_decompile("
                f"r'{self.remote_sample}', fa)}}))")
            cmd = _ps_py(r"C:\Python313\python.exe", _oneliner)
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
        FUN_ name, or 'entry'). Uses the scp'd helper pattern (same as
        _remote_sql_helper) — no inline code over SSH."""
        function_addr = str(function_addr or "").strip()
        # Reject control characters and quote/statement syntax before this
        # value is embedded in the local helper source or passed to Ghidra.
        if (not function_addr or len(function_addr) > 80
                or any(ord(ch) < 32 for ch in function_addr)
                or not __import__("re").fullmatch(r"[A-Za-z0-9_.$:@?+-]+", function_addr)):
            return {"ok": False, "status": "failed",
                    "reason_code": "invalid_function_selector",
                    "error": "function_addr must be a short address or function name"}
        if self.mode == "local":
            import subprocess as _sp
            tools = Path(r"C:\WinRE\tools")
            code = (
                "import sys, json\n"
                "sys.path.insert(0, r'C:\\WinRE\\tools')\n"
                "import flare_static_tools as fst\n"
                f"print(json.dumps({{'ghidra_decompile': fst.ghidra_decompile(r'{self.remote_sample}', "
                f"'{(function_addr or 'entry').replace(chr(39), '')}')}}))\n"
            )
            helper = REPO / "winre" / "_local_ghdec_helper.py"
            helper.write_text(code, encoding="utf-8")
            p = _sp.run([sys.executable, str(helper)], capture_output=True,
                        text=True, timeout=2400,
                        encoding="utf-8", errors="replace")
            if p.returncode != 0:
                return {"error": (p.stderr or p.stdout)[-250:]}
            try:
                return json.loads(p.stdout).get("ghidra_decompile") or {}
            except json.JSONDecodeError:
                return {"error": f"non-JSON: {(p.stdout or '')[-200:]}"}
        out = self._run_remote_py("_remote_ghdec_helper", self.remote_sample,
                                  function_addr or "entry", timeout=2400,
                                  helper_src=_REMOTE_GHDEC_HELPER)
        if "error" in out:
            return out
        return out.get("ghidra_decompile") or out

    def ida_query(self, sql: str) -> dict:
        """SQL against the IDA database on the VM (funcs/imports/strings).
        Skips honestly when no .i64 exists yet (idat analysis is a deep-stage
        pre-step; running it here burns the agent's budget)."""
        if self.mode == "local":
            import subprocess as _sp
            i64 = Path(self.remote_sample).with_suffix(
                Path(self.remote_sample).suffix + ".i64")
            if not i64.is_file():
                return {"status": "unavailable", "reason_code": "ida_database_missing",
                        "skipped": "no .i64 on VM yet",
                        "hint": "use ghidra_query / ghidra_decompile instead"}
            # HTTP transport on an existing .i64 is fast; the one-shot path
            # re-runs idat auto-analysis (10+ min on packed) — never in the
            # checklist. IDA is commercial-OPTIONAL: if the HTTP server can't
            # start fast, degrade to an honest skip (Ghidra is primary).
            tools = Path(r"C:\WinRE\tools")
            p = _sp.run([sys.executable, str(tools / "flarevm_ida_query.py"),
                         self.remote_sample, sql, "--http", "--json"],
                        capture_output=True, text=True, timeout=120,
                        encoding="utf-8", errors="replace")
            try:
                res = json.loads(p.stdout)
            except json.JSONDecodeError:
                return {"status": "unavailable", "reason_code": "ida_query_failed",
                        "skipped": "idasql http query failed",
                        "detail": (p.stderr or p.stdout)[-200:],
                        "hint": "use ghidra_query instead"}
            if not res.get("ok"):
                return {"status": "unavailable", "reason_code": "ida_server_unavailable",
                        "skipped": "idasql server unavailable",
                        "detail": str(res.get("error") or "")[:200],
                        "hint": "use ghidra_query instead"}
            return res
        # remote mode: SSH existence check + scp'd helper
        r = remote_driver.ssh_run(self.cfg, f'powershell -NoProfile -Command "Test-Path '
                                  f"'C:\\samples\\{Path(self.remote_sample).name}.i64'\"",
                                  timeout=30)
        if "True" not in (r.stdout or ""):
            return {"status": "unavailable", "reason_code": "ida_database_missing",
                    "skipped": "no .i64 on VM yet (deep dive pre-step creates it)",
                    "hint": "use ghidra_query / ghidra_decompile instead"}
        return self._run_remote_py("_remote_sql_helper", "ida",
                                   self.remote_sample, sql, timeout=600)


    def _malcat(self, tool: str, args: dict) -> dict:
        """Malcat MCP via SSH-exec bridge (port is localhost-bound on VM).

        View tools (fns_top_list, fn_decompile, anomalies_list, yara_list,
        strings_*) expect {"analysis_id"} — resolved once per sample and
        cached on the registry.
        """
        from winre.remote_driver import malcat_remote_call, malcat_remote_aid
        if tool in ("fns_top_list", "fn_decompile", "anomalies_list",
                    "yara_list", "strings_top_list", "strings_search",
                    "fn_disassemble", "fn_infos", "constants_list"):
            path = args.get("path") or self.remote_sample
            if not hasattr(self, "_malcat_aids"):
                self._malcat_aids = {}
            aid, err = malcat_remote_aid(path, self._malcat_aids)
            if err is not None:
                return err
            params = {"analysis_id": aid}
            for k in ("ea", "address", "count", "pattern", "index", "subfile"):
                if k in args:
                    params["ea" if k == "address" else k] = args[k]
            r = malcat_remote_call(tool, params)
        else:
            r = malcat_remote_call(tool, args)
        return r.get("result") or {"error": r.get("error")}

    def malcat_functions(self, count: int = 10) -> dict:
        """Top-N most interesting functions (Malcat heuristics)."""
        if self.mode == "local":
            from winre.mcp import MalcatClient
            mc = MalcatClient()
            r = mc.fns_top_list(self.remote_sample, count=count)
            if not r.get("ok"):
                return {"error": r.get("error")}
            return r.get("result") or {}
        try:
            return self._malcat("fns_top_list",
                                {"path": self.remote_sample, "count": count})
        except Exception as e:
            return {"error": str(e)}

    def malcat_decompile(self, address: int) -> dict:
        """Decompile one function by address (Malcat MCP)."""
        if self.mode == "local":
            from winre.mcp import MalcatClient
            mc = MalcatClient()
            r = mc.fn_decompile(self.remote_sample, address=address)
            if not r.get("ok"):
                return {"error": r.get("error")}
            return r.get("result") or {}
        try:
            return self._malcat("fn_decompile",
                                {"path": self.remote_sample,
                                 "address": address})
        except Exception as e:
            return {"error": str(e)}

    # --- dynamic tools (x64dbg debug loops; opt-in, bounded) ---------------

    def _dbg_client(self):
        from winre.mcp import X64DbgClient
        return X64DbgClient(host=self.cfg["host"])

    def _dbg_sample(self) -> str:
        """Private expression-safe VM copy for x64dbg tools (staged once).

        x64dbg resolves module names via its expression parser: hyphens become
        subtraction and hex-looking stems become numbers, so DumpModule /
        DetectOEP / AnalyzeModule fail on names like `notepad-sys32.exe`.
        """
        if self._dbg_sample_path is None:
            from winre.mcp.x64dbg_manager import stage_safe_sample
            self._dbg_sample_path = stage_safe_sample(
                self.cfg, self.remote_sample, tag=(self.sha or "")[:12])
        return self._dbg_sample_path

    def _dbg_gate(self) -> dict | None:
        """Preflight before ANY debugger execution on the VM: snapshot gate
        plus a one-time x64dbg MCP heal.

        enforce: the FIRST debug call consumes the marker (same-sha calls
        later in this agent run pass via session scope); blocked -> tools
        return an error, agent falls back to static. enforce (default):
        advisory only — never blocks testing. If :9094 is down, bring x64dbg
        up once via the scheduled-task launcher (interactive session).
        """
        from winre import snapshot_gate
        g = snapshot_gate.preflight("debug", sha=self.sha, cfg=self.cfg)
        if not g.get("allowed"):
            return {"error": f"{g.get('error')} — falling back to static analysis"}
        if self.mode == "remote" and not self._dbg_ensured:
            self._dbg_ensured = True
            if remote_driver.mcp_autostart_enabled():
                try:
                    from winre.mcp.x64dbg_manager import ensure_mcp
                    ok, info = ensure_mcp(wait_s=45,
                                          sample=self._dbg_sample())
                    # recorded on SUCCESS too: the pack must show WHICH
                    # debugger produced the unpack evidence (x32dbg for a PE32
                    # image, x64dbg otherwise - P1-F1), otherwise a
                    # silently-wrong-flavour run is indistinguishable from a
                    # correct one
                    self._dbg_ensure_info = info
                    if not ok:
                        self._dbg_ensure_error = info
                except Exception as e:
                    self._dbg_ensure_error = {"error": str(e)[:150]}
            if self._dbg_ensure_error:
                return {"error": "x64dbg MCP :9094 unavailable: "
                                 + str(self._dbg_ensure_error.get("error")
                                       or self._dbg_ensure_error)[:200]}
        return None

    def x64dbg_oep(self) -> dict:
        """Load at the entry point, then find a later OEP only for packed files."""
        gate = self._dbg_gate()
        if gate:
            return gate
        try:
            from winre import debug_loops
            sample = self._dbg_sample()
            client = self._dbg_client()
            if not self.packed_signal:
                r = debug_loops.ep_break(sample, xc=client)
                return {"ok": r.get("ok"),
                        "status": "completed" if r.get("ok") else "failed",
                        "method": "entrypoint_observation",
                        "entrypoint": r.get("oep"),
                        "error": r.get("error"),
                        "diagnostics": r.get("diagnostics"),
                        "evidence": r.get("evidence") or []}
            r = debug_loops.oep_by_section(sample, xc=client)
            return {"ok": r.get("ok"),
                    "status": "completed" if r.get("ok") else "failed",
                    "method": "memory_execute_oep", "oep": r.get("oep"),
                    "oep_target": r.get("target"),
                    "error": r.get("error"),
                    "diagnostics": r.get("diagnostics"),
                    "evidence": r.get("evidence") or []}
        except Exception as e:
            return {"error": str(e)}

    def x64dbg_run_window(self) -> dict:
        """Resume the current debug target for a bounded process-observation window."""
        gate = self._dbg_gate()
        if gate:
            return {"ok": False, "status": "failed",
                    "reason_code": "debug_gate_blocked",
                    "error": gate.get("error")}
        try:
            from winre import debug_loops
            return debug_loops.run_debug_window(
                xc=self._dbg_client(), seconds=30)
        except Exception as e:
            return {"ok": False, "status": "failed",
                    "reason_code": "debug_window_exception",
                    "error": f"{type(e).__name__}: {str(e)[:200]}"}

    def x64dbg_wpm_dump(self, max_hits: int = 3) -> dict:
        """BP WriteProcessMemory, dump written buffers (bounded hits)."""
        gate = self._dbg_gate()
        if gate:
            return gate
        try:
            from winre import debug_loops
            r = debug_loops.wpm_dump(self._dbg_sample(),
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
            r = debug_loops.crypt_dump(self._dbg_sample(),
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
            r = debug_loops.agentic_unpack(self._dbg_sample(),
                                           xc=self._dbg_client())
            return {"ok": r.get("ok"), "oep": r.get("oep"),
                    "entrypoint": r.get("entrypoint"),
                    "dump_path": r.get("dump_path"),
                    "comparison": r.get("comparison"),
                    "error": r.get("error"),
                    "method": r.get("method"),
                    "attempts": r.get("attempts"),
                    "oep_target": r.get("oep_target"),
                     "evidence": r.get("evidence") or [],
                    "dump_kind": r.get("dump_kind"),
                    "dump_source": r.get("dump_source"),
                    "heap_region": r.get("heap_region"),
                    "dump_parse": r.get("dump_parse"),
                    "rebuild_hint": r.get("rebuild_hint"),
                    "artifact": r.get("artifact"),
                    "diagnostics": r.get("diagnostics"),
                    "fallback_trace": r.get("fallback_trace"),
                    "fallback_summary": r.get("fallback_summary")}
        except Exception as e:
            return {"error": str(e)}

    def x64dbg_write_bp_trace(self) -> dict:
        """Write-BP memory-source trace (AMAT Track 14): HW write bp on the
        module header, run, capture WHO wrote it (RIP + module + regs) —
        the memory SOURCE of the unpacker write."""
        gate = self._dbg_gate()
        if gate:
            return gate
        try:
            from winre import debug_loops
            r = debug_loops.write_bp_trace(self._dbg_sample(),
                                           xc=self._dbg_client())
            return {"ok": r.get("ok"), "hit": r.get("hit"),
                    "summary": r.get("summary"), "error": r.get("error")}
        except Exception as e:
            return {"error": str(e)}

    def windbg_analyze_dump(self, dump: str = "") -> dict:
        """Dump interpretation runs on the control plane after evidence pull.

        The agent tool must not ask the guest that ran the sample to interpret
        its dump, even though opening a dump is passive. The post-pull analysis
        step owns that work and records missing local cdb as unavailable.
        """
        return {"status": "not_applicable",
                "reason_code": "deferred_to_control_plane",
                "skipped": "WinDbg analysis runs after the dynamic pack is pulled",
                "requested_dump": Path(str(dump)).name if dump else None}


# ---------------------------------------------------------------------------
# LangGraph ReAct (static phase)
# ---------------------------------------------------------------------------
TOOL_NAMES = ("ghidra_query", "ida_query", "malcat_analyze",
              "malcat_functions", "malcat_decompile",
              "capa", "floss", "pe_parse", "diec", "strings_tool", "yarascan",
              "pe_import_signals", "api_hash_resolver", "xor_string_search",
              "olevba_analyze",
              "peepdf_analyze", "speakeasy_emulate", "frida_static_probe",
              "r2_decompile", "upx_unpack", "shellcode_extract",
              "dotnet_analyze", "z3_solve", "angr_analyze", "ghidra_decompile",
              "crypto_constants", "mitigations", "sink_sites",
              "rtf_predecode", "string_decode_emulate", "rolling_xor",
              "script_decode", "ioc_extract", "goresym_analyze",
              "decrypt_gate", "threat_intel")
# Opt-in dynamic tools: x64dbg debug loops over MCP. Bounded, deterministic
# primitives — the LLM composes them, never free-forms debugger commands.
DYNAMIC_TOOL_NAMES = ("x64dbg_oep", "x64dbg_wpm_dump",
                      "x64dbg_crypt_dump", "x64dbg_unpack",
                      "x64dbg_write_bp_trace", "windbg_analyze_dump")


class GhidraQueryArgs(BaseModel):
    sql: str = Field(..., description="SQL against Ghidra tables (funcs/strings/imports)")
    max_rows: int = Field(25, description="max rows")


class IdaQueryArgs(BaseModel):
    sql: str = Field(..., description="SQL against IDA tables")


class GhidraDecompileArgs(BaseModel):
    function_addr: str = Field(
        ..., min_length=1, max_length=80,
        description="Exact Ghidra function address or function name to decompile")


class EmptyArgs(BaseModel):
    pass


class MalcatFnArgs(BaseModel):
    count: int = Field(10, description="how many top functions")


class MalcatDecompileArgs(BaseModel):
    address: int = Field(..., description="function address to decompile")


class X64DbgHitsArgs(BaseModel):
    max_hits: int = Field(3, description="max BP hits to service (bounded)")


class WindbgDumpArgs(BaseModel):
    dump: str = Field("", description="dump filename inside dynamic/memory/ "
                                      "(default: newest capture)")


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
    "api_hash_resolver": EmptyArgs,
    "xor_string_search": EmptyArgs,
    "crypto_constants": EmptyArgs,
    "mitigations": EmptyArgs,
    "sink_sites": EmptyArgs,
    "rtf_predecode": EmptyArgs,
    "string_decode_emulate": EmptyArgs,
    "rolling_xor": EmptyArgs,
    "script_decode": EmptyArgs,
    "ioc_extract": EmptyArgs,
    "goresym_analyze": EmptyArgs,
    "decrypt_gate": EmptyArgs,
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
    "ghidra_decompile": GhidraDecompileArgs,
    "x64dbg_oep": EmptyArgs,
    "x64dbg_wpm_dump": X64DbgHitsArgs,
    "x64dbg_crypt_dump": X64DbgHitsArgs,
    "x64dbg_unpack": EmptyArgs,
    "x64dbg_write_bp_trace": EmptyArgs,
    "windbg_analyze_dump": WindbgDumpArgs,
}


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"... (truncated {len(s) - n} chars)"


def _ctx_budget_chars() -> int:
    """Chars we may feed the LLM, derived from the model context window.

    Use the configured window, capped by the provider's published limit.
    This is an estimate at ~3.6 chars/token, with 30% reserved for the
    system prompt, planner history and the final answer.
    """
    from winre.llm_client import context_window_tokens
    return max(1, int(context_window_tokens() * 3.6 * 0.7))


def _quick_brief(quick: dict | None) -> str:
    """Compact quick-evidence summary for the agent's opening message.

    The agent still verifies everything via tools (nothing is trusted
    blindly) — this just saves ~3 turns of re-discovery. Mirrors RevAI's
    session-context injection (source_decisions from intake).
    """
    if not isinstance(quick, dict):
        return ""
    ev = quick.get("evidence") or {}
    parts = []
    gh = ev.get("ghidra") or {}
    if gh.get("func_rows") is not None:
        parts.append(f"Ghidra funcs={gh.get('func_rows')}")
    ida = ev.get("ida") or {}
    if ida.get("func_count") is not None:
        parts.append(f"IDA funcs={ida.get('func_count')}")
    mc = ev.get("malcat") or {}
    f = mc.get("file") or {}
    if f.get("entropy") is not None:
        parts.append(f"Malcat entropy={f.get('entropy')}")
    if mc.get("anomalies"):
        an = mc["anomalies"]
        names = [a.get("name", "?") for a in an[:4]] if isinstance(an, list) else []
        parts.append(f"Malcat anomalies={len(an) if isinstance(an, list) else '?'}"
                     + (f" ({', '.join(names)})" if names else ""))
    if mc.get("yara_hits"):
        yh = mc["yara_hits"]
        parts.append(f"Malcat yara_hits={len(yh) if isinstance(yh, list) else yh}")
    capa = ev.get("capa") or {}
    caps = [c.get("name") for c in (capa.get("capabilities") or [])][:5]
    if caps:
        parts.append("capa: " + ", ".join(caps))
    pe = ev.get("pe") or {}
    if pe.get("signed") is not None:
        parts.append(f"signed={pe.get('signed')}")
    fl = ev.get("floss") or {}
    if fl.get("total_decoded") is not None:
        parts.append(f"floss decoded={fl.get('total_decoded')}")
    dc = ev.get("diec") or {}
    if dc.get("detects"):
        parts.append("diec: " + ", ".join(str(d) for d in dc["detects"][:3]))
    ys = ev.get("yarascan") or {}
    if isinstance(ys, dict):
        hs = [str(h).split()[0] for h in (ys.get("high_signal") or []) if str(h).strip()]
        if hs:
            parts.append("yarascan high-signal: " + ", ".join(hs[:3]))
    if not parts:
        return ""
    return "Quick triage already found: " + "; ".join(parts) + ". "


# ── Packer-signal routing (W1) ──────────────────────────────────────────────
_PACKER_WORDS = (
    "upx", "aspack", "fsg", "mew", "mpress", "pecompact", "petite", "upack",
    "nspack", "armadillo", "themida", "vmprotect", "enigma", "obsidium",
    "protector", "protect", "packer", "packed", "custom virtual", "spaghetti",
    "crypter",
)

# Packing threshold in BITS PER BYTE, on the 0-8 Shannon scale that pefile,
# DIE and X-ray all use. Malcat reports entropy x 32 in a 0-255 integer, so
# this is compared AFTER conversion (see _packer_signal).
#
# Two thresholds, because they measure different things:
#   _PACKED_ENTROPY_BPB      - the FILE average. A file that is uniformly
#                              high-entropy (solid shellcode, whole-file
#                              encryption) trips this.
#   _PACKED_SECTION_BPB      - a single SECTION. A 3 MB packed .rsrc inside an
#                              otherwise ordinary file drags the average down
#                              to look unpacked, which is exactly how b108
#                              (real WannaCry, .rsrc = 226 = 7.06 b/B, file
#                              average 224 = 7.00) slipped past a 7.2
#                              file-level threshold and lost the only signal
#                              that static evidence on it is unreliable.
#
# Both are set against the batch's measured unpacked maxima, not guessed:
#   b102 (benign) max section 2.31 b/B
#   b107 (benign) max section 4.13 b/B
#   b108 (packed) max section 7.06 b/B
_PACKED_ENTROPY_BPB = 7.2
_PACKED_SECTION_BPB = 6.5

# Malcat's entropy field is bits-per-byte x 32
_MALCAT_ENTROPY_SCALE = 32.0


def _is_managed_quick(quick: dict | None) -> bool:
    """True when quick evidence says the sample is a .NET/managed assembly.

    Managed assemblies have no native entry-point pause: the x64dbg OEP/unpack
    prepass is meaningless for them (and CLI tools exit immediately), so the
    dynamic stage must route to dotnet_analyze / windbg instead.
    """
    ev = (quick or {}).get("evidence") or {}
    if not isinstance(ev, dict):
        return False
    for key in ("pe_parse", "pe", "threat_intel", "dotnet_analyze"):
        v = ev.get(key)
        if isinstance(v, dict) and v.get("is_dotnet"):
            return True
    dc = ev.get("diec") or {}
    det = " ".join(str(d) for d in (dc.get("detects") or [])).lower()
    return ".net" in det or "dotnet" in det or "msil" in det


def _max_section_bpb(f: dict) -> tuple[str, float] | None:
    """The highest-entropy PE section, converted to bits-per-byte.

    Malcat reports it as bits-per-byte x 32 in a 0-255 integer, so the raw
    value cannot be compared to a Shannon-scale threshold.
    """
    best: tuple[str, float] | None = None
    for s in (f.get("layout") or []):
        if not isinstance(s, dict):
            continue
        e = s.get("entropy")
        if not isinstance(e, (int, float)):
            continue
        b = e / _MALCAT_ENTROPY_SCALE
        if best is None or b > best[1]:
            best = (str(s.get("name") or "?"), b)
    return best


def _max_pe_section_bpb(pe: dict) -> tuple[str, float] | None:
    """Return the highest PE-section entropy in bits per byte.

    The PE parser reports Shannon entropy directly on the 0-8 scale. Keep
    that separate from Malcat's ``layout`` values, which are scaled by 32.
    Reject out-of-range values rather than guessing which unit a producer
    used.
    """
    best: tuple[str, float] | None = None
    for section in (pe.get("sections") or []):
        if not isinstance(section, dict):
            continue
        entropy = section.get("entropy")
        if (isinstance(entropy, bool)
                or not isinstance(entropy, (int, float))
                or not 0.0 <= entropy <= 8.0):
            continue
        if best is None or entropy > best[1]:
            best = (str(section.get("name") or "?"), float(entropy))
    return best


def _packer_signal(quick: dict | None) -> dict | None:
    """Deterministic packer indicators from quick evidence (no tool calls).

    Returns None when nothing fires, else a compact dict that (a) routes the
    agent to the debugger unpack primitive and (b) is recorded in deep.json.

    UNIT. Malcat reports entropy as bits-per-byte scaled by 32, as a 0-255
    integer: .text=132 is 4.125 b/B, .rsrc=226 is 7.06 b/B, 0 is 0. Comparing
    that raw integer against a bits-per-byte threshold is a unit bug: it makes
    essentially every file look packed (any integer >= 7 passes) while never
    actually measuring packing. Convert, then emit a thresholded verdict rather
    than a raw field - a route decision the agent has to re-derive from a
    number is how three samples in a row carried {"entropy": 71|107|224} with
    no unpacking work behind them.
    """
    ev = (quick or {}).get("evidence") or {}
    if not isinstance(ev, dict):
        return None
    sig: dict = {}
    dc = ev.get("diec") or {}
    detects = [str(d) for d in (dc.get("detects") or [])]
    hits = [d for d in detects
            if any(w in d.lower() for w in _PACKER_WORDS)]
    if hits:
        sig["diec"] = hits[:3]
    mc = ev.get("malcat") or {}
    f = mc.get("file") or {}
    ent = f.get("entropy")
    # Malcat's entropy field is bits-per-byte x 32 (see module constants)
    bpb = ent / _MALCAT_ENTROPY_SCALE if isinstance(ent, (int, float)) else None
    if bpb is not None and bpb >= _PACKED_ENTROPY_BPB:
        sig["entropy"] = round(bpb, 3)
    # A single packed section outranks a diluted file average. Both PE and
    # Malcat report section entropy, but their units differ: pefile is already
    # bits/byte while Malcat is x32. Normalize before comparing and retain the
    # producer so later analysis can explain the route decision.
    candidates: list[tuple[str, float, str]] = []
    malcat_sec = _max_section_bpb(f)
    if malcat_sec is not None:
        candidates.append((*malcat_sec, "malcat_layout"))
    pe_sec = _max_pe_section_bpb(ev.get("pe") or {})
    if pe_sec is not None:
        candidates.append((*pe_sec, "pe_sections"))
    if candidates:
        name, sb, source = max(candidates, key=lambda row: row[1])
        if sb >= _PACKED_SECTION_BPB:
            sig["packed_section"] = {
                "name": name, "bits_per_byte": round(sb, 3), "source": source,
            }
    an = mc.get("anomalies") or []
    if isinstance(an, list):
        ahits = [str(a.get("name")) for a in an if isinstance(a, dict)
                 and any(w in str(a.get("name", "")).lower()
                         for w in ("pack", "entrop", "overlay", "section"))]
        if ahits:
            sig["anomalies"] = ahits[:4]
    return sig or None


def _packer_note(sig: dict | None, prepass: dict | None,
                 dynamic: bool) -> str:
    if not sig:
        return ""
    # entropy is now bits-per-byte, so name the unit for the reader
    txt = ", ".join(
        f"{k}={v} bits/byte" if k == "entropy" else f"{k}={v}"
        for k, v in sig.items())
    if not dynamic:
        return (f"\nPACKER SIGNAL: {txt}. Static evidence on packed bytes is "
                "UNRELIABLE (see decrypt_gate) — do not lean malicious on "
                "packed-byte strings alone; say what still holds.")
    if prepass and prepass.get("ok"):
        return (
            f"\nPACKER SIGNAL: {txt}. A deterministic unpack prepass ALREADY "
            "ran x64dbg_unpack (do NOT repeat it): "
            f"OEP={prepass.get('oep')}, dump={prepass.get('dump_path')}, "
            f"compare={json.dumps(prepass.get('comparison'), default=str)[:200]}. "
            "The unpacked image is the real analysis target — use SQL/floss on "
            "the unpacked code; x64dbg_write_bp_trace can chase staged unpackers.")
    err = (prepass or {}).get("error") or (prepass or {}).get("note")
    if prepass and not prepass.get("ok") and err:
        trace = prepass.get("fallback_trace") or {}
        trace_note = ""
        if isinstance(trace, dict) and trace.get("rip"):
            trace_note = (f" A write-BP memory-source trace was captured instead: "
                          f"header written by {trace.get('module')} @ {trace.get('rip')}.")
        return (f"\nPACKER SIGNAL: {txt}. The deterministic x64dbg_unpack prepass "
                f"produced no usable dump ({str(err)[:160]}).{trace_note} "
                "Prefer x64dbg_oep or x64dbg_write_bp_trace early; packed-byte "
                "static evidence is unreliable.")
    return (f"\nPACKER SIGNAL: {txt}. Prefer the debugger pathway "
            "(x64dbg_unpack first) over static-only conclusions on packed bytes.")


# ── Curated-YARA verdict floor (W2) ─────────────────────────────────────────

def _yara_rule_names(payload) -> list[str]:
    """Rule names from a yarascan result: high_signal when the classifier is
    present, else all hits (legacy)."""
    if not isinstance(payload, dict):
        return []
    src = payload.get("high_signal")
    if not isinstance(src, list):
        src = payload.get("hits")
    out = []
    for x in (src or []):
        name = str(x).split()[0].strip()
        if name:
            out.append(name)
    return out


def _curated_yara_hits(quick: dict | None, findings: dict) -> list[str]:
    """Family-distinctive curated YARA rule names from quick evidence + the
    tools the agent itself ran. Deterministic; no extra tool calls."""
    names: list[str] = []
    ev = (quick or {}).get("evidence") or {}
    if isinstance(ev, dict):
        names += _yara_rule_names(ev.get("yarascan"))
    for k, v in (findings or {}).items():
        if str(k).startswith("yarascan"):
            names += _yara_rule_names(v)
    seen: set = set()
    out: list[str] = []
    for n in names:
        low = str(n).lower()
        # Auto-generated CADRE_v2_* rules and packer/compressor family rules
        # routinely match packed legitimate binaries - not floor-worthy.
        if low.startswith("cadre_v2_") or any(h in low for h in (
                "nspack", "upack", "aspack", "mpress", "fsg", "pecompact",
                "petite", "upx", "themida", "enigm", "vmprotect", "packman",
                "kkrunchy", "mew", "packed", "packer", "compressor")):
            continue
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _apply_verdict_floor(verdict: dict | None, rules: list[str]) -> dict | None:
    """Curated-YARA verdict floor: a below-malicious verdict cannot contradict
    a family-distinctive rule match (fixes malicious<->legit flapping across
    runs). Recorded, auditable — never silent."""
    if not isinstance(verdict, dict) or not rules:
        return verdict
    label = str(verdict.get("verdict") or "").strip().lower()
    if label == "malicious":
        return verdict
    out = dict(verdict)
    out["verdict"] = "malicious"
    out["confidence"] = "high"
    out["verdict_floored"] = True
    out["floor_source"] = "curated-yara"
    out["floor_rules"] = rules[:6]
    out["original_verdict"] = verdict.get("verdict")
    out["original_confidence"] = verdict.get("confidence")
    summary = str(verdict.get("summary") or "").strip()
    out["summary"] = ("Floored to malicious by high-signal curated YARA: "
                      + ", ".join(rules[:4])
                      + (". " + summary if summary else ""))
    out["rules_fired"] = list(verdict.get("rules_fired") or []) + \
        ["verdict-floor:curated-yara"]
    return out



def _normalize_verdict(verdict: dict) -> dict:
    """Map LLM verdict labels onto the pipeline enum (malicious/unknown/benign)."""
    if not isinstance(verdict, dict):
        return verdict
    raw = str(verdict.get("verdict") or "").strip().lower()
    mapping = {"tool/legit": "benign", "tool": "benign", "legit": "benign",
               "legitimate": "benign", "clean": "benign", "goodware": "benign",
               "benign-tool": "benign", "suspicious": "unknown",
               "malware": "malicious", "mal": "malicious"}
    mapped = mapping.get(raw, raw)
    if mapped not in ("malicious", "unknown", "benign"):
        # An off-enum label ("totally fine", "benign!!", true) is NOT a verdict.
        # It used to be silently rewritten to "unknown" and then recorded as a
        # judged, evidence-free verdict - indistinguishable from a real call
        # (code audit 2026-09-28, MEDIUM). Mark it invalid so the stage can
        # treat the verdict as missing.
        return {"verdict_invalid": True,
                "verdict_raw": verdict.get("verdict"),
                "verdict": None, "confidence": verdict.get("confidence"),
                "key_evidence": verdict.get("key_evidence") or [],
                "summary": verdict.get("summary")}
    if mapped != raw:
        out = dict(verdict)
        out["verdict_raw"] = verdict.get("verdict")
        out["verdict"] = mapped
        return out
    return verdict


def _llm_roles() -> dict:
    """Resolved per-role models for this run (llm_client is the only resolver).

    Recorded in deep.json so a consumer can verify WHICH model produced the
    tool loop and WHICH produced the verdict, per case, instead of trusting
    the environment (RevAI handoff 2026-09-27, item 7).
    """
    try:
        from winre.llm_client import resolved
        return resolved()
    except Exception as e:                      # never block a run on config
        return {"error": f"role resolution failed: {str(e)[:120]}"}


def run_langgraph_deep_dive(sample_name: str, sha: str, *,
                            max_steps: int = 14,
                            log_dir: Path | None = None,
                            dry: bool = False,
                            dynamic: bool = False,
                            available_tools: "Sequence[str] | None" = None,
                            mode: str = "remote",
                            quick: dict | None = None,
                            remote_sample: str | None = None) -> dict:
    """Run the LangGraph ReAct agent over the static toolset.

    available_tools: optional subset filter (commercial-optional tools are
    stripped by the caller when absent on the VM, e.g. Malcat).

    quick: optional quick-stage dict — a compact brief is injected into the
    opening message so the agent verifies rather than re-discovers.

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
    from winre import llm_client

    cfg = remote_driver.flare_cfg()
    registry = ToolRegistry(sample_name, sha, cfg, mode=mode,
                            remote_sample=remote_sample)

    # ---- the debugger is PART OF THE CONTRACT, not a planner's whim --------
    #
    # The defect this closes: --agentic-dbg exposed the bounded x64dbg tools to
    # the planner but never started the debugger. The only code that launches
    # the x64dbg MCP server lives INSIDE a tool call (_dbg_gate), so a planner
    # that did not pick a debug tool left the server down - and with it down
    # there was nothing to pick. The mode was circular: the real run recorded
    # 17 turns, one windbg call, zero x64dbg calls, and a pack whose dbg_ensure
    # was null while ports 9094/9095 were dead.
    #
    # In agentic-dbg mode the debugger does not get a veto. It is started
    # here, before the planner sees a single tool, on the VM snapshot, and the
    # outcome is journaled so a pack can tell "the debugger was never
    # available" (a product defect) from "the agent declined it".
    dbg_preflight: dict | None = None
    if dynamic and mode == "remote":
        try:
            gate = registry._dbg_gate()
            info = getattr(registry, "_dbg_ensure_info", None)
            if gate and gate.get("error"):
                dbg_preflight = {"ok": False, "error": gate["error"]}
            elif isinstance(info, dict):
                dbg_preflight = {"ok": True, **{
                    k: info.get(k) for k in
                    ("arch", "debugger", "exe", "already_up", "launched",
                     "replaced_wrong_arch", "port")
                    if info.get(k) is not None}}
            else:
                # autostart disabled: say so plainly up front rather than
                # letting the agent discover it one failed tool call at a time
                dbg_preflight = {
                    "ok": False,
                    "error": "x64dbg MCP was not started: "
                             "remote_driver.mcp_autostart_enabled() is "
                             "False. Set WINRE_MCP_AUTOSTART=1 for "
                             "agentic-dbg runs."}
        except Exception as e:
            dbg_preflight = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    history: list[dict] = []
    findings: dict[str, Any] = {}
    state = {"calls": 0, "redundant": 0, "seen": set(), "chars": 0}
    budget = max(10, int(max_steps) * 2)
    budget_chars = _ctx_budget_chars()
    managed = _is_managed_quick(quick)
    debug_terminal_recorded = False

    # The readiness gate is a required input to verdict calibration, so it
    # cannot depend on the planner choosing to call it. Run it once before
    # the agent sees the sample and record its structured outcome for audit.
    try:
        readiness_gate = registry.call("decrypt_gate", {})
    except Exception as e:
        readiness_gate = {"status": "failed", "reason_code": "tool_exception",
                          "error": f"decrypt_gate failed: {str(e)[:180]}"}
    history.append({"step": len(history) + 1, "tool": "decrypt_gate",
                    "args": {}, "result": readiness_gate,
                    "reason": "mandatory deterministic analysis-readiness preflight"})
    findings["decrypt_gate_preflight"] = readiness_gate
    state["calls"] += 1
    state["seen"].add(json.dumps(("decrypt_gate", {}), sort_keys=True,
                                 default=str))

    # PE parsing is also a required static capability. Run it before the
    # planner so a final verdict cannot conceal that the core format analysis
    # was skipped.
    try:
        pe_parse_preflight = registry.call("pe_parse", {})
    except Exception as e:
        pe_parse_preflight = {"status": "failed", "reason_code": "tool_exception",
                              "error": f"pe_parse failed: {str(e)[:180]}"}
    history.append({"step": len(history) + 1, "tool": "pe_parse",
                    "args": {}, "result": pe_parse_preflight,
                    "reason": "mandatory deterministic PE parse preflight"})
    findings["pe_parse_preflight"] = pe_parse_preflight
    state["calls"] += 1
    state["seen"].add(json.dumps(("pe_parse", {}), sort_keys=True,
                                 default=str))

    # Capa is part of the required static evidence contract. Do not leave this
    # deterministic operation to the planner: an otherwise successful agentic
    # run could omit it and fail the quality gate after producing a verdict.
    try:
        capa_preflight = registry.call("capa", {})
    except Exception as e:
        capa_preflight = {"status": "failed", "reason_code": "tool_exception",
                          "error": f"capa failed: {str(e)[:180]}"}
    history.append({"step": len(history) + 1, "tool": "capa",
                    "args": {}, "result": capa_preflight,
                    "reason": "mandatory deterministic capa evidence preflight"})
    findings["capa_preflight"] = capa_preflight
    state["calls"] += 1
    state["seen"].add(json.dumps(("capa", {}), sort_keys=True,
                                 default=str))

    def _debug_run_record() -> dict:
        calls = [h for h in history if h.get("tool") in {
            "x64dbg_oep", "x64dbg_wpm_dump", "x64dbg_crypt_dump",
            "x64dbg_unpack", "x64dbg_write_bp_trace",
            "x64dbg_run_window"}]
        if not dynamic:
            return {"requested": False, "attempted": False,
                    "status": "not_requested", "applicability": "not_requested",
                    "target": {"sha256": sha, "sample_name": sample_name},
                    "evidence": [], "limitations": []}
        if managed:
            return {"requested": True, "attempted": False,
                    "status": "not_applicable", "applicability": "managed_dotnet",
                    "target": {"sha256": sha, "sample_name": sample_name},
                    "evidence": [],
                    "limitations": ["native x64dbg debug loops do not apply to this managed sample"]}
        evidence = []
        successes = 0
        for h in calls:
            result = h.get("result") if isinstance(h.get("result"), dict) else {}
            if result.get("ok") is True:
                successes += 1
            # Keep the terminal summary reviewable and bounded; the full
            # result remains in the history entry it cites.
            detail = {k: result.get(k) for k in (
                "ok", "status", "oep", "entrypoint", "oep_target", "method", "hits", "hit",
                "dump_path", "dump_kind", "dump_source", "rebuild_hint",
                "error", "reason_code", "requested_seconds", "observed_seconds",
                "exit_observed", "natural_exit_observed", "completion_reason",
                "pause_count", "stopped_after_window",
                "final_state") if k in result}
            evidence.append({"tool": h.get("tool"), "step": h.get("step"),
                             "source_ref": f"deep.json#/agent/history/{h.get('step')}",
                             "result": detail})
        if not calls:
            status = "failed"
            reason = "debug was requested but no x64dbg operation was attempted"
        elif successes:
            status = "completed"
            reason = None
        else:
            status = "failed"
            reason = "all attempted x64dbg operations failed or were blocked"
        target_path = (getattr(registry, "_dbg_sample_path", None)
                       or remote_sample or sample_name)
        return {
            "requested": True, "attempted": bool(calls), "status": status,
            "applicability": "applicable",
            "target": {"sha256": sha, "sample_name": sample_name,
                       "staged_path": target_path,
                       "debugger": (dbg_ensure or {}).get("debugger"),
                       "arch": (dbg_ensure or {}).get("arch")},
            "startup": dbg_ensure, "evidence": evidence,
            "successful_operations": successes,
            "limitations": ([reason] if reason else []) + [
                "zero breakpoint hits can be a valid observation; they do not prove behavior is absent",
                "ETW records process starts and stops only; it does not cover file, registry, network, or memory activity",
            ],
        }

    def _capability_fields() -> dict:
        from .capabilities import census
        nonlocal debug_terminal_recorded
        debug_run = _debug_run_record()
        required = None
        if dynamic and not managed:
            required = ("pe_parse", "decrypt_gate", "capa", "ghidra_query",
                        "debug_run")
        if dynamic and not debug_terminal_recorded:
            # The synthetic terminal invocation makes a requested but skipped
            # debug capability visible to the same capability/audit contract.
            history.append({"step": len(history) + 1, "tool": "debug_run",
                            "args": {"requested": True},
                            "result": {"ok": debug_run["status"] == "completed",
                                       "status": debug_run["status"],
                                       "reason_code": "debug_" + debug_run["status"],
                                       "error": (debug_run.get("limitations") or [None])[0]},
                            "reason": "debug terminal record"})
            debug_terminal_recorded = True
        report = census(history,
                        required_tools=required or ("pe_parse", "decrypt_gate",
                                                    "capa", "ghidra_query"),
                        budget_exhausted=state["calls"] >= budget)
        return {"capability_census": report,
                "tool_failures": report["required_failures"],
                "debug_run": debug_run}

    def _budget_note() -> str:
        remaining = budget - state["calls"]
        if remaining <= 0:
            return "\n[BUDGET] tool budget exhausted — submit your final answer now."
        if remaining <= 3:
            return (f"\n[FINALIZE NOW] {remaining} tool call(s) left — stop "
                    f"investigating and submit your final verdict JSON.")
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
            # full-context policy: send as much of the raw tool result as the
            # model window allows (was a hard 2000-char cap)
            payload = json.dumps(result, default=str)
            remaining = max(0, budget_chars - int(state.get("chars") or 0))
            if not remaining:
                return ("[BUDGET] evidence context exhausted; the full tool result "
                        "is preserved in the run artifacts. Submit your final "
                        "answer from the evidence already supplied.")
            cap = min(240_000, remaining)
            sent = _truncate(payload, cap)
            state["chars"] = int(state.get("chars") or 0) + len(sent)
            return sent + _budget_note()

        _runner.__name__ = name
        _runner.__doc__ = f"Run tool `{name}` on the current sample."
        return StructuredTool.from_function(func=_runner, name=name,
                                            description=_runner.__doc__,
                                            args_schema=model)

    # These deterministic required operations already ran as preflight; do not
    # spend planner turns repeating them.
    names = [name for name in TOOL_NAMES
             if name not in {"decrypt_gate", "pe_parse", "capa"}]
    if available_tools is not None:
        names = [n for n in names if n in set(available_tools)]
    tools = [_make(n) for n in names]
    dyn_names = list(DYNAMIC_TOOL_NAMES)
    if managed:
        # native OEP/unpack primitives do not apply to managed assemblies
        dyn_names = [n for n in dyn_names
                     if n not in ("x64dbg_oep", "x64dbg_unpack",
                                  "x64dbg_crypt_dump")]
    dyn_note = ""
    if dynamic:
        tools += [_make(n) for n in dyn_names]
        dyn_note = """
Dynamic debugger tools (x64dbg in the VM snapshot — bounded primitives):
x64dbg_oep (find unpack OEP), x64dbg_wpm_dump (capture process-injected
buffers), x64dbg_crypt_dump (capture pre/post-decrypt buffers),
x64dbg_write_bp_trace (HW write-BP on the module header -> who wrote it:
memory-source of the unpacker write — use for multi-stage unpack where a
single OEP is misleading),
x64dbg_unpack (full OEP->dump->Malcat-compare in one call — prefer this for
packed samples over composing primitives yourself),
windbg_analyze_dump (PASSIVE WinDbg analysis of a captured memory dump:
!analyze -v triage + exception/module/stack highlights; use it when a
detonation already produced dynamic/memory/*.dmp — it never attaches to a
live target).
Debugger discipline: prefer x64dbg_unpack for packed binaries; keep hit
counts small (<=3); every dynamic claim needs a dump/evidence field; if a
dynamic tool errors, fall back to static — do not retry more than once.
The pipeline performs one deterministic OEP/unpack probe, resumes the target
for a bounded 30-second observation window, then stops it before the ETW
process observer closes. Do not start another sample session.
"""

    # packer-signal routing (W1): deterministic-first — when quick evidence
    # says packed, run the unpack primitive BEFORE the agent instead of
    # hoping the LLM picks it (0/14 calls on a packed sample happened).
    packed_sig = _packer_signal(quick)
    registry.packed_signal = packed_sig
    unpack_prepass: dict | None = None
    debug_prepass: dict | None = None
    if dynamic and packed_sig and not managed:
        try:
            r = registry.call("x64dbg_unpack", {})
        except Exception as e:
            r = {"error": str(e)[:200]}
        history.append({"step": len(history) + 1, "tool": "x64dbg_unpack",
                        "args": {}, "result": r,
                        "reason": "packer-signal deterministic route"})
        findings[f"x64dbg_unpack_{len(history)}"] = r
        state["calls"] += 1
        state["seen"].add(json.dumps(("x64dbg_unpack", {}), sort_keys=True))
        unpack_prepass = {k: r.get(k) for k in
                          ("ok", "oep", "entrypoint", "dump_path", "comparison", "note",
                           "error", "method", "attempts", "diagnostics",
                           "oep_target", "dump_kind", "dump_source",
                           "heap_region", "dump_parse", "rebuild_hint",
                           "imp_modes_tried", "artifact", "evidence", "fallback_trace",
                           "fallback_summary")
                          if k in r}
    elif dynamic and not managed:
        # `agentic-dbg` promises a debugger-assisted run. Merely starting the
        # x64dbg MCP server left the mode silently static whenever the planner
        # did not choose a debugger tool (observed live: x32dbg launched, zero
        # x64dbg calls, ETW never saw the target). For an unpacker signal the
        # full unpack prepass above is the one execution. Otherwise, make one
        # bounded OEP probe before the planner so the target is actually
        # loaded and run under the debugger and the concurrent ETW observer
        # can correlate its process lifetime.
        try:
            r = registry.call("x64dbg_oep", {})
        except Exception as e:
            r = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}
        debug_prepass = {k: r.get(k) for k in
                         ("ok", "status", "method", "oep", "entrypoint", "error")
                         if k in r}
        history.append({"step": len(history) + 1, "tool": "x64dbg_oep",
                        "args": {}, "result": r,
                        "reason": "agentic-dbg deterministic load/OEP probe"})
        findings[f"x64dbg_oep_{len(history)}"] = r
        state["calls"] += 1
        state["seen"].add(json.dumps(("x64dbg_oep", {}), sort_keys=True))

    if dynamic and not managed:
        # The OEP/unpack probe normally leaves the target paused at the entry
        # point or first unpacked instruction. Continue it for a fixed window
        # while the independent ETW observer is active, then stop it before
        # ETW collection closes. This makes agentic-dbg a real execution pass
        # even when a plain, non-packed image has no later unpack OEP.
        try:
            r = registry.call("x64dbg_run_window", {})
        except Exception as e:
            r = {"ok": False, "status": "failed",
                 "reason_code": "debug_window_exception",
                 "error": f"{type(e).__name__}: {str(e)[:200]}"}
        history.append({"step": len(history) + 1,
                        "tool": "x64dbg_run_window", "args": {},
                        "result": r,
                        "reason": "mandatory bounded debugger observation window"})
        findings[f"x64dbg_run_window_{len(history)}"] = r
        state["calls"] += 1
        state["seen"].add(json.dumps(("x64dbg_run_window", {}), sort_keys=True))
    # Which debugger actually served the unpack? x32dbg for a PE32 image,
    # x64dbg otherwise (P1-F1). Recorded so a pack is self-describing: if the
    # flavour were wrong the OEP failure would be otherwise indistinguishable
    # from a genuine "sample refused to unpack".
    dbg_ensure: dict | None = dbg_preflight or None
    try:
        _i = getattr(registry, "_dbg_ensure_info", None)
        if isinstance(_i, dict):
            dbg_ensure = {k: _i.get(k) for k in
                          ("arch", "debugger", "exe", "already_up",
                           "launched", "replaced_wrong_arch", "error")
                          if _i.get(k) is not None}
    except Exception:
        dbg_ensure = None

    packer_note = _packer_note(packed_sig, unpack_prepass, dynamic)
    debug_note = ""
    if debug_prepass is not None:
        debug_note = (
            "\nDEBUG PREFLIGHT: deterministic x64dbg load/entrypoint observation "
            "already ran before the planner: "
            f"{json.dumps(debug_prepass, default=str)[:2000]}. "
            "Use this result as evidence and do not repeat the same probe.")
    if managed:
        packer_note = ("\nPACKER SIGNAL (managed): packer/compression signals on a "
                       ".NET assembly do NOT route to native unpack - use "
                       "dotnet_analyze for IL/metadata and windbg for dumps.")

    # deterministic WinDbg routing (Bug-2 fix): the agent never reached for
    # windbg_analyze_dump on its own. Run it once when the debug tools are
    # available and record an explicit applicability reason — at deep time no
    # detonation dump exists yet, and the unpack artifact is a PE image
    # (cdb dump mode needs a minidump), so "not applicable" must be stated.
    windbg_dump: dict | None = None
    if dynamic:
        try:
            wb = registry.call("windbg_analyze_dump", {})
        except Exception as e:
            wb = {"error": f"{type(e).__name__}: {str(e)[:200]}"}
        windbg_dump = dict(wb or {})
        if not windbg_dump.get("ok") and not windbg_dump.get("error"):
            reason = str(windbg_dump.get("note") or windbg_dump.get("skipped")
                         or "no memory dump available")
            if unpack_prepass and unpack_prepass.get("ok") \
                    and "PE image" not in reason and "cdb" not in reason:
                reason += ("; the unpack artifact is a PE image — WinDbg dump "
                           "mode (cdb -z) does not apply to it")
            windbg_dump["note"] = reason
        windbg_dump.setdefault("reason", windbg_dump.get("note")
                               or windbg_dump.get("error") or "unknown")
        history.append({"step": len(history) + 1, "tool": "windbg_analyze_dump",
                        "args": {}, "result": windbg_dump,
                        "reason": "deterministic post-unpack routing"})
        findings[f"windbg_analyze_dump_{len(history)}"] = windbg_dump
        state["calls"] += 1
        state["seen"].add(json.dumps(("windbg_analyze_dump", {}),
                                     sort_keys=True))
    windbg_note = ""
    if windbg_dump is not None:
        if windbg_dump.get("ok"):
            windbg_note = ("\nWINDBG: deterministic dump analysis already ran "
                           "(see history) — do not repeat it.")
        else:
            windbg_note = ("\nWINDBG: dump analysis not applicable here: "
                           f"{str(windbg_dump.get('reason'))[:220]}. "
                           "Do not retry it.")

    if dry:
        # no LLM — deterministic fallback stub (the unpack prepass, if any,
        # still ran and is recorded in the history)
        return {"verdict": None, "source": "deterministic_fallback",
                "history": history, "llm_analysis": None, "dry": True,
                "packed_signal": packed_sig, "unpack_prepass": unpack_prepass,
                "windbg_dump": windbg_dump, "dbg_ensure": dbg_ensure,
                "llm_roles": _llm_roles(), **_capability_fields()}

    api_key = os.environ.get("WINRE_LLM_API_KEY", "")
    api_url = (os.environ.get("WINRE_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
               ).rstrip("/")
    if api_url.endswith("/chat/completions"):
        api_url = api_url[: -len("/chat/completions")]
    if not api_key and "127.0.0.1" not in api_url:
        return {"verdict": None, "source": "deterministic_fallback",
                "history": history,
                "llm_analysis": "WINRE_LLM_API_KEY not set for remote endpoint",
                "packed_signal": packed_sig, "unpack_prepass": unpack_prepass,
                "windbg_dump": windbg_dump, "dbg_ensure": dbg_ensure,
                "llm_roles": _llm_roles(), **_capability_fields()}

    try:
        _max_out = int(os.environ.get("WINRE_LLM_MAX_OUTPUT_TOKENS", "32768"))
    except ValueError:
        _max_out = 32768
    # Role separation (RevAI handoff item 7): the ReAct tool loop is the
    # call-heavy/token-heavy role, the final judge is the judgment role. Both
    # default to WINRE_LLM_MODEL; WINRE_LLM_PLANNER_MODEL /
    # WINRE_LLM_VERDICT_MODEL pin them independently. Resolved ONLY through
    # llm_client.roles() — no role variable is read here.
    llm_roles = _llm_roles()
    _mk = lambda role: ChatOpenAI(          # noqa: E731 - one-line factory
        model=llm_roles[role], api_key=api_key or "none",
        base_url=api_url, temperature=llm_client.request_temperature(default=0.0),
        **llm_client.chat_openai_options(_max_out, api_url))
    llm = _mk("planner")        # tool selection / investigation
    judge = _mk("judgment")     # verdict + finalize pass
    system_prompt = f"""You are an agentic malware reverse-engineering assistant on a Windows
FlareVM analysis pipeline. Sample: {sample_name} (SHA {sha[:16]}).

Known SQL schemas (do NOT waste turns discovering them — query directly):
Ghidra: funcs(name, addr, size) - the column is addr, there is NO
  'address' column (alias it yourself: SELECT addr AS address). imports
  (name,module/name,library), strings(content,addr); LIMIT small (25).
IDA: funcs(name, addr, size, prototype, arg_count, calling_conv) - the
  column is addr, there is NO 'address' column. imports(name,module),
  strings(content,addr), segments, names. Use LIMIT 20. IDs are strings in
  most rows.
Malcat (only if reachable): analyse_file / fns_top_list / fn_decompile.

Static evidence tools (no args — call and read the JSON):
capa: ATT&CK-mapped capabilities (e.g. "encode data using XOR") — cite the
  capability name + attack technique. STRONG signal for verdicts.
pe_import_signals: import→ATT&CK high-signal map (pefile). NOT capa.
api_hash_resolver: detects runtime API-hash import resolvers (4-byte
  constants == hashes of API names, murmur/djb2/sdbm/fnv). signal=true =>
  anti-import-table; matched names reveal the resolved API surface.
floss: deobfuscated/stack strings — decoded strings often reveal config,
  URLs, mutexes the raw strings hide.
pe_parse: imports (per-DLL function lists), sections + entropy, digital
  signature (signed true/false) — packing = few imports + high entropy.
diec: packer/protector/compiler identification.
strings_tool: raw ASCII strings (may be garbage if packed).
yarascan: ruleset scan. `high_signal` = curated family-distinctive hits
  (the verdict floor applies). `auto_generated` = CADRE_v2_* auto rules:
  LEADS only - they routinely match legit tools, never decisive alone.
  `generic` = common API/DLL/DOS literals: noise, never lean on them.
  `packer_signal` = packer-family hits (expected on packed legit binaries).
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
crypto_constants: crypto magic constants + AES S-box in exec sections ->
  crypto_identified tags (RC4/XTEA/SHA256/... leads for config extraction).
decrypt_gate: analysis-readiness gate — import-stripped + sparse strings +
  packer taxonomy. status='gate' means capa/string evidence is UNRELIABLE:
  do NOT lean a malicious verdict on capa clusters when gated.
The pipeline runs decrypt_gate deterministically before the planner and
supplies its result in the opening evidence brief. Treat that result as
authoritative; do not assume the gate passed if its output is missing or failed.
string_decode_emulate: encoded-config recovery (xor/add/sub/rol 1-2-byte +
  date-seeded keys) over high-entropy blobs -> plaintext config candidates.
rolling_xor: known-plaintext-guided rolling/date-seeded XOR keys (nested PE,
  compile-date seeds) — beats fixed-key bruteforce on loader-class samples.
mitigations: PE hardening catalog (ASLR/DEP/SEH/CFG). Weak signal only.
sink_sites: dangerous-API call sites with caller-function provenance (r2).
script_decode: script-stage deobfuscation (base64/deflate/fromcharcode) +
  embedded PE/shellcode flags for PS/JS/VBS/HTA delivery.
ioc_extract: wallets + defanged URLs + domains/IPs/emails from strings.
goresym_analyze: Go symbol recovery (honest skip when not Go).
rtf_predecode: RTF container decode; embedded OLE2 -> then olevba.
z3_solve / angr_analyze: deobfuscation solvers — only for confirmed
  obfuscation (MBA/CFF), never first-line.

VERDICT METHOD (ACH): frame the verdict as competing hypotheses
(malicious | benign (tool/legit) | unknown). Weight the DIAGNOSTICITY of each piece
of evidence, not its volume. Explicitly try to DISPROVE your leading
hypothesis (e.g., is the C2 string actually a kill-switch? is the
high-entropy section a legitimate packer?). Protection/obfuscation alone
never proves malicious. Report which evidence you tried to disprove and
why it held.

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
IDENTITY & MASQUERADE: VersionInfo/company metadata is trivially forged,
but so is every unsigned build - "unsigned + has VersionInfo" is NOT a
masquerade. A masquerade verdict needs identity mismatch PLUS decisive
behavioral evidence (C2/config, persistence, injection, crypto+exfil).
Malcat anomalies, packer hits, auto-generated CADRE_v2_* YARA leads and
high-signal imports alone never justify malicious.

KNOWN TOOLS: consult threat_intel early (signer + security-tool markers).
known_tool=true means dual-use behavior (debug/injection APIs, packing,
high entropy, credential-adjacent imports) is EXPECTED for that tool:
verdict must be benign (tool/legit) or unknown unless a curated family-exact YARA
hit or concrete malicious artifacts (C2 config, persistence, exfil) exist.
Kesakode/tool-tags in Malcat metadata corroborate known-tool identity.
BUDGET DISCIPLINE: limited tool calls; when a [BUDGET] note appears, converge
to your final answer immediately.
{dyn_note}{packer_note}{debug_note}{windbg_note}"""
    agent = create_react_agent(llm, tools=tools, prompt=system_prompt)
    recursion_limit = max(24, int(max_steps) * 2 + 10)
    try:
        brief = _quick_brief(quick)
        result = agent.invoke(
            {"messages": [HumanMessage(content=(
                f"Analyze sample {sha}. Mandatory decrypt_gate preflight result: "
                f"{json.dumps(readiness_gate, default=str)[:12000]}\n"
                f"Mandatory pe_parse preflight result: "
                f"{json.dumps(pe_parse_preflight, default=str)[:12000]}\n"
                f"Mandatory capa preflight result: "
                f"{json.dumps(capa_preflight, default=str)[:12000]}\n"
                f"{brief}{packer_note}{debug_note}{windbg_note}Use SQL + Malcat to "
                "deepen, then produce the final flat JSON verdict."))]},
            config={"recursion_limit": recursion_limit},
        )
    except Exception as e:
        return {"verdict": None, "source": "deterministic_fallback",
                "history": history, "llm_analysis": f"agent error: {e}",
                "packed_signal": packed_sig, "unpack_prepass": unpack_prepass,
                "windbg_dump": windbg_dump, "dbg_ensure": dbg_ensure,
                "llm_roles": _llm_roles(), **_capability_fields()}

    # parse final flat JSON from AI messages (newest first). Models wrap
    # verdicts in prose/fences, so try every {...} candidate, not just the
    # first-to-last span.
    import re as _re
    verdict = None
    llm_text = ""
    tool_dump = ""
    for msg in reversed(result.get("messages") or []):
        content = getattr(msg, "content", None)
        if isinstance(content, list):
            # tool-call content blocks — join text parts
            content = " ".join(
                str(p.get("text", "")) for p in content
                if isinstance(p, dict) and p.get("type") == "text")
        if not isinstance(content, str) or not content.strip():
            continue
        mtype = getattr(msg, "type", "")
        if not tool_dump and mtype == "tool":
            tool_dump = content.strip()[:120_000]
        if not llm_text and mtype not in ("human", "tool"):
            llm_text = content.strip()[:200_000]
        # A verdict may only come from the ASSISTANT's own message. Tool output
        # is evidence, not judgement: a tool payload carrying a nested
        # {"verdict": ...} object used to be parsed and promoted to this run's
        # verdict (code audit 2026-09-28, MEDIUM).
        if mtype == "tool":
            continue
        # strip code fences, then try each balanced {...} span
        text = _re.sub(r"```(?:json)?", "", content)
        for m in _re.finditer(r"\{[^{}]*\"verdict\"[^{}]*\}", text,
                              _re.IGNORECASE | _re.DOTALL):
            try:
                data = json.loads(m.group(0))
            except Exception:
                continue
            if isinstance(data, dict):
                v = data.get("verdict") or data.get("Verdict")
                if isinstance(v, str) and v.strip():
                    verdict = _normalize_verdict(data)
                    llm_text = content.strip()[:200_000]
                    break
        if verdict is not None:
            break
        # fallback: first-to-last span (original behavior)
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                data = json.loads(text[start:end + 1])
                if isinstance(data, dict) and data.get("verdict"):
                    verdict = _normalize_verdict(data)
                    llm_text = content.strip()[:200_000]
                    break
        except Exception:
            continue
    # Finalize pass: agents sometimes end with prose analysis instead of the
    # required JSON. One extra LLM call converts their own analysis into the
    # verdict object instead of falling back deterministically.
    fallback_reason = "no verdict JSON in agent output"
    basis = llm_text or tool_dump
    finalized_by_judge = False
    if verdict is None and basis:
        for _attempt in (1, 2, 3):
            try:
                _extra = ("" if _attempt == 1 else
                          "\n\nSTRICT: reply with ONLY the flat JSON object, "
                          "starting with { and ending with }.")
                fid = judge.invoke([HumanMessage(content=(
                    "Convert the following analysis into the required flat JSON "
                    "verdict object ONLY (keys: verdict (malicious/unknown/benign), "
                    "confidence (high/medium/low), summary, key_evidence (list of "
                    "strings)). No prose, no code fences." + _extra + "\n\n"
                    + basis[:300_000]))])
                ftext = str(getattr(fid, "content", "") or "")
                ftext = _re.sub(r"```(?:json)?", "", ftext)
                fm = _re.search(r"\{.*\}", ftext, _re.DOTALL)
                if fm:
                    fdata = json.loads(fm.group(0))
                    if isinstance(fdata, dict) and fdata.get("verdict"):
                        normalized = _normalize_verdict(fdata)
                        if normalized.get("verdict"):
                            verdict = normalized
                            finalized_by_judge = True
                            llm_text = (llm_text + "\n\n[finalize] " + ftext)[:250_000]
                            fallback_reason = ""
                            break
                fallback_reason = (f"finalize unparseable (attempt {_attempt}): "
                                   + repr(ftext[:120]))
                _time.sleep(1.5)
            except Exception as e:
                fallback_reason = (f"finalize failed (attempt {_attempt}): "
                                   f"{str(e)[:180]}")
                _time.sleep(1.5)
    # The verdict must come from the JUDGMENT role. When a distinct
    # WINRE_LLM_VERDICT_MODEL is pinned, the object parsed out of the planner's
    # final message is only a DRAFT: hand it to the judge, which produces the
    # authoritative verdict. Without this, deep.json / report.json / audit.json
    # all claimed the pinned judgment model produced a verdict it never saw
    # (code audit 2026-09-28, HIGH).
    verdict_judged_by = "judgment" if finalized_by_judge else "planner"
    judgment_pass_error = None
    planner_draft = None
    if (verdict is not None and llm_roles.get("judgment")
            and llm_roles.get("judgment") != llm_roles.get("planner")):
        planner_draft = dict(verdict)
        try:
            _jv = judge.invoke([HumanMessage(content=(
                "Convert this DRAFT verdict into the authoritative flat JSON "
                "verdict object ONLY (keys: verdict (malicious/unknown/benign), "
                "confidence (high/medium/low), summary, key_evidence (list of "
                "strings)). Correct any label or citation the evidence does not "
                "support. No prose, no code fences.\n\n"
                f"Draft: {json.dumps(verdict)[:4000]}\n\n"
                f"Evidence: {basis[:120000]}"))])
            _jtxt = _re.sub(r"```(?:json)?", "", str(getattr(_jv, "content", "") or ""))
            _jm = _re.search(r"\{.*\}", _jtxt, _re.DOTALL)
            if _jm:
                _jd = json.loads(_jm.group(0))
                if isinstance(_jd, dict) and _jd.get("verdict"):
                    normalized = _normalize_verdict(_jd)
                    if normalized.get("verdict"):
                        verdict = normalized
                        verdict_judged_by = "judgment"
                    else:
                        judgment_pass_error = "judgment response contained an invalid verdict label"
                else:
                    judgment_pass_error = "judgment response omitted a verdict"
            else:
                judgment_pass_error = "judgment response was not valid JSON"
        except Exception as e:
            judgment_pass_error = f"{type(e).__name__}: {str(e)[:150]}"
    if judgment_pass_error:
        # A planner draft is not a completed judgment when a distinct judge
        # was configured. Preserve the draft for diagnosis, but fail the stage
        # closed rather than publishing it under the judgment-role contract.
        llm_roles["judgment_pass_error"] = judgment_pass_error
        return {"verdict": None, "source": "deterministic_fallback",
                "history": history, "llm_analysis": llm_text[:200_000],
                "fallback_reason": "distinct judgment pass failed: " + judgment_pass_error,
                "planner_draft": planner_draft,
                "judgment_pass_error": judgment_pass_error,
                "packed_signal": packed_sig, "unpack_prepass": unpack_prepass,
                "windbg_dump": windbg_dump, "dbg_ensure": dbg_ensure,
                "llm_roles": llm_roles, **_capability_fields()}

    # curated-YARA verdict floor (W2): never let a below-malicious verdict
    # contradict a family-distinctive rule match
    verdict = _apply_verdict_floor(verdict, _curated_yara_hits(quick, findings))
    if verdict is None:
        return {"verdict": None, "source": "deterministic_fallback",
                "history": history, "llm_analysis": llm_text[:200_000],
                "fallback_reason": fallback_reason,
                "packed_signal": packed_sig, "unpack_prepass": unpack_prepass,
                "windbg_dump": windbg_dump, "dbg_ensure": dbg_ensure,
                "llm_roles": llm_roles, **_capability_fields()}
    return {"verdict": verdict, "source": "llm_judge",
            "verdict_judged_by": verdict_judged_by,
            "history": history, "llm_analysis": llm_text[:200_000],
            "packed_signal": packed_sig, "unpack_prepass": unpack_prepass,
            "windbg_dump": windbg_dump, "dbg_ensure": dbg_ensure,
            "judgment_pass_error": None,
            "llm_roles": llm_roles, **_capability_fields()}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="WinRE LangGraph deep dive (static phase)")
    ap.add_argument("sha")
    ap.add_argument("--sample-name", required=True)
    ap.add_argument("--max-steps", type=int, default=14)
    ap.add_argument("--dry", action="store_true",
                    help="no LLM - deterministic fallback only")
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
