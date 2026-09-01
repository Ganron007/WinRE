# Pipeline — WinRE static + dynamic RE workflow

> **Status:** LIVE (2026-09-01) — `winre/pipeline.py` spine verified end-to-end on FlareVM.
> WinRE is the Windows FlareVM pipeline: static AND dynamic AND interactive
> debugger on one host, all local, LLM interprets evidence only.

## Why WinRE beats static-only pipelines

RevEng/RevAI run static tools on Linux and hand the evidence to an LLM. They
cannot: detonate on Windows, hook APIs with Frida, capture Procmon/network,
drive x64dbg/WinDbg/Malcat over MCP, or unpack interactively. WinRE does all
of it on one host — static SQL, dynamic detonation, and agentic debugger
control — then applies the same honest gates.

## Spine

```
winre/pipeline.py <sample> [--max-seconds 45] [--pesieve] [--skip-dynamic] [--dry-llm]
   │
   ├─ 1. intake   hash, format, magic            → logs/<sha>/intake/
   ├─ 2. quick    Malcat MCP + IDA/Ghidra SQL    → logs/<sha>/quick/   (deterministic triage + verdict)
   ├─ 3. dynamic  orchestrator --mode local       → logs/<sha>/dynamic/ (FakeNet+Procmon+Frida+pe-sieve)
   │             (x64dbg OEP/dump best-effort)
   ├─ 4. deep     MCP-driven agent pass           → logs/<sha>/deep/    (x64dbg 71 + Malcat 45 + WinDbg 10)
   │             LLM interprets evidence (local endpoint, source-tagged)
   ├─ 5. yara     YARA + Sigma from evidence      → logs/<sha>/yara/    (deterministic, no LLM in rules)
   ├─ 6. report   source-tagged report + next     → logs/<sha>/report/
   └─ audit       truly_green gate                → logs/<sha>/audit.json
```

- **Deterministic-first**: tools produce evidence; the LLM only interprets
  (verdicts, report prose). Deep-dive LLM output is `source: llm_judge`; a
  missing LLM falls back to `deterministic_fallback` and the audit records it.
- **`static_yara_wins`**: dynamic evidence corroborates but never clears a
  static malicious verdict (policy in `audit.json`).
- **Honest gate**: `truly_green = all stages ran + zero failed tools + no
  fallback when primary tool required + no dynamic-vs-static conflict`.

## Stage detail

| Stage | Tools | Key artifacts |
|-------|-------|---------------|
| intake | file magic, sha256 | `intake.json` |
| quick | Malcat MCP (:9009) anomalies/yara/strings, IDA SQL funcs (if .i64), Ghidra SQL funcs | `quick.json` + `verdict` |
| dynamic | FakeNet-NG, Procmon→CSV, Frida trace, pe-sieve (opt), x64dbg OEP/dump | `META.json` (ok, frida_events), `frida_trace.jsonl`, `procmon.csv`, `network_intel.json` |
| deep | x64dbg-MCP (:9094) LoadBinary/DetectOEP/DumpModule, Malcat-MCP (:9009) fns/decompile, WinDbg-MCP (:9097) dump analysis | `deep.json` + `llm_analysis` (source-tagged) |
| yara | deterministic YARA (`CADRE_<sha8>.yar`) + Sigma (`CADRE_<sha8>.yml`) | `rule_report.json` |
| report | source-tagged `report.json` + `ANALYST-NEXT.md` | — |

## Local-only

No SSH, no remote agent, no external LLM host. The LLM endpoint is whatever
runs on/near the FlareVM (OpenAI-compatible):

```powershell
$env:WINRE_LLM_BASE_URL = "http://127.0.0.1:8000/v1"   # local model or API
$env:WINRE_LLM_API_KEY  = ""
$env:WINRE_LLM_MODEL    = "local"
```

MCP servers run on the VM console (`winre/mcp/start_servers.ps1`) — Malcat
:9009, WinDbg :9097, x64dbg :9094 when open.

## Run

```powershell
# static-only (no detonation, no LLM) — fastest smoke
python C:\WinRE\winre\pipeline.py C:\samples\foo.exe --skip-dynamic --dry-llm

# full
python C:\WinRE\winre\pipeline.py C:\samples\foo.exe --max-seconds 45 --pesieve

# env
$env:GHIDRA_HEADLESS_MAXMEM = "8G"     # 16GB host
$env:WINRE_PIPELINE_LOGS = "C:\WinRE\logs"
```

Exit code 0 only when `truly_green` (audit gate passed).

## Evidence contract with RevAI

`logs/<sha>/dynamic/` keeps the exact schema RevAI reads
(`load_dynamic_pack()`) — WinRE is now also the writer for the full pack;
RevAI can read any stage. The pipeline layout mirrors RevAI's
`{intake,quick,deep,publish}` naming so reports are portable.
