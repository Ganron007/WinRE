# Pipeline — WinRE static + dynamic RE workflow

> **Status:** LIVE (2026-09-02) — `winre/pipeline.py` with SEGREGATED static/dynamic phases.
> WinRE is the Windows FlareVM pipeline: static AND dynamic AND interactive
> debugger on one host, all local, LLM interprets evidence only.

## Static-first, dynamic opt-in + segregated (design)

**Static is the default and mirrors RevEng/RevAI exactly.** Dynamic is a
SEPARATE, opt-in phase that runs LAST from a restored (clean) VM — never in
the middle of static (detonation would contaminate the VM the deep static
agent runs on). `static_yara_wins`: dynamic corroborates, never clears.

```
DEFAULT (no env):   pipeline.py <sample>                  → STATIC ONLY
                    intake → quick → deep(agent) → yara → report → audit
                    Never detonates. Clean on any host.

OPT-IN DYNAMIC:     WINRE_ENABLE_DYNAMIC=1 pipeline.py <sample> --dynamic
                    (or RevEng triggers the legacy SSH orchestrator)
                    static completes FIRST → detonation on restored VM →
                    FakeNet+Procmon+Frida+pe-sieve → dynamic pack pulled →
                    static_yara_wins → snapshot revert (mandatory)
```

Why: a detonation dirties the VM (Run keys, dropped files, hooks). Running
the deep static agent after detonation would analyze on contaminated ground.
RevEng/RevAI (Linux static) can drive WinRE SQL over SSH; WinRE owns dynamic.

## Why WinRE beats static-only pipelines

RevEng/RevAI run static tools on Linux and hand the evidence to an LLM. They
cannot: detonate on Windows, hook APIs with Frida, capture Procmon/network,
drive x64dbg/WinDbg/Malcat over MCP, or unpack interactively. WinRE does all
of it on one host — static SQL, dynamic detonation (gated), and agentic
debugger control — then applies the same honest gates.

## Spine

```
winre/pipeline.py <sample> [--dynamic] [--max-seconds 45] [--pesieve] [--dry-llm] [--driver remote]
   │
   ├─ 1. intake   hash, format, magic            → logs/<sha>/intake/
   ├─ 2. quick    Malcat MCP + IDA/Ghidra SQL    → logs/<sha>/quick/   (deterministic triage + verdict)
   ├─ 3. deep     LangGraph agent (static tools) → logs/<sha>/deep/    (ghidra/ida SQL + malcat MCP)
   │             LLM interprets evidence (local endpoint, source-tagged)
   ├─ 4. yara     YARA + Sigma from evidence      → logs/<sha>/yara/    (deterministic, no LLM in rules)
   ├─ 5. report   source-tagged report + next     → logs/<sha>/report/
   └─ audit       truly_green gate (dynamic optional) → logs/<sha>/audit.json
          │
          └─ [--dynamic] detonation runs here, LAST, segregated:
             orchestrator --mode local → logs/<sha>/dynamic/ (pulled via scp)
```

- **Deterministic-first**: tools produce evidence; the LLM only interprets.
- **`static_yara_wins`**: dynamic evidence corroborates but never clears a
  static malicious verdict (policy in `audit.json`).
- **Honest gate**: `truly_green = all required stages ran + zero failed tools
  + no fallback + no dynamic-vs-static conflict`. Dynamic is NOT required for
  green (optional corroboration) unless it ran and conflicted.

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
# STATIC (default — never detonates) — fastest smoke
python C:\WinRE\winre\pipeline.py C:\samples\foo.exe --dry-llm

# STATIC + SEGREGATED DYNAMIC (opt-in; needs restored VM, then snapshot revert)
python C:\WinRE\winre\pipeline.py C:\samples\foo.exe --dynamic --max-seconds 45
# or env: $env:WINRE_ENABLE_DYNAMIC = "1"

# control-plane driver (run from operator host, SSH to FlareVM)
python winre\pipeline.py C:\samples\foo.exe --driver remote

# env
$env:GHIDRA_HEADLESS_MAXMEM = "8G"     # 16GB host
$env:WINRE_PIPELINE_LOGS = "C:\WinRE\logs"
$env:WINRE_LLM_BASE_URL / WINRE_LLM_API_KEY / WINRE_LLM_MODEL  (in .env)
```

Exit code 0 only when `truly_green` (audit gate passed). Dynamic is not
required for green — it is optional corroboration.

## Evidence contract with RevAI

`logs/<sha>/dynamic/` keeps the exact schema RevAI reads
(`load_dynamic_pack()`) — WinRE is now also the writer for the full pack;
RevAI can read any stage. The pipeline layout mirrors RevAI's
`{intake,quick,deep,publish}` naming so reports are portable.
