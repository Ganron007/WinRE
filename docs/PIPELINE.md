# Pipeline — WinRE static + dynamic RE workflow

> **Status:** LIVE (2026-09-07) — `winre/pipeline.py` with SEGREGATED static/dynamic phases,
> `--mode static|agentic` deep-dive engines, and RevAI-style mode sections
> (`logs/<sha>/<static|agentic>/`).
> WinRE is the Windows FlareVM pipeline: static AND dynamic AND interactive
> debugger on one host, all local, LLM interprets evidence only.

## Static-first, dynamic opt-in + segregated (design)

**Static is the default and mirrors RevEng/RevAI exactly.** Dynamic is a
SEPARATE, opt-in phase that runs LAST from a restored (clean) VM — never in
the middle of static (detonation would contaminate the VM the deep static
agent runs on). `static_yara_wins`: dynamic corroborates, never clears.

```
DEFAULT (no env):   pipeline.py <sample> [--mode agentic|static]  → STATIC ONLY
                    intake → quick → deep → yara → report → audit
                    (deep engine: agentic = LangGraph ReAct, llm_judge;
                     static = deterministic checklist, zero LLM calls)
                    Never detonates. Clean on any host.
                    Pack lands in logs/<sha>/<agentic|static>/
                    (mode sections — RevAI scripted/agentic style; same-mode
                    reruns overwrite their section, cross-mode coexists).

OPT-IN DYNAMIC:     WINRE_ENABLE_DYNAMIC=1 pipeline.py <sample> --dynamic
                    (or RevEng triggers the legacy SSH orchestrator)
                    static completes FIRST → detonation on restored VM →
                    FakeNet+Procmon+Frida+pe-sieve → dynamic pack pulled into
                    the run's mode section → static_yara_wins →
                    snapshot revert (mandatory)
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
python -m winre.pipeline <sample> [--mode agentic|static] [--dynamic] [--max-seconds 45]
                   [--pesieve] [--dry-llm] [--agentic-dbg] [--driver remote] [--publish]
   │
   ├─ 1. intake   hash, format, magic            → logs/<sha>/<mode>/intake/
   ├─ 2. quick    deterministic triage           → logs/<sha>/<mode>/quick/
   │             Malcat MCP views + IDA/Ghidra SQL + static-tools layer
   │             (capa/floss/lief/diec/yarascan/strings/import-signals/xor)
   ├─ 3. deep     engine selected by --mode      → logs/<sha>/<mode>/deep/
   │             agentic: LangGraph ReAct over the 35-tool set (llm_judge)
   │             static:  fixed 35-tool checklist (30 steps) + rules verdict,
   │                      zero LLM (static_deterministic — RevAI scripted)
   ├─ 4. yara     YARA + Sigma from evidence      → logs/<sha>/<mode>/yara/    (deterministic, no LLM in rules)
   ├─ 5. report   source-tagged report + next     → logs/<sha>/<mode>/report/
   │             source ∈ {llm_judge, static_deterministic, deterministic_fallback}
   └─ audit       truly_green gate (dynamic optional) → logs/<sha>/<mode>/audit.json
          │
          └─ [--dynamic] detonation runs here, LAST, segregated:
             orchestrator --mode local → logs/<sha>/<mode>/dynamic/ (pulled via scp)
             (WINRE_DYNAMIC_DIR pins the orchestrator output into the section)

   [--publish] sanitized case → docs/case-studies/<mode>/<sha>/ (no binaries)
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
| intake | file magic, sha256 | `intake.json` (+ filename-policy note) |
| quick | Malcat MCP (:9009) anomalies/yara/strings, IDA SQL funcs (if .i64), Ghidra SQL funcs, static-tools layer (capa/floss/lief/diec/yarascan/strings/import-signals/xor/api-hash-resolver/crypto/mitigations/iocs) | `quick.json` + `verdict` |
| dynamic | FakeNet-NG, Procmon→CSV, Frida trace, pe-sieve (opt) + suspended-process dump monitor, hollows_hunter, input jiggle, x64dbg OEP/dump; post-analysis: procmon persistence catalog + behavior timeline + spoof suspects, pcap beacon/HTTP-schema, post-mortem (procdump -ma harvest, ntdll integrity, process snapshot) | `META.json` (ok, frida_events, sample_pid), `STAGE.json` (audit wrapper + gate evidence), `frida_trace.jsonl`, `procmon.csv`, `procmon_summary.json` (+persistence/timeline/spoof), `behavior_timeline.csv`, `network_intel.json` (+beacon_analysis), `post_mortem.json`, `memory/*.dmp`, `process_snapshot.json` |
| deep | engine by `--mode`: `agentic` = LangGraph ReAct (x64dbg-MCP LoadBinary/DetectOEP/DumpModule + write-BP trace, Malcat-MCP fns/decompile, WinDbg-MCP dump analysis, 35 static tools); `static` = fixed 35-tool checklist (30 steps), no LLM | `deep.json` + verdict (`llm_judge` / `static_deterministic`), full history, `llm_analysis` (null in static mode), step-level `tool_failures` surfaced into audit |
| yara | deterministic YARA (`CADRE_<sha8>.yar`) + Sigma (`CADRE_<sha8>.yml`), curation lint (soundness/dupes/noise warnings in rule_report) | `rule_report.json` |
| report | source-tagged `report.json` + `ANALYST-NEXT.md`; sections incl. behavior-context (kill-switch/CLI/artifact catalog) + crypto-identified tags | — |

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
# Run all commands below as modules from C:\WinRE (WinRE is a package;
# direct script paths like python winre\pipeline.py fail).

# STATIC — deterministic engine, zero LLM calls (RevAI scripted)
python -m winre.pipeline C:\samples\foo.exe --mode static

# STATIC — agentic engine (default; needs the LLM endpoint for llm_judge)
python -m winre.pipeline C:\samples\foo.exe --mode agentic
# ... --dry-llm forces the honest deterministic_fallback (no LLM)

# STATIC + SEGREGATED DYNAMIC (opt-in; needs restored VM, then snapshot revert)
python -m winre.pipeline C:\samples\foo.exe --mode static --dynamic --max-seconds 45
# or env: $env:WINRE_ENABLE_DYNAMIC = "1"

# control-plane driver (run from operator host, SSH to FlareVM)
python -m winre.pipeline C:\samples\foo.exe --driver remote --mode static

# publish a sanitized, mode-keyed case (report-level artifacts only, no binaries)
python -m winre.pipeline C:\samples\foo.exe --mode static --publish
#    → docs/case-studies/static/<sha>/

# env
$env:GHIDRA_HEADLESS_MAXMEM = "8G"     # 16GB host
$env:WINRE_PIPELINE_LOGS = "C:\WinRE\logs"
$env:WINRE_LLM_BASE_URL / WINRE_LLM_API_KEY / WINRE_LLM_MODEL  (in .env)
```

Exit code 0 only when `truly_green` (audit gate passed). Dynamic is not
required for green — it is optional corroboration.

## Evidence contract with RevAI

`logs/<sha>/<mode>/dynamic/` keeps the exact schema RevAI reads
(`load_dynamic_pack()`) — WinRE is now also the writer for the full pack;
RevAI can read any stage. The pipeline layout mirrors RevAI's
`{intake,quick,deep,publish}` naming so reports are portable.
