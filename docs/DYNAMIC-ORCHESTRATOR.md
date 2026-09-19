# Dynamic Orchestrator — FlareVM

> **Status:** implemented (local-first) — `winre/orchestrator.py` drives `winre/flare_dynamic_job.ps1`, which stages Frida + Procmon + FakeNet-NG + pe-sieve.
> **Audience:** operators (detonation) and integrators.

## 1. Flow

```
host: scp sample → C:\samples\foo.exe + C:\WinRE\orchestrator.py --sample C:\samples\foo.exe --max-seconds 45 [--pesieve]
  → orchestrator.py (Flare local)
     ├─ detect fmt: PE vs ELF vs doc (via lief/magic)
     ├─ if REVENG_DYNAMIC_SKIP=1 → write META.json {skipped:true} + exit 0
     ├─ start FakeNet-NG → C:\WinRE\logs\<sha>\network_raw\fakenet.log
     ├─ start Procmon → procmon.exe /BackingFile C:\WinRE\logs\<sha>\procmon.pcap
     ├─ spawn frida_api_trace.py --target C:\samples\foo.exe --apis <hooklist> → frida_trace.jsonl
     ├─ wait --max-seconds (default 45; with --adaptive this is the CAP and
     │   the Frida trace stops early after --idle-stop-seconds without new
     │   events — effective window recorded in META.window), optional
     │   PE-sieve mid-run if --pesieve
     ├─ stop Procmon → procmon.csv, tshark enrich → procmon_summary.json + network_intel.json
     ├─ post-analysis (KB 2026-09-07): procmon_post (persistence catalog +
     │   behavior_timeline.csv + spoof suspects), pcap_beacon (cadence/UA/
     │   HTTP schema), post_mortem (procdump -ma harvest + ntdll integrity +
     │   process snapshot), windbg_post (mcp-windbg !analyze -v/.ecxr/k/lm
     │   over in-run dumps) → procmon_summary.json extended, network_intel.json
     │   +beacon_analysis, post_mortem.json, windbg_analysis.json
     ├─ suspended-process monitor: pe-sieve dump of every new sample process
     │   instance (Early-Bird/APC capture incl. CREATE_SUSPENDED children)
     ├─ input jiggle: synthetic mouse movement during the run (interaction gates)
     ├─ optional x64dbg-MCP DumpModule → x64dbg/dump/
     ├─ Mallcat triage → malcat-triage.json (if Malcat installed)
     └─ emit ANALYST-NEXT.md (emit_analyst_next.py) + META.json
  → SMB copy → \\<remnux-host>\opt\samples\corpus\<sha>\logs\<sha>\dynamic\
```

ELF on Flare is rare — `elf_dynamic_job.sh` handles `readelf/objdump` + local strace; Windows path is default.

## 2. CLI

```powershell
python C:\WinRE\winre\orchestrator.py C:\samples\foo.exe --max-seconds 45
python C:\WinRE\winre\orchestrator.py C:\samples\foo.exe --max-seconds 60 --pesieve
# adaptive window: 150s cap, stop 10s after the last Frida event
python C:\WinRE\winre\orchestrator.py C:\samples\foo.exe --max-seconds 150 --adaptive --idle-stop-seconds 10
python C:\WinRE\winre\orchestrator.py C:\samples\foo.exe --skip  # writes META skipped

# local mode (run on Flare, no SSH hop — preferred, Phase 7)
python C:\WinRE\winre\orchestrator.py C:\samples\foo.exe --max-seconds 45 --mode local
# or via env:
$env:WINRE_ORCHESTRATOR_MODE = "local"
python C:\WinRE\winre\orchestrator.py C:\samples\foo.exe --max-seconds 45

# direct job (inside VM only):
powershell -ExecutionPolicy Bypass -File C:\WinRE\winre\flare_dynamic_job.ps1 -Sample C:\samples\foo.exe -OutDir C:\WinRE\logs\<sha>\dynamic -MaxSeconds 45
```

Env flags (same as `dynamic_run_v2.py:317`):

| Flag | Effect |
|------|--------|
| `REVENG_DYNAMIC_SKIP=1` | write META skipped, exit 0 |
| `REVENG_DYNAMIC_PESIEVE=1` | run pe-sieve mid-detonation |
| `WINRE_ORCHESTRATOR_MODE={ssh,local}` | default orchestrator mode (Phase 7) |
| `REVENG_DYNAMIC_X64DBG=0` | skip x64dbg MCP OEP/dump pass |

## 3. Artifacts

See the dynamic artifact contract in [`EVIDENCE.md`](EVIDENCE.md). Key:

| File | Source |
|------|--------|
| `frida_trace.jsonl` | `tools/frida_api_trace.py` hook set (CreateFileW, VirtualAlloc, etc. `dynamic/README.md:20`) |
| `procmon.csv` | `C:\tools\sysinternals\Procmon64.exe /Quiet /Minimized /BackingFile` |
| `procmon_summary.json` | `winre/summarize_dynamic.py` (filters to process `foo.exe`) + `winre/procmon_post.py` (persistence families, spoofing_suspects, behavior timeline) |
| `network_intel.json` | `winre/enrich_pcap_tshark.py` over `network_raw/*.pcap` |
| `memory/pe_sieve_report.json` | `C:\ProgramData\chocolatey\bin\pe-sieve.exe /pid <pid> /json` |
| `malcat-triage.json` | `tools/malcat_win.py` (if licensed) |
| `x64dbg/dump/*.dmp` | `DumpModule` via `http://127.0.0.1:9094/` |
| `META.json` → `x64dbg_dump` | terminal OEP/dump record `{attempted, ok, reason, dump_path?, oep?, module?, detect_ok?, analyze_ok?}` — always present, so a missing dump is never silent (the pre-run META carries `running=true` if the orchestrator died mid-run) |
| `META.json` → `window` | detonation-window telemetry `{requested_s, effective_s, adaptive, idle_stop_s, stop_reason}` (also in `META.job.json`; Frida writes `frida_trace.jsonl.run.json`) |
| `windbg_analysis.json` | `winre/windbg_post.py` via mcp-windbg (`http://127.0.0.1:9097/mcp/`) over `memory/*.dmp`; passive, honest skip when no dump/server |

## 4. Helpers (vendored `winre/`)

| Script | Purpose |
|--------|---------|
| `summarize_dynamic.py` | Procmon CSV → `procmon_summary.json` (file/reg/proc/net groups) |
| `procmon_post.py` | Procmon CSV → persistence catalog (Run key/service/task/WMI/sideload/drop), `behavior_timeline.csv`, spoofing suspects |
| `pcap_beacon.py` | pcaps → `network_intel.json.beacon_analysis` (beacon cadence/jitter, HTTP URIs/UAs, DNS) |
| `post_mortem.py` | procdump -ma harvest + ntdll-integrity (unhooking) + process snapshot → `post_mortem.json`, `memory/*.dmp` |
| `windbg_post.py` | mcp-windbg dump triage (`!analyze -v`, `.ecxr`, `k`, `lm`, `vertarget` + exception/module highlights) → `windbg_analysis.json`; also exposed to the agent as `windbg_analyze_dump` |
| `enrich_pcap_tshark.py` | `tshark -r packets.pcap -T json` → `network_intel.json` |
| `emit_analyst_next.py` | `ANALYST-NEXT.md` template (next BPs, strings to chase) |
| `doc_triage_v2.py` | Office doc triage (OLE/Macro) — not detonation |

## 5. Snapshot

Orchestrator does NOT auto-revert — operator runs `Restore-VMSnapshot clean-*` after `META.json` + SMB copy (see [`OPERATE.md`](OPERATE.md) - snapshot gate / baseline recovery).

## References

- `winre/orchestrator.py`, `winre/flare_dynamic_job.ps1`, `winre/orchestrator.py` (emit_analyst_next).
