# Dynamic Orchestrator — FlareVM

> **Status:** PORT — `winre/orchestrator.py` is `Tools/v6_deploy/V6.2/scripts/dynamic_run_v2.py` (668 lines, local-first now). `winre/flare_dynamic_job.ps1` stages Frida+Procmon+FakeNet+PE-sieve.

## 1. Flow

```
host: scp sample → C:\samples\foo.exe + C:\WinRE\orchestrator.py --file C:\samples\foo.exe --max-seconds 45 [--pesieve]
  → orchestrator.py (Flare local)
     ├─ detect fmt: PE vs ELF vs doc (via lief/magic)
     ├─ if REVENG_DYNAMIC_SKIP=1 → write META.json {skipped:true} + exit 0
     ├─ start FakeNet-NG → C:\WinRE\logs\<sha>\network_raw\fakenet.log
     ├─ start Procmon → procmon.exe /BackingFile C:\WinRE\logs\<sha>\procmon.pcap
     ├─ spawn frida_api_trace.py --target C:\samples\foo.exe --apis <hooklist> → frida_trace.jsonl
     ├─ wait --max-seconds (default 45), optional PE-sieve mid-run if --pesieve
     ├─ stop Procmon → procmon.csv, tshark enrich → procmon_summary.json + network_intel.json
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

See `docs/internal/ARCHITECTURE.md:3` contract table. Key:

| File | Source |
|------|--------|
| `frida_trace.jsonl` | `tools/frida_api_trace.py` hook set (CreateFileW, VirtualAlloc, etc. `dynamic/README.md:20`) |
| `procmon.csv` | `C:\tools\sysinternals\Procmon64.exe /Quiet /Minimized /BackingFile` |
| `procmon_summary.json` | `winre/summarize_dynamic.py` (filters to process `foo.exe`) |
| `network_intel.json` | `winre/enrich_pcap_tshark.py` over `network_raw/*.pcap` |
| `memory/pe_sieve_report.json` | `C:\tools\pe-sieve\pe-sieve64.exe /pid <pid> /json` |
| `malcat-triage.json` | `tools/malcat_win.py` (if licensed) |
| `x64dbg/dump/*.dmp` | `DumpModule` via `http://127.0.0.1:9094/` |

## 4. Helpers (vendored `winre/`)

| Script | Purpose |
|--------|---------|
| `summarize_dynamic.py` | Procmon CSV → `procmon_summary.json` (file/reg/proc/net groups) |
| `enrich_pcap_tshark.py` | `tshark -r packets.pcap -T json` → `network_intel.json` |
| `emit_analyst_next.py` | `ANALYST-NEXT.md` template (next BPs, strings to chase) |
| `doc_triage_v2.py` | Office doc triage (OLE/Macro) — not detonation |

## 5. Snapshot

Orchestrator does NOT auto-revert — operator runs `Restore-VMSnapshot clean-*` after `META.json` + SMB copy (see `docs/internal/VM-ACCESS.md:6`).

## References

- `Tools/v6_deploy/V6.2/scripts/dynamic_run_v2.py:303`, `Tools/v6_deploy/V6.2/scripts/flare_dynamic_job.ps1:1`, `Tools/v6_deploy/V6.2/README.md:23`.
