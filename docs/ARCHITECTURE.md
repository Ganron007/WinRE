# WinRE Architecture — FlareVM Windows RE

> **SSoT for split:** RevEng (Remnux `.41` Linux, headless static + LLM) ↔ WinRE (FlareVM `.42` Windows, GUI debuggers + detonation).  
> **Principle:** Windows-only work stays on Windows. Linux stays headless. Contract is files, not shared process.

## 1. Hosts and networks

| Host | IP | OS | Purpose | Repo |
|------|----|----|---------|------|
| FlareVM | `192.168.77.42` | Windows 10 (Flare-VM) | IDA 9.3 `idat.exe`, BN 5.1, Ghidra Windows, x64dbg+WinDbg, Frida/Procmon/FakeNet/pe-sieve, dnSpy | **this repo** `WinRE` |
| Remnux | `192.168.77.41` | Ubuntu (Remnux) | ghidrasql `v0.0.4` + LibGhidraHost `v0.0.5`, idasql Linux, speakeasy, floss, capa-malcat, 14-tool manifest, LLM agentic | `RevEng` |
| Laptop GPU | `192.168.77.1:8000` | Windows | bge-m3/Qwen3 embed + rerank FastAPI | neither (shared) |

Flare ↔ Remnux: `OpenSSH` (`C:\ProgramData\ssh\sshd_config`) `192.168.77.42:22` + `HTTP` `9094/9095` (x64dbg-MCP) + `SMB` `\\192.168.77.41\opt\` (artifact share). All lab-net only.

## 2. Split by layer

```
C:\samples\<sha>.exe                # analyst scp to both
        │
        ├─ Remnux .41 (RevEng) ──────────────────────┐
        │  ghidra_sql_client → /opt/ghidra           │
        │  ida_sql_client (Linux idasql) — deprecated│
        │  speakeasy/floss/capa/malcat (local)       │
        │  quick_scan_v2 → deep_dive_agentic (LLM)   │
        │  logs/<sha>/{intake,quick,deep,publish}    │
        └────────────────────────────────────────────┘
        │
        └─ FlareVM .42 (WinRE) ──────────────────────┐
           flare_ghidra_sql → analyzeHeadless.bat     │
           flarevm_ida_query → idasql.exe v0.0.17     │
           x64dbg-MCP :9094 71 tools (MCP)            │
           windbg-mcp :9096 (planned)                 │
           flare_dynamic_job.ps1                      │
              ├─ frida_api_trace.py (hooked APIs)    │
              ├─ Procmon CSV → procmon_summary.json │
              ├─ FakeNet-NG → network_raw/*.pcap     │
              ├─ pe-sieve → memory/pe_sieve_report   │
              └─ x64dbg-mcp DumpModule → unpacked/   │
           logs/<sha>/dynamic/ ───────────────────────┘
                            │
                            └─ SMB → \\.41\opt\samples\corpus\…\logs\<sha>\dynamic\
                                   RevEng v2_lib.load_dynamic_pack() reads (advisory)
```

## 3. Artifact contract (file-based, versioned)

`logs/<sha>/dynamic/` (written by WinRE, read-only for RevEng):

| File | Writer | Schema |
|------|--------|--------|
| `META.json` | `orchestrator.py` | `{sha, file, started, duration_s, skipped, error, tool_versions}` |
| `META.job.json` | `flare_dynamic_job.ps1` | per-job params |
| `frida_trace.json` + `frida_trace.jsonl` | `frida_api_trace.py` | `[{ts, api, tid, args}]` JSONL |
| `procmon.csv` + `procmon_summary.json` | Procmon + `summarize_dynamic.py` | Sysinternals CSV, head `procmon.csv.head` |
| `network_raw/packets_*.pcap` + `network_intel.json` | FakeNet-NG + `enrich_pcap_tshark.py` | pcap + tshark enrich |
| `network.json` | `flare_dynamic_job.ps1` | aggregated network |
| `memory/pe_sieve_report.json` | pe-sieve (opt `--pesieve`) | hollowed PE report |
| `x64dbg/dump/*.dmp` | x64dbg-MCP `DumpModule` | unpacked modules |
| `process_snapshot_{pre,post}.json` | `Process Explorer` snapshot | process list |
| `ANALYST-NEXT.md` + `analyst_next.json` | `emit_analyst_next.py` | human next steps (RevEng never auto-ingests) |
| `SCHEMA.md` | committed | field definitions |

RevEng policy: `static_yara_wins=True` (`dynamic_run_v2.py:602`) — dynamic is corroboration, never clears `CADRE_*` YARA. `load_dynamic_pack()` returns `None` if missing — core stays `truly_green` without it.

## 4. Transports

| Path | Proto | Port | Auth |
|------|-------|------|------|
| Remnux → Flare detonate | SSH `ssh remnux@192.168.77.42` | 22 | `C:\Users\Ganro\.ssh\remnux-lab-key` (same key as `.41` — add Flare `authorized_keys`) |
| LLM → x64dbg | HTTP JSON-RPC | 9094 (x64) / 9095 (x32) | none (lab-net bind `0.0.0.0`, no internet) |
| LLM → WinDbg | HTTP JSON-RPC | 9096 (planned) | none |
| IDA/Ghidra SQL | local CLI | — | no network |
| Artifact share | SMB/CIFS | 445 | `remnux` mount `//192.168.77.42/C`/ `//192.168.77.42/WinRE` |

MCP is `streamable HTTP + SSE` (`x64dbg-mcp README:31`): `POST / {jsonrpc:2.0, method:tools/call, params:{name, arguments}}`.

## 5. Snapshot SOP (mandatory)

FlareVM is a detonation host — revert after every run:

```powershell
# Operator on FlareVM
Checkpoint-VM -Name FlareVM -SnapshotName "clean-2026-08-31"
# after dynamic_run
Restore-VMSnapshot -Name FlareVM -SnapshotName "clean-2026-08-31" -Confirm:$false
```

`V6.2.8[~]` operator, `FLARE-HYGIENE-LOG.md` records restores. Never detonate on bare host without snapshot.

## 6. What is NOT shared

- RevEng never imports WinRE Python — only reads `logs/<sha>/dynamic/` if present.
- WinRE never calls Remnux LLM directly — if LLM-driven x64dbg is needed, Remnux `deep_dive_agentic` `ToolRegistry` will `POST http://192.168.77.42:9094/` as an HTTP tool (fail-open, `REVENG_ENABLE_WINRE=0` default).
- No shared DB, no shared Ghidra project — each host imports the sample independently (avoids lock contention).

## 7. Build order for new agent

1. `TOOL-INVENTORY.md` — verify `C:\tools\` paths, `ghidraHome` if present.
2. `SQL-GHIDRA.md` → implement `flare_ghidra_sql.py` Windows port.
3. `SQL-IDA.md` → wrap `flarevm_ida_query.py` with HTTP.
4. `X64DBG-MCP.md` → `zig build` + deploy plugin.
5. `WINDBG-MCP.md` → Python bridge (spec, then code).
6. `DYNAMIC-ORCHESTRATOR.md` → wire all into `orchestrator.py`.
