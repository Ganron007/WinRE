# WinRE

<p align="center">
  <img src="assets/winre-logo.svg" alt="WinRE Logo" width="620">
</p>

> [!IMPORTANT]
> **⚠️ WORK IN PROGRESS — PUBLIC BETA (pre-v1.0).** This repository is
> published early as a project in progress. The pipeline is actively being
> hardened and tested; expect breaking changes, rough edges, and incomplete
> documentation until the v1.0 tag. Use it, break it, tell us — but pin a
> commit if you depend on anything.

<p align="center">
  <a href="https://github.com/Ganron007/WinRE"><img src="https://img.shields.io/badge/Status-LLM--assisted-blue.svg" alt="Status"></a>
  <a href="https://github.com/Ganron007/WinRE"><img src="https://img.shields.io/badge/Platform-Windows%2010%20(FlareVM)-green.svg" alt="Platform"></a>
  <a href="https://github.com/Ganron007/WinRE"><img src="https://img.shields.io/badge/RE-SQL%20First%20%2B%20Dynamic-blue.svg" alt="RE"></a>
  <a href="https://github.com/Ganron007/WinRE"><img src="https://img.shields.io/badge/MCP-x64dbg%20%2B%20WinDbg-orange.svg" alt="MCP"></a>
</p>

**WinRE is FlareVM-based Windows malware analysis — static and dynamic — with a dynamic remote driver for [RevAI](https://github.com/Ganron007/RevAI).**

It runs where Windows malware lives: on a [FlareVM](https://github.com/mandiant/flare-vm) analysis machine (Windows 10/11, isolated lab network), as the Windows companion to RevAI's Linux pipeline. The contract between them is **files, not shared process** — a versioned artifact pack the Linux side reads for corroboration, driven over SSH by WinRE's remote driver.

**Built entirely on free tooling.** Ghidra is the primary static engine; x64dbg (+ the bundled MCP plugin), FakeNet-NG, Procmon, pe-sieve, hollows_hunter and Frida power the detonation phase — setup verifies the complete set and refuses to declare the VM ready without it. **Commercial tools are pure upgrades, never requirements:** IDA Pro (via `idasql`) and Malcat are detected when present and skipped gracefully when absent (honest `skipped` annotations, no failures). Free tooling alone gives the complete intake → quick → deep → YARA → report → audit flow, plus detonation.

> [!WARNING]
> **Malware Sandbox Containment.** WinRE is a dynamic detonation host (Frida, Procmon, FakeNet-NG, pe-sieve). Run it only inside an isolated analysis VM (FlareVM), on a host-only lab network, and **revert the VM snapshot after every run**. The authors accept no liability for payload escapes or network contamination from improper containment.

---

## What is WinRE?

**WinRE** is the Windows-side of malware analysis, static and dynamic, with a dynamic remote driver for the RevAI Linux pipeline. Work that must run on Windows stays on Windows: SQL-first Ghidra/IDA querying, in-VM dynamic detonation, and debugger automation over MCP. The Linux side (RevAI) stays headless and static-first; the contract between them is **files, not shared process** — a versioned artifact pack in `logs/<sha>/dynamic/` that RevAI reads for corroboration.

- **Deterministic-first detonation** — a single PowerShell job stages FakeNet-NG (network sink), Procmon (file/reg/process events), Frida (API trace with string/sockaddr decode), and optional pe-sieve + hollows_hunter (injection/hollowing dumps). The LLM can only interpret what these tools emitted — it never runs the sample.
- **SQL-first Windows RE** — Ghidra (`analyzeHeadless` + SQL post-script) is the primary engine and always present; IDA Pro (`idasql`) and Binary Ninja are optional upgrades that plug into the same SQL surface when installed.
- **Debugger MCP** — a vendored 71-tool x64dbg MCP server (Zig, MIT) and a 12-tool WinDbg bridge speak JSON-RPC over HTTP, so an LLM agent can load a binary, find the OEP, dump modules, and step through unpackers.
- **Honest artifact contract** — every run emits `META.json` (schema-versioned), Frida/Procmon/network/memory artifacts, and `ANALYST-NEXT.md` marking which next steps are **analyst-only**. Dynamic evidence corroborates but **never clears** high-signal static YARA (`static_yara_wins`).

> **Reality check.** WinRE is an analyst assistant, not a finished autonomous product. Detonation results vary by sample; a green `META.json` means the tooling ran and produced artifacts — **not** that the sample is benign or fully understood. Unpacking, deep debugging, and full PCAP review are human work. Treat every pack as a starting point for analyst review, never as ground truth.

---

## Architecture

```
FlareVM (Windows 10 + Flare-VM)                       Remnux (Linux, RevAI)
────────────────────────────────                      ────────────────────
C:\samples\<sha>.exe  ◄──── analyst copies to both ──►  /opt/samples/<sha>/
        │                                                  │
        ├─ tools/flare_ghidra_sql.py ── analyzeHeadless ────┘  static/LLM pipeline
        │     └─ GhidraSql.java (SQL post-script)           (reads logs/<sha>/dynamic/
        ├─ tools/flarevm_ida_query.py ── idasql.exe          as corroboration only)
        ├─ tools/flarevm_bn_query.py ── Binary Ninja API
        │
        └─ winre/orchestrator.py ── ── ── ── ── ── ── ── ── ── ── ── ── ┐
              └─ winre/flare_dynamic_job.ps1                          │
                    ├─ FakeNet-NG  → network_raw/*.pcap               │
                    ├─ Procmon64   → procmon.csv                     │
                    ├─ Frida       → frida_trace.jsonl               │
                    ├─ pe-sieve    → memory/ (optional --pesieve)    │
                    ├─ x64dbg-MCP  → x64dbg/dump/*.dmp (OEP detect)  │
                    └─ summarize_dynamic.py + enrich_pcap_tshark.py  │
                                                                      │
              logs/<sha>/dynamic/  ◄── META.json, ANALYST-NEXT.md ───┘
                       │
                       └─ SMB → Remnux artifact share (read-only there)
```

- **SQL services** — `idasql_server.py` (:19300) and `flare_ghidra_sql.py --serve` (:19301) expose `/query` so a remote agent can query Windows databases over HTTP.
- **Debugger MCP** — `x64dbg-MCP` (:9094 x64 / :9095 x86), `windbg_bridge.py` (:9096). Same JSON-RPC shape on every port: `POST / {"jsonrpc":"2.0","method":"tools/call","params":{"name":...,"arguments":{...}}}`.
- **Artifact contract** — `logs/<sha>/dynamic/` is versioned (internal: `docs/internal/ARCHITECTURE.md`); RevAI reads it with `load_dynamic_pack()` and never writes into it.

Full breakdown: `docs/internal/ARCHITECTURE.md` (internal) · transports + ports: `docs/internal/VM-ACCESS.md` (internal) · tool layout: `docs/internal/TOOL-INVENTORY.md` (internal).

---

## Pipeline

`orchestrator.py` drives one detonation pass. `--mode local` runs the job directly on Flare; `--mode ssh` (legacy) drives the same job over SSH from the Linux host.

```
winre/orchestrator.py <sha256> --mode local --max-seconds 45 [--pesieve]
   ├─ format detect (PE / ELF / document) + REVENG_DYNAMIC_SKIP gate
   ├─ Malcat triage (canary — anomalies + YARA + imports)          → malcat-triage.json
   ├─ flare_dynamic_job.ps1
   │    ├─ FakeNet-NG (sink) + Procmon (PML→CSV) + Frida spawn
   │    ├─ pe-sieve / hollows_hunter mid-run (--pesieve)            → memory/
   │    └─ summarize_dynamic.py → frida_summary / procmon_summary / network.json
   ├─ x64dbg-MCP OEP detect + DumpModule (best-effort, fail-open)   → x64dbg/dump/
   ├─ enrich_pcap_tshark.py → network_intel.json (DNS/HTTP/SNI)
   ├─ emit_analyst_next.py  → ANALYST-NEXT.md + analyst_next.json
   └─ META.json (schema_version, yara_lock, ok/skipped/error, artifacts)
```

Artifacts land in `logs/<sha>/dynamic/` (`META.json` + `ANALYST-NEXT.md` are always present). After every Windows run the operator **restores the FlareVM clean snapshot** — the orchestrator never auto-reverts.

ELF samples are rare on Windows; the orchestrator dispatches them to the Linux-side `elf_dynamic_job.sh` path (strace + tcpdump) when one is present.

---

## Feature Matrix

| Capability | What makes it distinctive |
| :--- | :--- |
| **Frida path/registry decode** | Hooks decode WCHAR/ANSI string args and `sockaddr` (incl. `sendto`/`recvfrom`) so traces contain readable paths, keys, and IP:port instead of pointers |
| **SQL-first parity** | the same canonical queries run on both hosts — the Windows instance must answer the same questions the Linux side does (5% count tolerance) |
| **Honest `static_yara_wins`** | Dynamic packs can never clear high-signal YARA from the static stage — the verdict policy is written into every `META.json` |
| **Fail-open debugger passes** | x64dbg MCP OEP/dump and Malcat triage are best-effort: MCP down or license missing degrades the pack, never fails the run |
| **Analyst-only markers** | `ANALYST-NEXT.md` explicitly tags human work (PCAP deep-dive, snapshot restore, HITL unpacking) so an agent cannot claim it done |
| **Vendored debugger MCP** | 71-tool x64dbg server (Zig, MIT) + 12-tool WinDbg bridge share one JSON-RPC shape for the agentic loop |
| **Unique artifact names** | FakeNet sub-directory outputs (shared filenames like `capture.pcap`) are flattened with collision-free names — no silent capture loss |

---

## Requirements

* **OS**: Windows 10/11 (Flare-VM recommended — the VMware Flare image ships IDA/BN/Ghidra/x64dbg/WinDbg/Procmon/FakeNet)
* **Resources**: 8 GB RAM minimum (16 GB recommended); ≥60 GB disk
* **Python**: 3.11+ (`frida` for the tracer, `flask` for the SQL/HTTP servers)
* **Isolated lab network** — host-only VM network, no public internet
* **Optional tools**: IDA Pro 9.x (for `idasql`), Malcat (commercial license), pe-sieve (`choco install pe-sieve`), Ghidra 12.x extracted to `C:\tools\`
* **Linux peer**: RevAI/RevEng pipeline on Remnux (optional — WinRE runs standalone; the artifact share is the only coupling)

---

## Quickstart

```powershell
# 1. Clone + place on FlareVM
git clone https://github.com/Ganron007/WinRE.git C:\WinRE

# 2. Health check the tool stack
python C:\WinRE\tools\flarevm_toolset.py health          # IDA / idasql / Binary Ninja
python C:\WinRE\tools\flare_ghidra_sql.py health         # Ghidra + CADRE PE Loader
python C:\WinRE\tools\malcat_win.py health               # Malcat (optional, licensed)

# 3. SQL query a sample (IDA)
python C:\WinRE\tools\flarevm_toolset.py ida "SELECT count(*) FROM funcs" --file C:\samples\foo.i64 --json

# 4. Dynamic detonation (local mode — recommended)
python C:\WinRE\winre\orchestrator.py <sha256> --mode local --max-seconds 45
#    → C:\WinRE\logs\<sha>\dynamic\META.json + ANALYST-NEXT.md

# 5. Debugger MCP (x64dbg)
#    build once:    powershell -File C:\WinRE\tools\build_x64dbg_mcp.ps1
#    deploy:        xcopy /E dist\x64\plugins\x64dbg-MCP-Server.dp64 C:\tools\x64dbg\x64\plugins\
#    then in x64dbg: Plugins > Configure MCP Server > 0.0.0.0:9094
curl http://127.0.0.1:9094/ -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# 6. Smoke + lab status
python C:\WinRE\ops\smoke_flare.py

# 7. Full pipeline (static + dynamic + report + audit)
python C:\WinRE\winre\pipeline.py C:\samples\foo.exe --max-seconds 45
#    exit 0 only when truly_green; evidence pack under logs/<sha>/

# 8. UI console (control plane — operator host, drives FlareVM over SSH)
python winre\ui\app.py --port 5001
#    open http://127.0.0.1:5001  → Dashboard / Run Pipeline / Evidence / MCP
```

Per-feature docs: `docs/PIPELINE.md` · `docs/SQL-GHIDRA.md` · `docs/SQL-IDA.md` · `docs/X64DBG-MCP.md` · `docs/WINDBG-MCP.md` · `docs/DYNAMIC-ORCHESTRATOR.md`. Malcat-specific notes live in [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md) (optional-commercial section).

---

## Security Guidelines

* Keep FlareVM on a host-only / isolated lab NIC — **no public internet**.
* **Snapshot before every detonation run and restore after.** The VM is a detonation host; malware can persist via Run keys or services.
* Never commit `.env` files, API keys (e.g. `MALCAT_KEY`), or malware samples.
* MCP/SQL HTTP services are unauthenticated by design (lab-net only) — do not expose ports 9094–9096, 19300, 19301 outside the lab network.

---

## What's coming…

*Work-in-progress — the roadmap below is where WinRE is headed before the `v1.0.0` release tag. Items land as they are built and tested on the live lab.*

| Item | Description |
|------|-------------|
| **LangGraph deep-dive agent** | Agentic ReAct loop over the MCP servers (x64dbg/Malcat/WinDbg) — the LLM decides debugger moves within budget, RevAI-style |
| **LLM endpoint on control plane** | Point `WINRE_LLM_BASE_URL` at a local model / API so deep-dive reports are `llm_judge` not fallback |
| **Persistence forensics pass** | Registry Run keys / services diff in `process_snapshot_*` vs clean baseline, surfaced in `ANALYST-NEXT.md` |
| **RevAI evidence backlink** | URL/`load_dynamic_pack()` links in published RevAI reports pointing at the WinRE artifact pack |
| **Packer taxonomy** | pe-sieve + Malcat unpack results fused into a `packer-summary.json` the Linux agent can cite |

---

## License

MIT — see [LICENSE](LICENSE).

> Copyright (c) 2026 CADRE RE Team.

---

## Acknowledgements

* **idasql** — SQL interface for IDA Pro databases, by [Elias Bachaalany](https://github.com/allthingsida/idasql), used under the Human-Origin Source License v1.0.
* **ghidrasql / LibGhidraHost** — SQL interface for Ghidra program databases, by [Elias Bachaalany](https://github.com/0xeb/ghidrasql), used under the Human-Origin Source License v1.0.
* **x64dbg-MCP-Server** — MCP plugin for x64dbg, MIT (vendored under `integrations/`).
* **mcp-windbg** — MCP server for WinDbg crash analysis, by [svnscha](https://github.com/svnscha/mcp-windbg), MIT.
* **Malcat** — commercial binary analyzer (license required; binary not redistributed).
* Derived from the **RevEng** research pipeline; the Linux-side sibling is **RevAI**.
