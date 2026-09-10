# Operate

Day-2 operation of the WinRE lab. Install first: [`INSTALL.md`](INSTALL.md).

## Pipeline modes

| Mode | Command | What runs |
|---|---|---|
| **Static, agentic engine (default)** | `python -m winre.pipeline C:\samples\s.exe` | intake → quick → deep (LangGraph ReAct, `llm_judge`) → yara → report → audit → `logs/<sha>/agentic/` |
| **Static, deterministic engine** | `... --mode static` | same stages, deep = fixed 35-tool checklist (30 steps) + rules verdict + calibration gates, zero LLM (`static_deterministic`) → `logs/<sha>/static/` |
| **Static + agentic debug** | `... --agentic-dbg` | static + the deep agent gets bounded x64dbg tools (OEP/unpack/decrypt/write-BP) — **no detonation**. Local driver supported too: `python -m winre.pipeline C:\samples\s.exe --mode agentic --agentic-dbg` |
| **Static + dynamic** | `... --dynamic --max-seconds 45` | static first, then segregated detonation (FakeNet + Procmon + Frida [+ pe-sieve]) into the run's mode section |
| **Dry LLM** | add `--dry-llm` (agentic mode) | no LLM calls; deep stays `deterministic_fallback` (honest, not green) |
| **Publish case** | add `--publish` | sanitized case → `docs/case-studies/<mode>/<sha>/` (no binaries) |

Environment equivalents: `WINRE_ENABLE_DYNAMIC=1`, `WINRE_AGENTIC_DBG=1`.
The UI (`python -m winre.ui.app`, port 5001) drives the same engine: a
deep-mode selector on the Run page (agentic/static + live engine preview),
one row per `(sha, mode section)` in Cases with S/A badges, a section
switcher on the pack page, manual stage control that writes into the
viewed section, and **fire-one-tool** on the pack page (any of the 35
static tools, optional raw-JSON args; result → `deep/01-manual-<tool>.json`
+ `manual_runs.json` audit trail; x64dbg_* excluded — use deep +
agentic-dbg). Pack export zips the viewed section.

**Invariants:** dynamic is opt-in and always LAST; `static_yara_wins` —
dynamic corroborates, never clears a static verdict; every run is audited
(`audit.json`, `truly_green`).

## Where the LLM lives (driver owns the LLM)

The box that runs the driver owns the LLM calls — there is no LLM
negotiation with the VM. On import, `winre/envfile.py` loads *that box's*
`<repo>/.env` (override path via `WINRE_ENV`), and `llm_client` reads:

```
WINRE_LLM_BASE_URL=https://<your-provider>/v1
WINRE_LLM_MODEL=<model-name-your-provider-exposes>
WINRE_LLM_API_KEY=<key>
WINRE_LLM_REASONING=high
```

WinRE is model-agnostic: any OpenAI-compatible endpoint works. Only the
variable names above are contractual — never a specific model or provider.

| Driver | LLM config lives on | VM needs |
|---|---|---|
| **Remote** (`--driver remote`, UI, RevAI-driven) | Driving box (host `.env`, RevAI box `.env`, or exported env). That box needs internet to the provider. | Nothing LLM-related — tools + MCP + SSH + snapshot marker only. `C:\WinRE\.env` is never read. |
| **Local** (`pipeline.py` on the VM, `--driver local`) | `C:\WinRE\.env` on the VM (NAT phase / VM-side testing only) | Internet to the provider (conflicts with air-gap — never combine with detonation) |

This is deliberate (2026-09-01 split: LLM needs internet, detonation
can't have it) and it keeps API keys off the malware VM. For anything
RevAI-driven or detonation-adjacent, keys stay on the control plane.
The RevAI-side mapping (its config → `WINRE_LLM_*`) is specified in
[`REVAI-BRIDGE.md`](REVAI-BRIDGE.md).

## Evidence packs

`logs/<sha256>/<static|agentic>/` per sample and engine: `intake/ quick/
deep/ dynamic/ yara/ report/` + `audit.json` + pack-level `META.json`
(mode/engine/source). `snapshot.json` (HITL ledger) lives at the sha root
(VM-state, mode-independent). Browse them in the UI (Cases → pack — one row
per section) — verdicts, deep tool-call timeline (agentic) or checklist +
fired rules (static), dynamic artifacts (Frida traces, Procmon summaries +
persistence catalog + behavior timeline, beacon analysis, post-mortem
dumps, pcaps, pe-sieve dumps), YARA rules, analyst-next report.

## Sandbox realism (run BEFORE the first detonation)

The detonation VM must look like a real host, or modern malware exits before
behaving (Maldev 73/74 checks). On the VM:

```powershell
python -m winre.sandbox_realism check    # probe: CPU/RAM/USBSTOR/procs/boot/display
python -m winre.sandbox_realism apply    # seeds USBSTOR device history (registry)
```

Manual items the probe flags: display 1920x1080 (not headless), warm
snapshot (booted days ago), non-VMware-looking BIOS/MAC, VMware-tools
sanitization. Sample filenames: keep original human-ish names — never a
bare hash (intake records the policy note).

## Case pack (DFIR-Nexus ingest)

After every dynamic run the section pack gets a 7z with dynamic logs +
static context + `case_manifest.json` (file→sha256) + `case_timeline.json`
(incident-style ordered events). DFIR-Nexus consumes this for host+memory+
behavior correlation; full-image memory analysis is DFIR-Nexus-owned.

```powershell
python -m winre.casepack <sha256> [--mode static|agentic]
```

## Snapshot gate

Before any execution (detonation or agent debug) the gate checks a
clean-snapshot marker on the VM and a global run ledger
(`logs/_vm_state.json`).

- `observe` (default): everything is probed and recorded, **nothing is
  blocked** — advisory mode.
- `enforce` (`WINRE_SNAPSHOT_GATE=enforce`): execution is refused unless
  the marker is present (or an L2 hypervisor auto-restore just re-created
  it). The marker is consumed on use — two executions without a real
  restore in between are impossible.
- `off`: gate inert.

CLI:

```powershell
python -m winre.snapshot_gate status
python -m winre.snapshot_gate attest --action verified_clean   # marker-checked server-side
python -m winre.snapshot_gate marker-create                    # one-time, before taking a snapshot
```

The UI Run page shows the live gate card (mode, marker, ledger,
auto-restore config) with attest buttons. With `WINRE_HYPERVISOR` +
`WINRE_VM_PATH` + `WINRE_SNAPSHOT` set, the pipeline auto-restores before
each detonation.

## MCP plane

| Server | Port | Start | Notes |
|---|---|---|---|
| Malcat | 9009 | boot autostart (`WinRE-MCP.cmd`) | localhost-bound; control plane uses the SSH-exec bridge |
| WinDbg | 9097 | boot autostart | localhost-bound; SSH port probe for health |
| x64dbg | 9094 | on demand (manager) / scheduled task | binds all interfaces |

Restart everything on the VM console:
`powershell -File C:\WinRE\winre\mcp\start_servers.ps1` (idempotent).

## Health & diagnostics

```powershell
python ops\smoke_flare.py          # 9-check PASS/FAIL battery (SSH, py_compile, layout, MCP, gate, LLM)
python -m winre.snapshot_gate status
```

On the VM: `C:\WinRE\install\verify-flarevm.ps1` (read-only PASS/FAIL).

Common failures:

| Symptom | Fix |
|---|---|
| deep shows `deterministic_fallback` | LLM endpoint down / `.env` keys empty (`llm_client.available()`), or `--dry-llm` on agentic mode. Static mode (`--mode static`) never needs the LLM — expect `static_deterministic` |
| dynamic stage `snapshot gate: VM dirty` | restore the snapshot, or attest in the UI, or set auto-restore vars |
| MCP x64dbg down | scheduled task `WinRE-X64dbg-Once`, or let the manager ensure it on demand |
| Malcat calls fail from host | expected — localhost-bound; the SSH bridge handles it. If the bridge fails, restart `start_servers.ps1` on the VM |
| `orchestrator lock held` | a run is live (check writer pid in the error) or break with `--force` |
| IDA queries flaky | the agent uses idasql HTTP-first with one-shot fallback; Ghidra+Malcat cover the rest |

## Manual detonation (UI-free)

```powershell
python -m winre.orchestrator <sha256-or-sample-path> --mode local --max-seconds 45 --pesieve
```

Write the session file first (or pass the sample path — the CLI repairs the
session from it). Snapshot-restore afterwards. Manual runs land in the flat
`logs/<sha>/dynamic/`; pipeline-driven runs pin output into the mode section
via `WINRE_DYNAMIC_DIR`.
