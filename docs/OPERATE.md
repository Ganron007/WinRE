# Operate

Day-2 operation of the WinRE lab. Install first: [`INSTALL.md`](INSTALL.md).

## Pipeline modes

| Mode | Command | What runs |
|---|---|---|
| **Static (default)** | `python -m winre.remote_driver C:\samples\s.exe` | intake → quick → deep (LangGraph agent) → yara → report → audit |
| **Static + agentic debug** | `... --agentic-dbg` | static + the deep agent gets bounded x64dbg tools (OEP/unpack/decrypt) — **no detonation** |
| **Static + dynamic** | `... --dynamic --max-seconds 45` | static first, then segregated detonation (FakeNet + Procmon + Frida [+ pe-sieve]) |
| **Dry LLM** | add `--dry-llm` | no LLM calls; deep stays `deterministic_fallback` (honest) |

Environment equivalents: `WINRE_ENABLE_DYNAMIC=1`, `WINRE_AGENTIC_DBG=1`.
The UI (`python -m winre.ui.app`, port 5001) drives the same engine with
per-mode checkboxes and a live deep-mode preview.

**Invariants:** dynamic is opt-in and always LAST; `static_yara_wins` —
dynamic corroborates, never clears a static verdict; every run is audited
(`audit.json`, `truly_green`).

## Evidence packs

`logs/<sha256>/` per sample: `intake/ quick/ deep/ dynamic/ yara/ report/`
+ `audit.json` + `snapshot.json` (HITL ledger). Browse them in the UI
(Cases → pack) — verdicts, agent tool-call timeline, dynamic artifacts
(Frida traces, Procmon summaries, pcaps, pe-sieve dumps), YARA rules,
analyst-next report.

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
| deep shows `deterministic_fallback` | LLM endpoint down / `.env` keys empty (`llm_client.available()`) |
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
session from it). Snapshot-restore afterwards.
