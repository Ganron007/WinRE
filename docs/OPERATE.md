# Operate

> **Scope:** day-2 operation (runs, snapshot gate, packs, troubleshooting). **Audience:** analysts and operators.

Day-2 operation of the WinRE lab. Install first: [`INSTALL.md`](INSTALL.md).

## Pipeline modes

| Mode | Command | What runs |
|---|---|---|
| **Agentic engine (default)** | `python -m winre.pipeline "C:\samples\s.exe" --driver remote --mode agentic` | intake → quick → deep (LangGraph and configured LLM) → YARA → report → audit → `logs/<sha>/agentic/` |
| **Deterministic engine** | add `--mode static` | same analysis stages; deep uses the fixed checklist and deterministic verdict, with no LLM calls → `logs/<sha>/static/` |
| **Debugger execution** | add `--agentic-dbg` to an agentic run from an active FlareVM desktop session | entry-point or packed-file OEP probe, up to 30 seconds of x64dbg execution, ETW process trace, and scoped cleanup → `logs/<sha>/dbg/` |
| **Dynamic capability** | add `--dynamic --max-seconds 150` to an agentic run | static stages first, then gated detonation → `logs/<sha>/dynamic/` |
| **Dry LLM** | add `--dry-llm` (agentic mode) | no LLM calls; deep stays `deterministic_fallback` (honest, not green) |
| **Publish case** | add `--publish` | sanitized case → `docs/case-studies/<section>/<sha>/` (no binaries) |

The deterministic `static` engine cannot be combined with `--dynamic` or
`--agentic-dbg`. Dynamic and debugger capabilities have separate pack roots
and are separate gated executions. Debugger-assisted analysis can launch or
resume the target, so treat it as execution-consuming. Under the default
`enforce` gate, restore and attest a clean snapshot between them. Inspect the execution plan with
`python -m winre.snapshot_gate plan --dynamic --agentic-dbg` before a campaign.
Environment equivalents are `WINRE_ENABLE_DYNAMIC=1` and
`WINRE_AGENTIC_DBG=1`.
The UI (`python -m winre.ui.app` → `winre\ui\start_ui.ps1`, port 5001)
drives the same engine: a deep-mode selector on the Run page
(agentic/static + live engine preview), dynamic opt-in with a
**pe-sieve** toggle and an **adaptive-window** toggle (+ idle-stop seconds;
`--max-seconds` = cap, effective window lands in `META.window`), one row
per `(sha, mode section)` in Cases with S/A badges, a section switcher on
the pack page, manual stage control that writes into the viewed section,
and **fire-one-tool** on the pack page (a selected deterministic static tool,
optional raw-JSON args; result → `deep/01-manual-<tool>.json` +
`manual_runs.json` audit trail; x64dbg_* excluded — use deep +
agentic-dbg). Pack export zips the viewed section.

**UI operation.** The console is self-sufficient — no CLI
needed. Put `FLARE_*` + `WINRE_LLM_*` in the console host's repo `.env`,
start the console, open `http://127.0.0.1:5001`. From there: run the
pipeline (agentic/static, optional agentic-dbg, optional dynamic), watch
the live stage board, browse packs, rerun single stages, fire single
tools, attest the snapshot gate. Dry-LLM defaults to **off** when the LLM
endpoint answers (`/settings` shows reachability); it stays on when no
LLM is configured so the spine never stalls on timeouts. MCP badges: x64dbg
is probed directly (`:9094` binds `0.0.0.0`, restricted by a Windows Firewall
allow rule to `LocalSubnet` only), Malcat `:9009` and mcp-windbg `:9097` are
localhost-bound on the VM and probed over SSH.

**Invariants:** dynamic is opt-in and always LAST; `static_yara_wins` - dynamic corroborates, never clears a static verdict; every run is audited (`audit.json`, `truly_green`). The snapshot gate defaults to **`enforce`**. It requires both the guest marker and a clean ledger on the separate control plane: a marker can be recreated by code inside the guest, so it is not sufficient alone. After every restore, verify the marker and run `python -m winre.snapshot_gate attest --action verified_clean` from the control plane. The next dynamic/debug execution marks that ledger dirty; the product never restores snapshots automatically. Set `WINRE_SNAPSHOT_GATE=observe` only for intentional benign test loops. A refused dynamic run writes a fresh `dynamic/STAGE.json` (`ok=false`, "blocked by snapshot gate") and the audit records `dynamic_blocked: true` - stale evidence can never masquerade as this run's detonation. A run records its intent in `execution_plan.json` (how many VM executions it asked for vs what the gate allows; mirrored into `audit.json`), and a **verdict-less run is never green** - `audit.json → unmet_expectations` names the gap (`deep verdict missing`, `report verdict missing`) and `truly_green` is false. Dynamic-pack freshness is decided by the per-run nonce (`run_id`), never by comparing clocks; `clock_skew_s` (pack `META.json`, `dynamic/STAGE.json`, `/health`) is a diagnostic, and the VM publishes its own clock facts to `C:\WinRE\vm_clock.json` (w32time Automatic + resync in setup). On an air-gapped lab box `w32tm /query /status` honestly reports `Source: Local CMOS Clock` / `not synchronized` - there is no upstream peer, which is exactly why the pipeline no longer lets any clock decide freshness.

**Threat intel (triage):** the deterministic `threat_intel` tool identifies
known tools (Authenticode signer, VersionInfo, security-tool markers), and
the driver box adds a **VirusTotal HASH-ONLY** lookup (`WINRE_VT_API_KEY` in
the control-plane `.env`; only the SHA256 is sent - never a sample).
Evidence-only by policy: VT engines flag dual-use tooling constantly, so a
detection count never decides a verdict. **Kesakode is not available here**:
headless *offline* Kesakode is an OEM-license feature (this install is FULL,
and live-probed flavors are reported by `tools/malcat_kesakode.py`), and the
**online** lookup (`-k`, license quota) is deliberately **removed by policy**
- the VM holds no secrets. An OEM build auto-enables offline lookup through
the `kesakode_offline` evidence field.

## Where the LLM lives (driver owns the LLM)

The box that runs the driver owns the LLM calls — there is no LLM
negotiation with the VM. On import, `winre/envfile.py` loads *that box's*
`<repo>/.env` (override path via `WINRE_ENV`), and `llm_client` reads:

```
WINRE_LLM_BASE_URL=https://<your-provider>/v1
WINRE_LLM_MODEL=<model-name-your-provider-exposes>
WINRE_LLM_API_KEY=<key>
WINRE_LLM_REASONING=high
WINRE_VT_API_KEY=<virustotal-key>   # hash-only triage (optional)
WINRE_LLM_CONTEXT_TOKENS=1000000     # model window - evidence budget (default)
WINRE_LLM_MAX_OUTPUT_TOKENS=32768    # assistant output cap (default)
# optional role pins (blank = use WINRE_LLM_MODEL for that role)
#WINRE_LLM_PLANNER_MODEL=            # agent tool loop
#WINRE_LLM_VERDICT_MODEL=            # final judge (verdict + finalize pass)
```

**Role routing (optional).** Two pins split the LLM roles so the expensive
model is paid for once: the **planner** runs the agent tool loop (the
token- and call-heavy part) and the **judgment** model produces the verdict
and its finalize pass. Everything else in WinRE is deterministic, so there is
nothing else to route.

- Each pin defaults to `WINRE_LLM_MODEL`; a pin **never** moves another role.
  `WINRE_LLM_MODEL` is the default for every unpinned role and is resolved
  from that variable alone.
- The resolved routing is recorded **per run** in `deep.json → llm_roles`,
  `report.json` and `audit.json`, so which model produced the tool loop and
  which produced the verdict is verifiable per case rather than trusted.
- `/settings` shows the pins verbatim, the resolved routing, and whether each
  pinned model actually answers — a pin to a model the provider does not
  serve shows as *no answer* instead of silently becoming a deterministic
  fallback mid-run.
- `python -m pytest tests/test_llm_roles.py -q` covers the resolution matrix
  and the "a pin must not move the pipeline" invariant.

Full-context policy: tool results are sized from the model window
(~3.6 chars/token, 30% reserved for prompt/history/answer; per-call cap up
to 240k chars) instead of a fixed small truncation - the interpreter sees
the raw tool data. Lower `WINRE_LLM_CONTEXT_TOKENS` only for small models.

WinRE is model-agnostic: any OpenAI-compatible endpoint works. Only the
variable names above are contractual — never a specific model or provider.

| Driver | LLM config lives on | VM needs |
|---|---|---|
| **Remote** (`--driver remote`, UI, RevAI-driven) | Driving box (host `.env`, RevAI box `.env`, or exported env). That box needs internet to the provider. | Nothing LLM-related — tools + MCP + SSH + snapshot marker only. `C:\WinRE\.env` is never read. |
| **Local** (`--driver local`) | `.env` on the process host | On the FlareVM, the pipeline cannot pass the independent control-plane ledger gate. Use `--driver remote` for Flare analysis and detonation. |

This keeps API keys on the control plane while the malware VM remains
isolated. For anything
RevAI-driven or detonation-adjacent, keys stay on the control plane.
Direct local orchestrator execution is collection-only; trusted post-run
analysis requires the remote driver and pulled artifacts.
The RevAI-side mapping (its config → `WINRE_LLM_*`) is specified in
[`REVAI-BRIDGE.md`](REVAI-BRIDGE.md).

## Evidence packs

`logs/<sha256>/<static|agentic|dbg|dynamic>/` per sample and producer
section: `intake/ quick/ deep/ dynamic/ yara/ report/` plus run metadata,
manifests, composition, and `audit.json`. The evidence section identifies the
producer; `META.json` records the engine separately. The optional
`snapshot.json` is a sample-level HITL record, not the authoritative VM-state
ledger. The latter lives in `internal/_vm_state.json` on the control plane.
Browse packs in the UI (Cases → pack — one row
per section) — verdicts, deep tool-call timeline (agentic) or checklist +
fired rules (static), dynamic artifacts (Frida traces, Procmon summaries +
persistence catalog + behavior timeline, beacon analysis, post-mortem
harvest + ntdll integrity, WinDbg dump analysis, emulation-vs-detonation
diff, pcaps, pe-sieve dumps), YARA rules, analyst-next report. The pack
view surfaces all of those in-page (not just raw JSON downloads).

## Corpus identity and staging

The operator workstation may be a sample transit point. Inventory extracted
corpora by content before staging; the registry preserves source aliases while
deduplicating identical bytes. The inventory reads files as data and does not
execute them. Its default output, `internal/sample-registry.json`, is local
operator state and is gitignored.

```powershell
python -m winre.corpus_registry inventory `
  --source-root D:\corpora\extracted `
  --source-label extracted-corpus-2026-10

python -m winre.corpus_registry stage `
  --source D:\corpora\extracted\sample.bin `
  --destination-root D:\WinRE-corpus-staging `
  --source-label virussign-2026-10
```

Staging copies into `<destination-root>\<sha256>\<sanitized-name>` and verifies
the copied bytes against SHA-256; the original filename remains an alias in the
registry. PE format, architecture and DLL/driver
candidates are header-derived; executability is never treated as permission to
run. Source and destination paths are local to the machine running the command;
this step does not transfer samples to Flare. Family remains `unknown` until an
operator records supporting evidence:

```powershell
python -m winre.corpus_registry classify-family `
  --sha256 "<sha256>" --family "<family>" --operator "<name>" `
  --basis "<why-this-classification-is-supported>" --evidence-ref "<path-or-citation>"
```

Record runs only after they finish, with their mode, run ID, code revision and
configuration digest. A repeat of the same sample and mode requires an
explicit reason in the registry; separate modes remain valid. The registry
currently accepts `static`, `agentic`, and `agentic-dbg` for run history; it
does not separately encode the `--dynamic` capability yet. This registry does
not gate the live pipeline. History attestations apply only to this registry
and cannot establish that a sample never ran elsewhere.

```powershell
python -m winre.corpus_registry record-run `
  --sha256 "<sha256>" --mode static --run-id "<32-hex-run-id>" `
  --code-revision "<commit-or-build-id>" --config-digest "<config-hash>" `
  --outcome completed
```

A history import must use the documented schema and cite the source record:

```powershell
python -m winre.corpus_registry attest-history `
  --sha256 "<sha256>" --status no_recorded_winre_run_in_this_registry `
  --operator "<name>" --basis "<what-was-reviewed>"
```

This attestation is limited to the current registry; it is not evidence that
the sample never ran on another system. An imported-history record requires an
evidence reference.

```powershell
python -m winre.corpus_registry import-history `
  --sha256 "<sha256>" --history-file .\history.json `
  --operator "<name>" --basis "<reviewed-source>" `
  --evidence-ref "<path-or-citation>"
```

The history file uses `winre-corpus-run-history/v1`, carries the same `sha256`,
and contains a `runs` array. Each run needs a supported mode and either its
32-character `run_id` or a stable `legacy_id`; missing historical revision or
time values stay null. The imported file's hash is stored with each imported
record. Example shape:

```json
{"schema":"winre-corpus-run-history/v1","sha256":"<64-hex-sha256>",
 "runs":[{"legacy_id":"<stable-record-id>","mode":"static",
          "outcome":"unknown","recorded_at":null}]}
```

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

After a dynamic run — or a deep unpack (the pack accepts deep-only sections
too) — the section pack gets a 7z with dynamic logs, static context, the
PE-valid unpack dump (`deep/x64dbg/`), `case_manifest.json` (file→sha256) +
`case_timeline.json` (incident-style ordered events). DFIR-Nexus consumes
this for host+memory+behavior correlation; full-image memory analysis is
DFIR-Nexus-owned.

```powershell
python -m winre.casepack "<sha256>" [--mode static|agentic|dbg|dynamic]
```

## Snapshot gate

Before any guest-tool pipeline run the gate checks a clean-snapshot marker on
the VM and a global run ledger (`internal/_vm_state.json`) on the separate
control plane. This ignored directory is excluded from VM sync and is
independent of the configurable evidence root. The guest marker is writable by
guest code; the control-plane ledger prevents a recreated marker from
reopening a dirty VM.

- `enforce` (default): guest analysis is refused unless the marker is present
  and the control-plane ledger says `restored` or `verified_clean`. Dynamic or
  debug execution consumes the marker and marks the ledger dirty. A snapshot
  restore brings back the marker but does not reset the control-plane ledger;
  the operator must attest `verified_clean` after checking the restored VM. A
  refused run writes a non-green record and preserves prior evidence.
- `observe` (`WINRE_SNAPSHOT_GATE=observe`): everything is probed and recorded,
  the execution-budget gate is advisory. This does not bypass the separate
  guest-integrity check: the marker and clean control-plane ledger are still
  required for pipeline runs.
- `off`: disables the execution-budget gate only. The pipeline's independent
  guest-integrity check remains active.

### After a snapshot revert (baseline recovery)

A revert rolls the VM back to the snapshot's older state. Re-apply the
current repo + VM-side assets in one command from the control plane:

```powershell
powershell -ExecutionPolicy Bypass -File ops\reapply_after_revert.ps1
```

It syncs the repo, re-stages the gitignored `integrations/`, offline pip
wheels and rule-set backups (`internal\reapply\`), runs `setup-flarevm.ps1`
(which also auto-fixes the IDA license-shadowing trap) and the verify
battery, then prints the remaining operator steps (samples from the RevAI
box, `.env` removal/rotation, new snapshot).

CLI:

```powershell
python -m winre.snapshot_gate status
python -m winre.snapshot_gate attest --action verified_clean   # after restore, from the separate control plane
python -m winre.snapshot_gate marker-create                    # only when preparing a new clean baseline snapshot
```

The UI Run page shows the live gate card (mode, marker and control-plane
ledger) with attest buttons. Hypervisor variables are report-only; snapshot
restore remains an operator action.

### Golden image (before the first sample run)

Prepare a reusable baseline: deploy, verify, clean, snapshot.

1. Deploy: `ops\sync_to_flare.ps1` -> `ops\provision_tools.ps1` ->
   `ops\reapply_after_revert.ps1` (setup + verify battery). Expect
   `0 FAIL` in `verify-flarevm.ps1`.
2. Before taking the snapshot, confirm no sample-run artifacts remain under
   `C:\samples`, `C:\WinRE\logs` or `C:\WinRE\cache`, and no
   `__pycache__` directories remain under `C:\WinRE`. Perform this cleanup as
   an explicit operator step so existing evidence is not removed by a
   verification command.
   `ops\smoke_flare.py` uses a per-run compile helper and bytecode under
   `%TEMP%` and removes both. `install\verify-flarevm.ps1` uses benign SQL
   probe copies, caches and logs under `%TEMP%` and stops only SQL processes it
   started; neither command cleans existing samples or runtime state. Run
   verification while the VM is idle.
3. Confirm the clean marker is present (`python -m winre.snapshot_gate status`;
   create it only while preparing a new baseline) - the snapshot must contain
   it. From the separate control plane, attest `verified_clean` before the
   first run and again after every restore.
4. Shut down and snapshot. MCP servers do **not** need to be running in the
   snapshot: the `WinRE-MCP-Boot` scheduled task (AtStartup, SYSTEM) brings
   Malcat `:9009` / WinDbg `:9097` back after any reboot/restore (no logon
   required), and the x64dbg manager launches `:9094` on demand.

After restore, re-sync and verify the VM, then attest `verified_clean` from the
control plane. The first dynamic run consumes the marker and marks the external
ledger dirty; restore and attest again before another run.

## MCP plane

| Server | Port | Start | Notes |
|---|---|---|---|
| Malcat | 9009 | **boot task** `WinRE-MCP-Boot` (AtStartup, SYSTEM) + logon launcher + driver self-heal | localhost-bound; control plane uses the SSH-exec bridge; offline-only (no `-k`) |
| WinDbg | 9097 | **boot task** `WinRE-MCP-Boot` (AtStartup, SYSTEM) + self-heal (`windbg_post`) | localhost-bound; SSH port probe for health |
| x64dbg | 9094 | on demand only — scheduled-task launch via `x64dbg_manager` (agentic-dbg gate + dynamic OEP/dump heal); **not** auto-started at boot | binds all interfaces; GUI + plugin |

Restart everything on the VM console:
`powershell -File C:\WinRE\winre\mcp\start_servers.ps1` (idempotent).

**Self-healing.** `WinRE-MCP-Boot` (scheduled task, AtStartup, SYSTEM) is the
primary path and does **not** depend on an interactive logon. The logon
launcher remains available for interactive sessions. On top of both,
`remote_driver.ensure_mcp_servers()` (quick + deep stages) and
`windbg_post` (dynamic post-analysis) re-probe and, when a headless server
is down, run `start_servers.ps1 -NoX64dbg -Detach`. `-Detach` re-launches
the launcher via a one-shot scheduled task because Win32-OpenSSH kills the
connection's process tree on disconnect (servers started directly from the
SSH shell would die with it). Agentic-dbg heals x64dbg the same way through
`x64dbg_manager.ensure_mcp()` on the first debugger tool call, and the dynamic
OEP/dump step heals it VM-side via `ensure_mcp_local()` before it would skip.
Disable all driver-side healing with `WINRE_MCP_AUTOSTART=0` (driver box).
RevAI inherits this automatically — it runs the same `winre.remote_driver` code.

## Health & diagnostics

```powershell
python ops\smoke_flare.py          # PASS/FAIL battery (SSH, py_compile, layout, MCP, gate, LLM)
python -m winre.snapshot_gate status
```

On the VM: `C:\WinRE\install\verify-flarevm.ps1` (PASS/FAIL with isolated
temporary SQL probes; run while the VM is idle).

Common failures:

| Symptom | Fix |
|---|---|
| deep shows `deterministic_fallback` | LLM endpoint down / `.env` keys empty (`llm_client.available()`), or `--dry-llm` on agentic mode. Static mode (`--mode static`) never needs the LLM — expect `static_deterministic` |
| `snapshot gate` reports dirty or unattested | restore the known-clean snapshot, verify the marker, then attest `verified_clean` from the separate control plane |
| MCP x64dbg down | scheduled task `WinRE-X64dbg-Once`, or let the manager ensure it on demand |
| Malcat calls fail from host | expected — localhost-bound; the SSH bridge handles it. If the bridge fails, restart `start_servers.ps1` on the VM |
| `orchestrator lock held` | a run is live (check writer pid in the error) or break with `--force` |
| IDA queries flaky | the agent uses idasql HTTP-first with one-shot fallback; Ghidra+Malcat cover the rest |

## Manual detonation (UI-free)

```powershell
python -m winre.orchestrator "C:\samples\sample.exe" --mode ssh --max-seconds 150 --pesieve
```

The pipeline-driven remote command is preferred because it records the
requested capability, run ID, manifests, and final audit. The standalone SSH
orchestrator is a lower-level collection path; it does not replace the full
pipeline's run acceptance and reporting. Restore and attest the clean snapshot
after every dynamic or debugger execution. WinRE never restores it
automatically.
