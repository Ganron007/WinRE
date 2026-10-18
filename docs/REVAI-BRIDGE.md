# RevAI ↔ WinRE remote-driver bridge

> **Status:** integration guide for the remote-driver contract. Validate the
> toolchain and evidence behavior on the revision deployed in your lab.

> **Audience:** operators and integrators running RevAI (Remnux/Linux) or any
> other control plane that drives WinRE (FlareVM) remotely. This document is
> the contract for **where the LLM configuration lives and how it reaches the
> remote driver**. WinRE is model-agnostic: any OpenAI-compatible endpoint
> works; only the variable names below are contractual.

## 1. Topology

| Machine | Runs | Needs |
|---|---|---|
| **Driver box** (e.g. RevAI on Remnux, or the operator host) | `winre.remote_driver` / `winre.pipeline --driver remote` — the pipeline process, the LangGraph agent, **every LLM call** | WinRE code + Python deps, the 4 LLM variables, internet to the LLM endpoint, SSH to the VM |
| **FlareVM** (Windows, air-gapped) | Tools only: Ghidra/IDA/Malcat/x64dbg SQL+HTTP MCP, detonation job, snapshot gate | WinRE repo at `C:\WinRE`, tools, MCP servers, clean-snapshot marker. **No LLM keys. No internet.** |

```
Driver box (agent loop + LLM + internet)          FlareVM (air-gapped, tools only)
  winre.remote_driver ── SSH-exec ────────────────► C:\Python313 tools
                      ── SCP (sample/packs) ──────► C:\samples, C:\WinRE\logs
                      ── HTTP MCP :9094/:9009/:9097 ► x64dbg / Malcat / WinDbg
                      LLM calls go to the provider — never to the VM.
```

**Invariant:** LLM calls execute inside the process that runs the WinRE
driver. The VM never receives, stores, or needs LLM configuration. This is
what allows the FlareVM to stay permanently air-gapped, including during
detonation.

## 2. What the driver box must have

1. The **WinRE package** (repo clone or at minimum `winre/` + its deps:
   `langchain-openai`, `langgraph`, `langchain-core`, `pydantic`).
   The remote driver is WinRE code — whoever drives must run it.
2. The **4 LLM variables** (§3) in the driver process environment.
3. **Network** to the LLM endpoint and SSH access to the FlareVM
   (`FLARE_HOST`, `FLARE_USER`, `FLARE_SSH_KEY`, `FLARE_SSH_PORT`).

The FlareVM side needs none of the LLM variables. If a `C:\WinRE\.env`
exists there from a previous NAT/testing phase, delete it.

### 2.1 SSH key handling (FlareVM admin accounts)

If the FlareVM account is in the Administrators group (usual on FlareVM),
sshd authenticates it via `C:\ProgramData\ssh\administrators_authorized_keys`
— **not** the user-profile `authorized_keys`. That file is SYSTEM-owned and
read-only even for admins, so a new driver key cannot simply be appended:

```powershell
# on the FlareVM, once per new driver key
$f = "$env:ProgramData\ssh\administrators_authorized_keys"
takeown /f $f
icacls $f /grant "BUILTIN\Administrators:F"
Add-Content $f -Value (Get-Content C:\path\to\driver_key.pub)
icacls $f /inheritance:r /grant "SYSTEM:F" /grant "BUILTIN\Administrators:F"
Restart-Service sshd
```

Reusing a copy of an existing lab key also works, but every driver then
shares one credential and cannot be revoked independently — prefer a
per-driver keypair.

### 2.2 Key hygiene

- The VM must never hold LLM keys. Delete a leftover `C:\WinRE\.env` **and**
  ensure it is not preserved inside the clean snapshot (delete, then
  re-snapshot), otherwise a revert restores it.
- If LLM keys were ever present on the VM while a detonation ran, treat them
  as exposed: delete the file and **rotate the key at the provider**.

## 3. The 4 variables

```
WINRE_LLM_BASE_URL=https://<your-provider>/v1
WINRE_LLM_MODEL=<model-name-your-provider-exposes>
WINRE_LLM_API_KEY=<key>
WINRE_LLM_REASONING=enabled       # Agnes endpoint: enabled|disabled; effort labels are on aliases
WINRE_LLM_TIMEOUT=600             # per-request HTTP timeout in seconds (default 120)
```

Two **optional** role pins split the two
LLM roles WinRE actually has. Each defaults to `WINRE_LLM_MODEL`, and a pin
never moves the other role:

```
#WINRE_LLM_PLANNER_MODEL=         # agent tool loop
#WINRE_LLM_VERDICT_MODEL=         # final judge and report-claim reviewer
```

The resolved routing is recorded per run (`deep.json → llm_roles`,
`report.json`, `report/claim-review.json`, `audit.json`) so the model used for
the tool loop, verdict and claim review is verifiable per case. Mapping to
RevAI's three roles: WinRE's triage, fixed-checklist deep dive and report
rendering are deterministic; the judgment role separately reviews report
claims against source-bound evidence. `REVAI_LLM_MODEL` is the direct equivalent of `WINRE_LLM_MODEL`,
`REVAI_LLM_PLANNER_MODEL` of `WINRE_LLM_PLANNER_MODEL`, and
`REVAI_LLM_VERDICT_MODEL` of `WINRE_LLM_VERDICT_MODEL`.

Resolution order (highest first):

1. **Real process environment variables** — the `.env` file never
   overwrites an exported value. Best for secrets (nothing on disk).
2. `$WINRE_ENV` file (any path), if set.
3. `<repo>/.env` next to the WinRE package on the driver box.
4. Built-in fallback: `http://127.0.0.1:8000/v1`, model `local`
   (for a local unauthenticated server; non-localhost endpoints require
   `WINRE_LLM_API_KEY`).

### 3.1 Where the WinRE key lives (per runner)

The variable names are always `WINRE_LLM_*`; only the **surface** changes with
the machine that runs the driver process:

| Driver process runs on | WinRE key surface |
|---|---|
| Operator/Windows box — WinRE UI, `--driver local`, or a local `remote_driver` | `<WinRE repo>\.env` next to the package (gitignored, loaded automatically) |
| RevAI VM / any Linux control plane driving the FlareVM | a WinRE-owned env file on that box via `WINRE_ENV` (e.g. `/opt/winre/.env`), or process exports — **not** inside RevAI's own `llm.env` |
| FlareVM | none — the VM never holds LLM config; delete leftover `C:\WinRE\.env` |

**Same key or different keys — both are first-class.** Same model/endpoint on
both sides is expected; whether the API key is shared is the operator's choice:

- **Same key**: configure the same value independently in both surfaces.
- **Different keys** (independent quotas/rotation): keep each key in its own
  surface; WinRE traffic uses the WinRE key only.

Switching between the two is a one-line value change in the WinRE key
surface — no code change, no rewiring, and nothing moves into the other
project's config.

## 4. Wiring options on the driver box

Any of these is sufficient — pick one per deployment:

**A. Exports in the launcher/service (recommended; keys never on disk)**

```bash
export WINRE_LLM_BASE_URL="https://<your-provider>/v1"
export WINRE_LLM_MODEL="<model>"
export WINRE_LLM_API_KEY="<key>"
export WINRE_LLM_REASONING="enabled"
cd /opt/winre          # parent directory of the winre/ package
python3 -m winre.pipeline <sample> --driver remote --mode agentic
```

WinRE creates a 128-bit run ID for standalone invocations. A parent control
plane such as RevAI may pass its own ID with `--run-id <32-hex-value>`; WinRE
validates and reuses it so stage evidence, audit, dynamic pack, and exports can
be correlated to one end-to-end execution. Do not reuse an ID for a separate
analysis run.

Invoke WinRE as a module (`python3 -m winre.pipeline`) from the directory
that contains the `winre/` package (or with `PYTHONPATH` pointing there).
Direct script paths (`python3 winre/pipeline.py`) fail: WinRE uses
package-relative imports and ships no `__init__.py` entry script.

**B. `.env` next to the WinRE copy on the driver box**

```
/opt/winre/.env        # same 4 lines as §3; gitignored by WinRE
```

**C. Central keys file via `WINRE_ENV`**

```bash
export WINRE_ENV=/etc/winre.env     # file holding the 4 lines
```

## 5. If the driver box also has RevAI config

Maintain two independent configurations on that host: RevAI's `llm.env` and
WinRE's own env file (§3.1), or their respective process exports. The RevAI
bridge resolves only `WINRE_LLM_*` settings and removes `REVAI_LLM_*` values
from the WinRE child environment. A missing WinRE key is reported rather than
filled from RevAI. This applies to ordinary agentic, debugger and detonation
modes; deterministic static mode makes no agentic analysis calls, but a green
audit still requires the separate report-claim review.

For remote dynamic runs, the RevAI bridge passes
`--require-external-capture`. A missing or unhealthy passive sensor therefore
blocks the integrated detonation before the guest runs. Standalone WinRE does
not require that sensor; if its optional capture config cannot start, WinRE
records the failure and continues with guest-side FakeNet and telemetry. No
guest gateway or SSH policy change is needed for either path.

When updating a Linux driver from an operator's Windows checkout, sync the
package and LLM fields separately. Preserve that driver's native `FLARE_*`,
SSH key paths, gateway settings and execution gates. After securely transferring
the operator env file to a private location on the driver, run:

```bash
python3 ops/sync_llm_config.py /secure/operator-winre.env /opt/winre/.env
```

The destination must already contain that host's transport settings. The helper
replaces only `WINRE_LLM_*` entries, removes stale role pins absent from the new
source, creates a backup (mode 600 on Unix), and prints no values. It does not copy RevAI
settings or operator-host SSH paths. The FlareVM receives no LLM env file.

## 6. What each mode needs (driver box / VM)

| Mode | LLM variables on driver box | Internet on driver box | Internet/keys on VM |
|---|---|---|---|
| `--mode static` | **required for a green report review** | **required for review** | no |
| `--mode agentic` | **required** | **required** (to the endpoint) | no |
| `--mode agentic --agentic-dbg` | **required** | **required** | no (debug tools run on VM) |
| `--mode agentic --dynamic` | **required** for analysis and report review | **required** for those calls | no (detonation job does not call the LLM) |

A deterministic `--mode static` run cannot request `--dynamic` or
`--agentic-dbg`. Agentic debug and dynamic runs write to separate `dbg/` and
`dynamic/` evidence sections. Each capability is a distinct gated execution;
restore and attest the clean snapshot between them.

Standalone WinRE dynamic runs use guest FakeNet telemetry and continue when no
passive sensor is configured. The RevAI bridge adds
`--require-external-capture`, so an integrated dynamic run fails before guest
execution if the REMnux sensor is absent or unhealthy. Passive capture does not
change Flare's gateway, DNS, SSH access or standalone behavior.

## 7. Verify the wiring (on the driver box)

```bash
cd /opt/winre   # parent directory of the winre/ package
python3 -c "from winre.llm_client import available; print('LLM reachable:', available())"
```

Then a full run without touching the VM:

```bash
python3 -m winre.pipeline <local-sample-path> --driver remote --mode agentic --dry-llm
# dry-llm proves the remote path; drop --dry-llm to use the LLM
```

## 8. Troubleshooting

| Symptom (driver box) | Cause | Fix |
|---|---|---|
| `WINRE_LLM_API_KEY not set for remote endpoint` in deep META | variables not in the driver process env | wire §4/§5; re-check the spawn environment |
| `agent error: Connection error` | driver box cannot reach the endpoint | DNS/NAT/internet on the **driver box** (never the VM) |
| Deep source `deterministic_fallback` with a key configured | endpoint returned an error or timed out | test §7; check provider status |
| RevAI works, WinRE agentic falls back | WinRE's independent settings are missing or its endpoint failed | check WinRE's own env file and driver connectivity (§5) |
| Keys present on the VM | leftover from testing phase | delete `C:\WinRE\.env` (and from the snapshot, then re-snapshot) |

## 9. Artifacts RevAI consumes

Three WinRE outputs are part of the contract:

- **Unpack artifact (PE-valid):** `deep/x64dbg/<stem>_pesieve_unpacked.exe` in
  the mode-section pack, and inside the DFIR-Nexus casepack under
  `deep/x64dbg/`. Produced by **pe-sieve `/imp`** at the unpack OEP
  (ImportTable rebuilt from the in-memory IATs — parse it with normal PE
  tooling). `deep.json → agent.unpack_prepass.artifact` records
  `source` (`pesieve_imp` | `dumpex_savedata` | `dumpmemory_heap`),
  `imports`, `dump_parses`, `rebuild_hint`, `comparison_conclusive`.
- **Detonation window (behaviour-gated since 2026-10-06):**
  `dynamic/META.json → window {requested_s, effective_s, adaptive,
  idle_stop_s, stop_reason, gate_spec, gate_settle_s, gate {fired, kind, api,
  at_s}}` (also in `META.job.json`; the raw trace-side record is
  `frida_trace.jsonl.run.json`, and the verdict is mirrored at
  `META.json → window_gate` / `window_stop_reason`).

  **The window is configurable and recorded.** A historical measurement on
  one test sample found that a 45 s window produced 497 Frida events and no
  DGA, while 150 s produced 694,692 events and live HTTP POST C2. This is an
  example of sample-specific timing, not a guarantee for other samples. The
  current defaults are:

  - `--max-seconds` is the **cap** and defaults to **150**.
  - `--stop-on` is the **mechanism** (default `network,file`): the run keeps
    tracing until the sample does something notable — first outbound
    connection, first file write, or any `api:<ExportName>` you name — then
    keeps tracing `--stop-on-settle` seconds (default 20) so the follow-on
    traffic is captured too, and stops. `stop_reason` is then `gate:network`,
    `gate:file` or `gate:api:<Name>`, which is how you tell "the sample did
    nothing interesting" from "we stopped right after it did".
  - `--idle-stop-seconds` (idle cutoff) is **off by default** and is *not* the
    mechanism: a sleeping sample looks idle, so idle-stop truncates the window
    right before it wakes up and beacons.

  Cite `window` / `window_gate` when reporting dynamic evidence.
- **Dump schema (`x64dbg_dump`), for static re-analysis of a dump:**
  both dump paths now emit the same block — `dump_path`, `dump_kind`
  (`module` | `heap`), `is_pe` / `pe_valid` / `pe_valid_known`,
  `importable_by_pefile`, `imports_count`, `machine`, `dump_parse`,
  `oep`, `oep_target`, `ran_to_oep`, `payload_unpacked`, `imports_rebuilt`,
  `imports_rebuild_applicable`, `imports_rebuild_reason`, `rebuild_hint`, and
  sometimes `consumer_note`. Two rules a consumer must honour:

  1. **`pe_valid: null` means unknown, not bad.** The PE probe could not run
     (no `pefile` on the control plane and no reachable VM); `pe_valid_known`
     is `false` and `pe_valid_unknown_reason` says why. Do not read `null` as
     `false`.
  2. **`dump_kind: "heap"` is not a PE.** It is a raw committed region (the OEP
     was outside the module range), it has no `.idata`, and no import rebuild
     can turn it into one — do not hand it to `pefile`. `dump_kind: "module"`
     with `ran_to_oep: false` is the image **as loaded**: the `--dynamic` path
     never runs the sample, so that is the *packed stub*, not the unpacked
     payload, and a small import count there is the packer rather than damage.
     The rebuilt, unpacked image comes from the `--agentic-dbg` path, which
     escalates `pe-sieve /imp` (modes 1/3/4/5) until the dump parses with
     imports — measured 291 imports vs 0 for the plain `savedata` dump.
- **Case pack (DFIR-Nexus ingest):** `case-<sha16>-<mode>.7z` at the **pack
  root** (`logs/<sha>/<mode>/`), *not* inside a stage directory — it is a
  derived bundle, not a stage artifact, so do not read it as one. It contains
  the dynamic logs plus static context, unpack dumps, `case_manifest.json` and
  `case_timeline.json` (`.zip` fallback when 7-Zip is absent). The authoritative
  per-stage files remain the ones in `intake/`, `quick/`, `deep/`, `dynamic/`,
  `yara/`, `report/`.

### Run-level facts a consumer should read before trusting a pack

| Fact | Where | Meaning |
|---|---|---|
| `execution_plan` | `execution_plan.json` → `audit.json` | how many VM executions the run intended (`execution_sites`, `executions_requested`) and whether the snapshot gate could honor it. `gate_mode=enforce` allows **1 execution per operator-verified restore** — a run asking for `--dynamic` + `--agentic-dbg` is refused before anything executes. |
| `run_id` | root `META.json`, stage JSON, `audit.json`, `dynamic/META.json` + `dynamic/STAGE.json → nonce`, case archive and published `CASE.json` | the per-run nonce issued by the control plane, or generated by WinRE for standalone runs. Pack freshness is decided by this **value** (a VM `META.json` without it is not trusted); timestamps are for humans only. |
| `clock_skew_s` | `dynamic/STAGE.json`, pack `META.json`, `/health` | VM-vs-control-plane clock difference, seconds. **Diagnostic only** — freshness never depends on it (a 5h-fast control plane can no longer make a run look `not-run`). VM-side facts live in `C:\WinRE\vm_clock.json`. |
| `unmet_expectations` | `audit.json` | named gaps that block `truly_green` (e.g. `deep verdict missing`, `report verdict missing`). An empty list is part of the green contract. |
| `no_verdict` / `verdict` | `deep/deep.json` (top level **and** `agent`), `report/report.json` | the deep verdict is mirrored at the top level of `deep.json` (`verdict`, `verdict_obj`, `source`, `confidence`, `key_evidence`, `tool_failures`) so a consumer does not need to know it lives under `agent`. |

When a run does not request detonation, prior dynamic evidence may be preserved
under `previous_runs/`; it must not be interpreted as evidence from the current
run. Same-section reruns can update current artifacts. Consumers should bind
evidence to `run_id`, sample identity, pack section, and audit status.

**`dynamic/SKIP.json` — the one file to read for "did this detonate?".** It is
written whenever a run produced no detonation evidence, and it separates the
two reasons a consumer must not confuse:

```json
{"schema": "winre-dynamic-skip/v1", "ran": false, "skipped": true,
 "reason": "not_requested", "has_detonation_evidence": false,
 "cleared_previous": false, "preserved_previous": "previous_runs/dynamic_<ts>"}
```

- `reason: "not_requested"` — the run never asked to detonate.
- `reason: "snapshot_gate_blocked"` — it asked and the snapshot gate refused
  (`ok: false`, `error` carries the gate reason); the audit also reports
  `dynamic_blocked: true`.
- `preserved_previous` → an earlier pack exists there; `cleared_previous` is
  always `false` (nothing is ever deleted).
- A `dynamic/` folder containing **only** `STAGE.json` + `SKIP.json` is not a
  pack: `has_detonation_evidence: false` says so directly, so no consumer needs
  a "skip-only is not a pack" guard of its own.
