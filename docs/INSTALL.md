# Install

> **Scope:** install WinRE on the control plane and bootstrap the FlareVM. **Audience:** operators deploying the lab.

Two machines: the **control plane** (where you run the pipeline/UI) and the
**FlareVM** (where samples execute). See [`PREREQUISITES.md`](PREREQUISITES.md)
for the full hardware/software list. **Expected tool locations and env
overrides for non-default installs (IDA/Malcat especially) are in
[`TOOL-PATHS.md`](TOOL-PATHS.md) — read it before installing.**

## 1. Control plane (operator host)

```powershell
git clone <repo-url> WinRE
cd WinRE

python -m pip install langchain-openai langgraph langchain-core pydantic
# KB-derived static tools are pure-python/pefile; the VM needs pefile, psutil
# and (for Speakeasy) setuptools<81 pinned (pkg_resources removal):
python -m pip install pefile psutil "setuptools<81"

# Optional fast-path: pyghidra for ghidra_decompile (set GHIDRA_INSTALL_DIR)
# python -m pip install pyghidra

# LLM config (any OpenAI-compatible provider)
copy .env.template .env
notepad .env        # WINRE_LLM_BASE_URL / _MODEL / _API_KEY / _REASONING
```

Point `FLARE_*` environment variables at your VM (or put them in `.env`):

| Variable | Meaning | Default |
|---|---|---|
| `FLARE_HOST` | FlareVM address | *none — set yours* |
| `FLARE_USER` | SSH user on the VM | `FLARE-VM` |
| `FLARE_SSH_KEY` | path to your private key | `~/.ssh/<your-key>` |
| `FLARE_SSH_PORT` | SSH port | `22` |
| `WINRE_GATEWAY_HOST` | optional SSH jump host for callers that cannot reach Flare directly | `.43` in the paired lab |
| `WINRE_GATEWAY_USER` | SSH user on the jump host | `remnux` |
| `WINRE_GATEWAY_SSH_KEY` | operator-host private key used to reach the jump host | *set yours; leave unset on `.43`* |
| `WINRE_REMOTE_PIPELINE` | repo location on the VM | `C:\WinRE` |

Snapshot-gate config:

| Variable | Meaning |
|---|---|
| `WINRE_SNAPSHOT_GATE` | `enforce` (default - one execution per verified restore) / `observe` (advisory execution budget) / `off` (execution budget disabled); all pipeline runs still require the guest marker and clean control-plane ledger |
| `WINRE_HYPERVISOR` | `vmware` or `vbox` (report-only; does not enable restore) |
| `WINRE_VM_PATH` | VM path shown in gate status (report-only) |
| `WINRE_SNAPSHOT` | snapshot name shown in gate status (report-only) |
| `WINRE_LLM_CONTEXT_TOKENS` | model context window (generic default `1000000`); provider-specific published limits clamp the effective window used to estimate the evidence budget, with 30% reserved for prompts, history and output |
| `WINRE_LLM_MAX_OUTPUT_TOKENS` | assistant output cap (default `32768`); clamped to the configured provider/model's published output limit where supported |
| `WINRE_VT_API_KEY` | VirusTotal **hash-only** triage on the control plane (optional; only the SHA256 is sent) |

Smoke-check connectivity:

```powershell
python ops\smoke_flare.py
```

`ops\smoke_flare.py` uses the configured SSH jump host for its SSH and SCP
checks. From the workstation, set `WINRE_GATEWAY_HOST`, `WINRE_GATEWAY_USER`,
and `WINRE_GATEWAY_SSH_KEY` as described above; the x64dbg HTTP probe remains
advisory because its firewall rule accepts the `.43` control plane only. The
smoke check runs read-only checks and a per-run temporary compile helper, which
it removes before returning. `install\verify-flarevm.ps1`
performs live SQL checks using benign probe copies under `%TEMP%`; it isolates their cache,
logs and ports, disables Python bytecode writes, and stops only SQL processes
started by that invocation. It does not write to `C:\samples` or the deployed
cache/log trees. Run it while the VM is idle; its temporary probes and databases
are removed before it exits.

## 2. FlareVM (execution VM)

### Bare VM: what you provide vs what WinRE configures

**You provide (once):**

| Step | Why |
|---|---|
| Windows 10 + **FlareVM base** | all free tooling (Ghidra, x64dbg, FakeNet-NG, Procmon, Sysinternals, pe-sieve, hollows_hunter, ...) |
| **Python 3.13 (all users) -> `C:\Python313`** | every WinRE tool + MCP server runs on it; setup installs the pip deps |
| **Malcat** (optional commercial) installed + license activated | malcat_* tools; honest skip when absent |
| **IDA Pro** (optional commercial) installed + activated; `idasql.exe` next to `idat.exe` | `ida_query` / `.i64` creation; headless needs Pro (Free is GUI-only). Drop the licensed `idasql.exe` at `C:\Tools-staged\idasql.exe` and setup installs it |
| **SSH key**: your public key in `C:\ProgramData\ssh\administrators_authorized_keys` | FlareVM's admin user authenticates via that file, NOT the profile one - see [`REVAI-BRIDGE.md`](REVAI-BRIDGE.md) 2.1 |
| NAT/internet **during setup only** | pip downloads (or use staged wheels); production stays air-gapped |

**WinRE configures (idempotent: `sync_to_flare.ps1` + `setup-flarevm.ps1`):**
repo `C:\WinRE` + layout, snapshot marker, `.env.template`; pip deps
(`frida`, `flask`, `pefile`, `psutil`, `oletools`, `pypdf`, `dnfile`, `z3`,
`angr`, `speakeasy`, `mcp-windbg`, `flare-floss`, `setuptools<81`) - from
`C:\Tools-staged\wheels` first (air-gap safe); the **x64dbg-MCP plugin chain**
(source -> `tools\x64dbg-mcp-winre.patch` -> staged zig auto-unzip to
`C:\Tools\zig` -> build -> deploy BOTH arches (`release\x64\plugins\x64dbg-MCP-Server.dp64`
+ `release\x32\plugins\x64dbg-MCP-Server.dp32` - x64dbg.exe loads only the dp64, the old
single-select check silently shipped dp32-only and :9094 never bound); a firewall allow
rule then scopes `:9094` to the REMnux gateway address);
the **SQL-first Ghidra/IDA stack** (staged `LibGhidraHost.zip` +
`ghidrasql.exe` + `idasql.exe`; per-project HTTP servers with a reuse
registry and end-of-run sweep - see [`SQL-GHIDRA.md`](SQL-GHIDRA.md))
+ **CADRE PE loader** (auto-copied into Ghidra `Extensions\CADRE` from
`C:\Tools-staged\cadre-pe-loader`); **`idasql.exe`** auto-installed from
staging next to `idat.exe`; MCP autostart (`WinRE-MCP-Boot` AtStartup/SYSTEM + logon launcher: Malcat :9009, mcp-windbg :9097;
x64dbg :9094 on demand); IDA license hygiene (shadowed-Free auto-fix) +
logon/BinDiff cleanup.

Rules: `C:\Tools\capa-rules` (clone `mandiant/capa-rules`) and
`C:\Tools\yara-rules` (curated set - operator stages). `ops\provision_tools.ps1`
downloads/clones the free tools and stages them to `C:\Tools-staged\`.

For the paired RevAI/WinRE topology, run RevAI's `install/setup-remnux.sh` on
the control plane with WinRE installed. It binds no-upstream dnsmasq, INetSim,
and the capture guard to the private VMnet2 interface and keeps IP forwarding
disabled. Host-side sync and reapply reach Flare through `.43` as an SSH jump
host; configure `WINRE_GATEWAY_HOST`, `WINRE_GATEWAY_USER`, and
`WINRE_GATEWAY_SSH_KEY` in the operator-host `.env`. Then run
`setup-flarevm.ps1` (or `ops/reapply_after_revert.ps1`) on Flare. The guest
setup persists `.43` as its gateway and DNS, blocks inbound traffic by default,
allows routed outbound packets to the gateway, blocks all other on-link VMnet2
  IPv4 peers (including `.41` and the workstation host), blocks IPv6 in both
  directions on all guest interfaces, and restricts SSH/x64dbg
inbound access to `.43`. Direct host-to-Flare access is blocked; all VM
administration and source synchronization pass through the gateway.
REMnux captures those packets and never forwards them to its NAT interface. The
remote driver uses off-box gateway capture; standalone Flare runs retain
FakeNet. See
[`DYNAMIC-ORCHESTRATOR.md`](DYNAMIC-ORCHESTRATOR.md) for validation and
protocol coverage limits.

**Operator with staged assets** (`internal\reapply\`, air-gap safe): one
command re-applies everything to a fresh/reverted VM -
`powershell -ExecutionPolicy Bypass -File ops\reapply_after_revert.ps1`.

1. Build the VM: Windows 10 on an **isolated network**, FlareVM base
   installed, plus the "you provide" list above (commercial tools per
   [`PREREQUISITES.md`](PREREQUISITES.md)). Recommended: the WinRE-patched
   installer + fixture in [`install/flarevm/`](../install/flarevm/README.md)
   (fixes default-install failure modes; adds classic `cdb.exe`).
2. Sync the repo from the control plane:

   ```powershell
   powershell -ExecutionPolicy Bypass -File ops\sync_to_flare.ps1
   ```

3. On the VM, run the bootstrap (idempotent; detects commercial tools,
   instructs on anything manual, wires autostart + the snapshot gate):

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1
   ```

4. Verify (PASS/FAIL battery; live SQL probes are isolated under `%TEMP%` and
   safe to re-run while the VM is idle):

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\WinRE\install\verify-flarevm.ps1
   ```

5. **Take/update the VM snapshot** now — setup created
   `C:\WinRE\.clean_snapshot` and it must be inside the snapshot. The
   independent VM-state ledger is stored on the control plane and is not reset
   by restoring this snapshot.

   **The GOLD procedure (operator, in this order):**

   1. Confirm the VM is **current and uncontaminated**: marker armed,
      `C:\WinRE\.env` absent, 0 staged samples, no `.dmp`/`.pcap`/`.pml`
      residue anywhere, and the synced code matches host HEAD (parity).
   2. **Shut the VM down.** Memory state is not wanted — a baseline that
      carries a live guest's RAM is not a clean baseline, and reverting to one
      resumes a session rather than starting fresh.
   3. Take the GOLD snapshot (disk-only, no `.vmss`).
   4. **Start the VM again** so the MCP autostart tasks bring up :9009 / :9097.
   5. From the separate control plane, verify the restored marker and attest
      the clean state before running any pipeline mode:
      `python -m winre.snapshot_gate attest --action verified_clean`.

   A running-VM snapshot is a crash-consistent capture of a live guest, which
   is a different thing from a baseline. Prefer the shutdown form.

6. Reboot once: the Startup launcher starts Malcat (:9009) and WinDbg
   (:9097) MCP servers; x64dbg (:9094) starts on demand (its MCP needs a
   console session).

## 3. Control-plane UI (optional, recommended)

```powershell
python -m winre.ui.app          # http://127.0.0.1:5001
```

## 4. First run

> **Fresh-VM validation (benign):** use a **VM-native** benign binary. Copy
> `C:\Windows\System32\notepad.exe` from the VM to the control plane, then
> run it through the remote driver. This checks the configured tool path
> without using a malware sample.

```powershell
# deterministic static analysis; no LLM calls
python -m winre.pipeline "C:\samples\notepad.exe" --driver remote --mode static

# or agentic engine (needs the LLM endpoint for llm_judge)
python -m winre.pipeline "C:\samples\notepad.exe" --driver remote --mode agentic

# or from the UI: Run page -> pick sample -> deep-mode -> Run pipeline
```

Open the Cases page and confirm the section rows (`static` /
`agentic`): audit `truly_green`, deep source `static_deterministic`
(static mode) or `llm_judge` (agentic with LLM). `--dry-llm` on agentic
mode honestly shows `deterministic_fallback`. Then see
[`OPERATE.md`](OPERATE.md).

> **Verification note:** run `setup-flarevm.ps1` and then
> `verify-flarevm.ps1` on the revision you deploy. The verifier runs isolated
> benign SQL probes in `%TEMP%`; a successful tool check does not replace a
> benign first-run validation through the configured control plane.
