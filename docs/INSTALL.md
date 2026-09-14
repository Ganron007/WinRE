# Install

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
| `WINRE_REMOTE_PIPELINE` | repo location on the VM | `C:\WinRE` |

Gate + auto-restore config (optional):

| Variable | Meaning |
|---|---|
| `WINRE_SNAPSHOT_GATE` | `observe` (default) / `enforce` / `off` |
| `WINRE_HYPERVISOR` | `vmware` or `vbox` (enables pre-run auto-restore) |
| `WINRE_VM_PATH` | path of the VM (`.vmx` for VMware) |
| `WINRE_SNAPSHOT` | snapshot name to restore |

Smoke-check connectivity:

```powershell
python ops\smoke_flare.py
```

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
`angr`, `speakeasy`, `mcp-windbg`, `setuptools<81`) - from
`C:\Tools-staged\wheels` first (air-gap safe); the **x64dbg-MCP plugin chain**
(source -> `tools\x64dbg-mcp-winre.patch` -> staged zig auto-unzip to
`C:\Tools\zig` -> build -> deploy to `C:\Tools\x64dbg\release\x64\plugins`);
the **Ghidra SQL headless path** (repo `tools\ghidra_scripts\GhidraSql.java` -
zero install; LibGhidraHost `:19301` serve mode is optional) + **CADRE PE
loader** (auto-copied into Ghidra `Extensions\CADRE` from
`C:\Tools-staged\cadre-pe-loader`); **`idasql.exe`** auto-installed from
staging next to `idat.exe`; MCP autostart (Malcat :9009, mcp-windbg :9097;
x64dbg :9094 on demand); IDA license hygiene (shadowed-Free auto-fix) +
logon/BinDiff cleanup.

Rules: `C:\Tools\capa-rules` (clone `mandiant/capa-rules`) and
`C:\Tools\yara-rules` (curated set - operator stages). `ops\provision_tools.ps1`
downloads/clones the free tools and stages them to `C:\Tools-staged\`.

**Operator with staged assets** (`internal\reapply\`, air-gap safe): one
command re-applies everything to a fresh/reverted VM -
`powershell -ExecutionPolicy Bypass -File ops\reapply_after_revert.ps1`.

1. Build the VM: Windows 10/11 on an **isolated network**, FlareVM base
   installed, plus the "you provide" list above (commercial tools per
   [`PREREQUISITES.md`](PREREQUISITES.md)).
2. Sync the repo from the control plane:

   ```powershell
   powershell -ExecutionPolicy Bypass -File ops\sync_to_flare.ps1
   ```

3. On the VM, run the bootstrap (idempotent; detects commercial tools,
   instructs on anything manual, wires autostart + the snapshot gate):

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1
   ```

4. Verify (read-only PASS/FAIL battery):

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\WinRE\install\verify-flarevm.ps1
   ```

5. **Take/update the VM snapshot** now — setup created
   `C:\WinRE\.clean_snapshot` and it must be inside the snapshot.
6. Reboot once: the Startup launcher starts Malcat (:9009) and WinDbg
   (:9097) MCP servers; x64dbg (:9094) starts on demand (its MCP needs a
   console session).

## 3. Control-plane UI (optional, recommended)

```powershell
python -m winre.ui.app          # http://127.0.0.1:5001
```

## 4. First run

> **Fresh-VM validation (benign):** use a **VM-native** benign binary - copy
> `C:\Windows\System32\notepad.exe` *from the VM* to the control plane and run
> against that file. Host Windows 11 system binaries do NOT run on the
> Win10 VM (they exit instantly). This validates setup end-to-end without
> any sample risk.

```powershell
# static-only (default, safe) - deterministic engine needs no LLM at all
python -m winre.pipeline <vm-native-benign.exe> --mode static

# or agentic engine (needs the LLM endpoint for llm_judge)
python -m winre.pipeline <vm-native-benign.exe> --mode agentic

# or from the UI: Run page -> pick sample -> deep-mode -> Run pipeline
```

Open the Cases page and confirm the section rows (`static` /
`agentic`): audit `truly_green`, deep source `static_deterministic`
(static mode) or `llm_judge` (agentic with LLM). `--dry-llm` on agentic
mode honestly shows `deterministic_fallback`. Then see
[`OPERATE.md`](OPERATE.md).

> **Fresh-VM note:** `setup-flarevm.ps1` is idempotent and was verified
> against a fully provisioned VM (`--CheckMode` + verify). The cold-start
> path (bare VM → working platform, first sample in all modes) is part of
> the release checklist — see `internal/IMPROVEMENT-PLAN.md` P-D.
