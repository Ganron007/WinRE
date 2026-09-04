# Install

Two machines: the **control plane** (where you run the pipeline/UI) and the
**FlareVM** (where samples execute). See [`PREREQUISITES.md`](PREREQUISITES.md)
for the full hardware/software list.

## 1. Control plane (operator host)

```powershell
git clone <repo-url> WinRE
cd WinRE

python -m pip install langchain-openai langgraph langchain-core pydantic

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

1. Build the VM: Windows 10/11 on an **isolated network**, FlareVM base
   installed, commercial tools per [`PREREQUISITES.md`](PREREQUISITES.md).
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

```powershell
# static-only (default, safe)
python -m winre.remote_driver C:\samples\notepad.exe --dry-llm

# or from the UI: Run page -> pick sample -> Run pipeline
```

Open the Cases page and confirm the pack: audit `truly_green`, honest
`deterministic_fallback` deep source when the LLM is dry. Then see
[`OPERATE.md`](OPERATE.md).

> **Fresh-VM note:** `setup-flarevm.ps1` is idempotent and was verified
> against a fully provisioned VM (`--CheckMode` + verify). The cold-start
> path (bare VM → working platform, first sample in all modes) is part of
> the release checklist — see `internal/IMPROVEMENT-PLAN.md` P-D.
