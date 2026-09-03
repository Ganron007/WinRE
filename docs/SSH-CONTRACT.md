# WinRE SSH Contract — for RevEng / RevAI callers

> **Audience:** sibling pipelines (e.g. RevEng, RevAI) invoking WinRE
> (FlareVM) over SSH for static + dynamic analysis.
> **Status:** verified live; the SSH-exec path is the most-tested surface.

Conventions used below (no lab specifics committed — set these per lab):

| Placeholder | Meaning | Example |
|---|---|---|
| `<FLARE_HOST>` | FlareVM SSH host/IP | set via `FLARE_HOST` env |
| `<FLARE_USER>` | SSH user on FlareVM | set via `FLARE_USER` env |
| `$KEY` | path to your lab SSH private key | set via `FLARE_SSH_KEY` env |
| `<sha>` | lowercase hex sha256 of the sample | |

## 0. Transport baseline

| Item | Value |
|---|---|
| Flare host | `<FLARE_HOST>`, user `<FLARE_USER>`, SSH port 22 |
| Auth | key only, `BatchMode=yes` (no passwords, no prompts) |
| Remote shell | `powershell -NoProfile -ExecutionPolicy Bypass -File <script>` |
| Python on Flare | `C:\Python313\python.exe` |
| Repo on Flare | `C:\WinRE\` (synced via `ops/sync_to_flare.ps1`) |

**Non-interactive rules (learned the hard way):**
- Always `-File` with a script file. Never nest `powershell -Command "..."` strings
  inside an SSH command string — quoting mangles `*`, `(`, `"`.
- Pass SQL/paths with special chars **base64-encoded** through SSH layers;
  decode inside the remote script (see `winre/agentic.py::_run_remote_py`).
- Assume no TTY, no profile, no interactive desktop for CLI tools. GUI apps
  (x64dbg) only run in the autologon console session.

## 1. Dynamic detonation (primary use case)

Two equivalent entry points. Both write `logs/<sha>/dynamic/` (+ `META.json`).

### Option A — orchestrator `--mode ssh` (recommended)

Run **on the caller** host. The orchestrator scps the sample
to Flare, runs the job remotely, pulls `artifacts.zip` back and unzips it.

Caller-side prerequisites:
- `orchestrator.py` present (copy from WinRE `winre/`, or `git clone` WinRE)
- A session resolvable by `load_session(sha)`: either the sibling pipeline's
  session library on `sys.path`, or `SESSIONS_DIR/<sha>.json` (override via
  `REVENG_SESSIONS_DIR`) containing `{"sample_path": "<local path>"}` — the
  sample **must exist locally**; it is scp'd to Flare as `C:\samples\<sha>\sample.exe`
- Env: `FLARE_HOST`, `FLARE_USER`, `FLARE_SSH_KEY`, `FLARE_SSH_PORT`
  (defaults suit the reference lab; override per deployment)
- Output lands in `LOGS_DIR/<sha>/dynamic/` (override via `REVENG_LOGS_DIR`)

```bash
# on the caller host
export FLARE_HOST=<FLARE_HOST> FLARE_USER=<FLARE_USER>
export FLARE_SSH_KEY=$KEY
export REVENG_LOGS_DIR=/opt/samples/logs
export REVENG_SESSIONS_DIR=/opt/samples/sessions
python3 winre/orchestrator.py <sha256> --mode ssh --max-seconds 60
python3 winre/orchestrator.py <sha256> --mode ssh --max-seconds 60 --pesieve
python3 winre/orchestrator.py <sha256> --mode ssh --dry-run   # plan only
```

- Exit `0` = `ok:true` or `skipped:true`; exit `1` = failed (see `META.json:error`).
- SSH time budget = `max_seconds + 300` (FakeNet/Procmon/CSV export overhead).
- `--no-deploy` skips re-SCP of job scripts (use when Flare already has them).
- Gating: `REVENG_DYNAMIC_SKIP=1` → writes skipped META, exit 0, no detonation.
  Documents (`pdf`/`ole`/`ooxml`) auto-skip (no detonation; doc triage instead).

### Option B — direct job (caller drives each step)

```bash
# 1. upload sample
scp -i $KEY sample.exe <FLARE_USER>@<FLARE_HOST>:C:/samples/<sha>/sample.exe
# 2. run the job (writes C:\samples\<sha>\out\* + artifacts.zip on Flare)
ssh -i $KEY <FLARE_USER>@<FLARE_HOST> \
  "powershell -NoProfile -ExecutionPolicy Bypass -File C:/WinRE/winre/flare_dynamic_job.ps1 \
   -Sha256 <sha> -SamplePath C:/samples/<sha>/sample.exe -MaxSeconds 60 [-EnablePeSieve]"
# 3. pull artifacts
scp -i $KEY <FLARE_USER>@<FLARE_HOST>:C:/samples/<sha>/artifacts.zip ./logs/<sha>/dynamic/
```

## 2. Artifact contract (`logs/<sha>/dynamic/`)

Written by Flare, read-only for callers. Canonical files (see `META.json:artifacts`
for the per-run index):

| File | Content |
|---|---|
| `META.json` | `ok`, `skipped`, `error`, `frida_events`, `yara_lock`, `snapshot_restore_required:true`, `verdict_policy.static_yara_wins:true` |
| `META.job.json` | per-job params as run on Flare |
| `frida_trace.json[l]` | API trace (Frida 17+) |
| `frida_summary.json` | top APIs, decoded paths |
| `procmon.csv` + `procmon_summary.json` | Sysinternals Procmon capture + summary |
| `network.json` + `network_intel.json` | FakeNet capture + tshark enrichment |
| `process_snapshot.json` | pre/post process diff |
| `memory/` | pe-sieve / hollows_hunter dumps (only with `--pesieve`) |
| `ANALYST-NEXT.md` + `analyst_next.json` | human next steps |
| `malcat-triage.json` | fast Malcat triage (if licensed on Flare) |

**Verdict policy:** `static_yara_wins` — dynamic corroborates, never clears
`CADRE_*` YARA. `load_dynamic_pack()` returns `None` when absent; callers must
treat missing dynamic as "no data", never as benign.

**Snapshot obligation:** every `META.json` from a real run has
`"snapshot_restore_required": true`. The operator restores the FlareVM clean
snapshot after pulling artifacts. No exceptions.

## 3. Static SQL over SSH

```bash
# Ghidra (headless + post-script; ~14s; SQL via env var, never bare argv)
ssh -i $KEY <FLARE_USER>@<FLARE_HOST> \
  "C:\Python313\python.exe C:\WinRE\tools\flare_ghidra_sql.py query '@funcs' --file C:\samples\<sha>.exe --json"
# IDA (auto-creates .i64 on first run via idat -A; ~4min cold, ~14s cached)
ssh -i $KEY <FLARE_USER>@<FLARE_HOST> \
  "C:\Python313\python.exe C:\WinRE\tools\flarevm_ida_query.py C:\samples\<sha>.exe.i64 'SELECT ...' --json"
# Malcat triage
ssh -i $KEY <FLARE_USER>@<FLARE_HOST> \
  "C:\Python313\python.exe C:\WinRE\tools\malcat_win.py C:\samples\<sha>.exe --profile triage --json"
# Unified health
ssh -i $KEY <FLARE_USER>@<FLARE_HOST> \
  "C:\Python313\python.exe C:\WinRE\tools\flarevm_toolset.py health"
```

Notes:
- Ghidra SQL **must** go through `flare_ghidra_sql.py` (it passes SQL via
  `GHIDRA_SQL_QUERY` env; bare `-postScript` argv mangles `(`, `*`, `FROM`).
- `analyzeHeadless.bat` must be invoked via Python `subprocess.run` arg array —
  never PowerShell `Start-Process`/`cmd /c` (breaks quoting).
- IDA one-shot `-q` hangs on this idasql build for some queries; if a query
  stalls, use the HTTP server path or treat as unavailable (fail-open).
- Set `GHIDRA_HEADLESS_MAXMEM=8G` on Flare for sane headless times (16GB host).

## 4. MCP over HTTP (cross-VM reachability)

| Server | Port | Bind | Reachable from caller VM? |
|---|---|---|---|
| x64dbg-MCP | 9094 | `0.0.0.0` | **Yes, direct** |
| windbg_bridge | 9096 | `0.0.0.0` | **Yes, direct** |
| idasql_server | 19300 | `127.0.0.1` | No — SSH-exec CLI or `ssh -L` tunnel |
| ghidra serve | 19301 | `127.0.0.1` | No — SSH-exec CLI or `ssh -L` tunnel |
| malcat serve | 9009 | `127.0.0.1` | No — SSH-exec CLI or `ssh -L` tunnel |
| mcp-windbg | 9097 | `127.0.0.1` | No — SSH-exec CLI or `ssh -L` tunnel |

Rule: **SSH-exec CLIs are the primary contract; direct HTTP only for x64dbg.**
Tunnel example: `ssh -L 19300:127.0.0.1:19300 -i $KEY <FLARE_USER>@<FLARE_HOST>`.

**Servers are not always up.** Nothing listens after a fresh boot until the
Startup launcher fires (autologon) or an operator runs
`winre\mcp\start_servers.ps1` on the console. x64dbg specifically needs the
console session (GUI app); use `winre/mcp/x64dbg_manager.py::ensure_mcp()`
from the caller to bring it up on demand, or start it first:
`powershell -File C:\WinRE\winre\mcp\start_servers.ps1`.

## 5. Troubleshooting for callers

| Symptom | Cause / fix |
|---|---|
| `session load failed` | no `SESSIONS_DIR/<sha>.json` or bad `sample_path`; check env overrides |
| `sample missing` | sample not present on the **caller** (ssh mode scps it up) |
| `job_timeout` / SSH timeout | raise `--max-seconds`; budget is `max_seconds+300`; check hung tools via `taskkill` block |
| `GhidraSql.java did not emit JSON` | usually a bad SQL string; verify against canonical `@funcs/@imports/@strings` first |
| idasql query hangs | known flakiness on this build; retry once, else fail open and rely on Ghidra |
| `tools/list` refused on :9094/9096 | MCP not running — start via `start_servers.ps1`, then retry |
| `FROM was unexpected at this time` | SQL passed as bare argv to a `.bat` — always go through the wrappers |
| `META.ok=false` with empty error | check `META.job.json` + `job.log` in the pack; then `frida.stderr.txt` |
| Slow first Ghidra run | JVM cold start + `LibGhidraHost` absent (fallback walker used); set heap to 8G |

## References

- `docs/DYNAMIC-ORCHESTRATOR.md` (job internals), `docs/PIPELINE.md` (workflow)
- Code: `winre/orchestrator.py --help`, `winre/mcp/x64dbg_manager.py`,
  `winre/agentic.py::_run_remote_py` (base64-arg pattern)
