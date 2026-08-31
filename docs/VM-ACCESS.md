# VM Access — FlareVM + Remnux

> **For the WinRE agent.** Lab-net only (`192.168.77.0/24`). Do not expose to internet. Snapshot before detonation.

## 1. Hosts

| Alias | IP | OS | Purpose | Repo |
|-------|----|----|---------|------|
| FlareVM | `192.168.77.42` | Windows 10 22H2 + Flare-VM (Christensen) | This repo — IDA/BN/Ghidra/x64dbg/WinDbg/Frida/Procmon/FakeNet/Malcat/PE-sieve | `CADRE-Platform/WinRE` |
| Remnux | `192.168.77.41` | Ubuntu Remnux (LibGhidraHost `v0.0.5`, ghidrasql `v0.0.4`) | Sister lab — static headless + LLM, logs share | `CADRE-Platform/RevEng` |
| Laptop GPU | `192.168.77.1:8000` | Windows | bge-m3/Qwen3 `reranker_server.py` (FastAPI `/embed` + `/rerank`) | `unified service` |

Hypervisor: VMware Workstation (host `192.168.77.1`). VMs are bridged/host-only — `192.168.77.x` reachable from host + each other. No public IP.

## 2. SSH — primary transport

### FlareVM (`192.168.77.42`)

```powershell
# From host (PowerShell) — same key as Remnux, reuse remnux-lab-key
ssh -i C:\Users\Ganro\.ssh\remnux-lab-key flare@192.168.77.42
# or if user is FLARE-VM:
ssh -i C:\Users\Ganro\.ssh\remnux-lab-key FLARE-VM@192.168.77.42

# If OpenSSH not yet enabled on Flare (one-time, on Flare):
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service -Name sshd -StartupType Automatic
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
# then append host pubkey to C:\ProgramData\ssh\administrators_authorized_keys
# (ACL: icacls administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F")
```

Flare SSH user is whatever was created at Flare install — typically `FLARE-VM` or `flare`. If login fails, check `C:\ProgramData\ssh\sshd_config` (`PasswordAuthentication yes` for bootstrap, then key-only).

### Remnux (`192.168.77.41`) — for artifact share reference

```powershell
ssh -i C:\Users\Ganro\.ssh\remnux-lab-key remnux@192.168.77.41
# deployed scripts: /opt/scripts/{v2_lib.py,quick_scan_v2.py,deep_dive_agentic.py,publish_report_v2.py,audit_pipeline.py}
# samples: /opt/samples/corpus/<sha>/logs/<sha>/{intake,quick,deep,publish,dynamic}
# secrets: /opt/cadre-v3-tools/llm.env (StepFun step-3.7-flash) + /opt/secrets/cadre.env
```

### PowerShell quoting pitfall

PowerShell mangles `python -c "import ..."` — write check scripts to `C:\Users\Ganro\AppData\Local\Temp\opencode\check.py` on host and `scp` to `/tmp` on VM (`RevEng AGENTS.md` rigor). Always `Test-Path -LiteralPath <parent>` before `New-Item`.

## 3. HTTP / MCP

| Service | URL | Bind | Notes |
|---------|-----|------|-------|
| x64dbg-MCP x64 | `http://192.168.77.42:9094/` | `0.0.0.0:9094` | `integrations/x64dbg-mcp-server-main` Zig plugin |
| x64dbg-MCP x32 | `http://192.168.77.42:9095/` | `0.0.0.0:9095` | same |
| WinDbg-MCP (planned) | `http://192.168.77.42:9096/` | `0.0.0.0:9096` | `winre/mcp/windbg_bridge.py` |
| idasql HTTP | `http://192.168.77.42:19300/query` | `127.0.0.1:19300` | `winre/idasql_server.py` |
| ghidra SQL HTTP | `http://192.168.77.42:19301/query` | `127.0.0.1:19301` | `tools/flare_ghidra_sql.py --serve` |
| RAG (laptop) | `http://192.168.77.1:8000/{embed,rerank}` | `0.0.0.0:8000` | not on Flare |

MCP curl (same on host or Remnux):

```powershell
curl http://192.168.77.42:9094/ -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
curl -X POST http://192.168.77.42:9094/ -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"GetDebugState","arguments":{}}}'
```

MCP client config (Claude Code `.mcp.json`):

```json
{"mcpServers": {"x64dbg": {"type": "http", "url": "http://192.168.77.42:9094/"}}}
```

## 4. SMB / artifact share

```powershell
# Flare → Remnux (flare_dynamic_job.ps1 final step)
net use Z: \\192.168.77.41\opt /user:remnux
xcopy /E C:\WinRE\logs\<sha>\dynamic Z:\samples\corpus\<sha>\logs\<sha>\dynamic\

# host → both VMs
scp -i C:\Users\Ganro\.ssh\remnux-lab-key C:\samples\foo.exe flare@192.168.77.42:C:/samples/foo.exe
scp -i C:\Users\Ganro\.ssh\remnux-lab-key C:\samples\foo.exe remnux@192.168.77.41:/opt/samples/corpus/foo.exe
```

## 5. Tool paths on Flare (verify via `docs/TOOL-INVENTORY.md`)

| Tool | Flare path | Version |
|------|-----------|---------|
| IDA Pro | `C:\Program Files\IDA Professional 9.3\idat.exe` + `idasql.exe` | 9.3 / idasql `0.0.17` |
| BN | `C:\Users\FLARE-VM\AppData\Local\Programs\Vector35\BinaryNinja\` | 5.1.8104 |
| Ghidra | `C:\tools\ghidra_12.2_PUBLIC\support\analyzeHeadless.bat` | 12.2 (detect `GHIDRA_HOME`) |
| x64dbg | `C:\tools\x64dbg\release\x64\x64dbg.exe` | latest Flare |
| WinDbg | `C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe` | 10.0.22621 |
| Malcat | `C:\tools\malcat\malcat.exe` | license `AppData\Roaming\Malcat\license.dat` |
| Procmon | `C:\tools\sysinternals\Procmon64.exe` | Sysinternals |
| FakeNet-NG | `C:\tools\fakenet\fakenet3.5\fakenet.exe` | 3.5 |
| PE-sieve | `C:\tools\pe-sieve\pe-sieve64.exe` | 0.3.x |
| Frida | `C:\Python313\python.exe` + `pip show frida` | 17.15.3 |

## 6. Snapshots (mandatory)

```powershell
# VMware Workstation host
Get-VM FlareVM | Checkpoint-VM -SnapshotName "clean-2026-08-31"
# Hyper-V host
Checkpoint-VM -Name FlareVM -SnapshotName "clean-2026-08-31"
# restore after every detonation
Restore-VMSnapshot -Name clean-2026-08-31 -Confirm:$false
# record in Tools/v6_deploy/V6.2/FLARE-HYGIENE-LOG.md
```

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ssh: Permission denied (publickey)` | `icacls administrators_authorized_keys` ACL wrong, or key not in `C:\ProgramData\ssh\administrators_authorized_keys` + `C:\Users\FLARE-VM\.ssh\authorized_keys` |
| `curl 9094: connection refused` | x64dbg not running or plugin not in `C:\tools\x64dbg\x64\plugins\` — restart x64dbg, check log pane `MCP server listening` |
| `idasql: command not found` | `C:\Program Files\IDA Professional 9.3\` not in `PATH` — use full path |
| `analyzeHeadless.bat: not found` | set `GHIDRA_HOME` or `dir C:\tools\ghidra*` |
| `frida: not found` | `C:\Python313\python.exe -m pip install frida frida-tools` |

## 8. Secrets

- Never commit `C:\WinRE\.env` (`MALCAT_KEY`, `STEPFUN_API_KEY`).
- Remnux `/opt/cadre-v3-tools/llm.env` (`step-3.7-flash`, `REVENG_LLM_*`) not copied to Flare — Flare LLM calls go via Remnux `deep_dive_agentic` HTTP.
- Keep this file in private repo only (`CADRE-Platform/WinRE` private).
