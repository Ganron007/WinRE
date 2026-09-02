#Requires -Version 5.1
<#
.SYNOPSIS
    Install WinRE MCP auto-start at boot (Startup folder → fires on autologon).

.DESCRIPTION
    The FlareVM auto-logs-in (AutoAdminLogon=1). Dropping a launcher into the
    Startup folder makes every logon start all MCP servers:
      - Malcat MCP :9009 · WinDbg MCP :9097 · x64dbg MCP :9094 (GUI)
    Idempotent start_servers.ps1 makes repeated logons harmless.

    Usage (run once on the FlareVM console or via SSH):
      powershell -ExecutionPolicy Bypass -File install\install_mcp_autostart.ps1
      powershell ... -Remove          # remove the autostart entry
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\WinRE\install\install_mcp_autostart.ps1
#>
param([switch]$Remove)

$ErrorActionPreference = "Stop"
$startup = [Environment]::GetFolderPath("Startup")
$launcher = Join-Path $startup "WinRE-MCP.cmd"
$script = "C:\WinRE\winre\mcp\start_servers.ps1"

if ($Remove) {
    if (Test-Path $launcher) { Remove-Item $launcher -Force; Write-Host "removed $launcher" -ForegroundColor Green }
    else { Write-Host "no autostart entry present" -ForegroundColor Yellow }
    exit 0
}

if (-not (Test-Path $script)) { Write-Error "start_servers.ps1 missing: $script"; exit 2 }
if (-not (Test-Path $startup)) { New-Item -ItemType Directory -Path $startup -Force | Out-Null }

# .cmd so it runs hidden-ish at logon without a console flash policy fuss
$cmd = "@echo off`r`nrem WinRE MCP autostart (boot-safe, idempotent)`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"$script`" -NoX64dbg`r`n"
Set-Content -Path $launcher -Value $cmd -Encoding ASCII
Write-Host "installed: $launcher" -ForegroundColor Green

# verify the scheduled-task WinDbg entry from earlier is redundant; remove it
$task = Get-ScheduledTask -TaskName "WinRE-MCP-WinDbg" -ErrorAction SilentlyContinue
if ($task) { Unregister-ScheduledTask -TaskName "WinRE-MCP-WinDbg" -Confirm:$false; Write-Host "removed old WinRE-MCP-WinDbg task (superseded by startup launcher)" -ForegroundColor Yellow }

Write-Host "MCP autostart installed. Reboot (autologon) will bring up :9009 :9097 :9094." -ForegroundColor Cyan
