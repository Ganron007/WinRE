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

$bootTask = "WinRE-MCP-Boot"

if ($Remove) {
    if (Test-Path $launcher) { Remove-Item $launcher -Force; Write-Host "removed $launcher" -ForegroundColor Green }
    else { Write-Host "no autostart entry present" -ForegroundColor Yellow }
    if (Get-ScheduledTask -TaskName $bootTask -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $bootTask -Confirm:$false
        Write-Host "removed scheduled task $bootTask" -ForegroundColor Green
    }
    exit 0
}

if (-not (Test-Path $script)) { Write-Error "start_servers.ps1 missing: $script"; exit 2 }
if (-not (Test-Path $startup)) { New-Item -ItemType Directory -Path $startup -Force | Out-Null }

# .cmd so it runs hidden at logon without a console flash policy fuss.
# `start ""` DETACHES powershell immediately: cmd.exe exits in milliseconds,
# so a fast logoff/shutdown can never catch the launcher mid-start (that
# produced 'cmd.exe - Application Error 0xc0000142' popups at shutdown).
$cmd = "@echo off`r`nrem WinRE MCP autostart (detached, boot-safe, idempotent)`r`nstart `"`" /min powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`" -NoX64dbg`r`n"
Set-Content -Path $launcher -Value $cmd -Encoding ASCII
Write-Host "installed: $launcher" -ForegroundColor Green

# verify the scheduled-task WinDbg entry from earlier is redundant; remove it
$task = Get-ScheduledTask -TaskName "WinRE-MCP-WinDbg" -ErrorAction SilentlyContinue
if ($task) { Unregister-ScheduledTask -TaskName "WinRE-MCP-WinDbg" -Confirm:$false; Write-Host "removed old WinRE-MCP-WinDbg task (superseded by startup launcher)" -ForegroundColor Yellow }

# --- boot-safe scheduled task -----------------------------------------------
# The Startup-folder launcher only fires on an INTERACTIVE LOGON. This box has
# no AutoAdminLogon (verified 2026-09-20) - i.e. after a reboot nobody logs in
# and MCP never came up (found during the boot-autostart proof). Register an
# AtStartup task running as SYSTEM so :9009/:9097 are up after ANY reboot,
# independent of logons. Idempotent start_servers.ps1 makes a later user logon
# a no-op.
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument ("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden " +
               "-File `"$script`" -NoX64dbg")
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $bootTask -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "installed scheduled task: $bootTask (AtStartup, SYSTEM)" -ForegroundColor Green

# --- start NOW, not only on the next boot -----------------------------------
# An AtStartup trigger cannot fire for a boot that already happened, so after
# a snapshot revert the task exists but :9009/:9097 stay dead until someone
# reboots or starts the servers by hand (found 2026-09-27: the post-revert
# deployment finished "0 FAIL" yet left MCP down, so smoke_flare.py failed
# 2/9). Triggering the task we just registered runs the SAME launcher in the
# SAME SYSTEM context as a real boot, and start_servers.ps1 is idempotent
# ("already up on :port - skip"), so this is safe to repeat.
$ports = @(9009, 9097)
$up = @($ports | Where-Object {
    Get-NetTCPConnection -State Listen -LocalPort $_ -ErrorAction SilentlyContinue
})
if ($up.Count -eq $ports.Count) {
    Write-Host "MCP already listening on :$($up -join ', :') - no start needed" -ForegroundColor DarkGray
} else {
    Start-ScheduledTask -TaskName $bootTask
    Write-Host "triggered $bootTask (servers starting as SYSTEM)" -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 3
        $up = @($ports | Where-Object {
            Get-NetTCPConnection -State Listen -LocalPort $_ -ErrorAction SilentlyContinue
        })
    } while ($up.Count -lt $ports.Count -and (Get-Date) -lt $deadline)
    if ($up.Count -eq $ports.Count) {
        Write-Host "MCP up now: :$($up -join ' :')" -ForegroundColor Green
    } else {
        $missing = @($ports | Where-Object { $up -notcontains $_ })
        Write-Warning "MCP not up after 60s (missing :$($missing -join ' :')). Servers start on next boot; inspect logs\mcp\."
    }
}

Write-Host "MCP autostart installed: boot task + logon launcher -> :9009 :9097 (x64dbg :9094 on demand)." -ForegroundColor Cyan
