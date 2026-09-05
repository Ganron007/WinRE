#Requires -Version 5.1
<#
.SYNOPSIS
    install-host-status.ps1 - put a one-click "WinRE-Status" shortcut on the
    HOST desktop (control plane). Runs ops\winre-status.ps1 in a console
    window that stays open.

.DESCRIPTION
    Optional convenience. Idempotent: re-creates the shortcut each run.
    The shortcut targets powershell.exe with the repo script path baked in.
#>

$repo = Split-Path -Parent $PSScriptRoot
$desktop = [Environment]::GetFolderPath("Desktop")
$lnk = Join-Path $desktop "WinRE-Status.lnk"

$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnk)
$sc.TargetPath = "powershell.exe"
$sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$repo\ops\winre-status.ps1`""
$sc.WorkingDirectory = $repo
$sc.Description = "WinRE lab status: connectivity, MCP, snapshot gate, LLM"
$sc.Save()
Write-Host "[OK] shortcut -> $lnk" -ForegroundColor Green
