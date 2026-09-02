#Requires -Version 5.1
<#
.SYNOPSIS
    Start the WinRE UI console (control plane).

.DESCRIPTION
    Serves the dashboard + pipeline runner on the operator host. Drives the
    FlareVM execution plane through winre/remote_driver (SSH + HTTP MCP).

    Usage:
      powershell -ExecutionPolicy Bypass -File winre\ui\start_ui.ps1
      # options: -Port 5001 -Host 127.0.0.1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File winre\ui\start_ui.ps1 -Port 5001
#>
param(
    [int]$Port = 5001,
    [string]$HostAddr = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Repo
Write-Host "[winre-ui] starting on http://$HostAddr`:$Port  (ctrl+c to stop)" -ForegroundColor Cyan
python winre/ui/app.py --port $Port --host $HostAddr
