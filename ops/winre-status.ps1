#Requires -Version 5.1
<#
.SYNOPSIS
    winre-status.ps1 - ONE-RUN full lab status from the control plane (host).

.DESCRIPTION
    Host-tier verification battery. Combines:
      1. ops\smoke_flare.py   - 9-check PASS/FAIL (SSH, VM py_compile, layout,
                                samples dir, x64dbg :9094, Malcat bridge,
                                WinDbg port, gate probe, LLM)
      2. snapshot gate        - mode / marker / ledger / hypervisor
      3. guidance             - what to do about anything that is down

    Run from anywhere on the host:
      powershell -ExecutionPolicy Bypass -File <repo>\ops\winre-status.ps1
#>

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host ""
Write-Host "=== WinRE lab status (control plane) ===" -ForegroundColor Cyan
Write-Host "    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Write-Host ""
Write-Host "--- Connectivity / tools / MCP / gate (9 checks) ---" -ForegroundColor Cyan
& python "$repo\ops\smoke_flare.py"
$smoke = $LASTEXITCODE

Write-Host ""
Write-Host "--- Snapshot gate detail ---" -ForegroundColor Cyan
& python -m winre.snapshot_gate status

Write-Host ""
if ($smoke -eq 0) {
    Write-Host "=== LAB READY ===" -ForegroundColor Green
    Write-Host "  host can drive the VM: pipeline / UI / campaign can run."
} else {
    Write-Host "=== LAB DEGRADED - fix the FAIL rows above ===" -ForegroundColor Red
    Write-Host "  MCP down        -> VM console: C:\WinRE\winre\mcp\start_servers.ps1"
    Write-Host "                     (x64dbg: scheduled task WinRE-X64dbg-Once or on-demand)"
    Write-Host "  VM unreachable  -> boot the FlareVM, check host-only network"
    Write-Host "  VM dirty        -> restore the clean snapshot, then re-run this"
}
Write-Host ""
