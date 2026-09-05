#Requires -Version 5.1
<#
.SYNOPSIS
    Sync WinRE repo to FlareVM C:\WinRE over SSH (scp). Internal tool - gitignored tree.

.DESCRIPTION
    Deploys the local repo (excluding __pycache__, logs, .git) to the Flare VM so the
    pipeline runs from C:\WinRE as documented. Run from the host (any OS with scp/ssh).

    Usage:
      powershell -ExecutionPolicy Bypass -File ops\sync_to_flare.ps1
      $env:FLARE_HOST / FLARE_USER / FLARE_SSH_KEY  to override defaults
#>
param(
    [string]$FlareHost = $env:FLARE_HOST,
    [string]$User = $env:FLARE_USER,
    [string]$SshKey  = $env:FLARE_SSH_KEY,
    [string]$RemoteRoot = $env:FLARE_REMOTE_ROOT
)

$ErrorActionPreference = "Stop"
if (-not $FlareHost) { $FlareHost = $env:FLARE_HOST }
if (-not $User) { $User = "FLARE-VM" }
if (-not $SshKey)  { $SshKey  = $env:FLARE_SSH_KEY }
if (-not $RemoteRoot) { $RemoteRoot = "C:\WinRE" }

$Repo = Split-Path -Parent $PSScriptRoot
$Staging = Join-Path $env:TEMP "winre-sync-$PID"
$Excludes = @(".git","__pycache__","logs","cache","local-runs","dist",".env","docs\internal","internal")

function Die([string]$m) { Write-Error "[sync_to_flare] FATAL: $m"; exit 2 }
function Step([string]$m) { Write-Host "[sync_to_flare] $m" }

Step "staging repo -> $Staging"
New-Item -ItemType Directory -Force -Path $Staging | Out-Null
Get-ChildItem -LiteralPath $Repo -Force | Where-Object { $_.Name -notin $Excludes } | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Staging $_.Name) -Recurse -Force
}
# strip any pycache left inside staged tree
Get-ChildItem -LiteralPath $Staging -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$dest = "$User@$FlareHost`:$($RemoteRoot.Replace('\','/'))"
Step "scp -> $dest"
$null = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "winre-sync-tmp")
scp -i $SshKey -o StrictHostKeyChecking=no -o ConnectTimeout=15 -r $Staging\* "$dest" 2>&1 | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) { Die "scp failed rc=$LASTEXITCODE" }

Step "remote verify"
$probe = ssh -i $SshKey -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=yes "$User@$FlareHost" "powershell -NoProfile -Command (Test-Path 'C:\WinRE\winre\orchestrator.py')" 2>&1
if ("$probe".Trim() -eq "True") { Step "DEPLOY_OK" } else { Write-Output $probe; Die "remote verify failed" }

Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue
Step "DONE"
exit 0


