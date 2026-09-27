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
    [string]$RemoteRoot = $env:FLARE_REMOTE_ROOT,
    # Remove remote files inside the mirrored source trees that no longer exist
    # on the host. OFF by default: the sync is additive so a re-run can never
    # destroy something a user staged by hand. Turn it on for a true mirror
    # (after a revert, or when a file was renamed/removed upstream) - and read
    # the printed manifest first.
    [switch]$Prune,
    # Report-only for -Prune: list what would be deleted, delete nothing.
    [switch]$PruneDryRun
)

$ErrorActionPreference = "Stop"
# Fallback: parse the repo .env (host vars live there, not in the process env)
$Repo0 = Split-Path -Parent $PSScriptRoot
$DotEnv = Join-Path $Repo0 ".env"
$dotenvVars = @{}
if (Test-Path $DotEnv) {
    foreach ($ln in Get-Content $DotEnv) {
        if ($ln -match '^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+?)\s*$') {
            $dotenvVars[$Matches[1]] = $Matches[2].Trim('"')
        }
    }
}
if (-not $FlareHost) { $FlareHost = $env:FLARE_HOST; if (-not $FlareHost) { $FlareHost = $dotenvVars["FLARE_HOST"] } }
if (-not $User) { $User = $env:FLARE_USER; if (-not $User) { $User = $dotenvVars["FLARE_USER"] }; if (-not $User) { $User = "FLARE-VM" } }
if (-not $SshKey) { $SshKey = $env:FLARE_SSH_KEY; if (-not $SshKey) { $SshKey = $dotenvVars["FLARE_SSH_KEY"] } }
if (-not $FlareHost -or -not $SshKey) {
    Die "FLARE_HOST / FLARE_SSH_KEY not set (neither env nor .env)"
}
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

# scp's glob does NOT pick up dotfiles on Windows, so `.env.template` and
# `.gitignore` were silently left stale on the VM (found 2026-09-27: the
# template still lacked the LLM role pins that setup-flarevm.ps1 treats as
# "present, nothing to do"). Copy them explicitly by name. `.env` is never
# shipped - the VM must hold no secrets.
$dotStaged = Get-ChildItem -LiteralPath $Staging -Force -File |
    Where-Object { $_.Name.StartsWith(".") -and $_.Name -ne ".env" }
if ($dotStaged) {
    Step ("scp dotfiles -> " + (($dotStaged.Name) -join ", "))
    foreach ($f in $dotStaged) {
        scp -i $SshKey -o StrictHostKeyChecking=no -o ConnectTimeout=15 $f.FullName "$dest" 2>&1 |
            ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) { Die "scp dotfile $($f.Name) failed rc=$LASTEXITCODE" }
    }
}

# --- prune: drop remote files that no longer exist upstream ------------------
# Only the mirrored SOURCE trees are ever considered. Runtime/state on the VM
# (logs, cache, samples, sessions, lock, local-runs, integrations, .env,
# .clean_snapshot, vm_clock.json) is out of scope by construction, so -Prune
# can never touch evidence, credentials or the snapshot marker.
if ($Prune -or $PruneDryRun) {
    Step "prune: remote files with no upstream counterpart"
    $rel = Get-ChildItem -LiteralPath $Staging -Recurse -File -Force |
        ForEach-Object { $_.FullName.Substring($Staging.Length + 1).Replace('\','/') }
    $stagedList = ($rel -join "`n")
    $pruneScript = @"
`$ErrorActionPreference='SilentlyContinue'
`$root='$($RemoteRoot.Replace('\','\\'))'
`$staged=@{}
@'
$stagedList
'@ -split "`n" | Where-Object { `$_ } | ForEach-Object { `$staged[`$_] = 1 }
`$srcDirs=@('winre','tools','ops','install','docs','tests','assets')
`$cand=@()
foreach (`$d in `$srcDirs) { `$p=Join-Path `$root `$d
  if (Test-Path `$p) {
    Get-ChildItem `$p -Recurse -File -Force | ForEach-Object {
      `$r=`$_.FullName.Substring(`$root.Length+1).Replace('\','/')
      if ((`$_.Name -eq '__init__.py') -or (`$_.Extension -eq '.pyc')) { return }
      if (-not `$staged.ContainsKey(`$r)) { `$cand += `$r }
    }
  }
}
if (`$cand.Count -eq 0) { 'PRUNE_NONE'; exit 0 }
`$cand | Sort-Object | ForEach-Object { 'PRUNE ' + `$_ }
"@
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($pruneScript))
    $plist = ssh -i $SshKey -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=yes "$User@$FlareHost" "powershell -NoProfile -EncodedCommand $enc" 2>&1 | Out-String
    $lines = @($plist -split "`r?`n" | Where-Object { $_.Trim() -like "PRUNE*" })
    if (($plist -match "PRUNE_NONE") -or $lines.Count -eq 0) {
        Step "prune: nothing to remove (remote tree matches upstream)"
    } else {
        foreach ($l in $lines) { Write-Host ("  " + $l.Trim()) -ForegroundColor Yellow }
        if ($PruneDryRun) {
            Step "prune dry-run: $($lines.Count) file(s) WOULD be removed (re-run without -PruneDryRun to apply)"
        } else {
            $targets = @($lines | ForEach-Object { $_.Trim() -replace '^PRUNE\s+','' })
            $del = @"
`$ErrorActionPreference='SilentlyContinue'
@'
$($targets -join "`n")
'@ -split "`n" | Where-Object { `$_ } | ForEach-Object {
  `$f=Join-Path '$($RemoteRoot.Replace('\','\\'))' `$_
  if (Test-Path `$f) { Remove-Item -LiteralPath `$f -Force; 'REMOVED ' + `$_ } else { 'ABSENT ' + `$_ }
}
"@
            $denc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($del))
            $dout = ssh -i $SshKey -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=yes "$User@$FlareHost" "powershell -NoProfile -EncodedCommand $denc" 2>&1 | Out-String
            $removed = @($dout -split "`r?`n" | Where-Object { $_.Trim() -like "REMOVED*" })
            if ($removed.Count -eq 0) {
                Warn "prune: 0 files removed (targets may be locked - rerun or reboot)"
            } else {
                Step "prune: removed $($removed.Count) stale file(s)"
            }
        }
    }
}

Step "remote verify"
$probe = ssh -i $SshKey -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=yes "$User@$FlareHost" "powershell -NoProfile -Command (Test-Path 'C:\WinRE\winre\orchestrator.py')" 2>&1
if ("$probe".Trim() -eq "True") { Step "DEPLOY_OK" } else { Write-Output $probe; Die "remote verify failed" }

Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue
Step "DONE"
exit 0


