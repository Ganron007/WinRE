#Requires -Version 5.1
<#
.SYNOPSIS
    reapply_after_revert.ps1 - restore the FlareVM to the current repo state
    after a snapshot revert (air-gap safe, no NAT required).

.DESCRIPTION
    A snapshot revert rolls the VM back to an older baseline. This script
    re-applies everything that lives outside the snapshot, in order:

      1. sync repo             -> C:\WinRE              (ops/sync_to_flare.ps1)
      2. stage integrations    -> C:\WinRE\integrations (gitignored, host-only)
      3. stage offline wheels  -> C:\Tools-staged\wheels (pip --no-index)
      4. restore rule sets     -> C:\Tools\{yara,capa}-rules (host backup)
      5. run setup-flarevm.ps1 on the VM (detects/fixes: pip deps, setuptools
         pin, IDA license shadowing, x64dbg plugin, autostart, marker)
      6. run verify-flarevm.ps1 (PASS/FAIL battery)

    Host-side prerequisites (all under internal\reapply\, gitignored):
      - wheels\   : setuptools<81 + pypdf (+ floss fallback)
      - rules\    : yara-rules\ + capa-rules\ backups pulled from the VM

    Post-steps NOT automated here (by design):
      - Re-stage samples from the RevAI box per
        internal\campaign\samples-manifest.json (samples never touch this host)
      - Confirm C:\WinRE\.env is absent (it must never exist on the VM)
      - Confirm C:\WinRE\.clean_snapshot, then take the NEW snapshot

    Usage (host):
      powershell -ExecutionPolicy Bypass -File ops\reapply_after_revert.ps1
      powershell -ExecutionPolicy Bypass -File ops\reapply_after_revert.ps1 -SkipSync
#>
param(
    [switch]$SkipSync
)

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot

# --- dotenv (FLARE_* live in .env on this host) ------------------------------
$dotenv = @{}
$dotenvPath = Join-Path $repo ".env"
if (Test-Path $dotenvPath) {
    foreach ($ln in Get-Content $dotenvPath) {
        if ($ln -match "^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+?)\s*$") {
            $dotenv[$Matches[1]] = $Matches[2].Trim('"')
        }
    }
}
$flareHost = if ($env:FLARE_HOST) { $env:FLARE_HOST } else { $dotenv["FLARE_HOST"] }
$flareUser = if ($env:FLARE_USER) { $env:FLARE_USER } else { $dotenv["FLARE_USER"] }
$flareKey  = if ($env:FLARE_SSH_KEY) { $env:FLARE_SSH_KEY } else { $dotenv["FLARE_SSH_KEY"] }
if (-not $flareHost -or -not $flareKey) {
    Write-Error "FLARE_HOST / FLARE_SSH_KEY not set (env or .env)"
    exit 2
}
$t = "$flareUser@$flareHost"
$sshOpts = @("-i", $flareKey, "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15")

function Invoke-VM([string]$script, [int]$timeoutSec = 300) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    return ssh @sshOpts $t "powershell -NoProfile -EncodedCommand $enc" 2>&1 | Out-String
}

function Get-File([string]$local, [string]$remoteDir) {
    if (-not (Test-Path $local)) { Write-Host "  [SKIP] $(Split-Path $local -Leaf) (not staged on host)"; return }
    Write-Host "  [SCP ] $(Split-Path $local -Leaf) -> $remoteDir"
    scp @sshOpts -r $local "${t}:$remoteDir" 2>&1 | Out-Null
}

Write-Host "=== WinRE re-apply after snapshot revert ===" -ForegroundColor Cyan

# --- 0. reachability ----------------------------------------------------------
Write-Host "`n--- 0. VM reachability ---"
$ping = Invoke-VM "echo REAPPLY-OK" 60
if ($ping -notmatch "REAPPLY-OK") {
    Write-Host "VM not reachable:" -ForegroundColor Red
    Write-Host $ping
    exit 1
}
Write-Host "  VM reachable."

# --- 1. sync repo -------------------------------------------------------------
Write-Host "`n--- 1. sync repo -> C:\WinRE ---"
if ($SkipSync) { Write-Host "  [SKIP] -SkipSync" }
else {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "sync_to_flare.ps1")
    if ($LASTEXITCODE -ne 0) { Write-Host "sync failed" -ForegroundColor Red; exit 1 }
}

# --- 2. integrations (gitignored; needed for the x64dbg MCP plugin) -----------
Write-Host "`n--- 2. stage integrations ---"
$integ = Join-Path $repo "integrations"
if (Test-Path $integ) { Get-File $integ "C:/WinRE/" }
else { Write-Host "  [SKIP] host integrations\ missing" }

# --- 3. offline wheels --------------------------------------------------------
Write-Host "`n--- 3. stage offline wheels -> C:\Tools-staged\wheels ---"
$wheels = Join-Path $repo "internal\reapply\wheels"
if (Test-Path $wheels) {
    Invoke-VM "New-Item -ItemType Directory -Force -Path C:\Tools-staged\wheels | Out-Null; 'ok'" 60 | Out-Null
    Get-ChildItem $wheels -File | ForEach-Object { Get-File $_.FullName "C:/Tools-staged/wheels/" }
} else { Write-Host "  [SKIP] internal\reapply\wheels missing" }

# --- 4. rule sets -------------------------------------------------------------
Write-Host "`n--- 4. restore rule sets -> C:\Tools ---"
$rules = Join-Path $repo "internal\reapply\rules"
foreach ($r in @("yara-rules", "capa-rules")) {
    $src = Join-Path $rules $r
    if (Test-Path $src) { Get-File $src "C:/Tools/" }
    else { Write-Host "  [SKIP] $r backup missing on host" }
}

# --- 5. setup on the VM -------------------------------------------------------
Write-Host "`n--- 5. setup-flarevm.ps1 (VM) ---"
$out = Invoke-VM "Set-Location C:\WinRE; & powershell -NoProfile -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1 2>&1 | Select-Object -Last 40" 1800
Write-Host $out

# --- 6. verify ----------------------------------------------------------------
Write-Host "`n--- 6. verify-flarevm.ps1 (VM) ---"
$verify = Invoke-VM "Set-Location C:\WinRE; & powershell -NoProfile -ExecutionPolicy Bypass -File C:\WinRE\install\verify-flarevm.ps1 2>&1" 600
Write-Host $verify

# --- 7. explicit checks + post-steps ------------------------------------------
Write-Host "`n--- 7. critical checks ---"
$checkScript = @'
$envPresent = Test-Path 'C:\WinRE\.env'
$marker = Test-Path 'C:\WinRE\.clean_snapshot'
$freeLic = @(Get-ChildItem (Join-Path $env:APPDATA 'Hex-Rays\IDA Pro') -Filter 'idafree*.hexlic' -ErrorAction SilentlyContinue).Count
$proLic = @(Get-ChildItem 'C:\Program Files\IDA Professional 9.3' -Filter 'idapro*.hexlic' -ErrorAction SilentlyContinue).Count
$setuptools = & 'C:\Python313\python.exe' -c 'import setuptools; print(setuptools.__version__)' 2>$null
"VM .env present: $envPresent  (must be False)"
"clean marker:    $marker"
"IDA pro/free:    $proLic/$freeLic  (free must be 0 after setup auto-fix)"
"setuptools:      $setuptools  (must be <81)"
'@
$checks = Invoke-VM $checkScript 120
Write-Host $checks

Write-Host @"

=== Re-apply done. Remaining operator steps ===
  1. Re-stage samples from the RevAI box per internal\campaign\samples-manifest.json
     (samples NEVER transit this host; VM path C:\samples\<neutral>.bin)
  2. The revert may have restored C:\WinRE\.env (it existed in the old snapshot).
     If 'VM .env present' above is True: delete it now, and ROTATE the key at
     the provider (it was exposed on a VM that detonated).
  3. Confirm 'clean marker: True', then take the NEW clean snapshot (bakes the
     marker), and only then delete the old snapshot.
"@ -ForegroundColor Cyan
