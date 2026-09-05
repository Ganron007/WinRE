#Requires -Version 5.1
<#
.SYNOPSIS
    provision_tools.ps1 - download the REQUIRED free tools on the HOST and
    stage them to the FlareVM (which is air-gapped and cannot fetch).

.DESCRIPTION
    The FlareVM is offline by design. The internet-connected HOST downloads
    the required free tools and scps them to C:\Tools-staged\ on the VM;
    install\setup-flarevm.ps1 (run on the VM) installs/verifies from there.

    Staged:
      - Ghidra release zip          -> C:\Tools-staged\ghidra_<ver>.zip
      - x64dbg snapshot zip         -> C:\Tools-staged\x64dbg.zip
      - Zig toolchain zip           -> C:\Tools-staged\zig.zip (MCP plugin build)
      - pe-sieve + hollows_hunter   -> C:\Tools-staged\ (if choco missing on VM)

    Downloads go to <repo>\dist\provision\ on the host first (gitignored),
    so re-runs skip completed downloads. URLs are pinned to release pages
    of each project; if a URL 404s the script tells you which one to fetch
    manually - nothing is fatal.

    Usage (host):
      powershell -ExecutionPolicy Bypass -File ops\provision_tools.ps1 [-Skip existing]
#>

param(
    [string]$FlareHost = $env:FLARE_HOST,
    [string]$User = $env:FLARE_USER,
    [string]$SshKey = $env:FLARE_SSH_KEY
)

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $repo "dist\provision"
New-Item -ItemType Directory -Force -Path $stage | Out-Null

function Get-File([string]$url, [string]$out) {
    if (Test-Path $out) { Write-Host "  [SKIP] $(Split-Path $out -Leaf) (exists)" -ForegroundColor DarkGray; return $true }
    try {
        Write-Host "  [GET ] $(Split-Path $out -Leaf) ..."
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 600
        return (Test-Path $out)
    } catch {
        Write-Host "  [FAIL] $url -> $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

Write-Host "=== Provision required free tools (host -> VM staging) ===" -ForegroundColor Cyan

# Ghidra: latest release zip from ghidra-sre GitHub
$ghidraVer = "11.3.2"
$ghidraOk = Get-File "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${ghidraVer}_build/ghidra_${ghidraVer}_PUBLIC_20250415.zip" `
    (Join-Path $stage "ghidra_${ghidraVer}_PUBLIC.zip")

# x64dbg: latest snapshot zip
$x64Ok = Get-File "https://github.com/x64dbg/x64dbg/releases/download/snapshot/x64dbg.zip" `
    (Join-Path $stage "x64dbg.zip")

# Zig (for the x64dbg MCP plugin build)
$zigVer = "0.14.1"
$zigOk = Get-File "https://ziglang.org/download/${zigVer}/zig-windows-x86_64-${zigVer}.zip" `
    (Join-Path $stage "zig-${zigVer}.zip")

# pe-sieve / hollows_hunter (direct release binaries)
$peOk = Get-File "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe_sieve64.exe" `
    (Join-Path $stage "pe_sieve64.exe")
$hhOk = Get-File "https://github.com/hasherezade/hollows_hunter/releases/latest/download/hollows_hunter64.exe" `
    (Join-Path $stage "hollows_hunter64.exe")

Write-Host ""
Write-Host "--- Staging to VM (C:\Tools-staged) ---" -ForegroundColor Cyan
if (-not $FlareHost) { Write-Host "[WARN] FLARE_HOST not set - staging locally only ($stage)" -ForegroundColor Yellow }
else {
    $scpArgs = @("-i", $SshKey, "-o", "StrictHostKeyChecking=no")
    ssh @scpArgs "${User}@${FlareHost}" "cmd /c if not exist C:\Tools-staged mkdir C:\Tools-staged" 2>$null | Out-Null
    Get-ChildItem $stage -File | ForEach-Object {
        scp @scpArgs $_.FullName "${User}@${FlareHost}:C:/Tools-staged/" 2>$null
        Write-Host "  staged: $($_.Name)"
    }
}

Write-Host ""
Write-Host "=== NEXT STEPS (on the VM) ===" -ForegroundColor Cyan
Write-Host "  1. Unzip C:\Tools-staged\ghidra_*.zip      -> C:\Tools\ghidra_<ver>"
Write-Host "  2. Unzip C:\Tools-staged\x64dbg.zip        -> C:\Tools\x64dbg"
Write-Host "  3. Unzip C:\Tools-staged\zig-*.zip         -> C:\Tools\zig (add to PATH)"
Write-Host "  4. pe-sieve64.exe / hollows_hunter64.exe   -> chocolatey bin / C:\Tools\hollows_hunter"
Write-Host "     (or let the FlareVM base installer place them)"
Write-Host "  5. Run: powershell -File C:\WinRE\install\setup-flarevm.ps1"
Write-Host "     (builds the MCP plugin with the staged zig, verifies everything)"
Write-Host ""
$failed = @()
if (-not $ghidraOk) { $failed += "Ghidra" }
if (-not $x64Ok) { $failed += "x64dbg" }
if (-not $zigOk) { $failed += "zig" }
if (-not $peOk) { $failed += "pe-sieve" }
if (-not $hhOk) { $failed += "hollows_hunter" }
if ($failed) { Write-Host "DOWNLOAD FAILURES: $($failed -join ', ') - fetch manually from their release pages" -ForegroundColor Yellow; exit 1 }
Write-Host "All downloads staged OK." -ForegroundColor Green
