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

# dotenv: FLARE_* live in .env on this host (params/env still win)
$dotenv = @{}
$dotenvPath = Join-Path $repo ".env"
if (Test-Path $dotenvPath) {
    foreach ($ln in Get-Content $dotenvPath) {
        if ($ln -match '^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+?)\s*$') { $dotenv[$Matches[1]] = $Matches[2].Trim('"') }
    }
}
if (-not $FlareHost) { $FlareHost = if ($env:FLARE_HOST) { $env:FLARE_HOST } else { $dotenv["FLARE_HOST"] } }
if (-not $User) { $User = if ($env:FLARE_USER) { $env:FLARE_USER } else { $dotenv["FLARE_USER"] } }
if (-not $SshKey) { $SshKey = if ($env:FLARE_SSH_KEY) { $env:FLARE_SSH_KEY } else { $dotenv["FLARE_SSH_KEY"] } }
if (-not $User) { $User = "FLARE-VM" }

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

# x64dbg: latest snapshot zip (asset name varies; try both)
$x64Ok = Get-File "https://github.com/x64dbg/x64dbg/releases/download/snapshot/x64dbg.zip" `
    (Join-Path $stage "x64dbg.zip")
if (-not $x64Ok) {
    $x64Ok = Get-File "https://github.com/x64dbg/x64dbg/releases/latest/download/x64dbg.zip" `
        (Join-Path $stage "x64dbg.zip")
}

# Zig (for the x64dbg MCP plugin build) - 0.14+ uses zig-<arch>-windows-<ver>.zip
$zigVer = "0.14.1"
$zigOk = Get-File "https://ziglang.org/download/${zigVer}/zig-x86_64-windows-${zigVer}.zip" `
    (Join-Path $stage "zig-${zigVer}.zip")
if (-not $zigOk) {
    $zigOk = Get-File "https://ziglang.org/download/${zigVer}/zig-windows-x86_64-${zigVer}.zip" `
        (Join-Path $stage "zig-${zigVer}.zip")
}

# pe-sieve / hollows_hunter (direct release binaries; asset name varies)
$peOk = Get-File "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe_sieve64.exe" `
    (Join-Path $stage "pe-sieve64.exe")
if (-not $peOk) {
    $peOk = Get-File "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe-sieve64.exe" `
        (Join-Path $stage "pe-sieve64.exe")
}
$hhOk = Get-File "https://github.com/hasherezade/hollows_hunter/releases/latest/download/hollows_hunter64.exe" `
    (Join-Path $stage "hollows_hunter64.exe")

# Additional free static tools (staged for the air-gapped VM):
#   - Detect It Easy (portable release zip: contains diec.exe)
$dieVer = "3.09"
$dieOk = Get-File "https://github.com/horsicq/Detect-It-Easy/releases/download/${dieVer}/die_win32_portable_${dieVer}.zip" `
    (Join-Path $stage "die_win32_portable_${dieVer}.zip")
#   - goresym (Go symbol recovery; only needed for Go samples)
$goresymOk = Get-File "https://github.com/mandiant/GoReSym/releases/latest/download/GoReSym.exe" `
    (Join-Path $stage "GoReSym.exe")
#   - scdbg (shellcode emulator; FlareVM base usually ships it)
$scdbgOk = Get-File "https://github.com/dzzie/SCDBG/releases/latest/download/scdbg.zip" `
    (Join-Path $stage "scdbg.zip")
#   - yara-x scanner (yr.exe; FlareVM base usually ships it)
$yaraOk = Get-File "https://github.com/VirusTotal/yara-x/releases/latest/download/yr-x86_64-pc-windows-msvc.zip" `
    (Join-Path $stage "yr-x86_64-pc-windows-msvc.zip")

# capa-rules (mandiant): capa's capability signatures
$capaRulesDir = Join-Path $stage "capa-rules"
if (-not (Test-Path (Join-Path $capaRulesDir ".git"))) {
    try {
        git clone --depth 1 https://github.com/mandiant/capa-rules $capaRulesDir 2>$null
        if (Test-Path (Join-Path $capaRulesDir ".git")) { Write-Host "  [OK] capa-rules staged" }
        else { Write-Host "  [WARN] capa-rules clone failed - fetch manually (mandiant/capa-rules)" -ForegroundColor Yellow }
    } catch { Write-Host "  [WARN] git not available - fetch capa-rules manually" -ForegroundColor Yellow }
}

# x64dbg-MCP source (users fetch upstream; we apply tools\x64dbg-mcp-winre.patch)
$gitOk = try {
    $mcpDir = Join-Path $stage "x64dbg-mcp-server"
    if (-not (Test-Path $mcpDir)) {
        git clone --depth 1 https://github.com/duty1g/x64dbg-mcp-server $mcpDir 2>$null
    }
    if (Test-Path "$mcpDir\src\mcp\tools.zig") {
        # apply our patch (setHardwareBreakpoint failures must surface)
        Select-String -Path "$mcpDir\src\mcp\tools.zig" -Pattern "WinRE" -Quiet |
            ForEach-Object { if (-not $_) {
                Write-Host "  [NOTE] apply tools\x64dbg-mcp-winre.patch (host tools dir) after clone"
            } }
        Write-Host "  [OK] x64dbg-mcp-server staged"
    } else { Write-Host "  [WARN] x64dbg-mcp clone failed - fetch manually" -ForegroundColor Yellow }
} catch { Write-Host "  [WARN] git not available - fetch x64dbg-mcp-server manually" -ForegroundColor Yellow }

Write-Host ""
# --- Platform-provided / licensed (NOT downloaded) -----------------------------
#   CADRE PE loader : built extension - stage from RevAI\extensions\cadre-pe-loader
#                     (or build RevEng\Tools\cadre-ghidra-loader); setup installs
#                     it into Ghidra\Extensions\CADRE.
#   idasql.exe      : licensed (allthingsida/idasql) - drop your copy at
#                     dist\provision\idasql.exe; it is staged to C:\Tools-staged
#                     and setup installs it next to idat.exe.
# --- SQL-first artifacts (Ghidra SQL + IDA SQL) --------------------------------
# idasql is a FREE public release (github.com/allthingsida/idasql) - the archive
# is version-matched to the installed IDA (9.2/9.3/9.4). We stage the CLI as
# idasql.exe plus the raw zip for reference. The Ghidra side (LibGhidraHost
# extension + ghidrasql 0.0.6) is built once on a build VM and kept in
# internal\reapply\sql (gitignored) - see docs\SQL-GHIDRA.md for the build path.
$sqlSrc = Join-Path $repo "internal\reapply\sql"
$sqlStage = Join-Path $stage "sql"
New-Item -ItemType Directory -Force -Path $sqlStage | Out-Null
foreach ($f in @("LibGhidraHost.zip", "ghidrasql.exe")) {
    $srcF = Join-Path $sqlSrc $f
    if (Test-Path $srcF) {
        Copy-Item $srcF (Join-Path $sqlStage $f) -Force
        Write-Host "  [OK] $f staged (from internal\reapply\sql)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $f missing in internal\reapply\sql - build it (docs\SQL-GHIDRA.md)" -ForegroundColor Yellow
    }
}
$idasqlZip = Get-ChildItem $sqlSrc -Filter "idasql-v*-ida93.zip" -EA SilentlyContinue | Select-Object -First 1
if (-not $idasqlZip) {
    $u = "https://github.com/allthingsida/idasql/releases/download/v0.0.18.1/idasql-v0.0.18.1-ida93.zip"
    $out = Join-Path $sqlStage "idasql-v0.0.18.1-ida93.zip"
    Write-Host "  [GET ] idasql (IDA 9.3 build) ..."
    try { Invoke-WebRequest -Uri $u -OutFile $out -UseBasicParsing -TimeoutSec 600 } catch { Write-Host "  [FAIL] idasql download: $($_.Exception.Message)" -ForegroundColor Yellow }
    $idasqlZip = Get-Item $out -EA SilentlyContinue
} else {
    Copy-Item $idasqlZip.FullName (Join-Path $sqlStage $idasqlZip.Name) -Force
}
if ($idasqlZip -and (Test-Path $idasqlZip.FullName)) {
    $tmp = Join-Path $stage "_idasql_x"
    Remove-Item $tmp -Recurse -Force -EA SilentlyContinue
    Expand-Archive -Path $idasqlZip.FullName -DestinationPath $tmp -Force
    $cli = Get-ChildItem $tmp -Recurse -Filter "idasql.exe" | Where-Object FullName -match "windows-x86_64\\cli" | Select-Object -First 1
    if ($cli) {
        Copy-Item $cli.FullName (Join-Path $sqlStage "idasql.exe") -Force
        Write-Host "  [OK] idasql.exe staged (free release; matches IDA 9.3)" -ForegroundColor Green
    }
    Remove-Item $tmp -Recurse -Force -EA SilentlyContinue
}

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
Write-Host "  5. die_win32_portable_*.zip                -> unzip, copy diec.exe to C:\Tools\die\"
Write-Host "  6. GoReSym.exe                             -> C:\Tools\goresym\goresym.exe"
Write-Host "  7. scdbg.zip / yr-x86_64-*.zip             -> C:\Tools\scdbg\ / C:\Tools\yr\ (FlareVM base often ships these)"
Write-Host "  8. capa-rules\ (cloned)                    -> C:\Tools\capa-rules"
Write-Host "  9. x64dbg-mcp-server\ (cloned)             -> C:\WinRE\integrations\ (setup builds the plugin)"
Write-Host " 10. Run: powershell -File C:\WinRE\install\setup-flarevm.ps1"
Write-Host "     (unzips staged zig, builds the MCP plugin, verifies everything)"
Write-Host ""
$failed = @()
if (-not $ghidraOk) { $failed += "Ghidra" }
if (-not $x64Ok) { $failed += "x64dbg" }
if (-not $zigOk) { $failed += "zig" }
if (-not $peOk) { $failed += "pe-sieve" }
if (-not $hhOk) { $failed += "hollows_hunter" }
if ($failed) { Write-Host "DOWNLOAD FAILURES: $($failed -join ', ') - fetch manually from their release pages" -ForegroundColor Yellow; exit 1 }
Write-Host "All downloads staged OK." -ForegroundColor Green
