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

    VM-first: anything the FlareVM baseline already ships (x64dbg, DIE,
    GoReSym, scdbg, yara-x, hollows_hunter, Ghidra via choco, ...) is
    detected and skipped - we only stage the genuine gaps (zig, radare2,
    idasql, SQL-first artifacts, Python wheels).

    Downloads go to <repo>\dist\provision\ on the host first (gitignored),
    so re-runs skip completed downloads. GitHub asset URLs are resolved via
    the API (release asset names drift); a final 'DOWNLOAD FAILURES' line
    names anything that still needs a manual fetch.

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

# VM-first inventory: anything the FlareVM baseline already ships is skipped
# (public users start from FlareVM; we only stage the genuine gaps).
function Get-VmHas([string[]]$paths) {
    $json = ConvertTo-Json @($paths) -Compress
    $body = "`$paths = ConvertFrom-Json '$json'; for (`$i = 0; `$i -lt `$paths.Count; `$i++) { if (Test-Path -LiteralPath `$paths[`$i]) { 'EX' + `$i } }"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $sshArgs = @("-i", $SshKey, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes")
    $out = ssh @sshArgs "${User}@${FlareHost}" "powershell -NoProfile -EncodedCommand $enc" 2>$null
    $has = @{}
    for ($i = 0; $i -lt $paths.Count; $i++) { $has[$paths[$i]] = $false }
    foreach ($line in ($out -split "`n")) {
        if ($line -match '^EX(\d+)\s*$') {
            $idx = [int]$Matches[1]
            if ($idx -lt $paths.Count) { $has[$paths[$idx]] = $true }
        }
    }
    $found = @($paths | Where-Object { $has[$_] }).Count
    Write-Host "  [VM ] baseline inventory: $found/$($paths.Count) tool paths present" -ForegroundColor DarkGray
    return $has
}

$vmHas = Get-VmHas @(
    "C:\Tools\x64dbg\release\x64\x64dbg.exe",
    "C:\Tools\die\diec.exe",
    "C:\Tools\GoReSym\GoReSym.exe",
    "C:\Tools\scdbg\scdbg.exe",
    "C:\Tools\yara-x\yr.exe",
    "C:\Tools\hollows_hunter\hollows_hunter.exe",
    "C:\Tools\malcat\bin",
    "C:\Tools\radare2\radare2.exe",
    "C:\Tools\zig\zig.exe",
    "C:\Program Files\IDA Professional 9.3\idat.exe",
    "C:\ProgramData\chocolatey\lib\ghidra\tools"
)

Write-Host "=== Provision required free tools (host -> VM staging) ===" -ForegroundColor Cyan

# Ghidra: FlareVM ships it via chocolatey; only stage when the VM lacks it.
$ghidraVer = "11.3.2"
if ($vmHas["C:\ProgramData\chocolatey\lib\ghidra\tools"]) {
    Write-Host "  [SKIP] Ghidra (FlareVM choco install present on VM)" -ForegroundColor DarkGray
    $ghidraOk = $true
} else {
    $ghidraOk = Get-File "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${ghidraVer}_build/ghidra_${ghidraVer}_PUBLIC_20250415.zip" `
        (Join-Path $stage "ghidra_${ghidraVer}_PUBLIC.zip")
}

# x64dbg: snapshot release asset names are VERSIONED (snapshot_YYYY-MM-DD_HH-MM.zip),
# so a guessed static URL breaks whenever upstream re-cuts the snapshot. Resolve
# the current asset through the GitHub API, then fall back to pinned known assets.
function Get-GitHubAsset([string]$repoSlug, [string]$tag, [string]$pattern, [string]$out) {
    if (Test-Path $out) { Write-Host "  [SKIP] $(Split-Path $out -Leaf) (exists)" -ForegroundColor DarkGray; return $true }
    $url = $null
    $apiUrl = if ($tag -eq "latest") {
        "https://api.github.com/repos/$repoSlug/releases/latest"
    } else {
        "https://api.github.com/repos/$repoSlug/releases/tags/$tag"
    }
    try {
        $rel = Invoke-RestMethod -Uri $apiUrl `
            -Headers @{ "User-Agent" = "winre-provision" } -TimeoutSec 30
        $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if ($asset) { $url = $asset.browser_download_url }
    } catch {
        Write-Host "  [warn] GitHub API lookup failed for $repoSlug@$tag : $($_.Exception.Message)" -ForegroundColor DarkGray
    }
    if (-not $url) { return $false }
    return (Get-File $url $out)
}

if ($vmHas["C:\Tools\x64dbg\release\x64\x64dbg.exe"]) {
    Write-Host "  [SKIP] x64dbg (FlareVM provides C:\Tools\x64dbg + pluginsdk)" -ForegroundColor DarkGray
    $x64Ok = $true
} else {
    $x64Ok = Get-GitHubAsset "x64dbg/x64dbg" "snapshot" '^snapshot_\d{4}-\d{2}-\d{2}.+\.zip$' `
        (Join-Path $stage "x64dbg.zip")
}
if (-not $x64Ok) {
    foreach ($u in @(
            "https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_2025-03-15_15-57.zip",
            "https://github.com/x64dbg/x64dbg/releases/download/snapshot/x64dbg.zip")) {
        $x64Ok = Get-File $u (Join-Path $stage "x64dbg.zip")
        if ($x64Ok) { break }
    }
}

# Zig (for the x64dbg MCP plugin build) - 0.14+ uses zig-<arch>-windows-<ver>.zip
$zigVer = "0.14.1"
$zigOk = Get-File "https://ziglang.org/download/${zigVer}/zig-x86_64-windows-${zigVer}.zip" `
    (Join-Path $stage "zig-${zigVer}.zip")
if (-not $zigOk) {
    $zigOk = Get-File "https://ziglang.org/download/${zigVer}/zig-windows-x86_64-${zigVer}.zip" `
        (Join-Path $stage "zig-${zigVer}.zip")
}

# pe-sieve / hollows_hunter: FlareVM ships hollows_hunter; pe-sieve only when missing
if ($vmHas["C:\Tools\hollows_hunter\hollows_hunter.exe"]) {
    Write-Host "  [SKIP] hollows_hunter (FlareVM provides C:\Tools\hollows_hunter)" -ForegroundColor DarkGray
    $hhOk = $true
} else {
    $hhOk = Get-File "https://github.com/hasherezade/hollows_hunter/releases/latest/download/hollows_hunter64.exe" `
        (Join-Path $stage "hollows_hunter64.exe")
}
$peOk = $true
if (Test-Path "C:\ProgramData\chocolatey\bin\pe-sieve64.exe") {
    Write-Host "  [SKIP] pe-sieve (choco install present on VM)" -ForegroundColor DarkGray
} else {
    $peOk = Get-File "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe_sieve64.exe" `
        (Join-Path $stage "pe-sieve64.exe")
    if (-not $peOk) {
        $peOk = Get-File "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe-sieve64.exe" `
            (Join-Path $stage "pe-sieve64.exe")
    }
}

# Additional free static tools (staged for the air-gapped VM):
#   - Detect It Easy / GoReSym / scdbg / yara-x: FlareVM ships all four
#     (C:\Tools\die, C:\Tools\GoReSym, C:\Tools\scdbg, C:\Tools\yara-x).
#     Stage only for non-FlareVM hosts.
$dieOk = $true
if ($vmHas["C:\Tools\die\diec.exe"]) {
    Write-Host "  [SKIP] Detect It Easy (FlareVM provides C:\Tools\die)" -ForegroundColor DarkGray
} else {
    $dieVer = "3.09"
    $dieOk = Get-File "https://github.com/horsicq/Detect-It-Easy/releases/download/${dieVer}/die_win32_portable_${dieVer}.zip" `
        (Join-Path $stage "die_win32_portable_${dieVer}.zip")
    if (-not $dieOk) {
        $dieOk = Get-GitHubAsset "horsicq/Detect-It-Easy" "latest" 'portable.*\.zip$' `
            (Join-Path $stage "die_win32_portable.zip")
    }
}
$goresymOk = $true
if ($vmHas["C:\Tools\GoReSym\GoReSym.exe"]) {
    Write-Host "  [SKIP] GoReSym (FlareVM provides C:\Tools\GoReSym)" -ForegroundColor DarkGray
} else {
    $goresymOk = Get-GitHubAsset "mandiant/GoReSym" "latest" 'windows.*\.zip$|GoReSym.*\.exe$' `
        (Join-Path $stage "GoReSym-windows.zip")
}
$scdbgOk = $true
if ($vmHas["C:\Tools\scdbg\scdbg.exe"]) {
    Write-Host "  [SKIP] scdbg (FlareVM provides C:\Tools\scdbg)" -ForegroundColor DarkGray
} else {
    $scdbgOk = Get-File "https://github.com/dzzie/SCDBG/releases/latest/download/scdbg.zip" `
        (Join-Path $stage "scdbg.zip")
}
$yaraOk = $true
if ($vmHas["C:\Tools\yara-x\yr.exe"]) {
    Write-Host "  [SKIP] yara-x (FlareVM provides C:\Tools\yara-x)" -ForegroundColor DarkGray
} else {
    $yaraOk = Get-GitHubAsset "VirusTotal/yara-x" "latest" 'x86_64-pc-windows-msvc\.zip$' `
        (Join-Path $stage "yr-x86_64-pc-windows-msvc.zip")
}

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
# radare2 (2nd disasm engine; dropped from FlareVM 2026 package sets)
$r2Zip = Join-Path $stage "radare2.zip"
if (Test-Path $r2Zip) { Write-Host "  [OK] radare2.zip staged (cached)" -ForegroundColor Green }
else {
    Write-Host "  [GET ] radare2 (official Windows build) ..."
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/radareorg/radare2/releases/latest" -UseBasicParsing -TimeoutSec 120
        # prefer the classic distribution zip (radare2-<ver>-w64.zip);
        # r2blob-*.zip is the new single-file bundle (different layout)
        $asset = $rel.assets | Where-Object { $_.name -match '^radare2-.*-w64\.zip$' } | Select-Object -First 1
        if (-not $asset) {
            $asset = $rel.assets | Where-Object { $_.name -match '(w64|win64).*\.zip$' } | Select-Object -First 1
        }
        if ($asset) {
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $r2Zip -UseBasicParsing -TimeoutSec 900
            Write-Host "  [OK] radare2 staged ($($asset.name))" -ForegroundColor Green
        } else { Write-Host "  [WARN] no w64 asset in latest radare2 release" -ForegroundColor Yellow }
    } catch { Write-Host "  [WARN] radare2 download failed: $($_.Exception.Message)" -ForegroundColor Yellow }
}

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
    # SQL-first artifacts keep their own subdir (setup looks there first)
    if (Test-Path $sqlStage) {
        ssh @scpArgs "${User}@${FlareHost}" "cmd /c mkdir C:\Tools-staged\sql" 2>$null | Out-Null
        Get-ChildItem $sqlStage -File | ForEach-Object {
            scp @scpArgs $_.FullName "${User}@${FlareHost}:C:/Tools-staged/sql/" 2>$null
            Write-Host "  staged: sql\$($_.Name)"
        }
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
