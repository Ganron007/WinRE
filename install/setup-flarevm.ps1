#Requires -Version 5.1
<#
.SYNOPSIS
    setup-flarevm.ps1 - one-shot WinRE bootstrap for a FlareVM.

.DESCRIPTION
    Idempotent bootstrap for the Windows side of the WinRE lab (mirror of
    RevAI's install/setup-remnux.sh). Safe to re-run: existing components
    are detected and left alone; repo-owned items (directories, launcher,
    marker, env template) are created only when missing.

    What it DOES automate:
      - C:\WinRE layout + C:\samples
      - Python module install (frida, flask) when missing
      - MCP autostart (Startup launcher + scheduled task) via
        install\install_mcp_autostart.ps1
      - clean-snapshot marker (C:\WinRE\.clean_snapshot)

    What it DETECTS and instructs (commercial / manual - never scripted):
      - FlareVM base, Ghidra + CADRE loader, Malcat + license,
        IDA Professional + idasql, x64dbg + MCP plugin build (Zig),
        FakeNet / Procmon / pe-sieve / hollows_hunter

    Usage (ON the FlareVM, after syncing the repo via ops\sync_to_flare.ps1):
      powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1
      powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1 -CheckMode   # dry-run, changes nothing
#>
param(
    [switch]$CheckMode
)

$ErrorActionPreference = "Continue"
$script:ERR = 0
$script:ACT = 0

function Ok([string]$m)     { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Act([string]$m)    { Write-Host "  [DO]   $m$(if ($CheckMode) { '  (dry-run)' })" -ForegroundColor Cyan; $script:ACT++ }
function Warn([string]$m)   { Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Fail([string]$m)   { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:ERR++ }
function Manual([string]$m) { Write-Host "  [MANUAL] $m" -ForegroundColor Magenta }
function Info([string]$m)   { Write-Host "  [INFO] $m" -ForegroundColor DarkGray }

function Ensure-Dir([string]$p) {
    if (Test-Path $p) { Ok "dir exists: $p" }
    else { Act "create dir: $p"; if (-not $CheckMode) { New-Item -ItemType Directory -Force -Path $p | Out-Null } }
}

function Ensure-FileFromRepo([string]$repo, [string]$dest) {
    if (Test-Path $dest) { Ok "exists: $dest" }
    elseif (Test-Path $repo) { Act "copy $(Split-Path $repo -Leaf) -> $dest"; if (-not $CheckMode) { Copy-Item $repo $dest -Force } }
    else { Warn "repo source missing: $repo" }
}

Write-Host "=== WinRE / FlareVM setup $(if ($CheckMode) { '(CHECK MODE - no changes)' }) ===" -ForegroundColor Cyan

# --- 0. repo present ---------------------------------------------------------
Write-Host ""
Write-Host "--- Repo (C:\WinRE) ---"
if (-not (Test-Path "C:\WinRE\winre\pipeline.py")) {
    Fail "C:\WinRE repo incomplete (winre\pipeline.py missing)."
    Manual "From the control plane run: ops\sync_to_flare.ps1  - then re-run this script."
} else { Ok "repo present (winre\pipeline.py)" }

# --- 1. layout ---------------------------------------------------------------
Write-Host ""
Write-Host "--- Layout ---"
foreach ($d in @("C:\WinRE", "C:\WinRE\winre", "C:\WinRE\tools", "C:\WinRE\logs",
                 "C:\WinRE\lock", "C:\WinRE\ops", "C:\WinRE\sessions", "C:\samples")) {
    Ensure-Dir $d
}

# --- 2. python + modules ------------------------------------------------------
Write-Host ""
Write-Host "--- Python ---"
$py = "C:\Python313\python.exe"
if (Test-Path $py) { Ok "python -> $py" }
else {
    Fail "python missing at $py"
    Manual "Install Python 3.13 for ALL USERS to C:\Python313 (python.org), then re-run."
}
if (Test-Path $py) {
    foreach ($mod in @("frida", "flask")) {
        & $py -c "import $mod" 2>$null
        if ($LASTEXITCODE -eq 0) { Ok "module $mod present" }
        else { Act "pip install $mod"; if (-not $CheckMode) { & $py -m pip install --quiet $mod } }
    }
}

# --- 3. commercial/static tools: detect + instruct ----------------------------
Write-Host ""
Write-Host "--- Static tooling (detect + instruct) ---"

if ((Get-Command choco -ErrorAction SilentlyContinue) -or (Test-Path "C:\ProgramData\chocolatey\bin")) { Ok "chocolatey present" }
else { Manual "FlareVM base not detected (no chocolatey). Install FlareVM via its install.ps1 - see docs\PREREQUISITES.md." }

$ghidra = Get-ChildItem "C:\Tools" -Directory -ErrorAction SilentlyContinue |
    Where-Object Name -match "^ghidra_\d" | Select-Object -First 1
if ($ghidra) {
    Ok "Ghidra -> $($ghidra.FullName)"
    $loader = Get-ChildItem (Join-Path $ghidra.FullName "Ghidra\Extensions") -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match "CADRE" | Select-Object -First 1
    if ($loader) { Ok "CADRE PE loader -> $($loader.Name)" }
    else { Manual "Build/copy the CADRE PE loader into $($ghidra.FullName)\Ghidra\Extensions (see docs\PREREQUISITES.md)." }
} else { Manual "Install Ghidra 12.x to C:\Tools\ghidra_<version> (docs\PREREQUISITES.md)." }

$malcatBin = @("C:\Tools\malcat\bin", "C:\Program Files\Malcat\bin",
               "C:\Users\$env:USERNAME\Downloads\malcat\bin") |
    Where-Object { Test-Path (Join-Path $_ "malcat.mcp.py") } | Select-Object -First 1
if ($malcatBin) {
    Ok "Malcat -> $malcatBin"
    $malcatPy = Join-Path $malcatBin "python313\python.exe"
    if (-not (Test-Path $malcatPy)) { $malcatPy = "C:\Python313\python.exe" }
    $licOut = & $malcatPy -c "import sys; sys.path.insert(0, r'$malcatBin'); import malcat; print(malcat.env.flavor)" 2>$null
    if ($licOut -match "FULL|OEM|PRO") { Ok "Malcat license ACTIVE ($($licOut.Trim()))" }
    else { Manual "Activate Malcat (GUI -> Preferences -> license). Headless API reports: $($licOut ?? 'unknown')." }
} else { Manual "Install Malcat (commercial) with bin\malcat.mcp.py reachable (docs\PREREQUISITES.md)." }

$idaDir = "C:\Program Files\IDA Professional 9.3"
if (Test-Path (Join-Path $idaDir "idat.exe")) {
    Ok "IDA Professional -> $idaDir"
    if (Test-Path (Join-Path $idaDir "idasql.exe")) { Ok "idasql present" }
    else { Manual "Install idasql.exe into $idaDir (id_query tool needs it)." }
} else { Warn "IDA not detected (optional - deep degrades to Ghidra+Malcat)." }

$x64 = "C:\Tools\x64dbg\release\x64\x64dbg.exe"
if (Test-Path $x64) {
    Ok "x64dbg -> $x64"
    $plug = Get-ChildItem "C:\Tools\x64dbg" -Recurse -Depth 4 -Include "*.dp64", "*.dp32" -ErrorAction SilentlyContinue |
        Where-Object Name -match "^x64dbg-MCP-Server" | Select-Object -First 1
    if ($plug) { Ok "MCP plugin -> $($plug.FullName)" }
    else {
        if (Get-Command zig -ErrorAction SilentlyContinue) {
            Act "build x64dbg MCP plugin (zig build) from C:\WinRE\integrations\x64dbg-mcp-server"
            if (-not $CheckMode) {
                Push-Location "C:\WinRE\integrations\x64dbg-mcp-server"
                zig build 2>&1 | Select-Object -Last 3
                $built = Get-ChildItem "zig-out" -Recurse -Include "*.dp64", "*.dp32" -ErrorAction SilentlyContinue |
                    Where-Object Name -match "^x64dbg-MCP-Server" | Select-Object -First 1
                if ($built) {
                    $plugDir = Join-Path (Split-Path $x64) "plugins"
                    New-Item -ItemType Directory -Force -Path $plugDir | Out-Null
                    Copy-Item $built.FullName $plugDir -Force
                    Ok "plugin deployed: $($built.Name) -> $plugDir"
                } else { Manual "zig build produced no plugin - build manually (docs\X64DBG-MCP.md)." }
                Pop-Location
            }
        } else { Manual "MCP plugin missing and zig not on PATH - build per docs\X64DBG-MCP.md (zig 0.14.x)." }
    }
} else { Manual "Install x64dbg to C:\Tools\x64dbg (docs\PREREQUISITES.md)." }

foreach ($t in @(@("C:\Tools\fakenet\fakenet3.5\fakenet.exe", "FakeNet-NG"),
                 @("C:\Tools\sysinternals\Procmon64.exe", "Procmon"),
                 @("C:\ProgramData\chocolatey\bin\pe-sieve.exe", "pe-sieve"),
                 @("C:\Tools\hollows_hunter\hollows_hunter.exe", "hollows_hunter"))) {
    if (Test-Path $t[0]) { Ok "$($t[1]) present" } else { Manual "Install $($t[1]) at $($t[0]) (docs\PREREQUISITES.md)." }
}

# --- 4. repo-owned: autostart + task ------------------------------------------
Write-Host ""
Write-Host "--- MCP autostart ---"
$autostart = "C:\WinRE\install\install_mcp_autostart.ps1"
if (Test-Path $autostart) {
    if ($CheckMode) { Act "run install_mcp_autostart.ps1 (idempotent)" }
    else {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $autostart
        if ($LASTEXITCODE -eq 0) { Ok "autostart installer ran (idempotent)" }
        else { Warn "autostart installer exit=$LASTEXITCODE" }
    }
} else { Warn "install_mcp_autostart.ps1 missing from repo" }

$task = Get-ScheduledTask -TaskName "WinRE-X64dbg-Once" -ErrorAction SilentlyContinue
if ($task) { Ok "scheduled task WinRE-X64dbg-Once present" }
else { Warn "scheduled task WinRE-X64dbg-Once absent - x64dbg MCP needs a console-session kick; create it per docs\X64DBG-MCP.md or let the on-demand manager launch x64dbg." }

# --- 5. repo-owned: env template + gate marker ---------------------------------
Write-Host ""
Write-Host "--- Env template + snapshot gate ---"
$template = "C:\WinRE\.env.template"
$tmplBody = @"
# WinRE control-plane LLM config (copy to .env on the CONTROL PLANE, never commit .env)
WINRE_LLM_BASE_URL=
WINRE_LLM_MODEL=
WINRE_LLM_REASONING=
WINRE_LLM_API_KEY=
"@
if (Test-Path $template) { Ok "env template present" }
else { Act "write $template"; if (-not $CheckMode) { [System.IO.File]::WriteAllText($template, $tmplBody, (New-Object System.Text.UTF8Encoding($true))) } }
Info "LLM keys live on the CONTROL PLANE (.env next to the repo there) - the VM does not need them."

$marker = "C:\WinRE\.clean_snapshot"
if (Test-Path $marker) { Ok "clean-snapshot marker present" }
else { Act "create marker $marker"; if (-not $CheckMode) { New-Item -ItemType File -Path $marker -Force | Out-Null } }
if (-not $CheckMode) { Manual "TAKE/UPDATE the VM snapshot NOW so the marker is baked in (restores re-create it)." }

# --- 6. VM desktop status shortcut ---------------------------------------------
Write-Host ""
Write-Host "--- VM desktop status shortcut ---"
$desktop = [Environment]::GetFolderPath("Desktop")
$statusBat = Join-Path $desktop "WinRE-Status.bat"
$batBody = "@echo off`r`n" +
           "title WinRE Status`r`n" +
           "powershell -NoProfile -ExecutionPolicy Bypass -File `"C:\WinRE\install\verify-flarevm.ps1`"`r`n" +
           "echo.`r`n" +
           "pause`r`n"
if ((Test-Path $statusBat) -and ((Get-Item $statusBat).Length -gt 100)) { Ok "desktop WinRE-Status.bat present" }
else { Act "create $statusBat"; if (-not $CheckMode) { [System.IO.File]::WriteAllText($statusBat, $batBody, (New-Object System.Text.UTF8Encoding($true))) } }
Info "double-click it anytime for the full VM-side PASS/FAIL battery"

# --- 7. verify -----------------------------------------------------------------
Write-Host ""
if ($CheckMode) {
    Write-Host "=== Check mode complete: $script:ACT action(s) would be taken, $script:ERR blocker(s) ===" -ForegroundColor Cyan
} else {
    Write-Host "--- Final verification ---"
    & powershell -NoProfile -ExecutionPolicy Bypass -File "C:\WinRE\install\verify-flarevm.ps1"
    $script:ERR += $LASTEXITCODE
    Write-Host "=== Setup complete: $script:ACT action(s) taken, $script:ERR FAIL(s) in verify ===" -ForegroundColor Cyan
}
exit ([int]($script:ERR -gt 0))
