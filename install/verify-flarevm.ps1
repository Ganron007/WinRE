#Requires -Version 5.1
<#
.SYNOPSIS
    verify-flarevm.ps1 - verify a WinRE FlareVM deployment (READ-ONLY).

.DESCRIPTION
    Consolidated PASS/FAIL battery for the Windows side of the WinRE lab.
    Mirrors RevAI's install/verify-remnux.sh. Never modifies the system -
    safe to run anytime. Exit 0 = all critical checks passed; 1 = failures.

    Run ON the FlareVM:
      powershell -ExecutionPolicy Bypass -File C:\WinRE\install\verify-flarevm.ps1
#>

$ErrorActionPreference = "Continue"
$script:ERR = 0
$script:WARN = 0

function Ok([string]$m)   { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:WARN++ }
function Fail([string]$m) { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:ERR++ }
function Info([string]$m) { Write-Host "  [INFO] $m" -ForegroundColor DarkGray }

function Test-PathOk([string]$p, [string]$label, [string]$hint) {
    if (Test-Path $p) { Ok "$label -> $p" } else { Fail "$label missing: $p ($hint)" }
}

Write-Host "=== WinRE / FlareVM verification ===" -ForegroundColor Cyan

Write-Host ""
Write-Host "--- OS ---"
Info "Host: $env:COMPUTERNAME  User: $env:USERNAME"
$cv = Get-CimInstance Win32_OperatingSystem
Info "OS: $($cv.Caption) $($cv.Version)"

Write-Host ""
Write-Host "--- Python ---"
$py = "C:\Python313\python.exe"
if (Test-Path $py) {
    $v = & $py --version 2>&1
    Ok "python -> $py ($v)"
    foreach ($mod in @("frida", "flask")) {
        $mv = & $py -c "import $mod; print($mod.__version__)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $mv) { Ok "python module $mod == $mv" }
        else { Fail "python module $mod not importable (pip install $mod)" }
    }
} else {
    Fail "python missing at $py (install Python 3.13 - see docs/PREREQUISITES.md)"
}

Write-Host ""
Write-Host "--- C:\WinRE layout ---"
foreach ($d in @("winre", "tools", "logs", "lock", "ops", "sessions")) {
    $p = "C:\WinRE\$d"
    if (Test-Path $p) { Ok "layout $d\" } else { Fail "layout $d\ missing (run install\setup-flarevm.ps1)" }
}
foreach ($f in @("C:\WinRE\winre\pipeline.py", "C:\WinRE\winre\orchestrator.py",
                 "C:\WinRE\winre\remote_driver.py", "C:\WinRE\winre\flare_dynamic_job.ps1",
                 "C:\WinRE\tools\frida_api_trace.py", "C:\WinRE\winre\summarize_dynamic.py")) {
    if (Test-Path $f) { Ok "file $(Split-Path $f -Leaf)" } else { Warn "file missing: $f (sync repo via ops\sync_to_flare.ps1)" }
}
# remote helper needs summarize_dynamic.py next to the job script
if (-not (Test-Path "C:\WinRE\winre\summarize_dynamic.py") -and (Test-Path "C:\WinRE\tools\summarize_dynamic.py")) {
    Info "summarize_dynamic.py found in tools\ (job falls back to C:\tools\reveng-dynamic)"
}

Write-Host ""
Write-Host "--- Ghidra ---"
$ghidra = Get-ChildItem "C:\Tools" -Directory -ErrorAction SilentlyContinue |
    Where-Object Name -match "^ghidra_\d" | Select-Object -First 1
if ($ghidra) {
    Ok "Ghidra install -> $($ghidra.FullName)"
    $headless = Join-Path $ghidra.FullName "support\analyzeHeadless.bat"
    if (Test-Path $headless) { Ok "analyzeHeadless present" } else { Warn "analyzeHeadless.bat missing under $($ghidra.FullName)" }
    $loader = Get-ChildItem (Join-Path $ghidra.FullName "Ghidra\Extensions") -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match "CADRE" | Select-Object -First 1
    if ($loader) { Ok "CADRE PE loader extension -> $($loader.Name)" }
    else { Fail "CADRE PE loader extension not in Ghidra\Extensions (see docs\PREREQUISITES.md)" }
} else {
    Fail "Ghidra not found under C:\Tools\ghidra_* (see docs\PREREQUISITES.md)"
}

Write-Host ""
Write-Host "--- Malcat ---"
$malcatBin = $null
foreach ($cand in @("C:\Tools\malcat\bin", "C:\Program Files\Malcat\bin",
                    "C:\Users\$env:USERNAME\Downloads\malcat\bin")) {
    if (Test-Path (Join-Path $cand "malcat.mcp.py")) { $malcatBin = $cand; break }
}
if (-not $malcatBin) {
    $hit = Get-ChildItem "C:\Tools", "C:\Program Files" -Recurse -Depth 3 -Filter "malcat.mcp.py" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($hit) { $malcatBin = $hit.DirectoryName }
}
if ($malcatBin) {
    Ok "Malcat bin dir -> $malcatBin"
    # Functional license check: activation state lives inside Malcat (GUI
    # activation), NOT in a license.dat file. Query the python API.
    $malcatPy = Join-Path $malcatBin "python313\python.exe"
    if (-not (Test-Path $malcatPy)) { $malcatPy = "C:\Python313\python.exe" }
    $licOut = & $malcatPy -c "import sys; sys.path.insert(0, r'$malcatBin'); import malcat; print(malcat.env.flavor)" 2>$null
    if ($licOut -match "FULL|OEM|PRO") { Ok "Malcat license ACTIVE ($($licOut.Trim()))" }
    elseif ($licOut) { Warn "Malcat flavor: $($licOut.Trim()) (unlicensed/limited - headless analysis degraded)" }
    else { Warn "could not query Malcat license flavor via $malcatPy" }
} else {
    # Malcat is COMMERCIAL-OPTIONAL: pipeline degrades to Ghidra-primary
    # with honest 'skipped' annotations. Not a readiness failure.
    Warn "Malcat not installed (OPTIONAL commercial) - pipeline runs Ghidra-primary with malcat steps skipped"
}

Write-Host ""
Write-Host "--- IDA ---"
$idaDir = "C:\Program Files\IDA Professional 9.3"
if (Test-Path (Join-Path $idaDir "ida.exe")) { Ok "IDA Professional -> $idaDir" }
elseif (Test-Path (Join-Path $idaDir "idat.exe")) { Ok "IDA Professional (idat) -> $idaDir" }
else { Warn "IDA not found at $idaDir (optional: deep stage degrades to Ghidra+Malcat)" }
if (Test-Path (Join-Path $idaDir "idasql.exe")) { Ok "idasql.exe present" }
else { Warn "idasql.exe missing at $idaDir (ida_query tool disabled)" }

Write-Host ""
Write-Host "--- x64dbg + MCP plugin ---"
$x64 = @("C:\Tools\x64dbg\release\x64\x64dbg.exe", "C:\Tools\x64dbg\release\x32\x32dbg.exe") |
    Where-Object { Test-Path $_ }
if ($x64) { Ok "x64dbg -> $($x64 -join ', ')" }
else { Fail "x64dbg.exe not found under C:\Tools\x64dbg (see docs\PREREQUISITES.md)" }
$plugs = Get-ChildItem "C:\Tools\x64dbg" -Recurse -Depth 4 -Include "*.dp64", "*.dp32" -ErrorAction SilentlyContinue |
    Where-Object Name -match "^x64dbg-MCP-Server" 
if ($plugs) { Ok "MCP plugin -> $($plugs[0].FullName)" }
else { Fail "x64dbg MCP plugin (x64dbg-MCP-Server.dp64) not found - build from integrations\x64dbg-mcp-server (Zig)" }

Write-Host ""
Write-Host "--- Dynamic prerequisites ---"
Test-PathOk "C:\Tools\fakenet\fakenet3.5\fakenet.exe" "FakeNet-NG" "docs\PREREQUISITES.md"
Test-PathOk "C:\Tools\sysinternals\Procmon64.exe" "Procmon" "docs\PREREQUISITES.md"
Test-PathOk "C:\ProgramData\chocolatey\bin\pe-sieve.exe" "pe-sieve" "choco install pe-sieve"
Test-PathOk "C:\Tools\hollows_hunter\hollows_hunter.exe" "hollows_hunter" "docs\PREREQUISITES.md"
Test-PathOk "C:\samples" "samples dir" "mkdir C:\samples"

Write-Host ""
Write-Host "--- MCP plane ---"
$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in 9009, 9094, 9097 }
foreach ($p in @(@{n = "Malcat"; port = 9009 }, @{n = "x64dbg"; port = 9094 }, @{n = "WinDbg"; port = 9097 })) {
    $hit = $ports | Where-Object LocalPort -eq $p.port | Select-Object -First 1
    if ($hit) { Ok "$($p.n) MCP listening :$($p.port) (pid $($hit.OwningProcess))" }
    else { Warn "$($p.n) MCP NOT listening :$($p.port) (start via C:\WinRE\winre\mcp\start_servers.ps1 or x64dbg on-demand manager)" }
}

Write-Host ""
Write-Host "--- Autostart / boot persistence ---"
$startup = [Environment]::GetFolderPath("Startup")
if (Test-Path (Join-Path $startup "WinRE-MCP.cmd")) { Ok "Startup launcher -> WinRE-MCP.cmd" }
else { Warn "Startup launcher missing (run install\install_mcp_autostart.ps1)" }
$task = Get-ScheduledTask -TaskName "WinRE-X64dbg-Once" -ErrorAction SilentlyContinue
if ($task) { Ok "scheduled task WinRE-X64dbg-Once present" }
else { Warn "scheduled task WinRE-X64dbg-Once missing (x64dbg MCP needs a console-session kick)" }

Write-Host ""
Write-Host "--- Snapshot gate ---"
if (Test-Path "C:\WinRE\.clean_snapshot") { Ok "clean-snapshot marker present (bake it into the VM snapshot)" }
else { Info "no clean-snapshot marker (create with: New-Item C:\WinRE\.clean_snapshot -ItemType File, then re-snapshot)" }

Write-Host ""
Write-Host "--- LLM config (control-plane concern) ---"
if (Test-Path "C:\WinRE\.env") { Info "C:\WinRE\.env present (unused on the VM - LLM runs on the control plane)" }
else { Info "no C:\WinRE\.env (fine - LLM config lives on the control plane via .env)" }

Write-Host ""
Write-Host "=== Summary: $($script:ERR) FAIL, $($script:WARN) WARN ===" -ForegroundColor Cyan
if ($script:ERR -gt 0) { exit 1 } else { exit 0 }
