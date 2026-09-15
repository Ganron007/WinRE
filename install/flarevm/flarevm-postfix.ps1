#Requires -Version 5.1
<#
.SYNOPSIS
    flarevm-postfix.ps1 - WinRE post-install repair + readiness check for FLARE-VM.

.DESCRIPTION
    Companion to the WinRE-patched FLARE-VM install.ps1 (same folder). Safe to
    run standalone on an ALREADY-installed (even partial) FLARE-VM, and it is
    what the patched installer appends at the end of its run.

    Why this exists (observed on a real install, 2026-09):
      - The final FLARE-VM pass can fail lots of `.vm` packages because a pinned
        dependency conflicts with what is already installed (classic case:
        `vcredist140` newer than the pin -> `vcredist140.vm` fails -> everything
        depending on it fails: python3.vm, sysinternals.vm, ghidra.vm, ...).
      - Some upstream packages download dead URLs or checksum-mismatched files
        (e.g. regcool.vm) - those are upstream issues, not fatal.
      - FLARE-VM 2026 installs the *Store* WinDbg appx; WinRE's WinDbg
        pipeline (mcp-windbg, windbg_post) needs the classic `cdb.exe`.

    What it does (idempotent, log to the user's Desktop):
      1. Retries every package left in C:\ProgramData\chocolatey\lib-bad with
         `--ignore-dependencies` (breaks the pinned-dependency cascade).
      2. Ensures WinRE-critical extras: `sysinternals.vm`, `ghidra.vm`
         (if truly absent) and classic Debugging Tools
         (`windows-sdk-10-version-2004-windbg` -> cdb.exe/windbg.exe).
      3. Prints a WinRE tool checklist with the exact paths WinRE looks for.

.NOTES
    Upstream FLARE-VM installer: https://github.com/mandiant/flare-vm (Apache-2.0).
    This file is WinRE's own; it does not modify upstream content.
    Exit code: 0 = every WinRE-critical item present, 1 = something still missing.
#>

$ErrorActionPreference = "Continue"
$script:Missing = @()
$logPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "winre-flarevm-postfix.log"

function Say([string]$msg, [string]$color = "Gray") {
    Write-Host $msg -ForegroundColor $color
    Add-Content -Path $logPath -Value $msg -ErrorAction SilentlyContinue
}
function Have([string]$p) { Test-Path $p }

Say ""
Say "=== WinRE FLARE-VM post-fixup ($(Get-Date -Format o)) ===" "Cyan"
Say "log: $logPath"

# --- 1. retry packages left in lib-bad ----------------------------------------
$badDir = Join-Path $env:ProgramData "chocolatey\lib-bad"
$bad = @()
if (Test-Path $badDir) {
    $bad = @(Get-ChildItem $badDir -Directory -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name | Sort-Object -Unique)
}
if ($bad.Count -eq 0) {
    Say "[winre] no failed packages in lib-bad - nothing to retry" "Green"
} else {
    Say "[winre] failed packages to retry ($($bad.Count)): $($bad -join ', ')" "Yellow"
    foreach ($pkg in $bad) {
        Say "[winre] retry: $pkg (--ignore-dependencies)" "Yellow"
        & choco install $pkg -y --no-progress --ignore-dependencies 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Say "        OK   $pkg" "Green" }
        else { Say "        FAIL $pkg (upstream package issue - see %ProgramData%\chocolatey\logs\chocolatey.log)" "Red" }
    }
}

# --- 2. WinRE-critical extras -------------------------------------------------
if (-not (Have "C:\Tools\sysinternals\Procmon64.exe")) {
    Say "[winre] installing sysinternals.vm (Procmon/strings64/procdump)" "Yellow"
    & choco install sysinternals.vm -y --no-progress --ignore-dependencies 2>&1 | Out-Null
}
if (-not ((Get-ChildItem "C:\Tools" -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match "^ghidra_") -or
        (Test-Path "C:\ProgramData\chocolatey\lib\ghidra\tools"))) {
    Say "[winre] installing ghidra.vm (Ghidra + CADRE/SQL target)" "Yellow"
    & choco install ghidra.vm -y --no-progress --ignore-dependencies 2>&1 | Out-Null
}
if (-not (Have "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")) {
    Say "[winre] installing classic Debugging Tools (cdb.exe) - FlareVM 2026 ships Store WinDbg only" "Yellow"
    & choco install windows-sdk-10-version-2004-windbg -y --no-progress 2>&1 | Out-Null
}

# --- 3. WinRE checklist -------------------------------------------------------
Say ""
Say "--- WinRE tool checklist ---" "Cyan"
$checks = @(
    @{ n = "x64dbg";          p = "C:\Tools\x64dbg\release\x64\x64dbg.exe" },
    @{ n = "FakeNet-NG";      p = "C:\Tools\fakenet\fakenet3.5\fakenet.exe" },
    @{ n = "Procmon64";       p = "C:\Tools\sysinternals\Procmon64.exe" },
    @{ n = "procdump64";      p = "C:\Tools\sysinternals\procdump64.exe" },
    @{ n = "strings64";       p = "C:\Tools\sysinternals\strings64.exe" },
    @{ n = "pe-sieve";        p = "C:\ProgramData\chocolatey\bin\pe-sieve.exe" },
    @{ n = "hollows_hunter";  p = "C:\Tools\hollows_hunter\hollows_hunter.exe" },
    @{ n = "capa";            p = "C:\Tools\capa\capa.exe" },
    @{ n = "diec";            p = "C:\Tools\die\diec.exe" },
    @{ n = "scdbg";           p = "C:\Tools\scdbg\scdbg.exe" },
    @{ n = "goresym";         p = "C:\Tools\goresym\goresym.exe" },
    @{ n = "cdb (classic)";   p = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" }
)
foreach ($c in $checks) {
    if (Have $c.p) { Say ("[winre] OK      {0,-16} {1}" -f $c.n, $c.p) "Green" }
    else { Say ("[winre] MISSING {0,-16} {1}" -f $c.n, $c.p) "Red"; $script:Missing += $c.n }
}
# path-drift tolerant items (FlareVM moved these in 2026)
$yaraX = @("C:\Tools\yr\yr.exe", "C:\Tools\yara-x\yr.exe",
           (Get-Command yr.exe -ErrorAction SilentlyContinue).Source) |
    Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($yaraX) { Say "[winre] OK      yara-x           $yaraX" "Green" }
else { Say "[winre] MISSING yara-x           (C:\Tools\yara-x\yr.exe)" "Red"; $script:Missing += "yara-x" }
$upx = @("C:\Tools\upx\upx.exe", (Get-Command upx.exe -ErrorAction SilentlyContinue).Source) |
    Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $upx) {
    $upx = Get-ChildItem "C:\Tools\upx" -Recurse -Filter "upx.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}
if ($upx) { Say "[winre] OK      UPX              $upx" "Green" }
else { Say "[winre] MISSING UPX              (C:\Tools\upx\*\upx.exe)" "Red"; $script:Missing += "UPX" }

Say ""
if ($script:Missing.Count -eq 0) {
    Say "[winre] FlareVM is WinRE-ready (core tool set complete)." "Green"
    Say "[winre] next: run install\setup-flarevm.ps1 (stages WinRE, builds x64dbg MCP plugin, installs pip wheels)." "Cyan"
    exit 0
} else {
    Say "[winre] still missing: $($script:Missing -join ', ')" "Red"
    Say "[winre] retry those packages manually:  choco install -y --ignore-dependencies <package>" "Yellow"
    exit 1
}
