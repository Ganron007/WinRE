#Requires -Version 5.1
<#
.SYNOPSIS
    Build x64dbg-MCP-Server.dp64/.dp32 Zig plugin and stage into a dist\ tree.

.DESCRIPTION
    Mirrors `zig build -Doptimize=ReleaseSafe --prefix dist` from
    integrations/x64dbg-mcp-server-main/README.md. Can run on any host
    with Zig 0.16-dev; the resulting dist\ is what gets xcopy'd into
    C:\tools\x64dbg\{x64,x32}\plugins\ on Flare.

.PARAMETER ZigPath
    Path to zig.exe. Defaults to the one on PATH or C:\zig\zig.exe.

.PARAMETER SourceDir
    Path to integrations/x64dbg-mcp-server-main. Defaults to the
    sibling of this script's parent.

.PARAMETER OutDir
    Output prefix directory. Defaults to <SourceDir>\dist.

.PARAMETER Target
    Comma-separated subset of {x64,x32,all}. Defaults to "all".

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build_x64dbg_mcp.ps1
    powershell -ExecutionPolicy Bypass -File build_x64dbg_mcp.ps1 -ZigPath C:\zig\zig.exe -Target x64
#>
[CmdletBinding()]
param(
    [string]$ZigPath = "",
    [string]$SourceDir = "",
    [string]$OutDir = "",
    [ValidateSet("x64","x32","all")]
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"

# --- Resolve paths ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $SourceDir) {
    $SourceDir = Resolve-Path (Join-Path $ScriptDir "..\integrations\x64dbg-mcp-server-main")
} else {
    $SourceDir = Resolve-Path $SourceDir
}
if (-not $OutDir) {
    $OutDir = Join-Path $SourceDir "dist"
}
if (-not $ZigPath) {
    $cmd = Get-Command zig -ErrorAction SilentlyContinue
    if ($cmd) { $ZigPath = $cmd.Path } else { $ZigPath = "C:\zig\zig.exe" }
}

function Log([string]$m) { Write-Host "[build_x64dbg_mcp] $m" }
function Die([string]$m) { Write-Error "[build_x64dbg_mcp] FATAL: $m"; exit 2 }

Log "Zig       = $ZigPath"
Log "SourceDir = $SourceDir"
Log "OutDir    = $OutDir"
Log "Target    = $Target"

if (-not (Test-Path $ZigPath)) { Die "zig not found: $ZigPath (install from https://ziglang.org/download/, 0.16-dev required)" }
if (-not (Test-Path (Join-Path $SourceDir "build.zig"))) { Die "build.zig missing in $SourceDir (run `git submodule update --init`?)" }
if (-not (Test-Path (Join-Path $SourceDir "build.zig.zon"))) { Die "build.zig.zon missing" }

$targets = @()
if ($Target -eq "all") { $targets = @("x64","x32") } else { $targets = @($Target) }

# The upstream build.zig builds BOTH x64 and x32 plugins in a single
# `zig build` — there is nothing target-specific to loop over. Run once
# and validate the outputs requested by -Target.
$old = Get-Location
try {
    Set-Location $SourceDir
    Log "running zig build -Doptimize=ReleaseSafe --prefix $OutDir"
    # Zig 0.16-dev: target triple. x64dbg plugins use a custom target JSON usually,
    # but the upstream build.zig picks the correct one via -Dcpu. We keep it simple.
    & $ZigPath build -Doptimize=ReleaseSafe --prefix $OutDir 2>&1 | ForEach-Object { Log "$_" }
    if ($LASTEXITCODE -ne 0) { Die "zig build failed rc=$LASTEXITCODE" }
} finally {
    Set-Location $old
}

# --- Verify outputs ---
$expected = @()
if ($Target -eq "all" -or $Target -eq "x64") {
    $expected += Join-Path $OutDir "x64\plugins\x64dbg-MCP-Server.dp64"
}
if ($Target -eq "all" -or $Target -eq "x32") {
    $expected += Join-Path $OutDir "x32\plugins\x64dbg-MCP-Server.dp32"
}
foreach ($e in $expected) {
    if (-not (Test-Path $e)) { Die "expected output missing: $e" }
    $sha = (Get-FileHash $e -Algorithm SHA256).Hash
    $size = (Get-Item $e).Length
    Log "OK  $e  size=$size  sha256=$sha"
}

Log "DONE. Next step: xcopy /E dist\x64\plugins\x64dbg-MCP-Server.dp64 C:\tools\x64dbg\x64\plugins\"
exit 0
