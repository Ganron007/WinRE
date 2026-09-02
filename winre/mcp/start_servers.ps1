#Requires -Version 5.1
<#
.SYNOPSIS
    WinRE MCP launcher — starts the WinRE MCP servers for agentic use.

.DESCRIPTION
    Boot-safe launcher: checks each port before starting (idempotent), so it
    can run at every logon (Startup folder) without duplicate servers. Starts:
      - Malcat MCP     :9009 (malcat.mcp.py -p 9009 [-k $MALCAT_KEY])
      - WinDbg MCP     :9097 (mcp_windbg --transport streamable-http)
      - x64dbg-MCP     :9094 (optional: launches x64dbg GUI whose plugin
                               auto-starts the MCP server on :9094)
    Servers run hidden (boot-friendly); logs go to C:\WinRE\logs\mcp\.

    Usage:
      powershell -ExecutionPolicy Bypass -File C:\WinRE\winre\mcp\start_servers.ps1
      powershell ... -NoX64dbg        # skip launching x64dbg GUI
      powershell ... -Foreground      # show server windows (debugging)
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\WinRE\winre\mcp\start_servers.ps1 -NoX64dbg
#>
param(
    [int]$MalcatPort = 9009,
    [int]$WinDbgPort = 9097,
    [int]$X64dbgPort = 9094,
    [switch]$NoX64dbg,
    [switch]$Foreground
)

$ErrorActionPreference = "Continue"
$WinRE = "C:\WinRE"
$LogDir = "$WinRE\logs\mcp"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"

function Test-Port([int]$port) {
    $c = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    return [bool]$c
}

function Start-Hidden([string]$file, [string[]]$argsList, [string]$name, [int]$port) {
    if (Test-Port $port) {
        Write-Host "[winre-mcp] $name already up on :$port — skip" -ForegroundColor Yellow
        return
    }
    $win = "Hidden"
    if ($Foreground) { $win = "Normal" }
    $log = Join-Path $LogDir "$name-$ts.log"
    # Redirect *> only works in PS; for hidden windows we capture via
    # Start-Process -RedirectStandardOutput when not foreground.
    $p = Start-Process -FilePath $file -ArgumentList $argsList -PassThru `
        -WindowStyle $win
    if (-not $Foreground) {
        Start-Sleep -Milliseconds 500
    }
    Write-Host "[winre-mcp] $name starting -> :$port (pid $($p.Id))" -ForegroundColor Green
}

Write-Host "[winre-mcp] starting WinRE MCP servers (boot-safe)..." -ForegroundColor Cyan

# --- Malcat MCP (headless, 45 tools) ---
$malcatBin = "C:\Users\flare-vm\Downloads\malcat\bin\malcat.mcp.py"
if (-not (Test-Path $malcatBin)) { $malcatBin = "C:\tools\malcat\bin\malcat.mcp.py" }
if (Test-Path $malcatBin) {
    $key = ""
    if (Test-Path "$WinRE\.env") {
        $line = Select-String -Path "$WinRE\.env" -Pattern "^MALCAT_KEY=" | Select-Object -First 1
        if ($line) { $key = ($line.Line -split "=",2)[1].Trim() }
    }
    $argsList = @($malcatBin, "-p", "$MalcatPort")
    if ($key) { $argsList += @("-k", $key) }
    Start-Hidden "C:\Python313\python.exe" $argsList "malcat" $MalcatPort
} else {
    Write-Host "[winre-mcp] WARN: malcat.mcp.py not found — skipping Malcat MCP" -ForegroundColor Yellow
}

# --- WinDbg MCP (mcp_windbg, 10 tools, dump/kernel/remote) ---
Start-Hidden "C:\Python313\python.exe" @("-u", "-m", "mcp_windbg",
    "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "$WinDbgPort") `
    "windbg" $WinDbgPort

# --- x64dbg-MCP (plugin auto-starts :9094 when x64dbg opens) ---
if (-not $NoX64dbg) {
    if (-not (Test-Port $X64dbgPort)) {
        $x64 = "C:\tools\x64dbg\release\x64\x64dbg.exe"
        if (Test-Path $x64) {
            Start-Process $x64 -WindowStyle Minimized | Out-Null
            Write-Host "[winre-mcp] x64dbg launching (plugin -> :$X64dbgPort)" -ForegroundColor Green
        } else {
            Write-Host "[winre-mcp] WARN: x64dbg not found at $x64 — :$X64dbgPort unavailable" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[winre-mcp] x64dbg MCP already up on :$X64dbgPort — skip" -ForegroundColor Yellow
    }
} else {
    Write-Host "[winre-mcp] x64dbg skipped (-NoX64dbg)" -ForegroundColor Yellow
}

Start-Sleep -Seconds 3
Write-Host "[winre-mcp] done. Ports: malcat=$((Test-Port $MalcatPort)) windbg=$((Test-Port $WinDbgPort)) x64dbg=$((Test-Port $X64dbgPort))" -ForegroundColor Cyan
