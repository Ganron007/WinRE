#Requires -Version 5.1
<#
.SYNOPSIS
    WinRE MCP launcher — starts the WinRE MCP servers for agentic use.

.DESCRIPTION
    Run on the FlareVM console (interactive session). Starts:
      - Malcat MCP     :9009 (malcat.mcp.py -p 9009 [-k $MALCAT_KEY])
      - x64dbg-MCP     :9094 (in-process, when x64dbg is opened)
      - WinDbg MCP     :9097 (mcp_windbg --transport streamable-http)
    Each in its own window so the operator sees logs. Ctrl+C closes.

    Usage:
      powershell -ExecutionPolicy Bypass -File C:\WinRE\winre\mcp\start_servers.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\WinRE\winre\mcp\start_servers.ps1
#>
param(
    [int]$MalcatPort = 9009,
    [int]$WinDbgPort = 9097
)

$ErrorActionPreference = "Continue"
$WinRE = "C:\WinRE"

Write-Host "[winre-mcp] starting WinRE MCP servers..." -ForegroundColor Cyan

# --- Malcat MCP (headless, 45 tools) ---
$malcatBin = "C:\Users\flare-vm\Downloads\malcat\bin\malcat.mcp.py"
if (-not (Test-Path $malcatBin)) { $malcatBin = "C:\tools\malcat\bin\malcat.mcp.py" }
if (Test-Path $malcatBin) {
    $key = ""
    if (Test-Path "$WinRE\.env") {
        $line = Select-String -Path "$WinRE\.env" -Pattern "^MALCAT_KEY=" | Select-Object -First 1
        if ($line) { $key = ($line.Line -split "=",2)[1].Trim() }
    }
    $args = @("-p", "$MalcatPort")
    if ($key) { $args += @("-k", $key) }
    Start-Process powershell -ArgumentList @("-NoProfile","-Command",
        "& C:\Python313\python.exe `"$malcatBin`" $($args -join ' ')") -WindowStyle Normal
    Write-Host "[winre-mcp] Malcat MCP -> http://127.0.0.1:$MalcatPort/mcp (key: $(if($key){'set'}else{'none'}))" -ForegroundColor Green
} else {
    Write-Host "[winre-mcp] WARN: malcat.mcp.py not found — skipping Malcat MCP" -ForegroundColor Yellow
}

# --- WinDbg MCP (mcp_windbg, 10 tools, dump/kernel/remote) ---
Start-Process powershell -ArgumentList @("-NoProfile","-Command",
    "C:\Python313\python.exe -u -m mcp_windbg --transport streamable-http --host 127.0.0.1 --port $WinDbgPort") -WindowStyle Normal
Write-Host "[winre-mcp] WinDbg MCP -> http://127.0.0.1:$WinDbgPort/mcp" -ForegroundColor Green

# --- x64dbg-MCP (in-process — tell operator to open x64dbg) ---
Write-Host "[winre-mcp] x64dbg-MCP -> open x64dbg (C:\tools\x64dbg\release\x64\x64dbg.exe); plugin auto-starts :9094" -ForegroundColor Green

Write-Host "[winre-mcp] done. Ctrl+C in each window to stop." -ForegroundColor Cyan
