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

# Tool locations drift between FlareVM releases (2026 moved yara-x -> Tools\yara-x,
# UPX -> Tools\upx\upx-<ver>\, ilspycmd -> Tools\ilspycmd, Ghidra -> ProgramData).
function Resolve-Tool([string[]]$paths, [string[]]$names) {
    foreach ($p in $paths) { if ($p -and (Test-Path $p)) { return $p } }
    foreach ($n in $names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c -and $c.Source) { return $c.Source }
    }
    return $null
}
function Test-Tool([string]$label, [string[]]$paths, [string[]]$names, [string]$hint, [switch]$Optional) {
    $r = Resolve-Tool $paths $names
    if ($r) { Ok "$label -> $r" }
    elseif ($Optional) { Warn "$label missing ($hint)" }
    else { Fail "$label missing ($hint)" }
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
if (-not (Test-Path $py)) {
    $resolved = (& py -3.13 -c "import sys; print(sys.executable)" 2>$null)
    if ($resolved -and (Test-Path $resolved.Trim())) {
        $py = $resolved.Trim()
        Warn "python resolved via py -3.13 -> $py (preferred: C:\Python313 all-users)"
    }
}
if (Test-Path $py) {
    $v = & $py --version 2>&1
    Ok "python -> $py ($v)"
    # angr is deliberately NOT here: setup-flarevm.ps1 lists it in
    # $optionalMods (no offline wheel exists for it, so it cannot be
    # installed on the air-gapped asset set). It used to be checked here,
    # which made "0 FAIL" unreachable for a VM setup had legitimately
    # completed (code audit 2026-09-28). setup and verify must agree -
    # tests/test_tool_census.py asserts that they do.
    foreach ($mod in @("frida", "flask", "pefile", "psutil", "oletools",
                       "pypdf", "dnfile", "z3", "speakeasy", "mcp_windbg")) {
        # version probe must tolerate modules without __version__
        $mv = & $py -c "import importlib; m = importlib.import_module('$mod'); print(getattr(m, '__version__', 'import-ok'))" 2>$null
        if ($LASTEXITCODE -eq 0 -and $mv) { Ok "python module $mod == $mv" }
        else { Fail "python module $mod not importable (pip install $mod)" }
    }
    $angrVer = & $py -c "import angr, importlib.metadata as md; print(md.version('angr'))" 2>$null
    if ($LASTEXITCODE -eq 0 -and $angrVer) { Ok "python module angr == $($angrVer.Trim())" }
    else { Info "python module angr NOT installed - OPTIONAL by design (setup lists it in optionalMods: no offline wheel exists for the air-gapped asset set and the deep stage never imports it)" }
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
if (-not $ghidra) {
    # FlareVM 2026: the `ghidra` choco package installs under ProgramData
    $gdRoot = "C:\ProgramData\chocolatey\lib\ghidra\tools"
    if (Test-Path $gdRoot) {
        $ghidra = Get-ChildItem $gdRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object Name -match "^ghidra_\d" | Select-Object -First 1
    }
}
if ($ghidra) {
    Ok "Ghidra install -> $($ghidra.FullName)"
    $headless = Join-Path $ghidra.FullName "support\analyzeHeadless.bat"
    if (Test-Path $headless) { Ok "analyzeHeadless present" } else { Warn "analyzeHeadless.bat missing under $($ghidra.FullName)" }
    # Ghidra 12 needs JDK 21; FlareVM 2026 ships JDK 25 -> launcher hangs.
    $lp = Join-Path $ghidra.FullName "support\launch.properties"
    if (Test-Path $lp) {
        $ovr = (Select-String -Path $lp -Pattern "^JAVA_HOME_OVERRIDE=(.*)$" |
            Select-Object -First 1).Matches.Groups[1].Value
        if ($ovr -and (Test-Path $ovr)) { Ok "Ghidra JDK pinned -> $ovr" }
        else {
            $jvRaw = (& java -version 2>&1 | Select-Object -First 1) -replace '.*version "(\d+).*', '$1'
            if ($jvRaw -match '^\d+$' -and [int]$jvRaw -ge 21 -and [int]$jvRaw -le 24) {
                Ok "Ghidra JDK from PATH (java $jvRaw)"
            } else {
                Warn "Ghidra JAVA_HOME_OVERRIDE unset and java '$jvRaw' may be unsupported (Ghidra 12 wants 21) - analyzeHeadless can hang; run setup (pins temurin21)"
            }
        }
    }
    $loader = Get-ChildItem (Join-Path $ghidra.FullName "Ghidra\Extensions") -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match "CADRE" | Select-Object -First 1
    if ($loader) { Ok "CADRE PE loader extension -> $($loader.Name)" }
    else { Fail "CADRE PE loader extension not in Ghidra\Extensions (see docs\PREREQUISITES.md)" }
    # SQL-first gate: REAL engine only (LibGhidraHost + ghidrasql + JDK21 pin).
    if (Test-Path (Join-Path $ghidra.FullName "Ghidra\Extensions\LibGhidraHost")) {
        Ok "LibGhidraHost extension present"
    } else {
        Fail "LibGhidraHost extension missing - Ghidra SQL unavailable (run setup; docs\SQL-GHIDRA.md)"
    }
    if (Test-Path "C:\Tools\ghidrasql\ghidrasql.exe") {
        Ok "ghidrasql engine -> C:\Tools\ghidrasql\ghidrasql.exe"
        $grsVer = (& C:\Tools\ghidrasql\ghidrasql.exe --version 2>&1 | Select-Object -First 1)
        if ($grsVer) { Info "ghidrasql $($grsVer.Trim())" }
        # live SQL semantics check (WHERE + ORDER BY) on a small benign probe
        $probe = @("C:\samples\calc.exe", "C:\samples\notepad.exe") |
            Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $probe) {
            $probe = "C:\samples\_sqlprobe.exe"
            Copy-Item "$env:windir\system32\calc.exe" $probe -Force -EA SilentlyContinue
            $probe = if (Test-Path $probe) { $probe } else { $null }
        }
        if ($probe -and (Test-Path "C:\WinRE\tools\flare_ghidra_sql.py")) {
            $out = & $py "C:\WinRE\tools\flare_ghidra_sql.py" query `
                "SELECT name, size FROM funcs WHERE size > 150 ORDER BY size DESC LIMIT 3" `
                --file $probe 2>&1 | Out-String
            try { $j = $out | ConvertFrom-Json } catch { $j = $null }
            if ($j -and $j.ok) {
                $sizes = @()
                foreach ($row in @($j.rows)) { $sizes += [int](@($row)[-1]) }
                $sorted = $true
                for ($k = 1; $k -lt $sizes.Count; $k++) {
                    if ($sizes[$k] -gt $sizes[$k - 1]) { $sorted = $false; break }
                }
                $filtered = ($sizes.Count -gt 0) -and -not (@($sizes | Where-Object { $_ -le 150 }).Count -gt 0)
                if ($sorted -and $filtered) { Ok "Ghidra SQL semantics OK (WHERE/ORDER BY honored; $($sizes -join ', '))" }
                else { Fail "Ghidra SQL returned wrong semantics (sizes=[$($sizes -join ', ')] sorted=$sorted filtered=$filtered) - engine broken" }
            } else {
                $msg = if ($j) { $j.error } else { ($out.Trim() -split "`n" | Select-Object -Last 1) }
                Fail "Ghidra SQL live query failed: $($msg -replace '\s+',' ')"
            }
        } else { Warn "no benign probe sample available for the Ghidra SQL live check" }
    } else {
        Fail "ghidrasql engine missing - Ghidra SQL-first is NOT installed (run setup; docs\SQL-GHIDRA.md)"
    }
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
    if (-not (Test-Path $malcatPy)) { $malcatPy = $py }
    $licOut = & $malcatPy -c "import sys; sys.path.insert(0, r'$malcatBin'); import malcat; print(malcat.env.flavor)" 2>$null
    if ($licOut -match "FULL|OEM|PRO") { Ok "Malcat license ACTIVE ($($licOut.Trim()))" }
    elseif ($licOut) { Warn "Malcat flavor: $($licOut.Trim()) (unlicensed/limited - headless analysis degraded)" }
    else { Warn "could not query Malcat license flavor via $malcatPy" }
} else {
    # Malcat is COMMERCIAL-OPTIONAL: pipeline degrades to Ghidra-primary
    # with honest 'skipped' annotations. Not a readiness failure.
    Warn "Malcat not installed (OPTIONAL commercial) - place the portable folder at C:\Tools\malcat (keep folder name 'malcat'; bin\malcat.mcp.py) + activate license -> %APPDATA%\Malcat\license.dat"
}

Write-Host ""
Write-Host "--- IDA ---"
# Discovery MUST match setup-flarevm.ps1: when it does not, an operator who
# installed IDA Free (or pointed WINRE_IDA_DIR somewhere else) is told IDA
# is missing, the census calls it "operator-installed absent", and the SQL
# wiring gates that are OURS get skipped (code audit 2026-09-28).
$idaCands = @()
if ($env:WINRE_IDA_DIR) { $idaCands += $env:WINRE_IDA_DIR }
$idaCands += @("C:\Program Files\IDA Professional 9.3",
               "C:\Program Files\IDA Professional 9.2",
               "C:\Program Files\IDA Free 9.3",
               "C:\Program Files\IDA Professional 8.3",
               "C:\Tools\IDA Pro 9.3", "C:\Tools\IDA Free 9.3")
$idaDir = $idaCands | Where-Object {
    (Test-Path (Join-Path $_ "ida.exe")) -or (Test-Path (Join-Path $_ "idat.exe"))
} | Select-Object -First 1
if ($idaDir) { Ok "IDA -> $idaDir" }
else { Warn "IDA not found in any of: $($idaCands -join ', ') (operator-installed; deep stage degrades to Ghidra+Malcat)" }
if (Test-Path (Join-Path $idaDir "idasql.exe")) {
    Ok "idasql.exe present -> $(Join-Path $idaDir 'idasql.exe')"
    $idaProbe = @("C:\samples\calc.exe", "C:\samples\notepad.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $idaProbe) {
        # virgin VM: use a benign OS binary as the SQL probe (read-only copy)
        New-Item -ItemType Directory -Force -Path "C:\samples" | Out-Null
        Copy-Item "$env:windir\system32\notepad.exe" "C:\samples\_sqlprobe_ida.exe" -Force -EA SilentlyContinue
        if (Test-Path "C:\samples\_sqlprobe_ida.exe") { $idaProbe = "C:\samples\_sqlprobe_ida.exe" }
    }
    if (-not (Test-Path "C:\WinRE\tools\ida_sql_client.py")) {
        # OUR client, OUR wiring: a missing one is a broken deployment, not a
        # reason to skip the gate quietly - it used to, with no message at all
        Fail "IDA SQL client missing (C:\WinRE\tools\ida_sql_client.py) - re-run ops\sync_to_flare.ps1"
    } elseif (-not $idaProbe) {
        Fail "no benign probe sample for the IDA SQL live gate - stage one read-only in C:\samples"
    } else {
        $out = & $py "C:\WinRE\tools\ida_sql_client.py" query `
            "SELECT name, size FROM funcs WHERE size > 150 ORDER BY size DESC LIMIT 3" `
            --file $idaProbe 2>&1 | Out-String
        try { $j = $out | ConvertFrom-Json } catch { $j = $null }
        if ($j -and $j.ok) { Ok "IDA SQL live query OK (rows=$($j.row_count))" }
        else {
            $msg = if ($j) { $j.error } else { ($out.Trim() -split "`n" | Select-Object -Last 1) }
            # present-but-unwired is OUR bug, so it is a FAIL, not a warning
            Fail "IDA SQL live query failed: $($msg -replace '\s+',' ')"
        }
    }
} else { Warn "idasql.exe not found beside the IDA install (free release: github.com/allthingsida/idasql - provision_tools.ps1 auto-stages; the census makes this REQUIRED whenever IDA is present)" }

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
# x64dbg.exe (64-bit) only loads .dp64 - both arches must be present or
# :9094 never binds (2026-09-17 fresh-VM bug: dp32 satisfied the old check)
$plug64 = "C:\Tools\x64dbg\release\x64\plugins\x64dbg-MCP-Server.dp64"
$plug32 = "C:\Tools\x64dbg\release\x32\plugins\x64dbg-MCP-Server.dp32"
if (Test-Path $plug64) { Ok "MCP plugin dp64 -> $plug64" }
else { Fail "x64dbg MCP dp64 plugin missing ($plug64) - :9094 cannot bind" }
if (Test-Path $plug32) { Ok "MCP plugin dp32 -> $plug32" }
else { Warn "MCP plugin dp32 missing ($plug32) - x32dbg debug loop unavailable" }
$fwName = "WinRE x64dbg MCP (lab subnet)"
$fw = Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue
if ($fw) { Ok "firewall: :9094 scoped to LocalSubnet ($($fw.Enabled))" }
else { Fail "no firewall rule '$fwName' for :9094 - the port is reachable on ALL interfaces (docs/INSTALL.md promises setup creates this)" }

Write-Host ""
Write-Host "--- Dynamic prerequisites ---"
Test-Tool "FakeNet-NG" @("C:\Tools\fakenet\fakenet3.5\fakenet.exe") @("fakenet.exe") "docs\PREREQUISITES.md"
Test-Tool "Procmon" @("C:\Tools\sysinternals\Procmon64.exe") @("Procmon64.exe") "run install\flarevm\flarevm-postfix.ps1 (docs\PREREQUISITES.md)"
Test-Tool "pe-sieve" @("C:\ProgramData\chocolatey\bin\pe-sieve.exe") @("pe-sieve.exe", "pe-sieve64.exe") "choco install pe-sieve"
Test-Tool "hollows_hunter" @("C:\Tools\hollows_hunter\hollows_hunter.exe") @("hollows_hunter.exe", "hollows_hunter64.exe") "docs\PREREQUISITES.md"
Test-Tool "Procdump" @("C:\Tools\sysinternals\Procdump64.exe", "C:\Tools\sysinternals\procdump64.exe") @("procdump64.exe", "procdump.exe") "Sysinternals (post-mortem harvest)"
Test-Tool "cdb (classic debugger)" @("C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe", "C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe") @("cdb.exe") "install\flarevm\flarevm-postfix.ps1 - FlareVM 2026 ships Store WinDbg only"
Test-PathOk "C:\samples" "samples dir" "mkdir C:\samples"

Write-Host ""
Write-Host "--- Free static tooling ---"
Test-Tool "capa" @("C:\Tools\capa\capa.exe") @("capa.exe") "FlareVM base / pip fallback"
Test-Tool "capa-rules dir" @("C:\Tools\capa-rules") @() "mandiant/capa-rules (ops\provision_tools.ps1)"
Test-Tool "diec (Detect It Easy)" @("C:\Tools\die\diec.exe") @("diec.exe") "FlareVM base / provision_tools.ps1"
Test-Tool "yara-x" @("C:\Tools\yr\yr.exe", "C:\Tools\yara-x\yr.exe") @("yr.exe", "yara-x.exe") "FlareVM base / provision_tools.ps1"
Test-Tool "yara-rules dir" @("C:\Tools\yara-rules") @() "stage curated rules (operator)"
Test-Tool "scdbg" @("C:\Tools\scdbg\scdbg.exe") @("scdbg.exe") "FlareVM base"
$upxHit = Resolve-Tool @("C:\Tools\upx\upx.exe") @("upx.exe")
if (-not $upxHit) {
    $upxHit = Get-ChildItem "C:\Tools\upx" -Recurse -Filter "upx.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}
if ($upxHit) { Ok "UPX -> $upxHit" } else { Fail "UPX missing (FlareVM base / provision_tools.ps1)" }
Test-Tool "radare2" @("C:\Tools\radare2\radare2.exe") @("radare2.exe", "r2.exe") "ops\provision_tools.ps1 (required: r2_decompile + sink_sites)"
# r2 smoke: an installed-but-broken r2 must fail HERE, not mid-pipeline
$r2Hit = Resolve-Tool @("C:\Tools\radare2\radare2.exe") @("radare2.exe", "r2.exe")
if ($r2Hit) {
    $r2v = (& $r2Hit -v 2>&1 | Select-Object -First 1)
    if ($r2v -match "radare2") { Ok "radare2 smoke: $($r2v.Trim())" }
    else { Fail "radare2 present but not runnable: $r2Hit" }
}
# sink_sites smoke (r2-assisted deep tool): catches r2-integration regressions
$probeSql = @("C:\samples\calc.exe", "C:\samples\notepad.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $probeSql -and (Test-Path "C:\samples\_sqlprobe.exe")) { $probeSql = "C:\samples\_sqlprobe.exe" }
if ($r2Hit -and $probeSql -and (Test-Path "C:\WinRE\tools\kb_gap_tools.py")) {
    $sinkOut = (& $py "C:\WinRE\tools\kb_gap_tools.py" sink_sites $probeSql --json 2>&1 | Out-String)
    try { $sj = $sinkOut | ConvertFrom-Json } catch { $sj = $null }
    if ($sj -and $sj.ok) { Ok "sink_sites smoke OK (functions_scanned=$($sj.functions_scanned))" }
    else {
        $m = if ($sj) { $sj.error } else { "$sinkOut" }
        Fail "sink_sites smoke failed: $($m -replace '\s+',' ')".Substring(0, [Math]::Min(220, "sink_sites smoke failed: $($m -replace '\s+',' ')".Length))
    }
}
Test-Tool "goresym" @("C:\Tools\goresym\goresym.exe", "C:\Tools\GoReSym\GoReSym.exe") @("GoReSym.exe", "goresym.exe") "hasherezade releases (Go only)"
Test-Tool "strings64" @("C:\Tools\sysinternals\strings64.exe") @("strings64.exe") "run install\flarevm\flarevm-postfix.ps1 (FlareVM base)"
$ilspyHit = Resolve-Tool @("$env:USERPROFILE\.dotnet\tools\ilspycmd.exe", "C:\Tools\ilspycmd\ilspycmd.exe") @("ilspycmd.exe")
if ($ilspyHit) { Ok "ilspycmd (.NET) -> $ilspyHit" }
else { Warn "ilspycmd missing (dotnet tool install -g ilspycmd) - .NET decompile degrades" }
if (Test-Path "C:\Program Files\7-Zip\7z.exe") { Ok "7-Zip present" }
else { Warn "7-Zip missing - DFIR-Nexus case packs fall back to .zip" }
if (Test-Path "C:\Program Files\Wireshark\tshark.exe") { Ok "tshark present" }
else { Warn "tshark missing - beacon/pcap analysis degrades" }

Write-Host ""
Write-Host "--- MCP plane ---"
$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in 9009, 9094, 9097 }
# A listening socket is not proof of life: an unrelated or unlicensed
# listener satisfies a port check, and that is exactly how a deployment
# initialize request and require bytes back (code audit 2026-09-28).
function Test-McpHandshake([int]$Port, [int]$TimeoutMs = 4000) {
    try {
        $cli = New-Object System.Net.Sockets.TcpClient
        $iar = $cli.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $cli.Close(); return $false }
        $cli.EndConnect($iar)
        $st = $cli.GetStream()
        $st.ReadTimeout = $TimeoutMs
        $req = '{"jsonrpc":"2.0","id":1,"method":"initialize",' +
               '"params":{"protocolVersion":"2024-11-05","capabilities":{},' +
               '"clientInfo":{"name":"winre-verify","version":"1.0"}}}' + [char]10
        $by = [Text.Encoding]::UTF8.GetBytes($req)
        $st.Write($by, 0, $by.Length)
        $buf = New-Object byte[] 4096
        $n = $st.Read($buf, 0, $buf.Length)
        $cli.Close()
        return ($n -gt 0)
    } catch { return $false }
}
foreach ($p in @(@{n = "Malcat"; port = 9009; required = [bool]$malcatBin },
                 @{n = "x64dbg"; port = 9094; required = $false },
                 @{n = "WinDbg"; port = 9097; required = $true })) {
    $hit = $ports | Where-Object LocalPort -eq $p.port | Select-Object -First 1
    if (-not $hit) {
        if ($p.required) { Fail "$($p.n) MCP NOT listening :$($p.port) - start via install\install_mcp_autostart.ps1" }
        else { Warn "$($p.n) MCP NOT listening :$($p.port) (on-demand: the x64dbg manager starts it)" }
        continue
    }
    if (Test-McpHandshake $p.port) { Ok "$($p.n) MCP ANSWERING :$($p.port) (pid $($hit.OwningProcess); initialize got a reply)" }
    elseif ($p.required) { Fail "$($p.n) MCP socket open but DEAD: no reply to an initialize request on :$($p.port)" }
    else { Warn "$($p.n) MCP socket open but silent on :$($p.port)" }
}
$bootTask = Get-ScheduledTask -TaskName "WinRE-MCP-Boot" -ErrorAction SilentlyContinue
if ($bootTask) { Ok "scheduled task WinRE-MCP-Boot present (state=$($bootTask.State)) - this is what serves :9009/:9097 after a revert" }
else { Fail "scheduled task WinRE-MCP-Boot absent - after a revert nothing restarts the MCP plane (re-run install\install_mcp_autostart.ps1)" }

Write-Host ""
Write-Host "--- Autostart / boot persistence ---"
$startup = [Environment]::GetFolderPath("Startup")
if (Test-Path (Join-Path $startup "WinRE-MCP.cmd")) { Ok "Startup launcher -> WinRE-MCP.cmd" }
else { Warn "Startup launcher missing (run install\install_mcp_autostart.ps1)" }
$task = Get-ScheduledTask -TaskName "WinRE-X64dbg-Once" -ErrorAction SilentlyContinue
if ($task) {
    $rl = "$($task.Principal.RunLevel)"
    if ($rl -eq "Highest") { Ok "scheduled task WinRE-X64dbg-Once present (RunLevel=Highest - elevated, no UAC prompt)" }
    else { Warn "WinRE-X64dbg-Once RunLevel=$rl (re-register via x64dbg_manager for elevation without prompts)" }
}
else { Info "scheduled task WinRE-X64dbg-Once absent (created on demand by the x64dbg manager, RunLevel=Highest)" }

Write-Host ""
Write-Host "--- UAC / debugger elevation ---"
$lua = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($lua -eq 0) { Ok "UAC disabled (EnableLUA=0) - x64dbg manual launches run elevated silently" }
else { Warn "UAC enabled - task launches are elevated silently; manual x64dbg launches may prompt (setup -DisableUAC + reboot to silence)" }

Write-Host ""
Write-Host "--- Snapshot gate ---"
if (Test-Path "C:\WinRE\.clean_snapshot") {
    Ok "clean-snapshot marker present (bake it into the VM snapshot)"
    $mc = Get-Content "C:\WinRE\.clean_snapshot" -Raw -ErrorAction SilentlyContinue
    if ($mc -and $mc.Trim()) { Info "marker content: $($mc.Trim())" }
} else { Info "no clean-snapshot marker (create with: New-Item C:\WinRE\.clean_snapshot -ItemType File, then re-snapshot)" }

Write-Host ""
Write-Host "--- LLM config (control-plane concern) ---"
if (Test-Path "C:\WinRE\.env") { Info "C:\WinRE\.env present (unused on the VM - LLM runs on the control plane)" }
else { Info "no C:\WinRE\.env (fine - LLM config lives on the control plane via .env)" }

# --- REQUIRED TOOL CENSUS -------------------------------------------------
# Operator directive, encoded so it cannot be forgotten:
#
#   * The USER installs and ACTIVATES the licensed binaries: IDA Pro and
#     Malcat. If they are absent, that is an operator state, never our
#     failure - and never a silent skip: it is reported by name.
#   * EVERYTHING ELSE is ours - present in the FlareVM base or installed /
#     configured by setup-flarevm.ps1. Nothing may be skipped: a missing tool
#     we own is a FAIL, not a warning.
#   * The SQL and MCP WIRING around the user's binaries is OURS: if IDA Pro is
#     installed, idasql must be discoverable (and the live SQL gate above must
#     pass); if Malcat is installed, its MCP must answer. A licensed tool that
#     is present but not wired is OUR bug -> FAIL, not a skip.
#
# Three classes:
#   ours     - always required; absent = FAIL
#   user     - the licensed binary; absent = INFO (operator has not installed)
#   ours-if  - our wiring; required only when its user tool is present
$script:ReqTotal = 0
$script:ReqOk = 0
$script:ReqUserAbsent = @()
$script:ReqMissing = @()

function Test-Required {
    param(
        [string]$Name,
        [string[]]$Paths = @(),
        [string[]]$Names = @(),
        [string]$Provider = "setup-flarevm.ps1",
        [ValidateSet("ours", "user")][string]$Class = "ours"
    )
    $script:ReqTotal++
    $resolved = Resolve-Tool $Paths $Names
    if ($resolved) {
        $script:ReqOk++
        Ok "  [census] $Name -> $resolved"
        return $true
    }
    if ($Class -eq "user") {
        $script:ReqUserAbsent += $Name
        Info "  [census] $Name absent - operator installs + activates this one (not our skip)"
    } else {
        $script:ReqMissing += $Name
        Fail "  [census] REQUIRED and missing: $Name ($Provider)"
    }
    return $false
}

Write-Host ""
Write-Host "--- required tool census (nothing may be skipped) ---"

# --- our tools: base-provided or installed by setup ------------------------
Test-Required "Ghidra"          @("C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_*_PUBLIC\ghidraRun.bat", "C:\Tools\ghidra_*_PUBLIC\ghidraRun.bat") @() "FlareVM base / choco (setup)"
Test-Required "ghidrasql"       @("C:\Tools\ghidrasql\ghidrasql.exe") @() "ops\provision_tools.ps1 (C:\Tools-staged\sql)"
Test-Required "LibGhidraHost"   @("C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_*_PUBLIC\Ghidra\Extensions\LibGhidraHost", "C:\Tools\ghidra_*_PUBLIC\Ghidra\Extensions\LibGhidraHost") @() "ops\provision_tools.ps1"
Test-Required "Java 21"         @("C:\Program Files\Eclipse Adoptium\jdk-21*", "C:\Program Files\Java\*21*") @("java") "choco temurin21 (setup)"
Test-Required "capa"            @("C:\Tools\capa\capa.exe") @("capa") "FlareVM base / pip fallback"
Test-Required "capa-rules"      @("C:\Tools\capa-rules") @() "ops\provision_tools.ps1"
Test-Required "floss"           @("C:\Tools\FLOSS\floss.exe") @("floss") "pip flare-floss (setup)"
Test-Required "diec"            @("C:\Tools\die\diec.exe") @("diec") "FlareVM base / provision_tools"
Test-Required "yara-x"          @("C:\Tools\yr\yr.exe", "C:\Tools\yara-x\yr.exe") @("yr", "yara-x") "FlareVM base / provision_tools"
Test-Required "yara-rules"      @("C:\Tools\yara-rules") @() "ops\reapply_after_revert.ps1 (step 4)"
Test-Required "strings64"       @("C:\Tools\sysinternals\strings64.exe") @() "FlareVM base"
Test-Required "radare2"         @("C:\Tools\radare2\radare2.exe") @("radare2", "r2") "ops\provision_tools.ps1"
Test-Required "scdbg"           @("C:\Tools\scdbg\scdbg.exe") @() "FlareVM base"
Test-Required "UPX"             @("C:\Tools\upx") @("upx") "FlareVM base"
Test-Required "GoReSym"         @("C:\Tools\goresym\goresym.exe", "C:\Tools\GoReSym\GoReSym.exe") @() "FlareVM base / provision_tools"
Test-Required "ilspycmd"        @("C:\ProgramData\chocolatey\bin\ilspycmd.exe", "$env:USERPROFILE\.dotnet\tools\ilspycmd.exe", "C:\Tools\ilspycmd\ilspycmd.exe") @("ilspycmd") "FlareVM base / provision_tools"
Test-Required "zig"             @("C:\Tools\zig\zig.exe") @("zig") "ops\provision_tools.ps1 (dp64/dp32 build)"
Test-Required "x64dbg"          @("C:\Tools\x64dbg\release\x64\x64dbg.exe", "C:\Tools\x64dbg\x64dbg.exe") @() "FlareVM base"
Test-Required "x64dbg MCP dp64" @("C:\Tools\x64dbg\release\x64\plugins\x64dbg-MCP-Server.dp64") @() "zig build + setup deploy (ours)"
Test-Required "FakeNet-NG"      @("C:\Tools\fakenet\fakenet3.5\fakenet.exe") @("fakenet") "FlareVM base"
Test-Required "Procmon"         @("C:\Tools\sysinternals\Procmon64.exe") @() "FlareVM base"
Test-Required "pe-sieve"        @("C:\ProgramData\chocolatey\bin\pe-sieve.exe") @("pe-sieve", "pe-sieve64.exe") "choco / FlareVM base"
Test-Required "hollows_hunter"  @("C:\Tools\hollows_hunter\hollows_hunter.exe") @() "FlareVM base"
Test-Required "Procdump"        @("C:\Tools\sysinternals\Procdump64.exe") @() "FlareVM base"
Test-Required "tshark"          @("C:\Program Files\Wireshark\tshark.exe") @("tshark") "FlareVM base"
Test-Required "7-Zip"           @("C:\Program Files\7-Zip\7z.exe") @("7z") "FlareVM base"
Test-Required "cdb/WinDbg"      @("C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe", "C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe") @() "FlareVM base / flarevm-postfix"
# $py is the RESOLVED interpreter (default path, or the py -3.13 fallback), so
# this passes on a box where Python does not live at C:\Python313.
Test-Required "Python 3.13"     @($py) @() "choco python313 (setup)"

# --- python modules (installed offline from staged wheels by setup) ---------
if (Test-Path $py) {
    foreach ($m in @("frida", "flask", "pefile", "psutil", "oletools", "pypdf",
                     "dnfile", "z3", "speakeasy", "mcp_windbg", "floss")) {
        $script:ReqTotal++
        & $py -c "import $m" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $script:ReqOk++
            Ok "  [census] py:$m"
        } else {
            $script:ReqMissing += "py:$m"
            Fail "  [census] REQUIRED python module missing: $m (setup installs from C:\Tools-staged\wheels)"
        }
    }
}

# --- user-installed licensed binaries (operator installs + activates) -------
# same candidate list as the IDA section above and as setup, so an
# install that verify can see is never reported as absent
# keep this on ONE line: a PowerShell command cannot span lines without a
# continuation, and a split call silently loses its arguments
$idaBin = Test-Required "IDA Pro (licensed)" @("C:\Program Files\IDA Professional 9.3\idat.exe", "C:\Program Files\IDA Professional 9.2\idat.exe", "C:\Program Files\IDA Free 9.3\ida.exe", "C:\Program Files\IDA Professional 8.3\idat.exe", "C:\Tools\IDA Pro 9.3\idat.exe", "C:\Tools\IDA Free 9.3\ida.exe") @() "operator installs + activates" -Class user
# the Downloads location setup/start_servers also accept: without it a
# portable install is reported absent and the :9009 wiring gate is skipped
$malcatBin = Test-Required "Malcat (licensed)" @("C:\Tools\malcat\bin\malcat.mcp.py", "C:\Program Files\Malcat\bin\malcat.mcp.py", "$env:USERPROFILE\Downloads\malcat\bin\malcat.mcp.py") @() "operator installs + activates" -Class user

# --- OUR wiring around the user's binaries: required whenever they exist ---
$script:ReqTotal++
if ($idaBin) {
    $idasql = Resolve-Tool @($env:WINRE_IDASQL, $env:IDASQL,
                             "C:\Program Files\IDA Professional 9.3\idasql.exe",
                             "C:\Program Files\IDA Professional 9.2\idasql.exe") @("idasql.exe")
    if ($idasql) {
        $script:ReqOk++
        Ok "  [census] idasql (our SQL wiring) -> $idasql"
    } else {
        $script:ReqMissing += "idasql"
        Fail "  [census] IDA Pro is installed but idasql.exe is not discoverable - our job: set IDASQL/WINRE_IDASQL (the live SQL gate above also has to pass)"
    }
} else {
    $script:ReqOk++
    Info "  [census] idasql wiring not applicable (operator has not installed IDA Pro)"
}
$script:ReqTotal++
if ($malcatBin) {
    $mcpUp = Get-NetTCPConnection -State Listen -LocalPort 9009 -ErrorAction SilentlyContinue
    if ($mcpUp) {
        $script:ReqOk++
        Ok "  [census] Malcat MCP :9009 answering (our wiring)"
    } else {
        $script:ReqMissing += "Malcat MCP :9009"
        Fail "  [census] Malcat is installed but its MCP is NOT answering :9009 - our wiring (install\install_mcp_autostart.ps1, winre\mcp\start_servers.ps1)"
    }
} else {
    $script:ReqOk++
    Info "  [census] Malcat MCP wiring not applicable (operator has not installed Malcat)"
}

Write-Host ""
if ($script:ReqMissing.Count -eq 0) {
    $ua = if ($script:ReqUserAbsent.Count) { $script:ReqUserAbsent -join ", " } else { "none" }
    Ok ("census: {0}/{1} required present | operator-installed absent: {2} ({3}) | SKIPPED BY US: 0" -f `
        $script:ReqOk, $script:ReqTotal, $script:ReqUserAbsent.Count, $ua)
} else {
    Fail ("census: {0}/{1} required present | SKIPPED BY US: {2} -> {3}" -f `
        $script:ReqOk, $script:ReqTotal, $script:ReqMissing.Count, ($script:ReqMissing -join ", "))
}

Write-Host ""
Write-Host "--- clock (control-plane skew diagnosis) ---"
# RevAI handoff 2026-09-27 item 4: freshness no longer compares clocks
# (winre/run_nonce.py), so this is a DIAGNOSTIC gate: a stopped w32time is a
# WARN (it makes every timestamp in the pack untrustworthy for a human
# reading them), never a FAIL. Read-only: verify stays side-effect free.
$w32 = Get-Service -Name w32time -ErrorAction SilentlyContinue
if ($w32 -and $w32.Status -eq "Running") {
    $q = (& w32tm.exe /query /status 2>&1 | Out-String)
    $src = if ($q -match "Source:") { ($q -split "Source:")[1] -split "`r?`n" | Select-Object -First 1 } else { "?" }
    Ok ("w32time running (source: {0}); vm now {1}" -f $src.Trim(), (Get-Date -Format o))
} elseif ($w32) {
    Warn ("w32time stopped (startup={0}) - run setup or: Set-Service w32time -StartupType Automatic; w32tm /resync /force" -f $w32.StartType)
} else {
    Warn "w32time service not found"
}
if (Test-Path "C:\WinRE\vm_clock.json") { Ok "clock state file C:\WinRE\vm_clock.json present" }
else { Warn "clock state file missing (re-run install/setup-flarevm.ps1)" }

Write-Host ""
Write-Host "--- cleanup (verify must not dirty the image) ---"
# The SQL live gates stage probe samples and leave per-project servers/caches
# behind. A verify run must be side-effect free so a golden snapshot stays
# clean (found 2026-09-19: _sqlprobe* + cache\ghidra + server logs remained).
# Kill the per-project SQL servers FIRST - a live server recreates its
# project dir and log immediately after deletion.
Get-Process ghidrasql, idasql -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-ChildItem "C:\samples" -Filter "_sqlprobe*" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item "C:\WinRE\cache\ghidra\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\WinRE\logs\ghidrasql-servers.json",
            "C:\WinRE\logs\ghidrasql-server.log",
            "C:\WinRE\logs\idasql-server.log",
            "C:\WinRE\logs\ghidra-sql-audit.jsonl",
            "C:\WinRE\logs\ida-sql-audit.jsonl" `
            -Force -ErrorAction SilentlyContinue
# bytecode caches are not evidence either: the SQL/MCP helpers recreate them on
# every run, so a verify would otherwise bake one into a golden snapshot
Get-ChildItem "C:\WinRE" -Recurse -Directory -Filter "__pycache__" `
    -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
if (@(Get-ChildItem "C:\samples" -Filter "_sqlprobe*" -ErrorAction SilentlyContinue).Count -eq 0) {
    Ok "probe artifacts + SQL runtime state cleaned (samples/cache/logs/pycache)"
} else {
    Warn "probe artifacts still present under C:\samples"
}

Write-Host ""
Write-Host "=== Summary: $($script:ERR) FAIL, $($script:WARN) WARN ===" -ForegroundColor Cyan
if ($script:ERR -gt 0) { exit 1 } else { exit 0 }
