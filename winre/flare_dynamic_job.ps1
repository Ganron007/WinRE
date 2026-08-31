#Requires -Version 5.1
param(
  [Parameter(Mandatory = $true)][string]$Sha256,
  [string]$SamplePath = "",
  [int]$MaxSeconds = 45,
  [string]$WorkRoot = "",
  [string]$Python = "C:\Python313\python.exe",
  [string]$FridaScript = "C:\Tools\flarevm-deploy\dynamic\frida_api_trace.py",
  [string]$FakeNetExe = "C:\Tools\fakenet\fakenet3.5\fakenet.exe",
  [string]$ProcmonExe = "C:\Tools\sysinternals\Procmon64.exe",
  [string]$PeSieveExe = "C:\ProgramData\chocolatey\bin\pe-sieve.exe",
  [string]$HollowsHunterExe = "C:\Tools\hollows_hunter\hollows_hunter.exe",
  [switch]$EnablePeSieve,
  [string]$Apis = "CreateFileW,WriteFile,ReadFile,DeleteFileW,RegOpenKeyExW,RegSetValueExW,VirtualAlloc,VirtualProtect,WriteProcessMemory,CreateRemoteThread,WinHttpOpen,InternetOpenW,connect,send,recv,LoadLibraryW,GetProcAddress,CreateProcessW"
)

$ErrorActionPreference = "Continue"
$Sha256 = $Sha256.Trim().ToLower()
if (-not $WorkRoot) { $WorkRoot = "C:\samples\$Sha256" }
if (-not $SamplePath) { $SamplePath = Join-Path $WorkRoot "sample.exe" }

$OutDir = Join-Path $WorkRoot "out"
$LogFile = Join-Path $WorkRoot "job.log"
$ZipPath = Join-Path $WorkRoot "artifacts.zip"

function Log {
  param([string]$Message)
  $line = "[{0}] {1}" -f (Get-Date -Format "o"), $Message
  Add-Content -Path $LogFile -Value $line -Encoding UTF8
  Write-Host $line
}

function Kill-Image {
  param([string]$Image)
  Start-Process -FilePath "taskkill.exe" -ArgumentList "/F","/IM",$Image,"/T" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
}

function Kill-Stale {
  foreach ($im in @("sample.exe","frida-helper-64.exe","frida-helper-32.exe","fakenet.exe","Procmon64.exe","Procmon.exe")) {
    Kill-Image $im
  }
  Start-Sleep -Seconds 1
}

function Snapshot-Processes {
  param([string]$Label)
  $rows = @()
  try {
    $rows = @(Get-CimInstance Win32_Process | ForEach-Object {
      [pscustomobject]@{
        label = $Label
        pid = $_.ProcessId
        ppid = $_.ParentProcessId
        name = $_.Name
        cmdline = $_.CommandLine
      }
    })
  } catch {
    $rows = @([pscustomobject]@{ label = $Label; error = "$_" })
  }
  return $rows
}

New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (Test-Path $LogFile) { Remove-Item $LogFile -Force }
Log "START sha=$Sha256 max_seconds=$MaxSeconds"
Log "sample=$SamplePath"

if (-not (Test-Path $SamplePath)) {
  Log "FATAL: sample missing"
  @{ ok = $false; error = "sample missing"; sha256 = $Sha256 } | ConvertTo-Json | Set-Content (Join-Path $OutDir "META.job.json")
  exit 2
}
foreach ($req in @(@{p=$Python;n="python"},@{p=$FridaScript;n="frida"},@{p=$FakeNetExe;n="fakenet"},@{p=$ProcmonExe;n="procmon"})) {
  if (-not (Test-Path $req.p)) {
    Log ("FATAL: {0} missing: {1}" -f $req.n, $req.p)
    exit 3
  }
}

Kill-Stale

$pre = Snapshot-Processes "pre"
$pre | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutDir "process_snapshot_pre.json") -Encoding UTF8
Log ("pre_snapshot processes={0}" -f $pre.Count)

$fnWork = Join-Path $WorkRoot "fakenet"
New-Item -ItemType Directory -Force -Path $fnWork | Out-Null
Copy-Item "C:\Tools\fakenet\fakenet3.5\configs\default.ini" (Join-Path $fnWork "default.ini") -Force
Log "starting FakeNet..."
$fnProc = $null
try {
  $fnProc = Start-Process -FilePath $FakeNetExe -WorkingDirectory $fnWork -PassThru -WindowStyle Minimized
  Start-Sleep -Seconds 4
  if ($fnProc.HasExited) {
    Log ("WARN: FakeNet exited early rc={0}" -f $fnProc.ExitCode)
    $fnProc = $null
  } else {
    Log ("FakeNet pid={0}" -f $fnProc.Id)
  }
} catch {
  Log "WARN: FakeNet start failed: $_"
  $fnProc = $null
}

$pml = Join-Path $OutDir "procmon.pml"
$csv = Join-Path $OutDir "procmon.csv"
if (Test-Path $pml) { Remove-Item $pml -Force -ErrorAction SilentlyContinue }
Log "starting Procmon"
Start-Process -FilePath $ProcmonExe -ArgumentList "/AcceptEula","/Terminate" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Seconds 1
$pmProc = Start-Process -FilePath $ProcmonExe -ArgumentList "/AcceptEula","/Quiet","/Minimized","/BackingFile",$pml -PassThru
Start-Sleep -Seconds 3
Log ("Procmon pid={0}" -f $pmProc.Id)

$trace = Join-Path $OutDir "frida_trace.jsonl"
$memDir = Join-Path $OutDir "memory"
$peSieveRan = $false
$peSievePid = $null
$peSieveRc = $null
Log ("Frida start EnablePeSieve={0}" -f [bool]$EnablePeSieve)
$fridaExit = -1
try {
  # Non-blocking Frida so we can pe-sieve mid-run when enabled
  $fridaProc = Start-Process -FilePath $Python -ArgumentList @(
    $FridaScript,
    "--target", $SamplePath,
    "--apis", $Apis,
    "--out", $trace,
    "--max-seconds", "$MaxSeconds",
    "--max-calls", "5000"
  ) -PassThru -NoNewWindow `
    -RedirectStandardError (Join-Path $OutDir "frida.stderr.txt") `
    -RedirectStandardOutput (Join-Path $OutDir "frida.stdout.txt")

  if ($EnablePeSieve) {
    New-Item -ItemType Directory -Force -Path $memDir | Out-Null
    # Wait for sample.exe to appear
    $deadline = (Get-Date).AddSeconds([Math]::Min(20, [Math]::Max(5, $MaxSeconds / 2)))
    while ((Get-Date) -lt $deadline) {
      $sp = Get-Process -Name "sample" -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($sp) {
        $peSievePid = $sp.Id
        break
      }
      Start-Sleep -Seconds 1
    }
    if ($peSievePid -and (Test-Path $PeSieveExe)) {
      Log ("pe-sieve /pid {0} /dir {1}" -f $peSievePid, $memDir)
      # Redirect each stream to a distinct file: with /json the report goes
      # to STDOUT; keeping them separate stops the CLI log from clobbering
      # the JSON report.
      $psReport = Join-Path $memDir "pe_sieve_report.json"
      $psLog = Join-Path $memDir "pe_sieve.stdout.txt"
      $psErr = Join-Path $memDir "pe_sieve.stderr.txt"
      $psProc = Start-Process -FilePath $PeSieveExe -ArgumentList @(
        "/pid", "$peSievePid",
        "/dir", $memDir,
        "/quiet",
        "/json",
        "/jlvl", "1",
        "/minidmp",
        "/refl",
        "/ofilter", "0",
        "/shellc", "A",
        "/data", "3",
        "/dnet", "4"
      ) -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $psLog `
        -RedirectStandardError $psErr
      $peSieveRc = $psProc.ExitCode
      $peSieveRan = $true
      # When /json is active pe-sieve writes the report to STDOUT, so make
      # pe_sieve_report.json the real JSON artifact.
      if ((Test-Path $psLog) -and ((Get-Item $psLog).Length -gt 0)) {
        Copy-Item $psLog $psReport -Force -ErrorAction SilentlyContinue
      }
      Log ("pe-sieve exit={0} report={1} log={2}" -f $peSieveRc, (Test-Path $psReport), (Test-Path $psLog))
      # Optional hollows_hunter on same PID (best-effort)
      if (Test-Path $HollowsHunterExe) {
        $hhOut = Join-Path $memDir "hollows_hunter"
        New-Item -ItemType Directory -Force -Path $hhOut | Out-Null
        Log ("hollows_hunter /pid {0}" -f $peSievePid)
        Start-Process -FilePath $HollowsHunterExe -ArgumentList @(
          "/pid", "$peSievePid",
          "/dir", $hhOut,
          "/quiet"
        ) -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
      }
    } else {
      Log ("WARN: pe-sieve skipped (pid={0} exe={1})" -f $peSievePid, (Test-Path $PeSieveExe))
    }
  }

  Wait-Process -Id $fridaProc.Id -ErrorAction SilentlyContinue
  $fridaExit = $fridaProc.ExitCode
  if ($null -eq $fridaExit) { $fridaExit = 0 }
} catch {
  Log "Frida launch error: $_"
}
Log ("Frida exit={0}" -f $fridaExit)

Kill-Image "sample.exe"
Kill-Image "frida-helper-64.exe"

Log "stopping Procmon"
Start-Process -FilePath $ProcmonExe -ArgumentList "/AcceptEula","/Terminate" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Seconds 3
if (Test-Path $pml) {
  Log "exporting PML to CSV"
  Start-Process -FilePath $ProcmonExe -ArgumentList "/AcceptEula","/OpenLog",$pml,"/SaveAs",$csv,"/SaveApplyFilter" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    if ((Test-Path $csv) -and ((Get-Item $csv).Length -gt 0)) { break }
    Start-Sleep -Seconds 2
  }
  $csvSize = 0
  if (Test-Path $csv) { $csvSize = (Get-Item $csv).Length }
  Log ("csv exists={0} size={1}" -f (Test-Path $csv), $csvSize)
} else {
  Log "WARN: PML missing"
}
Start-Process -FilePath $ProcmonExe -ArgumentList "/AcceptEula","/Terminate" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null

if ($fnProc -and -not $fnProc.HasExited) {
  Log "stopping FakeNet"
  try { Stop-Process -Id $fnProc.Id -Force -ErrorAction SilentlyContinue } catch {}
  Start-Sleep -Seconds 2
}
Kill-Image "fakenet.exe"

$fnOut = Join-Path $OutDir "network_raw"
New-Item -ItemType Directory -Force -Path $fnOut | Out-Null
# Flatten FakeNet output with unique names. FakeNet-NG writes per-service
# logs/pcaps into subdirectories that share common filenames (e.g.
# capture.pcap) — a flat copy would silently overwrite earlier captures.
$fnFiles = Get-ChildItem $fnWork -Recurse -File -ErrorAction SilentlyContinue
foreach ($p in $fnFiles) {
  $rel = $p.FullName.Substring($fnWork.Length).TrimStart('\', '/')
  $dest = Join-Path $fnOut ($rel -replace '[\\/]', '_')
  Copy-Item $p.FullName $dest -Force -ErrorAction SilentlyContinue
}
$fnCopied = @(Get-ChildItem $fnOut -File -ErrorAction SilentlyContinue).Count
Log ("network_raw copied files={0}" -f $fnCopied)

$post = Snapshot-Processes "post"
$post | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutDir "process_snapshot_post.json") -Encoding UTF8
$preNames = @{}
foreach ($r in $pre) {
  if ($r.name) { $preNames[("{0}:{1}" -f $r.pid, $r.name)] = $true }
}
$newProcs = @()
foreach ($r in $post) {
  $k = ("{0}:{1}" -f $r.pid, $r.name)
  if ($r.name -and -not $preNames.ContainsKey($k)) { $newProcs += $r }
}
@{
  pre_count = $pre.Count
  post_count = $post.Count
  new_processes = $newProcs
} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutDir "process_snapshot.json") -Encoding UTF8
Log ("new_processes={0}" -f $newProcs.Count)

$summaryPy = Join-Path $PSScriptRoot "summarize_dynamic.py"
if (-not (Test-Path $summaryPy)) { $summaryPy = "C:\tools\reveng-dynamic\summarize_dynamic.py" }
if (Test-Path $summaryPy) {
  Log "running summarize_dynamic.py"
  & $Python $summaryPy --out-dir $OutDir --sample-name "sample.exe" 2>&1 | ForEach-Object { Log "$_" }
} else {
  Log "WARN: summarize_dynamic.py missing"
  @{ status = "partial"; reason = "summarizer missing" } | ConvertTo-Json | Set-Content (Join-Path $OutDir "network.json")
  @{ status = "partial"; reason = "summarizer missing" } | ConvertTo-Json | Set-Content (Join-Path $OutDir "procmon_summary.json")
  @{ status = "partial"; reason = "summarizer missing" } | ConvertTo-Json | Set-Content (Join-Path $OutDir "frida_summary.json")
}

if (Test-Path $trace) {
  Copy-Item $trace (Join-Path $OutDir "frida_trace.json") -Force
}

@{
  ok = $true
  sha256 = $Sha256
  max_seconds = $MaxSeconds
  frida_exit = $fridaExit
  fakenet_started = [bool]$fnProc
  procmon_pml = (Test-Path $pml)
  procmon_csv = (Test-Path $csv)
  pe_sieve_enabled = [bool]$EnablePeSieve
  pe_sieve_ran = $peSieveRan
  pe_sieve_pid = $peSievePid
  pe_sieve_rc = $peSieveRc
  memory_dir = if (Test-Path $memDir) { $memDir } else { $null }
  snapshot_restore_required = $true
  finished_at = (Get-Date).ToUniversalTime().ToString("o")
} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutDir "META.job.json") -Encoding UTF8

Copy-Item $LogFile (Join-Path $OutDir "job.log") -Force -ErrorAction SilentlyContinue
# Drop huge PML from zip (CSV is enough); keep PML on disk for optional forensics
$pmlZip = Join-Path $OutDir "procmon.pml"
if (Test-Path $pmlZip) {
  Log "excluding procmon.pml from zip (size large)"
}
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Log "zipping artifacts"
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
$zip = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Create')
try {
  Get-ChildItem $OutDir -Recurse -File | ForEach-Object {
    if ($_.Name -ieq "procmon.pml") { return }
    $rel = $_.FullName.Substring($OutDir.Length).TrimStart('\', '/').Replace('\', '/')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $rel, 'Optimal') | Out-Null
  }
} finally {
  $zip.Dispose()
}
$zipSize = (Get-Item $ZipPath).Length
Log ("DONE ok=true zip_size={0}" -f $zipSize)
exit 0
