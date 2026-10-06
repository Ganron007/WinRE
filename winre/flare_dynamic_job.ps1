#Requires -Version 5.1
param(
  [Parameter(Mandatory = $true)][string]$Sha256,
  [string]$SamplePath = "",
  [int]$MaxSeconds = 45,
  [string]$WorkRoot = "",
  [string]$Python = "C:\Python313\python.exe",
  [string]$FridaScript = "C:\WinRE\tools\frida_api_trace.py",
  [string]$FakeNetExe = "C:\Tools\fakenet\fakenet3.5\fakenet.exe",
  [string]$ProcmonExe = "C:\Tools\sysinternals\Procmon64.exe",
  [string]$PeSieveExe = "C:\ProgramData\chocolatey\bin\pe-sieve.exe",
  [string]$HollowsHunterExe = "C:\Tools\hollows_hunter\hollows_hunter.exe",
  [string]$ProcdumpExe = "C:\Tools\sysinternals\Procdump64.exe",
  [switch]$EnablePeSieve,
  [switch]$Adaptive,
  [int]$IdleStopSeconds = 0,
  # Behaviour-gated window (RevAI handoff item 9). The 2026-09-11 measurement:
  # a 45 s window gave 497 Frida events and no DGA, a 150 s window gave 694,692
  # events and live HTTP POST C2 - so the window followed a fixed guess and the
  # interesting part of a run was a coin flip. The gate keeps tracing until the
  # sample does something notable, then lets it settle.
  [string]$StopOn = "network,file",
  [int]$StopOnSettle = 20,
  # A DLL cannot be spawned - Frida refuses it with "unsupported file
  # format". It is loaded through a host instead (rundll32 -<File>,<Entry>).
  # Empty means: derive the entry point from the file's own export directory.
  [string]$DllEntry = "",
  [string]$Apis = "CreateFileW,WriteFile,ReadFile,DeleteFileW,RegOpenKeyExW,RegSetValueExW,VirtualAlloc,VirtualProtect,WriteProcessMemory,CreateRemoteThread,WinHttpOpen,InternetOpenW,connect,send,recv,LoadLibraryW,GetProcAddress,CreateProcessW"
)

$ErrorActionPreference = "Continue"
$Sha256 = $Sha256.Trim().ToLower()
if (-not $WorkRoot) { $WorkRoot = "C:\samples\$Sha256" }
if (-not $SamplePath) { $SamplePath = Join-Path $WorkRoot "sample.exe" }
# SSH mode normalizes the sample to sample.exe; LOCAL mode passes the real
# name (e.g. invoice.exe). Derive the process name so pe-sieve wait and
# target cleanup work in both modes.
$SampleProcName = [IO.Path]::GetFileNameWithoutExtension($SamplePath)
# A DLL is hosted by rundll32, so the process on the box is NOT named after
# the sample - it is named rundll32. Deriving the tracking name from the file
# name only works for an executable. Detect the DLL from its own FILE header
# (the Characteristics bit, not the extension - the corpus paths are hashes)
# and track the host instead. Without this, everything downstream of the pid
# sweep silently finds nothing: no sample_pid, no memory dump, and a stage
# that reports "not observed" for a detonation that actually ran.
$IsDllSample = $false
try {
  $fs = [IO.File]::OpenRead($SamplePath)
  try {
    $hdr = New-Object byte[] 512
    $null = $fs.Read($hdr, 0, 512)
    if ($hdr[0] -eq 0x4d -and $hdr[1] -eq 0x5a) {
      $pe = [BitConverter]::ToInt32($hdr, 0x3c)
      if ($pe -gt 0 -and ($pe + 24) -le 512 -and $hdr[$pe] -eq 0x50 -and $hdr[$pe+1] -eq 0x45) {
        $chars = [BitConverter]::ToUInt16($hdr, $pe + 22)
        $machine = [BitConverter]::ToUInt16($hdr, $pe + 4)
        if ($chars -band 0x2000) { $IsDllSample = $true }
        $DllIs64 = ($machine -eq 0x8664 -or $machine -eq 0xAA64)
      }
    }
  } finally { $fs.Close() }
} catch { }
if ($IsDllSample) {
  $SampleProcName = if ($DllIs64) { "rundll32" } else { "rundll32" }
  Log ("sample is a DLL ({0}-bit) - will be hosted by rundll32" -f $(if ($DllIs64) { "64" } else { "32" }))
}

$OutDir = Join-Path $WorkRoot "out"
$LogFile = Join-Path $WorkRoot "job.log"
$ZipPath = Join-Path $WorkRoot "artifacts.zip"

function Log {
  param([string]$Message)
  $line = "[{0}] {1}" -f (Get-Date -Format "o"), $Message
  Add-Content -Path $LogFile -Value $line -Encoding UTF8
  Write-Host $line
}

# -Adaptive used to mean "stop after IdleStopSeconds of quiet" and defaulted
# that to 10s. Keep that meaning for anyone who passes it, but do NOT make it
# the default: a sleeping sample looks idle, so idle-stop cuts the window right
# before the sample wakes up and beacons (RevAI handoff item 9). The default
# path uses the behaviour gate instead.
if ($Adaptive -and $IdleStopSeconds -le 0) {
  $IdleStopSeconds = 10
  Log "note: -Adaptive without -IdleStopSeconds -> using the historical 10s idle cutoff"
}

function Kill-Image {
  param([string]$Image)
  Start-Process -FilePath "taskkill.exe" -ArgumentList "/F","/IM",$Image,"/T" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
}

function Kill-Stale {
  # Full leftover coverage: detonation workers + stale MCP/debug hosts.
  # Deliberately NOT ida64.exe (static engine — dynamic runs after static).
  foreach ($im in @("sample.exe","frida-helper-64.exe","frida-helper-32.exe",
                    "fakenet.exe","Procmon64.exe","Procmon.exe",
                    "hollows_hunter.exe","pe-sieve.exe",
                    "idasql.exe","java.exe",
                    "windbg.exe","x64dbg.exe","x32dbg.exe")) {
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
# job.log size cap: rotate a runaway previous log instead of appending forever
if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 5MB)) {
  Move-Item $LogFile (Join-Path $WorkRoot "job.prev.log") -Force -ErrorAction SilentlyContinue
}
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
# Pack hygiene: drop dump dirs from PREVIOUS runs sharing this work root —
# stale process_* evidence must never masquerade as this run's capture.
if (Test-Path $memDir) {
  Get-ChildItem $memDir -Directory -Filter "process_*" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  Get-ChildItem $memDir -File -Filter "sample_*.dmp" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
}
$peSieveRan = $false
$peSievePid = $null
$peSieveRc = $null
$psReportValid = $false
$samplePid = $null
Log ("Frida start EnablePeSieve={0} Adaptive={1}" -f [bool]$EnablePeSieve, [bool]$Adaptive)
$fridaExit = -1
$fridaStart = $null
try {
  # Non-blocking Frida so we can pe-sieve mid-run when enabled
  $fridaArgs = @(
    $FridaScript,
    "--target", $SamplePath,
    "--apis", $Apis,
    "--out", $trace,
    "--max-seconds", "$MaxSeconds",
    "--max-calls", "5000"
  )
  if ($Adaptive) {
    # adaptive window: max-seconds is the CAP, idle-stop ends a quiet run
    $fridaArgs += @("--idle-stop", "$IdleStopSeconds")
  }
  if ($StopOn) {
    # behaviour gate (RevAI item 9). Independent of -Adaptive: the gate is the
    # mechanism that actually solves "the window is a guess". Idle-stop is NOT
    # enabled by default because a sleeping sample looks idle and would be cut
    # off right before it wakes up and beacons.
    $fridaArgs += @("--stop-on", "$StopOn", "--stop-on-settle", "$StopOnSettle")
  }
    if ($DllEntry) {
      # only meaningful for a DLL target; the tracer decides that from the
      # PE header and ignores it for an executable
      $fridaArgs += @("--dll-entry", "$DllEntry")
    }
  $fridaStart = Get-Date
  $fridaProc = Start-Process -FilePath $Python -ArgumentList $fridaArgs -PassThru -NoNewWindow `
    -RedirectStandardError (Join-Path $OutDir "frida.stderr.txt") `
    -RedirectStandardOutput (Join-Path $OutDir "frida.stdout.txt")

  # Capture the SAMPLE pid while it is ALIVE. (Previously the pid was only
  # resolved at META-write time - after Kill-Image - so sample_pid was always
  # null, which disabled the post-mortem memory harvest + ntdll integrity.)
  $deadline = (Get-Date).AddSeconds([Math]::Min(20, [Math]::Max(5, $MaxSeconds / 2)))
  while ((Get-Date) -lt $deadline) {
    # The tracer reports the pid it spawned. Authoritative when a DLL is hosted
    # by rundll32, whose name is shared with every other rundll32 on the box.
    if (-not $samplePid) {
      $spErr = Join-Path $OutDir "frida.stderr.txt"
      if (Test-Path $spErr) {
        $se = (Get-Content $spErr -Raw)
        if ($se -match "(?m)^spawned_pid=(\d+)") { $samplePid = [int]$Matches[1] }
      }
    }
    if (-not $samplePid) {
      $sp = Get-Process -Name $SampleProcName -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($sp) { $samplePid = $sp.Id }
    }
    if ($samplePid) {
      Log ("sample pid={0}" -f $samplePid)
      break
    }
    Start-Sleep -Milliseconds 500
  }
  if (-not $samplePid) { Log "WARN: sample process not observed (fast exit?)" }

  # Full process dumps while ALIVE. Two passes, because the behaviour gate
  # stops the window wherever the sample acts instead of where the cap said:
  # 20.8s on b108, 2.8s on b104, against a 150s cap. A single dump scheduled
  # at 70% of the cap therefore always lands after the sample has left -
  # b108's own log is "procdump scheduled in 105s" -> "procdump done (0 dmp)",
  # and it had dropped b.wnry/c.wnry and exited inside the first second.
  #   early ~2s : up, first payload already dropped. This is the pass that
  #               survives an early gate stop, now the common case.
  #   late  70% : unchanged, for samples that stay up for the whole window and
  #               unpack in memory later.
  $pdProcs = @()
  if ($samplePid -and (Test-Path $ProcdumpExe)) {
    New-Item -ItemType Directory -Force -Path $memDir | Out-Null
# 1s, not "2% of the cap". b103 exited 1.8s after spawn and a 3s early
    # dump missed it completely (0 dumps for a sample that had just run 878
    # API calls). The pid is observed within ~500ms of spawn, so a 1s delay
    # still catches a process that lives over a second, and the late pass
    # remains for everything that does.
    $delayEarly = 1
    $delayLate = [Math]::Max($delayEarly + 5, [Math]::Floor($MaxSeconds * 0.7))
    foreach ($tag in @("early", "late")) {
      $delay = if ($tag -eq "early") { $delayEarly } else { $delayLate }
      $outFile = "$memDir\sample_$tag"
      $dumpCmd = "Start-Sleep -Seconds $delay; & '$ProcdumpExe' -accepteula -ma $samplePid '$outFile'; exit"
      $p = Start-Process powershell -ArgumentList @(
        "-NoProfile", "-Command", $dumpCmd
      ) -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
      if ($p) { $pdProcs += $p }
      Log ("procdump[$tag] scheduled in {0}s pid={1}" -f $delay, $samplePid)
    }
  }

  # ---- KB: Early-Bird/APC-aware capture + sandbox input jiggle -----------
  # Start CONCURRENT with Frida (not after the run) so the monitor can catch
  # suspended/injected child processes during the live detonation window.
  $monitor = Join-Path $OutDir "_monitor_suspended.ps1"
  $jiggle = Join-Path $OutDir "_input_jiggle.ps1"
  @"
param(`$SampleName, `$PeSieveExe, `$MemDir, `$MaxSeconds)
`$deadline = (Get-Date).AddSeconds(`$MaxSeconds)
`$seen = @{}
while ((Get-Date) -lt `$deadline) {
  Get-Process -Name `$SampleName -ErrorAction SilentlyContinue | ForEach-Object {
    if (-not `$seen.ContainsKey(`$_.Id)) {
      `$seen[`$_.Id] = `$true
      & `$PeSieveExe /pid `$_.Id /dir `$MemDir /quiet /minidmp /shellc A /dnet 4 /data 3 2>`$null | Out-Null
    }
  }
  Start-Sleep -Seconds 3
}
"@ | Set-Content $monitor -Encoding ASCII
  @"
param(`$Seconds)
`$sig = '[DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);'
`$t = Add-Type -MemberDefinition `$sig -Name J -Namespace W -PassThru
`$deadline = (Get-Date).AddSeconds(`$Seconds)
`$r = New-Object System.Random
while ((Get-Date) -lt `$deadline) {
  `$t::SetCursorPos(`$r.Next(100, 1500), `$r.Next(100, 800)) | Out-Null
  Start-Sleep -Milliseconds 400
}
"@ | Set-Content $jiggle -Encoding ASCII
  $monProc = $null
  $jigProc = $null
  if ((Test-Path $PeSieveExe) -and (Test-Path $monitor)) {
    New-Item -ItemType Directory -Force -Path $memDir | Out-Null
    $monProc = Start-Process powershell -ArgumentList @(
      "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $monitor,
      "$SampleProcName", $PeSieveExe, $memDir, "$MaxSeconds"
    ) -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
    Log ("suspended-process monitor started pid={0}" -f $monProc.Id)
  }
  if (Test-Path $jiggle) {
    $jigProc = Start-Process powershell -ArgumentList @(
      "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $jiggle,
      "$MaxSeconds"
    ) -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
    Log ("input jiggle started pid={0}" -f $jigProc.Id)
  }

  if ($EnablePeSieve) {
    New-Item -ItemType Directory -Force -Path $memDir | Out-Null
    # Wait for the SAMPLE process to appear (name derived from SamplePath)
    if ($samplePid) { $peSievePid = $samplePid }
    else {
      $deadline = (Get-Date).AddSeconds([Math]::Min(20, [Math]::Max(5, $MaxSeconds / 2)))
      while ((Get-Date) -lt $deadline) {
        $sp = Get-Process -Name $SampleProcName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sp) {
          $peSievePid = $sp.Id
          break
        }
        Start-Sleep -Seconds 1
      }
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
      ) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $psLog `
        -RedirectStandardError $psErr
      # bounded wait: a hung pe-sieve must not stall the whole job
      if (-not ($psProc | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue)) { Stop-Process -Id $psProc.Id -Force -ErrorAction SilentlyContinue }
      $peSieveRc = $psProc.ExitCode
      $peSieveRan = $true
      # When /json is active pe-sieve writes the report to STDOUT, so make
      # pe_sieve_report.json the real JSON artifact — and PROVE it parses.
      # A non-JSON stdout (CLI banner, error text) is kept as .invalid.txt
      # so downstream never mistakes prose for a report.
      $psReportValid = $false
      if ((Test-Path $psLog) -and ((Get-Item $psLog).Length -gt 0)) {
        Copy-Item $psLog $psReport -Force -ErrorAction SilentlyContinue
        try {
          $null = Get-Content $psReport -Raw | ConvertFrom-Json
          $psReportValid = $true
        } catch {
          Move-Item $psReport (Join-Path $memDir "pe_sieve_report.invalid.txt") -Force -ErrorAction SilentlyContinue
          Log ("WARN: pe-sieve report not valid JSON: {0}" -f $_.Exception.Message)
        }
      }
      Log ("pe-sieve exit={0} report={1} valid={2} log={3}" -f $peSieveRc, (Test-Path $psReport), $psReportValid, (Test-Path $psLog))
      # Optional hollows_hunter on same PID (best-effort, bounded)
      if (Test-Path $HollowsHunterExe) {
        $hhOut = Join-Path $memDir "hollows_hunter"
        New-Item -ItemType Directory -Force -Path $hhOut | Out-Null
        Log ("hollows_hunter /pid {0}" -f $peSievePid)
        $hhProc = Start-Process -FilePath $HollowsHunterExe -ArgumentList @(
          "/pid", "$peSievePid",
          "/dir", $hhOut,
          "/quiet"
        ) -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        if ($hhProc -and -not ($hhProc | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue)) { Stop-Process -Id $hhProc.Id -Force -ErrorAction SilentlyContinue }
      }
    } else {
      Log ("WARN: pe-sieve skipped (pid={0} exe={1})" -f $peSievePid, (Test-Path $PeSieveExe))
    }
  }

  # bounded Frida wait: the script has its own watchdog; this backstop
  # stops a hung Frida from stalling the job until the orchestrator timeout
  Wait-Process -Id $fridaProc.Id -Timeout ($MaxSeconds + 90) -ErrorAction SilentlyContinue
  if (-not $fridaProc.HasExited) {
    Log "WARN: Frida still running past backstop - killing"
    Stop-Process -Id $fridaProc.Id -Force -ErrorAction SilentlyContinue
  }
  $fridaExit = $fridaProc.ExitCode
  if ($null -eq $fridaExit) { $fridaExit = 0 }
} catch {
  Log "Frida launch error: $_"
}
Log ("Frida exit={0}" -f $fridaExit)

# adaptive-window telemetry: effective run length + stop reason (Frida
# writes frida_trace.jsonl.run.json; wall time is the fallback)
$windowEffective = $null
$windowReason = "unknown"
$windowGate = @{ }
if ($fridaStart) {
  $windowEffective = [Math]::Round(((Get-Date) - $fridaStart).TotalSeconds, 1)
}
$frRun = Join-Path $OutDir "frida_trace.jsonl.run.json"
if (Test-Path $frRun) {
  try {
    $rj = Get-Content $frRun -Raw | ConvertFrom-Json
    if ($rj.stop_reason) { $windowReason = [string]$rj.stop_reason }
    if ($rj.elapsed_s) { $windowEffective = [double]$rj.elapsed_s }
    # the gate verdict travels with the pack: a reader can tell "the sample
    # never did anything interesting" from "we stopped right after it did"
    if ($null -ne $rj.gate_fired) {
      $windowGate = @{
        fired       = [bool]$rj.gate_fired
        kind        = [string]$rj.gate_kind
        api         = [string]$rj.gate_api
        at_s        = $rj.gate_at_s
        settle_s    = $rj.gate_settle_s
        spec        = [string]$StopOn
      }
    }
  } catch { $windowReason = "unparsable" }
}
Log ("window effective={0}s reason={1} adaptive={2} gate={3}/{4}" -f $windowEffective, $windowReason, [bool]$Adaptive, [string]$StopOn, $(if ($windowGate.fired) { [string]$windowGate.kind } else { "not-fired" }))

# The delayed in-run procdumps (scheduled at capture time) should be done or
# nearly done - bounded wait, then report how many dumps landed. Both passes
# are reported separately: a behaviour-gated window stops early, so the EARLY
# pass is the one that survives and logging only a combined 0 would hide it.
foreach ($d in $pdProcs) {
  if (-not ($d | Wait-Process -Timeout 90 -ErrorAction SilentlyContinue)) {
    Stop-Process -Id $d.Id -Force -ErrorAction SilentlyContinue
  }
}
foreach ($tag in @("early", "late")) {
  $n = (Get-ChildItem $memDir -Filter "sample_$tag*.dmp" -ErrorAction SilentlyContinue | Measure-Object).Count
  Log ("procdump[$tag] done ({0} dmp)" -f $n)
}
Log ("procdump total ({0} dmp)" -f (Get-ChildItem $memDir -Filter "sample_*.dmp" -ErrorAction SilentlyContinue | Measure-Object).Count)

Kill-Image "$SampleProcName.exe"
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

# KB: stop the aux monitors/jiggle (bounded; never stall the job)
foreach ($aux in @($monProc, $jigProc)) {
  if ($aux) {
    Stop-Process -Id $aux.Id -Force -ErrorAction SilentlyContinue
  }
}
Remove-Item $monitor, $jiggle -Force -ErrorAction SilentlyContinue

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
  & $Python $summaryPy --out-dir $OutDir --sample-name "$SampleProcName.exe" 2>&1 | ForEach-Object { Log "$_" }
} else {
  Log "WARN: summarize_dynamic.py missing"
  @{ status = "partial"; reason = "summarizer missing" } | ConvertTo-Json | Set-Content (Join-Path $OutDir "network.json")
  @{ status = "partial"; reason = "summarizer missing" } | ConvertTo-Json | Set-Content (Join-Path $OutDir "procmon_summary.json")
  @{ status = "partial"; reason = "summarizer missing" } | ConvertTo-Json | Set-Content (Join-Path $OutDir "frida_summary.json")
}

if (Test-Path $trace) {
  Copy-Item $trace (Join-Path $OutDir "frida_trace.json") -Force
}

  # How the sample was launched. Frida prints "loader=<direct|rundll32>
  # entry=<x>" to stderr; read it back so the pack is self-describing without
  # a second probe (b105 was a DLL and nothing in the pack said so).
  $launchLoader = $null
  $launchLoaderEntry = $null
  if (Test-Path (Join-Path $OutDir "frida.stderr.txt")) {
    $se = (Get-Content (Join-Path $OutDir "frida.stderr.txt") -Raw)
    if ($se -match "loader=(rundll32|direct)") { $launchLoader = $Matches[1] }
    if ($se -match "(?m)^loader=(?:rundll32|direct) entry=(.*)$") {
      $launchLoaderEntry = $Matches[1].Trim()
    }
  }
  # A detonation that never spawned the sample is not a green detonation.
  # b105 (2026-10-06) was a DLL masquerading as .exe: Frida's device.spawn
  # raised ExecutableNotSupportedError, exited 0 anyway, Procmon then recorded
  # a perfectly healthy 217k rows, and the stage reported ok=true with
  # events=None. Procmon being alive is not evidence the sample ran.
  $detonation_ran = [bool]$samplePid
  $detonation_err = $null
  if (-not $detonation_ran) {
    $spawnErr = $null
    if (Test-Path (Join-Path $OutDir "frida.stderr.txt")) {
      $spawnErr = (Get-Content (Join-Path $OutDir "frida.stderr.txt") -Raw)
    }
    $reason = "sample process was never observed (no pid)"
    if ($spawnErr -and $spawnErr -match "ExecutableNotSupportedError|unsupported file format") {
      $reason = ("Frida could not spawn the sample: unsupported file format. The file " +
                 "is a DLL, not an executable - it must be loaded through a host " +
                 "(rundll32/regsvr32), not spawned directly.")
    } elseif ($spawnErr -and $spawnErr.Trim()) {
      $reason = "Frida failed to spawn the sample: " + $spawnErr.Trim().Split("`n")[-1].Trim()
    }
    $detonation_err = $reason
  }
  @{
    ok = (-not $detonation_err)
    error = $detonation_err
    sha256 = $Sha256
  max_seconds = $MaxSeconds
  window = @{
    requested_s = $MaxSeconds
    effective_s = $windowEffective
    adaptive = [bool]$Adaptive
    idle_stop_s = if ($Adaptive -and $IdleStopSeconds -gt 0) { $IdleStopSeconds } else { $null }
    stop_reason = $windowReason
    # RevAI handoff item 9: why this window and not a shorter one
    gate_spec = if ($StopOn) { [string]$StopOn } else { $null }
    gate_settle_s = if ($StopOn) { $StopOnSettle } else { $null }
    gate = $windowGate
  }
  frida_exit = $fridaExit
  fakenet_started = [bool]$fnProc
  procmon_pml = (Test-Path $pml)
  procmon_csv = (Test-Path $csv)
  pe_sieve_enabled = [bool]$EnablePeSieve
  pe_sieve_ran = $peSieveRan
  pe_sieve_pid = $peSievePid
  pe_sieve_rc = $peSieveRc
  pe_sieve_report_valid = $psReportValid
  sample_pid = if ($samplePid) { $samplePid } elseif ($peSievePid) { $peSievePid } else { $null }
  memory_dir = if (Test-Path $memDir) { $memDir } else { $null }
  snapshot_restore_required = $true
  detonation_reason = if ($detonation_ran) { $null } else { $detonation_err }
  # how the sample was launched: "direct" (spawned) or "rundll32" (a DLL
  # hosted by rundll32.exe <file>,<entry> - Frida prints it to stderr.)
  loader = $launchLoader
  loader_entry = $launchLoaderEntry
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
    # procmon.pml: huge binary, CSV suffices (PML stays on disk).
    # frida_trace.json: byte-duplicate of frida_trace.jsonl — zip the
    # canonical .jsonl only, skip the compat copy.
    if ($_.Name -ieq "procmon.pml") { return }
    if ($_.Name -ieq "frida_trace.json") { return }
    $rel = $_.FullName.Substring($OutDir.Length).TrimStart('\', '/').Replace('\', '/')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $rel, 'Optimal') | Out-Null
  }
} finally {
  $zip.Dispose()
}
$zipSize = (Get-Item $ZipPath).Length
Log ("DONE ok=true zip_size={0}" -f $zipSize)
exit 0
