#Requires -Version 5.1
<#
.SYNOPSIS
    run_vm_static.ps1 - run the WinRE static pipeline ON the FlareVM via SSH.

.DESCRIPTION
    Campaign execution model (safety): samples NEVER touch the control-plane
    host. Binaries live only in C:\samples\ on the FlareVM; the pipeline,
    tools, LLM env (C:\WinRE\.env) and evidence packs (C:\WinRE\logs) all
    live on the VM. The host only sends a one-line SSH command and pulls back
    the REPORT FILES (markdown/json - never binary artifacts).

    Usage (host):
      powershell -File ops\run_vm_static.ps1 s02.bin
      powershell -File ops\run_vm_static.ps1 s02.bin -DryLlm
      powershell -File ops\run_vm_static.ps1 s02.bin -PullReports
#>
param(
    [Parameter(Mandatory = $true)][string]$SampleName,
    [switch]$DryLlm,
    [switch]$PullReports,
    [int]$MaxSeconds = 60
)

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$dotenv = @{}
$dotenvPath = Join-Path $repo ".env"
if (Test-Path $dotenvPath) {
    foreach ($ln in Get-Content $dotenvPath) {
        if ($ln -match "^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+?)\s*$") {
            $dotenv[$Matches[1]] = $Matches[2].Trim('"')
        }
    }
}
$flareHost = $env:FLARE_HOST
if (-not $flareHost) { $flareHost = $dotenv["FLARE_HOST"] }
$flareUser = $env:FLARE_USER
if (-not $flareUser) { $flareUser = $dotenv["FLARE_USER"] }
$flareKey = $env:FLARE_SSH_KEY
if (-not $flareKey) { $flareKey = $dotenv["FLARE_SSH_KEY"] }
if (-not $flareHost -or -not $flareKey) {
    Write-Error "FLARE_HOST / FLARE_SSH_KEY not set (neither env nor .env)"
    exit 2
}

$sshTarget = "$flareUser@$flareHost"
$py = "C:\Python313\python.exe"
$vmSample = "C:\samples\$SampleName"

# Build the VM command
$dryFlag = ""
if ($DryLlm) { $dryFlag = " --dry-llm" }
$vmCmd = "`$ErrorActionPreference = 'Continue'; & `"$py`" C:\WinRE\winre\pipeline.py `"$vmSample`" --max-seconds $MaxSeconds$dryFlag 2>&1"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($vmCmd))

Write-Host "[run_vm_static] SSH -> $sshTarget : pipeline.py $vmSample"
Write-Host "[run_vm_static] pipeline is running on the VM (may take several minutes)..."
$scpArgs = @("-i", $flareKey, "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15")
ssh -i $flareKey -o StrictHostKeyChecking=no -o ConnectTimeout=15 $sshTarget "powershell -NoProfile -EncodedCommand $enc"
$rc = $LASTEXITCODE
Write-Host "[run_vm_static] VM pipeline exit=$rc"

if ($PullReports -and $rc -eq 0) {
    # Get SHA via a simple python one-liner on the VM
    $shaPy = "import hashlib; print(hashlib.sha256(open(r'$vmSample','rb').read()).hexdigest())"
    $shaEnc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
        "& `"$py`" -c `"$shaPy`""))
    Write-Host "[run_vm_static] getting SHA..."
    $shaRaw = ssh -i $flareKey -o StrictHostKeyChecking=no $sshTarget "powershell -NoProfile -EncodedCommand $shaEnc"
    # Find the 64-hex line
    $sha = ""
    foreach ($line in $shaRaw) {
        $m = [regex]::Match($line, "([0-9a-f]{64})")
        if ($m.Success) {
            $sha = $m.Groups[1].Value
            break
        }
    }
    if ($sha -and $sha.Length -eq 64) {
        Write-Host "[run_vm_static] SHA=$sha — pulling report files"
        $dest = Join-Path $repo "logs" $sha
        New-Item -ItemType Directory -Force -Path (Join-Path $dest "report") | Out-Null
        foreach ($f in @("REPORT-TECHNICAL-v3.md", "AUDIT-REPORT.md",
                         "EVIDENCE-BUNDLE.md", "iocs.json", "META.json")) {
            scp -i $flareKey -o StrictHostKeyChecking=no `
                "${sshTarget}:C:/WinRE/logs/$sha/report/$f" `
                (Join-Path $dest "report\$f") 2>$null | Out-Null
        }
        foreach ($f in @("audit.json", "stage_trace.json")) {
            scp -i $flareKey -o StrictHostKeyChecking=no `
                "${sshTarget}:C:/WinRE/logs/$sha/$f" `
                (Join-Path $dest $f) 2>$null | Out-Null
        }
        Write-Host "[run_vm_static] report files pulled to $dest (no binary artifacts)"
    } else {
        Write-Host "[run_vm_static] WARN could not get SHA — report pull skipped"
    }
}

if ($rc -ne 0) { exit 1 } else { exit 0 }
