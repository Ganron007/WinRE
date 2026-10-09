#Requires -Version 5.1
<#
.SYNOPSIS
    provision_host.ps1 - provision the CONTROL PLANE (the analysis host).

.DESCRIPTION
    The analysis plane runs on the control plane, not the VM:
    winre/findings.py, winre/analysis.py, winre/pcap_beacon.py and
    winre/enrich_pcap_tshark.py all execute here, over evidence PULLED off the
    VM. They need real tools on this box.

    The FlareVM was fully provisioned (43/43, 0 FAIL) - and the control plane
    was provisioned by nobody. ops/provision_tools.ps1 uses this host only as a
    download proxy for the air-gapped VM; install/setup-flarevm.ps1 is
    explicitly "Usage (ON the FlareVM)". So the machine that does the analysis
    had no installer, and the gaps surfaced as "yara is not installed on the
    analysis host" in every findings.json - a limitation that never said the VM
    has yara-x at C:\Tools\yara-x\yr.exe, or that this box simply was never
    provisioned.

    This script closes that gap:

      pip   : yara-python (the rules engine), flare-floss, capa
      rules : the curated rule set, copied from the FlareVM (it is the
              authority - 57 files at C:\Tools\yara-rules)

    Everything is idempotent and re-runnable. Run it again after a host
    rebuild or a Python upgrade.

    Usage (on the control plane):
      powershell -ExecutionPolicy Bypass -File ops\provision_host.ps1
      powershell -ExecutionPolicy Bypass -File ops\provision_host.ps1 -Check   # report only
#>
param(
    [string]$FlareHost = $env:FLARE_HOST,
    [string]$User      = $env:FLARE_USER,
    [string]$SshKey    = $env:FLARE_SSH_KEY,
    [string]$RulesDest = "C:\Tools\yara-rules",
    [switch]$Check
)

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
$fails = @()

# dotenv: FLARE_* live in .env on this host (explicit params still win). Without
# this the rule fetch cannot find the VM even though .env knows where it is.
$dotenvPath = Join-Path $repo ".env"
if (Test-Path $dotenvPath) {
    foreach ($ln in Get-Content $dotenvPath) {
        if ($ln -match '^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+?)\s*$') {
            $k = $Matches[1]; $v = $Matches[2].Trim('"')
            if (-not (Test-Path "Env:$k") -or -not (Get-Item "Env:$k").Value) {
                Set-Item -Path "Env:$k" -Value $v
            }
        }
    }
}
if (-not $FlareHost) { $FlareHost = $env:FLARE_HOST }
if (-not $User)      { $User      = $env:FLARE_USER }
if (-not $SshKey)    { $SshKey    = $env:FLARE_SSH_KEY }

function Ok($m)   { Write-Host "  [OK]     $m" -ForegroundColor Green }
function Skip($m) { Write-Host "  [skip]   $m" -ForegroundColor DarkGray }
function Bad($m)  { Write-Host "  [MISS]   $m" -ForegroundColor Red; $script:fails += $m }

"  === control-plane provisioning $($(if ($Check) { '(CHECK MODE - no changes)' } else { '' })) ==="

# ---------------------------------------------------------------- python
$py = (Get-Command python -EA SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python3 -EA SilentlyContinue).Source }
if (-not $py) { Bad "python not on PATH - the analysis plane is Python"; exit 1 }
Ok "python -> $py"

# ---------------------------------------------------------------- pip pkgs
# Each entry: pip name, import name, why the analysis plane needs it.
$pipPkgs = @(
    @{ name = "yara-python"; imp = "yara";  why = "memory-dump YARA triage - the only thing that can triage the 121-306 MB of pulled memory evidence" },
    @{ name = "flare-floss"; imp = "floss"; why = "static string de-obfuscation" },
    @{ name = "flare-capa";  imp = "capa";  why = "capability extraction (weighted in compose)" }
)

foreach ($p in $pipPkgs) {
    $have = & $py -c "import $($p.imp)" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Ok "$($p.name) already importable"
        continue
    }
    if ($Check) { Bad "$($p.name) not importable"; continue }
    "  .... installing $($p.name)"
    & $py -m pip install --quiet --upgrade $p.name 2>&1 | Out-Null
    & $py -c "import $($p.imp)" 2>$null
    if ($LASTEXITCODE -eq 0) { Ok "$($p.name) installed" }
    else { Bad "$($p.name) failed to install - $($p.why)" }
}

# ---------------------------------------------------------------- the rules
# The FlareVM holds the curated set and is the authority for it. Copy it here
# rather than re-downloading: the box is air-gapped, so this is the only path.
if (Test-Path $RulesDest) {
    $n = @(Get-ChildItem $RulesDest -Recurse -File -EA SilentlyContinue).Count
    Ok "rules already staged at $RulesDest ($n files)"
} elseif ($Check) {
    Bad "no curated YARA rules at $RulesDest"
} else {
    if (-not $FlareHost -or -not $SshKey) {
        Bad "cannot fetch rules: FLARE_HOST / FLARE_SSH_KEY not set (they live in .env)"
    } else {
        "  .... fetching the curated rule set from the FlareVM"
        New-Item -ItemType Directory -Force -Path $RulesDest | Out-Null
        $remote = "${User}@${FlareHost}:C:/Tools/yara-rules"
        & scp -i $SshKey -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -r $remote $RulesDest 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $n = @(Get-ChildItem $RulesDest -Recurse -File -EA SilentlyContinue).Count
            Ok "rules staged at $RulesDest ($n files)"
        } else {
            Bad "could not copy the rule set from the FlareVM - copy C:\Tools\yara-rules by hand"
        }
    }
}

# ---------------------------------------------------------------- report
""
"  === what the analysis plane will now find on this host ==="
& $py -c @"
import shutil, sys
need = {
    'yara (python)':  lambda: __import__('yara'),
    'capa (python)':  lambda: __import__('capa'),
    'floss (python)': lambda: __import__('floss'),
    'tshark':         lambda: shutil.which('tshark'),
    'strings':        lambda: shutil.which('strings'),
    '7z':             lambda: shutil.which('7z'),
}
import pathlib
rules = pathlib.Path(r'C:\Tools\yara-rules')
need['yara rules'] = lambda: rules if rules.is_dir() else None
missing = []
for label, probe in need.items():
    try:
        v = probe()
    except Exception:
        v = None
    print(('    [OK]     ' if v else '    [MISS]   ') + label)
    if not v: missing.append(label)
print()
print('    analysis plane: ' + ('READY' if not missing else 'MISSING ' + ', '.join(missing)))
sys.exit(1 if missing else 0)
"@
if ($LASTEXITCODE -ne 0) { $fails += "analysis plane still incomplete" }

""
if ($fails.Count -eq 0) {
    Write-Host "  control plane provisioned." -ForegroundColor Green
    exit 0
} else {
    Write-Host "  $($fails.Count) item(s) outstanding:" -ForegroundColor Red
    foreach ($f in $fails) { Write-Host "    - $f" -ForegroundColor Red }
    exit 1
}
