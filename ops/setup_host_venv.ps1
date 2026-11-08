#Requires -Version 5.1
<#
.SYNOPSIS
    setup_host_venv.ps1 - create and provision an isolated Python virtual environment on the control plane.

.DESCRIPTION
    Creates a dedicated virtual environment (.venv) on the analysis host using the
    tested reference interpreter (Python 3.13) and installs pinned dependencies from
    requirements-host.txt.

    Usage (on the control plane):
      powershell -ExecutionPolicy Bypass -File ops\setup_host_venv.ps1
      powershell -ExecutionPolicy Bypass -File ops\setup_host_venv.ps1 -CheckOnly
      powershell -ExecutionPolicy Bypass -File ops\setup_host_venv.ps1 -VenvDir "C:\path\to\.venv"
#>
param(
    [string]$VenvDir = "",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot

if (-not $VenvDir) {
    $VenvDir = Join-Path $repo ".venv"
}

function Ok($m)   { Write-Host "  [OK]     $m" -ForegroundColor Green }
Write-Host "=== WinRE host virtual environment setup ===" -ForegroundColor Cyan

# 1. Discover Python interpreter — prioritize Python 3.13
$pyExe = $null

# Probe py launcher for 3.13
$pyLauncher = (Get-Command py -EA SilentlyContinue).Source
if ($pyLauncher) {
    $cand = & py -3.13 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $cand -and (Test-Path $cand)) {
        $pyExe = $cand.Trim()
    }
}

# Fallback to python / python3 on PATH
if (-not $pyExe) {
    $cand = (Get-Command python -EA SilentlyContinue).Source
    if (-not $cand) { $cand = (Get-Command python3 -EA SilentlyContinue).Source }
    if ($cand) { $pyExe = $cand }
}

if (-not $pyExe) {
    Write-Host "  [MISS]   No Python executable found on PATH or via py launcher." -ForegroundColor Red
    exit 1
}

$pyVer = & $pyExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Ok "Base Python -> $pyExe (Python $pyVer)"

if ($pyVer -ne "3.13") {
    Write-Host "  [WARN]   Base Python is $pyVer; Python 3.13 is the reference tested interpreter." -ForegroundColor Yellow
    Write-Host "           (3.14+ emits langchain-core pydantic-v1 compatibility warnings; staged floss wheels are cp313)" -ForegroundColor Yellow
}

$venvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    $venvPython = Join-Path $VenvDir "bin/python"
}

if ($CheckOnly) {
    if (Test-Path $venvPython) {
        $vVer = & $venvPython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
        Ok "Venv exists at $VenvDir (Python $vVer)"
        exit 0
    } else {
        Write-Host "  [MISS]   Venv does not exist at $VenvDir" -ForegroundColor Red
        exit 1
    }
}

# 2. Create virtual environment if missing
if (-not (Test-Path $venvPython)) {
    Write-Host "  .... creating virtual environment at $VenvDir"
    & $pyExe -m venv $VenvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPython)) {
        Write-Host "  [FAIL]   Failed to create virtual environment at $VenvDir" -ForegroundColor Red
        exit 1
    }
    Ok "Virtual environment created at $VenvDir"
} else {
    Ok "Virtual environment already present at $VenvDir"
}

# 3. Install/upgrade pip and wheel
Write-Host "  .... upgrading pip, setuptools, and wheel in venv"
& $venvPython -m pip install --quiet --upgrade pip setuptools wheel 2>&1 | Out-Null

# 4. Install pinned requirements
$reqFile = Join-Path $repo "requirements-host.txt"
if (Test-Path $reqFile) {
    Write-Host "  .... installing requirements from $reqFile"
    & $venvPython -m pip install --quiet -r $reqFile
    if ($LASTEXITCODE -eq 0) {
        Ok "Dependencies installed successfully from requirements-host.txt"
    } else {
        Write-Host "  [WARN]   Some packages in requirements-host.txt failed to install; check logs above." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN]   $reqFile not found" -ForegroundColor Yellow
}

# 5. Verify core packages
Write-Host "=== Verifying core packages in venv ===" -ForegroundColor Cyan
& $venvPython -c @"
import sys
mods = ['langgraph', 'langchain_core', 'pydantic', 'flask', 'requests', 'yaml', 'yara', 'capa', 'floss', 'pytest']
missing = []
for m in mods:
    try:
        __import__(m)
        print(f'  [OK]     {m}')
    except Exception as e:
        print(f'  [MISS]   {m}: {e}')
        missing.append(m)
if missing:
    sys.exit(1)
"@

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n  Venv is fully provisioned and ready." -ForegroundColor Green
    Write-Host "  To activate in PowerShell:" -ForegroundColor DarkGray
    Write-Host "    & '$VenvDir\Scripts\Activate.ps1'" -ForegroundColor Cyan
} else {
    Write-Host "`n  Venv provisioned with missing modules." -ForegroundColor Yellow
}
