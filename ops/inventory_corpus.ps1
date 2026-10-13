# Inventory an already-extracted local corpus by content hash. This is metadata
# collection only: samples are never opened as processes or copied to a VM.
#
# Example:
#   pwsh -NoProfile -File ops\inventory_corpus.ps1 `
#     -SourceRoot G:\Virussign\batch -SourceLabel virussign-2026-10

param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,
    [Parameter(Mandatory = $true)]
    [string]$SourceLabel,
    [string]$Registry = "internal\sample-registry.json",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
    Write-Host "SourceRoot must be an existing extracted corpus directory: $SourceRoot" -ForegroundColor Red
    exit 2
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$resolvedSourceRoot = [IO.Path]::GetFullPath($SourceRoot)
$resolvedRegistry = if ([IO.Path]::IsPathRooted($Registry)) {
    $Registry
} else {
    Join-Path $repoRoot $Registry
}
$exitCode = 0
Push-Location $repoRoot
try {
    & $Python -m winre.corpus_registry inventory `
        --source-root $resolvedSourceRoot `
        --source-label $SourceLabel `
        --registry $resolvedRegistry
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($exitCode -ne 0) {
    exit $exitCode
}

Write-Host "Inventory recorded. Family remains unknown until supported by cited evidence."
Write-Host "No sample was executed and no sample bytes were copied to a VM."
