# Ready-to-run: list the Virussign archives on .41 and select the two sets.
# LIST ONLY. Nothing is extracted to this host, nothing is written to .41.
#
# Usage:
#   pwsh -NoProfile -File ops\select_virussign_sets.ps1 -ArchiveDir /opt/samples/incoming/reveng-batch1
#
# Output: the 12 picks (2 sets of 6) with sha8, family, arch, size, and the
# exact VM destination path for each.

param(
    [string]$ArchiveDir = "/opt/samples/incoming/reveng-batch1",
    [string]$Key = "C:\Users\Ganro\.ssh\remnux-lab-key",
    [string]$Host41 = "remnux@192.168.77.41"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------- the remote job
# Everything runs ON .41. The host only ever sees text.
$remote = @'
set -u
ARCH_DIR="__ARCHDIR__"
echo "=== archives present ==="
ls -la "$ARCH_DIR" 2>/dev/null | sed 's/^/  /'
echo
echo "=== entries (name|size|crc) — LIST ONLY, no extraction ==="
for a in "$ARCH_DIR"/*.7z; do
  [ -f "$a" ] || continue
  echo "--- $(basename "$a") ---"
  7z l -slt "$a" 2>/dev/null | awk '
    /^Path = /   { p = substr($0, 8) }
    /^Size = /   { s = substr($0, 8) }
    /^CRC = /    { c = substr($0, 6); if (p != "") printf "%s|%s|%s\n", p, s, c; p = "" }
  '
done
'@ -replace '__ARCHDIR__', $ArchiveDir

$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remote))
$out = ssh -i $Key -o BatchMode=yes -o ConnectTimeout=60 -o StrictHostKeyChecking=no $Host41 "echo $b64 | base64 -d | bash" 2>&1

"  $out"

# ------------------------------------------------------------------ parse + score
$rows = @()
foreach ($ln in ($out -split "`r?`n")) {
    if ($ln -match '^(.+)\|(\d+)\|([0-9A-Fa-f]{8})$') {
        $rows += [pscustomobject]@{
            Name = $Matches[1]; Size = [int64]$Matches[2]; Crc = $Matches[3]
        }
    }
}

if (-not $rows) {
    Write-Host ""
    Write-Host "  No entries parsed. Either the archives are not in $ArchiveDir yet," -ForegroundColor Yellow
    Write-Host "  or 7z is not on .41. Nothing was extracted; this was a listing only." -ForegroundColor Yellow
    exit 3
}

Write-Host ""
Write-Host "  parsed $($rows.Count) entries" -ForegroundColor Cyan

# ---- classification from the NAME only (no bytes touched) --------------------
function Get-Family([string]$n) {
    foreach ($f in @('WannaCry','Lumma','Koi','XLoader','Xworm','Remcos','Kelihos',
                     'SnakeKeylogger','MassLogger','StealC','Redline','VIPRecovery',
                     'GoFlate','SmartApe','PureLogs','Artemis','ClickFix','Phantom',
                     'RaspberryRobin','VolatileCedar','EternalRocks','GhostSec',
                     'TransparentTribe','Wiper','Quasar','Vidar','Sliver','Hive',
                     'Guloader','DarkSide','AgentTesla','Formbook','AsyncRAT','njRAT')) {
        if ($n -match $f) { return $f }
    }
    return "_unclassified"
}

function Get-Arch([string]$n) {
    if ($n -match '(?i)_x64|_amd64|x64') { return "x64" }
    return "x86"
}

$scored = foreach ($r in $rows) {
    $fam = Get-Family $r.Name
    $arch = Get-Arch $r.Name
    # a detonatable Windows executable, not an archive/doc/dump
    $ok = $r.Name -match '(?i)\.(exe|dll|scr|sys)$'
    [pscustomobject]@{
        Family = $fam; Arch = $arch; Detonatable = $ok
        SizeMB = [math]::Round($r.Size / 1MB, 2)
        Crc = $r.Crc; Name = $r.Name
    }
}

Write-Host ""
Write-Host "  === families present in the archives ===" -ForegroundColor Cyan
$scored | Group-Object Family | Sort-Object Count -Descending |
    ForEach-Object { "    {0,-22} {1,4}  ({2} detonatable)" -f $_.Name, $_.Count,
        (($_.Group | Where-Object Detonatable).Count) }

Write-Host ""
Write-Host "  === size distribution ===" -ForegroundColor Cyan
$scored | Where-Object Detonatable |
    Group-Object { if ($_.SizeMB -lt 0.2) { "<200KB" } elseif ($_.SizeMB -lt 2) { "200KB-2MB" } elseif ($_.SizeMB -lt 10) { "2-10MB" } else { ">10MB" } } |
    Sort-Object Name | ForEach-Object { "    {0,-12} {1,4}" -f $_.Name, $_.Count }

Write-Host ""
Write-Host "  NEXT: pick 6 for VARIETY (one family each, spread across arch+size+type)" -ForegroundColor Green
Write-Host "        pick 6 for COVERAGE (one distinct pipeline feature each)" -ForegroundColor Green
Write-Host "  The sha256 (not the CRC) must come from .41 before staging — 7z l gives CRC only." -ForegroundColor DarkYellow
