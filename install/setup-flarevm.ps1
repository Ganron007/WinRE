#Requires -Version 5.1
<#
.SYNOPSIS
    setup-flarevm.ps1 - one-shot WinRE bootstrap for a FlareVM.

.DESCRIPTION
    Idempotent bootstrap for the Windows side of the WinRE lab (mirror of
    RevAI's install/setup-remnux.sh). Safe to re-run: existing components
    are detected and left alone; repo-owned items (directories, launcher,
    marker, env template) are created only when missing.

    What it DOES automate:
      - C:\WinRE layout + C:\samples
      - Python module install (frida, flask) when missing
      - MCP autostart (Startup launcher + scheduled task) via
        install\install_mcp_autostart.ps1
      - clean-snapshot marker (C:\WinRE\.clean_snapshot)

    What it DETECTS and instructs (commercial / manual - never scripted):
      - FlareVM base, Ghidra + CADRE loader, Malcat + license,
        IDA Professional + idasql, x64dbg + MCP plugin build (Zig),
        FakeNet / Procmon / pe-sieve / hollows_hunter

    Usage (ON the FlareVM, after syncing the repo via ops\sync_to_flare.ps1):
      powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1
      powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1 -CheckMode   # dry-run, changes nothing
      powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1 -DisableUAC # reboot required
#>
param(
    [switch]$CheckMode,
    [switch]$DisableUAC
)

$ErrorActionPreference = "Continue"
$script:ERR = 0
$script:ACT = 0

function Ok([string]$m)     { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Act([string]$m)    { Write-Host "  [DO]   $m$(if ($CheckMode) { '  (dry-run)' })" -ForegroundColor Cyan; $script:ACT++ }
function Warn([string]$m)   { Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Fail([string]$m)   { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:ERR++ }
function Manual([string]$m) { Write-Host "  [MANUAL] $m" -ForegroundColor Magenta }
function Info([string]$m)   { Write-Host "  [INFO] $m" -ForegroundColor DarkGray }

function Ensure-Dir([string]$p) {
    if (Test-Path $p) { Ok "dir exists: $p" }
    else { Act "create dir: $p"; if (-not $CheckMode) { New-Item -ItemType Directory -Force -Path $p | Out-Null } }
}

function Ensure-FileFromRepo([string]$repo, [string]$dest) {
    if (Test-Path $dest) { Ok "exists: $dest" }
    elseif (Test-Path $repo) { Act "copy $(Split-Path $repo -Leaf) -> $dest"; if (-not $CheckMode) { Copy-Item $repo $dest -Force } }
    else { Warn "repo source missing: $repo" }
}

Write-Host "=== WinRE / FlareVM setup $(if ($CheckMode) { '(CHECK MODE - no changes)' }) ===" -ForegroundColor Cyan

# --- 0. repo present ---------------------------------------------------------
Write-Host ""
Write-Host "--- Repo (C:\WinRE) ---"
if (-not (Test-Path "C:\WinRE\winre\pipeline.py")) {
    Fail "C:\WinRE repo incomplete (winre\pipeline.py missing)."
    Manual "From the control plane run: ops\sync_to_flare.ps1  - then re-run this script."
} else { Ok "repo present (winre\pipeline.py)" }

# --- 1. layout ---------------------------------------------------------------
Write-Host ""
Write-Host "--- Layout ---"
foreach ($d in @("C:\WinRE", "C:\WinRE\winre", "C:\WinRE\tools", "C:\WinRE\logs",
                 "C:\WinRE\lock", "C:\WinRE\ops", "C:\WinRE\sessions", "C:\samples")) {
    Ensure-Dir $d
}

# --- 2. python + modules ------------------------------------------------------
Write-Host ""
Write-Host "--- Python ---"
$py = "C:\Python313\python.exe"
if (-not (Test-Path $py)) {
    # Self-heal for public users: FlareVM base ships Python 3.11; WinRE needs
    # 3.13 all-users at C:\Python313 (baked into MCP launcher + helpers).
    $pyCmd = Get-Command py -ErrorAction SilentlyContinue
    if ($pyCmd) {
        Act "install Python 3.13 (all users) via chocolatey"
        if (-not $CheckMode) {
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                & choco install python313 -y --no-progress 2>$null | Out-Null
            }
            if (-not (Test-Path $py) -and $pyCmd) {
                # launcher fallback: resolve the 3.13 interpreter path
                $resolved = (& py -3.13 -c "import sys; print(sys.executable)" 2>$null)
                if ($resolved -and (Test-Path $resolved.Trim())) {
                    $py = $resolved.Trim()
                    Info "using py -3.13 interpreter at $py (preferred: C:\Python313 all-users)"
                }
            }
        }
    }
}
if (Test-Path $py) { Ok "python -> $py" }
else {
    Fail "python missing at $py"
    Manual "Install Python 3.13 for ALL USERS to C:\Python313 (python.org), then re-run."
}
if (Test-Path $py) {
    # static-analysis python deps (KB-derived tools + revai-parity wrappers).
    # Air-gapped friendly: when the host staged wheels under
    # C:\Tools-staged\wheels, try --no-index first; only fall back to the
    # network when the local wheel set does not satisfy the module.
    $wheelDir = "C:\Tools-staged\wheels"
    # import name -> PyPI package name (needed where they differ)
    $pipNames = @{ "z3" = "z3-solver"; "speakeasy" = "speakeasy-emulator"; "mcp_windbg" = "mcp-windbg" }
    # angr needs sdist-only deps (cooldict/cppheaderparser/mulpyplexer) - no
    # offline wheel set exists; the deobf helper degrades gracefully, so a
    # miss is Info, not Warn.
    $optionalMods = @("angr")
    foreach ($mod in @("frida", "flask", "pefile", "psutil", "oletools",
                       "pypdf", "dnfile", "z3", "speakeasy", "mcp_windbg", "angr")) {
        & $py -c "import $mod" 2>$null
        if ($LASTEXITCODE -eq 0) { Ok "module $mod present"; continue }
        $pipName = if ($pipNames.ContainsKey($mod)) { $pipNames[$mod] } else { $mod }
        Act "pip install $pipName"
        if (-not $CheckMode) {
            if (Test-Path $wheelDir) {
                & $py -m pip install --quiet --no-index --find-links $wheelDir $pipName 2>$null
                & $py -c "import $mod" 2>$null
            }
            if ($LASTEXITCODE -ne 0) { & $py -m pip install --quiet $pipName }
            & $py -c "import $mod" 2>$null
            if ($LASTEXITCODE -eq 0) { Ok "module $mod installed" }
            elseif ($optionalMods -contains $mod) { Info "optional module $mod not installed (helper will skip it)" }
            else { Warn "module $mod still not importable - install manually (pip install $pipName)" }
        }
    }
    # speakeasy + floss import setuptools.pkg_resources. Two traps:
    #   - Python 3.12+ does not bundle setuptools at all (absent on fresh 3.13)
    #   - setuptools>=81 removed pkg_resources (deprecated).
    # Ensure setuptools<81 is importable either way.
    $stv = & $py -c "import setuptools; print(setuptools.__version__)" 2>$null
    $needPin = (-not $stv) -or ([version]$stv -ge [version]"81.0.0")
    if ($needPin) {
        Act "install/pin setuptools<81 (speakeasy pkg_resources; not bundled on Py3.12+)"
        if (-not $CheckMode) {
            if (Test-Path $wheelDir) {
                & $py -m pip install --quiet --no-index --find-links $wheelDir "setuptools<81" 2>$null
            }
            $stv2 = & $py -c "import setuptools; print(setuptools.__version__)" 2>$null
            if ((-not $stv2) -or ([version]$stv2 -ge [version]"81.0.0")) { & $py -m pip install --quiet "setuptools<81" }
            $stv3 = & $py -c "import setuptools; print(setuptools.__version__)" 2>$null
            if ($stv3) { Ok "setuptools $($stv3.Trim()) (<81)" } else { Warn "setuptools<81 still not importable" }
        }
    } else { Ok "setuptools $($stv.Trim()) (<81)" }
}

if (Test-Path $py) {
    & $py -m pip --version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Act "bootstrap pip (ensurepip)"
        if (-not $CheckMode) { & $py -m ensurepip --upgrade 2>$null | Out-Null }
    }
}

# --- 3. commercial/static tools: detect + instruct ----------------------------
Write-Host ""
Write-Host "--- Static tooling (detect + instruct) ---"

if ((Get-Command choco -ErrorAction SilentlyContinue) -or (Test-Path "C:\ProgramData\chocolatey\bin")) { Ok "chocolatey present" }
else { Manual "FlareVM base not detected (no chocolatey). Install FlareVM via its install.ps1 - see docs\PREREQUISITES.md." }

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
    Ok "Ghidra -> $($ghidra.FullName)"
    # Ghidra headless needs a SUPPORTED JDK. FlareVM 2026 ships OpenJDK 25,
    # which hangs Ghidra 12's launcher (batch lands on 'Press any key').
    # Pin a Ghidra-supported JDK (21) via support\launch.properties.
    $lp = Join-Path $ghidra.FullName "support\launch.properties"
    if (Test-Path $lp) {
        $jdk21 = @(Get-ChildItem "C:\Program Files\Eclipse Adoptium",
                                   "C:\Program Files\Java",
                                   "C:\Program Files\OpenJDK" -Directory -ErrorAction SilentlyContinue |
            Where-Object Name -match "^jdk-21") | Select-Object -First 1
        if (-not $jdk21 -and (Get-Command choco -ErrorAction SilentlyContinue)) {
            Act "install temurin21 (Ghidra-supported JDK; FlareVM ships JDK25 which hangs Ghidra)"
            if (-not $CheckMode) { & choco install temurin21 -y --no-progress 2>$null | Out-Null }
            $jdk21 = @(Get-ChildItem "C:\Program Files\Eclipse Adoptium" -Directory -ErrorAction SilentlyContinue |
                Where-Object Name -match "^jdk-21") | Select-Object -First 1
        }
        if ($jdk21) {
            $cur = (Select-String -Path $lp -Pattern "^JAVA_HOME_OVERRIDE=(.*)$" |
                Select-Object -First 1).Matches.Groups[1].Value
            if ($cur -ne $jdk21.FullName) {
                Act "pin Ghidra JAVA_HOME_OVERRIDE -> $($jdk21.FullName)"
                if (-not $CheckMode) {
                    Copy-Item $lp "$lp.winre.bak" -Force -ErrorAction SilentlyContinue
                    $txt = Get-Content $lp -Raw
                    if ($txt -match "(?m)^JAVA_HOME_OVERRIDE=") {
                        $txt = $txt -replace "(?m)^JAVA_HOME_OVERRIDE=.*$", "JAVA_HOME_OVERRIDE=$($jdk21.FullName)"
                    } else {
                        $txt += "`nJAVA_HOME_OVERRIDE=$($jdk21.FullName)`n"
                    }
                    Set-Content -Path $lp -Value $txt -Encoding ASCII
                }
            } else { Ok "Ghidra JAVA_HOME_OVERRIDE pinned ($($jdk21.Name))" }
        } else {
            Manual "Ghidra needs a supported JDK (21): choco install temurin21, then set JAVA_HOME_OVERRIDE=<jdk-21 dir> in $lp (FlareVM ships JDK25 -> analyzeHeadless hangs)."
        }
    }
    $extDir = Join-Path $ghidra.FullName "Ghidra\Extensions"
    $loader = Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -match "CADRE" | Select-Object -First 1
    if (-not $loader -and (Test-Path "C:\Tools-staged\cadre-pe-loader")) {
        Act "install CADRE PE loader -> $extDir\CADRE"
        if (-not $CheckMode) {
            New-Item -ItemType Directory -Force -Path $extDir | Out-Null
            Copy-Item "C:\Tools-staged\cadre-pe-loader" (Join-Path $extDir "CADRE") -Recurse -Force
        }
        $loader = Get-Item (Join-Path $extDir "CADRE") -ErrorAction SilentlyContinue
    }
    if ($loader) { Ok "CADRE PE loader -> $($loader.Name)" }
    else { Manual "Copy the CADRE PE loader into $extDir (stage RevAI\extensions\cadre-pe-loader via ops\reapply_after_revert.ps1, or build RevEng\Tools\cadre-ghidra-loader)." }
    # SQL-first (RevAI parity): Ghidra SQL is served by the real engine -
    # LibGhidraHost extension (RPC host) + ghidrasql.exe (SQLite SQL, HTTP
    # :18080). No fallback stub. Staged artifacts live under
    # C:\Tools-staged\sql\ (LibGhidraHost.zip, ghidrasql.exe).
    $stagedSql = @("C:\Tools-staged\sql", "C:\Tools-staged") |
        Where-Object { Test-Path (Join-Path $_ "LibGhidraHost.zip") } | Select-Object -First 1
    if (-not (Test-Path (Join-Path $extDir "LibGhidraHost"))) {
        if ($stagedSql) {
            Act "install LibGhidraHost extension -> $extDir\LibGhidraHost"
            if (-not $CheckMode) {
                New-Item -ItemType Directory -Force -Path $extDir | Out-Null
                $tmp = Join-Path $env:TEMP "LibGhidraHost-$(Get-Random)"
                Expand-Archive -Path (Join-Path $stagedSql "LibGhidraHost.zip") -DestinationPath $tmp -Force
                # zip may contain a top-level folder; normalize
                $inner = Get-ChildItem $tmp -Directory | Where-Object { Test-Path (Join-Path $_.FullName "lib") } | Select-Object -First 1
                $src = if ($inner) { $inner.FullName } else { $tmp }
                Copy-Item $src (Join-Path $extDir "LibGhidraHost") -Recurse -Force
                Remove-Item $tmp -Recurse -Force -EA SilentlyContinue
            }
        } else {
            Manual "LibGhidraHost extension missing - stage it (ops\provision_tools.ps1) or build: libghidra/ghidra-extension -> gradle installExtension (docs\SQL-GHIDRA.md)."
        }
    }
    if (Test-Path (Join-Path $extDir "LibGhidraHost")) { Ok "LibGhidraHost (Ghidra SQL host) present" }
    else { Warn "LibGhidraHost NOT installed - ghidra_query will fail (SQL-first requires it)" }

    $stagedGrs = @("C:\Tools-staged\sql\ghidrasql.exe", "C:\Tools-staged\ghidrasql.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not (Test-Path "C:\Tools\ghidrasql\ghidrasql.exe")) {
        if ($stagedGrs) {
            Act "install ghidrasql.exe -> C:\Tools\ghidrasql"
            if (-not $CheckMode) {
                New-Item -ItemType Directory -Force -Path "C:\Tools\ghidrasql" | Out-Null
                Copy-Item $stagedGrs "C:\Tools\ghidrasql\ghidrasql.exe" -Force
            }
        } else {
            Manual "ghidrasql.exe missing - stage it (ops\provision_tools.ps1) or build ghidrasql 0.0.6 against libghidra main (docs\SQL-GHIDRA.md)."
        }
    }
    if (Test-Path "C:\Tools\ghidrasql\ghidrasql.exe") {
        Ok "ghidrasql engine -> C:\Tools\ghidrasql\ghidrasql.exe"
    } else { Warn "ghidrasql engine NOT installed - ghidra_query will fail (SQL-first requires it)" }

    # Project ownership: Ghidra records the project owner from java user.name;
    # SSH vs Task Scheduler contexts differ in case (flare-vm vs FLARE-VM) and
    # a mismatch aborts the headless host with NotOwnerException. Pin it.
    $lp = Join-Path $ghidra.FullName "support\launch.properties"
    if ((Test-Path $lp) -and -not (Select-String -Path $lp -Pattern "user\.name=flare-vm" -Quiet)) {
        Act "pin Ghidra VMARGS=-Duser.name=flare-vm (project ownership)"
        if (-not $CheckMode) {
            Add-Content -Path $lp -Value "VMARGS=-Duser.name=flare-vm" -Encoding ASCII
        }
    }
} else { Manual "Install Ghidra 11/12.x to C:\Tools\ghidra_<version> (docs\PREREQUISITES.md)." }

$malcatBin = @("C:\Tools\malcat\bin", "C:\Program Files\Malcat\bin",
               "C:\Users\$env:USERNAME\Downloads\malcat\bin") |
    Where-Object { Test-Path (Join-Path $_ "malcat.mcp.py") } | Select-Object -First 1
if ($malcatBin) {
    Ok "Malcat -> $malcatBin"
    if ($malcatBin -ne "C:\Tools\malcat\bin") {
        Info "canonical Malcat location is C:\Tools\malcat (folder name 'malcat') - move it there for consistency"
    }
    $malcatPy = Join-Path $malcatBin "python313\python.exe"
    if (-not (Test-Path $malcatPy)) { $malcatPy = "C:\Python313\python.exe" }
    $licOut = & $malcatPy -c "import sys; sys.path.insert(0, r'$malcatBin'); import malcat; print(malcat.env.flavor)" 2>$null
    $licVal = if ($licOut) { $licOut.Trim() } else { "unknown" }
    if ($licOut -match "FULL|OEM|PRO") { Ok "Malcat license ACTIVE ($($licOut.Trim()))" }
    else { Manual "Activate the Malcat license: open C:\Tools\malcat\bin\malcat.exe -> Preferences -> License, paste the license (it writes %APPDATA%\Malcat\license.dat). Headless API currently reports: $licVal." }
} else {
    Manual "Install the portable Malcat at C:\Tools\malcat (keep the folder name 'malcat'; expected C:\Tools\malcat\bin\malcat.exe + malcat.mcp.py), then activate the license -> %APPDATA%\Malcat\license.dat. Also probed: C:\Program Files\Malcat, %USERPROFILE%\Downloads\malcat. docs\PREREQUISITES.md."
}

$idaDir = if ($env:WINRE_IDA_DIR) { $env:WINRE_IDA_DIR } else { "C:\Program Files\IDA Professional 9.3" }
$idaCands = @()
if ($env:WINRE_IDA_DIR) { $idaCands += $env:WINRE_IDA_DIR }
$idaCands += @("C:\Program Files\IDA Professional 9.3", "C:\Program Files\IDA Free 9.3",
               "C:\Program Files\IDA Professional 8.3", "C:\Tools\IDA Pro 9.3",
               "C:\Tools\IDA Free 9.3")
$idaResolved = $idaCands | Where-Object { Test-Path (Join-Path $_ "idat.exe") } | Select-Object -First 1
if ($idaResolved) {
    Ok "IDA -> $idaResolved"
    $idasqlPath = Join-Path $idaResolved "idasql.exe"
    if (Test-Path $idasqlPath) { Ok "idasql present" }
    elseif (Test-Path "C:\Tools-staged\idasql.exe") {
        Act "install idasql.exe -> $idaResolved"
        if (-not $CheckMode) {
            Copy-Item "C:\Tools-staged\idasql.exe" $idasqlPath -Force
            if (Test-Path $idasqlPath) { Ok "idasql installed (from staged copy)" }
            else { Manual "copy failed - place idasql.exe next to idat.exe manually" }
        }
    } else {
        Manual "idasql.exe missing (IDA SQL; FREE release github.com/allthingsida/idasql): run ops\provision_tools.ps1 on the host (auto-downloads + stages), or place a copy at C:\Tools-staged\idasql.exe - setup installs it next to idat.exe."
    }
    # license-flavor resolution (same order IDA itself uses: profile first).
    # A stale FREE license in AppData SHADOWS a real PRO license in the
    # install dir for headless runs — the #1 user-side IDA integration trap.
    $proLic = Get-ChildItem $idaResolved -Filter "idapro*.hexlic" -ErrorAction SilentlyContinue | Select-Object -First 1
    $freeLic = Get-ChildItem (Join-Path $env:APPDATA "Hex-Rays\IDA Pro") -Filter "idafree*.hexlic" -ErrorAction SilentlyContinue | Select-Object -First 1
    # hygiene: stale Free license backups (we move them aside on shadowing;
    # once IDA Free is uninstalled they are dead weight + confusing)
    if (-not $freeLic) {
        Get-ChildItem (Join-Path $env:APPDATA "Hex-Rays\IDA Pro") -Filter "*.bak.stale-*" -ErrorAction SilentlyContinue |
            ForEach-Object { Act "remove stale IDA license backup $($_.Name)"; if (-not $CheckMode) { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } }
    }
    # hygiene: broken desktop shortcut to an uninstalled IDA Free
    $idaLnk = Join-Path ([Environment]::GetFolderPath("Desktop")) "Tools\Disassemblers\ida.lnk"
    if (Test-Path $idaLnk) {
        try {
            $shc = New-Object -ComObject WScript.Shell
            $tgt = $shc.CreateShortcut($idaLnk).TargetPath
            if ($tgt -and -not (Test-Path $tgt)) {
                Act "remove broken shortcut $idaLnk (points at $tgt)"
                if (-not $CheckMode) { Remove-Item $idaLnk -Force -ErrorAction SilentlyContinue }
            }
        } catch {}
    }
    if ($proLic -and -not $freeLic) {
        Ok "IDA PRO license present ($($proLic.Name)) - headless ida_query/.i64 fully supported"
    } elseif ($proLic -and $freeLic) {
        # AUTO-FIX (idempotent, reversible): a stale FREE license in the user
        # profile shadows the PRO license for headless runs (profile is
        # checked first) - idalib then fails and idasql hangs. Move it aside
        # with a timestamped backup so Pro is visible.
        $stamp = Get-Date -Format "yyyy-MM-dd"
        $bak = "$($freeLic.FullName).bak.stale-$stamp"
        Act "IDA license SHADOWING: PRO ($($proLic.Name)) shadowed by stale FREE ($($freeLic.Name)) - moving aside to $bak"
        if (-not $CheckMode) {
            Move-Item $freeLic.FullName $bak -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $freeLic.FullName)) { Ok "stale free license moved aside (backup: $bak)" }
            else { Manual "Could not move $($freeLic.FullName) - move/rename it manually (keep a backup) so idalib sees Pro." }
        }
    } elseif ($freeLic) {
        Warn "IDA FREE license only ($($freeLic.Name)) - headless ida_query/.i64 unsupported (GUI-only). Ghidra stays canonical; activate Pro to enable IDA participation."
    } else {
        Info "no *.hexlic found in install dir or profile - IDA will prompt/need activation; headless ida_query requires a Pro license."
    }
} else {
    Warn "IDA not detected (optional - deep degrades to Ghidra+Malcat)."
    if (-not $env:WINRE_IDA_DIR) { Info "Installed IDA somewhere else? Set WINRE_IDA_DIR (and IDASQL) so the pipeline finds it - see docs\TOOL-PATHS.md." }
}

# --- 3b. free static tooling (FlareVM base ships some; detect + instruct) -----
Write-Host ""
Write-Host "--- Free static tooling ---"
# Tool locations drift between FlareVM releases (2026: yara-x -> Tools\yara-x,
# UPX -> Tools\upx\upx-<ver>\, ilspycmd -> Tools\ilspycmd) - resolve + PATH.
function Resolve-Tool([string[]]$paths, [string[]]$names) {
    foreach ($p in $paths) { if ($p -and (Test-Path $p)) { return $p } }
    foreach ($n in $names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c -and $c.Source) { return $c.Source }
    }
    return $null
}
foreach ($t in @(
        @("capa (REQUIRED free; pip fallback auto-used)", @("C:\Tools\capa\capa.exe"), @("capa.exe")),
        @("capa-rules dir (REQUIRED free; mandiant/capa-rules)", @("C:\Tools\capa-rules"), @()),
        @("Detect It Easy diec (REQUIRED free)", @("C:\Tools\die\diec.exe"), @("diec.exe")),
        @("yara-x scanner (REQUIRED free)", @("C:\Tools\yr\yr.exe", "C:\Tools\yara-x\yr.exe"), @("yr.exe", "yara-x.exe")),
        @("curated YARA rules dir (REQUIRED free)", @("C:\Tools\yara-rules"), @()),
        @("scdbg shellcode emulator (free)", @("C:\Tools\scdbg\scdbg.exe"), @("scdbg.exe")),
        @("Sysinternals strings64 (free)", @("C:\Tools\sysinternals\strings64.exe"), @("strings64.exe")))) {
    $hit = Resolve-Tool $t[1] $t[2]
    if ($hit) { Ok "$($t[0]) present -> $hit" }
    else { Manual "Install $($t[0]) - run install\flarevm\flarevm-postfix.ps1 (online) or stage via ops\provision_tools.ps1 (host); see docs\TOOL-PATHS.md." }
}
# UPX ships in a versioned subdir on FlareVM 2026
$upxHit = Resolve-Tool @("C:\Tools\upx\upx.exe") @("upx.exe")
if (-not $upxHit) {
    $upxHit = Get-ChildItem "C:\Tools\upx" -Recurse -Filter "upx.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}
if ($upxHit) { Ok "UPX (free) present -> $upxHit" }
else { Manual "Install UPX - run install\flarevm\flarevm-postfix.ps1 or stage via ops\provision_tools.ps1." }
# radare2 is absent from FlareVM 2026 package sets - optional
$r2Hit = Resolve-Tool @("C:\Tools\radare2\radare2.exe") @("radare2.exe", "r2.exe")
if ($r2Hit) { Ok "radare2 (free, optional) present -> $r2Hit" }
else { Info "radare2 not present (optional; absent in FlareVM 2026 - r2_decompile degrades)" }
$goHit = Resolve-Tool @("C:\Tools\goresym\goresym.exe", "C:\Tools\GoReSym\GoReSym.exe") @("GoReSym.exe", "goresym.exe")
if ($goHit) { Ok "goresym (free; Go samples only) present -> $goHit" }
else { Manual "Install goresym - stage via ops\provision_tools.ps1." }
$ilspyHit = Resolve-Tool @("$env:USERPROFILE\.dotnet\tools\ilspycmd.exe", "C:\Tools\ilspycmd\ilspycmd.exe") @("ilspycmd.exe")
if ($ilspyHit) { Ok "ilspycmd (.NET) present -> $ilspyHit" }
else { Manual "Install ILSpy CLI: dotnet tool install -g ilspycmd (see docs\TOOL-PATHS.md)." }

$x64 = "C:\Tools\x64dbg\release\x64\x64dbg.exe"
if (Test-Path $x64) {
    Ok "x64dbg -> $x64"
    $plug = Get-ChildItem "C:\Tools\x64dbg" -Recurse -Depth 4 -Include "*.dp64", "*.dp32" -ErrorAction SilentlyContinue |
        Where-Object Name -match "^x64dbg-MCP-Server" | Select-Object -First 1
    if ($plug) { Ok "MCP plugin -> $($plug.FullName)" }
    else {
        # ---- fresh-VM plugin chain: source -> patch -> zig -> build ----
        # source: repo integrations\ OR the host-staged clone (provision_tools)
        $srcDir = Get-ChildItem "C:\WinRE\integrations" -Directory -ErrorAction SilentlyContinue |
            Where-Object Name -match "^x64dbg-mcp-server" | Select-Object -First 1
        if (-not $srcDir) {
            $stagedSrc = Get-ChildItem "C:\Tools-staged" -Directory -ErrorAction SilentlyContinue |
                Where-Object Name -match "^x64dbg-mcp-server" | Select-Object -First 1
            if ($stagedSrc) {
                Act "copy staged plugin source -> C:\WinRE\integrations\x64dbg-mcp-server"
                if (-not $CheckMode) {
                    New-Item -ItemType Directory -Force -Path "C:\WinRE\integrations" | Out-Null
                    Copy-Item $stagedSrc.FullName "C:\WinRE\integrations\x64dbg-mcp-server" -Recurse -Force
                    $srcDir = Get-Item "C:\WinRE\integrations\x64dbg-mcp-server" -ErrorAction SilentlyContinue
                } else {
                    $srcDir = $stagedSrc
                }
            }
        }
        # our one-line patch (hardware-BP failures must surface)
        if ($srcDir -and (Test-Path "C:\WinRE\tools\x64dbg-mcp-winre.patch")) {
            $toolsZig = Join-Path $srcDir.FullName "src\mcp\tools.zig"
            if ((Test-Path $toolsZig) -and
                -not (Select-String -Path $toolsZig -Pattern "WinRE" -Quiet)) {
                Act "apply tools\x64dbg-mcp-winre.patch"
                if (-not $CheckMode) {
                    Push-Location $srcDir.FullName
                    git apply "C:\WinRE\tools\x64dbg-mcp-winre.patch" 2>&1 | Select-Object -Last 2
                    Pop-Location
                    if (Select-String -Path $toolsZig -Pattern "WinRE" -Quiet) { Ok "patch applied" }
                    else { Manual "git apply failed - apply tools\x64dbg-mcp-winre.patch manually (docs\X64DBG-MCP.md)." }
                }
            }
        }
        # zig: on PATH, else auto-unzip the staged toolchain to C:\Tools\zig
        $zigCmd = Get-Command zig -ErrorAction SilentlyContinue
        if (-not $zigCmd -and -not (Test-Path "C:\Tools\zig\zig.exe")) {
            $zigZip = Get-ChildItem "C:\Tools-staged" -File -ErrorAction SilentlyContinue |
                Where-Object Name -match "^zig.*\.zip$" | Select-Object -First 1
            if ($zigZip) {
                Act "unzip $($zigZip.Name) -> C:\Tools\zig"
                if (-not $CheckMode) {
                    Expand-Archive -Path $zigZip.FullName -DestinationPath "C:\Tools\zig-tmp" -Force -ErrorAction SilentlyContinue
                    $inner = Get-ChildItem "C:\Tools\zig-tmp" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($inner) { Move-Item $inner.FullName "C:\Tools\zig" -Force }
                    Remove-Item "C:\Tools\zig-tmp" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        if (Test-Path "C:\Tools\zig\zig.exe") { $env:PATH = "C:\Tools\zig;$env:PATH" }
        $zigCmd = Get-Command zig -ErrorAction SilentlyContinue
        if ($srcDir -and $zigCmd) {
            Act "build x64dbg MCP plugin (zig build) from $($srcDir.FullName)"
            if (-not $CheckMode) {
                Push-Location $srcDir.FullName
                & $zigCmd.Path build 2>&1 | Select-Object -Last 3
                $built = Get-ChildItem "zig-out" -Recurse -Include "*.dp64", "*.dp32" -ErrorAction SilentlyContinue |
                    Where-Object Name -match "^x64dbg-MCP-Server" | Select-Object -First 1
                if ($built) {
                    $plugDir = Join-Path (Split-Path $x64) "plugins"
                    New-Item -ItemType Directory -Force -Path $plugDir | Out-Null
                    Copy-Item $built.FullName $plugDir -Force
                    Ok "plugin deployed: $($built.Name) -> $plugDir"
                } else { Manual "zig build produced no plugin - build manually (docs\X64DBG-MCP.md)." }
                Pop-Location
            }
        } else {
            if (-not $srcDir) { Manual "MCP plugin source missing - clone duty1g/x64dbg-mcp-server into C:\WinRE\integrations, or run ops\provision_tools.ps1 on the host (docs\X64DBG-MCP.md)." }
            if (-not $zigCmd) { Manual "zig missing - stage C:\Tools-staged\zig-*.zip via ops\provision_tools.ps1 (zig 0.14+, build.zig.zon minimum) or install manually (docs\X64DBG-MCP.md)." }
        }
    }
} else { Manual "REQUIRED (free): install x64dbg to C:\Tools\x64dbg - run the FlareVM base installer (brings it) or download the release; then re-run setup. docs\PREREQUISITES.md." }

foreach ($t in @(@("FakeNet-NG (REQUIRED free)", @("C:\Tools\fakenet\fakenet3.5\fakenet.exe"), @("fakenet.exe")),
                 @("Procmon (REQUIRED free)", @("C:\Tools\sysinternals\Procmon64.exe"), @("Procmon64.exe")),
                 @("procdump", @("C:\Tools\sysinternals\Procdump64.exe", "C:\Tools\sysinternals\procdump64.exe"), @("procdump64.exe")),
                 @("cdb (classic debugger; WinDbg MCP/post-mortem)", @("C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe", "C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe"), @("cdb.exe")),
                 @("pe-sieve (REQUIRED free)", @("C:\ProgramData\chocolatey\bin\pe-sieve.exe"), @("pe-sieve.exe", "pe-sieve64.exe")),
                 @("hollows_hunter (REQUIRED free)", @("C:\Tools\hollows_hunter\hollows_hunter.exe"), @("hollows_hunter.exe", "hollows_hunter64.exe")))) {
    $hit = Resolve-Tool $t[1] $t[2]
    if ($hit) { Ok "$($t[0]) present -> $hit" }
    else { Manual "REQUIRED: install $($t[0]) - run install\flarevm\flarevm-postfix.ps1 (online) or stage via ops\provision_tools.ps1 (host). docs\PREREQUISITES.md." }
}

# --- 4. repo-owned: autostart + task ------------------------------------------
Write-Host ""
Write-Host "--- MCP autostart ---"
$autostart = "C:\WinRE\install\install_mcp_autostart.ps1"
if (Test-Path $autostart) {
    if ($CheckMode) { Act "run install_mcp_autostart.ps1 (idempotent)" }
    else {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $autostart
        if ($LASTEXITCODE -eq 0) { Ok "autostart installer ran (idempotent)" }
        else { Warn "autostart installer exit=$LASTEXITCODE" }
    }
} else { Warn "install_mcp_autostart.ps1 missing from repo" }

$task = Get-ScheduledTask -TaskName "WinRE-X64dbg-Once" -ErrorAction SilentlyContinue
if ($task) { Ok "scheduled task WinRE-X64dbg-Once present" }
else { Warn "scheduled task WinRE-X64dbg-Once absent - x64dbg MCP needs a console-session kick; create it per docs\X64DBG-MCP.md or let the on-demand manager launch x64dbg." }

# --- 4b. logon hygiene (idempotent) -------------------------------------------
# FlareVM's BinDiff installer leaves a machine Run entry (BinDiffPerUserSetup)
# that HANGS at every logon (GUI-ish setup, observed >20s) and produces
# "bindiff_config_setup.exe - Application Error 0xc0000142" popups when the
# session ends during its init. Remove it; per-user setup can be re-run
# manually if ever needed.
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$bindiffRun = (Get-ItemProperty $runKey -ErrorAction SilentlyContinue).BinDiffPerUserSetup
if ($bindiffRun) {
    Act "remove stale BinDiff per-user setup Run entry (hangs at logon)"
    if (-not $CheckMode) { Remove-ItemProperty -Path $runKey -Name "BinDiffPerUserSetup" -ErrorAction SilentlyContinue }
} else { Ok "no stale BinDiff logon Run entry" }

# --- 5. repo-owned: env template + gate marker ---------------------------------
Write-Host ""
Write-Host "--- Env template + snapshot gate ---"
$template = "C:\WinRE\.env.template"
$tmplBody = @"
# WinRE control-plane LLM config (copy to .env on the CONTROL PLANE, never commit .env)
WINRE_LLM_BASE_URL=
WINRE_LLM_MODEL=
WINRE_LLM_REASONING=
WINRE_LLM_API_KEY=
"@
if (Test-Path $template) { Ok "env template present" }
else { Act "write $template"; if (-not $CheckMode) { [System.IO.File]::WriteAllText($template, $tmplBody, (New-Object System.Text.UTF8Encoding($true))) } }
Info "LLM keys live on the CONTROL PLANE (.env next to the repo there) - the VM does not need them."

$marker = "C:\WinRE\.clean_snapshot"
if (Test-Path $marker) { Ok "clean-snapshot marker present" }
else {
    Act "create marker $marker"
    if (-not $CheckMode) {
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        Set-Content -LiteralPath $marker -Encoding ASCII `
            -Value ("created=" + (Get-Date -Format o) + ";boot_epoch=" + $boot.ToString("o"))
    }
}
if (-not $CheckMode) { Manual "TAKE/UPDATE the VM snapshot NOW so the marker is baked in (restores re-create it)." }

# --- 6. VM desktop status shortcut ---------------------------------------------
Write-Host ""
Write-Host "--- VM desktop status shortcut ---"
$desktop = [Environment]::GetFolderPath("Desktop")
$statusBat = Join-Path $desktop "WinRE-Status.bat"
$batBody = "@echo off`r`n" +
           "title WinRE Status`r`n" +
           "powershell -NoProfile -ExecutionPolicy Bypass -File `"C:\WinRE\install\verify-flarevm.ps1`"`r`n" +
           "echo.`r`n" +
           "pause`r`n"
if ((Test-Path $statusBat) -and ((Get-Item $statusBat).Length -gt 100)) { Ok "desktop WinRE-Status.bat present" }
else { Act "create $statusBat"; if (-not $CheckMode) { [System.IO.File]::WriteAllText($statusBat, $batBody, (New-Object System.Text.UTF8Encoding($true))) } }
Info "double-click it anytime for the full VM-side PASS/FAIL battery"

# --- 6b. UAC / debugger elevation ----------------------------------------------
# x64dbg carries an admin manifest. Scheduled-task launches already use
# RunLevel=Highest (no prompt); disabling UAC additionally makes MANUAL
# launches silent. Lab VM only - never do this on a daily-driver host.
Write-Host ""
Write-Host "--- UAC / debugger elevation ---"
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$enableLua = (Get-ItemProperty -Path $uacKey -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($DisableUAC) {
    if ($enableLua -eq 0) { Ok "UAC already disabled (EnableLUA=0)" }
    else {
        Act "disable UAC (EnableLUA=0; ConsentPromptBehaviorAdmin=0; PromptOnSecureDesktop=0)"
        if (-not $CheckMode) {
            Set-ItemProperty -Path $uacKey -Name EnableLUA -Value 0 -Type DWord
            Set-ItemProperty -Path $uacKey -Name ConsentPromptBehaviorAdmin -Value 0 -Type DWord
            Set-ItemProperty -Path $uacKey -Name PromptOnSecureDesktop -Value 0 -Type DWord
        }
        Manual "REBOOT the VM so UAC-off takes effect, THEN take/refresh the snapshot."
    }
} elseif ($enableLua -eq 0) {
    Ok "UAC disabled (EnableLUA=0) - x64dbg manual launches run elevated silently"
} else {
    Warn "UAC enabled: task-launched x64dbg is elevated with no prompt; manual launches will prompt. Re-run with -DisableUAC (then reboot) to silence."
}

# --- 7. verify -----------------------------------------------------------------
Write-Host ""
if ($CheckMode) {
    Write-Host "=== Check mode complete: $script:ACT action(s) would be taken, $script:ERR blocker(s) ===" -ForegroundColor Cyan
} else {
    Write-Host "--- Final verification ---"
    & powershell -NoProfile -ExecutionPolicy Bypass -File "C:\WinRE\install\verify-flarevm.ps1"
    $script:ERR += $LASTEXITCODE
    Write-Host "=== Setup complete: $script:ACT action(s) taken, $script:ERR FAIL(s) in verify ===" -ForegroundColor Cyan
}
exit ([int]($script:ERR -gt 0))
