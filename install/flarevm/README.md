# WinRE-patched FLARE-VM installer

Drop-in replacement for the upstream [mandiant/flare-vm](https://github.com/mandiant/flare-vm)
`install.ps1`, plus a fixture config and a standalone post-install repair script.

```
install\flarevm\
  install.ps1          upstream script + small appended "WinRE patch" block (upstream content unmodified)
  config.xml           fixture package selection (the 193-package set validated for WinRE)
  flarevm-postfix.ps1  repair + readiness check (also runs standalone)
```

## Why

A default FLARE-VM install (Sep 2026) finished with **~60/193 packages failed**.
The reproducible causes:

| Cause | Effect | Fixed by |
|---|---|---|
| Pinned dependency conflicts (e.g. `vcredist140` newer than the pin) | cascades: `vcredist140.vm` fails -> `python3.vm` fails -> `sysinternals.vm`, `ghidra.vm`, ... fail | postfix retries `lib-bad` packages with `--ignore-dependencies` |
| Dead / checksum-mismatched upstream URLs (`regcool.vm`, ...) | individual package failures | reported only (upstream package issues; not WinRE-critical) |
| FLARE-VM 2026 ships the **Store WinDbg appx**, not classic `cdb.exe` | WinRE WinDbg pipeline (mcp-windbg, windbg_post) has no `cdb -z` | postfix installs `windows-sdk-10-version-2004-windbg` |
| Tool path drift (`yara-x\yr.exe`, `upx\upx-<ver>\upx.exe`, Ghidra in ProgramData) | WinRE path checks miss tools | WinRE `setup`/`verify` resolve alternates; see `docs/TOOL-PATHS.md` |

## Option A - recommended (patched installer + fixture)

On the Windows VM, **while it still has internet (NAT)**, and per FLARE-VM docs
(administrator PowerShell, Defender removed, snapshot taken):

```powershell
Set-ExecutionPolicy Unrestricted -Force
Unblock-File .\install.ps1
.\install.ps1 -customConfig .\config.xml -noWait -noGui -noChecks
```

- Omit `-noGui` if you want the category picker (the fixture is pre-selected).
- With `-customConfig` a supplied `config.xml` is used verbatim; add your own
  `<package name="..."/>` lines to extend it.
- At the end the WinRE patch runs `flarevm-postfix.ps1` automatically:
  retries failed packages, installs classic cdb, prints the WinRE checklist.
- Logs: `Desktop\winre-flarevm-postfix.log`, `%ProgramData%\_VM\log.txt`,
  `%ProgramData%\chocolatey\logs\choco.summary.log`.

## Option B - vanilla FLARE-VM, then postfix

If you already installed (or prefer) upstream `install.ps1`:

```powershell
.\flarevm-postfix.ps1
```

It is idempotent and safe on partial installs.

## What the patch changes (and what it does not)

- Upstream `install.ps1` content is **unmodified**. The patch is one appended
  block that calls `flarevm-postfix.ps1` (and prints a hint if the file is
  missing). Diff against upstream to verify.
- The postfix never removes packages; it only retries `lib-bad` entries with
  `--ignore-dependencies` and installs the three WinRE-critical extras if absent
  (`sysinternals.vm`, `ghidra.vm`, classic Debugging Tools).

## After FLARE-VM

WinRE's own installer still runs, and adds what FLARE-VM never covers:

```powershell
# from the synced repo on the VM
powershell -ExecutionPolicy Bypass -File C:\WinRE\install\setup-flarevm.ps1
```

That stages the OpenSSH/autostart pieces, builds the x64dbg MCP plugin from
vendored source, installs the offline pip wheel set, wires CADRE/idasql, and
prints the remaining manual items (Malcat, IDA Pro, `idasql.exe`).

Upstream: <https://github.com/mandiant/flare-vm> (Apache-2.0).
