# Tool-Paths — where WinRE expects every tool (and how to tell it otherwise)

This is the **tool-location contract**. `install/setup-flarevm.ps1 -CheckMode`
detects each entry below and tells you exactly what is missing; the pipeline
skips honestly when a tool is absent (never fake-fails, never invents
evidence). If you installed something somewhere else, set the env override
listed here — **no code changes needed**.

Legend: `[base]` = FlareVM installer ships it · `[setup]` = WinRE
`setup-flarevm.ps1` installs/verifies it · `[user]` = you install it ·
`[stage]` = `ops/provision_tools.ps1` can download it on the host and scp to
the air-gapped VM.

## Static analysis

| Tool | Expected default | Env override | Needed for | Missing → |
|---|---|---|---|---|
| Ghidra 11/12.x + CADRE loader `[user]` | `C:\Tools\ghidra_*_PUBLIC` (glob auto-detect) | `GHIDRA_INSTALL_DIR` (pyghidra fast-path) | ghidra_query, ghidra_decompile, signature SQL | deep skips ghidra tools → static weakens, honest skip |
| capa + mandiant rules `[base]` | `C:\Tools\capa\capa.exe` + `C:\Tools\capa-rules` | — | capability clusters (verdict driver) | capa evidence absent (pip fallback auto-tried) |
| floss `[base]` | pip module | — | decoded/stack strings | floss evidence absent |
| Detect It Easy `[base]`/`[stage]` | `C:\Tools\die\diec.exe` | — | packer/compiler taxonomy (decrypt-gate) | taxonomy falls back to entropy-only |
| yara-x `[base]` | `C:\Tools\yr\yr.exe` | — | curated-ruleset scan (verdict driver) | yara-hit rule can't fire |
| curated YARA rules `[setup]` | `C:\Tools\yara-rules` (`*.yar`) | `YARA_RULES_DIR` | family matches | yarascan reports `no rules staged` |
| Sysinternals strings64 `[base]` | `C:\Tools\sysinternals\strings64.exe` | — | raw string extraction | strings tool skips |
| radare2 `[base]` | `C:\Tools\radare2\radare2.exe` | — | r2_decompile, sink_sites | those tools skip |
| scdbg `[base]` | `C:\Tools\scdbg\scdbg.exe` | — | shellcode extraction emulation | shellcode_extract degrades |
| goresym `[user]`/`[stage]` | `C:\Tools\goresym\goresym.exe` | — | Go binaries only | goresym tool skips (Go detection gates it) |
| ILSpy CLI `[user]` | `%USERPROFILE%\.dotnet\tools\ilspycmd.exe` | — | .NET decompile | dotnet_analyze degrades to metadata-only |
| IDA Pro/Free + idasql `[user]` | `C:\Program Files\IDA Professional 9.3` (also probed: IDA Free 9.3/8.3, `C:\Tools\IDA*`) | **`WINRE_IDA_DIR`** (dir with `idat.exe`); **`IDASQL`** / `WINRE_IDASQL` (idasql.exe full path) | ida_query, .i64 creation | **IDA Free license is detected and skipped INSTANTLY with a clear message** — headless idalib/.i64 creation requires **IDA Professional** (activate Pro in the GUI, or point the env vars at a Pro install). Ghidra is canonical; IDA is corroboration |
| Malcat (portable) `[user]` | `C:\Tools\malcat\bin` (also probed: `C:\Program Files\Malcat\bin`, `%USERPROFILE%\Downloads\malcat\bin`) — must contain `bin\malcat.mcp.py` | `MALCAT_BIN_DIR`; license `MALCAT_LICENSE` (default `%APPDATA%\Malcat\license.dat`) | quick triage views, agent malcat tools, unpack compare | all malcat evidence skips honestly; Ghidra + x64dbg carry the analysis |

## Dynamic / detonation

| Tool | Expected default | Env override | Needed for | Missing → |
|---|---|---|---|---|
| x64dbg + MCP plugin `[base]`+`[setup]` | `C:\Tools\x64dbg` (+ `release\x64\plugins\x64dbg-MCP-Server.dp64`) | — | x64dbg OEP/dump/write-BP loops | agentic-dbg + debug loops unavailable |
| FakeNet-NG `[base]` | `C:\Tools\fakenet\fakenet3.5\fakenet.exe` | — | network sink, pcaps | detonation network evidence absent |
| Procmon `[base]` | `C:\Tools\sysinternals\Procmon64.exe` | — | file/reg/process capture | persistence/behavior analysis absent |
| pe-sieve `[base]` | `C:\ProgramData\chocolatey\bin\pe-sieve.exe` | — | injection/hollowing dumps + suspended-process monitor | memory dumps partial |
| hollows_hunter `[base]` | `C:\Tools\hollows_hunter\hollows_hunter.exe` | — | hollowing detection | best-effort skip |
| Frida `[base]` | pip module (Python 3.13) | — | API trace | frida trace absent |
| procdump `[base]` | `C:\Tools\sysinternals\Procdump64.exe` | — | post-mortem memory harvest | harvest skips; DFIR-Nexus gets other artifacts |
| Wireshark/tshark `[base]` | `C:\Program Files\Wireshark\tshark.exe` | — | pcap enrich + beacon analysis | network intel degrades |
| 7-Zip `[base]` | `C:\Program Files\7-Zip\7z.exe` (or PATH) | `WINRE_7Z` | DFIR-Nexus case packs | case pack falls back to .zip |
| WinDbg (Store/classic) `[base]` | — | — | windbg MCP (dump analysis) | windbg tools skip |
| VMWare Tools / hypervisor `[user]` | — | `WINRE_HYPERVISOR`, `WINRE_VM_PATH`, `WINRE_SNAPSHOT` | L2 snapshot auto-restore | manual snapshot discipline (gate observe mode) |

## Python deps (VM, `C:\Python313`)

Installed automatically by `setup-flarevm.ps1` (pip): `frida`, `flask`,
`pefile`, `psutil`, `oletools`, `pypdf`, `dnfile`, `z3`, `angr`,
`speakeasy`, plus `setuptools<81` (pinned — speakeasy imports
`pkg_resources`, removed in setuptools 81+).

Optional: `pyghidra` + `GHIDRA_INSTALL_DIR` → faster `ghidra_decompile`
(in-process); headless fallback otherwise.

## How a missing tool shows up (honesty contract)

- **Detection probe** — `install/setup-flarevm.ps1 -CheckMode` and
  `install/verify-flarevm.ps1` report `Ok` / `Manual` per tool with the exact
  expected path.
- **Runtime** — a tool that is absent returns `{"ok": false,
  "skipped": "<tool>: ..."}` and the checklist records a *skip*, not a
  failure. Commercial tools (Malcat/IDA) absent → no audit penalty.
  A tool that is *present but broken* is a real failure → `failed_tools`,
  `truly_green=False` (this distinction is what the double-audit fixed).
- **IDA specifically** — installed-at-preference is expected; set
  `WINRE_IDA_DIR`/`IDASQL` and re-run `verify-flarevm.ps1`. The pipeline
  probes Pro 9.3 → Free 9.3 → 8.3 → `C:\Tools\IDA*` in that order before
  skipping.