# Prerequisites

> **Scope:** what must exist before `install/setup-flarevm.ps1` runs. **Audience:** deployers.

Everything needed before `install/setup-flarevm.ps1` can bootstrap a WinRE
FlareVM. Read together with [`INSTALL.md`](INSTALL.md).

## Lab topology

WinRE uses a two-plane split: a **control plane** (LLM connection, UI,
reporting, and remote driver) drives a **FlareVM** (Windows tooling and sample
execution) over SSH. After initial deployment, keep Flare on a private,
non-routed analysis network. The standard Windows dynamic job starts
FakeNet-NG inside Flare; FakeNet supplies its DNS sink and guest-side packet
captures. FakeNet does not replace hypervisor isolation or prove that every
route is contained.

```
+--------------------------+         SSH / HTTP          +---------------------------+
|  control plane (host)    |  -------------------------> |  FlareVM (Windows 10)    |
|  - winre/ pipeline code  |   OpenSSH (22)              |  - C:\WinRE (repo copy)   |
|  - .env (LLM keys)       |   MCP HTTP (see below)      |  - Ghidra / IDA / Malcat  |
|  - UI :5001              |                             |  - x64dbg + MCP plugin    |
|  - logs/ evidence packs  |   <---- evidence back ----  |  - FakeNet / Procmon /    |
+--------------------------+                             |    Frida / pe-sieve       |
                                                         +---------------------------+
                                                         host-only / isolated NAT
```

Default MCP ports (VM side): Malcat `:9009` and WinDbg `:9097` bind
localhost on the VM (reached via the SSH-exec bridge), x64dbg `:9094`
binds all interfaces.

## Control plane (operator host)

- **Windows 10/11 or Linux** with OpenSSH client (`ssh`, `scp`) and Python
  **3.10+** (3.13 tested)
- Python packages: `langchain-openai`, `langgraph`, `langchain-core`,
  `pydantic` (see `.env.template` for LLM config)
- An **OpenAI-compatible LLM endpoint** (model, base URL, API key) for the
  deep-dive agent. Optional — without it the pipeline runs deterministic
  fallbacks and stays honest about it (`deterministic_fallback`)
- The FlareVM SSH private key on disk (path configured via `FLARE_SSH_KEY`)
- The repo itself (git clone)

## FlareVM (execution VM)

Start from a **Windows 10 VM on an isolated/host-only network**. Windows 10
is the documented execution target; Windows 11 detonation support has not
been established.

### Install order matters (internet is only needed during setup)

1. **While the VM still has internet (NAT):** run the **FlareVM base
   installer** (`install.ps1`) — it brings most required free tools
   (x64dbg, FakeNet-NG, Sysinternals, pe-sieve/hollows_hunter, Python).
   Install Ghidra now too, and let pip pull the Python deps.
   > **Recommended:** use the WinRE-patched installer and fixture in
   > [`install/flarevm/`](../install/flarevm/README.md), then run the WinRE
   > verification script. Vanilla FLARE-VM can also be used; apply
   > `flarevm-postfix.ps1` if the required Windows debugging components are
   > missing.
2. **Remove NAT/bridged internet access**: switch the VM to the private
   host-only VMnet2 network used by the lab. Keep the guest's normal gateway,
   DNS, and intended VMnet2 peer access; WinRE does not route through RevAI or
   block the workstation.
3. **Run `install/setup-flarevm.ps1`** on the VM: it *ensures* the complete
   required set exists (verifies every tool, builds the x64dbg MCP plugin
   from the vendored Zig source, wires autostart + gate marker) and fails
   with precise instructions for anything missing.
4. Anything missing while offline: stage it from the host with
   `ops/provision_tools.ps1` (downloads Ghidra/x64dbg/zig/pe-sieve on the
   internet-connected host, scps to `C:\Tools-staged\` on the VM).

### Ghidra SQL (LibGhidraHost + ghidrasql) - SQL-first

Ghidra querying in WinRE is REAL SQL (no stub): the LibGhidraHost extension
(RPC host) + `ghidrasql.exe` (SQLite engine, HTTP :18080). Artifacts are staged
offline in `internal\reapply\sql\` (`LibGhidraHost.zip`, `ghidrasql.exe`)
and installed by `install\setup-flarevm.ps1`; `verify-flarevm.ps1` runs a live
WHERE/ORDER BY gate. IDA side: `idasql.exe` is a FREE release
(github.com/allthingsida/idasql) auto-staged by `ops\provision_tools.ps1`.
Build/repair details: `docs\SQL-GHIDRA.md` + `docs\SQL-IDA.md`.

### Ghidra JDK (required for headless analysis)

Ghidra 12 needs a supported JDK (21). FlareVM 2026 ships OpenJDK 25, which
makes Ghidra's launcher fail and then hang at its batch \pause\ (every
\ghidra_query\ burns the full timeout). \install/setup-flarevm.ps1\ detects
this and pins a supported JDK via \support\\launch.properties(\JAVA_HOME_OVERRIDE=...\), installing \	emurin21\ when chocolatey is
available; \
erify-flarevm.ps1\ reports the pin. Manual fix:

\\powershell
choco install temurin21 -y
# then set in <ghidra>\\support\\launch.properties:
# JAVA_HOME_OVERRIDE=C:\\Program Files\\Eclipse Adoptium\\jdk-21.0.xx-hotspot
\
### Required — free tools (setup FAILS without these)

| Tool | Default location | Source |
|---|---|---|
| **FlareVM base** | — | mandiant/flare-vm `install.ps1` (step 1 above) |
| **Ghidra** 11.x/12.x + CADRE loader | `C:\Tools\ghidra_<version>` | NSA releases (primary static engine; auto-detected by glob) |
| **x64dbg** + MCP plugin | `C:\Tools\x64dbg` | x64dbg releases; plugin built by setup from `integrations/x64dbg-mcp-server` |
| **FakeNet-NG** 3.5 | `C:\Tools\fakenet\fakenet3.5\fakenet.exe` | FlareVM base / mandiant releases |
| **Procmon** (Sysinternals) | `C:\Tools\sysinternals\Procmon64.exe` | FlareVM base |
| **pe-sieve** | `C:\ProgramData\chocolatey\bin\pe-sieve.exe` | FlareVM base / hasherezade releases (also does Scylla-class IAT rebuild for unpack dumps: `/imp 1..5 /dmode 3`) |
| **hollows_hunter** | `C:\Tools\hollows_hunter\hollows_hunter.exe` | FlareVM base / hasherezade releases |
| **Python** 3.13 | `C:\Python313` | **Install (python.org, all users)** - WinRE setup installs the pip deps (`frida`, `flask`, `pefile`, `psutil`, `oletools`, `pypdf`, `dnfile`, `z3`, `angr`, `speakeasy`, `mcp-windbg`, `setuptools<81`) |
| **capa** + mandiant rules | `C:\Tools\capa\capa.exe` + `C:\Tools\capa-rules` | FlareVM base / pip fallback auto-used |
| **Detect It Easy** | `C:\Tools\die\diec.exe` | FlareVM base (or stage via `ops/provision_tools.ps1`) |
| **yara-x** + curated rules | `C:\Tools\yr\yr.exe` + `C:\Tools\yara-rules` | FlareVM base (rules: operator stages curated sets) |
| **scdbg** | `C:\Tools\scdbg\scdbg.exe` | FlareVM base |
| **radare2** | `C:\Tools\radare2\radare2.exe` | FlareVM base (sink_sites / r2_decompile) |
| **goresym** | `C:\Tools\goresym\goresym.exe` | hasherezade releases (Go samples only) |
| **ILSpy CLI** | `%USERPROFILE%\.dotnet\tools\ilspycmd.exe` | `dotnet tool install -g ilspycmd` (.NET samples only) |
| **7-Zip** | `C:\Program Files\7-Zip\7z.exe` | FlareVM base (DFIR-Nexus case packs; zip fallback) |
| **Wireshark/tshark** | `C:\Program Files\Wireshark\tshark.exe` | FlareVM base (beacon/pcap post-analysis) |

### Optional — commercial (setup detects; pipeline skips gracefully)

| Tool | Default location | Env override | Degradation when absent |
|---|---|---|---|
| **Malcat** (portable; + license) | `C:\Tools\malcat\bin` - **keep the folder name `malcat`**; expects `bin\malcat.exe` + `bin\malcat.mcp.py` (also probed: `C:\Program Files\Malcat\bin`, `%USERPROFILE%\Downloads\malcat\bin`) | `MALCAT_BIN_DIR` (license: `MALCAT_LICENSE`, default `%APPDATA%\Malcat\license.dat`)
| **IDA Professional** 9.x + `idasql` | `C:\Program Files\IDA Professional 9.3` (also probed: IDA Free 9.3/8.3, `C:\Tools\IDA*`) — **install-at-preference is fully supported** | `WINRE_IDA_DIR` (dir containing `idat.exe`); `IDASQL`/`WINRE_IDASQL` (full path to `idasql.exe`) | `ida_query` agent tool skips (honest skip + hint); Ghidra SQL is the canonical source. **Note: IDA Free licenses are detected and skipped with a clear message — headless `.i64`/idalib requires IDA Professional** |

> **Tool-location contract:** every expected path, its detection order, and
> the exact degradation is documented in [`TOOL-PATHS.md`](TOOL-PATHS.md).
> `install/setup-flarevm.ps1 -CheckMode` reports each tool as found/missing
> with the precise fix; `ops/smoke_flare.py` and `install/verify-flarevm.ps1`
> re-verify the resolved set at run time.

## Safety requirements

- Keep Flare on the private VMnet2 network and do not add a NAT or bridged
  adapter. WinRE preserves the guest's existing default route and DNS; its
  setup does not point Flare at RevAI `.43` or block other VMnet2 peers. SSH
  and x64dbg access are allowed from the VMnet2 `LocalSubnet`, so the operator
  workstation and RevAI can connect directly when attached to that network.
- Standalone and remote-driver WinRE runs both keep guest-side FakeNet-NG.
  Remote-driver dynamic runs require a run-scoped `tcpdump` capture on the
  control plane's VMnet2 interface and fail before guest launch if capture is
  not configured or cannot start. `tcpdump` requests promiscuous mode by default.
  VMware Workstation host-only
  networks are private LANs, but visibility of unicast frames depends on what
  the virtual network delivers to that interface; verify it with the benign
  packet test in [Dynamic Orchestrator](DYNAMIC-ORCHESTRATOR.md). A valid pcap
  proves the capture file was collected, not that every possible frame was
  mirrored or that a protocol parser understood it.
- After setup or a snapshot restore, verify Flare's existing route/DNS, direct
  SSH from the workstation and `.43`, and passive packet visibility before a
  sample run. The passive capture adds no guest route, DNS, firewall-peer, or
  gateway dependency; capture is restricted to `host 192.168.77.42`.
- **Snapshot discipline**: after setup creates `C:\WinRE\.clean_snapshot`,
  take/update the VM snapshot. After restoring it, verify the guest and attest
  the clean state from the separate control plane with
  `python -m winre.snapshot_gate attest --action verified_clean`. The guest
  marker alone is not sufficient for the snapshot gate.
- Samples live under `C:\samples\` on the VM and are **never executed on
  the control plane**.
