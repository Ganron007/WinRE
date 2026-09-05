# Prerequisites

Everything needed before `install/setup-flarevm.ps1` can bootstrap a WinRE
FlareVM. Read together with [`INSTALL.md`](INSTALL.md).

## Lab topology

WinRE uses a two-plane split: an **operator host** (internet, LLM, UI,
reporting) drives an **isolated FlareVM** (sample execution, no internet)
over SSH. The VM reaches nothing outside the lab; network traffic is sunk
by FakeNet-NG during detonation.

```
+--------------------------+         SSH / HTTP          +---------------------------+
|  control plane (host)    |  -------------------------> |  FlareVM (Windows 10/11)  |
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

- **Windows 10/11** with OpenSSH client (`ssh`, `scp`) and Python **3.10+**
  (3.13 tested)
- Python packages: `langchain-openai`, `langgraph`, `langchain-core`,
  `pydantic` (see `.env.template` for LLM config)
- An **OpenAI-compatible LLM endpoint** (model, base URL, API key) for the
  deep-dive agent. Optional — without it the pipeline runs deterministic
  fallbacks and stays honest about it (`deterministic_fallback`)
- The FlareVM SSH private key on disk (path configured via `FLARE_SSH_KEY`)
- The repo itself (git clone)

## FlareVM (execution VM)

Start from a **Windows 10/11 VM on an isolated/host-only network**.

### Install order matters (the VM is air-gapped in operation)

1. **While the VM still has internet (NAT):** run the **FlareVM base
   installer** (`install.ps1`) — it brings most required free tools
   (x64dbg, FakeNet-NG, Sysinternals, pe-sieve/hollows_hunter, Python).
   Install Ghidra now too, and let pip pull the Python deps.
2. **Air-gap**: switch the VM to host-only networking.
3. **Run `install/setup-flarevm.ps1`** on the VM: it *ensures* the complete
   required set exists (verifies every tool, builds the x64dbg MCP plugin
   from the vendored Zig source, wires autostart + gate marker) and fails
   with precise instructions for anything missing.
4. Anything missing while offline: stage it from the host with
   `ops/provision_tools.ps1` (downloads Ghidra/x64dbg/zig/pe-sieve on the
   internet-connected host, scps to `C:\Tools-staged\` on the VM).

### Required — free tools (setup FAILS without these)

| Tool | Default location | Source |
|---|---|---|
| **FlareVM base** | — | mandiant/flare-vm `install.ps1` (step 1 above) |
| **Ghidra** 11.x/12.x + CADRE loader | `C:\Tools\ghidra_<version>` | NSA releases (primary static engine) |
| **x64dbg** + MCP plugin | `C:\Tools\x64dbg` | x64dbg releases; plugin built by setup from `integrations/x64dbg-mcp-server` |
| **FakeNet-NG** 3.5 | `C:\Tools\fakenet\fakenet3.5\fakenet.exe` | FlareVM base / mandiant releases |
| **Procmon** (Sysinternals) | `C:\Tools\sysinternals\Procmon64.exe` | FlareVM base |
| **pe-sieve** | `C:\ProgramData\chocolatey\bin\pe-sieve.exe` | FlareVM base / hasherezade releases |
| **hollows_hunter** | `C:\Tools\hollows_hunter\hollows_hunter.exe` | FlareVM base / hasherezade releases |
| **Python** 3.13 + `frida`, `flask` | `C:\Python313` | FlareVM base; deps also auto-installed by setup |

### Optional — commercial (setup detects; pipeline skips gracefully)

| Tool | Default location | Degradation when absent |
|---|---|---|
| **Malcat** (+ license) | `C:\Tools\malcat\bin` | quick-triage strings/anomalies and Malcat agent tools are skipped (honest `skipped` annotations); Ghidra + x64dbg carry the analysis |
| **IDA Professional** 9.x + `idasql` | `C:\Program Files\IDA Professional 9.3` | `ida_query` agent tool disabled; Ghidra SQL is the canonical source |

## Safety requirements

- The FlareVM must be **isolated** (host-only or firewalled NAT). Detonation
  traffic is sunk by FakeNet; nothing should reach real infrastructure.
- **Snapshot discipline**: after setup creates `C:\WinRE\.clean_snapshot`,
  take/update the VM snapshot. Restores re-create the marker, which is what
  the snapshot gate consumes before any execution.
- Samples live under `C:\samples\` on the VM and are **never executed on
  the control plane**.
