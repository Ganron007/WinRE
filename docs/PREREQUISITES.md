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

### Automated by setup (free tooling)

- Python 3.13 installed **for all users** at `C:\Python313`
- `pip` packages: `frida`, `flask`
- MCP autostart launcher + scheduled task (installed by the script)
- Clean-snapshot marker (you take the snapshot afterwards)

### Commercial — install manually (setup detects and instructs)

| Tool | Default location | Notes |
|---|---|---|
| **FlareVM** base | — | run the official FlareVM `install.ps1` on a fresh VM first |
| **Ghidra** 12.x | `C:\Tools\ghidra_<version>` | plus the CADRE PE loader extension in `Ghidra\Extensions\` |
| **Malcat** | `C:\Tools\malcat\bin` (or Program Files) | commercial; headless MCP needs `bin\malcat.mcp.py` + a **license file** |
| **IDA Professional** 9.x | `C:\Program Files\IDA Professional 9.3` | optional (deep degrades to Ghidra+Malcat); needs `idasql.exe` alongside |
| **x64dbg** | `C:\Tools\x64dbg` | MCP plugin built from `integrations/x64dbg-mcp-server` (Zig 0.14.x) |

### Dynamic-analysis tooling

| Tool | Default location |
|---|---|
| FakeNet-NG 3.5 | `C:\Tools\fakenet\fakenet3.5\fakenet.exe` |
| Procmon (Sysinternals) | `C:\Tools\sysinternals\Procmon64.exe` |
| pe-sieve | `C:\ProgramData\chocolatey\bin\pe-sieve.exe` (`choco install pe-sieve`) |
| hollows_hunter | `C:\Tools\hollows_hunter\hollows_hunter.exe` |

## Safety requirements

- The FlareVM must be **isolated** (host-only or firewalled NAT). Detonation
  traffic is sunk by FakeNet; nothing should reach real infrastructure.
- **Snapshot discipline**: after setup creates `C:\WinRE\.clean_snapshot`,
  take/update the VM snapshot. Restores re-create the marker, which is what
  the snapshot gate consumes before any execution.
- Samples live under `C:\samples\` on the VM and are **never executed on
  the control plane**.
