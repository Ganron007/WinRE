# WinRE Docs

> **Scope:** index of the published documentation. **Audience:** operators, integrators and agent authors.

**Reading order for a new deployment:** [PREREQUISITES.md](PREREQUISITES.md) →
[INSTALL.md](INSTALL.md) → [OPERATE.md](OPERATE.md). Then the per-feature docs
below as needed.

| Doc | What it covers |
|---|---|
| [PREREQUISITES.md](PREREQUISITES.md) | What must exist before `setup-flarevm.ps1` runs (control plane + FlareVM) |
| [INSTALL.md](INSTALL.md) | Install the control plane and bootstrap the FlareVM (staged tools, wires, MCP) |
| [OPERATE.md](OPERATE.md) | Day-2 operation: runs, snapshot gate, packs, troubleshooting |
| [PIPELINE.md](PIPELINE.md) | Engine, capability, driver, snapshot-gate, and CLI contracts |
| [EVIDENCE.md](EVIDENCE.md) | Four evidence sections, manifests, provenance, and `truly_green` |
| [TOOL-PATHS.md](TOOL-PATHS.md) | Tool-location contract and per-tool env overrides |
| [SSH-CONTRACT.md](SSH-CONTRACT.md) | SSH/MCP transport contract for remote callers |
| [REVAI-BRIDGE.md](REVAI-BRIDGE.md) | Wiring the remote driver to a RevAI (or other control-plane) box |
| [SQL-GHIDRA.md](SQL-GHIDRA.md) | SQL-first Ghidra: `LibGhidraHost` + `ghidrasql` build/run + schema |
| [SQL-IDA.md](SQL-IDA.md) | SQL-first IDA: `idasql` install/run + schema |
| [DYNAMIC-ORCHESTRATOR.md](DYNAMIC-ORCHESTRATOR.md) | Pipeline-driven detonation and standalone collection interface |
| [X64DBG-MCP.md](X64DBG-MCP.md) | x64dbg MCP plugin: build, deploy, exposure, debug loops |
| [WINDBG-MCP.md](WINDBG-MCP.md) | `mcp-windbg`: passive dump/memory-image analysis |

> **Not published here:** operator-local internals (lab addressing, hostnames,
> keys, machine inventories) are intentionally kept out of this directory and
> the repository. Configuration placeholders (for example `FLARE_*`,
> `WINRE_LLM_*`) are documented in [INSTALL.md](INSTALL.md) and
> [OPERATE.md](OPERATE.md).
