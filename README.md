# WinRE

<p align="center">
  <img src="assets/winre-logo.svg" alt="WinRE logo" width="620">
</p>

> **Project status:** pre-v1.0. WinRE is under active development; command-line,
> evidence, and configuration contracts may change between revisions. Pin a
> commit when integrating it into another system.

WinRE is a Windows malware-analysis pipeline built around FlareVM. It combines
deterministic static analysis, optional LLM-assisted investigation, controlled
dynamic analysis, and debugger-assisted inspection. The LLM interprets
tool-produced evidence; it does not execute samples.

WinRE can run with a separate **control plane** and **Windows analysis guest**.
The control plane hosts the driver, UI, reports, evidence packs, and optional
LLM connection. The FlareVM guest hosts Windows tooling and sample execution.
The remote driver communicates with the guest over SSH and MCP and brings the
resulting evidence back to the control plane for analysis. Keep the guest on an
isolated lab network.

## Analysis modes

The pipeline defaults to the agentic deep-analysis engine, but it does not run
dynamic analysis unless explicitly requested. Engine choice and execution
capabilities determine the evidence-pack section:

| Command | Analysis | Evidence section |
|---|---|---|
| `--mode static` | Deterministic checklist; no agentic analysis call; report claims use the configured evidence reviewer | `logs/<sha256>/static/` |
| `--mode agentic` | LangGraph investigation with an OpenAI-compatible LLM | `logs/<sha256>/agentic/` |
| `--mode agentic --agentic-dbg` | Agentic investigation with an x64dbg OEP/unpack probe, bounded 30-second target run, and ETW process observation | `logs/<sha256>/dbg/` |
| `--mode agentic --dynamic` | Agentic static analysis followed by a separately gated detonation | `logs/<sha256>/dynamic/` |

`--mode static` cannot be combined with `--agentic-dbg` or `--dynamic`. Debug
and detonation are separate producers and cannot be combined in one pipeline
invocation. Run them after separate clean snapshot restores; the default gate
allows one gated execution per verified restore.

## Quick start

Read the deployment and safety requirements before connecting a FlareVM:

1. [Prerequisites](docs/PREREQUISITES.md)
2. [Install](docs/INSTALL.md)
3. [Operate the pipeline](docs/OPERATE.md)

From the control-plane checkout, install the Python dependencies listed in
`docs/INSTALL.md`, copy `.env.template` to `.env`, and configure the FlareVM
SSH connection. An LLM endpoint is needed for agentic analysis and for the
claim-level report review required by a green audit. The static checklist itself
does not make agentic analysis calls. `--dry-llm` disables all LLM calls and
leaves the claim review not requested, so the run is intentionally not green.

```powershell
python -m winre.pipeline "C:\samples\sample.exe" --driver remote --mode static
```

The remote driver requires a verified clean-state marker in the guest and a
clean attestation in the independent control-plane ledger. After restoring the
FlareVM snapshot, verify the guest and attest from the control plane:

```powershell
python -m winre.snapshot_gate attest --action verified_clean
```

WinRE does not restore hypervisor snapshots. Follow the full restore and
attestation procedure in [Operate](docs/OPERATE.md) before any pipeline run.

## Evidence and trust

Each sample is keyed by SHA-256. Separate sections preserve the deterministic,
agentic, debugger, and dynamic run outputs. Stage manifests record artifact
hashes and collection status; the pack manifest summarizes the delivered
evidence. See [Evidence Packs](docs/EVIDENCE.md) for the schema and audit
contract.

The `truly_green` audit result describes whether requested stages completed
with usable evidence and without required-tool failures or fallbacks. It is an
operational quality signal, not a malware verdict and not proof that a sample
is benign or fully understood. Dynamic observations have explicit scope and
coverage limits; they do not clear a high-signal static YARA result.

## Safety

- Run samples only in a properly isolated analysis VM. FakeNet-NG is a network
  sink, but it does not replace hypervisor isolation and firewall controls.
- Restore the approved clean snapshot after every dynamic or debugger execution
  and attest the restored state from the separate control plane.
- Treat guest-produced files and tool output as untrusted evidence.
- Keep API keys in the control-plane environment. Do not commit `.env` files,
  secrets, or malware samples.
- MCP and SQL services are intended for the isolated lab network. Do not expose
  their ports to untrusted networks.

## Platform and tooling

Windows 10 with FlareVM is the documented execution target. Windows 11 is not
currently established as a supported detonation platform. The standard stack
uses Ghidra, x64dbg, FakeNet-NG, Procmon, Frida, and supporting analysis tools.
IDA Professional and Malcat are optional commercial integrations and are
reported as unavailable when not installed or licensed.

The control plane may run on Windows or Linux and needs Python, OpenSSH client
tools, and network access to the configured LLM provider when agentic analysis
is used. See [Prerequisites](docs/PREREQUISITES.md) and
[Tool Paths](docs/TOOL-PATHS.md) for version and path details.

## Documentation

The [documentation index](docs/README.md) links installation, operation,
pipeline, evidence, transport, and tool-specific guides. The most relevant
references are [Pipeline](docs/PIPELINE.md),
[Dynamic Orchestrator](docs/DYNAMIC-ORCHESTRATOR.md), and
[RevAI Bridge](docs/REVAI-BRIDGE.md).

## Offline checks

The repository includes contract tests that use fixtures and mocked tool or
transport boundaries. Run them from the repository root:

```powershell
python -m pytest tests -q
```

These checks do not replace deployment verification or controlled runtime
validation on a restored lab VM.

## License

WinRE is licensed under MIT; see [LICENSE](LICENSE). Third-party tools and
integrations retain their own licenses and installation requirements.

## Acknowledgements

- [idasql](https://github.com/allthingsida/idasql), SQL interface for IDA.
- [ghidrasql and LibGhidraHost](https://github.com/0xeb/ghidrasql), SQL
  interface for Ghidra.
- [x64dbg-MCP-Server](https://github.com/duty1g/x64dbg-mcp-server), debugger
  MCP integration.
- [mcp-windbg](https://github.com/svnscha/mcp-windbg), WinDbg MCP integration.
