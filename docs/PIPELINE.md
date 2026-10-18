# Pipeline

> **Scope:** execution modes, stage order, driver boundaries, and CLI behavior.
> **Audience:** operators and integrators. WinRE is pre-v1.0; pin a revision
> when relying on these interfaces.

WinRE uses deterministic tools to produce evidence. The agentic engine can
interpret that evidence through an OpenAI-compatible LLM. It does not ask the
LLM to execute samples or replace deterministic collection.

## Engines and evidence sections

The analysis engine and the requested execution capability are separate
choices. The pack section names the producer so that one run does not silently
overwrite evidence produced by another capability.

| CLI selection | Deep-analysis engine | Additional execution | Pack section |
|---|---|---|---|
| `--mode static` | Fixed deterministic checklist; zero LLM calls | None | `static/` |
| `--mode agentic` | LangGraph tool loop and configured judgment role | None | `agentic/` |
| `--mode agentic --agentic-dbg` | Agentic | Entry-point or packed-file OEP probe; bounded x64dbg execution with ETW observation and scoped process cleanup | `dbg/` |
| `--mode agentic --dynamic` | Agentic | Gated detonation after the static stages | `dynamic/` |

The engine defaults to `agentic`; detonation and debugger execution are
opt-in. The deterministic `static` engine cannot be combined with either
execution capabilities. Dynamic and debugger work are separate producers and
cannot be combined in one pipeline invocation. Under the default `enforce`
snapshot gate, one verified restore permits one gated sample execution, so
restore and attest between them.

## Stage order

The normal evidence sequence is intake, quick triage, deep analysis, YARA,
reporting, and audit. When requested, dynamic collection runs after static
analysis and is recorded in its own `dynamic/` section. The execution plan is
written before stages begin; finalization writes the selected findings,
correlation/composition records, reports, audit, and artifact inventory for
that run.

The evidence root is `logs/<sha256>/<section>/`. The four section names are
`static`, `agentic`, `dbg`, and `dynamic`. Each section includes stage
directories and run metadata. See [Evidence Packs](EVIDENCE.md) for the
artifact and manifest layout.

Agentic deep analysis runs `decrypt_gate`, `pe_parse`, and `capa` as
deterministic preflights before the LLM planner starts. Their structured
results are kept in the deep-stage history and opening context, so the planner
cannot omit required operations. A failed or unavailable preflight remains
visible to the capability census and can keep the quality audit red.

The report and pack-level `META.json` expose two verdict fields: `verdict` is
the selected composite across current, identity-validated mode findings;
`mode_verdict` is the current section's result. The CLI summary prints both.
Definite detonation evidence has the highest weight, debugger evidence follows,
and static-only findings provide context. Disagreements are named in
`composite.json`; two static modes with definite but different results use the
more conservative label until execution evidence is available. An unknown
dynamic or debugger result does not erase a definite static result.

Dynamic collection uses Frida, Procmon, and optional memory and debugger
tooling. Standalone and remote-driver Flare runs use guest-side FakeNet-NG;
remote-driver runs also collect a run-scoped `tcpdump` pcap on the REMnux VMnet2
interface, filtered to the Flare guest IP.
The default detonation cap is 150 seconds. `--stop-on`
controls the behavior gate and `--stop-on-settle` controls how long collection
continues after it fires. `--adaptive` enables an idle-based stop; because a
sleeping sample can appear idle, it is off by default. Requested and effective
windows and the stop reason are recorded in the run evidence.

## Driver and trust boundary

Use the remote driver to run the pipeline from the separate control plane:

```powershell
python -m winre.pipeline "C:\samples\sample.exe" --driver remote --mode static
python -m winre.pipeline "C:\samples\sample.exe" --driver remote --mode agentic
```

The control plane holds the LLM configuration and trusted analysis outputs;
the FlareVM provides Windows tooling and sample execution. Every pipeline mode
that invokes guest tools requires both the guest clean-state marker and an
independent clean attestation in the control-plane ledger. A guest-local
process cannot provide that independent attestation. `--driver local` does
not permit dynamic or debugger execution; on the FlareVM it cannot pass the
independent-ledger trust boundary.

The pipeline never restores a VM snapshot. After restoring the approved
snapshot, verify the guest state and attest from the control plane:

```powershell
python -m winre.snapshot_gate attest --action verified_clean
```

The command records the attestation; it does not inspect or restore the
hypervisor snapshot for you. Follow [Operate](OPERATE.md) for the full gate and
recovery procedure.

## Common runs

Run the deterministic engine without LLM calls:

```powershell
python -m winre.pipeline "C:\samples\sample.exe" --driver remote --mode static
```

Run the agentic engine:

```powershell
python -m winre.pipeline "C:\samples\sample.exe" --driver remote --mode agentic
```

Run a detonation as a separate, gated pass. This uses the agentic engine and
writes to the `dynamic/` section:

```powershell
python -m winre.pipeline "C:\samples\sample.exe" --driver remote --mode agentic --dynamic --max-seconds 150
```

Run debugger-assisted analysis from its own verified restore and an active
interactive FlareVM desktop session (the x64dbg mode needs the logged-in GUI).
WinRE creates a hash-checked, run-local copy for x64dbg so a self-deleting
sample cannot erase the staged source used by later analysis tools. For ordinary
native files, x64dbg pauses at the entry point; a positive packer signal routes
to the memory-execute OEP/unpack probe. WinRE continues the target for up to 30
seconds, closes the debugger, then uses the independent ETW trace to identify
any target or descendant processes still active. Cleanup checks each process
ID, image name, and creation time before terminating it. The pass is
execution-consuming. ETW observes process lifecycles only; it does not cover
file, registry, network, or memory activity. Debugger availability, process
observation, and successful unpacking describe coverage; they do not by
themselves establish malicious intent:

```powershell
python -m winre.pipeline "C:\samples\sample.exe" --driver remote --mode agentic --agentic-dbg
```

A completed debugger window remains a valid debugger finding when no unpacked
dump is produced, provided ETW observed the target and confirmed cleanup. The
report records the missing dump as a limitation and keeps the execution
observation separate. Missing target observation, incomplete ETW collection,
or unconfirmed process cleanup keeps the debugger mode out of the composite
and the quality audit red.

Do not combine `--dynamic` and `--agentic-dbg` in one pipeline invocation;
they have separate pack roots and execution paths. Each execution-consuming
pass requires a fresh verified restore and attestation. To inspect the
execution budget without running a sample:

```powershell
python -m winre.snapshot_gate plan --dynamic --agentic-dbg
```

`--dry-llm` disables LLM calls. An agentic run then records
`deterministic_fallback`; the audit treats a required fallback as a quality
failure. `--publish` writes a sanitized report-level copy to
`docs/case-studies/<section>/<sha256>/` and does not include sample binaries.

## Audit meaning

`audit.json → truly_green` is a run-quality gate. It checks required stages,
the requested dynamic/debug capability, required tool outcomes, fallback
status, expected verdict/composition records, and snapshot-gate evidence. A
green audit means the requested workflow produced acceptable evidence under
its declared contract. It does not establish that the sample is benign, that
all behavior was observed, or that the analysis is complete.

Dynamic evidence can corroborate static analysis. The `static_yara_wins`
policy prevents dynamic output from clearing a high-signal static YARA result;
unresolved conflicts and coverage gaps remain visible in the audit and pack.

## Standalone dynamic orchestrator

`winre.orchestrator` is a lower-level collection entry point with `ssh` and
`local` modes. Pipeline-driven runs are preferred because they bind the
collection to a run ID, evidence section, capability plan, and final audit.
See [Dynamic Orchestrator](DYNAMIC-ORCHESTRATOR.md) and
[SSH Contract](SSH-CONTRACT.md) before using the standalone command.

## Related documentation

- [Operate](OPERATE.md): restore cadence, ledger, UI, troubleshooting.
- [Evidence Packs](EVIDENCE.md): file layout, provenance, and manifest status.
- [Install](INSTALL.md): host, guest, and LLM setup.
- [RevAI Bridge](REVAI-BRIDGE.md): remote-driver configuration and handoff.
