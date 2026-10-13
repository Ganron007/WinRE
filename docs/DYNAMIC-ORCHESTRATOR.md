# Dynamic Orchestrator

> **Scope:** dynamic collection on the FlareVM and the standalone orchestrator
> interface. **Audience:** operators and integrators.

The pipeline is the preferred entry point for dynamic analysis. It binds the
detonation request to a sample hash, run ID, execution plan, evidence section,
and final audit. Dynamic analysis is opt-in and requires the separate remote
driver so that post-run interpretation stays on the control plane.

```powershell
python -m winre.pipeline "C:\samples\sample.exe" `
  --driver remote --mode agentic --dynamic --max-seconds 150
```

The dynamic pass runs after static analysis and writes to
`logs/<sha256>/dynamic/dynamic/`. The outer `dynamic/` is the pack section; the
inner `dynamic/` contains the collection-stage evidence. See
[Pipeline](PIPELINE.md) for run separation and
[Evidence Packs](EVIDENCE.md) for the full layout.

## Collection flow

The orchestrator stages the requested sample and job configuration on the
guest, runs the PowerShell collection job, and returns the results to the
control plane. Collection may include FakeNet-NG, Procmon, Frida, and optional
memory or debugger tooling. Deterministic host-side helpers summarize and
validate returned artifacts. A collector that fails or produces incomplete
output is recorded as such; an empty output is not proof that no behavior
occurred.

The run records the requested and effective collection window, stop reason,
run ID, sample identity, and source coverage. The default maximum window is
150 seconds. `--stop-on` defaults to `network,file`; `--stop-on-settle` keeps
collection active after the gate fires. `--adaptive` enables the additional
idle-based stop and should be used with care because delayed behavior can look
idle.

## Standalone interface

The lower-level `winre.orchestrator` entry point supports `ssh` and `local`
collection modes. The standalone path is useful for orchestrator development
and recovery; use the pipeline for normal analysis and audited runs.

```powershell
# From the control plane; inspect the plan without starting collection.
python -m winre.orchestrator "C:\samples\sample.exe" --mode ssh --dry-run

# Standalone remote collection (requires Flare SSH configuration).
python -m winre.orchestrator "C:\samples\sample.exe" `
  --mode ssh --max-seconds 150 --pesieve
```

The standalone CLI accepts a SHA-256 with `--sample <path>` when the source
file is not supplied positionally. Its default mode is `ssh` unless
`WINRE_ORCHESTRATOR_MODE` overrides it. Other options include `--apis`,
`--dll-entry`, `--adaptive`, `--idle-stop-seconds`, `--stop-on`,
`--stop-on-settle`, `--no-deploy`, `--force`, and `--run-id`. Check
`python -m winre.orchestrator --help` for the exact interface at your pinned
revision.

`--mode local` runs collection on the Windows guest. The guest is not a
trusted analysis plane after sample execution; retrieve the output and perform
interpretation on the control plane. A guest-local process cannot attest its
own clean state in the independent control-plane ledger.

## Outputs and safety

The collection job produces source artifacts such as Frida traces, Procmon
logs, network captures, process snapshots, and memory dumps when those sources
are requested and available. The pipeline places returned files under the
run's pack section and writes stage and pack manifests. Manifests distinguish
complete, partial, failed, unavailable, not-applicable, and not-requested
sources. See [Evidence Packs](EVIDENCE.md) for details.

WinRE does not restore hypervisor snapshots. After a detonation, restore the
approved clean snapshot, verify the guest marker, and attest the clean state
from the separate control plane before another run. Keep the VM on an isolated
lab network; FakeNet-NG does not replace hypervisor isolation or firewall
controls.

The standard Windows job starts FakeNet-NG in the guest. Its configuration
temporarily points DNS at the guest-side sink and writes guest-side PCAPs,
which the remote driver returns with the run pack. The job does not start an
external DNS or capture service on the control plane. Pointing the guest's DNS
at the control plane alone will not capture all network flows; an external
capture path needs a simulator bound to the private analysis interface, a
verified route through that interface, and a benign packet-visibility check.
Keep the execution guest on its private analysis network after provisioning.
The remote control plane may have LLM or Internet access, but that does not
make it a gateway for the guest. Changing only the guest DNS address changes
where lookups go; it does not route subsequent TCP or UDP traffic through the
control plane. Keep FakeNet-NG guest-side unless an explicit, tested gateway
or mirrored-capture design is deployed.

## Related documentation

- [Operate](OPERATE.md): snapshot gate, recovery, UI, and troubleshooting.
- [SSH Contract](SSH-CONTRACT.md): transport behavior and remote tool calls.
- [Pipeline](PIPELINE.md): normal audited execution path.
