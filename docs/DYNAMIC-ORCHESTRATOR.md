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

Standalone and remote-driver dynamic runs use the same guest networking path:
FakeNet-NG stays active on Flare and the guest keeps its existing default route,
DNS, and VMnet2 peer access. The setup scripts never point Flare at `.43`, add a
NAT/bridged adapter, block VMnet2 peers, or route workstation SSH through RevAI.
The workstation and `.43` connect directly to `.42` over VMnet2.

When RevAI's remote driver runs a dynamic job, it starts a run-scoped `tcpdump`
capture on the REMnux VMnet2 interface before the guest helper launches. The
capture filter is exactly `host 192.168.77.42`; tcpdump's default promiscuous
request is enabled by omitting `-p`. It stops after the remote helper completes,
validates the classic pcap header and SHA-256, and places the pcap and capture
record under `dynamic/off_box/`. RevAI setup requires `tcpdump` capabilities and
writes `/etc/revai/winre-capture.json`; the remote dynamic path fails before
launch if this configuration or capture startup is missing. Static analysis
does not start a packet capture. The guest's FakeNet logs and the off-box pcap
remain separate evidence sources and are both reported.

Promiscuous mode asks Linux to accept frames that reach the REMnux VMnet2
interface. VMware Workstation's host-only description guarantees a private LAN
shared by the host and attached VMs, but does not promise that every unicast
frame between other VM ports is mirrored to `.43`. Verify visibility on the
actual host and Workstation build before relying on this sensor for complete
network evidence. A valid pcap with zero packets is reported as collected with
`packets_captured: 0`; it is not evidence that the sample made no network
connections.

Before the first sample run, test direct SSH from the workstation and `.43` to
Flare, then verify that `.43` sees traffic from `.42` that is addressed to a
different VMnet2 endpoint. On REMnUX, replace `<vmnet2-interface>` with the
interface owning `.43` and start:

```bash
sudo tcpdump -U -n -i <vmnet2-interface> -w /tmp/winre-vmnet2-smoke.pcap 'host 192.168.77.42'
```

While the capture runs, send a benign ping from Flare to the host-only VMware
adapter address (commonly `192.168.77.1`, but use the actual configured address):

```powershell
ping.exe -n 3 192.168.77.1
```

Stop tcpdump with Ctrl+C and inspect the capture with
`tcpdump -nn -r /tmp/winre-vmnet2-smoke.pcap`. It should show the `.42` packets
even though they were not addressed to `.43`. If it does not, the host-only
network is not delivering those frames to the RevAI interface; promiscuous mode
alone cannot fix that. Use host-side VMnet capture or a VMware-supported mirror
path and record the resulting capture source accurately. After snapshot restore,
run `ops/reapply_after_revert.ps1` to sync the current guest code and verify the
network policy before the next run.

## Related documentation

- [Operate](OPERATE.md): snapshot gate, recovery, UI, and troubleshooting.
- [SSH Contract](SSH-CONTRACT.md): transport behavior and remote tool calls.
- [Pipeline](PIPELINE.md): normal audited execution path.
