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

WinRE supports two network collection modes. Standalone Flare runs use the
existing guest-side FakeNet-NG configuration and return its logs and PCAPs.
When the remote driver runs on the configured REMnux control plane, it uses the
off-box gateway mode: Flare's default route and DNS point to REMnux, FakeNet is
disabled for that run, and the driver starts a run-scoped `dumpcap` capture on
the private interface. The pcap is returned under
`dynamic/off_box/network_raw/` and is covered by the artifact manifest.

The paired setup scripts make the intended lab topology persistent:
`RevAI/install/setup-remnux.sh` installs the REMnux gateway policy whenever
WinRE is present; `WinRE/install/setup-flarevm.ps1` sets Flare's gateway/DNS,
allows routed outbound packets so literal-IP traffic reaches the gateway,
blocks every other on-link VMnet2 peer (including the workstation host), and
limits SSH and x64dbg control to REMnux `.43`. Host-side sync and reapply use
`.43` as an SSH jump host; Flare has no direct host-management exception.
REMnux is the egress boundary: it captures guest packets,
redirects supported protocols to simulators, and drops every forwarded packet.
`ops/reapply_after_revert.ps1` passes the same settings on each post-snapshot
sync; the analysis gateway and additional blocked peers can be overridden with
`WINRE_ANALYSIS_GATEWAY` and `WINRE_BLOCKED_PEERS`. The SSH jump host, user, and
key are configured with `WINRE_GATEWAY_HOST`, `WINRE_GATEWAY_USER`, and
`WINRE_GATEWAY_SSH_KEY` in the operator-host `.env`.
Direct guest setup accepts `AnalysisGatewayAddress`, `BlockedPeerAddresses`,
and `AnalysisInterfaceAlias`. The REMnux setup defaults can be changed with
`WINRE_GATEWAY_IP`, `WINRE_GUEST_IP`, and `WINRE_ANALYSIS_INTERFACE`.

REMnux binds a no-upstream dnsmasq instance and INetSim to the guest-facing
interface. Its nftables policy redirects DNS to dnsmasq and common simulated
service ports to INetSim, captures guest packets, and drops all forwarded
traffic. The `.43` NAT interface is therefore not a route for Flare. DNS
responses are served by no-upstream dnsmasq, and common HTTP(S), mail, FTP,
IRC, TFTP, and NTP traffic is redirected to INetSim where the installed service
supports it. Other routed traffic remains visible at the capture interface and
is dropped by REMnux; Flare receives no Internet access. This does not decrypt
TLS.

Gateway mode is enabled only when the control plane has a valid
`/etc/revai/winre-gateway.json` from the RevAI setup script. It fails closed
before launching the sample if `dumpcap` cannot start. The off-box capture is a
required source for that mode; reports identify the interface and pcap hash.
Before the first sample run, verify the route, simulator listeners, forwarding
state, and a benign DNS/HTTP packet exchange from Flare. The following smoke
test uses only reserved test names and addresses; it does not execute a sample.

On REMnux, capture both the private VMnet2 interface and the NAT-facing
interface in separate terminals:

```bash
sudo timeout 30 tcpdump -nni ens32 'host 192.168.77.42 and (port 53 or host 198.51.100.17)' -w /tmp/winre-vmnet2.pcap
sudo timeout 30 tcpdump -nni ens33 'host 198.51.100.17 or host 192.168.77.42' -w /tmp/winre-nat.pcap
```

While both captures are running, use Flare's PowerShell prompt:

```powershell
Resolve-DnsName "preflight-$([guid]::NewGuid().ToString('N')).invalid" `
  -Server 192.168.77.43 -Type A -DnsOnly
curl.exe --noproxy "*" --max-time 10 -sS -o NUL -w "HTTP=%{http_code}`n" `
  http://198.51.100.17/
```

The DNS answer should be `192.168.77.43`, HTTP should return `200`, the VMnet2
capture should contain the guest DNS and HTTP exchange, and the NAT capture
should contain zero matching packets. Confirm `sysctl -n net.ipv4.ip_forward`
returns `0` on REMnux. After setup/revert, run
`ops/reapply_after_revert.ps1`; it resyncs local code and reapplies the guest
policy. Continue to restore and verify the clean snapshot between sample runs.

## Related documentation

- [Operate](OPERATE.md): snapshot gate, recovery, UI, and troubleshooting.
- [SSH Contract](SSH-CONTRACT.md): transport behavior and remote tool calls.
- [Pipeline](PIPELINE.md): normal audited execution path.
