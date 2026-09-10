# Evidence Packs & Reporting — where everything lives

WinRE writes one **evidence pack per sample per engine**, keyed by SHA256 +
deep-dive mode (RevAI-style sections — RevAI `scripted`/`agentic` folders).
Both the CLI and the console read from this layout; the RevAI remote driver
reads the same packs for corroboration.

```
logs/<sha256>/<static|agentic>/         ← one self-contained case per engine
├── META.json                        pack-level mode/engine/source/truly_green
├── intake/
│   ├── intake.json                   file facts: path, size, magic, format
│   └── META.json                     stage wrapper (ok/error/timing)
├── quick/                            deterministic triage
│   ├── quick.json                    verdict + full evidence dict
│   ├── 01-tools-raw.json             FULL untruncated tool outputs (citation target)
│   └── META.json
├── deep/                             deep dive — engine depends on the section
│   ├── deep.json                     verdict + full history (+ llm_analysis in agentic)
│   ├── 01-tools-raw.json             FULL tool-call results (untruncated)
│   └── META.json                     engine (langgraph|static_deterministic),
│                                     mode, fallback flag, MCP health
├── dynamic/                          (opt-in, segregated, runs LAST)
│   ├── META.json / STAGE.json        run status + sample_pid + snapshot-gate evidence
│   ├── frida_trace.jsonl / frida_summary.json
│   ├── procmon.csv / procmon_summary.json
│   │                               (+ persistence catalog, spoofing_suspects)
│   ├── behavior_timeline.csv         ordered high-signal events (incident-style)
│   ├── network.json / network_intel.json (+ beacon_analysis: cadence/UA/HTTP)
│   │   / network_raw/*.pcap
│   ├── memory/                       pe-sieve dumps + suspended-process dumps
│   │   / *.dmp                       procdump -ma harvest (post-mortem)
│   ├── post_mortem.json              memory harvest + ntdll integrity + snapshot
│   ├── windbg_analysis.json          mcp-windbg triage of in-run dumps
│   │                                 (!analyze -v/.ecxr/k/lm; passive)
│   ├── x64dbg/dump/                  OEP dumps (local-mode post step)
│   └── process_snapshot.json         PPID/cmdline snapshot (spoof correlation)
├── case-<sha16>-<mode>.7z            DFIR-Nexus ingest pack (dynamic + static
│                                     context + manifest + timeline)
├── yara/
│   ├── CADRE_<sha8|family>.yar       generated YARA (deterministic, no LLM)
│   ├── CADRE_<sha8|family>.yml       Sigma network rule
│   └── rule_report.json              what evidence fed the rule
├── report/
│   ├── REPORT-TECHNICAL-v3.md        multi-section cited report (RevAI v3 layout)
│   ├── iocs.json                     extracted IOCs (deterministic, no LLM)
│   ├── AUDIT-REPORT.md               human audit narrative
│   ├── EVIDENCE-BUNDLE.md            per-item provenance index
│   └── META.json
├── stage_trace.json                  per-stage trace across the whole run
└── audit.json                        machine audit gate (truly_green etc.)
```

Same-sample/same-mode reruns overwrite their section; the other section is
untouched. Pre-sectioning packs (flat stages directly under `logs/<sha>/`)
are still read as legacy rows. Sanitized, mode-keyed publish copies land in
`docs/case-studies/<mode>/<sha>/` (`--publish`; report-level artifacts only,
lab specifics redacted, no binaries).

## What cites what

- `REPORT-TECHNICAL-v3.md` sections cite `deep/01-tools-raw.json` and
  `quick/01-tools-raw.json` — **full raw tool outputs, never truncated**.
- The deep verdict (`deep.json → agent.verdict`) is reproduced verbatim in
  section 4 of the report and tagged with its source
  (`llm_judge` / `static_deterministic` / `deterministic_fallback`).
  Static sections have no `llm_analysis` (zero LLM calls) and show the
  fired rules instead (`rules_fired`); calibration caps malicious→suspicious
  when only protection signals exist (`verdict_calibrated` + reason).
- Step-level tool errors are surfaced into the audit (`failed_tools`) — a
  failed checklist step can never hide inside the history and still pass
  `truly_green`.
- `iocs.json` is deterministic extraction (no LLM). The agent narrative is
  scanned too, and tagged in `sources` as `agent_narrative(llm_tagged)`.
- `AUDIT-REPORT.md` renders `audit.json` — the same gate that decides
  `truly_green`.

## Honesty contract

- Dynamic is **opt-in** and runs LAST. A static-only pack is valid.
- `static_yara_wins`: dynamic evidence corroborates, never clears static.
- The snapshot gate records its evidence in `dynamic/STAGE.json → gate`
  (mode, marker state, consume result) and in `logs/_vm_state.json` (VM-wide
  ledger). In `enforce` mode a dynamic stage without gate evidence fails
  the audit.
- Dry-LLM agentic packs honestly show `deterministic_fallback` and cannot
  be truly_green (deep fallback fails quality). Static-mode packs show
  `static_deterministic` — a real verdict, green when the stages pass.

## Dynamic reporting (reserved section)

`REPORT-TECHNICAL-v3.md` section 7 is reserved for the detonation phase.
When a dynamic stage exists it reports: process behavior, network sink
activity, Frida API highlights, pe-sieve/unpacked-image findings, and the
snapshot-gate record. Static verdicts are never overridden by dynamic
results (see above).
