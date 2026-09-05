# Evidence Packs & Reporting — where everything lives

WinRE writes one **evidence pack per sample**, keyed by SHA256. Both the
CLI and the console read from this layout; the RevAI remote driver reads
the same packs for corroboration.

```
logs/<sha256>/                        ← the evidence pack (one dir per sample)
├── intake/
│   ├── intake.json                   file facts: path, size, magic, format
│   └── META.json                     stage wrapper (ok/error/timing)
├── quick/                            deterministic triage
│   ├── quick.json                    verdict + full evidence dict
│   ├── 01-tools-raw.json             FULL untruncated tool outputs (citation target)
│   └── META.json
├── deep/                             LangGraph agentic deep dive
│   ├── deep.json                     agent verdict + full history + llm_analysis
│   ├── 01-tools-raw.json             FULL tool-call results (untruncated)
│   └── META.json                     fallback flag, MCP health, engine badge
├── dynamic/                          (opt-in, segregated, runs LAST)
│   ├── META.json / STAGE.json        run status + snapshot-gate evidence
│   ├── frida_trace.jsonl / frida_summary.json
│   ├── procmon.csv / procmon_summary.json
│   ├── network.json / network_intel.json / network_raw/*.pcap
│   ├── memory/                       pe-sieve dumps (optional --pesieve)
│   ├── x64dbg/dump/                  OEP dumps (local-mode post step)
│   └── process_snapshot.json
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

## What cites what

- `REPORT-TECHNICAL-v3.md` sections cite `deep/01-tools-raw.json` and
  `quick/01-tools-raw.json` — **full raw tool outputs, never truncated**.
- The agent verdict (`deep.json → agent.verdict`) is reproduced verbatim in
  section 4 of the report and tagged with its source
  (`llm_judge` / `deterministic_fallback`).
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
- Dry-LLM packs honestly show `deterministic_fallback` and cannot be
  truly_green (deep fallback fails quality).

## Dynamic reporting (reserved section)

`REPORT-TECHNICAL-v3.md` section 7 is reserved for the detonation phase.
When a dynamic stage exists it reports: process behavior, network sink
activity, Frida API highlights, pe-sieve/unpacked-image findings, and the
snapshot-gate record. Static verdicts are never overridden by dynamic
results (see above).
