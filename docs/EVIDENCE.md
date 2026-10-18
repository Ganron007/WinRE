# Evidence Packs and Reporting

> **Scope:** pack layout, provenance, and the `truly_green` audit contract.
> **Audience:** analysts, operators, and integrators.

WinRE groups output by sample SHA-256 and producer section. The section is one
of `static`, `agentic`, `dbg`, or `dynamic`; these names distinguish the
deterministic engine, agentic engine, debugger capability, and detonation
capability. The engine used for a run is recorded separately in pack metadata.
At the pack root, `META.json.verdict` is the selected cross-mode verdict and
`mode_verdict` is the current section's result. `selected_verdict_source`
identifies the report's selection path. `report/report.json` also preserves
the section verdict and composite with its named disagreements.

```text
logs/<sha256>/
├── static/                       deterministic deep-analysis run
├── agentic/                      agentic deep-analysis run
├── dbg/                          agentic run with debugger capability
├── dynamic/                      agentic run with detonation capability
└── snapshot.json                 optional sample-level snapshot/HITL record

logs/<sha256>/<section>/
├── META.json                     pack mode, engine, run ID, status
├── execution_plan.json           requested execution sites and gate budget
├── intake/                       identity, file metadata, format
├── quick/                        deterministic triage and raw tool outputs
├── deep/                         checklist or agentic investigation
├── dynamic/                      detonation evidence when requested
├── yara/                         generated rules and rule-quality report
├── report/                       structured reports and provenance
├── composite.json                selected current-run findings, when present
├── findings.json                 normalized findings, when present
├── stage_trace.json              stage ordering and timing
├── artifact-manifest.json        finalized pack inventory and coverage
├── audit.json                    run-quality result
└── case-<sha16>-<section>.7z     optional DFIR-Nexus export
```

Each stage directory can include a `manifest.json` with file hashes,
producers, run identity, validation information, and source coverage. The
pack-level `artifact-manifest.json` inventories the delivered pack after
reports and audit are written. A source can be `complete`, `partial`,
`failed`, `unavailable`, `not_applicable`, or `not_requested`. A missing
capture is not treated as a successful empty capture. Files above the
configured hash limit may have a recorded reason instead of a file hash.

Dynamic collection is opt-in. Its `META.json` and `STAGE.json` record the
requested and effective time window, stop reason, execution gate, and run ID.
The run ID, rather than clock comparison, binds the guest result to the
control-plane request. `previous_runs/` may preserve earlier dynamic evidence
when a later run in the same section does not request detonation.
The guest's `META.job.json` is inventoried as in-guest run metadata and is the
primary terminal record for job-level collection coverage.

Debugger-assisted runs also record `deep/debug_monitor/process.etl`, the raw
kernel-process ETW trace, and a derived `process_events.jsonl` with process
start/stop events and target-descendant correlation. The observer is
run-scoped and independent of x64dbg. Its scope is process lifecycle only; it
does not observe file, registry, network, or memory behavior. A complete ETW
capture therefore complements the debugger evidence but does not replace the
dynamic collection sources. `deep.json` records the debugger OEP/unpack probe
and bounded observation window, including requested and observed seconds,
pause count, final debugger state, and whether the target exited or was stopped.
The mode-level `findings.json` keeps the window result, current-run ETW summary,
process cleanup result, and unpack result as separate fields. The debug copy is
separate from the staged source and is hash-checked before execution. Cleanup
uses the ETW active-process identities and confirms PID, image name, and
creation time before terminating a process. A completed debugger window can be
selected in the mode composite without an OEP dump only when ETW observed the
target and process cleanup completed. The report states missing-dump limits
and keeps the selected composite verdict distinct from the deep-stage agent
assessment. Debugger availability, process observation, and unpack success are
coverage evidence, not independent evidence of malicious intent. An incomplete
trace or unconfirmed cleanup keeps the mode red.

The control-plane snapshot ledger is stored in the ignored operator state file
`internal/_vm_state.json`; it is not a sample finding and is not part of the
pack. A guest-local `logs/_vm_state.json` is diagnostic only. This ledger is
separate from any optional `snapshot.json` copied into a case export.

## Findings and report provenance

The reports link conclusions to structured stage evidence. Quick and deep
stages retain raw tool results for review; generated rules record their input
evidence and lint results; the report and audit reflect the selected run.
When static and dynamic evidence disagree, the pack keeps the conflict visible
and applies the documented `static_yara_wins` policy. Dynamic evidence can
corroborate a static result but does not clear a high-signal static YARA
finding.

The report records whether its judgment came from the configured LLM, the
deterministic engine, or a deterministic fallback. Static mode has no agentic
LLM analysis, but the final report still receives a separate claim-support
review. That review records field-level evidence keys and fails closed when a
claim cannot be supported. An agentic run with `--dry-llm` records
`deterministic_fallback`; report review is also marked not requested, so the
fallback and missing report review remain visible to the operator and audit.

Dynamic findings separate process launch from evidence quality. `run_observed`
records whether the sample PID was observed, while `evidence_complete` and
`ok` remain false if the guest job or evidence transfer was incomplete. In that
case the findings remain unknown and the report must not describe the sample as
having done nothing; an absent signal may reflect a missing collector or an
unaccepted transfer.

## Audit contract

`audit.json → truly_green` evaluates workflow quality, not malware
classification. It checks that required stages ran, required capabilities
were accepted, expected verdict and composition records exist, tool failures
and required fallbacks are absent, and the snapshot gate passed when required.
An explicitly requested dynamic or debugger capability that fails cannot be
counted as an optional omission. A static-only run does not require dynamic
evidence.

A green result does not prove that a sample is benign, that every behavior was
observed, or that a tool had complete coverage. Consult stage manifests,
coverage status, collector terminal records, and `audit.json` together.
Treat all guest-produced files and tool output as untrusted input.

## Case exports

`--publish` creates a sanitized report-level copy under
`docs/case-studies/<section>/<sha256>/`. It excludes sample binaries. The
optional DFIR-Nexus case archive is written at the pack root and includes a
file/hash manifest. The archive is named `case-<sha16>-<mode>.7z` (or `.zip`
when 7-Zip is unavailable) and is a DFIR-Nexus ingest pack. Review its
`case_manifest.json` and the pack's finalized artifact manifest before
importing it into another system.

Debugger dumps include `dump_kind` (`module` or `heap`), `dump_source`,
`dump_path`, `pe_valid` and `pe_valid_known`, `imports_count`, `machine`,
`oep_target`, `ran_to_oep`, `payload_unpacked`, `imports_rebuilt`,
`imports_rebuild_applicable`, `imports_rebuild_reason`, and `rebuild_hint`.
Treat `pe_valid: null` as unknown. A heap dump is a raw memory region, not a PE
image; a module dump that did not run to OEP may still be the packed image.

## Legacy packs

Older packs may have flat stage directories directly under `logs/<sha256>/`
or may lack run IDs, manifests, coverage records, and finalized composition.
Readers retain limited compatibility for legacy layouts, but missing
provenance cannot be reconstructed after the fact. Do not infer that an
unrecorded collector completed or that an empty legacy artifact represents a
valid zero-result analysis.
