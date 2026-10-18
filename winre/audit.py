#!/usr/bin/env python3
"""audit.py — truly_green gate for the WinRE pipeline.

Mirrors RevAI's honesty contract:
    truly_green = all stages ran (all_green)
                + no stage used a deterministic fallback when the primary
                  tool was required (quality_green)
                + no unmet expectation (a stage that ran but produced
                  nothing usable — e.g. a deep dive with verdict: null)
                + zero failed tools (tool_failures empty)
                + dynamic honesty (dynamic evidence corroborates but never
                  overrides static YARA — static_yara_wins)

Every audit entry records per-stage ok, any fallbacks, failed tools and
`unmet_expectations`, so a stubbed or verdict-less run can never look green.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

try:
    from .evidence import pack_verdict
except ImportError:  # direct `python winre/audit.py <evidence_dir>`
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from winre.evidence import pack_verdict  # type: ignore


def _stage_ok(evidence: Path, stage: str) -> dict:
    # Prefer the pipeline's STAGE.json wrapper; fall back to META.json
    # (orchestrator's dynamic META has ok/error/frida_events directly).
    for name in ("STAGE.json", "META.json"):
        meta = evidence / stage / name
        if meta.is_file():
            try:
                m = json.loads(meta.read_text(encoding="utf-8"))
                # explicit "not requested"/skipped stages are NOT "ran"
                if m.get("ran") is False or m.get("skipped"):
                    ok = False
                else:
                    ok = bool(m.get("ok") or m.get("ran"))
                # orchestrator dynamic META marks ok=True when artifacts landed
                if stage == "dynamic" and "frida_events" in m:
                    ok = bool(m.get("ok"))
                return {
                    "stage": stage,
                    "ran": ok,
                    "error": m.get("error"),
                    "fallback": bool(m.get("fallback")),
                    "tool_failures": m.get("tool_failures") or [],
                    "summary": m.get("summary"),
                }
            except json.JSONDecodeError:
                continue
    return {"stage": stage, "ran": False, "error": f"{stage} meta missing"}


def audit(evidence: Path, *, stages: tuple[str, ...] = ("intake", "quick",
                                                        "dynamic", "deep",
                                                        "yara", "report"),
          require_dynamic: bool = False) -> dict:
    """Run the truly_green gate over an evidence pack.

    Dynamic is OPTIONAL by design (static-first, segregated), so a static-only
    run can be truly_green - that is a deliberate product decision and it stays.

    W4 (RevAI review 2026-10-08): `require_dynamic=True` was accepted and
    documented, then never read. `required` unconditionally excluded dynamic, so
    a caller that explicitly required the dynamic stage got the same all_green
    as one that did not - successful static stages plus a FAILED dynamic stage
    both returned green. A parameter that does not do what its name and its
    docstring say is worse than no parameter: it is an assurance the caller
    believes they have and did not.

    It is honoured now. The default is unchanged, so no existing static-only
    green verdict moves.
    """
    # The persisted execution plan is authoritative for what this run asked
    # the system to do. A caller/UI that forgets the argument must not turn an
    # explicitly requested but failed detonation into optional evidence.
    execution_plan = None
    ep = evidence / "execution_plan.json"
    if ep.is_file():
        try:
            execution_plan = json.loads(ep.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            execution_plan = {"error": "execution_plan.json unreadable"}
    dynamic_requested = bool(
        require_dynamic or
        (isinstance(execution_plan, dict)
         and "dynamic" in (execution_plan.get("execution_sites") or [])))
    run_id = (execution_plan.get("run_id")
              if isinstance(execution_plan, dict) else None)
    composition = None
    composition_path = evidence / "composite.json"
    if composition_path.is_file():
        try:
            composition = json.loads(composition_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            composition = {"error": "composite.json unreadable"}
    required = tuple(stages if dynamic_requested
                     else (s for s in stages if s != "dynamic"))
    checks = [_stage_ok(evidence, s) for s in stages]
    req_checks = [c for c in checks if c["stage"] in required]
    all_green = all(c["ran"] for c in req_checks)
    deep_check = next((c for c in checks if c["stage"] == "deep"), {})
    failed_tools = [t for c in checks for t in (c.get("tool_failures") or [])]
    fallbacks = [c["stage"] for c in checks if c.get("fallback")]

    # dynamic honesty: static_yara_wins. If dynamic ran but its verdict says
    # 'benign' while static says malicious, that's a conflict — not green.
    # Reads the CURRENT writers: static verdict from quick/quick.json (written
    # by pipeline._quick AND remote_quick), dynamic verdict from the
    # dynamic STAGE.json wrapper (frida_events/verdict kwargs) then META.json.
    static = _stage_ok(evidence, "quick")
    dynamic = _stage_ok(evidence, "dynamic")
    static_verdict = None
    dynamic_verdict = None
    qf = evidence / "quick" / "quick.json"
    if qf.is_file():
        try:
            static_verdict = (json.loads(qf.read_text(encoding="utf-8"))
                              .get("verdict"))
        except json.JSONDecodeError:
            pass
    if static_verdict is None:
        qm = evidence / "quick" / "META.json"
        if qm.is_file():
            try:
                static_verdict = (json.loads(qm.read_text(encoding="utf-8"))
                                  .get("verdict"))
            except json.JSONDecodeError:
                pass
    # The REAL static verdict is produced by the deep stage
    # (deep/deep.json -> agent.verdict). remote_quick writes a placeholder
    # 'unknown', so prefer the deep verdict when present.
    deepf = evidence / "deep" / "deep.json"
    if deepf.is_file():
        try:
            _dv = ((json.loads(deepf.read_text(encoding="utf-8"))
                    .get("agent") or {}).get("verdict"))
            if isinstance(_dv, dict) and _dv.get("verdict"):
                static_verdict = _dv.get("verdict")
            elif isinstance(_dv, str):
                static_verdict = _dv
        except json.JSONDecodeError:
            pass
    for dyn_name in ("STAGE.json", "META.json"):
        df = evidence / "dynamic" / dyn_name
        if df.is_file():
            try:
                dynamic_verdict = (json.loads(df.read_text(encoding="utf-8"))
                                   .get("verdict"))
                if dynamic_verdict is not None:
                    break
            except json.JSONDecodeError:
                pass

    dynamic_conflict = False
    if dynamic.get("ran") and static_verdict == "malicious" \
            and dynamic_verdict == "benign":
        dynamic_conflict = True

    # snapshot-gate honesty: when the gate is in enforce mode, a dynamic
    # stage that ran must carry proof that the guest marker and independent
    # control-plane ledger passed. observe mode is advisory — recorded,
    # never penalizes.
    # Fail CLOSED: if the gate mode cannot be resolved at all, enforce
    # posture is assumed (missing evidence then fails the audit).
    gate = None
    gate_ok = True
    try:
        from .snapshot_gate import mode as gate_mode
        gm = gate_mode()
    except Exception as e:
        gm = "enforce"  # fail closed
        gate = {"error": f"gate mode unresolved: {e}"}
    try:
        stg_file = evidence / "dynamic" / "STAGE.json"
        stg = json.loads(stg_file.read_text(encoding="utf-8")) \
            if stg_file.is_file() else {}
        gate = stg.get("gate") or gate
        if dynamic.get("ran"):
            if gm == "enforce":
                gate_ok = bool(stg.get("gate_pass"))
            else:
                gate_ok = True
    except json.JSONDecodeError:
        # FAIL CLOSED: an unreadable STAGE.json used to leave gate_ok at its
        # initialiser True, so a truncated file could keep a run green even
        # though the dynamic stage ran with no gate evidence (code audit
        # 2026-09-28).
        gate = gate or {"error": "dynamic STAGE.json unreadable"}
        if gm == "enforce" and dynamic.get("ran"):
            gate_ok = False

    unmet: list[str] = []
    # The technical report is part of the product output, not a decorative
    # afterthought. Its source-bound claim review must match this exact report,
    # sample and run. A present citation file or a successful LLM HTTP status
    # is not sufficient; every report claim must have a supported review.
    report_review: dict = {"ok": False, "status": "missing"}
    report_review_ok = False
    review_path = evidence / "report" / "claim-review.json"
    report_path = evidence / "report" / "REPORT-TECHNICAL-v3.md"
    locator_path = evidence / "report" / "evidence-locators.json"
    if review_path.is_file() and report_path.is_file():
        try:
            report_review = json.loads(review_path.read_text(encoding="utf-8"))
            report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
            root_meta = json.loads((evidence / "META.json").read_text(encoding="utf-8"))
            locator_bytes = locator_path.read_bytes()
            locator_sha = hashlib.sha256(locator_bytes).hexdigest()
            locator_manifest = json.loads(locator_bytes.decode("utf-8"))
            if not all(isinstance(value, dict) for value in
                       (report_review, root_meta, locator_manifest)):
                raise ValueError("report review provenance documents must be JSON objects")
            locator_rows = locator_manifest.get("locators")
            if not isinstance(locator_rows, dict):
                raise ValueError("evidence locator rows are malformed")
            statuses = report_review.get("by_status") or {}
            if not isinstance(statuses, dict):
                raise ValueError("claim review status counts are malformed")
            total = int(report_review.get("claims_total") or 0)
            supported = int(statuses.get("supported") or 0)
            reviewed_claims = report_review.get("claims")
            manifest_claims = locator_manifest.get("claims")
            claim_rows_valid = (isinstance(reviewed_claims, list)
                                and len(reviewed_claims) == total
                                and isinstance(manifest_claims, list)
                                and all(isinstance(row, dict)
                                        and isinstance(row.get("text"), str)
                                        and isinstance(row.get("locators"), list)
                                        for row in manifest_claims)
                                and len([row for row in reviewed_claims
                                         if isinstance(row, dict)
                                         and str(row.get("claim_id", "")).startswith("C")])
                                    == len(manifest_claims)
                                and all(isinstance(row, dict)
                                        and row.get("status") == "supported"
                                        and row.get("evidence_quote_valid") is True
                                        and isinstance(row.get("evidence_sources"), list)
                                        and all(isinstance(source, dict)
                                                for source in row.get("evidence_sources", []))
                                        and bool(row.get("evidence_sources"))
                                        and not row.get("unresolved_locators")
                                        for row in reviewed_claims))
            source_rows_valid = bool(claim_rows_valid)
            source_resolution_cache: dict[str, dict] = {}
            source_decoded_cache: dict = {}
            source_hash_cache: dict = {}
            from .report_quality import index_jsonl_references
            source_jsonl_cache = index_jsonl_references(
                evidence,
                [str(locator.get("reference"))
                 for locator in locator_rows.values()
                 if isinstance(locator, dict) and locator.get("reference")])
            if source_rows_valid:
                for index, row in enumerate(
                        (item for item in reviewed_claims
                         if str(item.get("claim_id", "")).startswith("C")), 1):
                    ledger = manifest_claims[index - 1]
                    expected_id = f"C{index:04d}"
                    if (row.get("claim_id") != expected_id
                            or row.get("claim") != ledger.get("text")
                            or row.get("locators") != ledger.get("locators")):
                        source_rows_valid = False
                        break
            if source_rows_valid:
                for row in reviewed_claims:
                    if not str(row.get("claim_id", "")).startswith("C"):
                        source_rows_valid = False
                        break
                    row_locators = set(str(value) for value in (row.get("locators") or []))
                    row_sources = row.get("evidence_sources") or []
                    reviewed_locator = str(row.get("reviewed_locator") or "")
                    if not row_locators or row_locators != {
                            str(source.get("locator")) for source in row_sources}:
                        source_rows_valid = False
                        break
                    if not reviewed_locator or reviewed_locator not in row_locators:
                        source_rows_valid = False
                        break
                    quote = str(row.get("evidence_quote") or "")
                    quote_matches_selected_source = False
                    for source in row_sources:
                        locator = locator_rows.get(str(source.get("locator")))
                        if not isinstance(locator, dict):
                            source_rows_valid = False
                            break
                        reference = str(locator.get("reference") or "")
                        resolved = source_resolution_cache.get(reference)
                        if resolved is None:
                            from .report_quality import resolve_reference
                            resolved = resolve_reference(
                                evidence, reference,
                                decoded_cache=source_decoded_cache,
                                hash_cache=source_hash_cache,
                                jsonl_cache=source_jsonl_cache)
                            source_resolution_cache[reference] = resolved
                        if not resolved.get("ok"):
                            source_rows_valid = False
                            break
                        if (source.get("artifact") != resolved.get("artifact")
                                or source.get("json_path") != resolved.get("pointer")
                                or source.get("artifact_sha256") != resolved.get("sha256")):
                            source_rows_valid = False
                            break
                        if (str(source.get("locator")) == reviewed_locator
                                and quote
                                and quote in str(resolved.get("excerpt") or "")):
                            quote_matches_selected_source = True
                    if not source_rows_valid or not quote_matches_selected_source:
                        source_rows_valid = False
                        break
                    if not source_rows_valid:
                        break
            review_attempts = report_review.get("review_attempts")
            call_records_valid = isinstance(review_attempts, list) and bool(review_attempts)
            call_decisions: dict[str, dict] = {}
            call_prompt_claims: dict[str, dict] = {}
            if call_records_valid:
                for attempt in review_attempts:
                    artifacts = (attempt.get("call_artifacts")
                                 if isinstance(attempt, dict) else None)
                    if not isinstance(artifacts, dict):
                        call_records_valid = False
                        break
                    request_rel = str(artifacts.get("request_path") or "")
                    response_rel = str(artifacts.get("response_path") or "")
                    request_file = (evidence / request_rel).resolve()
                    response_file = (evidence / response_rel).resolve()
                    if (not request_rel or not response_rel
                            or evidence.resolve() not in request_file.parents
                            or evidence.resolve() not in response_file.parents
                            or not request_file.is_file() or not response_file.is_file()):
                        call_records_valid = False
                        break
                    request_bytes = request_file.read_bytes()
                    response_bytes = response_file.read_bytes()
                    if (hashlib.sha256(request_bytes).hexdigest()
                            != artifacts.get("request_sha256")
                            or hashlib.sha256(response_bytes).hexdigest()
                            != artifacts.get("response_sha256")):
                        call_records_valid = False
                        break
                    request_doc = json.loads(request_bytes.decode("utf-8"))
                    response_doc = json.loads(response_bytes.decode("utf-8"))
                    payload = request_doc.get("payload")
                    messages = payload.get("messages") if isinstance(payload, dict) else None
                    prompt_text = next((message.get("content") for message in messages or []
                                        if isinstance(message, dict)
                                        and message.get("role") == "user"
                                        and isinstance(message.get("content"), str)), None)
                    response_content = response_doc.get("content")
                    if (not isinstance(prompt_text, str)
                            or hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
                                != artifacts.get("prompt_sha256")
                            or len(prompt_text) != artifacts.get("prompt_chars")
                            or not isinstance(response_content, str)
                            or hashlib.sha256(response_content.encode("utf-8")).hexdigest()
                                != attempt.get("response_sha256")
                            or response_doc.get("finish_reason") != attempt.get("finish_reason")
                            or response_doc.get("error") is not None
                            or attempt.get("error") is not None):
                        call_records_valid = False
                        break

                    # Bind the saved decision to the exact prompt batch and raw
                    # model response. Hashing request/response files alone does
                    # not establish that a given claim was the one reviewed.
                    analysis_marker = "ANALYSIS_IDENTITY: "
                    methodology_marker = "\nMETHODOLOGY: "
                    claims_marker = "\nCLAIMS: "
                    if (analysis_marker not in prompt_text
                            or methodology_marker not in prompt_text
                            or claims_marker not in prompt_text):
                        call_records_valid = False
                        break
                    try:
                        analysis_text = prompt_text.split(analysis_marker, 1)[1].split(
                            methodology_marker, 1)[0]
                        prompt_identity = json.loads(analysis_text)
                        prompt_claim_rows = json.loads(prompt_text.rsplit(
                            claims_marker, 1)[1])
                        review_text = str(response_content).strip()
                        review_text = re.sub(
                            r"^```(?:json)?\s*|\s*```$", "", review_text,
                            flags=re.IGNORECASE | re.DOTALL).strip()
                        response_rows = json.loads(review_text).get("reviews")
                    except (IndexError, json.JSONDecodeError, AttributeError):
                        call_records_valid = False
                        break
                    if (prompt_identity != {"sha256": root_meta.get("sha256"),
                                           "run_id": root_meta.get("run_id")}
                            or prompt_text.split(methodology_marker, 1)[1].split(
                                claims_marker, 1)[0] != report_review.get("methodology")
                            or not isinstance(prompt_claim_rows, list)
                            or not isinstance(response_rows, list)):
                        call_records_valid = False
                        break
                    batch_claims: dict[str, dict] = {}
                    for item in prompt_claim_rows:
                        if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                                or item["id"] in batch_claims
                                or not isinstance(item.get("claim"), str)
                                or not isinstance(item.get("evidence"), list)):
                            call_records_valid = False
                            break
                        batch_claims[item["id"]] = item
                    attempt_ids = attempt.get("claim_ids")
                    if (not call_records_valid
                            or not isinstance(attempt_ids, list)
                            or len(attempt_ids) != len(set(attempt_ids))
                            or set(attempt_ids) != set(batch_claims)
                            or any(claim_id in call_prompt_claims for claim_id in batch_claims)):
                        call_records_valid = False
                        break
                    if (not isinstance(payload, dict)
                            or payload.get("model") != report_review.get("reviewer_model")):
                        call_records_valid = False
                        break
                    call_prompt_claims.update(batch_claims)

                    batch_decisions: dict[str, dict] = {}
                    for response_row in response_rows:
                        if (not isinstance(response_row, list) or len(response_row) != 3
                                or not all(isinstance(value, str) for value in response_row)):
                            call_records_valid = False
                            break
                        claim_id, verdict, locator_id = response_row
                        if (claim_id in batch_decisions
                                or verdict not in {"supported", "contradicted", "insufficient"}):
                            call_records_valid = False
                            break
                        batch_decisions[claim_id] = {
                            "verdict": verdict, "locator": locator_id}
                    if (not call_records_valid
                            or set(batch_decisions) != set(batch_claims)):
                        call_records_valid = False
                        break
                    call_decisions.update(batch_decisions)

            # The exact claim and exact locator set sent to the model must
            # match the report ledger, and the final decision must match the
            # response bytes saved for that call. This closes a gap where a
            # valid call artifact and a separate green result could be paired.
            if call_records_valid and source_rows_valid:
                reviewed_by_id = {str(row.get("claim_id")): row
                                  for row in reviewed_claims if isinstance(row, dict)}
                expected_claim_ids = {
                    str(row.get("claim_id")) for row in reviewed_claims
                    if isinstance(row, dict) and str(row.get("claim_id", "")).startswith("C")}
                if set(call_prompt_claims) != expected_claim_ids \
                        or set(call_decisions) != expected_claim_ids:
                    call_records_valid = False
                else:
                    for claim_id in sorted(expected_claim_ids):
                        reviewed = reviewed_by_id.get(claim_id) or {}
                        prompt_claim = call_prompt_claims[claim_id]
                        decision = call_decisions[claim_id]
                        evidence_rows = prompt_claim.get("evidence") or []
                        evidence_by_locator = {
                            str(item.get("locator")): item for item in evidence_rows
                            if isinstance(item, dict) and item.get("locator")}
                        result_sources = {
                            str(item.get("locator")): item
                            for item in reviewed.get("evidence_sources") or []
                            if isinstance(item, dict) and item.get("locator")}
                        expected_locators = set(str(value) for value in
                                                (reviewed.get("locators") or []))
                        if (prompt_claim.get("claim") != reviewed.get("claim")
                                or set(evidence_by_locator) != expected_locators
                                or set(result_sources) != expected_locators
                                or decision.get("locator") != reviewed.get("reviewed_locator")
                                or decision.get("verdict") != reviewed.get("status")):
                            call_records_valid = False
                            break
                        for locator_id, prompt_source in evidence_by_locator.items():
                            locator = locator_rows.get(locator_id)
                            source = result_sources.get(locator_id) or {}
                            if not isinstance(locator, dict):
                                call_records_valid = False
                                break
                            reference = str(locator.get("reference") or "")
                            resolved = source_resolution_cache.get(reference)
                            if (resolved is None or not resolved.get("ok")
                                    or prompt_source.get("reference") != reference
                                    or prompt_source.get("artifact") != resolved.get("artifact")
                                    or prompt_source.get("json_path") != resolved.get("pointer")
                                    or prompt_source.get("artifact_sha256") != resolved.get("sha256")
                                    or prompt_source.get("excerpt") != resolved.get("excerpt")
                                    or source.get("artifact") != resolved.get("artifact")
                                    or source.get("json_path") != resolved.get("pointer")
                                    or source.get("artifact_sha256") != resolved.get("sha256")):
                                call_records_valid = False
                                break
                        if not call_records_valid:
                            break
            report_review_ok = bool(
                report_review.get("schema") == "winre-report-claim-review/v2"
                and report_review.get("ok") is True
                and report_review.get("status") == "complete"
                and report_review.get("sha256") == root_meta.get("sha256")
                and report_review.get("run_id") == root_meta.get("run_id")
                and bool(root_meta.get("sha256")) and bool(root_meta.get("run_id"))
                and report_review.get("report_sha256") == report_sha
                and report_review.get("locators_sha256") == locator_sha
                and locator_manifest.get("sha256") == root_meta.get("sha256")
                and locator_manifest.get("run_id") == root_meta.get("run_id")
                and locator_manifest.get("report_sha256") == report_sha
                and total > 0 and supported == total
                and sum(int(value or 0) for value in statuses.values()) == total
                and source_rows_valid and call_records_valid)
            if not report_review_ok:
                report_review = {**report_review, "ok": False,
                                 "status": "invalid-or-unsupported",
                                 "report_sha256_current": report_sha}
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            report_review = {"ok": False, "status": "unreadable",
                             "reason": f"{type(exc).__name__}: {exc}"}
    if not report_review_ok:
        unmet.append("report claim support review missing, stale, or not fully supported")

    quality_green = not fallbacks and not failed_tools \
        and not dynamic_conflict and gate_ok and report_review_ok

    # Unmet expectations (RevAI handoff 2026-09-27 item 2). A stage can be
    # "ran" and still have produced nothing usable — the deep dive finishing
    # with verdict: null used to be written ok=true, so `truly_green: true`
    # sat next to a missing verdict. These are named, recorded, and they DO
    # consume truly_green.
    if deep_check.get("ran"):
        if not isinstance(composition, dict) or composition.get("error"):
            unmet.append("current-run composite selection missing or unreadable")
        elif run_id and composition.get("run_id") != run_id:
            unmet.append("composite selection is not pinned to this pipeline run")
        else:
            pack_meta_path = evidence / "META.json"
            try:
                pack_meta = json.loads(pack_meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pack_meta = {}
            pack_mode = (pack_meta.get("pack_mode") or pack_meta.get("mode")
                         if isinstance(pack_meta, dict) else None)
            current_selection = ((composition.get("selection") or {})
                                 .get(str(pack_mode)) or {})
            if (pack_mode and current_selection.get("selected") is not True
                    and not current_selection.get("reason", "").startswith("current run candidate")):
                unmet.append("current mode is absent from composite selection")
    floor = ((composition or {}).get("curated_yara_floor") or {}) \
        if isinstance(composition, dict) else {}
    static_yara_wins = (not floor.get("applied")
                        or (composition or {}).get("level") == "malicious")
    if not static_yara_wins:
        unmet.append("composite verdict fell below the curated-YARA malicious floor")
    capability_census = None
    capability_failures: list[str] = []
    quick_json = evidence / "quick" / "quick.json"
    if quick_json.is_file():
        try:
            quick_record = json.loads(quick_json.read_text(encoding="utf-8"))
            quick_census = quick_record.get("capability_census")
        except json.JSONDecodeError:
            quick_census = None
            capability_failures.append("quick/quick.json unreadable")
        quick_check = next((c for c in checks if c["stage"] == "quick"), {})
        if quick_check.get("ran"):
            if not isinstance(quick_census, dict) or \
                    quick_census.get("schema") != "winre-quick-capability-census/v1":
                capability_failures.append("quick capability census missing or invalid")
            else:
                quick_required = set(quick_census.get("required") or [])
                quick_rows = {str(row.get("tool")): row
                              for row in quick_census.get("capabilities") or []
                              if isinstance(row, dict) and row.get("tool")}
                for tool in sorted(quick_required):
                    status = (quick_rows.get(tool) or {}).get("status", "not_attempted")
                    if status != "completed":
                        capability_failures.append(
                            f"required quick capability {tool} status={status}")
    deep_json = evidence / "deep" / "deep.json"
    if deep_json.is_file():
        try:
            deep_record = json.loads(deep_json.read_text(encoding="utf-8"))
            capability_census = deep_record.get("capability_census")
        except json.JSONDecodeError:
            capability_failures.append("deep/deep.json unreadable")
    if deep_check.get("ran"):
        from winre.capabilities import CORE_REQUIRED_TOOLS
        if not isinstance(capability_census, dict) or \
                capability_census.get("schema") != "winre-capability-census/v1":
            capability_failures.append("deep capability census missing or invalid")
        else:
            declared = set(capability_census.get("required") or [])
            summary = {str(row.get("tool")): row
                       for row in capability_census.get("summary") or []
                       if isinstance(row, dict) and row.get("tool")}
            undeclared = sorted(set(CORE_REQUIRED_TOOLS) - declared)
            if undeclared:
                capability_failures.append(
                    "required capabilities omitted from declaration: "
                    + ", ".join(undeclared))
            for tool in CORE_REQUIRED_TOOLS:
                status = (summary.get(tool) or {}).get("status", "not_attempted")
                if status != "completed":
                    capability_failures.append(
                        f"required capability {tool} status={status}")
    unmet.extend(capability_failures)

    # Collection coverage is a separate contract from tool exit status. Stage
    # manifests pin the collector terminal record and primary artifact format
    # to this run; a present file alone is never enough to mark it complete.
    artifact_coverage: dict[str, dict] = {}
    coverage_failures: list[str] = []
    try:
        from .manifest import read_manifest
        coverage_stages = ["intake", "quick", "deep", "yara", "report"]
        if dynamic_requested:
            coverage_stages.append("dynamic")
        for stage_name in coverage_stages:
            stage_manifest = read_manifest(evidence / stage_name)
            artifact_coverage[stage_name] = stage_manifest.get("coverage") or {}
            if not stage_manifest:
                coverage_failures.append(f"{stage_name} artifact manifest missing")
                continue
            if run_id and stage_manifest.get("run_id") != run_id:
                coverage_failures.append(
                    f"{stage_name} artifact manifest is not pinned to this run")
            for source, row in artifact_coverage[stage_name].items():
                if (row.get("requested") and row.get("required")
                        and row.get("status") != "complete"):
                    coverage_failures.append(
                        f"required artifact source {stage_name}/{source} "
                        f"status={row.get('status')}: {row.get('reason')}")
    except Exception as e:
        coverage_failures.append(f"artifact coverage could not be audited: {e}")
    unmet.extend(coverage_failures)

    if dynamic_requested:
        dynamic_stage_file = evidence / "dynamic" / "STAGE.json"
        try:
            dynamic_stage_meta = json.loads(
                dynamic_stage_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            dynamic_stage_meta = {}
        if not run_id or dynamic_stage_meta.get("run_id") != run_id:
            unmet.append("requested dynamic stage is not pinned to this pipeline run")

    deep_v = pack_verdict(evidence)
    if deep_check.get("ran") and not deep_v["present"]:
        unmet.append("deep verdict missing (deep stage produced no verdict)")
    # report stage: source says a judge produced it, but no verdict in it
    rep = None
    rf = evidence / "report" / "report.json"
    if rf.is_file():
        try:
            rep = json.loads(rf.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            rep = None
    if isinstance(rep, dict):
        if not rep.get("verdict"):
            unmet.append("report verdict missing (report carries no verdict)")
        if rep.get("source") == "deterministic_fallback":
            unmet.append("report source is deterministic_fallback")
    truly_green = all_green and quality_green and not unmet

    # A dynamic stage that was REQUESTED but refused by the snapshot gate is
    # recorded explicitly (the stage file exists with ok=False + gate error).
    # It does not fail truly_green (the gate acted correctly; dynamic is
    # optional), but reports must not look like detonation happened.
    dynamic_blocked = False
    try:
        stg_file = evidence / "dynamic" / "STAGE.json"
        if stg_file.is_file():
            _s = json.loads(stg_file.read_text(encoding="utf-8"))
            dynamic_blocked = bool(
                _s.get("ok") is False
                and "snapshot gate" in str(_s.get("error") or ""))
    except (OSError, json.JSONDecodeError):
        pass

    return {
        "truly_green": truly_green,
        "all_green": all_green,
        "quality_green": quality_green,
        "checks": checks,
        "fallback_stages": fallbacks,
        "failed_tools": failed_tools,
        "capability_census": capability_census,
        "capability_failures": capability_failures,
        "artifact_coverage": artifact_coverage,
        "artifact_coverage_failures": coverage_failures,
        "report_claim_review": report_review,
        "unmet_expectations": unmet,
        "dynamic_conflict": dynamic_conflict,
        "dynamic_blocked": dynamic_blocked,
        "static_yara_wins": static_yara_wins,
        "static_verdict": static_verdict,
        "deep_verdict": deep_v["verdict"],
        "deep_verdict_source": deep_v["source"],
        "llm_roles": deep_v.get("llm_roles"),
        "dynamic_verdict": dynamic_verdict,
        "execution_plan": execution_plan,
        "dynamic_requested": dynamic_requested,
        "run_id": run_id,
        "composite": composition,
        "selected_verdict": ((composition or {}).get("level")
                             if isinstance(composition, dict) else None),
        "snapshot_gate": {"mode": gm, "ok": gate_ok, "detail": gate},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("usage: audit.py <evidence_dir>")
        sys.exit(0 if len(sys.argv) > 1 else 2)
    ev = Path(sys.argv[1])
    res = audit(ev)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["truly_green"] else 1)
