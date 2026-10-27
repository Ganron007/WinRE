"""Controls for the report locator contract (2026-10-21/22).

The first live standalone static acceptance run (s02) failed its audit with
`truly_green=False` although every stage ran and the verdict was correct.
The claim review had marked 19 of 79 claims "unverifiable", all with the
same cause: "evidence excerpt exceeds review limit".

report_quality caps an evidence excerpt at 6,000 characters and REJECTS a
truncated excerpt, so a locator that points at a whole array (the capa
capability list, the deep tool history, the whole quick evidence, the
coverage map) can never be shown to the reviewer - the claim is
unverifiable whatever the reviewer answers, and the audit gate
(supported == total) then refuses the run.

Two contracts are therefore enforced here:

  1. the builder never publishes a locator whose evidence excerpt exceeds
     the review limit (it narrows the locator instead);
  2. the call-record files the reviewer writes hash to the same digest the
     audit recomputes - a Windows newline translation used to break this,
     so the claim review could never be green on the FlareVM.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from winre import reporting
from winre.report_quality import resolve_reference

SHA = "a" * 64


def _pack(tmp_path):
    """A minimal static pack whose quick evidence holds a capa list big
    enough to blow the excerpt limit if it is cited as one object."""
    pack_root = tmp_path / SHA / "static"
    (pack_root / "quick").mkdir(parents=True, exist_ok=True)
    (pack_root / "deep").mkdir(parents=True, exist_ok=True)
    (pack_root / "report").mkdir(parents=True, exist_ok=True)
    (pack_root / "META.json").write_text(json.dumps({
        "sha256": SHA, "mode": "static", "pack_mode": "static",
        "run_id": "b" * 32, "status": "in_progress",
    }), encoding="utf-8")
    # a capa list far larger than the 6,000 char review limit
    capabilities = [{"name": f"capability number {index}",
                     "attack": ["Discovery::Discovery [T1083]"],
                     "count": index,
                     "namespace": "host-interaction/x" * 3,
                     "mbc": ["Discovery::Discovery [E1083]"]}
                    for index in range(120)]
    (pack_root / "quick" / "quick.json").write_text(json.dumps({
        "evidence": {
            "capa": {"ok": True, "tool": "capa", "capabilities": capabilities,
                     "total": len(capabilities)},
            "pe": {"machine": "0x14c", "entrypoint": 728700, "signed": False,
                   "compile_ts": 1786354838, "imports": [],
                   "sections": [{"name": ".text", "entropy": 6.39}]},
            "ghidra": {"func_rows": 20, "imports": []},
            "ida": {"func_count": "3550", "i64_created": True},
        },
        "verdict": "malicious",
    }), encoding="utf-8")
    (pack_root / "deep" / "deep.json").write_text(json.dumps({
        "agent": {"source": "static_deterministic", "verdict": {
            "verdict": "malicious", "confidence": "high", "summary": "s"},
            "history": [{"tool": "capa", "result": {
                "ok": True, "capabilities": capabilities,
                "total": len(capabilities)}}]},
    }), encoding="utf-8")
    (pack_root / "composite.json").write_text(json.dumps({
        "level": "malicious", "confidence": "high", "basis": ["capa:x"],
        "deciding_mode": "static",
        "selection": {"static": {"selected": True, "run_id": "b" * 32}},
    }), encoding="utf-8")
    return pack_root


def test_the_builder_never_publishes_an_over_limit_locator(tmp_path):
    """THE control. Every locator the report publishes must resolve to an
    excerpt the reviewer can actually see."""
    pack_root = _pack(tmp_path)
    res = reporting.build_report_v3(pack_root, review_claims=False)
    assert res.get("ok"), res

    manifest = json.loads(
        (pack_root / "report" / "evidence-locators.json").read_text(encoding="utf-8"))
    locators = manifest.get("locators") or {}
    assert locators, "the report published no locator at all"

    over = []
    for locator_id, meta in locators.items():
        reference = (meta or {}).get("reference") or ""
        resolved = resolve_reference(pack_root, reference)
        if not resolved.get("ok") or resolved.get("excerpt_truncated"):
            over.append((locator_id, reference))
    assert not over, f"locators the reviewer cannot see: {over}"


def test_the_builder_refuses_and_records_an_over_broad_locator(tmp_path):
    """A locator that cannot be shown is not published, and the refusal is
    recorded instead of being hidden."""
    pack_root = _pack(tmp_path)
    res = reporting.build_report_v3(pack_root, review_claims=False)
    refused = res.get("over_broad_refs") or []
    manifest = json.loads(
        (pack_root / "report" / "evidence-locators.json").read_text(encoding="utf-8"))
    published = {(m or {}).get("reference") for m in (manifest.get("locators") or {}).values()}
    for reference in refused:
        assert reference not in published, (
            f"{reference} was recorded as over-broad but still published")


def _stubbed_review(monkeypatch):
    """A reviewer that supports every claim with the locators it was given."""
    from winre import llm_client

    def fake_chat_result(messages, **kwargs):
        prompt = next((m.get("content") for m in messages
                       if m.get("role") == "user"), "")
        claims = json.loads(prompt.split("CLAIMS: ", 1)[-1])
        reviews = [{"claim_id": item["id"], "verdict": "supported",
                    "locator_ids": [str(entry.get("locator"))
                                    for entry in (item.get("evidence") or [])]}
                   for item in claims]
        return {"content": "", "finish_reason": "tool_calls",
                "tool_calls": [{"function": {
                    "name": "submit_claim_reviews",
                    "arguments": json.dumps({"reviews": reviews})}}],
                "usage": {}, "model": "stub", "response_id": "stub",
                "error": None}

    monkeypatch.setattr(llm_client, "chat_result", fake_chat_result)
    monkeypatch.setattr(llm_client, "model_for", lambda role: "stub-model")
    monkeypatch.setattr(llm_client, "API_KEY", "stub-key")
    monkeypatch.setattr(llm_client, "BASE_URL", "http://127.0.0.1:9/v1")


def test_the_claim_review_accepts_its_own_verdicts_and_records_digests(
        tmp_path, monkeypatch):
    """The whole review path must reach a green result for every claim that
    HAS evidence, and the call records it writes must hash to the digests it
    records.

    A Windows newline translation used to break exactly this: the digest was
    taken over the string while the audit re-hashed the file, so the claim
    review could never be green on the FlareVM.
    """
    pack_root = _pack(tmp_path)
    _stubbed_review(monkeypatch)
    res = reporting.build_report_v3(pack_root, review_claims=True)
    review = res.get("claim_review") or {}
    assert review.get("status") in ("complete", "failed"), review

    statuses = review.get("by_status") or {}
    assert "invalid-review" not in statuses, (
        f"the review machinery rejected its own verdicts: {review}")
    evidenced = [claim for claim in (review.get("claims") or [])
                 if claim.get("status") != "unverifiable"]
    assert evidenced, "the fixture produced no reviewable claim"
    for claim in evidenced:
        assert claim.get("status") == "supported", claim

    for attempt in review.get("review_attempts") or []:
        artifacts = attempt.get("call_artifacts") or {}
        for path_key, digest_key in (("request_path", "request_sha256"),
                                     ("response_path", "response_sha256")):
            path = (pack_root / str(artifacts.get(path_key))).resolve()
            assert path.is_file(), path
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            assert digest == artifacts.get(digest_key), (
                f"{path.name}: the bytes on disk must hash to the recorded "
                "digest (a newline translation used to break this on Windows)")


def test_a_claim_must_cite_evidence_that_states_it(tmp_path):
    """A claim that names a source no evidence states is not verifiable: the
    report must name the mode composite.json says was selected."""
    pack_root = _pack(tmp_path)
    reporting.build_report_v3(pack_root, review_claims=False)
    markdown = (pack_root / "report" / "REPORT-TECHNICAL-v3.md").read_text(encoding="utf-8")
    assert "source `static`" in markdown, (
        "the report must name the selected mode, not an internal label")
    assert "mode-composite" not in markdown


def test_the_model_summary_is_attributed_not_presented_as_a_finding(tmp_path):
    """The deep agent's free-text summary is a model judgment over the
    evidence, not a finding in its own right.

    Presented as a bare fact ("Summary: ...") the reviewer contradicted it
    when it disagreed with the cited evidence (2026-10-24 dbg run: the
    summary said "not malware" beside a cited 16/71 VT ratio). The report now
    attributes it, so the claim is what the evidence actually states - that
    the agent recorded this judgment - while the evidence sections state what
    is known.
    """
    pack_root = _pack(tmp_path)
    reporting.build_report_v3(pack_root, review_claims=False)
    markdown = (pack_root / "report" / "REPORT-TECHNICAL-v3.md").read_text(encoding="utf-8")
    assert "Agent's recorded summary (model judgment over the cited evidence; " \
           "not an independent finding):**" in markdown
    assert "\n  - Summary:" not in markdown, (
        "a bare 'Summary:' line presents a model judgment as a report finding")


def _dynamic_pack(tmp_path):
    """A minimal dynamic pack whose frida_coverage record is far larger than
    the review limit if cited whole (installed_exports alone is ~5.6 KB)."""
    pack_root = tmp_path / SHA / "dynamic"
    for stage in ("deep", "dynamic", "report"):
        (pack_root / stage).mkdir(parents=True, exist_ok=True)
    (pack_root / "META.json").write_text(json.dumps({
        "sha256": SHA, "mode": "dynamic", "pack_mode": "dynamic",
        "run_id": "c" * 32, "status": "in_progress",
    }), encoding="utf-8")
    exports = [{"pid": 100 + i, "api": f"Api{i}", "module": "KERNEL32.DLL",
                "address": f"0x{0x75000000 + i * 16:x}"} for i in range(120)]
    (pack_root / "findings.json").write_text(json.dumps({
        "schema": "winre-findings/v1", "mode": "dynamic", "sha256": SHA,
        "ok": True, "run_id": "c" * 32,
        "verdict": {"level": "unknown", "confidence": "low", "basis": ["gate:x"]},
        "findings": {
            "frida_coverage": {
                "status": "reported",
                "requested": ["CreateFileW", "WriteFile", "ReadFile"],
                "installed": ["CreateFileW", "WriteFile"],
                "apis_fired": ["CreateFileW", "WriteFile"],
                "installed_exports": exports,
            },
        },
    }), encoding="utf-8")
    (pack_root / "dynamic" / "STAGE.json").write_text(json.dumps({
        "stage": "dynamic", "ok": True, "ran": True,
        "detonation_ran": True}), encoding="utf-8")
    (pack_root / "dynamic" / "META.json").write_text(json.dumps({
        "ok": True, "detonation_ran": True, "sample_pid": 1376}),
        encoding="utf-8")
    (pack_root / "deep" / "deep.json").write_text(json.dumps({
        "agent": {"source": "llm_judge",
                  "verdict": {"verdict": "benign", "confidence": "medium",
                              "summary": "s"},
                  "history": [{"tool": "capa", "result": {"ok": True}},
                              {"tool": "yarascan", "result": {"ok": True}}]},
    }), encoding="utf-8")
    (pack_root / "composite.json").write_text(json.dumps({
        "level": "unknown", "confidence": "low", "deciding_mode": "dynamic",
        "basis": ["gate:x"],
        "selection": {"dynamic": {"selected": True, "run_id": "c" * 32}}}),
        encoding="utf-8")
    return pack_root


def test_dynamic_claims_cite_the_fields_they_report(tmp_path):
    """Two dynamic claims were refused on the 2026-10-24 run:

    * "No signature-match invocation appears..." was contradicted because
      "signature-match" reads like YARA scanning (which DID run). The claim
      must name the `signature_match` tool.
    * the Frida coverage line cited the whole frida_coverage record (>6 KB,
      installed_exports alone 5.6 KB), so it had no usable excerpt at all and
      came back unverifiable. It must cite the fields it reports.
    """
    pack_root = _dynamic_pack(tmp_path)
    reporting.build_report_v3(pack_root, review_claims=False)
    markdown = (pack_root / "report" / "REPORT-TECHNICAL-v3.md").read_text(
        encoding="utf-8")
    assert "did not invoke the `signature_match` tool" in markdown

    manifest = json.loads(
        (pack_root / "report" / "evidence-locators.json").read_text(encoding="utf-8"))
    refs = {(meta or {}).get("reference")
            for meta in (manifest.get("locators") or {}).values()}
    for field in ("status", "requested", "installed", "apis_fired"):
        assert f"findings.json#$.findings.frida_coverage.{field}" in refs, field
    assert "findings.json#$.findings.frida_coverage" not in refs, (
        "the whole coverage record cannot be shown to the reviewer")


def test_a_truncated_review_response_is_retried_as_smaller_batches(
        tmp_path, monkeypatch):
    """One oversized model response must not discard the rest of the review.

    On the 2026-10-24 dynamic run a single batch came back
    finish_reason=length with empty content; the reviewer marked that batch
    verification-error and every LATER batch "not-reviewed", costing 19 of 79
    claims. The review now retries the failed batch as two smaller ones.
    """
    from winre import llm_client

    def fake_chat_result(messages, **kwargs):
        prompt = next((m.get("content") for m in messages
                       if m.get("role") == "user"), "")
        claims = json.loads(prompt.split("CLAIMS: ", 1)[-1])
        if len(claims) > 6:
            raise RuntimeError("LLM response missing content: finish_reason=length")
        reviews = [{"claim_id": item["id"], "verdict": "supported",
                    "locator_ids": [str(entry.get("locator"))
                                    for entry in (item.get("evidence") or [])]}
                   for item in claims]
        return {"content": "", "finish_reason": "tool_calls",
                "tool_calls": [{"function": {
                    "name": "submit_claim_reviews",
                    "arguments": json.dumps({"reviews": reviews})}}],
                "usage": {}, "model": "stub", "response_id": "stub",
                "error": None}

    monkeypatch.setattr(llm_client, "chat_result", fake_chat_result)
    monkeypatch.setattr(llm_client, "model_for", lambda role: "stub-model")
    monkeypatch.setattr(llm_client, "API_KEY", "stub-key")
    monkeypatch.setattr(llm_client, "BASE_URL", "http://127.0.0.1:9/v1")

    pack_root = _pack(tmp_path)
    res = reporting.build_report_v3(pack_root, review_claims=True)
    review = res.get("claim_review") or {}
    statuses = review.get("by_status") or {}
    assert "not-reviewed" not in statuses, review
    assert "verification-error" not in statuses, review
    reviewable = [claim for claim in (review.get("claims") or [])
                  if claim.get("status") != "unverifiable"]
    assert reviewable, "the fixture produced no reviewable claim"
    assert all(claim.get("status") == "supported" for claim in reviewable), review
    assert review.get("review_failures"), (
        "the truncated call must be recorded, not hidden")


def test_frida_selectors_are_only_built_for_api_names():
    """A basis label that is not an API must not become an @api selector.

    The dynamic verdict basis mixes API names with gate/unpack labels
    ("gate:drop:CreateFileW", "unpack:oep:0x8b2003", "packed-section:overlay").
    Building "@api=gate:drop:CreateFileW" produced a locator that resolves to no
    rows, and the audit refuses any claim with an unresolved locator
    (2026-10-24 dynamic run, claim C0053).
    """
    from winre.reporting import _raw_frida_refs

    refs = _raw_frida_refs(apis=["CreateFileW", "gate:drop:CreateFileW",
                                 "unpack:oep:0x8b2003", "packed-section:overlay",
                                 "VirtualAlloc"])
    assert refs == ["dynamic/frida_trace.jsonl#@api=CreateFileW",
                    "dynamic/frida_trace.jsonl#@api=VirtualAlloc"]
    assert _raw_frida_refs(event_refs=["a1b2c3"]) == [
        "dynamic/frida_trace.jsonl#@invocation_id=a1b2c3"]


def _pack_with_cli_strings(pack_root: Path, imports: list | None = None):
    """The s07 shape: switch-like strings in the quick strings evidence and
    a strings_tool result, with the packed stub's import table (or an
    import table the caller supplies)."""
    quick = json.loads(
        (pack_root / "quick" / "quick.json").read_text(encoding="utf-8"))
    quick["evidence"]["strings"] = {"strings": ["/Qmlv%uwjbwdh%fdkkjq%g`%wpk%"]}
    quick["evidence"]["strings_tool"] = {
        "strings": ["/Qmlv%uwjbwdh%fdkkjq%g`%wpk%"]}
    if imports is not None:
        quick["evidence"]["pe"]["imports"] = imports
    (pack_root / "quick" / "quick.json").write_text(
        json.dumps(quick), encoding="utf-8")
    return pack_root


def test_the_cli_switch_line_does_not_attribute_an_import_the_pack_lacks(tmp_path):
    """THE 2026-10-27 s07 control. The template asserted "switches from
    strings + GetCommandLine imports" for switch-like strings while the
    pack's imports were the UPX stub's LoadLibraryA/GetProcAddress only -
    GetCommandLine appeared nowhere in the evidence, the claim review
    correctly refused the claim, and the run went red on one insufficient
    claim of 58. The attribution must follow the import evidence."""
    pack_root = _pack_with_cli_strings(_pack(tmp_path))
    reporting.build_report_v3(pack_root, review_claims=False)
    markdown = (pack_root / "report" / "REPORT-TECHNICAL-v3.md").read_text(
        encoding="utf-8")
    assert "CLI-switch string candidates" in markdown, (
        "switch-like strings must still be reported, without the import claim")
    assert "GetCommandLine" not in markdown, (
        "the report attributed an import the evidence never showed "
        "(2026-10-27 s07 red run)")


def test_the_cli_switch_line_attributes_the_import_when_the_evidence_shows_it(tmp_path):
    """The other direction: when the imports evidence does show
    GetCommandLine and the reviewer can see that evidence, the attribution
    stays and cites the imports the reviewer can read."""
    pack_root = _pack_with_cli_strings(
        _pack(tmp_path),
        imports=[{"dll": "kernel32.dll",
                  "functions": ["GetCommandLineA", "lstrcatA"]}])
    reporting.build_report_v3(pack_root, review_claims=False)
    markdown = (pack_root / "report" / "REPORT-TECHNICAL-v3.md").read_text(
        encoding="utf-8")
    assert "switches from strings + GetCommandLine imports" in markdown
    locators = json.loads(
        (pack_root / "report" / "evidence-locators.json").read_text(
            encoding="utf-8")).get("locators") or {}
    assert any((meta or {}).get("reference") == "quick/quick.json#$.evidence.pe.imports"
               for meta in locators.values()), (
        "the import attribution must cite a locator the reviewer can resolve")


def test_the_decrypt_gate_line_cites_the_tool_result_it_reports(tmp_path):
    """2026-10-27 s09 static control: the "Decrypt gate: GATED" line cited
    quick/quick.json#$.evidence.decrypt_gate (never present - the result
    lives only in the deep history) and the whole-history wildcard (dropped
    as over-broad), so the line published with no locator and the claim
    review refused it as unverifiable. The line must cite the decrypt_gate
    tool's own history result."""
    pack_root = _pack(tmp_path)
    deep = json.loads(
        (pack_root / "deep" / "deep.json").read_text(encoding="utf-8"))
    deep["agent"]["history"].insert(0, {
        "tool": "decrypt_gate",
        "result": {"ok": True, "tool": "decrypt_gate", "status": "gate",
                   "taxonomy": "none", "import_count": 222,
                   "import_dlls": ["WS2_32.dll", "USER32.dll"]}})
    (pack_root / "deep" / "deep.json").write_text(
        json.dumps(deep), encoding="utf-8")
    reporting.build_report_v3(pack_root, review_claims=False)
    markdown = (pack_root / "report" / "REPORT-TECHNICAL-v3.md").read_text(
        encoding="utf-8")
    line = [ln for ln in markdown.splitlines()
            if "Decrypt gate: GATED" in ln]
    assert line, "the gated decrypt-gate line must still be reported"
    ids = re.findall(r"\[E(\d+)\]", line[0])
    assert ids, f"the decrypt-gate line published with no locator: {line[0]}"
    locators = json.loads(
        (pack_root / "report" / "evidence-locators.json").read_text(
            encoding="utf-8")).get("locators") or {}
    refs = [(locators.get(f"E{eid}") or {}).get("reference") for eid in ids]
    assert "deep/deep.json#$.agent.history[0].result" in refs, refs


def test_a_foreign_locator_id_is_discarded_not_invalidating(tmp_path, monkeypatch):
    """2026-10-27 s09 dbg C0006: the reviewer answered "supported" with the
    claim's own four locator ids plus one id belonging to the NEIGHBOUR
    claim, and the pipeline invalidated the whole decision. A foreign id
    carries no information about this claim: discard it and judge the
    decision on the ids that resolve - a supported verdict still needs at
    least one resolvable own locator plus valid quotes."""
    pack_root = _pack(tmp_path)
    from winre import llm_client

    def fake_chat_result(messages, **kwargs):
        prompt = next((m.get("content") for m in messages
                       if m.get("role") == "user"), "")
        claims = json.loads(prompt.split("CLAIMS: ", 1)[-1])
        reviews = []
        for index, item in enumerate(claims):
            own = [str(entry.get("locator"))
                   for entry in (item.get("evidence") or [])]
            if index == 0 and len(claims) > 1:
                neighbour = [str(entry.get("locator"))
                             for entry in (claims[1].get("evidence") or [])]
                foreign = next((x for x in neighbour if x not in own), None)
                if foreign:
                    own = own + [foreign]
            reviews.append({"claim_id": item["id"], "verdict": "supported",
                            "locator_ids": own})
        return {"content": "", "finish_reason": "tool_calls",
                "tool_calls": [{"function": {
                    "name": "submit_claim_reviews",
                    "arguments": json.dumps({"reviews": reviews})}}],
                "usage": {}, "model": "stub", "response_id": "stub",
                "error": None}

    monkeypatch.setattr(llm_client, "chat_result", fake_chat_result)
    monkeypatch.setattr(llm_client, "model_for", lambda role: "stub-model")
    monkeypatch.setattr(llm_client, "API_KEY", "stub-key")
    monkeypatch.setattr(llm_client, "BASE_URL", "http://127.0.0.1:9/v1")

    res = reporting.build_report_v3(pack_root, review_claims=True)
    review = res.get("claim_review") or {}
    statuses = review.get("by_status") or {}
    assert "invalid-review" not in statuses, review
    flagged = [c for c in (review.get("claims") or [])
               if c.get("unknown_locators")]
    assert flagged, "no claim recorded a discarded foreign locator id"
    for claim in flagged:
        assert claim.get("status") == "supported", claim


def test_the_summary_cites_the_dbg_fields_it_asserts(tmp_path):
    """2026-10-27 s09 dbg run 2: the attributed summary asserted prepass/OEP
    results with no citable locator behind them and the review judged the
    claim insufficient. The summary line must cite the agent fields that can
    back such assertions (set_evidence drops those a pack does not carry)."""
    pack_root = _pack(tmp_path)
    deep = json.loads(
        (pack_root / "deep" / "deep.json").read_text(encoding="utf-8"))
    deep["agent"]["unpack_prepass"] = {"ok": True,
                                       "method": "deterministic_prepass",
                                       "oep": "0x1400", "unpacked": True}
    deep["agent"]["packed_signal"] = {"sections": [".data"],
                                      "high_entropy": True}
    (pack_root / "deep" / "deep.json").write_text(
        json.dumps(deep), encoding="utf-8")
    reporting.build_report_v3(pack_root, review_claims=False)
    locators = json.loads(
        (pack_root / "report" / "evidence-locators.json").read_text(
            encoding="utf-8")).get("locators") or {}
    refs = {(m or {}).get("reference") for m in locators.values()}
    assert "deep/deep.json#$.agent.unpack_prepass" in refs, sorted(refs)[:8]
    assert "deep/deep.json#$.agent.packed_signal" in refs


def test_the_review_prompt_carries_the_attributed_summary_contract(
        tmp_path, monkeypatch):
    """2026-10-27 contract decision: a recorded-model-judgment claim is
    judged on (a) the judgment being genuinely recorded and (b) its factual
    assertions being covered by the cited evidence - not on whether the
    reviewer agrees with the recorded conclusion. Both s09 dbg refusals
    turned on exactly this distinction."""
    pack_root = _pack(tmp_path)
    captured = {}
    from winre import llm_client

    def fake_chat_result(messages, **kwargs):
        captured["prompt"] = next((m.get("content") for m in messages
                                   if m.get("role") == "user"), "")
        return {"content": "", "finish_reason": "stop", "tool_calls": [],
                "usage": {}, "model": "stub", "response_id": "stub",
                "error": None}

    monkeypatch.setattr(llm_client, "chat_result", fake_chat_result)
    monkeypatch.setattr(llm_client, "model_for", lambda role: "stub-model")
    monkeypatch.setattr(llm_client, "API_KEY", "stub-key")
    monkeypatch.setattr(llm_client, "BASE_URL", "http://127.0.0.1:9/v1")
    reporting.build_report_v3(pack_root, review_claims=True)
    prompt = captured.get("prompt") or ""
    assert "not an independent finding" in prompt
    assert "Refuse such a claim ONLY when the quoted judgment does not match" in prompt
    assert "directly contradicts the recorded judgment" in prompt
    assert "because some factual clause is not separately covered" in prompt
