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
