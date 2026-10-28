"""UI wiring controls (2026-10-29, before the operator's manual UI pass).

The manual 'report' stage used to call pipeline._report ALONE: report.json
updated while the rendered REPORT-TECHNICAL-v3.md and the claim review kept
describing the previous report, and the composite selection was dropped
(_report ran without the composition). The stage now runs
pipeline.rebuild_report - findings -> composite -> report -> rendered
markdown + claim review -> manifests -> audit - the pipeline tail, so a
manual rebuild leaves the pack exactly as a fresh run would have written
it.
"""
from __future__ import annotations

import hashlib
import json

from winre import llm_client
from winre.evidence import EvidencePack
from winre.pipeline import rebuild_report

SHA = "c" * 64


def _stub_review(monkeypatch):
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


def _pack(tmp_path):
    pack = EvidencePack(tmp_path, SHA, mode="static").ensure()
    (pack.root / "quick").mkdir(parents=True, exist_ok=True)
    (pack.root / "deep").mkdir(parents=True, exist_ok=True)
    (pack.root / "META.json").write_text(json.dumps({
        "sha256": SHA, "mode": "static", "pack_mode": "static",
        "run_id": "d" * 32, "status": "completed",
    }), encoding="utf-8")
    (pack.root / "quick" / "quick.json").write_text(json.dumps({
        "evidence": {
            "capa": {"ok": True, "tool": "capa", "total": 1,
                     "capabilities": [{"name": "packed with UPX",
                                       "attack": ["T1027.002"], "count": 1}]},
            "pe": {"machine": "0x14c", "entrypoint": 4096, "signed": False,
                   "compile_ts": 1786354838, "imports": [], "sections": []},
        },
        "verdict": "suspicious",
    }), encoding="utf-8")
    (pack.root / "deep" / "deep.json").write_text(json.dumps({
        "engine": "static_deterministic",
        "verdict": "suspicious", "confidence": "medium",
        "source": "static_deterministic",
        "key_evidence": ["packer-family yara (info): CADRE_v2_test"],
        "agent": {"source": "static_deterministic", "history": [],
                  "verdict": {"verdict": "suspicious",
                              "confidence": "medium", "summary": "s"}},
    }), encoding="utf-8")
    return pack


def test_manual_report_rebuild_rederives_the_whole_tail(tmp_path,
                                                        monkeypatch):
    _stub_review(monkeypatch)
    pack = _pack(tmp_path)
    rebuild_report(pack, SHA)
    md_bytes = (pack.root / "report" / "REPORT-TECHNICAL-v3.md").read_bytes()
    review = json.loads(
        (pack.root / "report" / "claim-review.json").read_text(
            encoding="utf-8"))
    # the review binds to the report as rendered NOW, not to a previous one
    # (raw bytes: a CRLF translation would break the digest on Windows)
    assert review.get("report_sha256") == hashlib.sha256(md_bytes).hexdigest()
    composite = json.loads((pack.root / "composite.json").read_text(
        encoding="utf-8"))
    assert composite.get("level"), "the rebuild must publish a composite"
    report = json.loads((pack.root / "report" / "report.json").read_text(
        encoding="utf-8"))
    # THE wiring invariant the old code violated: _report alone ran without
    # the composition, so the rebuilt report carried no composite selection
    assert report.get("composite"), (
        "the rebuilt report must carry the composite selection")
    assert report.get("selected_verdict_source") == "mode-composite"
    # the audit was re-run against the rebuilt pack and binds to the same
    # rendered report the review bound to
    audit = json.loads((pack.root / "audit.json").read_text(
        encoding="utf-8"))
    audit_review = audit.get("report_claim_review") or {}
    assert audit_review.get("report_sha256") == hashlib.sha256(
        md_bytes).hexdigest()


def test_manual_report_rebuild_regenerates_deleted_report_artifacts(
        tmp_path, monkeypatch):
    """A pack whose rendered report is gone must be fully re-derived by the
    manual stage - _report alone wrote report.json and left the rendered
    markdown and the claim review missing."""
    _stub_review(monkeypatch)
    pack = _pack(tmp_path)
    rebuild_report(pack, SHA)
    (pack.root / "report" / "REPORT-TECHNICAL-v3.md").unlink()
    rebuild_report(pack, SHA)
    md_bytes = (pack.root / "report" / "REPORT-TECHNICAL-v3.md").read_bytes()
    review = json.loads(
        (pack.root / "report" / "claim-review.json").read_text(
            encoding="utf-8"))
    assert review.get("report_sha256") == hashlib.sha256(md_bytes).hexdigest()
    assert "packed with UPX" in md_bytes.decode("utf-8", errors="replace"), (
        "the regenerated markdown must render the current evidence")
