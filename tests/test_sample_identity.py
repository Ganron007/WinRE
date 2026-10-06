"""The sample hash must never be the mode.

Found by reading a real pack during the P1 campaign (2026-10-06): a pack root
is `logs/<sha>/<mode>`, so `pack_root.name` is "static"/"agentic", and code
that assumed otherwise wrote `"sha256": "static"` into intake.json and into
every report header. A report that misstates the sample's hash silently
poisons any third-party ingestion keyed on SHA256 - which is precisely the
contract docs/REVAI-BRIDGE.md advertises.
"""
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SHA = "bc12d7052e6cfce8f16625ca8b88803cd4e58356eb32fe62667336d4dee708a3"


def test_sha_of_handles_both_pack_shapes(tmp_path):
    from winre.evidence import sha_of
    assert sha_of(tmp_path / SHA) == SHA
    for mode in ("static", "agentic"):
        assert sha_of(tmp_path / SHA / mode) == SHA, (
            f"a mode-scoped pack root ends in {mode!r}; the sha must still be "
            "recovered from the parent")


def test_no_module_derives_a_sha_from_the_pack_path():
    """The mistake is silent and easy to reintroduce; ban the pattern."""
    offenders = []
    for p in sorted(REPO.glob("winre/**/*.py")):
        src = p.read_text(encoding="utf-8")
        for lineno, line in enumerate(src.splitlines(), 1):
            code = line.split("#", 1)[0]
            if "root.name" not in code:
                continue
            # a sha may never come from a path component
            if ("sha" in code.lower() and "=" in code
                    and "root.name" in code.split("=", 1)[1]):
                offenders.append(f"{p.relative_to(REPO).as_posix()}:{lineno}")
    assert not offenders, (
        "these lines assign a sha from a path component, which is the MODE for "
        f"a mode-scoped pack: {offenders}. Use EvidencePack.sha or "
        "evidence.sha_of(pack_root).")


@pytest.mark.parametrize("mode", ["static", "agentic"])
def test_generated_pack_records_the_real_sha(tmp_path, mode):
    """End-to-end: intake.json and the report must carry the actual hash."""
    from winre import evidence, pipeline, reporting
    pack = evidence.EvidencePack(tmp_path / "logs", SHA, mode=mode).ensure()

    # behaviour, not bytecode: intake reads 5 bytes, so just run it
    sample = tmp_path / "s01.exe"
    sample.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    pipeline._intake(sample, pack)
    intake = json.loads(
        (pack.stages["intake"] / "intake.json").read_text(encoding="utf-8"))
    assert intake["sha256"] == SHA, (
        f"intake.json recorded {intake['sha256']!r} as the sample hash; for a "
        f"{mode!r} pack that is the MODE, not the hash")
    assert intake["format"] == "pe"

    # and the report header must render it
    (pack.stages["quick"]).mkdir(parents=True, exist_ok=True)
    (pack.stages["quick"] / "quick.json").write_text(
        json.dumps({"verdict": "malicious"}), encoding="utf-8")
    (pack.stages["deep"]).mkdir(parents=True, exist_ok=True)
    (pack.stages["deep"] / "deep.json").write_text(
        json.dumps({"verdict": "malicious", "confidence": "high",
                    "source": "llm_judge"}), encoding="utf-8")
    (pack.root / "report").mkdir(parents=True, exist_ok=True)
    (pack.root / "yara").mkdir(parents=True, exist_ok=True)
    reporting.generate_all(pack.root)
    md = (pack.root / "report" / "REPORT-TECHNICAL-v3.md").read_text(
        encoding="utf-8")
    assert f"`{SHA}`" in md, (
        "REPORT-TECHNICAL-v3.md must print the real sample hash")
    assert f"`{mode}`**" not in md, (
        "the report header is printing the MODE where the hash belongs")
    for other in ("AUDIT-REPORT.md", "EVIDENCE-BUNDLE.md"):
        text = (pack.root / "report" / other).read_text(encoding="utf-8")
        assert f"`{SHA}" in text or SHA[:16] in text, (
            f"{other} must identify the sample by hash")


def test_shipped_packs_are_not_mislabelled():
    """Any pack already on disk must not carry a mode in its sha256 field."""
    logs = REPO / "logs"
    if not logs.is_dir():
        pytest.skip("no packs on this host")
    bad = []
    for p in logs.glob("*/[a-z]*/*/intake/intake.json"):
        try:
            got = json.loads(p.read_text(encoding="utf-8")).get("sha256", "")
        except Exception:
            continue
        if got in ("static", "agentic"):
            bad.append(str(p.relative_to(logs)))
    assert not bad, f"packs with the mode in intake.sha256: {bad}"