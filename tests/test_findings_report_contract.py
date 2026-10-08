"""W3: the findings producer and its consumers must agree, end to end.

RevAI's 2026-10-08 review: findings.build writes `<mode>/findings.json`, but
reporting.py read `<mode>/dynamic/findings.json`. For every mode the report
emitted "the analysis plane did not run" over a pack that had findings.

That shipped because every test checked ONE side:
  * test_findings asserted the WRITER writes <mode>/findings.json
  * test_compose_reads_the_mode_root was a STRING GREP on compose.py

A string grep on a reader is structurally incapable of noticing that the reader
disagrees with the writer, because both sides are mine and both read correctly
in isolation. So these tests do the thing the grep could not: build a real pack,
run the real producer, and let the real report consume it.
"""
import json
import pathlib

import pytest

from winre import findings as F
from winre import reporting


SHA = "e" * 64
FINDINGS_STEM = "No findings.json was produced"


def _pack(tmp_path, *, with_findings, mode="dynamic"):
    """A minimal but REAL pack: the producer's own output plus the stage
    evidence the reporter needs to believe a detonation happened."""
    pack_root = tmp_path / SHA / mode
    stage = pack_root / "dynamic"
    stage.mkdir(parents=True, exist_ok=True)
    (pack_root / "report").mkdir(parents=True, exist_ok=True)
    (stage / "META.job.json").write_text(
        json.dumps({"sample_pid": 5156, "window": {"effective_s": 150},
                    "frida_events": 91, "loader": "direct"}), encoding="utf-8")
    (stage / "frida_summary.json").write_text(
        json.dumps({"top_apis": [["VirtualAlloc", 1], ["CreateRemoteThread", 1]]}),
        encoding="utf-8")
    (stage / "procmon_summary.json").write_text("{}", encoding="utf-8")
    (stage / "network_intel.json").write_text("{}", encoding="utf-8")
    (stage / "post_mortem.json").write_text("{}", encoding="utf-8")
    (stage / "windbg_analysis.json").write_text("{}", encoding="utf-8")
    # dynamic/META.json is the STAGE metadata and legitimately lives in the
    # stage dir - only the mode-level findings.json belongs at the mode root.
    (stage / "META.json").write_text(
        json.dumps({"sample_pid": 5156, "frida_events": 91, "ok": True}),
        encoding="utf-8")
    for name in ("STAGE.json",):
        (stage / name).write_text(json.dumps({"ok": True}), encoding="utf-8")
    if with_findings:
        F.build("dynamic", pack_root, sha=SHA)      # the REAL producer
    return pack_root


def _report(pack_root):
    """Run the REAL report builder and read the markdown it actually wrote."""
    res = reporting.build_report_v3(pack_root)
    assert res.get("ok"), res
    return (pack_root / "report" / "REPORT-TECHNICAL-v3.md").read_text(
        encoding="utf-8")


def test_the_report_consumes_the_file_the_producer_writes(tmp_path):
    """THE control. Producer writes, report reads the same file, and the
    report must not claim the analysis plane never ran."""
    pack_root = _pack(tmp_path, with_findings=True)
    assert (pack_root / "findings.json").is_file(), (
        "producer did not write the mode-root findings.json")

    md = _report(pack_root)
    assert FINDINGS_STEM not in md, (
        "the report claims the analysis plane did not run, but the producer "
        "wrote findings to the mode root. The reader and the writer disagree - "
        "this is W3 exactly.")


def test_a_pack_with_no_findings_still_reports_the_gap_honestly(tmp_path):
    """The negative direction: if nothing was produced, the report must SAY so.
    Fixing the reader must not turn a genuine gap into a silent success."""
    pack_root = _pack(tmp_path, with_findings=False)
    md = _report(pack_root)
    assert FINDINGS_STEM in md


def test_no_consumer_reads_the_stage_dir_for_findings():
    """Every findings consumer must read the mode root. Checked by BEHAVIOUR
    above; this asserts the stage-dir path is gone from the codebase so the
    two cannot both exist."""
    repo = pathlib.Path(__file__).resolve().parents[1] / "winre"
    offenders = []
    for py in repo.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        if 'pack_root / "dynamic" / "findings.json"' in text:
            offenders.append(py.name)
        if '/ "dynamic" / "findings.json"' in text and py.name != "findings.py":
            offenders.append(f"{py.name}:stage-dir-findings")
    assert not offenders, (
        f"these read findings from the stage dir instead of the mode root: "
        f"{offenders}")


def test_findings_land_at_the_mode_root_not_the_stage_dir(tmp_path):
    """The producer half of the same contract, asserted together with the
    consumer above so the two cannot drift apart again."""
    pack_root = _pack(tmp_path, with_findings=True)
    assert (pack_root / "findings.json").is_file()
    assert not (pack_root / "dynamic" / "findings.json").exists(), (
        "findings must not also be written into the stage dir - a second "
        "copy is what let the two locations drift unnoticed")