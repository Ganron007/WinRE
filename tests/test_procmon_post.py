from __future__ import annotations

import json
from pathlib import Path

from winre.procmon_post import build_procmon_report


def test_procmon_enrichment_preserves_summary_status_contract(tmp_path: Path):
    (tmp_path / "procmon.csv").write_text(
        "Time of Day,Process Name,PID,Operation,Path,Result,Detail\n"
        '19:00:00,sample.exe,4242,WriteFile,'
        'C:\\Users\\Public\\payload.bin,SUCCESS,bytes=64\n',
        encoding="utf-8",
    )

    report = build_procmon_report(tmp_path)

    assert report["status"] == "ok"
    assert report["ok"] is True
    stored = json.loads((tmp_path / "procmon_summary.json").read_text(
        encoding="utf-8"))
    assert stored["status"] == "ok"
    assert stored["rows_scanned"] == 1


def test_procmon_enrichment_distinguishes_missing_and_empty_inputs(tmp_path: Path):
    missing = build_procmon_report(tmp_path)
    assert missing["status"] == "missing"
    assert missing["ok"] is False

    (tmp_path / "procmon.csv").write_text(
        "Time of Day,Process Name,PID,Operation,Path,Result,Detail\n",
        encoding="utf-8",
    )
    empty = build_procmon_report(tmp_path)
    assert empty["status"] == "error"
    assert empty["ok"] is False
