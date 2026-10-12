"""A pull must never merge a new run into an old one.

`remote_dynamic` used to delete `META.json` and `memory/`, then pull fresh files
OVER whatever else was already in the stage directory. Everything else survived
from the previous run, so a partial pull - or a same-named file missing from this
run - left an old sibling beside a fresh META whose run nonce checked out.

The evidence was already on disk and nobody noticed: one pack held
`http_20261007_081151.txt`, `http_20261008_080635.txt` and
`http_20261008_091051.txt` side by side, plus `packets_20261007_*.pcap` next to
`packets_20261008_*.pcap`, while its META claimed a single fresh run.

The fix follows the contract `mark_dynamic_not_requested` already established:
the previous run is MOVED to previous_runs/, never deleted, and the pull lands
in an empty directory.
"""
import json
import pathlib

import pytest

from winre import evidence


SHA = "b" * 64


def _pack(tmp_path):
    return evidence.EvidencePack(tmp_path, SHA, mode="agentic").ensure()


def _fill_stage(pack, names):
    d = pack.stages["dynamic"]
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_text("previous-run", encoding="utf-8")


def test_the_previous_run_is_archived_not_deleted(tmp_path):
    pack = _pack(tmp_path)
    _fill_stage(pack, ["frida_trace.jsonl", "procmon.csv", "META.json"])
    out = evidence.archive_stage_for_fresh_run(pack)
    assert out["archived"] is True
    # only STAGE.json / SKIP.json are our own wrappers; META.json is real
    # evidence from the previous run and must be preserved with the rest
    assert out["preserved_artifacts"] == 3, (
        "our own wrappers must not be counted as evidence")
    dest = pack.root / out["preserved_previous"]
    assert (dest / "frida_trace.jsonl").is_file(), (
        "the previous run's evidence was destroyed instead of moved")
    assert (dest / "procmon.csv").is_file()


def test_the_stage_is_empty_after_the_archive(tmp_path):
    """The whole point: a fresh pull must have nothing to merge into."""
    pack = _pack(tmp_path)
    _fill_stage(pack, ["frida_trace.jsonl", "procmon.csv", "post_mortem.json",
                       "windbg_analysis.json", "network_intel.json"])
    evidence.archive_stage_for_fresh_run(pack)
    d = pack.stages["dynamic"]
    assert d.is_dir()
    assert list(d.iterdir()) == [], (
        f"the stage is not empty - a pull would merge into: "
        f"{[p.name for p in d.iterdir()]}")


def test_every_sibling_is_cleared_not_just_memory(tmp_path):
    """The old code cleared META.json and memory/ only. This names the files
    that used to survive, so a future 'optimisation' cannot quietly drop one."""
    pack = _pack(tmp_path)
    _fill_stage(pack, ["frida_trace.jsonl", "procmon.csv", "procmon.pml",
                       "post_mortem.json", "windbg_analysis.json",
                       "process_snapshot_pre.json", "network_intel.json"])
    (pack.stages["dynamic"] / "network_raw").mkdir()
    (pack.stages["dynamic"] / "network_raw" / "a.pcap").write_bytes(b"x")
    evidence.archive_stage_for_fresh_run(pack)
    stage = pack.stages["dynamic"]
    for name in ("frida_trace.jsonl", "procmon.csv", "procmon.pml",
                 "post_mortem.json", "windbg_analysis.json",
                 "process_snapshot_pre.json", "network_intel.json",
                 "network_raw"):
        assert not (stage / name).exists(), f"{name} survived the archive"


def test_a_failed_move_leaves_the_pack_alone(tmp_path, monkeypatch):
    """Never destroy: if the move fails the previous run must stay put, and the
    failure must be reported rather than swallowed."""
    import shutil
    pack = _pack(tmp_path)
    _fill_stage(pack, ["frida_trace.jsonl"])

    def _boom(*a, **k):
        raise OSError("disk on fire")

    monkeypatch.setattr(shutil, "move", _boom)
    out = evidence.archive_stage_for_fresh_run(pack)
    assert out["ok"] is False
    assert "disk on fire" in out["error"]
    assert (pack.stages["dynamic"] / "frida_trace.jsonl").is_file(), (
        "a failed move destroyed the previous run's evidence")


def test_an_empty_or_absent_stage_is_a_no_op(tmp_path):
    pack = _pack(tmp_path)
    out = evidence.archive_stage_for_fresh_run(pack)
    assert out["archived"] is False
    assert out["preserved_previous"] is None
    # a stage holding only our own wrappers is also "no evidence"
    d = pack.stages["dynamic"]
    d.mkdir(parents=True, exist_ok=True)
    for w in ("STAGE.json", "SKIP.json"):
        (d / w).write_text("{}", encoding="utf-8")
    out = evidence.archive_stage_for_fresh_run(pack)
    assert out["archived"] is False


def test_the_remote_driver_archives_before_it_pulls():
    """The call must sit between the detonation and the pull - if it moves after
    the pull it archives the new run instead of the old one."""
    src = pathlib.Path(__file__).resolve().parents[1] / "winre" / "remote_driver.py"
    text = src.read_text(encoding="utf-8")
    i = text.find("def remote_dynamic(")
    assert i != -1
    body = text[i:text.find("\ndef ", i + 10)]
    arch = body.find("archive_stage_for_fresh_run(pack)")
    pull = body.find("scp_from(cfg")
    assert arch != -1, "remote_dynamic does not archive the stage"
    assert pull != -1, "remote_dynamic does not pull"
    assert arch < pull, (
        "the archive runs AFTER the pull - it would archive the new run")
    # and the stale-delete shape must be gone
    assert 'stale.unlink()' not in body, (
        "the old META-only delete is still there")
