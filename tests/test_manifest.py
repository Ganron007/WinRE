"""The artifact manifest — design §8.

Two things it must never do:

  * encode a missing capture as an empty successful one. A source that was asked
    for and produced nothing is `partial` or `failed` with a reason; a source
    that was not asked for is `not_requested`. Neither is ever `complete`.
  * attribute evidence to the wrong collection domain. A pcap captured off-box
    and a registry key read by a removable hook are not the same class of
    observation, and the manifest is the only place that difference is recorded.

Every path in `_PATH_MAP` was taken from an inventory of what actually appears
in the packs on disk, and a test asserts the classification is COMPLETE against
that inventory — a file we do not recognise is the one a reader needs to see.
"""
import json
import pathlib

import pytest

from winre import manifest as M

SHA = "c" * 64


def _stage(tmp_path, files=()):
    d = tmp_path / "stage"
    d.mkdir(parents=True, exist_ok=True)
    for rel, body in files:
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return d


def _full(tmp_path, **kw):
    files = [
        ("frida_trace.jsonl", '{"api":"CreateFileW"}\n'),
        ("frida_summary.json", "{}"),
        ("procmon.csv", "Time,Process\n"),
        ("procmon_summary.json", "{}"),
        ("network_raw/a.pcap", "pcap"),
        ("network.json", "{}"),
        ("memory/sample_early.dmp", "MDMP"),
        ("post_mortem.json", "{}"),
        ("process_snapshot_pre.json", "{}"),
        ("malcat-triage.json", "{}"),
        ("META.job.json", "{}"),
    ]
    kw.setdefault("requested", {"frida": True, "procmon": True, "memory": True,
                                "network": True, "process_snapshot": True,
                                "malcat": True, "job": True})
    return M.write_manifest(_stage(tmp_path, files), run_id="r1",
                            sha256=SHA, mode="agentic", meta={"ok": True}, **kw)


# ------------------------------------------------------- the honesty rule

def test_a_source_that_produced_nothing_is_not_complete(tmp_path):
    m = M.build_manifest(_stage(tmp_path, [("procmon.csv", "x")]),
                         run_id="r", sha256=SHA,
                         requested={"procmon": True, "frida": True})
    assert m["coverage"]["procmon"]["status"] == "complete"
    # frida was requested and produced nothing
    assert m["coverage"]["frida"]["status"] == "partial"
    assert "no files" in m["coverage"]["frida"]["reason"]


def test_a_source_that_was_never_requested_is_not_requested(tmp_path):
    m = M.build_manifest(_stage(tmp_path), run_id="r", sha256=SHA,
                         requested={"frida": True})
    for src in ("procmon", "network", "memory"):
        assert m["coverage"][src]["status"] == "not_requested", src


def test_a_recorded_error_makes_a_source_failed_not_partial(tmp_path):
    m = M.build_manifest(_stage(tmp_path, [("procmon.csv", "x")]),
                         run_id="r", sha256=SHA,
                         requested={"frida": True},
                         meta={"errors": {"frida": "tracer died on spawn"}})
    assert m["coverage"]["frida"]["status"] == "failed"
    assert "tracer died" in m["coverage"]["frida"]["reason"]


def test_a_source_missing_its_primary_output_is_partial(tmp_path):
    """The trace file exists but the raw trace does not: not complete."""
    m = M.build_manifest(_stage(tmp_path, [("frida_summary.json", "{}")]),
                         run_id="r", sha256=SHA,
                         requested={"frida": True})
    assert m["coverage"]["frida"]["status"] == "partial"
    assert "frida_trace.jsonl" in m["coverage"]["frida"]["reason"]


def test_files_from_a_source_imply_it_was_requested(tmp_path):
    """A source whose output is plainly there must never read not_requested."""
    m = M.build_manifest(_stage(tmp_path, [("windbg_analysis.json", "{}")]),
                         run_id="r", sha256=SHA, requested={})
    assert m["coverage"]["windbg"]["status"] == "complete"


def test_incomplete_sources_names_every_gap(tmp_path):
    d = _stage(tmp_path, [("procmon.csv", "x")])
    M.write_manifest(d, run_id="r", sha256=SHA,
                     requested={"procmon": True, "network": True})
    gaps = dict(M.incomplete_sources(d))
    assert "network" in gaps, gaps
    assert gaps["network"].startswith("partial")
    assert "procmon" not in gaps, "a source that ran must not be a gap"


# ------------------------------------------------------- classification

@pytest.mark.parametrize("rel,source,domain", [
    ("frida_trace.jsonl", "frida", M.IN_GUEST),
    ("frida_summary.json", "frida", M.DERIVED),
    ("procmon.csv", "procmon", M.IN_GUEST),
    ("behavior_timeline.csv", "procmon", M.DERIVED),
    ("memory/sample_early.dmp", "memory", M.IN_GUEST),
    ("post_mortem.json", "memory", M.IN_GUEST),
    ("network_raw/a.pcap", "network", M.IN_GUEST),
    ("network_intel.json", "network", M.DERIVED),
    ("windbg_analysis.json", "windbg", M.IN_GUEST),
    ("x64dbg/dump/probe.dmp", "x64dbg", M.IN_GUEST),
    ("malcat-triage.json", "malcat", M.IN_GUEST),
    ("off_box/guest.pcapng", "external_capture", M.OFF_BOX),
    ("ANALYST-NEXT.md", "analyst_next", M.DERIVED),
])
def test_known_paths_are_attributed(rel, source, domain):
    s, d, k = M.classify(rel)
    assert (s, d) == (source, domain), rel


def test_classification_is_complete_over_the_real_inventory():
    """Every path that actually occurs in the packs on disk must be attributed.

    An `unclassified` file is recorded but not attributed to a source or a
    domain, which is the one case a reader cannot act on.
    """
    repo = pathlib.Path(__file__).resolve().parents[1]
    logs = repo / "logs"
    if not logs.is_dir():
        pytest.skip("no packs in logs/")
    stages = [p for p in logs.rglob("dynamic")
              if p.is_dir() and not (p / "deep").is_dir()
              and ((p / "procmon.csv").is_file()
                   or (p / "frida_trace.jsonl").is_file())]
    assert stages, "no real stage dirs found"
    bad = set()
    for st in stages:
        for f in st.rglob("*"):
            if not f.is_file():
                continue
            rel = str(f.relative_to(st)).replace("\\", "/")
            if rel in M._WRAPPERS:
                continue
            if M.classify(rel)[0] == "unclassified":
                bad.add(rel)
    assert not bad, f"unattributed evidence paths: {sorted(bad)[:10]}"


def test_our_own_wrappers_are_not_evidence(tmp_path):
    d = _stage(tmp_path, [("STAGE.json", "{}"), ("SKIP.json", "{}"),
                          ("META.json", "{}"), ("manifest.json", "{}")])
    m = M.build_manifest(d, run_id="r", sha256=SHA)
    assert m["artifact_count"] == 0


def test_an_unknown_file_is_recorded_not_dropped(tmp_path):
    d = _stage(tmp_path, [("some_future_sensor.out", "x")])
    m = M.build_manifest(d, run_id="r", sha256=SHA)
    arts = {a["path"]: a for a in m["artifacts"]}
    assert "some_future_sensor.out" in arts, "an unknown file was dropped"
    assert arts["some_future_sensor.out"]["source"] == "unclassified"


# ------------------------------------------------------- hashing

def test_every_artifact_carries_a_hash_or_a_reason(tmp_path):
    m = _full(tmp_path)
    for a in m["artifacts"]:
        assert a["sha256"] or a["hash_skipped_reason"], a["path"]
        if a["sha256"]:
            assert len(a["sha256"]) == 64


def test_a_hash_is_real_not_a_placeholder(tmp_path):
    import hashlib
    d = _stage(tmp_path, [("frida_trace.jsonl", "hello\n")])
    m = M.build_manifest(d, run_id="r", sha256=SHA)
    a = m["artifacts"][0]
    # Hash the file as it is ON DISK. write_text translates newlines on Windows,
    # so the bytes are b"hello\r\n" - a hash of the string we passed in would
    # be a placeholder, which is exactly the defect this guards.
    on_disk = (d / "frida_trace.jsonl").read_bytes()
    assert on_disk == b"hello\r\n", "the fixture did not write what it claims"
    assert a["sha256"] == hashlib.sha256(on_disk).hexdigest()
    assert a["size_bytes"] == len(on_disk)


def test_a_file_over_the_cap_is_recorded_as_unhashed_with_a_reason(tmp_path,
                                                                  monkeypatch):
    monkeypatch.setattr(M, "HASH_CAP_BYTES", 4)
    d = _stage(tmp_path, [("frida_trace.jsonl", "much longer than four bytes")])
    m = M.build_manifest(d, run_id="r", sha256=SHA)
    a = m["artifacts"][0]
    assert a["sha256"] is None
    assert "exceeds" in a["hash_skipped_reason"]
    assert a["size_bytes"] > 4, "the size is still recorded"


def test_hashing_can_be_disabled_and_says_so(tmp_path):
    m = _full(tmp_path, hash_files=False)
    assert all(a["sha256"] is None for a in m["artifacts"])
    assert all(a["hash_skipped_reason"] == "hashing disabled"
               for a in m["artifacts"])


# ------------------------------------------------------- ids and shape

def test_artifact_ids_are_unique(tmp_path):
    m = _full(tmp_path)
    ids = [a["id"] for a in m["artifacts"]]
    assert len(ids) == len(set(ids))


def test_artifact_ids_are_stable_across_rebuilds(tmp_path):
    d = _stage(tmp_path, [("frida_trace.jsonl", "x"),
                          ("procmon.csv", "y")])
    a = M.build_manifest(d, run_id="r", sha256=SHA)
    b = M.build_manifest(d, run_id="r", sha256=SHA)
    assert [x["id"] for x in a["artifacts"]] == [x["id"] for x in b["artifacts"]]


def test_the_manifest_records_the_run_it_belongs_to(tmp_path):
    m = _full(tmp_path)
    assert m["run_id"] == "r1"
    assert m["sample_sha256"] == SHA
    assert m["schema"] == M.SCHEMA


def test_the_manifest_note_says_coverage_is_not_trust(tmp_path):
    """A reader must not mistake 'complete' for 'trustworthy'."""
    m = _full(tmp_path)
    assert "untrusted data in every domain" in m["note"]


def test_write_manifest_never_raises(tmp_path, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("disk gone")
    monkeypatch.setattr(M, "build_manifest", _boom)
    out = M.write_manifest(tmp_path, run_id="r")
    assert out["ok"] is False
    assert "disk gone" in out["error"]


# ------------------------------------------------------- the wiring

def test_the_remote_driver_writes_the_manifest_after_the_pull():
    """It must sit after the pull (so it describes what arrived) and after the
    analysis steps (so the derived files are covered too)."""
    src = (pathlib.Path(__file__).resolve().parents[1] / "winre"
           / "remote_driver.py").read_text(encoding="utf-8")
    i = src.find("def remote_dynamic(")
    body = src[i:src.find("\ndef ", i + 10)]
    pull = body.find("scp_from(cfg")
    man = body.find("write_manifest(")
    assert pull != -1 and man != -1
    assert pull < man, "the manifest is written before the pull"


def test_the_findings_plane_reports_collection_gaps():
    """A missing capture must reach the limitations, not just the manifest."""
    src = (pathlib.Path(__file__).resolve().parents[1] / "winre"
           / "findings.py").read_text(encoding="utf-8")
    assert "incomplete_sources(" in src
    assert "incomplete evidence collection" in src
