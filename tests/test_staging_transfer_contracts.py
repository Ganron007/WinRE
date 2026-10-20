"""Offline failure contracts: run identity and evidence transfer (G7 / H1 / H6).

These are the remaining-verification controls from the improvement-plan
crosswalk. The source corrections were already written (staging refusal,
archive refusal, transfer inventory, nonce freshness, debugger gate); what the
crosswalk still demanded is PROOF that the failure shapes fail closed:

  G7  - a failed/partial upload, a destination collision, a stale same-name
        legacy sample or a mid-upload mutation must refuse BEFORE any tool,
        debugger or detonation can consume bytes, and land as a visible red
        record in the pack.
  H1  - ordinary static/agentic work must issue no target-load/start/step RPC;
        a debugger tool without opt-in refuses and falls back to static.
  H6  - an archive failure must refuse detonation; inventory/nonce/identity
        disagreements must never be promoted as this run's evidence.

Only the transport seam is mocked (ssh_ps / scp_to / remote_sha256); every
assertion runs the real production writer or reader. run_nonce and
_inventory_diff are exercised unmocked.
"""
import json
import subprocess
import pathlib

import pytest

from winre import evidence
from winre import remote_driver
from winre import run_nonce
from winre.evidence import EvidencePack

SHA = "a" * 64
OTHER = "b" * 64
RUN = "0123456789abcdef0123456789abcdef"
RUN2 = "fedcba9876543210fedcba9876543210"


class FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def pack(tmp_path):
    return EvidencePack(tmp_path, SHA, mode="static").ensure()


@pytest.fixture
def sample(tmp_path) -> pathlib.Path:
    """A real on-disk file whose SHA-256 is known."""
    p = tmp_path / "s1.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    return p


def _sha_of(p: pathlib.Path) -> str:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _no_transport(monkeypatch):
    """Any unexpected transport use inside a negative control fails the test."""
    def boom(name):
        def _f(*a, **k):
            raise AssertionError(f"transport seam {name} must not be touched")
        return _f
    monkeypatch.setattr(remote_driver, "ssh_ps", boom("ssh_ps"))
    monkeypatch.setattr(remote_driver, "scp_to", boom("scp_to"))
    monkeypatch.setattr(remote_driver, "remote_sha256", boom("remote_sha256"))


# ---------------------------------------------------------------- G7: identity


def test_invalid_sha_or_run_id_is_refused_before_any_transport(
        tmp_path, monkeypatch):
    _no_transport(monkeypatch)
    p = tmp_path / "s1.exe"
    p.write_bytes(b"x")
    with pytest.raises(ValueError):
        remote_driver.stage_remote_sample({}, p, "zz" * 32, RUN)
    with pytest.raises(ValueError):
        remote_driver.stage_remote_sample(
            {}, p, _sha_of(p), "not-a-nonce")


def test_destination_collision_refuses_before_upload(sample, monkeypatch):
    """The single fatal shape of G7's original defect: previous bytes already
    sitting under the name this run would use must abort the run, not get
    silently replaced and analysed."""
    _no_transport(monkeypatch)
    monkeypatch.setattr(
        remote_driver, "ssh_ps",
        lambda *a, **k: FakeResult(returncode=1, stdout="",
                                   stderr="run staging destination exists"))
    with pytest.raises(RuntimeError, match="could not be prepared"):
        remote_driver.stage_remote_sample({}, sample, _sha_of(sample), RUN)


def test_upload_failure_refuses_and_lands_red_in_the_pack(
        sample, pack, monkeypatch):
    remote = remote_driver._remote_staging_destination(
        sample, _sha_of(sample), RUN)

    def fake_scp(cfg, local, dest):
        assert dest == remote
        raise RuntimeError("scp to flare failed: connection dropped")

    monkeypatch.setattr(
        remote_driver, "ssh_ps",
        lambda *a, **k: FakeResult(returncode=0,
                                   stdout="STAGING_READY"))
    monkeypatch.setattr(remote_driver, "scp_to", fake_scp)

    with pytest.raises(RuntimeError, match="scp to flare failed"):
        remote_driver.stage_remote_sample({}, sample, _sha_of(sample), RUN)

    # the caller contract: the exception is turned into a visible red record
    try:
        remote_driver.stage_remote_sample({}, sample, _sha_of(sample), RUN)
    except RuntimeError as e:
        out = remote_driver._remote_staging_abort(
            pack, _sha_of(sample), RUN, str(e), remote)
    assert out["aborted"] is True
    staged = pack.read("intake", "REMOTE-STAGING.json")
    assert staged["ok"] is False and "staging rejected" in staged["error"]
    audit = json.loads((pack.root / "audit.json").read_text(encoding="utf-8"))
    assert audit["truly_green"] is False and audit["aborted"] is True
    assert audit["unmet_expectations"]
    root_meta = json.loads((pack.root / "META.json").read_text(encoding="utf-8"))
    assert root_meta["aborted"] is True and root_meta["truly_green"] is False


def test_remote_hash_mismatch_refuses(sample, monkeypatch):
    monkeypatch.setattr(
        remote_driver, "ssh_ps",
        lambda *a, **k: FakeResult(returncode=0, stdout="STAGING_READY"))
    monkeypatch.setattr(remote_driver, "scp_to", lambda *a, **k: None)
    monkeypatch.setattr(
        remote_driver, "remote_sha256", lambda *a, **k: OTHER)
    with pytest.raises(RuntimeError, match="remote sample hash mismatch"):
        remote_driver.stage_remote_sample({}, sample, _sha_of(sample), RUN)


def test_local_mutation_between_hash_checks_refuses(sample, monkeypatch):
    """The sample must not be replaceable while the upload is in flight."""
    real_sha = _sha_of(sample)
    calls = []

    def fake_sha256_file(p):
        calls.append(1)
        return real_sha if len(calls) == 1 else OTHER

    import winre.evidence as ev
    monkeypatch.setattr(ev, "sha256_file", fake_sha256_file)
    monkeypatch.setattr(
        remote_driver, "ssh_ps",
        lambda *a, **k: FakeResult(returncode=0, stdout="STAGING_READY"))
    monkeypatch.setattr(remote_driver, "scp_to", lambda *a, **k: None)
    # the VM still holds the correctly-paired bytes; the LOCAL file then moves
    monkeypatch.setattr(remote_driver, "remote_sha256",
                        lambda *a, **k: real_sha)
    with pytest.raises(RuntimeError,
                       match="local sample changed while it was being"):
        remote_driver.stage_remote_sample({}, sample, real_sha, RUN)
    assert len(calls) == 2


def test_staging_destination_is_run_specific(sample):
    """"Stale same-name bytes" is structurally impossible: two runs of the
    SAME sample hash must not share a destination directory."""
    a = remote_driver._remote_staging_destination(sample, SHA, RUN)
    b = remote_driver._remote_staging_destination(sample, SHA, RUN2)
    assert a != b
    assert a.startswith(f"C:/samples/winre/{SHA}/")
    assert a.endswith("/sample.exe") and f"/{RUN}/" in a


def test_verified_staging_success_records_the_hash_and_path(sample, monkeypatch):
    monkeypatch.setattr(
        remote_driver, "ssh_ps",
        lambda *a, **k: FakeResult(returncode=0, stdout="STAGING_READY"))
    monkeypatch.setattr(remote_driver, "scp_to", lambda *a, **k: None)
    # the VM really holds these bytes
    monkeypatch.setattr(
        remote_driver, "remote_sha256", lambda *a, **k: _sha_of(sample))
    real_sha = _sha_of(sample)
    out = remote_driver.stage_remote_sample({}, sample, real_sha, RUN)
    assert out["ok"] is True
    assert out["remote_sha256"] == real_sha
    assert out["remote_path"] == remote_driver._remote_staging_destination(
        sample, real_sha, RUN)


def _stage_record(pack, remote_path: str, sha: str = SHA):
    pack.write("intake", "REMOTE-STAGING.json", {
        "schema": "winre.remote-staging/v1", "ok": True, "run_id": RUN,
        "sha256": sha, "remote_sha256": sha, "remote_path": remote_path,
        "original_name": "s1.exe"})


def test_stale_legacy_sample_refuses(sample, pack, monkeypatch):
    """"The G7 defect itself: stale VM bytes under the legacy name with a
    fresh local hash. Identity is the hash, so this must be refused."""
    monkeypatch.setattr(
        remote_driver, "remote_sha256", lambda *a, **k: OTHER)
    with pytest.raises(RuntimeError, match="remote sample identity mismatch"):
        remote_driver._verified_remote_sample(pack, "s1.exe", {})


def test_staged_record_from_another_sha_is_not_trusted(sample, pack,
                                                      monkeypatch):
    """A REMOTE-STAGING.json that disagrees with the pack's SHA-256 must not
    hand out its path; the legacy fallback still has to survive the hash."""
    _stage_record(pack, "C:/samples/winre/other/only/here.exe", sha=OTHER)
    monkeypatch.setattr(
        remote_driver, "remote_sha256", lambda *a, **k: OTHER)
    with pytest.raises(RuntimeError, match="remote sample identity mismatch"):
        remote_driver._verified_remote_sample(pack, "s1.exe", {})


def test_tampered_staging_path_shape_is_not_trusted(sample, pack, monkeypatch):
    """"A staging record pointing outside the run-specific tree (or any '.'
    shape games) must be rejected as a candidate path."""
    _stage_record(pack, "D:/evil/thing.exe")
    calls = []

    def fake_remote_hash(cfg, p):
        calls.append(p)
        return OTHER  # the legacy fallback holds foreign bytes

    monkeypatch.setattr(remote_driver, "remote_sha256", fake_remote_hash)
    with pytest.raises(RuntimeError, match="remote sample identity mismatch"):
        remote_driver._verified_remote_sample(pack, "s1.exe", {})
    # the hashed path is the legacy fallback, never the tampered one
    assert calls == ["C:\\samples\\s1.exe"]


# ------------------------------------------------------------------ H6: refusal


def test_archive_failure_refuses_detonation(pack, monkeypatch):
    """H6: no safe place to preserve the previous run -> no detonation."""
    import winre.snapshot_gate as sg
    monkeypatch.setattr(
        sg, "preflight",
        lambda *a, **k: {"allowed": True, "gate": {"mode": "enforce"}})
    monkeypatch.setattr(
        remote_driver, "archive_stage_for_fresh_run",
        lambda p: {"ok": False, "error": "simulated archive failure"})
    monkeypatch.setattr(
        remote_driver, "remote_sha256", lambda *a, **k: SHA)
    monkeypatch.setattr(
        remote_driver, "scp_to", lambda *a, **k: None)
    out = remote_driver.remote_dynamic(
        "s1.exe", SHA, pack, {"remote_pipeline": r"C:\WinRE"},
        max_seconds=60, enable_pesieve=False, run_id=RUN)
    assert out.get("ok") is False
    assert "could not archive prior dynamic evidence" in (out.get("error")
                                                          or "")
    assert out["archived"]["ok"] is False


def test_run_id_invalid_refuses_before_archive(pack, monkeypatch):
    import winre.snapshot_gate as sg
    monkeypatch.setattr(
        sg, "preflight",
        lambda *a, **k: {"allowed": True, "gate": {"mode": "enforce"}})
    monkeypatch.setattr(
        remote_driver, "remote_sha256", lambda *a, **k: SHA)
    monkeypatch.setattr(
        remote_driver, "scp_to", lambda *a, **k: None)
    out = remote_driver.remote_dynamic(
        "s1.exe", SHA, pack, {"remote_pipeline": r"C:\WinRE"},
        max_seconds=60, enable_pesieve=False, run_id="zzzz")
    assert out.get("ok") is False
    assert "invalid dynamic run ID" in (out.get("error") or "")


def test_run_nonce_missing_branches_fail_closed():
    """Complement to test_contracts.py: the two branches not yet exercised."""
    r = run_nonce.check(None, RUN)
    assert r["fresh"] is False and "no META.json" in r["reason"]
    r = run_nonce.check({}, "")
    assert r["fresh"] is False and "no run_id issued" in r["reason"]


def test_inventory_diff_reports_missing_unexpected_and_mismatched():
    remote = {
        "META.json": (10, "a" * 64),
        "trace.jsonl": (100, "b" * 64),
        "pcap.pcapng": (2048, "c" * 64),
    }
    received = {
        "META.json": (10, "a" * 64),
        "trace.jsonl": (99, "b" * 64),        # size drift -> mismatch
        "stray.exe": (7, "d" * 64),           # never sent -> unexpected
        # pcap.pcapng missing on the receiving side
    }
    diff = remote_driver._inventory_diff(remote, received)
    assert diff["missing_local_count"] == 1
    assert diff["unexpected_local_count"] == 1
    assert diff["content_mismatch_count"] == 1
    detail = diff["content_mismatch_details"][0]
    assert detail["path"] == "trace.jsonl"


def test_inventory_diff_flags_truncation():
    remote = {f"f{i}.bin": (i, "0" * 64) for i in range(25)}
    diff = remote_driver._inventory_diff(remote, {}, limit=20)
    assert diff["truncated"] is True
    assert diff["missing_local_count"] == 25


# ------------------------------------------------------------------ H1: no RPC


def test_blocked_debug_gate_refuses_without_touching_the_debugger(
        monkeypatch):
    """Ordinary (non-opt-in) work must produce no target-load/start/step RPC.
    The blocked gate returns an error and never builds a client, ensures the
    debugger, or stages a copy."""
    import winre.snapshot_gate as sg
    from winre.agentic import ToolRegistry

    monkeypatch.setattr(
        sg, "preflight",
        lambda *a, **k: {"allowed": False, "error": "ledger not clean"})

    import winre.mcp.x64dbg_manager as mgr

    def refuse(name):
        def _f(*a, **k):
            raise AssertionError(f"{name} must not run for a gated-out tool")
        return _f
    monkeypatch.setattr(mgr, "ensure_mcp", refuse("ensure_mcp"))
    monkeypatch.setattr(mgr, "stage_safe_sample", refuse("stage_safe_sample"))

    reg = ToolRegistry("s1.exe", SHA, {}, mode="remote")
    for tool in (reg.x64dbg_oep, reg.x64dbg_run_window, reg.x64dbg_unpack,
                 reg.x64dbg_wpm_dump):
        r = tool()
        assert r.get("error"), "a gated-out debugger tool must refuse"
        assert "falling back to static" in r["error"]


def test_debugger_down_refuses_and_falls_back(monkeypatch):
    """The debugger-ready/down control: when ensure_mcp cannot bring :9094 up,
    the tool refuses cleanly instead of proceeding against a dead debugger."""
    import winre.snapshot_gate as sg
    import winre.mcp.x64dbg_manager as mgr
    from winre.agentic import ToolRegistry

    monkeypatch.setattr(
        sg, "preflight", lambda *a, **k: {"allowed": True})
    monkeypatch.setattr(remote_driver, "mcp_autostart_enabled",
                        lambda: True)
    ensure_calls = []

    def fake_ensure(**kw):
        ensure_calls.append(kw)
        return (False, {"error": "x64dbg ports did not open"})
    monkeypatch.setattr(mgr, "ensure_mcp", fake_ensure)
    monkeypatch.setattr(mgr, "stage_safe_sample",
                        lambda *a, **k: "C:\\dbg\\s1.exe")

    hit = []

    def no_loop(*a, **k):
        hit.append(1)
        raise AssertionError("debug loops must not run against a dead debugger")
    import winre.debug_loops as dl
    monkeypatch.setattr(dl, "ep_break", no_loop)
    monkeypatch.setattr(dl, "oep_by_section", no_loop)

    reg = ToolRegistry("s1.exe", SHA, {}, mode="remote")
    r = reg.x64dbg_oep()
    assert len(ensure_calls) == 1 and ensure_calls[0]["wait_s"] == 45
    assert "x64dbg MCP :9094 unavailable" in (r.get("error") or "")
    assert "did not open" in (r.get("error") or "")
    assert not hit


def test_static_deep_has_no_debugger_surface():
    """Source-level seal for H1: the static producer never references an
    x64dbg/windbg RPC surface at all."""
    src = pathlib.Path("winre/static_deep.py").read_text(encoding="utf-8")
    for needle in ("X64Dbg", "x64dbg", "windbg", "LoadBinary",
                   "start_step", "dbg_"):
        assert needle not in src, f"static deep dive references {needle!r}"
