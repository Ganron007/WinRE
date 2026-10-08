"""W1: a write-family call is proof in its own right.

Today's packs happen to also contain a `CreateFileW(..., GENERIC_WRITE)` for
every path a `WriteFile` landed on, so the access-mask proof subsumes the
write-family proof on existing data - measured, 8 proven writes either way.

That is not a reason to omit it. A run only hooks the APIs it was asked for
(`--apis`), so a trace that caught `WriteFile` but never hooked `CreateFileW`
has NO access mask at all. Without the write-family proof, a strict "require
write provenance" rule would then report a genuine drop as an observation -
which is the exact way a calibration fix silently becomes a blind fix.
"""
import json
import pathlib
import tempfile

from winre import findings as F

SHA = "w" * 64
DROP = "C:\\Users\\analyst\\AppData\\Local\\Temp\\payload.exe"


def pack(events):
    root = pathlib.Path(tempfile.mkdtemp())
    stage = root / "dynamic"
    stage.mkdir(parents=True)
    (stage / "META.job.json").write_text(
        json.dumps({"sample_pid": 4242, "window": {"effective_s": 30}}),
        encoding="utf-8")
    (stage / "frida_summary.json").write_text("{}", encoding="utf-8")
    (stage / "procmon_summary.json").write_text("{}", encoding="utf-8")
    (stage / "network_intel.json").write_text("{}", encoding="utf-8")
    (stage / "frida_trace.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return root


def test_a_write_to_an_attributed_handle_is_proof_of_a_drop():
    """A run that hooked WriteFile but NOT CreateFileW: there is no access mask
    anywhere, and the handle was resolved to a path. That path was written."""
    f = F.dynamic_findings(pack([
        {"type": "call", "api": "WriteFile",
         "args": ["0xafc", "0x1000", "0x200"],
         "decoded": {"path": DROP}},
    ]), sha=SHA)
    assert f["findings"]["drops"], (
        "a WriteFile to an attributed path was not counted as a write")
    assert f["findings"]["drops"][0]["path"] == DROP
    assert f["findings"]["file_provenance"]["available"] is True


def test_a_write_to_an_unattributed_handle_is_not_proof():
    """The other half: `WriteFile` alone, with no handle->path resolution, is
    what cost b104 its memory dump (P1-F6). It must not resurrect as proof."""
    f = F.dynamic_findings(pack([
        {"type": "call", "api": "WriteFile",
         "args": ["0xafc", "0x1000", "0x200"], "decoded": {}},
    ]), sha=SHA)
    assert f["findings"]["drops"] == [], (
        "a WriteFile with no attributed path was claimed as a drop")


def test_a_read_only_open_then_a_write_to_the_same_file():
    """The handle was opened for READ: the write would fail at the API, but the
    handle may have been opened GENERIC_READ in a session we never saw. Both
    proofs are recorded and a proven write outranks an unproven read."""
    f = F.dynamic_findings(pack([
        {"type": "call", "api": "CreateFileW", "args": ["0x1", "0x80000000"],
         "decoded": {"arg0": DROP}},
        {"type": "call", "api": "WriteFile",
         "args": ["0xafc", "0x1000", "0x200"], "decoded": {"path": DROP}},
    ]), sha=SHA)
    assert f["findings"]["drops"], (
        "a WriteFile to an attributed path outranks a stale read-only open")


def test_the_write_family_and_the_access_mask_cannot_disagree():
    """Both proofs must agree on what a write is. The tracer and findings.py
    restate the access bits (findings.py is host-side and cannot import a
    VM-side tool), so a test has to hold them together."""
    import importlib.util
    tr = pathlib.Path(__file__).resolve().parents[1] / "tools" / "frida_api_trace.py"
    spec = importlib.util.spec_from_file_location("frida_probe", tr)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert F._WRITE_BITS == mod.WRITE_ACCESS_BITS
    # the write-family set must match too
    js = tr.read_text(encoding="utf-8")
    assert all(m in js for m in ("WriteFile", "NtWriteFile", "WriteFileEx",
                                 "WriteFileGather", "FlushFileBuffers"))