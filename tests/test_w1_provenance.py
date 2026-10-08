"""W1: the two proofs must not be read as one filter.

A run hooks only the APIs it was asked for, so the provenance enumerator has to
accept two independent shapes:

  * Create*-style : arg0 = path, arg1 = dwDesiredAccess -> write bits
  * write-family  : a handle the tracer already resolved to a path

Getting the ordering between them wrong in either direction loses evidence:

  filter first, branches second -> a WriteFile is discarded before its own
      proof is examined, and a genuine drop becomes "an observation"
  branches first, no filter  -> every other hooked API (LoadLibraryW,
      CreateProcessW, GetProcAddress) falls into the Create* branch, and its
      arg0/arg1 get read as path + mask. That INVENTS proven writes.

The second direction shipped: it classified `mscoree.dll` (a LoadLibraryW
argument) as a proven drop. Caught by reading what the classifier produced,
not by any test - which is why it is pinned here.
"""
import json
import pathlib
import tempfile
import sys

sys.path.insert(0, r"C:\STUDY\Github\CADRE-Platform\WinRE")
from winre import findings as F

SHA = "w" * 64


def pack(events):
    root = pathlib.Path(tempfile.mkdtemp())
    st = root / "dynamic"
    st.mkdir(parents=True)
    (st / "META.job.json").write_text(
        json.dumps({"sample_pid": 4242, "window": {"effective_s": 30}}),
        encoding="utf-8")
    (st / "frida_summary.json").write_text("{}", encoding="utf-8")
    (st / "procmon_summary.json").write_text("{}", encoding="utf-8")
    (st / "network_intel.json").write_text("{}", encoding="utf-8")
    (st / "frida_trace.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return root


DROP = r"C:\Users\analyst\AppData\Local\Temp\payload.exe"


def test_only_create_apis_reach_the_access_mask_branch():
    """LoadLibraryW / CreateProcessW / GetProcAddress must never be read as
    CreateFileW(path, mask). The pack that shipped had `mscoree.dll` - a
    LoadLibraryW argument - counted as a proven write."""
    f = F.dynamic_findings(pack([
        # the real defect: LoadLibraryW(hModule, lpLibFileName) - arg0 is a
        # handle, arg1 is a path POINTER, not an access mask
        {"type": "call", "api": "LoadLibraryW",
         "args": ["0x7ffb", "0x1a2b3c4d"],
         "decoded": {"arg0": "mscoree.dll"}},
        {"type": "call", "api": "CreateProcessW",
         "args": ["0x7ffb", "0x20"],
         "decoded": {"arg0": r"C:\Windows\Microsoft.NET\Framework64\v2.0.50727\dw20.exe"}},
        {"type": "call", "api": "GetProcAddress",
         "args": ["0x7ffb", "0x0"],
         "decoded": {"arg0": "VirtualAlloc"}},
    ]), sha=SHA)
    assert f["findings"]["drops"] == [], (
        f"invented a drop from a non-file API: "
        f"{[d['path'] for d in f['findings']['drops']]}")
    prov = f["findings"]["file_provenance"]
    assert prov["proven_writes"] == 0, (
        f"invented {prov['proven_writes']} proven writes from unrelated "
        f"arguments")


def test_a_real_write_family_call_is_still_accepted():
    f = F.dynamic_findings(pack([
        {"type": "call", "api": "WriteFile",
         "args": ["0xafc", "0x1000", "0x200"], "decoded": {"path": DROP}},
    ]), sha=SHA)
    assert f["findings"]["drops"], "the write-family proof stopped working"
    assert f["findings"]["drops"][0]["path"] == DROP


def test_a_real_access_mask_is_still_accepted():
    f = F.dynamic_findings(pack([
        {"type": "call", "api": "CreateFileW",
         "args": ["0x1", "0x40000000"], "decoded": {"arg0": DROP}},
    ]), sha=SHA)
    assert f["findings"]["drops"], "the access-mask proof stopped working"


def test_the_two_families_are_separate_sets():
    assert not (F._BACKFILL_APIS & F._WRITE_FAMILY_APIS), (
        "an API in both sets would be claimed as write proof twice - the "
        "write-family branch wins, so the Create* mask is ignored for it")
    assert "writefile" in F._WRITE_FAMILY_APIS
    assert "createfilew" in F._BACKFILL_APIS
