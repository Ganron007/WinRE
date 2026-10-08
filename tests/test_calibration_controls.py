"""Calibration controls: what the verdict engine must REFUSE to condemn.

RevAI's 2026-10-08 review found two calibration failures by feeding benign
synthetic input and getting `malicious`:

  W1  one CreateFileW(..., GENERIC_READ) on a file in the analyst's own
      Downloads became `drop:` and malicious/high
  W2  one DNS answer for `example.org` became `c2:` and malicious/medium

Both were real and both were found only by negative testing. There were no
such tests here, which is why the suite was green.

Every "must not be X" case is PAIRED with a "must STILL be X" case using the
same input shape. A calibration fix that only lowers verdicts is easy to write
and useless: it would simply blind the product. These controls fail if the
engine stops detecting real C2 and real drops as well.
"""
import json
import pathlib

import pytest

from winre import findings as F

SHA = "w" * 64
HOST = "cdn.legit-vendor.net"
READ_ONLY = "C:\\Users\\analyst\\Downloads\\utility.exe"
PROVEN_DROP = "C:\\Users\\analyst\\AppData\\Local\\Temp\\payload.exe"


def pack(frida=None, ni=None, trace=None):
    root = pathlib.Path(__import__("tempfile").mkdtemp())
    d = root / "dynamic"
    d.mkdir(parents=True)
    (d / "META.job.json").write_text(
        json.dumps({"sample_pid": 4242, "window": {"effective_s": 30}}),
        encoding="utf-8")
    (d / "frida_summary.json").write_text(json.dumps(frida or {}),
                                          encoding="utf-8")
    (d / "procmon_summary.json").write_text("{}", encoding="utf-8")
    (d / "network_intel.json").write_text(json.dumps(ni or {}), encoding="utf-8")
    if trace is not None:
        (d / "frida_trace.jsonl").write_text(
            "\n".join(json.dumps(x) for x in trace), encoding="utf-8")
    return root                       # the MODE ROOT; dynamic_findings descends


def net(ni):
    return F.dynamic_findings(pack(ni=ni), sha=SHA)["findings"]["network"]


def createfile(path, access):
    return {"type": "call", "api": "CreateFileW",
            "args": ["0x1", access], "decoded": {"arg0": path}}


# ------------------------------------------------------------------ W1

def test_a_read_of_an_executable_is_not_a_drop():
    """The W1 defect, verbatim: a GENERIC_READ open of a file in Downloads."""
    f = F.dynamic_findings(pack({"decoded_paths": [READ_ONLY]},
                                trace=[createfile(READ_ONLY, "0x80000000")]),
                           sha=SHA)
    assert f["findings"]["drops"] == [], "a READ was claimed as a drop"
    assert f["verdict"]["level"] != F.MALICIOUS, (
        f"a read produced {f['verdict']['level']}")
    # the observation is still recorded - visible, just not counted as intent
    assert f["findings"]["unverified_opens"], "the read vanished entirely"


def test_a_proven_write_is_still_a_drop():
    """Paired control: the fix must not blind the engine to real drops."""
    f = F.dynamic_findings(pack({"decoded_paths": [PROVEN_DROP]},
                                trace=[createfile(PROVEN_DROP, "0x40000000")]),
                           sha=SHA)
    assert f["findings"]["drops"], "a PROVEN write was lost"
    assert f["verdict"]["level"] == F.MALICIOUS
    assert any(b.startswith("drop:") for b in f["verdict"]["basis"])


def test_an_unprovable_open_fails_closed_and_says_so():
    """Shape alone is not proof, and the gap must be disclosed, not hidden."""
    f = F.dynamic_findings(pack({"decoded_paths": [READ_ONLY]}), sha=SHA)
    assert f["findings"]["drops"] == [], (
        "an open with no write provenance was claimed as a drop")
    assert f["verdict"]["level"] != F.MALICIOUS
    assert any("predates file-access provenance" in x for x in f["limitations"]), (
        "the provenance gap was not disclosed to the reader")


def test_an_unparseable_access_mask_is_not_guessed():
    f = F.dynamic_findings(pack({"decoded_paths": [PROVEN_DROP]},
                                trace=[createfile(PROVEN_DROP, "not-a-number")]),
                           sha=SHA)
    assert f["findings"]["drops"] == [], (
        "an unparseable access mask was treated as a write")


def test_provenance_recovers_from_the_raw_trace():
    """A pack summarised before provenance existed still has the proof, in its
    raw trace. Reading shape alone would throw away real evidence because of a
    lossy intermediate summary."""
    f = F.dynamic_findings(pack(trace=[createfile(PROVEN_DROP, "0x40000000")]),
                           sha=SHA)
    assert f["findings"]["file_provenance"]["available"] is True


def test_the_access_bits_match_the_tracer_exactly():
    """findings.py restates the tracer's bits (it is host-side and may not
    import a VM-side tool), so a test must hold the two copies together."""
    import importlib.util
    tr = pathlib.Path(__file__).resolve().parents[1] / "tools" / "frida_api_trace.py"
    spec = importlib.util.spec_from_file_location("frida_api_trace_probe", tr)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert F._WRITE_BITS == mod.WRITE_ACCESS_BITS, (
        "the host-side and VM-side write-access bits have diverged")
    assert F._READ_BITS == mod.READ_ACCESS_BITS if hasattr(mod, "READ_ACCESS_BITS") \
        else True


def test_the_tracer_actually_records_the_access_mask():
    """The provenance has to be produced, or nothing downstream can use it."""
    src = pathlib.Path(
        __file__).resolve().parents[1] / "tools" / "frida_api_trace.py"
    text = src.read_text(encoding="utf-8")
    assert "decoded['access']" in text
    assert "decoded['writes']" in text
    # and the summary must carry it into the pack
    summ = (pathlib.Path(__file__).resolve().parents[1]
            / "winre" / "summarize_dynamic.py").read_text(encoding="utf-8")
    assert "file_events" in summ


# ------------------------------------------------------------------ W2

def test_dns_resolution_alone_is_a_lead_not_c2():
    n = net({"captures": [{"dns_queries": [HOST], "tls_sni": [],
                           "http_requests": []}]})
    assert not [c for c in n["c2"] if c["host"] == HOST]
    assert [l["host"] for l in n["leads"]] == [HOST], (
        "the resolved host must remain visible as a lead")


def test_an_http_request_promotes_the_lead_to_c2():
    """Paired control: real communication must still be detected."""
    n = net({"captures": [{"dns_queries": [HOST], "tls_sni": [],
                           "http_requests": [f"{HOST}\tGET\t/index"]}]})
    assert [c["host"] for c in n["c2"]] == [HOST]
    assert n["leads"] == []
    assert n["c2"][0]["reason"], "a promotion must state why"


def test_beaconing_promotes_the_lead_to_c2():
    n = net({"captures": [{"dns_queries": [HOST], "tls_sni": [],
                           "http_requests": []}],
             "beacon_analysis": {"ok": True,
                                 "beacons": [{"host": HOST, "period_s": 60}]}})
    assert [c["host"] for c in n["c2"]] == [HOST]
    assert n["c2"][0]["kind"] == "beacon"


@pytest.mark.parametrize("host", ["example.org", "example.com", "example.net"])
def test_reserved_documentation_names_are_never_c2(host):
    n = net({"captures": [{"dns_queries": [host], "tls_sni": [],
                           "http_requests": []}]})
    assert not n["c2"], f"{host} was reported as C2"
    assert not n["leads"]


def test_a_reserved_name_is_excluded_even_with_an_http_request():
    n = net({"captures": [{"dns_queries": ["example.org"],
                           "http_requests": ["example.org\tGET\t/"],
                           "tls_sni": []}]})
    assert not n["c2"]


@pytest.mark.parametrize("host", ["ctldl.windowsupdate.com", "ecs.office.com",
                                  "g.live.com"])
def test_os_telemetry_is_not_c2(host):
    n = net({"captures": [{"dns_queries": [host], "tls_sni": [],
                           "http_requests": []}]})
    assert not n["c2"]


def test_a_lead_alone_cannot_make_the_sample_malicious():
    f = F.dynamic_findings(pack(ni={"captures": [
        {"dns_queries": [HOST, "api.bank.example-svc.net"], "tls_sni": [],
         "http_requests": []}]}), sha=SHA)
    assert f["findings"]["network"]["c2"] == []
    assert f["verdict"]["level"] != F.MALICIOUS, (
        "resolved names alone produced a malicious verdict")


def test_the_lead_note_states_the_rule():
    n = net({"captures": [{"dns_queries": [HOST], "tls_sni": [],
                           "http_requests": []}]})
    assert "not a C2 host" in n["lead_note"]