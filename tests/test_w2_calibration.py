"""W2, round 2 - found only because the enrichment finally ran.

The host-side tshark deep-dive had never executed: `_tool()` looked for
`enrich_pcap_tshark.py` under `tools/` while the tool lives in `winre/`, so every
run skipped with "not found" while tshark was installed and the pcaps were
sitting right there. Wiring it up exposed a second calibration round, because
real captured traffic had never reached the C2 logic:

  * `x1.c.lencr.org` and three siblings were reported as C2 for making an HTTP
    request. They are Let's Encrypt's CDN, contacted by OCSP validation on every
    TLS session on the box - the VM's own traffic, not the sample's.
  * `239.255.255.250:1900` (SSDP multicast) was reported as C2 with an HTTP
    "request". That is the machine discovering its own network.
  * `aka.ms` (Microsoft's shortener) was reported as C2.
  * `archive.torproject.org` was only a LEAD - the strongest indicator in the
    pack - because TLS SNI was not a promotion route. The SNI branch existed but
    the caller passed `set()`, so it was dead code.

These tests pin all four. Each "must not be" is paired with a "must still be"
built on a real pack, because a calibration fix that only subtracts would just
blind the engine.
"""
import json
import pathlib
import tempfile

import pytest

from winre import findings as F

HOST = "cdn.legit-vendor.net"
REAL = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"   # a DGA domain


def _net(ni):
    return F.dynamic_findings(_pack(ni), sha="w" * 64)["findings"]["network"]


def _pack(ni):
    root = pathlib.Path(tempfile.mkdtemp())
    st = root / "dynamic"
    st.mkdir(parents=True)
    (st / "META.job.json").write_text(
        json.dumps({"sample_pid": 4242, "window": {"effective_s": 30}}),
        encoding="utf-8")
    for nm in ("frida_summary.json", "procmon_summary.json"):
        (st / nm).write_text("{}", encoding="utf-8")
    (st / "network_intel.json").write_text(json.dumps(ni), encoding="utf-8")
    return root


# -------------------------------------------- CA / CDN is not C2

@pytest.mark.parametrize("host", [
    "x1.c.lencr.org", "lencr.org", "e1.o.lencr.org", "r3.o.lencr.org",
    "ocsp.digicert.com", "crt.sectigo.com", "ocsp.godaddy.com",
    "a248.e.akamai.net", "cdn.akamaized.net", "d123456.cloudfront.net",
])
def test_ca_and_cdn_infrastructure_is_not_c2(host):
    """Contacted by OCSP validation and CDN fetches on every TLS session. The
    real pack had four of these reported as C2 with an HTTP 'request'."""
    assert F._is_reserved_or_noise(host), f"{host} was treated as a C2 candidate"
    n = _net({"captures": [{"dns_queries": [host], "tls_sni": [],
                            "http_requests": [f"{host}\tGET\t/"]}]})
    assert not [c for c in n["c2"] if c["host"] == host]


@pytest.mark.parametrize("host", [
    "239.255.255.250:1900", "239.255.255.250", "224.0.0.251", "255.255.255.255",
    "169.254.1.1", "127.0.0.1", "10.0.0.5", "192.168.1.10", "::1", "fe80::1",
])
def test_multicast_and_link_local_is_not_c2(host):
    """SSDP, mDNS, broadcast and RFC1918 addresses are not remote endpoints."""
    assert F._is_link_local_or_multicast(host), f"{host} was treated as remote"
    n = _net({"captures": [{"dns_queries": [host], "tls_sni": [],
                            "http_requests": [f"{host}\tNOTIFY\t/"]}]})
    assert not [c for c in n["c2"] if c["host"] == host]


@pytest.mark.parametrize("host", ["aka.ms", "go.microsoft.com",
                                  "support.microsoft.com",
                                  "learn.microsoft.com"])
def test_microsoft_infrastructure_is_not_c2(host):
    assert F._is_reserved_or_noise(host)


# -------------------------------------------- SNI is communication

def test_tls_sni_promotes_a_lead_to_c2():
    """The client sends SNI during the handshake, so seeing it in a capture
    means the sample MOVED to that host. A plain-HTTP-only rule missed
    archive.torproject.org - the strongest indicator in the pack - and left it
    as a mere lead."""
    n = _net({"captures": [{"dns_queries": [HOST], "tls_sni": [HOST],
                            "http_requests": []}]})
    assert [c["host"] for c in n["c2"]] == [HOST], (
        "TLS SNI did not promote the host to C2")
    assert n["c2"][0]["kind"] == "tls-sni"
    assert "TLS handshake" in n["c2"][0]["reason"]


def test_a_real_dga_domain_is_still_c2():
    """The paired positive control, built on a real pack's capture."""
    n = _net({"captures": [{"dns_queries": [REAL], "tls_sni": [],
                            "http_requests": [f"{REAL}\tPOST\t/gate.php"]}]})
    assert [c["host"] for c in n["c2"]] == [REAL]
    assert n["c2"][0]["kind"] == "http"


def test_a_dns_only_lookup_is_still_only_a_lead():
    n = _net({"captures": [{"dns_queries": [HOST], "tls_sni": [],
                            "http_requests": []}]})
    assert not n["c2"]
    assert [l["host"] for l in n["leads"]] == [HOST]


# -------------------------------------------- the tool path

def test_the_enrichment_tool_is_found():
    """The defect that hid all of the above: `_tool()` searched `tools/` while
    enrich_pcap_tshark.py lives in `winre/`, so the deep-dive skipped every run
    with "not found" - and its honest skip reason masked a broken code path."""
    from winre import analysis
    d = pathlib.Path(tempfile.mkdtemp())
    found = analysis._tool(d, "enrich_pcap_tshark.py")
    assert found is not None, (
        "enrich_pcap_tshark.py is not found by _tool(); the host-side pcap "
        "deep-dive will never run")
    assert found.name == "enrich_pcap_tshark.py"
    assert found.is_file()


def test_the_enrichment_reports_the_honest_reason_when_it_cannot_run():
    from winre import analysis
    # no network_raw pulled: that IS the honest reason, and it must be said
    r = analysis.enrich_pcap(pathlib.Path(tempfile.mkdtemp()))
    assert r.get("skipped") is True
    assert r.get("reason") == "no network_raw pulled"
