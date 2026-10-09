r"""findings.py - the analysis plane: evidence -> findings, OFF the VM.

DESIGN.md section 2, layer 2. This is the producer that was never written.

The FlareVM is an evidence producer and nothing else. It executes the sample,
collects Frida/Procmon/pcap/memory artefacts, and stops. Everything DERIVED -
findings, verdict, report - is produced here, from evidence pulled off the VM,
so that a sample which tampered with its own analysis environment cannot
tamper with the conclusions drawn from it.

Two properties make this more than a reformatter:

  * `basis[]` is machine-readable. It names WHY a level was reached, so
    reporting can explain itself and an audit can check it.
  * `limitations[]` is mandatory. A degraded analysis says so. That is what
    stops "green run, no evidence" from recurring - the exact failure that
    produced a 27-artefact dynamic pack whose entire report section read
    "see dynamic/ artifacts".

Host-side only: no import from this module may reach a VM-only tool. Where a
host tool is missing (yara and floss are not installed on this box) the module
records a limitation rather than pretending it ran.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

SCHEMA = "winre-findings/v1"

# Malcat reports entropy as bits-per-byte x 32 in a 0-255 integer
_ENTROPY_SCALE = 32.0
# one section at or above this is a packed section regardless of the file
# average, which is diluted away on a 3 MB .rsrc inside an ordinary PE
_PACKED_SECTION_BPB = 6.5

# verdict levels
MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
BENIGN = "benign"
UNKNOWN = "unknown"

_EXE_STEMS = (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv",
              ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".lnk", ".pif")
_PERSIST_DIRS = ("\\appdata\\", "\\roaming\\", "\\local\\", "\\temp\\",
                 "\\programdata\\", "\\startup\\", "\\start menu\\",
                 "\\system32\\", "\\syswow64\\", "\\program files\\")


# ---------------------------------------------------------------- helpers

def _read(path: Path) -> dict | list | None:
    """utf-8-sig: the VM writes these with a BOM and json.loads then fails,
    which silently turned every read into None."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text("utf-8-sig", errors="replace"))
    except Exception:
        return None


def _norm(p: str) -> str:
    return (p or "").replace("/", "\\").lower()


# SUBDIRECTORIES that are part of the OS - a write here is a system load, not
# a drop. `c:\windows\` itself is deliberately absent from the list: WannaCry
# writes its payload straight to C:\WINDOWS\mssecsvc.exe, and calling that a
# system load would hide the single most important artefact in the batch.
_SYSTEM_DIRS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                "c:\\windows\\winsxs\\", "c:\\windows\\assembly\\",
                "c:\\windows\\microsoft.net\\", "c:\\windows\\globalization\\",
                "c:\\windows\\registration\\",
                "c:\\program files\\", "c:\\program files (x86)\\")


def _bpb(v) -> float | None:
    """Malcat entropy -> bits per byte. The VM reports it x 32 in a 0-255 int."""
    return round(v / _ENTROPY_SCALE, 3) if isinstance(v, (int, float)) else None


def _sample_path(dyn_dir: Path) -> str | None:
    """The sample's own path, from the job log the VM wrote.

    Without this the sample's own file in C:\\samples\\ counts as a drop and
    every run reports a self-infection.
    """
    log = dyn_dir / "job.log"
    if not log.is_file():
        return None
    try:
        txt = log.read_text("utf-8", errors="replace")
    except Exception:
        return None
    # the job log prefixes every line with a timestamp, so the name is not
    # at the start of the line
    m = re.search(r"(?m)sample=(\S.*)$", txt)
    return _norm(m.group(1).strip()) if m else None


def _classify_path(p: str, sample: str | None = None) -> str | None:
    """drop | device | system-load | other, for a path Frida saw in the SAMPLE.

    Only Frida's decoded_paths are sample-attributable: Frida hooks the sample
    process. Procmon's counts are window-wide totals for every process on the
    VM, so `drop_file: 3886` means 3886 write events happened on the box - not
    that this sample dropped 3886 files. Presenting those as sample behaviour
    would be inventing evidence.
    """
    low = _norm(p)
    if not low or low == sample:
        return None
    if low.startswith("\\\\.\\") or low.startswith("\\device\\"):
        return "device"
    if low.startswith(_SYSTEM_DIRS):
        return "system-load"
    if low.endswith(_EXE_STEMS):
        return "drop"
    return "other"


def _host_tools() -> dict:
    """Which host-side analysis tools exist. Absent ones become limitations."""
    import shutil
    out = {}
    for t in ("tshark", "yara", "floss", "strings"):
        out[t] = bool(shutil.which(t))
    return out


def _frame(mode: str, sha: str, **kw) -> dict:
    return {"schema": SCHEMA, "mode": mode, "sha256": sha, **kw}


def _verdict(level: str, confidence: str, basis: list[str],
             source: str = "deterministic") -> dict:
    # basis is deduped and order-preserved: it is the audit trail
    seen, out = set(), []
    for b in basis:
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return {"level": level, "confidence": confidence, "basis": out,
            "source": source}


# ------------------------------------------------------- dynamic findings

def dynamic_findings(dyn_dir: Path, *, sha: str = "") -> dict:
    """Findings from a detonation's PULLED evidence.

    Reads what the VM collected (frida summary, procmon summary, network
    intel, the job's window/gate record, the memory inventory) and derives
    facts. Does not execute procdump or cdb - those are VM-side and belong to
    the evidence plane.
    """
    basis: list[str] = []
    limitations: list[str] = []
    used: list[str] = []
    findings: dict = {}

    # the stage dir for every mode: <mode_root>/dynamic/
    dyn_dir = Path(dyn_dir) / "dynamic"
    job = _read(dyn_dir / "META.job.json") or {}
    if job:
        used.append("META.job.json")
    fs = _read(dyn_dir / "frida_summary.json") or {}
    ps = _read(dyn_dir / "procmon_summary.json") or {}
    ni = _read(dyn_dir / "network_intel.json") or {}
    ed = _read(dyn_dir / "emu_diff.json") or {}
    pm = _read(dyn_dir / "post_mortem.json") or {}

    # --- did it even run? ------------------------------------------------
    ran = bool(job.get("sample_pid"))
    if not ran:
        limitations.append(
            "the detonation never spawned the sample process - the findings "
            "below are instrumentation-only and cannot speak to behaviour")
    loader = job.get("loader") or "direct"
    if loader == "rundll32":
        basis.append(f"loader:rundll32:{job.get('loader_entry')}")

    # --- sample-attributable paths (Frida hooks the sample process) -------
    #
    # W1 (RevAI review 2026-10-08): AN OPEN IS NOT A DROP.
    #
    # decoded_paths is a flat list of strings, so this loop could not tell a
    # CreateFileW(..., GENERIC_READ) from one opened GENERIC_WRITE. Every
    # observed open of an .exe therefore became `drop:` and, alone, a
    # malicious/high verdict - including a plain read of a file in the
    # analyst's own Downloads folder. Reading is not an intent to plant.
    #
    # The tracer records the access mask now (tools/frida_api_trace.py) and the
    # summary keeps it (summarize_dynamic.py -> file_events), so a drop needs
    # POSITIVE write evidence. Where a pack predates that recording there is no
    # proof, and an unproven path is reported as an OBSERVATION under
    # unverified_opens - visible, citable, and never counted as a drop.
    own = _sample_path(dyn_dir)
    paths = [p for p in (fs.get("decoded_paths") or []) if isinstance(p, str)]

    # path -> {"writes": bool, "reads": bool, "api": str, "access": str}
    prov: dict[str, dict] = {}
    has_provenance = False
    _events = fs.get("file_events") or []
    if not _events:
        # a pack pulled before provenance was summarised still has the access
        # mask in its raw trace; recover the proof rather than discard real
        # evidence because of a lossy intermediate summary
        _events = _backfill_provenance(dyn_dir)
    for ev in _events:
        if not isinstance(ev, dict):
            continue
        ep = ev.get("path")
        if not isinstance(ep, str) or not ep:
            continue
        if ev.get("access") is not None or ev.get("writes") is not None:
            has_provenance = True
        rec = prov.setdefault(ep, {"writes": False, "reads": False,
                                   "api": None, "access": None})
        if ev.get("writes"):
            rec["writes"] = True
        if ev.get("reads"):
            rec["reads"] = True
        rec["api"] = rec["api"] or ev.get("api")
        rec["access"] = rec["access"] or ev.get("access")

    # The evidence is the UNION of both sources, not one of them. A path can be
    # present in file_events and absent from decoded_paths - the summary keeps
    # only 80 sorted unique strings, and the write-family proof can attribute a
    # path the flat list lost. Iterating decoded_paths alone silently deleted
    # any drop whose only proof was a WriteFile to an attributed handle, which
    # is how a strict fix becomes a blind fix.
    seen_paths = set(paths)
    for _p in prov:
        if _p not in seen_paths:
            paths.append(_p)

    drops, device_writes, system_loads = [], [], []
    unverified: list[dict] = []
    for p in paths:
        kind = _classify_path(p, own)
        pv = prov.get(p)
        proven = bool(pv and pv.get("writes"))
        if kind == "drop":
            if proven:
                rec = {"path": p, "proven": True,
                       "api": pv.get("api"), "access": pv.get("access")}
                if any(d in _norm(p) for d in ("\\startup\\", "\\start menu\\")):
                    rec["persistence_location"] = True
                drops.append(rec)
            else:
                # observed, not attributed: recorded, never a drop
                unverified.append({
                    "path": p,
                    "reason": ("opened-for-read"
                               if (pv or {}).get("reads") else
                               "no write provenance recorded"),
                    "api": (pv or {}).get("api"),
                })
        elif kind == "device":
            # \\.\pipe\... is a named pipe, not a raw-device write
            if not _norm(p).startswith("\\\\.\\pipe"):
                if proven:
                    device_writes.append(p)
                else:
                    unverified.append({
                        "path": p,
                        "reason": ("opened-for-read"
                                   if (pv or {}).get("reads") else
                                   "no write provenance recorded"),
                        "api": (pv or {}).get("api"),
                    })
        elif kind == "system-load":
            system_loads.append(p)

    # only a PROVEN write earns a drop basis tag
    for d in drops:
        basis.append("drop:" + Path(d["path"].replace("\\", "/")).stem[:24])
        if d.get("persistence_location"):
            basis.append("persistence:startup-path")

    if unverified:
        limitations.append(
            f"{len(unverified)} path(s) looked like a drop by shape but carry "
            "no proof of being written: they are reported as observations, not "
            "as drops. A read of an executable is not evidence of planting one.")
    if not has_provenance and paths:
        limitations.append(
            "this pack predates file-access provenance (frida file_events), so "
            "NO path in it can be attributed to a write. Path shape alone is "
            "not sufficient to claim a drop.")
    findings["drops"] = drops
    findings["unverified_opens"] = unverified[:60]
    findings["device_writes"] = device_writes
    findings["system_loads"] = len(system_loads)
    findings["file_provenance"] = {
        "available": has_provenance,
        "events": len(prov),
        "proven_writes": sum(1 for v in prov.values() if v.get("writes")),
    }

    # --- system-wide context (NOT sample-attributable) --------------------
    cat = (ps.get("persistence") or {}) if isinstance(ps, dict) else {}
    persistence = []
    for kind, rec in (cat.items() if isinstance(cat, dict) else []):
        try:
            n = int((rec or {}).get("count") or 0)
        except (TypeError, ValueError):
            n = 0
        persistence.append({"kind": kind, "label": (rec or {}).get("label"),
                            "count": n,
                            "scope": "system-wide (Procmon sees every "
                                     "process in the window, not just the "
                                     "sample)"})
    findings["persistence"] = persistence
    findings["persistence_note"] = (
        "Procmon counts are window-wide event totals for the whole VM. They "
        "are context, not sample behaviour; only Frida's decoded_paths are "
        "sample-attributable.")
    findings["process_spawns"] = ps.get("process_spawns") if isinstance(ps, dict) else None

    # --- network ---------------------------------------------------------
    net = {"c2": [], "leads": [], "beacons": [], "pcaps": [],
           "pcap_deep_dive": "not-run"}
    ba = (ni.get("beacon_analysis") or {}) if isinstance(ni, dict) else {}
    net["beacons"] = ba.get("beacons") or []

    # every host the sample resolved or negotiated with, and HOW
    seen: dict[str, set[str]] = {}
    http_hosts: set[str] = set()
    sni_hosts: set[str] = set()
    for cap in (ni.get("captures") or []):
        for q in cap.get("dns_queries") or []:
            if isinstance(q, str) and q.strip():
                seen.setdefault(q.strip().lower(), set()).add("dns")
        for h in cap.get("tls_sni") or []:
            if isinstance(h, str) and h.strip():
                sni_hosts.add(h.strip().lower())
                seen.setdefault(h.strip().lower(), set()).add("tls-sni")
        for line in cap.get("http_requests") or []:
            # tshark -T fields: host, method, uri
            host = str(line).split("\t")[0].strip().lower()
            if host:
                http_hosts.add(host)
                seen.setdefault(host, set()).add("http")
        net["pcaps"].extend(cap.get("pcap") and [cap["pcap"]] or [])

    beaconed = set()
    for b in net["beacons"]:
        if isinstance(b, dict):
            h = (b.get("host") or b.get("domain") or b.get("server") or "")
            if isinstance(h, str) and h.strip():
                beaconed.add(h.strip().lower())
        elif isinstance(b, str) and b.strip():
            beaconed.add(b.strip().lower())

    for host, how in sorted(seen.items()):
        if not _looks_like_c2(host):
            continue
        promoted = _promote_to_c2(host, beaconed, http_hosts, sni_hosts)
        if promoted:
            kind, reason = promoted
            net["c2"].append({"host": host, "kind": kind, "reason": reason,
                              "observed_as": sorted(how)})
        else:
            net["leads"].append({
                "host": host, "observed_as": sorted(how),
                "status": "lead (resolution only - no communication, "
                          "no beaconing, no independent attribution)",
            })
    net["leads"] = net["leads"][:80]
    net["lead_note"] = (
        "A resolved host is not a C2 host. These are reported as leads: the "
        "sample looked the name up. Promotion to c2 requires communication "
        "semantics (an HTTP request or periodic beaconing) or independent "
        "attribution.")
    net["pcap_deep_dive"] = _pcap_status(ni)
    findings["network"] = net
    for c in net["c2"]:
        basis.append(f"c2:{c['host']}")
    if net["beacons"]:
        basis.append("beacon:candidate")

    # --- injection / memory ops ------------------------------------------
    apis = {a: n for a, n in (fs.get("top_apis") or [])}
    chain = []
    if apis.get("VirtualAlloc"):
        chain.append("VirtualAlloc")
    if apis.get("WriteProcessMemory") or apis.get("NtWriteVirtualMemory"):
        chain.append("WriteProcessMemory")
    if apis.get("CreateRemoteThread") or apis.get("NtCreateThreadEx"):
        chain.append("CreateRemoteThread")
    findings["injection"] = (
        [{"chain": chain, "evidence": "frida top_apis",
          "confidence": "medium" if len(chain) >= 2 else "low"}]
        if chain else [])
    # The injection chain is what raises this pack to suspicious/medium below,
    # so it must be named in the basis. A level with an empty basis is
    # un-auditable: the report shows a verdict and no trail for it, which is
    # the same defect class as the calibration items - a claim nothing supports.
    if chain:
        basis.append("injection:" + "+".join(chain))
    if len(chain) >= 2:
        basis.append("injection:" + "+".join(chain))

    # --- device writes (a wiper) ------------------------------------------
    # sample-attributable only: Frida hooks the sample, so a raw-device open
    # here is the sample reaching past the filesystem. Named pipes
    # (\\.\pipe\...) are IPC, not raw devices, and are excluded above.
    findings["device_writes"] = device_writes
    for d in device_writes[:3]:
        basis.append("device:" + d)

    # --- memory inventory (dumps were made, on the VM; triaged here) ------
    mem_dir = dyn_dir / "memory"
    dumps = [f for f in mem_dir.rglob("*.dmp")] if mem_dir.is_dir() else []
    mh = (pm.get("memory_harvest") or {}) if isinstance(pm, dict) else {}
    findings["memory"] = {
        "dumps": len(dumps),
        "bytes": sum(f.stat().st_size for f in dumps if f.is_file()),
        "harvest_ok": mh.get("ok"),
        "harvest_reason": mh.get("reason"),
        "triage": {"note": "dump triage runs on the analysis host, not the VM"},
    }
    if not dumps:
        limitations.append(
            "no memory dumps were produced: nothing to triage off-VM. A "
            "short-lived sample plus a gate that fired first is the usual "
            "cause")

    # --- window / gate ----------------------------------------------------
    w = job.get("window") or {}
    g = (w or {}).get("gate") or {}
    findings["window"] = {
        "effective_s": (w or {}).get("effective_s"),
        "stop_reason": (w or {}).get("stop_reason"),
        "gate_fired": bool(g.get("fired")),
        "gate_kind": g.get("kind"),
        "gate_api": g.get("api"),
        "gate_at_s": g.get("at_s"),
    }
    if g.get("fired"):
        basis.append(f"gate:{g.get('kind')}:{g.get('api')}")

    # --- emulation divergence (a coverage signal, not a verdict) ----------
    findings["anti_emulation"] = {
        "divergence": ed.get("divergence_score"),
        "suspect": bool(ed.get("anti_emulation_suspect")),
        "only_observed": (ed.get("only_observed") or [])[:10],
    }
    if ed.get("divergence_score") == 1.0 and not ran:
        limitations.append(
            "emulation-vs-detonation divergence is 1.0 because the "
            "detonation produced no API observations; it is not evidence of "
            "anti-emulation")

    # --- verdict ----------------------------------------------------------
    level, conf = UNKNOWN, "low"
    if not ran:
        level, conf = UNKNOWN, "low"
    elif drops or device_writes:
        level, conf = MALICIOUS, "high"
    elif net["c2"] or net["beacons"]:
        level, conf = MALICIOUS, "medium"
    elif findings["injection"]:
        level, conf = SUSPICIOUS, "medium"
    elif findings["process_spawns"]:
        level, conf = SUSPICIOUS, "low"
    else:
        level, conf = UNKNOWN, "low"
        limitations.append(
            "the detonation ran and the sample did nothing the instruments "
            "could see: no drops, no C2, no injection. That is a real "
            "observation, not a failure - but it does not support a verdict "
            "on its own.")

    tools = _host_tools()
    if not tools["tshark"]:
        limitations.append("pcap deep-dive skipped: tshark absent on this host")
    if not tools["yara"]:
        limitations.append(
            "memory-dump YARA triage skipped: yara is not installed on the "
            "analysis host (it lives on the VM, which is not a trusted "
            "analyst after detonation)")

    return _frame("dynamic", sha, ok=ran, verdict=_verdict(level, conf, basis),
                  findings=findings, evidence_used=used, limitations=limitations)


# RFC 2606 / RFC 6761 reserved and documentation names. These exist so
# documentation, examples and tests cannot be mistaken for infrastructure.
# example.org being reported as C2 is the single most embarrassing way for a
# findings plane to be wrong.
_RESERVED_NAMES = frozenset({
    "example.com", "example.net", "example.org", "example", "localhost",
})
_RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost",
                      ".arpa", ".local", ".lan", ".onion.test")

# Resolver / OS / CDN telemetry. Still a denylist, and still incomplete - which
# is why it is no longer sufficient on its own to call something C2.
# CA / CDN / OCSP infrastructure. A sample that completes a TLS handshake
# contacts these; that is certificate validation working, not a C2 channel.
# Still a denylist, and still incomplete by construction - which is why a
# promotion also needs a communication signal, not just a "not-listed" pass.
_CA_CDN_INFRA = frozenset({
    "lencr.org", "letsencrypt.org", "digicert.com", "sectigo.com",
    "comodoca.com", "usertrust.com", "globalsign.com", "godaddy.com",
    "verisign.com", "symantec.com", "thawte.com", "entrust.net",
    "startcom.org", "buypass.com", "actalis.com", "quotemedia.com",
    "akamai.net", "akamaihd.net", "akamaized.net", "fastly.net",
    "cloudfront.net", "azureedge.net", "windows.net", "msedge.net",
    "googleusercontent.com", "gvt1.com", "gvt2.com", "1e100.net",
    "doubleverify.com", "scorecardresearch.com", "quantserve.com",
})
_OS_NOISE = frozenset({
    "microsoft.com", "windowsupdate.com", "msftncsi.com", "windows.com",
    "aka.ms", "go.microsoft.com", "support.microsoft.com", "learn.microsoft.com",
    "office.com", "officeapps.live.com", "live.com", "msn.com", "bing.com",
    "adnxs.com", "doubleclick.net", "gstatic.com", "akamaitechnologies.com",
    "akamaiedge.net", "cloudflare.com", "cloudflare-dns.com", "verisign.com",
})



def _promote_to_c2(host: str, beaconed: set[str], http_hosts: set[str],
                   sni_hosts: set[str]) -> tuple[str, str] | None:
    """Decide whether an observed host is C2, and say why. -> (kind, reason).

    W2: RESOLUTION IS NOT ATTRIBUTION. A DNS answer proves the name was looked
    up, nothing more - which is why every benign program that resolves a CDN
    produced `c2:` and a malicious/medium verdict.

    A lead is promoted only on evidence of COMMUNICATION or ATTRIBUTION:
      * beaconed            - periodic callbacks (communication semantics)
      * http-requested      - the sample actually sent a request to the host,
                               which is more than resolving it
      * tls-sni + http      - both, the strongest passive case

    Returns None to leave it a lead.
    """
    if _is_reserved_or_noise(host):
        return None
    if host in beaconed:
        return ("beacon", "periodic callbacks to this host")
    if host in http_hosts:
        return ("http", "the sample sent an HTTP request to this host")
    # SNI is sent by the client during the handshake, so seeing it in a capture
    # means the sample MOVED to that host. That is stronger than resolving a
    # name, and it is how a plain-HTTP rule missed archive.torproject.org - the
    # single strongest indicator in the pack was left as a mere lead.
    if host in sni_hosts:
        return ("tls-sni", "the sample opened a TLS handshake to this host")
    return None


def _pcap_status(ni) -> str:
    """Did the pcap deep dive actually HAPPEN? W5 (RevAI review 2026-10-08).

    This used to be `"done (host tshark)" if _tshark() else "skipped..."` - the
    status of the analysis was read off the PRESENCE OF A BINARY. A host with
    tshark installed reported "done" over a fictitious pcap with no analysis
    operation performed at all, which is availability dressed as completion.

    The enrichment records what it did: enrich_pcap_tshark.py writes
    `ok: true` with `captures: [...]` when it ran, `ok: false` with an `error`
    when tshark was missing, and writes nothing at all when it never ran. So
    the status is derived from that record, and the counts are the operation's
    actual output.
    """
    if not isinstance(ni, dict) or not ni:
        return "not-run: this pack carries no network enrichment record, so " \
               "no pcap analysis was performed (having tshark installed says " \
               "nothing about whether it ran)"
    if ni.get("ok") is False:
        return f"skipped: {ni.get('error') or 'enrichment reported failure'}"
    caps = ni.get("captures") or []
    if not caps:
        return ("not-run: enrichment recorded no captures, so no pcap was " \
                "analysed")
    dns = sum(len(c.get("dns_queries") or []) for c in caps)
    http = sum(len(c.get("http_requests") or []) for c in caps)
    sni = sum(len(c.get("tls_sni") or []) for c in caps)
    return (f"done: {len(caps)} capture(s) analysed - {dns} dns, {http} http, "
            f"{sni} tls-sni observation(s)")


def _is_reserved_or_noise(host: str) -> bool:
    """Never C2, whatever else is true: a reserved name or OS telemetry."""
    h = (host or "").lower().strip(".")
    if not h:
        return True
    if h in _RESERVED_NAMES or h.endswith(_RESERVED_SUFFIXES):
        return True
    if h in _OS_NOISE:
        return True
    if h in _CA_CDN_INFRA or any(h.endswith("." + d) for d in _CA_CDN_INFRA):
        return True
    if any(h.endswith("." + d) for d in _OS_NOISE):
        return True
    # Not a remote host at all: multicast, broadcast and link-local traffic is
    # the machine discovering its own network. 239.255.255.250:1900 is SSDP,
    # generated by the OS, and it was reported as C2 with an HTTP "request".
    if _is_link_local_or_multicast(h):
        return True
    return False


def _is_link_local_or_multicast(host: str) -> bool:
    """Multicast, broadcast, link-local or loopback - never a C2 host.

    Port stripping has to be IPv6-aware: `split(":", 1)` turns `::1` into `""`
    and `fe80::1` into `"fe80"`, so both would silently stop being recognised as
    loopback/link-local. Only a trailing `:<port>` after a valid IPv4 literal is
    a port.
    """
    import ipaddress
    h = (host or "").strip().strip("[]")
    if h in ("localhost", "ip6-localhost", "ip6-loopback"):
        return True
    try:
        ipaddress.ip_address(h)
    except ValueError:
        # try "a.b.c.d:port"
        if ":" in h:
            head = h.rsplit(":", 1)[0].strip("[]")
            try:
                ipaddress.ip_address(head)
                h = head
            except ValueError:
                return False
        else:
            return False
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_link_local or ip.is_loopback \
            or ip.is_unspecified or ip.is_reserved:
        return True
    if str(ip) == "255.255.255.255":
        return True
    # 169.254.0.0/16 (APIPA) and 224.0.0.0/4 are covered above; a bare
    # non-routable private address is also not a remote C2 endpoint
    return ip.is_private


def _looks_like_c2(host: str) -> bool:
    """Is this host even a CANDIDATE?

    W2 (RevAI review 2026-10-08): this used to BE the C2 decision, which made a
    denylist the only thing standing between a DNS query and a `c2:` basis tag.
    `example.org` passed it, as would every legitimate domain not on a ten-entry
    list. It is now only the first filter: surviving it makes a host a LEAD, and
    a lead only becomes C2 with communication semantics or independent evidence
    (see _promote_to_c2).
    """
    return not _is_reserved_or_noise(host)


# W1 (RevAI review 2026-10-08): the file-access bits that make an open a WRITE.
# These mirror WRITE_ACCESS_BITS in tools/frida_api_trace.py. They are restated
# rather than imported because findings.py is the host-side analysis plane and
# may not import VM-side tools; tests/test_w1_provenance.py asserts the two
# copies stay identical, so the restatement cannot drift silently.
_WRITE_BITS = 0x40000000 | 0x00000002 | 0x00000004 | 0x00000100
_READ_BITS = 0x80000000 | 0x00000001 | 0x00000008 | 0x00000080
# Create*-style APIs whose argument layout is unambiguous here: arg0 is the
# path, arg1 is dwDesiredAccess. NtCreateFile/ZwCreateFile are deliberately
# EXCLUDED - their access mask sits at a different offset, and guessing would
# reintroduce exactly the unproven-claim defect this fixes.
_BACKFILL_APIS = {"createfilew", "createfilea"}
# W1, second proof. A write-family call whose handle the tracer already resolved
# to a path (P1-F6's handlePaths) is positive evidence of writing that file,
# needing no access mask at all. Excluding it would DISCARD real drops - 683
# real WriteFile events across the packs on disk carry an attributed path, and
# one of them is b110's genuine Temp drop. Missing this is how a strict fix
# becomes a blind fix.
_WRITE_FAMILY_APIS = {"writefile", "writefileex", "writefilegather",
                      "ntwritefile", "flushfilebuffers", "fwrite", "fputs"}


def _backfill_provenance(dyn_dir: Path, max_lines: int = 200_000) -> list[dict]:
    """Reconstruct file-access provenance from the RAW trace.

    Every pack pulled before 2026-10-08 has the access mask in its
    frida_trace.jsonl - the tracer recorded it all along - but
    summarize_dynamic.py collapsed it into a flat decoded_paths list. Reading
    the raw trace recovers the proof instead of throwing away genuine evidence
    because of a lossy summary.

    Fails closed: a CreateFile whose access mask cannot be parsed yields no
    event, so its path stays unproven rather than being assumed a write.
    """
    tr = Path(dyn_dir) / "frida_trace.jsonl"
    if not tr.is_file():
        return []
    out: list[dict] = []
    try:
        with tr.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh):
                if n >= max_lines:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if not isinstance(ev, dict) or ev.get("type") != "call":
                    continue
                dec = ev.get("decoded") or {}
                api = str(ev.get("api") or "")
                if api.lower() in _WRITE_FAMILY_APIS:
                    # the handle was resolved to a path: that IS the write
                    p = dec.get("path")
                    if not isinstance(p, str) or not p:
                        continue
                    out.append({
                        "path": p,
                        "api": ev.get("api"),
                        "access": None,
                        "writes": True,
                        "reads": False,
                        "provenance": "write-to-attributed-path",
                        "source": "backfilled-from-raw-trace",
                    })
                    continue
                # ONLY a Create*-style API has (arg0=path, arg1=dwDesiredAccess).
                # Without this filter every hooked API's arg0/arg1 get read as
                # path + access mask, so LoadLibraryW and CreateProcessW would
                # INVENT "proven writes" from unrelated arguments - the same
                # class of invented evidence the W1 fix exists to remove.
                if api.lower() not in _BACKFILL_APIS:
                    continue
                path = dec.get("arg0")
                if not isinstance(path, str) or not path:
                    continue
                args = ev.get("args") or []
                if len(args) < 2 or args[1] is None:
                    continue          # no access mask: cannot prove anything
                try:
                    acc = int(str(args[1]), 16) if isinstance(args[1], str) \
                        else int(args[1])
                except (TypeError, ValueError):
                    continue          # unparseable mask: do not guess
                out.append({
                    "path": path,
                    "api": ev.get("api"),
                    "access": "0x%08x" % (acc & 0xFFFFFFFF),
                    "writes": bool(acc & _WRITE_BITS),
                    "reads": bool(acc & _READ_BITS),
                    "provenance": "access-mask",
                    "source": "backfilled-from-raw-trace",
                })
    except OSError:
        return []
    return out


# ------------------------------------------------------------- dbg findings

def dbg_findings(mode_root: Path, *, sha: str = "") -> dict:
    """Findings from the debug loop: did it unpack, and what did it get?"""
    basis: list[str] = []
    limitations: list[str] = []
    used: list[str] = []
    deep = _read(mode_root / "deep" / "deep.json") or {}
    if deep:
        used.append("deep.json")
    agent = deep.get("agent") or {}
    up = agent.get("unpack_prepass") or {}
    dbg = agent.get("dbg_ensure") or {}
    # recorded at deep-dive START, so we can tell "the debugger was
    # never available" (a product defect) from "the agent declined"
    dbg_ensure = deep.get("dbg_ensure") or dbg
    quick = _read(mode_root / "quick" / "quick.json") or {}
    if quick:
        used.append("quick.json")

    # The ROUTE is a property of the sample, not a judgement call: a .NET
    # assembly has no native OEP to find, so x64dbg's memory-execute
    # breakpoint method does not apply to it by design. Recording that as an
    # explicit verdict is what stops "unknown/low" from being read as "we
    # forgot to try", which is how this mode read for an entire run.
    pe = (quick.get("pe") or quick.get("evidence", {}).get("pe") or {})
    managed = bool(pe.get("is_dotnet")) or bool(quick.get("is_dotnet")) \
        or bool((quick.get("evidence") or {}).get("threat_intel", {})
                .get("is_dotnet"))
    # The route value is computed here and folded into `findings` below.
    # Assigning findings["route"] BEFORE the dict exists is the same
    # use-before-def mistake that made a successful detonation report
    # "did not run" - and the only thing that caught it was running the code.
    route = {
        "managed": managed,
        "native_unpack_applies": (not managed),
        "method": ("dotnet_analyze (managed IL) + windbg dumps"
                   if managed else
                   "x64dbg memory-execute BP unpack (native)"),
    }

    findings: dict = {
        "debugger": {"arch": dbg.get("arch"), "exe": dbg.get("exe"),
                     "launched": dbg.get("launched"),
                     "port": dbg.get("port"),
                     "ok": dbg.get("ok")},
        "unpack": {},
        "route": route,
    }

    if not dbg and not up:
        if dbg_ensure is not None:
            limitations.append(
                "the debugger was NOT available when the deep dive started: "
                f"{dbg_ensure.get('error') or dbg_ensure}. The agent could not "
                "have used it, so the absence of debugger evidence is a "
                "product defect, not a planner choice.")
        else:
            limitations.append(
                "no debugger evidence in this pack: the agent either never "
                "called a debug tool, or a later run overwrote this pack "
                "(fixed in evidence.MODES)")
        level, conf = UNKNOWN, "low"
        return _frame("dbg", sha, ok=False,
                      verdict=_verdict(level, conf, basis),
                      findings=findings, evidence_used=used,
                      limitations=limitations)

    # managed assembly: native unpack is not applicable, so the debug section
    # must say WHY there is no OEP instead of implying the unpack failed
    if managed and not up.get("ok"):
        basis.append("route:managed:dotnet")
        limitations.append(
            "a .NET assembly has no native OEP to recover, so the x64dbg "
            "memory-execute-bp unpack does not apply by design. The debug "
            "section's evidence is the dotnet_analyse IL/metadata read plus "
            "any windbg memory dump, not an OEP.")
        return _frame("dbg", sha, ok=True,
                      verdict=_verdict(SUSPICIOUS, "medium", basis),
                      findings=findings, evidence_used=used,
                      limitations=limitations)

    ok = bool(up.get("ok"))
    oep = up.get("oep")
    dump = up.get("dump_path")
    parse = up.get("dump_parse") or {}
    findings["unpack"] = {
        "ok": ok, "oep": oep, "method": up.get("method"),
        "dump": dump, "dump_source": up.get("dump_source"),
        "parses": parse.get("parses"),
        "imports": parse.get("imports"),
        "machine": parse.get("machine"),
    }
    if ok and oep:
        basis.append(f"unpack:oep:{oep}")
    if parse.get("parses"):
        basis.append(f"unpacked:parses:imports={parse.get('imports')}")

    if not ok:
        limitations.append(
            "the debugger ran but produced no usable dump: "
            f"{str(up.get('error'))[:160] if up.get('error') else 'no OEP'}")
        level, conf = SUSPICIOUS, "low"
    else:
        # a successful unpack raises confidence in any static conclusion
        level, conf = SUSPICIOUS, "medium"

    # packed_signal is a route hint, and the section it names is evidence
    ps = agent.get("packed_signal") or {}
    findings["packed_signal"] = ps
    if ps.get("packed_section"):
        basis.append(f"packed-section:{ps['packed_section'].get('name')}")

    return _frame("dbg", sha, ok=ok,
                  verdict=_verdict(level, conf, basis),
                  findings=findings, evidence_used=used, limitations=limitations)


# ---------------------------------------------------------- static findings

def static_findings(mode_root: Path, *, sha: str = "") -> dict:
    """Findings from a static run.

    Static is a first-class producer: Windows static RE with Windows emulation
    (capa, Ghida/IDA, speakeasy, floss) is materially stronger than the Remnux
    equivalent, and that platform advantage is part of WinRE's value. These
    findings carry the Windows-specific evidence that justifies keeping static
    in the pipeline at all.
    """
    basis: list[str] = []
    limitations: list[str] = []
    used: list[str] = []
    findings: dict = {}

    quick = _read(mode_root / "quick" / "quick.json") or {}
    deep = _read(mode_root / "deep" / "deep.json") or {}
    if quick:
        used.append("quick.json")
    if deep:
        used.append("deep.json")
    ev = (quick.get("evidence") or {}) if isinstance(quick, dict) else {}

    # --- capa, with ATTACK mapping ----------------------------------------
    capa = (ev.get("capa") or {})
    caps = []
    if isinstance(capa, dict):
        for c in capa.get("capabilities") or []:
            if not isinstance(c, dict):
                continue
            atk = [a for a in (c.get("attack") or []) if isinstance(a, str)]
            caps.append({"name": c.get("name"), "attack": atk,
                         "count": c.get("count")})
    findings["capa"] = caps
    for c in caps:
        if c["attack"]:
            basis.append("capa:" + str(c["name"])[:40])
    if not caps:
        limitations.append("capa returned no capabilities")

    # --- yara, weighted by reliability ------------------------------------
    yara = (ev.get("yara") or {})
    hits = []
    if isinstance(yara, dict):
        for h in yara.get("hits") or []:
            if not isinstance(h, dict):
                continue
            hits.append({"id": h.get("id"), "reliability": h.get("reliability"),
                         "type": h.get("type"),
                         "category": h.get("category")})
    findings["yara"] = hits
    for h in hits:
        if isinstance(h.get("reliability"), int) and h["reliability"] >= 60:
            basis.append(f"yara:{h.get('id')}")

    # --- malcat anomalies --------------------------------------------------
    mc = (ev.get("malcat") or {}) or {}
    f = (mc.get("file") or {}) if isinstance(mc, dict) else {}
    top = _bpb(f.get("entropy"))
    sections = []
    for s in f.get("layout") or []:
        b = _bpb(s.get("entropy"))
        if b is not None:
            sections.append({"name": s.get("name"), "bits_per_byte": b})
    anomalies = []
    for a in ((mc.get("anomalies") or []) if isinstance(mc, dict) else []):
        if isinstance(a, dict):
            anomalies.append({"name": a.get("name"), "level": a.get("level"),
                              "hits": a.get("num_hits")})
    findings["entropy"] = {"file_bits_per_byte": top, "sections": sections}
    findings["malcat_anomalies"] = anomalies
    for a in anomalies:
        if isinstance(a.get("level"), int) and a["level"] >= 3:
            basis.append(f"malcat:{a.get('name')}")
    for s in sections:
        if s["bits_per_byte"] >= _PACKED_SECTION_BPB:
            basis.append(f"packed-section:{s['name']}")

    # --- diec -------------------------------------------------------------
    diec = (ev.get("diec") or {}) or {}
    detects = [str(d) for d in (diec.get("detects") or [])]
    findings["diec"] = detects

    # --- emulation (the Windows advantage: run it, don't just read it) ----
    emu = (ev.get("emulation") or {}) or {}
    apis = emu.get("api_calls") or []
    emu_apis = apis if isinstance(apis, list) else []
    findings["emulation"] = {"api_calls": len(emu_apis),
                             "ok": bool(emu.get("ok"))}

    # --- what the deep dive itself concluded ------------------------------
    agent = deep.get("agent") or {}
    dv = deep.get("verdict")
    if dv:
        basis.append(f"deep:{dv}")
        findings["deep_verdict"] = {"verdict": dv, "confidence": deep.get("confidence"),
                                    "source": deep.get("source"),
                                    "engine": deep.get("engine")}
        used.append("deep.json verdict")
    for e in (deep.get("key_evidence") or [])[:6]:
        basis.append("evidence:" + (e if isinstance(e, str) else json.dumps(e))[:60])

    # Capa capabilities mapped to ATT&CK are independent evidence: a sample
    # that encodes with XOR/DES and walks the PEB has done something worth
    # reporting even when the deep dive declines to call it. Weighting them is
    # what keeps a static run from collapsing to `unknown` on real signal.
    attack_caps = [c for c in caps if c["attack"]]
    strong = [c for c in findings["yara"]
              if isinstance(c.get("reliability"), int) and c["reliability"] >= 60]
    high_lvl = [a for a in anomalies if isinstance(a.get("level"), int) and a["level"] >= 3]

    level, conf = UNKNOWN, "low"
    if dv == MALICIOUS or (strong and high_lvl):
        level, conf = MALICIOUS, "high"
    elif dv == SUSPICIOUS:
        level, conf = SUSPICIOUS, "medium"
    elif len(attack_caps) >= 4 or strong or high_lvl:
        level, conf = SUSPICIOUS, "medium"
    elif attack_caps or emu_apis:
        level, conf = SUSPICIOUS, "low"
    elif dv == BENIGN:
        level, conf = BENIGN, "medium" if basis else "low"

    tools = _host_tools()
    if not tools["floss"]:
        limitations.append("floss not on the analysis host; deobfuscated "
                           "strings come from the VM's floss run")
    if not tools["yara"]:
        limitations.append("yara not on the analysis host; rule hits come from "
                           "the VM's yara run")

    return _frame(("static" if mode_root.name == "static" else "agentic"),
                  sha, ok=bool(quick or deep),
                  verdict=_verdict(level, conf, basis), findings=findings,
                  evidence_used=used, limitations=limitations)


# ------------------------------------------------------------------ writer

_DISPATCH = {
    "static": static_findings,
    "agentic": static_findings,
    "dbg": dbg_findings,
    "dynamic": dynamic_findings,
}


def build(mode: str, pack_root: Path, *, sha: str = "",
          evidence_dir: Path | None = None) -> dict:
    """Extract findings for one mode and write <pack_root>/findings.json.

    `pack_root` is the MODE root (logs/<sha>/<mode>/): that is where the pack
    writes quick.json / deep.json and where compose.load_findings() and the UI
    read findings.json from. Every extractor receives the mode root;
    dynamic_findings descends to <mode_root>/dynamic/ itself, because that is
    the stage dir for every mode that has one.

    Returns the dict. Never raises: a mode that cannot be analysed returns
    ok=False with the reason, because a missing findings file is silent and
    silence is what made the dynamic section invisible for so long.
    """
    pack_root = Path(pack_root)
    evidence = Path(evidence_dir) if evidence_dir else pack_root / "dynamic"
    if mode not in _DISPATCH:
        return _frame(mode, sha, ok=False,
                      verdict=_verdict(UNKNOWN, "low", []),
                      findings={}, evidence_used=[],
                      limitations=[f"no findings extractor for mode {mode!r}"])
    try:
        out = _DISPATCH[mode](pack_root, sha=sha)
        # The mode is THIS function's parameter, authoritative. The extractors
        # used to infer it from the directory name, which worked while they
        # received the mode root - but they receive the evidence dir, so
        # static_findings would mislabel itself "agentic".
        out["mode"] = mode
    except Exception as e:
        out = _frame(mode, sha, ok=False,
                     verdict=_verdict(UNKNOWN, "low", []), findings={},
                     evidence_used=[],
                     limitations=[f"{type(e).__name__}: {str(e)[:200]}"])
    try:
        pack_root.mkdir(parents=True, exist_ok=True)
        (pack_root / "findings.json").write_text(
            json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
    except Exception as e:
        out.setdefault("limitations", []).append(
            f"could not write findings.json: {e}")
    return out


def build_for_sample(sha: str, logs_dir: Path) -> list[dict]:
    """Findings for every mode present under logs/<sha>/, in MODES order."""
    from winre.evidence import MODES
    base = Path(logs_dir) / sha
    out = []
    for m in MODES:
        root = base / m
        if root.is_dir():
            out.append(build(m, root, sha=sha))
    return out


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args:
        print("usage: python -m winre.findings <mode_root> [mode]")
        raise SystemExit(2)
    root = Path(args[0])
    mode = args[1] if len(args) > 1 else root.name
    sha = args[2] if len(args) > 2 else root.parent.name
    print(json.dumps(build(mode, root, sha=sha), indent=2, default=str))