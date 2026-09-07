#!/usr/bin/env python3
"""pcap_beacon.py — C2 beaconing + HTTP schema extraction (KB: Wireshark
course methodology). Parses detonation pcaps via tshark and derives:

  * per-flow cadence stats (interval mean/jitter => beacon fingerprint)
  * HTTP request URIs + User-Agent strings (param schemas)
  * DNS query set (already in network_intel; kept consistent here)

Extends network_intel.json in the dynamic dir.

CLI: python pcap_beacon.py <dynamic_dir>
"""
from __future__ import annotations

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

TSHARK = None


def _tshark() -> str | None:
    global TSHARK
    if TSHARK is not None:
        return TSHARK
    for cand in (r"C:\Program Files\Wireshark\tshark.exe",
                 r"C:\tools\wireshark\tshark.exe"):
        if Path(cand).is_file():
            TSHARK = cand
            return cand
    try:
        import shutil
        TSHARK = shutil.which("tshark")
    except Exception:
        TSHARK = None
    return TSHARK


def _run_tshark(args: list[str], timeout: int = 300) -> str:
    exe = _tshark()
    if not exe:
        return ""
    try:
        p = subprocess.run([exe, *args], capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return p.stdout or ""
    except Exception:
        return ""


def analyze_pcaps(dyn_dir: Path) -> dict:
    raw = dyn_dir / "network_raw"
    pcaps = sorted(raw.glob("*.pcap*")) if raw.is_dir() else []
    if not pcaps and not list(dyn_dir.glob("*.pcap*")):
        return {"ok": False, "error": "no pcaps found"}
    if not pcaps:
        pcaps = sorted(dyn_dir.glob("*.pcap*"))
    if _tshark() is None:
        return {"ok": False, "error": "tshark not installed"}

    beacons: list[dict] = []
    http: dict = {"uris": [], "uas": []}
    dns: list[str] = []

    for pcap in pcaps[:8]:
        # per-flow packet timing: ip.src, ip.dst, tcp.dstport, frame.time_epoch
        out = _run_tshark(
            ["-r", str(pcap), "-T", "fields",
             "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.dstport", "-e", "tcp.len",
             "-Y", "tcp.len > 0", "-E", "occurrence=f"])
        flows: dict[tuple, list[float]] = {}
        for line in (out or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            try:
                ts = float(parts[0])
            except ValueError:
                continue
            key = (parts[1], parts[2], parts[3])
            flows.setdefault(key, []).append(ts)
        for (src, dst, dport), times in flows.items():
            if len(times) < 4:
                continue
            gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
            if not gaps:
                continue
            mean = statistics.mean(gaps)
            jitter = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
            # beacon heuristic: regular cadence (jitter < 40% of mean)
            if mean >= 5 and jitter < mean * 0.4:
                beacons.append({
                    "src": src, "dst": dst, "dst_port": dport,
                    "packets": len(times),
                    "interval_s": round(mean, 2),
                    "jitter_s": round(jitter, 2),
                    "cadence": f"~{round(mean)}s",
                    "note": "regular cadence — C2 beacon pattern candidate",
                })
        # HTTP: full URI + UA
        http_out = _run_tshark(
            ["-r", str(pcap), "-T", "fields",
             "-e", "http.request.full_uri", "-e", "http.user_agent",
             "-Y", "http.request", "-E", "occurrence=f"])
        for line in (http_out or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 1 and parts[0] and parts[0] not in http["uris"]:
                http["uris"].append(parts[0][:300])
            if len(parts) >= 2 and parts[1] and parts[1] not in http["uas"]:
                http["uas"].append(parts[1][:200])
        dns_out = _run_tshark(
            ["-r", str(pcap), "-T", "fields", "-e", "dns.qry.name",
             "-Y", "dns.qry.name", "-E", "occurrence=f"])
        for name in (dns_out or "").splitlines():
            if name.strip() and name.strip() not in dns:
                dns.append(name.strip()[:200])

    result = {
        "ok": True,
        "beacons": beacons[:10],
        "beacon_count": len(beacons),
        "http": {
            "uris": http["uris"][:15],
            "user_agents": http["uas"][:8],
            "uri_schema_note": ("check recurring GET/POST params across URIs — "
                                "param names are the C2 protocol schema"),
        },
        "dns_queries": dns[:30],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    # merge into network_intel.json (keep existing keys)
    ni_path = dyn_dir / "network_intel.json"
    ni = {}
    if ni_path.is_file():
        try:
            ni = json.loads(ni_path.read_text(encoding="utf-8")) or {}
        except json.JSONDecodeError:
            ni = {}
    ni["beacon_analysis"] = result
    ni_path.write_text(json.dumps(ni, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("dynamic_dir")
    args = ap.parse_args()
    print(json.dumps(analyze_pcaps(Path(args.dynamic_dir)), indent=2))