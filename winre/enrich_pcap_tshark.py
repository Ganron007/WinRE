#!/usr/bin/env python3
"""Light tshark enrich over dynamic/network_raw/*.pcap -> network_intel.json.

Does not replace analyst Wireshark deep-dive (see ANALYST-NEXT).

Usage:
  python3 enrich_pcap_tshark.py /opt/samples/logs/<sha>/dynamic
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def tshark_available() -> str | None:
    return shutil.which("tshark")


def run_fields(pcap: Path, display_filter: str,
               fields: list[str]) -> dict[str, Any]:
    argv = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for f in fields:
        argv.extend(["-e", f])
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=120, errors="replace")
    except subprocess.TimeoutExpired as e:
        return {"ok": False, "values": [], "returncode": None,
                "error": f"timeout after {e.timeout}s"}
    except OSError as e:
        return {"ok": False, "values": [], "returncode": None,
                "error": f"could not start tshark: {e}"}
    lines = []
    for line in (cp.stdout or "").splitlines():
        line = line.strip()
        if line:
            lines.append(line)
    return {"ok": cp.returncode == 0, "values": lines,
            "returncode": cp.returncode,
            "error": None if cp.returncode == 0 else
                     ((cp.stderr or cp.stdout or "tshark failed")[-500:])}


def enrich_one(pcap: Path) -> dict[str, Any]:
    queries = {
        "dns": run_fields(pcap, "dns.qry.name", ["dns.qry.name"]),
        "http": run_fields(pcap, "http.request", ["http.host", "http.request.method", "http.request.uri"]),
        "tls_sni": run_fields(pcap, "tls.handshake.type == 1", ["tls.handshake.extensions_server_name"]),
    }
    dns = sorted(set(queries["dns"]["values"]))
    http = queries["http"]["values"]
    sni = sorted(set(queries["tls_sni"]["values"]))
    return {
        "pcap": pcap.name,
        "ok": all(result["ok"] for result in queries.values()),
        "filter_results": queries,
        "dns_queries": dns[:200],
        "http_requests": http[:200],
        "tls_sni": sni[:200],
        "counts": {"dns": len(dns), "http": len(http), "sni": len(sni)},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dynamic_dir", type=Path)
    args = ap.parse_args()
    dyn = args.dynamic_dir.resolve()
    raw = dyn / "network_raw"
    if not tshark_available():
        out = {
            "schema": "v6.2.1-network-intel",
            "status": "unavailable",
            "reason_code": "tool_unavailable",
            "ok": False,
            "error": "tshark not installed",
            "analyst_hint": "apt install tshark  # or use Wireshark GUI on the pcap",
        }
        (dyn / "network_intel.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print("tshark missing - wrote stub network_intel.json")
        return 1
    if not raw.is_dir():
        out = {"schema": "v6.2.1-network-intel", "status": "failed",
               "reason_code": "capture_directory_missing", "ok": False,
               "error": f"missing {raw}"}
        (dyn / "network_intel.json").write_text(
            json.dumps(out, indent=2) + "\n", encoding="utf-8")
        return 1
    pcaps = sorted(p for p in raw.rglob("*") if p.suffix.lower() in (".pcap", ".pcapng"))
    if not pcaps:
        out = {"schema": "v6.2.1-network-intel", "status": "failed",
               "reason_code": "capture_file_missing", "ok": False,
               "error": f"no pcap in {raw}"}
        (dyn / "network_intel.json").write_text(
            json.dumps(out, indent=2) + "\n", encoding="utf-8")
        return 1
    captures = [enrich_one(p) for p in pcaps]
    failures = [f"{capture['pcap']}:{name}:{result.get('error')}"
                for capture in captures
                for name, result in capture["filter_results"].items()
                if not result.get("ok")]
    ok = not failures
    out = {
        "schema": "v6.2.1-network-intel",
        "status": "completed" if ok else "failed",
        "ok": ok,
        "error": None if ok else "one or more tshark filters failed",
        "filter_failures": failures,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "captures": captures,
        "analyst_next": [
            "Deep stream analysis is analyst-driven - see ANALYST-NEXT.md network section",
            "tcpdump capture (ELF path): already in network_raw if elf job ran",
        ],
    }
    (dyn / "network_intel.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    # merge tip into network.json if present
    nj = dyn / "network.json"
    if nj.is_file():
        try:
            base = json.loads(nj.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            base = {}
        base["network_intel_ref"] = "network_intel.json"
        base["tshark_enrich"] = True
        nj.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {dyn / 'network_intel.json'} ({len(pcaps)} pcap; ok={ok})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
