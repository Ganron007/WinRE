#!/usr/bin/env python3
"""Summarize Flare dynamic artifacts into network/procmon/frida JSON summaries."""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path


def summarize_frida(trace: Path) -> dict:
    apis: Counter = Counter()
    paths: list[str] = []
    sockaddrs: list[str] = []
    calls = 0
    if not trace.is_file():
        return {"status": "missing", "path": str(trace)}
    with trace.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("type") != "call":
                continue
            calls += 1
            api = ev.get("api") or "?"
            apis[api] += 1
            dec = ev.get("decoded") or {}
            for k, v in dec.items():
                if not isinstance(v, str) or not v:
                    continue
                if k == "sockaddr":
                    sockaddrs.append(v)
                elif "\\" in v or "/" in v or v.endswith(".exe") or v.startswith("Software"):
                    paths.append(v)
    return {
        "status": "ok",
        "calls": calls,
        "top_apis": apis.most_common(25),
        "decoded_paths": sorted(set(paths))[:80],
        "sockaddrs": sorted(set(sockaddrs))[:40],
    }


def summarize_procmon(csv_path: Path, sample_name: str) -> dict:
    if not csv_path.is_file() or csv_path.stat().st_size == 0:
        return {"status": "missing", "path": str(csv_path)}
    ops: Counter = Counter()
    paths: Counter = Counter()
    regs: Counter = Counter()
    procs: Counter = Counter()
    rows_total = 0
    rows_sample = 0
    try:
        with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows_total += 1
                pname = (row.get("Process Name") or row.get("Process") or "").strip()
                if sample_name and sample_name.lower() not in pname.lower():
                    # keep some global process creates
                    op = (row.get("Operation") or "").strip()
                    if op == "Process Create":
                        procs[pname] += 1
                    continue
                rows_sample += 1
                op = (row.get("Operation") or "").strip()
                path = (row.get("Path") or "").strip()
                ops[op] += 1
                if path:
                    if op.lower().startswith("reg") or "\\Registry\\" in path or path.startswith("HK"):
                        regs[path] += 1
                    else:
                        paths[path] += 1
                if op == "Process Create":
                    procs[path or pname] += 1
    except Exception as e:
        return {"status": "error", "error": str(e)}
    return {
        "status": "ok",
        "rows_total": rows_total,
        "rows_sample": rows_sample,
        "top_operations": ops.most_common(20),
        "top_paths": paths.most_common(40),
        "top_registry": regs.most_common(40),
        "process_creates": procs.most_common(20),
    }


def summarize_network(network_raw: Path) -> dict:
    if not network_raw.is_dir():
        return {"status": "missing", "reason": "network_raw absent"}
    all_files = [p for p in network_raw.rglob("*") if p.is_file()]
    files = [p.name for p in all_files]
    pcaps = [p.name for p in all_files
             if p.suffix.lower() in (".pcap", ".pcapng")]
    domains: list[str] = []
    # FakeNet HTML/txt logs sometimes embed hostnames
    host_re = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)\b")
    for p in all_files:
        if p.suffix.lower() not in (".txt", ".log", ".html", ".json"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")[:200_000]
        except Exception:
            continue
        for m in host_re.finditer(text):
            h = m.group(1).lower()
            if any(x in h for x in ("microsoft.", "windows.", "wpad.", "localhost")):
                continue
            if h.count(".") >= 1:
                domains.append(h)
    return {
        "status": "ok" if files else "empty",
        "policy": "lab_sink_only_no_open_internet",
        "sink": "FakeNet-NG on Flare",
        "files": files[:50],
        "pcaps": pcaps,
        "domains_guess": sorted(set(domains))[:50],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--sample-name", default="sample.exe")
    args = ap.parse_args()
    out = Path(args.out_dir)
    fr = summarize_frida(out / "frida_trace.jsonl")
    if fr.get("status") == "missing":
        fr = summarize_frida(out / "frida_trace.json")
    (out / "frida_summary.json").write_text(json.dumps(fr, indent=2), encoding="utf-8")
    pm = summarize_procmon(out / "procmon.csv", args.sample_name)
    (out / "procmon_summary.json").write_text(json.dumps(pm, indent=2), encoding="utf-8")
    net = summarize_network(out / "network_raw")
    (out / "network.json").write_text(json.dumps(net, indent=2), encoding="utf-8")
    print(json.dumps({"frida": fr.get("status"), "procmon": pm.get("status"), "network": net.get("status")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
