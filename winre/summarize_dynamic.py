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
    endpoints: list[dict] = []
    # Keep a bounded event view for consumers, but aggregate every attributed
    # file event by path. This means a late successful write remains visible
    # even after thousands of earlier reads, while the raw JSONL stays the
    # authoritative event-level record.
    file_events: list[dict] = []
    successful_file_events: list[dict] = []
    file_effects: dict[str, dict] = {}
    pending: dict[str, dict] = {}
    hook_records: dict[str, dict] = {}
    coverage_tree: dict | None = None
    process_events: list[dict] = []
    calls = 0
    returns = 0
    malformed_lines = 0
    endpoint_count = 0
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
                malformed_lines += 1
                continue
            if not isinstance(ev, dict):
                malformed_lines += 1
                continue
            typ = ev.get("type")
            if typ == "coverage":
                hook_records[str(ev.get("pid") or "unknown")] = ev
                continue
            if typ == "coverage_tree":
                coverage_tree = ev
                continue
            if typ == "process":
                if len(process_events) < 100:
                    process_events.append(ev)
                continue
            if typ == "endpoint":
                endpoint_count += 1
                if len(endpoints) < 500:
                    endpoints.append({
                        "event_ref": ev.get("invocation_id"),
                        "api": ev.get("api"), "pid": ev.get("pid"),
                        "tid": ev.get("tid"), "decoded_key": ev.get("decoded_key"),
                        "address": ev.get("address"), "role": ev.get("role"),
                        "address_family": ev.get("address_family"),
                        "family_number": ev.get("family_number"),
                        "ip": ev.get("ip"), "port": ev.get("port"),
                        "scope_id": ev.get("scope_id"),
                        "caller": ev.get("caller"),
                        "scope": "sample-process-api-observation",
                    })
                    sockaddrs.append(str(ev.get("address") or ""))
                continue
            if typ == "ret":
                returns += 1
                inv = ev.get("invocation_id")
                call = pending.pop(str(inv), None) if inv else None
                if call is None:
                    continue
                call["return_ref"] = inv
                call["success"] = ev.get("success")
                call["bytes_written"] = ev.get("bytes_written")
                call["write_succeeded"] = bool(ev.get("write_succeeded"))
                call["effect"] = ev.get("effect") or "unknown"
                _aggregate_file_event(call, file_effects)
                if call["write_succeeded"]:
                    successful_file_events.append(call)
                continue
            if typ != "call":
                continue
            calls += 1
            api = ev.get("api") or "?"
            apis[api] += 1
            dec = ev.get("decoded") or {}
            if not isinstance(dec, dict):
                dec = {}
            for k, v in dec.items():
                if not isinstance(v, str) or not v:
                    continue
                if k == "sockaddr" or re.fullmatch(r"sockaddr\d+", str(k)):
                    sockaddrs.append(v)
                    endpoint_count += 1
                    if len(endpoints) < 500:
                        meta = dec.get(str(k).replace("sockaddr", "sockaddr_meta", 1))
                        meta = meta if isinstance(meta, dict) else {}
                        endpoints.append({
                            "event_ref": ev.get("invocation_id"),
                            "api": api, "pid": ev.get("pid"),
                            "tid": ev.get("tid"), "decoded_key": k,
                            "address": v,
                            "address_family": meta.get("family"),
                            "family_number": meta.get("family_number"),
                            "ip": meta.get("ip"),
                            "port": meta.get("port"),
                            "scope_id": meta.get("scope_id"),
                            "role": ("outbound" if str(api).lower() in
                                     {"connect", "connectex", "wsaconnect", "sendto"}
                                     else "inbound" if str(api).lower() in
                                     {"recvfrom", "accept", "acceptex"}
                                     else "unknown"),
                            "caller": ev.get("caller"),
                            "scope": "sample-process-api-observation",
                        })
                elif "\\" in v or "/" in v or v.endswith(".exe") or v.startswith("Software"):
                    paths.append(v)

            p = (dec.get("path") or dec.get("arg0") or dec.get("arg5")
                 or dec.get("arg1"))
            if not isinstance(p, str) or not p or ("\\" not in p and "/" not in p):
                continue
            inv = ev.get("invocation_id")
            record = {
                "path": p, "api": api,
                "event_ref": inv,
                "pid": ev.get("pid"), "tid": ev.get("tid"),
                "access": dec.get("access"),
                # `writes` is legacy intent only. Successful effects are
                # recorded separately after the invocation's return arrives.
                "writes": bool(dec.get("writes")),
                "write_intent": bool(dec.get("write_intent", dec.get("writes"))),
                "reads": bool(dec.get("reads")),
                "creation_disposition": dec.get("creation_disposition"),
                "provenance": dec.get("provenance") or
                    ("access-mask" if dec.get("access") is not None else "none"),
                "success": None, "write_succeeded": False,
                "bytes_written": None, "effect": "attempted",
            }
            if inv:
                pending[str(inv)] = record
            else:
                # Older traces lack invocation IDs and return records. Their
                # access mask still proves intent, never a completed effect.
                _aggregate_file_event(record, file_effects)
            if len(file_events) < 200:
                file_events.append(record)

    # A trace may stop between onEnter and onLeave (process exit, cap, or
    # Frida shutdown). Preserve the attempt and leave its effect unknown.
    for record in pending.values():
        _aggregate_file_event(record, file_effects)

    # Successful effects have priority in the bounded event view. Aggregates
    # include all calls, including those beyond both event-list limits.
    selected = successful_file_events[:200]
    selected_refs = {e.get("event_ref") for e in selected}
    if len(selected) < 200:
        remaining = [e for e in file_events
                     if e.get("event_ref") not in selected_refs]
        selected.extend(remaining[:200-len(selected)])

    max_unmatched = len(pending)
    return {
        "status": "ok",
        "calls": calls,
        "returns": returns,
        "unmatched_calls": max_unmatched,
        "malformed_lines": malformed_lines,
        "top_apis": apis.most_common(25),
        "decoded_paths": sorted(set(paths))[:80],
        "sockaddrs": sorted(set(sockaddrs))[:40],
        "network_endpoints": endpoints,
        "network_endpoint_count": endpoint_count,
        "network_endpoints_truncated": endpoint_count > len(endpoints),
        "decoded_paths_total": len(set(paths)),
        "decoded_paths_truncated": len(set(paths)) > 80,
        "file_events": selected,
        "file_events_total": sum(int(v.get("event_count", 0))
                                  for v in file_effects.values()),
        "file_events_truncated": sum(int(v.get("event_count", 0))
                                      for v in file_effects.values()) > len(selected),
        "file_effects": file_effects,
        "file_effects_truncated": False,
        "hook_coverage": _hook_coverage(
            list(hook_records.values()), apis, calls, coverage_tree),
        "coverage_tree": coverage_tree,
        "process_events": process_events,
    }


def _aggregate_file_event(event: dict, aggregates: dict[str, dict]) -> None:
    """Accumulate full-trace effects by path without treating intent as effect."""
    path = event.get("path")
    if not isinstance(path, str) or not path:
        return
    rec = aggregates.setdefault(path, {
        "path": path, "event_count": 0, "write_attempts": 0,
        "successful_writes": 0, "bytes_written": 0,
        "successful_opens": 0, "created_or_truncated": 0,
        "open_or_create_ambiguous": 0,
        "failed_calls": 0, "read_attempts": 0, "apis": [],
        "event_refs": [], "event_refs_truncated": False,
    })
    rec["event_count"] += 1
    if event.get("write_intent"):
        rec["write_attempts"] += 1
    if event.get("reads"):
        rec["read_attempts"] += 1
    if event.get("write_succeeded"):
        rec["successful_writes"] += 1
        try:
            rec["bytes_written"] += max(0, int(event.get("bytes_written") or 0))
        except (TypeError, ValueError):
            pass
    if event.get("effect") == "opened":
        rec["successful_opens"] += 1
    elif event.get("effect") == "created_or_truncated":
        rec["created_or_truncated"] += 1
    elif event.get("effect") == "created_if_absent_or_opened":
        # OPEN_ALWAYS / FILE_OPEN_IF can either create or reuse an existing
        # file. Preserve the successful call without claiming a drop.
        rec["open_or_create_ambiguous"] += 1
    if event.get("success") is False:
        rec["failed_calls"] += 1
    api = event.get("api")
    if api and api not in rec["apis"]:
        rec["apis"].append(api)
    ref = event.get("event_ref")
    if ref:
        if len(rec["event_refs"]) < 50:
            rec["event_refs"].append(ref)
        else:
            rec["event_refs_truncated"] = True


def _hook_coverage(records: list[dict], apis: Counter, calls: int,
                   tree: dict | None = None) -> dict:
    """Report requested-hook installation separately from observed calls."""
    if not records:
        return {"status": "unreported", "requested": [], "installed": [],
                "unavailable": [], "failures": [], "calls_observed": calls,
                "apis_fired": sorted(apis),
                "process_coverage_complete": (tree or {}).get("process_coverage_complete"),
                "coverage_tree": tree,
                "note": "trace predates structured Frida hook-coverage records"}
    requested = sorted({str(a) for r in records for a in (r.get("requested") or [])})
    installed = sorted({str(a) for r in records for a in (r.get("installed") or [])})
    unavailable = [{"pid": r.get("pid"), "api": a}
                   for r in records for a in (r.get("unavailable") or [])]
    failures = [{"pid": r.get("pid"), **(f if isinstance(f, dict) else {"error": str(f)})}
                for r in records for f in (r.get("failures") or [])]
    exports = []
    seen_exports = set()
    for r in records:
        for item in r.get("installed_exports") or []:
            if not isinstance(item, dict):
                continue
            key = (r.get("pid"), item.get("api"), item.get("module"), item.get("address"))
            if key not in seen_exports:
                seen_exports.add(key)
                exports.append({"pid": r.get("pid"), **item})
    fired = sorted(apis)
    limits = [int(r["max_calls"]) for r in records
              if str(r.get("max_calls", "")).isdigit()]
    max_calls = ((tree or {}).get("max_calls_total")
                 if tree else (sum(limits) if limits else None))
    processes = [{
        "pid": r.get("pid"), "installed": r.get("installed") or [],
        "unavailable": r.get("unavailable") or [],
        "failures": r.get("failures") or [],
        "modules_seen": r.get("modules_seen"),
        "module_observer": r.get("module_observer"),
    } for r in records]
    return {
        "status": "reported",
        "pid": records[0].get("pid") if len(records) == 1 else None,
        "requested": requested,
        "installed": installed,
        "installed_exports": exports[:1000],
        "unavailable": unavailable,
        "failures": failures,
        "not_fired": [api for api in installed if api not in fired],
        "calls_observed": calls,
        "apis_fired": fired,
        "max_calls": max_calls,
        "call_limit_reached": max_calls is not None and calls >= max_calls,
        "installation_ratio": (round(len(installed) / len(requested), 3)
                               if requested else None),
        "process_count": len(records), "processes": processes,
        "module_observer": ("active" if all(r.get("module_observer") == "active"
                                             for r in records) else "partial"),
        "process_coverage_complete": (tree or {}).get("process_coverage_complete"),
        "coverage_tree": tree,
        "scope": "requested exports across recorded processes; process-tree completeness is explicit",
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
