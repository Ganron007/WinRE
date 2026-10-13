"""Conservative static-hypothesis to dynamic-observation correlation.

This module creates cited candidate links only. It never changes a verdict,
and it does not call an exact match "confirmed" while packet-flow/caller
attribution and complete instrumentation lifetime are unavailable.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


_HOST_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
_IP_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_PATH_RE = re.compile(r"(?i)(?:[A-Z]:\\[^\s\"'<>|]{3,240}|%[A-Z_]+%\\[^\s\"'<>|]{3,240})")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]{4,500}")


def _read(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _canonical(kind: str, value: str) -> str:
    value = str(value or "").strip().strip(".,;:()[]{}<>")
    if kind == "host":
        if "://" in value:
            value = urlsplit(value).hostname or ""
        value = value.rstrip(".").lower()
        return value
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return ""
    if kind == "path":
        return value.replace("/", "\\").rstrip("\\").casefold()
    return value.casefold()


def _id(prefix: str, source: str, value: str) -> str:
    digest = hashlib.sha256(f"{source}\0{value}".encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _strings(value, path: str, out: list[dict], *, limit: int = 4000) -> None:
    """Collect bounded literal strings with their exact source locations."""
    if len(out) >= limit:
        return
    if isinstance(value, str):
        if value:
            out.append({"text": value[:2000], "source_ref": path})
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if len(out) >= limit:
                break
            _strings(item, f"{path}[{i}]", out, limit=limit)
    elif isinstance(value, dict):
        # Ignore metadata and retain only known string-bearing evidence keys.
        for key, item in value.items():
            if key in {"decoded_strings", "strings", "candidates", "string",
                       "urls", "domains", "value", "text"}:
                _strings(item, f"{path}.{key}", out, limit=limit)
            elif key in {"malcat", "floss", "strings_tool", "strings",
                         "xor_string_search", "ioc_extract", "pe"}:
                _strings(item, f"{path}.{key}", out, limit=limit)


def _hypotheses(quick: dict, deep: dict) -> list[dict]:
    raw: list[dict] = []
    evidence = quick.get("evidence") if isinstance(quick, dict) else {}
    _strings(evidence or {}, "quick/quick.json#/evidence", raw)
    # Agent history may add strings discovered by deterministic tools. Keep
    # only outputs from string/IOC tools and cite the exact history step.
    agent = deep.get("agent") if isinstance(deep, dict) else {}
    for h in (agent or {}).get("history") or []:
        if not isinstance(h, dict) or h.get("tool") not in {
                "strings_tool", "floss", "ioc_extract", "xor_string_search"}:
            continue
        _strings(h.get("result"),
                 f"deep/deep.json#/agent/history/{h.get('step')}/result", raw)

    hypotheses: dict[tuple[str, str], dict] = {}
    for record in raw:
        text = record["text"]
        ref = record["source_ref"]
        candidates: list[tuple[str, str]] = []
        for match in _URL_RE.finditer(text):
            value = match.group(0).rstrip(".,;:)]}")
            host = urlsplit(value).hostname or ""
            if host:
                candidates.append(("host", host))
        candidates.extend(("host", m.group(0)) for m in _HOST_RE.finditer(text))
        candidates.extend(("ip", m.group(0)) for m in _IP_RE.finditer(text))
        candidates.extend(("path", m.group(0)) for m in _PATH_RE.finditer(text))
        for kind, value in candidates:
            normalized = _canonical(kind, value)
            if not normalized:
                continue
            # Avoid low-value host fragments and single-label domains.
            if kind == "host" and ("." not in normalized or normalized.endswith(
                    (".example", ".test", ".invalid", ".localhost"))):
                continue
            key = (kind, normalized)
            row = hypotheses.setdefault(key, {
                "id": _id("hyp", kind, normalized), "kind": kind,
                "value": value, "normalized": normalized,
                "hypothesis": ("static network-contact candidate" if kind in
                               {"host", "ip"} else "static file-path candidate"),
                "source_refs": [],
            })
            if ref not in row["source_refs"] and len(row["source_refs"]) < 12:
                row["source_refs"].append(ref)
            if len(hypotheses) >= 500:
                break
        if len(hypotheses) >= 500:
            break
    return list(hypotheses.values())


def _observations(dyn: Path, fr: dict, ni: dict) -> list[dict]:
    observations: list[dict] = []

    def add(kind: str, value: str, source_ref: str, scope: str,
            event_ref=None, **extra) -> None:
        normalized = _canonical(kind, value)
        if not normalized or len(observations) >= 1500:
            return
        observations.append({
            "id": _id("obs", source_ref, normalized), "kind": kind,
            "value": value, "normalized": normalized,
            "source_ref": source_ref, "event_ref": event_ref,
            "scope": scope, **extra,
        })

    for i, endpoint in enumerate(fr.get("network_endpoints") or []):
        if not isinstance(endpoint, dict):
            continue
        value = str(endpoint.get("address") or "")
        direct_ip = endpoint.get("ip")
        if (isinstance(direct_ip, str) and direct_ip
                and endpoint.get("address_family") == "ipv6"):
            add("ip", direct_ip,
                f"dynamic/frida_summary.json#/network_endpoints/{i}",
                "sample-process-api-observation", endpoint.get("event_ref"),
                api=endpoint.get("api"), pid=endpoint.get("pid"),
                tid=endpoint.get("tid"),
                address_family=endpoint.get("address_family"),
                port=endpoint.get("port"), caller=endpoint.get("caller"),
                attribution="process API only; flow/caller unresolved")
        for ip_match in _IP_RE.finditer(value):
            add("ip", ip_match.group(0),
                f"dynamic/frida_summary.json#/network_endpoints/{i}",
                "sample-process-api-observation", endpoint.get("event_ref"),
                api=endpoint.get("api"), pid=endpoint.get("pid"),
                tid=endpoint.get("tid"), attribution="process API only; flow/caller unresolved")
        for host_match in _HOST_RE.finditer(value):
            add("host", host_match.group(0),
                f"dynamic/frida_summary.json#/network_endpoints/{i}",
                "sample-process-api-observation", endpoint.get("event_ref"),
                api=endpoint.get("api"), pid=endpoint.get("pid"),
                tid=endpoint.get("tid"), attribution="process API only; flow/caller unresolved")

    for ci, capture in enumerate(ni.get("captures") or []):
        if not isinstance(capture, dict):
            continue
        pcap = str(capture.get("pcap") or ci)
        for field in ("dns_queries", "tls_sni"):
            for j, value in enumerate(capture.get(field) or []):
                add("host", str(value),
                    f"dynamic/network_intel.json#/captures/{ci}/{field}/{j}",
                    "vm-wide-pcap", None, capture=pcap,
                    attribution="VM-wide capture; process/flow ownership unresolved")
        for j, line in enumerate(capture.get("http_requests") or []):
            host = str(line).split("\t", 1)[0].strip()
            if host:
                add("host", host,
                    f"dynamic/network_intel.json#/captures/{ci}/http_requests/{j}",
                    "vm-wide-pcap", None, capture=pcap,
                    attribution="VM-wide capture; process/flow ownership unresolved")

    for i, (path, effect) in enumerate((fr.get("file_effects") or {}).items()):
        if not isinstance(effect, dict) or not int(effect.get("successful_writes") or 0):
            continue
        add("path", str(path), f"dynamic/frida_summary.json#/file_effects/{i}",
            "sample-process-api-observation", (effect.get("event_refs") or [None])[0],
            attribution="sample-process API only; caller/control-flow unresolved",
            successful_writes=effect.get("successful_writes"))
    return observations


def build(pack_root: Path, *, run_id: str | None = None) -> dict:
    """Build exact-indicator relationships; all claims remain non-verdict."""
    root = Path(pack_root)
    quick = _read(root / "quick" / "quick.json")
    deep = _read(root / "deep" / "deep.json")
    hypotheses = _hypotheses(quick, deep)
    stage = _read(root / "dynamic" / "STAGE.json")
    if not stage:
        return {"schema": "winre-correlation/v1", "run_id": run_id,
                "status": "unverifiable", "hypotheses": hypotheses,
                "observations": [], "relationships": [],
                "limitations": ["no current-run dynamic terminal record"]}
    if stage.get("ran") is False:
        return {"schema": "winre-correlation/v1", "run_id": run_id,
                "status": "not_requested" if stage.get("skipped") == "not requested"
                else "unverifiable", "hypotheses": hypotheses,
                "observations": [], "relationships": [],
                "limitations": [stage.get("summary") or stage.get("skipped") or
                                "dynamic stage did not run"]}
    if run_id and stage.get("run_id") != run_id:
        return {"schema": "winre-correlation/v1", "run_id": run_id,
                "status": "unverifiable", "hypotheses": hypotheses,
                "observations": [], "relationships": [],
                "limitations": ["dynamic terminal record is missing or belongs to another run"]}

    dyn = root / "dynamic"
    fr = _read(dyn / "frida_summary.json")
    ni = _read(dyn / "network_intel.json")
    observations = _observations(dyn, fr, ni)
    coverage = _read(dyn / "manifest.json").get("coverage") or {}
    fr_cov = fr.get("hook_coverage") or {}
    lifecycle_complete = bool(fr_cov.get("process_coverage_complete"))
    network_complete = ((coverage.get("network") or {}).get("status") == "complete"
                        or (coverage.get("external_capture") or {}).get("status") == "complete")
    frida_complete = (coverage.get("frida") or {}).get("status") == "complete"
    coverage_adequate = bool(lifecycle_complete and network_complete and frida_complete
                             and not fr_cov.get("unavailable")
                             and not fr_cov.get("failures")
                             and not fr_cov.get("call_limit_reached"))

    by_key: dict[tuple[str, str], list[dict]] = {}
    for obs in observations:
        by_key.setdefault((obs["kind"], obs["normalized"]), []).append(obs)
    relationships: list[dict] = []
    for hyp in hypotheses:
        matches = by_key.get((hyp["kind"], hyp["normalized"])) or []
        if matches:
            status = "unverifiable"
            reason = ("exact indicator match exists, but its sample execution/caller "
                      "relationship is not established by current capture attribution")
        elif coverage_adequate:
            status = "predicted_not_observed"
            reason = "not present in the recorded sensor window; this is not proof of absence"
        else:
            status = "unverifiable"
            reason = "no exact match, and instrumentation/capture coverage is insufficient to call it absent"
        relationships.append({
            "id": _id("rel", hyp["id"], status),
            "status": status, "hypothesis_id": hyp["id"],
            "hypothesis_refs": hyp["source_refs"],
            "observation_ids": [m["id"] for m in matches[:20]],
            "observation_refs": [m["source_ref"] for m in matches[:20]],
            "reason": reason,
        })

    hyp_keys = {(h["kind"], h["normalized"]) for h in hypotheses}
    for obs in observations:
        if (obs["kind"], obs["normalized"]) in hyp_keys:
            continue
        status = ("observed_not_predicted"
                  if obs["scope"] == "sample-process-api-observation"
                  else "unverifiable")
        relationships.append({
            "id": _id("rel", obs["id"], status), "status": status,
            "hypothesis_id": None, "hypothesis_refs": [],
            "observation_ids": [obs["id"]],
            "observation_refs": [obs["source_ref"]],
            "reason": ("dynamic sample-process API indicator has no exact static "
                       "counterpart" if status == "observed_not_predicted" else
                       "dynamic observation is not attributable to the sample"),
        })

    limitations = []
    if not lifecycle_complete:
        limitations.append("Frida coverage does not yet prove late-module/child-process instrumentation lifetime")
    if not network_complete:
        limitations.append("network capture coverage is incomplete or not current-run validated")
    if not frida_complete:
        limitations.append("Frida primary artifact coverage is incomplete")
    if any(o["scope"] == "vm-wide-pcap" for o in observations):
        limitations.append("pcap observations are VM-wide; matching a static host does not prove the sample made the flow")
    if any(r["status"] == "unverifiable" for r in relationships):
        limitations.append("no relationship is promoted to confirmed without process/flow/caller attribution")
    return {
        "schema": "winre-correlation/v1", "run_id": run_id,
        "status": "complete" if coverage_adequate else "partial",
        "coverage": {"adequate_for_negative_claim": coverage_adequate,
                     "frida": (coverage.get("frida") or {}).get("status"),
                     "network": (coverage.get("network") or {}).get("status"),
                     "process_lifecycle": "complete" if lifecycle_complete else "unproven"},
        "hypotheses": hypotheses, "observations": observations,
        "relationships": relationships,
        "counts": {s: sum(1 for r in relationships if r.get("status") == s)
                   for s in ("confirmed", "predicted_not_observed",
                             "observed_not_predicted", "unverifiable")},
        "limitations": limitations,
        "policy": "candidate links only; this artifact never changes the verdict",
    }
