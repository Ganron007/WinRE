#!/usr/bin/env python3
"""reporting.py — RevAI-contract reporting for WinRE evidence packs.

Generates per-sample artifacts mirroring RevAI's static reporting contract
(same method, same names), with a reserved dynamic section that populates
once the detonation stage exists:

  01-tools-raw.json   full, untruncated tool outputs (quick + deep)
  stage_trace.json    per-stage trace (tool, args, result/error, timing)
  iocs.json           deterministic IOC extraction (no LLM)
  REPORT-TECHNICAL-v3.md   multi-section cited markdown (RevAI v3 layout)
  AUDIT-REPORT.md     human audit narrative from audit.json
  EVIDENCE-BUNDLE.md  per-evidence-item index with provenance

The report is rendered deterministically from run artifacts. Every factual
line carries field-level evidence keys, and a separate configured-model review
checks the exact draft against those source-bound fields. The reviewer never
rewrites the report; an unsupported or unreviewed claim makes the final audit
red.
"""
from __future__ import annotations

import json
import hashlib
import re
import time
from pathlib import Path
from typing import Any

from .evidence import sha_of

URL_RE = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[^\s\"'<>`]{4,200}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
                   r"(?::\d{1,5})?")
SHA_RE = re.compile(r"\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b", re.IGNORECASE)
PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\[^\s\"'<>|*:?\[\]]{2,160}|/opt/[^\s\"'<>]{2,160}|"
    r"%[A-Z_]+%\\[^\s\"'<>]{2,160})")
MUTEX_RE = re.compile(r"(?:Global|Local)\\\\?[^\s\"'<>]{2,120}")
REGISTRY_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"'<>]{2,160}")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.){1,}(?:com|net|org|io|ru|cn|xyz|top|info|biz|su|cc|pw|me|tk|online|site|club|link)\b",
                       re.IGNORECASE)

# The claim review shows the reviewer one evidence excerpt per locator and
# REJECTS a truncated one (report_quality caps an excerpt at 6,000 chars).
# A locator that points at a whole array is therefore never verifiable, so
# the builder refuses to publish one.
REVIEW_EXCERPT_LIMIT = 6000


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_tools_raw(pack_root: Path) -> dict:
    """01-tools-raw.json — full untruncated tool outputs (quick + deep)."""
    out: dict = {"schema": "winre-tools-raw/v1", "generated_at": _utc()}
    q = _load(pack_root / "quick" / "quick.json") or {}
    out["quick"] = {"evidence": q.get("evidence") or {},
                    "tool_failures": q.get("tool_failures") or []}
    d = _load(pack_root / "deep" / "deep.json") or {}
    agent = d.get("agent") or {}
    history = []
    for h in (agent.get("history") or []):
        history.append({"step": h.get("step"), "tool": h.get("tool"),
                        "args": h.get("args"),
                        "result": h.get("result"),  # FULL, untruncated
                        "error": h.get("error"),
                        "reason": h.get("reason")})
    out["deep"] = {"source": agent.get("source"),
                   "verdict": agent.get("verdict"),
                   "verdict_judged_by": agent.get("verdict_judged_by"),
                   "judgment_pass_error": agent.get("judgment_pass_error"),
                   "planner_draft": agent.get("planner_draft"),
                   "debug_run": agent.get("debug_run"),
                   "llm_roles": agent.get("llm_roles"),
                   "llm_analysis": agent.get("llm_analysis"),
                   "tool_calls": agent.get("tool_calls"),
                   "history": history,
                   "mcp": d.get("mcp"), "engine": d.get("engine")}
    (pack_root / "deep" / "01-tools-raw.json").write_text(
        json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
    return {"ok": True, "path": str(pack_root / "deep" / "01-tools-raw.json"),
            "deep_history_len": len(history)}


def write_stage_trace(pack_root: Path) -> dict:
    """stage_trace.json — per-stage wrapper trace with all stage metadata."""
    stages = {}
    for stage in ("intake", "quick", "deep", "dynamic", "yara", "report"):
        for name in ("STAGE.json", "META.json"):
            m = _load(pack_root / stage / name)
            if m is not None:
                stages[stage] = {"file": name, **m}
                break
    out = {"schema": "winre-stage-trace/v1", "generated_at": _utc(),
           "stages": stages}
    (pack_root / "stage_trace.json").write_text(
        json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
    return {"ok": True, "stages": list(stages.keys())}


def extract_iocs(quick: dict, deep: dict, dynamic: dict | None) -> dict:
    """Extract static indicator candidates with exact source provenance.

    LLM-written analysis is never an IOC source. VM-wide packet captures are
    retained separately as unattributed observations; they are not promoted
    into sample IOC lists without process-level attribution.
    """
    categories = {
        "urls": set(), "ips": set(), "domains": set(), "emails": set(),
        "file_paths": set(), "mutexes": set(), "registry_keys": set(),
        "hashes": set(),
    }
    provenance: dict[tuple[str, str], set[str]] = {}

    def add(category: str, value: str, source_ref: str) -> None:
        value = str(value).strip()
        if not value:
            return
        categories[category].add(value)
        provenance.setdefault((category, value), set()).add(source_ref)

    def scan_text(text: str, source_ref: str) -> None:
        # Preserve conventional digest indicators found in sample-derived
        # static text. Accept only common digest lengths; arbitrary 33–63
        # character hex runs are not a recognized file-hash format.
        for value in SHA_RE.findall(text):
            add("hashes", value.lower(), source_ref)
        for value in URL_RE.findall(text):
            add("urls", value.rstrip(".,;)"), source_ref)
        for value in IP_RE.findall(text):
            if not value.startswith(("0.", "127.", "255.")):
                add("ips", value, source_ref)
        for value in EMAIL_RE.findall(text):
            email = value.lower()
            add("emails", email, source_ref)
            add("domains", email.split("@")[-1], source_ref)
        for value in PATH_RE.findall(text):
            add("file_paths", value.rstrip("\\/"), source_ref)
        for value in MUTEX_RE.findall(text):
            add("mutexes", value, source_ref)
        for value in REGISTRY_RE.findall(text):
            add("registry_keys", value.rstrip("\\/"), source_ref)
        for value in DOMAIN_RE.findall(text):
            add("domains", value.lower(), source_ref)

    q = (quick or {}).get("evidence") or {}
    mal = q.get("malcat") or {}
    for index, value in enumerate(mal.get("strings") or []):
        if isinstance(value, str):
            scan_text(value, f"quick/quick.json#$.evidence.malcat.strings[{index}]")
    for tool_name, field in (("floss", "decoded_strings"),
                             ("strings", "strings")):
        values = (q.get(tool_name) or {}).get(field) or []
        for index, value in enumerate(values):
            if isinstance(value, str):
                scan_text(value, f"quick/quick.json#$.evidence.{tool_name}.{field}[{index}]")
    for index, candidate in enumerate(
            (q.get("xor_string_search") or {}).get("candidates") or []):
        if isinstance(candidate, dict) and isinstance(candidate.get("string"), str):
            scan_text(candidate["string"],
                      f"quick/quick.json#$.evidence.xor_string_search.candidates[{index}].string")
    version_info = (q.get("pe") or {}).get("version_info") or {}
    if isinstance(version_info, dict):
        # The compact metadata object preserves exact fields while avoiding
        # invalid JSON-path expressions for arbitrary version-info keys.
        source_ref = "quick/quick.json#$.evidence.pe.version_info"
        for key, value in version_info.items():
            scan_text(f"{key}={value}", source_ref)

    limits = {"urls": 80, "ips": 80, "domains": 80, "emails": 40,
              "file_paths": 60, "mutexes": 40, "registry_keys": 40,
              "hashes": 20}
    indicators = []
    for category in sorted(categories):
        for value in sorted(categories[category])[:limits[category]]:
            indicators.append({
                "category": category,
                "value": value,
                "attribution": "sample-embedded-static-data",
                "evidence_refs": sorted(provenance.get((category, value), set())),
            })

    network_observations = []
    network_intel = (dynamic or {}).get("network_intel") or {}
    captures = network_intel.get("captures") or []
    for capture_index, capture in enumerate(captures):
        if not isinstance(capture, dict):
            continue
        for field, kind in (("dns_queries", "dns"), ("http_requests", "http"),
                            ("tls_sni", "tls_sni")):
            for observation_index, value in enumerate(capture.get(field) or []):
                if value in (None, ""):
                    continue
                network_observations.append({
                    "kind": kind,
                    "value": str(value),
                    "capture_index": capture_index,
                    "capture": str(capture.get("name") or capture.get("interface") or ""),
                    "scope": str(capture.get("scope") or capture.get("capture_scope")
                                  or "vm-wide-pcap"),
                    "attribution": "unresolved",
                    "eligible_as_sample_ioc": False,
                    "evidence_ref": (
                        f"dynamic/network_intel.json#$.captures[{capture_index}]."
                        f"{field}[{observation_index}]"),
                })

    result = {
        "schema": "winre-iocs/v2",
        "generated_at": _utc(),
        **{name: sorted(values)[:limits[name]]
           for name, values in categories.items()},
        "indicator_count": len(indicators),
        "network_observation_count": len(network_observations),
        "indicators": indicators,
        "network_observations": network_observations,
        "sources": ["malcat_strings", "floss_decoded_strings", "strings_tool",
                    "xor_string_search", "pe_version_info"],
        "excluded_sources": ["agent_llm_narrative", "vm_wide_packet_capture"],
    }
    return result


def _cite(raw_path: str, note: str) -> str:
    return f"{note} — raw: `{raw_path}`"


def _raw_frida_refs(*, event_refs: list | tuple | None = None,
                    apis: list | tuple | None = None) -> list[str]:
    """Locators into the raw Frida trace for observed events / APIs.

    An @api selector only resolves for an actual API name. The dynamic verdict
    basis mixes API names with non-API labels ("gate:drop:CreateFileW",
    "unpack:oep:0x8b2003", "packed-section:overlay"); building
    "@api=gate:drop:CreateFileW" produced a locator that resolves to no rows,
    which the audit refuses (2026-10-24 dynamic run, claim C0053).
    """
    refs = []
    for event_ref in event_refs or []:
        value = str(event_ref).strip()
        if value and len(value) <= 256 and "#" not in value:
            refs.append(f"dynamic/frida_trace.jsonl#@invocation_id={value}")
    for api in apis or []:
        value = str(api).strip()
        if (value and len(value) <= 128 and "#" not in value
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)):
            refs.append(f"dynamic/frida_trace.jsonl#@api={value}")
    return list(dict.fromkeys(refs))


def build_report_v3(pack_root: Path, *, review_claims: bool = True) -> dict:
    """Build and claim-review REPORT-TECHNICAL-v3.md from this pack's evidence."""
    sha = sha_of(pack_root)
    intake = _load(pack_root / "intake" / "intake.json") or {}
    quick = _load(pack_root / "quick" / "quick.json") or {}
    ev = quick.get("evidence") or {}
    # Merge deep-tool results (history results keyed by tool) so report
    # sections see supplemental deep evidence (crypto/decrypt-gate/IOC).
    deep = _load(pack_root / "deep" / "deep.json") or {}
    deep_ev = {}
    history_refs_by_tool: dict[str, list[str]] = {}
    deep_history = (deep.get("agent") or {}).get("history") or []
    for history_index, h in enumerate(deep_history):
        res = h.get("result")
        if isinstance(res, dict) and h.get("tool"):
            tool_name = str(h["tool"])
            deep_ev[tool_name] = res
            history_refs_by_tool.setdefault(tool_name, []).append(
                f"deep/deep.json#$.agent.history[{history_index}].result")
    ev = {**ev, **deep_ev}
    agent = (deep.get("agent") or {})
    verdict = agent.get("verdict") or {}
    if not isinstance(verdict, dict):
        verdict = {"verdict": verdict or "unknown"}
    src = agent.get("source") or "deterministic_fallback"
    iocs = _load(pack_root / "report" / "iocs.json") or {}
    yara_rep = _load(pack_root / "yara" / "rule_report.json") or {}
    dyn = _load(pack_root / "dynamic" / "META.json")
    dyn_stage = _load(pack_root / "dynamic" / "STAGE.json") or {}
    has_dynamic = bool(
        dyn_stage.get("detonation_ran") is True
        or (dyn or {}).get("detonation_ran") is True
        or (dyn or {}).get("sample_pid"))
    pack_mode = pack_root.name
    finding_record = _load(pack_root / "findings.json") or {}
    # findings.build writes the mode-specific finding object directly at
    # findings.json -> findings. The dynamic producer's run/evidence flags are
    # therefore direct children, not nested beneath a second "dynamic" key.
    dynamic_findings = ((finding_record.get("findings") or {})
                        if pack_mode == "dynamic" else {})
    dynamic_requested = bool(
        pack_mode == "dynamic"
        or (dyn_stage and dyn_stage.get("skipped") != "not requested")
    )
    dynamic_observed = bool(
        has_dynamic or dynamic_findings.get("run_observed") is True
    )
    dynamic_complete = bool(
        dynamic_observed
        and dynamic_findings.get("ok") is True
        and dynamic_findings.get("evidence_complete") is True
    )
    phase = (
        "static+dynamic" if dynamic_complete else
        "static+dynamic-incomplete" if dynamic_requested or dynamic_observed else
        "static+debugger" if pack_mode == "dbg" else
        # otherwise the phase IS the pack's mode - the evidence (META.json
        # $.mode) states it verbatim. A composed label ("static+agentic")
        # is a derivation the reviewer cannot confirm from the excerpts.
        pack_mode
    )
    composition = _load(pack_root / "composite.json") or {}
    selected_level = composition.get("level") or verdict.get("verdict")
    selected_confidence = (composition.get("confidence")
                           or verdict.get("confidence"))
    # The selected verdict comes from ONE mode's composite. Several modes can
    # be present in one pack (a static run corroborates an agentic one), so
    # the source label must be the mode that DECIDED the composite, not the
    # first mode in the selection map: a label naming a different mode
    # contradicts the evidence and the reviewer rejects the claim.
    selection = composition.get("selection") or {}
    selected_modes = [name for name, rec in selection.items()
                      if isinstance(rec, dict) and rec.get("selected")]
    selected_source = (composition.get("deciding_mode")
                       or (selected_modes[0] if selected_modes else None)
                       or ("mode-composite" if composition.get("level")
                           else src))
    raw = pack_root / "deep" / "01-tools-raw.json"

    L: list[str] = []
    locator_ids: dict[str, str] = {}
    claim_rows: list[dict] = []
    # A locator whose evidence excerpt exceeds the review limit is rejected by
    # the claim reviewer, so the claim can never be supported. The builder
    # records every over-broad locator it refused so the report states it
    # instead of shipping a claim the reviewer cannot verify.
    over_broad_refs: list[str] = []
    active_refs: tuple[str, ...] = ()
    reference_cache: dict[str, bool] = {}
    evidence_json_cache: dict[Path, Any] = {}
    unresolved_requested_refs: list[str] = []

    def _reference_exists(reference: str) -> bool:
        rel, sep, pointer = reference.partition("#")
        if not sep or not rel or not pointer:
            return False
        root = pack_root.resolve()
        path = (root / rel).resolve()
        if root not in path.parents or not path.is_file():
            return False
        if path.suffix.lower() == ".jsonl":
            from .report_quality import reference_exists
            return reference_exists(pack_root, reference)
        if path not in evidence_json_cache:
            try:
                evidence_json_cache[path] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                evidence_json_cache[path] = None
        decoded = evidence_json_cache[path]
        if decoded is None:
            return False
        try:
            from .report_quality import resolve_value
            return bool(resolve_value(decoded, pointer))
        except ValueError:
            return False

    def _excerpt_too_large(reference: str) -> bool:
        """True when the evidence a locator points at cannot be shown whole.

        report_quality caps an evidence excerpt at 6,000 characters and
        REJECTS a truncated excerpt ("partial excerpt support a claim"), so
        a locator that points at a whole array makes its claim
        unverifiable whatever the reviewer answers. Builders must narrow
        broad locators; this measures the excerpt so a broad one is never
        published. Unmeasurable refs (JSONL selectors) are not over-broad.
        """
        rel, sep, pointer = reference.partition("#")
        if not sep or not rel or not pointer:
            return False
        path = (pack_root / rel).resolve()
        if not path.is_file():
            return False
        if path not in evidence_json_cache:
            try:
                evidence_json_cache[path] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                evidence_json_cache[path] = None
        decoded = evidence_json_cache.get(path)
        if decoded is None:
            return False
        try:
            from .report_quality import resolve_value
            values = resolve_value(decoded, pointer)
        except (ValueError, TypeError):
            return False
        if not values:
            return False
        size = len(json.dumps(values if len(values) > 1 else values[0],
                              ensure_ascii=False, sort_keys=True, default=str))
        return size > REVIEW_EXCERPT_LIMIT

    def _narrow_reference(reference: str, claim: str) -> list[str]:
        """Replace broad source objects with exact fields containing claim literals."""
        required_literals = [value.strip().casefold()
                             for value in re.findall(r"`([^`]{3,200})`", claim)
                             if value.strip()]
        # Only narrow on explicit values printed in the claim. Generic words
        # such as "network", "process", or "injection" can occur in unrelated
        # records and are not a safe basis for selecting evidence fields.
        required_literals = list(dict.fromkeys(required_literals))[:20]
        if not required_literals:
            return [reference]
        rel, sep, pointer = reference.partition("#")
        if not sep or not any(marker in pointer for marker in (
                "$.evidence", "$.agent.history[*].result", "$.captures[*]",
                "$.file_effects")):
            return [reference]
        root = pack_root.resolve()
        path = (root / rel).resolve()
        if root not in path.parents or not path.is_file():
            return [reference]
        if path not in evidence_json_cache:
            try:
                evidence_json_cache[path] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                evidence_json_cache[path] = None
        value = evidence_json_cache.get(path)
        if value is None:
            return [reference]
        try:
            from .report_quality import _tokens
            tokens = _tokens(pointer)
            nodes: list[tuple[Any, str]] = [(value, "$")]
            for token in tokens:
                next_nodes: list[tuple[Any, str]] = []
                for node, node_path in nodes:
                    if token == "*" and isinstance(node, list):
                        next_nodes.extend((child, f"{node_path}[{index}]")
                                           for index, child in enumerate(node[:200]))
                    elif token.isdigit() and isinstance(node, list) \
                            and int(token) < len(node):
                        next_nodes.append((node[int(token)], f"{node_path}[{token}]"))
                    elif isinstance(node, dict) and token in node:
                        if not re.fullmatch(r"[A-Za-z0-9_:-]+", token):
                            continue
                        next_nodes.append((node[token], f"{node_path}.{token}"))
                nodes = next_nodes[:200]
            found: dict[str, set[str]] = {}
            visited = 0

            def scan(node: Any, node_path: str) -> None:
                nonlocal visited
                visited += 1
                if len(found) >= 64 or visited > 10000:
                    return
                if isinstance(node, str):
                    lower = node.casefold()
                    matched = {literal for literal in required_literals
                               if literal in lower}
                    if matched:
                        found[f"{rel}#{node_path}"] = matched
                elif isinstance(node, dict):
                    for key, child in node.items():
                        name = str(key)
                        if re.fullmatch(r"[A-Za-z0-9_:-]+", name):
                            scan(child, f"{node_path}.{name}")
                elif isinstance(node, list):
                    for index, child in enumerate(node):
                        scan(child, f"{node_path}[{index}]")

            for node, node_path in nodes:
                scan(node, node_path)
            # A narrowed citation is only used when the selected leaf fields
            # themselves cover every printed value. Otherwise retain the
            # original source object and let the claim reviewer fail closed.
            matched_literals = set().union(*found.values()) if found else set()
            if (found and set(required_literals).issubset(matched_literals)
                    and all(_reference_exists(found_ref) for found_ref in found)):
                return list(found)
        except (ValueError, TypeError):
            pass
        return [reference]

    def _coverage_refs(*, gaps_only: bool = False) -> list[str]:
        """Per-name coverage locators.

        The coverage map is ~6.3 KB - one claim short of the review limit -
        and the reviewer rejects a truncated excerpt, so the map is cited
        name by name (each entry is ~220 chars).
        """
        inventory = _load(pack_root / "artifact-manifest.json") or {}
        coverage = inventory.get("coverage") or {}
        refs: list[str] = []
        for name, row in coverage.items():
            if not isinstance(row, dict):
                continue
            if gaps_only and not (row.get("requested")
                                  and row.get("status") != "complete"):
                continue
            refs.extend([
                f"artifact-manifest.json#$.coverage.{name}.requested",
                f"artifact-manifest.json#$.coverage.{name}.status",
            ])
        return refs

    def set_evidence(*refs: str) -> None:
        nonlocal active_refs
        accepted = []
        for ref in dict.fromkeys(str(ref).strip() for ref in refs
                                 if str(ref).strip()):
            if ref not in reference_cache:
                reference_cache[ref] = _reference_exists(ref)
            if not reference_cache[ref]:
                if ref not in unresolved_requested_refs:
                    unresolved_requested_refs.append(ref)
                continue
            # A locator the reviewer cannot see is worse than no locator: the
            # claim review REJECTS a truncated excerpt, so an over-broad
            # reference makes the claim unverifiable no matter what the
            # reviewer answers, and the audit gate then refuses the run.
            # (First live static acceptance run, s02 2026-10-21: 16 of 79
            # claims unverifiable for exactly this reason.) Keep only refs
            # whose evidence excerpt fits the review limit; refs this builder
            # cannot measure (JSONL selectors) are kept as they are.
            if _excerpt_too_large(ref):
                if ref not in over_broad_refs:
                    over_broad_refs.append(ref)
                continue
            accepted.append(ref)
        active_refs = tuple(accepted)

    raw_frida_refs = _raw_frida_refs

    def A(line: str) -> None:
        """Append report prose with stable locators for its source fields."""
        text = str(line)
        if "\n" in text or "\r" in text:
            # One A() call is ONE report line: a multi-line error string
            # (floss crashed with an ASCII-art banner) used to split its
            # claim into three visible lines that no longer matched the
            # claim ledger (2026-10-27 s08 static M0001/U0001-3).
            lead = text[:len(text) - len(text.lstrip())]
            text = lead + re.sub(r"\s+", " ", text.strip())
        stripped = text.strip()
        structural = (not stripped or stripped.startswith(("#", "```"))
                      or bool(re.fullmatch(r"\|[\s:|\-]+\|", stripped)))
        if not structural and active_refs:
            ids = []
            claim_refs = []
            for active_ref in active_refs:
                claim_refs.extend(_narrow_reference(active_ref, stripped))
            for ref in dict.fromkeys(claim_refs):
                locator_id = locator_ids.get(ref)
                if locator_id is None:
                    locator_id = f"E{len(locator_ids) + 1:03d}"
                    locator_ids[ref] = locator_id
                ids.append(locator_id)
            marker = " ".join(f"[{locator_id}]" for locator_id in ids)
            text = f"{text} {marker}"
            claim_rows.append({"text": stripped, "locators": ids})
        elif not structural:
            claim_rows.append({"text": stripped, "locators": []})
        L.append(text)
    A(f"# WinRE Technical Report (v3) — {sha[:16]}…")
    A("")
    set_evidence("intake/intake.json#$.sha256", "intake/intake.json#$.file",
                 "intake/intake.json#$.size", "intake/intake.json#$.format")
    A(f"- **SHA256:** `{intake.get('sha256', sha)}`")
    A(f"- **Sample:** `{intake.get('file', '?')}`  |  size {intake.get('size', '?')}  |  "
      f"format {intake.get('format', '?')}")
    set_evidence("META.json#$.mode", "META.json#$.pack_mode")
    A(f"- **Mode:** `{pack_mode}`")
    if phase == "static+dynamic":
        set_evidence("findings.json#$.findings.dynamic",
                     "dynamic/STAGE.json#$.detonation_ran")
    elif phase == "static+dynamic-incomplete":
        set_evidence("dynamic/STAGE.json#$.detonation_ran",
                     "dynamic/STAGE.json#$.skipped",
                     "findings.json#$.findings.dynamic")
    elif phase == "static+debugger":
        # Cite the pack's own identity record too: the observation record
        # does not state a phase, and the reviewer refused "Phase: dbg" on
        # exactly that gap (2026-10-29 s13 dbg, claim C0004 - the same
        # refusal the other branches already fixed by citing META.json).
        set_evidence("META.json#$.mode",
                     "META.json#$.pack_mode",
                     "findings.json#$.findings.debug_observation")
    else:
        set_evidence("META.json#$.mode", "META.json#$.pack_mode")
    # The phase line must name what the EVIDENCE says, not a composed label:
    # the claim reviewer can only confirm a label it sees in an excerpt, and
    # it refused "static+debugger" (the pack's own META.json says "dbg") and
    # "static+agentic" ("agentic") for exactly that reason. The stages that
    # actually ran are described - and cited - in the sections below.
    A(f"- **Phase:** {pack_mode}")
    set_evidence("deep/deep.json#$.agent.source",
                 "deep/deep.json#$.agent.verdict")
    A(f"- **Analysis source:** `{src}`")
    A("")

    A("## 1. Verdict")
    A("")
    set_evidence("composite.json#$.level", "composite.json#$.confidence",
                 "composite.json#$.sources", "composite.json#$.selection")
    A(f"- Pipeline-selected composite verdict: **{str(selected_level or 'unknown').upper()}** "
      f"(confidence: {selected_confidence or 'n/a'}) — source `{selected_source}`.")
    if composition.get("deciding_mode"):
        set_evidence("composite.json#$.deciding_mode")
        A(f"- Deciding mode: `{composition['deciding_mode']}`")
    if composition.get("basis"):
        basis_refs = ["composite.json#$.basis"]
        gate = ((finding_record.get("findings") or {}).get("window") or {})
        if gate.get("gate_invocation_id"):
            basis_refs.extend([
                "findings.json#$.findings.window.gate_path",
                "findings.json#$.findings.window.gate_invocation_id",
                *raw_frida_refs(event_refs=[gate["gate_invocation_id"]]),
            ])
        set_evidence(*basis_refs)
        A("- Composite basis: " + ", ".join(
            f"`{item}`" for item in composition["basis"][:10]))
    A("")
    A("## 2. File overview")
    A("")
    # The whole pe object can exceed the 6 KB review limit on samples with
    # large import/version blocks (s12: 6,572 chars) - when it is refused as
    # over-broad the Machine/Signed lines published with NO locator and the
    # review marked them unverifiable. Cite the leaf fields the two lines
    # actually state; the whole object stays as a fallback for packs where
    # it fits.
    set_evidence("quick/quick.json#$.evidence.pe.machine",
                 "quick/quick.json#$.evidence.pe.entrypoint",
                 "quick/quick.json#$.evidence.pe.compile_ts",
                 "quick/quick.json#$.evidence.pe.signed",
                 "quick/quick.json#$.evidence.pe")
    pe = ev.get("pe") or {}
    if pe:
        A(f"- Machine: `{pe.get('machine')}` entrypoint `0x{pe.get('entrypoint', 0):x}` "
          f"timestamp {pe.get('compile_ts')}")
        A(f"- Signed: **{pe.get('signed')}**")
        section_rows = (pe.get("sections") or [])[:10]
        section_refs = [
            f"quick/quick.json#$.evidence.pe.sections[{index}].{field}"
            for index, _section in enumerate(section_rows)
            for field in ("name", "entropy")
        ]
        set_evidence(*section_refs)
        A("- Sections: " + ", ".join(
            f"`{section.get('name')}` (entropy {section.get('entropy')})"
            for section in section_rows))
        imp_count = sum(len(e.get("functions") or []) for e in pe.get("imports") or [])
        set_evidence("quick/quick.json#$.evidence.pe.imports")
        A(f"- Imports: {len(pe.get('imports') or [])} DLLs, {imp_count} functions")
    gh = ev.get("ghidra") or {}
    if gh:
        set_evidence("quick/quick.json#$.evidence.ghidra",
                     *(history_refs_by_tool.get("ghidra_query") or []))
        A(f"- Ghidra: {gh.get('func_rows', 0)} functions")
    else:
        set_evidence("quick/quick.json#$.tool_failures")
        A("- Ghidra: no result recorded by the quick stage.")
    ida = ev.get("ida") or {}
    if ida.get("func_count") is not None:
        set_evidence("quick/quick.json#$.evidence.ida",
                     *(history_refs_by_tool.get("ida_query") or []))
        A(f"- IDA: {ida.get('func_count')} functions (.i64 created at quick stage)")
    sink_scan = ev.get("sink_sites") or {}
    if isinstance(sink_scan, dict):
        sink_refs = history_refs_by_tool.get("sink_sites") or []
        if sink_refs:
            set_evidence(*(f"{sink_refs[-1]}.{field}"
                           for field in ("functions_scanned", "sites")))
            A(f"- Sink-site scan: {sink_scan.get('functions_scanned', 0)} functions scanned; "
              f"{len(sink_scan.get('sites') or [])} dangerous-API call sites recorded.")
    strings_record = ev.get("strings_tool") or {}
    if isinstance(strings_record, dict) and strings_record:
        strings_refs = history_refs_by_tool.get("strings_tool") or []
        if strings_refs:
            set_evidence(f"{strings_refs[-1]}.total")
            A(f"- Deep strings tool returned {strings_record.get('total', 0)} strings.")
            # The first strings in enumeration order are usually code-byte
            # fragments ("D$\;D$pt") with no analytic value, and duplicates
            # repeat across sections; every bullet becomes a claim the
            # reviewer must judge, and one fragment was noise-refused
            # (2026-10-27 s08 static, C0024 'contradicted' with no reason on
            # a claim that is its own quote). Emit only DISTINCT strings
            # that contain at least one 4-character alphanumeric run; locators
            # keep the original row indices. The 2026-10-29 s12 run showed the
            # 4-run filter alone is not enough on x64 samples: function
            # prologue fragments ("SUVWATAUAVAWH", "\$ UWAWH") are pure
            # uppercase alnum runs that pass it - require a lowercase letter
            # too (real words/identifiers are mixed case; pure-uppercase
            # acronyms are a display loss the raw string evidence keeps).
            shown = 0
            seen_strings: set[str] = set()
            for index, value in enumerate(strings_record.get("strings") or []):
                if shown >= 10:
                    break
                text = str(value)[:120]
                if text in seen_strings:
                    continue
                if not re.search(r"[A-Za-z0-9]{4}", text):
                    continue
                if not re.search(r"[a-z]", text):
                    continue
                seen_strings.add(text)
                set_evidence(f"{strings_refs[-1]}.strings[{index}]")
                A(f"  - `{text}`")
                shown += 1
    A("")

    A("## 3. Static evidence (per tool)")
    A("")
    capa = ev.get("capa") or {}
    A("### capa (Mandiant rules)")
    # The capability list is ~8.7 KB: a locator for the whole list can never
    # be shown to the reviewer, so cite each capability on its own.
    capa_history_refs = history_refs_by_tool.get("capa") or []
    capa_base = (capa_history_refs[-1] if capa_history_refs
                 else "quick/quick.json#$.evidence.capa")
    if capa.get("ok"):
        for index, c in enumerate((capa.get("capabilities") or [])[:15]):
            atk = ", ".join(c.get("attack") or [])
            set_evidence(f"{capa_base}.capabilities[{index}].name",
                         f"{capa_base}.capabilities[{index}].attack",
                         f"{capa_base}.capabilities[{index}].count")
            A(f"- {c.get('name')}" + (f" [{atk}]" if atk else ""))
    else:
        set_evidence(f"{capa_base}.skipped", f"{capa_base}.error")
        A(f"- skipped/error: {capa.get('skipped') or capa.get('error')}")
    A("")
    floss = ev.get("floss") or {}
    A("### floss (deobfuscated strings)")
    set_evidence("quick/quick.json#$.evidence.floss.decoded_strings",
                 *(history_refs_by_tool.get("floss") or []))
    ds = floss.get("decoded_strings") or []
    if ds:
        for s in ds[:15]:
            A(f"- `{s[:120]}`")
    elif floss.get("error") or floss.get("ok") is False:
        # A failed floss run is not a zero result: rendering the crash as
        # "none decoded (0 total)" told the reviewer the tool found nothing
        # when it never ran (2026-10-27 s08 static, C0030 insufficient - the
        # cited excerpt is the error record, and the silent-degradation
        # class B says a capability that did not run must not look like one
        # that found nothing).
        set_evidence("quick/quick.json#$.evidence.floss.error",
                     *(history_refs_by_tool.get("floss") or []))
        A(f"- floss failed on this sample - nothing was decoded "
          f"({str(floss.get('error'))[:160]})")
    else:
        A(f"- none decoded ({floss.get('total_decoded', 0)} total)")
    A("")
    mal = ev.get("malcat") or {}
    A("### Malcat")
    # The malcat blob is ~5.8 KB - one claim short of the review limit.
    # Cite its parts instead of the whole object.
    set_evidence("quick/quick.json#$.evidence.malcat.file",
                 "quick/quick.json#$.evidence.malcat.anomalies",
                 "quick/quick.json#$.evidence.malcat.yara_hits",
                 "quick/quick.json#$.evidence.malcat.strings")
    if mal.get("error") or mal.get("skipped"):
        A(f"- skipped/error: {mal.get('error') or mal.get('skipped')}")
    else:
        f = mal.get("file") or {}
        A(f"- file: {f.get('file_name')} | type {f.get('type')} | "
          f"entropy {f.get('entropy')}")
        an = (mal.get("anomalies") or {})
        an_list = an if isinstance(an, list) else (an.get("anomalies") or an.get("rows") or [])
        if an_list:
            for a_ in an_list[:10]:
                A(f"- anomaly: `{json.dumps(a_, default=str)[:160]}`")
        yh = mal.get("yara_hits") or {}
        yh_list = yh if isinstance(yh, list) else (yh.get("rows") or yh.get("hits") or [])
        if yh_list:
            for y in yh_list[:10]:
                A(f"- yara: `{json.dumps(y, default=str)[:160]}`")
        st = mal.get("strings") or {}
        st_rows = st.get("rows") if isinstance(st, dict) else st
        if st_rows:
            A(f"- strings (top): " + ", ".join(
                f"`{str(s)[:60]}`" for s in st_rows[:10]))
    A("")
    xs = ev.get("xor_string_search")
    if isinstance(xs, dict) and xs:
        A("### XOR-encoded strings (brute force)")
        xor_refs = ["quick/quick.json#$.evidence.xor_string_search"]
        xor_refs.extend(history_refs_by_tool.get("xor_string_search") or [])
        set_evidence(*xor_refs)
        for c in (xs.get("candidates") or [])[:10]:
            A(f"- [{c.get('mode')} key={c.get('key')}] offset {c.get('offset')}: "
              f"`{str(c.get('string'))[:100]}`")
        if xs.get("ok") is True and not xs.get("candidates"):
            A("- Search completed; candidate count: 0.")
        elif xs.get("ok") is not True:
            A(f"- Search did not complete: {xs.get('error') or xs.get('skipped') or 'status unavailable'}.")
        A("")
    sig = ev.get("signature_match")
    A("### Signature DB match (agent-invoked)")
    signature_refs = history_refs_by_tool.get("signature_match") or []
    if sig:
        set_evidence(*(signature_refs or ["deep/deep.json#$.agent.history"]))
        A(f"- {json.dumps(sig, default=str)[:300]}")
    elif signature_refs:
        set_evidence(*signature_refs)
        A("- Signature-match invocation was recorded but returned no result object.")
    elif isinstance(deep_history, list) and deep_history:
        set_evidence("deep/deep.json#$.agent.history[*].tool")
        # Name the TOOL, not the concept: "signature-match" reads like YARA
        # scanning, which this run does contain, and the reviewer contradicted
        # the claim for that reason (2026-10-24 dynamic run).
        A("- The agent did not invoke the `signature_match` tool in this run.")
    A("")
    imp_sig = ev.get("pe_import_signals") or {}
    A("### PE import signals")
    set_evidence("quick/quick.json#$.evidence.pe_import_signals",
                 "deep/deep.json#$.agent.history[*].result")
    if imp_sig.get("signals"):
        for s in imp_sig["signals"][:12]:
            A(f"- {s.get('label')} ({s.get('api_match')}) [{', '.join(s.get('attack') or [])}]")
    else:
        A(f"- none ({imp_sig.get('import_count', 0)} imports scanned)")
    A("")
    pif = ev.get("pe_import_signals")  # placehlder alignment
    A("### Ghidra/IDA SQL highlights")
    set_evidence("quick/quick.json#$.evidence.ghidra",
                 "quick/quick.json#$.evidence.ida",
                 "deep/deep.json#$.agent.history[*].result")
    A(f"- Ghidra funcs: {gh.get('func_rows', 0)}; imports surfaced: "
      f"{len(gh.get('imports') or [])}")
    if ida.get("func_count") is not None:
        A(f"- IDA funcs: {ida.get('func_count')}")
    A("")

    A("## 4. Agent analysis (source-tagged)")
    A("")
    set_evidence("deep/deep.json#$.agent.source")
    A(f"- Agent analysis source: `{src}`.")
    set_evidence("deep/deep.json#$.agent.verdict.verdict",
                 "deep/deep.json#$.agent.verdict.confidence")
    A(f"- Deep-stage assessment ({str(verdict.get('verdict', 'unknown')).upper()}; "
      f"confidence={verdict.get('confidence', 'n/a')}).")
    if verdict.get("summary"):
        # The whole quick evidence object is ~25 KB and the whole deep tool
        # history ~41 KB: neither can be shown to the reviewer. Cite the
        # summary's own field plus the bounded tool evidence it rests on.
        summary_text = str(verdict["summary"])
        # The summary usually NAMES capabilities ("the crypto capability hits
        # (RC4/SHA/Salsa20)"). A count cannot show that the named ones are
        # there, so cite each capability the summary actually names.
        capa_ev = ev.get("capa") or {}
        capa_history = history_refs_by_tool.get("capa") or []
        capa_source = (capa_history[-1] if capa_history
                       else "quick/quick.json#$.evidence.capa")
        named_caps = [
            f"{capa_source}.capabilities[{index}].name"
            for index, cap in enumerate(capa_ev.get("capabilities") or [])
            if cap.get("name")
            and str(cap["name"]).casefold() in summary_text.casefold()]
        # The agent's summary is an inference over ITS OWN tool results. The
        # reviewer can only judge it against the evidence it can see, so
        # cite every tool result the agent produced (set_evidence prunes the
        # ones too large to show) plus the quick-stage evidence it leans on.
        agent_refs: list[str] = []
        for tool_refs in history_refs_by_tool.values():
            agent_refs.extend(tool_refs)
        # The summary may name dbg-side results (the deterministic unpack
        # prepass, packed-section signal) and, when the verdict floor fired,
        # the floor record itself; the 2026-10-27 s09 dbg run failed its
        # review because the summary asserted prepass/OEP results with no
        # citable locator behind them (claim judged insufficient). Cite the
        # agent fields that back those assertions; set_evidence drops any
        # that do not exist.
        set_evidence("deep/deep.json#$.agent.verdict.summary",
                     "quick/quick.json#$.evidence.capa.total",
                     "quick/quick.json#$.evidence.pe.imports",
                     "quick/quick.json#$.evidence.threat_intel",
                     "quick/quick.json#$.evidence.yarascan",
                     "quick/quick.json#$.evidence.vt",
                     "deep/deep.json#$.agent.unpack_prepass",
                     "deep/deep.json#$.agent.packed_signal",
                     "deep/deep.json#$.agent.verdict.verdict_floored",
                     "deep/deep.json#$.agent.verdict.floor_source",
                     "deep/deep.json#$.agent.verdict.original_verdict",
                     *named_caps[:20],
                     *agent_refs[:30])
        # The summary is the MODEL's judgment over the evidence, not a
        # finding in its own right. Presented as a bare fact ("Summary: ...")
        # the reviewer correctly contradicted it when it disagreed with the
        # cited VT ratio (2026-10-24 dbg run: "not malware" beside 16/71
        # detections). Attribution is the honest framing: the report states
        # who concluded it, and the evidence sections state what is known.
        A(f"  - **Agent's recorded summary (model judgment over the cited "
          f"evidence; not an independent finding):** {verdict['summary']}")
    A("")

    A("## 5. IOC table")
    A("")
    indicators = iocs.get("indicators") or []
    if indicators:
        for index, item in enumerate(indicators):
            refs = [f"report/iocs.json#$.indicators[{index}]"]
            refs.extend(str(ref) for ref in item.get("evidence_refs") or [])
            set_evidence(*refs)
            A(f"- **{item.get('category')} candidate:** `{item.get('value')}` "
              "(embedded static data; not proof of runtime use).")
    else:
        set_evidence("report/iocs.json#$.indicator_count")
        A("- No static indicator candidates were extracted from the configured sources.")
    network_observations = iocs.get("network_observations") or []
    if network_observations:
        set_evidence("report/iocs.json#$.excluded_sources",
                     "report/iocs.json#$.network_observations[0]",
                     str(network_observations[0].get("evidence_ref") or ""))
        A("- VM-wide packet-capture observations are retained separately with "
          "unresolved process attribution and are excluded from sample IOC claims.")
    A("")
    crypto = ev.get("crypto_constants") or {}
    crypto_ids = crypto.get("crypto_identified") or []
    if crypto_ids:
        set_evidence("quick/quick.json#$.evidence.crypto_constants",
                     *(history_refs_by_tool.get("crypto_constants") or []))
        A(f"- **Crypto identified (constants/shape):** "
          + ", ".join(f"`{c}`" for c in crypto_ids[:8])
          + " - found in executable sections; config/keys may be recoverable.")
        A("")
    dg = ev.get("decrypt_gate") or {}
    if dg.get("status") == "gate":
        # The result lives in the deep history on every current pack (the
        # quick evidence never carries it), and the whole-history wildcard is
        # over-broad, so both refs dropped and the line published with no
        # locator at all - claim C0074 "no resolvable evidence locator"
        # (2026-10-27 s09 static). Cite the tool's own history result; if
        # nothing resolves, emit nothing rather than an uncited claim.
        set_evidence("quick/quick.json#$.evidence.decrypt_gate",
                     *(history_refs_by_tool.get("decrypt_gate") or []))
        if active_refs:
            A(f"- **Decrypt gate: GATED** ({dg.get('taxonomy') or 'unknown'} — "
              f"imports={dg.get('import_count')} sparse strings). Static "
              "capability evidence is unreliable; unpack + dynamic validation "
              "required before trusting capa/strings clusters.")
            A("")

    A("## 6. Behavior-context notes (kill-switch / CLI / artifacts)")
    A("")
    _behavior_refs = ["quick/quick.json#$.evidence.floss",
                      "quick/quick.json#$.evidence.strings",
                      "quick/quick.json#$.evidence.capa.capabilities"]
    if agent.get("history"):
        _behavior_refs.append("deep/deep.json#$.agent.history[*].result")
    set_evidence(*_behavior_refs)
    _bc = _behavior_context(ev)
    ks = _bc.get("kill_switch") or []
    if ks:
        A("- **Static anti-VM/anti-sandbox capability candidates:** "
          + "; ".join(f"`{k}`" for k in ks[:6])
          + " — these matches indicate static capability, not proof of runtime checks.")
    domains = _bc.get("domains") or []
    if domains:
        # The domains are in the IOC extractor's result; the string excerpts
        # do not necessarily contain the domain that is quoted.
        set_evidence(*(history_refs_by_tool.get("ioc_extract") or []),
                     "quick/quick.json#$.evidence.strings")
        A("- **Domains present in static strings:** "
          + ", ".join(f"`{domain}`" for domain in domains[:6])
          + " — this does not establish a runtime connection or C2.")
    cli = _bc.get("cli") or []
    if cli:
        # Attribute the import only when import evidence shows it AND the
        # reviewer can see that evidence: the 2026-10-27 s07 static run (UPX
        # stub imports LoadLibraryA/GetProcAddress only) had this line assert
        # "GetCommandLine imports" the pack never contained, and the claim
        # review correctly refused the claim as unsupported. set_evidence
        # drops an over-broad import locator, so an attribution citing it
        # would assert the import on invisible evidence - fall back to the
        # honest wording instead.
        _import_refs = ("quick/quick.json#$.evidence.pe.imports",
                        "quick/quick.json#$.evidence.pe_import_signals")
        set_evidence(*_import_refs, *_behavior_refs)
        _visible_import_refs = [ref for ref in _import_refs
                                if ref in active_refs]
        _imports_blob = json.dumps(
            [(ev.get("pe") or {}).get("imports"),
             ev.get("pe_import_signals")], default=str).lower()
        if "getcommandline" in _imports_blob and _visible_import_refs:
            A(f"- **CLI behavior table:** "
              + "; ".join(f"`{c}`" for c in cli[:8])
              + " (switches from strings + GetCommandLine imports; verify "
              "per-branch in the debugger/dynamic phase).")
        else:
            A(f"- **CLI-switch string candidates:** "
              + "; ".join(f"`{c}`" for c in cli[:8])
              + " (strings that look like command-line switches; this static "
              "evidence does not attribute them to command-line parsing; "
              "verify actual argument handling in the debugger/dynamic "
              "phase).")
    art = _bc.get("artifacts") or {}
    artifact_items = [
        ("mutex", art.get("mutexes") or []),
        ("registry", art.get("registry") or []),
        ("service/task", art.get("services") or []),
        ("file path", art.get("paths") or []),
    ]
    present_artifacts = [(label, values) for label, values in artifact_items if values]
    if present_artifacts:
        A("- **Static string-derived artifact candidates:** " + "; ".join(
            f"{label}: " + ", ".join(f"`{value}`" for value in values[:5])
            for label, values in present_artifacts))
    A("")

    A("## 7. YARA")
    A("")
    set_evidence("yara/rule_report.json#$.rule_id",
                 "yara/rule_report.json#$.empty_rule")
    A(f"- Rule ID: `{yara_rep.get('rule_id')}`; "
      f"empty_rule={yara_rep.get('empty_rule')}.")
    cur = (yara_rep.get("curation") or {})
    if cur.get("warnings"):
        set_evidence("yara/rule_report.json#$.curation.warnings",
                     "yara/rule_report.json#$.curation.short_strings",
                     "yara/rule_report.json#$.curation.string_count")
        A(f"- Curation warnings: {'; '.join(cur['warnings'])}")
    A("")

    A("## 8. Execution evidence")
    A("")

    set_evidence("artifact-manifest.json#$.artifact_count")
    if pack_mode == "dbg":
        A("### Debugger-assisted observation")
        A("")
        dbg_findings = finding_record.get("findings") or {}
        observation = dbg_findings.get("debug_observation") or {}
        unpack = dbg_findings.get("unpack") or {}
        if observation:
            set_evidence("findings.json#$.findings.debug_observation",
                         "dynamic/debug_monitor/process_summary.json#$.summary")
            A(f"- Bounded debugger window: completed={observation.get('window_completed')}; "
              f"observed={observation.get('observed_seconds')}s / "
              f"requested={observation.get('requested_seconds')}s; "
              f"target exit observed={observation.get('exit_observed')}.")
            A(f"- ETW process monitor: status=`{observation.get('monitor_status')}`; "
              f"target observed={observation.get('target_observed')}; "
              f"starts={observation.get('process_starts')}; "
              f"stops={observation.get('process_stops')}.")
            if observation.get("scope"):
                A(f"- Observer scope: {observation['scope']}.")
            if observation.get("unique_images"):
                A("- Process images observed: " + ", ".join(
                    f"`{str(name)[:100]}`"
                    for name in observation["unique_images"][:12]))
        else:
            set_evidence("findings.json#$.findings.debug_observation",
                         "dynamic/STAGE.json#$.debug_monitor")
            A("- No debugger observation record was produced for this run.")
        if unpack.get("ok"):
            set_evidence("findings.json#$.findings.unpack",
                         "dynamic/windbg_analysis.json#$.oep")
            A(f"- Unpack result: OEP `{unpack.get('oep')}`; "
              f"dump parses={unpack.get('parses')}; imports={unpack.get('imports')}.")
        else:
            debugger_probe = unpack.get("debugger_probe") or {}
            observation_completed = observation.get("window_completed") is True
            unpack_refs = ["findings.json#$.findings.unpack",
                           "dynamic/windbg_analysis.json#$.oep"]
            if observation:
                unpack_refs += [
                    "findings.json#$.findings.debug_observation.window_completed",
                    "findings.json#$.findings.debug_observation.completion_reason",
                ]
            set_evidence(*unpack_refs)
            if observation_completed:
                tail = (" This does not invalidate a completed debugger "
                        "observation.")
            else:
                # Never claim a completed observation the evidence does not
                # show: a failed debug session has no observation to
                # invalidate, and the reviewer correctly refused that claim
                # on the 2026-10-23 dbg pack.
                tail = (" The debugger observation did not complete in this "
                        "run, so this is a failed unpack attempt rather than "
                        "a completed observation without a dump.")
            if (debugger_probe.get("method") == "entrypoint_observation"
                    and debugger_probe.get("address")):
                A("- Unpack result: the debugger observed the original image "
                  f"entry point `{debugger_probe['address']}`; no unpacked dump "
                  "was produced." + tail)
            elif (debugger_probe.get("method") == "memory_execute_oep"
                  and debugger_probe.get("address")):
                A("- Unpack result: the debugger observed a candidate unpacked "
                  f"OEP at `{debugger_probe['address']}`, but no unpacked dump "
                  "was produced." + tail)
            else:
                A("- Unpack result: no unpacked OEP dump was recovered." + tail)
        for limitation in (finding_record.get("limitations") or [])[:5]:
            set_evidence("findings.json#$.limitations",
                         *_coverage_refs(gaps_only=True))
            A(f"- Limitation: {limitation}")
        A("")

    A("### Dynamic detonation")
    A("")

    inventory = _load(pack_root / "artifact-manifest.json") or {}
    coverage = inventory.get("coverage") or {}
    requested_gaps = [(name, row) for name, row in coverage.items()
                      if isinstance(row, dict) and row.get("requested")
                      and row.get("status") != "complete"]
    inventory_refs = ["artifact-manifest.json#$.artifact_count"]
    # The manifest records the gap count, so the statement is backed by one
    # decisive locator instead of a pile of per-source entries the reviewer
    # cannot take in.
    inventory_refs.append("artifact-manifest.json#$.coverage_gaps")
    set_evidence(*inventory_refs)
    A(f"- Artifact inventory: {inventory.get('artifact_count', 0)} files; "
      f"coverage gaps={len(requested_gaps)}.")
    capture = (_load(pack_root / "dynamic" / "off_box" / "capture.json")
               or _load(pack_root / "dynamic" / "external_capture.json") or {})
    if capture.get("requested"):
        set_evidence("dynamic/off_box/capture.json#$.status",
                     "dynamic/off_box/capture.json#$.interface",
                     "dynamic/off_box/capture.json#$.pcap_sha256",
                     "dynamic/external_capture.json#$.status",
                     "dynamic/external_capture.json#$.interface",
                     "dynamic/external_capture.json#$.pcap_sha256",
                     "dynamic/external_capture.json#$.promoted_sha256",
                     "dynamic/external_capture.json#$.packets_captured",
                     "dynamic/external_capture.json#$.reason")
        capture_details = [f"status=`{capture.get('status')}`"]
        if capture.get("interface"):
            capture_details.append(f"interface=`{capture['interface']}`")
        capture_sha = capture.get("pcap_sha256") or capture.get("promoted_sha256")
        if capture_sha:
            capture_details.append(f"pcap SHA256=`{capture_sha}`")
        if capture.get("packets_captured") is not None:
            capture_details.append(f"packets={capture['packets_captured']}")
        if capture.get("reason"):
            capture_details.append(f"reason=`{capture['reason']}`")
        A("- Off-box network capture: " + "; ".join(capture_details) + ".")
    for name, row in requested_gaps[:8]:
        set_evidence(f"artifact-manifest.json#$.coverage.{name}.requested",
                     f"artifact-manifest.json#$.coverage.{name}.status")
        A(f"  - `{name}`: {row.get('status')} - {row.get('reason')}")

    if has_dynamic:
        # W3 (RevAI review 2026-10-08): read the MODE ROOT.
        #
        # findings.build writes <mode>/findings.json; this read
        # <mode>/dynamic/findings.json - the stage dir. The producer-root
        # contract changed and this consumer was not moved with it, so for
        # every mode the report claimed "the analysis plane did not run" over a
        # pack that had findings. This is the third time one side of a
        # findings contract moved alone (MODES unimported in the embedded
        # helper; findings written to the stage dir; now the reader).
        #
        # tests/test_findings_contract.py asserts this end to end - producer
        # writes, report consumes the same file - because a string grep on the
        # reader is exactly the check that let the mismatch ship.
        dvi = _load(pack_root / "findings.json")
        if not dvi:
            set_evidence("dynamic/STAGE.json#$.detonation_ran",
                         "dynamic/META.json#$.frida_events")
            A(f"- Detonation ran (frida_events={dyn.get('frida_events')}). "
              "No findings.json was produced for this pack - the analysis "
              "plane did not run, so nothing below is a conclusion.")
        else:
            set_evidence("findings.json#$.verdict",
                         "dynamic/META.json#$.sample_pid",
                         "dynamic/frida_summary.json#$.file_effects",
                         "dynamic/network_intel.json#$.network")
            v = dvi.get("verdict") or {}
            A(f"- Findings-stage record: level=`{str(v.get('level')).upper()}`; "
              f"confidence=`{v.get('confidence')}`; derived on the analysis host "
              "from pulled evidence.")
            basis = v.get("basis") or []
            if basis:
                set_evidence("findings.json#$.verdict.basis",
                             "dynamic/frida_summary.json#$.top_apis",
                             *raw_frida_refs(apis=basis))
                A("  - declared basis: " + ", ".join(f"`{b}`" for b in basis[:10]))
            fd = dvi.get("findings") or {}
            if fd.get("drops"):
                set_evidence("findings.json#$.findings.drops",
                             "dynamic/frida_summary.json#$.file_effects")
                A(f"  - **payload drops ({len(fd['drops'])}):**")
                for d in fd["drops"][:6]:
                    set_evidence("findings.json#$.findings.drops",
                                 "dynamic/frida_summary.json#$.file_effects",
                                 *raw_frida_refs(event_refs=d.get("event_refs")))
                    flag = (" *(persistence location)*"
                            if d.get("persistence_location") else "")
                    A(f"    - `{d['path']}`{flag}")
            if fd.get("created_files"):
                set_evidence("findings.json#$.findings.created_files",
                             "dynamic/frida_summary.json#$.file_effects",
                             *[ref for item in fd["created_files"]
                               if isinstance(item, dict)
                               for ref in raw_frida_refs(event_refs=item.get("event_refs"))])
                A(f"  - successful create/truncate effects without a confirmed "
                  f"write: {len(fd['created_files'])}; these are not counted as drops")
            effect_intent = fd.get("file_effect_intent") or {}
            if effect_intent:
                set_evidence("findings.json#$.findings.file_effect_intent",
                             "dynamic/frida_summary.json#$.file_effects")
                A(f"  - file-effect intent: {effect_intent.get('status')} — "
                  f"{effect_intent.get('note')}")
            if fd.get("device_writes"):
                set_evidence("findings.json#$.findings.device_writes",
                             "dynamic/frida_summary.json#$.file_effects")
                A("  - **raw-device writes:** "
                  + ", ".join(f"`{x}`" for x in fd["device_writes"][:4])
                  + " - a wiper or raw-disk tamper")
            net = fd.get("network") or {}
            leads = net.get("leads") or []
            for index, lead in enumerate(leads[:12]):
                refs = [f"findings.json#$.findings.network.leads[{index}]"]
                refs.extend(str(ref) for ref in lead.get("evidence_refs") or [])
                set_evidence(*refs)
                A(f"  - VM-wide network lead `{lead.get('host')}` observed as "
                  f"{', '.join(lead.get('observed_as') or [])}; process attribution "
                  "is unresolved, so this is not a sample contact or C2 finding.")
            # Legacy packs may still contain hosts in `c2`; preserve them as
            # explicitly unverified leads rather than repeating the old label.
            for index, candidate in enumerate((net.get("c2") or [])[:12]):
                set_evidence(f"findings.json#$.findings.network.c2[{index}]")
                A(f"  - Legacy network candidate `{candidate.get('host')}` is "
                  "not promoted to sample C2 because process attribution and "
                  "communication intent are not established.")
            if net.get("beacons"):
                set_evidence("findings.json#$.findings.network.beacons",
                             "findings.json#$.findings.network.beacon_scope")
                A(f"  - VM-wide beacon-pattern leads: {len(net['beacons'])}; "
                  "sample process/flow attribution is unresolved.")
            if net.get("frida_endpoint_count"):
                set_evidence("findings.json#$.findings.network",
                             "dynamic/frida_summary.json#$.network_endpoints")
                A(f"  - Frida endpoint observations: "
                  f"{net.get('frida_endpoint_count')} (sample-process API scope; "
                  f"truncated={net.get('frida_endpoints_truncated')})")
            fc = fd.get("frida_coverage") or {}
            if fc:
                # The whole record is >6 KB (installed_exports alone is 5.6 KB),
                # so citing it yields no usable excerpt and the claim comes back
                # unverifiable. Cite the fields the sentence actually reports.
                set_evidence(
                    "findings.json#$.findings.frida_coverage.status",
                    "findings.json#$.findings.frida_coverage.requested",
                    "findings.json#$.findings.frida_coverage.installed",
                    "findings.json#$.findings.frida_coverage.apis_fired",
                )
                A(f"  - Frida hook coverage: {len(fc.get('installed') or [])}/"
                  f"{len(fc.get('requested') or [])} requested exports installed; "
                  f"{len(fc.get('apis_fired') or [])} APIs observed; "
                  f"status={fc.get('status')}")
            if net.get("pcap_deep_dive"):
                set_evidence("findings.json#$.findings.network.pcap_deep_dive",
                             "dynamic/network_intel.json#$.captures[*]")
                A(f"  - pcap deep-dive: {net['pcap_deep_dive']}")
            for inj in (fd.get("injection") or []):
                set_evidence("findings.json#$.findings.injection",
                             "dynamic/frida_summary.json#$.top_apis",
                             *raw_frida_refs(apis=inj.get("chain")))
                A("  - injection chain: "
                  + " -> ".join(f"`{a}`" for a in inj.get("chain") or [])
                  + f" ({inj.get('confidence')})")
            w = fd.get("window") or {}
            if w.get("effective_s") is not None:
                window_refs = [
                    "findings.json#$.findings.window",
                    "dynamic/META.json#$.window",
                ]
                if w.get("gate_invocation_id"):
                    window_refs.extend(raw_frida_refs(
                        event_refs=[w["gate_invocation_id"]]))
                set_evidence(*window_refs)
                requested_window_s = (w.get("requested_s")
                                      or ((dyn or {}).get("window") or {}).get("requested_s"))
                gate = (f"gate {w.get('gate_kind')}/{w.get('gate_api')} "
                        f"at {w.get('gate_at_s')}s"
                        if w.get("gate_fired") else "gate did not fire")
                requested_text = (f" / {requested_window_s}s requested"
                                  if requested_window_s is not None else "")
                A(f"  - window: {w.get('effective_s')}s observed{requested_text}, "
                  f"stop={w.get('stop_reason')}, {gate}")
            mem = fd.get("memory") or {}
            if mem.get("dumps"):
                set_evidence("findings.json#$.findings.memory",
                             "artifact-manifest.json#$.coverage.memory")
                A(f"  - memory: {mem['dumps']} dumps, "
                  f"{mem.get('bytes', 0) / 1e6:.0f} MB")
            lim = dvi.get("limitations") or []
            if lim:
                set_evidence("findings.json#$.limitations",
                             *_coverage_refs(gaps_only=True))
                A("  - **limitations:**")
                for l in lim[:5]:
                    if l.startswith("No confirmed drops, C2 candidates, or injection chains"):
                        set_evidence(
                            "findings.json#$.limitations",
                            "findings.json#$.findings.drops",
                            "findings.json#$.findings.network.c2",
                            "findings.json#$.findings.injection",
                            "findings.json#$.findings.window",
                            "findings.json#$.findings.frida_coverage",
                            *_coverage_refs(gaps_only=True))
                    else:
                        set_evidence("findings.json#$.limitations",
                                     *_coverage_refs(gaps_only=True))
                    A(f"    - {l}")
        ed = _load(pack_root / "dynamic" / "emu_diff.json") or {}
        if ed.get("ok"):
            set_evidence("dynamic/emu_diff.json#$.predicted",
                         "dynamic/emu_diff.json#$.observed",
                         "dynamic/speakeasy.json#$.api_calls",
                         "dynamic/frida_summary.json#$.top_apis")
            A(f"- **Emulation-vs-detonation:** speakeasy predicted "
              f"{ed.get('predicted')} APIs, Frida observed {ed.get('observed')}; "
              f"overlap {ed.get('overlap_count')}, divergence "
              f"{ed.get('divergence_score')} (0 = identical, 1 = disjoint).")
            if ed.get("only_predicted"):
                set_evidence("dynamic/emu_diff.json#$.only_predicted",
                             "dynamic/speakeasy.json#$.api_calls")
                A("- predicted-only: "
                  + ", ".join(f"`{a}`" for a in ed["only_predicted"][:10])
                  + " - emulation saw these, detonation didn't "
                  "(env-gating/anti-emulation candidate - investigate).")
            if ed.get("only_observed"):
                set_evidence("dynamic/emu_diff.json#$.only_observed",
                             "dynamic/frida_summary.json#$.top_apis")
                A("- observed-only: "
                  + ", ".join(f"`{a}`" for a in ed["only_observed"][:10])
                  + " - detonation saw these, emulation missed "
                  "(emulation coverage gap).")
    else:
        set_evidence("dynamic/STAGE.json#$.skipped",
                     "dynamic/STAGE.json#$.summary",
                     "execution_plan.json#$.execution_sites",
                     "execution_plan.json#$.gate_mode",
                     "execution_plan.json#$.auto_restore",
                     "execution_plan.json#$.budget_rationale")
        if pack_mode == "dbg":
            A("- No dynamic detonation was observed in this debugger-assisted run: "
              "the dynamic stage was skipped. The gate is `enforce` - one "
              "execution per clean restore, and restoring the snapshot is an "
              "operator action (WinRE never reverts the VM).")
        else:
            A("- No dynamic detonation was observed in this run: the dynamic "
              "stage was skipped. The gate is `enforce` - one execution per "
              "clean restore, and restoring the snapshot is an operator action "
              "(WinRE never reverts the VM).")
        if dyn_stage.get("summary"):
            set_evidence("dynamic/STAGE.json#$.summary")
            A(f"- Dynamic stage: {dyn_stage['summary']}")
    # Correlation is a cited analysis aid, not a verdict input. It remains
    # visible in static-only packs so the report says explicitly that no
    # current-run dynamic comparison was available.
    corr = finding_record.get("correlation") or {}
    if corr:
        A("### Static/runtime correlation (candidate links)")
        A("")
        set_evidence("findings.json#$.correlation.status")
        A(f"- Status: `{corr.get('status')}`.")
        counts = corr.get("counts") or {}
        if counts:
            set_evidence("findings.json#$.correlation.counts",
                         "findings.json#$.correlation.status")
            A("- Relationships: " + ", ".join(
                f"{name}={counts.get(name, 0)}" for name in
                ("confirmed", "predicted_not_observed", "observed_not_predicted", "unverifiable")))
        else:
            # No counts recorded: the correlation itself did not run, and the
            # status says so. A count no evidence states (and a status that
            # means "not measured", not "measured zero") must not be printed.
            set_evidence("findings.json#$.correlation.status")
            A(f"- Relationships: not correlated - correlation status "
              f"`{corr.get('status')}`.")
        hypothesis_rows = [h for h in corr.get("hypotheses") or []
                           if isinstance(h, dict)]
        observation_rows = [o for o in corr.get("observations") or []
                            if isinstance(o, dict)]
        hyps = {h.get("id"): h for h in hypothesis_rows}
        obs = {o.get("id"): o for o in observation_rows}
        hypothesis_indexes = {h.get("id"): index
                              for index, h in enumerate(hypothesis_rows)}
        observation_indexes = {o.get("id"): index
                               for index, o in enumerate(observation_rows)}
        for rel_index, rel in enumerate((corr.get("relationships") or [])[:8]):
            h = hyps.get(rel.get("hypothesis_id")) or {}
            observation_ids = rel.get("observation_ids") or []
            matched = [obs[o] for o in observation_ids if o in obs]
            label = h.get("value") or (matched[0].get("value") if matched else "unmatched candidate")
            relation_refs = [
                f"findings.json#$.correlation.relationships[{rel_index}]",
                "findings.json#$.correlation.coverage",
                "dynamic/manifest.json#$.coverage.frida",
                "dynamic/manifest.json#$.coverage.network",
                "dynamic/manifest.json#$.coverage.external_capture",
                "dynamic/frida_summary.json#$.hook_coverage.process_coverage_complete",
                "dynamic/frida_summary.json#$.hook_coverage.coverage_tree.process_coverage_complete",
                *([f"findings.json#$.correlation.hypotheses[{hypothesis_indexes[rel['hypothesis_id']]}]"]
                  if rel.get("hypothesis_id") in hypothesis_indexes else []),
                *[f"findings.json#$.correlation.observations[{observation_indexes[observation_id]}]"
                  for observation_id in observation_ids
                  if observation_id in observation_indexes],
                *(rel.get("hypothesis_refs") or []),
                *(rel.get("observation_refs") or []),
            ]
            set_evidence(*relation_refs)
            A(f"  - `{rel.get('status')}` `{label}` — {rel.get('reason')}.")
        for limitation_index, limitation in enumerate((corr.get("limitations") or [])[:5]):
            limitation_refs = [
                f"findings.json#$.correlation.limitations[{limitation_index}]",
                "findings.json#$.correlation.coverage",
            ]
            lower_limitation = str(limitation).casefold()
            if "frida" in lower_limitation or "instrumentation" in lower_limitation:
                limitation_refs.extend([
                    "dynamic/frida_summary.json#$.hook_coverage.process_coverage_complete",
                    "dynamic/frida_summary.json#$.hook_coverage.coverage_tree.limitations",
                    "dynamic/manifest.json#$.coverage.frida",
                ])
            if "network" in lower_limitation or "pcap" in lower_limitation:
                limitation_refs.extend([
                    "dynamic/manifest.json#$.coverage.network.status",
                    "dynamic/manifest.json#$.coverage.external_capture.status",
                ])
                capture_refs = [
                    "dynamic/external_capture.json#$.status",
                    "dynamic/external_capture.json#$.mode",
                    "dynamic/external_capture.json#$.promiscuous",
                    "dynamic/external_capture.json#$.interface",
                    "dynamic/external_capture.json#$.guest_ip",
                    "dynamic/external_capture.json#$.capture_filter",
                    "dynamic/external_capture.json#$.pcap_sha256",
                    "dynamic/external_capture.json#$.packets_captured",
                    "dynamic/external_capture.json#$.run_id",
                ]
                limitation_refs.extend(ref for ref in capture_refs
                                       if _reference_exists(ref))
                vm_wide_indexes = [
                    index for index, observation in enumerate(observation_rows)
                    if observation.get("scope") == "vm-wide-pcap"
                ][:5]
                limitation_refs.extend(
                    f"findings.json#$.correlation.observations[{index}]"
                    for index in vm_wide_indexes)
            if "no relationship" in lower_limitation or "confirmed" in lower_limitation:
                limitation_refs.extend([
                    "findings.json#$.correlation.counts.confirmed",
                    "findings.json#$.correlation.policy",
                ])
            set_evidence(*limitation_refs)
            A(f"  - coverage limitation: {limitation}")
        A("")
    A("")

    A("## 9. Quality and interpretation")
    A("")
    # Each report line cites a stable evidence-key. Keep the full relative file
    # and field locator beside the report, not in a human-readable sentence.
    L.append("")
    L.append("## Evidence locator keys")
    L.append("")
    for ref, locator_id in sorted(locator_ids.items(), key=lambda item: item[1]):
        L.append(f"- [{locator_id}] `{ref}`")
    md = "\n".join(L)
    out = pack_root / "report" / "REPORT-TECHNICAL-v3.md"
    out.write_text(md, encoding="utf-8")
    report_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()
    root_meta = _load(pack_root / "META.json") or {}
    locator_manifest = {
        "schema": "winre-report-evidence-locators/v1",
        "sha256": sha,
        "run_id": root_meta.get("run_id"),
        "report_sha256": report_sha256,
        "locators": {locator_id: {"reference": ref}
                     for ref, locator_id in locator_ids.items()},
        "claims": [{"text": row["text"], "locators": row["locators"]}
                   for row in claim_rows],
        "unresolved_requested_refs": unresolved_requested_refs,
        "over_broad_refs": over_broad_refs,
    }
    (pack_root / "report" / "evidence-locators.json").write_text(
        json.dumps(locator_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    from .report_quality import review_report
    claim_review = review_report(pack_root, report_path=out,
                                 enabled=review_claims)
    return {"ok": True, "path": str(out), "sections": 9,
            "length": len(md), "claim_review": claim_review,
            "over_broad_refs": list(over_broad_refs)}


def _behavior_context(ev: dict) -> dict:
    """Kill-switch / CLI-behavior / artifact-catalog from static evidence
    (MalTrak WannaCry/NotPetya/Emotet report structure; AMAT anti-sandbox)."""
    text_pool: list[str] = []
    for k in ("strings_tool", "floss", "ioc_extract"):
        v = ev.get(k)
        if isinstance(v, dict):
            for key in ("decoded_strings", "strings", "urls", "domains"):
                val = v.get(key)
                if isinstance(val, list):
                    text_pool.extend(str(x) for x in val)
    joined = " ".join(text_pool).lower()

    kill_switch: list[str] = []
    import re as _re
    domains = {d for d in _re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|onion|cc|top|ru|xyz)\b", joined)}
    caps = {str(c.get("name") or "").lower() for c in
            ((ev.get("capa") or {}).get("capabilities") or [])
            if isinstance(c, dict)}
    if any("anti-vm" in c or "anti-sandbox" in c for c in caps):
        kill_switch.append("anti-sandbox/anti-vm capability (capa)")

    cli: list[str] = []
    for s in text_pool:
        t = str(s).strip()
        if (t.startswith(("-", "/", "--")) and 2 <= len(t) <= 32
                and not t.lower().startswith(("https://", "http://", "hxxp"))):
            cli.append(t)
    cli = list(dict.fromkeys(cli))[:10]

    mutexes = [s for s in text_pool
               if ("global\\" in str(s).lower() or "local\\" in str(s).lower())]
    registry = [s for s in text_pool
                if "hkcu\\" in str(s).lower() or "hklm\\" in str(s).lower()
                or str(s).startswith("HKEY_")]
    svc = [s for s in text_pool if "create service" in str(s).lower()
           or "schtasks" in str(s).lower()]
    paths = [s for s in text_pool
             if ("\\appdata" in str(s).lower() or "\\programdata" in str(s).lower()
                 or "%temp%" in str(s).lower() or "\\windows\\" in str(s).lower())]
    return {
        "kill_switch": kill_switch[:8],
        "domains": sorted(domains)[:10],
        "cli": cli,
        "artifacts": {
            "mutexes": list(dict.fromkeys(mutexes))[:5],
            "registry": list(dict.fromkeys(registry))[:5],
            "services": list(dict.fromkeys(svc))[:5],
            "paths": list(dict.fromkeys(paths))[:5],
        },
    }


def build_audit_report(pack_root: Path) -> dict:
    audit = _load(pack_root / "audit.json") or {}
    L = [f"# WinRE Audit Report — {sha_of(pack_root)[:16]}…", "",
         f"Generated: {_utc()}", "",
         f"- truly_green: **{audit.get('truly_green')}**",
         f"- all_green: {audit.get('all_green')} | quality_green: "
         f"{audit.get('quality_green')}",
         f"- fallback stages: {audit.get('fallback_stages') or 'none'}",
         f"- failed tools: {audit.get('failed_tools') or 'none'}",
         f"- unmet expectations: "
         f"{', '.join(audit.get('unmet_expectations') or []) or 'none'}",
         f"- deep verdict: {audit.get('deep_verdict')} "
         f"(source: {audit.get('deep_verdict_source')})",
         f"- llm roles: {json.dumps(audit.get('llm_roles'))}",
         f"- dynamic conflict: {audit.get('dynamic_conflict')}",
         f"- execution plan: {json.dumps(audit.get('execution_plan'))}",
         f"- snapshot gate: {json.dumps(audit.get('snapshot_gate'))}", "",
         "| stage | ran | error |", "|---|---|---|"]
    for c in audit.get("checks") or []:
        err = (c.get("error") or "")[:80].replace("|", "\\|")
        L.append(f"| {c.get('stage')} | {c.get('ran')} | {err} |")
    out = pack_root / "report" / "AUDIT-REPORT.md"
    out.write_text("\n".join(L), encoding="utf-8")
    return {"ok": True, "path": str(out)}


def build_evidence_bundle(pack_root: Path) -> dict:
    L = [f"# Evidence Bundle — {sha_of(pack_root)[:16]}…", "",
         "Every evidence item with its provenance (raw file + producer stage).", ""]
    index = []
    for stage, files in (
            ("intake", ["intake.json", "META.json"]),
            ("quick", ["quick.json", "01-tools-raw.json", "META.json"]),
            ("deep", ["deep.json", "01-tools-raw.json", "META.json"]),
            ("dynamic", ["META.json", "STAGE.json", "SKIP.json",
                         "frida_trace.json", "procmon_summary.json",
                         "network.json"]),
            ("yara", ["rule_report.json", "META.json"]),
            ("report", ["report.json", "iocs.json", "META.json",
                         "REPORT-TECHNICAL-v3.md", "evidence-locators.json",
                         "claim-review.json"])):
        d = pack_root / stage
        if not d.is_dir():
            continue
        for f in files:
            p = d / f
            if p.is_file():
                index.append({"stage": stage, "file": f"{stage}/{f}",
                              "size": p.stat().st_size})
    for f in ("stage_trace.json", "audit.json"):
        p = pack_root / f
        if p.is_file():
            index.append({"stage": "root", "file": f, "size": p.stat().st_size})
    L.append("| location | size |")
    L.append("|---|---|")
    for it in index:
        L.append(f"| `{it['file']}` | {it['size']:,} |")
    L.append("")
    L.append("Report evidence keys resolve to exact artifact fields in "
             "`report/evidence-locators.json`; claim-level support results are "
             "in `report/claim-review.json`. Raw tool outputs remain under their "
             "own stage paths and are not replaced by report prose.")
    out = pack_root / "report" / "EVIDENCE-BUNDLE.md"
    out.write_text("\n".join(L), encoding="utf-8")
    return {"ok": True, "path": str(out), "items": len(index)}


def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


_PUB_FILES = (
    ("report", "REPORT-TECHNICAL-v3.md"),
    ("report", "evidence-locators.json"),
    ("report", "claim-review.json"),
    ("report", "iocs.json"),
    ("report", "AUDIT-REPORT.md"),
    ("report", "EVIDENCE-BUNDLE.md"),
    ("report", "report.json"),
    ("yara", None),  # rule_report.json + generated rules, handled below
    ("", "audit.json"),
    ("", "stage_trace.json"),
    ("", "META.json"),
)


def _sanitize_text(text: str) -> str:
    """Redact lab specifics so published packs stay public-safe."""
    red = IP_RE.sub("<redacted-ip>", text)
    red = re.sub(r"C:\\Users\\[^\\/\s\"']+", r"C:\\Users\\analyst", red)
    for token in ("FLARE-VM", "desktop-s8k347p"):
        red = red.replace(token, "<redacted-host>")
    red = re.sub(r"cadre-[0-9a-z.\-]*key", "<redacted-key>", red,
                 flags=re.IGNORECASE)
    red = re.sub(r"(?i)(api[_-]?key\s*[\"':=]+\s*)[^\s\"',}]+",
                 r"\1<redacted>", red)
    return red


def _mode_of_pack(pack_root: Path) -> str:
    meta = _load(pack_root / "META.json") or {}
    if meta.get("mode") in ("static", "agentic"):
        return meta["mode"]
    deep_meta = _load(pack_root / "deep" / "META.json") or {}
    if deep_meta.get("mode") in ("static", "agentic"):
        return deep_meta["mode"]
    engine = str(deep_meta.get("engine") or "")
    return "static" if "static" in engine else "agentic"


def publish_case(pack_root: Path, dest_root: Path | None = None,
                 mode: str | None = None) -> dict:
    """Publish a sanitized, mode-keyed case directory.

    Default destination: <repo>/docs/case-studies/<mode>/<sha>/.
    Only report-level artifacts (no binaries, no raw pcaps/dumps).
    """
    pack_root = Path(pack_root)
    sha = sha_of(pack_root)
    mode = mode or _mode_of_pack(pack_root)
    if mode not in ("static", "agentic"):
        mode = "agentic"
    if dest_root is None:
        dest_root = Path(__file__).resolve().parents[1] / "docs" / "case-studies"
    dest = Path(dest_root) / mode / sha
    dest.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for stage, name in _PUB_FILES:
        if name is None:  # yara rules: generated rule files only
            ydir = pack_root / "yara"
            if ydir.is_dir():
                for f in sorted(ydir.iterdir()):
                    if f.is_file() and f.suffix in (".yar", ".yml"):
                        (dest / f.name).write_text(
                            _sanitize_text(f.read_text(encoding="utf-8",
                                                       errors="replace")),
                            encoding="utf-8")
                        copied.append(f"yara/{f.name}")
            continue
        src = (pack_root / stage / name) if stage else (pack_root / name)
        if not src.is_file():
            continue
        (dest / src.name).write_text(
            _sanitize_text(src.read_text(encoding="utf-8", errors="replace")),
            encoding="utf-8")
        copied.append(f"{stage + '/' if stage else ''}{src.name}")
    (dest / "CASE.json").write_text(json.dumps({
        "sha256": sha,
        "mode": mode,
        "run_id": ((_load(pack_root / "META.json") or {}).get("run_id")),
        "engine": ((_load(pack_root / "deep" / "META.json") or {}).get("engine")),
        "source": ((_load(pack_root / "report" / "report.json") or {}).get("source")),
        "published_at": _utc(),
        "files": copied,
    }, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "mode": mode, "dest": str(dest), "files": copied}


def generate_all(pack_root: Path, *, review_claims: bool = True) -> dict:
    """Full reporting chain for one pack (static now; dynamic appends later)."""
    results = {}
    quick = _load(pack_root / "quick" / "quick.json") or {}
    deep = _load(pack_root / "deep" / "deep.json") or {}
    dyn_meta = _load(pack_root / "dynamic" / "META.json")

    results["tools_raw"] = write_tools_raw(pack_root)
    results["stage_trace"] = write_stage_trace(pack_root)

    # IOC extraction (dynamic network intel when present)
    dynamic_ctx = None
    ni = pack_root / "dynamic" / "network_intel.json"
    if ni.is_file():
        dynamic_ctx = {"network_intel": _load(ni) or {}}
    iocs = extract_iocs(quick, deep, dynamic_ctx)
    (pack_root / "report" / "iocs.json").write_text(
        json.dumps(iocs, indent=2) + "\n", encoding="utf-8")
    results["iocs"] = {"urls": len(iocs["urls"]), "domains": len(iocs["domains"]),
                       "ips": len(iocs["ips"]), "mutexes": len(iocs["mutexes"])}

    results["report_v3"] = build_report_v3(
        pack_root, review_claims=review_claims)
    results["audit_report"] = build_audit_report(pack_root)
    results["evidence_bundle"] = build_evidence_bundle(pack_root)
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("usage: reporting.py <pack_root>")
        sys.exit(0 if len(sys.argv) > 1 else 2)
    _root = Path(sys.argv[1])
    if not _root.is_dir():
        print(f"error: not a directory: {_root}", file=sys.stderr)
        sys.exit(2)
    res = generate_all(_root)
    print(json.dumps(res, indent=2, default=str))
