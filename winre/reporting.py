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

from .evidence import sha_of

URL_RE = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[^\s\"'<>`]{4,200}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
                   r"(?::\d{1,5})?")
SHA_RE = re.compile(r"\b[0-9a-f]{32,64}\b")
PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\[^\s\"'<>|*:?\[\]]{2,160}|/opt/[^\s\"'<>]{2,160}|"
    r"%[A-Z_]+%\\[^\s\"'<>]{2,160})")
MUTEX_RE = re.compile(r"(?:Global|Local)\\\\?[^\s\"'<>]{2,120}")
REGISTRY_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"'<>]{2,160}")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.){1,}(?:com|net|org|io|ru|cn|xyz|top|info|biz|su|cc|pw|me|tk|online|site|club|link)\b",
                       re.IGNORECASE)


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
    """Deterministic IOC extraction from static (and dynamic when present).
    Sources: malcat strings/yara, floss decoded, strings tool, xor candidates,
    pe version_info, network intel. No LLM."""
    urls: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()
    emails: set[str] = set()
    paths: set[str] = set()
    mutexes: set[str] = set()
    registry: set[str] = set()
    hashes: set[str] = set()

    def scan_text(text: str):
        urls.update(u.rstrip(".,;)") for u in URL_RE.findall(text))
        for ip in IP_RE.findall(text):
            if not ip.startswith(("0.", "127.", "255.")):
                ips.add(ip)
        for e in EMAIL_RE.findall(text):
            emails.add(e.lower())
            domains.add(e.split("@")[-1].lower())
        for p in PATH_RE.findall(text):
            paths.add(p.rstrip("\\/"))
        for mx in MUTEX_RE.findall(text):
            mutexes.add(mx)
        for r in REGISTRY_RE.findall(text):
            registry.add(r.rstrip("\\/"))
        for d in DOMAIN_RE.findall(text):
            domains.add(d.lower())

    q = (quick or {}).get("evidence") or {}
    mal = q.get("malcat") or {}
    for s in (mal.get("strings") or []):
        if isinstance(s, str):
            scan_text(s)
    for s in (q.get("floss") or {}).get("decoded_strings") or []:
        scan_text(str(s))
    for s in (q.get("strings") or {}).get("strings") or []:
        scan_text(str(s))
    for c in (q.get("xor_string_search") or {}).get("candidates") or []:
        scan_text(str(c.get("string", "")))
    pe = q.get("pe") or {}
    for entry in pe.get("imports") or []:
        if isinstance(entry, dict):
            scan_text(entry.get("dll", ""))
    for k, v in (pe.get("version_info") or {}).items():
        scan_text(f"{k}={v}")
    for cap in (q.get("capa") or {}).get("capabilities") or []:
        scan_text(str(cap.get("name", "")))

    # agent narrative (deep) — LLM-tagged source
    agent = (deep or {}).get("agent") or {}
    scan_text(str(agent.get("llm_analysis") or ""))
    for h in (agent.get("history") or []):
        scan_text(json.dumps(h.get("result") or "")[:4000])

    # dynamic (when present)
    if dynamic:
        ni = dynamic.get("network_intel") or {}
        for cap in ni.get("captures") or []:
            for d_ in cap.get("dns_queries") or []:
                domains.add(str(d_).lower())
            for h in cap.get("http_requests") or []:
                scan_text(str(h))

    iocs = {
        "schema": "winre-iocs/v1",
        "generated_at": _utc(),
        "urls": sorted(urls)[:80],
        "ips": sorted(ips)[:80],
        "domains": sorted(d for d in domains if d)[:80],
        "emails": sorted(emails)[:40],
        "file_paths": sorted(paths)[:60],
        "mutexes": sorted(mutexes)[:40],
        "registry_keys": sorted(registry)[:40],
        "hashes": sorted(hashes)[:20],
        "sources": ["malcat", "floss", "strings", "xor_string_search",
                    "pe_version_info", "agent_narrative(llm_tagged)"]
        + (["dynamic_network"] if dynamic else []),
    }
    return iocs


def _cite(raw_path: str, note: str) -> str:
    return f"{note} — raw: `{raw_path}`"


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
    for h in ((deep.get("agent") or {}).get("history") or []):
        res = h.get("result")
        if isinstance(res, dict) and h.get("tool"):
            deep_ev[h["tool"]] = res
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
    composition = _load(pack_root / "composite.json") or {}
    selected_level = composition.get("level") or verdict.get("verdict")
    selected_confidence = (composition.get("confidence")
                           or verdict.get("confidence"))
    selected_source = ("mode-composite" if composition.get("level")
                       else src)
    raw = pack_root / "deep" / "01-tools-raw.json"

    L: list[str] = []
    locator_ids: dict[str, str] = {}
    claim_rows: list[dict] = []
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

    def set_evidence(*refs: str) -> None:
        nonlocal active_refs
        accepted = []
        for ref in dict.fromkeys(str(ref).strip() for ref in refs
                                 if str(ref).strip()):
            if ref not in reference_cache:
                reference_cache[ref] = _reference_exists(ref)
            if reference_cache[ref]:
                accepted.append(ref)
            elif ref not in unresolved_requested_refs:
                unresolved_requested_refs.append(ref)
        active_refs = tuple(accepted)

    def raw_frida_refs(*, event_refs: list | tuple | None = None,
                       apis: list | tuple | None = None) -> list[str]:
        refs = []
        for event_ref in event_refs or []:
            value = str(event_ref).strip()
            if value and len(value) <= 256 and "#" not in value:
                refs.append(f"dynamic/frida_trace.jsonl#@invocation_id={value}")
        for api in apis or []:
            value = str(api).strip()
            if value and len(value) <= 256 and "#" not in value:
                refs.append(f"dynamic/frida_trace.jsonl#@api={value}")
        return list(dict.fromkeys(refs))

    def A(line: str) -> None:
        """Append report prose with stable locators for its source fields."""
        text = str(line)
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
    set_evidence("deep/deep.json#$.agent.source",
                 "deep/deep.json#$.agent.verdict")
    A(f"- **Analysis source:** `{src}`")
    A("")

    A("## 1. Verdict")
    A("")
    set_evidence("composite.json#$.level", "composite.json#$.confidence",
                 "composite.json#$.basis", "deep/deep.json#$.agent.verdict")
    A(f"- Pipeline-selected verdict: **{str(selected_level or 'unknown').upper()}** "
      f"(confidence: {selected_confidence or 'n/a'}); recorded source `{selected_source}`.")
    if composition.get("deciding_mode"):
        A(f"- Deciding mode: `{composition['deciding_mode']}`")
    if composition.get("basis"):
        A("- Composite basis: " + ", ".join(
            f"`{item}`" for item in composition["basis"][:10]))
    A("")
    A("## 2. File overview")
    A("")
    set_evidence("quick/quick.json#$.evidence.pe")
    pe = ev.get("pe") or {}
    if pe:
        A(f"- Machine: `{pe.get('machine')}` entrypoint `0x{pe.get('entrypoint', 0):x}` "
          f"timestamp {pe.get('compile_ts')}")
        A(f"- Signed: **{pe.get('signed')}**")
        A(f"- Sections: " + ", ".join(
            f"`{s.get('name')}` (entropy {s.get('entropy')})"
            for s in (pe.get("sections") or [])[:10]))
        imp_count = sum(len(e.get("functions") or []) for e in pe.get("imports") or [])
        A(f"- Imports: {len(pe.get('imports') or [])} DLLs, {imp_count} functions")
    gh = ev.get("ghidra") or {}
    if gh:
        set_evidence("quick/quick.json#$.evidence.ghidra",
                     "deep/deep.json#$.agent.history[*].result")
        A(f"- Ghidra: {gh.get('func_rows', 0)} functions")
    else:
        set_evidence("quick/quick.json#$.tool_failures")
        A("- Ghidra: no result recorded by the quick stage.")
    ida = ev.get("ida") or {}
    if ida.get("func_count") is not None:
        set_evidence("quick/quick.json#$.evidence.ida",
                     "deep/deep.json#$.agent.history[*].result")
        A(f"- IDA: {ida.get('func_count')} functions (.i64 created at quick stage)")
    A("")

    A("## 3. Static evidence (per tool)")
    A("")
    capa = ev.get("capa") or {}
    A("### capa (Mandiant rules)")
    set_evidence("quick/quick.json#$.evidence.capa.capabilities",
                 "deep/deep.json#$.agent.history[*].result")
    if capa.get("ok"):
        for c in (capa.get("capabilities") or [])[:15]:
            atk = ", ".join(c.get("attack") or [])
            A(f"- {c.get('name')}" + (f" [{atk}]" if atk else ""))
    else:
        A(f"- skipped/error: {capa.get('skipped') or capa.get('error')}")
    A("")
    floss = ev.get("floss") or {}
    A("### floss (deobfuscated strings)")
    set_evidence("quick/quick.json#$.evidence.floss.decoded_strings",
                 "deep/deep.json#$.agent.history[*].result")
    ds = floss.get("decoded_strings") or []
    if ds:
        for s in ds[:15]:
            A(f"- `{s[:120]}`")
    else:
        A(f"- none decoded ({floss.get('total_decoded', 0)} total)")
    A("")
    mal = ev.get("malcat") or {}
    A("### Malcat")
    set_evidence("quick/quick.json#$.evidence.malcat",
                 "deep/deep.json#$.agent.history[*].result")
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
    xs = ev.get("xor_string_search") or {}
    A("### XOR-encoded strings (brute force)")
    set_evidence("quick/quick.json#$.evidence.xor_string_search.candidates",
                 "deep/deep.json#$.agent.history[*].result")
    for c in (xs.get("candidates") or [])[:10]:
        A(f"- [{c.get('mode')} key={c.get('key')}] offset {c.get('offset')}: "
          f"`{str(c.get('string'))[:100]}`")
    if not xs.get("candidates"):
        A("- none found")
    A("")
    sig = ev.get("signature_match")
    A("### Signature DB match (agent-invoked)")
    set_evidence("deep/deep.json#$.agent.history",
                 "deep/deep.json#$.agent.history[*].result")
    A(f"- {json.dumps(sig, default=str)[:300]}" if sig else "- not invoked")
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
    set_evidence("deep/deep.json#$.agent.verdict",
                 "deep/deep.json#$.agent.history[*].result",
                 "quick/quick.json#$.evidence")
    A(f"- Agent analysis record: source=`{src}`; declared verdict=`{verdict.get('verdict', 'unknown')}`; "
      f"confidence=`{verdict.get('confidence', 'n/a')}`.")
    if verdict.get("summary"):
        A(f"- Assessment: {verdict['summary']}")
    for evidence_item in (verdict.get("key_evidence") or [])[:20]:
        A(f"- Key evidence: {evidence_item}")
    A("")

    A("## 5. IOC table")
    A("")
    _ioc_refs = ["report/iocs.json#$.urls", "report/iocs.json#$.domains",
                 "report/iocs.json#$.ips", "report/iocs.json#$.emails",
                 "report/iocs.json#$.file_paths",
                 "report/iocs.json#$.mutexes",
                 "report/iocs.json#$.registry_keys",
                 "quick/quick.json#$.evidence"]
    if agent.get("history"):
        _ioc_refs.append("deep/deep.json#$.agent.history[*].result")
    if has_dynamic:
        _ioc_refs.append("dynamic/network_intel.json#$.network")
    set_evidence(*_ioc_refs)
    if iocs:
        A(f"- URLs: {len(iocs.get('urls') or [])}" +
          (": " + ", ".join(f"`{u}`" for u in iocs["urls"][:8]) if iocs.get("urls") else ""))
        A(f"- Domains: {len(iocs.get('domains') or [])}" +
          (": " + ", ".join(f"`{d}`" for d in iocs["domains"][:8]) if iocs.get("domains") else ""))
        A(f"- IPs: {len(iocs.get('ips') or [])}" +
          (": " + ", ".join(f"`{i}`" for i in iocs["ips"][:8]) if iocs.get("ips") else ""))
        A(f"- Emails: {len(iocs.get('emails') or [])}" +
          (": " + ", ".join(f"`{e}`" for e in iocs["emails"][:8]) if iocs.get("emails") else ""))
        A(f"- File paths: {len(iocs.get('file_paths') or [])}")
        A(f"- Mutexes: {len(iocs.get('mutexes') or [])}")
        A(f"- Registry keys: {len(iocs.get('registry_keys') or [])}")
    else:
        A("- (no iocs.json)")
    A("")
    crypto = ev.get("crypto_constants") or {}
    crypto_ids = crypto.get("crypto_identified") or []
    if crypto_ids:
        set_evidence("quick/quick.json#$.evidence.crypto_constants",
                     "deep/deep.json#$.agent.history[*].result")
        A(f"- **Crypto identified (constants/shape):** "
          + ", ".join(f"`{c}`" for c in crypto_ids[:8])
          + " — config/key recovery leads (signature_match may resolve keys).")
        A("")
    dg = ev.get("decrypt_gate") or {}
    if dg.get("status") == "gate":
        set_evidence("quick/quick.json#$.evidence.decrypt_gate",
                     "deep/deep.json#$.agent.history[*].result")
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
        A("- **Kill-switch / sandbox-avoidance candidates:** "
          + "; ".join(f"`{k}`" for k in ks[:6])
          + " — NOTE: connectivity to these may be a NO-OP signal, not C2 "
          "(WannaCry-class); treat as its own analytic dimension.")
    else:
        A("- No kill-switch/sandbox-avoidance candidates surfaced.")
    cli = _bc.get("cli") or []
    if cli:
        A(f"- **CLI behavior table:** " + "; ".join(f"`{c}`" for c in cli[:8])
          + " (switches from strings + GetCommandLine imports; verify per-branch "
          "in the debugger/dynamic phase).")
    art = _bc.get("artifacts") or {}
    if art:
        A("- **Artifact catalog:** mutexes: "
          + "; ".join(f"`{m}`" for m in (art.get("mutexes") or [])[:5])
          + " | registry: "
          + "; ".join(f"`{r}`" for r in (art.get("registry") or [])[:5])
          + " | services/tasks: "
          + "; ".join(f"`{t}`" for t in (art.get("services") or [])[:5])
          + " | file paths: "
          + "; ".join(f"`{p}`" for p in (art.get("paths") or [])[:5]))
    A("")

    A("## 7. YARA")
    A("")
    set_evidence("yara/rule_report.json#$.rule_id",
                 "yara/rule_report.json#$.curation",
                 "quick/quick.json#$.evidence")
    A(f"- Rule: `{yara_rep.get('rule_id')}` — "
      f"empty_rule={yara_rep.get('empty_rule')} — deterministic, no LLM content")
    cur = (yara_rep.get("curation") or {})
    if cur.get("warnings"):
        A(f"- Curation warnings: {'; '.join(cur['warnings'])}")
    A("")

    A("## 8. Execution evidence")
    A("")

    set_evidence("artifact-manifest.json#$.artifact_count",
                 "artifact-manifest.json#$.coverage")
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
            set_evidence("findings.json#$.findings.unpack",
                         "dynamic/windbg_analysis.json#$.oep")
            if (debugger_probe.get("method") == "entrypoint_observation"
                    and debugger_probe.get("address")):
                A("- Unpack result: the debugger observed the original image "
                  f"entry point `{debugger_probe['address']}`; no unpacked dump "
                  "was produced. This does not invalidate a completed "
                  "debugger observation.")
            elif (debugger_probe.get("method") == "memory_execute_oep"
                  and debugger_probe.get("address")):
                A("- Unpack result: the debugger observed a candidate unpacked "
                  f"OEP at `{debugger_probe['address']}`, but no unpacked dump "
                  "was produced. This does not invalidate a completed "
                  "debugger observation.")
            else:
                A("- Unpack result: no unpacked OEP dump was recovered; this "
                  "does not invalidate a completed debugger observation.")
        for limitation in (finding_record.get("limitations") or [])[:5]:
            set_evidence("findings.json#$.limitations",
                         "artifact-manifest.json#$.coverage")
            A(f"- Limitation: {limitation}")
        A("")

    A("### Dynamic detonation")
    A("")

    set_evidence("artifact-manifest.json#$.artifact_count",
                 "artifact-manifest.json#$.coverage")
    inventory = _load(pack_root / "artifact-manifest.json") or {}
    coverage = inventory.get("coverage") or {}
    requested_gaps = [(name, row) for name, row in coverage.items()
                      if isinstance(row, dict) and row.get("requested")
                      and row.get("status") != "complete"]
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
        set_evidence("artifact-manifest.json#$.coverage")
        A(f"  - `{name}`: {row.get('status')} — {row.get('reason')}")

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
            if net.get("c2"):
                set_evidence("findings.json#$.findings.network.c2",
                             "dynamic/network_intel.json#$.captures[*]",
                             "dynamic/network.json#$.connections")
                A(f"  - **C2 candidates ({len(net['c2'])}):**")
                for c in net["c2"][:6]:
                    set_evidence("findings.json#$.findings.network.c2",
                                 "dynamic/network_intel.json#$.captures[*]",
                                 "dynamic/network.json#$.connections")
                    A(f"    - `{c.get('host')}` ({c.get('kind')})")
            if net.get("beacons"):
                set_evidence("findings.json#$.findings.network.beacons",
                             "dynamic/network_intel.json#$.captures[*]")
                A(f"  - beacon candidates: {len(net['beacons'])}")
            if net.get("frida_endpoint_count"):
                set_evidence("findings.json#$.findings.network",
                             "dynamic/frida_summary.json#$.network_endpoints")
                A(f"  - Frida endpoint observations: "
                  f"{net.get('frida_endpoint_count')} (sample-process API scope; "
                  f"truncated={net.get('frida_endpoints_truncated')})")
            fc = fd.get("frida_coverage") or {}
            if fc:
                set_evidence("findings.json#$.findings.frida_coverage",
                             "dynamic/frida_summary.json#$.hook_coverage")
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
                set_evidence("findings.json#$.findings.window",
                             "dynamic/META.json#$.job_timeout")
                gate = (f"gate {w.get('gate_kind')}/{w.get('gate_api')} "
                        f"at {w.get('gate_at_s')}s"
                        if w.get("gate_fired") else "gate did not fire")
                A(f"  - window: {w.get('effective_s')}s, "
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
                             "artifact-manifest.json#$.coverage")
                A("  - **limitations:**")
                for l in lim[:5]:
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
                     "execution_plan.json#$.execution_sites")
        if pack_mode == "dbg":
            A("- No dynamic detonation was observed in this debugger-assisted run. "
              "Detonation is a separate, opt-in producer and its findings land here.")
        else:
            A("- No dynamic detonation was observed in this run. Detonation is "
              "opt-in, segregated, snapshot-gated, and runs as a separate producer.")
        if dyn_stage.get("summary"):
            set_evidence("dynamic/STAGE.json#$.summary")
            A(f"- Dynamic stage: {dyn_stage['summary']}")
    # Correlation is a cited analysis aid, not a verdict input. It remains
    # visible in static-only packs so the report says explicitly that no
    # current-run dynamic comparison was available.
    corr = finding_record.get("correlation") or {}
    if corr:
        set_evidence("findings.json#$.correlation",
                     "quick/quick.json#$.evidence",
                     "dynamic/frida_summary.json#$.top_apis",
                     "dynamic/network_intel.json#$.captures[*]")
        A("### Static/runtime correlation (candidate links)")
        A("")
        A(f"- Status: `{corr.get('status')}`; this section does not change the verdict.")
        counts = corr.get("counts") or {}
        A("- Relationships: " + ", ".join(
            f"{name}={counts.get(name, 0)}" for name in
            ("confirmed", "predicted_not_observed", "observed_not_predicted", "unverifiable")))
        hyps = {h.get("id"): h for h in corr.get("hypotheses") or []
                if isinstance(h, dict)}
        obs = {o.get("id"): o for o in corr.get("observations") or []
               if isinstance(o, dict)}
        for rel in (corr.get("relationships") or [])[:8]:
            h = hyps.get(rel.get("hypothesis_id")) or {}
            matched = [obs[o] for o in (rel.get("observation_ids") or [])
                       if o in obs]
            label = h.get("value") or (matched[0].get("value") if matched else "unmatched candidate")
            A(f"  - `{rel.get('status')}` `{label}` — {rel.get('reason')}; "
              f"static refs={rel.get('hypothesis_refs') or 'none'}, "
              f"dynamic refs={rel.get('observation_refs') or 'none'}")
        for limitation in (corr.get("limitations") or [])[:5]:
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
    }
    (pack_root / "report" / "evidence-locators.json").write_text(
        json.dumps(locator_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    from .report_quality import review_report
    claim_review = review_report(pack_root, report_path=out,
                                 enabled=review_claims)
    return {"ok": True, "path": str(out), "sections": 9,
            "length": len(md), "claim_review": claim_review}


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
    if any("anti-vm" in c or "anti-sandbox" in c or "sleep" in c
           or "delay" in c for c in caps):
        kill_switch.append("anti-sandbox/anti-vm capability (capa)")
    for d in sorted(domains)[:5]:
        kill_switch.append(f"domain candidate: {d}")

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
