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

Deterministic only — the LLM narrative is included verbatim and tagged.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

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


def build_report_v3(pack_root: Path) -> dict:
    """REPORT-TECHNICAL-v3.md — RevAI v3 layout, deterministic sections."""
    sha = pack_root.name
    intake = _load(pack_root / "intake" / "intake.json") or {}
    quick = _load(pack_root / "quick" / "quick.json") or {}
    ev = quick.get("evidence") or {}
    deep = _load(pack_root / "deep" / "deep.json") or {}
    agent = (deep.get("agent") or {})
    verdict = agent.get("verdict") or {}
    if not isinstance(verdict, dict):
        verdict = {"verdict": verdict or "unknown"}
    audit = _load(pack_root / "audit.json") or {}
    iocs = _load(pack_root / "report" / "iocs.json") or {}
    yara_rep = _load(pack_root / "yara" / "rule_report.json") or {}
    dyn = _load(pack_root / "dynamic" / "META.json")
    has_dynamic = bool(dyn)
    raw = pack_root / "deep" / "01-tools-raw.json"

    L = []
    A = L.append
    A(f"# WinRE Technical Report (v3) — {sha[:16]}…")
    A("")
    A(f"- **SHA256:** `{intake.get('sha256', sha)}`")
    A(f"- **Sample:** `{intake.get('file', '?')}`  |  size {intake.get('size', '?')}  |  "
      f"format {intake.get('format', '?')}")
    A(f"- **Generated:** {_utc()}  |  **Phase:** "
      f"{'static+dynamic' if has_dynamic else 'static'}")
    src = agent.get("source") or "deterministic_fallback"
    A(f"- **Analysis source:** `{src}`  |  "
      f"**Audit:** truly_green={audit.get('truly_green')} "
      f"quality_green={audit.get('quality_green')}")
    A("")

    A("## 1. Verdict")
    A("")
    v = verdict.get("verdict") if isinstance(verdict, dict) else None
    conf = verdict.get("confidence") if isinstance(verdict, dict) else None
    A(f"**{str(v or 'unknown').upper()}** (confidence: {conf or 'n/a'}) — source `{src}`")
    A("")
    if isinstance(verdict, dict) and verdict.get("summary"):
        A(f"> {verdict['summary']}")
        A("")

    A("## 2. File overview")
    A("")
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
    A(f"- Ghidra: {gh.get('func_rows', 0)} functions")
    ida = ev.get("ida") or {}
    if ida.get("func_count") is not None:
        A(f"- IDA: {ida.get('func_count')} functions (.i64 created at quick stage)")
    A("")

    A("## 3. Static evidence (per tool)")
    A("")
    capa = ev.get("capa") or {}
    A("### capa (Mandiant rules)")
    if capa.get("ok"):
        for c in (capa.get("capabilities") or [])[:15]:
            atk = ", ".join(c.get("attack") or [])
            A(f"- {c.get('name')}" + (f" [{atk}]" if atk else ""))
    else:
        A(f"- skipped/error: {capa.get('skipped') or capa.get('error')}")
    A("")
    floss = ev.get("floss") or {}
    A("### floss (deobfuscated strings)")
    ds = floss.get("decoded_strings") or []
    if ds:
        for s in ds[:15]:
            A(f"- `{s[:120]}`")
    else:
        A(f"- none decoded ({floss.get('total_decoded', 0)} total)")
    A("")
    mal = ev.get("malcat") or {}
    A("### Malcat")
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
    for c in (xs.get("candidates") or [])[:10]:
        A(f"- [{c.get('mode')} key={c.get('key')}] offset {c.get('offset')}: "
          f"`{str(c.get('string'))[:100]}`")
    if not xs.get("candidates"):
        A("- none found")
    A("")
    sig = ev.get("signature_match")
    A("### Signature DB match (agent-invoked)")
    A(f"- {json.dumps(sig, default=str)[:300]}" if sig else "- not invoked")
    A("")
    imp_sig = ev.get("pe_import_signals") or {}
    A("### PE import signals")
    if imp_sig.get("signals"):
        for s in imp_sig["signals"][:12]:
            A(f"- {s.get('label')} ({s.get('api_match')}) [{', '.join(s.get('attack') or [])}]")
    else:
        A(f"- none ({imp_sig.get('import_count', 0)} imports scanned)")
    A("")
    pif = ev.get("pe_import_signals")  # placehlder alignment
    A("### Ghidra/IDA SQL highlights")
    A(f"- Ghidra funcs: {gh.get('func_rows', 0)}; imports surfaced: "
      f"{len(gh.get('imports') or [])}")
    if ida.get("func_count") is not None:
        A(f"- IDA funcs: {ida.get('func_count')}")
    A("")

    A("## 4. Agent analysis (LLM — verbatim, source-tagged)")
    A("")
    A(f"```json\n{json.dumps(verdict, indent=2, default=str)[:4000]}\n```")
    A("")

    A("## 5. IOC table")
    A("")
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

    A("## 6. YARA")
    A("")
    A(f"- Rule: `{yara_rep.get('rule_id')}` — "
      f"empty_rule={yara_rep.get('empty_rule')} — deterministic, no LLM content")
    A("")

    A("## 7. Dynamic analysis")
    A("")
    if has_dynamic:
        A(f"- Detonation ran (frida_events={dyn.get('frida_events')}) — "
          "dynamic section expanded after detonation stage; see `dynamic/` artifacts.")
    else:
        A("- Not run (static-only pack). Detonation is opt-in, segregated, "
          "runs LAST, snapshot-gated. Dynamic findings will append here: "
          "process behavior, network (FakeNet sink), Frida API trace, "
          "pe-sieve dumps, unpacked-image re-analysis.")
    A("")

    A("## 8. Honesty & audit")
    A("")
    A(f"- truly_green: **{audit.get('truly_green')}** | all_green: "
      f"{audit.get('all_green')} | quality_green: {audit.get('quality_green')}")
    A(f"- Fallback stages: {audit.get('fallback_stages') or 'none'}")
    A(f"- Failed tools: {audit.get('failed_tools') or 'none'}")
    A(f"- static_yara_wins: {audit.get('static_yara_wins')}")
    gate = audit.get("snapshot_gate") or {}
    A(f"- Snapshot gate: mode={gate.get('mode')} ok={gate.get('ok')}")
    A("")
    A("> **Reality check.** A green audit means the tooling ran and produced "
      "artifacts — not that the sample is benign or fully understood. "
      "Packed samples: behavioral intent requires the dynamic phase. "
      "Treat as a starting point for analyst review.")

    md = "\n".join(L)
    out = pack_root / "report" / "REPORT-TECHNICAL-v3.md"
    out.write_text(md, encoding="utf-8")
    return {"ok": True, "path": str(out), "sections": 8,
            "length": len(md)}


def build_audit_report(pack_root: Path) -> dict:
    audit = _load(pack_root / "audit.json") or {}
    L = [f"# WinRE Audit Report — {pack_root.name[:16]}…", "",
         f"Generated: {_utc()}", "",
         f"- truly_green: **{audit.get('truly_green')}**",
         f"- all_green: {audit.get('all_green')} | quality_green: "
         f"{audit.get('quality_green')}",
         f"- fallback stages: {audit.get('fallback_stages') or 'none'}",
         f"- failed tools: {audit.get('failed_tools') or 'none'}",
         f"- dynamic conflict: {audit.get('dynamic_conflict')}",
         f"- snapshot gate: {json.dumps(audit.get('snapshot_gate'))}", "",
         "| stage | ran | error |", "|---|---|---|"]
    for c in audit.get("checks") or []:
        err = (c.get("error") or "")[:80].replace("|", "\\|")
        L.append(f"| {c.get('stage')} | {c.get('ran')} | {err} |")
    out = pack_root / "report" / "AUDIT-REPORT.md"
    out.write_text("\n".join(L), encoding="utf-8")
    return {"ok": True, "path": str(out)}


def build_evidence_bundle(pack_root: Path) -> dict:
    L = [f"# Evidence Bundle — {pack_root.name[:16]}…", "",
         "Every evidence item with its provenance (raw file + producer stage).", ""]
    index = []
    for stage, files in (
            ("intake", ["intake.json", "META.json"]),
            ("quick", ["quick.json", "01-tools-raw.json", "META.json"]),
            ("deep", ["deep.json", "01-tools-raw.json", "META.json"]),
            ("dynamic", ["META.json", "STAGE.json", "frida_trace.json",
                         "procmon_summary.json", "network.json"]),
            ("yara", ["rule_report.json", "META.json"]),
            ("report", ["report.json", "iocs.json", "META.json"])):
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
    L.append("Raw tool outputs: `deep/01-tools-raw.json` (full, untruncated). "
             "Citations in REPORT-TECHNICAL-v3.md point here.")
    out = pack_root / "report" / "EVIDENCE-BUNDLE.md"
    out.write_text("\n".join(L), encoding="utf-8")
    return {"ok": True, "path": str(out), "items": len(index)}


def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def generate_all(pack_root: Path) -> dict:
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

    results["report_v3"] = build_report_v3(pack_root)
    results["audit_report"] = build_audit_report(pack_root)
    results["evidence_bundle"] = build_evidence_bundle(pack_root)
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: reporting.py <pack_root>", file=sys.stderr)
        sys.exit(2)
    res = generate_all(Path(sys.argv[1]))
    print(json.dumps(res, indent=2, default=str))
