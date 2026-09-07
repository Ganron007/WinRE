#!/usr/bin/env python3
"""static_deep.py — deterministic deep dive (RevAI `scripted` equivalent).

Runs the SAME 24-tool surface as the LangGraph agent, but with a FIXED
checklist instead of LLM-chosen calls, and a RULES-BASED verdict instead
of an LLM judge. Zero LLM calls. Same output contract as
run_langgraph_deep_dive (source/verdict/history/llm_analysis) so all
downstream reporting works unchanged.

Mode plumbing: mode="local" (VM-side subprocess) or "remote" (SSH-exec),
via ToolRegistry — same as the agent.

Verdict rules (conservative, evidence-cited):
  malicious/high   — curated YARA hit OR malcat yara_hits
  malicious/medium — ransomware-family capa cluster OR
                     (packed + XOR-encoded strings + forged metadata)
  suspicious       — packed/high-entropy + anomalies, or forged metadata,
                     or high-signal imports alone
  unknown          — nothing fires (honest)
"""
from __future__ import annotations

import json
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# capa capabilities that, as a CLUSTER, indicate ransomware-family behavior.
# Single capabilities never decide alone — see _rules_verdict.
RANSOMWARE_CAPA = {
    "encrypt data", "encrypt files", "delete shadow copies",
    "disable recovery", "ransom note", "payment",
    "enumerate files", "spread via network shares",
}
EXFIL_CAPA = {
    "steal credentials", "keylogging", "screenshot", "clipboard",
    "exfiltrate", "upload data",
}


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _as_hit_names(v) -> list:
    """YARA hit payloads arrive list- OR dict-shaped (MCP envelopes,
    malcat views, quick helpers). Normalize to a list of names — never
    slice a dict (py3.14 raises KeyError: slice(None, 3, None))."""
    if isinstance(v, dict):
        for k in ("hits", "matches", "rules", "results", "names"):
            inner = v.get(k)
            if isinstance(inner, list):
                return inner
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    if isinstance(v, str) and v.strip():
        return [v]
    return []


def _dict_of(v) -> dict:
    """Evidence values may be a dict, a list, or an error string."""
    return v if isinstance(v, dict) else {}


def _rules_verdict(ev: dict) -> dict:
    """Deterministic verdict from collected evidence. Returns verdict dict."""
    reasons: list[str] = []

    # 1. YARA (curated ruleset scan OR malcat yara engine)
    yh = _dict_of(ev.get("yarascan"))
    hits = _as_hit_names(yh.get("hits"))
    my = _as_hit_names(ev.get("malcat_yara"))
    if hits or my:
        names = [str(h).split()[0][:60] for h in (hits[:3] + my[:3])]
        reasons.append("yara hits: " + ", ".join(names))
        return {"verdict": "malicious", "confidence": "high",
                "summary": "Curated YARA rule match on the sample.",
                "key_evidence": reasons, "rules_fired": ["yara-hit"]}

    # 2. ransomware/exfil capa clusters
    capa = _dict_of(ev.get("capa"))
    caps = {(c.get("name") or "").lower() for c in (capa.get("capabilities") or [])
            if isinstance(c, dict)}
    ransom_hits = {c for c in caps if any(k in c for k in RANSOMWARE_CAPA)}
    exfil_hits = {c for c in caps if any(k in c for k in EXFIL_CAPA)}
    if len(ransom_hits) >= 2:
        reasons.append("capa ransomware cluster: " + ", ".join(sorted(ransom_hits)[:5]))
        return {"verdict": "malicious", "confidence": "medium",
                "summary": "Ransomware-family capability cluster (capa).",
                "key_evidence": reasons, "rules_fired": ["capa-ransomware-cluster"]}
    if len(exfil_hits) >= 2:
        reasons.append("capa exfil cluster: " + ", ".join(sorted(exfil_hits)[:5]))
        return {"verdict": "malicious", "confidence": "medium",
                "summary": "Exfiltration capability cluster (capa).",
                "key_evidence": reasons, "rules_fired": ["capa-exfil-cluster"]}

    # 3. packed + XOR strings + forged metadata cluster
    pe = _dict_of(ev.get("pe_parse"))
    secs = pe.get("sections") or []
    high_ent = [s for s in secs if isinstance(s, dict)
                and (s.get("entropy") or 0) >= 7.0]
    packed = bool(high_ent) or "pack" in json.dumps(
        ev.get("diec") or {}).lower()
    xor_ev = _dict_of(ev.get("xor_string_search"))
    xors = xor_ev.get("candidates") or []
    forged = False
    vi = pe.get("version_info") or {}
    if isinstance(vi, dict):
        vals = " ".join(str(v) for v in vi.values())
        # forged = gibberish company/product names
        forged = bool(vals) and not any(
            w in vals.lower() for w in ("microsoft", "google", "mozilla",
                                        "apple", "adobe"))
    if packed and xors and forged:
        reasons.append(f"packed ({len(high_ent)} high-entropy sections)")
        reasons.append(f"XOR-encoded strings: {len(xors)} candidates")
        reasons.append("version metadata looks forged")
        return {"verdict": "malicious", "confidence": "medium",
                "summary": "Packed binary with encoded strings and forged "
                           "metadata (dropper/loader pattern).",
                "key_evidence": reasons,
                "rules_fired": ["packed+xor+forged-metadata"]}

    # 4. suspicious singles
    sig_ev = _dict_of(ev.get("pe_import_signals"))
    sigs = sig_ev.get("signals") or []
    if sigs:
        reasons.append("high-signal imports: " + ", ".join(
            s.get("label", "?") for s in sigs[:5] if isinstance(s, dict)))
    if packed or high_ent:
        reasons.append(f"packed/high-entropy ({len(high_ent)} sections >= 7.0)")
    if forged:
        reasons.append("version metadata looks forged")
    anoms = (ev.get("malcat_anomalies") or [])
    if anoms:
        reasons.append(f"malcat anomalies: {len(anoms)}")
    if reasons:
        return {"verdict": "suspicious", "confidence": "medium",
                "summary": "Suspicious static indicators, no decisive match.",
                "key_evidence": reasons, "rules_fired": ["suspicious-singles"]}

    return {"verdict": "unknown", "confidence": "low",
            "summary": "No static indicator fired.",
            "key_evidence": [], "rules_fired": []}


def _is_dotnet(pe_ev: dict) -> bool:
    if not isinstance(pe_ev, dict):
        return False
    for entry in pe_ev.get("imports") or []:
        if isinstance(entry, dict) and "mscor" in str(entry.get("dll", "")).lower():
            return True
    return False


def _is_doc(sample: str) -> str | None:
    try:
        magic = Path(sample).read_bytes()[:8]
    except OSError:
        return None
    if magic[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if magic[:4] == b"PK\x03\x04":
        return "zip-office?"
    if magic[:5] == b"%PDF-":
        return "pdf"
    return None


def run_static_deep_dive(sample_name: str, sha: str, *,
                         max_steps: int = 30,
                         mode: str = "remote",
                         quick: dict | None = None,
                         cfg: dict | None = None) -> dict:
    """Deterministic deep dive over the static toolset (no LLM).

    Fixed checklist, bounded per-tool timeouts, rules-based verdict.
    Output contract matches run_langgraph_deep_dive, with
    source="static_deterministic".
    """
    from winre.agentic import ToolRegistry
    t0 = time.time()
    reg = ToolRegistry(sample_name, sha, cfg, mode=mode)
    history: list[dict] = []
    ev: dict = {}
    calls = 0

    def _run(tool: str, **kw):
        nonlocal calls
        if calls >= max_steps:
            return {"skipped": "checklist budget exhausted"}
        calls += 1
        try:
            r = reg.call(tool, kw)
        except Exception as e:
            r = {"error": str(e)[:200]}
        ev[tool] = r
        history.append({"step": len(history) + 1, "tool": tool,
                        "args": kw,
                        "result": r if len(json.dumps(r, default=str)) < 60000
                        else {"truncated": True,
                              "keys": list(r.keys()) if isinstance(r, dict) else []},
                        "error": r.get("error") if isinstance(r, dict) else None})
        return r

    # 1. structure first (grounds everything)
    _run("pe_parse")
    _run("pe_import_signals")
    _run("diec")
    # 2. capabilities + metadata
    _run("capa")
    _run("malcat_analyze")
    _run("malcat_functions", count=10)
    # 3. SQL surfaces
    _run("ghidra_query", sql="SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 20",
         max_rows=20)
    _run("ghidra_query", sql="SELECT content, address FROM strings LIMIT 25",
         max_rows=25)
    _run("ida_query", sql="SELECT name, address, size FROM funcs LIMIT 20")
    # 4. strings (plain, decoded, encoded)
    _run("strings_tool")
    _run("floss")
    _run("xor_string_search")
    # 5. curated rules + signatures
    _run("yarascan")
    gh = {} if not isinstance(ev.get("ghidra_query"), dict) else ev["ghidra_query"]
    # 6. decompile the largest function (if any found) + signature-match it
    rows = (gh.get("rows") or []) if isinstance(gh, dict) else []
    top_fn: dict = {}
    if rows:
        addr = None
        try:
            addr = rows[0][1] if isinstance(rows[0], (list, tuple)) else rows[0].get("address")
        except Exception:
            addr = None
        if addr:
            _run("ghidra_decompile", function_addr=str(addr))
        try:
            top_fn = {"name": str(rows[0][0]), "size": int(rows[0][2])} \
                if isinstance(rows[0], (list, tuple)) and len(rows[0]) > 2 else {}
        except Exception:
            top_fn = {}
    pe_imps: list[str] = []
    for entry in (ev.get("pe_parse") or {}).get("imports") or []:
        if isinstance(entry, dict):
            pe_imps.extend(entry.get("functions") or [])
    str_sample: list[str] = []
    for s in ((ev.get("floss") or {}).get("decoded_strings") or [])[:20]:
        str_sample.append(str(s))
    _run("signature_match", func_name=top_fn.get("name", ""),
         imports=pe_imps[:40], strings=str_sample[:20],
         size=top_fn.get("size", 0))
    # 7. format-gated extras
    if _is_dotnet(ev.get("pe_parse") or {}):
        _run("dotnet_analyze")
    doc = _is_doc(reg.remote_sample)
    if doc == "ole":
        _run("olevba_analyze")
    elif doc == "pdf":
        _run("peepdf_analyze")
    # 8. second engines + emulation (bounded, best-effort)
    _run("r2_decompile")
    _run("upx_unpack")
    _run("speakeasy_emulate")
    _run("shellcode_extract")
    _run("frida_static_probe")
    # 9. solvers last (only meaningful on obfuscation; cheap to attempt)
    _run("z3_solve")
    _run("angr_analyze")

    # quick-stage Malcat views (anomalies / yara) were captured during triage;
    # seed them so _rules_verdict sees the same evidence the agent does.
    q = (quick or {}).get("evidence") if isinstance(quick, dict) else None
    mcq = (q or {}).get("malcat") or {}
    if isinstance(mcq, dict):
        if mcq.get("yara_hits"):
            ev.setdefault("malcat_yara", mcq["yara_hits"])
        if mcq.get("anomalies"):
            ev.setdefault("malcat_anomalies", mcq["anomalies"])

    try:
        verdict = _rules_verdict(ev)
    except Exception as e:
        verdict = {"verdict": "unknown", "confidence": "low",
                   "summary": f"rules engine error: {str(e)[:120]}",
                   "key_evidence": [], "rules_fired": ["rules-error"]}
    elapsed = round(time.time() - t0, 1)
    return {"verdict": verdict, "source": "static_deterministic",
            "history": history, "llm_analysis": None,
            "tool_calls": calls, "elapsed_s": elapsed,
            "mode": "static"}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="WinRE deterministic deep dive")
    ap.add_argument("sha")
    ap.add_argument("--sample-name", required=True)
    ap.add_argument("--mode", default="remote", choices=["local", "remote"])
    ap.add_argument("--max-steps", type=int, default=30)
    args = ap.parse_args()
    print(json.dumps(run_static_deep_dive(
        args.sample_name, args.sha, mode=args.mode,
        max_steps=args.max_steps), indent=2, default=str))
