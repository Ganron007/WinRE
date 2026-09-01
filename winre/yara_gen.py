#!/usr/bin/env python3
"""yara_gen.py — deterministic YARA/Sigma generation from WinRE evidence.

Ported approach from RevAI's yara_gen_v2.py, but Windows-native: rules are
built from what the WinRE pipeline actually collected (static SQL strings/
imports, Malcat strings, dynamic network IOCs). Deterministic — no LLM in the
rule bodies. Every rule records its evidence lineage.

Outputs (per sample, logs/<sha>/yara/):
    CADRE_<family|sha8>.yar     — YARA rules (imports + strings + network)
    CADRE_<sha8>.yml            — Sigma rule (process/network behavior)
    rule_report.json            — what generated each rule + match provenance
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

# High-signal imports that commonly appear in YARA rules.
SIGNAL_IMPORTS = {
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
    "SetWindowsHookExW", "WinHttpOpen", "InternetOpenW", "URLDownloadToFileW",
    "CreateProcessW", "ShellExecuteW", "RegSetValueExW", "RegCreateKeyExW",
    "CryptEncrypt", "CryptDecrypt", "WSAStartup", "send", "recv",
    "LoadLibraryW", "GetProcAddress", "VirtualProtect", "WriteFile",
    "ReadProcessMemory", "QueueUserAPC", "NtUnmapViewOfSection",
}


def _sanitize_hex(s: str) -> str:
    """Escape a string for a YARA hex string rule."""
    out = []
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}")
    return "".join(out)


def _is_url_or_host(s: str) -> bool:
    s = s.lower()
    return bool("://" in s or s.startswith("http") or s.startswith("www.")
            or s.endswith(".com") or s.endswith(".net") or s.endswith(".org")
            or ".onion" in s or re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", s))


def _strings_from_evidence(quick: dict, dynamic: dict | None) -> list[str]:
    """Collect candidate strings from quick (Malcat) + dynamic (frida/network)."""
    seen: set[str] = set()
    out: list[str] = []
    # quick scan: malcat strings
    malcat = (quick or {}).get("malcat") or {}
    for s in (malcat.get("strings") or []):
        if isinstance(s, str) and 8 <= len(s) <= 256 and s not in seen:
            seen.add(s)
            out.append(s)
    # dynamic: network intel
    if dynamic:
        net = dynamic.get("network_intel") or {}
        for cap in (net.get("captures") or []):
            for d in (cap.get("dns_queries") or []):
                if _is_url_or_host(d) and d not in seen:
                    seen.add(d)
                    out.append(d)
            for h in (cap.get("http_requests") or []):
                if _is_url_or_host(h) and h not in seen:
                    seen.add(h)
                    out.append(h)
    return out[:40]


def _imports_from_evidence(quick: dict) -> list[str]:
    """Collect imports from quick (IDA/Ghidra SQL)."""
    out: list[str] = []
    for src in ("ida", "ghidra"):
        imps = ((quick or {}).get(src) or {}).get("imports") or []
        for imp in imps:
            if isinstance(imp, str) and imp in SIGNAL_IMPORTS:
                out.append(imp)
    return sorted(set(out))


def _safe_rule_id(sha: str, family: str | None) -> str:
    if family and re.match(r"^[A-Za-z0-9_\-]{1,32}$", family):
        return f"CADRE_{family}"
    return f"CADRE_{sha[:8]}"


def _yara_body(rule_id: str, strings: list[str], imports: list[str]) -> str:
    """Build a YARA rule body: imports-first, then unique strings."""
    lines = [f'rule {rule_id} {{', "    meta:", "        author = \"WinRE pipeline\"",
             "        description = \"Generated deterministically from WinRE evidence\"",
             "        source = \"evidence-pack\"", "    strings:"]
    for i, imp in enumerate(imports):
        lines.append(f"        $imp{i} = \"{_sanitize_hex(imp)}\"")
    for i, s in enumerate(strings):
        lines.append(f"        $s{i} = \"{_sanitize_hex(s)}\"")
    cond = []
    if imports:
        cond.append("any of ($imp*)")
    if strings:
        cond.append("2 of ($s*)")
    if not cond:
        cond.append("false")
    lines.append("    condition:")
    lines.append("        " + " and ".join(cond) if len(cond) > 1 else "        " + cond[0])
    lines.append("}")
    return "\n".join(lines)


def _sigma_body(rule_id: str, dynamic: dict | None) -> str:
    """Build a Sigma rule from dynamic network/process evidence."""
    net = (dynamic or {}).get("network_intel") or {}
    domains = set()
    for cap in (net.get("captures") or []):
        for d in (cap.get("dns_queries") or []):
            if _is_url_or_host(d):
                domains.add(d)
    dns_sel = " | ".join(sorted(domains)[:10]) if domains else "null"
    return f"""title: {rule_id} behavior
id: {hashlib.sha256(rule_id.encode()).hexdigest()[:16]}
status: experimental
description: Generated deterministically by WinRE from dynamic evidence
author: WinRE pipeline
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    query:
      - "{dns_sel}"
  condition: selection
"""


def generate_rules(evidence: Path, out_dir: Path) -> dict:
    """Generate YARA + Sigma from a WinRE evidence pack. Returns rule_report."""
    sha = evidence.name
    quick = None
    qj = evidence / "quick" / "quick.json"
    if qj.is_file():
        try:
            quick = json.loads(qj.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            quick = None
    dynamic = None
    dj = evidence / "dynamic" / "network_intel.json"
    if dj.is_file():
        try:
            dynamic = {"network_intel": json.loads(dj.read_text(encoding="utf-8"))}
        except json.JSONDecodeError:
            dynamic = None

    strings = _strings_from_evidence(quick or {}, dynamic)
    imports = _imports_from_evidence(quick or {})
    family = (quick or {}).get("family") or None
    rule_id = _safe_rule_id(sha, family)

    out_dir.mkdir(parents=True, exist_ok=True)
    yara_path = out_dir / f"{rule_id}.yar"
    yara_path.write_text(_yara_body(rule_id, strings, imports), encoding="utf-8")
    sigma_path = out_dir / f"{rule_id}.yml"
    sigma_path.write_text(_sigma_body(rule_id, dynamic), encoding="utf-8")

    report = {
        "rule_id": rule_id,
        "sha256": sha,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "yara": str(yara_path),
        "sigma": str(sigma_path),
        "evidence": {
            "imports_used": imports,
            "strings_used": strings,
            "network_used": sorted({s for s in strings if _is_url_or_host(s)}),
        },
        "honesty": "rules are deterministic; no LLM-authored content",
    }
    (out_dir / "rule_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("usage: yara_gen.py <evidence_dir> <out_dir>", file=sys.stderr)
        sys.exit(2)
    rep = generate_rules(Path(sys.argv[1]), Path(sys.argv[2]))
    print(json.dumps(rep, indent=2))
