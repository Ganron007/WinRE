#!/usr/bin/env python3
"""Emit ANALYST-NEXT.md + analyst_next.json for a dynamic (or doc) pack.

Usage (Remnux):
  python3 emit_analyst_next.py /opt/samples/logs/<sha>/dynamic
  python3 emit_analyst_next.py /opt/samples/logs/<sha>/dynamic --sha <sha>
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _exists(p: Path) -> bool:
    return p.is_file() or p.is_dir()


def _load_meta(dyn: Path) -> dict[str, Any]:
    meta = dyn / "META.json"
    if meta.is_file():
        try:
            return json.loads(meta.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {}
    return {}


def build_items(dyn: Path, sha: str, meta: dict[str, Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    platform = (meta.get("platform") or meta.get("worker") or "windows").lower()
    if "linux" in platform or "elf" in platform:
        platform = "linux"
    else:
        platform = "windows"

    # --- already collected ---
    collected = []
    for name, label in (
        ("frida_summary.json", "Frida API summary"),
        ("frida_trace.jsonl", "Frida full trace"),
        ("frida_trace.json", "Frida full trace"),
        ("procmon_summary.json", "Procmon summary"),
        ("procmon.csv", "Procmon CSV"),
        ("network.json", "Network summary"),
        ("network_intel.json", "tshark enrich"),
        ("process_snapshot.json", "Process snapshot"),
        ("strace_summary.json", "strace summary"),
        ("META.job.json", "Flare job META"),
    ):
        if (dyn / name).is_file():
            collected.append({"path": name, "label": label})
    pcap_dir = dyn / "network_raw"
    pcaps = sorted(pcap_dir.rglob("*.pcap")) + sorted(pcap_dir.rglob("*.pcapng")) if pcap_dir.is_dir() else []
    mem_dir = dyn / "memory"
    has_memory = mem_dir.is_dir() and any(p.is_file() for p in mem_dir.rglob("*"))
    if has_memory:
        n_mem = sum(1 for p in mem_dir.rglob("*") if p.is_file())
        collected.append({"path": "memory/", "label": f"pe-sieve / memory dumps ({n_mem} files)"})

    # --- recommended next ---
    if pcaps and not (dyn / "network_intel.json").is_file():
        items.append(
            {
                "id": "pcap-enrich",
                "priority": 1,
                "category": "network",
                "title": "Enrich captured PCAP with tshark",
                "why": "Sandbox already captured traffic; light DNS/HTTP/SNI extract is safe to re-run.",
                "commands": [
                    f"python3 /opt/scripts/enrich_pcap_tshark.py {dyn}",
                ],
                "analyst_only": False,
            }
        )
    if pcaps:
        pcap = pcaps[0].name
        items.append(
            {
                "id": "pcap-deep",
                "priority": 2,
                "category": "network",
                "title": "Analyst PCAP deep-dive (not automated)",
                "why": "Protocol RE and stream follow need human judgment; agents only hint.",
                "commands": [
                    f"tshark -r {dyn / 'network_raw' / pcap} -Y dns -T fields -e dns.qry.name",
                    f"tshark -r {dyn / 'network_raw' / pcap} -Y http.request -T fields -e http.host -e http.request.uri",
                    f"tshark -r {dyn / 'network_raw' / pcap} -Y tls.handshake.type==1 -T fields -e tls.handshake.extensions_server_name",
                    f"# Deep: open {pcap} in Wireshark → Follow → TCP Stream",
                ],
                "analyst_only": True,
            }
        )

    if platform == "windows" and not has_memory:
        items.append(
            {
                "id": "memory-pesieve",
                "priority": 1,
                "category": "memory",
                "title": "Memory To-Do — pe-sieve on live PID (analyst or next flagged run)",
                "why": "Injection/hollowing dumps are RE-critical; full-RAM Volatility is optional and heavy.",
                "commands": [
                    "# Option A — next automated run:",
                    "export REVENG_DYNAMIC_PESIEVE=1",
                    f"python3 /opt/scripts/dynamic_run_v2.py {sha} --max-seconds 45",
                    "# Option B — Flare HITL (after snapshot restore):",
                    r"pe-sieve64.exe /pid <PID> /dir C:\samples\<sha>\memory",
                    r"hollows_hunter64.exe /pid <PID> /dir C:\samples\<sha>\memory",
                    "# Offline on dumps: yara -r rules.yar memory/ ; strings ; open in Ghidra/IDA",
                    "# Volatility3: only if you captured a full RAM image (winpmem) — not default",
                ],
                "analyst_only": True,
            }
        )
    elif has_memory:
        items.append(
            {
                "id": "memory-review",
                "priority": 2,
                "category": "memory",
                "title": "Review pe-sieve / process dumps",
                "why": "Dumps present — YARA/strings/Ghidra beat full Vol for most malware RE.",
                "commands": [
                    f"yara -r /opt/rules/ packed {dyn / 'memory'}",
                    f"find {dyn / 'memory'} -type f | head",
                ],
                "analyst_only": True,
            }
        )

    items.append(
        {
            "id": "hitl-debug",
            "priority": 3,
            "category": "hitl_re",
            "title": "HITL reverse engineering (when static/dynamic disagree or packer)",
            "why": "Interactive unpack and API Monitor cannot be unattended; AI must not claim this done.",
            "commands": [
                r"C:\Tools\flarevm-deploy\dynamic\x64dbg_script.py  # generate BP list",
                r"C:\Tools\flarevm-deploy\dynamic\apimon_filter.py   # API Monitor filter helper",
                "# Open sample in x64dbg/IDA on Flare; restore snapshot after",
            ],
            "analyst_only": True,
        }
    )

    items.append(
        {
            "id": "snapshot",
            "priority": 0,
            "category": "ops",
            "title": "Restore Flare clean snapshot",
            "why": "Detonation can persist (Startup/Run keys). Required after every Windows dynamic run.",
            "commands": ["# VMware host: revert Flare-VM to last clean snapshot"],
            "analyst_only": True,
        }
    )

    return {
        "schema": "v6.2.1-analyst-next",
        "sha256": sha,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform,
        "collected": collected,
        "pcaps": [p.name for p in pcaps],
        "memory_present": has_memory,
        "items": sorted(items, key=lambda x: (x.get("priority", 99), x.get("id", ""))),
        "disclaimer": (
            "Not all analysis can be delegated to AI/agents. Items marked analyst_only "
            "are human-driven enrichments. Do not mark them complete unless an analyst ran them."
        ),
    }


def render_md(data: dict[str, Any]) -> str:
    lines = [
        f"# Analyst next actions — `{data.get('sha256', '')[:16]}…`",
        "",
        f"_Generated: {data.get('generated_at')}_ · platform=`{data.get('platform')}`",
        "",
        "> **Not all work can be delegated to AI/agents.** Below: what the pipeline already "
        "collected, then prioritized human next steps.",
        "",
        "## Already collected (do not redo)",
        "",
    ]
    if data.get("collected"):
        for c in data["collected"]:
            lines.append(f"- `{c['path']}` — {c['label']}")
    else:
        lines.append("- _(none listed — check META.json)_")
    if data.get("pcaps"):
        lines.append(f"- `network_raw/` — pcaps: {', '.join(data['pcaps'])}")
    lines += ["", "## Recommended next (priority order)", ""]
    for it in data.get("items", []):
        who = "ANALYST" if it.get("analyst_only") else "script-or-analyst"
        lines.append(f"### P{it.get('priority')} — {it.get('title')} `[{who}]`")
        lines.append("")
        lines.append(f"**Why:** {it.get('why')}")
        lines.append("")
        lines.append("```")
        for cmd in it.get("commands") or []:
            lines.append(cmd)
        lines.append("```")
        lines.append("")
    lines += [
        "## Out of scope for RevEng malware lab",
        "",
        "- Enterprise SIEM / Velociraptor hunts → **DFIR-Nexus / CADRE main**",
        "",
        data.get("disclaimer", ""),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dynamic_dir", type=Path, help="Path to logs/<sha>/dynamic")
    ap.add_argument("--sha", default="", help="SHA256 (else infer from parent dir name)")
    args = ap.parse_args()
    dyn = args.dynamic_dir.resolve()
    if not dyn.is_dir():
        raise SystemExit(f"not a directory: {dyn}")
    sha = args.sha or dyn.parent.name
    meta = _load_meta(dyn)
    data = build_items(dyn, sha, meta)
    (dyn / "analyst_next.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (dyn / "ANALYST-NEXT.md").write_text(render_md(data), encoding="utf-8")
    print(f"wrote {dyn / 'ANALYST-NEXT.md'}")
    print(f"wrote {dyn / 'analyst_next.json'} ({len(data['items'])} items)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
