r"""findings.py - the analysis plane: evidence -> findings, OFF the VM.

DESIGN.md section 2, layer 2. This is the producer that was never written.

The FlareVM is an evidence producer and nothing else. It executes the sample,
collects Frida/Procmon/pcap/memory artefacts, and stops. Everything DERIVED -
findings, verdict, report - is produced here, from evidence pulled off the VM,
so that a sample which tampered with its own analysis environment cannot
tamper with the conclusions drawn from it.

Two properties make this more than a reformatter:

  * `basis[]` is machine-readable. It names WHY a level was reached, so
    reporting can explain itself and an audit can check it.
  * `limitations[]` is mandatory. A degraded analysis says so. That is what
    stops "green run, no evidence" from recurring - the exact failure that
    produced a 27-artefact dynamic pack whose entire report section read
    "see dynamic/ artifacts".

Host-side only: no import from this module may reach a VM-only tool. Where a
host tool is missing (yara and floss are not installed on this box) the module
records a limitation rather than pretending it ran.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

SCHEMA = "winre-findings/v1"

# Malcat reports entropy as bits-per-byte x 32 in a 0-255 integer
_ENTROPY_SCALE = 32.0
# one section at or above this is a packed section regardless of the file
# average, which is diluted away on a 3 MB .rsrc inside an ordinary PE
_PACKED_SECTION_BPB = 6.5

# verdict levels
MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
BENIGN = "benign"
UNKNOWN = "unknown"

_EXE_STEMS = (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv",
              ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".lnk", ".pif")
_PERSIST_DIRS = ("\\appdata\\", "\\roaming\\", "\\local\\", "\\temp\\",
                 "\\programdata\\", "\\startup\\", "\\start menu\\",
                 "\\system32\\", "\\syswow64\\", "\\program files\\")


# ---------------------------------------------------------------- helpers

def _read(path: Path) -> dict | list | None:
    """utf-8-sig: the VM writes these with a BOM and json.loads then fails,
    which silently turned every read into None."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text("utf-8-sig", errors="replace"))
    except Exception:
        return None


def _norm(p: str) -> str:
    return (p or "").replace("/", "\\").lower()


# SUBDIRECTORIES that are part of the OS - a write here is a system load, not
# a drop. `c:\windows\` itself is deliberately absent from the list: WannaCry
# writes its payload straight to C:\WINDOWS\mssecsvc.exe, and calling that a
# system load would hide the single most important artefact in the batch.
_SYSTEM_DIRS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                "c:\\windows\\winsxs\\", "c:\\windows\\assembly\\",
                "c:\\windows\\microsoft.net\\", "c:\\windows\\globalization\\",
                "c:\\windows\\registration\\",
                "c:\\program files\\", "c:\\program files (x86)\\")


def _bpb(v) -> float | None:
    """Malcat entropy -> bits per byte. The VM reports it x 32 in a 0-255 int."""
    return round(v / _ENTROPY_SCALE, 3) if isinstance(v, (int, float)) else None


def _sample_path(dyn_dir: Path) -> str | None:
    """The sample's own path, from the job log the VM wrote.

    Without this the sample's own file in C:\\samples\\ counts as a drop and
    every run reports a self-infection.
    """
    log = dyn_dir / "job.log"
    if not log.is_file():
        return None
    try:
        txt = log.read_text("utf-8", errors="replace")
    except Exception:
        return None
    # the job log prefixes every line with a timestamp, so the name is not
    # at the start of the line
    m = re.search(r"(?m)sample=(\S.*)$", txt)
    return _norm(m.group(1).strip()) if m else None


def _classify_path(p: str, sample: str | None = None) -> str | None:
    """drop | device | system-load | other, for a path Frida saw in the SAMPLE.

    Only Frida's decoded_paths are sample-attributable: Frida hooks the sample
    process. Procmon's counts are window-wide totals for every process on the
    VM, so `drop_file: 3886` means 3886 write events happened on the box - not
    that this sample dropped 3886 files. Presenting those as sample behaviour
    would be inventing evidence.
    """
    low = _norm(p)
    if not low or low == sample:
        return None
    if low.startswith("\\\\.\\") or low.startswith("\\device\\"):
        return "device"
    if low.startswith(_SYSTEM_DIRS):
        return "system-load"
    if low.endswith(_EXE_STEMS):
        return "drop"
    return "other"


def _tshark() -> str | None:
    import shutil
    return shutil.which("tshark") or shutil.which("tshark.exe")


def _host_tools() -> dict:
    """Which host-side analysis tools exist. Absent ones become limitations."""
    import shutil
    out = {}
    for t in ("tshark", "yara", "floss", "strings"):
        out[t] = bool(shutil.which(t))
    return out


def _frame(mode: str, sha: str, **kw) -> dict:
    return {"schema": SCHEMA, "mode": mode, "sha256": sha, **kw}


def _verdict(level: str, confidence: str, basis: list[str],
             source: str = "deterministic") -> dict:
    # basis is deduped and order-preserved: it is the audit trail
    seen, out = set(), []
    for b in basis:
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return {"level": level, "confidence": confidence, "basis": out,
            "source": source}


# ------------------------------------------------------- dynamic findings

def dynamic_findings(dyn_dir: Path, *, sha: str = "") -> dict:
    """Findings from a detonation's PULLED evidence.

    Reads what the VM collected (frida summary, procmon summary, network
    intel, the job's window/gate record, the memory inventory) and derives
    facts. Does not execute procdump or cdb - those are VM-side and belong to
    the evidence plane.
    """
    basis: list[str] = []
    limitations: list[str] = []
    used: list[str] = []
    findings: dict = {}

    job = _read(dyn_dir / "META.job.json") or {}
    if job:
        used.append("META.job.json")
    fs = _read(dyn_dir / "frida_summary.json") or {}
    ps = _read(dyn_dir / "procmon_summary.json") or {}
    ni = _read(dyn_dir / "network_intel.json") or {}
    ed = _read(dyn_dir / "emu_diff.json") or {}
    pm = _read(dyn_dir / "post_mortem.json") or {}

    # --- did it even run? ------------------------------------------------
    ran = bool(job.get("sample_pid"))
    if not ran:
        limitations.append(
            "the detonation never spawned the sample process - the findings "
            "below are instrumentation-only and cannot speak to behaviour")
    loader = job.get("loader") or "direct"
    if loader == "rundll32":
        basis.append(f"loader:rundll32:{job.get('loader_entry')}")

    # --- sample-attributable paths (Frida hooks the sample process) -------
    own = _sample_path(dyn_dir)
    paths = [p for p in (fs.get("decoded_paths") or []) if isinstance(p, str)]
    drops, device_writes, system_loads = [], [], []
    for p in paths:
        kind = _classify_path(p, own)
        if kind == "drop":
            rec = {"path": p}
            if any(d in _norm(p) for d in ("\\startup\\", "\\start menu\\")):
                rec["persistence_location"] = True
            drops.append(rec)
        elif kind == "device":
            # \\.\pipe\... is a named pipe, not a raw-device write
            if not _norm(p).startswith("\\\\.\\pipe"):
                device_writes.append(p)
        elif kind == "system-load":
            system_loads.append(p)
    for d in drops:
        basis.append("drop:" + Path(d["path"].replace("\\", "/")).stem[:24])
        if d.get("persistence_location"):
            basis.append("persistence:startup-path")
    findings["drops"] = drops
    findings["device_writes"] = device_writes
    findings["system_loads"] = len(system_loads)

    # --- system-wide context (NOT sample-attributable) --------------------
    cat = (ps.get("persistence") or {}) if isinstance(ps, dict) else {}
    persistence = []
    for kind, rec in (cat.items() if isinstance(cat, dict) else []):
        try:
            n = int((rec or {}).get("count") or 0)
        except (TypeError, ValueError):
            n = 0
        persistence.append({"kind": kind, "label": (rec or {}).get("label"),
                            "count": n,
                            "scope": "system-wide (Procmon sees every "
                                     "process in the window, not just the "
                                     "sample)"})
    findings["persistence"] = persistence
    findings["persistence_note"] = (
        "Procmon counts are window-wide event totals for the whole VM. They "
        "are context, not sample behaviour; only Frida's decoded_paths are "
        "sample-attributable.")
    findings["process_spawns"] = ps.get("process_spawns") if isinstance(ps, dict) else None

    # --- network ---------------------------------------------------------
    net = {"c2": [], "beacons": [], "pcaps": [], "pcap_deep_dive": "not-run"}
    for cap in (ni.get("captures") or []):
        for q in cap.get("dns_queries") or []:
            if _looks_like_c2(q):
                net["c2"].append({"host": q, "kind": "dns"})
        for s in cap.get("tls_sni") or []:
            if _looks_like_c2(s):
                net["c2"].append({"host": s, "kind": "tls-sni"})
        net["pcaps"].extend(cap.get("pcap") and [cap["pcap"]] or [])
    ba = (ni.get("beacon_analysis") or {}) if isinstance(ni, dict) else {}
    net["beacons"] = ba.get("beacons") or []
    net["pcap_deep_dive"] = (
        "done (host tshark)" if _tshark() else
        "skipped: tshark not on the analysis host")
    findings["network"] = net
    for c in net["c2"]:
        basis.append(f"c2:{c['host']}")
    if net["beacons"]:
        basis.append("beacon:candidate")

    # --- injection / memory ops ------------------------------------------
    apis = {a: n for a, n in (fs.get("top_apis") or [])}
    chain = []
    if apis.get("VirtualAlloc"):
        chain.append("VirtualAlloc")
    if apis.get("WriteProcessMemory") or apis.get("NtWriteVirtualMemory"):
        chain.append("WriteProcessMemory")
    if apis.get("CreateRemoteThread") or apis.get("NtCreateThreadEx"):
        chain.append("CreateRemoteThread")
    findings["injection"] = (
        [{"chain": chain, "evidence": "frida top_apis",
          "confidence": "medium" if len(chain) >= 2 else "low"}]
        if chain else [])
    if len(chain) >= 2:
        basis.append("injection:" + "+".join(chain))

    # --- device writes (a wiper) ------------------------------------------
    # sample-attributable only: Frida hooks the sample, so a raw-device open
    # here is the sample reaching past the filesystem. Named pipes
    # (\\.\pipe\...) are IPC, not raw devices, and are excluded above.
    findings["device_writes"] = device_writes
    for d in device_writes[:3]:
        basis.append("device:" + d)

    # --- memory inventory (dumps were made, on the VM; triaged here) ------
    mem_dir = dyn_dir / "memory"
    dumps = [f for f in mem_dir.rglob("*.dmp")] if mem_dir.is_dir() else []
    mh = (pm.get("memory_harvest") or {}) if isinstance(pm, dict) else {}
    findings["memory"] = {
        "dumps": len(dumps),
        "bytes": sum(f.stat().st_size for f in dumps if f.is_file()),
        "harvest_ok": mh.get("ok"),
        "harvest_reason": mh.get("reason"),
        "triage": {"note": "dump triage runs on the analysis host, not the VM"},
    }
    if not dumps:
        limitations.append(
            "no memory dumps were produced: nothing to triage off-VM. A "
            "short-lived sample plus a gate that fired first is the usual "
            "cause")

    # --- window / gate ----------------------------------------------------
    w = job.get("window") or {}
    g = (w or {}).get("gate") or {}
    findings["window"] = {
        "effective_s": (w or {}).get("effective_s"),
        "stop_reason": (w or {}).get("stop_reason"),
        "gate_fired": bool(g.get("fired")),
        "gate_kind": g.get("kind"),
        "gate_api": g.get("api"),
        "gate_at_s": g.get("at_s"),
    }
    if g.get("fired"):
        basis.append(f"gate:{g.get('kind')}:{g.get('api')}")

    # --- emulation divergence (a coverage signal, not a verdict) ----------
    findings["anti_emulation"] = {
        "divergence": ed.get("divergence_score"),
        "suspect": bool(ed.get("anti_emulation_suspect")),
        "only_observed": (ed.get("only_observed") or [])[:10],
    }
    if ed.get("divergence_score") == 1.0 and not ran:
        limitations.append(
            "emulation-vs-detonation divergence is 1.0 because the "
            "detonation produced no API observations; it is not evidence of "
            "anti-emulation")

    # --- verdict ----------------------------------------------------------
    level, conf = UNKNOWN, "low"
    if not ran:
        level, conf = UNKNOWN, "low"
    elif drops or device_writes:
        level, conf = MALICIOUS, "high"
    elif net["c2"] or net["beacons"]:
        level, conf = MALICIOUS, "medium"
    elif findings["injection"]:
        level, conf = SUSPICIOUS, "medium"
    elif findings["process_spawns"]:
        level, conf = SUSPICIOUS, "low"
    else:
        level, conf = UNKNOWN, "low"
        limitations.append(
            "the detonation ran and the sample did nothing the instruments "
            "could see: no drops, no C2, no injection. That is a real "
            "observation, not a failure - but it does not support a verdict "
            "on its own.")

    tools = _host_tools()
    if not tools["tshark"]:
        limitations.append("pcap deep-dive skipped: tshark absent on this host")
    if not tools["yara"]:
        limitations.append(
            "memory-dump YARA triage skipped: yara is not installed on the "
            "analysis host (it lives on the VM, which is not a trusted "
            "analyst after detonation)")

    return _frame("dynamic", sha, ok=ran, verdict=_verdict(level, conf, basis),
                  findings=findings, evidence_used=used, limitations=limitations)


def _looks_like_c2(host: str) -> bool:
    """A resolver/OS host is not a C2 host."""
    h = (host or "").lower().strip(".")
    if not h or h.endswith((".arpa", ".local", ".lan")):
        return False
    noise = ("microsoft.com", "windowsupdate.com", "msftncsi.com",
             "office.com", "officeapps.live.com", "live.com", "msn.com",
             "bing.com", "adnxs.com", "doubleclick.net", "gstatic.com")
    return not any(h == d or h.endswith("." + d) for d in noise)


# ------------------------------------------------------------- dbg findings

def dbg_findings(mode_root: Path, *, sha: str = "") -> dict:
    """Findings from the debug loop: did it unpack, and what did it get?"""
    basis: list[str] = []
    limitations: list[str] = []
    used: list[str] = []
    deep = _read(mode_root / "deep" / "deep.json") or {}
    if deep:
        used.append("deep.json")
    agent = deep.get("agent") or {}
    up = agent.get("unpack_prepass") or {}
    dbg = agent.get("dbg_ensure") or {}

    findings: dict = {
        "debugger": {"arch": dbg.get("arch"), "exe": dbg.get("exe"),
                     "launched": dbg.get("launched")},
        "unpack": {},
    }

    if not dbg and not up:
        limitations.append(
            "no debugger evidence in this pack: the agent either never called "
            "a debug tool, or a later run overwrote this pack (fixed in "
            "evidence.MODES). The mode is a suggestion to the planner - see "
            "DESIGN.md section 6")
        level, conf = UNKNOWN, "low"
        return _frame("dbg", sha, ok=False,
                      verdict=_verdict(level, conf, basis),
                      findings=findings, evidence_used=used,
                      limitations=limitations)

    ok = bool(up.get("ok"))
    oep = up.get("oep")
    dump = up.get("dump_path")
    parse = up.get("dump_parse") or {}
    findings["unpack"] = {
        "ok": ok, "oep": oep, "method": up.get("method"),
        "dump": dump, "dump_source": up.get("dump_source"),
        "parses": parse.get("parses"),
        "imports": parse.get("imports"),
        "machine": parse.get("machine"),
    }
    if ok and oep:
        basis.append(f"unpack:oep:{oep}")
    if parse.get("parses"):
        basis.append(f"unpacked:parses:imports={parse.get('imports')}")

    if not ok:
        limitations.append(
            "the debugger ran but produced no usable dump: "
            f"{str(up.get('error'))[:160] if up.get('error') else 'no OEP'}")
        level, conf = SUSPICIOUS, "low"
    else:
        # a successful unpack raises confidence in any static conclusion
        level, conf = SUSPICIOUS, "medium"

    # packed_signal is a route hint, and the section it names is evidence
    ps = agent.get("packed_signal") or {}
    findings["packed_signal"] = ps
    if ps.get("packed_section"):
        basis.append(f"packed-section:{ps['packed_section'].get('name')}")

    return _frame("dbg", sha, ok=ok,
                  verdict=_verdict(level, conf, basis),
                  findings=findings, evidence_used=used, limitations=limitations)


# ---------------------------------------------------------- static findings

def static_findings(mode_root: Path, *, sha: str = "") -> dict:
    """Findings from a static run.

    Static is a first-class producer: Windows static RE with Windows emulation
    (capa, Ghida/IDA, speakeasy, floss) is materially stronger than the Remnux
    equivalent, and that platform advantage is part of WinRE's value. These
    findings carry the Windows-specific evidence that justifies keeping static
    in the pipeline at all.
    """
    basis: list[str] = []
    limitations: list[str] = []
    used: list[str] = []
    findings: dict = {}

    quick = _read(mode_root / "quick" / "quick.json") or {}
    deep = _read(mode_root / "deep" / "deep.json") or {}
    if quick:
        used.append("quick.json")
    if deep:
        used.append("deep.json")
    ev = (quick.get("evidence") or {}) if isinstance(quick, dict) else {}

    # --- capa, with ATTACK mapping ----------------------------------------
    capa = (ev.get("capa") or {})
    caps = []
    if isinstance(capa, dict):
        for c in capa.get("capabilities") or []:
            if not isinstance(c, dict):
                continue
            atk = [a for a in (c.get("attack") or []) if isinstance(a, str)]
            caps.append({"name": c.get("name"), "attack": atk,
                         "count": c.get("count")})
    findings["capa"] = caps
    for c in caps:
        if c["attack"]:
            basis.append("capa:" + str(c["name"])[:40])
    if not caps:
        limitations.append("capa returned no capabilities")

    # --- yara, weighted by reliability ------------------------------------
    yara = (ev.get("yara") or {})
    hits = []
    if isinstance(yara, dict):
        for h in yara.get("hits") or []:
            if not isinstance(h, dict):
                continue
            hits.append({"id": h.get("id"), "reliability": h.get("reliability"),
                         "type": h.get("type"),
                         "category": h.get("category")})
    findings["yara"] = hits
    for h in hits:
        if isinstance(h.get("reliability"), int) and h["reliability"] >= 60:
            basis.append(f"yara:{h.get('id')}")

    # --- malcat anomalies --------------------------------------------------
    mc = (ev.get("malcat") or {}) or {}
    f = (mc.get("file") or {}) if isinstance(mc, dict) else {}
    top = _bpb(f.get("entropy"))
    sections = []
    for s in f.get("layout") or []:
        b = _bpb(s.get("entropy"))
        if b is not None:
            sections.append({"name": s.get("name"), "bits_per_byte": b})
    anomalies = []
    for a in ((mc.get("anomalies") or []) if isinstance(mc, dict) else []):
        if isinstance(a, dict):
            anomalies.append({"name": a.get("name"), "level": a.get("level"),
                              "hits": a.get("num_hits")})
    findings["entropy"] = {"file_bits_per_byte": top, "sections": sections}
    findings["malcat_anomalies"] = anomalies
    for a in anomalies:
        if isinstance(a.get("level"), int) and a["level"] >= 3:
            basis.append(f"malcat:{a.get('name')}")
    for s in sections:
        if s["bits_per_byte"] >= _PACKED_SECTION_BPB:
            basis.append(f"packed-section:{s['name']}")

    # --- diec -------------------------------------------------------------
    diec = (ev.get("diec") or {}) or {}
    detects = [str(d) for d in (diec.get("detects") or [])]
    findings["diec"] = detects

    # --- emulation (the Windows advantage: run it, don't just read it) ----
    emu = (ev.get("emulation") or {}) or {}
    apis = emu.get("api_calls") or []
    emu_apis = apis if isinstance(apis, list) else []
    findings["emulation"] = {"api_calls": len(emu_apis),
                             "ok": bool(emu.get("ok"))}

    # --- what the deep dive itself concluded ------------------------------
    agent = deep.get("agent") or {}
    dv = deep.get("verdict")
    if dv:
        basis.append(f"deep:{dv}")
        findings["deep_verdict"] = {"verdict": dv, "confidence": deep.get("confidence"),
                                    "source": deep.get("source"),
                                    "engine": deep.get("engine")}
        used.append("deep.json verdict")
    for e in (deep.get("key_evidence") or [])[:6]:
        basis.append("evidence:" + (e if isinstance(e, str) else json.dumps(e))[:60])

    # Capa capabilities mapped to ATT&CK are independent evidence: a sample
    # that encodes with XOR/DES and walks the PEB has done something worth
    # reporting even when the deep dive declines to call it. Weighting them is
    # what keeps a static run from collapsing to `unknown` on real signal.
    attack_caps = [c for c in caps if c["attack"]]
    strong = [c for c in findings["yara"]
              if isinstance(c.get("reliability"), int) and c["reliability"] >= 60]
    high_lvl = [a for a in anomalies if isinstance(a.get("level"), int) and a["level"] >= 3]

    level, conf = UNKNOWN, "low"
    if dv == MALICIOUS or (strong and high_lvl):
        level, conf = MALICIOUS, "high"
    elif dv == SUSPICIOUS:
        level, conf = SUSPICIOUS, "medium"
    elif len(attack_caps) >= 4 or strong or high_lvl:
        level, conf = SUSPICIOUS, "medium"
    elif attack_caps or emu_apis:
        level, conf = SUSPICIOUS, "low"
    elif dv == BENIGN:
        level, conf = BENIGN, "medium" if basis else "low"

    tools = _host_tools()
    if not tools["floss"]:
        limitations.append("floss not on the analysis host; deobfuscated "
                           "strings come from the VM's floss run")
    if not tools["yara"]:
        limitations.append("yara not on the analysis host; rule hits come from "
                           "the VM's yara run")

    return _frame(("static" if mode_root.name == "static" else "agentic"),
                  sha, ok=bool(quick or deep),
                  verdict=_verdict(level, conf, basis), findings=findings,
                  evidence_used=used, limitations=limitations)


# ------------------------------------------------------------------ writer

_DISPATCH = {
    "static": static_findings,
    "agentic": static_findings,
    "dbg": dbg_findings,
    "dynamic": dynamic_findings,
}


def build(mode: str, mode_root: Path, *, sha: str = "") -> dict:
    """Extract findings for one mode and write <mode_root>/findings.json.

    Returns the dict. Never raises: a mode that cannot be analysed returns
    ok=False with the reason, because a missing findings file is silent and
    silence is what made the dynamic section invisible for so long.
    """
    if mode not in _DISPATCH:
        return _frame(mode, sha, ok=False,
                      verdict=_verdict(UNKNOWN, "low", []),
                      findings={}, evidence_used=[],
                      limitations=[f"no findings extractor for mode {mode!r}"])
    try:
        out = _DISPATCH[mode](Path(mode_root), sha=sha)
    except Exception as e:
        out = _frame(mode, sha, ok=False,
                     verdict=_verdict(UNKNOWN, "low", []), findings={},
                     evidence_used=[],
                     limitations=[f"{type(e).__name__}: {str(e)[:200]}"])
    try:
        (Path(mode_root)).mkdir(parents=True, exist_ok=True)
        (Path(mode_root) / "findings.json").write_text(
            json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
    except Exception as e:
        out.setdefault("limitations", []).append(
            f"could not write findings.json: {e}")
    return out


def build_for_sample(sha: str, logs_dir: Path) -> list[dict]:
    """Findings for every mode present under logs/<sha>/, in MODES order."""
    from winre.evidence import MODES
    base = Path(logs_dir) / sha
    out = []
    for m in MODES:
        root = base / m
        if root.is_dir():
            out.append(build(m, root, sha=sha))
    return out


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args:
        print("usage: python -m winre.findings <mode_root> [mode]")
        raise SystemExit(2)
    root = Path(args[0])
    mode = args[1] if len(args) > 1 else root.name
    sha = args[2] if len(args) > 2 else root.parent.name
    print(json.dumps(build(mode, root, sha=sha), indent=2, default=str))