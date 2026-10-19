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


def _host_tools() -> dict:
    """Which tools the analysis plane can actually use on THIS box.

    W2/host-provisioning: this used to be `shutil.which(name)` for four names,
    which is wrong in both directions and sent a reviewer down the wrong path:

      * yara is normally a LIBRARY on the analysis host (yara-python, imported
        as `yara`), not an executable on PATH. `which("yara")` therefore reports
        "not installed" while yara-python is present and working.
      * floss is likewise usually the pip package. And capa - which the static
        findings weight heavily - was never checked at all.
      * It says nothing about WHERE it looked, so a limitation reads as "this
        tool does not exist" rather than "this tool is not on the box that runs
        the analysis". The FlareVM has yara-x at C:/Tools/yara-x\\yr.exe and 57
        curated rules at C:/Tools/yara-rules; the analysis plane cannot use them
        because the VM is dirty after a detonation.

    So: probe by IMPORT for the Python tools, by PATH for the binaries, and
    record the rules directory separately - `ops/provision_host.ps1` is what
    fills these in.
    """
    import importlib
    import shutil

    out: dict = {}
    for t in ("tshark", "strings", "7z"):
        out[t] = bool(shutil.which(t) or shutil.which(t + ".exe"))
    # python modules: importability is the real test
    for mod in ("yara", "floss", "capa"):
        try:
            importlib.import_module(mod)
            out[mod] = True
        except Exception:
            out[mod] = False
    rules = _yara_rules_dir()
    out["yara_rules"] = bool(rules)
    out["yara_rules_dir"] = str(rules) if rules else None
    return out


def _yara_rules_dir() -> "Path | None":
    """The curated rule set on this box, if any.

    `ops/provision_host.ps1` stages it from the FlareVM (which holds the
    authority copy at C:/Tools/yara-rules). An env override wins so a host that
    keeps rules elsewhere does not need a code change.
    """
    import os
    from pathlib import Path as _P
    env = os.environ.get("WINRE_YARA_RULES")
    for cand in ([_P(env)] if env else []) + [
            _P("C:/Tools/yara-rules"), _P("C:/yara-rules"),
            _P(__file__).resolve().parents[1] / "yara-rules"]:
        try:
            if cand.is_dir() and any(cand.rglob("*.yar*")):
                return cand
        except OSError:
            continue
    return None


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

def dynamic_findings(dyn_dir: Path, *, sha: str = "",
                     run_meta: dict | None = None) -> dict:
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

    # the stage dir for every mode: <mode_root>/dynamic/
    dyn_dir = Path(dyn_dir) / "dynamic"
    job = _read(dyn_dir / "META.job.json") or {}
    if job:
        used.append("META.job.json")
    else:
        # A timeout can kill the PowerShell job before it writes its terminal
        # META.job.json, while the host orchestrator still writes META.json
        # with the observed sample PID and detonation status. This is a
        # run-scoped fallback, not a substitute for the required collectors.
        job = _read(dyn_dir / "META.json") or {}
        if job:
            used.append("META.json")
    stage_status = run_meta or _read(dyn_dir / "STAGE.json") or {}
    fs = _read(dyn_dir / "frida_summary.json") or {}
    ps = _read(dyn_dir / "procmon_summary.json") or {}
    ni = _read(dyn_dir / "network_intel.json") or {}
    ed = _read(dyn_dir / "emu_diff.json") or {}
    pm = _read(dyn_dir / "post_mortem.json") or {}
    ntdll = pm.get("ntdll_integrity") or {}
    windbg = _read(dyn_dir / "windbg_analysis.json") or {}
    if windbg:
        used.append("windbg_analysis.json")
    if ntdll.get("status") == "deferred_to_control_plane":
        limitations.append(
            "loaded ntdll integrity comparison was deferred because the VM is "
            "not a trusted analysis host; no off-box comparison is available yet")

    # --- did it even run? ------------------------------------------------
    ran = bool(job.get("sample_pid") or job.get("detonation_ran")
               or stage_status.get("sample_pid")
               or stage_status.get("detonation_ran"))
    transfer = stage_status.get("transfer")
    transfer_incomplete = (
        (isinstance(transfer, dict) and transfer.get("complete") is False)
        or job.get("job_timeout") is True
        or stage_status.get("job_timeout") is True
        or (ran and stage_status.get("ok") is False))
    if not ran:
        limitations.append(
            "the detonation never spawned the sample process - the findings "
            "below are instrumentation-only and cannot speak to behaviour")
    elif transfer_incomplete:
        limitations.append(
            "the sample process was observed, but current-run collection or "
            "evidence transfer was incomplete; behavior findings are not "
            "promoted")
    loader = job.get("loader") or "direct"
    if loader == "rundll32":
        basis.append(f"loader:rundll32:{job.get('loader_entry')}")

    # --- sample-attributable paths (Frida hooks the sample process) -------
    #
    # W1 (RevAI review 2026-10-08): AN OPEN IS NOT A DROP.
    #
    # decoded_paths is a flat list of strings, so this loop could not tell a
    # CreateFileW(..., GENERIC_READ) from one opened GENERIC_WRITE. Every
    # observed open of an .exe therefore became `drop:` and, alone, a
    # malicious/high verdict - including a plain read of a file in the
    # analyst's own Downloads folder. Reading is not an intent to plant.
    #
    # The tracer records the access mask now (tools/frida_api_trace.py) and the
    # summary keeps it (summarize_dynamic.py -> file_events), so a drop needs
    # POSITIVE write evidence. Where a pack predates that recording there is no
    # proof, and an unproven path is reported as an OBSERVATION under
    # unverified_opens - visible, citable, and never counted as a drop.
    own = _sample_path(dyn_dir)
    paths = [p for p in (fs.get("decoded_paths") or []) if isinstance(p, str)]

    # path -> {"writes": bool, "reads": bool, "api": str, "access": str}
    prov: dict[str, dict] = {}
    has_provenance = False
    _effects = fs.get("file_effects")
    if isinstance(_effects, dict):
        for ep, ev in _effects.items():
            if not isinstance(ev, dict) or not isinstance(ep, str) or not ep:
                continue
            has_provenance = has_provenance or bool(
                ev.get("write_attempts") or ev.get("read_attempts")
                or ev.get("successful_writes") or ev.get("created_or_truncated")
                or ev.get("open_or_create_ambiguous"))
            prov[ep] = {
                "writes": int(ev.get("successful_writes") or 0) > 0,
                "reads": int(ev.get("read_attempts") or 0) > 0,
                "write_attempts": int(ev.get("write_attempts") or 0),
                "successful_writes": int(ev.get("successful_writes") or 0),
                "created_or_truncated": int(ev.get("created_or_truncated") or 0),
                "open_or_create_ambiguous": int(
                    ev.get("open_or_create_ambiguous") or 0),
                "bytes_written": int(ev.get("bytes_written") or 0),
                "api": (ev.get("apis") or [None])[0],
                "access": None,
                "event_refs": ev.get("event_refs") or [],
            }
    _events = fs.get("file_events") or []
    if not isinstance(_effects, dict) and not _events:
        # Only invocation-paired raw events can establish a completed effect.
        # Older traces remain observations because they lack return linkage.
        _events = _backfill_provenance(dyn_dir)
    for ev in _events:
        if not isinstance(ev, dict):
            continue
        ep = ev.get("path")
        if not isinstance(ep, str) or not ep:
            continue
        if (ev.get("access") is not None or ev.get("write_intent") is not None
                or ev.get("write_succeeded") is not None):
            has_provenance = True
        rec = prov.setdefault(ep, {"writes": False, "reads": False,
                                   "write_attempts": 0,
                                   "successful_writes": 0,
                                   "created_or_truncated": 0,
                                   "open_or_create_ambiguous": 0,
                                   "bytes_written": 0,
                                   "api": None, "access": None,
                                   "event_refs": []})
        if ev.get("write_intent", ev.get("writes")):
            rec["write_attempts"] += 1
        if ev.get("write_succeeded") is True:
            rec["writes"] = True
            rec["successful_writes"] += 1
            try:
                rec["bytes_written"] += max(0, int(ev.get("bytes_written") or 0))
            except (TypeError, ValueError):
                pass
        if ev.get("effect") == "created_or_truncated":
            rec["created_or_truncated"] += 1
        elif ev.get("effect") == "created_if_absent_or_opened":
            rec["open_or_create_ambiguous"] += 1
        if ev.get("reads"):
            rec["reads"] = True
        rec["api"] = rec["api"] or ev.get("api")
        rec["access"] = rec["access"] or ev.get("access")
        if ev.get("event_ref") and len(rec["event_refs"]) < 50:
            rec["event_refs"].append(ev.get("event_ref"))

    # The evidence is the UNION of both sources, not one of them. A path can be
    # present in file_events and absent from decoded_paths - the summary keeps
    # only 80 sorted unique strings, and the write-family proof can attribute a
    # path the flat list lost. Iterating decoded_paths alone silently deleted
    # any drop whose only proof was a WriteFile to an attributed handle, which
    # is how a strict fix becomes a blind fix.
    seen_paths = set(paths)
    for _p in prov:
        if _p not in seen_paths:
            paths.append(_p)

    drops, created_files, device_writes, system_loads = [], [], [], []
    unverified: list[dict] = []
    for p in paths:
        kind = _classify_path(p, own)
        pv = prov.get(p)
        proven = bool(pv and pv.get("writes"))
        if kind == "drop":
            if pv and pv.get("created_or_truncated"):
                created_files.append({
                    "path": p,
                    "successful_create_or_truncate": pv["created_or_truncated"],
                    "successful_writes": pv.get("successful_writes", 0),
                    "bytes_written": pv.get("bytes_written", 0),
                    "event_refs": pv.get("event_refs", []),
                })
            if proven:
                rec = {"path": p, "proven": True,
                       "api": pv.get("api"), "access": pv.get("access"),
                       "successful_writes": pv.get("successful_writes", 0),
                       "bytes_written": pv.get("bytes_written", 0),
                       "event_refs": pv.get("event_refs", [])}
                if any(d in _norm(p) for d in ("\\startup\\", "\\start menu\\")):
                    rec["persistence_location"] = True
                drops.append(rec)
            else:
                # observed, not attributed: recorded, never a drop
                unverified.append({
                    "path": p,
                    "reason": ("created-or-truncated-but-no-successful-write"
                               if (pv or {}).get("created_or_truncated") else
                               "open-or-create-outcome-does-not-prove-creation"
                               if (pv or {}).get("open_or_create_ambiguous") else
                               "opened-for-read" if (pv or {}).get("reads") else
                               "write-attempted-but-completion-unproven"
                               if (pv or {}).get("write_attempts") else
                               "no completed-write evidence recorded"),
                    "api": (pv or {}).get("api"),
                })
        elif kind == "device":
            # \\.\pipe\... is a named pipe, not a raw-device write
            if not _norm(p).startswith("\\\\.\\pipe"):
                if proven:
                    device_writes.append(p)
                else:
                    unverified.append({
                        "path": p,
                        "reason": ("write-attempted-but-completion-unproven"
                                   if (pv or {}).get("write_attempts") else
                                   "no completed-write evidence recorded"),
                        "api": (pv or {}).get("api"),
                    })
        elif kind == "system-load":
            system_loads.append(p)

    # Completed file effects are cited, but do not independently establish
    # malicious intent. File-write-only evidence is capped at suspicious.
    for d in drops:
        basis.append("file-write:" + Path(d["path"].replace("\\", "/")).stem[:24])
        if d.get("persistence_location"):
            basis.append("persistence-location-write:startup-path")

    if unverified:
        limitations.append(
            f"{len(unverified)} path(s) looked like a drop by shape but carry "
            "no completed-write proof: they are reported as observations, not "
            "as completed drops. A read or failed write is not evidence of "
            "planting a file.")
    if not has_provenance and paths:
        limitations.append(
            "this pack predates file-access provenance (frida file_events), so "
            "NO path in it can be attributed to a write. Path shape alone is "
            "not sufficient to claim a drop.")
    if fs.get("unmatched_calls"):
        limitations.append(
            f"{fs.get('unmatched_calls')} Frida invocation(s) have no paired "
            "return record; their effects remain unverified.")
    if fs.get("malformed_lines"):
        limitations.append(
            f"{fs.get('malformed_lines')} malformed Frida trace line(s) were "
            "ignored during summary generation.")
    if fs.get("file_events_truncated"):
        limitations.append(
            "the bounded file-event detail list is truncated; full per-path "
            "effect counts are in file_effects and raw invocation records remain "
            "in frida_trace.jsonl.")
    findings["drops"] = drops
    findings["created_files"] = created_files
    findings["file_effect_intent"] = {
        "status": "not_assessed",
        "note": ("A successful file creation/write is an observed effect, not "
                 "by itself proof of malicious intent. Correlate with execution, "
                 "persistence, payload content and sample-attributable context."),
        "completed_write_paths": len(drops),
        "created_or_truncated_paths": len(created_files),
    }
    findings["unverified_opens"] = unverified[:60]
    findings["device_writes"] = device_writes
    findings["system_loads"] = len(system_loads)
    findings["file_provenance"] = {
        "available": has_provenance,
        "events": len(prov),
        "proven_writes": sum(1 for v in prov.values() if v.get("writes")),
        "write_attempts": sum(v.get("write_attempts", 0) for v in prov.values()),
        "successful_writes": sum(v.get("successful_writes", 0)
                                  for v in prov.values()),
        "created_or_truncated": sum(v.get("created_or_truncated", 0)
                                     for v in prov.values()),
    }
    hook_coverage = fs.get("hook_coverage") or {"status": "unreported"}
    findings["frida_coverage"] = hook_coverage
    if hook_coverage.get("status") != "reported":
        limitations.append(
            "Frida hook installation coverage is unreported; observed-call "
            "counts alone cannot distinguish no behavior from no active hooks.")
    else:
        if hook_coverage.get("unavailable") or hook_coverage.get("failures"):
            limitations.append(
                "one or more requested Frida hooks were unavailable or failed "
                "to install; see frida_coverage for the exact exports/errors.")
        if (hook_coverage.get("installed")
                and not hook_coverage.get("apis_fired")):
            limitations.append(
                "Frida installed the requested hooks but observed no calls in "
                "the capture window; this does not prove the behavior is absent.")
        if hook_coverage.get("call_limit_reached"):
            limitations.append(
                "the Frida call limit was reached; later behavior may be absent "
                "from the trace.")

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
    findings["process_spawns_scope"] = (
        "system-wide Procmon count; no sample process attribution")

    # --- network ---------------------------------------------------------
    net = {"c2": [], "leads": [], "beacons": [], "pcaps": [],
           "pcap_deep_dive": "not-run"}
    raw_endpoints = fs.get("network_endpoints") or []
    if isinstance(raw_endpoints, list):
        endpoints = [e for e in raw_endpoints if isinstance(e, dict)]
    else:
        endpoints = []
    # Compatibility with both the old singular key and the tracer's emitted
    # sockaddrN keys. Keep these as endpoint observations; they do not, alone,
    # establish process attribution or command-and-control intent.
    if not endpoints:
        for address in (fs.get("sockaddrs") or []):
            if isinstance(address, str) and address:
                endpoints.append({"address": address, "api": None,
                                  "pid": None, "tid": None,
                                  "event_ref": None,
                                  "scope": "legacy-frida-endpoint"})
    net["frida_endpoints"] = endpoints[:500]
    net["frida_endpoint_count"] = int(
        fs.get("network_endpoint_count") or len(endpoints))
    net["frida_endpoints_truncated"] = bool(
        fs.get("network_endpoints_truncated") or len(endpoints) > 500)
    net["frida_endpoint_scope"] = (
        "sample-process API observation; caller/module attribution and complete "
        "network-instrumentation coverage are not established by this field")
    ba = (ni.get("beacon_analysis") or {}) if isinstance(ni, dict) else {}
    # Beacon candidates are currently derived from VM-wide capture. Keep the
    # observations, but do not attribute them to the sample or let them vote
    # on the verdict until the flow-to-process contract exists (A2/A3).
    net["beacons"] = ba.get("beacons") or []
    net["beacon_scope"] = "vm-wide capture; sample process/flow ownership unresolved"

    # every host the sample resolved or negotiated with, and HOW
    seen: dict[str, set[str]] = {}
    for cap in (ni.get("captures") or []):
        for q in cap.get("dns_queries") or []:
            if isinstance(q, str) and q.strip():
                seen.setdefault(q.strip().lower(), set()).add("dns")
        for h in cap.get("tls_sni") or []:
            if isinstance(h, str) and h.strip():
                seen.setdefault(h.strip().lower(), set()).add("tls-sni")
        for line in cap.get("http_requests") or []:
            # tshark -T fields: host, method, uri
            host = str(line).split("\t")[0].strip().lower()
            if host:
                seen.setdefault(host, set()).add("http")
        net["pcaps"].extend(cap.get("pcap") and [cap["pcap"]] or [])

    for host, how in sorted(seen.items()):
        if not _looks_like_c2(host):
            continue
        # network_intel is tshark over the whole guest. DNS/HTTP/SNI/beacon
        # presence has no process association, so communication semantics do
        # not justify the phrase "the sample sent" or a C2 verdict.
        net["leads"].append({
            "host": host, "observed_as": sorted(how),
            "scope": "vm-wide-pcap", "attribution": "unresolved",
            "status": "unattributed network observation; not promoted to C2",
        })
    net["leads"] = net["leads"][:80]
    net["lead_note"] = (
        "The current pcap is VM-wide. These are network observations with no "
        "process/flow owner; they are leads, not sample contacts or C2. "
        "Promotion requires attributable process/flow evidence and intent.")
    net["pcap_deep_dive"] = _pcap_status(ni)
    findings["network"] = net
    for c in net["c2"]:
        basis.append(f"c2:{c['host']}")
    if net["beacons"]:
        limitations.append(
            "beacon candidates are derived from VM-wide pcap and are not "
            "attributed to this sample; they do not raise the verdict")

    # --- injection / memory ops ------------------------------------------
    apis = {str(a).casefold(): n for a, n in (fs.get("top_apis") or [])}
    remote_alloc_api = bool(apis.get("virtualallocex"))
    wrote_remote = any(apis.get(name) for name in
                       ("writeprocessmemory", "ntwritevirtualmemory"))
    executed_remote = any(apis.get(name) for name in
                          ("createremotethread", "ntcreatethreadex",
                           "queueuserapc"))
    # A plain VirtualAlloc is routine heap allocation in the current process.
    # It is useful behavioral evidence, but does not establish process
    # injection. Keep all memory APIs visible and require remote-write plus
    # remote-execution evidence before calling the behavior an injection chain.
    memory_apis = [name for name in (
        "virtualalloc", "virtualallocex", "ntallocatememory",
        "writeprocessmemory", "ntwritevirtualmemory",
        "createremotethread", "ntcreatethreadex", "queueuserapc")
        if apis.get(name)]
    findings["memory_activity"] = {
        "apis": memory_apis,
        "remote_allocation_api_observed": remote_alloc_api,
        "remote_write_api_observed": wrote_remote,
        "remote_execution_api_observed": executed_remote,
        "scope": "API presence in sample-attributed Frida summary; targets not resolved",
    }
    chain = []
    if remote_alloc_api:
        chain.append("VirtualAllocEx")
    if wrote_remote:
        chain.append("WriteProcessMemory/NtWriteVirtualMemory")
    if executed_remote:
        chain.append("CreateRemoteThread/NtCreateThreadEx/QueueUserAPC")
    injection_confirmed = wrote_remote and executed_remote
    findings["injection"] = (
        [{"chain": chain, "evidence": "frida top_apis",
          "confidence": "medium",
          "limitation": "target process and call success are unresolved"}]
        if injection_confirmed else [])
    # A verdict-driving injection claim requires cross-process write and
    # execution primitives; a generic allocation or one API remains a lead.
    if injection_confirmed:
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
        "windbg_analysis": {
            "status": ("completed" if windbg.get("ok") is True else
                       "not_applicable" if "no dump" in str(
                           windbg.get("skipped") or "").lower() else
                       "unavailable" if windbg.get("skipped") else
                       "failed" if windbg.get("error") else "not_run"),
            "highlights": windbg.get("highlights") or {},
            "analyzer": windbg.get("analyzer"),
            "reason": windbg.get("skipped") or windbg.get("error"),
        },
        "triage": _triage_dumps(dyn_dir, dumps),
    }
    if not dumps:
        if transfer_incomplete:
            limitations.append(
                "no memory dumps were available for off-host triage; "
                "incomplete collection or transfer does not show whether the "
                "guest produced a dump")
        else:
            limitations.append(
                "no memory dumps were produced: nothing to triage off-VM. A "
                "short-lived sample plus a gate that fired first is the usual "
                "cause")

    # --- window / gate ----------------------------------------------------
    w = job.get("window") or {}
    g = (w or {}).get("gate") or {}
    findings["window"] = {
        "effective_s": (w or {}).get("effective_s"),
        "requested_s": (w or {}).get("requested_s"),
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

    # ---- what this run did NOT capture ------------------------------------
    # The manifest is the authority on coverage. Before it, "no file" and "empty
    # file" were the same thing, so a capture that never happened read as a
    # sample that did nothing. Consult it and say so.
    try:
        from . import manifest as _manifest
        gaps = _manifest.incomplete_sources(dyn_dir)
        if gaps:
            limitations.append(
                "incomplete evidence collection: "
                + "; ".join(f"{s} {r}" for s, r in gaps[:6])
                + ". Absence of a signal below may mean the sensor never ran.")
    except Exception:
        pass

    # --- verdict ----------------------------------------------------------
    level, conf = UNKNOWN, "low"
    if not ran or transfer_incomplete:
        level, conf = UNKNOWN, "low"
    elif device_writes:
        level, conf = MALICIOUS, "high"
    elif net["c2"]:
        level, conf = MALICIOUS, "medium"
    elif drops:
        level, conf = SUSPICIOUS, "medium"
    elif findings["injection"]:
        level, conf = SUSPICIOUS, "medium"
    else:
        level, conf = UNKNOWN, "low"
        if not transfer_incomplete:
            limitations.append(
                "No confirmed drops, C2 candidates, or injection chains were "
                "recorded in the collected evidence. This describes the current "
                "run record only and does not establish that those behaviors "
                "never occurred.")

    tools = _host_tools()
    if not tools["tshark"]:
        limitations.append("pcap deep-dive skipped: tshark absent on this host")
    if not tools["yara"]:
        limitations.append(
            "memory-dump YARA triage skipped: yara is not installed on the "
            "analysis host (it lives on the VM, which is not a trusted "
            "analyst after detonation)")

    evidence_complete = bool(ran and not transfer_incomplete)
    return _frame("dynamic", sha, ok=ran and evidence_complete,
                  run_observed=ran, evidence_complete=evidence_complete,
                  verdict=_verdict(level, conf, basis),
                  findings=findings, evidence_used=used, limitations=limitations)


# RFC 2606 / RFC 6761 reserved and documentation names. These exist so
# documentation, examples and tests cannot be mistaken for infrastructure.
# example.org being reported as C2 is the single most embarrassing way for a
# findings plane to be wrong.
_RESERVED_NAMES = frozenset({
    "example.com", "example.net", "example.org", "example", "localhost",
})
_RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost",
                      ".arpa", ".local", ".lan", ".onion.test")

# Resolver / OS / CDN telemetry. Still a denylist, and still incomplete - which
# is why it is no longer sufficient on its own to call something C2.
# CA / CDN / OCSP infrastructure. A sample that completes a TLS handshake
# contacts these; that is certificate validation working, not a C2 channel.
# Still a denylist, and still incomplete by construction - which is why a
# promotion also needs a communication signal, not just a "not-listed" pass.
_CA_CDN_INFRA = frozenset({
    "lencr.org", "letsencrypt.org", "digicert.com", "sectigo.com",
    "comodoca.com", "usertrust.com", "globalsign.com", "godaddy.com",
    "verisign.com", "symantec.com", "thawte.com", "entrust.net",
    "startcom.org", "buypass.com", "actalis.com", "quotemedia.com",
    "akamai.net", "akamaihd.net", "akamaized.net", "fastly.net",
    "cloudfront.net", "azureedge.net", "windows.net", "msedge.net",
    "googleusercontent.com", "gvt1.com", "gvt2.com", "1e100.net",
    "doubleverify.com", "scorecardresearch.com", "quantserve.com",
})
_OS_NOISE = frozenset({
    "microsoft.com", "windowsupdate.com", "msftncsi.com", "windows.com",
    "aka.ms", "go.microsoft.com", "support.microsoft.com", "learn.microsoft.com",
    "office.com", "officeapps.live.com", "live.com", "msn.com", "bing.com",
    "adnxs.com", "doubleclick.net", "gstatic.com", "akamaitechnologies.com",
    "akamaiedge.net", "cloudflare.com", "cloudflare-dns.com", "verisign.com",
})



def _pcap_status(ni) -> str:
    """Did the pcap deep dive actually HAPPEN? W5 (RevAI review 2026-10-08).

    This used to be `"done (host tshark)" if _tshark() else "skipped..."` - the
    status of the analysis was read off the PRESENCE OF A BINARY. A host with
    tshark installed reported "done" over a fictitious pcap with no analysis
    operation performed at all, which is availability dressed as completion.

    The enrichment records what it did: enrich_pcap_tshark.py writes
    `ok: true` with `captures: [...]` when it ran, `ok: false` with an `error`
    when tshark was missing, and writes nothing at all when it never ran. So
    the status is derived from that record, and the counts are the operation's
    actual output.
    """
    if not isinstance(ni, dict) or not ni:
        return "not-run: this pack carries no network enrichment record, so " \
               "no pcap analysis was performed (having tshark installed says " \
               "nothing about whether it ran)"
    if ni.get("ok") is False:
        return f"skipped: {ni.get('error') or 'enrichment reported failure'}"
    caps = ni.get("captures") or []
    if not caps:
        return ("not-run: enrichment recorded no captures, so no pcap was " \
                "analysed")
    dns = sum(len(c.get("dns_queries") or []) for c in caps)
    http = sum(len(c.get("http_requests") or []) for c in caps)
    sni = sum(len(c.get("tls_sni") or []) for c in caps)
    return (f"done: {len(caps)} capture(s) analysed - {dns} dns, {http} http, "
            f"{sni} tls-sni observation(s)")


def _is_reserved_or_noise(host: str) -> bool:
    """Never C2, whatever else is true: a reserved name or OS telemetry."""
    h = (host or "").lower().strip(".")
    if not h:
        return True
    if h in _RESERVED_NAMES or h.endswith(_RESERVED_SUFFIXES):
        return True
    if h in _OS_NOISE:
        return True
    if h in _CA_CDN_INFRA or any(h.endswith("." + d) for d in _CA_CDN_INFRA):
        return True
    if any(h.endswith("." + d) for d in _OS_NOISE):
        return True
    # Not a remote host at all: multicast, broadcast and link-local traffic is
    # the machine discovering its own network. 239.255.255.250:1900 is SSDP,
    # generated by the OS, and it was reported as C2 with an HTTP "request".
    if _is_link_local_or_multicast(h):
        return True
    return False


def _is_link_local_or_multicast(host: str) -> bool:
    """Multicast, broadcast, link-local or loopback - never a C2 host.

    Port stripping has to be IPv6-aware: `split(":", 1)` turns `::1` into `""`
    and `fe80::1` into `"fe80"`, so both would silently stop being recognised as
    loopback/link-local. Only a trailing `:<port>` after a valid IPv4 literal is
    a port.
    """
    import ipaddress
    h = (host or "").strip().strip("[]")
    if h in ("localhost", "ip6-localhost", "ip6-loopback"):
        return True
    try:
        ipaddress.ip_address(h)
    except ValueError:
        # try "a.b.c.d:port"
        if ":" in h:
            head = h.rsplit(":", 1)[0].strip("[]")
            try:
                ipaddress.ip_address(head)
                h = head
            except ValueError:
                return False
        else:
            return False
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_link_local or ip.is_loopback \
            or ip.is_unspecified or ip.is_reserved:
        return True
    if str(ip) == "255.255.255.255":
        return True
    # 169.254.0.0/16 (APIPA) and 224.0.0.0/4 are covered above; a bare
    # non-routable private address is also not a remote C2 endpoint
    return ip.is_private


def _looks_like_c2(host: str) -> bool:
    """Is this host even a CANDIDATE?

    W2 (RevAI review 2026-10-08): this used to BE the C2 decision, which made a
    denylist the only thing standing between a DNS query and a `c2:` basis tag.
    `example.org` passed it, as would every legitimate domain not on a ten-entry
    list. It is now only a lead filter. C2 promotion is disabled until a
    communication observation has process/flow attribution and intent.
    """
    return not _is_reserved_or_noise(host)


# W1 (RevAI review 2026-10-08): the file-access bits that make an open a WRITE.
# These mirror WRITE_ACCESS_BITS in tools/frida_api_trace.py. They are restated
# rather than imported because findings.py is the host-side analysis plane and
# may not import VM-side tools; tests/test_w1_provenance.py asserts the two
# copies stay identical, so the restatement cannot drift silently.
_WRITE_BITS = 0x40000000 | 0x00000002 | 0x00000004 | 0x00000100
_READ_BITS = 0x80000000 | 0x00000001 | 0x00000008 | 0x00000080
# Create*-style APIs whose argument layout is unambiguous here: arg0 is the
# path, arg1 is dwDesiredAccess. NtCreateFile/ZwCreateFile are deliberately
# EXCLUDED - their access mask sits at a different offset, and guessing would
# reintroduce exactly the unproven-claim defect this fixes.
_BACKFILL_APIS = {"createfilew", "createfilea"}
# W1, second proof. A write-family call whose handle the tracer already resolved
# to a path (P1-F6's handlePaths) is positive evidence of writing that file,
# needing no access mask at all. Excluding it would DISCARD real drops - 683
# real WriteFile events across the packs on disk carry an attributed path, and
# one of them is b110's genuine Temp drop. Missing this is how a strict fix
# becomes a blind fix.
_WRITE_FAMILY_APIS = {"writefile", "writefileex", "writefilegather",
                      "ntwritefile", "flushfilebuffers", "fwrite", "fputs"}


def _backfill_provenance(dyn_dir: Path, max_lines: int = 200_000) -> list[dict]:
    """Reconstruct file-access provenance from the RAW trace.

    Every pack pulled before 2026-10-08 has the access mask in its
    frida_trace.jsonl - the tracer recorded it all along - but
    summarize_dynamic.py collapsed it into a flat decoded_paths list. Reading
    the raw trace recovers the proof instead of throwing away genuine evidence
    because of a lossy summary.

    Fails closed: a CreateFile whose access mask cannot be parsed yields no
    event, so its path stays unproven rather than being assumed a write.
    """
    tr = Path(dyn_dir) / "frida_trace.jsonl"
    if not tr.is_file():
        return []
    out: list[dict] = []
    try:
        with tr.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh):
                if n >= max_lines:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if not isinstance(ev, dict) or ev.get("type") != "call":
                    continue
                dec = ev.get("decoded") or {}
                api = str(ev.get("api") or "")
                if api.lower() in _WRITE_FAMILY_APIS:
                    # the handle was resolved to a path: that IS the write
                    p = dec.get("path")
                    if not isinstance(p, str) or not p:
                        continue
                    out.append({
                        "path": p,
                        "api": ev.get("api"),
                        "access": None,
                        "writes": True,
                        "reads": False,
                        "provenance": "write-to-attributed-path",
                        "source": "backfilled-from-raw-trace",
                    })
                    continue
                # ONLY a Create*-style API has (arg0=path, arg1=dwDesiredAccess).
                # Without this filter every hooked API's arg0/arg1 get read as
                # path + access mask, so LoadLibraryW and CreateProcessW would
                # INVENT "proven writes" from unrelated arguments - the same
                # class of invented evidence the W1 fix exists to remove.
                if api.lower() not in _BACKFILL_APIS:
                    continue
                path = dec.get("arg0")
                if not isinstance(path, str) or not path:
                    continue
                args = ev.get("args") or []
                if len(args) < 2 or args[1] is None:
                    continue          # no access mask: cannot prove anything
                try:
                    acc = int(str(args[1]), 16) if isinstance(args[1], str) \
                        else int(args[1])
                except (TypeError, ValueError):
                    continue          # unparseable mask: do not guess
                out.append({
                    "path": path,
                    "api": ev.get("api"),
                    "access": "0x%08x" % (acc & 0xFFFFFFFF),
                    "writes": bool(acc & _WRITE_BITS),
                    "reads": bool(acc & _READ_BITS),
                    "provenance": "access-mask",
                    "source": "backfilled-from-raw-trace",
                })
    except OSError:
        return []
    return out



def _triage_dumps(dyn_dir: Path, dumps: list[Path]) -> dict:
    """YARA-triage the pulled memory dumps, HERE, with the host's yara.

    W2/host-provisioning: the findings plane has reported
    `memory: {dumps, bytes}` since the beginning and then said only that triage
    "runs on the analysis host, not the VM". Nothing ran it. The limitation that
    used to excuse this - "yara is not installed on the analysis host" - was
    true, and it was true because the control plane was never provisioned:
    the FlareVM has yara-x and 57 curated rules, the box that does the analysis
    had neither, and no installer covered it.

    Now that `ops/provision_host.ps1` provisions this box, the triage runs here.

    Bounded on purpose: a dump is 60-300 MB, rule sets are large, and yara is
    slow. A per-dump wall-clock cap and a total hit cap keep a pathological
    dump from hanging the whole derivation - and a timeout is reported as a
    timeout, never as "no hits", because a silent cap would be the same
    dishonesty the rest of this module is built to avoid.
    """
    import os
    import time
    rules_dir = _yara_rules_dir()
    if not rules_dir:
        return {"ran": False, "reason": "no curated YARA rules on this host "
                                        "(ops/provision_host.ps1 stages them "
                                        "from the FlareVM)"}
    try:
        import yara
    except Exception as e:
        return {"ran": False, "reason": f"yara-python not importable: {e}"}

    # one compiled ruleset over the whole directory, rather than per file
    paths = sorted(rules_dir.rglob("*.yar")) + sorted(rules_dir.rglob("*.yara"))
    if not paths:
        return {"ran": False, "reason": f"no .yar/.yara files under {rules_dir}"}
    try:
        rules = yara.compile(filepaths={f"r{i}": str(p)
                                        for i, p in enumerate(paths)})
    except Exception as e:
        return {"ran": False,
                "reason": f"could not compile {len(paths)} rule file(s): "
                          f"{type(e).__name__}: {str(e)[:120]}"}

    cap_s = float(os.environ.get("WINRE_DUMP_TRIAGE_S", "90"))
    hits: list[dict] = []
    scanned, timed_out = 0, False
    for d in dumps:
        if not d.is_file():
            continue
        t0 = time.monotonic()
        try:
            for m in rules.match(str(d)):
                hits.append({"dump": d.name, "rule": m.rule,
                             "meta": (m.meta or {}).get("description")})
                if len(hits) >= 40:
                    break
        except Exception:
            # a dump that yara cannot read is reported, not swallowed
            hits.append({"dump": d.name, "rule": None,
                         "error": "yara could not read this dump"})
            continue
        scanned += 1
        if time.monotonic() - t0 > cap_s:
            timed_out = True
            break

    return {"ran": True, "rules_files": len(paths),
            "rules_dir": str(rules_dir), "dumps_scanned": scanned,
            "hits": hits[:40],
            "hit_count": len(hits),
            "timed_out": timed_out,
            "note": ("a timeout is a timeout, not 'no hits': a dump left "
                     "unscanned means its contents are unknown, not clean"
                     if timed_out else None)}


# ------------------------------------------------------------- dbg findings

def dbg_findings(mode_root: Path, *, sha: str = "",
                 run_id: str | None = None) -> dict:
    """Findings from the debug loop: what ran, what was observed, and did it unpack?"""
    basis: list[str] = []
    limitations: list[str] = []
    used: list[str] = []
    deep = _read(mode_root / "deep" / "deep.json") or {}
    if deep:
        used.append("deep.json")
    agent = deep.get("agent") or {}
    up = agent.get("unpack_prepass") or {}
    dbg = agent.get("dbg_ensure") or {}
    # recorded at deep-dive START, so we can tell "the debugger was
    # never available" (a product defect) from "the agent declined"
    dbg_ensure = deep.get("dbg_ensure") or dbg
    debug_run = agent.get("debug_run") or {}
    debug_evidence = debug_run.get("evidence") or []
    oep_probe = next((item.get("result") or {} for item in debug_evidence
                      if isinstance(item, dict)
                      and item.get("tool") == "x64dbg_oep"
                      and isinstance(item.get("result"), dict)), {})
    probe_address = (oep_probe.get("entrypoint")
                     if oep_probe.get("method") == "entrypoint_observation"
                     else oep_probe.get("oep"))
    if isinstance(probe_address, int) and not isinstance(probe_address, bool):
        probe_address = hex(probe_address)
    elif isinstance(probe_address, str):
        probe_address = probe_address.strip() or None
    else:
        probe_address = None
    debugger_probe = None
    if oep_probe.get("status") == "completed":
        debugger_probe = {
            "status": "completed",
            "method": oep_probe.get("method"),
            "address": probe_address,
            "target": oep_probe.get("oep_target"),
        }
    window = next((item.get("result") or {} for item in debug_evidence
                   if isinstance(item, dict)
                   and item.get("tool") == "x64dbg_run_window"
                   and isinstance(item.get("result"), dict)), {})
    monitor = _read(mode_root / "deep" / "debug_monitor" / "META.json") or {}
    monitor_summary = monitor.get("summary") or {}
    process_cleanup = monitor.get("cleanup") or {}
    monitor_matches_run = (not run_id or monitor.get("run_id") == run_id)
    monitor_ok = (monitor.get("ok") is True
                  and monitor.get("status") == "collected"
                  and monitor_matches_run
                  and process_cleanup.get("ok") is True)
    requested_window_s = window.get("requested_seconds")
    observed_window_s = window.get("observed_seconds")
    natural_exit = (window.get("natural_exit_observed") is True
                    or (window.get("exit_observed") is True
                        and window.get("stopped_after_window") is not True
                        and isinstance(requested_window_s, (int, float))
                        and isinstance(observed_window_s, (int, float))
                        and observed_window_s < requested_window_s))
    target_closed_cleanly = (window.get("stopped_after_window") is True
                             or natural_exit)
    debug_window_ok = (
        debug_run.get("requested") is True
        and debug_run.get("attempted") is True
        and debug_run.get("status") == "completed"
        and window.get("ok") is True
        and window.get("status") == "completed"
        and target_closed_cleanly
        and window.get("exit_observed") is True
        and str((window.get("final_state") or {}).get("isDebugging", "")).lower()
            == "false"
        and (window.get("final_state") or {}).get("status") == "NO_TARGET"
    )
    quick = _read(mode_root / "quick" / "quick.json") or {}
    if quick:
        used.append("quick.json")
    if monitor:
        used.append("debug_monitor/META.json")

    # The ROUTE is a property of the sample, not a judgement call: a .NET
    # assembly has no native OEP to find, so x64dbg's memory-execute
    # breakpoint method does not apply to it by design. Recording that as an
    # explicit verdict is what stops "unknown/low" from being read as "we
    # forgot to try", which is how this mode read for an entire run.
    pe = (quick.get("pe") or quick.get("evidence", {}).get("pe") or {})
    managed = bool(pe.get("is_dotnet")) or bool(quick.get("is_dotnet")) \
        or bool((quick.get("evidence") or {}).get("threat_intel", {})
                .get("is_dotnet"))
    # The route value is computed here and folded into `findings` below.
    # Assigning findings["route"] BEFORE the dict exists is the same
    # use-before-def mistake that made a successful detonation report
    # "did not run" - and the only thing that caught it was running the code.
    route = {
        "managed": managed,
        "native_unpack_applies": (not managed),
        "method": ("dotnet_analyze (managed IL) + windbg dumps"
                   if managed else
                   "x64dbg memory-execute BP for packed native samples; "
                   "entry-point observation otherwise"),
    }

    findings: dict = {
        "debugger": {"arch": dbg.get("arch"), "exe": dbg.get("exe"),
                     "launched": dbg.get("launched"),
                     "port": dbg.get("port"),
                     "ok": dbg.get("ok")},
        "debug_observation": {
            "requested": debug_run.get("requested"),
            "attempted": debug_run.get("attempted"),
            "window_completed": debug_window_ok,
            "requested_seconds": window.get("requested_seconds"),
            "observed_seconds": window.get("observed_seconds"),
            "exit_observed": window.get("exit_observed"),
            "natural_exit_observed": natural_exit,
            "completion_reason": window.get("completion_reason"),
            "stopped_after_window": window.get("stopped_after_window"),
            "final_state": window.get("final_state"),
            "monitor_status": monitor.get("status"),
            "monitor_run_matches": monitor_matches_run,
            "target_observed": (monitor_summary.get("target_observed")
                                if monitor_ok else None),
            "process_starts": (monitor_summary.get("process_starts")
                               if monitor_ok else None),
            "process_stops": (monitor_summary.get("process_stops")
                              if monitor_ok else None),
            "related_process_ids": (monitor_summary.get("related_process_ids")
                                    if monitor_ok else []),
            "active_sample_processes_before_cleanup": (
                monitor_summary.get("active_sample_processes")
                if monitor_ok else []),
            "process_cleanup_status": process_cleanup.get("status"),
            "process_cleanup_ok": process_cleanup.get("ok"),
            "terminated_process_ids": process_cleanup.get(
                "terminated_process_ids") or [],
            "scope": monitor_summary.get("scope") if monitor_ok else None,
        },
        "unpack": {},
        "route": route,
    }

    if not dbg and not up and not debug_window_ok:
        if dbg_ensure is not None:
            limitations.append(
                "the debugger was NOT available when the deep dive started: "
                f"{dbg_ensure.get('error') or dbg_ensure}. The agent could not "
                "have used it, so the absence of debugger evidence is a "
                "product defect, not a planner choice.")
        else:
            limitations.append(
                "no debugger evidence in this pack: the agent either never "
                "called a debug tool, or a later run overwrote this pack "
                "(fixed in evidence.MODES)")
        level, conf = UNKNOWN, "low"
        return _frame("dbg", sha, ok=False,
                      verdict=_verdict(level, conf, basis),
                      findings=findings, evidence_used=used,
                      limitations=limitations)

    # managed assembly: native unpack is not applicable, so the debug section
    # must say WHY there is no OEP instead of implying the unpack failed
    if managed and not up.get("ok"):
        basis.append("route:managed:dotnet")
        limitations.append(
            "a .NET assembly has no native OEP to recover, so the x64dbg "
            "memory-execute-bp unpack does not apply by design. The debug "
            "section's evidence is the dotnet_analyse IL/metadata read plus "
            "any windbg memory dump, not an OEP. Debugger availability or "
            "execution alone does not establish malicious intent.")
        return _frame("dbg", sha, ok=True,
                      verdict=_verdict(UNKNOWN, "low", basis),
                      findings=findings, evidence_used=used,
                      limitations=limitations)

    # Unpacking and observing execution are distinct outcomes. A normal,
    # unpacked program may never hit the memory-execute breakpoint, while the
    # bounded debug window and process observer still produce valid evidence.
    # Keep that mode eligible in the composite and report the absent dump as a
    # limitation instead of treating the entire producer as absent.
    unpack_ok = bool(up.get("ok"))
    producer_ok = bool((unpack_ok or debug_window_ok) and monitor_ok
                       and monitor_summary.get("target_observed") is True)
    oep = up.get("oep")
    dump = up.get("dump_path")
    parse = up.get("dump_parse") or {}
    findings["unpack"] = {
        "ok": unpack_ok, "oep": oep, "method": up.get("method"),
        "dump": dump, "dump_source": up.get("dump_source"),
        "parses": parse.get("parses"),
        "imports": parse.get("imports"),
        "machine": parse.get("machine"),
        "debugger_probe": debugger_probe,
    }
    if unpack_ok and oep:
        basis.append(f"unpack:oep:{oep}")
    if parse.get("parses"):
        basis.append(f"unpacked:parses:imports={parse.get('imports')}")

    if not up.get("ok"):
        if (debugger_probe
                and debugger_probe.get("method") == "entrypoint_observation"
                and debugger_probe.get("address")):
            limitations.append(
                "the debugger observed the original image entry point "
                f"{debugger_probe['address']}; no unpacked image "
                "dump was produced")
        elif (debugger_probe
              and debugger_probe.get("method") == "memory_execute_oep"
              and debugger_probe.get("address")):
            limitations.append(
                "the debugger observed a candidate unpacked OEP at "
                f"{debugger_probe['address']}, but no unpacked image dump "
                "was produced")
        elif up.get("error"):
            limitations.append(
                "the unpack prepass produced no usable dump: "
                f"{str(up.get('error'))[:160]}")
        elif debug_window_ok:
            limitations.append(
                "the bounded debugger observation completed, but no unpacked "
                "OEP or dump result was recorded")
        else:
            limitations.append("no unpacked OEP or dump result was recorded")
    # A debugger route, a packer hint, an unpacked image, or proof that the
    # target executed describes analysis coverage. None of those facts alone
    # establishes malicious intent. The deep-stage assessment and other
    # behavior-specific findings remain separate inputs to the composite.
    limitations.append(
        "debugger and process observations describe execution coverage; "
        "they do not independently establish malicious intent")
    level, conf = UNKNOWN, "low"

    # packed_signal is a route hint, and the section it names is evidence
    ps = agent.get("packed_signal") or {}
    findings["packed_signal"] = ps
    if ps.get("packed_section"):
        basis.append(f"packed-section:{ps['packed_section'].get('name')}")

    if not monitor_ok:
        reason = ("monitor run identity did not match this debug run"
                  if monitor else "debug monitor evidence was not collected")
        limitations.append(reason)
    elif monitor_summary.get("target_observed") is not True:
        limitations.append(
            "the ETW process monitor did not observe the staged sample; "
            "debugger execution alone does not establish process behavior")
    else:
        basis.append("debug:target-process-observed")
        findings["debug_observation"]["unique_images"] = \
            monitor_summary.get("unique_images") or []

    return _frame("dbg", sha, ok=producer_ok,
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

    yara_scan = ev.get("yarascan") or {}
    if not isinstance(yara_scan, dict):
        yara_scan = {}
    curated_hits = [str(x) for x in (yara_scan.get("high_signal") or [])
                    if str(x).strip()]
    auto_names = {str(x).split()[0].lower()
                  for x in (yara_scan.get("auto_generated") or [])
                  if str(x).strip()}
    packer_markers = ("nspack", "upack", "aspack", "mpress", "fsg",
                      "pecompact", "petite", "upx", "themida", "enigm",
                      "vmprotect", "packman", "kkrunchy", "mew", "packed",
                      "packer", "compressor")
    curated_hits = [name for name in curated_hits
                    if name.split()[0].lower() not in auto_names
                    and not any(marker in name.lower() for marker in packer_markers)]
    findings["curated_yara_floor"] = {
        "applied": bool(curated_hits), "level": "malicious" if curated_hits else None,
        "rules": curated_hits[:10],
        "policy": "family-distinctive curated YARA cannot be cleared by dynamic evidence",
    }

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
    yara = (ev.get("yarascan") or ev.get("yara") or {})
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
    for name in curated_hits:
        basis.append(f"curated-yara:{name.split()[0]}")

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
    if curated_hits or dv == MALICIOUS or (strong and high_lvl):
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

    verdict = _verdict(level, conf, basis)
    if curated_hits:
        verdict["floor"] = {"source": "curated-yara",
                            "rules": curated_hits[:10],
                            "minimum_level": "malicious"}
    return _frame(("static" if mode_root.name == "static" else "agentic"),
                  sha, ok=bool(quick or deep),
                  verdict=verdict, findings=findings,
                  evidence_used=used, limitations=limitations)


# ------------------------------------------------------------------ writer

_DISPATCH = {
    "static": static_findings,
    "agentic": static_findings,
    "dbg": dbg_findings,
    "dynamic": dynamic_findings,
}


def build(mode: str, pack_root: Path, *, sha: str = "",
          evidence_dir: Path | None = None,
          run_id: str | None = None,
          run_meta: dict | None = None) -> dict:
    """Extract findings for one mode and write <pack_root>/findings.json.

    `pack_root` is the MODE root (logs/<sha>/<mode>/): that is where the pack
    writes quick.json / deep.json and where compose.load_findings() and the UI
    read findings.json from. Every extractor receives the mode root;
    dynamic_findings descends to <mode_root>/dynamic/ itself, because that is
    the stage dir for every mode that has one.

    Returns the dict. Never raises: a mode that cannot be analysed returns
    ok=False with the reason, because a missing findings file is silent and
    silence is what made the dynamic section invisible for so long.
    """
    pack_root = Path(pack_root)
    evidence = Path(evidence_dir) if evidence_dir else pack_root / "dynamic"
    if mode not in _DISPATCH:
        return _frame(mode, sha, ok=False,
                      verdict=_verdict(UNKNOWN, "low", []),
                      findings={}, evidence_used=[],
                      limitations=[f"no findings extractor for mode {mode!r}"])
    try:
        if mode == "dbg":
            out = dbg_findings(pack_root, sha=sha, run_id=run_id)
        elif mode == "dynamic":
            out = dynamic_findings(pack_root, sha=sha, run_meta=run_meta)
        else:
            out = _DISPATCH[mode](pack_root, sha=sha)
        # The mode is THIS function's parameter, authoritative. The extractors
        # used to infer it from the directory name, which worked while they
        # received the mode root - but they receive the evidence dir, so
        # static_findings would mislabel itself "agentic".
        out["mode"] = mode
        out["run_id"] = run_id
        try:
            from .correlation import build as _build_correlation
            out["correlation"] = _build_correlation(pack_root, run_id=run_id)
        except Exception as e:
            out["correlation"] = {
                "schema": "winre-correlation/v1", "run_id": run_id,
                "status": "unverifiable", "hypotheses": [],
                "observations": [], "relationships": [],
                "limitations": [f"correlation build failed: {type(e).__name__}: {str(e)[:160]}"],
            }
    except Exception as e:
        out = _frame(mode, sha, ok=False,
                     verdict=_verdict(UNKNOWN, "low", []), findings={},
                     evidence_used=[],
                     limitations=[f"{type(e).__name__}: {str(e)[:200]}"])
    try:
        pack_root.mkdir(parents=True, exist_ok=True)
        (pack_root / "findings.json").write_text(
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
