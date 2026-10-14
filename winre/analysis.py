r"""analysis.py - the CONTROL-PLANE half of the old _post_pull_enrich.

Phase 3 of docs/internal/DESIGN.md.

`orchestrator._post_pull_enrich` used to run everything - tshark enrich,
beacon analysis, the Procmon persistence catalog, the emulation diff - inside
the orchestrator process. In remote mode that process runs ON THE FLAREVM, via
`ssh flare "python orchestrator.py --mode local ..."`. So every one of those
analyses executed on a box that had just run the sample, whose Python, tshark
and libraries are all fair game for a sample that wanted to tamper with its own
analysis environment.

The rule is: THE VM IS AN EVIDENCE PRODUCER AND NOTHING ELSE.

Split:
  * host-side (this module) - pcap enrich, beacon analysis, Procmon catalog,
    emulation diff. Pure Python over pulled files plus tshark on the host.
  * VM-side (stays in orchestrator) - process snapshots and memory capture
    only. WinDbg dump triage runs here against pulled files. Ntdll integrity
    interpretation remains deferred until its reference can be collected and
    checked off-box.

The orchestrator records what it deferred so a reader can see the analysis ran
elsewhere rather than never ran.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


def _tool(dyn_dir: Path, name: str) -> Path | None:
    """Find an analysis tool by name.

    Looks in the pulled pack first (a packed copy wins), then the repo's `tools/`
    and `winre/` directories. The `winre/` entry is not redundant: the
    host-side analysis tools - enrich_pcap_tshark, pcap_beacon, emu_diff,
    procmon_post - all live in `winre/`, and looking only in `tools/` made
    enrich_pcap skip every single run with "not found" while tshark was
    installed and the pcaps were sitting right there.
    """
    repo = Path(__file__).resolve().parents[1]
    for cand in (dyn_dir.parents[1] / "tools" / name,
                 dyn_dir.parents[0] / "tools" / name,
                 repo / "tools" / name,
                 repo / "winre" / name,
                 repo / name):
        if cand.is_file():
            return cand
    return None


def enrich_pcap(dyn_dir: Path) -> dict:
    """tshark enrichment of the pulled pcaps. Runs here, where tshark is OUR
    tshark - not the VM's, which the sample could have replaced."""
    if not any((dyn_dir / rel).is_dir() for rel in
               ("network_raw", "off_box/network_raw")):
        return {"skipped": True, "reason": "no guest or off-box network capture pulled"}
    exe = shutil.which("tshark") or shutil.which("tshark.exe")
    if not exe:
        return {"skipped": True,
                "reason": "tshark is not installed on the analysis host"}
    script = _tool(dyn_dir, "enrich_pcap_tshark.py") or (
        Path(__file__).resolve().parents[1] / "tools" / "enrich_pcap_tshark.py")
    if not script.is_file():
        return {"skipped": True, "reason": "enrich_pcap_tshark.py not found"}
    try:
        r = subprocess.run([sys.executable, str(script), str(dyn_dir)],
                           capture_output=True, text=True, timeout=300,
                           encoding="utf-8", errors="replace")
        try:
            intel = json.loads((dyn_dir / "network_intel.json").read_text(
                encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            intel = {}
        return {"ok": bool(r.returncode == 0 and intel.get("ok")),
                "status": intel.get("status") or
                         ("failed" if r.returncode else "unknown"),
                "reason_code": intel.get("reason_code"),
                "error": intel.get("error") or
                         ((r.stderr or r.stdout or "tshark enrichment failed")[-400:]
                          if r.returncode else None),
                "rc": r.returncode, "stdout": (r.stdout or "")[-400:],
                "host": "control-plane"}
    except Exception as e:
        return {"error": str(e)[:200]}


def beacon(dyn_dir: Path) -> dict:
    try:
        from winre.pcap_beacon import analyze_pcaps
        return analyze_pcaps(dyn_dir)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:160]}"}


def procmon_catalog(dyn_dir: Path) -> dict:
    """Procmon's persistence catalog. Note the counts are window-wide totals
    for the whole VM - see winre.findings, which is the consumer that keeps
    them labelled as such."""
    if not (dyn_dir / "procmon.csv").is_file():
        return {"skipped": True, "reason": "no procmon.csv pulled"}
    try:
        from winre.procmon_post import build_procmon_report
        return build_procmon_report(dyn_dir)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:160]}"}


def emulation_diff(dyn_dir: Path) -> dict:
    try:
        from winre.emu_diff import compare
        return compare(dyn_dir)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:160]}"}


def analyst_next(dyn_dir: Path) -> dict:
    """ANALYST-NEXT.md + analyst_next.json — the human next-steps checklist.

    Moved off the VM. It is pure enumeration over files already on disk, so a
    box that has just executed the sample has no business producing it. It is
    also NOT a verdict: it lists what was collected and what a human still has
    to do, and `analyst_only` items must never be reported as complete.

    This used to run on the VM via `from winre.emit_analyst_next import emit`,
    which was a name that never existed — so every run recorded an ImportError
    and produced nothing. `winre/tests/test_off_vm_split.py` now pins both the
    import and the host-side wiring so that cannot regress.
    """
    try:
        from winre.emit_analyst_next import emit
        return emit(dyn_dir)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:160]}"}


def windbg_dump(dyn_dir: Path) -> dict:
    """Analyze a pulled dump here; never fall back to a guest debugger."""
    try:
        from winre.windbg_post import analyze_dump
        return analyze_dump(dyn_dir)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:160]}"}


def run(dyn_dir: Path) -> dict:
    """Every host-side analysis step, best-effort and individually reported.

    Never raises: a failed step must not lose the detonation, and it must say
    it failed rather than silently producing a partial picture claimed as
    complete.
    """
    out: dict = {"ran_on": "control-plane", "steps": {}}
    for name, fn in (("enrich_pcap", enrich_pcap), ("pcap_beacon", beacon),
                     ("procmon_post", procmon_catalog),
                     ("emu_diff", emulation_diff),
                     ("analyst_next", analyst_next),
                     ("windbg_dump", windbg_dump)):
        try:
            out["steps"][name] = fn(dyn_dir)
        except Exception as e:                      # pragma: no cover
            out["steps"][name] = {"error": str(e)[:200]}
    try:
        (dyn_dir / "post_analysis.json").write_text(
            json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
    except Exception:
        pass
    return out


if __name__ == "__main__":
    import sys as _s
    d = Path(_s.argv[1]) if len(_s.argv) > 1 else Path(".")
    print(json.dumps(run(d), indent=2, default=str))
