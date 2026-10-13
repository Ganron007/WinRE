#!/usr/bin/env python3
"""windbg_post.py — WinDbg (mcp-windbg) dump analysis for dynamic packs.

Consumes the in-run memory captures (`memory/sample_full.dmp` from the
delayed procdump, or any pe-sieve `.dmp`) and produces a deterministic
analysis block at `dynamic/windbg_analysis.json`:

  * `!analyze -v` triage text + parsed highlights (exception/bugcheck,
    faulting module, image/process name, failure bucket)
  * `.ecxr` + `k` (faulting context + call stack)
  * `lm` (loaded modules) and `vertarget` (target summary)

PASSIVE: this opens a pulled dump file; it never attaches to a live target.
Analysis runs only on the control plane. If host cdb is unavailable, that is
recorded as a limitation; this module never falls back to a guest debugger.

WHERE THIS RUNS
--------------
This analysis is PASSIVE - it opens a `.dmp` file and never attaches to a live
target - so there is no technical reason for it to run on the box that just
executed the sample. For a while it did anyway, because the only WinDbg it could
reach was mcp-windbg on `127.0.0.1:9097`, which is deliberately localhost-bound
so nothing off-box can drive the VM's debugger.

That left the one step of the post-detonation window with no reason to be there:
a sample that had just controlled the machine was analysed BY that machine.

There is one supported path: `cdb.exe` on the control plane, run directly
against the pulled `.dmp`. No VM dependency, no network hop, and no analysis
executes on the guest after detonation. `ops/provision_host.ps1` installs cdb.

Run on the analysis host:
    python -m winre.windbg_post <dynamic_dir> [--dump sample_full.dmp]
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

MAX_CMD_CHARS = 4000
COMMANDS = ("!analyze -v", ".ecxr", "k", "lm", "vertarget")


def _out_path(dyn_dir: Path) -> Path:
    return dyn_dir / "windbg_analysis.json"


def _write(dyn_dir: Path, payload: dict) -> dict:
    try:
        _out_path(dyn_dir).write_text(
            json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    except OSError:
        pass
    return payload


def find_dump(dyn_dir: Path, dump: str | None = None) -> Path | None:
    """Resolve the dump inside dynamic/memory/ (basename-only override —
    the agent can never point WinDbg outside the pack's memory dir)."""
    mem = dyn_dir / "memory"
    if dump:
        p = mem / Path(str(dump)).name
        return p if p.is_file() else None
    pref = mem / "sample_full.dmp"
    if pref.is_file():
        return pref
    dumps = sorted((p for p in mem.rglob("*.dmp") if p.is_file()),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return dumps[0] if dumps else None


def _highlights(analyze_text: str) -> dict:
    out: dict = {}
    for key, pat in (
            ("bugcheck_str", r"BUGCHECK_STR:\s*(\S+)"),
            ("exception_code", r"EXCEPTION_CODE(?:_STR)?:\s*(\S+)"),
            ("faulting_module", r"MODULE_NAME:\s*(\S+)"),
            ("image_name", r"IMAGE_NAME:\s*(\S+)"),
            ("process_name", r"PROCESS_NAME:\s*(\S+)"),
            ("failure_bucket", r"FAILURE_BUCKET_ID:\s*(\S+)")):
        m = re.search(pat, analyze_text or "")
        if m:
            out[key] = m.group(1)
    return out


# ---------------------------------------------------------- host-side cdb

_CDB_NAMES = ("cdb.exe", "cdb", "kd.exe")
# the debugging tools ship inside the Windows SDK; these are the usual places
_CDB_DIRS = (
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64",
    r"C:\Program Files\Windows Kits\10\Debuggers\x86",
    r"C:\Debuggers\cdb.exe",
)


def local_cdb() -> "Path | None":
    """`cdb.exe` on THIS box, or None.

    Found by PATH first (choco/winget installs land there), then the Windows
    SDK's Debuggers directories. An env override wins so a host that keeps the
    debugging tools elsewhere needs no code change.
    """
    import os
    import shutil
    env = os.environ.get("WINRE_CDB")
    for cand in ([Path(env)] if env else []):
        if cand.is_file():
            return cand
    for name in _CDB_NAMES:
        hit = shutil.which(name)
        if hit:
            return Path(hit)
    for d in _CDB_DIRS:
        for name in _CDB_NAMES:
            p = Path(d) / name
            if p.is_file():
                return p
    return None


def _run_cdb(exe: Path, target: Path, timeout: int) -> dict:
    """Run the command set against a dump with the LOCAL debugger.

    `-z <dump>` opens a dump passively; `-c "<cmds>"` runs the set and quits.
    `-G` skips the final breakpoint, `-n` suppresses the extension-gallery
    banner and NatVis chatter that would otherwise dominate the transcript.
    Each command is separated by `;` so one process answers all of them - a
    60-300 MB dump takes tens of seconds to open, so paying that once matters.

    The dump path is made ABSOLUTE before it is passed: cdb resolves a relative
    path against its own working directory, not ours, and fails with
    "Win32 error 0n3" on a perfectly good file.
    """
    import subprocess
    # Each command is wrapped in an `.echo` marker. Splitting the transcript on
    # the command text alone does NOT work: cdb does not echo commands in `-c`
    # mode, so the blocks run together and every command after the first is
    # mis-attributed - `lm` came back 2 chars and `highlights` empty.
    parts = []
    for n, cmd in enumerate(COMMANDS):
        parts.append(f".echo ===WINRE_CMD_{n}===")
        parts.append(cmd)
    parts.append("q")   # without it cdb waits interactively and then fails
    joined = "; ".join(parts)
    argv = [str(exe), "-z", str(target.resolve()), "-G", "-n", "-c", joined]
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=max(60, int(timeout)),
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "cdb timed out on this dump",
                "timed_out": True}
    except OSError as e:
        return {"ok": False, "error": f"cdb could not run: {e}"}
    if r.returncode not in (0, 1):
        # cdb exits non-zero on a dump it cannot open; that is an honest
        # failure, not a crash
        return {"ok": False,
                "error": f"cdb exit {r.returncode}: "
                         f"{(r.stderr or '')[:200]}"}
    return {"ok": True, "stdout": r.stdout or "", "stderr": r.stderr or ""}


def _split_output(text: str) -> dict[str, str]:
    """Split one cdb transcript back into per-command blocks.

    `_run_cdb` wraps every command in an `.echo ===WINRE_CMD_n===` marker, and
    those markers are the only reliable delimiter: cdb does not echo commands
    in `-c` mode, so splitting on the command text merges the blocks and
    The LAST occurrence of each marker is the real one. The first occurrence
    sits inside cdb's own `Reading initial command '...'` echo of the whole
    `-c` string, which contains every marker - so `find()` lands in that line
    and every block comes back a few dozen characters long.
    """
    out: dict[str, str] = {}
    marks: list[tuple[int, int]] = []
    for n, _cmd in enumerate(COMMANDS):
        i = text.rfind(f"===WINRE_CMD_{n}===")
        if i >= 0:
            marks.append((i, n))
    marks.sort()
    for k, (pos, n) in enumerate(marks):
        end = marks[k + 1][0] if k + 1 < len(marks) else len(text)
        body = text[pos:end]
        # drop the marker line itself
        body = body.split("\n", 1)[1] if "\n" in body else ""
        out[COMMANDS[n]] = body.strip("\r\n")[:MAX_CMD_CHARS]
    for cmd in COMMANDS:
        out.setdefault(cmd, "")
    return out


def _analyze_with_local_cdb(target: Path, timeout: int) -> dict:
    """The host-side analysis: no VM, no MCP, no network."""
    exe = local_cdb()
    if exe is None:
        return {"ok": False, "skipped": "no cdb.exe on this host "
                                        "(ops/provision_host.ps1 installs it)"}
    r = _run_cdb(exe, target, timeout)
    if not r.get("ok"):
        return {"ok": False, "dump": str(target),
                "error": r.get("error"),
                "timed_out": r.get("timed_out", False),
                "analyzer": "local cdb", "cdb": str(exe)}
    cmds = _split_output(r["stdout"])
    return {"ok": True, "dump": str(target), "analyzer": "local cdb",
            "cdb": str(exe), "commands": cmds,
            "highlights": _highlights(cmds.get("!analyze -v", "")),
            "note": ("Passive WinDbg dump analysis, run on the ANALYSIS HOST "
                     "against the pulled dump. Nothing executed on the VM after "
                     "the sample ran. Full memory-image workflows are DFIR-Nexus "
                     "territory.")}


def analyze_dump(dyn_dir: Path, dump: str | None = None,
                 timeout: int = 300) -> dict:
    """Analyze the pack's captured dump with WinDbg (passive).

    This is passive analysis of a file, so it belongs on the analysis host -
    not on the box that just ran the sample.
    """
    t0 = time.time()
    dyn_dir = Path(dyn_dir)
    target = find_dump(dyn_dir, dump)
    if not target:
        return _write(dyn_dir, {
            "ok": False, "dump": None,
            "skipped": "no dump under dynamic/memory", "elapsed_s": 0.0})

    # --- preferred: a local debugger on the analysis host -------------------
    local = _analyze_with_local_cdb(target, timeout)
    if local.get("ok"):
        local["dump_size"] = target.stat().st_size
        local["elapsed_s"] = round(time.time() - t0, 1)
        return _write(dyn_dir, local)
    if local.get("skipped") is None and not local.get("timed_out"):
        # cdb exists and ran but failed: report that honestly rather than
        # silently falling through to a VM we may not even reach
        local["elapsed_s"] = round(time.time() - t0, 1)
        return _write(dyn_dir, local)
    # No guest fallback: the process that ran the sample cannot be asked to
    # interpret its own dump. A missing host cdb is an explicit limitation.
    local["elapsed_s"] = round(time.time() - t0, 1)
    local["note"] = "guest MCP fallback disabled by the evidence trust boundary"
    return _write(dyn_dir, local)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinDbg dump analysis for a pack")
    ap.add_argument("dynamic_dir")
    ap.add_argument("--dump", default=None,
                    help="dump filename inside dynamic/memory/ (default: "
                         "sample_full.dmp, else newest)")
    args = ap.parse_args()
    print(json.dumps(analyze_dump(Path(args.dynamic_dir), args.dump),
                     indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
