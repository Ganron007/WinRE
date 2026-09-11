#!/usr/bin/env python3
"""windbg_post.py — WinDbg (mcp-windbg) dump analysis for dynamic packs.

Consumes the in-run memory captures (`memory/sample_full.dmp` from the
delayed procdump, or any pe-sieve `.dmp`) and produces a deterministic
analysis block at `dynamic/windbg_analysis.json`:

  * `!analyze -v` triage text + parsed highlights (exception/bugcheck,
    faulting module, image/process name, failure bucket)
  * `.ecxr` + `k` (faulting context + call stack)
  * `lm` (loaded modules) and `vertarget` (target summary)

PASSIVE: this opens a dump file; it never attaches to a live target, so it
is NOT behind the execution snapshot gate. Best-effort by design — no dump
or an unreachable WinDbg MCP results in an honest `skipped` record, never a
pipeline failure.

Run on the VM (or via the scp'd helper from the control plane):
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


def _session_id(open_res: dict) -> str | None:
    """mcp-windbg returns content-block text; the session id may be plain
    text ('Session ID: abc-123') or JSON. Try both, tolerantly."""
    blobs: list[str] = []
    res = open_res.get("result") if isinstance(open_res, dict) else None
    if isinstance(res, dict):
        if isinstance(res.get("text"), str):
            blobs.append(res["text"])
        try:
            blobs.append(json.dumps(res.get("raw") or res, default=str))
        except Exception:
            pass
    for blob in blobs:
        if not blob:
            continue
        try:
            d = json.loads(blob)
            if isinstance(d, dict):
                for k in ("session_id", "sessionId", "id"):
                    if d.get(k):
                        return str(d[k])
        except Exception:
            pass
        m = re.search(r"(?:session[_ \-]?id|session)[\"':=\s]+([0-9a-zA-Z][0-9a-zA-Z\-]{3,})",
                      blob, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _text_of(call_res: dict) -> str:
    if not isinstance(call_res, dict):
        return ""
    res = call_res.get("result")
    if isinstance(res, dict):
        if isinstance(res.get("text"), str):
            return res["text"]
        try:
            return json.dumps(res, default=str)
        except Exception:
            return ""
    return ""


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


def _ensure_mcp_server() -> dict | None:
    """Heal :9097 locally when analyze_dump runs ON the VM (session-0 safe).

    The boot launcher is the primary path; this covers a failed logon launcher.
    Returns None when not on the VM (no local launcher script) or opted out
    via WINRE_MCP_AUTOSTART=0.
    """
    import os
    import subprocess
    flag = os.environ.get("WINRE_MCP_AUTOSTART", "1").strip().lower()
    if flag in ("0", "false", "no", "off"):
        return None
    script = Path(r"C:\WinRE\winre\mcp\start_servers.ps1")
    if not script.is_file():
        return None  # not the VM (control-plane local testing) — no-op
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", str(script), "-NoX64dbg", "-Detach"],
            capture_output=True, text=True, timeout=60)
        return {"exit": r.returncode}
    except Exception as e:
        return {"error": str(e)[:150]}


def analyze_dump(dyn_dir: Path, dump: str | None = None,
                 base: str | None = None, timeout: int = 300) -> dict:
    """Analyze the pack's captured dump with mcp-windbg (passive)."""
    t0 = time.time()
    dyn_dir = Path(dyn_dir)
    target = find_dump(dyn_dir, dump)
    if not target:
        return _write(dyn_dir, {
            "ok": False, "dump": None,
            "skipped": "no dump under dynamic/memory", "elapsed_s": 0.0})
    try:
        from winre.mcp import WinDbgMCPClient
    except Exception as e:
        return _write(dyn_dir, {"ok": False, "dump": str(target),
                                "error": f"client import: {str(e)[:150]}"})
    cli = WinDbgMCPClient(base=base, default_timeout=timeout)
    heal = None
    if not cli.is_up():
        # one local heal attempt (idempotent launcher), then re-probe
        heal = _ensure_mcp_server()
        if heal is not None:
            deadline = time.time() + 30
            while time.time() < deadline:
                time.sleep(3)
                if cli.is_up():
                    break
    if not cli.is_up():
        payload = {"ok": False, "dump": str(target),
                   "skipped": "windbg MCP :9097 not reachable",
                   "elapsed_s": round(time.time() - t0, 1)}
        if heal is not None:
            payload["heal"] = heal
        return _write(dyn_dir, payload)

    opened = cli.open_cdb_dump(str(target))
    sid = _session_id(opened)
    if not opened.get("ok") or not sid:
        return _write(dyn_dir, {
            "ok": False, "dump": str(target),
            "error": (f"open_cdb_dump failed: {opened.get('error')}"
                      if not opened.get("ok")
                      else "session id not found in open response"),
            "open_text": _text_of(opened)[:600],
            "elapsed_s": round(time.time() - t0, 1)})

    commands: dict[str, str] = {}
    for cmd in COMMANDS:
        r = cli.run_cdb_command(sid, cmd)
        commands[cmd] = (_text_of(r) if r.get("ok")
                         else f"[error] {r.get('error')}")[:MAX_CMD_CHARS]
    try:
        cli.close_cdb_session(sid)
    except Exception:
        pass

    return _write(dyn_dir, {
        "ok": True,
        "dump": str(target),
        "dump_size": target.stat().st_size,
        "session": sid,
        "highlights": _highlights(commands.get("!analyze -v", "")),
        "commands": commands,
        "elapsed_s": round(time.time() - t0, 1),
        "note": ("Passive WinDbg dump analysis (mcp-windbg); no live attach. "
                 "Full memory-image workflows are DFIR-Nexus territory."),
    })


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinDbg dump analysis for a pack")
    ap.add_argument("dynamic_dir")
    ap.add_argument("--dump", default=None,
                    help="dump filename inside dynamic/memory/ (default: "
                         "sample_full.dmp, else newest)")
    ap.add_argument("--base", default=None, help="WinDbg MCP base URL")
    args = ap.parse_args()
    print(json.dumps(analyze_dump(Path(args.dynamic_dir), args.dump,
                                  args.base), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
