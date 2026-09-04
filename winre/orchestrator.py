#!/usr/bin/env python3
"""
WinRE dynamic detonation orchestrator (Flare-VM).

Runs FakeNet + Procmon + Frida (+ optional pe-sieve / x64dbg OEP dump)
via flare_dynamic_job.ps1 and stages artifacts into logs/<sha>/dynamic/.
Originally a Remnux->Flare SSH orchestrator (dynamic_run_v2.py); now
local-first with `--mode local` as the recommended path (run on Flare,
no SSH hop). SSH mode is kept for Remnux-side orchestration.

Usage:
  python winre/orchestrator.py <sha256> --mode local --max-seconds 45
  python winre/orchestrator.py <sha256> --max-seconds 45 --dry-run

Mode:
  --mode local   run flare_dynamic_job.ps1 on this host (default when
                 WINRE_ORCHESTRATOR_MODE=local)
  --mode ssh     Remnux->Flare via SSH (legacy; requires FLARE_* env)

Env:
  FLARE_HOST       default 192.168.77.42
  FLARE_USER       default FLARE-VM
  FLARE_SSH_KEY    default ~/.ssh/cadre-77.42-key
  FLARE_SSH_PORT   default 22
  REVENG_DYNAMIC_SKIP=1     → write META skip and exit 0
  REVENG_DYNAMIC_PESIEVE=1  → Flare job runs pe-sieve (+ hollows_hunter) mid-detonation
  REVENG_DYNAMIC_X64DBG=0   → skip x64dbg MCP OEP/dump pass
  WINRE_ORCHESTRATOR_MODE={ssh,local} → default --mode
  WINRE_ORCH_LOCK          → override lockfile path
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
try:
    from v2_lib import LOGS_DIR, SESSIONS_DIR, load_session, high_signal_yara_matches
except Exception:
    LOGS_DIR = Path(os.environ.get("REVENG_LOGS_DIR", "/opt/samples/logs"))
    SESSIONS_DIR = Path(os.environ.get("REVENG_SESSIONS_DIR", "/opt/samples/sessions"))

    def load_session(sha: str) -> dict:
        return json.loads((SESSIONS_DIR / f"{sha}.json").read_text())

    def high_signal_yara_matches(yara: dict | None) -> list:
        return []


DEFAULT_APIS = (
    "CreateFileW,WriteFile,ReadFile,DeleteFileW,"
    "RegOpenKeyExW,RegSetValueExW,"
    "VirtualAlloc,VirtualProtect,WriteProcessMemory,CreateRemoteThread,"
    "WinHttpOpen,InternetOpenW,connect,send,recv,"
    "LoadLibraryW,GetProcAddress,CreateProcessW"
)

SCHEMA_VERSION = "v6.2.4"

# Local repo fallbacks when developing off Remnux
_REPO_SCRIPTS = Path(__file__).resolve().parent


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sample_format(session: dict, sample: str) -> str:
    ft = session.get("file_type") or {}
    fmt = (ft.get("format") or "").lower()
    if fmt:
        return fmt
    # magic fallback
    try:
        with open(sample, "rb") as f:
            head = f.read(5)
        if head[:4] == b"\x7fELF":
            return "elf"
        if head.startswith(b"%PDF"):
            return "pdf"
        if head[:2] == b"MZ":
            return "pe"
    except OSError:
        pass
    return "unknown"


def _post_pull_enrich(dyn_dir: Path, sha: str) -> dict:
    """tshark enrich + ANALYST-NEXT after every dynamic pull (Win or ELF)."""
    notes: dict = {"enrich_pcap": None, "analyst_next": None}
    enrich = _local_tool("enrich_pcap_tshark.py")
    if enrich and (dyn_dir / "network_raw").is_dir():
        try:
            r = subprocess.run(
                [sys.executable, str(enrich), str(dyn_dir)],
                capture_output=True,
                text=True,
                timeout=180,
            )
            notes["enrich_pcap"] = {
                "rc": r.returncode,
                "stdout": (r.stdout or "")[-300:],
            }
        except Exception as e:
            notes["enrich_pcap"] = {"error": str(e)}
    else:
        notes["enrich_pcap"] = {"skipped": True, "reason": "no script or no network_raw"}

    emit = _local_tool("emit_analyst_next.py")
    if emit:
        try:
            r = subprocess.run(
                [sys.executable, str(emit), str(dyn_dir), "--sha", sha],
                capture_output=True,
                text=True,
                timeout=60,
            )
            notes["analyst_next"] = {
                "rc": r.returncode,
                "path": str(dyn_dir / "ANALYST-NEXT.md"),
                "stdout": (r.stdout or "")[-300:],
            }
        except Exception as e:
            notes["analyst_next"] = {"error": str(e)}
    else:
        notes["analyst_next"] = {"skipped": True, "reason": "emit_analyst_next.py missing"}
    return notes


def _run_elf_dynamic(sha: str, sample: str, dyn_dir: Path, max_seconds: int, meta: dict) -> dict:
    """Remnux-local ELF worker — no Flare hop."""
    meta["platform"] = "linux"
    meta["worker"] = "remnux-elf"
    meta["network_mode"] = "tcpdump_local"
    meta["snapshot_restore_required"] = False
    job = _local_tool("elf_dynamic_job.sh")
    if not job:
        meta["error"] = "elf_dynamic_job.sh not found"
        meta["ok"] = False
        return meta
    # ensure executable bit ignored on Windows copy — invoke via bash
    bash = shutil.which("bash") or "/bin/bash"
    cmd = [bash, str(job), sample, str(dyn_dir), str(int(max_seconds))]
    print(f"[dynamic_run_v2] ELF job -> {job}", flush=True)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=int(max_seconds) + 120)
        meta["job_rc"] = cp.returncode
        meta["job_stdout_tail"] = (cp.stdout or "")[-800:]
        meta["job_stderr_tail"] = (cp.stderr or "")[-800:]
    except subprocess.TimeoutExpired as te:
        meta["job_timeout"] = True
        meta["job_rc"] = -1
        meta["error"] = f"elf job timeout: {te}"
        meta["ok"] = False
        return meta

    for name in (
        "META.json",
        "strace_summary.json",
        "strace.log",
        "network.json",
        "process_snapshot_pre.txt",
        "process_snapshot_post.txt",
        "job.log",
    ):
        p = dyn_dir / name
        if p.exists():
            meta["artifacts"][name] = str(p)
    has_core = (dyn_dir / "strace.log").is_file() or (dyn_dir / "strace_summary.json").is_file()
    meta["ok"] = has_core and cp.returncode in (0, 124)  # 124 = timeout but may have data
    if not meta["ok"] and not meta.get("error"):
        meta["error"] = f"elf incomplete pack rc={cp.returncode}"
    return meta


def _flare_cfg() -> dict:
    return {
        "host": os.environ.get("FLARE_HOST", "192.168.77.42"),
        "user": os.environ.get("FLARE_USER", "FLARE-VM"),
        "key": os.environ.get(
            "FLARE_SSH_KEY",
            str(Path.home() / ".ssh" / "cadre-77.42-key"),
        ),
        "port": int(os.environ.get("FLARE_SSH_PORT", "22")),
        "remote_root": os.environ.get("FLARE_SAMPLES_ROOT", r"C:\samples"),
        "remote_tools": os.environ.get(
            "FLARE_DYNAMIC_TOOLS",
            r"C:\tools\reveng-dynamic",
        ),
        "python": os.environ.get("FLARE_PYTHON", r"C:\Python313\python.exe"),
        "job_ps1": os.environ.get(
            "FLARE_DYNAMIC_JOB",
            r"C:\tools\reveng-dynamic\flare_dynamic_job.ps1",
        ),
    }


def _ssh_base(cfg: dict) -> list[str]:
    return [
        "ssh",
        "-i", cfg["key"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-o", "BatchMode=yes",
        "-p", str(cfg["port"]),
        f"{cfg['user']}@{cfg['host']}",
    ]


def _scp_to(cfg: dict, local: Path, remote: str) -> None:
    cmd = [
        "scp",
        "-i", cfg["key"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-P", str(cfg["port"]),
        str(local),
        f"{cfg['user']}@{cfg['host']}:{remote}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"scp to flare failed: {r.stderr[:400]}")


def _scp_from(cfg: dict, remote: str, local: Path) -> None:
    cmd = [
        "scp",
        "-i", cfg["key"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-P", str(cfg["port"]),
        f"{cfg['user']}@{cfg['host']}:{remote}",
        str(local),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"scp from flare failed: {r.stderr[:400]}")


def _ssh_run(cfg: dict, remote_cmd: str, timeout: int = 300) -> subprocess.CompletedProcess:
    cmd = _ssh_base(cfg) + [remote_cmd]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _yara_lock(sha: str) -> dict:
    out = {"high_signal": [], "policy": "sandbox_cannot_clear_high_signal_yara"}
    for path in (
        LOGS_DIR / sha / "quick_scan" / "00-tools-raw.json",
        LOGS_DIR / sha / "verdict.json",
        LOGS_DIR / sha / "deep_dive" / "01-tools-raw.json",
    ):
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        yara = data.get("yara") if isinstance(data, dict) else None
        if not yara and isinstance(data, dict) and "matches" in data:
            yara = data
        hits = high_signal_yara_matches(yara if isinstance(yara, dict) else {})
        if hits:
            out["high_signal"] = hits
            break
        if isinstance(data, dict) and data.get("yara_family_hits"):
            out["high_signal"] = list(data.get("yara_family_hits") or [])
            break
    return out


def _write_schema(dyn_dir: Path) -> None:
    (dyn_dir / "SCHEMA.md").write_text(
        "# Dynamic evidence schema (V6.2.3)\n\n"
        "- `META.json` — run status, platform (windows|linux), timings, yara_lock\n"
        "- Windows: `frida_trace.json`, `procmon.csv`, FakeNet `network_raw/`\n"
        "- Linux ELF: `strace.log`, `strace_summary.json`, tcpdump `network_raw/`\n"
        "- `network_intel.json` — tshark enrich (post-pull)\n"
        "- `ANALYST-NEXT.md` — human next actions (always)\n"
        "- `process_snapshot*` — pre/post process diff\n",
        encoding="utf-8",
    )


def _write_meta(dyn_dir: Path, meta: dict) -> None:
    dyn_dir.mkdir(parents=True, exist_ok=True)
    (dyn_dir / "META.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    _write_schema(dyn_dir)


def _local_tool(name: str) -> Path | None:
    for base in (
        _REPO_SCRIPTS,
        Path("/opt/scripts"),
        Path(__file__).resolve().parent,
    ):
        p = base / name
        if p.is_file():
            return p
    return None


def _env_truthy(name: str) -> bool:
    return str(os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Local mode (run orchestrator on Flare, no SSH hop)
# ---------------------------------------------------------------------------
LOCAL_JOB_PS1 = Path(__file__).resolve().parent / "flare_dynamic_job.ps1"
LOCK_PATH = Path(os.environ.get("WINRE_ORCH_LOCK", r"C:\WinRE\lock\orchestrator.lock"))

# Images that must never survive into a fresh detonation. Deliberately NOT
# including ida64.exe (the static engine) — dynamic runs after static in the
# spine, and killing a live analysis would break the pack. Everything here is
# either a detonation worker or a stale MCP/debug leftover that the manager
# can relaunch on demand.
STALE_IMAGES = (
    "sample.exe", "frida-helper-64.exe", "frida-helper-32.exe",
    "fakenet.exe", "Procmon64.exe", "Procmon.exe",
    "hollows_hunter.exe", "pe-sieve.exe",
    "idasql.exe", "java.exe",
    "windbg.exe", "x64dbg.exe", "x32dbg.exe",
)


def _kill_stale_ssh(cfg, extra_timeout: int = 45) -> None:
    """SSH-path cleanup, same image list as the job's Kill-Stale."""
    cmd = " & ".join(f"taskkill /F /IM {im} /T 2>nul" for im in STALE_IMAGES)
    _ssh_run(cfg, f"{cmd} & exit /b 0", timeout=extra_timeout)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes
            SYNCHRONIZE = 0x00100000
            h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
            if h:
                ctypes.windll.kernel32.CloseHandle(h)
                return True
            return False
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _lock_pid() -> int | None:
    """Second line of the lockfile holds the writer's pid."""
    try:
        lines = LOCK_PATH.read_text(encoding="utf-8").splitlines()
        return int(lines[1].strip())
    except Exception:
        return None


def _acquire_lock(force: bool = False) -> bool:
    """Mutex to prevent local+SSH jobs from stomping each other.

    Atomic exclusive create (no check-then-write TOCTOU). Stale-lock
    recovery: a fresh lockfile whose writer pid is DEAD is takeover-able
    (crashed run). A live pid holds the lock unless force=True (operator
    says break it). Fails CLOSED on unexpected errors — two orchestrators
    stomping the same VM is worse than a spurious refusal.
    """
    try:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        if LOCK_PATH.exists():
            age = time.time() - LOCK_PATH.stat().st_mtime
            pid = _lock_pid()
            alive = _pid_alive(pid) if pid else None  # None = unknown
            if alive is True and age < 7200 and not force:
                return False
            if alive is None and age < 7200 and not force:
                return False  # unparseable but fresh — respect it
            # stale (dead writer / too old) or forced — take over
            try:
                LOCK_PATH.unlink()
            except Exception:
                return False
        try:
            # O_EXCL: atomic — a concurrent acquirer loses cleanly
            fd = os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(f"{_utc()}\n{os.getpid()}\n")
            return True
        except FileExistsError:
            return False
    except Exception:
        return False  # fail closed


def _release_lock() -> None:
    try:
        if LOCK_PATH.exists():
            LOCK_PATH.unlink()
    except Exception:
        pass


# Execution-site snapshot gate (L1): the orchestrator RUNS ON THE VM, so the
# clean-marker check/consume is a local file operation — no SSH, atomic
# within the single-tenant detonation. The control-plane preflight (remote_
# driver/snapshot_gate) is the advisory/enforce decision; THIS is the
# mechanical guarantee. In enforce mode the sample never executes unless the
# marker was present and is now consumed.
def _exec_site_gate(kind: str, sha: str, meta: dict) -> bool:
    marker = Path(os.environ.get(
        "WINRE_SNAPSHOT_MARKER", r"C:\WinRE\.clean_snapshot"))
    gmode = os.environ.get("WINRE_SNAPSHOT_GATE", "observe").strip().lower()
    if gmode not in ("observe", "enforce"):
        gmode = "observe"
    meta["gate_mode"] = gmode
    if gmode == "off":
        meta["gate"] = "off"
        return True
    if marker.exists():
        try:
            marker.unlink()
            consumed = True
        except Exception:
            consumed = False
    else:
        consumed = False
    meta["gate_marker_consumed"] = consumed
    if gmode == "enforce" and not consumed:
        meta["error"] = ("snapshot gate: clean marker absent — restore the "
                         "VM snapshot before executing")
        return False
    # ledger (best-effort): logs/_vm_state.json next to the packs
    try:
        led = LOGS_DIR / "_vm_state.json"
        led.write_text(json.dumps({
            "last_action": "detonated" if kind == "dynamic" else "debugged",
            "ts": _utc(), "sha": sha, "detail": "execution-site consume",
            "gate_mode": gmode}, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass
    return True


def _static_pre_scan(sample: Path, dyn_dir: Path, meta: dict) -> None:
    """Cheap Malcat triage before Frida spawn. Writes malcat-triage.json.
    Never raises — Malcat failure is non-fatal.
    """
    try:
        from tools.malcat_win import canary  # type: ignore
    except Exception:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from tools.malcat_win import canary  # type: ignore
        except Exception as e:
            meta["malcat_skipped"] = f"wrapper missing: {e}"
            return
    try:
        t0 = time.time()
        result = canary(sample)
        result["elapsed_s"] = round(time.time() - t0, 1)
        (dyn_dir / "malcat-triage.json").write_text(
            json.dumps(result, indent=2, default=str), encoding="utf-8"
        )
        meta["malcat_triage"] = {
            "ok": result.get("ok", False),
            "analysis_id": result.get("analysis_id"),
            "yara_count": len(result.get("views", {}).get("yara_hits", [])),
            "anomalies_count": len(result.get("views", {}).get("anomalies", [])),
            "imports_count": len(result.get("views", {}).get("imports", [])),
        }
        meta["artifacts"]["malcat-triage.json"] = str(dyn_dir / "malcat-triage.json")
        if not result.get("ok"):
            meta["malcat_triage"]["error"] = result.get("error")
    except Exception as e:
        meta["malcat_triage"] = {"ok": False, "error": str(e)}


def _x64dbg_oep_dump(sample: Path, dyn_dir: Path, meta: dict) -> None:
    """Best-effort x64dbg OEP detect + dump. MCP-down is non-fatal."""
    if os.environ.get("REVENG_DYNAMIC_X64DBG", "1") in ("0", "false", "no"):
        meta["x64dbg_mcp_skipped"] = "REVENG_DYNAMIC_X64DBG=0"
        return
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from winre.mcp import X64DbgClient  # type: ignore
    except Exception as e:
        meta["x64dbg_mcp_skipped"] = f"client import: {e}"
        return
    cli = X64DbgClient()
    if not cli.is_up():
        meta["x64dbg_mcp_unreachable"] = True
        return
    try:
        load_out = cli.load_binary(str(sample))
        if not load_out.get("ok"):
            meta["x64dbg_load_error"] = load_out.get("error")
            return
        # module name is sample stem
        module = sample.stem
        analyze = cli.analyze_module(module)
        detect = cli.detect_oep(module)
        oep = None
        if detect.get("ok"):
            r = detect.get("result") or {}
            if isinstance(r, dict):
                oep = r.get("oep") or r.get("OEP")
        dump_dir = dyn_dir / "x64dbg" / "dump"
        dump_dir.mkdir(parents=True, exist_ok=True)
        dump_path = dump_dir / f"{sample.stem}.dmp"
        dump = cli.dump_module(module, str(dump_path))
        meta["x64dbg_mcp"] = {
            "loaded": True,
            "module": module,
            "oep": oep,
            "analyze_ok": analyze.get("ok"),
            "detect_ok": detect.get("ok"),
            "dump_ok": dump.get("ok"),
            "dump_path": str(dump_path) if dump.get("ok") else None,
        }
        if dump.get("ok") and dump_path.is_file():
            meta["artifacts"]["x64dbg/dump/"] = str(dump_dir)
    except Exception as e:
        meta["x64dbg_mcp_error"] = str(e)
    finally:
        # neat closure: stop the debuggee and close the x64dbg GUI — the
        # local-mode post-detonation dump must not leave a halted sample
        # inside a live debugger. WINRE_KEEP_DEBUGGER=1 preserves it.
        if os.environ.get("WINRE_KEEP_DEBUGGER", "").strip().lower() not in \
                ("1", "true", "yes"):
            try:
                cli.stop_debug()
            except Exception:
                pass
            try:
                cli.exit_gui()
            except Exception:
                pass
            subprocess.run(["taskkill", "/F", "/IM", "x64dbg.exe", "/T"],
                           capture_output=True, timeout=30)


def _kill_stale_local() -> None:
    """Local-mode orphan sweep (orchestrator RUNS ON THE VM — direct
    taskkill, no SSH). Mirrors the job's Kill-Stale so a timed-out or
    crashed job cannot leave the sample/Frida/FakeNet/Procmon running."""
    for im in STALE_IMAGES:
        try:
            subprocess.run(["taskkill", "/F", "/IM", im, "/T"],
                           capture_output=True, timeout=30)
        except Exception:
            pass


def _run_local_windows(sha: str, sample: Path, dyn_dir: Path,
                       max_seconds: int, apis: str,
                       enable_pesieve: bool, meta: dict) -> dict:
    """Run flare_dynamic_job.ps1 on the local host (no SSH)."""
    if not LOCAL_JOB_PS1.is_file():
        meta["error"] = f"job ps1 missing: {LOCAL_JOB_PS1}"
        meta["ok"] = False
        return meta
    work_root = Path(os.environ.get("FLARE_LOCAL_WORK_ROOT",
                                    rf"C:\WinRE\local-runs\{sha}"))
    (work_root / "out").mkdir(parents=True, exist_ok=True)
    job_args = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(LOCAL_JOB_PS1),
        "-Sha256", sha,
        "-SamplePath", str(sample),
        "-WorkRoot", str(work_root),
        "-MaxSeconds", str(int(max_seconds)),
        "-Apis", apis,
    ]
    if enable_pesieve:
        job_args.append("-EnablePeSieve")
    print(f"[dynamic_run_v2] LOCAL powershell job -> {LOCAL_JOB_PS1}", flush=True)
    timed_out = False
    try:
        cp = subprocess.run(job_args, capture_output=True, text=True,
                            timeout=int(max_seconds) + 300,
                            encoding="utf-8", errors="replace")
        meta["job_rc"] = cp.returncode
        meta["job_stdout_tail"] = (cp.stdout or "")[-800:]
        meta["job_stderr_tail"] = (cp.stderr or "")[-800:]
    except subprocess.TimeoutExpired as te:
        meta["job_timeout"] = True
        meta["error"] = f"local powershell timeout: {te}"
        meta["ok"] = False
        timed_out = True
        # python killed only the powershell child — Frida/sample/FakeNet/
        # Procmon (grandchildren) survive. Sweep them NOW; never leave a
        # sample running independently of the pipeline.
        _kill_stale_local()

    # Pull artifacts from <work_root>\out into dyn_dir (also on timeout —
    # a nearly-complete pack is evidence, not trash)
    out_dir = work_root / "out"
    if out_dir.is_dir():
        for src in out_dir.rglob("*"):
            if not src.is_file():
                continue
            rel = src.relative_to(out_dir)
            dst = dyn_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() and dst.stat().st_size == src.stat().st_size:
                continue
            try:
                shutil.copy2(src, dst)
            except Exception:
                pass

    # Canonical artifact index (same as SSH path)
    for name in (
        "frida_trace.json", "frida_summary.json",
        "procmon.csv", "procmon_summary.json",
        "network.json", "network_intel.json",
        "process_snapshot.json", "META.job.json", "job.log",
        "ANALYST-NEXT.md", "analyst_next.json", "malcat-triage.json",
    ):
        p = dyn_dir / name
        if p.exists():
            meta["artifacts"][name] = str(p)

    mem_dir = dyn_dir / "memory"
    if mem_dir.is_dir():
        mem_files = [p for p in mem_dir.rglob("*") if p.is_file()]
        meta["artifacts"]["memory/"] = str(mem_dir)
        meta["memory_file_count"] = len(mem_files)
        meta["pe_sieve_artifacts"] = bool(mem_files)
    else:
        meta["memory_file_count"] = 0
        meta["pe_sieve_artifacts"] = False

    job_meta_path = dyn_dir / "META.job.json"
    if job_meta_path.is_file():
        try:
            jm = json.loads(job_meta_path.read_text(encoding="utf-8-sig"))
            meta["pe_sieve_ran"] = bool(jm.get("pe_sieve_ran"))
            meta["pe_sieve_pid"] = jm.get("pe_sieve_pid")
            meta["pe_sieve_rc"] = jm.get("pe_sieve_rc")
        except Exception:
            pass

    trace = dyn_dir / "frida_trace.json"
    if not trace.is_file():
        trace = dyn_dir / "frida_trace.jsonl"
    if trace.is_file():
        try:
            meta["frida_events"] = sum(
                1 for ln in trace.open("r", encoding="utf-8", errors="replace") if ln.strip()
            )
        except Exception:
            meta["frida_events"] = 0

    has_core = bool(meta.get("frida_events")) or (dyn_dir / "procmon.csv").is_file()
    meta["ok"] = has_core
    if not meta["ok"] and not meta.get("error"):
        meta["error"] = f"incomplete local pack job_rc={meta.get('job_rc')}"
    # final local sweep: the job cleaned its own children; this catches any
    # survivor (hung helper, resumed sample) — nothing outlives the pipeline
    _kill_stale_local()
    return meta


def run_dynamic(
    sha: str,
    *,
    max_seconds: int = 60,
    dry_run: bool = False,
    apis: str | None = None,
    deploy_tools: bool = True,
    enable_pesieve: bool | None = None,
    mode: str | None = None,
    force: bool = False,
    sample_override: str | None = None,
) -> dict:
    cfg = _flare_cfg()
    dyn_dir = LOGS_DIR / sha / "dynamic"
    dyn_dir.mkdir(parents=True, exist_ok=True)
    yara_lock = _yara_lock(sha)
    if enable_pesieve is None:
        enable_pesieve = _env_truthy("REVENG_DYNAMIC_PESIEVE")
    if mode is None:
        mode = os.environ.get("WINRE_ORCHESTRATOR_MODE", "ssh")

    meta: dict = {
        "schema_version": SCHEMA_VERSION,
        "sha256": sha,
        "started_at": _utc(),
        "flare_host": cfg["host"],
        "ok": False,
        "skipped": False,
        "error": None,
        "yara_lock": yara_lock,
        "snapshot_restore_required": True,
        "artifacts": {},
        "network_mode": "fakenet_on_flare" if mode == "ssh" else "fakenet_local",
        "pe_sieve_requested": bool(enable_pesieve),
        "orchestrator_mode": mode,
    }

    if _env_truthy("REVENG_DYNAMIC_SKIP"):
        meta["skipped"] = True
        meta["ok"] = True
        meta["error"] = "REVENG_DYNAMIC_SKIP=1"
        meta["finished_at"] = _utc()
        _write_meta(dyn_dir, meta)
        print(f"[dynamic_run_v2] skipped REVENG_DYNAMIC_SKIP -> {dyn_dir}", flush=True)
        return meta

    try:
        session = load_session(sha)
    except Exception as e:
        # Session fallback: sha-only invocation with an explicit --sample
        # (or a session file lost on the VM). Repair the session instead of
        # dying — the caller told us where the sample lives.
        if sample_override and Path(sample_override).is_file():
            try:
                SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
                (SESSIONS_DIR / f"{sha}.json").write_text(json.dumps({
                    "sha256": sha,
                    "sample_path": str(sample_override),
                    "file_type": {"format": "pe"},
                }), encoding="utf-8")
                meta["session_repaired"] = str(sample_override)
                session = load_session(sha)
            except Exception as e2:
                meta["error"] = f"session repair failed: {e2}"
                meta["finished_at"] = _utc()
                _write_meta(dyn_dir, meta)
                return meta
        else:
            meta["error"] = (f"session load failed: {e} — pass --sample "
                             f"<path> to repair")
            meta["finished_at"] = _utc()
            _write_meta(dyn_dir, meta)
            return meta

    sample = session.get("sample_path") or ""
    if not sample or not Path(sample).is_file():
        meta["error"] = f"sample missing: {sample!r}"
        meta["finished_at"] = _utc()
        _write_meta(dyn_dir, meta)
        return meta

    fmt = _sample_format(session, sample)
    meta["file_format"] = fmt

    # Documents: no dynamic detonation — triage is intake-side
    if fmt in ("pdf", "ole", "ooxml"):
        meta["skipped"] = True
        meta["ok"] = True
        meta["error"] = "document_sample_use_doc_triage_not_dynamic"
        meta["platform"] = "document"
        meta["snapshot_restore_required"] = False
        meta["finished_at"] = _utc()
        _write_meta(dyn_dir, meta)
        # still emit analyst next pointing at doc_triage
        try:
            _post_pull_enrich(dyn_dir, sha)
        except Exception:
            pass
        print(f"[dynamic_run_v2] skip dynamic for document fmt={fmt}", flush=True)
        return meta

    if dry_run:
        meta["ok"] = True
        meta["skipped"] = True
        meta["error"] = "dry_run"
        meta["plan"] = {
            "sample": sample,
            "format": fmt,
            "worker": "remnux-elf" if fmt == "elf" else "flare-windows",
            "max_seconds": max_seconds,
            "pe_sieve": bool(enable_pesieve),
        }
        meta["finished_at"] = _utc()
        # Do not clobber a real prior META.json — write a sidecar
        dry_path = dyn_dir / "META.dry_run.json"
        dry_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        if not (dyn_dir / "META.json").is_file():
            _write_meta(dyn_dir, meta)
        print(f"[dynamic_run_v2] dry_run ok -> {dry_path}", flush=True)
        return meta

    t0 = time.time()

    # --- Local mode: run on Flare directly, no SSH hop ---
    if mode == "local" and fmt in ("pe",):
        if not _acquire_lock(force=force):
            meta["error"] = (f"orchestrator lock held: {LOCK_PATH} "
                             f"(writer pid={_lock_pid()}; --force to break)")
            meta["ok"] = False
            meta["elapsed_s"] = round(time.time() - t0, 1)
            meta["finished_at"] = _utc()
            _write_meta(dyn_dir, meta)
            return meta
        if force and LOCK_PATH.exists() and _lock_pid() not in (None, os.getpid()):
            meta["lock_forced"] = True
        # execution-site snapshot gate: NO marker consume -> NO execution
        # in enforce mode (see _exec_site_gate). Runs before anything spawns.
        if not _exec_site_gate("dynamic", sha, meta):
            meta["ok"] = False
            meta["elapsed_s"] = round(time.time() - t0, 1)
            meta["finished_at"] = _utc()
            _write_meta(dyn_dir, meta)
            _release_lock()
            print(f"[dynamic_run_v2] GATE BLOCKED: {meta.get('error')}",
                  flush=True)
            return meta
        try:
            # Malcat triage first (per docs/MALCAT.md:5 stage order)
            try:
                _static_pre_scan(Path(sample), dyn_dir, meta)
            except Exception as e:
                meta["malcat_pre_scan_error"] = str(e)
            meta["platform"] = "windows"
            meta["worker"] = "flare-local"
            api_list = apis or DEFAULT_APIS
            try:
                meta = _run_local_windows(sha, Path(sample), dyn_dir,
                                          max_seconds, api_list,
                                          enable_pesieve, meta)
            except Exception as e:
                meta["error"] = str(e)
                meta["ok"] = False
            # x64dbg OEP dump (best-effort, after Frida cleaned up)
            try:
                _x64dbg_oep_dump(Path(sample), dyn_dir, meta)
            except Exception as e:
                meta["x64dbg_post_error"] = str(e)
            meta["elapsed_s"] = round(time.time() - t0, 1)
            meta["post_pull"] = _post_pull_enrich(dyn_dir, sha)
            meta["verdict_policy"] = {
                "static_yara_wins": True,
                "high_signal_yara": yara_lock.get("high_signal") or [],
                "note": "Dynamic corroboration only; cannot clear CADRE_*/family YARA",
            }
            meta["finished_at"] = _utc()
            _write_meta(dyn_dir, meta)
            print(
                f"[dynamic_run_v2] LOCAL ok={meta.get('ok')} events={meta.get('frida_events')} "
                f"err={meta.get('error')} -> {dyn_dir}",
                flush=True,
            )
            return meta
        finally:
            _release_lock()

    # --- ELF: Remnux local ---
    if fmt == "elf":
        try:
            meta = _run_elf_dynamic(sha, sample, dyn_dir, max_seconds, meta)
        except Exception as e:
            meta["error"] = str(e)
            meta["ok"] = False
        meta["elapsed_s"] = round(time.time() - t0, 1)
        meta["post_pull"] = _post_pull_enrich(dyn_dir, sha)
        meta["finished_at"] = _utc()
        # Merge worker META if present
        worker_meta = dyn_dir / "META.json"
        if worker_meta.is_file():
            try:
                wm = json.loads(worker_meta.read_text(encoding="utf-8"))
                meta["worker_meta"] = {k: wm.get(k) for k in ("ok", "exit_code", "platform", "worker")}
            except Exception:
                pass
        _write_meta(dyn_dir, meta)
        print(
            f"[dynamic_run_v2] ELF ok={meta.get('ok')} err={meta.get('error')} -> {dyn_dir}",
            flush=True,
        )
        return meta

    # --- Windows PE / .NET: Flare ---
    meta["platform"] = "windows"
    meta["worker"] = "flare"
    root = str(cfg["remote_root"]).replace("\\", "/").rstrip("/")
    tools = str(cfg["remote_tools"]).replace("\\", "/").rstrip("/")
    remote_dir = f"{root}/{sha}"
    remote_sample = f"{remote_dir}/sample.exe"
    remote_zip = f"{remote_dir}/artifacts.zip"
    remote_dir_win = remote_dir.replace("/", "\\")
    tools_win = tools.replace("/", "\\")
    api_list = apis or DEFAULT_APIS

    try:
        if not Path(cfg["key"]).is_file():
            raise FileNotFoundError(f"FLARE_SSH_KEY not found: {cfg['key']}")

        probe = _ssh_run(cfg, "echo FLARE_OK", timeout=30)
        if probe.returncode != 0 or "FLARE_OK" not in (probe.stdout or ""):
            raise RuntimeError(f"flare ssh probe failed: {probe.stderr[:300]}")

        # Cleanup hung tools (same coverage as the job's Kill-Stale)
        _kill_stale_ssh(cfg)

        _ssh_run(cfg, f'cmd /c "if not exist {remote_dir_win} mkdir {remote_dir_win}"', timeout=60)
        _ssh_run(cfg, f'cmd /c "if not exist {tools_win} mkdir {tools_win}"', timeout=60)

        if deploy_tools:
            for name in ("flare_dynamic_job.ps1", "summarize_dynamic.py"):
                local = _local_tool(name)
                if not local:
                    # also check sibling deploy paths
                    alt = Path("/opt/scripts") / name
                    local = alt if alt.is_file() else None
                if not local:
                    print(f"[dynamic_run_v2] WARN missing local tool {name}", flush=True)
                    continue
                print(f"[dynamic_run_v2] deploy {name}", flush=True)
                _scp_to(cfg, local, f"{tools}/{name}")
            # Keep Frida script with path decode on Flare
            frida_local = Path("/opt/scripts/frida_api_trace.py")
            if not frida_local.is_file():
                frida_local = (
                    Path(__file__).resolve().parents[2]
                    / "flarevm-deploy"
                    / "dynamic"
                    / "frida_api_trace.py"
                )
            if not frida_local.is_file():
                # from Tools/v6_deploy/V6.2/scripts -> Tools/flarevm-deploy
                frida_local = (
                    Path(__file__).resolve().parents[2]
                    / "flarevm-deploy"
                    / "dynamic"
                    / "frida_api_trace.py"
                )
            # parents: scripts->V6.2->v6_deploy->Tools
            if frida_local.is_file():
                _scp_to(
                    cfg,
                    frida_local,
                    "C:/Tools/flarevm-deploy/dynamic/frida_api_trace.py",
                )

        print(f"[dynamic_run_v2] scp sample -> {remote_sample}", flush=True)
        _scp_to(cfg, Path(sample), remote_sample)

        job_win = cfg["job_ps1"]
        # Prefer deployed tools copy
        job_win = f"{tools_win}\\flare_dynamic_job.ps1"
        pesieve_flag = " -EnablePeSieve" if enable_pesieve else ""
        ps = (
            f'powershell -NoProfile -ExecutionPolicy Bypass -File "{job_win}" '
            f'-Sha256 "{sha}" -SamplePath "{remote_dir_win}\\sample.exe" '
            f'-MaxSeconds {int(max_seconds)} '
            f'-Apis "{api_list}"'
            f"{pesieve_flag}"
        )
        print(f"[dynamic_run_v2] job max_seconds={max_seconds}", flush=True)
        ssh_budget = int(max_seconds) + 300  # FakeNet/Procmon/CSV export overhead
        try:
            jr = _ssh_run(cfg, ps, timeout=ssh_budget)
        except subprocess.TimeoutExpired as te:
            meta["job_timeout"] = True
            meta["job_rc"] = -1
            meta["job_stderr_tail"] = f"ssh timeout after {ssh_budget}s: {te}"
            jr = subprocess.CompletedProcess(args=[], returncode=-1, stdout="", stderr=str(te))
            _kill_stale_ssh(cfg)

        meta["job_rc"] = jr.returncode
        meta["job_stdout_tail"] = (jr.stdout or "")[-800:]
        meta["job_stderr_tail"] = (jr.stderr or "")[-800:]

        local_zip = dyn_dir / "artifacts.zip"
        try:
            _scp_from(cfg, remote_zip, local_zip)
            meta["artifacts"]["artifacts.zip"] = str(local_zip)
            with zipfile.ZipFile(local_zip, "r") as zf:
                for info in zf.infolist():
                    # Windows Compress-Archive may use backslash names
                    name = info.filename.replace("\\", "/").lstrip("/")
                    if not name or name.endswith("/"):
                        continue
                    target = dyn_dir / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
            meta["unzipped"] = True
        except Exception as e:
            meta["zip_pull_error"] = str(e)
            meta["unzipped"] = False

        # Canonical artifact index
        for name in (
            "frida_trace.json",
            "frida_summary.json",
            "procmon.csv",
            "procmon_summary.json",
            "network.json",
            "network_intel.json",
            "process_snapshot.json",
            "META.job.json",
            "job.log",
            "ANALYST-NEXT.md",
            "analyst_next.json",
        ):
            p = dyn_dir / name
            if p.exists():
                meta["artifacts"][name] = str(p)

        mem_dir = dyn_dir / "memory"
        if mem_dir.is_dir():
            mem_files = [p for p in mem_dir.rglob("*") if p.is_file()]
            meta["artifacts"]["memory/"] = str(mem_dir)
            meta["memory_file_count"] = len(mem_files)
            meta["pe_sieve_artifacts"] = bool(mem_files)
        else:
            meta["memory_file_count"] = 0
            meta["pe_sieve_artifacts"] = False

        job_meta_path = dyn_dir / "META.job.json"
        if job_meta_path.is_file():
            try:
                job_meta = json.loads(
                    job_meta_path.read_text(encoding="utf-8-sig")
                )
                meta["pe_sieve_ran"] = bool(job_meta.get("pe_sieve_ran"))
                meta["pe_sieve_pid"] = job_meta.get("pe_sieve_pid")
                meta["pe_sieve_rc"] = job_meta.get("pe_sieve_rc")
            except Exception:
                pass

        # frida event count
        trace = dyn_dir / "frida_trace.json"
        if not trace.is_file():
            trace = dyn_dir / "frida_trace.jsonl"
        if trace.is_file():
            try:
                meta["frida_events"] = sum(
                    1 for ln in trace.open("r", encoding="utf-8", errors="replace") if ln.strip()
                )
            except Exception:
                meta["frida_events"] = 0

        meta["verdict_policy"] = {
            "static_yara_wins": True,
            "high_signal_yara": yara_lock.get("high_signal") or [],
            "note": "Dynamic corroboration only; cannot clear CADRE_*/family YARA",
        }
        # Success = artifacts landed (Frida and/or Procmon). SSH timeout after job
        # finished must not fail a complete pack.
        has_core = bool(meta.get("frida_events")) or (dyn_dir / "procmon.csv").is_file()
        meta["ok"] = bool(meta.get("unzipped")) and has_core
        if not meta["ok"] and not meta.get("error"):
            meta["error"] = f"incomplete pack job_rc={jr.returncode} timeout={meta.get('job_timeout')}"
        meta["elapsed_s"] = round(time.time() - t0, 1)

        # Best-effort remote wipe of sample dir contents (keep structure)
        _ssh_run(
            cfg,
            f'cmd /c "del /q {remote_dir_win}\\sample.exe 2>nul & exit /b 0"',
            timeout=30,
        )
    except Exception as e:
        meta["error"] = str(e)
        meta["ok"] = False
        meta["elapsed_s"] = round(time.time() - t0, 1)
        (dyn_dir / "network.json").write_text(
            json.dumps({"status": "not_collected", "reason": f"run_failed:{e}"}, indent=2),
            encoding="utf-8",
        )

    meta["post_pull"] = _post_pull_enrich(dyn_dir, sha)
    meta["finished_at"] = _utc()
    _write_meta(dyn_dir, meta)
    print(
        f"[dynamic_run_v2] ok={meta['ok']} events={meta.get('frida_events')} "
        f"err={meta.get('error')} -> {dyn_dir}",
        flush=True,
    )
    return meta


def main() -> int:
    import hashlib

    ap = argparse.ArgumentParser(description="V6.2 Flare dynamic detonation (Remnux orchestrator)")
    ap.add_argument("sample_or_sha",
                    help="64-hex sha256 (session lookup) OR a path to the sample")
    ap.add_argument("--sample", default=None,
                    help="explicit sample path (repairs a missing session)")
    ap.add_argument("--max-seconds", type=int, default=60)
    ap.add_argument("--apis", default=None, help="comma-separated API list override")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-deploy", action="store_true", help="skip SCP of job scripts (SSH mode only)")
    ap.add_argument("--force", action="store_true",
                    help="break a held orchestrator lock (operator override)")
    ap.add_argument(
        "--pesieve",
        action="store_true",
        help="run pe-sieve mid-detonation (same as REVENG_DYNAMIC_PESIEVE=1)",
    )
    ap.add_argument(
        "--mode",
        choices=["ssh", "local"],
        default=os.environ.get("WINRE_ORCHESTRATOR_MODE", "ssh"),
        help="ssh = Remnux to Flare via SSH (legacy); local = run on Flare (recommended)",
    )
    args = ap.parse_args()

    arg = args.sample_or_sha.strip()
    sample_override = args.sample
    if len(arg) == 64 and all(c in "0123456789abcdefABCDEF" for c in arg):
        sha = arg.lower()
    elif Path(arg).is_file():
        # path given positionally — compute sha, align --sample
        p = Path(arg).resolve()
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        sha = h.hexdigest()
        sample_override = str(p)
    else:
        print(f"ERROR: {arg!r} is neither 64-hex sha256 nor an existing file",
              file=sys.stderr)
        return 2
    if sample_override and not Path(sample_override).is_file():
        print(f"ERROR: --sample not found: {sample_override}", file=sys.stderr)
        return 2

    meta = run_dynamic(
        sha,
        max_seconds=args.max_seconds,
        dry_run=args.dry_run,
        apis=args.apis,
        deploy_tools=not args.no_deploy,
        enable_pesieve=True if args.pesieve else None,
        mode=args.mode,
        force=args.force,
        sample_override=sample_override,
    )
    if meta.get("skipped") or meta.get("ok"):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
