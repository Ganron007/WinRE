#!/usr/bin/env python3
r"""remote_driver.py — control-plane driver for WinRE (FlareVM execution plane).

WinRE split (see docs/ARCHITECTURE.md):
    CONTROL PLANE (this host — internet, LLM, UI):
        - runs pipeline.py with --driver remote
        - LLM endpoint (WINRE_LLM_BASE_URL), web UI, LangGraph deep-dive agent
    EXECUTION PLANE (FlareVM — NO internet, host-only NIC):
        - tools: Ghidra/IDA/Malcat/x64dbg/WinDbg/Frida/Procmon/FakeNet
        - MCP servers: x64dbg :9094 · Malcat :9009 · WinDbg :9097 · IDA :19300 · Ghidra :19301
        - detonation job (survives SSH drop; artifacts pulled via SCP)

The driver reuses the pipeline's evidence pack + audit, but the tool calls
become remote:
    - static SQL   : ssh flare "python flare_ghidra_sql.py ..." (or HTTP :19301)
    - dynamic      : ssh flare "python orchestrator.py --mode local ..." then
                     scp the dynamic pack back (REVENG_LOGS_DIR on VM)
    - MCP deep     : HTTP to <flare>:9094/9009/9097 from this host (lab net)
    - LLM          : local endpoint on this host

Env:
    FLARE_HOST / FLARE_USER / FLARE_SSH_KEY / FLARE_SSH_PORT   (SSH to VM)
    WINRE_LLM_BASE_URL / WINRE_LLM_API_KEY / WINRE_LLM_MODEL   (LLM here)
    WINRE_REMOTE_LOGS=logs   (local evidence root; pulled from VM)
    WINRE_REMOTE_PIPELINE=C:\WinRE   (repo path on the VM)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .envfile import load_dotenv  # noqa: F401  (ensures .env is loaded)
from .evidence import (EvidencePack, stage_result, verdict_fields
                       as _verdict_fields, write_execution_plan,
                       archive_stage_for_fresh_run)
from . import run_nonce
from .run_nonce import new_run_id
from .mcp.x64dbg_client import X64DbgClient
from . import findings as _findings  # host-side analysis plane; no VM tools

REPO = Path(__file__).resolve().parents[1]
from .paths import evidence_root as _evidence_root
LOCAL_LOGS = _evidence_root()


def flare_cfg() -> dict:
    """Execution-plane connection config. All values from env/.env —
    no lab defaults in code (see .env.template for the full block)."""
    return {
        "host": os.environ.get("FLARE_HOST", ""),
        "user": os.environ.get("FLARE_USER", "FLARE-VM"),
        "key": os.environ.get("FLARE_SSH_KEY",
                              str(Path.home() / ".ssh" / "id_ed25519")),
        "port": int(os.environ.get("FLARE_SSH_PORT", "22")),
        "remote_pipeline": os.environ.get("WINRE_REMOTE_PIPELINE", r"C:\WinRE"),
    }


def _dynamic_status_label(result: dict | None) -> str:
    """Describe whether a requested detonation ran, even when it failed."""
    if not isinstance(result, dict):
        return "not-requested"
    if result.get("ok"):
        return "ok"
    if result.get("detonation_ran") is True:
        return "failed-after-start"
    return "not-run"


def _ssh_base(cfg: dict) -> list[str]:
    return [
        "ssh", "-i", cfg["key"], "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
        "-p", str(cfg["port"]),
        f"{cfg['user']}@{cfg['host']}",
    ]


def ssh_run(cfg: dict, remote_cmd: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run a command on the FlareVM (quoted as ONE remote command string)."""
    return subprocess.run(_ssh_base(cfg) + [remote_cmd], capture_output=True,
                          text=True, timeout=timeout, encoding="utf-8",
                          errors="replace")


def ssh_ps(cfg: dict, script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a PowerShell script on the VM via -EncodedCommand.

    The ONLY reliable way to send non-trivial PowerShell over SSH — inline
    -Command strings get mangled by the cmd→ssh nesting ($, @, quotes).
    """
    import base64
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return ssh_run(cfg, f"powershell -NoProfile -EncodedCommand {enc}",
                   timeout=timeout)


def scp_to(cfg: dict, local: Path, remote: str) -> None:
    cmd = ["scp", "-i", cfg["key"], "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=15", "-P", str(cfg["port"]),
           str(local), f"{cfg['user']}@{cfg['host']}:{remote}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"scp to flare failed: {r.stderr[:300]}")


def scp_from(cfg: dict, remote: str, local: Path,
             *, recursive: bool = False) -> None:
    # scp remote paths MUST use forward slashes: Windows OpenSSH accepts
    # them, but a Linux scp client (e.g. RevAI on .43) mangles backslashes
    # in the remote path -> "No such file or directory". Normalize here so
    # every download call site is safe (uploads are left as-is).
    remote = remote.replace("\\", "/")
    cmd = ["scp", "-i", cfg["key"], "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=15", "-P", str(cfg["port"])]
    if recursive:
        cmd.append("-r")
    cmd += [f"{cfg['user']}@{cfg['host']}:{remote}", str(local)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise RuntimeError(f"scp from flare failed: {r.stderr[:300]}")


def remote_sha256(cfg: dict, remote_path: str) -> str:
    """Read a remote file's SHA-256 without transferring its contents."""
    escaped = remote_path.replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$p='{escaped}'; "
        "if (-not (Test-Path -LiteralPath $p -PathType Leaf)) "
        "{ throw 'staged sample is missing' }; "
        "(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash"
    )
    result = ssh_ps(cfg, script, timeout=90)
    if result.returncode != 0:
        raise RuntimeError("remote SHA-256 failed: "
                           + (result.stderr or result.stdout or "unknown error")[:240])
    hashes = re.findall(r"(?i)\b[0-9a-f]{64}\b", result.stdout or "")
    if not hashes:
        raise RuntimeError("remote SHA-256 returned no valid digest")
    return hashes[-1].lower()


def remote_file_inventory(cfg: dict, remote_dir: str) -> dict[str, tuple[int, str]]:
    """Inventory a finished producer directory by relative path, size and hash."""
    root = remote_dir.replace("/", "\\").replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$root=(Resolve-Path -LiteralPath '{root}').Path.TrimEnd('\\'); "
        "$rows=@(Get-ChildItem -LiteralPath $root -File -Recurse -Force | "
        "ForEach-Object { "
        "if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) "
        "{ throw ('reparse point is not accepted: ' + $_.FullName) }; "
        "$rel=$_.FullName.Substring($root.Length).TrimStart('\\').Replace('\\','/'); "
        "$h=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); "
        "[pscustomobject]@{path=$rel;size_bytes=[int64]$_.Length;sha256=$h} }); "
        "ConvertTo-Json -InputObject $rows -Depth 4 -Compress"
    )
    result = ssh_ps(cfg, script, timeout=900)
    if result.returncode != 0:
        raise RuntimeError("remote inventory failed: "
                           + (result.stderr or result.stdout or "unknown error")[:240])
    try:
        rows = json.loads((result.stdout or "").strip())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"remote inventory was not JSON: {e}") from e
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise RuntimeError("remote inventory has an invalid shape")
    inventory: dict[str, tuple[int, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("remote inventory contains an invalid entry")
        rel = str(row.get("path") or "").replace("\\", "/")
        digest = str(row.get("sha256") or "").lower()
        if (not rel or rel.startswith("/") or ".." in rel.split("/")
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or rel in inventory):
            raise RuntimeError("remote inventory contains an unsafe or duplicate entry")
        inventory[rel] = (int(row.get("size_bytes") or -1), digest)
    return inventory


def local_file_inventory(root: Path) -> dict[str, tuple[int, str]]:
    """Hash every regular file in an incoming directory without following links."""
    from .evidence import sha256_file

    inventory: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"incoming transfer contains a symbolic link: {path}")
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        inventory[rel] = (path.stat().st_size, sha256_file(path))
    return inventory


def _inventory_diff(remote: dict[str, tuple[int, str]],
                    received: dict[str, tuple[int, str]],
                    *, limit: int = 20) -> dict:
    """Explain which relative paths failed the remote-to-host hash check."""
    remote_paths, received_paths = set(remote), set(received)
    missing = sorted(remote_paths - received_paths)
    unexpected = sorted(received_paths - remote_paths)
    mismatched = sorted(
        path for path in remote_paths & received_paths
        if remote[path] != received[path])
    return {
        "missing_local_count": len(missing),
        "unexpected_local_count": len(unexpected),
        "content_mismatch_count": len(mismatched),
        "missing_local": missing[:limit],
        "unexpected_local": unexpected[:limit],
        "content_mismatch": mismatched[:limit],
        "truncated": any(len(items) > limit
                          for items in (missing, unexpected, mismatched)),
    }


def _remote_staging_destination(sample: Path, sha: str, run_id: str) -> str:
    suffix = sample.suffix.lower()
    if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
        suffix = ".bin"
    return f"C:/samples/winre/{sha.lower()}/{run_id.lower()}/sample{suffix}"


def stage_remote_sample(cfg: dict, sample: Path, sha: str,
                        run_id: str) -> dict:
    """Copy a sample to a unique remote path and prove the bytes match.

    A failed or partial copy is left in its unique run directory for diagnosis;
    callers must stop before invoking any analysis or execution tool.
    """
    from .evidence import sha256_file

    if not re.fullmatch(r"(?i)[0-9a-f]{64}", str(sha or "")):
        raise ValueError("expected sample SHA-256 is invalid")
    if not re.fullmatch(r"(?i)[0-9a-f]{32}", str(run_id or "")):
        raise ValueError("run ID is invalid")
    expected = sha.lower()
    local_before = sha256_file(sample)
    if local_before != expected:
        raise RuntimeError("local sample changed after run identity was computed")

    remote_path = _remote_staging_destination(sample, expected, run_id)
    remote_dir = remote_path.rsplit("/", 1)[0]
    escaped_dir = remote_dir.replace("'", "''")
    escaped_path = remote_path.replace("'", "''")
    ready = ssh_ps(
        cfg,
        "$ErrorActionPreference='Stop'; "
        f"$d='{escaped_dir}'; $p='{escaped_path}'; "
        "New-Item -ItemType Directory -Force -Path $d | Out-Null; "
        "if (Test-Path -LiteralPath $p) { throw 'run staging destination exists' }; "
        "'STAGING_READY'",
        timeout=90,
    )
    if ready.returncode != 0 or "STAGING_READY" not in (ready.stdout or ""):
        raise RuntimeError("remote staging directory could not be prepared: "
                           + (ready.stderr or ready.stdout or "unknown error")[:240])

    scp_to(cfg, sample, remote_path)
    remote_hash = remote_sha256(cfg, remote_path)
    local_after = sha256_file(sample)
    if local_after != expected:
        raise RuntimeError("local sample changed while it was being uploaded")
    if remote_hash != expected:
        raise RuntimeError(f"remote sample hash mismatch: expected {expected}, "
                           f"received {remote_hash}")
    return {
        "schema": "winre.remote-staging/v1",
        "ok": True,
        "run_id": run_id.lower(),
        "sha256": expected,
        "remote_sha256": remote_hash,
        "remote_path": remote_path,
        "original_name": sample.name,
        "bytes": sample.stat().st_size,
    }


def _verified_remote_sample(pack: EvidencePack, sample_name: str,
                            cfg: dict, *, supplied_path: str | None = None,
                            expected_sha: str | None = None) -> str:
    """Resolve the run's staged sample and verify its identity before use."""
    expected = (expected_sha or pack.sha or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("analysis refused: evidence pack has no valid sample SHA-256")

    remote_path = supplied_path
    if remote_path is None:
        staged = pack.read("intake", "REMOTE-STAGING.json") or {}
        if (staged.get("schema") == "winre.remote-staging/v1"
                and staged.get("ok") is True
                and str(staged.get("sha256") or "").lower() == expected
                and staged.get("original_name") == sample_name):
            candidate = str(staged.get("remote_path") or "")
            normalized = candidate.replace("/", "\\")
            required_prefix = f"C:\\samples\\winre\\{expected}\\"
            tail = normalized[len(required_prefix):] if normalized.lower().startswith(
                required_prefix.lower()) else ""
            if (tail and re.fullmatch(r"[0-9a-f]{32}\\sample\.[a-z0-9]{1,10}",
                                      tail, flags=re.IGNORECASE)):
                remote_path = normalized
        # Legacy/manual-stage fallback remains safe only because its bytes are
        # checked against this pack's SHA before any tool is called.
        if remote_path is None:
            remote_path = rf"C:\samples\{sample_name}"

    remote_hash = remote_sha256(cfg, remote_path)
    if remote_hash != expected:
        raise RuntimeError(f"analysis refused: remote sample identity mismatch "
                           f"(expected {expected}, received {remote_hash})")
    return remote_path


def _remote_staging_abort(pack: EvidencePack, sha: str, run_id: str,
                          error: str, remote_path: str | None = None) -> dict:
    """Make a rejected staging attempt visible and non-green in its pack."""
    message = f"sample staging rejected: {str(error)[:240]}"
    staging = {
        "schema": "winre.remote-staging/v1", "ok": False,
        "run_id": run_id, "sha256": sha, "remote_path": remote_path,
        "error": message, "recorded_at": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    pack.write("intake", "REMOTE-STAGING.json", staging)
    pack.write("intake", "META.json", stage_result(
        "intake", False, error=message, summary="remote sample identity not established"))
    audit = {
        "truly_green": False, "all_green": False, "quality_green": False,
        "aborted": True, "aborted_reason": message,
        "checks": [], "fallback_stages": [], "failed_tools": [],
        "unmet_expectations": [message], "dynamic_conflict": False,
        "dynamic_blocked": False, "static_yara_wins": True,
        "static_verdict": None, "deep_verdict": None,
        "deep_verdict_source": None, "llm_roles": None,
        "dynamic_verdict": None,
        "staging": {"ok": False, "run_id": run_id, "sha256": sha,
                    "remote_path": remote_path},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (pack.root / "audit.json").write_text(
        json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    (pack.root / "META.json").write_text(json.dumps({
        "sha256": sha, "mode": pack.mode, "pack_mode": pack.mode,
        "run_id": run_id, "aborted": True, "truly_green": False,
        "error": message,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2) + "\n", encoding="utf-8")
    return {"sha": sha, "pack_mode": pack.mode,
            "results": {"staging": staging, "audit": audit},
            "aborted": True, "error": message}


def _remote_py(cfg: dict) -> str:
    """Path of the repo's python on the VM (C:\\Python313 preferred)."""
    for cand in (r"C:\Python313\python.exe", r"C:\ProgramData\chocolatey\bin\python.exe"):
        if cand:  # probed lazily per call; first is standard on FlareVM
            return cand
    return "python"


# ---------------------------------------------------------------------------
# Remote helper (runs ON the VM via scp — avoids nested-quote breakage)
# ---------------------------------------------------------------------------
REMOTE_QUICK_HELPER = r'''
"""Remote quick-triage helper — runs on FlareVM, prints JSON to stdout.

Usage: python _remote_quick_helper.py <sample_path> --json
Output: {"evidence": {ghidra: {...}, ida: {...}, malcat: {...}}}

Malcat triage runs HERE on the VM (localhost :9009) — the commercial tool
is optional: absent/down => honest `skipped` annotation, never a failure.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sample = Path(sys.argv[1])
out = {"ghidra": {}, "ida": {}, "malcat": {}}
py = sys.executable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def run(script, *args, timeout=1800):
    p = subprocess.run([py, str(script), *args], capture_output=True, text=True,
                       timeout=timeout, encoding="utf-8", errors="replace")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": (p.stderr or p.stdout)[-200:]}

tools = Path(__file__).resolve().parents[1] / "tools"
g = run(tools / "flare_ghidra_sql.py", "query", "@funcs", "--file", str(sample), "--json")
if g.get("ok"):
    out["ghidra"] = {"func_rows": len(g.get("rows") or [])}
else:
    out["ghidra"] = {"error": g.get("error")}

g_imp = run(tools / "flare_ghidra_sql.py", "query", "@imports", "--file", str(sample), "--json")
if g_imp.get("ok"):
    rows = g_imp.get("rows") or []
    out["ghidra"]["imports"] = [r[0] for r in rows if r][:20]

# Malcat triage (optional commercial): HTTP MCP on VM-localhost :9009 with
# dedicated view endpoints (the CLI --views path returns empty on this build).
try:
    from tools.malcat_win import MALCAT_BIN_DIR  # type: ignore
    installed = MALCAT_BIN_DIR is not None
except Exception:
    try:
        sys.path.insert(0, str(tools))
        from malcat_win import MALCAT_BIN_DIR  # type: ignore
        installed = MALCAT_BIN_DIR is not None
    except Exception:
        installed = False
if not installed:
    out["malcat"] = {"skipped": "not installed (optional) — Ghidra-primary static path"}
else:
    from winre.mcp import MalcatClient  # noqa: E402
    mc = MalcatClient(default_timeout=180)
    if not mc.is_up():
        out["malcat"] = {"skipped": "server not running on :9009"}
    else:
        def _m(call):
            r = call()
            if not r.get("ok"):
                return {"error": (r.get("error") or "")[:120]}
            res = r.get("result") or {}
            # structuredContent first (view endpoints), then content[].text JSON
            sc = res.get("structuredContent")
            if sc:
                return sc
            txt = ""
            for part in (res.get("content") or []):
                if isinstance(part, dict) and part.get("type") == "text":
                    txt = part.get("text", "")
                    break
            try:
                return json.loads(txt)
            except json.JSONDecodeError:
                return {"raw": txt[:1000]}
        out["malcat"] = {
            "file": _m(lambda: mc.analyse_file(str(sample))),
            "anomalies": _m(lambda: mc.anomalies_list(str(sample))),
            "yara_hits": _m(lambda: mc.yara_list(str(sample))),
            "strings": (_m(lambda: mc.strings_top_list(str(sample), 60))
                        .get("strings") if True else []),
        }

# RevAI-parity static evidence (all free, all tolerant of absence)
try:
    st = run(tools / "flare_static_tools.py", "all", str(sample), timeout=2700)
    if isinstance(st, dict):
        for k in ("capa", "floss", "diec", "yarascan", "strings",
                  "pe_import_signals", "api_hash_resolver", "threat_intel"):
            v = st.get(k)
            if isinstance(v, dict):
                out[k] = v
        pe = st.get("lief")
        if isinstance(pe, dict):
            out["pe"] = pe
except Exception as e:
    out["static_tools_error"] = str(e)[:120]

# threat-intel enrichment: Malcat kesakode + publisher from the file view
try:
    ti = out.get("threat_intel")
    mc_file = ((out.get("malcat") or {}).get("file") or {})
    if isinstance(ti, dict) and isinstance(mc_file, dict):
        ks = mc_file.get("kesakode_verdict")
        if ks is not None:
            ti["kesakode"] = ks
            try:
                import json as _json
                ks_txt = _json.dumps(ks).lower()
                if "hacktool" in ks_txt or "securitytool" in ks_txt \
                        or "security tool" in ks_txt or "toolware" in ks_txt:
                    ti["known_tool"] = True
                    ti.setdefault("reasons", []).append("malcat kesakode: tool tag")
            except Exception:
                pass
        # offline Kesakode (Malcat headless): OEM-only; honest skip otherwise
        try:
            ks2 = run(tools / "flare_static_tools.py", "kesakode_offline",
                      str(sample), timeout=900)
            # the CLI wraps a single-tool payload: {"kesakode_offline": {...}}
            p2 = ks2.get("kesakode_offline") if isinstance(ks2, dict) else None
            if isinstance(p2, dict):
                if p2.get("skipped"):
                    ti["kesakode_offline"] = {"skipped": p2.get("skipped")}
                elif p2.get("ok"):
                    ti["kesakode_offline"] = {
                        "flavor": p2.get("flavor"),
                        "verdict": p2.get("verdict"),
                        "top": p2.get("top"), "matches": p2.get("matches")}
                    if p2.get("top"):
                        ti["known_tool"] = False
                        ti.setdefault("reasons", []).append(
                            "Kesakode: " + ", ".join(p2["top"][:3]))
                elif p2.get("error"):
                    ti["kesakode_offline"] = {"error": p2.get("error")}
        except Exception:
            pass
        md = mc_file.get("metadata")
        if isinstance(md, dict):
            comp = str(md.get("company") or md.get("Company") or "")
            prod = str(md.get("product") or md.get("Product") or "")
            if comp:
                ti["malcat_company"] = comp[:60]
            if prod:
                ti["malcat_product"] = prod[:60]
except Exception:
    pass

i64 = sample.with_suffix(sample.suffix + ".i64")
if i64.is_file():
    i = run(tools / "flarevm_ida_query.py", str(sample), "SELECT count(*) FROM funcs", "--json")
    if i.get("ok"):
        rows = i.get("rows") or []
        out["ida"] = {"func_count": rows[0][0] if rows and rows[0] else None}
    else:
        out["ida"] = {"error": i.get("error")}
else:
    # IDA runs EQUALLY (licensed) — create the .i64 NOW via idat auto-analysis
    # (same as RevAI's intake bridge) so deep's ida_query participates fully.
    i = run(tools / "flarevm_ida_query.py", str(sample), "SELECT count(*) FROM funcs",
            "--json", timeout=1500)
    if i.get("ok"):
        rows = i.get("rows") or []
        out["ida"] = {"func_count": rows[0][0] if rows and rows[0] else None,
                      "i64_created": True}
    else:
        err_txt = i.get("error") or ""
        if "timeout" in err_txt.lower():
            out["ida"] = {"error": err_txt[:120],
                          "note": "idat auto-analysis budget exceeded; .i64 may exist partially"}
        else:
            out["ida"] = {"error": err_txt[:200]}

print(json.dumps({"evidence": out}))
'''


# ---------------------------------------------------------------------------
# Remote stage implementations (control plane)
# ---------------------------------------------------------------------------

def remote_quick(sample_name: str, pack: EvidencePack, cfg: dict, *,
                 remote_sample: str | None = None) -> dict:
    """SSH: run the quick SQL wrappers on the VM via a helper script, pull JSON back.

    Uses a remote helper .py (scp'd) instead of nested inline quoting — the
    nested powershell -Command string mangles @ and quotes over SSH.
    """
    t0 = time.time()
    py = _remote_py(cfg)
    try:
        remote_sample = _verified_remote_sample(
            pack, sample_name, cfg, supplied_path=remote_sample)
    except Exception as e:
        failed = stage_result("quick", False,
                              error=f"staging identity: {str(e)[:220]}")
        pack.write("quick", "quick.json", {"evidence": {}, "verdict": "unknown",
                                           "tool_failures": [failed["error"]]})
        pack.write("quick", "META.json", failed)
        return failed
    ensure_mcp_servers(cfg, only=("malcat",))  # Malcat serves this stage

    # helper script: runs ghidra + ida counts, prints JSON
    helper = REPO / "winre" / "_remote_quick_helper.py"
    helper.write_text(REMOTE_QUICK_HELPER, encoding="utf-8")
    try:
        scp_to(cfg, helper, rf'{cfg["remote_pipeline"]}\winre\_remote_quick_helper.py')
    except Exception as e:
        return {"ok": False, "error": f"scp helper: {e}"}

    cmd = (f'powershell -NoProfile -ExecutionPolicy Bypass -Command "& {py} '
           f'{cfg["remote_pipeline"]}\\winre\\_remote_quick_helper.py '
           f'"{remote_sample}" --json 2>&1"')
    r = ssh_run(cfg, cmd, timeout=2100)
    evidence: dict = {}
    parsed = False
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            evidence = data.get("evidence") or {}
            parsed = True
        except json.JSONDecodeError:
            pass
    if not evidence:
        evidence = {"ghidra": {"error": (r.stderr or r.stdout)[-200:]}}
    # Ghidra function census is this stage's required quick capability. IDA
    # and Malcat are optional cross-checks (IDA may not have a database yet;
    # Malcat is a commercial installation), so their absence/errors remain
    # visible warnings and never inflate the required-failure list.
    gh = evidence.get("ghidra") if isinstance(evidence, dict) else None
    gh_ok = (isinstance(gh, dict) and not gh.get("error")
             and gh.get("func_rows") is not None)
    tool_failures = ([] if gh_ok else [
        f"ghidra:{((gh or {}).get('error') or 'function census missing')[:100]}"
    ])
    warnings = [f"{name}:{(evidence.get(name) or {}).get('error') or
                            (evidence.get(name) or {}).get('skipped')}"
                for name in ("ida", "malcat")
                if isinstance(evidence.get(name), dict)
                and ((evidence[name].get("error") or evidence[name].get("skipped")))]
    ok = bool(parsed and gh_ok)
    quick_census = {
        "schema": "winre-quick-capability-census/v1",
        "required": ["ghidra"],
        "capabilities": [
            {"tool": "ghidra", "required": True,
             "status": "completed" if gh_ok else "failed",
             "reason_code": "completed" if gh_ok else "ghidra_function_census_missing"},
            {"tool": "ida", "required": False,
             "status": "completed" if (evidence.get("ida") or {}).get("func_count") is not None
                      else "unavailable",
             "reason_code": "completed" if (evidence.get("ida") or {}).get("func_count") is not None
                           else "optional_cross_check_unavailable"},
            {"tool": "malcat", "required": False,
             "status": "completed" if (evidence.get("malcat") or {}).get("sha256")
                      else "unavailable",
             "reason_code": "completed" if (evidence.get("malcat") or {}).get("sha256")
                           else "commercial_tool_unavailable"},
        ],
        "required_failures": tool_failures,
        "optional_warnings": warnings,
    }

    # --- control-plane threat intel: VirusTotal HASH-ONLY -------------------
    # Runs on the driving box (never the air-gapped VM) and only sends the
    # SHA256. Evidence-only by policy: a detection count never decides a
    # verdict (commercial AV flags dual-use tooling constantly). Added AFTER
    # the failure/active accounting so VT errors can't fail the quick gate.
    try:
        from . import vt as _vt
        # shared helper instead of the local hex-check workaround that
        # only this one call site had (code audit 2026-10-06)
        from .evidence import sha_of
        vres = _vt.lookup(sha_of(pack.root))
        evidence["vt"] = vres
        ti = evidence.get("threat_intel")
        if isinstance(ti, dict):
            ti["vt"] = {k: vres.get(k) for k in
                        ("ok", "found", "malicious", "suspicious",
                         "detection_ratio", "family", "name", "link",
                         "error", "skipped")}
            if vres.get("malicious") and vres.get("family"):
                ti.setdefault("reasons", []).append(
                    f"VirusTotal: {vres['family']} "
                    f"({vres.get('detection_ratio')})")
    except Exception as e:  # noqa: BLE001
        evidence["vt"] = {"ok": False, "error": str(e)[:180]}

    verdict = "unknown"
    pack.write("quick", "quick.json", {"evidence": evidence, "verdict": verdict,
                                       "tool_failures": tool_failures,
                                       "tool_warnings": warnings,
                                       "capability_census": quick_census})
    pack.write("quick", "META.json", stage_result(
        "quick", ok,
        error=None if ok else "quick helper failed or required Ghidra census missing",
        summary=f"ghidra={evidence.get('ghidra',{}).get('func_rows')} "
                f"malcat={'yes' if evidence.get('malcat',{}).get('sha256') else 'skip'} "
                f"ida={evidence.get('ida',{}).get('func_count')}",
        verdict=verdict, tool_failures=tool_failures,
        tool_warnings=warnings, capability_census=quick_census,
        fallback=not ok, elapsed_s=round(time.time() - t0, 1)))
    return {"evidence": evidence, "verdict": verdict,
            "failures": tool_failures, "warnings": warnings,
            "capability_census": quick_census}


# ---------------------------------------------------------------------------
# Remote dynamic helper (runs ON the VM via scp)
# ---------------------------------------------------------------------------
REMOTE_DYNAMIC_HELPER = r'''
"""Remote dynamic helper — runs orchestrator --mode local on the VM.

Usage: python _remote_dynamic_helper.py <sha> <sample_path> <max_seconds> [--pesieve] [--adaptive] [--idle-stop=N] [--section=agentic|static] [--run-id=<nonce>]
Writes the session file, sets env, runs orchestrator, prints META.json tail.
--section pins detonation into logs/<sha>/<section>/dynamic (mode-sectioned
packs); default agentic for legacy callers.
--run-id passes the control plane's per-run nonce through to the
orchestrator, which stamps it into META.json; the control plane then decides
pack freshness by that value instead of comparing clocks (winre/run_nonce.py).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from winre.evidence import MODES  # the four producer modes (design section 3)

sha = sys.argv[1]
sample = sys.argv[2]
max_seconds = int(sys.argv[3])
pesieve = "--pesieve" in sys.argv[4:]
adaptive = "--adaptive" in sys.argv[4:]
# behaviour gate passthrough (RevAI handoff item 9): the window ends
# early once the sample does something notable and settles
stop_on = "network,file"
stop_on_settle = 20
for _a in sys.argv[4:]:
    if _a.startswith("--stop-on-settle="):
        stop_on_settle = int(_a.split("=", 1)[1])
    elif _a.startswith("--stop-on="):
        stop_on = _a.split("=", 1)[1]
idle_stop = 10
section = "agentic"
run_id = None
dll_entry = None
for _a in sys.argv[4:]:
    if _a.startswith("--section=") and _a.split("=", 1)[1] in MODES:
        section = _a.split("=", 1)[1]
    if _a.startswith("--idle-stop="):
        try:
            idle_stop = int(_a.split("=", 1)[1])
        except ValueError:
            idle_stop = 10
    if _a.startswith("--run-id=") and _a.split("=", 1)[1].strip():
        run_id = _a.split("=", 1)[1].strip()
    if _a.startswith("--dll-entry=") and _a.split("=", 1)[1].strip():
        dll_entry = _a.split("=", 1)[1].strip()

pipeline = Path(__file__).resolve().parents[1]
sessions = pipeline / "sessions"
session_file = sessions / "runs" / f"{run_id or sha}.json"
session_file.parent.mkdir(parents=True, exist_ok=True)
session_file.write_text(json.dumps({
    "sha256": sha,
    "sample_path": sample,
    "file_type": {"format": "pe"},
}), encoding="utf-8")

env = os.environ.copy()
env["WINRE_ORCHESTRATOR_MODE"] = "local"
env.setdefault("WINRE_ORCH_LOCK", str(pipeline / "lock" / "orchestrator.lock"))
env["REVENG_LOGS_DIR"] = str(pipeline / "logs")
env["WINRE_DYNAMIC_DIR"] = str(
    pipeline / "logs" / sha / section / "dynamic" / "runs" / (run_id or sha))
env["REVENG_SESSIONS_DIR"] = str(sessions)
env["WINRE_SESSION_FILE"] = str(session_file)
# phase 3 (docs/internal/DESIGN.md section 2): the orchestrator always defers
# interpretation; this control-plane process runs it after a verified pull.
if run_id:
    env["WINRE_RUN_ID"] = run_id

cmd = [sys.executable, str(pipeline / "winre" / "orchestrator.py"), sha,
       "--sample", sample, "--mode", "local", "--max-seconds", str(max_seconds)]
if run_id:
    cmd += ["--run-id", run_id]
if pesieve:
    cmd.append("--pesieve")
if adaptive:
    cmd += ["--adaptive", "--idle-stop-seconds", str(idle_stop)]
if stop_on:
    cmd += ["--stop-on", stop_on, "--stop-on-settle", str(stop_on_settle)]
if dll_entry:
    # only takes effect when the target is a DLL; the tracer decides that from
    # the PE header and ignores it for an executable
    cmd += ["--dll-entry", dll_entry]
print(f"run_id={run_id or 'none'}")
try:
    r = subprocess.run(cmd, capture_output=True, text=True, env=env,
                       timeout=int(max_seconds) + 600,
                       encoding="utf-8", errors="replace")
    print(f"RC={r.returncode}")
    print((r.stdout or "")[-600:])
except subprocess.TimeoutExpired:
    print("RC=-1 TIMEOUT")
'''


def clock_skew_s(cfg: dict | None = None, *, cached: dict | None = None,
                 timeout: int = 30) -> dict:
    """VM-vs-control-plane clock skew, in seconds (RevAI handoff item 4).

    A skewed VM clock used to make every detonation look "not run" to the
    control plane (freshness was a string compare on timestamps) and makes
    a 5h-fast control plane look guilty even when Flare's clock was right.
    Freshness no longer depends on clocks (winre/run_nonce.py) — this is a
    DIAGNOSTIC, recorded in the pack (`clock_skew_s` in
    dynamic/STAGE.json, pack META.json, audit.json) and surfaced by the UI
    health probe, so a WinRE-only operator gets the same visibility RevAI
    exposes on its Test connection.

    cached: pass an earlier probe result to avoid a second SSH round-trip.
    """
    if cached:
        return cached
    cfg = cfg or flare_cfg()
    out: dict = {"clock_skew_s": None, "vm_time": None,
                 "control_plane_utc": datetime.now(timezone.utc)
                 .strftime("%Y-%m-%dT%H:%M:%SZ")}
    try:
        p = ssh_run(cfg, "powershell -NoProfile -Command "
                         "[DateTimeOffset]::Now.ToString('o')", timeout=timeout)
        raw = [ln.strip() for ln in (p.stdout or "").splitlines()
               if ln.strip() and "T" in ln]
        if p.returncode == 0 and raw:
            vm = datetime.fromisoformat(raw[-1].replace("Z", "+00:00"))
            out["vm_time"] = vm.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            out["clock_skew_s"] = round(
                (vm - datetime.now(timezone.utc)).total_seconds(), 1)
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def _requested_sources(pack, meta: dict) -> dict:
    """Which artifact sources this run actually asked for.

    The manifest's coverage verdict depends on this: a source that was never
    requested is `not_requested`, not silently missing. Guessing from what is
    present would make every pack look complete.
    """
    dyn = bool(meta.get("execution_kind") == "dynamic" or
               meta.get("detonation_ran") or meta.get("sample_pid"))
    req = {
        "frida": {"requested": dyn, "required": dyn},
        "procmon": {"requested": dyn, "required": dyn},
        "network": {"requested": dyn, "required": dyn},
        "network_enrichment": {"requested": dyn, "required": False},
        "process_snapshot": {"requested": dyn, "required": False},
        "memory": {"requested": dyn, "required": False},
        "malcat": {"requested": dyn, "required": False},
        "job": {"requested": dyn, "required": dyn},
        "pe_sieve": {"requested": bool(meta.get("pe_sieve_ran") or
                                         meta.get("pe_sieve_enabled")),
                      "required": False},
        "x64dbg": {"requested": bool((meta.get("x64dbg_dump") or {}).get("attempted")),
                   "required": False},
        "windbg": {"requested": dyn, "required": False},
        "external_capture": {"requested": bool(meta.get("external_capture_requested")),
                              "required": False},
    }
    return req


def remote_dynamic(sample_name: str, sha: str, pack: EvidencePack, cfg: dict,
                   max_seconds: int, enable_pesieve: bool,
                   adaptive: bool = False,
                   idle_stop_seconds: int = 0,
                   stop_on: str = "network,file",
                   stop_on_settle: int = 20,
                   clock: dict | None = None,
                   remote_sample: str | None = None,
                   run_id: str | None = None) -> dict:
    """SSH: run orchestrator --mode local on the VM via helper, scp pack back."""
    t0 = time.time()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # --- snapshot gate: the control plane requires both the guest marker and
    # its independent clean-state ledger. The VM-side orchestrator then
    # consumes the marker at the execution site. Control plane never consumes
    # the guest marker here.
    from . import snapshot_gate
    gate = snapshot_gate.preflight("dynamic", sha=sha, cfg=cfg, consume=False)
    if not gate.get("allowed"):
        # Honesty without destruction: the PREVIOUS run's artifacts must not be
        # presented as this run's evidence (2026-09-18: a blocked enforce run
        # still showed events=533) - but they are EVIDENCE, so they are MOVED
        # to previous_runs/ and the pointer is recorded. Deleting them (the old
        # behaviour) broke the append-only contract and left a record that
        # claimed "moved, never deleted" while pointing nowhere (code audit
        # 2026-09-28, HIGH).
        from .evidence import (dynamic_skip_record, preserve_dynamic,
                               write_dynamic_skip)
        prev = preserve_dynamic(pack)
        blocked = stage_result("dynamic", False, error=gate.get("error"),
                              elapsed_s=round(time.time() - t0, 1),
                              gate_pass=False, gate=gate.get("gate"),
                              summary="blocked by snapshot gate"
                                      + (f"; previous pack preserved at "
                                         f"{prev['preserved_previous']}"
                                         if prev.get("preserved_previous") else ""),
                              preserved_previous=prev.get("preserved_previous"),
                              cleared_previous=False)
        try:
            pack.write("dynamic", "STAGE.json", blocked)
        except Exception:
            pass
        # sibling skip record: a consumer can tell "never asked" from
        # "asked and the gate refused" without parsing the stage wrapper
        write_dynamic_skip(pack, dynamic_skip_record(
            reason="snapshot_gate_blocked", ok=False,
            error=gate.get("error"),
            summary="blocked by snapshot gate (no detonation ran in this run)",
            preserved_previous=prev.get("preserved_previous"),
            preserved_artifacts=prev.get("preserved_artifacts") or None,
            extra={"gate_mode": gate.get("gate", {}).get("mode"),
                   "preserve_error": prev.get("preserve_error")}))
        return blocked
    try:
        remote_sample = _verified_remote_sample(
            pack, sample_name, cfg, supplied_path=remote_sample,
            expected_sha=sha)
    except Exception as e:
        failed = stage_result("dynamic", False,
                              error=f"staging identity: {str(e)[:220]}",
                              elapsed_s=round(time.time() - t0, 1),
                              gate=gate.get("gate"))
        pack.write("dynamic", "STAGE.json", failed)
        return failed
    py = _remote_py(cfg)
    # Helper source: the tracked file is the single source of truth; the
    # embedded copy is a fallback for checkouts without it (two drifting
    # copies of this script is how the --run-id arg nearly shipped missing).
    helper = REPO / "winre" / "_remote_dynamic_helper.py"
    try:
        # The helper is generated and gitignored. Always refresh it from the
        # embedded source before copying so a stale local helper cannot bypass
        # the run-specific directory/session contract.
        helper.write_text(REMOTE_DYNAMIC_HELPER, encoding="utf-8")
        scp_to(cfg, helper, rf'{cfg["remote_pipeline"]}\winre\_remote_dynamic_helper.py')
    except Exception as e:
        return stage_result("dynamic", False, error=f"scp helper: {e}",
                            elapsed_s=round(time.time() - t0, 1),
                            gate=gate.get("gate"))

    # Per-run nonce: freshness is decided by this VALUE (winre/run_nonce.py),
    # never by comparing the VM clock with the control plane's clock.
    run_id = run_id or new_run_id()
    if not re.fullmatch(r"[0-9a-f]{32}", run_id, flags=re.IGNORECASE):
        return stage_result("dynamic", False, error="invalid dynamic run ID",
                            elapsed_s=round(time.time() - t0, 1),
                            gate=gate.get("gate"))

    # Preserve the last accepted evidence before this run starts. A failed
    # archive means no detonation: the result would have nowhere safe to land.
    local_dyn = pack.stages["dynamic"]
    archived = archive_stage_for_fresh_run(pack)
    if not archived.get("ok"):
        failed = stage_result("dynamic", False,
                              error="could not archive prior dynamic evidence: "
                                    + str(archived.get("error") or "unknown error"),
                              archived=archived, run_id=run_id,
                              gate=gate.get("gate"))
        pack.write("dynamic", "STAGE.json", failed)
        return failed
    local_dyn.mkdir(parents=True, exist_ok=True)
    for wrapper in ("STAGE.json", "SKIP.json"):
        try:
            (local_dyn / wrapper).unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            failed = stage_result("dynamic", False,
                                  error=f"could not clear stale {wrapper}: {e}",
                                  archived=archived, run_id=run_id)
            pack.write("dynamic", "STAGE.json", failed)
            return failed
    # Gate mode is a CONTROL-PLANE decision: forward it (and the marker path)
    # to the VM helper so an operator's observe/off override works end-to-end.
    # Without this the helper's own default (enforce) blocks benign test
    # loops even when the host explicitly asked for observe.
    from . import snapshot_gate as _sg
    _marker_fwd = (f"$env:WINRE_SNAPSHOT_MARKER='{_sg.MARKER}'; "
                   if os.environ.get("WINRE_SNAPSHOT_MARKER") else "")
    # Build a real PowerShell script and send it via -EncodedCommand.
    #
    # The previous form wrapped everything in one inline
    # `powershell -Command "..."` string. That quoting does not survive the
    # cmd  ssh  powershell nesting: the sample path's own double quotes were
    # consumed, PowerShell reported a parse error, `cmd` came back as the whole
    # script text, and the DETONATION NEVER RAN - while STAGE.json still
    # carried a stage result as though it had. ssh_ps() exists precisely for
    # this ("inline -Command strings get mangled by the nesting") and the rest
    # of the VM plumbing already uses it.
    _script = (f"$env:WINRE_SNAPSHOT_GATE='{_sg.mode()}'; "
               + _marker_fwd
               + f"& '{py}' "
               f"'{cfg['remote_pipeline']}\\winre\\_remote_dynamic_helper.py' "
               f"'{sha}' '{remote_sample}' '{int(max_seconds)}'"
               f'{" --pesieve" if enable_pesieve else ""}'
               f'{" --adaptive" if adaptive else ""}'
               f' --idle-stop={int(idle_stop_seconds)}'
               f'{"" if not stop_on else " --stop-on=" + str(stop_on)}'
               f'{"" if not stop_on else " --stop-on-settle=" + str(int(stop_on_settle))}'
               f' --section={pack.mode or "agentic"}'
               f' --run-id={run_id}')
    try:
        r = ssh_ps(cfg, _script, timeout=int(max_seconds) + 700)
    except Exception as e:
        r = subprocess.CompletedProcess(
            args=[], returncode=-1, stdout="",
            stderr=f"dynamic helper SSH failed: {type(e).__name__}: {e}")
    # honest RC check: the helper prints RC=<code> as its last line
    helper_rc = None
    for line in reversed((r.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("RC="):
            try:
                helper_rc = int(line[3:])
            except ValueError:
                helper_rc = -1
            break
    job_ran = r.returncode == 0 and helper_rc is not None and helper_rc >= 0

    ok = False
    err = None
    remote_root = str(cfg["remote_pipeline"]).replace("\\", "/").rstrip("/")
    remote_dyn = (f"{remote_root}/logs/{sha}/{pack.mode or 'agentic'}"
                  f"/dynamic/runs/{run_id}")
    if not job_ran:
        err = (f"detonation did not run: ssh rc={r.returncode} "
               f"helper_rc={helper_rc}; stderr={(r.stderr or '')[:200]}")
    remote_inventory = None
    inventory_error = None
    try:
        remote_inventory = remote_file_inventory(cfg, remote_dyn)
    except Exception as e:
        inventory_error = f"remote inventory: {type(e).__name__}: {e}"

    incoming_parent = pack.root / ".incoming" / run_id
    pull_root = incoming_parent / "dynamic"
    transfer_error = None
    try:
        incoming_parent.mkdir(parents=True, exist_ok=True)
        if pull_root.exists():
            raise RuntimeError(f"incoming destination already exists: {pull_root}")
        scp_from(cfg, remote_dyn, pull_root, recursive=True)
    except Exception as e:
        transfer_error = f"transfer: {type(e).__name__}: {e}"

    incoming_meta: dict = {}
    incoming_inventory: dict[str, tuple[int, str]] = {}
    local_inventory_error = None
    try:
        if pull_root.is_dir():
            try:
                incoming_meta = json.loads(
                    (pull_root / "META.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                incoming_meta = {}
            incoming_inventory = local_file_inventory(pull_root)
    except Exception as e:
        local_inventory_error = f"local inventory: {type(e).__name__}: {e}"

    inventory_matches = (remote_inventory is not None
                         and local_inventory_error is None
                         and incoming_inventory == remote_inventory)
    inventory_diff = None
    if remote_inventory is not None and local_inventory_error is None:
        inventory_diff = _inventory_diff(remote_inventory, incoming_inventory)
    nonce = run_nonce.check(incoming_meta, run_id)
    metadata_complete = bool(
        incoming_meta.get("sha256") == sha
        and not incoming_meta.get("running")
        and incoming_meta.get("finished_at"))
    transfer_complete = bool(
        transfer_error is None and inventory_matches
        and nonce.get("fresh") and metadata_complete and job_ran)
    transfer = {
        "complete": transfer_complete,
        "run_id": run_id,
        "remote_directory": remote_dyn,
        "remote_files": len(remote_inventory or {}),
        "local_files": len(incoming_inventory),
        "inventory_matches": inventory_matches,
        "fresh_meta": bool(nonce.get("fresh")),
        "metadata_complete": metadata_complete,
        "helper_completed": job_ran,
        "inventory_diff": inventory_diff,
        "error": transfer_error or inventory_error or local_inventory_error,
    }
    if remote_inventory is not None and not inventory_matches and not transfer["error"]:
        diff = inventory_diff or {}
        transfer["error"] = (
            "remote and received file inventories differ "
            f"(missing={diff.get('missing_local_count', 0)}, "
            f"unexpected={diff.get('unexpected_local_count', 0)}, "
            f"content_mismatch={diff.get('content_mismatch_count', 0)})")

    if transfer_complete:
        import shutil as _shutil
        try:
            # The receiver was emptied before detonation. Replace it only after
            # the full incoming inventory and current-run META have matched.
            local_dyn.rmdir()
            _shutil.move(str(pull_root), str(local_dyn))
            ok = True
        except OSError as e:
            transfer_complete = False
            transfer["complete"] = False
            transfer["error"] = f"promote incoming evidence failed: {e}"
            err = transfer["error"]
        if ok:
            for parent in (incoming_parent, incoming_parent.parent):
                try:
                    parent.rmdir()
                except OSError:
                    pass
    if not transfer_complete:
        if err is None:
            err = (transfer["error"] or inventory_error
                   or nonce.get("reason")
                   or ("run metadata is incomplete" if not metadata_complete
                       else "run did not complete"))
        partial_path = None
        if pull_root.exists():
            import shutil as _shutil
            partial_parent = pack.root / "previous_runs"
            partial_parent.mkdir(parents=True, exist_ok=True)
            partial_dest = partial_parent / f"dynamic_partial_{run_id}"
            if partial_dest.exists():
                partial_dest = partial_parent / f"dynamic_partial_{run_id}-{time.time_ns()}"
            try:
                _shutil.move(str(pull_root), str(partial_dest))
                partial_path = str(partial_dest.relative_to(pack.root)).replace("\\", "/")
            except OSError as e:
                transfer["preserve_error"] = str(e)[:200]
        transfer["partial_evidence"] = partial_path
        for parent in (incoming_parent, incoming_parent.parent):
            try:
                parent.rmdir()
            except OSError:
                pass
        meta = incoming_meta
    else:
        meta = pack.read("dynamic", "META.json") or {}
    # Freshness = the orchestrator stamped OUR nonce (value comparison).
    # No clocks in the decision: a skewed VM clock can neither make a fresh
    # run look stale nor an old pack look fresh (RevAI handoff item 5).
    nonce = run_nonce.check(meta, run_id)
    fresh = bool(nonce["fresh"])
    gate_mode = snapshot_gate.mode()
    gate_pass = (gate_mode != "enforce") or bool(meta.get("gate_marker_consumed"))
    # ok=sample-ran without the tracer surviving is not a green detonation.
    ok = bool(transfer_complete and fresh and meta.get("ok"))
    # A stage can be "not green" for two different reasons, and only one of
    # them is a product failure. Say which, so the pack is auditable:
    #   no detonation      -> the sample never ran (DLL, spawn refused)
    #   tracer failure     -> it ran but Frida lost it
    detonation_ran = meta.get("detonation_ran")
    if detonation_ran is not None and not detonation_ran:
        err = (meta.get("error")
               or "sample process was never observed: the detonation never started")
    if not ok and err is None:
        err = ("no fresh META from this run"
               if not fresh else f"orchestrator error: {meta.get('error')}")
    # clock skew is a DIAGNOSTIC only (never part of the freshness decision)
    skew = clock_skew_s(cfg, cached=clock)
    restore_required = bool(meta.get("restore_required"))

    # phase 3: the analysis half of _post_pull_enrich runs HERE after a
    # verified pull. The guest always defers interpretation.
    # stage_meta must already exist: an earlier version of this block ran
    # BEFORE `stage_meta = stage_result(...)`, so every detonation that
    # succeeded crashed the control plane AFTER the evidence had been pulled.
    # The pack then said "detonation did not run" over 32 files of real
    # evidence including two memory dumps - the exact dishonesty this
    # architecture is meant to prevent.
    post_analysis = None
    if transfer_complete and fresh:
        try:
            from . import analysis as _analysis
            post_analysis = _analysis.run(pack.stages["dynamic"])
        except Exception as e:
            post_analysis = {"error": f"{type(e).__name__}: {e}"}

    # Finalize findings only after host-side enrichment has completed. The
    # earlier ordering wrote a verdict over an incomplete evidence view.
    dyn_findings = _findings.build(
        pack.mode or "dynamic", pack.root, sha=sha,
        evidence_dir=pack.stages["dynamic"], run_id=run_id,
        run_meta={"sample_pid": meta.get("sample_pid"),
                  "detonation_ran": meta.get("detonation_ran"),
                  "job_timeout": meta.get("job_timeout"),
                  "transfer": transfer, "ok": ok, "error": err})

    # ---- the artifact manifest (design §8) ---------------------------------
    # Written AFTER the analysis steps so it covers the derived files too, and
    # after the pull so it describes what actually arrived. This is what makes
    # "this run produced no network capture" distinguishable from "the network
    # capture is empty" - a distinction nothing recorded before.
    manifest_rec = None
    try:
        from . import manifest as _manifest
        manifest_rec = _manifest.write_manifest(
            pack.stages["dynamic"], run_id=run_id, sha256=sha,
            mode=pack.mode or "dynamic", meta=meta,
            requested=_requested_sources(pack, meta))
    except Exception as e:
        manifest_rec = {"schema": "winre-artifact-manifest/v1", "ok": False,
                        "error": f"{type(e).__name__}: {e}"}

    stage_meta = stage_result("dynamic", ok, error=err,
                              summary=(f"events={meta.get('frida_events')} "
                                       f"ok={ok}"
                                       + (f" | findings="
                                          f"{(dyn_findings.get('verdict') or {}).get('level')}"
                                          if dyn_findings.get("verdict") else "")
                                       + (" | VM DIRTY - restore the "
                                          "snapshot before the next run"
                                          if restore_required else "")),
                              restore_required=restore_required,
                              vm_dirty=bool(meta.get("vm_dirty")),
                              frida_events=meta.get("frida_events"),
                              detonation_ran=meta.get("detonation_ran"),
                              sample_pid=meta.get("sample_pid"),
                              job_timeout=bool(meta.get("job_timeout")),
                              job_error=meta.get("error"),
                              verdict=((dyn_findings.get("verdict") or {})
                                       .get("level")) or meta.get("verdict"),
                              findings=dyn_findings,
                              elapsed_s=round(time.time() - t0, 1),
                              gate_pass=gate_pass, gate=gate.get("gate"),
                              helper_rc=helper_rc,
                              run_id=run_id, nonce=nonce,
                              archived=archived, transfer=transfer,
                              clock_skew_s=(skew or {}).get("clock_skew_s"),
                              control_plane_started_at=started_at,
                              vm_finished_at=meta.get("finished_at"),
                              post_analysis=post_analysis,
                              manifest=manifest_rec)
    pack.write("dynamic", "STAGE.json", stage_meta)
    return stage_meta


def malcat_remote_call(name: str, arguments: dict | None = None,
                       timeout: int = 180,
                       method: str = "tools/call") -> dict:
    """Call the VM's Malcat MCP (localhost-bound :9009) via SSH-exec.

    Control-plane-safe transport: the JSON-RPC body is base64'd into a
    `powershell -EncodedCommand` (zero nested-quoting), POSTed to
    http://127.0.0.1:9009/mcp ON the VM, raw JSON printed to stdout.
    Returns the MalcatClient shape: {"ok","result","error","name"}.
    method="tools/list" ignores name/arguments (cheap liveness probe).
    """
    import base64
    import json as _json
    cfg = flare_cfg()
    if method == "tools/list":
        payload: dict = {"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": {}}
    else:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": {"name": name, "arguments": arguments or {}}}
    body = _json.dumps(payload)
    ps = (
        "$ErrorActionPreference='Stop';"
        f"$t={int(timeout)};"
        "$b=[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('"
        + base64.b64encode(body.encode("utf-8")).decode("ascii") + "'));"
        "$r=Invoke-RestMethod -Uri http://127.0.0.1:9009/mcp -Method Post "
        "-ContentType 'application/json' -Body $b -TimeoutSec $t;"
        "$r|ConvertTo-Json -Depth 16 -Compress"
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    try:
        p = ssh_run(cfg, f"powershell -NoProfile -EncodedCommand {enc}",
                    timeout=timeout + 60)
    except Exception as e:
        return {"ok": False, "error": f"ssh-exec malcat failed: {e}",
                "result": None, "name": name}
    if p.returncode != 0:
        return {"ok": False,
                "error": f"malcat remote exit={p.returncode}: "
                         f"{(p.stderr or '')[:300]}",
                "result": None, "name": name}
    try:
        raw = _json.loads(p.stdout)
    except Exception as e:
        return {"ok": False,
                "error": f"malcat remote non-JSON: {e}: "
                         f"{(p.stdout or '')[:200]}",
                "result": None, "name": name}
    if isinstance(raw, dict) and "error" in raw:
        return {"ok": False, "error": str(raw["error"]),
                "result": raw, "name": name}
    res = raw.get("result") if isinstance(raw, dict) else raw
    return {"ok": True, "error": None, "result": res, "name": name}


def malcat_remote_is_up(timeout: int = 20) -> bool:
    """SSH-exec probe: is Malcat MCP answering on the VM's localhost?"""
    r = malcat_remote_call("", None, timeout=timeout, method="tools/list")
    if not r.get("ok"):
        return False
    tools = ((r.get("result") or {}).get("tools")) or []
    return len(tools) > 0


def malcat_remote_aid(path: str, _cache: dict | None = None) -> tuple[int | None, dict | None]:
    """Resolve path -> analysis_id via the SSH-exec bridge (cached).

    malcat.mcp.py view tools expect {"analysis_id"}, NOT {"path"}.
    Returns (analysis_id, error_dict).
    """
    cache = _cache if _cache is not None else {}
    if path in cache:
        return cache[path], None
    r = malcat_remote_call("analyse_file", {"path": path})
    if not r.get("ok"):
        return None, r
    res = r.get("result") or {}
    aid = (res.get("structuredContent") or {}).get("analysis_id")
    if aid is None:
        try:
            for part in (res.get("content") or []):
                if isinstance(part, dict) and part.get("type") == "text":
                    import json as _json
                    aid = (_json.loads(part.get("text", "")) or {}).get("analysis_id")
                    break
        except Exception:
            aid = None
    if aid is None:
        return None, {"ok": False, "error": "no analysis_id from analyse_file",
                      "result": res}
    cache[path] = aid
    return aid, None


def malcat_installed(cfg: dict | None = None, timeout: int = 30) -> bool:
    """Is Malcat (commercial-optional) present on the VM at all?
    Checks the known bin locations for malcat.mcp.py. 'Not installed' is
    NOT a malfunction - the pipeline degrades to Ghidra-primary."""
    cfg = cfg or flare_cfg()
    script = (
        "@('C:\\Tools\\malcat\\bin', 'C:\\Program Files\\Malcat\\bin', "
        "'C:\\Users\\FLARE-VM\\Downloads\\malcat\\bin') | "
        "Where-Object { Test-Path (Join-Path $_ 'malcat.mcp.py') } | "
        "Select-Object -First 1")
    r = ssh_ps(cfg, script, timeout=timeout)
    return bool((r.stdout or "").strip())


def vm_port_listening(port: int, cfg: dict | None = None,
                      timeout: int = 60) -> bool:
    """SSH port probe for VM services bound to 127.0.0.1 (Malcat :9009,
    mcp-windbg :9097). A direct HTTP probe from the control plane can never
    reach a loopback bind — always go through SSH."""
    try:
        r = ssh_ps(cfg or flare_cfg(),
                   f"if (Get-NetTCPConnection -LocalPort {int(port)} -State "
                   "Listen -ErrorAction SilentlyContinue) { 'listening' } "
                   "else { 'down' }", timeout=timeout)
        return (r.stdout or "").strip() == "listening"
    except Exception:
        return False


def mcp_autostart_enabled() -> bool:
    """Driver-side MCP healing switch (WINRE_MCP_AUTOSTART=0 disables)."""
    return os.environ.get("WINRE_MCP_AUTOSTART", "1").strip().lower() not in (
        "0", "false", "no", "off")


def ensure_mcp_servers(cfg: dict | None = None, *,
                       only: tuple[str, ...] = ("malcat", "windbg"),
                       wait_s: int = 60) -> dict:
    """Heal the VM's headless MCP servers (boot launcher is the primary path).

    Malcat :9009 and mcp-windbg :9097 run headless, so the driver can start
    them over SSH in session 0 via the idempotent
    winre\\mcp\\start_servers.ps1 -NoX64dbg. x64dbg :9094 needs the interactive
    session — that path is winre.mcp.x64dbg_manager.ensure_mcp (agentic-dbg).

    Opt out with WINRE_MCP_AUTOSTART=0. Never raises; returns probe results.
    """
    out: dict = {"enabled": mcp_autostart_enabled(), "healed": False,
                 "malcat": None, "windbg": None}
    if not out["enabled"]:
        return out
    cfg = cfg or flare_cfg()

    def _probe(name: str, timeout: int) -> bool:
        if name == "malcat":
            return bool(malcat_remote_is_up(timeout=timeout))
        return bool(vm_port_listening(9097, cfg, timeout=timeout))

    for name in only:
        if name == "malcat":
            # commercial-optional: nothing to heal when not installed
            try:
                if not malcat_installed(cfg, timeout=30):
                    out["malcat"] = "not-installed"
                    continue
            except Exception:
                pass
        try:
            out[name] = _probe(name, 15 if name == "malcat" else 30)
        except Exception:
            out[name] = False
    if all(out.get(n) for n in only):
        return out

    # one idempotent heal attempt. -Detach re-runs the launcher via a
    # scheduled task: Win32-OpenSSH kills this connection's process tree on
    # disconnect, so servers started directly from the SSH shell would die
    # with it (same reason x64dbg_manager uses a task).
    try:
        r = ssh_run(cfg, "powershell -NoProfile -ExecutionPolicy Bypass "
                         r"-File C:\WinRE\winre\mcp\start_servers.ps1 "
                         "-NoX64dbg -Detach", timeout=60)
        out["heal_exit"] = r.returncode
    except Exception as e:
        out["error"] = f"heal failed: {str(e)[:200]}"
        return out
    out["healed"] = True

    deadline = time.time() + max(0, wait_s)
    while not all(out.get(n) for n in only) and time.time() < deadline:
        time.sleep(3)
        for name in only:
            if out.get(name):
                continue
            try:
                out[name] = _probe(name, 10 if name == "malcat" else 15)
            except Exception:
                pass
    return out


def _debug_target_image(agent_result: dict | None, fallback: str) -> str:
    """Basename of the exact sample copy x64dbg was asked to load.

    Debug-safe staging may rename a sample whose module name would be parsed
    as an x64dbg expression. ETW correlation must follow that actual path,
    while retaining the supplied sample name as a fallback for old packs.
    """
    from pathlib import PureWindowsPath
    target = (agent_result or {}).get("debug_run") or {}
    target = target.get("target") or {}
    candidate = target.get("staged_path") or target.get("sample_name") or fallback
    return PureWindowsPath(str(candidate)).name or PureWindowsPath(fallback).name


def _debug_monitor_failure(capture: dict) -> str | None:
    """A collected host trace is useful only if it observed the requested target."""
    if capture.get("status") != "collected":
        return str(capture.get("error") or capture.get("reason")
                   or capture.get("status") or "collection_failed")
    summary = capture.get("summary") or {}
    if summary.get("target_observed") is not True:
        return "target_process_not_observed"
    return None


def remote_mcp_health(cfg: dict) -> dict:
    """Probe the VM's MCP servers.

    x64dbg binds 0.0.0.0 - direct HTTP from this host, but its port depends
    on which plugin build is loaded (dp64 -> 9094, dp32 -> 9095, measured
    2026-10-06), so every candidate is probed rather than assuming 9094.
    Malcat :9009 and WinDbg :9097 bind 127.0.0.1 on the VM - those go via
    SSH-exec.
    """
    out = {}
    # per-port results are kept (they diagnose a wrong-port client), and
    # out["x64dbg"] is the OR - the server is up if ANY candidate answers
    xdbg_ports = {}
    import urllib.request
    for port in X64DbgClient.MCP_PORTS:
        url = "http://{}:{}/".format(cfg["host"], port)
        try:
            req = urllib.request.Request(url, data=b"{}", method="POST")
            with urllib.request.urlopen(req, timeout=8) as resp:
                xdbg_ports[str(port)] = resp.status == 200
        except Exception:
            xdbg_ports[str(port)] = False
    out["x64dbg_ports"] = xdbg_ports
    out["x64dbg"] = any(xdbg_ports.values())
    try:
        out["malcat"] = malcat_remote_is_up()
    except Exception:
        out["malcat"] = False
    try:
        out["windbg"] = vm_port_listening(9097, cfg, timeout=30)
    except Exception:
        out["windbg"] = False
    return out


def remote_deep(sample_name: str, pack: EvidencePack, cfg: dict, dry_llm: bool,
                sha: str = "", dynamic: bool = False,
                mode: str = "agentic",
                remote_sample: str | None = None,
                local_sample_path: str | Path | None = None,
                run_id: str = "") -> dict:
    """Deep dive from the control plane.

    mode="agentic" (default): LangGraph ReAct agent over the static toolset
    (Ghidra/IDA SQL over SSH + Malcat MCP over HTTP). When the LLM endpoint is
    configured the agent runs and the result is `llm_judge`; otherwise the
    stage records `deterministic_fallback` (honest, not green).
    mode="static": deterministic fixed-checklist deep dive, zero LLM calls
    (RevAI scripted). dry_llm is orthogonal.
    Set dynamic=True to also expose the bounded x64dbg debug-loop tools
    to the agent (agentic mode only).
    """
    from . import llm_client
    t0 = time.time()
    if not run_id:
        try:
            run_id = json.loads((pack.root / "META.json").read_text(
                encoding="utf-8")).get("run_id") or new_run_id()
        except Exception:
            run_id = new_run_id()
    try:
        remote_sample = _verified_remote_sample(
            pack, sample_name, cfg, supplied_path=remote_sample,
            expected_sha=sha or pack.sha)
    except Exception as e:
        failed = stage_result("deep", False,
                              error=f"staging identity: {str(e)[:220]}",
                              elapsed_s=round(time.time() - t0, 1))
        pack.write("deep", "deep.json", {"source": "staging_failure",
                                          "tool_failures": [failed["error"]],
                                          "agent": {"verdict": None}})
        pack.write("deep", "META.json", failed)
        return failed
    heal = ensure_mcp_servers(cfg)  # headless MCP self-heal (boot launcher is primary)
    mcp = remote_mcp_health(cfg)
    # commercial-optional: strip Malcat agent tools when Malcat is not
    # installed on the VM (honest degradation, no failures for absence)
    malcat_present = malcat_installed(cfg)
    if not malcat_present:
        mcp["malcat"] = "not-installed"
    engine = "static_deterministic" if mode == "static" else (
        "langgraph+dbg" if dynamic else "langgraph")
    out: dict = {"mcp": mcp, "mcp_heal": heal, "remote": True, "engine": engine}
    fallback = False
    failures: list[str] = []

    # Deep engine: static deterministic checklist, or LangGraph agent
    agent_result = None
    debug_capture: dict = {"requested": bool(dynamic),
                           "status": "not_requested" if not dynamic else "failed",
                           "run_id": run_id}
    debug_monitor_started = None
    debug_monitor_dir = pack.stages["deep"] / "debug_monitor"
    if dynamic:
        try:
            from .debug_monitor import start_remote
            debug_monitor_started = start_remote(cfg, run_id)
            debug_capture = {"requested": True, **debug_monitor_started}
        except Exception as e:
            debug_capture = {"requested": True, "status": "failed",
                             "run_id": run_id,
                             "error": f"{type(e).__name__}: {str(e)[:240]}"}
            debug_monitor_dir.mkdir(parents=True, exist_ok=True)
            (debug_monitor_dir / "META.json").write_text(
                json.dumps(debug_capture, indent=2) + "\n", encoding="utf-8")
    try:
        quick_ev = pack.read("quick", "quick.json")
        if mode == "static":
            from winre.static_deep import run_static_deep_dive
            agent_result = run_static_deep_dive(
                sample_name, sha or sample_name,
                mode="remote", quick=quick_ev, cfg=cfg,
                remote_sample=remote_sample,
                sample_path=local_sample_path)
        else:
            from winre.agentic import (run_langgraph_deep_dive, TOOL_NAMES)
            names: list[str] = list(TOOL_NAMES)
            if not malcat_present:
                names = [n for n in names if not n.startswith("malcat_")]
            agent_result = run_langgraph_deep_dive(sample_name, sha or sample_name,
                                                   max_steps=14, dry=dry_llm,
                                                   dynamic=dynamic,
                                                   available_tools=names,
                                                   quick=quick_ev,
                                                   remote_sample=remote_sample)
        history = []
        for h in (agent_result.get("history") or [])[:80]:
            entry = {"step": h.get("step"), "tool": h.get("tool"),
                     "args": h.get("args"), "error": h.get("error"),
                     "reason": h.get("reason"), "status": h.get("status")}
            res = h.get("result")
            if isinstance(res, dict):
                # FULL result preserved (evidence contract — raw outputs are
                # citable); only stringified blobs get a sane length cap
                entry["result"] = res
            history.append(entry)
        out["agent"] = {
            "source": agent_result.get("source"),
            "verdict": agent_result.get("verdict"),
            # WHICH role actually produced the verdict. Dropping it here made
            # deep.json unable to show the routing even though the run knew it
            # (code audit 2026-09-28).
            "verdict_judged_by": agent_result.get("verdict_judged_by"),
            "judgment_pass_error": agent_result.get("judgment_pass_error"),
            "planner_draft": agent_result.get("planner_draft"),
            "debug_run": agent_result.get("debug_run"),
            "format_detection": agent_result.get("format_detection"),
            "llm_analysis": agent_result.get("llm_analysis"),
            "fallback_reason": agent_result.get("fallback_reason"),
            "tool_calls": len(agent_result.get("history") or []),
            "history": history,
            "capability_census": agent_result.get("capability_census"),
            "tool_failures": agent_result.get("tool_failures") or [],
            "packed_signal": agent_result.get("packed_signal"),
            "unpack_prepass": agent_result.get("unpack_prepass"),
            "windbg_dump": agent_result.get("windbg_dump"),
            "debug_monitor": debug_capture,
            # which debugger served the unpack (x32dbg vs x64dbg, P1-F1)
            "dbg_ensure": agent_result.get("dbg_ensure"),
            # per-role models actually used (RevAI handoff item 7)
            "llm_roles": agent_result.get("llm_roles"),
        }
        # pull the unpack artifact into the pack (it lives on the VM otherwise)
        art = _pull_unpack_artifact(cfg, pack,
                                    agent_result.get("unpack_prepass"))
        if art:
            out["unpack_artifact"] = art
    except Exception as e:
        failures.append(f"agent:{e}")
        agent_result = None

    if debug_monitor_started:
        try:
            from .debug_monitor import stop_and_pull
            debug_capture = stop_and_pull(
                cfg, debug_monitor_started, debug_monitor_dir,
                target_image=_debug_target_image(agent_result, sample_name))
            debug_capture["run_id"] = run_id
            (debug_monitor_dir / "META.json").write_text(
                json.dumps(debug_capture, indent=2, default=str) + "\n",
                encoding="utf-8")
        except Exception as e:
            debug_capture = {"requested": True, "status": "failed",
                             "run_id": run_id,
                             "error": f"{type(e).__name__}: {str(e)[:240]}"}
            debug_monitor_dir.mkdir(parents=True, exist_ok=True)
            (debug_monitor_dir / "META.json").write_text(
                json.dumps(debug_capture, indent=2) + "\n", encoding="utf-8")
    if dynamic:
        out["debug_monitor"] = debug_capture
        if out.get("agent"):
            out["agent"]["debug_monitor"] = debug_capture
        monitor_failure = _debug_monitor_failure(debug_capture)
        if monitor_failure:
            failures.append("debug_monitor:" + monitor_failure)

    # Capability outcomes are audited the same way for both engines.
    if agent_result:
        out["capability_census"] = agent_result.get("capability_census")
        for _tf in (agent_result.get("tool_failures") or []):
            if _tf not in failures:
                failures.append(_tf)

    if agent_result and agent_result.get("source") in ("llm_judge",
                                                        "static_deterministic"):
        # deep produced a real verdict (LLM or deterministic rules) — not a fallback
        fallback = False
    else:
        fallback = True
        if not out.get("agent"):
            out["agent"] = {"source": "deterministic_fallback",
                            "text": "agent unavailable on control plane"}
        # keep evidence-only summary so the pack is still useful
        try:
            if llm_client.available() and not dry_llm:
                pass  # agent already tried; fall through
        except Exception:
            pass

    # Verdict contract (RevAI handoff 2026-09-27 item 2): a deep dive that
    # produced NO verdict is not a successful stage. ok=True used to be
    # written unconditionally, so `truly_green: true` could sit next to
    # `verdict: null`. ok is now gated on a real verdict, and the flat
    # verdict/source/key_evidence fields are mirrored at the TOP level of
    # deep.json so a third-party consumer does not have to know they live
    # under `agent`.
    verdict_obj, verdict_label, no_verdict = _verdict_fields(
        (out.get("agent") or {}).get("verdict"))
    out.update({
        "verdict": verdict_label,
        "verdict_obj": verdict_obj,
        "source": (out.get("agent") or {}).get("source"),
        "confidence": (verdict_obj or {}).get("confidence"),
        "key_evidence": (verdict_obj or {}).get("key_evidence") or [],
        "llm_analysis": (out.get("agent") or {}).get("llm_analysis"),
        "tool_failures": failures,
        "capability_census": out.get("capability_census"),
        "no_verdict": no_verdict,
        "llm_roles": (out.get("agent") or {}).get("llm_roles"),
    })
    pack.write("deep", "deep.json", out)
    pack.write("deep", "META.json", stage_result(
        "deep", not no_verdict,
        error=(("deep stage produced no verdict"
                + (f" ({(out.get('agent') or {}).get('fallback_reason')})"
                   if (out.get("agent") or {}).get("fallback_reason") else ""))
               if no_verdict else None),
        summary=f"mcp={mcp} engine={engine} mode={mode} fallback={fallback}",
        engine=engine, mode=mode, fallback=fallback, tool_failures=failures,
        debug_monitor=debug_capture,
        verdict=verdict_label, no_verdict=no_verdict,
        elapsed_s=round(time.time() - t0, 1)))
    # neat closure: if the agent had debug tools, x64dbg + the sample must
    # not outlive this stage (covers manual single-stage runs; the full
    # pipeline's final sweep is idempotent on top of this)
    if dynamic:
        try:
            from .mcp.x64dbg_manager import teardown, keep_debugger
            if not keep_debugger():
                out["x64dbg_teardown"] = teardown()
        except Exception as e:
            out["x64dbg_teardown"] = {"error": str(e)[:150]}
    # surface the agent block so _report can source-tag correctly
    return {"ok": True, "fallback": fallback, "failures": failures, "mcp": mcp,
            "agent": out.get("agent"), "llm_analysis": out.get("llm_analysis"),
            "x64dbg": out.get("x64dbg")}


def _pull_unpack_artifact(cfg: dict, pack, prepass: dict | None) -> dict | None:
    """Pull the x64dbg unpack dump from the VM into the pack (deep/x64dbg/).

    The dump is produced on the VM (C:\\samples\\<stem>_unpacked.exe); without
    this it would stay there and be lost to the evidence pack.
    """
    if not isinstance(prepass, dict) or not prepass.get("ok"):
        return None
    vm_path = str(prepass.get("dump_path") or "")
    if not vm_path:
        return None
    name = vm_path.replace("/", "\\").rsplit("\\", 1)[-1]
    if not name:
        return None
    dest_dir = pack.stages["deep"] / "x64dbg"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / name
    try:
        scp_from(cfg, vm_path, dest)
        return {"vm": vm_path, "local": f"deep/x64dbg/{name}",
                "bytes": dest.stat().st_size}
    except Exception as e:
        return {"vm": vm_path, "error": f"pull: {str(e)[:150]}"}


def run_remote_pipeline(sample: Path, *, max_seconds: int = 150,
                        enable_pesieve: bool = False, enable_dynamic: bool = False,
                        dry_llm: bool = False,
                        enable_agentic_dbg: bool = False,
                        mode: str = "agentic",
                        adaptive: bool = False,
                        idle_stop_seconds: int = 0,
                        stop_on: str = "network,file",
                        stop_on_settle: int = 20) -> dict:
    """Control-plane pipeline driver: SSH/HTTP to the VM + local LLM + local audit.

    DEFAULT = static-only (quick + deep + yara + report + audit). Dynamic is
    opt-in (enable_dynamic) and runs LAST, segregated, static_yara_wins.
    enable_agentic_dbg is independent: it gives the deep-dive agent the
    bounded x64dbg debug-loop tools (engine langgraph+dbg), without running
    the detonation phase.

    mode: "agentic" (default, RevAI agentic) or "static" (deterministic,
    RevAI scripted). dry_llm stays orthogonal.
    """
    from .evidence import sha256_file, resolve_pack_mode
    from . import audit as audit_mod
    from . import yara_gen

    cfg = flare_cfg()
    sha = sha256_file(sample)
    # one authority decides which pack root this run owns (docs/internal/
    # DESIGN.md 1.2e: dbg/dynamic used to share the agentic root and overwrite
    # each other)
    try:
        pack_mode = resolve_pack_mode(mode, agentic_dbg=enable_agentic_dbg,
                                      dynamic=enable_dynamic)
    except ValueError as e:
        return {"sha": sha, "aborted": True, "error": str(e),
                "results": {"audit": {"truly_green": False,
                                       "aborted": True,
                                       "aborted_reason": str(e)}}}
    pack = EvidencePack(LOCAL_LOGS, sha, mode=pack_mode).ensure()
    run_id = new_run_id()
    (pack.root / "META.json").write_text(json.dumps({
        "sha256": sha, "mode": pack_mode, "pack_mode": pack_mode,
        "run_id": run_id, "status": "in_progress",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2) + "\n", encoding="utf-8")

    # ---- RUN-LEVEL EXECUTION PLAN (fail fast, before any stage) -----------
    # Under `enforce` the clean marker is one-shot: a run that asks for two
    # executions (--dynamic + --agentic-dbg) used to half-execute — the debug
    # preflight consumed the marker, then dynamic was refused mid-run
    # (RevAI handoff 2026-09-27 item 1). Refuse up front, with one clear
    # message, and record the plan so audit.json states how many executions
    # the run intended.
    from . import snapshot_gate as _gate
    _gate.reset_session()      # debug-session scope is per run, not per process
    # phase 5 (DESIGN.md section 7): every mode invokes guest-side analysis
    # tools, which may have been tampered with by a prior sample. Require the
    # operator-attested clean marker before invoking any of them.
    from . import vm_gate as _vmgate
    gate_ok, blocker = _vmgate.require_clean_vm(
        cfg, mode=mode, agentic_dbg=enable_agentic_dbg, dynamic=enable_dynamic)
    if blocker:
        _vmgate.record_refusal(pack, blocker)
        print(f"[winre-remote] VM GATE: {blocker.get('reason')}", flush=True)
        for _step in blocker.get("how_to_clear") or []:
            print(f"[winre-remote]   -> {_step}", flush=True)
    plan = _gate.execution_plan(dynamic=enable_dynamic, debug=enable_agentic_dbg)
    write_execution_plan(pack, plan, run_id=run_id)
    results: dict = {"execution_plan": plan, "vm_gate": blocker}
    if not gate_ok or not plan.get("ok"):
        _msg = blocker.get("reason") if blocker else plan.get("error")
        print(f"[winre-remote] ABORT: {_msg}", flush=True)
        if blocker:
            for step in blocker.get("how_to_clear") or []:
                print(f"[winre-remote]   -> {step}", flush=True)
        results["aborted"] = True
        results["error"] = _msg
        # An audit must ALWAYS reflect the latest attempt: without this the
        # previous run's `truly_green: true` survived a refused run and the UI
        # showed a green section whose newest run never executed anything
        # (code audit 2026-09-28, HIGH).
        _aborted_audit = {
            "truly_green": False, "all_green": False, "quality_green": False,
            "aborted": True, "aborted_reason": _msg,
            "run_id": run_id,
            "execution_plan": plan,
            "unmet_expectations": [f"run aborted before any stage: {_msg}"],
            "checks": [], "fallback_stages": [], "failed_tools": [],
            "dynamic_conflict": False, "dynamic_blocked": False,
            "static_yara_wins": True, "static_verdict": None,
            "deep_verdict": None, "deep_verdict_source": None,
            "llm_roles": None, "dynamic_verdict": None,
            "snapshot_gate": {"mode": _gate.mode(),
                              "ok": bool(plan.get("ok")),
                              "detail": plan},
            "vm_gate": blocker,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        results["audit"] = _aborted_audit
        (pack.root / "audit.json").write_text(
            json.dumps(_aborted_audit, indent=2) + "\n", encoding="utf-8")
        (pack.root / "META.json").write_text(json.dumps({
            "sha256": sha, "mode": pack_mode, "engine_mode": mode,
            "pack_mode": pack_mode,
            "run_id": run_id, "aborted": True,
            "error": plan.get("error"),
            "truly_green": False,
            "execution_plan": plan,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2) + "\n", encoding="utf-8")
        return {"sha": sha, "results": results, "aborted": True}

    # one clock probe per run: recorded as a diagnostic, never used for the
    # freshness decision (winre/run_nonce.py)
    clock = clock_skew_s(cfg)
    results["clock"] = clock

    # Stage under a unique run directory, then verify bytes before any tool,
    # debugger, or detonation stage can consume them.
    remote_path = _remote_staging_destination(sample, sha, run_id)
    try:
        staging = stage_remote_sample(cfg, sample, sha, run_id)
    except Exception as e:
        print(f"[winre-remote] ABORT: sample staging failed: {e}", flush=True)
        return _remote_staging_abort(pack, sha, run_id, str(e), remote_path)
    remote_sample = staging["remote_path"]
    pack.write("intake", "REMOTE-STAGING.json", {
        **staging,
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    results["staging"] = staging

    # intake (local — we have the file)
    from .pipeline import _intake
    results["intake"] = _intake(sample, pack)

    # ---- STATIC phase (quick + deep over SSH/HTTP) ----
    results["quick"] = remote_quick(sample.name, pack, cfg,
                                    remote_sample=remote_sample)
    if (not results["quick"].get("ok")
            and "staging identity:" in str(results["quick"].get("error") or "")):
        aborted = _remote_staging_abort(
            pack, sha, run_id, str(results["quick"].get("error")), remote_path)
        aborted["results"].update(results)
        aborted["results"]["staging"] = {
            **staging, "ok": False,
            "error": results["quick"].get("error"),
        }
        return aborted
    results["deep"] = remote_deep(sample.name, pack, cfg, dry_llm, sha=sha,
                                  dynamic=enable_agentic_dbg, mode=mode,
                                  remote_sample=remote_sample,
                                  local_sample_path=sample.resolve(),
                                  run_id=run_id)
    if (not results["deep"].get("ok")
            and "staging identity:" in str(results["deep"].get("error") or "")):
        aborted = _remote_staging_abort(
            pack, sha, run_id, str(results["deep"].get("error")), remote_path)
        aborted["results"].update(results)
        aborted["results"]["staging"] = {
            **staging, "ok": False,
            "error": results["deep"].get("error"),
        }
        return aborted

    # ---- DYNAMIC phase (segregated, opt-in, runs LAST after static) ----
    if not enable_dynamic:
        from .evidence import mark_dynamic_not_requested
        mark_dynamic_not_requested(pack)
    if enable_dynamic:
        results["dynamic"] = remote_dynamic(sample.name, sha, pack, cfg,
                                            max_seconds, enable_pesieve,
                                            adaptive=adaptive,
                                            idle_stop_seconds=idle_stop_seconds,
                                            stop_on=stop_on,
                                            stop_on_settle=stop_on_settle,
                                            clock=clock,
                                            remote_sample=remote_sample,
                                            run_id=run_id)

    # yara (local, from evidence)
    try:
        rep = yara_gen.generate_rules(pack.root, pack.stages["yara"])
        # mirror the local path: an evidence-free rule is a fallback, so the
        # audit can see it (the remote writer previously omitted it entirely,
        # making `condition: false` rules invisible - code audit 2026-09-28)
        pack.write("yara", "META.json", stage_result(
            "yara", True, summary=f"rule={rep.get('rule_id')}",
            rule_id=rep.get("rule_id"),
            fallback=bool(rep.get("empty_rule")),
            error="empty rule (no evidence)" if rep.get("empty_rule") else None))
        results["yara"] = {"ok": True, "rule_id": rep.get("rule_id"),
                           "empty_rule": rep.get("empty_rule")}
    except Exception as e:
        results["yara"] = {"ok": False, "error": str(e)}

    # Findings are finalized after enrichment and before report/export.
    results["findings"] = _findings.build(
        pack_mode, pack.root, sha=sha,
        evidence_dir=pack.stages["dynamic"], run_id=run_id,
        run_meta=results.get("dynamic"))
    if pack_mode == "dynamic":
        dynamic_stage = pack.read("dynamic", "STAGE.json") or {}
        dynamic_stage["findings"] = results["findings"]
        dynamic_stage["verdict"] = (results["findings"].get("verdict") or {}).get("level")
        pack.write("dynamic", "STAGE.json", dynamic_stage)
    from .compose import compose_for_sample
    results["composite"] = compose_for_sample(
        sha, LOCAL_LOGS, pending={pack_mode: results["findings"]})
    results["composite"]["run_id"] = run_id
    (pack.root / "composite.json").write_text(
        json.dumps(results["composite"], indent=2, default=str) + "\n",
        encoding="utf-8")

    # report + audit + RevAI-contract reporting chain (local)
    from .pipeline import _report
    results["report"] = _report(pack, sha, results["quick"],
                                results.get("dynamic"), results["deep"],
                                composition=results["composite"])

    # Stage manifests feed the audit's requested-source coverage gate.
    try:
        from .manifest import write_pack_manifests
        results["artifact_manifests"] = write_pack_manifests(
            pack.root, run_id=run_id, sha256=sha, mode=pack_mode,
            dynamic_requested=enable_dynamic)
    except Exception as e:
        results["artifact_manifests"] = {
            "ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}

    audit_res = audit_mod.audit(pack.root, require_dynamic=enable_dynamic)
    (pack.root / "audit.json").write_text(
        json.dumps(audit_res, indent=2) + "\n", encoding="utf-8")
    results["audit"] = audit_res
    try:
        from .reporting import generate_all
        results["reporting"] = generate_all(pack.root)
    except Exception as e:
        results["reporting"] = {"error": str(e)[:200]}

    # pack-level META: mode/engine/source for UI rows + publish paths
    try:
        _deep_meta = pack.read("deep", "META.json") or {}
        (pack.root / "META.json").write_text(json.dumps({
            "sha256": sha,
            "mode": pack_mode, "pack_mode": pack_mode,
            "run_id": run_id, "status": "completed",
            "engine": _deep_meta.get("engine"),
            "source": (results.get("report") or {}).get("source"),
            "phase": (results.get("report") or {}).get("phase"),
            "verdict": (results["composite"].get("level")
                        or audit_res.get("selected_verdict")
                        or audit_res.get("static_verdict")),
            "mode_verdict": audit_res.get("static_verdict"),
            "selected_verdict_source": (results.get("report") or {})
                                       .get("selected_verdict_source"),
            "truly_green": audit_res["truly_green"],
            "unmet_expectations": audit_res.get("unmet_expectations") or [],
            "execution_plan": plan,
            "findings": results["findings"],
            "composite": results["composite"],
            "llm_roles": audit_res.get("llm_roles"),
            "clock_skew_s": (clock or {}).get("clock_skew_s"),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass

    # Refresh the inventory after the audit, rendered reports and final pack
    # metadata exist, then seal that exact view into a case export if needed.
    try:
        from .manifest import write_pack_manifests
        results["artifact_manifests"] = write_pack_manifests(
            pack.root, run_id=run_id, sha256=sha, mode=pack_mode,
            dynamic_requested=enable_dynamic)
    except Exception as e:
        results["artifact_manifests_final"] = {
            "ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}

    # Build the DFIR export after all reports, audit and pack metadata are
    # complete and pinned to this run.
    results["case_pack"] = None
    if results.get("dynamic", {}).get("ok"):
        try:
            from .casepack import build_case
            results["case_pack"] = build_case(pack.root, sha, pack_mode)
        except Exception as e:
            results["case_pack"] = {"ok": False,
                                    "error": f"case pack: {str(e)[:200]}"}

    # ---- final tool sweep: nothing keeps running after the pipeline ----
    results["cleanup"] = _final_sweep(cfg, dynamic=enable_dynamic,
                                      debug=enable_agentic_dbg)

    # Verdict line: never print a bare "unknown" that could be either a real
    # unknown verdict or a deep stage that produced nothing (RevAI handoff
    # item 6) — the two are different facts.
    _mode_verdict = (audit_res or {}).get("static_verdict")
    if _mode_verdict:
        _mode_vs = str(_mode_verdict)
    else:
        _mode_vs = ("none (deep stage produced no verdict)"
               if any("verdict" in str(u) for u in
                      (audit_res.get("unmet_expectations") or []))
               else "none")
    _selected_verdict = (results["composite"].get("level")
                         or audit_res.get("selected_verdict")
                         or _mode_vs)
    print(f"[winre-remote] {sha} verdict={_selected_verdict} "
          f"mode_verdict={_mode_vs} "
          f"dynamic={_dynamic_status_label(results.get('dynamic'))} "
          f"truly_green={audit_res['truly_green']}", flush=True)
    return {"sha": sha, "pack_mode": pack_mode, "run_id": run_id,
            "verdict": _selected_verdict,
            "results": results}


def _final_sweep(cfg: dict, *, dynamic: bool, debug: bool) -> dict:
    """Neat tool closure after a run: no sample, frida helper, or x64dbg GUI
    left alive on the VM. Idempotent, best-effort, never raises. Skipped
    entirely with WINRE_KEEP_DEBUGGER=1 (operator wants the session)."""
    from .mcp.x64dbg_manager import teardown, keep_debugger
    out: dict = {"skipped": keep_debugger()}
    if out["skipped"]:
        return out
    try:
        if debug:
            out["x64dbg"] = teardown()
    except Exception as e:
        out["x64dbg_error"] = str(e)[:150]
    try:
        if dynamic:
            # catch detonation orphans (job-timeout survivors etc.) — the
            # job's own Kill-Stale handles the normal path; this is the net
            images = ["sample.exe", "frida-helper-64.exe", "frida-helper-32.exe",
                      "hollows_hunter.exe", "pe-sieve.exe", "fakenet.exe",
                      "Procmon64.exe"]
            cmd = " & ".join(f"taskkill /F /IM {i} /T 2>nul" for i in images)
            r = ssh_run(cfg, f"{cmd} & exit /b 0", timeout=60)
            out["process_sweep"] = r.returncode == 0
    except Exception as e:
        out["sweep_error"] = str(e)[:150]
    try:
        # SQL servers are kept alive across helpers during the run (reuse is
        # required: killing a server holding an open Ghidra project can roll
        # the project back). Close them only now, after all SQL usage.
        images = ["ghidrasql.exe", "idasql.exe"]
        cmd = " & ".join(f"taskkill /F /IM {i} /T 2>nul" for i in images)
        r = ssh_run(cfg, f"{cmd} & exit /b 0", timeout=60)
        out["sql_sweep"] = r.returncode == 0
    except Exception as e:
        out["sql_sweep_error"] = str(e)[:150]
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="WinRE control-plane driver")
    ap.add_argument("sample", type=Path)
# RevAI handoff item 9: 45s missed the DGA that 150s caught, so the
# cap is 150s and the window ends early via the behaviour gate.
    ap.add_argument("--max-seconds", type=int, default=150)
    ap.add_argument("--pesieve", action="store_true")
    ap.add_argument("--dynamic", action="store_true",
                    help="enable segregated dynamic phase (opt-in)")
    ap.add_argument("--agentic-dbg", action="store_true",
                    help="give the deep-dive agent bounded x64dbg tools "
                         "(engine langgraph+dbg; no detonation)")
    ap.add_argument("--dry-llm", action="store_true")
    ap.add_argument("--stop-on", default="network,file",
                    help="behaviour gate (RevAI handoff item 9): end the "
                         "window once the sample does something notable "
                         "and settles. Empty disables.")
    ap.add_argument("--stop-on-settle", type=int, default=20,
                    help="seconds to keep tracing after the gate fires")
    ap.add_argument("--adaptive", action="store_true",
                    help="legacy idle-stop window (cap = --max-seconds). "
                         "The behaviour gate is the default mechanism.")
    ap.add_argument("--idle-stop-seconds", type=int, default=0,
                    help="OFF by default: a sleeping sample looks idle, so this "
                         "truncates the window before it wakes up. The "
                         "behaviour gate (--stop-on) is the mechanism that "
                         "solves the fixed-window problem (RevAI item 9).")
    ap.add_argument("--mode", choices=["agentic", "static"], default="agentic",
                    help="deep-dive engine: agentic = LangGraph ReAct (RevAI "
                         "agentic); static = deterministic fixed-checklist, "
                         "zero LLM calls (RevAI scripted)")
    ap.add_argument("--publish", action="store_true",
                    help="publish sanitized case to docs/case-studies/<mode>/<sha>/")
    args = ap.parse_args()
    if not args.sample.is_file():
        print(f"ERROR: sample not found: {args.sample}", file=sys.stderr)
        return 2
    import os as _os
    enable_dynamic = args.dynamic or _os.environ.get(
        "WINRE_ENABLE_DYNAMIC", "").strip().lower() in ("1", "true", "yes")
    enable_agentic_dbg = args.agentic_dbg or _os.environ.get(
        "WINRE_AGENTIC_DBG", "").strip().lower() in ("1", "true", "yes")
    res = run_remote_pipeline(args.sample, max_seconds=args.max_seconds,
                              enable_pesieve=args.pesieve,
                              enable_dynamic=enable_dynamic, dry_llm=args.dry_llm,
                              enable_agentic_dbg=enable_agentic_dbg,
                              mode=args.mode,
                              adaptive=getattr(args, "adaptive", False),
                              idle_stop_seconds=getattr(args, "idle_stop_seconds", 0),
                               stop_on=getattr(args, "stop_on", "network,file"),
                               stop_on_settle=getattr(args, "stop_on_settle", 20))
    if res.get("aborted"):
        # fail fast BEFORE anything executed (execution plan over budget)
        return 2
    if args.publish:
        from .evidence import EvidencePack
        from .reporting import publish_case
        # LOCAL_LOGS, NOT pipeline.LOGS_DIR: this run just created its pack
        # under LOCAL_LOGS, so publishing looked in a different root and
        # either failed or published somebody else's pack (code audit
        # 2026-10-06).
        _pub_mode = res.get("pack_mode") or args.mode
        pub = publish_case(
            EvidencePack(LOCAL_LOGS, res["sha"], mode=_pub_mode).root,
            mode=_pub_mode)
        print(f"[winre-remote] published {pub['dest']}", flush=True)
    return 0 if res["results"]["audit"]["truly_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

