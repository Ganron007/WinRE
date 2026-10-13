"""Run-scoped ETW process observer for agentic debugger sessions.

The observer runs as a Windows ETW session, so it survives the short SSH
command that starts it. It records kernel process start/stop events while the
agentic debugger runs, then returns the native ETL and a compact, correlated
event stream. It does not claim file, registry, network, or memory coverage;
the dynamic collection job remains responsible for those sources.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path, PureWindowsPath

_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_REMOTE_ROOT = r"C:\WinRE\sessions\debug-monitor"
_REMOTE_SCRIPT_ROOT = r"C:\Windows\Temp"
_SESSION_PREFIX = "WinREDbg"
_PROVIDER = "Microsoft-Windows-Kernel-Process"
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class DebugMonitorError(RuntimeError):
    """The requested ETW capture could not be started or recovered."""


def _json_response(result, operation: str) -> dict:
    if getattr(result, "returncode", 1) != 0:
        raise DebugMonitorError(
            f"{operation} SSH failed: "
            f"{(getattr(result, 'stderr', '') or getattr(result, 'stdout', '') or '')[:240]}")
    for line in reversed((getattr(result, "stdout", "") or "").splitlines()):
        try:
            value = json.loads(line.strip())
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            return value
    raise DebugMonitorError(f"{operation} returned no JSON result")


def _session_name(run_id: str) -> str:
    return _SESSION_PREFIX + run_id[:12]


def _remote_paths(run_id: str) -> tuple[str, str, str]:
    run_dir = _REMOTE_ROOT + "\\" + run_id
    return (run_dir + r"\process.etl", run_dir + r"\process.xml",
            _REMOTE_SCRIPT_ROOT + "\\WinRE-debug-stop-" + run_id + ".ps1")


def start_remote(cfg: dict, run_id: str) -> dict:
    """Start a fresh kernel-process ETW session and pin it to this run."""
    if not _RUN_ID.fullmatch(str(run_id or "")):
        raise DebugMonitorError("run_id must be the 32-character pipeline nonce")
    etl, _, _ = _remote_paths(run_id)
    session = _session_name(run_id)
    script = f"""
$ErrorActionPreference='Stop'
$session='{session}'
$dir='{_REMOTE_ROOT}\\{run_id}'
$etl='{etl}'
$logman=Join-Path $env:SystemRoot 'System32\\logman.exe'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
if (Test-Path -LiteralPath $etl) {{ throw 'run-unique ETL output already exists' }}
$old=@(& $logman query -ets $session 2>&1)
if ($LASTEXITCODE -eq 0) {{ throw 'run-scoped ETW session already exists' }}
$start=Start-Process -FilePath $logman -ArgumentList @('start','trace',$session,'-o',$etl,'-p','{_PROVIDER}','0x10','5','-ets') -Wait -PassThru -WindowStyle Hidden
if ($start.ExitCode -ne 0) {{ throw ('logman start failed: '+$start.ExitCode) }}
[pscustomobject]@{{ok=$true;status='started';run_id='{run_id}';session=$session;etl_path=$etl;provider='{_PROVIDER}';keyword='0x10';started_at=[DateTime]::UtcNow.ToString('o')}} | ConvertTo-Json -Compress
"""
    from .remote_driver import ssh_ps
    response = _json_response(ssh_ps(cfg, script, timeout=60), "ETW start")
    if response.get("status") != "started" or response.get("ok") is not True:
        raise DebugMonitorError(str(response.get("reason") or response.get("status") or
                                     "ETW session did not start")[:240])
    if (response.get("run_id") != run_id
            or response.get("session") != session
            or response.get("etl_path") != etl):
        raise DebugMonitorError("ETW start response failed identity validation")
    return response


def _parse_events(xml_path: Path, target_image: str | None = None) -> tuple[list[dict], dict]:
    """Parse ProcessStart/ProcessStop, omit command lines, and mark descendants."""
    target = PureWindowsPath(target_image or "").name.casefold()
    events: list[dict] = []
    target_pids: set[int] = set()
    related_pids: set[int] = set()
    q = lambda name: f"{{{_NS}}}{name}"

    for _, elem in ET.iterparse(xml_path, events=("end",)):
        if elem.tag != q("Event"):
            continue
        system = elem.find(q("System"))
        if system is None:
            elem.clear()
            continue
        provider = system.find(q("Provider"))
        event_id_node = system.find(q("EventID"))
        if (provider is None or provider.get("Name") != _PROVIDER
                or event_id_node is None or event_id_node.text not in {"1", "2"}):
            elem.clear()
            continue
        data: dict[str, str] = {}
        event_data = elem.find(q("EventData"))
        if event_data is not None:
            for node in event_data.findall(q("Data")):
                name = node.get("Name")
                if name and node.text is not None:
                    data[name] = node.text.strip()
        try:
            pid = int(data.get("ProcessID", ""))
        except ValueError:
            elem.clear()
            continue
        try:
            ppid = int(data.get("ParentProcessID", ""))
        except ValueError:
            ppid = None
        image = data.get("ImageName", "")
        basename = PureWindowsPath(image).name.casefold()
        is_target = bool(target and basename == target)
        if event_id_node.text == "1":
            if is_target:
                target_pids.add(pid)
            if ppid in target_pids or ppid in related_pids:
                related_pids.add(pid)
        events.append({
            "event": "process_start" if event_id_node.text == "1" else "process_stop",
            "timestamp_utc": (system.find(q("TimeCreated")).get("SystemTime")
                               if system.find(q("TimeCreated")) is not None else None),
            "process_id": pid,
            "parent_process_id": ppid,
            "image_name": image,
            "target_process": pid in target_pids,
            "descendant_of_target": pid in related_pids,
        })
        elem.clear()

    starts = sum(e["event"] == "process_start" for e in events)
    stops = len(events) - starts
    summary = {
        "provider": _PROVIDER,
        "scope": "process starts and stops only; no file, registry, network, or memory coverage",
        "events": len(events),
        "process_starts": starts,
        "process_stops": stops,
        "target_image": target_image,
        "target_observed": bool(target_pids),
        "target_process_ids": sorted(target_pids),
        "related_process_ids": sorted(related_pids),
        "unique_images": sorted({e["image_name"] for e in events if e["image_name"]})[:100],
    }
    return events, summary


def stop_and_pull(cfg: dict, started: dict, destination: Path,
                  *, target_image: str | None = None) -> dict:
    """Stop this run's ETW session, convert, hash-check, and pull its evidence."""
    run_id = str(started.get("run_id") or "")
    if not _RUN_ID.fullmatch(run_id):
        raise DebugMonitorError("invalid monitor run_id")
    etl, xml, remote_script = _remote_paths(run_id)
    session = _session_name(run_id)
    if started.get("session") != session or started.get("etl_path") != etl:
        raise DebugMonitorError("ETW session or path does not match this run")

    script = f"""
$ErrorActionPreference='Stop'
$session='{session}'; $etl='{etl}'; $xml='{xml}'
if (-not (Test-Path -LiteralPath $etl -PathType Leaf)) {{ throw 'ETW output missing' }}
$logman=Join-Path $env:SystemRoot 'System32\\logman.exe'
$stop=Start-Process -FilePath $logman -ArgumentList @('stop',$session,'-ets') -Wait -PassThru -WindowStyle Hidden
if ($stop.ExitCode -ne 0) {{ throw ('logman stop failed: '+$stop.ExitCode) }}
$tracerpt=Join-Path $env:SystemRoot 'System32\\tracerpt.exe'
$convert=Start-Process -FilePath $tracerpt -ArgumentList @($etl,'-o',$xml,'-of','XML','-y') -Wait -PassThru -WindowStyle Hidden
if ($convert.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $xml -PathType Leaf)) {{ throw ('tracerpt failed: '+$convert.ExitCode) }}
$ei=Get-Item -LiteralPath $etl; $xi=Get-Item -LiteralPath $xml
[pscustomobject]@{{ok=$true;status='collected';run_id='{run_id}';session=$session;etl_path=$etl;xml_path=$xml;etl_bytes=$ei.Length;etl_sha256=(Get-FileHash -LiteralPath $etl -Algorithm SHA256).Hash.ToLowerInvariant();xml_bytes=$xi.Length;xml_sha256=(Get-FileHash -LiteralPath $xml -Algorithm SHA256).Hash.ToLowerInvariant();stop_rc=$stop.ExitCode;convert_rc=$convert.ExitCode;stopped_at=[DateTime]::UtcNow.ToString('o')}} | ConvertTo-Json -Compress
"""
    from .remote_driver import scp_from, scp_to, ssh_ps, ssh_run
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    xml_local = destination / ".process.xml"
    if xml_local.exists():
        raise DebugMonitorError("temporary ETW XML path already exists")
    local_script = None
    remote: dict = {}
    pulled: dict[str, dict] = {}
    errors: list[str] = []
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", encoding="utf-8",
                                         delete=False, newline="\n") as fh:
            fh.write(script)
            local_script = Path(fh.name)
        scp_to(cfg, local_script, remote_script.replace("\\", "/"))
        command = "powershell -NoProfile -ExecutionPolicy Bypass -File " + remote_script
        remote = _json_response(ssh_run(cfg, command, timeout=180), "ETW stop/export")
    except Exception as e:
        errors.append(f"stop/export: {type(e).__name__}: {str(e)[:200]}")
    finally:
        if local_script:
            try:
                local_script.unlink(missing_ok=True)
            except OSError:
                pass
        # The script is uniquely named by the run nonce. Cleanup is bounded and
        # short enough to stay below Windows OpenSSH's command-line limit.
        try:
            ssh_ps(cfg, f"Remove-Item -LiteralPath '{remote_script}' -Force -ErrorAction SilentlyContinue; Write-Output 'CLEANUP_OK'",
                   timeout=30)
        except Exception:
            pass

    if remote.get("run_id") not in (None, run_id):
        errors.append("remote ETW result belongs to another run")
    if remote.get("status") == "collected":
        for remote_path, local_path, hash_key, name in (
                (etl, destination / "process.etl", "etl_sha256", "process.etl"),
                (xml, xml_local, "xml_sha256", ".process.xml")):
            try:
                scp_from(cfg, remote_path, local_path)
                digest = hashlib.sha256(local_path.read_bytes()).hexdigest()
                expected = str(remote.get(hash_key) or "").lower()
                if not expected or digest != expected:
                    raise DebugMonitorError(f"{name} hash differs after transfer")
                pulled[name] = {"path": name, "bytes": local_path.stat().st_size,
                                "sha256": digest}
            except Exception as e:
                errors.append(f"{name}: {type(e).__name__}: {str(e)[:180]}")

    summary: dict = {}
    if ".process.xml" in pulled:
        try:
            events, summary = _parse_events(xml_local, target_image=target_image)
            event_path = destination / "process_events.jsonl"
            with event_path.open("w", encoding="utf-8", newline="\n") as fh:
                for event in events:
                    fh.write(json.dumps(event, separators=(",", ":")) + "\n")
            pulled["process_events.jsonl"] = {
                "path": "process_events.jsonl",
                "bytes": event_path.stat().st_size,
                "sha256": hashlib.sha256(event_path.read_bytes()).hexdigest(),
            }
            (destination / "process_summary.json").write_text(
                json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        except Exception as e:
            errors.append(f"XML parse: {type(e).__name__}: {str(e)[:180]}")
    try:
        xml_local.unlink(missing_ok=True)
    except OSError as e:
        errors.append(f"temporary XML cleanup: {type(e).__name__}: {str(e)[:120]}")
    pulled.pop(".process.xml", None)

    has_etl = "process.etl" in pulled
    has_events = "process_events.jsonl" in pulled
    status = "collected" if has_etl and has_events and not errors else (
        "partial" if has_etl else "failed")
    result = {
        **remote,
        "requested": True,
        "collector": "Windows ETW Microsoft-Windows-Kernel-Process",
        "scope": "process starts and stops; no file, registry, network, or memory coverage",
        "started_at": started.get("started_at"),
        "run_id": run_id,
        "target_image": target_image,
        "summary": summary,
        "artifacts": pulled,
        "status": status,
        "ok": status == "collected",
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if errors:
        result["errors"] = errors
        result["reason"] = "; ".join(errors)[:500]
    (destination / "META.json").write_text(
        json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    return result
