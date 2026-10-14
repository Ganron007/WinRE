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


def _stop_matches_active_image(active_image: str, stopped_image: str) -> bool:
    """Match an ETW stop event to its start, including truncated image names.

    Kernel-Process stop events can contain only the first 14 characters of the
    image basename even when the start event has the full path. A PID is unique
    for the current active instance in event order, so accept that distinctive
    prefix while continuing to reject unrelated image names after PID reuse.
    """
    active_name = PureWindowsPath(active_image or "").name.casefold()
    stopped_name = PureWindowsPath(stopped_image or "").name.casefold()
    if not active_name or not stopped_name:
        return True
    if stopped_name == active_name:
        return True
    return len(stopped_name) >= 14 and active_name.startswith(stopped_name)


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
    # Track process *instances* for the duration of this trace. A PID can be
    # reused; a historical set of related PIDs incorrectly attributes a later
    # unrelated process (and its children) to the sample.
    active: dict[int, dict] = {}
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
        timestamp_node = system.find(q("TimeCreated"))
        timestamp = (timestamp_node.get("SystemTime")
                     if timestamp_node is not None else None)
        if event_id_node.text == "1":
            parent = active.get(ppid) if ppid is not None else None
            is_target = bool(target and basename == target)
            is_related = bool(parent and
                              (parent.get("target_process")
                               or parent.get("descendant_of_target")))
            if is_target:
                target_pids.add(pid)
            if is_related:
                related_pids.add(pid)
            depth = (int(parent.get("depth", 0)) + 1
                     if is_related and parent else 0)
            instance = {"process_id": pid, "parent_process_id": ppid,
                        "image_name": image, "timestamp_utc": timestamp,
                        "target_process": is_target,
                        "descendant_of_target": is_related,
                        "depth": depth}
            active[pid] = instance
        events.append({
            "event": "process_start" if event_id_node.text == "1" else "process_stop",
            "timestamp_utc": timestamp,
            "process_id": pid,
            "parent_process_id": ppid,
            "image_name": image,
            "target_process": (active.get(pid, {}).get("target_process", False)
                               if event_id_node.text == "1" else False),
            "descendant_of_target": (active.get(pid, {}).get(
                "descendant_of_target", False)
                if event_id_node.text == "1" else False),
        })
        if event_id_node.text == "2":
            instance = active.get(pid)
            if instance:
                # Keep the active identity on a genuine image mismatch (for
                # example, a late stop event after PID reuse), but normalize
                # the 14-character basename truncation used by ETW stop rows.
                if _stop_matches_active_image(
                        str(instance.get("image_name") or ""), image):
                    events[-1]["target_process"] = bool(
                        instance.get("target_process"))
                    events[-1]["descendant_of_target"] = bool(
                        instance.get("descendant_of_target"))
                    active.pop(pid, None)
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
        "active_sample_processes": sorted(
            [{k: v.get(k) for k in ("process_id", "parent_process_id",
                                     "image_name", "timestamp_utc",
                                     "target_process", "descendant_of_target",
                                     "depth")}
             for v in active.values()
             if v.get("target_process") or v.get("descendant_of_target")],
            key=lambda v: (v.get("depth", 0), v.get("process_id", 0)),
            reverse=True),
        "unique_images": sorted({e["image_name"] for e in events if e["image_name"]})[:100],
    }
    return events, summary


def cleanup_active_processes(cfg: dict, run_id: str, summary: dict) -> dict:
    """Stop only the target/descendant process instances still active at trace end.

    The ETW process tree supplies candidate PIDs. Before terminating one, the
    guest checks its current image name and creation time against the captured
    start event so a PID reused by an unrelated process is left alone.
    """
    if not _RUN_ID.fullmatch(str(run_id or "")):
        return {"ok": False, "status": "failed", "reason": "invalid_run_id"}
    candidates = summary.get("active_sample_processes") or []
    if not candidates:
        return {"ok": True, "status": "clean", "checked": 0,
                "terminated_process_ids": [], "results": []}

    normalized = []
    for item in candidates:
        try:
            pid = int(item.get("process_id"))
            image = PureWindowsPath(str(item.get("image_name") or "")).name
            started = str(item.get("timestamp_utc") or "")
            if pid <= 0 or not image or not started:
                raise ValueError("incomplete active process identity")
            normalized.append({"process_id": pid, "image_name": image,
                               "timestamp_utc": started})
        except (TypeError, ValueError, AttributeError) as e:
            return {"ok": False, "status": "failed",
                    "reason": f"invalid_active_process_identity: {e}",
                    "checked": len(normalized), "results": []}

    payload = json.dumps(normalized, separators=(",", ":")).encode("utf-8")
    import base64
    encoded = base64.b64encode(payload).decode("ascii")
    script = f"""
$ErrorActionPreference='Stop'
$runId='{run_id}'
$raw=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))
$candidates=ConvertFrom-Json -InputObject $raw
$results=@()
foreach ($candidate in $candidates) {{
  $processId=[int]$candidate.process_id
  $name=[string]$candidate.image_name
  $actual=Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
  if (-not $actual) {{
    $results+=@{{process_id=$processId;image_name=$name;status='already_exited'}}
    continue
  }}
  if ([IO.Path]::GetFileName([string]$actual.Name) -ine $name) {{
    $results+=@{{process_id=$processId;image_name=$name;status='identity_mismatch_skipped'}}
    continue
  }}
  try {{
    if ($actual.CreationDate -is [DateTime]) {{
      $created=([DateTime]$actual.CreationDate).ToUniversalTime()
    }} else {{
      $created=[Management.ManagementDateTimeConverter]::ToDateTime([string]$actual.CreationDate).ToUniversalTime()
    }}
    $expected=[DateTimeOffset]::Parse([string]$candidate.timestamp_utc).UtcDateTime
    $delta=[Math]::Abs(($created-$expected).TotalSeconds)
  }} catch {{
    $results+=@{{process_id=$processId;image_name=$name;status='identity_unverified';error=$_.Exception.Message}}
    continue
  }}
  if ($delta -gt 5) {{
    $results+=@{{process_id=$processId;image_name=$name;status='identity_mismatch_skipped';creation_delta_seconds=[Math]::Round($delta,3)}}
    continue
  }}
  try {{
    Stop-Process -Id $processId -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 300
    $remaining=Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
    if (-not $remaining) {{
      $results+=@{{process_id=$processId;image_name=$name;status='terminated'}}
    }} else {{
      $results+=@{{process_id=$processId;image_name=$name;status='termination_unconfirmed'}}
    }}
  }} catch {{
    $results+=@{{process_id=$processId;image_name=$name;status='failed';error=$_.Exception.Message}}
  }}
}}
$bad=@($results | Where-Object {{ $_.status -in @('identity_unverified','termination_unconfirmed','failed') }})
$terminated=@($results | Where-Object status -eq 'terminated' | ForEach-Object {{ $_.process_id }})
[pscustomobject]@{{run_id=$runId;ok=($bad.Count -eq 0);status=$(if($bad.Count -eq 0){{if($terminated.Count -gt 0){{'terminated'}}else{{'clean'}}}}else{{'failed'}});checked=$results.Count;terminated_process_ids=$terminated;results=$results}} | ConvertTo-Json -Depth 5 -Compress
"""
    remote_script = (_REMOTE_SCRIPT_ROOT + "\\WinRE-debug-cleanup-"
                     + run_id + ".ps1")
    local_script: Path | None = None
    response: dict = {}
    errors: list[str] = []
    from .remote_driver import scp_to, ssh_ps, ssh_run
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", encoding="utf-8",
                                         delete=False, newline="\n") as fh:
            fh.write(script)
            local_script = Path(fh.name)
        scp_to(cfg, local_script, remote_script.replace("\\", "/"))
        response = _json_response(
            ssh_run(cfg, "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    + remote_script, timeout=120), "debug process cleanup")
    except Exception as e:
        errors.append(f"{type(e).__name__}: {str(e)[:220]}")
    finally:
        if local_script:
            try:
                local_script.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            ssh_ps(cfg, f"Remove-Item -LiteralPath '{remote_script}' -Force "
                   "-ErrorAction SilentlyContinue; Write-Output 'CLEANUP_OK'",
                   timeout=30)
        except Exception:
            pass
    if response.get("run_id") not in (None, run_id):
        errors.append("cleanup result belongs to another run")
    if errors:
        return {"ok": False, "status": "failed", "reason": "; ".join(errors),
                "checked": 0, "terminated_process_ids": [], "results": []}
    if response.get("ok") is not True:
        response.setdefault("status", "failed")
        response.setdefault("reason", "guest did not confirm process cleanup")
    return response


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
