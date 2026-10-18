"""Run-scoped passive packet capture from the REMnux VMnet2 interface.

The capture configuration is installed on the control plane by
RevAI's ``install/setup-winre-capture.sh``. The Flare guest keeps its normal
route/DNS and FakeNet configuration; tcpdump requests promiscuous capture on
the shared VMnet2 interface, filtered to the Flare guest IP. Captures are raw evidence
and are placed under ``dynamic/off_box/network_raw`` only after the process has
stopped and the pcap header/hash have been checked.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any


DEFAULT_CONFIG = Path("/etc/revai/winre-capture.json")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_config(env: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Return enabled passive-capture settings, or None when absent."""
    source = os.environ if env is None else env
    explicit = (source.get("WINRE_EXTERNAL_CAPTURE") or "").strip().lower()
    if explicit in {"0", "false", "no", "off"}:
        return None
    # The old gateway variable must not select a stale gateway policy file.
    # Passive capture is configured independently at the capture sensor path.
    config_path = Path(source.get("WINRE_CAPTURE_CONFIG") or DEFAULT_CONFIG)
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if explicit in {"1", "true", "yes", "on"}:
            raise RuntimeError(f"external capture requested but config is missing: {config_path}")
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not read external capture config {config_path}: {exc}") from exc
    if not isinstance(config, dict) or config.get("enabled") is not True:
        if explicit in {"1", "true", "yes", "on"}:
            raise RuntimeError(f"external capture config is not enabled: {config_path}")
        return None
    mode = str(config.get("mode") or "passive").strip().lower()
    if mode != "passive":
        raise RuntimeError(f"unsupported external capture mode: {mode}")
    iface = (source.get("WINRE_CAPTURE_INTERFACE") or config.get("interface") or "").strip()
    guest = (source.get("WINRE_CAPTURE_GUEST_IP") or config.get("guest_ip") or "").strip()
    capture_filter = (source.get("WINRE_CAPTURE_FILTER") or config.get("capture_filter") or "").strip()
    if not iface or not guest or not capture_filter:
        raise RuntimeError("capture config requires interface, guest_ip, and capture_filter")
    try:
        guest = str(ipaddress.IPv4Address(guest))
    except ipaddress.AddressValueError as exc:
        raise RuntimeError(f"capture guest_ip is not valid IPv4: {guest}") from exc
    if capture_filter != f"host {guest}":
        raise RuntimeError("capture_filter must be exactly 'host <guest_ip>'")
    if config.get("promiscuous") is not True:
        raise RuntimeError("passive WinRE capture requires promiscuous mode")
    return {**config, "interface": iface, "guest_ip": guest,
            "capture_filter": capture_filter, "mode": mode,
            "promiscuous": True,
            "config_path": str(config_path)}


def require_config(env: dict[str, str] | None = None) -> dict[str, Any]:
    """Require the passive sensor for an integrated remote dynamic run."""
    config = load_config(env)
    if config is None:
        raise RuntimeError(
            "remote dynamic execution requires configured passive tcpdump capture; "
            "run RevAI install/setup-winre-capture.sh with WinRE enabled")
    return config


def verify_capture_host(config: dict[str, Any]) -> None:
    """Verify the passive REMnux capture interface without requiring routing."""
    if config.get("forwarding") is not False:
        raise RuntimeError("capture host policy must declare forwarding=false")
    if not sys.platform.startswith("linux"):
        return

    def run(argv: list[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(argv, capture_output=True, text=True,
                                  timeout=8, check=False,
                                  encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"capture preflight command failed ({argv[0]}): {exc}") from exc

    interface = str(config["interface"])
    link = run(["ip", "-o", "link", "show", "dev", interface])
    if link.returncode or "state UP" not in link.stdout:
        raise RuntimeError(f"capture interface {interface} is not up")
    addr = run(["ip", "-o", "-4", "addr", "show", "dev", interface])
    host_ip = str(config.get("host_ip") or config.get("gateway_ip") or "")
    if addr.returncode or not host_ip or host_ip not in addr.stdout:
        raise RuntimeError(f"capture host address is not bound to {interface}")
    for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
                "net.ipv6.conf.default.forwarding"):
        value = run(["sysctl", "-n", key])
        if value.returncode or value.stdout.strip() != "0":
            raise RuntimeError(f"{key} must be 0 before capture/dynamic execution")

    mode = str(config.get("mode") or "passive").strip().lower()
    if mode != "passive":
        raise RuntimeError(f"unsupported external capture mode: {mode}")
    return


# Kept as an import alias for downstream integrations that used the old name.
verify_gateway = verify_capture_host


@dataclass
class CaptureSession:
    config: dict[str, Any]
    work_dir: Path
    pcap_path: Path
    process: subprocess.Popen
    stderr_file: Any
    started_at: str
    started_monotonic: float

    @classmethod
    def start(cls, config: dict[str, Any]) -> "CaptureSession":
        verify_capture_host(config)
        tcpdump = shutil.which("tcpdump")
        if not tcpdump:
            raise RuntimeError("tcpdump is unavailable on the control plane")
        work_dir = Path(tempfile.mkdtemp(prefix="winre-external-capture-"))
        pcap_path = work_dir / "vmnet2.pcap"
        stderr_path = work_dir / "tcpdump.stderr.txt"
        stderr_file = stderr_path.open("wb")
        argv = [tcpdump, "-U", "-n", "-i", str(config["interface"]),
                "-w", str(pcap_path), str(config["capture_filter"])]
        # tcpdump requests promiscuous mode by default; deliberately omit -p
        # so the interface requests all frames VMware delivers to it.
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=stderr_file)
            time.sleep(0.25)
            if proc.poll() is not None:
                stderr_file.flush()
                details = stderr_path.read_text(encoding="utf-8", errors="replace")[-500:]
                stderr_file.close()
                shutil.rmtree(work_dir, ignore_errors=True)
                raise RuntimeError(f"tcpdump exited during startup ({proc.returncode}): {details}")
        except Exception:
            if not stderr_file.closed:
                stderr_file.close()
            shutil.rmtree(work_dir, ignore_errors=True)
            raise
        return cls(config=config, work_dir=work_dir, pcap_path=pcap_path,
                   process=proc, stderr_file=stderr_file,
                   started_at=_utc(), started_monotonic=time.monotonic())

    def stop(self) -> dict[str, Any]:
        """Stop capture, validate its pcap container, and return terminal facts."""
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            returncode = self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                returncode = self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                returncode = self.process.wait(timeout=5)
        self.stderr_file.flush()
        self.stderr_file.close()
        stderr_path = self.work_dir / "tcpdump.stderr.txt"
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace")[-1000:]
        record: dict[str, Any] = {
            "schema": "winre-external-capture/v1",
            "requested": True,
            "status": "failed",
            "mode": str(self.config.get("mode") or "passive"),
            "promiscuous": True,
            "interface": self.config["interface"],
            "guest_ip": self.config["guest_ip"],
            "capture_filter": self.config["capture_filter"],
            "started_at": self.started_at,
            "finished_at": _utc(),
            "elapsed_s": round(time.monotonic() - self.started_monotonic, 3),
            "returncode": returncode,
            "stderr_tail": stderr,
        }
        try:
            size = self.pcap_path.stat().st_size
            with self.pcap_path.open("rb") as fh:
                magic = fh.read(4)
            pcap_magics = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                           b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
            if size < 24 or magic not in pcap_magics:
                raise ValueError(f"invalid pcap file (size={size}, magic={magic.hex()})")
            digest = _sha256_file(self.pcap_path)
            packet_match = re.search(r"(\d+) packets captured", stderr)
            record.update({"status": "collected" if returncode == 0 else "partial",
                           "pcap_size": size, "pcap_sha256": digest,
                           "pcap_name": "vmnet2.pcap",
                           "packets_captured": int(packet_match.group(1)) if packet_match else None})
            if returncode != 0:
                record["reason"] = f"tcpdump exited with {returncode} after writing a valid pcap"
        except (OSError, ValueError) as exc:
            record["reason"] = str(exc)[:300]
        return record

    def promote(self, stage_dir: Path, record: dict[str, Any]) -> dict[str, Any]:
        """Copy validated capture into the pack and write its provenance sidecar."""
        if record.get("status") not in {"collected", "partial"}:
            return record
        target_dir = Path(stage_dir) / "off_box" / "network_raw"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "vmnet2.pcap"
        shutil.copy2(self.pcap_path, target)
        digest = _sha256_file(target)
        if digest != record.get("pcap_sha256"):
            record = {**record, "status": "failed",
                      "reason": "capture hash changed while promoting into the evidence pack"}
            target.unlink(missing_ok=True)
            return record
        record = {**record,
                  "path": "off_box/network_raw/vmnet2.pcap",
                  "promoted_sha256": digest}
        sidecar = Path(stage_dir) / "off_box" / "capture.json"
        sidecar.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return record

    def cleanup(self) -> None:
        try:
            if not self.stderr_file.closed:
                self.stderr_file.close()
        finally:
            shutil.rmtree(self.work_dir, ignore_errors=True)
