"""Run-scoped off-box packet capture for the REMnux/Flare gateway topology.

The capture configuration is installed on the control plane by
RevAI's ``install/setup-winre-gateway.sh``. Captures are raw evidence and are
placed under ``dynamic/off_box/network_raw`` only after the collection process
has stopped and the pcap header/hash have been checked.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any


DEFAULT_CONFIG = Path("/etc/revai/winre-gateway.json")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_config(env: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Return enabled gateway settings, or None when off-box capture is absent."""
    source = os.environ if env is None else env
    explicit = (source.get("WINRE_EXTERNAL_CAPTURE") or "").strip().lower()
    if explicit in {"0", "false", "no", "off"}:
        return None
    config_path = Path(source.get("WINRE_GATEWAY_CONFIG") or DEFAULT_CONFIG)
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if explicit in {"1", "true", "yes", "on"}:
            raise RuntimeError(f"external capture requested but config is missing: {config_path}")
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not read gateway capture config {config_path}: {exc}") from exc
    if not isinstance(config, dict) or config.get("enabled") is not True:
        if explicit in {"1", "true", "yes", "on"}:
            raise RuntimeError(f"gateway capture config is not enabled: {config_path}")
        return None
    iface = (source.get("WINRE_CAPTURE_INTERFACE") or config.get("interface") or "").strip()
    guest = (source.get("WINRE_CAPTURE_GUEST_IP") or config.get("guest_ip") or "").strip()
    capture_filter = (source.get("WINRE_CAPTURE_FILTER") or config.get("capture_filter") or "").strip()
    if not iface or not guest or not capture_filter:
        raise RuntimeError("gateway capture config requires interface, guest_ip, and capture_filter")
    return {**config, "interface": iface, "guest_ip": guest,
            "capture_filter": capture_filter, "config_path": str(config_path)}


def verify_gateway(config: dict[str, Any]) -> None:
    """Fail closed if the persistent simulator/containment policy is inactive."""
    if config.get("forwarding") is not False:
        raise RuntimeError("gateway policy must declare forwarding=false")
    if not sys.platform.startswith("linux"):
        return

    def run(argv: list[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(argv, capture_output=True, text=True,
                                  timeout=8, check=False,
                                  encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"gateway preflight command failed ({argv[0]}): {exc}") from exc

    addr = run(["ip", "-o", "-4", "addr", "show", "dev", str(config["interface"])])
    if addr.returncode or str(config.get("gateway_ip", "")) not in addr.stdout:
        raise RuntimeError(f"gateway address is not bound to {config['interface']}")
    for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
                "net.ipv6.conf.default.forwarding"):
        value = run(["sysctl", "-n", key])
        if value.returncode or value.stdout.strip() != "0":
            raise RuntimeError(f"{key} must be 0 before dynamic execution")
    active = run(["systemctl", "is-active", "--quiet", "inetsim.service"])
    if active.returncode:
        raise RuntimeError("INetSim is not active")
    for service in ("inetsim.service", "winre-guest-guard.service",
                    "winre-dnsmasq.service"):
        enabled = run(["systemctl", "is-enabled", "--quiet", service])
        if enabled.returncode:
            raise RuntimeError(f"{service} is not enabled for reboot persistence")
    guard = run(["systemctl", "is-active", "--quiet", "winre-guest-guard.service"])
    if guard.returncode:
        raise RuntimeError("WinRE guest firewall/NAT policy is not active")
    dns = run(["systemctl", "is-active", "--quiet", "winre-dnsmasq.service"])
    if dns.returncode:
        raise RuntimeError("WinRE DNS simulator is not active")
    for family, table in (("inet", "winre_guest_guard"),
                          ("ip", "winre_guest_nat")):
        result = run(["nft", "list", "table", family, table])
        if result.returncode:
            raise RuntimeError(f"nftables containment table is missing: {family} {table}")
    guard_json = run(["nft", "-j", "list", "table", "inet", "winre_guest_guard"])
    try:
        guard = json.loads(guard_json.stdout)
        chains = [item["chain"] for item in guard["nftables"] if "chain" in item]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError(f"could not inspect nftables guest guard: {exc}") from exc
    if guard_json.returncode or not any(
            chain.get("name") == "forward" and chain.get("hook") == "forward"
            and chain.get("policy") == "drop" for chain in chains):
        raise RuntimeError("nftables guest forwarding policy is not drop")
    listeners = run(["ss", "-H", "-lntup"])
    gateway_ip = str(config.get("gateway_ip", ""))
    if listeners.returncode or f"{gateway_ip}:53" not in listeners.stdout:
        raise RuntimeError(f"INetSim DNS is not listening on {gateway_ip}:53")
    if f"{gateway_ip}:80" not in listeners.stdout:
        raise RuntimeError(f"INetSim HTTP is not listening on {gateway_ip}:80")


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
        verify_gateway(config)
        dumpcap = shutil.which("dumpcap")
        if not dumpcap:
            raise RuntimeError("dumpcap is unavailable on the control plane")
        work_dir = Path(tempfile.mkdtemp(prefix="winre-gateway-capture-"))
        pcap_path = work_dir / "gateway.pcapng"
        stderr_path = work_dir / "dumpcap.stderr.txt"
        stderr_file = stderr_path.open("wb")
        argv = [dumpcap, "-q", "-i", str(config["interface"]),
                "-f", str(config["capture_filter"]), "-w", str(pcap_path)]
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=stderr_file)
            time.sleep(0.25)
            if proc.poll() is not None:
                stderr_file.flush()
                details = stderr_path.read_text(encoding="utf-8", errors="replace")[-500:]
                stderr_file.close()
                shutil.rmtree(work_dir, ignore_errors=True)
                raise RuntimeError(f"dumpcap exited during startup ({proc.returncode}): {details}")
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
        stderr_path = self.work_dir / "dumpcap.stderr.txt"
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace")[-1000:]
        record: dict[str, Any] = {
            "schema": "winre-external-capture/v1",
            "requested": True,
            "status": "failed",
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
            if size < 24 or magic != b"\x0a\x0d\x0d\x0a":
                raise ValueError(f"invalid pcapng file (size={size}, magic={magic.hex()})")
            digest = _sha256_file(self.pcap_path)
            record.update({"status": "collected" if returncode == 0 else "partial",
                           "pcap_size": size, "pcap_sha256": digest,
                           "pcap_name": "gateway.pcapng"})
            if returncode != 0:
                record["reason"] = f"dumpcap exited with {returncode} after writing a valid pcapng"
        except (OSError, ValueError) as exc:
            record["reason"] = str(exc)[:300]
        return record

    def promote(self, stage_dir: Path, record: dict[str, Any]) -> dict[str, Any]:
        """Copy validated capture into the pack and write its provenance sidecar."""
        if record.get("status") not in {"collected", "partial"}:
            return record
        target_dir = Path(stage_dir) / "off_box" / "network_raw"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "gateway.pcapng"
        shutil.copy2(self.pcap_path, target)
        digest = _sha256_file(target)
        if digest != record.get("pcap_sha256"):
            record = {**record, "status": "failed",
                      "reason": "capture hash changed while promoting into the evidence pack"}
            target.unlink(missing_ok=True)
            return record
        record = {**record,
                  "path": "off_box/network_raw/gateway.pcapng",
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
