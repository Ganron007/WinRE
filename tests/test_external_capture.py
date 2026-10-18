import json
from pathlib import Path
import subprocess

import pytest

from winre import external_capture, manifest, remote_driver


def test_capture_config_is_opt_in_without_installed_sensor(tmp_path):
    assert external_capture.load_config({
        "WINRE_CAPTURE_CONFIG": str(tmp_path / "absent.json")
    }) is None

    with pytest.raises(RuntimeError, match="config is missing"):
        external_capture.load_config({
            "WINRE_EXTERNAL_CAPTURE": "1",
            "WINRE_CAPTURE_CONFIG": str(tmp_path / "absent.json"),
        })


def test_remote_dynamic_requires_capture_config_before_guest_launch(tmp_path):
    with pytest.raises(RuntimeError, match="requires configured passive tcpdump capture"):
        external_capture.require_config({
            "WINRE_EXTERNAL_CAPTURE": "0",
            "WINRE_CAPTURE_CONFIG": str(tmp_path / "absent.json"),
        })


def test_capture_config_uses_installed_passive_sensor_and_interface_override(tmp_path):
    config_path = tmp_path / "capture.json"
    config_path.write_text(json.dumps({
        "schema": "winre-capture/v1", "enabled": True,
        "mode": "passive", "promiscuous": True,
        "interface": "ens32", "guest_ip": "192.168.77.42",
        "host_ip": "192.168.77.43", "forwarding": False,
        "capture_filter": "host 192.168.77.42",
    }), encoding="utf-8")

    config = external_capture.load_config({
        "WINRE_CAPTURE_CONFIG": str(config_path),
        "WINRE_CAPTURE_INTERFACE": "ens33",
    })

    assert config["interface"] == "ens33"
    assert config["capture_filter"] == "host 192.168.77.42"
    assert config["guest_ip"] == "192.168.77.42"
    assert config["mode"] == "passive"
    assert config["promiscuous"] is True


def test_require_config_reads_installed_config_from_process_environment(
        tmp_path, monkeypatch):
    config_path = tmp_path / "capture.json"
    config_path.write_text(json.dumps({
        "schema": "winre-capture/v1", "enabled": True,
        "mode": "passive", "promiscuous": True,
        "interface": "ens32", "guest_ip": "192.168.77.42",
        "host_ip": "192.168.77.43", "forwarding": False,
        "capture_filter": "host 192.168.77.42",
    }), encoding="utf-8")
    monkeypatch.setenv("WINRE_CAPTURE_CONFIG", str(config_path))
    monkeypatch.delenv("WINRE_EXTERNAL_CAPTURE", raising=False)

    config = external_capture.require_config()

    assert config["interface"] == "ens32"
    assert config["promiscuous"] is True


def test_legacy_gateway_env_cannot_override_passive_capture_config(
        tmp_path, monkeypatch):
    current = tmp_path / "current-capture.json"
    current.write_text(json.dumps({
        "enabled": True, "mode": "passive", "promiscuous": True,
        "interface": "ens32", "guest_ip": "192.168.77.42",
        "host_ip": "192.168.77.43", "forwarding": False,
        "capture_filter": "host 192.168.77.42",
    }), encoding="utf-8")
    old = tmp_path / "old-gateway.json"
    old.write_text(json.dumps({
        "enabled": True, "mode": "gateway", "promiscuous": False,
    }), encoding="utf-8")
    monkeypatch.setattr(external_capture, "DEFAULT_CONFIG", current)

    config = external_capture.load_config({"WINRE_GATEWAY_CONFIG": str(old)})

    assert config["mode"] == "passive"
    assert config["config_path"] == str(current)


def test_passive_capture_preflight_does_not_require_gateway_services(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        stdout = ""
        if argv[0] == "ip":
            if "link" in argv:
                stdout = "2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP"
            else:
                stdout = "2: ens32 inet 192.168.77.43/24 scope global ens32"
        elif argv[0] == "sysctl":
            stdout = "0\n"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(external_capture.sys, "platform", "linux")
    monkeypatch.setattr(external_capture.subprocess, "run", fake_run)

    external_capture.verify_capture_host({
        "forwarding": False,
        "mode": "passive",
        "interface": "ens32",
        "guest_ip": "192.168.77.42",
        "host_ip": "192.168.77.43",
    })

    assert not any("nft" in argv for argv in calls)
    assert any(argv[:4] == ["ip", "-o", "link", "show"] for argv in calls)


def test_external_capture_can_be_optional_for_standalone_runs():
    requested = remote_driver._requested_sources(None, {
        "execution_kind": "dynamic", "network_mode": "passive",
        "external_capture_requested": True,
        "external_capture_required": False,
    })

    assert requested["network"] == {"requested": True, "required": True}
    assert requested["external_capture"] == {"requested": True, "required": False}


def test_integrated_capture_is_required_when_explicitly_marked():
    requested = remote_driver._requested_sources(None, {
        "execution_kind": "dynamic", "network_mode": "passive",
        "external_capture_requested": True,
        "external_capture_required": True,
    })

    assert requested["network"] == {"requested": True, "required": True}
    assert requested["external_capture"] == {"requested": True, "required": True}


def test_manifest_uses_run_scoped_capture_terminal_record(tmp_path):
    off_box = tmp_path / "off_box"
    (off_box / "network_raw").mkdir(parents=True)
    (off_box / "network_raw" / "vmnet2.pcap").write_bytes(
        b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    (off_box / "capture.json").write_text(json.dumps({
        "requested": True, "status": "collected", "run_id": "run-1",
    }), encoding="utf-8")

    result = manifest._terminal(
        "external_capture", tmp_path, {"external_capture_requested": True},
        {}, "run-1")
    wrong_run = manifest._terminal(
        "external_capture", tmp_path, {"external_capture_requested": True},
        {}, "run-2")

    assert result["status"] == "completed"
    assert wrong_run["status"] == "failed"


def test_capture_starts_tcpdump_promiscuously_for_only_the_guest_ip(monkeypatch, tmp_path):
    captured = {}

    class FakeProcess:
        returncode = None

        def __init__(self, argv, kwargs):
            self.stderr = kwargs["stderr"]
            self.pcap = Path(argv[argv.index("-w") + 1])
            self.pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

        def poll(self):
            return self.returncode

        def send_signal(self, _sig):
            self.returncode = 0

        def wait(self, timeout=None):
            self.stderr.write(b"0 packets captured\n")
            self.stderr.flush()
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return FakeProcess(argv, kwargs)

    monkeypatch.setattr(external_capture, "verify_capture_host", lambda _cfg: None)
    monkeypatch.setattr(external_capture.shutil, "which", lambda name: "/usr/sbin/tcpdump")
    monkeypatch.setattr(external_capture.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(external_capture.time, "sleep", lambda _seconds: None)
    work_dir = tmp_path / "capture-work"

    def fake_mkdtemp(prefix):
        work_dir.mkdir()
        return str(work_dir)

    monkeypatch.setattr(external_capture.tempfile, "mkdtemp", fake_mkdtemp)

    session = external_capture.CaptureSession.start({
        "forwarding": False, "mode": "passive", "promiscuous": True,
        "interface": "ens32", "guest_ip": "192.168.77.42",
        "host_ip": "192.168.77.43", "capture_filter": "host 192.168.77.42",
    })
    record = session.stop()
    session.cleanup()

    argv = captured["argv"]
    assert argv[0] == "/usr/sbin/tcpdump"
    assert "-p" not in argv
    assert argv[argv.index("-i") + 1] == "ens32"
    assert argv[-1] == "host 192.168.77.42"
    assert record["status"] == "collected"
    assert record["packets_captured"] == 0
    assert record["pcap_name"] == "vmnet2.pcap"


def test_capture_rejects_legacy_gateway_mode(tmp_path):
    config_path = tmp_path / "legacy.json"
    config_path.write_text(json.dumps({
        "enabled": True, "mode": "gateway", "interface": "ens32",
        "guest_ip": "192.168.77.42", "host_ip": "192.168.77.43",
        "forwarding": False, "capture_filter": "host 192.168.77.42",
    }), encoding="utf-8")

    with pytest.raises(RuntimeError, match="unsupported external capture mode"):
        external_capture.load_config({"WINRE_CAPTURE_CONFIG": str(config_path)})


def test_capture_rejects_unscoped_filter_and_non_promiscuous_config(tmp_path):
    config_path = tmp_path / "capture.json"
    base = {
        "enabled": True, "mode": "passive", "interface": "ens32",
        "guest_ip": "192.168.77.42", "host_ip": "192.168.77.43",
        "forwarding": False, "promiscuous": True,
        "capture_filter": "host 192.168.77.42",
    }
    config_path.write_text(json.dumps({**base, "capture_filter": "ip"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="exactly 'host <guest_ip>'"):
        external_capture.load_config({"WINRE_CAPTURE_CONFIG": str(config_path)})

    config_path.write_text(json.dumps({**base, "promiscuous": False}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="requires promiscuous mode"):
        external_capture.load_config({"WINRE_CAPTURE_CONFIG": str(config_path)})
