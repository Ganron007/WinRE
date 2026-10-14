import json
from pathlib import Path
import subprocess

import pytest

from winre import external_capture, manifest, remote_driver


def test_capture_config_is_opt_in_without_installed_gateway(tmp_path):
    assert external_capture.load_config({
        "WINRE_GATEWAY_CONFIG": str(tmp_path / "absent.json")
    }) is None

    with pytest.raises(RuntimeError, match="config is missing"):
        external_capture.load_config({
            "WINRE_EXTERNAL_CAPTURE": "1",
            "WINRE_GATEWAY_CONFIG": str(tmp_path / "absent.json"),
        })


def test_capture_config_uses_installed_gateway_and_per_run_overrides(tmp_path):
    config_path = tmp_path / "gateway.json"
    config_path.write_text(json.dumps({
        "schema": "winre-gateway/v1", "enabled": True,
        "interface": "ens32", "guest_ip": "192.168.77.42",
        "capture_filter": "host 192.168.77.42",
    }), encoding="utf-8")

    config = external_capture.load_config({
        "WINRE_GATEWAY_CONFIG": str(config_path),
        "WINRE_CAPTURE_INTERFACE": "ens33",
        "WINRE_CAPTURE_FILTER": "host 192.168.77.42 and tcp",
    })

    assert config["interface"] == "ens33"
    assert config["capture_filter"] == "host 192.168.77.42 and tcp"
    assert config["guest_ip"] == "192.168.77.42"


def test_non_root_gateway_preflight_uses_sudo_for_live_nftables(monkeypatch):
    calls = []
    input_rules = (
        'ct state established,related accept\n'
        'iifname "ens32" ip saddr 192.168.77.1 tcp dport 22 accept\n'
        'iifname "ens32" drop\n'
    )
    nat_rules = (
        'udp dport 53 dnat to 192.168.77.43:53\n'
        'tcp dport 53 dnat to 192.168.77.43:53\n'
        'tcp dport { 21, 25, 80, 443 } dnat to 192.168.77.43\n'
    )

    def fake_run(argv, **kwargs):
        calls.append(argv)
        stdout = ""
        if argv[0] == "ip":
            stdout = "2: ens32 inet 192.168.77.43/24 scope global ens32"
        elif argv[0] == "sysctl":
            stdout = "0\n"
        elif argv[:3] == ["sudo", "-n", "nft"]:
            if argv[3:6] == ["list", "chain", "inet"] and argv[-1] == "input":
                stdout = input_rules
            elif argv[3:6] == ["list", "chain", "ip"]:
                stdout = nat_rules
            elif argv[3:6] == ["-j", "list", "table"]:
                stdout = json.dumps({"nftables": [{"chain": {
                    "name": "forward", "hook": "forward", "policy": "drop",
                }}]})
        elif argv[0] == "ss":
            stdout = "udp 192.168.77.43:53\ntcp 192.168.77.43:80"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(external_capture.sys, "platform", "linux")
    monkeypatch.setattr(external_capture.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(external_capture.subprocess, "run", fake_run)

    external_capture.verify_gateway({
        "forwarding": False,
        "interface": "ens32",
        "guest_ip": "192.168.77.42",
        "gateway_ip": "192.168.77.43",
        "management_ip": "192.168.77.1",
    })

    nft_calls = [argv for argv in calls if "nft" in argv]
    assert nft_calls
    assert all(argv[:3] == ["sudo", "-n", "nft"] for argv in nft_calls)


def test_external_capture_is_required_in_gateway_mode():
    requested = remote_driver._requested_sources(None, {
        "execution_kind": "dynamic", "network_mode": "gateway",
        "external_capture_requested": True,
    })

    assert requested["network"] == {"requested": False, "required": False}
    assert requested["external_capture"] == {"requested": True, "required": True}


def test_manifest_uses_run_scoped_capture_terminal_record(tmp_path):
    off_box = tmp_path / "off_box"
    (off_box / "network_raw").mkdir(parents=True)
    (off_box / "network_raw" / "gateway.pcapng").write_bytes(
        b"\x0a\x0d\x0d\x0a" + b"\x00" * 24)
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
