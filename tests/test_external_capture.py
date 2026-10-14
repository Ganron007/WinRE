import json
from pathlib import Path

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
