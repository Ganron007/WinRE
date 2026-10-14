from winre import remote_driver


def test_flare_cfg_uses_optional_gateway_for_ssh_and_scp(monkeypatch):
    monkeypatch.setenv("FLARE_HOST", "192.168.77.42")
    monkeypatch.setenv("FLARE_USER", "FLARE-VM")
    monkeypatch.setenv("FLARE_SSH_KEY", r"C:\keys\flare")
    monkeypatch.setenv("WINRE_GATEWAY_HOST", "192.168.77.43")
    monkeypatch.setenv("WINRE_GATEWAY_USER", "remnux")
    monkeypatch.setenv("WINRE_GATEWAY_SSH_KEY", r"C:\keys\gateway")

    cfg = remote_driver.flare_cfg()

    assert cfg["proxy_command"] == (
        'ssh -i "C:\\keys\\gateway" -o IdentitiesOnly=yes '
        "-o BatchMode=yes -o StrictHostKeyChecking=no "
        "-W %h:%p remnux@192.168.77.43")
    assert "ProxyCommand=" + cfg["proxy_command"] in remote_driver._ssh_base(cfg)
    assert "ProxyCommand=" + cfg["proxy_command"] in remote_driver._scp_base(cfg)


def test_gateway_host_without_gateway_key_fails_early(monkeypatch):
    monkeypatch.setenv("WINRE_GATEWAY_HOST", "192.168.77.43")
    monkeypatch.delenv("WINRE_GATEWAY_SSH_KEY", raising=False)

    try:
        remote_driver.flare_cfg()
    except ValueError as exc:
        assert "WINRE_GATEWAY_SSH_KEY" in str(exc)
    else:
        raise AssertionError("incomplete gateway configuration was accepted")


def test_flare_cfg_keeps_direct_route_when_no_gateway_is_configured(monkeypatch):
    monkeypatch.delenv("WINRE_GATEWAY_HOST", raising=False)
    monkeypatch.delenv("WINRE_GATEWAY_SSH_KEY", raising=False)

    cfg = remote_driver.flare_cfg()

    assert cfg["proxy_command"] == ""
    assert not any(arg.startswith("ProxyCommand=")
                   for arg in remote_driver._ssh_base(cfg))
    assert not any(arg.startswith("ProxyCommand=")
                   for arg in remote_driver._scp_base(cfg))
