"""Controls for the debugger-MCP reachability contract (2026-10-23/24).

The first agentic-dbg acceptance run on s02 produced a pack with a correct
verdict but no debugger at all: `dbg_ensure` reported

    "x64dbg MCP not answering on :9094/9095 after 45s (launched x32dbg.exe)"

while the plugin WAS listening on 0.0.0.0:9095 on the VM. The cause was not
the plugin, the port or the launcher: Windows Firewall had auto-created two
inbound **Block** rules for x32dbg.exe (Public profile), and Block beats
Allow in Windows Firewall regardless of rule order - so the WinRE allow rules
for :9094/:9095 were inert.

Windows creates such a rule the first time a program listens on a
Public-profile adapter, which is also what makes it prompt "allow x64dbg
access?". This lab is air-gapped on VMnet2, so the firewall buys nothing and
only breaks the lab plane; setup now disables it on every profile and pins it
by policy.

Three contracts are enforced here:

  1. setup-flarevm.ps1 disables the firewall on every profile AND pins it in
     policy, so a refresh cannot silently re-enable it (and no prompt can
     appear);
  2. the debug-session preflight disables any auto-created debugger block rule
     before it probes or launches (defence in depth if the firewall is ever
     re-enabled);
  3. the launcher stops a stale scheduled-task instance first - Start on an
     already-Running task is a silent no-op, which is why the 64-bit flavour
     never started after a killed 32-bit session.
"""
from __future__ import annotations

from pathlib import Path

from winre.mcp import x64dbg_manager as M

ROOT = Path(__file__).resolve().parents[1]


class _FakeClient:
    """An x64dbg MCP client that is already answering."""

    base = "http://192.168.77.42:9095"
    MCP_PORTS = [9094, 9095]

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    @classmethod
    def forget_port(cls) -> None:
        return None

    def is_up(self) -> bool:
        return True


def test_preflight_disables_the_debugger_block_rules_before_probing(monkeypatch):
    """The heal must run BEFORE the probe: a blocked port looks exactly like a
    debugger that is not running, and the old code reacted by relaunching."""
    events: list[str] = []

    def fake_heal(cfg):
        events.append("heal")
        return {"disabled": ["TCP Query User{...}x32dbg.exe"]}

    def fake_up(self):
        events.append("probe")
        return True

    monkeypatch.setattr(M, "_heal_firewall_vm", fake_heal)
    monkeypatch.setattr(M, "_running_arch_vm", lambda cfg: 32)
    monkeypatch.setattr(M, "xdbg_arch", lambda sample, cfg=None: 32)
    monkeypatch.setattr(M.X64DbgClient, "__init__",
                        lambda self, *a, **k: _FakeClient.__init__(self, *a, **k))
    monkeypatch.setattr(M.X64DbgClient, "is_up", fake_up)
    monkeypatch.setattr(M.X64DbgClient, "forget_port", classmethod(lambda cls: None))
    monkeypatch.setattr(M.X64DbgClient, "MCP_PORTS", [9094, 9095], raising=False)

    ok, info = M.ensure_mcp(cfg={"host": "192.168.77.42"}, wait_s=1,
                            sample=None)

    assert ok is True, info
    assert events[0] == "heal" and "probe" in events, events
    assert info["already_up"] is True
    assert info["firewall_healed"], (
        "the disabled rule must be recorded so a pack can show why the port "
        "became reachable")


def test_launcher_stops_a_stale_task_before_starting(monkeypatch):
    """Start-ScheduledTask on an already-Running task is a silent no-op.

    Observed live: after the 32-bit debugger was killed externally the task
    stayed "Running", so the 64-bit launch never happened and ensure_mcp timed
    out with the process absent.
    """
    seen: dict[str, str] = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_ssh_run(cfg, ps, timeout=60):
        seen["ps"] = ps
        return _Result()

    monkeypatch.setattr(M.remote_driver, "ssh_run", fake_ssh_run)
    assert M._launch_on_vm({"host": "192.168.77.42"}, arch=64) is True
    ps = seen["ps"]
    assert "Stop-ScheduledTask" in ps, ps
    assert ps.index("Stop-ScheduledTask") < ps.index("Start-ScheduledTask"), ps
    assert "x64dbg.exe" in ps


def test_setup_disables_the_firewall_on_every_profile_and_pins_it():
    """The deployment itself must leave the firewall off (FLARE-VM default).

    Without this the first debugger launch raises a Windows Security prompt on
    the Public-profile adapter and, unanswered, silently creates the inbound
    Block rule that made the debugger MCP unreachable.
    """
    setup = (ROOT / "install" / "setup-flarevm.ps1").read_text(
        encoding="utf-8", errors="replace")
    assert "Set-NetFirewallProfile" in setup
    assert "-Profile Domain,Private,Public -Enabled False" in setup
    # pin it so a policy refresh cannot turn it back on
    assert 'New-ItemProperty -LiteralPath $profilePath -Name "EnableFirewall" -Value 0' in setup
    assert "DisableNotifications" in setup
    # and suppress the prompt itself
    assert "-NotifyOnListen False" in setup


def test_verify_fails_when_the_firewall_is_enabled():
    """The battery must catch a host where something re-enabled the firewall,
    because an enabled Public-profile firewall re-creates the block rule."""
    verify = (ROOT / "install" / "verify-flarevm.ps1").read_text(
        encoding="utf-8", errors="replace")
    assert "Get-NetFirewallProfile" in verify
    assert "Windows Firewall is ENABLED on:" in verify
    assert "no inbound block rule shadows the debugger MCP allow rules" in verify
    assert "firewall is disabled - no rule can shadow the debugger MCP" in verify
