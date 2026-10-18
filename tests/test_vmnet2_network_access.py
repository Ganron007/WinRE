"""Exercise the WinRE VMnet2 contract: peer access stays open for SSH/MCP."""
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_setup_removes_legacy_peer_blocks_and_allows_vmnet2_local_subnet():
    source = (ROOT / "install" / "setup-flarevm.ps1").read_text(encoding="utf-8")

    assert 'Get-NetFirewallRule -DisplayName "$networkRulePrefix -*"' in source
    assert 'RemoteAddress = "LocalSubnet"' in source
    assert '"WinRE SSH (VMnet2 LocalSubnet)"' in source
    assert '"WinRE x64dbg MCP (VMnet2 x64)"' in source
    assert '"WinRE x64dbg MCP (VMnet2 x86)"' in source
    assert "Set-NetFirewallProfile" not in source
    assert "block IPv6" not in source


@pytest.mark.parametrize("defect", [
    "none", "legacy_peer", "missing_ssh", "disabled", "block",
    "direction", "remote", "port",
])
def test_verifier_rejects_peer_blocks_or_ineffective_local_subnet_allows(
        tmp_path, defect):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell is required to execute the Windows verifier")

    source = (ROOT / "install" / "verify-flarevm.ps1").read_text(encoding="utf-8")
    start = source.index("$legacyNetworkRules = @(")
    end = source.index('Write-Host ""', start)
    block = source[start:end]
    harness = r'''
param([string]$Defect)
$ErrorActionPreference = 'Stop'
$script:Failed = $false
function Ok($message) { Write-Output "OK: $message" }
function Fail($message) { $script:Failed = $true; Write-Output "FAIL: $message" }
function Get-NetFirewallRule {
    [CmdletBinding()] param($PolicyStore, $DisplayName)
    if ($DisplayName -eq 'WinRE isolated analysis network -*') {
        if ($Defect -eq 'legacy_peer') { return [pscustomobject]@{ DisplayName = 'old peer block' } }
        return @()
    }
    if ($DisplayName -eq 'WinRE x64dbg MCP (lab subnet)') { return @() }
    $port = if ($DisplayName -eq 'WinRE SSH (VMnet2 LocalSubnet)') { '22' }
            elseif ($DisplayName -eq 'WinRE x64dbg MCP (VMnet2 x64)') { '9094' }
            else { '9095' }
    if ($Defect -eq 'missing_ssh' -and $port -eq '22') { return $null }
    [pscustomobject]@{
        Enabled = $(if ($Defect -eq 'disabled' -and $port -eq '22') { 'False' } else { 'True' })
        Action = $(if ($Defect -eq 'block' -and $port -eq '22') { 'Block' } else { 'Allow' })
        Direction = $(if ($Defect -eq 'direction' -and $port -eq '22') { 'Outbound' } else { 'Inbound' })
        Port = $port
    }
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{ RemoteAddress = @($(if ($Defect -eq 'remote' -and $AssociatedNetFirewallRule.Port -eq '22') { '192.168.77.43' } else { 'LocalSubnet' })) }
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{ LocalPort = @($(if ($Defect -eq 'port' -and $AssociatedNetFirewallRule.Port -eq '22') { '2222' } else { $AssociatedNetFirewallRule.Port })) }
}
'''
    script = tmp_path / "verify-network.ps1"
    script.write_text(harness + block + "\nif ($script:Failed) { exit 1 }\n",
                      encoding="utf-8")
    result = subprocess.run(
        [shell, "-NoProfile", "-File", str(script), defect],
        capture_output=True, text=True, timeout=30,
    )

    expected_ok = defect == "none"
    assert result.returncode == (0 if expected_ok else 1), result.stdout + result.stderr
    if expected_ok:
        assert "OK: TCP 22 is allowed from VMnet2 LocalSubnet" in result.stdout
    else:
        assert "FAIL:" in result.stdout
