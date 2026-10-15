"""Exercise the shipped verifier against effective firewall filter defects."""
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("defect", [
    "none", "missing", "disabled", "allow", "direction", "profile",
    "remote", "half", "local", "protocol", "local_port", "remote_port", "interface",
])
def test_ipv6_verifier_rejects_ineffective_rules(tmp_path, defect):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell is required to execute the Windows verifier")
    source = (Path(__file__).resolve().parents[1] / "install" /
              "verify-flarevm.ps1").read_text(encoding="utf-8")
    block = source.split("# Check effective filters,", 1)[1]
    block = "# Check effective filters," + block.split("if ($analysisAddress)", 1)[0]
    harness = r'''
param([string]$Defect)
$ErrorActionPreference = 'Stop'
$script:Failed = $false
function Ok($message) { Write-Output "OK: $message" }
function Fail($message) { $script:Failed = $true; Write-Output "FAIL: $message" }
function Get-NetFirewallRule {
    [CmdletBinding()] param($PolicyStore, $DisplayName)
    if ($Defect -eq 'missing' -and $DisplayName.EndsWith('Outbound')) { return }
    $script:Outbound = $DisplayName.EndsWith('Outbound')
    [pscustomobject]@{
        Enabled = $(if ($script:Outbound -and $Defect -eq 'disabled') { 'False' } else { 'True' })
        Action = $(if ($script:Outbound -and $Defect -eq 'allow') { 'Allow' } else { 'Block' })
        Direction = $(if ($script:Outbound -and $Defect -ne 'direction') { 'Outbound' } else { 'Inbound' })
        Profile = $(if ($script:Outbound -and $Defect -eq 'profile') { 'Private' } else { 'Any' })
    }
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{
        RemoteAddress = @($(if ($script:Outbound -and $Defect -eq 'remote') { 'fe80::/64' }
            elseif ($script:Outbound -and $Defect -eq 'half') { '::/1' }
            else { '::/1'; '8000::/1' }))
        LocalAddress = @($(if ($script:Outbound -and $Defect -eq 'local') { '::1' } else { 'Any' }))
    }
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{
        Protocol = $(if ($script:Outbound -and $Defect -eq 'protocol') { 'TCP' } else { 'Any' })
        LocalPort = @($(if ($script:Outbound -and $Defect -eq 'local_port') { '80' } else { 'Any' }))
        RemotePort = @($(if ($script:Outbound -and $Defect -eq 'remote_port') { '443' } else { 'Any' }))
    }
}
function Get-NetFirewallInterfaceFilter {
    [CmdletBinding()] param($AssociatedNetFirewallRule)
    [pscustomobject]@{
        InterfaceAlias = @($(if ($script:Outbound -and $Defect -eq 'interface') { 'Other adapter' } else { 'Any' }))
    }
}
'''
    script = tmp_path / "verify-ipv6.ps1"
    script.write_text(harness + block + "\nif ($script:Failed) { exit 1 }\n",
                      encoding="utf-8")
    result = subprocess.run(
        [shell, "-NoProfile", "-File", str(script), defect],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == (0 if defect == "none" else 1), result.stdout + result.stderr
    assert ("OK: IPv6 blocked" if defect == "none" else "FAIL: IPv6 isolation") in result.stdout
