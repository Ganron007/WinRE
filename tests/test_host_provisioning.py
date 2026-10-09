"""The control plane is a machine the product needs, and nothing provisioned it.

The FlareVM was fully provisioned - 43/43 required present, 0 FAIL, SKIPPED BY
US: 0 - while the box that actually RUNS the analysis had no installer at all.
`ops/provision_tools.ps1` uses the host only as a download proxy for the
air-gapped VM, and `install/setup-flarevm.ps1` says "Usage (ON the FlareVM)".
So the analysis plane ran on a box with no yara, no capa, no floss and no rules,
and every findings.json said "yara is not installed on the analysis host" - a
limitation that never said WHERE it looked, or that the VM has yara-x and 57
rules at C:/Tools/yara-rules.

These tests pin both halves of the fix: the host-side discovery, and that the
triage it enables actually detects something. A triage that returns 0 hits
because it is broken is worse than no triage.
"""
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


# ------------------------------------------------------- host-side discovery

def test_host_tool_probing_does_not_confuse_a_library_with_a_binary():
    """yara is normally a LIBRARY on the analysis host (yara-python), not an
    executable on PATH. `shutil.which("yara")` reports "not installed" while
    yara-python is present and working - which is how the whole gap hid."""
    from winre import findings as F
    src = pathlib.Path(F.__file__).read_text(encoding="utf-8")
    assert "importlib.import_module(mod)" in src, (
        "the Python tools must be probed by import, not by PATH")
    assert 'for t in ("tshark", "yara", "floss", "strings")' not in src, (
        "yara/floss are being probed with shutil.which, which cannot see the "
        "pip packages the analysis plane actually uses")


def test_a_missing_tool_says_where_it_looked():
    """The limitation must name the machine and the fix, not just the absence.
    "yara is not installed on the analysis host" sent a reviewer looking for a
    missing install on the VM, which already had it."""
    from winre import findings as F
    src = pathlib.Path(F.__file__).read_text(encoding="utf-8")
    assert "analysis host" in src
    assert "provision_host" in src, (
        "the gap must name the script that closes it")


def test_the_control_plane_has_a_provisioner():
    """The gap in one line: there was no installer for the machine that does the
    analysis. ops/provision_host.ps1 is it."""
    p = REPO / "ops" / "provision_host.ps1"
    assert p.is_file(), (
        "ops/provision_host.ps1 is missing - the control plane is unprovisioned")
    text = p.read_text(encoding="utf-8")
    for need in ("yara-python", "flare-floss", "flare-capa"):
        assert need in text, f"{need} is not provisioned on the control plane"
    # and it must be idempotent and re-runnable
    assert "already importable" in text


def test_the_provisioner_stages_the_rules_from_the_vm():
    """The FlareVM holds the authority copy of the curated rules; the control
    plane is the only other place they can live."""
    text = (REPO / "ops" / "provision_host.ps1").read_text(encoding="utf-8")
    assert "C:/Tools/yara-rules" in text
    assert "scp" in text, "the rules must be copied from the air-gapped VM"


# ------------------------------------------------------- the triage itself

def test_the_dump_triage_actually_detects(tmp_path):
    """Positive control. 0 hits is only meaningful if the triage can hit."""
    yara = pytest.importorskip("yara")
    from winre import findings as F

    dump = tmp_path / "probe.dmp"
    dump.write_bytes(b"MZ\x90\x00"
                     + b"This program cannot be run in DOS mode" * 300)
    rule = tmp_path / "probe.yar"
    rule.write_text(
        'rule winre_probe_dos_stub {\n'
        '  strings:\n'
        '    $a = "This program cannot be run in DOS mode"\n'
        '  condition:\n'
        '    $a\n'
        '}\n', encoding="utf-8")

    import os
    from unittest import mock
    with mock.patch.object(F, "_yara_rules_dir", return_value=tmp_path):
        out = F._triage_dumps(tmp_path, [dump])
    assert out.get("ran") is True, f"triage did not run: {out}"
    assert out.get("hit_count", 0) >= 1, (
        "the triage found nothing in a dump that contains a matchable string - "
        "it is decorative")
    assert out["hits"][0]["rule"] == "winre_probe_dos_stub"


def test_the_triage_reports_a_timeout_as_a_timeout():
    """A silent cap would be the same dishonesty this module exists to avoid."""
    from winre import findings as F
    src = pathlib.Path(F.__file__).read_text(encoding="utf-8")
    assert "timed_out" in src
    assert "not 'no hits'" in src, (
        "a timeout must be reported as a timeout, not as an absence of hits")


def test_the_triage_says_so_when_there_are_no_rules(tmp_path):
    from unittest import mock
    from winre import findings as F
    with mock.patch.object(F, "_yara_rules_dir", return_value=None):
        out = F._triage_dumps(tmp_path, [tmp_path / "none.dmp"])
    assert out.get("ran") is False
    assert "provision_host" in out.get("reason", ""), (
        "a missing rule set must name the script that stages it")


def test_no_triage_claim_without_rules_on_this_box():
    """The honest statement when the host was never provisioned."""
    from winre import findings as F
    if F._yara_rules_dir() is None:
        pytest.skip("this host has no curated rules; that is the gap itself")
    tools = F._host_tools()
    assert tools.get("yara") is True, "yara-python is importable but not seen"
    assert tools.get("yara_rules") is True
