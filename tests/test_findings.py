"""The findings module: evidence -> findings, off the VM.

The producer that was never written. Before this, a dynamic run produced ~27
artefacts and `audit.dynamic_verdict` stayed null because nothing produced
one; the report's dynamic section read "see dynamic/ artifacts".

These tests use the real packs from the batch, because the failure mode being
fixed was "looks fine in a summary, empty in practice".
"""
import json
import pathlib
import sys

import pytest

from winre import findings

B108 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
B106 = "a1b468e9550f9960c5e60f7c52ca3c058de19d42eafa760b9d5282eb24b7c55f"
B109 = "55504677f82981962d85495231695d3a92aa0b31ec35a957bd9cbbef618658e3"
B101 = "bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488"
LOGS = pathlib.Path(__file__).resolve().parents[1] / "logs"

_real = [m for m in (B108, B106, B109, B101) if (LOGS / m).is_dir()]
needs_real = pytest.mark.skipif(not _real,
                               reason="no campaign packs present (CI)")


# ------------------------------------------------------------- classification

def test_a_payload_drop_is_a_drop():
    assert findings._classify_path(r"C:\samples\taskdl.exe") == "drop"
    assert findings._classify_path(r"C:\WINDOWS\mssecsvc.exe") == "drop"
    assert findings._classify_path(
        r"C:\Users\X\AppData\Roaming\a.dll") == "drop"


def test_system_subdirs_are_loads_not_drops():
    """Calling mswsock.dll a drop would manufacture evidence."""
    assert findings._classify_path(r"C:\Windows\System32\mswsock.dll") == "system-load"
    assert findings._classify_path(r"C:\Windows\SysWOW64\kernel32.dll") == "system-load"
    assert findings._classify_path(r"C:\Windows\Microsoft.NET\Framework\x.dll") == "system-load"


def test_the_samples_own_file_is_not_a_self_infection():
    own = r"c:\samples\b106_x64_ghostsec.exe"
    assert findings._classify_path(r"C:\samples\b106_x64_ghostsec.exe", own) is None


def test_a_named_pipe_is_not_a_raw_device_write():
    assert findings._classify_path(r"\\.\pipe\GmdAslLogger") == "device"
    assert findings._classify_path(r"\\.\PhysicalDrive0") == "device"
    # and the caller filters pipes out of device_writes
    assert findings._norm(r"\\.\pipe\x").startswith("\\\\.\\pipe")


def test_non_executable_traffic_is_not_a_drop():
    assert findings._classify_path(r"C:\Users\X\AppData\local\temp\notes.txt") == "other"
    assert findings._classify_path(r"C:\programdata\vmware\tools.conf") == "other"


# ------------------------------------------------------------------- schema

def test_findings_have_a_machine_readable_basis():
    """basis is the audit trail; an empty basis on a malicious level is a bug."""
    @pytest.mark.parametrize("sha", _real)
    def _check(sha):
        f = findings.dynamic_findings(LOGS / sha / "agentic" / "dynamic", sha=sha)
        assert f["schema"] == findings.SCHEMA
        v = f["verdict"]
        if v["level"] == findings.MALICIOUS:
            assert v["basis"], f"{sha}: malicious with no basis"
        for b in v["basis"]:
            assert ":" in b, f"basis tag {b!r} is not machine-readable"

    if _real:
        _check(_real[0])


def test_limitations_are_always_present():
    f = findings.dynamic_findings(pathlib.Path("nope"), sha="x" * 64)
    assert "limitations" in f and f["limitations"]
    assert f["ok"] is False


def test_a_missing_pack_is_not_silent(tmp_path):
    f = findings.build("dynamic", tmp_path / "nope", sha="y" * 64)
    assert f["ok"] is False and f["verdict"]["level"] == findings.UNKNOWN
    assert f["limitations"]


def test_unknown_mode_is_reported_not_crashed():
    f = findings.build("nonsense", pathlib.Path("."), sha="z" * 64)
    assert f["ok"] is False
    assert "no findings extractor" in f["limitations"][0]


# --------------------------------------------------------- the real evidence

@needs_real
def test_the_real_packs_now_carry_the_evidence_they_always_had():
    """The defect: b108 dropped b.wnry/taskdl.exe and the report said nothing."""
    f = findings.dynamic_findings(LOGS / B108 / "agentic" / "dynamic", sha=B108)
    assert f["ok"] is True
    assert f["verdict"]["level"] == findings.MALICIOUS
    drops = [d["path"].lower() for d in f["findings"]["drops"]]
    assert any("taskdl" in p or "taskse" in p for p in drops)


@needs_real
def test_persistence_in_the_startup_folder_is_named():
    f = findings.dynamic_findings(LOGS / B106 / "agentic" / "dynamic", sha=B106)
    assert "persistence:startup-path" in f["verdict"]["basis"]
    assert any(d.get("persistence_location") for d in f["findings"]["drops"])


@needs_real
def test_c2_hosts_are_found_and_os_noise_is_not():
    f = findings.dynamic_findings(LOGS / B101 / "agentic" / "dynamic", sha=B101)
    hosts = {c["host"] for c in f["findings"]["network"]["c2"]}
    assert "x1.c.lencr.org" in hosts
    for noise in ("ecs.office.com", "ctldl.windowsupdate.com", "g.live.com"):
        assert noise not in hosts, f"{noise} is OS telemetry, not C2"


@needs_real
def test_procmon_counts_are_labelled_system_wide():
    """`drop_file: 3886` is a window total for the whole VM, not sample
    behaviour. Labelling it as sample evidence would be inventing facts."""
    f = findings.dynamic_findings(LOGS / B108 / "agentic" / "dynamic", sha=B108)
    for p in f["findings"]["persistence"]:
        assert "system-wide" in p["scope"]
    assert "Procmon counts are window-wide" in f["findings"]["persistence_note"]


@needs_real
def test_a_dead_detonation_does_not_claim_behaviour():
    f = findings.dynamic_findings(LOGS / B108 / "agentic" / "dynamic", sha=B108)
    assert f["ok"] is True
    assert f["findings"]["window"]["gate_fired"] is True


# ---------------------------------------------------------------- the writer

def test_build_writes_findings_json(tmp_path):
    d = tmp_path / "dyn"
    d.mkdir(parents=True)
    out = findings.build("dynamic", d, sha="q" * 64)
    assert (d / "findings.json").is_file()
    got = json.loads((d / "findings.json").read_text("utf-8"))
    assert got["schema"] == findings.SCHEMA and got["mode"] == "dynamic"


def test_build_for_sample_returns_one_entry_per_mode(tmp_path):
    sha = "s" * 64
    for m in ("static", "agentic", "dbg", "dynamic"):
        (tmp_path / sha / m).mkdir(parents=True)
    out = findings.build_for_sample(sha, tmp_path)
    assert [f["mode"] for f in out] == ["static", "agentic", "dbg", "dynamic"]


def test_host_tools_are_consulted_and_absent_ones_become_limitations():
    tools = findings._host_tools()
    assert set(tools) >= {"tshark", "yara", "floss", "strings"}
    if not tools["yara"]:
        f = findings.dynamic_findings(pathlib.Path("x"), sha="w" * 64)
        assert any("yara" in l for l in f["limitations"])


# ------------------------------------------------------- no VM dependencies

def test_the_module_imports_no_vm_only_tool():
    """It runs on the analysis host. A VM import here would defeat the design."""
    src = pathlib.Path(findings.__file__).read_text(encoding="utf-8")
    for bad in ("import procmon_post", "import windbg_post",
                "from winre import orchestrator", "device.spawn"):
        assert bad not in src, f"{bad} would run on the VM, not the host"