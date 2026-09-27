#!/usr/bin/env python3
"""tests/test_tool_census.py — the deployment must skip nothing we own.

Operator directive, encoded (2026-09-27):

  * the USER installs and activates the licensed binaries — IDA Pro and Malcat.
    Their absence is an operator state, reported by name, never a failure;
  * EVERYTHING else is ours: FlareVM base or installed/configured by
    `setup-flarevm.ps1`. **Nothing may be skipped** — a missing tool we own is
    a FAIL, not a warning;
  * the SQL + MCP WIRING around the user's binaries is OURS: if IDA Pro is
    installed, `idasql.exe` must be discoverable and the live SQL gate must
    pass; if Malcat is installed, its MCP must answer on :9009. Present but
    not wired is our bug, not a skip.

The census in `install/verify-flarevm.ps1` is the enforcement point. These
tests make sure it cannot silently rot:

  1. every tool promised in docs/TOOL-PATHS.md appears in the census,
  2. only Malcat / IDA Pro may be the "user installs" class,
  3. the battery ends with a `SKIPPED BY US: 0` line and fails otherwise,
  4. a tool that is present but unwired is a FAIL, not a skip (the wiring
     checks exist and are not INFO),
  5. no census tool is still marked merely "optional" in the older
     Test-Tool section (that was how radare2 escaped the exit bar).

Run:  python -m pytest tests/test_tool_census.py -q     (no VM)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

VERIFY = REPO / "install" / "verify-flarevm.ps1"
DOC = REPO / "docs" / "TOOL-PATHS.md"

# Tools the pipeline genuinely needs. Each must be asserted by the census.
# key = a distinctive token that must appear in the census entry.
REQUIRED_TOOLS = {
    # static analysis
    "Ghidra": "ghidraRun.bat",
    "ghidrasql": "ghidrasql.exe",
    "LibGhidraHost": "LibGhidraHost",
    "Java 21": "jdk-21",
    "capa": "capa.exe",
    "capa-rules": "capa-rules",
    "floss": "FLOSS",
    "diec": "diec.exe",
    "yara-x": "yara-x",
    "yara-rules": "yara-rules",
    "strings64": "strings64.exe",
    "radare2": "radare2.exe",
    "scdbg": "scdbg.exe",
    "UPX": "Tools\\upx",
    "GoReSym": "goresym.exe",
    "ilspycmd": "ilspycmd",
    "zig": "zig.exe",
    # dynamic / detonation
    "x64dbg": "x64dbg.exe",
    "x64dbg MCP dp64": "x64dbg-MCP-Server.dp64",
    "FakeNet-NG": "fakenet.exe",
    "Procmon": "Procmon64.exe",
    "pe-sieve": "pe-sieve.exe",
    "hollows_hunter": "hollows_hunter.exe",
    "Procdump": "Procdump64.exe",
    "tshark": "tshark.exe",
    "7-Zip": "7z.exe",
    "cdb/WinDbg": "cdb.exe",
    "Python 3.13": "Python313",
}

# python modules setup installs offline from the staged wheels
REQUIRED_PY_MODULES = ("frida", "flask", "pefile", "psutil", "oletools",
                       "pypdf", "dnfile", "z3", "speakeasy", "mcp_windbg",
                       "floss")

# the ONLY tools the operator installs + activates
USER_INSTALLED = ("IDA Pro", "Malcat")


def _verify() -> str:
    return VERIFY.read_text(encoding="utf-8")


def _census_block() -> str:
    src = _verify()
    start = src.index("REQUIRED TOOL CENSUS")
    end = src.index("--- clock (control-plane skew diagnosis)", start)
    return src[start:end]


# --- completeness -----------------------------------------------------------

@pytest.mark.parametrize("tool,token", sorted(REQUIRED_TOOLS.items()))
def test_required_tool_is_in_the_census(tool, token):
    assert token.lower() in _census_block().lower(), (
        f"{tool} is required but missing from the census (looked for {token!r})")


@pytest.mark.parametrize("mod", REQUIRED_PY_MODULES)
def test_required_python_module_is_probed(mod):
    assert f'"{mod}"' in _census_block(), f"py:{mod} not probed by the census"


def test_every_doc_tool_row_is_accounted_for():
    """docs/TOOL-PATHS.md is the promise; the census must cover every row."""
    doc = DOC.read_text(encoding="utf-8")
    rows = [ln for ln in doc.splitlines() if ln.startswith("| ")
            and ln.count("|") >= 6 and "---" not in ln]
    census = _census_block().lower()
    # rows are `| Tool | path | env | used for | missing -> |`
    missing_rows = []
    for ln in rows:
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) < 5 or cells[0].lower() in ("tool", "component"):
            continue
        name = cells[0]
        # a row is covered if its name or a distinctive path token is asserted
        tokens = [t for t in re.split(r"[ /\\+()]+", name) if len(t) > 2]
        if not any(t.lower() in census for t in tokens):
            missing_rows.append(name)
    assert not missing_rows, (
        f"documented tools with no census entry: {missing_rows}")


# --- policy: only the licensed binaries may be the user's job ---------------

def test_only_malcat_and_ida_are_operator_installed():
    src = _census_block()
    user_classed = [re.sub(r"\s*\(licensed\)$", "", m).strip() for m in re.findall(
        r'Test-Required\s+"([^"]+)"[^\n]*-Class\s+user', src)]
    assert sorted(user_classed) == sorted(USER_INSTALLED), (
        f"only {USER_INSTALLED} may be operator-installed, found {user_classed}")


def test_licensed_binaries_are_reported_not_penalised():
    src = _census_block()
    assert "operator installs + activates this one (not our skip)" in src
    assert "operator-installed absent" in src


# --- the wiring around the user's tools is ours -----------------------------

def test_ida_sql_wiring_is_ours_and_required_when_ida_present():
    src = _census_block()
    assert "idasql" in src
    # present-but-unwired must be a FAIL, not an Info/Warn
    assert re.search(r'idasql\.exe is not discoverable[^\n]*\n?\s*Fail', src) \
        or 'IDA Pro is installed but idasql.exe is not discoverable' in src
    assert "IDASQL" in src and "WINRE_IDASQL" in src


def test_malcat_mcp_wiring_is_ours_and_required_when_malcat_present():
    src = _census_block()
    assert "Malcat MCP :9009" in src
    assert re.search(r"NOT answering :9009", src)
    # must be a Fail, and must name the wiring scripts
    line = next(ln for ln in src.splitlines()
                if "Malcat is installed but its MCP" in ln)
    assert line.strip().startswith("Fail"), f"must be a Fail, got: {line.strip()}"
    assert "install_mcp_autostart.ps1" in line and "start_servers.ps1" in line


def test_cdb_presence_does_not_substitute_for_windbg_store():
    """WinDbg (Store/classic) drives :9097; cdb is only the classic debugger.
    Both are asserted; the module probe (mcp_windbg) is the real gate."""
    src = _census_block()
    assert "cdb/WinDbg" in src
    assert "mcp_windbg" in src


# --- the exit bar -----------------------------------------------------------

def test_census_ends_with_a_skip_free_summary():
    src = _census_block()
    assert "SKIPPED BY US" in src
    assert "required present" in src


def test_missing_our_tool_fails_the_battery():
    """A missing tool we own must call Fail (which feeds $script:ERR), never
    Warn - that is the difference between 'skipped' and 'not green'."""
    seg = _census_block()
    assert 'Fail "  [census] REQUIRED and missing: $Name ($Provider)"' in seg
    assert "Test-Required" in seg and "-Optional" not in seg


def test_earlier_optional_testtool_calls_do_not_contradict_the_census():
    """radare2 used to be `-Optional` in the Test-Tool section, which is how a
    required tool escaped the exit bar. No Test-Tool call may claim Optional
    for a tool the census requires."""
    src = _verify()
    optional_labels = set()
    for m in re.finditer(r'Test-Tool\s+"([^"]+)"[^\n]*-Optional', src):
        optional_labels.add(m.group(1).lower())
    assert not optional_labels, (
        f"tools still marked optional in verify: {sorted(optional_labels)}")


# --- doc carries the same policy -------------------------------------------

def test_docs_state_the_ownership_contract():
    doc = DOC.read_text(encoding="utf-8")
    assert "Who owns what" in doc
    assert "Nothing is skipped" in doc
    assert "SKIPPED BY US: 0" in doc
    assert "licensed binaries only: IDA Pro and Malcat" in doc
