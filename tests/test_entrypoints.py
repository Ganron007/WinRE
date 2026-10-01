#!/usr/bin/env python3
"""tests/test_entrypoints.py — every CLI entry point must answer --help.

The 2026-09-20 sweep found real defects this way (a cp125arg-decoding crash
on `--help` in several tools, arg handling that swallowed values). Those were
fixed one bug at a time; this file makes the bar permanent and cheap: any
entry point that cannot print its help without a traceback fails here, not on
a sample run.

The list is DISCOVERED (modules with `def main(` + `__main__`) so a new tool
is covered the day it is added, minus an explicit allowlist for entry points
that legitimately need arguments before they can do anything.

Run:  python -m pytest tests/test_entrypoints.py -q      (no VM, no samples)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# entry points whose argparse has no --help by design (they act immediately
# or are library shims). Keep this list tiny and justified.
NO_HELP = {
    "tools.apimon_filter": "argparse-less filter; no CLI surface",
    "winre.mcp.windbg_bridge": "bridge server; starts on import of main()",
}


def _entry_points() -> list[str]:
    """Every module that can be run with -m and takes arguments.

    The predicate used to require `def main(`, which silently excluded every
    module whose CLI is `def _main(argv)`: snapshot_gate, audit and all three
    SQL clients. Those are documented CLIs - and verify-flarevm.ps1 invokes the
    SQL ones - so they had ZERO --help coverage. ops/*.py are documented CLIs
    too (code audit 2026-09-28).
    """
    import re as _re
    mods: list[str] = []
    paths = (sorted(REPO.glob("winre/**/*.py"))
             + sorted(REPO.glob("tools/*.py"))
             + sorted(REPO.glob("ops/*.py")))
    for p in paths:
        try:
            src = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "__main__" not in src:
            continue
        if not _re.search(r"def (?:main|_main|_cli|cli_main)\s*\(", src):
            continue
        rel = p.relative_to(REPO).as_posix()[:-3].replace("/", ".")
        if rel.endswith(".__init__"):
            rel = rel[:-9]
        mods.append(rel)
    return mods


EPS = _entry_points()


def test_entry_points_were_discovered():
    assert len(EPS) >= 26, (
        f"only {len(EPS)} entry points discovered")


def _env() -> dict:
    """Minimal-but-usable child env: a few tools resolve Path.home() at
    import time, so HOME/USERPROFILE/TEMP must survive (the cp1252 sweep's
    original lesson applies to the harness too)."""
    import os
    import tempfile
    keep = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
            "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
            "PROGRAMFILES", "WINDIR", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
            "OS")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.setdefault("TEMP", tempfile.gettempdir())
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(REPO)
    return env


@pytest.mark.parametrize("mod", EPS)
def test_help_exits_cleanly(mod):
    if mod in NO_HELP:
        pytest.skip(NO_HELP[mod])
    r = subprocess.run([sys.executable, "-m", mod, "--help"],
                       capture_output=True, text=True, timeout=180,
                       cwd=str(REPO), env=_env(), encoding="utf-8",
                       errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    assert "Traceback (most recent call last)" not in out, (
        f"{mod} --help crashed:\n{out[-800:]}")
    assert r.returncode == 0, f"{mod} --help exit={r.returncode}:\n{out[-800:]}"
    assert "usage:" in out.lower(), f"{mod} --help printed no usage:\n{out[-400:]}"


def test_no_entry_point_crashes_without_args():
    """A missing-argument call must be a clean usage error (rc 2), never a
    traceback: operators hit these paths with the wrong arguments."""
    for mod in EPS:
        if mod in NO_HELP:
            continue
        if mod == "winre.ui.app":
            continue          # starts the server; covered by ops/smoke_flare.py
        try:
            r = subprocess.run([sys.executable, "-m", mod],
                               capture_output=True, text=True, timeout=90,
                               cwd=str(REPO), env=_env(), encoding="utf-8",
                               errors="replace")
        except subprocess.TimeoutExpired:
            pytest.fail(f"{mod} with no args hung (no usage error)")
        out = (r.stdout or "") + (r.stderr or "")
        assert "Traceback (most recent call last)" not in out, (
            f"{mod} (no args) crashed:\n{out[-600:]}")
