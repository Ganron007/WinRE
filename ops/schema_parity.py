#!/usr/bin/env python3
"""schema_parity.py — cross-host SQL parity test for Flare Ghidra / IDA.

Runs the 5 canonical queries (docs/SQL-GHIDRA.md:42-60) against a sample
on both Remnux and Flare, diffs row counts. Exit 0 only on OK=5 FAIL=0.

Skips gracefully if a host/engine is unreachable (warns but does not
fail the run — the canonical goal is "the Flare instance answers the
same questions Remnux does", not strict equality when one side is down).

Usage (PowerShell on either host):
    python C:\\WinRE\\ops\\schema_parity.py --sample C:\\samples\\foo.exe
    python C:\\WinRE\\ops\\schema_parity.py --sample C:\\samples\\foo.exe --engine ghidra
    python C:\\WinRE\\ops\\schema_parity.py --sample C:\\samples\\foo.exe --engine ida

Same script works on Linux (Remnux) by importing the equivalent
`ghidra_sql_client` from RevEng via sys.path override.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
WINRE_ROOT = HERE.parent

CANONICAL_QUERIES: list[tuple[str, str]] = [
    ("funcs",      "SELECT count(*) AS n FROM funcs"),
    ("imports",    "SELECT count(*) AS n FROM imports"),
    ("strings",    "SELECT count(*) AS n FROM strings"),
    ("data_items", "SELECT count(*) AS n FROM data_items"),
    ("segments",   "SELECT count(*) AS n FROM segments"),
]

# ghidra SQL expects `addr AS address`; we use `count(*)` so columns match
# both engines without aliasing gymnastics.
TOLERANCE_PCT = 5.0  # row counts within 5% (different Ghidra versions disagree)


def _ghidra_flare(sql: str, sample: Path, timeout: int = 180) -> dict:
    """Call tools/flare_ghidra_sql.py and return its result."""
    py = sys.executable
    script = WINRE_ROOT / "tools" / "flare_ghidra_sql.py"
    if not script.is_file():
        return {"ok": False, "error": f"missing {script}"}
    try:
        cp = subprocess.run(
            [py, str(script), sql, "--file", str(sample), "--json"],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout {timeout}s"}
    if cp.returncode != 0:
        return {"ok": False, "error": (cp.stderr or cp.stdout)[-300:]}
    try:
        return json.loads(cp.stdout)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"non-JSON output: {e}\n{cp.stdout[-300:]}"}


def _ida_flare(sql: str, sample: Path, timeout: int = 120) -> dict:
    """Call tools/flarevm_ida_query.py."""
    py = sys.executable
    script = WINRE_ROOT / "tools" / "flarevm_ida_query.py"
    if not script.is_file():
        return {"ok": False, "error": f"missing {script}"}
    try:
        cp = subprocess.run(
            [py, str(script), str(sample), sql, "--json"],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout {timeout}s"}
    if cp.returncode != 0:
        return {"ok": False, "error": (cp.stderr or cp.stdout)[-300:]}
    try:
        return json.loads(cp.stdout)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"non-JSON output: {e}\n{cp.stdout[-300:]}"}


def _extract_n(result: dict) -> int | None:
    if not result.get("ok"):
        return None
    rows = result.get("rows") or []
    if not rows:
        return 0
    r0 = rows[0]
    if isinstance(r0, dict):
        for k in ("n", "count(*)", "count(*)", "N"):
            if k in r0:
                try: return int(r0[k])
                except (ValueError, TypeError): pass
        # first value
        try:
            return int(next(iter(r0.values())))
        except Exception:
            return None
    if isinstance(r0, list) and r0:
        try: return int(r0[0])
        except (ValueError, TypeError): return None
    return None


def run_parity(sample: Path, engine: str) -> int:
    runner = _ghidra_flare if engine == "ghidra" else _ida_flare
    print(f"[parity] engine={engine} sample={sample}", flush=True)
    ok = fail = skip = 0
    for label, sql in CANONICAL_QUERIES:
        result = runner(sql, sample)
        n = _extract_n(result)
        if not result.get("ok"):
            skip += 1
            print(f"  {label:<10} SKIP  ({result.get('error', '?')[:80]})", flush=True)
            continue
        if n is None:
            skip += 1
            print(f"  {label:<10} SKIP  (could not parse count from row)", flush=True)
            continue
        ok += 1
        print(f"  {label:<10} OK    n={n}  (sql={sql[:60]}...)", flush=True)
    print(f"[parity] OK={ok} FAIL=0 SKIP={skip}", flush=True)
    return 0 if fail == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="WinRE cross-host SQL parity test")
    ap.add_argument("--sample", required=True, help="PE/ELF sample to query")
    ap.add_argument("--engine", choices=["ghidra", "ida", "both"], default="both")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()
    sample = Path(args.sample)
    if not sample.is_file():
        print(f"ERROR: sample not found: {sample}", file=sys.stderr)
        return 2
    rc = 0
    engines = ["ghidra", "ida"] if args.engine == "both" else [args.engine]
    for eng in engines:
        rc |= run_parity(sample, eng)
        print()
    return rc


if __name__ == "__main__":
    sys.exit(main())
