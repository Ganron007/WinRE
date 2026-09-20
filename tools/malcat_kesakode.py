#!/usr/bin/env python3
"""malcat_kesakode.py - OFFLINE Kesakode lookup (Malcat headless, OEM only).

Facts (verified 2026-09-20 on a FULL license):
  - Malcat bundles the offline DB at <install>/data/kesakode/malware.kodb.
  - But headless *offline* Kesakode is an OEM-license feature: with a FULL/PRO
    named license the module/x refuses with
    "Only the OEM version of Malcat may use offline Kesakode in headless mode".
  - Online Kesakode needs the full/pro license key (`-k`) and consumes quota;
    WinRE policy is OFFLINE-ONLY and keyless, so WinRE does not use it.

This tool probes the license flavor and only then runs the offline lookup.
No key, no network. Honest skip otherwise.

Usage: python malcat_kesakode.py <file> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

CANDIDATES = [
    os.environ.get("MALCAT_BIN_DIR"),
    r"C:\Tools\malcat\bin",
    r"C:\Program Files\Malcat\bin",
]


def _bin_dir() -> Path | None:
    for c in CANDIDATES:
        if c and (Path(c) / "malcat.pyd").is_file():
            return Path(c)
    return None


def _flavor(bin_dir: Path) -> tuple[str | None, str | None]:
    """Return (flavor_name, error)."""
    if str(bin_dir) not in sys.path:
        sys.path.insert(0, str(bin_dir))
    try:
        import malcat  # type: ignore
    except Exception as e:  # noqa: BLE001
        return None, f"malcat import failed: {str(e)[:160]}"
    try:
        f = malcat.env.flavor
        return getattr(f, "name", str(f)), None
    except Exception as e:  # noqa: BLE001
        return None, f"flavor probe failed: {str(e)[:160]}"


def lookup(path: str) -> dict:
    out: dict = {"ok": False, "tool": "kesakode_offline",
                 "verdict": {}, "top": [], "matches": 0,
                 "flavor": None, "error": None, "skipped": None}
    p = Path(path)
    if not p.is_file():
        out["error"] = f"sample missing: {p}"
        return out
    bin_dir = _bin_dir()
    if bin_dir is None:
        out["skipped"] = "Malcat bin dir not found (bin\\malcat.pyd)"
        return out
    flavor, err = _flavor(bin_dir)
    out["flavor"] = flavor
    if err:
        out["error"] = err
        return out
    if (flavor or "").upper() != "OEM":
        out["skipped"] = (f"offline Kesakode requires an OEM license "
                          f"(flavor={flavor}); online would need -k, which "
                          f"WinRE does not use (offline-only policy)")
        return out
    try:
        import malcat  # type: ignore
        a = malcat.analyse(str(p), options={
            "anom_disable": True, "loop_disable": True,
            "invalidate_cache": False})
        ks = a.kesakode
        verdict = dict(getattr(ks, "verdict", {}) or {})
        ranked = sorted(verdict.items(), key=lambda kv: -float(kv[1] or 0))
        out.update({
            "ok": True,
            "verdict": {k: round(float(v), 2) for k, v in ranked[:20]},
            "top": [k for k, _ in ranked[:5]],
            "matches": len(verdict),
        })
    except Exception as e:  # noqa: BLE001
        out["error"] = f"offline kesakode failed: {str(e)[:180]}"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline Kesakode lookup (OEM only)")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = lookup(a.path)
    if a.json:
        print(json.dumps(res))
    else:
        if res.get("skipped"):
            print(f"skipped: {res['skipped']}")
        elif res.get("error"):
            print(f"error: {res['error']}")
        else:
            print(f"flavor={res['flavor']} matches={res['matches']}")
            for fam, score in (res.get("verdict") or {}).items():
                print(f"  {fam}: {score}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
