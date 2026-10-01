#!/usr/bin/env python3
"""ops/parity_check.py — is the FlareVM running the same code as HEAD?

The "is the VM current?" question gets asked after every deploy, every
snapshot revert and every batch of fixes. Answering it by hand is how a
stale `.env.template` survived several syncs: the old ad-hoc sweep hashed
only the 92 files it happened to walk and never covered the rest, so
"92/92 no mismatches" was true and still wrong.

This checks EVERY file git tracks on the host against the copy under
C:\\WinRE on the VM, and reports three distinct outcomes:

    mismatched   present on both, different content   -> stale, sync needed
    missing      tracked on the host, absent on the VM -> sync needed
    untracked-on-vm is NOT reported (the VM carries runtime state:
                 logs, cache, samples, vm_clock.json, sessions, .env is
                 never copied)

Exit 0 = parity, 1 = drift, 2 = could not reach the VM.

Usage (host, any OS with ssh):
    python ops/parity_check.py
    python ops/parity_check.py --quiet          # one line, for scripts
Env: FLARE_HOST / FLARE_USER / FLARE_SSH_KEY / FLARE_SSH_PORT,
     WINRE_REMOTE_PIPELINE (default C:\\WinRE).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _tracked() -> list[str]:
    r = subprocess.run(["git", "ls-files"], cwd=str(REPO),
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FATAL: git ls-files failed: {r.stderr[:200]}", file=sys.stderr)
        raise SystemExit(2)
    return [f for f in r.stdout.split() if (REPO / f).is_file()]


def _sha(path: Path, n: int = 12) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:n]


def _env_or_dotenv(name: str, default: str = "") -> str:
    v = os.environ.get(name, "").strip()
    if v:
        return v
    env = REPO / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith(f"{name}="):
                return line.split("=", 1)[1].strip().strip('"')
    return default


def _remote_hashes(root: str, ssh_key: str, host: str, user: str,
                   port: int) -> dict:
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$out=@{};"
        f"Get-ChildItem -LiteralPath '{root}' -Recurse -File -Force | ForEach-Object {{"
        "$r=$_.FullName.Substring(" + str(len(root) + 1) + ").Replace('\\','/');"
        "$out[$r]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256)"
        ".Hash.Substring(0,12).ToLower() };"
        "$out | ConvertTo-Json -Compress"
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    cmd = ["ssh", "-i", ssh_key, "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
           "-p", str(port), f"{user}@{host}",
           f"powershell -NoProfile -EncodedCommand {enc}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    raw = (r.stdout or "").strip()
    if r.returncode != 0 or not raw:
        print(f"FATAL: remote hash probe failed rc={r.returncode}: "
              f"{(r.stderr or raw)[:200]}", file=sys.stderr)
        raise SystemExit(2)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"FATAL: remote probe returned non-JSON: {raw[:200]}",
              file=sys.stderr)
        raise SystemExit(2)
    if isinstance(data, list):                      # PS emits a list for >1 key
        return {d.get("key"): d.get("value") for d in data if isinstance(d, dict)}
    if isinstance(data, dict):
        return data
    return {}


def main() -> int:
    # --help must answer instead of hashing the tree over SSH
    if "-h" in sys.argv or "--help" in sys.argv:
        print("usage: python -m ops.parity_check [--quiet]\n\n"
              "Compare every tracked repo file host<->VM by hash.")
        print("exit 0 identical, 1 differences, 2 unusable.")
        return 0
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true", help="one summary line only")
    ap.add_argument("--root", default=None,
                    help="remote repo root (default WINRE_REMOTE_PIPELINE)")
    a = ap.parse_args()

    host = _env_or_dotenv("FLARE_HOST")
    user = _env_or_dotenv("FLARE_USER", "FLARE-VM")
    key = _env_or_dotenv("FLARE_SSH_KEY")
    port = int(_env_or_dotenv("FLARE_SSH_PORT", "22") or 22)
    root = a.root or _env_or_dotenv("WINRE_REMOTE_PIPELINE", r"C:\WinRE")
    if not host or not key:
        print("FATAL: FLARE_HOST / FLARE_SSH_KEY not set (env or .env)",
              file=sys.stderr)
        return 2

    files = _tracked()
    local = {f: _sha(REPO / f) for f in files}
    remote = _remote_hashes(root, key, host, user, port)

    mismatched = sorted(f for f, h in local.items() if f in remote
                        and remote[f] != h)
    missing = sorted(f for f in local if f not in remote)

    if a.quiet:
        state = "PARITY" if not (mismatched or missing) else "DRIFT"
        print(f"{state} {len(local) - len(missing)}/{len(local)} tracked files "
              f"match {root}@{host} "
              f"(mismatched={len(mismatched)} missing={len(missing)})")
    else:
        print(f"tracked files on host : {len(local)}")
        print(f"remote root           : {root} on {user}@{host}:{port}")
        if mismatched:
            print(f"STALE on VM ({len(mismatched)}):")
            for f in mismatched:
                print(f"  {f}  (vm={remote[f]} host={local[f]})")
        if missing:
            print(f"MISSING on VM ({len(missing)}):")
            for f in missing:
                print(f"  {f}")
        if not (mismatched or missing):
            print(f"PARITY: every tracked file matches the VM byte for byte.")
    return 0 if not (mismatched or missing) else 1


if __name__ == "__main__":
    raise SystemExit(main())
