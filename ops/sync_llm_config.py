#!/usr/bin/env python3
"""Sync WinRE LLM settings without replacing the driver's transport settings.

Run on the driver host after securely transferring the operator's source env
file. The destination must already contain that host's own Flare/SSH settings.
Only WINRE_LLM_* entries are replaced; values are never printed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import uuid


def _llm_pairs(text: str) -> dict[str, str]:
    pairs = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.strip().startswith("WINRE_LLM_"):
            pairs[key.strip()] = value.strip()
    return pairs


def sync_llm_config(source: Path, destination: Path) -> dict:
    source_values = _llm_pairs(source.read_text(encoding="utf-8-sig"))
    if not all(source_values.get(key, "").strip("\"'") for key in
               ("WINRE_LLM_BASE_URL", "WINRE_LLM_MODEL")):
        raise ValueError("source must define WINRE_LLM_BASE_URL and WINRE_LLM_MODEL")
    original = destination.read_bytes()  # refuse to invent host SSH settings
    old_text = original.decode("utf-8-sig")
    if _llm_pairs(old_text) == source_values:
        return {"changed": False, "settings": len(source_values), "backup": None}

    retained = [line for line in old_text.splitlines()
                if not _llm_pairs(line)]
    rendered = ("\n".join(retained).rstrip() + "\n\n" +
                "\n".join(f"{key}={value}" for key, value in source_values.items()) + "\n")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = destination.with_name(destination.name + f".bak-{stamp}-{uuid.uuid4().hex[:8]}")
    # Use owner-only POSIX modes when creating secret-bearing files.
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(original)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            stream.write(rendered.encode("utf-8"))
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return {"changed": True, "settings": len(source_values), "backup": str(backup)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(sync_llm_config(args.source, args.destination)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
