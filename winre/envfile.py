#!/usr/bin/env python3
"""envfile.py — tiny .env loader for the WinRE control plane.

Reads KEY=VAL lines from a .env file (gitignored) into os.environ, WITHOUT
overwriting real environment variables (env wins — lets an operator override
per-run without touching the file). Also strips surrounding quotes.

Location: the .env sits next to this package (repo root: C:\\WinRE\\.env on
the VM, <repo>\\.env on the control plane). Set WINRE_ENV to override.
"""
from __future__ import annotations

import os
from pathlib import Path

_ENV_PATH = os.environ.get("WINRE_ENV", str(Path(__file__).resolve().parents[1] / ".env"))


def load_dotenv(path: str | None = None) -> dict:
    """Load a .env file into os.environ (env vars win). Returns loaded pairs."""
    p = Path(path or _ENV_PATH)
    loaded: dict = {}
    if not p.is_file():
        return loaded
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v
            loaded[k] = v
    return loaded


# Load once at import so every consumer (llm_client, agentic, remote_driver)
# sees the .env values without extra ceremony.
load_dotenv()
