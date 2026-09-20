#!/usr/bin/env python3
"""vt.py - VirusTotal HASH-ONLY triage lookup (control plane).

Reads the API key from WINRE_VT_API_KEY (fallback VT_API_KEY) via the
environment/.env. **Only the SHA256 is sent** - the sample never leaves the
VM, and this module never uploads a file.

Evidence-only by policy: a VT detection count never decides a verdict on its
own (commercial AV engines flag dual-use/legitimate tooling constantly). The
strict spine records it; the LLM may cite it.

Output: {"ok": bool, "found": bool, "malicious": n, "suspicious": n,
         "harmless": n, "undetected": n, "detection_ratio": "m/total",
         "name": str|None, "type": str|None, "family": str|None,
         "reputation": int|None, "last_analysis_date": int|None,
         "link": str, "error": str|None}
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .envfile import load_dotenv  # noqa: F401  (ensures .env is loaded)

_API = "https://www.virustotal.com/api/v3/files/{sha}"
_GUI = "https://www.virustotal.com/gui/file/{sha}"


def api_key() -> str:
    return (os.environ.get("WINRE_VT_API_KEY")
            or os.environ.get("VT_API_KEY") or "").strip()


def lookup(sha256: str, timeout: int = 30) -> dict:
    """Hash-only VT lookup. Never raises; returns an honest dict."""
    sha = (sha256 or "").strip().lower()
    out: dict = {"ok": False, "found": False, "malicious": None,
                 "suspicious": None, "harmless": None, "undetected": None,
                 "detection_ratio": None, "name": None, "type": None,
                 "family": None, "reputation": None,
                 "last_analysis_date": None,
                 "link": _GUI.format(sha=sha), "error": None}
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        out["error"] = "not a sha256"
        return out
    key = api_key()
    if not key:
        out["skipped"] = "WINRE_VT_API_KEY not set"
        return out
    req = urllib.request.Request(_API.format(sha=sha),
                                 headers={"x-apikey": key,
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            out["ok"] = True          # lookup succeeded: hash unknown to VT
            out["found"] = False
            return out
        if e.code == 401:
            out["error"] = "VT auth failed (401) - check the API key"
            return out
        if e.code == 429:
            out["error"] = "VT rate-limited (429) - quota/backoff"
            return out
        out["error"] = f"VT HTTP {e.code}"
        return out
    except Exception as e:  # noqa: BLE001
        out["error"] = f"VT lookup failed: {str(e)[:180]}"
        return out

    attrs = ((payload or {}).get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    m = int(stats.get("malicious") or 0)
    s = int(stats.get("suspicious") or 0)
    h = int(stats.get("harmless") or 0)
    u = int(stats.get("undetected") or 0)
    total = m + s + h + u
    threat = (attrs.get("popular_threat_classification") or {})
    out.update({
        "ok": True,
        "found": True,
        "malicious": m,
        "suspicious": s,
        "harmless": h,
        "undetected": u,
        "detection_ratio": f"{m + s}/{total}" if total else None,
        "name": attrs.get("meaningful_name") or None,
        "type": attrs.get("type_description") or None,
        "family": threat.get("suggested_threat_label") or None,
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    })
    return out
