#!/usr/bin/env python3
"""llm_client.py — local OpenAI-compatible LLM client for the WinRE pipeline.

WinRE is fully local: no SSH, no remote agent. The LLM endpoint is whatever
the operator configures (a local model on the FlareVM or an OpenAI-compatible
API reachable from it) — via WINRE_LLM_BASE_URL / WINRE_LLM_API_KEY.

Deterministic-first: the pipeline NEVER lets the LLM run tools or decide
stages. It only interprets evidence (verdicts, report prose). Every response
is source-tagged (llm_judge); a failed/absent LLM falls back to
deterministic_fallback verdicts and the audit gate records it.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

BASE_URL = os.environ.get("WINRE_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
API_KEY = os.environ.get("WINRE_LLM_API_KEY", "")
MODEL = os.environ.get("WINRE_LLM_MODEL", "local")


class LLMError(RuntimeError):
    """Raised when the LLM is unreachable or returns a bad response."""


def _post(path: str, payload: dict, timeout: int = 120) -> dict:
    url = BASE_URL.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.URLError as e:
        raise LLMError(f"LLM unreachable at {url}: {e}") from e
    except json.JSONDecodeError as e:
        raise LLMError(f"LLM returned non-JSON: {e}") from e


def chat(messages: list[dict[str, str]], *, model: str | None = None,
         timeout: int = 120, temperature: float = 0.1, max_tokens: int = 4000) -> str:
    """One chat completion. Returns the assistant text."""
    m = model or MODEL
    payload = {
        "model": m,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    out = _post("/chat/completions", payload, timeout=timeout)
    try:
        return out["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"LLM response missing content: {out!r:.200}") from e


def available() -> bool:
    """Cheap reachability probe (no key required)."""
    try:
        _post("/models", {"model": MODEL}, timeout=10)
        return True
    except Exception:
        return False


def complete(prompt: str, *, system: str | None = None,
             temperature: float = 0.1, timeout: int = 120) -> str:
    """Convenience: one-shot completion from a prompt string."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return chat(messages, temperature=temperature, timeout=timeout)
