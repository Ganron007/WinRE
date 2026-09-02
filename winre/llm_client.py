#!/usr/bin/env python3
"""llm_client.py — OpenAI-compatible LLM client for the WinRE pipeline.

Reads configuration from the environment, which is loaded from <repo>/.env
(gitignored) by winre/envfile.py on import. Keys (WINRE_LLM_*):

    WINRE_LLM_BASE_URL   base URL (e.g. https://api.stepfun.com/v1)
    WINRE_LLM_API_KEY    API key (leave blank for a local unauthed server)
    WINRE_LLM_MODEL      model name (e.g. step-3.7-flash)
    WINRE_LLM_REASONING  reasoning effort: low|medium|high|max (optional)

Deterministic-first: the pipeline never lets the LLM run tools or decide
stages; it only interprets evidence. Every response is source-tagged
(llm_judge vs deterministic_fallback) by the caller.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .envfile import load_dotenv  # noqa: F401  (ensures .env is loaded)

BASE_URL = os.environ.get("WINRE_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
API_KEY = os.environ.get("WINRE_LLM_API_KEY", "")
MODEL = os.environ.get("WINRE_LLM_MODEL", "local")
REASONING = os.environ.get("WINRE_LLM_REASONING", "").strip().lower()


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


def _reasoning_field() -> dict:
    """Map WINRE_LLM_REASONING to the provider field if set.

    StepFun/OpenAI-compatible APIs accept either `reasoning_effort`
    (low/medium/high) or a `reasoning_level`-style field. We send
    `reasoning_effort` only when a value is configured and the field is
    supported; otherwise omit (provider default applies).
    """
    if REASONING in ("low", "medium", "high", "max"):
        return {"reasoning_effort": REASONING}
    return {}


def chat(messages: list[dict[str, str]], *, model: str | None = None,
         timeout: int = 120, temperature: float = 0.1, max_tokens: int = 4000) -> str:
    """One chat completion. Returns the assistant text."""
    m = model or MODEL
    payload: dict[str, Any] = {
        "model": m,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    payload.update(_reasoning_field())
    out = _post("/chat/completions", payload, timeout=timeout)
    try:
        return out["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"LLM response missing content: {out!r:.200}") from e


def available() -> bool:
    """Reachability probe: try a 1-token chat; swallow any error.

    (A GET /models probe can 404/401 on some providers, so a tiny chat is the
    most reliable liveness check.)
    """
    try:
        _post("/chat/completions", {
            "model": MODEL,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            **_reasoning_field(),
        }, timeout=15)
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
