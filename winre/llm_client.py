#!/usr/bin/env python3
"""llm_client.py — OpenAI-compatible LLM client for the WinRE pipeline.

Reads configuration from the environment, which is loaded from <repo>/.env
(gitignored) by winre/envfile.py on import. Keys (WINRE_LLM_*):

    WINRE_LLM_BASE_URL   base URL (any OpenAI-compatible endpoint)
    WINRE_LLM_API_KEY    API key (leave blank for a local unauthed server)
    WINRE_LLM_MODEL      model name (whatever your provider exposes)
    WINRE_LLM_REASONING  reasoning effort: low|medium|high|max (optional)

Role separation (RevAI handoff 2026-09-27, item 7) — OPTIONAL pins, each
defaulting to WINRE_LLM_MODEL:

    WINRE_LLM_PLANNER_MODEL   the 35-tool ReAct loop (tool selection: the
                              token-heavy, call-heavy role)
    WINRE_LLM_VERDICT_MODEL   the final judge (verdict JSON + finalize pass)

    WINRE_LLM_MODEL           the DEFAULT for any role that is not pinned

THE TRAP (RevAI hit it in production on 2026-09-27): a role pin must never be
able to move the whole pipeline. Their `get_llm_model()` returned the
*judgment* model, so pinning VERDICT dragged triage, deep dive and reports onto
it and the default became dead config. Here `default` is resolved ONLY from
WINRE_LLM_MODEL and roles fall back TO it — never the reverse. `roles()` is the
single resolver: no call site may read a role variable directly (asserted by
tests/test_llm_roles.py).

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

#: role name -> env var that pins it (the default role is deliberately unpinned)
ROLE_VARS = {
    "planner": "WINRE_LLM_PLANNER_MODEL",
    "judgment": "WINRE_LLM_VERDICT_MODEL",
}


def roles() -> dict:
    """Resolve the per-role models. Read at CALL time (not import) so the UI,
    the tests and a settings change all see the current environment.

    Returns {"default", "planner", "judgment", "pinned": {role: var}}.
    Invariants (tests/test_llm_roles.py):
      * `default` comes from WINRE_LLM_MODEL only — never from a role pin,
      * an unset or blank pin falls back to `default`,
      * `pinned` lists only the roles that are genuinely pinned.
    """
    default = (os.environ.get("WINRE_LLM_MODEL") or "").strip() or "local"
    out: dict = {"default": default}
    pinned: dict = {}
    for role, var in ROLE_VARS.items():
        val = (os.environ.get(var) or "").strip()
        if val:
            out[role] = val
            pinned[role] = var
        else:
            out[role] = default
    out["pinned"] = pinned
    return out


def model_for(role: str = "default") -> str:
    """Resolved model name for a role ('default' | 'planner' | 'judgment')."""
    r = roles()
    return r.get(role) or r["default"]


def pins() -> dict:
    """Raw env values of the optional role pins, for DISPLAY only.

    {WINRE_LLM_PLANNER_MODEL: "", WINRE_LLM_VERDICT_MODEL: ""} — the settings
    page shows exactly what the operator typed, so a typo in a pin stays
    visible. Routing never reads this; it reads `roles()`.
    """
    return {var: (os.environ.get(var) or "") for var in ROLE_VARS}


def resolved() -> dict:
    """Audit-facing record: what each role resolved to, and what was pinned."""
    r = roles()
    return {
        "default": r["default"],
        "planner": r["planner"],
        "judgment": r["judgment"],
        "pinned": dict(r["pinned"]),
        "single_model": r["planner"] == r["judgment"] == r["default"],
    }


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

    OpenAI-compatible APIs accept either `reasoning_effort`
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
    most reliable liveness check.) Uses the DEFAULT model — see
    `available_roles()` for the per-role view.
    """
    try:
        _post("/chat/completions", {
            "model": model_for("default"),
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            **_reasoning_field(),
        }, timeout=15)
        return True
    except Exception:
        return False


def available_roles() -> dict:
    """Per-role reachability: {role: bool} for the default + any distinct pin.

    A pin to a model the provider does not serve must be visible, otherwise
    the run silently falls back to deterministic and the pin looks honored.
    Only distinct models are probed (max 3 calls, and 1 when nothing is
    pinned, so the common case costs exactly what `available()` always did).
    """
    r = roles()
    names = [r["default"], r["planner"], r["judgment"]]
    out: dict = {}
    for name in dict.fromkeys(n for n in names if n):
        try:
            _post("/chat/completions", {
                "model": name,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
                **_reasoning_field(),
            }, timeout=15)
            ok = True
        except Exception:
            ok = False
        for role in ("default", "planner", "judgment"):
            if r.get(role) == name:
                out[role] = ok
    return out


def complete(prompt: str, *, system: str | None = None,
             temperature: float = 0.1, timeout: int = 120) -> str:
    """Convenience: one-shot completion from a prompt string."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return chat(messages, temperature=temperature, timeout=timeout)
