#!/usr/bin/env python3
"""tests/test_llm_roles.py — per-role LLM routing (RevAI handoff item 7).

RevAI ships three resolvable roles (default / planner / judgment) and, until
2026-09-27, made the mistake this file exists to prevent: their
`get_llm_model()` returned the *judgment* model, so pinning
`REVAI_LLM_VERDICT_MODEL` silently dragged every triage, deep-dive and report
call onto it and the default became dead config. A role pin that quietly moves
the whole pipeline is worse than no separation at all.

So the contract tested here is:

  * `default` is resolved from `WINRE_LLM_MODEL` ONLY — a role pin can never
    become the default,
  * an unset or blank pin falls back to the default,
  * roles are resolved in exactly ONE place (`llm_client.roles()`); no call
    site may read a role variable directly, so the routing cannot drift,
  * the two real call sites (ReAct tool loop / final judge) take their models
    from the resolver, and the finalize pass uses the judge,
  * the resolved routing is recorded per run (deep.json / report.json /
    audit.json) so it is verifiable per case, not trusted,
  * a pin to a model the endpoint does not serve is visible
    (`available_roles()`), never a silent deterministic fallback.

Run:  python -m pytest tests/test_llm_roles.py -q     (no network: the probes
      are monkeypatched)
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from winre import llm_client            # noqa: E402

ROLE_VARS = ("WINRE_LLM_PLANNER_MODEL", "WINRE_LLM_VERDICT_MODEL")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("WINRE_LLM_MODEL", raising=False)
    for v in ROLE_VARS:
        monkeypatch.delenv(v, raising=False)


# --- resolution matrix ------------------------------------------------------

def test_no_config_resolves_to_local(monkeypatch):
    r = llm_client.roles()
    assert r["default"] == "local"
    assert r["planner"] == "local"
    assert r["judgment"] == "local"
    assert r["pinned"] == {}


def test_only_default_set(monkeypatch):
    monkeypatch.setenv("WINRE_LLM_MODEL", "fast-1")
    r = llm_client.roles()
    assert (r["default"], r["planner"], r["judgment"]) == ("fast-1",) * 3
    assert llm_client.resolved()["single_model"] is True


def test_planner_pin_only(monkeypatch):
    monkeypatch.setenv("WINRE_LLM_MODEL", "mid-1")
    monkeypatch.setenv("WINRE_LLM_PLANNER_MODEL", "cheap-1")
    r = llm_client.roles()
    assert r["planner"] == "cheap-1"
    assert r["judgment"] == "mid-1"
    assert r["default"] == "mid-1"
    assert r["pinned"] == {"planner": "WINRE_LLM_PLANNER_MODEL"}


def test_verdict_pin_only(monkeypatch):
    monkeypatch.setenv("WINRE_LLM_MODEL", "cheap-1")
    monkeypatch.setenv("WINRE_LLM_VERDICT_MODEL", "strong-1")
    r = llm_client.roles()
    assert r["judgment"] == "strong-1"
    assert r["planner"] == "cheap-1"
    assert r["default"] == "cheap-1"
    assert llm_client.resolved()["single_model"] is False


def test_both_pins(monkeypatch):
    monkeypatch.setenv("WINRE_LLM_MODEL", "mid-1")
    monkeypatch.setenv("WINRE_LLM_PLANNER_MODEL", "cheap-1")
    monkeypatch.setenv("WINRE_LLM_VERDICT_MODEL", "strong-1")
    r = llm_client.roles()
    assert (r["default"], r["planner"], r["judgment"]) == \
        ("mid-1", "cheap-1", "strong-1")
    assert set(r["pinned"]) == {"planner", "judgment"}


def test_blank_pin_is_not_a_pin(monkeypatch):
    """An empty env value must fall back, not resolve to ''."""
    monkeypatch.setenv("WINRE_LLM_MODEL", "mid-1")
    monkeypatch.setenv("WINRE_LLM_PLANNER_MODEL", "   ")
    monkeypatch.setenv("WINRE_LLM_VERDICT_MODEL", "")
    r = llm_client.roles()
    assert r["planner"] == "mid-1" and r["judgment"] == "mid-1"
    assert r["pinned"] == {}


def test_verdict_pin_can_never_become_the_default(monkeypatch):
    """THE TRAP. With no WINRE_LLM_MODEL at all, pinning the verdict model
    must leave the default (and therefore the planner) alone."""
    monkeypatch.setenv("WINRE_LLM_VERDICT_MODEL", "strong-1")
    r = llm_client.roles()
    assert r["judgment"] == "strong-1"
    assert r["default"] == "local"
    assert r["planner"] == "local"


def test_model_for_role(monkeypatch):
    monkeypatch.setenv("WINRE_LLM_MODEL", "mid-1")
    monkeypatch.setenv("WINRE_LLM_PLANNER_MODEL", "cheap-1")
    assert llm_client.model_for("planner") == "cheap-1"
    assert llm_client.model_for("judgment") == "mid-1"
    assert llm_client.model_for("default") == "mid-1"
    assert llm_client.model_for("nonsense") == "mid-1"   # never blank


# --- one resolver, two call sites -------------------------------------------

def test_only_the_resolver_reads_role_variables():
    """No module may read a role variable directly — that is how routing
    drifts. llm_client.ROLE_VARS is the single mapping."""
    offenders: list[str] = []
    for p in sorted(REPO.glob("winre/**/*.py")):
        if p.name == "llm_client.py":
            continue
        src = p.read_text(encoding="utf-8")
        for var in ROLE_VARS:
            # a bare os.environ.get("<VAR>") read outside the resolver
            for needle in (f'os.environ.get("{var}"',
                           f"os.environ.get('{var}'",
                           f'os.environ["{var}"]'):
                if needle in src:
                    offenders.append(f"{p.relative_to(REPO).as_posix()}: {var}")
    assert not offenders, f"role variables read outside the resolver: {offenders}"


def test_agent_builds_one_client_per_role():
    from winre import agentic
    src = inspect.getsource(agentic.run_langgraph_deep_dive)
    assert 'llm = _mk("planner")' in src
    assert 'judge = _mk("judgment")' in src
    # the tool loop runs on the planner, the finalize pass on the judge
    assert "agent = create_react_agent(llm," in src
    assert "fid = judge.invoke(" in src
    # and the model is never read straight from the environment any more
    assert 'os.environ.get("WINRE_LLM_MODEL"' not in src


def test_dry_and_fallback_paths_still_record_roles(monkeypatch):
    """Even a dry or keyless run records what WOULD have been used."""
    from winre import agentic
    src = inspect.getsource(agentic.run_langgraph_deep_dive)
    assert src.count('"llm_roles": _llm_roles()') >= 5
    assert src.count('return {"verdict"') >= 5


# --- per-run verifiability --------------------------------------------------

def test_pipeline_records_roles_in_deep_and_report():
    from pathlib import Path as _P
    for rel, needle in (("winre/pipeline.py", '"llm_roles"'),
                        ("winre/remote_driver.py", '"llm_roles"')):
        src = (REPO / rel).read_text(encoding="utf-8")
        assert needle in src, f"{rel} does not record llm_roles"


def test_audit_and_report_expose_roles():
    audit = (REPO / "winre" / "audit.py").read_text(encoding="utf-8")
    assert '"llm_roles": deep_v.get("llm_roles")' in audit
    rep = (REPO / "winre" / "reporting.py").read_text(encoding="utf-8")
    assert "llm roles:" in rep


def test_settings_page_shows_the_routing():
    tpl = (REPO / "winre" / "ui" / "templates" / "settings.html").read_text(
        encoding="utf-8")
    for needle in ("WINRE_LLM_PLANNER_MODEL", "WINRE_LLM_VERDICT_MODEL",
                   "resolved role routing", "cfg.llm.roles.planner"):
        assert needle in tpl, needle


def test_env_template_documents_the_pins():
    tpl = (REPO / ".env.template").read_text(encoding="utf-8")
    assert "WINRE_LLM_PLANNER_MODEL" in tpl
    assert "WINRE_LLM_VERDICT_MODEL" in tpl
    assert "A pin never moves the other roles" in tpl


# --- a pin the endpoint does not serve must be visible ----------------------

def test_available_roles_probes_each_distinct_model(monkeypatch):
    calls: list[str] = []

    def fake_post(path, payload, timeout=120):
        calls.append(payload["model"])
        if payload["model"] == "ghost-1":
            raise llm_client.LLMError("model not found")
        return {"choices": [{"message": {"content": "pong"}}]}

    monkeypatch.setattr(llm_client, "_post", fake_post)
    monkeypatch.setenv("WINRE_LLM_MODEL", "cheap-1")
    monkeypatch.setenv("WINRE_LLM_PLANNER_MODEL", "ghost-1")
    r = llm_client.available_roles()
    assert r == {"default": True, "planner": False, "judgment": True}
    assert sorted(set(calls)) == ["cheap-1", "ghost-1"]


def test_available_roles_costs_one_call_when_nothing_is_pinned(monkeypatch):
    calls: list[str] = []

    def fake_post(path, payload, timeout=120):
        calls.append(payload["model"])
        return {"choices": [{"message": {"content": "pong"}}]}

    monkeypatch.setattr(llm_client, "_post", fake_post)
    monkeypatch.setenv("WINRE_LLM_MODEL", "only-1")
    assert llm_client.available_roles() == {"default": True, "planner": True,
                                            "judgment": True}
    assert calls == ["only-1"]


def test_available_uses_the_default_model(monkeypatch):
    seen: list[str] = []

    def fake_post(path, payload, timeout=120):
        seen.append(payload["model"])
        return {"choices": [{"message": {"content": "pong"}}]}

    monkeypatch.setattr(llm_client, "_post", fake_post)
    monkeypatch.setenv("WINRE_LLM_MODEL", "mid-1")
    monkeypatch.setenv("WINRE_LLM_VERDICT_MODEL", "strong-1")
    assert llm_client.available() is True
    assert seen == ["mid-1"]
